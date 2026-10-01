"""Customer API surface `/capi/v1/*` (SPEC §10.1).

Authenticated by a per-service key (`Authorization: Bearer pcdn_...`), NOT the admin key.
The key resolves to exactly one site and every call is scoped to that site only; each key
carries a subset of the scopes {purge, stats, dns} and an endpoint checks its scope (403
otherwise). All logic (purge, analytics, events, records, config) is reused from the admin
routes so behaviour/validation never drifts between the two surfaces.
"""

import time

from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from .audit import record_audit
from .auth import hash_token
from .config import settings
from .db import get_db
from .models import ApiKey, Site, utcnow
from .routes_admin import (
    PurgeIn,
    RecordIn,
    add_record_of,
    delete_record_of,
    list_records_of,
    purge_site,
    update_record_of,
)
from .routes_v2 import read_section_of, site_analytics, site_events, write_section_of

router = APIRouter(prefix="/capi/v1")

# Per-key sliding-window rate limiter. NOTE: this state lives in-process, so with several
# controller workers the effective limit is CAPI_RATE * (number of processes). Fine for the
# current single-process deployment; move to a shared store (Redis) if that changes.
_hits: dict[int, list[float]] = {}
# F5: a separate, tighter window for config/record *writes* only. A burst of these bumps the edge
# config version and can herd fleet-wide reloads, so they are limited beyond the general CAPI_RATE.
# Reads, purges and stats never touch this window.
_config_hits: dict[int, list[float]] = {}


def _sliding(store: dict[int, list[float]], key_id: int, limit: int, label: str):
    now = time.monotonic()
    window = store.setdefault(key_id, [])
    window[:] = [t for t in window if t > now - 60]
    if len(window) >= limit:
        raise HTTPException(429, f"محدودیت نرخ {label} ({limit} در دقیقه) رد شد؛ کمی بعد دوباره تلاش کنید")
    window.append(now)


def _rate_limit(key_id: int):
    _sliding(_hits, key_id, settings.capi_rate, "درخواست")


def _rate_limit_config(key: ApiKey) -> ApiKey:
    """F5: extra per-key limit for config/record write verbs (in addition to CAPI_RATE)."""
    _sliding(_config_hits, key.id, settings.capi_config_rate, "تغییر پیکربندی")
    return key


def resolve_key(authorization: str | None = Header(default=None), db: Session = Depends(get_db)) -> ApiKey:
    """Resolve the bearer key to a non-revoked ApiKey, rate-limit it and update last_used_at.

    Only customer keys ('pcdn_...') are accepted here; the admin key never resolves. Unknown or
    revoked keys -> 401 JSON {"detail": ...}."""
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(401, "missing bearer token")
    token = authorization[7:].strip()
    if not token.startswith("pcdn_"):
        raise HTTPException(401, "invalid api key")
    key = db.scalar(select(ApiKey).where(ApiKey.key_hash == hash_token(token), ApiKey.revoked.is_(False)))
    if key is None:
        raise HTTPException(401, "invalid api key")
    _rate_limit(key.id)
    key.last_used_at = utcnow()
    db.commit()
    return key


def require_scope(scope: str):
    """Dependency: resolve the key and require it to carry `scope` (403 otherwise)."""

    def dep(key: ApiKey = Depends(resolve_key)) -> ApiKey:
        if scope not in key.scope_list:
            raise HTTPException(403, f"این کلید دسترسی «{scope}» را ندارد")
        return key

    return dep


def _site(key: ApiKey) -> Site:
    return key.site


def _audit(db: Session, request: Request, key: ApiKey, action: str, detail: dict | None = None) -> None:
    """Record a customer-API mutation (SPEC §13.2). The actor is the key's name (or id) and the
    target is always the key's own site; secrets are stripped by record_audit."""
    actor = key.name or f"key:{key.id}"
    ip = request.client.host if request.client else None
    record_audit(db, actor=actor, actor_kind="capi", action=action, target=key.site.domain,
                 detail=detail, ip=ip)


# ------------------------------------------------------------------ purge (scope: purge)

@router.post("/purge")
def purge(body: PurgeIn, request: Request, key: ApiKey = Depends(require_scope("purge")),
          db: Session = Depends(get_db)):
    result = purge_site(db, _site(key), body)
    _audit(db, request, key, "purge",
           {"everything": body.everything, "urls": len(body.urls), "prefixes": len(body.prefixes)})
    return result


# ------------------------------------------------------------------ analytics + events (scope: stats)

@router.get("/analytics")
def analytics(period: str = "24h", key: ApiKey = Depends(require_scope("stats")), db: Session = Depends(get_db)):
    return site_analytics(db, _site(key), period)


@router.get("/events")
def events(limit: int = 100, key: ApiKey = Depends(require_scope("stats")), db: Session = Depends(get_db)):
    return site_events(db, _site(key), limit)


# ------------------------------------------------------------------ records + config (scope: dns)

@router.get("/records")
def list_records(key: ApiKey = Depends(require_scope("dns"))):
    return list_records_of(_site(key))


@router.post("/records", status_code=201)
def add_record(body: RecordIn, request: Request, key: ApiKey = Depends(require_scope("dns")),
               db: Session = Depends(get_db)):
    result = add_record_of(db, _site(_rate_limit_config(key)), body)
    _audit(db, request, key, "record.create", {"type": body.type})
    return result


@router.patch("/records/{record_id}")
def update_record(record_id: int, body: RecordIn, request: Request,
                  key: ApiKey = Depends(require_scope("dns")), db: Session = Depends(get_db)):
    result = update_record_of(db, _site(_rate_limit_config(key)), record_id, body)
    _audit(db, request, key, "record.update", {"record_id": record_id, "type": body.type})
    return result


@router.delete("/records/{record_id}")
def delete_record(record_id: int, request: Request, key: ApiKey = Depends(require_scope("dns")),
                  db: Session = Depends(get_db)):
    result = delete_record_of(db, _site(_rate_limit_config(key)), record_id)
    _audit(db, request, key, "record.delete", {"record_id": record_id})
    return result


@router.get("/config/{section}")
def read_section(section: str, key: ApiKey = Depends(require_scope("dns"))):
    return read_section_of(_site(key), section)


@router.put("/config/{section}")
def write_section(section: str, body: dict, response: Response, request: Request,
                  key: ApiKey = Depends(require_scope("dns")), db: Session = Depends(get_db)):
    result = write_section_of(db, _site(_rate_limit_config(key)), section, body, response)
    _audit(db, request, key, "config.update", {"section": section})
    return result
