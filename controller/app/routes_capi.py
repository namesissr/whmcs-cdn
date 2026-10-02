"""Customer API surface `/capi/v1/*` (SPEC §10.1).

Authenticated by a per-service key (`Authorization: Bearer pcdn_...`), NOT the admin key.
The key resolves to exactly one site and every call is scoped to that site only; each key
carries a subset of the scopes (403 otherwise):

* ``purge``: cache purges;
* ``stats``: analytics, events, tunnel reports, function statistics (read only);
* ``dns``: DNS records and the `dns_secondary` section;
* ``config``: every other configuration section, redirect CSV import, image transform secret;
* ``functions``: the `functions` section (edge function code).

Security review M3: `dns` used to cover every config section and function code. Keys that existed
before the split (migration 0019) got `config` added to `dns`, but NOT `functions`.

M2: while the site is suspended a key can still READ (GET, analytics …) but every write (purge,
record / config changes, secret rotation) answers 403. All logic (purge, analytics, events, records, config) is reused from the admin
routes so behaviour/validation never drifts between the two surfaces.

SPEC §14.3.5: `GET /capi/v1/site` (any scope), `GET /capi/v1/analytics/live` (stats) and the
public `GET /capi/v1/openapi.json` describing these routes only (bearer security scheme).
"""

import math
import time

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.openapi.utils import get_openapi
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import sections, tunnel_quality
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
from .routes_platform import live_of
from .routes_tunnel import quality_of, usage_of
from .routes_v2 import (
    config_audit,
    csv_body,
    functions_stats_of,
    image_secret_create_of,
    image_secret_delete_of,
    import_redirects_of,
    read_section_of,
    site_analytics,
    site_events,
    write_section_of,
)
from .validation import fqdn

router = APIRouter(prefix="/capi/v1")

# Per-key sliding-window rate limiter. NOTE: this state lives in-process, so with several
# controller workers the effective limit is CAPI_RATE * (number of processes). Fine for the
# current single-process deployment; move to a shared store (Redis) if that changes.
_hits: dict[int, list[float]] = {}
# F5: a separate, tighter window for config/record *writes* only. A burst of these bumps the edge
# config version and can herd fleet-wide reloads, so they are limited beyond the general CAPI_RATE.
# Reads, purges and stats never touch this window.
_config_hits: dict[int, list[float]] = {}


def retry_after(window: list[float], now: float) -> dict[str, str]:
    """`Retry-After` for a full 60 s sliding window: seconds until its oldest hit leaves it."""
    return {"Retry-After": str(max(1, math.ceil(window[0] + 60 - now)) if window else 60)}


def _sliding(store: dict[int, list[float]], key_id: int, limit: int, label: str):
    now = time.monotonic()
    window = store.setdefault(key_id, [])
    window[:] = [t for t in window if t > now - 60]
    if len(window) >= limit:
        raise HTTPException(429, f"محدودیت نرخ {label} ({limit} در دقیقه) رد شد؛ کمی بعد دوباره تلاش کنید",
                            headers=retry_after(window, now))
    window.append(now)


def _rate_limit(key_id: int):
    _sliding(_hits, key_id, settings.capi_rate, "درخواست")


def _rate_limit_config(key: ApiKey) -> ApiKey:
    """F5: extra per-key limit for config/record write verbs (in addition to CAPI_RATE)."""
    _sliding(_config_hits, key.id, settings.capi_config_rate, "تغییر پیکربندی")
    return key


# the bearer scheme also documents the auth in the customer OpenAPI document (SPEC §14.3.5)
bearer = HTTPBearer(auto_error=False, scheme_name="bearerAuth",
                    description="Customer API key of one service: `Authorization: Bearer pcdn_…`")


def resolve_key(credentials: HTTPAuthorizationCredentials | None = Depends(bearer),
                db: Session = Depends(get_db)) -> ApiKey:
    """Resolve the bearer key to a non-revoked ApiKey, rate-limit it and update last_used_at.

    Only customer keys ('pcdn_...') are accepted here; the admin key never resolves. Unknown or
    revoked keys -> 401 JSON {"detail": ...}."""
    if credentials is None or not credentials.credentials:
        raise HTTPException(401, "missing bearer token")
    token = credentials.credentials.strip()
    if not token.startswith("pcdn_"):
        raise HTTPException(401, "invalid api key")
    key = db.scalar(select(ApiKey).where(ApiKey.key_hash == hash_token(token), ApiKey.revoked.is_(False)))
    if key is None:
        raise HTTPException(401, "invalid api key")
    _rate_limit(key.id)
    key.last_used_at = utcnow()
    db.commit()
    return key


def check_scope(key: ApiKey, scope: str, write: bool = False) -> ApiKey:
    """403 unless the key carries `scope`; for a write also 403 while the site is suspended (M2)."""
    if scope not in key.scope_list:
        raise HTTPException(403, f"این کلید دسترسی «{scope}» را ندارد")
    if write and key.site is not None and key.site.suspended:
        raise HTTPException(403, "سرویس معلق است؛ تا رفع تعلیق فقط خواندن از طریق API مجاز است")
    return key


def require_scope(scope: str, write: bool = False):
    """Dependency: resolve the key and require it to carry `scope` (403 otherwise); `write` also
    refuses a suspended site (M2)."""

    def dep(key: ApiKey = Depends(resolve_key)) -> ApiKey:
        return check_scope(key, scope, write)

    return dep


def section_scope(section: str) -> str:
    """The scope a config section needs (M3): functions -> functions, dns_secondary -> dns, else config."""
    if section == "functions":
        return "functions"
    if section == "dns_secondary":
        return "dns"
    return "config"


def _site(key: ApiKey) -> Site:
    return key.site


def _audit(db: Session, request: Request, key: ApiKey, action: str, detail: dict | None = None) -> None:
    """Record a customer-API mutation (SPEC §13.2). The actor is the key's name (or id) and the
    target is always the key's own site; secrets are stripped by record_audit."""
    actor = key.name or f"key:{key.id}"
    ip = request.client.host if request.client else None
    record_audit(db, actor=actor, actor_kind="capi", action=action, target=key.site.domain,
                 detail=detail, ip=ip)


# ------------------------------------------------------------------ site (any scope, SPEC §14.3.5)

def cname_target(site: Site) -> str | None:
    """The hostname another name can CNAME to in order to be served like this site's proxied
    hosts: the apex when it is proxied, else the first proxied hostname; None without one."""
    proxied = [r for r in site.records if r.proxied and r.type in ("A", "AAAA", "CNAME")]
    rec = next((r for r in proxied if r.name == "@"), proxied[0] if proxied else None)
    return fqdn(rec.name, site.domain) if rec is not None else None


@router.get("/site")
def site_info(key: ApiKey = Depends(resolve_key)):
    site = _site(key)
    return {
        "domain": site.domain,
        "status": site.effective_status,
        "suspended": bool(site.suspended),
        "plan": {"bandwidth_limit_gb": site.bandwidth_limit_gb, "max_records": site.max_records,
                 "ssl_allowed": site.ssl_allowed, "rate_limit_rps": site.rate_limit_rps,
                 "features": sections.features_of(site)},
        "nameservers": settings.nameservers,
        "cname_target": cname_target(site),
        "ssl_status": site.ssl_status,
    }


# ------------------------------------------------------------------ purge (scope: purge)

@router.post("/purge")
def purge(body: PurgeIn, request: Request, key: ApiKey = Depends(require_scope("purge", write=True)),
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


@router.get("/analytics/live")
def analytics_live(minutes: int = 60, key: ApiKey = Depends(require_scope("stats")),
                   db: Session = Depends(get_db)):
    """Per-minute series of the last `minutes` (1..1440) minutes (SPEC §14.3.1)."""
    return live_of(db, _site(key), minutes)


# ------------------------------------------------------------------ tunnel (scope: stats, SPEC §15.3/§15.4)

@router.get("/tunnel/quality")
def tunnel_quality_report(hours: int = 24, key: ApiKey = Depends(require_scope("stats")),
                          db: Session = Depends(get_db)):
    """Per-path / per-edge tunnel quality of the last `hours` (1..744) hours."""
    return quality_of(db, _site(key), hours)


@router.get("/tunnel/usage")
def tunnel_usage(days: int = 30, key: ApiKey = Depends(require_scope("stats")), db: Session = Depends(get_db)):
    """Daily tunnel usage of the last `days` (1..90) days and the month forecast."""
    return usage_of(db, _site(key), days)


@router.get("/tunnel/health")
def tunnel_health(key: ApiKey = Depends(require_scope("stats")), db: Session = Depends(get_db)):
    """Origin health of the site's tunnel paths as seen by the edges: up | down | unknown."""
    return tunnel_quality.health(db, _site(key))


# ------------------------------------------------------------------ edge functions (scope: stats, SPEC §16.9)

@router.get("/functions/stats")
def functions_stats(hours: int = 24, key: ApiKey = Depends(require_scope("stats")), db: Session = Depends(get_db)):
    """Invocations, CPU ms, errors and timeouts of the site's edge functions, last `hours` (1..744)."""
    return functions_stats_of(db, _site(key), hours)


# ------------------------------------------------------------------ records (scope: dns), config (config / functions)

@router.get("/records")
def list_records(key: ApiKey = Depends(require_scope("dns"))):
    return list_records_of(_site(key))


@router.post("/records", status_code=201)
def add_record(body: RecordIn, request: Request, key: ApiKey = Depends(require_scope("dns", write=True)),
               db: Session = Depends(get_db)):
    result = add_record_of(db, _site(_rate_limit_config(key)), body)
    _audit(db, request, key, "record.create", {"type": body.type})
    return result


@router.patch("/records/{record_id}")
def update_record(record_id: int, body: RecordIn, request: Request,
                  key: ApiKey = Depends(require_scope("dns", write=True)), db: Session = Depends(get_db)):
    result = update_record_of(db, _site(_rate_limit_config(key)), record_id, body)
    _audit(db, request, key, "record.update", {"record_id": record_id, "type": body.type})
    return result


@router.delete("/records/{record_id}")
def delete_record(record_id: int, request: Request, key: ApiKey = Depends(require_scope("dns", write=True)),
                  db: Session = Depends(get_db)):
    result = delete_record_of(db, _site(_rate_limit_config(key)), record_id)
    _audit(db, request, key, "record.delete", {"record_id": record_id})
    return result


@router.get("/config/{section}")
def read_section(section: str, key: ApiKey = Depends(resolve_key)):
    check_scope(key, section_scope(section))
    return read_section_of(_site(key), section)


@router.put("/config/{section}")
def write_section(section: str, body: dict, response: Response, request: Request,
                  key: ApiKey = Depends(resolve_key), db: Session = Depends(get_db)):
    check_scope(key, section_scope(section), write=True)
    result = write_section_of(db, _site(_rate_limit_config(key)), section, body, response)
    _audit(db, request, key, "config.update", config_audit(section, result))
    return result


@router.post("/redirects/import")
def import_redirects(request: Request, response: Response, mode: str | None = None,
                     body: dict = Depends(csv_body), key: ApiKey = Depends(require_scope("config", write=True)),
                     db: Session = Depends(get_db)):
    """Bulk CSV import of redirect rules (SPEC §14.2), same rules as the admin endpoint."""
    mode = body["mode"] or mode or "append"
    result = import_redirects_of(db, _site(_rate_limit_config(key)), body["csv"], mode, response)
    _audit(db, request, key, "redirects.import", {"count": result["imported"], "mode": mode})
    return result


@router.post("/image/transform-secret")
def image_secret_create(request: Request, key: ApiKey = Depends(require_scope("config", write=True)),
                        db: Session = Depends(get_db)):
    """Generate a new signed-URL key for image transforms (SPEC §16.6); shown this once."""
    result = image_secret_create_of(db, _site(_rate_limit_config(key)))
    _audit(db, request, key, "image.transform_secret", {"mode": "rotate"})
    return result


@router.delete("/image/transform-secret")
def image_secret_delete(request: Request, key: ApiKey = Depends(require_scope("config", write=True)),
                        db: Session = Depends(get_db)):
    result = image_secret_delete_of(db, _site(_rate_limit_config(key)))
    _audit(db, request, key, "image.transform_secret", {"mode": "remove"})
    return result


# ------------------------------------------------------------------ OpenAPI (public, SPEC §14.3.5)

_openapi: dict | None = None


@router.get("/openapi.json", include_in_schema=False)
def openapi():
    """OpenAPI 3 document of the /capi/v1 routes only (no admin or edge paths), with the bearer
    security scheme. Public: it describes the API, it grants nothing."""
    global _openapi
    if _openapi is None:
        _openapi = get_openapi(
            title="Pasargad CDN customer API", version="1",
            description="Per-service API (SPEC §10.1 / §14.3.5). Authenticate with "
                        "`Authorization: Bearer pcdn_…`; every call acts on that key's site only. "
                        "Scopes: purge, stats, dns (records, secondary DNS), config (configuration "
                        "sections), functions (edge function code). Writes answer 403 while the "
                        "service is suspended.",
            routes=[r for r in router.routes if getattr(r, "path", "").startswith(router.prefix + "/")])
    return _openapi
