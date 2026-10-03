"""Wave 14 (SPEC §23) per-site customer-experience API (admin surface; the capi twins live in
routes_capi.py and reuse the *_of helpers here): config history + restore (§23.4), provider import
(§23.6), RUM (§23.7), diagnostics report (§23.8).

This router is included BEFORE routes_v2 so `/config/history` is not taken for a section name.
"""

import json
import re

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import Response
from sqlalchemy.orm import Session

from . import config_history, config_restore, diagnostics, importer, rum, sections
from .audit import record_audit, with_actor
from .auth import require_admin
from .config import settings
from .db import SessionLocal, get_db
from .models import Site
from .routes_admin import get_site

router = APIRouter(prefix="/api/v1", dependencies=[Depends(require_admin)])

SECTION_RE = re.compile(r"^[a-z_0-9]{1,32}$")


def _audit(db: Session, request: Request, action: str, target: str | None, detail: dict | None = None):
    ip = request.client.host if request.client else None
    record_audit(db, actor="admin", actor_kind="admin", action=action, target=target,
                 detail=with_actor(detail, request), ip=ip)


# ------------------------------------------------------------------ config history (§23.4)

def _history_on():
    if not settings.config_history_enabled:
        raise HTTPException(404, "config history is disabled")


def history_of(db: Session, site: Site, limit: int, before: int | None, functions: bool = True) -> dict:
    _history_on()
    if not 1 <= limit <= 200:
        raise HTTPException(422, "limit must be 1..200")
    return config_history.history(db, site, limit, before)


def version_of(db: Session, site: Site, version: int, functions: bool = True) -> dict:
    _history_on()
    v = config_history.get_version(db, site.id, version)
    if v is None:
        raise HTTPException(404, "version not found")
    cfg = config_history.config_at(db, site.id, version) or {}
    view = {}
    for name, value in cfg.items():
        if name == "functions" and not functions:
            continue
        if name == "functions" and isinstance(value, dict) and not config_history.is_omitted(value):
            value = {**value, "items": [{k: x for k, x in i.items() if k != "code"} for i in value.get("items", [])]}
        view[name] = config_history.redact_value(name, value)
    d = config_history.version_dict(v, config_history.current_version(db, site.id))
    return {"version": d["version"], "at": d["at"], "actor": d["actor"], "source": d["source"],
            "sections": d["sections"], "restored_from": d["restored_from"], "config": view}


def diff_of(db: Session, site: Site, version: int, against: str, section: str | None,
            functions: bool = True) -> dict:
    _history_on()
    if config_history.get_version(db, site.id, version) is None:
        raise HTTPException(404, "version not found")
    if section is not None and section not in sections.SECTIONS:
        raise HTTPException(422, "unknown section")
    if section == "functions" and not functions:
        raise HTTPException(403, "این کلید دسترسی «functions» را ندارد")
    a = config_history.config_at(db, site.id, version) or {}
    if against == "current":
        stored = config_history._stored(site.config)
        b = {n: config_history.section_value(stored, n) for n in sections.SECTIONS}
        to = "current"
    elif re.match(r"^\d{1,9}$", against or ""):
        if config_history.get_version(db, site.id, int(against)) is None:
            raise HTTPException(404, "version not found")
        b = config_history.config_at(db, site.id, int(against)) or {}
        to = int(against)
    else:
        raise HTTPException(422, "against must be current or a version")
    names = [section] if section else [n for n in sections.SECTIONS if functions or n != "functions"]
    out, redacted = {}, False
    for n in names:
        ops = config_history.section_diff(n, a.get(n), b.get(n))
        if ops:
            out[n] = ops
            redacted = redacted or any(o.get("redacted") for o in ops)
    return {"from": version, "to": to, "sections": out, "redacted": redacted}


def restore_of(db: Session, site: Site, version: int, body: dict, functions: bool = True) -> dict:
    _history_on()
    wanted = body.get("sections")
    if wanted is not None and (not isinstance(wanted, list) or not all(isinstance(x, str) for x in wanted)):
        raise HTTPException(422, "sections must be a list of section names or null")
    if wanted is not None and "functions" in wanted and not functions:
        raise HTTPException(403, "این کلید دسترسی «functions» را ندارد")
    return config_restore.restore(db, site, version, wanted, bool(body.get("dry_run")),
                                  exclude=() if functions else ("functions",))


@router.get("/sites/{domain}/config/history")
def config_history_list(domain: str, limit: int = 50, before: int | None = None, db: Session = Depends(get_db)):
    return history_of(db, get_site(db, domain), limit, before)


@router.get("/sites/{domain}/config/history/{version}")
def config_history_version(domain: str, version: int, db: Session = Depends(get_db)):
    return version_of(db, get_site(db, domain), version)


@router.get("/sites/{domain}/config/history/{version}/diff")
def config_history_diff(domain: str, version: int, against: str = "current", section: str | None = None,
                        db: Session = Depends(get_db)):
    return diff_of(db, get_site(db, domain), version, against, section)


@router.post("/sites/{domain}/config/history/{version}/restore")
def config_history_restore(domain: str, version: int, request: Request, body: dict | None = None,
                           db: Session = Depends(get_db)):
    site = get_site(db, domain)
    result = restore_of(db, site, version, body or {})
    if not (body or {}).get("dry_run"):
        _audit(db, request, "config.restore", site.domain, {"section": result["applied"], "record_id": version})
    return result


# ------------------------------------------------------------------ import (§23.6)
#
# The provider key travels only in the preview body: the body is parsed here (never by FastAPI's
# validation, whose 422 would echo the input), the key is passed to the importer and dropped.

GENERIC_422 = {"detail": "invalid request"}


async def _json_body(request: Request) -> dict:
    try:
        raw = await request.body()
        body = json.loads(raw or b"{}")
    except (ValueError, UnicodeDecodeError):
        raise HTTPException(422, GENERIC_422["detail"]) from None
    if not isinstance(body, dict):
        raise HTTPException(422, GENERIC_422["detail"])
    return body


def preview_of(site_id: int, body: dict) -> dict:
    provider, key, zone = body.get("provider"), body.get("api_key"), body.get("zone")
    if provider not in importer.PROVIDERS or not isinstance(key, str) or not key or len(key) > 512 \
            or (zone is not None and not isinstance(zone, str)):
        raise HTTPException(422, GENERIC_422["detail"])
    db = SessionLocal()
    try:
        site = db.get(Site, site_id)
        return importer.preview(db, site, provider, key, zone)
    finally:
        db.close()


def apply_of(db: Session, site: Site, body: dict) -> dict:
    sid = body.get("session_id")
    secs = body.get("sections") or []
    names = body.get("record_names")
    if not isinstance(sid, str) or not isinstance(secs, list) or (names is not None and not isinstance(names, list)):
        raise HTTPException(422, GENERIC_422["detail"])
    if not settings.import_enabled:
        raise HTTPException(404, "import is disabled")
    return importer.apply(db, site, sid, bool(body.get("records", True)), bool(body.get("replace_records")),
                          [str(n) for n in names] if names is not None else None, [str(s) for s in secs])


@router.post("/sites/{domain}/import/preview")
async def import_preview(domain: str, request: Request, db: Session = Depends(get_db)):
    site = get_site(db, domain)
    body = await _json_body(request)
    return await run_in_threadpool(preview_of, site.id, body)


@router.post("/sites/{domain}/import/apply")
async def import_apply(domain: str, request: Request, db: Session = Depends(get_db)):
    site = get_site(db, domain)
    body = await _json_body(request)
    result = await run_in_threadpool(apply_of, db, site, body)
    await run_in_threadpool(_audit, db, request, "import.apply", site.domain,
                            {"mode": result["provider"], "count": result["records"]["imported"],
                             "section": result["sections"]["applied"]})
    return result


@router.delete("/sites/{domain}/import/{session_id}", status_code=204)
def import_delete(domain: str, session_id: str, db: Session = Depends(get_db)):
    importer.drop(db, get_site(db, domain), session_id)
    return Response(status_code=204)


# ------------------------------------------------------------------ RUM (§23.7)

def rum_of(db: Session, site: Site, hours: int, by: str | None) -> dict:
    if not sections.features_of(site).get("rum"):
        raise HTTPException(404, "RUM is not in this plan")
    if hours not in rum.HOURS:
        raise HTTPException(422, "hours must be 24, 168 or 720")
    if by is not None and by not in rum.BY_DIM:
        raise HTTPException(422, "by must be country, isp, region, device or path")
    return rum.report(db, site, hours, by)


@router.get("/sites/{domain}/rum")
def rum_report(domain: str, hours: int = 24, by: str | None = None, db: Session = Depends(get_db)):
    return rum_of(db, get_site(db, domain), hours, by)


# ------------------------------------------------------------------ diagnostics (§23.8)

def diagnostics_of(db: Session, site: Site, audience: str) -> dict:
    if audience not in ("customer", "admin"):
        raise HTTPException(422, "audience must be customer or admin")
    if not diagnostics.rate_limit(site.id):
        raise HTTPException(429, "rate_limited")
    return diagnostics.build(db, site, audience)


@router.get("/sites/{domain}/diagnostics")
def diagnostics_report(domain: str, request: Request, audience: str = "customer", db: Session = Depends(get_db)):
    site = get_site(db, domain)
    report = diagnostics_of(db, site, audience)
    _audit(db, request, "diagnostics.generate", site.domain, {"items": report["report_id"]})
    return report
