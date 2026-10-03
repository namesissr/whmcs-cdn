"""Migration from ArvanCloud / Cloudflare (SPEC §23.6): preview sessions and apply.

Key handling (the core rule): the customer's provider API key is used only inside the preview request:
it is held in a local variable, sent to the provider over HTTPS and dropped when the request ends. It is
never stored (database, state, files, cache), logged, audited, put into an exception message, returned
or echoed by a validation error (routes answer a generic 422 for malformed bodies). What IS kept is the
provider data fetched with it, encrypted with crypto.encrypt in `import_sessions.data` for
IMPORT_SESSION_MINUTES and deleted on apply, expiry or DELETE. Without DATA_ENCRYPTION_KEY the session
lives in this process's memory only (single instance).
"""

import json
import re
import secrets
import threading
import time
from datetime import datetime, timedelta

import pydantic
from fastapi import HTTPException
from sqlalchemy import delete
from sqlalchemy.orm import Session

from . import config_history, config_restore, crypto, sections
from .config import settings
from .importers import ProviderError, arvan, cloudflare
from .models import ImportSession, Record, Site, utcnow
from .services import lock_site, sync_site_dns
from .validation import ValidationError, normalize_domain

PROVIDERS = {"arvan": arvan, "cloudflare": cloudflare}
SESSION_RE = re.compile(r"^imp_[0-9a-f]{16}$")
PREVIEWS_PER_HOUR = 10
SECTION_NAMES = ("cache", "ssl", "firewall", "redirects", "ddos", "ratelimit")

_memory: dict[str, dict] = {}
_previews: dict[int, list[float]] = {}
_lock = threading.Lock()


def _rate(site_id: int) -> None:
    now = time.monotonic()
    with _lock:
        hits = [t for t in _previews.get(site_id, []) if t > now - 3600]
        if len(hits) >= PREVIEWS_PER_HOUR:
            _previews[site_id] = hits
            raise HTTPException(429, "rate_limited")
        hits.append(now)
        _previews[site_id] = hits


def _iso(dt: datetime) -> str:
    return dt.isoformat() + "Z"


# ------------------------------------------------------------------ sessions

def _save(db: Session, sid: str, site: Site, provider: str, data: dict, expires: datetime) -> None:
    raw = json.dumps(data, ensure_ascii=False)
    if crypto.enabled():
        db.add(ImportSession(id=sid, site_id=site.id, provider=provider, data=crypto.encrypt(raw),
                             created_at=utcnow(), expires_at=expires))
        db.commit()
    else:
        with _lock:
            _memory[sid] = {"site_id": site.id, "provider": provider, "data": raw, "expires_at": expires}


def load(db: Session, site: Site, sid: str) -> tuple[str, dict]:
    if not SESSION_RE.match(sid or ""):
        raise HTTPException(404, "import session not found")
    now = utcnow()
    row = db.get(ImportSession, sid)
    if row is not None:
        if row.site_id != site.id or row.expires_at < now:
            raise HTTPException(404, "import session not found")
        try:
            return row.provider, json.loads(crypto.decrypt(row.data))
        except (crypto.CryptoError, ValueError):
            raise HTTPException(404, "import session not found") from None
    with _lock:
        m = _memory.get(sid)
    if m is None or m["site_id"] != site.id or m["expires_at"] < now:
        raise HTTPException(404, "import session not found")
    return m["provider"], json.loads(m["data"])


def drop(db: Session, site: Site, sid: str) -> None:
    if SESSION_RE.match(sid or ""):
        db.execute(delete(ImportSession).where(ImportSession.id == sid, ImportSession.site_id == site.id))
        db.commit()
        with _lock:
            m = _memory.get(sid)
            if m is not None and m["site_id"] == site.id:
                _memory.pop(sid, None)


def prune(db: Session, now: datetime | None = None) -> None:
    now = now or utcnow()
    db.execute(delete(ImportSession).where(ImportSession.expires_at < now))
    with _lock:
        for k in [k for k, v in _memory.items() if v["expires_at"] < now]:
            _memory.pop(k, None)


# ------------------------------------------------------------------ preview

def _record_status(site: Site, rec: dict, seen: set, budget: list) -> tuple[str, str | None]:
    from .routes_admin import RecordIn, _conflicts, _record_from
    from .validation import normalize_name

    if rec.get("status"):
        return rec["status"], rec.get("reason")
    key = (rec["name"], rec["type"], rec["content"])
    if key in seen:
        return "duplicate", "تکراری در داده‌های ارائه‌دهنده"
    if any(r.name == rec["name"] and r.type == rec["type"] and r.content.rstrip(".") == rec["content"]
           for r in site.records):
        return "duplicate", "این رکورد از قبل وجود دارد"
    try:
        name = normalize_name(rec["name"], site.domain)
        _conflicts(site, name, rec["type"], weighted=rec.get("weight") is not None)
    except ValidationError as e:
        return "conflict", str(e)[:200]
    try:
        _record_from(site, _record_in(RecordIn, rec))
    except (ValidationError, PermissionError, pydantic.ValidationError, ValueError) as e:
        msg = str(e)[:200] if not isinstance(e, pydantic.ValidationError) else "مقدار نامعتبر"
        return "invalid", msg
    if budget[0] <= 0:
        return "limit", "سقف تعداد رکوردهای پلن"
    budget[0] -= 1
    seen.add(key)
    return "ok", None


def _record_in(RecordIn, rec: dict):
    kw = {"name": rec["name"], "type": rec["type"], "content": rec["content"], "ttl": rec["ttl"],
          "priority": rec.get("priority"), "proxied": bool(rec.get("proxied"))}
    if rec.get("weight") is not None:
        kw["weight"] = rec["weight"]
    if rec.get("origin_port"):
        kw["origin_port"] = rec["origin_port"]
    return RecordIn(**kw)


def _proposed(site: Site, name: str, mapped: dict) -> dict | None:
    """The full section value the import would write: the current section + the mapped fields/rules."""
    if mapped.get("status") == "none":
        return None
    current = sections.storable(name, sections.get_section(site, name))
    if "rules" in mapped:
        if not mapped["rules"]:
            return None
        taken = {r.get("id") for r in current.get("rules", [])}
        rules = [r for r in mapped["rules"] if r["id"] not in taken]
        return {**current, "rules": current.get("rules", []) + rules}
    fields = mapped.get("fields") or {}
    if not fields:
        return None
    out = dict(current)
    for k, v in fields.items():
        out[k] = {**(current.get(k) or {}), **v} if isinstance(v, dict) and isinstance(current.get(k), dict) else v
    return out


def preview(db: Session, site: Site, provider: str, api_key: str, zone: str | None) -> dict:
    if not settings.import_enabled:
        raise HTTPException(404, "import is disabled")
    module = PROVIDERS.get(provider)
    if module is None or not api_key or len(api_key) > 512:
        raise HTTPException(422, "invalid request")
    try:
        zone = normalize_domain(zone) if zone else site.domain
    except ValidationError:
        raise HTTPException(422, "invalid request") from None
    _rate(site.id)
    try:
        raw = module.fetch(api_key, zone)
    except ProviderError as e:
        raise HTTPException(e.status, e.detail) from None
    finally:
        api_key = None  # noqa: F841 - dropped here; never stored anywhere
    records, secs, unmapped = module.map_all(raw, zone)
    seen: set = set()
    budget = [max(0, site.max_records - len(site.records))]
    items = []
    for rec in records:
        status, reason = _record_status(site, rec, seen, budget)
        items.append({"name": rec["name"], "type": rec["type"], "content": rec["content"], "ttl": rec["ttl"],
                      "proxied": bool(rec.get("proxied")), "priority": rec.get("priority"),
                      "status": status, "reason": reason,
                      **({"weight": rec["weight"]} if rec.get("weight") is not None else {}),
                      **({"origin_port": rec["origin_port"]} if rec.get("origin_port") else {})})
    sec_report = {}
    for name in SECTION_NAMES:
        m = secs.get(name)
        if m is None:
            continue
        sec_report[name] = {"status": m["status"], "value": _proposed(site, name, m), "notes": m.get("notes", [])}
    sid = "imp_" + secrets.token_hex(8)
    expires = utcnow() + timedelta(minutes=settings.import_session_minutes)
    _save(db, sid, site, provider, {"zone": zone, "records": items,
                                    "sections": {k: secs[k] for k in sec_report}}, expires)
    return {"session_id": sid, "expires_at": _iso(expires), "provider": provider, "zone": zone,
            "report": {"records": {"total": len(items), "importable": sum(1 for i in items if i["status"] == "ok"),
                                   "items": items},
                       "sections": sec_report, "unmapped": unmapped}}


# ------------------------------------------------------------------ apply

def apply(db: Session, site: Site, sid: str, records: bool, replace_records: bool,
          record_names: list[str] | None, wanted_sections: list[str]) -> dict:
    from .routes_admin import RecordIn, _record_from

    provider, data = load(db, site, sid)
    bad_sections = [s for s in wanted_sections if s not in SECTION_NAMES]
    if bad_sections:
        raise HTTPException(422, f"unknown section: {bad_sections[0]}")
    imported, skipped = 0, []
    before = config_history.current_version(db, site.id)
    with config_history.source("import"):
        site = lock_site(db, site)
        if records:
            if replace_records:
                site.records.clear()
            names = set(record_names) if record_names is not None else None
            for rec in data.get("records") or []:
                if names is not None and rec["name"] not in names:
                    continue
                if rec.get("status") not in ("ok", "duplicate", "conflict", "limit"):
                    skipped.append({"name": rec["name"], "reason": rec.get("reason") or rec.get("status")})
                    continue
                if len(site.records) >= site.max_records:
                    skipped.append({"name": rec["name"], "reason": "سقف تعداد رکوردها"})
                    continue
                if any(r.name == rec["name"] and r.type == rec["type"] and r.content.rstrip(".") == rec["content"]
                       for r in site.records):
                    skipped.append({"name": rec["name"], "reason": "تکراری"})
                    continue
                try:
                    site.records.append(Record(**_record_from(site, _record_in(RecordIn, rec))))
                    imported += 1
                except (ValidationError, PermissionError, pydantic.ValidationError, ValueError) as e:
                    msg = str(e)[:200] if not isinstance(e, pydantic.ValidationError) else "مقدار نامعتبر"
                    skipped.append({"name": rec["name"], "reason": msg})
        values = {}
        for name in wanted_sections:
            m = (data.get("sections") or {}).get(name)
            value = _proposed(site, name, m) if m else None
            if value is not None:
                values[name] = value
        result = config_restore.apply_sections(db, site, values) if values else \
            {"applied": [], "dropped": [], "warnings": [], "touched": []}
        for name in wanted_sections:
            if name not in values:
                result["dropped"].append({"section": name, "reason": "nothing_to_import"})
        db.commit()
    after = config_history.current_version(db, site.id)
    drop(db, site, sid)
    dns_error = sync_site_dns(db, site) if (imported or replace_records) else None
    return {"provider": provider, "records": {"imported": imported, "skipped": skipped},
            "sections": {"applied": result["applied"], "dropped": result["dropped"], "warnings": result["warnings"]},
            "config_version": after if after != before else None, "dns_error": dns_error}
