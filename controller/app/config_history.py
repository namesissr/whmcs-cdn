"""Site configuration history (SPEC §23.4): versions, diff with secret redaction, restore.

Capture: a SQLAlchemy `before_flush` listener sees every `Site` whose `config` attribute changed and
appends one version holding only the sections whose canonical sha256 changed — so every writer
(section PUT, legacy settings PATCH, l4, WAF learning, transfer, imports, restores) is covered
without touching each call site. The actor comes from the context variable `ACTOR` (set per request by
the ASGI middleware in main.py, by the capi key resolver and by the scheduler per job).

Stored values are the `storable()` form already kept in `sites.config`: they never contain write-only
secrets (those live in `site_secrets`). `functions` larger than 1 MiB are stored as
{"_omitted": true, "sha256", "ids"} and are not restorable from that version.
"""

import contextvars
import hashlib
import json
import logging
import re
from contextlib import contextmanager
from datetime import datetime, timedelta

from sqlalchemy import delete, event, func, inspect, select
from sqlalchemy.orm import Session

from . import sections
from .config import settings
from .models import Site, SiteConfigValue, SiteConfigVersion, utcnow

log = logging.getLogger("pcdn.config_history")

FUNCTIONS_MAX_BYTES = 1024 * 1024
RESTORES_PER_HOUR = 10
SOURCES = ("api", "capi", "admin", "restore", "import", "waf_learning", "transfer", "system")

# {"kind": admin|capi|system, "actor": str, "on_behalf_of": str|None, "source": str,
#  "key_name": str|None, "key_id": int|None, "restored_from": int|None}. A mutable dict so a sync
# dependency (capi key resolver) can complete what the middleware started.
ACTOR: contextvars.ContextVar[dict | None] = contextvars.ContextVar("pcdn_config_actor", default=None)


def set_actor(**kw) -> contextvars.Token:
    return ACTOR.set(dict(kw))


def update_actor(**kw) -> None:
    ctx = ACTOR.get()
    if ctx is not None:
        ctx.update(kw)


@contextmanager
def source(name: str, **extra):
    """Run a block with an explicit history source (restore / import / transfer / waf_learning)."""
    prev = ACTOR.get()
    ctx = dict(prev or {"kind": "system", "actor": "system"})
    ctx.update(source=name, **extra)
    token = ACTOR.set(ctx)
    try:
        yield ctx
    finally:
        ACTOR.reset(token)


def _ctx() -> dict:
    return ACTOR.get() or {"kind": "system", "actor": "system", "source": "system"}


# ------------------------------------------------------------------ canonical values

def canonical(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha(value) -> str:
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def _default(name: str) -> dict:
    return sections.storable(name, sections.dump(sections.SECTIONS[name]()))


def _stored(raw: str | None) -> dict:
    try:
        d = json.loads(raw or "{}")
    except ValueError:
        return {}
    return d if isinstance(d, dict) else {}


def section_value(stored: dict, name: str):
    return stored[name] if name in stored else _default(name)


def _storage_form(name: str, value) -> str:
    """The text kept in site_config_values (functions > 1 MiB -> an omitted marker)."""
    text = canonical(value)
    if name == "functions" and len(text.encode()) > FUNCTIONS_MAX_BYTES:
        ids = [i.get("id") for i in (value or {}).get("items", []) if isinstance(i, dict)]
        return canonical({"_omitted": True, "sha256": sha(value), "ids": ids})
    return text


def is_omitted(value) -> bool:
    return isinstance(value, dict) and value.get("_omitted") is True


# ------------------------------------------------------------------ capture (before_flush)

def _next_version(db: Session, site_id: int) -> int:
    return int(db.scalar(select(func.coalesce(func.max(SiteConfigVersion.version), 0))
                         .where(SiteConfigVersion.site_id == site_id)) or 0) + 1


def _add_version(db: Session, site_id: int, number: int, changed: dict, ctx: dict, now: datetime) -> None:
    src = ctx.get("source") or ("system" if ctx.get("kind") == "system" else
                                "capi" if ctx.get("kind") == "capi" else
                                "api" if ctx.get("on_behalf_of") else "admin")
    ver = SiteConfigVersion(site_id=site_id, version=number, at=now, actor_kind=str(ctx.get("kind") or "system")[:16],
                            actor=str(ctx.get("actor") or "")[:120],
                            on_behalf_of=(str(ctx["on_behalf_of"])[:64] if ctx.get("on_behalf_of") else None),
                            source=src[:16] if src in SOURCES else "system",
                            sections=json.dumps(sorted(changed)), restored_from=ctx.get("restored_from"))
    for name, value in sorted(changed.items()):
        ver.values.append(SiteConfigValue(section=name, sha256=sha(value), value=_storage_form(name, value)))
    db.add(ver)


def capture(db: Session, site: Site, old_raw: str | None, new_raw: str | None, now: datetime | None = None) -> bool:
    """Append a version for the sections that differ between old and new stored config; True when one
    was added. A site without history first gets a baseline version of the old config."""
    if not settings.config_history_enabled or site.id is None:
        return False
    old, new = _stored(old_raw), _stored(new_raw)
    changed = {}
    for name in sections.SECTIONS:
        nv = section_value(new, name)
        if sha(section_value(old, name)) != sha(nv):
            changed[name] = nv
    if not changed:
        return False
    now = now or utcnow()
    number = _next_version(db, site.id)
    ctx = _ctx()
    if number == 1 and old:
        # first capture of an existing site: a baseline of what it had (system), then the change
        base = {n: old[n] for n in sections.SECTIONS if n in old}
        if base:
            _add_version(db, site.id, 1, base, {"kind": "system", "actor": "baseline", "source": "system"},
                         now - timedelta(microseconds=1))
            number = 2
    _add_version(db, site.id, number, changed, ctx, now)
    return True


@event.listens_for(Session, "before_flush")
def _before_flush(session: Session, flush_context, instances):
    if not settings.config_history_enabled:
        return
    try:
        for obj in list(session.dirty):
            if not isinstance(obj, Site) or obj.id is None:
                continue
            hist = inspect(obj).attrs.config.history
            if not hist.has_changes():
                continue
            new_raw = obj.config
            if hist.deleted:
                old_raw = hist.deleted[0]
            else:  # attribute was not loaded before the change: the newest captured state
                with session.no_autoflush:
                    old_raw = canonical(config_at(session, obj.id, None) or {})
            with session.no_autoflush:
                capture(session, obj, old_raw, new_raw)
    except Exception:  # noqa: BLE001 - history must never break a configuration write
        log.exception("config history capture failed")


# ------------------------------------------------------------------ reading

def current_version(db: Session, site_id: int) -> int:
    return int(db.scalar(select(func.coalesce(func.max(SiteConfigVersion.version), 0))
                         .where(SiteConfigVersion.site_id == site_id)) or 0)


def get_version(db: Session, site_id: int, number: int) -> SiteConfigVersion | None:
    return db.scalar(select(SiteConfigVersion).where(SiteConfigVersion.site_id == site_id,
                                                     SiteConfigVersion.version == number))


def config_at(db: Session, site_id: int, number: int | None) -> dict | None:
    """{section: stored value} as of version `number` (None = newest); None when no version exists."""
    q = select(SiteConfigValue.section, SiteConfigValue.value, SiteConfigVersion.version).join(
        SiteConfigVersion, SiteConfigVersion.id == SiteConfigValue.version_id).where(
        SiteConfigVersion.site_id == site_id)
    if number is not None:
        q = q.where(SiteConfigVersion.version <= number)
    rows = db.execute(q.order_by(SiteConfigVersion.version)).all()
    if not rows and not db.scalar(select(func.count(SiteConfigVersion.id)).where(SiteConfigVersion.site_id == site_id)):
        return None
    out = {}
    for name, value, _ in rows:  # oldest first: newer values overwrite
        try:
            out[name] = json.loads(value)
        except ValueError:
            continue
    for name in sections.SECTIONS:
        out.setdefault(name, _default(name))
    return out


_FA_KIND = {"admin": "support", "capi": "api_key", "system": "system"}


def actor_view(v: SiteConfigVersion) -> dict:
    """SPEC §23.4 actor mapping; the internal admin label is never shown."""
    if v.actor_kind == "admin":
        who = v.on_behalf_of or ""
        m = re.match(r"^client:(\d+)$", who)
        if m:
            return {"kind": "client", "label": None, "id": m.group(1)}
        m = re.match(r"^share:(\d+):[a-z_-]+$", who)
        if m:
            return {"kind": "collaborator", "label": None, "id": m.group(1)}
        return {"kind": "support", "label": None, "id": None}
    if v.actor_kind == "capi":
        m = re.match(r"^key:(\d+):(.*)$", v.actor or "")
        if m:
            return {"kind": "api_key", "label": m.group(2) or None, "id": m.group(1)}
        return {"kind": "api_key", "label": v.actor or None, "id": None}
    label = v.source if v.source not in ("system", "api", "admin", "capi") else None
    if v.actor == "baseline":
        label = "baseline"
    return {"kind": "system", "label": label, "id": None}


def _iso(dt: datetime | None) -> str | None:
    return dt.isoformat() + "Z" if dt else None


def version_dict(v: SiteConfigVersion, current: int) -> dict:
    try:
        secs = json.loads(v.sections or "[]")
    except ValueError:
        secs = []
    return {"version": v.version, "at": _iso(v.at), "actor": actor_view(v), "source": v.source,
            "sections": secs, "restored_from": v.restored_from, "restorable": v.version != current}


def history(db: Session, site: Site, limit: int = 50, before: int | None = None) -> dict:
    q = select(SiteConfigVersion).where(SiteConfigVersion.site_id == site.id)
    if before is not None:
        q = q.where(SiteConfigVersion.version < before)
    rows = list(db.scalars(q.order_by(SiteConfigVersion.version.desc()).limit(limit)))
    cur = current_version(db, site.id)
    return {"versions": [version_dict(v, cur) for v in rows], "current": cur,
            "retention": {"max_versions": settings.config_history_max_versions,
                          "days": settings.config_history_days}}


# ------------------------------------------------------------------ redaction (§23.4)

SECRET_KEY_RE = re.compile(r"(?i)secret|password|passwd|token|api_?key|private|signature|cookie|authorization")
SENSITIVE_HEADERS = {"authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key", "x-auth-token"}
REDACTED = "[redacted]"


def _redact(node, section: str, key: str | None = None):
    if isinstance(node, dict):
        out = {}
        hdr = str(node.get("name") or "").lower() if section in ("headers", "transform") else ""
        for k, v in node.items():
            if section == "logs" and k == "access_key" and isinstance(v, str):
                out[k] = (v[:4] + "…") if v else ""
            elif section == "functions" and k == "code":
                out["code_sha256"] = hashlib.sha256(str(v or "").encode()).hexdigest()
            elif SECRET_KEY_RE.search(str(k)) and not isinstance(v, bool) and k not in ("secret_key_set", "secret_set"):
                out[k] = REDACTED if v not in (None, "", [], {}) else v
            elif k == "value" and hdr in SENSITIVE_HEADERS and v not in (None, ""):
                out[k] = REDACTED
            else:
                out[k] = _redact(v, section, k)
        return out
    if isinstance(node, list):
        return [_redact(x, section, key) for x in node]
    return node


def redact_value(section: str, value):
    """A section value with secrets replaced by "[redacted]" (diffs and version views)."""
    return _redact(value, section)


# ------------------------------------------------------------------ diff (§23.4)

def _esc(seg: str) -> str:
    return str(seg).replace("~", "~0").replace("/", "~1")


def diff(a, b, path: str = "") -> list[dict]:
    """JSON-pointer ops turning `a` into `b`; list items with an `id` are matched by id
    (`/rules/[id=r1]/action`), others by index."""
    if isinstance(a, dict) and isinstance(b, dict):
        ops = []
        for k in sorted(set(a) | set(b), key=str):
            p = f"{path}/{_esc(k)}"
            if k not in a:
                ops.append({"op": "add", "path": p, "old": None, "new": b[k]})
            elif k not in b:
                ops.append({"op": "remove", "path": p, "old": a[k], "new": None})
            else:
                ops += diff(a[k], b[k], p)
        return ops
    if isinstance(a, list) and isinstance(b, list):
        ids_a = [x.get("id") for x in a if isinstance(x, dict)]
        ids_b = [x.get("id") for x in b if isinstance(x, dict)]
        if (a or b) and all(isinstance(x, dict) and x.get("id") for x in a + b) \
                and len(set(ids_a)) == len(ids_a) and len(set(ids_b)) == len(ids_b):
            ops = []
            ma, mb = {x["id"]: x for x in a}, {x["id"]: x for x in b}
            for i in ids_a + [x for x in ids_b if x not in ma]:
                p = f"{path}/[id={_esc(i)}]"
                if i not in mb:
                    ops.append({"op": "remove", "path": p, "old": ma[i], "new": None})
                elif i not in ma:
                    ops.append({"op": "add", "path": p, "old": None, "new": mb[i]})
                else:
                    ops += diff(ma[i], mb[i], p)
            return ops
        ops = []
        for i in range(max(len(a), len(b))):
            p = f"{path}/{i}"
            if i >= len(a):
                ops.append({"op": "add", "path": p, "old": None, "new": b[i]})
            elif i >= len(b):
                ops.append({"op": "remove", "path": p, "old": a[i], "new": None})
            else:
                ops += diff(a[i], b[i], p)
        return ops
    if canonical(a) == canonical(b):
        return []
    return [{"op": "replace", "path": path or "/", "old": a, "new": b}]


def _has_redacted(v) -> bool:
    return REDACTED in canonical(v) if v is not None else False


def section_diff(name: str, a, b) -> list[dict]:
    """Redacted diff of one section: an op whose only change is a redacted value says redacted: true."""
    if is_omitted(a) or is_omitted(b):
        sa_, sb_ = (a or {}).get("sha256") if is_omitted(a) else sha(a), \
            (b or {}).get("sha256") if is_omitted(b) else sha(b)
        return [] if sa_ == sb_ else [{"op": "replace", "path": "/", "old": {"code_sha256": sa_},
                                       "new": {"code_sha256": sb_}, "redacted": True}]
    raw = diff(a, b)
    red = {op["path"]: op for op in diff(redact_value(name, a), redact_value(name, b))}
    out, seen = [], set()
    for op in raw:
        if name == "functions" and op["path"].endswith("/code"):
            continue
        r = red.get(op["path"])
        if r is not None:
            seen.add(op["path"])
            o = dict(r)
            if _has_redacted(o.get("old")) or _has_redacted(o.get("new")):
                o["redacted"] = True
            out.append(o)
        else:
            out.append({"op": op["op"], "path": op["path"], "old": REDACTED if op["old"] is not None else None,
                        "new": REDACTED if op["new"] is not None else None, "redacted": True})
    for p, r in red.items():  # e.g. functions code_sha256 changes
        if p not in seen and not any(o["path"] == p for o in out):
            out.append(r)
    return out


# ------------------------------------------------------------------ retention (§23.4)

def prune(db: Session, now: datetime | None = None) -> int:
    """Keep a version while it is among the newest CONFIG_HISTORY_MAX_VERSIONS of its site AND younger
    than CONFIG_HISTORY_DAYS; the newest is always kept. Values needed to reconstruct the oldest
    retained version are re-attached to it. Returns the number of versions removed. Caller commits."""
    now = now or utcnow()
    cutoff = now - timedelta(days=settings.config_history_days)
    keep_n = settings.config_history_max_versions
    removed = 0
    site_ids = [sid for (sid,) in db.execute(select(SiteConfigVersion.site_id).distinct())]
    for sid in site_ids:
        versions = list(db.scalars(select(SiteConfigVersion).where(SiteConfigVersion.site_id == sid)
                                   .order_by(SiteConfigVersion.version.desc())))
        keep = [v for i, v in enumerate(versions) if i == 0 or (i < keep_n and v.at >= cutoff)]
        # contiguous: once one is dropped, every older one goes too
        kept_ids, cut = [], False
        for v in versions:
            if not cut and v in keep:
                kept_ids.append(v.id)
            else:
                cut = True
        drop = [v for v in versions if v.id not in kept_ids]
        if not drop:
            continue
        oldest = versions[len(kept_ids) - 1]
        have = {s for (s,) in db.execute(select(SiteConfigValue.section).where(SiteConfigValue.version_id == oldest.id))}
        drop_ids = [v.id for v in drop]
        for name in sections.SECTIONS:
            if name in have:
                continue
            row = db.scalar(select(SiteConfigValue).join(SiteConfigVersion, SiteConfigVersion.id == SiteConfigValue.version_id)
                            .where(SiteConfigValue.version_id.in_(drop_ids), SiteConfigValue.section == name)
                            .order_by(SiteConfigVersion.version.desc()).limit(1))
            if row is not None:
                row.version_id = oldest.id  # re-attached: the base of the oldest retained version
        db.flush()
        db.execute(delete(SiteConfigValue).where(SiteConfigValue.version_id.in_(drop_ids)))
        db.execute(delete(SiteConfigVersion).where(SiteConfigVersion.id.in_(drop_ids)))
        removed += len(drop_ids)
    return removed


def delete_site(db: Session, site_id: int) -> None:
    """SQLite enforces no foreign keys: remove a deleted site's history explicitly."""
    ids = [i for (i,) in db.execute(select(SiteConfigVersion.id).where(SiteConfigVersion.site_id == site_id))]
    if ids:
        db.execute(delete(SiteConfigValue).where(SiteConfigValue.version_id.in_(ids)))
        db.execute(delete(SiteConfigVersion).where(SiteConfigVersion.id.in_(ids)))


def restores_last_hour(db: Session, site_id: int, now: datetime | None = None) -> int:
    since = (now or utcnow()) - timedelta(hours=1)
    return int(db.scalar(select(func.count(SiteConfigVersion.id)).where(
        SiteConfigVersion.site_id == site_id, SiteConfigVersion.source == "restore",
        SiteConfigVersion.at >= since)) or 0)
