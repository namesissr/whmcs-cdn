"""Capacity-driven node provisioning, operator-approved (SPEC §23.9), and one-time join tokens.

Flow: capacity alert -> proposal -> admin approval (edge rows + join tokens) -> the operator-run
provisioner fetches the job and uploads a `terraform plan` summary -> admin approves the apply -> the
provisioner applies -> each VM joins with its one-time token. Nothing is created without two explicit
admin approvals; the controller never holds cloud credentials.

HARD CONSTRAINT: proposals are sized from capacity only (p95 vs capacity_mbps) — never from
reachability, blocking or ISP data — and every new node gets ordinary, stable addresses.
"""

import hmac
import json
import math
import re
import secrets
import statistics
import threading
import time
from datetime import datetime, timedelta

from fastapi import HTTPException
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from . import alerts, bundle, crypto, edge_state
from .auth import hash_token, new_token
from .config import settings
from .errors import ApiError
from .models import Edge, EdgeJoinToken, ProvisionProposal, UsageHourly, utcnow

FINAL = ("joined", "failed", "rejected", "expired")
EXPIRE_AFTER = timedelta(days=7)
JOIN_RE = re.compile(r"jt_[0-9a-f]{40}")
SUMMARY_MAX = 64 * 1024
JOIN_PER_MIN = 10
_join_hits: dict[str, list[float]] = {}
_lock = threading.Lock()


def _iso(dt: datetime | None) -> str | None:
    return dt.isoformat() + "Z" if dt else None


def _ids(p: ProvisionProposal) -> list[int]:
    try:
        v = json.loads(p.edge_ids or "[]")
    except ValueError:
        return []
    return [int(x) for x in v if isinstance(x, int)]


def sizes() -> list[tuple[str, int]]:
    return sorted(settings.provision_sizes.items(), key=lambda kv: (kv[1], kv[0]))


def size_capacity(name: str) -> int:
    return int(settings.provision_sizes.get(name) or 0)


# ------------------------------------------------------------------ join tokens

def new_join_token() -> str:
    return "jt_" + secrets.token_hex(20)


def mint(db: Session, edge: Edge, created_by: str = "admin", now: datetime | None = None) -> tuple[str, datetime]:
    now = now or utcnow()
    token = new_join_token()
    expires = now + timedelta(hours=settings.join_token_hours)
    db.add(EdgeJoinToken(edge_id=edge.id, token_hash=hash_token(token), expires_at=expires, created_at=now,
                         created_by=created_by[:64]))
    return token, expires


def install_command(edge: Edge, token: str, db: Session | None = None) -> str:
    base = bundle.base_url()
    cmd = (f"curl -fsSL {base}/edge/bootstrap.sh | sudo PCDN_JOIN_TOKEN={token} bash -s -- "
           f"--controller {base} --region {edge.region} --role {edge.group}")
    pin = bundle.group_pin(db, edge.group) if db is not None else None
    if pin:
        cmd += f" --version {pin}"
    return cmd


def join_rate(ip: str) -> bool:
    now = time.monotonic()
    with _lock:
        hits = [t for t in _join_hits.get(ip, []) if t > now - 60]
        if len(hits) >= JOIN_PER_MIN:
            _join_hits[ip] = hits
            return False
        hits.append(now)
        _join_hits[ip] = hits
        return True


def join(db: Session, token: str, now: datetime | None = None) -> tuple[Edge, str]:
    """POST /edge/v1/join: a fresh edge token for an unused, unexpired join token; 401 otherwise."""
    now = now or utcnow()
    th = hash_token(token or "")
    row = db.scalar(select(EdgeJoinToken).where(EdgeJoinToken.token_hash == th))
    # constant-time on the hash even when unknown
    ok = hmac.compare_digest(row.token_hash if row is not None else "0" * 64, th)
    if row is None or not ok or row.used_at is not None or row.expires_at < now or not JOIN_RE.fullmatch(token or ""):
        raise HTTPException(401, "invalid join token")
    edge = db.get(Edge, row.edge_id)
    if edge is None:
        raise HTTPException(401, "invalid join token")
    edge_token = new_token()
    edge.token_hash = hash_token(edge_token)
    edge.enabled = True
    row.used_at = now
    edge_state.add_event(db, edge, "joined", {}, now)
    db.commit()
    return edge, edge_token


# ------------------------------------------------------------------ proposals

def proposal_dict(db: Session, p: ProvisionProposal) -> dict:
    edges = []
    for eid in _ids(p):
        e = db.get(Edge, eid)
        if e is not None:
            edges.append({"id": e.id, "name": e.name, "joined": e.last_seen_at is not None})
    plan = None
    if p.plan_at is not None:
        plan = {"summary": p.plan_summary or "", "adds": p.plan_adds, "changes": p.plan_changes,
                "destroys": p.plan_destroys, "uploaded_at": _iso(p.plan_at)}
    return {"id": p.id, "group": p.group, "region": p.region, "size": p.size, "count": p.count, "reason": p.reason,
            "state": p.state, "plan": plan, "edges": edges, "created_at": _iso(p.created_at),
            "updated_at": _iso(p.updated_at), "decided_by": p.decided_by, "error": p.error}


def _active(db: Session, group: str) -> ProvisionProposal | None:
    return db.scalar(select(ProvisionProposal).where(ProvisionProposal.group == group,
                                                     ProvisionProposal.state.notin_(FINAL)))


def _region_for(db: Session, group: str, now: datetime) -> str:
    """The group's region with the highest share of the group's 72 h traffic (home when unknown)."""
    since = now - timedelta(hours=72)
    rows = db.execute(select(Edge.region, func.sum(UsageHourly.bytes)).join(Edge, Edge.id == UsageHourly.edge_id)
                      .where(Edge.group == group, UsageHourly.hour >= since).group_by(Edge.region)).all()
    best = max(rows, key=lambda r: (int(r[1] or 0), r[0]), default=None)
    if best is not None and int(best[1] or 0) > 0:
        return best[0] or "home"
    regions = [e.region for e in db.scalars(select(Edge).where(Edge.group == group, Edge.enabled.is_(True)))]
    return max(set(regions), key=regions.count) if regions else "home"


def size_for(db: Session, group: str) -> str:
    caps = [e.capacity_mbps for e in db.scalars(select(Edge).where(Edge.group == group, Edge.enabled.is_(True)))
            if (e.capacity_mbps or 0) > 0]
    if not caps:
        return "medium" if "medium" in settings.provision_sizes else sizes()[0][0]
    med = statistics.median(caps)
    for name, cap in sizes():
        if cap >= med:
            return name
    return sizes()[-1][0]


def count_for(p95: float, capacity: float, size_cap: int) -> int:
    """max(1, ceil((p95 / (target/100) − capacity) / size_capacity)) — capacity only."""
    if size_cap <= 0:
        return 1
    need = p95 / (settings.provision_target_pct / 100.0) - capacity
    return max(1, math.ceil(need / size_cap)) if need > 0 else 1


def propose_from_capacity(db: Session, report: list[dict] | None, now: datetime | None = None) -> list[int]:
    """On `capacity:{group}` open (and daily while open): one proposal per group in a non-final state."""
    if not settings.provisioning_enabled or not report:
        return []
    now = now or utcnow()
    open_keys = {c.get("key") for c in alerts.open_alerts(db)}
    created = []
    for g in report:
        if f"capacity:{g['group']}" not in open_keys or _active(db, g["group"]) is not None:
            continue
        size = size_for(db, g["group"])
        count = count_for(float(g["p95_mbps"] or 0), float(g["capacity_mbps"] or 0), size_capacity(size))
        reason = (f"group {g['group']}: p95 {g['p95_mbps']} Mbps of {g['capacity_mbps']} Mbps capacity "
                  f"({g['pct']}%), target {settings.provision_target_pct:g}%")
        p = ProvisionProposal(group=g["group"], region=_region_for(db, g["group"], now), size=size, count=count,
                              reason=reason, state="proposed", edge_ids="[]", created_at=now, updated_at=now)
        db.add(p)
        db.commit()
        created.append(p.id)
        alerts.raise_alert(f"provision_proposed:{g['group']}", f"پیشنهاد افزودن نود به گروه {g['group']}",
                           f"پیشنهاد شمارهٔ {p.id}: {count} نود {size} در منطقهٔ {p.region}. {reason}. "
                           "در صفحهٔ «پیشنهاد افزودن نود» بررسی و تأیید کنید.", "info")
    return created


def create_manual(db: Session, group: str, region: str, size: str, count: int, actor: str) -> ProvisionProposal:
    if group not in ("general", "tunnel") or region not in ("home", "global") or size not in settings.provision_sizes \
            or not 1 <= count <= 20:
        raise HTTPException(422, "invalid proposal")
    if _active(db, group) is not None:
        raise HTTPException(409, "proposal_active")
    now = utcnow()
    p = ProvisionProposal(group=group, region=region, size=size, count=count, reason="manual", state="proposed",
                          edge_ids="[]", created_at=now, updated_at=now, decided_by=actor[:64])
    db.add(p)
    db.commit()
    return p


def _state(p: ProvisionProposal, allowed: tuple) -> None:
    if p.state not in allowed:
        raise ApiError(409, "invalid_state", state=p.state)


def approve(db: Session, p: ProvisionProposal, region: str | None, size: str | None, count: int | None,
            actor: str) -> None:
    _state(p, ("proposed",))
    if not crypto.enabled():
        raise HTTPException(422, "encryption_required")
    if region is not None:
        if region not in ("home", "global"):
            raise HTTPException(422, "invalid region")
        p.region = region
    if size is not None:
        if size not in settings.provision_sizes:
            raise HTTPException(422, "invalid size")
        p.size = size
    if count is not None:
        if not 1 <= count <= 20:
            raise HTTPException(422, "invalid count")
        p.count = count
    now = utcnow()
    taken = {n for (n,) in db.execute(select(Edge.name))}
    tokens, ids = [], []
    for n in range(1, p.count + 1):
        name = f"{p.group}-{p.region}-p{p.id}-{n}"
        while name in taken:
            name += "x"
        taken.add(name)
        # placeholder address exactly like /edges/batch; learned from the first heartbeat
        e = Edge(name=name, ipv4="0.0.0.0", region=p.region, group=p.group, enabled=True,
                 token_hash=hash_token(new_token()), capacity_mbps=size_capacity(p.size))
        db.add(e)
        db.flush()
        tok, _ = mint(db, e, f"proposal:{p.id}", now)
        tokens.append({"name": name, "join_token": tok})
        ids.append(e.id)
    p.edge_ids = json.dumps(ids)
    p.join_tokens_enc = crypto.encrypt(json.dumps(tokens))
    p.state, p.decided_by, p.updated_at = "approved", actor[:64], now
    db.commit()


def approve_apply(db: Session, p: ProvisionProposal, actor: str) -> None:
    _state(p, ("planned",))
    if (p.plan_destroys or 0) != 0:
        raise HTTPException(409, "plan_destroys")
    p.state, p.decided_by, p.updated_at = "apply_approved", actor[:64], utcnow()
    db.commit()


def reject(db: Session, p: ProvisionProposal, actor: str) -> None:
    _state(p, ("proposed", "approved", "planning", "planned", "apply_approved"))
    _drop_unjoined(db, p)
    p.state, p.decided_by, p.updated_at, p.join_tokens_enc = "rejected", actor[:64], utcnow(), None
    db.commit()
    alerts.resolve_alert(f"provision_proposed:{p.group}", notify=False)


def _drop_unjoined(db: Session, p: ProvisionProposal) -> None:
    from sqlalchemy import delete

    for eid in _ids(p):
        e = db.get(Edge, eid)
        if e is not None and e.last_seen_at is None:
            db.execute(delete(EdgeJoinToken).where(EdgeJoinToken.edge_id == e.id))
            db.delete(e)


# ------------------------------------------------------------------ provisioner API

def next_job(db: Session) -> dict | None:
    p = db.scalar(select(ProvisionProposal).where(ProvisionProposal.state.in_(("approved", "apply_approved")))
                  .order_by(ProvisionProposal.id).limit(1))
    if p is None:
        return None
    now = utcnow()
    names = []
    for eid in _ids(p):
        e = db.get(Edge, eid)
        if e is not None:
            names.append(e.name)
    action = "plan" if p.state == "approved" else "apply"
    edges = [{"name": n} for n in names]
    if action == "plan" and p.join_tokens_enc:
        try:
            tokens = {t["name"]: t["join_token"] for t in json.loads(crypto.decrypt(p.join_tokens_enc))}
        except (crypto.CryptoError, ValueError, TypeError, KeyError):
            tokens = {}
        edges = [{"name": n, **({"join_token": tokens[n]} if n in tokens else {})} for n in names]
        p.join_tokens_enc = None  # handed out once, then wiped
    p.state = "planning" if action == "plan" else "applying"
    p.updated_at = now
    db.commit()
    return {"id": p.id, "action": action, "group": p.group, "region": p.region, "size": p.size, "count": p.count,
            "edges": edges, "controller_url": bundle.base_url(), "release": bundle.group_pin(db, p.group)}


def upload_plan(db: Session, p: ProvisionProposal, summary: str, adds: int, changes: int, destroys: int) -> None:
    _state(p, ("planning",))
    if len(summary.encode()) > SUMMARY_MAX:
        raise HTTPException(422, "summary_too_large")
    # never a join token in a stored plan summary (the provisioner masks them as jt_***)
    if JOIN_RE.search(summary):
        raise HTTPException(422, "summary_contains_join_token")
    p.plan_summary, p.plan_adds, p.plan_changes, p.plan_destroys = summary, adds, changes, destroys
    p.plan_at = p.updated_at = utcnow()
    p.state = "planned"
    db.commit()


def upload_result(db: Session, p: ProvisionProposal, ok: bool, error: str | None) -> None:
    _state(p, ("applying",))
    p.updated_at = utcnow()
    if ok:
        p.state, p.error = "applied", None
    else:
        p.state, p.error = "failed", (error or "apply failed")[:500]
        alerts.raise_alert(f"provision_failed:{p.id}", f"اجرای پیشنهاد نود {p.id} ناموفق بود",
                           f"اجرای terraform برای پیشنهاد {p.id} (گروه {p.group}) ناموفق بود: {p.error}", "warning")
    db.commit()


def check(db: Session, now: datetime | None = None) -> None:
    """Leader: applied -> joined when every edge joined; proposed/planned untouched 7 days -> expired."""
    now = now or utcnow()
    for p in db.scalars(select(ProvisionProposal).where(ProvisionProposal.state.notin_(FINAL))):
        if p.state == "applied":
            edges = [db.get(Edge, i) for i in _ids(p)]
            if edges and all(e is not None and e.last_seen_at is not None for e in edges):
                p.state, p.updated_at = "joined", now
                alerts.resolve_alert(f"provision_proposed:{p.group}", notify=False)
        elif p.state in ("proposed", "planned") and now - (p.updated_at or p.created_at) > EXPIRE_AFTER:
            _drop_unjoined(db, p)
            p.state, p.updated_at, p.join_tokens_enc = "expired", now, None
            alerts.resolve_alert(f"provision_proposed:{p.group}", notify=False)
    db.commit()


def provisioner_auth(authorization: str | None) -> None:
    token = settings.provisioner_token
    given = authorization[7:].strip() if authorization and authorization.lower().startswith("bearer ") else ""
    if not token or len(token) < 32 or not hmac.compare_digest(given.encode(), token.encode()):
        raise HTTPException(401, "invalid provisioner token")

