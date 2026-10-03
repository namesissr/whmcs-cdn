"""Staged node rollout with automatic rollback (SPEC §23.2).

One rollout at a time. Rings per edge group, computed at creation and stable: ring 0 = one canary per
group (the online, non-shield, non-draining edge with the most siblings in its group+region pool, ties:
lowest id), ring 1 = ceil(ring_percent % × n) of the remaining edges spread round-robin over the region
pools, ring 2 = the rest. Edges without `capabilities.self_upgrade` are `manual` (listed, never touched).

The leader job (`tick`) starts edges of the current ring under the per-pool parallel limit and the
last-edge rule (never silently upgrading the last serving node of a pool), exposes `node.upgrade` in
the edge's config (non-rendered: no nginx reload), watches the heartbeat `release` / `upgrade`, runs the
soak health gate and rolls everything back automatically on a failure.

HARD CONSTRAINT: gates use the node's own health only (heartbeat, controller probe, internal tunnel
probe, platform error rate) — never reachability from user networks, RUM or ISP data.
"""

import json
import math
from datetime import datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from . import alerts, bundle, dnsbuild, edge_state
from .audit import record_audit
from .config import settings
from .errors import ApiError
from .models import Edge, Rollout, RolloutEdge, UsageHourly, utcnow

ACTIVE = ("planned", "running", "paused", "rolling_back")
IN_FLIGHT = ("upgrading", "soaking")
MIN_REQUESTS = 200
CONFIG_GRACE = timedelta(minutes=10)


def _iso(dt: datetime | None) -> str | None:
    return dt.isoformat() + "Z" if dt else None


def _caps(e: Edge) -> dict:
    try:
        v = json.loads(e.capabilities or "{}")
    except ValueError:
        return {}
    return v if isinstance(v, dict) else {}


def upgrade_report(e: Edge) -> dict:
    try:
        v = json.loads(e.upgrade_state or "{}")
    except ValueError:
        return {}
    return v if isinstance(v, dict) else {}


def _online(e: Edge, now: datetime) -> bool:
    return bool(e.enabled and e.last_seen_at is not None
                and now - e.last_seen_at <= timedelta(seconds=settings.edge_offline_seconds))


def _pool(e: Edge) -> tuple[str, str]:
    return dnsbuild.edge_group(e), dnsbuild.region_of(e)


def active(db: Session) -> Rollout | None:
    return db.scalar(select(Rollout).where(Rollout.state.in_(ACTIVE)).order_by(Rollout.id.desc()).limit(1))


def _groups(r: Rollout) -> list[str] | None:
    try:
        v = json.loads(r.groups) if r.groups else None
    except ValueError:
        return None
    return v if isinstance(v, list) else None


# ------------------------------------------------------------------ planning (rings)

def compute_rings(edges: list[Edge], all_enabled: list[Edge], ring_percent: int, now: datetime) -> dict[int, int]:
    """{edge id: ring} of the in-scope, non-manual edges (pure)."""
    siblings: dict[tuple, int] = {}
    for e in all_enabled:
        siblings[_pool(e)] = siblings.get(_pool(e), 0) + 1
    rings: dict[int, int] = {}
    by_group: dict[str, list[Edge]] = {}
    for e in sorted(edges, key=lambda x: x.id):
        by_group.setdefault(dnsbuild.edge_group(e), []).append(e)
    for group, members in by_group.items():
        cands = [e for e in members if _online(e, now) and not e.shield and not dnsbuild.is_draining(e)]
        canary = None
        if cands:
            canary = sorted(cands, key=lambda e: (-siblings.get(_pool(e), 0), e.id))[0]
            rings[canary.id] = 0
        rest = [e for e in members if canary is None or e.id != canary.id]
        n1 = math.ceil(ring_percent / 100.0 * len(rest)) if rest else 0
        pools: dict[str, list[Edge]] = {}
        for e in rest:
            pools.setdefault(dnsbuild.region_of(e), []).append(e)
        order = [sorted(p, key=lambda x: x.id) for _, p in sorted(pools.items())]
        picked = []
        while len(picked) < n1 and any(order):
            for p in order:
                if p and len(picked) < n1:
                    picked.append(p.pop(0))
        for e in picked:
            rings[e.id] = 1
        for e in rest:
            rings.setdefault(e.id, 2)
    return rings


def plan(db: Session, release: str, groups: list[str] | None, ring_percent: int, allow_no_rollback: bool,
         now: datetime | None = None) -> list[dict]:
    """[{edge, ring, state, from_release}] of a rollout to `release` (nothing stored)."""
    now = now or utcnow()
    enabled = list(db.scalars(select(Edge).where(Edge.enabled.is_(True)).order_by(Edge.id)))
    scope = [e for e in enabled if (groups is None or dnsbuild.edge_group(e) in groups) and e.release != release]
    auto = [e for e in scope if _caps(e).get("self_upgrade")]
    manual = [e for e in scope if not _caps(e).get("self_upgrade")]
    no_rb = [e.name for e in auto if not e.release or bundle.release_file(e.release) is None]
    if no_rb and not allow_no_rollback:
        raise ApiError(422, "no_rollback_release", edges=no_rb)
    rings = compute_rings(auto, enabled, ring_percent, now)
    out = [{"edge": e, "ring": rings[e.id], "state": "pending", "from_release": e.release} for e in auto]
    out += [{"edge": e, "ring": 2, "state": "manual", "from_release": e.release} for e in manual]
    return out


def create(db: Session, body: dict, actor: str, now: datetime | None = None) -> tuple[Rollout | None, dict]:
    now = now or utcnow()
    release = body["release"]
    if not bundle.VERSION_RE.match(release or "") or bundle.release_file(release) is None:
        raise ApiError(404, "unknown_release")
    if active(db) is not None:
        raise ApiError(409, "rollout_active")
    groups = body.get("groups")
    soak = body.get("soak_minutes") or settings.rollout_soak_minutes
    ring_pct = body.get("ring_percent") or 25
    auto_rb = settings.rollout_auto_rollback if body.get("auto_rollback") is None else bool(body["auto_rollback"])
    entries = plan(db, release, groups, ring_pct, bool(body.get("allow_no_rollback")), now)
    r = Rollout(release=release, groups=json.dumps(groups) if groups is not None else None, state="planned",
                ring=0, soak_minutes=soak, ring_percent=ring_pct, auto_rollback=auto_rb,
                allow_no_rollback=bool(body.get("allow_no_rollback")), created_by=actor[:64], created_at=now)
    if body.get("dry_run"):
        return None, preview_dict(r, entries)
    db.add(r)
    db.flush()
    for x in entries:
        db.add(RolloutEdge(rollout_id=r.id, edge_id=x["edge"].id, ring=x["ring"], state=x["state"],
                           from_release=x["from_release"], attempts=0, force_no_drain=False))
    db.commit()
    return r, {}


def preview_dict(r: Rollout, entries: list[dict]) -> dict:
    rings = []
    for ring in (0, 1, 2):
        rings.append({"ring": ring, "edges": [
            {"id": x["edge"].id, "name": x["edge"].name, "group": dnsbuild.edge_group(x["edge"]),
             "region": dnsbuild.region_of(x["edge"]), "state": x["state"], "from_release": x["from_release"],
             "started_at": None, "soak_until": None, "error": None, "gate": None}
            for x in entries if x["ring"] == ring]})
    return {"id": None, "dry_run": True, "release": r.release, "state": "planned", "ring": 0,
            "groups": _groups(r), "soak_minutes": r.soak_minutes, "ring_percent": r.ring_percent,
            "auto_rollback": r.auto_rollback, "reason": None, "created_at": None, "started_at": None,
            "finished_at": None, "rings": rings}


# ------------------------------------------------------------------ views

def _edges(db: Session, r: Rollout) -> list[tuple[RolloutEdge, Edge]]:
    rows = db.execute(select(RolloutEdge, Edge).join(Edge, Edge.id == RolloutEdge.edge_id)
                      .where(RolloutEdge.rollout_id == r.id).order_by(RolloutEdge.ring, Edge.id)).all()
    return [(re_, e) for re_, e in rows]


def baseline_err_pct(db: Session, e: Edge, now: datetime) -> float | None:
    req, pe = _usage(db, e, now - timedelta(hours=24), now)
    return round(100.0 * pe / req, 3) if req else None


def _usage(db: Session, e: Edge, start: datetime, end: datetime) -> tuple[int, int]:
    req, pe = 0, 0
    for r, details in db.execute(select(UsageHourly.requests, UsageHourly.details).where(
            UsageHourly.edge_id == e.id, UsageHourly.hour >= start.replace(minute=0, second=0, microsecond=0),
            UsageHourly.hour <= end)):
        req += int(r or 0)
        try:
            pe += int((json.loads(details or "{}") or {}).get("platform_errors") or 0)
        except (ValueError, AttributeError):
            pass
    return req, pe


def gate(db: Session, x: RolloutEdge, e: Edge, now: datetime) -> dict:
    hb = e.last_seen_at is not None and now - e.last_seen_at <= timedelta(seconds=settings.edge_offline_seconds)
    probe = (e.probe_fail or 0) < settings.probe_fail_checks
    tp = None if not _caps(e).get("tunnel_probe") else not bool(e.tunnel_degraded)
    limit = max(settings.rollout_max_error_pct, 2 * (x.baseline_err_pct or 0.0))
    err = None
    if x.started_at is not None:
        req, pe = _usage(db, e, x.started_at, now)
        if req >= MIN_REQUESTS:
            err = round(100.0 * pe / req, 3)
    return {"heartbeat": hb, "probe": probe, "tunnel_probe": tp, "error_pct": err, "limit_pct": round(limit, 3)}


def to_dict(db: Session, r: Rollout, with_gate: bool = True) -> dict:
    now = utcnow()
    rings = {0: [], 1: [], 2: []}
    for x, e in _edges(db, r):
        rings.setdefault(x.ring, []).append({
            "id": e.id, "name": e.name, "group": dnsbuild.edge_group(e), "region": dnsbuild.region_of(e),
            "state": x.state, "from_release": x.from_release, "started_at": _iso(x.started_at),
            "soak_until": _iso(x.soak_until), "error": x.error,
            "gate": gate(db, x, e, now) if with_gate and x.state in ("soaking", "upgrading") else None})
    return {"id": r.id, "release": r.release, "state": r.state, "ring": r.ring, "groups": _groups(r),
            "soak_minutes": r.soak_minutes, "ring_percent": r.ring_percent, "auto_rollback": r.auto_rollback,
            "reason": r.reason, "created_by": r.created_by, "created_at": _iso(r.created_at),
            "started_at": _iso(r.started_at), "finished_at": _iso(r.finished_at),
            "rings": [{"ring": k, "edges": v} for k, v in sorted(rings.items())]}


# ------------------------------------------------------------------ edge config (A emits, B consumes)

def upgrade_block(db: Session, edge: Edge | None) -> dict | None:
    """`node.upgrade` of this edge or None. A non-rendered key: changing it never reloads nginx."""
    if edge is None:
        return None
    row = db.execute(select(RolloutEdge, Rollout).join(Rollout, Rollout.id == RolloutEdge.rollout_id).where(
        RolloutEdge.edge_id == edge.id, Rollout.state.in_(("running", "paused", "rolling_back")),
        RolloutEdge.state.in_(("upgrading", "soaking", "rolling_back"))).limit(1)).first()
    if row is None:
        return None
    x, r = row
    rollback = x.state == "rolling_back"
    if rollback and x.started_at is None:
        return None
    release = x.from_release if rollback else r.release
    if not release:
        return None
    return {"id": f"{r.id}-{x.attempts}", "release": release, "sha256": bundle.release_sha256(release),
            "drain_minutes": 0 if x.force_no_drain else settings.rollout_drain_minutes, "rollback": rollback,
            "timeout_s": settings.rollout_upgrade_timeout_minutes * 60}


# ------------------------------------------------------------------ admin actions

def _invalid(r: Rollout):
    raise ApiError(409, "invalid_state", state=r.state)


def act(db: Session, r: Rollout, action: str, now: datetime | None = None) -> None:
    now = now or utcnow()
    if action == "start":
        if r.state != "planned":
            _invalid(r)
        r.state, r.started_at, r.reason = "running", now, None
    elif action == "pause":
        if r.state != "running":
            _invalid(r)
        r.state, r.reason = "paused", "admin"
    elif action == "resume":
        if r.state != "paused":
            _invalid(r)
        for x, _ in _edges(db, r):
            if x.state == "blocked":
                x.state = "rolling_back" if x.error == "last_edge_rollback" else "pending"
                x.started_at = None if x.state == "rolling_back" else x.started_at
        rb = any(x.state == "rolling_back" for x, _ in _edges(db, r))
        r.state, r.reason = ("rolling_back" if rb else "running"), None
    elif action == "abort":
        if r.state not in ("planned", "running", "paused"):
            _invalid(r)
        r.state, r.finished_at, r.reason = "aborted", now, "admin"
    elif action == "rollback":
        if r.state not in ("running", "paused", "aborted", "completed", "failed"):
            _invalid(r)
        if r.state in ("aborted", "completed", "failed") and active(db) is not None:
            raise ApiError(409, "rollout_active")
        start_rollback(db, r, now, reason="admin")
    else:
        raise ApiError(404, "unknown_action")
    db.commit()


def edge_act(db: Session, r: Rollout, edge_id: int, action: str, now: datetime | None = None) -> None:
    x = db.scalar(select(RolloutEdge).where(RolloutEdge.rollout_id == r.id, RolloutEdge.edge_id == edge_id))
    if x is None:
        raise ApiError(404, "edge_not_in_rollout")
    if r.state not in ACTIVE:
        _invalid(r)
    if action == "skip":
        if x.state not in ("pending", "blocked", "failed"):
            raise ApiError(409, "invalid_state", state=x.state)
        x.state, x.error = "skipped", None
    elif action == "force":
        if x.state not in ("pending", "blocked"):
            raise ApiError(409, "invalid_state", state=x.state)
        x.force_no_drain = True
        if x.error == "last_edge_rollback":
            x.state, x.started_at = "rolling_back", None
        else:
            x.state = "pending"
    elif action == "retry":
        if x.state != "failed" or r.state == "rolling_back":
            raise ApiError(409, "invalid_state", state=x.state)
        x.state, x.error, x.started_at, x.soak_until = "pending", None, None, None
        alerts.resolve_alert(f"rollout_failed:{r.id}", notify=False)
    else:
        raise ApiError(404, "unknown_action")
    # a pause for a blocked last edge / a failure ends once nothing is blocked / failed any more
    db.flush()
    states = [y.state for y, _ in _edges(db, r)]
    if r.state == "paused" and (((r.reason or "").startswith("last_edge") and "blocked" not in states)
                                or ((r.reason or "").startswith("failed") and "failed" not in states)):
        r.state, r.reason = ("rolling_back" if "rolling_back" in states else "running"), None
        alerts.resolve_alert(f"rollout_blocked:{r.id}", notify=False)
    db.commit()


def start_rollback(db: Session, r: Rollout, now: datetime, reason: str) -> None:
    for x, _ in _edges(db, r):
        if x.state in ("upgrading", "soaking", "healthy", "failed", "blocked"):
            if x.state == "blocked" and x.started_at is None:
                x.state = "skipped"  # never upgraded: nothing to roll back
                continue
            x.state, x.started_at, x.soak_until, x.finished_at = "rolling_back", None, None, None
    r.state, r.reason, r.finished_at = "rolling_back", (reason or "")[:200], None


# ------------------------------------------------------------------ the leader job

def _in_flight(x: RolloutEdge) -> bool:
    return x.state in IN_FLIGHT or (x.state == "rolling_back" and x.started_at is not None)


def _can_start(db: Session, r: Rollout, x: RolloutEdge, e: Edge, rows: list, now: datetime) -> str:
    """'go' | 'wait' | 'blocked' (the only edge of its pool)."""
    pool = _pool(e)
    flight_ids = {y.edge_id for y, f in rows if _in_flight(y) and _pool(f) == pool}
    if len(flight_ids) >= settings.rollout_parallel:
        return "wait"
    if x.force_no_drain:
        return "go"
    members = [f for f in db.scalars(select(Edge).where(Edge.enabled.is_(True))) if _pool(f) == pool]
    others = [f for f in members if f.id != e.id and f.id not in flight_ids and _online(f, now)
              and not dnsbuild.is_shed(f, now) and not dnsbuild.is_draining(f)]
    if others:
        return "go"
    return "blocked" if len(members) <= 1 else "wait"


def _start(db: Session, r: Rollout, x: RolloutEdge, e: Edge, now: datetime, rollback: bool) -> None:
    x.attempts = (x.attempts or 0) + 1
    x.started_at = now
    x.error = None
    if not rollback:
        x.state = "upgrading"
        x.baseline_err_pct = baseline_err_pct(db, e, now)
        edge_state.add_event(db, e, "rollout_start", {"release": r.release, "rollout": r.id}, now)
    else:
        edge_state.add_event(db, e, "rollback", {"release": x.from_release, "rollout": r.id}, now)


def _fail(x: RolloutEdge, now: datetime, error: str) -> None:
    x.state, x.error, x.finished_at = "failed", error[:500], now


def _block(db: Session, r: Rollout, x: RolloutEdge, e: Edge, rollback: bool) -> None:
    x.state, x.error = "blocked", "last_edge_rollback" if rollback else "last_edge"
    r.state, r.reason = "paused", f"last_edge:{e.name}"[:200]
    alerts.raise_alert(f"rollout_blocked:{r.id}", f"انتشار {r.release}: آخرین نود {e.name}",
                       f"نود {e.name} تنها نود گروه/منطقهٔ خود است؛ انتشار متوقف شد. در صفحهٔ «انتشار نسخه» "
                       "«رد کردن» یا «ارتقا بدون تخلیه» را انتخاب کنید.", "critical" if rollback else "warning")


def _watch_forward(db: Session, r: Rollout, x: RolloutEdge, e: Edge, now: datetime) -> None:
    up = upgrade_report(e)
    my_id = str(up.get("id") or "") == f"{r.id}-{x.attempts}"
    timeout = timedelta(minutes=settings.rollout_upgrade_timeout_minutes)
    if x.state == "upgrading":
        if e.release == r.release and up.get("state") == "done":
            x.state, x.soak_until = "soaking", now + timedelta(minutes=r.soak_minutes)
        elif my_id and up.get("state") == "failed":
            _fail(x, now, str(up.get("error") or "upgrade_failed")[:200])
        elif x.started_at and now - x.started_at > timeout:
            _fail(x, now, "upgrade_timeout")
        return
    # soaking: the health gate (every tick, all must hold)
    g = gate(db, x, e, now)
    reason = None
    if not g["heartbeat"]:
        reason = "heartbeat"
    elif e.last_error:
        reason = "last_error"
    elif x.started_at and now - x.started_at > CONFIG_GRACE and not _config_applied(db, e):
        reason = "config_not_applied"
    elif not g["probe"]:
        reason = "probe"
    elif g["tunnel_probe"] is False:
        reason = "tunnel_probe"
    elif g["error_pct"] is not None and g["error_pct"] > g["limit_pct"]:
        reason = f"error_pct {g['error_pct']} > {g['limit_pct']}"
    if reason:
        _fail(x, now, reason)
    elif x.soak_until and now >= x.soak_until:
        x.state, x.finished_at = "healthy", now
        edge_state.add_event(db, e, "rollout_done", {"release": r.release, "rollout": r.id}, now)


def _config_applied(db: Session, e: Edge) -> bool:
    from .services import build_edge_config

    return e.applied_version == build_edge_config(db, e)["version"]


def tick(db: Session, now: datetime | None = None) -> dict | None:
    """job_rollout body (every scheduler tick, leader only)."""
    now = now or utcnow()
    r = db.scalar(select(Rollout).where(Rollout.state.in_(("running", "paused", "rolling_back")))
                  .order_by(Rollout.id.desc()).limit(1))
    if r is None:
        return None
    rows = _edges(db, r)
    if r.state in ("running", "paused"):
        for x, e in rows:
            if x.state in IN_FLIGHT:
                _watch_forward(db, r, x, e, now)
        failed = [(x, e) for x, e in rows if x.state == "failed"]
        handled = (r.reason or "").startswith("failed")
        if failed and (r.state == "running" or (r.auto_rollback and not handled)):
            x, e = failed[0]
            if r.auto_rollback:
                alerts.raise_alert(f"rollout_failed:{r.id}", f"انتشار {r.release} ناموفق بود؛ بازگردانی خودکار",
                                   f"نود {e.name} در پایش ناموفق بود ({x.error}). همهٔ نودهای ارتقایافته به نسخهٔ "
                                   "قبلی بازگردانده می‌شوند.", "critical")
                start_rollback(db, r, now, reason=f"failed:{e.name}:{x.error}")
            else:
                r.state, r.reason = "paused", f"failed:{e.name}"[:200]
                alerts.raise_alert(f"rollout_failed:{r.id}", f"انتشار {r.release} ناموفق بود",
                                   f"نود {e.name} در پایش ناموفق بود ({x.error}). انتشار متوقف شد.", "critical")
        if r.state == "running":
            _advance(db, r, rows, now)
    if r.state == "rolling_back":
        _roll_back(db, r, rows, now)
    db.commit()
    return to_dict(db, r, with_gate=False)


def _advance(db: Session, r: Rollout, rows: list, now: datetime) -> None:
    while r.ring <= 2:
        ring_rows = [(x, e) for x, e in rows if x.ring == r.ring and x.state not in ("manual", "skipped")]
        for x, e in ring_rows:
            if x.state != "pending":
                continue
            verdict = _can_start(db, r, x, e, rows, now)
            if verdict == "go":
                _start(db, r, x, e, now, rollback=False)
            elif verdict == "blocked":
                _block(db, r, x, e, rollback=False)
                return
        if all(x.state == "healthy" for x, _ in ring_rows):
            r.ring += 1
            continue
        return
    r.state, r.finished_at, r.ring = "completed", now, 2
    groups = _groups(r) or sorted({dnsbuild.edge_group(e) for _, e in rows} | set(bundle.GROUPS))
    for g in groups:
        members = list(db.scalars(select(Edge).where(Edge.enabled.is_(True), Edge.group == g)))
        if members and all(m.release == r.release for m in members):
            bundle.set_group_pin(db, g, r.release)
    alerts.resolve_alert(f"rollout_blocked:{r.id}", notify=False)
    record_audit(db, actor="system", actor_kind="system", action="rollout.complete", target=r.release,
                 detail={"items": r.id})


def _roll_back(db: Session, r: Rollout, rows: list, now: datetime) -> None:
    timeout = timedelta(minutes=settings.rollout_upgrade_timeout_minutes)
    for x, e in rows:
        if x.state != "rolling_back":
            continue
        if not x.from_release:
            x.state, x.error = "manual", "no_rollback_release"
            continue
        if x.started_at is not None:
            if e.release == x.from_release:
                x.state, x.finished_at = "rolled_back", now
            elif x.started_at and now - x.started_at > timeout:
                x.state, x.error, x.finished_at = "failed", "rollback_timeout", now
        if x.started_at is None and x.state == "rolling_back":
            if e.release == x.from_release:
                x.state, x.finished_at = "rolled_back", now
                continue
            verdict = _can_start(db, r, x, e, rows, now)
            if verdict == "go":
                _start(db, r, x, e, now, rollback=True)
            elif verdict == "blocked":
                _block(db, r, x, e, rollback=True)
                return
    states = [x.state for x, _ in rows]
    if "rolling_back" in states or "blocked" in states:
        return
    if any(x.state == "failed" and x.error == "rollback_timeout" for x, _ in rows):
        r.state, r.finished_at = "failed", now
        alerts.raise_alert(f"rollout_failed:{r.id}", f"بازگردانی انتشار {r.release} ناموفق بود",
                           "حداقل یک نود به نسخهٔ قبلی برنگشت؛ وضعیت نودها را بررسی کنید.", "critical")
        return
    r.state, r.finished_at = "rolled_back", now
    alerts.resolve_alert(f"rollout_failed:{r.id}", f"انتشار {r.release} به نسخهٔ قبلی بازگردانده شد.")
    alerts.resolve_alert(f"rollout_blocked:{r.id}", notify=False)


# ------------------------------------------------------------------ releases overview

def releases(db: Session) -> dict:
    counts: dict = {}
    for (rel,) in db.execute(select(Edge.release).where(Edge.enabled.is_(True))):
        counts[rel] = counts.get(rel, 0) + 1
    out = []
    for item in bundle.list_releases():
        out.append({**item, "nodes": counts.get(item["version"], 0)})
    return {"releases": out, "pinned": bundle.configured_pin(), "groups": bundle.pins(db),
            "controller": settings.app_version, "nodes": {("null" if k is None else k): v for k, v in counts.items()}}


def metrics(db: Session) -> tuple[Rollout | None, dict[str, int]]:
    r = db.scalar(select(Rollout).order_by(Rollout.id.desc()).limit(1))
    if r is None:
        return None, {}
    counts = dict(db.execute(select(RolloutEdge.state, func.count(RolloutEdge.id)).where(
        RolloutEdge.rollout_id == r.id).group_by(RolloutEdge.state)).all())
    return r, {k: int(v) for k, v in counts.items()}
