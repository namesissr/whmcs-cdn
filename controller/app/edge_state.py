"""Wave 13 (SPEC §22) node state kept by the controller: drain before upgrade (§22.1), the reload /
tuning reports (§22.2 / §22.6), the synthetic tunnel probe with its degraded state (§22.3), the
capacity-weighted DNS load level (§22.10) and the edge_events log (§22.13).

Scope: node health, maintenance and capacity only. Nothing here looks at reachability from user
networks, ISPs or countries, and nothing selects nodes by "what is not blocked": a node leaves DNS
answers only because an operator (or the node itself) drains it for maintenance, or because its own
tunnel proxy path fails the loopback probe — always within a budget and never emptying a pool.

Internal hysteresis counters live under "_"-prefixed keys of the edge's JSON columns (metrics,
reload_stats, tuning) and are stripped from every API view.
"""

import json
import logging
import re
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import dnsbuild
from .config import settings
from .models import Edge, EdgeEvent, utcnow

log = logging.getLogger("pcdn.edge_state")

DRAIN_STATES = ("", "draining", "drained")
DRAIN_GRACE_EXTRA = 30  # seconds after PROXIED_TTL before the node refuses NEW tunnel connections
EVENT_KINDS = ("drain_start", "drain_end", "drained", "degraded", "recovered", "upgrade",
               # SPEC §23.2 / §23.9 (wave 14)
               "rollout_start", "rollout_done", "rollback", "joined")
EVENT_DATA_MAX = 2048
EDGE_EVENTS_RETENTION_DAYS = 90
# a degraded edge stays degraded at least this long, even after TUNNEL_PROBE_OK_CHECKS good reports
DEGRADED_MIN_HOLD = timedelta(minutes=10)
# a tunnel_probe whose `at` is older than this is a stale report and never counts
PROBE_STALE = timedelta(minutes=20)
# §22.2 alert thresholds
RELOAD_STORM_OPEN, RELOAD_STORM_RESOLVE, RELOAD_STORM_CHECKS = 12, 6, 3
PILEUP_PER_CPU, PILEUP_CHECKS = 4, 5
# §22.2 node memory (the memory part of edge_health): EDGE_MEM_ALERT for MEM_ALERT_CHECKS heartbeats,
# resolving MEM_RESOLVE_MARGIN points lower. From MEM_CRIT_PCT the alert opens on the first report and is
# critical: there the kernel's OOM killer is minutes away and it picks its own victim, which can be the
# nginx master -- and every tunnel on the node goes with it.
MEM_ALERT_CHECKS, MEM_RESOLVE_MARGIN, MEM_CRIT_PCT = 3, 10.0, 97.0
TUNING_CHECKS = 3
# §22.10 load levels: factor per level, up thresholds (2 reports) and down thresholds (3 reports)
LEVEL_FACTOR = {0: 1.0, 1: 0.5, 2: 0.25}
LEVEL_UP_CHECKS, LEVEL_DOWN_CHECKS = 2, 3
# §22.3 node.probe interval sent to the agents (the agent's PROBE_INTERVAL default)
PROBE_INTERVAL_DEFAULT = 60

_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b|\[?[0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7}\]?")


def iso(dt: datetime | None) -> str | None:
    return dt.isoformat(timespec="seconds") + "Z" if dt else None


def naive(dt: datetime | None) -> datetime | None:
    if dt is not None and dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


def scrub(text: str | None, limit: int = 120) -> str | None:
    """Short operational text from a node with any address replaced (never stored or shown)."""
    if text is None:
        return None
    return _IP_RE.sub("<addr>", str(text))[:limit]


def loads(raw: str | None) -> dict:
    try:
        d = json.loads(raw or "{}")
    except (ValueError, TypeError):
        return {}
    return d if isinstance(d, dict) else {}


def public(doc: dict | None) -> dict | None:
    """A stored report without the internal "_" counters."""
    if not doc:
        return None
    return {k: v for k, v in doc.items() if not str(k).startswith("_")}


# ------------------------------------------------------------------ edge events (§22.13)

def add_event(db: Session, edge: Edge, kind: str, data: dict | None = None, now: datetime | None = None) -> None:
    """Append one edge_events row (caller commits). `data` never carries an address or a secret."""
    assert kind in EVENT_KINDS, kind
    raw = json.dumps(data or {}, ensure_ascii=False, sort_keys=True)
    if len(raw.encode()) > EVENT_DATA_MAX:
        raw = "{}"
    db.add(EdgeEvent(edge_id=edge.id, at=now or utcnow(), kind=kind, data=raw))


def prune_events(db: Session, now: datetime | None = None) -> None:
    from sqlalchemy import delete

    cutoff = (now or utcnow()) - timedelta(days=EDGE_EVENTS_RETENTION_DAYS)
    db.execute(delete(EdgeEvent).where(EdgeEvent.at < cutoff))


def events_of(db: Session, edge: Edge, limit: int = 20) -> list[dict]:
    rows = db.scalars(select(EdgeEvent).where(EdgeEvent.edge_id == edge.id)
                      .order_by(EdgeEvent.at.desc(), EdgeEvent.id.desc()).limit(limit))
    return [{"at": iso(r.at), "kind": r.kind, "data": loads(r.data)} for r in rows]


# ------------------------------------------------------------------ drain (§22.1)

def is_draining(e) -> bool:
    return dnsbuild.is_draining(e)


def refuse_after(e) -> datetime | None:
    """When the node starts refusing NEW tunnel connections: after one DNS answer lifetime + 30 s,
    so a client holding a fresh answer is never refused."""
    if not is_draining(e) or e.drain_started_at is None:
        return None
    return e.drain_started_at + timedelta(seconds=settings.proxied_ttl + DRAIN_GRACE_EXTRA)


def drain_dict(e: Edge) -> dict:
    """edge_to_dict["drain"]."""
    state = e.drain_state or ""
    if state not in ("draining", "drained"):
        return {"state": "", "since": None, "until": None, "by": None, "reason": None, "conns": e.drain_conns}
    return {"state": state, "since": iso(e.drain_started_at), "until": iso(e.drain_until),
            "by": e.drain_by, "reason": e.drain_reason, "conns": e.drain_conns}


def drain_block(e: Edge | None) -> dict:
    """Edge config `node.drain` (only the requesting edge's own state; agent-side only, never
    rendered into nginx)."""
    if e is None or not is_draining(e):
        return {"state": ""}
    return {"state": e.drain_state, "refuse_after": iso(refuse_after(e)), "until": iso(e.drain_until)}


def is_last_edge(db: Session, e: Edge, now: datetime | None = None) -> bool:
    """Draining `e` would leave its group+region with no online, enabled, non-shed, non-draining
    edge."""
    from .services import online_edges

    now = now or utcnow()
    group, region = dnsbuild.edge_group(e), dnsbuild.region_of(e)
    for x in online_edges(db):
        if x.id == e.id or dnsbuild.edge_group(x) != group or dnsbuild.region_of(x) != region:
            continue
        if not dnsbuild.is_shed(x, now) and not is_draining(x):
            return False
    return True


def start_drain(db: Session, e: Edge, minutes: int, reason: str, by: str, now: datetime | None = None) -> None:
    """Start (or re-time) a drain. Caller checks last_edge / already_draining and commits."""
    now = now or utcnow()
    if is_draining(e) and e.drain_started_at is not None:
        # re-timing only moves drain_until; a drained edge stays drained (its connections are gone)
        e.drain_until = e.drain_started_at + timedelta(minutes=minutes)
        return
    e.drain_state = "draining"
    e.drain_started_at = now
    e.drain_until = now + timedelta(minutes=minutes)
    e.drain_by = by
    e.drain_reason = reason
    add_event(db, e, "drain_start", {"by": by, "reason": reason, "minutes": minutes}, now)


def stop_drain(db: Session, e: Edge, by: str, now: datetime | None = None, auto: bool = False) -> bool:
    """Clear a drain; True when there was one. Caller commits."""
    if not is_draining(e):
        return False
    now = now or utcnow()
    add_event(db, e, "drain_end", {"by": by, "auto": auto,
                                   "minutes": int((now - e.drain_started_at).total_seconds() // 60)
                                   if e.drain_started_at else None}, now)
    e.drain_state, e.drain_started_at, e.drain_until = "", None, None
    e.drain_by = e.drain_reason = None
    return True


def record_drain_report(db: Session, e: Edge, report: dict, now: datetime) -> None:
    """Heartbeat `drain` {state, conns, since}: the agent reports `drained` once its client
    connections went down; the drain itself stays controller-driven."""
    conns = report.get("conns")
    if conns is not None:
        e.drain_conns = int(conns)
    if e.drain_state == "draining" and report.get("state") == "drained":
        e.drain_state = "drained"
        add_event(db, e, "drained", {"by": "edge", "conns": e.drain_conns}, now)


def job_drain(db: Session, now: datetime | None = None) -> dict:
    """Scheduler (leader): `draining` -> `drained` at drain_until; a drain still held
    DRAIN_MAX_HOLD_MINUTES after drain_until is cleared (alert edge_drain_stuck + audit by system).
    DNS is re-synced at once when an edge comes back."""
    from . import alerts
    from .audit import record_audit
    from .services import sync_all_dns

    now = now or utcnow()
    hold = timedelta(minutes=settings.drain_max_hold_minutes)
    drained, cleared = [], []
    for e in db.scalars(select(Edge).where(Edge.drain_state.in_(("draining", "drained"))).order_by(Edge.id)):
        if e.drain_until is None:
            continue
        if now >= e.drain_until + hold:
            stop_drain(db, e, "system", now, auto=True)
            cleared.append(e)
        elif e.drain_state == "draining" and now >= e.drain_until:
            e.drain_state = "drained"
            add_event(db, e, "drained", {"by": "controller", "conns": e.drain_conns}, now)
            drained.append(e.name)
    db.commit()
    for e in cleared:
        record_audit(db, actor="system", actor_kind="system", action="edge.undrain", target=e.name,
                     detail={"auto": True, "hold_minutes": settings.drain_max_hold_minutes})
        alerts.raise_alert(
            f"edge_drain_stuck:{e.id}", f"تخلیه‌ی نود {e.name} خودکار لغو شد",
            f"نود {e.name} {settings.drain_max_hold_minutes} دقیقه پس از پایان زمان تخلیه هنوز در حالت تخلیه بود؛ "
            "تخلیه خودکار لغو شد و نود به پاسخ‌های DNS برگشت. اگر به‌روزرسانی نود ناتمام مانده، وضعیت آن را "
            "بررسی کنید.", "warning")
    if cleared:
        sync_all_dns(db)
    return {"drained": drained, "cleared": [e.name for e in cleared]}


# ------------------------------------------------------------------ tunnel probe (§22.3)

def record_probe(db: Session, e: Edge, probe: dict, now: datetime) -> None:
    """Store the latest probe report and apply the degraded hysteresis. A report is counted once
    (by its `at`) and only while fresh; a heartbeat without `tunnel_probe` changes nothing."""
    prev = loads(e.tunnel_probe)
    e.tunnel_probe = json.dumps(probe, sort_keys=True)
    at = None
    try:
        at = naive(datetime.fromisoformat(str(probe.get("at")).replace("Z", "+00:00")))
    except (TypeError, ValueError):
        return
    if prev.get("at") == probe.get("at") or at is None or now - at > PROBE_STALE:
        return
    if probe.get("ok"):
        e.tunnel_probe_ok = (e.tunnel_probe_ok or 0) + 1
        e.tunnel_probe_fail = 0
    else:
        e.tunnel_probe_fail = (e.tunnel_probe_fail or 0) + 1
        e.tunnel_probe_ok = 0
    if not e.tunnel_degraded and e.tunnel_probe_fail >= settings.tunnel_probe_fail_checks:
        e.tunnel_degraded, e.tunnel_degraded_since = True, now
        add_event(db, e, "degraded", {"fail": e.tunnel_probe_fail}, now)
        log.warning("edge %s: tunnel probe failed %d times, tunnel-degraded", e.name, e.tunnel_probe_fail)
    elif (e.tunnel_degraded and e.tunnel_probe_ok >= settings.tunnel_probe_ok_checks
          and (e.tunnel_degraded_since is None or now - e.tunnel_degraded_since >= DEGRADED_MIN_HOLD)):
        add_event(db, e, "recovered", {"ok": e.tunnel_probe_ok}, now)
        e.tunnel_degraded, e.tunnel_degraded_since = False, None
        log.info("edge %s: tunnel probe recovered", e.name)


def tunnel_probe_dict(e: Edge) -> dict:
    last = loads(e.tunnel_probe) or None
    return {"degraded": bool(e.tunnel_degraded), "since": iso(e.tunnel_degraded_since), "last": last}


def parse_probe_origin(raw: str) -> dict | None:
    """TUNNEL_PROBE_ORIGIN "host:port[:tls]" ([v6]:port allowed) -> {host, port, tls}; None when empty
    or invalid (the node then probes its local loopback echo origin)."""
    raw = (raw or "").strip()
    if not raw:
        return None
    tls = False
    if raw.lower().endswith(":tls"):
        tls, raw = True, raw[:-4]
    host, _, port = raw.rpartition(":")
    host = host.strip().strip("[]")
    if not host or not port.isdigit() or not 1 <= int(port) <= 65535 or not re.match(r"^[A-Za-z0-9.:_-]{1,253}$", host):
        log.warning("TUNNEL_PROBE_ORIGIN is not host:port[:tls]; the nodes probe their local echo origin")
        return None
    return {"host": host, "port": int(port), "tls": tls}


def probe_block() -> dict:
    """Edge config `node.probe` (agent-side only, never rendered)."""
    return {"origin": parse_probe_origin(settings.tunnel_probe_origin), "interval": PROBE_INTERVAL_DEFAULT}


# ------------------------------------------------------------------ reloads / tuning / pileup (§22.2, §22.6)

def record_reloads(e: Edge, reloads: dict) -> None:
    prev = loads(e.reload_stats)
    n = int(prev.get("_storm_n") or 0)
    storm = bool(prev.get("_storm"))
    count = int(reloads.get("count_1h") or 0)
    n = n + 1 if count > RELOAD_STORM_OPEN else 0
    if n >= RELOAD_STORM_CHECKS:
        storm = True
    elif count <= RELOAD_STORM_RESOLVE:
        storm = False
    e.reload_stats = json.dumps({**reloads, "_storm_n": n, "_storm": storm}, sort_keys=True)


def reload_storm(e: Edge) -> bool:
    return bool(loads(e.reload_stats).get("_storm"))


def record_tuning(e: Edge, tuning: dict) -> None:
    prev = loads(e.tuning)
    n = 0 if tuning.get("ok", True) else int(prev.get("_bad_n") or 0) + 1
    e.tuning = json.dumps({**tuning, "_bad_n": n}, sort_keys=True)


def tuning_bad(e: Edge) -> bool:
    return int(loads(e.tuning).get("_bad_n") or 0) >= TUNING_CHECKS


def pileup_counter(prev: dict, metrics: dict) -> int:
    """Consecutive heartbeats with draining worker generations > 4 x cpus."""
    dw, cpus = metrics.get("draining_workers"), metrics.get("cpus") or 0
    if dw is None or cpus <= 0 or dw <= PILEUP_PER_CPU * cpus:
        return 0
    return int(prev.get("_pileup_n") or 0) + 1


def mem_counter(prev: dict, metrics: dict, open_pct: float) -> tuple[int, bool]:
    """(consecutive heartbeats at or above `open_pct`, alert state) with hysteresis: the state opens after
    MEM_ALERT_CHECKS of them (at once from MEM_CRIT_PCT up) and closes MEM_RESOLVE_MARGIN points below
    `open_pct`. A node that reports no mem_pct (older agent) never alerts, and never resolves on the
    missing value alone."""
    mem = metrics.get("mem_pct")
    high = bool(prev.get("_mem_high"))
    if mem is None:
        return int(prev.get("_mem_n") or 0), high
    mem = float(mem)
    n = int(prev.get("_mem_n") or 0) + 1 if mem >= open_pct else 0
    if mem >= MEM_CRIT_PCT or n >= MEM_ALERT_CHECKS:
        high = True
    elif mem <= max(0.0, open_pct - MEM_RESOLVE_MARGIN):
        high = False
    return n, high


def memory_high(e: Edge) -> bool:
    return bool(loads(e.metrics).get("_mem_high"))


# ------------------------------------------------------------------ DNS weight level (§22.10)

def weight_level(level: int, pct: float | None, prev: dict) -> tuple[int, int, int]:
    """(new level, up streak, down streak). Up to 1 at >= 70 % / 2 at >= 85 % for 2 consecutive
    reports; down below 60 % (to 0) / 75 % (to 1) for 3 reports. Unknown load counts as low."""
    level = level if level in LEVEL_FACTOR else 0
    p = -1.0 if pct is None else pct
    up_target = 2 if p >= 85 else 1 if p >= 70 else 0
    down_target = 0 if p < 60 else 1 if p < 75 else 2
    up = int(prev.get("_wl_up") or 0) + 1 if up_target > level else 0
    down = int(prev.get("_wl_down") or 0) + 1 if down_target < level else 0
    if up >= LEVEL_UP_CHECKS:
        return up_target, 0, 0
    if down >= LEVEL_DOWN_CHECKS:
        return down_target, 0, 0
    return level, up, down


def dns_weight_dict(e: Edge, q: int | None) -> dict:
    return {"level": int(e.dns_weight_level or 0), "q": q}
