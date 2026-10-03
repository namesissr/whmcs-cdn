"""API polled by edge agents."""

import hashlib
import ipaddress
import json
import logging
import math
import re
import threading
import time
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from typing import Any, Literal

from fastapi import APIRouter, Depends, Header, Request, Response
from pydantic import BaseModel, ConfigDict, Field, field_validator
from pydantic import ValidationError as PydanticValidationError
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from . import access as access_mod
from . import alerts, dnsbuild, edge_state, live, logexport, sections, waf_learning, webhooks
from . import waiting_room as wr_mod
from .auth import require_edge
from .config import settings
from .db import get_db
from .models import Edge, Purge, SecurityEvent, Site, State, UsageBatch, UsageHourly, utcnow
from .services import EDGE_IP_PLACEHOLDER, build_edge_config, record_metrics
from .validation import num
from .validation import obj as _obj

log = logging.getLogger("pcdn")

router = APIRouter(prefix="/edge/v1")


@router.get("/config")
def config(
    response: Response,
    if_none_match: str | None = Header(default=None),
    edge: Edge = Depends(require_edge),
    db: Session = Depends(get_db),
):
    edge.last_seen_at = utcnow()
    db.commit()
    # per-edge: the node-wide `shield` block (self flag, peer list without this edge) differs by node
    cfg = build_edge_config(db, edge)
    etag = f'"{cfg["version"]}"'
    if if_none_match == etag:
        return Response(status_code=304, headers={"ETag": etag})
    response.headers["ETag"] = etag
    return cfg


class Metrics(BaseModel):
    """Edge load (SPEC §7.4); unknown keys are ignored."""
    rx_mbps: float = Field(0, ge=0, le=10_000_000)
    tx_mbps: float = Field(0, ge=0, le=10_000_000)
    connections: int = Field(0, ge=0, le=1_000_000_000)
    load1: float = Field(0, ge=0, le=1_000_000)
    cpus: int = Field(0, ge=0, le=100_000)
    # optional; older agents omit them and no disk/memory alert is raised for that edge
    disk_pct: float | None = Field(default=None, ge=0, le=100)
    mem_pct: float | None = Field(default=None, ge=0, le=100)
    # SPEC §22.2: worker generations still shutting down after reloads, and the node's TCP sockets
    # (all / TIME_WAIT); older agents omit them
    draining_workers: int | None = Field(default=None, ge=0, le=100_000)
    sock_tcp: int | None = Field(default=None, ge=0, le=10**9)
    sock_tw: int | None = Field(default=None, ge=0, le=10**9)


CAP_MODULES_MAX = 64
CAP_MODULE_RE = re.compile(r"^[A-Za-z0-9_.\-]{1,64}$")


class Capabilities(BaseModel):
    """What this node's nginx can do (SPEC §14.1); unknown keys are ignored. The agent detects
    them (`nginx -V`, module files present) and the edge renders the matching directives only where
    supported; the controller just keeps the latest report for the panel."""
    http3: bool = False
    early_hints: bool = False
    webp_convert: bool = False
    modules: list[str] = Field(default_factory=list)
    # SPEC §14.2: managed WAF pack versions ({pack: version}); SPEC §14.3: the agent sends `live`
    # minute aggregates and ships access-log records. Older agents omit them (False / {}).
    waf_packs: dict[str, int] = Field(default_factory=dict)
    live_analytics: bool = False
    logship: bool = False
    # wave 8 (SPEC §16.3-§16.6), older agents omit them (False / None): `l4` = the node can carry the
    # TCP/UDP listeners (nginx stream module + include) and its L4_PORT_RANGE, `slice` = byte-range
    # slicing for video, `video`, `avif` (avifenc/libavif), `image_transform` (resizer present),
    # `net_guard` (install.sh --harden-net nftables guard)
    l4: bool = False
    l4_port_range: str | None = None
    slice: bool = False
    video: bool = False
    avif: bool = False
    image_transform: bool = False
    net_guard: bool = False
    # SPEC §16.9: pcdn-fn installed (install.sh --functions) and its sandbox self-test passing
    edge_functions: bool = False
    # SPEC §22 (wave 13): the agent enforces drain (§22.1), runs the tunnel probe (§22.3), builds
    # internal pools for `origins` paths (§22.4), nginx has `server … resolve` in upstreams (§22.7)
    drain: bool = False
    tunnel_probe: bool = False
    tunnel_multi_origin: bool = False
    upstream_resolve: bool = False

    @field_validator("l4_port_range", mode="before")
    @classmethod
    def _range(cls, v):
        # informational: a malformed value is dropped, never fails the heartbeat
        return v if isinstance(v, str) and re.match(r"^\d{1,5}-\d{1,5}$", v) else None

    @field_validator("waf_packs", mode="before")
    @classmethod
    def _waf_packs(cls, v):
        if not isinstance(v, dict):
            return {}
        # junk entries are dropped (not rejected), like module names
        out = {k: n for k, n in v.items() if isinstance(k, str) and CAP_MODULE_RE.match(k)
               and isinstance(n, int) and not isinstance(n, bool) and 0 <= n <= 1_000_000}
        return dict(sorted(out.items())[:CAP_MODULES_MAX])

    @field_validator("modules", mode="before")
    @classmethod
    def _modules(cls, v):
        if v is None:
            return []
        if not isinstance(v, list):
            raise ValueError("modules must be a list of module names")
        out: list[str] = []
        for m in v:
            # junk names are dropped (not rejected) so a quirky build never fails the heartbeat
            if isinstance(m, str) and CAP_MODULE_RE.match(m) and m not in out:
                out.append(m)
        return sorted(out)[:CAP_MODULES_MAX]


def _clip(v, n: int):
    return v[:n] if isinstance(v, str) else v


class DrainReport(BaseModel):
    """Heartbeat `drain` (SPEC §22.1)."""
    state: Literal["", "draining", "drained"] = ""
    conns: int | None = Field(default=None, ge=0, le=10**9)
    since: datetime | None = None


class ProbeResult(BaseModel):
    """One probe of heartbeat `tunnel_probe` (SPEC §22.3): ws / grpc, or {"unsupported": true}."""
    unsupported: bool | None = None
    ok: bool | None = None
    setup_ms: int | None = Field(default=None, ge=0, le=10**7)
    echo_ok: bool | None = None
    down_kbps: int | None = Field(default=None, ge=0, le=10**9)
    up_kbps: int | None = Field(default=None, ge=0, le=10**9)
    error: str | None = None

    @field_validator("error", mode="before")
    @classmethod
    def _error(cls, v):
        from .edge_state import scrub

        return scrub(v, 120) if isinstance(v, str) else None


class TunnelProbe(BaseModel):
    at: datetime
    ok: bool
    ws: ProbeResult | None = None
    grpc: ProbeResult | None = None
    consecutive_fail: int = Field(default=0, ge=0, le=10**6)


class Reloads(BaseModel):
    """Heartbeat `reloads` (SPEC §22.2)."""
    count_1h: int = Field(default=0, ge=0, le=10**6)
    count_24h: int = Field(default=0, ge=0, le=10**7)
    last_at: datetime | None = None
    coalesced_1h: int = Field(default=0, ge=0, le=10**6)
    pending_s: int = Field(default=0, ge=0, le=10**8)
    deferred: bool = False
    wst_s: int | None = Field(default=None, ge=0, le=10**7)
    forced_shutdowns_24h: int = Field(default=0, ge=0, le=10**6)


class TuningMismatch(BaseModel):
    key: str = Field(default="", max_length=256)
    want: str = ""
    have: str = ""

    @field_validator("key", "want", "have", mode="before")
    @classmethod
    def _cut(cls, v):
        return _clip(str(v) if v is not None else "", 64)


class Tuning(BaseModel):
    """Heartbeat `tuning` (SPEC §22.6)."""
    profile: Literal["auto", "off"] = "auto"
    ram_mb: int = Field(default=0, ge=0, le=10**8)
    ok: bool = True
    cc: str | None = None
    qdisc: str | None = None
    nofile: int | None = Field(default=None, ge=0, le=10**10)
    mismatches: list[TuningMismatch] = Field(default_factory=list)

    @field_validator("cc", "qdisc", mode="before")
    @classmethod
    def _short(cls, v):
        return _clip(v, 64) if isinstance(v, str) else None

    @field_validator("mismatches", mode="before")
    @classmethod
    def _cap(cls, v):
        return list(v)[:20] if isinstance(v, list) else []


def _ignore_malformed(name: str):
    """A malformed wave-13 heartbeat object is ignored (None), never a 422: a heartbeat must not
    fail on an informational field."""
    def wrap(cls, v, handler):
        try:
            return handler(v)
        except PydanticValidationError:
            log.warning("ignoring malformed %s in an edge heartbeat", name)
            return None
    return wrap


class Heartbeat(BaseModel):
    applied_version: str | None = None
    error: str | None = Field(default=None, max_length=4000)
    metrics: Metrics | None = None
    # running edge bundle version (SPEC §11.1); older agents omit it
    bundle_version: str | None = Field(default=None, max_length=64)
    # self-registration into the right pool on first contact (SPEC §11.1); older agents omit them
    region: str | None = Field(default=None, pattern="^(home|global)$")
    group: str | None = Field(default=None, pattern="^(general|tunnel)$")
    # F9: whether the node currently has a GeoIP database. The edge FAILS OPEN on allowed_countries
    # when it has none (it no longer 403s every tunnel request), so the controller must NOT assume the
    # edge enforces allowed_countries at the node — it doesn't here, and geoip provisioning is a node
    # concern. Accepted for observability; older agents omit it.
    geoip: bool | None = None
    # node capabilities (SPEC §14.1); older agents omit them. A malformed report is ignored (the
    # previously stored capabilities are kept) instead of failing the heartbeat: a 422 here would
    # make a healthy node look silent and drop it from DNS over an informational field.
    capabilities: Capabilities | None = None
    # wave 10, older agents omit them. SPEC §18.4: agent errors logged in the last hour (shown on the
    # node page); SPEC §18.1: per-site waiting room counters {"<domain>": {"active": n, "queued": n}}
    # (≤1000 sites). Malformed values are ignored, never a 422 (a heartbeat must not fail on them).
    errors_last_hour: int | None = None
    waiting_room: dict[str, dict[str, int]] | None = None

    @field_validator("errors_last_hour", mode="before")
    @classmethod
    def _errors(cls, v):
        if isinstance(v, bool) or not isinstance(v, int) or not 0 <= v <= wr_mod.HEARTBEAT_MAX_VALUE:
            return None
        return v

    @field_validator("waiting_room", mode="before")
    @classmethod
    def _wr(cls, v):
        return None if v is None else wr_mod.clean_heartbeat(v)

    # wave 13 (SPEC §22), older agents omit them; malformed values are ignored (never a 422)
    drain: DrainReport | None = None
    tunnel_probe: TunnelProbe | None = None
    reloads: Reloads | None = None
    tuning: Tuning | None = None

    _drain = field_validator("drain", mode="wrap")(classmethod(_ignore_malformed("drain")))
    _probe = field_validator("tunnel_probe", mode="wrap")(classmethod(_ignore_malformed("tunnel_probe")))
    _reloads = field_validator("reloads", mode="wrap")(classmethod(_ignore_malformed("reloads")))
    _tuning = field_validator("tuning", mode="wrap")(classmethod(_ignore_malformed("tuning")))

    @field_validator("capabilities", mode="wrap")
    @classmethod
    def _capabilities(cls, v, handler):
        try:
            return handler(v)
        except PydanticValidationError:
            log.warning("ignoring malformed capabilities in an edge heartbeat")
            return None


def _self_register_ip(edge: Edge, request: Request) -> None:
    """Fill a batch edge's placeholder IP from the heartbeat's source address, so it enters DNS
    with a real address (uvicorn runs with --proxy-headers, so this is the node's public IP)."""
    if edge.ipv4 != EDGE_IP_PLACEHOLDER or request.client is None:
        return
    try:
        ip = ipaddress.ip_address(request.client.host)
    except ValueError:
        return
    if ip.is_private or ip.is_loopback or ip.is_link_local:
        return
    if ip.version == 4:
        edge.ipv4 = str(ip)
    elif edge.ipv6 is None:
        edge.ipv6 = str(ip)  # v6-only first contact; the operator can still set the v4 in the panel


@router.post("/heartbeat")
def heartbeat(body: Heartbeat, request: Request, edge: Edge = Depends(require_edge),
              db: Session = Depends(get_db)):
    first_contact = edge.last_seen_at is None
    edge.last_seen_at = utcnow()
    edge.applied_version = body.applied_version
    edge.last_error = body.error
    now = edge.last_seen_at
    if body.bundle_version is not None:
        if edge.bundle_version and body.bundle_version != edge.bundle_version:
            # SPEC §22.12/§22.13: a node upgrade is a maintenance event (no address, no secret)
            edge_state.add_event(db, edge, "upgrade", {"version": body.bundle_version}, now)
        edge.bundle_version = body.bundle_version
    # a fresh node reports its region/role once; never override an operator's later panel edit
    if first_contact:
        if body.region is not None:
            edge.region = body.region
        if body.group is not None:
            edge.group = body.group
    _self_register_ip(edge, request)
    if body.capabilities is not None:
        edge.capabilities = json.dumps(body.capabilities.model_dump(), sort_keys=True)
    if body.metrics is not None:
        # the shed flag changes here; scheduler.job_edges rewrites DNS on its next tick
        record_metrics(edge, body.metrics.model_dump(), edge.last_seen_at)
    if body.errors_last_hour is not None:
        edge.errors_last_hour = body.errors_last_hour
    if body.waiting_room is not None:
        wr_mod.record_heartbeat(edge, body.waiting_room, edge.last_seen_at)
    # wave 13 (SPEC §22): drain progress, tunnel probe (degraded hysteresis), reload / tuning reports.
    # A heartbeat without them leaves the stored state untouched (old agents are never degraded).
    if body.drain is not None:
        edge_state.record_drain_report(db, edge, body.drain.model_dump(), now)
    if body.tunnel_probe is not None:
        edge_state.record_probe(db, edge, body.tunnel_probe.model_dump(mode="json", exclude_none=True), now)
    if body.reloads is not None:
        edge_state.record_reloads(edge, body.reloads.model_dump(mode="json"))
    if body.tuning is not None:
        edge_state.record_tuning(edge, body.tuning.model_dump(mode="json"))
    db.commit()
    return {"ok": True}


# ------------------------------------------------------------------ drain (SPEC §22.1)

DRAIN_RATE_PER_MIN = 10
_drain_calls: dict[int, list[float]] = {}
_drain_lock = threading.Lock()


class DrainIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    action: Literal["start", "stop"]
    minutes: int | None = Field(default=None, ge=1, le=120)
    reason: str | None = Field(default=None, pattern=r"^[\x20-\x7e]{1,64}$")


def _drain_rate(edge_id: int) -> None:
    from fastapi import HTTPException

    now = time.monotonic()
    with _drain_lock:
        calls = [t for t in _drain_calls.get(edge_id, []) if now - t < 60]
        if len(calls) >= DRAIN_RATE_PER_MIN:
            _drain_calls[edge_id] = calls
            raise HTTPException(429, "too many drain calls", headers={"Retry-After": str(int(60 - (now - calls[0])) + 1)})
        calls.append(now)
        _drain_calls[edge_id] = calls


@router.post("/drain")
def drain(body: DrainIn, request: Request, edge: Edge = Depends(require_edge), db: Session = Depends(get_db)):
    """The node drains / undrains ITSELF (bootstrap.sh / install.sh --upgrade --drain). 409
    {"detail": "last_edge"} when it is the last active edge of its group+region (no force here)."""
    from fastapi import HTTPException

    from .audit import record_audit
    from .services import sync_all_dns

    _drain_rate(edge.id)
    now = utcnow()
    edge.last_seen_at = now
    ip = request.client.host if request.client else None
    if body.action == "start":
        minutes = body.minutes or settings.drain_default_minutes
        reason = body.reason or "upgrade"
        if not edge_state.is_draining(edge) and edge_state.is_last_edge(db, edge, now):
            db.commit()
            raise HTTPException(409, "last_edge")
        edge_state.start_drain(db, edge, minutes, reason, "edge", now)
        db.commit()
        record_audit(db, actor=edge.name, actor_kind="edge", action="edge.drain", target=edge.name,
                     detail={"minutes": minutes, "reason": reason, "force": False}, ip=ip)
    else:
        changed = edge_state.stop_drain(db, edge, "edge", now)
        db.commit()
        if changed:
            record_audit(db, actor=edge.name, actor_kind="edge", action="edge.undrain", target=edge.name,
                         detail={}, ip=ip)
    alerts.resolve_alert(f"edge_drain_stuck:{edge.id}", notify=False)
    sync_all_dns(db)
    return {"state": edge.drain_state if edge_state.is_draining(edge) else "",
            "until": edge_state.iso(edge.drain_until) if edge_state.is_draining(edge) else None,
            "refuse_after": edge_state.iso(edge_state.refuse_after(edge))}


# centralized node logs (SPEC §11.2): the agent ships only recent operational WARN/ERROR/crit
# lines (nginx error log + its own log). Size-capped so a noisy node cannot flood the controller.
LOG_LEVELS = {"warn", "error", "crit", "notice", "info"}
LOG_MAX_LINES_PER_CALL = 40
LOG_MSG_MAX = 500
LOG_RING_MAX_LINES = 120
LOG_RING_MAX_BYTES = 16 * 1024


class LogLine(BaseModel):
    t: str = Field(default="", max_length=40)
    level: str = "info"
    msg: str = Field(default="", max_length=4000)


class LogsIn(BaseModel):
    lines: list[LogLine] = Field(default_factory=list, max_length=LOG_MAX_LINES_PER_CALL)


def _append_logs(edge: Edge, incoming: list[dict]) -> None:
    """Append newest-last into the edge's capped ring; drop oldest past the line/byte cap."""
    try:
        ring = json.loads(edge.logs) if edge.logs else []
        if not isinstance(ring, list):
            ring = []
    except (ValueError, TypeError):
        ring = []
    ring.extend(incoming)
    # hard line cap first, then byte cap (drop oldest until the serialized ring fits)
    if len(ring) > LOG_RING_MAX_LINES:
        ring = ring[-LOG_RING_MAX_LINES:]
    while len(ring) > 1 and len(json.dumps(ring, ensure_ascii=False).encode("utf-8")) > LOG_RING_MAX_BYTES:
        ring = ring[1:]
    edge.logs = json.dumps(ring, ensure_ascii=False)
    edge.logs_at = utcnow()


@router.post("/logs")
def logs(body: LogsIn, edge: Edge = Depends(require_edge), db: Session = Depends(get_db)):
    clean = []
    for ln in body.lines:
        level = ln.level if ln.level in LOG_LEVELS else "info"
        msg = (ln.msg or "")[:LOG_MSG_MAX]
        clean.append({"t": ln.t[:40], "level": level, "msg": msg})
    if clean:
        _append_logs(edge, clean)
        db.commit()
    return {"ok": True}


@router.get("/purges")
def purges(after: int = 0, edge: Edge = Depends(require_edge), db: Session = Depends(get_db)):
    rows = db.execute(
        select(Purge, Site.domain).join(Site, Site.id == Purge.site_id)
        .where(Purge.id > after).order_by(Purge.id).limit(500)
    ).all()
    return [{"id": p.id, "domain": d, "site_id": p.site_id, "urls": json.loads(p.urls),
             "prefixes": json.loads(p.prefixes), "everything": p.everything} for p, d in rows]


Counts = dict[str, int]


TUNNEL_PROTOCOLS = ("ws", "httpupgrade", "grpc", "xhttp", "h2")
TUNNEL_COUNTERS = ("sessions", "seconds", "bytes_up", "bytes_down")
BIG = 10**18


# SPEC §15.1: per tunnel path id quality counters (wave 7). Pre-wave-7 agents omit `paths`.
TUNNEL_PATH_ID_RE = re.compile(r"^[a-z0-9_-]{1,32}$")
TUNNEL_MAX_PATHS = 50
TUNNEL_ERROR_KEYS = ("origin_refused", "origin_timeout", "origin_error", "limit", "country", "protocol", "edge")
TUNNEL_PATH_COUNTERS = ("sessions", "seconds", "bytes_up", "bytes_down", "abnormal", "connect_ms_sum",
                        "connect_n", "reused_n")
# SPEC §22.12: how accepted tunnel sessions of a host-hour ended (pre-wave-13 agents omit `ends`)
TUNNEL_END_KEYS = ("normal", "idle_timeout", "origin", "node_reload", "node_drain", "other")


class TunnelPathErrors(BaseModel):
    """Request counts per error class (SPEC §15.1); unknown keys are ignored (dropped)."""
    origin_refused: int = Field(0, ge=0, le=BIG)
    origin_timeout: int = Field(0, ge=0, le=BIG)
    origin_error: int = Field(0, ge=0, le=BIG)
    limit: int = Field(0, ge=0, le=BIG)
    country: int = Field(0, ge=0, le=BIG)
    protocol: int = Field(0, ge=0, le=BIG)
    edge: int = Field(0, ge=0, le=BIG)


class TunnelPathEnds(BaseModel):
    """Session ends per reason (SPEC §22.12); unknown keys are ignored (dropped)."""
    normal: int = Field(0, ge=0, le=BIG)
    idle_timeout: int = Field(0, ge=0, le=BIG)
    origin: int = Field(0, ge=0, le=BIG)
    node_reload: int = Field(0, ge=0, le=BIG)
    node_drain: int = Field(0, ge=0, le=BIG)
    other: int = Field(0, ge=0, le=BIG)


class TunnelPathUsage(BaseModel):
    """One path id of one host-hour (SPEC §15.1); unknown keys are ignored (dropped)."""
    sessions: int = Field(0, ge=0, le=BIG)
    seconds: float = Field(0, ge=0, le=BIG)
    bytes_up: int = Field(0, ge=0, le=BIG)
    bytes_down: int = Field(0, ge=0, le=BIG)
    abnormal: int = Field(0, ge=0, le=BIG)
    connect_ms_sum: float = Field(0, ge=0, le=BIG)
    connect_n: int = Field(0, ge=0, le=BIG)
    # SPEC §22.7: tunnel requests whose upstream connect time was exactly 0.000 (reused connection)
    reused_n: int = Field(0, ge=0, le=BIG)
    errors: TunnelPathErrors = Field(default_factory=TunnelPathErrors)
    # SPEC §22.12 (optional): None = the agent does not classify session ends yet
    ends: TunnelPathEnds | None = None


class TunnelUsage(BaseModel):
    sessions: int = Field(0, ge=0, le=BIG)
    seconds: float = Field(0, ge=0, le=BIG)
    bytes_up: int = Field(0, ge=0, le=BIG)    # received from the client (billed too, SPEC §7.3)
    bytes_down: int = Field(0, ge=0, le=BIG)  # sent to the client (already part of `bytes`)
    by_protocol: Counts = {}                  # protocol -> bytes (up + down)
    # SPEC §15.1: {path id: counters}. Ids not matching [a-z0-9_-]{1,32} are dropped, and at most 50
    # ids are kept (the busiest ones) instead of rejecting the batch: a 422 here would block the
    # agent's billing outbox on an informational field. Negative / non-numeric counters -> 422 like
    # every other usage counter.
    paths: dict[str, TunnelPathUsage] = {}

    @field_validator("paths", mode="before")
    @classmethod
    def _path_ids(cls, v):
        if v is None:
            return {}
        if not isinstance(v, dict):
            raise ValueError("tunnel.paths must be an object of path id -> counters")
        return {k: c for k, c in v.items() if isinstance(k, str) and TUNNEL_PATH_ID_RE.match(k)}

    @field_validator("paths", mode="after")
    @classmethod
    def _cap(cls, v):
        if len(v) <= TUNNEL_MAX_PATHS:
            return v
        busiest = sorted(v.items(), key=lambda kv: (-(kv[1].sessions + sum(kv[1].errors.model_dump().values())),
                                                    kv[0]))
        log.warning("dropping %d tunnel path ids beyond %d in a usage item", len(v) - TUNNEL_MAX_PATHS,
                    TUNNEL_MAX_PATHS)
        return dict(busiest[:TUNNEL_MAX_PATHS])


L4_APP_ID_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?$")
L4_MAX_APPS = 100
L4_COUNTERS = ("bytes_in", "bytes_out", "sessions")


class L4AppUsage(BaseModel):
    """One TCP/UDP proxy app of one site-hour (SPEC §16.4); unknown keys are ignored."""
    bytes_in: int = Field(0, ge=0, le=BIG)   # client -> edge
    bytes_out: int = Field(0, ge=0, le=BIG)  # edge -> client
    sessions: int = Field(0, ge=0, le=BIG)


class VideoUsage(BaseModel):
    """Video part of an item's traffic (SPEC §16.5): bytes (already included in `bytes`) and requests
    of manifests + segments. A bare integer is accepted as the byte count."""
    bytes: int = Field(0, ge=0, le=BIG)
    requests: int = Field(0, ge=0, le=BIG)
    cache_hits: int = Field(0, ge=0, le=BIG)


FUNCTION_COUNTERS = ("invocations", "cpu_ms", "errors", "timeouts")


class FunctionsUsage(BaseModel):
    """Edge function invocations of one host-hour (SPEC §16.9); unknown keys are ignored. `errors`
    and `timeouts` are disjoint (a timed-out invocation is not also an error)."""
    invocations: int = Field(0, ge=0, le=BIG, strict=True)
    cpu_ms: int = Field(0, ge=0, le=BIG, strict=True)
    errors: int = Field(0, ge=0, le=BIG, strict=True)
    timeouts: int = Field(0, ge=0, le=BIG, strict=True)


class UsageItem(BaseModel):
    host: str = Field(max_length=253)
    hour: datetime
    bytes: int = Field(ge=0, le=BIG)
    requests: int = Field(ge=0, le=BIG)
    cache_hits: int = Field(default=0, ge=0, le=BIG)
    status: Counts = {}
    codes: Counts = {}
    countries: Counts = {}
    paths: Counts = {}
    security: Counts = {}
    tunnel: TunnelUsage | None = None
    # SPEC §14.3.1: responses with status >= 500 the edge produced itself (no upstream status, no
    # security action); origin errors never count. Summed into the hourly details for the SLA report.
    platform_errors: int = Field(default=0, ge=0, le=BIG)
    # SPEC §16.4: {app id: {bytes_in, bytes_out, sessions}} of the TCP/UDP proxy apps of the item's
    # site (host = the site domain or an app's l4-<id> hostname). NOT part of `bytes`: both directions
    # are added to the billed bytes here. Unknown ids are dropped, at most 100 per item.
    l4: dict[str, L4AppUsage] = {}
    # SPEC §16.5: the video share of `bytes` (breakdown only, not billed twice)
    video: VideoUsage | None = None
    # SPEC §16.9 (optional): edge function invocations of this host-hour (not billed as bytes)
    functions: FunctionsUsage | None = None
    # SPEC §17.1 (optional): WAF learning observations of this host-hour, only from sites in learning
    # mode (waf_learning.WafLearn: junk keys dropped and bounded, bad counters 422). Reports for a site
    # that is not learning (or for an hour outside its window) are dropped by the controller.
    waf_learn: waf_learning.WafLearn | None = None
    # SPEC §18.1 (optional): waiting room counters of this host-hour {admitted, queued, max_wait_s,
    # peak_active}; bad counters 422 like every other usage counter
    waiting_room: wr_mod.WaitingRoomUsage | None = None
    # SPEC §18.2 (optional): access sign-in counters {ok, fail, otp} and ≤50 events
    # [{t, app, email_hash, ok}] (malformed events are dropped, never a 422)
    access: access_mod.AccessUsage | None = None
    access_events: list[access_mod.AccessEvent] = []

    @field_validator("access_events", mode="before")
    @classmethod
    def _access_events(cls, v):
        return access_mod.clean_events(v)

    @field_validator("l4", mode="before")
    @classmethod
    def _l4_ids(cls, v):
        if v is None:
            return {}
        if not isinstance(v, dict):
            raise ValueError("l4 must be an object of app id -> counters")
        out = {k: c for k, c in v.items() if isinstance(k, str) and L4_APP_ID_RE.match(k)}
        return dict(list(out.items())[:L4_MAX_APPS])

    @field_validator("video", mode="before")
    @classmethod
    def _video_int(cls, v):
        return {"bytes": v} if isinstance(v, int) and not isinstance(v, bool) else v


class LiveItem(BaseModel):
    """One 1-minute aggregate of one host (SPEC §14.3.1); top ≤20 countries / paths."""
    host: str = Field(max_length=253)
    minute: datetime
    requests: int = Field(default=0, ge=0, le=BIG)
    bytes: int = Field(default=0, ge=0, le=BIG)
    cache_hits: int = Field(default=0, ge=0, le=BIG)
    status: Counts = {}
    countries: Counts = {}
    paths: Counts = {}
    # SPEC §15.4 (wave 7, optional): tunnel requests in this minute that were attributed to a tunnel
    # path, and how many of them failed to reach the origin (origin_refused + origin_timeout). The
    # controller's origin-down detection reads them; older agents omit them (0).
    tunnel_attempts: int = Field(default=0, ge=0, le=BIG)
    tunnel_errors: int = Field(default=0, ge=0, le=BIG)


class EventIn(BaseModel):
    t: datetime
    host: str = Field(max_length=253)
    ip: str = Field("", max_length=45)
    country: str = Field("", max_length=2)
    method: str = Field("", max_length=10)
    path: str = Field("", max_length=2048)
    action: str = Field("", max_length=12)
    source: str = Field("", max_length=12)
    rule: str = Field("", max_length=64)
    user_agent: str = Field("", max_length=512)


class UsageIn(BaseModel):
    items: list[UsageItem] = Field(max_length=20000)
    events: list[EventIn] = Field(default_factory=list, max_length=2000)
    # F7: idempotency key for this POST. The agent generates a stable id per persisted outbox entry
    # and resends the SAME id verbatim on any retry (timeout / lost response), so a replayed batch is
    # counted at most once. Optional and pattern-validated: pre-upgrade agents omit it and keep the
    # existing at-least-once behaviour (SHARED CONTRACT: field name `batch_id`, 32 lowercase hex).
    batch_id: str | None = Field(None, pattern=r"^[0-9a-f]{32}$")
    # SPEC §14.3.1: 1-minute aggregates per host for the live analytics; pre-6D agents omit it.
    # Same transaction and batch_id dedup as the rest of the body.
    live: list[LiveItem] = Field(default_factory=list, max_length=5000)


DETAIL_KEYS = ("status", "codes", "countries", "paths", "security")
MAX_KEYS = {"codes": 60, "countries": 250, "paths": 200}


def _merge_details(current: dict, add: dict) -> dict:
    pe = add.get("platform_errors")
    if pe:
        current["platform_errors"] = num(current.get("platform_errors")) + num(pe)
    for key in DETAIL_KEYS:
        src = _obj(add.get(key))
        if not src:
            continue
        dst = current.get(key)
        if not isinstance(dst, dict):
            dst = current[key] = {}
        for k, v in src.items():
            k = str(k)[:512]
            if k in dst or len(dst) < MAX_KEYS.get(key, 50):
                dst[k] = num(dst.get(k)) + num(v)
    vd = _obj(add.get("video"))
    if vd:
        dst = current.get("video")
        if not isinstance(dst, dict):
            dst = current["video"] = {}
        for k in ("bytes", "requests", "cache_hits"):
            dst[k] = num(dst.get(k)) + num(vd.get(k))
    fn = _obj(add.get("functions"))
    if fn:
        dst = current.get("functions")
        if not isinstance(dst, dict):
            dst = current["functions"] = {}
        for k in FUNCTION_COUNTERS:
            dst[k] = num(dst.get(k)) + num(fn.get(k))
    if _obj(add.get("l4")):
        apps = current.get("l4")
        if not isinstance(apps, dict):
            apps = current["l4"] = {}
        for app_id, c in add["l4"].items():
            if not L4_APP_ID_RE.match(str(app_id)) or not isinstance(c, dict):
                continue
            if app_id not in apps and len(apps) >= L4_MAX_APPS:
                continue
            a = apps.get(app_id)
            if not isinstance(a, dict):
                a = apps[app_id] = {}
            for k in L4_COUNTERS:
                a[k] = num(a.get(k)) + num(c.get(k))
    wr = _obj(add.get("waiting_room"))
    if wr:
        current["waiting_room"] = wr_mod.merge(current.get("waiting_room"), wr)
    if add.get("access") or add.get("access_events"):
        access_mod.merge(current, add)
    wl = _obj(add.get("waf_learn"))
    if wl:
        current["waf_learn"] = waf_learning.merge(current.get("waf_learn"), wl)
    tn = _obj(add.get("tunnel"))
    if tn:
        dst = current.get("tunnel")
        if not isinstance(dst, dict):
            dst = current["tunnel"] = {}
        for k in TUNNEL_COUNTERS:
            dst[k] = num(dst.get(k)) + num(tn.get(k))
        protos = dst.get("by_protocol")
        if not isinstance(protos, dict):
            protos = dst["by_protocol"] = {}
        for k, v in _obj(tn.get("by_protocol")).items():
            if k in TUNNEL_PROTOCOLS:
                protos[k] = num(protos.get(k)) + num(v)
        if _obj(tn.get("paths")):
            paths = dst.get("paths")
            if not isinstance(paths, dict):
                paths = dst["paths"] = {}
            merge_tunnel_paths(paths, tn["paths"])
    return current


def merge_tunnel_paths(dst: dict, add: dict) -> dict:
    """Sum per path id counters (SPEC §15.1/§15.3) into `dst`; at most TUNNEL_MAX_PATHS ids per
    hourly row (new ids beyond the cap are dropped), unknown counter / error keys are ignored."""
    for pid, src in add.items():
        pid = str(pid)
        if not TUNNEL_PATH_ID_RE.match(pid) or not isinstance(src, dict):
            continue
        if pid not in dst and len(dst) >= TUNNEL_MAX_PATHS:
            continue
        p = dst.get(pid)
        if not isinstance(p, dict):
            p = dst[pid] = {}
        for k in TUNNEL_PATH_COUNTERS:
            p[k] = num(p.get(k)) + num(src.get(k))
        errs = p.get("errors")
        if not isinstance(errs, dict):
            errs = p["errors"] = {}
        for k in TUNNEL_ERROR_KEYS:
            errs[k] = num(errs.get(k)) + num(_obj(src.get("errors")).get(k))
        # SPEC §22.12: only reports that classify ends create the key (has_data of the drops report)
        if isinstance(src.get("ends"), dict):
            ends = p.get("ends")
            if not isinstance(ends, dict):
                ends = p["ends"] = {}
            for k in TUNNEL_END_KEYS:
                ends[k] = num(ends.get(k)) + num(src["ends"].get(k))
    return dst


def _site_for_host(host: str, domains: dict[str, int]) -> int | None:
    host = host.lower().rstrip(".").split(":")[0]
    parts = host.split(".")
    for i in range(len(parts) - 1):
        sid = domains.get(".".join(parts[i:]))
        if sid:
            return sid
    return None


@router.post("/usage")
def usage(body: UsageIn, edge: Edge = Depends(require_edge), db: Session = Depends(get_db)):
    # F7: dedup on batch_id. The insert shares this transaction with the UsageHourly upserts and the
    # SecurityEvent inserts below, so a crash between them cannot mark a batch consumed without
    # applying it, and a concurrent duplicate blocks on the primary key then fails. A replay of an
    # already-applied batch hits the PK and is skipped (counted once). Missing batch_id -> no dedup.
    if body.batch_id is not None:
        db.add(UsageBatch(edge_id=edge.id, batch_id=body.batch_id))
        try:
            db.flush()
        except IntegrityError:
            db.rollback()
            return {"ok": True, "duplicate": True, "accepted": 0, "events": 0}
    domains, foreign = _own_group_sites(db, edge)
    now = utcnow()
    newest = now.replace(minute=0, second=0, microsecond=0) + timedelta(hours=1)
    oldest = now - timedelta(days=settings.usage_max_age_days)
    dropped = {"foreign_group": 0, "out_of_window": 0, "implausible": 0}
    agg: dict[tuple[int, datetime], dict] = {}
    # security events per site in this batch (attack.detected webhook, SPEC §14.3.3)
    security: dict[int, dict[str, int]] = {}
    learning: dict[int, dict] = {}  # site id -> waf.learning (only looked up for items with waf_learn)
    for it in body.items:
        sid = _site_for_host(it.host, domains)
        if sid is None:
            continue
        if sid in foreign:  # M1: an edge reports only for the sites of its own group
            dropped["foreign_group"] += 1
            continue
        hour = _naive(it.hour).replace(minute=0, second=0, microsecond=0)
        if hour > newest or hour < oldest:  # M1: no future hours, nothing older than the window
            dropped["out_of_window"] += 1
            continue
        a = agg.setdefault((sid, hour), {"b": 0, "r": 0, "h": 0, "d": {}})
        # tunnels are charged in both directions: `bytes` is what the edge sent to the client
        a["b"] += it.bytes + (it.tunnel.bytes_up if it.tunnel else 0)
        # SPEC §16.4: TCP/UDP proxy traffic is billed in both directions, like tunnels
        a["b"] += sum(u.bytes_in + u.bytes_out for u in it.l4.values())
        a["r"] += it.requests
        a["h"] += it.cache_hits
        item = it.model_dump()
        if item.get("waf_learn") is not None:
            if sid not in learning:
                site = db.get(Site, sid)
                learning[sid] = sections.get_section(site, "waf")["learning"] if site is not None else {}
            if not waf_learning.accepts(learning[sid], hour):
                item["waf_learn"] = None  # SPEC §17.1: only sites in learning, inside the window
        _merge_details(a["d"], item)
        for k, v in it.security.items():
            if v > 0:
                src = security.setdefault(sid, {})
                src[k] = src.get(k, 0) + v
    agg, dropped["implausible"] = _plausible(db, edge, agg)
    for (sid, hour), a in agg.items():
        row = db.scalar(select(UsageHourly).where(
            UsageHourly.site_id == sid, UsageHourly.edge_id == edge.id, UsageHourly.hour == hour))
        if row is None:
            db.add(UsageHourly(site_id=sid, edge_id=edge.id, hour=hour, bytes=a["b"], requests=a["r"],
                               cache_hits=a["h"], details=json.dumps(a["d"])))
        else:
            row.bytes += a["b"]
            row.requests += a["r"]
            row.cache_hits += a["h"]
            try:
                current = json.loads(row.details or "{}")
            except ValueError:
                current = {}
            row.details = json.dumps(_merge_details(current, a["d"]))
    accepted_events = 0
    event_counts: dict[int, int] = {}
    for ev in body.events:
        sid = _site_for_host(ev.host, domains)
        if sid is None or sid in foreign:
            continue
        db.add(SecurityEvent(site_id=sid, edge_id=edge.id, ts=_naive(ev.t), ip=ev.ip, country=ev.country.upper(),
                             method=ev.method, host=ev.host.lower(), path=ev.path, action=ev.action,
                             source=ev.source, rule=ev.rule, user_agent=ev.user_agent))
        event_counts[sid] = event_counts.get(sid, 0) + 1
        accepted_events += 1
    # live analytics (SPEC §14.3.1): minute buckets, same transaction + batch_id dedup as above
    live_buckets = 0
    if body.live:
        live_buckets = live.ingest(db, [{**it.model_dump(), "minute": _naive(it.minute)} for it in body.live],
                                   lambda h: _own(_site_for_host(h, domains), foreign), _merge_details)
    # attack.detected: the counters are authoritative; events (a sample) cover agents without them
    for sid in set(security) | set(event_counts):
        n = max(sum(security.get(sid, {}).values()), event_counts.get(sid, 0))
        site = db.get(Site, sid)
        if site is not None:
            webhooks.note_security(db, site, n, security.get(sid))
    edge.last_seen_at = utcnow()
    # metrics: monotonic count of usage batches ingested (SPEC §13.1); duplicates returned earlier
    row = db.get(State, "metrics:usage_batches")
    if row is None:
        db.add(State(key="metrics:usage_batches", value="1"))
    else:
        try:
            row.value = str(int(row.value or "0") + 1)
        except ValueError:
            row.value = "1"
    if sum(dropped.values()):
        row = db.get(State, "metrics:usage_dropped")
        if row is None:
            db.add(State(key="metrics:usage_dropped", value=str(sum(dropped.values()))))
        else:
            row.value = str(num(row.value) + sum(dropped.values()))
    db.commit()
    if dropped["implausible"] or dropped["out_of_window"]:
        log.warning("edge %s: dropped usage items %s", edge.name, dropped)
        alerts.raise_alert(f"usage_implausible:{edge.id}", f"گزارش مصرف غیرعادی از لبه {edge.name}",
                           f"لبه {edge.name} مصرفی گزارش کرد که از ظرفیت آن بیشتر است یا ساعتش خارج از بازه است؛ "
                           f"این موارد اعمال نشدند: {dropped}. اگر لبه به خطر افتاده باشد، توکن آن را عوض و "
                           "لبه را غیرفعال کنید.", "critical")
    return {"ok": True, "accepted": len(agg), "events": accepted_events, "live": live_buckets,
            "dropped": dropped}


def _own(sid: int | None, foreign: set[int]) -> int | None:
    return None if sid is None or sid in foreign else sid


def _own_group_sites(db: Session, edge: Edge) -> tuple[dict[str, int], set[int]]:
    """({domain: site id} of every site, {ids of sites of ANOTHER edge group}) — M1: an edge may
    report usage / events / live data only for sites of its own group (a general edge serving a
    tunnel site in DNS fail-open is not billed for it)."""
    group = dnsbuild.edge_group(edge)
    domains, foreign = {}, set()
    for sid, domain, features in db.execute(select(Site.id, Site.domain, Site.features)).all():
        domains[domain] = sid
        if dnsbuild.site_edge_group(SimpleNamespace(features=features)) != group:
            foreign.add(sid)
    return domains, foreign


def usage_ceiling(edge: Edge) -> tuple[int, int]:
    """(bytes, requests) one edge can plausibly serve in one hour (M1, see config.py)."""
    mbps = int(edge.capacity_mbps or 0)
    bits = mbps * 1_000_000 if mbps > 0 else settings.usage_max_gbps * 1_000_000_000
    return int(bits / 8 * 3600 * settings.usage_safety_factor), int(settings.usage_max_rps * 3600)


def _plausible(db: Session, edge: Edge, agg: dict) -> tuple[dict, int]:
    """Keep the (site, hour) aggregates that fit, with what this edge already reported for that
    hour, under the edge's hourly ceiling (smallest first); the rest is dropped (M1)."""
    max_b, max_r = usage_ceiling(edge)
    kept, n_dropped = {}, 0
    for hour in sorted({h for _, h in agg}):
        used_b, used_r = db.execute(select(func.coalesce(func.sum(UsageHourly.bytes), 0),
                                           func.coalesce(func.sum(UsageHourly.requests), 0))
                                    .where(UsageHourly.edge_id == edge.id, UsageHourly.hour == hour)).one()
        used_b, used_r = int(used_b or 0), int(used_r or 0)
        for key, a in sorted(((k, v) for k, v in agg.items() if k[1] == hour), key=lambda kv: (kv[1]["b"], kv[0])):
            if used_b + a["b"] > max_b or used_r + a["r"] > max_r:
                n_dropped += 1
                continue
            used_b += a["b"]
            used_r += a["r"]
            kept[key] = a
    return kept, n_dropped


# ------------------------------------------------------------------ log export (SPEC §14.3.2)

class LogShipIn(BaseModel):
    """`{batch_id, records}`: ≤5000 sampled access-log records of sites with logs.enabled. Records
    are validated one by one (a malformed record is skipped, never the whole batch)."""
    batch_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    records: list[Any] = Field(default_factory=list, max_length=logexport.MAX_RECORDS_PER_POST)


def _logship_key(batch_id: str) -> str:
    """Dedup key in usage_batches, namespaced so a logship id can never collide with a usage id."""
    return hashlib.sha256(b"logship:" + batch_id.encode()).hexdigest()[:32]


@router.post("/logship")
def logship(body: LogShipIn, edge: Edge = Depends(require_edge), db: Session = Depends(get_db)):
    db.add(UsageBatch(edge_id=edge.id, batch_id=_logship_key(body.batch_id)))
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        return {"ok": True, "duplicate": True, "accepted": 0, "dropped": 0, "ignored": 0, "invalid": 0}
    domains = {d: i for i, d in db.execute(select(Site.id, Site.domain)).all()}
    out = logexport.ingest(db, body.records, lambda h: _site_for_host(h, domains))
    db.commit()
    return {"ok": True, **out}


def _naive(dt: datetime) -> datetime:
    """Store UTC without tzinfo, like the rest of the schema."""
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


# ------------------------------------------------------------------ access one-time codes (SPEC §18.2)

class AccessOtpIn(BaseModel):
    """POST /edge/v1/access/otp from the edge's internal location; unknown keys are ignored."""
    domain: str = Field(min_length=1, max_length=253)
    app: str = Field(min_length=1, max_length=32)
    email: str = Field(min_length=3, max_length=254)


def _serves(db: Session, edge: Edge, site: Site) -> bool:
    """The edge answers for the site: same edge group, or (DNS fail-open) the site's group has no
    online edge at all."""
    from .services import online_edges

    group = dnsbuild.site_edge_group(site)
    if dnsbuild.edge_group(edge) == group:
        return True
    return not any(dnsbuild.edge_group(e) == group for e in online_edges(db))


@router.post("/access/otp")
def access_otp(body: AccessOtpIn, request: Request, edge: Edge = Depends(require_edge),
               db: Session = Depends(get_db)):
    """Generate the visitor's one-time code (access.otp_code) and e-mail it. The code never appears
    in a response, a log line or the audit log (only a hash of the address does).

    200 {"ok": true, "expires_in": s} | 403 not served by this edge / site not active / access off /
    app without e-mail codes / address not allowed | 404 unknown site or app | 422 bad body or address
    | 429 rate limited (Retry-After) | 503 no SMTP / no usable secret / delivery failed."""
    from fastapi import HTTPException

    from .audit import record_audit
    from .validation import ValidationError, normalize_domain

    try:
        domain = normalize_domain(body.domain)
    except ValidationError:
        raise HTTPException(422, "invalid domain") from None
    email = body.email.strip().lower()
    if not sections.EMAIL_RE.match(email):
        raise HTTPException(422, "invalid email")
    site = db.scalar(select(Site).where(Site.domain == domain))
    if site is None:
        raise HTTPException(404, "site not found")
    if not _serves(db, edge, site):
        raise HTTPException(403, "site not served by this edge")
    if site.effective_status != "active":
        raise HTTPException(403, "site not active")
    value = sections.get_section(site, "access")
    if not (value["enabled"] and sections.features_of(site).get("access")):
        raise HTTPException(403, "access not enabled")
    app = next((a for a in value["apps"] if a["id"] == body.app), None)
    if app is None:
        raise HTTPException(404, "app not found")
    if app["methods"] == "ip":
        raise HTTPException(403, "app does not use e-mail codes")
    if not access_mod.email_allowed(app, email):
        raise HTTPException(403, "email not allowed")
    secret = access_mod.secret_of(site)
    if not secret:
        raise HTTPException(503, "access secret unavailable")
    if not alerts.mail_configured():
        raise HTTPException(503, "mail not configured")
    ref = access_mod.email_ref(email)
    now = utcnow()
    try:
        access_mod.check_rate(db, site, ref, now)
    except access_mod.RateLimited as e:
        raise HTTPException(429, f"rate limited ({e.scope})", headers={"Retry-After": str(e.retry_after)}) from None
    access_mod.note_sent(db, site, ref, now)  # counted even when delivery fails (no retry loops)
    edge.last_seen_at = now
    db.commit()
    unix = now.replace(tzinfo=timezone.utc).timestamp()
    window = access_mod.otp_window(unix)
    subject, text = access_mod.mail_text(site.domain, app["name"],
                                         access_mod.otp_code(secret, app["id"], email, window))
    try:
        alerts.send_mail(email, subject, text, sender=settings.access_mail_from)
    except alerts.AlertError as e:
        log.warning("access code e-mail for %s (app %s) failed: %s", site.domain, app["id"], e)
        raise HTTPException(503, "mail delivery failed") from None
    record_audit(db, actor=edge.name, actor_kind="edge", action="access.otp_sent", target=site.domain,
                 detail={"app": app["id"], "email_ref": ref},
                 ip=request.client.host if request.client else None)
    # valid in this window and the next one: always MORE than one window. Rounded up to whole seconds
    # (truncating answered exactly WINDOW_SECONDS during the last second of a window)
    expires_in = math.ceil((window + 2) * access_mod.WINDOW_SECONDS - unix)
    return {"ok": True, "expires_in": expires_in}
