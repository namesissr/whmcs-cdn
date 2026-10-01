"""API polled by edge agents."""

import hashlib
import ipaddress
import json
import logging
import re
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, Header, Request, Response
from pydantic import BaseModel, Field, field_validator
from pydantic import ValidationError as PydanticValidationError
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from . import live, logexport, webhooks
from .auth import require_edge
from .db import get_db
from .models import Edge, Purge, SecurityEvent, Site, State, UsageBatch, UsageHourly, utcnow
from .services import EDGE_IP_PLACEHOLDER, build_edge_config, record_metrics

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
    if body.bundle_version is not None:
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
    db.commit()
    return {"ok": True}


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
                        "connect_n")


class TunnelPathErrors(BaseModel):
    """Request counts per error class (SPEC §15.1); unknown keys are ignored (dropped)."""
    origin_refused: int = Field(0, ge=0, le=BIG)
    origin_timeout: int = Field(0, ge=0, le=BIG)
    origin_error: int = Field(0, ge=0, le=BIG)
    limit: int = Field(0, ge=0, le=BIG)
    country: int = Field(0, ge=0, le=BIG)
    protocol: int = Field(0, ge=0, le=BIG)
    edge: int = Field(0, ge=0, le=BIG)


class TunnelPathUsage(BaseModel):
    """One path id of one host-hour (SPEC §15.1); unknown keys are ignored (dropped)."""
    sessions: int = Field(0, ge=0, le=BIG)
    seconds: float = Field(0, ge=0, le=BIG)
    bytes_up: int = Field(0, ge=0, le=BIG)
    bytes_down: int = Field(0, ge=0, le=BIG)
    abnormal: int = Field(0, ge=0, le=BIG)
    connect_ms_sum: float = Field(0, ge=0, le=BIG)
    connect_n: int = Field(0, ge=0, le=BIG)
    errors: TunnelPathErrors = Field(default_factory=TunnelPathErrors)


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


class UsageItem(BaseModel):
    host: str
    hour: datetime
    bytes: int = Field(ge=0)
    requests: int = Field(ge=0)
    cache_hits: int = Field(default=0, ge=0)
    status: Counts = {}
    codes: Counts = {}
    countries: Counts = {}
    paths: Counts = {}
    security: Counts = {}
    tunnel: TunnelUsage | None = None
    # SPEC §14.3.1: responses with status >= 500 the edge produced itself (no upstream status, no
    # security action); origin errors never count. Summed into the hourly details for the SLA report.
    platform_errors: int = Field(default=0, ge=0, le=BIG)


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
        current["platform_errors"] = int(current.get("platform_errors") or 0) + max(int(pe), 0)
    for key in DETAIL_KEYS:
        src = add.get(key) or {}
        if not src:
            continue
        dst = current.setdefault(key, {})
        for k, v in src.items():
            k = str(k)[:512]
            if k in dst or len(dst) < MAX_KEYS.get(key, 50):
                dst[k] = dst.get(k, 0) + max(int(v), 0)
    tn = add.get("tunnel")
    if tn:
        dst = current.setdefault("tunnel", {})
        for k in TUNNEL_COUNTERS:
            dst[k] = int(dst.get(k, 0)) + max(int(round(tn.get(k) or 0)), 0)
        protos = dst.setdefault("by_protocol", {})
        for k, v in (tn.get("by_protocol") or {}).items():
            if k in TUNNEL_PROTOCOLS:
                protos[k] = protos.get(k, 0) + max(int(v), 0)
        if tn.get("paths"):
            merge_tunnel_paths(dst.setdefault("paths", {}), tn["paths"])
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
        p = dst.setdefault(pid, {})
        for k in TUNNEL_PATH_COUNTERS:
            p[k] = int(p.get(k) or 0) + max(int(round(src.get(k) or 0)), 0)
        errs = p.setdefault("errors", {})
        for k in TUNNEL_ERROR_KEYS:
            errs[k] = int(errs.get(k) or 0) + max(int((src.get("errors") or {}).get(k) or 0), 0)
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
    domains = {d: i for i, d in db.execute(select(Site.id, Site.domain)).all()}
    agg: dict[tuple[int, datetime], dict] = {}
    # security events per site in this batch (attack.detected webhook, SPEC §14.3.3)
    security: dict[int, dict[str, int]] = {}
    for it in body.items:
        sid = _site_for_host(it.host, domains)
        if sid is None:
            continue
        hour = _naive(it.hour).replace(minute=0, second=0, microsecond=0)
        a = agg.setdefault((sid, hour), {"b": 0, "r": 0, "h": 0, "d": {}})
        # tunnels are charged in both directions: `bytes` is what the edge sent to the client
        a["b"] += it.bytes + (it.tunnel.bytes_up if it.tunnel else 0)
        a["r"] += it.requests
        a["h"] += it.cache_hits
        _merge_details(a["d"], it.model_dump())
        for k, v in it.security.items():
            if v > 0:
                src = security.setdefault(sid, {})
                src[k] = src.get(k, 0) + v
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
        if sid is None:
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
                                   lambda h: _site_for_host(h, domains), _merge_details)
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
    db.commit()
    return {"ok": True, "accepted": len(agg), "events": accepted_events, "live": live_buckets}


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
