"""API polled by edge agents."""

import ipaddress
import json
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Header, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .auth import require_edge
from .db import get_db
from .models import Edge, Purge, SecurityEvent, Site, UsageBatch, UsageHourly, utcnow
from .services import build_edge_config, record_metrics

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
    cfg = build_edge_config(db)
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


EDGE_IP_PLACEHOLDER = "0.0.0.0"  # batch-created edges (SPEC §11.1) until the node reports itself


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


class TunnelUsage(BaseModel):
    sessions: int = Field(0, ge=0, le=BIG)
    seconds: float = Field(0, ge=0, le=BIG)
    bytes_up: int = Field(0, ge=0, le=BIG)    # received from the client (billed too, SPEC §7.3)
    bytes_down: int = Field(0, ge=0, le=BIG)  # sent to the client (already part of `bytes`)
    by_protocol: Counts = {}                  # protocol -> bytes (up + down)


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


DETAIL_KEYS = ("status", "codes", "countries", "paths", "security")
MAX_KEYS = {"codes": 60, "countries": 250, "paths": 200}


def _merge_details(current: dict, add: dict) -> dict:
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
    return current


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
    for ev in body.events:
        sid = _site_for_host(ev.host, domains)
        if sid is None:
            continue
        db.add(SecurityEvent(site_id=sid, edge_id=edge.id, ts=_naive(ev.t), ip=ev.ip, country=ev.country.upper(),
                             method=ev.method, host=ev.host.lower(), path=ev.path, action=ev.action,
                             source=ev.source, rule=ev.rule, user_agent=ev.user_agent))
        accepted_events += 1
    edge.last_seen_at = utcnow()
    db.commit()
    return {"ok": True, "accepted": len(agg), "events": accepted_events}


def _naive(dt: datetime) -> datetime:
    """Store UTC without tzinfo, like the rest of the schema."""
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt
