import json
import secrets
from datetime import datetime, timezone

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from . import crypto
from .db import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


class Site(Base):
    __tablename__ = "sites"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    domain: Mapped[str] = mapped_column(String(253), unique=True, index=True)
    external_id: Mapped[str | None] = mapped_column(String(64), nullable=True)  # WHMCS service id
    # pending_ns -> active ; suspended is set by billing
    status: Mapped[str] = mapped_column(String(20), default="pending_ns")
    suspended: Mapped[bool] = mapped_column(Boolean, default=False)
    over_quota: Mapped[bool] = mapped_column(Boolean, default=False)
    ns_verified_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    ns_checked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    ns_found: Mapped[str] = mapped_column(Text, default="[]")

    # plan (set by WHMCS)
    bandwidth_limit_gb: Mapped[int] = mapped_column(Integer, default=0)  # 0 = unlimited
    max_records: Mapped[int] = mapped_column(Integer, default=100)
    ssl_allowed: Mapped[bool] = mapped_column(Boolean, default=True)
    rate_limit_rps: Mapped[int] = mapped_column(Integer, default=0)  # per client IP, 0 = off

    features: Mapped[str] = mapped_column(Text, default="{}")  # plan feature flags, see sections.DEFAULT_FEATURES

    # reseller tag: a sub-site owned by a reseller's WHMCS client (set by WHMCS), see SPEC §10.5
    reseller_client_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True, default=None)
    reseller_label: Mapped[str | None] = mapped_column(String(120), nullable=True, default=None)

    # customer settings: JSON document of sections (see sections.SECTIONS / SPEC §2)
    config: Mapped[str] = mapped_column(Text, default="{}")
    blocked_ips: Mapped[str] = mapped_column(Text, default="[]")
    # HMAC key the edges use for challenge clearance cookies. Stored encrypted when
    # DATA_ENCRYPTION_KEY is set (see crypto.py); use the `secret` property.
    secret_stored: Mapped[str] = mapped_column("secret", Text, default=lambda: crypto.encrypt(secrets.token_hex(32)))
    dnssec_enabled: Mapped[bool] = mapped_column(Boolean, default=False)

    # ssl
    ssl_status: Mapped[str] = mapped_column(String(10), default="none")  # none|pending|active|failed
    ssl_cert: Mapped[str | None] = mapped_column(Text, nullable=True)
    # PEM private key, encrypted at rest when DATA_ENCRYPTION_KEY is set; use the `ssl_key` property
    ssl_key_stored: Mapped[str | None] = mapped_column("ssl_key", Text, nullable=True)
    ssl_expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    ssl_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    ssl_source: Mapped[str | None] = mapped_column(String(12), nullable=True)  # letsencrypt | custom

    # authenticated origin pulls, custom mode (SPEC §14.2): the customer's client certificate (PEM,
    # chain allowed) the edges present to the origin, and its private key — encrypted at rest like
    # ssl_key; use the `origin_client_key` property
    origin_client_cert: Mapped[str | None] = mapped_column(Text, nullable=True)
    origin_client_key_stored: Mapped[str | None] = mapped_column("origin_client_key", Text, nullable=True)
    origin_client_expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    # write-only integration secrets (SPEC §14.3): JSON {"logs": <log export S3 secret key>,
    # "webhooks": {"wh_…": <signing secret>}}; every value is encrypted at rest like ssl_key (see
    # site_secrets.py / crypto.SITE_JSON_SECRETS) and is never returned by any GET, edge config or audit
    integration_secrets: Mapped[str | None] = mapped_column(Text, nullable=True)
    # when the quota.warning webhook (80 % of bandwidth_limit_gb) was last emitted; once per month
    quota_warned_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)

    records: Mapped[list["Record"]] = relationship(
        back_populates="site", cascade="all, delete-orphan", order_by="Record.id"
    )

    @property
    def ssl_key(self) -> str | None:
        return crypto.decrypt(self.ssl_key_stored)

    @ssl_key.setter
    def ssl_key(self, value: str | None):
        self.ssl_key_stored = crypto.encrypt(value)

    @property
    def origin_client_key(self) -> str | None:
        return crypto.decrypt(self.origin_client_key_stored)

    @origin_client_key.setter
    def origin_client_key(self, value: str | None):
        self.origin_client_key_stored = crypto.encrypt(value)

    @property
    def secret(self) -> str:
        return crypto.decrypt(self.secret_stored)

    @secret.setter
    def secret(self, value: str):
        self.secret_stored = crypto.encrypt(value)

    @property
    def blocked_ip_list(self) -> list[str]:
        try:
            return list(json.loads(self.blocked_ips or "[]"))
        except ValueError:
            return []

    @property
    def effective_status(self) -> str:
        if self.suspended:
            return "suspended"
        if self.over_quota:
            return "over_quota"
        return self.status


class Record(Base):
    __tablename__ = "records"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    site_id: Mapped[int] = mapped_column(ForeignKey("sites.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(253))  # relative: "@", "www", "*"
    type: Mapped[str] = mapped_column(String(10))
    content: Mapped[str] = mapped_column(Text)
    ttl: Mapped[int] = mapped_column(Integer, default=300)
    priority: Mapped[int | None] = mapped_column(Integer, nullable=True)
    proxied: Mapped[bool] = mapped_column(Boolean, default=False)
    pool: Mapped[str | None] = mapped_column(String(32), nullable=True)
    origin_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    health_check: Mapped[bool] = mapped_column(Boolean, default=False)
    health_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # wave 8 (SPEC §16.7): weighted / failover sets of non-proxied A/AAAA/CNAME records. weight 0..100
    # (NULL = not weighted; 0 = standby, answered only while no member with weight > 0 is healthy).
    # health_protocol tcp | http | https (NULL = tcp) and health_path (http/https) of the controller's
    # 60 s probe; health_ok / health_fail / health_at / health_ms / health_error are its last result
    # and consecutive-failure counter (withdrawn after PROBE_FAIL_CHECKS failures, never all members)
    weight: Mapped[int | None] = mapped_column(Integer, nullable=True)
    health_protocol: Mapped[str | None] = mapped_column(String(8), nullable=True)
    health_path: Mapped[str | None] = mapped_column(String(512), nullable=True)
    health_ok: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    health_fail: Mapped[int] = mapped_column(Integer, default=0)
    health_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    health_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    health_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    # SPEC §16.8 origin shortcut: a proxied record served from one of the site's storage buckets
    # (StorageBucket.name, the customer's short name). The edge gets the storage endpoint, the
    # bucket path and the bucket's read token instead of an address (storage.edge_origin).
    storage_bucket: Mapped[str | None] = mapped_column(String(63), nullable=True)

    site: Mapped[Site] = relationship(back_populates="records")


class L4Port(Base):
    """An edge port allocated to one TCP/UDP proxy app (SPEC §16.4). Unique per edge group across
    every site (the nginx `stream` listeners of one group share the nodes' ports); the row of an app
    is replaced on every write of the site's `l4` section and removed with the app / the site."""

    __tablename__ = "l4_ports"
    __table_args__ = (UniqueConstraint("group", "port", name="uq_l4_ports_group_port"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    group: Mapped[str] = mapped_column(String(16))  # edge group: general | tunnel
    port: Mapped[int] = mapped_column(Integer)
    site_id: Mapped[int] = mapped_column(ForeignKey("sites.id", ondelete="CASCADE"), index=True)
    app_id: Mapped[str] = mapped_column(String(32))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Edge(Base):
    __tablename__ = "edges"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(64), unique=True)
    ipv4: Mapped[str] = mapped_column(String(45))
    ipv6: Mapped[str | None] = mapped_column(String(45), nullable=True)
    region: Mapped[str] = mapped_column(String(16), default="global")  # "home" (e.g. Iran) | "global"
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    applied_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    # tunnel mode (SPEC §7.4): DNS answers a site with the edges of its plan's edge_group
    group: Mapped[str] = mapped_column(String(16), default="general")  # "general" | "tunnel"
    capacity_mbps: Mapped[int] = mapped_column(Integer, default=0)  # 0 = unknown, never shed
    # latest heartbeat metrics (JSON: rx_mbps, tx_mbps, connections, load1, cpus)
    metrics: Mapped[str | None] = mapped_column(Text, nullable=True)
    metrics_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    # load shedding: left out of DNS while saturated (hysteresis, see services.update_shed)
    shed: Mapped[bool] = mapped_column(Boolean, default=False)
    # consecutive metric reports above services.LOAD_ALERT_PERCENT (edge_saturated alert)
    load_high: Mapped[int] = mapped_column(Integer, default=0)
    # consecutive metric reports with load1/cpus above EDGE_CPU_ALERT (edge_cpu alert)
    cpu_high: Mapped[int] = mapped_column(Integer, default=0)
    # synthetic health probe (SPEC §8.1, job_probe): the controller itself fetches
    # http://<ipv4>/__pcdn/health with Host: health.pcdn every ~60s to catch a node that
    # still heartbeats but serves errors. probe_fail is the consecutive failure counter.
    probe_ok: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    probe_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    probe_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    probe_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    probe_fail: Mapped[int] = mapped_column(Integer, default=0)
    # per-family primary probe state (SPEC §12, F32): the primary IPv4 and IPv6 address of a node
    # are probed and withdrawn independently, so a dead family is pulled from DNS while the healthy
    # family stays advertised. probe_ok*/probe_fail* mirror probe_ok/probe_fail but per family; the
    # aggregate probe_ok/probe_fail above is kept only for the §8.1 edge_probe alert. NULL = never
    # probed yet (advertised, fail-open) — the migration backfills NULL for the same reason.
    probe_ok4: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    probe_fail4: Mapped[int] = mapped_column(Integer, default=0)
    probe_ok6: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    probe_fail6: Mapped[int] = mapped_column(Integer, default=0)
    # consecutive metric reports at/above EDGE_SHED_PERCENT (F25 shed hysteresis) and the time the
    # edge was last put into the shed state, so a shed is held for at least EDGE_SHED_HOLD seconds
    shed_high: Mapped[int] = mapped_column(Integer, default=0)
    shed_since: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    # centralized node logs (SPEC §11.2): a capped rolling buffer of recent WARN/ERROR/crit
    # lines the agent ships (nginx error log + the agent's own log). JSON list, newest last,
    # hard-capped (~120 lines / ~16 KiB, oldest dropped). NEVER access logs, IPs, tokens or keys.
    logs: Mapped[str | None] = mapped_column(Text, nullable=True)
    logs_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    # running edge bundle version the agent reports (SPEC §11.1); compared to the controller's
    # current bundle (GET /edge/version) to flag nodes that are behind ("update available")
    bundle_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # origin shield / tiered cache (SPEC §14.1): admin-set; non-shield edges of the same group send
    # cache misses of sites with cache.shield to the online shield edges (services.shield_peers)
    shield: Mapped[bool] = mapped_column(Boolean, default=False)
    # node capabilities from the latest heartbeat (SPEC §14.1), JSON
    # {"http3": bool, "early_hints": bool, "webp_convert": bool, "modules": [str]}; NULL = never reported
    capabilities: Mapped[str | None] = mapped_column(Text, nullable=True)

    # additional addresses of the same node for health-based failover (SPEC §12); ipv4/ipv6
    # above stay the primary address
    addresses: Mapped[list["EdgeAddress"]] = relationship(
        back_populates="edge", cascade="all, delete-orphan", order_by="EdgeAddress.id"
    )


class EdgeAddress(Base):
    """An additional address of an edge node (SPEC §12). The edge's own ipv4/ipv6 remain its
    primary (identity) address; these are extra addresses of the SAME node between which DNS
    fails over based ONLY on the synthetic health probe (§8.1). Each address carries its own
    probe health and can be enabled/disabled by the operator for maintenance."""

    __tablename__ = "edge_addresses"
    # the same address can't be registered twice for a family (backstop; the endpoint also
    # rejects duplicates of any edge's primary or additional address)
    __table_args__ = (UniqueConstraint("family", "ip", name="uq_edge_addresses_family_ip"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    edge_id: Mapped[int] = mapped_column(ForeignKey("edges.id", ondelete="CASCADE"), index=True)
    family: Mapped[int] = mapped_column(Integer)  # 4 | 6
    ip: Mapped[str] = mapped_column(String(45))
    label: Mapped[str] = mapped_column(String(64), default="")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    # per-address synthetic probe (SPEC §12.2); probe_fail is the consecutive-failure counter
    probe_ok: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    probe_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    probe_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    probe_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    probe_fail: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    edge: Mapped["Edge"] = relationship(back_populates="addresses")


class EdgeUptime(Base):
    """Per-edge, per-hour availability rollup: how many scheduler samples found the edge
    online (last_seen within EDGE_OFFLINE_SECONDS) out of the total taken that hour."""

    __tablename__ = "edge_uptime"
    __table_args__ = (UniqueConstraint("edge_id", "hour"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    edge_id: Mapped[int] = mapped_column(ForeignKey("edges.id", ondelete="CASCADE"), index=True)
    hour: Mapped[datetime] = mapped_column(DateTime, index=True)
    samples_total: Mapped[int] = mapped_column(Integer, default=0)
    samples_online: Mapped[int] = mapped_column(Integer, default=0)


class Purge(Base):
    __tablename__ = "purges"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    site_id: Mapped[int] = mapped_column(ForeignKey("sites.id", ondelete="CASCADE"), index=True)
    urls: Mapped[str] = mapped_column(Text, default="[]")  # empty list = purge everything
    prefixes: Mapped[str] = mapped_column(Text, default="[]")  # path prefixes, optional scheme+host
    everything: Mapped[bool] = mapped_column(Boolean, default=False)  # explicit whole-cache purge
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class UsageHourly(Base):
    __tablename__ = "usage_hourly"
    __table_args__ = (UniqueConstraint("site_id", "edge_id", "hour"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    site_id: Mapped[int] = mapped_column(ForeignKey("sites.id", ondelete="CASCADE"), index=True)
    edge_id: Mapped[int] = mapped_column(ForeignKey("edges.id", ondelete="CASCADE"))
    hour: Mapped[datetime] = mapped_column(DateTime, index=True)
    bytes: Mapped[int] = mapped_column(BigInteger, default=0)
    requests: Mapped[int] = mapped_column(BigInteger, default=0)
    cache_hits: Mapped[int] = mapped_column(BigInteger, default=0)
    # {"status": {...}, "codes": {...}, "countries": {...}, "paths": {...}, "security": {...},
    #  "tunnel": {"sessions", "seconds", "bytes_up", "bytes_down", "by_protocol": {...}}}
    details: Mapped[str] = mapped_column(Text, default="{}")


class SecurityEvent(Base):
    __tablename__ = "security_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    site_id: Mapped[int] = mapped_column(ForeignKey("sites.id", ondelete="CASCADE"), index=True)
    edge_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    ts: Mapped[datetime] = mapped_column(DateTime, index=True)
    ip: Mapped[str] = mapped_column(String(45), default="")
    country: Mapped[str] = mapped_column(String(2), default="")
    method: Mapped[str] = mapped_column(String(10), default="")
    host: Mapped[str] = mapped_column(String(253), default="")
    path: Mapped[str] = mapped_column(Text, default="")
    action: Mapped[str] = mapped_column(String(12), default="")
    source: Mapped[str] = mapped_column(String(12), default="")
    rule: Mapped[str] = mapped_column(String(64), default="")
    user_agent: Mapped[str] = mapped_column(Text, default="")


class Incident(Base):
    """Operator-written incident shown on the public status page (SPEC §8.3)."""

    __tablename__ = "incidents"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(200))
    body: Mapped[str] = mapped_column(Text, default="")
    # minor | major | maintenance
    severity: Mapped[str] = mapped_column(String(16), default="minor")
    # investigating | identified | monitoring | resolved | scheduled
    status: Mapped[str] = mapped_column(String(16), default="investigating")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)

    updates: Mapped[list["IncidentUpdate"]] = relationship(
        back_populates="incident", cascade="all, delete-orphan", order_by="IncidentUpdate.id"
    )


class IncidentUpdate(Base):
    __tablename__ = "incident_updates"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"), index=True)
    status: Mapped[str] = mapped_column(String(16), default="investigating")
    body: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    incident: Mapped[Incident] = relationship(back_populates="updates")


class ApiKey(Base):
    """Per-site customer API key (SPEC §10.1). The plaintext key ("pcdn_" + 40 hex) is shown
    once at creation and never stored; only its SHA-256 hash is kept (like edge tokens)."""

    __tablename__ = "api_keys"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    site_id: Mapped[int] = mapped_column(ForeignKey("sites.id", ondelete="CASCADE"), index=True)
    key_hash: Mapped[str] = mapped_column(String(64), unique=True)
    name: Mapped[str] = mapped_column(String(64), default="")
    scopes: Mapped[str] = mapped_column(Text, default="[]")  # JSON list, subset of {purge, stats, dns}
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)

    site: Mapped[Site] = relationship()

    @property
    def scope_list(self) -> list[str]:
        try:
            return list(json.loads(self.scopes or "[]"))
        except ValueError:
            return []


class UsageBatch(Base):
    """Idempotency key for a usage POST (F7). The agent sends a stable ``batch_id`` per persisted
    outbox entry and resends the SAME id verbatim on any retry (timeout / lost response). The first
    successful apply inserts (edge_id, batch_id) in the same transaction as the UsageHourly upserts;
    a replay hits the primary key and is skipped, so a timed-out POST is counted at most once. Rows
    are pruned after a week (job_cleanup). Missing batch_id keeps the old at-least-once behaviour."""

    __tablename__ = "usage_batches"

    edge_id: Mapped[int] = mapped_column(ForeignKey("edges.id", ondelete="CASCADE"), primary_key=True)
    batch_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    received_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)


class State(Base):
    """Small key/value table for scheduler state."""

    __tablename__ = "state"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[str] = mapped_column(Text, default="")


class AuditLog(Base):
    """Append-only record of platform mutations (SPEC §13.2). Writes only — reads are never
    audited. `detail` is a small JSON document from which secrets, tokens and private keys are
    always stripped (see audit.record_audit). Old rows are pruned by the scheduler after
    AUDIT_RETENTION_DAYS."""

    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    # admin-key label / customer-key id-or-name / "system"
    actor: Mapped[str] = mapped_column(String(120), default="")
    actor_kind: Mapped[str] = mapped_column(String(16), default="admin")  # admin | capi | system
    action: Mapped[str] = mapped_column(String(64), index=True)  # e.g. site.create, edge.add, purge
    target: Mapped[str | None] = mapped_column(String(253), nullable=True)  # domain / edge name / ...
    detail: Mapped[str] = mapped_column(Text, default="{}")  # JSON, secret-free
    ip: Mapped[str | None] = mapped_column(String(45), nullable=True)


class AnalyticsMinute(Base):
    """Near-real-time per-site minute buckets (SPEC §14.3.1), summed over every edge's `live`
    aggregates. Kept for 24 h (job_cleanup). `details` = {"status", "countries", "paths"} capped
    like UsageHourly.details."""

    __tablename__ = "analytics_minute"

    site_id: Mapped[int] = mapped_column(ForeignKey("sites.id", ondelete="CASCADE"), primary_key=True)
    minute: Mapped[datetime] = mapped_column(DateTime, primary_key=True, index=True)
    requests: Mapped[int] = mapped_column(BigInteger, default=0)
    bytes: Mapped[int] = mapped_column(BigInteger, default=0)
    cache_hits: Mapped[int] = mapped_column(BigInteger, default=0)
    details: Mapped[str] = mapped_column(Text, default="{}")


class LogSpool(Base):
    """One gzip JSON-lines chunk of a site's access-log records for one hour (SPEC §14.3.2): one
    row per /edge/v1/logship POST per site/hour. The leader uploads every completed hour as one
    object (the chunks concatenated: gzip members form a valid gzip stream) and deletes the rows;
    failed uploads keep them, chunks older than 72 h are dropped (counted)."""

    __tablename__ = "log_spool"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    site_id: Mapped[int] = mapped_column(ForeignKey("sites.id", ondelete="CASCADE"), index=True)
    hour: Mapped[datetime] = mapped_column(DateTime, index=True)  # UTC hour the records belong to
    records: Mapped[int] = mapped_column(Integer, default=0)
    data: Mapped[bytes] = mapped_column(LargeBinary)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)


class WebhookDelivery(Base):
    """One webhook event for one hook (SPEC §14.3.3). `payload` holds the exact JSON body that is
    sent (and signed) on every attempt. pending rows are picked up by the leader's webhook job when
    next_attempt_at is due; rows are kept 7 days."""

    __tablename__ = "webhook_delivery"
    __table_args__ = (Index("ix_webhook_delivery_due", "status", "next_attempt_at"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    delivery_id: Mapped[str] = mapped_column(String(24), unique=True)  # "dlv_" + 16 hex (X-Pcdn-Delivery)
    site_id: Mapped[int] = mapped_column(ForeignKey("sites.id", ondelete="CASCADE"), index=True)
    hook_id: Mapped[str] = mapped_column(String(16))
    event: Mapped[str] = mapped_column(String(32))
    event_id: Mapped[str] = mapped_column(String(24))  # "evt_" + 16 hex, the body's `id`
    payload: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(10), default="pending")  # pending | ok | failed
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    last_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    delivered_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    next_attempt_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class SiteEvent(Base):
    """A customer-facing site event the WHMCS cron polls (SPEC §15.4): `GET /api/v1/events?type=tunnel`
    lists the tunnel origin transitions (`tunnel.origin_down` / `tunnel.origin_up`) so WHMCS can
    e-mail the service owner, deduped by the stable `event_id` (the same id the webhook body carries).
    Rows are pruned after SITE_EVENTS_RETENTION_DAYS (job_cleanup)."""

    __tablename__ = "site_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    event_id: Mapped[str] = mapped_column(String(24), unique=True)  # "evt_" + 16 hex
    site_id: Mapped[int] = mapped_column(ForeignKey("sites.id", ondelete="CASCADE"), index=True)
    type: Mapped[str] = mapped_column(String(32), index=True)  # e.g. tunnel.origin_down
    data: Mapped[str] = mapped_column(Text, default="{}")  # JSON
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)


class StorageBucket(Base):
    """A customer bucket on the platform's MinIO (SPEC §16.8). `bucket` is the global name on MinIO
    (STORAGE_BUCKET_PREFIX + a random per-site tag + "-" + `name`). `access_key` is the MinIO service
    account (owned by the controller's storage user, inline policy scoped to this bucket only); its
    secret is shown once and stored encrypted (`secret_key`). `origin_token` is the value the edges
    send as Referer: the bucket policy allows anonymous s3:GetObject only with it, so the bucket is
    a CDN origin without being public. size/objects are the last MinIO scanner reading."""

    __tablename__ = "storage_buckets"
    __table_args__ = (UniqueConstraint("site_id", "name", name="uq_storage_buckets_site_name"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    site_id: Mapped[int] = mapped_column(ForeignKey("sites.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(63))
    bucket: Mapped[str] = mapped_column(String(63), unique=True)
    access_key: Mapped[str] = mapped_column(String(32))
    secret_key_stored: Mapped[str] = mapped_column("secret_key", Text)
    origin_token_stored: Mapped[str] = mapped_column("origin_token", Text)
    quota_bytes: Mapped[int] = mapped_column(BigInteger, default=0)
    size_bytes: Mapped[int] = mapped_column(BigInteger, default=0)
    objects: Mapped[int] = mapped_column(BigInteger, default=0)
    usage_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    rotated_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    @property
    def secret_key(self) -> str | None:
        return crypto.decrypt(self.secret_key_stored)

    @secret_key.setter
    def secret_key(self, value: str):
        self.secret_key_stored = crypto.encrypt(value)

    @property
    def origin_token(self) -> str | None:
        return crypto.decrypt(self.origin_token_stored)

    @origin_token.setter
    def origin_token(self, value: str):
        self.origin_token_stored = crypto.encrypt(value)


class StorageUsageHourly(Base):
    """Hourly sample of one bucket's stored bytes (SPEC §16.8 billing): bytes x 1 h = byte-hours, so
    the sum of a month's rows / 1024^3 is the GB-hours WHMCS invoices. Keyed by the bucket's global
    name (not its row) so the usage of a deleted bucket stays billable; pruned with the site."""

    __tablename__ = "storage_usage_hourly"
    __table_args__ = (UniqueConstraint("bucket", "hour", name="uq_storage_usage_bucket_hour"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    site_id: Mapped[int] = mapped_column(ForeignKey("sites.id", ondelete="CASCADE"), index=True)
    bucket: Mapped[str] = mapped_column(String(63))
    hour: Mapped[datetime] = mapped_column(DateTime, index=True)
    bytes: Mapped[int] = mapped_column(BigInteger, default=0)
    objects: Mapped[int] = mapped_column(BigInteger, default=0)
