import json
import secrets
from datetime import datetime, timezone

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
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

    site: Mapped[Site] = relationship(back_populates="records")


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


class State(Base):
    """Small key/value table for scheduler state."""

    __tablename__ = "state"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[str] = mapped_column(Text, default="")
