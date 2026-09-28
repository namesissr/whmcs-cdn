import json
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

    # customer settings
    cache_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    dev_mode: Mapped[bool] = mapped_column(Boolean, default=False)
    force_https: Mapped[bool] = mapped_column(Boolean, default=False)
    origin_protocol: Mapped[str] = mapped_column(String(5), default="http")
    edge_cache_ttl: Mapped[int] = mapped_column(Integer, default=86400)
    browser_cache_ttl: Mapped[int] = mapped_column(Integer, default=0)
    blocked_ips: Mapped[str] = mapped_column(Text, default="[]")

    # ssl
    ssl_status: Mapped[str] = mapped_column(String(10), default="none")  # none|pending|active|failed
    ssl_cert: Mapped[str | None] = mapped_column(Text, nullable=True)
    ssl_key: Mapped[str | None] = mapped_column(Text, nullable=True)
    ssl_expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    ssl_error: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)

    records: Mapped[list["Record"]] = relationship(
        back_populates="site", cascade="all, delete-orphan", order_by="Record.id"
    )

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


class Purge(Base):
    __tablename__ = "purges"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    site_id: Mapped[int] = mapped_column(ForeignKey("sites.id", ondelete="CASCADE"), index=True)
    urls: Mapped[str] = mapped_column(Text, default="[]")  # empty list = purge everything
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


class State(Base):
    """Small key/value table for scheduler state."""

    __tablename__ = "state"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[str] = mapped_column(Text, default="")
