import hashlib
import json
import logging
from datetime import datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from . import pdns
from .config import settings
from .models import Edge, Purge, Site, UsageHourly, utcnow
from .validation import fqdn

log = logging.getLogger("pcdn")


def online_edges(db: Session) -> list[Edge]:
    cutoff = utcnow() - timedelta(seconds=settings.edge_offline_seconds)
    return list(db.scalars(
        select(Edge).where(Edge.enabled.is_(True), Edge.last_seen_at.is_not(None), Edge.last_seen_at >= cutoff)
        .order_by(Edge.id)
    ))


def sync_site_dns(db: Session, site: Site) -> str | None:
    """Push the zone to PowerDNS. Returns an error string on failure."""
    if not settings.pdns_enabled:
        return None
    try:
        pdns.client().sync_zone(site, online_edges(db))
        return None
    except Exception as e:  # noqa: BLE001 - never break the API because DNS is down
        log.exception("DNS sync failed for %s", site.domain)
        return str(e)


def sync_all_dns(db: Session) -> int:
    failed = 0
    for site in db.scalars(select(Site)):
        if sync_site_dns(db, site):
            failed += 1
    return failed


def month_start(now: datetime | None = None) -> datetime:
    now = now or utcnow()
    return now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)


def usage_totals(db: Session, site_id: int, start: datetime, end: datetime | None = None) -> dict:
    q = select(
        func.coalesce(func.sum(UsageHourly.bytes), 0),
        func.coalesce(func.sum(UsageHourly.requests), 0),
        func.coalesce(func.sum(UsageHourly.cache_hits), 0),
    ).where(UsageHourly.site_id == site_id, UsageHourly.hour >= start)
    if end is not None:
        q = q.where(UsageHourly.hour < end)
    b, r, h = db.execute(q).one()
    return {"bytes": int(b), "requests": int(r), "cache_hits": int(h)}


def site_to_dict(db: Session, site: Site) -> dict:
    usage = usage_totals(db, site.id, month_start())
    return {
        "id": site.id,
        "domain": site.domain,
        "external_id": site.external_id,
        "status": site.effective_status,
        "ns_verified": site.ns_verified_at is not None,
        "ns_found": json.loads(site.ns_found or "[]"),
        "nameservers": settings.nameservers,
        "plan": {
            "bandwidth_limit_gb": site.bandwidth_limit_gb,
            "max_records": site.max_records,
            "ssl_allowed": site.ssl_allowed,
            "rate_limit_rps": site.rate_limit_rps,
        },
        "settings": {
            "cache_enabled": site.cache_enabled,
            "dev_mode": site.dev_mode,
            "force_https": site.force_https,
            "origin_protocol": site.origin_protocol,
            "edge_cache_ttl": site.edge_cache_ttl,
            "browser_cache_ttl": site.browser_cache_ttl,
            "blocked_ips": site.blocked_ip_list,
        },
        "ssl": {
            "status": site.ssl_status,
            "expires_at": site.ssl_expires_at.isoformat() + "Z" if site.ssl_expires_at else None,
            "error": site.ssl_error,
        },
        "usage_month": {**usage, "gb": round(usage["bytes"] / 1024**3, 3)},
        "records": [record_to_dict(r) for r in site.records],
        "created_at": site.created_at.isoformat() + "Z",
    }


def record_to_dict(r) -> dict:
    return {
        "id": r.id, "name": r.name, "type": r.type, "content": r.content,
        "ttl": r.ttl, "priority": r.priority, "proxied": r.proxied,
    }


# ---------------------------------------------------------------- edge config

def resolve_origin(site: Site, rec) -> str | None:
    """Origin address the edge should connect to for a proxied record.

    A CNAME pointing back into the same zone (e.g. www -> example.com) must be
    followed inside our records; otherwise the edge would resolve it to itself.
    """
    by_name: dict[str, list] = {}
    for r in site.records:
        if r.type in ("A", "AAAA", "CNAME"):
            by_name.setdefault(fqdn(r.name, site.domain), []).append(r)
    seen = set()
    while rec.type == "CNAME":
        target = rec.content
        in_zone = target == site.domain or target.endswith("." + site.domain)
        if not in_zone:
            return target
        if target in seen or target not in by_name:
            return None
        seen.add(target)
        cands = by_name[target]
        rec = next((c for c in cands if c.type == "A"), cands[0])
    return rec.content if rec.type == "A" else f"[{rec.content}]"


def build_edge_config(db: Session) -> dict:
    sites = []
    for site in db.scalars(select(Site).order_by(Site.id)):
        hosts = []
        for r in site.records:
            if not r.proxied:
                continue
            origin = resolve_origin(site, r)
            if origin:
                hosts.append({"name": fqdn(r.name, site.domain), "origin": origin})
        if not hosts:
            continue
        # one origin per hostname (first proxied record wins, like round-robin off)
        seen, uniq = set(), []
        for h in hosts:
            if h["name"] not in seen:
                seen.add(h["name"])
                uniq.append(h)
        ssl = None
        if site.ssl_status == "active" and site.ssl_cert and site.ssl_key:
            ssl = {"cert": site.ssl_cert, "key": site.ssl_key}
        sites.append({
            "id": site.id,
            "domain": site.domain,
            "status": site.effective_status,
            "hosts": uniq,
            "cache_enabled": site.cache_enabled and not site.dev_mode,
            "force_https": site.force_https and ssl is not None,
            "origin_protocol": site.origin_protocol,
            "edge_cache_ttl": site.edge_cache_ttl,
            "browser_cache_ttl": site.browser_cache_ttl,
            "rate_limit_rps": site.rate_limit_rps,
            "blocked_ips": site.blocked_ip_list,
            "ssl": ssl,
        })
    body = {"sites": sites}
    version = hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()
    return {"version": version, **body}


def queue_purge(db: Session, site: Site, urls: list[str]):
    db.add(Purge(site_id=site.id, urls=json.dumps(urls)))
