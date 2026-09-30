import hashlib
import json
import logging
from datetime import datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from . import pdns, sections
from .config import settings
from .models import Edge, Purge, Site, State, UsageHourly, utcnow
from .validation import fqdn

log = logging.getLogger("pcdn")


def online_edges(db: Session) -> list[Edge]:
    cutoff = utcnow() - timedelta(seconds=settings.edge_offline_seconds)
    return list(db.scalars(
        select(Edge).where(Edge.enabled.is_(True), Edge.last_seen_at.is_not(None), Edge.last_seen_at >= cutoff)
        .order_by(Edge.id)
    ))


# ---------------------------------------------------------------- edge load (SPEC §7.4)

# hysteresis: a shed edge comes back once its load drops below EDGE_SHED_PERCENT - this
SHED_HYSTERESIS = 15
# edge_saturated alert when the load stays above this for LOAD_ALERT_CHECKS reports
LOAD_ALERT_PERCENT = 80
LOAD_ALERT_CHECKS = 3


def edge_metrics(e: Edge) -> dict | None:
    """Latest heartbeat metrics as shown on the edge object ({..., "at": "...Z"}) or None."""
    if not e.metrics or e.metrics_at is None:
        return None
    try:
        m = json.loads(e.metrics)
    except ValueError:
        return None
    return {**m, "at": e.metrics_at.isoformat() + "Z"}


def metrics_fresh(e, now: datetime | None = None) -> bool:
    at = getattr(e, "metrics_at", None)
    return at is not None and (now or utcnow()) - at <= timedelta(seconds=settings.edge_offline_seconds)


def edge_load_percent(e: Edge, now: datetime | None = None) -> float | None:
    """max(rx, tx) as % of capacity_mbps; None when the capacity or fresh metrics are unknown."""
    if not e.capacity_mbps or e.capacity_mbps <= 0 or not metrics_fresh(e, now):
        return None
    m = edge_metrics(e) or {}
    peak = max(float(m.get("rx_mbps") or 0), float(m.get("tx_mbps") or 0))
    return peak * 100 / e.capacity_mbps


def update_shed(e: Edge, now: datetime | None = None):
    """Recompute the load-shedding flag (with hysteresis). Caller commits."""
    pct = edge_load_percent(e, now)
    if pct is None:
        e.shed = False
    elif pct >= settings.edge_shed_percent:
        e.shed = True
    elif pct < settings.edge_shed_percent - SHED_HYSTERESIS:
        e.shed = False


def cpu_ratio(m: dict) -> float | None:
    """load1 per CPU core, or None when either is missing."""
    cpus = float(m.get("cpus") or 0)
    if cpus <= 0 or m.get("load1") is None:
        return None
    return float(m.get("load1") or 0) / cpus


def record_metrics(e: Edge, metrics: dict, now: datetime | None = None):
    """Store heartbeat metrics and update the shed flag and the high-load counters. Caller commits."""
    now = now or utcnow()
    # drop keys the agent didn't send (disk_pct/mem_pct are optional) so they don't show as 0
    clean = {k: v for k, v in metrics.items() if v is not None}
    e.metrics = json.dumps(clean)
    e.metrics_at = now
    update_shed(e, now)
    pct = edge_load_percent(e, now)
    e.load_high = (e.load_high or 0) + 1 if pct is not None and pct > LOAD_ALERT_PERCENT else 0
    ratio = cpu_ratio(clean)
    e.cpu_high = (e.cpu_high or 0) + 1 if ratio is not None and ratio > settings.edge_cpu_alert else 0


DNS_DIRTY_KEY = "dns_dirty"


def sync_site_dns(db: Session, site: Site, server_errors: dict[int, str] | None = None) -> str | None:
    """Push the zone to PowerDNS. Returns an error string on failure.

    A failure marks DNS as dirty so the scheduler re-syncs every zone once the
    PowerDNS server is reachable again (see scheduler.job_edges).
    """
    if not settings.pdns_enabled:
        return None
    try:
        pdns.client().sync_zone(site, online_edges(db))
        return None
    except Exception as e:  # noqa: BLE001 - never break the API because DNS is down
        log.exception("DNS sync failed for %s", site.domain)
        if server_errors is not None:
            server_errors.update(getattr(e, "servers", None) or {-1: str(e)})
        mark_dns_dirty(db)
        return str(e)


def mark_dns_dirty(db: Session):
    try:
        if db.get(State, DNS_DIRTY_KEY) is None:
            db.add(State(key=DNS_DIRTY_KEY, value=utcnow().isoformat()))
        db.commit()
    except Exception:  # noqa: BLE001
        log.exception("could not flag DNS for resync")
        db.rollback()


def sync_all_dns(db: Session, server_errors: dict[int, str] | None = None) -> int:
    failed = 0
    for site in list(db.scalars(select(Site))):
        if sync_site_dns(db, site, server_errors):
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


def refresh_quota(db: Session, site: Site) -> bool:
    """Recompute over_quota for this month; returns True when it changed. Caller commits."""
    over = False
    if site.bandwidth_limit_gb > 0:
        used = usage_totals(db, site.id, month_start())["bytes"]
        over = used >= site.bandwidth_limit_gb * 1024**3
    changed = over != site.over_quota
    site.over_quota = over
    return changed


def site_to_dict(db: Session, site: Site) -> dict:
    usage = usage_totals(db, site.id, month_start())
    config = sections.all_config(site)
    cache, ssl_opts = config["cache"], config["ssl"]
    return {
        "id": site.id,
        "domain": site.domain,
        "external_id": site.external_id,
        "reseller_client_id": site.reseller_client_id,
        "reseller_label": site.reseller_label,
        "status": site.effective_status,
        "ns_verified": site.ns_verified_at is not None,
        "ns_found": json.loads(site.ns_found or "[]"),
        "nameservers": settings.nameservers,
        "plan": {
            "bandwidth_limit_gb": site.bandwidth_limit_gb,
            "max_records": site.max_records,
            "ssl_allowed": site.ssl_allowed,
            "rate_limit_rps": site.rate_limit_rps,
            "features": sections.features_of(site),
        },
        # v1 view, kept for older clients; the source of truth is "config"
        "settings": {
            "cache_enabled": cache["enabled"],
            "dev_mode": cache["dev_mode"],
            "force_https": ssl_opts["force_https"],
            "origin_protocol": ssl_opts["origin_protocol"],
            "edge_cache_ttl": cache["edge_ttl"],
            "browser_cache_ttl": cache["browser_ttl"],
            "blocked_ips": site.blocked_ip_list,
        },
        "config": config,
        "ssl": {
            "status": site.ssl_status,
            "source": site.ssl_source if site.ssl_status == "active" else None,
            "names": cert_names(site.ssl_cert) if site.ssl_status == "active" and site.ssl_cert else [],
            "expires_at": site.ssl_expires_at.isoformat() + "Z" if site.ssl_expires_at else None,
            "error": site.ssl_error,
        },
        "dnssec": site.dnssec_enabled,
        # customers whitelist these at their origin and use them for real-IP config
        "edge_ips": edge_ips(db),
        "usage_month": {**usage, "gb": round(usage["bytes"] / 1024**3, 3)},
        "records": [record_to_dict(r) for r in site.records],
        "created_at": site.created_at.isoformat() + "Z",
    }


def edge_ips(db: Session) -> list[str]:
    ips = []
    for e in db.scalars(select(Edge).where(Edge.enabled.is_(True)).order_by(Edge.id)):
        ips.append(e.ipv4)
        if e.ipv6:
            ips.append(e.ipv6)
    return ips


def cert_names(pem: str) -> list[str]:
    from . import ssl

    try:
        return ssl.cert_info(pem)["names"]
    except Exception:  # noqa: BLE001
        return []


def record_to_dict(r) -> dict:
    return {
        "id": r.id, "name": r.name, "type": r.type, "content": r.content,
        "ttl": r.ttl, "priority": r.priority, "proxied": r.proxied,
        "pool": r.pool, "origin_port": r.origin_port,
        "health_check": r.health_check, "health_port": r.health_port,
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
    out = []
    for site in db.scalars(select(Site).order_by(Site.id)):
        hosts, seen = [], set()
        for r in site.records:
            if not r.proxied:
                continue
            name = fqdn(r.name, site.domain)
            if name in seen:  # one origin per hostname (first proxied record wins)
                continue
            if r.pool:
                origin = {"pool": r.pool}
            else:
                address = resolve_origin(site, r)
                if not address:
                    continue
                origin = {"address": address, "port": r.origin_port}
            seen.add(name)
            hosts.append({"name": name, "origin": origin})
        if not hosts:
            continue
        cfg = sections.all_config(site)
        feats = sections.features_of(site)
        ssl = None
        if site.ssl_status == "active" and site.ssl_cert and site.ssl_key:
            ssl = {"cert": site.ssl_cert, "key": site.ssl_key}

        cache = dict(cfg["cache"])
        if cache["dev_mode"]:
            cache["enabled"] = False
        ssl_opts = dict(cfg["ssl"])
        if ssl is None:
            ssl_opts["force_https"] = False
            ssl_opts["hsts"] = dict(ssl_opts["hsts"], enabled=False)
        # a feature switched off by the plan wins over what the customer saved
        if not feats["waf"]:
            cfg["waf"] = dict(cfg["waf"], mode="off")
        if not feats["ddos"]:
            cfg["ddos"] = dict(cfg["ddos"], mode="off")
        if not feats["image_optimization"]:
            cfg["image"] = dict(cfg["image"], enabled=False)
        if not feats["load_balancer"]:
            cfg["pools"] = {"pools": []}
            hosts = [h for h in hosts if "pool" not in h["origin"]]
        for key, feat in (("firewall", "max_firewall_rules"), ("ratelimit", "max_ratelimit_rules"),
                          ("pagerules", "max_page_rules")):
            cfg[key] = dict(cfg[key], rules=cfg[key]["rules"][: feats[feat]])
        pool_names = {p["name"] for p in cfg["pools"]["pools"]}
        hosts = [h for h in hosts if "pool" not in h["origin"] or h["origin"]["pool"] in pool_names]
        if not hosts:
            continue

        out.append({
            "id": site.id,
            "domain": site.domain,
            "status": site.effective_status,
            "secret": site.secret,
            "hosts": hosts,
            "ssl": ssl,
            "rate_limit_rps": site.rate_limit_rps,
            "blocked_ips": site.blocked_ip_list,
            "cache": cache,
            "ssl_options": ssl_opts,
            "waf": cfg["waf"],
            "ddos": cfg["ddos"],
            "firewall": cfg["firewall"],
            "ratelimit": cfg["ratelimit"],
            "pagerules": cfg["pagerules"],
            "pools": cfg["pools"],
            "headers": cfg["headers"],
            "hotlink": cfg["hotlink"],
            "image": cfg["image"],
            "errorpages": cfg["errorpages"],
            "tunnel": tunnel_for_edge(site, cfg["tunnel"], feats, pool_names),
        })
    body = {"sites": out}
    version = hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()
    return {"version": version, **body}


def tunnel_for_edge(site: Site, tunnel: dict, feats: dict, pool_names: set[str]) -> dict:
    """Tunnel section as the edges get it (SPEC §7.3): plan limits folded in."""
    t = dict(tunnel)
    # a path whose pool is gone (or load balancing is off) is dropped, like hosts above
    t["paths"] = [p for p in t["paths"] if not p["pool"] or p["pool"] in pool_names][: feats["max_tunnel_paths"]]
    cap = feats["tunnel_max_mbps"]
    if cap > 0 and (t["per_connection_mbps"] == 0 or t["per_connection_mbps"] > cap):
        t["per_connection_mbps"] = cap
    t["max_connections"] = feats["max_tunnel_connections"]
    if not feats["tunnel"] or site.effective_status != "active":
        t["enabled"] = False
    return t


def queue_purge(db: Session, site: Site, urls: list[str],
                prefixes: list[str] | None = None, everything: bool = False):
    db.add(Purge(site_id=site.id, urls=json.dumps(urls),
                 prefixes=json.dumps(prefixes or []), everything=everything))
