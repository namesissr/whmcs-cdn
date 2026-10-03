import hashlib
import hmac
import json
import logging
from collections import defaultdict
from datetime import datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from . import (access, botranges, crypto, dnsbuild, edge_labels, edge_state, images, l4, logexport, origin_guard,
               origin_pull, pdns, rollout, rum, sections, storage, tls_tickets, waf_learning, waiting_room, webhooks)
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
    if not isinstance(m, dict):
        return None
    # "_"-prefixed keys are the controller's own hysteresis counters (edge_state.py), never shown
    return {**{k: v for k, v in m.items() if not k.startswith("_")}, "at": e.metrics_at.isoformat() + "Z"}


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
    """Recompute the load-shedding flag with hysteresis, a consecutive-report requirement and a
    minimum hold time (F25). Caller commits.

    An edge is shed only after EDGE_SHED_CHECKS consecutive reports at/above EDGE_SHED_PERCENT (or,
    when EDGE_CPU_SHED>0, load1/cpus at/above it), so a single 60s spike can no longer herd a whole
    region. Once shed it stays shed for at least EDGE_SHED_HOLD seconds, then recovers only when the
    load is genuinely back below EDGE_SHED_PERCENT - SHED_HYSTERESIS (and CPU below EDGE_CPU_SHED).
    The pool-level "shed at most one edge per group+region per tick / keep capacity above load" cap
    lives in the scheduler, which alone sees the whole edge set."""
    now = now or utcnow()
    pct = edge_load_percent(e, now)
    if pct is None:  # no fresh metrics: is_shed's freshness guard already excludes this edge
        e.shed = False
        e.shed_high = 0
        e.shed_since = None
        return
    ratio = cpu_ratio(edge_metrics(e) or {}) if settings.edge_cpu_shed > 0 else None
    cpu_high = ratio is not None and ratio >= settings.edge_cpu_shed
    high = pct >= settings.edge_shed_percent or cpu_high
    e.shed_high = (e.shed_high or 0) + 1 if high else 0
    if not e.shed:
        if e.shed_high >= settings.edge_shed_checks:
            e.shed = True
            e.shed_since = now
        return
    held = e.shed_since is not None and now - e.shed_since < timedelta(seconds=settings.edge_shed_hold)
    recovered = pct < settings.edge_shed_percent - SHED_HYSTERESIS and (
        ratio is None or ratio < settings.edge_cpu_shed)
    if recovered and not held:
        e.shed = False
        e.shed_since = None


def cpu_ratio(m: dict) -> float | None:
    """load1 per CPU core, or None when either is missing."""
    cpus = float(m.get("cpus") or 0)
    if cpus <= 0 or m.get("load1") is None:
        return None
    return float(m.get("load1") or 0) / cpus


def record_metrics(e: Edge, metrics: dict, now: datetime | None = None):
    """Store heartbeat metrics and update the shed flag and the high-load counters. Caller commits."""
    from . import edge_state

    now = now or utcnow()
    try:
        prev = json.loads(e.metrics or "{}")
        prev = prev if isinstance(prev, dict) else {}
    except ValueError:
        prev = {}
    # drop keys the agent didn't send (disk_pct/mem_pct are optional) so they don't show as 0
    clean = {k: v for k, v in metrics.items() if v is not None and not str(k).startswith("_")}
    e.metrics = json.dumps(clean)
    e.metrics_at = now
    update_shed(e, now)
    pct = edge_load_percent(e, now)
    # SPEC §22.2 draining-generation pile-up and §22.10 DNS weight level hysteresis (internal counters)
    level, up, down = edge_state.weight_level(int(e.dns_weight_level or 0), pct, prev)
    e.dns_weight_level = level
    e.metrics = json.dumps({**clean, "_pileup_n": edge_state.pileup_counter(prev, clean),
                            "_wl_up": up, "_wl_down": down})
    e.load_high = (e.load_high or 0) + 1 if pct is not None and pct > LOAD_ALERT_PERCENT else 0
    ratio = cpu_ratio(clean)
    e.cpu_high = (e.cpu_high or 0) + 1 if ratio is not None and ratio > settings.edge_cpu_alert else 0


def _peak_mbps(e: Edge, now: datetime | None = None) -> float:
    """The edge's current peak (rx/tx) load in Mbps from its fresh metrics, else 0."""
    if not metrics_fresh(e, now):
        return 0.0
    m = edge_metrics(e) or {}
    return max(float(m.get("rx_mbps") or 0), float(m.get("tx_mbps") or 0))


def rebalance_pool_shed(db: Session, now: datetime | None = None) -> None:
    """Pool-level load-shed safety cap (F25). Load shedding is decided per edge on each heartbeat
    (update_shed), which cannot see the rest of the pool; here — where the scheduler holds the whole
    online edge set — we make sure shedding never herds a region: within each (group, region) pool
    the remaining unshed capacity_mbps must stay at or above the pool's aggregate load. When it would
    drop below, the least-loaded shed edges are put back into DNS (their shed_high is reset so they
    do not instantly re-shed). Recovery is never throttled. Caller-independent: commits its own work."""
    now = now or utcnow()
    pools: dict[tuple[str, str], list[Edge]] = defaultdict(list)
    for e in online_edges(db):
        pools[(dnsbuild.edge_group(e), "home" if e.region == "home" else "global")].append(e)
    changed = False
    for members in pools.values():
        shed = [e for e in members if dnsbuild.is_shed(e, now)]
        if not shed:
            continue
        unshed = [e for e in members if not dnsbuild.is_shed(e, now)]
        # capacity_mbps 0 means "unknown, never shed" — if any staying edge is unknown-capacity we
        # cannot compute a meaningful floor, so assume the pool can absorb the load and don't force
        if unshed and any(e.capacity_mbps <= 0 for e in unshed):
            continue
        load = sum(_peak_mbps(e, now) for e in members)
        unshed_cap = sum(e.capacity_mbps for e in unshed)
        for e in sorted(shed, key=lambda e: _peak_mbps(e, now)):
            if unshed_cap >= load:
                break
            e.shed, e.shed_since, e.shed_high = False, None, 0
            unshed_cap += e.capacity_mbps
            changed = True
    if changed:
        db.commit()


DNS_DIRTY_KEY = "dns_dirty"


def sync_site_dns(db: Session, site: Site, server_errors: dict[int, str] | None = None,
                  force_secondary: bool = False) -> str | None:
    """Push the zone to PowerDNS. Returns an error string on failure.

    A failure marks DNS as dirty so the scheduler re-syncs every zone once the
    PowerDNS server is reachable again (see scheduler.job_edges). `force_secondary`: also apply an
    "off" secondary-DNS setting (clears transfer metadata left by an earlier setting, SPEC §16.7).
    """
    if not settings.pdns_enabled:
        return None
    try:
        if force_secondary:
            pdns.client().sync_zone(site, online_edges(db), force_secondary=True)
        else:
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


def lock_site(db: Session, site: Site) -> Site:
    """Re-read the site row with SELECT … FOR UPDATE, refreshing the in-memory object from the
    locked row, before any read-modify-write of its JSON columns (config, features,
    integration_secrets). Concurrent writers to the same site then serialize instead of silently
    overwriting each other's sections (each PUT rewrites the whole site.config document). The lock is
    held until the caller commits / rolls back. SQLite ignores FOR UPDATE (it serializes writers
    itself); the refresh still applies there."""
    locked = db.scalar(select(Site).where(Site.id == site.id).with_for_update()
                       .execution_options(populate_existing=True))
    return locked if locked is not None else site


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


def billing_start(site: Site, start: datetime) -> datetime:
    """Where the billed usage of a period starting at `start` begins: max(start, billing_since)
    (SPEC §19.2 — after a transfer with reset_billing_anchor the new owner does not pay for the
    previous owner's traffic)."""
    since = getattr(site, "billing_since", None)
    return since if since is not None and since > start else start


def billed_usage(db: Session, site: Site, start: datetime, end: datetime | None = None) -> dict:
    """usage_totals of [max(start, billing_since), end): the quota counter and every month figure
    reported to WHMCS. Analytics / history keep using usage_totals (the full history)."""
    begin = billing_start(site, start)
    if end is not None and begin >= end:
        return {"bytes": 0, "requests": 0, "cache_hits": 0}
    return usage_totals(db, site.id, begin, end)


QUOTA_WARNING_PERCENT = 80


def refresh_quota(db: Session, site: Site, now: datetime | None = None, emit: bool = True) -> bool:
    """Recompute over_quota for this month (counted from max(month start, billing_since), SPEC
    §19.2); returns True when it changed. Caller commits.

    Quota transitions emit webhooks (SPEC §14.3.3): `quota.exceeded` when the site goes over its
    bandwidth limit, `quota.warning` once per month when usage reaches 80 % of it first. `emit=False`
    (a domain transfer) only updates the flag."""
    now = now or utcnow()
    over = False
    used = limit = 0
    if site.bandwidth_limit_gb > 0:
        used = billed_usage(db, site, month_start(now))["bytes"]
        limit = site.bandwidth_limit_gb * 1024**3
        over = used >= limit
    changed = over != site.over_quota
    if limit > 0 and emit:
        data = {"used_bytes": used, "limit_bytes": limit, "percent": round(used * 100 / limit, 1),
                "month": now.strftime("%Y-%m")}
        warned = site.quota_warned_at is not None and site.quota_warned_at >= month_start(now)
        if over and not site.over_quota:
            webhooks.emit(db, site, "quota.exceeded", data, now)
            site.quota_warned_at = now  # no separate warning for the rest of this month
        elif not over and used * 100 >= limit * QUOTA_WARNING_PERCENT and not warned:
            webhooks.emit(db, site, "quota.warning", data, now)
            site.quota_warned_at = now
    site.over_quota = over
    return changed


def site_to_dict(db: Session, site: Site) -> dict:
    usage = billed_usage(db, site, month_start())
    # the function bodies are left out of the site object (SPEC §16.9: up to 8 MB of code per site)
    config = sections.config_view(sections.all_config(site))
    cache, ssl_opts = config["cache"], config["ssl"]
    return {
        "id": site.id,
        "domain": site.domain,
        "external_id": site.external_id,
        "client_id": site.client_id,
        "reseller_client_id": site.reseller_client_id,
        "reseller_label": site.reseller_label,
        # SPEC §19: client | reseller | operator; the admin-only note of an operator site; where the
        # billed usage (usage_month, quota) of the current owner starts (null = the whole month)
        "owner_kind": site.owner_kind or "client",
        "operator_note": site.operator_note,
        "billing_since": site.billing_since.isoformat() + "Z" if site.billing_since else None,
        "status": site.effective_status,
        # SPEC §23.10: suspended by the abuse desk (a billing unsuspend does not clear it)
        "abuse_suspended": bool(site.abuse_suspended),
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
        # authenticated origin pulls (SPEC §14.2): setting, effective mode, uploaded cert facts (no key)
        "origin_client": origin_pull.site_info(site, ssl_opts["origin_client_auth"]),
        # SPEC §22.8: key type of the served certificate and whether an RSA certificate is served too
        "ssl_key_type": _key_type(site),
        "ssl_dual_rsa": bool(settings.acme_dual_rsa and site.ssl_status == "active"
                             and site.ssl_source == "letsencrypt" and site.ssl_cert_rsa),
        "dnssec": site.dnssec_enabled,
        # customers whitelist these at their origin and use them for real-IP config
        "edge_ips": edge_ips(db),
        "usage_month": {**usage, "gb": round(usage["bytes"] / 1024**3, 3)},
        "records": [record_to_dict(r) for r in site.records],
        "created_at": site.created_at.isoformat() + "Z",
    }


def _key_type(site: Site) -> str | None:
    if site.ssl_status != "active" or not site.ssl_cert:
        return None
    from . import ssl as sslmod

    return sslmod.cert_key_type(site.ssl_cert)


def edge_ips(db: Session) -> list[str]:
    """SPEC §23.12.4: the origin allow-list — the enabled edges' addresses, unlabeled and unordered by
    node: de-duplicated, sorted numerically, IPv4 then IPv6, no names / cities / groups (the same
    addresses as before; nothing beyond what an origin sees in its own access log)."""
    import ipaddress

    seen = set()
    for e in db.scalars(select(Edge).where(Edge.enabled.is_(True))):
        for raw in (e.ipv4, e.ipv6):
            if not raw or raw == EDGE_IP_PLACEHOLDER:
                continue
            try:
                seen.add(ipaddress.ip_address(raw))
            except ValueError:
                continue
    return [str(ip) for ip in sorted(seen, key=lambda ip: (ip.version, int(ip)))]


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
        # SPEC §16.8: origin shortcut to one of the site's storage buckets (its short name)
        "storage": r.storage_bucket,
        "health_check": r.health_check, "health_port": r.health_port,
        # SPEC §16.7: weighted / failover sets and the controller's probe of non-proxied records
        "weight": r.weight, "health_protocol": r.health_protocol, "health_path": r.health_path,
        "health": ({"ok": r.health_ok, "ms": r.health_ms, "fail": r.health_fail or 0,
                    "at": r.health_at.isoformat() + "Z" if r.health_at else None, "error": r.health_error,
                    "advertised": dnsbuild.record_advertised(r)} if r.health_check else None),
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


SHIELD_CONTEXT = b"pcdn-shield"
EDGE_IP_PLACEHOLDER = "0.0.0.0"  # batch-created edges (SPEC §11.1) until the node reports itself


def shield_secret() -> str:
    """Fleet-wide key for the `X-Pcdn-Shield` hop header (SPEC §14.1).

    HMAC-SHA256(server-side secret material, "pcdn-shield"): every controller of an HA set derives
    the same value, every edge gets the same value, and neither the raw DATA_ENCRYPTION_KEY nor
    the ADMIN_API_KEY ever leaves the controller (HMAC is one-way). The primary (first)
    DATA_ENCRYPTION_KEY is preferred, ADMIN_API_KEY otherwise; rotating that key rotates this one
    (one config bump on every edge). Empty when neither is configured: the shield is then off."""
    material = (settings.data_encryption_key or "").split(",")[0].strip() or (settings.admin_api_key or "")
    if not material:
        return ""
    return hmac.new(material.encode(), SHIELD_CONTEXT, hashlib.sha256).hexdigest()


def _edge_addr(e: Edge) -> str | None:
    """The address other edges reach this edge on: the primary IPv4, else the primary IPv6."""
    if e.ipv4 and e.ipv4 != EDGE_IP_PLACEHOLDER:
        return e.ipv4
    return e.ipv6 or None


def shield_peers(db: Session, edge: Edge | None) -> list[str]:
    """Addresses of the enabled + online shield edges of `edge`'s group, `edge` itself excluded,
    ordered by edge id (stable, so every edge builds the same consistent-hash ring)."""
    if edge is None:
        return []
    group = dnsbuild.edge_group(edge)
    out = []
    for e in online_edges(db):  # enabled and heartbeating, ordered by id
        if not e.shield or e.id == edge.id or dnsbuild.edge_group(e) != group:
            continue
        if dnsbuild.is_draining(e):  # SPEC §22.1: a draining shield gets no new hops either
            continue
        addr = _edge_addr(e)
        if addr and addr not in out:
            out.append(addr)
    return out


def edge_capabilities(e: Edge) -> dict | None:
    """Capabilities from the edge's latest heartbeat (SPEC §14.1), or None when never reported."""
    if not e.capabilities:
        return None
    try:
        caps = json.loads(e.capabilities)
    except ValueError:
        return None
    return caps if isinstance(caps, dict) else None


def build_edge_config(db: Session, edge: Edge | None = None) -> dict:
    """The config body for one edge (SPEC §5). `edge` is the requesting node: it decides the
    node-wide `shield` block (self flag, peers without itself) and therefore the version too.
    Without an edge the shield block is inert."""
    out = []
    secret = shield_secret()
    peers = shield_peers(db, edge) if secret else []
    group = dnsbuild.edge_group(edge) if edge is not None else None
    shield_used = False
    platform_pull = False  # some site presents the platform origin-pull client certificate
    buckets = storage.edge_buckets(db)  # SPEC §16.8 storage origins: (site id, name) -> bucket
    # origin host names that resolve to non-public addresses (origin_guard.py): never handed out
    blocked_hosts = origin_guard.blocked(db)
    online = None  # SPEC §18.1: computed once, only when some site has a waiting room
    for site in db.scalars(select(Site).order_by(Site.id)):
        hosts, seen = [], set()
        storage_on = bool(buckets) and sections.features_of(site)["storage_gb"] > 0
        for r in site.records:
            if not r.proxied:
                continue
            name = fqdn(r.name, site.domain)
            if name in seen:  # one origin per hostname (first proxied record wins)
                continue
            if r.storage_bucket:
                # a bucket that is gone, a plan without storage or a controller without storage
                # config drops the host (like a missing pool); the bucket's customer keys never
                # travel, only its read token for the Referer-conditioned bucket policy
                b = buckets.get((site.id, r.storage_bucket)) if storage_on else None
                if b is None:
                    continue
                try:
                    origin = {"storage": storage.edge_origin(b)}
                except crypto.CryptoError:  # unreadable token (key lost): this host only
                    continue
            elif r.pool:
                origin = {"pool": r.pool}
            else:
                address = resolve_origin(site, r)
                if not address or origin_guard.is_blocked(blocked_hosts, address):
                    continue
                origin = {"address": address, "port": r.origin_port}
            seen.add(name)
            hosts.append({"name": name, "origin": origin})
        if not hosts:
            continue
        cfg = sections.all_config(site)
        feats = sections.features_of(site)
        # F2: keep serving the stored certificate while it is present AND unexpired, including
        # during a renewal or a manual re-request (ssl_status "pending"). A renewal/retry/re-request
        # must never drop the site's HTTPS server from the edge config while the old cert is still
        # valid. Every path that should actually STOP HTTPS (custom-cert removal routes_v2:119,
        # undecryptable key crypto:206, plan losing SSL routes_admin.apply_plan) clears ssl_cert, so
        # gating on the stored pair + expiry never serves a cert that no longer applies. ssl=None
        # only when there is genuinely no usable cert (initial issuance, or expired + reissue failed).
        ssl = None
        if (site.ssl_cert and site.ssl_key and site.ssl_status in ("active", "pending")
                and (site.ssl_expires_at is None or site.ssl_expires_at > utcnow())):
            ssl = ssl_block(site)

        cache = dict(cfg["cache"])
        if cache["dev_mode"]:
            cache["enabled"] = False
        # SPEC §14.1: cache.shield takes effect only on an edge of the site's own group that has
        # at least one online shield peer (the site's group has ≥1 enabled, online shield edge);
        # otherwise it is folded to false so the edge fetches from the origin as before. A foreign-
        # group edge only serves the site in DNS fail-open, i.e. when that group has no online edge
        # (and so no online shield) at all.
        site_group = dnsbuild.site_edge_group(site)
        cache["shield"] = bool(cache["shield"] and cache["enabled"] and peers and site_group == group)
        ssl_opts = dict(cfg["ssl"])
        if ssl is None:
            ssl_opts["force_https"] = False
            ssl_opts["hsts"] = dict(ssl_opts["hsts"], enabled=False)
            ssl_opts["http3"] = False  # QUIC needs the HTTPS server, which is not rendered
        # a feature switched off by the plan wins over what the customer saved
        if not feats["waf"]:
            cfg["waf"] = dict(cfg["waf"], mode="off")
        if not feats["ddos"]:
            cfg["ddos"] = dict(cfg["ddos"], mode="off")
        if not feats["load_balancer"]:
            cfg["pools"] = {"pools": []}
            hosts = [h for h in hosts if "pool" not in h["origin"]]
        if blocked_hosts:
            # members on the origin guard's block list leave their pool; an emptied pool goes
            pools = []
            for p in cfg["pools"]["pools"]:
                members = [o for o in p["origins"] if not origin_guard.is_blocked(blocked_hosts, o["address"])]
                if members:
                    pools.append(dict(p, origins=members))
            cfg["pools"] = dict(cfg["pools"], pools=pools)
        # H2: a firewall / transform / redirect rule stored before today's regex safety check is not
        # sent while one of its regexes fails that check (dropping only the condition would widen the
        # rule); the edges skip such a rule too. The scheduler alerts on them (check_unsafe_regex).
        cfg = sections.drop_unsafe_regex_rules(cfg)
        for key, feat in (("firewall", "max_firewall_rules"), ("ratelimit", "max_ratelimit_rules"),
                          ("pagerules", "max_page_rules"), ("transform", "max_transform_rules"),
                          ("redirects", "max_redirects")):
            cfg[key] = dict(cfg[key], rules=cfg[key]["rules"][: feats[feat]])
        pool_names = {p["name"] for p in cfg["pools"]["pools"]}
        hosts = [h for h in hosts if "pool" not in h["origin"] or h["origin"]["pool"] in pool_names]
        if not hosts:
            continue
        shield_used = shield_used or cache["shield"]
        wr_serving = 1
        if cfg["waiting_room"]["enabled"]:
            if online is None:
                online = online_edges(db)
            wr_serving = waiting_room.serving_edges(site, online)
        # SPEC §14.2 authenticated origin pulls: what the edges present to this site's origin.
        # {"mode": "off"|"platform"} or {"mode": "custom", "cert", "key"} (this site's own pair); a
        # custom mode without a usable uploaded certificate is folded to off
        ssl_opts["origin_client"] = origin_pull.edge_block(site, ssl_opts["origin_client_auth"])
        platform_pull = platform_pull or ssl_opts["origin_client"]["mode"] == "platform"

        out.append({
            "id": site.id,
            "domain": site.domain,
            "status": site.effective_status,
            # F21: the site's edge group, so a node can tell own-group from foreign-group changes and
            # defer a foreign-group-only reload (the edge keeps every site configured for DNS fail-open)
            "edge_group": dnsbuild.site_edge_group(site),
            "secret": site.secret,
            "hosts": hosts,
            "ssl": ssl,
            "rate_limit_rps": site.rate_limit_rps,
            "blocked_ips": site.blocked_ip_list,
            "cache": cache,
            "ssl_options": ssl_opts,
            # SPEC §17.1: learning reduced to {enabled, until}; off without the plan's WAF
            "waf": waf_learning.edge_waf(cfg["waf"], feats),
            "ddos": cfg["ddos"],
            "firewall": cfg["firewall"],
            "ratelimit": cfg["ratelimit"],
            "pagerules": cfg["pagerules"],
            "pools": cfg["pools"],
            "headers": cfg["headers"],
            "hotlink": cfg["hotlink"],
            # SPEC §16.6: avif / smart_crop and the signed-URL key in clear (images.py); the plan's
            # image_optimization switch folds every image feature off
            "image": images.edge_block(site, cfg["image"], feats),
            # SPEC §16.5: HLS/DASH delivery settings, passed through
            "video": cfg["video"],
            # SPEC §16.4: this site's TCP/UDP apps for this node (same apps as the node-wide `l4`)
            "l4": l4.site_block(site, edge, blocked_hosts),
            "errorpages": cfg["errorpages"],
            "tunnel": tunnel_for_edge(site, cfg["tunnel"], feats, pool_names, blocked_hosts),
            # rules & security (SPEC §14.2); waf.packs travels inside "waf"
            "transform": cfg["transform"],
            "redirects": cfg["redirects"],
            "bots": cfg["bots"],
            # log export (SPEC §14.3.2): sampling only — never the endpoint, bucket or keys
            "logs": logexport.edge_block(site, cfg["logs"], feats),
            # SPEC §16.9 edge functions (run by pcdn-fn on nodes installed with --functions)
            "functions": functions_for_edge(site, cfg["functions"], feats),
            # SPEC §18.1: node_max = ceil(max_active / healthy edges serving the site), the wr_secret
            # (64 hex = 32 bytes) for the __pcdn_wr cookie; enabled folded with plan + site status
            "waiting_room": waiting_room.edge_block(site, cfg["waiting_room"], feats, wr_serving),
            # SPEC §18.2: protected apps + access_secret (64 hex = 32 bytes, HMAC key = the raw bytes)
            "access": access.edge_block(site, cfg["access"], feats),
        })
        # SPEC §23.7: per-site RUM block only when enabled (absent otherwise: old agents ignore it)
        rum_block = rum.edge_block(site, cfg["rum"], feats)
        if rum_block is not None:
            out[-1]["rum"] = rum_block
    body = {
        "sites": out,
        # node-wide origin shield block (SPEC §14.1). `self`: this node is a shield (accepts shield
        # hops carrying a valid X-Pcdn-Shield, never re-shields). `peers`: the shield edges this
        # node sends cache misses of shield-enabled sites to — listed only while at least one site
        # actually uses them, so a shield going on/offline does not bump every node's version (and
        # reload) when nobody shields. `secret`: fleet-wide hop key (shield_secret).
        "shield": {
            "self": bool(edge is not None and edge.shield and secret),
            "peers": peers if shield_used else [],
            "secret": secret,
        },
        # node-wide verified crawler IP ranges for bot management (SPEC §14.2, botranges.py)
        "bots": botranges.edge_block(db),
        # node-wide platform client certificate for authenticated origin pulls (SPEC §14.2): the
        # client cert + key only (never the CA key), present only while a site uses mode platform
        "origin_pull": origin_pull.client_pair() if platform_pull else None,
        # the requesting node itself (SPEC §15.2/§15.6): its capacity for tunnel fair share (0 =
        # unknown, fair share never engages) and its name (hashed by the edge for X-Pcdn-Node)
        "node": {
            "name": edge.name if edge is not None else "",
            "capacity_mbps": int(edge.capacity_mbps or 0) if edge is not None else 0,
            "fair_share_pct": settings.fair_share_pct,
            # SPEC §22: drain (§22.1), probe origin (§22.3) and dns_weight (§22.10) are agent-side only
            # (never rendered: a change of only these keys never reloads nginx); http3 = this node's
            # admin switch (§22.9); tls_tickets = the fleet's session ticket keys or null (§22.8)
            "drain": edge_state.drain_block(edge),
            "probe": edge_state.probe_block(),
            "http3": edge is None or edge.http3_enabled is not False,
            "tls_tickets": tls_tickets.edge_block(db),
            "dns_weight": _node_dns_weight(db, edge),
            # SPEC §23.12.2: the node's public tag (8 hex, HMAC of its id; rendered as X-Served-By /
            # X-Pcdn-Node instead of the host name) and §23.2 the self-upgrade request (non-rendered)
            "public_tag": edge_labels.public_tag(edge.id, db) if edge is not None else None,
            "upgrade": rollout.upgrade_block(db, edge),
        },
        # SPEC §16.4: the TCP/UDP proxy apps this node listens for — apps of the node's own edge
        # group, of active sites whose plan has l4_proxy, enabled apps only (l4.edge_block)
        "l4": l4.edge_block(db, edge, blocked_hosts),
    }
    # content hash: an unchanged body keeps its version/ETag, so the edge sees a 304 and no reload
    version = hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()
    return {"version": version, **body}


def _node_dns_weight(db: Session, edge: Edge | None) -> dict | None:
    """Edge config `node.dns_weight` (informational): {level, q} while DNS_WEIGHTS=capacity, else null."""
    if edge is None or not dnsbuild.weights_enabled():
        return None
    return edge_state.dns_weight_dict(edge, edge_dns_q(db, edge))


def edge_dns_q(db: Session, edge: Edge, online: list | None = None) -> int | None:
    """The DNS weight q (1..4) of `edge` in its pool (SPEC §22.10); None when DNS_WEIGHTS=off or the
    edge is not online."""
    if not dnsbuild.weights_enabled():
        return None
    online = online if online is not None else online_edges(db)
    me = next((e for e in online if e.id == edge.id), None)
    if me is None:
        return None
    return dnsbuild.edge_q(online, 4).get(id(me)) or dnsbuild.edge_q(online, 6).get(id(me))


def ssl_block(site: Site) -> dict:
    """The `ssl` block of a site with a usable certificate (SPEC §22.8): the ECDSA pair, the optional
    RSA pair (ACME_DUAL_RSA, Let's Encrypt sites, while unexpired) and whether to staple OCSP (only
    when the leaf names an OCSP responder and the chain includes its issuer)."""
    from . import ssl as sslmod

    out = {"cert": site.ssl_cert, "key": site.ssl_key, "ocsp": sslmod.ocsp_capable(site.ssl_cert)}
    if settings.acme_dual_rsa and site.ssl_source == "letsencrypt" and site.ssl_cert_rsa \
            and site.ssl_key_rsa_stored and sslmod.cert_valid(site.ssl_cert_rsa):
        try:
            key = site.ssl_key_rsa
        except crypto.CryptoError:  # unreadable key (key lost): ECDSA only
            key = None
        if key:
            out["cert_rsa"], out["key_rsa"] = site.ssl_cert_rsa, key
    return out


def functions_for_edge(site: Site, fn: dict, feats: dict) -> dict:
    """Functions section as the edges get it (SPEC §16.9): the plan folded in (no edge_functions ->
    off, at most max_functions items), only enabled items, each with its effective on_error (an
    explicit null would make the edge skip the item). Off for a site that is not active: the edge
    ignores them there, so their code does not travel."""
    off = {"enabled": False, "on_error": fn["on_error"], "items": []}
    if not fn["enabled"] or not feats["edge_functions"] or site.effective_status != "active":
        return off
    items = [{"id": i["id"], "route": i["route"], "code": i["code"], "enabled": True,
              "timeout_ms": i["timeout_ms"], "memory_mb": i["memory_mb"],
              "on_error": i["on_error"] or fn["on_error"]}
             for i in fn["items"][: feats["max_functions"]] if i["enabled"]]
    return {"enabled": bool(items), "on_error": fn["on_error"], "items": items}


ORIGIN_COMPAT_KEYS = ("address", "port", "tls", "sni", "verify")


def _edge_tunnel_path(p: dict, max_origins: int, blocked_hosts: dict | None) -> dict | None:
    """One tunnel path as the edges get it (SPEC §22.4): `origins` members on the origin guard's
    block list are dropped (a path left without members is dropped), the list is cut to the plan's
    max_tunnel_origins (one member left -> a plain `origin` path), `failover` without explicit backups
    sends every member after the first as backup, and `origin` carries the first non-backup member for
    agents that predate `origins` (they serve the primary only, no failover)."""
    p = dict(p)
    for k in ("origins", "balance", "health", "idle_timeout"):
        p.setdefault(k, None)
    members = p.get("origins")
    if not members:
        p["origins"] = p["balance"] = p["health"] = None
        return p
    members = [dict(o) for o in members
               if not (blocked_hosts and origin_guard.is_blocked(blocked_hosts, o["address"]))]
    if not members:
        return None
    if all(o["backup"] for o in members):  # every primary was blocked: the first backup takes over
        members[0]["backup"] = False
    cut = members[: max(1, max_origins)]
    if all(o["backup"] for o in cut):
        cut[-1] = next(o for o in members if not o["backup"])
    if len(cut) == 1:
        p["origin"] = {k: cut[0][k] for k in ORIGIN_COMPAT_KEYS}
        p["origins"] = p["balance"] = p["health"] = None
        return p
    if p["balance"] == "failover" and not any(o["backup"] for o in cut):
        cut = [cut[0]] + [dict(o, backup=True) for o in cut[1:]]
    p["origins"] = cut
    primary = next(o for o in cut if not o["backup"])
    p["origin"] = {k: primary[k] for k in ORIGIN_COMPAT_KEYS}
    return p


def tunnel_for_edge(site: Site, tunnel: dict, feats: dict, pool_names: set[str],
                    blocked_hosts: dict | None = None) -> dict:
    """Tunnel section as the edges get it (SPEC §7.3): plan limits folded in."""
    t = dict(tunnel)
    # a path whose pool is gone (or load balancing is off) is dropped, like hosts above; so is a
    # path whose own origin host is on the origin guard's block list
    max_origins = int(feats.get("max_tunnel_origins") or 1)
    paths = [p for p in t["paths"] if (not p["pool"] or p["pool"] in pool_names) and not (
        blocked_hosts and p.get("origin") and origin_guard.is_blocked(blocked_hosts, p["origin"]["address"]))]
    paths = [x for x in (_edge_tunnel_path(p, max_origins, blocked_hosts) for p in paths) if x is not None]
    t["paths"] = paths[: feats["max_tunnel_paths"]]
    cap = feats["tunnel_max_mbps"]
    if cap > 0 and (t["per_connection_mbps"] == 0 or t["per_connection_mbps"] > cap):
        t["per_connection_mbps"] = cap
    t["max_connections"] = feats["max_tunnel_connections"]
    # F35: a suspended or over-quota site keeps advertising its tunnel path prefixes as `cut_paths`
    # so the edge can answer client reconnects with a cheap, rate-limited, body-less 503 on exactly
    # those paths instead of an unthrottled full-HTML 503 (or falling through to the origin). Only
    # when the plan has tunnel and the customer had it enabled; a plan-disabled tunnel has no paths.
    cut = (feats["tunnel"] and tunnel.get("enabled")
           and site.effective_status in ("suspended", "over_quota"))
    t["cut_paths"] = [p["path"] for p in t["paths"]] if cut else []
    if not feats["tunnel"] or site.effective_status != "active":
        t["enabled"] = False
    return t


def delete_platform_data(db: Session, site_id: int) -> None:
    """Remove a deleted site's per-site rows: API keys, usage, security events, purges, live
    analytics, log spool, webhook deliveries and their state. PostgreSQL cascades the rows itself,
    but SQLite enforces no foreign keys and may reuse the id for the next site, which must never
    inherit another customer's API keys, logs or events. Records go with the ORM cascade of
    Site.records. Caller commits."""
    from sqlalchemy import delete

    from .models import AnalyticsMinute, ApiKey, LogSpool, Purge, SecurityEvent, UsageHourly, WebhookDelivery

    from .models import AccessOtp, StorageBucket, StorageUsageHourly

    for model in (ApiKey, UsageHourly, SecurityEvent, Purge, AnalyticsMinute, LogSpool, WebhookDelivery,
                  StorageBucket, StorageUsageHourly, AccessOtp):
        db.execute(delete(model).where(model.site_id == site_id))
    # SPEC §23: config history, RUM, import sessions, alert subscriptions (outbox rows keep no site)
    from . import config_history, notify
    from .models import ImportSession, RumHourly

    for model in (RumHourly, ImportSession):
        db.execute(delete(model).where(model.site_id == site_id))
    config_history.delete_site(db, site_id)
    notify.prune_site(db, site_id)
    l4.delete_site(db, site_id)  # SPEC §16.4: the site's edge ports are free again
    keys = [logexport.STATUS_KEY.format(site_id), logexport.DROPPED_KEY.format(site_id),
            webhooks.ATTACK_KEY.format(site_id)]
    db.execute(delete(State).where(State.key.in_(keys)))


def queue_purge(db: Session, site: Site, urls: list[str],
                prefixes: list[str] | None = None, everything: bool = False) -> Purge:
    """Queue a purge for every edge (they poll /edge/v1/purges) and emit `purge.completed`
    (SPEC §14.3.3) in the same transaction. Caller commits."""
    p = Purge(site_id=site.id, urls=json.dumps(urls), prefixes=json.dumps(prefixes or []), everything=everything)
    db.add(p)
    db.flush()
    webhooks.emit(db, site, "purge.completed", {
        "purge_id": p.id, "urls": urls, "prefixes": prefixes or [],
        "everything": bool(everything or (not urls and not prefixes))})
    return p
