"""Support diagnostics report (SPEC §23.8): one JSON document a customer can send to support.

Never included: secrets (sections are summarized as counts / modes only: no header values, no tunnel
path strings, no origin addresses, no webhook URLs, no API keys), node addresses, internal node names
(the customer audience gets the §23.12 city labels), other sites. A final scrub pass replaces any
sensitive string of the site (tunnel paths, origin hosts, webhook / log URLs, header values, node
names and addresses) that might still appear in free text. ≤ 64 KB.
"""

import json
import secrets
import threading
import time
from datetime import timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from . import config_history, edge_labels, sections, tunnel_quality
from .config import settings
from .models import AnalyticsMinute, Edge, Incident, SecurityEvent, Site, SiteEvent, UsageHourly, utcnow
from .services import billed_usage, month_start, online_edges

MAX_BYTES = 64 * 1024
PER_HOUR = 20
_hits: dict[int, list[float]] = {}
_lock = threading.Lock()


def rate_limit(site_id: int) -> bool:
    now = time.monotonic()
    with _lock:
        hits = [t for t in _hits.get(site_id, []) if t > now - 3600]
        if len(hits) >= PER_HOUR:
            _hits[site_id] = hits
            return False
        hits.append(now)
        _hits[site_id] = hits
        return True


def _iso(dt) -> str | None:
    return dt.isoformat() + "Z" if dt else None


def _loads(raw) -> dict:
    try:
        v = json.loads(raw or "{}")
    except ValueError:
        return {}
    return v if isinstance(v, dict) else {}


def _ns_found(site: Site) -> list:
    try:
        v = json.loads(site.ns_found or "[]")
    except ValueError:
        return []
    return v if isinstance(v, list) else []


def config_summary(cfg: dict) -> dict:
    tn = cfg["tunnel"]
    return {
        "cache": {"enabled": cfg["cache"]["enabled"], "dev_mode": cfg["cache"]["dev_mode"],
                  "edge_ttl": cfg["cache"]["edge_ttl"]},
        "ssl": {"force_https": cfg["ssl"]["force_https"], "hsts": cfg["ssl"]["hsts"]["enabled"]},
        "firewall": {"rules": len(cfg["firewall"]["rules"])},
        "ratelimit": {"rules": len(cfg["ratelimit"]["rules"])},
        "waf": {"mode": cfg["waf"]["mode"], "learning": "on" if cfg["waf"]["learning"].get("enabled") else "off"},
        "ddos": {"mode": cfg["ddos"]["mode"]},
        "tunnel": {"enabled": bool(tn.get("enabled")), "paths": len(tn["paths"]),
                   "protocols": sorted({p["protocol"] for p in tn["paths"]})},
        "pools": {"pools": len(cfg["pools"]["pools"])},
        "redirects": {"rules": len(cfg["redirects"]["rules"])},
        "transform": {"rules": len(cfg["transform"]["rules"])},
        "pagerules": {"rules": len(cfg["pagerules"]["rules"])},
        "headers": {"rules": len(cfg["headers"].get("request", [])) + len(cfg["headers"].get("response", []))},
        "functions": {"items": len(cfg["functions"]["items"])},
        "webhooks": {"items": len(cfg["webhooks"]["items"])},
        "logs": {"enabled": bool(cfg["logs"]["enabled"])},
        "l4": {"apps": len(cfg["l4"]["apps"])},
        "waiting_room": {"enabled": bool(cfg["waiting_room"]["enabled"])},
        "access": {"apps": len(cfg["access"].get("apps", []))},
        "rum": {"enabled": bool(cfg["rum"]["enabled"])},
        "image": {"enabled": bool(cfg["image"].get("enabled"))},
    }


def _sensitive(db: Session, site: Site, cfg: dict) -> list[str]:
    """Strings of this site that must never appear in a customer report."""
    out = set()
    for p in cfg["tunnel"]["paths"]:
        out.add(p.get("path") or "")
        for o in [p.get("origin")] + list(p.get("origins") or []):
            if isinstance(o, dict):
                out.add(str(o.get("address") or ""))
    for pool in cfg["pools"]["pools"]:
        for o in pool.get("origins", []):
            out.add(str(o.get("address") or ""))
    for h in cfg["webhooks"]["items"]:
        out.add(h.get("url") or "")
    for k in ("s3_endpoint", "bucket", "access_key"):
        out.add(str(cfg["logs"].get(k) or ""))
    for part in ("request", "response"):
        for h in cfg["headers"].get(part, []) or []:
            out.add(str(h.get("value") or ""))
    for r in site.records:
        if r.proxied or r.type in ("A", "AAAA"):
            out.add(r.content)
    for e in db.scalars(select(Edge)):
        out.update({e.name, e.ipv4 or "", e.ipv6 or ""})
        out.update(a.ip for a in e.addresses)
    keep = {site.domain, *settings.nameservers}
    return sorted((s for s in out if s and len(s) >= 4 and s != "0.0.0.0" and s not in keep
                   and not s.endswith("." + site.domain)), key=len, reverse=True)


def _scrub(node, bad: list[str]):
    if isinstance(node, str):
        for s in bad:
            if s in node:
                node = node.replace(s, "[redacted]")
        return node
    if isinstance(node, list):
        return [_scrub(x, bad) for x in node]
    if isinstance(node, dict):
        return {k: _scrub(v, bad) for k, v in node.items()}
    return node


def build(db: Session, site: Site, audience: str = "customer") -> dict:
    now = utcnow()
    since = now - timedelta(hours=24)
    cfg = sections.all_config(site)
    feats = sections.features_of(site)
    warnings = []
    for name in sections.SECTIONS:
        try:
            warnings += sections.section_warnings(site, name, cfg[name])
        except Exception:  # noqa: BLE001 - a broken section never breaks the report
            continue
    ssl_days = int((site.ssl_expires_at - now).total_seconds() // 86400) if site.ssl_expires_at else None
    from .services import _key_type

    # recent activity --------------------------------------------------------------------------
    sec_n = db.scalar(select(func.count(SecurityEvent.id)).where(SecurityEvent.site_id == site.id,
                                                                 SecurityEvent.ts >= since)) or 0
    top = db.execute(select(SecurityEvent.source, SecurityEvent.rule, func.count(SecurityEvent.id)).where(
        SecurityEvent.site_id == site.id, SecurityEvent.ts >= since).group_by(
        SecurityEvent.source, SecurityEvent.rule).order_by(func.count(SecurityEvent.id).desc()).limit(5)).all()
    status = {"2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0}
    platform_errors = 0
    for (details,) in db.execute(select(UsageHourly.details).where(UsageHourly.site_id == site.id,
                                                                    UsageHourly.hour >= since)):
        d = _loads(details)
        for k, v in (d.get("status") or {}).items():
            if k in status and isinstance(v, int):
                status[k] += v
        platform_errors += int(d.get("platform_errors") or 0)
    origin_errors = 0
    for (details,) in db.execute(select(AnalyticsMinute.details).where(AnalyticsMinute.site_id == site.id,
                                                                        AnalyticsMinute.minute >= since)):
        origin_errors += int(_loads(details).get("oe") or 0)
    events = [{"t": _iso(e.created_at), "type": e.type} for e in db.scalars(
        select(SiteEvent).where(SiteEvent.site_id == site.id, SiteEvent.created_at >= since)
        .order_by(SiteEvent.created_at.desc()).limit(20))]

    # tunnel -----------------------------------------------------------------------------------
    tunnel = None
    if feats.get("tunnel") and cfg["tunnel"]["paths"]:
        q = tunnel_quality.quality(db, site, 24, now)
        sessions = sum(p["sessions"] or 0 for p in q["paths"])
        abnormal = [p["abnormal_pct"] for p in q["paths"] if p["abnormal_pct"] is not None]
        conn = [p["connect_ms_avg"] for p in q["paths"] if p["connect_ms_avg"] is not None]
        tunnel = {"sessions_24h": sessions,
                  "abnormal_pct": round(sum(abnormal) / len(abnormal), 1) if abnormal else None,
                  "connect_ms_avg": round(sum(conn) / len(conn), 1) if conn else None,
                  "origin": tunnel_quality.health(db, site)["state"],
                  "top_drop_reason": tunnel_quality.drops(db, site, 24, now)["top"],
                  "nodes": [{"label": e["name"], "label_en": e["label_en"], "sessions": e["sessions"],
                             "abnormal_pct": e["abnormal_pct"]} for e in q["edges"]]}

    # usage, history, incidents ----------------------------------------------------------------
    used = billed_usage(db, site, month_start(now))
    limit_gb = site.bandwidth_limit_gb or 0
    pct = round(100.0 * used["bytes"] / (limit_gb * 1024 ** 3), 1) if limit_gb else None
    hist = config_history.history(db, site, limit=5) if settings.config_history_enabled else {"versions": []}
    incidents = [{"title": i.title, "status": i.status, "at": _iso(i.created_at)} for i in db.scalars(
        select(Incident).where(Incident.created_at >= now - timedelta(days=30)).order_by(Incident.id.desc()).limit(5))]

    report = {
        "report_id": "dg_" + secrets.token_hex(6),
        "generated_at": _iso(now),
        "audience": audience,
        "site": {"domain": site.domain, "status": site.effective_status, "created_at": _iso(site.created_at),
                 "plan": {"bandwidth_limit_gb": site.bandwidth_limit_gb, "features": feats}},
        "dns": {"ns_verified": site.ns_verified_at is not None, "ns_expected": settings.nameservers,
                "ns_found": _ns_found(site),
                "ns_checked_at": _iso(site.ns_checked_at), "dnssec": bool(site.dnssec_enabled),
                "records": len(site.records), "proxied": sum(1 for r in site.records if r.proxied),
                "secondary": cfg["dns_secondary"].get("mode", "off") != "off"},
        "ssl": {"status": site.ssl_status, "source": site.ssl_source, "expires_at": _iso(site.ssl_expires_at),
                "days_left": ssl_days, "key_type": _key_type(site), "error": (site.ssl_error or None) and
                str(site.ssl_error)[:300]},
        "config": config_summary(cfg),
        "warnings": warnings[:30],
        "recent": {"security_events_24h": int(sec_n),
                   "top_rules": [{"rule": f"{src}:{rule}" if rule else src, "count": int(n)} for src, rule, n in top],
                   "status_24h": status, "origin_errors_24h": origin_errors,
                   "platform_errors_24h": platform_errors, "events": events},
        "tunnel": tunnel,
        "usage": {"month_bytes": used["bytes"], "limit_gb": limit_gb, "pct": pct, "over_quota": bool(site.over_quota)},
        "history": [{"version": v["version"], "at": v["at"], "actor": {"kind": v["actor"]["kind"]},
                     "sections": v["sections"]} for v in hist["versions"]],
        "incidents": incidents,
    }
    report = _scrub(report, _sensitive(db, site, cfg))
    if audience == "admin":
        online = {e.id for e in online_edges(db)}
        from . import dnsbuild

        group = dnsbuild.site_edge_group(site)
        report["internal"] = {
            "edges_serving": [{"name": e.name, "group": e.group, "region": e.region, "online": e.id in online,
                               "release": e.release, "label": edge_labels.label_of(db, e.id)["fa"]}
                              for e in db.scalars(select(Edge).where(Edge.enabled.is_(True), Edge.group == group)
                                                  .order_by(Edge.id))],
            "site_id": site.id, "external_id": site.external_id}
    return _cap(report)


def _cap(report: dict) -> dict:
    """Trim the longest lists until the document is ≤ 64 KB."""
    def size():
        return len(json.dumps(report, ensure_ascii=False).encode())

    for path in (("recent", "events"), ("warnings",), ("tunnel", "nodes"), ("history",), ("incidents",),
                 ("recent", "top_rules")):
        while size() > MAX_BYTES:
            node = report
            for p in path[:-1]:
                node = node.get(p) or {}
            lst = node.get(path[-1]) if isinstance(node, dict) else None
            if not lst:
                break
            lst.pop()
    return report
