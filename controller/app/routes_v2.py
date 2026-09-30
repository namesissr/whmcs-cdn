"""v2 admin API: configuration sections, custom SSL, zone import/export, DNSSEC, analytics (SPEC §2–4)."""

import json
from collections import Counter
from datetime import timedelta

import dns.exception
import dns.rdatatype
import dns.zone
import pydantic
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from . import pdns, sections, ssl, tunnel
from .auth import require_admin
from .config import settings
from .db import get_db
from .models import Incident, IncidentUpdate, Record, SecurityEvent, Site, UsageHourly, utcnow
from .routes_admin import RecordIn, _record_from, bad, get_site
from .services import site_to_dict, sync_site_dns
from .validation import ValidationError

router = APIRouter(prefix="/api/v1", dependencies=[Depends(require_admin)])


def _pydantic_422(e: pydantic.ValidationError):
    raise HTTPException(422, [{"loc": list(err["loc"]), "msg": err["msg"].removeprefix("Value error, ")}
                              for err in e.errors()])


# ------------------------------------------------------------------ sections

@router.get("/sites/{domain}/config")
def read_config(domain: str, db: Session = Depends(get_db)):
    return sections.all_config(get_site(db, domain))


@router.get("/sites/{domain}/config/{section}")
def read_section(domain: str, section: str, db: Session = Depends(get_db)):
    if section not in sections.SECTIONS:
        raise HTTPException(404, "بخش نامعتبر است")
    return sections.get_section(get_site(db, domain), section)


@router.put("/sites/{domain}/config/{section}")
def write_section(domain: str, section: str, body: dict, db: Session = Depends(get_db)):
    site = get_site(db, domain)
    if section not in sections.SECTIONS:
        raise HTTPException(404, "بخش نامعتبر است")
    pools_in_use = {r.pool for r in site.records if r.pool}
    try:
        value = sections.validate_section(site, section, body, pools_in_use)
    except pydantic.ValidationError as e:
        _pydantic_422(e)
    except PermissionError as e:
        raise HTTPException(403, str(e))
    except ValidationError as e:
        bad(e)
    sections.store_section(site, section, value)
    db.commit()
    return value


# ------------------------------------------------------------------ tunnel mode (SPEC §7.5)

@router.get("/sites/{domain}/tunnel/stats")
def tunnel_stats(domain: str, hours: int = 24, db: Session = Depends(get_db)):
    site = get_site(db, domain)
    return tunnel.stats(db, site, max(1, min(hours, 24 * 31)))


@router.post("/sites/{domain}/tunnel/check")
def tunnel_check(domain: str, db: Session = Depends(get_db)):
    """Can the controller reach each tunnel path's origin (TCP, plus TLS when used)?"""
    paths = tunnel.targets(get_site(db, domain))
    db.rollback()  # do not hold a transaction open while connecting
    return {"results": tunnel.check(paths)}


# ------------------------------------------------------------------ custom SSL

class CustomCert(BaseModel):
    cert: str = Field(max_length=65536)
    key: str = Field(max_length=16384)


@router.put("/sites/{domain}/ssl/custom")
def upload_cert(domain: str, body: CustomCert, db: Session = Depends(get_db)):
    site = get_site(db, domain)
    if not sections.features_of(site)["custom_ssl"]:
        raise HTTPException(403, "گواهی اختصاصی در پلن شما فعال نیست")
    try:
        info = ssl.validate_custom(site.domain, body.cert.strip() + "\n", body.key.strip() + "\n")
    except ssl.SslError as e:
        bad(e)
    site.ssl_cert, site.ssl_key = body.cert.strip() + "\n", body.key.strip() + "\n"
    site.ssl_expires_at = info["expires_at"]
    site.ssl_status, site.ssl_source, site.ssl_error = "active", "custom", None
    db.commit()
    return site_to_dict(db, site)["ssl"]


@router.delete("/sites/{domain}/ssl/custom")
def remove_cert(domain: str, db: Session = Depends(get_db)):
    site = get_site(db, domain)
    if site.ssl_source != "custom":
        raise HTTPException(404, "گواهی اختصاصی ثبت نشده است")
    site.ssl_cert = site.ssl_key = site.ssl_expires_at = None
    site.ssl_source, site.ssl_error = None, None
    site.ssl_status = "pending" if site.ssl_allowed and site.ns_verified_at else "none"
    db.commit()
    return site_to_dict(db, site)["ssl"]


# ------------------------------------------------------------------ zone import / export

class ZoneImport(BaseModel):
    zone: str = Field(max_length=1_000_000)
    replace: bool = False


def _rdata_to_record(rtype: str, rd) -> tuple[str, int | None]:
    if rtype in ("A", "AAAA"):
        return rd.address, None
    if rtype in ("CNAME", "NS"):
        return rd.target.to_text(omit_final_dot=True), None
    if rtype == "MX":
        return rd.exchange.to_text(omit_final_dot=True), rd.preference
    if rtype == "SRV":
        return f"{rd.weight} {rd.port} {rd.target.to_text(omit_final_dot=True)}", rd.priority
    if rtype == "TXT":
        return b"".join(rd.strings).decode("utf-8", "replace"), None
    if rtype == "CAA":
        return f'{rd.flags} {rd.tag.decode()} "{rd.value.decode()}"', None
    raise ValidationError("نوع رکورد پشتیبانی نمی‌شود")


@router.post("/sites/{domain}/records/import")
def import_zone(domain: str, body: ZoneImport, db: Session = Depends(get_db)):
    site = get_site(db, domain)
    try:
        # relativize=False keeps in-zone targets (e.g. "sip" in SRV) fully qualified
        zone = dns.zone.from_text(body.zone, origin=site.domain + ".", relativize=False, check_origin=False)
    except (dns.exception.DNSException, ValueError) as e:
        bad(ValidationError(f"فایل زون قابل خواندن نیست: {e}"))
    if body.replace:
        site.records.clear()
    imported, skipped = 0, []
    for name, node in zone.nodes.items():
        rel = name.relativize(zone.origin).to_text()
        rel = "@" if rel in ("@", "") else rel
        for rdataset in node.rdatasets:
            rtype = dns.rdatatype.to_text(rdataset.rdtype)
            for rd in rdataset:
                line = f"{rel} {rdataset.ttl} {rtype} {rd.to_text()}"
                if rtype == "SOA" or (rtype == "NS" and rel == "@"):
                    skipped.append({"line": line, "reason": "به‌صورت خودکار مدیریت می‌شود"})
                    continue
                if len(site.records) >= site.max_records:
                    skipped.append({"line": line, "reason": "سقف تعداد رکوردها"})
                    continue
                try:
                    content, prio = _rdata_to_record(rtype, rd)
                    rec_in = RecordIn(name=rel, type=rtype, content=content, priority=prio,
                                      ttl=min(max(rdataset.ttl, 60), 86400))
                    data = _record_from(site, rec_in)
                except (ValidationError, PermissionError, pydantic.ValidationError) as e:
                    skipped.append({"line": line, "reason": str(e)[:200]})
                    continue
                if any(r.name == data["name"] and r.type == data["type"] and r.content == data["content"]
                       for r in site.records):
                    skipped.append({"line": line, "reason": "تکراری"})
                    continue
                site.records.append(Record(**data))
                imported += 1
    db.commit()
    return {"imported": imported, "skipped": skipped, "dns_error": sync_site_dns(db, site)}


@router.get("/sites/{domain}/records/export")
def export_zone(domain: str, db: Session = Depends(get_db)):
    site = get_site(db, domain)
    lines = [f"$ORIGIN {site.domain}.", f"; exported {utcnow().isoformat()}Z"]
    for r in site.records:
        if r.type in ("CNAME", "NS", "ALIAS", "MX"):
            content = f"{r.content}."
        elif r.type == "SRV":
            w, p, t = r.content.split()
            content = f"{w} {p} {t}."
        elif r.type == "TXT":
            content = " ".join(f'"{r.content[i:i + 255]}"' for i in range(0, max(len(r.content), 1), 255))
        else:
            content = r.content
        prio = f"{r.priority} " if r.priority is not None else ""
        note = "  ; cdn-proxied" if r.proxied else ""
        lines.append(f"{r.name}\t{r.ttl}\tIN\t{r.type}\t{prio}{content}{note}")
    return {"zone": "\n".join(lines) + "\n"}


# ------------------------------------------------------------------ DNSSEC

class DnssecIn(BaseModel):
    enabled: bool


@router.get("/sites/{domain}/dnssec")
def dnssec_status(domain: str, db: Session = Depends(get_db)):
    site = get_site(db, domain)
    if not site.dnssec_enabled or not settings.pdns_enabled:
        return {"enabled": site.dnssec_enabled, "ds": [], "dnskey": None}
    try:
        return pdns.client().dnssec_info(site.domain)
    except Exception as e:  # noqa: BLE001
        raise HTTPException(502, f"خطای DNS: {e}")


@router.post("/sites/{domain}/dnssec")
def dnssec_toggle(domain: str, body: DnssecIn, db: Session = Depends(get_db)):
    site = get_site(db, domain)
    if body.enabled and not sections.features_of(site)["dnssec"]:
        raise HTTPException(403, "DNSSEC در پلن شما فعال نیست")
    if settings.pdns_enabled:
        try:
            err = sync_site_dns(db, site)  # make sure the zone exists everywhere first
            if err:
                raise RuntimeError(err)
            info = pdns.client().enable_dnssec(site.domain) if body.enabled else None
            if not body.enabled:
                pdns.client().disable_dnssec(site.domain)
        except Exception as e:  # noqa: BLE001
            raise HTTPException(502, f"خطای DNS: {e}")
    else:
        info = None
    site.dnssec_enabled = body.enabled
    db.commit()
    return info or {"enabled": body.enabled, "ds": [], "dnskey": None}


# ------------------------------------------------------------------ analytics

PERIODS = {"24h": timedelta(hours=24), "7d": timedelta(days=7), "30d": timedelta(days=30)}


def _loads(s: str) -> dict:
    try:
        return json.loads(s or "{}")
    except ValueError:
        return {}


@router.get("/sites/{domain}/analytics")
def analytics(domain: str, period: str = "24h", db: Session = Depends(get_db)):
    site = get_site(db, domain)
    if period not in PERIODS:
        bad(ValidationError("period باید 24h، 7d یا 30d باشد"))
    now = utcnow().replace(minute=0, second=0, microsecond=0)
    since = now - PERIODS[period] + timedelta(hours=1)
    hourly = period == "24h"
    rows = db.scalars(select(UsageHourly).where(UsageHourly.site_id == site.id, UsageHourly.hour >= since))

    totals = {"requests": 0, "bytes": 0, "cache_hits": 0,
              "status": {k: 0 for k in ("2xx", "3xx", "4xx", "5xx")},
              "security": {k: 0 for k in ("waf", "firewall", "ratelimit", "challenge", "ddos", "hotlink")}}
    buckets: dict[str, dict] = {}
    countries, paths, codes = Counter(), Counter(), Counter()
    for row in rows:
        key = row.hour.strftime("%Y-%m-%dT%H:00:00Z") if hourly else row.hour.strftime("%Y-%m-%dT00:00:00Z")
        b = buckets.setdefault(key, {"t": key, "requests": 0, "bytes": 0, "cache_hits": 0})
        b["requests"] += row.requests
        b["bytes"] += row.bytes
        b["cache_hits"] += row.cache_hits
        totals["requests"] += row.requests
        totals["bytes"] += row.bytes
        totals["cache_hits"] += row.cache_hits
        d = _loads(row.details)
        for k, v in d.get("status", {}).items():
            totals["status"][k] = totals["status"].get(k, 0) + int(v)
        for k, v in d.get("security", {}).items():
            totals["security"][k] = totals["security"].get(k, 0) + int(v)
        countries.update({k: int(v) for k, v in d.get("countries", {}).items()})
        paths.update({k: int(v) for k, v in d.get("paths", {}).items()})
        codes.update({k: int(v) for k, v in d.get("codes", {}).items()})

    # zero-filled series so charts have a point per hour/day
    series, step = [], timedelta(hours=1) if hourly else timedelta(days=1)
    t = since if hourly else since.replace(hour=0)
    while t <= now:
        key = t.strftime("%Y-%m-%dT%H:00:00Z") if hourly else t.strftime("%Y-%m-%dT00:00:00Z")
        series.append(buckets.get(key, {"t": key, "requests": 0, "bytes": 0, "cache_hits": 0}))
        t += step
    return {
        "period": period,
        "totals": totals,
        "series": series,
        "countries": [{"code": k, "requests": v} for k, v in countries.most_common(20)],
        "paths": [{"path": k, "requests": v} for k, v in paths.most_common(20)],
        "status_codes": [{"code": int(k), "requests": v} for k, v in codes.most_common(10) if k.isdigit()],
    }


@router.get("/analytics")
def platform_analytics(period: str = "24h", db: Session = Depends(get_db)):
    """Same shape as the per-site analytics, aggregated across ALL sites (SPEC §9.1)."""
    if period not in PERIODS:
        bad(ValidationError("period باید 24h، 7d یا 30d باشد"))
    now = utcnow().replace(minute=0, second=0, microsecond=0)
    since = now - PERIODS[period] + timedelta(hours=1)
    hourly = period == "24h"
    rows = db.scalars(select(UsageHourly).where(UsageHourly.hour >= since))

    totals = {"requests": 0, "bytes": 0, "cache_hits": 0,
              "status": {k: 0 for k in ("2xx", "3xx", "4xx", "5xx")},
              "security": {k: 0 for k in ("waf", "firewall", "ratelimit", "challenge", "ddos", "hotlink")}}
    buckets: dict[str, dict] = {}
    sec_buckets: Counter = Counter()
    countries = Counter()
    site_requests, site_bytes = Counter(), Counter()
    for row in rows:  # one bounded pass over the window
        key = row.hour.strftime("%Y-%m-%dT%H:00:00Z") if hourly else row.hour.strftime("%Y-%m-%dT00:00:00Z")
        b = buckets.setdefault(key, {"t": key, "requests": 0, "bytes": 0, "cache_hits": 0})
        b["requests"] += row.requests
        b["bytes"] += row.bytes
        b["cache_hits"] += row.cache_hits
        totals["requests"] += row.requests
        totals["bytes"] += row.bytes
        totals["cache_hits"] += row.cache_hits
        site_requests[row.site_id] += row.requests
        site_bytes[row.site_id] += row.bytes
        d = _loads(row.details)
        for k, v in d.get("status", {}).items():
            totals["status"][k] = totals["status"].get(k, 0) + int(v)
        for k, v in d.get("security", {}).items():
            totals["security"][k] = totals["security"].get(k, 0) + int(v)
            sec_buckets[key] += int(v)
        countries.update({k: int(v) for k, v in d.get("countries", {}).items()})

    # zero-filled series so charts have a point per hour/day
    series, security_series = [], []
    step = timedelta(hours=1) if hourly else timedelta(days=1)
    t = since if hourly else since.replace(hour=0)
    while t <= now:
        key = t.strftime("%Y-%m-%dT%H:00:00Z") if hourly else t.strftime("%Y-%m-%dT00:00:00Z")
        series.append(buckets.get(key, {"t": key, "requests": 0, "bytes": 0, "cache_hits": 0}))
        security_series.append({"t": key, "events": sec_buckets.get(key, 0)})
        t += step
    domains = dict(db.execute(select(Site.id, Site.domain)).all())
    return {
        "period": period,
        "totals": totals,
        "series": series,
        "countries": [{"code": k, "requests": v} for k, v in countries.most_common(20)],
        "sites": [{"domain": domains.get(sid, "?"), "requests": r, "bytes": site_bytes[sid]}
                  for sid, r in site_requests.most_common(20)],
        "security_series": security_series,
    }


@router.get("/sites/{domain}/events")
def events(domain: str, limit: int = 100, db: Session = Depends(get_db)):
    site = get_site(db, domain)
    limit = max(1, min(limit, 1000))
    rows = db.scalars(select(SecurityEvent).where(SecurityEvent.site_id == site.id)
                      .order_by(SecurityEvent.ts.desc(), SecurityEvent.id.desc()).limit(limit))
    return [{"t": e.ts.isoformat() + "Z", "ip": e.ip, "country": e.country, "method": e.method, "host": e.host,
             "path": e.path, "action": e.action, "source": e.source, "rule": e.rule, "user_agent": e.user_agent}
            for e in rows]


def prune_events(db: Session, keep: int = 1000):
    for (site_id,) in db.execute(select(Site.id)).all():
        cutoff = db.scalar(select(SecurityEvent.id).where(SecurityEvent.site_id == site_id)
                           .order_by(SecurityEvent.id.desc()).offset(keep).limit(1))
        if cutoff is not None:
            db.execute(delete(SecurityEvent).where(SecurityEvent.site_id == site_id, SecurityEvent.id <= cutoff))


# ------------------------------------------------------------------ platform-wide (admin panel)

@router.get("/overview")
def overview(db: Session = Depends(get_db)):
    """One call for the WHMCS admin dashboard: site/edge counts, month totals, top sites."""
    from .models import Edge
    from .services import month_start, online_edges

    start = month_start()
    by_status = Counter()
    for s in db.scalars(select(Site)):
        by_status[s.effective_status] += 1
    usage = Counter()
    requests = Counter()
    security = Counter()
    for row in db.scalars(select(UsageHourly).where(UsageHourly.hour >= start)):
        usage[row.site_id] += row.bytes
        requests[row.site_id] += row.requests
        for k, v in _loads(row.details).get("security", {}).items():
            security[k] += int(v)
    domains = dict(db.execute(select(Site.id, Site.domain)).all())
    online = {e.id for e in online_edges(db)}
    edges = list(db.scalars(select(Edge).order_by(Edge.id)))
    from . import uptime as up
    from .services import edge_metrics
    ups = up.summaries(db)
    return {
        "sites": {"total": sum(by_status.values()), "by_status": dict(by_status)},
        "edges": {"total": len(edges), "enabled": sum(1 for e in edges if e.enabled), "online": len(online),
                  "with_errors": sum(1 for e in edges if e.last_error),
                  "shed": sum(1 for e in edges if e.shed),
                  "list": [{"id": e.id, "name": e.name, "group": e.group, "enabled": e.enabled,
                            "online": e.id in online, "shed": e.shed, "capacity_mbps": e.capacity_mbps,
                            "metrics": edge_metrics(e), "uptime": ups.get(e.id, {"h24": None, "d30": None})}
                           for e in edges]},
        "month": {"start": start.isoformat() + "Z", "bytes": sum(usage.values()), "requests": sum(requests.values()),
                  "security": dict(security)},
        "top_sites": [{"domain": domains.get(sid, "?"), "bytes": b, "requests": requests[sid]}
                      for sid, b in usage.most_common(10)],
        "nameservers": settings.nameservers,
    }


# ------------------------------------------------------------------ incidents (SPEC §8.3)

INCIDENT_SEVERITIES = ("minor", "major", "maintenance")
INCIDENT_STATUSES = ("investigating", "identified", "monitoring", "resolved", "scheduled")


class IncidentIn(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    body: str = Field(default="", max_length=20000)
    severity: str
    status: str = "investigating"


class IncidentUpdateIn(BaseModel):
    status: str
    body: str = Field(default="", max_length=20000)


class IncidentPatch(BaseModel):
    title: str | None = Field(default=None, min_length=1, max_length=200)
    body: str | None = Field(default=None, max_length=20000)
    severity: str | None = None
    status: str | None = None


def _check_severity(sev: str):
    if sev not in INCIDENT_SEVERITIES:
        bad(ValidationError("شدت باید یکی از minor، major یا maintenance باشد"))


def _check_status(st: str):
    if st not in INCIDENT_STATUSES:
        bad(ValidationError("وضعیت باید یکی از investigating، identified، monitoring، resolved یا scheduled باشد"))


def _get_incident(db: Session, incident_id: int) -> Incident:
    inc = db.get(Incident, incident_id)
    if inc is None:
        raise HTTPException(404, "رخداد یافت نشد")
    return inc


@router.get("/incidents")
def list_incidents(all: bool = False, db: Session = Depends(get_db)):
    from .status import incident_dict

    q = select(Incident).order_by(Incident.id.desc())
    if not all:
        q = q.where(Incident.status != "resolved")
    return [incident_dict(i) for i in db.scalars(q)]


@router.post("/incidents", status_code=201)
def create_incident(body: IncidentIn, db: Session = Depends(get_db)):
    from .status import incident_dict

    _check_severity(body.severity)
    _check_status(body.status)
    inc = Incident(title=body.title.strip(), body=body.body, severity=body.severity, status=body.status)
    db.add(inc)
    db.flush()
    inc.updates.append(IncidentUpdate(status=body.status, body=body.body))
    db.commit()
    return incident_dict(inc)


@router.post("/incidents/{incident_id}/updates", status_code=201)
def add_incident_update(incident_id: int, body: IncidentUpdateIn, db: Session = Depends(get_db)):
    from .status import incident_dict

    _check_status(body.status)
    inc = _get_incident(db, incident_id)
    inc.updates.append(IncidentUpdate(status=body.status, body=body.body))
    inc.status = body.status
    inc.updated_at = utcnow()
    db.commit()
    return incident_dict(inc)


@router.patch("/incidents/{incident_id}")
def update_incident(incident_id: int, body: IncidentPatch, db: Session = Depends(get_db)):
    from .status import incident_dict

    inc = _get_incident(db, incident_id)
    data = body.model_dump(exclude_none=True)
    if "severity" in data:
        _check_severity(data["severity"])
    if "status" in data:
        _check_status(data["status"])
    if not data:
        bad(ValidationError("هیچ تغییری ارسال نشده است"))
    for k, v in data.items():
        setattr(inc, k, v.strip() if k == "title" else v)
    inc.updated_at = utcnow()
    db.commit()
    return incident_dict(inc)


@router.get("/events")
def all_events(limit: int = 100, source: str | None = None, db: Session = Depends(get_db)):
    """Newest security events across every site (admin panel)."""
    limit = max(1, min(limit, 1000))
    q = select(SecurityEvent, Site.domain).join(Site, Site.id == SecurityEvent.site_id)
    if source:
        q = q.where(SecurityEvent.source == source)
    rows = db.execute(q.order_by(SecurityEvent.ts.desc(), SecurityEvent.id.desc()).limit(limit)).all()
    return [{"domain": d, "t": e.ts.isoformat() + "Z", "ip": e.ip, "country": e.country, "method": e.method,
             "host": e.host, "path": e.path, "action": e.action, "source": e.source, "rule": e.rule,
             "user_agent": e.user_agent} for e, d in rows]
