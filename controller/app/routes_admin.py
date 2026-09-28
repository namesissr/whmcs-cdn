"""API used by the WHMCS module (and by admins)."""

import ipaddress
import json
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from . import nscheck, pdns, sections
from .auth import hash_token, new_token, require_admin
from .config import settings
from .db import get_db
from .models import Edge, Record, Site, UsageHourly, utcnow
from .services import (
    refresh_quota,
    month_start,
    queue_purge,
    record_to_dict,
    site_to_dict,
    sync_all_dns,
    sync_site_dns,
    usage_totals,
)
from .validation import (
    ValidationError,
    normalize_domain,
    normalize_name,
    validate_ip,
    validate_record,
)

router = APIRouter(prefix="/api/v1", dependencies=[Depends(require_admin)])


def bad(e: Exception):
    raise HTTPException(422, str(e))


def get_site(db: Session, domain: str) -> Site:
    try:
        d = normalize_domain(domain)
    except ValidationError as e:
        bad(e)
    site = db.scalar(select(Site).where(Site.domain == d))
    if site is None:
        raise HTTPException(404, "site not found")
    return site


class FeaturesIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    waf: bool | None = None
    ddos: bool | None = None
    load_balancer: bool | None = None
    image_optimization: bool | None = None
    custom_ssl: bool | None = None
    dnssec: bool | None = None
    max_page_rules: int | None = Field(default=None, ge=0, le=1000)
    max_firewall_rules: int | None = Field(default=None, ge=0, le=1000)
    max_ratelimit_rules: int | None = Field(default=None, ge=0, le=1000)
    max_pools: int | None = Field(default=None, ge=0, le=100)


class Plan(BaseModel):
    bandwidth_limit_gb: int | None = Field(default=None, ge=0)
    max_records: int | None = Field(default=None, ge=1, le=10000)
    ssl_allowed: bool | None = None
    rate_limit_rps: int | None = Field(default=None, ge=0, le=100000)
    features: FeaturesIn | None = None


class SiteCreate(BaseModel):
    domain: str
    external_id: str | None = None
    origin_ip: str | None = None  # optional: creates proxied @ and www records
    plan: Plan = Plan()


class SiteSettings(BaseModel):
    cache_enabled: bool | None = None
    dev_mode: bool | None = None
    force_https: bool | None = None
    origin_protocol: str | None = Field(default=None, pattern="^(http|https)$")
    edge_cache_ttl: int | None = Field(default=None, ge=0, le=31536000)
    browser_cache_ttl: int | None = Field(default=None, ge=0, le=31536000)
    blocked_ips: list[str] | None = None


class RecordIn(BaseModel):
    name: str = "@"
    type: str
    content: str
    ttl: int = Field(default=300, ge=60, le=86400)
    priority: int | None = None
    proxied: bool = False
    pool: str | None = Field(default=None, pattern=r"^[a-z0-9_-]{1,32}$")
    origin_port: int | None = Field(default=None, ge=1, le=65535)
    health_check: bool = False
    health_port: int | None = Field(default=None, ge=1, le=65535)


class PurgeIn(BaseModel):
    urls: list[str] = []


class EdgeIn(BaseModel):
    name: str = Field(pattern=r"^[a-zA-Z0-9_.-]{1,64}$")
    ipv4: str
    ipv6: str | None = None
    region: str = Field(default="global", pattern="^(home|global)$")


def apply_plan(site: Site, plan: Plan):
    data = plan.model_dump(exclude_none=True)
    feats = data.pop("features", None)
    for k, v in data.items():
        setattr(site, k, v)
    if feats:
        site.features = json.dumps({**sections.features_of(site), **feats})
    if not sections.features_of(site)["custom_ssl"] and site.ssl_source == "custom":
        site.ssl_status, site.ssl_cert, site.ssl_key, site.ssl_expires_at = "none", None, None, None
        site.ssl_source = None
    if not site.ssl_allowed and site.ssl_status != "none":
        site.ssl_status, site.ssl_cert, site.ssl_key, site.ssl_expires_at = "none", None, None, None
    elif site.ssl_allowed and site.ssl_status == "none" and site.ns_verified_at:
        site.ssl_status = "pending"


# ------------------------------------------------------------------ misc

@router.get("/ping")
def ping(db: Session = Depends(get_db)):
    return {
        "ok": True,
        "sites": db.scalar(select(func.count(Site.id))),
        "edges": db.scalar(select(func.count(Edge.id))),
        "nameservers": settings.nameservers,
    }


# ------------------------------------------------------------------ sites

@router.post("/sites", status_code=201)
def create_site(body: SiteCreate, db: Session = Depends(get_db)):
    try:
        domain = normalize_domain(body.domain)
        origin = validate_ip(body.origin_ip, 4) if body.origin_ip else None
    except ValidationError as e:
        bad(e)
    if db.scalar(select(Site).where(Site.domain == domain)):
        raise HTTPException(409, "این دامنه قبلاً ثبت شده است")
    site = Site(domain=domain, external_id=body.external_id)
    apply_plan(site, body.plan)
    if origin:
        site.records = [
            Record(name="@", type="A", content=origin, ttl=300, proxied=True),
            Record(name="www", type="CNAME", content=domain, ttl=300, proxied=True),
        ]
    db.add(site)
    db.commit()
    err = sync_site_dns(db, site)
    return {**site_to_dict(db, site), "dns_error": err}


@router.get("/sites")
def list_sites(db: Session = Depends(get_db)):
    return [
        {"domain": s.domain, "status": s.effective_status, "external_id": s.external_id}
        for s in db.scalars(select(Site).order_by(Site.id))
    ]


@router.get("/sites/{domain}")
def read_site(domain: str, db: Session = Depends(get_db)):
    return site_to_dict(db, get_site(db, domain))


@router.patch("/sites/{domain}/plan")
def update_plan(domain: str, plan: Plan, db: Session = Depends(get_db)):
    site = get_site(db, domain)
    apply_plan(site, plan)
    # a raised/lowered bandwidth limit takes effect now, not on the next scheduler tick
    refresh_quota(db, site)
    db.commit()
    return site_to_dict(db, site)


@router.patch("/sites/{domain}/settings")
def update_settings(domain: str, body: SiteSettings, db: Session = Depends(get_db)):
    """v1 settings endpoint; values are written into the cache/ssl sections."""
    site = get_site(db, domain)
    data = body.model_dump(exclude_none=True)
    if "blocked_ips" in data:
        ips = []
        for raw in data.pop("blocked_ips"):
            raw = raw.strip()
            if not raw:
                continue
            try:
                ips.append(str(ipaddress.ip_network(raw, strict=False)))
            except ValueError:
                bad(ValidationError(f"IP نامعتبر: {raw}"))
        if len(ips) > 1000:
            bad(ValidationError("حداکثر ۱۰۰۰ آدرس"))
        site.blocked_ips = json.dumps(sorted(set(ips)))
    cache, ssl_opts = sections.get_section(site, "cache"), sections.get_section(site, "ssl")
    mapping = {"cache_enabled": (cache, "enabled"), "dev_mode": (cache, "dev_mode"),
               "edge_cache_ttl": (cache, "edge_ttl"), "browser_cache_ttl": (cache, "browser_ttl"),
               "force_https": (ssl_opts, "force_https"), "origin_protocol": (ssl_opts, "origin_protocol")}
    for k, v in data.items():
        target, key = mapping[k]
        target[key] = max(v, 60) if key == "edge_ttl" else v
    for name, value in (("cache", cache), ("ssl", ssl_opts)):
        sections.store_section(site, name, sections.validate_section(site, name, value))
    db.commit()
    return site_to_dict(db, site)


@router.post("/sites/{domain}/suspend")
def suspend(domain: str, db: Session = Depends(get_db)):
    site = get_site(db, domain)
    site.suspended = True
    db.commit()
    return {"ok": True}


@router.post("/sites/{domain}/unsuspend")
def unsuspend(domain: str, db: Session = Depends(get_db)):
    site = get_site(db, domain)
    site.suspended = False
    db.commit()
    return {"ok": True}


@router.delete("/sites/{domain}")
def delete_site(domain: str, db: Session = Depends(get_db)):
    site = get_site(db, domain)
    name = site.domain
    db.delete(site)
    db.commit()
    if settings.pdns_enabled:
        try:
            pdns.client().delete_zone(name)
        except Exception as e:  # noqa: BLE001
            return {"ok": True, "dns_error": str(e)}
    return {"ok": True}


@router.post("/sites/{domain}/ns-check")
def ns_check(domain: str, db: Session = Depends(get_db)):
    site = get_site(db, domain)
    ok, found = nscheck.check_and_update(site)
    db.commit()
    return {"ok": ok, "found": found, "expected": settings.nameservers, "status": site.effective_status}


@router.post("/sites/{domain}/ssl")
def request_ssl(domain: str, db: Session = Depends(get_db)):
    site = get_site(db, domain)
    if not site.ssl_allowed:
        raise HTTPException(403, "SSL در این پلن فعال نیست")
    if site.ns_verified_at is None:
        raise HTTPException(409, "ابتدا نیم‌سرورهای دامنه را تغییر دهید")
    if site.ssl_source == "custom" and site.ssl_status == "active":
        raise HTTPException(409, "ابتدا گواهی اختصاصی را حذف کنید")
    if site.ssl_status != "pending":
        site.ssl_status, site.ssl_error = "pending", None
        db.commit()
    return {"ok": True, "status": site.ssl_status}


@router.post("/sites/{domain}/purge")
def purge(domain: str, body: PurgeIn, db: Session = Depends(get_db)):
    site = get_site(db, domain)
    urls = [u.strip() for u in body.urls if u.strip()]
    if len(urls) > 100:
        bad(ValidationError("حداکثر ۱۰۰ آدرس در هر درخواست"))
    for u in urls:
        if not u.startswith(("http://", "https://")):
            bad(ValidationError(f"آدرس باید کامل باشد: {u}"))
    queue_purge(db, site, urls)
    db.commit()
    return {"ok": True, "queued": len(urls) or "all"}


@router.get("/sites/{domain}/usage")
def site_usage(domain: str, days: int = 30, db: Session = Depends(get_db)):
    site = get_site(db, domain)
    days = max(1, min(days, 366))
    since = utcnow().replace(minute=0, second=0, microsecond=0) - timedelta(days=days)
    rows = db.execute(
        select(func.date(UsageHourly.hour), func.sum(UsageHourly.bytes), func.sum(UsageHourly.requests),
               func.sum(UsageHourly.cache_hits))
        .where(UsageHourly.site_id == site.id, UsageHourly.hour >= since)
        .group_by(func.date(UsageHourly.hour)).order_by(func.date(UsageHourly.hour))
    ).all()
    return {
        "month": usage_totals(db, site.id, month_start()),
        "daily": [{"date": str(d), "bytes": int(b or 0), "requests": int(r or 0), "cache_hits": int(h or 0)}
                  for d, b, r, h in rows],
    }


@router.get("/usage")
def all_usage(month: str | None = None, db: Session = Depends(get_db)):
    """Monthly bandwidth for every site — used by WHMCS UsageUpdate."""
    if month:
        try:
            start = datetime.strptime(month, "%Y-%m")
        except ValueError:
            bad(ValidationError("month must be YYYY-MM"))
    else:
        start = month_start()
    end = (start.replace(day=28) + timedelta(days=4)).replace(day=1)
    out = []
    for s in db.scalars(select(Site).order_by(Site.id)):
        u = usage_totals(db, s.id, start, end)
        out.append({"domain": s.domain, "external_id": s.external_id, "bandwidth_limit_gb": s.bandwidth_limit_gb,
                    "status": s.effective_status, **u})
    return {"month": start.strftime("%Y-%m"), "sites": out}


# ------------------------------------------------------------------ records

def _conflicts(site: Site, name: str, rtype: str, exclude_id: int | None = None):
    others = [r for r in site.records if r.name == name and r.id != exclude_id]
    if rtype == "CNAME" and others:
        raise ValidationError("رکورد CNAME نمی‌تواند با رکورد دیگری هم‌نام باشد")
    if any(r.type == "CNAME" for r in others):
        raise ValidationError("برای این نام یک رکورد CNAME وجود دارد")
    # ALIAS answers A/AAAA itself, so it cannot share a name with address records
    address = {"A", "AAAA", "ALIAS"}
    if rtype in address and any(r.type in address and (r.type == "ALIAS" or rtype == "ALIAS") for r in others):
        raise ValidationError("رکورد ALIAS نمی‌تواند با رکورد A/AAAA هم‌نام باشد")


def _record_from(site: Site, body: RecordIn, exclude_id: int | None = None) -> dict:
    name = normalize_name(body.name, site.domain)
    rtype, content, prio, proxied = validate_record(body.type, body.content, body.priority, body.proxied)
    if rtype == "CNAME" and name == "@" and not proxied:
        raise ValidationError("CNAME روی ریشه دامنه فقط در حالت پروکسی (CDN) مجاز است؛ از ALIAS استفاده کنید")
    if rtype == "NS" and name == "@":
        raise ValidationError("نیم‌سرورهای ریشه به‌صورت خودکار مدیریت می‌شوند")
    _conflicts(site, name, rtype, exclude_id)
    pool = body.pool if proxied else None
    if pool:
        if not sections.features_of(site)["load_balancer"]:
            raise PermissionError("توزیع بار در پلن شما فعال نیست")
        if pool not in {p["name"] for p in sections.get_section(site, "pools")["pools"]}:
            raise ValidationError(f"استخر {pool} تعریف نشده است")
    health = body.health_check and not proxied and rtype in ("A", "AAAA")
    return {
        "name": name, "type": rtype, "content": content, "priority": prio, "proxied": proxied, "ttl": body.ttl,
        "pool": pool,
        "origin_port": body.origin_port if proxied and not pool else None,
        "health_check": health,
        "health_port": body.health_port if health else None,
    }


def _record_or_error(site: Site, body: RecordIn, exclude_id: int | None = None) -> dict:
    try:
        return _record_from(site, body, exclude_id)
    except ValidationError as e:
        bad(e)
    except PermissionError as e:
        raise HTTPException(403, str(e))


@router.get("/sites/{domain}/records")
def list_records(domain: str, db: Session = Depends(get_db)):
    return [record_to_dict(r) for r in get_site(db, domain).records]


@router.post("/sites/{domain}/records", status_code=201)
def add_record(domain: str, body: RecordIn, db: Session = Depends(get_db)):
    site = get_site(db, domain)
    if len(site.records) >= site.max_records:
        raise HTTPException(403, f"سقف تعداد رکوردها ({site.max_records}) پر شده است")
    rec = Record(**_record_or_error(site, body))
    site.records.append(rec)
    db.commit()
    return {**record_to_dict(rec), "dns_error": sync_site_dns(db, site)}


@router.put("/sites/{domain}/records/{record_id}")
def update_record(domain: str, record_id: int, body: RecordIn, db: Session = Depends(get_db)):
    site = get_site(db, domain)
    rec = next((r for r in site.records if r.id == record_id), None)
    if rec is None:
        raise HTTPException(404, "record not found")
    for k, v in _record_or_error(site, body, exclude_id=rec.id).items():
        setattr(rec, k, v)
    db.commit()
    return {**record_to_dict(rec), "dns_error": sync_site_dns(db, site)}


@router.delete("/sites/{domain}/records/{record_id}")
def delete_record(domain: str, record_id: int, db: Session = Depends(get_db)):
    site = get_site(db, domain)
    rec = next((r for r in site.records if r.id == record_id), None)
    if rec is None:
        raise HTTPException(404, "record not found")
    site.records.remove(rec)
    db.commit()
    return {"ok": True, "dns_error": sync_site_dns(db, site)}


@router.post("/sites/{domain}/dns-sync")
def dns_sync(domain: str, db: Session = Depends(get_db)):
    site = get_site(db, domain)
    err = sync_site_dns(db, site)
    return {"ok": err is None, "error": err}


# ------------------------------------------------------------------ edges

def edge_to_dict(e: Edge) -> dict:
    return {
        "id": e.id, "name": e.name, "ipv4": e.ipv4, "ipv6": e.ipv6, "region": e.region,
        "enabled": e.enabled, "last_seen_at": e.last_seen_at.isoformat() + "Z" if e.last_seen_at else None,
        "applied_version": e.applied_version, "last_error": e.last_error,
    }


@router.get("/edges")
def list_edges(db: Session = Depends(get_db)):
    return [edge_to_dict(e) for e in db.scalars(select(Edge).order_by(Edge.id))]


@router.post("/edges", status_code=201)
def create_edge(body: EdgeIn, db: Session = Depends(get_db)):
    try:
        ipv4 = validate_ip(body.ipv4, 4)
        ipv6 = validate_ip(body.ipv6, 6) if body.ipv6 else None
    except ValidationError as e:
        bad(e)
    if db.scalar(select(Edge).where(Edge.name == body.name)):
        raise HTTPException(409, "edge name exists")
    token = new_token()
    edge = Edge(name=body.name, ipv4=ipv4, ipv6=ipv6, region=body.region, token_hash=hash_token(token))
    db.add(edge)
    db.commit()
    # DNS changes once the edge sends its first heartbeat
    return {**edge_to_dict(edge), "token": token}


@router.post("/edges/{edge_id}/rotate-token")
def rotate_edge_token(edge_id: int, db: Session = Depends(get_db)):
    edge = db.get(Edge, edge_id)
    if edge is None:
        raise HTTPException(404, "edge not found")
    token = new_token()
    edge.token_hash = hash_token(token)
    db.commit()
    return {"token": token}


@router.patch("/edges/{edge_id}")
def toggle_edge(edge_id: int, enabled: bool, db: Session = Depends(get_db)):
    edge = db.get(Edge, edge_id)
    if edge is None:
        raise HTTPException(404, "edge not found")
    edge.enabled = enabled
    db.commit()
    return {"ok": True, "dns_failed": sync_all_dns(db)}


@router.delete("/edges/{edge_id}")
def delete_edge(edge_id: int, db: Session = Depends(get_db)):
    edge = db.get(Edge, edge_id)
    if edge is None:
        raise HTTPException(404, "edge not found")
    db.delete(edge)
    db.commit()
    return {"ok": True, "dns_failed": sync_all_dns(db)}
