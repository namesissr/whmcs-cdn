"""API used by the WHMCS module (and by admins)."""

import ipaddress
import json
from datetime import datetime, timedelta
from typing import Literal

from fastapi import APIRouter, Body, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from . import bundle, dnsbuild, nscheck, pdns, sections, webhooks
from .audit import record_audit
from .auth import hash_token, new_capi_key, new_token, require_admin
from .config import settings
from .db import get_db
from .models import ApiKey, AuditLog, Edge, EdgeAddress, Record, Site, UsageHourly, utcnow
from .services import (
    delete_platform_data,
    lock_site,
    refresh_quota,
    month_start,
    queue_purge,
    record_to_dict,
    edge_capabilities,
    edge_metrics,
    site_to_dict,
    sync_all_dns,
    sync_site_dns,
    update_shed,
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


def _client_ip(request: Request | None) -> str | None:
    return request.client.host if request is not None and request.client else None


def _audit(db: Session, request: Request | None, action: str, target: str | None = None,
           detail: dict | None = None) -> None:
    """Record an admin mutation (SPEC §13.2). The admin surface has a single key, so the actor
    label is simply "admin"; secrets are stripped by record_audit."""
    record_audit(db, actor="admin", actor_kind="admin", action=action, target=target,
                 detail=detail, ip=_client_ip(request))


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
    tunnel: bool | None = None
    max_tunnel_paths: int | None = Field(default=None, ge=0, le=50)
    max_tunnel_connections: int | None = Field(default=None, ge=0, le=1000000)
    tunnel_max_mbps: int | None = Field(default=None, ge=0, le=100000)
    edge_group: Literal["general", "tunnel"] | None = None
    max_transform_rules: int | None = Field(default=None, ge=0, le=1000)
    max_redirects: int | None = Field(default=None, ge=0, le=10000)
    # analytics & platform (SPEC §14.3)
    log_export: bool | None = None
    max_webhooks: int | None = Field(default=None, ge=0, le=sections.WEBHOOKS_MAX)
    sla_target: float | None = Field(default=None, ge=0, le=100)


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
    # reseller sub-site tag (SPEC §10.5), set by WHMCS
    reseller_client_id: int | None = Field(default=None, ge=1)
    reseller_label: str | None = None


class ResellerIn(BaseModel):
    """Set or clear the reseller tag on a site; pass null to clear a field."""
    model_config = ConfigDict(extra="forbid")
    reseller_client_id: int | None = Field(default=None, ge=1)
    reseller_label: str | None = None


def _clean_label(label: str | None) -> str | None:
    if label is None:
        return None
    label = label.strip()[:120]
    return label or None


def _clean_addr_label(label: str | None) -> str:
    """Edge-address label: stored as "" when absent (SPEC §12.1, String(64))."""
    return (label or "").strip()[:64]


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
    prefixes: list[str] = []
    everything: bool = False


class EdgeIn(BaseModel):
    name: str = Field(pattern=r"^[a-zA-Z0-9_.-]{1,64}$")
    ipv4: str
    ipv6: str | None = None
    region: str = Field(default="global", pattern="^(home|global)$")
    group: Literal["general", "tunnel"] = "general"
    capacity_mbps: int = Field(default=0, ge=0, le=10_000_000)  # 0 = unknown (never shed)
    shield: bool = False  # origin shield / tiered cache node (SPEC §14.1)


class EdgePatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool | None = None
    group: Literal["general", "tunnel"] | None = None
    capacity_mbps: int | None = Field(default=None, ge=0, le=10_000_000)
    region: str | None = Field(default=None, pattern="^(home|global)$")
    shield: bool | None = None  # origin shield / tiered cache node (SPEC §14.1)


class EdgeAddressIn(BaseModel):
    """Add an additional address to an edge (SPEC §12.4)."""
    model_config = ConfigDict(extra="forbid")
    family: Literal[4, 6]
    ip: str
    label: str | None = None


class EdgeAddressPatch(BaseModel):
    """Edit / enable / disable an additional address (SPEC §12.4). The family is fixed."""
    model_config = ConfigDict(extra="forbid")
    ip: str | None = None
    label: str | None = None
    enabled: bool | None = None


class EdgeBatchIn(BaseModel):
    """Batch-create N edges in one call (SPEC §11.1)."""
    model_config = ConfigDict(extra="forbid")
    count: int = Field(ge=1, le=50)
    region: str = Field(default="global", pattern="^(home|global)$")
    group: Literal["general", "tunnel"] = "general"
    name_prefix: str = Field(default="edge", pattern=r"^[a-zA-Z0-9_.-]{1,48}$")
    capacity_mbps: int = Field(default=0, ge=0, le=10_000_000)


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
def create_site(body: SiteCreate, request: Request, db: Session = Depends(get_db)):
    try:
        domain = normalize_domain(body.domain)
        origin = validate_ip(body.origin_ip, 4) if body.origin_ip else None
    except ValidationError as e:
        bad(e)
    if db.scalar(select(Site).where(Site.domain == domain)):
        raise HTTPException(409, "این دامنه قبلاً ثبت شده است")
    site = Site(domain=domain, external_id=body.external_id,
                reseller_client_id=body.reseller_client_id,
                reseller_label=_clean_label(body.reseller_label))
    apply_plan(site, body.plan)
    if origin:
        site.records = [
            Record(name="@", type="A", content=origin, ttl=300, proxied=True),
            Record(name="www", type="CNAME", content=domain, ttl=300, proxied=True),
        ]
    db.add(site)
    db.commit()
    _audit(db, request, "site.create", site.domain,
           {"external_id": body.external_id, "reseller_client_id": body.reseller_client_id})
    err = sync_site_dns(db, site)
    return {**site_to_dict(db, site), "dns_error": err}


@router.get("/sites")
def list_sites(reseller: int | None = None, db: Session = Depends(get_db)):
    stmt = select(Site).order_by(Site.id)
    if reseller is not None:
        # rolled-up report for one reseller (SPEC §10.5): only its sub-sites
        stmt = stmt.where(Site.reseller_client_id == reseller)
        return [
            {"domain": s.domain, "reseller_label": s.reseller_label, "status": s.effective_status,
             "bandwidth_limit_gb": s.bandwidth_limit_gb, "over_quota": s.over_quota,
             "suspended": s.suspended}
            for s in db.scalars(stmt)
        ]
    return [
        {"domain": s.domain, "status": s.effective_status, "external_id": s.external_id,
         "reseller_client_id": s.reseller_client_id, "reseller_label": s.reseller_label}
        for s in db.scalars(stmt)
    ]


@router.get("/sites/{domain}")
def read_site(domain: str, db: Session = Depends(get_db)):
    return site_to_dict(db, get_site(db, domain))


@router.patch("/sites/{domain}/plan")
def update_plan(domain: str, plan: Plan, request: Request, db: Session = Depends(get_db)):
    site = lock_site(db, get_site(db, domain))  # read-modify-write of site.features
    group = sections.features_of(site)["edge_group"]
    apply_plan(site, plan)
    # a raised/lowered bandwidth limit takes effect now, not on the next scheduler tick
    refresh_quota(db, site)
    db.commit()
    _audit(db, request, "site.plan", site.domain, plan.model_dump(exclude_none=True))
    if sections.features_of(site)["edge_group"] != group:
        sync_site_dns(db, site)  # the site is now answered by the other group of edges
    return site_to_dict(db, site)


@router.patch("/sites/{domain}/reseller")
def update_reseller(domain: str, body: ResellerIn, request: Request, db: Session = Depends(get_db)):
    """Set or clear the reseller tag on a site (SPEC §10.5). Only provided fields change;
    pass an explicit null to clear one."""
    site = get_site(db, domain)
    fields = body.model_fields_set
    if "reseller_client_id" in fields:
        site.reseller_client_id = body.reseller_client_id
    if "reseller_label" in fields:
        site.reseller_label = _clean_label(body.reseller_label)
    db.commit()
    _audit(db, request, "reseller.flag", site.domain,
           {"reseller_client_id": site.reseller_client_id, "reseller_label": site.reseller_label})
    return site_to_dict(db, site)


@router.patch("/sites/{domain}/settings")
def update_settings(domain: str, body: SiteSettings, db: Session = Depends(get_db)):
    """v1 settings endpoint; values are written into the cache/ssl sections."""
    site = lock_site(db, get_site(db, domain))  # read-modify-write of site.config
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
    site = lock_site(db, get_site(db, domain))  # one webhook per transition, also when concurrent
    if not site.suspended:  # webhook on the transition only (SPEC §14.3.3)
        webhooks.emit(db, site, "site.suspended", {"status": "suspended"})
    site.suspended = True
    db.commit()
    return {"ok": True}


@router.post("/sites/{domain}/unsuspend")
def unsuspend(domain: str, db: Session = Depends(get_db)):
    site = lock_site(db, get_site(db, domain))
    if site.suspended:
        site.suspended = False
        webhooks.emit(db, site, "site.unsuspended", {"status": site.effective_status})
    db.commit()
    return {"ok": True}


@router.delete("/sites/{domain}")
def delete_site(domain: str, request: Request, db: Session = Depends(get_db)):
    site = get_site(db, domain)
    name = site.domain
    delete_platform_data(db, site.id)
    db.delete(site)
    db.commit()
    _audit(db, request, "site.delete", name)
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


def purge_site(db: Session, site: Site, body: PurgeIn) -> dict:
    """Shared purge validation + queueing (SPEC §9.2), used by the admin and customer APIs."""
    urls = [u.strip() for u in body.urls if u.strip()]
    prefixes = [p.strip() for p in body.prefixes if p.strip()]
    if len(urls) + len(prefixes) > 100:
        bad(ValidationError("حداکثر ۱۰۰ مورد در هر درخواست"))
    if len(prefixes) > 20:
        bad(ValidationError("حداکثر ۲۰ پیشوند در هر درخواست"))
    for u in urls:
        if not u.startswith(("http://", "https://")):
            bad(ValidationError(f"آدرس باید کامل باشد: {u}"))
    for p in prefixes:
        if len(p) > 200:
            bad(ValidationError(f"پیشوند باید حداکثر ۲۰۰ نویسه باشد: {p}"))
        # a prefix is a path ("/blog/") or a full address ("https://ex.com/img/")
        if not (p.startswith("/") or p.startswith(("http://", "https://"))):
            bad(ValidationError(f"پیشوند باید با / یا آدرس کامل شروع شود: {p}"))
    queue_purge(db, site, urls, prefixes, body.everything)
    db.commit()
    return {"ok": True, "queued": (len(urls) + len(prefixes)) or "all"}


@router.post("/sites/{domain}/purge")
def purge(domain: str, body: PurgeIn, request: Request, db: Session = Depends(get_db)):
    site = get_site(db, domain)
    result = purge_site(db, site, body)
    _audit(db, request, "purge", site.domain,
           {"everything": body.everything, "urls": len(body.urls), "prefixes": len(body.prefixes)})
    return result


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


# ------------------------------------------------------------------ customer API keys (SPEC §10.1)

CAPI_SCOPES = ("purge", "stats", "dns")
MAX_API_KEYS = 5


class ApiKeyIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=64)
    scopes: list[str] = Field(min_length=1)


def api_key_dict(k: ApiKey) -> dict:
    """Public view of an ApiKey — never includes the key itself."""
    return {
        "id": k.id, "name": k.name, "scopes": k.scope_list,
        "last_used_at": k.last_used_at.isoformat() + "Z" if k.last_used_at else None,
        "created_at": k.created_at.isoformat() + "Z" if k.created_at else None,
        "revoked": k.revoked,
    }


@router.get("/sites/{domain}/apikeys")
def list_api_keys(domain: str, db: Session = Depends(get_db)):
    site = get_site(db, domain)
    keys = db.scalars(select(ApiKey).where(ApiKey.site_id == site.id).order_by(ApiKey.id))
    return [api_key_dict(k) for k in keys]


@router.post("/sites/{domain}/apikeys", status_code=201)
def create_api_key(domain: str, body: ApiKeyIn, db: Session = Depends(get_db)):
    site = get_site(db, domain)
    scopes = []
    for s in body.scopes:
        if s not in CAPI_SCOPES:
            bad(ValidationError(f"دسترسی نامعتبر: {s} (مجاز: {'، '.join(CAPI_SCOPES)})"))
        if s not in scopes:
            scopes.append(s)
    active = db.scalar(select(func.count(ApiKey.id)).where(
        ApiKey.site_id == site.id, ApiKey.revoked.is_(False)))
    if active >= MAX_API_KEYS:
        raise HTTPException(403, f"حداکثر {MAX_API_KEYS} کلید فعال برای هر سرویس مجاز است")
    plaintext = new_capi_key()
    key = ApiKey(site_id=site.id, key_hash=hash_token(plaintext), name=body.name.strip(),
                 scopes=json.dumps(scopes))
    db.add(key)
    db.commit()
    # the plaintext key is returned ONCE and never stored or shown again
    return {**api_key_dict(key), "key": plaintext}


@router.delete("/sites/{domain}/apikeys/{key_id}")
def revoke_api_key(domain: str, key_id: int, db: Session = Depends(get_db)):
    site = get_site(db, domain)
    key = db.scalar(select(ApiKey).where(ApiKey.id == key_id, ApiKey.site_id == site.id))
    if key is None:
        raise HTTPException(404, "کلید یافت نشد")
    key.revoked = True
    db.commit()
    return {"ok": True}


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


# record handlers factored so the admin and customer APIs share identical validation/logic

def list_records_of(site: Site) -> list[dict]:
    return [record_to_dict(r) for r in site.records]


def add_record_of(db: Session, site: Site, body: RecordIn) -> dict:
    if len(site.records) >= site.max_records:
        raise HTTPException(403, f"سقف تعداد رکوردها ({site.max_records}) پر شده است")
    rec = Record(**_record_or_error(site, body))
    site.records.append(rec)
    db.commit()
    return {**record_to_dict(rec), "dns_error": sync_site_dns(db, site)}


def update_record_of(db: Session, site: Site, record_id: int, body: RecordIn) -> dict:
    rec = next((r for r in site.records if r.id == record_id), None)
    if rec is None:
        raise HTTPException(404, "record not found")
    for k, v in _record_or_error(site, body, exclude_id=rec.id).items():
        setattr(rec, k, v)
    db.commit()
    return {**record_to_dict(rec), "dns_error": sync_site_dns(db, site)}


def delete_record_of(db: Session, site: Site, record_id: int) -> dict:
    rec = next((r for r in site.records if r.id == record_id), None)
    if rec is None:
        raise HTTPException(404, "record not found")
    site.records.remove(rec)
    db.commit()
    return {"ok": True, "dns_error": sync_site_dns(db, site)}


@router.get("/sites/{domain}/records")
def list_records(domain: str, db: Session = Depends(get_db)):
    return list_records_of(get_site(db, domain))


@router.post("/sites/{domain}/records", status_code=201)
def add_record(domain: str, body: RecordIn, db: Session = Depends(get_db)):
    return add_record_of(db, get_site(db, domain), body)


@router.put("/sites/{domain}/records/{record_id}")
def update_record(domain: str, record_id: int, body: RecordIn, db: Session = Depends(get_db)):
    return update_record_of(db, get_site(db, domain), record_id, body)


@router.delete("/sites/{domain}/records/{record_id}")
def delete_record(domain: str, record_id: int, db: Session = Depends(get_db)):
    return delete_record_of(db, get_site(db, domain), record_id)


@router.post("/sites/{domain}/dns-sync")
def dns_sync(domain: str, db: Session = Depends(get_db)):
    site = get_site(db, domain)
    err = sync_site_dns(db, site)
    return {"ok": err is None, "error": err}


# ------------------------------------------------------------------ edges

def _probe_dict(ok, ms, at, error) -> dict:
    return {"ok": ok, "ms": ms, "at": at.isoformat() + "Z" if at else None, "error": error}


def address_to_dict(a: EdgeAddress) -> dict:
    """One additional address with its per-address health and current DNS-advertise state (§12)."""
    return {
        "id": a.id, "family": a.family, "ip": a.ip, "label": a.label, "enabled": a.enabled,
        "primary": False,
        "advertised": dnsbuild.address_advertised(a.enabled, a.probe_ok, a.probe_fail),
        "probe": _probe_dict(a.probe_ok, a.probe_ms, a.probe_at, a.probe_error),
    }


def _advertised_counts(e: Edge) -> dict:
    """How many addresses of each family are currently advertised in DNS (primary + additional).

    Per-address health only; the DNS fail-open (dnsbuild.edge_pools) can still advertise a
    withdrawn address when a pool would otherwise be empty.
    """
    counts = {"4": 0, "6": 0}
    # F32: each primary family advertises on its own probe state
    if e.ipv4 and dnsbuild.address_advertised(True, e.probe_ok4, e.probe_fail4):
        counts["4"] += 1
    if e.ipv6 and dnsbuild.address_advertised(True, e.probe_ok6, e.probe_fail6):
        counts["6"] += 1
    for a in e.addresses:
        if dnsbuild.address_advertised(a.enabled, a.probe_ok, a.probe_fail):
            counts["6" if a.family == 6 else "4"] += 1
    return counts


def edge_to_dict(e: Edge, uptime: dict | None = None) -> dict:
    return {
        "id": e.id, "name": e.name, "ipv4": e.ipv4, "ipv6": e.ipv6, "region": e.region,
        "enabled": e.enabled, "last_seen_at": e.last_seen_at.isoformat() + "Z" if e.last_seen_at else None,
        "applied_version": e.applied_version, "last_error": e.last_error,
        "group": e.group, "capacity_mbps": e.capacity_mbps, "metrics": edge_metrics(e), "shed": e.shed,
        "uptime": uptime if uptime is not None else {"h24": None, "d30": None},
        "probe": {"ok": e.probe_ok, "ms": e.probe_ms,
                  "at": e.probe_at.isoformat() + "Z" if e.probe_at else None, "error": e.probe_error},
        # additional addresses + per-family advertised counts (multi-address failover, SPEC §12)
        "addresses": [address_to_dict(a) for a in e.addresses],
        "advertised": _advertised_counts(e),
        # centralized logs hint (SPEC §11.2): the full lines come from GET /edges/{id}/logs
        "logs_at": e.logs_at.isoformat() + "Z" if e.logs_at else None,
        "has_logs": bool(e.logs and e.logs not in ("[]", "null")),
        # running bundle version (SPEC §11.1); the panel compares it to GET /edge/version
        "bundle_version": e.bundle_version,
        # origin shield flag + heartbeat-reported node capabilities (SPEC §14.1); capabilities is
        # {"http3", "early_hints", "webp_convert", "modules"} or null when never reported
        "shield": e.shield,
        "capabilities": edge_capabilities(e),
    }


@router.get("/edges")
def list_edges(db: Session = Depends(get_db)):
    from . import uptime as up

    ups = up.summaries(db)
    return [edge_to_dict(e, ups.get(e.id)) for e in db.scalars(select(Edge).order_by(Edge.id))]


@router.get("/edges/{edge_id}/uptime")
def edge_uptime(edge_id: int, days: int = 30, db: Session = Depends(get_db)):
    from . import uptime as up

    if db.get(Edge, edge_id) is None:
        raise HTTPException(404, "edge not found")
    return up.daily(db, edge_id, days)


def _edge_install(edge: Edge, token: str) -> str:
    """The one-command install one-liner for this node (SPEC §11.1); role == edge group."""
    return bundle.install_command(token, region=edge.region, role=edge.group)


@router.post("/edges", status_code=201)
def create_edge(body: EdgeIn, request: Request, db: Session = Depends(get_db)):
    try:
        ipv4 = validate_ip(body.ipv4, 4)
        ipv6 = validate_ip(body.ipv6, 6) if body.ipv6 else None
    except ValidationError as e:
        bad(e)
    if db.scalar(select(Edge).where(Edge.name == body.name)):
        raise HTTPException(409, "edge name exists")
    token = new_token()
    edge = Edge(name=body.name, ipv4=ipv4, ipv6=ipv6, region=body.region, token_hash=hash_token(token),
                group=body.group, capacity_mbps=body.capacity_mbps, shield=body.shield)
    db.add(edge)
    db.commit()
    _audit(db, request, "edge.add", edge.name,
           {"region": edge.region, "group": edge.group, "capacity_mbps": edge.capacity_mbps,
            "shield": edge.shield})
    # DNS changes once the edge sends its first heartbeat
    return {**edge_to_dict(edge), "token": token, "install": _edge_install(edge, token)}


@router.post("/edges/batch", status_code=201)
def batch_create_edges(body: EdgeBatchIn, request: Request, db: Session = Depends(get_db)):
    """Create N edges in one call (SPEC §11.1). IPs are unknown at batch time (the node reports
    itself on first heartbeat); each edge gets a unique name and its one-time token + install
    one-liner. Names are name_prefix + index, skipping names already taken."""
    taken = {n for (n,) in db.execute(select(Edge.name)).all()}
    out = []
    idx = 1
    for _ in range(body.count):
        while f"{body.name_prefix}-{idx}" in taken:
            idx += 1
        name = f"{body.name_prefix}-{idx}"
        taken.add(name)
        idx += 1
        token = new_token()
        # ipv4 is filled in once the node heartbeats; 0.0.0.0 is a harmless placeholder (kept out of
        # DNS because it is not online). The operator can also set it from the panel.
        edge = Edge(name=name, ipv4="0.0.0.0", region=body.region, token_hash=hash_token(token),
                    group=body.group, capacity_mbps=body.capacity_mbps)
        db.add(edge)
        db.flush()
        out.append({**edge_to_dict(edge), "token": token, "install": _edge_install(edge, token)})
    db.commit()
    _audit(db, request, "edge.add", body.name_prefix,
           {"count": body.count, "region": body.region, "group": body.group})
    return {"edges": out}


@router.get("/edges/install")
def edge_install_oneliner(token: str, region: str = "global", role: str = "general"):
    """Ready copy-paste one-liner for a specific node/token (SPEC §11.1)."""
    region = region if region in ("home", "global") else "global"
    role = role if role in ("general", "tunnel") else "general"
    return {"command": bundle.install_command(token, region=region, role=role)}


@router.post("/edges/{edge_id}/rotate-token")
def rotate_edge_token(edge_id: int, request: Request, db: Session = Depends(get_db)):
    edge = db.get(Edge, edge_id)
    if edge is None:
        raise HTTPException(404, "edge not found")
    token = new_token()
    edge.token_hash = hash_token(token)
    db.commit()
    # the new token is NEVER written to the audit log
    _audit(db, request, "edge.rotate", edge.name)
    return {"token": token}


@router.patch("/edges/{edge_id}")
def update_edge(edge_id: int, request: Request, enabled: bool | None = None,
                body: EdgePatch | None = Body(default=None), db: Session = Depends(get_db)):
    """JSON body {enabled?, group?, capacity_mbps?, region?, shield?}; v1 clients send ?enabled=true|false.
    A shield change reaches the edges through their next config poll (SPEC §14.1)."""
    edge = db.get(Edge, edge_id)
    if edge is None:
        raise HTTPException(404, "edge not found")
    changes = body.model_dump(exclude_none=True) if body else {}
    if enabled is not None:
        changes.setdefault("enabled", enabled)
    if not changes:
        bad(ValidationError("هیچ تغییری ارسال نشده است"))
    for k, v in changes.items():
        setattr(edge, k, v)
    update_shed(edge)
    db.commit()
    _audit(db, request, "edge.patch", edge.name, {"fields": sorted(changes), **changes})
    return {"ok": True, "dns_failed": sync_all_dns(db), "edge": edge_to_dict(edge)}


@router.delete("/edges/{edge_id}")
def delete_edge(edge_id: int, request: Request, db: Session = Depends(get_db)):
    edge = db.get(Edge, edge_id)
    if edge is None:
        raise HTTPException(404, "edge not found")
    name = edge.name
    db.delete(edge)
    db.commit()
    _audit(db, request, "edge.delete", name)
    return {"ok": True, "dns_failed": sync_all_dns(db)}


@router.get("/edges/{edge_id}/logs")
def edge_logs(edge_id: int, db: Session = Depends(get_db)):
    """Centralized node logs (SPEC §11.2). `lines` are stored newest-last (as the ring keeps
    them); the UI shows them newest-first. Empty list when the node has reported none."""
    edge = db.get(Edge, edge_id)
    if edge is None:
        raise HTTPException(404, "edge not found")
    try:
        lines = json.loads(edge.logs) if edge.logs else []
        if not isinstance(lines, list):
            lines = []
    except (ValueError, TypeError):
        lines = []
    return {"name": edge.name, "logs_at": edge.logs_at.isoformat() + "Z" if edge.logs_at else None,
            "lines": lines}


# ------------------------------------------------------------------ edge addresses (SPEC §12)

def _get_edge(db: Session, edge_id: int) -> Edge:
    edge = db.get(Edge, edge_id)
    if edge is None:
        raise HTTPException(404, "edge not found")
    return edge


def _address_in_use(db: Session, ip: str, exclude_id: int | None = None) -> bool:
    """True when `ip` already belongs to ANY edge — a primary (ipv4/ipv6) or an additional
    address (SPEC §12.4: reject duplicates of any edge's address)."""
    if db.scalar(select(Edge.id).where(or_(Edge.ipv4 == ip, Edge.ipv6 == ip))) is not None:
        return True
    q = select(EdgeAddress.id).where(EdgeAddress.ip == ip)
    if exclude_id is not None:
        q = q.where(EdgeAddress.id != exclude_id)
    return db.scalar(q) is not None


def _primary_entry(e: Edge, family: int) -> dict | None:
    """The primary address of a family as an address entry (health = the edge-level probe)."""
    ip = e.ipv4 if family == 4 else e.ipv6
    if not ip:
        return None
    return {
        "id": None, "family": family, "ip": ip, "label": "primary", "enabled": True, "primary": True,
        "advertised": dnsbuild.address_advertised(True, e.probe_ok, e.probe_fail),
        "probe": _probe_dict(e.probe_ok, e.probe_ms, e.probe_at, e.probe_error),
    }


@router.get("/edges/{edge_id}/addresses")
def list_edge_addresses(edge_id: int, db: Session = Depends(get_db)):
    """Primary + additional addresses with per-address health (SPEC §12.4). The primary is the
    node's identity address (edges.ipv4/ipv6) and cannot be deleted; correct it via PATCH
    /api/v1/edges/{id}."""
    edge = _get_edge(db, edge_id)
    return {
        "edge_id": edge.id, "name": edge.name,
        "primary": [p for p in (_primary_entry(edge, 4), _primary_entry(edge, 6)) if p],
        "additional": [address_to_dict(a) for a in edge.addresses],
        "advertised": _advertised_counts(edge),
    }


@router.post("/edges/{edge_id}/addresses", status_code=201)
def add_edge_address(edge_id: int, body: EdgeAddressIn, request: Request, db: Session = Depends(get_db)):
    """Add an additional address to a node (SPEC §12.4). Validated, family-matched, and rejected
    when the address already belongs to any edge."""
    edge = _get_edge(db, edge_id)
    try:
        ip = validate_ip(body.ip, body.family)
    except ValidationError as e:
        bad(e)
    if _address_in_use(db, ip):
        raise HTTPException(409, "این آدرس قبلاً برای یکی از نودها ثبت شده است")
    a = EdgeAddress(edge_id=edge.id, family=body.family, ip=ip, label=_clean_addr_label(body.label))
    db.add(a)
    db.commit()
    _audit(db, request, "edge.address.add", edge.name, {"family": a.family, "ip": a.ip, "address_id": a.id})
    db.refresh(edge)
    return {"address": address_to_dict(a), "edge": edge_to_dict(edge), "dns_failed": sync_all_dns(db)}


@router.patch("/edges/{edge_id}/addresses/{address_id}")
def update_edge_address(edge_id: int, address_id: int, body: EdgeAddressPatch, request: Request,
                        db: Session = Depends(get_db)):
    """Edit / rename / enable / disable an additional address (SPEC §12.4). The family is fixed;
    a changed IP starts its health over. `enabled=false` withdraws it from DNS immediately."""
    edge = _get_edge(db, edge_id)
    a = db.get(EdgeAddress, address_id)
    if a is None or a.edge_id != edge.id:
        raise HTTPException(404, "address not found")
    changes = body.model_dump(exclude_unset=True)
    if not changes:
        bad(ValidationError("هیچ تغییری ارسال نشده است"))
    if changes.get("ip") is not None:
        try:
            ip = validate_ip(changes["ip"], a.family)  # family cannot change on edit
        except ValidationError as e:
            bad(e)
        if _address_in_use(db, ip, exclude_id=a.id):
            raise HTTPException(409, "این آدرس قبلاً برای یکی از نودها ثبت شده است")
        if ip != a.ip:  # a new address is unprobed again -> advertised until it fails
            a.ip = ip
            a.probe_ok = a.probe_ms = a.probe_at = a.probe_error = None
            a.probe_fail = 0
    if "label" in changes:
        a.label = _clean_addr_label(changes["label"])
    if changes.get("enabled") is not None:
        a.enabled = changes["enabled"]
    db.commit()
    _audit(db, request, "edge.address.patch", edge.name,
           {"address_id": a.id, "family": a.family, "ip": a.ip, "fields": sorted(changes)})
    db.refresh(edge)
    return {"address": address_to_dict(a), "edge": edge_to_dict(edge), "dns_failed": sync_all_dns(db)}


@router.delete("/edges/{edge_id}/addresses/{address_id}")
def delete_edge_address(edge_id: int, address_id: int, request: Request, db: Session = Depends(get_db)):
    """Remove an additional address (SPEC §12.4). The primary cannot be deleted."""
    edge = _get_edge(db, edge_id)
    a = db.get(EdgeAddress, address_id)
    if a is None or a.edge_id != edge.id:
        raise HTTPException(404, "address not found")
    ip, family = a.ip, a.family
    db.delete(a)
    db.commit()
    _audit(db, request, "edge.address.del", edge.name, {"address_id": address_id, "family": family, "ip": ip})
    return {"ok": True, "dns_failed": sync_all_dns(db)}


# ------------------------------------------------------------------ audit log (SPEC §13.2)

AUDIT_MAX_LIMIT = 500


def audit_to_dict(e: AuditLog) -> dict:
    try:
        detail = json.loads(e.detail or "{}")
    except ValueError:
        detail = {}
    return {"id": e.id, "at": e.at.isoformat() + "Z" if e.at else None, "actor": e.actor,
            "actor_kind": e.actor_kind, "action": e.action, "target": e.target,
            "detail": detail, "ip": e.ip}


@router.get("/audit")
def list_audit(limit: int = 100, since: str | None = None, action: str | None = None,
               actor: str | None = None, db: Session = Depends(get_db)):
    """Recent audit entries, newest first (SPEC §13.2). `since` is an ISO-8601 timestamp."""
    limit = max(1, min(limit, AUDIT_MAX_LIMIT))
    q = select(AuditLog).order_by(AuditLog.id.desc())
    if action:
        q = q.where(AuditLog.action == action)
    if actor:
        q = q.where(AuditLog.actor == actor)
    if since:
        try:
            dt = datetime.fromisoformat(since.replace("Z", "").strip())
        except ValueError:
            bad(ValidationError("since باید یک زمان ISO-8601 باشد"))
        q = q.where(AuditLog.at >= dt)
    return [audit_to_dict(e) for e in db.scalars(q.limit(limit))]
