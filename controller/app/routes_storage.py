"""Object storage API for WHMCS (SPEC §16.8, docs/STORAGE.md). Admin key only.

Secrets: `secret_key` appears only in the 201/200 body of create and rotate-key; it is never in a
GET, the audit log (detail = bucket name only) or a log line.
"""

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import storage
from .auth import require_admin
from .db import get_db
from .models import Site, utcnow
from .routes_admin import _audit, get_site
from .services import lock_site

router = APIRouter(prefix="/api/v1", dependencies=[Depends(require_admin)])


class BucketIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=63)


def _fail(e: storage.StorageError):
    raise HTTPException(e.status, str(e))


def _credentials(b, secret: str) -> dict:
    return {**storage.bucket_dict(b), "secret_key": secret,
            "secret_note": "این کلید فقط همین یک بار نمایش داده می‌شود؛ آن را ذخیره کنید."}


def _overview(db: Session, site: Site, live: bool = True) -> dict:
    rows = storage.site_buckets(db, site)
    fresh = storage.refresh_usage(db, rows) if (live and rows and storage.available()) else not rows
    if live and rows and fresh:
        db.commit()
    limit = storage.limit_bytes(site)
    used = storage.used_bytes(rows)
    return {
        "available": storage.available(),
        "enabled": storage.available() and limit > 0,
        "storage_gb": limit // storage.GIB,
        "limit_bytes": limit,
        "used_bytes": used,
        "used_gb": round(used / storage.GIB, 3),
        "over_quota": used > limit,
        "endpoint": storage.public_endpoint() or None,
        "region": storage.settings.storage_region,
        "max_buckets": storage.settings.storage_max_buckets,
        "usage_stale": not fresh,
        "buckets": [storage.bucket_dict(b) for b in rows],
    }


@router.get("/sites/{domain}/storage")
@router.get("/sites/{domain}/storage/buckets")
def list_buckets(domain: str, db: Session = Depends(get_db)):
    """Buckets with usage (MinIO scanner, refreshed live when reachable; `usage_stale` otherwise)."""
    return _overview(db, get_site(db, domain))


@router.post("/sites/{domain}/storage/buckets", status_code=201)
def create_bucket(domain: str, body: BucketIn, request: Request, db: Session = Depends(get_db)):
    site = lock_site(db, get_site(db, domain))  # one bucket create/delete/rotate per site at a time
    try:
        row, secret = storage.create_bucket(db, site, body.name)
    except storage.StorageError as e:
        db.rollback()
        _fail(e)
    db.commit()
    _audit(db, request, "storage.bucket.create", site.domain, {"name": row.name})
    return _credentials(row, secret)


@router.delete("/sites/{domain}/storage/buckets/{name}")
def delete_bucket(domain: str, name: str, request: Request, db: Session = Depends(get_db)):
    site = lock_site(db, get_site(db, domain))
    try:
        b = storage.find_bucket(db, site, name)
        storage.delete_bucket(db, site, b)
    except storage.StorageError as e:
        db.rollback()
        _fail(e)
    db.commit()
    _audit(db, request, "storage.bucket.delete", site.domain, {"name": name})
    return {"ok": True}


@router.post("/sites/{domain}/storage/buckets/{name}/rotate-key")
def rotate_key(domain: str, name: str, request: Request, db: Session = Depends(get_db)):
    site = lock_site(db, get_site(db, domain))
    try:
        b = storage.find_bucket(db, site, name)
        secret = storage.rotate_key(db, site, b)
    except storage.StorageError as e:
        db.rollback()
        _fail(e)
    db.commit()
    _audit(db, request, "storage.bucket.rotate_key", site.domain, {"name": b.name})
    return _credentials(b, secret)


@router.get("/sites/{domain}/storage/usage")
def site_storage_usage(domain: str, month: str | None = None, db: Session = Depends(get_db)):
    """GB-hours of one month for WHMCS invoicing (current month when `month` is omitted)."""
    site = get_site(db, domain)
    try:
        return storage.month_report(db, site, month)
    except storage.StorageError as e:
        _fail(e)


@router.get("/storage/usage")
def all_storage_usage(month: str | None = None, db: Session = Depends(get_db)):
    """The same report for every site that stored anything that month (WHMCS cron)."""
    from .models import StorageUsageHourly

    try:
        start, end = storage.month_bounds(month)
    except storage.StorageError as e:
        _fail(e)
    ids = set(db.scalars(select(StorageUsageHourly.site_id).where(
        StorageUsageHourly.hour >= start, StorageUsageHourly.hour < end).distinct()))
    now = utcnow()
    sites = [s for s in db.scalars(select(Site).order_by(Site.id)) if s.id in ids]
    return {"month": start.strftime("%Y-%m"),
            "sites": [storage.month_report(db, s, start.strftime("%Y-%m"), now) for s in sites]}
