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
        "max_upload_bytes": storage.max_upload_bytes(),
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


# ------------------------------------------------------------------ file manager (SPEC §16.8)
#
# The browser never gets a key: it gets presigned URLs, one object at a time, from the controller's
# own identity. Listing / deleting / folders / renames run here, where the site's limits apply.


class ObjectsIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    keys: list[str] = Field(default_factory=list, max_length=storage.DELETE_MAX)
    prefixes: list[str] = Field(default_factory=list, max_length=10)


class PresignIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    key: str = Field(min_length=1, max_length=storage.MAX_KEY_BYTES)
    expires_in: int | None = Field(default=None, ge=60, le=storage.PRESIGN_MAX_S)
    attachment: bool = True


class UploadIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    key: str = Field(min_length=1, max_length=storage.MAX_KEY_BYTES)
    size: int = Field(default=0, ge=0, le=1 << 50)
    content_type: str = Field(default="", max_length=255)
    expires_in: int | None = Field(default=None, ge=60, le=storage.PRESIGN_MAX_S)
    parts: int = Field(default=storage.MULTIPART_URLS_PER_CALL, ge=1,
                       le=storage.MULTIPART_URLS_PER_CALL)


class PartsIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    key: str = Field(min_length=1, max_length=storage.MAX_KEY_BYTES)
    upload_id: str = Field(min_length=1, max_length=256)
    first: int = Field(default=1, ge=1, le=storage.MULTIPART_PART_MAX)
    count: int = Field(default=storage.MULTIPART_URLS_PER_CALL, ge=1,
                      le=storage.MULTIPART_URLS_PER_CALL)
    expires_in: int | None = Field(default=None, ge=60, le=storage.PRESIGN_MAX_S)


class Part(BaseModel):
    model_config = ConfigDict(extra="forbid")
    part: int = Field(ge=1, le=storage.MULTIPART_PART_MAX)
    etag: str = Field(min_length=1, max_length=128)


class CompleteIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    key: str = Field(min_length=1, max_length=storage.MAX_KEY_BYTES)
    upload_id: str = Field(min_length=1, max_length=256)
    parts: list[Part] = Field(min_length=1, max_length=storage.MULTIPART_PART_MAX)


class KeyIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    key: str = Field(min_length=1, max_length=storage.MAX_KEY_BYTES)


class RenameIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    key: str = Field(min_length=1, max_length=storage.MAX_KEY_BYTES)
    to: str = Field(min_length=1, max_length=storage.MAX_KEY_BYTES)


def _call(fn, *args, **kw):
    try:
        return fn(*args, **kw)
    except storage.StorageError as e:
        _fail(e)


@router.get("/sites/{domain}/storage/buckets/{name}/objects")
def list_objects(domain: str, name: str, prefix: str = "", token: str = "",
                 limit: int = storage.LIST_DEFAULT, db: Session = Depends(get_db)):
    site = get_site(db, domain)
    return _call(storage.list_objects, db, site, name, prefix, token, limit)


@router.post("/sites/{domain}/storage/buckets/{name}/objects/download")
def presign_download(domain: str, name: str, body: PresignIn, db: Session = Depends(get_db)):
    """A time-limited download URL for one object (and the permanent CDN URL when the bucket is
    wired to a record)."""
    site = get_site(db, domain)
    return _call(storage.presign_download, db, site, name, body.key, body.expires_in, body.attachment)


@router.post("/sites/{domain}/storage/buckets/{name}/objects/upload")
def presign_upload(domain: str, name: str, body: UploadIn, db: Session = Depends(get_db)):
    site = get_site(db, domain)
    return _call(storage.presign_upload, db, site, name, body.key, body.size, body.content_type,
                 body.expires_in)


@router.post("/sites/{domain}/storage/buckets/{name}/objects/multipart")
def multipart_start(domain: str, name: str, body: UploadIn, db: Session = Depends(get_db)):
    site = get_site(db, domain)
    return _call(storage.multipart_start, db, site, name, body.key, body.size, body.content_type,
                 body.parts, body.expires_in)


@router.post("/sites/{domain}/storage/buckets/{name}/objects/multipart/parts")
def multipart_parts(domain: str, name: str, body: PartsIn, db: Session = Depends(get_db)):
    site = get_site(db, domain)
    return _call(storage.multipart_part_urls, db, site, name, body.key, body.upload_id, body.first,
                 body.count, body.expires_in)


@router.post("/sites/{domain}/storage/buckets/{name}/objects/multipart/complete")
def multipart_complete(domain: str, name: str, body: CompleteIn, db: Session = Depends(get_db)):
    site = get_site(db, domain)
    return _call(storage.multipart_finish, db, site, name, body.key, body.upload_id,
                 [p.model_dump() for p in body.parts])


@router.post("/sites/{domain}/storage/buckets/{name}/objects/multipart/abort")
def multipart_abort(domain: str, name: str, body: PartsIn, db: Session = Depends(get_db)):
    site = get_site(db, domain)
    return _call(storage.multipart_cancel, db, site, name, body.key, body.upload_id)


@router.post("/sites/{domain}/storage/buckets/{name}/objects/folder", status_code=201)
def make_folder(domain: str, name: str, body: KeyIn, db: Session = Depends(get_db)):
    site = get_site(db, domain)
    return _call(storage.make_folder, db, site, name, body.key)


@router.post("/sites/{domain}/storage/buckets/{name}/objects/rename")
def rename_object(domain: str, name: str, body: RenameIn, db: Session = Depends(get_db)):
    site = get_site(db, domain)
    return _call(storage.rename_object, db, site, name, body.key, body.to)


@router.post("/sites/{domain}/storage/buckets/{name}/objects/delete")
def delete_objects(domain: str, name: str, body: ObjectsIn, request: Request,
                   db: Session = Depends(get_db)):
    site = get_site(db, domain)
    out = _call(storage.delete_objects, db, site, name, body.keys, body.prefixes)
    if out["deleted"]:
        # the keys themselves are customer content: the audit entry counts, it does not list them
        _audit(db, request, "storage.objects.delete", site.domain,
               {"name": name, "deleted": out["deleted"]})
        db.commit()
    return out


@router.get("/sites/{domain}/storage/usage")
def site_storage_usage(domain: str, month: str | None = None, db: Session = Depends(get_db)):
    """GB-hours of one month for WHMCS invoicing (current month when `month` is omitted)."""
    site = get_site(db, domain)
    try:
        return storage.month_report(db, site, month)
    except storage.StorageError as e:
        _fail(e)


@router.get("/storage/capacity")
def storage_capacity(db: Session = Depends(get_db)):
    """Operator view: what the storage server has (disk), what it is holding (the customers' objects)
    and what has been sold (the sum of plan storage_gb). For the admin dashboard."""
    return storage.capacity(db)


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
