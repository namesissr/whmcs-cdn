"""Object storage product (SPEC §16.8, docs/STORAGE.md).

The platform runs one storage deployment (deploy/storage/): SeaweedFS by default, or MinIO / AIStor
on a server that already runs it (STORAGE_BACKEND; seaweed_client.py / minio_client.py, same
interface). Either way the controller holds a scoped identity whose policy allows only s3:* on
`cdn-*` buckets plus the calls that manage a customer's key and quota — never the admin or root
credentials. Per customer bucket:

* the bucket itself, named STORAGE_BUCKET_PREFIX + a random per-site tag + "-" + the customer's name
  (globally unique on the server; the tag also keeps a reused site id away from a leftover bucket);
* an access key limited to that one bucket by an inline policy: on SeaweedFS an IAM user named after
  the key (the server keeps it in the filer), on MinIO a service account owned by the controller's
  user, which MinIO evaluates as (parent policy ∩ inline policy). Neither needs a permission that
  could mint credentials for another identity. Key rotation = new key + delete old;
* a hard bucket quota: the bucket's own size + the site's remaining headroom (plan `storage_gb`
  minus the site's total), recomputed hourly and on every bucket / plan change, plus a refusal of
  new buckets and an operator alert while a site is over its storage;
* a bucket policy allowing anonymous s3:GetObject only with `Referer: <origin token>` — the token
  is sent by the edges only, so a bucket can be a CDN origin without being public.

The customer's secret key is returned once (create / rotate) and stored encrypted; it never appears
in a GET, the audit log, a log line or the edge config. The edge config only carries the bucket's
origin token (it grants exactly what the CDN publishes anyway: GET of that bucket's objects).

Customer input never chooses a host: the endpoint is operator config (STORAGE_ENDPOINT /
STORAGE_PUBLIC_ENDPOINT), a bucket name is validated to [a-z0-9-] and always prefixed.
"""

import hashlib
import hmac
import logging
import re
import secrets
import time
from datetime import datetime, timedelta

from urllib.parse import quote

import httpx
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from . import alerts, minio_client, sections
from .config import settings
from .minio_client import MinioClient, MinioError
from .seaweed_client import SeaweedClient
from .models import Record, Site, State, StorageBucket, StorageUsageHourly, utcnow

log = logging.getLogger("pcdn.storage")

GIB = 1024 ** 3
TAG_LEN = 8
NAME_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$")
USAGE_STATE = "storage:usage_hour"
GAP_FILL_HOURS = 72  # missed hourly samples (controller down) are back-filled at most this far
ALERT_PREFIX = "storage_quota:"


class StorageError(Exception):
    """A refusal or failure the routes turn into an HTTP status."""

    def __init__(self, message: str, status: int = 422):
        super().__init__(message)
        self.status = status


# ------------------------------------------------------------------ client / configuration

_client: MinioClient | None = None


def set_client(c: MinioClient | None) -> None:
    """Tests inject a client on a fake transport; None = build from settings again."""
    global _client
    _client = c


def configured() -> bool:
    if not (settings.storage_endpoint and settings.storage_admin_access_key and settings.storage_admin_secret_key):
        return False
    for url in (settings.storage_endpoint, settings.storage_public_endpoint):
        try:
            u = httpx.URL(url)
        except Exception:  # noqa: BLE001
            return False
        if not u.host or u.scheme not in ("https", "http") or (
                u.scheme == "http" and not settings.storage_insecure_http):
            return False
    return True


def backend() -> str:
    """"seaweedfs" (the default for a new install) or "minio" (an existing MinIO / AIStor server)."""
    return "minio" if (settings.storage_backend or "").lower() == "minio" else "seaweedfs"


def client() -> MinioClient:
    global _client
    if _client is not None:
        return _client
    if not configured():
        raise StorageError("فضای ذخیره‌سازی روی این کنترلر پیکربندی نشده است (STORAGE_ENDPOINT)", 503)
    args = (settings.storage_endpoint, settings.storage_admin_access_key,
            settings.storage_admin_secret_key, settings.storage_region)
    if backend() == "minio":
        _client = MinioClient(*args)
    else:
        _client = SeaweedClient(*args, metrics_path=settings.storage_metrics_path,
                                 status_path=settings.storage_status_path)
    return _client


def available() -> bool:
    return _client is not None or configured()


def _require() -> MinioClient:
    if not available():
        raise StorageError("فضای ذخیره‌سازی روی این کنترلر پیکربندی نشده است (STORAGE_ENDPOINT)", 503)
    return client()


def public_endpoint() -> str:
    return settings.storage_public_endpoint or settings.storage_endpoint


# ------------------------------------------------------------------ names, policies, limits

def max_name_len() -> int:
    return min(40, 63 - len(settings.storage_bucket_prefix) - TAG_LEN - 1)


def validate_name(name: str) -> str:
    n = (name or "").strip().lower()
    hi = max_name_len()
    if not (3 <= len(n) <= hi) or not NAME_RE.match(n):
        raise StorageError(f"نام باکت باید {3} تا {hi} کاراکتر از حروف کوچک انگلیسی، رقم و - باشد "
                           "و با حرف یا رقم شروع و تمام شود")
    return n


def _new_tag() -> str:
    alphabet = "abcdefghijklmnopqrstuvwxyz234567"
    return "".join(secrets.choice(alphabet) for _ in range(TAG_LEN))


def site_tag(db: Session, site: Site) -> str:
    """The site's bucket tag: taken from an existing bucket of the site, else a new random one."""
    p = settings.storage_bucket_prefix
    for b in db.scalars(select(StorageBucket).where(StorageBucket.site_id == site.id)):
        if b.bucket.startswith(p) and len(b.bucket) > len(p) + TAG_LEN and b.bucket[len(p) + TAG_LEN] == "-":
            return b.bucket[len(p):len(p) + TAG_LEN]
    return _new_tag()


def limit_bytes(site: Site) -> int:
    return int(sections.features_of(site).get("storage_gb") or 0) * GIB


def customer_policy(bucket: str) -> dict:
    """Inline policy of the customer's service account: objects of this one bucket, nothing else
    (no bucket policy / versioning / lifecycle / delete-bucket, no admin action)."""
    arn = f"arn:aws:s3:::{bucket}"
    return {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Resource": [arn],
         "Action": ["s3:GetBucketLocation", "s3:ListBucket", "s3:ListBucketMultipartUploads"]},
        {"Effect": "Allow", "Resource": [arn + "/*"],
         "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:AbortMultipartUpload",
                    "s3:ListMultipartUploadParts", "s3:GetObjectTagging", "s3:PutObjectTagging",
                    "s3:DeleteObjectTagging"]},
    ]}


def origin_policy(bucket: str, token: str) -> dict:
    """Bucket policy: anonymous GET of objects only with the edges' Referer token (no listing)."""
    return {"Version": "2012-10-17", "Statement": [{
        "Sid": "PcdnEdgeOrigin", "Effect": "Allow", "Principal": {"AWS": ["*"]},
        "Action": ["s3:GetObject"], "Resource": [f"arn:aws:s3:::{bucket}/*"],
        "Condition": {"StringEquals": {"aws:Referer": [token]}},
    }]}


def _iso(dt: datetime | None) -> str | None:
    return dt.isoformat() + "Z" if dt else None


def bucket_dict(b: StorageBucket) -> dict:
    """Public view of a bucket — never the secret key or the origin token."""
    return {
        "name": b.name, "bucket": b.bucket, "access_key": b.access_key,
        "endpoint": public_endpoint(), "region": settings.storage_region,
        "quota_bytes": int(b.quota_bytes or 0),
        "usage": {"bytes": int(b.size_bytes or 0), "objects": int(b.objects or 0),
                  "gb": round((b.size_bytes or 0) / GIB, 3), "at": _iso(b.usage_at)},
        "created_at": _iso(b.created_at), "rotated_at": _iso(b.rotated_at),
    }


def site_buckets(db: Session, site: Site) -> list[StorageBucket]:
    return list(db.scalars(select(StorageBucket).where(StorageBucket.site_id == site.id)
                           .order_by(StorageBucket.id)))


def find_bucket(db: Session, site: Site, name: str) -> StorageBucket:
    b = db.scalar(select(StorageBucket).where(StorageBucket.site_id == site.id,
                                              StorageBucket.name == (name or "").strip().lower()))
    if b is None:
        raise StorageError("باکت یافت نشد", 404)
    return b


# ------------------------------------------------------------------ usage + quota

def _apply_usage(rows: list[StorageBucket], usage: dict, now: datetime) -> None:
    buckets = usage.get("buckets") or {}
    for b in rows:
        u = buckets.get(b.bucket)
        if u is not None:
            b.size_bytes, b.objects, b.usage_at = u["size"], u["objects"], now


def refresh_usage(db: Session, rows: list[StorageBucket], now: datetime | None = None) -> bool:
    """Update the rows from MinIO's data usage; False (rows unchanged) when MinIO cannot be read."""
    if not rows:
        return True
    try:
        usage = _require().data_usage()
    except (MinioError, StorageError) as e:
        log.warning("storage data usage unavailable: %s", e)
        return False
    _apply_usage(rows, usage, now or utcnow())
    return True


def quota_for(site: Site, rows: list[StorageBucket], b: StorageBucket) -> int:
    """Hard quota of `b`: its own size + the site's remaining headroom, at least 1 byte (MinIO reads 0
    as 'no quota'); with storage_gb 0 a bucket is frozen at its current size (read / delete only)."""
    total = sum(int(r.size_bytes or 0) for r in rows)
    headroom = max(0, limit_bytes(site) - total)
    return max(1, int(b.size_bytes or 0) + headroom)


def sync_site_quotas(db: Session, site: Site, rows: list[StorageBucket] | None = None) -> list[str]:
    """Push changed bucket quotas to MinIO; returns the buckets that failed. Caller commits."""
    rows = site_buckets(db, site) if rows is None else rows
    failed = []
    for b in rows:
        q = quota_for(site, rows, b)
        if q == b.quota_bytes:
            continue
        try:
            _require().set_bucket_quota(b.bucket, q)
            b.quota_bytes = q
        except (MinioError, StorageError) as e:
            log.warning("storage quota of %s not set: %s", b.bucket, e)
            failed.append(b.bucket)
    return failed


def used_bytes(rows: list[StorageBucket]) -> int:
    return sum(int(r.size_bytes or 0) for r in rows)


# ------------------------------------------------------------------ the server's own capacity (operator)

_CAPACITY_TTL_S = 30.0
_capacity_cache: dict[str, object] = {}


def capacity(db: Session, now: float | None = None) -> dict:
    """What the storage server HAS against what it is holding and what has been sold, for the admin
    panel. Three different numbers, which is the point:

    * disk — the server's own filesystem (total / used / free). `used` is everything on that disk,
      not only customer objects, so it is the figure that decides when to add space. Absent when the
      server does not report it (no status path, or the MinIO backend without one reachable), in
      which case STORAGE_CAPACITY_GB stands in for the total if the operator set it.
    * data — the customers' objects, summed from the per-bucket usage the hourly job stores.
    * sold — the sum of every site's plan `storage_gb`. Larger than the disk means overcommitted,
      which is normal for a reseller but worth seeing.

    Cached for 30 s: the dashboard asks on every page load and the server recomputes its bucket
    gauges once a minute anyway."""
    now = now if now is not None else time.monotonic()
    hit = _capacity_cache.get("at")
    if isinstance(hit, float) and now - hit < _CAPACITY_TTL_S and isinstance(_capacity_cache.get("v"), dict):
        return dict(_capacity_cache["v"])          # type: ignore[arg-type]

    rows = list(db.scalars(select(StorageBucket)))
    # the same live read the customer's own page does, so the two never disagree on the same minute
    fresh = refresh_usage(db, rows) if (rows and available()) else not rows
    if rows and fresh:
        db.commit()
    data_bytes = used_bytes(rows)
    sites = db.scalars(select(Site)).all()
    sold = sum(limit_bytes(s) for s in sites)
    with_storage = sum(1 for s in sites if limit_bytes(s) > 0)
    out: dict = {
        "available": available(),
        "backend": backend(),
        "endpoint": public_endpoint() or None,
        "buckets": len(rows),
        "objects": sum(int(r.objects or 0) for r in rows),
        "data_bytes": data_bytes,
        "sold_bytes": sold,
        "sites_with_storage": with_storage,
        "data_stale": not fresh,
        "disk": None,
        "disk_error": None,
        "at": utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    configured_total = int(settings.storage_capacity_gb * GIB)
    if available():
        try:
            disk = _require().disk_status()
            out["disk"] = {**disk, "source": "server"}
        except (MinioError, NotImplementedError) as e:
            out["disk_error"] = str(e) or type(e).__name__
            if configured_total > 0:
                out["disk"] = {"total": configured_total, "used": data_bytes,
                               "free": max(0, configured_total - data_bytes), "dirs": [],
                               "source": "configured"}
    if out["disk"]:
        total = int(out["disk"]["total"] or 0)
        out["disk"]["percent_used"] = round(out["disk"]["used"] * 100 / total, 1) if total > 0 else None
    _capacity_cache["at"] = now
    _capacity_cache["v"] = dict(out)
    return out


# ------------------------------------------------------------------ bucket lifecycle

def create_bucket(db: Session, site: Site, name: str) -> tuple[StorageBucket, str]:
    """Create bucket + quota + origin policy + scoped service account. -> (row, secret key shown
    once). Anything created on MinIO is rolled back when a later step fails. Caller commits."""
    name = validate_name(name)
    cli = _require()
    limit = limit_bytes(site)
    if limit <= 0:
        raise StorageError("فضای ذخیره‌سازی در پلن این سرویس فعال نیست", 403)
    rows = site_buckets(db, site)
    if any(r.name == name for r in rows):
        raise StorageError("باکتی با این نام برای این سرویس وجود دارد", 409)
    if len(rows) >= settings.storage_max_buckets:
        raise StorageError(f"حداکثر {settings.storage_max_buckets} باکت برای هر سرویس مجاز است", 403)
    refresh_usage(db, rows)
    if rows and used_bytes(rows) >= limit:
        raise StorageError("فضای ذخیره‌سازی این سرویس پر است؛ باکت جدید ساخته نمی‌شود", 403)
    bucket = f"{settings.storage_bucket_prefix}{site_tag(db, site)}-{name}"
    if db.scalar(select(StorageBucket.id).where(StorageBucket.bucket == bucket)) is not None:
        raise StorageError("این نام باکت در دسترس نیست", 409)
    try:
        if cli.bucket_exists(bucket):  # never adopt a bucket the controller did not create now
            raise StorageError("این نام باکت در دسترس نیست", 409)
        cli.make_bucket(bucket)
    except MinioError as e:
        if e.code in ("BucketAlreadyExists", "BucketAlreadyOwnedByYou"):
            raise StorageError("این نام باکت در دسترس نیست", 409) from None
        raise StorageError(f"ساخت باکت روی سرور ذخیره‌سازی ناموفق بود: {e}", 502) from None

    row = StorageBucket(site_id=site.id, name=name, bucket=bucket, access_key="", quota_bytes=0,
                        size_bytes=0, objects=0)
    token, secret = secrets.token_hex(24), minio_client.new_secret_key()
    access_key = minio_client.new_access_key()
    sa_created = False
    try:
        row.quota_bytes = quota_for(site, rows + [row], row)
        cli.set_bucket_quota(bucket, row.quota_bytes)
        cli.put_bucket_policy(bucket, origin_policy(bucket, token))
        cli.add_service_account(access_key, secret, customer_policy(bucket), name=f"pcdn-{name}"[:32],
                                description=f"{site.domain} {bucket}")
        sa_created = True
    except MinioError as e:
        _rollback_create(cli, bucket, access_key if not sa_created else None)
        raise StorageError(f"پیکربندی باکت روی سرور ذخیره‌سازی ناموفق بود: {e}", 502) from None
    row.access_key = access_key
    row.secret_key = secret
    row.origin_token = token
    db.add(row)
    db.flush()
    # the other buckets' headroom shrank by nothing (new bucket is empty) — but a plan change may be
    # pending, so bring every quota of the site in line now (best effort, the hourly job retries)
    sync_site_quotas(db, site, rows + [row])
    return row, secret


def _rollback_create(cli: MinioClient, bucket: str, access_key: str | None) -> None:
    for step in (lambda: access_key and cli.delete_service_account(access_key),
                 lambda: cli.delete_bucket_policy(bucket), lambda: cli.delete_bucket(bucket)):
        try:
            step()
        except MinioError as e:
            log.warning("storage rollback of %s incomplete: %s", bucket, e)


def records_using(site: Site, name: str) -> list[Record]:
    return [r for r in site.records if r.storage_bucket == name]


def delete_bucket(db: Session, site: Site, b: StorageBucket) -> None:
    """Only an empty bucket that no record uses (409 otherwise). Caller commits."""
    used = records_using(site, b.name)
    if used:
        raise StorageError(f"این باکت مبدأ رکورد {used[0].name} است؛ ابتدا رکورد را تغییر دهید", 409)
    cli = _require()
    try:
        if not cli.bucket_is_empty(b.bucket):
            raise StorageError("باکت خالی نیست؛ ابتدا همه فایل‌ها را حذف کنید", 409)
        cli.delete_bucket(b.bucket)
    except MinioError as e:
        if e.code == "BucketNotEmpty":
            raise StorageError("باکت خالی نیست؛ ابتدا همه فایل‌ها را حذف کنید", 409) from None
        if e.code != "NoSuchBucket":
            raise StorageError(f"حذف باکت روی سرور ذخیره‌سازی ناموفق بود: {e}", 502) from None
    try:
        cli.delete_service_account(b.access_key)
    except MinioError as e:  # the bucket is gone, so the key can reach nothing any more
        log.warning("storage service account of %s not removed: %s", b.bucket, e)
    db.delete(b)
    db.flush()
    sync_site_quotas(db, site)  # the freed headroom goes to the remaining buckets


def rotate_key(db: Session, site: Site, b: StorageBucket) -> str:
    """New access key + secret (new service account), then the old one is deleted. -> secret,
    shown once. Caller commits."""
    cli = _require()
    access_key, secret = minio_client.new_access_key(), minio_client.new_secret_key()
    try:
        cli.add_service_account(access_key, secret, customer_policy(b.bucket), name=f"pcdn-{b.name}"[:32],
                                description=f"{site.domain} {b.bucket}")
    except MinioError as e:
        raise StorageError(f"ساخت کلید جدید روی سرور ذخیره‌سازی ناموفق بود: {e}", 502) from None
    old = b.access_key
    try:
        cli.delete_service_account(old)
    except MinioError as e:
        try:
            cli.delete_service_account(access_key)
        except MinioError:
            log.warning("storage: new key %s of %s left behind after a failed rotation", access_key, b.bucket)
        raise StorageError(f"حذف کلید قبلی روی سرور ذخیره‌سازی ناموفق بود؛ کلید عوض نشد: {e}", 502) from None
    b.access_key = access_key
    b.secret_key = secret
    b.rotated_at = utcnow()
    return secret


def pending_rotations(db: Session) -> list[StorageBucket]:
    """Buckets whose access key a domain transfer still has to rotate (SPEC §19.2)."""
    return list(db.scalars(select(StorageBucket).where(StorageBucket.credentials_rotation_pending_at.is_not(None))
                           .order_by(StorageBucket.id)))


def rotate_pending(db: Session, bucket_ids: list[int] | None = None) -> tuple[list[str], list[str]]:
    """Rotate the access key of every bucket marked credentials_rotation_pending_at (or of those of
    `bucket_ids` that are still marked) — after a domain transfer the previous owner must not keep a
    working storage key. Each bucket is rotated under its row lock and committed on its own; a
    failure leaves the mark for the next try (scheduler.job_storage_rotation). The new secret is not
    shown to anyone: the new owner rotates once more to get a key of their own.
    Returns (done, still pending) global bucket names."""
    ids = bucket_ids if bucket_ids is not None else [b.id for b in pending_rotations(db)]
    done: list[str] = []
    pending: list[str] = []
    for bid in ids:
        b = db.scalar(select(StorageBucket).where(StorageBucket.id == bid,
                                                  StorageBucket.credentials_rotation_pending_at.is_not(None))
                      .with_for_update().execution_options(populate_existing=True))
        if b is None:  # rotated meanwhile (another worker) or deleted
            db.rollback()
            continue
        name = b.bucket
        site = db.get(Site, b.site_id)
        try:
            if site is None:
                raise StorageError("site not found", 404)
            rotate_key(db, site, b)
            b.credentials_rotation_pending_at = None
            db.commit()
            done.append(name)
        except StorageError as e:
            db.rollback()
            log.warning("storage: key rotation of %s after a domain transfer failed (retried): %s", name, e)
            pending.append(name)
    return done, pending


def on_site_delete(db: Session, site: Site) -> list[str]:
    """Best effort before a site is deleted: revoke every access key and remove the empty buckets.
    Non-empty buckets are left on MinIO (customer data is never deleted implicitly) and reported in
    an operator alert. Returns the buckets left behind. The rows go with delete_platform_data."""
    rows = site_buckets(db, site)
    if not rows:
        return []
    left = []
    try:
        cli = _require()
    except StorageError:
        left = [b.bucket for b in rows]
    else:
        for b in rows:
            try:
                cli.delete_service_account(b.access_key)
                cli.delete_bucket_policy(b.bucket)
                if cli.bucket_is_empty(b.bucket):
                    cli.delete_bucket(b.bucket)
                else:
                    left.append(b.bucket)
            except MinioError as e:
                if e.code != "NoSuchBucket":
                    log.warning("storage cleanup of %s incomplete: %s", b.bucket, e)
                    left.append(b.bucket)
    if left:
        alerts.raise_alert(
            f"storage_orphans:{site.domain}", "باکت‌های بدون سرویس روی سرور ذخیره‌سازی",
            f"سرویس {site.domain} حذف شد ولی این باکت‌ها خالی نبودند یا حذف نشدند و روی MinIO مانده‌اند "
            f"(کلیدهای دسترسی مشتری باطل شده است): {', '.join(left)}\n"
            "پس از مهلت نگهداری با `mc rb --force` حذفشان کنید (docs/STORAGE.md).")
    return left


# ------------------------------------------------------------------ hourly job (leader)

def _hour(now: datetime) -> datetime:
    return now.replace(minute=0, second=0, microsecond=0)


def _set_state(db: Session, key: str, value: str) -> None:
    row = db.get(State, key)
    if row is None:
        db.add(State(key=key, value=value))
    else:
        row.value = value


def record_samples(db: Session, rows: list[StorageBucket], hour: datetime) -> int:
    """Write this hour's sample of every bucket (upsert) and back-fill missed hours (controller
    down) with min(previous sample, now) — never billing more than was stored at either end."""
    n = 0
    for b in rows:
        size, objs = int(b.size_bytes or 0), int(b.objects or 0)
        cur = db.scalar(select(StorageUsageHourly).where(StorageUsageHourly.bucket == b.bucket,
                                                         StorageUsageHourly.hour == hour))
        if cur is not None:
            cur.bytes, cur.objects = size, objs
            continue
        prev = db.scalar(select(StorageUsageHourly).where(StorageUsageHourly.bucket == b.bucket,
                                                          StorageUsageHourly.hour < hour)
                         .order_by(StorageUsageHourly.hour.desc()).limit(1))
        if prev is not None:
            gap = prev.hour + timedelta(hours=1)
            start = max(gap, hour - timedelta(hours=GAP_FILL_HOURS))
            t = start
            while t < hour:
                db.add(StorageUsageHourly(site_id=b.site_id, bucket=b.bucket, hour=t,
                                          bytes=min(int(prev.bytes), size), objects=min(int(prev.objects), objs)))
                t += timedelta(hours=1)
                n += 1
        db.add(StorageUsageHourly(site_id=b.site_id, bucket=b.bucket, hour=hour, bytes=size, objects=objs))
        n += 1
    return n


def run_hourly(db: Session, now: datetime | None = None, force: bool = False) -> dict | None:
    """Once per UTC hour: read MinIO's data usage, store it on the buckets, write the hourly billing
    samples, re-balance quotas and alert on sites over their storage. A failed MinIO read keeps the
    hour pending (retried next tick) and raises an alert."""
    now = now or utcnow()
    hour = _hour(now)
    st = db.get(State, USAGE_STATE)
    if not force and st is not None and st.value == hour.isoformat():
        return None
    rows = list(db.scalars(select(StorageBucket).order_by(StorageBucket.site_id, StorageBucket.id)))
    if not rows:
        _set_state(db, USAGE_STATE, hour.isoformat())
        db.commit()
        alerts.sync(ALERT_PREFIX, {})
        return {"buckets": 0, "samples": 0}
    try:
        usage = _require().data_usage()
    except (MinioError, StorageError) as e:
        alerts.raise_alert("storage_usage", "خواندن مصرف فضای ذخیره‌سازی ناموفق بود",
                           f"کنترلر نتوانست مصرف باکت‌ها را از MinIO بخواند؛ هر دقیقه دوباره تلاش می‌شود.\n{e}")
        return {"error": str(e)}
    alerts.resolve_alert("storage_usage", "خواندن مصرف فضای ذخیره‌سازی دوباره کار می‌کند.")
    _apply_usage(rows, usage, now)
    samples = record_samples(db, rows, hour)
    policy_failed = reapply_origin_policies(rows)
    by_site: dict[int, list[StorageBucket]] = {}
    for b in rows:
        by_site.setdefault(b.site_id, []).append(b)
    over = {}
    failed = []
    for site_id, srows in by_site.items():
        site = db.get(Site, site_id)
        if site is None:
            continue
        failed += sync_site_quotas(db, site, srows)
        limit, used = limit_bytes(site), used_bytes(srows)
        if used > limit:
            over[ALERT_PREFIX + site.domain] = (
                f"فضای ذخیره‌سازی {site.domain} بیش از پلن",
                f"مصرف {used / GIB:.2f} GB از {limit / GIB:.0f} GB پلن. نوشتن در باکت‌ها با سهمیه (quota) MinIO "
                "متوقف شده و باکت جدید ساخته نمی‌شود.", "warning")
    _set_state(db, USAGE_STATE, hour.isoformat())
    db.commit()
    alerts.sync(ALERT_PREFIX, over)
    return {"buckets": len(rows), "samples": samples, "over_quota": sorted(over), "quota_failed": failed,
            "policy_failed": policy_failed}


def reapply_origin_policies(rows: list[StorageBucket]) -> list[str]:
    """Re-put every bucket's origin policy (hourly): self-heals a policy removed by hand and moves
    the buckets to a token regenerated by `manage drop-unreadable-secrets`. Returns the failed buckets."""
    from .crypto import CryptoError

    failed = []
    for b in rows:
        try:
            _require().put_bucket_policy(b.bucket, origin_policy(b.bucket, b.origin_token))
        except (MinioError, StorageError, CryptoError) as e:
            log.warning("storage origin policy of %s not applied: %s", b.bucket, e)
            failed.append(b.bucket)
    return failed


def prune(db: Session, days: int = 400) -> None:
    db.execute(delete(StorageUsageHourly).where(StorageUsageHourly.hour < utcnow() - timedelta(days=days)))


# ------------------------------------------------------------------ billing report

def month_bounds(month: str | None, now: datetime | None = None) -> tuple[datetime, datetime]:
    if month:
        try:
            start = datetime.strptime(month, "%Y-%m")
        except ValueError:
            raise StorageError("month must be YYYY-MM") from None
    else:
        start = (now or utcnow()).replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    end = (start.replace(day=28) + timedelta(days=4)).replace(day=1)
    return start, end


def month_report(db: Session, site: Site, month: str | None = None, now: datetime | None = None) -> dict:
    """GB-hours of a month for invoicing. gb_hours = Σ hourly samples / 1024³; gb_month = gb_hours /
    hours of the month (the average GB stored over the whole month, what a GB-month price applies to)."""
    now = now or utcnow()
    start, end = month_bounds(month, now)
    hours = int((end - start).total_seconds() // 3600)
    q = (select(StorageUsageHourly.bucket, func.coalesce(func.sum(StorageUsageHourly.bytes), 0),
                func.coalesce(func.max(StorageUsageHourly.bytes), 0), func.count(StorageUsageHourly.id))
         .where(StorageUsageHourly.site_id == site.id, StorageUsageHourly.hour >= start,
                StorageUsageHourly.hour < end)
         .group_by(StorageUsageHourly.bucket).order_by(StorageUsageHourly.bucket))
    names = {b.bucket: b.name for b in site_buckets(db, site)}
    buckets, total, samples = [], 0, 0
    peak_hour = dict(db.execute(
        select(StorageUsageHourly.hour, func.sum(StorageUsageHourly.bytes))
        .where(StorageUsageHourly.site_id == site.id, StorageUsageHourly.hour >= start,
               StorageUsageHourly.hour < end)
        .group_by(StorageUsageHourly.hour)).all())
    for bucket, byte_hours, peak, n in db.execute(q).all():
        total += int(byte_hours)
        samples = max(samples, int(n))
        buckets.append({"bucket": bucket, "name": names.get(bucket), "deleted": bucket not in names,
                        "byte_hours": int(byte_hours), "gb_hours": round(int(byte_hours) / GIB, 4),
                        "peak_gb": round(int(peak) / GIB, 4), "samples": int(n)})
    elapsed = max(0, min(hours, int((min(now, end) - start).total_seconds() // 3600)))
    return {
        "domain": site.domain, "external_id": site.external_id, "month": start.strftime("%Y-%m"),
        "complete": now >= end, "hours_in_month": hours, "hours_elapsed": elapsed,
        "storage_gb": int(sections.features_of(site).get("storage_gb") or 0),
        "byte_hours": total, "gb_hours": round(total / GIB, 4),
        "gb_month": round(total / GIB / hours, 4) if hours else 0.0,
        "peak_gb": round(max(peak_hour.values(), default=0) / GIB, 4),
        "buckets": buckets,
    }


# ------------------------------------------------------------------ edge config

def link_key(b: StorageBucket) -> str:
    """The key the edges verify this bucket's signed links with (SPEC §16.8). Derived from the
    bucket's read token rather than being it, so a link's signature never reveals what the edges send
    as Referer, and separate from the customer's own access key, so «کلید جدید» does not break links
    the customer has already shared. A link therefore stands until its own expiry (7 days at most);
    what ends every link at once is a new read token (crypto.drop_unreadable_secrets)."""
    return hmac.new(b.origin_token.encode(), b"pcdn-file-link-v1", hashlib.sha256).hexdigest()


def edge_origin(b: StorageBucket, signed: bool = False) -> dict:
    """The `origin.storage` block of an edge host (SPEC §16.8): fetch over TLS from `host:port`
    (SNI + certificate verification for `host`), `Host: host_header`, URI = path_prefix + the
    request path (path-style S3, no query string), `Referer: referer`. GET/HEAD only.

    `signed`: the host serves this bucket only to a signed, unexpired link (`link_key`)."""
    u = httpx.URL(public_endpoint())
    tls = u.scheme == "https"
    host = u.host
    port = u.port or (443 if tls else 80)
    host_header = (f"[{host}]" if ":" in host else host) + (f":{u.port}" if u.port else "")
    return {"host": host, "port": port, "tls": tls, "host_header": host_header, "bucket": b.bucket,
            "path_prefix": f"{u.path.rstrip('/')}/{b.bucket}", "referer": b.origin_token,
            **({"signed": True, "link_key": link_key(b)} if signed else {})}


def edge_buckets(db: Session) -> dict[tuple[int, str], StorageBucket]:
    """(site id, bucket name) -> row, for build_edge_config; empty when storage is not available."""
    if not available():
        return {}
    return {(b.site_id, b.name): b for b in db.scalars(select(StorageBucket))}


# ------------------------------------------------------------------ file manager (SPEC §16.8)
#
# The customer's browser talks to the storage server DIRECTLY with presigned URLs the controller
# signs with its own identity: a file never passes through the controller (a 7 GB upload would
# otherwise cost the controller that bandwidth and memory), the customer's own secret key is never
# needed for it, and each URL is good for one object and a few minutes. Listing, deleting, folders
# and renames are server-side calls, where the answer is small and the controller can enforce the
# site's limits.

MAX_KEY_BYTES = 1024
LIST_MAX = 1000
LIST_DEFAULT = 200
PRESIGN_DEFAULT_S = 3600
PRESIGN_MAX_S = 7 * 24 * 3600          # S3's own ceiling for a SigV4 query signature
MULTIPART_PART_MAX = 1000              # part numbers per upload (S3)
MULTIPART_URLS_PER_CALL = 100
DELETE_MAX = 200                       # keys per call; a prefix is expanded up to this many
_CORS_TTL_S = 600
_cors_applied: dict[str, float] = {}

# a key may hold any UTF-8, but not these: they break paths, listings or the edge's URI mapping
_KEY_BAD = re.compile(r"[\x00-\x1f\x7f]")


def max_upload_bytes() -> int:
    return int(settings.storage_max_upload_gb * GIB)


def validate_key(key: str, folder: bool = False) -> str:
    """A customer-supplied object key, normalised (no leading slash) and refused when it could not
    round-trip: empty / only slashes, a "." or ".." segment, a double slash, a control character, or
    more than 1024 bytes. `folder` requires (and keeps) the trailing slash."""
    k = (key or "").strip().lstrip("/")
    if not k or _KEY_BAD.search(k) or "//" in k:
        raise StorageError("نام فایل یا پوشه معتبر نیست")
    if any(seg in (".", "..") for seg in k.split("/")):
        raise StorageError("نام فایل یا پوشه معتبر نیست")
    if len(k.encode()) > MAX_KEY_BYTES:
        raise StorageError(f"مسیر فایل بیش از {MAX_KEY_BYTES} بایت است")
    if folder:
        k = k.rstrip("/") + "/"
        if k == "/":
            raise StorageError("نام پوشه خالی است")
    elif k.endswith("/"):
        raise StorageError("نام فایل نمی‌تواند به / تمام شود")
    return k


def _prefix(prefix: str) -> str:
    """A listing prefix: "" (the bucket root) or a validated folder key."""
    p = (prefix or "").strip().lstrip("/")
    return validate_key(p, folder=True) if p else ""


def cors_origins() -> list[str]:
    """Origins the customer's browser may upload from. Empty config means "*", which grants nothing
    on its own: a presigned URL carries its own authentication and no cookie is involved."""
    raw = [o.strip() for o in (settings.storage_cors_origins or "").split(",")]
    return [o for o in raw if o] or ["*"]


def ensure_cors(cli, bucket: str, now: float | None = None) -> None:
    """Put the CORS rule on the bucket, at most once per _CORS_TTL_S per process. Never fatal: a
    server that refuses it only means the browser upload will fail, which the caller reports."""
    now = now if now is not None else time.monotonic()
    if now - _cors_applied.get(bucket, 0.0) < _CORS_TTL_S:
        return
    try:
        cli.put_bucket_cors(bucket, cors_origins())
        _cors_applied[bucket] = now
    except MinioError as e:
        log.warning("storage: CORS on %s not applied: %s", bucket, e)


def cdn_host(db: Session, site: Site, bucket_name: str) -> tuple[str, bool] | None:
    """(host, signed only?) of the proxied record served from this bucket, so a file link can be on
    the customer's own domain. None when no record uses the bucket."""
    from .models import Record

    rec = db.scalar(select(Record).where(Record.site_id == site.id, Record.proxied.is_(True),
                                        Record.storage_bucket == bucket_name).order_by(Record.id))
    if rec is None:
        return None
    host = site.domain if rec.name in ("@", "", None) else f"{rec.name}.{site.domain}"
    return host, bool(rec.storage_signed)


def public_base(db: Session, site: Site, bucket_name: str) -> str | None:
    """`https://host` at which this bucket's files are publicly readable, for the permanent link the
    file manager shows. None when no record uses the bucket, and None when that record hands the
    bucket out by signed link only — there is no permanent address then, which is the point."""
    hit = cdn_host(db, site, bucket_name)
    return None if hit is None or hit[1] else "https://" + hit[0]


def cdn_link(db: Session, site: Site, b: StorageBucket, key: str, seconds: int) -> str | None:
    """A signed link to one file on the customer's own CDN host, or None when this bucket's record
    does not hand files out that way. `e` is the expiry and `s` the signature the edges check
    (edge/njs/pcdn.js fileLink): HMAC-SHA256 over host, the decoded path and the expiry, truncated to
    128 bits. Nothing of the storage server's own address appears in it."""
    hit = cdn_host(db, site, b.name)
    if hit is None or not hit[1]:
        return None
    host, _ = hit
    exp = int(time.time()) + seconds
    path = "/" + key.lstrip("/")
    mac = hmac.new(link_key(b).encode(), f"f|{host}|{path}|{exp}".encode(), hashlib.sha256)
    sig = mac.hexdigest()[:32]
    return f"https://{host}{quote(path)}?e={exp}&s={sig}"


def list_objects(db: Session, site: Site, name: str, prefix: str = "", token: str = "",
                 limit: int = LIST_DEFAULT) -> dict:
    b = find_bucket(db, site, name)
    cli = _require()
    p = _prefix(prefix)
    try:
        page = cli.list_objects(b.bucket, p, token, max(1, min(LIST_MAX, int(limit or LIST_DEFAULT))))
    except MinioError as e:
        raise StorageError(f"خواندن فهرست فایل‌ها ناموفق بود: {e}", 502) from None
    hit = cdn_host(db, site, b.name)
    base = None if hit is None or hit[1] else "https://" + hit[0]
    objects = []
    for o in page["objects"]:
        if o["key"] == p:          # the folder marker itself
            continue
        objects.append({**o, "name": o["key"][len(p):],
                        "public_url": (base + "/" + o["key"]) if base else None})
    return {"prefix": p, "folders": [{"key": f, "name": f[len(p):].rstrip("/")} for f in page["folders"]],
            "objects": objects, "next_token": page["next_token"], "public_base": base,
            # the customer's own host that serves this bucket, and whether it does so by signed link
            # only — what the panel needs to say where a download link will point
            "link_host": hit[0] if hit else None, "signed_only": bool(hit and hit[1]),
            "max_upload_bytes": max_upload_bytes()}


def _expires(seconds: int | None) -> int:
    return max(60, min(PRESIGN_MAX_S, int(seconds or PRESIGN_DEFAULT_S)))


def presign_download(db: Session, site: Site, name: str, key: str, seconds: int | None = None,
                     attachment: bool = True) -> dict:
    """A time-limited link to one file.

    When the bucket's CDN record hands files out by signed link, the link is on the customer's own
    host and the storage server's address never appears (`kind: "cdn"`). Otherwise it is a presigned
    URL of the storage endpoint (`kind: "storage"`), which is the only address a bucket without a CDN
    record has. `public_url` is the permanent address, which exists only while the bucket is public."""
    b = find_bucket(db, site, name)
    cli = _require()
    k = validate_key(key)
    exp = _expires(seconds)
    cdn = cdn_link(db, site, b, k, exp)
    if cdn:
        return {"url": cdn, "method": "GET", "expires_in": exp, "kind": "cdn", "public_url": None}
    query = {}
    if attachment:
        filename = k.rsplit("/", 1)[-1].replace('"', "")
        query["response-content-disposition"] = f'attachment; filename="{filename}"'
    return {"url": cli.presign("GET", b.bucket, k, exp, query), "method": "GET", "expires_in": exp,
            "kind": "storage",
            "public_url": (lambda base: base + "/" + k if base else None)(public_base(db, site, b.name))}


def _headroom(db: Session, site: Site, size: int) -> None:
    """Refuse an upload that cannot fit in the plan. The usage figure is a minute old at worst, so
    this is a guard rather than a hard accountant — the bucket quota on the server is the hard stop."""
    size = max(0, int(size or 0))
    if size > max_upload_bytes():
        raise StorageError(f"حجم هر فایل حداکثر {settings.storage_max_upload_gb} گیگابایت است")
    rows = site_buckets(db, site)
    limit = limit_bytes(site)
    if limit <= 0:
        raise StorageError("فضای ذخیره‌سازی برای این سرویس فعال نیست", 403)
    if used_bytes(rows) + size > limit:
        raise StorageError("فضای ذخیره‌سازی سرویس پر است؛ فایلی حذف کنید یا پلن را ارتقا دهید", 409)


def presign_upload(db: Session, site: Site, name: str, key: str, size: int = 0,
                   content_type: str = "", seconds: int | None = None) -> dict:
    """One presigned PUT for a whole (small) file."""
    b = find_bucket(db, site, name)
    cli = _require()
    k = validate_key(key)
    _headroom(db, site, size)
    ensure_cors(cli, b.bucket)
    exp = _expires(seconds)
    return {"url": cli.presign("PUT", b.bucket, k, exp), "method": "PUT", "expires_in": exp,
            "key": k, "content_type": content_type or ""}


def multipart_start(db: Session, site: Site, name: str, key: str, size: int = 0,
                    content_type: str = "", parts: int = MULTIPART_URLS_PER_CALL,
                    seconds: int | None = None) -> dict:
    """Start a multipart upload and hand out the first batch of presigned part URLs. The browser asks
    for more with multipart_part_urls() as it goes, so one stalled upload never holds 1000 URLs."""
    b = find_bucket(db, site, name)
    cli = _require()
    k = validate_key(key)
    _headroom(db, site, size)
    ensure_cors(cli, b.bucket)
    try:
        upload_id = cli.create_multipart(b.bucket, k, content_type)
    except MinioError as e:
        raise StorageError(f"شروع آپلود چندبخشی ناموفق بود: {e}", 502) from None
    return {"key": k, "upload_id": upload_id,
            **multipart_part_urls(db, site, name, k, upload_id, 1, parts, seconds)}


def multipart_part_urls(db: Session, site: Site, name: str, key: str, upload_id: str, first: int,
                        count: int, seconds: int | None = None) -> dict:
    b = find_bucket(db, site, name)
    cli = _require()
    k = validate_key(key)
    first = max(1, min(MULTIPART_PART_MAX, int(first or 1)))
    count = max(1, min(MULTIPART_URLS_PER_CALL, int(count or 1)))
    last = min(MULTIPART_PART_MAX, first + count - 1)
    exp = _expires(seconds)
    urls = [{"part": n, "url": cli.presign("PUT", b.bucket, k, exp,
                                           {"uploadId": upload_id, "partNumber": str(n)})}
            for n in range(first, last + 1)]
    return {"urls": urls, "expires_in": exp, "part_max": MULTIPART_PART_MAX}


def multipart_finish(db: Session, site: Site, name: str, key: str, upload_id: str,
                     parts: list[dict]) -> dict:
    b = find_bucket(db, site, name)
    cli = _require()
    k = validate_key(key)
    clean = []
    for p in parts or []:
        try:
            n, tag = int(p.get("part")), str(p.get("etag") or "").strip('"')
        except (TypeError, ValueError):
            raise StorageError("فهرست بخش‌های آپلود معتبر نیست") from None
        if not (1 <= n <= MULTIPART_PART_MAX) or not re.fullmatch(r"[A-Za-z0-9+/=._-]{1,128}", tag):
            raise StorageError("فهرست بخش‌های آپلود معتبر نیست")
        clean.append({"part": n, "etag": tag})
    if not clean:
        raise StorageError("فهرست بخش‌های آپلود خالی است")
    try:
        cli.complete_multipart(b.bucket, k, upload_id, clean)
    except MinioError as e:
        raise StorageError(f"تکمیل آپلود ناموفق بود: {e}", 502) from None
    return {"key": k, "parts": len(clean)}


def multipart_cancel(db: Session, site: Site, name: str, key: str, upload_id: str) -> dict:
    b = find_bucket(db, site, name)
    cli = _require()
    try:
        cli.abort_multipart(b.bucket, validate_key(key), upload_id)
    except MinioError as e:
        raise StorageError(f"لغو آپلود ناموفق بود: {e}", 502) from None
    return {"ok": True}


def make_folder(db: Session, site: Site, name: str, key: str) -> dict:
    """A zero-byte object ending in "/" — what every S3 tool shows as a folder."""
    b = find_bucket(db, site, name)
    cli = _require()
    k = validate_key(key, folder=True)
    try:
        cli.put_object(b.bucket, k, b"")
    except MinioError as e:
        raise StorageError(f"ساخت پوشه ناموفق بود: {e}", 502) from None
    return {"key": k}


def rename_object(db: Session, site: Site, name: str, src: str, dst: str) -> dict:
    """Server-side copy + delete (S3 has no rename). Files only: renaming a folder would mean copying
    every key under it, which the file manager does not offer."""
    b = find_bucket(db, site, name)
    cli = _require()
    s, d = validate_key(src), validate_key(dst)
    if s == d:
        return {"key": d}
    try:
        cli.copy_object(b.bucket, s, d)
        cli.delete_object(b.bucket, s)
    except MinioError as e:
        raise StorageError(f"تغییر نام ناموفق بود: {e}", 502) from None
    return {"key": d}


def delete_objects(db: Session, site: Site, name: str, keys: list[str] | None = None,
                   prefixes: list[str] | None = None) -> dict:
    """Delete up to DELETE_MAX objects. A prefix (folder) is expanded server-side up to the same cap
    and `truncated` tells the caller to repeat — a folder of 100k files is many calls, never one
    request that times out."""
    b = find_bucket(db, site, name)
    cli = _require()
    todo: list[str] = []
    for k in (keys or [])[:DELETE_MAX]:
        todo.append(validate_key(k.rstrip("/") + "/" if str(k).endswith("/") else k,
                                 folder=str(k).endswith("/")))
    truncated = False
    for p in (prefixes or [])[:10]:
        pre = validate_key(p, folder=True)
        page = cli.list_objects(b.bucket, pre, "", DELETE_MAX, delimiter="")
        todo += [o["key"] for o in page["objects"]]
        if page["next_token"]:
            truncated = True
        else:
            # the folder itself last: SeaweedFS keeps buckets as a real directory tree, so an emptied
            # folder would otherwise stay in the listing (and the key is also the marker a plain S3
            # tool would have left behind)
            todo.append(pre)
    done, failed = 0, []
    for k in dict.fromkeys(todo):
        try:
            cli.delete_object(b.bucket, k)
            done += 1
        except MinioError as e:
            log.warning("storage: delete of %s failed: %s", b.bucket, e)
            failed.append(k)
    if failed and not done:
        raise StorageError("حذف فایل ناموفق بود", 502)
    return {"deleted": done, "failed": failed, "truncated": truncated}
