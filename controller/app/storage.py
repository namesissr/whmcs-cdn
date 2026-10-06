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

import logging
import re
import secrets
from datetime import datetime, timedelta

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
        _client = SeaweedClient(*args, metrics_path=settings.storage_metrics_path)
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

def edge_origin(b: StorageBucket) -> dict:
    """The `origin.storage` block of an edge host (SPEC §16.8): fetch over TLS from `host:port`
    (SNI + certificate verification for `host`), `Host: host_header`, URI = path_prefix + the
    request path (path-style S3, no query string), `Referer: referer`. GET/HEAD only."""
    u = httpx.URL(public_endpoint())
    tls = u.scheme == "https"
    host = u.host
    port = u.port or (443 if tls else 80)
    host_header = (f"[{host}]" if ":" in host else host) + (f":{u.port}" if u.port else "")
    return {"host": host, "port": port, "tls": tls, "host_header": host_header, "bucket": b.bucket,
            "path_prefix": f"{u.path.rstrip('/')}/{b.bucket}", "referer": b.origin_token}


def edge_buckets(db: Session) -> dict[tuple[int, str], StorageBucket]:
    """(site id, bucket name) -> row, for build_edge_config; empty when storage is not available."""
    if not available():
        return {}
    return {(b.site_id, b.name): b for b in db.scalars(select(StorageBucket))}
