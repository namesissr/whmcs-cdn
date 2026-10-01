"""Log export to the customer's S3-compatible bucket (SPEC §14.3.2).

Flow: the edges sample a site's access-log records (edge config `logs: {enabled, sample_rate,
anonymize_ip}`) and POST them to /edge/v1/logship; the controller re-applies IP anonymization,
drops records of sites without `logs.enabled`, and spools one gzip JSON-lines chunk per POST per
site/hour (`log_spool`), capped at LOG_EXPORT_MAX_PER_HOUR records per site and hour (excess counted
as dropped). The leader (scheduler.job_log_export) uploads every completed hour as ONE object
`{prefix}{domain}/YYYY/MM/DD/HH-<8hex>.jsonl.gz` — the chunks concatenated, which is a valid gzip
stream (RFC 1952 multi-member) — with SigV4 path-style requests (backup.S3Client). A failure keeps
the chunks and is retried every 10 minutes; chunks older than 72 h are dropped and counted.

Uploads run on a small worker pool, never in the scheduler thread, so a slow or hostile bucket
cannot stall DNS failover; a per-site lease prevents two uploads of the same site at once. Every
upload re-runs the SSRF guard (netguard) and connects to the vetted address only. The secret key is
decrypted only to sign the request: it is never logged, stored in status or returned.

State keys: `logs:status:<site_id>` (JSON: last_upload_at, last_object, last_error, last_error_at,
lease_until) and `logs:dropped:<site_id>` (integer counter).
"""

import gzip
import ipaddress
import json
import logging
import secrets as pysecrets
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from . import kv, netguard, sections, site_secrets
from .config import settings
from .db import SessionLocal
from .models import LogSpool, Site, utcnow

log = logging.getLogger("pcdn.logs")

MAX_RECORDS_PER_POST = 5000
RETRY = timedelta(minutes=10)
MAX_AGE = timedelta(hours=72)
GRACE = timedelta(minutes=5)       # an hour is "completed" this long after it ends (late batches)
LEASE = timedelta(minutes=15)      # a site handed to the upload worker is not handed out again
FUTURE_SLACK = timedelta(minutes=5)
UPLOAD_TIMEOUT = 60.0
TEST_OBJECT = ".pcdn-test"
STATUS_KEY = "logs:status:{}"
DROPPED_KEY = "logs:dropped:{}"

_executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="pcdn-logs")


# ------------------------------------------------------------------ config

def effective(site: Site, cfg: dict | None = None, feats: dict | None = None) -> dict | None:
    """The site's logs section when export is effectively on (section enabled + plan feature),
    else None."""
    feats = feats if feats is not None else sections.features_of(site)
    cfg = cfg if cfg is not None else sections.get_section(site, "logs")
    if not feats.get("log_export") or not cfg.get("enabled"):
        return None
    return cfg


def edge_block(site: Site, cfg: dict, feats: dict) -> dict:
    """What an edge gets per site (SPEC §14.3.2): never the endpoint, bucket or keys."""
    return {"enabled": effective(site, cfg, feats) is not None, "sample_rate": cfg["sample_rate"],
            "anonymize_ip": cfg["anonymize_ip"]}


def apply_write(site: Site, value: dict) -> dict:
    """PUT logs: store a supplied secret_key encrypted (""/omitted keeps the stored one) and return
    the section as stored (no secret)."""
    if value.get("secret_key"):
        site_secrets.set_logs_secret(site, value["secret_key"])
    return sections.storable("logs", value)


# ------------------------------------------------------------------ ingestion (/edge/v1/logship)

def anonymize_ip(value: str) -> str:
    """IPv4: last octet zeroed; IPv6: only the first 48 bits kept. Idempotent; "" when invalid."""
    try:
        ip = ipaddress.ip_address(str(value).strip().strip("[]"))
    except ValueError:
        return ""
    bits = 24 if ip.version == 4 else 48
    return str(ipaddress.ip_network(f"{ip}/{bits}", strict=False).network_address)


def _str(v, n: int) -> str:
    return "" if v is None else str(v)[:n]


def _no_query(v, n: int) -> str:
    return _str(v, 8192).split("?", 1)[0].split("#", 1)[0][:n]


def _int(v, lo: int = 0, hi: int = 10**18) -> int:
    try:
        return max(lo, min(int(v), hi))
    except (TypeError, ValueError):
        return 0


def _float(v) -> float:
    try:
        f = float(v)
    except (TypeError, ValueError):
        return 0.0
    return round(f, 3) if 0 <= f < 10**9 else 0.0


def parse_time(v) -> datetime | None:
    """ISO-8601 -> naive UTC, or None."""
    if not isinstance(v, str) or not v:
        return None
    try:
        dt = datetime.fromisoformat(v.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


def clean_record(raw: dict, t: datetime, anonymize: bool) -> dict:
    """One normalised record as written to the export (field order kept stable)."""
    ip = _str(raw.get("ip"), 64).strip()
    if anonymize:
        ip = anonymize_ip(ip)
    else:
        try:
            ip = str(ipaddress.ip_address(ip.strip("[]")))
        except ValueError:
            ip = ""
    return {
        "t": t.isoformat(timespec="milliseconds") + "Z",
        "host": _str(raw.get("host"), 253).lower(),
        "ip": ip,
        "method": _str(raw.get("method"), 16),
        "scheme": _str(raw.get("scheme"), 8),
        "path": _no_query(raw.get("path"), 2048),
        "status": _int(raw.get("status"), 0, 999),
        "bytes": _int(raw.get("bytes")),
        "rt": _float(raw.get("rt")),
        "cache": _str(raw.get("cache"), 16),
        "country": _str(raw.get("country"), 2).upper(),
        "ua": _str(raw.get("ua"), 512),
        "referer": _no_query(raw.get("referer"), 1024),
        "proto": _str(raw.get("proto"), 16),
    }


def _gzip_lines(records: list[dict]) -> bytes:
    text = "".join(json.dumps(r, ensure_ascii=False, separators=(",", ":")) + "\n" for r in records)
    return gzip.compress(text.encode("utf-8"), compresslevel=6, mtime=0)


def ingest(db: Session, records: list, site_for_host, now: datetime | None = None) -> dict:
    """Spool one /edge/v1/logship body (already deduplicated on batch_id). Caller commits.
    Returns counters {accepted, dropped, ignored, invalid}."""
    now = now or utcnow()
    out = {"accepted": 0, "dropped": 0, "ignored": 0, "invalid": 0}
    sites: dict[int, dict | None] = {}
    groups: dict[tuple[int, datetime], list[dict]] = defaultdict(list)
    dropped: dict[int, int] = defaultdict(int)
    for raw in records:
        if not isinstance(raw, dict) or not isinstance(raw.get("host"), str):
            out["invalid"] += 1
            continue
        sid = site_for_host(raw["host"])
        if sid is None:
            out["ignored"] += 1
            continue
        if sid not in sites:
            site = db.get(Site, sid)
            sites[sid] = effective(site) if site is not None else None
        cfg = sites[sid]
        if cfg is None:  # export off for this site: the records are dropped (not counted)
            out["ignored"] += 1
            continue
        t = parse_time(raw.get("t"))
        if t is None:
            out["invalid"] += 1
            continue
        if t < now - MAX_AGE:
            dropped[sid] += 1
            continue
        t = min(t, now) if t > now + FUTURE_SLACK else t
        groups[(sid, t.replace(minute=0, second=0, microsecond=0))].append(
            clean_record(raw, t, cfg["anonymize_ip"]))
    cap = settings.log_export_max_per_hour
    for (sid, hour), recs in sorted(groups.items()):
        spooled = int(db.scalar(select(func.coalesce(func.sum(LogSpool.records), 0)).where(
            LogSpool.site_id == sid, LogSpool.hour == hour)) or 0)
        room = max(0, cap - spooled)
        keep = recs[:room]
        dropped[sid] += len(recs) - len(keep)
        if keep:
            db.add(LogSpool(site_id=sid, hour=hour, records=len(keep), data=_gzip_lines(keep), created_at=now))
            out["accepted"] += len(keep)
    for sid, n in dropped.items():
        kv.incr(db, DROPPED_KEY.format(sid), n)
        out["dropped"] += n
    return out


# ------------------------------------------------------------------ status

def _iso(v: str | None) -> str | None:
    return v + "Z" if v else None


def status(db: Session, site: Site) -> dict:
    """GET /api/v1/sites/{domain}/logs/status. last_error/last_error_at describe the CURRENT
    failure: a later successful upload clears them."""
    st = kv.get_json(db, STATUS_KEY.format(site.id))
    pending = db.scalar(select(func.coalesce(func.sum(LogSpool.records), 0)).where(LogSpool.site_id == site.id))
    return {
        "enabled": effective(site) is not None,
        "last_upload_at": _iso(st.get("last_upload_at")),
        "last_object": st.get("last_object"),
        "last_error": st.get("last_error"),
        "last_error_at": _iso(st.get("last_error_at")),
        "pending_records": int(pending or 0),
        "dropped_records": kv.get_int(db, DROPPED_KEY.format(site.id)),
    }


# ------------------------------------------------------------------ S3

def object_key(cfg: dict, domain: str, hour: datetime) -> str:
    return f"{cfg['prefix']}{domain}/{hour:%Y/%m/%d/%H}-{pysecrets.token_hex(4)}.jsonl.gz"


def _put(cfg: dict, secret: str, key: str, data: bytes, content_type: str) -> None:
    """One PUT to the customer's bucket: SSRF re-check, then a connection to the vetted address."""
    from .backup import S3Client

    target = netguard.vet(cfg["s3_endpoint"])
    s3 = S3Client(cfg["s3_endpoint"], cfg["bucket"], cfg["access_key"], secret, cfg["region"],
                  transport=netguard.PinnedTransport(target), timeout=UPLOAD_TIMEOUT)
    try:
        s3.put_bytes(key, data, content_type)
    finally:
        s3.close()


def _error_text(e: Exception) -> str:
    if isinstance(e, netguard.UnsafeTarget):
        return str(e)[:500]
    return f"{type(e).__name__}: {e}"[:500]


def _credentials(site: Site, cfg: dict) -> tuple[str | None, str | None]:
    """(secret, error): the decrypted secret key or a Persian reason why the config is unusable."""
    if not (cfg["s3_endpoint"] and cfg["bucket"] and cfg["access_key"]):
        return None, "تنظیمات خروجی لاگ کامل نیست (آدرس S3، باکت و کلیدها لازم است)"
    try:
        secret = site_secrets.logs_secret(site)
    except Exception:  # noqa: BLE001 - CryptoError: lost DATA_ENCRYPTION_KEY
        return None, "کلید مخفی ذخیره‌شده قابل خواندن نیست؛ آن را دوباره وارد کنید"
    if not secret:
        return None, "کلید مخفی (secret_key) ثبت نشده است"
    return secret, None


def test_upload(db: Session, site: Site) -> dict:
    """POST .../logs/test: write a tiny `{prefix}{domain}/.pcdn-test` object with the SAVED
    settings (enabled or not) -> {ok, error}. The status document is not touched."""
    cfg = sections.get_section(site, "logs")
    secret, error = _credentials(site, cfg)
    domain = site.domain
    db.rollback()  # no transaction is held open across the network call
    if error:
        return {"ok": False, "error": error}
    body = f"pasargad cdn log export test {utcnow().isoformat(timespec='seconds')}Z\n".encode()
    try:
        _put(cfg, secret, f"{cfg['prefix']}{domain}/{TEST_OBJECT}", body, "text/plain")
    except Exception as e:  # noqa: BLE001 - reported to the customer
        return {"ok": False, "error": _error_text(e)}
    return {"ok": True, "error": None}


# ------------------------------------------------------------------ leader job

def _drop_expired(db: Session, now: datetime) -> int:
    rows = db.execute(select(LogSpool.site_id, func.sum(LogSpool.records))
                      .where(LogSpool.created_at < now - MAX_AGE).group_by(LogSpool.site_id)).all()
    total = 0
    for sid, n in rows:
        kv.incr(db, DROPPED_KEY.format(sid), int(n or 0))
        total += int(n or 0)
    if rows:
        db.execute(delete(LogSpool).where(LogSpool.created_at < now - MAX_AGE))
        log.warning("log export: dropped %d record(s) older than 72 h that could not be uploaded", total)
    return total


def _parse(v: str | None) -> datetime | None:
    try:
        return datetime.fromisoformat(v) if v else None
    except ValueError:
        return None


def completed_before(now: datetime) -> datetime:
    """Hours strictly before this one are completed (ended at least GRACE ago)."""
    return (now - GRACE).replace(minute=0, second=0, microsecond=0)


def run_uploads(db: Session, now: datetime | None = None, wait: bool = False) -> list[int]:
    """Leader job body: drop chunks older than 72 h, then hand every site that has a completed hour
    (and is not leased / inside its 10-minute retry wait) to the upload worker. Returns the site ids
    handed out; `wait` blocks until they are done (tests)."""
    now = now or utcnow()
    _drop_expired(db, now)
    before = completed_before(now)
    site_ids = sorted({sid for (sid,) in db.execute(
        select(LogSpool.site_id).where(LogSpool.hour < before).distinct())})
    handed = []
    for sid in site_ids:
        site = db.get(Site, sid)
        key = STATUS_KEY.format(sid)
        st = kv.get_json(db, key)
        lease = _parse(st.get("lease_until"))
        if lease is not None and lease > now:
            continue
        failed_at = _parse(st.get("last_error_at"))
        if failed_at is not None and now - failed_at < RETRY:
            continue
        if site is None or effective(site) is None:
            # export switched off (or plan feature removed): what is left is discarded, not uploaded
            db.execute(delete(LogSpool).where(LogSpool.site_id == sid, LogSpool.hour < before))
            continue
        st["lease_until"] = (now + LEASE).isoformat()
        kv.set_json(db, key, st)
        handed.append((sid, st["lease_until"]))
    db.commit()
    futures = [_executor.submit(_upload_site, sid, before, now, lease) for sid, lease in handed]
    if wait:
        for f in futures:
            f.result()
    return [sid for sid, _ in handed]


def _upload_site(site_id: int, before: datetime, now: datetime, lease: str) -> None:
    """Worker: upload each completed hour of one site as one object; stop at the first failure,
    or as soon as the site's lease is no longer ours (it expired and the site was handed out again)."""
    db = SessionLocal()
    key = STATUS_KEY.format(site_id)
    try:
        site = db.get(Site, site_id)
        cfg = effective(site) if site is not None else None
        if cfg is None:
            return
        secret, error = _credentials(site, cfg)
        hours = [h for (h,) in db.execute(select(LogSpool.hour).where(
            LogSpool.site_id == site_id, LogSpool.hour < before).distinct().order_by(LogSpool.hour))]
        domain = site.domain
        for hour in hours:
            if kv.get_json(db, key, fresh=True).get("lease_until") != lease:
                return
            rows = db.execute(select(LogSpool.id, LogSpool.data).where(
                LogSpool.site_id == site_id, LogSpool.hour == hour).order_by(LogSpool.id)).all()
            if not rows:
                continue
            obj = object_key(cfg, domain, hour)
            data = b"".join(r.data for r in rows)
            db.rollback()  # never hold a transaction open across the upload
            try:
                if error:
                    raise RuntimeError(error)
                _put(cfg, secret, obj, data, "application/gzip")
            except Exception as e:  # noqa: BLE001 - kept and retried in 10 minutes
                message = error or _error_text(e)
                log.warning("log export for %s failed (retry in 10 min): %s", domain, message)
                st = kv.get_json(db, key)
                st.update(last_error=message, last_error_at=now.isoformat())
                kv.set_json(db, key, st)
                db.commit()
                return
            db.execute(delete(LogSpool).where(LogSpool.id.in_([r.id for r in rows])))
            st = kv.get_json(db, key)
            st.update(last_upload_at=now.isoformat(), last_object=obj, last_error=None, last_error_at=None)
            kv.set_json(db, key, st)
            db.commit()
    except Exception:  # noqa: BLE001 - a worker never dies loudly; the lease expires and it retries
        log.exception("log export worker failed for site %s", site_id)
        db.rollback()
    finally:
        try:
            st = kv.get_json(db, key, fresh=True)
            if st.get("lease_until") == lease:
                st["lease_until"] = None
                kv.set_json(db, key, st)
                db.commit()
        except Exception:  # noqa: BLE001
            db.rollback()
        db.close()
