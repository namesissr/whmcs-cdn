"""Backup / restore-test run history, queueing and the admin status view (SPEC §23.3).

The admin API queues a run (`backup:queued` / `backup_verify:queued` state flags); the scheduler leader
picks it up within one tick. Every run is a `backup_runs` row (newest 200 kept) whose error text went
through `backup.scrub()`: no passphrase, S3 key, data key, URL credentials or signature ever lands in a
row, an alert or a log line.
"""

import json
from datetime import datetime, timedelta

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from . import alerts, backup, kv
from .config import settings
from .models import BackupRun, State, utcnow

KEEP = 200
QUEUE = {"backup": "backup:queued", "verify": "backup_verify:queued"}
PARTIAL_STREAK = "backup_verify:partial_streak"


def _iso(dt: datetime | None) -> str | None:
    return dt.isoformat() + "Z" if dt else None


def run_dict(r: BackupRun | None) -> dict | None:
    if r is None:
        return None
    try:
        checks = json.loads(r.checks or "{}")
    except ValueError:
        checks = {}
    return {"id": r.id, "kind": r.kind, "started_at": _iso(r.started_at), "finished_at": _iso(r.finished_at),
            "ok": r.ok, "name": r.name, "size": r.size, "location": r.location, "level": r.level,
            "checks": checks if isinstance(checks, dict) else {}, "error": r.error}


def start(db: Session, kind: str, now: datetime | None = None) -> BackupRun:
    r = BackupRun(kind=kind, started_at=now or utcnow(), checks="{}")
    db.add(r)
    db.commit()
    return r


def finish(db: Session, r: BackupRun, ok: bool, now: datetime | None = None, **fields) -> None:
    r.finished_at = now or utcnow()
    r.ok = ok
    for k, v in fields.items():
        if k == "checks":
            v = json.dumps(v or {})
        if k == "error" and v is not None:
            v = backup.scrub(v)
        setattr(r, k, v)
    db.commit()
    ids = [i for (i,) in db.execute(select(BackupRun.id).order_by(BackupRun.id.desc()).offset(KEEP))]
    if ids:
        db.execute(delete(BackupRun).where(BackupRun.id.in_(ids)))
        db.commit()


def queue(db: Session, kind: str) -> bool:
    """Set the queue flag; False (-> 409) when one is already queued or running."""
    key = QUEUE[kind]
    if kv.get_json(db, key, fresh=True).get("state") in ("queued", "running"):
        return False
    kv.set_json(db, key, {"state": "queued", "at": utcnow().isoformat()})
    db.commit()
    return True


def take(db: Session, kind: str) -> bool:
    key = QUEUE[kind]
    if kv.get_json(db, key, fresh=True).get("state") != "queued":
        return False
    kv.set_json(db, key, {"state": "running", "at": utcnow().isoformat()})
    db.commit()
    return True


def done(db: Session, kind: str) -> None:
    row = db.get(State, QUEUE[kind])
    if row is not None:
        db.delete(row)
        db.commit()


def last(db: Session, kind: str) -> BackupRun | None:
    return db.scalar(select(BackupRun).where(BackupRun.kind == kind, BackupRun.finished_at.is_not(None))
                     .order_by(BackupRun.id.desc()).limit(1))


def status(db: Session) -> dict:
    runs = list(db.scalars(select(BackupRun).order_by(BackupRun.id.desc()).limit(30)))
    try:
        encrypted = bool(backup.backup_key())
    except backup.BackupError:
        encrypted = False
    return {
        "enabled": settings.backup_enabled,
        "encrypted": encrypted,
        "offsite": backup.S3Client.from_settings() is not None,
        "schedule": {"backup_hour": settings.backup_hour,
                     "verify": {"enabled": settings.backup_verify_enabled, "weekday": settings.backup_verify_weekday,
                                "hour": settings.backup_verify_hour,
                                "scratch_db": bool(settings.backup_verify_database_url)}},
        "last_backup": run_dict(last(db, "backup")),
        "last_verify": run_dict(last(db, "verify")),
        "runs": [run_dict(r) for r in runs],
        "remote": backup.remote_summary(),
    }


def offsite_alerts(encrypted: bool) -> None:
    """backup_not_offsite (info, while BACKUP_ENABLED without S3) and backup_unencrypted_offsite."""
    offsite = backup.S3Client.from_settings() is not None
    if settings.backup_enabled and not offsite:
        alerts.raise_alert("backup_not_offsite", "پشتیبان‌ها فقط روی همین سرور نگه داشته می‌شوند",
                           "BACKUP_S3_* تنظیم نشده است؛ با از دست رفتن این سرور پشتیبان‌ها هم از دست می‌روند. "
                           "یک فضای ذخیره‌سازی S3 خارج از سرور تنظیم کنید.", "info")
    else:
        alerts.resolve_alert("backup_not_offsite", notify=False)
    if offsite and not encrypted:
        alerts.raise_alert("backup_unencrypted_offsite", "پشتیبان بدون رمزنگاری به فضای ابری فرستاده می‌شود",
                           "BACKUP_ENCRYPTION_KEY تنظیم نشده است؛ پشتیبان‌های خارج از سرور رمزنگاری نمی‌شوند. "
                           "کلید را تنظیم کنید (یا BACKUP_REQUIRE_ENCRYPTION=true تا بارگذاری بدون رمز رد شود).",
                           "warning")
    else:
        alerts.resolve_alert("backup_unencrypted_offsite", notify=False)


def verify_due(db: Session, now: datetime) -> bool:
    if not settings.backup_verify_enabled:
        return False
    if now.weekday() != settings.backup_verify_weekday or now.hour < settings.backup_verify_hour:
        return False
    r = last(db, "verify")
    return r is None or now - r.started_at > timedelta(hours=20)


def record_verify_alerts(db: Session, result: dict) -> None:
    if not result["ok"]:
        alerts.raise_alert("backup_verify_failed", "آزمون بازیابی پشتیبان ناموفق بود",
                           f"آزمون خودکار بازیابی آخرین پشتیبان ({result.get('name')}) ناموفق بود: "
                           f"{backup.scrub(result.get('error'))[:500]}", "critical")
        return
    alerts.resolve_alert("backup_verify_failed", f"آزمون بازیابی پشتیبان دوباره موفق شد ({result.get('name')}).")
    streak = kv.get_json(db, PARTIAL_STREAK).get("n", 0)
    streak = streak + 1 if result.get("level") == "partial" else 0
    kv.set_json(db, PARTIAL_STREAK, {"n": streak})
    db.commit()
    if streak >= 2:
        alerts.raise_alert("backup_verify_partial", "آزمون بازیابی فقط در سطح جزئی انجام می‌شود",
                           "دو هفتهٔ پیاپی آزمون بازیابی PostgreSQL بدون پایگاه آزمایشی (BACKUP_VERIFY_DATABASE_URL) "
                           "فقط در سطح جزئی انجام شد؛ برای اثبات کامل بازیابی یک پایگاه آزمایشی تنظیم کنید.", "info")
    else:
        alerts.resolve_alert("backup_verify_partial", notify=False)
