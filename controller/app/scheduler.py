"""Background jobs: edge failover, NS verification, SSL issue/renew, quota, cleanup,
alerts and backups.

Only one controller instance runs them: every tick the Scheduler asks its leader
elector (app/leader.py) whether this instance leads; followers just wait.
"""

import logging
import threading
from datetime import datetime, timedelta

from sqlalchemy import delete, or_, select

from . import alerts, nscheck, ssl
from .config import settings
from .db import SessionLocal
from .leader import instance_id, make_elector
from .models import Purge, Site, State, UsageHourly, utcnow
from .routes_v2 import prune_events
from .services import DNS_DIRTY_KEY, online_edges, refresh_quota, sync_all_dns, sync_site_dns

log = logging.getLogger("pcdn.scheduler")


def _state(db, key: str) -> str:
    row = db.get(State, key)
    return row.value if row else ""


def _set_state(db, key: str, value: str):
    row = db.get(State, key)
    if row is None:
        db.add(State(key=key, value=value))
    else:
        row.value = value


def edge_reports_trusted(db, now: datetime | None = None) -> bool:
    """False for EDGE_OFFLINE_SECONDS after the scheduler resumes from an outage.

    While no controller was running, edges could not report, so their last_seen_at is
    stale. Acting on it right away would pull every edge out of DNS (and alert) at once;
    instead the scheduler waits one offline period for the agents to check in again.
    PowerDNS keeps health-checking the edges itself in the meantime.
    """
    resumed = _state(db, "scheduler:resumed_at")
    if not resumed:
        return True
    now = now or utcnow()
    return now - datetime.fromisoformat(resumed) >= timedelta(seconds=settings.edge_offline_seconds)


def note_resume(db, now: datetime | None = None):
    now = now or utcnow()
    last = _state(db, "scheduler:last_run")
    if last and now - datetime.fromisoformat(last) > timedelta(seconds=settings.edge_offline_seconds):
        log.warning("scheduler resumes after %s without a run: trusting edge reports again in %ss",
                    now - datetime.fromisoformat(last), settings.edge_offline_seconds)
        _set_state(db, "scheduler:resumed_at", now.isoformat())
        db.commit()


def job_edges(db):
    """Resync every zone when the set of healthy edges changes, or after a failed DNS write."""
    if not edge_reports_trusted(db):
        return
    current = ",".join(f"{e.id}:{e.ipv4}:{e.ipv6 or ''}:{e.region}" for e in online_edges(db))
    dirty = db.get(State, DNS_DIRTY_KEY) is not None
    if current == _state(db, "online_edges") and not dirty:
        return
    if current != _state(db, "online_edges"):
        log.info("edge set changed -> %s", current or "(none)")
    else:
        log.info("re-syncing DNS after an earlier failure")
    server_errors: dict[int, str] = {}
    failed = sync_all_dns(db, server_errors)
    if failed == 0:
        _set_state(db, "online_edges", current)
        row = db.get(State, DNS_DIRTY_KEY)
        if row is not None:
            db.delete(row)
    db.commit()
    _dns_sync_alerts(failed, server_errors)


def _dns_sync_alerts(failed: int, server_errors: dict[int, str]):
    from .pdns import client

    try:
        servers = client().clients
    except Exception:  # noqa: BLE001
        servers = []
    active = {}
    for idx, err in server_errors.items():
        label = alerts.pdns_server_label(idx, servers[idx].base) if 0 <= idx < len(servers) else "PowerDNS"
        active[f"dns_sync:{idx}"] = (
            f"همگام‌سازی DNS روی {label} ناموفق بود",
            f"نوشتن {failed} زون روی {label} ناموفق بود؛ کنترلر هر دقیقه دوباره تلاش می‌کند.\n"
            f"خطا: {err[:500]}",
            "critical",
        )
    alerts.sync("dns_sync:", active, lambda c: "همگام‌سازی DNS دوباره موفق شد و همه زون‌ها به‌روز هستند.")


def job_ns(db):
    cutoff = utcnow() - timedelta(seconds=settings.ns_check_interval)
    sites = db.scalars(select(Site).where(
        Site.status == "pending_ns",
        or_(Site.ns_checked_at.is_(None), Site.ns_checked_at < cutoff),
    ).limit(50))
    for site in sites:
        try:
            ok, _ = nscheck.check_and_update(site)
            db.commit()
            if ok:
                sync_site_dns(db, site)
        except Exception:  # noqa: BLE001
            log.exception("ns check failed for %s", site.domain)
            db.rollback()


# after a failed renewal the old certificate is still valid: wait before trying again
# (Let's Encrypt allows only a few failed validations per hostname per hour)
SSL_RENEW_RETRY = timedelta(hours=6)


def job_ssl(db):
    renew_before = utcnow() + timedelta(days=30)
    for site in db.scalars(select(Site).where(
        Site.ssl_status == "active", Site.ssl_allowed.is_(True), Site.ssl_expires_at < renew_before,
        or_(Site.ssl_source.is_(None), Site.ssl_source != "custom"),  # customers renew their own certs
        or_(Site.ssl_error.is_(None), Site.updated_at < utcnow() - SSL_RENEW_RETRY),
    )):
        site.ssl_status = "pending"
    db.commit()

    site = db.scalar(select(Site).where(
        Site.ssl_status == "pending", Site.ns_verified_at.is_not(None), Site.ssl_allowed.is_(True)
    ).order_by(Site.updated_at).limit(1))
    if site is None:
        return
    log.info("issuing certificate for %s", site.domain)
    had_cert = bool(site.ssl_cert)
    domain = site.domain
    try:
        ssl.issue(site)
        error = None
    except Exception as e:  # noqa: BLE001
        log.error("certificate for %s failed: %s", domain, e)
        # keep serving the old (still valid) cert on renewal failure
        site.ssl_status = "active" if had_cert else "failed"
        site.ssl_error = error = str(e)[-2000:]
    db.commit()
    key = f"ssl_failed:{domain}"
    if error is None:
        alerts.resolve_alert(key, f"گواهی {domain} با موفقیت صادر/تمدید شد.")
    else:
        what = "تمدید" if had_cert else "صدور"
        extra = " گواهی قبلی هنوز معتبر است و سرو می‌شود." if had_cert else ""
        alerts.raise_alert(key, f"{what} گواهی {domain} ناموفق بود",
                           f"{what} گواهی Let's Encrypt برای {domain} ناموفق بود.{extra}\nخطا:\n{error[-600:]}")


def job_quota(db):
    for site in db.scalars(select(Site)):
        if refresh_quota(db, site):
            log.info("%s over_quota=%s", site.domain, site.over_quota)
    db.commit()


def job_cleanup(db):
    db.execute(delete(Purge).where(Purge.created_at < utcnow() - timedelta(days=2)))
    db.execute(delete(UsageHourly).where(UsageHourly.hour < utcnow() - timedelta(days=400)))
    prune_events(db)
    db.commit()


def job_alerts(db):
    alerts.check_all(db, edges=edge_reports_trusted(db))


BACKUP_RETRY = timedelta(hours=1)


def job_backup(db, now: datetime | None = None, force: bool = False):
    """Daily backup at BACKUP_HOUR (UTC); a missed hour runs later the same day."""
    if not settings.backup_enabled and not force:
        return
    from . import backup

    now = now or utcnow()
    today = now.date().isoformat()
    if not force:
        if now.hour < settings.backup_hour or _state(db, "backup:last_success_day") == today:
            return
        last_fail = _state(db, "backup:last_failure_at")
        if last_fail and now - datetime.fromisoformat(last_fail) < BACKUP_RETRY:
            return
    db.rollback()  # do not hold a transaction open while dumping the database
    try:
        result = backup.create_backup(now=now)
    except Exception as e:  # noqa: BLE001
        log.exception("backup failed")
        _set_state(db, "backup:last_failure_at", now.isoformat())
        _set_state(db, "backup:last_error", str(e)[-1000:])
        db.commit()
        alerts.raise_alert("backup_failed", "پشتیبان‌گیری ناموفق بود",
                           f"پشتیبان‌گیری خودکار کنترلر ناموفق بود؛ یک ساعت بعد دوباره تلاش می‌شود.\n"
                           f"خطا: {str(e)[-600:]}", "critical")
        return
    _set_state(db, "backup:last_success_day", today)
    _set_state(db, "backup:last_success_at", now.isoformat())
    _set_state(db, "backup:last_file", result["name"])
    _set_state(db, "backup:last_failure_at", "")
    db.commit()
    alerts.resolve_alert("backup_failed", f"پشتیبان‌گیری دوباره موفق شد: {result['name']}"
                         + (" (در فضای ابری هم بارگذاری شد)" if result.get("uploaded") else ""))


JOBS = [job_edges, job_alerts, job_ns, job_quota, job_cleanup, job_ssl, job_backup]


def run_once():
    db = SessionLocal()
    try:
        note_resume(db)
    except Exception:  # noqa: BLE001
        log.exception("could not check the previous scheduler run")
        db.rollback()
    finally:
        db.close()
    for job in JOBS:
        db = SessionLocal()
        failed = None
        try:
            job(db)
        except Exception as e:  # noqa: BLE001
            log.exception("job %s failed", job.__name__)
            db.rollback()
            failed = e
        finally:
            db.close()
        key = f"job_failed:{job.__name__}"
        if failed is not None:
            alerts.raise_alert(key, f"خطا در کار زمان‌بندی‌شده {job.__name__}",
                               f"کار {job.__name__} در کنترلر {instance_id()} با خطا متوقف شد:\n"
                               f"{type(failed).__name__}: {str(failed)[:600]}\nجزئیات در لاگ کنترلر.")
        else:
            alerts.resolve_alert(key, f"کار {job.__name__} دوباره بدون خطا اجرا شد.")


def record_run():
    db = SessionLocal()
    try:
        _set_state(db, "scheduler:last_run", utcnow().isoformat())
        _set_state(db, "scheduler:leader", instance_id())
        db.commit()
    except Exception:  # noqa: BLE001
        log.exception("could not record scheduler run")
        db.rollback()
    finally:
        db.close()


# the Scheduler of this process (for /healthz/deep)
current: "Scheduler | None" = None


class Scheduler(threading.Thread):
    def __init__(self, elector=None, interval: float | None = None, work=None):
        super().__init__(daemon=True, name="pcdn-scheduler")
        self.stop_event = threading.Event()
        self.elector = elector if elector is not None else make_elector()
        self.interval = settings.scheduler_interval if interval is None else interval
        self.work = work or run_once
        self.is_leader = False

    def tick(self) -> bool:
        """One scheduler iteration; returns True when this instance led (and ran the jobs)."""
        try:
            leading = self.elector.check()
        except Exception:  # noqa: BLE001
            log.exception("leader election failed")
            leading = False
        if leading != self.is_leader:
            log.info("instance %s is now the scheduler %s", instance_id(), "LEADER" if leading else "follower")
        self.is_leader = leading
        if not leading:
            return False
        self.work()
        record_run()
        return True

    def run(self):
        try:
            while not self.stop_event.is_set():
                try:
                    self.tick()
                except Exception:  # noqa: BLE001
                    log.exception("scheduler tick failed")
                self.stop_event.wait(self.interval)
        finally:
            self.release()

    def release(self):
        try:
            self.elector.release()
        except Exception:  # noqa: BLE001
            log.exception("releasing leadership failed")
        self.is_leader = False

    def stop(self, timeout: float = 10):
        self.stop_event.set()
        if self.is_alive():
            self.join(timeout)
