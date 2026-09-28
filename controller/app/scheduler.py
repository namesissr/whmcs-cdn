"""Background jobs: edge failover, NS verification, SSL issue/renew, quota, cleanup."""

import logging
import threading
from datetime import timedelta

from sqlalchemy import delete, or_, select

from . import nscheck, ssl
from .config import settings
from .db import SessionLocal
from .models import Purge, Site, State, UsageHourly, utcnow
from .routes_v2 import prune_events
from .services import online_edges, refresh_quota, sync_all_dns, sync_site_dns

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


def job_edges(db):
    """Resync every zone when the set of healthy edges changes."""
    current = ",".join(f"{e.id}:{e.ipv4}:{e.ipv6 or ''}:{e.region}" for e in online_edges(db))
    if current != _state(db, "online_edges"):
        log.info("edge set changed -> %s", current or "(none)")
        failed = sync_all_dns(db)
        if failed == 0:
            _set_state(db, "online_edges", current)
        db.commit()


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


def job_ssl(db):
    renew_before = utcnow() + timedelta(days=30)
    for site in db.scalars(select(Site).where(
        Site.ssl_status == "active", Site.ssl_allowed.is_(True), Site.ssl_expires_at < renew_before,
        or_(Site.ssl_source.is_(None), Site.ssl_source != "custom"),  # customers renew their own certs
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
    try:
        ssl.issue(site)
    except Exception as e:  # noqa: BLE001
        log.error("certificate for %s failed: %s", site.domain, e)
        # keep serving the old (still valid) cert on renewal failure
        site.ssl_status = "active" if had_cert else "failed"
        site.ssl_error = str(e)[-2000:]
    db.commit()


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


JOBS = [job_edges, job_ns, job_quota, job_cleanup, job_ssl]


def run_once():
    for job in JOBS:
        db = SessionLocal()
        try:
            job(db)
        except Exception:  # noqa: BLE001
            log.exception("job %s failed", job.__name__)
            db.rollback()
        finally:
            db.close()


class Scheduler(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True, name="pcdn-scheduler")
        self.stop_event = threading.Event()

    def run(self):
        while not self.stop_event.is_set():
            run_once()
            self.stop_event.wait(settings.scheduler_interval)
