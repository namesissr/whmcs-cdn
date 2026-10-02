"""Background jobs: edge failover, NS verification, SSL issue/renew, quota, cleanup,
alerts and backups.

Only one controller instance runs them: every tick the Scheduler asks its leader
elector (app/leader.py) whether this instance leads; followers just wait.
"""

import logging
import threading
import time
from datetime import datetime, timedelta

from sqlalchemy import and_, delete, or_, select

from . import alerts, dnsbuild, geocheck, live, logexport, nscheck, ssl, tunnel_quality, uptime, webhooks
from .config import settings
from .db import SessionLocal
from .leader import instance_id, make_elector
from .models import Purge, Site, State, UsageBatch, UsageHourly, utcnow
from .routes_v2 import prune_events
from .services import (
    DNS_DIRTY_KEY,
    online_edges,
    rebalance_pool_shed,
    refresh_quota,
    sync_all_dns,
    sync_site_dns,
)

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


def dns_signature() -> str:
    return ";".join([dnsbuild.BUILD_VERSION, str(settings.geoip_enabled), ",".join(settings.geo_home_countries),
                     settings.geo_no_ecs_pool, ",".join(settings.geo_no_ecs_resolvers),
                     ",".join(settings.geo_no_ecs_countries), settings.geo_unknown_pool,
                     settings.lua_selector, settings.tunnel_lua_selector, str(settings.edge_probe),
                     settings.health_url, str(settings.geo_log)])


def edge_dns_state(e) -> str:
    """Per-edge fingerprint of everything that changes a zone's edge answers: identity, region,
    group, load shedding, and — for multi-address failover (SPEC §12) — the advertised state of
    the primary and of every additional address (health, enable/disable, add/remove)."""
    flags = [f"{e.id}:{e.ipv4}:{e.ipv6 or ''}:{e.region}:{e.group}:{int(dnsbuild.is_shed(e))}",
             # F32: the primary's IPv4 and IPv6 advertise independently, so a per-family change
             # (one family withdrawn/restored) still triggers a zone rewrite
             f"p4{int(dnsbuild.address_advertised(True, e.probe_ok4, e.probe_fail4))}",
             f"p6{int(dnsbuild.address_advertised(True, e.probe_ok6, e.probe_fail6))}"]
    for a in sorted(e.addresses, key=lambda a: a.id):
        flags.append(f"a{a.id}:{a.family}:{a.ip}:{int(a.enabled)}:"
                     f"{int(dnsbuild.address_advertised(a.enabled, a.probe_ok, a.probe_fail))}")
    return "/".join(flags)


SILENT_GUARD_ALERT = "edge_fleet_silent"


def _bulk_went_silent(db, edges: list) -> bool:
    """F10: is this a control-plane outage rather than many nodes dying at once?

    The DNS edge set follows the control-plane heartbeat. If the online (heartbeating) set suddenly
    collapses — more than EDGE_SILENT_GUARD_FRACTION of the previously-published edges go silent in
    one step — that is far more likely the edges losing the controller than a simultaneous mass node
    death, so we keep publishing the last-known DNS and raise a critical alert instead of emptying or
    drastically shrinking the pool (fail-static, same spirit as SPEC §12.3 fail-open).

    Armed only when EDGE_PROBE is on, because PowerDNS ifurlup then still removes a genuinely dead
    edge from within its pool in ~5s — so a real single-node failure is handled at the data plane and
    never reaches this guard, while a bulk go-silent is held here. DNS still reacts to genuine
    reachability, never to any filtering signal. A fresh install (nothing published yet) is let
    through so the first real edge set is published normally (see test_api fresh-install fallback)."""
    if not settings.edge_probe or settings.edge_silent_guard_fraction <= 0:
        alerts.resolve_alert(SILENT_GUARD_ALERT, "مجموعه نودهای فعال دوباره پایدار است.")
        return False
    prev_ids = _state(db, "online_edge_ids")
    prev = {p for p in prev_ids.split(",") if p}
    now_ids = {str(e.id) for e in edges}
    if not prev or now_ids >= prev:  # fresh install, or the set is stable / grew
        alerts.resolve_alert(SILENT_GUARD_ALERT, "مجموعه نودهای فعال دوباره پایدار است.")
        return False
    lost = prev - now_ids
    if len(lost) / len(prev) <= settings.edge_silent_guard_fraction:
        alerts.resolve_alert(SILENT_GUARD_ALERT, "مجموعه نودهای فعال دوباره پایدار است.")
        return False
    log.warning("F10 guard: %d/%d online edges went silent at once; keeping last-known DNS",
                len(lost), len(prev))
    alerts.raise_alert(
        SILENT_GUARD_ALERT, "افت ناگهانی نودهای فعال (احتمال قطعی مسیر کنترلر)",
        f"{len(lost)} نود از {len(prev)} نودی که در DNS منتشر شده بودند هم‌زمان از دسترس کنترلر خارج "
        f"شدند. این معمولاً یعنی نودها به کنترلر نمی‌رسند، نه اینکه واقعاً از کار افتاده باشند؛ برای "
        f"جلوگیری از خالی/کوچک شدن استخر DNS، آخرین وضعیت شناخته‌شده حفظ می‌شود و PowerDNS با پروب "
        f"مستقیم، نودهای واقعاً از کارافتاده را ظرف چند ثانیه از استخر حذف می‌کند.", "critical")
    return True


def job_edges(db):
    """Resync every zone when the set of healthy edges changes, or after a failed DNS write."""
    if not edge_reports_trusted(db):
        return
    # F25: keep pool-level load shedding from herding a region before we (re)build zones
    rebalance_pool_shed(db)
    edges = online_edges(db)
    # F10: a bulk "went silent" is treated as a control-plane outage, not many node deaths
    if _bulk_went_silent(db, edges):
        return
    # the DNS settings and the record format are part of the state: changing GEOIP_ENABLED,
    # GEO_* or upgrading the controller rewrites every zone on the next tick
    # group and load shedding decide which edges answer (dnsbuild.dns_edges): part of the state too
    # per-address advertisement (probe health / enable / add-remove) is part of the state too (§12)
    current = ",".join(edge_dns_state(e) for e in edges) + "|" + dns_signature()
    dirty = db.get(State, DNS_DIRTY_KEY) is not None
    if current == _state(db, "online_edges") and not dirty:
        # DNS already matches the live edge set: record the freshness for the /metrics age
        _set_state(db, "dns:last_sync_at", utcnow().isoformat())
        db.commit()
        return
    if current != _state(db, "online_edges"):
        log.info("edge set changed -> %s", current or "(none)")
    else:
        log.info("re-syncing DNS after an earlier failure")
    server_errors: dict[int, str] = {}
    failed = sync_all_dns(db, server_errors)
    if failed == 0:
        _set_state(db, "online_edges", current)
        _set_state(db, "online_edge_ids", ",".join(sorted(str(e.id) for e in edges)))
        _set_state(db, "dns:last_sync_at", utcnow().isoformat())  # metrics: DNS last-sync age
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
    # F2: renew IN PLACE — never flip a due "active" site to "pending" first. The old flip removed
    # nothing on its own, but it churned status and, together with the pre-F2 build_edge_config, could
    # drop the site's HTTPS server. Now a due site keeps ssl_status "active" (and keeps serving its
    # still-valid cert, F2 in services.build_edge_config) until ssl.issue() succeeds and sets active
    # again. Pick the single most-urgent site: one awaiting first issuance ("pending"), or an active
    # cert inside the 30-day renewal window (not a customer's own "custom" cert; respect the retry
    # backoff after a failure). Order by expiry so the closest-to-expiring renews first; a pending
    # site with no cert yet (NULL expiry) is taken first.
    renew_before = utcnow() + timedelta(days=30)
    not_custom = or_(Site.ssl_source.is_(None), Site.ssl_source != "custom")
    retry_ok = or_(Site.ssl_error.is_(None), Site.updated_at < utcnow() - SSL_RENEW_RETRY)
    site = db.scalar(select(Site).where(
        Site.ns_verified_at.is_not(None), Site.ssl_allowed.is_(True),
        or_(
            Site.ssl_status == "pending",
            and_(Site.ssl_status == "active", Site.ssl_expires_at < renew_before, not_custom, retry_ok),
        ),
    ).order_by(Site.ssl_expires_at.is_(None).desc(), Site.ssl_expires_at).limit(1))
    if site is None:
        return
    log.info("issuing certificate for %s", site.domain)
    had_cert = bool(site.ssl_cert)
    domain = site.domain
    try:
        ssl.issue(site)  # sets ssl_status active, clears ssl_error, stores the new cert
        error = None
    except Exception as e:  # noqa: BLE001
        log.error("certificate for %s failed: %s", domain, e)
        # renewal failure: leave the still-valid cert active and served; set only the error + the
        # updated_at that arms SSL_RENEW_RETRY. Initial issuance with no cert becomes "failed".
        site.ssl_status = "active" if had_cert else "failed"
        site.ssl_error = error = str(e)[-2000:]
        site.updated_at = utcnow()
    # webhooks (SPEC §14.3.3), queued in the same transaction; never the certificate or key
    if error is None:
        webhooks.emit(db, site, "ssl.issued", {
            "renewal": had_cert, "names": [domain, f"*.{domain}"],
            "expires_at": site.ssl_expires_at.isoformat() + "Z" if site.ssl_expires_at else None})
    else:
        webhooks.emit(db, site, "ssl.failed", {"renewal": had_cert, "error": error[-500:]})
    db.commit()
    key = f"ssl_failed:{domain}"
    if error is None:
        from .audit import record_audit

        alerts.resolve_alert(key, f"گواهی {domain} با موفقیت صادر/تمدید شد.")
        # scheduler-driven mutation (SPEC §13.2): actor "system"; never stores the key/cert
        record_audit(db, actor="system", actor_kind="system",
                     action="ssl.renew" if had_cert else "ssl.issue", target=domain,
                     detail={"ssl_source": site.ssl_source})
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


def job_uptime(db):
    uptime.sample(db)


def job_cleanup(db):
    db.execute(delete(Purge).where(Purge.created_at < utcnow() - timedelta(days=2)))
    db.execute(delete(UsageHourly).where(UsageHourly.hour < utcnow() - timedelta(days=400)))
    # F7: usage idempotency keys only need to outlive the agent's retry window; a week is plenty
    db.execute(delete(UsageBatch).where(UsageBatch.received_at < utcnow() - timedelta(days=7)))
    uptime.prune(db)
    prune_events(db)
    # SPEC §14.3: live analytics minute buckets live 24 h, webhook delivery rows 7 days
    live.prune(db)
    webhooks.prune(db)
    # SPEC §15.4: tunnel origin-down / origin-up site events are kept SITE_EVENTS_RETENTION_DAYS
    tunnel_quality.prune_events(db)
    # SPEC §16.8: storage billing samples are kept like the bandwidth usage (400 days)
    from . import storage

    storage.prune(db)
    db.commit()


def job_prune_audit(db):
    """Delete audit_log rows older than AUDIT_RETENTION_DAYS (SPEC §13.2, leader only)."""
    from .models import AuditLog

    days = settings.audit_retention_days
    if days <= 0:
        return
    db.execute(delete(AuditLog).where(AuditLog.at < utcnow() - timedelta(days=days)))
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


GEO_CHECK_INTERVAL = timedelta(minutes=10)


def job_geo(db, now: datetime | None = None, force: bool = False):
    """Every 10 minutes: does every nameserver route home and foreign visitors correctly?"""
    now = now or utcnow()
    last = geocheck.last_report(db)
    if not force and last and now - datetime.fromisoformat(last["at"]) < GEO_CHECK_INTERVAL:
        return
    active = {}
    off = geocheck.geo_off_warning(db)
    if off:
        active["geo:off"] = ("GeoDNS خاموش است",
                             "نود ایران و نود خارج هر دو آنلاین هستند ولی GEOIP_ENABLED=true در .env کنترلر "
                             "تنظیم نشده؛ پس هر بازدیدکننده به‌صورت تصادفی به یکی از نودهای داخل یا خارج "
                             "فرستاده می‌شود.\n" + off, "critical")
    if settings.geo_check_enabled and settings.pdns_enabled:
        db.rollback()
        report = geocheck.check(db)
        geocheck.save_report(db, report)
        if settings.geoip_enabled and report["problems"]:
            active["geo:check"] = ("مسیریابی کشوری (GeoDNS) درست کار نمی‌کند",
                                   "آزمون خودکار GeoDNS روی نیم‌سرورها خطا داد:\n- "
                                   + "\n- ".join(report["problems"][:10]), "critical")
    alerts.sync("geo:", active, lambda c: "مسیریابی کشوری (GeoDNS) دوباره درست کار می‌کند.")


PROBE_INTERVAL = timedelta(seconds=60)


def job_probe(db, now: datetime | None = None, force: bool = False):
    """Every ~60s: synthetic health probe of every enabled edge (SPEC §8.1, leader only)."""
    if not settings.probe_enabled:
        return
    from . import probe

    now = now or utcnow()
    last = _state(db, "probe:last_run")
    if not force and last and now - datetime.fromisoformat(last) < PROBE_INTERVAL:
        return
    probe.run(db, now)
    _set_state(db, "probe:last_run", now.isoformat())
    db.commit()


def job_record_health(db, now: datetime | None = None, force: bool = False):
    """Every ~60s: controller health probe of non-proxied health-checked DNS records (SPEC §16.7,
    leader only); zones whose answer changes are re-synced at once."""
    if not settings.record_probe_enabled:
        return []
    from . import record_health

    now = now or utcnow()
    last = _state(db, "record_probe:last_run")
    if not force and last and now - datetime.fromisoformat(last) < PROBE_INTERVAL:
        return []
    synced = record_health.run(db, now)
    _set_state(db, "record_probe:last_run", now.isoformat())
    db.commit()
    return synced


def job_origin_pull(db, now: datetime | None = None):
    """Renew the platform origin-pull client certificate when fewer than 30 days remain (SPEC §14.2,
    leader only). Never creates the platform CA: that happens lazily on first use."""
    from . import origin_pull

    if db.get(State, origin_pull.STATE_KEY) is None:
        return
    db.rollback()
    origin_pull.ensure(now=now, create=False)


def job_bot_ranges(db, now: datetime | None = None, force: bool = False):
    """Daily refresh of the verified search-engine crawler IP ranges (SPEC §14.2, leader only); runs
    right away when none are stored yet. A failed fetch keeps the last good list."""
    from . import botranges

    if not settings.bot_ranges_enabled:
        return
    botranges.refresh(db, now=now, force=force)


def job_webhooks(db, now: datetime | None = None, wait: bool = False):
    """Hand due webhook deliveries to the delivery workers (SPEC §14.3.3, leader only). Runs every
    tick and in the ~30 s fast lane between ticks; the HTTP requests happen on worker threads, so
    a slow receiver never delays this scheduler."""
    return webhooks.run_due(db, now=now, wait=wait)


def job_log_export(db, now: datetime | None = None, wait: bool = False):
    """Upload every completed hour of spooled access logs to the customers' buckets (SPEC §14.3.2,
    leader only): failures retry every 10 min, chunks older than 72 h are dropped and counted. The
    uploads run on worker threads."""
    return logexport.run_uploads(db, now=now, wait=wait)


def job_tunnel_origin(db, now: datetime | None = None):
    """Every tick (~1 min): tunnel origin-down / origin-up detection from the edges' per-minute
    tunnel counters of the last 5 minutes (SPEC §15.4, leader only)."""
    if not settings.tunnel_origin_check:
        return []
    return tunnel_quality.check_origins(db, now)


def job_storage(db, now: datetime | None = None, force: bool = False):
    """Hourly (SPEC §16.8, leader only): bucket usage from MinIO -> GB-hour billing samples, bucket
    quotas re-balanced to each site's storage_gb, over-quota alerts. No-op without STORAGE_*."""
    from . import storage

    if not storage.available():
        return None
    return storage.run_hourly(db, now=now, force=force)


def job_security_audit(db, now: datetime | None = None, force: bool = False):
    """Every ORIGIN_RECHECK_MINUTES (leader only, security review wave 9): re-resolve every customer
    origin host name (origin_guard.recheck: a name now pointing at a non-public address leaves the
    edge config + alert) and alert on parent/child sites of different owners (legacy data the
    creation rule refuses today, tenancy.py)."""
    if settings.origin_recheck_minutes <= 0:
        return None
    from . import origin_guard, tenancy

    now = now or utcnow()
    last = _state(db, "security_audit:last_run")
    if not force and last and now - datetime.fromisoformat(last) < timedelta(minutes=settings.origin_recheck_minutes):
        return None
    blocked = origin_guard.recheck(db)
    pairs = tenancy.nested_conflicts(db)
    if pairs:
        alerts.raise_alert("nested_sites", "سایت‌های تودرتو با مالک متفاوت",
                           "این سایت‌ها زیردامنهٔ سایت مشتری دیگری‌اند (پیش از قانون C1 ساخته شده‌اند)؛ "
                           "یکی را حذف یا مالک (client_id) آن‌ها را یکی کنید:\n"
                           + "\n".join(f"• {p} ⊃ {c}" for p, c in pairs[:20]), "warning")
    else:
        alerts.resolve_alert("nested_sites", "دیگر سایت تودرتو با مالک متفاوتی وجود ندارد.")
    _set_state(db, "security_audit:last_run", now.isoformat())
    db.commit()
    return {"blocked": blocked, "nested": pairs}


def job_capacity(db, now: datetime | None = None, force: bool = False):
    """Daily: edge-group capacity alert from the 3-day p95 of the hourly tx (SPEC §15.5, leader
    only)."""
    return tunnel_quality.check_capacity(db, now, force=force)


# metrics: per-job last-completed timestamps are stored in the State table under this prefix
# (read by routes_metrics for pcdn_scheduler_job_last_run_age_seconds)
JOBRUN_PREFIX = "jobrun:"

# job_bot_ranges goes last: its (rare, daily) outbound fetch must not delay the other jobs of a tick
JOBS = [job_edges, job_uptime, job_probe, job_record_health, job_alerts, job_geo, job_ns, job_quota, job_tunnel_origin,
        job_capacity, job_cleanup, job_prune_audit, job_ssl, job_backup, job_origin_pull, job_webhooks,
        job_log_export, job_storage, job_security_audit, job_bot_ranges]
# run again between two full ticks (every FAST_INTERVAL seconds) while this instance leads
FAST_JOBS = [job_webhooks]
FAST_INTERVAL = 30.0


def _record_job_run(name: str):
    """Note that job `name` completed, for the scheduler-per-job age metric (SPEC §13.1)."""
    db = SessionLocal()
    try:
        _set_state(db, JOBRUN_PREFIX + name, utcnow().isoformat())
        db.commit()
    except Exception:  # noqa: BLE001
        log.exception("could not record run of job %s", name)
        db.rollback()
    finally:
        db.close()


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
            _record_job_run(job.__name__)


def run_fast():
    """The fast lane between two full ticks (FAST_JOBS). Failures are logged; the full tick's
    job_failed alerting covers the same jobs."""
    for job in FAST_JOBS:
        db = SessionLocal()
        try:
            job(db)
        except Exception:  # noqa: BLE001
            log.exception("fast job %s failed", job.__name__)
            db.rollback()
        finally:
            db.close()


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
    def __init__(self, elector=None, interval: float | None = None, work=None, fast_work=None):
        super().__init__(daemon=True, name="pcdn-scheduler")
        self.stop_event = threading.Event()
        self.elector = elector if elector is not None else make_elector()
        self.interval = settings.scheduler_interval if interval is None else interval
        self.work = work or run_once
        # the fast lane only accompanies the real job list (a custom `work` gets none by default)
        self.fast_work = fast_work if fast_work is not None else (run_fast if work is None else None)
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
                self.wait_interval()
        finally:
            self.release()

    def wait_interval(self):
        """Sleep until the next full tick; meanwhile, while leading, run the fast lane (webhook
        deliveries) every FAST_INTERVAL seconds. Returns early when stopped."""
        deadline = time.monotonic() + self.interval
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return
            if self.stop_event.wait(min(FAST_INTERVAL, remaining)):
                return
            if self.fast_work is not None and self.is_leader and deadline - time.monotonic() > 1:
                try:
                    self.fast_work()
                except Exception:  # noqa: BLE001
                    log.exception("scheduler fast lane failed")

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
