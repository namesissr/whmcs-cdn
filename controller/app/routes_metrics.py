"""GET /metrics — Prometheus text exposition (SPEC §13.1).

Platform aggregates ONLY. The endpoint NEVER exposes a domain, IP, token, key or any other
per-customer identifier — just counts and ages. It is cheap (a handful of aggregate queries)
and wrapped so a scrape never 500s: whatever cannot be computed is simply left out.

Mounted WITHOUT the admin-auth dependency. If METRICS_TOKEN is set it must be presented as
`Authorization: Bearer <token>`; otherwise the endpoint is open (an internal scrape network).
"""

import hmac
import logging
from datetime import timedelta

from fastapi import APIRouter, Header, HTTPException
from fastapi.responses import PlainTextResponse
from sqlalchemy import func, select

from . import alerts
from .config import settings
from .db import SessionLocal
from .models import AuditLog, Edge, LogSpool, Site, State, WebhookDelivery, utcnow

log = logging.getLogger("pcdn.metrics")

router = APIRouter()

CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"
# scheduler per-job last-run timestamps live in the State table under this prefix (see scheduler)
JOBRUN_PREFIX = "jobrun:"


def _check_token(authorization: str | None) -> None:
    token = settings.metrics_token
    if not token:
        return  # open endpoint (internal scrape network)
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(401, "missing bearer token")
    if not hmac.compare_digest(authorization[7:].strip(), token):
        raise HTTPException(401, "invalid metrics token")


class _Out:
    """Accumulates Prometheus metric families; HELP/TYPE emitted once per metric name."""

    def __init__(self):
        self.lines: list[str] = []
        self._seen: set[str] = set()

    def metric(self, name: str, value, help_: str, type_: str = "gauge", labels: dict | None = None):
        if value is None:
            return
        if name not in self._seen:
            self.lines.append(f"# HELP {name} {help_}")
            self.lines.append(f"# TYPE {name} {type_}")
            self._seen.add(name)
        if labels:
            label_str = ",".join(f'{k}="{_escape(str(v))}"' for k, v in labels.items())
            self.lines.append(f"{name}{{{label_str}}} {_num(value)}")
        else:
            self.lines.append(f"{name} {_num(value)}")

    def text(self) -> str:
        return "\n".join(self.lines) + "\n"


def _escape(v: str) -> str:
    return v.replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ")


def _num(v) -> str:
    if isinstance(v, bool):
        return "1" if v else "0"
    if isinstance(v, float):
        return repr(v)
    return str(v)


def _age_seconds(iso: str | None, now) -> int | None:
    if not iso:
        return None
    from datetime import datetime
    try:
        return max(0, int((now - datetime.fromisoformat(iso)).total_seconds()))
    except ValueError:
        return None


def _collect(out: _Out) -> None:
    """Fill `out` with every aggregate we can compute. Each block is wrapped so one failing
    query never costs the whole scrape."""
    now = utcnow()
    db = SessionLocal()
    try:
        # edges ---------------------------------------------------------------
        try:
            cutoff = now - timedelta(seconds=settings.edge_offline_seconds)
            edges = list(db.scalars(select(Edge).where(Edge.enabled.is_(True))))
            online = sum(1 for e in edges if e.last_seen_at is not None and e.last_seen_at >= cutoff)
            shed = sum(1 for e in edges if e.shed)
            probe_failing = sum(1 for e in edges if (e.probe_fail or 0) >= settings.probe_fail_checks)
            total = db.scalar(select(func.count(Edge.id)))
            out.metric("pcdn_edges_total", total, "Number of edge nodes registered.")
            out.metric("pcdn_edges_online", online, "Enabled edge nodes seen within EDGE_OFFLINE_SECONDS.")
            out.metric("pcdn_edges_shed", shed, "Enabled edge nodes currently shed from DNS (load shedding).")
            out.metric("pcdn_edges_probe_failing", probe_failing,
                       "Enabled edges that heartbeat but fail the synthetic health probe.")
        except Exception:  # noqa: BLE001
            log.exception("metrics: edges block failed")
            db.rollback()

        # sites ---------------------------------------------------------------
        try:
            rows = db.execute(select(Site.status, Site.suspended, Site.over_quota)).all()
            by_status: dict[str, int] = {}
            for status, suspended, over_quota in rows:
                eff = "suspended" if suspended else "over_quota" if over_quota else status
                by_status[eff] = by_status.get(eff, 0) + 1
            out.metric("pcdn_sites_total", len(rows), "Number of sites.")
            for eff, n in sorted(by_status.items()):
                out.metric("pcdn_sites", n, "Sites by effective status.", labels={"status": eff})
        except Exception:  # noqa: BLE001
            log.exception("metrics: sites block failed")
            db.rollback()

        # ssl -----------------------------------------------------------------
        try:
            ssl_rows = db.execute(
                select(Site.ssl_status, func.count(Site.id)).group_by(Site.ssl_status)).all()
            for status, n in ssl_rows:
                out.metric("pcdn_ssl_certificates", n, "Sites by SSL status.",
                           labels={"status": status or "none"})
            limit = now + timedelta(days=settings.alert_cert_days)
            expiring = db.scalar(select(func.count(Site.id)).where(
                Site.ssl_status.in_(("active", "pending")),
                Site.ssl_expires_at.is_not(None), Site.ssl_expires_at < limit,
                Site.ssl_allowed.is_(True)))
            out.metric("pcdn_ssl_certs_expiring", expiring,
                       f"Certificates expiring within ALERT_CERT_DAYS ({settings.alert_cert_days}d).")
        except Exception:  # noqa: BLE001
            log.exception("metrics: ssl block failed")
            db.rollback()

        # scheduler / dns / usage / backup (all from the State table) ---------
        try:
            state = {r.key: r.value for r in db.scalars(select(State))}
        except Exception:  # noqa: BLE001
            log.exception("metrics: state read failed")
            db.rollback()
            state = {}

        sched_age = _age_seconds(state.get("scheduler:last_run"), now)
        out.metric("pcdn_scheduler_last_run_age_seconds", sched_age,
                   "Seconds since any scheduler job last ran (leader).")
        for key, value in sorted(state.items()):
            if key.startswith(JOBRUN_PREFIX):
                age = _age_seconds(value, now)
                out.metric("pcdn_scheduler_job_last_run_age_seconds", age,
                           "Seconds since each scheduler job last completed.",
                           labels={"job": key[len(JOBRUN_PREFIX):]})

        dns_age = _age_seconds(state.get("dns:last_sync_at"), now)
        out.metric("pcdn_dns_last_sync_age_seconds", dns_age, "Seconds since DNS last synced cleanly.")

        usage_ingested = state.get("metrics:usage_batches")
        if usage_ingested is not None:
            try:
                out.metric("pcdn_usage_batches_ingested_total", int(usage_ingested),
                           "Usage batches accepted from edges.", type_="counter")
            except ValueError:
                pass

        backup_age = _age_seconds(state.get("backup:last_success_at"), now)
        out.metric("pcdn_backup_last_success_age_seconds", backup_age,
                   "Seconds since the last successful backup.")

        # dns sync errors + active alerts -------------------------------------
        try:
            open_alerts = alerts.open_alerts(db)
            dns_errors = sum(1 for c in open_alerts
                             if str(c.get("key", "")).startswith(("dns_sync:", "pdns_down:")))
            out.metric("pcdn_dns_sync_errors", dns_errors, "Open DNS-sync / PowerDNS error conditions.")
            out.metric("pcdn_active_alerts", len(open_alerts), "Currently open alert conditions.")
            by_sev: dict[str, int] = {}
            for c in open_alerts:
                sev = str(c.get("severity") or "warning")
                by_sev[sev] = by_sev.get(sev, 0) + 1
            for sev, n in sorted(by_sev.items()):
                out.metric("pcdn_active_alerts_by_severity", n, "Open alerts by severity.",
                           labels={"severity": sev})
        except Exception:  # noqa: BLE001
            log.exception("metrics: alerts block failed")
            db.rollback()

        # audit log size (cheap sanity signal; no identifiers) ----------------
        try:
            out.metric("pcdn_audit_log_entries", db.scalar(select(func.count(AuditLog.id))),
                       "Rows currently held in the audit log.")
        except Exception:  # noqa: BLE001
            log.exception("metrics: audit block failed")
            db.rollback()

        # webhooks + log export (SPEC §14.3): platform totals only, never a domain or URL ------
        try:
            counts = dict(db.execute(select(WebhookDelivery.status, func.count(WebhookDelivery.id))
                                     .where(WebhookDelivery.status.in_(("pending", "failed")))
                                     .group_by(WebhookDelivery.status)).all())
            for status in ("pending", "failed"):
                out.metric("pcdn_webhook_deliveries", int(counts.get(status, 0)),
                           "Webhook deliveries held (last 7 days) by status.", labels={"status": status})
            out.metric("pcdn_log_export_pending_records",
                       int(db.scalar(select(func.coalesce(func.sum(LogSpool.records), 0))) or 0),
                       "Access-log records spooled for upload to customer buckets.")
        except Exception:  # noqa: BLE001
            log.exception("metrics: webhooks/log export block failed")
            db.rollback()
    finally:
        db.close()


@router.get("/metrics")
def metrics(authorization: str | None = Header(default=None)):
    _check_token(authorization)
    out = _Out()
    try:
        _collect(out)
    except Exception:  # noqa: BLE001 - a scrape must never 500
        log.exception("metrics collection failed")
    return PlainTextResponse(out.text(), media_type=CONTENT_TYPE)
