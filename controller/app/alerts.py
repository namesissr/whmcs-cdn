"""Operator alerts over Telegram and/or e-mail.

Channels (both optional, see docs/OPERATIONS.md):
  * Telegram: TELEGRAM_BOT_TOKEN + TELEGRAM_CHAT_IDS (comma separated). TELEGRAM_API_URL
    can point to a relay / reverse proxy (api.telegram.org is filtered in Iran); httpx
    also honours HTTPS_PROXY / ALL_PROXY from the environment.
  * E-mail over SMTP: SMTP_HOST/PORT/USER/PASSWORD/FROM, SMTP_SECURITY=starttls|ssl|none,
    ALERT_EMAILS (comma separated).

Alerts are *conditions* identified by a key (e.g. "edge_offline:3"). A condition is sent
once when it opens, repeated at most every ALERT_REMINDER_HOURS while it stays open, and
a "resolved" message is sent when it clears. The state lives in the `state` table (key
"alert:<hash>") so it is shared by every controller instance and survives restarts.

Sending never raises and never blocks for more than ALERT_TIMEOUT (<= 10 s) per channel.
Secrets (bot token, SMTP password) never appear in logs or API responses.
"""

import hashlib
import json
import logging
import smtplib
import ssl as ssl_lib
import threading
from datetime import datetime, timedelta
from email.message import EmailMessage
from email.utils import formatdate, make_msgid

import httpx
from sqlalchemy import select

from .config import settings
from .models import State, utcnow

log = logging.getLogger("pcdn.alerts")

STATE_PREFIX = "alert:"
SEVERITY_EN = {"critical": "CRITICAL", "warning": "WARNING", "info": "INFO", "resolved": "RESOLVED"}
SEVERITY_FA = {"critical": "بحرانی", "warning": "هشدار", "info": "اطلاع", "resolved": "رفع شد"}
# failed deliveries are retried on later ticks, but not more often than this
RETRY_AFTER = timedelta(minutes=5)

# tests inject an httpx.MockTransport here
telegram_transport: httpx.BaseTransport | None = None

_lock = threading.Lock()


class AlertError(RuntimeError):
    pass


def _redact(text: str) -> str:
    for secret in (settings.telegram_bot_token, settings.smtp_password):
        if secret:
            text = text.replace(secret, "***")
    return text


class _RedactFilter(logging.Filter):
    """httpx logs every request URL at INFO; the Telegram bot token is part of that URL."""

    def filter(self, record: logging.LogRecord) -> bool:
        token = settings.telegram_bot_token
        if token:
            msg = record.getMessage()
            if token in msg:
                record.msg, record.args = msg.replace(token, "***"), None
        return True


for _name in ("httpx", "httpcore"):
    logging.getLogger(_name).addFilter(_RedactFilter())


# ------------------------------------------------------------------ channels

class TelegramNotifier:
    name = "telegram"

    def configured(self) -> bool:
        return bool(settings.telegram_bot_token and settings.telegram_chat_ids)

    def describe(self) -> dict:
        return {"configured": self.configured(), "chats": len(settings.telegram_chat_ids),
                "api": "default" if settings.telegram_api_url == "https://api.telegram.org" else "custom"}

    def send(self, subject: str, body: str):
        url = f"{settings.telegram_api_url}/bot{settings.telegram_bot_token}/sendMessage"
        text = f"{subject}\n\n{body}"[:4000]  # Telegram limit is 4096 characters
        errors = []
        with httpx.Client(timeout=settings.alert_timeout, transport=telegram_transport) as client:
            for chat in settings.telegram_chat_ids:
                try:
                    r = client.post(url, json={"chat_id": chat, "text": text,
                                               "disable_web_page_preview": True})
                    ok = r.status_code == 200 and r.json().get("ok") is True
                    if not ok:
                        try:
                            desc = r.json().get("description", "")
                        except ValueError:
                            desc = r.text[:200]
                        errors.append(f"chat {chat}: HTTP {r.status_code} {desc}")
                except (httpx.HTTPError, ValueError) as e:
                    errors.append(f"chat {chat}: {type(e).__name__}: {e}")
        if errors:
            raise AlertError(_redact("; ".join(errors)))


class EmailNotifier:
    name = "email"

    def configured(self) -> bool:
        return bool(settings.smtp_host and settings.alert_emails)

    def describe(self) -> dict:
        return {"configured": self.configured(), "recipients": len(settings.alert_emails),
                "security": settings.smtp_security}

    def send(self, subject: str, body: str):
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = settings.smtp_from or settings.smtp_user or f"pcdn@{settings.smtp_host}"
        msg["To"] = ", ".join(settings.alert_emails)
        msg["Date"] = formatdate(localtime=False)
        msg["Message-ID"] = make_msgid(domain="pcdn.alerts")
        msg.set_content(body, charset="utf-8")
        security = settings.smtp_security
        port = settings.smtp_port or (465 if security == "ssl" else 587 if security == "starttls" else 25)
        timeout = settings.alert_timeout
        try:
            if security == "ssl":
                smtp = smtplib.SMTP_SSL(settings.smtp_host, port, timeout=timeout,
                                        context=ssl_lib.create_default_context())
            else:
                smtp = smtplib.SMTP(settings.smtp_host, port, timeout=timeout)
            with smtp:
                if security == "starttls":
                    smtp.starttls(context=ssl_lib.create_default_context())
                if settings.smtp_user:
                    smtp.login(settings.smtp_user, settings.smtp_password)
                smtp.send_message(msg)
        except (OSError, smtplib.SMTPException) as e:
            raise AlertError(_redact(f"{type(e).__name__}: {e}")) from None


def notifiers() -> list:
    return [TelegramNotifier(), EmailNotifier()]


def configured_channels() -> list:
    return [n for n in notifiers() if n.configured()]


def subject_for(severity: str, title: str) -> str:
    return f"{settings.alert_subject_prefix} {SEVERITY_EN.get(severity, severity.upper())}: {title}"


def send(severity: str, title: str, body: str) -> dict[str, str]:
    """Deliver one message on every configured channel. Returns {channel: "ok" | error}."""
    subject = subject_for(severity, title)
    text = f"[{SEVERITY_FA.get(severity, severity)}] {body}\n\n— {utcnow():%Y-%m-%d %H:%M} UTC"
    results = {}
    for n in configured_channels():
        try:
            n.send(subject, text)
            results[n.name] = "ok"
        except Exception as e:  # noqa: BLE001 - alerts never break the caller
            results[n.name] = _redact(str(e))[:500]
            log.warning("alert via %s failed: %s", n.name, results[n.name])
    return results


# ------------------------------------------------------------------ conditions

def _state_key(key: str) -> str:
    return STATE_PREFIX + hashlib.sha1(key.encode()).hexdigest()[:40]


def _iso(dt: datetime | None) -> str | None:
    return dt.isoformat() if dt else None


def _parse(dt: str | None) -> datetime | None:
    return datetime.fromisoformat(dt) if dt else None


def human_duration(delta: timedelta) -> str:
    secs = max(int(delta.total_seconds()), 0)
    d, rem = divmod(secs, 86400)
    h, rem = divmod(rem, 3600)
    m = rem // 60
    parts = []
    if d:
        parts.append(f"{d} روز")
    if h:
        parts.append(f"{h} ساعت")
    if m or not parts:
        parts.append(f"{m} دقیقه")
    return " و ".join(parts)


def _session():
    from .db import SessionLocal

    return SessionLocal()


def _deliver_if_due(cond: dict, now: datetime) -> bool:
    """Send the open (or reminder) message when due. Mutates cond; True when it changed."""
    last_sent = _parse(cond.get("last_sent_at"))
    last_try = _parse(cond.get("last_attempt_at"))
    reminder = timedelta(hours=settings.alert_reminder_hours) if settings.alert_reminder_hours > 0 else None
    if last_sent is None:
        due = last_try is None or now - last_try >= RETRY_AFTER
        reminder_msg = False
    else:
        due = reminder is not None and now - last_sent >= reminder and (
            last_try is None or last_try <= last_sent or now - last_try >= RETRY_AFTER)
        reminder_msg = True
    if not due or not configured_channels():
        return False
    body = cond["text"]
    if reminder_msg:
        opened = _parse(cond["opened_at"]) or now
        body = f"یادآوری — این مشکل هنوز برطرف نشده است (از {human_duration(now - opened)} پیش).\n\n{body}"
    results = send(cond["severity"], cond["title"], body)
    cond["last_attempt_at"] = _iso(now)
    if any(v == "ok" for v in results.values()):
        cond["last_sent_at"] = _iso(now)
        cond["sent"] = cond.get("sent", 0) + 1
    return True


def raise_alert(key: str, title: str, text: str, severity: str = "warning") -> None:
    """Open (or keep open) the condition `key`; sends only when new or a reminder is due."""
    try:
        with _lock, _session() as db:
            now = utcnow()
            row = db.get(State, _state_key(key))
            if row is None:
                cond = {"key": key, "title": title, "text": text, "severity": severity,
                        "opened_at": _iso(now), "last_sent_at": None, "last_attempt_at": None, "sent": 0}
                row = State(key=_state_key(key), value="")
                db.add(row)
                log.warning("alert opened: %s", key)
            else:
                cond = json.loads(row.value)
                cond.update(title=title, text=text, severity=severity)
            _deliver_if_due(cond, now)
            row.value = json.dumps(cond, ensure_ascii=False)
            db.commit()
    except Exception:  # noqa: BLE001
        log.exception("alert bookkeeping failed for %s", key)


def resolve_alert(key: str, text: str | None = None, notify: bool = True) -> None:
    """Close the condition `key` (no-op when it is not open) and send a resolved message."""
    try:
        with _lock, _session() as db:
            row = db.get(State, _state_key(key))
            if row is None:
                return
            cond = json.loads(row.value)
            db.delete(row)
            db.commit()
            log.info("alert resolved: %s", key)
            if notify and cond.get("last_sent_at"):
                opened = _parse(cond.get("opened_at")) or utcnow()
                body = (text or f"برطرف شد: {cond.get('title', key)}")
                body += f"\nمدت: {human_duration(utcnow() - opened)}"
                send("resolved", cond.get("title", key), body)
    except Exception:  # noqa: BLE001
        log.exception("alert bookkeeping failed for %s", key)


def open_alerts(db=None) -> list[dict]:
    own = db is None
    db = db or _session()
    try:
        rows = db.scalars(select(State).where(State.key.startswith(STATE_PREFIX)))
        out = []
        for r in rows:
            try:
                out.append(json.loads(r.value))
            except ValueError:
                continue
        return sorted(out, key=lambda c: c.get("opened_at") or "")
    finally:
        if own:
            db.close()


def sync(prefix: str, active: dict[str, tuple[str, str, str]], resolved_text=None) -> None:
    """Make the set of open conditions starting with `prefix` equal `active`.

    active: {key: (title, text, severity)}. Conditions under `prefix` that are not in
    `active` are resolved; resolved_text(cond) may return the resolved message.
    """
    for key, (title, text, severity) in active.items():
        raise_alert(key, title, text, severity)
    for cond in open_alerts():
        key = cond.get("key", "")
        if key.startswith(prefix) and key not in active:
            resolve_alert(key, resolved_text(cond) if resolved_text else None)


# ------------------------------------------------------------------ periodic checks

def check_all(db, edges: bool = True) -> None:
    """Evaluate the state-based conditions (called by the scheduler every tick).

    edges=False skips the edge checks right after a controller outage (see scheduler).
    """
    for fn in ((check_edges, check_edge_load, check_edge_health, check_edge_probe) if edges else ()) \
            + (check_certs, check_pdns):
        try:
            fn(db)
        except Exception:  # noqa: BLE001
            log.exception("alert check %s failed", fn.__name__)


def check_edges(db) -> None:
    from .models import Edge

    now = utcnow()
    # alert as soon as a node is silent for edge_alert_seconds; it stays in DNS until the
    # longer edge_offline_seconds, so the message says which of the two has been crossed
    alert_cutoff = now - timedelta(seconds=settings.edge_alert_seconds)
    dns_cutoff = now - timedelta(seconds=settings.edge_offline_seconds)
    edges = list(db.scalars(select(Edge).where(Edge.enabled.is_(True)).order_by(Edge.id)))
    names = {f"edge_offline:{e.id}": e.name for e in edges}

    offline, errors = {}, {}
    online = 0  # "online" for the all-nodes-down check = still in DNS
    for e in edges:
        if e.last_seen_at is not None and e.last_seen_at >= dns_cutoff:
            online += 1
        if e.last_seen_at is not None and e.last_seen_at < alert_cutoff:
            in_dns = e.last_seen_at >= dns_cutoff
            silent = int((now - e.last_seen_at).total_seconds())
            tail = ("هنوز در DNS است؛ اگر تا لحظاتی دیگر گزارش ندهد از پاسخ‌های DNS حذف می‌شود."
                    if in_dns else "از پاسخ‌های DNS حذف شده است.")
            offline[f"edge_offline:{e.id}"] = (
                f"نود {e.name} از دسترس خارج شد",
                f"نود {e.name} ({e.ipv4}) حدود {silent} ثانیه است گزارشی نفرستاده "
                f"(آخرین گزارش: {e.last_seen_at:%Y-%m-%d %H:%M} UTC). {tail}",
                "warning",
            )
        if e.last_error:
            errors[f"edge_error:{e.id}"] = (
                f"خطای کانفیگ روی نود {e.name}",
                f"نود {e.name} ({e.ipv4}) نتوانست آخرین کانفیگ را اعمال کند و با کانفیگ قبلی کار می‌کند.\n"
                f"خطا:\n{e.last_error[:800]}",
                "warning",
            )

    def back_online(cond):
        name = names.get(cond["key"])
        if name is None:
            return "نود غیرفعال یا حذف شد؛ هشدار بسته شد."
        return f"نود {name} دوباره آنلاین شد."

    sync("edge_offline:", offline, back_online)
    sync("edge_error:", errors, lambda c: "خطای کانفیگ نود برطرف شد (کانفیگ جدید با موفقیت اعمال شد).")
    all_down = {}
    if edges and online == 0:
        all_down["all_edges_offline"] = (
            "هیچ نود CDN آنلاینی وجود ندارد",
            f"هیچ‌کدام از {len(edges)} نود فعال در {settings.edge_offline_seconds} ثانیه اخیر گزارش نداده‌اند. "
            "رکوردهای پروکسی مستقیماً به سرور اصلی مشتری‌ها اشاره می‌کنند (بدون کش و محافظت).",
            "critical",
        )
    sync("all_edges_offline", all_down, lambda c: "دست‌کم یک نود دوباره آنلاین است.")


def check_edge_load(db) -> None:
    """edge_saturated:{id} while an edge is shed from DNS or stays above 80 % of its capacity."""
    from .models import Edge
    from .services import LOAD_ALERT_CHECKS, LOAD_ALERT_PERCENT, edge_load_percent, edge_metrics

    now = utcnow()
    cutoff = now - timedelta(seconds=settings.edge_offline_seconds)
    active, names = {}, {}
    for e in db.scalars(select(Edge).where(Edge.enabled.is_(True)).order_by(Edge.id)):
        key = f"edge_saturated:{e.id}"
        names[key] = e.name
        if e.last_seen_at is None or e.last_seen_at < cutoff:
            continue  # offline edges have their own alert
        pct = edge_load_percent(e, now)
        if pct is None or not (e.shed or (e.load_high or 0) >= LOAD_ALERT_CHECKS):
            continue
        m = edge_metrics(e) or {}
        peak = max(float(m.get("rx_mbps") or 0), float(m.get("tx_mbps") or 0))
        if e.shed:
            state = (f"بار از آستانه EDGE_SHED_PERCENT ({settings.edge_shed_percent:g}٪) گذشته است؛ تا وقتی نود "
                     "دیگری از همان گروه و منطقه آنلاین باشد، این نود در پاسخ‌های DNS قرار نمی‌گیرد.")
        else:
            state = f"بار بیش از {LOAD_ALERT_PERCENT}٪ ظرفیت مانده است؛ نود یا ظرفیت بیشتری اضافه کنید."
        active[key] = (
            f"نود {e.name} نزدیک به ظرفیت کامل است",
            f"نود {e.name} ({e.ipv4}، گروه {e.group}) {pct:.0f}٪ ظرفیت را مصرف می‌کند "
            f"({peak:.0f} از {e.capacity_mbps} مگابیت بر ثانیه، {int(m.get('connections') or 0)} اتصال).\n{state}",
            "critical" if e.shed else "warning",
        )

    def normal(cond):
        name = names.get(cond["key"])
        if name is None:
            return "نود غیرفعال یا حذف شد؛ هشدار بسته شد."
        return f"بار نود {name} به حالت عادی برگشت."

    sync("edge_saturated:", active, normal)


def check_edge_health(db) -> None:
    """edge_health:{id} for sustained high CPU load, or a full disk / memory (agent metrics)."""
    from .models import Edge
    from .services import LOAD_ALERT_CHECKS, cpu_ratio, edge_metrics, metrics_fresh

    now = utcnow()
    active, names = {}, {}
    for e in db.scalars(select(Edge).where(Edge.enabled.is_(True)).order_by(Edge.id)):
        key = f"edge_health:{e.id}"
        names[key] = e.name
        if not metrics_fresh(e, now):
            continue  # offline / no recent metrics: handled by the offline alert
        m = edge_metrics(e) or {}
        problems, severity = [], "warning"
        ratio = cpu_ratio(m)
        if ratio is not None and (e.cpu_high or 0) >= LOAD_ALERT_CHECKS:
            problems.append(f"بار پردازنده بالاست ({m.get('load1')} روی {m.get('cpus')} هسته).")
        disk = m.get("disk_pct")
        if disk is not None and disk >= settings.edge_disk_alert:
            problems.append(f"دیسک {disk:.0f}٪ پر است؛ فضای کش رو به اتمام است.")
            severity = "critical"
        mem = m.get("mem_pct")
        if mem is not None and mem >= settings.edge_mem_alert:
            problems.append(f"حافظه {mem:.0f}٪ مصرف شده است.")
        if problems:
            active[key] = (
                f"نود {e.name} تحت فشار است",
                f"نود {e.name} ({e.ipv4}):\n- " + "\n- ".join(problems),
                severity,
            )

    def normal(cond):
        name = names.get(cond["key"])
        return f"وضعیت نود {name} به حالت عادی برگشت." if name else "نود غیرفعال یا حذف شد؛ هشدار بسته شد."

    sync("edge_health:", active, normal)


def check_edge_probe(db) -> None:
    """edge_probe:{id} when a node heartbeats but its synthetic health check keeps failing.

    "Reporting but broken": the agent is alive (last_seen fresh) yet the controller's own
    fetch of /__pcdn/health has failed PROBE_FAIL_CHECKS times in a row. A node with no
    heartbeat is left to the edge_offline alert instead.
    """
    from .models import Edge

    now = utcnow()
    cutoff = now - timedelta(seconds=settings.edge_offline_seconds)
    active, names = {}, {}
    for e in db.scalars(select(Edge).where(Edge.enabled.is_(True)).order_by(Edge.id)):
        key = f"edge_probe:{e.id}"
        names[key] = e.name
        if e.last_seen_at is None or e.last_seen_at < cutoff:
            continue  # no heartbeat: covered by edge_offline
        if e.probe_ok is False and (e.probe_fail or 0) >= settings.probe_fail_checks:
            active[key] = (
                f"نود {e.name} گزارش می‌دهد ولی سالم نیست",
                f"نود {e.name} ({e.ipv4}) هنوز گزارش می‌فرستد اما آزمون سلامت (health check) کنترلر "
                f"روی آن {e.probe_fail} بار پیاپی ناموفق بوده است؛ احتمالاً nginx یا سرویس لبه درست کار "
                f"نمی‌کند و درخواست‌ها با خطا پاسخ داده می‌شوند.\n"
                f"خطا: {(e.probe_error or '-')[:400]}",
                "warning",
            )

    def normal(cond):
        name = names.get(cond["key"])
        return f"آزمون سلامت نود {name} دوباره موفق شد." if name else "نود غیرفعال یا حذف شد؛ هشدار بسته شد."

    sync("edge_probe:", active, normal)


def check_certs(db) -> None:
    from sqlalchemy import or_

    from .models import Site

    limit = utcnow() + timedelta(days=settings.alert_cert_days)
    active = {}
    for s in db.scalars(select(Site).where(
        Site.ssl_status.in_(("active", "pending")), Site.ssl_expires_at.is_not(None), Site.ssl_expires_at < limit,
        Site.ssl_allowed.is_(True), or_(Site.ssl_source.is_(None), Site.ssl_source != "custom"),
    )):
        active[f"cert_expiring:{s.domain}"] = (
            f"گواهی {s.domain} به‌زودی منقضی می‌شود",
            f"گواهی Let's Encrypt دامنه {s.domain} در {s.ssl_expires_at:%Y-%m-%d %H:%M} UTC منقضی می‌شود "
            f"و هنوز تمدید نشده است.\nآخرین خطا: {(s.ssl_error or '-')[:500]}",
            "critical" if s.ssl_expires_at < utcnow() + timedelta(days=2) else "warning",
        )
    sync("cert_expiring:", active, lambda c: "گواهی تمدید شد (یا دامنه دیگر گواهی خودکار ندارد).")

    # ssl_failed:* is opened by the scheduler; close it when the site is gone or healthy again
    existing = {d: err for d, err in db.execute(select(Site.domain, Site.ssl_error))}
    for cond in open_alerts():
        key = cond.get("key", "")
        if key.startswith("ssl_failed:"):
            domain = key.split(":", 1)[1]
            if domain not in existing or not existing[domain]:
                resolve_alert(key, f"گواهی {domain} با موفقیت صادر شد (یا سایت حذف شد).")


def pdns_server_label(index: int, base: str) -> str:
    host = httpx.URL(base).host or base
    return f"PowerDNS #{index + 1} ({host})"


def check_pdns(db) -> None:
    if not settings.pdns_enabled:
        return
    from . import pdns

    down = {}
    for i, c in enumerate(pdns.client().clients):
        err = pdns.ping(c)
        if err:
            label = pdns_server_label(i, c.base)
            down[f"pdns_down:{i}"] = (
                f"{label} در دسترس نیست",
                f"API سرور {label} پاسخ نمی‌دهد: {err[:300]}\n"
                "تغییرات DNS روی این سرور نوشته نمی‌شوند؛ پس از برگشت، کنترلر زون‌ها را دوباره همگام می‌کند.",
                "critical",
            )
    sync("pdns_down:", down, lambda c: "API سرور PowerDNS دوباره در دسترس است.")
