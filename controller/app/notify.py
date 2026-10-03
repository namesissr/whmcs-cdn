"""Customer notification engine (SPEC §23.5).

The controller is the single engine: events -> subscriptions of the site's account (WHMCS client id)
-> plan / channel availability -> dedup -> rate limits -> quiet hours -> one `notification_outbox` row
per (delivery, channel, target). SMS, Bale and Telegram rows are sent here (job_notify, retries 1/5/15
min); e-mail rows are pulled and acknowledged by the WHMCS addon cron. Webhooks stay a separate
per-site channel (webhooks.py). Texts never carry a node name or address (notify_templates.py).

Targets (phones / chat ids) are encrypted at rest; `value_hash` = HMAC for uniqueness and lookups.
Secrets of the providers never reach the database, a log line or an API answer.
"""

import hashlib
import hmac
import json
import logging
import re
import secrets
from datetime import datetime, time, timedelta, timezone

from sqlalchemy import delete, func, or_, select
from sqlalchemy.orm import Session

from . import keys, kv, notify_providers, notify_templates, sections
from .config import settings
from .errors import ApiError
from .models import (Incident, NotificationLinkCode, NotificationOutbox, NotificationSubscription,
                     NotificationTarget, Site, utcnow)

log = logging.getLogger("pcdn.notify")

CHANNELS = ("email", "sms", "bale", "telegram")
MSG_CHANNELS = ("bale", "telegram")
# event -> (severity, site_scoped, subscribable)
EVENTS: dict[str, tuple[str, bool, bool]] = {
    "origin.down": ("critical", True, True),
    "origin.up": ("info", True, True),
    "tunnel.origin_down": ("critical", True, True),
    "tunnel.origin_up": ("info", True, True),
    "quota.warning": ("warning", True, True),
    "quota.exceeded": ("critical", True, True),
    "ssl.expiring": ("warning", True, True),
    "ssl.failed": ("critical", True, True),
    "attack.detected": ("warning", True, True),
    "site.suspended": ("info", True, True),
    "site.unsuspended": ("info", True, True),
    "incident.opened": ("warning", False, True),
    "incident.resolved": ("info", False, True),
    "abuse.notice": ("critical", True, False),
}
# recovery event -> the event that must have been sent on a channel first
RECOVERY_OF = {"origin.up": "origin.down", "tunnel.origin_up": "tunnel.origin_down",
               "incident.resolved": "incident.opened", "site.unsuspended": "site.suspended"}
# tunnel origin e-mails are sent by the WHMCS TunnelAlerts cron (SPEC §15.4): never twice
NO_EMAIL = {"tunnel.origin_down", "tunnel.origin_up"}
RETRY_DELAYS = (timedelta(minutes=1), timedelta(minutes=5), timedelta(minutes=15))
PERMANENT_FAILURES_DISABLE = 3
EMAIL_REOFFER = timedelta(minutes=30)
EMAIL_EXPIRE = timedelta(hours=48)
OUTBOX_RETENTION = timedelta(days=30)
SMS_CODE_TTL = timedelta(minutes=10)
LINK_CODE_TTL = timedelta(minutes=15)
SMS_CODE_TRIES = 5
SMS_CODES_PER_HOUR = 3
SMS_CODES_PER_PHONE_DAY = 5
TESTS_PER_HOUR = 3
LINK_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
HHMM_RE = re.compile(r"^([01]\d|2[0-3]):[0-5]\d$")


class NotifyError(ApiError):
    """An API error of the alerts endpoints (flat JSON body, e.g. 403 {"detail": "channel_not_in_plan",
    "channel": "sms"})."""


def _tehran():
    try:
        from zoneinfo import ZoneInfo

        return ZoneInfo("Asia/Tehran")
    except Exception:  # noqa: BLE001 - no tz database: Iran has used a fixed UTC+03:30 since 2022
        return timezone(timedelta(hours=3, minutes=30))


def iso(dt: datetime | None) -> str | None:
    return dt.isoformat() + "Z" if dt else None


def _loads(raw, default):
    try:
        v = json.loads(raw) if raw else default
    except ValueError:
        return default
    return v if isinstance(v, type(default)) else default


# ------------------------------------------------------------------ accounts

def account_of(site: Site) -> int | None:
    """The account (WHMCS client id) owning a site: the reseller for reseller-owned sites."""
    if (site.owner_kind or "client") == "reseller" and site.reseller_client_id:
        return site.reseller_client_id
    return site.client_id or site.reseller_client_id


def account_sites(db: Session, client_id: int) -> list[Site]:
    return [s for s in db.scalars(select(Site).where(or_(Site.client_id == client_id,
                                                         Site.reseller_client_id == client_id)).order_by(Site.id))
            if account_of(s) == client_id]


def _feat(site: Site, name: str):
    return sections.features_of(site).get(name)


def channel_allowed(site: Site, channel: str) -> bool:
    """Plan per channel (SMS: alert_sms, Bale/Telegram: alert_messengers; e-mail always)."""
    if channel == "email":
        return True
    if channel == "sms":
        return bool(_feat(site, "alert_sms"))
    return bool(_feat(site, "alert_messengers"))


def channel_available(channel: str) -> bool:
    return notify_providers.configured(channel)


def max_subscriptions(sites: list[Site]) -> int:
    return max((int(_feat(s, "max_alert_subscriptions") or 0) for s in sites), default=20)


# ------------------------------------------------------------------ targets helpers

def value_hash(channel: str, value: str, db: Session | None = None) -> str:
    return keys.mac("pcdn-notify-target", f"{channel}:{value}", db)


def mask(channel: str, value: str) -> str:
    if channel == "sms":
        return f"{value[:6]}•••{value[-4:]}"
    return f"chat •••{value[-3:]}"


def target_dict(t: NotificationTarget) -> dict:
    return {"id": t.id, "channel": t.channel, "masked": t.masked, "verified": t.verified_at is not None,
            "disabled": t.disabled_at is not None}


def _code_hash(code: str, db: Session | None = None) -> str:
    return keys.mac("pcdn-notify-code", code.strip().upper(), db)


# ------------------------------------------------------------------ subscriptions

def sub_dict(db: Session, s: NotificationSubscription) -> dict:
    site = db.get(Site, s.site_id) if s.site_id else None
    quiet = None
    if s.quiet_start and s.quiet_end:
        quiet = {"start": s.quiet_start, "end": s.quiet_end, "bypass_critical": bool(s.quiet_bypass_critical)}
    return {"id": s.id, "site": site.domain if site is not None else None,
            "events": _loads(s.events, []), "channels": _loads(s.channels, []), "lang": s.lang,
            "quiet_hours": quiet, "enabled": bool(s.enabled)}


def account_view(db: Session, client_id: int) -> dict:
    sites = account_sites(db, client_id)
    channels = {"email": {"available": True}}
    for ch in ("sms", "bale", "telegram"):
        entry = {"available": channel_available(ch), "plan": any(channel_allowed(s, ch) for s in sites)}
        if ch in MSG_CHANNELS:
            entry["username"] = (settings.telegram_customer_bot_username if ch == "telegram"
                                 else settings.bale_bot_username) or None
        channels[ch] = entry
    subs = db.scalars(select(NotificationSubscription).where(NotificationSubscription.client_id == client_id)
                      .order_by(NotificationSubscription.id))
    targets = db.scalars(select(NotificationTarget).where(NotificationTarget.client_id == client_id)
                         .order_by(NotificationTarget.id))
    return {
        "channels": channels,
        "events": [{"event": e, "severity": sev, "site_scoped": scoped}
                   for e, (sev, scoped, sub) in EVENTS.items() if sub],
        "subscriptions": [sub_dict(db, s) for s in subs],
        "targets": [target_dict(t) for t in targets],
        "limits": {"max_subscriptions": max_subscriptions(sites)},
    }


def replace_subscriptions(db: Session, client_id: int, items: list[dict]) -> None:
    """Full replace (validated). Raises NotifyError(403 channel_not_in_plan / 422 …)."""
    sites = account_sites(db, client_id)
    by_domain = {s.domain: s for s in sites}
    limit = max_subscriptions(sites)
    if len(items) > limit:
        raise NotifyError(422, "too_many_subscriptions", max=limit)
    rows = []
    for it in items:
        domain = it.get("site")
        site = None
        if domain:
            site = by_domain.get(str(domain).strip().lower())
            if site is None:
                raise NotifyError(422, "site_not_in_account", site=domain)
        events = list(dict.fromkeys(it.get("events") or []))
        bad = [e for e in events if e not in EVENTS or not EVENTS[e][2]]
        if bad or not events:
            raise NotifyError(422, "invalid_events", events=bad)
        channels = list(dict.fromkeys(it.get("channels") or []))
        if not channels or any(c not in CHANNELS for c in channels):
            raise NotifyError(422, "invalid_channels")
        scope = [site] if site is not None else sites
        for ch in channels:
            if ch == "email":
                continue
            if not channel_available(ch):
                raise NotifyError(403, "channel_unavailable", channel=ch)
            if not scope or not all(channel_allowed(s, ch) for s in scope):
                raise NotifyError(403, "channel_not_in_plan", channel=ch)
        lang = it.get("lang") or "fa"
        if lang not in ("fa", "en"):
            raise NotifyError(422, "invalid_lang")
        quiet = it.get("quiet_hours")
        qs = qe = None
        bypass = True
        if quiet:
            qs, qe = str(quiet.get("start") or ""), str(quiet.get("end") or "")
            if not HHMM_RE.match(qs) or not HHMM_RE.match(qe) or qs == qe:
                raise NotifyError(422, "invalid_quiet_hours")
            bypass = bool(quiet.get("bypass_critical", True))
        rows.append(NotificationSubscription(
            client_id=client_id, site_id=site.id if site is not None else None, events=json.dumps(events),
            channels=json.dumps(channels), lang=lang, quiet_start=qs, quiet_end=qe, quiet_bypass_critical=bypass,
            enabled=bool(it.get("enabled", True))))
    db.execute(delete(NotificationSubscription).where(NotificationSubscription.client_id == client_id))
    for r in rows:
        db.add(r)


# ------------------------------------------------------------------ quiet hours

def _hm(v: str) -> time:
    h, m = v.split(":")
    return time(int(h), int(m))


def quiet_until(sub: NotificationSubscription, now: datetime) -> datetime | None:
    """The UTC end of the quiet window when `now` (naive UTC) is inside it, else None."""
    if not (sub.quiet_start and sub.quiet_end):
        return None
    tz = _tehran()
    local = now.replace(tzinfo=timezone.utc).astimezone(tz)
    start, end = _hm(sub.quiet_start), _hm(sub.quiet_end)
    t = local.time()
    if start < end:
        inside = start <= t < end
        end_day = local.date()
    else:  # crosses midnight
        inside = t >= start or t < end
        end_day = local.date() + timedelta(days=1) if t >= start else local.date()
    if not inside:
        return None
    end_local = datetime.combine(end_day, end, tzinfo=tz)
    return end_local.astimezone(timezone.utc).replace(tzinfo=None)


# ------------------------------------------------------------------ emitting

def _targets(db: Session, client_id: int, channel: str) -> list[NotificationTarget]:
    return list(db.scalars(select(NotificationTarget).where(
        NotificationTarget.client_id == client_id, NotificationTarget.channel == channel,
        NotificationTarget.verified_at.is_not(None), NotificationTarget.disabled_at.is_(None))
        .order_by(NotificationTarget.id)))


def _dedup(site_id: int | None, event: str, key: str) -> str:
    return f"{site_id or 0}:{event}:{key}"[:128]


def _recent(db: Session, client_id: int, dedup: str, since: datetime) -> bool:
    return db.scalar(select(func.count(NotificationOutbox.id)).where(
        NotificationOutbox.client_id == client_id, NotificationOutbox.dedup_key == dedup,
        NotificationOutbox.created_at >= since)) > 0


def _sent_channels(db: Session, client_id: int, site_id: int | None, event: str, key: str) -> set[tuple]:
    """(channel, target id) where the opening event of this recovery was delivered (or is queued)."""
    rows = db.execute(select(NotificationOutbox.channel, NotificationOutbox.target_id).where(
        NotificationOutbox.client_id == client_id, NotificationOutbox.dedup_key == _dedup(site_id, event, key),
        NotificationOutbox.status.in_(("sent", "pending", "deferred")))).all()
    return {(c, t) for c, t in rows}


def _count(db: Session, client_id: int, channel: str, since: datetime) -> int:
    return int(db.scalar(select(func.count(NotificationOutbox.id)).where(
        NotificationOutbox.client_id == client_id, NotificationOutbox.channel == channel,
        NotificationOutbox.created_at >= since, NotificationOutbox.event.notin_(("digest", "test")),
        or_(NotificationOutbox.error.is_(None), NotificationOutbox.error != "rate_limited"))) or 0)


def over_limit(db: Session, client_id: int, channel: str, now: datetime) -> bool:
    hour = _count(db, client_id, channel, now - timedelta(hours=1))
    if channel == "sms":
        return hour >= settings.notify_rate_sms_hour or \
            _count(db, client_id, channel, now - timedelta(days=1)) >= settings.notify_rate_sms_day
    if channel in MSG_CHANNELS:
        return hour >= settings.notify_rate_msg_hour
    return hour >= settings.notify_rate_email_hour


def _row(client_id, site, event, severity, channel, target_id, lang, values, dedup, now) -> NotificationOutbox:
    subject, text = notify_templates.render(event, lang, values, channel)
    return NotificationOutbox(client_id=client_id, site_id=site.id if site is not None else None, event=event,
                              severity=severity, channel=channel, target_id=target_id, lang=lang,
                              subject=subject, text=text, vars=json.dumps(values, ensure_ascii=False),
                              dedup_key=dedup, status="pending", attempts=0, next_attempt_at=now, created_at=now)


def _accounts_for(db: Session, site: Site | None, event: str) -> list[int]:
    if site is not None:
        acc = account_of(site)
        return [acc] if acc else []
    ids = set()
    for s in db.scalars(select(NotificationSubscription).where(NotificationSubscription.enabled.is_(True))):
        if event in _loads(s.events, []):
            ids.add(s.client_id)
    return sorted(ids)


def emit(db: Session, site: Site | None, event: str, values: dict | None = None, dedup_key: str = "",
         now: datetime | None = None, severity: str | None = None) -> int:
    """Queue `event` for every matching subscription (caller's transaction). Never raises; returns
    the number of outbox rows created."""
    try:
        if event not in EVENTS or not EVENTS[event][2]:
            return 0
        return _emit(db, site, event, values or {}, dedup_key, now or utcnow(), severity)
    except Exception:  # noqa: BLE001 - notifying must never break the triggering action
        log.exception("could not queue notification %s", event)
        return 0


def _emit(db, site, event, values, dedup_key, now, severity_override=None) -> int:
    severity, scoped, _ = EVENTS[event]
    severity = severity_override or severity
    if scoped and site is None:
        return 0
    created = 0
    for client_id in _accounts_for(db, site, event):
        sites = account_sites(db, client_id)
        if not sites:
            continue
        sid = site.id if (scoped and site is not None) else None
        dedup = _dedup(sid, event, dedup_key)
        if settings.notify_dedup_minutes and _recent(db, client_id, dedup,
                                                     now - timedelta(minutes=settings.notify_dedup_minutes)):
            continue
        recovery = RECOVERY_OF.get(event)
        allowed_pairs = _sent_channels(db, client_id, sid, recovery, dedup_key) if recovery else None
        subs = db.scalars(select(NotificationSubscription).where(
            NotificationSubscription.client_id == client_id, NotificationSubscription.enabled.is_(True))
            .order_by(NotificationSubscription.id))
        done: set[tuple] = set()
        vals = {"domain": site.domain if site is not None else "", "time": _time(now), **values}
        for sub in subs:
            if event not in _loads(sub.events, []):
                continue
            if scoped and sub.site_id is not None and sub.site_id != sid:
                continue
            for channel in _loads(sub.channels, []):
                if channel not in CHANNELS or (channel == "email" and event in NO_EMAIL):
                    continue
                if channel != "email":
                    if not channel_available(channel):
                        continue
                    plan_sites = [site] if (scoped and site is not None) else sites
                    if not any(channel_allowed(s, channel) for s in plan_sites):
                        continue
                targets = [None] if channel == "email" else [t.id for t in _targets(db, client_id, channel)]
                for tid in targets:
                    pair = (channel, tid)
                    if pair in done:
                        continue
                    if allowed_pairs is not None and pair not in allowed_pairs:
                        continue
                    done.add(pair)
                    row = _row(client_id, site if scoped else None, event, severity, channel, tid, sub.lang,
                               vals, dedup, now)
                    if over_limit(db, client_id, channel, now):
                        row.status, row.error, row.next_attempt_at = "skipped", "rate_limited", None
                    elif channel != "email" and not (severity == "critical" and sub.quiet_bypass_critical):
                        until = quiet_until(sub, now)
                        if until is not None:
                            row.status, row.next_attempt_at = "deferred", until
                    db.add(row)
                    db.flush()
                    created += 1
    return created


def _time(now: datetime) -> str:
    return now.replace(tzinfo=timezone.utc).astimezone(_tehran()).strftime("%Y-%m-%d %H:%M")


# hooks used by the event sources --------------------------------------------------------------

def on_webhook_event(db: Session, site: Site, event: str, data: dict | None) -> None:
    """Called by webhooks.emit for every site event (also when the site has no hooks)."""
    if event not in EVENTS:
        return
    data = data or {}
    key = ""
    if event in ("ssl.expiring",):
        key = f"{data.get('serial', '')}:{data.get('days_threshold', '')}"
    values = {k: data[k] for k in ("days", "reason") if k in data}
    emit(db, site, event, values, key)


def on_incident(db: Session, incident: Incident, opened: bool) -> None:
    event = "incident.opened" if opened else "incident.resolved"
    emit(db, None, event, {"title": incident.title[:120]}, str(incident.id),
         severity="info" if (incident.severity == "maintenance" or not opened) else "warning")
    # webhook catalog (SPEC §23.5 ✚): every site with a hook subscribed to the event
    from . import webhooks

    payload = {"incident_id": incident.id, "title": incident.title[:200], "severity": incident.severity,
               "status": incident.status}
    for s in db.scalars(select(Site).where(Site.config.like('%"' + event + '"%'))):
        webhooks.emit(db, s, event, payload, notify_customers=False)


def enqueue_abuse_notice(db: Session, site: Site, values: dict, lang: str, now: datetime | None = None) -> int:
    """§23.10: the legal notice to the site owner (e-mail only, not subscribable, no opt-out)."""
    client_id = account_of(site)
    if not client_id:
        return 0
    now = now or utcnow()
    row = _row(client_id, site, "abuse.notice", "critical", "email", None, lang if lang in ("fa", "en") else "fa",
               {"domain": site.domain, **values}, _dedup(site.id, "abuse.notice", str(values.get("ticket", ""))), now)
    db.add(row)
    return 1


# ------------------------------------------------------------------ targets (SMS verification, bot links)

def add_sms_target(db: Session, client_id: int, phone: str, now: datetime | None = None) -> dict:
    now = now or utcnow()
    phone = (phone or "").strip().replace(" ", "")
    pattern = notify_providers.INTL_PHONE_RE if settings.sms_allow_international else notify_providers.PHONE_RE
    if not pattern.match(phone):
        raise NotifyError(422, "invalid_phone")
    provider = notify_providers.sms_provider()
    if provider is None:
        raise NotifyError(404, "channel_unavailable", channel="sms")
    sites = account_sites(db, client_id)
    if not any(channel_allowed(s, "sms") for s in sites):
        raise NotifyError(403, "channel_not_in_plan", channel="sms")
    vh = value_hash("sms", phone, db)
    if db.scalar(select(func.count(NotificationLinkCode.id)).where(
            NotificationLinkCode.client_id == client_id, NotificationLinkCode.kind == "sms_verify",
            NotificationLinkCode.created_at >= now - timedelta(hours=1))) >= SMS_CODES_PER_HOUR:
        raise NotifyError(429, "too_many_codes")
    same_phone = select(NotificationTarget.id).where(NotificationTarget.channel == "sms",
                                                     NotificationTarget.value_hash == vh)
    if db.scalar(select(func.count(NotificationLinkCode.id)).where(
            NotificationLinkCode.kind == "sms_verify", NotificationLinkCode.target_id.in_(same_phone),
            NotificationLinkCode.created_at >= now - timedelta(days=1))) >= SMS_CODES_PER_PHONE_DAY:
        raise NotifyError(429, "too_many_codes")
    t = db.scalar(select(NotificationTarget).where(NotificationTarget.client_id == client_id,
                                                   NotificationTarget.channel == "sms",
                                                   NotificationTarget.value_hash == vh))
    if t is None:
        t = NotificationTarget(client_id=client_id, channel="sms", value_hash=vh, masked=mask("sms", phone),
                               created_at=now, fail_count=0)
        t.value = phone
        db.add(t)
        db.flush()
    code = f"{secrets.randbelow(10**6):06d}"
    expires = now + SMS_CODE_TTL
    db.add(NotificationLinkCode(client_id=client_id, kind="sms_verify", target_id=t.id,
                                code_hash=_code_hash(f"{t.id}:{code}", db), expires_at=expires, tries=0,
                                created_at=now))
    lang_text = f"{notify_templates.brand('fa')}: کد تأیید شما {code}"
    ok, _, _ = provider.send(phone, lang_text)
    if not ok:
        db.rollback()
        raise NotifyError(502, "sms_send_failed")
    return {"target_id": t.id, "expires_at": iso(expires)}


def verify_sms_target(db: Session, client_id: int, target_id: int, code: str, now: datetime | None = None) -> dict:
    now = now or utcnow()
    t = db.get(NotificationTarget, target_id)
    if t is None or t.client_id != client_id or t.channel != "sms":
        raise NotifyError(404, "target_not_found")
    row = db.scalar(select(NotificationLinkCode).where(
        NotificationLinkCode.target_id == t.id, NotificationLinkCode.kind == "sms_verify",
        NotificationLinkCode.used_at.is_(None)).order_by(NotificationLinkCode.id.desc()).limit(1))
    if row is None or row.expires_at < now:
        raise NotifyError(422, "code_expired")
    if row.tries >= SMS_CODE_TRIES:
        raise NotifyError(422, "too_many_tries")
    row.tries += 1
    if not hmac.compare_digest(row.code_hash, _code_hash(f"{t.id}:{(code or '').strip()}", db)):
        db.commit()
        raise NotifyError(422, "invalid_code")
    row.used_at = now
    t.verified_at, t.disabled_at, t.fail_count = now, None, 0
    return {"verified": True}


def new_link_code(db: Session, client_id: int, channel: str, now: datetime | None = None) -> dict:
    now = now or utcnow()
    if channel not in MSG_CHANNELS:
        raise NotifyError(404, "unknown_channel")
    if notify_providers.bot(channel) is None or not notify_providers.deep_link(channel, "X"):
        raise NotifyError(404, "channel_unavailable", channel=channel)
    if not any(channel_allowed(s, channel) for s in account_sites(db, client_id)):
        raise NotifyError(403, "channel_not_in_plan", channel=channel)
    code = "".join(secrets.choice(LINK_ALPHABET) for _ in range(8))
    expires = now + LINK_CODE_TTL
    db.add(NotificationLinkCode(client_id=client_id, kind=channel, code_hash=_code_hash(code, db),
                                expires_at=expires, tries=0, created_at=now))
    return {"code": code, "deep_link": notify_providers.deep_link(channel, code), "expires_at": iso(expires)}


def link_status(db: Session, client_id: int, code: str) -> dict:
    if not re.match(r"^[A-Z2-9]{8}$", code or ""):
        raise NotifyError(404, "code_not_found")
    row = db.scalar(select(NotificationLinkCode).where(NotificationLinkCode.client_id == client_id,
                                                       NotificationLinkCode.code_hash == _code_hash(code, db),
                                                       NotificationLinkCode.kind.in_(MSG_CHANNELS)))
    if row is None:
        raise NotifyError(404, "code_not_found")
    return {"linked": row.target_id is not None, "target_id": row.target_id}


def delete_target(db: Session, client_id: int, target_id: int) -> NotificationTarget:
    t = db.get(NotificationTarget, target_id)
    if t is None or t.client_id != client_id:
        raise NotifyError(404, "target_not_found")
    db.delete(t)
    return t


def queue_test(db: Session, client_id: int, channel: str, target_id: int | None, now: datetime | None = None) -> int:
    now = now or utcnow()
    if channel not in CHANNELS:
        raise NotifyError(422, "invalid_channel")
    if db.scalar(select(func.count(NotificationOutbox.id)).where(
            NotificationOutbox.client_id == client_id, NotificationOutbox.event == "test",
            NotificationOutbox.created_at >= now - timedelta(hours=1))) >= TESTS_PER_HOUR:
        raise NotifyError(429, "too_many_tests")
    if channel != "email" and not channel_available(channel):
        raise NotifyError(404, "channel_unavailable", channel=channel)
    if channel == "email":
        tids = [None]
    else:
        ts = _targets(db, client_id, channel)
        if target_id is not None:
            ts = [t for t in ts if t.id == target_id]
        if not ts:
            raise NotifyError(404, "target_not_found")
        tids = [t.id for t in ts]
    for tid in tids:
        db.add(_row(client_id, None, "test", "info", channel, tid, "fa", {}, f"0:test:{secrets.token_hex(4)}", now))
    return len(tids)


# ------------------------------------------------------------------ bots (job_bots)

BOT_OFFSET_KEY = "notify_bot_offset:{}"


def _reply(api, chat_id: str, fa: str, en: str) -> None:
    api.send_message(chat_id, f"{fa}\n{en}")


def poll_bots(db: Session, now: datetime | None = None) -> int:
    """getUpdates on each configured customer bot: `/start <code>` binds the chat, `/stop` disables
    every target with that chat id. Nothing else is ever answered. Returns the updates processed."""
    now = now or utcnow()
    handled = 0
    for channel in MSG_CHANNELS:
        api = notify_providers.bot(channel)
        if api is None:
            continue
        key = BOT_OFFSET_KEY.format(channel)
        offset = kv.get_json(db, key).get("offset")
        updates = api.get_updates(offset)
        last = None
        for u in updates:
            uid = u.get("update_id")
            if isinstance(uid, int):
                last = uid if last is None else max(last, uid)
            msg = u.get("message") or {}
            chat = (msg.get("chat") or {}).get("id")
            text = str(msg.get("text") or "").strip()
            if chat is None or not text.startswith("/"):
                continue
            chat_id = str(chat)
            handled += 1
            cmd, _, arg = text.partition(" ")
            cmd = cmd.split("@")[0].lower()
            if cmd == "/start" and arg.strip():
                _bind(db, api, channel, chat_id, arg.strip().upper(), now)
            elif cmd == "/stop":
                vh = value_hash(channel, chat_id, db)
                n = 0
                for t in db.scalars(select(NotificationTarget).where(NotificationTarget.channel == channel,
                                                                     NotificationTarget.value_hash == vh)):
                    if t.disabled_at is None:
                        t.disabled_at = now
                        n += 1
                db.commit()
                _reply(api, chat_id, "ارسال هشدارها به این گفتگو متوقف شد.", "Alerts to this chat are stopped.")
        if last is not None:
            kv.set_json(db, key, {"offset": last + 1})
            db.commit()
    return handled


def _bind(db: Session, api, channel: str, chat_id: str, code: str, now: datetime) -> None:
    if not re.match(r"^[A-Z2-9]{8}$", code):
        return
    row = db.scalar(select(NotificationLinkCode).where(NotificationLinkCode.kind == channel,
                                                       NotificationLinkCode.code_hash == _code_hash(code, db)))
    if row is None or row.used_at is not None or row.expires_at < now:
        _reply(api, chat_id, "کد اتصال نامعتبر یا منقضی است.", "The link code is invalid or expired.")
        return
    vh = value_hash(channel, chat_id, db)
    t = db.scalar(select(NotificationTarget).where(NotificationTarget.client_id == row.client_id,
                                                   NotificationTarget.channel == channel,
                                                   NotificationTarget.value_hash == vh))
    if t is None:
        t = NotificationTarget(client_id=row.client_id, channel=channel, value_hash=vh,
                               masked=mask(channel, chat_id), created_at=now, fail_count=0)
        t.value = chat_id
        db.add(t)
    t.verified_at, t.disabled_at, t.fail_count = now, None, 0
    db.flush()
    row.used_at, row.target_id = now, t.id
    db.commit()
    _reply(api, chat_id, "اتصال برقرار شد", "Linked")


# ------------------------------------------------------------------ delivery (job_notify)

def _deliver(db: Session, row: NotificationOutbox, now: datetime) -> None:
    t = db.get(NotificationTarget, row.target_id) if row.target_id else None
    if t is None or t.disabled_at is not None or t.verified_at is None:
        row.status, row.error, row.next_attempt_at = "skipped", "target_unavailable", None
        return
    try:
        value = t.value
    except Exception:  # noqa: BLE001 - unreadable (key lost)
        row.status, row.error, row.next_attempt_at = "failed", "target_unreadable", None
        return
    if row.channel == "sms":
        provider = notify_providers.sms_provider()
        result = provider.send(value, row.text) if provider is not None else (False, False, None)
    else:
        api = notify_providers.bot(row.channel)
        result = api.send_message(value, row.text) if api is not None else (False, False, None)
    ok, permanent, _ = result
    row.attempts += 1
    if ok:
        row.status, row.sent_at, row.next_attempt_at, row.error = "sent", now, None, None
        t.fail_count = 0
        return
    if permanent:
        t.fail_count = (t.fail_count or 0) + 1
        if t.fail_count >= PERMANENT_FAILURES_DISABLE:
            t.disabled_at = now
        row.status, row.error, row.next_attempt_at = "failed", "provider_rejected", None
        return
    if row.attempts > len(RETRY_DELAYS):
        row.status, row.error, row.next_attempt_at = "failed", "provider_unreachable", None
        return
    row.error = "retrying"
    row.next_attempt_at = now + RETRY_DELAYS[row.attempts - 1]


def _release_deferred(db: Session, now: datetime) -> None:
    """Quiet windows that ended: one digest per (account, channel, target)."""
    rows = list(db.scalars(select(NotificationOutbox).where(NotificationOutbox.status == "deferred",
                                                            NotificationOutbox.next_attempt_at <= now)
                           .order_by(NotificationOutbox.id)))
    groups: dict[tuple, list] = {}
    for r in rows:
        groups.setdefault((r.client_id, r.channel, r.target_id), []).append(r)
    for (client_id, channel, tid), members in groups.items():
        if len(members) == 1:
            members[0].status, members[0].next_attempt_at = "pending", now
            continue
        for m in members:
            m.status, m.error, m.next_attempt_at = "skipped", "digest", None
        db.add(_row(client_id, None, "digest", "info", channel, tid, members[0].lang, {"n": len(members)},
                    f"0:digest:{secrets.token_hex(4)}", now))


def _rate_digests(db: Session, now: datetime) -> None:
    """One digest per hour per (account, channel, target) for messages dropped by the rate limits."""
    hour = now.replace(minute=0, second=0, microsecond=0)
    prev = hour - timedelta(hours=1)
    rows = db.execute(select(NotificationOutbox.client_id, NotificationOutbox.channel, NotificationOutbox.target_id,
                             func.count(NotificationOutbox.id)).where(
        NotificationOutbox.error == "rate_limited", NotificationOutbox.created_at >= prev,
        NotificationOutbox.created_at < hour).group_by(NotificationOutbox.client_id, NotificationOutbox.channel,
                                                      NotificationOutbox.target_id)).all()
    for client_id, channel, tid, n in rows:
        key = f"0:digest-rate:{prev:%Y%m%d%H}:{channel}:{tid or 0}"
        if _recent(db, client_id, key, prev):
            continue
        lang = "fa"
        db.add(_row(client_id, None, "digest", "info", channel, tid, lang, {"n": int(n)}, key, now))


def run(db: Session, now: datetime | None = None) -> int:
    """job_notify body: release quiet windows, send due SMS / bot rows, rate-limit digests, expire and
    prune. Returns the number of rows attempted."""
    now = now or utcnow()
    _release_deferred(db, now)
    _rate_digests(db, now)
    db.commit()
    due = list(db.scalars(select(NotificationOutbox).where(
        NotificationOutbox.status == "pending", NotificationOutbox.channel != "email",
        NotificationOutbox.next_attempt_at <= now).order_by(NotificationOutbox.id).limit(200)))
    for row in due:
        _deliver(db, row, now)
        db.commit()
    db.execute(NotificationOutbox.__table__.update().where(
        NotificationOutbox.channel == "email", NotificationOutbox.status == "pending",
        NotificationOutbox.created_at < now - EMAIL_EXPIRE).values(status="expired", next_attempt_at=None))
    db.execute(delete(NotificationOutbox).where(NotificationOutbox.created_at < now - OUTBOX_RETENTION))
    db.execute(delete(NotificationLinkCode).where(NotificationLinkCode.created_at < now - timedelta(days=2)))
    db.commit()
    return len(due)


# ------------------------------------------------------------------ e-mail outbox (WHMCS cron)

def outbox_item(db: Session, r: NotificationOutbox) -> dict:
    site = db.get(Site, r.site_id) if r.site_id else None
    return {"id": r.id, "client_id": r.client_id, "service_id": site.external_id if site is not None else None,
            "site": site.domain if site is not None else None, "event": r.event, "severity": r.severity,
            "lang": r.lang, "subject": r.subject, "text": r.text, "vars": _loads(r.vars, {}),
            "created_at": iso(r.created_at)}


def outbox(db: Session, after: int, limit: int, now: datetime | None = None) -> dict:
    """Pending e-mail rows due now (a row offered is re-offered after 30 min unless acknowledged)."""
    now = now or utcnow()
    rows = list(db.scalars(select(NotificationOutbox).where(
        NotificationOutbox.channel == "email", NotificationOutbox.status == "pending",
        NotificationOutbox.id > after, NotificationOutbox.created_at >= now - EMAIL_EXPIRE,
        or_(NotificationOutbox.next_attempt_at.is_(None), NotificationOutbox.next_attempt_at <= now))
        .order_by(NotificationOutbox.id).limit(limit + 1)))
    more = len(rows) > limit
    rows = rows[:limit]
    for r in rows:
        r.attempts += 1
        r.next_attempt_at = now + EMAIL_REOFFER
    items = [outbox_item(db, r) for r in rows]
    db.commit()
    return {"items": items, "next": rows[-1].id if more and rows else None}


def ack(db: Session, results: dict, now: datetime | None = None) -> dict:
    now = now or utcnow()
    done = 0
    for raw_id, result in (results or {}).items():
        try:
            rid = int(raw_id)
        except (TypeError, ValueError):
            continue
        if result not in ("sent", "failed", "skipped"):
            continue
        r = db.get(NotificationOutbox, rid)
        if r is None or r.channel != "email" or r.status != "pending":
            continue
        r.status, r.next_attempt_at = result, None
        if result == "sent":
            r.sent_at = now
        done += 1
    db.commit()
    return {"acked": done}


def capi_alerts(db: Session, site: Site) -> dict:
    client_id = account_of(site)
    if not client_id:
        return {"subscriptions": []}
    subs = db.scalars(select(NotificationSubscription).where(
        NotificationSubscription.client_id == client_id,
        or_(NotificationSubscription.site_id.is_(None), NotificationSubscription.site_id == site.id))
        .order_by(NotificationSubscription.id))
    return {"subscriptions": [sub_dict(db, s) for s in subs]}


# ------------------------------------------------------------------ new event sources

WEB_ORIGIN_KEY = "web_origin:{}"
WEB_ORIGIN_LAST = "web_origin:last_window"
WINDOW = timedelta(minutes=5)
MIN_REQUESTS = 20
DOWN_PCT = 50
UP_PCT = 10


def _window_counts(db: Session, start: datetime, end: datetime) -> dict[int, tuple[int, int]]:
    from .models import AnalyticsMinute

    out: dict[int, list] = {}
    for sid, req, details in db.execute(select(AnalyticsMinute.site_id, AnalyticsMinute.requests,
                                               AnalyticsMinute.details).where(
            AnalyticsMinute.minute >= start, AnalyticsMinute.minute < end)):
        d = _loads(details, {})
        if "oe" not in d and "pe" not in d:
            continue  # minutes from agents that do not count origin errors
        acc = out.setdefault(sid, [0, 0])
        acc[0] += int(req or 0)
        acc[1] += max(int(d.get("oe") or 0), 0)
    return {k: (a, min(e, a)) for k, (a, e) in out.items()}


def _verdict(req: int, oe: int) -> str | None:
    if req < MIN_REQUESTS:
        return None
    if oe * 100 >= DOWN_PCT * req:
        return "bad"
    if oe * 100 < UP_PCT * req:
        return "good"
    return None


def check_web_origins(db: Session, now: datetime | None = None) -> list[tuple[str, str]]:
    """origin.down / origin.up (SPEC §23.5) from the minute buckets' origin-attributed 5xx (`oe`): two
    consecutive 5-minute windows with ≥ 20 requests and oe ≥ 50 % -> down; < 10 % for two -> up."""
    from . import tunnel_quality

    now = now or utcnow()
    end = now.replace(minute=now.minute - now.minute % 5, second=0, microsecond=0)
    if kv.get_json(db, WEB_ORIGIN_LAST).get("end") == end.isoformat():
        return []
    w2 = _window_counts(db, end - WINDOW, end)
    w1 = _window_counts(db, end - 2 * WINDOW, end - WINDOW)
    emitted = []
    for sid in sorted(set(w1) | set(w2)):
        v1, v2 = _verdict(*w1.get(sid, (0, 0))), _verdict(*w2.get(sid, (0, 0)))
        if v1 is None or v1 != v2:
            continue
        site = db.get(Site, sid)
        if site is None:
            continue
        key = WEB_ORIGIN_KEY.format(sid)
        st = kv.get_json(db, key)
        cur = st.get("state") or "up"
        req, oe = w2.get(sid, (0, 0))
        if v2 == "bad" and cur != "down":
            st = {"state": "down", "since": now.isoformat()}
            tunnel_quality.record_event(db, site, "origin.down", {"requests": req, "origin_errors": oe,
                                                                  "since": iso(now)}, now)
            emitted.append((site.domain, "origin.down"))
        elif v2 == "good" and cur == "down":
            down_since = st.get("since")
            st = {"state": "up", "since": now.isoformat()}
            tunnel_quality.record_event(db, site, "origin.up", {"requests": req, "origin_errors": oe,
                                                                "since": iso(now), "down_since": down_since}, now)
            emitted.append((site.domain, "origin.up"))
        else:
            continue
        kv.set_json(db, key, st)
    kv.set_json(db, WEB_ORIGIN_LAST, {"end": end.isoformat()})
    db.commit()
    return emitted


SSL_THRESHOLDS = (14, 7, 3, 1)
SSL_KEY = "ssl_expiring:{}"
SSL_LAST = "ssl_expiring:last_day"


def check_ssl_expiring(db: Session, now: datetime | None = None, force: bool = False) -> list[tuple[str, int]]:
    """Daily: ssl.expiring once per threshold (14/7/3/1 days) per certificate."""
    from . import webhooks

    now = now or utcnow()
    today = now.date().isoformat()
    if not force and kv.get_json(db, SSL_LAST).get("day") == today:
        return []
    out = []
    for site in db.scalars(select(Site).where(Site.ssl_status == "active", Site.ssl_expires_at.is_not(None),
                                              Site.ssl_expires_at <= now + timedelta(days=SSL_THRESHOLDS[0]),
                                              Site.ssl_expires_at > now)):
        days = max(1, -(-int((site.ssl_expires_at - now).total_seconds()) // 86400))
        threshold = min(t for t in SSL_THRESHOLDS if days <= t) if days <= SSL_THRESHOLDS[0] else None
        if threshold is None:
            continue
        serial = hashlib.sha256((site.ssl_cert or "").encode()).hexdigest()[:16]
        key = SSL_KEY.format(site.id)
        st = kv.get_json(db, key)
        if st.get("serial") != serial:
            st = {"serial": serial, "sent": []}
        if threshold in st["sent"]:
            continue
        st["sent"] = sorted(set(st["sent"]) | {threshold})
        kv.set_json(db, key, st)
        webhooks.emit(db, site, "ssl.expiring", {"days": days, "days_threshold": threshold, "serial": serial,
                                                 "expires_at": iso(site.ssl_expires_at)}, now)
        out.append((site.domain, threshold))
    kv.set_json(db, SSL_LAST, {"day": today})
    db.commit()
    return out


def prune_site(db: Session, site_id: int) -> None:
    db.execute(delete(NotificationSubscription).where(NotificationSubscription.site_id == site_id))
    db.execute(NotificationOutbox.__table__.update().where(NotificationOutbox.site_id == site_id)
               .values(site_id=None))

