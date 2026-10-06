"""Abuse desk (SPEC §23.10): public intake with proof of work, admin queue, owner notice, suspension.

Privacy: nothing about a report is published beyond its status and the public note; the reporter's
e-mail is encrypted and shown to admins only (deleted ABUSE_RETENTION_DAYS after closing); the
reporter's IP is never stored — only an HMAC with a daily-rotated key, for rate limiting, cleared after
30 days. The owner notice never names the reporter.

Abuse suspension (`sites.abuse_suspended`) is independent of billing: `effective_status` is
"suspended" while it is set (edge config, DNS and capi behave as for a billing suspension) and only the
abuse desk clears it.
"""

import hashlib
import hmac
import ipaddress
import json
import re
import secrets
import uuid
from datetime import datetime, timedelta
from urllib.parse import urlsplit

from fastapi import HTTPException
from sqlalchemy import delete, func, or_, select
from sqlalchemy.orm import Session

from . import alerts, keys
from .config import settings
from .models import AbuseEvent, AbuseReport, Site, State, utcnow

CATEGORIES = ("phishing", "malware", "illegal", "spam", "copyright", "other")
STATUSES = ("new", "triage", "notified", "actioned", "closed", "rejected")
FINAL = ("closed", "rejected")
CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
CHALLENGE_TTL = timedelta(minutes=10)
USED_PREFIX = "abuse_pow_used:"
IP_HASH_DAYS = 30
EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,}$")


def _iso(dt: datetime | None) -> str | None:
    return dt.isoformat() + "Z" if dt else None


# ------------------------------------------------------------------ proof of work

def _sig(cid: str, rand: str, exp: int, bits: int) -> str:
    return keys.mac("pcdn-abuse-pow", f"{cid}|{rand}|{exp}|{bits}")[:16]


def challenge(now: datetime | None = None) -> dict:
    """Stateless: the salt carries a random part, the expiry and an HMAC over (id, salt, bits)."""
    now = now or utcnow()
    cid = str(uuid.uuid4())
    rand = secrets.token_hex(8)
    exp = int((now + CHALLENGE_TTL).timestamp())
    bits = settings.abuse_pow_bits
    salt = f"{rand}{exp:010x}{_sig(cid, rand, exp, bits)}"
    return {"id": cid, "salt": salt, "bits": bits, "expires_at": _iso(now + CHALLENGE_TTL)}


def leading_zero_bits(digest: bytes) -> int:
    n = 0
    for b in digest:
        if b == 0:
            n += 8
            continue
        n += 8 - b.bit_length()
        break
    return n


def solve(salt: str, bits: int) -> str:
    """Reference solver (tests, tooling)."""
    i = 0
    while True:
        nonce = str(i)
        if leading_zero_bits(hashlib.sha256((salt + nonce).encode()).digest()) >= bits:
            return nonce
        i += 1


def verify_challenge(db: Session, ch: dict, now: datetime | None = None) -> None:
    """422 unless the challenge is ours, unexpired, unused and solved; marks it used."""
    now = now or utcnow()
    cid, salt, nonce = str(ch.get("id") or ""), str(ch.get("salt") or ""), str(ch.get("nonce") or "")
    m = re.match(r"^([0-9a-f]{16})([0-9a-f]{10})([0-9a-f]{16})$", salt)
    try:
        uuid.UUID(cid)
    except ValueError:
        m = None
    if not m or not nonce or len(nonce) > 64:
        raise HTTPException(422, "invalid_challenge")
    rand, exp, sig = m.group(1), int(m.group(2), 16), m.group(3)
    bits = settings.abuse_pow_bits
    if not hmac.compare_digest(sig, _sig(cid, rand, exp, bits)):
        raise HTTPException(422, "invalid_challenge")
    if exp < int(now.timestamp()):
        raise HTTPException(422, "challenge_expired")
    if leading_zero_bits(hashlib.sha256((salt + nonce).encode()).digest()) < bits:
        raise HTTPException(422, "challenge_unsolved")
    key = USED_PREFIX + cid
    if db.get(State, key) is not None:
        raise HTTPException(422, "challenge_used")
    db.add(State(key=key, value=json.dumps({"exp": exp})))
    db.flush()


# ------------------------------------------------------------------ intake

def ip_hash(ip: str, now: datetime | None = None) -> str | None:
    ip = (ip or "").strip()[:64]
    if not ip:
        return None
    try:
        ip = str(ipaddress.ip_address(ip))
    except ValueError:
        pass  # an unparsable source label is still rate limited as itself
    day = (now or utcnow()).date().isoformat()
    return keys.mac(f"pcdn-abuse-ip:{day}", ip)


def clean_urls(urls) -> list[str]:
    if not isinstance(urls, list) or not 1 <= len(urls) <= 10:
        raise HTTPException(422, "invalid_urls")
    out = []
    for u in urls:
        u = str(u or "").strip()
        if len(u) > 2048 or not re.match(r"^https?://", u, re.I) or re.search(r"\s", u):
            raise HTTPException(422, "invalid_urls")
        host = (urlsplit(u).hostname or "").lower()
        if not host:
            raise HTTPException(422, "invalid_urls")
        if u not in out:
            out.append(u)
    return out


def match_site(db: Session, urls: list[str]) -> Site | None:
    """The site whose domain is a URL host or a parent of it (longest match wins)."""
    best = None
    for u in urls:
        host = (urlsplit(u).hostname or "").lower().rstrip(".")
        parts = host.split(".")
        for i in range(len(parts) - 1):
            cand = ".".join(parts[i:])
            site = db.scalar(select(Site).where(Site.domain == cand))
            if site is not None:
                if best is None or len(site.domain) > len(best.domain):
                    best = site
                break
    return best


def _ticket(db: Session) -> str:
    while True:
        t = "AB-" + "".join(secrets.choice(CROCKFORD) for _ in range(8))
        if db.scalar(select(AbuseReport.id).where(AbuseReport.ticket == t)) is None:
            return t


def _event(db: Session, report: AbuseReport, actor: str, kind: str, data: dict | None = None,
           now: datetime | None = None) -> None:
    raw = json.dumps(data or {}, ensure_ascii=False)
    if len(raw) > 2000:
        raw = json.dumps({"truncated": True})
    db.add(AbuseEvent(report_id=report.id, at=now or utcnow(), actor=actor[:64], kind=kind, data=raw))


def submit(db: Session, body: dict, ip: str | None, check_pow: bool = True, now: datetime | None = None) -> dict:
    now = now or utcnow()
    if str(body.get("website") or ""):
        raise HTTPException(422, "invalid_request")  # honeypot
    category = body.get("category")
    if category not in CATEGORIES:
        raise HTTPException(422, "invalid_category")
    urls = clean_urls(body.get("urls"))
    description = str(body.get("description") or "")
    if len(description) > 4000:
        raise HTTPException(422, "description_too_long")
    email = str(body.get("email") or "").strip()
    if email and (len(email) > 254 or not EMAIL_RE.match(email)):
        raise HTTPException(422, "invalid_email")
    ih = ip_hash(ip or "", now)
    if ih and db.scalar(select(func.count(AbuseReport.id)).where(
            AbuseReport.reporter_ip_hash == ih, AbuseReport.created_at >= now - timedelta(hours=1))) \
            >= settings.abuse_rate_per_hour:
        raise HTTPException(429, "rate_limited")
    if check_pow:
        ch = body.get("challenge")
        if not isinstance(ch, dict):
            raise HTTPException(422, "invalid_challenge")
        verify_challenge(db, ch, now)
    token = secrets.token_urlsafe(18)[:24]
    site = match_site(db, urls)
    r = AbuseReport(ticket=_ticket(db), created_at=now, category=category, urls=json.dumps(urls),
                    description=description, reporter_email_hash=(
                        hashlib.sha256(email.lower().encode()).hexdigest() if email else None),
                    reporter_ip_hash=ih, status_token_hash=hashlib.sha256(token.encode()).hexdigest(),
                    status="new", site_id=site.id if site is not None else None, action="none", updated_at=now)
    r.reporter_email = email or None
    db.add(r)
    db.flush()
    _event(db, r, "reporter", "created", {"category": category, "urls": len(urls)}, now)
    db.commit()
    return {"ticket": r.ticket, "status_token": token}


def public_status(db: Session, ticket: str, token: str) -> dict:
    r = db.scalar(select(AbuseReport).where(AbuseReport.ticket == (ticket or "").upper()))
    want = r.status_token_hash if r is not None else "0" * 64
    ok = hmac.compare_digest(want, hashlib.sha256((token or "").encode()).hexdigest())
    if r is None or not ok:
        raise HTTPException(404, "not found")
    return {"ticket": r.ticket, "status": r.status, "created_at": _iso(r.created_at),
            "updated_at": _iso(r.updated_at), "public_note": r.public_note}


# ------------------------------------------------------------------ admin

def report_dict(db: Session, r: AbuseReport, detail: bool = False) -> dict:
    site = db.get(Site, r.site_id) if r.site_id else None
    try:
        urls = json.loads(r.urls or "[]")
    except ValueError:
        urls = []
    out = {"id": r.id, "ticket": r.ticket, "created_at": _iso(r.created_at), "updated_at": _iso(r.updated_at),
           "category": r.category, "urls": urls, "status": r.status, "action": r.action,
           "site": site.domain if site is not None else None, "deadline_at": _iso(r.deadline_at),
           "public_note": r.public_note, "overdue": bool(r.status == "notified" and r.deadline_at
                                                        and r.deadline_at < utcnow())}
    if detail:
        try:
            email = r.reporter_email
        except Exception:  # noqa: BLE001 - unreadable (key lost)
            email = None
        out.update(description=r.description, reporter_email=email,
                   site_external_id=site.external_id if site is not None else None,
                   site_client_id=site.client_id if site is not None else None,
                   site_abuse_suspended=bool(site.abuse_suspended) if site is not None else None,
                   events=[{"at": _iso(e.at), "actor": e.actor, "kind": e.kind, "data": _loads(e.data)}
                           for e in db.scalars(select(AbuseEvent).where(AbuseEvent.report_id == r.id)
                                               .order_by(AbuseEvent.id))])
    return out


def _loads(raw):
    try:
        v = json.loads(raw or "{}")
    except ValueError:
        return {}
    return v if isinstance(v, dict) else {}


def list_reports(db: Session, status: str | None, category: str | None, q: str | None, limit: int) -> list[dict]:
    query = select(AbuseReport)
    if status:
        query = query.where(AbuseReport.status == status)
    if category:
        query = query.where(AbuseReport.category == category)
    if q:
        like = f"%{q.strip()[:100]}%"
        query = query.where(or_(AbuseReport.ticket.ilike(like), AbuseReport.urls.ilike(like)))
    rows = db.scalars(query.order_by(AbuseReport.id.desc()).limit(limit))
    return [report_dict(db, r) for r in rows]


def get(db: Session, report_id: int) -> AbuseReport:
    r = db.get(AbuseReport, report_id)
    if r is None:
        raise HTTPException(404, "report not found")
    return r


def patch(db: Session, r: AbuseReport, body: dict, actor: str = "admin") -> None:
    now = utcnow()
    if "status" in body and body["status"] is not None:
        if body["status"] not in STATUSES:
            raise HTTPException(422, "invalid_status")
        if body["status"] != r.status:
            _event(db, r, actor, "status", {"from": r.status, "to": body["status"]}, now)
            r.status = body["status"]
            if r.status in FINAL:
                r.closed_at = now
            if r.status == "triage":
                _event(db, r, actor, "triaged", {}, now)
    if body.get("site") is not None:
        domain = str(body["site"]).strip().lower()
        site = db.scalar(select(Site).where(Site.domain == domain)) if domain else None
        if domain and site is None:
            raise HTTPException(422, "unknown_site")
        r.site_id = site.id if site is not None else None
        _event(db, r, actor, "note", {"site": domain or None}, now)
    if body.get("public_note") is not None:
        r.public_note = str(body["public_note"])[:500]
    if body.get("note"):
        _event(db, r, actor, "note", {"note": str(body["note"])[:2000]}, now)
    r.updated_at = now
    db.commit()


def notify_owner(db: Session, r: AbuseReport, deadline_hours: int | None, lang: str, message: str | None,
                 actor: str = "admin") -> None:
    from . import notify

    site = db.get(Site, r.site_id) if r.site_id else None
    if site is None:
        raise HTTPException(409, "no_site")
    now = utcnow()
    hours = deadline_hours or settings.abuse_deadline_hours
    if not 1 <= hours <= 720:
        raise HTTPException(422, "invalid_deadline")
    deadline = now + timedelta(hours=hours)
    try:
        urls = json.loads(r.urls or "[]")
    except ValueError:
        urls = []
    # template vars: domain, category, URLs, deadline, ticket — never the reporter's identity
    values = {"category": r.category, "urls": "\n".join(urls), "deadline": deadline.strftime("%Y-%m-%d %H:%M UTC"),
              "ticket": r.ticket, "message": (message or "")[:2000]}
    if not notify.enqueue_abuse_notice(db, site, values, lang, now):
        raise HTTPException(409, "site_has_no_owner")
    r.status, r.deadline_at, r.updated_at = "notified", deadline, now
    _event(db, r, actor, "notified", {"deadline_hours": hours, "lang": lang}, now)
    db.commit()
    alerts.resolve_alert(f"abuse_overdue:{r.id}", notify=False)
    reporter_mail(r)


def action(db: Session, r: AbuseReport, act: str, public_note: str | None, actor: str = "admin") -> Site | None:
    """warn | suspend | unsuspend | close | reject. Returns the site whose DNS / edge config changed."""
    from . import webhooks

    if act not in ("warn", "suspend", "unsuspend", "close", "reject"):
        raise HTTPException(422, "invalid_action")
    now = utcnow()
    site = db.get(Site, r.site_id) if r.site_id else None
    changed = None
    if act in ("suspend", "unsuspend", "warn") and site is None:
        raise HTTPException(409, "no_site")
    if act == "warn":
        r.action, r.status = "warned", "actioned"
    elif act == "suspend":
        if not site.abuse_suspended:
            if not site.suspended:
                webhooks.emit(db, site, "site.suspended", {"status": "suspended", "reason": "abuse"}, now)
            site.abuse_suspended = True
            changed = site
        r.action, r.status = "suspended", "actioned"
    elif act == "unsuspend":
        if site.abuse_suspended:
            site.abuse_suspended = False
            if not site.suspended:
                webhooks.emit(db, site, "site.unsuspended", {"status": site.effective_status, "reason": "abuse"}, now)
            changed = site
        r.action = "unsuspended"
    elif act == "close":
        r.status, r.closed_at = "closed", now
    else:
        r.status, r.closed_at = "rejected", now
    if public_note is not None:
        r.public_note = str(public_note)[:500]
    r.updated_at = now
    _event(db, r, actor, "action", {"action": act}, now)
    db.commit()
    if r.status != "notified":
        alerts.resolve_alert(f"abuse_overdue:{r.id}", notify=False)
    if r.status in ("actioned", "closed"):
        reporter_mail(r)
    return changed


def reporter_mail(r: AbuseReport) -> None:
    """Status e-mail to the reporter (when one was given): ticket + status + public note only."""
    try:
        email = r.reporter_email
    except Exception:  # noqa: BLE001
        return
    if not email or not alerts.mail_configured():
        return
    fa = {"notified": "به مالک سرویس اطلاع داده شد", "actioned": "اقدام انجام شد", "closed": "بسته شد",
          "rejected": "رد شد"}.get(r.status, r.status)
    body = (f"گزارش {r.ticket}: {fa}\n{r.public_note or ''}\n\n"
            f"Report {r.ticket}: {r.status}\n{r.public_note or ''}")
    try:
        alerts.send_mail(email, f"Pasargad CDN abuse report {r.ticket}", body)
    except Exception:  # noqa: BLE001 - best effort, never logged with the address
        pass


def check(db: Session, now: datetime | None = None) -> dict:
    """job_abuse: overdue alerts, retention of reporter data, used-challenge cleanup."""
    now = now or utcnow()
    active = {}
    for r in db.scalars(select(AbuseReport).where(AbuseReport.status == "notified",
                                                  AbuseReport.deadline_at.is_not(None),
                                                  AbuseReport.deadline_at < now)):
        active[f"abuse_overdue:{r.id}"] = (f"مهلت گزارش تخلف {r.ticket} گذشت",
                                           f"مهلت رسیدگی مالک سرویس به گزارش {r.ticket} ({r.category}) تمام شده است؛ "
                                           "در صفحهٔ «گزارش‌های تخلف» اقدام کنید.", "warning")
    alerts.sync("abuse_overdue:", active)
    cutoff = now - timedelta(days=settings.abuse_retention_days)
    for r in db.scalars(select(AbuseReport).where(AbuseReport.closed_at.is_not(None), AbuseReport.closed_at < cutoff,
                                                  AbuseReport.reporter_email_stored.is_not(None))):
        r.reporter_email_stored = None
        r.reporter_email_hash = None
    db.execute(AbuseReport.__table__.update().where(
        AbuseReport.created_at < now - timedelta(days=IP_HASH_DAYS), AbuseReport.reporter_ip_hash.is_not(None))
        .values(reporter_ip_hash=None))
    stale = [row.key for row in db.scalars(select(State).where(State.key.startswith(USED_PREFIX)))
             if (kv_exp(row.value) or 0) < int(now.timestamp())]
    if stale:
        db.execute(delete(State).where(State.key.in_(stale)))
    db.commit()
    return {"overdue": len(active)}


def kv_exp(raw: str) -> int | None:
    try:
        return int(json.loads(raw).get("exp"))
    except (ValueError, TypeError, AttributeError):
        return None


def open_count(db: Session) -> int:
    return int(db.scalar(select(func.count(AbuseReport.id)).where(AbuseReport.status.notin_(FINAL))) or 0)

