"""Webhooks (SPEC §14.3.3): signed event deliveries to customer endpoints.

* Section `webhooks` holds ≤ max_webhooks items `{id, url, events, enabled, description}`; ids
  ("wh_" + 8 hex) and signing secrets ("whsec_" + 40 hex, encrypted at rest in site_secrets) are
  controller-generated. A PUT that creates items returns their secrets once (`new_secrets`).
* `emit()` is called on the real code paths (purge, certificates, quota, suspend, attacks). It
  only inserts pending `webhook_delivery` rows in the caller's transaction — it never does network
  I/O and never raises, so it cannot break or slow the triggering request.
* The leader job (`run_due`, every ~30 s via the scheduler fast lane) claims due rows with a short
  lease and hands them to a small worker pool (never the scheduler thread). Each attempt re-runs the
  SSRF guard and connects to the vetted address: `POST url` with the stored JSON body, 10 s timeout,
  no redirects, response read ≤ 4 KB and discarded, `X-Pcdn-Signature: sha256=HMAC(secret,
  timestamp + "." + body)` over the exact bytes sent. 2xx = delivered.
* Retries after a failure: 1 m, 5 m, 30 m, 2 h, 6 h, then every 6 h until 24 h after creation ->
  `failed`. Rows are kept 7 days (job_cleanup).
"""

import hashlib
import hmac
import json
import logging
import secrets as pysecrets
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta

import httpx
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from . import kv, netguard, sections, site_secrets
from .config import settings
from .db import SessionLocal
from .models import Site, WebhookDelivery, utcnow

log = logging.getLogger("pcdn.webhooks")

USER_AGENT = "PasargadCDN-Webhooks/1"
TIMEOUT = 10.0
READ_MAX = 4096
BACKOFF = (60, 300, 1800, 7200, 21600)  # after failed attempt 1, 2, 3, 4, 5; then every 6 h
GIVE_UP = timedelta(hours=24)
KEEP = timedelta(days=7)
# a claimed row is not handed out again for this long; BATCH x TIMEOUT / workers stays well below it
LEASE = timedelta(minutes=5)
BATCH = 100
ATTACK_EVERY = timedelta(hours=1)
ATTACK_KEY = "attack:{}"

_executor = ThreadPoolExecutor(max_workers=8, thread_name_prefix="pcdn-webhooks")


def _iso(dt: datetime | None) -> str | None:
    return dt.isoformat(timespec="seconds") + "Z" if dt else None


# ------------------------------------------------------------------ section write (ids + secrets)

def new_hook_id(taken: set[str]) -> str:
    while True:
        hid = "wh_" + pysecrets.token_hex(4)
        if hid not in taken:
            return hid


def apply_write(site: Site, value: dict) -> tuple[dict, dict[str, str]]:
    """PUT webhooks: keep the ids of items the site already has, assign new ids (and secrets) to
    items without an id or with an unknown one, forget the secrets of removed items. Returns the
    section as stored and {id: secret} of the newly created items (shown once)."""
    known = {i["id"] for i in sections.get_section(site, "webhooks")["items"]}
    taken = set(known) | {i["id"] for i in value["items"] if i.get("id")}
    new_secrets: dict[str, str] = {}
    items = []
    for item in value["items"]:
        item = dict(item)
        if not item.get("id") or item["id"] not in known:
            item["id"] = new_hook_id(taken)
            taken.add(item["id"])
            secret = site_secrets.new_webhook_secret()
            site_secrets.set_webhook_secret(site, item["id"], secret)
            new_secrets[item["id"]] = secret
        items.append(item)
    site_secrets.keep_webhook_secrets(site, {i["id"] for i in items})
    return sections.storable("webhooks", {**value, "items": items}), new_secrets


def find_hook(site: Site, hook_id: str) -> dict | None:
    return next((i for i in sections.get_section(site, "webhooks")["items"] if i["id"] == hook_id), None)


def rotate(site: Site, hook_id: str) -> str | None:
    """New signing secret for one hook (None when the hook does not exist). Caller commits."""
    if find_hook(site, hook_id) is None:
        return None
    secret = site_secrets.new_webhook_secret()
    site_secrets.set_webhook_secret(site, hook_id, secret)
    return secret


# ------------------------------------------------------------------ emitting events

def active_hooks(site: Site, event: str) -> list[dict]:
    """Enabled hooks of the site subscribed to `event`, within the plan's max_webhooks."""
    limit = int(sections.features_of(site).get("max_webhooks") or 0)
    if limit <= 0:
        return []
    items = sections.get_section(site, "webhooks")["items"][:limit]
    return [i for i in items if i["enabled"] and event in i["events"]]


def _body(event_id: str, event: str, site: Site, data: dict, now: datetime) -> str:
    return json.dumps({"id": event_id, "type": event, "created_at": _iso(now), "site": site.domain,
                       "data": data}, ensure_ascii=False, separators=(",", ":"))


def new_event_id() -> str:
    return "evt_" + pysecrets.token_hex(8)


def emit(db: Session, site: Site, event: str, data: dict | None = None, now: datetime | None = None,
         event_id: str | None = None, notify_customers: bool = True) -> int:
    """Queue `event` for every matching hook of `site` (pending rows, caller's transaction). Never
    raises; returns the number of deliveries queued. `event_id` lets a caller that also records the
    event elsewhere (site_events, SPEC §15.4) use the same id in the webhook body. Every site event
    also reaches the customer notification engine (SPEC §23.5, notify.py), hooks or not."""
    if notify_customers:
        try:
            from . import notify

            notify.on_webhook_event(db, site, event, data)
        except Exception:  # noqa: BLE001 - never break the triggering request
            log.exception("could not queue customer notification %s", event)
    try:
        hooks = active_hooks(site, event)
        if not hooks:
            return 0
        now = now or utcnow()
        event_id = event_id or new_event_id()
        payload = _body(event_id, event, site, data or {}, now)
        for h in hooks:
            db.add(WebhookDelivery(delivery_id="dlv_" + pysecrets.token_hex(8), site_id=site.id, hook_id=h["id"],
                                   event=event, event_id=event_id, payload=payload, status="pending",
                                   attempts=0, created_at=now, next_attempt_at=now))
        return len(hooks)
    except Exception:  # noqa: BLE001 - emitting must never break the triggering request
        log.exception("could not queue webhook event %s", event)
        return 0


def note_security(db: Session, site: Site, events: int, by_source: dict | None = None,
                  now: datetime | None = None) -> bool:
    """attack.detected (SPEC §14.3.3): count the site's security events in fixed 5-minute windows;
    above ATTACK_EVENTS_PER_5M emit at most once per hour. Only sites with a hook subscribed to the
    event keep a counter. Caller commits. Never raises; True when the event was emitted."""
    try:
        if events <= 0 or not active_hooks(site, "attack.detected"):
            return False
        now = now or utcnow()
        bucket = now.replace(minute=now.minute - now.minute % 5, second=0, microsecond=0)
        key = ATTACK_KEY.format(site.id)
        st = kv.lock_json(db, key)  # edges of the same site serialize on this row
        if st.get("bucket") != bucket.isoformat():
            st = {"bucket": bucket.isoformat(), "n": 0, "fired_at": st.get("fired_at"), "by_source": {}}
        st["n"] = int(st.get("n") or 0) + int(events)
        src = st.setdefault("by_source", {})
        for k, v in (by_source or {}).items():
            src[str(k)[:16]] = int(src.get(str(k)[:16], 0)) + int(v)
        fired = False
        last = datetime.fromisoformat(st["fired_at"]) if st.get("fired_at") else None
        threshold = settings.attack_events_per_5m
        if st["n"] > threshold and (last is None or now - last >= ATTACK_EVERY):
            emit(db, site, "attack.detected", {"events_5m": st["n"], "threshold": threshold,
                                               "window_start": _iso(bucket), "by_source": dict(src)}, now)
            st["fired_at"] = now.isoformat()
            fired = True
        kv.set_json(db, key, st)
        return fired
    except Exception:  # noqa: BLE001
        log.exception("attack detection failed for site %s", getattr(site, "id", "?"))
        return False


# ------------------------------------------------------------------ delivery

def sign(secret: str, timestamp: str, body: bytes) -> str:
    return "sha256=" + hmac.new(secret.encode(), timestamp.encode() + b"." + body, hashlib.sha256).hexdigest()


def send(url: str, secret: str, event: str, delivery_id: str, body: bytes,
         timestamp: int | None = None) -> tuple[bool, int | None, str | None]:
    """One POST (no DB access): SSRF check, connect to the vetted address, 10 s timeout, no
    redirects, ≤ 4 KB of the response read and discarded. -> (ok, status_code, error)."""
    try:
        target = netguard.vet(url)
    except netguard.UnsafeTarget as e:
        return False, None, str(e)[:500]
    ts = str(int(timestamp if timestamp is not None else time.time()))
    headers = {"Content-Type": "application/json", "User-Agent": USER_AGENT, "X-Pcdn-Event": event,
               "X-Pcdn-Delivery": delivery_id, "X-Pcdn-Timestamp": ts,
               "X-Pcdn-Signature": sign(secret, ts, body)}
    # Residual risk: httpx has no total-request deadline, so a receiver trickling its response
    # *headers* can hold one worker for longer than TIMEOUT (each read still times out after 10 s
    # of silence). The body is bounded by READ_MAX and a 10 s deadline, workers are a fixed small
    # pool and never the scheduler thread, so this cannot stall the platform.
    deadline = time.monotonic() + TIMEOUT
    try:
        with httpx.Client(transport=netguard.PinnedTransport(target), timeout=TIMEOUT,
                          follow_redirects=False) as client:
            with client.stream("POST", url, content=body, headers=headers) as r:
                code = r.status_code
                read = 0
                try:
                    for chunk in r.iter_raw():  # read ≤ 4 KB, discard it
                        read += len(chunk)
                        if read >= READ_MAX or time.monotonic() > deadline:
                            break
                except httpx.HTTPError:
                    pass  # the status line already decided the outcome
    except httpx.TimeoutException:
        return False, None, f"پاسخی در {TIMEOUT:g} ثانیه دریافت نشد"
    except httpx.HTTPError as e:
        return False, None, f"{type(e).__name__}: {e}"[:500]
    except Exception as e:  # noqa: BLE001 - never raises
        return False, None, f"{type(e).__name__}: {e}"[:500]
    if 200 <= code < 300:
        return True, code, None
    if 300 <= code < 400:
        return False, code, f"HTTP {code} (ریدایرکت دنبال نمی‌شود)"
    return False, code, f"HTTP {code}"


def next_delay(attempts: int) -> timedelta:
    """Wait after the `attempts`-th failed attempt."""
    return timedelta(seconds=BACKOFF[attempts - 1] if attempts <= len(BACKOFF) else BACKOFF[-1])


def _record(d: WebhookDelivery, ok: bool, code: int | None, error: str | None, now: datetime) -> None:
    d.attempts = (d.attempts or 0) + 1
    d.last_code, d.last_error = code, error
    if ok:
        d.status, d.delivered_at, d.next_attempt_at = "ok", now, None
        return
    nxt = now + next_delay(d.attempts)
    if nxt > d.created_at + GIVE_UP:
        d.status, d.next_attempt_at = "failed", None
    else:
        d.next_attempt_at = nxt


def _attempt(row_id: int, lease: datetime, now: datetime | None = None) -> None:
    """Worker: one delivery attempt for a row claimed with `lease`; the DB is not held during the
    request. A row whose lease changed meanwhile (it expired and was claimed again) is skipped."""
    db = SessionLocal()
    try:
        d = db.get(WebhookDelivery, row_id)
        if d is None or d.status != "pending" or d.next_attempt_at != lease:
            return
        site = db.get(Site, d.site_id)
        hook = find_hook(site, d.hook_id) if site is not None else None
        secret = None
        if hook is not None:
            try:
                secret = site_secrets.webhook_secret(site, d.hook_id)
            except Exception:  # noqa: BLE001 - CryptoError
                secret = None
        if hook is None or not hook["enabled"]:
            d.attempts, d.status, d.next_attempt_at = d.attempts or 0, "failed", None
            d.last_error = "وب‌هوک حذف یا غیرفعال شده است"
            db.commit()
            return
        url, event, delivery_id, body = hook["url"], d.event, d.delivery_id, d.payload.encode("utf-8")
        db.rollback()
        if not secret:
            ok, code, error = False, None, "کلید امضای این وب‌هوک در دسترس نیست؛ آن را بازتولید (rotate) کنید"
        else:
            ok, code, error = send(url, secret, event, delivery_id, body)
        d = db.get(WebhookDelivery, row_id)
        if d is None or d.status != "pending":
            return
        _record(d, ok, code, error, now or utcnow())
        db.commit()
    except Exception:  # noqa: BLE001 - the lease expires and the row is retried
        log.exception("webhook delivery %s failed unexpectedly", row_id)
        db.rollback()
    finally:
        db.close()


def run_due(db: Session, now: datetime | None = None, wait: bool = False) -> list[int]:
    """Leader job body: claim due pending rows (lease) and hand them to the worker pool. Returns
    the claimed row ids; `wait` blocks until the attempts are done (tests)."""
    now = now or utcnow()
    ids = list(db.scalars(select(WebhookDelivery.id).where(
        WebhookDelivery.status == "pending", WebhookDelivery.next_attempt_at.is_not(None),
        WebhookDelivery.next_attempt_at <= now).order_by(WebhookDelivery.next_attempt_at).limit(BATCH)))
    claimed = []
    lease = now + LEASE
    t = WebhookDelivery.__table__
    for row_id in ids:
        res = db.execute(update(t).where(t.c.id == row_id, t.c.status == "pending", t.c.next_attempt_at <= now)
                         .values(next_attempt_at=lease))
        if res.rowcount == 1:
            claimed.append(row_id)
    db.commit()
    futures = [_executor.submit(_attempt, row_id, lease, now if wait else None) for row_id in claimed]
    if wait:
        for f in futures:
            f.result()
    return claimed


# ------------------------------------------------------------------ test + deliveries list

def test(db: Session, site: Site, hook_id: str) -> dict | None:
    """POST .../webhooks/{id}/test: send a `ping` now (also to a disabled hook) and record it as a
    delivery (no retries) -> {ok, status_code, error}; None when the hook does not exist."""
    hook = find_hook(site, hook_id)
    if hook is None:
        return None
    now = utcnow()
    site_id = site.id
    event_id, delivery_id = "evt_" + pysecrets.token_hex(8), "dlv_" + pysecrets.token_hex(8)
    payload = _body(event_id, "ping", site, {"hook_id": hook_id}, now)
    try:
        secret = site_secrets.webhook_secret(site, hook_id)
    except Exception:  # noqa: BLE001 - CryptoError
        secret = None
    db.rollback()  # no transaction is held open across the request
    if not secret:
        ok, code, error = False, None, "کلید امضای این وب‌هوک در دسترس نیست؛ آن را بازتولید (rotate) کنید"
    else:
        ok, code, error = send(hook["url"], secret, "ping", delivery_id, payload.encode("utf-8"))
    db.add(WebhookDelivery(delivery_id=delivery_id, site_id=site_id, hook_id=hook_id, event="ping",
                           event_id=event_id, payload=payload, status="ok" if ok else "failed", attempts=1,
                           last_code=code, last_error=error, created_at=now,
                           delivered_at=utcnow() if ok else None, next_attempt_at=None))
    db.commit()
    return {"ok": ok, "status_code": code, "error": error}


def delivery_dict(d: WebhookDelivery) -> dict:
    return {"id": d.delivery_id, "hook_id": d.hook_id, "event": d.event, "status": d.status,
            "attempts": d.attempts, "last_code": d.last_code, "last_error": d.last_error,
            "created_at": _iso(d.created_at), "delivered_at": _iso(d.delivered_at),
            "next_attempt_at": _iso(d.next_attempt_at)}


def deliveries(db: Session, site: Site, limit: int = 50, now: datetime | None = None) -> list[dict]:
    """Newest first, last 7 days, limit clamped to 1..200."""
    now = now or utcnow()
    limit = max(1, min(int(limit), 200))
    rows = db.scalars(select(WebhookDelivery).where(
        WebhookDelivery.site_id == site.id, WebhookDelivery.created_at >= now - KEEP)
        .order_by(WebhookDelivery.created_at.desc(), WebhookDelivery.id.desc()).limit(limit))
    return [delivery_dict(d) for d in rows]


def prune(db: Session, now: datetime | None = None) -> None:
    """Delete delivery rows older than 7 days (job_cleanup). Caller commits."""
    from sqlalchemy import delete

    now = now or utcnow()
    db.execute(delete(WebhookDelivery).where(WebhookDelivery.created_at < now - KEEP))
