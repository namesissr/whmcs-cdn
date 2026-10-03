"""TLS session ticket keys shared by every node (SPEC §22.8).

With TLS_TICKETS=on a client resumes its TLS session on ANY node of the fleet (faster reconnects
after a DNS change or a drain), at the cost of forward secrecy over one rotation period (see
docs/SECURITY.md). Off by default: nginx then keeps `ssl_session_tickets off`.

* Three keys of 80 random bytes (nginx's AES-256 ticket key format): `next`, `current`, `previous`,
  stored in the `state` table under `tls_tickets` as {"rotated_at", "keys": <crypto.encrypt(JSON)>}.
  Refused (logged once at startup, tickets stay off) without DATA_ENCRYPTION_KEY.
* The scheduler leader rotates every TLS_TICKET_ROTATE_HOURS under a row lock (compare-and-set on
  rotated_at): previous <- current, current <- next, next <- new; the dropped key is gone.
* Edge config `node.tls_tickets` = {"id": first 8 hex of sha256(current), "keys": [current, next,
  previous]} (base64). nginx encrypts with the first key and decrypts with all of them, so a node that
  has not fetched a promotion yet still decrypts tickets made with the new current key (its `next`).

The keys never appear in a log line, an audit entry, an error, /metrics or any admin API answer; the
config version hash covers them (a SHA-256 reveals nothing).
"""

import base64
import hashlib
import json
import logging
import secrets
from datetime import datetime, timedelta

from sqlalchemy.orm import Session

from . import crypto, kv
from .config import settings
from .models import State, utcnow

log = logging.getLogger("pcdn.tls_tickets")

STATE_KEY = "tls_tickets"
KEY_BYTES = 80
ROLES = ("current", "next", "previous")


def active() -> bool:
    """TLS_TICKETS=on AND a usable DATA_ENCRYPTION_KEY."""
    if not settings.tls_tickets:
        return False
    try:
        return crypto.enabled()
    except crypto.CryptoError:
        return False


def startup_check() -> None:
    """Log once at startup when TLS_TICKETS=on cannot be honoured."""
    if settings.tls_tickets and not active():
        log.warning("TLS_TICKETS=on but DATA_ENCRYPTION_KEY is not configured: session tickets stay off "
                    "(the shared ticket keys are only ever stored encrypted)")


def _new_key() -> str:
    return base64.b64encode(secrets.token_bytes(KEY_BYTES)).decode()


def _valid(b64: object) -> bool:
    try:
        return isinstance(b64, str) and len(base64.b64decode(b64, validate=True)) == KEY_BYTES
    except (ValueError, TypeError):
        return False


def _keys(doc: dict) -> dict | None:
    """The decrypted {current, next, previous} of a stored document, None when missing/unreadable."""
    enc = doc.get("keys")
    if not crypto.is_encrypted(enc):
        return None
    try:
        keys = json.loads(crypto.decrypt(enc))
    except (crypto.CryptoError, ValueError, TypeError):
        return None
    if not isinstance(keys, dict) or not all(_valid(keys.get(r)) for r in ROLES):
        return None
    return keys


def _store(db: Session, keys: dict, now: datetime) -> None:
    kv.set_json(db, STATE_KEY, {"rotated_at": now.isoformat(), "keys": crypto.encrypt(json.dumps(keys))})


def rotate(db: Session, now: datetime | None = None, force: bool = False) -> bool:
    """Leader job: create the keys, or rotate them once per period. Returns True when they changed.
    With tickets off the stored keys are deleted (no key outlives its use)."""
    now = now or utcnow()
    if not active():
        row = db.get(State, STATE_KEY)
        if row is not None:
            db.delete(row)
            db.commit()
        return False
    doc = kv.lock_json(db, STATE_KEY)  # row lock: one rotation per period across controllers
    keys = _keys(doc)
    try:
        rotated = datetime.fromisoformat(doc["rotated_at"]) if doc.get("rotated_at") else None
    except (TypeError, ValueError):
        rotated = None
    period = timedelta(hours=settings.tls_ticket_rotate_hours)
    if keys is not None and rotated is not None and now - rotated < period and not force:
        db.commit()  # release the lock
        return False
    if keys is None:
        keys = {"current": _new_key(), "next": _new_key(), "previous": _new_key()}
        log.info("TLS session ticket keys created")
    else:
        keys = {"previous": keys["current"], "current": keys["next"], "next": _new_key()}
        log.info("TLS session ticket keys rotated")
    _store(db, keys, now)
    db.commit()
    return True


def edge_block(db: Session) -> dict | None:
    """Edge config `node.tls_tickets` or None (off / not created yet / unreadable)."""
    if not active():
        return None
    keys = _keys(kv.get_json(db, STATE_KEY))
    if keys is None:
        return None
    kid = hashlib.sha256(base64.b64decode(keys["current"])).hexdigest()[:8]
    return {"id": kid, "keys": [keys["current"], keys["next"], keys["previous"]]}


def status(db: Session) -> dict:
    """Secret-free view for the operator: whether tickets are on and when they last rotated."""
    doc = kv.get_json(db, STATE_KEY)
    return {"enabled": active(), "configured": bool(settings.tls_tickets),
            "rotated_at": doc.get("rotated_at") if _keys(doc) is not None else None,
            "rotate_hours": settings.tls_ticket_rotate_hours}
