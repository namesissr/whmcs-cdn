"""Derived HMAC keys for lookup hashes (SPEC §23): notification target hashes, abuse reporter hashes,
abuse challenge signatures. Derived with HKDF from the first DATA_ENCRYPTION_KEY or, without one, from a
random controller-wide `state` value created once (so hashes stay stable either way). Never logged."""

import hashlib
import hmac
import secrets

from .config import settings
from .models import State

STATE_KEY = "hmac_master_key"


def _hkdf(material: bytes, info: str) -> bytes:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info.encode()).derive(material)


def _master(db=None, state_key: str = STATE_KEY) -> bytes:
    raw = (settings.data_encryption_key or "").split(",")[0].strip()
    if raw:
        return raw.encode()
    from . import kv
    from .db import SessionLocal

    row = db.get(State, state_key) if db is not None else None
    if row is not None and row.value:
        return bytes.fromhex(row.value)
    if db is not None:
        # inside the caller's transaction (committed with it); main.py creates the keys at startup
        kv.insert_ignore(db, State, {"key": state_key, "value": secrets.token_hex(32)})
        db.flush()
        return bytes.fromhex(db.get(State, state_key, populate_existing=True).value)
    own = SessionLocal()
    try:
        kv.insert_ignore(own, State, {"key": state_key, "value": secrets.token_hex(32)})
        own.commit()
        return bytes.fromhex(own.get(State, state_key, populate_existing=True).value)
    finally:
        own.close()


def key(info: str, db=None, state_key: str = STATE_KEY) -> bytes:
    return _hkdf(_master(db, state_key), info)


def mac(info: str, message: str, db=None) -> str:
    return hmac.new(key(info, db), message.encode(), hashlib.sha256).hexdigest()
