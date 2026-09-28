"""Encryption at rest for secrets stored in the controller database.

DATA_ENCRYPTION_KEY holds one or more Fernet keys (urlsafe base64 of 32 random bytes),
comma separated. The first key encrypts; every key is tried when decrypting, so a key
can be rotated without downtime:

    1. DATA_ENCRYPTION_KEY=<new>,<old>   and restart every controller
    2. python -m app.manage rotate-key   (re-encrypts every row with <new>)
    3. DATA_ENCRYPTION_KEY=<new>         and restart again

Encrypted values are stored as "enc:v1:<fernet token>". Values without the prefix are
plaintext (rows written before a key was configured) and are returned unchanged, so
turning encryption on never breaks existing data; `python -m app.manage encrypt-secrets`
(also run automatically at startup when a key is set) encrypts them in place.

Key material is never logged: errors mention the key index, never its value.
"""

import logging

from cryptography.fernet import Fernet, InvalidToken, MultiFernet

from .config import settings

log = logging.getLogger("pcdn.crypto")

PREFIX = "enc:v1:"


class CryptoError(RuntimeError):
    pass


_cache: tuple[str, MultiFernet | None] | None = None


def _keys_raw() -> str:
    return settings.data_encryption_key or ""


def _fernet() -> MultiFernet | None:
    """MultiFernet built from DATA_ENCRYPTION_KEY (cached per key string), None when unset."""
    global _cache
    raw = _keys_raw()
    if _cache is not None and _cache[0] == raw:
        return _cache[1]
    parts = [p.strip() for p in raw.split(",") if p.strip()]
    if not parts:
        _cache = (raw, None)
        return None
    fernets = []
    for i, p in enumerate(parts):
        try:
            fernets.append(Fernet(p.encode()))
        except (ValueError, TypeError):
            raise CryptoError(
                f"DATA_ENCRYPTION_KEY: key #{i + 1} is not a valid Fernet key "
                "(expected urlsafe base64 of 32 bytes; generate one with `python -m app.manage gen-key`)"
            ) from None
    _cache = (raw, MultiFernet(fernets))
    return _cache[1]


def enabled() -> bool:
    return _fernet() is not None


def generate_key() -> str:
    return Fernet.generate_key().decode()


def is_encrypted(value: str | None) -> bool:
    return bool(value) and value.startswith(PREFIX)


def encrypt(value: str | None) -> str | None:
    """Encrypt with the primary key; plaintext passthrough when no key is configured."""
    if value is None or value == "" or is_encrypted(value):
        return value
    f = _fernet()
    if f is None:
        return value
    return PREFIX + f.encrypt(value.encode()).decode()


def decrypt(value: str | None) -> str | None:
    if not is_encrypted(value):
        return value
    f = _fernet()
    if f is None:
        raise CryptoError(
            "an encrypted secret was found in the database but DATA_ENCRYPTION_KEY is not set"
        )
    try:
        return f.decrypt(value[len(PREFIX):].encode()).decode()
    except InvalidToken:
        raise CryptoError(
            "cannot decrypt a secret: DATA_ENCRYPTION_KEY does not contain the key it was encrypted with"
        ) from None


def rotate(value: str | None) -> str | None:
    """Re-encrypt with the primary key (or encrypt a plaintext value)."""
    if value is None or value == "":
        return value
    f = _fernet()
    if f is None:
        raise CryptoError("DATA_ENCRYPTION_KEY is not set")
    if not is_encrypted(value):
        return encrypt(value)
    try:
        return PREFIX + f.rotate(value[len(PREFIX):].encode()).decode()
    except InvalidToken:
        raise CryptoError(
            "cannot decrypt a secret: DATA_ENCRYPTION_KEY does not contain the key it was encrypted with"
        ) from None


# ------------------------------------------------------------------ bulk operations

def _secret_rows(db):
    from sqlalchemy import select

    from .models import Site

    return db.scalars(select(Site).order_by(Site.id))


def status(db) -> dict:
    """Counts of plaintext / encrypted secrets and whether the current keys can read them."""
    from sqlalchemy import select

    from .models import Site

    out = {"key_configured": False, "plaintext": 0, "encrypted": 0, "readable": True, "error": None}
    try:
        out["key_configured"] = enabled()
    except CryptoError as e:
        out["error"] = str(e)
        out["readable"] = False
    sample = None
    for key_raw, secret_raw in db.execute(select(Site.ssl_key_stored, Site.secret_stored)):
        for v in (key_raw, secret_raw):
            if not v:
                continue
            if is_encrypted(v):
                out["encrypted"] += 1
                sample = sample or v
            else:
                out["plaintext"] += 1
    if sample and out["error"] is None:
        try:
            decrypt(sample)
        except CryptoError as e:
            out["readable"] = False
            out["error"] = str(e)
    return out


def encrypt_existing(db) -> int:
    """Encrypt every plaintext secret with the primary key. Returns the number of values changed."""
    if not enabled():
        raise CryptoError("DATA_ENCRYPTION_KEY is not set")
    changed = 0
    for site in _secret_rows(db):
        for attr in ("ssl_key_stored", "secret_stored"):
            v = getattr(site, attr)
            if v and not is_encrypted(v):
                setattr(site, attr, encrypt(v))
                changed += 1
    db.commit()
    return changed


def rotate_all(db) -> int:
    """Re-encrypt every secret with the primary key (after adding a new key in front)."""
    if not enabled():
        raise CryptoError("DATA_ENCRYPTION_KEY is not set")
    changed = 0
    for site in _secret_rows(db):
        for attr in ("ssl_key_stored", "secret_stored"):
            v = getattr(site, attr)
            if v:
                setattr(site, attr, rotate(v))
                changed += 1
    db.commit()
    return changed


def drop_unreadable(db) -> list[str]:
    """Last resort after losing DATA_ENCRYPTION_KEY: forget secrets that cannot be decrypted.

    Let's Encrypt certificates are queued for re-issue, custom certificates are removed (the
    customer must upload them again), and challenge secrets are regenerated. Returns the
    affected domains.
    """
    import secrets as pysecrets

    affected = []
    for site in _secret_rows(db):
        touched = False
        try:
            decrypt(site.ssl_key_stored)
        except CryptoError:
            site.ssl_key_stored = None
            site.ssl_cert = None
            site.ssl_expires_at = None
            if site.ssl_source == "custom" or not site.ssl_allowed or site.ns_verified_at is None:
                site.ssl_status, site.ssl_source = "none", None
            else:
                site.ssl_status = "pending"
            touched = True
        try:
            decrypt(site.secret_stored)
        except CryptoError:
            site.secret = pysecrets.token_hex(32)
            touched = True
        if touched:
            affected.append(site.domain)
    db.commit()
    return affected
