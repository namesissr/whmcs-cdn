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

import json
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

# encrypted columns of the sites table (ORM attribute names). sites.integration_secrets is a JSON
# document whose values are each encrypted (log-export S3 secret key, webhook signing secrets,
# SPEC §14.3); site_secrets.map_values / values / drop_unreadable handle it below.
SITE_SECRETS = ("ssl_key_stored", "secret_stored", "origin_client_key_stored",
                # SPEC §22.8: the optional RSA certificate's key (ACME_DUAL_RSA)
                "ssl_key_rsa_stored")
# `state` rows holding a JSON document whose listed fields are encrypted secrets (the platform
# origin-pull CA + client certificate keys, SPEC §14.2; see origin_pull.py)
STATE_SECRETS = {"origin_pull:platform": ("ca_key", "client_key"),
                 # SPEC §22.8: the fleet's TLS session ticket keys (one encrypted JSON document)
                 "tls_tickets": ("keys",)}
# encrypted columns of storage_buckets (SPEC §16.8): the customer's MinIO secret key (shown once,
# kept for the record) and the bucket's edge origin token
STORAGE_SECRETS = ("secret_key_stored", "origin_token_stored")


def _storage_rows(db):
    from sqlalchemy import select

    from .models import StorageBucket

    return list(db.scalars(select(StorageBucket).order_by(StorageBucket.id)))


def _map_storage_secrets(db, fn, plaintext_only: bool) -> int:
    changed = 0
    for b in _storage_rows(db):
        for attr in STORAGE_SECRETS:
            v = getattr(b, attr)
            if v and not (plaintext_only and is_encrypted(v)):
                setattr(b, attr, fn(v))
                changed += 1
    return changed


def _secret_rows(db):
    from sqlalchemy import select

    from .models import Site

    return db.scalars(select(Site).order_by(Site.id))


def _state_docs(db):
    """(row, document, secret fields) of every STATE_SECRETS row present."""
    from sqlalchemy import select

    from .models import State

    for row in list(db.scalars(select(State).where(State.key.in_(list(STATE_SECRETS))))):
        try:
            doc = json.loads(row.value)
        except ValueError:
            continue
        if isinstance(doc, dict):
            yield row, doc, STATE_SECRETS[row.key]


def _map_state_secrets(db, fn, plaintext_only: bool) -> int:
    """Apply encrypt/rotate to the secret fields of the STATE_SECRETS documents; returns the count."""
    changed = 0
    for row, doc, fields in _state_docs(db):
        touched = 0
        for f in fields:
            v = doc.get(f)
            if v and not (plaintext_only and is_encrypted(v)):
                doc[f] = fn(v)
                touched += 1
        if touched:
            row.value = json.dumps(doc)
            changed += touched
    return changed


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
    from . import site_secrets

    values = [v for row in db.execute(select(*(getattr(Site, a) for a in SITE_SECRETS))) for v in row]
    values += [doc.get(f) for _, doc, fields in _state_docs(db) for f in fields]
    values += [v for site in _secret_rows(db) for v in site_secrets.values(site)]
    values += [getattr(b, a) for b in _storage_rows(db) for a in STORAGE_SECRETS]
    sample = None
    for v in values:
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
    from . import site_secrets

    changed = 0
    for site in _secret_rows(db):
        for attr in SITE_SECRETS:
            v = getattr(site, attr)
            if v and not is_encrypted(v):
                setattr(site, attr, encrypt(v))
                changed += 1
        changed += site_secrets.map_values(site, encrypt, plaintext_only=True)
    changed += _map_state_secrets(db, encrypt, plaintext_only=True)
    changed += _map_storage_secrets(db, encrypt, plaintext_only=True)
    db.commit()
    return changed


def rotate_all(db) -> int:
    """Re-encrypt every secret with the primary key (after adding a new key in front)."""
    if not enabled():
        raise CryptoError("DATA_ENCRYPTION_KEY is not set")
    from . import site_secrets

    changed = 0
    for site in _secret_rows(db):
        for attr in SITE_SECRETS:
            v = getattr(site, attr)
            if v:
                setattr(site, attr, rotate(v))
                changed += 1
        changed += site_secrets.map_values(site, rotate, plaintext_only=False)
    changed += _map_state_secrets(db, rotate, plaintext_only=False)
    changed += _map_storage_secrets(db, rotate, plaintext_only=False)
    db.commit()
    return changed


def _readable(v: str | None) -> bool:
    try:
        decrypt(v)
        return True
    except CryptoError:
        return False


def drop_unreadable(db) -> list[str]:
    """Last resort after losing DATA_ENCRYPTION_KEY: forget secrets that cannot be decrypted.

    Let's Encrypt certificates are queued for re-issue, custom certificates (and custom origin
    client certificates) are removed (the customer must upload them again), and challenge secrets
    are regenerated. An unreadable platform origin-pull CA is dropped and recreated on next use
    (customers using it must download the new CA). Returns the affected domains.
    """
    import secrets as pysecrets

    affected = []
    for site in _secret_rows(db):
        touched = False
        if not _readable(site.ssl_key_stored):
            site.ssl_key_stored = None
            site.ssl_cert = None
            site.ssl_expires_at = None
            if site.ssl_source == "custom" or not site.ssl_allowed or site.ns_verified_at is None:
                site.ssl_status, site.ssl_source = "none", None
            else:
                site.ssl_status = "pending"
            touched = True
        if not _readable(site.ssl_key_rsa_stored):  # SPEC §22.8: re-issued with the next renewal
            site.ssl_key_rsa_stored = site.ssl_cert_rsa = None
            touched = True
        if not _readable(site.origin_client_key_stored):
            site.origin_client_key_stored = site.origin_client_cert = site.origin_client_expires_at = None
            touched = True
        if not _readable(site.secret_stored):
            site.secret = pysecrets.token_hex(32)
            touched = True
        # log-export secret key / webhook signing secrets: forgotten; the customer re-enters the key
        # and rotates the webhook secrets (GET then shows secret_key_set / secret_set false)
        from . import site_secrets

        if site_secrets.drop_unreadable(site, _readable):
            touched = True
        if touched:
            affected.append(site.domain)
    for row, doc, fields in _state_docs(db):
        if not all(_readable(doc.get(f)) for f in fields):
            log.warning("dropping the unreadable %s secrets; they are recreated on next use", row.key)
            db.delete(row)
    # storage buckets (SPEC §16.8): the stored copy of the customer's secret is only a record (it was
    # shown once) and is forgotten; a new edge origin token is generated — the hourly storage job
    # re-applies every bucket's origin policy, so the edges use the new token within the hour
    import secrets as pysecrets

    for b in _storage_rows(db):
        if not _readable(b.secret_key_stored):
            b.secret_key_stored = ""
        if not _readable(b.origin_token_stored):
            b.origin_token = pysecrets.token_hex(24)
    db.commit()
    return affected
