"""Write-only integration secrets of a site (SPEC §14.3): the log-export S3 secret key and the
webhook signing secrets.

Stored in ``sites.integration_secrets`` as JSON ``{"logs": <enc>, "webhooks": {"wh_…": <enc>},
"image_transform": <enc>, "tsig": <enc>}`` (wave 8, SPEC §16.6/§16.7: the image signed-URL key and
the secondary-DNS TSIG secret)
where every value is encrypted with crypto.encrypt (DATA_ENCRYPTION_KEY, like the custom SSL keys);
``crypto`` re-encrypts / rotates / drops them with the other site secrets. Nothing here is ever
returned by a GET, put into the edge config, the audit log or a log line.
"""

import json
import secrets as pysecrets

from . import crypto


def _doc(site) -> dict:
    try:
        doc = json.loads(getattr(site, "integration_secrets", None) or "{}")
    except ValueError:
        doc = {}
    return doc if isinstance(doc, dict) else {}


def _save(site, doc: dict) -> None:
    hooks = doc.get("webhooks")
    if isinstance(hooks, dict) and not hooks:
        doc.pop("webhooks")
    site.integration_secrets = json.dumps(doc, sort_keys=True) if doc else None


# ------------------------------------------------------------------ log export (S3 secret key)

def logs_secret(site) -> str | None:
    """The decrypted log-export secret key, or None (CryptoError when it cannot be decrypted)."""
    v = _doc(site).get("logs")
    return crypto.decrypt(v) if v else None


def has_logs_secret(site) -> bool:
    return bool(_doc(site).get("logs"))


def set_logs_secret(site, value: str | None) -> None:
    doc = _doc(site)
    if value:
        doc["logs"] = crypto.encrypt(value)
    else:
        doc.pop("logs", None)
    _save(site, doc)


# ------------------------------------------------------------------ other scalar secrets (SPEC §16)

# every top-level key holding one encrypted string (the webhooks map is handled separately)
# wave 10 (SPEC §18.1/§18.2): "waiting_room" (wr_secret) and "access" (access_secret), each 64 lowercase
# hex = 32 random bytes; unlike the others these two DO travel to the edges (waiting_room.py, access.py)
SCALAR_KEYS = ("logs", "image_transform", "tsig", "waiting_room", "access")


def has_secret(site, key: str) -> bool:
    return bool(_doc(site).get(key))


def get_secret(site, key: str) -> str | None:
    """The decrypted value of a scalar secret, or None (CryptoError when it cannot be decrypted)."""
    v = _doc(site).get(key)
    return crypto.decrypt(v) if v else None


def set_secret(site, key: str, value: str | None) -> None:
    doc = _doc(site)
    if value:
        doc[key] = crypto.encrypt(value)
    else:
        doc.pop(key, None)
    _save(site, doc)


# ------------------------------------------------------------------ webhook signing secrets

def new_webhook_secret() -> str:
    """"whsec_" + 40 hex (SPEC §14.3.3)."""
    return "whsec_" + pysecrets.token_hex(20)


def _hooks(doc: dict) -> dict:
    hooks = doc.get("webhooks")
    return hooks if isinstance(hooks, dict) else {}


def webhook_secret_ids(site) -> set[str]:
    return set(_hooks(_doc(site)))


def webhook_secret(site, hook_id: str) -> str | None:
    v = _hooks(_doc(site)).get(hook_id)
    return crypto.decrypt(v) if v else None


def set_webhook_secret(site, hook_id: str, value: str) -> None:
    doc = _doc(site)
    hooks = _hooks(doc)
    hooks[hook_id] = crypto.encrypt(value)
    doc["webhooks"] = hooks
    _save(site, doc)


def keep_webhook_secrets(site, hook_ids: set[str]) -> None:
    """Forget the secret of every hook not in `hook_ids` (a removed item loses its secret)."""
    doc = _doc(site)
    doc["webhooks"] = {k: v for k, v in _hooks(doc).items() if k in hook_ids}
    _save(site, doc)


# ------------------------------------------------------------------ bulk (crypto.py)

def map_values(site, fn, plaintext_only: bool = False) -> int:
    """Apply fn (encrypt / rotate) to every stored value; returns how many changed."""
    doc = _doc(site)
    if not doc:
        return 0
    changed = 0
    for key in SCALAR_KEYS:
        v = doc.get(key)
        if v and not (plaintext_only and crypto.is_encrypted(v)):
            doc[key] = fn(v)
            changed += 1
    hooks = _hooks(doc)
    for k, v in list(hooks.items()):
        if v and not (plaintext_only and crypto.is_encrypted(v)):
            hooks[k] = fn(v)
            changed += 1
    if hooks:
        doc["webhooks"] = hooks
    if changed:
        _save(site, doc)
    return changed


def values(site) -> list[str]:
    doc = _doc(site)
    out = [doc[k] for k in SCALAR_KEYS if doc.get(k)]
    return out + [v for v in _hooks(doc).values() if v]


def drop_unreadable(site, readable) -> bool:
    """Forget values that cannot be decrypted (lost DATA_ENCRYPTION_KEY); True when any was dropped.
    The customer re-enters the log secret / rotates the webhook secret (GET shows *_set: false)."""
    doc = _doc(site)
    touched = False
    for key in SCALAR_KEYS:
        if doc.get(key) and not readable(doc[key]):
            doc.pop(key)
            touched = True
    hooks = _hooks(doc)
    for k in [k for k, v in hooks.items() if v and not readable(v)]:
        hooks.pop(k)
        touched = True
    if touched:
        doc["webhooks"] = hooks
        _save(site, doc)
    return touched
