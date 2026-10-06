"""Images v2 (SPEC §16.6): AVIF, smart crop and signed transform URLs.

URL transform parameters (edge): ``w``, ``h`` (1..4096), ``fit`` (cover | contain), ``q`` (1..100),
``fmt`` (webp | avif | jpeg). Unsupported features degrade gracefully: the original is served.

Signed transform URLs
---------------------
When the site has a ``transform_secret`` (write-only: ``POST /api/v1/sites/{domain}/image/
transform-secret`` generates one and shows it once; ``DELETE`` removes it), the edges only answer a
request carrying transform parameters when it is signed, so third parties cannot generate unlimited
variants; a missing or wrong signature is refused (403). URLs without transform parameters are served
as usual.

    canonical = <path> "?" <k=v pairs of the signed parameters present, in the order below, joined by "&">
    sig       = lowercase hex( HMAC-SHA256( key = transform_secret (UTF-8), msg = canonical (UTF-8) ) )

* ``<path>`` is the URL path exactly as requested (still percent-encoded), without host or query.
* the signed parameters, in this fixed order: ``w``, ``h``, ``fit``, ``q``, ``fmt``, ``width``,
  ``height`` (the legacy resize parameters) — only those present in the URL, with their raw (still
  percent-encoded) values; every other query parameter is ignored.
* the signature travels as ``sig=<64 hex>`` (anywhere in the query); it is never part of canonical.

Example: URL ``/img/cat.jpg?fit=cover&w=300`` → canonical ``/img/cat.jpg?w=300&fit=cover`` →
``/img/cat.jpg?fit=cover&w=300&sig=<hex>``.

The edges verify with the same secret, which therefore travels in the per-site ``image`` block of the
edge config (``image.transform_secret``; "" = unsigned transforms allowed). The edge config is already
a sensitive document (it carries every site's TLS private key and clearance secret): it is only served
to authenticated edges over TLS and the agent stores it root-only.
"""

import hashlib
import hmac
import secrets as pysecrets

from . import sections, site_secrets

SECRET_KEY = "image_transform"  # site_secrets key
SIGNED_PARAMS = ("w", "h", "fit", "q", "fmt", "width", "height")  # in canonical order


def new_secret() -> str:
    """"imgsec_" + 48 hex (55 characters, matches sections.TRANSFORM_SECRET_RE)."""
    return "imgsec_" + pysecrets.token_hex(24)


def canonical(path: str, query: str | dict) -> str:
    """The signed string for a request path and its (raw) query string or {param: value}."""
    if isinstance(query, str):  # raw query string: values are kept as sent (still percent-encoded)
        params = {}
        for part in query.lstrip("?").split("&"):
            k, _, v = part.partition("=")
            if k and k not in params:
                params[k] = v
    else:
        params = dict(query)
    return path + "?" + "&".join(f"{k}={params[k]}" for k in SIGNED_PARAMS if k in params)


def sign(secret: str, path: str, params: dict) -> str:
    return hmac.new(secret.encode(), canonical(path, params).encode(), hashlib.sha256).hexdigest()


def apply_write(site, value: dict) -> dict:
    """PUT image: a supplied transform_secret is stored encrypted (""/omitted keeps the stored one);
    returns the section as stored (without the secret)."""
    if value.get("transform_secret"):
        site_secrets.set_secret(site, SECRET_KEY, value["transform_secret"])
    return sections.storable("image", value)


def rotate(site) -> str:
    """A new transform secret for the site (stored encrypted, returned once). Caller commits."""
    secret = new_secret()
    site_secrets.set_secret(site, SECRET_KEY, secret)
    return secret


def remove(site) -> bool:
    """Forget the transform secret (unsigned transforms are allowed again); False when none was set."""
    had = site_secrets.has_secret(site, SECRET_KEY)
    site_secrets.set_secret(site, SECRET_KEY, None)
    return had


def edge_block(site, image: dict, feats: dict) -> dict:
    """The per-site `image` block of the edge config: the section with the plan folded in and the
    transform secret in clear (the edges verify signatures with it; "" = no signing)."""
    out = {k: v for k, v in image.items() if k not in ("transform_secret", "transform_secret_set")}
    if not feats["image_optimization"]:
        out.update(enabled=False, auto_webp=False, avif=False, smart_crop=False)
    try:
        secret = site_secrets.get_secret(site, SECRET_KEY) or ""
    except Exception:  # noqa: BLE001 - undecryptable (lost DATA_ENCRYPTION_KEY): fail closed
        secret = ""
        out.update(enabled=False)  # no variants at all rather than unsigned ones
    out["transform_secret"] = secret
    return out
