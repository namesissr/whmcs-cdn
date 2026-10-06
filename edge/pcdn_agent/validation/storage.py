"""Object-storage origins (SPEC §16.8): validation of the bucket endpoint, bucket, prefix and read
token, and their log-safe representation."""

import ipaddress
import re


# ----------------------------------------------------------------- object-storage origins (SPEC §16.8)

_STO_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
SAFE_STO_HOST = re.compile(rf"^(?=.{{1,253}}$){_STO_LABEL}(?:\.{_STO_LABEL})*$")
SAFE_STO_BUCKET = re.compile(r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")
# path-style prefix: "/<segment>..." ending in "/<bucket>"; a segment never starts with "." (no "."
# / ".." segment) and never contains "%", so nothing in it is decoded or normalised away
SAFE_STO_PREFIX = re.compile(r"^(?:/[A-Za-z0-9_~-][A-Za-z0-9._~-]{0,127}){1,16}$")
SAFE_STO_TOKEN = re.compile(r"^[A-Za-z0-9_-]{16,128}$")
# SPEC §16.8 signed file links: the key njs verifies a link's signature with (hex, controller-derived)
SAFE_STO_LINK_KEY = re.compile(r"^[0-9a-f]{32,128}$")
STO_KEYS = ("host", "port", "tls", "host_header", "bucket", "path_prefix", "referer")


def _sto_ip(v: str) -> str | None:
    """An IP literal (v4 dotted, v6 bare or bracketed) -> its compressed form, or None."""
    try:
        ip = ipaddress.ip_address(v[1:-1] if v.startswith("[") and v.endswith("]") else v)
    except ValueError:
        return None
    if ip.is_unspecified or ip.is_multicast:
        return None
    return ip.compressed if ip.version == 4 else f"[{ip.compressed}]"


def _sto_hostname(v: str) -> str | None:
    """A hostname or an IP literal -> nginx form ("[v6]" bracketed), or None."""
    if ":" in v or "[" in v or re.match(r"^[0-9.]+$", v):   # an address, never a name
        return _sto_ip(v)
    return v if SAFE_STO_HOST.match(v) else None


def norm_storage_origin(origin) -> dict | None:
    """A host's `origin = {"storage": {...}}` (SPEC §16.8: records only, never pools) -> {proto,
    hp, host, ssl_name, host_header, bucket, prefix, referer, tls}, or None when anything is off.
    Strict: host = hostname or IP, port 1..65535 (int), tls bool, host_header = host[:port],
    bucket / path_prefix charset (prefix ends in "/<bucket>"), referer [A-Za-z0-9_-]{16,128}.
    The referer is the bucket's read token: never log or expose the result (storage_log_repr)."""
    if not isinstance(origin, dict) or set(origin) != {"storage"}:
        return None
    st = origin["storage"]
    if not isinstance(st, dict) or not all(isinstance(st.get(k), (str, int)) for k in STO_KEYS):
        return None
    host, port, tls = st["host"], st["port"], st["tls"]
    if not isinstance(host, str) or not isinstance(tls, bool) or type(port) is not int or not 1 <= port <= 65535:
        return None
    nhost = _sto_hostname(host.lower())
    hh = st["host_header"]
    if nhost is None or not isinstance(hh, str) or len(hh) > 260:
        return None
    m = re.match(r"^(\[[0-9a-fA-F:.]+\]|[^:\[\]]+)(?::(\d{1,5}))?$", hh)
    if (not m or _sto_hostname(m.group(1).lower()) is None
            or (m.group(2) is not None and not 1 <= int(m.group(2)) <= 65535)):
        return None
    bucket, prefix, ref = st["bucket"], st["path_prefix"], st["referer"]
    if not all(isinstance(x, str) for x in (bucket, prefix, ref)):
        return None
    if (not SAFE_STO_BUCKET.match(bucket) or ".." in bucket or len(prefix) > 512
            or not SAFE_STO_PREFIX.match(prefix) or not prefix.endswith("/" + bucket)
            or not SAFE_STO_TOKEN.match(ref)):
        return None
    # SPEC §16.8: signed links only. Both must be right or the host is dropped: serving the bucket
    # publicly because a key was malformed would be exactly the mistake the mode exists to prevent.
    signed = st.get("signed", False)
    link_key = st.get("link_key", "")
    if signed is not False:
        if signed is not True or not isinstance(link_key, str) or not SAFE_STO_LINK_KEY.match(link_key):
            return None
    elif link_key != "":
        return None
    return {"proto": "https" if tls else "http", "tls": tls, "hp": f"{nhost}:{port}", "host": nhost,
            "signed": bool(signed), "link_key": link_key if signed else "",
            # SNI / certificate name: the hostname (nginx sends no SNI for an IP literal, and an IP
            # endpoint only verifies when its certificate names it)
            "ssl_name": nhost.strip("[]"), "host_header": m.group(1).lower() + (f":{m.group(2)}" if m.group(2) else ""),
            "bucket": bucket, "prefix": prefix, "referer": ref}


def storage_log_repr(origin) -> str:
    """repr() of a host's origin for log lines, the storage read token (referer) masked."""
    if isinstance(origin, dict) and isinstance(origin.get("storage"), dict):
        origin = dict(origin, storage={k: ("<redacted>" if k in ("referer", "link_key") else v)
                                       for k, v in origin["storage"].items()})
    return repr(origin)
