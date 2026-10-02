"""Reload discipline (F20/F21/F29): rendered-tree digests (whole tree, per site, certificates,
node-global files) and the post-reload /__pcdn/confver verification."""

import hashlib
import re
import time
import urllib.request

from .common import _int


CONFVER_MARKER = "__PCDN_CONFVER__"


def tree_digest(files: dict) -> str:
    """Order-independent digest of a rendered tree (F20/F29). Rendering is deterministic (sites.js
    uses sort_keys; decoy {{YEAR}} shifts once a year), so an identical config produces an identical
    digest and the agent can skip the write/test/reload."""
    h = hashlib.sha256()
    for rel in sorted(files):
        h.update(rel.encode() + b"\0" + files[rel].encode() + b"\0")
    return h.hexdigest()


def _group_digests(files: dict, pattern: str) -> dict:
    """Per-site digests of the rendered files whose path matches `pattern` (F21)."""
    groups: dict = {}
    for rel in sorted(files):
        m = re.match(pattern, rel)
        if m:
            groups.setdefault(m.group(1), []).append(rel)
    return {sid: tree_digest({rel: files[rel] for rel in rels}) for sid, rels in groups.items()}


def site_digests(files: dict) -> dict:
    """Per-site content digest (config + certs + error pages) for group-aware reload deferral (F21)."""
    return _group_digests(files, r"^(?:sites|certs|errors|mtls|storage|l4/sites)/(\d+)")


def cert_digests(files: dict) -> dict:
    """Per-site certificate/key digest, so a foreign-group site's cert rotation is never deferred;
    the object-storage read tokens (SPEC §16.8) too: a rotated token is refused by the bucket at once."""
    return _group_digests(files, r"^(?:certs|storage)/(\d+)\.")


GLOBAL_FILES = ("http.conf", "js/pcdn.js", "shield.conf", "bots.conf", "mtls.conf", "mtls/platform.crt",
                "mtls/platform.key", "l4/stream.conf")


def global_digest(files: dict) -> str:
    """Digest of the node-global rendered files (base http.conf + njs module + shield.conf): any
    change here affects every site and must not be deferred (F21)."""
    return tree_digest({k: files[k] for k in GLOBAL_FILES if k in files})


def verify_reload(cfg: dict, digest: str) -> bool:
    """Poll /__pcdn/confver (localhost) until it returns the digest of the tree just written, or the
    RELOAD_VERIFY budget expires (F29). A reload the nginx master rejected keeps serving the old
    digest, so the caller can retry instead of recording the config as applied."""
    port = _int(cfg.get("HTTP_PORT"), 80, 1, 65535)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    deadline = time.monotonic() + 10
    url = f"http://127.0.0.1:{port}/__pcdn/confver"
    while time.monotonic() < deadline:
        try:
            with opener.open(url, timeout=2) as r:
                if r.read().decode("utf-8", "replace").strip() == digest:
                    return True
        except Exception:  # noqa: BLE001 - connection refused mid-reload etc.: keep polling
            pass
        time.sleep(0.3)
    return False
