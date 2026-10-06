"""Cache purges: whole site, URL prefixes and exact URLs (with their cache-key variants)."""

import hashlib
import os
import re
import shutil

from .common import _int
from .settings import log


# ----------------------------------------------------------------- purge

def cache_file(cache_dir: str, site_id: int, key: str) -> str:
    h = hashlib.md5(key.encode()).hexdigest()
    return os.path.join(cache_dir, str(site_id), h[-1], h[-3:-1], h)


def wipe_cache(base: str) -> int:
    """Delete the whole site cache dir contents (everything / legacy empty-urls purge)."""
    removed = 0
    if os.path.isdir(base):
        for name in os.listdir(base):
            shutil.rmtree(os.path.join(base, name), ignore_errors=True)
            removed += 1
    return removed


def _prefix_target(prefix: str) -> tuple[str | None, str] | None:
    """A purge prefix -> (host_or_None, path). '/blog/' matches any host; a full URL pins the host."""
    if prefix.startswith(("http://", "https://")):
        m = re.match(r"^https?://([^/?#]+)([^#]*)", prefix)
        if not m:
            return None
        host, path = m.group(1).lower(), m.group(2) or "/"
        if not path.startswith("/"):
            path = "/" + path
        return host, path
    return (None, prefix) if prefix.startswith("/") else None


def _cache_key_host_path(key: str) -> tuple[str, str] | None:
    """Split a cache KEY '<scheme>://<host><uri>' into (host, path)."""
    m = re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://([^/]*)(.*)$", key)
    if not m:
        return None
    return m.group(1).lower(), m.group(2) or "/"


def _read_cache_key(path: str) -> str | None:
    """nginx writes a 'KEY: <scheme>://<host><uri>' line near the top of every cache file."""
    try:
        with open(path, "rb") as f:
            head = f.read(16384)
    except OSError:
        return None
    i = head.find(b"\nKEY: ")
    if i < 0:
        return None
    j = head.find(b"\n", i + 6)
    if j < 0:
        return None
    return head[i + 6:j].decode("latin-1", "replace")


def purge_prefixes(base: str, prefixes: list[str], scan_max: int) -> tuple[int, bool]:
    """Scan the site's cache files and delete those whose KEY path starts with a prefix.
    Returns (removed, overflow); overflow=True means the scan cap was hit."""
    targets = [t for t in (_prefix_target(p) for p in prefixes) if t]
    if not targets or not os.path.isdir(base):
        return 0, False
    removed = scanned = 0
    for root, _dirs, files in os.walk(base):
        for name in files:
            scanned += 1
            if scanned > scan_max:
                return removed, True
            fpath = os.path.join(root, name)
            key = _read_cache_key(fpath)
            if key is None:
                continue
            hp = _cache_key_host_path(key)
            if hp is None:
                continue
            khost, kpath = hp
            for phost, ppath in targets:
                if phost is not None and khost != phost:
                    continue
                if kpath.startswith(ppath):
                    try:
                        os.remove(fpath)
                        removed += 1
                    except OSError:
                        pass
                    break
    return removed, False


def _arg(query: str, name: str) -> str:
    """nginx $arg_<name> semantics: raw value of the first `name=` parameter (name case-insensitive)."""
    for part in query.split("&"):
        k, eq, v = part.partition("=")
        if eq and k.lower() == name.lower():
            return v
    return ""


def url_key_bases(path: str, kinfo: dict | None) -> list[str]:
    """The "<uri>" parts (after scheme://host) an exact URL can be cached under: the full request
    URI, the query-less path (ignore_query) and, for cache.key_query_allow sites, the path with
    only the allowed parameters in their configured order (SPEC §14.1)."""
    noq, _, query = path.partition("?")
    bases = [path, noq]
    if kinfo and kinfo.get("qa"):
        bases.append(noq + "?" + "&".join(f"{n}={_arg(query, n)}" for n in kinfo["qa"]))
    return list(dict.fromkeys(bases))


def key_suffixes(kinfo: dict | None) -> list[str] | None:
    """Every variant suffix of a key when they can be enumerated (device class, WebP flag), or None
    when cookie values are part of the key (the cache then has to be scanned)."""
    if not kinfo:
        return [""]
    if kinfo.get("cookies"):
        return None
    devs = [";d=mobile", ";d=desktop"] if kinfo.get("dev") else [""]
    webps = [";w=", ";w=0", ";w=1"] if kinfo.get("webp") else [""]
    return [d + w for d in devs for w in webps]


def purge_exact_scan(base: str, targets: set, fields: int, scan_max: int) -> tuple[int, bool]:
    """Delete cache files whose KEY minus its `fields` trailing ";<field>" parts is in `targets`."""
    if not targets or not os.path.isdir(base):
        return 0, False
    removed = scanned = 0
    for root, _dirs, names in os.walk(base):
        for name in names:
            scanned += 1
            if scanned > scan_max:
                return removed, True
            fpath = os.path.join(root, name)
            key = _read_cache_key(fpath)
            if key is None:
                continue
            if (key.rsplit(";", fields)[0] if fields else key) in targets:
                try:
                    os.remove(fpath)
                    removed += 1
                except OSError:
                    pass
    return removed, False


def do_purge(item: dict, cfg: dict, kinfo: dict | None = None) -> int:
    """kinfo: the site's cache-key options (key_infos) when its keys carry variants."""
    sid = int(item["site_id"])
    base = os.path.join(cfg["CACHE_DIR"], str(sid))
    urls = item.get("urls") or []
    prefixes = item.get("prefixes") or []
    everything = bool(item.get("everything"))
    # whole-site wipe: explicit `everything`, or the legacy empty-urls request (no prefixes either)
    if everything or (not urls and not prefixes):
        return wipe_cache(base)
    removed = 0
    scan_max = _int(cfg.get("PURGE_SCAN_MAX"), 500000, 1, 10 ** 9)
    suffixes = key_suffixes(kinfo)
    scan_targets = set()
    for url in urls:  # exact URLs keep the fast hashed-key delete
        m = re.match(r"^https?://([^/?#]+)([^#]*)", url)
        if not m:
            continue
        host, path = m.group(1).lower(), m.group(2) or "/"
        if not path.startswith("/"):
            path = "/" + path
        # cache keys are "$scheme://$host$request_uri", or "$scheme://$host$pcdn_path"
        # (query dropped) on sites with ignore_query: remove both variants (plus the
        # key_query_allow form and every device/WebP variant, SPEC §14.1)
        for scheme in ("http", "https"):
            for p in url_key_bases(path, kinfo):
                if suffixes is None:   # cookie-keyed variants: found by scanning below
                    scan_targets.add(f"{scheme}://{host}{p}")
                    continue
                for suf in suffixes:
                    try:
                        os.remove(cache_file(cfg["CACHE_DIR"], sid, f"{scheme}://{host}{p}{suf}"))
                        removed += 1
                    except FileNotFoundError:
                        pass
    if kinfo and kinfo.get("slice"):
        # SPEC §16.5: sliced *.mp4 entries carry one more trailing key field (";r=<range>") whose values
        # cannot be enumerated: those URLs are found by scanning
        slice_targets = set()
        for url in urls:
            m = re.match(r"^https?://([^/?#]+)([^#]*)", url)
            if not m or not m.group(2).split("?", 1)[0].lower().endswith(".mp4"):
                continue
            host, path = m.group(1).lower(), m.group(2)
            for scheme in ("http", "https"):
                for p in url_key_bases(path, kinfo):
                    for suf in (suffixes if suffixes is not None else [None]):
                        slice_targets.add((f"{scheme}://{host}{p}" + (suf or ""), suf is None))
        if slice_targets:
            fields = int(bool(kinfo.get("dev"))) + len(kinfo.get("cookies") or []) + int(bool(kinfo.get("webp")))
            exact = {t for t, var in slice_targets if not var}
            n, overflow = purge_exact_scan(base, exact, 1, scan_max) if exact else (0, False)
            if not overflow and any(var for _, var in slice_targets):
                m2, overflow = purge_exact_scan(base, {t for t, var in slice_targets if var}, fields + 1, scan_max)
                n += m2
            if overflow:
                log.warning("purge scan cap %d exceeded for site %s; falling back to full purge", scan_max, sid)
                return wipe_cache(base)
            removed += n
    if scan_targets:
        fields = int(bool(kinfo.get("dev"))) + len(kinfo.get("cookies") or []) + int(bool(kinfo.get("webp")))
        n, overflow = purge_exact_scan(base, scan_targets, fields, scan_max)
        if overflow:
            log.warning("purge scan cap %d exceeded for site %s; falling back to full purge", scan_max, sid)
            return wipe_cache(base)
        removed += n
    if prefixes:
        n, overflow = purge_prefixes(base, prefixes, scan_max)
        if overflow:  # too many files to scan safely -> fall back to a full-site purge
            log.warning("purge scan cap %d exceeded for site %s; falling back to full purge", scan_max, sid)
            return wipe_cache(base)
        removed += n
    return removed
