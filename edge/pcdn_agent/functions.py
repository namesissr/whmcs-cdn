"""Edge functions glue (SPEC §16.9): validation of the function sections, the nginx routes to the
pcdn-fn socket, the code bundle pcdn-fn reads, its status and the per-function usage log."""

import hashlib
import json
import os
import re
import shutil
import time

from .common import SAFE_FSPATH, SAFE_ID, SAFE_NAME, _sec
from .reload import tree_digest
from .settings import log
from .usage import _bucket, _times
from .validation.origin import norm_pools, norm_tunnel


# ----------------------------------------------------------------- edge functions (SPEC §16.9)
#
# Customer JavaScript never runs in nginx/njs. nginx only routes the bound path prefixes over a unix
# socket to pcdn-fn (pcdn-fn.py, systemd/pcdn-fn.service), which runs every invocation in a fresh
# sandboxed QuickJS process. The agent (1) validates the site's `functions` section, (2) writes the
# code bundle pcdn-fn reads (FN_DIR/manifest.json + FN_DIR/code/<sha256>.js, root:<nginx group> 0640,
# content-addressed so a sandboxed worker cannot even probe which sites have functions), (3) renders
# one `location ^~ <route>` per function plus a local fetch() server per host, (4) reports the
# `edge_functions` capability only while pcdn-fn's self-test passes and (5) bills the usage lines
# pcdn-fn appends to FN_USAGE_LOG.

FN_ROUTE = re.compile(r"^/[A-Za-z0-9._~/-]{0,255}$")
FN_MAX_CODE = 256 * 1024          # bytes of UTF-8 source per function
FN_MAX_PER_SITE = 32
FN_TIMEOUT_MS = (1, 200, 50)      # (min, max, default) CPU milliseconds per invocation
FN_MEMORY_MB = (8, 128, 32)       # (min, max, default) JS heap per invocation
FN_ON_ERROR = ("502", "origin")   # default first: fail closed (a broken auth function never opens the origin)
FN_STATUS_MAX_AGE = 180           # pcdn-fn rewrites its status file every 30 s


def functions_enabled(cfg: dict) -> bool:
    """install.sh --functions (FUNCTIONS=yes in agent.conf): pcdn-fn is installed on this node."""
    return str(cfg.get("FUNCTIONS") or "").lower() == "yes"


def _fn_bounded(v, lim: tuple):
    if v is None:
        return lim[2]
    if isinstance(v, bool) or not isinstance(v, int) or not lim[0] <= v <= lim[1]:
        return None
    return v


def norm_functions(site: dict, tunnel_prefixes=()) -> list[dict]:
    """Validated, enabled functions of a site (SPEC §16.9): [{id, route, code, sha256, timeout_ms,
    memory_mb, on_error}]. Invalid items are skipped, never "fixed"; the first item wins a duplicate
    id or route; a route equal to / nested with a tunnel path prefix is skipped (tunnel paths keep
    their own location)."""
    sec = _sec(site, "functions")
    if sec.get("enabled") is not True:
        return []
    site_err = sec.get("on_error") if sec.get("on_error") in FN_ON_ERROR else FN_ON_ERROR[0]
    out, ids, routes = [], set(), set()
    for f in sec.get("items") or []:
        if not isinstance(f, dict) or f.get("enabled") is False:
            continue
        fid, route, code = f.get("id"), f.get("route"), f.get("code")
        if not (isinstance(fid, str) and SAFE_ID.match(fid) and isinstance(route, str) and FN_ROUTE.match(route)
                and isinstance(code, str) and code.strip()):
            log.warning("site %s: skipping invalid function %r", site.get("id"), fid)
            continue
        segs = route.split("/")[1:-1] if route.endswith("/") else route.split("/")[1:]
        if (route.startswith("/__pcdn") or "//" in route or any(x in (".", "..") for x in segs)
                or fid in ids or route in routes):
            log.warning("site %s: skipping function %s (route %s)", site.get("id"), fid, route)
            continue
        if any(route.startswith(p) or p.startswith(route) for p in tunnel_prefixes):
            log.warning("site %s: function %s route %s overlaps a tunnel path", site.get("id"), fid, route)
            continue
        raw = code.encode("utf-8", "surrogatepass")
        tmo, mem = _fn_bounded(f.get("timeout_ms"), FN_TIMEOUT_MS), _fn_bounded(f.get("memory_mb"), FN_MEMORY_MB)
        on_err = f.get("on_error", site_err)
        if len(raw) > FN_MAX_CODE or tmo is None or mem is None or on_err not in FN_ON_ERROR:
            log.warning("site %s: skipping function %s (size / limits / on_error)", site.get("id"), fid)
            continue
        ids.add(fid)
        routes.add(route)
        out.append({"id": fid, "route": route, "code": code, "sha256": hashlib.sha256(raw).hexdigest(),
                    "timeout_ms": tmo, "memory_mb": mem, "on_error": on_err})
        if len(out) >= FN_MAX_PER_SITE:
            break
    return out


def _fn_tunnel_prefixes(site: dict) -> list[str]:
    tn = norm_tunnel(site, norm_pools(site))
    return [p["path"] for p in tn["paths"]] if tn else []


def _fn_site_ok(site: dict) -> bool:
    """Functions run only for active sites that serve origin content (not decoy / 404 tunnel hosts)."""
    if site.get("status", "active") in ("suspended", "over_quota"):
        return False
    tn = norm_tunnel(site, norm_pools(site))
    return not tn or tn["fallback"] == "origin"


def render_functions(config: dict, cfg: dict) -> dict:
    """The pcdn-fn bundle {rel path: text} (empty when FUNCTIONS is off or no site has functions):
    manifest.json {"v": 1, "sites": {"<id>": {"domain", "hosts", "functions": {"<fn id>": {route,
    sha256, timeout_ms, memory_mb}}}}} and code/<sha256>.js."""
    if not functions_enabled(cfg):
        return {}
    files, sites = {}, {}
    for site in config.get("sites", []):
        if not _fn_site_ok(site):
            continue
        fns = norm_functions(site, _fn_tunnel_prefixes(site))
        if not fns:
            continue
        hosts = sorted({str(h.get("name") or "").lower() for h in site.get("hosts") or []
                        if SAFE_NAME.match(str(h.get("name") or "").lower())})
        sites[str(int(site["id"]))] = {
            "domain": str(site.get("domain") or "").lower(), "hosts": hosts,
            "functions": {f["id"]: {"route": f["route"], "sha256": f["sha256"], "timeout_ms": f["timeout_ms"],
                                    "memory_mb": f["memory_mb"]} for f in fns}}
        for f in fns:
            files[f"code/{f['sha256']}.js"] = f["code"]
    if not sites:
        return {}
    files["manifest.json"] = json.dumps({"v": 1, "sites": sites}, sort_keys=True, separators=(",", ":")) + "\n"
    return files


def _fn_gid(cfg: dict) -> int | None:
    """Group that may read the bundle and connect to the sockets: FN_GROUP or NGINX_USER's group."""
    import grp  # noqa: PLC0415
    import pwd  # noqa: PLC0415
    try:
        if cfg.get("FN_GROUP"):
            return grp.getgrnam(cfg["FN_GROUP"]).gr_gid
        return pwd.getpwnam(cfg.get("NGINX_USER") or "www-data").pw_gid
    except (KeyError, OSError):
        return None


def write_functions(cfg: dict, files: dict):
    """Atomically replace FN_DIR with the bundle (dirs 0750, files 0640, group = _fn_gid). pcdn-fn
    re-reads manifest.json when it changes; an empty bundle leaves an empty FN_DIR."""
    root = (cfg.get("FN_DIR") or "/var/lib/pcdn-fn").rstrip("/")
    if not SAFE_FSPATH.match(root):
        raise ValueError("unsafe FN_DIR")
    gid = _fn_gid(cfg)
    new, old = root + ".new", root + ".old"
    shutil.rmtree(new, ignore_errors=True)
    shutil.rmtree(old, ignore_errors=True)
    os.makedirs(os.path.join(new, "code"), mode=0o750)
    for d in (new, os.path.join(new, "code")):
        os.chmod(d, 0o750)
        if gid is not None:
            os.chown(d, 0 if os.geteuid() == 0 else -1, gid)
    for rel, content in files.items():
        path = os.path.join(new, rel)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o640)
        with os.fdopen(fd, "wb") as f:
            f.write(content.encode("utf-8", "surrogatepass"))
        os.chmod(path, 0o640)
        if gid is not None:
            os.chown(path, 0 if os.geteuid() == 0 else -1, gid)
    if os.path.exists(root):
        os.rename(root, old)
    os.rename(new, root)
    shutil.rmtree(old, ignore_errors=True)


def sync_functions(config: dict, cfg: dict, state: dict):
    """Write the bundle when it changed (agent-side, independent of the nginx reload: pcdn-fn picks
    the new code up without one). Called before the nginx tree is applied, so a new route never
    reaches pcdn-fn before its code."""
    files = render_functions(config, cfg)
    digest = tree_digest(files)
    root = (cfg.get("FN_DIR") or "/var/lib/pcdn-fn").rstrip("/")
    if digest == state.get("fn_digest") and (not files or os.path.isfile(os.path.join(root, "manifest.json"))):
        return
    if not files and not os.path.exists(root):
        state["fn_digest"] = digest
        return
    write_functions(cfg, files)
    state["fn_digest"] = digest


def functions_status(cfg: dict) -> dict | None:
    """pcdn-fn's status file (self-test result) when it is fresh, else None."""
    path = cfg.get("FN_STATUS") or "/run/pcdn-fn/status.json"
    try:
        if time.time() - os.path.getmtime(path) > FN_STATUS_MAX_AGE:
            return None
        with open(path) as f:
            st = json.load(f)
        return st if isinstance(st, dict) else None
    except (OSError, ValueError):
        return None


def functions_ready(cfg: dict) -> bool:
    """SPEC §16.9 capability `edge_functions`: installed (FUNCTIONS=yes), the engine binary present,
    pcdn-fn alive (fresh status + its socket) and its sandbox self-test passed."""
    if not functions_enabled(cfg):
        return False
    st = functions_status(cfg)
    if not st or st.get("ok") is not True or not all((st.get("checks") or {"x": False}).values()):
        return False
    import stat as _stat  # noqa: PLC0415
    try:
        return _stat.S_ISSOCK(os.stat(cfg.get("FN_SOCKET") or "/run/pcdn-fn/fn.sock").st_mode)
    except OSError:
        return False


FN_READ_MAX = 8 * 1024 * 1024


def _account_fn(e: dict, pending: dict):
    """One pcdn-fn usage line {"t","h","n","c","e","o"} -> the `functions` counters of the host-hour."""
    host = str(e.get("h") or "").lower()
    if not SAFE_NAME.match(host):
        return
    _, hour, _ = _times(e["t"])
    a = _bucket(pending, f"{host}|{hour}")
    c = a.setdefault("functions", {"invocations": 0, "cpu_ms": 0, "errors": 0, "timeouts": 0})
    for k, src in (("invocations", "n"), ("cpu_ms", "c"), ("errors", "e"), ("timeouts", "o")):
        c[k] += max(0, int(e.get(src) or 0))


def _consume_fn(path: str, pos: int, pending: dict, max_bytes: int) -> int:
    read = 0
    with open(path, "rb") as f:
        f.seek(pos)
        for raw in f:
            if not raw.endswith(b"\n"):
                break
            pos += len(raw)
            read += len(raw)
            try:
                _account_fn(json.loads(raw), pending)
            except (ValueError, KeyError, TypeError, AttributeError):
                pass
            if read >= max_bytes:
                break
    return pos


def read_fn_usage(state: dict, path: str, max_bytes: int = FN_READ_MAX) -> None:
    """Fold new pcdn-fn usage lines into state['pending'] (own offset / inode: fn_pos, fn_inode).
    pcdn-fn rotates usage.log -> usage.log.1 itself; the rest of the old file is read first."""
    try:
        st = os.stat(path)
    except OSError:
        return
    pending = state.setdefault("pending", {})
    pos, ino = int(state.get("fn_pos") or 0), state.get("fn_inode")
    if ino is not None and ino != st.st_ino:
        try:
            if os.stat(path + ".1").st_ino == ino:
                _consume_fn(path + ".1", pos, pending, max_bytes)
        except OSError:
            pass
        pos = 0
    elif st.st_size < pos:
        pos = 0
    state["fn_pos"] = _consume_fn(path, pos, pending, max_bytes)
    state["fn_inode"] = st.st_ino
