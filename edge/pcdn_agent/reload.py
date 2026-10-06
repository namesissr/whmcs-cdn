"""Reload discipline (F20/F21/F29): rendered-tree digests (whole tree, per site, certificates,
node-global files) and the post-reload /__pcdn/confver verification."""

import hashlib
import os
import re
import signal
import time
import urllib.request

from .common import _int
from .settings import log


CONFVER_MARKER = "__PCDN_CONFVER__"


def tree_digest(files: dict) -> str:
    """Order-independent digest of a rendered tree (F20/F29). Rendering is deterministic (sites.js
    uses sort_keys; decoy {{YEAR}} shifts once a year), so an identical config produces an identical
    digest and the agent can skip the write/test/reload."""
    h = hashlib.sha256()
    for rel in sorted(files):
        v = files[rel]
        h.update(rel.encode() + b"\0" + (v if isinstance(v, bytes) else v.encode()) + b"\0")
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
                "mtls/platform.key", "l4/stream.conf",
                # SPEC §22.8 shared TLS session-ticket keys (raw bytes): one reload per rotation
                "tickets/0.key", "tickets/1.key", "tickets/2.key")


_CONFVER_VALUE = re.compile(r'return 200 "([0-9a-f]{64})";')


def global_digest(files: dict) -> str:
    """Digest of the node-global rendered files (base http.conf + njs module + shield.conf): any
    change here affects every site and must not be deferred (F21). http.conf carries the digest of the
    WHOLE tree at /__pcdn/confver (F29), which changes with any site; it is masked here, otherwise every
    change would look global and F21 could never defer anything."""
    g = {k: files[k] for k in GLOBAL_FILES if k in files}
    m = _CONFVER_VALUE.search(g["http.conf"]) if isinstance(g.get("http.conf"), str) else None
    if m:   # every place the marker was substituted (the endpoint and the template's own comment)
        g["http.conf"] = g["http.conf"].replace(m.group(1), CONFVER_MARKER)
    return tree_digest(g)


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


# ----------------------------------------------------------------- reloading the master

_MASTER_TITLE = re.compile(r"nginx:\s+master process")


def _read_pid(path: str) -> int | None:
    try:
        with open(path) as f:
            return int(f.read().strip())
    except (OSError, ValueError):
        return None


def _is_master(proc: str, pid: int) -> bool:
    try:
        with open(os.path.join(proc, str(pid), "cmdline"), "rb") as f:
            title = f.read(256).replace(b"\0", b" ").decode("utf-8", "replace")
    except OSError:
        return False
    return bool(_MASTER_TITLE.match(title))


def find_master_pid(cfg: dict) -> int | None:
    """Pid of the running nginx master, read from its process title under PROC_DIR (the lowest such
    pid: a master spawned by a reload-less restart is always older than its workers)."""
    proc = cfg.get("PROC_DIR") or "/proc"
    try:
        pids = sorted(int(n) for n in os.listdir(proc) if n.isdigit())
    except OSError:
        return None
    for pid in pids:
        if _is_master(proc, pid):
            return pid
    return None


def reload_nginx(cfg: dict, run) -> tuple[int, str]:
    """NGINX_RELOAD_CMD, with a repair path for the one failure that otherwise strands a node on
    stale config forever: an empty / stale /run/nginx.pid. `nginx -s reload` (and systemd's
    ExecReload, which is the same command) reads the master's pid from that file, so once it is
    truncated every reload fails with `invalid PID number ""` while nginx keeps serving happily --
    no `nginx -t` error, no `emerg`, nothing in the error log but that one line. The node then runs
    whatever config it had when the file broke, and every later change (a new site, a rotated
    certificate, the tunnel self-probe's own server blocks) is silently never loaded.

    Only touched when the pid file does not already point at a live master, so a reload that fails
    for any other reason is reported as before."""
    code, output = run(cfg["NGINX_RELOAD_CMD"])
    if code == 0:
        return code, output
    path = cfg.get("NGINX_PID_FILE") or "/run/nginx.pid"
    stale = _read_pid(path)
    if stale is not None and _is_master(cfg.get("PROC_DIR") or "/proc", stale):
        return code, output   # the pid file is fine; this failure is something else
    master = find_master_pid(cfg)
    if master is None:
        return code, output   # no master running: a restart is the operator's call, not ours
    try:
        with open(path, "w") as f:
            f.write(f"{master}\n")
    except OSError as e:
        log.warning("nginx reload failed and %s could not be rewritten (%s)", path, e)
    else:
        code2, out2 = run(cfg["NGINX_RELOAD_CMD"])
        if code2 == 0:
            log.warning("nginx reload failed (%s); rewrote %s with master pid %d and reloaded",
                        " ".join(output.split())[-200:], path, master)
            return 0, out2
        output += "\n" + out2
    try:
        os.kill(master, signal.SIGHUP)
    except OSError as e:
        return code, output + f"\n(pid file {path} repaired to {master}, SIGHUP failed: {e})"
    log.warning("nginx reload command failed (%s); sent SIGHUP to the master (pid %d) instead",
                " ".join(output.split())[-200:], master)
    return 0, output + f"\n(reload command failed; SIGHUP sent to nginx master {master})"


# ----------------------------------------------------------------- worker_shutdown_timeout (SPEC §22.2)

_WST_RE = re.compile(r"^\s*worker_shutdown_timeout\s+(\d+)\s*(ms|s|m|h|d)?\s*;", re.M)
_WST_UNIT = {None: 1, "s": 1, "m": 60, "h": 3600, "d": 86400}


def parse_wst(text: str) -> int | None:
    """worker_shutdown_timeout of an nginx.conf in seconds (`1h` / `30m` / `600s` / `600` forms; the
    last one wins like in nginx); None when absent."""
    val = None
    for m in _WST_RE.finditer(text or ""):
        n, unit = int(m.group(1)), m.group(2)
        val = n // 1000 if unit == "ms" else n * _WST_UNIT[unit]
    return val


def wst_seconds(cfg: dict) -> int | None:
    """worker_shutdown_timeout of NGINX_CONF (None when absent / unreadable)."""
    try:
        with open(cfg.get("NGINX_CONF") or "/etc/nginx/nginx.conf") as f:
            return parse_wst(f.read())
    except OSError:
        return None
