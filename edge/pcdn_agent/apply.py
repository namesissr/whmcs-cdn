"""Applying a rendered tree: write it atomically, nginx -t, reload (and roll back), the bootstrap
tree, render_rev, and keeping the origin guard's shield peers in sync."""

import hashlib
import json
import os
import shutil
import subprocess
import time

from .capabilities import nginx_capabilities
from .reload import verify_reload
from .render.guards import ORIGIN_GUARD_TABLE
from .render.site import ensure_speed_file
from .render.tree import render_tree
from .settings import DEFAULTS, HERE, agent_source_files, asset, log
from .validation.origin import is_public_ip


# ----------------------------------------------------------------- apply

def run(cmd: str) -> tuple[int, str]:
    p = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return p.returncode, (p.stdout + p.stderr).strip()


def write_tree(root: str, files: dict):
    os.makedirs(os.path.join(root, "sites"), exist_ok=True)
    os.makedirs(os.path.join(root, "certs"), mode=0o700, exist_ok=True)
    for d in ("mtls", "storage", "tickets"):
        if any(rel.startswith(d + "/") for rel in files):
            os.makedirs(os.path.join(root, d), mode=0o700, exist_ok=True)
    for rel, content in files.items():
        path = os.path.join(root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        # keys and the HMAC / shield secrets are only read by the nginx master (root) at load time;
        # so are the origin-pull client certificates (mtls/, mtls.conf; SPEC §14.2) and the object-
        # storage read tokens (storage/; SPEC §16.8) and the controller token of the access OTP hop
        # (edge-auth.conf; SPEC §18.2)
        # SPEC §22.8: the session-ticket keys (tickets/, raw bytes) are secrets of the master too
        mode = 0o600 if (rel.endswith(".key") or rel in ("js/sites.js", "shield.conf", "mtls.conf", "edge-auth.conf")
                         or rel.startswith(("mtls/", "storage/", "tickets/"))) else 0o644
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
        with os.fdopen(fd, "wb" if isinstance(content, bytes) else "w") as f:
            f.write(content)


def ensure_cache_dirs(config: dict, cfg: dict):
    base = cfg["CACHE_DIR"]
    os.makedirs(base, exist_ok=True)
    wanted = {str(int(s["id"])) for s in config.get("sites", [])}
    for sid in wanted:
        os.makedirs(os.path.join(base, sid), exist_ok=True)
        try:
            shutil.chown(os.path.join(base, sid), user=cfg["NGINX_USER"])
        except (LookupError, PermissionError, OSError):
            pass
    for name in os.listdir(base):
        if name.isdigit() and name not in wanted:
            shutil.rmtree(os.path.join(base, name), ignore_errors=True)


def apply_config(config: dict, cfg: dict, files: dict | None = None, digest: str | None = None) -> str | None:
    """Atomically swap the rendered tree in; roll back if nginx rejects it. `files`/`digest` may be
    passed pre-rendered (F20/F29) to avoid a second render; otherwise they are rendered here."""
    root = cfg["NGINX_DIR"].rstrip("/")
    new, old = root + ".new", root + ".old"
    shutil.rmtree(new, ignore_errors=True)
    shutil.rmtree(old, ignore_errors=True)
    if files is None:
        files, digest = render_tree(config, cfg)
    write_tree(new, files)
    ensure_cache_dirs(config, cfg)
    ensure_speed_file(cfg)   # SPEC §15.6 (once; outside the swapped tree)

    had_old = os.path.exists(root)
    if had_old:
        os.rename(root, old)
    os.rename(new, root)
    code, output = run(cfg["NGINX_TEST_CMD"])
    if code != 0:
        shutil.rmtree(root, ignore_errors=True)
        if had_old:
            os.rename(old, root)
        return "nginx -t failed: " + output[-1500:]
    code, output = run(cfg["NGINX_RELOAD_CMD"])
    shutil.rmtree(old, ignore_errors=True)
    if code != 0:
        return "nginx reload failed: " + output[-1500:]
    # F29: confirm the master actually applied the new tree (a rejected reload keeps the old one).
    if digest and str(cfg.get("RELOAD_VERIFY", "yes")).lower() in ("1", "yes", "true", "on"):
        if not verify_reload(cfg, digest):
            return "nginx reload not applied (see error.log)"
    return None


def bootstrap(cfg: dict):
    """Empty tree so nginx can start before the first successful sync."""
    root = cfg["NGINX_DIR"].rstrip("/")
    if not os.path.exists(os.path.join(root, "http.conf")):
        files, _ = render_tree({"sites": []}, cfg)
        write_tree(root, files)
    os.makedirs(cfg["CACHE_DIR"], exist_ok=True)
    ensure_speed_file(cfg)


def render_rev(cfg: dict) -> str:
    """Changes whenever local rendering inputs change (agent/njs/template upgrade, GeoIP DB
    appearing, local settings) so the next sync re-renders even if the config ETag is unchanged."""
    h = hashlib.sha256()
    decoy = os.path.join(cfg.get("PAGES_DIR") or "", "decoy.html")
    for path in (asset(cfg, "NJS_FILE", "njs/pcdn.js"), asset(cfg, "BASE_TEMPLATE", "nginx/pcdn-base.conf"),
                 decoy if os.path.isfile(decoy) else os.path.join(HERE, "pages", "decoy.html"),
                 *agent_source_files()):
        try:
            with open(path, "rb") as f:
                h.update(f.read())
        except OSError:
            pass
    h.update(str(os.path.isfile(cfg.get("GEOIP_DB") or "")).encode())
    h.update(json.dumps({k: cfg.get(k) for k in sorted(DEFAULTS) if k not in ("CONTROLLER_URL", "EDGE_TOKEN")}).encode())
    # an nginx swap (install.sh --http3) changes what can be rendered (SPEC §14.1)
    h.update(json.dumps(nginx_capabilities(cfg), sort_keys=True).encode())
    return h.hexdigest()


def origin_guard_installed(cfg: dict) -> bool:
    return str(cfg.get("ORIGIN_GUARD") or "").lower() == "yes" and os.path.isfile(
        cfg.get("ORIGIN_GUARD_FILE") or "/etc/pcdn/origin-guard.nft")


def sync_origin_guard_peers(cfg: dict, st: dict, peers: list, force: bool = False, run=subprocess.run) -> bool:
    """Keep the origin guard's shield-peer sets equal to the shield peers that are not public
    (public ones pass the guard anyway). Re-applied when they change and every 10 minutes (the
    guard service may have reloaded the table). Best effort; True when nft was run successfully."""
    if not origin_guard_installed(cfg):
        return False
    want = sorted({p.strip("[]") for p in peers or [] if not is_public_ip(p)})
    now = time.time()
    if not force and want == st.get("og_peers") and now - st.get("og_peers_at", 0) < 600:
        return False
    v4 = [p for p in want if ":" not in p]
    v6 = [p for p in want if ":" in p]
    script = (f"flush set inet {ORIGIN_GUARD_TABLE} peers4\nflush set inet {ORIGIN_GUARD_TABLE} peers6\n"
              + (f"add element inet {ORIGIN_GUARD_TABLE} peers4 {{ {', '.join(v4)} }}\n" if v4 else "")
              + (f"add element inet {ORIGIN_GUARD_TABLE} peers6 {{ {', '.join(v6)} }}\n" if v6 else ""))
    try:
        p = run(["nft", "-f", "-"], input=script, capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError) as e:
        log.warning("origin guard: cannot update the shield peers: %s", e)
        return False
    if p.returncode != 0:
        log.warning("origin guard: cannot update the shield peers: %s", (p.stderr or "").strip()[:200])
        return False
    st["og_peers"], st["og_peers_at"] = want, now
    return True
