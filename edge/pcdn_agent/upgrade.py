"""Agent self-upgrade to a target release (SPEC §23.2) and the installed release (SPEC §23.1).

The controller's rollout puts `node.upgrade = {"id", "release", "sha256", "drain_minutes", "rollback",
"timeout_s"}` into this edge's config (a non-rendered key: no reload). For an `id` not handled yet and a
release other than the running one the agent
  1. takes the tarball from RELEASES_DIR/<release>.tar.gz when its sha256 matches, else downloads
     CONTROLLER_URL/edge/bundle.tar.gz?version=<release> (max 50 MB) and verifies the sha256;
  2. unpacks it into a new 0700 directory under UPGRADE_DIR;
  3. records state["upgrade"] = {"id", "release", "state": "installing", "at", "rollback"} (saved under the
     state lock before anything runs);
  4. starts `systemd-run --unit=pcdn-upgrade-<id> --collect ... install.sh --upgrade --release <release>
     [--drain=<m>]` as its own transient unit, so the installer survives the agent restart it causes
     (install.sh keeps the tarball in RELEASES_DIR for a later rollback);
  5. the new agent sees its own release == the target -> "done"; a non-zero installer exit (status file /
     `systemctl show`) or `timeout_s` without the release change -> "failed" (exit 3 of the drain = the
     last active node -> "last_edge").
Never two upgrades at once; a node.upgrade for the release already running is "done" at once (idempotent);
a rollback is the same path with the older release. SELF_UPGRADE=no turns all of it off (the capability is
then false and rollouts treat the node as `manual`)."""

import hashlib
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

from .capabilities import self_upgrade_enabled
from .common import _int
from .drain import iso, parse_iso
from .settings import log

RELEASE_RE = re.compile(r"^v\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$")
UPGRADE_ID = re.compile(r"^[A-Za-z0-9._:-]{1,64}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
UPGRADE_ACTIVE = ("downloading", "installing")
UPGRADE_STATES = UPGRADE_ACTIVE + ("done", "failed")
UPGRADE_MAX_BYTES = 50 * 1024 * 1024
UPGRADE_ERR_MAX = 200
UPGRADE_DL_TIMEOUT = 300
EXIT_LAST_EDGE_INSTALL = 3   # install.sh under a self-upgrade: the drain refused (last active node)


def running_release(cfg: dict) -> str | None:
    """The installed release (RELEASE_FILE, written by install.sh from the bundle's edge/RELEASE), or None."""
    try:
        with open(cfg.get("RELEASE_FILE") or "/etc/pcdn/release", encoding="utf-8") as f:
            v = f.readline().strip()
    except (OSError, UnicodeDecodeError):
        return None
    return v if RELEASE_RE.match(v) else None


def norm_upgrade(config: dict) -> dict | None:
    """node.upgrade of the config, validated; None when absent / null (no upgrade asked) or malformed."""
    n = config.get("node") if isinstance(config.get("node"), dict) else {}
    u = n.get("upgrade")
    if u is None:
        return None
    if not isinstance(u, dict):
        log.warning("node.upgrade ignored: not an object")
        return None
    uid, rel, sha = str(u.get("id") or ""), str(u.get("release") or ""), str(u.get("sha256") or "").lower()
    if not UPGRADE_ID.match(uid) or not RELEASE_RE.match(rel) or not SHA256_RE.match(sha):
        log.warning("node.upgrade ignored: malformed id / release / sha256")
        return None
    return {"id": uid, "release": rel, "sha256": sha,
            "drain_minutes": _int(u.get("drain_minutes", 15), 15, 0, 120),
            "rollback": u.get("rollback") is True,
            "timeout_s": _int(u.get("timeout_s", 3600), 3600, 60, 86400)}


def unit_name(uid: str) -> str:
    return "pcdn-upgrade-" + (re.sub(r"[^A-Za-z0-9_-]", "_", uid)[:64] or "x")


def heartbeat_upgrade(state: dict) -> dict | None:
    """The heartbeat `upgrade` object (omitted when this node never upgraded itself)."""
    u = state.get("upgrade")
    if not isinstance(u, dict) or u.get("state") not in UPGRADE_STATES:
        return None
    return {"id": str(u.get("id") or ""), "release": str(u.get("release") or ""), "state": u["state"],
            "error": u.get("error") or None, "at": u.get("at") or iso(time.time()),
            "rollback": bool(u.get("rollback"))}


def _err(text: str) -> str:
    return "".join(c for c in str(text) if c.isprintable())[:UPGRADE_ERR_MAX]


def _sha256_file(path: str) -> str | None:
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
    except OSError:
        return None
    return h.hexdigest()


class UpgradeError(Exception):
    """A failed upgrade step; str() is the short error code reported in the heartbeat (no secrets)."""


class Upgrader:
    """One node's self-upgrade state machine, driven from the agent loop (step) with the agent's state
    dict. `save` persists the state under the state lock; `run` / `opener` / `now` are injectable."""

    def __init__(self, cfg: dict, state: dict, save=None, run=subprocess.run, opener=None, now=time.time):
        self.cfg, self.state, self.save = cfg, state, save
        self.run, self.now = run, now
        self.opener = opener or urllib.request.build_opener().open

    # ---- helpers
    def _set(self, u: dict, **kw) -> dict:
        u.update(kw, at=iso(self.now()))
        self.state["upgrade"] = u
        return u

    def _finish(self, u: dict, state: str, error: str | None = None):
        self._set(u, state=state, error=_err(error) if error else None)
        d = u.pop("dir", None)
        # a finished upgrade's directory may still hold the installer that is ending right now: it is
        # removed when the next upgrade starts; a failed one is removed at once
        if state == "failed" and d and os.path.isdir(d) and os.path.realpath(d).startswith(self._upgrade_dir() + os.sep):
            shutil.rmtree(d, ignore_errors=True)
        if state == "done":
            log.info("self-upgrade %s: release %s installed", u.get("id"), u.get("release"))
        else:
            log.error("self-upgrade %s to %s failed: %s", u.get("id"), u.get("release"), u.get("error"))

    def _upgrade_dir(self) -> str:
        return os.path.realpath(self.cfg.get("UPGRADE_DIR") or "/var/lib/pcdn/upgrade")

    def _persist(self):
        if self.save:
            self.save()

    # ---- the loop step
    def step(self, nu: dict | None):
        """nu: norm_upgrade of the latest full config (None = no upgrade asked). Never raises."""
        try:
            self._poll()
            if nu is None or not self_upgrade_enabled(self.cfg):
                return
            u = self.state.get("upgrade") if isinstance(self.state.get("upgrade"), dict) else {}
            if (u.get("id") == nu["id"] and u.get("release") == nu["release"]) or u.get("state") in UPGRADE_ACTIVE:
                return   # handled already (a rollback may reuse the attempt id: the release differs) / one at a time
            self._start(nu)
        except Exception as e:  # noqa: BLE001 - an upgrade problem must never break the agent loop
            log.error("self-upgrade step failed: %s", e)

    def _poll(self):
        """An upgrade in progress: done once this agent runs the target release, failed on a non-zero
        installer exit or after timeout_s."""
        u = self.state.get("upgrade")
        if not isinstance(u, dict) or u.get("state") not in UPGRADE_ACTIVE:
            return
        if running_release(self.cfg) == u.get("release"):
            return self._finish(u, "done")
        if u.get("state") == "downloading":
            # step() never returns while downloading: an agent restart cut this attempt short (the
            # controller retries with a new attempt id)
            return self._finish(u, "failed", "interrupted")
        rc = self._exit_status(u)
        if rc is not None:
            if rc == EXIT_LAST_EDGE_INSTALL:
                return self._finish(u, "failed", "last_edge")
            if rc != 0:
                return self._finish(u, "failed", f"install_failed: exit {rc}")
            return self._finish(u, "failed", "release_mismatch")
        started = parse_iso(u.get("started")) or self.now()
        if self.now() - started > _int(u.get("timeout_s"), 3600, 60, 86400):
            self._finish(u, "failed", "timeout")

    def _exit_status(self, u: dict) -> int | None:
        """The installer's exit code: the wrapper's status file, else `systemctl show` while the
        transient unit is still loaded (failed units can linger until collected). None = still running
        or unknown."""
        sf = u.get("status_file")
        if sf:
            try:
                with open(sf) as f:
                    txt = f.read().strip()
                if txt:
                    return int(txt)
            except (OSError, ValueError):
                pass
        unit = u.get("unit")
        if not unit:
            return None
        try:
            p = self.run(["systemctl", "show", unit, "-p", "LoadState", "-p", "ActiveState", "-p", "Result",
                          "-p", "ExecMainStatus"], capture_output=True, text=True, timeout=20)
        except (OSError, subprocess.SubprocessError):
            return None
        props = dict(line.split("=", 1) for line in (p.stdout or "").splitlines() if "=" in line)
        if props.get("LoadState") != "loaded" or props.get("ActiveState") not in ("failed", "inactive"):
            return None
        try:
            code = int(props.get("ExecMainStatus") or 0)
        except ValueError:
            code = 0
        if props.get("Result", "success") != "success" or code:
            return code or 1
        return None   # finished cleanly: the status file (or the release change) tells the rest

    def _start(self, nu: dict):
        u = {"id": nu["id"], "release": nu["release"], "rollback": nu["rollback"], "error": None,
             "timeout_s": nu["timeout_s"]}
        if running_release(self.cfg) == nu["release"]:
            self._set(u, state="done")   # idempotent: already running the target
            log.info("self-upgrade %s: release %s already running", nu["id"], nu["release"])
            return
        log.info("self-upgrade %s: %s %s", nu["id"], "rolling back to" if nu["rollback"] else "upgrading to",
                 nu["release"])
        self._set(u, state="downloading", started=iso(self.now()))
        self._persist()
        try:
            base = self._prepare_dir(u)
            tarball = self._tarball(nu, base)
            edge = self._extract(tarball, base)
            self._launch(u, nu, edge, tarball)
        except UpgradeError as e:
            self._finish(u, "failed", str(e))
        self._persist()

    def _prepare_dir(self, u: dict) -> str:
        top = self._upgrade_dir()
        try:
            os.makedirs(top, mode=0o700, exist_ok=True)
            os.chmod(top, 0o700)
            for name in os.listdir(top):   # leftovers of earlier upgrades (none is running: checked above)
                p = os.path.join(top, name)
                shutil.rmtree(p, ignore_errors=True) if os.path.isdir(p) else os.unlink(p)
            d = tempfile.mkdtemp(prefix="u-", dir=top)
            os.chmod(d, 0o700)
        except OSError as e:
            raise UpgradeError(f"upgrade_dir: {type(e).__name__}") from e
        u["dir"] = d
        return d

    def _tarball(self, nu: dict, base: str) -> str:
        cached = os.path.join(self.cfg.get("RELEASES_DIR") or "/var/lib/pcdn/releases", nu["release"] + ".tar.gz")
        if _sha256_file(cached) == nu["sha256"]:
            log.info("self-upgrade %s: using the cached %s", nu["id"], cached)
            return cached
        url = ((self.cfg.get("CONTROLLER_URL") or "").rstrip("/") + "/edge/bundle.tar.gz?version="
               + urllib.parse.quote(nu["release"]))
        dest = os.path.join(base, "bundle.tar.gz")
        h, size = hashlib.sha256(), 0
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "pcdn-agent/2.0"})
            with self.opener(req, timeout=UPGRADE_DL_TIMEOUT) as r, \
                    open(os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "wb") as f:
                while True:
                    chunk = r.read(1 << 20)
                    if not chunk:
                        break
                    size += len(chunk)
                    if size > UPGRADE_MAX_BYTES:
                        raise UpgradeError("bundle_too_large")
                    h.update(chunk)
                    f.write(chunk)
        except urllib.error.HTTPError as e:
            raise UpgradeError(f"download_failed: HTTP {e.code}") from e
        except (urllib.error.URLError, OSError, ValueError) as e:
            raise UpgradeError(f"download_failed: {type(e).__name__}") from e
        if h.hexdigest() != nu["sha256"]:
            raise UpgradeError("sha256_mismatch")
        return dest

    def _extract(self, tarball: str, base: str) -> str:
        out = os.path.join(base, "x")
        try:
            os.makedirs(out, mode=0o700)
            with tarfile.open(tarball, "r:gz") as t:
                for m in t.getmembers():   # defence in depth (the data filter below checks the same)
                    name = os.path.normpath(m.name)
                    if name.startswith(("/", "..")) or m.isdev() or ((m.issym() or m.islnk()) and (
                            os.path.isabs(m.linkname) or os.path.normpath(
                                os.path.join(os.path.dirname(name), m.linkname)).startswith(".."))):
                        raise UpgradeError("bad_bundle: unsafe member")
                try:
                    t.extractall(out, filter="data")
                except TypeError:   # a Python without extraction filters (checked above)
                    t.extractall(out)
        except UpgradeError:
            raise
        except (OSError, tarfile.TarError, ValueError) as e:
            raise UpgradeError(f"bad_bundle: {type(e).__name__}") from e
        edge = os.path.join(out, "edge")
        if not os.path.isfile(os.path.join(edge, "install.sh")):
            raise UpgradeError("bad_bundle: no edge/install.sh")
        return edge

    def _launch(self, u: dict, nu: dict, edge: str, tarball: str):
        unit = unit_name(nu["id"]) + ("-rb" if nu["rollback"] else "")
        status = os.path.join(self._upgrade_dir(), unit + ".status")
        args = ["--upgrade"]
        try:
            with open(os.path.join(edge, "install.sh"), encoding="utf-8", errors="replace") as f:
                script = f.read()
        except OSError as e:
            raise UpgradeError("bad_bundle: install.sh unreadable") from e
        if "--release)" in script:   # an installer from before §23.1 has no --release (rollback target)
            args += ["--release", nu["release"]]
        if nu["drain_minutes"] > 0:
            args.append(f"--drain={nu['drain_minutes']}")
        self._set(u, state="installing", unit=unit, status_file=status)
        self._persist()   # recorded before anything runs (the installer restarts this agent)
        # the wrapper records the installer's exit code: a --collect'ed failed unit is gone quickly
        wrapper = 'rc=0; /bin/bash "$0" "$@" || rc=$?; echo "$rc" > "$PCDN_UPGRADE_STATUS"; exit "$rc"'
        cmd = ["systemd-run", f"--unit={unit}", "--collect", "--no-block", "--property=Type=oneshot",
               f"--property=TimeoutStartSec={nu['timeout_s']}", "--setenv=PCDN_SELF_UPGRADE=1",
               f"--setenv=PCDN_UPGRADE_STATUS={status}", f"--setenv=PCDN_RELEASE_TARBALL={tarball}",
               f"--working-directory={edge}", "/bin/bash", "-c", wrapper, os.path.join(edge, "install.sh"), *args]
        try:
            p = self.run(cmd, capture_output=True, text=True, timeout=60)
        except (OSError, subprocess.SubprocessError) as e:
            raise UpgradeError(f"systemd_run_failed: {type(e).__name__}") from e
        if p.returncode != 0:
            raise UpgradeError(f"systemd_run_failed: exit {p.returncode}")
        log.info("self-upgrade %s: installer started (unit %s)", nu["id"], unit)
