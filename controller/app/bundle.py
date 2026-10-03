"""Edge bundle: the controller serves the secret-free edge/ tree so a node can be
provisioned with one command (SPEC §11.1).

The bundle is a gzip tar of the edge/ directory (agent, nginx/njs/pages templates,
install.sh, systemd units, geoip updater), built on the fly from EDGE_BUNDLE_DIR. It
holds NO secrets, keys or tokens; live configs (*.conf) and caches are excluded. The
bundle version is a short, stable hash of the included files' contents (identical trees
hash identically) and is reported by the agent so the panel can flag out-of-date nodes.
"""

import hashlib
import io
import os
import shlex
import tarfile

from .config import settings

# directory / file names never included in the bundle: python caches, tests, VCS and
# anything that could carry a live secret. The templates (edge/*/*.conf) are included;
# only a live agent config (agent.conf) would carry a token, and it never lives in edge/.
EXCLUDE_DIRS = {"__pycache__", "tests", ".git", ".pytest_cache", ".mypy_cache", "node_modules"}
EXCLUDE_SUFFIXES = (".pyc", ".pyo")
EXCLUDE_NAMES = {"agent.conf"}


def _bundle_dir() -> str | None:
    d = settings.edge_bundle_dir
    return d if d and os.path.isdir(d) else None


def _included_files(root: str) -> list[tuple[str, str]]:
    """(absolute path, arcname) of every file to include, sorted by arcname for stability."""
    out: list[tuple[str, str]] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in EXCLUDE_DIRS)
        for name in filenames:
            if name in EXCLUDE_NAMES or name.endswith(EXCLUDE_SUFFIXES):
                continue
            full = os.path.join(dirpath, name)
            if not os.path.isfile(full):  # skip symlinks / sockets / fifos
                continue
            arc = os.path.relpath(full, root).replace(os.sep, "/")
            out.append((full, arc))
    out.sort(key=lambda p: p[1])
    return out


def available() -> bool:
    return _bundle_dir() is not None


def version() -> str | None:
    """Short stable hash of the bundle (sorted arcname + file bytes). None when no bundle dir."""
    root = _bundle_dir()
    if root is None:
        return None
    h = hashlib.sha256()
    for full, arc in _included_files(root):
        h.update(arc.encode())
        h.update(b"\0")
        with open(full, "rb") as f:
            h.update(f.read())
        h.update(b"\0")
    return h.hexdigest()[:16]


def build_tar() -> bytes | None:
    """gzip tar of the edge/ tree, or None when no bundle dir is configured/present.

    Deterministic: files in sorted order, fixed mtime/uid/gid so identical trees produce
    byte-identical archives (a cache-friendly, reproducible bundle)."""
    root = _bundle_dir()
    if root is None:
        return None
    buf = io.BytesIO()
    # mtime 0 keeps the archive reproducible; executables keep their bit, others 0644
    with tarfile.open(fileobj=buf, mode="w:gz", format=tarfile.GNU_FORMAT) as tar:
        for full, arc in _included_files(root):
            info = tarfile.TarInfo(name="edge/" + arc)
            with open(full, "rb") as f:
                data = f.read()
            info.size = len(data)
            info.mtime = 0
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            info.mode = 0o755 if (os.stat(full).st_mode & 0o111) else 0o644
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def bootstrap_script() -> str | None:
    """Contents of edge/bootstrap.sh, or None when the bundle dir has no such file."""
    root = _bundle_dir()
    if root is None:
        return None
    path = os.path.join(root, "bootstrap.sh")
    if not os.path.isfile(path):
        return None
    with open(path, encoding="utf-8") as f:
        return f.read()


# ---- install one-liner (SPEC §11.1) ---------------------------------------

_VALID_REGION = ("home", "global")
_VALID_ROLE = ("general", "tunnel")


def base_url() -> str:
    """Public controller URL for the one-liner; https://<CONTROLLER_DOMAIN> or a placeholder."""
    dom = settings.controller_domain
    return f"https://{dom}" if dom else "https://<controller>"


def install_command(token: str, region: str | None = None, role: str | None = None,
                    extra: str = "", version: str | None = None) -> str:
    """The copy-paste one-command install for a node with this one-time token (SPEC §11.1). The
    token travels in the environment (PCDN_EDGE_TOKEN, read by edge/bootstrap.sh), not on bash's
    argv, so it is not visible to other local users in ps / /proc/<pid>/cmdline while it installs."""
    base = base_url()
    cmd = (f"curl -fsSL {base}/edge/bootstrap.sh | sudo PCDN_EDGE_TOKEN={shlex.quote(token)} bash -s -- "
           f"--controller {base}")
    if region in _VALID_REGION:
        cmd += f" --region {region}"
    if role in _VALID_ROLE:
        cmd += f" --role {role}"
    if version and VERSION_RE.match(version):  # SPEC §23.1: the pinned release of the edge's group
        cmd += f" --version {version}"
    if extra:
        cmd += f" {extra}"
    return cmd


# ---- pinned edge releases (SPEC §23.1) -------------------------------------
#
# EDGE_RELEASES_DIR holds pcdn-edge-vX.Y.Z.tar.gz + pcdn-edge-vX.Y.Z.tar.gz.sha256 (sha256sum format),
# filled by the operator (tools/release/fetch-edge-release.sh / build-edge-bundle.sh). Empty = off:
# every bundle route behaves exactly as before. File names are always built from a validated version.

import logging  # noqa: E402
import re  # noqa: E402

log = logging.getLogger("pcdn.bundle")

VERSION_RE = re.compile(r"^v\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$")
GROUP_PIN_KEY = "edge_release:group:{}"
GROUPS = ("general", "tunnel")
_warned: set[str] = set()


def releases_dir() -> str | None:
    d = settings.edge_releases_dir
    return d if d and os.path.isdir(d) else None


def releases_enabled() -> bool:
    return bool(settings.edge_releases_dir)


def release_file(version: str) -> str | None:
    """Absolute path of the tarball of a validated version, or None (no dir / unknown version)."""
    d = releases_dir()
    if d is None or not VERSION_RE.match(version or ""):
        return None
    path = os.path.join(d, f"pcdn-edge-{version}.tar.gz")
    return path if os.path.isfile(path) else None


def _hash_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def release_sha256(version: str) -> str | None:
    """The sha256 of a release: its .sha256 file (sha256sum format), else computed from the tarball."""
    path = release_file(version)
    if path is None:
        return None
    try:
        with open(path + ".sha256", encoding="utf-8") as f:
            first = (f.read().split() or [""])[0].lower()
        if re.match(r"^[0-9a-f]{64}$", first):
            return first
    except OSError:
        pass
    return _hash_file(path)


def semver_key(version: str):
    """Sort key per SemVer §11 (a pre-release sorts before its release)."""
    m = re.match(r"^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?$", version or "")
    if not m:
        return (0, 0, 0, 0, ())
    pre = m.group(4)
    ids = tuple((0, int(p), "") if p.isdigit() else (1, 0, p) for p in pre.split(".")) if pre else ()
    return (int(m.group(1)), int(m.group(2)), int(m.group(3)), 0 if pre else 1, ids)


def list_releases() -> list[dict]:
    """[{"version", "sha256", "size"}] of EDGE_RELEASES_DIR, newest SemVer first."""
    d = releases_dir()
    if d is None:
        return []
    out = []
    for name in os.listdir(d):
        m = re.match(r"^pcdn-edge-(v.+)\.tar\.gz$", name)
        if not m or not VERSION_RE.match(m.group(1)):
            continue
        v = m.group(1)
        out.append({"version": v, "sha256": release_sha256(v), "size": os.path.getsize(os.path.join(d, name))})
    out.sort(key=lambda r: semver_key(r["version"]), reverse=True)
    return out


def configured_pin() -> str | None:
    """EDGE_RELEASE when it exists in EDGE_RELEASES_DIR (else logged once and ignored)."""
    v = settings.edge_release
    if not v:
        return None
    if release_file(v) is None:
        if v not in _warned:
            _warned.add(v)
            log.error("EDGE_RELEASE=%s is not in EDGE_RELEASES_DIR (or the format is invalid); ignored, "
                      "new installs get the live bundle", v[:40])
        return None
    return v


def group_pin(db, group: str) -> str | None:
    """Effective pin of an edge group: a completed rollout's state value, else EDGE_RELEASE."""
    if not releases_enabled():
        return None
    from . import kv

    row = kv.get_json(db, GROUP_PIN_KEY.format(group)) if db is not None else {}
    v = row.get("release") if isinstance(row, dict) else None
    if v and release_file(v):
        return v
    return configured_pin()


def set_group_pin(db, group: str, release: str) -> None:
    from . import kv

    kv.set_json(db, GROUP_PIN_KEY.format(group), {"release": release})


def pins(db) -> dict[str, str | None]:
    return {g: group_pin(db, g) for g in GROUPS}
