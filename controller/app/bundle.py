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
                    extra: str = "") -> str:
    """The copy-paste one-command install for a node with this one-time token (SPEC §11.1)."""
    base = base_url()
    cmd = (f"curl -fsSL {base}/edge/bootstrap.sh | sudo bash -s -- "
           f"--controller {base} --token {token}")
    if region in _VALID_REGION:
        cmd += f" --region {region}"
    if role in _VALID_ROLE:
        cmd += f" --role {role}"
    if extra:
        cmd += f" {extra}"
    return cmd
