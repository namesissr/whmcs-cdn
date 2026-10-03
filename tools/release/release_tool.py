#!/usr/bin/env python3
"""Pasargad CDN release helpers (SPEC §23.1) — Python 3 standard library only.

The shell entry points in this directory (prepare.sh, changelog-section.sh, build-edge-bundle.sh,
security-check.sh, check-meta.sh) call the sub-commands below; they are kept here so the logic is
unit-tested (tools/release/tests).

  release_tool.py semver-cmp A B                 print -1 / 0 / 1 (SemVer 2.0.0 §11 precedence)
  release_tool.py check-meta [--repo DIR]        VERSION is SemVer, CHANGELOG has "## [Unreleased]"
  release_tool.py prepare X.Y.Z [--repo DIR] [--date YYYY-MM-DD]
                                                 rewrite CHANGELOG + VERSION (no git commands)
  release_tool.py section X.Y.Z|Unreleased [--repo DIR]
                                                 print one CHANGELOG section body
  release_tool.py bundle vX.Y.Z --src DIR --out DIR --mtime EPOCH
                                                 deterministic pcdn-edge-vX.Y.Z.tar.gz + .sha256
  release_tool.py scan-secrets [--repo DIR] [--since REF] [FILE...]
                                                 built-in secret scan (used when gitleaks is absent)
  release_tool.py hard-constraint [--repo DIR]   no rum / ISP import in node-selection modules (§23.7)

Nothing here runs `git commit`, `git tag`, `git push` or talks to GitHub: merging, tagging and
publishing a release are the repository owner's decisions (docs/RELEASE.md).
"""

from __future__ import annotations

import argparse
import ast
import datetime as dt
import gzip
import hashlib
import io
import os
import re
import subprocess
import sys
import tarfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent

# SemVer 2.0.0 without build metadata (the controller / bootstrap regex rejects "+build" too)
_NUM = r"(?:0|[1-9]\d*)"
_PRE_ID = r"(?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*)"
SEMVER_RE = re.compile(rf"^({_NUM})\.({_NUM})\.({_NUM})(?:-({_PRE_ID}(?:\.{_PRE_ID})*))?$")
TAG_RE = re.compile(r"^v\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$")  # the frozen §23.1 tag regex

KAC_ORDER = ("Added", "Changed", "Deprecated", "Removed", "Fixed", "Security")
DEFAULT_REPO_URL = "https://github.com/namesissr/whmcs-cdn"


class ReleaseError(Exception):
    """A refusal: printed as "release: <msg>" with exit code 1."""


# ---------------------------------------------------------------------------------------- SemVer

def parse_semver(v: str) -> tuple[int, int, int, tuple | None]:
    m = SEMVER_RE.match(v or "")
    if not m:
        raise ReleaseError(f"{v!r} is not a SemVer version X.Y.Z[-pre] (no leading 'v', no +build)")
    pre = tuple(m.group(4).split(".")) if m.group(4) else None
    return int(m.group(1)), int(m.group(2)), int(m.group(3)), pre


def _cmp_pre(a: tuple | None, b: tuple | None) -> int:
    # SemVer §11.3: a version without pre-release has higher precedence
    if a is None and b is None:
        return 0
    if a is None:
        return 1
    if b is None:
        return -1
    for x, y in zip(a, b):
        if x == y:
            continue
        xn, yn = x.isdigit(), y.isdigit()
        if xn and yn:
            return -1 if int(x) < int(y) else 1
        if xn != yn:                      # numeric identifiers sort before alphanumeric ones
            return -1 if xn else 1
        return -1 if x < y else 1         # ASCII order
    return (len(a) > len(b)) - (len(a) < len(b))


def semver_cmp(a: str, b: str) -> int:
    pa, pb = parse_semver(a), parse_semver(b)
    if pa[:3] != pb[:3]:
        return -1 if pa[:3] < pb[:3] else 1
    return _cmp_pre(pa[3], pb[3])


def read_version(repo: Path) -> str:
    path = repo / "VERSION"
    if not path.is_file():
        raise ReleaseError(f"{path} is missing")
    lines = path.read_text(encoding="utf-8").splitlines()
    v = lines[0].strip() if lines else ""
    parse_semver(v)
    return v


# ---------------------------------------------------------------------------------------- CHANGELOG

HEAD_RE = re.compile(r"^## \[([^\]]+)\](?:\s*-\s*(.+?))?\s*$")
LINKDEF_RE = re.compile(r"^\[([^\]]+)\]:\s*(\S+)\s*$")


def _sections(lines: list[str]) -> list[dict]:
    """Every "## [name] - date" heading: {"name", "date", "start", "end"} (end = exclusive line index,
    stops before the next "## " heading or the link definitions at the bottom)."""
    heads = [(i, HEAD_RE.match(line)) for i, line in enumerate(lines)]
    heads = [(i, m) for i, m in heads if m]
    link_start = len(lines)
    for i in range(len(lines) - 1, -1, -1):
        if LINKDEF_RE.match(lines[i]) or not lines[i].strip():
            if LINKDEF_RE.match(lines[i]):
                link_start = i
            continue
        break
    out = []
    for n, (i, m) in enumerate(heads):
        end = heads[n + 1][0] if n + 1 < len(heads) else link_start
        out.append({"name": m.group(1), "date": (m.group(2) or "").strip(), "start": i, "end": end})
    return out


def _body(lines: list[str], sec: dict) -> list[str]:
    body = lines[sec["start"] + 1:sec["end"]]
    while body and not body[0].strip():
        body.pop(0)
    while body and not body[-1].strip():
        body.pop()
    return body


def _has_entries(body: list[str]) -> bool:
    return any(line.strip() and not line.startswith("#") for line in body)


def _split_sub(body: list[str]) -> tuple[list[str], list[tuple[str, list[str]]]]:
    """Body -> (preamble lines, [(### heading, lines)])."""
    pre: list[str] = []
    subs: list[tuple[str, list[str]]] = []
    for line in body:
        if line.startswith("### "):
            subs.append((line.rstrip(), []))
        elif subs:
            subs[-1][1].append(line)
        else:
            pre.append(line)
    return pre, subs


def _trim(block: list[str]) -> list[str]:
    block = list(block)
    while block and not block[0].strip():
        block.pop(0)
    while block and not block[-1].strip():
        block.pop()
    return block


def merge_bodies(newer: list[str], older: list[str]) -> list[str]:
    """Merge the [Unreleased] body (newer) into an existing "[X.Y.Z] - Unreleased" body (older):
    older preamble first (it introduces the version), then the newer one; ### sub-sections with the
    same heading are combined (newer entries first), Keep-a-Changelog categories in their usual order."""
    pre_n, subs_n = _split_sub(newer)
    pre_o, subs_o = _split_sub(older)
    merged: dict[str, list[str]] = {}
    order: list[str] = []
    for head, block in subs_n + subs_o:
        if head not in merged:
            merged[head] = []
            order.append(head)
        part = _trim(block)
        if part:
            if merged[head]:
                merged[head].append("")
            merged[head].extend(part)

    def rank(head: str) -> tuple[int, int]:
        word = head[4:].split()[0] if len(head) > 4 else ""
        return (KAC_ORDER.index(word) if word in KAC_ORDER else len(KAC_ORDER), order.index(head))

    out: list[str] = []
    for pre in (_trim(pre_o), _trim(pre_n)):
        if pre:
            out.extend(pre + [""])
    for head in sorted(order, key=rank):
        out.extend([head, ""] + merged[head] + [""])
    return _trim(out)


def prepare_changelog(text: str, version: str, date: str, current: str | None = None) -> tuple[str, list[str]]:
    """Return (new CHANGELOG text, warnings). Raises ReleaseError on a refusal."""
    lines = text.splitlines()
    secs = _sections(lines)
    by_name = {s["name"]: s for s in secs}
    unrel = by_name.get("Unreleased")
    if unrel is None:
        raise ReleaseError("CHANGELOG.md has no '## [Unreleased]' section")
    body_new = _body(lines, unrel)
    if not _has_entries(body_new):
        raise ReleaseError("the [Unreleased] section of CHANGELOG.md is empty: nothing to release")
    existing = by_name.get(version)
    if existing and existing["date"].lower() != "unreleased":
        raise ReleaseError(f"CHANGELOG.md already has a released section [{version}] - {existing['date']}")
    body = merge_bodies(body_new, _body(lines, existing)) if existing else body_new

    warnings = []
    for s in secs:
        if s["name"] not in ("Unreleased", version) and s["date"].lower() == "unreleased":
            warnings.append(f"section [{s['name']}] is still marked 'Unreleased' (it was never tagged)")

    new_sec = ["## [Unreleased]", "", f"## [{version}] - {date}", ""] + body + [""]
    drop = {unrel["start"]} | ({existing["start"]} if existing else set())
    out: list[str] = []
    i = 0
    while i < len(lines):
        sec = next((s for s in secs if s["start"] == i and s["start"] in drop), None)
        if sec is None:
            out.append(lines[i])
            i += 1
            continue
        if sec is unrel:
            out.extend(new_sec)
        i = sec["end"]
    # collapse runs of blank lines left by a removed section
    collapsed: list[str] = []
    for line in out:
        if not line.strip() and collapsed and not collapsed[-1].strip():
            continue
        collapsed.append(line)
    out = collapsed

    # compare links ----------------------------------------------------------------------------
    released = []
    for s in secs:
        if s["name"] in ("Unreleased", version) or s["date"].lower() == "unreleased":
            continue
        try:
            if semver_cmp(s["name"], version) < 0:
                released.append(s["name"])
        except ReleaseError:
            continue
    prev = max(released, key=_SortKey) if released else None
    base = None
    link_idx = {}
    for i, line in enumerate(out):
        m = LINKDEF_RE.match(line)
        if m:
            link_idx[m.group(1)] = i
            if m.group(1) == "Unreleased" and "/compare/" in m.group(2):
                base = m.group(2).split("/compare/")[0]
    if base is None:
        base = DEFAULT_REPO_URL
        warnings.append(f"no [Unreleased] compare link found; using {base}")
    unrel_link = f"[Unreleased]: {base}/compare/v{version}...HEAD"
    ver_link = (f"[{version}]: {base}/compare/v{prev}...v{version}" if prev
                else f"[{version}]: {base}/releases/tag/v{version}")
    if "Unreleased" in link_idx:
        out[link_idx["Unreleased"]] = unrel_link
        if version in link_idx:
            out[link_idx[version]] = ver_link
        else:
            out.insert(link_idx["Unreleased"] + 1, ver_link)
    else:
        while out and not out[-1].strip():
            out.pop()
        out += ["", unrel_link, ver_link]
    return "\n".join(out).rstrip("\n") + "\n", warnings


class _SortKey:
    def __init__(self, v):
        self.v = v

    def __lt__(self, other):
        return semver_cmp(self.v, other.v) < 0


def changelog_section(text: str, name: str) -> str:
    lines = text.splitlines()
    for s in _sections(lines):
        if s["name"] == name:
            return "\n".join(_body(lines, s)) + "\n"
    raise ReleaseError(f"CHANGELOG.md has no section [{name}]")


def prepare(repo: Path, version: str, date: str | None) -> list[str]:
    parse_semver(version)
    current = read_version(repo)
    cl_path = repo / "CHANGELOG.md"
    text = cl_path.read_text(encoding="utf-8")
    cmp = semver_cmp(version, current)
    if cmp < 0 or (cmp == 0 and not re.search(rf"^## \[{re.escape(version)}\]\s*-\s*Unreleased\s*$", text,
                                              re.M | re.I)):
        raise ReleaseError(f"{version} must be greater than VERSION ({current}) — or equal to it only while "
                           f"CHANGELOG.md still has '## [{version}] - Unreleased'")
    date = date or dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d")
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", date):
        raise ReleaseError("--date must be YYYY-MM-DD")
    new, warnings = prepare_changelog(text, version, date, current)
    cl_path.write_text(new, encoding="utf-8")
    (repo / "VERSION").write_text(version + "\n", encoding="utf-8")
    return warnings


def check_meta(repo: Path) -> list[str]:
    problems = []
    try:
        read_version(repo)
    except ReleaseError as e:
        problems.append(str(e))
    cl = repo / "CHANGELOG.md"
    if not cl.is_file() or not re.search(r"^## \[Unreleased\]\s*$", cl.read_text(encoding="utf-8"), re.M):
        problems.append("CHANGELOG.md has no '## [Unreleased]' heading")
    return problems


# ---------------------------------------------------------------------------------------- edge bundle

# identical to controller/app/bundle.py (frozen contract §23.18 item 7)
EXCLUDE_DIRS = {"__pycache__", "tests", ".git", ".pytest_cache", ".mypy_cache", "node_modules"}
EXCLUDE_SUFFIXES = (".pyc", ".pyo")
EXCLUDE_NAMES = {"agent.conf"}


def included_files(root: Path) -> list[tuple[str, str]]:
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in EXCLUDE_DIRS)
        for name in filenames:
            if name in EXCLUDE_NAMES or name.endswith(EXCLUDE_SUFFIXES):
                continue
            full = os.path.join(dirpath, name)
            if not os.path.isfile(full):  # like bundle.py: skip sockets / fifos / dangling links
                continue
            arc = os.path.relpath(full, root).replace(os.sep, "/")
            if arc == "RELEASE":
                continue  # written from the tag below, never taken from the tree
            out.append((full, arc))
    out.sort(key=lambda p: p[1])
    return out


def build_bundle(tag: str, src: Path, out_dir: Path, mtime: int) -> tuple[Path, str]:
    """dist/pcdn-edge-<tag>.tar.gz (top dir edge/, edge/RELEASE = tag) + .sha256 in sha256sum format.

    Deterministic: sorted entries, every mtime = `mtime` (the tag commit time), uid/gid 0 without
    names, mode 0755 for executables else 0644, gzip without name and timestamp (like `gzip -n`)."""
    if not TAG_RE.match(tag):
        raise ReleaseError(f"{tag!r} is not a release tag vX.Y.Z[-pre]")
    parse_semver(tag[1:])
    if not (src / "install.sh").is_file():
        raise ReleaseError(f"{src} does not look like the edge/ tree (no install.sh)")
    entries = [(arc, full) for full, arc in included_files(src)]
    entries.append(("RELEASE", None))
    entries.sort(key=lambda e: e[0])
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.GNU_FORMAT) as tar:
        for arc, full in entries:
            if full is None:
                data, mode = (tag + "\n").encode(), 0o644
            else:
                with open(full, "rb") as f:
                    data = f.read()
                mode = 0o755 if (os.stat(full).st_mode & 0o111) else 0o644
            info = tarfile.TarInfo(name="edge/" + arc)
            info.size = len(data)
            info.mtime = mtime
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            info.mode = mode
            tar.addfile(info, io.BytesIO(data))
    gz = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=gz, compresslevel=9, mtime=0) as g:
        g.write(raw.getvalue())
    out_dir.mkdir(parents=True, exist_ok=True)
    name = f"pcdn-edge-{tag}.tar.gz"
    path = out_dir / name
    path.write_bytes(gz.getvalue())
    digest = hashlib.sha256(gz.getvalue()).hexdigest()
    (out_dir / (name + ".sha256")).write_text(f"{digest}  {name}\n", encoding="utf-8")
    return path, digest


# ---------------------------------------------------------------------------------------- secret scan

SECRET_PATTERNS = [
    ("private_key", re.compile(r"-----BEGIN (?:[A-Z]+ )*PRIVATE KEY(?: BLOCK)?-----")),
    ("edge_token", re.compile(r"\bedge_[0-9a-f]{32,}\b")),
    ("customer_api_key", re.compile(r"\bpcdn_[0-9a-f]{40}\b")),
    ("join_token", re.compile(r"\bjt_[0-9a-f]{40}\b")),
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("aws_secret_key", re.compile(r"(?i)aws_?secret_?access_?key\s*[=:]\s*['\"]?[A-Za-z0-9/+]{40}\b")),
    ("bot_token", re.compile(r"\b\d{6,}:[A-Za-z0-9_-]{30,}")),
    ("arvan_apikey", re.compile(r"Apikey [A-Za-z0-9-]{20,}")),
]
ALLOW_MARK = "secret-scan: allow"
_B64_LINE = re.compile(r"^[A-Za-z0-9+/=]{40,}$")


def is_placeholder(token: str) -> bool:
    """Obvious test placeholders: the secret part is periodic ("0123456789abcdef0123…", "ffff…")."""
    s = re.sub(r"^(?:edge_|pcdn_|jt_|Apikey |AKIA|ASIA|\d+:)", "", token)
    if len(s) < 8:
        return True
    for p in range(1, min(16, len(s) // 2) + 1):
        if all(s[i] == s[i % p] for i in range(len(s))):
            return True
    return "EXAMPLE" in token.upper() or "XXXX" in token.upper()


def scan_text(text: str, where: str) -> list[dict]:
    findings = []
    lines = text.splitlines()
    for n, line in enumerate(lines, 1):
        if ALLOW_MARK in line:
            continue
        for kind, rx in SECRET_PATTERNS:
            for m in rx.finditer(line):
                if kind == "private_key":
                    # a real key has a base64 body; markers in docs / validators / UI hints do not
                    nxt = lines[n].strip() if n < len(lines) else ""
                    if not _B64_LINE.match(nxt):
                        continue
                elif is_placeholder(m.group(0)):
                    continue
                findings.append({"file": where, "line": n, "kind": kind,
                                 "match": m.group(0)[:12] + "…"})   # never print the whole secret
    return findings


def _git(repo: Path, *args) -> str:
    return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True).stdout


def previous_tag(repo: Path) -> str | None:
    """Newest v* tag reachable from HEAD that does not point at HEAD itself."""
    try:
        head = _git(repo, "rev-parse", "HEAD").strip()
        tags = _git(repo, "tag", "--merged", "HEAD", "--list", "v[0-9]*", "--sort=-creatordate").split()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None
    for t in tags:
        if TAG_RE.match(t) and _git(repo, "rev-list", "-n1", t).strip() != head:
            return t
    return None


def files_to_scan(repo: Path, since: str | None) -> list[str]:
    if since:
        names = _git(repo, "diff", "--name-only", "--diff-filter=ACMR", f"{since}...HEAD").split("\n")
    else:
        names = _git(repo, "ls-files").split("\n")
    # uncommitted changes are part of the candidate too
    names += _git(repo, "diff", "--name-only", "--diff-filter=ACMR", "HEAD").split("\n")
    return sorted({n for n in names if n and (repo / n).is_file()})


def scan_secrets(repo: Path, since: str | None, files: list[str] | None = None) -> list[dict]:
    findings = []
    for rel in files if files else files_to_scan(repo, since):
        p = Path(rel) if os.path.isabs(rel) else repo / rel
        try:
            data = p.read_bytes()
        except OSError:
            continue
        if b"\0" in data[:8192] or len(data) > 5 * 1024 * 1024:
            continue  # binary / huge
        findings += scan_text(data.decode("utf-8", "replace"), rel)
    return findings


FORBIDDEN_TRACKED = re.compile(r"(^|/)(\.env|agent\.conf)$|\.pem$|(^|/)\.env\.(?!example$)[^/]+$")


def forbidden_tracked(repo: Path) -> list[str]:
    return [n for n in _git(repo, "ls-files").split("\n") if n and FORBIDDEN_TRACKED.search(n)]


# ---------------------------------------------------------------------------------------- hard constraint

# modules that choose / weigh / roll out / provision nodes must never read RUM or ISP data (§23 / §23.7)
NODE_SELECTION_MODULES = ("dnsbuild.py", "rollout.py", "provisioning.py")
FORBIDDEN_IMPORT = re.compile(r"(^|\.)(rum|isp|isp_names)$|(^|\.)rum[._]|isp_names")


def hard_constraint(repo: Path) -> list[str]:
    problems = []
    app = repo / "controller" / "app"
    for name in NODE_SELECTION_MODULES:
        path = app / name
        if not path.is_file():
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), str(path))
        except SyntaxError as e:
            problems.append(f"{path}: cannot parse ({e})")
            continue
        for node in ast.walk(tree):
            mods = []
            if isinstance(node, ast.Import):
                mods = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom):
                base = node.module or ""
                mods = [base] + [f"{base}.{a.name}" if base else a.name for a in node.names]
            bad = [m for m in mods if FORBIDDEN_IMPORT.search(m)]
            if bad:
                problems.append(f"controller/app/{name}:{node.lineno} imports {bad[0]} (RUM/ISP data must never "
                                "reach node selection, SPEC §23.7)")
            if isinstance(node, ast.Constant) and isinstance(node.value, str) and "isp_names" in node.value:
                problems.append(f"controller/app/{name}:{node.lineno} references isp_names")
    return problems


# ---------------------------------------------------------------------------------------- CLI

def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="release_tool.py", description=__doc__.split("\n")[0])
    ap.add_argument("--repo", type=Path, default=None, help="repository root (default: this checkout)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("semver-cmp")
    p.add_argument("a")
    p.add_argument("b")
    sub.add_parser("check-meta")
    p = sub.add_parser("prepare")
    p.add_argument("version")
    p.add_argument("--date")
    p = sub.add_parser("section")
    p.add_argument("version")
    p = sub.add_parser("bundle")
    p.add_argument("tag")
    p.add_argument("--src", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--mtime", type=int, required=True)
    p = sub.add_parser("scan-secrets")
    p.add_argument("--since")
    p.add_argument("files", nargs="*")
    sub.add_parser("forbidden-files")
    sub.add_parser("hard-constraint")
    sub.add_parser("previous-tag")
    a = ap.parse_args(argv)
    repo = (a.repo or REPO).resolve()
    try:
        if a.cmd == "semver-cmp":
            print(semver_cmp(a.a, a.b))
        elif a.cmd == "check-meta":
            problems = check_meta(repo)
            for msg in problems:
                print(f"release-meta: {msg}", file=sys.stderr)
            if problems:
                return 1
            print(f"VERSION {read_version(repo)} ok; CHANGELOG has [Unreleased]")
        elif a.cmd == "prepare":
            v = a.version[1:] if a.version.startswith("v") else a.version
            for w in prepare(repo, v, a.date):
                print(f"warning: {w}", file=sys.stderr)
        elif a.cmd == "section":
            v = a.version[1:] if a.version.startswith("v") and a.version[1:2].isdigit() else a.version
            sys.stdout.write(changelog_section((repo / "CHANGELOG.md").read_text(encoding="utf-8"), v))
        elif a.cmd == "bundle":
            path, digest = build_bundle(a.tag, a.src.resolve(), a.out, a.mtime)
            print(f"{digest}  {path}")
        elif a.cmd == "scan-secrets":
            found = scan_secrets(repo, a.since, a.files or None)
            for f in found:
                print(f"{f['file']}:{f['line']}: possible {f['kind']} ({f['match']})")
            return 1 if found else 0
        elif a.cmd == "forbidden-files":
            bad = forbidden_tracked(repo)
            for n in bad:
                print(f"tracked file must not be committed: {n}")
            return 1 if bad else 0
        elif a.cmd == "hard-constraint":
            problems = hard_constraint(repo)
            for msg in problems:
                print(msg)
            return 1 if problems else 0
        elif a.cmd == "previous-tag":
            t = previous_tag(repo)
            if t:
                print(t)
    except ReleaseError as e:
        print(f"release: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
