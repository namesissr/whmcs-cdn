"""Tests for the release tooling (SPEC §23.1): prepare / changelog section, deterministic edge bundle,
fetch-edge-release, staging-verify against a fake controller, security-check scanners."""

import functools
import hashlib
import http.server
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tarfile
import threading

import pytest

HERE = pathlib.Path(__file__).resolve().parent
REL = HERE.parent
REPO = REL.parent.parent
sys.path.insert(0, str(REL))

import release_tool as rt  # noqa: E402
import staging_verify as sv  # noqa: E402

FIXTURE_CHANGELOG = """# Changelog

Intro text.

## [Unreleased]

### Added

- New thing A.

### Fixed

- Bug B.

## [2.1.0] - Unreleased

Second release intro.

### Added

- Older thing C.

## [2.0.0] - 2026-01-10

### Added

- First release.

[Unreleased]: https://github.com/example/repo/compare/v2.0.0...HEAD
[2.0.0]: https://github.com/example/repo/releases/tag/v2.0.0
"""


def git(cwd, *args):
    return subprocess.run(["git", "-C", str(cwd), *args], check=True, capture_output=True, text=True).stdout


@pytest.fixture
def repo(tmp_path):
    r = tmp_path / "repo"
    r.mkdir()
    git(r, "init", "-q", "-b", "main")
    git(r, "config", "user.email", "t@example.com")
    git(r, "config", "user.name", "t")
    (r / "CHANGELOG.md").write_text(FIXTURE_CHANGELOG)
    (r / "VERSION").write_text("2.0.0\n")
    git(r, "add", ".")
    git(r, "commit", "-qm", "init")
    return r


def prepare(repo, *args):
    return subprocess.run(["bash", str(REL / "prepare.sh"), *args], cwd=repo, capture_output=True, text=True)


# ------------------------------------------------------------------------------------------- SemVer

def test_semver_precedence_spec_example():
    chain = ["1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta", "1.0.0-beta.2", "1.0.0-beta.11",
             "1.0.0-rc.1", "1.0.0", "1.0.1", "1.1.0", "2.0.0-rc.1", "2.0.0", "2.1.0-rc.1", "2.1.0", "10.0.0"]
    for a, b in zip(chain, chain[1:]):
        assert rt.semver_cmp(a, b) == -1 and rt.semver_cmp(b, a) == 1, (a, b)
    assert rt.semver_cmp("2.1.0", "2.1.0") == 0
    for bad in ("v2.1.0", "2.1", "02.1.0", "2.1.0+build", "2.1.0-", "2.1.0-01", ""):
        with pytest.raises(rt.ReleaseError):
            rt.parse_semver(bad)


# ------------------------------------------------------------------------------------------- prepare

def test_prepare_merges_existing_unreleased_version_and_links(repo):
    p = prepare(repo, "2.1.0", "--date", "2026-10-03")
    assert p.returncode == 0, p.stderr
    text = (repo / "CHANGELOG.md").read_text()
    assert (repo / "VERSION").read_text() == "2.1.0\n"
    assert text.count("## [2.1.0]") == 1 and "## [2.1.0] - 2026-10-03" in text
    assert text.index("## [Unreleased]") < text.index("## [2.1.0] - 2026-10-03") < text.index("## [2.0.0]")
    section = rt.changelog_section(text, "2.1.0")
    # older intro first, newer entries before older ones inside a merged category, KaC order kept
    assert section.index("Second release intro.") < section.index("### Added")
    assert section.index("New thing A.") < section.index("Older thing C.") < section.index("### Fixed")
    assert section.count("### Added") == 1
    assert rt.changelog_section(text, "Unreleased").strip() == ""
    assert "[Unreleased]: https://github.com/example/repo/compare/v2.1.0...HEAD" in text
    assert "[2.1.0]: https://github.com/example/repo/compare/v2.0.0...v2.1.0" in text
    assert "[2.0.0]: https://github.com/example/repo/releases/tag/v2.0.0" in text
    # prints the commands, runs none of them
    assert 'git tag -a v2.1.0 -m "Pasargad CDN v2.1.0"' in p.stdout and "git push origin v2.1.0" in p.stdout
    assert git(repo, "tag").strip() == "" and git(repo, "log", "--oneline").count("\n") == 1
    assert git(repo, "rev-parse", "--abbrev-ref", "HEAD").strip() == "main"


def test_prepare_prerelease_then_final(repo):
    assert prepare(repo, "2.1.0-rc.1", "--date", "2026-10-01").returncode == 0
    text = (repo / "CHANGELOG.md").read_text()
    assert "## [2.1.0-rc.1] - 2026-10-01" in text and "## [2.1.0] - Unreleased" in text
    git(repo, "commit", "-qam", "rc1")
    # an rc.1 -> rc.0 step backwards is refused, the final 2.1.0 > 2.1.0-rc.1 is accepted
    (repo / "CHANGELOG.md").write_text(text.replace("## [Unreleased]\n", "## [Unreleased]\n\n### Fixed\n\n- D.\n", 1))
    git(repo, "commit", "-qam", "entry")
    p = prepare(repo, "2.1.0-rc.0")
    assert p.returncode == 1 and "greater than VERSION" in p.stderr
    assert prepare(repo, "2.1.0", "--date", "2026-10-03").returncode == 0
    assert (repo / "VERSION").read_text() == "2.1.0\n"


@pytest.mark.parametrize("case", ["dirty", "not_greater", "invalid", "empty", "released"])
def test_prepare_refusals(repo, case):
    if case == "dirty":
        (repo / "x.txt").write_text("x")
        p = prepare(repo, "2.1.0")
        assert "not clean" in p.stderr
    elif case == "not_greater":
        p = prepare(repo, "1.9.0")
        assert "greater than VERSION" in p.stderr
    elif case == "invalid":
        p = prepare(repo, "2.1")
        assert "not a SemVer" in p.stderr
    elif case == "empty":
        (repo / "CHANGELOG.md").write_text(FIXTURE_CHANGELOG.replace(
            "### Added\n\n- New thing A.\n\n### Fixed\n\n- Bug B.\n\n", "### Added\n\n", 1))
        git(repo, "commit", "-qam", "empty")
        p = prepare(repo, "2.1.0")
        assert "empty" in p.stderr
    else:
        (repo / "VERSION").write_text("1.0.0\n")
        git(repo, "commit", "-qam", "v")
        p = prepare(repo, "2.0.0")
        assert "already has a released section" in p.stderr
    assert p.returncode in (1, 2)
    assert git(repo, "status", "--porcelain").strip() in ("", "?? x.txt")


def test_prepare_equal_version_only_while_unreleased(repo):
    # VERSION 2.1.0 still documented as "[2.1.0] - Unreleased" (like today's 2.0.0) may be prepared
    (repo / "VERSION").write_text("2.1.0\n")
    git(repo, "commit", "-qam", "v")
    assert prepare(repo, "2.1.0", "--date", "2026-10-03").returncode == 0


def test_changelog_section_script_and_real_changelog(repo):
    p = subprocess.run(["bash", str(REL / "changelog-section.sh"), "v2.0.0"], capture_output=True, text=True,
                       env=dict(os.environ, PCDN_REPO=str(repo)))
    assert p.returncode == 0 and p.stdout.strip() == "### Added\n\n- First release."
    p = subprocess.run(["bash", str(REL / "changelog-section.sh"), "9.9.9"], capture_output=True, text=True,
                       env=dict(os.environ, PCDN_REPO=str(repo)))
    assert p.returncode == 1 and "no section" in p.stderr
    # the repository's own metadata is valid (what CI's release-meta job checks)
    assert rt.check_meta(REPO) == []


# ------------------------------------------------------------------------------------------- bundle

def make_edge(root: pathlib.Path):
    (root / "pcdn_agent" / "__pycache__").mkdir(parents=True)
    (root / "tests").mkdir()
    (root / "install.sh").write_text("#!/bin/sh\necho install\n")
    (root / "install.sh").chmod(0o755)
    (root / "pcdn_agent" / "agent.py").write_text("print('agent')\n")
    (root / "pcdn_agent" / "agent.pyc").write_bytes(b"\0")
    (root / "pcdn_agent" / "__pycache__" / "x.pyc").write_bytes(b"\0")
    (root / "tests" / "test_x.py").write_text("")
    (root / "agent.conf").write_text("EDGE_TOKEN=secret\n")
    (root / "nginx").mkdir()
    (root / "nginx" / "pcdn-base.conf").write_text("events {}\n")


def test_bundle_deterministic_layout_and_sha(tmp_path):
    src = tmp_path / "edge"
    src.mkdir()
    make_edge(src)
    out1, out2 = tmp_path / "a", tmp_path / "b"
    for out in (out1, out2):
        p = subprocess.run(["bash", str(REL / "build-edge-bundle.sh"), "v2.1.0", "--src", str(src), "--out", str(out)],
                           capture_output=True, text=True, env=dict(os.environ, SOURCE_DATE_EPOCH="1700000000"))
        assert p.returncode == 0, p.stderr
        os.utime(src / "install.sh", (1, 1))   # file mtimes on disk must not matter
    name = "pcdn-edge-v2.1.0.tar.gz"
    b1, b2 = (out1 / name).read_bytes(), (out2 / name).read_bytes()
    assert b1 == b2 and b1[4:8] == b"\0\0\0\0"          # gzip header without timestamp (gzip -n)
    sha = (out1 / (name + ".sha256")).read_text()
    assert sha == f"{hashlib.sha256(b1).hexdigest()}  {name}\n"
    assert subprocess.run(["sha256sum", "-c", name + ".sha256"], cwd=out1, capture_output=True).returncode == 0
    with tarfile.open(out1 / name) as tar:
        members = tar.getmembers()
        names = [m.name for m in members]
        assert names == sorted(names)
        assert names == ["edge/RELEASE", "edge/install.sh", "edge/nginx/pcdn-base.conf", "edge/pcdn_agent/agent.py"]
        assert tar.extractfile("edge/RELEASE").read() == b"v2.1.0\n"
        assert all(m.mtime == 1700000000 and m.uid == 0 and m.gid == 0 and not m.uname for m in members)
        modes = {m.name: m.mode for m in members}
        assert modes["edge/install.sh"] == 0o755 and modes["edge/pcdn_agent/agent.py"] == 0o644
    # bad tag is refused
    p = subprocess.run(["bash", str(REL / "build-edge-bundle.sh"), "2.1.0", "--src", str(src), "--out", str(out1)],
                       capture_output=True, text=True)
    assert p.returncode == 2


def test_bundle_exclusions_match_controller_bundle():
    src = (REPO / "controller" / "app" / "bundle.py").read_text()
    for token in ('"__pycache__"', '"tests"', '".git"', '"node_modules"', '(".pyc", ".pyo")', '{"agent.conf"}'):
        assert token in src, token
    assert rt.EXCLUDE_DIRS >= {"__pycache__", "tests", ".git", ".pytest_cache", ".mypy_cache", "node_modules"}
    assert rt.EXCLUDE_NAMES == {"agent.conf"} and rt.EXCLUDE_SUFFIXES == (".pyc", ".pyo")


def test_bundle_from_tag(repo, tmp_path):
    make_edge(repo / "edge")
    (repo / "edge" / "agent.conf").unlink()
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "edge")
    git(repo, "tag", "v2.1.0")
    # a copy of the release scripts inside the fixture repo, so --from-tag reads that repo
    shutil.copytree(REL, repo / "tools" / "release", ignore=shutil.ignore_patterns("tests", "__pycache__"))
    p = subprocess.run(["bash", str(repo / "tools/release/build-edge-bundle.sh"), "v2.1.0", "--from-tag",
                        "--out", str(tmp_path / "d")], capture_output=True, text=True)
    assert p.returncode == 0, p.stderr
    with tarfile.open(tmp_path / "d" / "pcdn-edge-v2.1.0.tar.gz") as tar:
        ct = int(git(repo, "log", "-1", "--format=%ct", "v2.1.0").strip())
        assert {m.mtime for m in tar.getmembers()} == {ct}
        assert "edge/RELEASE" in tar.getnames() and "edge/tests/test_x.py" not in tar.getnames()


# ------------------------------------------------------------------------------------------- fetch

@pytest.fixture
def file_server(tmp_path):
    root = tmp_path / "srv"
    root.mkdir()
    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(root))
    handler.log_message = lambda *a: None
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield root, f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


def fetch(*args):
    return subprocess.run(["bash", str(REL / "fetch-edge-release.sh"), *args], capture_output=True, text=True)


def test_fetch_edge_release(tmp_path, file_server):
    root, url = file_server
    name = "pcdn-edge-v2.1.0.tar.gz"
    data = b"tarball-bytes"
    (root / name).write_bytes(data)
    (root / (name + ".sha256")).write_text(f"{hashlib.sha256(data).hexdigest()}  {name}\n")
    dest = tmp_path / "releases"
    p = fetch("v2.1.0", "--dir", str(dest), "--base-url", url)
    assert p.returncode == 0, p.stderr
    assert (dest / name).read_bytes() == data and (dest / (name + ".sha256")).is_file()
    assert oct((dest / name).stat().st_mode & 0o777) == "0o644"
    # same content again: ok, untouched
    p = fetch("v2.1.0", "--dir", str(dest), "--base-url", url)
    assert p.returncode == 0 and "already present" in p.stdout
    # a different existing file is never replaced
    (dest / name).write_bytes(b"other")
    p = fetch("v2.1.0", "--dir", str(dest), "--base-url", url)
    assert p.returncode == 1 and "refusing" in p.stderr and (dest / name).read_bytes() == b"other"
    # checksum mismatch: nothing installed
    (root / name).write_bytes(b"tampered")
    dest2 = tmp_path / "r2"
    p = fetch("v2.1.0", "--dir", str(dest2), "--base-url", url)
    assert p.returncode == 1 and "mismatch" in p.stderr and not (dest2 / name).exists()
    # plain http to a non-loopback host and bad tags are refused
    assert fetch("v2.1.0", "--dir", str(dest2), "--base-url", "http://example.com/x").returncode == 2
    assert fetch("2.1.0", "--dir", str(dest2)).returncode == 2


# ------------------------------------------------------------------------------------------- staging-verify

ADMIN_KEY = "staging-admin-key-0123456789abcdefXYZ"


class FakeController:
    """GET /healthz, /healthz/deep, /api/v1/edges, /api/v1/backups; POST backups run/verify, rollouts."""

    def __init__(self, environment="staging", version="2.1.0", revision=None, blocked=False, verify_level="full"):
        self.environment, self.version, self.blocked, self.verify_level = environment, version, blocked, verify_level
        self.revision = revision if revision is not None else sv.head_revision(REPO)
        self.runs = {"backup": None, "verify": None}
        self.next_id = 1
        self.auth = []
        fake = self

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def reply(self, status, body):
                raw = json.dumps(body).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def do_GET(self):
                fake.auth.append((self.path, self.headers.get("Authorization")))
                if self.path == "/healthz":
                    return self.reply(200, {"ok": True, "version": fake.version})
                if self.path == "/healthz/deep":
                    return self.reply(200, {"status": "ok", "environment": fake.environment, "version": fake.version,
                                            "database": {"ok": True, "revision": fake.revision}})
                if self.headers.get("Authorization") != "Bearer " + ADMIN_KEY:
                    return self.reply(401, {"detail": "unauthorized"})
                if self.path == "/api/v1/edges":
                    return self.reply(200, [
                        {"id": 1, "name": "edge-1", "enabled": True, "release": "v2.1.0"},
                        {"id": 2, "name": "edge-2", "enabled": True, "release": "v2.0.0"},
                        {"id": 3, "name": "off", "enabled": False, "release": None}])
                if self.path == "/api/v1/backups":
                    return self.reply(200, {"enabled": True, "last_backup": fake.runs["backup"],
                                            "last_verify": fake.runs["verify"], "runs": []})
                return self.reply(404, {"detail": "Not Found"})

            def do_POST(self):
                n = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(n) or b"null")
                if self.headers.get("Authorization") != "Bearer " + ADMIN_KEY:
                    return self.reply(401, {"detail": "unauthorized"})
                if self.path in ("/api/v1/backups/run", "/api/v1/backups/verify"):
                    kind = "backup" if self.path.endswith("run") else "verify"
                    fake.runs[kind] = {"id": fake.next_id, "kind": kind, "ok": True, "finished_at": "2026-10-03T00:00:00Z",
                                       "location": "both", "level": fake.verify_level if kind == "verify" else None}
                    fake.next_id += 1
                    return self.reply(202, {"queued": True})
                if self.path == "/api/v1/rollouts":
                    assert body == {"release": "v2.1.0", "dry_run": True}
                    state = "blocked" if fake.blocked else "pending"
                    return self.reply(200, {"dry_run": True, "rings": [
                        {"ring": 0, "edges": [{"id": 2, "name": "edge-2", "state": state}]}]})
                return self.reply(404, {"detail": "Not Found"})

        self.srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.srv.server_address[1]}"

    def __enter__(self):
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        return self

    def __exit__(self, *exc):
        self.srv.shutdown()


@pytest.fixture
def gate_repo(tmp_path):
    """A minimal repo copy: VERSION 2.1.0 + the controller migrations (for the head revision)."""
    r = tmp_path / "gate"
    shutil.copytree(REPO / "controller" / "migrations" / "versions", r / "controller" / "migrations" / "versions",
                    ignore=shutil.ignore_patterns("__pycache__"))
    (r / "VERSION").write_text("2.1.0\n")
    env = r / "staging.env"
    env.write_text(f"# staging gate\nPCDN_ADMIN_KEY='{ADMIN_KEY}'\nSTAGING_EDGE_TARGET=127.0.0.1:1\n"
                   "STAGING_LOADTEST_HOST=lt.test\n")
    return r


def stub(tmp_path, name, code=0, out=""):
    p = tmp_path / name
    p.write_text(f"#!/bin/sh\necho '{out}'\nenv | grep -q '^PCDN_ADMIN_KEY=' || exit 9\nexit {code}\n")
    p.chmod(0o755)
    return str(p)


def gate(gate_repo, ctl, tmp_path, *extra, env=None, preflight_json=None, signed=True):
    pf = tmp_path / "pf.sh"
    summary = preflight_json or {"checks": [], "summary": {"ok": 5, "warn": 0, "fail": 0, "skip": 0}, "exit_code": 0}
    pf.write_text("#!/bin/sh\ncat <<'J'\n" + json.dumps(summary, indent=1) + "\nJ\n")
    pf.chmod(0o755)
    lt = tmp_path / "lt.py"
    lt.write_text("import sys, json\na = sys.argv[1:]\nout = a[a.index('--out') + 1]\n"
                  "json.dump({'thresholds': {'pass': True, 'error_pct': 0.0, 'p99_ms': 12.0}}, open(out, 'w'))\n")
    out = tmp_path / "evidence"
    if signed:
        (out / "v2.1.0").mkdir(parents=True, exist_ok=True)
        (out / "v2.1.0" / "security-signoff.md").write_text("# sign-off\nSigned: Reviewer R\n")
    args = ["--env-file", str(gate_repo / "staging.env"), "--controller", ctl.url, "--repo", str(gate_repo),
            "--out", str(out), "--poll-interval", "0.01", "--backup-timeout", "5",
            "--preflight-cmd", str(pf), "--integration-cmd", stub(tmp_path, "it.sh"),
            "--loadtest-cmd", f"{sys.executable} {lt}", "--security-cmd", stub(tmp_path, "sec.sh"), *extra]
    p = subprocess.run([sys.executable, str(REL / "staging_verify.py"), *args], capture_output=True, text=True,
                       env=dict(os.environ, **(env or {})))
    return p, out / "v2.1.0"


def test_staging_verify_pass_and_evidence(gate_repo, tmp_path):
    with FakeController() as ctl:
        p, ev = gate(gate_repo, ctl, tmp_path)
    assert p.returncode == 0, p.stdout + p.stderr
    rep = json.loads((ev / "report.json").read_text())
    assert rep["result"] == "PASS" and [s["step"] for s in rep["steps"]] == list(sv.STEPS)
    assert all(s["status"] == "PASS" for s in rep["steps"])
    version = rep["steps"][0]
    assert version["data"]["pending_rollout"] == ["edge-2 (v2.0.0)"] and "pending rollout" in version["detail"]
    assert "| backup | PASS |" in (ev / "report.md").read_text()
    for f in ("healthz-deep.json", "edges.json", "rollout-dry-run.json", "integration.txt", "preflight.txt"):
        assert (ev / "raw" / f).is_file(), f
    # the admin key only travels to /api/ and never lands in the evidence or the output
    assert all((auth is not None) == path.startswith("/api/") for path, auth in ctl.auth)
    blob = p.stdout + p.stderr + "".join(f.read_text() for f in ev.rglob("*") if f.is_file())
    assert ADMIN_KEY not in blob


def test_staging_verify_refuses_production(gate_repo, tmp_path):
    with FakeController(environment="production") as ctl:
        p, ev = gate(gate_repo, ctl, tmp_path)
    assert p.returncode == 2 and "production" in p.stderr and not (ev / "report.json").exists()
    with FakeController() as ctl:
        listed = ctl.url.replace("127.0.0.1", "127.0.0.1") + "/"
        p, _ = gate(gate_repo, ctl, tmp_path, env={"PCDN_PROD_CONTROLLERS": f"https://prod.example, {listed}"})
        assert p.returncode == 2 and "PCDN_PROD_CONTROLLERS" in p.stderr
        assert not any(path.startswith("/api/") for path, _ in ctl.auth)   # nothing touched


def test_staging_verify_partial_and_failures(gate_repo, tmp_path):
    with FakeController() as ctl:
        p, ev = gate(gate_repo, ctl, tmp_path, "--skip-integration", "--skip-loadtest")
    assert p.returncode == 3
    rep = json.loads((ev / "report.json").read_text())
    assert rep["result"] == "PARTIAL" and {s["step"]: s["status"] for s in rep["steps"]}["loadtest"] == "SKIP"

    shutil.rmtree(tmp_path / "evidence")
    with FakeController(version="2.0.9", blocked=True, verify_level="partial", revision="0001") as ctl:
        warn = {"checks": [], "summary": {"ok": 4, "warn": 1, "fail": 0, "skip": 0}, "exit_code": 1}
        p, ev = gate(gate_repo, ctl, tmp_path, preflight_json=warn, signed=False)
    assert p.returncode == 1
    st = {s["step"]: s for s in json.loads((ev / "report.json").read_text())["steps"]}
    assert st["version"]["status"] == "FAIL" and "2.0.9" in st["version"]["detail"]
    assert st["preflight"]["status"] == "FAIL"
    assert st["migrations"]["status"] == "FAIL"
    assert st["backup"]["status"] == "FAIL" and "level=partial" in st["backup"]["detail"]
    assert st["rollout"]["status"] == "FAIL" and "edge-2" in st["rollout"]["detail"]
    assert st["security"]["status"] == "FAIL" and "security-signoff.md" in st["security"]["detail"]


def test_staging_verify_requires_loadtest_target(gate_repo, tmp_path):
    (gate_repo / "staging.env").write_text(f"PCDN_ADMIN_KEY={ADMIN_KEY}\n")
    p = subprocess.run([sys.executable, str(REL / "staging_verify.py"), "--env-file", str(gate_repo / "staging.env"),
                        "--controller", "http://127.0.0.1:9"], capture_output=True, text=True)
    assert p.returncode == 2 and "--edge-target" in p.stderr


def test_env_file_and_url_normalisation(tmp_path):
    f = tmp_path / "e.env"
    f.write_text("# c\nexport A=1\nB=\"two words\"\nbad line\nC='x=y'\n")
    assert sv.parse_env_file(str(f)) == {"A": "1", "B": "two words", "C": "x=y"}
    assert sv.norm_url("HTTPS://Api.Example.com/") == sv.norm_url("https://api.example.com:443")


# ------------------------------------------------------------------------------------------- security-check

def test_secret_regexes_on_fixtures():
    real_edge = "edge_" + "9f2c4e1a7b3d5f60c81e2a4d97b05f3e"
    fixtures = {
        "private_key": "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAu1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV6ffAt0gun\n",
        "edge_token": f"EDGE_TOKEN={real_edge}",
        "customer_api_key": "key = 'pcdn_" + "3e7a91c04b5d2f86" * 2 + "7c1e0a9d'",
        "join_token": "PCDN_JOIN_TOKEN=jt_" + "8d1f3b7a2c9e4f60" * 2 + "5a7c3e1b",
        "aws_access_key": "aws_access_key_id = AKIAQ7XR4MZB2KPL9TWN",  # secret-scan: allow (test fixture)
        "bot_token": "TELEGRAM_BOT_TOKEN=7123456890:AAGx9fQkLm2Rz8TbWcVnHs4YpJd6Ue1oPiA",  # secret-scan: allow (test fixture)
        "arvan_apikey": "Authorization: Apikey 5c1d7f2a-93be-4e08-b6a1-7d3f9e2c4b8a",  # secret-scan: allow (test fixture)
    }
    for kind, text in fixtures.items():
        found = rt.scan_text(text, "f")
        assert [f["kind"] for f in found] == [kind], (kind, found)
        assert all(len(f["match"]) <= 13 for f in found)       # never echo a full secret
    clean = [
        "const testKey = \"pcdn_0123456789abcdef0123456789abcdef01234567\"",      # periodic placeholder
        "api_key = \"pcdn_ffffffffffffffffffffffffffffffffffffffff\"",
        "placeholder: '-----BEGIN PRIVATE KEY-----'",                            # marker without a key body
        "if (!/-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(key))",
        "EDGE_TOKEN=edge_9f2c4e1a7b3d5f60c81e2a4d97b05f3e  # secret-scan: allow",
        "AKIAIOSFODNN7EXAMPLE",
    ]
    for text in clean:
        assert rt.scan_text(text, "f") == [], text


def test_forbidden_files_and_hard_constraint(repo):
    (repo / "deploy").mkdir()
    (repo / "deploy" / ".env.example").write_text("A=1\n")
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "ok")
    assert rt.forbidden_tracked(repo) == []
    for bad in (".env", "edge/agent.conf", "certs/server.pem", "deploy/.env.prod"):
        (repo / bad).parent.mkdir(parents=True, exist_ok=True)
        (repo / bad).write_text("x")
    git(repo, "add", "-A", "-f")
    assert sorted(rt.forbidden_tracked(repo)) == [".env", "certs/server.pem", "deploy/.env.prod", "edge/agent.conf"]

    app = repo / "controller" / "app"
    app.mkdir(parents=True)
    (app / "dnsbuild.py").write_text("from . import models, services\nimport json\n")
    (app / "rollout.py").write_text("from .services import edge_pools\n")
    assert rt.hard_constraint(repo) == []
    (app / "dnsbuild.py").write_text("from . import rum\n")
    (app / "provisioning.py").write_text("from .rum import report\nNAMES = 'data/isp_names.json'\n")
    problems = rt.hard_constraint(repo)
    assert len(problems) == 3 and any("dnsbuild.py:1" in p for p in problems)
    # the real controller passes
    assert rt.hard_constraint(REPO) == []


def test_security_check_script(repo, tmp_path):
    (repo / "x.py").write_text("TOKEN = 'edge_9f2c4e1a7b3d5f60c81e2a4d97b05f3e'\n")  # secret-scan: allow (test fixture)
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "leak")
    env = dict(os.environ, PATH="/usr/bin:/bin")   # no gitleaks / pip-audit / bandit -> SKIP rows
    p = subprocess.run(["bash", str(REL / "security-check.sh"), "--repo", str(repo)], capture_output=True, text=True,
                       env=env)
    assert p.returncode == 1 and "secrets          FAIL" in p.stdout and "x.py:1" in p.stdout
    assert "9f2c4e1a7b3d5f60c81e" not in p.stdout
    assert "Security sign-off — Pasargad CDN v2.0.0" in p.stdout
    (repo / "x.py").write_text("ok = 1\n")
    git(repo, "commit", "-qam", "fix")
    git(repo, "tag", "v2.0.0", "HEAD~1")   # previous tag -> only later changes are scanned
    p = subprocess.run(["bash", str(REL / "security-check.sh"), "--repo", str(repo)], capture_output=True, text=True,
                       env=env)
    assert p.returncode == 0, p.stdout
    assert "changes since v2.0.0" in p.stdout and "pip-audit        SKIP" in p.stdout
    p = subprocess.run(["bash", str(REL / "security-check.sh"), "--template-only"], capture_output=True, text=True)
    assert p.returncode == 0 and "Signed: <name>" in p.stdout
