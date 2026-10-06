#!/usr/bin/env python3
"""Pasargad CDN staging verification gate (SPEC §23.1) — Python 3 standard library only.

Runs the release checklist against a STAGING controller and writes the evidence to
<out>/vX.Y.Z/ (report.md, report.json, raw/ outputs). Called by tools/release/staging-verify.sh.

  step              pass when
  version           GET /healthz version == VERSION; every enabled node's release == vVERSION
                    (others are listed as pending rollout)
  preflight         tools/preflight/preflight.py --strict --json: no FAIL and no WARN
  migrations        /healthz/deep database.revision == head of controller/migrations/versions
  integration       deploy/staging/staging.sh test exits 0
  loadtest          pcdn-loadtest http (120 s, --max-error-pct 0.5 --max-p99-ms 1500) and ws (60 s,
                    --max-error-pct 0.5) against --edge-target exit 0
  backup            POST /api/v1/backups/run + /verify, poll GET /api/v1/backups: both ok, verify level full
  rollout           POST /api/v1/rollouts {"release", "dry_run": true}: 200 and no blocked edge
  security          tools/release/security-check.sh exits 0 and <out>/vX.Y.Z/security-signoff.md is signed

Exit codes: 0 PASS, 1 FAIL, 2 refused (production controller / bad usage), 3 PARTIAL (a step skipped).
It refuses — without any override — a controller listed in PCDN_PROD_CONTROLLERS (comma list, from the
environment or the env file) or whose /healthz/deep reports "environment": "production".
The admin key is read only from the env file / environment (PCDN_ADMIN_KEY) and never printed.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
PASS, FAIL, SKIP = "PASS", "FAIL", "SKIP"
EXIT_PASS, EXIT_FAIL, EXIT_REFUSED, EXIT_PARTIAL = 0, 1, 2, 3
STEPS = ("version", "preflight", "migrations", "integration", "loadtest", "backup", "rollout", "security")
KEY_ENV = "PCDN_ADMIN_KEY"
UA = "pcdn-staging-verify/1.0"


class Refused(Exception):
    pass


def parse_env_file(path: str | None) -> dict:
    env: dict[str, str] = {}
    if not path:
        return env
    for raw in Path(path).read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].strip()
        if "=" not in line:
            continue
        k, v = line.split("=", 1)
        k, v = k.strip(), v.strip()
        if len(v) >= 2 and v[0] == v[-1] and v[0] in "'\"":
            v = v[1:-1]
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", k):
            env[k] = v
    return env


def norm_url(u: str) -> str:
    p = urllib.parse.urlsplit(u.strip())
    host = (p.hostname or "").lower()
    port = p.port or (443 if p.scheme == "https" else 80)
    return f"{p.scheme.lower()}://{host}:{port}{p.path.rstrip('/')}"


def head_revision(repo: Path) -> str | None:
    revs, downs = set(), set()
    for f in (repo / "controller" / "migrations" / "versions").glob("*.py"):
        text = f.read_text(encoding="utf-8", errors="replace")
        m = re.search(r'^revision\s*(?::[^=]*)?=\s*["\']([^"\']+)["\']', text, re.M)
        if m:
            revs.add(m.group(1))
        for d in re.findall(r'^down_revision\s*(?::[^=]*)?=\s*(.+)$', text, re.M):
            downs.update(re.findall(r'["\']([^"\']+)["\']', d))
    heads = sorted(revs - downs)
    return heads[-1] if heads else None


class Api:
    def __init__(self, base: str, key: str | None, timeout: float, ca_file: str | None):
        self.base = base.rstrip("/")
        self.key = key
        self.timeout = timeout
        self.ctx = ssl.create_default_context(cafile=ca_file) if ca_file else None

    def call(self, method: str, path: str, body=None) -> tuple[int, object]:
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base + path, data=data, method=method)
        req.add_header("User-Agent", UA)
        req.add_header("Accept", "application/json")
        if data is not None:
            req.add_header("Content-Type", "application/json")
        if path.startswith("/api/") and self.key:
            req.add_header("Authorization", "Bearer " + self.key)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=self.ctx) as r:
                status, raw = r.status, r.read()
        except urllib.error.HTTPError as e:
            status, raw = e.code, e.read()
        try:
            return status, json.loads(raw.decode() or "null")
        except ValueError:
            return status, raw.decode("utf-8", "replace")[:500]


class Gate:
    def __init__(self, a, env: dict):
        self.a = a
        self.env = env
        self.key = env.get(KEY_ENV) or os.environ.get(KEY_ENV) or None
        self.repo = Path(a.repo).resolve()
        self.version = (self.repo / "VERSION").read_text(encoding="utf-8").splitlines()[0].strip()
        self.tag = "v" + self.version
        self.out = Path(a.out or (self.repo / "release-evidence")).resolve() / self.tag
        self.raw = self.out / "raw"
        self.api = Api(a.controller, self.key, a.timeout, a.ca_file)
        self.results: list[dict] = []
        self.deep: dict = {}

    # ---------------------------------------------------------------- helpers
    def redact(self, text: str) -> str:
        return text.replace(self.key, "***") if self.key and len(self.key) >= 4 else text

    def save(self, name: str, content) -> str:
        self.raw.mkdir(parents=True, exist_ok=True)
        text = content if isinstance(content, str) else json.dumps(content, ensure_ascii=False, indent=2)
        (self.raw / name).write_text(self.redact(text), encoding="utf-8")
        return f"raw/{name}"

    def add(self, step: str, status: str, detail: str, **data):
        self.results.append({"step": step, "status": status, "detail": self.redact(detail), **data})
        print(f"{step:<12} {status:<5} {self.redact(detail)}", flush=True)

    def run_cmd(self, cmd: list[str], name: str, extra_env: dict | None = None, timeout=None) -> int:
        env = dict(os.environ)
        if self.key:
            env[KEY_ENV] = self.key
        env.update(extra_env or {})
        try:
            p = subprocess.run(cmd, cwd=self.repo, env=env, capture_output=True, text=True, timeout=timeout)
            rc, out = p.returncode, (p.stdout or "") + ("\n--- stderr ---\n" + p.stderr if p.stderr else "")
        except FileNotFoundError as e:
            rc, out = 127, str(e)
        except subprocess.TimeoutExpired:
            rc, out = 124, f"timed out after {timeout} s"
        self.save(name, f"$ {' '.join(map(shlex.quote, cmd))}\n(exit {rc})\n\n{out}")
        return rc

    def skipped(self, step: str) -> bool:
        if step in self.a.skip:
            self.add(step, SKIP, f"--skip-{step}")
            return True
        return False

    # ---------------------------------------------------------------- production guard
    def guard(self):
        prod = ",".join(filter(None, [os.environ.get("PCDN_PROD_CONTROLLERS", ""),
                                       self.env.get("PCDN_PROD_CONTROLLERS", "")]))
        mine = norm_url(self.a.controller)
        for u in (x for x in prod.split(",") if x.strip()):
            if norm_url(u) == mine:
                raise Refused(f"{self.a.controller} is listed in PCDN_PROD_CONTROLLERS: the staging gate never "
                              "runs against production")
        try:
            status, deep = self.api.call("GET", "/healthz/deep")
        except (urllib.error.URLError, OSError) as e:
            raise Refused(f"cannot reach {self.a.controller}/healthz/deep ({e}); refusing to run without knowing "
                          "the environment")
        if not isinstance(deep, dict):
            raise Refused(f"/healthz/deep answered {status} without JSON; refusing")
        self.deep = deep
        self.save("healthz-deep.json", deep)
        if str(deep.get("environment", "")).strip().lower() == "production":
            raise Refused(f"{self.a.controller} reports environment=production: the staging gate never runs "
                          "against production")

    # ---------------------------------------------------------------- steps
    def step_version(self):
        status, hz = self.api.call("GET", "/healthz")
        self.save("healthz.json", hz)
        cv = hz.get("version") if isinstance(hz, dict) else None
        st, es = self.api.call("GET", "/api/v1/edges")
        self.save("edges.json", es)
        if st != 200:
            return self.add("version", FAIL, f"GET /api/v1/edges -> {st} (is {KEY_ENV} set in the env file?)")
        edges = es if isinstance(es, list) else (es.get("edges") or es.get("items") or []) if isinstance(es, dict) else []
        enabled = [e for e in edges if isinstance(e, dict) and e.get("enabled", True)]
        on = [e.get("name") for e in enabled if e.get("release") == self.tag]
        pending = [f"{e.get('name')} ({e.get('release') or 'unknown'})" for e in enabled if e.get("release") != self.tag]
        data = {"controller": cv, "expected": self.version, "nodes_on_release": on, "pending_rollout": pending}
        if cv != self.version:
            return self.add("version", FAIL, f"controller reports {cv!r}, VERSION is {self.version}", data=data)
        detail = f"controller {cv}; {len(on)}/{len(enabled)} node(s) on {self.tag}"
        if pending:
            detail += "; pending rollout: " + ", ".join(pending)
        self.add("version", PASS, detail, data=data)

    def step_preflight(self):
        if self.skipped("preflight"):
            return
        cmd = shlex.split(self.a.preflight_cmd) if self.a.preflight_cmd else \
            [sys.executable, str(self.repo / "tools" / "preflight" / "preflight.py")]
        cmd += ["--controller", self.a.controller, "--strict", "--json"]
        for ns in self.a.ns:
            cmd += ["--ns", ns]
        if self.a.ca_file:
            cmd += ["--ca-file", self.a.ca_file]
        rc = self.run_cmd(cmd, "preflight.txt", timeout=600)
        text = (self.raw / "preflight.txt").read_text(encoding="utf-8")
        summary = {}
        m = re.search(r"^\{.*^\}", text, re.M | re.S)
        if m:
            try:
                summary = json.loads(m.group(0)).get("summary", {})
            except ValueError:
                summary = {}
        ok = rc == 0 and not summary.get("fail") and not summary.get("warn")
        self.add("preflight", PASS if ok else FAIL, f"exit {rc} summary {summary or 'n/a'}", raw="raw/preflight.txt")

    def step_migrations(self):
        db = self.deep.get("database") or {}
        head = head_revision(self.repo)
        rev = db.get("revision")
        data = {"revision": rev, "code_head": head}
        if head and rev == head:
            self.add("migrations", PASS, f"database at {rev} = code head", data=data)
        else:
            self.add("migrations", FAIL, f"database revision {rev!r} != code head {head!r}", data=data)

    def step_integration(self):
        if self.skipped("integration"):
            return
        cmd = shlex.split(self.a.integration_cmd) if self.a.integration_cmd else \
            [str(self.repo / "deploy" / "staging" / "staging.sh"), "test"]
        rc = self.run_cmd(cmd, "integration.txt", timeout=3600)
        self.add("integration", PASS if rc == 0 else FAIL, f"{' '.join(cmd[-2:])} exit {rc}", raw="raw/integration.txt")

    def step_loadtest(self):
        if self.skipped("loadtest"):
            return
        a = self.a
        lt = shlex.split(a.loadtest_cmd) if a.loadtest_cmd else [str(self.repo / "tools" / "loadtest" / "pcdn-loadtest")]
        base = ["--target", a.edge_target, "--host", a.loadtest_host, "--quiet", *a.loadtest_arg]
        self.raw.mkdir(parents=True, exist_ok=True)
        runs = [("http", ["http", *base, "--duration", str(a.http_duration), "--max-error-pct", str(a.max_error_pct),
                          "--max-p99-ms", str(a.max_p99_ms), "--out", str(self.raw / "loadtest-http.json")]),
                ("ws", ["ws", *base, "--duration", str(a.ws_duration), "--max-error-pct", str(a.max_error_pct),
                        "--out", str(self.raw / "loadtest-ws.json")])]
        fails, notes = [], []
        for name, args in runs:
            rc = self.run_cmd(lt + args, f"loadtest-{name}.txt", timeout=a.http_duration + a.ws_duration + 600)
            th = {}
            try:
                th = json.loads((self.raw / f"loadtest-{name}.json").read_text()).get("thresholds") or {}
            except (OSError, ValueError):
                pass
            notes.append(f"{name}: exit {rc} err {th.get('error_pct')}% p99 {th.get('p99_ms')} ms")
            if rc != 0:
                fails.append(name)
        thresholds = {"max_error_pct": a.max_error_pct, "max_p99_ms_http": a.max_p99_ms}
        self.add("loadtest", FAIL if fails else PASS, "; ".join(notes), thresholds=thresholds)

    def _wait_run(self, kind: str, before_id) -> dict | None:
        deadline = time.monotonic() + self.a.backup_timeout
        key = "last_backup" if kind == "backup" else "last_verify"
        while time.monotonic() < deadline:
            st, body = self.api.call("GET", "/api/v1/backups")
            if st == 200 and isinstance(body, dict):
                run = body.get(key)
                if isinstance(run, dict) and run.get("id") != before_id and run.get("finished_at"):
                    self.save(f"backups-after-{kind}.json", body)
                    return run
            time.sleep(self.a.poll_interval)
        return None

    def step_backup(self):
        if self.skipped("backup"):
            return
        st, body = self.api.call("GET", "/api/v1/backups")
        self.save("backups-before.json", body)
        if st != 200 or not isinstance(body, dict):
            return self.add("backup", FAIL, f"GET /api/v1/backups -> {st}")
        runs = {}
        for kind, path in (("backup", "/api/v1/backups/run"), ("verify", "/api/v1/backups/verify")):
            prev = (body.get("last_backup" if kind == "backup" else "last_verify") or {}).get("id")
            st, ans = self.api.call("POST", path)
            if st not in (200, 202, 409):
                return self.add("backup", FAIL, f"POST {path} -> {st} {ans}")
            run = self._wait_run(kind, prev)
            if run is None:
                return self.add("backup", FAIL, f"{kind} did not finish within {self.a.backup_timeout} s")
            runs[kind] = run
            if kind == "backup":
                st, body = self.api.call("GET", "/api/v1/backups")
                body = body if isinstance(body, dict) else {}
        b, v = runs["backup"], runs["verify"]
        ok = b.get("ok") is True and v.get("ok") is True and v.get("level") == "full"
        detail = (f"backup ok={b.get('ok')} location={b.get('location')}; verify ok={v.get('ok')} "
                  f"level={v.get('level')}" + (f" error={v.get('error') or b.get('error')}" if not ok else ""))
        self.add("backup", PASS if ok else FAIL, detail, runs=runs)

    def step_rollout(self):
        if self.skipped("rollout"):
            return
        st, body = self.api.call("POST", "/api/v1/rollouts", {"release": self.tag, "dry_run": True})
        self.save("rollout-dry-run.json", body)
        if st != 200 or not isinstance(body, dict):
            detail = body.get("detail") if isinstance(body, dict) else body
            return self.add("rollout", FAIL, f"dry run -> {st} {detail}")
        blocked = [e.get("name") for r in body.get("rings") or [] for e in r.get("edges") or []
                   if e.get("state") == "blocked"]
        n = sum(len(r.get("edges") or []) for r in body.get("rings") or [])
        if blocked:
            self.add("rollout", FAIL, f"dry run: blocked edge(s) {', '.join(map(str, blocked))}")
        else:
            self.add("rollout", PASS, f"dry run: {len(body.get('rings') or [])} ring(s), {n} edge(s), none blocked")

    def step_security(self):
        if self.skipped("security"):
            return
        cmd = shlex.split(self.a.security_cmd) if self.a.security_cmd else \
            [str(self.repo / "tools" / "release" / "security-check.sh")]
        rc = self.run_cmd(cmd, "security-check.txt", timeout=1800)
        signoff = self.out / "security-signoff.md"
        signed = signoff.is_file() and not re.search(r"^Signed:\s*<name>\s*$", signoff.read_text(encoding="utf-8"), re.M)
        if rc == 0 and signed:
            self.add("security", PASS, "security-check.sh exit 0; sign-off present", raw="raw/security-check.txt")
        else:
            why = [] if rc == 0 else [f"security-check.sh exit {rc}"]
            if not signed:
                why.append(f"missing or unsigned {signoff} (template: tools/release/security-check.sh --template-only)")
            self.add("security", FAIL, "; ".join(why), raw="raw/security-check.txt")

    # ---------------------------------------------------------------- report
    def run(self) -> int:
        self.out.mkdir(parents=True, exist_ok=True)
        default_root = (self.repo / "release-evidence").resolve()
        if self.out.parent == default_root and not (default_root / ".gitignore").exists():
            (default_root / ".gitignore").write_text("# release evidence is never committed\n*\n", encoding="utf-8")
        started = datetime.now(timezone.utc).isoformat(timespec="seconds")
        self.guard()
        for step in STEPS:
            try:
                getattr(self, f"step_{step}")()
            except (urllib.error.URLError, OSError, ValueError) as e:
                self.add(step, FAIL, f"error: {e}")
        statuses = {r["status"] for r in self.results}
        result = "FAIL" if FAIL in statuses else ("PARTIAL" if SKIP in statuses else "PASS")
        code = {"PASS": EXIT_PASS, "FAIL": EXIT_FAIL, "PARTIAL": EXIT_PARTIAL}[result]
        try:
            commit = subprocess.run(["git", "-C", str(self.repo), "rev-parse", "HEAD"], capture_output=True,
                                    text=True).stdout.strip() or None
        except OSError:
            commit = None
        report = {"tool": "staging-verify", "release": self.tag, "version": self.version, "commit": commit,
                  "controller": self.a.controller, "started_at": started,
                  "finished_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                  "result": result, "exit_code": code, "steps": self.results}
        (self.out / "report.json").write_text(self.redact(json.dumps(report, ensure_ascii=False, indent=2)) + "\n",
                                              encoding="utf-8")
        md = [f"# Staging verification — Pasargad CDN {self.tag}", "",
              f"- Result: **{result}** (exit {code})", f"- Controller: `{self.a.controller}`",
              f"- Commit: `{commit or 'unknown'}`", f"- Run: {started} → {report['finished_at']}", "",
              "| step | status | detail |", "|---|---|---|"]
        for r in self.results:
            md.append(f"| {r['step']} | {r['status']} | {r['detail'].replace('|', '/')} |")
        md += ["", "Raw outputs: `raw/`. Merge / tag / publish still need the repository owner's explicit "
               "confirmation (docs/RELEASE.md).", ""]
        (self.out / "report.md").write_text(self.redact("\n".join(md)), encoding="utf-8")
        print(f"\nresult: {result} — evidence in {self.out}")
        return code


def parse_args(argv):
    p = argparse.ArgumentParser(prog="staging-verify.sh", description="Pasargad CDN staging gate (SPEC §23.1)")
    p.add_argument("--env-file", required=True, help="KEY=VALUE file with PCDN_ADMIN_KEY (never put the key on argv)")
    p.add_argument("--controller", help="staging controller URL (default: PCDN_CONTROLLER_URL of the env file)")
    p.add_argument("--ns", action="append", default=[], metavar="HOST[:PORT]", help="nameserver for preflight")
    p.add_argument("--edge-target", help="IP:port of the staging edge for the load test (env STAGING_EDGE_TARGET)")
    p.add_argument("--loadtest-host", help="Host/SNI of a staging test site (env STAGING_LOADTEST_HOST)")
    p.add_argument("--loadtest-arg", action="append", default=[], metavar="ARG",
                   help="extra pcdn-loadtest argument, e.g. --loadtest-arg=--insecure (repeatable)")
    p.add_argument("--max-error-pct", type=float, default=0.5, help="load test error threshold in %% (0.5)")
    p.add_argument("--max-p99-ms", type=float, default=1500.0, help="http load test p99 threshold (1500)")
    p.add_argument("--http-duration", type=float, default=120.0, help="http load test seconds (120)")
    p.add_argument("--ws-duration", type=float, default=60.0, help="ws load test seconds (60)")
    p.add_argument("--backup-timeout", type=float, default=1800.0, help="seconds to wait for each backup run")
    p.add_argument("--poll-interval", type=float, default=10.0, help="backup polling interval (10 s)")
    p.add_argument("--timeout", type=float, default=30.0, help="HTTP timeout (30 s)")
    p.add_argument("--ca-file", help="CA bundle (PEM) for a staging controller with a private CA")
    p.add_argument("--out", help="evidence root (default <repo>/release-evidence; git-ignored)")
    p.add_argument("--repo", default=str(REPO), help=argparse.SUPPRESS)
    for step in STEPS[1:]:
        if step == "migrations":
            continue
        p.add_argument(f"--skip-{step}", dest="skip", action="append_const", const=step,
                       help=f"skip the {step} step (result PARTIAL, exit 3)")
    for name in ("preflight", "integration", "loadtest", "security"):
        p.add_argument(f"--{name}-cmd", help=f"command replacing the default {name} tool (custom setups / tests)")
    a = p.parse_args(argv)
    a.skip = a.skip or []
    return p, a


def main(argv=None) -> int:
    p, a = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        env = parse_env_file(a.env_file)
    except OSError as e:
        p.error(f"--env-file: {e}")
    a.controller = a.controller or env.get("PCDN_CONTROLLER_URL") or os.environ.get("PCDN_CONTROLLER_URL")
    if not a.controller or urllib.parse.urlsplit(a.controller).scheme not in ("http", "https"):
        p.error("--controller http(s)://… is required (or PCDN_CONTROLLER_URL in the env file)")
    a.edge_target = a.edge_target or env.get("STAGING_EDGE_TARGET")
    a.loadtest_host = a.loadtest_host or env.get("STAGING_LOADTEST_HOST")
    if not a.ns and env.get("STAGING_NS"):
        a.ns = [x for x in re.split(r"[,\s]+", env["STAGING_NS"]) if x]
    if "loadtest" not in a.skip and not (a.edge_target and a.loadtest_host):
        p.error("the load test needs --edge-target IP:port and --loadtest-host (or --skip-loadtest)")
    gate = Gate(a, env)
    try:
        return gate.run()
    except Refused as e:
        print(f"staging-verify: REFUSED: {e}", file=sys.stderr)
        return EXIT_REFUSED


if __name__ == "__main__":
    sys.exit(main())
