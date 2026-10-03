#!/usr/bin/env python3
"""pcdn-provision — operator-run node provisioner (SPEC §23.9, docs/TERRAFORM.md).

Python 3 standard library + the `terraform` binary. It polls the controller's provisioner API for
APPROVED jobs and runs Terraform with the cloud credentials of ITS OWN environment (HCLOUD_TOKEN, …):
the controller never holds cloud credentials, and nothing is created without two admin approvals
(proposal -> plan, plan -> apply).

  pcdn-provision --controller https://cdn-api.example.com --token-file /etc/pcdn/provisioner.token \\
      --workdir /var/lib/pcdn-provision --module terraform/providers/hcloud [--once]

  GET  /api/v1/provisioner/jobs/next           {"job": {...} | null}   (every --interval s, default 60)
  plan:  writes terraform.tfvars.json (no secrets) + secrets.auto.tfvars.json (0600, join tokens),
         terraform init / plan -out=plan.bin / show  -> masked summary (jt_***)
  POST /api/v1/provisioner/jobs/{id}/plan       {"summary", "adds", "changes", "destroys"}
  apply: terraform apply plan.bin (refused when the plan destroys anything); the secrets file and
         plan.bin are deleted afterwards
  POST /api/v1/provisioner/jobs/{id}/result     {"ok", "error"}

It never runs `terraform destroy` and never applies a plan that destroys or replaces a resource.
Exit codes (--once): 0 no job or job done, 1 the job failed, 2 usage/configuration error.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import ssl
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

USER_AGENT = "pcdn-provision/1.0"
TOKEN_RE = re.compile(r"jt_[0-9a-f]{40}")
MAX_SUMMARY = 64 * 1024
MAX_ERROR = 500
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
COMMON_VARS = ("controller_url", "names", "join_tokens", "region", "role", "group", "size", "release")


class ProvisionError(Exception):
    pass


def mask(text: str, tokens=()) -> str:
    for t in tokens:
        if t:
            text = text.replace(t, "jt_***")
    return TOKEN_RE.sub("jt_***", text)


def log(msg: str):
    print(f"[{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}] {msg}", file=sys.stderr, flush=True)


class Controller:
    def __init__(self, base: str, token: str, timeout: float = 30, ca_file: str | None = None):
        self.base = base.rstrip("/")
        self.token = token
        self.timeout = timeout
        self.ctx = ssl.create_default_context(cafile=ca_file) if ca_file else None

    def call(self, method: str, path: str, body=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base + path, data=data, method=method)
        req.add_header("Authorization", "Bearer " + self.token)
        req.add_header("User-Agent", USER_AGENT)
        req.add_header("Accept", "application/json")
        if data is not None:
            req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=self.ctx) as r:
                raw = r.read()
                return r.status, json.loads(raw or b"null")
        except urllib.error.HTTPError as e:
            raw = e.read()
            try:
                return e.code, json.loads(raw or b"null")
            except ValueError:
                return e.code, None

    def next_job(self) -> dict | None:
        st, body = self.call("GET", "/api/v1/provisioner/jobs/next")
        if st == 401:
            raise ProvisionError("401 from the controller: wrong token-file or PROVISIONER_TOKEN unset")
        if st == 404:
            raise ProvisionError("404: PROVISIONING_ENABLED is off on this controller (or it is older than wave 14)")
        if st != 200 or not isinstance(body, dict):
            raise ProvisionError(f"jobs/next answered {st}")
        return body.get("job")


def validate_job(job: dict) -> dict:
    if not isinstance(job, dict):
        raise ProvisionError("malformed job")
    jid = job.get("id")
    if not isinstance(jid, int) or jid < 1:
        raise ProvisionError("job without a valid id")
    if job.get("action") not in ("plan", "apply"):
        raise ProvisionError(f"unknown action {job.get('action')!r}")
    names = [e.get("name") for e in job.get("edges") or [] if isinstance(e, dict)]
    if not names or not all(isinstance(n, str) and NAME_RE.match(n) for n in names):
        raise ProvisionError("job edges must have DNS-label names")
    for k in ("group", "region", "size"):
        if not isinstance(job.get(k), str) or not re.fullmatch(r"[a-z0-9_-]{1,32}", job[k]):
            raise ProvisionError(f"job {k} is invalid")
    url = job.get("controller_url") or ""
    if urllib.parse.urlsplit(url).scheme != "https":
        raise ProvisionError("job controller_url must be https://")
    return job


class Runner:
    def __init__(self, a, ctl: Controller):
        self.a = a
        self.ctl = ctl
        self.module = Path(a.module).resolve()
        self.workdir = Path(a.workdir).resolve()
        self.tf = a.terraform

    # ------------------------------------------------------------------ terraform
    def terraform(self, jobdir: Path, *args: str, tokens=(), timeout=3600) -> str:
        if args and args[0] == "destroy":   # belt and braces: this tool never destroys
            raise ProvisionError("refusing to run terraform destroy")
        env = dict(os.environ, TF_IN_AUTOMATION="1", TF_INPUT="0", CHECKPOINT_DISABLE="1")
        try:
            p = subprocess.run([self.tf, *args], cwd=jobdir, env=env, capture_output=True, text=True,
                               timeout=timeout)
        except FileNotFoundError:
            raise ProvisionError(f"terraform binary not found ({self.tf})")
        except subprocess.TimeoutExpired:
            raise ProvisionError(f"terraform {args[0]} timed out")
        if p.returncode != 0:
            tail = mask((p.stderr or p.stdout or "").strip(), tokens)[-MAX_ERROR:]
            raise ProvisionError(f"terraform {args[0]} failed: {tail}")
        return p.stdout

    def jobdir(self, jid: int) -> Path:
        d = self.workdir / f"job-{jid}"
        d.mkdir(parents=True, exist_ok=True)
        os.chmod(d, 0o700)
        return d

    def write_root(self, d: Path):
        """A generated root module in the job directory that calls the chosen providers/<name> module, so
        state, plan and .terraform stay per job (outside the repository)."""
        lines = ["# generated by pcdn-provision — do not edit", ""]
        for v in COMMON_VARS:
            if v == "names":
                lines.append('variable "names" {\n  type = list(string)\n}')
            elif v == "join_tokens":
                lines.append('variable "join_tokens" {\n  type      = map(string)\n  sensitive = true\n}')
            else:
                lines.append(f'variable "{v}" {{\n  type = string\n}}')
        # a RELATIVE local path: an absolute one would be treated as a module package, and the provider
        # module's own "../../modules/pcdn-edge-node" would then "escape" it
        rel = os.path.relpath(self.module, d)
        if not rel.startswith("."):
            rel = "./" + rel
        lines.append(f'module "nodes" {{\n  source = {json.dumps(rel)}')
        lines += [f"  {v} = var.{v}" for v in COMMON_VARS]
        lines.append("}")
        (d / "main.tf").write_text("\n".join(lines) + "\n", encoding="utf-8")

    @staticmethod
    def count_actions(plan_json: dict) -> tuple[int, int, int]:
        adds = changes = destroys = 0
        for rc in plan_json.get("resource_changes") or []:
            actions = (rc.get("change") or {}).get("actions") or []
            if "delete" in actions:
                destroys += 1           # a replace (delete+create) counts as a destroy: refused
                if "create" in actions:
                    adds += 1
            elif "create" in actions:
                adds += 1
            elif "update" in actions:
                changes += 1
        return adds, changes, destroys

    # ------------------------------------------------------------------ actions
    def plan(self, job: dict) -> dict:
        d = self.jobdir(job["id"])
        tokens = {e["name"]: e.get("join_token") for e in job["edges"]}
        missing = [n for n, t in tokens.items() if not (isinstance(t, str) and TOKEN_RE.fullmatch(t))]
        if missing:
            raise ProvisionError("the job carries no valid join token for: " + ", ".join(missing)
                                 + " (tokens are handed out once; ask the admin to re-approve)")
        self.write_root(d)
        tfvars = {"controller_url": job["controller_url"], "names": [e["name"] for e in job["edges"]],
                  "region": job["region"], "group": job["group"],
                  "role": "tunnel" if job["group"] == "tunnel" else "general",
                  "size": job["size"], "release": job.get("release") or ""}
        (d / "terraform.tfvars.json").write_text(json.dumps(tfvars, indent=2), encoding="utf-8")
        secrets = d / "secrets.auto.tfvars.json"
        fd = os.open(secrets, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump({"join_tokens": tokens}, f)
        os.chmod(secrets, 0o600)
        tv = list(tokens.values())
        self.terraform(d, "init", "-input=false", "-no-color", tokens=tv)
        self.terraform(d, "plan", "-out=plan.bin", "-input=false", "-no-color", tokens=tv)
        if (d / "plan.bin").exists():
            os.chmod(d / "plan.bin", 0o600)   # a plan file holds the variable values (join tokens)
        summary = mask(self.terraform(d, "show", "-no-color", "plan.bin", tokens=tv), tv)
        try:
            pj = json.loads(self.terraform(d, "show", "-json", "plan.bin", tokens=tv))
            adds, changes, destroys = self.count_actions(pj)
        except ValueError:
            adds, changes, destroys = self.count_from_text(summary)
        if len(summary.encode()) > MAX_SUMMARY:
            summary = summary.encode()[:MAX_SUMMARY - 40].decode("utf-8", "ignore") + "\n… (truncated)\n"
        body = {"summary": summary, "adds": adds, "changes": changes, "destroys": destroys}
        st, ans = self.ctl.call("POST", f"/api/v1/provisioner/jobs/{job['id']}/plan", body)
        if st not in (200, 201, 202):
            raise ProvisionError(f"uploading the plan answered {st} {mask(json.dumps(ans))[:200]}")
        log(f"job {job['id']}: plan uploaded ({adds} to add, {changes} to change, {destroys} to destroy)")
        return body

    @staticmethod
    def count_from_text(text: str) -> tuple[int, int, int]:
        m = re.search(r"Plan: (\d+) to add, (\d+) to change, (\d+) to destroy", text)
        if m:
            return int(m.group(1)), int(m.group(2)), int(m.group(3))
        return 0, 0, 0

    def apply(self, job: dict) -> None:
        d = self.workdir / f"job-{job['id']}"
        plan = d / "plan.bin"
        if not plan.is_file():
            raise ProvisionError("no plan.bin for this job in the workdir (planned on another machine?)")
        tokens = []
        sec = d / "secrets.auto.tfvars.json"
        if sec.is_file():
            try:
                tokens = list(json.loads(sec.read_text()).get("join_tokens", {}).values())
            except ValueError:
                tokens = []
        try:
            pj = json.loads(self.terraform(d, "show", "-json", "plan.bin", tokens=tokens))
            destroys = self.count_actions(pj)[2]
        except ValueError:
            destroys = self.count_from_text(self.terraform(d, "show", "-no-color", "plan.bin", tokens=tokens))[2]
        if destroys:
            raise ProvisionError(f"plan_destroys: the plan destroys {destroys} resource(s); never applied")
        try:
            self.terraform(d, "apply", "-input=false", "-no-color", "-auto-approve", "plan.bin", tokens=tokens)
        finally:
            for f in (sec, plan):
                try:
                    f.unlink()
                except FileNotFoundError:
                    pass
        log(f"job {job['id']}: applied")

    def report(self, jid: int, ok: bool, error: str | None, tokens=()):
        body = {"ok": ok, "error": mask(error, tokens)[:MAX_ERROR] if error else None}
        st, _ = self.ctl.call("POST", f"/api/v1/provisioner/jobs/{jid}/result", body)
        if st not in (200, 201, 202, 204):
            log(f"job {jid}: reporting the result answered {st}")

    def handle(self, job: dict) -> bool:
        tokens = [e.get("join_token") for e in (job or {}).get("edges") or [] if isinstance(e, dict)]
        try:
            job = validate_job(job)
            log(f"job {job['id']}: {job['action']} {len(job['edges'])} node(s) group={job['group']} "
                f"region={job['region']} size={job['size']}")
            if job["action"] == "plan":
                self.plan(job)
            else:
                self.apply(job)
                self.report(job["id"], True, None)
            return True
        except (ProvisionError, OSError) as e:
            msg = mask(str(e), tokens)
            log(f"job {job.get('id') if isinstance(job, dict) else '?'}: FAILED: {msg}")
            if isinstance(job, dict) and isinstance(job.get("id"), int):
                self.report(job["id"], False, msg, tokens)
            if isinstance(job, dict) and job.get("action") == "plan" and isinstance(job.get("id"), int):
                sec = self.workdir / f"job-{job['id']}" / "secrets.auto.tfvars.json"
                if sec.exists():
                    sec.unlink()
            return False


def read_token(path: str) -> str:
    p = Path(path)
    st = p.stat()
    if st.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        log(f"warning: {path} is readable by group/others; chmod 600 it")
    tok = p.read_text(encoding="utf-8").strip()
    if len(tok) < 32:
        raise ProvisionError("the provisioner token must be at least 32 characters (PROVISIONER_TOKEN)")
    return tok


def parse_args(argv):
    p = argparse.ArgumentParser(prog="pcdn-provision", description="Pasargad CDN node provisioner (SPEC §23.9)")
    p.add_argument("--controller", required=True, help="controller base URL (https; http only for localhost)")
    p.add_argument("--token-file", required=True, help="file holding PROVISIONER_TOKEN (never on argv)")
    p.add_argument("--workdir", required=True, help="per-job Terraform directories (state, plans) live here")
    p.add_argument("--module", required=True, help="terraform/providers/<name> directory")
    p.add_argument("--once", action="store_true", help="handle at most one job, then exit")
    p.add_argument("--interval", type=float, default=60.0, help="poll interval in seconds (60)")
    p.add_argument("--terraform", default=os.environ.get("TERRAFORM", "terraform"), help="terraform binary")
    p.add_argument("--ca-file", help="CA bundle for a controller with a private CA")
    p.add_argument("--timeout", type=float, default=30.0, help="HTTP timeout (30 s)")
    a = p.parse_args(argv)
    u = urllib.parse.urlsplit(a.controller)
    if u.scheme != "https" and not (u.scheme == "http" and u.hostname in ("127.0.0.1", "localhost", "::1")):
        p.error("--controller must be https:// (http only for localhost)")
    if not (Path(a.module) / "main.tf").is_file():
        p.error(f"--module {a.module} has no main.tf (expected terraform/providers/<name>)")
    return a


def main(argv=None) -> int:
    a = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        token = read_token(a.token_file)
    except (OSError, ProvisionError) as e:
        print(f"pcdn-provision: {e}", file=sys.stderr)
        return 2
    Path(a.workdir).mkdir(parents=True, exist_ok=True)
    runner = Runner(a, Controller(a.controller, token, a.timeout, a.ca_file))
    if shutil.which(a.terraform) is None and not os.path.isfile(a.terraform):
        print(f"pcdn-provision: terraform binary not found ({a.terraform})", file=sys.stderr)
        return 2
    while True:
        try:
            job = runner.ctl.next_job()
        except ProvisionError as e:
            log(str(e))
            if a.once:
                return 2
            job = None
        except (urllib.error.URLError, OSError) as e:
            log(f"controller unreachable: {e}")
            if a.once:
                return 1
            job = None
        if job:
            ok = runner.handle(job)
            if a.once:
                return 0 if ok else 1
        elif a.once:
            log("no job")
            return 0
        time.sleep(a.interval)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
