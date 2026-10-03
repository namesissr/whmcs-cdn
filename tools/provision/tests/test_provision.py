"""pcdn-provision against a fake controller (SPEC §23.9): a fake `terraform` shim always, and the real
Terraform CLI with terraform/providers/fake when it is installed (CI: PCDN_REQUIRE_TERRAFORM=1)."""

import http.server
import json
import os
import pathlib
import shutil
import stat
import subprocess
import sys
import threading

import pytest

HERE = pathlib.Path(__file__).resolve().parent
PROV = HERE.parent
REPO = PROV.parent.parent
sys.path.insert(0, str(PROV))

import pcdn_provision as pp  # noqa: E402

PTOKEN = "prov-token-0123456789abcdef0123456789abcdef"
JT = {"general-home-p7-1": "jt_" + "a3f9c1e07b5d2c8e4f61" + "9d0b7a3e5c1f2d84b6a0",
      "general-home-p7-2": "jt_" + "5e2b8d1c9a7f3e60b4d2" + "c8a1f7e3d9b05c2a6e14"}


class FakeController:
    def __init__(self, jobs):
        self.jobs = list(jobs)
        self.posts = []
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
                fake.auth.append(self.headers.get("Authorization"))
                if self.headers.get("Authorization") != "Bearer " + PTOKEN:
                    return self.reply(401, {"detail": "unauthorized"})
                if self.path == "/api/v1/provisioner/jobs/next":
                    return self.reply(200, {"job": fake.jobs.pop(0) if fake.jobs else None})
                return self.reply(404, {})

            def do_POST(self):
                n = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(n) or b"null")
                if self.headers.get("Authorization") != "Bearer " + PTOKEN:
                    return self.reply(401, {"detail": "unauthorized"})
                fake.posts.append((self.path, body))
                return self.reply(200, {"ok": True})

        self.srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.srv.server_address[1]}"

    def __enter__(self):
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        return self

    def __exit__(self, *exc):
        self.srv.shutdown()


FAKE_TF = r'''#!/usr/bin/env python3
import json, os, sys
log = os.environ["FAKE_TF_LOG"]
with open(log, "a") as f:
    f.write(json.dumps(sys.argv[1:]) + "\n")
cmd = sys.argv[1]
if cmd == "destroy":
    sys.exit(99)
if cmd == "init":
    os.makedirs(".terraform", exist_ok=True); sys.exit(0)
if cmd == "plan":
    if os.environ.get("FAKE_TF_FAIL") == "plan":
        tok = json.load(open("secrets.auto.tfvars.json"))["join_tokens"]
        sys.stderr.write("Error: boom with " + list(tok.values())[0] + "\n"); sys.exit(1)
    mode = os.stat("secrets.auto.tfvars.json").st_mode & 0o777
    assert mode == 0o600, oct(mode)
    v = json.load(open("terraform.tfvars.json"))
    assert "join_tokens" not in v
    tok = json.load(open("secrets.auto.tfvars.json"))["join_tokens"]
    assert "module \"nodes\"" in open("main.tf").read()
    acts = [["create"]] * len(v["names"])
    if os.environ.get("FAKE_TF_DESTROY"):
        acts.append(["delete", "create"])
    json.dump({"vars": v, "tokens": tok, "actions": acts}, open("plan.bin", "w")); sys.exit(0)
if cmd == "show":
    p = json.load(open(sys.argv[-1]))
    if "-json" in sys.argv:
        print(json.dumps({"resource_changes": [{"change": {"actions": a}} for a in p["actions"]]}))
    else:
        for n in p["vars"]["names"]:
            print(f'  + resource "terraform_data" "node" {{ name = "{n}" }}')
            print(f'    user_data = "curl ... | PCDN_JOIN_TOKEN={p["tokens"][n]} bash -s --"')
        d = sum(1 for a in p["actions"] if "delete" in a)
        print(f"Plan: {len(p['actions'])} to add, 0 to change, {d} to destroy.")
    sys.exit(0)
if cmd == "apply":
    p = json.load(open(sys.argv[-1]))
    os.makedirs("out", exist_ok=True)
    for n in p["vars"]["names"]:
        open(f"out/{n}", "w").write("ok")
    sys.exit(0)
sys.exit(3)
'''


def job(jid=7, action="plan", tokens=True):
    edges = [{"name": n, **({"join_token": t} if tokens else {})} for n, t in JT.items()]
    return {"id": jid, "action": action, "group": "general", "region": "home", "size": "medium", "count": 2,
            "edges": edges, "controller_url": "https://cdn-api.example.com", "release": "v2.1.0"}


@pytest.fixture
def env(tmp_path):
    tf = tmp_path / "terraform"
    tf.write_text(FAKE_TF)
    tf.chmod(0o755)
    tok = tmp_path / "token"
    tok.write_text(PTOKEN + "\n")
    tok.chmod(0o600)
    return {"tf": str(tf), "token": str(tok), "work": tmp_path / "work", "log": tmp_path / "tf.log"}


def run(env, ctl, *extra, module=None, extra_env=None, terraform=None):
    args = ["--controller", ctl.url, "--token-file", env["token"], "--workdir", str(env["work"]),
            "--module", str(module or REPO / "terraform" / "providers" / "fake"), "--once",
            "--terraform", terraform or env["tf"], *extra]
    p = subprocess.run([sys.executable, str(PROV / "pcdn-provision"), *args], capture_output=True, text=True,
                       env=dict(os.environ, FAKE_TF_LOG=str(env["log"]), **(extra_env or {})))
    return p


def tf_calls(env):
    return [json.loads(line) for line in env["log"].read_text().splitlines()] if env["log"].exists() else []


def test_plan_then_apply_masks_tokens(env):
    with FakeController([job(), job(action="apply", tokens=False)]) as ctl:
        p = run(env, ctl)
        assert p.returncode == 0, p.stderr
        path, body = ctl.posts[0]
        assert path == "/api/v1/provisioner/jobs/7/plan"
        assert (body["adds"], body["changes"], body["destroys"]) == (2, 0, 0)
        assert "jt_***" in body["summary"] and "PCDN_JOIN_TOKEN=jt_***" in body["summary"]
        for t in JT.values():
            assert t not in body["summary"] and t not in p.stderr
        jd = env["work"] / "job-7"
        assert json.loads((jd / "terraform.tfvars.json").read_text())["role"] == "general"
        assert stat.S_IMODE((jd / "secrets.auto.tfvars.json").stat().st_mode) == 0o600
        assert stat.S_IMODE(jd.stat().st_mode) == 0o700
        p = run(env, ctl)
        assert p.returncode == 0, p.stderr
        assert ctl.posts[1] == ("/api/v1/provisioner/jobs/7/result", {"ok": True, "error": None})
        assert not (jd / "secrets.auto.tfvars.json").exists() and not (jd / "plan.bin").exists()
        assert (jd / "out" / "general-home-p7-1").is_file()
        p = run(env, ctl)                      # no job left
        assert p.returncode == 0 and "no job" in p.stderr
    assert set(ctl.auth) == {"Bearer " + PTOKEN}
    cmds = [c[0] for c in tf_calls(env)]
    assert "destroy" not in cmds and cmds.count("apply") == 1


def test_never_applies_destroying_plan(env):
    with FakeController([job(), job(action="apply", tokens=False)]) as ctl:
        assert run(env, ctl, extra_env={"FAKE_TF_DESTROY": "1"}).returncode == 0
        assert ctl.posts[0][1]["destroys"] == 1
        p = run(env, ctl)
        assert p.returncode == 1
        path, body = ctl.posts[1]
        assert path.endswith("/7/result") and body["ok"] is False and "plan_destroys" in body["error"]
    assert "apply" not in [c[0] for c in tf_calls(env)]


def test_failure_reports_masked_error_and_drops_secrets(env):
    with FakeController([job()]) as ctl:
        p = run(env, ctl, extra_env={"FAKE_TF_FAIL": "plan"})
        assert p.returncode == 1
        path, body = ctl.posts[0]
        assert path.endswith("/7/result") and body["ok"] is False and "jt_***" in body["error"]
        assert all(t not in body["error"] + p.stderr for t in JT.values())
    assert not (env["work"] / "job-7" / "secrets.auto.tfvars.json").exists()


def test_refusals(env, tmp_path):
    with FakeController([job(tokens=False)]) as ctl:
        p = run(env, ctl)                     # plan without join tokens
        assert p.returncode == 1 and "join token" in ctl.posts[0][1]["error"]
    with FakeController([dict(job(), controller_url="http://cdn.example")]) as ctl:
        assert run(env, ctl).returncode == 1 and "https" in ctl.posts[0][1]["error"]
    with FakeController([]) as ctl:
        bad = tmp_path / "short"
        bad.write_text("short")
        p = subprocess.run([sys.executable, str(PROV / "pcdn-provision"), "--controller", ctl.url, "--token-file",
                            str(bad), "--workdir", str(tmp_path / "w"), "--module",
                            str(REPO / "terraform/providers/fake"), "--once"], capture_output=True, text=True)
        assert p.returncode == 2 and "32 characters" in p.stderr
        env2 = dict(env, token=str(bad))
        assert run(env2, ctl).returncode == 2
    p = subprocess.run([sys.executable, str(PROV / "pcdn-provision"), "--controller", "http://cdn.example.com",
                        "--token-file", env["token"], "--workdir", str(tmp_path / "w"), "--module",
                        str(REPO / "terraform/providers/fake")], capture_output=True, text=True)
    assert p.returncode == 2 and "https" in p.stderr
    with pytest.raises(pp.ProvisionError):
        pp.Runner.terraform(object.__new__(pp.Runner), tmp_path, "destroy")


def test_wrong_token_is_reported(env, tmp_path):
    other = tmp_path / "other"
    other.write_text("x" * 40)
    other.chmod(0o600)
    with FakeController([job()]) as ctl:
        p = run(dict(env, token=str(other)), ctl)
        assert p.returncode == 2 and "401" in p.stderr and ctl.posts == []


def test_count_actions_and_mask():
    pj = {"resource_changes": [{"change": {"actions": ["create"]}}, {"change": {"actions": ["update"]}},
                               {"change": {"actions": ["delete", "create"]}}, {"change": {"actions": ["no-op"]}}]}
    assert pp.Runner.count_actions(pj) == (2, 1, 1)
    assert pp.mask("a jt_" + "0" * 40 + " b") == "a jt_*** b"
    assert pp.Runner.count_from_text("Plan: 3 to add, 1 to change, 0 to destroy.") == (3, 1, 0)


def _terraform():
    tf = os.environ.get("TERRAFORM") or shutil.which("terraform")
    if not tf and os.environ.get("PCDN_REQUIRE_TERRAFORM") == "1":
        pytest.fail("terraform CLI required (PCDN_REQUIRE_TERRAFORM=1)")
    return tf


def test_real_terraform_with_fake_module(env):
    tf = _terraform()
    if not tf:
        pytest.skip("terraform CLI not installed")
    with FakeController([job(), job(action="apply", tokens=False)]) as ctl:
        p = run(env, ctl, terraform=tf)
        assert p.returncode == 0, p.stderr
        body = ctl.posts[0][1]
        assert (body["adds"], body["destroys"]) == (4, 0)       # 2 terraform_data + 2 local_sensitive_file
        assert all(t not in body["summary"] for t in JT.values())
        p = run(env, ctl, terraform=tf)
        assert p.returncode == 0, p.stderr
        assert ctl.posts[1][1] == {"ok": True, "error": None}
    ud = (env["work"] / "job-7" / "out" / "general-home-p7-1.cloud-init.yaml").read_text()
    assert ud.startswith("#cloud-config")
    assert (f"curl -fsSL --proto '=https' https://cdn-api.example.com/edge/bootstrap.sh | "
            f"PCDN_JOIN_TOKEN={JT['general-home-p7-1']} bash -s -- --controller https://cdn-api.example.com "
            "--role general --region home --version v2.1.0") in ud
    assert not (env["work"] / "job-7" / "secrets.auto.tfvars.json").exists()
