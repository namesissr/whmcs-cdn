"""Wave 13 (SPEC §22, agent B): tunnel speed and stability on the edge — unit tests (fake /proc and
/proc/sys trees, fake controllers, node for the njs logic, `nginx -t` where nginx is installed).

The real-nginx scenarios (probe, drain refusal, multi-origin failover, ticket resumption) live in
test_tunnel_speed_e2e.py."""

import base64
import io
import json
import os
import pathlib
import shutil
import socket
import subprocess
import threading
import time
import urllib.error

import pytest

from test_agent import SITE, agent, make_cfg, self_signed

HERE = pathlib.Path(__file__).resolve().parent
EDGE = HERE.parent

WS_ORIGIN = {"address": "198.51.100.10", "port": 8443, "tls": False}


def tsite(paths, sid=7, **kw):
    s = dict(SITE, id=sid, rate_limit_rps=0, hosts=[{"name": "example.com", "origin": {"address": "127.0.0.1",
                                                                                      "port": 18080}}],
             tunnel={"enabled": True, "idle_timeout": 3600, "paths": paths})
    s.update(kw)
    return s


def loc(text, path):
    return text.split(f'location ^~ "{path}" {{', 1)[1].split("\n    }", 1)[0]


# ================================================================= §22.1 drain

NJS_HARNESS = r"""
import m from './pcdn.mjs';
const store = {};
const dict = { get: k => store[k], set: (k, v) => { store[k] = v; }, incr: (k, d, i) => (store[k] = (store[k] === undefined ? i : store[k]) + d),
  delete: k => { delete store[k]; } };
globalThis.ngx = { shared: { pcdn_cnt: dict, pcdn_blk: dict, pcdn_hc: dict, pcdn_fair: dict } };
const cases = JSON.parse(process.argv[2]);
const out = cases.map(c => {
  if (c.kind === 'set') {
    const res = {};
    m.fairSet({ args: c.args, return: code => { res.code = code; } });
    res.hot = store.hot === undefined ? null : store.hot;
    res.drain = store.drain === undefined ? null : store.drain;
    return res;
  }
  if (c.kind === 'drain') return m.tunnelDrain({ method: c.method || 'GET', variables: {
    pcdn_tn: c.tn || 'ws', connection_requests: c.cr } });
  if (c.kind === 'expire') { delete store.drain; return null; }
  if (c.kind === 'hcset') {
    const res = {};
    m.hcSet({ method: c.method || 'POST', requestText: c.body, return: (code, b) => { res.code = code; res.body = b; } });
    res.store = Object.assign({}, store);
    return res;
  }
  if (c.kind === 'pick') {
    Object.keys(c.hc || {}).forEach(k => { store[k] = c.hc[k]; });
    const seen = {};
    for (let i = 0; i < (c.n || 20); i++) {
      const v = m.tunnelUpstream({ uri: c.uri || '/svc', method: 'GET', variables: { pcdn_site: c.site,
        pcdn_tn: c.tn, pcdn_tn_pool: c.pool, pcdn_tn_prefix: '/svc', remote_addr: '10.0.0.' + i }, headersIn: {},
        args: {}, error: () => {} });
      seen[v] = (seen[v] || 0) + 1;
    }
    return seen;
  }
});
console.log(JSON.stringify(out));
"""


def njs(tmp_path, cases, sites=None):
    if shutil.which("node") is None:
        pytest.skip("node not installed")
    src = (EDGE / "njs/pcdn.js").read_text().replace("from 'sites.js'", "from './sites.mjs'")
    (tmp_path / "pcdn.mjs").write_text(src)
    (tmp_path / "sites.mjs").write_text("export default " + json.dumps(sites or {}) + ";\n")
    (tmp_path / "h.mjs").write_text(NJS_HARNESS)
    p = subprocess.run(["node", str(tmp_path / "h.mjs"), json.dumps(cases)], capture_output=True, text=True,
                       cwd=tmp_path)
    assert p.returncode == 0, p.stderr
    return json.loads(p.stdout)


def test_njs_drain_predicate(tmp_path):
    res = njs(tmp_path, [
        {"kind": "drain", "cr": "1"},                              # no flag: never refused
        {"kind": "set", "args": {"drain": "1"}},
        {"kind": "drain", "cr": "1"},                              # first request of a new connection
        {"kind": "drain", "cr": "2"},                              # an existing connection
        {"kind": "drain", "cr": "1", "tn": "grpc"},                # first stream of a new h2 connection
        {"kind": "drain", "cr": "7", "tn": "grpc"},                # another stream on an existing h2 connection
        {"kind": "drain", "cr": "1", "tn": "xhttp", "method": "POST"},   # xhttp packets: never
        {"kind": "drain", "cr": "1", "tn": "xhttp", "method": "GET"},
        {"kind": "set", "args": {"hot": "25"}},                    # hot only: the drain flag stays
        {"kind": "set", "args": {"drain": "0"}},
        {"kind": "drain", "cr": "1"},
        {"kind": "set", "args": {"drain": "1"}},
        {"kind": "expire"},                                        # the zone timeout dropped it: fail open
        {"kind": "drain", "cr": "1"},
    ])
    assert res[0] == "" and res[1] == {"code": 204, "hot": None, "drain": 1}
    assert res[2:8] == ["1", "", "1", "", "", "1"]
    assert res[8] == {"code": 204, "hot": 25, "drain": 1} and res[9] == {"code": 204, "hot": 25, "drain": None}
    assert res[10] == "" and res[13] == ""


def test_drain_rendered_on_tunnel_paths_only(tmp_path):
    cfg = make_cfg(tmp_path)
    text, _ = agent.render_site(tsite([{"id": "w", "path": "/ws", "protocol": "ws", "origin": WS_ORIGIN}]), cfg)
    w = loc(text, "/ws")
    assert "if ($pcdn_tn_drain) { error_page 503 = /__pcdn_drain; return 503; }" in w
    assert w.index("if ($pcdn_tn_fair)") < w.index("if ($pcdn_tn_drain)")   # right after the fair-share line
    assert ("location = /__pcdn_drain { internal; keepalive_timeout 0; add_header Retry-After 30 always; "
            "return 503; }") in text
    plain, _ = agent.render_site(dict(SITE, rate_limit_rps=0), cfg)
    assert "pcdn_tn_drain" not in plain and "__pcdn_drain" not in plain
    nonjs = make_cfg(tmp_path, NGINX_CAPS=dict(agent.LEGACY_CAPS, nginx="1.24.0", modules=[]))
    t2, _ = agent.render_site(tsite([{"id": "w", "path": "/ws", "protocol": "ws", "origin": WS_ORIGIN}]), nonjs)
    assert "pcdn_tn_drain" not in t2
    http = agent.render_all({"sites": []}, cfg)["http.conf"]
    assert "js_set $pcdn_tn_drain pcdn.tunnelDrain;" in http and "/__pcdn_drain       drain;" in http
    # a refused attempt is an edge error, never "limit" (the F35 / limit_req 503 keeps its meaning)
    e = {"tn": "ws", "s": 503, "us": "", "pg": "drain", "tp": "w"}
    assert agent.classify_tunnel(e) == "edge" and agent.classify_tunnel(dict(e, pg="")) == "limit"
    assert agent.platform_error(e) is False


class FakeCtl:
    def __init__(self, answers):
        self.answers, self.calls = list(answers), []

    def call(self, method, path, body=None, headers=None, timeout=30):
        self.calls.append((method, path, body))
        a = self.answers.pop(0) if self.answers else (200, {"state": "draining"})
        if isinstance(a, Exception):
            raise a
        return a[0], {}, a[1]


def http_error(code, detail=None):
    body = json.dumps({"detail": detail}).encode() if detail else b""
    return urllib.error.HTTPError("http://c/edge/v1/drain", code, "x", {}, io.BytesIO(body))


def test_drain_cli_exit_codes(tmp_path):
    cfg = make_cfg(tmp_path)
    out = io.StringIO()
    until = "2030-01-01T00:15:00Z"
    ctl = FakeCtl([(200, {"state": "draining", "until": until, "refuse_after": "2030-01-01T00:05:30Z"})])
    assert agent.drain_main(cfg, ["--minutes", "15", "--reason", "upgrade"], ctl=ctl, out=out) == 0
    assert ctl.calls == [("POST", "/edge/v1/drain", {"action": "start", "minutes": 15, "reason": "upgrade"})]
    d = json.loads(pathlib.Path(cfg["STATE_FILE"]).read_text())["drain"]
    assert d["state"] == "draining" and d["until"] == until and d["by"] == "edge" and d["upgrade"] is True
    assert d["refuse_after"] == "2030-01-01T00:05:30Z" and d["at"] > 0
    out = io.StringIO()
    assert agent.drain_main(cfg, ["--minutes", "5"], ctl=FakeCtl([http_error(409, "last_edge")]), out=out) == 3
    assert "last active node" in out.getvalue() and "آخرین نود فعال" in out.getvalue()
    out = io.StringIO()   # an old controller: no endpoint
    assert agent.drain_main(cfg, ["--minutes", "5"], ctl=FakeCtl([http_error(404)]), out=out) == 2
    assert "older controller" in out.getvalue()
    assert agent.drain_main(cfg, ["--minutes", "5"], ctl=FakeCtl([http_error(409, "already_draining")]),
                            out=io.StringIO()) == 2
    assert agent.drain_main(cfg, ["--minutes", "5"], ctl=FakeCtl([urllib.error.URLError("down")]),
                            out=io.StringIO()) == 2
    assert agent.drain_main(cfg, ["--minutes", "0"], ctl=FakeCtl([]), out=io.StringIO()) == 2
    assert agent.drain_main(dict(cfg, CONTROLLER_URL=""), ["--minutes", "5"], out=io.StringIO()) == 2
    # undrain: stop + local state cleared (also when the controller cannot be reached)
    ctl = FakeCtl([(200, {"state": ""})])
    assert agent.undrain_main(cfg, [], ctl=ctl, out=io.StringIO()) == 0
    assert ctl.calls == [("POST", "/edge/v1/drain", {"action": "stop"})]
    st = json.loads(pathlib.Path(cfg["STATE_FILE"]).read_text())
    assert st["drain"]["state"] == "" and st["drain_log"][-1]["upgrade"] is True
    assert agent.undrain_main(cfg, [], ctl=FakeCtl([http_error(500)]), out=io.StringIO()) == 2


def test_drain_cli_wait(tmp_path, monkeypatch):
    cfg = make_cfg(tmp_path, DRAIN_IDLE_CONNS="10")
    conns, flags, clock = [50, 8, 3], [], [1000.0]
    monkeypatch.setattr(agent, "public_conns", lambda c: conns.pop(0) if conns else 0)
    monkeypatch.setattr(agent, "set_flag", lambda c, on, opener=None: flags.append(on) or True)
    out = io.StringIO()
    ctl = FakeCtl([(200, {"state": "draining", "until": agent.iso(1900), "refuse_after": agent.iso(1005)})])
    rc = agent.drain_main(cfg, ["--minutes", "15", "--wait"], ctl=ctl, out=out,
                          sleep=lambda s: clock.__setitem__(0, clock[0] + s), now=lambda: clock[0])
    assert rc == 0 and "drained" in out.getvalue() and out.getvalue().count("drain: connections") == 3
    assert flags == [True, True]          # refused only after refuse_after (t = 1010, 1020)
    assert json.loads(pathlib.Path(cfg["STATE_FILE"]).read_text())["drain"]["state"] == "drained"
    # `until` reached while connections stay high -> done as well
    conns[:] = [99] * 5
    clock[0] = 2000.0
    ctl = FakeCtl([(200, {"state": "draining", "until": agent.iso(2015), "refuse_after": agent.iso(2000)})])
    assert agent.drain_main(cfg, ["--minutes", "1", "--wait"], ctl=ctl, out=io.StringIO(),
                            sleep=lambda s: clock.__setitem__(0, clock[0] + s), now=lambda: clock[0]) == 0
    assert clock[0] == 2020.0


def test_drain_help_needs_no_config():
    p = subprocess.run(["python3", str(EDGE / "pcdn-agent.py"), "drain", "--help"], capture_output=True, text=True,
                       env=dict(os.environ, PCDN_CONFIG="/nonexistent"), cwd="/")
    assert p.returncode == 0 and "--minutes" in p.stdout
    p = subprocess.run(["python3", str(EDGE / "pcdn-agent.py"), "nosuchcommand"], capture_output=True, text=True,
                       env=dict(os.environ, PCDN_CONFIG="/nonexistent"), cwd="/")
    assert p.returncode == 2   # never the agent loop for an unknown command


def test_config_drain_transitions():
    st, now = {}, 1000.0
    assert agent.apply_config_drain(st, None, now) is None and "drain" not in st           # old controller
    nd = agent.norm_drain({"node": {"drain": {"state": "draining", "refuse_after": "2030-01-01T00:00:00Z",
                                              "until": "2030-01-01T00:10:00Z"}}})
    assert agent.apply_config_drain(st, nd, now) == "start"
    assert st["drain"]["state"] == "draining" and st["drain"]["by"] == "admin" and st["drain"]["upgrade"] is False
    # an extension from the controller moves `until`
    nd2 = dict(nd, until=nd["until"] + 600)
    assert agent.apply_config_drain(st, nd2, now + 10) is None and st["drain"]["until"] == "2030-01-01T00:20:00Z"
    # the controller no longer shows a drain it has shown: ended at once (kept for §22.12)
    off = agent.norm_drain({"node": {"drain": {"state": ""}}})
    assert agent.apply_config_drain(st, off, now + 20) == "end"
    assert st["drain"]["state"] == "" and st["drain_log"][-1]["u"] == "2030-01-01T00:20:00Z"
    # a drain the CLI just started (the controller has not shown it yet) survives the propagation lag ...
    st["drain"] = {"state": "draining", "since": agent.iso(now), "by": "edge", "at": now}
    assert agent.apply_config_drain(st, off, now + 20) is None and st["drain"]["state"] == "draining"
    # ... until DRAIN_LAG_S after its start
    assert agent.apply_config_drain(st, off, now + 500) == "end" and st["drain"]["state"] == ""
    assert agent.norm_drain({"node": {}}) is None and agent.norm_drain({"node": {"drain": "x"}})["state"] == ""
    assert agent.refuse_now({"state": "draining", "refuse_after": agent.iso(100)}, 99) is False
    assert agent.refuse_now({"state": "draining", "refuse_after": agent.iso(100)}, 100) is True
    assert agent.refuse_now({"state": "draining", "since": agent.iso(100)}, 100 + 330) is True   # fallback grace
    assert agent.refuse_now({"state": ""}, 10 ** 10) is False
    assert agent.heartbeat_drain(None, 4) == {"state": "", "conns": 4, "since": None}
    assert agent.heartbeat_drain({"state": "drained", "since": "x"}, 1) == {"state": "drained", "conns": 1, "since": "x"}


def bare_agent(cfg, ctl=None, state=None):
    a = agent.Agent.__new__(agent.Agent)
    a.cfg, a.state, a.ctl = cfg, state if state is not None else {}, ctl
    a.last_heartbeat = 1e12
    return a


def test_agent_drain_step_flag_and_drained(tmp_path, monkeypatch):
    flags, conns = [], [40, 5, 5]
    monkeypatch.setattr(agent, "set_flag", lambda c, on, opener=None: flags.append(on) or True)
    monkeypatch.setattr(agent, "public_conns", lambda c: conns.pop(0))
    a = bare_agent(make_cfg(tmp_path), state={"drain": {"state": "draining", "since": agent.iso(1000),
                                                        "refuse_after": agent.iso(1100), "until": agent.iso(5000),
                                                        "at": 1000}})
    a.drain_step(1050)                     # DNS grace: no flag yet, first check (40 conns)
    assert flags == [] and a.state["drain"]["ok"] == 0
    a.drain_step(1100)                     # refuse_after reached: flag on; 5 conns
    a.drain_step(1105)                     # < 10 s since the last check: flag refreshed, no check
    a.drain_step(1110)                     # second check <= DRAIN_IDLE_CONNS -> drained, early heartbeat
    assert flags == [True, True, True] and a.state["drain"]["state"] == "drained" and a.last_heartbeat == 0
    a.state["drain"] = {"state": "", "at": 1200}
    a.drain_step(1200)                     # ended: the flag is cleared once, then left alone
    a.drain_step(1210)
    assert flags[-1] is False and len(flags) == 4 and "drain_flag" not in a.state


def test_upgrade_auto_undrain_conditions(tmp_path, monkeypatch):
    monkeypatch.setattr(agent, "set_flag", lambda c, on, opener=None: True)
    cfg = make_cfg(tmp_path, CONTROLLER_URL="http://c", EDGE_TOKEN="t", PROBE_ENABLED="yes",
                   PROBE_DIR=str(tmp_path / "probe"))
    drain = {"state": "drained", "since": agent.iso(1000), "until": agent.iso(1900), "by": "edge", "upgrade": True,
             "at": 1000}
    agent.save_state(cfg["STATE_FILE"], {"drain": drain})
    a = agent.Agent(cfg)
    a.ctl = FakeCtl([(200, {"state": ""})])
    assert a.upgrade_restart and a.state["drain"]["restart_at"]
    assert agent.ensure_probe_files(cfg)          # probe ready -> its first round must pass first
    a.maybe_upgrade_undrain()
    assert a.ctl.calls == []                      # no config applied yet
    a.first_apply_ok = True
    a.maybe_upgrade_undrain()
    assert a.ctl.calls == []                      # the probe has not run yet
    a.probe_runner.rounds, a.probe_runner.result = 1, {"ok": False}
    a.maybe_upgrade_undrain()
    assert a.ctl.calls == []                      # the probe failed
    a.probe_runner.result = {"ok": True}
    a.maybe_upgrade_undrain()
    assert a.ctl.calls == [("POST", "/edge/v1/drain", {"action": "stop"})]
    assert a.state["drain"]["state"] == "" and not a.upgrade_restart
    assert a.state["drain_log"][-1]["r"]          # the restart time feeds the §22.12 node_drain window
    # an admin drain is never ended by the agent
    agent.save_state(cfg["STATE_FILE"], {"drain": dict(drain, by="admin", upgrade=False)})
    b = agent.Agent(cfg)
    b.ctl, b.first_apply_ok = FakeCtl([]), True
    b.maybe_upgrade_undrain()
    assert b.ctl.calls == [] and b.state["drain"]["state"] == "drained"
    # an old controller (404): the local drain ends anyway; another error is retried
    agent.save_state(cfg["STATE_FILE"], {"drain": drain})
    c = agent.Agent(dict(cfg, PROBE_ENABLED="no"))
    c.ctl, c.first_apply_ok = FakeCtl([http_error(503)]), True
    c.maybe_upgrade_undrain()
    assert c.state["drain"]["state"] == "drained"
    c.ctl = FakeCtl([http_error(404)])
    c.maybe_upgrade_undrain()
    assert c.state["drain"]["state"] == ""


def test_upgrade_undrain_forced_after_grace_when_probe_keeps_failing(tmp_path, monkeypatch):
    # SPEC §22.1 safety net: a self-probe that never passes must not strand the node drained forever
    # (that refuses every tunnel connection on the node). After UPGRADE_UNDRAIN_GRACE_S it undrains anyway.
    monkeypatch.setattr(agent, "set_flag", lambda c, on, opener=None: True)
    cfg = make_cfg(tmp_path, CONTROLLER_URL="http://c", EDGE_TOKEN="t", PROBE_ENABLED="yes",
                   PROBE_DIR=str(tmp_path / "probe"))
    assert agent.ensure_probe_files(cfg)
    drain = {"state": "drained", "since": agent.iso(1000), "until": agent.iso(1900), "by": "edge",
             "upgrade": True, "at": 1000}
    agent.save_state(cfg["STATE_FILE"], {"drain": drain})
    a = agent.Agent(cfg)
    a.ctl, a.first_apply_ok = FakeCtl([(200, {"state": ""})]), True
    a.probe_runner.rounds, a.probe_runner.result = 5, {"ok": False}   # probe keeps failing
    # within the grace window: still stranded (service held back while the probe might recover)
    a.state["drain"]["restart_at"] = agent.iso(time.time() - 10)
    a.maybe_upgrade_undrain()
    assert a.ctl.calls == [] and a.state["drain"]["state"] == "drained"
    # past the grace window: undrain anyway so tunnel service returns
    a.state["drain"]["restart_at"] = agent.iso(time.time() - (agent.UPGRADE_UNDRAIN_GRACE_S + 5))
    a.maybe_upgrade_undrain()
    assert a.ctl.calls == [("POST", "/edge/v1/drain", {"action": "stop"})]
    assert a.state["drain"]["state"] == "" and not a.upgrade_restart


def test_cli_drain_written_under_lock_survives_agent_save(tmp_path):
    cfg = make_cfg(tmp_path)
    a = bare_agent(cfg, state={"pending": {"x": 1}})
    a._save()
    agent.write_drain(cfg["STATE_FILE"], {"state": "draining", "since": agent.iso(time.time()), "by": "edge",
                                          "upgrade": True})
    a.state["pending"]["y"] = 2
    a._save()                                     # merges the CLI's drain instead of overwriting it
    st = json.loads(pathlib.Path(cfg["STATE_FILE"]).read_text())
    assert st["drain"]["state"] == "draining" and st["pending"] == {"x": 1, "y": 2}
    agent.write_drain(cfg["STATE_FILE"], {"state": ""})
    a._adopt_disk_drain()
    assert a.state["drain"]["state"] == ""


def _block(path, start, end):
    text = (EDGE / path).read_text()
    return text.split(start, 1)[1].split("\n", 1)[1].split(end, 1)[0]


def _run(script, **env):
    base = {"PATH": os.environ.get("PATH", "/usr/bin:/bin")}
    base.update(env)
    return subprocess.run(["bash", "-euo", "pipefail", "-c", script], capture_output=True, text=True, env=base)


def test_install_arg_checks():
    funcs = _block("install.sh", "# >>> pcdn wst", "# <<< pcdn wst")
    checks = _block("install.sh", "# >>> pcdn arg checks", "# <<< pcdn arg checks")

    def run(drain="", upgrade="no", wst=""):
        return _run(f'DRAIN="{drain}"; UPGRADE={upgrade}; SHUTDOWN_TIMEOUT="{wst}"\n' + funcs + checks
                    + 'echo "DRAIN=$DRAIN"')
    assert run("15", "no").returncode == 1 and "only valid together with --upgrade" in run("15").stdout
    assert run("0", "yes").returncode == 1 and run("121", "yes").returncode == 1 and run("x", "yes").returncode == 1
    assert run("", "yes").returncode == 0
    p = run("015", "yes")
    assert p.returncode == 0 and p.stdout.strip() == "DRAIN=15"
    assert run("", "no", "30").returncode == 1 and run("", "no", "45s").returncode == 1   # hard cut
    for ok in ("auto", "60", "90s", "30m", "2h", "1d", "60000ms"):
        assert run("", "no", ok).returncode == 0, ok
    for bad in ("1h30m", "h", "-5m", "0m", "1x"):
        assert run("", "no", bad).returncode == 1, bad
    # the parser itself: --drain / --drain=N, unknown flags refused
    text = (EDGE / "install.sh").read_text()
    assert "    --drain) DRAIN=15; shift ;;" in text and '    --drain=*) DRAIN="${1#--drain=}"; shift ;;' in text
    assert subprocess.run(["bash", "-n", str(EDGE / "install.sh")]).returncode == 0
    assert subprocess.run(["bash", "-n", str(EDGE / "bootstrap.sh")]).returncode == 0


def test_install_drain_args_fail_before_any_change(tmp_path):
    """The real script: --drain without --upgrade and --drain=0 exit 1 before the root check."""
    for args in (["--drain"], ["--drain=0", "--upgrade"], ["--drain=500", "--upgrade"], ["--shutdown-timeout", "10s"]):
        # an empty PATH: nothing but bash builtins could run even if the check did not stop the script
        p = subprocess.run(["/bin/bash", str(EDGE / "install.sh"), "--controller", "https://c", "--token", "t", *args],
                           capture_output=True, text=True, env={"PATH": str(tmp_path), "PCDN_MEMINFO": "/nonexistent"})
        assert p.returncode == 1 and ("--drain" in p.stdout or "--shutdown-timeout" in p.stdout), (args, p.stdout)


def test_bootstrap_drain_checks():
    block = _block("bootstrap.sh", "# >>> pcdn bootstrap drain check", "# <<< pcdn bootstrap drain check")

    def run(drain, upgrade):
        return _run(f'DRAIN="{drain}"; UPGRADE={upgrade}; PASS=()\n' + block + 'echo "${PASS[@]+"${PASS[@]}"}"')
    assert run("15", "no").returncode == 1
    assert run("0", "yes").returncode == 1 and run("121", "yes").returncode == 1
    p = run("30", "yes")
    assert p.returncode == 0 and p.stdout.strip() == "--drain=30"
    p = run("", "no")
    assert p.returncode == 0 and p.stdout.strip() == ""
    text = (EDGE / "bootstrap.sh").read_text()
    # --upgrade without --drain keeps reading the controller URL from the installed agent.conf
    assert "sed -n 's/^CONTROLLER_URL=//p' /etc/pcdn/agent.conf" in text
    assert "    --drain) DRAIN=15; shift ;;" in text and '    --drain=*) DRAIN="${1#--drain=}"; shift ;;' in text


def test_bootstrap_rejects_drain_without_upgrade_before_root_check():
    p = subprocess.run(["/bin/bash", str(EDGE / "bootstrap.sh"), "--controller", "https://c", "--drain"],
                       capture_output=True, text=True, env={"PATH": "/nonexistent"})
    assert p.returncode == 1 and "--drain is only valid together with --upgrade" in p.stderr


def test_install_upgrade_drain_block(tmp_path):
    block = _block("install.sh", "# >>> pcdn upgrade drain", "# <<< pcdn upgrade drain")
    fake = tmp_path / "pcdn-agent"

    def run(script_body, drain="15"):
        fake.write_text(script_body)
        return _run(f'DRAIN="{drain}"\n' + block.replace("/usr/bin/python3", "/bin/bash") + '\nUPGRADE_DONE=yes\n'
                    + 'echo "DRAINED=$DRAINED"', AGENT_BIN=str(fake), PCDN_AGENT_CONF=str(tmp_path / "agent.conf"))
    ok = 'if [ "$1" = drain ] && [ "${2:-}" = --help ]; then exit 0; fi\necho "args: $*"; exit 0\n'
    p = run(ok)
    assert p.returncode == 0 and "DRAINED=yes" in p.stdout
    assert "args: drain --minutes 15 --reason upgrade --wait" in p.stdout
    p = run('if [ "${2:-}" = --help ]; then exit 0; fi\nexit 3\n')
    assert p.returncode == 1 and "last active node" in p.stdout and "بدون --drain" in p.stdout
    p = run('if [ "${2:-}" = --help ]; then exit 0; fi\nexit 2\n')
    assert p.returncode == 0 and "DRAINED=no" in p.stdout and "warning" in p.stdout
    # an agent too old for `drain` (its --help is not a drain help: it exits non-zero)
    p = run("exit 1\n")
    assert p.returncode == 0 and "DRAINED=no" in p.stdout and "does not support drain" in p.stdout
    p = run(ok, drain="")
    assert p.returncode == 0 and "DRAINED=no" in p.stdout and "args:" not in p.stdout
    # a failed upgrade after the drain gives the node back (trap -> undrain)
    fake.write_text('if [ "${2:-}" = --help ]; then exit 0; fi\necho "call: $1"; exit 0\n')
    p = _run('DRAIN=5\n' + block.replace("/usr/bin/python3", "/bin/bash") + "\nfalse\n", AGENT_BIN=str(fake),
             PCDN_AGENT_CONF=str(tmp_path / "agent.conf"))
    assert p.returncode == 1 and "call: drain" in p.stdout and "call: undrain" in p.stdout


# ================================================================= §22.2 fewer reloads

class SeqCtl:
    def __init__(self):
        self.body, self.hb = {"version": "v0", "sites": []}, []

    def serve(self, version, sites=None, **extra):
        self.body = dict({"version": version, "sites": sites if sites is not None else []}, **extra)

    def call(self, method, path, body=None, headers=None, timeout=30):
        if path == "/edge/v1/config":
            return 200, {"ETag": "e-" + self.body["version"]}, json.loads(json.dumps(self.body))
        if "heartbeat" in path:
            self.hb.append(body)
        return 200, {}, None


MINSITE = {"id": 3, "domain": "m.test", "status": "active", "secret": "s",
           "hosts": [{"name": "m.test", "origin": {"address": "127.0.0.1", "port": 18080}}], "ssl": None,
           "edge_group": "general"}


def test_non_rendered_node_keys_keep_the_tree(tmp_path):
    cfg = make_cfg(tmp_path)
    base = {"sites": [MINSITE], "node": {"name": "n1", "capacity_mbps": 100}}
    d0 = agent.render_tree(base, cfg)[1]
    for extra in ({"drain": {"state": "draining", "refuse_after": "2030-01-01T00:00:00Z", "until": None}},
                  {"probe": {"origin": {"host": "echo.example.net", "port": 9000, "tls": True}, "interval": 120}},
                  {"dns_weight": {"level": 2, "q": 1}}):
        body = json.loads(json.dumps(base))
        body["node"].update(extra)
        assert agent.render_tree(body, cfg)[1] == d0, extra
    # http3 / tls_tickets ARE rendered
    body = json.loads(json.dumps(base))
    body["node"]["tls_tickets"] = {"id": "01234567", "keys": [base64.b64encode(b"k" * 80).decode()] * 3}
    assert agent.render_tree(body, cfg)[1] != d0


def test_reload_max_wait_forces_apply(tmp_path, monkeypatch):
    clock = [1000.0]
    monkeypatch.setattr(agent.time, "monotonic", lambda: clock[0])
    applies = []
    cfg = make_cfg(tmp_path, RELOAD_MIN_INTERVAL="600", RELOAD_DEBOUNCE="5", RELOAD_MAX_WAIT="900",
                   FOREIGN_DEFER="86400", GROUP="tunnel")

    def fake_apply(config, cfg_, files=None, digest=None):
        applies.append(config["version"])
        agent.write_tree(cfg_["NGINX_DIR"].rstrip("/"), files)
        return None
    monkeypatch.setattr(agent, "apply_config", fake_apply)
    monkeypatch.setattr(agent, "count_draining_workers", lambda proc="/proc": 1000)   # back-pressure: x2
    a = bare_agent(cfg, SeqCtl())
    a.ctl.serve("v1", [MINSITE])
    a.sync_config()                                 # first boot
    assert applies == ["v1"]
    # foreign-group churn: every poll a new version (never settles), deferred by F21 for a day
    for i in range(2, 40):
        clock[0] += 30
        a.ctl.serve(f"v{i}", [dict(MINSITE, edge_group="general", domain=f"m{i}.test",
                                   hosts=[{"name": f"m{i}.test", "origin": {"address": "127.0.0.1", "port": 18080}}])])
        a.sync_config()
        if len(applies) > 1:
            break
    # applied once the oldest pending change was RELOAD_MAX_WAIT old, not after a day
    assert len(applies) == 2 and 900 <= clock[0] - 1030 < 960
    st = a.state
    assert "pending_first" not in st and len(st["reload_times"]) == 2
    assert len(st["coalesced_times"]) >= 28        # superseded before being applied
    stats = agent.reload_stats(st, 3600)
    assert stats["count_1h"] == 2 and stats["count_24h"] == 2 and stats["coalesced_1h"] >= 28
    assert stats["pending_s"] == 0 and stats["deferred"] is False and stats["wst_s"] == 3600
    assert stats["forced_shutdowns_24h"] == 0 and stats["last_at"].endswith("Z")
    # while deferring, the stats say so
    clock[0] += 30
    a.ctl.serve("vX", [dict(MINSITE, domain="z.test", hosts=[{"name": "z.test", "origin":
                                                               {"address": "127.0.0.1", "port": 18080}}])])
    a.sync_config()
    clock[0] += 30
    a.sync_config()
    clock[0] += 700
    a.sync_config()
    s2 = agent.reload_stats(a.state, None, mono=clock[0])
    assert s2["deferred"] is True and s2["pending_s"] >= 700 and s2["wst_s"] is None


def test_wst_parser():
    assert agent.parse_wst("worker_shutdown_timeout 1h;") == 3600
    assert agent.parse_wst("user x;\n  worker_shutdown_timeout 30m;\n") == 1800
    assert agent.parse_wst("worker_shutdown_timeout 600s;") == 600
    assert agent.parse_wst("worker_shutdown_timeout 600;") == 600
    assert agent.parse_wst("worker_shutdown_timeout 2d;") == 172800
    assert agent.parse_wst("# worker_shutdown_timeout 1h;\nevents {}") is None
    assert agent.parse_wst("") is None


def test_install_wst_auto_table(tmp_path):
    funcs = _block("install.sh", "# >>> pcdn wst", "# <<< pcdn wst")
    out = {}
    for gib, want in ((1, "30m"), (3.9, "30m"), (4, "2h"), (7.5, "2h"), (8, "4h"), (64, "4h")):
        mi = tmp_path / f"meminfo{gib}"
        mi.write_text(f"MemTotal:       {int(gib * 1024 * 1024)} kB\nMemFree:         1000 kB\n")
        p = _run(funcs + "wst_auto", PCDN_MEMINFO=str(mi))
        out[gib] = p.stdout.strip()
        assert out[gib] == want, (gib, out)
    assert _run(funcs + "wst_auto", PCDN_MEMINFO="/nonexistent").stdout.strip() == "30m"


def test_install_wst_kept_on_upgrade(tmp_path):
    """--upgrade without SHUTDOWN_TIMEOUT keeps nginx.conf's value; an explicit value is stored."""
    text = (EDGE / "install.sh").read_text()
    edit = _block("install.sh", "# >>> nginx.conf edits", "# <<< nginx.conf edits")
    pre = text.split("# SPEC §22.2 worker_shutdown_timeout: explicit / stored value", 1)[1].split(
        "# >>> nginx.conf edits", 1)[0]
    funcs = _block("install.sh", "# >>> pcdn wst", "# <<< pcdn wst")
    ngx = tmp_path / "nginx.conf"
    mi = tmp_path / "meminfo"
    mi.write_text("MemTotal: 16000000 kB\n")

    def run(conf, wst="", upgrade="yes"):
        ngx.write_text(conf)
        script = funcs + f'SHUTDOWN_TIMEOUT="{wst}"; UPGRADE={upgrade}; SHUTDOWN_STORE=no\n#' + pre + edit
        p = _run(script.replace("/etc/nginx/nginx.conf", str(ngx)), PCDN_MEMINFO=str(mi))
        assert p.returncode == 0, p.stderr
        return agent.parse_wst(ngx.read_text())
    stock = "user www-data;\nworker_processes auto;\nevents {\n worker_connections 768;\n}\n"
    assert run(stock + "worker_shutdown_timeout 45m;\n") == 2700          # kept
    assert run(stock + "worker_shutdown_timeout 45m;\n", "1h") == 3600    # explicit wins
    assert run(stock) == 4 * 3600                                         # upgrade of an edge without one: auto
    assert run(stock + "worker_shutdown_timeout 45m;\n", "", "no") == 4 * 3600   # fresh install: auto


def fake_proc(tmp_path, procs):
    """procs: {pid: (cmdline, start ticks)}."""
    root = tmp_path / "proc"
    for pid, (cmd, start) in procs.items():
        d = root / str(pid)
        d.mkdir(parents=True)
        (d / "cmdline").write_bytes(cmd.encode() + b"\0")
        fields = ["S"] + ["0"] * 18 + [str(start)] + ["0"] * 10
        (d / "stat").write_text(f"{pid} (nginx: wor ker) " + " ".join(fields) + "\n")
    (root / "self").mkdir(parents=True, exist_ok=True)
    return root


def test_memory_guard_victim_selection(tmp_path):
    proc = fake_proc(tmp_path, {
        100: ("nginx: master process /usr/sbin/nginx", 10),
        201: ("nginx: worker process is shutting down", 500),
        202: ("nginx: worker process is shutting down", 300),     # the oldest old generation
        301: ("nginx: worker process", 50),                        # current generation (even if older start)
        302: ("nginx: worker process", 900)})
    assert agent.shutting_down_workers(str(proc)) == [(300, 202), (500, 201)]
    cfg = make_cfg(tmp_path, PROC_DIR=str(proc), MEM_GUARD_PCT="92")
    killed, st = [], {}

    def kill(pid, sig):
        killed.append(pid)
    assert agent.memory_guard(st, cfg, 95.0, now=1000, kill=kill) is None   # the first high heartbeat
    assert agent.memory_guard(st, cfg, 95.0, now=1060, kill=kill) == 202    # second: the oldest old worker
    assert agent.memory_guard(st, cfg, 96.0, now=1100, kill=kill) is None   # rate limit: one per 60 s
    assert agent.memory_guard(st, cfg, 96.0, now=1121, kill=kill) == 202    # (the fake /proc still lists it)
    assert killed == [202, 202] and 100 not in killed and 301 not in killed and 302 not in killed
    assert [f["pid"] for f in st["forced_shutdowns"]] == [202, 202]
    assert agent.memory_guard(st, cfg, 50.0, now=1200, kill=kill) is None and st["mem_high"] == 0
    assert agent.memory_guard({"mem_high": 5}, dict(cfg, MEM_GUARD_PCT="0"), 99.0, now=1, kill=kill) is None
    assert agent.reload_stats(st, None, now=1300)["forced_shutdowns_24h"] == 2
    empty = fake_proc(tmp_path / "e", {301: ("nginx: worker process", 50)})
    st2 = {"mem_high": 1}
    assert agent.memory_guard(st2, dict(cfg, PROC_DIR=str(empty)), 99.0, now=1, kill=kill) is None


# ================================================================= §22.3 probe

def test_echo_origin_protocol():
    srv = agent.EchoServer("127.0.0.1", 0).start()
    try:
        s = socket.create_connection(("127.0.0.1", srv.port), timeout=5)
        key = base64.b64encode(os.urandom(16)).decode()
        s.sendall(f"GET /x HTTP/1.1\r\nHost: e\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                  f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n".encode())
        head = agent.probe._read_http_head(s)
        import hashlib
        acc = base64.b64encode(hashlib.sha1(key.encode() + agent.WS_GUID).digest())
        assert b" 101 " in head and acc in head
        msg = os.urandom(3000)
        s.sendall(agent.ws_frame(0x2, msg, True))
        assert agent.ws_read_message(s, True) == (0x2, msg)
        s.sendall(agent.ws_frame(0x1, b"down:100000", True))
        got = b""
        while True:
            op, data = agent.ws_read_message(s, True)
            if op == 0x1:
                assert data == b"end"
                break
            got += data
        assert len(got) == 100000
        s.sendall(agent.ws_frame(0x1, b"up:70000", True))
        s.sendall(agent.ws_frame(0x2, b"a" * 65536, True) + agent.ws_frame(0x2, b"b" * 4464, True))
        assert agent.ws_read_message(s, True) == (0x1, b"up:70000")
        s.sendall(agent.ws_frame(0x1, b"down:99999999", True))           # over 4 MiB: refused
        assert agent.ws_read_message(s, True) == (0x1, b"error")
        s.sendall(agent.ws_frame(0x9, b"hi", True))                      # ping -> pong, then echo works
        s.sendall(agent.ws_frame(0x2, b"z", True))
        assert agent.ws_read_message(s, True) == (0x2, b"z")
        s.close()
        # not an upgrade -> 400
        with socket.create_connection(("127.0.0.1", srv.port), timeout=5) as s2:
            s2.sendall(b"GET / HTTP/1.1\r\nHost: e\r\n\r\n")
            assert b" 400 " in agent.probe._read_http_head(s2)
    finally:
        srv.stop()


def test_echo_origin_relay_to_operator_origin():
    remote = agent.EchoServer("127.0.0.1", 0).start()
    local = agent.EchoServer("127.0.0.1", 0, relay=("127.0.0.1", remote.port, False)).start()
    try:
        s = socket.create_connection(("127.0.0.1", local.port), timeout=5)
        s.sendall(b"GET / HTTP/1.1\r\nHost: e\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                  b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n")
        assert b" 101 " in agent.probe._read_http_head(s)
        s.sendall(agent.ws_frame(0x2, b"via relay", True))
        assert agent.ws_read_message(s, True) == (0x2, b"via relay")
        s.close()
    finally:
        local.stop()
        remote.stop()
    assert agent.norm_probe_node({"node": {"probe": {"origin": {"host": "Echo.Example.net", "port": 9000, "tls": True},
                                                     "interval": 120}}}) == \
        {"origin": ("echo.example.net", 9000, True), "interval": 120}
    assert agent.norm_probe_node({"node": {"probe": {"origin": {"host": "x;y", "port": 1}, "interval": 5}}}) == \
        {"origin": None, "interval": 30}
    assert agent.norm_probe_node({}) == {"origin": None, "interval": None}


def test_probe_ports_are_internal_and_server_renders(tmp_path):
    cfg = make_cfg(tmp_path, PROBE_ECHO_PORT="18192", PROBE_H2C_PORT="18193", PROBE_DIR=str(tmp_path / "probe"),
                   HTTPS_PORT="18543")
    assert {18192, 18193} <= set(agent.internal_ports(cfg))
    assert agent.render_probe(cfg) == ""                    # no certificate yet: nothing rendered
    assert agent.ensure_probe_files(cfg)
    f = agent.probe_files(cfg)
    assert os.stat(f["key"]).st_mode & 0o777 == 0o600 and os.path.getsize(f["body"]) == 262144
    mt = os.stat(f["crt"]).st_mtime_ns
    assert agent.ensure_probe_files(cfg) and os.stat(f["crt"]).st_mtime_ns == mt   # once
    http = agent.render_all({"sites": []}, cfg)["http.conf"]
    srv = http.split("server_name probe.pcdn.invalid;", 1)[1].split("\n}\n", 1)[0]
    assert "allow 127.0.0.0/8;" in srv and "deny all;" in srv and "access_log off;" in srv
    ws = srv.split("location ^~ /__pcdn_probe/ws {", 1)[1].split("    }", 1)[0]
    # the same directives as a customer ws path (tunnel_pass_lines), towards the local echo origin
    assert "proxy_set_header Upgrade $http_upgrade;" in ws and "proxy_buffering off;" in ws
    assert "proxy_bind 127.0.0.2;" in ws and "proxy_pass http://127.0.0.1:18192;" in ws
    g = srv.split("location ^~ /__pcdn_probe/grpc {", 1)[1].split("    }", 1)[0]
    assert "grpc_bind 127.0.0.2;" in g and "grpc_pass grpc://127.0.0.1:18193;" in g and "grpc_read_timeout 60s;" in g
    assert "$pcdn_tp" not in srv and "limit_conn" not in srv and "$pcdn_tn_fair" not in srv
    assert "listen 127.0.0.1:18193 http2;" in http and "add_trailer grpc-status 0 always;" in http
    assert "error_page 405 =200 /__pcdn_probe_body;" in http
    # PROBE_BYTES changes the body; the probe off renders nothing
    assert agent.ensure_probe_files(dict(cfg, PROBE_BYTES="16384")) and os.path.getsize(f["body"]) == 16384
    assert agent.render_probe(dict(cfg, PROBE_ENABLED="no")) == ""
    if shutil.which("nginx"):
        from conftest import modules_available, nginx_conf
        if modules_available():
            cfg2 = dict(cfg, PROBE_BYTES="16384", LISTEN_IPV6="no", HTTP_PORT="18580")
            assert agent.apply_config({"sites": []}, cfg2) is None
            p = subprocess.run(["nginx", "-t", "-c", str(nginx_conf(tmp_path, cfg2))], capture_output=True, text=True)
            assert p.returncode == 0, p.stderr


def test_grpc_probe_unsupported_without_http2_curl(monkeypatch):
    monkeypatch.setattr(agent.probe, "_CURL_H2", {})

    class P:
        returncode, stdout = 0, "curl 8.5.0\nProtocols: http https\nFeatures: IPv6 Largefile SSL\n"
    assert agent.grpc_probe(443, 1000, 5, run=lambda *a, **k: P()) == {"unsupported": True}
    monkeypatch.setattr(agent.probe, "_CURL_H2", {"v": True})

    class Q:
        returncode, stdout = 0, "200 1000 0.004 0.010"
    r = agent.grpc_probe(443, 1000, 5, run=lambda *a, **k: Q())
    assert r["ok"] and r["echo_ok"] and r["setup_ms"] == 4 and r["down_kbps"] == 1333 and r["error"] is None

    class R:
        returncode, stdout = 0, "502 150 4.5 4.6"
    r = agent.grpc_probe(443, 1000, 5, run=lambda *a, **k: R())
    assert not r["ok"] and r["error"] == "http 502, 150 bytes"


def test_probe_runner_result_and_errors(tmp_path, monkeypatch):
    cfg = make_cfg(tmp_path, PROBE_DIR=str(tmp_path / "probe"))
    pr = agent.ProbeRunner(cfg)
    assert pr.round() is None and pr.result is None     # nothing rendered: no supported probe
    pr.rendered = True
    assert agent.ensure_probe_files(cfg)
    seq = [{"ok": False, "setup_ms": 4000, "echo_ok": True, "down_kbps": 1, "up_kbps": 1, "error": None},
           {"ok": True, "setup_ms": 10, "echo_ok": True, "down_kbps": 1, "up_kbps": 1, "error": None}]
    monkeypatch.setattr(agent.probe, "ws_probe", lambda *a, **k: seq.pop(0))
    monkeypatch.setattr(agent.probe, "grpc_probe", lambda *a, **k: {"unsupported": True})
    r = pr.round()
    assert r["ok"] is False and r["consecutive_fail"] == 1 and r["grpc"] == {"unsupported": True}
    assert not pr.first_passed_or_unsupported()
    r = pr.round()
    assert r["ok"] is True and r["consecutive_fail"] == 0 and pr.first_passed_or_unsupported()
    assert agent.probe._clean_err(OSError("connect to 10.1.2.3:443 failed")) == \
        "OSError: connect to [addr] failed"
    assert len(agent.probe._clean_err("x" * 500)) == 120


def test_ws_probe_fails_cleanly_without_a_listener():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    r = agent.ws_probe(port, 1000, 2)
    assert r["ok"] is False and r["setup_ms"] is None and r["error"] and "127.0.0.1" not in r["error"]


# ================================================================= §22.4 multi-origin paths

def mo_path(**kw):
    p = {"id": "grpc1", "path": "/svc", "protocol": "grpc", "origin": {"address": "203.0.113.10", "port": 8443},
         "origins": [{"address": "203.0.113.10", "port": 8443, "tls": False, "sni": None, "verify": False,
                      "weight": 1, "backup": False},
                     {"address": "203.0.113.11", "port": 8443, "tls": False, "backup": True}],
         "balance": "failover", "health": {"type": "tcp", "interval": 10, "timeout": 3}, "idle_timeout": None}
    p.update(kw)
    return p


def test_internal_pool_build():
    pd = agent.norm_tunnel_origins(mo_path())
    assert pd["method"] == "weighted" and pd["protocol"] == "http"
    assert pd["origins"] == [{"hp": "203.0.113.10:8443", "weight": 1, "backup": False},
                             {"hp": "203.0.113.11:8443", "weight": 1, "backup": True}]
    assert pd["health"] == {"enabled": True, "type": "tcp", "path": "/", "interval": 10, "timeout": 3,
                            "expect": "2xx,3xx,4xx", "host": None}
    assert agent.norm_tunnel_origins(mo_path(balance="sticky_ip"))["method"] == "ip_hash"
    rr = mo_path(balance="round_robin", origins=[dict(o, backup=False, weight=w) for o, w in
                                                 zip(mo_path()["origins"], (3, 1))])
    assert [o["weight"] for o in agent.norm_tunnel_origins(rr)["origins"]] == [3, 1]
    tls = mo_path(origins=[{"address": "a.example.net", "port": 443, "tls": True, "sni": "svc.example.net",
                            "verify": True}, {"address": "b.example.net", "port": 443, "tls": True,
                                              "sni": "svc.example.net", "verify": True, "backup": True},
                           {"address": "c.example.net", "port": 443, "tls": False}])   # differs: skipped
    pd = agent.norm_tunnel_origins(tls)
    assert pd["protocol"] == "https" and pd["sni"] == "svc.example.net" and pd["verify"] is True
    assert [o["hp"] for o in pd["origins"]] == ["a.example.net:443", "b.example.net:443"]
    http_h = agent.norm_tunnel_origins(mo_path(health={"type": "http", "path": "/h", "interval": 5, "timeout": 30}))
    assert "type" not in http_h["health"] and http_h["health"]["timeout"] == 4 and http_h["health"]["path"] == "/h"
    assert agent.norm_tunnel_origins(mo_path(origins=[])) is None
    assert agent.norm_tunnel_origins(mo_path(origins=[dict(o, backup=True) for o in mo_path()["origins"]])) is None
    many = mo_path(origins=[{"address": f"203.0.113.{i}", "port": 1} for i in range(1, 15)])
    assert len(agent.norm_tunnel_origins(many)["origins"]) == 10
    t = agent.norm_tunnel(tsite([mo_path()]), {})
    assert t["paths"][0]["pool"] == "tn.grpc1" and t["paths"][0]["origin"] is None
    # an old-style path (origin only) is unchanged; invalid origins fall back to `origin`
    t = agent.norm_tunnel(tsite([mo_path(origins=[{"address": "x y", "port": 1}])]), {})
    assert t["paths"][0]["pool"] is None and t["paths"][0]["origin"]["hp"] == "203.0.113.10:8443"
    old = {"id": "g", "path": "/g", "protocol": "grpc", "origin": {"address": "203.0.113.10", "port": 8443}}
    t = agent.norm_tunnel(tsite([old]), {})
    assert set(t["paths"][0]) == {"id", "path", "protocol", "origin", "pool"}


def test_multi_origin_render_and_sites_js(tmp_path):
    cfg = make_cfg(tmp_path, ORIGIN_PRIVATE_ALLOW="127.0.0.0/8 203.0.113.0/24")
    s = tsite([mo_path(), mo_path(id="w2", path="/w2", protocol="ws",
                                  origins=[{"address": "10.0.0.1", "port": 1}, {"address": "10.0.0.2", "port": 1}])])
    files = agent.render_all({"sites": [s]}, cfg)
    text = files["sites/7.conf"]
    g = loc(text, "/svc")
    assert 'set $pcdn_tn_pool "tn.grpc1";' in g and "set $pcdn_tn_target $pcdn_tn_upstream;" in g
    assert "grpc_pass grpc://$pcdn_tn_target;" in g and "grpc_next_upstream error timeout;" in g
    assert "upstream pcdn_tn_7_p0_0_h2 {\n    server 203.0.113.10:8443 max_fails=0;" in text   # F11 keepalive
    assert '"/w2"' not in text                     # private members dropped -> path without members dropped
    js = json.loads(files["js/sites.js"].split("export default ", 1)[1].rstrip().rstrip(";"))
    pool = js["7"]["pools"]["tn.grpc1"]
    assert pool["health"]["type"] == "tcp" and [o["backup"] for o in pool["origins"]] == [False, True]
    assert pool["origins"][0]["up"] == {"h1": None, "h2": "pcdn_tn_7_p0_0_h2"}
    assert agent.tcp_targets(files) == [["7|tn.grpc1|203.0.113.10:8443", "203.0.113.10", 8443, 10, 3],
                                        ["7|tn.grpc1|203.0.113.11:8443", "203.0.113.11", 8443, 10, 3]]
    # a TLS multi-origin path: the shared sni / verification of its members
    tls = tsite([mo_path(protocol="ws", origins=[
        {"address": "203.0.113.10", "port": 443, "tls": True, "sni": "svc.example.net", "verify": True},
        {"address": "203.0.113.11", "port": 443, "tls": True, "sni": "svc.example.net", "verify": True,
         "backup": True}])])
    w = loc(agent.render_site(tls, cfg)[0], "/svc")
    assert "proxy_ssl_name svc.example.net;" in w and "proxy_ssl_verify on;" in w and "proxy_pass https://" in w
    # customer pools gain health.type tcp (HTTP-checked pools unchanged); tcp pools do not stretch HC_INTERVAL
    pools = agent.norm_pools({"pools": {"pools": [
        {"name": "a", "origins": [{"address": "203.0.113.1", "port": 80}], "health": {"enabled": True, "type": "tcp",
                                                                                      "timeout": 25}},
        {"name": "b", "origins": [], "health": {"enabled": True, "timeout": 25}}]}})
    assert pools["a"]["health"]["type"] == "tcp" and pools["a"]["health"]["timeout"] == 25
    assert "type" not in pools["b"]["health"] and pools["b"]["health"]["timeout"] == 10
    lb = dict(SITE, pools={"pools": [{"name": "a", "origins": [{"address": "203.0.113.1", "port": 80}],
                                      "health": {"enabled": True, "type": "tcp", "timeout": 25}}]},
              hosts=[{"name": "example.com", "origin": {"pool": "a"}}])
    assert "js_periodic pcdn.health interval=2s;" in agent.render_all({"sites": [lb]}, cfg)["http.conf"]


def test_njs_pick_with_tcp_health_entries(tmp_path):
    pools = {"tn.grpc1": {"method": "weighted", "protocol": "http", "health": {"enabled": True, "type": "tcp"},
                          "origins": [{"hp": "203.0.113.10:8443", "weight": 1, "backup": False},
                                      {"hp": "203.0.113.11:8443", "weight": 1, "backup": True}]}}
    sites = {"7": {"domain": "x.test", "secret": "k", "hosts": ["x.test"], "blocked_ips": [], "min_tls": "1.2",
                   "firewall": {"default_action": "allow", "rules": []}, "hotlink": {"enabled": False},
                   "ratelimit": [], "ddos": {"mode": "off"},
                   "waf": {"mode": "off", "groups": [], "exclusions": [], "off_paths": []},
                   "image": {"enabled": False}, "pools": pools, "tunnel_paths": ["/svc"]}}
    res = njs(tmp_path, [
        {"kind": "pick", "site": "7", "pool": "tn.grpc1", "tn": "ws"},
        {"kind": "pick", "site": "7", "pool": "tn.grpc1", "tn": "ws", "hc": {"7|tn.grpc1|203.0.113.10:8443": 1}},
        {"kind": "pick", "site": "7", "pool": "tn.grpc1", "tn": "ws", "hc": {"7|tn.grpc1|203.0.113.10:8443": 2}},
        {"kind": "pick", "site": "7", "pool": "tn.grpc1", "tn": "ws",
         "hc": {"7|tn.grpc1|203.0.113.11:8443": 5}},           # everyone down: fail open to the primary
        {"kind": "hcset", "body": json.dumps({"7|tn.grpc1|203.0.113.10:8443": 0, "bad|key": 1, "1|p|h:1": -1})},
        {"kind": "hcset", "body": "[]"},
        {"kind": "hcset", "body": "{", "method": "POST"},
        {"kind": "hcset", "body": "{}", "method": "GET"},
    ], sites)
    assert res[0] == {"203.0.113.10:8443": 20}                 # failover: the primary only
    assert res[1] == {"203.0.113.10:8443": 20}                 # one failure: still up (HC_FALL 2)
    assert res[2] == {"203.0.113.11:8443": 20}                 # down: new sessions go to the backup
    assert res[3] == {"203.0.113.10:8443": 20}
    assert res[4]["code"] == 200 and res[4]["body"] == "1" and res[4]["store"]["7|tn.grpc1|203.0.113.10:8443"] == 0
    assert [r["code"] for r in res[5:]] == [400, 400, 405]
    src = (EDGE / "njs/pcdn.js").read_text()
    assert "if (!pool.health.enabled || pool.health.tcp) return;" in src    # njs health() skips tcp pools


def test_tcp_checker_and_push(tmp_path):
    cfg = make_cfg(tmp_path)
    lsock = socket.socket()
    lsock.bind(("127.0.0.1", 0))
    lsock.listen(8)
    up_port = lsock.getsockname()[1]
    with socket.socket() as c:
        c.bind(("127.0.0.1", 0))
        closed_port = c.getsockname()[1]
    try:
        assert agent.tcp_check("127.0.0.1", up_port, 2, cfg) is True
        assert agent.tcp_check("127.0.0.1", closed_port, 2, cfg) is False
        # the origin guard: a private address outside ORIGIN_PRIVATE_ALLOW is never connected to
        assert agent.tcp_check("127.0.0.1", up_port, 2, dict(cfg, ORIGIN_PRIVATE_ALLOW="")) is False
        pushed = []
        hc = agent.TcpHealth(cfg, push=lambda d: pushed.append(d))
        hc.set_targets([[f"7|p|127.0.0.1:{up_port}", "127.0.0.1", up_port, 10, 2],
                        [f"7|p|127.0.0.1:{closed_port}", "127.0.0.1", closed_port, 10, 2]])
        assert hc.step(now=1000) == {f"7|p|127.0.0.1:{up_port}": 0, f"7|p|127.0.0.1:{closed_port}": 1}
        assert hc.step(now=1005) == {}                       # not due yet
        assert hc.step(now=1010) == {f"7|p|127.0.0.1:{closed_port}": 2}   # only changes are pushed
        assert hc.step(now=1020) == {f"7|p|127.0.0.1:{closed_port}": 3}
        assert len(hc.step(now=1700)) == 2                   # every entry again after HC_REFRESH
        hc.set_targets([[f"7|p|127.0.0.1:{up_port}", "127.0.0.1", up_port, 10, 2]])
        assert set(hc.fails) == {f"7|p|127.0.0.1:{up_port}"}
        assert not agent.TcpHealth(dict(cfg, ORIGIN_TCP_HEALTH="no")).enabled()
    finally:
        lsock.close()


def test_tcp_targets_persist_in_state(tmp_path, monkeypatch):
    monkeypatch.setattr(agent, "apply_config", lambda config, cfg_, files=None, digest=None:
                        agent.write_tree(cfg_["NGINX_DIR"].rstrip("/"), files))
    a = bare_agent(make_cfg(tmp_path), SeqCtl())
    a.ctl.serve("v1", [tsite([mo_path()])])
    a.sync_config()
    assert [t[0] for t in a.state["hc_targets"]] == ["7|tn.grpc1|203.0.113.10:8443", "7|tn.grpc1|203.0.113.11:8443"]
    assert [t[0] for t in a.tcp_hc.targets] == [t[0] for t in a.state["hc_targets"]]


# ================================================================= §22.5 timeouts

def test_per_path_idle_timeout_and_timer_contract(tmp_path):
    cfg = make_cfg(tmp_path)
    s = tsite([{"id": "w", "path": "/ws", "protocol": "ws", "origin": WS_ORIGIN, "idle_timeout": 120},
               {"id": "g", "path": "/g", "protocol": "grpc", "origin": WS_ORIGIN, "idle_timeout": None},
               {"id": "x", "path": "/x", "protocol": "xhttp", "origin": WS_ORIGIN, "idle_timeout": 99999}])
    text, _ = agent.render_site(s, cfg)
    w, g, x = loc(text, "/ws"), loc(text, "/g"), loc(text, "/x")
    assert "proxy_read_timeout 120s;" in w and "client_body_timeout 120s;" in w and "send_timeout 120s;" in w
    assert "grpc_read_timeout 3600s;" in g                     # null: the site's idle_timeout
    assert "proxy_read_timeout 86400s;" in x                   # clamped to 60..86400
    # server-level timers: the documented contract (controller tunnel.py EDGE_TUNNEL_TIMERS mirrors it)
    assert agent.EDGE_TUNNEL_TIMERS == {"client_idle_s": 600, "max_connection_age_s": 21600, "h2_max_streams": 512,
                                        "tcp_keepalive": {"idle_s": 120, "interval_s": 30, "count": 4},
                                        "connect_timeout_s": 10}
    assert "    keepalive_timeout 600s;\n    keepalive_time 6h;" in text and "    send_timeout 300s;" in text
    http = agent.render_all({"sites": []}, cfg)["http.conf"]
    assert "http2_max_concurrent_streams 512;" in http and "so_keepalive=120s:30s:4" in http
    assert "proxy_connect_timeout 10s;" in http and "grpc_connect_timeout 10s;" in http
    assert agent.norm_tunnel(tsite([{"id": "a", "path": "/a", "protocol": "ws", "idle_timeout": 30}]), {})[
        "paths"][0]["idle_timeout"] == 60
    assert "idle_timeout" not in agent.norm_tunnel(tsite([{"id": "a", "path": "/a", "protocol": "ws",
                                                           "idle_timeout": True}]), {})["paths"][0]


# ================================================================= §22.6 tuning

def test_tuning_profile_table():
    G = 1024 ** 3
    for ram, buf, ct in ((1 * G, 8, 262144), (2 * G - 1, 8, 262144), (2 * G, 32, 524288), (8 * G - 1, 32, 524288),
                         (8 * G, 64, 1048576), (128 * G, 64, 1048576)):
        p = agent.profile(ram)
        b = buf * 1024 * 1024
        assert p == {"net.core.rmem_max": str(b), "net.core.wmem_max": str(b),
                     "net.ipv4.tcp_rmem": f"4096 131072 {b}", "net.ipv4.tcp_wmem": f"4096 65536 {b}",
                     "net.netfilter.nf_conntrack_max": str(ct), "net.ipv4.tcp_notsent_lowat": "131072"}, ram


def test_tuning_writer_idempotent(tmp_path):
    mi = tmp_path / "meminfo"
    mi.write_text("MemTotal:        2048000 kB\n")
    d = tmp_path / "sysctl.d"
    cfg = make_cfg(tmp_path, SYSCTL_DIR=str(d), PROC_MEMINFO=str(mi))
    runs = []
    r1 = agent.write_profile(cfg, run=lambda *a, **k: runs.append(a[0]))
    path = d / agent.MEM_FILE
    assert r1["changed"] and path.read_text().count(" = ") == 6 and "net.core.rmem_max = 8388608" in path.read_text()
    mt = path.stat().st_mtime_ns
    r2 = agent.write_profile(cfg, run=lambda *a, **k: runs.append(a[0]))
    assert not r2["changed"] and path.stat().st_mtime_ns == mt
    # sorts after the static base and the conntrack file (sysctl --system applies files by name)
    assert sorted(["999-pcdn.conf", "999-pcdn-conntrack.conf", agent.MEM_FILE])[-1] == agent.MEM_FILE
    if shutil.which("sysctl"):
        assert runs and runs[0][:3] == ["sysctl", "-q", "-p"]
    r3 = agent.write_profile(dict(cfg, TUNE_PROFILE="off"))
    assert r3["removed"] and not path.exists()


def fake_sys(tmp_path, values):
    root = tmp_path / "sys"
    for k, v in values.items():
        p = root.joinpath(*k.split("."))
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(v + "\n")
    return root


def test_tuning_check_with_fake_proc_sys(tmp_path):
    d = tmp_path / "sysctl.d"
    d.mkdir()
    (d / "999-pcdn.conf").write_text("net.core.default_qdisc = fq\nnet.ipv4.tcp_congestion_control = bbr\n"
                                     "net.core.somaxconn = 65535\nnet.ipv4.ip_local_port_range = 10240 65535\n"
                                     "net.core.rmem_max = 67108864\n# comment\n")
    (d / "999-pcdn-conntrack.conf").write_text("net.netfilter.nf_conntrack_max = 1048576\n")
    mi = tmp_path / "meminfo"
    mi.write_text("MemTotal: 1024000 kB\n")
    cfg = make_cfg(tmp_path, SYSCTL_DIR=str(d), PROC_MEMINFO=str(mi), TCP_CC="bbr")
    agent.write_profile(cfg, run=None)
    good = {"net.core.default_qdisc": "fq", "net.ipv4.tcp_congestion_control": "bbr", "net.core.somaxconn": "65535",
            "net.ipv4.ip_local_port_range": "10240\t65535", "net.core.rmem_max": "8388608",
            "net.core.wmem_max": "8388608", "net.ipv4.tcp_rmem": "4096\t131072\t8388608",
            "net.ipv4.tcp_wmem": "4096\t65536\t8388608", "net.ipv4.tcp_notsent_lowat": "131072",
            "net.ipv4.tcp_available_congestion_control": "reno cubic bbr"}
    proc = tmp_path / "proc"
    (proc / "4242").mkdir(parents=True)
    (proc / "4242/limits").write_text("Limit                     Soft Limit           Hard Limit           Units\n"
                                      "Max open files            1048576              1048576              files\n")
    pidf = tmp_path / "nginx.pid"
    pidf.write_text("4242\n")
    cfg.update(PROC_SYS=str(fake_sys(tmp_path, good)), PROC_DIR=str(proc), NGINX_PID_FILE=str(pidf),
               PROC_ROUTE=str(tmp_path / "noroute"))
    t = agent.check_tuning(cfg)
    assert t == {"profile": "auto", "ram_mb": 1000, "ok": True, "cc": "bbr", "qdisc": None, "nofile": 1048576,
                 "mismatches": []}   # nf_conntrack not loaded (no /proc/sys entry): not verifiable, skipped
    bad = dict(good, **{"net.core.somaxconn": "4096", "net.ipv4.tcp_congestion_control": "cubic",
                        "net.ipv4.tcp_available_congestion_control": "reno cubic",
                        "net.netfilter.nf_conntrack_max": "65536"})
    cfg["PROC_SYS"] = str(fake_sys(tmp_path / "b", bad))
    t = agent.check_tuning(cfg)
    assert not t["ok"] and t["cc"] == "cubic"
    assert {m["key"] for m in t["mismatches"]} == {"net.core.somaxconn", "net.ipv4.tcp_congestion_control",
                                                   "net.ipv4.tcp_available_congestion_control",
                                                   "net.netfilter.nf_conntrack_max"}
    assert {"key": "net.netfilter.nf_conntrack_max", "want": "262144", "have": "65536"} in t["mismatches"]
    assert all(len(m["want"]) <= 64 and len(m["have"]) <= 64 for m in t["mismatches"])
    off = agent.check_tuning(dict(cfg, TUNE_PROFILE="off"))
    assert off["profile"] == "off"
    json.dumps(t)
    # cached hourly
    tc = agent.TuningCheck(cfg)
    v = tc.get(now=0)
    cfg["PROC_SYS"] = str(fake_sys(tmp_path / "c", good))
    assert tc.get(now=100) is v and tc.get(now=3700) is not v


def test_tune_cli(tmp_path, capsys):
    mi = tmp_path / "meminfo"
    mi.write_text("MemTotal: 16000000 kB\n")
    cfg = make_cfg(tmp_path, SYSCTL_DIR=str(tmp_path / "s"), PROC_SYS=str(tmp_path / "nosys"), PROC_MEMINFO=str(mi))
    assert agent.tune_main(cfg, ["--check"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["profile_values"]["net.core.rmem_max"] == str(64 * 1024 * 1024) and out["check"]["ok"] is True
    assert agent.tune_main(dict(cfg, TUNE_PROFILE="off"), ["--write"]) == 0
    assert json.loads(capsys.readouterr().out)["removed"] is False
    # the launcher knows the command (exit 0, JSON)
    env = dict(os.environ, PCDN_CONFIG="/nonexistent", PCDN_SYSCTL_DIR=str(tmp_path / "s"),
               PCDN_PROC_SYS=str(tmp_path / "nosys"))
    p = subprocess.run(["python3", str(EDGE / "pcdn-agent.py"), "tune", "--check"], capture_output=True, text=True,
                       env=env, cwd="/")
    assert p.returncode == 0 and "check" in json.loads(p.stdout), p.stderr


# ================================================================= §22.7 upstream keepalive (host names)

def test_upstream_resolve_capability_and_render(tmp_path):
    v = "nginx version: nginx/{}\nconfigure arguments: --prefix=/etc/nginx --with-http_v3_module\n"
    assert agent.parse_nginx_v(v.format("1.27.2"), exists=lambda p: False)["upstream_resolve"] is False
    assert agent.parse_nginx_v(v.format("1.27.3"), exists=lambda p: False)["upstream_resolve"] is True
    assert agent.LEGACY_CAPS["upstream_resolve"] is False
    paths = [{"id": "g", "path": "/g", "protocol": "grpc", "origin": {"address": "vpn.example.net", "port": 8443}},
             {"id": "w", "path": "/w", "protocol": "ws", "origin": {"address": "vpn.example.net", "port": 8443}}]
    s = tsite(paths, pools={"pools": [{"name": "p", "origins": [{"address": "o.example.net", "port": 80}]}]})
    s["tunnel"]["paths"].append({"id": "x", "path": "/x", "protocol": "xhttp", "pool": "p"})
    old, _ = agent.render_site(s, make_cfg(tmp_path))
    assert " resolve max_fails" not in old and 'set $pcdn_tn_target "vpn.example.net:8443";' in old
    cfg = make_cfg(tmp_path, NGINX_CAPS=dict(agent.LEGACY_CAPS, nginx="1.27.3", http2_directive=True,
                                             upstream_resolve=True))
    new, _ = agent.render_site(s, cfg)
    assert ("upstream pcdn_tn_7_h0 {\n    zone pcdn_tn_7_h0 64k;\n    server vpn.example.net:8443 resolve max_fails=0;\n"
            "    keepalive 64;\n    keepalive_timeout 300s;\n    keepalive_requests 1000000;\n    keepalive_time 1h;\n}") in new
    assert "grpc_pass grpc://pcdn_tn_7_h0;" in loc(new, "/g")
    assert 'set $pcdn_tn_target "vpn.example.net:8443";' in loc(new, "/w")   # ws: never reused, unchanged
    assert "server o.example.net:80 resolve max_fails=0;" in new and "upstream pcdn_tn_7_hp0_0 {" in new
    js = agent.render_all({"sites": [s]}, cfg)["js/sites.js"]
    assert '"up": {"h1": "pcdn_tn_7_hp0_0", "h2": "pcdn_tn_7_hp0_0_h2"}' in js
    caps = agent.heartbeat_capabilities(cfg)
    assert caps["upstream_resolve"] is True and caps["drain"] and caps["tunnel_probe"] and caps["tunnel_multi_origin"]


def tline(**kw):
    e = {"t": "2026-03-01T10:00:30+00:00", "h": "t.com", "b": 500, "s": 101, "c": "", "ip": "1.1.1.1", "cc": "IR",
         "m": "GET", "u": "/ws", "ua": "x", "v": "ok", "tn": "ws", "rt": 30.0, "bu": 200, "ub": "9000", "us": "101",
         "pg": "", "tp": "w1", "uct": "0.004"}
    e.update(kw)
    return e


def write_log(path, rows):
    path.write_text("".join(json.dumps(r) + "\n" for r in rows))


def test_reused_n_counting(tmp_path):
    log = tmp_path / "access.log"
    write_log(log, [tline(uct="0.000"), tline(uct="0.000", tn="xhttp", s=200), tline(uct="0.001"),
                    tline(uct="0.000, 0.000"), tline(uct="0.000", tp=""), tline(uct="-", s=502, us="502")])
    state = {}
    agent.read_usage(state, str(log))
    p = agent.usage_items(state["pending"])[0]["tunnel"]["paths"]["w1"]
    assert p["reused_n"] == 2 and p["connect_n"] == 4


# ================================================================= §22.8 TLS

def test_ticket_keys_files_and_render(tmp_path, caplog):
    cfg = make_cfg(tmp_path)
    raw = [os.urandom(80) for _ in range(3)]
    node = {"tls_tickets": {"id": "a1b2c3d4", "keys": [base64.b64encode(k).decode() for k in raw]}}
    files = agent.render_all({"sites": [], "node": node}, cfg)
    assert [files[f"tickets/{i}.key"] for i in range(3)] == raw
    http = files["http.conf"]
    root = cfg["NGINX_DIR"]
    assert ("ssl_session_tickets on;\n" + "".join(f"ssl_session_ticket_key {root}/tickets/{i}.key;\n" for i in range(3))
            ) in http and "ssl_session_tickets off;" not in http
    agent.write_tree(root, files)
    for i in range(3):
        p = pathlib.Path(root, f"tickets/{i}.key")
        assert p.read_bytes() == raw[i] and p.stat().st_mode & 0o777 == 0o600
    assert (pathlib.Path(root) / "tickets").stat().st_mode & 0o777 == 0o700
    assert "tickets/0.key" in agent.GLOBAL_FILES and agent.global_digest(files) != agent.global_digest(
        agent.render_all({"sites": []}, cfg))
    # off / null / malformed -> off, no files; key material never in a log line
    for bad in (None, {"id": "x", "keys": []}, {"id": "a1b2c3d4", "keys": ["AAAA"]},
                {"id": "a1b2c3d4", "keys": [base64.b64encode(k).decode() for k in raw] + ["x"]},
                {"id": "a1b2c3d4", "keys": "nope"}):
        f2 = agent.render_all({"sites": [], "node": {"tls_tickets": bad}}, cfg)
        assert "ssl_session_tickets off;" in f2["http.conf"] and not any(k.startswith("tickets/") for k in f2)
    import logging
    with caplog.at_level(logging.DEBUG, logger="pcdn-agent"):
        agent.render_all({"sites": [], "node": {"tls_tickets": {"id": "a1b2c3d4", "keys": [
            base64.b64encode(raw[0]).decode(), base64.b64encode(raw[1][:40]).decode()]}}}, cfg)
        agent.render_all({"sites": [], "node": node}, cfg)
    text = caplog.text
    for k in raw:
        assert base64.b64encode(k).decode() not in text and k.hex() not in text
    assert "tls_tickets ignored" in text
    # the old controller: no key -> exactly today's directive
    assert "ssl_session_tickets off;" in agent.render_all({"sites": []}, cfg)["http.conf"]


def ocsp_cert(tmp_path, aia=True, rsa=False):
    key, crt = tmp_path / f"k{aia}{rsa}.pem", tmp_path / f"c{aia}{rsa}.pem"
    args = ["openssl", "req", "-x509", "-nodes", "-subj", "/CN=example.com", "-days", "2", "-keyout", key, "-out", crt]
    args += ["-newkey", "rsa:2048"] if rsa else ["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1"]
    if aia:
        args += ["-addext", "authorityInfoAccess=OCSP;URI:http://ocsp.example.test"]
    subprocess.run(args, check=True, capture_output=True)
    return crt.read_text(), key.read_text()


def test_dual_cert_and_ocsp_stapling(tmp_path):
    cfg = make_cfg(tmp_path)
    cert, key = ocsp_cert(tmp_path, aia=True)
    plain, pkey = ocsp_cert(tmp_path, aia=False)
    rcert, rkey = ocsp_cert(tmp_path, aia=False, rsa=True)
    assert agent.cert_has_ocsp(cert) and not agent.cert_has_ocsp(plain) and not agent.cert_has_ocsp("junk")
    s = dict(SITE, rate_limit_rps=0, hosts=[{"name": "example.com", "origin": {"address": "127.0.0.1", "port": 1}}],
             ssl={"cert": cert, "key": key, "cert_rsa": rcert, "key_rsa": rkey, "ocsp": True})
    text, files = agent.render_site(s, cfg)
    root = cfg["NGINX_DIR"]
    assert files["certs/7.rsa.crt"] == rcert and files["certs/7.rsa.key"] == rkey
    assert (f"    ssl_certificate {root}/certs/7.crt;\n    ssl_certificate_key {root}/certs/7.key;\n"
            f"    ssl_certificate {root}/certs/7.rsa.crt;\n    ssl_certificate_key {root}/certs/7.rsa.key;\n"
            f"    ssl_stapling on;\n    ssl_stapling_verify on;\n    ssl_trusted_certificate {cfg['CA_BUNDLE']};") in text
    assert agent.cert_digests(files) == agent.cert_digests(dict(files)) and "7" in agent.cert_digests(files)
    # the controller asks for stapling but the leaf has no OCSP URL: never rendered
    t2, _ = agent.render_site(dict(s, ssl={"cert": plain, "key": pkey, "ocsp": True}), cfg)
    assert "ssl_stapling" not in t2 and ".rsa." not in t2
    t3, f3 = agent.render_site(dict(s, ssl={"cert": cert, "key": key}), cfg)   # an old controller
    assert "ssl_stapling" not in t3 and set(f3) == {"certs/7.crt", "certs/7.key"}
    if shutil.which("nginx"):
        from conftest import modules_available, nginx_conf
        if modules_available():
            c2 = dict(cfg, LISTEN_IPV6="no", HTTP_PORT="18780", HTTPS_PORT="18743")
            assert agent.apply_config({"sites": [s], "node": {"tls_tickets": {"id": "a1b2c3d4", "keys": [
                base64.b64encode(os.urandom(80)).decode()] * 3}}}, c2) is None
            p = subprocess.run(["nginx", "-t", "-c", str(nginx_conf(tmp_path, c2))], capture_output=True, text=True)
            assert p.returncode == 0, p.stderr


# ================================================================= §22.9 HTTP/3 gate

def test_http3_node_switch(tmp_path):
    cert, key = self_signed(tmp_path)
    caps = dict(agent.LEGACY_CAPS, nginx="1.29.1", http3=True, http2_directive=True)
    cfg = make_cfg(tmp_path, NGINX_CAPS=caps)
    s = dict(SITE, rate_limit_rps=0, hosts=[{"name": "example.com", "origin": {"address": "127.0.0.1", "port": 1}}],
             ssl={"cert": cert, "key": key})
    for node, want in ((None, True), ({}, True), ({"http3": True}, True), ({"http3": False}, False)):
        body = {"sites": [s]} if node is None else {"sites": [s], "node": node}
        files = agent.render_all(body, cfg)
        assert ("listen 443 quic;" in files["sites/7.conf"]) is want, node
        assert ("quic default_server reuseport" in files["http.conf"]) is want, node
    no_caps = agent.render_all({"sites": [s], "node": {"http3": True}}, make_cfg(tmp_path))
    assert "quic" not in no_caps["sites/7.conf"]


# ================================================================= §22.12 session ends

def ends_of(tmp_path, rows, state=None):
    """Per-path wire entries of t.com, summed over its host-hours."""
    log = tmp_path / "access.log"
    write_log(log, rows)
    state = state if state is not None else {}
    agent.read_usage(state, str(log))
    out = {}
    for item in agent.usage_items(state["pending"]):
        for pid, p in ((item.get("tunnel") or {}).get("paths") or {}).items():
            q = out.setdefault(pid, {"sessions": 0, "ends": dict.fromkeys(agent.TUNNEL_END_KEYS, 0)})
            q["sessions"] += p["sessions"]
            for k, v in p["ends"].items():
                q["ends"][k] += v
    return out, state


def ts(s):
    from datetime import datetime
    return datetime.fromisoformat(s).timestamp()


def test_session_end_classification(tmp_path):
    R = ts("2026-03-01T09:00:00+00:00")
    state = {"reload_times": [R], "wst_s": 1800,
             "forced_shutdowns": [{"t": ts("2026-03-01T10:20:00+00:00"), "pid": 9}],
             "drain_log": [{"s": "2026-03-01T10:40:00Z", "u": "2026-03-01T10:50:00Z", "r": None}]}
    rows = [
        tline(t="2026-03-01T10:00:30+00:00", rt=30.0),                    # normal
        tline(t="2026-03-01T09:30:02+00:00", rt=3600.0),                  # started before R, ended at R + WST
        tline(t="2026-03-01T09:30:20+00:00", rt=3600.0),                  # 20 s off R + WST: normal
        tline(t="2026-03-01T09:30:02+00:00", rt=60.0),                    # started after R: normal
        tline(t="2026-03-01T10:20:03+00:00", rt=700.0),                   # forced worker shutdown
        tline(t="2026-03-01T10:51:00+00:00", rt=1200.0),                  # drained at until + 60 s
        tline(t="2026-03-01T10:49:58+00:00", rt=1200.0),                  # until - 2 s
        tline(t="2026-03-01T10:45:00+00:00", rt=1200.0),                  # mid-drain: normal (app closed it)
        tline(t="2026-03-01T10:51:00+00:00", rt=30.0),                    # started after the drain began
        tline(t="2026-03-01T10:00:30+00:00", s=499, us="200", tn="grpc", tp="g1"),   # client closed: normal
        tline(t="2026-03-01T10:00:30+00:00", s=502, us="502", uct="-"),   # not accepted: no end at all
    ]
    paths, _ = ends_of(tmp_path, rows, state)
    assert paths["w1"]["ends"] == {"normal": 5, "idle_timeout": 0, "origin": 0, "node_reload": 2, "node_drain": 2,
                                   "other": 0}
    assert sum(paths["w1"]["ends"].values()) == paths["w1"]["sessions"] == 9
    assert paths["g1"]["ends"]["normal"] == 1


def test_session_end_upgrade_restart_window(tmp_path):
    d = {"state": "draining", "since": "2026-03-01T10:00:00Z", "until": "2026-03-01T11:00:00Z",
         "restart_at": "2026-03-01T10:30:00Z", "upgrade": True}
    rows = [tline(t="2026-03-01T10:30:40+00:00", rt=3600.0),               # ended at the agent restart
            tline(t="2026-03-01T10:20:00+00:00", rt=3600.0)]               # before it: normal
    paths, _ = ends_of(tmp_path, rows, {"drain": d})
    assert paths["w1"]["ends"]["node_drain"] == 1 and paths["w1"]["ends"]["normal"] == 1


def test_error_log_ends_subtracted_never_negative(tmp_path):
    state = {"tunnel_map": {"t.com": [["/ws", "w1"]]}}
    paths, state = ends_of(tmp_path, [tline(), tline()], state)
    from datetime import datetime, timezone

    def lt(sec):   # nginx writes its error log in local time
        return datetime(2026, 3, 1, 10, 0, sec, tzinfo=timezone.utc).astimezone().strftime("%Y/%m/%d %H:%M:%S")
    err = ("2026/03/01 10:00:31 [error] 11#11: *5 upstream timed out (110: Connection timed out) while proxying "
           'upgraded connection, client: 1.1.1.1, server: t.com, request: "GET /ws HTTP/1.1", upstream: '
           '"http://1.2.3.4:80/ws", host: "t.com"\n'
           "2026/03/01 10:00:32 [error] 11#11: *6 recv() failed (104: Connection reset by peer) while proxying "
           'upgraded connection, client: 1.1.1.1, server: t.com, request: "GET /ws HTTP/1.1", upstream: '
           '"http://1.2.3.4:80/ws", host: "t.com"\n'
           "2026/03/01 10:00:33 [info] 11#11: *7 client timed out (110: Connection timed out) while proxying "
           'upgraded connection, client: 1.1.1.1, server: t.com, request: "GET /ws HTTP/1.1", upstream: '
           '"http://1.2.3.4:80/ws", host: "t.com"\n'
           "2026/03/01 10:00:34 [info] 11#11: *8 client closed connection while proxying upgraded connection, "
           'client: 1.1.1.1, server: t.com, request: "GET /ws HTTP/1.1", host: "t.com"\n'
           "2026/03/01 10:00:35 [error] 11#11: *9 upstream sent invalid header while reading upstream, "
           'client: 1.1.1.1, server: t.com, request: "GET /ws HTTP/1.1", host: "t.com"\n')
    for sec in range(31, 36):
        err = err.replace(f"2026/03/01 10:00:{sec}", lt(sec))
    assert agent.account_abnormal(state, err) == 3          # §15.1 abnormal: [error] lines only, unchanged
    item = agent.usage_items(state["pending"])
    p = [i for i in item if i["host"] == "t.com"][0]["tunnel"]["paths"]["w1"]
    assert p["abnormal"] == 3
    assert p["ends"] == {"normal": 0, "idle_timeout": 2, "origin": 1, "node_reload": 0, "node_drain": 0, "other": 1}
    assert agent.end_class("info", "client closed connection") is None
    # ends of non-tunnel lines: none
    paths2, st2 = ends_of(tmp_path, [tline(tn="", tp="", u="/")])
    assert "tunnel" not in agent.usage_items(st2["pending"])[0]
    assert agent.tpath_item({"ends": {"normal": 1}, "ends_err": {"origin": 5}})["ends"]["normal"] == 0


def test_end_reason_rules():
    ctx = {"reloads": [1000.0], "wst": 600, "forced": [5000.0], "drains": [(8000.0, 9000.0, None)]}
    assert agent.end_reason(ctx, 900, 1603) == "node_reload"
    assert agent.end_reason(ctx, 900, 1606) is None
    assert agent.end_reason(ctx, 1001, 1600) is None
    assert agent.end_reason(dict(ctx, wst=None), 900, 1600) is None
    assert agent.end_reason(ctx, 4000, 5005) == "node_reload" and agent.end_reason(ctx, 4000, 5006) is None
    assert agent.end_reason(ctx, 7000, 8997) == "node_drain" and agent.end_reason(ctx, 7000, 9120) == "node_drain"
    assert agent.end_reason(ctx, 7000, 9121) is None and agent.end_reason(ctx, 8001, 9000) is None
    assert agent.end_reason(None, 1, 2) is None


# ================================================================= heartbeat / old controller

def test_wave13_heartbeat_objects(tmp_path, monkeypatch):
    ngx = tmp_path / "nginx.conf"
    ngx.write_text("worker_shutdown_timeout 2h;\n")
    cfg = make_cfg(tmp_path, NGINX_CONF=str(ngx), SYSCTL_DIR=str(tmp_path / "none"), PROC_SYS=str(tmp_path / "none"),
                   MEM_GUARD_PCT="0")
    a = bare_agent(cfg, state={"drain": {"state": "draining", "since": "2030-01-01T00:00:00Z"},
                               "reload_times": [time.time() - 10]})
    out = a.wave13_heartbeat({"connections": 12, "mem_pct": 50.0})
    assert out["drain"] == {"state": "draining", "conns": 12, "since": "2030-01-01T00:00:00Z"}
    assert out["reloads"]["count_1h"] == 1 and out["reloads"]["wst_s"] == 7200
    assert set(out["reloads"]) == {"count_1h", "count_24h", "last_at", "coalesced_1h", "pending_s", "deferred",
                                   "wst_s", "forced_shutdowns_24h"}
    assert set(out["tuning"]) == {"profile", "ram_mb", "ok", "cc", "qdisc", "nofile", "mismatches"}
    assert "tunnel_probe" not in out                  # no supported probe yet: the field is omitted
    a.probe_runner.result = {"at": "x", "ok": True, "ws": {}, "grpc": {"unsupported": True}, "consecutive_fail": 0}
    assert a.wave13_heartbeat({"connections": 0})["tunnel_probe"]["ok"] is True
    json.dumps(out)


def test_old_controller_config_renders_as_before(tmp_path):
    """A config without any wave-13 key renders the same tree as one with every key at its default."""
    cfg = make_cfg(tmp_path)
    s = tsite([{"id": "w", "path": "/ws", "protocol": "ws", "origin": WS_ORIGIN}])
    a = agent.render_tree({"sites": [s]}, cfg)[1]
    b = agent.render_tree({"sites": [s], "node": {"drain": {"state": ""}, "probe": {"origin": None},
                                                    "http3": True, "tls_tickets": None, "dns_weight": None}}, cfg)[1]
    assert a == b


def test_threads_never_block_the_loop(tmp_path):
    """The probe / TCP health threads are daemons started by loop(), not by the constructor."""
    from conftest import pick_port
    cfg = make_cfg(tmp_path, CONTROLLER_URL="http://c", EDGE_TOKEN="t", PROBE_ECHO_PORT=str(pick_port()))
    before = threading.active_count()
    a = agent.Agent(cfg)
    assert threading.active_count() == before
    a.start_background()
    try:
        assert a.probe_runner.thread.daemon and a.tcp_hc.thread.daemon
    finally:
        a.probe_runner.stop()
        a.tcp_hc.stop()
        a._echo.stop()


def test_controller_path_shape_with_null_keys(tmp_path):
    """The controller always sends origins / balance / health / idle_timeout (null when unset) and, with
    origins, the default balance "failover" and health {type tcp, interval 10, timeout 3, path, expect}."""
    plain = {"id": "w", "path": "/ws", "protocol": "ws", "origin": WS_ORIGIN, "pool": None,
             "origins": None, "balance": None, "health": None, "idle_timeout": None}
    t = agent.norm_tunnel(tsite([plain]), {})
    assert t["paths"][0]["origin"]["hp"] == "198.51.100.10:8443" and t["paths"][0]["pool"] is None
    assert "idle_timeout" not in t["paths"][0]
    multi = dict(plain, origins=mo_path()["origins"], balance="failover",
                 health={"type": "tcp", "interval": 10, "timeout": 3, "path": "/", "expect": "2xx,3xx,4xx"})
    t = agent.norm_tunnel(tsite([multi]), {})
    assert t["paths"][0]["pool"] == "tn.w" and t["paths"][0]["pool_def"]["health"]["type"] == "tcp"
    # node block as the controller sends it (dns_weight null when off, probe interval 60)
    body = {"sites": [tsite([plain])], "node": {"name": "n", "capacity_mbps": 0, "fair_share_pct": 25,
                                                 "drain": {"state": "", "refuse_after": None, "until": None},
                                                 "probe": {"origin": None, "interval": 60}, "http3": True,
                                                 "tls_tickets": None, "dns_weight": None}}
    assert agent.norm_probe_node(body) == {"origin": None, "interval": 60}
    assert agent.norm_drain(body)["state"] == ""
    assert agent.render_tree(body, make_cfg(tmp_path))[1] == agent.render_tree(
        dict(body, node={"name": "n", "capacity_mbps": 0, "fair_share_pct": 25}), make_cfg(tmp_path))[1]



def test_controller_undrain_ends_a_drained_node_promptly(tmp_path, monkeypatch):
    """CI regression: drain -> the node turns "drained" (bumping `at`) -> the admin undrains. The agent
    must end the drain on the next config, and keep honouring the controller's view while later config
    polls are 304s (it used to wait DRAIN_LAG_S after `at` and was never re-evaluated on a 304)."""
    flags = []
    monkeypatch.setattr(agent, "set_flag", lambda c, on, opener=None: flags.append(on) or True)
    monkeypatch.setattr(agent, "public_conns", lambda c: 0)
    a = bare_agent(make_cfg(tmp_path))
    on = {"state": "draining", "refuse_after": 1100.0, "until": 9000.0}
    a.state["ctl_drain"] = on
    assert agent.apply_config_drain(a.state, on, 1000) == "start"
    a.drain_step(1000)
    a.drain_step(1010)                       # 0 connections twice -> drained (at = 1010)
    assert a.state["drain"]["state"] == "drained"
    a.drain_step(1100)                       # grace over: refusing
    assert flags[-1] is True
    # the admin undrains at 1110; the next config (a full fetch) shows it 10 s after `at` was bumped
    a.state["ctl_drain"] = {"state": "", "refuse_after": None, "until": None}
    assert agent.apply_config_drain(a.state, a.state["ctl_drain"], 1120) == "end"
    a.drain_step(1120)
    assert a.state["drain"]["state"] == "" and flags[-1] is False and "drain_flag" not in a.state
    # a later 304 poll never revives it; drain_step alone re-evaluates the kept controller view
    a.drain_step(1130)
    assert a.state["drain"]["state"] == "" and flags[-1] is False
    # the CLI starts a new drain: the stale controller view is dropped until a fresh config shows it
    a.state["ctl_drain"] = on
    agent.merge_disk_drain(a.state, {"drain": {"state": "", "at": 2000.0}})
    assert "ctl_drain" not in a.state


def test_sync_config_304_still_ends_a_drain(tmp_path, monkeypatch):
    monkeypatch.setattr(agent, "set_flag", lambda c, on, opener=None: True)
    monkeypatch.setattr(agent, "apply_config", lambda config, cfg_, files=None, digest=None:
                        agent.write_tree(cfg_["NGINX_DIR"].rstrip("/"), files))

    class Ctl(SeqCtl):
        def __init__(self):
            super().__init__()
            self.not_modified = False

        def call(self, method, path, body=None, headers=None, timeout=30):
            if path == "/edge/v1/config" and self.not_modified:
                return 304, {}, None
            return super().call(method, path, body, headers, timeout)
    a = bare_agent(make_cfg(tmp_path), Ctl())
    now = time.time()
    a.ctl.serve("v1", [MINSITE], node={"drain": {"state": "draining", "refuse_after": agent.iso(now - 10),
                                                 "until": agent.iso(now + 600)}})
    a.sync_config()
    a.state["drain"]["state"], a.state["drain"]["at"] = "drained", time.time()
    a.ctl.serve("v2", [MINSITE], node={"drain": {"state": ""}})
    a.sync_config()
    assert a.state["drain"]["state"] == ""
    a.ctl.not_modified = True
    a.sync_config()
    a.drain_step()
    assert a.state["drain"]["state"] == ""
