"""Wave 14 (SPEC §23, agent B): release safety, operations and customer experience on the edge - unit
tests: public node tag (X-Served-By / X-Pcdn-Node), node.upgrade + the self-upgrade state machine (fake
controller, PATH shims for systemd-run / systemctl), heartbeat release / upgrade / capabilities, live
oe / pe, RUM (bucket contract, aggregation, rendering, njs ingestion, beacon script under node),
install.sh / bootstrap.sh blocks (release check / files, join flow, --version, last-edge exit).

The real-nginx scenarios (RUM injection and ingestion, the RUM log, X-Served-By) are in
test_wave14_e2e.py."""

import hashlib
import io
import json
import os
import pathlib
import shutil
import subprocess
import tarfile
import urllib.error

import pytest

from test_agent import SITE, agent, make_cfg

HERE = pathlib.Path(__file__).resolve().parent
EDGE = HERE.parent
T_HOUR = "2026-10-03T10:00:00+00:00"


def _block(path, start, end):
    text = (EDGE / path).read_text()
    return text.split(start, 1)[1].split("\n", 1)[1].split(end, 1)[0]


def _run(script, cwd=None, **env):
    base = {"PATH": os.environ.get("PATH", "/usr/bin:/bin")}
    base.update(env)
    return subprocess.run(["bash", "-euo", "pipefail", "-c", script], capture_output=True, text=True, env=base,
                          cwd=cwd)


MINSITE = {"id": 3, "domain": "m.test", "status": "active", "secret": "s",
           "hosts": [{"name": "m.test", "origin": {"address": "127.0.0.1", "port": 18080}}], "ssl": None,
           "edge_group": "general", "cache": {"enabled": True, "level": "standard", "edge_ttl": 60}}


# ================================================================= §23.12.2 public node tag

def test_public_tag_normalisation_and_fallback(tmp_path):
    cfg = make_cfg(tmp_path, NODE_NAME="edge-1")
    assert agent.norm_node({"node": {"public_tag": "0a1b2c3d"}}, cfg)["public_tag"] == "0a1b2c3d"
    for bad in ("0A1B2C3D", "0a1b2c3", "0a1b2c3d9", "zzzzzzzz", 12345678, None, ["0a1b2c3d"]):
        assert agent.norm_node({"node": {"public_tag": bad}}, cfg)["public_tag"] == "", bad
    assert agent.served_tag({"public_tag": "0a1b2c3d", "name": "edge-1"}) == "0a1b2c3d"
    # an old controller (no public_tag): today's name hash, never the name itself
    fb = agent.served_tag({"public_tag": "", "name": "edge-1"})
    assert fb == agent.node_tag("edge-1") and "edge" not in fb and len(fb) == 8


def test_x_served_by_renders_the_tag_never_hostname(tmp_path):
    cfg = make_cfg(tmp_path, NODE_NAME="edge-secret-1")
    body = {"sites": [MINSITE, dict(SITE)], "node": {"name": "edge-secret-1", "public_tag": "5f00ba11"}}
    files, _ = agent.render_tree(body, cfg)
    sites = "".join(v for k, v in files.items() if k.startswith("sites/"))
    assert "X-Served-By $hostname" not in sites and "$hostname" not in sites
    assert sites.count("add_header X-Served-By $pcdn_node always;") >= 2
    http = files["http.conf"]
    assert 'default "5f00ba11";' in http.split("map $uri $pcdn_node {", 1)[1].split("}", 1)[0]
    assert "edge-secret-1" not in http and "edge-secret-1" not in sites
    # speed test header comes from the same variable
    assert "add_header X-Pcdn-Node $pcdn_node always;" in sites
    # without the key (old controller) the hash of the name - still not the name or the host name
    files, _ = agent.render_tree({"sites": [MINSITE], "node": {"name": "edge-secret-1"}}, cfg)
    tag = files["http.conf"].split("map $uri $pcdn_node {", 1)[1].split("}", 1)[0]
    assert agent.node_tag("edge-secret-1") in tag and "edge-secret" not in tag


def test_upgrade_key_is_not_rendered_but_public_tag_is(tmp_path):
    cfg = make_cfg(tmp_path)
    base = {"sites": [MINSITE], "node": {"name": "n1", "capacity_mbps": 100}}
    d0 = agent.render_tree(base, cfg)[1]
    body = json.loads(json.dumps(base))
    body["node"]["upgrade"] = {"id": "4-1", "release": "v2.1.0", "sha256": "a" * 64, "drain_minutes": 15,
                               "rollback": False, "timeout_s": 3600}
    assert agent.render_tree(body, cfg)[1] == d0
    body["node"]["upgrade"] = None
    assert agent.render_tree(body, cfg)[1] == d0
    body["node"]["public_tag"] = "0123abcd"
    assert agent.render_tree(body, cfg)[1] != d0


# ================================================================= §23.2 node.upgrade + self-upgrade

GOOD_UP = {"id": "7-1", "release": "v2.1.0", "sha256": "ab" * 32, "drain_minutes": 15, "rollback": False,
           "timeout_s": 3600}


def test_norm_upgrade_shapes():
    assert agent.norm_upgrade({}) is None and agent.norm_upgrade({"node": {}}) is None
    assert agent.norm_upgrade({"node": {"upgrade": None}}) is None
    u = agent.norm_upgrade({"node": {"upgrade": dict(GOOD_UP, sha256="AB" * 32)}})
    assert u == dict(GOOD_UP, sha256="ab" * 32)
    u = agent.norm_upgrade({"node": {"upgrade": {"id": "9-2", "release": "v2.1.0-rc.1", "sha256": "0" * 64}}})
    assert u["drain_minutes"] == 15 and u["timeout_s"] == 3600 and u["rollback"] is False
    assert agent.norm_upgrade({"node": {"upgrade": dict(GOOD_UP, drain_minutes=0)}})["drain_minutes"] == 0
    assert agent.norm_upgrade({"node": {"upgrade": dict(GOOD_UP, drain_minutes=500)}})["drain_minutes"] == 120
    for bad in ({"release": "2.1.0"}, {"release": "v2.1"}, {"release": "v2.1.0; rm -rf /"}, {"sha256": "x" * 64},
                {"sha256": "ab"}, {"id": ""}, {"id": "a b"}, {"id": "x" * 65}):
        assert agent.norm_upgrade({"node": {"upgrade": dict(GOOD_UP, **bad)}}) is None, bad
    assert agent.norm_upgrade({"node": {"upgrade": "v2.1.0"}}) is None
    assert agent.unit_name("7-1") == "pcdn-upgrade-7-1" and agent.unit_name("a:b/c") == "pcdn-upgrade-a_b_c"


def make_bundle(path, release="v2.1.0", install="exit 0\n"):
    """A release tarball like build-edge-bundle.sh makes: top dir edge/, edge/RELEASE, edge/install.sh."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as t:
        for name, data in (("edge/RELEASE", release + "\n"), ("edge/install.sh", "#!/bin/bash\n# --release) x\n" + install)):
            b = data.encode()
            ti = tarfile.TarInfo(name)
            ti.size, ti.mode = len(b), 0o755
            t.addfile(ti, io.BytesIO(b))
    path.write_bytes(buf.getvalue())
    return hashlib.sha256(buf.getvalue()).hexdigest()


class Shims:
    """PATH shims: systemd-run records its arguments; systemctl answers `show` from a props file."""

    def __init__(self, tmp, monkeypatch):
        self.bin = tmp / "bin"
        self.bin.mkdir()
        self.calls = tmp / "systemd-run.calls"
        self.props = tmp / "systemctl.props"
        self.rc = tmp / "systemd-run.rc"
        (self.bin / "systemd-run").write_text(
            f'#!/bin/bash\nprintf "%s\\n" "$@" > {self.calls}\nexit "$(cat {self.rc} 2>/dev/null || echo 0)"\n')
        (self.bin / "systemctl").write_text(f'#!/bin/bash\ncat {self.props} 2>/dev/null\nexit 0\n')
        for f in self.bin.iterdir():
            f.chmod(0o755)
        monkeypatch.setenv("PATH", f"{self.bin}:{os.environ.get('PATH', '/usr/bin:/bin')}")

    def args(self):
        return self.calls.read_text().splitlines() if self.calls.exists() else None


class FakeDownload:
    def __init__(self, data=b"", code=200):
        self.data, self.code, self.urls = data, code, []

    def __call__(self, req, timeout=None):
        self.urls.append(req.full_url)
        if self.code != 200:
            raise urllib.error.HTTPError(req.full_url, self.code, "x", {}, None)
        return io.BytesIO(self.data)


def up_cfg(tmp_path, **over):
    return make_cfg(tmp_path, CONTROLLER_URL="https://ctl.test", RELEASE_FILE=str(tmp_path / "release"),
                    UPGRADE_DIR=str(tmp_path / "upgrade"), RELEASES_DIR=str(tmp_path / "releases"), **over)


def test_upgrade_downloads_verifies_and_starts_the_installer(tmp_path, monkeypatch):
    sh = Shims(tmp_path, monkeypatch)
    cfg = up_cfg(tmp_path)
    (tmp_path / "release").write_text("v2.0.0\n")
    tb = tmp_path / "b.tgz"
    sha = make_bundle(tb)
    dl, state, saves = FakeDownload(tb.read_bytes()), {}, []
    up = agent.Upgrader(cfg, state, save=lambda: saves.append(json.loads(json.dumps(state.get("upgrade")))),
                        opener=dl)
    up.step(dict(GOOD_UP, sha256=sha))
    assert dl.urls == ["https://ctl.test/edge/bundle.tar.gz?version=v2.1.0"]
    u = state["upgrade"]
    assert u["state"] == "installing" and u["release"] == "v2.1.0" and u["id"] == "7-1"
    # recorded as installing BEFORE systemd-run ran
    assert [s["state"] for s in saves][:2] == ["downloading", "installing"]
    a = sh.args()
    assert "--unit=pcdn-upgrade-7-1" in a and "--collect" in a and "--property=TimeoutStartSec=3600" in a
    i = a.index("-c")
    script, rest = a[i + 2], a[i + 3:]
    assert script.endswith("/x/edge/install.sh") and rest == ["--upgrade", "--release", "v2.1.0", "--drain=15"]
    assert any(x.startswith("--setenv=PCDN_RELEASE_TARBALL=") for x in a)
    d = pathlib.Path(u["dir"])
    assert d.parent == tmp_path / "upgrade" and oct(d.stat().st_mode & 0o777) == "0o700"
    assert (d / "x/edge/RELEASE").read_text().strip() == "v2.1.0"
    # the agent's heartbeat object
    hb = agent.heartbeat_upgrade(state)
    assert set(hb) == {"id", "release", "state", "error", "at", "rollback"} and hb["state"] == "installing"
    # a second poll while the installer runs: nothing changes; the same id is never started twice
    sh.calls.unlink()
    up.step(dict(GOOD_UP, sha256=sha))
    assert state["upgrade"]["state"] == "installing" and sh.args() is None
    # never two upgrades at once: another id waits
    up.step(dict(GOOD_UP, id="8-1", release="v2.2.0", sha256=sha))
    assert state["upgrade"]["id"] == "7-1" and sh.args() is None
    # the installer replaced the release and restarted the agent: the NEW agent finds its release -> done
    (tmp_path / "release").write_text("v2.1.0\n")
    state2 = json.loads(json.dumps(state))
    agent.Upgrader(cfg, state2, opener=dl).step(None)
    assert state2["upgrade"]["state"] == "done" and state2["upgrade"]["error"] is None


def test_upgrade_reuses_a_cached_tarball_and_rejects_a_bad_sha(tmp_path, monkeypatch):
    sh = Shims(tmp_path, monkeypatch)
    cfg = up_cfg(tmp_path)
    (tmp_path / "releases").mkdir()
    sha = make_bundle(tmp_path / "releases/v2.1.0.tar.gz")
    dl, state = FakeDownload(b"never"), {}
    agent.Upgrader(cfg, state, opener=dl).step(dict(GOOD_UP, sha256=sha))
    assert dl.urls == [] and state["upgrade"]["state"] == "installing"
    assert f"--setenv=PCDN_RELEASE_TARBALL={tmp_path}/releases/v2.1.0.tar.gz" in sh.args()
    # sha mismatch (cached file does not match -> downloaded; the download does not match either)
    state = {}
    sh.calls.unlink()
    other = tmp_path / "other.tgz"
    make_bundle(other, install="echo other\n")
    dl = FakeDownload(other.read_bytes())
    agent.Upgrader(cfg, state, opener=dl).step(dict(GOOD_UP, id="7-2", sha256="0" * 64))
    assert dl.urls and state["upgrade"]["state"] == "failed" and state["upgrade"]["error"] == "sha256_mismatch"
    assert sh.args() is None and not list((tmp_path / "upgrade").iterdir())   # nothing left, nothing run
    # an unreachable bundle
    state = {}
    agent.Upgrader(cfg, state, opener=FakeDownload(code=404)).step(dict(GOOD_UP, id="7-3", sha256="0" * 64))
    assert state["upgrade"]["state"] == "failed" and state["upgrade"]["error"] == "download_failed: HTTP 404"


def test_upgrade_idempotent_for_the_running_release_and_off_switch(tmp_path, monkeypatch):
    sh = Shims(tmp_path, monkeypatch)
    cfg = up_cfg(tmp_path)
    (tmp_path / "release").write_text("v2.1.0\n")
    dl, state = FakeDownload(), {}
    agent.Upgrader(cfg, state, opener=dl).step(GOOD_UP)
    assert state["upgrade"]["state"] == "done" and dl.urls == [] and sh.args() is None
    # a rollback to the running release is the same
    state = {}
    agent.Upgrader(cfg, state, opener=dl).step(dict(GOOD_UP, id="3-1", rollback=True))
    assert state["upgrade"]["state"] == "done" and state["upgrade"]["rollback"] is True
    # SELF_UPGRADE=no: nothing happens, the capability is false
    (tmp_path / "release").write_text("v2.0.0\n")
    cfg_off, state = up_cfg(tmp_path, SELF_UPGRADE="no"), {}
    agent.Upgrader(cfg_off, state, opener=dl).step(GOOD_UP)
    assert state == {} and dl.urls == []
    assert agent.heartbeat_capabilities(cfg_off)["self_upgrade"] is False
    assert agent.heartbeat_capabilities(cfg)["self_upgrade"] is True   # systemd-run shim on PATH
    assert agent.heartbeat_upgrade({}) is None


def test_upgrade_failures_exit_status_last_edge_and_timeout(tmp_path, monkeypatch):
    sh = Shims(tmp_path, monkeypatch)
    cfg = up_cfg(tmp_path)
    (tmp_path / "release").write_text("v2.0.0\n")
    tb = tmp_path / "b.tgz"
    sha = make_bundle(tb)
    now = [1_800_000_000.0]

    def started(uid):
        state = {}
        up = agent.Upgrader(cfg, state, opener=FakeDownload(tb.read_bytes()), now=lambda: now[0])
        up.step(dict(GOOD_UP, id=uid, sha256=sha))
        assert state["upgrade"]["state"] == "installing"
        return up, state

    for rc, err in (("1", "install_failed: exit 1"), ("3", "last_edge"), ("0", "release_mismatch")):
        up, state = started("s" + rc)
        pathlib.Path(state["upgrade"]["status_file"]).write_text(rc + "\n")
        up.step(None)
        assert state["upgrade"]["state"] == "failed" and state["upgrade"]["error"] == err, rc
    # no status file (the wrapper never ran), but systemd still knows the failed unit
    up, state = started("u1")
    sh.props.write_text("LoadState=loaded\nActiveState=failed\nResult=exit-code\nExecMainStatus=2\n")
    up.step(None)
    assert state["upgrade"]["error"] == "install_failed: exit 2"
    # a running unit, then timeout_s passes without the release changing
    up, state = started("t1")
    sh.props.write_text("LoadState=loaded\nActiveState=active\nResult=success\nExecMainStatus=0\n")
    up.step(None)
    assert state["upgrade"]["state"] == "installing"
    now[0] += 3601
    up.step(None)
    assert state["upgrade"]["state"] == "failed" and state["upgrade"]["error"] == "timeout"
    # an agent restart during the download: that attempt is over
    state = {"upgrade": {"id": "d1", "release": "v2.1.0", "state": "downloading", "started": "2026-10-03T10:00:00Z"}}
    agent.Upgrader(cfg, state).step(None)
    assert state["upgrade"]["state"] == "failed" and state["upgrade"]["error"] == "interrupted"
    # systemd-run itself refuses
    sh.rc.write_text("1")
    state = {}
    agent.Upgrader(cfg, state, opener=FakeDownload(tb.read_bytes())).step(dict(GOOD_UP, id="r1", sha256=sha))
    assert state["upgrade"]["state"] == "failed" and state["upgrade"]["error"] == "systemd_run_failed: exit 1"


def test_upgrade_refuses_unsafe_bundles(tmp_path, monkeypatch):
    Shims(tmp_path, monkeypatch)
    cfg = up_cfg(tmp_path)
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as t:
        ti = tarfile.TarInfo("../escape.sh")
        ti.size = 3
        t.addfile(ti, io.BytesIO(b"bad"))
    data = buf.getvalue()
    state = {}
    agent.Upgrader(cfg, state, opener=FakeDownload(data)).step(dict(GOOD_UP, sha256=hashlib.sha256(data).hexdigest()))
    assert state["upgrade"]["state"] == "failed" and state["upgrade"]["error"].startswith("bad_bundle")
    assert not (tmp_path / "escape.sh").exists() and not (tmp_path / "upgrade/escape.sh").exists()
    # a bundle without edge/install.sh
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as t:
        ti = tarfile.TarInfo("edge/RELEASE")
        ti.size = 7
        t.addfile(ti, io.BytesIO(b"v2.1.0\n"))
    data = buf.getvalue()
    state = {}
    agent.Upgrader(cfg, state, opener=FakeDownload(data)).step(dict(GOOD_UP, sha256=hashlib.sha256(data).hexdigest()))
    assert state["upgrade"]["error"] == "bad_bundle: no edge/install.sh"


def test_upgrade_without_release_flag_support_and_no_drain(tmp_path, monkeypatch):
    """A rollback target whose install.sh predates --release gets no --release; drain_minutes 0 = no drain."""
    sh = Shims(tmp_path, monkeypatch)
    cfg = up_cfg(tmp_path)
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as t:
        b = b"#!/bin/bash\nexit 0\n"
        ti = tarfile.TarInfo("edge/install.sh")
        ti.size = len(b)
        t.addfile(ti, io.BytesIO(b))
    data = buf.getvalue()
    state = {}
    agent.Upgrader(cfg, state, opener=FakeDownload(data)).step(
        dict(GOOD_UP, release="v2.0.0", drain_minutes=0, rollback=True, sha256=hashlib.sha256(data).hexdigest()))
    a = sh.args()
    assert a[a.index("-c") + 3:] == ["--upgrade"] and state["upgrade"]["rollback"] is True
    assert "--unit=pcdn-upgrade-7-1-rb" in a


def test_rollback_reusing_the_attempt_id_is_a_new_upgrade(tmp_path, monkeypatch):
    sh = Shims(tmp_path, monkeypatch)
    cfg = up_cfg(tmp_path)
    (tmp_path / "release").write_text("v2.1.0\n")
    tb = tmp_path / "b.tgz"
    sha = make_bundle(tb, release="v2.0.0")
    state = {"upgrade": {"id": "7-1", "release": "v2.1.0", "state": "done", "rollback": False}}
    agent.Upgrader(cfg, state, opener=FakeDownload(tb.read_bytes())).step(
        dict(GOOD_UP, release="v2.0.0", rollback=True, sha256=sha))
    assert state["upgrade"]["state"] == "installing" and state["upgrade"]["release"] == "v2.0.0"
    assert "--release" in sh.args() and "v2.0.0" in sh.args()


class HbCtl:
    def __init__(self, body):
        self.body, self.hb = body, []

    def call(self, method, path, body=None, headers=None, timeout=30):
        if path == "/edge/v1/config":
            return 200, {"ETag": "e1"}, json.loads(json.dumps(self.body))
        if "heartbeat" in path:
            self.hb.append(body)
        return 200, {}, None


def test_agent_keeps_node_upgrade_and_reports_release(tmp_path, monkeypatch):
    sh = Shims(tmp_path, monkeypatch)
    cfg = up_cfg(tmp_path)
    (tmp_path / "release").write_text("v2.1.0\n")
    a = agent.Agent.__new__(agent.Agent)
    a.cfg, a.state, a.running, a.last_heartbeat = cfg, {}, True, 0.0
    a.ctl = HbCtl({"version": "v1", "sites": [MINSITE], "node": {"upgrade": GOOD_UP}})
    a.sync_config()
    assert a.state["ctl_upgrade"] == GOOD_UP
    a.upgrade_step()   # the running release: done at once, reported on the next heartbeat
    assert a.state["upgrade"]["state"] == "done" and sh.args() is None and a.last_heartbeat == 0.0
    hb = a._hb()
    assert hb["release"] == "v2.1.0" and hb["upgrade"]["state"] == "done" and hb["upgrade"]["id"] == "7-1"
    assert hb["capabilities"]["self_upgrade"] is True and hb["capabilities"]["rum"] is True
    # the controller removed node.upgrade (new version): nothing asked any more
    a.ctl.body = {"version": "v2", "sites": [MINSITE], "node": {}}
    a.sync_config()
    assert a.state["ctl_upgrade"] is None
    # release unknown (no / malformed file): null, still sent
    (tmp_path / "release").write_text("2.1\n")
    assert a._hb()["release"] is None
    (tmp_path / "release").unlink()
    assert "release" in a._hb() and a._hb()["release"] is None


# ================================================================= §23.5 live oe / pe

def _line(**kw):
    e = {"t": "2026-10-03T10:00:05+00:00", "h": "a.com", "b": 10, "s": 200, "c": "", "ip": "1.2.3.4", "cc": "IR",
         "m": "GET", "u": "/", "v": "ok", "tn": "", "rt": 0.01, "bu": 100, "ub": "", "us": "200", "pg": "",
         "uct": "0.001"}
    e.update(kw)
    return e


@pytest.mark.parametrize("kw,oe,pe", [
    ({"s": 502, "us": "502", "uct": "-"}, True, False),            # origin connect failed
    ({"s": 504, "us": "504"}, True, False),                         # origin timeout
    ({"s": 503, "us": "503"}, True, False),                         # the origin answered 503
    ({"s": 502, "us": "502, 200"}, True, False),                     # several attempts
    ({"s": 500, "us": "500"}, False, False),                        # 500 from the origin: not in the oe set
    ({"s": 502, "us": "", "uct": ""}, False, True),                 # edge-produced (e.g. unresolvable origin)
    ({"s": 500, "us": ""}, False, True),                            # njs / internal failure
    ({"s": 502, "us": "", "uct": "-"}, False, True),                # no upstream status: the platform's
    ({"s": 503, "us": "", "pg": "site"}, False, False),              # the suspended page
    ({"s": 503, "us": "", "pg": "drain"}, False, False),             # drain refusal: neither
    ({"s": 504, "us": "504", "c": "STALE"}, False, False),          # served from the cache
    ({"s": 503, "us": "", "v": "block:waf:1"}, False, False),       # security answer
    ({"s": 501, "us": ""}, False, False),                           # client-triggerable
    ({"s": 200}, False, False),
])
def test_oe_pe_counting_rules(tmp_path, kw, oe, pe):
    e = _line(**kw)
    assert agent.origin_error(e) is oe and agent.platform_error(e) is pe
    log = tmp_path / "access.log"
    log.write_text(json.dumps(e) + "\n")
    state = {}
    agent.read_usage(state, str(log), time_budget=5)
    item = agent.live_items(state["live"], "2000-01-01T00:00:00Z")[0]
    assert item["oe"] == int(oe) and item["pe"] == int(pe)


def test_oe_needs_the_upstream_field():
    e = _line(s=502)
    e.pop("us")
    assert agent.origin_error(e) is False


# ================================================================= §23.7 RUM aggregation

def test_rum_bucket_contract_golden():
    # the contract shared with the controller (A pins the same numbers)
    assert agent.RUM_MS_BOUNDS == (50, 100, 200, 300, 500, 800, 1000, 1500, 1800, 2000, 2500, 3000, 4000, 5000,
                                   8000, 12000)
    assert agent.RUM_CLS_BOUNDS == (10, 50, 100, 150, 250, 500, 1000)
    assert agent.RUM_MS_METRICS == ("ttfb", "fcp", "lcp", "inp", "dns", "tcp", "tls", "dom", "load")
    b = agent.RUM_MS_BOUNDS
    assert [agent.rum_bucket(v, b) for v in (0, 50, 50.5, 100, 2499, 2500, 2501, 12000, 12001, 60000)] == \
        [0, 0, 1, 1, 10, 10, 11, 15, 16, 16]
    c = agent.RUM_CLS_BOUNDS
    assert [agent.rum_bucket(v * 1000, c) for v in (0, 0.01, 0.04, 0.1, 0.11, 0.25, 1.0, 1.5)] == \
        [0, 0, 1, 2, 3, 4, 6, 7]


def rum_line(h="a.com", t="2026-10-03T10:07:00Z", **kw):
    e = {"t": t, "h": h, "cc": "IR", "asn": 197207, "rg": "Tehran", "p": "/", "nt": "navigate", "dev": "m",
         "cs": "HIT", "ttfb": 120, "fcp": 900, "lcp": 1800, "cls": 0.04, "inp": 80}
    e.update(kw)
    return json.dumps(e) + "\n"


def test_rum_log_aggregation_and_item(tmp_path):
    log = tmp_path / "rum.log"
    lines = [rum_line(), rum_line(lcp=3000, cs="MISS", dev="d", cc="DE", asn=0, rg="", p="/x"),
             rum_line(h="b.com", lcp=70000, cls=50, ttfb=-5, inp="x"), "not json\n", rum_line(h="bad host")]
    log.write_text("".join(lines))
    state = {}
    agent.read_rum_usage(state, str(log))
    a = state["pending"]["a.com|2026-10-03T10:00:00Z"]
    item = agent.usage_item("a.com|2026-10-03T10:00:00Z", a)
    assert item["requests"] == 0 and item["bytes"] == 0
    r = item["rum"]
    assert r["n"] == 2 and r["all"]["n"] == 2 and len(r["all"]["lcp"]) == 17 and len(r["all"]["cls"]) == 8
    assert r["all"]["lcp"][agent.rum_bucket(1800, agent.RUM_MS_BOUNDS)] == 1
    assert r["all"]["lcp"][agent.rum_bucket(3000, agent.RUM_MS_BOUNDS)] == 1
    assert r["by"]["cc"] == {"IR": r["by"]["cc"]["IR"], "DE": r["by"]["cc"]["DE"]}
    assert r["by"]["asn"].keys() == {"197207"} and r["by"]["rg"].keys() == {"Tehran"}   # unknown ones left out
    assert r["by"]["dev"].keys() == {"m", "d"} and r["by"]["cs"].keys() == {"HIT", "MISS"}
    assert r["by"]["path"].keys() == {"/", "/x"}
    b = agent.usage_item("b.com|2026-10-03T10:00:00Z", state["pending"]["b.com|2026-10-03T10:00:00Z"])["rum"]
    assert b["all"]["lcp"][16] == 1 and b["all"]["cls"][7] == 1      # clamped into the open bucket
    assert "ttfb" not in b["all"] and "inp" not in b["all"]           # invalid metrics skipped
    assert not any(k.startswith("bad") for k in state["pending"])
    # the item never carries an address or a node dimension
    blob = json.dumps(item)
    assert "1.2.3.4" not in blob and "ip" not in r and "node" not in blob
    # incremental reading + rotation (like the L4 log)
    log.write_text(log.read_text() + rum_line(t="2026-10-03T11:01:00Z"))
    agent.read_rum_usage(state, str(log))
    assert "a.com|2026-10-03T11:00:00Z" in state["pending"]
    os.rename(log, str(log) + ".1")
    with open(str(log) + ".1", "a") as f:
        f.write(rum_line(t="2026-10-03T11:02:00Z"))
    log.write_text(rum_line(t="2026-10-03T11:03:00Z"))
    agent.read_rum_usage(state, str(log))
    assert state["pending"]["a.com|2026-10-03T11:00:00Z"]["rum"]["n"] == 3


def test_rum_top_n_other_and_size_cap(monkeypatch):
    pending = {}
    for i in range(45):
        for _ in range(i + 1):
            e = json.loads(rum_line(cc=chr(65 + i // 26) + chr(65 + i % 26), asn=1000 + i, rg=f"R{i}",
                                    p=f"/p{i}", dns=5, tcp=20, tls=30, dom=900, load=2000))
            agent._account_rum(e, pending)
    R = pending["a.com|2026-10-03T10:00:00Z"]["rum"]
    item = agent.rum_item(R)
    total = R["n"]
    for dim, top in agent.RUM_TOP.items():
        if dim not in item["by"]:
            continue
        d = item["by"][dim]
        assert len([k for k in d if k != "other"]) <= top, dim
        assert sum(h["n"] for h in d.values()) == total, dim      # nothing lost: the rest is in "other"
    assert len(item["by"]["cc"]) == 31 and item["by"]["cc"]["other"]["n"] == sum(range(1, 16))
    assert len(json.dumps(item, separators=(",", ":"))) <= agent.RUM_ITEM_MAX
    # 45 keys per dimension x 10 metrics: over 32 KB -> path dropped first, then rg
    assert "path" not in item["by"] and "rg" not in item["by"] and {"cc", "asn", "dev", "cs"} <= set(item["by"])
    monkeypatch.setattr(agent, "RUM_ITEM_MAX", 10 ** 6)
    whole = agent.rum_item(R)
    assert set(whole["by"]) == {"cc", "asn", "rg", "dev", "path", "cs"}
    no_path = dict(whole, by={k: v for k, v in whole["by"].items() if k != "path"})
    monkeypatch.setattr(agent, "RUM_ITEM_MAX", len(json.dumps(no_path, separators=(",", ":"))))
    assert set(agent.rum_item(R)["by"]) == {"cc", "asn", "rg", "dev", "cs"}     # only path dropped
    # tracking cap: a new key beyond RUM_TRACK goes to "other" at once
    pending = {}
    for i in range(agent.RUM_TRACK["path"] + 5):
        agent._account_rum(json.loads(rum_line(p=f"/q{i}")), pending)
    by = pending["a.com|2026-10-03T10:00:00Z"]["rum"]["by"]["path"]
    assert len(by) == agent.RUM_TRACK["path"] + 1 and by["other"]["n"] == 5
    assert agent.rum_item({"n": 0}) is None


def test_rum_rides_in_the_usage_post(tmp_path):
    cfg = make_cfg(tmp_path, RUM_LOG=str(tmp_path / "rum.log"))
    (tmp_path / "rum.log").write_text(rum_line())
    sent = []

    class Ctl:
        def call(self, method, path, body=None, headers=None, timeout=30):
            sent.append(body)
            return 200, {}, None
    a = agent.Agent.__new__(agent.Agent)
    a.cfg, a.state, a.ctl = cfg, {}, Ctl()
    a.push_usage()
    items = [i for b in sent for i in b["items"]]
    assert items and items[0]["host"] == "a.com" and items[0]["rum"]["n"] == 1


# ================================================================= §23.7 RUM rendering

def rum_site(**rum):
    r = {"enabled": True, "sample": 0.25, "inject": "auto", "exclude": ["/admin", "/wp-login.php"], "spa": False}
    r.update(rum)
    return dict(MINSITE, rum=r)


def test_norm_rum():
    assert agent.norm_rum(MINSITE) is None and agent.norm_rum(dict(MINSITE, rum={"enabled": False})) is None
    n = agent.norm_rum(rum_site(sample=5, exclude=["/ok", "bad", "/a b", "/x\"y", "/ok"] + [f"/e{i}" for i in range(30)],
                                inject="weird", spa=True))
    assert n["sample"] == 1.0 and n["inject"] == "auto" and n["spa"] is True
    assert n["exclude"][0] == "/ok" and len(n["exclude"]) == 20 and "bad" not in n["exclude"]
    assert agent.norm_rum(rum_site(sample=0))["sample"] == 0.01
    assert agent.norm_rum(rum_site(sample="x"))["sample"] == 0.1


def test_rum_locations_injection_and_exclusions(tmp_path):
    cfg = make_cfg(tmp_path, RUM_LOG=str(tmp_path / "rum.log"))
    text = agent.render_site(rum_site(), cfg)[0]
    assert "location = /__pcdn/rum.js {" in text and "location = /__pcdn/rum {" in text
    rum_loc = text.split("location = /__pcdn/rum {", 1)[1].split("}", 1)[0]
    assert "js_content pcdn.rumIngest;" in rum_loc and "limit_req zone=pcdn_rum burst=20 nodelay;" in rum_loc
    assert f"access_log {tmp_path}/rum.log pcdn_rum if=$pcdn_rum_line;" in rum_loc
    assert "client_max_body_size 2k;" in rum_loc and "pcdn-access" not in rum_loc
    js_loc = text.split("location = /__pcdn/rum.js {", 1)[1].split("\n", 1)[0]
    assert "public, max-age=3600" in js_loc and "nosniff" in js_loc and "application/javascript" in js_loc
    m = text.split("map $uri $pcdn_rum_3 {", 1)[1].split("}", 1)[0]
    assert "default '<script src=\"/__pcdn/rum.js\" data-s=\"0.25\" defer></script>';" in m
    assert '"~^/admin" "";' in m and '"~^/wp\\\\-login\\\\.php" "";' in m
    assert text.count("sub_filter '</head>' '$pcdn_rum_3</head>';") >= 1
    assert 'proxy_set_header Accept-Encoding "";' in text and "add_header Server-Timing $pcdn_rum_st;" in text
    # never in the static location, the /__pcdn/ locations or tunnel paths
    static = text.split("location ~* \\.(?:", 1)[1].split("\n    }", 1)[0]
    assert "sub_filter" not in static
    # spa: the tag carries data-spa
    assert 'data-spa="1"' in agent.render_site(rum_site(spa=True), cfg)[0]
    # manual: endpoints, no rewriting
    man = agent.render_site(rum_site(inject="manual"), cfg)[0]
    assert "location = /__pcdn/rum {" in man and "sub_filter" not in man and "$pcdn_rum_3" not in man
    # off / absent / suspended / no njs: nothing at all
    for s, c in ((MINSITE, cfg), (dict(rum_site(), status="suspended"), cfg),
                 (rum_site(), dict(cfg, NGINX_CAPS=dict(cfg["NGINX_CAPS"], modules=["geoip2"])))):
        t = agent.render_site(s, c)[0]
        assert "__pcdn/rum" not in t and "sub_filter" not in t
    # a decoy tunnel site: endpoints but no injection
    tn = dict(rum_site(), tunnel={"enabled": True, "fallback": "decoy", "paths": [
        {"id": "ws", "path": "/ws", "protocol": "ws"}]})
    t = agent.render_site(tn, cfg)[0]
    assert "location = /__pcdn/rum {" in t and "sub_filter" not in t
    ws = t.split('location ^~ "/ws" {', 1)[1].split("\n    }", 1)[0]
    assert "sub_filter" not in ws and "Accept-Encoding" not in ws


def test_rum_base_config_and_geo(tmp_path):
    cfg = make_cfg(tmp_path)
    http = agent.render_tree({"sites": []}, cfg)[0]["http.conf"]
    assert "log_format pcdn_rum escape=none '$pcdn_rum_line';" in http
    assert "limit_req_zone $binary_remote_addr zone=pcdn_rum:10m rate=2r/s;" in http
    assert "js_var $pcdn_rum_line;" in http
    assert 'map $host $pcdn_asn {\n    default "0";\n}' in http and 'map $host $pcdn_region {\n    default "";\n}' in http
    asn = tmp_path / "asn.mmdb"
    asn.write_bytes(b"x")
    reg = tmp_path / "city.mmdb"
    reg.write_bytes(b"x")
    http = agent.render_tree({"sites": []}, dict(cfg, RUM_ASN_DB=str(asn), RUM_REGION_DB=str(reg)))[0]["http.conf"]
    assert f"geoip2 {asn} {{" in http and "$pcdn_asn autonomous_system_number;" in http
    assert f"geoip2 {reg} {{" in http and "$pcdn_region subdivisions 0 names en;" in http
    # the RUM log format has no address field
    fmt = http.split("log_format pcdn_rum", 1)[1].split("\n", 1)[0]
    assert "remote_addr" not in fmt and "$pcdn_rum_line" in fmt
    # databases appearing re-render (render revision)
    assert agent.render_rev(cfg) != agent.render_rev(dict(cfg, RUM_ASN_DB=str(asn)))


def test_rum_render_passes_nginx_t(tmp_path):
    if shutil.which("nginx") is None:
        pytest.skip("nginx not installed")
    from conftest import modules_available, nginx_conf
    if not modules_available():
        pytest.skip("nginx modules not installed")
    cfg = make_cfg(tmp_path, RUM_LOG=str(tmp_path / "rum.log"), LISTEN_IPV6="no", HTTP_PORT="18981",
                   HTTPS_PORT="18982", NGINX_USER="root")
    files, _ = agent.render_tree({"sites": [rum_site(), dict(rum_site(inject="manual"), id=4, domain="n.test",
                                                              hosts=[{"name": "n.test", "origin": MINSITE["hosts"][0]["origin"]}])]},
                                 cfg)
    root = pathlib.Path(cfg["NGINX_DIR"])
    for sid in (3, 4):
        (pathlib.Path(cfg["CACHE_DIR"]) / str(sid)).mkdir(parents=True, exist_ok=True)
    for rel, content in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(content if isinstance(content, bytes) else content.encode())
    conf = nginx_conf(tmp_path, cfg)
    p = subprocess.run(["nginx", "-t", "-q", "-c", str(conf)], capture_output=True, text=True)
    assert p.returncode == 0, p.stderr


# ================================================================= §23.7 njs rumIngest

RUM_HARNESS = r"""
import m from './pcdn.mjs';
const cases = JSON.parse(process.argv[2]);
const out = cases.map(c => {
  const r = { method: c.method || 'POST', headersIn: c.headers || {}, requestText: c.body,
    variables: Object.assign({ host: 'shop.test', pcdn_country: 'IR', pcdn_asn: '197207', pcdn_region: 'Tehran',
      remote_addr: '203.0.113.9' }, c.vars || {}), return: code => { r.code = code; } };
  m.rumIngest(r);
  return { code: r.code, line: r.variables.pcdn_rum_line === undefined ? null : JSON.parse(r.variables.pcdn_rum_line) };
});
console.log(JSON.stringify(out));
"""


def njs_rum(tmp_path, cases):
    if shutil.which("node") is None:
        pytest.skip("node not installed")
    src = (EDGE / "njs/pcdn.js").read_text().replace("from 'sites.js'", "from './sites.mjs'")
    (tmp_path / "pcdn.mjs").write_text(src)
    (tmp_path / "sites.mjs").write_text("export default {};\n")
    (tmp_path / "h.mjs").write_text(RUM_HARNESS)
    p = subprocess.run(["node", str(tmp_path / "h.mjs"), json.dumps(cases)], capture_output=True, text=True,
                       cwd=tmp_path)
    assert p.returncode == 0, p.stderr
    return json.loads(p.stdout)


def test_njs_rum_ingest_validation_clamping_origin(tmp_path):
    ok_h = {"Content-Type": "text/plain;charset=UTF-8", "Origin": "https://shop.test"}
    body = {"v": 1, "p": "/products", "nt": "navigate", "dev": "m", "cs": "HIT", "ttfb": 312.4, "fcp": 900,
            "lcp": 99999, "cls": 42, "inp": -5, "dns": "7", "tcp": 20, "tls": 30, "dom": 1200, "load": 2100,
            "ua": "Mozilla", "ip": "1.1.1.1", "cookie": "x"}
    res = njs_rum(tmp_path, [
        {"headers": ok_h, "body": json.dumps(body)},
        {"headers": {"Content-Type": "application/json", "Referer": "https://shop.test:443/a?b=c"},
         "body": json.dumps({"v": 1, "p": "/a b?x", "nt": "evil", "dev": "x", "cs": "<x>"}), "vars": {"pcdn_asn": ""}},
        {"headers": dict(ok_h, Origin="https://evil.test"), "body": json.dumps(body)},
        {"headers": {"Content-Type": "text/plain"}, "body": json.dumps(body)},                  # no Origin / Referer
        {"headers": dict(ok_h, Origin="null"), "body": json.dumps(body)},
        {"headers": dict(ok_h, **{"Content-Type": "application/x-www-form-urlencoded"}), "body": json.dumps(body)},
        {"method": "GET", "headers": ok_h, "body": ""},
        {"headers": ok_h, "body": json.dumps(dict(body, v=2))},
        {"headers": ok_h, "body": "{not json"},
        {"headers": ok_h, "body": "[1]"},
        {"headers": dict(ok_h, Origin="https://sub.shop.test"), "body": json.dumps(body)},
    ])
    assert all(r["code"] == 204 for r in res)
    line = res[0]["line"]
    assert line["h"] == "shop.test" and line["cc"] == "IR" and line["asn"] == 197207 and line["rg"] == "Tehran"
    assert line["p"] == "/products" and line["nt"] == "navigate" and line["dev"] == "m" and line["cs"] == "HIT"
    assert line["ttfb"] == 312 and line["lcp"] == 60000 and line["cls"] == 10 and line["inp"] == 0
    assert "dns" not in line and line["load"] == 2100
    assert line["t"].endswith(":00Z") and len(line["t"]) == 20
    # nothing of the visitor beyond the metrics: no address, UA, cookie, query
    assert set(line) <= {"t", "h", "cc", "asn", "rg", "p", "nt", "dev", "cs", "ttfb", "fcp", "lcp", "cls", "inp",
                         "dns", "tcp", "tls", "dom", "load"}
    assert "203.0.113.9" not in json.dumps(res) and "1.1.1.1" not in json.dumps(res)
    bad = res[1]["line"]
    assert bad["p"] == "/" and "nt" not in bad and "dev" not in bad and bad["cs"] == "" and bad["asn"] == 0
    assert all(r["line"] is None for r in res[2:])


# ================================================================= §23.7 beacon script (node)

BEACON_HARNESS = r"""
const fs = require('fs');
const opts = JSON.parse(process.argv[3]);
const sent = [], listeners = {}, obs = [];
global.window = global;
global.location = { pathname: opts.path || '/products' };
global.history = { pushState: function () {} };
global.Math.random = () => opts.random;
global.matchMedia = q => ({ matches: q.indexOf('767') >= 0 ? opts.mobile : false });
global.navigator = { sendBeacon: (u, b) => { sent.push({ u, b: JSON.parse(b) }); return true; } };
global.fetch = () => { throw new Error('no fetch expected'); };
global.performance = { getEntriesByType: t => t === 'navigation' ? [{ activationStart: 0, responseStart: 300.4,
  domainLookupStart: 1, domainLookupEnd: 11, connectStart: 11, connectEnd: 61, secureConnectionStart: 31,
  domInteractive: 1200, loadEventEnd: 2100, type: 'navigate', serverTiming: [{ name: 'cdn-cache', description: 'hit' }] }] : [] };
global.PerformanceObserver = function (cb) { this.cb = cb; obs.push(this); };
global.PerformanceObserver.prototype.observe = function (o) { this.type = o.type; };
const doc = { visibilityState: 'visible', currentScript: { getAttribute: n => n === 'data-s' ? opts.s : (opts.spa ? '1' : null) },
  addEventListener: (t, f) => { (listeners['d:' + t] = listeners['d:' + t] || []).push(f); } };
global.document = doc;
global.addEventListener = (t, f) => { (listeners['w:' + t] = listeners['w:' + t] || []).push(f); };
eval(fs.readFileSync(process.argv[2], 'utf8'));
const emit = (type, entries) => obs.filter(o => o.type === type).forEach(o => o.cb({ getEntries: () => entries }));
emit('paint', [{ name: 'first-contentful-paint', startTime: 800 }]);
emit('largest-contentful-paint', [{ startTime: 1500 }, { startTime: 1700 }]);
emit('layout-shift', [{ value: 0.05, startTime: 100, hadRecentInput: false }, { value: 0.5, startTime: 200, hadRecentInput: true },
  { value: 0.02, startTime: 600, hadRecentInput: false }, { value: 0.03, startTime: 3000, hadRecentInput: false }]);
emit('event', [{ interactionId: 0, duration: 900 }, { interactionId: 5, duration: 120 }]);
(listeners['d:pointerdown'] || []).forEach(f => f());
emit('largest-contentful-paint', [{ startTime: 4000 }]);   // after the first input: ignored
if (opts.spa) { global.location.pathname = '/next'; global.history.pushState({}, '', '/next');
  emit('event', [{ interactionId: 7, duration: 60 }]); }
doc.visibilityState = 'hidden';
(listeners['d:visibilitychange'] || []).forEach(f => f());
(listeners['w:pagehide'] || []).forEach(f => f());
console.log(JSON.stringify({ sent, observers: obs.map(o => o.type) }));
"""


def beacon(tmp_path, **opts):
    if shutil.which("node") is None:
        pytest.skip("node not installed")
    (tmp_path / "h.js").write_text(BEACON_HARNESS)
    p = subprocess.run(["node", str(tmp_path / "h.js"), str(EDGE / "pages/rum.js"),
                        json.dumps(dict({"s": "0.5", "random": 0.1, "mobile": True}, **opts))],
                       capture_output=True, text=True)
    assert p.returncode == 0, p.stderr
    return json.loads(p.stdout)


def test_beacon_script_metrics_and_one_send(tmp_path):
    out = beacon(tmp_path)
    assert len(out["sent"]) == 1                     # visibilitychange + pagehide: one beacon
    s = out["sent"][0]
    assert s["u"] == "/__pcdn/rum"
    b = s["b"]
    assert b == {"v": 1, "p": "/products", "dev": "m", "ttfb": 300, "dns": 10, "tcp": 50, "tls": 30, "dom": 1200,
                 "nt": "navigate", "cs": "HIT", "fcp": 800, "lcp": 1700, "load": 2100, "inp": 120, "cls": 0.07}
    # not sampled / bad rate: nothing observed, nothing sent
    assert beacon(tmp_path, random=0.9)["sent"] == [] and beacon(tmp_path, s="x")["sent"] == []
    assert beacon(tmp_path, s="0", random=0.0)["sent"] == []
    # soft navigations (spa): the hard view, then one "soft" beacon per further view (inp / cls only)
    out = beacon(tmp_path, spa=True)
    assert [x["b"].get("nt") for x in out["sent"]] == ["navigate", "soft"]
    soft = out["sent"][1]["b"]
    assert soft["p"] == "/next" and soft["inp"] == 60 and "lcp" not in soft and "ttfb" not in soft
    # the script is small and CSP-friendly (no eval / inline handlers / storage / cookies)
    src = (EDGE / "pages/rum.js").read_text()
    assert len(src.encode()) <= 4096
    for bad in ("eval(", "document.cookie", "localStorage", "sessionStorage", "userAgent", "new Function"):
        assert bad not in src, bad


# ================================================================= install.sh / bootstrap.sh blocks

def test_install_release_check_block(tmp_path):
    block = _block("install.sh", "# >>> pcdn release check", "# <<< pcdn release check")
    here = tmp_path / "edge"
    here.mkdir()

    def run(arg, rel=None):
        f = here / "RELEASE"
        if rel is None:
            f.unlink(missing_ok=True)
        else:
            f.write_text(rel)
        return _run(f'HERE="{here}"; RELEASE_ARG="{arg}"\n' + block + 'echo "BR=$BUNDLE_RELEASE"')
    p = run("v2.1.0", "v2.1.0\n")
    assert p.returncode == 0 and "BR=v2.1.0" in p.stdout
    p = run("v2.2.0", "v2.1.0\n")
    assert p.returncode == 1 and "does not match" in p.stdout
    assert run("v2.1.0", None).returncode == 1           # a live bundle is not a pinned release
    assert run("2.1.0", "v2.1.0").returncode == 1        # malformed --release
    p = run("", None)
    assert p.returncode == 0 and "BR=\n" in p.stdout + "\n"
    p = run("", "garbage")
    assert p.returncode == 0 and "BR=" in p.stdout and "malformed" in p.stdout
    p = run("", "v2.1.0-rc.1")
    assert "BR=v2.1.0-rc.1" in p.stdout
    # the parser
    text = (EDGE / "install.sh").read_text()
    assert '    --release) RELEASE_ARG="${2:-}"; shift 2 ;;' in text
    assert subprocess.run(["bash", "-n", str(EDGE / "install.sh")]).returncode == 0


def test_install_release_files_block(tmp_path):
    block = _block("install.sh", "# >>> pcdn release files", "# <<< pcdn release files")
    rel_file, rdir = tmp_path / "etc/release", tmp_path / "releases"
    rel_file.parent.mkdir()

    def run(release, tarball=""):
        return _run(f'BUNDLE_RELEASE="{release}"; RELEASE_FILE="{rel_file}"; RELEASES_DIR="{rdir}"\n' + block,
                    PCDN_RELEASE_TARBALL=tarball)
    tb = tmp_path / "b.tgz"
    for i, v in enumerate(("v2.0.0", "v2.0.1", "v2.1.0", "v2.2.0")):
        tb.write_bytes(v.encode())
        p = run(v, str(tb))
        assert p.returncode == 0, p.stderr
        os.utime(rdir / f"{v}.tar.gz", (1_000_000 + i, 1_000_000 + i))
    assert rel_file.read_text() == "v2.2.0\n"
    assert sorted(x.name for x in rdir.iterdir()) == ["v2.0.1.tar.gz", "v2.1.0.tar.gz", "v2.2.0.tar.gz"]
    assert oct((rdir / "v2.2.0.tar.gz").stat().st_mode & 0o777) == "0o600" and (rdir / "v2.1.0.tar.gz").read_bytes() == b"v2.1.0"
    assert oct(rdir.stat().st_mode & 0o777) == "0o700"
    # re-installing an older cached release (rollback from the cache itself) keeps it as the newest
    p = run("v2.0.1", str(rdir / "v2.0.1.tar.gz"))
    assert p.returncode == 0 and (rdir / "v2.0.1.tar.gz").read_bytes() == b"v2.0.1"
    assert rel_file.read_text() == "v2.0.1\n" and len(list(rdir.iterdir())) == 3
    # a live bundle (no edge/RELEASE): the release file is removed (release unknown), the cache untouched
    p = run("", str(tb))
    assert p.returncode == 0 and not rel_file.exists() and len(list(rdir.iterdir())) == 3


class FakeCurl:
    """A curl shim answering from a directory: <name>.code / <name>.body per URL key; records the stdin
    body and the argv of every call."""

    def __init__(self, tmp):
        self.dir = tmp / "curl"
        self.dir.mkdir()
        self.bin = tmp / "curlbin"
        self.bin.mkdir()
        script = r'''#!/bin/bash
out=""; wfmt=""; url=""; fail=no; data=no
while [ $# -gt 0 ]; do
  case "$1" in
    -o) out="$2"; shift 2 ;;
    -w) wfmt="$2"; shift 2 ;;
    -H|--proto|--proto-redir|--max-time) shift 2 ;;
    --data-binary) data=yes; shift 2 ;;
    -fsSL|-f) fail=yes; shift ;;
    -*) shift ;;
    *) url="$1"; shift ;;
  esac
done
echo "$url" >> "D/calls"
[ "$data" = yes ] && cat > "D/stdin"
key="$(printf '%s' "$url" | sed 's|^[a-z]*://[^/]*||; s|[^A-Za-z0-9.]|_|g')"
code="$(cat "D/$key.code" 2>/dev/null || echo 404)"
if [ -n "$out" ] && [ -f "D/$key.body" ]; then cp "D/$key.body" "$out"; fi
[ -n "$wfmt" ] && printf '%s' "$code"
if [ "$fail" = yes ] && [ "$code" != 200 ]; then exit 22; fi
exit 0
'''.replace("D/", f"{self.dir}/")
        (self.bin / "curl").write_text(script)
        (self.bin / "curl").chmod(0o755)

    def serve(self, path, code=200, body=None):
        key = "".join(c if c.isalnum() or c == "." else "_" for c in path)
        (self.dir / f"{key}.code").write_text(str(code))
        if body is not None:
            (self.dir / f"{key}.body").write_bytes(body if isinstance(body, bytes) else body.encode())

    def calls(self):
        p = self.dir / "calls"
        return p.read_text().splitlines() if p.exists() else []

    @property
    def path(self):
        return f"{self.bin}:{os.environ.get('PATH', '/usr/bin:/bin')}"


def test_install_join_block(tmp_path):
    block = _block("install.sh", "# >>> pcdn join", "# <<< pcdn join")
    fc = FakeCurl(tmp_path)
    jt = "jt_" + "a" * 40

    def run(controller="https://ctl.test", token="", join=jt, insecure="no"):
        return _run(f'CONTROLLER="{controller}"; TOKEN="{token}"; JOIN_TOKEN="{join}"; INSECURE_HTTP={insecure}\n'
                    + block + '\necho "TOKEN=$TOKEN"', PATH=fc.path)
    fc.serve("/edge/v1/join", 200, '{"edge_id": 9, "name": "general-home-p3-1", "token": "edge_' + "f" * 40 + '"}')
    p = run()
    assert p.returncode == 0, p.stdout + p.stderr
    assert f"TOKEN=edge_{'f' * 40}" in p.stdout and "joined" in p.stdout
    sent = json.loads((fc.dir / "stdin").read_text())
    assert sent["join_token"] == jt and "hostname" in sent
    assert fc.calls()[-1] == "https://ctl.test/edge/v1/join"
    fc.serve("/edge/v1/join", 401, '{"detail": "invalid"}')
    p = run()
    assert p.returncode == 1 and "join token invalid or expired" in p.stdout and "توکن پیوستن" in p.stdout
    fc.serve("/edge/v1/join", 404)
    p = run()
    assert p.returncode == 1 and "does not support join tokens" in p.stdout
    # plain http only with --insecure-http; a malformed token never leaves the node
    n = len(fc.calls())
    assert run(controller="http://ctl.test").returncode == 1 and len(fc.calls()) == n
    assert run(join="jt_short").returncode == 1 and len(fc.calls()) == n
    fc.serve("/edge/v1/join", 200, '{"token": "edge_' + "e" * 40 + '"}')
    assert run(controller="http://ctl.test", insecure="yes").returncode == 0
    # an edge token given: no join at all
    n = len(fc.calls())
    p = run(token="edge_given")
    assert p.returncode == 0 and "TOKEN=edge_given" in p.stdout and len(fc.calls()) == n
    # the token is never on curl's command line
    assert jt not in (fc.dir / "calls").read_text()


def test_install_last_edge_exit_under_self_upgrade(tmp_path):
    block = _block("install.sh", "# >>> pcdn upgrade drain", "# <<< pcdn upgrade drain")
    fake = tmp_path / "pcdn-agent"
    fake.write_text('if [ "${2:-}" = --help ]; then exit 0; fi\nexit 3\n')
    script = 'DRAIN="15"\n' + block.replace("/usr/bin/python3", "/bin/bash") + "\nUPGRADE_DONE=yes\n"
    p = _run(script, AGENT_BIN=str(fake), PCDN_AGENT_CONF=str(tmp_path / "agent.conf"))
    assert p.returncode == 1 and "last active node" in p.stdout
    p = _run(script, AGENT_BIN=str(fake), PCDN_AGENT_CONF=str(tmp_path / "agent.conf"), PCDN_SELF_UPGRADE="1")
    assert p.returncode == 3


def test_install_keeps_wave14_conf_and_installs_rum_assets():
    text = (EDGE / "install.sh").read_text()
    keep = text.split('KEEP_CONF="$(grep -E', 1)[1].split("\n", 1)[0]
    for k in ("RUM_ASN_DB", "RUM_REGION_DB", "UPGRADE_DIR", "RELEASES_DIR", "SELF_UPGRADE"):
        assert k in keep, k
    assert 'install -m 644 "$HERE/pages/rum.js" /usr/share/pcdn/pages/rum.js' in text
    assert "/var/log/nginx/pcdn-rum.log {" in text
    assert "pcdn-geoip-update --asn" in text
    # the join token is read from the environment / a file, never from an argument
    assert "--join-token)" not in text and '--join-token-file) JOIN_TOKEN=' in text


def test_bootstrap_version_check():
    block = _block("bootstrap.sh", "# >>> pcdn bootstrap version check", "# <<< pcdn bootstrap version check")
    for ok in ("", "v2.1.0", "v10.0.3", "v2.1.0-rc.1"):
        assert _run(f'VERSION="{ok}"\n' + block).returncode == 0, ok
    for bad in ("2.1.0", "v2.1", "v2.1.0;id", "latest", "v2.1.0 "):
        p = _run(f'VERSION="{bad}"\n' + block)
        assert p.returncode == 1 and "--version" in p.stderr, bad
    text = (EDGE / "bootstrap.sh").read_text()
    assert '    --version) VERSION="${2:-}"; shift 2 ;;' in text and '    --version=*) VERSION="${1#--version=}"; shift ;;' in text
    # rejected before the root check / any download (an empty PATH: nothing could run anyway)
    p = subprocess.run(["/bin/bash", str(EDGE / "bootstrap.sh"), "--controller", "https://c", "--version=v2"],
                       capture_output=True, text=True, env={"PATH": "/nonexistent"})
    assert p.returncode == 1 and "--version must look like" in p.stderr


def test_bootstrap_release_block(tmp_path):
    block = _block("bootstrap.sh", "# >>> pcdn bootstrap release", "# <<< pcdn bootstrap release")
    fc = FakeCurl(tmp_path)
    work = tmp_path / "tmp"
    work.mkdir()
    bundle = b"pinned-bundle-bytes"
    sha = hashlib.sha256(bundle).hexdigest()

    def run(version="", group="general"):
        for f in work.iterdir():
            f.unlink()
        return _run(f'CONTROLLER="https://ctl.test"; CURL_PROTO=(--proto =https); TMP="{work}"; VERSION="{version}"; '
                    f'GROUP="{group}"\n' + block + '\necho "RELEASE=$RELEASE"', PATH=fc.path)
    # an old controller: no /edge/releases -> the live bundle; --version -> clear error
    fc.serve("/edge/bundle.tar.gz", 200, b"live-bundle")
    p = run()
    assert p.returncode == 0 and "RELEASE=\n" in p.stdout + "\n" and (work / "bundle.tar.gz").read_bytes() == b"live-bundle"
    p = run("v2.1.0")
    assert p.returncode == 1 and "نسخهٔ پین‌شده" in p.stderr and "does not offer pinned releases" in p.stderr
    # --version with a matching .sha256
    fc.serve("/edge/releases", 200, json.dumps({"pinned": None, "groups": {"general": None, "tunnel": None},
                                                "releases": [{"version": "v2.1.0", "sha256": sha, "size": 19}]}))
    fc.serve("/edge/bundle.tar.gz?version=v2.1.0", 200, bundle)
    fc.serve("/edge/releases/v2.1.0.sha256", 200, f"{sha}  pcdn-edge-v2.1.0.tar.gz\n")
    p = run("v2.1.0")
    assert p.returncode == 0, p.stderr
    assert "RELEASE=v2.1.0" in p.stdout and (work / "bundle.tar.gz").read_bytes() == bundle
    assert "https://ctl.test/edge/bundle.tar.gz?version=v2.1.0" in fc.calls()
    # a sha mismatch aborts (exit 1)
    fc.serve("/edge/releases/v2.1.0.sha256", 200, f"{'0' * 64}  pcdn-edge-v2.1.0.tar.gz\n")
    p = run("v2.1.0")
    assert p.returncode == 1 and "sha256 mismatch" in p.stderr
    fc.serve("/edge/releases/v2.1.0.sha256", 200, f"{sha}  pcdn-edge-v2.1.0.tar.gz\n")
    # no --version: the group's pin from /edge/releases (tunnel differs from general)
    fc.serve("/edge/releases", 200, json.dumps({"pinned": "v2.0.0", "groups": {"general": "v2.1.0", "tunnel": None},
                                                "releases": []}))
    p = run()
    assert p.returncode == 0 and "RELEASE=v2.1.0" in p.stdout and "pins release v2.1.0" in p.stdout
    fc.serve("/edge/bundle.tar.gz?version=v2.0.0", 200, b"other")
    fc.serve("/edge/releases/v2.0.0.sha256", 200, f"{sha}  pcdn-edge-v2.0.0.tar.gz\n")
    p = run(group="tunnel")   # no group pin -> the global pin, verified like any pinned release
    assert p.returncode == 1 and "RELEASE=" not in p.stdout and "sha256 mismatch" in p.stderr
    # no pin at all: the live bundle
    fc.serve("/edge/releases", 200, json.dumps({"pinned": None, "groups": {"general": None}, "releases": []}))
    p = run()
    assert p.returncode == 0 and (work / "bundle.tar.gz").read_bytes() == b"live-bundle"
    # the release + tarball reach install.sh
    text = (EDGE / "bootstrap.sh").read_text()
    assert '[ -z "$RELEASE" ] || PASS+=(--release "$RELEASE")' in text
    assert 'PCDN_JOIN_TOKEN="$JOIN_TOKEN" PCDN_RELEASE_TARBALL="$TMP/bundle.tar.gz"' in text
    assert "sed -n 's/^CONTROLLER_URL=//p' /etc/pcdn/agent.conf" in text   # --upgrade still reads it


def test_geoip_update_asn_options(tmp_path):
    db = tmp_path / "asn.mmdb"
    db.write_bytes(b"x")
    env = {"PATH": "/usr/bin:/bin", "PCDN_ASN_DB": str(db)}
    p = subprocess.run(["bash", str(EDGE / "pcdn-geoip-update.sh"), "--asn", "--if-missing"], capture_output=True,
                       text=True, env=env)
    assert p.returncode == 0 and "already present" in p.stdout and str(db) in p.stdout
    p = subprocess.run(["bash", str(EDGE / "pcdn-geoip-update.sh"), "--bogus"], capture_output=True, text=True, env=env)
    assert p.returncode == 2
    svc = (EDGE / "systemd/pcdn-geoip.service").read_text()
    assert "ExecStart=-/usr/local/sbin/pcdn-geoip-update --asn" in svc


def test_upgrade_wrapper_records_the_installer_exit(tmp_path, monkeypatch):
    """The command handed to systemd-run, run directly: the wrapper writes install.sh's exit code to the
    status file the agent polls, with the installer's arguments intact."""
    sh = Shims(tmp_path, monkeypatch)
    cfg = up_cfg(tmp_path)
    tb = tmp_path / "b.tgz"
    sha = make_bundle(tb, install='echo "args: $*" > "$(dirname "$0")/../../args"; exit 3\n')
    state = {}
    agent.Upgrader(cfg, state, opener=FakeDownload(tb.read_bytes())).step(dict(GOOD_UP, sha256=sha))
    a = sh.args()
    env = dict(os.environ)
    for x in a:
        if x.startswith("--setenv="):
            k, v = x[len("--setenv="):].split("=", 1)
            env[k] = v
    p = subprocess.run(a[a.index("/bin/bash"):], env=env, capture_output=True, text=True)
    assert p.returncode == 3
    status = pathlib.Path(state["upgrade"]["status_file"])
    assert status.read_text().strip() == "3" and status.parent == tmp_path / "upgrade"
    d = pathlib.Path(state["upgrade"]["dir"])
    assert (d / "args").read_text().strip() == "args: --upgrade --release v2.1.0 --drain=15"
    assert env["PCDN_SELF_UPGRADE"] == "1"
    agent.Upgrader(cfg, state).step(None)
    assert state["upgrade"]["state"] == "failed" and state["upgrade"]["error"] == "last_edge"
