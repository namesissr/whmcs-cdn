"""End-to-end tests for SPEC §14.3.1 / §14.3.2 (Wave 6D, edge side) with real nginx + njs.

One nginx instance runs the agent's rendered config; the agent itself talks HTTP to a fake controller
(config, usage, logship, heartbeat). Covered: the new access-log fields as nginx really writes them
(upstream status of origin vs edge-produced 5xx, the suspended-page marker, scheme / protocol /
referer), `live` minute aggregates and `platform_errors` in the usage POST, sampled log-export records
(anonymized IP, query-stripped path and referer, no tunnel / internal / disabled-site records) shipped
to /edge/v1/logship, and a 404 from an old controller switching shipping off without spinning.
"""

import http.client
import http.server
import importlib.util
import json
import pathlib
import shutil
import socket
import subprocess
import threading
import time

import pytest

from conftest import modules_available, nginx_conf, TEST_ORIGIN_ALLOW

HERE = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("agent_6d_e2e", HERE.parent / "pcdn-agent.py")
agent = importlib.util.module_from_spec(spec)
spec.loader.exec_module(agent)

pytestmark = pytest.mark.skipif(shutil.which("nginx") is None or not modules_available(),
                                reason="nginx with njs/geoip2/image_filter/brotli modules not installed")

SECRET = "5e" * 32
TOKEN = "edge_e2e_" + "x" * 20


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def serve(handler) -> http.server.ThreadingHTTPServer:
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


class OriginH(http.server.BaseHTTPRequestHandler):
    """/boom -> 500 from the origin; anything else -> 200 text."""
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def do_GET(self):
        code = 500 if self.path.startswith("/boom") else 200
        body = f"origin {self.path}".encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class FakeController:
    """GET /edge/v1/config, GET /edge/v1/purges, POST usage / logship / heartbeat / logs (recorded).
    `logship_status` lets a test answer the logship endpoint like an old controller (404)."""

    def __init__(self, config: dict):
        self.config, self.posts, self.logship_status = config, [], 200
        fake = self

        class H(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):
                pass

            def _json(self, code, obj):
                body = json.dumps(obj).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                assert self.headers.get("Authorization") == f"Bearer {TOKEN}"
                if self.path.startswith("/edge/v1/config"):
                    return self._json(200, fake.config)
                return self._json(200, [])

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)) or b"null")
                fake.posts.append((self.path, body))
                if self.path == "/edge/v1/logship" and fake.logship_status != 200:
                    return self._json(fake.logship_status, {"detail": "Not Found"})
                return self._json(200, {"ok": True})

        self.server = serve(H)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"

    def bodies(self, path):
        return [b for p, b in self.posts if p == path]


def site(sid, host, origin, logs=None, **over):
    s = {"id": sid, "domain": host, "status": "active", "secret": SECRET, "ssl": None, "rate_limit_rps": 0,
         "blocked_ips": [], "hosts": [{"name": host, "origin": origin}],
         "cache": {"enabled": False, "level": "standard", "edge_ttl": 3600, "browser_ttl": 0, "ignore_query": False,
                   "bypass_cookies": [], "always_online": True}}
    if logs is not None:
        s["logs"] = logs
    s.update(over)
    return s


LOGS_ON = {"enabled": True, "sample_rate": 1.0, "anonymize_ip": True}


def req(port, host, path, headers=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    try:
        conn.request("GET", path, headers={"Host": host, "User-Agent": "e2e-6d/1", "Connection": "close",
                                           **(headers or {})})
        r = conn.getresponse()
        r.read()
        return r.status
    finally:
        conn.close()


def log_lines(cfg):
    p = pathlib.Path(cfg["ACCESS_LOG"])
    return [json.loads(x) for x in p.read_text().splitlines() if x.strip()] if p.exists() else []


def wait_logged(cfg, markers, timeout=10.0):
    """The access log is buffered (flush=1s): wait until a line for every (host, uri) marker is there."""
    end = time.time() + timeout
    while True:
        seen = {(e["h"], e["u"]) for e in log_lines(cfg)}
        if all(m in seen for m in markers):
            return
        if time.time() > end:
            raise AssertionError(f"not logged: {[m for m in markers if m not in seen]}")
        time.sleep(0.2)


@pytest.fixture(scope="module")
def env(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("edge6d")
    origin = serve(OriginH)
    A = {"address": "127.0.0.1", "port": origin.server_address[1]}
    dead = {"address": "127.0.0.1", "port": free_port()}
    cfg = dict(agent.DEFAULTS, ORIGIN_PRIVATE_ALLOW=TEST_ORIGIN_ALLOW)
    cfg.update({
        "NGINX_DIR": str(tmp / "pcdn"), "CACHE_DIR": str(tmp / "cache"), "STATE_FILE": str(tmp / "state.json"),
        "ACCESS_LOG": str(tmp / "access.log"), "L4_ACCESS_LOG": str(tmp / "l4.log"), "FN_USAGE_LOG": str(tmp / "fn-usage.log"), "ERROR_LOG": str(tmp / "error.log"),
        "PAGES_DIR": str(HERE.parent / "pages"), "NJS_FILE": str(HERE.parent / "njs/pcdn.js"),
        "BASE_TEMPLATE": str(HERE.parent / "nginx/pcdn-base.conf"), "GEOIP_DB": str(tmp / "none.mmdb"),
        "RESOLVER": "127.0.0.1", "NGINX_USER": "root", "LISTEN_IPV6": "no", "HTTP_PORT": str(free_port()),
        "HTTPS_PORT": str(free_port()), "RESIZE_PORT": str(free_port()), "DICT_SIZE": "4m",
        "BUNDLE_VERSION_FILE": str(tmp / "bundle.version"), "EDGE_TOKEN": TOKEN,
    })
    conf = nginx_conf(tmp, cfg)
    cfg["NGINX_TEST_CMD"] = f"nginx -t -q -c {conf}"
    cfg["NGINX_RELOAD_CMD"] = f"nginx -s reload -c {conf}"
    sites = [
        site(201, "logs.test", A, LOGS_ON,
             tunnel={"enabled": True, "idle_timeout": 600, "fallback": "origin",
                     "paths": [{"id": "w1", "path": "/tun", "protocol": "ws", "origin": None, "pool": None}]}),
        site(202, "nolog.test", A, {"enabled": False, "sample_rate": 1.0, "anonymize_ip": True}),
        site(203, "dead.test", dead, LOGS_ON),
        site(204, "susp.test", A, LOGS_ON, status="suspended"),
    ]
    config = {"version": "v6d-1", "sites": sites}
    ctl = FakeController(config)
    cfg["CONTROLLER_URL"] = ctl.url
    agent.bootstrap(cfg)
    p = subprocess.run(["nginx", "-c", str(conf)], capture_output=True, text=True)
    assert p.returncode == 0, p.stderr
    port = int(cfg["HTTP_PORT"])
    try:
        deadline = time.time() + 15
        while True:
            try:
                if req(port, "unknown.test", "/__pcdn/health") == 200:
                    break
            except OSError:
                pass
            assert time.time() < deadline, "nginx did not come up"
            time.sleep(0.2)
        assert agent.apply_config(config, cfg) is None
        # an edge-produced 500 inside a real rendered site server (stands in for an njs / internal
        # failure, which a correct config never produces on purpose)
        sconf = pathlib.Path(cfg["NGINX_DIR"]) / "sites/201.conf"
        text = sconf.read_text()
        anchor = "    location ^~ /__pcdn/ { return 404; }"
        assert anchor in text
        sconf.write_text(text.replace(anchor, anchor + "\n    location = /edge500 { return 500; }", 1))
        assert subprocess.run(cfg["NGINX_RELOAD_CMD"].split(), capture_output=True).returncode == 0
        deadline = time.time() + 15
        while req(port, "logs.test", "/edge500?probe=1") != 500:
            assert time.time() < deadline, "reload with /edge500 not applied"
            time.sleep(0.2)
        yield {"cfg": cfg, "ctl": ctl, "port": port, "tmp": tmp}
    finally:
        subprocess.run(["nginx", "-s", "stop", "-c", str(conf)], capture_output=True)
        origin.shutdown()
        ctl.server.shutdown()


def test_live_platform_errors_and_logship_end_to_end(env):
    cfg, ctl, port = env["cfg"], env["ctl"], env["port"]
    ref = {"Referer": "https://ref.test/from?utm=secret#x"}
    assert [req(port, "logs.test", "/page?token=s3cret", ref) for _ in range(3)] == [200] * 3
    assert req(port, "logs.test", "/boom?x=1") == 500            # origin 5xx
    assert req(port, "logs.test", "/edge500") == 500             # edge-produced 5xx
    # tunnel path (ws location); since wave 7 a ws path without Upgrade gets the edge's 426 (SPEC §15.1)
    assert req(port, "logs.test", "/tun", {"Upgrade": "websocket", "Connection": "Upgrade"}) == 200
    req(port, "logs.test", "/__pcdn/verify?t=1&n=1&r=/")          # internal endpoint
    assert req(port, "nolog.test", "/hidden?q=1") == 200          # export disabled for this site
    assert req(port, "dead.test", "/down") == 502                # origin connect failure
    assert req(port, "susp.test", "/") == 503                    # suspended page
    wait_logged(cfg, [("logs.test", "/page?token=s3cret"), ("logs.test", "/boom?x=1"), ("logs.test", "/edge500"),
                      ("logs.test", "/tun"), ("nolog.test", "/hidden?q=1"), ("dead.test", "/down"),
                      ("susp.test", "/")])

    # the new log fields as nginx writes them
    by = {(e["h"], e["u"]): e for e in log_lines(cfg)}
    assert by[("logs.test", "/edge500")]["us"] == "" and by[("logs.test", "/boom?x=1")]["us"] == "500"
    assert by[("dead.test", "/down")]["us"] == "502" and by[("susp.test", "/")]["pg"] == "site"
    page = by[("logs.test", "/page?token=s3cret")]
    assert (page["sc"], page["pr"], page["rf"], page["us"], page["pg"]) == (
        "http", "HTTP/1.1", "https://ref.test/from?utm=secret#x", "200", "")
    assert by[("logs.test", "/tun")]["tn"] == "ws"
    for key, counted in ((("logs.test", "/edge500"), True), (("logs.test", "/boom?x=1"), False),
                         (("dead.test", "/down"), False), (("susp.test", "/"), False)):
        assert agent.platform_error(by[key]) is counted, key

    a = agent.Agent(cfg)
    a.sync_config()        # real HTTP: picks up the per-site `logs` blocks (no reload needed for them)
    assert a.logship.site_for("logs.test") == (1.0, True) and a.logship.site_for("nolog.test") is None
    a.push_usage()
    [usage] = ctl.bodies("/edge/v1/usage")
    items = {}
    for it in usage["items"]:
        items.setdefault(it["host"], []).append(it)
    pe = {h: sum(i["platform_errors"] for i in its) for h, its in items.items()}
    assert pe["logs.test"] >= 2 and pe["dead.test"] == 0 and pe["susp.test"] == 0 and pe["nolog.test"] == 0
    # exactly the edge-produced /edge500 answers (the fixture's probe + this test's) are platform errors
    assert pe["logs.test"] == sum(1 for e in log_lines(cfg)
                                  if e["h"] == "logs.test" and e["u"].startswith("/edge500") and e["s"] == 500)
    live = [x for x in usage["live"] if x["host"] == "logs.test"]
    assert live and sum(x["requests"] for x in live) == sum(i["requests"] for i in items["logs.test"])
    paths = {}
    for x in live:
        for p, n in x["paths"].items():
            paths[p] = paths.get(p, 0) + n
        # SPEC §15.4: the minute with the /tun request also carries the tunnel counters
        assert set(x) - {"tunnel_attempts", "tunnel_errors"} == {"host", "minute", "requests", "bytes", "cache_hits",
                                                                  "status", "countries", "paths"}
        assert x["minute"].endswith(":00Z")
    assert sum(x.get("tunnel_attempts", 0) for x in live) == 1 and sum(x.get("tunnel_errors", 0) for x in live) == 0
    assert paths["/page"] == 3 and all("?" not in p for p in paths)
    assert sum(x["status"].get("5xx", 0) for x in live) >= 3

    assert a.logship.ship(a.ctl) == 1
    [ship] = ctl.bodies("/edge/v1/logship")
    assert len(ship["batch_id"]) == 32
    recs = ship["records"]
    hosts = {r["host"] for r in recs}
    assert hosts == {"logs.test", "dead.test", "susp.test"}                       # never nolog.test
    assert not any(r["path"].startswith("/__pcdn") or r["path"] == "/tun" for r in recs)
    pr = [r for r in recs if r["path"] == "/page"]
    assert len(pr) == 3
    r0 = pr[0]
    assert r0["ip"] == "127.0.0.0" and r0["referer"] == "https://ref.test/from" and r0["status"] == 200
    assert (r0["scheme"], r0["proto"], r0["method"], r0["ua"]) == ("http", "HTTP/1.1", "GET", "e2e-6d/1")
    assert r0["t"].endswith("Z") and isinstance(r0["rt"], float) and r0["bytes"] > 0
    assert all("s3cret" not in json.dumps(r) and "utm=" not in json.dumps(r) for r in recs)
    assert {r["status"] for r in recs if r["host"] == "logs.test"} >= {200, 500}
    assert a.logship.batches() == []

    # heartbeat advertises the capabilities and the spool state
    a.metrics = lambda: {}
    a.heartbeat()
    hb = ctl.bodies("/edge/v1/heartbeat")[-1]
    assert hb["capabilities"]["live_analytics"] and hb["capabilities"]["logship"]
    assert hb["logship"]["sites"] == 3 and hb["logship"]["spool_batches"] == 0
    assert TOKEN not in json.dumps(ctl.posts) and SECRET not in json.dumps(ctl.posts)


def test_old_controller_404_turns_shipping_off_without_spinning(env):
    cfg, ctl, port = env["cfg"], env["ctl"], env["port"]
    a = agent.Agent(dict(cfg, STATE_FILE=str(env["tmp"] / "state404.json"),
                         LOGSHIP_SPOOL_DIR=str(env["tmp"] / "spool404")))
    a.sync_config()
    with open(cfg["ACCESS_LOG"]) as f:   # only read what this test produces
        f.seek(0, 2)
        a.state["log_pos"], a.state["log_inode"] = f.tell(), pathlib.Path(cfg["ACCESS_LOG"]).stat().st_ino
    ctl.logship_status = 404
    try:
        assert req(port, "logs.test", "/after-404") == 200
        wait_logged(cfg, [("logs.test", "/after-404")])
        a.push_usage()
        n = len(ctl.posts)
        assert a.logship.ship(a.ctl) == 0
        assert len(ctl.posts) == n + 1 and ctl.posts[-1][0] == "/edge/v1/logship"
        assert a.logship.stats()["disabled"] and a.logship.stats()["spool_records"] == 1
        a.logship.next_run = 0
        for _ in range(3):
            a.logship.ship(a.ctl)
        assert len(ctl.posts) == n + 1                                    # no spinning
        # a config change (new version) re-enables shipping; the spooled record is delivered
        ctl.logship_status = 200
        ctl.config = dict(ctl.config, version="v6d-2")
        a.state.pop("etag", None)
        a.sync_config()
        assert a.logship.ship(a.ctl) == 1
        assert [r["path"] for r in ctl.bodies("/edge/v1/logship")[-1]["records"]] == ["/after-404"]
    finally:
        ctl.logship_status = 200
