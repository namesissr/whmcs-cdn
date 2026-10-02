"""SPEC §16.9 edge functions end-to-end: real nginx (the agent's rendered tree) + the real pcdn-fn
service (sandboxed QuickJS workers) + a python origin.

Covered: routing of bound prefixes only, request / response mapping, `pass` (GET and POST with the
body) to the origin, on_error "origin" vs "502" (exception, CPU timeout, pcdn-fn down), the security
verdict still running before a function, fetch() to the site's own origin through the local fetch
socket (never another site), X-Accel-* / foreign Set-Cookie stripping, forged control headers, the
1 MB request-body cap, a function bound to "/", HEAD, and billing (usage lines -> agent usage item).
"""

import http.server
import json
import os
import pathlib
import shutil
import subprocess
import sys
import threading
import time

import pytest

from conftest import modules_available
from test_perf_e2e import Node, agent, node_cfg, wait_for

HERE = pathlib.Path(__file__).resolve().parent
EDGE = HERE.parent
QJS = shutil.which("qjs")

pytestmark = pytest.mark.skipif(shutil.which("nginx") is None or not modules_available() or not QJS
                                or os.geteuid() != 0,
                                reason="needs root, nginx with the pcdn modules and qjs (package quickjs)")

SECRET = "5e" * 32


class Origin:
    """/origin/data -> "origin-data"; anything else -> JSON echo of the request."""

    def __init__(self):
        self.seen = []
        o = self

        class H(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):
                pass

            def _do(self):
                n = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(n) if n else b""
                o.seen.append((self.command, self.path, dict(self.headers), body))
                if self.path.startswith("/origin/data"):
                    out, ctype = b"origin-data:" + self.path.encode(), "text/plain"
                else:
                    out = json.dumps({"origin": True, "method": self.command, "path": self.path,
                                      "body": body.decode("latin-1"), "xrip": self.headers.get("X-Real-IP"),
                                      "fnclient": self.headers.get("X-Pcdn-Fn-Client")}).encode()
                    ctype = "application/json"
                self.send_response(200)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(out)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(out)

            do_GET = do_POST = do_PUT = do_HEAD = _do

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.server.daemon_threads = True
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def stop(self):
        self.server.shutdown()
        self.server.server_close()


ECHO = """
async function handleRequest(req) {
  const h = {}; for (const [k, v] of req.headers) h[k] = v;
  return Response.json({fn: true, method: req.method, url: req.url, body: await req.text(), ip: req.client.ip,
                        headers: h}, {status: 203, headers: {'X-Fn': 'echo'}});
}"""

FNS = [
    {"id": "echo", "route": "/fn/echo", "code": ECHO, "timeout_ms": 200},   # 1 MB body echo: CPU headroom on a busy runner
    {"id": "pass", "route": "/fn/pass", "code": "function handleRequest(){ return null }"},
    {"id": "throwo", "route": "/fn/throw-o", "on_error": "origin", "code": "function handleRequest(){throw 1}"},
    {"id": "throwc", "route": "/fn/throw-c", "code": "function handleRequest(){throw 1}"},
    {"id": "slow", "route": "/fn/slow", "timeout_ms": 10, "code": "function handleRequest(){for(;;){}}"},
    {"id": "fetch", "route": "/fn/fetch", "code": """
      async function handleRequest(req) {
        const r = await fetch('/origin/data?x=1', {headers: {'X-Pcdn-Fn-Client': '6.6.6.6'}});
        const e = await fetch('/echo-origin', {method: 'POST', body: 'b0dy'});
        let cross; try { await fetch('http://other.test/origin/data'); cross = 'sent'; } catch (x) { cross = 'blocked'; }
        return Response.json({status: r.status, text: (await r.text()).toUpperCase(), echo: await e.json(), cross});
      }"""},
    {"id": "accel", "route": "/fn/accel", "code": """
      function handleRequest() {
        const h = new Headers();
        h.append('X-Accel-Redirect', '/__pcdn/health'); h.append('X-Accel-Buffering', 'no');
        h.append('Set-Cookie', 'evil=1; Domain=other.test'); h.append('Set-Cookie', 'good=1; Domain=fn.test; Path=/');
        h.append('X-Ok', '1');
        return new Response('accel-body', {headers: h});
      }"""},
    {"id": "blocked", "route": "/fn/blocked", "code": "function handleRequest(){ return new Response('ran') }"},
]

ROOT_FN = """
function handleRequest(req) {
  const u = new URL(req.url);
  if (u.pathname.startsWith('/hi')) return new Response('root-fn:' + u.pathname);
  return null;
}"""


def site(sid, host, origin_port, **sections):
    s = {"id": sid, "domain": host, "status": "active", "secret": SECRET, "ssl": None, "rate_limit_rps": 0,
         "blocked_ips": [], "hosts": [{"name": host, "origin": {"address": "127.0.0.1", "port": origin_port}}],
         "cache": {"enabled": True, "level": "standard", "edge_ttl": 3600, "browser_ttl": 0, "ignore_query": False,
                   "bypass_cookies": [], "always_online": True}}
    s.update(sections)
    return s


@pytest.fixture(scope="module")
def env(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("fn")
    origin = Origin()
    paths = {"FN_DIR": str(tmp / "bundle"), "FN_SOCKET": str(tmp / "fn.sock"), "FN_FETCH_SOCKET": str(tmp / "fetch.sock"),
             "FN_STATUS": str(tmp / "status.json"), "FN_USAGE_LOG": str(tmp / "usage.log")}
    cfg, conf = node_cfg(tmp, FUNCTIONS="yes", FN_WALL_MS="3000", **paths)
    fn_conf = tmp / "fn.conf"
    fn_conf.write_text("".join(f"{k}={v}\n" for k, v in dict(
        paths, FN_RUNTIME=str(EDGE / "fn" / "runtime.js"), FN_QJS=QJS, FN_WALL_MS="3000", FN_USAGE_FLUSH="1").items()))
    node = Node(cfg, conf, tmp)
    node.origin = origin
    node.config = {"sites": [
        site(501, "fn.test", origin.port, functions={"enabled": True, "items": FNS},
             firewall={"default_action": "allow", "rules": [{"id": "blk", "action": "block", "conditions": [
                 {"field": "path", "op": "starts_with", "value": "/fn/blocked"}]}]}),
        site(502, "root.test", origin.port, functions={"enabled": True, "items": [
            {"id": "root", "route": "/", "code": ROOT_FN}]}),
        site(503, "other.test", origin.port),
    ]}
    svc = None

    def start_fn():
        return subprocess.Popen([sys.executable, str(EDGE / "pcdn-fn.py"), "serve"],
                                env=dict(os.environ, PCDN_FN_CONFIG=str(fn_conf)),
                                stdout=subprocess.DEVNULL, stderr=open(tmp / "pcdn-fn.log", "ab"))
    try:
        st = {}
        agent.sync_functions(node.config, cfg, st)
        svc = start_fn()

        def ready():
            return json.loads(pathlib.Path(paths["FN_STATUS"]).read_text()).get("ok") is True
        assert wait_for(ready, timeout=20), (svc.poll(), (tmp / "pcdn-fn.log").read_text())
        assert agent.functions_ready(cfg)
        agent.bootstrap(cfg)
        p = subprocess.run(["nginx", "-c", str(conf)], capture_output=True, text=True)
        assert p.returncode == 0, p.stderr
        assert wait_for(lambda: node.req("unknown.test", "/__pcdn/health").status == 200)
        err = agent.apply_config(node.config, cfg)
        assert err is None, err
        assert wait_for(lambda: node.req("other.test", "/x").status == 200)
        node.svc = svc
        yield node
    finally:
        subprocess.run(["nginx", "-s", "stop", "-c", str(conf)], capture_output=True)
        proc = getattr(node, "svc", None) or svc
        if proc is not None and proc.poll() is None:
            proc.terminate()
            proc.wait(10)
        origin.stop()


def test_function_response_and_request_mapping(env):
    r = env.req("fn.test", "/fn/echo/sub?a=1", method="POST", body=b"hello",
                headers={"X-Test": "t1", "X-Pcdn-Fn-Site": "503", "X-Pcdn-Fn-Id": "pass", "X-Pcdn-Fn-Err": "@x"})
    assert r.status == 203 and r.headers["x-fn"] == "echo" and r.headers["x-cache"] == "BYPASS"
    d = r.json
    assert d["fn"] and d["method"] == "POST" and d["url"] == "http://fn.test/fn/echo/sub?a=1" and d["body"] == "hello"
    assert d["ip"] == "127.0.0.5" and d["headers"]["x-test"] == "t1"
    assert not any(k.startswith("x-pcdn") for k in d["headers"]), d["headers"]   # forged control headers ignored
    assert not any(m == "POST" and p.startswith("/fn/echo") for m, p, _, _ in env.origin.seen)
    h = env.req("fn.test", "/fn/echo", method="HEAD")
    assert h.status == 203 and h.body == b""
    # routes are prefixes; other paths go to the origin as usual
    assert env.req("fn.test", "/other").json["origin"] is True
    assert env.req("fn.test", "/fn/echoX").json.get("fn") is True        # "/fn/echo" is a plain prefix


def test_pass_continues_to_origin_with_method_and_body(env):
    r = env.req("fn.test", "/fn/pass/x?y=2")
    assert r.status == 200 and r.json == dict(r.json, origin=True, method="GET", path="/fn/pass/x?y=2")
    r = env.req("fn.test", "/fn/pass/post", method="POST", body=b"payload-123")
    assert r.json["method"] == "POST" and r.json["body"] == "payload-123"
    assert r.json["xrip"] == "127.0.0.5"


def test_on_error_origin_vs_502(env):
    r = env.req("fn.test", "/fn/throw-o")
    assert r.status == 200 and r.json["origin"] is True
    assert env.req("fn.test", "/fn/throw-c").status == 502
    t0 = time.monotonic()
    assert env.req("fn.test", "/fn/slow").status == 502            # CPU limit -> fail closed
    assert time.monotonic() - t0 < 2


def test_security_verdict_runs_before_functions(env):
    assert env.req("fn.test", "/fn/blocked").status == 403


def test_fetch_own_origin_only(env):
    r = env.req("fn.test", "/fn/fetch")
    assert r.status == 200, r.body
    d = r.json
    assert d["status"] == 200 and d["text"] == "ORIGIN-DATA:/ORIGIN/DATA?X=1"
    assert d["echo"]["method"] == "POST" and d["echo"]["body"] == "b0dy"
    # the origin sees the visitor's address (not the function's forged header) and no control header
    assert d["echo"]["xrip"] == "127.0.0.5" and d["echo"]["fnclient"] is None
    assert d["cross"] == "blocked"
    seen = [x for x in env.origin.seen if x[1].startswith("/origin/data")]
    assert seen and seen[-1][2].get("X-Real-IP") == "127.0.0.5"


def test_response_header_policy(env):
    r = env.req("fn.test", "/fn/accel")
    assert r.status == 200 and r.body == b"accel-body"
    assert "x-accel-redirect" not in r.headers and r.headers["x-ok"] == "1"
    assert r.all("Set-Cookie") == ["good=1; Domain=fn.test; Path=/"]


def test_request_body_cap(env):
    assert env.req("fn.test", "/fn/echo", method="POST", body=b"x" * (1024 * 1024 + 1)).status == 413
    assert env.req("fn.test", "/fn/echo", method="POST", body=b"x" * (1024 * 1024)).status == 203


def test_function_bound_to_root(env):
    r = env.req("root.test", "/hi/there")
    assert r.status == 200 and r.body == b"root-fn:/hi/there"
    assert env.req("root.test", "/style.css").json["origin"] is True      # pass -> origin (static too)


def test_fetch_socket_rejects_unknown_hosts(env):
    import http.client
    import socket as so

    class UC(http.client.HTTPConnection):
        def connect(self):
            self.sock = so.socket(so.AF_UNIX)
            self.sock.connect(env.cfg["FN_FETCH_SOCKET"])
    c = UC("x")
    c.request("GET", "/origin/data", headers={"Host": "unknown.test"})
    assert c.getresponse().status == 421
    for site_hdr, want in ((None, 421), ("502", 421), ("501", 200)):   # pinned to the calling site
        c = UC("x")
        h = {"Host": "fn.test"}
        if site_hdr:
            h["X-Pcdn-Fn-Site"] = site_hdr
        c.request("GET", "/fn/echo", headers=h)                       # the fetch server never runs functions
        r = c.getresponse()
        assert r.status == want, (site_hdr, r.status)
        if want == 200:
            assert json.loads(r.read())["origin"] is True


def test_usage_is_billed(env):
    for _ in range(3):
        env.req("fn.test", "/fn/echo")
    st = {}

    def counted():
        agent.read_fn_usage(st, env.cfg["FN_USAGE_LOG"])
        f = [v["functions"] for k, v in st.get("pending", {}).items() if k.startswith("fn.test|") and "functions" in v]
        tot = {k: sum(x[k] for x in f) for k in ("invocations", "errors", "timeouts", "cpu_ms")}
        return tot["invocations"] >= 10 and tot["errors"] >= 2 and tot["timeouts"] >= 1 and tot["cpu_ms"] > 0
    assert wait_for(counted, timeout=15, interval=0.5), st
    key = [k for k in st["pending"] if k.startswith("fn.test|")][0]
    item = agent.usage_item(key, st["pending"][key])
    assert set(item["functions"]) == {"invocations", "cpu_ms", "errors", "timeouts"}


def test_service_down_follows_on_error(env):
    """Last: stops pcdn-fn. nginx-generated 502 -> @pcdn_fn_pass for "origin", 502 otherwise."""
    env.svc.terminate()
    env.svc.wait(10)
    assert wait_for(lambda: not os.path.exists(env.cfg["FN_SOCKET"]), timeout=5)
    assert env.req("fn.test", "/fn/throw-o").json["origin"] is True
    assert env.req("fn.test", "/fn/echo").status == 502
    assert env.req("fn.test", "/other").json["origin"] is True
    assert not agent.functions_ready(env.cfg)
