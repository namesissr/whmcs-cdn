"""Wave 14 (SPEC §23, agent B) with real nginx + njs: RUM auto injection (HTML gets the tag once, JSON and
excluded paths do not, compressed towards the client), the beacon script endpoint, the ingestion endpoint
(origin check, the RUM log line has no address, the access log never sees beacons) and the agent's
aggregation of that log; X-Served-By / X-Pcdn-Node carry the public tag, never the host name."""

import gzip
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

from conftest import TEST_ORIGIN_ALLOW, modules_available, nginx_conf, pick_port

HERE = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("agent_w14_e2e", HERE.parent / "pcdn-agent.py")
agent = importlib.util.module_from_spec(spec)
spec.loader.exec_module(agent)

pytestmark = pytest.mark.skipif(shutil.which("nginx") is None or not modules_available(),
                                reason="nginx with njs/geoip2/image_filter/brotli modules not installed")

CLIENT_IP = "127.0.0.5"
TAG = "c0ffee42"
HTML = b"<!doctype html><html><head><title>t</title></head><body>hello</body></html>"


class Origin:
    def __init__(self):
        self.seen = []
        origin = self

        class H(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):
                pass

            def do_GET(self):
                origin.seen.append((self.path, self.headers.get("Accept-Encoding")))
                if self.path.startswith("/api"):
                    body, ctype = b'{"x": "</head>"}', "application/json"
                else:
                    body, ctype = HTML, "text/html; charset=utf-8"
                self.send_response(200)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "max-age=60")
                self.end_headers()
                self.wfile.write(body)

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.server.daemon_threads = True
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def stop(self):
        self.server.shutdown()
        self.server.server_close()


def wait_for(fn, timeout=15.0):
    end = time.time() + timeout
    while time.time() < end:
        try:
            if fn():
                return True
        except (OSError, http.client.HTTPException, ValueError):
            pass
        time.sleep(0.2)
    return False


@pytest.fixture(scope="module")
def env(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("w14")
    origin = Origin()
    cfg = dict(agent.DEFAULTS, ORIGIN_PRIVATE_ALLOW=TEST_ORIGIN_ALLOW)
    cfg.update({
        "NGINX_DIR": str(tmp / "pcdn"), "CACHE_DIR": str(tmp / "cache"), "STATE_FILE": str(tmp / "state.json"),
        "ACCESS_LOG": str(tmp / "access.log"), "L4_ACCESS_LOG": str(tmp / "l4.log"), "RUM_LOG": str(tmp / "rum.log"),
        "FN_USAGE_LOG": str(tmp / "fn.log"), "PAGES_DIR": str(HERE.parent / "pages"),
        "NJS_FILE": str(HERE.parent / "njs/pcdn.js"), "BASE_TEMPLATE": str(HERE.parent / "nginx/pcdn-base.conf"),
        "GEOIP_DB": str(tmp / "none.mmdb"), "RESOLVER": "127.0.0.1", "NGINX_USER": "root", "LISTEN_IPV6": "no",
        "HTTP_PORT": str(pick_port()), "HTTPS_PORT": str(pick_port()), "RESIZE_PORT": str(pick_port()),
        "DICT_SIZE": "4m", "NODE_NAME": "edge-secret-1", "PROBE_ENABLED": "no",
    })
    conf = nginx_conf(tmp, cfg)
    cfg["NGINX_TEST_CMD"] = f"nginx -t -q -c {conf}"
    cfg["NGINX_RELOAD_CMD"] = f"nginx -s reload -c {conf}"
    site = {"id": 41, "domain": "rum.test", "status": "active", "secret": "ab" * 32, "ssl": None, "rate_limit_rps": 0,
            "blocked_ips": [], "hosts": [{"name": "rum.test", "origin": {"address": "127.0.0.1", "port": origin.port}}],
            "cache": {"enabled": True, "level": "standard", "edge_ttl": 3600, "browser_ttl": 0, "ignore_query": False,
                      "bypass_cookies": [], "always_online": True},
            "rum": {"enabled": True, "sample": 0.5, "inject": "auto", "exclude": ["/admin"], "spa": False}}
    plain = dict(site, id=42, domain="plain.test", rum=None,
                 hosts=[{"name": "plain.test", "origin": {"address": "127.0.0.1", "port": origin.port}}])
    config = {"version": "w14", "sites": [site, plain], "node": {"name": "edge-secret-1", "public_tag": TAG}}
    agent.bootstrap(cfg)
    p = subprocess.run(["nginx", "-c", str(conf)], capture_output=True, text=True)
    assert p.returncode == 0, p.stderr
    port = int(cfg["HTTP_PORT"])

    def req(host, path="/", method="GET", headers=None, body=None):
        h = {"Host": host, "Connection": "close"}
        h.update(headers or {})
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=10, source_address=(CLIENT_IP, 0))
        try:
            c.request(method, path, body=body, headers=h)
            r = c.getresponse()
            return r.status, {k.lower(): v for k, v in r.getheaders()}, r.read()
        finally:
            c.close()
    assert wait_for(lambda: req("unknown.test", "/__pcdn/health")[0] == 200)
    err = agent.apply_config(config, cfg)
    assert err is None, err
    yield {"cfg": cfg, "req": req, "origin": origin, "tmp": tmp}
    subprocess.run(["nginx", "-s", "quit", "-c", str(conf)], capture_output=True)
    origin.stop()


def test_html_gets_the_tag_once_json_and_excluded_paths_do_not(env):
    req = env["req"]
    st, h, body = req("rum.test", "/page")
    tag = b'<script src="/__pcdn/rum.js" data-s="0.5" defer></script></head>'
    assert st == 200 and body.count(b"/__pcdn/rum.js") == 1 and tag in body
    assert h.get("server-timing", "").startswith("cdn-cache;desc=")
    assert h.get("x-served-by") == TAG
    # the origin was asked for an uncompressed body; the client still gets gzip
    st, h, body = req("rum.test", "/page2", headers={"Accept-Encoding": "gzip"})
    assert h.get("content-encoding") == "gzip" and tag in gzip.decompress(body)
    assert ("/page2", None) in env["origin"].seen
    # cached copy (HIT) is rewritten as well
    st, h, body = req("rum.test", "/page")
    assert h.get("x-cache") == "HIT" and body.count(b"/__pcdn/rum.js") == 1
    assert h.get("server-timing") == "cdn-cache;desc=HIT"
    st, h, body = req("rum.test", "/admin/x")
    assert st == 200 and b"rum.js" not in body and b"</head>" in body
    st, h, body = req("rum.test", "/api/data")
    assert body == b'{"x": "</head>"}' and "server-timing" not in h
    # a site without RUM: untouched, still the public tag
    st, h, body = req("plain.test", "/page")
    assert body == HTML and "server-timing" not in h and h.get("x-served-by") == TAG
    assert socket.gethostname() not in json.dumps(h)


def test_script_endpoint(env):
    st, h, body = env["req"]("rum.test", "/__pcdn/rum.js")
    assert st == 200 and body == (HERE.parent / "pages/rum.js").read_bytes()
    assert h["content-type"] == "application/javascript; charset=utf-8"
    assert h["cache-control"] == "public, max-age=3600" and h["x-content-type-options"] == "nosniff"
    st, _, _ = env["req"]("plain.test", "/__pcdn/rum.js")
    assert st == 404


def test_ingestion_writes_a_line_without_address(env):
    req, cfg = env["req"], env["cfg"]
    beacon = json.dumps({"v": 1, "p": "/page", "nt": "navigate", "dev": "d", "cs": "HIT", "ttfb": 120, "lcp": 1900,
                         "cls": 0.02, "inp": 90})
    hdr = {"Content-Type": "text/plain;charset=UTF-8", "Origin": "http://rum.test"}
    st, h, _ = req("rum.test", "/__pcdn/rum", "POST", hdr, beacon)
    assert st == 204 and h.get("cache-control") == "no-store"
    for bad in ({"Origin": "http://evil.test"}, {"Content-Type": "application/x-www-form-urlencoded"}):
        assert req("rum.test", "/__pcdn/rum", "POST", dict(hdr, **bad), beacon)[0] == 204
    assert req("rum.test", "/__pcdn/rum", "POST", hdr, "x" * 4000)[0] == 413
    log = pathlib.Path(cfg["RUM_LOG"])
    assert wait_for(lambda: log.exists() and log.read_text().strip())
    time.sleep(0.5)
    lines = [json.loads(x) for x in log.read_text().splitlines()]
    assert len(lines) == 1
    e = lines[0]
    assert e["h"] == "rum.test" and e["p"] == "/page" and e["lcp"] == 1900 and e["asn"] == 0 and e["rg"] == ""
    assert CLIENT_IP not in log.read_text() and "127.0.0" not in log.read_text()
    # beacons never reach the access log (no billing / analytics / fair share)
    acc = pathlib.Path(cfg["ACCESS_LOG"])
    assert "/__pcdn/rum\"" not in (acc.read_text() if acc.exists() else "")
    # the agent folds it into the host-hour usage item
    state = {}
    agent.read_rum_usage(state, cfg["RUM_LOG"])
    (key,) = [k for k in state["pending"] if k.startswith("rum.test|")]
    item = agent.usage_item(key, state["pending"][key])
    assert item["rum"]["n"] == 1 and item["rum"]["by"]["cs"]["HIT"]["n"] == 1


def test_speed_test_node_header_is_the_tag(env):
    st, h, _ = env["req"]("rum.test", "/__pcdn/speed/ping")
    assert st == 204 and h.get("x-pcdn-node") == TAG
