"""End-to-end tests: real nginx + njs + the agent's rendered config, python origins on high ports.

One nginx instance (module scope) serves every test site; each feature gets its own host so the
tests do not interfere. Requests come from 127.0.0.1, which the generated test GeoIP database maps
to "CN". Skipped when nginx or the dynamic modules are missing.
"""

import hashlib
import hmac
import http.client
import http.server
import importlib.util
import json
import pathlib
import re
import shutil
import socket
import ssl
import struct
import subprocess
import threading
import time
import urllib.parse
import zlib

import pytest

from conftest import modules_available, nginx_conf, TEST_ORIGIN_ALLOW

HERE = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("agent_e2e", HERE.parent / "pcdn-agent.py")
agent = importlib.util.module_from_spec(spec)
spec.loader.exec_module(agent)

pytestmark = pytest.mark.skipif(shutil.which("nginx") is None or not modules_available(),
                                reason="nginx with njs/geoip2/image_filter/brotli modules not installed")

SECRET = "5e" * 32
CAPTCHA_ALPHABET = "ACEFHKLMNPRTUVWXYZ347"
SQLI = "/?id=" + urllib.parse.quote("1' or '1'='1")


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def make_png(w: int, h: int) -> bytes:
    def chunk(kind, data):
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))
    rows = b"".join(b"\x00" + b"".join(bytes((x * 255 // w, y * 255 // h, 128)) for x in range(w)) for y in range(h))
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(rows)) + chunk(b"IEND", b""))


PNG = make_png(400, 300)


class Origin:
    """Tiny origin: /health, /img.png, *.css (no cache headers), everything else echoes the request."""

    def __init__(self, name):
        self.name, self.hits = name, 0
        origin = self

        class H(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):
                pass

            def _send(self, code, body, ctype, extra=()):
                self.send_response(code)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("X-Origin", origin.name)
                self.send_header("X-Powered-By", "PHP/8.3")
                for k, v in extra:
                    self.send_header(k, v)
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(body)

            def do_GET(self):
                origin.hits += 1
                path = self.path.split("?", 1)[0]
                if path == "/health":
                    return self._send(200, b"ok", "text/plain")
                if path.endswith(".png"):
                    return self._send(200, PNG, "image/png")
                if path.endswith(".css"):
                    return self._send(200, f"/* {origin.name} {self.path} {origin.hits} */".encode(), "text/css")
                body = json.dumps({"origin": origin.name, "path": self.path, "headers": dict(self.headers)}).encode()
                return self._send(200, body, "application/json")

            do_POST = do_HEAD = do_GET

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.server.daemon_threads = True
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def stop(self):
        if self.server:
            self.server.shutdown()
            self.server.server_close()
            self.server = None


class Resp:
    def __init__(self, r, body):
        self.status, self.body, self.raw = r.status, body, r
        self.headers = {k.lower(): v for k, v in r.getheaders()}
        self.cookies = r.msg.get_all("Set-Cookie") or []

    @property
    def text(self):
        return self.body.decode("utf-8", "replace")


class Edge:
    def __init__(self, cfg, conf):
        self.cfg, self.conf = cfg, conf
        self.port, self.sport = int(cfg["HTTP_PORT"]), int(cfg["HTTPS_PORT"])

    def req(self, host, path="/", method="GET", headers=None, body=None, https=False, tls_max=None):
        h = {"Host": host, "User-Agent": "pytest-e2e", "Connection": "close"}
        h.update(headers or {})
        if https:
            ctx = ssl.create_default_context()
            ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
            if tls_max:
                ctx.maximum_version = tls_max
            sock = socket.create_connection(("127.0.0.1", self.sport), timeout=10)
            conn = http.client.HTTPSConnection(host, self.sport, timeout=10, context=ctx)
            conn.sock = ctx.wrap_socket(sock, server_hostname=host)
        else:
            conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            conn.request(method, path, body=body, headers=h)
            r = conn.getresponse()
            return Resp(r, r.read())
        finally:
            conn.close()

    def log(self):
        p = pathlib.Path(self.cfg["ACCESS_LOG"])
        return [json.loads(line) for line in p.read_text().splitlines() if line.strip()] if p.exists() else []

    def last_log(self, host, marker, timeout=8.0):
        # the access log is buffered (F23: buffer=64k flush=1s), so a just-written line may take a
        # moment to reach the file; poll rather than read once.
        end = time.time() + timeout
        while True:
            for e in reversed(self.log()):
                if e["h"] == host and marker in e["u"]:
                    return e
            if time.time() > end:
                raise AssertionError(f"no log line for {host} {marker}")
            time.sleep(0.2)


def site(sid, host, origin, **sections):
    s = {"id": sid, "domain": host, "status": "active", "secret": SECRET, "ssl": None, "rate_limit_rps": 0,
         "blocked_ips": [], "hosts": [{"name": host, "origin": origin}],
         "cache": {"enabled": False, "level": "standard", "edge_ttl": 3600, "browser_ttl": 0, "ignore_query": False,
                   "bypass_cookies": [], "always_online": True}}
    s.update(sections)
    return s


def self_signed(tmp, cn):
    key, crt = tmp / "k.pem", tmp / "c.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
                    "-subj", f"/CN={cn}", "-days", "2", "-keyout", key, "-out", crt], check=True, capture_output=True)
    return crt.read_text(), key.read_text()


def make_mmdb(path):
    from mmdb_writer import MMDBWriter
    from netaddr import IPSet
    w = MMDBWriter(ip_version=4, database_type="DBIP-Country-Lite", languages=["en"], description="pcdn test")
    w.insert_network(IPSet(["127.0.0.0/8"]), {"country": {"iso_code": "CN"}})
    w.to_db_file(str(path))


def wait_for(fn, timeout=15.0, interval=0.2):
    end = time.time() + timeout
    while True:
        try:
            if fn():
                return True
        except (OSError, http.client.HTTPException):
            pass
        if time.time() > end:
            return False
        time.sleep(interval)


@pytest.fixture(scope="module")
def env(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("edge")
    try:
        make_mmdb(tmp / "country.mmdb")
    except ImportError:
        pytest.skip("mmdb_writer/netaddr not installed")
    o = {n: Origin(n) for n in ("A", "LB1", "LB2", "LB3")}
    dead_port = free_port()
    cfg = dict(agent.DEFAULTS, ORIGIN_PRIVATE_ALLOW=TEST_ORIGIN_ALLOW)
    cfg.update({
        "NGINX_DIR": str(tmp / "pcdn"), "CACHE_DIR": str(tmp / "cache"), "STATE_FILE": str(tmp / "state.json"),
        "ACCESS_LOG": str(tmp / "access.log"), "L4_ACCESS_LOG": str(tmp / "l4.log"), "FN_USAGE_LOG": str(tmp / "fn-usage.log"), "PAGES_DIR": str(HERE.parent / "pages"),
        "NJS_FILE": str(HERE.parent / "njs/pcdn.js"), "BASE_TEMPLATE": str(HERE.parent / "nginx/pcdn-base.conf"),
        "GEOIP_DB": str(tmp / "country.mmdb"), "RESOLVER": "127.0.0.1", "NGINX_USER": "root", "LISTEN_IPV6": "no",
        "HTTP_PORT": str(free_port()), "HTTPS_PORT": str(free_port()), "RESIZE_PORT": str(free_port()),
        "DICT_SIZE": "4m",
    })
    conf = nginx_conf(tmp, cfg)
    cfg["NGINX_TEST_CMD"] = f"nginx -t -q -c {conf}"
    cfg["NGINX_RELOAD_CMD"] = f"nginx -s reload -c {conf}"

    A = {"address": "127.0.0.1", "port": o["A"].port}
    all_groups = ["sqli", "xss", "lfi", "rce", "php", "scanner", "protocol"]
    cert, key = self_signed(tmp, "tls.test")
    sites = [
        site(101, "waf.test", A, waf={"mode": "block", "paranoia": 1, "groups": all_groups,
                                      "exclusions": [{"rule_id": 0, "path": "/excluded/*"}]},
             pagerules={"rules": [{"id": "nw", "pattern": "/nowaf/*", "waf": False}]}),
        site(102, "wafd.test", A, waf={"mode": "detect", "paranoia": 1, "groups": all_groups}),
        site(103, "geo.test", A, waf={"mode": "block", "paranoia": 1, "groups": all_groups},
             firewall={"default_action": "allow", "rules": [
                 {"id": "open", "enabled": True, "action": "allow",
                  "conditions": [{"field": "path", "op": "starts_with", "value": "/open"}]},
                 {"id": "watch", "enabled": True, "action": "log",
                  "conditions": [{"field": "header", "name": "X-Watch", "op": "eq", "value": "yes"}]},
                 {"id": "cn", "enabled": True, "action": "block",
                  "conditions": [{"field": "country", "op": "in", "value": ["CN", "RU"]},
                                 {"field": "path", "op": "not_contains", "value": "/public"}]}]}),
        site(104, "js.test", A, ddos={"mode": "js", "threshold_rps": 200, "clearance_ttl": 600}),
        site(105, "cap.test", A, ddos={"mode": "captcha", "threshold_rps": 200, "clearance_ttl": 600}),
        site(106, "rl.test", A, ratelimit={"rules": [
            {"id": "login", "enabled": True, "path": "/login*", "methods": ["GET"], "requests": 3, "period": 60,
             "action": "block", "block_seconds": 30}]}),
        site(107, "lb.test", {"pool": "main"}, pools={"pools": [
            {"name": "main", "method": "weighted", "protocol": "http",
             "origins": [{"address": "127.0.0.1", "port": o["LB1"].port, "weight": 1, "backup": False},
                         {"address": "127.0.0.1", "port": o["LB2"].port, "weight": 1, "backup": False},
                         {"address": "127.0.0.1", "port": o["LB3"].port, "weight": 1, "backup": True}],
             "health": {"enabled": True, "path": "/health", "interval": 1, "timeout": 1, "expect": "2xx"}}]}),
        site(108, "pr.test", A, cache={"enabled": True, "level": "standard", "edge_ttl": 3600, "browser_ttl": 0},
             pagerules={"rules": [
                 {"id": "p1", "enabled": True, "pattern": "/nocache/*", "cache": "bypass"},
                 {"id": "p2", "enabled": True, "pattern": "/old", "redirect": {"url": "https://example.com/new", "code": 301}},
                 {"id": "p3", "enabled": True, "pattern": "/all/*", "cache": "everything", "edge_ttl": 120, "browser_ttl": 90}]}),
        site(109, "iq.test", A, cache={"enabled": True, "level": "standard", "edge_ttl": 3600, "ignore_query": True}),
        site(110, "hl.test", A, hotlink={"enabled": True, "extensions": ["png", "jpg"],
                                         "allowed_referers": ["good.com", "*.partner.com"], "allow_empty": True}),
        site(111, "hdr.test", A, headers={"request": [{"name": "X-From-CDN", "value": "pasargad$1"}],
                                          "response": [{"name": "X-Frame-Options", "value": "SAMEORIGIN"},
                                                       {"name": "X-Powered-By", "value": None}]}),
        site(112, "tls.test", A, ssl={"cert": cert, "key": key},
             ssl_options={"force_https": False, "min_tls": "1.3", "origin_protocol": "http",
                          "hsts": {"enabled": True, "max_age": 600, "include_subdomains": True, "preload": False}}),
        site(113, "err.test", {"address": "127.0.0.1", "port": dead_port},
             errorpages={"5xx": "<html><body>PCDN-CUSTOM-5XX</body></html>", "4xx": None}),
        site(114, "img.test", A, cache={"enabled": True, "level": "standard", "edge_ttl": 3600},
             image={"enabled": True, "quality": 80, "max_width": 150}),
        site(115, "auto.test", A, ddos={"mode": "auto", "threshold_rps": 1, "clearance_ttl": 600}),
        site(116, "blk.test", A, blocked_ips=["127.0.0.0/8"]),
        site(117, "susp.test", A, status="suspended"),
        site(118, "fwc.test", A,
             firewall={"default_action": "allow", "rules": [
                 {"id": "members", "enabled": True, "action": "challenge",
                  "conditions": [{"field": "path", "op": "starts_with", "value": "/members"}]},
                 {"id": "badua", "enabled": True, "action": "captcha",
                  "conditions": [{"field": "user_agent", "op": "regex", "value": "^evil-bot/[0-9]+$"}]}]},
             ratelimit={"rules": [{"id": "api", "enabled": True, "path": "/api/*", "methods": [], "requests": 2,
                                   "period": 60, "action": "challenge", "block_seconds": 60}]},
             errorpages={"5xx": None, "4xx": "<html><body>PCDN-CUSTOM-4XX</body></html>"}),
        site(119, "purge.test", A, cache={"enabled": True, "level": "standard", "edge_ttl": 3600,
                                          "browser_ttl": 0, "ignore_query": False}),
    ]

    agent.bootstrap(cfg)
    p = subprocess.run(["nginx", "-c", str(conf)], capture_output=True, text=True)
    assert p.returncode == 0, p.stderr
    edge = Edge(cfg, conf)
    try:
        assert wait_for(lambda: edge.req("unknown.test", "/__pcdn/health").status == 200)
        err = agent.apply_config({"sites": sites}, cfg)
        assert err is None, err
        assert wait_for(lambda: edge.req("waf.test", "/").status == 200), (tmp / "error.log").read_text()[-3000:]
        edge.origins, edge.sites, edge.tmp = o, {s["domain"]: s for s in sites}, tmp
        yield edge
    finally:
        subprocess.run(["nginx", "-s", "stop", "-c", str(conf)], capture_output=True)
        for x in o.values():
            x.stop()


# ----------------------------------------------------------------- base config

def test_default_server_and_health(env):
    assert env.req("unknown.test", "/").status == 421
    assert env.req("unknown.test", "/__pcdn/health").text == "ok\n"
    assert env.req("waf.test", "/__pcdn/health").status == 200
    assert env.req("waf.test", "/__pcdn/anything").status == 404  # never proxied, never WAF-bypass
    assert env.req("waf.test", "/__pcdn/deny/block:waf:1").status == 404  # internal only


def test_brotli_and_gzip(env):
    path = "/x" * 200  # the origin echoes the path, so the body is large enough to compress
    assert env.req("hdr.test", path, headers={"Accept-Encoding": "br, gzip"}).headers.get("content-encoding") == "br"
    assert env.req("hdr.test", path, headers={"Accept-Encoding": "gzip"}).headers.get("content-encoding") == "gzip"


# ----------------------------------------------------------------- WAF

def test_waf_blocks_sqli_in_block_mode(env):
    r = env.req("waf.test", SQLI + "&m=w1")
    assert r.status == 403 and "دسترسی مسدود شد" in r.text and "Access denied" in r.text
    assert "waf:942100" in r.text
    assert env.last_log("waf.test", "m=w1")["v"] == "block:waf:942100"
    assert env.req("waf.test", "/?id=42").status == 200
    x = env.req("waf.test", "/?q=" + urllib.parse.quote("<script>alert(1)</script>"))
    assert x.status == 403 and "waf:941100" in x.text
    assert env.req("waf.test", "/", headers={"User-Agent": "sqlmap/1.7"}).status == 403
    assert env.req("waf.test", "/.git/config").status == 403
    assert env.req("waf.test", "/?f=" + urllib.parse.quote("../../etc/passwd")).status == 403


def test_waf_exclusions_and_page_rule_off(env):
    assert env.req("waf.test", "/excluded/a" + SQLI[1:]).status == 200
    assert env.req("waf.test", "/nowaf/a" + SQLI[1:]).status == 200
    assert env.req("waf.test", "/other/a" + SQLI[1:]).status == 403


def test_waf_detect_mode_only_logs(env):
    r = env.req("wafd.test", SQLI + "&m=d1")
    assert r.status == 200 and json.loads(r.body)["origin"] == "A"
    assert env.last_log("wafd.test", "m=d1")["v"] == "log:waf:942100"


# ----------------------------------------------------------------- firewall / GeoIP

def test_firewall_country_block_with_geoip(env):
    r = env.req("geo.test", "/?m=g1")
    assert r.status == 403
    e = env.last_log("geo.test", "m=g1")
    assert e["v"] == "block:firewall:cn" and e["cc"] == "CN"
    # all conditions must match: /public is excluded from the country rule
    assert env.req("geo.test", "/public/x").status == 200
    # allow short-circuits the rest, including the WAF
    assert env.req("geo.test", "/open" + SQLI[1:]).status == 200
    # log records and continues (then the country rule blocks)
    env.req("geo.test", "/?m=g2", headers={"X-Watch": "yes"})
    assert env.last_log("geo.test", "m=g2")["v"] == "block:firewall:cn"
    env.req("geo.test", "/public/?m=g3", headers={"X-Watch": "yes"})
    assert env.last_log("geo.test", "m=g3")["v"] == "log:firewall:watch"


def test_country_header_to_origin(env):
    r = env.req("hdr.test", "/echo")
    assert json.loads(r.body)["headers"]["X-Country-Code"] == "CN"


def test_legacy_blocked_ips(env):
    r = env.req("blk.test", "/?m=b1")
    assert r.status == 403
    assert env.last_log("blk.test", "m=b1")["v"] == "block:firewall:blocked_ips"


def test_suspended_site_still_works(env):
    r = env.req("susp.test", "/")
    assert r.status == 503 and "معلق" in r.text


# ----------------------------------------------------------------- JS challenge

def solve_pow(c):
    zeros, n = "0" * c["d"], 0
    while not hashlib.sha256(f"{c['n']}:{n}".encode()).hexdigest().startswith(zeros):
        n += 1
    return n


def challenge_data(text):
    m = re.search(r'<script id="pcdn-challenge" type="application/json">(.*?)</script>', text)
    assert m, text[:500]
    return json.loads(m.group(1))


def test_js_challenge_flow(env):
    r = env.req("js.test", "/page?x=1")
    assert r.status == 403 and "Checking your browser" in r.text and r.headers["cache-control"] == "no-store"
    c = challenge_data(r.text)
    assert c["r"] == "/page?x=1"
    n = solve_pow(c)
    qs = urllib.parse.urlencode({"t": c["t"], "n": n, "r": c["r"]})
    bad = env.req("js.test", "/__pcdn/verify?" + urllib.parse.urlencode({"t": c["t"], "n": n + 1, "r": c["r"]}))
    assert bad.status == 403 and not bad.cookies
    v = env.req("js.test", "/__pcdn/verify?" + qs)
    assert v.status == 302 and v.headers["location"].endswith("/page?x=1"), v.text
    cookie = v.cookies[0].split(";")[0]
    assert cookie.startswith("__pcdn_clr=") and "HttpOnly" in v.cookies[0]
    ok = env.req("js.test", "/page?x=1", headers={"Cookie": cookie})
    assert ok.status == 200 and json.loads(ok.body)["path"] == "/page?x=1"
    # the token is single use, and the clearance is bound to the user agent
    assert env.req("js.test", "/__pcdn/verify?" + qs).status == 403
    assert env.req("js.test", "/", headers={"Cookie": cookie, "User-Agent": "other"}).status == 403
    # open redirects are neutralised
    c2 = challenge_data(env.req("js.test", "/").text)
    v2 = env.req("js.test", "/__pcdn/verify?" + urllib.parse.urlencode({"t": c2["t"], "n": solve_pow(c2), "r": "//evil.com/"}))
    assert v2.status == 302 and not v2.headers["location"].endswith("evil.com/")


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_challenge_page_sha256_matches(env, tmp_path):
    page = env.req("js.test", "/").text
    js = re.search(r"<script>(function S\(m\).*?return r})", page).group(1)
    (tmp_path / "t.js").write_text(js + "\nconsole.log(S('abc'));console.log(S('x'.repeat(200)));\n")
    out = subprocess.run(["node", str(tmp_path / "t.js")], capture_output=True, text=True, check=True).stdout.split()
    assert out == [hashlib.sha256(b"abc").hexdigest(), hashlib.sha256(b"x" * 200).hexdigest()]


def test_firewall_and_ratelimit_challenge_actions(env):
    r = env.req("fwc.test", "/members/?m=f1")
    assert r.status == 403 and "pcdn-challenge" in r.text  # njs page, not replaced by the custom 4xx page
    assert env.last_log("fwc.test", "m=f1")["v"] == "challenge:firewall:members"
    r = env.req("fwc.test", "/?m=f2", headers={"User-Agent": "evil-bot/7"})
    assert r.status == 403 and "<svg" in r.text
    assert env.last_log("fwc.test", "m=f2")["v"] == "captcha:firewall:badua"
    assert env.req("fwc.test", "/").status == 200
    # rate-limit rule with the challenge action: counted once per request (not again by the deny page)
    codes = [env.req("fwc.test", f"/api/x?i={i}").status for i in range(4)]
    assert codes == [200, 200, 403, 403]
    assert env.last_log("fwc.test", "i=3")["v"] == "challenge:ratelimit:api"
    # a solved challenge clears the rate-limit challenge as well. The limit_req bucket may have
    # refilled a token between the burst above and here (CI timing), so re-request back-to-back
    # until a rate-limit challenge is actually served instead of assuming the bucket is still full.
    c = None
    for _ in range(12):
        c = challenge_data(env.req("fwc.test", "/api/x").text)
        if c:
            break
    assert c, "no rate-limit challenge served after re-saturating /api/x"
    v = env.req("fwc.test", "/__pcdn/verify?" + urllib.parse.urlencode({"t": c["t"], "n": solve_pow(c), "r": c["r"]}))
    cookie = v.cookies[0].split(";")[0]
    assert env.req("fwc.test", "/api/x", headers={"Cookie": cookie}).status == 200
    assert env.req("fwc.test", "/members/", headers={"Cookie": cookie}).status == 200


def test_custom_4xx_page(env):
    r = env.req("fwc.test", "/__pcdn/nothing")
    assert r.status == 404 and "PCDN-CUSTOM-4XX" in r.text
    assert env.req("waf.test", "/__pcdn/nothing").status == 404


def test_ddos_auto_mode(env):
    codes = [env.req("auto.test", f"/?n={i}").status for i in range(25)]
    assert codes[0] == 200 and codes[-1] == 403
    assert env.last_log("auto.test", "n=24")["v"] == "challenge:ddos:auto"


# ----------------------------------------------------------------- captcha

def captcha_form(text):
    t = re.search(r'name="t" value="([^"]+)"', text).group(1)
    ret = re.search(r'name="r" value="([^"]+)"', text).group(1)
    return t, ret


def test_captcha_flow(env):
    r = env.req("cap.test", "/dash")
    assert r.status == 403 and "<svg" in r.text and "<text" not in r.text
    t, ret = captcha_form(r.text)
    assert ret == "/dash"
    form = {"Content-Type": "application/x-www-form-urlencoded"}
    bad = env.req("cap.test", "/__pcdn/captcha", "POST", form, urllib.parse.urlencode({"t": t, "a": "ZZZZZ", "r": ret}))
    assert bad.status == 403 and not bad.cookies and "Incorrect" in bad.text
    # a token is burnt by any attempt, so brute forcing one image is impossible
    nonce = t.split(".")[1]
    hx = hmac.new(SECRET.encode(), f"capans|{nonce}".encode(), hashlib.sha256).hexdigest()
    answer = "".join(CAPTCHA_ALPHABET[int(hx[i * 4:i * 4 + 4], 16) % len(CAPTCHA_ALPHABET)] for i in range(5))
    again = env.req("cap.test", "/__pcdn/captcha", "POST", form, urllib.parse.urlencode({"t": t, "a": answer, "r": ret}))
    assert again.status == 403 and not again.cookies
    # fresh image, right answer (lower case is fine)
    t, ret = captcha_form(env.req("cap.test", "/dash").text)
    nonce = t.split(".")[1]
    hx = hmac.new(SECRET.encode(), f"capans|{nonce}".encode(), hashlib.sha256).hexdigest()
    answer = "".join(CAPTCHA_ALPHABET[int(hx[i * 4:i * 4 + 4], 16) % len(CAPTCHA_ALPHABET)] for i in range(5))
    good = env.req("cap.test", "/__pcdn/captcha", "POST", form, urllib.parse.urlencode({"t": t, "a": answer.lower(), "r": ret}))
    assert good.status == 302 and good.headers["location"].endswith("/dash"), good.text
    cookie = good.cookies[0].split(";")[0]
    ok = env.req("cap.test", "/dash", headers={"Cookie": cookie})
    assert ok.status == 200 and json.loads(ok.body)["origin"] == "A"
    # a JS-level clearance is not enough for captcha mode
    js_cookie = cookie.replace(".cap.", ".js.")
    assert env.req("cap.test", "/dash", headers={"Cookie": js_cookie}).status == 403


# ----------------------------------------------------------------- rate limit

def test_rate_limit_429(env):
    codes = [env.req("rl.test", f"/login?i={i}").status for i in range(5)]
    assert codes == [200, 200, 200, 429, 429]
    r = env.req("rl.test", "/login?i=x")
    assert r.status == 429 and int(r.headers["retry-after"]) > 0 and "Too many requests" in r.text
    assert env.last_log("rl.test", "i=x")["v"] == "block:ratelimit:login"
    assert env.req("rl.test", "/other").status == 200
    assert env.req("rl.test", "/login", "POST").status == 200  # rule is GET only


# ----------------------------------------------------------------- load balancer

def test_load_balancer_failover(env):
    o = env.origins
    seen = {json.loads(env.req("lb.test", "/").body)["origin"] for _ in range(40)}
    assert seen == {"LB1", "LB2"}  # backup unused while primaries are up

    o["LB1"].stop()
    assert wait_for(lambda: all(env.req("lb.test", "/").headers.get("x-origin") == "LB2" for _ in range(10)), 15)
    o["LB2"].stop()
    assert wait_for(lambda: all(env.req("lb.test", "/").headers.get("x-origin") == "LB3" for _ in range(10)), 15)


# ----------------------------------------------------------------- page rules & cache

def test_page_rule_bypass_and_redirect(env):
    r = env.req("pr.test", "/nocache/a.css")
    assert r.status == 200 and r.headers["x-cache"] == "BYPASS"
    r = env.req("pr.test", "/old")
    assert r.status == 301 and r.headers["location"] == "https://example.com/new"
    # "everything" caches a dynamic response and overrides the browser TTL
    first = env.req("pr.test", "/all/x")
    second = env.req("pr.test", "/all/x")
    assert first.headers["x-cache"] == "MISS" and second.headers["x-cache"] == "HIT"
    assert second.headers["cache-control"] == "public, max-age=90"
    # static files are cached by default
    env.req("pr.test", "/s.css")
    assert env.req("pr.test", "/s.css").headers["x-cache"] == "HIT"


def test_ignore_query_cache_key_and_purge(env):
    a = env.req("iq.test", "/style.css?a=1")
    b = env.req("iq.test", "/style.css?b=2")
    assert a.headers["x-cache"] == "MISS" and b.headers["x-cache"] == "HIT" and a.body == b.body
    removed = agent.do_purge({"site_id": 109, "urls": ["http://iq.test/style.css?whatever"]}, env.cfg)
    assert removed == 1
    assert env.req("iq.test", "/style.css?c=3").headers["x-cache"] == "MISS"


def _cache_files(env):
    return [p for p in (pathlib.Path(env.cfg["CACHE_DIR"]) / "119").rglob("*") if p.is_file()]


def test_prefix_and_everything_purge(env):
    # populate the cache through real nginx; each cacheable response lands on disk as a cache file.
    # (post-purge x-cache is unreliable here: nginx's per-worker open_file_cache can keep serving a
    # deleted file's fd, so purge effects are verified against the on-disk cache files instead.)
    def cf(path):
        return pathlib.Path(agent.cache_file(env.cfg["CACHE_DIR"], 119, f"http://purge.test{path}"))

    def prime(path):
        assert env.req("purge.test", path).status == 200
        assert wait_for(cf(path).exists), f"{path} not cached"
        return cf(path)

    blog_a, blog_b = prime("/blog/a.css"), prime("/blog/b.css")
    img_c, keep = prime("/img/c.css"), prime("/keep.css")

    # the nginx KEY header line format is exactly "KEY: <scheme>://<host><uri>"
    assert b"\nKEY: http://purge.test/blog/a.css\n" in blog_a.read_bytes()
    assert agent._read_cache_key(str(keep)) == "http://purge.test/keep.css"

    # prefix purge removes only the matching paths, leaves the others
    assert agent.do_purge({"site_id": 119, "prefixes": ["/blog/"]}, env.cfg) == 2
    assert not blog_a.exists() and not blog_b.exists()
    assert img_c.exists() and keep.exists()

    # a host-pinned prefix naming another host matches nothing here; the right host does match
    assert agent.do_purge({"site_id": 119, "prefixes": ["https://other.test/img/"]}, env.cfg) == 0
    assert img_c.exists()
    assert agent.do_purge({"site_id": 119, "prefixes": ["http://purge.test/img/"]}, env.cfg) == 1
    assert not img_c.exists()

    # exact URL purge still works on the fast hashed-key path
    assert keep.exists()
    assert agent.do_purge({"site_id": 119, "urls": ["http://purge.test/keep.css"]}, env.cfg) == 1
    assert not keep.exists()

    # a scan that exceeds PURGE_SCAN_MAX falls back to a full-site purge
    for path in ("/x1.css", "/x2.css", "/x3.css"):
        prime(path)
    assert _cache_files(env)
    agent.do_purge({"site_id": 119, "prefixes": ["/none/"]}, dict(env.cfg, PURGE_SCAN_MAX="1"))
    assert _cache_files(env) == []

    # everything purge wipes whatever is left
    prime("/again.css")
    assert _cache_files(env)
    agent.do_purge({"site_id": 119, "everything": True}, env.cfg)
    assert _cache_files(env) == []


# ----------------------------------------------------------------- hotlink / headers / TLS / errors / images

def test_hotlink_protection(env):
    assert env.req("hl.test", "/a.png", headers={"Referer": "http://evil.com/x"}).status == 403
    assert env.last_log("hl.test", "/a.png")["v"] == "block:hotlink:referer"
    assert env.req("hl.test", "/a.png", headers={"Referer": "https://good.com/"}).status == 200
    assert env.req("hl.test", "/a.png", headers={"Referer": "https://cdn.partner.com/"}).status == 200
    assert env.req("hl.test", "/a.png", headers={"Referer": "http://hl.test/page"}).status == 200
    assert env.req("hl.test", "/a.png").status == 200  # allow_empty
    assert env.req("hl.test", "/page", headers={"Referer": "http://evil.com/x"}).status == 200


def test_request_and_response_headers(env):
    r = env.req("hdr.test", "/echo")
    assert json.loads(r.body)["headers"]["X-From-CDN"] == "pasargad$1"
    assert r.headers["x-frame-options"] == "SAMEORIGIN"
    assert "x-powered-by" not in r.headers
    assert env.req("waf.test", "/").headers["x-powered-by"] == "PHP/8.3"


def test_hsts_and_min_tls(env):
    r = env.req("tls.test", "/", https=True)
    assert r.status == 200 and r.headers["strict-transport-security"] == "max-age=600; includeSubDomains"
    assert "strict-transport-security" not in env.req("tls.test", "/").headers
    old = env.req("tls.test", "/?m=t12", https=True, tls_max=ssl.TLSVersion.TLSv1_2)
    assert old.status == 403
    assert env.last_log("tls.test", "m=t12")["v"] == "block:firewall:min_tls"


def test_custom_502_page(env):
    r = env.req("err.test", "/")
    assert r.status == 502 and "PCDN-CUSTOM-5XX" in r.text


def png_size(body):
    assert body[:8] == b"\x89PNG\r\n\x1a\n", body[:40]
    return struct.unpack(">II", body[16:24])


def test_image_resize(env):
    r = env.req("img.test", "/pic.png?width=100")
    assert r.status == 200 and r.headers["content-type"] == "image/png"
    assert png_size(r.body) == (100, 75) and r.headers["x-cache"] == "MISS"
    assert env.req("img.test", "/pic.png?width=100").headers["x-cache"] == "HIT"
    assert png_size(env.req("img.test", "/pic.png?height=30").body) == (40, 30)
    assert png_size(env.req("img.test", "/pic.png?width=1000").body) == (150, 112)  # capped by max_width
    assert png_size(env.req("img.test", "/pic.png").body) == (400, 300)


# ----------------------------------------------------------------- usage / events from the real log

def test_usage_payload_from_real_log(env):
    env.req("waf.test", SQLI + "&m=usage")
    # the access log is buffered (F23): wait for the line to reach the file before reading it
    assert wait_for(lambda: any("m=usage" in e.get("u", "") for e in env.log()))
    state = {}
    agent.read_usage(state, env.cfg["ACCESS_LOG"])
    items = agent.usage_items(state["pending"])
    waf = [i for i in items if i["host"] == "waf.test"]
    assert waf and sum(i["requests"] for i in waf) >= 5
    it = waf[-1]
    assert set(it) >= {"host", "hour", "bytes", "requests", "cache_hits", "status", "codes", "countries", "paths", "security"}
    assert it["security"]["waf"] >= 1 and it["countries"]["CN"] >= 1 and it["status"]["4xx"] >= 1
    assert re.match(r"^\d{4}-\d\d-\d\dT\d\d:00:00Z$", it["hour"])
    ev = [e for e in state["events"] if "m=usage" in e["path"]]
    assert len(ev) == 1 and ev[0]["action"] == "block" and ev[0]["source"] == "waf" and ev[0]["rule"] == "942100"
    assert ev[0]["country"] == "CN" and ev[0]["method"] == "GET" and ev[0]["ip"] == "127.0.0.1"
    sources = {e["source"] for e in state["events"]}
    assert {"waf", "firewall", "ratelimit", "ddos", "hotlink"} <= sources
    # every non-ok verdict produced exactly one event
    non_ok = [e for e in env.log() if e["v"] != "ok"]
    assert len(state["events"]) == len(non_ok)
