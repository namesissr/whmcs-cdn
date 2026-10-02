"""End-to-end tests for SPEC §14.2 (Wave 6B: rules & security) with real nginx + njs.

One nginx instance runs the agent's rendered config. Python origins: a plain HTTP echo origin and an
HTTPS origin that REQUIRES a client certificate issued by a test CA (authenticated origin pulls).
Covered: redirect rules (codes, Location, query preservation, captures, ordering, case, encoded
sources, CR/LF safety, never before the security verdict), transform rules (request / response
header set + remove with and without conditions, multi-value Set-Cookie removal, rewrite_path
reaching the origin while the cache stays keyed on the visitor URL), managed WAF packs (WordPress
xmlrpc multicall body, Laravel .env, author enumeration, exclusions, detect vs block, API JSON
bodies), bot management (library / headless / empty UAs per mode, verified vs spoofed crawlers,
fail-open without ranges) and mTLS towards the origin (platform / custom / off, image resizer).
Requests come from 127.0.0.1 (the test GeoIP database maps 127.0.0.0/8 to "CN"); the verified
crawler "ranges" are 127.0.0.2/32 (google) and 127.0.0.3/32 (bing).
"""

import hashlib
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
spec = importlib.util.spec_from_file_location("agent_rules_e2e", HERE.parent / "pcdn-agent.py")
agent = importlib.util.module_from_spec(spec)
spec.loader.exec_module(agent)

pytestmark = pytest.mark.skipif(shutil.which("nginx") is None or not modules_available(),
                                reason="nginx with njs/geoip2/image_filter/brotli modules not installed")

SECRET = "5e" * 32
UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/126.0 Safari/537.36"
GOOGLEBOT = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
BINGBOT = "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)"
GOOGLE_IP, BING_IP = "127.0.0.2", "127.0.0.3"
BOTS = {"verified": {"google": [GOOGLE_IP + "/32"], "bing": [BING_IP + "/32"]}, "fetched_at": "2026-10-01T00:00:00Z"}


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def make_png(w: int, h: int) -> bytes:
    def chunk(kind, data):
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))
    rows = b"".join(b"\x00" + b"".join(bytes((x * 255 // w, y * 255 // h, 90)) for x in range(w)) for y in range(h))
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(rows)) + chunk(b"IEND", b""))


PNG = make_png(200, 150)


class Origin:
    """Echo origin. *.png: an image; *.css: cacheable text; anything else: JSON describing the
    request (method, path, headers, body length + sha256, client certificate CN). Every response
    carries X-Powered-By and two Set-Cookie headers."""

    def __init__(self, tls: ssl.SSLContext | None = None):
        self.hits = {}
        origin = self

        class H(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):
                pass

            def _send(self, code, body, ctype):
                self.send_response(code)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("X-Powered-By", "PHP/8.3")
                self.send_header("Set-Cookie", "a=1; Path=/")
                self.send_header("Set-Cookie", "b=2; Path=/")
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(body)

            def do_GET(self):
                n = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(n) if n else b""
                path = self.path.split("?", 1)[0]
                origin.hits[self.path] = origin.hits.get(self.path, 0) + 1
                if path.endswith(".png"):
                    return self._send(200, PNG, "image/png")
                if path.endswith(".css"):
                    return self._send(200, f"/* {self.path} {origin.hits[self.path]} */".encode(), "text/css")
                peer = None
                if tls is not None:
                    cert = self.connection.getpeercert()
                    peer = dict(x[0] for x in cert["subject"])["commonName"] if cert else None
                out = {"method": self.command, "path": self.path, "headers": {k.lower(): v for k, v in self.headers.items()},
                       "body_len": len(body), "body_sha": hashlib.sha256(body).hexdigest(), "peer": peer}
                return self._send(200, json.dumps(out).encode(), "application/json")

            do_POST = do_HEAD = do_PUT = do_GET

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.server.daemon_threads = True
        if tls is not None:
            self.server.socket = tls.wrap_socket(self.server.socket, server_side=True)
            self.server.handle_error = lambda *a: None   # rejected handshakes are expected
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def stop(self):
        self.server.shutdown()
        self.server.server_close()


class Resp:
    def __init__(self, r, body):
        self.status, self.body = r.status, body
        self.header_list = r.getheaders()
        self.headers = {k.lower(): v for k, v in self.header_list}

    def all(self, name):
        return [v for k, v in self.header_list if k.lower() == name.lower()]

    @property
    def json(self):
        return json.loads(self.body)

    @property
    def text(self):
        return self.body.decode("utf-8", "replace")


class Edge:
    def __init__(self, cfg, conf, tmp):
        self.cfg, self.conf, self.tmp = cfg, conf, tmp
        self.port = int(cfg["HTTP_PORT"])

    def req(self, host, path="/", method="GET", headers=None, body=None, src="127.0.0.1", ua=UA):
        h = {"Host": host, "Connection": "close"}
        if ua is not None:
            h["User-Agent"] = ua
        h.update(headers or {})
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10, source_address=(src, 0))
        try:
            conn.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
            for k, v in h.items():
                conn.putheader(k, v)
            if body is not None and "Content-Length" not in h and "Transfer-Encoding" not in h:
                conn.putheader("Content-Length", str(len(body)))
            conn.endheaders(body)
            r = conn.getresponse()
            return Resp(r, r.read())
        finally:
            conn.close()

    def log(self):
        p = pathlib.Path(self.cfg["ACCESS_LOG"])
        return [json.loads(x) for x in p.read_text().splitlines() if x.strip()] if p.exists() else []

    def last_log(self, host, marker, timeout=8.0):
        end = time.time() + timeout
        while True:
            for e in reversed(self.log()):
                if e["h"] == host and marker in e["u"]:
                    return e
            if time.time() > end:
                raise AssertionError(f"no log line for {host} {marker}")
            time.sleep(0.2)


def wait_for(fn, timeout=15.0, interval=0.2):
    end = time.time() + timeout
    while True:
        try:
            if fn():
                return True
        except (OSError, http.client.HTTPException, ValueError):
            pass
        if time.time() > end:
            return False
        time.sleep(interval)


def openssl(*args):
    subprocess.run(["openssl", *map(str, args)], check=True, capture_output=True)


def make_pki(tmp):
    """Test CA, two client certificates signed by it (platform / customer) and an origin server cert."""
    ec = ["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes"]
    openssl("req", "-x509", *ec, "-subj", "/CN=pcdn-test-ca", "-days", "2", "-keyout", tmp / "ca.key", "-out", tmp / "ca.crt")
    out = {}
    for name in ("platform", "customer"):
        openssl("req", *ec, "-subj", f"/CN={name}", "-keyout", tmp / f"{name}.key", "-out", tmp / f"{name}.csr")
        openssl("x509", "-req", "-in", tmp / f"{name}.csr", "-CA", tmp / "ca.crt", "-CAkey", tmp / "ca.key",
                "-CAcreateserial", "-days", "2", "-out", tmp / f"{name}.crt")
        out[name] = {"cert": (tmp / f"{name}.crt").read_text(), "key": (tmp / f"{name}.key").read_text()}
    openssl("req", "-x509", *ec, "-subj", "/CN=origin", "-days", "2", "-keyout", tmp / "origin.key", "-out", tmp / "origin.crt")
    return out


def site(sid, host, origin_port, **sections):
    s = {"id": sid, "domain": host, "status": "active", "secret": SECRET, "ssl": None, "rate_limit_rps": 0,
         "blocked_ips": [], "hosts": [{"name": host, "origin": {"address": "127.0.0.1", "port": origin_port}}],
         "cache": {"enabled": False, "level": "standard", "edge_ttl": 3600, "browser_ttl": 0, "ignore_query": False,
                   "bypass_cookies": [], "always_online": True}}
    s.update(sections)
    return s


def rule(rid, source, match, target, status=301, preserve_query=False, enabled=True):
    return {"id": rid, "enabled": enabled, "source": source, "match": match, "target": target, "status": status,
            "preserve_query": preserve_query}


def tf(rid, actions, path="/*", methods=(), countries=()):
    return {"id": rid, "enabled": True, "match": {"path": path, "methods": list(methods), "countries": list(countries)},
            "actions": [dict({"name": None, "value": None, "regex": None, "replacement": None}, **a) for a in actions]}


ALL_PACKS_WAF = {"mode": "block", "paranoia": 1, "groups": [], "packs": ["wordpress", "laravel", "generic"],
                 "exclusions": [{"rule_id": 991130, "path": "/team/*"}]}


@pytest.fixture(scope="module")
def env(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("rules")
    try:
        from mmdb_writer import MMDBWriter
        from netaddr import IPSet
    except ImportError:
        pytest.skip("mmdb_writer/netaddr not installed")
    w = MMDBWriter(ip_version=4, database_type="DBIP-Country-Lite", languages=["en"], description="pcdn test")
    w.insert_network(IPSet(["127.0.0.0/8"]), {"country": {"iso_code": "CN"}})
    w.to_db_file(str(tmp / "country.mmdb"))
    pki = make_pki(tmp)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(tmp / "origin.crt", tmp / "origin.key")
    tls.verify_mode = ssl.CERT_REQUIRED
    tls.load_verify_locations(tmp / "ca.crt")
    plain, secure = Origin(), Origin(tls)
    op, sp = plain.port, secure.port

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
    https_origin = {"force_https": False, "min_tls": "1.2", "origin_protocol": "https", "origin_verify": False}
    bots = lambda mode: {"mode": mode, "allow_verified": True, "block_empty_ua": True}   # noqa: E731

    sites = [
        site(401, "rd.test", op,
             firewall={"default_action": "allow", "rules": [
                 {"id": "fw", "enabled": True, "action": "block",
                  "conditions": [{"field": "path", "op": "eq", "value": "/blocked-old"}]}]},
             redirects={"rules": [
                 rule("r1", "/old", "exact", "https://new.test/page", 301),
                 rule("r2", "/About", "exact", "/about", 308),                      # case: /about is not a loop
                 rule("r3", "/blog/", "prefix", "https://blog.test/", 302, preserve_query=True),
                 rule("r4", r"^/p/(\d+)/([a-z]+)$", "regex", "/post/$2?id=$1", 307, preserve_query=True),
                 rule("r5", "/keep", "exact", "https://k.test/x#frag", 302, preserve_query=True),
                 rule("r6", "/off", "exact", "/never", 301, enabled=False),
                 rule("r7", r"^/x/.*$", "regex", "/first", 301),                    # earlier rule wins ...
                 rule("r8", "/x/y", "exact", "/second", 302),                       # ... over a later exact
                 rule("r9", "/z", "exact", "/exact-first", 302),                    # earlier exact wins ...
                 rule("r10", "/z", "prefix", "/prefix-later", 301),                 # ... over a later prefix
                 rule("r11", "/%D8%B3%D9%84%D8%A7%D9%85%20%D8%AF%D9%86%DB%8C%D8%A7", "exact", "/fa", 301),
                 rule("r12", r"^/c/(.*)$", "regex", "/d/$1", 302),
                 rule("r13", "/blocked-old", "exact", "/somewhere", 301),
                 rule("r14", "/__pcdn/verify", "exact", "/hijack", 301),            # dropped on the edge
                 rule("r15", "/bad", "exact", 'https://x.test/"\r\nSet-Cookie: a=b', 301),   # dropped
             ]}),
        site(402, "rdall.test", op, ddos={"mode": "js", "threshold_rps": 200, "clearance_ttl": 600},
             redirects={"rules": [rule("all", r"^/(.*)$", "regex", "https://other.test/$1", 302)]}),
        site(403, "tf.test", op,
             cache={"enabled": True, "level": "standard", "edge_ttl": 3600, "browser_ttl": 0, "ignore_query": False,
                    "bypass_cookies": [], "always_online": True},
             headers={"request": [{"name": "X-Static", "value": "s"}],
                      "response": [{"name": "X-Resp-Static", "value": "rs"}]},
             transform={"rules": [
                 tf("all", [{"type": "set_request_header", "name": "X-Tf-All", "value": 'all$1 "q"'},
                            {"type": "remove_request_header", "name": "X-Drop"},
                            {"type": "set_response_header", "name": "X-Resp-All", "value": "yes"},
                            {"type": "remove_response_header", "name": "X-Powered-By"}]),
                 tf("api", [{"type": "set_request_header", "name": "X-Static", "value": "t"},
                            {"type": "set_request_header", "name": "X-Api", "value": "post"},
                            {"type": "remove_request_header", "name": "Cookie"},
                            {"type": "set_response_header", "name": "X-Resp-Static", "value": "rt"},
                            {"type": "set_response_header", "name": "X-Api-Resp", "value": "1"}],
                    path="/api/*", methods=["POST"]),
                 tf("cn", [{"type": "set_request_header", "name": "X-Cn", "value": "cn"}], countries=["CN"]),
                 tf("de", [{"type": "set_request_header", "name": "X-De", "value": "de"}], countries=["DE"]),
                 tf("cond", [{"type": "remove_response_header", "name": "Set-Cookie"},
                             {"type": "remove_request_header", "name": "X-Drop2"}], path="/cond/*"),
                 tf("rw", [{"type": "rewrite_path", "regex": r"^/old-api/(.*)$", "replacement": "/v2/$1"}],
                    path="/old-api/*"),
                 tf("rwq", [{"type": "rewrite_path", "regex": r"^/q/(\d+)$", "replacement": "/item?id=$1"}], path="/q/*"),
                 tf("bad", [{"type": "set_request_header", "name": "X-Pcdn-Shield", "value": "x"},
                            {"type": "set_request_header", "name": "Connection", "value": "x"},
                            {"type": "set_request_header", "name": "X-Nl", "value": "a\r\nb: c"}]),
             ]}),
        site(404, "wp.test", op, waf=ALL_PACKS_WAF),
        site(405, "wpd.test", op, waf=dict(ALL_PACKS_WAF, mode="detect")),
        site(406, "api.test", op, waf={"mode": "block", "paranoia": 1, "groups": ["sqli", "xss"], "packs": ["api"]},
             firewall={"default_action": "allow", "rules": [
                 {"id": "trusted", "enabled": True, "action": "allow",
                  "conditions": [{"field": "path", "op": "starts_with", "value": "/trusted"}]}]}),
        site(407, "botb.test", op, bots=bots("block")),
        site(408, "botc.test", op, bots=bots("challenge")),
        site(409, "botl.test", op, bots=bots("log")),
        site(410, "botd.test", op, bots=bots("log"), ddos={"mode": "js", "threshold_rps": 200, "clearance_ttl": 600}),
        site(411, "mtls.test", sp, ssl_options=dict(https_origin, origin_client_auth="platform",
                                                    origin_client={"mode": "platform"})),
        site(412, "mtlsc.test", sp, ssl_options=dict(https_origin, origin_client_auth="custom",
                                                     origin_client=dict(pki["customer"], mode="custom"))),
        site(413, "mtlsoff.test", sp, ssl_options=dict(https_origin, origin_client={"mode": "off"})),
        site(414, "mtlsimg.test", sp, ssl_options=dict(https_origin, origin_client={"mode": "platform"}),
             cache={"enabled": True, "level": "standard", "edge_ttl": 3600},
             image={"enabled": True, "quality": 80, "max_width": 150}),
        site(415, "mtlsoffimg.test", sp, ssl_options=dict(https_origin, origin_client={"mode": "off"}),
             image={"enabled": True, "quality": 80, "max_width": 150}),
    ]
    config = {"sites": sites, "bots": BOTS, "origin_pull": pki["platform"]}

    agent.bootstrap(cfg)
    p = subprocess.run(["nginx", "-c", str(conf)], capture_output=True, text=True)
    assert p.returncode == 0, p.stderr
    edge = Edge(cfg, conf, tmp)
    try:
        assert wait_for(lambda: edge.req("unknown.test", "/__pcdn/health").status == 200)
        err = agent.apply_config(config, cfg)
        assert err is None, err
        assert wait_for(lambda: edge.req("rd.test", "/plain").status == 200), (tmp / "error.log").read_text()[-3000:]
        edge.config, edge.plain, edge.secure, edge.pki = config, plain, secure, pki
        yield edge
    finally:
        subprocess.run(["nginx", "-s", "stop", "-c", str(conf)], capture_output=True)
        plain.stop()
        secure.stop()


def loc(r):
    """Location without the edge's own scheme://host:port (relative targets are made absolute)."""
    v = r.headers.get("location", "")
    m = re.match(r"^http://rd\.test:\d+(/.*)$", v)
    return m.group(1) if m else v


# ----------------------------------------------------------------- redirects

def test_redirect_codes_location_and_query(env):
    r = env.req("rd.test", "/old?x=1")
    assert r.status == 301 and r.headers["location"] == "https://new.test/page"     # no preserve_query
    r = env.req("rd.test", "/About")
    assert r.status == 308 and loc(r) == "/about"
    assert env.req("rd.test", "/about").status == 200                                # case-sensitive, no loop
    r = env.req("rd.test", "/blog/2024/post?utm=a&b=c")
    assert r.status == 302 and r.headers["location"] == "https://blog.test/?utm=a&b=c"
    assert env.req("rd.test", "/blog/").headers["location"] == "https://blog.test/"   # no query, no "?"
    r = env.req("rd.test", "/p/42/hello?ref=x")
    assert r.status == 307 and loc(r) == "/post/hello?id=42&ref=x"                   # captures + "&query"
    assert env.req("rd.test", "/p/42/HELLO").status == 200                           # regex is case-sensitive
    r = env.req("rd.test", "/keep?a=1")
    assert r.status == 302 and r.headers["location"] == "https://k.test/x?a=1#frag"  # query before the fragment
    assert env.req("rd.test", "/off").status == 200                                  # disabled rule
    assert env.req("rd.test", "/old/deeper").status == 200                           # exact means exact


def test_redirect_order_first_rule_wins(env):
    r = env.req("rd.test", "/x/y")
    assert r.status == 301 and loc(r) == "/first"            # earlier regex beats a later exact
    r = env.req("rd.test", "/z")
    assert r.status == 302 and loc(r) == "/exact-first"      # earlier exact beats a later prefix
    r = env.req("rd.test", "/zz")
    assert r.status == 301 and loc(r) == "/prefix-later"


def test_redirect_encoded_source_and_crlf_safety(env):
    r = env.req("rd.test", "/" + urllib.parse.quote("سلام دنیا"))
    assert r.status == 301 and loc(r) == "/fa"
    r = env.req("rd.test", "/c/a%0D%0ASet-Cookie:%20evil=1")
    assert r.status == 302 and loc(r) == "/d/a%0D%0ASet-Cookie:%20evil=1"            # stays encoded
    assert not r.all("Set-Cookie")
    assert env.req("rd.test", "/bad").status == 200                                  # unsafe target dropped


def test_redirect_after_security_verdict_and_never_internal(env):
    r = env.req("rd.test", "/blocked-old?m=rd1")
    assert r.status == 403                                     # the firewall runs before redirect rules
    assert env.last_log("rd.test", "m=rd1")["v"] == "block:firewall:fw"
    assert env.req("rd.test", "/__pcdn/verify").status != 301
    # a catch-all regex redirect never touches /__pcdn/ ...
    assert env.req("rdall.test", "/__pcdn/health").status == 200
    assert env.req("rdall.test", "/__pcdn/verify?t=x").status == 403
    # ... and the DDoS challenge (part of the verdict) comes first
    r = env.req("rdall.test", "/page")
    assert r.status == 403 and "pcdn-challenge" in r.text


# ----------------------------------------------------------------- transform rules

def test_transform_request_headers(env):
    r = env.req("tf.test", "/echo", headers={"X-Drop": "1", "X-Drop2": "1", "Cookie": "sid=1"})
    h = r.json["headers"]
    assert h["x-tf-all"] == 'all$1 "q"'                       # literal $ and quotes
    assert "x-drop" not in h and h["x-drop2"] == "1"          # unconditional removal; conditional not matched
    assert h["x-static"] == "s" and "x-api" not in h and h["cookie"] == "sid=1"
    assert h["x-cn"] == "cn" and "x-de" not in h              # country condition (127.0.0.1 -> CN)
    assert "x-pcdn-shield" not in h and "x-nl" not in h and h.get("connection") != "x"   # reserved / unsafe dropped
    # POST /api/*: method + path condition; overrides the static headers.request value; removes Cookie
    p = env.req("tf.test", "/api/x", "POST", {"Cookie": "sid=1", "Content-Type": "text/plain"}, b"abc").json
    assert p["headers"]["x-static"] == "t" and p["headers"]["x-api"] == "post" and "cookie" not in p["headers"]
    assert p["body_len"] == 3
    g = env.req("tf.test", "/api/x", headers={"Cookie": "sid=1"}).json["headers"]
    assert g["x-static"] == "s" and "x-api" not in g and g["cookie"] == "sid=1"
    assert "x-drop2" not in env.req("tf.test", "/cond/x", headers={"X-Drop2": "1"}).json["headers"]


def test_transform_response_headers(env):
    r = env.req("tf.test", "/echo")
    assert r.headers["x-resp-all"] == "yes" and "x-powered-by" not in r.headers
    assert r.all("X-Resp-Static") == ["rs"] and "x-api-resp" not in r.headers
    assert sorted(r.all("Set-Cookie")) == ["a=1; Path=/", "b=2; Path=/"]       # both kept, not joined
    p = env.req("tf.test", "/api/y", "POST", {"Content-Type": "text/plain"}, b"x")
    assert p.all("X-Resp-Static") == ["rt"] and p.headers["x-api-resp"] == "1"   # later matching rule wins
    c = env.req("tf.test", "/cond/z")
    assert c.status == 200 and c.all("Set-Cookie") == [] and c.headers["x-resp-all"] == "yes"


def test_transform_rewrite_path_and_cache_key(env):
    a = env.req("tf.test", "/old-api/a.css?v=1")
    assert a.status == 200 and a.text.startswith("/* /v2/a.css?v=1 ") and a.headers["x-cache"] == "MISS"
    b = env.req("tf.test", "/old-api/a.css?v=1")
    assert b.headers["x-cache"] == "HIT" and b.body == a.body and env.plain.hits["/v2/a.css?v=1"] == 1
    # the cache stays keyed on the visitor's URL, so the original URL purges it
    key_file = pathlib.Path(agent.cache_file(env.cfg["CACHE_DIR"], 403, "http://tf.test/old-api/a.css?v=1"))
    assert wait_for(key_file.exists) and agent._read_cache_key(str(key_file)) == "http://tf.test/old-api/a.css?v=1"
    j = env.req("tf.test", "/old-api/item?x=2").json
    assert j["path"] == "/v2/item?x=2"
    assert env.req("tf.test", "/q/12?x=1").json["path"] == "/item?id=12&x=1"       # query in the replacement
    assert env.req("tf.test", "/q/abc").json["path"] == "/q/abc"                   # regex not matching: unchanged
    raw = env.req("tf.test", "/old-api/a%0D%0AX-Evil:%201").json
    assert raw["path"] == "/v2/a%0D%0AX-Evil:%201" and "x-evil" not in raw["headers"]
    assert env.req("tf.test", "/other").json["path"] == "/other"


# ----------------------------------------------------------------- WAF packs

MULTICALL = (b"<?xml version=\"1.0\"?><methodCall><methodName>system.multicall</methodName><params><param><value>"
             b"<array><data><value><struct><member><name>methodName</name><value><string>wp.getUsersBlogs</string>"
             b"</value></member></struct></value></data></array></value></param></params></methodCall>")
SINGLE = (b"<?xml version=\"1.0\"?><methodCall><methodName>wp.getUsersBlogs</methodName><params><param><value>"
          b"<string>admin</string></value></param></params></methodCall>")
XML = {"Content-Type": "text/xml"}


def test_wordpress_xmlrpc_multicall_blocked_in_block_mode(env):
    hits = dict(env.plain.hits)
    r = env.req("wp.test", "/xmlrpc.php?m=x1", "POST", XML, MULTICALL)
    assert r.status == 403 and "waf:991100" in r.text
    assert env.last_log("wp.test", "m=x1")["v"] == "block:waf:991100"
    assert env.plain.hits.get("/xmlrpc.php?m=x1") == hits.get("/xmlrpc.php?m=x1")   # never reached the origin
    ok = env.req("wp.test", "/xmlrpc.php?m=x2", "POST", XML, SINGLE)
    assert ok.status == 200
    j = ok.json
    assert j["path"] == "/xmlrpc.php?m=x2" and j["body_sha"] == hashlib.sha256(SINGLE).hexdigest()
    assert env.last_log("wp.test", "m=x2")["v"] == "ok"
    big = env.req("wp.test", "/xmlrpc.php?m=x3", "POST", XML, SINGLE + b" " * 140000)   # past the inspection cap
    assert big.status == 403 and env.last_log("wp.test", "m=x3")["v"] == "block:waf:991105"


def test_wordpress_xmlrpc_detect_mode_only_logs(env):
    r = env.req("wpd.test", "/xmlrpc.php?m=d1", "POST", XML, MULTICALL)
    assert r.status == 200 and r.json["body_sha"] == hashlib.sha256(MULTICALL).hexdigest()
    assert env.last_log("wpd.test", "m=d1")["v"] == "log:waf:991100"
    assert env.req("wpd.test", "/.env?m=d2").status == 200
    assert env.last_log("wpd.test", "m=d2")["v"] == "log:waf:994100"


def test_pack_request_rules_and_exclusions(env):
    for path, rid in (("/.env", 994100), ("/app/.env.backup", 994100), ("/_ignition/execute-solution", 994110),
                      ("/?author=1", 991130), ("/wp-config.php.bak", 991120), ("/backup.zip", 990110),
                      ("/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", 990160)):
        r = env.req("wp.test", path)
        assert r.status == 403 and f"waf:{rid}" in r.text, (path, r.status, r.text[-200:])
    assert env.req("wp.test", "/team/?author=1").status == 200        # exclusion of 991130 on /team/*
    assert env.req("wp.test", "/environment").status == 200           # not an .env file
    assert env.req("wp.test", "/?author_name=x").status == 200
    # packs are independent of waf.groups (none enabled here): a plain SQLi passes
    assert env.req("wp.test", "/?id=" + urllib.parse.quote("1' or '1'='1")).status == 200


def test_api_pack_json_bodies(env):
    j = {"Content-Type": "application/json"}

    def post(body, path="/api/v1/items", headers=j):
        return env.req("api.test", path, "POST", headers, body if isinstance(body, bytes) else json.dumps(body).encode())
    ok = post({"name": "Tom's shop", "tags": ["a", "b"], "n": 1})
    assert ok.status == 200 and ok.json["body_len"] > 0
    r = post({"q": "1' or '1'='1"}, "/api/v1/items?m=a1")
    assert r.status == 403 and env.last_log("api.test", "m=a1")["v"] == "block:waf:942100"
    assert post(b'{"__proto__": {"admin": true}}').status == 403
    assert post({"filter": {"$where": "sleep(1000)"}}).status == 403
    assert post({"filter": {"price": {"$gt": 5}}}).status == 200                # comparison ops: paranoia 2
    assert post(b"[" * 40 + b"]" * 40).status == 403                            # nesting depth
    assert post(b"{not json").status == 200                                     # invalid JSON: paranoia 2
    assert post({"q": "<script>alert(1)</script>"}).status == 403
    assert post(b"{}", headers={"Content-Type": "json"}).status == 403          # malformed Content-Type
    assert env.req("api.test", "/api?a[__proto__][x]=1").status == 403
    # a firewall `allow` skips the WAF, also the body inspection
    assert post(b'{"__proto__": {"admin": true}}', "/trusted/x").status == 200


# ----------------------------------------------------------------- bot management

def test_bot_modes_for_automation_user_agents(env):
    r = env.req("botb.test", "/?m=b1", ua="curl/8.5.0")
    assert r.status == 403 and env.last_log("botb.test", "m=b1")["v"] == "block:bots:library"
    r = env.req("botc.test", "/?m=c1", ua="python-requests/2.31")
    assert r.status == 403 and "pcdn-challenge" in r.text
    assert env.last_log("botc.test", "m=c1")["v"] == "challenge:bots:library"
    r = env.req("botl.test", "/?m=l1", ua="curl/8.5.0")
    assert r.status == 200 and env.last_log("botl.test", "m=l1")["v"] == "log:bots:library"
    assert env.req("botb.test", "/?m=b2", ua=None).status == 403
    assert env.last_log("botb.test", "m=b2")["v"] == "block:bots:empty_ua"
    hl = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 HeadlessChrome/120.0 Safari/537.36"
    assert env.req("botb.test", "/?m=b3", ua=hl).status == 403
    assert env.last_log("botb.test", "m=b3")["v"] == "block:bots:headless"
    assert env.req("botb.test", "/?m=b4").status == 200 and env.last_log("botb.test", "m=b4")["v"] == "ok"


def test_verified_and_spoofed_crawlers(env):
    assert env.req("botb.test", "/?m=g1", ua=GOOGLEBOT, src=GOOGLE_IP).status == 200
    assert env.last_log("botb.test", "m=g1")["v"] == "ok"
    r = env.req("botb.test", "/?m=g2", ua=GOOGLEBOT)                      # Googlebot UA, not a Google IP
    assert r.status == 403 and env.last_log("botb.test", "m=g2")["v"] == "block:bots:spoofed"
    assert env.req("botb.test", "/?m=g3", ua=BINGBOT, src=BING_IP).status == 200
    assert env.req("botb.test", "/?m=g4", ua=BINGBOT, src=GOOGLE_IP).status == 403   # wrong engine's range
    assert env.last_log("botb.test", "m=g4")["v"] == "block:bots:spoofed"
    # a verified crawler is not sent the DDoS JS challenge it cannot solve; a browser is
    assert env.req("botd.test", "/?m=v1", ua=GOOGLEBOT, src=GOOGLE_IP).status == 200
    assert env.req("botd.test", "/?m=v2").status == 403
    assert env.last_log("botd.test", "m=v2")["v"] == "challenge:ddos:js"


# ----------------------------------------------------------------- authenticated origin pulls

def test_mtls_platform_custom_and_off(env):
    r = env.req("mtls.test", "/echo")
    assert r.status == 200 and r.json["peer"] == "platform"
    r = env.req("mtlsc.test", "/echo")
    assert r.status == 200 and r.json["peer"] == "customer"
    assert env.req("mtlsoff.test", "/echo").status == 502          # the origin requires a client certificate
    files = sorted(p.relative_to(env.cfg["NGINX_DIR"]).as_posix()
                   for p in (pathlib.Path(env.cfg["NGINX_DIR"]) / "mtls").iterdir())
    assert files == ["mtls/412.crt", "mtls/412.key", "mtls/platform.crt", "mtls/platform.key"]
    for f in files:
        assert oct((pathlib.Path(env.cfg["NGINX_DIR"]) / f).stat().st_mode & 0o777) == "0o600"


def test_mtls_image_resizer(env):
    r = env.req("mtlsimg.test", "/pic.png?width=100")
    assert r.status == 200 and r.headers["content-type"] == "image/png", r.body[:200]
    assert struct.unpack(">II", r.body[16:24]) == (100, 75)
    assert env.req("mtlsimg.test", "/echo").json["peer"] == "platform"
    # a visitor cannot make the resizer present a certificate by sending the selector header itself:
    # the origin refuses the handshake (the resizer turns that into 415, image_filter's error)
    for sel in ("platform", "411", agent.mtls_token("platform", ("", "guess"))):
        assert env.req("mtlsoffimg.test", "/pic.png?width=100", headers={"X-Pcdn-Mtls": sel}).status in (415, 502)


# ----------------------------------------------------------------- reconfigures the edge: last

def test_bots_fail_open_without_ranges(env):
    """No verified ranges ever received: a crawler UA is not treated as spoofed; library UAs still are."""
    config = dict(env.config, bots={"verified": {}, "fetched_at": None})
    try:
        assert agent.apply_config(config, env.cfg) is None
        assert "bots.conf" not in [p.name for p in pathlib.Path(env.cfg["NGINX_DIR"]).iterdir()]
        assert env.req("botb.test", "/?m=f1", ua=GOOGLEBOT).status == 200
        assert env.req("botb.test", "/?m=f2", ua="curl/8").status == 403
    finally:
        assert agent.apply_config(env.config, env.cfg) is None
    assert env.req("botb.test", "/?m=f3", ua=GOOGLEBOT).status == 403
