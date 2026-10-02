"""End-to-end tests for SPEC §14.1 (Wave 6A: edge performance & cache) with real nginx + njs.

Two nginx instances run the agent's rendered config: an EDGE (non-shield node whose shield peer is
127.0.0.1) and a SHIELD (shield.self). A python origin echoes requests, serves cacheable assets,
negotiates WebP on Accept and can be switched to answer 500. Covered: the shield hop, which is TLS
only (address / scheme forwarding, header stripping, caching on the shield, no double billing,
GET/HEAD only, certificate verification, fallback to the origin), HTTP-only sites never shielding,
the shield refusing forged headers and valid headers sent over plain HTTP, cache-key
variants (device / cookies / query allow-list) and their purge, stale-if-error and
stale-while-revalidate, preload Link headers and the WebP accept-key mode. nginx 1.24 has no
HTTP/3: h3 rendering is covered by text assertions in test_agent.py only.
"""

import http.client
import http.server
import importlib.util
import json
import pathlib
import shutil
import socket
import ssl
import subprocess
import threading
import time

import pytest

from conftest import modules_available, nginx_conf, TEST_ORIGIN_ALLOW

HERE = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("agent_perf_e2e", HERE.parent / "pcdn-agent.py")
agent = importlib.util.module_from_spec(spec)
spec.loader.exec_module(agent)

pytestmark = pytest.mark.skipif(shutil.which("nginx") is None or not modules_available(),
                                reason="nginx with njs/geoip2/image_filter/brotli modules not installed")

SECRET = "5e" * 32
SHIELD_SECRET = "c0ffee" * 6
CLIENT_IP = "127.0.0.5"   # visitors connect from here; the edge reaches the shield from 127.0.0.1
UA_MOBILE = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148"
UA_DESKTOP = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/126.0 Safari/537.36"
PNG = b"\x89PNG\r\n\x1a\n" + b"png-bytes" * 10
WEBP = b"RIFF\x00\x00\x00\x00WEBPVP8 " + b"webp-bytes" * 10


def free_port() -> int:
    from conftest import pick_port

    return pick_port()


class Origin:
    """*/echo*: JSON of the request; *.css: cacheable text; /sie/*: Cache-Control max-age=1 (500
    while the path is in `failing`); *.png/*.jpg: WebP when Accept allows it (and no Vary)."""

    def __init__(self):
        self.hits, self.failing = {}, set()
        origin = self

        class H(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):
                pass

            def _send(self, code, body, ctype, extra=()):
                self.send_response(code)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                for k, v in extra:
                    self.send_header(k, v)
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(body)

            def do_GET(self):
                path = self.path.split("?", 1)[0]
                n = origin.hits[path] = origin.hits.get(path, 0) + 1
                if self.command == "POST":
                    self.rfile.read(int(self.headers.get("Content-Length") or 0))
                if "/echo" in path or self.command == "POST":
                    body = json.dumps({"path": self.path, "method": self.command, "headers": dict(self.headers)})
                    return self._send(200, body.encode(), "application/json")
                if path.startswith("/sie/"):
                    if path in origin.failing:
                        return self._send(500, b"origin down", "text/plain")
                    return self._send(200, f"v{n}".encode(), "text/plain", [("Cache-Control", "max-age=1")])
                if path.endswith((".png", ".jpg")):
                    if "image/webp" in (self.headers.get("Accept") or ""):
                        return self._send(200, WEBP, "image/webp")
                    return self._send(200, PNG, "image/png")
                if path.endswith(".css"):
                    return self._send(200, f"/* {self.path} {n} */".encode(), "text/css")
                return self._send(200, f"page {self.path}".encode(), "text/html")

            do_POST = do_HEAD = do_GET

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.server.daemon_threads = True
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


class Node:
    def __init__(self, cfg, conf, tmp):
        self.cfg, self.conf, self.tmp = cfg, conf, tmp
        self.port, self.sport = int(cfg["HTTP_PORT"]), int(cfg["HTTPS_PORT"])

    def req(self, host, path="/", method="GET", headers=None, body=None, https=False, src=CLIENT_IP):
        h = {"Host": host, "User-Agent": UA_DESKTOP, "Connection": "close"}
        h.update(headers or {})
        if https:
            ctx = ssl.create_default_context()
            ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
            sock = socket.create_connection(("127.0.0.1", self.sport), timeout=10, source_address=(src, 0))
            conn = http.client.HTTPSConnection(host, self.sport, timeout=10, context=ctx)
            conn.sock = ctx.wrap_socket(sock, server_hostname=host)
        else:
            conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10, source_address=(src, 0))
        try:
            conn.request(method, path, body=body, headers=h)
            r = conn.getresponse()
            return Resp(r, r.read())
        finally:
            conn.close()

    def log(self):
        p = pathlib.Path(self.cfg["ACCESS_LOG"])
        return [json.loads(x) for x in p.read_text().splitlines() if x.strip()] if p.exists() else []


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


def site(sid, host, origin_port, **sections):
    s = {"id": sid, "domain": host, "status": "active", "secret": SECRET, "ssl": None, "rate_limit_rps": 0,
         "blocked_ips": [], "hosts": [{"name": host, "origin": {"address": "127.0.0.1", "port": origin_port}}],
         "cache": {"enabled": True, "level": "standard", "edge_ttl": 3600, "browser_ttl": 0, "ignore_query": False,
                   "bypass_cookies": [], "always_online": True}}
    for k, v in sections.items():
        s[k] = dict(s[k], **v) if k == "cache" else v
    return s


def node_cfg(tmp, **over):
    cfg = dict(agent.DEFAULTS, ORIGIN_PRIVATE_ALLOW=TEST_ORIGIN_ALLOW)
    cfg.update({
        "NGINX_DIR": str(tmp / "pcdn"), "CACHE_DIR": str(tmp / "cache"), "STATE_FILE": str(tmp / "state.json"),
        "ACCESS_LOG": str(tmp / "access.log"), "L4_ACCESS_LOG": str(tmp / "l4.log"), "FN_USAGE_LOG": str(tmp / "fn-usage.log"), "PAGES_DIR": str(HERE.parent / "pages"),
        "NJS_FILE": str(HERE.parent / "njs/pcdn.js"), "BASE_TEMPLATE": str(HERE.parent / "nginx/pcdn-base.conf"),
        "GEOIP_DB": str(tmp / "none.mmdb"), "RESOLVER": "127.0.0.1", "NGINX_USER": "root", "LISTEN_IPV6": "no",
        "HTTP_PORT": str(free_port()), "HTTPS_PORT": str(free_port()), "RESIZE_PORT": str(free_port()),
        "DICT_SIZE": "4m",
    })
    cfg.update(over)
    conf = nginx_conf(tmp, cfg)
    cfg["NGINX_TEST_CMD"] = f"nginx -t -q -c {conf}"
    cfg["NGINX_RELOAD_CMD"] = f"nginx -s reload -c {conf}"
    return cfg, conf


def self_signed(tmp, cn):
    key, crt = tmp / f"{cn}.key", tmp / f"{cn}.crt"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
                    "-subj", f"/CN={cn}", "-addext", f"subjectAltName=DNS:{cn}", "-days", "2",
                    "-keyout", key, "-out", crt], check=True, capture_output=True)
    return crt, key


def start(node, config):
    agent.bootstrap(node.cfg)
    p = subprocess.run(["nginx", "-c", str(node.conf)], capture_output=True, text=True)
    assert p.returncode == 0, p.stderr
    assert wait_for(lambda: node.req("unknown.test", "/__pcdn/health").status == 200)
    err = agent.apply_config(config, node.cfg)
    assert err is None, err


@pytest.fixture(scope="module")
def env(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("perf")
    origin = Origin()
    op = origin.port
    crt, key = self_signed(tmp, "shs.test")
    tls = {"cert": crt.read_text(), "key": key.read_text()}
    crt2, key2 = self_signed(tmp, "shtf.test")
    tls2 = {"cert": crt2.read_text(), "key": key2.read_text()}
    bundle = tmp / "bundle.pem"       # the edge verifies both shielded sites' certificates on the hop
    bundle.write_text(tls["cert"] + tls2["cert"])

    def shield_sites(hop):
        req = {"request": [{"name": "X-Hop", "value": hop}]}
        fw = {"default_action": "allow", "rules": [{"id": "blk", "enabled": True, "action": "block",
                                                    "conditions": [{"field": "path", "op": "starts_with",
                                                                    "value": "/blocked"}]}]}
        # SPEC §14.2 transform rules on a shielded site: an unconditional rewrite_path plus
        # conditional header rules whose values differ per node, to show the shield never re-applies
        # what the visitor-facing edge did (no double rewrite, hop headers passed through)
        tfm = {"rules": [
            {"id": "rw", "enabled": True, "match": {"path": "/*", "methods": [], "countries": []},
             "actions": [{"type": "rewrite_path", "name": None, "value": None, "regex": "^/rw/(.*)$",
                          "replacement": "/echo/pre/$1"}]},
            {"id": "hdr", "enabled": True, "match": {"path": "/rw/*", "methods": [], "countries": []},
             "actions": [{"type": "set_request_header", "name": "X-Tf", "value": hop, "regex": None, "replacement": None},
                         {"type": "set_response_header", "name": "X-Tf-Resp", "value": hop, "regex": None,
                          "replacement": None}]}]}
        # sh.test has no certificate (never shielded); shs.test hops edge -> shield over TLS
        return [site(306, "sh.test", op, cache={"shield": True}, headers=req, firewall=fw),
                site(307, "shs.test", op, cache={"shield": True}, headers=req, ssl=tls, firewall=fw,
                     ssl_options={"force_https": False, "origin_protocol": "http"}),
                site(309, "shtf.test", op, cache={"shield": True}, headers=req, ssl=tls2, transform=tfm,
                     ssl_options={"force_https": False, "origin_protocol": "http"})]

    edge_sites = [
        site(301, "kv.test", op, cache={"key_device": True, "key_cookies": ["lang", "wp-lang"],
                                        "key_query_allow": ["v"]}),
        site(302, "swr.test", op, cache={"stale_while_revalidate": True, "stale_if_error": 0}),
        site(303, "sie.test", op, cache={"stale_while_revalidate": False, "stale_if_error": 86400}),
        site(304, "nostale.test", op, cache={"stale_while_revalidate": False, "stale_if_error": 0}),
        site(305, "pre.test", op, pagerules={"rules": [
            {"id": "home", "enabled": True, "pattern": "/",
             "preload": [{"url": "/a.css", "as": "style"}, {"url": "/f.woff2", "as": "font"},
                         {"url": '/x"; evil', "as": "style"}, {"url": "/y\r\nSet-Cookie: a=b", "as": "script"}]},
            {"id": "blog", "enabled": True, "pattern": "/blog/*", "preload": [{"url": "/b.js", "as": "script"}]}]}),
        site(308, "webp.test", op, image={"enabled": True, "quality": 80, "max_width": 2000, "auto_webp": True}),
    ] + shield_sites("edge")

    shield_tmp, edge_tmp = tmp / "shield", tmp / "edge"
    shield_tmp.mkdir()
    edge_tmp.mkdir()
    s_cfg, s_conf = node_cfg(shield_tmp)
    e_cfg, e_conf = node_cfg(edge_tmp, SHIELD_HTTPS_PORT=s_cfg["HTTPS_PORT"], CA_BUNDLE=str(bundle))
    shield = Node(s_cfg, s_conf, shield_tmp)
    edge = Node(e_cfg, e_conf, edge_tmp)
    edge.config = {"sites": edge_sites, "shield": {"self": False, "peers": ["127.0.0.1"], "secret": SHIELD_SECRET}}
    try:
        start(shield, {"sites": shield_sites("shield"), "shield": {"self": True, "peers": [], "secret": SHIELD_SECRET}})
        start(edge, edge.config)
        assert wait_for(lambda: edge.req("kv.test", "/ready.css").status == 200)
        edge.origin, edge.shield = origin, shield
        yield edge
    finally:
        for n in (edge, shield):
            subprocess.run(["nginx", "-s", "stop", "-c", str(n.conf)], capture_output=True)
        origin.stop()


def xcache(r):
    return r.headers.get("x-cache")


# ----------------------------------------------------------------- origin shield

def hdrs(r):
    return {k.lower(): v for k, v in r.json["headers"].items()}


def test_shield_hop_forwards_visitor_and_strips_secret(env):
    r = env.req("shs.test", "/echo?a=1")                         # http visitor; the hop is TLS
    assert r.status == 200, r.body
    h = hdrs(r)
    assert h["x-hop"] == "shield"                                  # fetched by the shield
    assert h["host"] == "shs.test"                                 # Host preserved over the hop
    assert h["x-real-ip"] == CLIENT_IP and h["x-forwarded-for"] == CLIENT_IP
    assert h["x-forwarded-proto"] == "http"
    assert "x-pcdn-shield" not in h                                # never reaches the origin
    # one X-Cache / X-Served-By (the edge's), not the shield's copies on top
    assert len(r.all("X-Cache")) == 1 and len(r.all("X-Served-By")) == 1


def test_http_only_site_never_shields(env):
    """A site without a certificate fetches from the origin directly and never sends the secret."""
    r = env.req("sh.test", "/echo?plain=1")
    h = hdrs(r)
    assert r.status == 200 and h["x-hop"] == "edge" and "x-pcdn-shield" not in h
    assert xcache(env.req("sh.test", "/h1.css")) == "MISS" and env.origin.hits["/h1.css"] == 1
    assert xcache(env.shield.req("sh.test", "/h1.css")) == "MISS"   # the shield never fetched it
    assert env.origin.hits["/h1.css"] == 2


def test_shield_caches_and_does_not_bill_twice(env):
    o, shield = env.origin, env.shield
    assert xcache(env.req("shs.test", "/s1.css")) == "MISS" and o.hits["/s1.css"] == 1
    # the shield stored it: a direct (ordinary visitor) request there is a HIT, no new origin fetch
    direct = shield.req("shs.test", "/s1.css")
    assert xcache(direct) == "HIT" and o.hits["/s1.css"] == 1
    assert xcache(env.req("shs.test", "/s1.css")) == "HIT"
    # usage: the shield logs the direct request only, never the hop the edge sent
    env.req("shs.test", "/s2.css?m=billing")
    assert wait_for(lambda: any(e["u"] == "/s2.css?m=billing" for e in env.log()))
    assert wait_for(lambda: any(e["u"] == "/s1.css" for e in shield.log()))
    time.sleep(1.5)   # access logs are buffered (flush=1s)
    assert [e["u"] for e in shield.log() if e["u"].startswith("/s")] == ["/s1.css"]
    assert all("c0ffee" not in json.dumps(e) for e in shield.log() + env.log())   # secret never logged


def test_shield_only_for_get_and_head(env):
    post = env.req("shs.test", "/echo", "POST", {"Content-Type": "application/json"}, b"{}")
    assert post.status == 200 and post.json["headers"]["X-Hop"] == "edge"   # straight to the origin
    head = env.req("shs.test", "/echo-head", "HEAD")
    assert head.status == 200 and env.origin.hits["/echo-head"] == 1


def test_shield_accepts_only_a_valid_secret_over_tls(env):
    shield = env.shield

    def get(path, https, **h):
        return shield.req("shs.test", path, headers=h, https=https)
    for https in (True, False):
        assert get("/blocked", https).status == 403                                # firewall applies
        assert get("/blocked", https, **{"X-Pcdn-Shield": "f" * 36}).status == 403
        assert get("/blocked", https, **{"X-Pcdn-Shield": SHIELD_SECRET + "0"}).status == 403
    claimed = {"X-Pcdn-Shield": SHIELD_SECRET, "X-Real-IP": "203.0.113.9", "X-Forwarded-For": "203.0.113.9"}
    ok = get("/blocked/echo", True, **claimed)                                     # TLS + valid: a hop
    assert ok.status == 200
    h = hdrs(ok)
    assert h["x-real-ip"] == "203.0.113.9" and "x-pcdn-shield" not in h
    # the valid secret over plain HTTP is an ordinary visitor (and still never reaches the origin)
    assert get("/blocked/echo", False, **claimed).status == 403
    assert shield.req("sh.test", "/blocked", headers={"X-Pcdn-Shield": SHIELD_SECRET}).status == 403
    plain = hdrs(get("/echo?plainsecret=1", False, **claimed))
    assert plain["x-real-ip"] == CLIENT_IP and "x-pcdn-shield" not in plain
    assert wait_for(lambda: any(e["u"] == "/echo?plainsecret=1" for e in shield.log()))   # logged + billed
    # a forged hop over TLS is an ordinary visitor too: its own address, not the claimed one
    forged = hdrs(get("/echo", True, **dict(claimed, **{"X-Pcdn-Shield": "nope"})))
    assert forged["x-real-ip"] == CLIENT_IP


def test_shield_https_hop_verifies_certificate(env):
    r = env.req("shs.test", "/echo?tls=1", https=True)
    h = hdrs(r)
    assert h["x-hop"] == "shield" and h["x-forwarded-proto"] == "https"
    # an http visitor of an HTTPS site still hops over TLS; the shield keeps the visitor's scheme
    plain = env.req("shs.test", "/echo?tls=0")
    h = hdrs(plain)
    assert h["x-hop"] == "shield" and h["x-forwarded-proto"] == "http"


def test_shield_with_transform_rules_applies_them_once(env):
    """SPEC §14.2 + §14.1: the edge rewrites the path and sets the headers; the shield (a valid hop
    never matches a transform condition and skips rewrite_path) passes them through unchanged."""
    r = env.req("shtf.test", "/rw/x?q=1")
    assert r.status == 200, r.body
    h = hdrs(r)
    assert r.json["path"] == "/echo/pre/x?q=1"                      # rewritten once, not twice
    assert h["x-hop"] == "shield" and h["x-tf"] == "edge"            # fetched by the shield, edge's value
    assert r.all("X-Tf-Resp") == ["edge"]
    # a visitor of the shield itself gets the shield's own transforms
    d = env.shield.req("shtf.test", "/rw/y")
    assert d.json["path"] == "/echo/pre/y" and hdrs(d)["x-tf"] == "shield" and d.all("X-Tf-Resp") == ["shield"]
    # POST is never shielded: the origin fallback rewrites exactly once as well
    p = env.req("shtf.test", "/rw/p", "POST", {"Content-Type": "application/json"}, b"{}")
    assert p.json["path"] == "/echo/pre/p" and hdrs(p)["x-hop"] == "edge" and hdrs(p)["x-tf"] == "edge"
    # cached on the edge under the visitor's URL
    assert xcache(env.req("shtf.test", "/rw/t.css")) == "MISS"
    assert xcache(env.req("shtf.test", "/rw/t.css")) == "HIT" and env.origin.hits["/echo/pre/t.css"] == 1


# ----------------------------------------------------------------- cache key variants + purge

def test_cache_key_device_variants(env):
    assert xcache(env.req("kv.test", "/d.css", headers={"User-Agent": UA_MOBILE})) == "MISS"
    assert xcache(env.req("kv.test", "/d.css", headers={"User-Agent": UA_DESKTOP})) == "MISS"
    assert xcache(env.req("kv.test", "/d.css", headers={"User-Agent": UA_MOBILE})) == "HIT"
    assert xcache(env.req("kv.test", "/d.css", headers={"User-Agent": UA_DESKTOP})) == "HIT"
    assert env.origin.hits["/d.css"] == 2


def test_cache_key_cookie_variants(env):
    get = lambda c: xcache(env.req("kv.test", "/c.css", headers={"Cookie": c} if c else {}))  # noqa: E731
    assert get("lang=fa") == "MISS" and get("lang=en") == "MISS"
    assert get("other=1; lang=fa") == "HIT"                 # only the listed cookies count
    assert get("lang=fa; wp-lang=x") == "MISS"              # a dashed cookie name (regex map)
    assert get("wp-lang=x; lang=fa") == "HIT"
    assert get(None) == "MISS" and get("unrelated=1") == "HIT"


def test_cache_key_query_allow_list(env):
    get = lambda q: xcache(env.req("kv.test", "/q.css" + q))  # noqa: E731
    assert get("?v=1&utm_source=a") == "MISS"
    assert get("?utm_source=b&v=1") == "HIT"                # other params are not part of the key
    assert get("?v=2") == "MISS" and get("") == "MISS" and get("?fbclid=x") == "HIT"


def _keys_on_disk(env, sid):
    return sorted(k for k in (agent._read_cache_key(str(p)) for p in (pathlib.Path(env.cfg["CACHE_DIR"]) / str(sid))
                              .rglob("*") if p.is_file()) if k)


def test_purge_removes_every_variant(env):
    for ua in (UA_MOBILE, UA_DESKTOP):
        env.req("kv.test", "/p.css?v=7&x=1", headers={"User-Agent": ua, "Cookie": "lang=fa"})
    mine = lambda: [k for k in _keys_on_disk(env, 301) if k.startswith("http://kv.test/p.css")]  # noqa: E731
    assert wait_for(lambda: len(mine()) == 2)
    assert mine() == ["http://kv.test/p.css?v=7;d=desktop;c.lang=fa;c.wp-lang=",
                      "http://kv.test/p.css?v=7;d=mobile;c.lang=fa;c.wp-lang="]
    kinfo = agent.key_infos(env.config)["301"]
    assert agent.do_purge({"site_id": 301, "urls": ["http://kv.test/p.css?x=2&v=7"]}, env.cfg, kinfo) == 2
    assert mine() == []


# ----------------------------------------------------------------- stale content

def _prime_then_expire(env, host, path):
    r = env.req(host, path)
    assert r.status == 200 and xcache(r) == "MISS", (r.status, r.body)
    # origin max-age=1: nginx stores valid_sec = now + 1 at whole-second resolution and expires the
    # entry once now > valid_sec, i.e. up to 2 s later
    time.sleep(2.2)


def test_stale_if_error_serves_stale_on_origin_5xx(env):
    _prime_then_expire(env, "sie.test", "/sie/a")
    env.origin.failing.add("/sie/a")
    r = env.req("sie.test", "/sie/a")
    assert r.status == 200 and r.body == b"v1" and xcache(r) == "STALE"
    # stale_if_error = 0 (and no stale-while-revalidate): the origin's 500 goes through
    _prime_then_expire(env, "nostale.test", "/sie/b")
    env.origin.failing.add("/sie/b")
    r = env.req("nostale.test", "/sie/b")
    assert r.status == 500 and xcache(r) == "EXPIRED"


def test_stale_while_revalidate(env):
    _prime_then_expire(env, "swr.test", "/sie/c")
    r = env.req("swr.test", "/sie/c")
    assert r.body == b"v1" and xcache(r) in ("STALE", "UPDATING")    # answered at once, refreshed behind
    assert wait_for(lambda: env.req("swr.test", "/sie/c").body == b"v2", 5)
    # off: an expired entry is refetched synchronously
    _prime_then_expire(env, "nostale.test", "/sie/d")
    r = env.req("nostale.test", "/sie/d")
    assert r.body == b"v2" and xcache(r) == "EXPIRED"


# ----------------------------------------------------------------- preload / WebP

def test_preload_link_headers(env):
    home = env.req("pre.test", "/")
    assert home.all("Link") == ["</a.css>; rel=preload; as=style, </f.woff2>; rel=preload; as=font; crossorigin"]
    assert "set-cookie" not in home.headers
    assert env.req("pre.test", "/blog/post").all("Link") == ["</b.js>; rel=preload; as=script"]
    assert env.req("pre.test", "/other").all("Link") == []
    assert env.req("pre.test", "/style.css").all("Link") == []


def test_webp_accept_key_mode(env):
    webp = {"Accept": "image/avif,image/webp,*/*"}
    a = env.req("webp.test", "/p.png", headers=webp)
    assert a.status == 200 and a.headers["content-type"] == "image/webp" and xcache(a) == "MISS"
    assert "Accept" in a.all("Vary")
    b = env.req("webp.test", "/p.png", headers={"Accept": "image/png,*/*"})
    assert b.headers["content-type"] == "image/png" and xcache(b) == "MISS"
    c = env.req("webp.test", "/p.png", headers=webp)
    assert c.body == WEBP and xcache(c) == "HIT" and "Accept" in c.all("Vary")
    d = env.req("webp.test", "/p.png")                             # no Accept: the non-WebP variant
    assert d.body == PNG and xcache(d) == "HIT"
    css = env.req("webp.test", "/x.css", headers=webp)
    assert "Accept" not in css.all("Vary")


# ----------------------------------------------------------------- shield fallback (reconfigures the edge: last)

def test_shield_unreachable_falls_back_to_origin(env):
    dead = dict(env.cfg, SHIELD_HTTPS_PORT=str(free_port()))
    try:
        assert agent.apply_config(env.config, dead) is None          # verified via /__pcdn/confver
        r = env.req("shs.test", "/echo?fallback=1")
        assert r.status == 200 and r.json["headers"]["X-Hop"] == "edge"
        assert "x-pcdn-shield" not in hdrs(r)
        s = env.req("shs.test", "/fb.css")
        assert s.status == 200 and xcache(s) == "MISS" and xcache(env.req("shs.test", "/fb.css")) == "HIT"
        tls = env.req("shs.test", "/echo?fallback=2", https=True)
        assert tls.status == 200 and tls.json["headers"]["X-Hop"] == "edge"
    finally:
        assert agent.apply_config(env.config, env.cfg) is None
