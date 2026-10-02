"""SPEC §16.8 object-storage origins end to end with real nginx.

A python TLS server emulates the bucket endpoint (path-style `/<bucket>/<key>`, objects readable only
with the bucket's Referer token, every request recorded); a tiny DNS responder resolves the endpoint
names for nginx's resolver, so the edge really connects by hostname with SNI and certificate
verification against CA_BUNDLE (the endpoint's self-signed certificate). Covered: Host / Referer /
path prefix / no query string, the visitor's Authorization / Cookie / X-Amz-* / X-Pcdn-* never
reaching the bucket, GET/HEAD only (405 + Allow), the path guard (400), caching, a certificate that
does not match (502, no request sent), the image resizer and transformer through the loopback
storage server, the functions pass-through and fetch() socket, and the token never appearing in a
response, the access log, the error log or the agent's log.
"""

import io
import logging
import os
import shutil
import socket
import ssl
import struct
import subprocess
import threading
import http.server

import pytest

from conftest import modules_available, nginx_conf, TEST_ORIGIN_ALLOW
from test_perf_e2e import Node, agent, free_port, self_signed, wait_for

pytestmark = pytest.mark.skipif(shutil.which("nginx") is None or not modules_available(),
                                reason="nginx with njs/geoip2/image_filter/brotli modules not installed")

try:
    from PIL import Image
except ImportError:  # pragma: no cover
    Image = None

TOKEN = "edgeTok_" + "Q7w-x9_Z" * 5          # 48 chars
BUCKET = "cdn-abc12345-assets"
SECRET = "5e" * 32


class DNS:
    """A records for the names in `zone` (127.0.0.1), NXDOMAIN for anything else, no AAAA."""

    def __init__(self, zone):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port, self.zone = self.sock.getsockname()[1], set(zone)
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while True:
            try:
                data, addr = self.sock.recvfrom(512)
            except OSError:
                return
            try:
                self.sock.sendto(self._answer(data), addr)
            except (OSError, ValueError, IndexError, struct.error):
                pass

    def _answer(self, q):
        i, labels = 12, []
        while q[i]:
            labels.append(q[i + 1:i + 1 + q[i]].decode().lower())
            i += 1 + q[i]
        qtype = struct.unpack("!H", q[i + 1:i + 3])[0]
        question = q[12:i + 5]
        name = ".".join(labels)
        known = name in self.zone
        an = (b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 30, 4) + socket.inet_aton("127.0.0.1")) if known and qtype == 1 else b""
        flags = 0x8180 if known else 0x8183
        return q[:2] + struct.pack("!HHHHH", flags, 1, 1 if an else 0, 0, 0) + question + an

    def stop(self):
        self.sock.close()


class Bucket:
    """The storage endpoint: TLS, path-style, anonymous GET only with the Referer token."""

    def __init__(self, crt, key, jpg):
        self.reqs, b = [], self
        self.objects = {f"/{BUCKET}/hello.txt": (b"hello object", "text/plain"),
                        f"/{BUCKET}/fn/hello.txt": (b"fn object", "text/plain"),
                        f"/{BUCKET}/img/a.jpg": (jpg, "image/jpeg")}

        class H(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):
                pass

            def _reply(self, code, body, ctype):
                self.send_response(code)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("X-Amz-Request-Id", "17A2B3C4D5E6F")
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(body)

            def _any(self):
                n = int(self.headers.get("Content-Length") or 0)
                if n:
                    self.rfile.read(n)
                b.reqs.append({"method": self.command, "path": self.path, "headers": dict(self.headers.items()),
                               "sni": getattr(self.connection, "server_hostname", None)})
                if self.command not in ("GET", "HEAD"):
                    return self._reply(405, b"<Error><Code>MethodNotAllowed</Code></Error>", "application/xml")
                if self.headers.get("Referer") != TOKEN or "Authorization" in self.headers:
                    return self._reply(403, b"<Error><Code>AccessDenied</Code></Error>", "application/xml")
                obj = b.objects.get(self.path)
                if obj is None:
                    return self._reply(404, b"<Error><Code>NoSuchKey</Code></Error>", "application/xml")
                return self._reply(200, *obj)

            do_GET = do_HEAD = do_POST = do_PUT = do_DELETE = do_OPTIONS = do_PATCH = _any

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(crt, key)
        snis = {}

        def sni_cb(sock, name, _ctx):
            snis[id(sock)] = name
        ctx.sni_callback = sni_cb
        self.snis = []

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.server.daemon_threads = True
        orig_get = self.server.get_request

        def tls_get_request():
            conn, addr = orig_get()
            tconn = ctx.wrap_socket(conn, server_side=True, do_handshake_on_connect=False)
            tconn.settimeout(10)
            try:
                tconn.do_handshake()
            finally:
                b.snis.append(snis.pop(id(tconn), None))
            return tconn, addr
        self.server.get_request = tls_get_request
        self.server.handle_error = lambda *a: None
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def stop(self):
        self.server.shutdown()
        self.server.server_close()


class Plain:
    """An ordinary HTTP origin (the site's non-storage host): records the headers it receives."""

    def __init__(self):
        self.reqs, o = [], self

        class H(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):
                pass

            def do_GET(self):
                o.reqs.append({"path": self.path, "headers": dict(self.headers.items())})
                self.send_response(200)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"ok")

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.server.daemon_threads = True
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def stop(self):
        self.server.shutdown()
        self.server.server_close()


def jpeg():
    im = Image.new("RGB", (400, 200), (20, 120, 200))
    buf = io.BytesIO()
    im.save(buf, "JPEG", quality=90)
    return buf.getvalue()


def storage(host, port):
    return {"storage": {"host": host, "port": port, "tls": True, "host_header": f"{host}:{port}", "bucket": BUCKET,
                        "path_prefix": f"/{BUCKET}", "referer": TOKEN}}


@pytest.fixture(scope="module")
def env(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("sto")
    crt, key = self_signed(tmp, "s3.test")
    bucket, plain = Bucket(str(crt), str(key), jpeg() if Image else b"\xff\xd8"), Plain()
    dns = DNS({"s3.test", "wrong.test"})
    cfg = dict(agent.DEFAULTS, ORIGIN_PRIVATE_ALLOW=TEST_ORIGIN_ALLOW)
    cfg.update({
        "NGINX_DIR": str(tmp / "pcdn"), "CACHE_DIR": str(tmp / "cache"), "STATE_FILE": str(tmp / "state.json"),
        "ACCESS_LOG": str(tmp / "access.log"), "L4_ACCESS_LOG": str(tmp / "l4.log"), "FN_USAGE_LOG": str(tmp / "fn-usage.log"), "PAGES_DIR": str(agent.HERE) + "/pages",
        "NJS_FILE": str(agent.HERE) + "/njs/pcdn.js", "BASE_TEMPLATE": str(agent.HERE) + "/nginx/pcdn-base.conf",
        "GEOIP_DB": str(tmp / "none.mmdb"), "RESOLVER": f"127.0.0.1:{dns.port}", "NGINX_USER": "root",
        "LISTEN_IPV6": "no", "HTTP_PORT": str(free_port()), "HTTPS_PORT": str(free_port()),
        "RESIZE_PORT": str(free_port()), "IMAGE_PORT": str(free_port()), "STORAGE_FETCH_PORT": str(free_port()),
        "DICT_SIZE": "4m", "CA_BUNDLE": str(crt), "FUNCTIONS": "yes",
        "FN_SOCKET": str(tmp / "fn-absent.sock"), "FN_FETCH_SOCKET": str(tmp / "fetch.sock"),
    })
    conf = nginx_conf(tmp, cfg)
    cfg.update(NGINX_TEST_CMD=f"nginx -t -q -c {conf}", NGINX_RELOAD_CMD=f"nginx -s reload -c {conf}")
    node = Node(cfg, conf, tmp)
    node.bucket, node.plain, node.tmp = bucket, plain, tmp
    node.config = {"sites": [{
        "id": 501, "domain": "st.test", "status": "active", "secret": SECRET, "ssl": None, "rate_limit_rps": 0,
        "blocked_ips": [],
        "hosts": [{"name": "st.test", "origin": {"address": "127.0.0.1", "port": plain.port}},
                  {"name": "cdn.st.test", "origin": storage("s3.test", bucket.port)},
                  # the endpoint's certificate does not name wrong.test: verification must fail
                  {"name": "bad.st.test", "origin": storage("wrong.test", bucket.port)}],
        "cache": {"enabled": True, "level": "standard", "edge_ttl": 3600, "browser_ttl": 0, "ignore_query": False,
                  "bypass_cookies": [], "always_online": True},
        "image": {"enabled": True, "quality": 80, "max_width": 2000},
        "waf": {"mode": "block", "packs": ["wordpress"]},
        "functions": {"enabled": True, "items": [{"id": "fx", "route": "/fn/", "enabled": True, "on_error": "origin",
                                                  "code": "function handleRequest(r){return r.pass()}"}]},
    }]}
    imaged = agent.imaged_server(cfg) if agent.image_capabilities(cfg)["transform"] else None
    if imaged:
        threading.Thread(target=imaged.serve_forever, daemon=True).start()
    node.imaged = imaged
    logs = []

    class Grab(logging.Handler):
        def emit(self, record):
            logs.append(record.getMessage())
    grab = Grab()
    agent.log.addHandler(grab)
    node.agent_logs = logs
    try:
        agent.bootstrap(cfg)
        p = subprocess.run(["nginx", "-c", str(conf)], capture_output=True, text=True)
        assert p.returncode == 0, p.stderr
        assert wait_for(lambda: node.req("unknown.test", "/__pcdn/health").status == 200)
        err = agent.apply_config(node.config, cfg)
        assert err is None, err
        assert wait_for(lambda: node.req("cdn.st.test", "/__pcdn/health").status == 200)
        yield node
    finally:
        agent.log.removeHandler(grab)
        subprocess.run(["nginx", "-s", "stop", "-c", str(conf)], capture_output=True)
        if imaged:
            imaged.shutdown()
            imaged.server_close()
        bucket.stop()
        plain.stop()
        dns.stop()


VISITOR = {"Authorization": "AWS4-HMAC-SHA256 Credential=AKIAVISITOR/x", "Cookie": "session=visitor-secret",
           "X-Amz-Security-Token": "visitor-token", "X-Amz-Date": "20261001T000000Z",
           "X-Amz-Content-Sha256": "UNSIGNED-PAYLOAD", "X-Pcdn-Shield": "forged", "X-Pcdn-Fn-Site": "1",
           "X-Forwarded-Host": "evil.test", "Referer": "https://evil.example/page"}


def last(env, path):
    rs = [r for r in env.bucket.reqs if r["path"] == path]
    assert rs, (path, env.bucket.reqs[-3:])
    return rs[-1]


def no_token(*resps):
    for r in resps:
        assert TOKEN.encode() not in r.body and all(TOKEN not in v for _, v in r.header_list)


def test_get_rewrites_host_referer_path_and_strips_visitor_headers(env):
    r = env.req("cdn.st.test", "/hello.txt?X-Amz-Signature=abc&response-content-type=text/html&x=1", headers=VISITOR)
    assert r.status == 200 and r.body == b"hello object", (r.status, r.body)
    assert r.headers["x-cache"] == "MISS"
    no_token(r)
    req = last(env, f"/{BUCKET}/hello.txt")                            # path prefix, NO query string
    h = {k.lower(): v for k, v in req["headers"].items()}
    assert req["method"] == "GET" and h["host"] == f"s3.test:{env.bucket.port}" and h["referer"] == TOKEN
    for k in ("authorization", "cookie", "x-amz-security-token", "x-amz-date", "x-amz-content-sha256",
              "x-pcdn-shield", "x-pcdn-fn-site", "x-forwarded-host", "x-forwarded-for", "x-real-ip"):
        assert k not in h, k
    assert not any(k.startswith(("x-amz-", "x-pcdn-")) for k in h)
    assert "s3.test" in env.bucket.snis                                 # SNI = the endpoint name
    r2 = env.req("cdn.st.test", "/hello.txt?X-Amz-Signature=abc&response-content-type=text/html&x=1")
    assert r2.status == 200 and r2.headers["x-cache"] == "HIT"
    h = env.req("cdn.st.test", "/hello.txt", method="HEAD")
    assert h.status == 200 and h.body == b""
    miss = env.req("cdn.st.test", "/nope.txt")
    assert miss.status == 404 and last(env, f"/{BUCKET}/nope.txt")["headers"]["Referer"] == TOKEN
    no_token(r2, h, miss)


@pytest.mark.parametrize("method", ["POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
def test_only_get_and_head(env, method):
    n = len(env.bucket.reqs)
    r = env.req("cdn.st.test", "/hello.txt", method=method, body=b"x=1" if method in ("POST", "PUT", "PATCH") else None,
                headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert r.status == 405 and r.headers.get("allow") == "GET, HEAD"
    assert len(env.bucket.reqs) == n                                    # never reached the bucket
    no_token(r)
    # the method guard covers the image path and JSON / xmlrpc bodies (WAF body inspection) too
    assert env.req("cdn.st.test", "/img/a.jpg?width=100", method=method).status == 405
    assert env.req("cdn.st.test", "/xmlrpc.php", method=method, body=b"<x/>").status == 405
    assert len(env.bucket.reqs) == n


@pytest.mark.parametrize("path", ["/x/../hello.txt", "/a/%2e%2e/hello.txt", "/a/%2E./hello.txt", "/a%2fhello.txt",
                                  "/a%5c..%5chello.txt", "/x/./hello.txt", "/hello.txt%00"])
def test_paths_that_could_leave_the_bucket_are_refused(env, path):
    n = len(env.bucket.reqs)
    assert env.req("cdn.st.test", path).status == 400
    assert len(env.bucket.reqs) == n


def test_certificate_mismatch_fails_closed(env):
    n = len([r for r in env.bucket.reqs])
    r = env.req("bad.st.test", "/hello.txt")
    assert r.status == 502
    assert len(env.bucket.reqs) == n                                    # no HTTP request after a failed check
    no_token(r)


def test_ordinary_host_of_the_same_site_is_unchanged(env):
    r = env.req("st.test", "/page?x=1", headers={"Cookie": "a=b", "Referer": "https://ref.example/"})
    assert r.status == 200
    got = env.plain.reqs[-1]
    assert got["path"] == "/page?x=1" and got["headers"]["Cookie"] == "a=b"
    assert got["headers"]["Host"] == "st.test" and got["headers"]["Referer"] == "https://ref.example/"


@pytest.mark.skipif(Image is None, reason="python3-pil not installed")
def test_image_resizer_fetches_through_the_storage_origin(env):
    r = env.req("cdn.st.test", "/img/a.jpg?width=100", headers=VISITOR)
    assert r.status == 200 and r.headers["content-type"] == "image/jpeg", (r.status, r.body[:200])
    assert Image.open(io.BytesIO(r.body)).size == (100, 50)
    req = last(env, f"/{BUCKET}/img/a.jpg")
    assert req["headers"]["Referer"] == TOKEN and req["headers"]["Host"] == f"s3.test:{env.bucket.port}"
    assert "Authorization" not in req["headers"] and "Cookie" not in req["headers"]
    no_token(r)
    assert env.imaged is not None or not agent.image_capabilities(env.cfg)["transform"]
    if env.imaged is not None:   # images v2 transformer: originals via /__pcdn_rz/src/ -> loopback server
        r = env.req("cdn.st.test", "/img/a.jpg?w=80&fmt=webp")
        assert r.status == 200 and r.headers["content-type"] == "image/webp", (r.status, r.body[:200])
        assert Image.open(io.BytesIO(r.body)).size == (80, 40)
        no_token(r)
    # the loopback port answers 404 for hosts it does not know
    import http.client
    c = http.client.HTTPConnection("127.0.0.1", int(env.cfg["STORAGE_FETCH_PORT"]), timeout=5)
    c.request("GET", "/hello.txt", headers={"Host": "other.test"})
    assert c.getresponse().status == 404


def test_functions_pass_through_and_fetch_socket(env):
    # pcdn-fn is not running: on_error "origin" continues to the storage origin (GET only)
    r = env.req("cdn.st.test", "/fn/hello.txt?q=1", headers={"Cookie": "c=1"})
    assert r.status == 200 and r.body == b"fn object"
    req = last(env, f"/{BUCKET}/fn/hello.txt")
    assert req["headers"]["Referer"] == TOKEN and "Cookie" not in req["headers"]

    def fetch(raw):
        with socket.socket(socket.AF_UNIX) as s:
            s.settimeout(10)
            s.connect(env.cfg["FN_FETCH_SOCKET"])
            s.sendall(raw)
            out = b""
            while True:
                chunk = s.recv(65536)
                if not chunk:
                    return out
                out += chunk
    out = fetch(b"GET /hello.txt?sig=1 HTTP/1.0\r\nHost: cdn.st.test\r\nX-Pcdn-Fn-Site: 501\r\n"
                b"X-Pcdn-Fn-Client: 127.0.0.9\r\nAuthorization: Bearer x\r\nX-Amz-Date: 1\r\n\r\n")
    assert out.startswith(b"HTTP/1.1 200") and out.endswith(b"hello object") and TOKEN.encode() not in out
    h = last(env, f"/{BUCKET}/hello.txt")["headers"]
    assert h["Referer"] == TOKEN and "Authorization" not in h and "X-Amz-Date" not in h and "X-Pcdn-Fn-Client" not in h
    out = fetch(b"PUT /hello.txt HTTP/1.0\r\nHost: cdn.st.test\r\nX-Pcdn-Fn-Site: 501\r\nContent-Length: 1\r\n\r\nx")
    assert out.startswith(b"HTTP/1.1 405")
    out = fetch(b"GET /hello.txt HTTP/1.0\r\nHost: cdn.st.test\r\nX-Pcdn-Fn-Site: 9\r\n\r\n")
    assert out.startswith(b"HTTP/1.1 421")


def test_token_never_logged_and_kept_root_only(env):
    env.req("cdn.st.test", "/hello.txt", headers=VISITOR)
    env.req("bad.st.test", "/hello.txt")
    assert wait_for(lambda: any(e.get("h") == "bad.st.test" for e in env.log()), timeout=5)
    access = (env.tmp / "access.log").read_text()
    error = (env.tmp / "error.log").read_text()
    assert "cdn.st.test" in access and "upstream SSL certificate does not match" in error and "wrong.test" in error
    assert TOKEN not in access and TOKEN not in error
    assert all(TOKEN not in m for m in env.agent_logs)
    root = env.cfg["NGINX_DIR"]
    assert oct(os.stat(os.path.join(root, "storage/501.conf")).st_mode & 0o777) == "0o600"
    for rel in ("sites/501.conf", "http.conf", "js/sites.js"):
        with open(os.path.join(root, rel)) as f:
            assert TOKEN not in f.read(), rel
