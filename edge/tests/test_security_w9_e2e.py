"""Security review w9, edge side, end to end with real nginx (+ njs / PCRE2) and real nftables.

* H2 timing: customer regexes (firewall in njs, regex redirects / rewrite_path in nginx maps) and
  multi-star wildcards (rate limits, WAF off paths, page-rule locations) on adversarial requests
  answer in milliseconds; unsafe rules were skipped at render time;
* origin guard: nginx workers run as a dedicated unprivileged user, the agent's origin guard ruleset
  is loaded, origins are host names answered by a stub DNS server. An origin resolving to 127.0.0.1
  (a "local service"), to the loopback image resizer port or to 169.254.169.254 fails fast (502)
  while an allow-listed test origin and the edge's own resizer hop (proxy_bind INTERNAL_SRC) work,
  and processes of other users (here: root, like the agent) are untouched.
"""

import http.client
import http.server
import importlib.util
import os
import pathlib
import pwd
import re
import shutil
import socket
import socketserver
import struct
import subprocess
import tempfile
import threading
import time

import pytest
from conftest import TEST_ORIGIN_ALLOW, modules_available, nginx_conf

HERE = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("agent_w9e2e", HERE.parent / "pcdn-agent.py")
agent = importlib.util.module_from_spec(spec)
spec.loader.exec_module(agent)

pytestmark = pytest.mark.skipif(shutil.which("nginx") is None or not modules_available(),
                                reason="nginx with njs/geoip2/image_filter/brotli modules not installed")

SECRET = "5e" * 32


def free_port(host="127.0.0.1") -> int:
    from conftest import pick_port

    return pick_port(host)


class Origin:
    """Echo origin (records hits); *.png answers a small PNG."""

    def __init__(self, host="127.0.0.1"):
        self.hits = 0
        me = self

        class H(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):
                pass

            def do_GET(self):
                me.hits += 1
                if self.path.split("?")[0].endswith(".png"):
                    body, ctype = PNG, "image/png"
                else:
                    body, ctype = f"origin {self.path}".encode(), "text/plain"
                self.send_response(200)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self.server = http.server.ThreadingHTTPServer((host, 0), H)
        self.server.daemon_threads = True
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def stop(self):
        self.server.shutdown()
        self.server.server_close()


def _png(w, h):
    import zlib

    def chunk(kind, data):
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))
    rows = b"".join(b"\x00" + b"".join(bytes((x % 256, y % 256, 128)) for x in range(w)) for y in range(h))
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(rows)) + chunk(b"IEND", b""))


PNG = _png(200, 100)


def png_size(b):
    return struct.unpack(">II", b[16:24])


class StubDNS:
    """UDP DNS answering A queries from a dict (NXDOMAIN otherwise)."""

    def __init__(self, records):
        self.records = records
        me = self

        class H(socketserver.BaseRequestHandler):
            def handle(self):
                data, sock = self.request
                try:
                    i, labels = 12, []
                    while data[i]:
                        labels.append(data[i + 1:i + 1 + data[i]].decode())
                        i += 1 + data[i]
                    qtype = struct.unpack(">H", data[i + 1:i + 3])[0]
                    q = data[12:i + 5]
                except (IndexError, UnicodeDecodeError, struct.error):
                    return
                name = ".".join(labels).lower()
                ip = me.records.get(name)
                if ip and qtype == 1:
                    ans = b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 5, 4) + socket.inet_aton(ip)
                    resp = data[:2] + b"\x81\x80" + struct.pack(">HHHH", 1, 1, 0, 0) + q + ans
                else:
                    rcode = b"\x81\x80" if ip else b"\x81\x83"
                    resp = data[:2] + rcode + struct.pack(">HHHH", 1, 0, 0, 0) + q
                sock.sendto(resp, self.client_address)

        self.server = socketserver.ThreadingUDPServer(("127.0.0.1", 0), H)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def stop(self):
        self.server.shutdown()
        self.server.server_close()


def site(sid, host, origin, **sections):
    s = {"id": sid, "domain": host, "status": "active", "secret": SECRET, "ssl": None, "rate_limit_rps": 0,
         "blocked_ips": [], "hosts": [{"name": host, "origin": origin}],
         "cache": {"enabled": False, "level": "standard", "edge_ttl": 3600, "browser_ttl": 0, "ignore_query": False,
                   "bypass_cookies": [], "always_online": True}}
    s.update(sections)
    return s


def req(port, host, path="/", headers=None, timeout=20):
    h = {"Host": host, "User-Agent": "pytest", "Connection": "close"}
    h.update(headers or {})
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    try:
        t0 = time.monotonic()
        conn.request("GET", path, headers=h)
        r = conn.getresponse()
        body = r.read()
        return r.status, body, {k.lower(): v for k, v in r.getheaders()}, time.monotonic() - t0
    finally:
        conn.close()


def wait_for(fn, timeout=15.0):
    end = time.time() + timeout
    while time.time() < end:
        try:
            if fn():
                return True
        except (OSError, http.client.HTTPException):
            pass
        time.sleep(0.2)
    return False


def base_cfg(tmp, **over):
    cfg = dict(agent.DEFAULTS, ORIGIN_PRIVATE_ALLOW=TEST_ORIGIN_ALLOW)
    cfg.update({
        "NGINX_DIR": str(tmp / "pcdn"), "CACHE_DIR": str(tmp / "cache"), "STATE_FILE": str(tmp / "state.json"),
        "ACCESS_LOG": str(tmp / "access.log"), "L4_ACCESS_LOG": str(tmp / "l4.log"), "FN_USAGE_LOG": str(tmp / "fn-usage.log"), "PAGES_DIR": str(HERE.parent / "pages"),
        "NJS_FILE": str(HERE.parent / "njs/pcdn.js"), "BASE_TEMPLATE": str(HERE.parent / "nginx/pcdn-base.conf"),
        "GEOIP_DB": str(tmp / "missing.mmdb"), "RESOLVER": "127.0.0.1", "NGINX_USER": "root", "LISTEN_IPV6": "no",
        "HTTP_PORT": str(free_port()), "HTTPS_PORT": str(free_port()), "RESIZE_PORT": str(free_port()),
        "IMAGE_PORT": str(free_port()), "STORAGE_FETCH_PORT": str(free_port()), "DICT_SIZE": "4m", "IMAGED": "no",
    })
    cfg.update(over)
    return cfg


def start(cfg, conf):
    agent.bootstrap(cfg)
    p = subprocess.run(["nginx", "-c", str(conf)], capture_output=True, text=True)
    assert p.returncode == 0, p.stderr
    port = int(cfg["HTTP_PORT"])
    assert wait_for(lambda: req(port, "unknown.test", "/__pcdn/health")[0] == 200)
    cfg["NGINX_TEST_CMD"] = f"nginx -t -q -c {conf}"
    cfg["NGINX_RELOAD_CMD"] = f"nginx -s reload -c {conf}"


# ----------------------------------------------------------------- H2: regex timing on real nginx / njs

@pytest.fixture(scope="module")
def rx(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("w9rx")
    o = Origin()
    cfg = base_cfg(tmp)
    conf = nginx_conf(tmp, cfg)
    A = {"address": "127.0.0.1", "port": o.port}
    fw = {"default_action": "allow", "rules": [
        {"id": "ua", "action": "block", "conditions": [{"field": "user_agent", "op": "regex", "value": "a.*b$"}]},
        {"id": "two", "action": "block", "conditions": [{"field": "path", "op": "regex", "value": "^/(.*)/(.*)x$"}]},
        {"id": "hdr", "action": "block", "conditions": [{"field": "header", "name": "X-P", "op": "regex",
                                                         "value": ".*\\.php$"}]},
        # unsafe: skipped at render time (they would cost seconds per request)
        {"id": "exp", "action": "block", "conditions": [{"field": "user_agent", "op": "regex", "value": "^(a+)+$"}]},
        {"id": "poly", "action": "block", "conditions": [{"field": "user_agent", "op": "regex", "value": "a.*a.*c"}]}]}
    sites = [
        site(201, "rx.test", A, firewall=fw,
             ratelimit={"rules": [{"id": "rl", "path": "/*a*a*a*a*b", "requests": 1000, "period": 60}]},
             waf={"mode": "block", "paranoia": 1, "groups": ["sqli"]},
             pagerules={"rules": [{"id": "pr", "pattern": "/*a*a*a*b", "waf": False, "cache": "bypass"}]},
             redirects={"rules": [{"id": "r1", "match": "regex", "source": "^/r/(.*)/(.*)z$", "target": "/to/$2",
                                   "status": 302},
                                  {"id": "bad", "match": "regex", "source": "^/(a+)+$", "target": "/x", "status": 301}]},
             transform={"rules": [{"id": "t", "actions": [{"type": "rewrite_path", "regex": "^/w/(.*)/(.*)q$",
                                                           "replacement": "/rw/$1"}]}]}),
    ]
    start(cfg, conf)
    try:
        err = agent.apply_config({"sites": sites}, cfg)
        assert err is None, err
        assert wait_for(lambda: req(int(cfg["HTTP_PORT"]), "rx.test", "/ok")[0] == 200)
        yield int(cfg["HTTP_PORT"]), cfg, o
    finally:
        subprocess.run(["nginx", "-s", "stop", "-c", str(conf)], capture_output=True)
        o.stop()


def test_unsafe_customer_regexes_not_rendered(rx):
    _, cfg, _ = rx
    js = (pathlib.Path(cfg["NGINX_DIR"]) / "js/sites.js").read_text()
    conf = (pathlib.Path(cfg["NGINX_DIR"]) / "sites/201.conf").read_text()
    assert '"id": "ua"' in js and '"id": "exp"' not in js and '"id": "poly"' not in js
    assert "(a+)+" not in conf and "^/r/(.*)/(.*)z$" in conf


def test_adversarial_requests_answer_fast(rx):
    port, _, _ = rx
    slow = []
    probes = [("/ok", {"User-Agent": "a" * 7000 + "!"}),                 # firewall a.*b$ (njs, capped input)
              ("/ok", {"User-Agent": "a" * 7000 + "c!"}),                # the skipped a.*a.*c would be cubic here
              ("/ok", {"X-P": "Mozilla" * 1000 + "\x21"}),
              ("/" + "/" * 3000 + "y", {}),                              # firewall ^/(.*)/(.*)x$
              ("/" + "a" * 3000 + "b!", {}),                             # rate limit + page rule multi-star
              ("/" + "ab" * 1500 + "c", {}),
              ("/r/" + "/" * 1500 + "y", {}),                            # regex redirect map (<= 2048 bytes)
              ("/r/" + "/" * 5000 + "y", {}),                            # over 2048: map skipped
              ("/w/" + "/" * 1500 + "y", {}),                            # rewrite_path map
              ("/" + "a/" * 1000 + "!", {"User-Agent": "a" * 40 + "!"})]
    for path, headers in probes:
        status, _, _, took = req(port, "rx.test", path, headers)
        assert status in (200, 403, 404, 414), (path[:30], status)
        if took > 1.0:
            slow.append((path[:20], headers and list(headers)[0], round(took, 2)))
    assert not slow, slow


def test_regex_rules_still_work(rx):
    port, _, o = rx
    assert req(port, "rx.test", "/ok", {"User-Agent": "xab"})[0] == 403                  # a.*b$
    assert req(port, "rx.test", "/a/b/cx")[0] == 403                                     # ^/(.*)/(.*)x$
    assert req(port, "rx.test", "/ok", {"X-P": "index.php"})[0] == 403
    status, _, hdrs, _ = req(port, "rx.test", "/r/1/2z")
    assert status == 302 and hdrs["location"].endswith("/to/2")
    status, body, _, _ = req(port, "rx.test", "/w/abc/dq")
    assert status == 200 and body == b"origin /rw/abc", body[:60]
    # page rule /*a*a*a*b (WAF off): an SQLi probe on a matching path passes, elsewhere it is blocked
    assert req(port, "rx.test", "/xayazab?id=1%27%20or%20%271%27=%271")[0] == 200
    assert req(port, "rx.test", "/xyz?id=1%27%20or%20%271%27=%271")[0] == 403
    # an over-long path skips the regex redirect (served by the origin instead)
    assert req(port, "rx.test", "/r/" + "1" * 2100 + "/2z")[0] == 200


# ----------------------------------------------------------------- origin guard (nftables)

OG_USER = "pcdn-ogtest"


def _og_ready():
    if os.geteuid() != 0 or shutil.which("nft") is None:
        return "needs root and nft"
    if subprocess.run(["nft", "list", "table", "inet", agent.ORIGIN_GUARD_TABLE], capture_output=True).returncode == 0:
        return "an origin guard is already installed on this host"
    try:
        pwd.getpwnam(OG_USER)
    except KeyError:
        if shutil.which("useradd") is None or subprocess.run(
                ["useradd", "-r", "-M", "-s", "/usr/sbin/nologin", OG_USER], capture_output=True).returncode != 0:
            return "cannot create a test user"
    probe = subprocess.run(["nft", "-c", "-f", "-"], input="table inet pcdn_og_probe {\n chain o {\n"
                           "  type filter hook output priority filter; policy accept;\n  meta skuid 1 accept\n }\n}\n",
                           capture_output=True, text=True)
    return None if probe.returncode == 0 else "nft cannot load an output skuid rule here"


@pytest.fixture(scope="module")
def og():
    why = _og_ready()
    if why:
        pytest.skip(why)
    pw = pwd.getpwnam(OG_USER)
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="pcdn-og-", dir="/tmp"))
    os.chmod(tmp, 0o755)
    ok_origin = Origin("127.0.0.3")        # "public" test origin: allow-listed (ORIGIN_PRIVATE_ALLOW)
    secret = Origin("127.0.0.1")           # a local service no customer may reach
    dns = StubDNS({"ok.origin.test": "127.0.0.3", "internal.origin.test": "127.0.0.1",
                   "meta.origin.test": "169.254.169.254"})
    cfg = base_cfg(tmp, NGINX_USER=OG_USER, ORIGIN_PRIVATE_ALLOW="127.0.0.3/32",
                   RESOLVER=f"127.0.0.1:{dns.port}", ORIGIN_GUARD="yes",
                   ORIGIN_GUARD_FILE=str(tmp / "origin-guard.nft"))
    conf = nginx_conf(tmp, cfg)
    conf.write_text(conf.read_text().replace("user root;", f"user {OG_USER};"))
    for d in ("cache", "client_body", "proxy", "fastcgi", "uwsgi", "scgi"):
        (tmp / d).mkdir(exist_ok=True)
        os.chown(tmp / d, pw.pw_uid, pw.pw_gid)
    rz = int(cfg["RESIZE_PORT"])
    sites = [
        site(301, "ok.test", {"address": "ok.origin.test", "port": ok_origin.port},
             image={"enabled": True, "quality": 80, "max_width": 150}),
        site(302, "evil.test", {"address": "internal.origin.test", "port": secret.port}),
        site(303, "rz.test", {"address": "internal.origin.test", "port": rz}),
        site(304, "meta.test", {"address": "meta.origin.test", "port": 80}),
        site(305, "lit.test", {"address": "127.0.0.1", "port": secret.port}),          # render time: skipped
        site(306, "num.test", {"address": "2130706433", "port": secret.port}),         # = 127.0.0.1
    ]
    guard = agent.render_origin_guard(cfg, uid=pw.pw_uid)
    pathlib.Path(cfg["ORIGIN_GUARD_FILE"]).write_text(guard)
    p = subprocess.run(["nft", "-f", cfg["ORIGIN_GUARD_FILE"]], capture_output=True, text=True)
    assert p.returncode == 0, p.stderr
    try:
        start(cfg, conf)
        err = agent.apply_config({"sites": sites}, cfg)
        assert err is None, err
        port = int(cfg["HTTP_PORT"])
        assert wait_for(lambda: req(port, "ok.test", "/x")[0] == 200), (tmp / "error.log").read_text()[-2000:]
        yield {"port": port, "cfg": cfg, "secret": secret, "ok": ok_origin, "tmp": tmp, "conf": conf}
    finally:
        subprocess.run(["nft", "delete", "table", "inet", agent.ORIGIN_GUARD_TABLE], capture_output=True)
        subprocess.run(["nginx", "-s", "stop", "-c", str(conf)], capture_output=True)
        for x in (ok_origin, secret, dns):
            x.stop()
        shutil.rmtree(tmp, ignore_errors=True)


def test_guard_allows_public_origin_and_internal_resizer_hop(og):
    status, body, _, _ = req(og["port"], "ok.test", "/hello")
    assert status == 200 and body == b"origin /hello"
    # image resize: site location -> loopback resizer (proxy_bind 127.0.0.2) -> origin by host name
    status, body, hdrs, _ = req(og["port"], "ok.test", "/pic.png?width=100")
    assert status == 200 and hdrs.get("content-type") == "image/png", (status, body[:100])
    assert png_size(body) == (100, 50)


def test_guard_blocks_origins_resolving_to_internal_addresses(og):
    before = og["secret"].hits
    for host in ("evil.test", "rz.test", "meta.test"):
        status, _, _, took = req(og["port"], host, "/steal")
        assert status == 502 and took < 3, (host, status, took)       # rejected at once, not a timeout
    assert og["secret"].hits == before
    # IP literals (also numeric forms) never even reach the config
    conf = "\n".join(p.read_text() for p in (pathlib.Path(og["cfg"]["NGINX_DIR"]) / "sites").glob("*.conf"))
    assert "server_name lit.test;" not in conf and "server_name num.test;" not in conf
    assert req(og["port"], "lit.test", "/")[0] == 421 and req(og["port"], "num.test", "/")[0] == 421
    # the guard counted the rejections
    out = subprocess.run(["nft", "list", "table", "inet", agent.ORIGIN_GUARD_TABLE], capture_output=True,
                         text=True).stdout
    hits = [int(x) for x in re.findall(r"counter packets (\d+) bytes \d+ reject", out)]
    assert sum(hits) >= 3, out


def test_guard_leaves_other_users_alone(og):
    # root (the agent, apt, the controller connection) still reaches the local service and the DNS stub
    with socket.create_connection(("127.0.0.1", og["secret"].port), timeout=3):
        pass
    status, _, _, _ = req(og["secret"].port, "x", "/direct")
    assert status == 200


def test_guard_is_what_blocks(og):
    """Control: without the table the same origin is reached (so the 502s above come from the guard)."""
    subprocess.run(["nft", "delete", "table", "inet", agent.ORIGIN_GUARD_TABLE], check=True)
    before = og["secret"].hits
    assert req(og["port"], "evil.test", "/steal")[0] == 200
    assert og["secret"].hits == before + 1
