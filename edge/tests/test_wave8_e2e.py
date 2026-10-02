"""Wave 8 end-to-end tests with real nginx (SPEC §16.4 L4 proxy, §16.5 video, §16.6 images v2).

One nginx instance runs the agent's rendered tree plus the stream module and the main-context
`include NGINX_DIR/l4/*.conf` that install.sh adds; the image transformer (`pcdn-agent imaged`) runs
in-process; a python origin serves HLS manifests / segments, a large mp4 with Range support and
JPEG images, and TCP / UDP echo servers stand behind the L4 apps.
"""

import io
import os
import pathlib
import shutil
import socket
import socketserver
import subprocess
import threading
import time
import http.server

import pytest

from conftest import modules_available, MODULES_DIR, nginx_conf, TEST_ORIGIN_ALLOW
from test_perf_e2e import Node, agent, free_port, wait_for

pytestmark = pytest.mark.skipif(
    shutil.which("nginx") is None or not modules_available()
    or not os.path.exists(os.path.join(MODULES_DIR, "ngx_stream_module.so")),
    reason="nginx with njs/geoip2/image_filter/brotli + stream modules not installed")

try:
    from PIL import Image
except ImportError:  # pragma: no cover
    Image = None

HERE = pathlib.Path(__file__).resolve().parent
SECRET = "5e" * 32
IMG_SECRET = "imgsec_" + "cd" * 24
MP4 = bytes((i * 7 + i // 251) % 256 for i in range(3 * 1024 * 1024 + 12345))


def jpeg(size=(400, 200)) -> bytes:
    im = Image.new("RGB", size, (20, 120, 200))
    for x in range(size[0] - 80, size[0]):
        for y in range(0, size[1], 3):
            im.putpixel((x, y), ((x * 13) % 255, (y * 29) % 255, 90))
    buf = io.BytesIO()
    im.save(buf, "JPEG", quality=90)
    return buf.getvalue()


class Origin:
    """/v/index.m3u8 (no-cache), /v/seg_NNNN.ts, /v/big.mp4 (single Range), /img/*.jpg."""

    def __init__(self):
        self.hits, self.ranges = {}, []
        o = self
        self.jpg = jpeg() if Image else b""

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
                n = o.hits[path] = o.hits.get(path, 0) + 1
                if path.endswith(".m3u8"):
                    return self._send(200, f"#EXTM3U\n#v{n}\nseg_0001.ts\n".encode(), "application/vnd.apple.mpegurl",
                                      [("Cache-Control", "no-cache"), ("Access-Control-Allow-Origin", "https://x")])
                if path.endswith(".ts"):
                    return self._send(200, path.encode() * 100, "video/mp2t")
                if path.endswith(".mp4"):
                    rng = self.headers.get("Range")
                    o.ranges.append(rng)
                    if rng and rng.startswith("bytes="):
                        a, _, b = rng[6:].partition("-")
                        a, b = int(a), min(int(b) if b else len(MP4) - 1, len(MP4) - 1)
                        return self._send(206, MP4[a:b + 1], "video/mp4",
                                          [("Content-Range", f"bytes {a}-{b}/{len(MP4)}")])
                    return self._send(200, MP4, "video/mp4")
                if path.endswith(".jpg"):
                    return self._send(200, o.jpg, "image/jpeg")
                return self._send(404, b"nope", "text/plain")

            do_HEAD = do_GET

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.server.daemon_threads = True
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def stop(self):
        self.server.shutdown()
        self.server.server_close()


class TcpEcho(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self):
        class H(socketserver.BaseRequestHandler):
            def handle(self):
                while True:
                    data = self.request.recv(65536)
                    if not data:
                        return
                    self.request.sendall(b"echo:" + data)
        super().__init__(("127.0.0.1", 0), H)
        self.port = self.server_address[1]
        threading.Thread(target=self.serve_forever, daemon=True).start()


class UdpEcho(socketserver.ThreadingUDPServer):
    daemon_threads = True

    def __init__(self):
        class H(socketserver.BaseRequestHandler):
            def handle(self):
                data, sock = self.request
                sock.sendto(b"udp:" + data, self.client_address)
        super().__init__(("127.0.0.1", 0), H)
        self.port = self.server_address[1]
        threading.Thread(target=self.serve_forever, daemon=True).start()


def site(sid, host, origin_port, **sections):
    s = {"id": sid, "domain": host, "status": "active", "secret": SECRET, "ssl": None, "rate_limit_rps": 0,
         "blocked_ips": [], "hosts": [{"name": host, "origin": {"address": "127.0.0.1", "port": origin_port}}],
         "cache": {"enabled": True, "level": "standard", "edge_ttl": 3600, "browser_ttl": 0, "ignore_query": False,
                   "bypass_cookies": [], "always_online": True}}
    s.update(sections)
    return s


def l4_entry(sid, domain, app, proto, port, oport, **kw):
    return dict({"site": domain, "site_id": sid, "app_id": app, "hostname": f"l4-{app}.{domain}", "protocol": proto,
                 "port": port, "origin": {"address": "127.0.0.1", "port": oport}, "proxy_protocol": "off",
                 "ip_allow": [], "idle_timeout": 30}, **kw)


def l4_ports(cfg, names):
    """Distinct ports inside L4_PORT_RANGE (render_l4 skips an app outside it), free for TCP and UDP
    on all addresses (nginx binds *:port) and not one of the node's own ports. A plain free_port()
    comes from the kernel's ephemeral range (here up to 65535), which may lie above the L4 range."""
    import random
    lo, hi = agent.l4_port_range(cfg)
    own = {int(cfg[k]) for k in ("HTTP_PORT", "HTTPS_PORT", "RESIZE_PORT", "IMAGE_PORT") if cfg.get(k)}
    rnd, out = random.Random(), {}
    for name in names:
        for _ in range(1000):
            p = rnd.randint(lo, hi)
            if p in own or p in out.values():
                continue
            try:
                for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
                    with socket.socket(socket.AF_INET, kind) as s:
                        s.bind(("0.0.0.0", p))
            except OSError:
                continue
            out[name] = p
            break
        else:
            raise RuntimeError("no free port in L4_PORT_RANGE")
    return out


@pytest.fixture(scope="module")
def env(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("w8")
    origin, tcp, udp = Origin(), TcpEcho(), UdpEcho()
    op = origin.port
    cfg = dict(agent.DEFAULTS, ORIGIN_PRIVATE_ALLOW=TEST_ORIGIN_ALLOW)
    cfg.update({
        "NGINX_DIR": str(tmp / "pcdn"), "CACHE_DIR": str(tmp / "cache"), "STATE_FILE": str(tmp / "state.json"),
        "ACCESS_LOG": str(tmp / "access.log"), "L4_ACCESS_LOG": str(tmp / "l4.log"), "FN_USAGE_LOG": str(tmp / "fn-usage.log"),
        "PAGES_DIR": str(HERE.parent / "pages"), "NJS_FILE": str(HERE.parent / "njs/pcdn.js"),
        "BASE_TEMPLATE": str(HERE.parent / "nginx/pcdn-base.conf"), "GEOIP_DB": str(tmp / "none.mmdb"),
        "RESOLVER": "127.0.0.1", "NGINX_USER": "root", "LISTEN_IPV6": "no", "HTTP_PORT": str(free_port()),
        "HTTPS_PORT": str(free_port()), "RESIZE_PORT": str(free_port()), "IMAGE_PORT": str(free_port()),
        "DICT_SIZE": "4m", "L4_PORT_RANGE": "20000-60999",
    })
    conf = nginx_conf(tmp, cfg)
    text = conf.read_text()
    conf.write_text(f"load_module {MODULES_DIR}/ngx_stream_module.so;\n" + text
                    + f"include {cfg['NGINX_DIR']}/l4/*.conf;\n")          # what install.sh adds
    cfg.update(NGINX_CONF=str(conf), NGINX_TEST_CMD=f"nginx -t -q -c {conf}", NGINX_RELOAD_CMD=f"nginx -s reload -c {conf}")
    assert agent.l4_ready(cfg)
    ports = l4_ports(cfg, ("tcp", "deny", "pp", "udp"))
    node = Node(cfg, conf, tmp)
    node.ports, node.origin, node.tcp, node.udp = ports, origin, tcp, udp
    node.config = {"sites": [
        site(401, "vid.test", op, video={"enabled": True, "segment_ttl": 3600, "manifest_ttl": 1, "prefetch_next": True},
             ratelimit={"rules": [{"id": "rl", "path": "/v/rl/*", "requests": 3, "period": 60, "action": "block",
                                   "block_seconds": 60}]}),
        site(402, "img2.test", op, image={"enabled": True, "quality": 80, "max_width": 2000}),
        site(403, "avif.test", op, image={"enabled": True, "quality": 60, "max_width": 2000, "avif": True,
                                          "smart_crop": True}),
        site(404, "signed.test", op, image={"enabled": True, "quality": 80, "max_width": 2000,
                                            "transform_secret": IMG_SECRET}),
    ], "l4": [
        l4_entry(401, "vid.test", "echo", "tcp", ports["tcp"], tcp.port),
        l4_entry(401, "vid.test", "deny", "tcp", ports["deny"], tcp.port, ip_allow=["10.0.0.0/8"]),
        l4_entry(402, "img2.test", "pp", "tcp", ports["pp"], tcp.port, proxy_protocol="v1"),
        l4_entry(402, "img2.test", "dns", "udp", ports["udp"], udp.port),
    ]}
    imaged = agent.imaged_server(cfg) if agent.image_capabilities(cfg)["transform"] else None
    if imaged:
        threading.Thread(target=imaged.serve_forever, daemon=True).start()
    node.imaged = imaged
    try:
        agent.bootstrap(cfg)
        p = subprocess.run(["nginx", "-c", str(conf)], capture_output=True, text=True)
        assert p.returncode == 0, p.stderr
        assert wait_for(lambda: node.req("unknown.test", "/__pcdn/health").status == 200)
        err = agent.apply_config(node.config, cfg)
        assert err is None, err
        assert wait_for(lambda: node.req("vid.test", "/v/ready.ts").status == 200)
        yield node
    finally:
        subprocess.run(["nginx", "-s", "stop", "-c", str(conf)], capture_output=True)
        if imaged:
            imaged.shutdown()
            imaged.server_close()
        for s in (origin,):
            s.stop()
        for s in (tcp, udp):
            s.shutdown()
            s.server_close()


# ----------------------------------------------------------------- L4 (SPEC §16.4)

def test_l4_tcp_proxy_allow_list_and_usage(env):
    with socket.create_connection(("127.0.0.1", env.ports["tcp"]), timeout=5) as s:
        s.sendall(b"hello")
        assert s.recv(100) == b"echo:hello"
        s.sendall(b"x" * 1000)
        got = b""
        while len(got) < 1005:
            got += s.recv(4096)
    # ip_allow 10.0.0.0/8 only: nginx closes the connection without proxying
    with socket.create_connection(("127.0.0.1", env.ports["deny"]), timeout=5) as s:
        s.sendall(b"hello")
        try:
            assert s.recv(100) == b""
        except ConnectionResetError:
            pass
    # usage from the JSON stream log (buffered: flush=5s)
    st = {}

    def counted():
        agent.read_l4_usage(st, env.cfg["L4_ACCESS_LOG"])
        apps = {k: v for item in st.get("pending", {}).values() for k, v in (item.get("l4") or {}).items()}
        return apps.get("echo", {}).get("sessions", 0) >= 1 and "deny" in apps
    assert wait_for(counted, timeout=15, interval=0.5)
    key = [k for k in st["pending"] if k.startswith("vid.test|")][0]
    item = agent.usage_item(key, st["pending"][key])
    assert item["l4"]["echo"]["bytes_in"] >= 1005 and item["l4"]["echo"]["bytes_out"] >= 1015
    assert item["l4"]["deny"]["bytes_out"] == 0 and item["bytes"] == 0


def test_l4_proxy_protocol_v1(env):
    with socket.create_connection(("127.0.0.1", env.ports["pp"]), timeout=5) as s:
        s.sendall(b"data")
        got = b""
        while b"data" not in got:
            chunk = s.recv(4096)
            if not chunk:
                break
            got += chunk
    assert got.startswith(b"echo:PROXY TCP4 127.0.0.1 127.0.0.1 "), got


def test_l4_udp_proxy(env):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(5)
        s.sendto(b"ping", ("127.0.0.1", env.ports["udp"]))
        data, _ = s.recvfrom(100)
    assert data == b"udp:ping"


# ----------------------------------------------------------------- video (SPEC §16.5)

def test_video_manifest_short_ttl_and_cors(env):
    r1 = env.req("vid.test", "/v/index.m3u8")
    assert r1.status == 200 and r1.headers["x-cache"] == "MISS"
    assert r1.all("access-control-allow-origin") == ["*"]               # origin's own value replaced
    r2 = env.req("vid.test", "/v/index.m3u8")
    assert r2.headers["x-cache"] == "HIT" and r2.body == r1.body          # cached despite no-cache
    # manifest_ttl 1 s (nginx validity has 1 s resolution: expired within ~2 s), then served stale
    # while revalidating in the background
    assert wait_for(lambda: env.req("vid.test", "/v/index.m3u8").headers["x-cache"] in ("STALE", "UPDATING", "EXPIRED"),
                    timeout=5, interval=0.25)
    assert wait_for(lambda: env.origin.hits.get("/v/index.m3u8", 0) >= 2)


def test_video_segment_prefetch_next(env):
    r = env.req("vid.test", "/v/seg_0041.ts")
    assert r.status == 200 and r.headers["x-cache"] == "MISS" and r.headers["access-control-allow-origin"] == "*"
    # the mirror subrequest fetched seg_0042.ts into the cache before anybody asked for it
    assert wait_for(lambda: env.origin.hits.get("/v/seg_0042.ts", 0) == 1)
    r2 = env.req("vid.test", "/v/seg_0042.ts")
    assert r2.status == 200 and r2.headers["x-cache"] == "HIT" and r2.body == b"/v/seg_0042.ts" * 100
    # bounded / once: seg_0042's own request prefetched seg_0043 (once); repeats never fetch again
    assert wait_for(lambda: env.origin.hits.get("/v/seg_0043.ts", 0) == 1)
    for _ in range(3):
        env.req("vid.test", "/v/seg_0041.ts")
    time.sleep(0.5)
    assert env.origin.hits["/v/seg_0042.ts"] == 1 and env.origin.hits["/v/seg_0043.ts"] == 1
    # the prefetch is never logged / billed as a visitor request
    assert not any(e.get("u") == "/v/seg_0043.ts" for e in env.log())


def test_video_prefetch_subrequest_is_not_rate_limited_twice(env):
    """The mirror subrequest reuses the visitor request's verdict: a rate-limit rule counts the
    segment request once (3 allowed, the 4th refused), never the prefetch too."""
    codes = [env.req("vid.test", f"/v/rl/s_{i}.ts").status for i in (1, 3, 5, 7)]
    assert codes == [200, 200, 200, 429] or codes[:3] == [200, 200, 200] and codes[3] in (403, 429), codes


def test_video_mp4_byte_ranges_are_sliced_and_purged(env):
    r = env.req("vid.test", "/v/big.mp4", headers={"Range": "bytes=100-199"})
    assert r.status == 206 and r.body == MP4[100:200] and r.headers["access-control-allow-origin"] == "*"
    r = env.req("vid.test", "/v/big.mp4", headers={"Range": "bytes=2097100-2097299"})  # crosses a slice
    assert r.status == 206 and r.body == MP4[2097100:2097300]
    assert all(x and x.startswith("bytes=") for x in env.origin.ranges)  # the origin only sees 1 MB slices
    n = len(env.origin.ranges)
    full = env.req("vid.test", "/v/big.mp4")
    assert full.status == 200 and full.body == MP4
    keys = []
    for root, _, files in os.walk(os.path.join(env.cfg["CACHE_DIR"], "401")):
        keys += [agent._read_cache_key(os.path.join(root, f)) for f in files]
    sliced = [k for k in keys if k and "/v/big.mp4;r=bytes=" in k]
    assert len(sliced) == 4                                               # 3 MB + a bit = 4 slices
    assert n == 3 and len(env.origin.ranges) == n + 1                     # only the missing last slice
    kinfo = agent.key_infos(env.config)["401"]
    removed = agent.do_purge({"site_id": 401, "urls": ["http://vid.test/v/big.mp4"]}, env.cfg, kinfo)
    assert removed == 4


def test_video_usage_breakdown(env):
    env.req("vid.test", "/v/seg_0091.ts")
    st = {"video_hosts": agent.video_hosts(env.config)}
    assert wait_for(lambda: any(e.get("u") == "/v/seg_0091.ts" for e in env.log()))
    time.sleep(1.2)   # access_log flush=1s
    agent.read_usage(st, env.cfg["ACCESS_LOG"])
    v = [a["video"] for k, a in st["pending"].items() if k.startswith("vid.test|") and a.get("video")]
    assert v and sum(x["requests"] for x in v) >= 3 and sum(x["bytes"] for x in v) > 0


# ----------------------------------------------------------------- images v2 (SPEC §16.6)

def size_of(body):
    return Image.open(io.BytesIO(body)).size


needs_imaged = pytest.mark.skipif(Image is None, reason="python3-pil not installed")


@needs_imaged
def test_image_v2_transform_and_cache(env):
    r = env.req("img2.test", "/img/a.jpg?w=100&fmt=webp")
    assert r.status == 200 and r.headers["content-type"] == "image/webp", (r.status, r.body[:200])
    assert size_of(r.body) == (100, 50) and r.headers["x-cache"] == "MISS"
    assert env.req("img2.test", "/img/a.jpg?w=100&fmt=webp").headers["x-cache"] == "HIT"
    r = env.req("img2.test", "/img/a.jpg?w=80&h=80&fit=cover&q=40")
    assert r.headers["content-type"] == "image/jpeg" and size_of(r.body) == (80, 80)
    r = env.req("img2.test", "/img/a.jpg?width=100")                      # legacy: nginx image_filter
    assert r.headers["content-type"] == "image/jpeg" and size_of(r.body) == (100, 50)
    r = env.req("img2.test", "/img/a.jpg?w=99999")                        # bounded, never enlarged
    assert size_of(r.body) == (400, 200)


@needs_imaged
def test_image_v2_avif_negotiation(env):
    if not agent.image_capabilities(env.cfg)["avif"]:
        pytest.skip("no AVIF encoder (Pillow AVIF plugin / avifenc) on this machine")
    r = env.req("avif.test", "/img/b.jpg", headers={"Accept": "image/avif,image/webp,*/*"})
    assert r.status == 200 and r.headers["content-type"] == "image/avif" and "Accept" in r.headers.get("vary", "")
    plain = env.req("avif.test", "/img/b.jpg", headers={"Accept": "image/webp,*/*"})
    assert plain.headers["content-type"] == "image/jpeg" and plain.body == env.origin.jpg
    r = env.req("avif.test", "/img/b.jpg?w=60&h=60&fit=cover", headers={"Accept": "image/avif"})
    assert r.headers["content-type"] == "image/avif"


@needs_imaged
def test_image_v2_signed_urls(env):
    assert env.req("signed.test", "/img/c.jpg?w=100").status == 403
    sig = agent.image_signature(IMG_SECRET, "/img/c.jpg", {"w": "100"})
    r = env.req("signed.test", f"/img/c.jpg?w=100&sig={sig}")
    assert r.status == 200 and size_of(r.body) == (100, 50)
    assert env.req("signed.test", f"/img/c.jpg?w=101&sig={sig}").status == 403
    assert env.req("signed.test", "/img/c.jpg").status == 200              # no transform params: no signature


@needs_imaged
def test_image_v2_falls_back_when_the_transformer_is_down(env):
    if env.imaged is None:
        pytest.skip("no transformer")
    env.imaged.shutdown()
    env.imaged.server_close()
    env.imaged = None
    r = env.req("img2.test", "/img/d.jpg?w=100&fmt=webp")
    assert r.status == 200 and r.headers["content-type"] == "image/jpeg" and size_of(r.body) == (100, 50)
    r = env.req("img2.test", "/img/d.jpg?fmt=webp")                        # nothing to resize: the original
    assert r.status == 200 and r.body == env.origin.jpg
