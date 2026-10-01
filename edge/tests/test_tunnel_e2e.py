"""Tunnel mode (SPEC §7) end-to-end: real nginx + njs + the agent's rendered config.

Stand-ins for Xray/V2Ray inbounds live in tunnel_kit.py (stdlib only): a WebSocket /
HTTPUpgrade / XHTTP origin and an h2c echo server behind grpc_pass. Requests come from
127.0.0.1, which the generated GeoIP database maps to "CN".
"""

import json
import re
import shutil
import subprocess
import time

import pytest

from conftest import modules_available, nginx_conf
from test_nginx_e2e import SQLI, Edge, Origin, agent, free_port, make_mmdb, self_signed, site, wait_for
from tunnel_kit import (H2Client, H2Origin, TunnelOrigin, connect, read_until, upgrade_request, ws_frame,
                        ws_read)

pytestmark = pytest.mark.skipif(shutil.which("nginx") is None or not modules_available(),
                                reason="nginx with njs/geoip2/image_filter/brotli modules not installed")

ALL_GROUPS = ["sqli", "xss", "lfi", "rce", "php", "scanner", "protocol"]


def tpath(pid, path, protocol, origin=None, pool=None):
    return {"id": pid, "path": path, "protocol": protocol, "origin": origin, "pool": pool}


def tunnel(paths, **kw):
    t = {"enabled": True, "paths": paths, "idle_timeout": 90, "per_connection_mbps": 0, "max_connections_per_ip": 0,
         "allowed_countries": [], "fallback": "origin", "max_connections": 0}
    t.update(kw)
    return t


@pytest.fixture(scope="module")
def tn(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("tunnel")
    try:
        make_mmdb(tmp / "country.mmdb")
    except ImportError:
        pytest.skip("mmdb_writer/netaddr not installed")
    web, to, h2o = Origin("WEB"), TunnelOrigin(gap=0.4, chunks=4), H2Origin()
    # a real h2c server (nginx, prior knowledge) to check what an HTTP/2 origin receives through grpc_pass
    h2n_port = free_port()
    (tmp / "h2origin").mkdir()
    (tmp / "h2origin.conf").write_text(
        f"pid {tmp}/h2origin/nginx.pid;\nerror_log {tmp}/h2origin/error.log;\nevents {{}}\nhttp {{\n access_log off;\n"
        + "".join(f" {d}_temp_path {tmp}/h2origin/{d};\n" for d in ("client_body", "proxy", "fastcgi", "uwsgi", "scgi"))
        + f" server {{\n  listen 127.0.0.1:{h2n_port} http2;\n"
        + '  location / { return 200 "host=$host proto=$server_protocol xri=$http_x_real_ip ct=$http_content_type"; }\n'
        + " }\n}\n")
    p = subprocess.run(["nginx", "-c", str(tmp / "h2origin.conf")], capture_output=True, text=True)
    assert p.returncode == 0, p.stderr
    cfg = dict(agent.DEFAULTS)
    cfg.update({
        "NGINX_DIR": str(tmp / "pcdn"), "CACHE_DIR": str(tmp / "cache"), "STATE_FILE": str(tmp / "state.json"),
        "ACCESS_LOG": str(tmp / "access.log"), "PAGES_DIR": str(agent.HERE) + "/pages",
        "NJS_FILE": str(agent.HERE) + "/njs/pcdn.js", "BASE_TEMPLATE": str(agent.HERE) + "/nginx/pcdn-base.conf",
        "GEOIP_DB": str(tmp / "country.mmdb"), "RESOLVER": "127.0.0.1", "NGINX_USER": "root", "LISTEN_IPV6": "no",
        "HTTP_PORT": str(free_port()), "HTTPS_PORT": str(free_port()), "RESIZE_PORT": str(free_port()),
        "DICT_SIZE": "4m",
    })
    conf = nginx_conf(tmp, cfg)
    cfg["NGINX_TEST_CMD"] = f"nginx -t -q -c {conf}"
    cfg["NGINX_RELOAD_CMD"] = f"nginx -s reload -c {conf}"
    cert, key = self_signed(tmp, "tn.test")
    WEB = {"address": "127.0.0.1", "port": web.port}
    TO = {"address": "127.0.0.1", "port": to.port, "tls": False, "sni": None, "verify": False}
    TO_NAME = dict(TO, address="localhost")  # hostname origin: resolved at request time, no keepalive upstream
    H2 = {"address": "127.0.0.1", "port": h2o.port, "tls": False, "sni": None, "verify": False}
    H2N = {"address": "127.0.0.1", "port": h2n_port, "tls": False, "sni": None, "verify": False}
    main_paths = [tpath("h2n", "/h2n", "h2", H2N), tpath("ws", "/ws", "ws", TO), tpath("hu", "/hu", "httpupgrade", TO),
                  tpath("xh", "/xh", "xhttp", TO), tpath("gr", "/grpc.Svc", "grpc", H2), tpath("h2", "/h2", "h2", H2),
                  tpath("wsp", "/wsp", "ws", pool="tp"), tpath("wsn", "/wsn", "ws", TO_NAME)]
    sites = [
        # every security feature is on: tunnel paths must pass, other paths get challenged
        site(201, "tn.test", WEB, ssl={"cert": cert, "key": key}, rate_limit_rps=1,
             waf={"mode": "block", "paranoia": 1, "groups": ALL_GROUPS, "exclusions": []},
             ddos={"mode": "js", "threshold_rps": 200, "clearance_ttl": 600},
             hotlink={"enabled": True, "extensions": ["png"], "allowed_referers": [], "allow_empty": False},
             ratelimit={"rules": [{"id": "all", "enabled": True, "path": "/*", "methods": [], "requests": 1,
                                   "period": 60, "action": "block", "block_seconds": 60}]},
             firewall={"default_action": "allow", "rules": [
                 {"id": "chal", "enabled": True, "action": "challenge",
                  "conditions": [{"field": "path", "op": "starts_with", "value": "/"}]},
                 {"id": "evil", "enabled": True, "action": "block",
                  "conditions": [{"field": "header", "name": "X-Evil", "op": "eq", "value": "yes"}]}]},
             headers={"request": [{"name": "X-From-CDN", "value": "pcdn"}],
                      "response": [{"name": "X-Frame-Options", "value": "DENY"}]},
             pools={"pools": [{"name": "tp", "method": "weighted", "protocol": "http",
                               "origins": [{"address": "127.0.0.1", "port": to.port, "weight": 1, "backup": False}],
                               "health": {"enabled": False}}]},
             tunnel=tunnel(main_paths, allowed_countries=["CN", "IR"], max_connections=100,
                           max_connections_per_ip=50)),
        site(202, "decoy.test", WEB, tunnel=tunnel([tpath("t", "/t", "ws", TO)], fallback="decoy")),
        site(203, "nf.test", WEB, tunnel=tunnel([tpath("t", "/t", "ws", TO)], fallback="404", max_connections=1)),
        site(204, "cc.test", WEB, tunnel=tunnel([tpath("t", "/t", "ws", TO)], allowed_countries=["IR"])),
        site(205, "lim.test", WEB, tunnel=tunnel([tpath("t", "/t", "ws", TO), tpath("x", "/x", "xhttp", TO),
                                                  tpath("g", "/g", "grpc", H2)],
                                                 max_connections_per_ip=2, per_connection_mbps=1)),
        site(206, "blk.test", WEB, blocked_ips=["127.0.0.0/8"], tunnel=tunnel([tpath("t", "/t", "ws", TO)])),
        site(207, "host.test", {"address": "127.0.0.1", "port": to.port},
             tunnel=tunnel([tpath("t", "/t", "ws"), tpath("x", "/x", "xhttp")])),
        site(208, "off.test", WEB, tunnel=dict(tunnel([tpath("t", "/t", "ws", TO)], fallback="404"), enabled=False)),
    ]
    agent.bootstrap(cfg)
    p = subprocess.run(["nginx", "-c", str(conf)], capture_output=True, text=True)
    assert p.returncode == 0, p.stderr
    edge = Edge(cfg, conf)
    try:
        assert wait_for(lambda: edge.req("unknown.test", "/__pcdn/health").status == 200)
        err = agent.apply_config({"sites": sites}, cfg)
        assert err is None, err
        assert wait_for(lambda: edge.req("decoy.test", "/").status == 200), (tmp / "error.log").read_text()[-3000:]
        edge.tmp, edge.to, edge.h2o, edge.web = tmp, to, h2o, web
        yield edge
    finally:
        subprocess.run(["nginx", "-s", "stop", "-c", str(conf)], capture_output=True)
        subprocess.run(["nginx", "-s", "stop", "-c", str(tmp / "h2origin.conf")], capture_output=True)
        for x in (web, to, h2o):
            x.stop()


def log_lines(env, host, tn=None):
    # nginx writes the line when the request/session ends, and the log is buffered (F23), so poll
    for _ in range(40):
        lines = [e for e in env.log() if e["h"] == host and (tn is None or e.get("tn") == tn)]
        if lines:
            return lines
        time.sleep(0.1)
    return []


def ws_open(env, host, path, tls=True, extra=None):
    sock = connect(env.sport if tls else env.port, host, tls, alpn=["http/1.1"] if tls else None)
    sock.sendall(upgrade_request(host, path, True, extra))
    head, rest = read_until(sock, b"\r\n\r\n")
    return sock, head.decode("latin-1"), rest


def status_of(head: str) -> int:
    return int(head.split(" ", 2)[1])


def log_wait(env, host, marker, timeout=5.0):
    """Wait for a specific buffered access-log line (F23: buffer=64k flush=1s) to reach the file."""
    for _ in range(int(timeout / 0.1)):
        hit = [e for e in env.log() if e["h"] == host and marker in e["u"]]
        if hit:
            return hit
        time.sleep(0.1)
    return []


# ----------------------------------------------------------------- rendering

def test_rendered_config(tn):
    conf = (tn.tmp / "pcdn/sites/201.conf").read_text()
    assert 'location ^~ "/ws" {' in conf and 'location ^~ "/grpc.Svc" {' in conf
    # tunnel locations come before the page rule / static regex locations
    assert conf.index('location ^~ "/wsn"') < conf.index("location / {")
    assert "proxy_read_timeout 90s;" in conf and "grpc_read_timeout 90s;" in conf and "grpc_send_timeout 90s;" in conf
    assert "client_max_body_size 0;" in conf and "tcp_nodelay on;" in conf
    assert "limit_req_dry_run" not in conf                                    # F40: skipped via empty key
    assert "grpc_pass grpc://pcdn_tn_201_" in conf  # IP-literal origin -> keepalive upstream
    assert "keepalive 64;" in conf and "keepalive_requests 1000000;" in conf
    assert "proxy_pass http://$pcdn_tn_target;" in conf  # hostname / pool origin -> resolved per request
    assert "limit_conn pcdn_tn_site2 100;" in conf and "limit_conn pcdn_tn_ip2 50;" in conf  # F13
    # F3/F14: HTTP/2 body buffer + relay buffers on the tunnel data path
    assert "client_body_buffer_size 256k;" in conf and "http2_chunk_size 16k;" in conf
    assert "proxy_buffer_size 16k;" in conf and "grpc_buffer_size 16k;" in conf
    assert "grpc_next_upstream error timeout;" in conf                        # F28
    # F27/N2: raised client-facing HTTP/2 connection timers + stream cap on the tunnel host
    assert "keepalive_timeout 600s;" in conf and "keepalive_time 6h;" in conf
    assert "keepalive_requests 10000000;" in conf and "send_timeout 90s;" in conf
    # F13: xhttp counts only the downlink GET
    xh = conf.split('location ^~ "/xh" {', 1)[1].split("\n    }", 1)[0]
    assert "set $pcdn_tn_ckey $pcdn_tn_isget;" in xh
    # F1: a pool tunnel path carries the session-affinity prefix, set before $pcdn_tn_target
    wsp = conf.split('location ^~ "/wsp" {', 1)[1].split("\n    }", 1)[0]
    assert 'set $pcdn_tn_prefix "/wsp";' in wsp and 'set $pcdn_tn_pool "tp";' in wsp
    assert wsp.index('set $pcdn_tn_prefix "/wsp";') < wsp.index("set $pcdn_tn_target $pcdn_tn_upstream;")
    lim = (tn.tmp / "pcdn/sites/205.conf").read_text()
    assert "limit_conn pcdn_tn_ip2 2;" in lim and "limit_conn pcdn_tn_site2" not in lim
    assert "location ^~ \"/t\"" not in (tn.tmp / "pcdn/sites/208.conf").read_text()  # tunnel.enabled = false
    http = (tn.tmp / "pcdn/http.conf").read_text()
    assert "http2_max_concurrent_streams" in http and '"tn":"$pcdn_tn"' in http
    assert "grpc_connect_timeout 10s;" in http and "resolver_timeout 11s;" in http  # F12 / F15
    assert "reuseport backlog=65535 so_keepalive=120s:30s:4;" in http           # F4/F16/F17
    assert "location = /__pcdn/confver {" in http                               # F29


# ----------------------------------------------------------------- WebSocket / HTTPUpgrade

@pytest.mark.parametrize("tls", [True, False])
def test_websocket_echo(tn, tls):
    sock, head, buf = ws_open(tn, "tn.test", "/ws?ed=2048", tls=tls, extra={"User-Agent": "sqlmap/1.7"})
    try:
        assert status_of(head) == 101, head
        for i in range(5):
            msg = f"packet-{i}-".encode() * 50
            sock.sendall(ws_frame(msg))
            op, data, buf = ws_read(sock, buf)
            assert op == 2 and data == msg
        # messages keep flowing after a pause (nothing buffered, nothing timed out)
        time.sleep(1.2)
        sock.sendall(ws_frame(b"after-pause"))
        assert ws_read(sock, buf)[1] == b"after-pause"
        sock.sendall(ws_frame(b"", 8))
    finally:
        sock.close()
    line, hdrs = tn.to.requests[-1]
    assert line.startswith("GET /ws?ed=2048") and hdrs["x-real-ip"] == "127.0.0.1" and hdrs["x-from-cdn"] == "pcdn"
    assert hdrs["host"] == "tn.test" and hdrs["upgrade"] == "websocket"


def test_websocket_pool_origin(tn):
    # (hostname origins are resolved at request time; the test resolver has no DNS server, so /wsn is
    # only checked in test_rendered_config)
    for path in ("/wsp/x",):
        sock, head, buf = ws_open(tn, "tn.test", path)
        try:
            assert status_of(head) == 101, (path, head)
            sock.sendall(ws_frame(b"hi " + path.encode()))
            assert ws_read(sock, buf)[1] == b"hi " + path.encode()
        finally:
            sock.close()


def test_httpupgrade_raw_stream(tn):
    sock = connect(tn.sport, "tn.test", True, alpn=["http/1.1"])
    try:
        sock.sendall(upgrade_request("tn.test", "/hu", ws=False))
        head, buf = read_until(sock, b"\r\n\r\n")
        assert status_of(head.decode()) == 101
        for i in range(3):
            sock.sendall(b"raw-%d" % i)
            got = buf
            while len(got) < 5:
                got += sock.recv(100)
            buf = b""
            assert got == b"raw-%d" % i
    finally:
        sock.close()


def test_host_origin_tunnel(tn):
    sock, head, buf = ws_open(tn, "host.test", "/t", tls=False)
    try:
        assert status_of(head) == 101
        sock.sendall(ws_frame(b"own-origin"))
        assert ws_read(sock, buf)[1] == b"own-origin"
    finally:
        sock.close()
    r = tn.req("host.test", "/x/down")  # xhttp via the host origin's keepalive upstream
    assert r.status == 200 and r.text == "chunk-0|chunk-1|chunk-2|chunk-3|"


# ----------------------------------------------------------------- XHTTP

def test_xhttp_download_streams_unbuffered(tn):
    sock = connect(tn.sport, "tn.test", True, alpn=["http/1.1"])
    try:
        sock.sendall(b"GET /xh/down HTTP/1.1\r\nHost: tn.test\r\nUser-Agent: Go-http-client/1.1\r\n\r\n")
        head, buf = read_until(sock, b"\r\n\r\n")
        t0 = time.time()
        assert b" 200 " in head and b"chunked" in head.lower()
        stamps = []
        while b"chunk-3|" not in buf:
            if b"chunk-%d|" % len(stamps) in buf:
                stamps.append(time.time() - t0)
                continue
            buf += sock.recv(1024)
        stamps.append(time.time() - t0)
        # the origin sends one chunk every 0.4 s: they must arrive spread out, not in one burst
        assert stamps[0] < 0.3 and stamps[-1] > 0.9, stamps
    finally:
        sock.close()


def test_xhttp_large_download_integrity(tn):
    # F14: with the relay buffers raised (proxy_buffer_size / http2_chunk_size 16k) a large tunnel
    # download must still be byte-exact.
    n = 2_000_000
    r = tn.req("lim.test", f"/x/big?n={n}")
    assert r.status == 200 and len(r.body) == n and r.body == b"b" * n


def test_xhttp_chunked_upload_not_buffered(tn):
    sock = connect(tn.sport, "tn.test", True, alpn=["http/1.1"])
    try:
        sock.sendall(b"POST /xh/up?seq=0 HTTP/1.1\r\nHost: tn.test\r\nTransfer-Encoding: chunked\r\n"
                     b"Content-Type: application/octet-stream\r\n\r\n")
        for i in range(3):
            piece = (b"%d" % i) * 3000
            sock.sendall(b"%x\r\n%s\r\n" % (len(piece), piece))
            time.sleep(0.5)
        sock.sendall(b"0\r\n\r\n")
        head, buf = read_until(sock, b"\r\n\r\n")
        assert b" 200 " in head
        n = int(re.search(rb"content-length: (\d+)", head, re.I).group(1))
        while len(buf) < n:
            buf += sock.recv(4096)
        res = json.loads(buf[:n])
    finally:
        sock.close()
    assert res["bytes"] == 9000
    # the origin saw the pieces while the client was still sending (no request buffering)
    assert res["arrivals"][-1] - res["arrivals"][0] >= 0.8, res["arrivals"]
    assert res["headers"].get("transfer-encoding") == "chunked"


# ----------------------------------------------------------------- gRPC / raw HTTP/2

@pytest.mark.parametrize("path", ["/grpc.Svc/Tun", "/h2/stream"])
def test_grpc_and_h2_bidirectional_stream(tn, path):
    before = tn.h2o.streams
    c = H2Client(tn.sport, "tn.test", path + "?" + SQLI.split("?", 1)[1])
    try:
        for i in range(4):
            msg = b"\x00\x00\x00\x00\x08" + b"msg-%04d" % i
            c.send(msg)
            got = b""
            while len(got) < len(msg):
                got += c.recv_data()
            assert got == msg
            assert c.status == 200
            time.sleep(0.2)
        c.send(b"", end=True)
        while not c.closed:
            if c.recv_data() is None:
                break
        assert c.trailers  # grpc-status trailers made it through
    finally:
        c.close()
    assert tn.h2o.streams == before + 1


def test_h2_origin_sees_host_and_client_headers(tn):
    """Through grpc_pass a real HTTP/2 server gets the site's host name (grpc_set_header Host -> host header,
    which h2 servers such as Go's net/http and nginx use as the authority) and the edge headers."""
    c = H2Client(tn.sport, "tn.test", "/h2n/x", method="GET", ctype="application/grpc", end_stream=True)
    try:
        body = b""
        while True:
            d = c.recv_data()
            if d is None:
                break
            body += d
    finally:
        c.close()
    assert c.status == 200
    assert body.decode() == "host=tn.test proto=HTTP/2.0 xri=127.0.0.1 ct=application/grpc"


def test_normal_paths_still_work_over_http2(tn):
    if not shutil.which("curl"):
        pytest.skip("curl missing")
    out = subprocess.run(["curl", "-sk", "--http2", "--noproxy", "*", "-o", "/dev/null", "-w", "%{http_version} %{http_code}",
                          "--resolve", f"tn.test:{tn.sport}:127.0.0.1", f"https://tn.test:{tn.sport}/page"],
                         capture_output=True, text=True).stdout
    assert out in ("2 403", "2 429")  # normal path over HTTP/2: challenged (or the legacy 1 r/s limit)


# ----------------------------------------------------------------- security bypass / blocks

def test_security_bypassed_on_tunnel_paths_but_blocks_apply(tn):
    # a normal path of the same site: challenged (firewall challenge rule + DDoS js mode)
    r = tn.req("tn.test", "/normal?m=n1")
    assert r.status in (403, 429)  # 429: the site's legacy 1 r/s limit_req also applies to normal paths
    assert [e["v"] for e in log_wait(tn, "tn.test", "m=n1")] == ["challenge:firewall:chal"]
    # tunnel path: WAF signature, scanner UA, challenge rules, rate limits all bypassed
    for i in range(3):
        sock, head, _ = ws_open(tn, "tn.test", "/ws" + SQLI[1:] + f"&i={i}", extra={"User-Agent": "sqlmap/1.7"})
        sock.close()
        assert status_of(head) == 101, head
    r = tn.req("tn.test", "/xh/get" + SQLI[1:], https=True)
    assert r.status == 200 and "x-frame-options" not in r.headers  # no response header rewriting
    # firewall block rules still apply
    sock, head, _ = ws_open(tn, "tn.test", "/ws?m=evil", extra={"X-Evil": "yes"})
    sock.close()
    assert status_of(head) in (403, 429)  # the deny page itself is subject to the legacy limit_req (1 r/s)
    assert [e["v"] for e in log_wait(tn, "tn.test", "m=evil")] == ["block:firewall:evil"]
    # blocked_ips too
    sock, head, _ = ws_open(tn, "blk.test", "/t", tls=False)
    sock.close()
    assert status_of(head) == 403


def test_allowed_countries(tn):
    sock, head, _ = ws_open(tn, "cc.test", "/t", tls=False)  # 127.0.0.1 is "CN", only IR allowed
    sock.close()
    assert status_of(head) == 403
    assert tn.req("cc.test", "/").status == 200  # other paths are not restricted
    sock, head, _ = ws_open(tn, "tn.test", "/ws")  # CN is on the list of tn.test
    sock.close()
    assert status_of(head) == 101


def test_limit_conn_per_ip(tn):
    socks = []
    try:
        for _ in range(2):
            s, head, _ = ws_open(tn, "lim.test", "/t", tls=False)
            socks.append(s)
            assert status_of(head) == 101
        s, head, _ = ws_open(tn, "lim.test", "/t", tls=False)
        socks.append(s)
        assert status_of(head) == 429
    finally:
        for s in socks:
            s.close()
    # closing the streams frees the slots
    assert wait_for(lambda: tn.req("lim.test", "/x/down").status == 200, 5)


def test_limit_conn_per_site(tn):
    a, head, _ = ws_open(tn, "nf.test", "/t", tls=False)  # nf.test: max_connections = 1
    try:
        assert status_of(head) == 101
        b, head2, _ = ws_open(tn, "nf.test", "/t", tls=False)
        b.close()
        assert status_of(head2) == 429
    finally:
        a.close()

    def again():
        c, h, _ = ws_open(tn, "nf.test", "/t", tls=False)
        c.close()
        return status_of(h) == 101
    assert wait_for(again, 5)


def test_unbuffered_proxying_ignores_limit_rate_on_nginx_124(tn, tmp_path):
    """Why tunnel.per_connection_mbps is not rendered: nginx resets limit_rate for unbuffered responses."""
    conf = tn.tmp / "pcdn/sites/205.conf"
    orig = conf.read_text()
    assert "limit_rate" not in orig
    try:
        conf.write_text(orig.replace("proxy_buffering off;", "proxy_buffering off; limit_rate 125000;"))
        assert subprocess.run(tn.cfg["NGINX_RELOAD_CMD"], shell=True).returncode == 0
        time.sleep(0.5)
        t0 = time.time()
        assert len(tn.req("lim.test", "/x/big?n=400000").body) == 400000
        elapsed = time.time() - t0
    finally:
        conf.write_text(orig)
        subprocess.run(tn.cfg["NGINX_RELOAD_CMD"], shell=True)
        time.sleep(0.5)
    if elapsed > 2:  # a future nginx that honours it: render it again (pcdn-agent.py tunnel_loc)
        pytest.fail(f"this nginx rate-limits unbuffered responses ({elapsed:.1f}s); tunnel limit_rate can be enabled")


# ----------------------------------------------------------------- fallback

def test_decoy_and_404_fallback(tn):
    r = tn.req("decoy.test", "/")
    assert r.status == 200 and r.headers["content-type"].startswith("text/html")
    assert "<title>Decoy</title>" in r.text
    for word in ("cdn", "vpn", "pasargad", "proxy", "nginx", "tunnel"):
        assert word not in r.text.lower()
    assert tn.req("decoy.test", "/any/path?x=1", "POST", body=b"a=1").status == 200
    assert tn.req("decoy.test", "/pic.png?width=100").text == r.text  # no image fetch from the origin
    assert tn.req("nf.test", "/").status == 404
    assert tn.req("nf.test", "/index.php").status == 404
    for host in ("decoy.test", "nf.test"):
        sock, head, _ = ws_open(tn, host, "/t/sub", tls=False)
        sock.close()
        assert status_of(head) == 101
    assert tn.req("off.test", "/t").status == 200  # disabled tunnel: normal site (the origin echoes)


# ----------------------------------------------------------------- access log + usage aggregation

def test_tunnel_log_fields_and_usage(tn):
    start = len(tn.log())
    sock, head, buf = ws_open(tn, "lim.test", "/t?m=usage", tls=False)
    up = b"u" * 20000
    sock.sendall(ws_frame(up))
    got = b""
    while len(got) < len(up):
        _, data, buf = ws_read(sock, buf)
        got += data
    time.sleep(0.3)
    sock.close()
    c = H2Client(tn.sport, "tn.test", "/grpc.Svc/Usage")
    c.send(b"g" * 30000)
    got = b""
    while len(got) < 30000:
        got += c.recv_data()
    c.send(b"", end=True)
    while c.recv_data() is not None:
        pass
    c.close()

    assert wait_for(lambda: any("m=usage" in e["u"] for e in tn.log()[start:])
                    and any("Usage" in e["u"] for e in tn.log()[start:]), 5)
    new = tn.log()[start:]
    ws = next(e for e in new if "m=usage" in e["u"])
    gr = next(e for e in new if "Usage" in e["u"])
    assert ws["tn"] == "ws" and gr["tn"] == "grpc"
    assert float(ws["rt"]) >= 0.3
    # nginx reports the upstream-bound bytes of the whole session (see docs/EDGE.md)
    assert ws["b"] > 20000 and int(ws["ub"]) > 20000 and ws["bu"] < 20000
    assert gr["b"] > 30000 and int(gr["ub"]) > 30000 and gr["bu"] > 30000

    state = {}
    agent.read_usage(state, tn.cfg["ACCESS_LOG"])
    items = {i["host"]: i for i in agent.usage_items(state["pending"])}
    t = items["lim.test"]["tunnel"]
    assert t["sessions"] >= 1 and t["bytes_up"] > 20000 and t["bytes_down"] > 20000 and t["seconds"] >= 0
    assert set(t["by_protocol"]) <= {"ws", "xhttp"} and t["by_protocol"]["ws"] > 40000
    g = items["tn.test"]["tunnel"]
    assert g["by_protocol"]["grpc"] > 60000
    # refused tunnel requests (403 country) count bytes but no session; normal requests no tunnel counters
    assert items["cc.test"]["tunnel"]["sessions"] == 0 and items["cc.test"]["tunnel"]["bytes_down"] > 0
    assert "tunnel" not in items["off.test"]
