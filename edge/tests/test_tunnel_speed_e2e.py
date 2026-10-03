"""Wave 13 (SPEC §22) end-to-end: real nginx + njs + the agent's rendered config.

  * the synthetic tunnel probe (§22.3): WS + gRPC through the node's own nginx to the loopback echo
    origin / h2c body server, 403 for a non-loopback client;
  * the node drain flag (§22.1): only the FIRST request of a NEW client connection is refused (503,
    Retry-After, Connection: close, "pg":"drain" -> errors.edge); requests on existing connections and
    xhttp POSTs pass; clearing the flag restores service;
  * multi-origin tunnel paths with agent TCP health (§22.4): primary down -> a new WS session lands on
    the backup while the session already on the primary keeps working; /__pcdn/hc is localhost-only;
  * shared session-ticket keys (§22.8) pass nginx -t.
"""

import base64
import json
import os
import shutil
import socket
import ssl
import subprocess
import time

import pytest

from conftest import modules_available, nginx_conf, TEST_ORIGIN_ALLOW
from test_nginx_e2e import Edge, Origin, agent, free_port, self_signed, site, wait_for
from tunnel_kit import connect, read_until, upgrade_request, ws_frame, ws_read

pytestmark = pytest.mark.skipif(shutil.which("nginx") is None or not modules_available(),
                                reason="nginx with njs/geoip2/image_filter/brotli modules not installed")


class CountingEcho(agent.EchoServer):
    """The agent's echo origin, counting the HTTP requests it got (which origin served a session); the
    bare TCP health-check connections send nothing and are not counted."""

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.n = 0

    def _serve(self, conn):
        try:
            conn.settimeout(5)
            if conn.recv(4, socket.MSG_PEEK) == b"GET ":
                self.n += 1
        except OSError:
            pass
        super()._serve(conn)


def tunnel(paths, **kw):
    t = {"enabled": True, "paths": paths, "idle_timeout": 90, "per_connection_mbps": 0, "max_connections_per_ip": 0,
         "allowed_countries": [], "fallback": "origin", "max_connections": 0, "fair_share": False}
    t.update(kw)
    return t


@pytest.fixture(scope="module")
def sp(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("speed")
    web = Origin("WEB")
    echo_port, h2c_port = free_port(), free_port()
    primary, backup, single = (CountingEcho("127.0.0.1", free_port()).start() for _ in range(3))
    cfg = dict(agent.DEFAULTS, ORIGIN_PRIVATE_ALLOW=TEST_ORIGIN_ALLOW)
    cfg.update({
        "NGINX_DIR": str(tmp / "pcdn"), "CACHE_DIR": str(tmp / "cache"), "STATE_FILE": str(tmp / "state.json"),
        "ACCESS_LOG": str(tmp / "access.log"), "L4_ACCESS_LOG": str(tmp / "l4.log"),
        "FN_USAGE_LOG": str(tmp / "fn-usage.log"), "PAGES_DIR": str(agent.HERE) + "/pages",
        "NJS_FILE": str(agent.HERE) + "/njs/pcdn.js", "BASE_TEMPLATE": str(agent.HERE) + "/nginx/pcdn-base.conf",
        "GEOIP_DB": str(tmp / "none.mmdb"), "RESOLVER": "127.0.0.1", "NGINX_USER": "root", "LISTEN_IPV6": "no",
        "HTTP_PORT": str(free_port()), "HTTPS_PORT": str(free_port()), "RESIZE_PORT": str(free_port()),
        "DICT_SIZE": "4m", "PROBE_ENABLED": "yes", "PROBE_ECHO_PORT": str(echo_port), "PROBE_H2C_PORT": str(h2c_port),
        "PROBE_DIR": str(tmp / "probe"), "PROBE_BYTES": "65536",
    })
    conf = nginx_conf(tmp, cfg)
    cfg["NGINX_TEST_CMD"] = f"nginx -t -q -c {conf}"
    cfg["NGINX_RELOAD_CMD"] = f"nginx -s reload -c {conf}"
    assert agent.ensure_probe_files(cfg)
    echo = agent.EchoServer("127.0.0.1", echo_port).start()
    cert, key = self_signed(tmp, "sp.test")
    WEB = {"address": "127.0.0.1", "port": web.port}

    def o(srv, **kw):
        return dict({"address": "127.0.0.1", "port": srv.port, "tls": False, "sni": None, "verify": False}, **kw)
    sites = [site(301, "sp.test", WEB, ssl={"cert": cert, "key": key}, tunnel=tunnel([
        {"id": "ws", "path": "/ws", "protocol": "ws", "origin": o(single)},
        {"id": "xh", "path": "/xh", "protocol": "xhttp", "origin": o(single)},
        # §22.4: two origins, failover (the controller sends every item after the first as backup)
        {"id": "mo", "path": "/mo", "protocol": "ws", "origin": o(primary),
         "origins": [o(primary), o(backup, backup=True)], "balance": "failover",
         "health": {"type": "tcp", "interval": 5, "timeout": 1}}]))]
    keys = [base64.b64encode(os.urandom(80)).decode() for _ in range(3)]
    config = {"version": "v1", "sites": sites, "node": {"tls_tickets": {"id": "0a1b2c3d", "keys": keys}}}
    agent.bootstrap(cfg)
    p = subprocess.run(["nginx", "-c", str(conf)], capture_output=True, text=True)
    assert p.returncode == 0, p.stderr
    edge = Edge(cfg, conf)
    try:
        assert wait_for(lambda: edge.req("unknown.test", "/__pcdn/health").status == 200)
        err = agent.apply_config(config, cfg)
        assert err is None, err
        edge.tmp, edge.config, edge.keys = tmp, config, keys
        edge.primary, edge.backup, edge.single = primary, backup, single
        assert wait_for(lambda: edge.req("sp.test", "/").status == 200)
        yield edge
    finally:
        subprocess.run(["nginx", "-s", "stop", "-c", str(conf)], capture_output=True)
        for x in (echo, primary, backup, single):
            x.stop()
        web.stop()


def local_non_loopback_ip() -> str | None:
    """An address of this host that is not loopback (a client from it is not 'local' to nginx)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("192.0.2.1", 9))
            ip = s.getsockname()[0]
        return None if ip.startswith("127.") else ip
    except OSError:
        return None


def fair(edge, query):
    return edge.req("x", f"/__pcdn/fair?{query}").status


def ws_open(edge, host, path, sock=None):
    sock = sock or connect(edge.sport, host, True, alpn=["http/1.1"])
    sock.sendall(upgrade_request(host, path, True))
    head, rest = read_until(sock, b"\r\n\r\n")
    return sock, head, rest


def ws_echo(sock, rest=b"", payload=b"ping-123"):
    sock.sendall(ws_frame(payload))
    op, data, rest = ws_read(sock, rest)
    return data == payload, rest


def test_ticket_keys_and_probe_server_rendered(sp):
    root = sp.cfg["NGINX_DIR"]
    http = open(f"{root}/http.conf").read()
    assert "ssl_session_tickets on;" in http and http.count("ssl_session_ticket_key") == 3
    for i, k in enumerate(sp.keys):
        path = f"{root}/tickets/{i}.key"
        assert open(path, "rb").read() == base64.b64decode(k) and os.stat(path).st_mode & 0o777 == 0o600
    assert "server_name probe.pcdn.invalid;" in http and "deny all;" in http
    p = subprocess.run(["nginx", "-t", "-c", str(sp.conf)], capture_output=True, text=True)
    assert p.returncode == 0, p.stderr
    # resumption with a shared ticket: a second TLS connection resumes the first one's session
    ctx = ssl.create_default_context()
    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    with ctx.wrap_socket(socket.create_connection(("127.0.0.1", sp.sport)), server_hostname="sp.test") as s1:
        s1.sendall(b"GET / HTTP/1.1\r\nHost: sp.test\r\nConnection: close\r\n\r\n")
        while s1.recv(65536):
            pass
        sess = s1.session
    with ctx.wrap_socket(socket.create_connection(("127.0.0.1", sp.sport)), server_hostname="sp.test",
                         session=sess) as s2:
        assert s2.session_reused


def test_ws_and_grpc_probe_through_own_nginx(sp):
    n = int(sp.cfg["PROBE_BYTES"])
    ws = agent.ws_probe(sp.sport, n, 8)
    assert ws["ok"] and ws["echo_ok"] and ws["error"] is None, ws
    assert ws["setup_ms"] is not None and ws["down_kbps"] > 0 and ws["up_kbps"] > 0
    res = agent.run_probe(sp.cfg, True)
    assert res["ws"]["ok"], res
    if agent.curl_has_http2():
        assert res["grpc"]["ok"] and res["grpc"]["echo_ok"], res
        assert set(res["grpc"]) == {"ok", "setup_ms", "echo_ok", "down_kbps", "error"}
    else:
        assert res["grpc"] == {"unsupported": True}
    assert res["ok"] is True and set(res) == {"at", "ok", "ws", "grpc"}
    # the probe never counts as site usage (no access log, no $pcdn_tp)
    assert all(e["h"] != "probe.pcdn.invalid" for e in sp.log())


def test_probe_server_refuses_public_clients(sp):
    ip = local_non_loopback_ip()
    if not ip:
        pytest.skip("no non-loopback address on this host")
    ctx = ssl.create_default_context()
    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    ctx.set_alpn_protocols(["http/1.1"])
    try:
        raw = socket.create_connection((ip, sp.sport), timeout=5)
    except OSError:
        pytest.skip("cannot reach the edge on the non-loopback address")
    with ctx.wrap_socket(raw, server_hostname="probe.pcdn.invalid") as s:
        s.sendall(upgrade_request("probe.pcdn.invalid", "/__pcdn_probe/ws", True))
        head, _ = read_until(s, b"\r\n\r\n")
    assert b" 403 " in head.split(b"\r\n", 1)[0]
    # the TCP health endpoint is localhost-only too
    with socket.create_connection((ip, sp.port), timeout=5) as s:
        s.sendall(b"POST /__pcdn/hc HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}")
        head, _ = read_until(s, b"\r\n\r\n")
    assert b" 403 " in head.split(b"\r\n", 1)[0]


def test_drain_refuses_only_new_connections(sp):
    try:
        # an existing client connection: one normal request first, keep-alive
        old = connect(sp.sport, "sp.test", True, alpn=["http/1.1"])
        old.sendall(b"GET / HTTP/1.1\r\nHost: sp.test\r\n\r\n")
        head, rest = read_until(old, b"\r\n\r\n")
        assert b" 200 " in head.split(b"\r\n", 1)[0]
        n = int([ln for ln in head.split(b"\r\n") if ln.lower().startswith(b"content-length")][0].split(b":")[1])
        while len(rest) < n:
            rest += old.recv(65536)
        # an established WS session from before the drain
        s0, h0, r0 = ws_open(sp, "sp.test", "/ws")
        assert b" 101 " in h0.split(b"\r\n", 1)[0]
        assert fair(sp, "drain=1") == 204
        # a NEW connection opening a tunnel session: refused, told to come back elsewhere, closed
        s1, h1, _ = ws_open(sp, "sp.test", "/ws")
        status, *lines = h1.decode("latin-1").split("\r\n")
        hdrs = {k.lower(): v.strip() for k, _, v in (ln.partition(":") for ln in lines if ln)}
        assert " 503 " in status and hdrs.get("retry-after") == "30" and hdrs.get("connection") == "close"
        s1.close()
        # the second request of the existing connection passes (connection_requests = 2)
        _, h2, r2 = ws_open(sp, "sp.test", "/ws", sock=old)
        assert b" 101 " in h2.split(b"\r\n", 1)[0]
        assert ws_echo(old, r2)[0]
        # the session established before the drain keeps working
        assert ws_echo(s0, r0)[0]
        # an xhttp POST (packets of an existing session) is never refused, even on a new connection
        r = sp.req("sp.test", "/xh/sess/0", method="POST", body=b"x" * 10, https=True)
        assert r.status != 503
        # web traffic is still served
        assert sp.req("sp.test", "/", https=True).status == 200
        # the refusal is an edge decision in the access log: "pg":"drain" -> errors.edge
        e = sp.last_log("sp.test", "/ws")
        lines = [x for x in sp.log() if x["h"] == "sp.test" and x["u"] == "/ws" and x["s"] == 503]
        assert lines and lines[-1]["pg"] == "drain" and lines[-1]["tp"] == "ws" and e
        assert agent.classify_tunnel(lines[-1]) == "edge"
    finally:
        fair(sp, "drain=0")
    s3, h3, r3 = ws_open(sp, "sp.test", "/ws")
    assert b" 101 " in h3.split(b"\r\n", 1)[0] and ws_echo(s3, r3)[0]
    for s in (old, s0, s3):
        s.close()


def test_drain_flag_expires_and_hot_flag_untouched(sp):
    """drain=... never touches the fair-share hot flag (and vice versa)."""
    assert fair(sp, "hot=0") == 204 and fair(sp, "drain=1") == 204
    s, h, _ = ws_open(sp, "sp.test", "/ws")
    assert b" 503 " in h.split(b"\r\n", 1)[0]
    s.close()
    assert fair(sp, "hot=0") == 204     # hot only: drain stays on
    s, h, _ = ws_open(sp, "sp.test", "/ws")
    assert b" 503 " in h.split(b"\r\n", 1)[0]
    s.close()
    assert fair(sp, "drain=0") == 204
    s, h, _ = ws_open(sp, "sp.test", "/ws")
    assert b" 101 " in h.split(b"\r\n", 1)[0]
    s.close()


def test_multi_origin_failover_with_tcp_health(sp):
    hc = agent.TcpHealth(sp.cfg)
    files = agent.render_all(sp.config, sp.cfg)
    targets = agent.tcp_targets(files)
    assert sorted(t[0] for t in targets) == sorted(f"301|tn.mo|127.0.0.1:{s.port}" for s in (sp.primary, sp.backup))
    hc.set_targets(targets)
    assert hc.step(now=1000.0) == {t[0]: 0 for t in targets}   # both up, pushed into nginx
    p0, b0 = sp.primary.n, sp.backup.n
    s1, h1, r1 = ws_open(sp, "sp.test", "/mo")
    assert b" 101 " in h1.split(b"\r\n", 1)[0]
    assert sp.primary.n == p0 + 1 and sp.backup.n == b0           # failover: the primary serves
    # the primary stops accepting: two failed checks (HC_FALL) take it out of new sessions
    sp.primary.stop()
    hc.step(now=1006.0)
    pushed = hc.step(now=1012.0)
    assert pushed == {f"301|tn.mo|127.0.0.1:{sp.primary.port}": 2}
    b1 = sp.backup.n
    s2, h2, r2 = ws_open(sp, "sp.test", "/mo")
    assert b" 101 " in h2.split(b"\r\n", 1)[0] and sp.backup.n == b1 + 1
    assert ws_echo(s2, r2)[0]
    # the session that was already on the primary is untouched until it closes
    assert ws_echo(s1, r1)[0]
    for s in (s1, s2):
        s.close()


def test_hc_endpoint_validates_keys(sp):
    url = f"http://127.0.0.1:{sp.port}/__pcdn/hc"
    import urllib.request
    op = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    body = json.dumps({"301|tn.mo|127.0.0.1:1": 0, "bad key": 3, "1|x|h:1": "junk"}).encode()
    with op.open(urllib.request.Request(url, data=body, method="POST"), timeout=5) as r:
        assert r.status == 200 and r.read() == b"1"
    with pytest.raises(urllib.error.HTTPError) as e:
        op.open(urllib.request.Request(url, data=b"[1]", method="POST"), timeout=5)
    assert e.value.code == 400
    with pytest.raises(urllib.error.HTTPError) as e:
        op.open(url, timeout=5)
    assert e.value.code == 405


def test_agent_probe_round_and_heartbeat(sp):
    pr = agent.ProbeRunner(sp.cfg)
    pr.rendered = True
    res = pr.round()
    assert res and res["ok"] and res["consecutive_fail"] == 0
    assert pr.first_passed_or_unsupported()
    json.dumps(res)
    # the nginx tree carries the probe only while it is enabled
    off = dict(sp.cfg, PROBE_ENABLED="no")
    assert "probe.pcdn.invalid" not in agent.render_all(sp.config, off)["http.conf"]
    assert agent.ProbeRunner(off).first_passed_or_unsupported()
    time.sleep(0)
