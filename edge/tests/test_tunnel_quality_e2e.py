"""Wave 7 (SPEC §15) end-to-end: real nginx output for the tunnel quality classification, the
wrong-protocol answer, fair-share admission and the speed-test endpoints.

The point of the classification tests is to pin what nginx 1.24 actually logs ($status,
$upstream_status, $upstream_connect_time) for each failure mode, and that the agent's
classify_tunnel() puts every one of those real lines into the right bucket.
"""

import json
import socket
import shutil
import subprocess
import threading
import time
import urllib.request

import pytest

from conftest import modules_available, nginx_conf, TEST_ORIGIN_ALLOW
from test_nginx_e2e import Edge, Origin, agent, free_port, make_mmdb, self_signed, site, wait_for
from tunnel_kit import (DATA, END_HEADERS, GOAWAY, HEADERS, PING, PREFACE, SETTINGS, ACK, H2Client,
                        H2Origin, TunnelOrigin, connect, h2_frame, h2_read, hpack_literal, read_exact, read_until,
                        upgrade_request, ws_frame, ws_read)

pytestmark = pytest.mark.skipif(shutil.which("nginx") is None or not modules_available(),
                                reason="nginx with njs/geoip2/image_filter/brotli modules not installed")


def tpath(pid, path, protocol, origin=None):
    return {"id": pid, "path": path, "protocol": protocol, "origin": origin, "pool": None}


def tunnel(paths, **kw):
    t = {"enabled": True, "paths": paths, "idle_timeout": 60, "per_connection_mbps": 0, "max_connections_per_ip": 0,
         "allowed_countries": [], "fallback": "origin", "max_connections": 0}
    t.update(kw)
    return t


class ScriptedOrigin:
    """HTTP/1.1 origin whose behaviour depends on the path: /o404 -> 404, /close -> close without an
    answer, /rst -> 101 then a TCP reset after the first frame, anything else -> 101 echo."""

    def __init__(self):
        self.lsock = socket.socket()
        self.lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.lsock.bind(("127.0.0.1", 0))
        self.lsock.listen(64)
        self.port = self.lsock.getsockname()[1]
        self.running = True
        threading.Thread(target=self._accept, daemon=True).start()

    def stop(self):
        self.running = False
        self.lsock.close()

    def _accept(self):
        while self.running:
            try:
                c, _ = self.lsock.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(c,), daemon=True).start()

    def _serve(self, c):
        try:
            head, buf = read_until(c, b"\r\n\r\n")
            path = head.split(b" ", 2)[1].decode()
            if path.startswith("/o404"):
                c.sendall(b"HTTP/1.1 404 Not Found\r\nContent-Length: 2\r\nConnection: close\r\n\r\nno")
            elif path.startswith("/close"):
                pass
            elif path.startswith("/rst"):
                c.sendall(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
                if not buf:
                    c.recv(100)
                c.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, b"\x01\x00\x00\x00\x00\x00\x00\x00")
            else:
                c.sendall(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
                while True:
                    d = buf or c.recv(65536)
                    buf = b""
                    if not d:
                        break
                    c.sendall(d)
        except OSError:
            pass
        finally:
            c.close()


class H2Reset:
    """h2c origin that answers a stream with 200 headers, echoes the first DATA, then drops the TCP
    connection (an established gRPC stream dying on the origin side)."""

    def __init__(self):
        self.lsock = socket.socket()
        self.lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.lsock.bind(("127.0.0.1", 0))
        self.lsock.listen(64)
        self.port = self.lsock.getsockname()[1]
        threading.Thread(target=self._accept, daemon=True).start()

    def stop(self):
        self.lsock.close()

    def _accept(self):
        while True:
            try:
                c, _ = self.lsock.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(c,), daemon=True).start()

    def _serve(self, c):
        try:
            _, buf = read_exact(c, len(PREFACE))
            c.sendall(h2_frame(SETTINGS, 0, 0))
            while True:
                ftype, flags, sid, payload, buf = h2_read(c, buf)
                if ftype == SETTINGS and not flags & ACK:
                    c.sendall(h2_frame(SETTINGS, ACK, 0))
                elif ftype == PING and not flags & ACK:
                    c.sendall(h2_frame(PING, ACK, 0, payload))
                elif ftype == HEADERS:
                    c.sendall(h2_frame(HEADERS, END_HEADERS, sid, b"\x88" + hpack_literal("content-type",
                                                                                           "application/grpc")))
                elif ftype == DATA and payload:
                    c.sendall(h2_frame(DATA, 0, sid, payload))
                    time.sleep(0.2)
                    c.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, b"\x01\x00\x00\x00\x00\x00\x00\x00")
                    return
                elif ftype == GOAWAY:
                    return
        except OSError:
            pass
        finally:
            c.close()


def blackhole():
    """A listening socket whose accept queue is full: SYNs are dropped, so a connect times out."""
    ls = socket.socket()
    ls.bind(("127.0.0.1", 0))
    ls.listen(0)
    port = ls.getsockname()[1]
    fillers = []
    for _ in range(3):
        s = socket.socket()
        s.setblocking(False)
        try:
            s.connect(("127.0.0.1", port))
        except BlockingIOError:
            pass
        fillers.append(s)
    time.sleep(0.2)
    return ls, port, fillers


@pytest.fixture(scope="module")
def tq(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("tquality")
    try:
        make_mmdb(tmp / "country.mmdb")
    except ImportError:
        pytest.skip("mmdb_writer/netaddr not installed")
    web, to, h2o, so, h2r = Origin("WEB"), TunnelOrigin(), H2Origin(), ScriptedOrigin(), H2Reset()
    bh_sock, bh_port, bh_fill = blackhole()
    dead = free_port()   # nothing listens: connection refused
    cfg = dict(agent.DEFAULTS, ORIGIN_PRIVATE_ALLOW=TEST_ORIGIN_ALLOW)
    cfg.update({
        "NGINX_DIR": str(tmp / "pcdn"), "CACHE_DIR": str(tmp / "cache"), "STATE_FILE": str(tmp / "state.json"),
        "ACCESS_LOG": str(tmp / "access.log"), "L4_ACCESS_LOG": str(tmp / "l4.log"), "FN_USAGE_LOG": str(tmp / "fn-usage.log"), "PAGES_DIR": str(agent.HERE) + "/pages",
        "NJS_FILE": str(agent.HERE) + "/njs/pcdn.js", "BASE_TEMPLATE": str(agent.HERE) + "/nginx/pcdn-base.conf",
        "GEOIP_DB": str(tmp / "country.mmdb"), "RESOLVER": "127.0.0.1", "NGINX_USER": "root", "LISTEN_IPV6": "no",
        "HTTP_PORT": str(free_port()), "HTTPS_PORT": str(free_port()), "RESIZE_PORT": str(free_port()),
        "DICT_SIZE": "4m", "TUNNEL_CONNECT_TIMEOUT": "3", "NODE_NAME": "edge-test-1",
    })
    conf = nginx_conf(tmp, cfg)
    cfg["NGINX_TEST_CMD"] = f"nginx -t -q -c {conf}"
    cfg["NGINX_RELOAD_CMD"] = f"nginx -s reload -c {conf}"
    cert, key = self_signed(tmp, "q.test")
    ssl = {"cert": cert, "key": key}

    def o(port):
        return {"address": "127.0.0.1", "port": port, "tls": False, "sni": None, "verify": False}
    paths = [tpath("ws", "/ws", "ws", o(to.port)), tpath("hu", "/hu", "httpupgrade", o(to.port)),
             tpath("xh", "/xh", "xhttp", o(to.port)), tpath("gr", "/gr", "grpc", o(h2o.port)),
             tpath("h2", "/h2", "h2", o(h2o.port)),
             tpath("refws", "/refws", "ws", o(dead)), tpath("refgr", "/refgr", "grpc", o(dead)),
             tpath("refxh", "/refxh", "xhttp", o(dead)),
             tpath("tows", "/tows", "ws", o(bh_port)), tpath("togr", "/togr", "grpc", o(bh_port)),
             tpath("o404", "/o404", "ws", o(so.port)), tpath("close", "/close", "ws", o(so.port)),
             tpath("rst", "/rst", "ws", o(so.port)), tpath("h2rst", "/h2rst", "grpc", o(h2r.port))]
    sites = [
        site(301, "q.test", {"address": "127.0.0.1", "port": web.port}, ssl=ssl, tunnel=tunnel(paths)),
        site(302, "lim.test", {"address": "127.0.0.1", "port": web.port},
             tunnel=tunnel([tpath("t", "/t", "ws", o(to.port))], max_connections_per_ip=1)),
        site(303, "cc.test", {"address": "127.0.0.1", "port": web.port},
             tunnel=tunnel([tpath("t", "/t", "ws", o(to.port))], allowed_countries=["IR"])),
        site(304, "plain.test", {"address": "127.0.0.1", "port": web.port}, ssl=ssl,
             firewall={"default_action": "allow", "rules": [
                 {"id": "chal", "enabled": True, "action": "challenge",
                  "conditions": [{"field": "path", "op": "starts_with", "value": "/"}]},
                 {"id": "evil", "enabled": True, "action": "block",
                  "conditions": [{"field": "header", "name": "X-Evil", "op": "eq", "value": "yes"}]}]},
             waf={"mode": "block", "paranoia": 1, "groups": ["sqli", "scanner"], "exclusions": []}),
        site(305, "hog.test", {"address": "127.0.0.1", "port": web.port},
             tunnel=tunnel([tpath("t", "/t", "ws", o(to.port)), tpath("x", "/x", "xhttp", o(to.port))])),
        site(306, "small.test", {"address": "127.0.0.1", "port": web.port},
             tunnel=tunnel([tpath("t", "/t", "ws", o(to.port))])),
        site(307, "nofair.test", {"address": "127.0.0.1", "port": web.port},
             tunnel=tunnel([tpath("t", "/t", "ws", o(to.port))], fair_share=False)),
    ]
    agent.bootstrap(cfg)
    p = subprocess.run(["nginx", "-c", str(conf)], capture_output=True, text=True)
    assert p.returncode == 0, p.stderr
    edge = Edge(cfg, conf)
    try:
        assert wait_for(lambda: edge.req("unknown.test", "/__pcdn/health").status == 200)
        err = agent.apply_config({"sites": sites, "node": {"capacity_mbps": 1000, "fair_share_pct": 25}}, cfg)
        assert err is None, err
        assert wait_for(lambda: edge.req("plain.test", "/__pcdn/speed/ping").status == 204), \
            (tmp / "error.log").read_text()[-3000:]
        edge.tmp, edge.sites = tmp, sites
        yield edge
    finally:
        subprocess.run(["nginx", "-s", "stop", "-c", str(conf)], capture_output=True)
        for x in (web, to, h2o, so, h2r):
            x.stop()
        bh_sock.close()
        for s in bh_fill:
            s.close()


def ws_try(env, host, path, tls=False, upgrade=True, hold=0.0, send=b""):
    sock = connect(env.sport if tls else env.port, host, tls, alpn=["http/1.1"] if tls else None, timeout=20)
    try:
        if upgrade:
            sock.sendall(upgrade_request(host, path, True))
        else:
            sock.sendall(f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: probe\r\n\r\n".encode())
        head, buf = read_until(sock, b"\r\n\r\n")
        code = int(head.split(b" ", 2)[1])
        if code == 101 and send:
            sock.sendall(ws_frame(send))
            try:
                ws_read(sock, buf)
            except (OSError, ValueError, ConnectionError):
                pass
        if hold:
            time.sleep(hold)
        return code
    finally:
        sock.close()


def h2_try(env, host, path, send=b"", wait=10):
    c = H2Client(env.sport, host, path)
    try:
        if send:
            c.send(send)
        try:
            while c.recv_data(timeout=wait) is not None:
                pass
        except (OSError, ValueError, ConnectionError):
            pass
        return c.status
    finally:
        c.close()


def h1_req(env, host, path, method="GET", tls=True, headers=None):
    sock = connect(env.sport if tls else env.port, host, tls, alpn=["http/1.1"] if tls else None, timeout=20)
    try:
        h = {"Host": host, "User-Agent": "probe", "Connection": "close", "Content-Length": "0"}
        h.update(headers or {})
        sock.sendall((f"{method} {path} HTTP/1.1\r\n" + "".join(f"{k}: {v}\r\n" for k, v in h.items())
                      + "\r\n").encode())
        head, _ = read_until(sock, b"\r\n\r\n")
        return int(head.split(b" ", 2)[1])
    finally:
        sock.close()


def line_for(env, host, marker, timeout=8.0):
    return env.last_log(host, marker, timeout)



# ----------------------------------------------------------------- classification (SPEC §15.1)

GRPC_MSG = b"\x00\x00\x00\x00\x02hi"


def test_real_nginx_lines_classify(tq):
    got = {
        "okws": ws_try(tq, "q.test", "/ws?m=okws", send=b"hi"),
        "okgr": h2_try(tq, "q.test", "/gr/x?m=okgr", send=GRPC_MSG, wait=1),
        "refws": ws_try(tq, "q.test", "/refws?m=refws"),
        "refgr": h2_try(tq, "q.test", "/refgr/x?m=refgr"),
        "refxh": h1_req(tq, "q.test", "/refxh/a?m=refxh"),
        "tows": ws_try(tq, "q.test", "/tows?m=tows"),
        "togr": h2_try(tq, "q.test", "/togr/x?m=togr"),
        "o404": ws_try(tq, "q.test", "/o404?m=o404"),
        "close": ws_try(tq, "q.test", "/close?m=close"),
        "noupg": ws_try(tq, "q.test", "/ws?m=noupg", upgrade=False),
        "huno": ws_try(tq, "q.test", "/hu?m=huno", upgrade=False),
        "grh1": h1_req(tq, "q.test", "/gr/x?m=grh1", method="POST", headers={"Content-Type": "application/grpc"}),
        "cc": ws_try(tq, "cc.test", "/t?m=cc"),
    }
    held = connect(tq.port, "lim.test", False)
    held.sendall(upgrade_request("lim.test", "/t?m=lim1"))
    read_until(held, b"\r\n\r\n")
    got["lim"] = ws_try(tq, "lim.test", "/t?m=lim2")
    # the client gives up while the edge is still connecting (blackholed origin)
    s = connect(tq.port, "q.test", False)
    s.sendall(upgrade_request("q.test", "/tows?m=early"))
    time.sleep(0.5)
    s.close()
    held.close()
    assert got == {"okws": 101, "okgr": 200, "refws": 502, "refgr": 502, "refxh": 502, "tows": 504, "togr": 504,
                   "o404": 404, "close": 502, "noupg": 426, "huno": 426, "grh1": 200, "cc": 403, "lim": 429}
    want = {  # marker -> (host, $status, last $upstream_status, connect time present, class)
        "okws": ("q.test", 101, "101", True, "session"),
        "okgr": ("q.test", 200, "200", True, "session"),
        "refws": ("q.test", 502, "502", False, "origin_refused"),
        "refgr": ("q.test", 502, "502", False, "origin_refused"),
        "refxh": ("q.test", 502, "502", False, "origin_refused"),
        "tows": ("q.test", 504, "504", False, "origin_timeout"),
        "togr": ("q.test", 504, "504", False, "origin_timeout"),
        "o404": ("q.test", 404, "404", True, "origin_error"),
        "close": ("q.test", 502, "502", True, "origin_refused"),     # closed before a response header
        "noupg": ("q.test", 426, "", False, "protocol"),             # edge answer, origin never asked
        "huno": ("q.test", 426, "", False, "protocol"),
        "grh1": ("q.test", 200, "200", True, "protocol"),            # gRPC path over HTTP/1.1
        "cc": ("cc.test", 403, "", False, "country"),
        "lim2": ("lim.test", 429, "", False, "limit"),
        "lim1": ("lim.test", 101, "101", True, "session"),
        "early": ("q.test", 499, "-", False, None),                  # client gave up: not counted
    }
    for marker, (host, status, us, ct, cls) in want.items():
        e = line_for(tq, host, "m=" + marker)
        assert e["s"] == status and agent._last_value(e["us"]) == us, (marker, e)
        assert e["tp"] and e["tn"], (marker, e)
        assert (agent.connect_ms(e) is not None) == ct, (marker, e)
        assert agent.classify_tunnel(e) == cls, (marker, e)
    # the 426 never reached the origin and carries no body worth billing
    assert line_for(tq, "q.test", "m=noupg")["uct"] == ""

    # the whole log through the agent: per-path counters + live minute counters
    state = {}
    agent.read_usage(state, tq.cfg["ACCESS_LOG"])
    items = {i["host"]: i for i in agent.usage_items(state["pending"])}
    paths = items["q.test"]["tunnel"]["paths"]
    assert paths["refws"]["errors"]["origin_refused"] == 1 and paths["refws"]["sessions"] == 0
    assert paths["refws"]["connect_n"] == 0
    assert paths["refgr"]["errors"]["origin_refused"] == 1 and paths["refxh"]["errors"]["origin_refused"] == 1
    assert paths["togr"]["errors"]["origin_timeout"] == 1
    assert paths["tows"]["errors"]["origin_timeout"] >= 1 and sum(paths["tows"]["errors"].values()) == \
        paths["tows"]["errors"]["origin_timeout"]
    assert paths["o404"]["errors"]["origin_error"] == 1 and paths["o404"]["connect_n"] == 1
    assert paths["close"]["errors"]["origin_refused"] == 1
    assert paths["ws"]["sessions"] >= 1 and paths["ws"]["errors"]["protocol"] >= 1
    assert paths["ws"]["connect_n"] >= 1 and paths["ws"]["connect_ms_sum"] >= 0
    assert paths["hu"]["errors"]["protocol"] >= 1 and paths["gr"]["errors"]["protocol"] >= 1
    assert items["cc.test"]["tunnel"]["paths"]["t"]["errors"]["country"] >= 1
    assert items["lim.test"]["tunnel"]["paths"]["t"]["errors"]["limit"] >= 1
    for p in paths.values():   # wire shape: integers >= 0, all seven error keys
        assert set(p) == {"sessions", "seconds", "bytes_up", "bytes_down", "abnormal", "connect_ms_sum", "connect_n",
                          "errors", "reused_n", "ends"}   # + SPEC §22.7 / §22.12
        assert set(p["errors"]) == set(agent.TUNNEL_ERRORS) and set(p["ends"]) == set(agent.TUNNEL_END_KEYS)
        assert all(isinstance(v, int) and v >= 0 for k, v in p.items() if k not in ("errors", "ends"))
    live = [i for i in agent.live_items(state["live"], agent.live_cutoff()) if i["host"] == "q.test"]
    lines = [e for e in tq.log() if e["h"] == "q.test" and e.get("tp")]
    assert sum(i.get("tunnel_attempts", 0) for i in live) == len(lines)
    assert sum(i.get("tunnel_errors", 0) for i in live) == sum(
        1 for e in lines if agent.classify_tunnel(e) in ("origin_refused", "origin_timeout"))
    assert all(i.get("tunnel_errors", 0) <= i.get("tunnel_attempts", 0) for i in live)
    plain = [i for i in agent.live_items(state["live"], agent.live_cutoff()) if i["host"] == "plain.test"]
    assert plain and all("tunnel_attempts" not in i for i in plain)


def test_abnormal_session_ends_from_the_error_log(tq):
    assert ws_try(tq, "q.test", "/rst?m=rst", send=b"x", hold=0.5) == 101        # origin resets after 101
    assert h2_try(tq, "q.test", "/h2rst/x?m=h2rst", send=GRPC_MSG) == 200          # origin drops the stream
    assert ws_try(tq, "q.test", "/ws?m=clean", send=b"hi") == 101                  # clean end: not abnormal
    for m in ("rst", "h2rst", "clean"):
        e = line_for(tq, "q.test", "m=" + m)
        assert agent.classify_tunnel(e) == "session"   # the access log alone cannot tell them apart
    cfg = dict(tq.cfg, ERROR_LOG=str(tq.tmp / "error.log"))
    state = {"tunnel_map": agent.tunnel_map({"sites": tq.sites})}
    lens = [len(prefix) for prefix, _ in state["tunnel_map"]["q.test"]]
    assert lens == sorted(lens, reverse=True)   # longest prefix first, like nginx "location ^~"
    assert wait_for(lambda: "while reading upstream" in (tq.tmp / "error.log").read_text(), 5)
    agent.collect_logs(state, cfg)
    paths = agent.usage_items(state["pending"])
    q = {i["host"]: i for i in paths}["q.test"]["tunnel"]["paths"]
    assert q["rst"]["abnormal"] == 1 and q["h2rst"]["abnormal"] == 1
    assert "ws" not in q and "refws" not in q and "tows" not in q   # connect failures are not abnormal ends
    # the next read sees no new lines: nothing counted twice
    agent.collect_logs(state, cfg)
    q = {i["host"]: i for i in agent.usage_items(state["pending"])}["q.test"]["tunnel"]["paths"]
    assert q["rst"]["abnormal"] == 1


def test_wrong_protocol_answer_keeps_real_clients_working(tq):
    # ws / httpupgrade with Upgrade: unchanged
    assert ws_try(tq, "q.test", "/ws?m=wsok2", send=b"x") == 101
    sock = connect(tq.port, "q.test", False)
    try:
        sock.sendall(upgrade_request("q.test", "/hu?m=huok", ws=False))
        head, _ = read_until(sock, b"\r\n\r\n")
        assert b" 101 " in head
    finally:
        sock.close()
    # an HTTP/2 request on a ws path (nginx cannot carry WebSocket over HTTP/2): 426 from the edge
    assert h2_try(tq, "q.test", "/ws/h2?m=wsh2") == 426
    # xhttp / grpc / h2 semantics are untouched: plain GET / POST still reach the origin
    assert h1_req(tq, "q.test", "/xh/down?m=xhok") == 200
    assert h2_try(tq, "q.test", "/h2/s?m=h2ok", send=GRPC_MSG, wait=1) == 200


# ----------------------------------------------------------------- fair share (SPEC §15.2)

def test_fair_share_refuses_only_new_sessions_of_the_hog_while_hot(tq):
    ag = agent.Agent(dict(tq.cfg, CONTROLLER_URL="http://127.0.0.1:9", EDGE_TOKEN="edge_test"))
    ag.state["node"] = {"capacity_mbps": 1000, "fair_share_pct": 25, "name": "edge-test-1"}
    established = connect(tq.port, "hog.test", False)
    established.sendall(upgrade_request("hog.test", "/t?m=hold"))
    head, buf = read_until(established, b"\r\n\r\n")
    assert b" 101 " in head
    try:
        ag.fair_signal({"tx_mbps": 900})   # 90 % of capacity: hot
        assert ag.state["fair_hot"] is True
        for i in range(12):
            assert ws_try(tq, "small.test", f"/t?m=s{i}") == 101
        codes = [ws_try(tq, "hog.test", f"/t?m=h{i}") for i in range(120)]
        assert codes[:29] == [101] * 29          # never refused below FAIR_MIN_SITE (30) opens, "hold" incl.
        assert 429 in codes
        admitted = codes.count(101)
        assert admitted < 120
        # the established session of the hog is untouched
        established.sendall(ws_frame(b"still-here"))
        assert ws_read(established, buf)[1] == b"still-here"
        # xhttp packet POSTs of the hog are never refused, its new downlink GETs are
        assert h1_req(tq, "hog.test", "/x/up?m=xpost", method="POST", tls=False) == 200
        assert h1_req(tq, "hog.test", "/x/down?m=xget", tls=False) == 429
        # hysteresis: 82 % keeps it hot
        ag.fair_signal({"tx_mbps": 820})
        assert ag.state["fair_hot"] is True and ws_try(tq, "hog.test", "/t?m=still-hot") == 429
        # a site with fair_share false is never refused; neither is the small site
        assert [ws_try(tq, "nofair.test", f"/t?m=n{i}") for i in range(40)] == [101] * 40
        assert ws_try(tq, "small.test", "/t?m=s-after") == 101
        # the refusals are "limit" errors of the hog's path
        e = line_for(tq, "hog.test", "m=xget")
        assert e["s"] == 429 and agent.classify_tunnel(e) == "limit"
        # 70 % releases it
        ag.fair_signal({"tx_mbps": 700})
        assert ag.state["fair_hot"] is False
        assert ws_try(tq, "hog.test", "/t?m=cool") == 101
    finally:
        ag.fair_signal({"tx_mbps": 0})
        established.close()


def test_fair_share_flag_is_localhost_only_and_validated(tq):
    # the default server only answers it on loopback addresses; a site host never serves it
    assert tq.req("hog.test", "/__pcdn/fair?hot=25").status == 404
    with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(
            f"http://127.0.0.1:{tq.port}/__pcdn/fair?hot=0", timeout=5) as r:
        assert r.status == 204


# ----------------------------------------------------------------- speed test (SPEC §15.6)

def test_speed_ping_and_download(tq):
    tag = agent.node_tag("edge-test-1")
    r = tq.req("plain.test", "/__pcdn/speed/ping", https=True)
    assert r.status == 204 and r.headers["x-pcdn-node"] == tag and "no-store" in r.headers["cache-control"]
    r = tq.req("plain.test", "/__pcdn/speed/down?bytes=3000000", headers={"Accept-Encoding": "gzip, br"})
    assert r.status == 200 and len(r.body) == 3000000
    assert r.headers["content-length"] == "3000000" and "content-encoding" not in r.headers
    assert "no-store" in r.headers["cache-control"] and r.headers["x-pcdn-node"] == tag
    import zlib
    assert len(zlib.compress(r.body[:1_000_000], 6)) > 990_000      # incompressible
    assert r.body[:65536] != r.body[65536:131072]
    r = tq.req("plain.test", "/__pcdn/speed/down?bytes=10")
    assert r.status == 200 and len(r.body) == 10 and r.headers["x-pcdn-node"] == tag
    r = tq.req("plain.test", "/__pcdn/speed/down?bytes=10485760")
    assert r.status == 200 and len(r.body) == 10485760
    assert tq.req("plain.test", "/__pcdn/speed/file?start=1").status == 404   # internal only
    assert tq.req("plain.test", "/__pcdn/speed/down?bytes=10485761").status == 400
    assert tq.req("plain.test", "/__pcdn/speed/down?bytes=-1").status == 400
    # also on tunnel-only hosts and through every site; the node tag is the same everywhere, no address
    r = tq.req("hog.test", "/__pcdn/speed/ping")
    assert r.status == 204 and r.headers["x-pcdn-node"] == tag
    assert "127.0.0.1" not in json.dumps(dict(r.headers))
    e = line_for(tq, "plain.test", "/__pcdn/speed/down?bytes=3000000")
    assert e["v"] == "ok" and e["b"] > 3000000 and e["tn"] == "" and e["tp"] == ""   # counted as normal traffic


CORS = {"access-control-allow-origin": "*", "access-control-expose-headers": "X-Pcdn-Node",
        "timing-allow-origin": "*"}


def req_from(env, src, host, path, method="GET", headers=None, body=None):
    """Like Edge.req, from another loopback address (its own per-IP speed-test budget)."""
    import http.client
    from test_nginx_e2e import Resp
    conn = http.client.HTTPConnection("127.0.0.1", env.port, timeout=10, source_address=(src, 0))
    try:
        conn.request(method, path, body=body, headers=dict({"Host": host, "Connection": "close"}, **(headers or {})))
        r = conn.getresponse()
        return Resp(r, r.read())
    finally:
        conn.close()


def test_speed_cross_origin_headers_and_cache_buster(tq):
    """The page runs in the WHMCS client area (another origin) and appends "&_=<random>"."""
    origin = {"Origin": "https://my.whmcs.example"}
    cases = [("GET", "/__pcdn/speed/ping?_=xyz", None, 204),
             ("GET", "/__pcdn/speed/down?bytes=200000&_=xyz", None, 200),
             ("GET", "/__pcdn/speed/down?_=xyz&bytes=20", None, 200),
             ("GET", "/__pcdn/speed/down?bytes=abc&_=1", None, 400),
             ("POST", "/__pcdn/speed/up?_=xyz", b"x" * 1000, 204),
             ("GET", "/__pcdn/speed/up?_=1", None, 405),
             ("OPTIONS", "/__pcdn/speed/ping?_=1", None, 204),
             ("OPTIONS", "/__pcdn/speed/down?bytes=10&_=1", None, None),
             ("OPTIONS", "/__pcdn/speed/up?_=1", None, 405)]
    for method, path, body, status in cases:
        h = dict(origin, **({"Content-Type": "text/plain"} if body else {}))
        r = req_from(tq, "127.0.0.2", "plain.test", path, method, headers=h, body=body)
        assert (r.status == status) if status else r.status < 500, (method, path, r.status)
        assert {k: r.headers.get(k) for k in CORS} == CORS, (method, path, dict(r.headers))
        assert r.headers.get("x-pcdn-node") == agent.node_tag("edge-test-1")
        if path.startswith("/__pcdn/speed/down?bytes=200000"):
            assert len(r.body) == 200000
    r = req_from(tq, "127.0.0.2", "plain.test", "/__pcdn/speed/up?_=1", "POST", body=b"u" * (10 * 1024 * 1024 + 1))
    assert r.status == 413 and r.headers.get("access-control-allow-origin") == "*"


def test_speed_upload(tq):
    body = b"u" * 2_000_000
    assert tq.req("plain.test", "/__pcdn/speed/up", "POST", body=body,
                  headers={"Content-Type": "application/octet-stream"}).status == 204
    assert tq.req("plain.test", "/__pcdn/speed/up", "POST", body=b"u" * (10 * 1024 * 1024 + 1)).status == 413
    assert tq.req("plain.test", "/__pcdn/speed/up").status == 405


def test_speed_skips_challenges_but_keeps_firewall_blocks(tq):
    # plain.test challenges every path and runs the WAF; the speed endpoints are not challenged
    assert tq.req("plain.test", "/").status == 403
    assert tq.req("plain.test", "/__pcdn/speed/ping?x=1%27%20or%20%271%27=%271",
                  headers={"User-Agent": "sqlmap/1.7"}).status == 204
    assert tq.req("plain.test", "/x?x=1%27%20or%20%271%27=%271", headers={"User-Agent": "sqlmap/1.7"}).status == 403
    r = tq.req("plain.test", "/__pcdn/speed/ping?m=evil", headers={"X-Evil": "yes"})
    assert r.status == 403
    assert line_for(tq, "plain.test", "m=evil")["v"] == "block:firewall:evil"


def test_speed_rate_limit_per_ip(tq):
    rs = [tq.req("plain.test", "/__pcdn/speed/down?bytes=1&_=x") for _ in range(30)]
    codes = [r.status for r in rs]
    assert codes[0] == 200 and 429 in codes
    limited = rs[codes.index(429)]
    assert {k: limited.headers.get(k) for k in CORS} == CORS   # a 429 is readable cross-origin too
