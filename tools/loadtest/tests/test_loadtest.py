"""pcdn-loadtest against the local echo origin (fast: every run is ~1-2 s)."""

import asyncio
import json
import random
import subprocess

import pytest

from lt_testkit import LT_DIR, loadtest, origin_proc, run_cli, run_lt

import lt_proto


@pytest.fixture(scope="module")
def origin(tmp_path_factory):
    with origin_proc(tmp_path_factory.mktemp("origin")) as port:
        yield port


@pytest.fixture(scope="module")
def tls_origin(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("tlsorigin")
    key, crt = tmp / "k.pem", tmp / "c.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
                    "-subj", "/CN=lt.test", "-addext", "subjectAltName=DNS:lt.test", "-days", "2",
                    "-keyout", key, "-out", crt], check=True, capture_output=True)
    with origin_proc(tmp, "--tls-cert", crt, "--tls-key", key) as port:
        yield port, crt


def target(port):
    return ["--target", f"127.0.0.1:{port}", "--host", "lt.test"]


# ----------------------------------------------------------------- safety / CLI

def test_refuses_without_target():
    p = run_cli("ws", "--host", "lt.test")
    assert p.returncode == 2
    assert "--target" in p.stderr and "infrastructure you own" in p.stderr and "خودتان" in p.stderr


@pytest.mark.parametrize("bad", ["example.com:443", "1.2.3.4", "1.2.3.4:99999", "http://1.2.3.4:80"])
def test_refuses_non_ip_targets(bad):
    p = run_cli("http", "--target", bad, "--host", "lt.test")
    assert p.returncode == 2 and "IP" in p.stderr


def test_parse_target():
    assert loadtest.parse_target("203.0.113.10:443") == ("203.0.113.10", 443)
    assert loadtest.parse_target("[2001:db8::1]:8443") == ("2001:db8::1", 8443)
    with pytest.raises(ValueError):
        loadtest.parse_target("999.1.1.1:80")


def test_requires_host(origin):
    p = run_cli("ws", "--target", f"127.0.0.1:{origin}")
    assert p.returncode == 2 and "--host" in p.stderr


# ----------------------------------------------------------------- scenarios against origin.py

@pytest.mark.parametrize("scenario,extra", [
    ("ws", []), ("httpupgrade", []), ("grpc", []), ("h2", []),
    ("grpc", ["--streams-per-conn", "3"]),
    ("xhttp", ["--xhttp-mode", "packet-up"]), ("xhttp", ["--xhttp-mode", "stream-up"]),
])
def test_tunnel_scenarios(tmp_path, origin, scenario, extra):
    rep = run_lt(tmp_path, scenario, *target(origin), "--connections", 6, "--duration", 0.8, "--mbps", 3,
                 "--msg-size", 8192, *extra)
    r = rep["result"]
    assert rep["scenario"] == scenario and rep["tls"] is False
    assert r["errors"] == {} and r["error_rate"] == 0
    assert r["max_sustainable_connections"] == 6
    assert r["connections"]["opened"] == 6 and r["connections"]["peak_active"] == 6
    # 6 sessions x 3 Mbps up, echoed back: ~18 up + ~18 down
    assert 9 < r["throughput_mbps"]["up"] < 27, r["throughput_mbps"]
    assert 9 < r["throughput_mbps"]["down"] < 27, r["throughput_mbps"]
    assert r["latency_ms"]["rtt"]["n"] > 10 and r["latency_ms"]["rtt"]["p99"] < 1000
    assert r["messages"]["echoed"] >= r["messages"]["sent"] - 6 * 8
    assert rep["timeline"] and "raw" in rep


def test_unlimited_rate_and_big_messages(tmp_path, origin):
    # 256 KiB messages exercise HTTP/2 flow control (> 64k initial window) and WS 64-bit lengths
    for scenario in ("grpc", "ws"):
        rep = run_lt(tmp_path, scenario, *target(origin), "--connections", 2, "--duration", 1, "--mbps", 0,
                     "--msg-size", 262144, "--inflight", 4)
        r = rep["result"]
        assert r["errors"] == {} and r["throughput_mbps"]["total"] > 50, (scenario, r)


def test_http_scenario(tmp_path, origin):
    rep = run_lt(tmp_path, "http", *target(origin), "--path", "/bytes/4096", "--concurrency", 4,
                 "--duration", 1, "--rps", 200, "--miss-ratio", 0.5)
    r = rep["result"]
    q = r["requests"]
    assert r["errors"] == {} and q["status"].get("200", 0) == q["total"] > 50
    assert 120 < q["rps"] < 260, q          # paced at 200 rps
    assert r["throughput_mbps"]["down"] > 1 and r["latency_ms"]["request"]["p50"] is not None
    assert r["max_sustainable_connections"] == 4


def test_tls_alpn_and_verification(tmp_path, tls_origin):
    port, crt = tls_origin
    for scenario in ("grpc", "ws", "xhttp"):
        rep = run_lt(tmp_path, scenario, *target(port), "--tls", "--ca", crt, "--connections", 3,
                     "--duration", 1)
        assert rep["tls"] is True and rep["result"]["errors"] == {}, rep["result"]
    # wrong name -> verification error, unless --insecure is given explicitly
    rep = run_lt(tmp_path, "ws", "--target", f"127.0.0.1:{port}", "--host", "other.test", "--tls", "--ca", crt,
                 "--connections", 2, "--duration", 0.5, "--no-reconnect")
    assert rep["result"]["errors"] == {"tls_verify": 2} and rep["result"]["max_sustainable_connections"] == 0
    rep = run_lt(tmp_path, "ws", "--target", f"127.0.0.1:{port}", "--host", "other.test", "--tls", "--insecure",
                 "--connections", 2, "--duration", 0.5)
    assert rep["result"]["errors"] == {}


def test_error_classification(tmp_path, origin):
    import socket
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    dead = s.getsockname()[1]
    s.close()
    rep = run_lt(tmp_path, "ws", *target(dead), "--connections", 3, "--duration", 0.5, "--no-reconnect")
    assert rep["result"]["errors"] == {"connect_refused": 3}
    assert rep["result"]["error_rate"] == 1.0
    # TLS towards a plain port
    rep = run_lt(tmp_path, "grpc", *target(origin), "--tls", "--insecure", "--connections", 2, "--duration", 0.5,
                 "--no-reconnect", "--connect-timeout", 3)
    assert set(rep["result"]["errors"]) <= {"tls_error", "closed", "reset"} and rep["result"]["errors"]


def test_ramp_until_max_and_until_threshold(tmp_path, origin):
    rep = run_lt(tmp_path, "ramp", "--protocol", "ws", *target(origin), "--start", 4, "--step", 4, "--max", 12,
                 "--step-duration", 0.6)
    assert rep["stop_reason"] == "max_reached" and [s["target"] for s in rep["steps"]] == [4, 8, 12]
    assert all(s["pass"] for s in rep["steps"])
    assert rep["result"]["max_sustainable_connections"] == 12 and rep["result"]["capacity_hint_mbps"] >= 0
    # an impossible p99 bound fails the first step
    rep = run_lt(tmp_path, "ramp", "--protocol", "grpc", *target(origin), "--start", 2, "--max", 10,
                 "--step-duration", 0.6, "--max-p99-ms", 0.001)
    assert rep["stop_reason"] == "p99" and len(rep["steps"]) == 1
    assert rep["result"]["max_sustainable_connections"] == 0
    rep = run_lt(tmp_path, "ramp", "--protocol", "http", *target(origin), "--start", 2, "--step", 2, "--max", 4,
                 "--step-duration", 0.6, "--rps", 100)
    assert rep["stop_reason"] == "max_reached" and rep["steps"][-1]["rps"] > 30


def test_merge(tmp_path, origin):
    a = run_lt(tmp_path, "ws", *target(origin), "--connections", 3, "--duration", 0.8)
    b = run_lt(tmp_path, "ws", *target(origin), "--connections", 2, "--duration", 0.8)
    (tmp_path / "a.json").write_text(json.dumps(a))
    (tmp_path / "b.json").write_text(json.dumps(b))
    p = run_cli("merge", tmp_path / "a.json", tmp_path / "b.json", "--out", tmp_path / "m.json")
    assert p.returncode == 0, p.stderr
    m = json.loads((tmp_path / "m.json").read_text())
    assert m["merged_from"] == 2 and m["result"]["max_sustainable_connections"] == 5
    assert m["result"]["latency_ms"]["rtt"]["n"] == a["raw"]["rtt"]["n"] + b["raw"]["rtt"]["n"]
    assert "بیشینه‌ی اتصال پایدار: 5" in p.stdout


def test_persian_summary(tmp_path, origin):
    p = run_cli("httpupgrade", *target(origin), "--connections", 2, "--duration", 0.5, "--out", tmp_path / "x.json")
    assert p.returncode == 0, p.stderr
    for s in ("بیشینه‌ی اتصال پایدار", "پهنای باند (Mbps)", "p50=", "p95=", "p99=", "خطا"):
        assert s in p.stdout
    assert json.loads((tmp_path / "x.json").read_text())["result"]["max_sustainable_connections"] == 2


# ----------------------------------------------------------------- units

def test_hist_percentiles():
    h = loadtest.Hist()
    vals = [random.uniform(1, 100) for _ in range(20000)]
    for v in vals:
        h.add(v)
    vals.sort()
    for p in (50, 95, 99):
        exact = vals[int(len(vals) * p / 100) - 1]
        assert abs(h.pct(p) - exact) / exact < 0.02
    h2 = loadtest.Hist.from_raw(json.loads(json.dumps(h.raw())))
    assert h2.n == h.n and h2.pct(99) == h.pct(99)


def test_msg_parser_split_and_grpc():
    pad = bytes(range(256)) * 64
    for grpc in (False, True):
        stream = b"".join(lt_proto.build_msg(100 + i, i, pad, grpc) for i in range(5))
        p = lt_proto.MsgParser(grpc)
        got = []
        for i in range(0, len(stream), 7):
            got += p.feed(stream[i:i + 7])
        assert [s for _, s in got] == [0, 1, 2, 3, 4]


def test_h2_small_window_flow_control():
    """Client and server with a 64 KiB window still move 1 MiB both ways (WINDOW_UPDATE paths)."""
    async def go():
        async def on_conn(r, w):
            await r.readexactly(len(lt_proto.PREFACE))

            async def echo(s):
                s.send_headers(None, raw=b"\x88")
                while (d := await s.recv()) is not None:
                    await s.send(d)
                s.send_headers([("grpc-status", "0")], end=True)
            c = lt_proto.H2Conn(r, w, client=False, on_stream=echo, window=65535)
            await c.start()
            await c._task
        srv = await asyncio.start_server(on_conn, "127.0.0.1", 0)
        port = srv.sockets[0].getsockname()[1]
        r, w = await asyncio.open_connection("127.0.0.1", port)
        c = lt_proto.H2Conn(r, w, client=True, window=65535)
        await c.start()
        s = c.open_stream([(":method", "POST"), (":scheme", "http"), (":path", "/x"), (":authority", "a")])
        assert await asyncio.wait_for(s.wait_headers(), 5) == 200
        data = bytes(random.getrandbits(8) for _ in range(1 << 20))
        sender = asyncio.create_task(s.send(data, end=True))
        got = bytearray()
        while (d := await asyncio.wait_for(s.recv(), 5)) is not None:
            got += d
        await sender
        assert bytes(got) == data
        await c.close()
        srv.close()
    asyncio.run(go())


def test_h2_status_decoding():
    assert lt_proto.h2_status(b"\x88") == 200
    assert lt_proto.h2_status(b"\x48\x03429") == 429
    assert lt_proto.h2_status(b"\x08\x03503") == 503
    assert lt_proto.h2_status(b"") is None


def test_no_third_party_imports():
    for f in ("loadtest.py", "lt_proto.py", "origin.py"):
        text = (LT_DIR / f).read_text()
        assert "import h2" not in text and "import aiohttp" not in text
