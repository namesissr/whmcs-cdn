"""pcdn-loadtest through a REAL edge: nginx + njs + the agent's rendered config (edge/tests harness),
with tools/loadtest/origin.py as the site origin and as every tunnel path's origin.

Skipped when nginx or its dynamic modules / mmdb_writer are missing (same rule as edge/tests), or
when PCDN_LOADTEST_NO_EDGE=1. Runs are ~1 s each so the whole module stays around 15 s.
"""

import os
import pathlib
import shutil
import subprocess
import sys

import pytest

from lt_testkit import REPO, origin_proc, run_lt

EDGE_TESTS = REPO / "edge" / "tests"
sys.path.insert(0, str(EDGE_TESTS))

try:
    from conftest import modules_available, nginx_conf  # edge/tests/conftest.py
    _EDGE_OK = shutil.which("nginx") is not None and modules_available()
except ImportError:  # pragma: no cover
    _EDGE_OK = False

pytestmark = pytest.mark.skipif(not _EDGE_OK or os.environ.get("PCDN_LOADTEST_NO_EDGE") == "1",
                                reason="nginx with the edge modules not installed (or PCDN_LOADTEST_NO_EDGE=1)")

PATHS = {"ws": "/lt-ws", "httpupgrade": "/lt-hu", "xhttp": "/lt-xh", "grpc": "/lt.Tunnel", "h2": "/lt-h2"}


@pytest.fixture(scope="module")
def edge(tmp_path_factory):
    from test_nginx_e2e import Edge, agent, free_port, make_mmdb, self_signed, site, wait_for

    tmp = tmp_path_factory.mktemp("ltedge")
    try:
        make_mmdb(tmp / "country.mmdb")
    except ImportError:
        pytest.skip("mmdb_writer/netaddr not installed")
    with origin_proc(tmp, "--max-age", "600") as oport:
        cfg = dict(agent.DEFAULTS)
        cfg.update({
            "NGINX_DIR": str(tmp / "pcdn"), "CACHE_DIR": str(tmp / "cache"), "STATE_FILE": str(tmp / "state.json"),
            "ACCESS_LOG": str(tmp / "access.log"), "PAGES_DIR": str(agent.HERE) + "/pages",
            # the test origin is on loopback: allow it past the edge's origin guard, and keep the agent
            # off the host's real L4 / functions usage logs
            "ORIGIN_PRIVATE_ALLOW": "127.0.0.0/8 ::1/128",
            "L4_ACCESS_LOG": str(tmp / "l4.log"), "FN_USAGE_LOG": str(tmp / "fn-usage.log"),
            "NJS_FILE": str(agent.HERE) + "/njs/pcdn.js", "BASE_TEMPLATE": str(agent.HERE) + "/nginx/pcdn-base.conf",
            "GEOIP_DB": str(tmp / "country.mmdb"), "RESOLVER": "127.0.0.1", "NGINX_USER": "root",
            "LISTEN_IPV6": "no", "HTTP_PORT": str(free_port()), "HTTPS_PORT": str(free_port()),
            "RESIZE_PORT": str(free_port()), "DICT_SIZE": "4m",
        })
        conf = nginx_conf(tmp, cfg)
        cfg["NGINX_TEST_CMD"] = f"nginx -t -q -c {conf}"
        cfg["NGINX_RELOAD_CMD"] = f"nginx -s reload -c {conf}"
        cert, key = self_signed(tmp, "lt.test")
        O = {"address": "127.0.0.1", "port": oport}
        TO = dict(O, tls=False, sni=None, verify=False)

        def tunnel(**kw):
            t = {"enabled": True, "idle_timeout": 120, "per_connection_mbps": 0, "max_connections_per_ip": 0,
                 "allowed_countries": [], "fallback": "origin", "max_connections": 0,
                 "paths": [{"id": p.strip("/").replace(".", "-").lower(), "path": path, "protocol": p,
                            "origin": TO, "pool": None} for p, path in PATHS.items()]}
            t.update(kw)
            return t
        cache = {"enabled": True, "level": "standard", "edge_ttl": 3600, "browser_ttl": 0, "ignore_query": False,
                 "bypass_cookies": [], "always_online": True}
        sites = [site(301, "lt.test", O, ssl={"cert": cert, "key": key}, cache=cache, tunnel=tunnel()),
                 site(302, "lim.test", O, ssl={"cert": cert, "key": key}, tunnel=tunnel(max_connections_per_ip=2))]
        agent.bootstrap(cfg)
        p = subprocess.run(["nginx", "-c", str(conf)], capture_output=True, text=True)
        assert p.returncode == 0, p.stderr
        e = Edge(cfg, conf)
        try:
            assert wait_for(lambda: e.req("unknown.test", "/__pcdn/health").status == 200)
            err = agent.apply_config({"sites": sites}, cfg)
            assert err is None, err
            assert wait_for(lambda: e.req("lt.test", "/bytes/10").status == 200)
            e.tmp = tmp
            yield e
        finally:
            subprocess.run(["nginx", "-s", "stop", "-c", str(conf)], capture_output=True)


def tls_target(e, host="lt.test"):
    # --insecure: the harness uses a throw-away self-signed certificate
    return ["--target", f"127.0.0.1:{e.sport}", "--host", host, "--tls", "--insecure"]


@pytest.mark.parametrize("scenario,path,extra", [
    ("ws", "/lt-ws", []), ("httpupgrade", "/lt-hu", []), ("grpc", "/lt.Tunnel/Tun", ["--streams-per-conn", "2"]),
    ("h2", "/lt-h2", []), ("xhttp", "/lt-xh", []), ("xhttp", "/lt-xh", ["--xhttp-mode", "stream-up"]),
])
def test_tunnels_through_edge(tmp_path, edge, scenario, path, extra):
    rep = run_lt(tmp_path, scenario, *tls_target(edge), "--path", path, "--connections", 4, "--duration", 1,
                 "--mbps", 2, "--msg-size", 8192, *extra)
    r = rep["result"]
    assert rep["tls"] is True
    assert r["errors"] == {}, r["errors"]
    assert r["max_sustainable_connections"] == 4
    assert r["throughput_mbps"]["down"] > 3 and r["latency_ms"]["rtt"]["n"] > 10


def test_ws_over_plain_http_port(tmp_path, edge):
    rep = run_lt(tmp_path, "ws", "--target", f"127.0.0.1:{edge.port}", "--host", "lt.test", "--path", "/lt-ws",
                 "--connections", 3, "--duration", 0.8)
    assert rep["tls"] is False and rep["result"]["errors"] == {}


def test_http_cache_hits_through_edge(tmp_path, edge):
    run_lt(tmp_path, "http", *tls_target(edge), "--path", "/bytes/8192", "--concurrency", 2, "--duration", 0.5,
           "--miss-ratio", 0)  # warm the cache
    rep = run_lt(tmp_path, "http", *tls_target(edge), "--path", "/bytes/8192", "--concurrency", 4, "--duration", 1,
                 "--miss-ratio", 0.2, "--rps", 300)
    q = rep["result"]["requests"]
    assert rep["result"]["errors"] == {} and q["status"].get("200") == q["total"]
    assert q["cache"].get("HIT", 0) > 0 and q["cache"].get("MISS", 0) > 0, q["cache"]
    assert 0.6 < q["hit_ratio"] < 0.95, q


def test_limit_errors_are_classified(tmp_path, edge):
    # lim.test allows 2 tunnel sessions per IP: the rest get 429 [limit]
    rep = run_lt(tmp_path, "ws", *tls_target(edge, "lim.test"), "--path", "/lt-ws", "--connections", 5,
                 "--duration", 0.8, "--no-reconnect", "--open-rate", 1000)
    r = rep["result"]
    assert r["errors"] == {"http_429": 3}, r["errors"]
    assert r["max_sustainable_connections"] == 2


def test_wrong_protocol_is_classified(tmp_path, edge):
    # HTTPUpgrade / gRPC client on a path whose protocol differs, and gRPC on the plain port
    rep = run_lt(tmp_path, "grpc", "--target", f"127.0.0.1:{edge.port}", "--host", "lt.test",
                 "--path", "/lt.Tunnel/Tun", "--connections", 1, "--duration", 0.5, "--no-reconnect",
                 "--handshake-timeout", 3)
    assert rep["result"]["connections"]["opened"] == 0 and rep["result"]["errors"]
    rep = run_lt(tmp_path, "xhttp", *tls_target(edge), "--path", "/lt-ws", "--connections", 1, "--duration", 0.5,
                 "--no-reconnect")
    assert rep["result"]["errors"] == {"http_426": 1}


def test_ramp_through_edge(tmp_path, edge):
    rep = run_lt(tmp_path, "ramp", "--protocol", "grpc", *tls_target(edge), "--path", "/lt.Tunnel/Tun",
                 "--start", 4, "--step", 4, "--max", 8, "--step-duration", 0.8)
    assert rep["stop_reason"] == "max_reached", rep["steps"]
    assert rep["result"]["max_sustainable_connections"] == 8
    assert pathlib.Path(edge.cfg["ACCESS_LOG"]).exists()
