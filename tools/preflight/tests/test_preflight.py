"""tools/preflight/preflight.py against a fake controller and fake nameservers (SPEC §18.6)."""

import json
import struct

import pytest

from pf_testkit import (BUNDLE, KEY, FakeController, FakeDNS, closed_port, have_openssl, healthy_routes, iso_ago,
                        listening_port, make_cert, preflight, run_main)

needs_openssl = pytest.mark.skipif(not have_openssl(), reason="openssl CLI not installed")


@pytest.fixture
def key_env(monkeypatch):
    monkeypatch.setenv("PCDN_ADMIN_KEY", KEY)


@pytest.fixture
def tls(tmp_path):
    if not have_openssl():
        pytest.skip("openssl CLI not installed")
    return make_cert(tmp_path, 365)


def base_args(ctl, ns, pdns_port, ca=None):
    a = ["--controller", ctl.url, "--pdns-api", f"127.0.0.1:{pdns_port}", "--dns-timeout", "0.5",
         "--pdns-timeout", "0.5", "--timeout", "5"]
    for n in ns:
        a += ["--ns", n.spec]
    if ca:
        a += ["--ca-file", ca]
    return a


def rows(out_json):
    return {c["name"]: c for c in json.loads(out_json)["checks"]}


# ------------------------------------------------------------------------------------ OK path

def test_all_green_over_https(capsys, key_env, tls):
    ctx, ca = tls
    with FakeController(healthy_routes(), ctx) as ctl, FakeDNS() as ns1, FakeDNS() as ns2:
        rc, out = run_main(capsys, *base_args(ctl, [ns1, ns2], closed_port(), ca), "--strict")
    assert rc == 0, out
    assert "FAIL=0" in out and "WARN=0" in out
    for name in ("controller /healthz", "controller /healthz/deep", "database migrations", "backup age",
                 "node edge-1", "node edge-2", "dns serials match", "controller TLS", "metrics protected"):
        assert any(line.startswith(name) and " OK " in line for line in out.splitlines()), (name, out)
    assert "old-off" not in out          # disabled nodes are ignored
    assert "shop.test" in out            # sample zone = first active site
    assert KEY not in out
    # admin key only on /api/ requests, as a bearer header
    for method, path, auth in ctl.seen:
        assert (auth == "Bearer " + KEY) == path.startswith("/api/"), (method, path)
    assert ("POST", "/api/v1/alerts/test", "Bearer " + KEY) not in ctl.seen  # only with --alert-test


def test_json_output_and_alert_test(capsys, key_env, tls):
    ctx, ca = tls
    with FakeController(healthy_routes(), ctx) as ctl, FakeDNS() as ns1, FakeDNS() as ns2:
        rc, out = run_main(capsys, *base_args(ctl, [ns1, ns2], closed_port(), ca), "--zone", "example.org",
                           "--alert-test", "--json")
    doc = json.loads(out)
    assert rc == 0 and doc["exit_code"] == 0
    assert doc["summary"]["fail"] == 0 and doc["summary"]["warn"] == 0
    r = {c["name"]: c for c in doc["checks"]}
    assert r["alert test"]["status"] == "OK"
    assert r[f"dns {ns1.spec} SOA example.org"]["data"]["serial"] == 2026100201
    assert r["controller TLS"]["data"]["days_left"] >= 360
    assert r["node edge-1"]["data"]["bundle_version"] == BUNDLE
    assert ("POST", "/api/v1/alerts/test", "Bearer " + KEY) in ctl.seen
    assert KEY not in out


# ----------------------------------------------------------------------------------- WARN path

def test_warnings_exit_0_or_1_with_strict(capsys, key_env):
    routes = healthy_routes({
        ("GET", "/metrics"): (200, "# HELP pcdn_up\n"),
        ("GET", "/api/v1/edges"): lambda: (200, [
            {"id": 1, "name": "edge-1", "enabled": True, "last_seen_at": iso_ago(10), "bundle_version": "old-1"}]),
    })
    with FakeController(routes) as ctl, FakeDNS(serial=5) as ns1, FakeDNS(serial=6) as ns2:
        args = base_args(ctl, [ns1, ns2], closed_port())
        rc, out = run_main(capsys, *args, "--json")
        rc_strict, out_strict = run_main(capsys, *args, "--strict")
    assert rc == 0 and rc_strict == 1
    r = rows(out)
    assert r["metrics protected"]["status"] == "WARN"
    assert r["node edge-1"]["status"] == "WARN" and "old-1" in r["node edge-1"]["detail"]
    assert r["dns serials match"]["status"] == "WARN"
    assert r["controller TLS"]["status"] == "WARN"      # plain http controller URL
    assert "WARN" in out_strict and "FAIL=0" in out_strict


def test_degraded_deep_health_and_no_key_is_warn(capsys, monkeypatch):
    monkeypatch.delenv("PCDN_ADMIN_KEY", raising=False)
    routes = healthy_routes()
    deep = dict(routes[("GET", "/healthz/deep")][1], status="degraded",
                warnings=["no controller has run the scheduler recently"],
                alerts={"channels": [], "open": 0, "critical": 0})
    routes[("GET", "/healthz/deep")] = (200, deep)
    with FakeController(routes) as ctl:
        rc, out = run_main(capsys, "--controller", ctl.url, "--skip-pdns", "--json")
    r = rows(out)
    assert rc == 0
    assert r["controller /healthz/deep"]["status"] == "WARN" and "scheduler" in r["controller /healthz/deep"]["detail"]
    assert r["alert channels"]["status"] == "WARN"
    assert r["nodes"]["status"] == "WARN" and "PCDN_ADMIN_KEY" in r["nodes"]["detail"]
    assert r["dns SOA"]["status"] == "SKIP"
    assert all(auth is None for _, _, auth in ctl.seen)
    assert not any(p.startswith("/api/") for _, p, _ in ctl.seen)


def test_non_authoritative_answer_warns(capsys, key_env):
    with FakeController(healthy_routes()) as ctl, FakeDNS(aa=False) as ns1:
        rc, out = run_main(capsys, *base_args(ctl, [ns1], closed_port()), "--json")
    assert rc == 0
    assert rows(out)[f"dns {ns1.spec} SOA shop.test"]["status"] == "WARN"


# ----------------------------------------------------------------------------------- FAIL path

def test_failures_exit_2(capsys, key_env):
    routes = healthy_routes({
        ("GET", "/healthz/deep"): (200, {"status": "degraded", "warnings": ["database migrations are pending"],
                                         "database": {"ok": True, "revision": "0019", "head": "0020"},
                                         "backup": {"enabled": True, "last_success_age_hours": 50.0,
                                                    "failing": True}}),
        ("GET", "/api/v1/edges"): lambda: (200, [
            {"id": 1, "name": "edge-1", "enabled": True, "last_seen_at": iso_ago(20), "bundle_version": BUNDLE},
            {"id": 2, "name": "edge-stale", "enabled": True, "last_seen_at": iso_ago(3600), "bundle_version": BUNDLE},
            {"id": 3, "name": "edge-new", "enabled": True, "last_seen_at": None, "bundle_version": None}]),
    })
    with FakeController(routes) as ctl, FakeDNS(mode="refused") as ns1, FakeDNS(mode="silent") as ns2, \
            listening_port() as open_port:
        rc, out = run_main(capsys, *base_args(ctl, [ns1, ns2], open_port), "--json")
    r = rows(out)
    assert rc == 2 and json.loads(out)["exit_code"] == 2
    assert r["database migrations"]["status"] == "FAIL"
    assert r["backup age"]["status"] == "FAIL"
    assert r["node edge-1"]["status"] == "OK"
    assert r["node edge-stale"]["status"] == "FAIL" and "heartbeat" in r["node edge-stale"]["detail"]
    assert r["node edge-new"]["status"] == "FAIL"
    assert r[f"dns {ns1.spec} SOA shop.test"]["status"] == "FAIL" and "REFUSED" in r[f"dns {ns1.spec} SOA shop.test"]["detail"]
    assert r[f"dns {ns2.spec} SOA shop.test"]["status"] == "FAIL"
    assert r[f"pdns API 127.0.0.1:{open_port} closed"]["status"] == "FAIL"


def test_controller_down(capsys, key_env):
    rc, out = run_main(capsys, "--controller", f"http://127.0.0.1:{closed_port()}", "--skip-pdns", "--timeout", "2")
    assert rc == 2
    assert "controller /healthz" in out and "FAIL" in out


def test_bad_key_and_alert_test_without_channel(capsys, monkeypatch):
    monkeypatch.setenv("PCDN_ADMIN_KEY", "wrong-key-value")
    with FakeController(healthy_routes()) as ctl:
        rc, out = run_main(capsys, "--controller", ctl.url, "--skip-pdns", "--alert-test", "--json")
    r = rows(out)
    assert rc == 2
    assert r["nodes"]["status"] == "FAIL" and "401" in r["nodes"]["detail"]
    assert r["alert test"]["status"] == "FAIL"
    assert "wrong-key-value" not in out


def test_alert_test_409_fails(capsys, key_env):
    routes = healthy_routes({("POST", "/api/v1/alerts/test"): (409, {"detail": "no channel"})})
    with FakeController(routes) as ctl:
        rc, out = run_main(capsys, "--controller", ctl.url, "--skip-pdns", "--alert-test", "--json")
    assert rc == 2 and rows(out)["alert test"]["status"] == "FAIL"


def test_key_is_redacted_even_if_echoed(capsys, key_env):
    routes = healthy_routes({("GET", "/api/v1/edges"): (500, {"detail": f"boom Authorization: Bearer {KEY}"})})
    with FakeController(routes) as ctl:
        rc, out = run_main(capsys, "--controller", ctl.url, "--skip-pdns")
        rc_j, out_j = run_main(capsys, "--controller", ctl.url, "--skip-pdns", "--json")
    assert rc == 2 and rc_j == 2
    assert KEY not in out and KEY not in out_j and "***" in out


@needs_openssl
def test_certificate_expiring_soon(capsys, key_env, tmp_path):
    ctx, ca = make_cert(tmp_path, 3)
    with FakeController(healthy_routes(), ctx) as ctl:
        rc, out = run_main(capsys, "--controller", ctl.url, "--ca-file", ca, "--skip-pdns", "--json")
    r = rows(out)["controller TLS"]
    assert rc == 2 and r["status"] == "FAIL" and r["data"]["days_left"] <= 3
    with FakeController(healthy_routes(), ctx) as ctl:
        rc, out = run_main(capsys, "--controller", ctl.url, "--ca-file", ca, "--skip-pdns", "--json",
                           "--tls-fail-days", "1", "--tls-warn-days", "30")
    assert rc == 0 and rows(out)["controller TLS"]["status"] == "WARN"


@needs_openssl
def test_untrusted_certificate_fails(capsys, key_env, tmp_path):
    ctx, _ca = make_cert(tmp_path, 365)
    with FakeController(healthy_routes(), ctx) as ctl:
        rc, out = run_main(capsys, "--controller", ctl.url, "--skip-pdns", "--json", "--timeout", "3")
    r = rows(out)
    assert rc == 2
    assert r["controller TLS"]["status"] == "FAIL" and r["controller /healthz"]["status"] == "FAIL"


# ------------------------------------------------------------------------------ units / CLI rules

def test_key_never_from_argv():
    with pytest.raises(SystemExit):
        preflight.parse_args(["--controller", "http://x", "--key", "abc"])


def test_controller_required(monkeypatch):
    monkeypatch.delenv("PCDN_CONTROLLER_URL", raising=False)
    with pytest.raises(SystemExit):
        preflight.parse_args([])


def test_soa_parser_handles_compression_and_id():
    q = preflight.build_query(0x1234, "example.org")
    assert q[:2] == b"\x12\x34" and q.endswith(struct.pack(">HH", 6, 1))
    question = q[12:]
    rdata = b"\x03ns1\xc0\x0c" + b"\x02hm\xc0\x0c" + struct.pack(">IIIII", 42, 1, 2, 3, 4)
    rr = b"\xc0\x0c" + struct.pack(">HHIH", 6, 1, 60, len(rdata)) + rdata
    msg = struct.pack(">HHHHHH", 0x1234, 0x8400, 1, 1, 0, 0) + question + rr
    r = preflight.parse_soa_response(msg, 0x1234)
    assert r == {"rcode": "NOERROR", "aa": True, "tc": False, "serial": 42, "mname": "ns1.example.org"}
    with pytest.raises(preflight.DnsError):
        preflight.parse_soa_response(msg, 0x1235)
    with pytest.raises(preflight.DnsError):  # pointer loop
        preflight._read_name(b"\xc0\x00", 0)


def test_exit_code_rules():
    C = preflight.Check
    assert preflight.exit_code([C("a", "OK"), C("b", "SKIP")], True) == 0
    assert preflight.exit_code([C("a", "WARN")], False) == 0
    assert preflight.exit_code([C("a", "WARN")], True) == 1
    assert preflight.exit_code([C("a", "WARN"), C("b", "FAIL")], False) == 2
