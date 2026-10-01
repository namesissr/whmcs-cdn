"""Multi-address edges & health-based failover (SPEC §12): address CRUD, per-address probing,
health-driven DNS advertisement with fail-open, and the per-address alert."""

import threading
from datetime import timedelta
from http.server import BaseHTTPRequestHandler, HTTPServer
from types import SimpleNamespace

import pytest

from app import alerts, dnsbuild, probe
from app.config import settings
from app.db import SessionLocal
from app.models import Edge, EdgeAddress, utcnow


def _edge(db, name="ir1", ipv4="5.160.1.1", ipv6=None, region="home", **kw):
    e = Edge(name=name, ipv4=ipv4, ipv6=ipv6, region=region, token_hash=name, enabled=True, **kw)
    db.add(e)
    db.commit()
    return e


def _add(db, edge, family=4, ip="5.160.2.2", **kw):
    a = EdgeAddress(edge_id=edge.id, family=family, ip=ip, **kw)
    db.add(a)
    db.commit()
    return a


# ------------------------------------------------------------------ health server / probe redirect

class _HealthHandler(BaseHTTPRequestHandler):
    body = b"ok\n"
    code = 200

    def do_GET(self):
        self.send_response(type(self).code)
        self.end_headers()
        self.wfile.write(type(self).body)

    def log_message(self, *a):
        pass


@pytest.fixture()
def health_server():
    handler = type("H", (_HealthHandler,), {"body": b"ok\n", "code": 200})
    srv = HTTPServer(("127.0.0.1", 0), handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield handler, srv.server_address[1]
    srv.shutdown()


@pytest.fixture()
def probe_map(monkeypatch):
    """Redirect every address probe (primary AND additional) by IP. Patching address_url is
    enough: probe_url delegates to it. Unmapped IPs point at a closed port and fail."""
    by_ip: dict[str, str] = {}

    def fake(ip, family):
        return f"http://{by_ip.get(ip, '127.0.0.1:1')}/__pcdn/health"

    monkeypatch.setattr(probe, "address_url", fake)
    return by_ip


# ------------------------------------------------------------------ admin API: address CRUD (§12.4)

def _add_edge(client, name="ir1", ipv4="5.160.1.10", ipv6=None, region="home"):
    body = {"name": name, "ipv4": ipv4, "region": region}
    if ipv6:
        body["ipv6"] = ipv6
    r = client.post("/api/v1/edges", json=body)
    assert r.status_code == 201, r.text
    return r.json()


def test_address_crud(client):
    eid = _add_edge(client)["id"]

    r = client.post(f"/api/v1/edges/{eid}/addresses", json={"family": 4, "ip": "5.160.1.20", "label": "second"})
    assert r.status_code == 201, r.text
    a = r.json()["address"]
    assert a["family"] == 4 and a["ip"] == "5.160.1.20" and a["label"] == "second"
    assert a["enabled"] is True and a["advertised"] is True  # never probed -> advertised
    aid = a["id"]

    # GET: primary + additional with health, per-family advertised counts
    lst = client.get(f"/api/v1/edges/{eid}/addresses").json()
    assert [p["ip"] for p in lst["primary"]] == ["5.160.1.10"]
    assert lst["primary"][0]["primary"] is True
    assert [x["ip"] for x in lst["additional"]] == ["5.160.1.20"]
    assert lst["advertised"] == {"4": 2, "6": 0}

    # edge_to_dict carries addresses + advertised counts
    ed = next(x for x in client.get("/api/v1/edges").json() if x["id"] == eid)
    assert [x["ip"] for x in ed["addresses"]] == ["5.160.1.20"]
    assert ed["advertised"] == {"4": 2, "6": 0}

    # rename + disable (maintenance) -> not advertised
    r = client.patch(f"/api/v1/edges/{eid}/addresses/{aid}", json={"label": "renamed", "enabled": False})
    assert r.status_code == 200
    assert r.json()["address"]["label"] == "renamed"
    assert r.json()["address"]["enabled"] is False and r.json()["address"]["advertised"] is False

    # change the IP (validated), re-enable
    r = client.patch(f"/api/v1/edges/{eid}/addresses/{aid}", json={"ip": "5.160.1.30", "enabled": True})
    assert r.status_code == 200 and r.json()["address"]["ip"] == "5.160.1.30"

    # delete
    assert client.delete(f"/api/v1/edges/{eid}/addresses/{aid}").json()["ok"] is True
    assert client.get(f"/api/v1/edges/{eid}/addresses").json()["additional"] == []


def test_address_duplicate_rejection(client):
    e1 = _add_edge(client, name="a", ipv4="5.160.1.10")
    e2 = _add_edge(client, name="b", ipv4="5.160.1.11")
    eid = e1["id"]
    # duplicate of another edge's primary, and of own primary
    assert client.post(f"/api/v1/edges/{eid}/addresses", json={"family": 4, "ip": "5.160.1.11"}).status_code == 409
    assert client.post(f"/api/v1/edges/{eid}/addresses", json={"family": 4, "ip": "5.160.1.10"}).status_code == 409
    # a fresh additional, then a duplicate of it on another edge
    assert client.post(f"/api/v1/edges/{eid}/addresses", json={"family": 4, "ip": "5.160.1.50"}).status_code == 201
    assert client.post(f"/api/v1/edges/{e2['id']}/addresses",
                       json={"family": 4, "ip": "5.160.1.50"}).status_code == 409
    # editing an address onto another address is rejected too
    aid = client.get(f"/api/v1/edges/{eid}/addresses").json()["additional"][0]["id"]
    assert client.patch(f"/api/v1/edges/{eid}/addresses/{aid}",
                        json={"ip": "5.160.1.11"}).status_code == 409


def test_address_validation_and_404(client):
    eid = _add_edge(client)["id"]
    # family / ip mismatch
    assert client.post(f"/api/v1/edges/{eid}/addresses", json={"family": 4, "ip": "2a01:4f8::1"}).status_code == 422
    assert client.post(f"/api/v1/edges/{eid}/addresses", json={"family": 6, "ip": "5.160.1.99"}).status_code == 422
    # malformed and non-public addresses
    assert client.post(f"/api/v1/edges/{eid}/addresses", json={"family": 4, "ip": "not-an-ip"}).status_code == 422
    assert client.post(f"/api/v1/edges/{eid}/addresses", json={"family": 4, "ip": "10.0.0.5"}).status_code == 422
    # invalid family value -> pydantic 422
    assert client.post(f"/api/v1/edges/{eid}/addresses", json={"family": 5, "ip": "5.160.1.99"}).status_code == 422
    # empty patch -> 422
    aid = client.post(f"/api/v1/edges/{eid}/addresses",
                      json={"family": 4, "ip": "5.160.1.60"}).json()["address"]["id"]
    assert client.patch(f"/api/v1/edges/{eid}/addresses/{aid}", json={}).status_code == 422
    # 404s
    assert client.post("/api/v1/edges/9999/addresses", json={"family": 4, "ip": "5.160.1.98"}).status_code == 404
    assert client.patch(f"/api/v1/edges/{eid}/addresses/9999", json={"label": "x"}).status_code == 404
    assert client.delete(f"/api/v1/edges/{eid}/addresses/9999").status_code == 404


# ------------------------------------------------------------------ per-address probing (§12.2)

def test_probe_sets_per_address_health(client, health_server, probe_map):
    _, port = health_server
    with SessionLocal() as db:
        e = _edge(db, ipv4="5.160.1.1")
        a_ok = _add(db, e, family=4, ip="5.160.2.2")
        a_bad = _add(db, e, family=4, ip="5.160.3.3")
        probe_map["5.160.1.1"] = f"127.0.0.1:{port}"  # primary healthy
        probe_map["5.160.2.2"] = f"127.0.0.1:{port}"  # additional healthy
        # a_bad unmapped -> connection refused -> fails
        probe.run(db)
        db.refresh(e), db.refresh(a_ok), db.refresh(a_bad)
        assert e.probe_ok is True  # primary answered (edge-level unchanged)
        assert a_ok.probe_ok is True and a_ok.probe_fail == 0 and a_ok.probe_ms is not None
        assert a_ok.probe_at is not None and a_ok.probe_error is None
        assert a_bad.probe_ok is False and a_bad.probe_fail == 1 and "IPv4" in a_bad.probe_error


def test_disabled_additional_address_not_probed(client, health_server, probe_map):
    _, port = health_server
    with SessionLocal() as db:
        e = _edge(db, ipv4="5.160.1.1")
        a = _add(db, e, family=4, ip="5.160.2.2", enabled=False)
        probe_map["5.160.1.1"] = f"127.0.0.1:{port}"
        probe.run(db)
        db.refresh(a)
        assert a.probe_ok is None and a.probe_fail == 0 and a.probe_at is None  # skipped


# ------------------------------------------------------------------ DNS advertisement / withdrawal / fail-open (§12.3)

def test_dns_advertises_additional_addresses(client):
    with SessionLocal() as db:
        e = _edge(db, ipv4="5.160.1.1", region="global")
        _add(db, e, family=4, ip="5.160.2.2")
        db.refresh(e)
        _, g = dnsbuild.edge_pools([e], 4)
        assert g == ["5.160.1.1", "5.160.2.2"]  # primary + healthy (unprobed) additional


def test_dns_withdraws_after_threshold_and_restores(client, health_server, probe_map, monkeypatch):
    monkeypatch.setattr(settings, "probe_fail_checks", 3)
    # this test covers the per-address probe debounce; the F26 withdrawal budget (which for a tiny
    # 2-address pool would keep both) is exercised separately, so disable it here
    monkeypatch.setattr(settings, "probe_withdraw_max_fraction", 1.0)
    _, port = health_server
    with SessionLocal() as db:
        e = _edge(db, ipv4="5.160.1.1", region="global")
        a = _add(db, e, family=4, ip="5.160.2.2")
        probe_map["5.160.1.1"] = f"127.0.0.1:{port}"  # primary always healthy
        probe_map["5.160.2.2"] = f"127.0.0.1:{port}"  # additional healthy at first
        probe.run(db)
        db.refresh(a)
        assert a.probe_ok is True
        assert "5.160.2.2" in dnsbuild.edge_pools([e], 4)[1]

        # one/two transient failures do NOT withdraw it (debounce until PROBE_FAIL_CHECKS)
        del probe_map["5.160.2.2"]
        probe.run(db)
        db.refresh(a)
        assert a.probe_fail == 1 and "5.160.2.2" in dnsbuild.edge_pools([e], 4)[1]
        probe.run(db)
        db.refresh(a)
        assert a.probe_fail == 2 and "5.160.2.2" in dnsbuild.edge_pools([e], 4)[1]

        # third failure crosses the threshold -> withdrawn (primary still advertised)
        probe.run(db)
        db.refresh(a)
        assert a.probe_fail == 3 and a.probe_ok is False
        g = dnsbuild.edge_pools([e], 4)[1]
        assert "5.160.2.2" not in g and g == ["5.160.1.1"]

        # recovery on the next healthy probe restores it
        probe_map["5.160.2.2"] = f"127.0.0.1:{port}"
        probe.run(db)
        db.refresh(a)
        assert a.probe_ok is True and a.probe_fail == 0
        assert "5.160.2.2" in dnsbuild.edge_pools([e], 4)[1]


def test_dns_fail_open_when_every_address_failing(client, probe_map, monkeypatch):
    """The zone is never emptied by health state: if withdrawal would empty a pool, the known
    addresses are advertised anyway (SPEC §12.3)."""
    monkeypatch.setattr(settings, "probe_fail_checks", 3)
    with SessionLocal() as db:
        e = _edge(db, ipv4="5.160.1.1", region="home")
        a = _add(db, e, family=4, ip="5.160.2.2")
        # nothing mapped -> every probe fails
        for _ in range(3):
            probe.run(db)
        db.refresh(e), db.refresh(a)
        assert e.probe_ok is False and e.probe_fail == 3
        assert a.probe_ok is False and a.probe_fail == 3
        # per-address, both are health-withdrawn ...
        assert not dnsbuild.address_advertised(True, e.probe_ok, e.probe_fail)
        assert not dnsbuild.address_advertised(a.enabled, a.probe_ok, a.probe_fail)
        # ... but the pool still advertises them (fail-open), never empty
        home, _ = dnsbuild.edge_pools([e], 4)
        assert set(home) == {"5.160.1.1", "5.160.2.2"}


def test_disabled_address_withdrawn_immediately_and_not_failed_open(client):
    with SessionLocal() as db:
        e = _edge(db, ipv4="5.160.1.1", region="global")
        a = _add(db, e, family=4, ip="5.160.2.2", enabled=True)
        db.refresh(e)
        assert "5.160.2.2" in dnsbuild.edge_pools([e], 4)[1]
        a.enabled = False
        db.commit()
        db.refresh(e)
        assert dnsbuild.edge_pools([e], 4)[1] == ["5.160.1.1"]  # gone immediately

        # a family whose only address is operator-disabled stays empty: fail-open never
        # resurrects a disabled address (only health-withdrawn ones)
        e6 = _edge(db, name="e6", ipv4="5.160.9.9", ipv6=None, region="global")
        _add(db, e6, family=6, ip="2a01:4f8::1", enabled=False)
        db.refresh(e6)
        assert dnsbuild.edge_pools([e6], 6) == ([], [])


def test_build_rrsets_includes_additional_address(client):
    site = SimpleNamespace(domain="ex.com", records=[
        SimpleNamespace(name="@", type="A", content="1.2.3.4", proxied=True, priority=None, ttl=300)])
    with SessionLocal() as db:
        e = _edge(db, ipv4="5.160.1.1", region="global")
        _add(db, e, family=4, ip="5.160.2.2")
        db.refresh(e)
        rr = {(r["name"], r["type"]): r for r in dnsbuild.build_rrsets(site, [e])}
        a_lua = next(c["content"] for c in rr[("ex.com.", "LUA")]["records"] if c["content"].startswith('A "'))
    assert "5.160.1.1" in a_lua and "5.160.2.2" in a_lua


# ------------------------------------------------------------------ per-address alert (§12.2)

def test_edge_address_down_alert_raise_and_resolve(client, alert_settings, monkeypatch):
    monkeypatch.setattr(settings, "probe_fail_checks", 3)
    now = utcnow()
    with SessionLocal() as db:
        e = _edge(db, ipv4="5.160.1.1", last_seen_at=now)  # heartbeating
        a = _add(db, e, family=4, ip="5.160.2.2")
        a.probe_ok, a.probe_fail, a.probe_error = False, 3, "IPv4: HTTP 500"
        db.commit()
        alerts.check_edge_address_probe(db)
        conds = {c["key"]: c for c in alerts.open_alerts(db)}
        key = f"edge_address_down:{a.id}"
        assert key in conds and "5.160.2.2" in conds[key]["text"]
        # the primary keeps the separate edge_probe alert; this check does not raise it
        assert f"edge_probe:{e.id}" not in conds

        # recovery resolves it
        a.probe_ok, a.probe_fail, a.probe_error = True, 0, None
        db.commit()
        alerts.check_edge_address_probe(db)
        assert key not in {c["key"] for c in alerts.open_alerts(db)}


def test_edge_address_down_not_raised_when_offline_or_disabled(client, alert_settings, monkeypatch):
    monkeypatch.setattr(settings, "probe_fail_checks", 3)
    monkeypatch.setattr(settings, "edge_offline_seconds", 180)
    now = utcnow()
    with SessionLocal() as db:
        # node has no heartbeat -> edge_offline covers it, no per-address alert
        off = _edge(db, name="off", ipv4="5.160.1.1", last_seen_at=now - timedelta(seconds=600))
        a1 = _add(db, off, family=4, ip="5.160.2.2")
        a1.probe_ok, a1.probe_fail = False, 5
        # heartbeating node but the failing address is disabled (maintenance)
        on = _edge(db, name="on", ipv4="5.160.1.9", last_seen_at=now)
        a2 = _add(db, on, family=4, ip="5.160.3.3", enabled=False)
        a2.probe_ok, a2.probe_fail = False, 5
        db.commit()
        alerts.check_edge_address_probe(db)
        keys = {c["key"] for c in alerts.open_alerts(db)}
        assert f"edge_address_down:{a1.id}" not in keys
        assert f"edge_address_down:{a2.id}" not in keys
