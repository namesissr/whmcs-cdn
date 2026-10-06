"""WAVE 1 reliability (SPEC §8): synthetic edge probes, public status, incidents."""

import threading
from datetime import timedelta
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from app import alerts, probe
from app.config import settings
from app.db import SessionLocal
from app.models import Edge, utcnow


def _edge(db, name="ir1", **kw):
    e = Edge(name=name, ipv4=kw.pop("ipv4", "127.0.0.1"), region=kw.pop("region", "home"),
             token_hash=name, enabled=True, **kw)
    db.add(e)
    db.commit()
    return e


class _HealthHandler(BaseHTTPRequestHandler):
    body = b"ok\n"
    code = 200

    def do_GET(self):
        self.send_response(type(self).code)
        self.end_headers()
        self.wfile.write(type(self).body)

    def log_message(self, *a):  # silence
        pass


@pytest.fixture()
def health_server():
    """A tiny stand-in edge that answers /__pcdn/health on 127.0.0.1."""
    handler = type("H", (_HealthHandler,), {"body": b"ok\n", "code": 200})
    srv = HTTPServer(("127.0.0.1", 0), handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    port = srv.server_address[1]
    yield handler, port
    srv.shutdown()


@pytest.fixture()
def probe_to(monkeypatch):
    """Point probe.probe_url at a chosen host:port (per address family)."""
    hosts: dict[str, str] = {}

    def fake_url(edge, family):
        return f"http://{hosts.get(family, '127.0.0.1:0')}/__pcdn/health"

    monkeypatch.setattr(probe, "probe_url", fake_url)
    return hosts


# ------------------------------------------------------------------ probes

def test_probe_success(client, health_server, probe_to):
    handler, port = health_server
    probe_to["4"] = f"127.0.0.1:{port}"
    with SessionLocal() as db:
        e = _edge(db)
        probe.run(db)
        db.refresh(e)
        assert e.probe_ok is True and e.probe_fail == 0
        assert e.probe_ms is not None and e.probe_at is not None and e.probe_error is None


def test_probe_failure_increments_counter(client, health_server, probe_to):
    handler, port = health_server
    handler.code = 500  # node heartbeats but serves errors
    probe_to["4"] = f"127.0.0.1:{port}"
    with SessionLocal() as db:
        e = _edge(db)
        for i in range(3):
            probe.run(db)
            db.refresh(e)
            assert e.probe_ok is False and e.probe_fail == i + 1
            assert "IPv4" in e.probe_error and "500" in e.probe_error
        # recovery resets the counter
        handler.code = 200
        probe.run(db)
        db.refresh(e)
        assert e.probe_ok is True and e.probe_fail == 0 and e.probe_error is None


def test_probe_body_must_start_with_ok(client, health_server, probe_to):
    handler, port = health_server
    handler.body = b"nope"
    probe_to["4"] = f"127.0.0.1:{port}"
    with SessionLocal() as db:
        e = _edge(db)
        probe.run(db)
        db.refresh(e)
        assert e.probe_ok is False and e.probe_fail == 1


def test_probe_ipv6_either_family_ok(client, health_server, probe_to, monkeypatch):
    handler, port = health_server
    monkeypatch.setattr(settings, "probe_ipv6", True)
    # IPv4 points nowhere (connection refused), IPv6 answers -> edge counts as OK
    probe_to["4"] = "127.0.0.1:1"       # closed port
    probe_to["6"] = f"127.0.0.1:{port}"  # the working server stands in for the v6 address
    with SessionLocal() as db:
        e = _edge(db, ipv6="2a01:4f8::1")
        probe.run(db)
        db.refresh(e)
        assert e.probe_ok is True and e.probe_fail == 0
        # the failing family is still recorded
        assert e.probe_error and "IPv4" in e.probe_error and "IPv6" not in e.probe_error


# ------------------------------------------------------------------ probe alert

def test_probe_alert_reporting_but_broken(client, alert_settings, monkeypatch):
    monkeypatch.setattr(settings, "probe_fail_checks", 3)
    now = utcnow()
    with SessionLocal() as db:
        e = _edge(db, last_seen_at=now)  # heartbeating
        e.probe_ok = False
        e.probe_error = "IPv4: HTTP 500"
        e.probe_fail = 3
        db.commit()
        alerts.check_edge_probe(db)
        conds = {c["key"]: c for c in alerts.open_alerts(db)}
        assert f"edge_probe:{e.id}" in conds
        assert "گزارش می‌فرستد" in conds[f"edge_probe:{e.id}"]["text"]
        assert "HTTP 500" in conds[f"edge_probe:{e.id}"]["text"]
        # a successful probe resolves it
        e.probe_ok = True
        e.probe_fail = 0
        db.commit()
        alerts.check_edge_probe(db)
        assert f"edge_probe:{e.id}" not in {c["key"] for c in alerts.open_alerts(db)}


def test_probe_alert_not_raised_when_offline(client, alert_settings, monkeypatch):
    monkeypatch.setattr(settings, "probe_fail_checks", 3)
    monkeypatch.setattr(settings, "edge_offline_seconds", 180)
    now = utcnow()
    with SessionLocal() as db:
        e = _edge(db, last_seen_at=now - timedelta(seconds=600))  # no heartbeat
        e.probe_ok = False
        e.probe_fail = 5
        db.commit()
        alerts.check_edge_probe(db)
        # edge_offline covers it; no edge_probe alert
        assert f"edge_probe:{e.id}" not in {c["key"] for c in alerts.open_alerts(db)}


def test_edge_object_and_healthz_probe(client, monkeypatch):
    monkeypatch.setattr(settings, "probe_fail_checks", 3)
    now = utcnow()
    with SessionLocal() as db:
        e = _edge(db, last_seen_at=now)
        e.probe_ok, e.probe_ms, e.probe_at, e.probe_fail = False, 12, now, 3
        e.probe_error = "IPv4: HTTP 502"
        db.commit()
    row = next(x for x in client.get("/api/v1/edges").json() if x["id"] == e.id)
    assert row["probe"] == {"ok": False, "ms": 12, "at": e.probe_at.isoformat() + "Z", "error": "IPv4: HTTP 502"}
    deep = client.get("/healthz/deep").json()
    assert deep["edges"]["probe_failing"] == 1


# ------------------------------------------------------------------ public status

def test_status_json_shape_and_no_leak(client):
    now = utcnow()
    with SessionLocal() as db:
        _edge(db, name="ir1", ipv4="5.160.1.10", region="home", last_seen_at=now)
        _edge(db, name="gl1", ipv4="8.8.8.8", region="global", last_seen_at=now)
    # an incident whose text is fine to expose
    client.post("/api/v1/incidents", json={"title": "کندی موقت", "body": "در حال بررسی", "severity": "minor"})
    r = client.get("/status.json")
    assert r.status_code == 200
    body = r.json()
    assert set(body) == {"status", "updated_at", "nodes", "components", "incidents"}
    assert body["nodes"] == {"total": 2, "online": 2}
    assert [c["name"] for c in body["components"]] == ["شبکه توزیع محتوا (CDN)", "سرویس تونل", "DNS"]
    assert body["status"] in ("operational", "degraded", "maintenance", "major_outage")
    assert len(body["incidents"]) == 1
    # NEVER leak infrastructure identifiers
    text = r.text
    for leak in ("5.160.1.10", "8.8.8.8", "ir1", "gl1"):
        assert leak not in text, f"status.json leaked {leak}"


def test_status_json_public_no_auth(client):
    r = client.get("/status.json", headers={"Authorization": ""})
    assert r.status_code == 200


def test_status_degraded_when_node_down(client):
    now = utcnow()
    with SessionLocal() as db:
        _edge(db, name="a", ipv4="5.160.1.1", region="home", last_seen_at=now, group="general")
        _edge(db, name="b", ipv4="5.160.1.2", region="home", last_seen_at=now - timedelta(hours=1), group="general")
    body = client.get("/status.json").json()
    assert body["nodes"] == {"total": 2, "online": 1}
    cdn = next(c for c in body["components"] if c["name"].startswith("شبکه"))
    assert cdn["status"] == "degraded"
    assert body["status"] in ("degraded", "major_outage")


# ------------------------------------------------------------------ incidents CRUD

def test_incident_crud_and_updates(client):
    r = client.post("/api/v1/incidents", json={"title": "قطعی", "body": "شروع", "severity": "major"})
    assert r.status_code == 201
    inc = r.json()
    assert inc["status"] == "investigating" and inc["severity"] == "major"
    assert len(inc["updates"]) == 1
    iid = inc["id"]

    # invalid severity / status -> Persian 422
    assert client.post("/api/v1/incidents", json={"title": "x", "severity": "huge"}).status_code == 422
    assert client.post(f"/api/v1/incidents/{iid}/updates", json={"status": "weird", "body": ""}).status_code == 422

    # post an update: moves status
    up = client.post(f"/api/v1/incidents/{iid}/updates", json={"status": "monitoring", "body": "پایدار شد"})
    assert up.status_code == 201 and up.json()["status"] == "monitoring"
    assert len(up.json()["updates"]) == 2

    # open list shows it, patch severity
    assert any(i["id"] == iid for i in client.get("/api/v1/incidents").json())
    patched = client.patch(f"/api/v1/incidents/{iid}", json={"severity": "minor"})
    assert patched.status_code == 200 and patched.json()["severity"] == "minor"

    # resolve -> drops off the default (open-only) list
    client.post(f"/api/v1/incidents/{iid}/updates", json={"status": "resolved", "body": "برطرف شد"})
    assert not any(i["id"] == iid for i in client.get("/api/v1/incidents").json())
    assert any(i["id"] == iid for i in client.get("/api/v1/incidents?all=1").json())
    assert client.patch("/api/v1/incidents/99999", json={"title": "x"}).status_code == 404


def test_status_keeps_open_plus_last_10_resolved(client):
    # 12 resolved incidents; only the newest 10 stay on status.json
    ids = []
    for i in range(12):
        r = client.post("/api/v1/incidents", json={"title": f"حادثه {i}", "severity": "minor",
                                                   "status": "resolved"})
        ids.append(r.json()["id"])
    # one still open
    client.post("/api/v1/incidents", json={"title": "باز", "severity": "minor"})
    body = client.get("/status.json").json()
    resolved = [i for i in body["incidents"] if i["status"] == "resolved"]
    assert len(resolved) == 10
    # the two oldest resolved dropped off
    shown = {i["id"] for i in resolved}
    assert ids[0] not in shown and ids[1] not in shown
    assert ids[-1] in shown
