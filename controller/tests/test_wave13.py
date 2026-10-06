"""Wave 13 (SPEC §22): tunnel speed and stability, controller side.

Node drain (§22.1), reload / tuning reports (§22.2 / §22.6), the synthetic tunnel probe and the
tunnel-degraded state (§22.3), multi-origin tunnel paths (§22.4), timeouts + client profile (§22.5 /
§22.11), upstream reuse (§22.7), TLS tickets / dual RSA / OCSP (§22.8), per-node HTTP/3 (§22.9),
capacity-weighted DNS (§22.10), the drops report (§22.12) and the data model (§22.13).
"""

import base64
import hashlib
import json
import logging
from datetime import datetime, timedelta
from types import SimpleNamespace

import pytest
from cryptography.fernet import Fernet
from sqlalchemy import select

from app import alerts, dnsbuild, edge_state, routes_capi, routes_edge, scheduler, sections, services, tunnel
from app import ssl as sslmod
from app import tls_tickets
from app.config import settings
from app.db import SessionLocal
from app.models import AuditLog, Edge, EdgeEvent, Site, State, utcnow
from tests.fixtures import certs
from tests.test_capi import new_key
from tests.test_tunnel import activate
from tests.test_tunnel import site as tunnel_site

S = "/api/v1/sites/example.com"
CAPI = "/capi/v1"


@pytest.fixture(autouse=True)
def _reset_limits():
    routes_capi._hits.clear()
    routes_edge._drain_calls.clear()
    yield
    routes_capi._hits.clear()
    routes_edge._drain_calls.clear()


def auth(tok: str) -> dict:
    return {"Authorization": f"Bearer {tok}"}


def mk_edge(client, name, ip, region="home", group="general", **extra):
    r = client.post("/api/v1/edges", json={"name": name, "ipv4": ip, "region": region, "group": group, **extra})
    assert r.status_code == 201, r.text
    return r.json()["id"], r.json()["token"]


def hb(client, tok, **body):
    r = client.post("/edge/v1/heartbeat", json={"applied_version": "v", **body}, headers=auth(tok))
    assert r.status_code == 200, r.text
    return r


def edge_dict(client, eid):
    return next(e for e in client.get("/api/v1/edges").json() if e["id"] == eid)


def zone_answer(fake_pdns, domain="example.com"):
    rr = fake_pdns.rrset(f"{domain}.", f"{domain}.", "LUA")
    return rr["records"][0]["content"] if rr else ""


def node_cfg(client, tok):
    return client.get("/edge/v1/config", headers=auth(tok)).json()


def web_site(client, domain="example.com"):
    r = client.post("/api/v1/sites", json={"domain": domain, "origin_ip": "93.184.216.34", "plan": {}})
    assert r.status_code == 201, r.text


def two_edges(client):
    a = mk_edge(client, "e1", "5.160.1.10")
    b = mk_edge(client, "e2", "5.160.1.11")
    hb(client, a[1])
    hb(client, b[1])
    return a, b


def ns_edge(ip, region="home", group="general", drain="", degraded=False, since=None, cap=0, level=0,
            shed=False):
    return SimpleNamespace(ipv4=ip, ipv6=None, region=region, group=group, shed=shed, metrics_at=utcnow(),
                           drain_state=drain, tunnel_degraded=degraded, tunnel_degraded_since=since,
                           capacity_mbps=cap, dns_weight_level=level, addresses=[])


GENERAL = SimpleNamespace(domain="ex.com", features="{}", config="{}")
TUNNEL = SimpleNamespace(domain="ex.com", features="{}", config='{"tunnel": {"enabled": true}}')


def ips(edges):
    return sorted(e.ipv4 for e in edges)


# ================================================================== §22.1 drain

def test_dns_drain_exclusion_and_fail_open_per_group_region():
    edges = [ns_edge("5.0.0.1", drain="draining"), ns_edge("5.0.0.2"), ns_edge("8.0.0.1", "global", drain="drained")]
    # home keeps its healthy edge; the global pool's only edge is draining -> stays in (never empty)
    assert ips(dnsbuild.dns_edges(GENERAL, edges)) == ["5.0.0.2", "8.0.0.1"]
    # every home edge draining -> all of them stay (fail-open)
    edges = [ns_edge("5.0.0.1", drain="draining"), ns_edge("5.0.0.2", drain="drained")]
    assert ips(dnsbuild.dns_edges(GENERAL, edges)) == ["5.0.0.1", "5.0.0.2"]
    # the tunnel group's pools are separate from the general group's
    edges = [ns_edge("5.0.0.1", group="tunnel", drain="draining"), ns_edge("5.0.0.2", group="tunnel"),
             ns_edge("5.0.0.3")]
    t = SimpleNamespace(domain="t.com", features='{"edge_group": "tunnel"}', config="{}")
    assert ips(dnsbuild.dns_edges(t, edges)) == ["5.0.0.2"]
    # shed + drain interplay: one shed, one draining in a pool of two -> the pool is never empty
    edges = [ns_edge("5.0.0.1", shed=True), ns_edge("5.0.0.2", drain="draining")]
    assert len(dnsbuild.dns_edges(GENERAL, edges)) >= 1


def test_admin_drain_last_edge_force_retime_undrain_and_dns(client, fake_pdns):
    web_site(client)
    (e1, t1), (e2, t2) = two_edges(client)
    scheduler.job_edges(SessionLocal())
    assert "5.160.1.10" in zone_answer(fake_pdns) and "5.160.1.11" in zone_answer(fake_pdns)

    r = client.post(f"/api/v1/edges/{e1}/drain", json={"minutes": 20, "reason": "upgrade"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["ok"] is True and body["dns_failed"] == 0
    d = body["edge"]["drain"]
    assert d["state"] == "draining" and d["by"] == "admin" and d["reason"] == "upgrade"
    since, until = datetime.fromisoformat(d["since"][:-1]), datetime.fromisoformat(d["until"][:-1])
    assert until - since == timedelta(minutes=20)
    ans = zone_answer(fake_pdns)
    assert "5.160.1.10" not in ans and "5.160.1.11" in ans  # left out of DNS at once

    # same minutes again -> already_draining; other minutes re-time drain_until only
    assert client.post(f"/api/v1/edges/{e1}/drain", json={"minutes": 20}).json() == {"detail": "already_draining"}
    r = client.post(f"/api/v1/edges/{e1}/drain", json={"minutes": 45})
    assert r.status_code == 200 and r.json()["edge"]["drain"]["since"] == d["since"]
    assert r.json()["edge"]["drain"]["until"] != d["until"]

    # e2 is now the last active edge of home/general
    r = client.post(f"/api/v1/edges/{e2}/drain", json={})
    assert r.status_code == 409 and r.json() == {"detail": "last_edge"}
    r = client.post(f"/api/v1/edges/{e2}/drain", json={"force": True})
    assert r.status_code == 200 and r.json()["edge"]["drain"]["reason"] == "admin"
    assert r.json()["edge"]["drain"]["until"]  # DRAIN_DEFAULT_MINUTES
    ans = zone_answer(fake_pdns)
    assert "5.160.1.10" in ans and "5.160.1.11" in ans  # every edge draining: fail-open

    for eid in (e1, e2):
        r = client.delete(f"/api/v1/edges/{eid}/drain")
        assert r.status_code == 200 and r.json()["edge"]["drain"]["state"] == ""
    assert client.delete(f"/api/v1/edges/{e1}/drain").status_code == 200  # idempotent
    assert "5.160.1.10" in zone_answer(fake_pdns)

    assert client.post("/api/v1/edges/999/drain", json={}).status_code == 404
    assert client.delete("/api/v1/edges/999/drain").status_code == 404
    for bad in ({"minutes": 0}, {"minutes": 121}, {"reason": "x" * 65}, {"reason": "bad\nreason"}, {"x": 1}):
        assert client.post(f"/api/v1/edges/{e1}/drain", json=bad).status_code == 422, bad

    with SessionLocal() as db:
        actions = [a.action for a in db.scalars(select(AuditLog).order_by(AuditLog.id))]
        assert actions.count("edge.drain") == 3 and actions.count("edge.undrain") == 2
        detail = json.loads(db.scalars(select(AuditLog).where(AuditLog.action == "edge.drain")).first().detail)
        assert detail == {"minutes": 20, "reason": "upgrade", "force": False}
        kinds = [ev.kind for ev in db.scalars(select(EdgeEvent).order_by(EdgeEvent.id))]
        assert kinds == ["drain_start", "drain_start", "drain_end", "drain_end"]


def test_edge_self_drain_endpoint_config_and_rate_limit(client):
    (e1, t1), (e2, t2) = two_edges(client)
    r = client.post("/edge/v1/drain", json={"action": "start", "minutes": 10}, headers=auth(t1))
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["state"] == "draining" and out["until"] and out["refuse_after"]
    with SessionLocal() as db:
        e = db.get(Edge, e1)
        # clients holding a fresh DNS answer are never refused: PROXIED_TTL + 30 s of grace
        assert edge_state.refuse_after(e) - e.drain_started_at == timedelta(seconds=settings.proxied_ttl + 30)
        assert e.drain_by == "edge" and e.drain_reason == "upgrade"
        assert db.get(Edge, e2).drain_state == ""  # only itself
    cfg = node_cfg(client, t1)["node"]["drain"]
    assert set(cfg) == {"state", "refuse_after", "until"} and cfg["state"] == "draining"
    assert cfg["until"] == out["until"] and cfg["refuse_after"] == out["refuse_after"]
    assert node_cfg(client, t2)["node"]["drain"] == {"state": ""}
    # the other edge is now the last one; the edge endpoint has no force
    r = client.post("/edge/v1/drain", json={"action": "start", "force": True}, headers=auth(t2))
    assert r.status_code == 422
    r = client.post("/edge/v1/drain", json={"action": "start"}, headers=auth(t2))
    assert r.status_code == 409 and r.json() == {"detail": "last_edge"}
    # re-start while draining is fine (idempotent for upgrade retries)
    assert client.post("/edge/v1/drain", json={"action": "start", "minutes": 10}, headers=auth(t1)).status_code == 200
    r = client.post("/edge/v1/drain", json={"action": "stop"}, headers=auth(t1))
    assert r.json() == {"state": "", "until": None, "refuse_after": None}
    for bad in ({"action": "pause"}, {"action": "start", "minutes": 0}, {"action": "start", "minutes": 121},
                {"action": "start", "edge_id": e2}, {}):
        assert client.post("/edge/v1/drain", json=bad, headers=auth(t1)).status_code == 422, bad
    assert client.post("/edge/v1/drain", json={"action": "stop"}).status_code == 401
    routes_edge._drain_calls.clear()
    codes = [client.post("/edge/v1/drain", json={"action": "stop"}, headers=auth(t1)).status_code for _ in range(11)]
    assert codes[:10] == [200] * 10 and codes[10] == 429
    assert client.post("/edge/v1/drain", json={"action": "stop"}, headers=auth(t2)).status_code == 200  # per edge


def test_heartbeat_drained_job_until_and_auto_undrain_after_hold(client, alert_settings):
    (e1, t1), (e2, t2) = two_edges(client)
    client.post(f"/api/v1/edges/{e1}/drain", json={"minutes": 5})
    # an old agent's heartbeat (no drain object) changes nothing
    hb(client, t1)
    assert edge_dict(client, e1)["drain"]["state"] == "draining"
    hb(client, t1, drain={"state": "drained", "conns": 3, "since": None})
    d = edge_dict(client, e1)["drain"]
    assert d["state"] == "drained" and d["conns"] == 3
    hb(client, t1, drain={"state": "nonsense"})  # malformed -> ignored, never a 422
    assert edge_dict(client, e1)["drain"]["state"] == "drained"

    client.delete(f"/api/v1/edges/{e1}/drain")
    client.post(f"/api/v1/edges/{e1}/drain", json={"minutes": 5})
    with SessionLocal() as db:
        until = db.get(Edge, e1).drain_until
        edge_state.job_drain(db, until - timedelta(seconds=1))
        assert db.get(Edge, e1).drain_state == "draining"
        edge_state.job_drain(db, until + timedelta(seconds=1))  # the controller flips at until
        db.expire_all()
        assert db.get(Edge, e1).drain_state == "drained"
        hold = timedelta(minutes=settings.drain_max_hold_minutes)
        edge_state.job_drain(db, until + hold - timedelta(seconds=1))
        db.expire_all()
        assert db.get(Edge, e1).drain_state == "drained"
        out = edge_state.job_drain(db, until + hold + timedelta(seconds=1))
        assert out["cleared"] == ["e1"]
        db.expire_all()
        assert db.get(Edge, e1).drain_state == "" and db.get(Edge, e1).drain_until is None
        audit = db.scalars(select(AuditLog).where(AuditLog.action == "edge.undrain")).all()
        assert any(a.actor == "system" and a.actor_kind == "system" for a in audit)
        kinds = [ev.kind for ev in db.scalars(select(EdgeEvent).where(EdgeEvent.edge_id == e1).order_by(EdgeEvent.id))]
        assert kinds[-3:] == ["drain_start", "drained", "drain_end"]
    assert any(c["key"] == f"edge_drain_stuck:{e1}" for c in alerts.open_alerts())
    # the next drain action on that edge closes the stuck alert
    client.post(f"/api/v1/edges/{e1}/drain", json={"minutes": 5})
    assert not any(c["key"] == f"edge_drain_stuck:{e1}" for c in alerts.open_alerts())


def test_drain_changes_edge_dns_state_and_shield_peers(client):
    (e1, t1), (e2, t2) = two_edges(client)
    e3, t3 = mk_edge(client, "e3", "5.160.1.12")
    hb(client, t3)
    client.patch(f"/api/v1/edges/{e1}", json={"shield": True})
    client.patch(f"/api/v1/edges/{e2}", json={"shield": True})
    with SessionLocal() as db:
        before = scheduler.edge_dns_state(db.get(Edge, e1))
        assert services.shield_peers(db, db.get(Edge, e3)) == ["5.160.1.10", "5.160.1.11"]
    client.post(f"/api/v1/edges/{e1}/drain", json={})
    with SessionLocal() as db:
        after = scheduler.edge_dns_state(db.get(Edge, e1))
        assert before != after and "/d1/" in after + "/" and "/d0/" in before + "/"
        assert services.shield_peers(db, db.get(Edge, e3)) == ["5.160.1.11"]


def test_bundle_upgrade_is_an_edge_event(client):
    (e1, t1), _ = two_edges(client)
    hb(client, t1, bundle_version="1.0")
    hb(client, t1, bundle_version="1.0")
    hb(client, t1, bundle_version="1.1")
    with SessionLocal() as db:
        evs = db.scalars(select(EdgeEvent).where(EdgeEvent.edge_id == e1)).all()
        assert [(e.kind, json.loads(e.data)) for e in evs] == [("upgrade", {"version": "1.1"})]
    client.delete(f"/api/v1/edges/{e1}")
    with SessionLocal() as db:
        assert db.scalars(select(EdgeEvent).where(EdgeEvent.edge_id == e1)).all() == []


# ================================================================== §22.2 reloads + metrics

def test_edge_memory_alert(client, alert_settings):
    """§22.2: the memory part of edge_health gets hysteresis and a critical tier — above it the kernel's
    OOM killer gets there first, and its victim can be the nginx master (every tunnel on the node with
    it). EDGE_MEM_ALERT stays the operator's threshold."""
    from app import config, edge_state

    (e1, t1), _ = two_edges(client)
    m = {"rx_mbps": 1, "tx_mbps": 1, "connections": 1, "load1": 0.1, "cpus": 2}
    open_pct = config.settings.edge_mem_alert

    def cond():
        with SessionLocal() as db:
            alerts.check_edge_health(db)
        return {c["key"]: c for c in alerts.open_alerts()}.get(f"edge_health:{e1}")

    for _ in range(edge_state.MEM_ALERT_CHECKS - 1):
        hb(client, t1, metrics={**m, "mem_pct": open_pct})
    assert cond() is None                                  # one heartbeat short
    hb(client, t1, metrics={**m, "mem_pct": open_pct})
    c = cond()
    assert c is not None and c["severity"] == "warning" and f"{open_pct:.0f}٪ مصرف" in c["text"]
    # hysteresis: just below the threshold keeps it open, MEM_RESOLVE_MARGIN points below closes it
    hb(client, t1, metrics={**m, "mem_pct": open_pct - 1})
    assert cond() is not None
    hb(client, t1, metrics={**m, "mem_pct": open_pct - edge_state.MEM_RESOLVE_MARGIN})
    assert cond() is None
    # from MEM_CRIT_PCT a single report is enough and the alert is critical, with the node's generations
    hb(client, t1, metrics={**m, "mem_pct": 99.1, "draining_workers": 7})
    c = cond()
    assert c["severity"] == "critical" and "99٪" in c["text"] and "7 نسل" in c["text"]
    assert "تونل" in c["text"] and "shutdown-timeout" in c["text"]
    # a heartbeat without mem_pct (older agent) cannot show the condition, but the stored state is kept:
    # the next report at the threshold opens the alert again at once instead of restarting the streak
    hb(client, t1, metrics=m)
    assert cond() is None
    hb(client, t1, metrics={**m, "mem_pct": open_pct})
    assert cond() is not None
    hb(client, t1, metrics={**m, "mem_pct": 10.0})
    assert cond() is None
    assert not any(k.startswith("_") for k in edge_dict(client, e1)["metrics"])


def test_metrics_fields_reloads_storage_alerts_and_prometheus(client, alert_settings):
    (e1, t1), _ = two_edges(client)
    m = {"rx_mbps": 1, "tx_mbps": 2, "connections": 5, "load1": 0.1, "cpus": 1,
         "draining_workers": 5, "sock_tcp": 1200, "sock_tw": 300}
    rl = {"count_1h": 13, "count_24h": 40, "last_at": "2026-10-02T10:00:00Z", "coalesced_1h": 4,
          "pending_s": 0, "deferred": False, "wst_s": 3600, "forced_shutdowns_24h": 0}
    for _ in range(2):
        hb(client, t1, metrics=m, reloads=rl)
    e = edge_dict(client, e1)
    assert (e["metrics"]["draining_workers"], e["metrics"]["sock_tcp"], e["metrics"]["sock_tw"]) == (5, 1200, 300)
    assert not any(k.startswith("_") for k in e["metrics"])
    assert e["reloads"] == {**rl, "last_at": "2026-10-02T10:00:00Z"}
    with SessionLocal() as db:
        alerts.check_edge_tunnel(db)
    keys = {c["key"] for c in alerts.open_alerts()}
    assert f"edge_reload_storm:{e1}" not in keys and f"edge_draining_pileup:{e1}" not in keys
    for _ in range(3):
        hb(client, t1, metrics=m, reloads=rl)
    with SessionLocal() as db:
        alerts.check_edge_tunnel(db)
    keys = {c["key"] for c in alerts.open_alerts()}
    assert f"edge_reload_storm:{e1}" in keys and f"edge_draining_pileup:{e1}" in keys
    # hysteresis: 8/h keeps the storm open, <= 6 resolves it
    hb(client, t1, metrics={**m, "draining_workers": 1}, reloads={**rl, "count_1h": 8})
    with SessionLocal() as db:
        alerts.check_edge_tunnel(db)
    keys = {c["key"] for c in alerts.open_alerts()}
    assert f"edge_reload_storm:{e1}" in keys and f"edge_draining_pileup:{e1}" not in keys
    hb(client, t1, metrics=m, reloads={**rl, "count_1h": 6})
    with SessionLocal() as db:
        alerts.check_edge_tunnel(db)
    assert f"edge_reload_storm:{e1}" not in {c["key"] for c in alerts.open_alerts()}

    # malformed reloads are ignored (stored report kept), never a 422
    hb(client, t1, reloads={"count_1h": "many"})
    hb(client, t1, reloads=[1, 2])
    assert edge_dict(client, e1)["reloads"]["count_1h"] == 6
    # an out-of-range metrics value is still a 422 like every metrics field
    r = client.post("/edge/v1/heartbeat", json={"metrics": {"draining_workers": -1}}, headers=auth(t1))
    assert r.status_code == 422

    text = client.get("/metrics").text
    assert 'pcdn_edge_reloads_1h{edge="e1"} 6' in text
    assert 'pcdn_edge_draining_workers{edge="e1"} 5' in text
    assert "5.160.1.10" not in text


def test_tuning_report_storage_and_info_alert(client, alert_settings):
    (e1, t1), _ = two_edges(client)
    bad = {"profile": "auto", "ram_mb": 1024, "ok": False, "cc": "cubic", "qdisc": "fq", "nofile": 1048576,
           "mismatches": [{"key": "net.core.rmem_max", "want": "8388608", "have": "212992"}] * 25}
    for i in range(3):
        hb(client, t1, tuning=bad)
        with SessionLocal() as db:
            alerts.check_edge_tunnel(db)
        cond = next((c for c in alerts.open_alerts() if c["key"] == f"edge_tuning:{e1}"), None)
        assert (cond is not None) is (i == 2)
    assert cond["severity"] == "info"
    t = edge_dict(client, e1)["tuning"]
    assert t["ok"] is False and len(t["mismatches"]) == 20 and "_bad_n" not in t
    hb(client, t1, tuning={**bad, "ok": True, "mismatches": []})
    with SessionLocal() as db:
        alerts.check_edge_tunnel(db)
    assert not any(c["key"] == f"edge_tuning:{e1}" for c in alerts.open_alerts())
    hb(client, t1, tuning={"profile": "turbo"})  # malformed -> ignored
    assert edge_dict(client, e1)["tuning"]["ok"] is True


# ================================================================== §22.3 tunnel probe

def probe(at, ok=True):
    res = {"ok": ok, "setup_ms": 40, "echo_ok": ok, "down_kbps": 90000, "up_kbps": 80000,
           "error": None if ok else "echo mismatch from 127.0.0.1"}
    return {"at": at.isoformat() + "Z", "ok": ok, "ws": res, "grpc": {"unsupported": True},
            "consecutive_fail": 0 if ok else 1}


def test_probe_hysteresis_dns_tunnel_only_alert_and_recovery(client, fake_pdns, alert_settings, monkeypatch):
    monkeypatch.setattr(settings, "tunnel_probe_fail_checks", 3)
    monkeypatch.setattr(settings, "tunnel_probe_ok_checks", 2)
    tunnel_site(client)
    client.put(f"{S}/config/tunnel", json={"enabled": True, "paths": [{"id": "w", "path": "/w", "protocol": "ws"}]})
    web_site(client, "web.example")
    (e1, t1), (e2, t2) = two_edges(client)
    now = utcnow()
    hb(client, t1, tunnel_probe=probe(now - timedelta(minutes=5), ok=False))
    hb(client, t1, tunnel_probe=probe(now - timedelta(minutes=5), ok=False))  # the same report again
    hb(client, t1, tunnel_probe=probe(now - timedelta(minutes=4), ok=False))
    hb(client, t1, tunnel_probe=probe(now - timedelta(hours=2), ok=False))  # stale: never counts
    hb(client, t1)  # old agent / no probe: nothing changes
    tp = edge_dict(client, e1)["tunnel_probe"]
    assert tp["degraded"] is False and tp["last"]["ok"] is False
    assert "127.0.0.1" not in json.dumps(tp)  # addresses scrubbed from probe errors
    hb(client, t1, tunnel_probe=probe(now - timedelta(minutes=3), ok=False))
    tp = edge_dict(client, e1)["tunnel_probe"]
    assert tp["degraded"] is True and tp["since"]
    assert client.get("/api/v1/overview").json()["tunnel_degraded"] == ["e1"]

    scheduler.job_edges(SessionLocal())
    assert "5.160.1.10" not in zone_answer(fake_pdns) and "5.160.1.11" in zone_answer(fake_pdns)
    assert "5.160.1.10" in zone_answer(fake_pdns, "web.example")  # web sites keep it
    with SessionLocal() as db:
        alerts.check_edge_tunnel(db)
    cond = next(c for c in alerts.open_alerts() if c["key"] == f"edge_tunnel_degraded:{e1}")
    assert "پروب داخلی" in cond["title"] and "e1" in cond["title"]

    # recovery needs TUNNEL_PROBE_OK_CHECKS ok reports AND >= 10 min degraded
    hb(client, t1, tunnel_probe=probe(now - timedelta(minutes=2)))
    hb(client, t1, tunnel_probe=probe(now - timedelta(minutes=1)))
    assert edge_dict(client, e1)["tunnel_probe"]["degraded"] is True
    with SessionLocal() as db:
        db.get(Edge, e1).tunnel_degraded_since = utcnow() - timedelta(minutes=11)
        db.commit()
    hb(client, t1, tunnel_probe=probe(now))
    assert edge_dict(client, e1)["tunnel_probe"] == {"degraded": False, "since": None,
                                                    "last": edge_dict(client, e1)["tunnel_probe"]["last"]}
    with SessionLocal() as db:
        alerts.check_edge_tunnel(db)
        kinds = [ev.kind for ev in db.scalars(select(EdgeEvent).where(EdgeEvent.edge_id == e1))]
    assert kinds == ["degraded", "recovered"]
    assert not any(c["key"] == f"edge_tunnel_degraded:{e1}" for c in alerts.open_alerts())
    scheduler.job_edges(SessionLocal())
    assert "5.160.1.10" in zone_answer(fake_pdns)


def test_degraded_budget_most_recent_stay_and_fail_open(monkeypatch):
    monkeypatch.setattr(settings, "tunnel_degraded_max_fraction", 0.5)
    t0 = utcnow()
    edges = [ns_edge("5.0.0.1", degraded=True, since=t0 - timedelta(hours=2)),
             ns_edge("5.0.0.2", degraded=True, since=t0 - timedelta(minutes=5)),
             ns_edge("5.0.0.3", degraded=True, since=t0 - timedelta(hours=1)),
             ns_edge("5.0.0.4")]
    # n=4 -> at most 2 withdrawn, the longest-degraded first; general sites keep every edge
    assert ips(dnsbuild.dns_edges(TUNNEL, edges)) == ["5.0.0.2", "5.0.0.4"]
    assert len(dnsbuild.dns_edges(GENERAL, edges)) == 4
    # a single degraded edge alone in its pool: floor(1 x 0.5) = 0 -> stays (never emptied)
    assert ips(dnsbuild.dns_edges(TUNNEL, [ns_edge("5.0.0.1", degraded=True)])) == ["5.0.0.1"]
    monkeypatch.setattr(settings, "tunnel_degraded_max_fraction", 1.0)
    both = [ns_edge("5.0.0.1", degraded=True), ns_edge("5.0.0.2", degraded=True)]
    assert len(dnsbuild.dns_edges(TUNNEL, both)) == 2  # fail-open
    # per region pool: the global edge is untouched by the home pool's budget
    edges = [ns_edge("5.0.0.1", degraded=True), ns_edge("5.0.0.2"), ns_edge("8.0.0.1", "global", degraded=True)]
    assert ips(dnsbuild.dns_edges(TUNNEL, edges)) == ["5.0.0.2", "8.0.0.1"]
    # drain + degraded in one pool: never empty
    edges = [ns_edge("5.0.0.1", drain="draining"), ns_edge("5.0.0.2", degraded=True)]
    assert ips(dnsbuild.dns_edges(TUNNEL, edges)) == ["5.0.0.2"]


def test_edge_dns_state_degraded_flag(client):
    (e1, t1), _ = two_edges(client)
    with SessionLocal() as db:
        e = db.get(Edge, e1)
        a = scheduler.edge_dns_state(e)
        e.tunnel_degraded = True
        assert scheduler.edge_dns_state(e) != a and "/t1" in scheduler.edge_dns_state(e)


# ================================================================== §22.4 multi-origin paths

O1 = {"address": "185.143.233.10", "port": 8443}
O2 = {"address": "185.143.233.11", "port": 8443}
O3 = {"address": "185.143.233.12", "port": 8443}


def put_tunnel(client, paths):
    return client.put(f"{S}/config/tunnel", json={"enabled": True, "paths": paths})


def mpath(origins, **kw):
    return {"id": "grpc1", "path": "/svc", "protocol": "grpc", "origins": origins, **kw}


@pytest.mark.parametrize("path", [
    mpath([O1, O2], origin=O1),
    mpath([O1, O2], pool="vpn"),
    mpath([O1]),
    mpath([dict(O1, port=1000 + i) for i in range(11)]),
    mpath([O1, dict(O2, tls=True)]),
    mpath([dict(O1, tls=True, verify=True), dict(O2, tls=True)]),
    mpath([dict(O1, sni="a.example.com"), dict(O2, sni="b.example.com")]),
    mpath([dict(O1, backup=True), dict(O2, backup=True)]),
    mpath([O1, dict(O1)]),
    mpath([O1, dict(O2, weight=0)]),
    mpath([O1, O2], balance="random"),
    mpath([O1, O2], health={"type": "udp"}),
    mpath([O1, O2], health={"interval": 5, "timeout": 5}),
    mpath([O1, O2], health={"type": "http", "expect": "abc"}),
    {"id": "p", "path": "/p", "protocol": "ws", "idle_timeout": 59},
    {"id": "p", "path": "/p", "protocol": "ws", "idle_timeout": 86401},
])
def test_multi_origin_schema_rejects(client, path):
    tunnel_site(client, features={"max_tunnel_origins": 10})
    r = put_tunnel(client, [path])
    assert r.status_code == 422, (path, r.text)


def test_multi_origin_plan_limit_roundtrip_edge_config_and_downgrade(client):
    tunnel_site(client)
    activate()
    _, tok = mk_edge(client, "e1", "5.160.1.10")
    r = put_tunnel(client, [mpath([O1, O2])])
    assert r.status_code == 403 and "حداکثر 1 مبدأ" in r.json()["detail"]
    assert client.patch(f"{S}/plan", json={"features": {"max_tunnel_origins": 11}}).status_code == 422
    assert client.patch(f"{S}/plan", json={"features": {"max_tunnel_origins": 0}}).status_code == 422
    client.patch(f"{S}/plan", json={"features": {"max_tunnel_origins": 3}})
    assert put_tunnel(client, [mpath([O1, O2, O3, dict(O3, port=9)])]).status_code == 403
    r = put_tunnel(client, [mpath([O1, O2, O3]), {"id": "w", "path": "/w", "protocol": "ws", "idle_timeout": 120}])
    assert r.status_code == 200, r.text
    p = r.json()["paths"][0]
    assert p["balance"] == "failover" and p["health"] == {"type": "tcp", "interval": 10, "timeout": 3,
                                                          "path": "/", "expect": "2xx,3xx,4xx"}
    assert p["origins"][0] == {"address": "185.143.233.10", "port": 8443, "tls": False, "sni": None,
                               "verify": False, "weight": 1, "backup": False}
    assert r.json()["paths"][1]["idle_timeout"] == 120
    assert client.get(f"{S}/config/tunnel").json() == r.json()

    def edge_paths():
        return next(s for s in node_cfg(client, tok)["sites"] if s["domain"] == "example.com")["tunnel"]["paths"]

    ep = edge_paths()[0]
    # failover without explicit backups: every member after the first goes as backup; `origin` = primary
    assert [o["backup"] for o in ep["origins"]] == [False, True, True]
    assert ep["origin"] == {"address": "185.143.233.10", "port": 8443, "tls": False, "sni": None, "verify": False}
    assert ep["balance"] == "failover" and ep["health"]["type"] == "tcp"
    w = edge_paths()[1]
    assert (w["origins"], w["balance"], w["health"], w["idle_timeout"]) == (None, None, None, 120)
    # explicit backups are kept; round robin over the primaries
    assert client.get("/api/v1/overview").json()["tunnel_multi_origin_sites"] == 1
    put_tunnel(client, [mpath([dict(O1, backup=True), O2, dict(O3, weight=5)], balance="round_robin")])
    ep = edge_paths()[0]
    assert [o["backup"] for o in ep["origins"]] == [True, False, False] and ep["origin"]["address"] == "185.143.233.11"
    # downgrade: the first max_tunnel_origins members, keeping a primary; 1 -> a plain origin path
    client.patch(f"{S}/plan", json={"features": {"max_tunnel_origins": 1}})
    ep = edge_paths()[0]
    assert ep["origins"] is None and ep["origin"]["address"] == "185.143.233.11" and ep["balance"] is None
    client.patch(f"{S}/plan", json={"features": {"max_tunnel_origins": 2}})
    ep = edge_paths()[0]
    assert [o["address"] for o in ep["origins"]] == ["185.143.233.10", "185.143.233.11"]


def test_multi_origin_origin_guard_filtering():
    site = SimpleNamespace(effective_status="active")
    feats = {**sections.DEFAULT_FEATURES, "tunnel": True, "max_tunnel_origins": 10}
    base = {"enabled": True, "paths": [], "idle_timeout": 3600, "per_connection_mbps": 0}
    origins = [dict(O1, address="vpn1.example.net", tls=False, sni=None, verify=False, weight=1, backup=False),
               dict(O2, tls=False, sni=None, verify=False, weight=1, backup=False),
               dict(O3, tls=False, sni=None, verify=False, weight=1, backup=False)]
    path = {"id": "g", "path": "/g", "protocol": "grpc", "origin": None, "pool": None, "origins": origins,
            "balance": "failover", "health": {"type": "tcp"}, "idle_timeout": None}
    t = services.tunnel_for_edge(site, {**base, "paths": [path]}, feats, set(), {"vpn1.example.net": {}})
    p = t["paths"][0]
    assert [o["address"] for o in p["origins"]] == ["185.143.233.11", "185.143.233.12"]
    assert p["origin"]["address"] == "185.143.233.11"
    every = {"vpn1.example.net": {}, "185.143.233.11": {}, "185.143.233.12": {}}
    assert services.tunnel_for_edge(site, {**base, "paths": [path]}, feats, set(), every)["paths"] == []
    # a blocked primary: the first backup is promoted
    path2 = dict(path, origins=[origins[0], dict(origins[1], backup=True), dict(origins[2], backup=True)])
    p = services.tunnel_for_edge(site, {**base, "paths": [path2]}, feats, set(), {"vpn1.example.net": {}})["paths"][0]
    assert [o["backup"] for o in p["origins"]] == [False, True]
    # origin_hosts / the reachability check see every member
    assert ("vpn1.example.net", "مسیر تونل g") in sections.origin_hosts("tunnel", {"paths": [path]})


def test_pools_health_type_and_grpc_http_warning(client):
    tunnel_site(client, features={"max_tunnel_origins": 3})
    r = client.put(f"{S}/config/pools", json={"pools": [{"name": "vpn", "origins": [{"address": "185.1.2.3"}],
                                                         "health": {"type": "tcp"}}]})
    assert r.status_code == 200 and r.json()["pools"][0]["health"]["type"] == "tcp"
    assert client.put(f"{S}/config/pools", json={"pools": [{"name": "vpn", "origins": [{"address": "185.1.2.3"}],
                                                            "health": {"type": "icmp"}}]}).status_code == 422
    r = client.put(f"{S}/config/pools", json={"pools": [{"name": "web", "origins": [{"address": "185.1.2.3"}]}]})
    assert r.json()["pools"][0]["health"]["type"] == "http"  # existing pools unchanged
    with SessionLocal() as db:
        s = db.scalar(select(Site))
        value = {"paths": [{"id": "g", "path": "/g", "protocol": "grpc", "origin": None, "pool": None,
                            "origins": [O1, O2], "health": {"type": "http"}}]}
        assert any("tcp" in w and "gRPC" in w for w in sections.section_warnings(s, "tunnel", value))
        value["paths"][0]["health"] = {"type": "tcp"}
        assert not any("gRPC" in w for w in sections.section_warnings(s, "tunnel", value))
    # the tunnel reachability check probes every member of an origins path
    put_tunnel(client, [mpath([O1, O2])])
    with SessionLocal() as db:
        tg = dict(tunnel.targets(db.scalar(select(Site))))
    assert [t["address"] for t in tg["grpc1"]] == ["185.143.233.10", "185.143.233.11"]


# ================================================================== §22.5 / §22.11 profile

def test_edge_timer_contract_is_pinned():
    assert tunnel.EDGE_TUNNEL_TIMERS == {
        "client_idle_s": 600, "max_connection_age_s": 21600, "h2_max_streams": 512,
        "tcp_keepalive": {"idle_s": 120, "interval_s": 30, "count": 4}, "connect_timeout_s": 10}


@pytest.mark.parametrize("idle,k", [(60, 20), (90, 30), (100, 33), (120, 40), (180, 60), (600, 60), (3600, 60),
                                    (86400, 60)])
def test_recommended_keepalive_formula(idle, k):
    assert tunnel.keepalive_s(idle) == k


def test_profile_shape_recommendations_404_and_capi_scope(client):
    tunnel_site(client)
    r = put_tunnel(client, [
        {"id": "grpc1", "path": "/svc", "protocol": "grpc", "idle_timeout": 60},
        {"id": "x1", "path": "/xh", "protocol": "xhttp"},
        {"id": "w1", "path": "/ws", "protocol": "ws", "idle_timeout": 240},
        {"id": "u1", "path": "/up", "protocol": "httpupgrade"},
    ])
    assert r.status_code == 200, r.text
    prof = client.get(f"{S}/tunnel/profile").json()
    assert prof["edge"] == tunnel.EDGE_TUNNEL_TIMERS
    assert prof["http3"] == {"site": False, "nodes": 0, "nodes_h3": 0, "available": False}
    g, x, w, u = prof["paths"]
    assert g == {"id": "grpc1", "path": "/svc", "protocol": "grpc", "idle_timeout_s": 60, "read_timeout_s": 60,
                 "send_timeout_s": 60, "origins": 1, "balance": None, "http3": False,
                 "recommended": {"keepalive_s": 20, "mux": "off", "xmux": None,
                                 "grpc": {"idle_timeout_s": 20, "health_check_timeout_s": 20,
                                          "permit_without_stream": False},
                                 "ws_heartbeat_s": None}}
    assert (x["idle_timeout_s"], x["send_timeout_s"], x["recommended"]["keepalive_s"]) == (3600, 300, 60)
    assert x["recommended"]["mux"] == "off" and x["recommended"]["xmux"] == {
        "max_concurrency": "16-32", "c_max_reuse_times": 0, "h_max_request_times": "600-900",
        "h_max_reusable_secs": "1800-3000", "h_keepalive_period_s": 60}
    assert w["recommended"] == {"keepalive_s": 60, "mux": "low", "xmux": None, "grpc": None, "ws_heartbeat_s": 60}
    assert w["send_timeout_s"] == 240
    assert u["recommended"]["mux"] == "low" and u["recommended"]["ws_heartbeat_s"] is None
    assert not any("؀" <= ch <= "ۿ" for ch in json.dumps(prof, ensure_ascii=False))  # no Persian
    for forbidden in ("fragment", "noise", "padding", "sni"):
        assert forbidden not in json.dumps(prof).lower()

    stats = new_key(client, scopes=["stats"])["key"]
    dns = new_key(client, name="d", scopes=["dns"])["key"]
    assert client.get(f"{CAPI}/tunnel/profile", headers=auth(stats)).json() == prof
    assert client.get(f"{CAPI}/tunnel/profile", headers=auth(dns)).status_code == 403
    client.patch(f"{S}/plan", json={"features": {"tunnel": False}})
    assert client.get(f"{S}/tunnel/profile").status_code == 404
    assert client.get(f"{CAPI}/tunnel/profile", headers=auth(stats)).status_code == 404
    spec = client.get(f"{CAPI}/openapi.json").json()
    assert {"/capi/v1/tunnel/profile", "/capi/v1/tunnel/drops"} <= set(spec["paths"])


# ================================================================== §22.9 HTTP/3

def test_http3_availability_counts_patch_and_node_config(client):
    tunnel_site(client)
    activate()
    put_tunnel(client, [{"id": "x1", "path": "/xh", "protocol": "xhttp"}, {"id": "g", "path": "/g", "protocol": "grpc"}])
    cert, key = certs.chain()
    with SessionLocal() as db:
        s = db.scalar(select(Site))
        s.ssl_cert, s.ssl_key, s.ssl_status, s.ssl_source = cert, key, "active", "letsencrypt"
        s.ssl_expires_at = utcnow() + timedelta(days=60)
        db.commit()
    e1, t1 = mk_edge(client, "e1", "5.160.1.10")
    e2, t2 = mk_edge(client, "e2", "5.160.1.11")
    hb(client, t1, capabilities={"http3": True})
    hb(client, t2, capabilities={"http3": False})
    h3 = client.get(f"{S}/tunnel/profile").json()["http3"]
    assert h3 == {"site": True, "nodes": 2, "nodes_h3": 1, "available": False}  # mixed group
    hb(client, t2, capabilities={"http3": True})
    prof = client.get(f"{S}/tunnel/profile").json()
    assert prof["http3"]["available"] is True
    assert [p["http3"] for p in prof["paths"]] == [True, False]  # xhttp only
    r = client.patch(f"/api/v1/edges/{e1}", json={"http3_enabled": False})
    assert r.status_code == 200 and r.json()["edge"]["http3_enabled"] is False
    assert client.get(f"{S}/tunnel/profile").json()["http3"] == {"site": True, "nodes": 2, "nodes_h3": 1,
                                                                 "available": False}
    assert node_cfg(client, t1)["node"]["http3"] is False and node_cfg(client, t2)["node"]["http3"] is True
    assert edge_dict(client, e2)["http3_enabled"] is True
    client.put(f"{S}/config/ssl", json={"http3": False})
    assert client.get(f"{S}/tunnel/profile").json()["http3"]["site"] is False
    assert client.patch(f"/api/v1/edges/{e1}", json={"http3_enabled": "maybe"}).status_code == 422


# ================================================================== §22.10 capacity-weighted DNS

def test_weights_from_capacity_median_unknown_and_level():
    a, b, c = ns_edge("5.0.0.1", cap=100), ns_edge("5.0.0.2", cap=200), ns_edge("5.0.0.3", cap=0)
    q = dnsbuild.edge_q([a, b, c], 4)
    assert (q[id(a)], q[id(b)], q[id(c)]) == (2, 4, 3)  # unknown -> median 150
    x, y = ns_edge("5.0.0.1"), ns_edge("5.0.0.2")
    q = dnsbuild.edge_q([x, y], 4)
    assert (q[id(x)], q[id(y)]) == (4, 4)  # nothing known -> 100 each
    hot, cold = ns_edge("5.0.0.1", cap=200, level=2), ns_edge("5.0.0.2", cap=100)
    q = dnsbuild.edge_q([hot, cold], 4)
    assert (q[id(hot)], q[id(cold)]) == (2, 4)  # 200 x 0.25 = 50 vs 100
    tiny = [ns_edge("5.0.0.1", cap=10000), ns_edge("5.0.0.2", cap=10)]
    assert dnsbuild.edge_q(tiny, 4)[id(tiny[1])] == 1  # never 0
    # pools are per group + region: the global edge is the max of its own pool
    g = ns_edge("8.0.0.1", "global", cap=10)
    assert dnsbuild.edge_q([a, b, g], 4)[id(g)] == 4


def test_weight_level_hysteresis():
    lvl, prev = 0, {}
    seq = [(72, 0), (72, 1), (90, 1), (90, 2), (70, 2), (70, 2), (70, 1), (65, 1), (55, 1), (55, 1), (55, 0),
           (None, 0)]
    for pct, want in seq:
        lvl, up, down = edge_state.weight_level(lvl, pct, prev)
        prev = {"_wl_up": up, "_wl_down": down}
        assert lvl == want, (pct, want, lvl)


def test_weight_level_from_heartbeats_and_quantisation_stability(client, monkeypatch):
    monkeypatch.setattr(settings, "dns_weights", "capacity")
    e1, t1 = mk_edge(client, "e1", "5.160.1.10", capacity_mbps=100)
    e2, t2 = mk_edge(client, "e2", "5.160.1.11", capacity_mbps=100)
    base = {"connections": 1, "load1": 0.1, "cpus": 4}
    hb(client, t2, metrics={**base, "tx_mbps": 10})

    def state():
        with SessionLocal() as db:
            edges = services.online_edges(db)
            q4 = dnsbuild.edge_q(edges, 4)
            return ",".join(scheduler.edge_dns_state(e, f"{q4.get(id(e), 0)}-0") for e in edges)

    hb(client, t1, metrics={**base, "tx_mbps": 30})
    s1 = state()
    hb(client, t1, metrics={**base, "tx_mbps": 41})  # small load change: same level, same q
    assert state() == s1
    hb(client, t1, metrics={**base, "tx_mbps": 88})
    assert edge_dict(client, e1)["dns_weight"] == {"level": 0, "q": 4}
    hb(client, t1, metrics={**base, "tx_mbps": 88})  # 2 reports >= 85 % -> level 2 (factor 0.25)
    assert edge_dict(client, e1)["dns_weight"] == {"level": 2, "q": 1}
    assert state() != s1
    assert node_cfg(client, t1)["node"]["dns_weight"] == {"level": 2, "q": 1}
    monkeypatch.setattr(settings, "dns_weights", "off")
    assert edge_dict(client, e1)["dns_weight"] == {"level": 2, "q": None}
    assert node_cfg(client, t1)["node"]["dns_weight"] is None


def rendered(site, edges):
    rr = {(r["name"], r["type"]): r for r in dnsbuild.build_rrsets(site, edges)}
    return rr[("ex.com.", "LUA")]["records"][0]["content"]


def wsite(tunnel_on=False):
    rec = SimpleNamespace(name="@", type="A", content="1.2.3.4", proxied=True, priority=None, ttl=300)
    cfg = '{"tunnel": {"enabled": true}}' if tunnel_on else "{}"
    return SimpleNamespace(domain="ex.com", features="{}", config=cfg, records=[rec])


@pytest.mark.parametrize("probe_on", [False, True])
def test_weighted_lua_rendering_per_selector(monkeypatch, probe_on):
    monkeypatch.setattr(settings, "edge_probe", probe_on)
    monkeypatch.setattr(settings, "geoip_enabled", False)
    edges = [ns_edge("5.0.0.1", cap=200), ns_edge("5.0.0.2", cap=100)]
    out = {}
    for mode in ("off", "capacity"):
        monkeypatch.setattr(settings, "dns_weights", mode)
        for sel in ("random", "hashed", "all", "first", "pickclosest"):
            monkeypatch.setattr(settings, "lua_selector", sel)
            out[(mode, sel)] = rendered(wsite(), edges)
        out[(mode, "tunnel")] = rendered(wsite(True), edges)
    for sel in ("all", "first", "pickclosest", "tunnel"):  # ignore weights: byte-identical
        assert out[("off", sel)] == out[("capacity", sel)], sel
    if probe_on:
        assert "{'5.0.0.1','5.0.0.1','5.0.0.1','5.0.0.1','5.0.0.2','5.0.0.2'}" in out[("capacity", "random")]
        assert "selector='random'" in out[("capacity", "random")]
        assert "selector='hashed'" in out[("capacity", "hashed")]
    else:
        assert "pickwrandom({{4,'5.0.0.1'},{2,'5.0.0.2'}})" in out[("capacity", "random")]
        assert "pickwhashed({{4,'5.0.0.1'},{2,'5.0.0.2'}})" in out[("capacity", "hashed")]
    # equal weights everywhere -> exactly today's output
    equal = [ns_edge("5.0.0.1", cap=100), ns_edge("5.0.0.2", cap=100)]
    for sel in ("random", "hashed"):
        monkeypatch.setattr(settings, "lua_selector", sel)
        monkeypatch.setattr(settings, "dns_weights", "off")
        off = rendered(wsite(), equal)
        monkeypatch.setattr(settings, "dns_weights", "capacity")
        assert rendered(wsite(), equal) == off


def test_weights_with_shed_drain_degraded_fail_open(monkeypatch):
    monkeypatch.setattr(settings, "dns_weights", "capacity")
    monkeypatch.setattr(settings, "edge_probe", False)
    monkeypatch.setattr(settings, "lua_selector", "random")
    edges = [ns_edge("5.0.0.1", cap=400, drain="draining"), ns_edge("5.0.0.2", cap=100),
             ns_edge("5.0.0.3", cap=200)]
    ans = rendered(wsite(), edges)
    # the drained edge is out; the others keep the q of their full pool (max = the drained 400)
    assert "5.0.0.1" not in ans and "pickwrandom({{1,'5.0.0.2'},{2,'5.0.0.3'}})" in ans
    only = [ns_edge("5.0.0.1", cap=400, drain="draining")]
    assert "5.0.0.1" in rendered(wsite(), only)


# ================================================================== §22.7 / §22.12 usage, quality, drops

def pc(sessions=0, connect_n=0, reused_n=0, ends=None, **errors):
    out = {"sessions": sessions, "seconds": 0, "bytes_up": 0, "bytes_down": 0, "abnormal": 0,
           "connect_ms_sum": connect_n * 10, "connect_n": connect_n, "reused_n": reused_n,
           "errors": {k: errors.get(k, 0) for k in routes_edge.TUNNEL_ERROR_KEYS}}
    if ends is not None:
        out["ends"] = ends
    return out


def usage_item(paths, when):
    hour = when.replace(minute=0, second=0, microsecond=0).isoformat() + "Z"
    return {"host": "example.com", "hour": hour, "bytes": 100, "requests": 1,
            "tunnel": {"sessions": 0, "seconds": 0, "bytes_up": 0, "bytes_down": 0, "by_protocol": {},
                       "paths": paths}}


def post_usage(client, tok, items):
    r = client.post("/edge/v1/usage", json={"items": items}, headers=auth(tok))
    assert r.status_code == 200, r.text


def ends(**kw):
    return {k: kw.get(k, 0) for k in routes_edge.TUNNEL_END_KEYS}


def stored_paths():
    from app.models import UsageHourly

    with SessionLocal() as db:
        return [json.loads(r.details)["tunnel"]["paths"] for r in db.scalars(select(UsageHourly))]


def test_usage_merge_ends_reused_and_reuse_pct(client):
    tunnel_site(client)
    put_tunnel(client, [{"id": "grpc1", "path": "/x", "protocol": "grpc"}, {"id": "ws1", "path": "/ws", "protocol": "ws"}])
    _, tok = mk_edge(client, "e1", "5.160.1.10")
    now = utcnow()
    post_usage(client, tok, [usage_item({"grpc1": pc(4, connect_n=10, reused_n=4, ends=ends(normal=3, origin=1)),
                                         "ws1": pc(2, connect_n=2)}, now)])
    post_usage(client, tok, [usage_item({"grpc1": pc(1, connect_n=10, reused_n=5,
                                                     ends={**ends(idle_timeout=2), "bogus": 9})}, now)])
    paths = stored_paths()[0]
    assert paths["grpc1"]["ends"] == ends(normal=3, origin=1, idle_timeout=2) and paths["grpc1"]["reused_n"] == 9
    assert "ends" not in paths["ws1"]  # old agents: no ends key at all (has_data stays false)
    q = {p["id"]: p for p in client.get(f"{S}/tunnel/quality?hours=2").json()["paths"]}
    assert q["grpc1"]["reuse_pct"] == 45.0 and q["ws1"]["reuse_pct"] == 0.0
    # malformed ends values -> 422 like every usage counter
    r = client.post("/edge/v1/usage", json={"items": [usage_item({"grpc1": pc(ends={"normal": -1})}, now)]},
                    headers=auth(tok))
    assert r.status_code == 422


def test_drops_report_aggregation_top_maintenance_plan_and_capi(client):
    tunnel_site(client)
    put_tunnel(client, [{"id": "grpc1", "path": "/x", "protocol": "grpc"}, {"id": "ws1", "path": "/ws", "protocol": "ws"}])
    e1, t1 = mk_edge(client, "e1", "5.160.1.10")
    e2, t2 = mk_edge(client, "e2", "5.160.1.11")
    hb(client, t1)
    hb(client, t2)
    now = utcnow()
    # pre-wave-13 data only -> has_data false
    post_usage(client, t1, [usage_item({"grpc1": pc(5, origin_refused=2, limit=1)}, now - timedelta(hours=3))])
    d = client.get(f"{S}/tunnel/drops?hours=24").json()
    assert d["has_data"] is False and d["total"] == 0 and d["top"] is None
    assert d["rejected"] == {"limit": 1, "origin_refused": 2, "origin_timeout": 0}

    post_usage(client, t1, [usage_item({"grpc1": pc(60, ends=ends(normal=50, idle_timeout=8, node_reload=2),
                                                     origin_timeout=3),
                                        "ws1": pc(40, ends=ends(normal=38, origin=2))}, now)])
    post_usage(client, t2, [usage_item({"grpc1": pc(1, ends=ends(node_drain=1))}, now - timedelta(hours=1))])
    with SessionLocal() as db:
        e = db.get(Edge, e1)
        edge_state.add_event(db, e, "drain_start", {"by": "edge", "reason": "upgrade", "minutes": 15},
                             now - timedelta(hours=1))
        edge_state.add_event(db, e, "drain_start", {"by": "admin", "reason": "admin", "minutes": 15},
                             now - timedelta(minutes=30))
        edge_state.add_event(db, e, "degraded", {"fail": 3}, now - timedelta(minutes=20))
        e3 = Edge(name="e3", ipv4="5.160.1.12", token_hash="x" * 64)  # never served the site
        db.add(e3)
        db.flush()
        edge_state.add_event(db, e3, "upgrade", {"version": "2"}, now - timedelta(minutes=10))
        s = db.scalar(select(Site))
        s.over_quota, s.quota_warned_at = True, now - timedelta(days=1)
        db.commit()

    d = client.get(f"{S}/tunnel/drops?hours=24").json()
    assert d["hours"] == 24 and d["has_data"] is True and d["total"] == 101
    assert d["reasons"] == ends(normal=88, idle_timeout=8, origin=2, node_reload=2, node_drain=1)
    assert d["rejected"] == {"limit": 1, "origin_refused": 2, "origin_timeout": 3}
    assert d["top"] == "idle_timeout"  # 8 of 101 >= 5 %
    paths = {p["id"]: p for p in d["paths"]}
    assert paths["grpc1"]["total"] == 61 and paths["grpc1"]["top"] == "idle_timeout"
    assert paths["ws1"]["top"] == "origin"  # 2 of 40 = 5 % -> counts
    assert len(d["series"]) == 24 and sum(p["normal"] for p in d["series"]) == 88
    assert set(d["series"][0]) == {"t", *routes_edge.TUNNEL_END_KEYS}
    assert [m["kind"] for m in d["maintenance"]] == ["upgrade", "drain"]
    assert all(set(m) == {"t", "kind"} for m in d["maintenance"])
    blob = json.dumps(d)
    assert "e1" not in blob and "5.160.1.1" not in blob  # no node identity
    assert d["plan"]["suspended"] is False and d["plan"]["over_quota_since"].endswith("Z")

    assert client.get(f"{S}/tunnel/drops?hours=0").status_code == 422
    assert client.get(f"{S}/tunnel/drops?hours=745").status_code == 422
    stats = new_key(client, scopes=["stats"])["key"]
    dns = new_key(client, name="d", scopes=["dns"])["key"]
    assert client.get(f"{CAPI}/tunnel/drops?hours=24", headers=auth(stats)).json() == d
    assert client.get(f"{CAPI}/tunnel/drops", headers=auth(dns)).status_code == 403


def test_top_reason_threshold():
    assert tunnel_quality_top(ends(normal=96, origin=4), 100) is None
    assert tunnel_quality_top(ends(normal=95, origin=5), 100) == "origin"
    assert tunnel_quality_top(ends(normal=90, origin=5, other=5), 100) == "origin"  # ties: SPEC order
    assert tunnel_quality_top(ends(), 0) is None


def tunnel_quality_top(reasons, total):
    from app import tunnel_quality

    return tunnel_quality.top_reason(reasons, total)


# ================================================================== §22.8 TLS tickets, certificates

@pytest.fixture()
def enc_key(monkeypatch):
    key = Fernet.generate_key().decode()
    monkeypatch.setattr(settings, "data_encryption_key", key)
    return key


def test_tls_tickets_rotation_encryption_config_and_secrecy(client, enc_key, monkeypatch, caplog):
    caplog.set_level(logging.DEBUG)
    _, tok = mk_edge(client, "e1", "5.160.1.10")
    assert node_cfg(client, tok)["node"]["tls_tickets"] is None  # default off
    monkeypatch.setattr(settings, "tls_tickets", True)
    # the config request path never creates keys (only the scheduler leader does)
    assert node_cfg(client, tok)["node"]["tls_tickets"] is None
    t0 = utcnow()
    with SessionLocal() as db:
        assert tls_tickets.rotate(db, t0) is True
        raw = db.get(State, tls_tickets.STATE_KEY).value
    doc = json.loads(raw)
    assert doc["keys"].startswith("enc:v1:") and set(doc) == {"rotated_at", "keys"}
    blk = node_cfg(client, tok)["node"]["tls_tickets"]
    assert set(blk) == {"id", "keys"} and len(blk["keys"]) == 3
    raws = [base64.b64decode(k) for k in blk["keys"]]
    assert all(len(r) == 80 for r in raws) and len(set(raws)) == 3
    assert blk["id"] == hashlib.sha256(raws[0]).hexdigest()[:8]
    for k in blk["keys"]:
        assert k not in raw
    cur, nxt, prev = blk["keys"]

    with SessionLocal() as db:
        assert tls_tickets.rotate(db, t0 + timedelta(hours=23)) is False  # inside the period
        assert tls_tickets.rotate(db, t0 + timedelta(hours=23)) is False
        assert tls_tickets.rotate(db, t0 + timedelta(hours=24)) is True
    blk2 = node_cfg(client, tok)["node"]["tls_tickets"]
    # previous <- current, current <- next, next <- new; the old previous is gone
    assert blk2["keys"][0] == nxt and blk2["keys"][2] == cur and blk2["keys"][1] not in (cur, nxt, prev)
    assert prev not in json.dumps(node_cfg(client, tok))

    # never in the admin API, the audit log, /metrics or the logs
    everything = blk["keys"] + blk2["keys"]
    listing = client.get("/api/v1/edges").text + client.get("/metrics").text + client.get("/api/v1/overview").text
    with SessionLocal() as db:
        audit = " ".join(a.detail for a in db.scalars(select(AuditLog)))
    for k in everything:
        for blob in (listing, audit, caplog.text):
            assert k not in blob
            assert base64.b64decode(k).hex() not in blob

    # the scheduler job (leader only) is the one that rotates; turning tickets off forgets the keys
    assert scheduler.job_tls_tickets in scheduler.JOBS
    monkeypatch.setattr(settings, "tls_tickets", False)
    with SessionLocal() as db:
        scheduler.job_tls_tickets(db)
        assert db.get(State, tls_tickets.STATE_KEY) is None
    assert node_cfg(client, tok)["node"]["tls_tickets"] is None


def test_tls_tickets_refused_without_encryption_key(client, monkeypatch, caplog):
    monkeypatch.setattr(settings, "data_encryption_key", "")
    monkeypatch.setattr(settings, "tls_tickets", True)
    _, tok = mk_edge(client, "e1", "5.160.1.10")
    with SessionLocal() as db:
        assert tls_tickets.rotate(db) is False
        assert db.get(State, tls_tickets.STATE_KEY) is None
    assert node_cfg(client, tok)["node"]["tls_tickets"] is None
    with caplog.at_level(logging.WARNING):
        tls_tickets.startup_check()
    assert "DATA_ENCRYPTION_KEY" in caplog.text


def test_tls_ticket_keys_follow_key_rotation(client, enc_key, monkeypatch):
    from app import crypto

    monkeypatch.setattr(settings, "tls_tickets", True)
    with SessionLocal() as db:
        tls_tickets.rotate(db)
        before = tls_tickets.edge_block(db)
        new = Fernet.generate_key().decode()
        monkeypatch.setattr(settings, "data_encryption_key", f"{new},{enc_key}")
        assert crypto.rotate_all(db) >= 1
        monkeypatch.setattr(settings, "data_encryption_key", new)
        assert tls_tickets.edge_block(db) == before


def test_ocsp_detection_and_key_types():
    with_ocsp, _ = certs.chain(ocsp=True)
    assert sslmod.ocsp_capable(with_ocsp) is True
    assert sslmod.ocsp_capable(certs.chain(ocsp=True, with_issuer=False)[0]) is False  # issuer missing
    assert sslmod.ocsp_capable(certs.chain(ocsp=False)[0]) is False  # no OCSP URL (LE since 2025)
    assert sslmod.ocsp_capable("CERTDATA") is False
    assert sslmod.cert_key_type(certs.chain()[0]) == "ecdsa-p256"
    assert sslmod.cert_key_type(certs.chain(key_type="ec384")[0]) == "ecdsa-p384"
    assert sslmod.cert_key_type(certs.chain(key_type="rsa")[0]) == "rsa-2048"
    assert sslmod.cert_key_type("junk") is None
    assert sslmod.cert_valid(certs.chain()[0]) is True


def test_dual_rsa_issue_isolation_config_and_site_dict(client, enc_key, monkeypatch):
    tunnel_site(client)
    activate()
    _, tok = mk_edge(client, "e1", "5.160.1.10")
    ec_pair, rsa_pair = certs.chain(ocsp=True), certs.chain(key_type="rsa")
    calls = []

    def fake_run(args, timeout=600):
        calls.append(args[args.index("--keylength") + 1] if "--keylength" in args else "register")
        if "2048" in args and fail["rsa"]:
            raise sslmod.SslError("rsa boom")
        return "ok"

    def fake_read(base, domain):
        return ec_pair if base.endswith("_ecc") else rsa_pair

    fail = {"rsa": True}
    monkeypatch.setattr(sslmod, "_run", fake_run)
    monkeypatch.setattr(sslmod, "_read_pair", fake_read)
    monkeypatch.setattr(settings, "acme_dual_rsa", True)
    with SessionLocal() as db:
        s = db.scalar(select(Site))
        sslmod.issue(s)  # the RSA failure never fails the ECDSA issuance
        db.commit()
        assert s.ssl_status == "active" and s.ssl_cert == ec_pair[0] and s.ssl_cert_rsa is None
        fail["rsa"] = False
        sslmod.issue(s)
        db.commit()
        assert s.ssl_cert_rsa == rsa_pair[0] and s.ssl_key_rsa == rsa_pair[1]
        assert s.ssl_key_rsa_stored.startswith("enc:v1:")  # encrypted at rest
    assert calls.count("2048") == 2 and calls.count("ec-256") == 2
    blk = next(x for x in node_cfg(client, tok)["sites"] if x["domain"] == "example.com")["ssl"]
    assert blk == {"cert": ec_pair[0], "key": ec_pair[1], "cert_rsa": rsa_pair[0], "key_rsa": rsa_pair[1],
                   "ocsp": True}
    site = client.get(S).json()
    assert site["ssl_key_type"] == "ecdsa-p256" and site["ssl_dual_rsa"] is True
    assert rsa_pair[1] not in json.dumps(site)
    monkeypatch.setattr(settings, "acme_dual_rsa", False)
    blk = next(x for x in node_cfg(client, tok)["sites"] if x["domain"] == "example.com")["ssl"]
    assert set(blk) == {"cert", "key", "ocsp"}
    assert client.get(S).json()["ssl_dual_rsa"] is False


# ================================================================== §22.3 node.probe, §22.13 retention

@pytest.mark.parametrize("raw,want", [
    ("", None), ("echo.example.net:9000", {"host": "echo.example.net", "port": 9000, "tls": False}),
    ("185.1.2.3:443:tls", {"host": "185.1.2.3", "port": 443, "tls": True}),
    ("[2a01:4f8::1]:8443", {"host": "2a01:4f8::1", "port": 8443, "tls": False}),
    ("nohost", None), ("h:0", None), ("h:70000", None), ("bad host:80", None)])
def test_probe_origin_parsing(raw, want):
    assert edge_state.parse_probe_origin(raw) == want


def test_node_probe_block_and_non_rendered_keys(client, monkeypatch):
    _, tok = mk_edge(client, "e1", "5.160.1.10")
    node = node_cfg(client, tok)["node"]
    assert node["probe"] == {"origin": None, "interval": 60}
    assert set(node) >= {"drain", "probe", "http3", "tls_tickets", "dns_weight"}
    monkeypatch.setattr(settings, "tunnel_probe_origin", "echo.example.net:9000:tls")
    assert node_cfg(client, tok)["node"]["probe"]["origin"] == {"host": "echo.example.net", "port": 9000,
                                                                "tls": True}


def test_edge_events_pruned_after_90_days(client):
    (e1, _), _ = two_edges(client)
    now = utcnow()
    with SessionLocal() as db:
        e = db.get(Edge, e1)
        edge_state.add_event(db, e, "upgrade", {"version": "1"}, now - timedelta(days=91))
        edge_state.add_event(db, e, "upgrade", {"version": "2"}, now - timedelta(days=89))
        db.commit()
        scheduler.job_cleanup(db)
        left = [json.loads(ev.data)["version"] for ev in db.scalars(select(EdgeEvent))]
    assert left == ["2"]
    with SessionLocal() as db:
        assert edge_state.events_of(db, db.get(Edge, e1))[0]["kind"] == "upgrade"


def test_unreadable_rsa_key_is_dropped(client, enc_key, monkeypatch):
    from app import crypto

    tunnel_site(client)
    with SessionLocal() as db:
        s = db.scalar(select(Site))
        s.ssl_cert_rsa, s.ssl_key_rsa = "RSA-CERT", "RSA-KEY"
        db.commit()
    monkeypatch.setattr(settings, "data_encryption_key", Fernet.generate_key().decode())
    with SessionLocal() as db:
        assert "example.com" in crypto.drop_unreadable(db)
        s = db.scalar(select(Site))
        assert s.ssl_cert_rsa is None and s.ssl_key_rsa_stored is None
