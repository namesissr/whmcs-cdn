"""Tunnel mode (SPEC §7): plan features, the tunnel section, edge config, usage, edge groups,
load-aware DNS, load shedding + alerts, and the customer stats / check endpoints."""

import socket
import ssl as ssl_lib
import threading
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from app import alerts, dnsbuild, tunnel
from app.config import settings
from app.db import SessionLocal
from app.models import Edge, Site, UsageHourly, utcnow
from app.scheduler import job_edges
from tests.test_api import add_edge, edge_get
from tests.test_v2 import _cert

S = "/api/v1/sites/example.com"

PATHS = [
    {"id": "grpc1", "path": "/my-secret-service", "protocol": "grpc"},
    {"id": "ws1", "path": "/ws/v2ray", "protocol": "ws",
     "origin": {"address": "VPN.Example.NET", "tls": True, "sni": "Vpn.Example.net"}},
]


def site(client, features=None, origin="93.184.216.34", **plan):
    body = {"domain": "example.com", "plan": {**plan, "features": {"tunnel": True, **(features or {})}}}
    if origin:
        body["origin_ip"] = origin
    r = client.post("/api/v1/sites", json=body)
    assert r.status_code == 201, r.text
    return r.json()


def activate(domain="example.com"):
    with SessionLocal() as db:
        s = db.query(Site).filter_by(domain=domain).one()
        s.status, s.ns_verified_at = "active", utcnow()
        db.commit()


# ------------------------------------------------------------------ plan + section

def test_features_defaults_and_plan_patch(client):
    s = site(client, features={"tunnel": False})
    f = s["plan"]["features"]
    assert (f["tunnel"], f["max_tunnel_paths"], f["max_tunnel_connections"], f["tunnel_max_mbps"],
            f["edge_group"]) == (False, 10, 0, 0, "general")
    assert s["config"]["tunnel"] == {"enabled": False, "paths": [], "idle_timeout": 3600, "per_connection_mbps": 0,
                                     "max_connections_per_ip": 0, "allowed_countries": [], "fallback": "origin"}
    r = client.patch(f"{S}/plan", json={"features": {"tunnel": True, "edge_group": "tunnel", "tunnel_max_mbps": 20}})
    assert r.status_code == 200 and r.json()["plan"]["features"]["edge_group"] == "tunnel"
    for bad in ({"edge_group": "vip"}, {"max_tunnel_paths": 51}, {"max_tunnel_connections": -1},
                {"tunnel_max_mbps": -5}):
        assert client.patch(f"{S}/plan", json={"features": bad}).status_code == 422, bad


def test_tunnel_section_roundtrip_and_normalisation(client):
    site(client)
    client.put(f"{S}/config/pools", json={"pools": [{"name": "vpn", "origins": [{"address": "185.1.2.3"}]}]})
    body = {"enabled": True, "paths": PATHS + [
        {"id": "x1", "path": "/xh", "protocol": "xhttp", "pool": "vpn"},
        {"id": "h2", "path": "/h2", "protocol": "h2", "origin": {"address": "2a01:4f8::1", "port": 8443}},
    ], "allowed_countries": ["ir", "IR", " de "], "fallback": "decoy", "idle_timeout": 600}
    r = client.put(f"{S}/config/tunnel", json=body)
    assert r.status_code == 200, r.text
    t = r.json()
    assert t["allowed_countries"] == ["IR", "DE"]
    assert t["paths"][0] == {"id": "grpc1", "path": "/my-secret-service", "protocol": "grpc", "origin": None,
                             "pool": None}
    assert t["paths"][1]["origin"] == {"address": "vpn.example.net", "port": 443, "tls": True,
                                       "sni": "vpn.example.net", "verify": False}
    assert t["paths"][3]["origin"]["address"] == "[2a01:4f8::1]" and t["paths"][3]["origin"]["port"] == 8443
    assert client.get(f"{S}/config/tunnel").json() == t
    # a pool used by a tunnel path cannot be deleted
    assert client.put(f"{S}/config/pools", json={"pools": []}).status_code == 422


@pytest.mark.parametrize("body", [
    {"paths": [{"id": "a", "path": "/", "protocol": "ws"}]},
    {"paths": [{"id": "a", "path": "/__pcdn/x", "protocol": "ws"}]},
    {"paths": [{"id": "a", "path": "/__PCDN", "protocol": "ws"}]},
    {"paths": [{"id": "a", "path": "no-slash", "protocol": "ws"}]},
    {"paths": [{"id": "a", "path": "/a b", "protocol": "ws"}]},
    {"paths": [{"id": "a", "path": "/a?b", "protocol": "ws"}]},
    {"paths": [{"id": "a", "path": "/" + "a" * 201, "protocol": "ws"}]},
    {"paths": [{"id": "A!", "path": "/a", "protocol": "ws"}]},
    {"paths": [{"id": "a", "path": "/a", "protocol": "ssh"}]},
    {"paths": [{"id": "a", "path": "/a", "protocol": "ws"}, {"id": "a", "path": "/b", "protocol": "ws"}]},
    {"paths": [{"id": "a", "path": "/a", "protocol": "ws"}, {"id": "b", "path": "/a", "protocol": "grpc"}]},
    {"paths": [{"id": "a", "path": "/a", "protocol": "ws", "origin": {"address": "1.2.3.4"}, "pool": "vpn"}]},
    {"paths": [{"id": "a", "path": "/a", "protocol": "ws", "origin": {"address": "10.0.0.1"}}]},
    {"paths": [{"id": "a", "path": "/a", "protocol": "ws", "origin": {"address": "127.0.0.1", "port": 80}}]},
    {"paths": [{"id": "a", "path": "/a", "protocol": "ws", "origin": {"address": "bad host!"}}]},
    {"paths": [{"id": "a", "path": "/a", "protocol": "ws", "origin": {"address": "1.2.3.4", "port": 70000}}]},
    {"paths": [{"id": "a", "path": "/a", "protocol": "ws", "origin": {"address": "1.2.3.4", "sni": "a b"}}]},
    {"paths": [{"id": "a", "path": "/a", "protocol": "ws", "origin": {"address": "1.2.3.4", "x": 1}}]},
    {"paths": [{"id": "a", "path": "/a", "protocol": "ws", "pool": "missing"}]},
    {"idle_timeout": 10},
    {"idle_timeout": 100000},
    {"max_connections_per_ip": 10001},
    {"per_connection_mbps": -1},
    {"allowed_countries": ["IRN"]},
    {"fallback": "redirect"},
    {"unknown": True},
])
def test_tunnel_section_rejects(client, body):
    site(client)
    r = client.put(f"{S}/config/tunnel", json={"enabled": True, **body})
    assert r.status_code == 422, r.text
    assert r.json()["detail"]


def test_tunnel_plan_gate_and_limits(client):
    site(client, features={"tunnel": False, "max_tunnel_paths": 1, "tunnel_max_mbps": 10})
    one = {"paths": PATHS[:1]}
    r = client.put(f"{S}/config/tunnel", json={"enabled": True, **one})
    assert r.status_code == 403 and "پلن" in r.json()["detail"]
    # turning things off (or keeping them off) is always allowed
    assert client.put(f"{S}/config/tunnel", json={"enabled": False, **one}).status_code == 200
    client.patch(f"{S}/plan", json={"features": {"tunnel": True}})
    assert client.put(f"{S}/config/tunnel", json={"enabled": True, **one}).status_code == 200
    assert client.put(f"{S}/config/tunnel", json={"enabled": True, "paths": PATHS}).status_code == 403
    assert client.put(f"{S}/config/tunnel", json={"per_connection_mbps": 11}).status_code == 403
    assert client.put(f"{S}/config/tunnel", json={"per_connection_mbps": 10}).status_code == 200
    assert client.put(f"{S}/config/tunnel", json={"per_connection_mbps": 0}).status_code == 200


# ------------------------------------------------------------------ edge config

def test_edge_config_tunnel(client):
    site(client, features={"max_tunnel_connections": 500, "tunnel_max_mbps": 20})
    client.put(f"{S}/config/pools", json={"pools": [{"name": "vpn", "origins": [{"address": "185.1.2.3"}]}]})
    body = {"enabled": True, "per_connection_mbps": 0, "max_connections_per_ip": 8,
            "paths": PATHS + [{"id": "x1", "path": "/xh", "protocol": "xhttp", "pool": "vpn"}]}
    assert client.put(f"{S}/config/tunnel", json=body).status_code == 200
    token = add_edge(client)

    def cfg():
        return edge_get(client, token, "/edge/v1/config").json()["sites"][0]["tunnel"]

    t = cfg()
    assert t["enabled"] is False  # site not active yet (pending_ns)
    assert t["max_connections"] == 500 and t["per_connection_mbps"] == 20  # plan cap folded in
    assert t["max_connections_per_ip"] == 8 and [p["id"] for p in t["paths"]] == ["grpc1", "ws1", "x1"]

    activate()
    r = edge_get(client, token, "/edge/v1/config")
    etag = r.headers["etag"]
    assert r.json()["sites"][0]["tunnel"]["enabled"] is True
    assert edge_get(client, token, "/edge/v1/config", headers={"If-None-Match": etag}).status_code == 304

    # load balancing switched off by the plan: the pool path disappears with the pools
    client.patch(f"{S}/plan", json={"features": {"load_balancer": False}})
    assert [p["id"] for p in cfg()["paths"]] == ["grpc1", "ws1"]
    client.patch(f"{S}/plan", json={"features": {"tunnel": False}})
    t = cfg()
    assert t["enabled"] is False and t["paths"]
    r = edge_get(client, token, "/edge/v1/config", headers={"If-None-Match": etag})
    assert r.status_code == 200 and r.headers["etag"] != etag
    client.post(f"{S}/suspend")
    client.patch(f"{S}/plan", json={"features": {"tunnel": True}})
    assert cfg()["enabled"] is False


# ------------------------------------------------------------------ usage + stats

def test_usage_tunnel_ingestion_billing_and_stats(client):
    site(client)
    token = add_edge(client)
    hour = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
    item = {"host": "www.example.com", "hour": hour.isoformat(), "bytes": 1000, "requests": 3,
            "tunnel": {"sessions": 3, "seconds": 5400.4, "bytes_up": 123, "bytes_down": 456,
                       "by_protocol": {"grpc": 579, "evil": 5}}}
    plain = {"host": "example.com", "hour": hour.isoformat(), "bytes": 10, "requests": 1}
    auth = {"Authorization": f"Bearer {token}"}
    for _ in range(2):
        r = client.post("/edge/v1/usage", json={"items": [item, plain]}, headers=auth)
        assert r.status_code == 200, r.text
    bad = dict(item, tunnel={"bytes_up": -1})
    assert client.post("/edge/v1/usage", json={"items": [bad]}, headers=auth).status_code == 422

    # both directions are billed: bytes + bytes_up
    u = client.get("/api/v1/usage").json()["sites"][0]
    assert u["bytes"] == 2 * (1000 + 123 + 10) and u["requests"] == 8
    assert client.get(S).json()["usage_month"]["bytes"] == 2 * 1133
    with SessionLocal() as db:
        (row,) = db.query(UsageHourly).all()
        assert '"tunnel"' in row.details

    st = client.get(f"{S}/tunnel/stats?hours=24").json()
    assert len(st["hours"]) == 24 and st["hours"][-1] == {
        "hour": hour.strftime("%Y-%m-%dT%H:00:00Z"), "sessions": 6, "seconds": 10800, "bytes_up": 246,
        "bytes_down": 912}
    assert st["hours"][0]["sessions"] == 0
    assert st["by_protocol"] == {"grpc": 1158}
    assert st["totals"] == {"sessions": 6, "bytes_up": 246, "bytes_down": 912}
    assert len(client.get(f"{S}/tunnel/stats?hours=0").json()["hours"]) == 1
    assert client.get("/api/v1/sites/nope.com/tunnel/stats").status_code == 404


# ------------------------------------------------------------------ edges: groups, capacity, metrics

def test_edge_create_and_patch_json_and_query(client):
    r = client.post("/api/v1/edges", json={"name": "ir-t1", "ipv4": "5.160.1.20", "region": "home",
                                           "group": "tunnel", "capacity_mbps": 1000})
    assert r.status_code == 201
    e = r.json()
    assert (e["group"], e["capacity_mbps"], e["metrics"], e["shed"]) == ("tunnel", 1000, None, False)
    assert client.post("/api/v1/edges", json={"name": "x", "ipv4": "5.160.1.21", "group": "vip"}).status_code == 422
    add_edge(client, "ir-g1", "5.160.1.10")  # v1 body: defaults
    assert client.get("/api/v1/edges").json()[1]["group"] == "general"

    eid = e["id"]
    # v1 query string (WHMCS module)
    r = client.patch(f"/api/v1/edges/{eid}?enabled=false")
    assert r.status_code == 200 and r.json()["ok"] and r.json()["edge"]["enabled"] is False
    r = client.patch(f"/api/v1/edges/{eid}", json={"enabled": True, "group": "general", "capacity_mbps": 250,
                                                   "region": "global"})
    assert r.status_code == 200, r.text
    got = r.json()["edge"]
    assert (got["enabled"], got["group"], got["capacity_mbps"], got["region"]) == (True, "general", 250, "global")
    for bad in ({"group": "vip"}, {"capacity_mbps": -1}, {"region": "mars"}, {"name": "x"}, {}):
        assert client.patch(f"/api/v1/edges/{eid}", json=bad).status_code == 422, bad
    assert client.patch(f"/api/v1/edges/{eid}").status_code == 422
    assert client.patch("/api/v1/edges/999?enabled=true").status_code == 404


def heartbeat(client, token, **metrics):
    body = {"applied_version": "v"}
    if metrics:
        body["metrics"] = {"connections": 10, "load1": 0.5, "cpus": 4, **metrics}
    r = client.post("/edge/v1/heartbeat", json=body, headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200, r.text


def edge_obj(client, name):
    return next(e for e in client.get("/api/v1/edges").json() if e["name"] == name)


def test_heartbeat_metrics_and_shed_hysteresis(client, monkeypatch):
    monkeypatch.setattr(settings, "edge_shed_percent", 90.0)
    client.post("/api/v1/edges", json={"name": "t1", "ipv4": "5.160.1.20", "capacity_mbps": 100})
    token = client.post("/api/v1/edges/1/rotate-token").json()["token"]
    heartbeat(client, token)  # v1 agent: no metrics
    assert edge_obj(client, "t1")["metrics"] is None
    heartbeat(client, token, rx_mbps=12.5, tx_mbps=80.1)
    e = edge_obj(client, "t1")
    assert e["metrics"]["tx_mbps"] == 80.1 and e["metrics"]["at"].endswith("Z") and not e["shed"]
    heartbeat(client, token, rx_mbps=10, tx_mbps=91)
    assert edge_obj(client, "t1")["shed"]
    heartbeat(client, token, rx_mbps=80, tx_mbps=10)  # between 75 and 90: stays shed
    assert edge_obj(client, "t1")["shed"]
    heartbeat(client, token, rx_mbps=74, tx_mbps=10)
    assert not edge_obj(client, "t1")["shed"]
    heartbeat(client, token, rx_mbps=95, tx_mbps=10)
    assert edge_obj(client, "t1")["shed"]
    # capacity unknown -> never shed
    client.patch("/api/v1/edges/1", json={"capacity_mbps": 0})
    assert not edge_obj(client, "t1")["shed"]
    bad = {"metrics": {"rx_mbps": -1}}
    assert client.post("/edge/v1/heartbeat", json=bad, headers={"Authorization": f"Bearer {token}"}).status_code == 422


# ------------------------------------------------------------------ DNS

def rec(name, type_, content, proxied=False):
    return SimpleNamespace(name=name, type=type_, content=content, proxied=proxied, priority=None, ttl=300)


def edge(ip, region="home", group="general", shed=False, ipv6=None, fresh=True):
    at = utcnow() - (timedelta(seconds=5) if fresh else timedelta(hours=1))
    return SimpleNamespace(ipv4=ip, ipv6=ipv6, region=region, group=group, shed=shed, metrics_at=at)


def answer(site, edges):
    rr = {(r["name"], r["type"]): r for r in dnsbuild.build_rrsets(site, edges)}
    return rr[("ex.com.", "LUA")]["records"][0]["content"]


def tsite(group):
    return SimpleNamespace(domain="ex.com", features=f'{{"edge_group": "{group}"}}',
                           records=[rec("@", "A", "1.2.3.4", proxied=True)])


def test_dns_edge_group_and_fail_open():
    edges = [edge("5.5.5.1"), edge("5.5.5.2", group="tunnel"), edge("8.8.4.1", "global")]
    a = answer(tsite("tunnel"), edges)
    assert "5.5.5.2" in a and "5.5.5.1" not in a and "8.8.4.1" not in a
    a = answer(tsite("general"), edges)
    assert "5.5.5.1" in a and "8.8.4.1" in a and "5.5.5.2" not in a
    # legacy site without the feature -> general
    legacy = SimpleNamespace(domain="ex.com", features="{}", records=tsite("x").records)
    assert "5.5.5.2" not in answer(legacy, edges)
    # no tunnel edge online: every online edge answers (fail open)
    a = answer(tsite("tunnel"), [edges[0], edges[2]])
    assert "5.5.5.1" in a and "8.8.4.1" in a


def test_dns_geo_pools_follow_the_group(monkeypatch):
    monkeypatch.setattr(settings, "geoip_enabled", True)
    edges = [edge("5.5.5.1", group="tunnel", ipv6="2a01::5"), edge("5.5.5.2"), edge("8.8.4.1", "global")]
    site = tsite("tunnel")
    rr = {(r["name"], r["type"]): r for r in dnsbuild.build_rrsets(site, edges)}
    lua = [r["content"] for r in rr[("ex.com.", "LUA")]["records"]]
    # only a home edge in the tunnel group: no geo split, everyone gets it (v4 and v6)
    assert "countryCode" not in lua[0] and "5.5.5.1" in lua[0] and "8.8.4.1" not in lua[0]
    assert lua[1].startswith('AAAA "') and "2a01::5" in lua[1]
    assert "'home-only'" in rr[("_pcdn-geo.ex.com.", "LUA")]["records"][0]["content"]
    # general group has both pools: geo split as before
    a = answer(tsite("general"), edges)
    assert "if home then" in a and "5.5.5.2" in a and "8.8.4.1" in a


def test_dns_load_shedding():
    site = tsite("general")
    a = answer(site, [edge("5.5.5.1", shed=True), edge("5.5.5.2"), edge("8.8.4.1", "global")])
    assert "5.5.5.1" not in a and "5.5.5.2" in a
    # the only edge of its pool stays in even when shed
    a = answer(site, [edge("5.5.5.1"), edge("8.8.4.1", "global", shed=True)])
    assert "8.8.4.1" in a
    # all shed in a pool: keep them all
    a = answer(site, [edge("5.5.5.1", shed=True), edge("5.5.5.2", shed=True)])
    assert "5.5.5.1" in a and "5.5.5.2" in a
    # stale metrics do not shed
    a = answer(site, [edge("5.5.5.1", shed=True, fresh=False), edge("5.5.5.2")])
    assert "5.5.5.1" in a
    # edges without the new attributes (older callers) behave as general, not shed
    old = SimpleNamespace(ipv4="5.5.5.9", ipv6=None, region="home")
    assert "5.5.5.9" in answer(site, [old])


def test_scheduler_resyncs_dns_on_shed_and_group_changes(client, fake_pdns, monkeypatch):
    monkeypatch.setattr(settings, "edge_shed_percent", 90.0)
    site(client)
    t1 = add_edge(client, "ir-1", "5.160.1.10")
    t2 = add_edge(client, "ir-2", "5.160.1.11")
    client.patch("/api/v1/edges/1", json={"capacity_mbps": 100})
    for t in (t1, t2):
        heartbeat(client, t, rx_mbps=1, tx_mbps=1)

    def lua():
        with SessionLocal() as db:
            job_edges(db)
        return fake_pdns.rrset("example.com.", "example.com.", "LUA")["records"][0]["content"]

    assert "5.160.1.10" in lua() and "5.160.1.11" in lua()
    heartbeat(client, t1, rx_mbps=1, tx_mbps=95)
    a = lua()
    assert "5.160.1.10" not in a and "5.160.1.11" in a
    heartbeat(client, t1, rx_mbps=1, tx_mbps=50)
    assert "5.160.1.10" in lua()

    # moving the site to the tunnel group: ir-2 becomes a tunnel edge -> only it answers
    client.patch("/api/v1/edges/2", json={"group": "tunnel"})
    assert "5.160.1.10" in lua()  # site still general
    client.patch(f"{S}/plan", json={"features": {"edge_group": "tunnel"}})
    a = fake_pdns.rrset("example.com.", "example.com.", "LUA")["records"][0]["content"]
    assert "5.160.1.11" in a and "5.160.1.10" not in a


# ------------------------------------------------------------------ alerts

def test_edge_saturated_alert(client, alert_settings, monkeypatch):
    monkeypatch.setattr(settings, "edge_shed_percent", 90.0)
    client.post("/api/v1/edges", json={"name": "t1", "ipv4": "5.160.1.20", "capacity_mbps": 100})
    token = client.post("/api/v1/edges/1/rotate-token").json()["token"]

    def check():
        with SessionLocal() as db:
            alerts.check_edge_load(db)
        return {c["key"]: c for c in alerts.open_alerts()}

    heartbeat(client, token, rx_mbps=85, tx_mbps=1)
    heartbeat(client, token, rx_mbps=85, tx_mbps=1)
    assert check() == {}  # > 80 % for only 2 reports
    heartbeat(client, token, rx_mbps=85, tx_mbps=1)
    c = check()["edge_saturated:1"]
    assert c["severity"] == "warning" and "85٪" in c["text"]
    heartbeat(client, token, rx_mbps=10, tx_mbps=1)
    assert check() == {}
    heartbeat(client, token, rx_mbps=99, tx_mbps=1)  # shed at once
    c = check()["edge_saturated:1"]
    assert c["severity"] == "critical" and "EDGE_SHED_PERCENT" in c["text"]
    # an edge that stopped reporting is covered by edge_offline instead
    with SessionLocal() as db:
        db.get(Edge, 1).last_seen_at = utcnow() - timedelta(hours=1)
        db.commit()
    assert check() == {}


# ------------------------------------------------------------------ reachability check

class Server:
    """Local TCP (optionally TLS) server accepting any number of connections."""

    def __init__(self, tls_files=None):
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.port = self.sock.getsockname()[1]
        self.ctx = None
        if tls_files:
            self.ctx = ssl_lib.SSLContext(ssl_lib.PROTOCOL_TLS_SERVER)
            self.ctx.load_cert_chain(*tls_files)
        threading.Thread(target=self.run, daemon=True).start()

    def run(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            try:
                if self.ctx:
                    conn.settimeout(5)
                    conn = self.ctx.wrap_socket(conn, server_side=True)
            except (OSError, ssl_lib.SSLError):
                pass
            finally:
                conn.close()

    def close(self):
        self.sock.close()


def test_tunnel_check(client, monkeypatch, tmp_path):
    monkeypatch.setattr(tunnel, "_public", lambda ip: True)  # the test servers live on 127.0.0.1
    cert, key = _cert(tmp_path, "localhost")
    (tmp_path / "c.pem").write_text(cert)
    (tmp_path / "k.pem").write_text(key)
    plain, tls = Server(), Server((tmp_path / "c.pem", tmp_path / "k.pem"))
    closed = socket.socket()
    closed.bind(("127.0.0.1", 0))
    closed_port = closed.getsockname()[1]
    closed.close()
    try:
        site(client, origin=None)
        # the host's own origin: @ -> localhost:<plain>
        r = client.post(f"{S}/records", json={"name": "@", "type": "CNAME", "content": "localhost", "proxied": True,
                                              "origin_port": plain.port})
        assert r.status_code == 201, r.text
        client.put(f"{S}/config/pools", json={"pools": [{"name": "vpn", "origins": [
            {"address": "localhost", "port": closed_port}, {"address": "localhost", "port": plain.port}]}]})
        paths = [
            {"id": "own", "path": "/own", "protocol": "ws"},
            {"id": "tcp", "path": "/tcp", "protocol": "ws", "origin": {"address": "localhost", "port": plain.port}},
            {"id": "closed", "path": "/closed", "protocol": "ws",
             "origin": {"address": "localhost", "port": closed_port}},
            {"id": "tls", "path": "/tls", "protocol": "grpc",
             "origin": {"address": "localhost", "port": tls.port, "tls": True, "sni": "localhost"}},
            {"id": "tlsv", "path": "/tlsv", "protocol": "grpc",
             "origin": {"address": "localhost", "port": tls.port, "tls": True, "verify": True}},
            {"id": "pool", "path": "/pool", "protocol": "xhttp", "pool": "vpn"},
            {"id": "nx", "path": "/nx", "protocol": "ws", "origin": {"address": "nx.invalid", "port": 1}},
        ]
        r = client.put(f"{S}/config/tunnel", json={"enabled": True, "paths": paths})
        assert r.status_code == 200, r.text
        r = client.post(f"{S}/tunnel/check")
        assert r.status_code == 200, r.text
        res = {x["id"]: x for x in r.json()["results"]}
        assert list(res) == [p["id"] for p in paths]
        for ok in ("own", "tcp", "tls", "pool"):
            assert res[ok]["ok"] and isinstance(res[ok]["ms"], int) and res[ok]["error"] is None, res[ok]
        assert not res["closed"]["ok"] and res["closed"]["ms"] is None and "رد شد" in res["closed"]["error"]
        assert not res["tlsv"]["ok"] and "گواهی" in res["tlsv"]["error"]  # self-signed
        assert not res["nx"]["ok"] and res["nx"]["error"]
    finally:
        plain.close()
        tls.close()


def test_tunnel_check_refuses_private_addresses(client, monkeypatch):
    site(client, origin=None)
    client.post(f"{S}/records", json={"name": "@", "type": "CNAME", "content": "localhost", "proxied": True})
    client.put(f"{S}/config/tunnel", json={"paths": [{"id": "own", "path": "/own", "protocol": "ws"}]})
    (res,) = client.post(f"{S}/tunnel/check").json()["results"]
    assert res["ok"] is False and "عمومی" in res["error"]
    # no proxied record at all
    client.delete(f"{S}/records/{client.get(f'{S}/records').json()[0]['id']}")
    (res,) = client.post(f"{S}/tunnel/check").json()["results"]
    assert res["ok"] is False and "پروکسی" in res["error"]


def test_probe_tries_every_address(monkeypatch):
    """A dual-stack origin whose first address is unreachable (e.g. localhost -> ::1 first) is still reachable."""
    monkeypatch.setattr(tunnel, "_public", lambda ip: True)
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    def fake(host, p, *a, **k):
        return [(socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("::1", p, 0, 0)),
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.2", p)),
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", p))]
    monkeypatch.setattr(tunnel.socket, "getaddrinfo", fake)
    try:
        # IPv4 first; a refused address (nothing listens on 127.0.0.2) falls through to the next one
        assert tunnel._resolve("dual.example", port) == ["127.0.0.2", "127.0.0.1", "::1"]
        with tunnel._connect(["127.0.0.2", "127.0.0.1"], port) as s:
            assert s.getpeername()[0] == "127.0.0.1"
        assert tunnel.probe({"address": "dual.example", "port": port})["ok"]
        closed = socket.socket()
        closed.bind(("127.0.0.1", 0))
        closed_port = closed.getsockname()[1]
        closed.close()
        assert "رد شد" in tunnel.probe({"address": "dual.example", "port": closed_port})["error"]
    finally:
        srv.close()
