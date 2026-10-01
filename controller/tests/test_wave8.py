"""Wave 8 controller side (SPEC §16.4 L4 proxy, §16.5 video, §16.6 images v2, §16.7 DNS weighted /
failover records + secondary DNS)."""

import base64
import hashlib
import hmac
import http.server
import socket
import threading
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
from sqlalchemy import select

from app import dnsbuild, images, record_health, routes_capi, scheduler
from app.config import settings
from app.db import SessionLocal
from app.models import L4Port, Record, Site
from app.scheduler import job_edges
from tests.test_api import add_edge, edge_get

S = "/api/v1/sites/example.com"
TSIG = base64.b64encode(b"0123456789abcdef0123456789abcdef").decode()


def make_site(client, domain="example.com", **features):
    r = client.post("/api/v1/sites", json={"domain": domain, "origin_ip": "93.184.216.34",
                                           "plan": {"features": features}})
    assert r.status_code == 201, r.text
    return r.json()


def activate(domain="example.com"):
    with SessionLocal() as db:
        site = db.scalar(select(Site).where(Site.domain == domain))
        site.status = "active"
        db.commit()


def online_edge(client, name="ir-1", ip="5.160.1.10", group="general"):
    r = client.post("/api/v1/edges", json={"name": name, "ipv4": ip, "region": "home", "group": group})
    assert r.status_code == 201, r.text
    token = r.json()["token"]
    assert edge_get(client, token, "/edge/v1/config").status_code == 200  # heartbeat-ish: now online
    return token


def l4_app(app_id="game", port=None, **kw):
    app = {"id": app_id, "protocol": "tcp", "origin": {"address": "93.184.216.34", "port": 25565}, **kw}
    if port is not None:
        app["edge_port"] = port
    return app


# ------------------------------------------------------------------ §16.4 TCP/UDP proxy

def test_l4_plan_gate_and_limit(client):
    make_site(client)
    assert client.put(f"{S}/config/l4", json={"apps": []}).status_code == 200  # the off shape always
    r = client.put(f"{S}/config/l4", json={"apps": [l4_app()]})
    assert r.status_code == 403, r.text
    client.patch(f"{S}/plan", json={"features": {"l4_proxy": True, "max_l4_apps": 1}})
    assert client.put(f"{S}/config/l4", json={"apps": [l4_app()]}).status_code == 200
    r = client.put(f"{S}/config/l4", json={"apps": [l4_app("a"), l4_app("b")]})
    assert r.status_code == 403 and "حداکثر 1" in r.text
    features = client.get(S).json()["plan"]["features"]
    assert features["l4_proxy"] is True and features["max_l4_apps"] == 1


def test_l4_validation(client):
    make_site(client, l4_proxy=True, max_l4_apps=10)
    bad = [
        {"apps": [l4_app(protocol="udp", proxy_protocol="v2")]},
        {"apps": [l4_app(proxy_protocol="v2")]},                             # edges send PROXY v1 only            # PROXY protocol is tcp only
        {"apps": [l4_app(port=80)]},                                          # below 1024
        {"apps": [l4_app(port=30000)]},                                       # outside L4_PORT_RANGE
        {"apps": [l4_app("a", 20010), l4_app("b", 20010)]},                   # same port twice
        {"apps": [l4_app("a"), l4_app("a")]},                                 # duplicate id
        {"apps": [l4_app("Bad_ID")]},                                         # not a DNS label
        {"apps": [l4_app(ip_allow=["nope"])]},
        {"apps": [l4_app(idle_timeout=5)]},
        {"apps": [{**l4_app(), "origin": {"address": "10.0.0.1", "port": 22}}]},  # private origin
    ]
    for body in bad:
        assert client.put(f"{S}/config/l4", json=body).status_code == 422, body
    # a record already named l4-<id> blocks that app id, and the other way round
    client.post(f"{S}/records", json={"name": "l4-taken", "type": "A", "content": "93.184.216.35"})
    assert client.put(f"{S}/config/l4", json={"apps": [l4_app("taken")]}).status_code == 422
    assert client.put(f"{S}/config/l4", json={"apps": [l4_app("mine")]}).status_code == 200
    r = client.post(f"{S}/records", json={"name": "l4-mine", "type": "A", "content": "93.184.216.35"})
    assert r.status_code == 422


def test_l4_port_allocation_and_conflicts(client, monkeypatch):
    make_site(client, l4_proxy=True, max_l4_apps=10)
    make_site(client, "other.com", l4_proxy=True, max_l4_apps=10)
    make_site(client, "tun.com", l4_proxy=True, max_l4_apps=10, edge_group="tunnel")

    r = client.put(f"{S}/config/l4", json={"apps": [l4_app("a"), l4_app("b", ip_allow=["1.2.3.4"]),
                                                    l4_app("c", 20005, protocol="udp")]})
    assert r.status_code == 200, r.text
    apps = {a["id"]: a for a in r.json()["apps"]}
    assert (apps["a"]["edge_port"], apps["b"]["edge_port"], apps["c"]["edge_port"]) == (20000, 20001, 20005)
    assert apps["a"]["hostname"] == "l4-a.example.com"
    assert apps["b"]["ip_allow"] == ["1.2.3.4/32"]
    # ports are kept when the app is written again without one; GET shows the same
    r = client.put(f"{S}/config/l4", json={"apps": [l4_app("b"), l4_app("a")]})
    assert {a["id"]: a["edge_port"] for a in r.json()["apps"]} == {"a": 20000, "b": 20001}
    got = client.get(f"{S}/config/l4").json()
    assert {a["id"]: (a["edge_port"], a["hostname"]) for a in got["apps"]} == {
        "a": (20000, "l4-a.example.com"), "b": (20001, "l4-b.example.com")}

    # another site of the same group: explicit conflict -> 409, automatic -> the next free port
    r = client.put("/api/v1/sites/other.com/config/l4", json={"apps": [l4_app("x", 20000)]})
    assert r.status_code == 409, r.text
    r = client.put("/api/v1/sites/other.com/config/l4", json={"apps": [l4_app("x")]})
    assert r.json()["apps"][0]["edge_port"] == 20002  # 20005 was released by the rewrite above
    # another edge group has its own port space
    r = client.put("/api/v1/sites/tun.com/config/l4", json={"apps": [l4_app("y", 20000)]})
    assert r.status_code == 200, r.text
    # the failed write did not keep anything; the table holds exactly the stored apps
    with SessionLocal() as db:
        rows = sorted((p.group, p.port, p.app_id) for p in db.scalars(select(L4Port)))
    assert rows == [("general", 20000, "a"), ("general", 20001, "b"), ("general", 20002, "x"),
                    ("tunnel", 20000, "y")]

    # an exhausted range -> 409
    monkeypatch.setattr(settings, "l4_port_range", (20000, 20002))
    r = client.put("/api/v1/sites/other.com/config/l4", json={"apps": [l4_app("x"), l4_app("z")]})
    assert r.status_code == 409

    # deleting a site frees its ports
    assert client.delete("/api/v1/sites/other.com").status_code == 200
    r = client.put(f"{S}/config/l4", json={"apps": [l4_app("a"), l4_app("b"), l4_app("c")]})
    assert [a["edge_port"] for a in r.json()["apps"]] == [20000, 20001, 20002]


def test_l4_plan_group_change_rehomes_ports(client):
    make_site(client, l4_proxy=True, max_l4_apps=10)
    make_site(client, "tun.com", l4_proxy=True, max_l4_apps=10, edge_group="tunnel")
    client.put(f"{S}/config/l4", json={"apps": [l4_app("a", 20000), l4_app("b", 20001)]})
    client.put("/api/v1/sites/tun.com/config/l4", json={"apps": [l4_app("t", 20000)]})
    r = client.patch(f"{S}/plan", json={"features": {"edge_group": "tunnel"}})
    assert r.status_code == 200, r.text
    assert r.json()["l4_reallocated"] == [{"app_id": "a", "old_port": 20000, "new_port": 20002}]
    with SessionLocal() as db:
        rows = sorted((p.group, p.port, p.app_id) for p in db.scalars(select(L4Port)))
    assert rows == [("tunnel", 20000, "t"), ("tunnel", 20001, "b"), ("tunnel", 20002, "a")]
    assert {a["id"]: a["edge_port"] for a in client.get(f"{S}/config/l4").json()["apps"]} == {"a": 20002, "b": 20001}


def test_l4_edge_config_and_dns(client, fake_pdns):
    make_site(client, l4_proxy=True, max_l4_apps=10)
    activate()
    t_gen = online_edge(client, "ir-1", "5.160.1.10")
    t_tun = online_edge(client, "tun-1", "5.160.1.11", group="tunnel")
    r = client.put(f"{S}/config/l4", json={"apps": [
        l4_app("game", proxy_protocol="v1", ip_allow=["1.2.3.0/24"], idle_timeout=600),
        l4_app("off", enabled=False)]})
    assert r.status_code == 200, r.text
    cfg = edge_get(client, t_gen, "/edge/v1/config").json()
    assert cfg["l4"] == [{"site": "example.com", "site_id": cfg["sites"][0]["id"], "app_id": "game",
                          "hostname": "l4-game.example.com", "protocol": "tcp", "port": 20000,
                          "origin": {"address": "93.184.216.34", "port": 25565}, "proxy_protocol": "v1",
                          "ip_allow": ["1.2.3.0/24"], "idle_timeout": 600}]
    assert cfg["sites"][0]["l4"] == {"apps": [{
        "id": "game", "protocol": "tcp", "edge_port": 20000, "origin": {"address": "93.184.216.34", "port": 25565},
        "proxy_protocol": "v1", "ip_allow": ["1.2.3.0/24"], "idle_timeout": 600, "enabled": True,
        "hostname": "l4-game.example.com"}]}
    tun_cfg = edge_get(client, t_tun, "/edge/v1/config").json()
    assert tun_cfg["l4"] == [] and tun_cfg["sites"][0]["l4"] == {"apps": []}  # other group

    # DNS: l4-game answers with the site's edges (never the origin), l4-off does not exist
    with SessionLocal() as db:
        job_edges(db)
    lua = fake_pdns.rrset("example.com.", "l4-game.example.com.", "LUA")
    assert lua and "5.160.1.10" in lua["records"][0]["content"] and "93.184.216.34" not in str(lua)
    assert fake_pdns.rrset("example.com.", "l4-off.example.com.", "LUA") is None

    # suspended site / plan without l4_proxy -> no listeners
    client.post(f"{S}/suspend")
    assert edge_get(client, t_gen, "/edge/v1/config").json()["l4"] == []
    client.post(f"{S}/unsuspend")
    assert len(edge_get(client, t_gen, "/edge/v1/config").json()["l4"]) == 1
    client.patch(f"{S}/plan", json={"features": {"l4_proxy": False}})
    assert edge_get(client, t_gen, "/edge/v1/config").json()["l4"] == []
    assert fake_pdns.rrset("example.com.", "l4-game.example.com.", "LUA") is None
    client.patch(f"{S}/plan", json={"features": {"l4_proxy": True}})
    assert fake_pdns.rrset("example.com.", "l4-game.example.com.", "LUA") is not None

    # deleting the app removes its name
    assert client.put(f"{S}/config/l4", json={"apps": []}).status_code == 200
    assert fake_pdns.rrset("example.com.", "l4-game.example.com.", "LUA") is None


def test_l4_and_video_usage(client):
    make_site(client, l4_proxy=True, max_l4_apps=10)
    token = add_edge(client)
    hour = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0).isoformat()
    items = [
        {"host": "example.com", "hour": hour, "bytes": 1000, "requests": 4,
         "video": {"bytes": 800, "requests": 3, "cache_hits": 2}},
        {"host": "l4-game.example.com", "hour": hour, "bytes": 0, "requests": 0,
         "l4": {"game": {"bytes_in": 100, "bytes_out": 400, "sessions": 2}, "BAD id": {"bytes_in": 5}}},
        {"host": "example.com", "hour": hour, "bytes": 0, "requests": 0, "video": 50,
         "l4": {"game": {"bytes_in": 1, "bytes_out": 2, "sessions": 1}, "voice": {"sessions": 1}}},
    ]
    r = client.post("/edge/v1/usage", json={"items": items}, headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200, r.text
    # l4 bytes are billed in both directions on top of the HTTP bytes; video is a breakdown only
    assert client.get("/api/v1/usage").json()["sites"][0]["bytes"] == 1000 + 500 + 3
    totals = client.get(f"{S}/analytics?period=24h").json()["totals"]
    assert totals["video"] == {"bytes": 850, "requests": 3, "cache_hits": 2}
    assert totals["l4"] == {"bytes_in": 101, "bytes_out": 402, "sessions": 4, "apps": {
        "game": {"bytes_in": 101, "bytes_out": 402, "sessions": 3},
        "voice": {"bytes_in": 0, "bytes_out": 0, "sessions": 1}}}
    bad = [{"host": "example.com", "hour": hour, "bytes": 0, "requests": 0, "l4": {"game": {"bytes_in": -1}}}]
    assert client.post("/edge/v1/usage", json={"items": bad},
                       headers={"Authorization": f"Bearer {token}"}).status_code == 422


# ------------------------------------------------------------------ §16.5 video

def test_video_section_passthrough(client):
    make_site(client)
    token = add_edge(client)
    assert client.get(f"{S}/config/video").json() == {"enabled": False, "segment_ttl": 86400,
                                                       "manifest_ttl": 2, "prefetch_next": True}
    body = {"enabled": True, "segment_ttl": 3600, "manifest_ttl": 1, "prefetch_next": False}
    assert client.put(f"{S}/config/video", json=body).json() == body
    assert client.put(f"{S}/config/video", json={"manifest_ttl": 0}).status_code == 422
    assert client.put(f"{S}/config/video", json={"bogus": 1}).status_code == 422
    assert edge_get(client, token, "/edge/v1/config").json()["sites"][0]["video"] == body


# ------------------------------------------------------------------ §16.6 images v2

def test_image_v2_secret_and_edge(client):
    make_site(client)
    token = add_edge(client)
    r = client.put(f"{S}/config/image", json={"enabled": True, "avif": True, "smart_crop": True})
    assert r.status_code == 200, r.text
    assert r.json()["transform_secret"] == "" and r.json()["transform_secret_set"] is False
    img = edge_get(client, token, "/edge/v1/config").json()["sites"][0]["image"]
    assert img["avif"] is True and img["smart_crop"] is True and img["transform_secret"] == ""
    assert "transform_secret_set" not in img

    # generated on request, shown once, never returned by GET / audit; the edge gets it
    r = client.post(f"{S}/image/transform-secret")
    assert r.status_code == 200, r.text
    secret = r.json()["transform_secret"]
    assert secret.startswith("imgsec_") and len(secret) == 55
    got = client.get(f"{S}/config/image").json()
    assert got["transform_secret"] == "" and got["transform_secret_set"] is True
    assert secret not in client.get(S).text and secret not in client.get("/api/v1/audit").text
    assert edge_get(client, token, "/edge/v1/config").json()["sites"][0]["image"]["transform_secret"] == secret
    # a PUT without the secret keeps it; with one replaces it; invalid -> 422
    client.put(f"{S}/config/image", json={"enabled": True, "quality": 70})
    assert edge_get(client, token, "/edge/v1/config").json()["sites"][0]["image"]["transform_secret"] == secret
    own = "x" * 40
    client.put(f"{S}/config/image", json={"enabled": True, "transform_secret": own})
    assert edge_get(client, token, "/edge/v1/config").json()["sites"][0]["image"]["transform_secret"] == own
    assert client.put(f"{S}/config/image", json={"transform_secret": "short"}).status_code == 422
    assert client.delete(f"{S}/image/transform-secret").json() == {"transform_secret_set": False}
    assert client.delete(f"{S}/image/transform-secret").status_code == 404
    assert edge_get(client, token, "/edge/v1/config").json()["sites"][0]["image"]["transform_secret"] == ""

    # the plan's image_optimization folds every image feature off and blocks the secret endpoint
    client.patch(f"{S}/plan", json={"features": {"image_optimization": False}})
    img = edge_get(client, token, "/edge/v1/config").json()["sites"][0]["image"]
    assert (img["enabled"], img["auto_webp"], img["avif"], img["smart_crop"]) == (False, False, False, False)
    assert client.post(f"{S}/image/transform-secret").status_code == 403
    assert client.put(f"{S}/config/image", json={"avif": True}).status_code == 403


def test_image_signature_algorithm():
    """Same algorithm as the edge (pcdn.js imgSigBase): fixed parameter order, raw values."""
    secret = "imgsec_" + "ab" * 24
    path, query = "/img/cat%20one.jpg", "fit=cover&utm=x&w=300&sig=ignored&fmt=avif"
    want = hmac.new(secret.encode(), b"/img/cat%20one.jpg?w=300&fit=cover&fmt=avif", hashlib.sha256).hexdigest()
    assert images.canonical(path, query) == "/img/cat%20one.jpg?w=300&fit=cover&fmt=avif"
    assert images.sign(secret, path, {"fmt": "avif", "w": 300, "fit": "cover"}) == want
    assert images.canonical("/a.png", {"height": 5, "q": 80, "h": 10, "width": 7}) == \
        "/a.png?h=10&q=80&width=7&height=5"


def test_image_secret_via_capi(client):
    make_site(client)
    routes_capi._hits.clear()
    routes_capi._config_hits.clear()
    key = client.post(f"{S}/apikeys", json={"name": "k", "scopes": ["dns"]}).json()["key"]
    h = {"Authorization": f"Bearer {key}"}
    r = client.post("/capi/v1/image/transform-secret", headers=h)
    assert r.status_code == 200 and r.json()["transform_secret"].startswith("imgsec_")
    assert client.get("/capi/v1/config/image", headers=h).json()["transform_secret_set"] is True
    assert client.delete("/capi/v1/image/transform-secret", headers=h).status_code == 200
    routes_capi._hits.clear()
    routes_capi._config_hits.clear()


# ------------------------------------------------------------------ §16.7 weighted / failover records

def rec(content, type_="A", weight=None, health=False, ok=None, fail=0, protocol=None, name="w"):
    return SimpleNamespace(name=name, type=type_, content=content, proxied=False, priority=None, ttl=300,
                           weight=weight, health_check=health, health_ok=ok, health_fail=fail,
                           health_protocol=protocol, health_port=None)


def test_managed_content_weights_standby_and_fail_open():
    a, b, c = rec("1.1.1.1", weight=70), rec("2.2.2.2", weight=30), rec("3.3.3.3", weight=0)
    assert dnsbuild.managed_content("A", [a, b, c]) == "LUA A \"pickwrandom({{70,'1.1.1.1'},{30,'2.2.2.2'}})\""
    # equal weights: plain round robin
    assert dnsbuild.managed_content("A", [rec("1.1.1.1", weight=5), rec("2.2.2.2", weight=5)]) == \
        "1.1.1.1\n2.2.2.2"
    # a member withdrawn after PROBE_FAIL_CHECKS failures; one left -> plain answer
    down = settings.probe_fail_checks
    a2 = rec("1.1.1.1", weight=70, health=True, ok=False, fail=down)
    b2 = rec("2.2.2.2", weight=30, health=True, ok=False, fail=down - 1)  # not yet withdrawn
    assert dnsbuild.managed_content("A", [a2, b2, c]) == "2.2.2.2"
    # every primary member down -> the standby (weight 0) takes over
    b3 = rec("2.2.2.2", weight=30, health=True, ok=False, fail=down)
    assert dnsbuild.managed_content("A", [a2, b3, c]) == "3.3.3.3"
    # everything down -> fail open (never empty)
    c3 = rec("3.3.3.3", weight=0, health=True, ok=False, fail=down)
    assert dnsbuild.managed_content("A", [a2, b3, c3]) == "LUA A \"pickwrandom({{70,'1.1.1.1'},{30,'2.2.2.2'}})\""
    # unweighted, controller-checked: the healthy members only, all when none is healthy
    h1 = rec("1.1.1.1", health=True, protocol="http", ok=False, fail=down)
    h2 = rec("2.2.2.2", health=True, protocol="http", ok=True)
    assert dnsbuild.managed_content("A", [h1, h2]) == "2.2.2.2"
    assert dnsbuild.managed_content("A", [h1]) == "1.1.1.1"
    # weighted CNAMEs answer fully qualified targets
    assert dnsbuild.managed_content("CNAME", [rec("a.net", "CNAME", 1), rec("b.net", "CNAME", 1)]) == \
        "LUA CNAME \"pickwrandom({{1,'a.net.'},{1,'b.net.'}})\""
    # a legacy health-checked set (no protocol, no weight) is not managed: PowerDNS ifportup
    assert not dnsbuild.is_managed_set([rec("1.1.1.1", health=True)])
    assert dnsbuild.is_managed_set([rec("1.1.1.1", health=True, protocol="tcp")])


def test_weighted_record_validation(client):
    make_site(client)
    base = {"name": "w", "type": "A", "content": "93.184.216.10"}
    assert client.post(f"{S}/records", json={**base, "weight": 101}).status_code == 422
    assert client.post(f"{S}/records", json={**base, "weight": 5, "proxied": True}).status_code == 422
    assert client.post(f"{S}/records", json={"name": "t", "type": "TXT", "content": "x", "weight": 1}).status_code == 422
    r = client.post(f"{S}/records", json={**base, "weight": 60, "health_check": True, "health_protocol": "https",
                                          "health_port": 8443, "health_path": "/up"})
    assert r.status_code == 201, r.text
    d = r.json()
    assert (d["weight"], d["health_protocol"], d["health_path"], d["health_port"]) == (60, "https", "/up", 8443)
    assert d["health"] == {"ok": None, "ms": None, "fail": 0, "at": None, "error": None, "advertised": True}
    # weighted CNAMEs may share a name, a plain one may not join them
    c = {"name": "api", "type": "CNAME", "content": "a.example.net", "weight": 50}
    assert client.post(f"{S}/records", json=c).status_code == 201
    assert client.post(f"{S}/records", json={**c, "content": "b.example.net", "weight": 50,
                                             "health_check": True}).status_code == 201
    assert client.post(f"{S}/records", json={**c, "content": "c.example.net", "weight": None}).status_code == 422
    assert client.post(f"{S}/records", json={"name": "api", "type": "A", "content": "93.184.216.11"}).status_code == 422
    # health_path only travels with http/https; a lone CNAME gets no health check
    r = client.post(f"{S}/records", json={**base, "name": "t2", "health_check": True, "health_path": "/x"})
    assert r.json()["health_path"] is None and r.json()["health_protocol"] is None
    r = client.post(f"{S}/records", json={"name": "solo", "type": "CNAME", "content": "x.example.net",
                                          "health_check": True})
    assert r.json()["health_check"] is False


def test_weighted_records_in_zone_and_probe_failover(client, fake_pdns, monkeypatch):
    make_site(client)
    for content, weight in (("93.184.216.10", 80), ("93.184.216.20", 20), ("93.184.216.30", 0)):
        r = client.post(f"{S}/records", json={"name": "w", "type": "A", "content": content, "weight": weight,
                                              "health_check": True, "health_protocol": "tcp", "ttl": 600})
        assert r.status_code == 201, r.text
    lua = fake_pdns.rrset("example.com.", "w.example.com.", "LUA")
    assert lua["records"][0]["content"] == "A \"pickwrandom({{80,'93.184.216.10'},{20,'93.184.216.20'}})\""
    assert lua["ttl"] == settings.proxied_ttl
    assert fake_pdns.rrset("example.com.", "w.example.com.", "A") is None

    healthy = {"93.184.216.10": False, "93.184.216.20": True, "93.184.216.30": True}
    calls = []

    def fake_check(r, host, timeout):
        calls.append((r.content, host))
        return (True, 3, None) if healthy[r.content] else (False, None, "ConnectError: refused")

    monkeypatch.setattr(record_health, "check", fake_check)
    for _ in range(settings.probe_fail_checks - 1):
        with SessionLocal() as db:
            assert scheduler.job_record_health(db, force=True) == []  # not yet withdrawn
    assert ("93.184.216.10", "w.example.com") in calls
    with SessionLocal() as db:
        assert scheduler.job_record_health(db, force=True) == ["example.com"]
    rr = fake_pdns.rrset("example.com.", "w.example.com.", "A")
    assert rr["records"] == [{"content": "93.184.216.20", "disabled": False}]
    recs = {x["content"]: x for x in client.get(f"{S}/records").json()}
    assert recs["93.184.216.10"]["health"]["ok"] is False
    assert recs["93.184.216.10"]["health"]["advertised"] is False
    assert recs["93.184.216.10"]["health"]["error"] == "ConnectError: refused"

    # the 60 s interval: an unforced run right after the last one does nothing
    with SessionLocal() as db:
        n = len(calls)
        scheduler.job_record_health(db)
    assert len(calls) == n

    # all primaries down -> standby; recovery brings the weighted answer back
    healthy["93.184.216.20"] = False
    for _ in range(settings.probe_fail_checks):
        with SessionLocal() as db:
            scheduler.job_record_health(db, force=True)
    assert fake_pdns.rrset("example.com.", "w.example.com.", "A")["records"] == [
        {"content": "93.184.216.30", "disabled": False}]
    healthy.update({"93.184.216.10": True, "93.184.216.20": True})
    with SessionLocal() as db:
        assert scheduler.job_record_health(db, force=True) == ["example.com"]
    assert "pickwrandom" in fake_pdns.rrset("example.com.", "w.example.com.", "LUA")["records"][0]["content"]


def test_legacy_health_check_keeps_powerdns_probe(client, fake_pdns):
    make_site(client)
    for ip in ("93.184.216.10", "93.184.216.20"):
        client.post(f"{S}/records", json={"name": "h", "type": "A", "content": ip, "health_check": True})
    lua = fake_pdns.rrset("example.com.", "h.example.com.", "LUA")
    assert "ifportup(80" in lua["records"][0]["content"]


def _tcp_server():
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(5)
    def serve():
        try:
            srv.accept()[0].close()
        except OSError:
            pass

    threading.Thread(target=serve, daemon=True).start()
    return srv


def test_record_probe_check_tcp_http_and_ssrf(monkeypatch):
    # contents that are not public addresses are never contacted
    r = SimpleNamespace(type="A", content="127.0.0.1", health_protocol="tcp", health_port=1, health_path=None)
    ok, _, err = record_health.check(r, "w.example.com", 1)
    assert ok is False and err
    monkeypatch.setattr(record_health.netguard, "resolver", lambda host, port: ["10.1.2.3"])
    r = SimpleNamespace(type="CNAME", content="internal.example.net", health_protocol="tcp", health_port=80,
                        health_path=None)
    ok, _, err = record_health.check(r, "w.example.com", 1)
    assert ok is False and "غیرعمومی" in err

    # the real TCP / HTTP probe against local servers (address check bypassed for the test)
    monkeypatch.setattr(record_health, "_addresses", lambda r: ["127.0.0.1"])
    srv = _tcp_server()
    r = SimpleNamespace(type="A", content="x", health_protocol=None, health_port=srv.getsockname()[1],
                        health_path=None)
    assert record_health.check(r, "w.example.com", 2)[0] is True
    srv.close()
    seen = {}

    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            seen["host"], seen["path"] = self.headers["Host"], self.path
            self.send_response(503 if self.path == "/bad" else 204)
            self.end_headers()

        def log_message(self, *a):
            pass

    httpd = http.server.HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        r = SimpleNamespace(type="A", content="x", health_protocol="http", health_port=httpd.server_port,
                            health_path="/health")
        assert record_health.check(r, "w.example.com", 2)[0] is True
        assert seen == {"host": "w.example.com", "path": "/health"}
        r.health_path = "/bad"
        assert record_health.check(r, "w.example.com", 2)[:3:2] == (False, "HTTP 503")
    finally:
        httpd.shutdown()


# ------------------------------------------------------------------ §16.7 secondary DNS

def test_dns_secondary_slave_zone(client, fake_pdns):
    make_site(client)
    z = "example.com."
    assert fake_pdns.zones[z]["kind"] == "Native"
    body = {"mode": "primary_elsewhere", "primaries": ["93.184.216.53"],
            "tsig": {"name": "Transfer-Key.", "algorithm": "hmac-sha256", "secret": TSIG}}
    r = client.put(f"{S}/config/dns_secondary", json=body)
    assert r.status_code == 200, r.text
    assert r.json()["tsig"] == {"name": "transfer-key", "algorithm": "hmac-sha256", "secret": "",
                                "secret_set": True}
    zone = fake_pdns.zones[z]
    assert zone["kind"] == "Slave" and zone["masters"] == ["93.184.216.53"]
    assert fake_pdns.tsigkeys["transfer-key."]["key"] == TSIG
    assert zone["metadata"] == {"AXFR-MASTER-TSIG": ["transfer-key"]}
    assert fake_pdns.axfr_retrieved == [z]
    assert TSIG not in client.get(S).text and TSIG not in client.get("/api/v1/audit").text
    # a slave zone's rrsets are never written (the fake refuses PATCH on slaves like PowerDNS)
    assert client.post(f"{S}/records", json={"name": "x", "type": "A", "content": "93.184.216.1"}).json()[
        "dns_error"] is None
    assert fake_pdns.rrset(z, "x.example.com.", "A") is None
    # the same key without a new secret keeps it; a renamed key needs one
    body2 = {**body, "tsig": {"name": "transfer-key", "algorithm": "hmac-sha512"}}
    assert client.put(f"{S}/config/dns_secondary", json=body2).status_code == 200
    assert fake_pdns.tsigkeys["transfer-key."]["algorithm"] == "hmac-sha512"
    assert client.put(f"{S}/config/dns_secondary",
                      json={**body, "tsig": {"name": "other-key"}}).status_code == 422

    # back to off: Native again, records published, metadata and the key gone
    r = client.put(f"{S}/config/dns_secondary", json={"mode": "off"})
    assert r.status_code == 200, r.text
    assert zone["kind"] == "Native" and zone["masters"] == [] and zone["metadata"] == {}
    assert fake_pdns.rrset(z, "x.example.com.", "A")["records"][0]["content"] == "93.184.216.1"
    assert fake_pdns.tsigkeys == {}


def test_dns_secondary_allow_axfr_and_validation(client, fake_pdns):
    make_site(client)
    make_site(client, "other.com")
    z = "example.com."
    assert client.put(f"{S}/config/dns_secondary", json={"allow_axfr": ["93.184.216.0/28"]}).status_code == 422
    bad = [{"mode": "primary_elsewhere"}, {"mode": "primary_elsewhere", "primaries": ["10.0.0.1"]},
           {"allow_axfr": ["192.168.0.0/16"], "tsig": {"name": "k", "secret": TSIG}},
           {"tsig": {"name": "k", "secret": "not base64!"}},
           {"tsig": {"name": "k", "secret": base64.b64encode(b"short").decode()}},
           {"tsig": {"name": "bad name", "secret": TSIG}},
           {"tsig": {"name": "k"}}]  # no secret stored yet
    for b in bad:
        assert client.put(f"{S}/config/dns_secondary", json=b).status_code == 422, b
    body = {"allow_axfr": ["93.184.216.7", "2606:2800:220:1::/64"], "tsig": {"name": "xfr", "secret": TSIG}}
    r = client.put(f"{S}/config/dns_secondary", json=body)
    assert r.status_code == 200, r.text
    zone = fake_pdns.zones[z]
    assert zone["kind"] == "Native"
    assert zone["metadata"] == {"ALLOW-AXFR-FROM": ["93.184.216.7/32", "2606:2800:220:1::/64"],
                                "TSIG-ALLOW-AXFR": ["xfr"]}
    assert fake_pdns.rrset(z, "example.com.", "NS") is not None  # records still published
    # the key name belongs to this site only
    r = client.put("/api/v1/sites/other.com/config/dns_secondary", json={"tsig": {"name": "xfr", "secret": TSIG}})
    assert r.status_code == 409
    # a later full re-sync (scheduler) keeps the metadata
    add_edge(client)
    with SessionLocal() as db:
        site = db.scalar(select(Site).where(Site.domain == "example.com"))
        from app.services import sync_site_dns

        assert sync_site_dns(db, site) is None
    assert fake_pdns.zones[z]["metadata"]["TSIG-ALLOW-AXFR"] == ["xfr"]


def test_dns_secondary_new_zone_created_as_slave(client, fake_pdns):
    make_site(client)
    client.put(f"{S}/config/dns_secondary", json={"mode": "primary_elsewhere", "primaries": ["93.184.216.53"]})
    fake_pdns.zones.clear()  # e.g. a fresh second nameserver
    with SessionLocal() as db:
        from app.services import sync_site_dns

        site = db.scalar(select(Site).where(Site.domain == "example.com"))
        assert sync_site_dns(db, site) is None
    zone = fake_pdns.zones["example.com."]
    assert zone["kind"] == "Slave" and zone["masters"] == ["93.184.216.53"] and zone["rrsets"] == []


def test_record_columns_roundtrip_db(client):
    make_site(client)
    client.post(f"{S}/records", json={"name": "w", "type": "A", "content": "93.184.216.10", "weight": 0})
    with SessionLocal() as db:
        r = db.scalar(select(Record).where(Record.name == "w"))
        assert (r.weight, r.health_fail, r.health_protocol) == (0, 0, None)


@pytest.mark.parametrize("raw,want", [("20000-29999", (20000, 29999)), ("100-2000", (1024, 2000)),
                                      ("x", (20000, 29999)), ("3000-2000", (20000, 29999))])
def test_l4_port_range_env(raw, want):
    from app.config import _port_range

    assert _port_range(raw) == want


def test_new_secrets_are_covered_by_key_rotation():
    from app import site_secrets

    site = SimpleNamespace(integration_secrets=None)
    site_secrets.set_secret(site, "image_transform", "a" * 40)
    site_secrets.set_secret(site, "tsig", TSIG)
    assert len(site_secrets.values(site)) == 2
    assert site_secrets.map_values(site, lambda v: "X" + v) == 2
    assert site_secrets.drop_unreadable(site, lambda v: False) is True
    assert site_secrets.values(site) == [] and not site_secrets.has_secret(site, "tsig")


def test_heartbeat_reports_wave8_capabilities(client):
    token = add_edge(client)
    r = client.post("/edge/v1/heartbeat", headers={"Authorization": f"Bearer {token}"},
                    json={"capabilities": {"avif": True, "l4": True, "l4_port_range": "20000-29999",
                                           "l4_proxy_protocol": ["v1"], "slice": True, "video": True,
                                           "image_transform": True, "net_guard": False}})
    assert r.status_code == 200
    caps = client.get("/api/v1/edges").json()[0]["capabilities"]
    assert (caps["avif"], caps["l4"], caps["l4_port_range"], caps["slice"], caps["video"],
            caps["image_transform"]) == (True, True, "20000-29999", True, True, True)
    client.post("/edge/v1/heartbeat", headers={"Authorization": f"Bearer {token}"},
                json={"capabilities": {"l4": True, "l4_port_range": "junk"}})
    caps = client.get("/api/v1/edges").json()[0]["capabilities"]
    assert caps["l4"] is True and caps["l4_port_range"] is None
