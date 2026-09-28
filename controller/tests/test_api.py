from datetime import datetime, timedelta, timezone

from app.db import SessionLocal
from app.models import Site
from app.scheduler import job_edges, job_quota


def add_edge(client, name="ir-thr-1", ip="5.160.1.10", region="home", ipv6=None):
    r = client.post("/api/v1/edges", json={"name": name, "ipv4": ip, "region": region, "ipv6": ipv6})
    assert r.status_code == 201, r.text
    return r.json()["token"]


def edge_get(client, token, path, **kw):
    return client.get(path, headers={"Authorization": f"Bearer {token}", **kw.pop("headers", {})}, **kw)


def test_auth_required(client):
    assert client.get("/api/v1/ping", headers={"Authorization": "Bearer nope"}).status_code == 401
    assert client.get("/api/v1/ping").status_code == 200


def test_create_site_with_origin(client, fake_pdns):
    r = client.post("/api/v1/sites", json={"domain": "WWW.Example.com", "origin_ip": "93.184.216.34",
                                           "plan": {"bandwidth_limit_gb": 100}})
    assert r.status_code == 201, r.text
    site = r.json()
    assert site["domain"] == "example.com"
    assert site["status"] == "pending_ns"
    assert {x["name"] for x in site["records"]} == {"@", "www"}
    # no edges online yet -> proxied records fall back to the origin
    assert fake_pdns.rrset("example.com.", "example.com.", "A")["records"][0]["content"] == "93.184.216.34"
    ns = fake_pdns.rrset("example.com.", "example.com.", "NS")
    assert {r["content"] for r in ns["records"]} == {"ns1.example-cdn.com.", "ns2.example-cdn.com."}
    assert client.post("/api/v1/sites", json={"domain": "example.com"}).status_code == 409


def test_records_validation(client):
    client.post("/api/v1/sites", json={"domain": "example.com"})
    bad = [
        {"type": "A", "content": "10.0.0.1"},
        {"type": "A", "content": "not-an-ip"},
        {"type": "AAAA", "content": "1.2.3.4"},
        {"name": "@", "type": "CNAME", "content": "foo.com"},
        {"name": "@", "type": "NS", "content": "ns.foo.com"},
        {"type": "CAA", "content": "bogus"},
        {"type": "PTR", "content": "x"},
    ]
    for b in bad:
        assert client.post("/api/v1/sites/example.com/records", json=b).status_code == 422, b
    ok = client.post("/api/v1/sites/example.com/records",
                     json={"name": "mail", "type": "A", "content": "1.1.1.1"})
    assert ok.status_code == 201
    # CNAME conflicts with existing A
    r = client.post("/api/v1/sites/example.com/records",
                    json={"name": "mail", "type": "CNAME", "content": "x.com"})
    assert r.status_code == 422
    r = client.post("/api/v1/sites/example.com/records",
                    json={"name": "mail.example.com", "type": "MX", "content": "mail.example.com"})
    assert r.status_code == 201 and r.json()["priority"] == 10


def test_record_limit(client):
    client.post("/api/v1/sites", json={"domain": "example.com", "plan": {"max_records": 1}})
    assert client.post("/api/v1/sites/example.com/records",
                       json={"type": "TXT", "content": "a"}).status_code == 201
    assert client.post("/api/v1/sites/example.com/records",
                       json={"type": "TXT", "content": "b"}).status_code == 403


def test_edge_config_and_lua(client, fake_pdns):
    client.post("/api/v1/sites", json={"domain": "example.com", "origin_ip": "93.184.216.34"})
    client.post("/api/v1/sites/example.com/records",
                json={"name": "_dmarc", "type": "TXT", "content": "v=DMARC1; p=none"})
    t1 = add_edge(client, "ir-1", "5.160.1.10", "home")
    add_edge(client, "de-1", "88.99.1.10", "global", ipv6="2a01:4f8::10")

    r = edge_get(client, t1, "/edge/v1/config")
    assert r.status_code == 200
    cfg = r.json()
    assert cfg["sites"][0]["hosts"] == [
        {"name": "example.com", "origin": {"address": "93.184.216.34", "port": None}},
        {"name": "www.example.com", "origin": {"address": "93.184.216.34", "port": None}},
    ]
    etag = r.headers["etag"]
    assert edge_get(client, t1, "/edge/v1/config", headers={"If-None-Match": etag}).status_code == 304
    assert edge_get(client, "bad", "/edge/v1/config").status_code == 401

    # only edge 1 has checked in -> DNS points at it
    with SessionLocal() as db:
        job_edges(db)
    lua = fake_pdns.rrset("example.com.", "example.com.", "LUA")
    assert lua and "5.160.1.10" in lua["records"][0]["content"]
    assert "88.99.1.10" not in lua["records"][0]["content"]
    assert fake_pdns.rrset("example.com.", "example.com.", "A") is None
    assert fake_pdns.rrset("example.com.", "www.example.com.", "CNAME") is None
    txt = fake_pdns.rrset("example.com.", "_dmarc.example.com.", "TXT")
    assert txt["records"][0]["content"] == '"v=DMARC1; p=none"'


def test_suspend_and_usage(client):
    client.post("/api/v1/sites", json={"domain": "example.com", "origin_ip": "93.184.216.34",
                                       "plan": {"bandwidth_limit_gb": 1}})
    token = add_edge(client)
    hour = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
    items = [{"host": "www.example.com", "hour": hour.isoformat(), "bytes": 600 * 1024**2, "requests": 10,
              "cache_hits": 7},
             {"host": "example.com", "hour": hour.isoformat(), "bytes": 600 * 1024**2, "requests": 5},
             {"host": "unknown.org", "hour": hour.isoformat(), "bytes": 5, "requests": 1}]
    r = client.post("/edge/v1/usage", json={"items": items}, headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200, r.text

    u = client.get("/api/v1/usage").json()["sites"][0]
    assert u["bytes"] == 1200 * 1024**2 and u["requests"] == 15 and u["cache_hits"] == 7

    with SessionLocal() as db:
        job_quota(db)
    assert client.get("/api/v1/sites/example.com").json()["status"] == "over_quota"
    client.patch("/api/v1/sites/example.com/plan", json={"bandwidth_limit_gb": 0})
    with SessionLocal() as db:
        job_quota(db)
    assert client.get("/api/v1/sites/example.com").json()["status"] == "pending_ns"

    client.post("/api/v1/sites/example.com/suspend")
    cfg = edge_get(client, token, "/edge/v1/config").json()
    assert cfg["sites"][0]["status"] == "suspended"
    client.post("/api/v1/sites/example.com/unsuspend")
    assert client.get("/api/v1/sites/example.com").json()["status"] == "pending_ns"


def test_purge_and_settings(client):
    client.post("/api/v1/sites", json={"domain": "example.com", "origin_ip": "93.184.216.34"})
    token = add_edge(client)
    assert client.post("/api/v1/sites/example.com/purge", json={"urls": ["/relative"]}).status_code == 422
    client.post("/api/v1/sites/example.com/purge", json={"urls": []})
    client.post("/api/v1/sites/example.com/purge", json={"urls": ["https://example.com/a.css"]})
    p = edge_get(client, token, "/edge/v1/purges?after=0").json()
    assert [x["urls"] for x in p] == [[], ["https://example.com/a.css"]]
    assert edge_get(client, token, f"/edge/v1/purges?after={p[-1]['id']}").json() == []

    r = client.patch("/api/v1/sites/example.com/settings",
                     json={"blocked_ips": ["1.2.3.4", "10.0.0.0/8", ""], "dev_mode": True})
    assert r.json()["settings"]["blocked_ips"] == ["1.2.3.4/32", "10.0.0.0/8"]
    assert client.patch("/api/v1/sites/example.com/settings",
                        json={"blocked_ips": ["nope"]}).status_code == 422
    cfg = edge_get(client, token, "/edge/v1/config").json()
    assert cfg["sites"][0]["cache"]["enabled"] is False  # dev mode bypasses cache


def test_delete_site(client, fake_pdns):
    client.post("/api/v1/sites", json={"domain": "example.com"})
    assert "example.com." in fake_pdns.zones
    assert client.delete("/api/v1/sites/example.com").json()["ok"]
    assert "example.com." not in fake_pdns.zones
    assert client.get("/api/v1/sites/example.com").status_code == 404


def test_ssl_request_requires_ns(client):
    client.post("/api/v1/sites", json={"domain": "example.com"})
    assert client.post("/api/v1/sites/example.com/ssl").status_code == 409
    with SessionLocal() as db:
        s = db.query(Site).one()
        s.ns_verified_at = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(minutes=1)
        db.commit()
    assert client.post("/api/v1/sites/example.com/ssl").json()["status"] == "pending"


def test_cname_origin_resolution(client):
    client.post("/api/v1/sites", json={"domain": "example.com"})
    for body in [
        {"name": "a", "type": "CNAME", "content": "b.example.com", "proxied": True},
        {"name": "b", "type": "CNAME", "content": "a.example.com", "proxied": True},   # loop -> dropped
        {"name": "shop", "type": "CNAME", "content": "shops.myshopify.com", "proxied": True},
        {"name": "v6", "type": "AAAA", "content": "2a01:4f8::1", "proxied": True},
    ]:
        assert client.post("/api/v1/sites/example.com/records", json=body).status_code == 201
    token = add_edge(client)
    hosts = edge_get(client, token, "/edge/v1/config").json()["sites"][0]["hosts"]
    assert hosts == [{"name": "shop.example.com", "origin": {"address": "shops.myshopify.com", "port": None}},
                     {"name": "v6.example.com", "origin": {"address": "[2a01:4f8::1]", "port": None}}]
