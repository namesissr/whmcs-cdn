"""Customer API `/capi/v1/*` (SPEC §10.1): key management, bearer auth, scope + site isolation."""

from datetime import datetime, timezone

import pytest

from app import routes_capi
from app.config import settings
from tests.test_api import add_edge

CAPI = "/capi/v1"


@pytest.fixture(autouse=True)
def _reset_rate():
    """The in-process rate-limit window persists across tests; start each test clean."""
    routes_capi._hits.clear()
    yield
    routes_capi._hits.clear()


def make_site(client, domain="example.com", origin="93.184.216.34"):
    r = client.post("/api/v1/sites", json={"domain": domain, "origin_ip": origin, "plan": {}})
    assert r.status_code == 201, r.text
    return r.json()


def new_key(client, domain="example.com", name="k", scopes=("purge", "stats", "dns")):
    r = client.post(f"/api/v1/sites/{domain}/apikeys", json={"name": name, "scopes": list(scopes)})
    assert r.status_code == 201, r.text
    return r.json()


def auth(key: str) -> dict:
    return {"Authorization": f"Bearer {key}"}


def ingest(client, host, requests=10, bytes_=1000):
    token = add_edge(client, name=f"e-{host}", ip="5.160.1.10")
    now = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
    payload = {
        "items": [{"host": host, "hour": now.isoformat(), "bytes": bytes_, "requests": requests,
                   "cache_hits": 6, "status": {"2xx": requests}, "countries": {"IR": requests},
                   "security": {"waf": 1}}],
        "events": [{"t": now.isoformat(), "host": host, "ip": "5.5.5.5", "country": "ir",
                    "method": "GET", "path": "/", "action": "block", "source": "waf", "rule": "1"}],
    }
    assert client.post("/edge/v1/usage", json=payload, headers=auth(token)).status_code == 200


# ---------------------------------------------------------------- key management (admin API)

def test_key_create_returns_key_once_and_list_never_leaks(client):
    make_site(client)
    created = new_key(client, name="prod", scopes=["purge", "stats"])
    assert created["key"].startswith("pcdn_") and len(created["key"]) == len("pcdn_") + 40
    assert created["name"] == "prod" and created["scopes"] == ["purge", "stats"]
    assert created["revoked"] is False

    listed = client.get("/api/v1/sites/example.com/apikeys").json()
    assert len(listed) == 1
    assert "key" not in listed[0] and "key_hash" not in listed[0]
    assert listed[0]["id"] == created["id"] and listed[0]["scopes"] == ["purge", "stats"]


def test_key_validation_and_max_five(client):
    make_site(client)
    assert client.post("/api/v1/sites/example.com/apikeys",
                       json={"name": "x", "scopes": ["nope"]}).status_code == 422
    assert client.post("/api/v1/sites/example.com/apikeys",
                       json={"name": "", "scopes": ["purge"]}).status_code == 422
    assert client.post("/api/v1/sites/example.com/apikeys",
                       json={"name": "x", "scopes": []}).status_code == 422
    for i in range(5):
        new_key(client, name=f"k{i}", scopes=["purge"])
    assert client.post("/api/v1/sites/example.com/apikeys",
                       json={"name": "k6", "scopes": ["purge"]}).status_code == 403


def test_revoke_frees_a_slot_and_blocks_the_key(client):
    make_site(client)
    k = new_key(client, scopes=["stats"])
    assert client.get(f"{CAPI}/analytics", headers=auth(k["key"])).status_code == 200
    assert client.delete(f"/api/v1/sites/example.com/apikeys/{k['id']}").status_code == 200
    assert client.get(f"{CAPI}/analytics", headers=auth(k["key"])).status_code == 401
    assert client.get("/api/v1/sites/example.com/apikeys").json()[0]["revoked"] is True
    # a revoked key does not count toward the max of 5
    for i in range(5):
        new_key(client, name=f"k{i}", scopes=["purge"])
    assert client.delete("/api/v1/sites/example.com/apikeys/999").status_code == 404


# ---------------------------------------------------------------- bearer auth

def test_bearer_auth_valid_invalid_revoked(client):
    make_site(client)
    k = new_key(client, scopes=["stats"])
    assert client.get(f"{CAPI}/analytics", headers=auth(k["key"])).status_code == 200
    assert client.get(f"{CAPI}/analytics").status_code == 401  # no header
    assert client.get(f"{CAPI}/analytics", headers=auth("pcdn_" + "0" * 40)).status_code == 401  # unknown
    assert client.get(f"{CAPI}/analytics", headers=auth("garbage")).status_code == 401  # not a pcdn key
    r = client.get(f"{CAPI}/analytics", headers=auth("pcdn_bad"))
    assert r.status_code == 401 and "detail" in r.json()  # JSON {"detail": ...}


# ---------------------------------------------------------------- scope enforcement

def test_scope_enforced_per_endpoint(client):
    make_site(client)
    stats = new_key(client, name="stats-only", scopes=["stats"])["key"]
    # a stats-only key can read analytics but cannot purge / touch records / config
    assert client.get(f"{CAPI}/analytics", headers=auth(stats)).status_code == 200
    assert client.post(f"{CAPI}/purge", json={"everything": True}, headers=auth(stats)).status_code == 403
    assert client.get(f"{CAPI}/records", headers=auth(stats)).status_code == 403
    assert client.get(f"{CAPI}/config/cache", headers=auth(stats)).status_code == 403

    dns = new_key(client, name="dns-only", scopes=["dns"])["key"]
    assert client.get(f"{CAPI}/records", headers=auth(dns)).status_code == 200
    assert client.get(f"{CAPI}/analytics", headers=auth(dns)).status_code == 403
    assert client.post(f"{CAPI}/purge", json={"everything": True}, headers=auth(dns)).status_code == 403


# ---------------------------------------------------------------- purge parity

def test_purge_via_capi_equals_admin_purge(client):
    make_site(client)
    token = add_edge(client)
    key = new_key(client, scopes=["purge"])["key"]

    admin = client.post("/api/v1/sites/example.com/purge",
                        json={"urls": ["https://example.com/a.css"]})
    capi = client.post(f"{CAPI}/purge", json={"urls": ["https://example.com/a.css"]}, headers=auth(key))
    assert admin.status_code == capi.status_code == 200
    assert admin.json() == capi.json() == {"ok": True, "queued": 1}

    # same validation as the admin route (Persian errors, 100-item cap)
    assert client.post(f"{CAPI}/purge", json={"urls": ["/relative"]}, headers=auth(key)).status_code == 422
    assert client.post(f"{CAPI}/purge",
                       json={"urls": [f"https://e/{i}" for i in range(101)]}, headers=auth(key)).status_code == 422

    # both purges reached the edge queue for this site
    q = client.get("/edge/v1/purges?after=0", headers=auth(token)).json()
    assert len(q) == 2


# ---------------------------------------------------------------- analytics / events site isolation

def test_analytics_and_events_scoped_to_the_keys_site(client):
    make_site(client, "a.com", "1.1.1.1")
    make_site(client, "b.com", "2.2.2.2")
    ingest(client, "a.com", requests=10)
    ingest(client, "b.com", requests=99)
    key_a = new_key(client, "a.com", scopes=["stats"])["key"]

    a = client.get(f"{CAPI}/analytics?period=24h", headers=auth(key_a)).json()
    assert a["totals"]["requests"] == 10  # site A only, never B's 99
    admin_a = client.get("/api/v1/sites/a.com/analytics?period=24h").json()
    assert a == admin_a

    ev = client.get(f"{CAPI}/events", headers=auth(key_a)).json()
    assert len(ev) == 1 and ev[0]["host"] == "a.com"
    assert ev == client.get("/api/v1/sites/a.com/events").json()
    # a key for A has no endpoint that can name B; it structurally never sees B's larger numbers
    assert a["totals"]["requests"] != 99


# ---------------------------------------------------------------- records / config parity

def test_records_crud_via_capi_mirrors_admin(client, fake_pdns):
    make_site(client)
    key = new_key(client, scopes=["dns"])["key"]

    created = client.post(f"{CAPI}/records", json={"name": "api", "type": "A", "content": "185.1.2.3"},
                          headers=auth(key))
    assert created.status_code == 201, created.text
    rid = created.json()["id"]
    # the admin API sees the same record
    admin_list = client.get("/api/v1/sites/example.com/records").json()
    assert any(r["id"] == rid and r["name"] == "api" for r in admin_list)
    assert client.get(f"{CAPI}/records", headers=auth(key)).json() == admin_list

    upd = client.patch(f"{CAPI}/records/{rid}", json={"name": "api", "type": "A", "content": "185.1.2.9"},
                       headers=auth(key))
    assert upd.status_code == 200 and upd.json()["content"] == "185.1.2.9"
    assert client.delete(f"{CAPI}/records/{rid}", headers=auth(key)).status_code == 200
    assert client.delete(f"{CAPI}/records/{rid}", headers=auth(key)).status_code == 404


def test_config_read_write_via_capi_mirrors_admin(client):
    make_site(client)
    key = new_key(client, scopes=["dns"])["key"]

    fw = {"default_action": "allow", "rules": [
        {"id": "r1", "action": "block",
         "conditions": [{"field": "country", "op": "in", "value": ["cn"]}]}]}
    w = client.put(f"{CAPI}/config/firewall", json=fw, headers=auth(key))
    assert w.status_code == 200, w.text
    assert client.get(f"{CAPI}/config/firewall", headers=auth(key)).json() == w.json()
    # admin sees the same stored section
    assert client.get("/api/v1/sites/example.com/config/firewall").json() == w.json()
    assert client.get(f"{CAPI}/config/nope", headers=auth(key)).status_code == 404


# ---------------------------------------------------------------- rate limit

def test_rate_limit_429(client, monkeypatch):
    make_site(client)
    monkeypatch.setattr(settings, "capi_rate", 3)
    key = new_key(client, scopes=["stats"])["key"]
    for _ in range(3):
        assert client.get(f"{CAPI}/analytics", headers=auth(key)).status_code == 200
    r = client.get(f"{CAPI}/analytics", headers=auth(key))
    assert r.status_code == 429 and "detail" in r.json()


# ---------------------------------------------------------------- cross-surface isolation

def test_admin_key_rejected_on_capi_and_customer_key_rejected_on_admin(client):
    make_site(client)
    key = new_key(client, scopes=["purge", "stats", "dns"])["key"]

    # the admin key must NOT authenticate the customer surface
    assert client.get(f"{CAPI}/analytics", headers=auth("test-admin-key")).status_code == 401
    assert client.post(f"{CAPI}/purge", json={"everything": True},
                       headers=auth("test-admin-key")).status_code == 401

    # a customer key must NOT authenticate the admin / edge surfaces
    assert client.get("/api/v1/ping", headers=auth(key)).status_code == 401
    assert client.get("/api/v1/sites/example.com/records", headers=auth(key)).status_code == 401
    assert client.get("/edge/v1/config", headers=auth(key)).status_code == 401


def test_deleted_site_leaves_no_key_or_data_for_a_reused_id(client):
    """SQLite enforces no foreign keys and may hand a deleted site's id to the next site: the old
    customer's API key, usage and events must never carry over to it."""
    first = make_site(client, "old.example")
    key = new_key(client, "old.example")["key"]
    ingest(client, "old.example")
    assert client.delete("/api/v1/sites/old.example").status_code == 200
    second = make_site(client, "new.example")
    assert client.get(f"{CAPI}/analytics", headers=auth(key)).status_code == 401
    if second["id"] == first["id"]:   # the id really was reused (SQLite)
        assert client.get("/api/v1/sites/new.example/apikeys").json() == []
        totals = client.get("/api/v1/sites/new.example/analytics?period=24h").json()["totals"]
        assert totals["requests"] == 0


def test_no_public_admin_api_docs(client):
    for path in ("/docs", "/redoc", "/openapi.json"):
        assert client.get(path).status_code == 404, path
    assert client.get(f"{CAPI}/openapi.json").status_code == 200
