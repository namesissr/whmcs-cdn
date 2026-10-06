"""Wave 4 — scale & operations (SPEC §11): centralized node logs, batch add, bundle routes."""

import io
import tarfile

from app.config import settings


def add_edge(client, name="ir-1", ip="5.160.1.10", region="home", group="general"):
    r = client.post("/api/v1/edges", json={"name": name, "ipv4": ip, "region": region, "group": group})
    assert r.status_code == 201, r.text
    return r.json()


def edge_headers(token):
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------- centralized logs (§11.2)

def test_logs_require_edge_auth(client):
    assert client.post("/edge/v1/logs", json={"lines": []}).status_code == 401
    assert client.post("/edge/v1/logs", json={"lines": []},
                       headers=edge_headers("bad")).status_code == 401


def test_logs_stored_and_read_back(client):
    tok = add_edge(client)["token"]
    body = {"lines": [{"t": "2026-09-30T10:00:00Z", "level": "error", "msg": "upstream timed out"},
                      {"t": "2026-09-30T10:00:01Z", "level": "warn", "msg": "cache full"}]}
    r = client.post("/edge/v1/logs", json=body, headers=edge_headers(tok))
    assert r.status_code == 200, r.text

    eid = client.get("/api/v1/edges").json()[0]["id"]
    got = client.get(f"/api/v1/edges/{eid}/logs").json()
    assert got["name"] == "ir-1"
    assert got["logs_at"] is not None
    assert [ln["msg"] for ln in got["lines"]] == ["upstream timed out", "cache full"]
    # edge_to_dict hint
    ed = client.get("/api/v1/edges").json()[0]
    assert ed["has_logs"] is True
    assert ed["logs_at"] is not None


def test_logs_level_validation_and_msg_cap(client):
    tok = add_edge(client)["token"]
    r = client.post("/edge/v1/logs", headers=edge_headers(tok), json={
        "lines": [{"t": "", "level": "bogus", "msg": "x" * 999}]})
    assert r.status_code == 200
    eid = client.get("/api/v1/edges").json()[0]["id"]
    lines = client.get(f"/api/v1/edges/{eid}/logs").json()["lines"]
    assert lines[0]["level"] == "info"          # unknown level -> info
    assert len(lines[0]["msg"]) == 500          # capped ~500 chars


def test_logs_reject_over_40_lines(client):
    tok = add_edge(client)["token"]
    r = client.post("/edge/v1/logs", headers=edge_headers(tok),
                    json={"lines": [{"t": "", "level": "warn", "msg": str(i)} for i in range(41)]})
    assert r.status_code == 422  # pydantic max_length


def test_logs_ring_cap_enforced_across_calls(client):
    tok = add_edge(client)["token"]
    # push far more than the 120-line cap across many calls
    for batch in range(10):
        client.post("/edge/v1/logs", headers=edge_headers(tok), json={
            "lines": [{"t": "", "level": "warn", "msg": f"line-{batch}-{i}"} for i in range(40)]})
    eid = client.get("/api/v1/edges").json()[0]["id"]
    lines = client.get(f"/api/v1/edges/{eid}/logs").json()["lines"]
    assert len(lines) <= 120
    # newest kept (oldest dropped): the last pushed line survives, the first does not
    msgs = [ln["msg"] for ln in lines]
    assert "line-9-39" in msgs
    assert "line-0-0" not in msgs


def test_logs_byte_cap_enforced(client):
    tok = add_edge(client)["token"]
    big = "z" * 500
    for _ in range(5):
        client.post("/edge/v1/logs", headers=edge_headers(tok),
                    json={"lines": [{"t": "", "level": "error", "msg": big} for _ in range(40)]})
    eid = client.get("/api/v1/edges").json()[0]["id"]
    import json as _json
    from app.db import SessionLocal
    from app.models import Edge
    db = SessionLocal()
    try:
        e = db.get(Edge, eid)
        assert len(e.logs.encode("utf-8")) <= 16 * 1024
        assert isinstance(_json.loads(e.logs), list)
    finally:
        db.close()


def test_logs_404_unknown_edge(client):
    assert client.get("/api/v1/edges/9999/logs").status_code == 404


def test_empty_logs_state(client):
    add_edge(client)
    eid = client.get("/api/v1/edges").json()[0]["id"]
    got = client.get(f"/api/v1/edges/{eid}/logs").json()
    assert got["lines"] == [] and got["logs_at"] is None
    assert client.get("/api/v1/edges").json()[0]["has_logs"] is False


# ---------------------------------------------------------------- heartbeat extras (§11.1)

def test_heartbeat_reports_bundle_version_and_first_contact_region(client):
    # create as global/general, node self-registers as home/tunnel on first heartbeat
    tok = add_edge(client, region="global", group="general")["token"]
    r = client.post("/edge/v1/heartbeat", headers=edge_headers(tok),
                    json={"applied_version": "v1", "bundle_version": "abc123",
                          "region": "home", "group": "tunnel"})
    assert r.status_code == 200
    e = client.get("/api/v1/edges").json()[0]
    assert e["bundle_version"] == "abc123"
    assert e["region"] == "home" and e["group"] == "tunnel"
    # a later heartbeat does NOT override an operator's region (only first contact self-registers)
    client.post("/edge/v1/heartbeat", headers=edge_headers(tok),
                json={"applied_version": "v1", "region": "global", "group": "general"})
    e = client.get("/api/v1/edges").json()[0]
    assert e["region"] == "home" and e["group"] == "tunnel"


# ---------------------------------------------------------------- batch add + install (§11.1)

def test_batch_create(client):
    r = client.post("/api/v1/edges/batch", json={"count": 3, "region": "home", "group": "tunnel",
                                                 "name_prefix": "ir", "capacity_mbps": 1000})
    assert r.status_code == 201, r.text
    edges = r.json()["edges"]
    assert len(edges) == 3
    names = [e["name"] for e in edges]
    assert names == ["ir-1", "ir-2", "ir-3"]
    for e in edges:
        assert e["token"].startswith("edge_")
        assert e["region"] == "home" and e["group"] == "tunnel"
        assert "| sudo PCDN_EDGE_TOKEN=" + e["token"] + " bash -s -- " in e["install"]
        assert "--token" not in e["install"]
        assert "--region home" in e["install"] and "--role tunnel" in e["install"]


def test_batch_edge_ip_placeholder_and_self_register(client):
    r = client.post("/api/v1/edges/batch", json={"count": 1, "name_prefix": "ir"})
    assert r.json()["edges"][0]["ipv4"] == "0.0.0.0"

    # unit-test the self-registration helper directly (TestClient can't run the proxy middleware)
    from types import SimpleNamespace

    from app.models import Edge
    from app.routes_edge import _self_register_ip

    e = Edge(name="x", ipv4="0.0.0.0", ipv6=None)
    _self_register_ip(e, SimpleNamespace(client=SimpleNamespace(host="5.160.1.10")))
    assert e.ipv4 == "5.160.1.10"
    # a private/loopback source never overwrites the placeholder
    e2 = Edge(name="y", ipv4="0.0.0.0", ipv6=None)
    _self_register_ip(e2, SimpleNamespace(client=SimpleNamespace(host="10.0.0.5")))
    assert e2.ipv4 == "0.0.0.0"
    # a real (non-placeholder) IP is never touched
    e3 = Edge(name="z", ipv4="5.6.7.8", ipv6=None)
    _self_register_ip(e3, SimpleNamespace(client=SimpleNamespace(host="88.99.1.10")))
    assert e3.ipv4 == "5.6.7.8"


def test_batch_skips_taken_names(client):
    add_edge(client, name="ir-1")
    r = client.post("/api/v1/edges/batch", json={"count": 2, "name_prefix": "ir"})
    names = [e["name"] for e in r.json()["edges"]]
    assert names == ["ir-2", "ir-3"]


def test_install_oneliner_endpoint(client, monkeypatch):
    monkeypatch.setattr(settings, "controller_domain", "cdn-api.example.com")
    r = client.get("/api/v1/edges/install?token=edge_xyz&region=home&role=tunnel")
    assert r.status_code == 200
    cmd = r.json()["command"]
    assert cmd.startswith("curl -fsSL https://cdn-api.example.com/edge/bootstrap.sh")
    assert "--controller https://cdn-api.example.com" in cmd
    assert cmd == ("curl -fsSL https://cdn-api.example.com/edge/bootstrap.sh | sudo PCDN_EDGE_TOKEN=edge_xyz "
                   "bash -s -- --controller https://cdn-api.example.com --region home --role tunnel")
    # the token is passed via the environment (not bash's argv) and shell-quoted
    r = client.get("/api/v1/edges/install", params={"token": "edge_x; id"})
    assert "PCDN_EDGE_TOKEN='edge_x; id' bash" in r.json()["command"]


# ---------------------------------------------------------------- public bundle routes (§11.1)

def test_bootstrap_sh_served(client):
    r = client.get("/edge/bootstrap.sh")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/x-shellscript")
    assert "bundle.tar.gz" in r.text and "install.sh" in r.text


def test_version_stable(client):
    a = client.get("/edge/version")
    b = client.get("/edge/version")
    assert a.status_code == 200 and a.json()["version"]
    assert a.json() == b.json()  # identical tree -> identical hash


def test_bundle_tar_excludes_pycache_and_tests(client):
    r = client.get("/edge/bundle.tar.gz")
    assert r.status_code == 200
    assert r.headers["content-type"] == "application/gzip"
    tf = tarfile.open(fileobj=io.BytesIO(r.content), mode="r:gz")
    names = tf.getnames()
    assert any(n == "edge/install.sh" for n in names)
    assert any(n == "edge/pcdn-agent.py" for n in names)
    assert not any("__pycache__" in n for n in names)
    assert not any(n.endswith(".pyc") for n in names)
    assert not any("/tests/" in n or n.startswith("edge/tests") for n in names)


def test_bundle_404_when_dir_missing(client, monkeypatch, tmp_path):
    missing = str(tmp_path / "nope")
    monkeypatch.setattr(settings, "edge_bundle_dir", missing)
    assert client.get("/edge/bundle.tar.gz").status_code == 404
    assert client.get("/edge/bootstrap.sh").status_code == 404
    assert client.get("/edge/version").status_code == 404


def test_bundle_routes_are_unauthenticated(client):
    # no admin/edge auth header, still served (public bundle)
    r = client.get("/edge/version", headers={"Authorization": ""})
    assert r.status_code in (200, 404)  # 200 when a bundle dir exists
