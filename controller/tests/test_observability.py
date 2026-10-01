"""Wave 5: Prometheus /metrics, the audit log + GET /api/v1/audit, and the audit prune job."""

from datetime import timedelta

from app import scheduler
from app.config import settings
from app.db import SessionLocal
from app.models import AuditLog, utcnow


# ------------------------------------------------------------------ /metrics

def _families(text: str) -> dict[str, list[str]]:
    """Map every sample line to its metric name (ignoring labels), for easy assertions."""
    out: dict[str, list[str]] = {}
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        name = line.split("{", 1)[0].split(" ", 1)[0]
        out.setdefault(name, []).append(line)
    return out


def test_metrics_exposes_platform_aggregates(client):
    client.post("/api/v1/sites", json={"domain": "example.com", "origin_ip": "93.184.216.34"})
    client.post("/api/v1/sites", json={"domain": "second.org"})
    client.post("/api/v1/edges", json={"name": "ir-1", "ipv4": "5.160.1.10", "region": "home"})

    r = client.get("/metrics")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/plain; version=0.0.4")
    fam = _families(r.text)
    # the aggregates listed in SPEC §13.1
    for name in ("pcdn_edges_total", "pcdn_edges_online", "pcdn_edges_shed", "pcdn_edges_probe_failing",
                 "pcdn_sites_total", "pcdn_sites", "pcdn_ssl_certificates", "pcdn_ssl_certs_expiring",
                 "pcdn_active_alerts", "pcdn_dns_sync_errors", "pcdn_audit_log_entries"):
        assert name in fam, name
    assert any(line.endswith(" 2") for line in fam["pcdn_sites_total"])
    assert any(line.endswith(" 1") for line in fam["pcdn_edges_total"])
    # Prometheus HELP/TYPE scaffolding is present
    assert "# TYPE pcdn_edges_total gauge" in r.text


def test_metrics_leaks_no_domain_or_ip(client):
    client.post("/api/v1/sites", json={"domain": "secret-domain.example", "origin_ip": "203.0.113.7"})
    client.post("/api/v1/edges", json={"name": "edge-secret", "ipv4": "198.51.100.9", "region": "home"})
    text = client.get("/metrics").text
    for leak in ("secret-domain.example", "203.0.113.7", "198.51.100.9", "edge-secret", "token"):
        assert leak not in text, leak


def test_metrics_token_required_when_set(client, monkeypatch):
    monkeypatch.setattr(settings, "metrics_token", "scrape-secret")
    # no header -> 401
    bare = client.__class__(client.app)  # a client without the admin Authorization header
    assert bare.get("/metrics").status_code == 401
    # wrong token -> 401
    assert bare.get("/metrics", headers={"Authorization": "Bearer nope"}).status_code == 401
    # correct token -> 200
    ok = bare.get("/metrics", headers={"Authorization": "Bearer scrape-secret"})
    assert ok.status_code == 200 and "pcdn_edges_total" in ok.text


def test_metrics_open_when_token_unset(client, monkeypatch):
    monkeypatch.setattr(settings, "metrics_token", "")
    bare = client.__class__(client.app)
    assert bare.get("/metrics").status_code == 200


def test_metrics_counts_usage_batches(client):
    client.post("/api/v1/sites", json={"domain": "example.com"})
    edge = client.post("/api/v1/edges", json={"name": "ir-1", "ipv4": "5.160.1.10", "region": "home"}).json()
    hour = utcnow().replace(minute=0, second=0, microsecond=0).isoformat() + "Z"
    for bid in ("a" * 32, "b" * 32):
        client.post("/edge/v1/usage", headers={"Authorization": "Bearer " + edge["token"]},
                    json={"batch_id": bid, "items": [{"host": "example.com", "hour": hour,
                          "bytes": 10, "requests": 1, "cache_hits": 0}], "events": []})
    fam = _families(client.get("/metrics").text)
    assert "pcdn_usage_batches_ingested_total" in fam
    assert fam["pcdn_usage_batches_ingested_total"][0].endswith(" 2")


# ------------------------------------------------------------------ audit log

def _audit(client, **params):
    return client.get("/api/v1/audit", params=params).json()


def test_audit_recorded_on_create_site(client):
    client.post("/api/v1/sites", json={"domain": "example.com", "origin_ip": "93.184.216.34"})
    rows = _audit(client, action="site.create")
    assert len(rows) == 1
    e = rows[0]
    assert e["action"] == "site.create" and e["target"] == "example.com"
    assert e["actor"] == "admin" and e["actor_kind"] == "admin"
    assert e["detail"].get("external_id") is None
    assert e["at"].endswith("Z")


def test_audit_recorded_on_edge_and_address_and_purge(client):
    client.post("/api/v1/sites", json={"domain": "example.com"})
    edge = client.post("/api/v1/edges", json={"name": "ir-1", "ipv4": "5.160.1.10", "region": "home"}).json()
    client.post(f"/api/v1/edges/{edge['id']}/addresses", json={"family": 4, "ip": "5.160.1.11"})
    client.post("/api/v1/sites/example.com/purge", json={"everything": True})

    actions = {e["action"] for e in _audit(client, limit=50)}
    assert {"site.create", "edge.add", "edge.address.add", "purge"} <= actions
    add = _audit(client, action="edge.add")[0]
    assert add["target"] == "ir-1" and add["detail"]["region"] == "home"


def test_audit_never_stores_secrets(client):
    """A rotated edge token and a custom cert/key must never appear in the audit detail."""
    client.post("/api/v1/sites", json={"domain": "example.com"})
    edge = client.post("/api/v1/edges", json={"name": "ir-1", "ipv4": "5.160.1.10"}).json()
    token = client.post(f"/api/v1/edges/{edge['id']}/rotate-token").json()["token"]
    blob = str(_audit(client, limit=50))
    assert token not in blob
    for forbidden in ("ssl_key", "secret", "token_hash", "private"):
        assert forbidden not in blob


def test_audit_filters_newest_first_and_limit_cap(client):
    for d in ("a.com", "b.com", "c.com"):
        client.post("/api/v1/sites", json={"domain": d})
    rows = _audit(client, action="site.create")
    # newest first
    assert [r["target"] for r in rows] == ["c.com", "b.com", "a.com"]
    # actor filter
    assert _audit(client, actor="nobody") == []
    assert len(_audit(client, actor="admin")) >= 3
    # limit is capped at 500
    assert len(client.get("/api/v1/audit", params={"limit": 100000}).json()) <= 500
    # explicit small limit honoured
    assert len(_audit(client, limit=1)) == 1


def test_audit_since_filter(client):
    client.post("/api/v1/sites", json={"domain": "old.com"})
    future = (utcnow() + timedelta(hours=1)).isoformat() + "Z"
    assert _audit(client, since=future) == []
    past = (utcnow() - timedelta(hours=1)).isoformat()
    assert len(_audit(client, since=past)) >= 1


def test_audit_requires_admin(client):
    bare = client.__class__(client.app)
    assert bare.get("/api/v1/audit").status_code == 401


# ------------------------------------------------------------------ prune job

def test_prune_job_removes_old_rows(client, monkeypatch):
    monkeypatch.setattr(settings, "audit_retention_days", 30)
    with SessionLocal() as db:
        db.add(AuditLog(at=utcnow() - timedelta(days=90), actor="admin", actor_kind="admin",
                        action="site.create", target="old.com", detail="{}"))
        db.add(AuditLog(at=utcnow() - timedelta(days=1), actor="admin", actor_kind="admin",
                        action="site.create", target="fresh.com", detail="{}"))
        db.commit()
        scheduler.job_prune_audit(db)
    targets = [e["target"] for e in client.get("/api/v1/audit").json()]
    assert "fresh.com" in targets and "old.com" not in targets


def test_prune_job_disabled_when_retention_zero(client, monkeypatch):
    monkeypatch.setattr(settings, "audit_retention_days", 0)
    with SessionLocal() as db:
        db.add(AuditLog(at=utcnow() - timedelta(days=9999), actor="system", actor_kind="system",
                        action="ssl.issue", target="x.com", detail="{}"))
        db.commit()
        scheduler.job_prune_audit(db)
        assert db.query(AuditLog).count() == 1


# ------------------------------------------------------------------ customer API actor

def test_capi_write_audited_with_key_actor(client):
    client.post("/api/v1/sites", json={"domain": "example.com"})
    key = client.post("/api/v1/sites/example.com/apikeys",
                      json={"name": "ci-key", "scopes": ["purge"]}).json()["key"]
    capi = client.__class__(client.app)
    capi.headers["Authorization"] = "Bearer " + key
    assert capi.post("/capi/v1/purge", json={"everything": True}).status_code == 200
    rows = _audit(client, actor="ci-key")
    assert len(rows) == 1 and rows[0]["action"] == "purge" and rows[0]["actor_kind"] == "capi"
    assert rows[0]["target"] == "example.com"
