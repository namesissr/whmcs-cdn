"""SPEC §19 controller side: operator (admin-owned) sites (§19.1) and domain transfer (§19.2)."""

import json
from datetime import datetime, timedelta

import httpx
import pytest
from sqlalchemy import create_engine, select, text

from app import (migrate, routes_capi, routes_platform, scheduler, services, site_secrets, statements, storage,
                 tenancy)
from app.config import settings
from app.minio_client import MinioClient
from app.db import SessionLocal
from app.models import (AccessOtp, ApiKey, AuditLog, Edge, LogSpool, Site, StorageBucket, UsageHourly,
                        WebhookDelivery, utcnow)
from tests.test_storage import ADMIN_AK, ADMIN_SK, ENDPOINT, FakeMinio
from tests.test_wave8 import TSIG

CAPI = "/capi/v1"
GB = 1024**3


@pytest.fixture(autouse=True)
def _isolate(fake_dns):
    routes_capi._hits.clear()
    routes_platform._test_hits.clear()
    yield
    routes_capi._hits.clear()
    routes_platform._test_hits.clear()


def create(client, domain, status=201, **body):
    r = client.post("/api/v1/sites", json={"domain": domain, **body})
    assert r.status_code == status, r.text
    return r.json()


def operator(client, domain, status=201, **body):
    return create(client, domain, status, operator=True, **body)


def transfer(client, domain, status=200, **body):
    r = client.post(f"/api/v1/sites/{domain}/transfer", json=body)
    assert r.status_code == status, r.text
    return r.json()


def db_site(db, domain) -> Site:
    return db.scalar(select(Site).where(Site.domain == domain))


def new_key(client, domain, scopes=("stats", "purge")):
    r = client.post(f"/api/v1/sites/{domain}/apikeys", json={"name": "k", "scopes": list(scopes)})
    assert r.status_code == 201, r.text
    return r.json()["key"]


def capi_ok(client, key) -> int:
    return client.get(f"{CAPI}/analytics", headers={"Authorization": f"Bearer {key}"}).status_code


def add_usage(domain, hour: datetime, nbytes: int):
    with SessionLocal() as db:
        edge = db.scalar(select(Edge))
        if edge is None:
            edge = Edge(name="ir-1", ipv4="5.160.1.10", region="home", token_hash="h")
            db.add(edge)
            db.flush()
        db.add(UsageHourly(site_id=db_site(db, domain).id, edge_id=edge.id, hour=hour, bytes=nbytes, requests=1,
                           cache_hits=0))
        db.commit()


# ================================================================== tenancy helpers

class _S:
    def __init__(self, client_id=None, reseller_client_id=None, owner_kind="client"):
        self.client_id, self.reseller_client_id, self.owner_kind = client_id, reseller_client_id, owner_kind


def test_tenancy_owner_identities():
    op = _S(owner_kind="operator")
    assert tenancy.site_owner(op) == tenancy.OPERATOR == "operator"
    assert tenancy.owner_of(None, None, operator=True) == "operator"
    assert tenancy.owner_of(5, None, operator=True) == "operator"  # the kind wins
    # one shared identity for all operator sites, distinct from every client / reseller / nobody
    assert tenancy.same_owner("operator", _S(owner_kind="operator"))
    for other in (_S(client_id=1), _S(reseller_client_id=1), _S()):
        assert not tenancy.same_owner("operator", other)
        assert not tenancy.same_owner(tenancy.site_owner(other), op)
    # unchanged for clients / resellers / legacy null-owner sites
    assert tenancy.same_owner(7, _S(client_id=7)) and tenancy.same_owner(7, _S(reseller_client_id=7))
    assert not tenancy.same_owner(None, _S()) and tenancy.site_owner(_S()) is None


def test_tenancy_nesting_across_kinds(client):
    operator(client, "platform.ir")
    operator(client, "cdn.platform.ir")  # the operator may nest its own domains
    operator(client, "deep.cdn.platform.ir")
    # a customer can never add a child of an operator domain, at any depth, nor a reseller
    r = client.post("/api/v1/sites", json={"domain": "shop.platform.ir", "client_id": 3})
    assert r.status_code == 422 and "زیردامنه" in r.json()["detail"]
    create(client, "x.cdn.platform.ir", 422, reseller_client_id=3)
    create(client, "y.platform.ir", 422)  # nobody (legacy admin create) is not the operator either
    # ... and the operator never adds a parent / child of a customer's domain
    create(client, "customer.com", client_id=3)
    operator(client, "shop.customer.com", 422)
    create(client, "a.b.example.org", client_id=4)
    operator(client, "example.org", 422)
    # domain-check knows the operator
    chk = lambda **b: client.post("/api/v1/domain-check", json=b).json()  # noqa: E731
    assert chk(domain="api.platform.ir", operator=True)["ok"] is True
    assert chk(domain="api.platform.ir", client_id=3)["code"] == "nested"
    assert chk(domain="api.customer.com", operator=True)["code"] == "nested"
    assert chk(domain="api.customer.com", client_id=3)["ok"] is True
    assert client.post("/api/v1/domain-check", json={"domain": "z.ir", "operator": True,
                                                     "client_id": 1}).status_code == 422


def test_nested_sites_audit_ignores_operator_pairs(client, monkeypatch):
    operator(client, "platform.ir")
    operator(client, "a.platform.ir")
    raised = []
    monkeypatch.setattr(scheduler.alerts, "raise_alert", lambda k, *a, **kw: raised.append(k))
    with SessionLocal() as db:
        assert tenancy.nested_conflicts(db) == []
        assert scheduler.job_security_audit(db, force=True)["nested"] == []
    assert "nested_sites" not in raised
    # a legacy foreign child of an operator site is still reported
    with SessionLocal() as db:
        db.add(Site(domain="evil.platform.ir", client_id=9))
        db.commit()
        assert tenancy.nested_conflicts(db) == [("platform.ir", "evil.platform.ir")]


# ================================================================== §19.1 operator sites

def test_create_operator_site(client):
    s = operator(client, "Platform.IR", operator_note="  landing page\n of the brand ", origin_ip="93.184.216.34",
                 plan={"bandwidth_limit_gb": 0, "features": {"waf": True}})
    assert s["owner_kind"] == "operator" and s["operator_note"] == "landing page of the brand"
    assert s["client_id"] is None and s["reseller_client_id"] is None and s["external_id"] is None
    assert s["billing_since"] is None and s["plan"]["features"]["waf"] is True
    assert {r["name"] for r in s["records"]} == {"@", "www"}
    got = client.get("/api/v1/sites/platform.ir").json()
    assert got["owner_kind"] == "operator" and got["operator_note"] == "landing page of the brand"
    with SessionLocal() as db:
        a = db.scalar(select(AuditLog).where(AuditLog.action == "site.create"))
        assert json.loads(a.detail)["owner_kind"] == "operator"
    # normal sites
    assert create(client, "c.com", client_id=3)["owner_kind"] == "client"
    assert create(client, "r.com", reseller_client_id=4, reseller_label="x")["owner_kind"] == "reseller"
    legacy = create(client, "legacy.com")
    assert legacy["owner_kind"] == "client" and legacy["operator_note"] is None


@pytest.mark.parametrize("extra", [{"client_id": 1}, {"reseller_client_id": 2}, {"reseller_label": "x"},
                                   {"external_id": "55"}])
def test_operator_site_rejects_owner_fields(client, extra):
    r = client.post("/api/v1/sites", json={"domain": "platform.ir", "operator": True, **extra})
    assert r.status_code == 422 and "اپراتور" in r.json()["detail"]
    with SessionLocal() as db:
        assert db_site(db, "platform.ir") is None


def test_operator_note_validation_and_edit(client):
    r = client.post("/api/v1/sites", json={"domain": "p.ir", "operator": True, "operator_note": "x" * 201})
    assert r.status_code == 422
    r = client.post("/api/v1/sites", json={"domain": "p.ir", "client_id": 1, "operator_note": "n"})
    assert r.status_code == 422  # a note needs operator: true
    operator(client, "p.ir")
    r = client.patch("/api/v1/sites/p.ir/operator", json={"operator_note": " main site "})
    assert r.status_code == 200 and r.json()["operator_note"] == "main site"
    assert client.patch("/api/v1/sites/p.ir/operator", json={"operator_note": "y" * 201}).status_code == 422
    assert client.patch("/api/v1/sites/p.ir/operator", json={"bogus": 1}).status_code == 422
    assert client.patch("/api/v1/sites/p.ir/operator", json={"operator_note": None}).json()["operator_note"] is None
    with SessionLocal() as db:
        assert db.scalar(select(AuditLog).where(AuditLog.action == "site.operator_note")) is not None
    create(client, "c.com", client_id=3)
    assert client.patch("/api/v1/sites/c.com/operator", json={"operator_note": "n"}).status_code == 422
    assert client.patch("/api/v1/sites/missing.com/operator", json={"operator_note": "n"}).status_code == 404
    # the owner / reseller patches refuse operator sites (use a transfer)
    assert client.patch("/api/v1/sites/p.ir/owner", json={"client_id": 4}).status_code == 422
    assert client.patch("/api/v1/sites/p.ir/reseller", json={"reseller_client_id": 4}).status_code == 422


def test_reseller_patch_keeps_owner_kind_in_sync(client):
    create(client, "c.com", client_id=3)
    assert client.patch("/api/v1/sites/c.com/reseller", json={"reseller_client_id": 3}).json()["owner_kind"] \
        == "reseller"
    assert client.patch("/api/v1/sites/c.com/reseller", json={"reseller_client_id": None}).json()["owner_kind"] \
        == "client"


def test_list_filter_by_owner(client):
    operator(client, "p.ir", operator_note="n")
    create(client, "c.com", client_id=3, external_id="10")
    create(client, "r.com", reseller_client_id=4)
    create(client, "r2.com", reseller_client_id=5)
    every = client.get("/api/v1/sites").json()
    assert [s["domain"] for s in every] == ["p.ir", "c.com", "r.com", "r2.com"]
    assert every[0] == {"domain": "p.ir", "status": "pending_ns", "external_id": None, "client_id": None,
                        "reseller_client_id": None, "reseller_label": None, "owner_kind": "operator",
                        "operator_note": "n", "billing_since": None}
    names = lambda q: [s["domain"] for s in client.get(f"/api/v1/sites?{q}").json()]  # noqa: E731
    assert names("owner=operator") == ["p.ir"]
    assert names("owner=client") == ["c.com"]
    assert names("owner=reseller") == ["r.com", "r2.com"]
    assert client.get("/api/v1/sites?owner=bogus").status_code == 422
    # reseller= keeps its rolled-up shape
    assert client.get("/api/v1/sites?reseller=4").json() == [
        {"domain": "r.com", "reseller_label": None, "status": "pending_ns", "bandwidth_limit_gb": 0,
         "over_quota": False, "suspended": False}]


def test_overview_counts_owner_kinds(client):
    operator(client, "p.ir")
    create(client, "c.com", client_id=3)
    assert client.get("/api/v1/overview").json()["sites"]["by_owner"] == {"operator": 1, "client": 1}


# ================================================================== §19.2 transfer

def _integrations(client, domain, access=True):
    """Two webhooks, log export and an access app (with its secret) on `domain`."""
    path = f"/api/v1/sites/{domain}"
    if access:
        assert client.patch(f"{path}/plan", json={"features": {"access": True}}).status_code == 200
        r = client.put(f"{path}/config/access", json={"enabled": True, "apps": [
            {"id": "admin", "name": "Admin", "paths": ["/admin"], "methods": "otp", "emails": ["a@b.com"]}]})
        assert r.status_code == 200, r.text
    r = client.put(f"{path}/config/webhooks", json={"items": [
        {"url": "https://hooks.public.example/a", "events": ["quota.exceeded", "purge.completed"]},
        {"url": "https://hooks.public.example/b", "events": ["ssl.issued"], "enabled": False}]})
    assert r.status_code == 200, r.text
    r = client.put(f"{path}/config/logs", json={
        "enabled": True, "s3_endpoint": "https://s3.public.example", "region": "r", "bucket": "old-logs",
        "prefix": "cdn/", "access_key": "AKID", "secret_key": "OLD-SECRET", "anonymize_ip": True,
        "sample_rate": 0.5})
    assert r.status_code == 200, r.text
    return [i["id"] for i in client.get(f"{path}/config/webhooks").json()["items"]]


def test_transfer_client_to_client_full(client):
    create(client, "shop.com", client_id=1, external_id="100", origin_ip="93.184.216.34")
    hook_ids = _integrations(client, "shop.com")
    k1, k2 = new_key(client, "shop.com"), new_key(client, "shop.com")
    assert capi_ok(client, k1) == 200 and capi_ok(client, k2) == 200
    with SessionLocal() as db:
        s = db_site(db, "shop.com")
        old_access = site_secrets.get_secret(s, "access")
        assert old_access and site_secrets.logs_secret(s) == "OLD-SECRET"
        assert site_secrets.webhook_secret_ids(s) == set(hook_ids)
        db.add(WebhookDelivery(delivery_id="dlv_1", site_id=s.id, hook_id=hook_ids[0], event="purge.completed",
                               event_id="evt_1", payload="{}", status="pending", attempts=0,
                               next_attempt_at=utcnow()))
        db.add(LogSpool(site_id=s.id, hour=utcnow().replace(minute=0, second=0, microsecond=0),
                        records=1, data=b"x"))
        db.add(AccessOtp(site_id=s.id, email_hash="e" * 64, at=utcnow()))
        db.commit()
        records_before = len(s.records)
        config_before = json.loads(s.config)

    r = transfer(client, "shop.com", to={"kind": "client", "client_id": 2})
    assert r["domain"] == "shop.com" and r["dry_run"] is False
    assert r["from"] == {"kind": "client", "client_id": 1, "external_id": "100"}
    # client -> client: the WHMCS service moves with the site, so external_id is kept unless sent
    assert r["to"] == {"kind": "client", "client_id": 2, "external_id": "100"}
    assert r["related"] == [] and r["revoked_keys"] == 2 and r["billing_since"] is None
    assert r["access_rotated"] == ["shop.com"]
    assert sorted((p["type"], p["id"]) for p in r["paused"]) == sorted(
        [("logs", None)] + [("webhook", h) for h in hook_ids])

    # revoked keys fail auth now
    assert capi_ok(client, k1) == 401 and capi_ok(client, k2) == 401
    assert all(k["revoked"] for k in client.get("/api/v1/sites/shop.com/apikeys").json())
    site = client.get("/api/v1/sites/shop.com").json()
    assert site["client_id"] == 2 and site["owner_kind"] == "client" and site["external_id"] == "100"
    # integrations paused with their settings kept, secrets gone
    logs = client.get("/api/v1/sites/shop.com/config/logs").json()
    assert logs["enabled"] is False and logs["bucket"] == "old-logs" and logs["access_key"] == "AKID"
    assert logs["secret_key_set"] is False
    hooks = client.get("/api/v1/sites/shop.com/config/webhooks").json()["items"]
    assert [h["id"] for h in hooks] == hook_ids and not any(h["enabled"] for h in hooks)
    assert not any(h["secret_set"] for h in hooks) and hooks[0]["url"] == "https://hooks.public.example/a"
    with SessionLocal() as db:
        s = db_site(db, "shop.com")
        assert site_secrets.logs_secret(s) is None and site_secrets.webhook_secret_ids(s) == set()
        new_access = site_secrets.get_secret(s, "access")
        assert new_access and new_access != old_access  # every access session of the old owner ends
        assert db.scalars(select(WebhookDelivery)).all() == [] and db.scalars(select(LogSpool)).all() == []
        # everything else stays with the site
        assert len(s.records) == records_before
        after = json.loads(s.config)
        assert after["access"] == config_before["access"]
        assert {k: v for k, v in after.items() if k not in ("logs", "webhooks")} == \
            {k: v for k, v in config_before.items() if k not in ("logs", "webhooks")}
        a = db.scalar(select(AuditLog).where(AuditLog.action == "site.transfer"))
        d = json.loads(a.detail)
        assert a.target == "shop.com" and d["from"]["client_id"] == 1 and d["to"]["client_id"] == 2
        assert d["revoked_keys"] == 2 and len(d["paused"]) == 3 and d["related"] == []
        assert "OLD-SECRET" not in a.detail and old_access not in a.detail
    # a webhook event after the transfer goes nowhere (the old endpoints are paused)
    assert client.post("/api/v1/sites/shop.com/purge", json={"everything": True}).status_code == 200
    with SessionLocal() as db:
        assert db.scalars(select(WebhookDelivery)).all() == []
    # tenancy follows: client 2 may add a child now, client 1 no longer
    create(client, "a.shop.com", 422, client_id=1)
    create(client, "a.shop.com", client_id=2)


def test_transfer_dry_run_changes_nothing(client):
    create(client, "shop.com", client_id=1, external_id="100")
    hook_ids = _integrations(client, "shop.com", access=False)
    key = new_key(client, "shop.com")
    with SessionLocal() as db:
        before = db.execute(text("SELECT * FROM sites")).mappings().all()
    r = transfer(client, "shop.com", to={"kind": "operator"}, reset_billing_anchor=True, dry_run=True)
    assert r["dry_run"] is True and r["revoked_keys"] == 1
    assert r["to"] == {"kind": "operator", "client_id": None, "external_id": None}
    assert {p["id"] for p in r["paused"] if p["type"] == "webhook"} == set(hook_ids)
    assert r["billing_since"] is not None and r["access_rotated"] == []
    with SessionLocal() as db:
        assert db.execute(text("SELECT * FROM sites")).mappings().all() == before
        assert db.scalar(select(AuditLog).where(AuditLog.action == "site.transfer")) is None
    assert capi_ok(client, key) == 200
    assert client.get("/api/v1/sites/shop.com/config/logs").json()["secret_key_set"] is True


def test_transfer_client_to_operator(client):
    create(client, "shop.com", client_id=1, external_id="100")
    key = new_key(client, "shop.com")
    r = transfer(client, "shop.com", to={"kind": "operator", "operator_note": "taken back"},
                 revoke_credentials=True, pause_integrations=True)
    assert r["to"] == {"kind": "operator", "client_id": None, "external_id": None} and r["revoked_keys"] == 1
    s = client.get("/api/v1/sites/shop.com").json()
    assert s["owner_kind"] == "operator" and s["operator_note"] == "taken back" and s["external_id"] is None
    assert capi_ok(client, key) == 401
    assert [x["domain"] for x in client.get("/api/v1/sites?owner=operator").json()] == ["shop.com"]
    # the operator now owns the tenancy of the name
    operator(client, "api.shop.com")
    create(client, "x.shop.com", 422, client_id=1)
    # transferring to the same owner again is refused
    r = client.post("/api/v1/sites/shop.com/transfer", json={"to": {"kind": "operator"}})
    assert r.status_code == 422 and "همین مالک" in r.json()["detail"]


def test_transfer_operator_to_client_with_billing_anchor(client):
    operator(client, "p.ir", operator_note="n", plan={"bandwidth_limit_gb": 1})
    now = utcnow()
    month = services.month_start(now)
    # the operator's traffic this month: 3 GB, already over the 1 GB limit
    add_usage("p.ir", month, 3 * GB)
    with SessionLocal() as db:
        s = db_site(db, "p.ir")
        services.refresh_quota(db, s)
        db.commit()
        assert s.over_quota is True
    r = transfer(client, "p.ir", to={"kind": "client", "client_id": 7, "external_id": "555"},
                 reset_billing_anchor=True)
    assert r["from"] == {"kind": "operator", "client_id": None, "external_id": None}
    assert r["to"] == {"kind": "client", "client_id": 7, "external_id": "555"}
    since = datetime.fromisoformat(r["billing_since"].rstrip("Z"))
    assert abs((since - now).total_seconds()) < 60
    s = client.get("/api/v1/sites/p.ir").json()
    assert s["operator_note"] is None and s["billing_since"] == r["billing_since"]
    assert s["usage_month"]["bytes"] == 0  # the new customer does not pay for the operator's traffic
    with SessionLocal() as db:
        site = db_site(db, "p.ir")
        assert site.over_quota is False and site.quota_warned_at is None
    # traffic after the anchor counts; history endpoints keep everything
    add_usage("p.ir", since + timedelta(hours=1), 2 * GB)
    with SessionLocal() as db:
        site = db_site(db, "p.ir")
        assert services.refresh_quota(db, site, now=since + timedelta(hours=2)) is True
        assert site.over_quota is True
        db.rollback()
    usage = client.get("/api/v1/usage").json()
    row = next(x for x in usage["sites"] if x["domain"] == "p.ir")
    assert row["bytes"] == 2 * GB and row["owner_kind"] == "client" and row["billing_since"] == r["billing_since"]
    assert row["external_id"] == "555"
    su = client.get("/api/v1/sites/p.ir/usage").json()
    assert su["month"]["bytes"] == 2 * GB and sum(d["bytes"] for d in su["daily"]) == 5 * GB
    # a month before the anchor reports nothing to the new owner
    prev = (month - timedelta(days=1)).strftime("%Y-%m")
    add_usage("p.ir", month - timedelta(days=2), 4 * GB)
    prow = next(x for x in client.get(f"/api/v1/usage?month={prev}").json()["sites"] if x["domain"] == "p.ir")
    assert prow["bytes"] == 0
    # the statement's quota counts from the anchor, the totals keep the whole month
    with SessionLocal() as db:
        doc = statements.build(db, db_site(db, "p.ir"), now=since + timedelta(hours=2))
    assert doc["totals"]["bytes"] == 5 * GB and doc["quota"]["used_gb"] == 2.0
    assert doc["billing_since"] == r["billing_since"]


def test_usage_and_quota_without_anchor_unchanged(client):
    create(client, "c.com", client_id=1, plan={"bandwidth_limit_gb": 1})
    month = services.month_start()
    add_usage("c.com", month, 2 * GB)
    with SessionLocal() as db:
        assert services.billed_usage(db, db_site(db, "c.com"), month)["bytes"] == 2 * GB
        assert services.refresh_quota(db, db_site(db, "c.com")) is True
    assert next(x for x in client.get("/api/v1/usage").json()["sites"])["bytes"] == 2 * GB


def test_billing_start_helper():
    s = _S()
    s.billing_since = None
    m = datetime(2026, 10, 1)
    assert services.billing_start(s, m) == m
    s.billing_since = datetime(2026, 9, 20)
    assert services.billing_start(s, m) == m
    s.billing_since = datetime(2026, 10, 5)
    assert services.billing_start(s, m) == datetime(2026, 10, 5)


def test_transfer_related_sites(client):
    create(client, "shop.com", client_id=1)
    create(client, "a.shop.com", client_id=1)
    create(client, "b.a.shop.com", client_id=1)
    create(client, "other.com", client_id=1)
    ka = new_key(client, "a.shop.com")
    # parent/child sites of the old owner block the transfer ...
    r = client.post("/api/v1/sites/a.shop.com/transfer", json={"to": {"kind": "client", "client_id": 2}})
    assert r.status_code == 422 and "shop.com" in r.json()["detail"] and "include_related" in r.json()["detail"]
    r = client.post("/api/v1/sites/a.shop.com/transfer",
                    json={"to": {"kind": "client", "client_id": 2}, "dry_run": True})
    assert r.status_code == 422
    # ... unless they move together (dry run first)
    r = transfer(client, "a.shop.com", to={"kind": "client", "client_id": 2, "external_id": "9"},
                 include_related=True, dry_run=True)
    assert r["related"] == ["b.a.shop.com", "shop.com"] and r["revoked_keys"] == 1
    r = transfer(client, "a.shop.com", to={"kind": "client", "client_id": 2, "external_id": "9"},
                 include_related=True)
    assert r["related"] == ["b.a.shop.com", "shop.com"]
    owners = {s["domain"]: (s["client_id"], s["external_id"]) for s in client.get("/api/v1/sites").json()}
    assert owners == {"shop.com": (2, None), "a.shop.com": (2, "9"), "b.a.shop.com": (2, None),
                      "other.com": (1, None)}
    assert capi_ok(client, ka) == 401


def test_transfer_blocked_by_foreign_related_site(client):
    create(client, "shop.com", client_id=1)
    with SessionLocal() as db:  # a legacy child of another client (from before the C1 rule)
        db.add(Site(domain="x.shop.com", client_id=5))
        db.commit()
    r = client.post("/api/v1/sites/shop.com/transfer",
                    json={"to": {"kind": "client", "client_id": 2}, "include_related": True})
    assert r.status_code == 422 and "x.shop.com" in r.json()["detail"]
    # ... but moving it to that same other client is fine (the pair gets one owner)
    r = transfer(client, "shop.com", to={"kind": "client", "client_id": 5})
    assert r["related"] == [] and r["to"]["client_id"] == 5


def test_transfer_operator_group(client):
    operator(client, "p.ir")
    operator(client, "cdn.p.ir")
    r = client.post("/api/v1/sites/cdn.p.ir/transfer", json={"to": {"kind": "client", "client_id": 3}})
    assert r.status_code == 422
    r = transfer(client, "cdn.p.ir", to={"kind": "client", "client_id": 3}, include_related=True)
    assert r["related"] == ["p.ir"]
    assert client.get("/api/v1/sites?owner=operator").json() == []


def test_transfer_refusals(client):
    create(client, "r.com", reseller_client_id=4, reseller_label="end")
    r = client.post("/api/v1/sites/r.com/transfer", json={"to": {"kind": "client", "client_id": 2}})
    assert r.status_code == 422 and "نماینده" in r.json()["detail"]
    # a reseller sub-site in the related group refuses as well
    create(client, "shop.com", client_id=4)
    create(client, "sub.shop.com", reseller_client_id=4)
    r = client.post("/api/v1/sites/shop.com/transfer",
                    json={"to": {"kind": "client", "client_id": 2}, "include_related": True})
    assert r.status_code == 422 and "نماینده" in r.json()["detail"] and "sub.shop.com" in r.json()["detail"]
    create(client, "c.com", client_id=1)
    bad = [
        {"to": {"kind": "client", "client_id": 1}},  # same owner
        {"to": {"kind": "client"}},  # no client
        {"to": {"kind": "client", "client_id": 2, "operator_note": "x"}},
        {"to": {"kind": "operator", "client_id": 2}},
        {"to": {"kind": "operator", "external_id": "9"}},
        {"to": {"kind": "reseller", "client_id": 2}},
        {"to": {"kind": "client", "client_id": 0}},
        {"to": {"kind": "client", "client_id": 2}, "bogus": True},
        {},
    ]
    for body in bad:
        assert client.post("/api/v1/sites/c.com/transfer", json=body).status_code == 422, body
    assert client.post("/api/v1/sites/missing.com/transfer",
                       json={"to": {"kind": "operator"}}).status_code == 404
    with SessionLocal() as db:
        assert db.scalar(select(AuditLog).where(AuditLog.action == "site.transfer")) is None
        assert db_site(db, "c.com").client_id == 1


def test_transfer_without_revoke_or_pause(client):
    create(client, "c.com", client_id=1)
    _integrations(client, "c.com", access=False)
    key = new_key(client, "c.com")
    r = transfer(client, "c.com", to={"kind": "client", "client_id": 2}, revoke_credentials=False,
                 pause_integrations=False)
    assert r["revoked_keys"] == 0 and r["paused"] == []
    assert capi_ok(client, key) == 200
    assert client.get("/api/v1/sites/c.com/config/logs").json()["enabled"] is True


def test_legacy_null_owner_site_can_be_transferred(client):
    create(client, "legacy.com")
    r = transfer(client, "legacy.com", to={"kind": "client", "client_id": 3, "external_id": "77"})
    assert r["from"] == {"kind": "client", "client_id": None, "external_id": None}
    assert r["to"] == {"kind": "client", "client_id": 3, "external_id": "77"}


# ================================================================== migration 0021

def test_migration_0021_backfill_and_downgrade(tmp_path):
    eng = create_engine(f"sqlite:///{tmp_path}/m21.db")
    migrate.upgrade(eng, "0020")
    with eng.begin() as c:
        for d, rid, cid in (("plain.com", None, 3), ("res.com", 42, None), ("none.com", None, None)):
            c.execute(text(
                "INSERT INTO sites (domain, status, suspended, over_quota, ns_found, bandwidth_limit_gb, max_records,"
                " ssl_allowed, rate_limit_rps, features, config, blocked_ips, secret, dnssec_enabled, ssl_status,"
                " reseller_client_id, client_id, created_at, updated_at) VALUES (:d, 'active', false, false, '[]',"
                " 0, 100, true, 0, '{}', '{}', '[]', :s, false, 'none', :r, :c, CURRENT_TIMESTAMP,"
                " CURRENT_TIMESTAMP)"), {"d": d, "s": "ab" * 32, "r": rid, "c": cid})
    migrate.upgrade(eng, "0021")
    with eng.connect() as c:
        rows = {r[0]: tuple(r[1:]) for r in c.execute(text(
            "SELECT domain, owner_kind, operator_note, billing_since FROM sites"))}
        assert rows == {"plain.com": ("client", None, None), "res.com": ("reseller", None, None),
                        "none.com": ("client", None, None)}
        ddl = c.execute(text("SELECT sql FROM sqlite_master WHERE name = 'sites'")).scalar()
        assert "AUTOINCREMENT" in ddl.upper()
    # a raw insert without owner_kind (older code paths / tools) gets the server default
    with eng.begin() as c:
        c.execute(text(
            "INSERT INTO sites (domain, status, suspended, over_quota, ns_found, bandwidth_limit_gb, max_records,"
            " ssl_allowed, rate_limit_rps, features, config, blocked_ips, secret, dnssec_enabled, ssl_status,"
            " created_at, updated_at) VALUES ('raw.com', 'active', false, false, '[]', 0, 100, true, 0, '{}',"
            " '{}', '[]', 'x', false, 'none', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"))
        assert c.execute(text("SELECT owner_kind FROM sites WHERE domain = 'raw.com'")).scalar() == "client"
        c.execute(text("DELETE FROM sites WHERE domain = 'raw.com'"))
        c.execute(text("UPDATE sites SET owner_kind = 'operator', operator_note = 'n' WHERE domain = 'none.com'"))
    migrate.downgrade(eng, "0020")
    with eng.connect() as c:
        cols = {r[1] for r in c.execute(text("PRAGMA table_info(sites)"))}
        assert not cols & {"owner_kind", "operator_note", "billing_since"}
        assert c.execute(text("SELECT count(*) FROM sites")).scalar() == 3
        assert "AUTOINCREMENT" in c.execute(text("SELECT sql FROM sqlite_master WHERE name = 'sites'")).scalar().upper()
    migrate.upgrade(eng)
    with eng.connect() as c:
        assert dict(c.execute(text("SELECT domain, owner_kind FROM sites")).all()) == {
            "plain.com": "client", "res.com": "reseller", "none.com": "client"}
    eng.dispose()


def test_api_key_model_unchanged_by_transfer_of_other_site(client):
    """Only the moved site's keys are revoked."""
    create(client, "a.com", client_id=1)
    create(client, "b.com", client_id=1)
    ka, kb = new_key(client, "a.com"), new_key(client, "b.com")
    transfer(client, "a.com", to={"kind": "client", "client_id": 2})
    assert capi_ok(client, ka) == 401 and capi_ok(client, kb) == 200
    with SessionLocal() as db:
        assert db.scalar(select(ApiKey).where(ApiKey.revoked.is_(False))).name == "k"


# ================================================================== credentials rotated on transfer

@pytest.fixture()
def minio(monkeypatch):
    """The fake MinIO of test_storage (same setup as its `minio` fixture)."""
    fake = FakeMinio()
    monkeypatch.setattr(settings, "storage_endpoint", ENDPOINT)
    monkeypatch.setattr(settings, "storage_public_endpoint", ENDPOINT)
    monkeypatch.setattr(settings, "storage_admin_access_key", ADMIN_AK)
    monkeypatch.setattr(settings, "storage_admin_secret_key", ADMIN_SK)
    storage.set_client(MinioClient(ENDPOINT, ADMIN_AK, ADMIN_SK, transport=httpx.MockTransport(fake.handler)))
    yield fake
    storage.set_client(None)


def _image_key(client, domain):
    client.patch(f"/api/v1/sites/{domain}/plan", json={"features": {"image_optimization": True}})
    r = client.post(f"/api/v1/sites/{domain}/image/transform-secret")
    assert r.status_code == 200, r.text
    return r.json()["transform_secret"]


def _secret(domain, key):
    with SessionLocal() as db:
        return site_secrets.get_secret(db_site(db, domain), key)


def test_transfer_rotates_image_key_and_tsig(client, fake_pdns):
    create(client, "example.com", client_id=1, origin_ip="93.184.216.34",
           plan={"features": {"dns_secondary": True}})
    old_img = _image_key(client, "example.com")
    body = {"mode": "off", "allow_axfr": ["93.184.216.53"],
            "tsig": {"name": "xfer.example.com", "algorithm": "hmac-sha512", "secret": TSIG}}
    assert client.put("/api/v1/sites/example.com/config/dns_secondary", json=body).status_code == 200
    assert fake_pdns.tsigkeys["xfer.example.com."]["key"] == TSIG

    dry = transfer(client, "example.com", to={"kind": "client", "client_id": 2}, dry_run=True)
    assert dry["rotated"] == {"image_key": True, "tsig": [{"domain": "example.com", "name": "xfer.example.com"}],
                              "buckets": {"done": [], "pending": []}}
    assert _secret("example.com", "image_transform") == old_img and _secret("example.com", "tsig") == TSIG
    assert fake_pdns.tsigkeys["xfer.example.com."]["key"] == TSIG

    r = transfer(client, "example.com", to={"kind": "client", "client_id": 2})
    assert r["rotated"]["image_key"] is True
    assert r["rotated"]["tsig"] == [{"domain": "example.com", "name": "xfer.example.com", "dns_error": None}]
    new_img, new_tsig = _secret("example.com", "image_transform"), _secret("example.com", "tsig")
    assert new_img and new_img != old_img
    import base64

    assert new_tsig != TSIG and len(base64.b64decode(new_tsig)) == 64  # hmac-sha512 sized key
    # PowerDNS has the new secret (pushed like a normal TSIG change), the section keeps name / algorithm
    assert fake_pdns.tsigkeys["xfer.example.com."]["key"] == new_tsig
    sec = client.get("/api/v1/sites/example.com/config/dns_secondary").json()
    assert sec["tsig"]["name"] == "xfer.example.com" and sec["tsig"]["secret_set"] is True
    # the edges get the new image key on their next poll
    from tests.test_api import add_edge, edge_get

    token = add_edge(client)
    cfg = edge_get(client, token, "/edge/v1/config").json()
    img = next(s for s in cfg["sites"] if s["domain"] == "example.com")["image"]
    assert img["transform_secret"] == new_img
    # no secret in the response or the audit log
    with SessionLocal() as db:
        a = db.scalar(select(AuditLog).where(AuditLog.action == "site.transfer"))
        assert json.loads(a.detail)["rotated"]["image_key"] is True
        for secret in (old_img, new_img, TSIG, new_tsig):
            assert secret not in a.detail and secret not in json.dumps(r)


def test_transfer_tsig_push_failure_marks_dns_dirty(client, fake_pdns):
    create(client, "example.com", client_id=1, plan={"features": {"dns_secondary": True}})
    body = {"mode": "off", "allow_axfr": ["93.184.216.53"], "tsig": {"name": "k.example.com", "secret": TSIG}}
    assert client.put("/api/v1/sites/example.com/config/dns_secondary", json=body).status_code == 200
    fake_pdns.down = True
    r = transfer(client, "example.com", to={"kind": "operator"})
    assert r["rotated"]["tsig"][0]["dns_error"]
    with SessionLocal() as db:
        assert db.scalar(text("SELECT value FROM state WHERE key = 'dns_dirty'")) is not None
    fake_pdns.down = False
    with SessionLocal() as db:
        assert services.sync_all_dns(db) == 0  # the scheduler's re-sync of the dirty zones
    assert fake_pdns.tsigkeys["k.example.com."]["key"] == _secret("example.com", "tsig") != TSIG


def test_transfer_without_revoke_keeps_rotatable_credentials(client, fake_pdns, minio):
    create(client, "example.com", client_id=1, plan={"features": {"storage_gb": 1}})
    old_img = _image_key(client, "example.com")
    b = client.post("/api/v1/sites/example.com/storage/buckets", json={"name": "assets"}).json()
    r = transfer(client, "example.com", to={"kind": "client", "client_id": 2}, revoke_credentials=False)
    assert r["rotated"] == {"image_key": False, "tsig": [], "buckets": {"done": [], "pending": []}}
    assert _secret("example.com", "image_transform") == old_img and b["access_key"] in minio.sas


def test_transfer_rotates_storage_keys(client, minio):
    create(client, "example.com", client_id=1, plan={"features": {"storage_gb": 2}})
    b1 = client.post("/api/v1/sites/example.com/storage/buckets", json={"name": "assets"}).json()
    b2 = client.post("/api/v1/sites/example.com/storage/buckets", json={"name": "media"}).json()
    dry = transfer(client, "example.com", to={"kind": "operator"}, dry_run=True)
    assert dry["rotated"]["buckets"] == {"done": [], "pending": [b1["bucket"], b2["bucket"]]}
    with SessionLocal() as db:
        assert all(x.credentials_rotation_pending_at is None for x in db.scalars(select(StorageBucket)))
    assert set(minio.sas) == {b1["access_key"], b2["access_key"]}

    r = transfer(client, "example.com", to={"kind": "operator"})
    assert r["rotated"]["buckets"] == {"done": [b1["bucket"], b2["bucket"]], "pending": []}
    # the previous owner's keys are gone on MinIO; the buckets (and their data) stay with the site
    assert b1["access_key"] not in minio.sas and b2["access_key"] not in minio.sas and len(minio.sas) == 2
    with SessionLocal() as db:
        rows = list(db.scalars(select(StorageBucket).order_by(StorageBucket.id)))
        assert [x.bucket for x in rows] == [b1["bucket"], b2["bucket"]]
        assert all(x.credentials_rotation_pending_at is None and x.access_key in minio.sas for x in rows)
    assert client.get("/healthz/deep").json()["storage_rotation_pending"] == 0


def test_storage_rotation_failure_is_pending_then_retried(client, minio, monkeypatch):
    from app import routes_ops

    create(client, "example.com", client_id=1, plan={"features": {"storage_gb": 1}})
    b = client.post("/api/v1/sites/example.com/storage/buckets", json={"name": "assets"}).json()
    minio.fail["PUT /minio/admin/v3/add-service-account"] = 500
    r = transfer(client, "example.com", to={"kind": "client", "client_id": 2})
    # the DB transfer is committed regardless; the key rotation is pending
    assert r["rotated"]["buckets"] == {"done": [], "pending": [b["bucket"]]}
    assert client.get("/api/v1/sites/example.com").json()["client_id"] == 2
    assert list(minio.sas) == [b["access_key"]]  # nothing changed on MinIO
    with SessionLocal() as db:
        assert db.scalar(select(StorageBucket)).credentials_rotation_pending_at is not None
    routes_ops._cache["body"] = None
    deep = client.get("/healthz/deep").json()
    assert deep["storage_rotation_pending"] == 1
    assert any("storage bucket key" in w for w in deep["warnings"])

    # the scheduler retries: still failing (now the old key's removal) -> still pending, old key kept
    minio.fail.clear()
    minio.fail_once["DELETE /minio/admin/v3/delete-service-account"] = 500
    with SessionLocal() as db:
        assert scheduler.job_storage_rotation(db) == {"done": [], "pending": [b["bucket"]]}
        assert db.scalar(select(StorageBucket)).access_key == b["access_key"]
    assert list(minio.sas) == [b["access_key"]]  # the half-made new key was removed again
    # MinIO healthy again -> rotated, mark cleared, warning gone, job idle
    minio.fail.clear()
    with SessionLocal() as db:
        assert scheduler.job_storage_rotation(db) == {"done": [b["bucket"]], "pending": []}
        row = db.scalar(select(StorageBucket))
        assert row.credentials_rotation_pending_at is None and row.access_key != b["access_key"]
        assert scheduler.job_storage_rotation(db) is None
    assert b["access_key"] not in minio.sas and len(minio.sas) == 1
    routes_ops._cache["body"] = None
    deep = client.get("/healthz/deep").json()
    assert deep["storage_rotation_pending"] == 0
    assert not any("storage bucket key" in w for w in deep["warnings"])


def test_storage_rotation_pending_when_storage_unconfigured(client, minio, monkeypatch):
    create(client, "example.com", client_id=1, plan={"features": {"storage_gb": 1}})
    b = client.post("/api/v1/sites/example.com/storage/buckets", json={"name": "assets"}).json()
    minio.down = True
    r = transfer(client, "example.com", to={"kind": "client", "client_id": 2})
    assert r["rotated"]["buckets"]["pending"] == [b["bucket"]]
    minio.down = False
    with SessionLocal() as db:
        assert scheduler.job_storage_rotation(db)["done"] == [b["bucket"]]
