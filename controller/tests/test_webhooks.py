"""Webhooks (SPEC §14.3.3): section CRUD with controller ids + write-only secrets, rotate/test,
signed deliveries to a local receiver, backoff, no redirects, SSRF guard, every event source."""

import hashlib
import hmac
import json
import re
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select, text

from app import crypto, netguard, routes_platform, scheduler, site_secrets, ssl, webhooks
from app.config import settings
from app.db import SessionLocal, engine
from app.models import AuditLog, Site, UsageHourly, WebhookDelivery, utcnow
from tests.platform_helpers import LOCAL_HOST, S, auth, edge_token, make_site
from tests.test_api import edge_get

ALL_EVENTS = ["purge.completed", "ssl.issued", "ssl.failed", "quota.warning", "quota.exceeded",
              "site.suspended", "site.unsuspended", "attack.detected"]


@pytest.fixture(autouse=True)
def _isolate(fake_dns):
    """No real DNS in this module; a clean rate-limit window per test."""
    routes_platform._test_hits.clear()
    yield
    routes_platform._test_hits.clear()


def put_hooks(client, items, path=S):
    return client.put(f"{path}/config/webhooks", json={"items": items})


def hook(url, events=("purge.completed",), **kw):
    return {"url": url, "events": list(events), **kw}


def run_job(now=None):
    with SessionLocal() as db:
        return scheduler.job_webhooks(db, now=now, wait=True)


def rows(**where):
    with SessionLocal() as db:
        q = select(WebhookDelivery).order_by(WebhookDelivery.id)
        for k, v in where.items():
            q = q.where(getattr(WebhookDelivery, k) == v)
        return list(db.scalars(q))


# ------------------------------------------------------------------ section CRUD + secrets

def test_crud_assigns_ids_and_shows_new_secrets_once(client, monkeypatch):
    monkeypatch.setattr(settings, "data_encryption_key", crypto.generate_key())
    make_site(client)
    r = put_hooks(client, [hook("https://hooks.public.example/a", description=" main "),
                           hook("https://hooks.public.example/b", ["ssl.issued", "ssl.issued"], id="custom")])
    assert r.status_code == 200, r.text
    body = r.json()
    items, new = body["items"], body["new_secrets"]
    assert [i["description"] for i in items] == ["main", ""]
    assert items[1]["events"] == ["ssl.issued"]  # de-duplicated
    ids = [i["id"] for i in items]
    assert all(re.fullmatch(r"wh_[0-9a-f]{8}", i) for i in ids) and len(set(ids)) == 2
    assert set(new) == set(ids) and all(re.fullmatch(r"whsec_[0-9a-f]{40}", s) for s in new.values())
    assert all(i["secret_set"] is True for i in items)

    # GET / site / edge config / audit never show a secret
    got = client.get(f"{S}/config/webhooks")
    assert got.json() == {"items": items} and "new_secrets" not in got.json()
    token = edge_token(client)
    blobs = [got.text, client.get(S).text, edge_get(client, token, "/edge/v1/config").text,
             json.dumps([a.detail for a in SessionLocal().scalars(select(AuditLog))])]
    for secret in new.values():
        assert all(secret not in b for b in blobs)
    assert "webhooks" not in edge_get(client, token, "/edge/v1/config").json()["sites"][0]
    # encrypted at rest
    with engine.connect() as c:
        raw = c.execute(text("SELECT integration_secrets FROM sites")).scalar()
    assert "enc:v1:" in raw and not any(s in raw for s in new.values())

    # keep one (edited), drop one, add one, and an unknown id is treated as new
    r = put_hooks(client, [dict(items[0], description="edited", secret_set=False),
                           hook("https://hooks.public.example/c", id="wh_deadbeef")])
    assert r.status_code == 200, r.text
    items2, new2 = r.json()["items"], r.json()["new_secrets"]
    assert items2[0]["id"] == ids[0] and items2[0]["description"] == "edited"
    assert items2[1]["id"] not in (ids[1], "wh_deadbeef") and list(new2) == [items2[1]["id"]]
    with SessionLocal() as db:
        site = db.scalar(select(Site))
        assert site_secrets.webhook_secret_ids(site) == {items2[0]["id"], items2[1]["id"]}
        assert site_secrets.webhook_secret(site, ids[0]) == new[ids[0]]  # unchanged
    # a PUT that creates nothing still answers new_secrets: {}
    assert put_hooks(client, items2).json()["new_secrets"] == {}
    # duplicate ids
    assert put_hooks(client, [items2[0], items2[0]]).status_code == 422


def test_validation_and_plan_limit(client):
    make_site(client, max_webhooks=1)
    ok = "https://hooks.public.example/x"
    assert put_hooks(client, [hook(ok, [])]).status_code == 422
    assert put_hooks(client, [hook(ok, ["nope"])]).status_code == 422
    assert put_hooks(client, [hook(ok, ["ping"])]).status_code == 422  # ping is only sent by /test
    assert put_hooks(client, [hook(ok, description="x" * 101)]).status_code == 422
    assert put_hooks(client, [hook("https://hooks.public.example/" + "a" * 520)]).status_code == 422
    assert put_hooks(client, [hook("not a url")]).status_code == 422
    r = put_hooks(client, [hook("http://hooks.public.example/x")])
    assert r.status_code == 422 and "https" in r.text
    assert put_hooks(client, [{"url": ok, "events": ["ssl.issued"], "extra": 1}]).status_code == 422
    assert put_hooks(client, [hook(ok), hook(ok)]).status_code == 403  # plan: max_webhooks 1
    assert put_hooks(client, [hook(ok)]).status_code == 200
    assert client.patch(f"{S}/plan", json={"features": {"max_webhooks": 0}}).status_code == 200
    assert put_hooks(client, [hook(ok)]).status_code == 403
    assert put_hooks(client, []).status_code == 200
    assert client.patch(f"{S}/plan", json={"features": {"max_webhooks": 51}}).status_code == 422


@pytest.mark.parametrize("url", [
    "https://private.example/h", "https://loop.example/h", "https://metadata.example/h",
    "https://cgnat.example/h", "https://multicast.example/h", "https://mixed.example/h",
    "https://ula.example/h", "https://mapped.example/h", "https://sixtofour.example/h",
    "https://unknown.example/h", "https://10.0.0.1/h", "https://127.0.0.1:8443/h", "https://[::1]/h",
    "https://[::ffff:10.0.0.1]/h", "https://[fe80::1]/h", "https://169.254.169.254/latest",
    "https://user:pw@hooks.public.example/h", "ftp://hooks.public.example/h", "https://localhost/h",
])
def test_ssrf_refused_at_save(client, url):
    make_site(client)
    r = put_hooks(client, [hook(url)])
    assert r.status_code == 422, (url, r.text)


def test_public_targets_accepted_at_save(client):
    make_site(client)
    for url in ("https://hooks.public.example/h", "https://v6.public.example:8443/h", "https://93.184.216.34/h",
                "https://[2606:4700::1111]/h"):
        assert put_hooks(client, [hook(url)]).status_code == 200, url


@pytest.mark.parametrize("ip,public", [
    ("93.184.216.34", True), ("2606:4700::1111", True), ("::ffff:93.184.216.34", True),
    ("10.0.0.1", False), ("172.16.0.1", False), ("192.168.0.1", False), ("127.0.0.1", False),
    ("169.254.169.254", False), ("100.64.0.1", False), ("0.0.0.0", False), ("224.0.0.1", False),
    ("240.0.0.1", False), ("255.255.255.255", False), ("192.0.2.1", False), ("198.18.0.1", False),
    ("::1", False), ("::", False), ("fe80::1", False), ("fd12::1", False), ("fec0::1", False),
    ("ff02::1", False), ("::ffff:127.0.0.1", False), ("::ffff:10.1.1.1", False), ("2002:7f00:1::", False),
    ("2002:a00:1::", False), ("64:ff9b::7f00:1", False), ("2001:db8::1", False), ("fe80::1%eth0", False),
    ("not-an-ip", False),
])
def test_is_public_ip(ip, public):
    assert netguard.is_public_ip(ip) is public


# ------------------------------------------------------------------ delivery

def _verify(req, secret):
    ts = req["headers"]["x-pcdn-timestamp"]
    expected = "sha256=" + hmac.new(secret.encode(), ts.encode() + b"." + req["body"], hashlib.sha256).hexdigest()
    return hmac.compare_digest(req["headers"]["x-pcdn-signature"], expected)


def test_signed_delivery_to_local_receiver(client, receiver, local_vet):
    make_site(client)
    r = put_hooks(client, [hook(receiver.url(), ["purge.completed"])])
    hid, secret = r.json()["items"][0]["id"], next(iter(r.json()["new_secrets"].values()))
    assert client.post(f"{S}/purge", json={"urls": ["https://example.com/a.css"]}).status_code == 200
    queued = client.get(f"{S}/webhooks/deliveries").json()
    assert len(queued) == 1 and queued[0]["status"] == "pending" and queued[0]["attempts"] == 0
    assert receiver.requests == []  # nothing is sent in the request path

    run_job()
    assert len(receiver.requests) == 1
    req = receiver.requests[0]
    h = req["headers"]
    assert req["method"] == "POST" and req["path"] == "/hook"
    assert h["content-type"] == "application/json" and h["user-agent"] == "PasargadCDN-Webhooks/1"
    assert h["x-pcdn-event"] == "purge.completed" and h["x-pcdn-delivery"] == queued[0]["id"]
    assert re.fullmatch(r"dlv_[0-9a-f]{16}", h["x-pcdn-delivery"])
    assert abs(int(h["x-pcdn-timestamp"]) - datetime.now(timezone.utc).timestamp()) < 60
    assert _verify(req, secret)
    # connected to the vetted address, Host header kept (DNS-rebinding defence)
    assert h["host"] == f"{LOCAL_HOST}:{receiver.port}"
    body = json.loads(req["body"])
    assert re.fullmatch(r"evt_[0-9a-f]{16}", body["id"]) and body["type"] == "purge.completed"
    assert body["site"] == "example.com" and body["created_at"].endswith("Z")
    assert body["data"]["urls"] == ["https://example.com/a.css"] and body["data"]["everything"] is False
    assert isinstance(body["data"]["purge_id"], int)

    d = client.get(f"{S}/webhooks/deliveries").json()[0]
    assert d["status"] == "ok" and d["attempts"] == 1 and d["last_code"] == 200 and d["hook_id"] == hid
    assert d["delivered_at"] and d["next_attempt_at"] is None and d["last_error"] is None
    run_job()
    assert len(receiver.requests) == 1  # delivered once


def test_backoff_schedule_then_failed_after_24h(client, receiver, local_vet):
    make_site(client)
    put_hooks(client, [hook(receiver.url(), ["site.suspended"])])
    receiver.status = 500
    client.post(f"{S}/suspend")
    (d,) = rows()
    t0 = d.created_at
    gaps = []
    now = t0
    while True:
        claimed = run_job(now)
        assert claimed, now
        (d,) = rows()
        if d.status != "pending":
            break
        assert d.last_code == 500 and d.last_error == "HTTP 500"
        gaps.append(int((d.next_attempt_at - now).total_seconds()))
        assert run_job(d.next_attempt_at - timedelta(seconds=1)) == []  # not due yet
        now = d.next_attempt_at
    assert gaps == [60, 300, 1800, 7200, 21600, 21600, 21600]
    assert d.status == "failed" and d.attempts == 8 and d.next_attempt_at is None
    assert len(receiver.requests) == 8
    # every attempt resends the same body, freshly signed
    assert len({r["body"] for r in receiver.requests}) == 1


def test_recovery_after_failures(client, receiver, local_vet):
    make_site(client)
    put_hooks(client, [hook(receiver.url(), ["site.suspended"])])
    receiver.status = 503
    client.post(f"{S}/suspend")
    run_job()
    (d,) = rows()
    receiver.status = 204
    run_job(d.next_attempt_at)
    (d,) = rows()
    assert d.status == "ok" and d.attempts == 2 and d.last_code == 204 and d.last_error is None


def test_redirects_are_not_followed(client, receiver, local_vet):
    make_site(client)
    put_hooks(client, [hook(receiver.url(), ["site.suspended"])])
    receiver.status, receiver.location = 302, receiver.url("/elsewhere")
    client.post(f"{S}/suspend")
    run_job()
    assert [r["path"] for r in receiver.requests] == ["/hook"]
    (d,) = rows()
    assert d.status == "pending" and d.last_code == 302 and "ریدایرکت" in d.last_error


def test_large_response_is_read_at_most_4kb(client, receiver, local_vet):
    make_site(client)
    put_hooks(client, [hook(receiver.url(), ["site.suspended"])])
    receiver.body = b"x" * 2_000_000
    client.post(f"{S}/suspend")
    run_job()
    (d,) = rows()
    assert d.status == "ok" and d.last_code == 200


def test_ssrf_checked_again_at_delivery(client, receiver, fake_dns):
    """Saved while public; the name now resolves to loopback (rebinding): the attempt fails
    without any connection."""
    make_site(client)
    assert put_hooks(client, [hook("https://hooks.public.example/h", ["site.suspended"])]).status_code == 200
    fake_dns["hooks.public.example"] = ["127.0.0.1"]
    client.post(f"{S}/suspend")
    run_job()
    (d,) = rows()
    assert d.status == "pending" and d.attempts == 1 and d.last_code is None
    assert "غیرعمومی" in d.last_error


def test_pinned_transport_connects_to_vetted_address_only(receiver):
    import httpx

    target = netguard.Target(url="", scheme="http", host="pinned.example", port=receiver.port, ips=["127.0.0.1"])
    with httpx.Client(transport=netguard.PinnedTransport(target)) as c:
        assert c.get(f"http://pinned.example:{receiver.port}/x").status_code == 200
        with pytest.raises(httpx.ConnectError):
            c.get(f"http://other.example:{receiver.port}/x")  # never a host that was not vetted
    assert receiver.requests[0]["headers"]["host"] == f"pinned.example:{receiver.port}"


def test_a_worker_with_a_stale_lease_does_not_send(client, receiver, local_vet):
    """A row whose lease expired and was claimed again is only attempted by the new claim."""
    make_site(client)
    put_hooks(client, [hook(receiver.url(), ["site.suspended"])])
    client.post(f"{S}/suspend")
    (d,) = rows()
    webhooks._attempt(d.id, d.next_attempt_at + timedelta(seconds=1))
    assert receiver.requests == [] and rows()[0].attempts == 0
    webhooks._attempt(d.id, d.next_attempt_at)
    assert len(receiver.requests) == 1 and rows()[0].status == "ok"


def test_disabled_or_removed_hook_fails_pending_delivery(client, receiver, local_vet):
    make_site(client)
    r = put_hooks(client, [hook(receiver.url(), ["site.suspended"])])
    item = r.json()["items"][0]
    client.post(f"{S}/suspend")
    put_hooks(client, [dict(item, enabled=False)])
    run_job()
    (d,) = rows()
    assert d.status == "failed" and "غیرفعال" in d.last_error and receiver.requests == []
    # a disabled hook gets no new events at all
    client.post(f"{S}/unsuspend")
    assert len(rows()) == 1


# ------------------------------------------------------------------ rotate / test / deliveries

def test_rotate_and_test_endpoints(client, receiver, local_vet, monkeypatch):
    make_site(client)
    r = put_hooks(client, [hook(receiver.url(), ["ssl.issued"])])
    hid, old = r.json()["items"][0]["id"], next(iter(r.json()["new_secrets"].values()))
    assert client.post(f"{S}/webhooks/wh_00000000/rotate").status_code == 404
    rot = client.post(f"{S}/webhooks/{hid}/rotate")
    assert rot.status_code == 200
    new = rot.json()["secret"]
    assert rot.json()["id"] == hid and re.fullmatch(r"whsec_[0-9a-f]{40}", new) and new != old
    assert client.get(f"{S}/config/webhooks").json()["items"][0]["secret_set"] is True

    t = client.post(f"{S}/webhooks/{hid}/test")
    assert t.status_code == 200 and t.json() == {"ok": True, "status_code": 200, "error": None}
    req = receiver.requests[-1]
    assert req["headers"]["x-pcdn-event"] == "ping" and _verify(req, new) and not _verify(req, old)
    assert json.loads(req["body"])["data"] == {"hook_id": hid}
    receiver.status = 500
    t = client.post(f"{S}/webhooks/{hid}/test").json()
    assert t["ok"] is False and t["status_code"] == 500 and t["error"] == "HTTP 500"
    d = client.get(f"{S}/webhooks/deliveries").json()
    assert [(x["event"], x["status"]) for x in d] == [("ping", "failed"), ("ping", "ok")]  # newest first
    assert client.post(f"{S}/webhooks/wh_00000000/test").status_code == 404

    audit = client.get("/api/v1/audit").json()
    assert {"webhook.rotate", "webhook.test"} <= {a["action"] for a in audit}
    assert all(new not in json.dumps(a) and old not in json.dumps(a) for a in audit)
    assert any(a["action"] == "webhook.test" and a["detail"] == {"hook_id": hid, "ok": False} for a in audit)

    # rate-limited like config writes (CAPI_CONFIG_RATE per minute and site)
    monkeypatch.setattr(settings, "capi_config_rate", 3)
    routes_platform._test_hits.clear()
    codes = [client.post(f"{S}/webhooks/{hid}/test").status_code for _ in range(4)]
    assert codes == [200, 200, 200, 429]


def test_deliveries_limit_and_seven_day_retention(client):
    make_site(client)
    put_hooks(client, [hook("https://hooks.public.example/h", ["site.suspended"])])
    with SessionLocal() as db:
        site = db.scalar(select(Site))
        for i in range(5):
            webhooks.emit(db, site, "site.suspended", {"n": i})
        webhooks.emit(db, site, "site.suspended", {"old": True}, now=utcnow() - timedelta(days=8))
        db.commit()
    assert len(client.get(f"{S}/webhooks/deliveries").json()) == 5  # last 7 days only
    assert len(client.get(f"{S}/webhooks/deliveries?limit=2").json()) == 2
    assert len(client.get(f"{S}/webhooks/deliveries?limit=100000").json()) == 5
    assert len(rows()) == 6
    with SessionLocal() as db:
        scheduler.job_cleanup(db)
    assert len(rows()) == 5


# ------------------------------------------------------------------ event sources

def test_every_event_source_emits(client, monkeypatch):
    make_site(client)
    client.patch(f"{S}/plan", json={"bandwidth_limit_gb": 1})
    put_hooks(client, [hook("https://hooks.public.example/all", ALL_EVENTS),
                       hook("https://hooks.public.example/other", ["ssl.failed"]),
                       hook("https://hooks.public.example/off", ALL_EVENTS, enabled=False)])

    def events():
        return [d.event for d in rows()]

    # purge
    client.post(f"{S}/purge", json={"everything": True})
    assert events() == ["purge.completed"]

    # certificate issued / failed (scheduler job_ssl)
    with SessionLocal() as db:
        site = db.scalar(select(Site))
        site.ns_verified_at, site.ssl_status = utcnow(), "pending"
        db.commit()

    def fake_issue(site):
        site.ssl_cert, site.ssl_key = "CERT", "KEY"
        site.ssl_expires_at = utcnow() + timedelta(days=90)
        site.ssl_status, site.ssl_error, site.ssl_source = "active", None, "letsencrypt"

    monkeypatch.setattr(ssl, "issue", fake_issue)
    with SessionLocal() as db:
        scheduler.job_ssl(db)
    assert events()[-1] == "ssl.issued"
    issued = json.loads(rows(event="ssl.issued")[0].payload)["data"]
    assert issued["renewal"] is False and issued["names"] == ["example.com", "*.example.com"]
    assert "CERT" not in json.dumps(issued) and "KEY" not in json.dumps(issued)

    with SessionLocal() as db:
        site = db.scalar(select(Site))
        site.ssl_status, site.ssl_expires_at = "active", utcnow() + timedelta(days=3)
        db.commit()

    def failing(site):
        raise RuntimeError("acme: DNS problem")

    monkeypatch.setattr(ssl, "issue", failing)
    with SessionLocal() as db:
        scheduler.job_ssl(db)
    failed = rows(event="ssl.failed")
    assert len(failed) == 2  # both subscribed hooks, one event id
    assert len({d.event_id for d in failed}) == 1 and {d.hook_id for d in failed} == {
        i["id"] for i in client.get(f"{S}/config/webhooks").json()["items"][:2]}
    assert json.loads(failed[0].payload)["data"] == {"renewal": True, "error": "acme: DNS problem"}

    # quota: warning at 80 %, exceeded at 100 % (scheduler job_quota), each once
    from app.services import month_start

    hours = iter(range(100))

    def add_usage(gb):
        with SessionLocal() as db:
            site = db.scalar(select(Site))
            db.add(UsageHourly(site_id=site.id, edge_id=_edge_id(client),
                               hour=month_start() + timedelta(hours=next(hours)),
                               bytes=int(gb * 1024**3), requests=1, cache_hits=0, details="{}"))
            db.commit()
        with SessionLocal() as db:
            scheduler.job_quota(db)

    add_usage(0.5)
    assert "quota.warning" not in events()
    add_usage(0.35)
    add_usage(0.01)
    assert events().count("quota.warning") == 1
    warning = json.loads(rows(event="quota.warning")[0].payload)["data"]
    assert warning["limit_bytes"] == 1024**3 and 85 <= warning["percent"] < 100
    add_usage(0.2)
    add_usage(0.2)
    assert events().count("quota.exceeded") == 1 and events().count("quota.warning") == 1

    # admin suspend / unsuspend, on transitions only
    client.post(f"{S}/suspend")
    client.post(f"{S}/suspend")
    client.post(f"{S}/unsuspend")
    client.post(f"{S}/unsuspend")
    assert events().count("site.suspended") == 1 and events().count("site.unsuspended") == 1

    # attack.detected: security events above ATTACK_EVENTS_PER_5M, at most once per hour
    monkeypatch.setattr(settings, "attack_events_per_5m", 50)
    token = edge_token(client, name="att-1", ip="5.160.1.20")
    hour = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0).isoformat()

    def attack(n, batch=None):
        body = {"items": [{"host": "example.com", "hour": hour, "bytes": 1, "requests": n,
                           "security": {"waf": n - 2, "ratelimit": 1, "bots": 1}}]}
        if batch:
            body["batch_id"] = batch
        assert client.post("/edge/v1/usage", json=body, headers=auth(token)).status_code == 200

    attack(30)
    assert "attack.detected" not in events()
    attack(30, "a" * 32)
    attack(30, "a" * 32)  # replay: deduplicated, not counted again
    assert events().count("attack.detected") == 1
    data = json.loads(rows(event="attack.detected")[0].payload)["data"]
    # every security source counts, bot management (`bots`) included
    assert data["events_5m"] == 60 and data["threshold"] == 50
    assert data["by_source"] == {"waf": 56, "ratelimit": 2, "bots": 2}
    attack(500)
    assert events().count("attack.detected") == 1  # once per hour

    # the disabled hook never got anything, the ssl.failed-only hook only ssl.failed
    seen = set(events())
    assert seen == set(ALL_EVENTS)
    hooks = client.get(f"{S}/config/webhooks").json()["items"]
    assert {d.event for d in rows(hook_id=hooks[1]["id"])} == {"ssl.failed"}
    assert rows(hook_id=hooks[2]["id"]) == []


def _edge_id(client):
    from app.models import Edge

    with SessionLocal() as db:
        e = db.scalar(select(Edge).order_by(Edge.id))
        if e is None:
            edge_token(client, name="usage-1", ip="5.160.1.30")
            e = db.scalar(select(Edge).order_by(Edge.id))
        return e.id


def test_emit_never_breaks_the_triggering_request(client, monkeypatch):
    make_site(client)
    put_hooks(client, [hook("https://hooks.public.example/h", ALL_EVENTS)])

    def boom(*a, **kw):
        raise RuntimeError("broken")

    monkeypatch.setattr(webhooks, "active_hooks", boom)
    assert client.post(f"{S}/purge", json={"everything": True}).status_code == 200
    assert client.post(f"{S}/suspend").status_code == 200
    assert rows() == []


def test_no_hooks_no_rows(client):
    make_site(client)
    client.post(f"{S}/purge", json={"everything": True})
    client.post(f"{S}/suspend")
    assert rows() == []


def test_capi_config_returns_new_secrets_and_hides_them(client):
    make_site(client)
    key = client.post(f"{S}/apikeys", json={"name": "k", "scopes": ["dns"]}).json()["key"]
    r = client.put("/capi/v1/config/webhooks", json={"items": [hook("https://hooks.public.example/c")]},
                   headers=auth(key))
    assert r.status_code == 200, r.text
    (hid, secret), = r.json()["new_secrets"].items()
    got = client.get("/capi/v1/config/webhooks", headers=auth(key))
    assert got.json()["items"][0]["id"] == hid and secret not in got.text
