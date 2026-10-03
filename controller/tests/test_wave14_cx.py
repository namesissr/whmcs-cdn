"""Wave 14 (SPEC §23), customer experience: config history (§23.4), alert channels (§23.5), Arvan /
Cloudflare import (§23.6), RUM (§23.7), diagnostics (§23.8), abuse desk (§23.10) and that no customer
answer ever carries an internal node name (§23.12)."""

import hashlib
import json
import logging
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from cryptography.fernet import Fernet
from sqlalchemy import select

from app import (abuse, config_history, diagnostics, importer, importers, notify, notify_providers, routes_capi, rum,
                 scheduler)
from app.config import settings
from app.db import SessionLocal
from app.importers import arvan, cloudflare
from app.models import (AbuseReport, AnalyticsMinute, AuditLog, ImportSession, NotificationLinkCode,
                        NotificationOutbox, NotificationSubscription, NotificationTarget, Site, SiteConfigVersion,
                        State, utcnow)

A = "/api/v1"
S = "/api/v1/sites/example.com"


def auth(tok):
    return {"Authorization": f"Bearer {tok}"}


@pytest.fixture(autouse=True)
def _reset():
    routes_capi._hits.clear()
    routes_capi._config_hits.clear()
    importer._previews.clear()
    importer._memory.clear()
    diagnostics._hits.clear()
    yield
    notify_providers.transport = None
    importers.transport = None


def mk_site(client, domain="example.com", client_id=7, **features):
    r = client.post(f"{A}/sites", json={"domain": domain, "origin_ip": "93.184.216.34", "client_id": client_id,
                                        "plan": {"features": features}})
    assert r.status_code == 201, r.text
    return r.json()


def capi_key(client, scopes=("stats", "config", "dns"), domain="example.com"):
    r = client.post(f"{A}/sites/{domain}/apikeys", json={"name": "ci", "scopes": list(scopes)})
    return r.json()["key"]


# ================================================================== §23.4 config history

def test_capture_actor_mapping_noop_and_diff(client):
    mk_site(client)
    cache = client.get(f"{S}/config/cache").json()
    r = client.put(f"{S}/config/cache", json={**cache, "edge_ttl": 7200}, headers={"X-PCDN-Actor": "client:7"})
    assert r.status_code == 200
    client.put(f"{S}/config/cache", json={**cache, "edge_ttl": 7200})  # no-op: no version
    client.put(f"{S}/config/cache", json={**cache, "edge_ttl": 600}, headers={"X-PCDN-Actor": "share:9:edit"})
    client.put(f"{S}/config/ddos", json={"mode": "js", "threshold_rps": 200, "clearance_ttl": 3600})
    h = client.get(f"{S}/config/history").json()
    vs = h["versions"]
    assert h["current"] == vs[0]["version"] and h["retention"] == {"max_versions": 100, "days": 90}
    assert [v["actor"]["kind"] for v in vs[:3]] == ["support", "collaborator", "client"]
    assert vs[1]["actor"]["id"] == "9" and vs[2]["actor"]["id"] == "7"
    assert vs[0]["sections"] == ["ddos"] and vs[0]["source"] == "admin" and vs[2]["source"] == "api"
    first = vs[2]["version"]
    d = client.get(f"{S}/config/history/{first}/diff?against=current&section=cache").json()
    assert d["sections"]["cache"] == [{"op": "replace", "path": "/edge_ttl", "old": 7200, "new": 600}]
    assert client.get(f"{S}/config/history/999/diff").status_code == 404
    assert client.get(f"{S}/config/history?limit=0").status_code == 422
    view = client.get(f"{S}/config/history/{first}").json()
    assert view["config"]["cache"]["edge_ttl"] == 7200


def test_capture_from_legacy_settings_l4_transfer_and_scheduler(client, monkeypatch):
    mk_site(client)
    client.patch(f"{S}/settings", json={"dev_mode": True})
    with SessionLocal() as db:
        from app.services import lock_site
        from app import sections

        token = config_history.set_actor(kind="system", actor="job:job_waf_learning", source="waf_learning")
        try:
            site = lock_site(db, db.scalar(select(Site)))
            sections.store_section(site, "bots", {**sections.get_section(site, "bots"), "mode": "log"})
            db.commit()
        finally:
            config_history.ACTOR.reset(token)
    vs = client.get(f"{S}/config/history").json()["versions"]
    assert vs[0]["source"] == "waf_learning" and vs[0]["actor"] == {"kind": "system", "label": "waf_learning",
                                                                    "id": None}
    assert vs[1]["sections"] == ["cache"]


def test_redaction_keys_headers_access_key_and_functions(client):
    a = {"request": [{"name": "Authorization", "value": "Bearer topsecret"}, {"name": "X-A", "value": "1"}],
         "response": []}
    b = {"request": [{"name": "Authorization", "value": "Bearer other"}, {"name": "X-A", "value": "2"}],
         "response": []}
    ops = config_history.section_diff("headers", a, b)
    assert {"op": "replace", "path": "/request/0/value", "old": "[redacted]", "new": "[redacted]",
            "redacted": True} in ops
    assert {"op": "replace", "path": "/request/1/value", "old": "1", "new": "2"} in ops
    assert "topsecret" not in json.dumps(ops)
    red = config_history.redact_value("logs", {"access_key": "AKIA12345", "secret_key": "s", "enabled": True})
    assert red["access_key"] == "AKIA…" and red["secret_key"] == "[redacted]"
    f1 = {"items": [{"id": "f1", "code": "a()", "route": "/x"}]}
    f2 = {"items": [{"id": "f1", "code": "b()", "route": "/x"}]}
    ops = config_history.section_diff("functions", f1, f2)
    assert ops and all("a()" not in json.dumps(o) and "b()" not in json.dumps(o) for o in ops)
    assert any(o["path"].endswith("/code_sha256") for o in ops)
    # list items with an id are matched by id
    ops = config_history.diff({"rules": [{"id": "r1", "action": "block"}, {"id": "r2", "action": "allow"}]},
                              {"rules": [{"id": "r2", "action": "allow"}, {"id": "r1", "action": "challenge"}]})
    assert ops == [{"op": "replace", "path": "/rules/[id=r1]/action", "old": "block", "new": "challenge"}]


def test_functions_size_cap(client):
    big = {"enabled": True, "items": [{"id": "f1", "code": "x" * (1024 * 1024 + 10)}]}
    text = config_history._storage_form("functions", big)
    assert json.loads(text)["_omitted"] is True and json.loads(text)["ids"] == ["f1"]


def test_retention_count_age_reattach_and_newest_kept(client, monkeypatch):
    mk_site(client)
    cache = client.get(f"{S}/config/cache").json()
    client.put(f"{S}/config/ddos", json={"mode": "js", "threshold_rps": 200, "clearance_ttl": 3600})
    for ttl in range(600, 600 + 12 * 60, 60):
        client.put(f"{S}/config/cache", json={**cache, "edge_ttl": ttl})
    monkeypatch.setattr(settings, "config_history_max_versions", 10)
    with SessionLocal() as db:
        site = db.scalar(select(Site))
        before = config_history.config_at(db, site.id, None)
        removed = config_history.prune(db)
        db.commit()
        assert removed > 0
        versions = list(db.scalars(select(SiteConfigVersion).order_by(SiteConfigVersion.version)))
        assert len(versions) == 10
        oldest = versions[0].version
        # the ddos value of a removed version was re-attached to the oldest retained version
        assert config_history.config_at(db, site.id, oldest)["ddos"]["mode"] == "js"
        assert config_history.config_at(db, site.id, None) == before
        # age: everything older than CONFIG_HISTORY_DAYS goes, the newest stays
        for v in versions:
            v.at = utcnow() - timedelta(days=200)
        db.commit()
        config_history.prune(db)
        db.commit()
        assert db.query(SiteConfigVersion).count() == 1


def test_restore_plan_gate_limit_invalid_logs_and_webhook_secret(client, fake_dns, monkeypatch):
    mk_site(client, max_firewall_rules=5, ddos=True)
    rules = [{"id": f"r{i}", "action": "block", "conditions": [{"field": "path", "op": "eq", "value": f"/{i}"}]}
             for i in range(4)]
    client.put(f"{S}/config/firewall", json={"default_action": "allow", "rules": rules})
    client.put(f"{S}/config/ddos", json={"mode": "js", "threshold_rps": 200, "clearance_ttl": 3600})
    hooks = client.put(f"{S}/config/webhooks", json={"items": [{"url": "https://hooks.public.example/x",
                                                                "events": ["ssl.issued"]}]}).json()
    hook_id = hooks["items"][0]["id"]
    v = client.get(f"{S}/config/history").json()["current"]
    # change everything, then shrink the plan
    client.put(f"{S}/config/firewall", json={"default_action": "allow", "rules": []})
    client.put(f"{S}/config/ddos", json={"mode": "off", "threshold_rps": 200, "clearance_ttl": 3600})
    client.put(f"{S}/config/webhooks", json={"items": []})
    client.patch(f"{S}/plan", json={"features": {"max_firewall_rules": 2, "ddos": False}})
    dry = client.post(f"{S}/config/history/{v}/restore", json={"dry_run": True}).json()
    assert dry["version"] is None and set(dry["applied"]) == {"firewall", "webhooks"}
    assert {"section": "ddos", "reason": "feature_missing", "feature": "ddos"} in dry["dropped"]
    assert {"section": "firewall", "reason": "limit", "feature": "max_firewall_rules", "kept": 2,
            "removed": 2} in dry["dropped"]
    assert client.get(f"{S}/config/firewall").json()["rules"] == []  # dry run wrote nothing
    res = client.post(f"{S}/config/history/{v}/restore", json={"sections": None}).json()
    assert res["restored_from"] == v and res["version"] > v
    fw = client.get(f"{S}/config/firewall").json()
    assert [r["id"] for r in fw["rules"]] == ["r0", "r1"]
    wh = client.get(f"{S}/config/webhooks").json()["items"]
    assert wh[0]["id"] == hook_id and wh[0]["secret_set"] is True
    assert any(hook_id in w for w in res["warnings"])
    top = client.get(f"{S}/config/history").json()["versions"][0]
    assert top["source"] == "restore" and top["restored_from"] == v
    with SessionLocal() as db:
        a = db.scalar(select(AuditLog).where(AuditLog.action == "config.restore"))
        assert a is not None
    # rate limit: 10 restores / hour / site
    monkeypatch.setattr(config_history, "RESTORES_PER_HOUR", 1)
    assert client.post(f"{S}/config/history/{v}/restore", json={}).status_code == 429


def test_restore_logs_without_secret_comes_back_disabled(client):
    from app import config_restore

    mk_site(client)
    with SessionLocal() as db:
        site = db.scalar(select(Site))
        res = config_restore.apply_sections(db, site, {"logs": {"enabled": True, "s3_endpoint": "",
                                                                "bucket": "", "access_key": ""}})
        db.rollback()
    assert res["dropped"] and res["dropped"][0]["reason"] == "invalid" or \
        any("logs" in w for w in res["warnings"])


def test_capi_history_scopes_and_suspended(client):
    mk_site(client)
    key = capi_key(client, scopes=("stats",))
    assert client.get("/capi/v1/config/history", headers=auth(key)).status_code == 403
    key = capi_key(client, scopes=("config",))
    cache = client.get("/capi/v1/config/cache", headers=auth(key)).json()
    client.put("/capi/v1/config/cache", json={**cache, "edge_ttl": 999}, headers=auth(key))
    h = client.get("/capi/v1/config/history", headers=auth(key)).json()
    assert h["versions"][0]["actor"] == {"kind": "api_key", "label": "ci", "id": h["versions"][0]["actor"]["id"]}
    v = h["versions"][-1]["version"]
    assert client.get(f"/capi/v1/config/history/{v}/diff?section=functions", headers=auth(key)).status_code == 403
    client.post(f"{S}/suspend")
    assert client.post(f"/capi/v1/config/history/{v}/restore", json={}, headers=auth(key)).status_code == 403


def test_history_disabled_404(client, monkeypatch):
    mk_site(client)
    monkeypatch.setattr(settings, "config_history_enabled", False)
    assert client.get(f"{S}/config/history").status_code == 404


# ================================================================== §23.5 alerts

class FakeProviders:
    def __init__(self):
        self.calls = []
        self.status = 200
        self.updates = []
        self.bale = False

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.calls.append(request)
        if request.url.path.endswith("/getUpdates"):
            # the updates belong to the Telegram bot; the Bale bot sees none
            ups = self.updates if ("TGTOKEN" in request.url.path) != self.bale else []
            return httpx.Response(200, json={"ok": True, "result": ups})
        if request.url.path.endswith("/sendMessage"):
            return httpx.Response(self.status, json={"ok": True, "result": {"message_id": 5}})
        return httpx.Response(self.status, json={"entries": [{"messageid": 1}], "data": {"packId": "p"},
                                                 "recId": 3})


@pytest.fixture()
def providers(monkeypatch):
    fake = FakeProviders()
    notify_providers.transport = httpx.MockTransport(fake.handler)
    for k, v in {"sms_provider": "kavenegar", "sms_api_key": "SMSKEY123456", "sms_sender": "3000",
                 "telegram_customer_bot_token": "111:TGTOKEN", "telegram_customer_bot_username": "pcdnbot",
                 "bale_bot_token": "222:BALETOKEN", "bale_bot_username": "pcdnbale"}.items():
        monkeypatch.setattr(settings, k, v)
    return fake


def test_each_sms_provider_request_shape_and_key_never_logged(providers, monkeypatch, caplog):
    caplog.set_level(logging.DEBUG)
    for name, check in (("kavenegar", lambda r: r.url.path == "/v1/SMSKEY123456/sms/send.json"
                         and b"receptor=%2B989121234567" in r.read()),
                        ("smsir", lambda r: r.url.path == "/v1/send/bulk" and r.headers["x-api-key"] == "SMSKEY123456"
                         and json.loads(r.read())["mobiles"] == ["+989121234567"]),
                        ("melipayamak", lambda r: r.url.path == "/api/send/simple/SMSKEY123456"
                         and json.loads(r.read())["to"] == "+989121234567")):
        monkeypatch.setattr(settings, "sms_provider", name)
        providers.calls.clear()
        assert notify_providers.sms_provider().send("+989121234567", "hi")[0] is True
        assert check(providers.calls[0])
    providers.status = 400
    assert notify_providers.sms_provider().send("+989121234567", "hi") == (False, True, None)
    providers.status = 503
    assert notify_providers.sms_provider().send("+989121234567", "hi") == (False, False, None)
    assert "SMSKEY123456" not in caplog.text and "TGTOKEN" not in caplog.text
    st = notify_providers.status()
    assert st["sms"] == {"provider": "melipayamak", "configured": True} and "SMSKEY" not in json.dumps(st)


def test_account_404_plan_403_and_subscription_validation(client, providers):
    assert client.get(f"{A}/accounts/7/alerts").status_code == 404
    mk_site(client)
    view = client.get(f"{A}/accounts/7/alerts").json()
    assert view["channels"]["sms"] == {"available": True, "plan": False}
    assert view["limits"]["max_subscriptions"] == 20
    item = {"site": "example.com", "events": ["origin.down"], "channels": ["sms"], "lang": "fa"}
    r = client.put(f"{A}/accounts/7/alerts/subscriptions", json={"items": [item]})
    assert r.status_code == 403 and r.json() == {"detail": "channel_not_in_plan", "channel": "sms"}
    client.patch(f"{S}/plan", json={"features": {"alert_sms": True}})
    r = client.put(f"{A}/accounts/7/alerts/subscriptions",
                   json={"items": [{**item, "quiet_hours": {"start": "23:00", "end": "07:00"}}]})
    assert r.status_code == 200 and r.json()["subscriptions"][0]["quiet_hours"]["bypass_critical"] is True
    bad = client.put(f"{A}/accounts/7/alerts/subscriptions", json={"items": [{**item, "events": ["abuse.notice"]}]})
    assert bad.status_code == 422
    other = client.put(f"{A}/accounts/7/alerts/subscriptions", json={"items": [{**item, "site": "nope.com"}]})
    assert other.status_code == 422


def test_sms_otp_flow_limits_tries_and_encryption(client, providers, monkeypatch):
    monkeypatch.setattr(settings, "data_encryption_key", Fernet.generate_key().decode())
    mk_site(client, alert_sms=True)
    assert client.post(f"{A}/accounts/7/alerts/targets/sms", json={"phone": "09121234567"}).status_code == 422
    assert client.post(f"{A}/accounts/7/alerts/targets/sms", json={"phone": "+441234567890"}).status_code == 422
    r = client.post(f"{A}/accounts/7/alerts/targets/sms", json={"phone": "+989121234567"})
    assert r.status_code == 202
    tid = r.json()["target_id"]
    sent = providers.calls[-1].read().decode()
    import urllib.parse

    code = [x for x in urllib.parse.parse_qs(sent)["message"][0].split() if x.isdigit()][0]
    with SessionLocal() as db:
        t = db.get(NotificationTarget, tid)
        assert t.value_stored.startswith("enc:v1:") and "989121234567" not in t.value_stored
        assert t.masked == "+98912•••4567"
        assert code not in json.dumps([c.code_hash for c in db.scalars(select(NotificationLinkCode))])
    assert client.post(f"{A}/accounts/7/alerts/targets/{tid}/verify", json={"code": "000000"}).status_code == 422
    assert client.post(f"{A}/accounts/7/alerts/targets/{tid}/verify", json={"code": code}).json() == {"verified": True}
    client.post(f"{A}/accounts/7/alerts/targets/sms", json={"phone": "+989121234568"})
    client.post(f"{A}/accounts/7/alerts/targets/sms", json={"phone": "+989121234569"})
    assert client.post(f"{A}/accounts/7/alerts/targets/sms", json={"phone": "+989121234560"}).status_code == 429
    with SessionLocal() as db:
        details = json.dumps([a.detail for a in db.scalars(select(AuditLog))])
        assert "989121234567" not in details


def test_sms_code_tries_limit(client, providers):
    mk_site(client, alert_sms=True)
    tid = client.post(f"{A}/accounts/7/alerts/targets/sms", json={"phone": "+989121234567"}).json()["target_id"]
    for _ in range(5):
        client.post(f"{A}/accounts/7/alerts/targets/{tid}/verify", json={"code": "000000"})
    r = client.post(f"{A}/accounts/7/alerts/targets/{tid}/verify", json={"code": "000000"})
    assert r.status_code == 422 and r.json()["detail"] == "too_many_tries"


def test_bot_link_single_use_expiry_and_stop(client, providers):
    mk_site(client, alert_messengers=True)
    r = client.post(f"{A}/accounts/7/alerts/targets/telegram/link").json()
    code = r["code"]
    assert r["deep_link"] == f"https://t.me/pcdnbot?start={code}"
    assert client.get(f"{A}/accounts/7/alerts/targets/link/{code}").json() == {"linked": False, "target_id": None}
    providers.updates = [{"update_id": 10, "message": {"chat": {"id": 555123}, "text": f"/start {code}"}},
                         {"update_id": 11, "message": {"chat": {"id": 999}, "text": "hello"}}]
    with SessionLocal() as db:
        scheduler.job_bots(db, force=True)
    st = client.get(f"{A}/accounts/7/alerts/targets/link/{code}").json()
    assert st["linked"] is True
    replies = [json.loads(c.read()) for c in providers.calls if c.url.path.endswith("/sendMessage")]
    assert replies[-1]["chat_id"] == "555123" and "Linked" in replies[-1]["text"]
    assert len(replies) == 1  # nothing else is ever answered
    # the offset advanced; the same code cannot be reused by another chat
    providers.updates = [{"update_id": 12, "message": {"chat": {"id": 777}, "text": f"/start {code}"}}]
    with SessionLocal() as db:
        scheduler.job_bots(db, force=True)
        assert db.query(NotificationTarget).count() == 1
        assert json.loads(db.get(State, "notify_bot_offset:telegram").value)["offset"] == 13
    providers.updates = [{"update_id": 13, "message": {"chat": {"id": 555123}, "text": "/stop"}}]
    with SessionLocal() as db:
        scheduler.job_bots(db, force=True)
        assert db.scalar(select(NotificationTarget)).disabled_at is not None
    # expiry
    code2 = client.post(f"{A}/accounts/7/alerts/targets/bale/link").json()["code"]
    with SessionLocal() as db:
        for c in db.scalars(select(NotificationLinkCode).where(NotificationLinkCode.kind == "bale")):
            c.expires_at = utcnow() - timedelta(minutes=1)
        db.commit()
    with SessionLocal() as db:
        db.query(State).filter(State.key == "notify_bot_offset:bale").delete()
        db.commit()
    providers.updates = [{"update_id": 1, "message": {"chat": {"id": 42}, "text": f"/start {code2}"}}]
    providers.bale = True
    with SessionLocal() as db:
        scheduler.job_bots(db, force=True)
    assert client.get(f"{A}/accounts/7/alerts/targets/link/{code2}").json()["linked"] is False


def _bind_telegram(client, providers, chat=555):
    code = client.post(f"{A}/accounts/7/alerts/targets/telegram/link").json()["code"]
    providers.updates = [{"update_id": chat, "message": {"chat": {"id": chat}, "text": f"/start {code}"}}]
    with SessionLocal() as db:
        scheduler.job_bots(db, force=True)
    providers.updates = []


def _subscribe(client, events, channels, **extra):
    r = client.put(f"{A}/accounts/7/alerts/subscriptions",
                   json={"items": [{"site": None, "events": events, "channels": channels, **extra}]})
    assert r.status_code == 200, r.text


def _rows():
    with SessionLocal() as db:
        return [(r.event, r.channel, r.status, r.error) for r in db.scalars(select(NotificationOutbox)
                                                                           .order_by(NotificationOutbox.id))]


def test_dedup_recovery_rules_and_tunnel_email_exclusion(client, providers):
    mk_site(client, alert_messengers=True)
    _bind_telegram(client, providers)
    _subscribe(client, ["origin.down", "origin.up", "tunnel.origin_down", "quota.warning"], ["email", "telegram"])
    with SessionLocal() as db:
        site = db.scalar(select(Site))
        assert notify.emit(db, site, "origin.up") == 0  # recovery without a sent "down"
        assert notify.emit(db, site, "origin.down") == 2
        assert notify.emit(db, site, "origin.down") == 0  # dedup window
        assert notify.emit(db, site, "origin.up") == 2
        assert notify.emit(db, site, "tunnel.origin_down") == 1  # telegram only (WHMCS e-mails these)
        db.commit()
    assert ("tunnel.origin_down", "email", "pending", None) not in _rows()


def test_rate_limits_and_digest(client, providers, monkeypatch):
    monkeypatch.setattr(settings, "notify_dedup_minutes", 0)
    monkeypatch.setattr(settings, "notify_rate_msg_hour", 2)
    mk_site(client, alert_messengers=True)
    _bind_telegram(client, providers)
    _subscribe(client, ["quota.warning"], ["telegram"])
    now = utcnow().replace(minute=10)
    with SessionLocal() as db:
        site = db.scalar(select(Site))
        for i in range(4):
            notify.emit(db, site, "quota.warning", dedup_key=str(i), now=now)
        db.commit()
    rows = _rows()
    assert [r[2] for r in rows] == ["pending", "pending", "skipped", "skipped"]
    with SessionLocal() as db:
        notify.run(db, now + timedelta(hours=1))
    digests = [r for r in _rows() if r[0] == "digest"]
    assert len(digests) == 1 and digests[0][2] == "sent"
    with SessionLocal() as db:
        d = db.scalar(select(NotificationOutbox).where(NotificationOutbox.event == "digest"))
        assert "2" in d.text or "۲" in d.text


def test_quiet_hours_tehran_midnight_crossing_bypass_and_digest(client, providers, monkeypatch):
    monkeypatch.setattr(settings, "notify_dedup_minutes", 0)
    mk_site(client, alert_messengers=True)
    _bind_telegram(client, providers)
    _subscribe(client, ["quota.warning", "origin.down"], ["telegram", "email"],
               quiet_hours={"start": "23:00", "end": "07:00", "bypass_critical": True})
    # 21:00 UTC = 00:30 Asia/Tehran: inside the window
    night = datetime(2026, 10, 1, 21, 0)
    with SessionLocal() as db:
        sub = db.scalar(select(NotificationSubscription))
        assert notify.quiet_until(sub, night) == datetime(2026, 10, 2, 3, 30)
        assert notify.quiet_until(sub, datetime(2026, 10, 1, 12, 0)) is None
        site = db.scalar(select(Site))
        notify.emit(db, site, "quota.warning", dedup_key="a", now=night)
        notify.emit(db, site, "quota.warning", dedup_key="b", now=night)
        notify.emit(db, site, "origin.down", now=night)
        db.commit()
    rows = _rows()
    assert ("quota.warning", "telegram", "deferred", None) in rows
    assert ("quota.warning", "email", "pending", None) in rows  # e-mail is never deferred
    assert ("origin.down", "telegram", "pending", None) in rows  # critical bypasses
    with SessionLocal() as db:
        notify.run(db, datetime(2026, 10, 2, 3, 31))
    assert [r for r in _rows() if r[0] == "digest"][0][2] == "sent"


def test_retries_and_permanent_failure_disabling(client, providers):
    mk_site(client, alert_messengers=True)
    _bind_telegram(client, providers)
    _subscribe(client, ["quota.warning"], ["telegram"])
    providers.status = 503
    now = utcnow()
    with SessionLocal() as db:
        notify.emit(db, db.scalar(select(Site)), "quota.warning", now=now)
        db.commit()
        notify.run(db, now)
        row = db.scalar(select(NotificationOutbox))
        assert row.status == "pending" and row.next_attempt_at == now + timedelta(minutes=1)
        for hours in (1, 2, 3):
            notify.run(db, now + timedelta(hours=hours))
        db.refresh(row)
        assert row.status == "failed" and row.error == "provider_unreachable"
    providers.status = 403
    with SessionLocal() as db:
        for i in range(3):
            notify.emit(db, db.scalar(select(Site)), "quota.warning", dedup_key=f"p{i}", now=now)
            db.commit()
            notify.run(db, now)
        assert db.scalar(select(NotificationTarget)).disabled_at is not None


def test_email_outbox_paging_ack_reoffer_expiry_and_abuse_notice(client, providers):
    mk_site(client)
    mk_site(client, domain="second.org")
    _subscribe(client, ["quota.warning"], ["email"])
    with SessionLocal() as db:
        for s in db.scalars(select(Site)):
            notify.emit(db, s, "quota.warning")
        db.commit()
    page = client.get(f"{A}/notifications/outbox?channel=email&limit=1").json()
    assert len(page["items"]) == 1 and page["next"] == page["items"][0]["id"]
    item = page["items"][0]
    assert item["client_id"] == 7 and item["site"] == "example.com" and item["subject"] and item["lang"] == "fa"
    page2 = client.get(f"{A}/notifications/outbox?after={page['next']}").json()
    assert len(page2["items"]) == 1 and page2["next"] is None
    assert client.get(f"{A}/notifications/outbox").json()["items"] == []  # offered: re-offered after 30 min
    client.post(f"{A}/notifications/outbox/ack", json={"results": {str(item["id"]): "sent"}})
    with SessionLocal() as db:
        for r in db.scalars(select(NotificationOutbox)):
            if r.status == "pending":
                r.next_attempt_at = utcnow() - timedelta(minutes=1)
        db.commit()
    again = client.get(f"{A}/notifications/outbox").json()["items"]
    assert [i["site"] for i in again] == ["second.org"]
    with SessionLocal() as db:
        db.query(NotificationOutbox).update({"created_at": utcnow() - timedelta(hours=49)})
        db.commit()
        notify.run(db)
        assert {r.status for r in db.scalars(select(NotificationOutbox))} == {"sent", "expired"}


def test_incident_account_scoped_and_test_message_limit(client, providers):
    mk_site(client)
    mk_site(client, domain="second.org")
    _subscribe(client, ["incident.opened", "incident.resolved"], ["email"])
    inc = client.post(f"{A}/incidents", json={"title": "DNS slow", "severity": "maintenance"}).json()
    rows = _rows()
    assert rows == [("incident.opened", "email", "pending", None)]  # one per account, not per site
    with SessionLocal() as db:
        assert db.scalar(select(NotificationOutbox)).severity == "info"
    client.patch(f"{A}/incidents/{inc['id']}", json={"status": "resolved"})
    assert ("incident.resolved", "email", "pending", None) in _rows()
    for _ in range(3):
        assert client.post(f"{A}/accounts/7/alerts/test", json={"channel": "email"}).status_code == 202
    assert client.post(f"{A}/accounts/7/alerts/test", json={"channel": "email"}).status_code == 429


def test_origin_down_up_windows_from_oe(client, providers):
    mk_site(client)
    _subscribe(client, ["origin.down", "origin.up"], ["email"])
    now = datetime(2026, 10, 3, 10, 11)
    end = datetime(2026, 10, 3, 10, 10)

    def put(minute_offset, req, oe):
        with SessionLocal() as db:
            db.merge(AnalyticsMinute(site_id=1, minute=end - timedelta(minutes=minute_offset), requests=req, bytes=0,
                                     cache_hits=0, details=json.dumps({"oe": oe, "pe": 0})))
            db.commit()

    for m in range(1, 11):
        put(m, 10, 6)  # 2 windows × 50 requests, 60 % origin 5xx
    with SessionLocal() as db:
        assert notify.check_web_origins(db, now) == [("example.com", "origin.down")]
        assert notify.check_web_origins(db, now) == []  # once per window
    for m in range(1, 11):
        put(m, 10, 0)
    with SessionLocal() as db:
        assert notify.check_web_origins(db, now) == []  # this window was evaluated already
    with SessionLocal() as db:
        db.query(State).filter(State.key == notify.WEB_ORIGIN_LAST).delete()
        db.commit()
        assert notify.check_web_origins(db, now) == [("example.com", "origin.up")]
    events = [e["type"] for e in client.get(f"{S}/events").json()] if client.get(f"{S}/events").status_code == 200 \
        else []
    assert isinstance(events, list)
    assert [r[0] for r in _rows()] == ["origin.down", "origin.up"]


def test_ssl_expiring_thresholds_once_each(client, providers):
    mk_site(client)
    _subscribe(client, ["ssl.expiring"], ["email"])
    now = utcnow()
    with SessionLocal() as db:
        s = db.scalar(select(Site))
        s.ssl_status, s.ssl_cert, s.ssl_expires_at = "active", "CERT", now + timedelta(days=10, hours=1)
        db.commit()
        assert notify.check_ssl_expiring(db, now, force=True) == [("example.com", 14)]
        assert notify.check_ssl_expiring(db, now, force=True) == []
        s.ssl_expires_at = now + timedelta(days=6)
        db.commit()
        assert notify.check_ssl_expiring(db, now, force=True) == [("example.com", 7)]
        s.ssl_cert = "NEWCERT"
        db.commit()
        assert notify.check_ssl_expiring(db, now, force=True) == [("example.com", 7)]  # new certificate
    assert [r[0] for r in _rows()].count("ssl.expiring") >= 1


def test_capi_alerts_and_templates_have_no_node_identity(client, providers):
    mk_site(client)
    _subscribe(client, ["quota.warning"], ["email"])
    key = capi_key(client)
    assert client.get("/capi/v1/alerts", headers=auth(key)).json()["subscriptions"][0]["events"] == ["quota.warning"]
    from app import notify_templates

    for event, langs in notify_templates.TEMPLATES.items():
        for lang, (subj, text) in langs.items():
            assert "WHMCS" not in subj + text and "edge" not in (subj + text).lower()


# ================================================================== §23.6 import

ARVAN_DNS = [
    {"type": "a", "name": "@", "value": [{"ip": "93.184.216.34"}], "ttl": 120, "cloud": True},
    {"type": "a", "name": "multi", "value": [{"ip": "93.184.216.35", "weight": 50},
                                              {"ip": "93.184.216.36", "weight": 50}], "ttl": 30, "cloud": False},
    {"type": "aaaa", "name": "v6", "value": [{"ip": "2606:4700::1111", "country": "IR"}], "ttl": 100000, "cloud": False},
    {"type": "cname", "name": "www", "value": {"host": "example.com"}, "ttl": 300, "cloud": True},
    {"type": "aname", "name": "alias", "value": {"location": "target.example.net"}, "ttl": 300},
    {"type": "mx", "name": "@", "value": {"host": "mail.example.com", "priority": 10}, "ttl": 300},
    {"type": "txt", "name": "@", "value": {"text": "v=spf1 -all"}, "ttl": 300},
    {"type": "ns", "name": "@", "value": {"host": "ns1.arvancdn.ir"}, "ttl": 300},
    {"type": "ns", "name": "sub", "value": {"host": "ns1.other.net"}, "ttl": 300},
    {"type": "srv", "name": "_sip._tcp", "value": {"target": "sip.example.com", "port": 5060, "weight": 5,
                                                    "priority": 1}, "ttl": 300},
    {"type": "caa", "name": "@", "value": {"tag": "issue", "value": "letsencrypt.org"}, "ttl": 300},
    {"type": "tlsa", "name": "x", "value": {"x": 1}, "ttl": 300},
]
ARVAN_SETTINGS = {
    "caching": {"cache_status": "uri", "cache_page_200": "2h", "cache_browser": "30m", "cache_developer_mode": False,
                "cache_ignore_sc": True},
    "https": {"https_redirect": True, "hsts_status": True, "hsts_max_age": 31536000, "hsts_subdomain": True,
              "hsts_preload": True},
    "firewall": [{"name": "block bad", "filter_expr": "ip.src in {1.2.3.4 5.6.7.0/24}", "action": "deny"},
                 {"name": "geo", "filter_expr": 'ip.geoip.country in {"CN" "RU"} and '
                                                'starts_with(http.request.uri.path, "/admin")', "action": "challenge"},
                 {"name": "complex", "filter_expr": "http.user_agent contains \"x\" or ip.src eq 1.1.1.1",
                  "action": "deny"}],
    "page_rules": [{"url": "example.com/old*", "forward_url": "https://example.com/new", "forward_status": 302},
                   {"url": "/cache-only", "cache_level": "all"}],
    "ddos": {"ddos_protection_mode": "cookie"},
    "rate_limit": [{"url_pattern": "/login", "rate": 10, "duration": "1m"}, {"url_pattern": "x", "rate": "?"}],
}


def test_arvan_mappers_on_fixtures():
    recs, unmapped = arvan.map_records(ARVAN_DNS, "example.com")
    by = {(r["name"], r["type"]): r for r in recs}
    assert by[("@", "A")]["proxied"] is True and by[("@", "A")]["ttl"] == 120
    assert [r["weight"] for r in recs if r["name"] == "multi"] == [50, 50]
    assert by[("v6", "AAAA")]["ttl"] == 86400
    assert by[("alias", "ALIAS")]["content"] == "target.example.net"
    assert by[("@", "MX")]["priority"] == 10 and by[("@", "TXT")]["content"] == "v=spf1 -all"
    assert by[("@", "NS")]["status"] == "unsupported" and by[("sub", "NS")]["content"] == "ns1.other.net"
    assert by[("_sip._tcp", "SRV")]["content"] == "5 5060 sip.example.com"
    assert by[("@", "CAA")]["content"] == '0 issue "letsencrypt.org"'
    assert by[("x", "TLSA")]["status"] == "unsupported"
    assert any(u["what"].endswith(":country") for u in unmapped)
    cache = arvan.map_caching(ARVAN_SETTINGS["caching"])
    assert cache["status"] == "partial" and cache["fields"] == {"enabled": True, "ignore_query": True,
                                                                "edge_ttl": 7200, "browser_ttl": 1800,
                                                                "dev_mode": False}
    ssl = arvan.map_https(ARVAN_SETTINGS["https"])
    assert ssl["status"] == "maps" and ssl["fields"]["hsts"]["preload"] is True
    fw, u = arvan.map_firewall(ARVAN_SETTINGS["firewall"])
    assert fw["status"] == "partial" and [r["action"] for r in fw["rules"]] == ["block", "challenge"]
    assert fw["rules"][1]["conditions"] == [{"field": "country", "op": "in", "value": ["CN", "RU"]},
                                            {"field": "path", "op": "starts_with", "value": "/admin"}]
    assert [x["what"] for x in u] == ["firewall:complex"]
    pr, u = arvan.map_page_rules(ARVAN_SETTINGS["page_rules"])
    assert pr["rules"][0]["source"] == "/old" and pr["rules"][0]["match"] == "prefix" and pr["rules"][0]["status"] == 302
    assert arvan.map_ddos(ARVAN_SETTINGS["ddos"])["fields"] == {"mode": "js"}
    rl, u = arvan.map_rate_limit(ARVAN_SETTINGS["rate_limit"])
    assert rl["rules"][0]["requests"] == 10 and rl["rules"][0]["period"] == 60 and len(u) == 1
    assert arvan.map_caching(None)["status"] == "none"
    _, _, unm = arvan.map_all({"dns": []}, "example.com")
    assert {u["what"] for u in unm} >= {"load_balancers", "tls_certificates", "log_forwarders"}


def arvan_handler(pages=2, fail=None, seen=None):
    def handler(request: httpx.Request) -> httpx.Response:
        if seen is not None:
            seen.append(request)
        if fail:
            return fail(request)
        p = request.url.path
        if p.endswith("/domains/example.com"):
            return httpx.Response(200, json={"data": {"domain": "example.com"}})
        if p.endswith("/dns-records"):
            page = int(request.url.params.get("page"))
            half = len(ARVAN_DNS) // pages
            items = ARVAN_DNS[(page - 1) * half: page * half if page < pages else None]
            return httpx.Response(200, json={"data": items, "meta": {"last_page": pages}})
        for key, path in (("caching", "/caching"), ("https", "/https"), ("firewall", "/firewall/rules"),
                          ("page_rules", "/page-rules"), ("ddos", "/ddos"), ("rate_limit", "/rate-limit/rules")):
            if p.endswith(path):
                return httpx.Response(200, json={"data": ARVAN_SETTINGS[key]})
        return httpx.Response(404)
    return handler


def test_arvan_fetch_pagination_auth_and_errors():
    seen = []
    importers.transport = httpx.MockTransport(arvan_handler(seen=seen))
    raw = arvan.fetch("MYKEY-123", "example.com")
    assert len(raw["dns"]) == len(ARVAN_DNS) and raw["ddos"] == ARVAN_SETTINGS["ddos"]
    assert all(r.headers["authorization"] == "Apikey MYKEY-123" for r in seen)
    importers.transport = httpx.MockTransport(arvan_handler(fail=lambda r: httpx.Response(401)))
    with pytest.raises(importers.ProviderError) as e:
        arvan.fetch("k", "example.com")
    assert e.value.detail == "provider_auth" and e.value.status == 422
    importers.transport = httpx.MockTransport(arvan_handler(fail=lambda r: httpx.Response(404)))
    with pytest.raises(importers.ProviderError, match="provider_zone_not_found"):
        arvan.fetch("k", "example.com")

    def boom(r):
        raise httpx.ConnectTimeout("timeout")

    importers.transport = httpx.MockTransport(arvan_handler(fail=boom))
    with pytest.raises(importers.ProviderError, match="provider_unreachable"):
        arvan.fetch("k", "example.com")


def test_cloudflare_mappers_and_fetch():
    def handler(request):
        p = request.url.path
        assert request.headers["authorization"] == "Bearer CFTOKEN"
        if p.endswith("/zones"):
            return httpx.Response(200, json={"result": [{"id": "abc123"}]})
        if p.endswith("/dns_records"):
            return httpx.Response(200, json={"result": [
                {"type": "A", "name": "example.com", "content": "93.184.216.34", "ttl": 1, "proxied": True},
                {"type": "MX", "name": "example.com", "content": "mx.example.com", "priority": 5, "ttl": 300},
                {"type": "SRV", "name": "_x._tcp.example.com", "ttl": 300,
                 "data": {"priority": 1, "weight": 2, "port": 3, "target": "t.example.com"}}],
                "result_info": {"total_pages": 1}})
        if p.endswith("/settings"):
            return httpx.Response(200, json={"result": [{"id": "always_use_https", "value": "on"},
                                                        {"id": "browser_cache_ttl", "value": 3600},
                                                        {"id": "development_mode", "value": "off"},
                                                        {"id": "security_level", "value": "under_attack"}]})
        return httpx.Response(404)

    importers.transport = httpx.MockTransport(handler)
    raw = cloudflare.fetch("CFTOKEN", "example.com")
    recs, secs, unm = cloudflare.map_all(raw, "example.com")
    assert recs[0] == {"name": "@", "type": "A", "content": "93.184.216.34", "ttl": 300, "proxied": True,
                       "priority": None}
    assert recs[2]["content"] == "2 3 t.example.com" and recs[2]["priority"] == 1
    assert secs["ssl"]["fields"] == {"force_https": True} and secs["ddos"]["fields"] == {"mode": "js"}
    assert secs["cache"]["fields"] == {"browser_ttl": 3600, "dev_mode": False}
    importers.transport = httpx.MockTransport(lambda r: httpx.Response(200, json={"result": []}))
    with pytest.raises(importers.ProviderError, match="provider_zone_not_found"):
        cloudflare.fetch("CFTOKEN", "example.com")


def test_import_preview_apply_key_never_stored_or_logged(client, fake_pdns, monkeypatch, caplog):
    caplog.set_level(logging.DEBUG)
    monkeypatch.setattr(settings, "data_encryption_key", Fernet.generate_key().decode())
    mk_site(client)
    secret_key = "ARVAN-SECRET-KEY-0123456789"
    importers.transport = httpx.MockTransport(arvan_handler())
    r = client.post(f"{S}/import/preview", json={"provider": "arvan", "api_key": secret_key})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["session_id"].startswith("imp_") and body["provider"] == "arvan" and body["zone"] == "example.com"
    items = body["report"]["records"]["items"]
    st = {(i["name"], i["type"]): i["status"] for i in items}
    assert st[("@", "A")] == "duplicate" and st[("@", "NS")] == "unsupported" and st[("_sip._tcp", "SRV")] == "ok"
    assert body["report"]["sections"]["cache"]["value"]["edge_ttl"] == 7200
    assert body["report"]["sections"]["firewall"]["status"] == "partial"
    # the key is nowhere: response, DB, logs, audit
    assert secret_key not in r.text and secret_key not in caplog.text
    with SessionLocal() as db:
        row = db.get(ImportSession, body["session_id"])
        assert row.data.startswith("enc:v1:") and secret_key not in row.data
        dump = json.dumps([(s.key, s.value) for s in db.scalars(select(State))])
        assert secret_key not in dump
    res = client.post(f"{S}/import/apply", json={"session_id": body["session_id"], "records": True,
                                                 "sections": ["cache", "ddos", "firewall"]}).json()
    assert res["records"]["imported"] >= 5 and res["config_version"] is not None
    assert set(res["sections"]["applied"]) == {"cache", "ddos", "firewall"}
    assert client.get(f"{S}/config/history").json()["versions"][0]["source"] == "import"
    assert client.get(f"{S}/config/ddos").json()["mode"] == "js"
    with SessionLocal() as db:
        assert db.get(ImportSession, body["session_id"]) is None  # deleted on apply
        assert secret_key not in json.dumps([a.detail for a in db.scalars(select(AuditLog))])
    assert client.post(f"{S}/import/apply", json={"session_id": body["session_id"]}).status_code == 404


def test_import_generic_422_errors_rate_limit_and_delete(client, monkeypatch):
    mk_site(client)
    secret_key = "ZZSECRETZZ"
    r = client.post(f"{S}/import/preview", json={"provider": "nope", "api_key": secret_key})
    assert r.status_code == 422 and secret_key not in r.text and r.json() == {"detail": "invalid request"}
    r = client.post(f"{S}/import/preview", content=b"{bad json " + secret_key.encode())
    assert r.status_code == 422 and secret_key not in r.text
    importers.transport = httpx.MockTransport(lambda req: httpx.Response(403))
    r = client.post(f"{S}/import/preview", json={"provider": "cloudflare", "api_key": secret_key})
    assert r.status_code == 422 and r.json() == {"detail": "provider_auth"}
    importers.transport = httpx.MockTransport(lambda req: httpx.Response(503))
    r = client.post(f"{S}/import/preview", json={"provider": "cloudflare", "api_key": secret_key})
    assert r.status_code == 502 and r.json() == {"detail": "provider_unreachable"}
    importers.transport = httpx.MockTransport(arvan_handler())
    ok = client.post(f"{S}/import/preview", json={"provider": "arvan", "api_key": "k"}).json()
    # without DATA_ENCRYPTION_KEY the session lives in memory only
    with SessionLocal() as db:
        assert db.get(ImportSession, ok["session_id"]) is None
    assert client.delete(f"{S}/import/{ok['session_id']}").status_code == 204
    assert client.post(f"{S}/import/apply", json={"session_id": ok["session_id"]}).status_code == 404
    for _ in range(10):
        client.post(f"{S}/import/preview", json={"provider": "arvan", "api_key": "k"})
    assert client.post(f"{S}/import/preview", json={"provider": "arvan", "api_key": "k"}).status_code == 429


def test_import_capi_scopes_and_plan_limits(client):
    mk_site(client, max_firewall_rules=1)
    key = capi_key(client, scopes=("config",))
    assert client.post("/capi/v1/import/preview", json={"provider": "arvan", "api_key": "k"},
                       headers=auth(key)).status_code == 403
    key = capi_key(client, scopes=("config", "dns"))
    importers.transport = httpx.MockTransport(arvan_handler())
    body = client.post("/capi/v1/import/preview", json={"provider": "arvan", "api_key": "k"}, headers=auth(key)).json()
    res = client.post("/capi/v1/import/apply", json={"session_id": body["session_id"], "records": False,
                                                    "sections": ["firewall"]}, headers=auth(key)).json()
    assert {"section": "firewall", "reason": "limit", "feature": "max_firewall_rules", "kept": 1,
            "removed": 1} in res["sections"]["dropped"]


# ================================================================== §23.7 RUM

def H(n=0, **m):
    out = {"n": n}
    for k, v in m.items():
        out[k] = v
    return out


def ms_hist(idx, n):
    h = [0] * 17
    h[idx] = n
    return h


def test_bucket_contract_golden():
    assert rum.MS_BOUNDS[:-1] == [50, 100, 200, 300, 500, 800, 1000, 1500, 1800, 2000, 2500, 3000, 4000, 5000,
                                  8000, 12000] and len(rum.MS_BOUNDS) == 17
    assert rum.CLS_BOUNDS[:-1] == [10, 50, 100, 150, 250, 500, 1000] and len(rum.CLS_BOUNDS) == 8


def test_p75_interpolation_thresholds_and_clean():
    counts = ms_hist(10, 100)  # all in (2000, 2500]
    assert rum.percentile(counts, "lcp") == 2375.0
    assert rum.shares(counts, "lcp") == (100.0, 0.0)
    last = ms_hist(16, 4)
    assert rum.percentile(last, "lcp") == 12000.0
    cls = [0, 0, 10, 0, 0, 0, 0, 0]  # (50, 100]
    assert rum.percentile(cls, "cls") == pytest.approx(0.0875, abs=0.001)
    assert rum.clean({"all": {"n": 1, "lcp": [1]}}) is None
    assert rum.clean({"all": {"n": -1}}) is None
    assert rum.clean({"all": H(1), "by": {"cc": {"IR": H(1), "bad": "x"}}})["by"] == {"cc": {"IR": {"n": 1}}}


def usage_with_rum(client, tok, rum_obj, host="example.com"):
    hour = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0).isoformat()
    r = client.post("/edge/v1/usage", headers=auth(tok), json={"items": [
        {"host": host, "hour": hour, "bytes": 1, "requests": 1, "rum": rum_obj}]})
    assert r.status_code == 200, r.text


def test_rum_merge_report_impact_plan_and_capi(client):
    mk_site(client, rum=True)
    tok = client.post(f"{A}/edges", json={"name": "edge-secret-1", "ipv4": "5.160.1.10"}).json()["token"]
    client.post("/edge/v1/heartbeat", json={"applied_version": "v"}, headers=auth(tok))
    obj = {"n": 50, "all": H(50, lcp=ms_hist(10, 50), ttfb=ms_hist(3, 50)),
           "by": {"cc": {"IR": H(40, lcp=ms_hist(10, 40)), "other": H(10, lcp=ms_hist(10, 10))},
                  "asn": {"197207": H(50, lcp=ms_hist(10, 50))},
                  "cs": {"HIT": H(30, ttfb=ms_hist(1, 30), lcp=ms_hist(8, 30)),
                         "MISS": H(30, ttfb=ms_hist(6, 30), lcp=ms_hist(11, 30))}}}
    usage_with_rum(client, tok, obj)
    usage_with_rum(client, tok, obj)  # bucket-wise addition
    usage_with_rum(client, tok, {"garbage": True})  # malformed -> ignored, never a 422
    r = client.get(f"{S}/rum?hours=24&by=isp").json()
    assert r["n"] == 100 and r["has_data"] and r["metrics"]["lcp"]["p75"] == 2375.0
    assert r["by"][0] == {"key": "197207", "label": "همراه اول", "label_en": "MCI", "n": 100,
                          "p75": {"lcp": 2375.0, "inp": None, "cls": None, "ttfb": None}}
    imp = r["cdn_impact"]
    assert imp["hit"]["n"] == 60 and imp["ttfb_gain_pct"] > 0 and imp["hit_ratio_pct"] == 50.0
    c = client.get(f"{S}/rum?by=country").json()["by"]
    assert c[0]["label"] == "ایران"
    assert client.get(f"{S}/rum?hours=5").status_code == 422
    key = capi_key(client, scopes=("stats",))
    assert client.get("/capi/v1/rum", headers=auth(key)).json()["n"] == 100
    client.patch(f"{S}/plan", json={"features": {"rum": False}})
    assert client.get(f"{S}/rum").status_code == 404
    assert "edge-secret-1" not in json.dumps(r)


def test_rum_impact_null_below_30_and_retention(client, monkeypatch):
    mk_site(client, rum=True)
    tok = client.post(f"{A}/edges", json={"name": "e1", "ipv4": "5.160.1.10"}).json()["token"]
    usage_with_rum(client, tok, {"all": H(10), "by": {"cs": {"HIT": H(10), "MISS": H(10)}}})
    assert client.get(f"{S}/rum").json()["cdn_impact"] is None
    from app.models import RumHourly

    with SessionLocal() as db:
        db.query(RumHourly).update({"hour": utcnow() - timedelta(days=40)})
        db.commit()
        rum.prune(db)
        db.commit()
        assert db.query(RumHourly).count() == 0


def test_rum_section_gate_and_edge_block(client):
    mk_site(client)
    body = {"enabled": True, "sample_rate": 0.5, "inject": "manual", "exclude_paths": ["/admin"], "spa": True}
    assert client.put(f"{S}/config/rum", json=body).status_code == 403
    assert client.put(f"{S}/config/rum", json={**body, "enabled": False}).status_code == 200
    client.patch(f"{S}/plan", json={"features": {"rum": True}})
    assert client.put(f"{S}/config/rum", json={**body, "exclude_paths": ["admin"]}).status_code == 422
    assert client.put(f"{S}/config/rum", json=body).status_code == 200
    tok = client.post(f"{A}/edges", json={"name": "e1", "ipv4": "5.160.1.10"}).json()["token"]
    cfg = client.get("/edge/v1/config", headers=auth(tok)).json()
    assert cfg["sites"][0]["rum"] == {"enabled": True, "sample": 0.5, "inject": "manual", "exclude": ["/admin"],
                                      "spa": True}


def test_live_oe_pe_stored(client):
    mk_site(client)
    tok = client.post(f"{A}/edges", json={"name": "e1", "ipv4": "5.160.1.10"}).json()["token"]
    minute = datetime.now(timezone.utc).replace(second=0, microsecond=0).isoformat()
    r = client.post("/edge/v1/usage", headers=auth(tok), json={"items": [], "live": [
        {"host": "example.com", "minute": minute, "requests": 10, "oe": 3, "pe": 0}]})
    assert r.status_code == 200
    with SessionLocal() as db:
        d = json.loads(db.scalar(select(AnalyticsMinute)).details)
        assert d["oe"] == 3 and d["pe"] == 0


# ================================================================== §23.8 diagnostics

def test_diagnostics_shape_redaction_labels_and_admin_internal(client, fake_dns):
    mk_site(client, tunnel=True)
    client.put(f"{S}/config/headers", json={"request": [{"name": "X-Secret", "value": "hdr-secret-value"}],
                                           "response": []})
    client.put(f"{S}/config/webhooks", json={"items": [{"url": "https://hooks.public.example/secret-hook",
                                                        "events": ["ssl.issued"]}]})
    client.put(f"{S}/config/tunnel", json={"enabled": True, "paths": [
        {"id": "p1", "path": "/very-secret-path", "protocol": "ws", "origin": {"address": "93.184.216.34",
                                                                              "port": 8443}}]})
    tok = client.post(f"{A}/edges", json={"name": "edge-secret-1", "ipv4": "5.160.1.10"}).json()["token"]
    client.post("/edge/v1/heartbeat", json={"applied_version": "v"}, headers=auth(tok))
    r = client.get(f"{S}/diagnostics")
    assert r.status_code == 200
    rep = r.json()
    assert rep["report_id"].startswith("dg_") and rep["audience"] == "customer" and "internal" not in rep
    assert rep["config"]["tunnel"] == {"enabled": True, "paths": 1, "protocols": ["ws"]}
    assert rep["site"]["domain"] == "example.com"
    for secret in ("hdr-secret-value", "secret-hook", "/very-secret-path", "edge-secret-1", "5.160.1.10",
                   "93.184.216.34"):
        assert secret not in r.text, secret
    assert len(r.content) <= 64 * 1024
    adm = client.get(f"{S}/diagnostics?audience=admin").json()
    assert adm["internal"]["edges_serving"][0]["name"] == "edge-secret-1"
    key = capi_key(client, scopes=("stats",))
    c = client.get("/capi/v1/diagnostics", headers=auth(key)).json()
    assert c["audience"] == "customer" and "internal" not in c
    with SessionLocal() as db:
        assert db.scalar(select(AuditLog).where(AuditLog.action == "diagnostics.generate")) is not None


def test_diagnostics_rate_limit(client, monkeypatch):
    mk_site(client)
    monkeypatch.setattr(diagnostics, "PER_HOUR", 2)
    assert client.get(f"{S}/diagnostics").status_code == 200
    assert client.get(f"{S}/diagnostics").status_code == 200
    assert client.get(f"{S}/diagnostics").status_code == 429


# ================================================================== §23.12 no internal names anywhere

def test_no_internal_node_name_in_customer_endpoints(client, fake_dns):
    mk_site(client, tunnel=True, rum=True)
    client.put(f"{S}/config/tunnel", json={"enabled": True, "paths": [
        {"id": "p1", "path": "/t", "protocol": "ws", "origin": {"address": "93.184.216.34", "port": 8443}}]})
    tok = client.post(f"{A}/edges", json={"name": "edge-secret-1", "ipv4": "5.160.1.10"}).json()["token"]
    client.post("/edge/v1/heartbeat", json={"applied_version": "v"}, headers=auth(tok))
    hour = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0).isoformat()
    client.post("/edge/v1/usage", headers=auth(tok), json={"items": [
        {"host": "example.com", "hour": hour, "bytes": 1, "requests": 1,
         "tunnel": {"sessions": 2, "seconds": 10, "bytes_up": 1, "bytes_down": 1,
                    "paths": {"p1": {"sessions": 2, "seconds": 10, "bytes_up": 1, "bytes_down": 1}}}}]})
    key = capi_key(client, scopes=("stats", "config", "dns"))
    paths = ["/tunnel/quality", "/tunnel/drops", "/tunnel/profile", "/diagnostics", "/rum", "/config/history",
             "/alerts", "/site"]
    for p in paths:
        r = client.get("/capi/v1" + p, headers=auth(key))
        assert r.status_code == 200, (p, r.text)
        assert "edge-secret-1" not in r.text, p
    q = client.get(f"{S}/tunnel/quality").json()
    assert q["edges"] and q["edges"][0]["name"].startswith("نود") and "edge-secret-1" not in json.dumps(q)


# ================================================================== §23.10 abuse desk

@pytest.fixture()
def abuse_on(monkeypatch):
    monkeypatch.setattr(settings, "abuse_enabled", True)
    monkeypatch.setattr(settings, "abuse_pow_bits", 16)


def solved(client):
    ch = client.get("/public/v1/abuse/challenge").json()
    return {"id": ch["id"], "salt": ch["salt"], "nonce": abuse.solve(ch["salt"], ch["bits"])}


def report(client, ch, **kw):
    body = {"category": "phishing", "urls": ["https://login.example.com/x"], "description": "fake bank",
            "email": "reporter@mail.test", "challenge": ch, "website": "", **kw}
    return client.post("/public/v1/abuse/reports", json=body)


def test_abuse_disabled_404(client):
    assert client.get("/public/v1/abuse/challenge").status_code == 404
    assert client.post("/public/v1/abuse/reports", json={}).status_code == 404


def test_pow_bits_reuse_expiry_signature_and_honeypot(client, abuse_on):
    ch = solved(client)
    assert hashlib.sha256((ch["salt"] + ch["nonce"]).encode()).digest()[:2] == b"\0\0"
    r = report(client, ch)
    assert r.status_code == 201 and r.headers["access-control-allow-origin"] == "*"
    assert report(client, ch).json()["detail"] == "challenge_used"
    bad = dict(solved(client))
    bad["salt"] = bad["salt"][:-1] + ("0" if bad["salt"][-1] != "0" else "1")
    assert report(client, bad).json()["detail"] == "invalid_challenge"
    unsolved = solved(client)
    unsolved["nonce"] = "x"
    assert report(client, unsolved).status_code == 422
    assert report(client, solved(client), website="http://spam").status_code == 422
    assert report(client, solved(client), urls=["ftp://x"]).status_code == 422
    assert report(client, solved(client), urls=[f"https://a{i}.com" for i in range(11)]).status_code == 422
    import uuid

    from app.models import utcnow as now_

    with SessionLocal() as db:
        old = abuse.challenge(now_() - timedelta(minutes=11))
        nonce = abuse.solve(old["salt"], 16)
        with pytest.raises(Exception) as e:
            abuse.verify_challenge(db, {"id": old["id"], "salt": old["salt"], "nonce": nonce})
        assert "challenge_expired" in str(e.value.detail)
        assert uuid.UUID(old["id"])


def test_rate_limit_status_token_and_site_matching(client, abuse_on, monkeypatch):
    mk_site(client)
    monkeypatch.setattr(settings, "abuse_rate_per_hour", 2)
    out = report(client, solved(client), urls=["https://shop.example.com/a"]).json()
    report(client, solved(client))
    assert report(client, solved(client)).status_code == 429
    st = client.get(f"/public/v1/abuse/reports/{out['ticket']}?token={out['status_token']}").json()
    assert st == {"ticket": out["ticket"], "status": "new", "created_at": st["created_at"],
                  "updated_at": st["updated_at"], "public_note": None}
    assert client.get(f"/public/v1/abuse/reports/{out['ticket']}?token=wrong").status_code == 404
    with SessionLocal() as db:
        r = db.scalar(select(AbuseReport).where(AbuseReport.ticket == out["ticket"]))
        assert r.site_id == db.scalar(select(Site)).id and r.reporter_ip_hash and len(r.status_token_hash) == 64
        assert r.ticket.startswith("AB-") and len(r.ticket) == 11


def test_admin_queue_notify_suspend_unsuspend_and_billing_interplay(client, abuse_on, fake_pdns, alert_settings):
    mk_site(client)
    out = report(client, solved(client), urls=["https://example.com/phish"]).json()
    rid = client.get(f"{A}/abuse/reports").json()["reports"][0]["id"]
    det = client.get(f"{A}/abuse/reports/{rid}").json()
    assert det["site"] == "example.com" and det["reporter_email"] == "reporter@mail.test" and det["site_client_id"] == 7
    assert client.get(f"{A}/abuse/reports?q=phish").json()["reports"]
    client.patch(f"{A}/abuse/reports/{rid}", json={"status": "triage", "note": "looks real"})
    client.post(f"{A}/abuse/reports/{rid}/notify", json={"deadline_hours": 24, "lang": "en"})
    with SessionLocal() as db:
        row = db.scalar(select(NotificationOutbox).where(NotificationOutbox.event == "abuse.notice"))
        assert row.channel == "email" and row.client_id == 7 and out["ticket"] in row.text
        assert "reporter@mail.test" not in row.text + row.vars
    assert client.get(f"{A}/overview").json()["abuse_open"] == 1
    tok = client.post(f"{A}/edges", json={"name": "e1", "ipv4": "5.160.1.10"}).json()["token"]
    r = client.post(f"{A}/abuse/reports/{rid}/action", json={"action": "suspend", "public_note": "removed"})
    assert r.status_code == 200
    assert client.get(S).json()["status"] == "suspended" and client.get(S).json()["abuse_suspended"] is True
    cfg = client.get("/edge/v1/config", headers=auth(tok)).json()
    assert cfg["sites"][0]["status"] == "suspended"
    # billing suspend + unsuspend never clears the abuse suspension
    client.post(f"{S}/suspend")
    client.post(f"{S}/unsuspend")
    assert client.get(S).json()["status"] == "suspended"
    client.post(f"{A}/abuse/reports/{rid}/action", json={"action": "unsuspend"})
    assert client.get(S).json()["status"] != "suspended"
    st = client.get(f"/public/v1/abuse/reports/{out['ticket']}?token={out['status_token']}").json()
    assert st["status"] == "actioned" and st["public_note"] == "removed"
    with SessionLocal() as db:
        actions = {a.action for a in db.scalars(select(AuditLog))}
        assert {"abuse.suspend", "abuse.unsuspend", "abuse.notify"} <= actions


def test_overdue_alert_and_retention(client, abuse_on, alert_settings, monkeypatch):
    mk_site(client)
    report(client, solved(client), urls=["https://example.com/p"])
    rid = client.get(f"{A}/abuse/reports").json()["reports"][0]["id"]
    client.post(f"{A}/abuse/reports/{rid}/notify", json={"deadline_hours": 1})
    with SessionLocal() as db:
        r = db.get(AbuseReport, rid)
        r.deadline_at = utcnow() - timedelta(minutes=1)
        db.commit()
        abuse.check(db)
    from app import alerts

    assert f"abuse_overdue:{rid}" in {c["key"] for c in alerts.open_alerts()}
    client.post(f"{A}/abuse/reports/{rid}/action", json={"action": "close"})
    assert f"abuse_overdue:{rid}" not in {c["key"] for c in alerts.open_alerts()}
    with SessionLocal() as db:
        r = db.get(AbuseReport, rid)
        r.closed_at = utcnow() - timedelta(days=400)
        r.created_at = utcnow() - timedelta(days=400)
        db.commit()
        abuse.check(db)
        db.expire_all()
        r = db.get(AbuseReport, rid)
        assert r.reporter_email_stored is None and r.reporter_ip_hash is None


def test_admin_server_side_submit_uses_reporter_ip_header(client, abuse_on):
    ch = solved(client)
    r = client.post(f"{A}/abuse/reports", headers={"X-PCDN-Reporter-IP": "198.51.100.7"}, json={
        "category": "spam", "urls": ["https://x.example.org"], "challenge": ch})
    assert r.status_code == 201
    with SessionLocal() as db:
        row = db.scalar(select(AbuseReport))
        assert row.reporter_ip_hash and "198.51.100.7" not in json.dumps(
            [row.reporter_ip_hash, row.description, row.urls])
