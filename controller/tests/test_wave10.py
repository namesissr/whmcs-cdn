"""SPEC §18 controller side (wave 10): waiting room, access (protected paths + one-time codes),
monthly statements, audit export, error tracking (scrubber, client errors, edge errors_last_hour)."""

import csv
import hashlib
import hmac
import io
import json
import struct
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from app import access, alerts, errortrack, routes_capi, sections, site_secrets, statements, waiting_room
from app.config import settings
from app.db import SessionLocal
from app.models import AccessOtp, AuditLog, Edge, Site, UsageHourly, utcnow
from tests.test_api import add_edge, edge_get

S = "/api/v1/sites/example.com"
CAPI = "/capi/v1"


@pytest.fixture(autouse=True)
def _reset_rate():
    routes_capi._hits.clear()
    routes_capi._config_hits.clear()
    yield
    routes_capi._hits.clear()
    routes_capi._config_hits.clear()


# ------------------------------------------------------------------ helpers

def mk_site(client, domain="example.com", active=True, **features):
    r = client.post("/api/v1/sites", json={"domain": domain, "origin_ip": "93.184.216.34",
                                           "plan": {"features": features}})
    assert r.status_code == 201, r.text
    if active:
        with SessionLocal() as db:
            site = db.scalar(select(Site).where(Site.domain == domain))
            site.status = "active"
            db.commit()


def auth(token):
    return {"Authorization": f"Bearer {token}"}


def heartbeat(client, token, **body):
    r = client.post("/edge/v1/heartbeat", json={"applied_version": "v", **body}, headers=auth(token))
    assert r.status_code == 200, r.text
    return r


def edge_site(client, token, domain="example.com"):
    cfg = edge_get(client, token, "/edge/v1/config").json()
    return next(s for s in cfg["sites"] if s["domain"] == domain)


def hour_now():
    return datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)


def post_usage(client, token, host="example.com", hour=None, **extra):
    item = {"host": host, "hour": (hour or hour_now()).isoformat(), "bytes": 1000, "requests": 10, **extra}
    return client.post("/edge/v1/usage", json={"items": [item]}, headers=auth(token))


def details(domain="example.com"):
    with SessionLocal() as db:
        site = db.scalar(select(Site).where(Site.domain == domain))
        return [json.loads(r.details) for r in db.scalars(select(UsageHourly).where(UsageHourly.site_id == site.id))]


def new_key(client, scopes=("stats", "config")):
    r = client.post(f"{S}/apikeys", json={"name": "k", "scopes": list(scopes)})
    assert r.status_code == 201, r.text
    return r.json()["key"]


def stored_secret(key, domain="example.com"):
    with SessionLocal() as db:
        site = db.scalar(select(Site).where(Site.domain == domain))
        raw = json.loads(site.integration_secrets or "{}").get(key)
        return raw, site_secrets.get_secret(site, key)


WR = {"enabled": True, "max_active": 100, "paths": ["/", "/shop"], "session_minutes": 15,
      "queue_page": {"title_fa": "صف", "message_en": "Please wait"},
      "bypass": {"paths": ["/api/"], "ips": ["10.1.2.3/16"]}}

APPS = [{"id": "admin", "name": "Admin", "paths": ["/admin"], "methods": "otp",
         "emails": ["Alice@Example.com", "@company.com"]},
        {"id": "wiki", "name": "Wiki", "paths": ["/wiki", "/docs/"], "methods": "otp_or_ip",
         "emails": ["bob@x.io"], "ips": ["5.6.7.0/24"], "session_hours": 48}]


# ================================================================== waiting room (SPEC §18.1)

def test_waiting_room_plan_gating_and_defaults(client):
    mk_site(client)
    r = client.get(f"{S}/config/waiting_room")
    assert r.status_code == 200
    assert r.json() == {"enabled": False, "mode": "queue", "paths": ["/"], "max_active": 1000, "session_minutes": 10,
                        "queue_page": {"title_fa": "", "title_en": "", "message_fa": "", "message_en": ""},
                        "bypass": {"verified_bots": True, "paths": [], "ips": []}}
    # plan without the feature: enabling -> 403, the disabled shape is always accepted
    assert client.put(f"{S}/config/waiting_room", json=WR).status_code == 403
    assert client.put(f"{S}/config/waiting_room", json={**WR, "enabled": False}).status_code == 200
    assert client.patch(f"{S}/plan", json={"features": {"waiting_room": True}}).status_code == 200
    r = client.put(f"{S}/config/waiting_room", json=WR)
    assert r.status_code == 200, r.text
    assert r.json()["bypass"]["ips"] == ["10.1.0.0/16"]  # normalized


@pytest.mark.parametrize("bad", [
    {"max_active": 0}, {"max_active": 1_000_001}, {"session_minutes": 0}, {"session_minutes": 121},
    {"paths": []}, {"paths": ["nope"]}, {"paths": ["/__pcdn/x"]}, {"paths": ["/a*"]},
    {"paths": [f"/p{i}" for i in range(21)]}, {"mode": "block"}, {"queue_page": {"title_fa": "x" * 501}},
    {"queue_page": {"message_en": "a\x07b"}}, {"bypass": {"ips": ["300.1.1.1"]}}, {"bypass": {"ips": ["0.0.0.0/0"]}},
    {"bypass": {"ips": ["1.1.1.1"] * 51}}, {"bypass": {"paths": ["x"]}}, {"unknown": 1},
])
def test_waiting_room_validation(client, bad):
    mk_site(client, waiting_room=True)
    assert client.put(f"{S}/config/waiting_room", json={**WR, **bad}).status_code == 422


def test_waiting_room_secret_and_edge_block_node_max(client):
    mk_site(client, waiting_room=True)
    t1 = add_edge(client, "e1", "5.160.1.10")
    t2 = add_edge(client, "e2", "5.160.1.11")
    t3 = add_edge(client, "e3", "5.160.1.12")
    for t in (t1, t2):
        heartbeat(client, t)
    assert client.put(f"{S}/config/waiting_room", json=WR).status_code == 200
    raw, secret = stored_secret("waiting_room")
    assert len(secret) == 64 and int(secret, 16) >= 0
    wr = edge_site(client, t1)["waiting_room"]
    assert wr["enabled"] is True and wr["secret"] == secret
    assert wr["node_max"] == 50  # ceil(100 / 2 online edges)
    assert wr["paths"] == ["/", "/shop"] and wr["bypass"] == {"verified_bots": True, "paths": ["/api/"],
                                                               "ips": ["10.1.0.0/16"]}
    assert wr["queue_page"]["title_fa"] == "صف"
    heartbeat(client, t3)
    assert edge_site(client, t1)["waiting_room"]["node_max"] == 34  # ceil(100 / 3)
    # the secret is not exposed by the section GET / site object
    assert secret not in client.get(f"{S}/config").text
    assert secret not in client.get(S).text
    # saving again keeps the secret
    assert client.put(f"{S}/config/waiting_room", json={**WR, "max_active": 7}).status_code == 200
    assert stored_secret("waiting_room")[1] == secret
    assert edge_site(client, t1)["waiting_room"]["node_max"] == 3


def test_waiting_room_node_max_math():
    assert waiting_room.node_max(100, 3) == 34
    assert waiting_room.node_max(1, 5) == 1
    assert waiting_room.node_max(10, 0) == 10
    assert waiting_room.node_max(1_000_000, 7) == 142858


def test_waiting_room_folded_off(client):
    mk_site(client, waiting_room=True)
    t = add_edge(client)
    heartbeat(client, t)
    client.put(f"{S}/config/waiting_room", json=WR)
    assert edge_site(client, t)["waiting_room"]["enabled"] is True
    client.put(f"{S}/config/waiting_room", json={**WR, "mode": "off"})
    assert edge_site(client, t)["waiting_room"]["enabled"] is False
    client.put(f"{S}/config/waiting_room", json=WR)
    client.patch(f"{S}/plan", json={"features": {"waiting_room": False}})
    assert edge_site(client, t)["waiting_room"]["enabled"] is False
    client.patch(f"{S}/plan", json={"features": {"waiting_room": True}})
    client.post(f"{S}/suspend")
    assert edge_site(client, t)["waiting_room"]["enabled"] is False


def test_waiting_room_usage_heartbeat_and_stats(client):
    mk_site(client, waiting_room=True)
    t1, t2 = add_edge(client, "e1", "5.160.1.10"), add_edge(client, "e2", "5.160.1.11")
    client.put(f"{S}/config/waiting_room", json=WR)
    wr1 = {"admitted": 10, "queued": 4, "max_wait_s": 30, "peak_active": 20}
    assert post_usage(client, t1, waiting_room=wr1).status_code == 200
    assert post_usage(client, t1, waiting_room={"admitted": 5, "queued": 1, "max_wait_s": 12,
                                                "peak_active": 25}).status_code == 200
    assert post_usage(client, t2, waiting_room={"admitted": 1, "queued": 0, "max_wait_s": 90,
                                                "peak_active": 3, "junk": 1}).status_code == 200
    rows = [d["waiting_room"] for d in details()]
    assert {"admitted": 15, "queued": 5, "max_wait_s": 30, "peak_active": 25} in rows
    # bad counters -> 422 (like every usage counter)
    for bad in ({"admitted": -1}, {"queued": "x"}, {"max_wait_s": 10**9}, {"peak_active": 1.5}):
        assert post_usage(client, t1, waiting_room=bad).status_code == 422
    heartbeat(client, t1, waiting_room={"example.com": {"active": 40, "queued": 7}, "other.com": {"active": 1}})
    heartbeat(client, t2, waiting_room={"EXAMPLE.com.": {"active": 2, "queued": 1}, "bad host!": {"active": 1},
                                        "x.com": {"active": -1}, "y.com": "nope"})
    with SessionLocal() as db:
        e2 = db.scalar(select(Edge).where(Edge.name == "e2"))
        assert json.loads(e2.waiting_room)["sites"] == {"example.com": {"active": 2, "queued": 1}}
    r = client.get(f"{S}/waiting-room")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["enabled"] is True and body["active_estimate"] == 42 and body["queued_estimate"] == 8
    assert body["edges_reporting"] == 2 and body["serving_edges"] == 2 and body["node_max"] == 50
    assert body["last_hour"] == {"admitted": 16, "queued": 5, "max_wait_s": 90, "peak_active": 28}
    assert len(body["hourly"]) == 24 and body["hourly"][-1]["t"].endswith(":00:00Z")
    assert client.get(f"{S}/waiting-room?hours=0").status_code == 422
    # a malformed heartbeat block never fails the heartbeat
    heartbeat(client, t1, waiting_room="garbage", errors_last_hour="x")
    # stale heartbeats are not counted
    with SessionLocal() as db:
        for e in db.scalars(select(Edge)):
            e.last_seen_at = utcnow() - timedelta(hours=1)
        db.commit()
    assert client.get(f"{S}/waiting-room").json()["active_estimate"] == 0
    # capi (scope stats)
    key = new_key(client, ("stats",))
    assert client.get(f"{CAPI}/waiting-room", headers=auth(key)).status_code == 200
    key2 = new_key(client, ("config",))
    assert client.get(f"{CAPI}/waiting-room", headers=auth(key2)).status_code == 403


def test_heartbeat_bounded_sites():
    many = {f"s{i}.com": {"active": 1, "queued": 0} for i in range(1500)}
    assert len(waiting_room.clean_heartbeat(many)) == waiting_room.HEARTBEAT_MAX_SITES
    assert waiting_room.clean_heartbeat({"a.com": {"active": True}}) == {}
    assert waiting_room.clean_heartbeat([1, 2]) == {}


# ================================================================== access (SPEC §18.2)

SECRET = bytes(range(32)).hex()
# fixed vectors for the edge's implementation: (app, email, window, code)
VECTORS = [
    ("admin", "alice@example.com", 5000000, "412921"),
    ("admin", "Alice@Example.com", 5000000, "412921"),  # e-mail lower-cased
    ("admin", "alice@example.com", 4999999, "512275"),
    ("wiki", "bob@company.com", 5872320, "291143"),
    ("a", "x@y.io", 0, "921788"),
]


def _independent_code(secret_hex, app, email, window):
    d = hmac.new(bytes.fromhex(secret_hex), f"otp|{app}|{email.lower()}|{window}".encode(), hashlib.sha256).digest()
    off = d[-1] & 15
    return "%06d" % ((struct.unpack(">I", d[off:off + 4])[0] & 0x7FFFFFFF) % 1000000)


@pytest.mark.parametrize("app_id,email,window,code", VECTORS)
def test_otp_code_vectors(app_id, email, window, code):
    assert access.otp_code(SECRET, app_id, email, window) == code
    assert _independent_code(SECRET, app_id, email, window) == code


def test_otp_verify_windows():
    t = 5000000 * 300 + 10
    code = access.otp_code(SECRET, "admin", "a@b.com", 5000000)
    assert access.verify_code(SECRET, "admin", "a@b.com", code, t)
    assert access.verify_code(SECRET, "admin", "a@b.com", code, t + 300)  # previous window still accepted
    assert not access.verify_code(SECRET, "admin", "a@b.com", code, t + 600)
    assert not access.verify_code(SECRET, "wiki", "a@b.com", code, t)
    assert access.otp_code("ff" * 32, "admin", "alice@example.com", 5000000) == "900693"


def test_email_allowed():
    app = {"emails": ["alice@example.com", "@company.com"]}
    assert access.email_allowed(app, "ALICE@example.com")
    assert access.email_allowed(app, "x@company.com")
    assert not access.email_allowed(app, "x@sub.company.com")
    assert not access.email_allowed(app, "x@evilcompany.com")
    assert not access.email_allowed(app, "bob@example.com")


def test_access_section_gating_and_validation(client):
    mk_site(client)
    body = {"enabled": True, "apps": APPS}
    assert client.put(f"{S}/config/access", json=body).status_code == 403
    assert client.put(f"{S}/config/access", json={"enabled": False, "apps": APPS}).status_code == 200
    client.patch(f"{S}/plan", json={"features": {"access": True}})
    r = client.put(f"{S}/config/access", json=body)
    assert r.status_code == 200, r.text
    assert r.json()["apps"][0]["emails"] == ["alice@example.com", "@company.com"]
    assert r.json()["apps"][1]["session_hours"] == 48 and r.json()["apps"][0]["session_hours"] == 24
    base = APPS[0]
    bad_apps = [
        [base, dict(APPS[1], paths=["/admin/x"])],             # overlap with another app
        [base, dict(APPS[1], paths=["/adm"])],                 # string prefix overlap
        [base, dict(base)],                                    # duplicate id
        [dict(base, id="Bad_ID")], [dict(base, paths=[])], [dict(base, paths=["/__pcdn/access"])],
        [dict(base, emails=[])], [dict(base, emails=["not-an-email"])], [dict(base, emails=["@"])],
        [dict(base, methods="ip", ips=[])], [dict(base, methods="otp_or_ip", emails=[], ips=[])],
        [dict(base, ips=["::/0"])], [dict(base, session_hours=0)], [dict(base, session_hours=721)],
        [dict(base, methods="password")], [dict(base, name="")], [dict(base, emails=[f"u{i}@x.io" for i in range(201)])],
        [dict(base, id=f"a{i}", paths=[f"/p{i}"]) for i in range(21)],
    ]
    for apps in bad_apps:
        assert client.put(f"{S}/config/access", json={"enabled": True, "apps": apps}).status_code == 422, apps
    # same-app paths may nest (deduplicated)
    assert client.put(f"{S}/config/access", json={"enabled": True, "apps": [
        dict(base, paths=["/a", "/a", "/a/b"])]}).json()["apps"][0]["paths"] == ["/a", "/a/b"]


def test_access_secret_edge_block_and_rotate(client):
    mk_site(client, access=True)
    t = add_edge(client)
    heartbeat(client, t)
    assert client.put(f"{S}/config/access", json={"enabled": True, "apps": APPS}).status_code == 200
    raw, secret = stored_secret("access")
    assert len(secret) == 64 and raw
    blk = edge_site(client, t)["access"]
    assert blk["enabled"] is True and blk["secret"] == secret
    assert [a["id"] for a in blk["apps"]] == ["admin", "wiki"]
    assert blk["apps"][1] == {"id": "wiki", "name": "Wiki", "paths": ["/wiki", "/docs/"], "methods": "otp_or_ip",
                              "emails": ["bob@x.io"], "ips": ["5.6.7.0/24"], "session_hours": 48}
    assert secret not in client.get(f"{S}/config/access").text
    r = client.post(f"{S}/access/rotate")
    assert r.status_code == 200 and secret not in r.text and r.json()["ok"] is True
    new = stored_secret("access")[1]
    assert new != secret and len(new) == 64
    assert edge_site(client, t)["access"]["secret"] == new
    with SessionLocal() as db:
        assert db.scalar(select(AuditLog).where(AuditLog.action == "access.rotate")) is not None
    # plan loses the feature: off on the edge, rotate refused
    client.patch(f"{S}/plan", json={"features": {"access": False}})
    assert edge_site(client, t)["access"] == {"enabled": False, "apps": [], "secret": ""}
    assert client.post(f"{S}/access/rotate").status_code == 403


def test_access_secret_encrypted_at_rest(client, monkeypatch):
    from cryptography.fernet import Fernet

    from app import crypto

    monkeypatch.setattr(settings, "data_encryption_key", Fernet.generate_key().decode())
    mk_site(client, access=True, waiting_room=True)
    client.put(f"{S}/config/access", json={"enabled": True, "apps": APPS})
    client.put(f"{S}/config/waiting_room", json=WR)
    for key in ("access", "waiting_room"):
        raw, plain = stored_secret(key)
        assert crypto.is_encrypted(raw) and plain not in raw and len(plain) == 64


def test_access_capi_rotate_scope_and_suspended(client):
    mk_site(client, access=True)
    client.put(f"{S}/config/access", json={"enabled": True, "apps": APPS})
    stats_key = new_key(client, ("stats",))
    cfg_key = new_key(client, ("config",))
    assert client.post(f"{CAPI}/access/rotate", headers=auth(stats_key)).status_code == 403
    assert client.post(f"{CAPI}/access/rotate", headers=auth(cfg_key)).status_code == 200
    client.post(f"{S}/suspend")
    assert client.post(f"{CAPI}/access/rotate", headers=auth(cfg_key)).status_code == 403
    assert client.get(f"{CAPI}/access/log", headers=auth(stats_key)).status_code == 200


@pytest.fixture()
def mailbox(monkeypatch):
    sent = []
    monkeypatch.setattr(settings, "smtp_host", "smtp.test")
    monkeypatch.setattr(alerts, "send_mail", lambda to, subject, body, sender="": sent.append((to, subject, body)))
    return sent


def otp(client, token, email="alice@example.com", app="admin", domain="example.com"):
    return client.post("/edge/v1/access/otp", json={"domain": domain, "app": app, "email": email},
                       headers=auth(token))


def test_access_otp_sends_code(client, mailbox, caplog):
    mk_site(client, access=True)
    t = add_edge(client)
    heartbeat(client, t)
    client.put(f"{S}/config/access", json={"enabled": True, "apps": APPS})
    secret = stored_secret("access")[1]
    r = otp(client, t, email="  Alice@Example.COM ")
    assert r.status_code == 200, r.text
    assert r.json()["ok"] is True and 300 < r.json()["expires_in"] <= 600
    assert "code" not in r.text
    to, subject, body = mailbox[0]
    assert to == "alice@example.com" and "example.com" in subject
    w = access.otp_window()
    codes = {access.otp_code(secret, "admin", "alice@example.com", x) for x in (w, w - 1)}
    assert any(c in body for c in codes)
    assert "کد ورود" in body and "sign-in code" in body and "Admin" in body and secret not in body
    code = next(c for c in codes if c in body)
    assert code not in caplog.text
    with SessionLocal() as db:
        a = db.scalar(select(AuditLog).where(AuditLog.action == "access.otp_sent"))
        assert a.target == "example.com" and a.actor_kind == "edge"
        d = json.loads(a.detail)
        assert d == {"app": "admin", "email_ref": access.email_ref("alice@example.com")}
        assert "alice" not in a.detail and code not in a.detail
        assert db.scalar(select(AccessOtp)).email_hash == access.email_ref("alice@example.com")
    # @domain entry
    assert otp(client, t, email="carol@company.com").status_code == 200


def test_access_otp_errors(client, mailbox, monkeypatch):
    mk_site(client, access=True)
    mk_site(client, "other.com", access=True)
    t = add_edge(client)
    heartbeat(client, t)
    client.put(f"{S}/config/access", json={"enabled": True, "apps": APPS + [
        {"id": "ips", "name": "IPs", "paths": ["/ip"], "methods": "ip", "ips": ["1.2.3.4"]}]})
    assert otp(client, "nope").status_code == 401
    assert otp(client, t, domain="missing.com").status_code == 404
    assert otp(client, t, app="nope").status_code == 404
    assert otp(client, t, app="ips").status_code == 403
    assert otp(client, t, email="eve@example.com").status_code == 403
    assert otp(client, t, email="x@sub.company.com").status_code == 403
    assert otp(client, t, email="not an email").status_code == 422
    assert otp(client, t, domain="other.com").status_code == 403  # access not enabled there
    assert client.post("/edge/v1/access/otp", json={"domain": "example.com"}, headers=auth(t)).status_code == 422
    # a tunnel-group edge does not serve a general site while the general group has an online edge
    tt = add_edge(client, "tun-1", "5.160.2.10")
    client.patch("/api/v1/edges/" + str(_edge_id("tun-1")), json={"group": "tunnel"})
    heartbeat(client, tt)
    assert otp(client, tt).status_code == 403
    # no SMTP -> 503
    monkeypatch.setattr(settings, "smtp_host", "")
    assert otp(client, t).status_code == 503
    monkeypatch.setattr(settings, "smtp_host", "smtp.test")
    # delivery failure -> 503 (and still counted)
    def fail(*a, **k):
        raise alerts.AlertError("down")
    monkeypatch.setattr(alerts, "send_mail", fail)
    assert otp(client, t).status_code == 503
    # suspended site
    client.post(f"{S}/suspend")
    assert otp(client, t).status_code == 403
    assert mailbox == []


def _edge_id(name):
    with SessionLocal() as db:
        return db.scalar(select(Edge.id).where(Edge.name == name))


def test_access_otp_rate_limits(client, mailbox, monkeypatch):
    mk_site(client, access=True)
    t = add_edge(client)
    heartbeat(client, t)
    client.put(f"{S}/config/access", json={"enabled": True, "apps": APPS})
    for _ in range(5):
        assert otp(client, t).status_code == 200
    r = otp(client, t)
    assert r.status_code == 429 and 0 < int(r.headers["Retry-After"]) <= 3600
    # per e-mail: a different address still works; the site limit applies to all addresses
    monkeypatch.setattr(settings, "access_otp_per_site_hour", 8)
    for i in range(3):
        assert otp(client, t, email=f"u{i}@company.com").status_code == 200
    assert otp(client, t, email="u9@company.com").status_code == 429
    assert len(mailbox) == 8
    # an hour later the window is free again
    with SessionLocal() as db:
        for row in db.scalars(select(AccessOtp)):
            row.at -= timedelta(minutes=61)
        db.commit()
    assert otp(client, t).status_code == 200


def test_access_usage_and_log(client):
    mk_site(client, access=True)
    t = add_edge(client)
    client.put(f"{S}/config/access", json={"enabled": True, "apps": APPS})
    now = datetime.now(timezone.utc)
    evs = [{"t": (now - timedelta(minutes=i)).isoformat(), "app": "admin", "email_hash": "ab" * 8, "ok": i % 2 == 0}
           for i in range(60)]
    evs += [{"t": now.isoformat(), "app": "BAD", "email_hash": "ab" * 8, "ok": True},
            {"t": now.isoformat(), "app": "admin", "email_hash": "zz", "ok": True}, "junk"]
    r = post_usage(client, t, access={"ok": 3, "fail": 1, "otp": 2}, access_events=evs)
    assert r.status_code == 200, r.text
    r = post_usage(client, t, access={"ok": 1, "fail": 0, "otp": 0},
                   access_events=[{"t": now.isoformat(), "app": "wiki", "email_hash": "cd" * 8, "ok": True}])
    assert r.status_code == 200
    d = details()[0]
    assert d["access"] == {"ok": 4, "fail": 1, "otp": 2}
    assert len(d["access_events"]) == 51  # 50 of the first item + 1
    assert post_usage(client, t, access={"ok": -1}).status_code == 422
    log = client.get(f"{S}/access/log").json()
    assert log["enabled"] is True and log["apps"] == ["admin", "wiki"]
    assert log["last_24h"] == {"ok": 4, "fail": 1, "otp": 2}
    assert len(log["events"]) == 51 and log["events"][0]["t"] >= log["events"][-1]["t"]
    assert set(log["events"][0]) == {"t", "app", "email_hash", "ok"}
    # bounded per row
    for _ in range(5):
        post_usage(client, t, access_events=evs[:50])
    assert len(details()[0]["access_events"]) == access.EVENTS_PER_ROW
    assert len(client.get(f"{S}/access/log?limit=1000").json()["events"]) == 200


# ================================================================== statements (SPEC §18.3)

def _seed_month(domain="example.com"):
    with SessionLocal() as db:
        site = db.scalar(select(Site).where(Site.domain == domain))
        e = Edge(name="seed", ipv4="5.160.9.9", token_hash="x" * 64)
        db.add(e)
        db.flush()
        det = {"tunnel": {"bytes_up": 2 * 1024**3, "bytes_down": 1024**3}, "l4": {"ssh": {"bytes_in": 1024**3,
                                                                                       "bytes_out": 0}},
               "functions": {"invocations": 42}, "security": {"waf": 5, "bots": 2}}
        for day, hour in ((1, 3), (1, 4), (15, 10)):
            db.add(UsageHourly(site_id=site.id, edge_id=e.id, hour=datetime(2026, 8, day, hour),
                               bytes=5 * 1024**3, requests=1000, cache_hits=250, details=json.dumps(det)))
        db.commit()


def test_statement_json_csv(client):
    mk_site(client)
    client.patch(f"{S}/plan", json={"bandwidth_limit_gb": 10})
    _seed_month()
    r = client.get(f"{S}/statement?month=2026-08&format=json&plan=Pro&block_gb=2")
    assert r.status_code == 200, r.text
    doc = r.json()
    assert doc["month"] == "2026-08" and doc["complete"] is True and doc["month_to_date"] is False
    assert len(doc["days"]) == 31
    assert doc["days"][0] == {"date": "2026-08-01", "gb": 10.0, "bytes": 10 * 1024**3, "requests": 2000,
                              "cache_hits": 500, "cache_hit_ratio": 25.0}
    assert doc["totals"]["gb"] == 15.0 and doc["totals"]["requests"] == 3000
    assert doc["tunnel_gb"] == 9.0 and doc["l4_gb"] == 3.0 and doc["functions_invocations"] == 126
    assert doc["security"] == {"bots": 6, "waf": 15} and doc["security_total"] == 21
    assert doc["quota"] == {"limit_gb": 10, "used_gb": 15.0, "overage_gb": 5.0, "block_gb": 2.0, "blocks": 3}
    assert doc["plan"]["name"] == "Pro"
    assert "ip" not in json.dumps(doc).lower().replace("ship", "")  # no customer IPs anywhere
    r = client.get(f"{S}/statement?month=2026-08&format=csv&lang=fa")
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/csv")
    assert r.content.startswith(b"\xef\xbb\xbf")
    rows = list(csv.reader(io.StringIO(r.content.decode("utf-8-sig"))))
    assert rows[0] == ["سرویس", "example.com"]
    assert ["2026-08-01", "10.000", "2000", "25.00"] in rows
    assert 'filename="statement-example.com-2026-08.csv"' in r.headers["content-disposition"]
    en = client.get(f"{S}/statement?month=2026-08&format=csv&lang=en").content.decode("utf-8-sig")
    assert "Traffic (GB)" in en and "Total,15.000,3000,25.00" in en


def test_statement_validation_and_current_month(client):
    mk_site(client)
    nxt = (utcnow().replace(day=28) + timedelta(days=5)).strftime("%Y-%m")
    assert client.get(f"{S}/statement?month={nxt}").status_code == 422
    assert client.get(f"{S}/statement?month=2026-13").status_code == 422
    assert client.get(f"{S}/statement?month=junk").status_code == 422
    assert client.get(f"{S}/statement?format=xml").status_code == 422
    assert client.get(f"{S}/statement?lang=de").status_code == 422
    assert client.get(f"{S}/statement?block_gb=0").status_code == 422
    assert client.get(f"{S}/statement?plan=" + "x" * 101).status_code == 422
    doc = client.get(f"{S}/statement").json()
    assert doc["month"] == utcnow().strftime("%Y-%m") and doc["month_to_date"] is True
    assert len(doc["days"]) == utcnow().day
    assert client.get("/api/v1/sites/nope.com/statement").status_code == 404


@pytest.mark.parametrize("lang", ["fa", "en"])
def test_statement_pdf(client, lang):
    mk_site(client)
    _seed_month()
    r = client.get(f"{S}/statement?month=2026-08&format=pdf&lang={lang}")
    assert r.status_code == 200, r.text
    assert r.headers["content-type"] == "application/pdf"
    pdf = r.content
    assert pdf.startswith(b"%PDF") and len(pdf) < 2 * 1024 * 1024
    assert b"Vazirmatn" in pdf  # the bundled font is embedded
    # deterministic for the same data
    assert client.get(f"{S}/statement?month=2026-08&format=pdf&lang={lang}").content == pdf


def test_statement_font_files_and_licence():
    import os

    for f in ("Vazirmatn-Regular.ttf", "Vazirmatn-Bold.ttf", "OFL.txt"):
        assert os.path.getsize(os.path.join(statements.FONT_DIR, f)) > 1000
    assert "SIL OPEN FONT LICENSE" in open(os.path.join(statements.FONT_DIR, "OFL.txt")).read()


def test_statement_capi(client):
    mk_site(client)
    _seed_month()
    key = new_key(client, ("stats",))
    r = client.get(f"{CAPI}/statement?month=2026-08&format=json", headers=auth(key))
    assert r.status_code == 200 and r.json()["totals"]["gb"] == 15.0
    assert client.get(f"{CAPI}/statement", headers=auth(new_key(client, ("config",)))).status_code == 403


# ================================================================== audit export (SPEC §18.3)

def _audit(n, target="example.com", actor_kind="admin", actor="admin", action="config.update", at=None):
    with SessionLocal() as db:
        for i in range(n):
            db.add(AuditLog(actor=actor, actor_kind=actor_kind, action=action, target=target,
                            detail=json.dumps({"section": "cache"}), ip="198.51.100.7", at=at or utcnow()))
        db.commit()


def test_site_audit_export(client):
    mk_site(client)
    mk_site(client, "other.com")
    _audit(2)
    _audit(1, actor_kind="capi", actor="my-ci-key-with-a-long-name-here")
    _audit(1, actor_kind="edge", actor="ir-thr-secret-node", action="access.otp_sent")
    _audit(3, target="other.com")
    _audit(1, at=utcnow() - timedelta(days=60))
    r = client.get(f"{S}/audit")
    assert r.status_code == 200
    body = r.json()
    items = [i for i in body["items"] if i["action"] in ("config.update", "access.otp_sent")]
    actors = {i["actor"] for i in items}
    assert actors == {"admin", "capi:my-ci-key-with-a-long-na", "edge"}
    assert all(i["target"] == "example.com" for i in body["items"])
    assert "198.51.100.7" not in r.text and "ir-thr" not in r.text
    assert len(items) == 4  # the 60-day-old entry is outside the default 30 days
    old = client.get(f"{S}/audit?from=" + (utcnow() - timedelta(days=90)).isoformat() + "Z").json()
    assert len([i for i in old["items"] if i["action"] == "config.update"]) == 4
    r = client.get(f"{S}/audit?format=csv")
    assert r.content.startswith(b"\xef\xbb\xbf") and r.headers["content-type"].startswith("text/csv")
    rows = list(csv.reader(io.StringIO(r.content.decode("utf-8-sig"))))
    assert rows[0] == ["at", "actor", "action", "target", "detail"]
    assert client.get(f"{S}/audit?format=xml").status_code == 422
    assert client.get(f"{S}/audit?from=junk").status_code == 422
    assert client.get(f"{S}/audit?from=2026-09-10T00:00:00Z&to=2026-09-01T00:00:00Z").status_code == 422
    key = new_key(client, ("stats",))
    r = client.get(f"{CAPI}/audit?format=csv", headers=auth(key))
    assert r.status_code == 200 and b"other.com" not in r.content


def test_admin_audit_export_cap(client, monkeypatch):
    from app import routes_reports

    monkeypatch.setattr(routes_reports, "AUDIT_EXPORT_MAX", 5)
    _audit(7, target="a.com")
    r = client.get("/api/v1/audit/export")
    assert r.status_code == 200 and r.headers["x-pcdn-truncated"] == "true"
    rows = list(csv.reader(io.StringIO(r.content.decode("utf-8-sig"))))
    assert rows[0] == ["id", "at", "actor_kind", "actor", "action", "target", "detail", "ip"]
    assert len(rows) == 6 and rows[1][7] == "198.51.100.7"
    assert client.get("/api/v1/audit/export?format=json").json()["truncated"] is True
    assert client.get("/api/v1/audit/export", headers={"Authorization": "Bearer nope"}).status_code == 401


# ================================================================== error tracking (SPEC §18.4)

def test_scrubber():
    event = {
        "request": {"url": "https://cdn.example/api/v1/sites?token=abc", "query_string": "token=abc",
                    "headers": {"Authorization": "Bearer s3cr3t", "Cookie": "a=b", "X-Edge-Token": "t",
                                "X-Api-Key": "k", "User-Agent": "ua", "Content-Type": "json"},
                    "data": {"password": "p"}, "cookies": {"a": "b"}, "env": {"REMOTE_ADDR": "1.2.3.4"}},
        "user": {"ip_address": "1.2.3.4"},
        "extra": {"admin_api_key": "zzz", "note": "login with password=hunter2 failed",
                  "url": "see https://x.example/p?sig=deadbeef#f", "nested": {"secret_key": "abc", "ok": "fine"}},
        "exception": {"values": [{"value": "Authorization: Bearer abc.def failed for pcdn_0123456789abcdef",
                                  "stacktrace": {"frames": [{"vars": {"token": "t0k", "n": 1}}]}}]},
        "breadcrumbs": {"values": [{"message": "GET https://h/x?api_key=1"}]},
    }
    out = errortrack.scrub_event(event)
    s = json.dumps(out)
    for leaked in ("s3cr3t", "token=abc", "hunter2", "zzz", "deadbeef", "pcdn_0123", "t0k", "1.2.3.4", "a=b",
                   "abc.def", "api_key=1", '"password": "p"'):
        assert leaked not in s, leaked
    req = out["request"]
    assert set(req["headers"]) == {"User-Agent", "Content-Type"}
    assert req["url"] == "https://cdn.example/api/v1/sites"
    assert "query_string" not in req and "data" not in req and "cookies" not in req and "user" not in out
    assert out["extra"]["nested"]["ok"] == "fine" and out["extra"]["nested"]["secret_key"] == "[Filtered]"
    assert "login with password=[Filtered] failed" == out["extra"]["note"]
    assert errortrack.scrub_event(None) is None
    pem = "x -----BEGIN PRIVATE KEY-----\nMIIabc\n-----END PRIVATE KEY----- y"
    assert "MIIabc" not in errortrack.scrub_string(pem)


def test_sentry_off_without_dsn(monkeypatch):
    monkeypatch.setattr(settings, "sentry_dsn", "")
    assert errortrack.init_sentry() is False


def test_sentry_init_with_dsn(monkeypatch):
    sentry_sdk = pytest.importorskip("sentry_sdk")
    calls = {}
    monkeypatch.setattr(settings, "sentry_dsn", "https://public@sentry.example/1")
    monkeypatch.setattr(sentry_sdk, "init", lambda **kw: calls.update(kw))
    try:
        assert errortrack.init_sentry() is True
        assert calls["send_default_pii"] is False and calls["before_send"] is errortrack.scrub_event
        assert calls["dsn"] == "https://public@sentry.example/1"
    finally:
        monkeypatch.setattr(errortrack, "_enabled", False)


def test_client_errors_and_metric(client, monkeypatch):
    forwarded = []
    monkeypatch.setattr(errortrack, "forward_client_error", lambda page, data: forwarded.append((page, data)))
    body = {"message": "x is undefined", "source": "/modules/servers/x.js?token=abc", "line": 3, "col": 7,
            "stack": "at f (https://h/a.js?k=1)", "page": "Firewall", "ua": "Mozilla"}
    r = client.post("/api/v1/client-errors", json=body)
    assert r.status_code == 200 and r.json()["page"] == "firewall"
    client.post("/api/v1/client-errors", json={**body, "page": "<script>"})
    client.post("/api/v1/client-errors", json={**body, "page": "waiting-room"})
    assert forwarded[0][1]["source"] == "/modules/servers/x.js" and "k=1" not in forwarded[0][1]["stack"]
    assert [p for p, _ in forwarded] == ["firewall", "other", "waiting_room"]
    assert client.post("/api/v1/client-errors", json={"stack": "x" * 9000}).status_code == 422
    assert client.post("/api/v1/client-errors", json=body, headers={"Authorization": "Bearer no"}).status_code == 401
    m = client.get("/metrics").text
    assert 'pcdn_client_errors_total{page="firewall"} 1' in m
    assert 'pcdn_client_errors_total{page="other"} 1' in m
    assert "# TYPE pcdn_client_errors_total counter" in m and "script" not in m


def test_edge_errors_last_hour(client):
    t = add_edge(client)
    heartbeat(client, t, errors_last_hour=7)
    e = client.get("/api/v1/edges").json()[0]
    assert e["errors_last_hour"] == 7
    heartbeat(client, t, errors_last_hour=-3)  # ignored, never a 422
    heartbeat(client, t)
    assert client.get("/api/v1/edges").json()[0]["errors_last_hour"] == 7
    heartbeat(client, t, errors_last_hour=0)
    assert client.get("/api/v1/edges").json()[0]["errors_last_hour"] == 0


def test_send_mail_helper(monkeypatch):
    msgs = []
    monkeypatch.setattr(alerts, "smtp_send", lambda m: msgs.append(m))
    alerts.send_mail("a@b.com", "سلام", "متن", sender="x@y.com")
    assert msgs[0]["To"] == "a@b.com" and msgs[0]["From"] == "x@y.com"
    assert "متن" in msgs[0].get_content()


def test_features_and_sections_registered():
    assert sections.DEFAULT_FEATURES["waiting_room"] is False and sections.DEFAULT_FEATURES["access"] is False
    assert "waiting_room" in sections.SECTIONS and "access" in sections.SECTIONS
    assert set(site_secrets.SCALAR_KEYS) >= {"waiting_room", "access"}


def test_statement_pdf_without_shaping(client, monkeypatch):
    """Without uharfbuzz the PDF is still produced (unshaped)."""
    monkeypatch.setattr(statements, "SHAPING", False)
    mk_site(client)
    _seed_month()
    r = client.get(f"{S}/statement?month=2026-08&format=pdf&lang=fa")
    assert r.status_code == 200 and r.content.startswith(b"%PDF")


def test_new_secrets_follow_key_rotation(client, monkeypatch):
    """wr_secret / access_secret are re-encrypted with the other site secrets on key rotation."""
    from cryptography.fernet import Fernet

    from app import crypto

    k1, k2 = Fernet.generate_key().decode(), Fernet.generate_key().decode()
    monkeypatch.setattr(settings, "data_encryption_key", k1)
    mk_site(client, access=True)
    client.put(f"{S}/config/access", json={"enabled": True, "apps": APPS})
    before = stored_secret("access")
    monkeypatch.setattr(settings, "data_encryption_key", f"{k2},{k1}")
    with SessionLocal() as db:
        assert crypto.rotate_all(db) >= 1
    monkeypatch.setattr(settings, "data_encryption_key", k2)  # the old key is gone
    raw, plain = stored_secret("access")
    assert plain == before[1] and raw != before[0]
