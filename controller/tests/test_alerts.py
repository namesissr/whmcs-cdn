"""Telegram / e-mail alerts: channels, dedup + reminders + resolve, and the conditions the scheduler raises."""

import json
import logging
from datetime import timedelta
from email import message_from_bytes, policy

import httpx
import pytest

from app import alerts, scheduler
from app.db import SessionLocal
from app.models import Edge, Site, utcnow

TOKEN = "123456:SECRET-bot-token"


class FakeTelegram:
    def __init__(self, status=200):
        self.messages: list[dict] = []
        self.urls: list[str] = []
        self.status = status

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.urls.append(str(request.url))
        if self.status != 200:
            return httpx.Response(self.status, json={"ok": False, "description": "Bad Gateway"})
        self.messages.append(json.loads(request.content))
        return httpx.Response(200, json={"ok": True, "result": {"message_id": len(self.messages)}})

    @property
    def texts(self):
        return [m["text"] for m in self.messages]


@pytest.fixture()
def telegram(alert_settings, monkeypatch):
    fake = FakeTelegram()
    monkeypatch.setattr(alert_settings, "telegram_bot_token", TOKEN)
    monkeypatch.setattr(alert_settings, "telegram_chat_ids", ["-1001", "42"])
    monkeypatch.setattr(alert_settings, "telegram_api_url", "https://tg-relay.example.ir")
    monkeypatch.setattr(alerts, "telegram_transport", httpx.MockTransport(fake.handler))
    return fake


@pytest.fixture()
def clock(monkeypatch):
    """Controllable utcnow() for the alerts module."""
    state = {"now": utcnow()}
    monkeypatch.setattr(alerts, "utcnow", lambda: state["now"])

    def advance(**kw):
        state["now"] += timedelta(**kw)

    advance.now = lambda: state["now"]
    return advance


# ------------------------------------------------------------------ channels

def test_telegram_message_goes_to_every_chat_through_the_relay(client, telegram):
    res = alerts.send("critical", "همه نودها خاموش", "متن فارسی")
    assert res == {"telegram": "ok"}
    assert [m["chat_id"] for m in telegram.messages] == ["-1001", "42"]
    assert all(u.startswith(f"https://tg-relay.example.ir/bot{TOKEN}/sendMessage") for u in telegram.urls)
    text = telegram.messages[0]["text"]
    assert text.startswith("[Pasargad CDN] CRITICAL: همه نودها خاموش") and "[بحرانی] متن فارسی" in text


def test_telegram_failure_is_reported_without_the_token(client, telegram, caplog):
    caplog.set_level(logging.DEBUG, logger="httpx")  # httpx logs request URLs, which contain the token
    telegram.status = 502
    res = alerts.send("warning", "t", "b")
    assert res["telegram"].startswith("chat -1001: HTTP 502")
    assert TOKEN not in res["telegram"] and TOKEN not in caplog.text
    assert "/bot***/sendMessage" in caplog.text


def test_telegram_network_error_does_not_raise(client, alert_settings, monkeypatch, caplog):
    monkeypatch.setattr(alert_settings, "telegram_bot_token", TOKEN)
    monkeypatch.setattr(alert_settings, "telegram_chat_ids", ["1"])

    def boom(request):
        raise httpx.ConnectTimeout(f"timed out connecting to {request.url}")

    monkeypatch.setattr(alerts, "telegram_transport", httpx.MockTransport(boom))
    res = alerts.send("warning", "t", "b")
    assert "ConnectTimeout" in res["telegram"] and TOKEN not in res["telegram"] and TOKEN not in caplog.text


@pytest.fixture()
def smtp_server():
    aiosmtpd = pytest.importorskip("aiosmtpd.controller")

    class Handler:
        def __init__(self):
            self.messages = []

        async def handle_DATA(self, server, session, envelope):
            self.messages.append(envelope)
            return "250 OK"

    import socket

    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    handler = Handler()
    ctl = aiosmtpd.Controller(handler, hostname="127.0.0.1", port=port)
    ctl.start()
    yield port, handler
    ctl.stop()


def test_email_alert(client, alert_settings, monkeypatch, smtp_server):
    port, handler = smtp_server
    for k, v in {"smtp_host": "127.0.0.1", "smtp_port": port, "smtp_security": "none", "smtp_user": "",
                 "smtp_from": "cdn@pasargadmizban.com", "alert_emails": ["ops@example.com", "boss@example.com"]
                 }.items():
        monkeypatch.setattr(alert_settings, k, v)
    assert alerts.send("warning", "نود از دسترس خارج شد", "نود ir-thr-1 گزارشی نفرستاده است") == {"email": "ok"}
    (env,) = handler.messages
    assert sorted(env.rcpt_tos) == ["boss@example.com", "ops@example.com"]
    msg = message_from_bytes(env.content, policy=policy.default)
    assert msg["Subject"] == "[Pasargad CDN] WARNING: نود از دسترس خارج شد"
    assert "نود ir-thr-1 گزارشی نفرستاده است" in msg.get_content()


def test_email_unreachable_server_fails_fast(client, alert_settings, monkeypatch):
    monkeypatch.setattr(alert_settings, "smtp_host", "127.0.0.1")
    monkeypatch.setattr(alert_settings, "smtp_port", 1)  # nothing listens there
    monkeypatch.setattr(alert_settings, "smtp_security", "none")
    monkeypatch.setattr(alert_settings, "alert_emails", ["ops@example.com"])
    res = alerts.send("warning", "t", "b")
    assert "ConnectionRefusedError" in res["email"]


# ------------------------------------------------------------------ dedup / reminders / resolve

def test_condition_is_sent_once_then_reminded_then_resolved(client, telegram, clock):
    alerts.raise_alert("edge_offline:1", "نود خاموش", "متن", "warning")
    alerts.raise_alert("edge_offline:1", "نود خاموش", "متن", "warning")
    assert len(telegram.messages) == 2  # one message, two chats

    clock(hours=5)
    alerts.raise_alert("edge_offline:1", "نود خاموش", "متن", "warning")
    assert len(telegram.messages) == 2
    clock(hours=1, minutes=1)
    alerts.raise_alert("edge_offline:1", "نود خاموش", "متن", "warning")
    assert len(telegram.messages) == 4 and "یادآوری" in telegram.texts[-1]

    assert [c["key"] for c in alerts.open_alerts()] == ["edge_offline:1"]
    clock(minutes=30)
    alerts.resolve_alert("edge_offline:1", "دوباره آنلاین شد")
    assert len(telegram.messages) == 6
    assert "RESOLVED" in telegram.texts[-1] and "6 ساعت و 31 دقیقه" in telegram.texts[-1]
    assert alerts.open_alerts() == []
    alerts.resolve_alert("edge_offline:1")  # already closed: nothing sent
    assert len(telegram.messages) == 6


def test_reminders_can_be_disabled(client, telegram, clock, alert_settings, monkeypatch):
    monkeypatch.setattr(alert_settings, "alert_reminder_hours", 0)
    alerts.raise_alert("x", "t", "b")
    clock(days=3)
    alerts.raise_alert("x", "t", "b")
    assert len(telegram.messages) == 2


def test_failed_delivery_is_retried_later(client, telegram, clock):
    telegram.status = 500
    alerts.raise_alert("x", "t", "b")
    telegram.status = 200
    alerts.raise_alert("x", "t", "b")
    assert telegram.messages == []  # retry is rate limited
    clock(minutes=6)
    alerts.raise_alert("x", "t", "b")
    assert len(telegram.messages) == 2


def test_no_channel_configured_still_tracks_conditions(client, alert_settings):
    alerts.raise_alert("x", "t", "b", "critical")
    assert alerts.open_alerts()[0]["severity"] == "critical"
    alerts.resolve_alert("x")
    assert alerts.open_alerts() == []


# ------------------------------------------------------------------ conditions

def _edge(db, name, seen_ago=None, error=None, enabled=True):
    e = Edge(name=name, ipv4="5.160.1.10", token_hash=name * 4, enabled=enabled,
             last_seen_at=utcnow() - timedelta(seconds=seen_ago) if seen_ago is not None else None,
             last_error=error)
    db.add(e)
    db.commit()
    return e


def test_edge_offline_online_and_all_edges_offline(client, telegram):
    with SessionLocal() as db:
        a = _edge(db, "ir-1", seen_ago=10)
        b = _edge(db, "de-1", seen_ago=10)
        _edge(db, "never-seen")
        alerts.check_edges(db)
        assert alerts.open_alerts() == []

        b.last_seen_at = utcnow() - timedelta(hours=1)
        db.commit()
        alerts.check_edges(db)
        assert [c["key"] for c in alerts.open_alerts()] == [f"edge_offline:{b.id}"]
        assert "نود de-1 از دسترس خارج شد" in telegram.texts[-1]

        a.last_seen_at = utcnow() - timedelta(hours=1)
        db.commit()
        alerts.check_edges(db)
        keys = {c["key"] for c in alerts.open_alerts()}
        assert keys == {f"edge_offline:{a.id}", f"edge_offline:{b.id}", "all_edges_offline"}
        assert "CRITICAL" in telegram.texts[-1]
        sent = len(telegram.messages)
        alerts.check_edges(db)  # nothing new
        assert len(telegram.messages) == sent

        b.last_seen_at = utcnow()
        db.commit()
        alerts.check_edges(db)
        assert {c["key"] for c in alerts.open_alerts()} == {f"edge_offline:{a.id}"}
        resolved = [t for t in telegram.texts[sent:] if "RESOLVED" in t]
        assert any("de-1 دوباره آنلاین شد" in t and "مدت:" in t for t in resolved)
        assert any("دست‌کم یک نود" in t for t in resolved)

        db.delete(db.get(Edge, a.id))  # a deleted edge closes its condition
        db.commit()
        alerts.check_edges(db)
        assert alerts.open_alerts() == []


def test_edge_config_error_set_and_cleared(client, telegram):
    with SessionLocal() as db:
        e = _edge(db, "ir-1", seen_ago=5, error="nginx -t failed: unknown directive")
        alerts.check_edges(db)
        assert [c["key"] for c in alerts.open_alerts()] == [f"edge_error:{e.id}"]
        assert "unknown directive" in telegram.texts[-1]
        e.last_error = None
        db.commit()
        alerts.check_edges(db)
        assert alerts.open_alerts() == [] and "RESOLVED" in telegram.texts[-1]


def test_pdns_unreachable_and_dns_sync_failures(client, telegram, fake_pdns):
    with SessionLocal() as db:
        alerts.check_pdns(db)
        assert alerts.open_alerts() == []
        fake_pdns.down = True
        alerts.check_pdns(db)
        (cond,) = alerts.open_alerts()
        assert cond["key"] == "pdns_down:0" and "PowerDNS #1 (pdns)" in cond["title"]

    # a record change while PowerDNS is down marks DNS dirty; the scheduler retries until it works
    r = client.post("/api/v1/sites", json={"domain": "example.com", "origin_ip": "93.184.216.34"})
    assert r.json()["dns_error"]
    with SessionLocal() as db:
        scheduler.job_edges(db)
        assert {c["key"] for c in alerts.open_alerts()} == {"pdns_down:0", "dns_sync:0"}
    fake_pdns.down = False
    with SessionLocal() as db:
        scheduler.job_edges(db)
        alerts.check_pdns(db)
    assert alerts.open_alerts() == []
    assert "example.com." in fake_pdns.zones  # the zone written while ns was down is there now
    assert sum("RESOLVED" in t for t in telegram.texts) == 2 * 2  # two conditions x two chats


def test_ssl_failure_and_expiring_certificate(client, telegram, monkeypatch):
    from app import ssl

    client.post("/api/v1/sites", json={"domain": "example.com", "origin_ip": "93.184.216.34"})
    with SessionLocal() as db:
        s = db.query(Site).one()
        s.ns_verified_at = utcnow()
        s.ssl_status, s.ssl_source = "active", "letsencrypt"
        s.ssl_cert, s.ssl_key = "CERT", "KEY"
        s.ssl_expires_at = utcnow() + timedelta(days=5)
        db.commit()

    def fail(site):
        raise ssl.SslError("DNS problem: NXDOMAIN looking up TXT")

    monkeypatch.setattr(ssl, "issue", fail)
    with SessionLocal() as db:
        scheduler.job_ssl(db)
        alerts.check_certs(db)
    keys = {c["key"] for c in alerts.open_alerts()}
    assert keys == {"ssl_failed:example.com", "cert_expiring:example.com"}
    assert any("تمدید گواهی example.com ناموفق بود" in t for t in telegram.texts)

    def ok(site):
        site.ssl_cert, site.ssl_key = "CERT2", "KEY2"
        site.ssl_expires_at = utcnow() + timedelta(days=90)
        site.ssl_status, site.ssl_error, site.ssl_source = "active", None, "letsencrypt"

    monkeypatch.setattr(ssl, "issue", ok)
    with SessionLocal() as db:
        scheduler.job_ssl(db)  # a failed renewal is not retried every tick
        s = db.query(Site).one()
        assert s.ssl_key == "KEY" and s.ssl_error
        s.updated_at = utcnow() - timedelta(hours=7)
        db.commit()
        scheduler.job_ssl(db)
        assert db.query(Site).one().ssl_key == "KEY2"
        alerts.check_certs(db)
    assert alerts.open_alerts() == []


def test_scheduler_job_exception_alert(client, telegram, monkeypatch):
    calls = {"n": 0}

    def job_flaky(db):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("boom")

    monkeypatch.setattr(scheduler, "JOBS", [job_flaky])
    scheduler.run_once()
    assert [c["key"] for c in alerts.open_alerts()] == ["job_failed:job_flaky"]
    assert "RuntimeError: boom" in telegram.texts[-1]
    scheduler.run_once()
    assert alerts.open_alerts() == [] and "RESOLVED" in telegram.texts[-1]


def test_alerts_never_break_the_caller(client, monkeypatch):
    def broken_session():
        raise RuntimeError("database is gone")

    monkeypatch.setattr(alerts, "_session", broken_session)
    alerts.raise_alert("x", "t", "b")  # logged, not raised
    alerts.resolve_alert("x")


# ------------------------------------------------------------------ admin API

def test_alerts_api(client, alert_settings, telegram):
    alerts.raise_alert("edge_offline:9", "نود خاموش", "متن")
    st = client.get("/api/v1/alerts/status").json()
    assert st["channels"]["telegram"] == {"configured": True, "chats": 2, "api": "custom"}
    assert st["channels"]["email"]["configured"] is False
    assert [c["key"] for c in st["open"]] == ["edge_offline:9"]
    assert TOKEN not in json.dumps(st)

    r = client.post("/api/v1/alerts/test")
    assert r.status_code == 200 and r.json() == {"ok": True, "results": {"telegram": "ok"}}
    assert "پیام آزمایشی" in telegram.texts[-1]
    assert client.post("/api/v1/alerts/test", headers={"Authorization": "Bearer nope"}).status_code == 401


def test_alerts_test_without_channels(client, alert_settings):
    assert client.post("/api/v1/alerts/test").status_code == 409


def test_deep_health_is_public_and_has_no_secrets(client, fake_pdns, alert_settings, monkeypatch):
    from app import routes_ops
    from app.config import settings

    monkeypatch.setattr(settings, "pdns_api_key", "pdns-secret-key")
    r = client.get("/healthz/deep", headers={"Authorization": ""})
    assert r.status_code == 200
    body = r.json()
    assert body["database"]["ok"] is True and body["pdns"] == [{"server": 1, "ok": True,
                                                                "latency_ms": body["pdns"][0]["latency_ms"]}]
    assert body["scheduler"]["role"] == "disabled"
    for secret in ("test-admin-key", "pdns-secret-key", "http://pdns"):
        assert secret not in r.text

    fake_pdns.down = True
    routes_ops._cache["body"] = None
    body = client.get("/healthz/deep").json()
    assert body["status"] == "degraded" and body["pdns"][0]["ok"] is False


def test_no_mass_edge_failover_right_after_a_controller_outage(client, telegram, fake_pdns):
    """Edges cannot report while no controller runs; their stale last_seen must not be acted on."""
    from app.config import settings

    with SessionLocal() as db:
        e = _edge(db, "ir-1", seen_ago=3600)
        db.add(scheduler.State(key="scheduler:last_run", value=(utcnow() - timedelta(hours=1)).isoformat()))
        db.add(scheduler.State(key="online_edges", value=f"{e.id}:5.160.1.10::global"))
        db.commit()
    scheduler.run_once()
    assert alerts.open_alerts() == [] and telegram.messages == []
    with SessionLocal() as db:
        assert db.get(scheduler.State, "online_edges").value.startswith(f"{e.id}:")  # DNS untouched
        assert not scheduler.edge_reports_trusted(db)
        later = utcnow() + timedelta(seconds=settings.edge_offline_seconds + 1)
        assert scheduler.edge_reports_trusted(db, now=later)
        # after the grace period an edge that still has not reported is failed over
        db.get(scheduler.State, "scheduler:resumed_at").value = (utcnow() - timedelta(hours=1)).isoformat()
        db.get(scheduler.State, "scheduler:last_run").value = utcnow().isoformat()  # written by Scheduler.tick
        db.commit()
    scheduler.run_once()
    assert {c["key"] for c in alerts.open_alerts()} == {f"edge_offline:{e.id}", "all_edges_offline"}
