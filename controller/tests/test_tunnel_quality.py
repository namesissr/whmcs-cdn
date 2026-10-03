"""Wave 7 (SPEC §15.1/§15.3–§15.5): tunnel path telemetry ingestion, the quality / usage reports
(admin + customer API), origin-down detection with webhooks + site events (events API, flapping
guard), origin health, and the edge-group capacity alert."""

import json
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import delete, select

from app import alerts, routes_capi, scheduler, tunnel_quality
from app.db import SessionLocal
from app.models import AnalyticsMinute, Edge, Site, SiteEvent, UsageHourly, WebhookDelivery, utcnow
from tests.platform_helpers import auth, edge_token
from tests.test_capi import new_key
from tests.test_tunnel import site as tunnel_site

S = "/api/v1/sites/example.com"
CAPI = "/capi/v1"

PATHS = [
    {"id": "grpc1", "path": "/x", "protocol": "grpc"},
    {"id": "ws1", "path": "/ws", "protocol": "ws"},
]
ERR0 = {k: 0 for k in tunnel_quality.ADVICE}


@pytest.fixture(autouse=True)
def _reset_rate():
    routes_capi._hits.clear()
    yield
    routes_capi._hits.clear()


def make_tunnel_site(client, paths=PATHS, **plan):
    tunnel_site(client, **plan)
    r = client.put(f"{S}/config/tunnel", json={"enabled": True, "paths": paths})
    assert r.status_code == 200, r.text


def hour_iso(dt: datetime) -> str:
    return dt.replace(minute=0, second=0, microsecond=0, tzinfo=None).isoformat() + "Z"


def path_counters(sessions=0, seconds=0, abnormal=0, connect_ms_sum=0, connect_n=0, bytes_up=0, bytes_down=0,
                  **errors):
    return {"sessions": sessions, "seconds": seconds, "bytes_up": bytes_up, "bytes_down": bytes_down,
            "abnormal": abnormal, "connect_ms_sum": connect_ms_sum, "connect_n": connect_n,
            "errors": {**ERR0, **errors}}


def item(paths, when=None, host="example.com", **tunnel):
    when = when or utcnow()
    tn = {"sessions": 0, "seconds": 0, "bytes_up": 0,
          "bytes_down": 0, "by_protocol": {}, "paths": paths, **tunnel}
    return {"host": host, "hour": hour_iso(when), "bytes": 100, "requests": 1, "tunnel": tn}


def post(client, token, items=(), live=()):
    return client.post("/edge/v1/usage", json={"items": list(items), "live": list(live)}, headers=auth(token))


def details(edge_name=None):
    with SessionLocal() as db:
        q = select(UsageHourly)
        if edge_name:
            q = q.join(Edge, Edge.id == UsageHourly.edge_id).where(Edge.name == edge_name)
        return [json.loads(r.details) for r in db.scalars(q)]


# ------------------------------------------------------------------ ingestion (SPEC §15.1)

def test_ingest_paths_validated_merged_and_capped(client):
    make_tunnel_site(client)
    token = edge_token(client)
    raw = {
        "grpc1": {**path_counters(sessions=3, seconds=90, connect_ms_sum=30.4, connect_n=3, origin_timeout=1),
                  "unknown_counter": 5, "errors": {**ERR0, "origin_timeout": 1, "bogus": 9}},
        "BAD!": path_counters(sessions=1),          # invalid id: dropped
        "x" * 33: path_counters(sessions=1),        # too long: dropped
        "ok_id-2": {"sessions": 1},                 # missing counters default to 0
    }
    r = post(client, token, [item(raw)])
    assert r.status_code == 200, r.text
    tn = details()[0]["tunnel"]
    assert set(tn["paths"]) == {"grpc1", "ok_id-2"}
    g = tn["paths"]["grpc1"]
    assert g["sessions"] == 3 and g["connect_ms_sum"] == 30 and "unknown_counter" not in g
    assert g["errors"] == {**ERR0, "origin_timeout": 1}  # unknown error key dropped
    # a second post merges (sums) into the same hourly row
    assert post(client, token, [item({"grpc1": path_counters(sessions=2, origin_refused=4)})]).status_code == 200
    g = details()[0]["tunnel"]["paths"]["grpc1"]
    assert g["sessions"] == 5 and g["errors"]["origin_refused"] == 4 and g["errors"]["origin_timeout"] == 1
    # negative / non-numeric counters are rejected like every other usage counter
    for bad in ({"grpc1": {"sessions": -1}}, {"grpc1": {"errors": {"limit": -2}}}, {"grpc1": {"sessions": "x"}},
                ["grpc1"]):
        assert post(client, token, [item(bad)]).status_code == 422, bad
    # pre-wave-7 agents omit `paths`
    old = {"host": "example.com", "hour": hour_iso(utcnow()), "bytes": 1, "requests": 1,
           "tunnel": {"sessions": 1, "seconds": 1, "bytes_up": 1, "bytes_down": 1}}
    assert post(client, token, [old]).status_code == 200


def test_ingest_caps_path_ids_at_50(client):
    make_tunnel_site(client)
    token = edge_token(client)
    many = {f"p{i}": path_counters(sessions=i + 1) for i in range(60)}
    assert post(client, token, [item(many)]).status_code == 200
    paths = details()[0]["tunnel"]["paths"]
    assert len(paths) == 50 and "p59" in paths and "p0" not in paths  # the busiest are kept
    # the hourly row never grows beyond 50 ids; existing ids keep merging
    assert post(client, token, [item({"newid": path_counters(sessions=99), "p59": path_counters(sessions=1)})]
                ).status_code == 200
    paths = details()[0]["tunnel"]["paths"]
    assert len(paths) == 50 and "newid" not in paths and paths["p59"]["sessions"] == 61


def test_live_tunnel_counters_stored_in_minute_details(client):
    make_tunnel_site(client)
    token = edge_token(client)
    m = utcnow().replace(second=0, microsecond=0).isoformat() + "Z"
    live = [{"host": "example.com", "minute": m, "requests": 5, "tunnel_attempts": 12, "tunnel_errors": 3},
            {"host": "www.example.com", "minute": m, "requests": 1, "tunnel_attempts": 3, "tunnel_errors": 1},
            {"host": "example.com", "minute": m, "requests": 1}]  # older agents omit them
    assert post(client, token, live=live).status_code == 200
    with SessionLocal() as db:
        d = json.loads(db.scalar(select(AnalyticsMinute)).details)
    assert d["tunnel_attempts"] == 15 and d["tunnel_errors"] == 4
    assert post(client, token, live=live).status_code == 200  # summed into the same bucket
    with SessionLocal() as db:
        d = json.loads(db.scalar(select(AnalyticsMinute)).details)
    assert d["tunnel_attempts"] == 30 and d["tunnel_errors"] == 8
    for bad in ({"tunnel_attempts": -1}, {"tunnel_errors": "x"}):
        r = post(client, token, live=[{"host": "example.com", "minute": m, **bad}])
        assert r.status_code == 422, bad


# ------------------------------------------------------------------ quality (SPEC §15.3)

def test_quality_math_edges_series_removed_and_advice(client):
    make_tunnel_site(client)
    t1 = edge_token(client, "edge-1", "5.160.1.10")
    t2 = edge_token(client, "edge-2", "5.160.1.11")
    now = utcnow()
    # the SPEC example on edge-1: 12 sessions, 5400 s, 1 abnormal, 840 ms / 12, one origin timeout
    assert post(client, t1, [item({"grpc1": path_counters(sessions=7, seconds=3150, connect_ms_sum=420, connect_n=7),
                                   "old9": path_counters(sessions=0, origin_refused=2)})]).status_code == 200
    assert post(client, t2, [item({"grpc1": path_counters(sessions=5, seconds=2250, abnormal=1, connect_ms_sum=420,
                                                          connect_n=5, origin_timeout=1)},
                                  when=now - timedelta(hours=2))]).status_code == 200
    r = client.get(f"{S}/tunnel/quality?hours=24")
    assert r.status_code == 200, r.text
    q = r.json()
    assert q["hours"] == 24 and len(q["series"]) == 24
    grpc, ws, old = q["paths"]
    assert grpc == {"id": "grpc1", "path": "/x", "protocol": "grpc", "sessions": 12, "avg_session_s": 450.0,
                    "abnormal_pct": 8.333, "connect_ms_avg": 70.0, "reuse_pct": 0.0, "errors": {**ERR0, "origin_timeout": 1},
                    "error_total": 1, "success_pct": 92.308, "top_issue": "origin_timeout",
                    "advice": tunnel_quality.ADVICE["origin_timeout"], "removed": False}
    # a configured path without data: nulls, no advice
    assert ws == {"id": "ws1", "path": "/ws", "protocol": "ws", "sessions": 0, "avg_session_s": None,
                  "abnormal_pct": None, "connect_ms_avg": None, "reuse_pct": None, "errors": ERR0, "error_total": 0,
                  "success_pct": None, "top_issue": None, "advice": None, "removed": False}
    # a path id that is no longer configured
    assert old["id"] == "old9" and old["removed"] is True and old["path"] is None and old["protocol"] is None
    assert old["success_pct"] == 0.0 and old["top_issue"] == "origin_refused"
    assert old["advice"] == "سرور شما روی پورت مسیر اتصال را رد می‌کند؛ سرویس Xray/sing-box و پورت را بررسی کنید."
    # SPEC §23.12: city labels + public tag, never the internal edge name
    assert [{k: v for k, v in e.items() if k != "key"} for e in q["edges"]] == [
        {"name": "نود ایران ۱", "label_en": "Iran node 1", "sessions": 7, "abnormal_pct": 0.0,
         "connect_ms_avg": 60.0, "error_total": 2},
        {"name": "نود ایران ۲", "label_en": "Iran node 2", "sessions": 5, "abnormal_pct": 20.0,
         "connect_ms_avg": 84.0, "error_total": 1}]
    assert all(len(e["key"]) == 8 for e in q["edges"]) and "edge-1" not in r.text
    assert q["series"][-1] == {"t": hour_iso(now).replace("+00:00", ""), "sessions": 7, "errors": 2, "abnormal": 0}
    assert q["series"][-3]["sessions"] == 5 and q["series"][-3]["errors"] == 1
    assert sum(p["sessions"] for p in q["series"]) == 12
    # 1-hour window leaves out the older edge-2 hour
    one = client.get(f"{S}/tunnel/quality?hours=1").json()
    assert one["paths"][0]["sessions"] == 7 and [e["name"] for e in one["edges"]] == ["نود ایران ۱"]
    for bad in (0, 745, "x"):
        assert client.get(f"{S}/tunnel/quality?hours={bad}").status_code == 422
    assert client.get(f"{S}/tunnel/quality").json()["hours"] == 24
    assert client.get("/api/v1/sites/nope.com/tunnel/quality").status_code == 404


def test_every_error_key_has_persian_advice_and_ties_follow_spec_order():
    assert set(tunnel_quality.ADVICE) == {"origin_refused", "origin_timeout", "origin_error", "limit", "country",
                                          "protocol", "edge"}
    assert all(v.strip().endswith(".") and "؛" in v for v in tunnel_quality.ADVICE.values())
    assert tunnel_quality.top_issue({**ERR0, "limit": 2, "edge": 2}) == "limit"
    assert tunnel_quality.top_issue(ERR0) is None


def test_quality_without_data_and_capi_scope(client):
    make_tunnel_site(client)
    q = client.get(f"{S}/tunnel/quality?hours=3").json()
    assert q["edges"] == [] and [p["id"] for p in q["paths"]] == ["grpc1", "ws1"]
    assert q["series"] == [{"t": s["t"], "sessions": 0, "errors": 0, "abnormal": 0} for s in q["series"]]
    stats = new_key(client, scopes=["stats"])["key"]
    dns = new_key(client, name="d", scopes=["dns"])["key"]
    assert client.get(f"{CAPI}/tunnel/quality?hours=3", headers={"Authorization": f"Bearer {stats}"}).json() == q
    for path in ("/tunnel/quality", "/tunnel/usage", "/tunnel/health"):
        assert client.get(CAPI + path, headers={"Authorization": f"Bearer {dns}"}).status_code == 403
        assert client.get(CAPI + path, headers={"Authorization": f"Bearer {stats}"}).status_code == 200
    assert client.get(f"{CAPI}/tunnel/quality?hours=745",
                      headers={"Authorization": f"Bearer {stats}"}).status_code == 422
    assert client.get(f"{CAPI}/tunnel/usage?days=91",
                      headers={"Authorization": f"Bearer {stats}"}).status_code == 422
    spec = client.get(f"{CAPI}/openapi.json").json()
    assert {"/capi/v1/tunnel/quality", "/capi/v1/tunnel/usage", "/capi/v1/tunnel/health"} <= set(spec["paths"])


# ------------------------------------------------------------------ usage + forecast (SPEC §15.3)

def test_usage_days_by_protocol_and_path(client):
    make_tunnel_site(client, bandwidth_limit_gb=100)
    token = edge_token(client)
    now = utcnow()
    tn = {"sessions": 4, "bytes_up": 100, "bytes_down": 900, "by_protocol": {"grpc": 1000, "bogus": 5}}
    paths = {"grpc1": path_counters(sessions=4, bytes_up=100, bytes_down=900)}
    assert post(client, token, [item(paths, **tn)]).status_code == 200
    r = client.get(f"{S}/tunnel/usage?days=3")
    assert r.status_code == 200, r.text
    u = r.json()
    assert [d["date"] for d in u["days"]] == [(now - timedelta(days=i)).date().isoformat() for i in (2, 1, 0)]
    assert u["days"][0] == {"date": u["days"][0]["date"], "bytes_up": 0, "bytes_down": 0, "sessions": 0,
                            "by_protocol": {}, "by_path": {}}
    assert u["days"][-1] == {"date": now.date().isoformat(), "bytes_up": 100, "bytes_down": 900, "sessions": 4,
                             "by_protocol": {"grpc": 1000}, "by_path": {"grpc1": 1000}}
    m = u["month"]
    assert m["used_bytes"] == 200  # billed: 100 sent + 100 tunnel bytes_up
    assert m["limit_bytes"] == 100 * 1024**3 and m["tunnel_bytes"] == 1000
    assert m["forecast_bytes"] >= 200 and m["forecast_exhaust_date"] is None
    assert len(client.get(f"{S}/tunnel/usage").json()["days"]) == 30
    for bad in (0, 91):
        assert client.get(f"{S}/tunnel/usage?days={bad}").status_code == 422


def test_month_forecast_math():
    f = tunnel_quality.month_forecast
    now = datetime(2026, 9, 10, 0, 0)  # 9 full days elapsed, 30-day month
    assert f(900, None, now) == {"used_bytes": 900, "limit_bytes": None, "forecast_bytes": 3000,
                                 "forecast_exhaust_date": None}
    # 100/day -> a 2000 limit is reached on day 20 (start + 20 days)
    assert f(900, 2000, now)["forecast_exhaust_date"] == "2026-09-21"
    # the pace never reaches the limit this month
    assert f(900, 5000, now)["forecast_exhaust_date"] is None
    # already over the limit: today
    assert f(2500, 2000, now)["forecast_exhaust_date"] == "2026-09-10"
    # nothing used: no exhaust date
    assert f(0, 2000, now) == {"used_bytes": 0, "limit_bytes": 2000, "forecast_bytes": 0,
                               "forecast_exhaust_date": None}
    # the first hours of a month extrapolate from at least one day
    assert f(100, None, datetime(2026, 2, 1, 1, 0))["forecast_bytes"] == 2800


# ------------------------------------------------------------------ origin-down detection (SPEC §15.4)

def set_window(now, attempts, errors, domain="example.com"):
    """Replace the minute buckets with one bucket at `now` carrying the tunnel counters."""
    with SessionLocal() as db:
        db.execute(delete(AnalyticsMinute))
        sid = db.scalar(select(Site.id).where(Site.domain == domain))
        db.add(AnalyticsMinute(site_id=sid, minute=now.replace(second=0, microsecond=0), requests=attempts,
                               bytes=0, cache_hits=0,
                               details=json.dumps({"tunnel_attempts": attempts, "tunnel_errors": errors})))
        db.commit()


def check(now):
    with SessionLocal() as db:
        return scheduler.job_tunnel_origin(db, now)


def tunnel_events(client, since=None):
    q = "/api/v1/events?type=tunnel" + (f"&since={since}" if since else "")
    r = client.get(q)
    assert r.status_code == 200, r.text
    return r.json()


def test_decide_thresholds():
    d = tunnel_quality.decide
    assert d("unknown", 10, 8) == "down" and d("up", 9, 9) == "up"   # < 10 attempts: no verdict
    assert d("up", 10, 7) == "up"                                     # 70 % < 80 %
    assert d("down", 5, 0) == "up" and d("down", 4, 0) == "down"      # >= 5 attempts, < 20 %
    assert d("down", 10, 2) == "down"                                 # 20 % is not < 20 %
    assert d("unknown", 0, 0) == "unknown"


def test_origin_down_up_webhooks_events_health_and_flapping_guard(client, fake_dns):
    make_tunnel_site(client)
    r = client.put(f"{S}/config/webhooks", json={"items": [
        {"url": "https://hooks.public.example/t", "events": ["tunnel.origin_down", "tunnel.origin_up"]}]})
    assert r.status_code == 200, r.text
    token = edge_token(client)
    assert client.get(f"{S}/tunnel/health").json() == {"state": "unknown", "since": None, "last_check": None}

    t0 = utcnow().replace(second=0, microsecond=0)
    # per-path hourly data says which paths fail
    assert post(client, token, [item({"ws1": path_counters(origin_refused=9), "grpc1": path_counters(sessions=1,
                                                                                                    origin_timeout=1)},
                                     when=t0)]).status_code == 200
    set_window(t0, 6, 6)
    assert check(t0) == []  # too few attempts: still unknown
    h = client.get(f"{S}/tunnel/health").json()
    assert h["state"] == "unknown" and h["last_check"] == t0.isoformat() + "Z"

    set_window(t0, 20, 17)  # 85 % origin errors
    assert check(t0) == [("example.com", "tunnel.origin_down")]
    assert client.get(f"{S}/tunnel/health").json() == {"state": "down", "since": t0.isoformat() + "Z",
                                                       "last_check": t0.isoformat() + "Z"}
    assert check(t0 + timedelta(minutes=1)) == []  # stays down: no repeat
    ev = tunnel_events(client)
    assert len(ev) == 1
    e = ev[0]
    assert e["type"] == "tunnel.origin_down" and e["domain"] == "example.com" and e["id"].startswith("evt_")
    assert e["data"] == {"paths": ["ws1", "grpc1"], "attempts": 20, "origin_errors": 17,
                         "since": t0.isoformat() + "Z"}
    with SessionLocal() as db:
        d = db.scalar(select(WebhookDelivery).where(WebhookDelivery.event == "tunnel.origin_down"))
        body = json.loads(d.payload)
    assert body["id"] == e["id"] and body["type"] == "tunnel.origin_down" and body["data"] == e["data"]

    t1 = t0 + timedelta(minutes=3)
    set_window(t1, 10, 1)
    assert check(t1) == [("example.com", "tunnel.origin_up")]
    up = tunnel_events(client)[-1]
    assert up["data"] == {"paths": ["ws1", "grpc1"], "attempts": 10, "origin_errors": 1,
                          "since": t1.isoformat() + "Z", "down_since": t0.isoformat() + "Z"}
    assert client.get(f"{S}/tunnel/health").json()["state"] == "up"

    # flapping: down again within 30 min of the last down notification -> no notification, and the
    # matching recovery is silent too; the state itself still follows the data
    t2 = t0 + timedelta(minutes=10)
    set_window(t2, 30, 30)
    assert check(t2) == []
    assert client.get(f"{S}/tunnel/health").json()["state"] == "down"
    t3 = t0 + timedelta(minutes=12)
    set_window(t3, 30, 0)
    assert check(t3) == []
    assert len(tunnel_events(client)) == 2
    # 30 minutes after the last notified down, a new outage is notified again
    t4 = t0 + timedelta(minutes=31)
    set_window(t4, 30, 30)
    assert check(t4) == [("example.com", "tunnel.origin_down")]
    with SessionLocal() as db:
        events = [d.event for d in db.scalars(select(WebhookDelivery).order_by(WebhookDelivery.id))]
    assert events == ["tunnel.origin_down", "tunnel.origin_up", "tunnel.origin_down"]

    # events API: since filter (inclusive), oldest first, stable ids
    all_ev = tunnel_events(client)
    assert [x["type"] for x in all_ev] == ["tunnel.origin_down", "tunnel.origin_up", "tunnel.origin_down"]
    assert [x["seq"] for x in all_ev] == sorted(x["seq"] for x in all_ev)
    later = tunnel_events(client, since=all_ev[1]["created_at"])
    assert [x["id"] for x in later] == [all_ev[1]["id"], all_ev[2]["id"]]
    offset = tunnel_events(client, since=t4.replace(tzinfo=timezone.utc).isoformat().replace("+", "%2B"))
    assert [x["id"] for x in offset] == [all_ev[2]["id"]]
    assert tunnel_events(client, since=(t4 + timedelta(minutes=1)).isoformat() + "Z") == []
    assert client.get("/api/v1/events?type=tunnel&limit=1").json()[0]["id"] == all_ev[0]["id"]


def test_origin_up_from_unknown_is_silent_and_edges_without_data_keep_state(client):
    make_tunnel_site(client)
    now = utcnow()
    set_window(now, 8, 0)
    assert check(now) == []
    assert client.get(f"{S}/tunnel/health").json()["state"] == "up"
    with SessionLocal() as db:
        db.execute(delete(AnalyticsMinute))
        db.commit()
    assert check(now + timedelta(minutes=10)) == []
    assert client.get(f"{S}/tunnel/health").json()["state"] == "up"
    assert tunnel_events(client) == []


def test_origin_check_switch_retention_and_deleted_site(client, monkeypatch):
    from app.config import settings

    make_tunnel_site(client)
    now = utcnow()
    set_window(now, 20, 20)
    monkeypatch.setattr(settings, "tunnel_origin_check", False)
    assert check(now) == []
    monkeypatch.setattr(settings, "tunnel_origin_check", True)
    assert check(now) == [("example.com", "tunnel.origin_down")]
    # job_cleanup prunes old site events
    with SessionLocal() as db:
        db.query(SiteEvent).update({SiteEvent.created_at: now - timedelta(days=31)})
        db.commit()
        scheduler.job_cleanup(db)
        assert db.scalar(select(SiteEvent)) is None
    # a deleted site's state is dropped
    assert client.delete(S).status_code == 200
    check(now + timedelta(minutes=1))
    with SessionLocal() as db:
        from app.models import State

        assert db.scalars(select(State).where(State.key.startswith("tunnel_origin:", autoescape=True))).all() == []


def test_events_api_types_and_since_validation(client):
    assert client.get("/api/v1/events").status_code == 200
    assert client.get("/api/v1/events?type=security&since=2026-01-01T00:00:00Z").status_code == 200
    assert client.get("/api/v1/events?type=tunnel").json() == []
    assert client.get("/api/v1/events?type=nope").status_code == 422
    assert client.get("/api/v1/events?type=tunnel&since=yesterday").status_code == 422
    assert client.get("/api/v1/events?type=tunnel", headers={"Authorization": "Bearer x"}).status_code == 401


def test_webhook_section_accepts_tunnel_events(client, fake_dns):
    make_tunnel_site(client)
    r = client.put(f"{S}/config/webhooks", json={"items": [
        {"url": "https://hooks.public.example/t", "events": ["tunnel.origin_up"]}]})
    assert r.status_code == 200 and r.json()["items"][0]["events"] == ["tunnel.origin_up"]


# ------------------------------------------------------------------ capacity (SPEC §15.5)

def _traffic(edge_name, mbps_by_hour, now):
    """usage_hourly rows on `edge_name` for the last len(list) completed hours (Mbps -> bytes)."""
    end = now.replace(minute=0, second=0, microsecond=0)
    with SessionLocal() as db:
        eid = db.scalar(select(Edge.id).where(Edge.name == edge_name))
        sid = db.scalar(select(Site.id))
        db.execute(delete(UsageHourly).where(UsageHourly.edge_id == eid))
        for i, mbps in enumerate(mbps_by_hour):
            db.add(UsageHourly(site_id=sid, edge_id=eid, hour=end - timedelta(hours=i + 1),
                               bytes=int(mbps * 1e6 / 8 * 3600), requests=1, cache_hits=0, details="{}"))
        db.commit()


def test_capacity_p95_alert_hysteresis_and_overview(client, alert_settings):
    make_tunnel_site(client)
    edge_token(client, "g1", "5.160.1.10")
    edge_token(client, "g2", "5.160.1.11")
    edge_token(client, "t1", "5.160.1.12")
    assert client.patch("/api/v1/edges/1", json={"capacity_mbps": 600}).status_code == 200
    assert client.patch("/api/v1/edges/2", json={"capacity_mbps": 400}).status_code == 200
    assert client.patch("/api/v1/edges/3", json={"group": "tunnel"}).status_code == 200  # capacity unknown
    now = utcnow()
    # 72 hours: 68 quiet hours + 4 peaks; p95 (nearest rank 69th of 72) lands on the first peak value
    _traffic("g1", [500, 750, 760, 770] + [100] * 68, now)
    _traffic("g2", [0] * 72, now)
    report = tunnel_quality.capacity(SessionLocal(), now)
    assert report == [{"group": "general", "p95_mbps": 500.0, "capacity_mbps": 1000, "pct": 50.0},
                      {"group": "tunnel", "p95_mbps": 0.0, "capacity_mbps": 0, "pct": None}]
    assert client.get("/api/v1/overview").json()["capacity"][0]["group"] == "general"

    def run(force=True, when=now):
        with SessionLocal() as db:
            return scheduler.job_capacity(db, when, force=force)

    def is_open():
        return any(c["key"] == "capacity:general" for c in alerts.open_alerts())

    run()
    assert not is_open()
    _traffic("g1", [750] * 72, now)
    run()
    assert is_open()
    cond = next(c for c in alerts.open_alerts() if c["key"] == "capacity:general")
    assert cond["title"] == "ظرفیت گروه general به ۷۰٪ رسیده؛ نود اضافه کنید"
    assert run(force=False) is None  # once per day
    _traffic("g1", [650] * 72, now)   # 65 %: between resolve and alert -> stays open
    run()
    assert is_open()
    _traffic("g1", [550] * 72, now)   # 55 %: resolved
    run()
    assert not is_open()
    # the next day runs again without force
    assert run(force=False, when=now + timedelta(days=1)) is not None
    assert scheduler.job_capacity in scheduler.JOBS and scheduler.job_tunnel_origin in scheduler.JOBS


def test_edge_config_node_block_and_fair_share_default(client):
    """SPEC §15.2/§15.6: each edge gets its own name/capacity and the fair-share percent; the tunnel
    section carries fair_share (default on)."""
    from tests.test_api import add_edge

    tok = add_edge(client, name="fs-edge", ip="5.160.9.9")
    cfg = client.get("/edge/v1/config", headers={"Authorization": f"Bearer {tok}"}).json()
    assert cfg["node"]["name"] == "fs-edge"
    assert cfg["node"]["fair_share_pct"] == 25
    assert isinstance(cfg["node"]["capacity_mbps"], int)
    r = client.post("/api/v1/sites", json={"domain": "fs.example", "origin_ip": "93.184.216.34", "plan": {}})
    assert r.status_code == 201
    t = client.get("/api/v1/sites/fs.example/config/tunnel").json()
    assert t["fair_share"] is True
