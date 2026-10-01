"""Analytics & platform (SPEC §14.3): live analytics (§14.3.1), platform_errors + SLA report
(§14.3.4), customer API additions + OpenAPI (§14.3.5), metrics and the scheduler fast lane."""

import json
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from app import leader, routes_capi, scheduler
from app.db import SessionLocal
from app.models import AnalyticsMinute, Edge, EdgeUptime, Site, UsageHourly, utcnow
from tests.platform_helpers import S, auth, edge_token, make_site

CAPI = "/capi/v1"


@pytest.fixture(autouse=True)
def _reset_rate():
    routes_capi._hits.clear()
    routes_capi._config_hits.clear()
    yield
    routes_capi._hits.clear()


def minute(dt: datetime) -> datetime:
    return dt.replace(second=0, microsecond=0)


def iso(dt: datetime) -> str:
    return dt.replace(tzinfo=None).isoformat() + "Z"


def live_item(t, host="example.com", requests=10, **kw):
    return {"host": host, "minute": iso(minute(t)), "requests": requests, "bytes": requests * 100,
            "cache_hits": requests // 2, "status": {"2xx": requests}, "countries": {"IR": requests},
            "paths": {"/": requests}, **kw}


def post_usage(client, token, items=(), live=(), batch=None, events=()):
    body = {"items": list(items), "live": list(live), "events": list(events)}
    if batch:
        body["batch_id"] = batch
    r = client.post("/edge/v1/usage", json=body, headers=auth(token))
    assert r.status_code == 200, r.text
    return r.json()


# ------------------------------------------------------------------ live analytics

def test_live_ingest_zero_filled_series_totals_and_dedup(client):
    make_site(client)
    token = edge_token(client)
    now = datetime.now(timezone.utc)
    live = [
        live_item(now - timedelta(minutes=2), requests=10, paths={"/a": 7, "/b": 3}, countries={"IR": 9, "DE": 1},
                  status={"2xx": 8, "5xx": 2}),
        live_item(now - timedelta(minutes=2), host="www.example.com", requests=4, cache_hits=4,
                  paths={"/a": 4}, countries={"DE": 4}, status={"3xx": 4}),
        live_item(now, requests=6, cache_hits=0, paths={"/c?x=1": 6}, countries={"US": 6}, status={"4xx": 6}),
        live_item(now, host="unknown.net", requests=99),
        live_item(now - timedelta(hours=25), requests=50),  # older than the 24 h window: ignored
    ]
    batch = uuid.uuid4().hex
    assert post_usage(client, token, live=live, batch=batch)["live"] == 2
    assert post_usage(client, token, live=live, batch=batch)["duplicate"] is True  # counted once

    r = client.get(f"{S}/analytics/live?minutes=5")
    assert r.status_code == 200
    d = r.json()
    end = minute(now).replace(tzinfo=None)
    assert d["minutes"] == 5 and d["to"] == iso(end) and d["from"] == iso(end - timedelta(minutes=4))
    assert [p["t"] for p in d["series"]] == [iso(end - timedelta(minutes=i)) for i in range(4, -1, -1)]
    assert [p["requests"] for p in d["series"]] == [0, 0, 14, 0, 6]
    two = d["series"][2]
    assert two == {"t": iso(end - timedelta(minutes=2)), "requests": 14, "bytes": 1000 + 400, "cache_hits": 9,
                   "status": {"2xx": 8, "3xx": 4, "4xx": 0, "5xx": 2}}
    assert d["series"][0]["status"] == {"2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0}
    assert d["totals"] == {"requests": 20, "bytes": 2000, "cache_hits": 9, "hit_ratio": 0.45,
                           "status": {"2xx": 8, "3xx": 4, "4xx": 6, "5xx": 2}}
    assert d["top_paths"] == [["/a", 11], ["/c?x=1", 6], ["/b", 3]]
    assert d["top_countries"] == [["IR", 9], ["US", 6], ["DE", 5]]
    assert len(client.get(f"{S}/analytics/live?minutes=1").json()["series"]) == 1
    assert len(client.get(f"{S}/analytics/live?minutes=1440").json()["series"]) == 1440
    default = client.get(f"{S}/analytics/live").json()
    assert default["minutes"] == 60 and len(default["series"]) == 60


@pytest.mark.parametrize("q", ["0", "1441", "-5", "abc"])
def test_live_minutes_validation(client, q):
    make_site(client)
    assert client.get(f"{S}/analytics/live?minutes={q}").status_code == 422


def test_live_top_lists_capped_and_hit_ratio_null(client):
    make_site(client)
    token = edge_token(client)
    d = client.get(f"{S}/analytics/live?minutes=3").json()
    assert d["totals"]["hit_ratio"] is None and d["top_paths"] == [] and d["top_countries"] == []
    now = datetime.now(timezone.utc)
    for n in range(15):  # 15 posts x 20 paths -> the stored bucket is capped like hourly details
        post_usage(client, token, live=[live_item(now, paths={f"/p{n}-{i}": 1 + i for i in range(20)},
                                                  countries={f"C{n % 26}{chr(65 + i)}"[-2:]: 1 for i in range(20)})])
    with SessionLocal() as db:
        row = db.scalar(select(AnalyticsMinute))
        details = json.loads(row.details)
    assert len(details["paths"]) == 200
    d = client.get(f"{S}/analytics/live?minutes=3").json()
    assert len(d["top_paths"]) == 10 and len(d["top_countries"]) == 10
    assert d["top_paths"][0][1] == 20 and d["top_paths"] == sorted(d["top_paths"], key=lambda x: (-x[1], x[0]))


def test_live_retention_job(client):
    site = make_site(client)
    now = utcnow()
    with SessionLocal() as db:
        for age in (timedelta(minutes=5), timedelta(hours=23, minutes=59), timedelta(hours=24, minutes=2),
                    timedelta(days=3)):
            db.add(AnalyticsMinute(site_id=site["id"], minute=minute(now - age), requests=1, bytes=1,
                                   cache_hits=0, details="{}"))
        db.commit()
    with SessionLocal() as db:
        scheduler.job_cleanup(db)
    with SessionLocal() as db:
        left = sorted(r.minute for r in db.scalars(select(AnalyticsMinute)))
    assert left == [minute(now - timedelta(hours=23, minutes=59)), minute(now - timedelta(minutes=5))]


def test_live_items_validation(client):
    make_site(client)
    token = edge_token(client)
    now = datetime.now(timezone.utc)
    bad = client.post("/edge/v1/usage", json={"items": [], "live": [live_item(now, requests=-1)]},
                      headers=auth(token))
    assert bad.status_code == 422
    big = client.post("/edge/v1/usage", json={"items": [], "live": [live_item(now)] * 5001}, headers=auth(token))
    assert big.status_code == 422
    # pre-6D agents omit `live` (and `platform_errors`)
    assert post_usage(client, token)["live"] == 0


# ------------------------------------------------------------------ platform_errors + bots counters

def test_platform_errors_summed_into_hourly_details(client):
    make_site(client)
    token = edge_token(client)
    hour = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0).isoformat()
    item = {"host": "example.com", "hour": hour, "bytes": 10, "requests": 100, "platform_errors": 3,
            "security": {"bots": 4, "waf": 1}}
    post_usage(client, token, items=[item])
    post_usage(client, token, items=[dict(item, platform_errors=2), {**item, "host": "www.example.com",
                                                                     "platform_errors": 0}])
    with SessionLocal() as db:
        row = db.scalar(select(UsageHourly))
        assert json.loads(row.details)["platform_errors"] == 5 and row.requests == 300
    bad = client.post("/edge/v1/usage", json={"items": [dict(item, platform_errors=-1)]}, headers=auth(token))
    assert bad.status_code == 422
    # bot-management counters (source `bots`) show in the analytics totals
    totals = client.get(f"{S}/analytics?period=24h").json()["totals"]["security"]
    assert totals["bots"] == 12 and totals["waf"] == 3 and totals["hotlink"] == 0


# ------------------------------------------------------------------ SLA report

def _usage(db, site_id, edge_id, when, requests, errors):
    db.add(UsageHourly(site_id=site_id, edge_id=edge_id, hour=when, bytes=0, requests=requests, cache_hits=0,
                       details=json.dumps({"platform_errors": errors} if errors is not None else {})))


def _uptime(db, edge_id, when, online, total):
    db.add(EdgeUptime(edge_id=edge_id, hour=when, samples_online=online, samples_total=total))


def test_sla_month_math(client):
    site = make_site(client)
    edge_token(client, name="g1", ip="5.160.1.11")
    edge_token(client, name="g2", ip="5.160.1.12")
    edge_token(client, name="t1", ip="5.160.1.13")
    client.patch("/api/v1/edges/3", json={"group": "tunnel"})
    month = (utcnow().replace(day=1) - timedelta(days=1)).replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    d1, d2 = month, month + timedelta(days=1)
    with SessionLocal() as db:
        _usage(db, site["id"], 1, d1 + timedelta(hours=1), 1000, 1)        # 99.9 %
        _usage(db, site["id"], 2, d1 + timedelta(hours=2), 1000, None)     # older rows: no counter
        _usage(db, site["id"], 1, d2 + timedelta(hours=5), 500, 5)          # 99.0 %
        _uptime(db, 1, d1, 60, 60)          # g1 day 1: 100 %
        _uptime(db, 2, d1, 57, 60)          # g2 day 1: 95 %
        _uptime(db, 1, d2, 30, 60)          # g2 has no samples on day 2
        _uptime(db, 3, d1, 0, 60)           # tunnel-group edge: not in this site's group
        db.commit()
    r = client.get(f"{S}/sla?month={month:%Y-%m}")
    assert r.status_code == 200, r.text
    rep = r.json()
    assert rep["month"] == f"{month:%Y-%m}" and rep["domain"] == "example.com"
    assert rep["requests"] == 2500 and rep["platform_errors"] == 6
    assert rep["request_success_pct"] == 99.76
    # mean over the group's edges of each edge's month uptime: g1 90/120 = 75 %, g2 95 % -> 85 %
    assert rep["edge_uptime_pct"] == 85.0
    assert rep["availability_pct"] == 85.0 and rep["target_pct"] == 99.9 and rep["met"] is False
    days = {d["date"]: d for d in rep["days"]}
    next_month = (month.replace(day=28) + timedelta(days=4)).replace(day=1)
    assert len(rep["days"]) == (next_month - month).days  # a past month: every day
    assert days[d1.date().isoformat()] == {"date": d1.date().isoformat(), "requests": 2000, "platform_errors": 1,
                                           "request_success_pct": 99.95, "edge_uptime_pct": 97.5}
    assert days[d2.date().isoformat()] == {"date": d2.date().isoformat(), "requests": 500, "platform_errors": 5,
                                           "request_success_pct": 99.0, "edge_uptime_pct": 50.0}
    empty = days[(d1 + timedelta(days=2)).date().isoformat()]
    assert empty["requests"] == 0 and empty["request_success_pct"] is None and empty["edge_uptime_pct"] is None
    assert rep["days"][0]["date"] == d1.date().isoformat()
    # target from the plan; met when availability >= target
    client.patch(f"{S}/plan", json={"features": {"sla_target": 80}})
    rep = client.get(f"{S}/sla?month={month:%Y-%m}").json()
    assert rep["target_pct"] == 80.0 and rep["met"] is True


def test_sla_nulls_without_data_and_three_decimals(client):
    site = make_site(client)
    rep = client.get(f"{S}/sla").json()  # default: the current month
    assert rep["month"] == utcnow().strftime("%Y-%m")
    assert rep["requests"] == 0 and rep["platform_errors"] == 0
    assert rep["request_success_pct"] is None and rep["edge_uptime_pct"] is None
    assert rep["availability_pct"] is None and rep["met"] is None and rep["target_pct"] == 99.9
    assert len(rep["days"]) == utcnow().day  # up to today
    edge_token(client)
    now = utcnow().replace(minute=0, second=0, microsecond=0)
    with SessionLocal() as db:
        _usage(db, site["id"], 1, now.replace(hour=0), 3, 1)
        db.commit()
    rep = client.get(f"{S}/sla").json()
    # only one of the two values -> availability is that value; 3 decimals
    assert rep["request_success_pct"] == 66.667 and rep["edge_uptime_pct"] is None
    assert rep["availability_pct"] == 66.667 and rep["met"] is False


def test_sla_falls_back_to_every_edge_when_the_group_has_no_samples(client):
    site = make_site(client)
    client.patch(f"{S}/plan", json={"features": {"edge_group": "tunnel"}})
    edge_token(client)
    now = utcnow().replace(minute=0, second=0, microsecond=0)
    with SessionLocal() as db:
        _uptime(db, 1, now.replace(hour=0), 99, 100)  # a general edge serves the site (DNS fail-open)
        _usage(db, site["id"], 1, now.replace(hour=0), 1000, 0)
        db.commit()
    rep = client.get(f"{S}/sla").json()
    assert rep["edge_uptime_pct"] == 99.0 and rep["request_success_pct"] == 100.0
    assert rep["availability_pct"] == 99.0 and rep["met"] is False


def test_sla_month_validation(client):
    make_site(client)
    now = utcnow()

    def back(n):
        y, m = divmod(now.year * 12 + now.month - 1 - n, 12)
        return f"{y:04d}-{m + 1:02d}"

    assert client.get(f"{S}/sla?month={back(12)}").status_code == 200
    for bad in (back(13), back(-1), "2026-13", "2026-1x", "26-01", "2026/09"):
        assert client.get(f"{S}/sla?month={bad}").status_code == 422, bad
    assert client.get("/api/v1/sites/nope.com/sla").status_code == 404


# ------------------------------------------------------------------ customer API

def new_key(client, scopes):
    r = client.post(f"{S}/apikeys", json={"name": "k", "scopes": list(scopes)})
    assert r.status_code == 201, r.text
    return r.json()["key"]


def test_capi_site_with_any_scope(client):
    make_site(client)
    key = new_key(client, ["purge"])
    r = client.get(f"{CAPI}/site", headers=auth(key))
    assert r.status_code == 200, r.text
    body = r.json()
    assert set(body) == {"domain", "status", "suspended", "plan", "nameservers", "cname_target", "ssl_status"}
    assert body["domain"] == "example.com" and body["status"] == "pending_ns" and body["suspended"] is False
    assert body["nameservers"] == ["ns1.example-cdn.com", "ns2.example-cdn.com"]
    assert body["cname_target"] == "example.com" and body["ssl_status"] == "none"
    assert body["plan"]["features"]["max_webhooks"] == 10 and body["plan"]["features"]["log_export"] is True
    assert client.get(f"{CAPI}/site").status_code == 401
    client.post(f"{S}/suspend")
    assert client.get(f"{CAPI}/site", headers=auth(key)).json()["status"] == "suspended"
    # no proxied host -> no cname target
    client.post("/api/v1/sites", json={"domain": "bare.org"})
    k2 = client.post("/api/v1/sites/bare.org/apikeys", json={"name": "k", "scopes": ["dns"]}).json()["key"]
    assert client.get(f"{CAPI}/site", headers=auth(k2)).json()["cname_target"] is None


def test_capi_live_needs_stats_scope(client):
    make_site(client)
    token = edge_token(client)
    post_usage(client, token, live=[live_item(datetime.now(timezone.utc), requests=7)])
    stats = new_key(client, ["stats"])
    r = client.get(f"{CAPI}/analytics/live?minutes=2", headers=auth(stats))
    assert r.status_code == 200 and r.json()["totals"]["requests"] == 7
    assert client.get(f"{CAPI}/analytics/live?minutes=0", headers=auth(stats)).status_code == 422
    assert client.get(f"{CAPI}/analytics/live", headers=auth(new_key(client, ["dns"]))).status_code == 403


def test_capi_openapi_is_public_and_customer_only(client):
    r = client.get(f"{CAPI}/openapi.json", headers={"Authorization": ""})
    assert r.status_code == 200
    doc = r.json()
    assert doc["openapi"].startswith("3.")
    paths = set(doc["paths"])
    assert {"/capi/v1/site", "/capi/v1/analytics/live", "/capi/v1/purge", "/capi/v1/records",
            "/capi/v1/config/{section}"} <= paths
    assert all(p.startswith("/capi/v1/") for p in paths)
    assert "/capi/v1/openapi.json" not in paths
    text = r.text
    assert "/api/v1" not in text and "/edge/v1" not in text
    scheme = doc["components"]["securitySchemes"]["bearerAuth"]
    assert scheme["type"] == "http" and scheme["scheme"] == "bearer"
    assert doc["paths"]["/capi/v1/site"]["get"]["security"] == [{"bearerAuth": []}]


# ------------------------------------------------------------------ metrics

def test_metrics_aggregates_without_identifiers(client):
    make_site(client)
    client.put(f"{S}/config/webhooks", json={"items": [
        {"url": "https://93.184.216.34/h", "events": ["site.suspended"]}]})
    client.post(f"{S}/suspend")
    text = client.get("/metrics").text
    assert 'pcdn_webhook_deliveries{status="pending"} 1' in text
    assert 'pcdn_webhook_deliveries{status="failed"} 0' in text
    assert "pcdn_log_export_pending_records 0" in text
    assert "example.com" not in text and "93.184.216.34" not in text


# ------------------------------------------------------------------ scheduler

def test_new_jobs_are_registered_leader_jobs():
    assert scheduler.job_webhooks in scheduler.JOBS and scheduler.job_log_export in scheduler.JOBS
    assert scheduler.FAST_JOBS == [scheduler.job_webhooks] and scheduler.FAST_INTERVAL == 30.0


def test_fast_lane_runs_between_ticks_only_while_leading(monkeypatch):
    monkeypatch.setattr(scheduler, "FAST_INTERVAL", 0.02)
    runs = {"work": 0, "fast": 0}
    lock = threading.Lock()

    def bump(k):
        with lock:
            runs[k] += 1

    s = scheduler.Scheduler(elector=leader.AlwaysLeader(), interval=3.0, work=lambda: bump("work"),
                            fast_work=lambda: bump("fast"))
    s.start()
    deadline = time.monotonic() + 5
    while runs["fast"] < 3 and time.monotonic() < deadline:
        time.sleep(0.01)
    s.stop()
    assert runs["work"] == 1 and runs["fast"] >= 3

    class Follower:
        def check(self):
            return False

        def release(self):
            pass

    runs.update(work=0, fast=0)
    s = scheduler.Scheduler(elector=Follower(), interval=0.5, work=lambda: bump("work"),
                            fast_work=lambda: bump("fast"))
    s.start()
    time.sleep(0.2)
    s.stop()
    assert runs == {"work": 0, "fast": 0}
    # a custom work function gets no fast lane unless asked for
    assert scheduler.Scheduler(elector=leader.AlwaysLeader(), work=lambda: None).fast_work is None
    assert scheduler.Scheduler(elector=leader.AlwaysLeader()).fast_work is scheduler.run_fast


def test_site_delete_removes_platform_data(client):
    """Also on SQLite (no FK enforcement, ids may be reused): a new site never inherits them."""
    from app import kv, logexport
    from app.models import LogSpool, State, WebhookDelivery

    site = make_site(client)
    client.put(f"{S}/config/webhooks", json={"items": [
        {"url": "https://93.184.216.34/h", "events": ["site.suspended"]}]})
    client.post(f"{S}/suspend")
    with SessionLocal() as db:
        db.add(AnalyticsMinute(site_id=site["id"], minute=minute(utcnow()), requests=1, bytes=1, cache_hits=0,
                               details="{}"))
        db.add(LogSpool(site_id=site["id"], hour=utcnow(), records=1, data=b"x"))
        kv.incr(db, logexport.DROPPED_KEY.format(site["id"]), 3)
        db.commit()
    assert client.delete(S).status_code == 200
    with SessionLocal() as db:
        assert db.scalar(select(Site)) is None
        for model in (AnalyticsMinute, LogSpool, WebhookDelivery):
            assert list(db.scalars(select(model))) == []
        assert db.get(State, logexport.DROPPED_KEY.format(site["id"])) is None
        assert db.scalar(select(Edge)) is None
