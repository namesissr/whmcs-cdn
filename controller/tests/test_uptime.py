"""Edge availability rollup + the faster/richer edge alerts."""

from datetime import timedelta

from app import alerts, uptime
from app.config import settings
from app.db import SessionLocal
from app.models import Edge, EdgeUptime, utcnow


def _edge(db, name="ir1", **kw):
    e = Edge(name=name, ipv4=kw.pop("ipv4", "5.160.1.1"), region=kw.pop("region", "home"),
             token_hash=name, enabled=True, **kw)
    db.add(e)
    db.commit()
    return e


def test_sample_and_summary(client):
    now = utcnow()
    with SessionLocal() as db:
        e = _edge(db, last_seen_at=now)
        # 3 online samples this hour, then the edge goes silent for 2 samples
        for _ in range(3):
            uptime.sample(db, now)
        e.last_seen_at = now - timedelta(hours=1)  # stale
        db.commit()
        for _ in range(2):
            uptime.sample(db, now)
        rows = db.query(EdgeUptime).filter_by(edge_id=e.id).all()
        assert len(rows) == 1 and rows[0].samples_total == 5 and rows[0].samples_online == 3
        s = uptime.summary(db, e.id, now)
        assert s["h24"] == 60.0 and s["d30"] == 60.0
        assert uptime.summaries(db, now)[e.id]["d30"] == 60.0


def test_daily_report_zero_fills(client):
    now = utcnow()
    with SessionLocal() as db:
        e = _edge(db, last_seen_at=now)
        # one online sample today, and a fully-online day 3 days ago
        uptime.sample(db, now)
        db.add(EdgeUptime(edge_id=e.id, hour=uptime.floor_hour(now - timedelta(days=3)),
                          samples_total=10, samples_online=10))
        db.commit()
        rep = uptime.daily(db, e.id, 7, now)
        assert len(rep["days"]) == 7
        assert rep["days"][-1]["uptime"] == 100.0        # today
        assert rep["days"][3]["uptime"] == 100.0         # 3 days ago
        assert rep["days"][0]["uptime"] is None          # 6 days ago: no data
        assert rep["overall"] == 100.0


def test_prune_old_rows(client):
    now = utcnow()
    with SessionLocal() as db:
        e = _edge(db, last_seen_at=now)
        db.add(EdgeUptime(edge_id=e.id, hour=uptime.floor_hour(now - timedelta(days=uptime.RETAIN_DAYS + 5)),
                          samples_total=1, samples_online=1))
        db.add(EdgeUptime(edge_id=e.id, hour=uptime.floor_hour(now), samples_total=1, samples_online=1))
        db.commit()
        uptime.prune(db, now)
        db.commit()
        assert db.query(EdgeUptime).count() == 1


def test_uptime_endpoint_and_edge_object(client):
    now = utcnow()
    with SessionLocal() as db:
        e = _edge(db, last_seen_at=now)
        for _ in range(4):
            uptime.sample(db, now)
    eid = e.id
    row = next(x for x in client.get("/api/v1/edges").json() if x["id"] == eid)
    assert row["uptime"]["d30"] == 100.0
    r = client.get(f"/api/v1/edges/{eid}/uptime?days=30").json()
    assert r["overall"] == 100.0 and len(r["days"]) == 30
    assert client.get("/api/v1/edges/99999/uptime").status_code == 404


def test_overview_lists_edge_uptime(client):
    now = utcnow()
    with SessionLocal() as db:
        e = _edge(db, last_seen_at=now)
        uptime.sample(db, now)
    o = client.get("/api/v1/overview").json()
    row = next(x for x in o["edges"]["list"] if x["id"] == e.id)
    assert row["online"] is True and row["uptime"]["d30"] == 100.0


def test_offline_alert_fires_before_dns_removal(client, alert_settings, monkeypatch):
    monkeypatch.setattr(settings, "edge_alert_seconds", 90)
    monkeypatch.setattr(settings, "edge_offline_seconds", 180)
    now = utcnow()
    with SessionLocal() as db:
        e = _edge(db, last_seen_at=now - timedelta(seconds=120))  # silent 120s: alert yes, still in DNS
        alerts.check_edges(db)
        conds = {c["key"]: c for c in alerts.open_alerts(db)}
        assert f"edge_offline:{e.id}" in conds
        assert "هنوز در DNS" in conds[f"edge_offline:{e.id}"]["text"]
        # once past edge_offline_seconds the message says it was removed from DNS
        e.last_seen_at = now - timedelta(seconds=200)
        db.commit()
        alerts.check_edges(db)
        conds = {c["key"]: c for c in alerts.open_alerts(db)}
        assert "حذف شده" in conds[f"edge_offline:{e.id}"]["text"]
        # fresh again -> resolved
        e.last_seen_at = utcnow()
        db.commit()
        alerts.check_edges(db)
        assert f"edge_offline:{e.id}" not in {c["key"] for c in alerts.open_alerts(db)}


def test_cpu_disk_mem_health_alert(client, alert_settings, monkeypatch):
    from app.services import record_metrics
    monkeypatch.setattr(settings, "edge_cpu_alert", 4)
    monkeypatch.setattr(settings, "edge_disk_alert", 90)
    now = utcnow()
    with SessionLocal() as db:
        e = _edge(db, last_seen_at=now)
        # sustained high CPU: needs LOAD_ALERT_CHECKS consecutive reports
        from app.services import LOAD_ALERT_CHECKS
        for _ in range(LOAD_ALERT_CHECKS):
            record_metrics(e, {"load1": 40.0, "cpus": 4, "disk_pct": 95.0, "mem_pct": 50.0}, now)
        db.commit()
        alerts.check_edge_health(db)
        cond = {c["key"]: c for c in alerts.open_alerts(db)}[f"edge_health:{e.id}"]
        assert cond["severity"] == "critical"  # disk full is critical
        assert "پردازنده" in cond["text"] and "دیسک" in cond["text"]
        # back to normal -> resolved
        record_metrics(e, {"load1": 0.5, "cpus": 4, "disk_pct": 40.0, "mem_pct": 40.0}, utcnow())
        db.commit()
        alerts.check_edge_health(db)
        assert f"edge_health:{e.id}" not in {c["key"] for c in alerts.open_alerts(db)}


def test_optional_metrics_absent_no_health_alert(client, alert_settings):
    from app.services import record_metrics
    now = utcnow()
    with SessionLocal() as db:
        e = _edge(db, last_seen_at=now)
        # an old agent that never sends disk/mem and runs at low load
        record_metrics(e, {"load1": 0.2, "cpus": 4}, now)
        db.commit()
        from app.services import edge_metrics
        assert "disk_pct" not in (edge_metrics(e) or {})
        alerts.check_edge_health(db)
        assert f"edge_health:{e.id}" not in {c["key"] for c in alerts.open_alerts(db)}
