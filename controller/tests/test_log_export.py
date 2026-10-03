"""Log export (SPEC §14.3.2): section with a write-only encrypted secret, /edge/v1/logship
ingestion (anonymization, dedup, hourly cap), hourly upload to S3 (moto), retry, 72 h drop,
status and test endpoints."""

import gzip
import json
import re
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select, text, update

from app import crypto, logexport, routes_platform, scheduler, site_secrets
from app.config import settings
from app.db import SessionLocal, engine
from app.models import AuditLog, LogSpool, Site, utcnow
from tests.platform_helpers import S, auth, edge_token, make_site
from tests.test_api import edge_get

LOGS = {"enabled": True, "s3_endpoint": "https://s3.public.example", "region": "ir-thr-at1",
        "bucket": "my-logs", "prefix": "cdn/", "access_key": "AKID", "secret_key": "SECRET/KEY+1",
        "anonymize_ip": True, "sample_rate": 0.5}


@pytest.fixture(autouse=True)
def _isolate(fake_dns):
    routes_platform._test_hits.clear()
    yield
    routes_platform._test_hits.clear()


def put_logs(client, body, path=S):
    return client.put(f"{path}/config/logs", json=body)


def moto_logs(endpoint, **kw):
    return {**LOGS, "s3_endpoint": endpoint, "bucket": "pcdn", "access_key": "AK", "secret_key": "SK", **kw}


def iso(dt: datetime) -> str:
    return dt.replace(tzinfo=None).isoformat() + "Z"


def rec(t: datetime, **kw) -> dict:
    return {"host": "example.com", "t": iso(t), "ip": "93.184.216.34", "method": "GET", "scheme": "https",
            "path": "/a.css", "status": 200, "bytes": 1234, "rt": 0.0123, "cache": "HIT", "country": "ir",
            "ua": "Mozilla/5.0", "referer": "https://ref.example/page", "proto": "HTTP/2.0", **kw}


def ship(client, token, records, batch=None):
    return client.post("/edge/v1/logship", json={"batch_id": batch or uuid.uuid4().hex, "records": records},
                       headers=auth(token))


def spooled() -> list[dict]:
    out = []
    with SessionLocal() as db:
        for row in db.scalars(select(LogSpool).order_by(LogSpool.id)):
            out += [json.loads(line) for line in gzip.decompress(row.data).decode().splitlines()]
    return out


def run_job(now=None):
    with SessionLocal() as db:
        return scheduler.job_log_export(db, now=now, wait=True)


def status(client):
    r = client.get(f"{S}/logs/status")
    assert r.status_code == 200
    return r.json()


# ------------------------------------------------------------------ section

def test_section_secret_is_write_only_and_encrypted(client, monkeypatch):
    monkeypatch.setattr(settings, "data_encryption_key", crypto.generate_key())
    make_site(client)
    default = client.get(f"{S}/config/logs").json()
    assert default == {"enabled": False, "s3_endpoint": "", "region": "us-east-1", "bucket": "", "prefix": "",
                       "access_key": "", "secret_key": "", "secret_key_set": False, "anonymize_ip": True,
                       "sample_rate": 1.0}
    r = put_logs(client, LOGS)
    assert r.status_code == 200, r.text
    expected = {**LOGS, "secret_key": "", "secret_key_set": True}
    assert r.json() == expected
    assert client.get(f"{S}/config/logs").json() == expected
    assert client.get(S).json()["config"]["logs"] == expected
    with engine.connect() as c:
        raw_secrets, raw_config = c.execute(text("SELECT integration_secrets, config FROM sites")).one()
    assert "enc:v1:" in raw_secrets and "SECRET/KEY+1" not in raw_secrets and "SECRET/KEY+1" not in raw_config

    # the edges get sampling only — never endpoint, bucket or keys
    token = edge_token(client)
    cfg = edge_get(client, token, "/edge/v1/config")
    assert cfg.json()["sites"][0]["logs"] == {"enabled": True, "sample_rate": 0.5, "anonymize_ip": True}
    for secret in ("SECRET/KEY+1", "AKID", "s3.public.example", "my-logs"):
        assert secret not in cfg.text
    audit = json.dumps([a.detail for a in SessionLocal().scalars(select(AuditLog))])
    assert "SECRET/KEY+1" not in audit

    # "" and omitted keep the stored key; a new one replaces it
    def stored():
        with SessionLocal() as db:
            return site_secrets.logs_secret(db.scalar(select(Site)))

    assert put_logs(client, {**LOGS, "secret_key": "", "sample_rate": 1}).json()["secret_key_set"] is True
    assert stored() == "SECRET/KEY+1"
    body = {k: v for k, v in LOGS.items() if k != "secret_key"}
    assert put_logs(client, {**body, "secret_key_set": False}).status_code == 200  # output field ignored
    assert stored() == "SECRET/KEY+1"
    put_logs(client, {**LOGS, "secret_key": "NEW"})
    assert stored() == "NEW"


@pytest.mark.parametrize("change", [
    {"s3_endpoint": ""}, {"bucket": ""}, {"access_key": ""},
    {"bucket": "Bad_Bucket"}, {"bucket": "ab"}, {"bucket": "a..b"}, {"bucket": "192.168.1.1"},
    {"prefix": "../x"}, {"prefix": "a b"}, {"prefix": "x" * 129}, {"region": "bad region"},
    {"sample_rate": 0}, {"sample_rate": 0.001}, {"sample_rate": 1.5},
    {"s3_endpoint": "http://s3.public.example"}, {"s3_endpoint": "https://private.example"},
    {"s3_endpoint": "https://10.0.0.1"}, {"s3_endpoint": "https://unknown.example"},
    {"s3_endpoint": "https://s3.public.example/?x=1"}, {"access_key": "with space"}, {"extra": True},
])
def test_section_validation(client, change):
    make_site(client)
    r = put_logs(client, {**LOGS, **change})
    assert r.status_code == 422, (change, r.text)


def test_enabling_needs_a_secret_and_the_plan_feature(client):
    make_site(client)
    r = put_logs(client, {**LOGS, "secret_key": ""})
    assert r.status_code == 422 and "secret_key" in r.text
    assert put_logs(client, {**LOGS, "enabled": False, "secret_key": ""}).status_code == 200
    assert client.patch(f"{S}/plan", json={"features": {"log_export": False}}).status_code == 200
    assert put_logs(client, LOGS).status_code == 403
    assert put_logs(client, {**LOGS, "enabled": False}).status_code == 200  # turning off is always allowed
    token = edge_token(client)
    client.patch(f"{S}/plan", json={"features": {"log_export": True}})
    put_logs(client, LOGS)
    client.patch(f"{S}/plan", json={"features": {"log_export": False}})
    assert edge_get(client, token, "/edge/v1/config").json()["sites"][0]["logs"]["enabled"] is False
    assert client.post(f"{S}/logs/test").status_code == 403


# ------------------------------------------------------------------ ingestion

def test_anonymize_ip():
    assert logexport.anonymize_ip("93.184.216.34") == "93.184.216.0"
    assert logexport.anonymize_ip("93.184.216.0") == "93.184.216.0"  # idempotent
    assert logexport.anonymize_ip("2001:db8:abcd:1234:5678::1") == "2001:db8:abcd::"
    assert logexport.anonymize_ip("2001:db8:abcd::") == "2001:db8:abcd::"
    assert logexport.anonymize_ip("not an ip") == "" and logexport.anonymize_ip("") == ""


def test_logship_anonymizes_strips_and_dedups(client):
    make_site(client)
    make_site(client, domain="other.org")
    put_logs(client, LOGS)
    token = edge_token(client)
    now = datetime.now(timezone.utc)
    records = [
        rec(now, path="/p?token=secret#frag", referer="https://ref.example/x?q=1", ua="u" * 900),
        rec(now, host="www.example.com", ip="2001:db8:abcd:1234::1", path="/" + "a" * 3000),
        rec(now, host="other.org"),           # site without logs.enabled -> dropped silently
        rec(now, host="unknown.net"),          # not ours
        {"host": "example.com", "t": "yesterday"},  # unparsable time -> skipped, not the batch
        "garbage",
    ]
    batch = uuid.uuid4().hex
    r = ship(client, token, records, batch)
    assert r.status_code == 200, r.text
    assert r.json() == {"ok": True, "accepted": 2, "dropped": 0, "ignored": 2, "invalid": 2}
    a, b = spooled()
    assert a["ip"] == "93.184.216.0" and b["ip"] == "2001:db8:abcd::"
    assert a["path"] == "/p" and a["referer"] == "https://ref.example/x" and len(a["ua"]) == 512
    assert len(b["path"]) == 2048 and b["host"] == "www.example.com"
    assert a["country"] == "IR" and a["status"] == 200 and a["bytes"] == 1234 and a["rt"] == 0.012
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z", a["t"])
    assert list(a) == ["t", "host", "ip", "method", "scheme", "path", "status", "bytes", "rt", "cache",
                       "country", "ua", "referer", "proto"]
    # a replay of the same batch is counted once
    assert ship(client, token, records, batch).json()["duplicate"] is True
    assert len(spooled()) == 2
    # the same id on the usage endpoint is a different namespace
    usage = client.post("/edge/v1/usage", json={"batch_id": batch, "items": []}, headers=auth(token))
    assert usage.json().get("duplicate") is None

    put_logs(client, {**LOGS, "anonymize_ip": False})
    ship(client, token, [rec(now, ip="93.184.216.34")])
    assert spooled()[-1]["ip"] == "93.184.216.34"


def test_logship_envelope_validation(client):
    make_site(client)
    token = edge_token(client)
    assert client.post("/edge/v1/logship", json={"records": []}, headers=auth(token)).status_code == 422
    assert client.post("/edge/v1/logship", json={"batch_id": "x", "records": []},
                       headers=auth(token)).status_code == 422
    big = {"batch_id": uuid.uuid4().hex, "records": [{}] * 5001}
    assert client.post("/edge/v1/logship", json=big, headers=auth(token)).status_code == 422
    assert client.post("/edge/v1/logship", json={"batch_id": uuid.uuid4().hex, "records": []}).status_code == 401


def test_hourly_cap_and_old_records_are_counted_as_dropped(client, monkeypatch):
    monkeypatch.setattr(settings, "log_export_max_per_hour", 3)
    make_site(client)
    put_logs(client, LOGS)
    token = edge_token(client)
    now = datetime.now(timezone.utc)
    assert ship(client, token, [rec(now)] * 5).json()["dropped"] == 2
    assert ship(client, token, [rec(now)] * 2).json() == {"ok": True, "accepted": 0, "dropped": 2,
                                                           "ignored": 0, "invalid": 0}
    # another hour has its own budget; records older than 72 h are dropped (counted)
    r = ship(client, token, [rec(now - timedelta(hours=2))] * 2 + [rec(now - timedelta(hours=73))])
    assert r.json()["accepted"] == 2 and r.json()["dropped"] == 1
    st = status(client)
    assert st["pending_records"] == 5 and st["dropped_records"] == 5 and st["enabled"] is True


# ------------------------------------------------------------------ upload (moto)

def _objects(endpoint, prefix=""):
    import boto3

    s3 = boto3.client("s3", endpoint_url=endpoint, aws_access_key_id="AK", aws_secret_access_key="SK",
                      region_name="ir-thr-at1")
    keys = [o["Key"] for o in s3.list_objects_v2(Bucket="pcdn", Prefix=prefix).get("Contents", [])]
    return s3, keys


def test_completed_hours_upload_as_one_gzip_object(client, s3_server, local_vet):
    make_site(client)
    assert put_logs(client, moto_logs(s3_server)).status_code == 200
    token = edge_token(client)
    now = datetime.now(timezone.utc)
    past = now - timedelta(hours=2)
    ship(client, token, [rec(past, path="/one")])
    ship(client, token, [rec(past, path="/two"), rec(past, path="/three")])
    ship(client, token, [rec(now, path="/current-hour")])
    assert status(client)["pending_records"] == 4

    assert run_job() != []
    s3, keys = _objects(s3_server, "cdn/")
    hour = past.replace(minute=0, second=0, microsecond=0)
    assert len(keys) == 1
    assert re.fullmatch(rf"cdn/example\.com/{hour:%Y/%m/%d/%H}-[0-9a-f]{{8}}\.jsonl\.gz", keys[0])
    obj = s3.get_object(Bucket="pcdn", Key=keys[0])["Body"].read()
    lines = gzip.decompress(obj).decode().splitlines()  # concatenated members = one valid gzip stream
    assert [json.loads(line)["path"] for line in lines] == ["/one", "/two", "/three"]

    st = status(client)
    assert st["last_object"] == keys[0] and st["last_upload_at"].endswith("Z")
    assert st["last_error"] is None and st["last_error_at"] is None
    assert st["pending_records"] == 1  # the current hour is not complete yet
    assert run_job() == []  # nothing else is due


def test_failure_keeps_chunks_retries_after_10_minutes_then_72h_drop(client, receiver, local_vet):
    make_site(client)
    put_logs(client, {**LOGS, "s3_endpoint": f"http://127.0.0.1:{receiver.port}"})
    token = edge_token(client)
    now = utcnow()
    ship(client, token, [rec(now - timedelta(hours=2))] * 3)
    receiver.status = 500
    run_job(now)
    assert len(receiver.requests) == 1 and receiver.requests[0]["method"] == "PUT"
    st = status(client)
    assert st["pending_records"] == 3 and "HTTP 500" in st["last_error"] and st["last_error_at"]
    assert "SECRET" not in st["last_error"]

    run_job(now + timedelta(minutes=5))  # inside the 10-minute retry wait
    assert len(receiver.requests) == 1
    receiver.status = 200
    run_job(now + timedelta(minutes=11))
    assert len(receiver.requests) == 2
    st = status(client)
    assert st["pending_records"] == 0 and st["last_error"] is None and st["last_upload_at"]
    put = receiver.requests[-1]
    assert put["path"].startswith("/my-logs/cdn/example.com/") and put["path"].endswith(".jsonl.gz")
    assert put["headers"]["authorization"].startswith("AWS4-HMAC-SHA256 Credential=AKID/")
    assert put["headers"]["host"] == f"127.0.0.1:{receiver.port}"
    assert len(gzip.decompress(put["body"]).decode().splitlines()) == 3

    # chunks that could not be uploaded for 72 h are dropped and counted
    receiver.status = 503
    ship(client, token, [rec(now - timedelta(hours=1, minutes=30))] * 4)
    with engine.begin() as c:
        c.execute(update(LogSpool).values(created_at=now - timedelta(hours=73)))
    run_job(now + timedelta(hours=1))
    st = status(client)
    assert st["pending_records"] == 0 and st["dropped_records"] == 4
    assert len(receiver.requests) == 2  # dropped before any upload attempt


def test_ssrf_rechecked_before_every_upload(client, fake_dns):
    make_site(client)
    put_logs(client, LOGS)
    token = edge_token(client)
    ship(client, token, [rec(utcnow() - timedelta(hours=2))])
    fake_dns["s3.public.example"] = ["10.0.0.5"]  # rebinding after the save
    run_job()
    st = status(client)
    assert st["pending_records"] == 1 and "غیرعمومی" in st["last_error"]


def test_disabling_export_discards_the_spool(client):
    make_site(client)
    put_logs(client, LOGS)
    token = edge_token(client)
    ship(client, token, [rec(utcnow() - timedelta(hours=2))] * 2)
    put_logs(client, {**LOGS, "enabled": False})
    assert ship(client, token, [rec(utcnow())]).json()["ignored"] == 1
    run_job()
    st = status(client)
    assert st == {"enabled": False, "last_upload_at": None, "last_object": None, "last_error": None,
                  "last_error_at": None, "pending_records": 0, "dropped_records": 0}


def test_lease_prevents_a_second_upload_of_the_same_site(client, receiver, local_vet):
    make_site(client)
    put_logs(client, {**LOGS, "s3_endpoint": f"http://127.0.0.1:{receiver.port}"})
    token = edge_token(client)
    ship(client, token, [rec(utcnow() - timedelta(hours=2))])
    now = utcnow()
    with SessionLocal() as db:
        from app import kv

        kv.set_json(db, logexport.STATUS_KEY.format(1), {"lease_until": (now + timedelta(minutes=5)).isoformat()})
        db.commit()
    assert run_job(now) == []
    assert run_job(now + timedelta(minutes=6)) == [1]
    assert len(receiver.requests) == 1


# ------------------------------------------------------------------ test endpoint

def test_test_endpoint_writes_a_tiny_object(client, s3_server, local_vet, monkeypatch):
    make_site(client)
    # works before export is enabled, with the saved settings
    put_logs(client, moto_logs(s3_server, enabled=False))
    r = client.post(f"{S}/logs/test")
    assert r.status_code == 200 and r.json() == {"ok": True, "error": None}
    s3, keys = _objects(s3_server)
    assert keys == ["cdn/example.com/.pcdn-test"]
    assert any(a["action"] == "logs.test" and a["detail"] == {"ok": True}
               for a in client.get("/api/v1/audit").json())

    put_logs(client, moto_logs(s3_server, bucket="missing-bucket"))
    r = client.post(f"{S}/logs/test").json()
    assert r["ok"] is False and "HTTP 404" in r["error"]

    put_logs(client, {**moto_logs(s3_server), "enabled": False, "access_key": ""})
    r = client.post(f"{S}/logs/test").json()
    assert r["ok"] is False and "کامل نیست" in r["error"]

    monkeypatch.setattr(settings, "capi_config_rate", 2)
    routes_platform._test_hits.clear()
    assert [client.post(f"{S}/logs/test").status_code for _ in range(3)] == [200, 200, 429]
    assert client.post("/api/v1/sites/nope.com/logs/test").status_code == 404


def test_status_requires_admin_and_known_site(client):
    make_site(client)
    assert client.get(f"{S}/logs/status", headers={"Authorization": "Bearer nope"}).status_code == 401
    assert client.get("/api/v1/sites/nope.com/logs/status").status_code == 404


def test_crypto_rotation_and_drop_cover_integration_secrets(client, monkeypatch):
    k1, k2 = crypto.generate_key(), crypto.generate_key()
    monkeypatch.setattr(settings, "data_encryption_key", k1)
    make_site(client)
    put_logs(client, LOGS)
    hooks = client.put(f"{S}/config/webhooks", json={"items": [
        {"url": "https://hooks.public.example/x", "events": ["ssl.issued"]}]}).json()
    (hid, secret), = hooks["new_secrets"].items()
    with engine.connect() as c:
        before = c.execute(text("SELECT integration_secrets FROM sites")).scalar()
    monkeypatch.setattr(settings, "data_encryption_key", f"{k2},{k1}")
    with SessionLocal() as db:
        assert crypto.rotate_all(db) == 3  # the challenge secret + the 2 integration secrets
    monkeypatch.setattr(settings, "data_encryption_key", k2)
    with SessionLocal() as db:
        site = db.scalar(select(Site))
        assert site.integration_secrets != before
        assert site_secrets.logs_secret(site) == "SECRET/KEY+1" and site_secrets.webhook_secret(site, hid) == secret
        assert crypto.status(db)["readable"] is True
    # losing the key: the integration secrets are forgotten, the GET shows it
    monkeypatch.setattr(settings, "data_encryption_key", crypto.generate_key())
    with SessionLocal() as db:
        assert "example.com" in crypto.drop_unreadable(db)
    assert client.get(f"{S}/config/logs").json()["secret_key_set"] is False
    assert client.get(f"{S}/config/webhooks").json()["items"][0]["secret_set"] is False
