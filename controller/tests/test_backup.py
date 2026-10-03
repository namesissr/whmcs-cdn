"""Backups: archive contents, SQLite + PostgreSQL restore, encryption, retention, S3 upload, scheduling."""

import datetime as dt
import json
import os
import shutil
import sqlite3
import tarfile

import httpx
import pytest
from sqlalchemy import create_engine, text

from app import alerts, backup, migrate, scheduler
from app.config import settings
from app.db import SessionLocal
from app.models import Site, State, utcnow

PASS = "correct horse battery staple"


@pytest.fixture()
def env(tmp_path, monkeypatch):
    """Backup settings pointing into tmp_path, with a fake PowerDNS DB and acme home."""
    pdns_db = tmp_path / "pdns-data" / "pdns.sqlite3"
    pdns_db.parent.mkdir()
    c = sqlite3.connect(pdns_db)
    c.execute("PRAGMA journal_mode=WAL")  # like PowerDNS' gsqlite3 backend
    c.execute("CREATE TABLE cryptokeys (id INTEGER PRIMARY KEY, domain TEXT, content TEXT)")
    c.execute("INSERT INTO cryptokeys (domain, content) VALUES ('example.com', 'Private-key-format: v1.2')")
    c.commit()
    c.close()
    os.chmod(pdns_db, 0o640)
    acme = tmp_path / "acme"
    (acme / "ca").mkdir(parents=True)
    (acme / "account.conf").write_text("ACCOUNT_EMAIL='admin@example.com'\n")
    for k, v in {"backup_dir": str(tmp_path / "backups"), "backup_pdns_db": str(pdns_db), "acme_home": str(acme),
                 "backup_passphrase": "", "backup_keep": 14, "backup_s3_endpoint": "", "backup_s3_keep": 0,
                 "backup_enabled": True, "backup_hour": 2}.items():
        monkeypatch.setattr(settings, k, v)
    return tmp_path


def members(path, passphrase=None):
    work = os.path.dirname(path) + "/.inspect"
    shutil.rmtree(work, ignore_errors=True)
    os.makedirs(work)
    out, manifest = backup.open_archive(path, passphrase, work)
    names = sorted(os.listdir(out))
    return names, manifest


# ------------------------------------------------------------------ SQLite end to end

def test_sqlite_backup_and_restore(client, env):
    client.post("/api/v1/sites", json={"domain": "example.com", "origin_ip": "93.184.216.34"})
    client.post("/api/v1/sites", json={"domain": "second.org"})
    res = backup.create_backup(upload=False)
    assert res["name"].startswith("pcdn-backup-") and res["name"].endswith(".tar.gz") and not res["encrypted"]
    assert oct(os.stat(res["path"]).st_mode & 0o777) == "0o600"
    names, manifest = members(res["path"])
    assert names == ["acme", "controller.sqlite3", "manifest.json", "pdns.sqlite3"]
    assert manifest["contents"]["controller"]["kind"] == "sqlite" and manifest["alembic_revision"] == migrate.head_revision()

    # disaster: sites deleted, PowerDNS DB corrupted, acme home lost
    assert client.delete("/api/v1/sites/example.com").status_code == 200
    with SessionLocal() as db:
        db.add(State(key="junk", value="after-backup"))
        db.commit()
    with open(settings.backup_pdns_db, "wb") as f:
        f.write(b"garbage")
    shutil.rmtree(settings.acme_home)

    out = backup.restore(res["path"], pdns_target=settings.backup_pdns_db, acme_target=settings.acme_home)
    assert out["restored"][0] == "controller database"
    domains = [s["domain"] for s in client.get("/api/v1/sites").json()]
    assert domains == ["example.com", "second.org"]
    with SessionLocal() as db:
        assert db.get(State, "junk") is None
        assert len(db.query(Site).filter_by(domain="example.com").one().records) == 2
    assert oct(os.stat(settings.backup_pdns_db).st_mode & 0o777) == "0o640"  # owner/mode kept for PowerDNS
    c = sqlite3.connect(settings.backup_pdns_db)
    assert c.execute("SELECT content FROM cryptokeys").fetchone()[0] == "Private-key-format: v1.2"
    c.close()
    assert os.path.exists(os.path.join(settings.acme_home, "account.conf"))
    assert any(".before-restore-" in f for f in os.listdir(os.path.dirname(settings.backup_pdns_db)))


def test_pdns_copy_from_read_only_location(env):
    """The PowerDNS volume is mounted read-only in the controller container."""
    src = settings.backup_pdns_db
    os.chmod(os.path.dirname(src), 0o555)
    try:
        dst = str(env / "copy.sqlite3")
        backup.sqlite_copy(src, dst)
        assert sqlite3.connect(dst).execute("SELECT count(*) FROM cryptokeys").fetchone()[0] == 1
    finally:
        os.chmod(os.path.dirname(src), 0o755)


def test_pdns_copy_fallback_when_sqlite_cannot_open_read_only(env, monkeypatch):
    """A WAL database on a read-only mount without a usable -shm file: copy the files first."""
    src = settings.backup_pdns_db
    writer = sqlite3.connect(src)  # keep a connection open so -wal holds uncheckpointed data
    writer.execute("INSERT INTO cryptokeys (domain, content) VALUES ('second.com', 'k2')")
    writer.commit()
    real_connect = sqlite3.connect

    def connect(target, *a, **kw):
        if kw.get("uri"):
            raise sqlite3.OperationalError("unable to open database file")
        return real_connect(target, *a, **kw)

    monkeypatch.setattr(backup.sqlite3, "connect", connect)
    dst = str(env / "copy.sqlite3")
    backup.sqlite_copy(src, dst)
    monkeypatch.undo()
    writer.close()
    rows = sqlite3.connect(dst).execute("SELECT domain FROM cryptokeys ORDER BY id").fetchall()
    assert rows == [("example.com",), ("second.com",)]


def test_missing_parts_are_warnings_not_failures(client, env, monkeypatch):
    monkeypatch.setattr(settings, "backup_pdns_db", str(env / "nope.sqlite3"))
    monkeypatch.setattr(settings, "acme_home", str(env / "no-acme"))
    res = backup.create_backup(upload=False)
    assert len(res["warnings"]) == 2
    names, _ = members(res["path"])
    assert names == ["controller.sqlite3", "manifest.json"]
    with pytest.raises(backup.BackupError, match="no PowerDNS database"):
        backup.restore(res["path"], controller=False, pdns_target=str(env / "x.sqlite3"))


# ------------------------------------------------------------------ encryption

def test_encrypted_backup_round_trip_and_wrong_passphrase(client, env, monkeypatch):
    client.post("/api/v1/sites", json={"domain": "example.com"})
    monkeypatch.setattr(settings, "backup_passphrase", PASS)
    res = backup.create_backup(upload=False)
    assert res["encrypted"] and res["name"].endswith(".tar.gz.enc")
    with open(res["path"], "rb") as f:
        head = f.read(4096)
    assert head.startswith(b"PCDNBAK") and b"manifest" not in head
    with pytest.raises(tarfile.TarError):
        tarfile.open(res["path"], "r:gz").getmembers()

    with pytest.raises(backup.BackupError, match="wrong passphrase"):
        backup.restore(res["path"], passphrase="wrong")
    with pytest.raises(backup.BackupError, match="encrypted"):
        backup.restore(res["path"], passphrase="")
    client.delete("/api/v1/sites/example.com")
    backup.restore(res["path"])  # BACKUP_PASSPHRASE from settings
    assert [s["domain"] for s in client.get("/api/v1/sites").json()] == ["example.com"]


def test_chunked_encryption_detects_truncation_and_tampering(tmp_path, monkeypatch):
    monkeypatch.setattr(backup, "CHUNK", 1000)
    monkeypatch.setattr(backup, "SCRYPT_LOG2N", 10)  # fast KDF for the test
    data = os.urandom(5500)
    (tmp_path / "plain").write_bytes(data)
    backup.encrypt_file(str(tmp_path / "plain"), str(tmp_path / "enc"), PASS)
    backup.decrypt_file(str(tmp_path / "enc"), str(tmp_path / "dec"), PASS)
    assert (tmp_path / "dec").read_bytes() == data

    enc = (tmp_path / "enc").read_bytes()
    one_chunk = 4 + 1000 + 16
    (tmp_path / "trunc").write_bytes(enc[:-(4 + 500 + 16)])  # drop the last (short) chunk
    with pytest.raises(backup.BackupError, match="truncated"):
        backup.decrypt_file(str(tmp_path / "trunc"), str(tmp_path / "x"), PASS)
    tampered = bytearray(enc)
    tampered[backup.HEADER_LEN + one_chunk + 50] ^= 1
    (tmp_path / "tampered").write_bytes(bytes(tampered))
    with pytest.raises(backup.BackupError, match="authentication failed"):
        backup.decrypt_file(str(tmp_path / "tampered"), str(tmp_path / "x"), PASS)
    with pytest.raises(backup.BackupError, match="wrong passphrase"):
        backup.decrypt_file(str(tmp_path / "enc"), str(tmp_path / "x"), "nope")
    # empty input still produces a valid (single, final) chunk
    (tmp_path / "empty").write_bytes(b"")
    backup.encrypt_file(str(tmp_path / "empty"), str(tmp_path / "empty.enc"), PASS)
    backup.decrypt_file(str(tmp_path / "empty.enc"), str(tmp_path / "empty.dec"), PASS)
    assert (tmp_path / "empty.dec").read_bytes() == b""


# ------------------------------------------------------------------ retention

def test_local_retention(tmp_path):
    names = [f"pcdn-backup-202601{d:02d}T020000Z.tar.gz" + (".enc" if d % 2 else "") for d in range(1, 11)]
    for n in names:
        (tmp_path / n).write_bytes(b"x")
    (tmp_path / "unrelated.txt").write_text("keep me")
    removed = backup.prune_local(str(tmp_path), 3)
    assert removed == names[:7]
    assert sorted(os.listdir(tmp_path)) == sorted(names[7:] + ["unrelated.txt"])
    assert backup.prune_local(str(tmp_path), 0) == []


# ------------------------------------------------------------------ S3 (s3_server fixture: conftest.py)

def test_sigv4_matches_botocore(monkeypatch):
    pytest.importorskip("botocore")
    import botocore.auth
    from botocore.auth import S3SigV4Auth
    from botocore.awsrequest import AWSRequest
    from botocore.credentials import Credentials

    now = dt.datetime(2026, 9, 28, 12, 0, 0, tzinfo=dt.timezone.utc)
    c = backup.S3Client("https://s3.ir-thr-at1.arvanstorage.ir", "my-bucket", "AKID", "SECRET/KEY",
                        "ir-thr-at1")
    for key, query in (("pcdn-backups/pcdn-backup-20260928T120000Z.tar.gz.enc", {}),
                       ("", {"list-type": "2", "prefix": "pcdn-backups/"})):
        url, path = c._url_and_path(key)
        payload = backup.hashlib.sha256(b"").hexdigest()
        ours = c.sign("GET", url, path, query, payload, now=now)

        qs = "&".join(f"{k}={backup.quote(v, safe='-_.~')}" for k, v in query.items())
        req = AWSRequest(method="GET", url=url + ("?" + qs if qs else ""),
                         headers={"x-amz-content-sha256": payload})
        signer = S3SigV4Auth(Credentials("AKID", "SECRET/KEY"), "s3", "ir-thr-at1")
        monkeypatch.setattr(botocore.auth, "get_current_datetime", lambda: now.replace(tzinfo=None))
        signer.add_auth(req)
        theirs = req.headers["Authorization"]
        assert ours["Authorization"].split("Signature=")[1] == theirs.split("Signature=")[1], key


def test_s3_upload_list_download_and_remote_retention(client, env, s3_server, monkeypatch):
    for k, v in {"backup_s3_endpoint": s3_server, "backup_s3_bucket": "pcdn", "backup_s3_access_key": "AK",
                 "backup_s3_secret_key": "SK", "backup_s3_region": "ir-thr-at1",
                 "backup_s3_prefix": "cdn/", "backup_s3_keep": 2, "backup_passphrase": PASS}.items():
        monkeypatch.setattr(settings, k, v)
    client.post("/api/v1/sites", json={"domain": "example.com"})
    results = []
    for i in range(3):
        now = dt.datetime(2026, 9, 20 + i, 2, 0, tzinfo=dt.timezone.utc)
        results.append(backup.create_backup(now=now))
    assert all(r["uploaded"] for r in results)
    assert results[-1]["pruned_remote"] == ["cdn/" + results[0]["name"]]
    s3 = backup.S3Client.from_settings()
    keys = [o["key"] for o in s3.list("cdn/")]
    assert keys == ["cdn/" + r["name"] for r in results[1:]]

    # disaster recovery from object storage via the CLI
    from app import manage

    client.delete("/api/v1/sites/example.com")
    assert manage.main(["restore", "s3:" + keys[-1], "--yes"]) == 0
    assert [s["domain"] for s in client.get("/api/v1/sites").json()] == ["example.com"]


def test_s3_errors_are_backup_errors(env):
    def handler(request):
        return httpx.Response(403, text="<Error><Code>SignatureDoesNotMatch</Code></Error>")

    s3 = backup.S3Client("https://s3.example", "b", "a", "s", transport=httpx.MockTransport(handler))
    (env / "f").write_bytes(b"data")
    with pytest.raises(backup.BackupError, match="HTTP 403 .*SignatureDoesNotMatch"):
        s3.put_file("k", str(env / "f"))


# ------------------------------------------------------------------ scheduler job + alerts

def test_backup_job_schedule_failure_alert_and_recovery(client, env, alert_settings, monkeypatch):
    sent = []
    monkeypatch.setattr(alerts, "send", lambda sev, title, body: sent.append((sev, title, body)) or {"x": "ok"})
    monkeypatch.setattr(alerts, "configured_channels", lambda: [type("Fake", (), {"name": "x"})()])
    day = utcnow().replace(hour=1, minute=0, second=0, microsecond=0)

    def run(at):
        with SessionLocal() as db:
            scheduler.job_backup(db, now=at)

    run(day)  # before BACKUP_HOUR
    assert backup.list_local() == []
    run(day.replace(hour=2))
    assert len(backup.list_local()) == 1
    run(day.replace(hour=5))  # once per day
    assert len(backup.list_local()) == 1

    # next day the database dump fails -> alert, retried after an hour, not every tick
    real_dump, broken = backup.dump_controller_db, {"on": True}

    def dump(out):
        if broken["on"]:
            raise backup.BackupError("pg_dump failed: connection refused")
        return real_dump(out)

    monkeypatch.setattr(backup, "dump_controller_db", dump)
    nxt = day + dt.timedelta(days=1, hours=1)
    run(nxt.replace(hour=3))
    assert [c["key"] for c in alerts.open_alerts()] == ["backup_not_offsite", "backup_failed"]
    assert sent[-1][0] == "critical" and "connection refused" in sent[-1][2]
    n = len(sent)
    run(nxt.replace(hour=3, minute=30))
    assert len(sent) == n

    broken["on"] = False
    run(nxt.replace(hour=4, minute=5))
    assert len(backup.list_local()) == 2
    # SPEC §23.3: without BACKUP_S3_* the info alert backup_not_offsite stays open
    assert [c["key"] for c in alerts.open_alerts()] == ["backup_not_offsite"]
    assert sent[-1][0] == "resolved" and "پشتیبان‌گیری دوباره موفق شد" in sent[-1][2]
    with SessionLocal() as db:
        assert db.get(State, "backup:last_success_day").value == nxt.date().isoformat()
    deep = client.get("/healthz/deep").json()
    assert deep["backup"]["enabled"] is True and deep["backup"]["failing"] is False


def test_manage_backup_verify_cli(client, env, capsys):
    from app import manage

    # no backups yet -> fails cleanly, non-zero, with a clear message (never crashes)
    with pytest.raises(SystemExit) as e:
        manage.main(["backup-verify"])
    assert "no local backups" in str(e.value.code)

    client.post("/api/v1/sites", json={"domain": "example.com", "origin_ip": "93.184.216.34"})
    assert manage.main(["backup", "--no-upload"]) == 0
    capsys.readouterr()
    # the newest backup restores into a throwaway SQLite DB at head
    assert manage.main(["backup-verify"]) == 0
    out = capsys.readouterr().out
    assert out.startswith("OK:") and "throwaway SQLite" in out and migrate.head_revision() in out

    # a tampered/non-backup file fails cleanly
    bad = env / "backups" / "pcdn-backup-20260101T000000Z.tar.gz"
    bad.write_bytes(b"not a real archive")
    with pytest.raises(SystemExit) as e:
        manage.main(["backup-verify", str(bad)])
    # a non-zero exit (string message or code 1), never a crash
    assert e.value.code != 0 and "FAIL" in str(e.value.code)


def test_manage_backup_and_restore_cli(client, env, capsys):
    from app import manage

    client.post("/api/v1/sites", json={"domain": "example.com"})
    assert manage.main(["backup", "--no-upload"]) == 0
    path = json.loads(capsys.readouterr().out)["path"]
    with pytest.raises(SystemExit, match="--yes"):
        manage.main(["restore", path])
    client.delete("/api/v1/sites/example.com")
    extract = env / "extracted"
    assert manage.main(["restore", path, "--yes", "--extract", str(extract)]) == 0
    assert (extract / "controller.sqlite3").exists() and (extract / "acme" / "account.conf").exists()
    assert [s["domain"] for s in client.get("/api/v1/sites").json()] == ["example.com"]
    assert manage.main(["backups"]) == 0
    assert os.path.basename(path) in capsys.readouterr().out


# ------------------------------------------------------------------ PostgreSQL

def test_postgres_dump_and_restore(pg_url, tmp_path):
    if shutil.which("pg_dump") is None:
        pytest.skip("pg_dump not installed")
    from app import migrate

    eng = create_engine(pg_url)
    migrate.upgrade(eng)
    with eng.begin() as c:
        c.execute(text("INSERT INTO state (key, value) VALUES ('hello', 'world')"))
    path = backup.dump_controller_db(str(tmp_path), url=pg_url)
    assert path.endswith("controller.pgdump")
    with eng.begin() as c:
        c.execute(text("DELETE FROM state"))
        c.execute(text("INSERT INTO state (key, value) VALUES ('after', 'backup')"))
    eng.dispose()

    backup.restore_controller_db(path, "postgresql", url=pg_url)
    with eng.connect() as c:
        assert c.execute(text("SELECT key, value FROM state")).all() == [("hello", "world")]
    assert migrate.current_revision(eng) == migrate.head_revision()
    eng.dispose()

    with pytest.raises(backup.BackupError, match="holds a sqlite database"):
        backup.restore_controller_db(path, "sqlite", url=pg_url)


def test_postgres_dump_with_multi_host_ha_url(pg_url, tmp_path):
    """HA setups list both database servers; libpq picks the writable one."""
    if shutil.which("pg_dump") is None:
        pytest.skip("pg_dump not installed")
    from sqlalchemy.engine import make_url

    from app import migrate, leader

    u = make_url(pg_url)
    multi = (f"postgresql+psycopg://{u.username}:{u.password}@/{u.database}"
             f"?host=127.0.0.1:1&host={u.host}:{u.port or 5432}&target_session_attrs=read-write")
    eng = create_engine(multi)
    migrate.upgrade(eng)
    eng.dispose()
    assert backup.dump_controller_db(str(tmp_path), url=multi).endswith(".pgdump")
    e = leader.PgLeader(multi)
    try:
        assert e.check()
    finally:
        e.release()


def test_manage_dns_sync_after_restore(client, fake_pdns, capsys):
    from app import manage

    client.post("/api/v1/sites", json={"domain": "example.com", "origin_ip": "93.184.216.34"})
    fake_pdns.zones.clear()  # e.g. PowerDNS restored from an older backup
    assert manage.main(["dns-sync"]) == 0
    assert "example.com." in fake_pdns.zones and "zones failed: 0" in capsys.readouterr().out
    fake_pdns.down = True
    with pytest.raises(SystemExit):
        manage.main(["dns-sync"])
