"""Upgrade / rollback paths of REAL data (not just empty schemas, see test_migrations.py).

An operator database sits at an old revision (production was at 0012 before the recent waves);
the next controller release upgrades it to head on startup. For each old revision an operator can
still be at (tests/fixtures/upgrade_seed.SEED_REVISIONS) this:

1. migrates a fresh database to that revision and seeds it with raw SQL that is valid for exactly
   that schema (sites + configs incl. tunnel/pools, proxied/pooled records, edges of both groups with
   extra addresses, usage with full details, API keys, audit rows, encrypted secrets ...);
2. upgrades it to head and checks that no row was lost or changed, the schema matches the models,
   and the app's main read paths work on it: site_to_dict, build_edge_config (also over HTTP with
   the edges' EXISTING tokens), DNS zone building, analytics (site, platform, tunnel, live), the
   customer API with existing keys, decryption of every stored secret;
3. downgrades ONE revision at a time back to the seeded revision (every downgrade must run and
   keep the seeded rows), checks the database equals the seeded snapshot, upgrades again and checks
   that the head state is identical to the first upgrade, then writes new rows through the ORM
   (sequences / autoincrement survived the table rebuilds).

Also: a stepwise upgrade (one release at a time) and an encrypted backup taken at an old revision,
restored into a fresh database and upgraded (the disaster-recovery path), checked with the same
verification code the DR drill uses (tools/drill/drill_check.py).

Runs on SQLite always and on PostgreSQL when PCDN_TEST_PG_URL is set (see conftest.pg_url).
"""

import datetime as dt
import importlib.util
import json
import os
import sqlite3

import pytest
from alembic.autogenerate import compare_metadata
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, inspect, select, text
from sqlalchemy.orm import Session

from app import crypto, dnsbuild, live, migrate, services, site_secrets, tunnel
from app.config import settings
from app.db import Base, get_db
from app.models import ApiKey, Edge, Record, Site, utcnow
from tests.fixtures import upgrade_seed as S

HEAD = migrate.head_revision()
# tables written by every seed (exist since the baseline)
BASE_TABLES = ("sites", "records", "edges", "usage_hourly", "security_events", "purges", "state")


def chain() -> list[str]:
    """Every revision, oldest first."""
    script = ScriptDirectory.from_config(migrate.alembic_config())
    return [r.revision for r in reversed(list(script.walk_revisions("base", "heads")))]


def down_revision(rev: str) -> str | None:
    script = ScriptDirectory.from_config(migrate.alembic_config())
    return script.get_revision(rev).down_revision


@pytest.fixture(params=["sqlite", "postgresql"])
def any_engine(request, tmp_path):
    if request.param == "sqlite":
        eng = create_engine(f"sqlite:///{tmp_path}/up.db")
    else:
        eng = create_engine(request.getfixturevalue("pg_url"))
    yield eng
    eng.dispose()


@pytest.fixture()
def enc_key(monkeypatch):
    """The DATA_ENCRYPTION_KEY the seeded secrets were encrypted with."""
    monkeypatch.setattr(settings, "data_encryption_key", S.FERNET_KEY)
    yield S.FERNET_KEY


def schema_diff(engine):
    with engine.connect() as conn:
        ctx = MigrationContext.configure(conn, opts={"compare_type": True, "compare_server_default": True})
        return compare_metadata(ctx, Base.metadata)


def _norm(v):
    if isinstance(v, memoryview):
        return bytes(v)
    return v


# written by the read paths themselves (an edge's config poll, a customer API call): not compared
VOLATILE = {("edges", "last_seen_at"), ("api_keys", "last_used_at")}


def snapshot(engine) -> dict:
    """{table: sorted list of {column: value}} of every application table (alembic_version left out;
    VOLATILE columns left out)."""
    out = {}
    insp = inspect(engine)
    with engine.connect() as conn:
        for t in sorted(insp.get_table_names()):
            if t == "alembic_version":
                continue
            rows = [{k: _norm(v) for k, v in m.items() if (t, k) not in VOLATILE}
                    for m in conn.execute(text(f'SELECT * FROM "{t}"')).mappings()]
            out[t] = sorted(rows, key=lambda r: json.dumps(r, sort_keys=True, default=str))
    return out


def counts(engine, tables) -> dict:
    present = set(inspect(engine).get_table_names())
    with engine.connect() as conn:
        return {t: conn.execute(text(f'SELECT count(*) FROM "{t}"')).scalar_one() for t in tables if t in present}


def seed_at(engine, rev: str) -> dict:
    assert migrate.upgrade(engine, rev) == rev
    with engine.begin() as conn:
        return S.seed(conn, rev)


# ------------------------------------------------------------------ the checks at head

def check_rows(engine, exp: dict):
    """Seeded rows survived with their values; columns added later got their defaults."""
    rev = exp["revision"]
    with engine.connect() as c:
        assert c.execute(text("SELECT count(*) FROM sites")).scalar_one() == 3
        for dom, n in exp["records"].items():
            assert c.execute(text("SELECT count(*) FROM records WHERE site_id = :s"),
                             {"s": exp["site_ids"][dom]}).scalar_one() == n
        # 0017/0018 record columns: NULL / 0 on every existing record (today's behaviour)
        assert c.execute(text("SELECT count(*) FROM records WHERE weight IS NOT NULL OR health_fail <> 0 "
                              "OR storage_bucket IS NOT NULL OR health_protocol IS NOT NULL")).scalar_one() == 0
        edges = {r.name: r for r in c.execute(text(
            'SELECT name, token_hash, "group", capacity_mbps, shed, probe_fail, probe_fail4, probe_fail6, '
            "shed_high, shield, cpu_high FROM edges"))}
        assert set(edges) == set(exp["tokens"])
        for name, token in exp["tokens"].items():
            assert edges[name].token_hash == S.sha256(token)
            assert edges[name].probe_fail == 0 and edges[name].probe_fail4 == 0 and edges[name].shed_high == 0
        assert edges["ir-tun-1"].group == "tunnel" and edges["ir-thr-1"].group == "general"
        # 0013: nobody is a shield after the upgrade unless the seed (>= 0013) said so
        assert bool(edges["de-fsn-1"].shield) is S.at_least(rev, "0013")
        assert not edges["ir-thr-1"].shield
        purge = c.execute(text("SELECT urls, prefixes, everything FROM purges")).one()
        assert json.loads(purge.urls) == [f"https://{S.SHOP}/index.html"]
        assert json.loads(purge.prefixes) == (["/static/"] if S.at_least(rev, "0006") else [])
        assert not purge.everything
        usage = c.execute(text("SELECT count(*), sum(bytes), sum(requests) FROM usage_hourly")).one()
        assert tuple(usage) == (len(exp["usage"]), sum(u[2] for u in exp["usage"]), sum(u[3] for u in exp["usage"]))
        if S.at_least(rev, "0012"):
            assert c.execute(text("SELECT count(*) FROM audit_log")).scalar_one() == 4
            site = c.execute(text("SELECT reseller_client_id, reseller_label FROM sites WHERE domain = :d"),
                             {"d": S.SHOP}).one()
            assert tuple(site) == (42, "Reseller A — shop")
        if S.at_least(rev, "0010"):
            assert c.execute(text("SELECT count(*) FROM edge_addresses")).scalar_one() == 2
        # 0021: owner_kind derived from the reseller tag; no operator note / billing anchor anywhere
        kinds = dict(c.execute(text("SELECT domain, owner_kind FROM sites")).all())
        assert kinds == {S.SHOP: "reseller" if S.at_least(rev, "0008") else "client",
                         S.TUNNEL: "client", S.SUSPENDED: "client"}
        assert c.execute(text("SELECT count(*) FROM sites WHERE operator_note IS NOT NULL "
                              "OR billing_since IS NOT NULL")).scalar_one() == 0


def check_read_paths(engine, exp: dict):
    """site_to_dict, build_edge_config, DNS building, analytics and secrets on the upgraded DB."""
    rev, sid = exp["revision"], exp["site_ids"]
    with Session(engine) as db:
        st = crypto.status(db)
        assert st["readable"] and st["error"] is None, st
        assert st["plaintext"] == 1  # the legacy plaintext secret of the suspended site

        sites = {s.domain: s for s in db.scalars(select(Site))}
        for dom, secret in exp["secrets"].items():
            assert sites[dom].secret == secret
        assert sites[S.SHOP].ssl_key == exp["ssl_keys"][S.SHOP]

        # ---- site_to_dict (admin API / WHMCS read path)
        shop = services.site_to_dict(db, sites[S.SHOP])
        assert shop["status"] == "active" and shop["dnssec"] is True
        assert len(shop["records"]) == exp["records"][S.SHOP]
        assert shop["ssl"]["status"] == "active" and set(shop["ssl"]["names"]) == {S.SHOP, "www." + S.SHOP}
        assert shop["config"]["pools"]["pools"][0]["name"] == "web"  # the stored section survived
        assert shop["config"]["cache"]["edge_ttl"] == 3600 and shop["config"]["waf"]["mode"] == "block"
        assert shop["plan"]["features"]["load_balancer"] is True
        assert shop["settings"]["blocked_ips"] == ["45.12.0.0/16", "103.21.244.7"]
        month = services.month_start()
        assert shop["usage_month"]["bytes"] == sum(u[2] for u in exp["usage"] if u[0] == sid[S.SHOP] and u[1] >= month)
        assert shop["reseller_client_id"] == (42 if S.at_least(rev, "0008") else None)
        api = next(r for r in shop["records"] if r["name"] == "api")
        assert api["pool"] == "web" and api["weight"] is None and api["storage"] is None
        mail = next(r for r in shop["records"] if r["name"] == "mail" and r["type"] == "A")
        assert mail["health"]["fail"] == 0 and mail["health"]["advertised"] is True
        tun = services.site_to_dict(db, sites[S.TUNNEL])
        assert tun["config"]["tunnel"]["enabled"] is True
        assert [p["id"] for p in tun["config"]["tunnel"]["paths"]] == ["p1", "p2"]
        assert services.site_to_dict(db, sites[S.SUSPENDED])["status"] == "suspended"
        if S.at_least(rev, "0015"):
            assert shop["config"]["webhooks"]["items"][0]["id"] == "wh_0123abcd"
            assert site_secrets.logs_secret(sites[S.SHOP]) == "LOGS-S3-SECRET"
            assert site_secrets.values(sites[S.SHOP])  # every integration secret readable

        # ---- build_edge_config (what every edge polls)
        edges = {e.name: e for e in db.scalars(select(Edge))}
        for name, e in edges.items():
            cfg = services.build_edge_config(db, e)
            by = {s["domain"]: s for s in cfg["sites"]}
            assert set(by) == {S.SHOP, S.TUNNEL, S.SUSPENDED}, name
            hosts = {h["name"]: h["origin"] for h in by[S.SHOP]["hosts"]}
            assert hosts[S.SHOP] == {"address": "185.143.233.10", "port": None}
            assert hosts["www." + S.SHOP] == {"address": "185.143.233.10", "port": None}  # in-zone CNAME
            assert hosts["api." + S.SHOP] == {"pool": "web"}
            assert by[S.SHOP]["ssl"]["key"] == exp["ssl_keys"][S.SHOP]
            assert by[S.SHOP]["secret"] == exp["secrets"][S.SHOP]
            assert by[S.SHOP]["ssl_options"]["force_https"] is True
            if S.at_least(rev, "0014"):
                oc = by[S.SHOP]["ssl_options"]["origin_client"]
                assert oc["mode"] == "custom" and oc["key"] == exp["origin_client_key"]
            t = by[S.TUNNEL]
            assert t["edge_group"] == "tunnel" and t["tunnel"]["enabled"] is True
            assert [p["path"] for p in t["tunnel"]["paths"]] == ["/ws-secret", "/grpc-x"]
            assert t["tunnel"]["per_connection_mbps"] == 50 and t["tunnel"]["max_connections"] == 200
            assert by[S.SUSPENDED]["status"] == "suspended" and by[S.SUSPENDED]["cache"]["enabled"] is False
            assert by[S.SUSPENDED]["secret"] == exp["secrets"][S.SUSPENDED]
            assert cfg["node"]["name"] == name
        # shield (0013+): the general group's shield edge is a peer of the other general edge
        sh = services.build_edge_config(db, edges["ir-thr-1"])["shield"]
        assert sh["self"] is False

        # ---- DNS zones (PowerDNS sync path)
        online = services.online_edges(db)
        assert {e.name for e in online} == set(exp["tokens"])
        for s in sites.values():
            rrsets = dnsbuild.build_rrsets(s, online)
            names = {(r["name"], r["type"]) for r in rrsets}
            assert any(n == dnsbuild.dot(s.domain) for n, _ in names), names
        shop_rr = {(r["name"], r["type"]) for r in dnsbuild.build_rrsets(sites[S.SHOP], online)}
        assert ("mail." + S.SHOP + ".", "LUA") in shop_rr and (S.SHOP + ".", "MX") in shop_rr

        # ---- analytics
        from app.routes_v2 import platform_analytics, site_analytics

        a = site_analytics(db, sites[S.SHOP], "24h")
        in_window = [u for u in exp["usage"] if u[0] == sid[S.SHOP] and u[1] >= utcnow().replace(
            minute=0, second=0, microsecond=0) - dt.timedelta(hours=23)]
        assert a["totals"]["requests"] == sum(u[3] for u in in_window)
        assert a["totals"]["status"]["5xx"] == 10 * len(in_window)
        assert a["totals"]["security"]["waf"] == 3 * len(in_window)
        assert {c["code"] for c in a["countries"]} == {"IR", "DE"}
        p = platform_analytics(period="30d", db=db)
        assert p["totals"]["requests"] == sum(u[3] for u in exp["usage"]) - 7  # the 40-day-old row is out
        ts = tunnel.stats(db, sites[S.TUNNEL], 24)
        assert ts["totals"]["sessions"] == sum(10 + k for k in range(6))
        assert ts["by_protocol"]["ws"] == 7 * 6
        lv = live.series(db, sites[S.SHOP], 60)
        assert lv["totals"]["requests"] == exp.get("live_requests", 0)


def check_http(engine, exp: dict):
    """Edges fetch their config with their EXISTING tokens; customers use their EXISTING API keys."""
    from app import routes_capi
    from app.main import app

    def db_override():
        db = Session(engine)
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = db_override
    routes_capi._hits.clear()
    try:
        c = TestClient(app)  # no `with`: the lifespan (init_db on the global engine) is not run
        for name, token in exp["tokens"].items():
            r = c.get("/edge/v1/config", headers={"Authorization": f"Bearer {token}"})
            assert r.status_code == 200, (name, r.text[:300])
            assert {s["domain"] for s in r.json()["sites"]} == {S.SHOP, S.TUNNEL, S.SUSPENDED}
            etag = r.headers["ETag"]
            assert c.get("/edge/v1/config", headers={"Authorization": f"Bearer {token}",
                                                     "If-None-Match": etag}).status_code == 304
        assert c.get("/edge/v1/config", headers={"Authorization": "Bearer edge_wrong"}).status_code == 401
        for dom, key in exp["api_keys"].items():
            r = c.get("/capi/v1/analytics", headers={"Authorization": f"Bearer {key}"})
            assert r.status_code == 200, (dom, r.text[:300])
        if S.at_least(exp["revision"], "0007"):
            assert exp["api_keys"]  # keys exist from 0007 on
    finally:
        app.dependency_overrides.pop(get_db, None)


def check_writes(engine, exp: dict):
    """New rows after the upgrade (and after table rebuilds): ids / sequences still work."""
    with Session(engine) as db:
        site = Site(domain="new-after-upgrade.ir", status="active", features=json.dumps({"tunnel": True}))
        db.add(site)
        db.flush()
        assert site.id not in exp["site_ids"].values()
        db.add(Record(site_id=site.id, name="@", type="A", content="185.143.233.40", proxied=True, weight=10))
        db.add(Edge(name="new-edge", ipv4="5.160.9.9", region="home", token_hash=S.sha256("new"), shield=True))
        db.add(ApiKey(site_id=site.id, key_hash=S.sha256("pcdn_new"), name="n", scopes='["stats"]'))
        db.commit()
        assert db.scalar(select(Site).where(Site.domain == "new-after-upgrade.ir")).records[0].weight == 10
        cfg = services.build_edge_config(db, db.scalar(select(Edge).where(Edge.name == "new-edge")))
        assert "new-after-upgrade.ir" in {s["domain"] for s in cfg["sites"]}


def check_head(engine, exp):
    assert migrate.current_revision(engine) == HEAD
    assert schema_diff(engine) == []
    check_rows(engine, exp)
    check_read_paths(engine, exp)
    check_http(engine, exp)


# ------------------------------------------------------------------ tests

@pytest.mark.parametrize("seed_rev", S.SEED_REVISIONS)
def test_upgrade_round_trip_of_seeded_database(any_engine, enc_key, seed_rev):
    exp = seed_at(any_engine, seed_rev)
    seeded = snapshot(any_engine)
    base_counts = counts(any_engine, BASE_TABLES)

    # 1) upgrade to head in one go (what the controller does at startup)
    assert migrate.upgrade(any_engine) == HEAD
    check_head(any_engine, exp)
    at_head = snapshot(any_engine)

    # 2) every downgrade, one revision at a time, back to the seeded revision
    revs = chain()
    for rev in reversed(revs[revs.index(seed_rev) + 1:]):
        target = down_revision(rev)
        migrate.downgrade(any_engine, target)
        assert migrate.current_revision(any_engine) == target, rev
        assert counts(any_engine, BASE_TABLES) == base_counts, f"downgrade of {rev} lost rows"
        with any_engine.connect() as c:  # the seeded secrets / tokens are untouched by every step
            assert dict(c.execute(text("SELECT domain, secret FROM sites")).all())[S.SUSPENDED] == "c3" * 32
    assert migrate.current_revision(any_engine) == seed_rev
    assert snapshot(any_engine) == seeded, "upgrade + downgrade is not lossless"

    # 3) upgrade again: the same head state, and the app still works (incl. writes)
    assert migrate.upgrade(any_engine) == HEAD
    assert snapshot(any_engine) == at_head
    check_head(any_engine, exp)
    check_writes(any_engine, exp)


def test_stepwise_upgrade_from_production_revision(any_engine, enc_key):
    """The operator database was at 0012: upgrading one release at a time ends in the same state
    as the single jump, and every intermediate revision is a working database."""
    exp = seed_at(any_engine, "0012")
    revs = chain()
    for rev in revs[revs.index("0012") + 1:]:
        assert migrate.upgrade(any_engine, rev) == rev
        assert counts(any_engine, ("sites", "records", "edges")) == {"sites": 3, "records": 12, "edges": 3}
    check_head(any_engine, exp)
    check_writes(any_engine, exp)


def test_downgrade_below_seed_keeps_base_rows(any_engine, enc_key):
    """Rolling back further than the release that produced the data (0012 data -> 0003) still works
    and keeps the baseline rows; upgrading again yields a working head."""
    exp = seed_at(any_engine, "0012")
    migrate.upgrade(any_engine)
    base_counts = counts(any_engine, BASE_TABLES)
    revs = chain()
    for rev in reversed(revs[revs.index("0003") + 1:]):
        migrate.downgrade(any_engine, down_revision(rev))
        assert counts(any_engine, BASE_TABLES) == base_counts, rev
    assert migrate.current_revision(any_engine) == "0003"
    assert "audit_log" not in inspect(any_engine).get_table_names()
    migrate.upgrade(any_engine)
    # data of the tables dropped on the way down (audit_log, api_keys, edge_addresses, ...) is gone
    exp_after = dict(exp, revision="0003", api_keys={})
    check_rows(any_engine, exp_after)
    assert schema_diff(any_engine) == []


def test_downgrade_below_0002_with_encrypted_secrets(any_engine, enc_key):
    """0002's downgrade would turn sites.secret back into VARCHAR(64), which cannot hold an encrypted
    secret ("enc:v1:" + Fernet token, ~190 characters). It now refuses with a clear error instead of
    failing half-way (PostgreSQL) or over-filling the column (SQLite). On PostgreSQL the downgrade runs
    in one transaction, so the database stays at head and fully usable. Rollbacks to 0003+ are
    unaffected."""
    exp = seed_at(any_engine, "0004")
    migrate.upgrade(any_engine)
    with pytest.raises(RuntimeError, match="cannot downgrade below 0002"):
        migrate.downgrade(any_engine, "0001")
    if any_engine.dialect.name == "postgresql":
        assert migrate.current_revision(any_engine) == HEAD
        assert schema_diff(any_engine) == []
        check_rows(any_engine, exp)
    with any_engine.connect() as c:
        assert max(len(v) for v, in c.execute(text("SELECT secret FROM sites"))) > 64


def test_seeds_are_valid_for_their_revision_only(tmp_path, enc_key):
    """Guard for the fixture itself: the 0015 seed cannot be written into an 0004 schema."""
    eng = create_engine(f"sqlite:///{tmp_path}/guard.db")
    migrate.upgrade(eng, "0004")
    with pytest.raises(Exception):
        with eng.begin() as conn:
            S.seed(conn, "0015")
    eng.dispose()


# ------------------------------------------------------------------ old backup -> restore -> upgrade (DR)

def _drill_check():
    path = os.path.join(os.path.dirname(__file__), "..", "..", "tools", "drill", "drill_check.py")
    if not os.path.exists(path):
        pytest.skip("tools/drill not present")
    spec = importlib.util.spec_from_file_location("drill_check", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _fake_pdns_db(path, zones: dict[str, bool]):
    """A gsqlite3-shaped PowerDNS database: zones (+ a DNSSEC key for the signed ones)."""
    c = sqlite3.connect(path)
    c.executescript("""
        CREATE TABLE domains (id INTEGER PRIMARY KEY, name VARCHAR(255) NOT NULL, type VARCHAR(8));
        CREATE TABLE records (id INTEGER PRIMARY KEY, domain_id INTEGER, name VARCHAR(255), type VARCHAR(10),
                              content VARCHAR(65535), ttl INTEGER);
        CREATE TABLE cryptokeys (id INTEGER PRIMARY KEY, domain_id INTEGER NOT NULL, flags INT NOT NULL,
                                 active BOOL, published BOOL DEFAULT 1, content TEXT);
    """)
    for zone, signed in zones.items():
        cur = c.execute("INSERT INTO domains (name, type) VALUES (?, 'NATIVE')", (zone,))
        c.execute("INSERT INTO records (domain_id, name, type, content, ttl) VALUES (?, ?, 'SOA', 'ns1. h. 1 2 3 4 5', 300)",
                  (cur.lastrowid, zone))
        if signed:
            c.execute("INSERT INTO cryptokeys (domain_id, flags, active, content) VALUES (?, 257, 1, 'Private-key')",
                      (cur.lastrowid,))
    c.commit()
    c.close()


def test_old_backup_restores_and_upgrades(any_engine, enc_key, tmp_path, monkeypatch):
    """An encrypted backup taken while the database was at 0012 restores into a FRESH database and
    is upgraded to head; the DR drill's verification (drill_check) passes on it, and fails loudly
    when the restored data does not match the dump."""
    from app import backup

    dc = _drill_check()
    exp = seed_at(any_engine, "0012")
    src_url = any_engine.url.render_as_string(hide_password=False)
    pdns_db = tmp_path / "pdns.sqlite3"
    _fake_pdns_db(pdns_db, {S.SHOP: True, S.TUNNEL: False, S.SUSPENDED: False})
    acme = tmp_path / "acme"
    (acme / "ca").mkdir(parents=True)
    (acme / "account.conf").write_text("ACCOUNT_EMAIL='ops@example.ir'\n")
    monkeypatch.setattr(settings, "database_url", src_url)
    monkeypatch.setattr(settings, "backup_pdns_db", str(pdns_db))
    monkeypatch.setattr(settings, "acme_home", str(acme))
    res = backup.create_backup(out_dir=str(tmp_path / "backups"), passphrase="drill-pass", upload=False)
    assert res["encrypted"]

    # a fresh target database of the same kind
    if any_engine.dialect.name == "sqlite":
        target_url = f"sqlite:///{tmp_path}/restored.db"
    else:
        from sqlalchemy.engine import make_url

        name = any_engine.url.database + "_r"
        with create_engine(src_url, isolation_level="AUTOCOMMIT").connect() as c:
            c.execute(text(f'CREATE DATABASE "{name}"'))
        target_url = make_url(src_url).set(database=name).render_as_string(hide_password=False)
    target = create_engine(target_url)
    try:
        restored = tmp_path / "restore"
        backup.restore(res["path"], passphrase="drill-pass", controller=True, url=target_url,
                       pdns_target=str(restored / "pdns.sqlite3"), acme_target=str(restored / "acme"))
        assert migrate.current_revision(target) == "0012"
        assert migrate.upgrade(target) == HEAD
        check_head(target, exp)

        # the drill's checks (expected values are read from the dump inside the archive itself)
        expected = dc.expected_from_archive(res["path"], "drill-pass", str(tmp_path / "x"))
        assert expected["sites"]["count"] == 3 and expected["records"]["count"] == 12
        assert expected["revision"] == "0012"  # read from the dump itself, not the manifest
        assert expected["dnssec_domains"] == [S.SHOP]
        assert sorted(n for n, _ in expected["edges"]["tokens"]) == sorted(exp["tokens"])
        results = dc.run_db_checks(target, expected, pdns_db=str(restored / "pdns.sqlite3"),
                                   acme_dir=str(restored / "acme"))
        failed = [r for r in results if r["status"] == "fail"]
        assert failed == [], failed
        assert {r["name"] for r in results} >= {"migrations_at_head", "sites_match", "records_match",
                                                "edge_tokens_match", "secrets_readable", "edge_config_builds",
                                                "pdns_zones_present", "dnssec_keys_present", "acme_present"}

        # a mismatch is a FAIL, not a silent pass
        with target.begin() as c:
            c.execute(text("DELETE FROM records WHERE name = '_dmarc'"))
        bad = {r["name"]: r for r in dc.run_db_checks(target, expected, pdns_db=str(restored / "pdns.sqlite3"))}
        assert bad["records_match"]["status"] == "fail"
        assert bad["sites_match"]["status"] == "pass"
    finally:
        target.dispose()
        if any_engine.dialect.name == "postgresql":
            with create_engine(src_url, isolation_level="AUTOCOMMIT").connect() as c:
                c.execute(text(f'DROP DATABASE IF EXISTS "{target.url.database}" WITH (FORCE)'))
