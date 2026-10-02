"""Alembic migrations: empty DB -> head matches the models; legacy create_all DBs get stamped."""

import pytest
from alembic.autogenerate import compare_metadata
from alembic.runtime.migration import MigrationContext
from sqlalchemy import create_engine, inspect, text

from app import migrate
from app.db import Base


def _diff(engine):
    with engine.connect() as conn:
        ctx = MigrationContext.configure(conn, opts={"compare_type": True, "compare_server_default": True})
        return compare_metadata(ctx, Base.metadata)


@pytest.fixture(params=["sqlite", "postgresql"])
def any_engine(request, tmp_path):
    if request.param == "sqlite":
        eng = create_engine(f"sqlite:///{tmp_path}/m.db")
    else:
        url = request.getfixturevalue("pg_url")
        eng = create_engine(url)
    yield eng
    eng.dispose()


def test_upgrade_empty_database_matches_models(any_engine):
    assert migrate.upgrade(any_engine) == migrate.head_revision()
    assert _diff(any_engine) == []
    # running it again is a no-op
    assert migrate.upgrade(any_engine) == migrate.head_revision()


def test_baseline_is_the_pre_migration_schema(any_engine):
    """Revision 0001 == what create_all produced before migrations; only later revisions differ."""
    migrate.upgrade(any_engine, "0001")
    diff = _diff(any_engine)
    flat = [d for grp in diff for d in (grp if isinstance(grp, list) else [grp])]
    # 0003: edge group / capacity / metrics columns; 0004: edges.cpu_high; 0005: probe fields;
    # 0009: logs / logs_at / bundle_version (centralized node logs + bundle version);
    # 0011: per-family primary probe (probe_ok4/fail4/ok6/fail6, F32) + shed hysteresis
    # (shed_high / shed_since, F25); 0013: origin shield flag + heartbeat capabilities (SPEC §14.1)
    added = sorted(d[3].name for d in flat if d[0] == "add_column" and d[2] == "edges")
    # 0020: errors_last_hour + waiting_room (wave 10 heartbeat, SPEC §18.4 / §18.1)
    assert added == ["bundle_version", "capabilities", "capacity_mbps", "cpu_high", "errors_last_hour", "group",
                     "load_high", "logs", "logs_at", "metrics", "metrics_at", "probe_at", "probe_error", "probe_fail",
                     "probe_fail4", "probe_fail6", "probe_ms", "probe_ok", "probe_ok4", "probe_ok6",
                     "shed", "shed_high", "shed_since", "shield", "waiting_room"], diff
    # 0006: purges.prefixes / everything
    purge_added = sorted(d[3].name for d in flat if d[0] == "add_column" and d[2] == "purges")
    assert purge_added == ["everything", "prefixes"], diff
    # 0008: sites.reseller_client_id / reseller_label; 0014: custom origin client certificate
    # (authenticated origin pulls, SPEC §14.2); 0015: integration secrets + quota warning (SPEC §14.3)
    site_added = sorted(d[3].name for d in flat if d[0] == "add_column" and d[2] == "sites")
    # 0019: sites.client_id (owning WHMCS client, security review C1)
    assert site_added == ["client_id", "integration_secrets", "origin_client_cert", "origin_client_expires_at",
                          "origin_client_key", "quota_warned_at", "reseller_client_id", "reseller_label"], diff
    # 0004: the edge_uptime table; 0005: incidents + incident_updates; 0007: api_keys;
    # 0010: edge_addresses (multi-address edges / health-based failover);
    # 0011: usage_batches (idempotent usage reports, F7); 0012: audit_log (SPEC §13.2);
    # 0015: analytics_minute, log_spool, webhook_delivery (analytics & platform, SPEC §14.3);
    # 0016: site_events (tunnel origin-down / origin-up events, SPEC §15.4);
    # 0017: l4_ports (TCP/UDP proxy edge ports, SPEC §16.4)
    # 0018: storage_buckets + storage_usage_hourly (object storage, SPEC §16.8)
    # 0020: access_otp (rate limits of the access one-time codes, SPEC §18.2)
    tables = {d[1].name for d in flat if d[0] == "add_table"}
    assert {"edge_uptime", "incidents", "incident_updates", "api_keys", "edge_addresses",
            "usage_batches", "audit_log", "analytics_minute", "log_spool", "webhook_delivery",
            "site_events", "l4_ports", "storage_buckets", "storage_usage_hourly", "access_otp"} <= tables, diff
    # 0017: weighted / controller-checked DNS records (SPEC §16.7); 0018: records.storage_bucket
    record_added = sorted(d[3].name for d in flat if d[0] == "add_column" and d[2] == "records")
    assert record_added == ["health_at", "health_error", "health_fail", "health_ms", "health_ok", "health_path",
                            "health_protocol", "storage_bucket", "weight"], diff
    # 0002: sites.secret String(64) -> Text
    assert any(d[0] == "modify_type" and d[2:4] == ("sites", "secret") for d in flat), diff
    # nothing else changed between 0001 and head
    other = [d for d in flat if d[0] not in ("add_column", "add_table", "modify_type")
             and not (d[0] == "add_index" and d[1].table.name in
                      ("edge_uptime", "incident_updates", "api_keys", "sites", "edge_addresses",
                       "usage_batches", "audit_log", "analytics_minute", "log_spool", "webhook_delivery",
                       "site_events", "l4_ports", "storage_buckets", "storage_usage_hourly", "access_otp"))]
    assert other == [], other


def test_legacy_create_all_database_is_stamped_and_upgraded(any_engine):
    # a database from an older controller: tables at the baseline schema, no alembic_version
    migrate.upgrade(any_engine, "0001")
    with any_engine.begin() as c:
        c.execute(text("DROP TABLE alembic_version"))
        c.execute(text(
            "INSERT INTO sites (domain, status, suspended, over_quota, ns_found, bandwidth_limit_gb, max_records,"
            " ssl_allowed, rate_limit_rps, features, config, blocked_ips, secret, dnssec_enabled, ssl_status,"
            " created_at, updated_at) VALUES ('legacy.com', 'active', false, false, '[]', 0, 100, true, 0, '{}',"
            " '{}', '[]', :s, false, 'none', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"), {"s": "ab" * 32})
        c.execute(text("INSERT INTO edges (name, ipv4, region, token_hash, enabled, created_at)"
                       " VALUES ('ir-1', '5.160.1.10', 'home', 'h', true, CURRENT_TIMESTAMP)"))
    with any_engine.connect() as c:
        assert migrate.is_legacy(c)

    assert migrate.upgrade(any_engine) == migrate.head_revision()
    assert _diff(any_engine) == []
    with any_engine.connect() as c:
        assert c.execute(text("SELECT domain, secret FROM sites")).one() == ("legacy.com", "ab" * 32)
        # 0014: no custom origin client certificate on existing sites
        assert tuple(c.execute(text(
            "SELECT origin_client_cert, origin_client_key, origin_client_expires_at FROM sites")).one()) \
            == (None, None, None)
        # 0015: no integration secret / quota warning on existing sites; the new tables are empty
        assert tuple(c.execute(text("SELECT integration_secrets, quota_warned_at FROM sites")).one()) \
            == (None, None)
        # 0016: the site_events table is empty
        for table in ("analytics_minute", "log_spool", "webhook_delivery", "site_events"):
            assert c.execute(text(f"SELECT count(*) FROM {table}")).scalar() == 0
        # 0003/0004/0005/0013 fill in the new edge columns of existing edges
        assert tuple(c.execute(text(
            'SELECT "group", capacity_mbps, shed, load_high, cpu_high, metrics, probe_fail, probe_ok,'
            " shield, capabilities FROM edges")).one()) \
            == ("general", 0, False, 0, 0, None, 0, None, False, None)
        assert not migrate.is_legacy(c)


def test_create_all_database_of_current_models_is_adopted(any_engine):
    Base.metadata.create_all(any_engine)
    assert "alembic_version" not in inspect(any_engine).get_table_names()
    migrate.upgrade(any_engine)
    assert migrate.current_revision(any_engine) == migrate.head_revision()
    assert _diff(any_engine) == []


def test_downgrade_and_upgrade_again(any_engine):
    migrate.upgrade(any_engine)
    migrate.downgrade(any_engine, "base")
    assert set(inspect(any_engine).get_table_names()) <= {"alembic_version"}
    migrate.upgrade(any_engine)
    assert _diff(any_engine) == []


def test_single_head():
    from alembic.script import ScriptDirectory

    heads = ScriptDirectory.from_config(migrate.alembic_config()).get_heads()
    assert len(heads) == 1, "migration history has diverged; merge the heads"


def test_manage_cli(tmp_path, monkeypatch, capsys):
    from app import db as app_db
    from app import manage

    eng = create_engine(f"sqlite:///{tmp_path}/cli.db")
    monkeypatch.setattr(app_db, "engine", eng)
    assert manage.main(["migrate"]) == 0
    assert manage.main(["current"]) == 0
    assert "current: " + migrate.head_revision() in capsys.readouterr().out
    assert manage.main(["stamp", "0001"]) == 0
    assert migrate.current_revision(eng) == "0001"
    with pytest.raises(SystemExit):
        manage.main(["downgrade", "base"])  # refuses without --yes


def test_app_startup_runs_migrations(client):
    """The test app starts through init_db -> migrate.upgrade (see conftest)."""
    from app.db import engine

    assert migrate.current_revision(engine) == migrate.head_revision()
