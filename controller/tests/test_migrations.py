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
    # 0003: edge group / capacity / metrics columns
    added = sorted(d[3].name for d in diff if isinstance(d, tuple) and d[0] == "add_column" and d[2] == "edges")
    assert added == ["capacity_mbps", "group", "load_high", "metrics", "metrics_at", "shed"], diff
    rest = [d for d in diff if not (isinstance(d, tuple) and d[0] == "add_column")]
    assert len(rest) == 1, diff
    (op,) = rest[0]
    # 0002: sites.secret String(64) -> Text
    assert op[0] == "modify_type" and op[2:4] == ("sites", "secret")


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
        # 0003 fills in the new edge columns of existing edges
        assert tuple(c.execute(text('SELECT "group", capacity_mbps, shed, load_high, metrics FROM edges')).one()) \
            == ("general", 0, False, 0, None)
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
