"""Database migrations (Alembic) — run at startup and from `python -m app.manage`.

* An empty database is created by running every migration.
* A database created by an older controller (Base.metadata.create_all, so it has the
  application tables but no alembic_version table) is stamped with the baseline
  revision first, then upgraded normally.
* Several controllers may start at the same time (HA): the upgrade runs under a
  PostgreSQL advisory lock (or a file lock for SQLite), so only one of them migrates
  and the others find the database already at head.
"""

import contextlib
import fcntl
import logging
import os

from alembic import command
from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import inspect, text

log = logging.getLogger("pcdn.migrate")

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BASELINE = "0001"
# tables that exist in every database created before migrations were introduced
LEGACY_MARKER_TABLES = {"sites", "edges", "state"}
MIGRATION_LOCK_ID = 0x70636E01  # "pcn" + 1; the scheduler leader lock uses another id


def alembic_config(connection=None) -> Config:
    cfg = Config(os.path.join(ROOT, "alembic.ini"))
    cfg.set_main_option("script_location", os.path.join(ROOT, "migrations"))
    cfg.attributes["configure_logging"] = False
    if connection is not None:
        cfg.attributes["connection"] = connection
    return cfg


def head_revision() -> str:
    return ScriptDirectory.from_config(alembic_config()).get_current_head()


def current_revision(engine) -> str | None:
    with engine.connect() as conn:
        return MigrationContext.configure(conn).get_current_revision()


def _sqlite_path(engine) -> str | None:
    if engine.dialect.name != "sqlite":
        return None
    db = engine.url.database
    if not db or db == ":memory:" or db.startswith("file:"):
        return None
    return os.path.abspath(db)


@contextlib.contextmanager
def migration_lock(engine, conn):
    """Serialize migrations between controller processes sharing one database."""
    if engine.dialect.name == "postgresql":
        conn.execute(text("SELECT pg_advisory_lock(:k)"), {"k": MIGRATION_LOCK_ID})
        conn.commit()
        try:
            yield
        finally:
            conn.rollback()
            conn.execute(text("SELECT pg_advisory_unlock(:k)"), {"k": MIGRATION_LOCK_ID})
            conn.commit()
        return
    path = _sqlite_path(engine)
    if path is None:
        yield
        return
    with open(path + ".migrate.lock", "a+") as fh:
        fcntl.flock(fh, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(fh, fcntl.LOCK_UN)


def is_legacy(conn) -> bool:
    tables = set(inspect(conn).get_table_names())
    return "alembic_version" not in tables and LEGACY_MARKER_TABLES <= tables


def upgrade(engine=None, revision: str = "head") -> str | None:
    """Bring the database to `revision` (stamping legacy create_all databases first)."""
    if engine is None:
        from .db import engine as default_engine

        engine = default_engine
    with engine.connect() as conn:
        with migration_lock(engine, conn):
            cfg = alembic_config(conn)
            if is_legacy(conn):
                log.warning("database was created without migrations: stamping baseline %s", BASELINE)
                command.stamp(cfg, BASELINE)
                conn.commit()
            before = MigrationContext.configure(conn).get_current_revision()
            command.upgrade(cfg, revision)
            conn.commit()
            after = MigrationContext.configure(conn).get_current_revision()
            conn.commit()
    if before != after:
        log.info("database migrated %s -> %s", before or "(empty)", after)
    return after


def stamp(engine, revision: str):
    with engine.connect() as conn:
        with migration_lock(engine, conn):
            command.stamp(alembic_config(conn), revision)
            conn.commit()


def downgrade(engine, revision: str):
    with engine.connect() as conn:
        with migration_lock(engine, conn):
            command.downgrade(alembic_config(conn), revision)
            conn.commit()


def pending(engine) -> bool:
    return current_revision(engine) != head_revision()
