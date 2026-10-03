"""security review wave 9: sites.client_id (owning WHMCS client, parent/child zone rule C1) and the
split customer API scopes (M3): `dns` now covers DNS records (and secondary DNS) only, configuration
sections need `config`, edge functions need `functions`. Every existing key that had `dns` gets
`config` added so it keeps the access it had (but NOT `functions`).

Also (SQLite only): purges.id becomes AUTOINCREMENT. Edges fetch purges with `?after=<last id>`;
without AUTOINCREMENT SQLite hands out max(id)+1 again after the newest rows are deleted (site
deletion, the 2-day purge cleanup), so new purges got ids at or below the edges' cursors and were
silently skipped. The sequence starts PURGE_ID_GAP above the current maximum: ids that were issued
and deleted before this upgrade are unknown, the gap keeps every new id above them. PostgreSQL
sequences were monotonic already. The same for sites.id (the edges key per-site cache directories and
state by it); no gap there.

Revision ID: 0019
Revises: 0018
Create Date: 2026-10-02
"""
import json
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0019"
down_revision: str | None = "0018"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _scopes(raw) -> list | None:
    try:
        v = json.loads(raw or "[]")
    except ValueError:
        return None
    return v if isinstance(v, list) else None


def _rewrite(conn, fn) -> None:
    keys = sa.table("api_keys", sa.column("id", sa.Integer()), sa.column("scopes", sa.Text()))
    for kid, raw in conn.execute(sa.select(keys.c.id, keys.c.scopes)).all():
        cur = _scopes(raw)
        if cur is None:
            continue
        new = fn(list(cur))
        if new != cur:
            conn.execute(keys.update().where(keys.c.id == kid).values(scopes=json.dumps(new)))


PURGE_ID_GAP = 1_000_000


def _sqlite_autoincrement(conn, table: str, gap: int) -> None:
    """SQLite only: rebuild `table` with AUTOINCREMENT (ids are never handed out twice) and start
    its sequence at least `gap` above the current maximum id."""
    if conn.dialect.name != "sqlite":
        return
    ddl = conn.execute(sa.text("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = :t"),
                       {"t": table}).scalar()
    if ddl and "AUTOINCREMENT" not in ddl.upper():
        with op.batch_alter_table(table, recreate="always", table_kwargs={"sqlite_autoincrement": True}):
            pass
    top = conn.execute(sa.text(f'SELECT COALESCE(MAX(id), 0) FROM "{table}"')).scalar() or 0
    seq = conn.execute(sa.text("SELECT seq FROM sqlite_sequence WHERE name = :t"), {"t": table}).scalar()
    if seq is None or seq < top + gap:
        conn.execute(sa.text("DELETE FROM sqlite_sequence WHERE name = :t"), {"t": table})
        conn.execute(sa.text("INSERT INTO sqlite_sequence (name, seq) VALUES (:t, :s)"), {"t": table, "s": top + gap})


def upgrade() -> None:
    conn = op.get_bind()
    insp = sa.inspect(conn)
    # a database created by create_all of the current models already has the column / index
    if "client_id" not in {c["name"] for c in insp.get_columns("sites")}:
        with op.batch_alter_table("sites") as batch_op:
            batch_op.add_column(sa.Column("client_id", sa.Integer(), nullable=True))
    if "ix_sites_client_id" not in {i["name"] for i in insp.get_indexes("sites")}:
        op.create_index(op.f("ix_sites_client_id"), "sites", ["client_id"], unique=False)
    # M3: keys that could write config through `dns` keep that through the new `config` scope
    _rewrite(conn, lambda s: s + ["config"] if "dns" in s and "config" not in s else s)
    _sqlite_autoincrement(conn, "purges", PURGE_ID_GAP)
    # site ids name the edges' per-site cache directories and state: never reuse one either
    _sqlite_autoincrement(conn, "sites", 0)


def downgrade() -> None:
    conn = op.get_bind()

    def old(s: list) -> list:
        # the old code knows purge/stats/dns only; config/functions access was part of `dns`
        had = "config" in s or "functions" in s
        s = [x for x in s if x not in ("config", "functions")]
        if had and "dns" not in s:
            s.append("dns")
        return s

    _rewrite(conn, old)
    # purges / sites keep AUTOINCREMENT (harmless for the older code; ids must never go backwards)
    op.drop_index(op.f("ix_sites_client_id"), table_name="sites")
    with op.batch_alter_table("sites") as batch_op:
        batch_op.drop_column("client_id")
