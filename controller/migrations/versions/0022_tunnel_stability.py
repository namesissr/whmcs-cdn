"""wave 13 (SPEC §22): tunnel speed and stability.

edges: drain state (§22.1: drain_state, drain_started_at, drain_until, drain_by, drain_reason,
drain_conns), heartbeat reload counters (§22.2: reload_stats), synthetic tunnel probe + degraded state
(§22.3: tunnel_probe, tunnel_probe_fail, tunnel_probe_ok, tunnel_degraded, tunnel_degraded_since),
kernel tuning report (§22.6: tuning), per-node HTTP/3 switch (§22.9: http3_enabled, default true) and
the capacity-weighted DNS load level (§22.10: dns_weight_level).
sites: optional RSA-2048 certificate next to the ECDSA one (§22.8: ssl_cert_rsa, ssl_key_rsa — the
key encrypted at rest like ssl_key).
New table edge_events (§22.13). TLS ticket keys live in the `state` table (no schema change).

Idempotent like 0021: a database created by create_all of the current models already has them.

Revision ID: 0022
Revises: 0021
Create Date: 2026-10-02
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0022"
down_revision: str | None = "0021"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# sites.id is AUTOINCREMENT on SQLite (0019); keep it when a batch operation rebuilds the table
_KW = {"table_kwargs": {"sqlite_autoincrement": True}}

# NOT NULL edge columns get a server default so existing edges are filled in (no drain, never
# degraded, HTTP/3 allowed, weight level 0 = today's behaviour); the default is dropped afterwards
# because the model sets the value, like 0003/0011/0013
EDGE_DEFAULTED = [
    ("drain_state", sa.String(length=10), sa.text("''")),
    ("tunnel_probe_fail", sa.Integer(), sa.text("0")),
    ("tunnel_probe_ok", sa.Integer(), sa.text("0")),
    ("tunnel_degraded", sa.Boolean(), sa.false()),
    ("http3_enabled", sa.Boolean(), sa.true()),
    ("dns_weight_level", sa.Integer(), sa.text("0")),
]
EDGE_NULLABLE = [
    ("drain_started_at", sa.DateTime()),
    ("drain_until", sa.DateTime()),
    ("drain_by", sa.String(length=8)),
    ("drain_reason", sa.String(length=64)),
    ("drain_conns", sa.Integer()),
    ("reload_stats", sa.Text()),
    ("tunnel_probe", sa.Text()),
    ("tunnel_degraded_since", sa.DateTime()),
    ("tuning", sa.Text()),
]
SITE_NULLABLE = [
    ("ssl_cert_rsa", sa.Text()),
    ("ssl_key_rsa", sa.Text()),
]


def upgrade() -> None:
    conn = op.get_bind()
    insp = sa.inspect(conn)
    existing = {c["name"] for c in insp.get_columns("edges")}
    defaulted = [c for c in EDGE_DEFAULTED if c[0] not in existing]
    nullable = [c for c in EDGE_NULLABLE if c[0] not in existing]
    if defaulted or nullable:
        with op.batch_alter_table("edges") as batch_op:
            for name, type_, default in defaulted:
                batch_op.add_column(sa.Column(name, type_, nullable=False, server_default=default))
            for name, type_ in nullable:
                batch_op.add_column(sa.Column(name, type_, nullable=True))
        if defaulted:
            with op.batch_alter_table("edges") as batch_op:
                for name, type_, _ in defaulted:
                    batch_op.alter_column(name, existing_type=type_, existing_nullable=False, server_default=None)

    scols = {c["name"] for c in insp.get_columns("sites")}
    snew = [c for c in SITE_NULLABLE if c[0] not in scols]
    if snew:
        with op.batch_alter_table("sites", **_KW) as batch_op:
            for name, type_ in snew:
                batch_op.add_column(sa.Column(name, type_, nullable=True))

    if "edge_events" not in set(sa.inspect(conn).get_table_names()):
        op.create_table(
            "edge_events",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("edge_id", sa.Integer(), sa.ForeignKey("edges.id", ondelete="CASCADE"), nullable=False),
            sa.Column("at", sa.DateTime(), nullable=False),
            sa.Column("kind", sa.String(length=16), nullable=False),
            sa.Column("data", sa.Text(), nullable=False),
        )
        op.create_index(op.f("ix_edge_events_edge_id"), "edge_events", ["edge_id"], unique=False)
        op.create_index(op.f("ix_edge_events_at"), "edge_events", ["at"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_edge_events_at"), table_name="edge_events")
    op.drop_index(op.f("ix_edge_events_edge_id"), table_name="edge_events")
    op.drop_table("edge_events")
    with op.batch_alter_table("sites", **_KW) as batch_op:
        for name, _ in reversed(SITE_NULLABLE):
            batch_op.drop_column(name)
    with op.batch_alter_table("edges") as batch_op:
        for name, _ in reversed(EDGE_NULLABLE):
            batch_op.drop_column(name)
        for name, _, _ in reversed(EDGE_DEFAULTED):
            batch_op.drop_column(name)
