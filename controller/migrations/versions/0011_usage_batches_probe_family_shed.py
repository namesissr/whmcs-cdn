"""usage_batches (idempotent usage, F7), per-family primary probe state (F32) and
load-shed hysteresis counters (F25)

Revision ID: 0011
Revises: 0010
Create Date: 2026-09-30
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0011"
down_revision: str | None = "0010"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# nullable edge columns (NULL probe_ok* = never probed yet -> advertised, fail-open, F32)
NULLABLE = [
    ("probe_ok4", sa.Boolean()),
    ("probe_ok6", sa.Boolean()),
    ("shed_since", sa.DateTime()),
]
# NOT NULL integer counters; get a server default that is dropped afterwards (existing edges
# start at 0), like 0003/0004/0005
DEFAULTED = [
    ("probe_fail4", sa.Integer(), sa.text("0")),
    ("probe_fail6", sa.Integer(), sa.text("0")),
    ("shed_high", sa.Integer(), sa.text("0")),
]


def upgrade() -> None:
    insp = sa.inspect(op.get_bind())

    existing = {c["name"] for c in insp.get_columns("edges")}
    nullable = [(name, type_) for name, type_ in NULLABLE if name not in existing]
    defaulted = [c for c in DEFAULTED if c[0] not in existing]
    if nullable or defaulted:
        with op.batch_alter_table("edges") as batch_op:
            for name, type_ in nullable:
                batch_op.add_column(sa.Column(name, type_, nullable=True))
            for name, type_, default in defaulted:
                batch_op.add_column(sa.Column(name, type_, nullable=False, server_default=default))
        if defaulted:
            with op.batch_alter_table("edges") as batch_op:
                for name, type_, _ in defaulted:
                    batch_op.alter_column(name, existing_type=type_, existing_nullable=False,
                                          server_default=None)

    # F7: usage idempotency table (edge_id, batch_id) primary key
    if "usage_batches" not in insp.get_table_names():
        op.create_table(
            "usage_batches",
            sa.Column("edge_id", sa.Integer(),
                      sa.ForeignKey("edges.id", ondelete="CASCADE"), primary_key=True),
            sa.Column("batch_id", sa.String(length=32), primary_key=True),
            sa.Column("received_at", sa.DateTime(), nullable=False),
        )
        op.create_index(op.f("ix_usage_batches_received_at"), "usage_batches", ["received_at"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_usage_batches_received_at"), table_name="usage_batches")
    op.drop_table("usage_batches")
    with op.batch_alter_table("edges") as batch_op:
        for name in ("shed_since", "shed_high", "probe_fail6", "probe_ok6", "probe_fail4", "probe_ok4"):
            batch_op.drop_column(name)
