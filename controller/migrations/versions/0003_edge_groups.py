"""edges: group, capacity_mbps, heartbeat metrics and load-shedding state (tunnel mode, SPEC §7.4)

Revision ID: 0003
Revises: 0002
Create Date: 2026-09-29
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0003"
down_revision: str | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# NOT NULL columns get a server default so existing edges are filled in; the default is
# dropped afterwards because the models set these values themselves
DEFAULTED = [
    ("group", sa.String(length=16), sa.text("'general'")),
    ("capacity_mbps", sa.Integer(), sa.text("0")),
    ("shed", sa.Boolean(), sa.false()),
    ("load_high", sa.Integer(), sa.text("0")),
]


def upgrade() -> None:
    # a database created by create_all of these models (stamped as the baseline by
    # app.migrate) already has the columns
    existing = {c["name"] for c in sa.inspect(op.get_bind()).get_columns("edges")}
    defaulted = [c for c in DEFAULTED if c[0] not in existing]
    nullable = [c for c in (sa.Column("metrics", sa.Text(), nullable=True),
                            sa.Column("metrics_at", sa.DateTime(), nullable=True)) if c.name not in existing]
    if not defaulted and not nullable:
        return
    with op.batch_alter_table("edges") as batch_op:
        for name, type_, default in defaulted:
            batch_op.add_column(sa.Column(name, type_, nullable=False, server_default=default))
        for col in nullable:
            batch_op.add_column(col)
    if defaulted:
        with op.batch_alter_table("edges") as batch_op:
            for name, type_, _ in defaulted:
                batch_op.alter_column(name, existing_type=type_, existing_nullable=False, server_default=None)


def downgrade() -> None:
    with op.batch_alter_table("edges") as batch_op:
        for name in ("metrics_at", "metrics", "load_high", "shed", "capacity_mbps", "group"):
            batch_op.drop_column(name)
