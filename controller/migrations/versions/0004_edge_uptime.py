"""edge availability rollup (edge_uptime) + edges.cpu_high

Revision ID: 0004
Revises: 0003
Create Date: 2026-09-29
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0004"
down_revision: str | None = "0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    bind = op.get_bind()
    insp = sa.inspect(bind)

    if "cpu_high" not in {c["name"] for c in insp.get_columns("edges")}:
        with op.batch_alter_table("edges") as batch_op:
            batch_op.add_column(sa.Column("cpu_high", sa.Integer(), nullable=False, server_default=sa.text("0")))
        with op.batch_alter_table("edges") as batch_op:
            batch_op.alter_column("cpu_high", existing_type=sa.Integer(), existing_nullable=False,
                                  server_default=None)

    if "edge_uptime" not in insp.get_table_names():
        op.create_table(
            "edge_uptime",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("edge_id", sa.Integer(),
                      sa.ForeignKey("edges.id", ondelete="CASCADE"), nullable=False),
            sa.Column("hour", sa.DateTime(), nullable=False),
            sa.Column("samples_total", sa.Integer(), nullable=False),
            sa.Column("samples_online", sa.Integer(), nullable=False),
            sa.UniqueConstraint("edge_id", "hour", name="uq_edge_uptime_edge_hour"),
        )
        op.create_index("ix_edge_uptime_edge_id", "edge_uptime", ["edge_id"])
        op.create_index("ix_edge_uptime_hour", "edge_uptime", ["hour"])


def downgrade() -> None:
    op.drop_table("edge_uptime")
    with op.batch_alter_table("edges") as batch_op:
        batch_op.drop_column("cpu_high")
