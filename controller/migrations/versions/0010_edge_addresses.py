"""edge_addresses: additional addresses per edge for health-based failover (SPEC §12)

Revision ID: 0010
Revises: 0009
Create Date: 2026-09-30
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0010"
down_revision: str | None = "0009"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # a database created by create_all of these models already has the table
    if "edge_addresses" not in sa.inspect(op.get_bind()).get_table_names():
        op.create_table(
            "edge_addresses",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("edge_id", sa.Integer(),
                      sa.ForeignKey("edges.id", ondelete="CASCADE"), nullable=False),
            sa.Column("family", sa.Integer(), nullable=False),
            sa.Column("ip", sa.String(length=45), nullable=False),
            sa.Column("label", sa.String(length=64), nullable=False),
            sa.Column("enabled", sa.Boolean(), nullable=False),
            sa.Column("probe_ok", sa.Boolean(), nullable=True),
            sa.Column("probe_ms", sa.Integer(), nullable=True),
            sa.Column("probe_at", sa.DateTime(), nullable=True),
            sa.Column("probe_error", sa.Text(), nullable=True),
            sa.Column("probe_fail", sa.Integer(), nullable=False),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.UniqueConstraint("family", "ip", name="uq_edge_addresses_family_ip"),
        )
        op.create_index(op.f("ix_edge_addresses_edge_id"), "edge_addresses", ["edge_id"], unique=False)


def downgrade() -> None:
    op.drop_table("edge_addresses")
