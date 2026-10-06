"""audit_log: append-only record of platform mutations (SPEC §13.2)

Revision ID: 0012
Revises: 0011
Create Date: 2026-10-01
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0012"
down_revision: str | None = "0011"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # a database created by create_all of the current models already has the table
    if "audit_log" not in sa.inspect(op.get_bind()).get_table_names():
        op.create_table(
            "audit_log",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("at", sa.DateTime(), nullable=False),
            sa.Column("actor", sa.String(length=120), nullable=False),
            sa.Column("actor_kind", sa.String(length=16), nullable=False),
            sa.Column("action", sa.String(length=64), nullable=False),
            sa.Column("target", sa.String(length=253), nullable=True),
            sa.Column("detail", sa.Text(), nullable=False),
            sa.Column("ip", sa.String(length=45), nullable=True),
        )
        op.create_index(op.f("ix_audit_log_at"), "audit_log", ["at"], unique=False)
        op.create_index(op.f("ix_audit_log_action"), "audit_log", ["action"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_audit_log_action"), table_name="audit_log")
    op.drop_index(op.f("ix_audit_log_at"), table_name="audit_log")
    op.drop_table("audit_log")
