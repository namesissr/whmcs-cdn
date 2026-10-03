"""edges.logs / logs_at / bundle_version: centralized node logs + bundle version (SPEC §11)

Revision ID: 0009
Revises: 0008
Create Date: 2026-09-30
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0009"
down_revision: str | None = "0008"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    bind = op.get_bind()
    insp = sa.inspect(bind)
    # a database created by create_all of these models already has the columns
    existing = {c["name"] for c in insp.get_columns("edges")}
    with op.batch_alter_table("edges") as batch_op:
        if "logs" not in existing:
            batch_op.add_column(sa.Column("logs", sa.Text(), nullable=True))
        if "logs_at" not in existing:
            batch_op.add_column(sa.Column("logs_at", sa.DateTime(), nullable=True))
        if "bundle_version" not in existing:
            batch_op.add_column(sa.Column("bundle_version", sa.String(length=64), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("edges") as batch_op:
        for name in ("bundle_version", "logs_at", "logs"):
            batch_op.drop_column(name)
