"""api_keys: per-site customer API keys (SPEC §10.1)

Revision ID: 0007
Revises: 0006
Create Date: 2026-09-30
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0007"
down_revision: str | None = "0006"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # a database created by create_all of these models already has the table
    if "api_keys" not in sa.inspect(op.get_bind()).get_table_names():
        op.create_table(
            "api_keys",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("site_id", sa.Integer(),
                      sa.ForeignKey("sites.id", ondelete="CASCADE"), nullable=False),
            sa.Column("key_hash", sa.String(length=64), nullable=False),
            sa.Column("name", sa.String(length=64), nullable=False),
            sa.Column("scopes", sa.Text(), nullable=False),
            sa.Column("last_used_at", sa.DateTime(), nullable=True),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.Column("revoked", sa.Boolean(), nullable=False),
            sa.UniqueConstraint("key_hash"),
        )
        op.create_index(op.f("ix_api_keys_site_id"), "api_keys", ["site_id"], unique=False)


def downgrade() -> None:
    op.drop_table("api_keys")
