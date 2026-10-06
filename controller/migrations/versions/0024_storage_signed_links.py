"""SPEC §16.8 signed file links: records.storage_signed.

A proxied record whose origin is a storage bucket may serve that bucket by signed link only — the
edges answer 403 to a request without a valid, unexpired signature — so a customer can hand out a
download link on their own domain without the bucket being public. Default false, which is exactly
today's behaviour (a bucket used as a website origin must stay public).

Idempotent like 0021–0023: a database created by create_all of the current models already has it.

Revision ID: 0024
Revises: 0023
Create Date: 2026-10-06
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0024"
down_revision: str | None = "0023"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    insp = sa.inspect(op.get_bind())
    if "storage_signed" not in {c["name"] for c in insp.get_columns("records")}:
        # existing records keep serving their bucket publicly; the server default is dropped again
        # (the model carries it) so the column reads the same on every backend
        with op.batch_alter_table("records") as batch_op:
            batch_op.add_column(sa.Column("storage_signed", sa.Boolean(), nullable=False,
                                          server_default=sa.false()))
        with op.batch_alter_table("records") as batch_op:
            batch_op.alter_column("storage_signed", existing_type=sa.Boolean(), existing_nullable=False,
                                  server_default=None)


def downgrade() -> None:
    with op.batch_alter_table("records") as batch_op:
        batch_op.drop_column("storage_signed")
