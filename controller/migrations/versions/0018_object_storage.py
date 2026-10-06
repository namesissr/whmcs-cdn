"""object storage (SPEC §16.8): storage_buckets (customer MinIO buckets, encrypted service-account
secret + edge origin token), storage_usage_hourly (hourly stored-bytes samples for GB-hour billing)
and records.storage_bucket (origin shortcut `{"storage": "<bucket>"}`)

Revision ID: 0018
Revises: 0017
Create Date: 2026-10-01
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0018"
down_revision: str | None = "0017"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    insp = sa.inspect(op.get_bind())
    # a database created by create_all of the current models already has the column / tables
    if "storage_bucket" not in {c["name"] for c in insp.get_columns("records")}:
        with op.batch_alter_table("records") as batch_op:
            batch_op.add_column(sa.Column("storage_bucket", sa.String(length=63), nullable=True))
    tables = set(insp.get_table_names())
    if "storage_buckets" not in tables:
        op.create_table(
            "storage_buckets",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("site_id", sa.Integer(), sa.ForeignKey("sites.id", ondelete="CASCADE"), nullable=False),
            sa.Column("name", sa.String(length=63), nullable=False),
            sa.Column("bucket", sa.String(length=63), nullable=False),
            sa.Column("access_key", sa.String(length=32), nullable=False),
            sa.Column("secret_key", sa.Text(), nullable=False),
            sa.Column("origin_token", sa.Text(), nullable=False),
            sa.Column("quota_bytes", sa.BigInteger(), nullable=False),
            sa.Column("size_bytes", sa.BigInteger(), nullable=False),
            sa.Column("objects", sa.BigInteger(), nullable=False),
            sa.Column("usage_at", sa.DateTime(), nullable=True),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.Column("rotated_at", sa.DateTime(), nullable=True),
            sa.UniqueConstraint("bucket"),
            sa.UniqueConstraint("site_id", "name", name="uq_storage_buckets_site_name"),
        )
        op.create_index(op.f("ix_storage_buckets_site_id"), "storage_buckets", ["site_id"], unique=False)
    if "storage_usage_hourly" not in tables:
        op.create_table(
            "storage_usage_hourly",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("site_id", sa.Integer(), sa.ForeignKey("sites.id", ondelete="CASCADE"), nullable=False),
            sa.Column("bucket", sa.String(length=63), nullable=False),
            sa.Column("hour", sa.DateTime(), nullable=False),
            sa.Column("bytes", sa.BigInteger(), nullable=False),
            sa.Column("objects", sa.BigInteger(), nullable=False),
            sa.UniqueConstraint("bucket", "hour", name="uq_storage_usage_bucket_hour"),
        )
        op.create_index(op.f("ix_storage_usage_hourly_site_id"), "storage_usage_hourly", ["site_id"], unique=False)
        op.create_index(op.f("ix_storage_usage_hourly_hour"), "storage_usage_hourly", ["hour"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_storage_usage_hourly_hour"), table_name="storage_usage_hourly")
    op.drop_index(op.f("ix_storage_usage_hourly_site_id"), table_name="storage_usage_hourly")
    op.drop_table("storage_usage_hourly")
    op.drop_index(op.f("ix_storage_buckets_site_id"), table_name="storage_buckets")
    op.drop_table("storage_buckets")
    with op.batch_alter_table("records") as batch_op:
        batch_op.drop_column("storage_bucket")
