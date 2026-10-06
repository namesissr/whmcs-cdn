"""analytics & platform (SPEC §14.3): analytics_minute (live analytics), log_spool (log export),
webhook_delivery (webhooks), sites.integration_secrets (encrypted write-only secrets of the log
export and the webhooks) and sites.quota_warned_at (quota.warning once per month)

Revision ID: 0015
Revises: 0014
Create Date: 2026-10-01
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0015"
down_revision: str | None = "0014"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# all nullable: NULL = no integration secret stored / no quota warning sent yet (every existing site)
SITE_NULLABLE = [
    ("integration_secrets", sa.Text()),
    ("quota_warned_at", sa.DateTime()),
]


def upgrade() -> None:
    # a database created by create_all of the current models already has the tables / columns
    insp = sa.inspect(op.get_bind())
    tables = set(insp.get_table_names())

    existing = {c["name"] for c in insp.get_columns("sites")}
    missing = [(name, type_) for name, type_ in SITE_NULLABLE if name not in existing]
    if missing:
        with op.batch_alter_table("sites") as batch_op:
            for name, type_ in missing:
                batch_op.add_column(sa.Column(name, type_, nullable=True))

    if "analytics_minute" not in tables:
        op.create_table(
            "analytics_minute",
            sa.Column("site_id", sa.Integer(), sa.ForeignKey("sites.id", ondelete="CASCADE"), primary_key=True),
            sa.Column("minute", sa.DateTime(), primary_key=True),
            sa.Column("requests", sa.BigInteger(), nullable=False),
            sa.Column("bytes", sa.BigInteger(), nullable=False),
            sa.Column("cache_hits", sa.BigInteger(), nullable=False),
            sa.Column("details", sa.Text(), nullable=False),
        )
        op.create_index(op.f("ix_analytics_minute_minute"), "analytics_minute", ["minute"], unique=False)

    if "log_spool" not in tables:
        op.create_table(
            "log_spool",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("site_id", sa.Integer(), sa.ForeignKey("sites.id", ondelete="CASCADE"), nullable=False),
            sa.Column("hour", sa.DateTime(), nullable=False),
            sa.Column("records", sa.Integer(), nullable=False),
            sa.Column("data", sa.LargeBinary(), nullable=False),
            sa.Column("created_at", sa.DateTime(), nullable=False),
        )
        op.create_index(op.f("ix_log_spool_site_id"), "log_spool", ["site_id"], unique=False)
        op.create_index(op.f("ix_log_spool_hour"), "log_spool", ["hour"], unique=False)
        op.create_index(op.f("ix_log_spool_created_at"), "log_spool", ["created_at"], unique=False)

    if "webhook_delivery" not in tables:
        op.create_table(
            "webhook_delivery",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("delivery_id", sa.String(length=24), nullable=False),
            sa.Column("site_id", sa.Integer(), sa.ForeignKey("sites.id", ondelete="CASCADE"), nullable=False),
            sa.Column("hook_id", sa.String(length=16), nullable=False),
            sa.Column("event", sa.String(length=32), nullable=False),
            sa.Column("event_id", sa.String(length=24), nullable=False),
            sa.Column("payload", sa.Text(), nullable=False),
            sa.Column("status", sa.String(length=10), nullable=False),
            sa.Column("attempts", sa.Integer(), nullable=False),
            sa.Column("last_code", sa.Integer(), nullable=True),
            sa.Column("last_error", sa.Text(), nullable=True),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.Column("delivered_at", sa.DateTime(), nullable=True),
            sa.Column("next_attempt_at", sa.DateTime(), nullable=True),
            sa.UniqueConstraint("delivery_id"),
        )
        op.create_index(op.f("ix_webhook_delivery_site_id"), "webhook_delivery", ["site_id"], unique=False)
        op.create_index(op.f("ix_webhook_delivery_created_at"), "webhook_delivery", ["created_at"], unique=False)
        op.create_index("ix_webhook_delivery_due", "webhook_delivery", ["status", "next_attempt_at"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_webhook_delivery_due", table_name="webhook_delivery")
    op.drop_index(op.f("ix_webhook_delivery_created_at"), table_name="webhook_delivery")
    op.drop_index(op.f("ix_webhook_delivery_site_id"), table_name="webhook_delivery")
    op.drop_table("webhook_delivery")
    op.drop_index(op.f("ix_log_spool_created_at"), table_name="log_spool")
    op.drop_index(op.f("ix_log_spool_hour"), table_name="log_spool")
    op.drop_index(op.f("ix_log_spool_site_id"), table_name="log_spool")
    op.drop_table("log_spool")
    op.drop_index(op.f("ix_analytics_minute_minute"), table_name="analytics_minute")
    op.drop_table("analytics_minute")
    with op.batch_alter_table("sites") as batch_op:
        for name in ("quota_warned_at", "integration_secrets"):
            batch_op.drop_column(name)
