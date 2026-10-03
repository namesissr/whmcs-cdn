"""wave 7 (SPEC §15.4): site_events — tunnel origin-down / origin-up transitions listed by
GET /api/v1/events?type=tunnel for the WHMCS cron (stable event ids, shared with the webhook body)

Revision ID: 0016
Revises: 0015
Create Date: 2026-10-01
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0016"
down_revision: str | None = "0015"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # a database created by create_all of the current models already has the table
    insp = sa.inspect(op.get_bind())
    if "site_events" in set(insp.get_table_names()):
        return
    op.create_table(
        "site_events",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("event_id", sa.String(length=24), nullable=False),
        sa.Column("site_id", sa.Integer(), sa.ForeignKey("sites.id", ondelete="CASCADE"), nullable=False),
        sa.Column("type", sa.String(length=32), nullable=False),
        sa.Column("data", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.UniqueConstraint("event_id"),
    )
    op.create_index(op.f("ix_site_events_site_id"), "site_events", ["site_id"], unique=False)
    op.create_index(op.f("ix_site_events_type"), "site_events", ["type"], unique=False)
    op.create_index(op.f("ix_site_events_created_at"), "site_events", ["created_at"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_site_events_created_at"), table_name="site_events")
    op.drop_index(op.f("ix_site_events_type"), table_name="site_events")
    op.drop_index(op.f("ix_site_events_site_id"), table_name="site_events")
    op.drop_table("site_events")
