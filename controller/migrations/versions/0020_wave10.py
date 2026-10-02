"""wave 10 (SPEC §18): edges.errors_last_hour + edges.waiting_room (heartbeat, §18.4 / §18.1) and the
access_otp table (rate limits of the access one-time codes, §18.2). The per-site wr_secret /
access_secret live in sites.integration_secrets (no schema change).

Revision ID: 0020
Revises: 0019
Create Date: 2026-10-02
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0020"
down_revision: str | None = "0019"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    insp = sa.inspect(op.get_bind())
    # a database created by create_all of the current models already has them
    cols = {c["name"] for c in insp.get_columns("edges")}
    with op.batch_alter_table("edges") as batch_op:
        if "errors_last_hour" not in cols:
            batch_op.add_column(sa.Column("errors_last_hour", sa.Integer(), nullable=True))
        if "waiting_room" not in cols:
            batch_op.add_column(sa.Column("waiting_room", sa.Text(), nullable=True))
    if "access_otp" not in set(insp.get_table_names()):
        op.create_table(
            "access_otp",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("site_id", sa.Integer(), sa.ForeignKey("sites.id", ondelete="CASCADE"), nullable=False),
            sa.Column("email_hash", sa.String(length=64), nullable=False),
            sa.Column("at", sa.DateTime(), nullable=False),
        )
        op.create_index(op.f("ix_access_otp_site_id"), "access_otp", ["site_id"], unique=False)
        op.create_index(op.f("ix_access_otp_email_hash"), "access_otp", ["email_hash"], unique=False)
        op.create_index(op.f("ix_access_otp_at"), "access_otp", ["at"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_access_otp_at"), table_name="access_otp")
    op.drop_index(op.f("ix_access_otp_email_hash"), table_name="access_otp")
    op.drop_index(op.f("ix_access_otp_site_id"), table_name="access_otp")
    op.drop_table("access_otp")
    with op.batch_alter_table("edges") as batch_op:
        batch_op.drop_column("waiting_room")
        batch_op.drop_column("errors_last_hour")
