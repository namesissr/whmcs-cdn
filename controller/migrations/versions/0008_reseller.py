"""sites.reseller_client_id / reseller_label: reseller sub-site tag (SPEC §10.5)

Revision ID: 0008
Revises: 0007
Create Date: 2026-09-30
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0008"
down_revision: str | None = "0007"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    bind = op.get_bind()
    insp = sa.inspect(bind)
    # a database created by create_all of these models already has the columns/index
    existing = {c["name"] for c in insp.get_columns("sites")}
    with op.batch_alter_table("sites") as batch_op:
        if "reseller_client_id" not in existing:
            batch_op.add_column(sa.Column("reseller_client_id", sa.Integer(), nullable=True))
        if "reseller_label" not in existing:
            batch_op.add_column(sa.Column("reseller_label", sa.String(length=120), nullable=True))
    indexes = {i["name"] for i in insp.get_indexes("sites")}
    if "ix_sites_reseller_client_id" not in indexes:
        op.create_index(op.f("ix_sites_reseller_client_id"), "sites", ["reseller_client_id"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_sites_reseller_client_id"), table_name="sites")
    with op.batch_alter_table("sites") as batch_op:
        for name in ("reseller_label", "reseller_client_id"):
            batch_op.drop_column(name)
