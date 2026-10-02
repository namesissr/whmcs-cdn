"""operator sites and domain transfer (SPEC §19): sites.owner_kind (client | reseller | operator;
existing rows: reseller_client_id set -> reseller, else client), sites.operator_note (≤200, admin
only) and sites.billing_since (quota / WHMCS month usage count from max(month start, billing_since));
storage_buckets.credentials_rotation_pending_at (a transfer's access-key rotation not yet done on MinIO).

Revision ID: 0021
Revises: 0020
Create Date: 2026-10-02
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0021"
down_revision: str | None = "0020"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# sites.id is AUTOINCREMENT on SQLite (0019); keep it when a batch operation rebuilds the table
_KW = {"table_kwargs": {"sqlite_autoincrement": True}}


def upgrade() -> None:
    conn = op.get_bind()
    cols = {c["name"] for c in sa.inspect(conn).get_columns("sites")}
    # a database created by create_all of the current models already has them
    with op.batch_alter_table("sites", **_KW) as batch_op:
        if "owner_kind" not in cols:
            batch_op.add_column(sa.Column("owner_kind", sa.String(length=10), nullable=False,
                                          server_default="client"))
        if "operator_note" not in cols:
            batch_op.add_column(sa.Column("operator_note", sa.String(length=200), nullable=True))
        if "billing_since" not in cols:
            batch_op.add_column(sa.Column("billing_since", sa.DateTime(), nullable=True))
    bcols = {c["name"] for c in sa.inspect(conn).get_columns("storage_buckets")}
    if "credentials_rotation_pending_at" not in bcols:
        with op.batch_alter_table("storage_buckets") as batch_op:
            batch_op.add_column(sa.Column("credentials_rotation_pending_at", sa.DateTime(), nullable=True))
    if "owner_kind" not in cols:
        sites = sa.table("sites", sa.column("owner_kind", sa.String()), sa.column("reseller_client_id", sa.Integer()))
        conn.execute(sites.update().where(sites.c.reseller_client_id.is_not(None)).values(owner_kind="reseller"))


def downgrade() -> None:
    with op.batch_alter_table("storage_buckets") as batch_op:
        batch_op.drop_column("credentials_rotation_pending_at")
    with op.batch_alter_table("sites", **_KW) as batch_op:
        batch_op.drop_column("billing_since")
        batch_op.drop_column("operator_note")
        batch_op.drop_column("owner_kind")
