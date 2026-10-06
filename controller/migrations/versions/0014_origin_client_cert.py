"""sites.origin_client_cert / origin_client_key / origin_client_expires_at: the customer-uploaded
client certificate for authenticated origin pulls (ssl.origin_client_auth = custom), SPEC §14.2.
The key is encrypted at rest like sites.ssl_key.

Revision ID: 0014
Revises: 0013
Create Date: 2026-10-01
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0014"
down_revision: str | None = "0013"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# all nullable: NULL = no custom origin client certificate uploaded (every existing site)
NULLABLE = [
    ("origin_client_cert", sa.Text()),
    ("origin_client_key", sa.Text()),
    ("origin_client_expires_at", sa.DateTime()),
]


def upgrade() -> None:
    # a database created by create_all of the current models already has the columns
    existing = {c["name"] for c in sa.inspect(op.get_bind()).get_columns("sites")}
    missing = [(name, type_) for name, type_ in NULLABLE if name not in existing]
    if not missing:
        return
    with op.batch_alter_table("sites") as batch_op:
        for name, type_ in missing:
            batch_op.add_column(sa.Column(name, type_, nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("sites") as batch_op:
        for name in ("origin_client_expires_at", "origin_client_key", "origin_client_cert"):
            batch_op.drop_column(name)
