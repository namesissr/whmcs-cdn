"""sites.secret: String(64) -> Text, so it can hold an encrypted value (enc:v1:...)

Revision ID: 0002
Revises: 0001
Create Date: 2026-09-28
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("sites") as batch_op:
        batch_op.alter_column("secret", existing_type=sa.String(length=64), type_=sa.Text(),
                              existing_nullable=False)


def downgrade() -> None:
    # only possible while secrets are stored in plaintext (64 hex characters): refuse clearly instead of
    # failing half-way on PostgreSQL / silently over-filling the column on SQLite
    n = op.get_bind().execute(sa.text("SELECT count(*) FROM sites WHERE length(secret) > 64")).scalar()
    if n:
        raise RuntimeError(f"cannot downgrade below 0002: {n} site secret(s) are longer than 64 characters "
                           "(encrypted with DATA_ENCRYPTION_KEY); decrypt them first or stay at >= 0002")
    with op.batch_alter_table("sites") as batch_op:
        batch_op.alter_column("secret", existing_type=sa.Text(), type_=sa.String(length=64),
                              existing_nullable=False)
