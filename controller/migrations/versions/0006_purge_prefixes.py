"""purges: prefixes + everything columns (prefix / whole-cache purge, SPEC §9.2)

Revision ID: 0006
Revises: 0005
Create Date: 2026-09-30
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0006"
down_revision: str | None = "0005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# NOT NULL columns get a server default so existing purge rows are filled in; the default is
# dropped afterwards because the model sets these values itself (like 0003/0004/0005)
DEFAULTED = [
    ("prefixes", sa.Text(), sa.text("'[]'")),
    ("everything", sa.Boolean(), sa.false()),
]


def upgrade() -> None:
    # a database created by create_all of these models already has the columns
    existing = {c["name"] for c in sa.inspect(op.get_bind()).get_columns("purges")}
    defaulted = [c for c in DEFAULTED if c[0] not in existing]
    if not defaulted:
        return
    with op.batch_alter_table("purges") as batch_op:
        for name, type_, default in defaulted:
            batch_op.add_column(sa.Column(name, type_, nullable=False, server_default=default))
    with op.batch_alter_table("purges") as batch_op:
        for name, type_, _ in defaulted:
            batch_op.alter_column(name, existing_type=type_, existing_nullable=False, server_default=None)


def downgrade() -> None:
    with op.batch_alter_table("purges") as batch_op:
        for name in ("everything", "prefixes"):
            batch_op.drop_column(name)
