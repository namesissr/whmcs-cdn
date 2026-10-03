"""edges.shield (origin shield / tiered cache) and edges.capabilities (heartbeat-reported node
capabilities: http3, early_hints, webp_convert, modules), SPEC §14.1

Revision ID: 0013
Revises: 0012
Create Date: 2026-10-01
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0013"
down_revision: str | None = "0012"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# NOT NULL columns get a server default so existing edges are filled in (no edge is a shield after
# the upgrade); the default is dropped afterwards because the model sets the value, like 0003/0011
DEFAULTED = [
    ("shield", sa.Boolean(), sa.false()),
]
# nullable: NULL capabilities = the node has not reported any yet (older agent)
NULLABLE = [
    ("capabilities", sa.Text()),
]


def upgrade() -> None:
    # a database created by create_all of the current models already has the columns
    existing = {c["name"] for c in sa.inspect(op.get_bind()).get_columns("edges")}
    defaulted = [c for c in DEFAULTED if c[0] not in existing]
    nullable = [(name, type_) for name, type_ in NULLABLE if name not in existing]
    if not defaulted and not nullable:
        return
    with op.batch_alter_table("edges") as batch_op:
        for name, type_, default in defaulted:
            batch_op.add_column(sa.Column(name, type_, nullable=False, server_default=default))
        for name, type_ in nullable:
            batch_op.add_column(sa.Column(name, type_, nullable=True))
    if defaulted:
        with op.batch_alter_table("edges") as batch_op:
            for name, type_, _ in defaulted:
                batch_op.alter_column(name, existing_type=type_, existing_nullable=False, server_default=None)


def downgrade() -> None:
    with op.batch_alter_table("edges") as batch_op:
        for name in ("capabilities", "shield"):
            batch_op.drop_column(name)
