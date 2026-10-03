"""synthetic edge probe fields + incidents / incident_updates (SPEC §8)

Revision ID: 0005
Revises: 0004
Create Date: 2026-09-30
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0005"
down_revision: str | None = "0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# nullable probe fields; probe_fail is NOT NULL, so it gets a server default that is dropped
# afterwards (existing edges start at 0), like 0003/0004
NULLABLE = [
    ("probe_ok", sa.Boolean()),
    ("probe_ms", sa.Integer()),
    ("probe_at", sa.DateTime()),
    ("probe_error", sa.Text()),
]
DEFAULTED = [
    ("probe_fail", sa.Integer(), sa.text("0")),
]


def upgrade() -> None:
    bind = op.get_bind()
    insp = sa.inspect(bind)

    existing = {c["name"] for c in insp.get_columns("edges")}
    nullable = [(name, type_) for name, type_ in NULLABLE if name not in existing]
    defaulted = [c for c in DEFAULTED if c[0] not in existing]
    if nullable or defaulted:
        with op.batch_alter_table("edges") as batch_op:
            for name, type_ in nullable:
                batch_op.add_column(sa.Column(name, type_, nullable=True))
            for name, type_, default in defaulted:
                batch_op.add_column(sa.Column(name, type_, nullable=False, server_default=default))
        if defaulted:
            with op.batch_alter_table("edges") as batch_op:
                for name, type_, _ in defaulted:
                    batch_op.alter_column(name, existing_type=type_, existing_nullable=False,
                                          server_default=None)

    if "incidents" not in insp.get_table_names():
        op.create_table(
            "incidents",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("title", sa.String(length=200), nullable=False),
            sa.Column("body", sa.Text(), nullable=False),
            sa.Column("severity", sa.String(length=16), nullable=False),
            sa.Column("status", sa.String(length=16), nullable=False),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.Column("updated_at", sa.DateTime(), nullable=False),
        )
    if "incident_updates" not in insp.get_table_names():
        op.create_table(
            "incident_updates",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("incident_id", sa.Integer(),
                      sa.ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False),
            sa.Column("status", sa.String(length=16), nullable=False),
            sa.Column("body", sa.Text(), nullable=False),
            sa.Column("created_at", sa.DateTime(), nullable=False),
        )
        op.create_index("ix_incident_updates_incident_id", "incident_updates", ["incident_id"])


def downgrade() -> None:
    op.drop_table("incident_updates")
    op.drop_table("incidents")
    with op.batch_alter_table("edges") as batch_op:
        for name in ("probe_fail", "probe_error", "probe_at", "probe_ms", "probe_ok"):
            batch_op.drop_column(name)
