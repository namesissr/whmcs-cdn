"""wave 8 (SPEC §16.4/§16.7): l4_ports (TCP/UDP proxy edge ports, unique per edge group) and the
weighted / health-checked DNS record columns (records.weight, health_protocol, health_path and the
controller probe state health_ok / health_fail / health_at / health_ms / health_error)

Revision ID: 0017
Revises: 0016
Create Date: 2026-10-01
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0017"
down_revision: str | None = "0016"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# NULL = not weighted / tcp / never probed (every existing record keeps today's behaviour)
NULLABLE = [
    ("weight", sa.Integer()),
    ("health_protocol", sa.String(length=8)),
    ("health_path", sa.String(length=512)),
    ("health_ok", sa.Boolean()),
    ("health_at", sa.DateTime()),
    ("health_ms", sa.Integer()),
    ("health_error", sa.Text()),
]


def upgrade() -> None:
    insp = sa.inspect(op.get_bind())
    # a database created by create_all of the current models already has the columns / table
    existing = {c["name"] for c in insp.get_columns("records")}
    missing = [(name, type_) for name, type_ in NULLABLE if name not in existing]
    counter = "health_fail" not in existing
    if missing or counter:
        with op.batch_alter_table("records") as batch_op:
            for name, type_ in missing:
                batch_op.add_column(sa.Column(name, type_, nullable=True))
            if counter:  # NOT NULL counter: server default for the existing rows, dropped afterwards
                batch_op.add_column(sa.Column("health_fail", sa.Integer(), nullable=False,
                                              server_default=sa.text("0")))
        if counter:
            with op.batch_alter_table("records") as batch_op:
                batch_op.alter_column("health_fail", existing_type=sa.Integer(), existing_nullable=False,
                                      server_default=None)
    if "l4_ports" not in set(insp.get_table_names()):
        op.create_table(
            "l4_ports",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("group", sa.String(length=16), nullable=False),
            sa.Column("port", sa.Integer(), nullable=False),
            sa.Column("site_id", sa.Integer(), sa.ForeignKey("sites.id", ondelete="CASCADE"), nullable=False),
            sa.Column("app_id", sa.String(length=32), nullable=False),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.UniqueConstraint("group", "port", name="uq_l4_ports_group_port"),
        )
        op.create_index(op.f("ix_l4_ports_site_id"), "l4_ports", ["site_id"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_l4_ports_site_id"), table_name="l4_ports")
    op.drop_table("l4_ports")
    with op.batch_alter_table("records") as batch_op:
        for name in ("health_error", "health_ms", "health_at", "health_fail", "health_ok", "health_path",
                     "health_protocol", "weight"):
            batch_op.drop_column(name)
