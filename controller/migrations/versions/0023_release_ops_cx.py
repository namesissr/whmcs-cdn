"""wave 14 (SPEC §23): release safety, operations and customer experience.

edges: display_city / display_city_en (§23.12 customer-visible label), release (§23.1 heartbeat
`release`), upgrade_state (§23.2 heartbeat `upgrade`).
sites: abuse_suspended (§23.10, default false).
New tables: site_config_versions + site_config_values (§23.4), backup_runs + pcdn_live_marker (§23.3,
one row, live database only), notification_subscriptions / _targets / _link_codes / _outbox (§23.5),
import_sessions (§23.6), rum_hourly (§23.7), abuse_reports + abuse_events (§23.10), slo_buckets
(§23.11), rollouts + rollout_edges (§23.2), edge_join_tokens + provision_proposals (§23.9).

Idempotent like 0021/0022: a database created by create_all of the current models already has them.

Revision ID: 0023
Revises: 0022
Create Date: 2026-10-03
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0023"
down_revision: str | None = "0022"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# sites.id is AUTOINCREMENT on SQLite (0019); keep it when a batch operation rebuilds the table
_KW = {"table_kwargs": {"sqlite_autoincrement": True}}

EDGE_NULLABLE = [
    ("display_city", sa.String(length=32)),
    ("display_city_en", sa.String(length=32)),
    ("release", sa.String(length=40)),
    ("upgrade_state", sa.Text()),
]


def _id():
    return sa.Column("id", sa.Integer(), primary_key=True)


def _tables() -> list[tuple[str, list, list[tuple[str, list[str], bool]]]]:
    """(name, columns + constraints, indexes [(column-derived name suffix, columns, unique)])."""
    return [
        ("site_config_versions", [
            _id(),
            sa.Column("site_id", sa.Integer(), sa.ForeignKey("sites.id", ondelete="CASCADE"), nullable=False),
            sa.Column("version", sa.Integer(), nullable=False),
            sa.Column("at", sa.DateTime(), nullable=False),
            sa.Column("actor_kind", sa.String(length=16), nullable=False),
            sa.Column("actor", sa.String(length=120), nullable=False),
            sa.Column("on_behalf_of", sa.String(length=64), nullable=True),
            sa.Column("source", sa.String(length=16), nullable=False),
            sa.Column("sections", sa.Text(), nullable=False),
            sa.Column("restored_from", sa.Integer(), nullable=True),
            sa.UniqueConstraint("site_id", "version", name="uq_site_config_versions_site_version"),
        ], [("site_id", ["site_id"], False), ("at", ["at"], False)]),
        ("site_config_values", [
            _id(),
            sa.Column("version_id", sa.Integer(), sa.ForeignKey("site_config_versions.id", ondelete="CASCADE"),
                      nullable=False),
            sa.Column("section", sa.String(length=32), nullable=False),
            sa.Column("sha256", sa.String(length=64), nullable=False),
            sa.Column("value", sa.Text(), nullable=False),
            sa.UniqueConstraint("version_id", "section", name="uq_site_config_values_version_section"),
        ], [("version_id", ["version_id"], False)]),
        ("backup_runs", [
            _id(),
            sa.Column("kind", sa.String(length=8), nullable=False),
            sa.Column("started_at", sa.DateTime(), nullable=False),
            sa.Column("finished_at", sa.DateTime(), nullable=True),
            sa.Column("ok", sa.Boolean(), nullable=True),
            sa.Column("name", sa.String(length=80), nullable=True),
            sa.Column("size", sa.BigInteger(), nullable=True),
            sa.Column("sha256", sa.String(length=64), nullable=True),
            sa.Column("location", sa.String(length=8), nullable=True),
            sa.Column("level", sa.String(length=8), nullable=True),
            sa.Column("checks", sa.Text(), nullable=False),
            sa.Column("error", sa.Text(), nullable=True),
        ], [("started_at", ["started_at"], False)]),
        ("pcdn_live_marker", [_id()], []),
        ("notification_subscriptions", [
            _id(),
            sa.Column("client_id", sa.Integer(), nullable=False),
            sa.Column("site_id", sa.Integer(), sa.ForeignKey("sites.id", ondelete="CASCADE"), nullable=True),
            sa.Column("events", sa.Text(), nullable=False),
            sa.Column("channels", sa.Text(), nullable=False),
            sa.Column("lang", sa.String(length=2), nullable=False),
            sa.Column("quiet_start", sa.String(length=5), nullable=True),
            sa.Column("quiet_end", sa.String(length=5), nullable=True),
            sa.Column("quiet_bypass_critical", sa.Boolean(), nullable=False),
            sa.Column("enabled", sa.Boolean(), nullable=False),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.Column("updated_at", sa.DateTime(), nullable=False),
        ], [("client_id", ["client_id"], False)]),
        ("notification_targets", [
            _id(),
            sa.Column("client_id", sa.Integer(), nullable=False),
            sa.Column("channel", sa.String(length=8), nullable=False),
            sa.Column("value", sa.Text(), nullable=False),
            sa.Column("value_hash", sa.String(length=64), nullable=False),
            sa.Column("masked", sa.String(length=32), nullable=False),
            sa.Column("verified_at", sa.DateTime(), nullable=True),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.Column("disabled_at", sa.DateTime(), nullable=True),
            sa.Column("fail_count", sa.Integer(), nullable=False),
        ], [("client_id", ["client_id"], False), ("value_hash", ["value_hash"], False)]),
        ("notification_link_codes", [
            _id(),
            sa.Column("client_id", sa.Integer(), nullable=False),
            sa.Column("kind", sa.String(length=16), nullable=False),
            sa.Column("target_id", sa.Integer(), nullable=True),
            sa.Column("code_hash", sa.String(length=64), nullable=False),
            sa.Column("expires_at", sa.DateTime(), nullable=False),
            sa.Column("tries", sa.Integer(), nullable=False),
            sa.Column("used_at", sa.DateTime(), nullable=True),
            sa.Column("created_at", sa.DateTime(), nullable=False),
        ], [("client_id", ["client_id"], False), ("code_hash", ["code_hash"], False),
            ("created_at", ["created_at"], False)]),
        ("notification_outbox", [
            _id(),
            sa.Column("client_id", sa.Integer(), nullable=False),
            sa.Column("site_id", sa.Integer(), sa.ForeignKey("sites.id", ondelete="SET NULL"), nullable=True),
            sa.Column("event", sa.String(length=32), nullable=False),
            sa.Column("severity", sa.String(length=8), nullable=False),
            sa.Column("channel", sa.String(length=8), nullable=False),
            sa.Column("target_id", sa.Integer(), nullable=True),
            sa.Column("lang", sa.String(length=2), nullable=False),
            sa.Column("subject", sa.Text(), nullable=False),
            sa.Column("text", sa.Text(), nullable=False),
            sa.Column("vars", sa.Text(), nullable=False),
            sa.Column("dedup_key", sa.String(length=128), nullable=False),
            sa.Column("status", sa.String(length=10), nullable=False),
            sa.Column("attempts", sa.Integer(), nullable=False),
            sa.Column("next_attempt_at", sa.DateTime(), nullable=True),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.Column("sent_at", sa.DateTime(), nullable=True),
            sa.Column("error", sa.Text(), nullable=True),
        ], [("client_id", ["client_id"], False), ("dedup_key", ["dedup_key"], False),
            ("next_attempt_at", ["next_attempt_at"], False), ("created_at", ["created_at"], False)]),
        ("import_sessions", [
            sa.Column("id", sa.String(length=20), primary_key=True),
            sa.Column("site_id", sa.Integer(), sa.ForeignKey("sites.id", ondelete="CASCADE"), nullable=False),
            sa.Column("provider", sa.String(length=16), nullable=False),
            sa.Column("data", sa.Text(), nullable=False),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.Column("expires_at", sa.DateTime(), nullable=False),
        ], [("expires_at", ["expires_at"], False)]),
        ("rum_hourly", [
            _id(),
            sa.Column("site_id", sa.Integer(), sa.ForeignKey("sites.id", ondelete="CASCADE"), nullable=False),
            sa.Column("hour", sa.DateTime(), nullable=False),
            sa.Column("dim", sa.String(length=8), nullable=False),
            sa.Column("key", sa.String(length=200), nullable=False),
            sa.Column("n", sa.BigInteger(), nullable=False),
            sa.Column("hist", sa.Text(), nullable=False),
            sa.UniqueConstraint("site_id", "hour", "dim", "key", name="uq_rum_hourly"),
        ], [("hour", ["hour"], False)]),
        ("abuse_reports", [
            _id(),
            sa.Column("ticket", sa.String(length=12), nullable=False, unique=True),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.Column("category", sa.String(length=16), nullable=False),
            sa.Column("urls", sa.Text(), nullable=False),
            sa.Column("description", sa.Text(), nullable=False),
            sa.Column("reporter_email", sa.Text(), nullable=True),
            sa.Column("reporter_email_hash", sa.String(length=64), nullable=True),
            sa.Column("reporter_ip_hash", sa.String(length=64), nullable=True),
            sa.Column("status_token_hash", sa.String(length=64), nullable=False),
            sa.Column("status", sa.String(length=10), nullable=False),
            sa.Column("site_id", sa.Integer(), sa.ForeignKey("sites.id", ondelete="SET NULL"), nullable=True),
            sa.Column("deadline_at", sa.DateTime(), nullable=True),
            sa.Column("action", sa.String(length=12), nullable=False),
            sa.Column("public_note", sa.Text(), nullable=True),
            sa.Column("updated_at", sa.DateTime(), nullable=False),
            sa.Column("closed_at", sa.DateTime(), nullable=True),
        ], [("created_at", ["created_at"], False), ("reporter_ip_hash", ["reporter_ip_hash"], False),
            ("status", ["status"], False), ("site_id", ["site_id"], False)]),
        ("abuse_events", [
            _id(),
            sa.Column("report_id", sa.Integer(), sa.ForeignKey("abuse_reports.id", ondelete="CASCADE"),
                      nullable=False),
            sa.Column("at", sa.DateTime(), nullable=False),
            sa.Column("actor", sa.String(length=64), nullable=False),
            sa.Column("kind", sa.String(length=16), nullable=False),
            sa.Column("data", sa.Text(), nullable=False),
        ], [("report_id", ["report_id"], False)]),
        ("slo_buckets", [
            _id(),
            sa.Column("group", sa.String(length=16), nullable=False),
            sa.Column("start", sa.DateTime(), nullable=False),
            sa.Column("res", sa.String(length=3), nullable=False),
            sa.Column("avail_good", sa.BigInteger(), nullable=False),
            sa.Column("avail_total", sa.BigInteger(), nullable=False),
            sa.Column("lat_good", sa.BigInteger(), nullable=False),
            sa.Column("lat_total", sa.BigInteger(), nullable=False),
            sa.Column("requests", sa.BigInteger(), nullable=False),
            sa.Column("errors", sa.BigInteger(), nullable=False),
            sa.UniqueConstraint("group", "start", "res", name="uq_slo_buckets"),
        ], []),
        ("rollouts", [
            _id(),
            sa.Column("release", sa.String(length=40), nullable=False),
            sa.Column("groups", sa.Text(), nullable=True),
            sa.Column("state", sa.String(length=16), nullable=False),
            sa.Column("ring", sa.Integer(), nullable=False),
            sa.Column("soak_minutes", sa.Integer(), nullable=False),
            sa.Column("ring_percent", sa.Integer(), nullable=False),
            sa.Column("auto_rollback", sa.Boolean(), nullable=False),
            sa.Column("allow_no_rollback", sa.Boolean(), nullable=False),
            sa.Column("reason", sa.String(length=200), nullable=True),
            sa.Column("created_by", sa.String(length=64), nullable=False),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.Column("started_at", sa.DateTime(), nullable=True),
            sa.Column("finished_at", sa.DateTime(), nullable=True),
        ], [("state", ["state"], False)]),
        ("rollout_edges", [
            _id(),
            sa.Column("rollout_id", sa.Integer(), sa.ForeignKey("rollouts.id", ondelete="CASCADE"), nullable=False),
            sa.Column("edge_id", sa.Integer(), sa.ForeignKey("edges.id", ondelete="CASCADE"), nullable=False),
            sa.Column("ring", sa.Integer(), nullable=False),
            sa.Column("from_release", sa.String(length=40), nullable=True),
            sa.Column("state", sa.String(length=16), nullable=False),
            sa.Column("started_at", sa.DateTime(), nullable=True),
            sa.Column("soak_until", sa.DateTime(), nullable=True),
            sa.Column("finished_at", sa.DateTime(), nullable=True),
            sa.Column("error", sa.String(length=500), nullable=True),
            sa.Column("attempts", sa.Integer(), nullable=False),
            sa.Column("force_no_drain", sa.Boolean(), nullable=False),
            sa.Column("baseline_err_pct", sa.Float(), nullable=True),
            sa.UniqueConstraint("rollout_id", "edge_id", name="uq_rollout_edges"),
        ], [("rollout_id", ["rollout_id"], False)]),
        ("edge_join_tokens", [
            _id(),
            sa.Column("edge_id", sa.Integer(), sa.ForeignKey("edges.id", ondelete="CASCADE"), nullable=False),
            sa.Column("token_hash", sa.String(length=64), nullable=False, unique=True),
            sa.Column("expires_at", sa.DateTime(), nullable=False),
            sa.Column("used_at", sa.DateTime(), nullable=True),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.Column("created_by", sa.String(length=64), nullable=False),
        ], [("edge_id", ["edge_id"], False)]),
        ("provision_proposals", [
            _id(),
            sa.Column("group", sa.String(length=16), nullable=False),
            sa.Column("region", sa.String(length=16), nullable=False),
            sa.Column("size", sa.String(length=16), nullable=False),
            sa.Column("count", sa.Integer(), nullable=False),
            sa.Column("reason", sa.Text(), nullable=False),
            sa.Column("state", sa.String(length=16), nullable=False),
            sa.Column("plan_summary", sa.Text(), nullable=True),
            sa.Column("plan_adds", sa.Integer(), nullable=True),
            sa.Column("plan_changes", sa.Integer(), nullable=True),
            sa.Column("plan_destroys", sa.Integer(), nullable=True),
            sa.Column("plan_at", sa.DateTime(), nullable=True),
            sa.Column("join_tokens_enc", sa.Text(), nullable=True),
            sa.Column("edge_ids", sa.Text(), nullable=False),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.Column("decided_by", sa.String(length=64), nullable=True),
            sa.Column("error", sa.Text(), nullable=True),
            sa.Column("updated_at", sa.DateTime(), nullable=False),
        ], [("state", ["state"], False)]),
    ]


def upgrade() -> None:
    conn = op.get_bind()
    insp = sa.inspect(conn)
    existing = {c["name"] for c in insp.get_columns("edges")}
    new = [c for c in EDGE_NULLABLE if c[0] not in existing]
    if new:
        with op.batch_alter_table("edges") as batch_op:
            for name, type_ in new:
                batch_op.add_column(sa.Column(name, type_, nullable=True))

    if "abuse_suspended" not in {c["name"] for c in insp.get_columns("sites")}:
        # existing sites are not abuse-suspended; the default is dropped again (the model sets it)
        with op.batch_alter_table("sites", **_KW) as batch_op:
            batch_op.add_column(sa.Column("abuse_suspended", sa.Boolean(), nullable=False, server_default=sa.false()))
        with op.batch_alter_table("sites", **_KW) as batch_op:
            batch_op.alter_column("abuse_suspended", existing_type=sa.Boolean(), existing_nullable=False,
                                  server_default=None)

    tables = set(sa.inspect(conn).get_table_names())
    for name, cols, indexes in _tables():
        if name in tables:
            continue
        op.create_table(name, *cols)
        for suffix, columns, unique in indexes:
            op.create_index(op.f(f"ix_{name}_{suffix}"), name, columns, unique=unique)
        if name == "pcdn_live_marker":
            op.execute(sa.text("INSERT INTO pcdn_live_marker (id) VALUES (1)"))


def downgrade() -> None:
    for name, _, indexes in reversed(_tables()):
        for suffix, _, _ in indexes:
            op.drop_index(op.f(f"ix_{name}_{suffix}"), table_name=name)
        op.drop_table(name)
    with op.batch_alter_table("sites", **_KW) as batch_op:
        batch_op.drop_column("abuse_suspended")
    with op.batch_alter_table("edges") as batch_op:
        for name, _ in reversed(EDGE_NULLABLE):
            batch_op.drop_column(name)
