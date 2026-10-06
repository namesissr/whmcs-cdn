"""baseline: the schema as created by Base.metadata.create_all before migrations existed

Databases created by older controller versions (create_all, no alembic_version table)
are stamped with this revision by app.migrate and then upgraded normally.

Revision ID: 0001
Revises:
Create Date: 2026-09-28
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op


revision: str = '0001'
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table('edges',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=64), nullable=False),
    sa.Column('ipv4', sa.String(length=45), nullable=False),
    sa.Column('ipv6', sa.String(length=45), nullable=True),
    sa.Column('region', sa.String(length=16), nullable=False),
    sa.Column('token_hash', sa.String(length=64), nullable=False),
    sa.Column('enabled', sa.Boolean(), nullable=False),
    sa.Column('last_seen_at', sa.DateTime(), nullable=True),
    sa.Column('applied_version', sa.String(length=64), nullable=True),
    sa.Column('last_error', sa.Text(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('name'),
    sa.UniqueConstraint('token_hash')
    )
    op.create_table('sites',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('domain', sa.String(length=253), nullable=False),
    sa.Column('external_id', sa.String(length=64), nullable=True),
    sa.Column('status', sa.String(length=20), nullable=False),
    sa.Column('suspended', sa.Boolean(), nullable=False),
    sa.Column('over_quota', sa.Boolean(), nullable=False),
    sa.Column('ns_verified_at', sa.DateTime(), nullable=True),
    sa.Column('ns_checked_at', sa.DateTime(), nullable=True),
    sa.Column('ns_found', sa.Text(), nullable=False),
    sa.Column('bandwidth_limit_gb', sa.Integer(), nullable=False),
    sa.Column('max_records', sa.Integer(), nullable=False),
    sa.Column('ssl_allowed', sa.Boolean(), nullable=False),
    sa.Column('rate_limit_rps', sa.Integer(), nullable=False),
    sa.Column('features', sa.Text(), nullable=False),
    sa.Column('config', sa.Text(), nullable=False),
    sa.Column('blocked_ips', sa.Text(), nullable=False),
    sa.Column('secret', sa.String(length=64), nullable=False),
    sa.Column('dnssec_enabled', sa.Boolean(), nullable=False),
    sa.Column('ssl_status', sa.String(length=10), nullable=False),
    sa.Column('ssl_cert', sa.Text(), nullable=True),
    sa.Column('ssl_key', sa.Text(), nullable=True),
    sa.Column('ssl_expires_at', sa.DateTime(), nullable=True),
    sa.Column('ssl_error', sa.Text(), nullable=True),
    sa.Column('ssl_source', sa.String(length=12), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_sites_domain'), 'sites', ['domain'], unique=True)
    op.create_table('state',
    sa.Column('key', sa.String(length=64), nullable=False),
    sa.Column('value', sa.Text(), nullable=False),
    sa.PrimaryKeyConstraint('key')
    )
    op.create_table('purges',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('site_id', sa.Integer(), nullable=False),
    sa.Column('urls', sa.Text(), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['site_id'], ['sites.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_purges_site_id'), 'purges', ['site_id'], unique=False)
    op.create_table('records',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('site_id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=253), nullable=False),
    sa.Column('type', sa.String(length=10), nullable=False),
    sa.Column('content', sa.Text(), nullable=False),
    sa.Column('ttl', sa.Integer(), nullable=False),
    sa.Column('priority', sa.Integer(), nullable=True),
    sa.Column('proxied', sa.Boolean(), nullable=False),
    sa.Column('pool', sa.String(length=32), nullable=True),
    sa.Column('origin_port', sa.Integer(), nullable=True),
    sa.Column('health_check', sa.Boolean(), nullable=False),
    sa.Column('health_port', sa.Integer(), nullable=True),
    sa.ForeignKeyConstraint(['site_id'], ['sites.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_records_site_id'), 'records', ['site_id'], unique=False)
    op.create_table('security_events',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('site_id', sa.Integer(), nullable=False),
    sa.Column('edge_id', sa.Integer(), nullable=True),
    sa.Column('ts', sa.DateTime(), nullable=False),
    sa.Column('ip', sa.String(length=45), nullable=False),
    sa.Column('country', sa.String(length=2), nullable=False),
    sa.Column('method', sa.String(length=10), nullable=False),
    sa.Column('host', sa.String(length=253), nullable=False),
    sa.Column('path', sa.Text(), nullable=False),
    sa.Column('action', sa.String(length=12), nullable=False),
    sa.Column('source', sa.String(length=12), nullable=False),
    sa.Column('rule', sa.String(length=64), nullable=False),
    sa.Column('user_agent', sa.Text(), nullable=False),
    sa.ForeignKeyConstraint(['site_id'], ['sites.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_security_events_site_id'), 'security_events', ['site_id'], unique=False)
    op.create_index(op.f('ix_security_events_ts'), 'security_events', ['ts'], unique=False)
    op.create_table('usage_hourly',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('site_id', sa.Integer(), nullable=False),
    sa.Column('edge_id', sa.Integer(), nullable=False),
    sa.Column('hour', sa.DateTime(), nullable=False),
    sa.Column('bytes', sa.BigInteger(), nullable=False),
    sa.Column('requests', sa.BigInteger(), nullable=False),
    sa.Column('cache_hits', sa.BigInteger(), nullable=False),
    sa.Column('details', sa.Text(), nullable=False),
    sa.ForeignKeyConstraint(['edge_id'], ['edges.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['site_id'], ['sites.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('site_id', 'edge_id', 'hour')
    )
    op.create_index(op.f('ix_usage_hourly_hour'), 'usage_hourly', ['hour'], unique=False)
    op.create_index(op.f('ix_usage_hourly_site_id'), 'usage_hourly', ['site_id'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_usage_hourly_site_id'), table_name='usage_hourly')
    op.drop_index(op.f('ix_usage_hourly_hour'), table_name='usage_hourly')
    op.drop_table('usage_hourly')
    op.drop_index(op.f('ix_security_events_ts'), table_name='security_events')
    op.drop_index(op.f('ix_security_events_site_id'), table_name='security_events')
    op.drop_table('security_events')
    op.drop_index(op.f('ix_records_site_id'), table_name='records')
    op.drop_table('records')
    op.drop_index(op.f('ix_purges_site_id'), table_name='purges')
    op.drop_table('purges')
    op.drop_table('state')
    op.drop_index(op.f('ix_sites_domain'), table_name='sites')
    op.drop_table('sites')
    op.drop_table('edges')
