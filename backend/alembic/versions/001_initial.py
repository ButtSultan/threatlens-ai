"""Initial migration - create all tables

Revision ID: 001_initial
Revises: 
Create Date: 2024-01-01 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql
import uuid

revision = '001_initial'
down_revision = None
branch_labels = None
depends_on = None


def _uuid_col(name, **kwargs):
    """UUID column compatible with both PostgreSQL and SQLite."""
    from alembic import op
    from sqlalchemy.engine import reflection
    bind = op.get_bind()
    if bind.dialect.name == 'postgresql':
        return sa.Column(name, postgresql.UUID(as_uuid=True), **kwargs)
    return sa.Column(name, sa.String(36), **kwargs)


def upgrade() -> None:
    bind = op.get_bind()
    is_pg = bind.dialect.name == 'postgresql'

    def uuid_type():
        return postgresql.UUID(as_uuid=True) if is_pg else sa.String(36)

    def enum_type(name, *values):
        # Use non-native VARCHAR enum for SQLite compatibility
        return sa.String(50)

    # Users
    op.create_table(
        'users',
        sa.Column('id', uuid_type(), nullable=False),
        sa.Column('username', sa.String(50), nullable=False),
        sa.Column('email', sa.String(255), nullable=False),
        sa.Column('hashed_password', sa.String(255), nullable=False),
        sa.Column('full_name', sa.String(100), nullable=True),
        sa.Column('role', sa.String(50), nullable=False, server_default='analyst'),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('is_verified', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('last_login', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_users_username', 'users', ['username'], unique=True)
    op.create_index('ix_users_email', 'users', ['email'], unique=True)

    # Log entries
    op.create_table(
        'log_entries',
        sa.Column('id', uuid_type(), nullable=False),
        sa.Column('source_file', sa.String(255), nullable=True),
        sa.Column('log_type', sa.String(50), nullable=False, server_default='json'),
        sa.Column('raw_data', sa.Text(), nullable=False),
        sa.Column('parsed_data', sa.JSON(), nullable=True),
        sa.Column('source_ip', sa.String(45), nullable=True),
        sa.Column('destination_ip', sa.String(45), nullable=True),
        sa.Column('username', sa.String(100), nullable=True),
        sa.Column('event_type', sa.String(100), nullable=True),
        sa.Column('event_id', sa.String(50), nullable=True),
        sa.Column('hostname', sa.String(255), nullable=True),
        sa.Column('timestamp', sa.DateTime(timezone=True), nullable=True),
        sa.Column('uploaded_by', uuid_type(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('batch_id', sa.String(50), nullable=True),
        sa.ForeignKeyConstraint(['uploaded_by'], ['users.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_log_entries_source_ip', 'log_entries', ['source_ip'])
    op.create_index('ix_log_entries_username', 'log_entries', ['username'])
    op.create_index('ix_log_entries_timestamp', 'log_entries', ['timestamp'])
    op.create_index('ix_log_entries_batch_id', 'log_entries', ['batch_id'])

    # Threat detections
    op.create_table(
        'threat_detections',
        sa.Column('id', uuid_type(), nullable=False),
        sa.Column('log_entry_id', uuid_type(), nullable=True),
        sa.Column('detection_type', sa.String(100), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('severity', sa.String(50), nullable=False),
        sa.Column('confidence_score', sa.Float(), nullable=True),
        sa.Column('raw_indicators', sa.JSON(), nullable=True),
        sa.Column('source_ips', sa.JSON(), nullable=True),
        sa.Column('affected_users', sa.JSON(), nullable=True),
        sa.Column('affected_hosts', sa.JSON(), nullable=True),
        sa.Column('first_seen', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.Column('last_seen', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.Column('event_count', sa.Integer(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.ForeignKeyConstraint(['log_entry_id'], ['log_entries.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_threat_detections_detection_type', 'threat_detections', ['detection_type'])
    op.create_index('ix_threat_detections_severity', 'threat_detections', ['severity'])

    # Alerts
    op.create_table(
        'alerts',
        sa.Column('id', uuid_type(), nullable=False),
        sa.Column('title', sa.String(255), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('severity', sa.String(50), nullable=False),
        sa.Column('status', sa.String(50), nullable=False, server_default='open'),
        sa.Column('detection_id', uuid_type(), nullable=True),
        sa.Column('assigned_to', uuid_type(), nullable=True),
        sa.Column('ai_summary', sa.Text(), nullable=True),
        sa.Column('ai_recommendations', sa.JSON(), nullable=True),
        sa.Column('analyst_notes', sa.Text(), nullable=True),
        sa.Column('false_positive', sa.Boolean(), nullable=True, server_default='false'),
        sa.Column('tags', sa.JSON(), nullable=True),
        sa.Column('resolved_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['assigned_to'], ['users.id']),
        sa.ForeignKeyConstraint(['detection_id'], ['threat_detections.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_alerts_severity', 'alerts', ['severity'])
    op.create_index('ix_alerts_status', 'alerts', ['status'])

    # MITRE mappings
    op.create_table(
        'mitre_mappings',
        sa.Column('id', uuid_type(), nullable=False),
        sa.Column('detection_id', uuid_type(), nullable=False),
        sa.Column('technique_id', sa.String(20), nullable=False),
        sa.Column('technique_name', sa.String(255), nullable=False),
        sa.Column('tactic', sa.String(100), nullable=False),
        sa.Column('tactic_id', sa.String(20), nullable=True),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('url', sa.String(500), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.ForeignKeyConstraint(['detection_id'], ['threat_detections.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_mitre_mappings_technique_id', 'mitre_mappings', ['technique_id'])
    op.create_index('ix_mitre_mappings_tactic', 'mitre_mappings', ['tactic'])

    # Incidents
    op.create_table(
        'incidents',
        sa.Column('id', uuid_type(), nullable=False),
        sa.Column('incident_number', sa.String(20), nullable=False),
        sa.Column('title', sa.String(255), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('severity', sa.String(50), nullable=False),
        sa.Column('status', sa.String(50), nullable=False, server_default='new'),
        sa.Column('alert_id', uuid_type(), nullable=True),
        sa.Column('affected_assets', sa.JSON(), nullable=True),
        sa.Column('timeline', sa.JSON(), nullable=True),
        sa.Column('containment_actions', sa.JSON(), nullable=True),
        sa.Column('root_cause', sa.Text(), nullable=True),
        sa.Column('lessons_learned', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('closed_at', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['alert_id'], ['alerts.id']),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('incident_number'),
    )

    # Reports
    op.create_table(
        'reports',
        sa.Column('id', uuid_type(), nullable=False),
        sa.Column('title', sa.String(255), nullable=False),
        sa.Column('report_type', sa.String(50), nullable=False),
        sa.Column('incident_id', uuid_type(), nullable=True),
        sa.Column('file_path', sa.String(500), nullable=True),
        sa.Column('content', sa.JSON(), nullable=True),
        sa.Column('generated_by', uuid_type(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.ForeignKeyConstraint(['generated_by'], ['users.id']),
        sa.ForeignKeyConstraint(['incident_id'], ['incidents.id']),
        sa.PrimaryKeyConstraint('id'),
    )

    # Audit logs
    op.create_table(
        'audit_logs',
        sa.Column('id', uuid_type(), nullable=False),
        sa.Column('user_id', uuid_type(), nullable=True),
        sa.Column('action', sa.String(100), nullable=False),
        sa.Column('resource_type', sa.String(50), nullable=True),
        sa.Column('resource_id', sa.String(100), nullable=True),
        sa.Column('details', sa.JSON(), nullable=True),
        sa.Column('ip_address', sa.String(45), nullable=True),
        sa.Column('user_agent', sa.String(500), nullable=True),
        sa.Column('success', sa.Boolean(), nullable=True, server_default='true'),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['users.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_audit_logs_action', 'audit_logs', ['action'])
    op.create_index('ix_audit_logs_created_at', 'audit_logs', ['created_at'])


def downgrade() -> None:
    op.drop_table('audit_logs')
    op.drop_table('reports')
    op.drop_table('incidents')
    op.drop_table('mitre_mappings')
    op.drop_table('alerts')
    op.drop_table('threat_detections')
    op.drop_table('log_entries')
    op.drop_table('users')
