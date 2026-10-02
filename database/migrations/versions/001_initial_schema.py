"""Initial schema for scans and scan_findings

Revision ID: 001_initial_schema
Revises: 
Create Date: 2026-10-02 18:30:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = '001_initial_schema'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'scans',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('input_type', sa.String(length=20), nullable=False),
        sa.Column('target', sa.Text(), nullable=False),
        sa.Column('raw_input', sa.JSON(), nullable=False),
        sa.Column('status', sa.String(length=20), nullable=False),
        sa.Column('risk_score', sa.Integer(), nullable=True),
        sa.Column('classification', sa.String(length=20), nullable=True),
        sa.Column('summary', sa.Text(), nullable=True),
        sa.Column('explanation', sa.Text(), nullable=True),
        sa.Column('signals', sa.JSON(), nullable=True),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('retries', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_scans_input_type', 'scans', ['input_type'], unique=False)
    op.create_index('ix_scans_status', 'scans', ['status'], unique=False)
    op.create_index('ix_scans_created_at', 'scans', ['created_at'], unique=False)
    op.create_index('ix_scans_status_created', 'scans', ['status', 'created_at'], unique=False)

    op.create_table(
        'scan_findings',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('scan_id', sa.String(length=36), nullable=False),
        sa.Column('severity', sa.String(length=10), nullable=False),
        sa.Column('title', sa.String(length=255), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('category', sa.String(length=50), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['scan_id'], ['scans.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_scan_findings_scan_id', 'scan_findings', ['scan_id'], unique=False)


def downgrade() -> None:
    op.drop_index('ix_scan_findings_scan_id', table_name='scan_findings')
    op.drop_table('scan_findings')
    op.drop_index('ix_scans_status_created', table_name='scans')
    op.drop_index('ix_scans_created_at', table_name='scans')
    op.drop_index('ix_scans_status', table_name='scans')
    op.drop_index('ix_scans_input_type', table_name='scans')
    op.drop_table('scans')
