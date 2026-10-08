"""Add recommended_actions to scans and evidence fields to scan_findings.

Revision ID: 005_add_recommended_actions
Revises: 004_add_idempotency_keys_table
Create Date: 2026-10-08 12:56:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '005_add_recommended_actions'
down_revision: Union[str, None] = '004_add_idempotency_keys_table'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Add recommended_actions to scans
    op.add_column('scans', sa.Column('recommended_actions', sa.JSON(), nullable=True))
    
    # Add signal metadata and evidence to scan_findings
    op.add_column('scan_findings', sa.Column('signal_type', sa.String(length=50), nullable=True))
    op.add_column('scan_findings', sa.Column('weight', sa.Integer(), nullable=True, server_default='0'))
    op.add_column('scan_findings', sa.Column('evidence', sa.Text(), nullable=True))
    op.add_column('scan_findings', sa.Column('source', sa.String(length=50), nullable=True, server_default='deterministic'))
    op.add_column('scan_findings', sa.Column('recommended_actions', sa.JSON(), nullable=True))


def downgrade() -> None:
    op.drop_column('scan_findings', 'recommended_actions')
    op.drop_column('scan_findings', 'source')
    op.drop_column('scan_findings', 'evidence')
    op.drop_column('scan_findings', 'weight')
    op.drop_column('scan_findings', 'signal_type')
    op.drop_column('scans', 'recommended_actions')
