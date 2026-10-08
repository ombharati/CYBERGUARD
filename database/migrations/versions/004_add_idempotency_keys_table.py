"""Add idempotency_keys table.

Revision ID: 004_add_idempotency_keys_table
Revises: 003_add_idempotency_key
Create Date: 2026-10-08 11:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '004_add_idempotency_keys_table'
down_revision: Union[str, None] = '003_add_idempotency_key'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'idempotency_keys',
        sa.Column('key', sa.String(length=64), primary_key=True, nullable=False),
        sa.Column('scan_id', sa.String(length=36), sa.ForeignKey('scans.id', ondelete='CASCADE'), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.UniqueConstraint('key', name='uq_idempotency_keys_key')
    )
    op.create_index('ix_idempotency_keys_scan_id', 'idempotency_keys', ['scan_id'])


def downgrade() -> None:
    op.drop_index('ix_idempotency_keys_scan_id', table_name='idempotency_keys')
    op.drop_table('idempotency_keys')
