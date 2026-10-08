"""Add idempotency_key column and unique index to scans table.

Revision ID: 003_add_idempotency_key
Revises: 002_add_report_columns
Create Date: 2026-10-08 10:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = '003_add_idempotency_key'
down_revision: Union[str, None] = '002_add_report_columns'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('scans', sa.Column('idempotency_key', sa.String(length=64), nullable=True))
    op.create_index('ix_scans_idempotency_key', 'scans', ['idempotency_key'], unique=True)


def downgrade() -> None:
    op.drop_index('ix_scans_idempotency_key', table_name='scans')
    op.drop_column('scans', 'idempotency_key')
