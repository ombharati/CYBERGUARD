"""Add report_text and report_generated_by columns to scans

Revision ID: 002_add_report_columns
Revises: 001_initial_schema
Create Date: 2026-10-03 09:30:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = '002_add_report_columns'
down_revision: Union[str, None] = '001_initial_schema'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('scans', sa.Column('report_text', sa.Text(), nullable=True))
    op.add_column('scans', sa.Column('report_generated_by', sa.String(length=20), nullable=True))


def downgrade() -> None:
    op.drop_column('scans', 'report_generated_by')
    op.drop_column('scans', 'report_text')
