"""contact details (Support page) on system settings

Revision ID: c4e8f2a6b1d7
Revises: b7d2e4f1a9c3
Create Date: 2026-09-25 19:00:00

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'c4e8f2a6b1d7'
down_revision: Union[str, None] = 'b7d2e4f1a9c3'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('system_settings', sa.Column('contact_website', sa.String(length=255), nullable=True))
    op.add_column('system_settings', sa.Column('contact_phone', sa.String(length=40), nullable=True))
    op.add_column('system_settings', sa.Column('contact_email', sa.String(length=255), nullable=True))
    op.add_column('system_settings', sa.Column('contact_address', sa.String(length=500), nullable=True))


def downgrade() -> None:
    for column in ('contact_address', 'contact_email', 'contact_phone', 'contact_website'):
        op.drop_column('system_settings', column)
