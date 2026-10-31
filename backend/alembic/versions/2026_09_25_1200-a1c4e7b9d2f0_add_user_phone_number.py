"""add phone number to users

Revision ID: a1c4e7b9d2f0
Revises: 83d618ecb3ad
Create Date: 2026-09-25 12:00:00

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'a1c4e7b9d2f0'
down_revision: Union[str, None] = '83d618ecb3ad'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('users', sa.Column('phone_number', sa.String(length=20), nullable=True))


def downgrade() -> None:
    op.drop_column('users', 'phone_number')
