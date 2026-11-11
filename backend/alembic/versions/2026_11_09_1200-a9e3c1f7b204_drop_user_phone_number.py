"""drop phone number from users

Phone number was removed from registration, profile and the API. This drops the
now-unused users.phone_number column.

Revision ID: a9e3c1f7b204
Revises: f7c2a8e5b3d1
Create Date: 2026-11-09 12:00:00

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'a9e3c1f7b204'
down_revision: Union[str, None] = 'f7c2a8e5b3d1'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table('users') as batch_op:
        batch_op.drop_column('phone_number')


def downgrade() -> None:
    with op.batch_alter_table('users') as batch_op:
        batch_op.add_column(sa.Column('phone_number', sa.String(length=20), nullable=True))
