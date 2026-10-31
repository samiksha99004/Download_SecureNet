"""each user can turn attack alert emails on/off

Revision ID: e6b1c9d4a2f7
Revises: d5f9a3c7e2b8
Create Date: 2026-09-26 12:00:00

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'e6b1c9d4a2f7'
down_revision: Union[str, None] = 'd5f9a3c7e2b8'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # everyone keeps getting alert emails until they switch them off
    op.add_column('users', sa.Column('email_alerts', sa.Boolean(), nullable=False, server_default=sa.true()))


def downgrade() -> None:
    op.drop_column('users', 'email_alerts')
