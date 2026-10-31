"""keep the model's guesses (which attack it might be) with each event

Revision ID: f7c2a8e5b3d1
Revises: e6b1c9d4a2f7
Create Date: 2026-10-06 12:00:00

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'f7c2a8e5b3d1'
down_revision: Union[str, None] = 'e6b1c9d4a2f7'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # [{"label": "DDoS", "probability": 0.97}, ...] best guess first; null for older events
    op.add_column('security_events', sa.Column('attack_guesses', sa.JSON(), nullable=True))


def downgrade() -> None:
    op.drop_column('security_events', 'attack_guesses')
