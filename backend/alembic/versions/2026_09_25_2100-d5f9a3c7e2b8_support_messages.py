"""support messages table (record + persistent sending limit)

Revision ID: d5f9a3c7e2b8
Revises: c4e8f2a6b1d7
Create Date: 2026-09-25 21:00:00

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'd5f9a3c7e2b8'
down_revision: Union[str, None] = 'c4e8f2a6b1d7'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'support_messages',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('user_id', sa.Uuid(), nullable=True),
        sa.Column('sender_email', sa.String(length=255), nullable=False),
        sa.Column('recipient', sa.String(length=255), nullable=False),
        sa.Column('subject', sa.String(length=150), nullable=False),
        sa.Column('message', sa.Text(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_support_messages_user_id', 'support_messages', ['user_id'])
    op.create_index('ix_support_messages_created_at', 'support_messages', ['created_at'])


def downgrade() -> None:
    op.drop_index('ix_support_messages_created_at', table_name='support_messages')
    op.drop_index('ix_support_messages_user_id', table_name='support_messages')
    op.drop_table('support_messages')
