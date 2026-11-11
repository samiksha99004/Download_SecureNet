"""per-user ownership of security events

Adds security_events.owner_id (the account that owns each event) and backfills every
existing event to 4mt23ic012@mite.ac.in, so that account keeps the current dashboard and
new accounts start empty.

Revision ID: b1f4d8c2e9a7
Revises: a9e3c1f7b204
Create Date: 2026-11-09 15:00:00

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'b1f4d8c2e9a7'
down_revision: Union[str, None] = 'a9e3c1f7b204'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_KEEP_OWNER_EMAIL = "4mt23ic012@mite.ac.in"


def upgrade() -> None:
    op.add_column('security_events', sa.Column('owner_id', sa.Uuid(), nullable=True))
    op.create_index('ix_security_events_owner_id', 'security_events', ['owner_id'])
    op.create_foreign_key('fk_security_events_owner_id_users', 'security_events', 'users',
                          ['owner_id'], ['id'])
    # Backfill: all existing events belong to the main account.
    op.execute(sa.text(
        "UPDATE security_events SET owner_id = (SELECT id FROM users WHERE lower(email) = :email) "
        "WHERE owner_id IS NULL"
    ).bindparams(email=_KEEP_OWNER_EMAIL))


def downgrade() -> None:
    op.drop_constraint('fk_security_events_owner_id_users', 'security_events', type_='foreignkey')
    op.drop_index('ix_security_events_owner_id', table_name='security_events')
    op.drop_column('security_events', 'owner_id')
