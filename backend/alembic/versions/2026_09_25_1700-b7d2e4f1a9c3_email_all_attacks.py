"""email alerts for every attack (alert_on_low, all severities on); IDS default mode monitor

Revision ID: b7d2e4f1a9c3
Revises: a1c4e7b9d2f0
Create Date: 2026-09-25 17:00:00

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'b7d2e4f1a9c3'
down_revision: Union[str, None] = 'a1c4e7b9d2f0'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('notification_settings',
                  sa.Column('alert_on_low', sa.Boolean(), nullable=False, server_default=sa.true()))
    # The owner wants an email for every detected attack
    op.execute("UPDATE notification_settings SET email_enabled = true, alert_on_high = true, "
               "alert_on_medium = true, alert_on_low = true")
    # The IDS is simply ON/OFF now (detect + alert); no automatic blocking mode
    op.execute("UPDATE protection_settings SET mode = 'MONITOR'")


def downgrade() -> None:
    op.drop_column('notification_settings', 'alert_on_low')
