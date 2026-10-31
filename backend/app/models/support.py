"""
SecureNet Backend — Support message model

Every "Send us a message" from the Support page is kept, so the admin has a
record and the per-user sending limit survives a restart.
"""

import uuid

from sqlalchemy import Column, DateTime, ForeignKey, String, Text
from sqlalchemy import Uuid as UUID

from app.db.base import Base
from app.utils.timeutil import utcnow


class SupportMessage(Base):
    __tablename__ = "support_messages"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    sender_email = Column(String(255), nullable=False)
    recipient = Column(String(255), nullable=False)
    subject = Column(String(150), nullable=False)
    message = Column(Text, nullable=False)
    created_at = Column(DateTime, nullable=False, default=utcnow, index=True)
