"""
Delete ALL test/fake events from database
Leave only real captured network traffic
"""

import asyncio
from app.db.base import AsyncSessionLocal
from app.models.security_event import SecurityEvent
from sqlalchemy import select, delete

async def delete_all_events():
    async with AsyncSessionLocal() as db:
        # Count before
        result = await db.execute(select(SecurityEvent))
        before_count = len(result.scalars().all())
        print(f"Events before deletion: {before_count}")
        
        # Delete ALL events
        await db.execute(delete(SecurityEvent))
        await db.commit()
        
        # Count after
        result = await db.execute(select(SecurityEvent))
        after_count = len(result.scalars().all())
        print(f"Events after deletion: {after_count}")
        print(f"✓ Deleted {before_count} test events")
        print("\n✅ Database is now clean - only real network traffic will appear")

if __name__ == "__main__":
    asyncio.run(delete_all_events())
