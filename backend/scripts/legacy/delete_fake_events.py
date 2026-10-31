"""
Delete all fake/sample security events from database.
Only real network monitoring data should exist.
"""
import asyncio
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from sqlalchemy import select, delete
from app.models.security_event import SecurityEvent
from app.core.config import settings

async def delete_all_events():
    """Delete all security events from database"""
    engine = create_async_engine(settings.DATABASE_URL, echo=True)
    async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    
    async with async_session() as db:
        # Count existing events
        result = await db.execute(select(SecurityEvent))
        existing = result.scalars().all()
        count = len(existing)
        
        if count == 0:
            print("✓ No events to delete - database is clean")
            return
        
        print(f"\nFound {count} events in database")
        print("Deleting all events...")
        
        # Delete all events
        await db.execute(delete(SecurityEvent))
        await db.commit()
        
        print(f"✓ Deleted {count} fake/sample events")
        print("✓ Database is now clean - only real monitoring data will appear")

if __name__ == "__main__":
    asyncio.run(delete_all_events())
