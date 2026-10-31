"""Seed database with initial admin user and test data"""
import asyncio
import sys
from datetime import datetime, timedelta
import random
from sqlalchemy import select
from app.db.base import get_db
from app.models.user import User, UserRole, AccountStatus
from app.models.settings import (
    DetectionSettings, ProtectionSettings, NotificationSettings, 
    SystemSettings, DetectionSensitivity, ProtectionMode
)
from app.models.security_event import (
    SecurityEvent, SeverityLevel, EventState, DetectionMode,
    ActionTaken, Protocol
)
from app.core.security import hash_password


async def seed_database():
    """Seed database with initial data"""
    print("=" * 70)
    print("SEEDING NEON POSTGRESQL DATABASE")
    print("=" * 70)
    
    async for db in get_db():
        # 1. Create Admin User
        print("\n[1] Creating Admin User")
        result = await db.execute(select(User).where(User.email == "admin@securenet.com"))
        existing_admin = result.scalar_one_or_none()
        
        if existing_admin:
            print("  → Admin user already exists")
        else:
            admin_user = User(
                email="admin@securenet.com",
                full_name="SecureNet Administrator",
                password_hash=hash_password("Admin@123456"),
                role=UserRole.ADMIN,
                account_status=AccountStatus.ACTIVE
            )
            db.add(admin_user)
            await db.commit()
            print("  ✓ Admin user created: admin@securenet.com / Admin@123456")
        
        # 2. Create Analyst User
        print("\n[2] Creating Analyst User")
        result = await db.execute(select(User).where(User.email == "analyst@securenet.com"))
        existing_analyst = result.scalar_one_or_none()
        
        if existing_analyst:
            print("  → Analyst user already exists")
        else:
            analyst_user = User(
                email="analyst@securenet.com",
                full_name="Security Analyst",
                password_hash=hash_password("Analyst@123456"),
                role=UserRole.ANALYST,
                account_status=AccountStatus.ACTIVE
            )
            db.add(analyst_user)
            await db.commit()
            print("  ✓ Analyst user created: analyst@securenet.com / Analyst@123456")
        
        # 3. Create Viewer User  
        print("\n[3] Creating Viewer User")
        result = await db.execute(select(User).where(User.email == "viewer@securenet.com"))
        existing_viewer = result.scalar_one_or_none()
        
        if existing_viewer:
            print("  → Viewer user already exists")
        else:
            viewer_user = User(
                email="viewer@securenet.com",
                full_name="Security Viewer",
                password_hash=hash_password("Viewer@123456"),
                role=UserRole.VIEWER,
                account_status=AccountStatus.ACTIVE
            )
            db.add(viewer_user)
            await db.commit()
            print("  ✓ Viewer user created: viewer@securenet.com / Viewer@123456")
        
        # 4. Create Default Settings
        print("\n[4] Creating Default Settings")
        
        # Detection Settings
        result = await db.execute(select(DetectionSettings))
        if not result.scalar_one_or_none():
            detection = DetectionSettings(
                enabled=True,
                sensitivity=DetectionSensitivity.MEDIUM,
                anomaly_threshold=0.5,
                min_flows_for_analysis=10,
                analysis_interval_ms=5000,
                stage2_enabled=True,
                stage2_confidence_threshold=0.3
            )
            db.add(detection)
            print("  ✓ Detection settings created")
        
        # Protection Settings
        result = await db.execute(select(ProtectionSettings))
        if not result.scalar_one_or_none():
            protection = ProtectionSettings(
                mode=ProtectionMode.PROTECT,
                auto_block=True,
                block_duration_seconds=3600,
                max_blocked_ips=1000,
                notify_on_block=True
            )
            db.add(protection)
            print("  ✓ Protection settings created")
        
        # Notification Settings
        result = await db.execute(select(NotificationSettings))
        if not result.scalar_one_or_none():
            notifications = NotificationSettings(
                email_enabled=False,
                alert_on_high=True,
                alert_on_medium=False,
                alert_on_block=True,
                digest_enabled=False,
                digest_interval_hours=24
            )
            db.add(notifications)
            print("  ✓ Notification settings created")
        
        # System Settings
        result = await db.execute(select(SystemSettings))
        if not result.scalar_one_or_none():
            system = SystemSettings(
                log_retention_days=90,
                max_stored_events=100000,
                timezone="UTC",
                date_format="YYYY-MM-DD HH:mm:ss",
                debug_mode=False
            )
            db.add(system)
            print("  ✓ System settings created")
        
        await db.commit()
        
        # No sample events created - only real network monitoring data will appear
        
        print("\n" + "=" * 70)
        print("DATABASE SEEDING COMPLETE")
        print("=" * 70)
        print("\nTest Accounts Created:")
        print("  Admin:   admin@securenet.com    / Admin@123456")
        print("  Analyst: analyst@securenet.com  / Analyst@123456")
        print("  Viewer:  viewer@securenet.com   / Viewer@123456")
        print("\nDefault settings configured.")
        print("NO sample events - only real network monitoring data will appear")
        print("=" * 70)
        
        break


if __name__ == "__main__":
    try:
        asyncio.run(seed_database())
    except Exception as e:
        print(f"\nError seeding database: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
