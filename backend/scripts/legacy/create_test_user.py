"""Create test user for authentication testing"""
import asyncio
import sys
import bcrypt
from sqlalchemy import text
from app.db.base import AsyncSessionLocal, engine
from app.models.user import User, UserRole
from datetime import datetime

def hash_password(password: str) -> str:
    """Hash password using bcrypt"""
    pwd_bytes = password.encode('utf-8')
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(pwd_bytes, salt)
    return hashed.decode('utf-8')

async def create_tables():
    """Create all tables"""
    try:
        from app.models import user, security_event, settings
        from app.db.base import Base
        
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        
        print("✓ Tables created")
        return True
    except Exception as e:
        print(f"✗ Table creation failed: {e}")
        return False

async def create_test_user():
    """Create a test user"""
    try:
        async with AsyncSessionLocal() as db:
            # Check if user exists
            result = await db.execute(
                text("SELECT * FROM users WHERE email = 'admin@test.com'")
            )
            if result.fetchone():
                print("✓ Test user already exists: admin@test.com")
                return True
            
            # Create user
            hashed = hash_password("admin123")
            
            query = text("""
                INSERT INTO users (id, email, full_name, password_hash, role, account_status, auth_provider, created_at, updated_at, failed_login_attempts)
                VALUES (:id, :email, :full_name, :password_hash, :role, :account_status, :auth_provider, :created_at, :updated_at, :failed_login_attempts)
            """)
            
            import uuid
            from datetime import datetime
            
            await db.execute(query, {
                "id": str(uuid.uuid4()),
                "email": "admin@test.com",
                "full_name": "Admin User",
                "password_hash": hashed,
                "role": "ADMIN",
                "account_status": "ACTIVE",
                "auth_provider": "LOCAL",
                "created_at": datetime.utcnow(),
                "updated_at": datetime.utcnow(),
                "failed_login_attempts": "0"
            })
            await db.commit()
            
            print("✓ Test user created:")
            print("  Email: admin@test.com")
            print("  Password: admin123")
            print("  Role: ADMIN")
            return True
            
    except Exception as e:
        print(f"✗ User creation failed: {e}")
        return False

async def main():
    print("Creating database tables and test user...")
    
    # Create tables
    tables_ok = await create_tables()
    if not tables_ok:
        sys.exit(1)
    
    # Create test user
    user_ok = await create_test_user()
    if not user_ok:
        sys.exit(1)
    
    print("\n✓ Setup complete!")
    print("  You can now login with admin@test.com / admin123")

if __name__ == "__main__":
    asyncio.run(main())
