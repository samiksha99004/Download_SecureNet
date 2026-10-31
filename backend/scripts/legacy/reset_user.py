"""Reset test user"""
import sqlite3

# Delete using sqlite3
conn = sqlite3.connect('securenet.db')
conn.execute('DELETE FROM users WHERE email = ?', ('admin@test.com',))
conn.commit()
conn.close()
print("User deleted from database")

# Re-create with correct values
import bcrypt

def hash_password(password: str) -> str:
    pwd_bytes = password.encode('utf-8')
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(pwd_bytes, salt)
    return hashed.decode('utf-8')

import uuid
from datetime import datetime

conn = sqlite3.connect('securenet.db')
cursor = conn.cursor()

user_id = str(uuid.uuid4())
hashed = hash_password("admin123")

cursor.execute("""
    INSERT INTO users (id, email, full_name, password_hash, role, account_status, auth_provider, created_at, updated_at, failed_login_attempts)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
""", (
    user_id,
    "admin@test.com",
    "Admin User",
    hashed,
    "ADMIN",
    "ACTIVE",
    "LOCAL",
    datetime.utcnow().isoformat(),
    datetime.utcnow().isoformat(),
    "0"
))

conn.commit()
conn.close()

print("Test user created successfully")
print("Email: admin@test.com")
print("Password: admin123")
print("Role: ADMIN")

