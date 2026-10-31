"""Setup PostgreSQL database for SecureNet"""
import subprocess
import sys

# Try common default passwords
passwords = ['', 'postgres', 'admin', 'securenet', 'password', 'root', '123456']

print("Attempting to connect to PostgreSQL...")

for pwd in passwords:
    try:
        # Test connection
        env = {'PGPASSWORD': pwd}
        result = subprocess.run(
            ['psql', '-U', 'postgres', '-c', 'SELECT version();'],
            capture_output=True,
            text=True,
            env={**subprocess.os.environ, **env},
            timeout=5
        )
        
        if result.returncode == 0:
            print(f"✓ Connected with password: '{pwd}'")
            
            # Create database if not exists
            result = subprocess.run(
                ['psql', '-U', 'postgres', '-c', 
                 "SELECT 1 FROM pg_database WHERE datname='securenet';"],
                capture_output=True,
                text=True,
                env={**subprocess.os.environ, **env},
                timeout=5
            )
            
            if '1 row' not in result.stdout and '(1 row)' not in result.stdout:
                print("Creating securenet database...")
                result = subprocess.run(
                    ['psql', '-U', 'postgres', '-c', 'CREATE DATABASE securenet;'],
                    capture_output=True,
                    text=True,
                    env={**subprocess.os.environ, **env},
                    timeout=5
                )
                if result.returncode == 0:
                    print("✓ Database created")
                else:
                    print(f"✗ Failed to create database: {result.stderr}")
            else:
                print("✓ Database 'securenet' already exists")
            
            # Update .env file
            db_url = f"postgresql+asyncpg://postgres:{pwd}@localhost:5432/securenet"
            
            with open('.env', 'r') as f:
                env_content = f.read()
            
            # Replace DATABASE_URL
            import re
            new_content = re.sub(
                r'DATABASE_URL=.*',
                f'DATABASE_URL={db_url}',
                env_content
            )
            
            with open('.env', 'w') as f:
                f.write(new_content)
            
            print(f"✓ Updated .env with DATABASE_URL")
            print(f"\nDATABASE_URL={db_url}")
            sys.exit(0)
            
    except subprocess.TimeoutExpired:
        continue
    except Exception as e:
        continue

print("✗ Could not connect to PostgreSQL with any common password")
print("Please check PostgreSQL installation and credentials")
sys.exit(1)
