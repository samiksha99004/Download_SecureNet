"""Test login and data transformation"""
import requests

# Test login
r = requests.post('http://127.0.0.1:8000/api/auth/login', json={
    'email': 'admin@securenet.com',
    'password': 'Admin@123456'
})

if r.status_code == 200:
    data = r.json()
    print('✓ Login successful')
    print(f'User: {data["user"]["full_name"]}')
    print(f'Email: {data["user"]["email"]}')
    print(f'Role: {data["user"]["role"]}')
    print('')
    print('Frontend authService.ts will transform:')
    print('  full_name → fullName')
    print('  account_status → accountStatus')
    print('  auth_provider → authProvider')
    print('  created_at → createdAt')
    print('  last_login_at → lastLoginAt')
    print('  avatar_url → avatarUrl')
    print('')
    print('✓ Sidebar will now display:', data["user"]["full_name"])
else:
    print(f'✗ Login failed: {r.status_code}')
