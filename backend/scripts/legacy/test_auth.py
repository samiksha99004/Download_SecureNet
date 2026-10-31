"""Test authentication and get JWT token"""
import requests
import json

BASE_URL = "http://127.0.0.1:8000"

print("Testing authentication...")

# Login
login_data = {
    "email": "admin@test.com",
    "password": "admin123"
}

print(f"\n1. POST {BASE_URL}/api/auth/login")
print(f"   Body: {json.dumps(login_data)}")

response = requests.post(f"{BASE_URL}/api/auth/login", json=login_data)

if response.status_code == 200:
    data = response.json()
    print(f"   ✓ Status: {response.status_code}")
    print(f"   ✓ User: {data['user']['email']}")
    print(f"   ✓ Role: {data['user']['role']}")
    
    access_token = data['tokens']['accessToken']
    print(f"\n2. Access Token: {access_token[:50]}...")
    
    # Test IDS status with token
    headers = {"Authorization": f"Bearer {access_token}"}
    
    print(f"\n3. GET {BASE_URL}/api/ids/status")
    response = requests.get(f"{BASE_URL}/api/ids/status", headers=headers)
    print(f"   ✓ Status: {response.status_code}")
    print(f"   ✓ Response: {json.dumps(response.json(), indent=2)}")
    
    # Save token for other tests
    with open('test_token.txt', 'w') as f:
        f.write(access_token)
    print("\n✓ Token saved to test_token.txt")
    
else:
    print(f"   ✗ Status: {response.status_code}")
    print(f"   ✗ Error: {response.text}")
