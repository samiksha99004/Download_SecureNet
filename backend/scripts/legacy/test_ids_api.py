"""Test IDS API endpoints"""
import requests
import json
import time

BASE_URL = "http://127.0.0.1:8000"

# Load token
try:
    with open('test_token.txt', 'r') as f:
        token = f.read().strip()
except:
    print("✗ No token found. Run test_auth.py first")
    exit(1)

headers = {"Authorization": f"Bearer {token}"}

print("Testing IDS API Endpoints\n")

# 1. Get IDS Status
print("1. GET /api/ids/status")
response = requests.get(f"{BASE_URL}/api/ids/status", headers=headers)
print(f"   Status: {response.status_code}")
if response.status_code == 200:
    status = response.json()
    print(f"   ✓ IDS Enabled: {status['enabled']}")
    print(f"   ✓ Mode: {status['mode']}")
    print(f"   ✓ ML Loaded: {status['ml_loaded']}")
    print(f"   ✓ Packets: {status['packets_processed']}")
    print(f"   ✓ Anomalies: {status['anomalies_detected']}")
else:
    print(f"   ✗ Error: {response.text}")

# 2. Start IDS
print("\n2. POST /api/ids/control (Start IDS)")
control_data = {"enabled": True}
response = requests.post(f"{BASE_URL}/api/ids/control", json=control_data, headers=headers)
print(f"   Status: {response.status_code}")
if response.status_code == 200:
    status = response.json()
    print(f"   ✓ IDS Started")
    print(f"   ✓ Enabled: {status['enabled']}")
    print(f"   ✓ Mode: {status['mode']}")
else:
    print(f"   ✗ Error: {response.text}")

# 3. Get Status Again
print("\n3. GET /api/ids/status (after start)")
time.sleep(1)
response = requests.get(f"{BASE_URL}/api/ids/status", headers=headers)
if response.status_code == 200:
    status = response.json()
    print(f"   ✓ IDS Enabled: {status['enabled']}")
    print(f"   ✓ Mode: {status['mode']}")

# 4. Get Events
print("\n4. GET /api/events")
response = requests.get(f"{BASE_URL}/api/events", headers=headers)
print(f"   Status: {response.status_code}")
if response.status_code == 200:
    data = response.json()
    print(f"   ✓ Total Events: {data['total']}")
    print(f"   ✓ Page: {data['page']} of {data['total_pages']}")
else:
    print(f"   ✗ Error: {response.text}")

# 5. Stop IDS
print("\n5. POST /api/ids/control (Stop IDS)")
control_data = {"enabled": False}
response = requests.post(f"{BASE_URL}/api/ids/control", json=control_data, headers=headers)
print(f"   Status: {response.status_code}")
if response.status_code == 200:
    status = response.json()
    print(f"   ✓ IDS Stopped")
    print(f"   ✓ Enabled: {status['enabled']}")

print("\n✓ All IDS API tests complete")
