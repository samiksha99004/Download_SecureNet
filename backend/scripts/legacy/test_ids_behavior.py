"""Test actual IDS ON/OFF behavior"""
import requests
import time

BASE_URL = "http://127.0.0.1:8000"

# Login
login_resp = requests.post(f"{BASE_URL}/api/auth/login", json={
    "email": "testadmin@example.com",
    "password": "TestPassword123!"
})
token = login_resp.json()['tokens']['accessToken']
headers = {"Authorization": f"Bearer {token}"}

print("=" * 60)
print("IDS ON/OFF BEHAVIOR TEST")
print("=" * 60)

# Get initial state
print("\n1. Initial State")
status = requests.get(f"{BASE_URL}/api/ids/status", headers=headers).json()
print(f"   Enabled: {status['enabled']}")
print(f"   Mode: {status['mode']}")
print(f"   ML Loaded: {status['ml_loaded']}")
print(f"   Packets: {status['packets_processed']}")
print(f"   Flows: {status.get('flows_analyzed', 0)}")
print(f"   Anomalies: {status['anomalies_detected']}")

# Turn OFF
print("\n2. Turning IDS OFF")
off_resp = requests.post(f"{BASE_URL}/api/ids/control", headers=headers, json={"enabled": False})
off_status = off_resp.json()
print(f"   Response: enabled={off_status['enabled']}")

time.sleep(2)

# Check OFF state
print("\n3. Verifying OFF State")
status = requests.get(f"{BASE_URL}/api/ids/status", headers=headers).json()
print(f"   Enabled: {status['enabled']}")
print(f"   Packets (should not increase): {status['packets_processed']}")

if status['enabled']:
    print("   ✗ IDS still enabled after OFF command")
else:
    print("   ✓ IDS is OFF")

# Turn ON
print("\n4. Turning IDS ON")
on_resp = requests.post(f"{BASE_URL}/api/ids/control", headers=headers, json={"enabled": True})
on_status = on_resp.json()
print(f"   Response: enabled={on_status['enabled']}, mode={on_status['mode']}")

time.sleep(2)

# Check ON state
print("\n5. Verifying ON State")
status = requests.get(f"{BASE_URL}/api/ids/status", headers=headers).json()
print(f"   Enabled: {status['enabled']}")
print(f"   Mode: {status['mode']}")
print(f"   ML Loaded: {status['ml_loaded']}")

if not status['enabled']:
    print("   ✗ IDS still disabled after ON command")
elif status['mode'] != 'protect':
    print(f"   ✗ Mode is '{status['mode']}', expected 'protect'")
else:
    print("   ✓ IDS is ON with protect mode")

print("\n" + "=" * 60)
print("✓ IDS behavior test complete")
print("=" * 60)
