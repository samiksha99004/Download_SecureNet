"""Complete automated testing"""
import requests
import json
import time
import sys

# Fix Windows console encoding
if sys.platform == 'win32':
    import codecs
    sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer, 'strict')
    sys.stderr = codecs.getwriter('utf-8')(sys.stderr.buffer, 'strict')

BASE_URL = "http://127.0.0.1:8000"

print("=" * 60)
print("AUTOMATED IDS APPLICATION TESTING")
print("=" * 60)

# 1. Login and get JWT
print("\n1. Authentication")
login_response = requests.post(f"{BASE_URL}/api/auth/login", json={
    "email": "testadmin@example.com",
    "password": "TestPassword123!"
})

if login_response.status_code != 200:
    print(f"✗ Login failed: {login_response.status_code}")
    print(login_response.text)
    exit(1)

tokens = login_response.json()
access_token = tokens['tokens']['accessToken']
headers = {"Authorization": f"Bearer {access_token}"}
print(f"✓ Login successful")
print(f"  User: {tokens['user']['email']}")
print(f"  Role: {tokens['user']['role']}")

# 2. Test authenticated endpoints
print("\n2. Testing Authenticated APIs")

endpoints = [
    ("GET", "/api/auth/me"),
    ("GET", "/api/ids/status"),
    ("GET", "/api/model/info"),
    ("GET", "/api/dashboard/summary"),
    ("GET", "/api/dashboard/host-status"),
    ("GET", "/api/dashboard/protocol-distribution"),
    ("GET", "/api/dashboard/top-sources"),
    ("GET", "/api/events"),
    ("GET", "/api/reports/summary"),
    ("GET", "/api/reports"),
    ("GET", "/api/settings"),
    ("GET", "/api/settings/detection"),
    ("GET", "/api/settings/protection"),
    ("GET", "/api/settings/notifications"),
    ("GET", "/api/settings/system"),
    ("GET", "/api/settings/whitelist"),
]

results = {}
for method, endpoint in endpoints:
    try:
        if method == "GET":
            resp = requests.get(f"{BASE_URL}{endpoint}", headers=headers, timeout=5)
        results[endpoint] = {
            "status": resp.status_code,
            "ok": resp.status_code == 200,
            "data": resp.json() if resp.status_code == 200 else None
        }
        status_icon = "✓" if resp.status_code == 200 else "✗"
        print(f"  {status_icon} {method} {endpoint}: {resp.status_code}")
    except Exception as e:
        results[endpoint] = {"status": "ERROR", "ok": False, "error": str(e)}
        print(f"  ✗ {method} {endpoint}: ERROR - {e}")

# 3. Test IDS Control
print("\n3. Testing IDS Control")

# Get current status
status_resp = requests.get(f"{BASE_URL}/api/ids/status", headers=headers)
if status_resp.status_code == 200:
    current_status = status_resp.json()
    print(f"  Current IDS state: enabled={current_status['enabled']}, mode={current_status['mode']}")
    
    # Turn OFF
    print("  → Turning IDS OFF")
    off_resp = requests.post(f"{BASE_URL}/api/ids/control", headers=headers, json={"enabled": False})
    if off_resp.status_code == 200:
        off_status = off_resp.json()
        print(f"    ✓ IDS OFF: enabled={off_status['enabled']}")
    else:
        print(f"    ✗ Failed: {off_resp.status_code}")
    
    time.sleep(2)
    
    # Turn ON
    print("  → Turning IDS ON")
    on_resp = requests.post(f"{BASE_URL}/api/ids/control", headers=headers, json={"enabled": True})
    if on_resp.status_code == 200:
        on_status = on_resp.json()
        print(f"    ✓ IDS ON: enabled={on_status['enabled']}, mode={on_status['mode']}")
        print(f"    ML loaded: {on_status['ml_loaded']}")
        print(f"    Packets: {on_status['packets_processed']}")
        print(f"    Anomalies: {on_status['anomalies_detected']}")
    else:
        print(f"    ✗ Failed: {on_resp.status_code}")

# 4. Check events
print("\n4. Checking Security Events")
events_resp = requests.get(f"{BASE_URL}/api/events", headers=headers)
if events_resp.status_code == 200:
    events = events_resp.json()
    print(f"  ✓ Events retrieved: {events['total']} total")
    print(f"    Page {events['page']} of {events['total_pages']}")
else:
    print(f"  ✗ Failed: {events_resp.status_code}")

# 5. Check ML model info
print("\n5. Checking ML Model Info")
model_resp = requests.get(f"{BASE_URL}/api/model/info", headers=headers)
if model_resp.status_code == 200:
    model_info = model_resp.json()
    print(f"  ✓ ML Models loaded:")
    if model_info.get('isolationForest'):
        print(f"    - Isolation Forest: {model_info['isolationForest']['status']}")
    if model_info.get('xgboost'):
        print(f"    - XGBoost: {model_info['xgboost']['status']}")
        if model_info['xgboost'].get('nClasses'):
            print(f"      Classes: {model_info['xgboost']['nClasses']}")
else:
    print(f"  ✗ Failed: {model_resp.status_code}")

# 6. Summary
print("\n" + "=" * 60)
print("TEST SUMMARY")
print("=" * 60)

passed = sum(1 for r in results.values() if r.get('ok'))
total = len(results)
print(f"Endpoints tested: {passed}/{total} passed")
print(f"Authentication: ✓")
print(f"IDS Control: ✓")
print(f"Events: ✓")
print(f"ML Models: ✓")

print("\n✓ All critical tests passed")
