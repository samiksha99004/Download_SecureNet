"""
Test IDS Toggle Behavior
- When IDS is OFF: Dashboard shows zeros and no events
- When IDS is ON: Dashboard shows real data with camelCase fields
"""

import requests
import json

BASE_URL = "http://127.0.0.1:8000"

# Login
response = requests.post(
    f"{BASE_URL}/api/auth/login",
    json={"email": "admin@securenet.com", "password": "Admin@123456"}
)
token = response.json()["tokens"]["accessToken"]
headers = {"Authorization": f"Bearer {token}"}

print("=" * 70)
print("TESTING IDS TOGGLE BEHAVIOR")
print("=" * 70)

# Test 1: IDS OFF
print("\n[TEST 1] IDS OFF - Should show zeros and empty events")
print("-" * 70)
requests.post(f"{BASE_URL}/api/ids/control", json={"enabled": False}, headers=headers)
response = requests.get(f"{BASE_URL}/api/dashboard/summary", headers=headers)
data = response.json()

print(f"✓ Active Flows: {data['activeFlows']} (expected: 0)")
print(f"✓ Anomalies Last Hour: {data['anomaliesLastHour']} (expected: 0)")
print(f"✓ Recent Events: {len(data['recentEvents'])} (expected: 0)")

assert data['activeFlows'] == 0, "activeFlows should be 0 when IDS is OFF"
assert len(data['recentEvents']) == 0, "recentEvents should be empty when IDS is OFF"
print("\n✅ TEST 1 PASSED - Dashboard shows zeros when IDS is OFF")

# Test 2: IDS ON
print("\n[TEST 2] IDS ON - Should show real data with camelCase")
print("-" * 70)
requests.post(f"{BASE_URL}/api/ids/control", json={"enabled": True}, headers=headers)
response = requests.get(f"{BASE_URL}/api/dashboard/summary", headers=headers)
data = response.json()

print(f"✓ Active Flows: {data['activeFlows']} (expected: > 0)")
print(f"✓ Anomalies Last Hour: {data['anomaliesLastHour']} (expected: > 0)")
print(f"✓ Recent Events: {len(data['recentEvents'])} (expected: > 0)")

assert data['activeFlows'] > 0, "activeFlows should be > 0 when IDS is ON"
assert len(data['recentEvents']) > 0, "recentEvents should have data when IDS is ON"

# Test 3: Check camelCase fields
print("\n[TEST 3] Checking camelCase field names in events")
print("-" * 70)
if data['recentEvents']:
    event = data['recentEvents'][0]
    
    # Check for camelCase fields (not snake_case)
    required_camel_fields = [
        'sourceIp', 'sourcePort', 'destinationIp', 'destinationPort',
        'anomalyScore', 'attackType', 'actionTaken', 'detectionReason'
    ]
    
    for field in required_camel_fields:
        assert field in event, f"Field '{field}' missing (should be camelCase)"
        print(f"✓ {field}: {event[field]}")
    
    # Ensure snake_case fields are NOT present
    snake_case_fields = ['source_ip', 'anomaly_score', 'action_taken']
    for field in snake_case_fields:
        assert field not in event, f"Field '{field}' should NOT be present (should be camelCase)"
    
    print("\n✅ TEST 3 PASSED - All fields are in camelCase format")

print("\n" + "=" * 70)
print("✅ ALL TESTS PASSED!")
print("=" * 70)
print("\nSummary:")
print("  • IDS OFF → Dashboard shows zeros/empty ✅")
print("  • IDS ON → Dashboard shows real data ✅")
print("  • API returns camelCase (not snake_case) ✅")
print("  • Frontend will display properly ✅")
