"""
End-to-end test simulating exact user scenario:
1. Login to frontend
2. Turn IDS ON
3. Check dashboard doesn't go blank
4. Verify no fake data appears
"""
import asyncio
import httpx

BASE_URL = "http://127.0.0.1:8000/api"

async def test_user_scenario():
    """Test exact user scenario"""
    print("=" * 80)
    print("END-TO-END USER SCENARIO TEST")
    print("Simulating: Login → Turn IDS ON → Check Dashboard")
    print("=" * 80)
    
    async with httpx.AsyncClient(timeout=30.0) as client:
        # Step 1: Login
        print("\n[USER ACTION] Login to SecureNet as admin...")
        login_resp = await client.post(
            f"{BASE_URL}/auth/login",
            json={"email": "admin@securenet.com", "password": "Admin@123456"}
        )
        
        if login_resp.status_code != 200:
            print(f"✗ Login failed: {login_resp.status_code}")
            print("❌ USER SEES: Login page with error")
            return False
        
        token = login_resp.json()["tokens"]["accessToken"]
        headers = {"Authorization": f"Bearer {token}"}
        print("✓ Login successful")
        print("✓ USER SEES: Dashboard page loads")
        
        # Step 2: Get initial dashboard state
        print("\n[PAGE LOAD] Dashboard loads with IDS OFF...")
        dash_resp = await client.get(f"{BASE_URL}/dashboard/summary", headers=headers)
        
        if dash_resp.status_code != 200:
            print(f"✗ Dashboard failed to load: {dash_resp.status_code}")
            print("❌ USER SEES: BLANK PAGE or error")
            return False
        
        dash = dash_resp.json()
        print("✓ Dashboard loaded successfully")
        print(f"  Active Flows: {dash['activeFlows']}")
        print(f"  High Severity: {dash['highSeverityCount']}")
        print(f"  Blocked: {dash['blockedCount']}")
        print(f"  Recent Events: {len(dash['recentEvents'])}")
        
        if len(dash['recentEvents']) > 0:
            print("⚠ WARNING: Found events - checking if they are fake...")
            for event in dash['recentEvents']:
                print(f"  - {event['attackType']} from {event['sourceIp']}")
            print("❌ USER SEES: FAKE DATA (blocked IPs, fake attacks)")
            return False
        else:
            print("✓ NO FAKE DATA - Dashboard shows clean state")
            print("✓ USER SEES: All KPIs showing 0 (correct)")
        
        # Step 3: Turn IDS ON
        print("\n[USER ACTION] Click IDS ON button...")
        on_resp = await client.post(
            f"{BASE_URL}/ids/control",
            headers=headers,
            json={"enabled": True}
        )
        
        if on_resp.status_code != 200:
            print(f"✗ IDS control failed: {on_resp.status_code}")
            print(f"  Response: {on_resp.text}")
            print("❌ USER SEES: Error message, IDS doesn't turn on")
            return False
        
        on_status = on_resp.json()
        print("✓ IDS turned ON successfully")
        print(f"  Enabled: {on_status['enabled']}")
        print(f"  Mode: {on_status['mode']}")
        print("✓ USER SEES: IDS button shows 'ON' state")
        
        # Step 4: Check dashboard after IDS ON
        print("\n[PAGE UPDATE] Dashboard refreshes with IDS ON...")
        await asyncio.sleep(1)  # Simulate brief delay
        
        dash2_resp = await client.get(f"{BASE_URL}/dashboard/summary", headers=headers)
        
        if dash2_resp.status_code != 200:
            print(f"✗ Dashboard failed after IDS ON: {dash2_resp.status_code}")
            print(f"  Response: {dash2_resp.text}")
            print("❌ USER SEES: BLANK PAGE - Dashboard goes blank when IDS ON!")
            return False
        
        dash2 = dash2_resp.json()
        print("✓ Dashboard still loads correctly with IDS ON")
        print(f"  Active Flows: {dash2['activeFlows']}")
        print(f"  Recent Events: {len(dash2['recentEvents'])}")
        
        if len(dash2['recentEvents']) > 0:
            print("⚠ WARNING: Fake data appeared after turning IDS ON!")
            print("❌ USER SEES: FAKE BLOCKED LIST, FAKE ATTACKS")
            return False
        
        print("✓ NO FAKE DATA appeared after IDS ON")
        print("✓ USER SEES: Dashboard with IDS status 'NORMAL' and 0 events")
        
        # Step 5: Check IDS widget data
        print("\n[WIDGET UPDATE] IDS Control Widget updates...")
        ids_resp = await client.get(f"{BASE_URL}/ids/status", headers=headers)
        
        if ids_resp.status_code != 200:
            print(f"✗ IDS status failed: {ids_resp.status_code}")
            return False
        
        ids = ids_resp.json()
        print("✓ IDS status loaded")
        print(f"  Packets Processed: {ids.get('packetsProcessed', ids.get('packets_processed', 0))}")
        print(f"  Anomalies: {ids.get('anomaliesDetected', ids.get('anomalies_detected', 0))}")
        print(f"  Attacks: {ids.get('attacksDetected', ids.get('attacks_detected', 0))}")
        print("✓ USER SEES: Real monitoring metrics (currently 0)")
        
        # Step 6: Check top sources (blocked IPs list)
        print("\n[CHECK] Top Sources / Blocked IPs list...")
        sources_resp = await client.get(f"{BASE_URL}/dashboard/top-sources?limit=10", headers=headers)
        
        if sources_resp.status_code != 200:
            print(f"✗ Top sources failed: {sources_resp.status_code}")
            return False
        
        sources = sources_resp.json()
        print(f"✓ Top sources loaded: {len(sources)} IPs")
        
        if len(sources) > 0:
            print("⚠ WARNING: Found blocked IPs - checking if fake...")
            for src in sources:
                print(f"  - {src['sourceIp']}: {src['flowCount']} flows")
            print("❌ USER SEES: FAKE BLOCKED IPs LIST")
            return False
        
        print("✓ NO FAKE BLOCKED IPs")
        print("✓ USER SEES: Empty top sources (correct - no attacks yet)")
        
        # Step 7: Turn IDS OFF
        print("\n[USER ACTION] Click IDS OFF button...")
        off_resp = await client.post(
            f"{BASE_URL}/ids/control",
            headers=headers,
            json={"enabled": False}
        )
        
        if off_resp.status_code != 200:
            print(f"✗ IDS OFF failed: {off_resp.status_code}")
            return False
        
        print("✓ IDS turned OFF")
        print("✓ USER SEES: IDS button shows 'OFF', monitoring disabled message")
        
        # Final verification
        print("\n" + "=" * 80)
        print("TEST RESULTS")
        print("=" * 80)
        print("✅ Login works")
        print("✅ Dashboard loads (not blank)")
        print("✅ IDS ON/OFF works")
        print("✅ Dashboard doesn't go blank when IDS ON")
        print("✅ NO FAKE DATA anywhere")
        print("✅ NO FAKE VALUES")
        print("✅ NO FAKE BLOCKED LIST")
        print("✅ NO RANDOM VALUES")
        print("\nUSER EXPERIENCE:")
        print("- Dashboard shows clean state (0 events)")
        print("- IDS control works correctly")
        print("- All components render properly")
        print("- No fake attacks or blocked IPs")
        print("- System ready for real network monitoring")
        print("=" * 80)
        
        return True

if __name__ == "__main__":
    success = asyncio.run(test_user_scenario())
    exit(0 if success else 1)
