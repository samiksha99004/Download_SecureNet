"""
Test that IDS API returns proper camelCase for frontend
"""
import asyncio
import httpx

BASE_URL = "http://127.0.0.1:8000/api"

async def test_camelcase():
    """Verify camelCase format in IDS responses"""
    print("=" * 70)
    print("TESTING CAMELCASE FORMAT FIX")
    print("=" * 70)
    
    async with httpx.AsyncClient(timeout=30.0) as client:
        # Login
        print("\n[1] Login...")
        login_resp = await client.post(
            f"{BASE_URL}/auth/login",
            json={"email": "admin@securenet.com", "password": "Admin@123456"}
        )
        
        token = login_resp.json()["tokens"]["accessToken"]
        headers = {"Authorization": f"Bearer {token}"}
        print("OK Logged in")
        
        # Test IDS status GET
        print("\n[2] GET /api/ids/status")
        status_resp = await client.get(f"{BASE_URL}/ids/status", headers=headers)
        status = status_resp.json()
        
        print(f"Response keys: {list(status.keys())}")
        
        required_fields = ['enabled', 'mode', 'mlLoaded', 'packetsProcessed', 
                          'flowsAnalyzed', 'anomaliesDetected', 'attacksDetected']
        
        missing = [f for f in required_fields if f not in status]
        wrong_case = [k for k in status.keys() if '_' in k]
        
        if missing:
            print(f"X FAIL: Missing fields: {missing}")
            return False
        
        if wrong_case:
            print(f"X FAIL: Found snake_case fields: {wrong_case}")
            return False
        
        print("OK All fields in camelCase")
        
        # Test IDS control POST
        print("\n[3] POST /api/ids/control (enable=true)")
        on_resp = await client.post(
            f"{BASE_URL}/ids/control",
            headers=headers,
            json={"enabled": True}
        )
        on_status = on_resp.json()
        
        print(f"Response keys: {list(on_status.keys())}")
        
        missing = [f for f in required_fields if f not in on_status]
        wrong_case = [k for k in on_status.keys() if '_' in k]
        
        if missing:
            print(f"X FAIL: Missing fields: {missing}")
            return False
        
        if wrong_case:
            print(f"X FAIL: Found snake_case fields: {wrong_case}")
            return False
        
        print("OK All fields in camelCase")
        print(f"Values: mlLoaded={on_status['mlLoaded']}, packetsProcessed={on_status['packetsProcessed']}")
        
        # Turn OFF
        print("\n[4] POST /api/ids/control (enable=false)")
        off_resp = await client.post(
            f"{BASE_URL}/ids/control",
            headers=headers,
            json={"enabled": False}
        )
        off_status = off_resp.json()
        
        print(f"Response keys: {list(off_status.keys())}")
        
        missing = [f for f in required_fields if f not in off_status]
        wrong_case = [k for k in off_status.keys() if '_' in k]
        
        if missing:
            print(f"X FAIL: Missing fields: {missing}")
            return False
        
        if wrong_case:
            print(f"X FAIL: Found snake_case fields: {wrong_case}")
            return False
        
        print("OK All fields in camelCase")
        
        print("\n" + "=" * 70)
        print("RESULT: PASS")
        print("=" * 70)
        print("OK IDS API returns proper camelCase")
        print("OK Frontend will be able to parse responses")
        print("OK Dashboard should NOT go blank when IDS ON")
        print("=" * 70)
        
        return True

if __name__ == "__main__":
    success = asyncio.run(test_camelcase())
    exit(0 if success else 1)
