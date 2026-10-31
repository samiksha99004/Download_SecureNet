"""
Test API responses when IDS is ON
"""
import asyncio
import httpx
import json

BASE_URL = "http://127.0.0.1:8000/api"

async def test_ids_on_api():
    """Test all API responses when IDS is ON"""
    print("=" * 70)
    print("TESTING API WHEN IDS IS ON")
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
        print("✓ Logged in")
        
        # Turn IDS ON
        print("\n[2] Turn IDS ON...")
        on_resp = await client.post(
            f"{BASE_URL}/ids/control",
            headers=headers,
            json={"enabled": True}
        )
        
        if on_resp.status_code != 200:
            print(f"✗ Failed: {on_resp.status_code}")
            print(on_resp.text)
            return
        
        print("✓ IDS is ON")
        print(f"Response: {json.dumps(on_resp.json(), indent=2)}")
        
        # Now call each API endpoint that dashboard uses
        print("\n[3] GET /api/dashboard/summary")
        try:
            summary_resp = await client.get(f"{BASE_URL}/dashboard/summary", headers=headers)
            print(f"Status: {summary_resp.status_code}")
            if summary_resp.status_code == 200:
                data = summary_resp.json()
                print(f"✓ Response: {json.dumps(data, indent=2)}")
            else:
                print(f"✗ Error: {summary_resp.text}")
        except Exception as e:
            print(f"✗ Exception: {e}")
        
        print("\n[4] GET /api/ids/status")
        try:
            ids_resp = await client.get(f"{BASE_URL}/ids/status", headers=headers)
            print(f"Status: {ids_resp.status_code}")
            if ids_resp.status_code == 200:
                data = ids_resp.json()
                print(f"✓ Response: {json.dumps(data, indent=2)}")
            else:
                print(f"✗ Error: {ids_resp.text}")
        except Exception as e:
            print(f"✗ Exception: {e}")
        
        print("\n[5] GET /api/dashboard/host-status")
        try:
            host_resp = await client.get(f"{BASE_URL}/dashboard/host-status", headers=headers)
            print(f"Status: {host_resp.status_code}")
            if host_resp.status_code == 200:
                data = host_resp.json()
                print(f"✓ Response keys: {list(data.keys())}")
            else:
                print(f"✗ Error: {host_resp.text}")
        except Exception as e:
            print(f"✗ Exception: {e}")
        
        print("\n[6] GET /api/dashboard/protocol-distribution")
        try:
            proto_resp = await client.get(f"{BASE_URL}/dashboard/protocol-distribution", headers=headers)
            print(f"Status: {proto_resp.status_code}")
            if proto_resp.status_code == 200:
                data = proto_resp.json()
                print(f"✓ Response: {json.dumps(data, indent=2)}")
            else:
                print(f"✗ Error: {proto_resp.text}")
        except Exception as e:
            print(f"✗ Exception: {e}")
        
        print("\n[7] GET /api/dashboard/top-sources")
        try:
            sources_resp = await client.get(f"{BASE_URL}/dashboard/top-sources", headers=headers)
            print(f"Status: {sources_resp.status_code}")
            if sources_resp.status_code == 200:
                data = sources_resp.json()
                print(f"✓ Response: {json.dumps(data, indent=2)}")
            else:
                print(f"✗ Error: {sources_resp.text}")
        except Exception as e:
            print(f"✗ Exception: {e}")
        
        print("\n[8] GET /api/events")
        try:
            events_resp = await client.get(f"{BASE_URL}/events?page=1&page_size=10", headers=headers)
            print(f"Status: {events_resp.status_code}")
            if events_resp.status_code == 200:
                data = events_resp.json()
                print(f"✓ Events count: {data['total']}")
            else:
                print(f"✗ Error: {events_resp.text}")
        except Exception as e:
            print(f"✗ Exception: {e}")
        
        # Turn IDS OFF
        print("\n[9] Turn IDS OFF...")
        off_resp = await client.post(
            f"{BASE_URL}/ids/control",
            headers=headers,
            json={"enabled": False}
        )
        print(f"✓ IDS is OFF")
        
        print("\n" + "=" * 70)
        print("All API endpoints should return HTTP 200 when IDS is ON")
        print("If any endpoint fails, frontend will go blank")
        print("=" * 70)

if __name__ == "__main__":
    asyncio.run(test_ids_on_api())
