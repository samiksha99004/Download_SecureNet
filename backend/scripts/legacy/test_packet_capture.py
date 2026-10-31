"""
Test if Scapy can capture packets
"""
import sys

try:
    from scapy.all import sniff, IP
    print("OK Scapy imported successfully")
    
    print("\nTesting packet capture (5 seconds)...")
    print("Generating traffic: ping 127.0.0.1 in another window")
    
    packets = []
    def packet_callback(pkt):
        packets.append(pkt)
        if IP in pkt:
            print(f"  Captured: {pkt[IP].src} -> {pkt[IP].dst}")
    
    # Try to capture for 5 seconds
    sniff(timeout=5, prn=packet_callback, store=False)
    
    print(f"\nTotal packets captured: {len(packets)}")
    
    if len(packets) == 0:
        print("\nX NO PACKETS CAPTURED")
        print("\nPossible issues:")
        print("1. Scapy needs Administrator privileges on Windows")
        print("2. No network traffic during capture window")
        print("3. Firewall/antivirus blocking")
        print("\nSolution:")
        print("- Run backend as Administrator")
        print("- Or generate network traffic while IDS is ON")
        
except ImportError as e:
    print(f"X Scapy not installed: {e}")
    print("Install: pip install scapy")
    
except PermissionError as e:
    print(f"X Permission denied: {e}")
    print("\nScapy needs Administrator privileges on Windows!")
    print("Solution: Run PowerShell/CMD as Administrator, then run backend")
    
except Exception as e:
    print(f"X Error: {e}")
    import traceback
    traceback.print_exc()
