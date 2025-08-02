#!/usr/bin/env python3

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from api.nmap_service import NmapService

def test_nmap():
    print("Testing Nmap Service...")
    
    # Initialize service
    nmap_service = NmapService()
    
    # Check availability
    availability = nmap_service.check_nmap_availability()
    print(f"Nmap availability: {availability}")
    
    if not availability.get('available', False):
        print("❌ Nmap is not available!")
        return
    
    print("✅ Nmap is available!")
    
    # Test a quick scan
    print("\nTesting quick scan on 127.0.0.1...")
    result = nmap_service.start_scan("127.0.0.1", "quick")
    
    print(f"Scan result: {result}")
    
    if 'error' in result:
        print(f"❌ Scan failed: {result['error']}")
        return
    
    if 'results' in result:
        results = result['results']
        print(f"\nScan Results:")
        print(f"  Type: {results.get('type')}")
        print(f"  Total ports: {results.get('total_ports')}")
        print(f"  Open ports: {results.get('open_ports')}")
        print(f"  Closed ports: {results.get('closed_ports')}")
        print(f"  OS info: {results.get('os_info')}")
        print(f"  Data length: {len(results.get('data', []))}")
        
        if results.get('data'):
            print(f"  First few ports:")
            for i, port in enumerate(results['data'][:5]):
                print(f"    {i+1}. Port {port.get('port')} - {port.get('state')} - {port.get('service')}")
    
    print("\n✅ Test completed!")

if __name__ == "__main__":
    test_nmap() 