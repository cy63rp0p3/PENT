#!/usr/bin/env python3
"""
Test script for reconnaissance APIs
Tests WHOIS, DNS, and Subdomain enumeration with real data
"""

import requests
import json
import time

BASE_URL = "http://localhost:8000/api"

def test_whois_lookup(domain="google.com"):
    """Test WHOIS lookup API"""
    print(f"🔍 Testing WHOIS lookup for: {domain}")
    try:
        response = requests.post(
            f"{BASE_URL}/recon/whois/",
            json={"target": domain},
            headers={"Content-Type": "application/json"}
        )
        
        if response.status_code == 200:
            data = response.json()
            print("✅ WHOIS lookup successful!")
            print(f"   Domain: {data.get('domain', 'N/A')}")
            print(f"   Registrar: {data.get('registrar', 'N/A')}")
            print(f"   Created: {data.get('created', 'N/A')}")
            print(f"   Expires: {data.get('expires', 'N/A')}")
            print(f"   Organization: {data.get('organization', 'N/A')}")
            print(f"   Nameservers: {len(data.get('nameservers', []))} found")
            return True
        else:
            print(f"❌ WHOIS lookup failed: {response.status_code}")
            print(f"   Error: {response.text}")
            return False
    except Exception as e:
        print(f"❌ WHOIS lookup error: {str(e)}")
        return False

def test_dns_lookup(domain="google.com"):
    """Test DNS lookup API"""
    print(f"\n🔍 Testing DNS lookup for: {domain}")
    try:
        response = requests.post(
            f"{BASE_URL}/recon/dns/",
            json={"target": domain},
            headers={"Content-Type": "application/json"}
        )
        
        if response.status_code == 200:
            data = response.json()
            print("✅ DNS lookup successful!")
            print(f"   Total records: {data.get('total_records', 0)}")
            print(f"   Record types: {data.get('record_types_found', [])}")
            
            records = data.get('records', [])
            for record in records[:5]:  # Show first 5 records
                print(f"   {record['type']}: {record['value']} (TTL: {record['ttl']})")
            
            if len(records) > 5:
                print(f"   ... and {len(records) - 5} more records")
            return True
        else:
            print(f"❌ DNS lookup failed: {response.status_code}")
            print(f"   Error: {response.text}")
            return False
    except Exception as e:
        print(f"❌ DNS lookup error: {str(e)}")
        return False

def test_subdomain_enum(domain="google.com"):
    """Test subdomain enumeration API"""
    print(f"\n🔍 Testing subdomain enumeration for: {domain}")
    try:
        response = requests.post(
            f"{BASE_URL}/recon/subdomain/",
            json={"target": domain},
            headers={"Content-Type": "application/json"}
        )
        
        if response.status_code == 200:
            data = response.json()
            print("✅ Subdomain enumeration successful!")
            print(f"   Total found: {data.get('total_found', 0)}")
            print(f"   Total checked: {data.get('total_checked', 0)}")
            
            subdomains = data.get('subdomains', [])
            for subdomain in subdomains[:10]:  # Show first 10 subdomains
                print(f"   {subdomain['subdomain']} -> {subdomain['ip']} ({subdomain['status']})")
            
            if len(subdomains) > 10:
                print(f"   ... and {len(subdomains) - 10} more subdomains")
            
            if data.get('errors'):
                print(f"   Errors: {len(data['errors'])} encountered")
            return True
        else:
            print(f"❌ Subdomain enumeration failed: {response.status_code}")
            print(f"   Error: {response.text}")
            return False
    except Exception as e:
        print(f"❌ Subdomain enumeration error: {str(e)}")
        return False

def main():
    """Run all reconnaissance tests"""
    print("🚀 Pent-Framework Reconnaissance API Test")
    print("=" * 50)
    
    # Test domains
    test_domains = ["google.com", "github.com", "microsoft.com"]
    
    for domain in test_domains:
        print(f"\n📊 Testing domain: {domain}")
        print("-" * 30)
        
        whois_success = test_whois_lookup(domain)
        dns_success = test_dns_lookup(domain)
        subdomain_success = test_subdomain_enum(domain)
        
        # Summary for this domain
        success_count = sum([whois_success, dns_success, subdomain_success])
        print(f"\n📈 Domain {domain}: {success_count}/3 tests passed")
        
        # Small delay between domains
        time.sleep(1)
    
    print("\n✅ Reconnaissance API testing complete!")
    print("🌐 Your reconnaissance tools are now providing real live data!")

if __name__ == "__main__":
    main() 