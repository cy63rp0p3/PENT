#!/usr/bin/env python3

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from api.python_scan_service import PythonScanService

def test_python_scanning():
    print("Testing Pure Python Scanning Service...")
    
    # Initialize service
    scan_service = PythonScanService()
    
    # Test 1: Port scanning
    print("\n1. Testing Port Scanning...")
    port_results = scan_service.scan_ports("127.0.0.1", [80, 443, 8080, 22, 21])
    print(f"Port scan results: {port_results}")
    
    # Test 2: SSL certificate check
    print("\n2. Testing SSL Certificate Check...")
    ssl_results = scan_service.check_ssl_certificate("google.com")
    print(f"SSL results: {ssl_results}")
    
    # Test 3: HTTP security headers
    print("\n3. Testing HTTP Security Headers...")
    headers_results = scan_service.check_http_security_headers("httpbin.org")
    print(f"Security headers: {headers_results}")
    
    # Test 4: Vulnerability scanning
    print("\n4. Testing Vulnerability Scanning...")
    vuln_results = scan_service.vulnerability_scan("httpbin.org", ["sql_injection", "xss"])
    print(f"Vulnerability scan results: {vuln_results}")
    
    # Test 5: Async scanning
    print("\n5. Testing Async Port Scanning...")
    async_result = scan_service.start_async_port_scan("127.0.0.1", [80, 443])
    print(f"Async scan started: {async_result}")
    
    if 'scan_id' in async_result:
        scan_id = async_result['scan_id']
        
        # Wait a bit and check status
        import time
        time.sleep(2)
        
        status = scan_service.get_scan_status(scan_id)
        print(f"Scan status: {status}")
    
    print("\n✅ All tests completed!")

if __name__ == "__main__":
    test_python_scanning() 