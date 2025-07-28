#!/usr/bin/env python3
"""
Test script to debug ZAP integration
"""

import requests
import time
import json

def test_zap_integration():
    """Test ZAP API integration step by step"""
    print("Testing ZAP integration...")
    
    # Test parameters
    target = "http://testphp.vulnweb.com/"
    zap_host = 'localhost'
    zap_port = 8080
    base_url = f'http://{zap_host}:{zap_port}/JSON'
    
    try:
        # Step 1: Check if ZAP is running
        print("\n1. Checking ZAP version...")
        version_response = requests.get(f'{base_url}/core/view/version/', timeout=5)
        print(f"Version response: {version_response.status_code}")
        if version_response.status_code == 200:
            print(f"ZAP version: {version_response.json()}")
        else:
            print(f"Error: {version_response.text}")
            return
        
        # Step 2: Create context
        print("\n2. Creating context...")
        context_name = f'context_test_{int(time.time())}'
        context_data = {'contextName': context_name}
        context_response = requests.post(f'{base_url}/context/action/newContext/', data=context_data)
        print(f"Context response: {context_response.status_code}")
        if context_response.status_code != 200:
            print(f"Error: {context_response.text}")
            return
        
        # Step 3: Start spider scan
        print("\n3. Starting spider scan...")
        spider_data = {
            'url': target,
            'maxChildren': '10',
            'recurse': 'true',
            'contextName': context_name
        }
        spider_response = requests.post(f'{base_url}/spider/action/scan/', data=spider_data)
        print(f"Spider response: {spider_response.status_code}")
        if spider_response.status_code == 200:
            spider_result = spider_response.json()
            spider_scan_id = spider_result.get('scan')
            print(f"Spider scan ID: {spider_scan_id}")
            
            # Wait for spider to complete
            print("Waiting for spider to complete...")
            while True:
                spider_status = requests.get(f'{base_url}/spider/view/status/?scanId={spider_scan_id}')
                if spider_status.status_code == 200:
                    status_result = spider_status.json()
                    status = status_result.get('status', '0')
                    print(f"Spider status: {status}%")
                    if status == '100':
                        break
                time.sleep(2)
        else:
            print(f"Error: {spider_response.text}")
            return
        
        # Step 4: Get alerts
        print("\n4. Retrieving alerts...")
        alerts_response = requests.get(f'{base_url}/core/view/alerts/?baseurl={target}')
        print(f"Alerts response: {alerts_response.status_code}")
        if alerts_response.status_code == 200:
            alerts_result = alerts_response.json()
            alerts = alerts_result.get('alerts', [])
            print(f"Found {len(alerts)} alerts")
            
            for alert in alerts[:5]:  # Show first 5 alerts
                print(f"- {alert.get('name')} ({alert.get('risk')})")
        else:
            print(f"Error: {alerts_response.text}")
            return
        
        print("\n✅ ZAP integration test completed successfully!")
        
    except Exception as e:
        print(f"\n❌ Error: {e}")

if __name__ == "__main__":
    test_zap_integration() 