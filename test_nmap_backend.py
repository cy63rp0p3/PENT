#!/usr/bin/env python3
"""
Test script to debug Nmap backend integration
"""

import subprocess
import tempfile
import os
import xml.etree.ElementTree as ET
import time

def test_nmap_integration():
    """Test Nmap integration similar to backend"""
    print("Testing Nmap integration...")
    
    # Test parameters
    target = "google.com"
    scan_type = "quick"
    scan_id = "test_123"
    
    # Build Nmap command
    nmap_cmd = ['nmap']
    
    if scan_type == 'quick':
        nmap_cmd.extend(['-F', '-sV'])
    
    # Add output formats
    temp_dir = tempfile.gettempdir()
    xml_file = os.path.join(temp_dir, f'nmap_{scan_id}.xml')
    txt_file = os.path.join(temp_dir, f'nmap_{scan_id}.txt')
    nmap_cmd.extend(['-oX', xml_file, '-oN', txt_file])
    
    # Add target
    nmap_cmd.append(target)
    
    print(f"Nmap command: {' '.join(nmap_cmd)}")
    
    try:
        # Run Nmap
        print("Running Nmap...")
        result = subprocess.run(nmap_cmd, capture_output=True, text=True, timeout=300)
        
        print(f"Return code: {result.returncode}")
        print(f"STDOUT: {result.stdout[:200]}...")
        print(f"STDERR: {result.stderr[:200]}...")
        
        if result.returncode == 0:
            # Check if XML file exists
            if os.path.exists(xml_file):
                print(f"XML file exists: {xml_file}")
                
                # Parse XML output
                try:
                    tree = ET.parse(xml_file)
                    root = tree.getroot()
                    
                    results = []
                    for host in root.findall('.//host'):
                        for port in host.findall('.//port'):
                            port_id = port.get('portid')
                            protocol = port.get('protocol')
                            
                            state_elem = port.find('state')
                            state = state_elem.get('state') if state_elem is not None else 'unknown'
                            
                            service_elem = port.find('service')
                            service = service_elem.get('name') if service_elem is not None else 'unknown'
                            version = service_elem.get('version') if service_elem is not None else ''
                            
                            results.append({
                                'port': int(port_id),
                                'protocol': protocol,
                                'state': state,
                                'service': service,
                                'version': version
                            })
                    
                    print(f"Found {len(results)} ports:")
                    for r in results:
                        print(f"  Port {r['port']}: {r['state']} - {r['service']}")
                    
                except Exception as xml_error:
                    print(f"XML parsing error: {xml_error}")
            else:
                print(f"XML file not found: {xml_file}")
        else:
            print("Nmap failed to run successfully")
            
    except subprocess.TimeoutExpired:
        print("Nmap scan timed out")
    except Exception as e:
        print(f"Error running Nmap: {e}")

if __name__ == "__main__":
    test_nmap_integration() 