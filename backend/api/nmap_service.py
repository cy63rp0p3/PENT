import subprocess
import xml.etree.ElementTree as ET
import json
import time
import threading
import os
import shutil
from typing import Dict, List, Optional
import tempfile

class NmapService:
    def __init__(self):
        """Initialize Nmap service"""
        self.nmap_path = self._find_nmap()
        self.scan_results = {}  # Store scan results in memory
    
    def _find_nmap(self) -> str:
        """Find Nmap installation path"""
        # Try to find nmap in PATH
        nmap_path = shutil.which('nmap')
        if nmap_path:
            return nmap_path
        
        # Common Windows installation paths
        windows_paths = [
            r"C:\Program Files (x86)\Nmap\nmap.exe",
            r"C:\Program Files\Nmap\nmap.exe",
            r"C:\nmap\nmap.exe"
        ]
        
        for path in windows_paths:
            if os.path.exists(path):
                return path
        
        # Common Linux/macOS paths
        unix_paths = [
            "/usr/bin/nmap",
            "/usr/local/bin/nmap",
            "/opt/nmap/bin/nmap"
        ]
        
        for path in unix_paths:
            if os.path.exists(path):
                return path
        
        return None
    
    def check_nmap_availability(self) -> Dict:
        """Check if Nmap is available"""
        if not self.nmap_path:
            return {
                'available': False,
                'error': 'Nmap not found. Please install Nmap and ensure it\'s in your PATH.'
            }
        
        try:
            # Test Nmap installation
            result = subprocess.run([self.nmap_path, '--version'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                return {
                    'available': True,
                    'version': result.stdout.split('\n')[0],
                    'path': self.nmap_path
                }
            else:
                return {
                    'available': False,
                    'error': 'Nmap installation test failed'
                }
        except Exception as e:
            return {
                'available': False,
                'error': f'Nmap test failed: {str(e)}'
            }
    
    def _build_nmap_command(self, target: str, scan_type: str = 'quick', 
                           ports: str = None, options: Dict = None) -> List[str]:
        """Build Nmap command based on scan type and options"""
        cmd = [self.nmap_path]
        
        # Set default scan speed for better performance
        default_speed = '-T4'  # Fast timing
        
        # Add scan type specific options with performance optimizations
        if scan_type == 'quick':
            # Quick scan: Fast scan of most common ports (100 ports)
            cmd.extend(['-F', '-T4'])  # Fast scan with fast timing
            if not ports:  # Use default fast scan ports
                ports = None  # Let -F handle it (top 100 ports)
        elif scan_type == 'full':
            # Full scan: Comprehensive scan with service detection
            cmd.extend(['-sS', '-sV', '-O', '-T4'])
        elif scan_type == 'stealth':
            # Stealth scan: SYN scan only
            cmd.extend(['-sS', '-T4'])
        elif scan_type == 'aggressive':
            # Aggressive scan: Maximum detection
            cmd.extend(['-A', '-T4'])
        
        # Add custom port range only if specified and not using quick scan default
        if ports and scan_type != 'quick':
            cmd.extend(['-p', ports])
        elif ports and scan_type == 'quick':
            # For quick scan, use specified ports but keep fast timing
            cmd.extend(['-p', ports])
        
        # Add options from advanced settings (with performance considerations)
        if options:
            # Service detection - only add if not already present and not quick scan
            if options.get('serviceDetection', True) and scan_type != 'quick':
                if '-sV' not in cmd:
                    cmd.append('-sV')
            
            # OS detection - only add if not already present and not quick scan
            if options.get('osDetection', False) and scan_type != 'quick':
                if '-O' not in cmd:
                    cmd.append('-O')
            
            # Script scan - only add if not already present and not quick scan
            if options.get('scriptScan', False) and scan_type != 'quick':
                if '-sC' not in cmd:
                    cmd.append('-sC')
            
            # Scan speed - override default if specified
            scan_speed = options.get('scanSpeed', 'fast')  # Default to fast
            speed_map = {
                'slow': '-T1',
                'normal': '-T3',
                'fast': '-T4',
                'aggressive': '-T5'
            }
            if scan_speed in speed_map:
                # Replace existing timing option if present
                cmd = [arg for arg in cmd if not arg.startswith('-T')]
                cmd.append(speed_map[scan_speed])
        
        # Add output formats
        temp_dir = tempfile.gettempdir()
        xml_file = os.path.join(temp_dir, f'nmap_scan_{int(time.time())}.xml')
        txt_file = os.path.join(temp_dir, f'nmap_scan_{int(time.time())}.txt')
        
        cmd.extend(['-oX', xml_file, '-oN', txt_file])
        
        # Add target
        cmd.append(target)
        
        return cmd, xml_file, txt_file
    
    def _parse_nmap_xml(self, xml_file: str) -> Dict:
        """Parse Nmap XML output"""
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            scan_results = []
            os_info = {}
            total_ports = 0
            open_ports = 0
            
            # Parse hosts
            for host in root.findall('.//host'):
                # OS detection
                os_elem = host.find('.//osmatch')
                if os_elem is not None:
                    os_info = {
                        'name': os_elem.get('name', 'Unknown'),
                        'accuracy': os_elem.get('accuracy', '0'),
                        'line': os_elem.get('line', '')
                    }
                
                # Parse ports
                for port_elem in host.findall('.//port'):
                    port_id = port_elem.get('portid', '')
                    protocol = port_elem.get('protocol', 'tcp')
                    state_elem = port_elem.find('state')
                    service_elem = port_elem.find('service')
                    
                    if state_elem is not None:
                        state = state_elem.get('state', 'unknown')
                        total_ports += 1
                        
                        if state == 'open':
                            open_ports += 1
                        
                        service_info = {
                            'port': port_id,
                            'protocol': protocol,
                            'state': state,
                            'service': service_elem.get('name', 'unknown') if service_elem is not None else 'unknown',
                            'product': service_elem.get('product', '') if service_elem is not None else '',
                            'version': service_elem.get('version', '') if service_elem is not None else '',
                            'extrainfo': service_elem.get('extrainfo', '') if service_elem is not None else ''
                        }
                        
                        scan_results.append(service_info)
            
            # Debug: Log parsing results
            print(f"Parsed {len(scan_results)} ports")
            print(f"Total ports: {total_ports}")
            print(f"Open ports: {open_ports}")
            print(f"OS info: {os_info}")
            
            # Clean up temporary files
            try:
                os.remove(xml_file)
                os.remove(txt_file)
            except:
                pass
            
            return {
                'type': 'port_scan',
                'total_ports': total_ports,
                'open_ports': open_ports,
                'closed_ports': total_ports - open_ports,
                'os_info': os_info,
                'data': scan_results,
                'services': list(set([r['service'] for r in scan_results if r['service'] != 'unknown']))
            }
            
        except ET.ParseError as e:
            return {'error': f'Failed to parse Nmap XML output: {str(e)}'}
        except Exception as e:
            return {'error': f'Failed to process scan results: {str(e)}'}
    
    def start_scan(self, target: str, scan_type: str = 'quick', 
                   ports: str = None, options: Dict = None) -> Dict:
        """Start a port scan"""
        # Check Nmap availability
        availability = self.check_nmap_availability()
        if not availability['available']:
            return availability
        
        scan_id = f"nmap_scan_{int(time.time())}"
        
        try:
            # Build command
            cmd, xml_file, txt_file = self._build_nmap_command(target, scan_type, ports, options)
            
            # Debug: Log the command being executed
            print(f"Executing Nmap command: {' '.join(cmd)}")
            
            # Execute scan
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            # Debug: Log the result
            print(f"Nmap return code: {result.returncode}")
            print(f"Nmap stdout: {result.stdout[:500]}...")
            print(f"Nmap stderr: {result.stderr[:500]}...")
            
            if result.returncode not in [0, 1]:  # Nmap returns 1 for some warnings
                return {'error': f'Nmap scan failed: {result.stderr}'}
            
            # Parse results
            scan_data = self._parse_nmap_xml(xml_file)
            if 'error' in scan_data:
                return scan_data
            
            # Store results
            self.scan_results[scan_id] = {
                'status': 'completed',
                'target': target,
                'scan_type': scan_type,
                'results': scan_data,
                'timestamp': time.time()
            }
            
            return {
                'scan_id': scan_id,
                'status': 'completed',
                'target': target,
                'scan_type': scan_type,
                'results': scan_data
            }
            
        except subprocess.TimeoutExpired:
            return {'error': 'Nmap scan timed out after 5 minutes'}
        except Exception as e:
            return {'error': f'Nmap scan failed: {str(e)}'}
    
    def start_async_scan(self, target: str, scan_type: str = 'quick', 
                        ports: str = None, options: Dict = None) -> Dict:
        """Start an asynchronous port scan"""
        # Check Nmap availability
        availability = self.check_nmap_availability()
        if not availability['available']:
            return availability
        
        scan_id = f"nmap_scan_{int(time.time())}"
        
        # Initialize scan status
        self.scan_results[scan_id] = {
            'status': 'running',
            'target': target,
            'scan_type': scan_type,
            'progress': 0,
            'timestamp': time.time()
        }
        
        # Start scan in background thread
        def run_scan():
            try:
                # Build command
                cmd, xml_file, txt_file = self._build_nmap_command(target, scan_type, ports, options)
                
                # Debug: Log the command being executed
                print(f"Executing Nmap command: {' '.join(cmd)}")
                
                # Execute scan
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                
                # Debug: Log the result
                print(f"Nmap return code: {result.returncode}")
                print(f"Nmap stdout: {result.stdout[:500]}...")
                print(f"Nmap stderr: {result.stderr[:500]}...")
                
                if result.returncode not in [0, 1]:
                    self.scan_results[scan_id] = {
                        'status': 'failed',
                        'error': f'Nmap scan failed: {result.stderr}',
                        'timestamp': time.time()
                    }
                    return
                
                # Parse results
                scan_data = self._parse_nmap_xml(xml_file)
                if 'error' in scan_data:
                    self.scan_results[scan_id] = {
                        'status': 'failed',
                        'error': scan_data['error'],
                        'timestamp': time.time()
                    }
                    return
                
                # Update results
                self.scan_results[scan_id] = {
                    'status': 'completed',
                    'target': target,
                    'scan_type': scan_type,
                    'results': scan_data,
                    'progress': 100,
                    'timestamp': time.time()
                }
                
            except Exception as e:
                self.scan_results[scan_id] = {
                    'status': 'failed',
                    'error': str(e),
                    'timestamp': time.time()
                }
        
        # Start background thread
        thread = threading.Thread(target=run_scan)
        thread.daemon = True
        thread.start()
        
        return {
            'scan_id': scan_id,
            'status': 'started',
            'target': target,
            'scan_type': scan_type,
            'message': 'Scan started successfully'
        }
    
    def get_scan_status(self, scan_id: str) -> Dict:
        """Get scan status and results"""
        if scan_id not in self.scan_results:
            return {'error': 'Scan not found'}
        
        scan_data = self.scan_results[scan_id]
        
        if scan_data['status'] == 'running':
            # Estimate progress based on time elapsed
            elapsed = time.time() - scan_data['timestamp']
            estimated_progress = min(90, int(elapsed / 30))  # Assume 5 minutes for full scan
            scan_data['progress'] = estimated_progress
        
        return scan_data
    
    def get_all_scans(self) -> Dict:
        """Get all scan results"""
        return {
            'scans': self.scan_results,
            'total_scans': len(self.scan_results)
        }
    
    def cancel_scan(self, scan_id: str) -> Dict:
        """Cancel a running scan (note: Nmap doesn't support easy cancellation)"""
        if scan_id not in self.scan_results:
            return {'error': 'Scan not found'}
        
        scan_data = self.scan_results[scan_id]
        if scan_data['status'] != 'running':
            return {'error': 'Scan is not running'}
        
        # Mark as cancelled (actual cancellation would require process management)
        scan_data['status'] = 'cancelled'
        scan_data['timestamp'] = time.time()
        
        return {'status': 'cancelled', 'scan_id': scan_id}
    
    def clear_old_scans(self, max_age_hours: int = 24) -> Dict:
        """Clear old scan results"""
        current_time = time.time()
        max_age_seconds = max_age_hours * 3600
        
        old_scans = []
        for scan_id, scan_data in list(self.scan_results.items()):
            if current_time - scan_data['timestamp'] > max_age_seconds:
                old_scans.append(scan_id)
                del self.scan_results[scan_id]
        
        return {
            'cleared_scans': len(old_scans),
            'remaining_scans': len(self.scan_results)
        }
    
    def test_performance(self, target: str = "127.0.0.1") -> Dict:
        """Test scan performance with different configurations"""
        results = {}
        
        # Test 1: Quick scan (optimized)
        start_time = time.time()
        quick_result = self.start_scan(target, 'quick')
        quick_time = time.time() - start_time
        
        results['quick_scan'] = {
            'time': round(quick_time, 2),
            'success': 'error' not in quick_result,
            'command': 'nmap -F -T4'
        }
        
        # Test 2: Quick scan with service detection (old way)
        start_time = time.time()
        quick_sv_result = self.start_scan(target, 'quick', options={'serviceDetection': True})
        quick_sv_time = time.time() - start_time
        
        results['quick_scan_with_service'] = {
            'time': round(quick_sv_time, 2),
            'success': 'error' not in quick_sv_result,
            'command': 'nmap -F -sV -T4'
        }
        
        # Test 3: Full port range (old way)
        start_time = time.time()
        full_range_result = self.start_scan(target, 'quick', ports='1-1000')
        full_range_time = time.time() - start_time
        
        results['full_range_scan'] = {
            'time': round(full_range_time, 2),
            'success': 'error' not in full_range_result,
            'command': 'nmap -p 1-1000 -T4'
        }
        
        # Calculate improvements
        if results['quick_scan']['success'] and results['quick_scan_with_service']['success']:
            improvement = results['quick_scan_with_service']['time'] / results['quick_scan']['time']
            results['improvement'] = f"{improvement:.1f}x faster"
        
        return results 