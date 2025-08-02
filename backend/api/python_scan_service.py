import socket
import threading
import time
import requests
import ssl
import urllib.parse
from typing import Dict, List, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import re
from urllib.parse import urljoin, urlparse
import http.client
import subprocess
import platform

class PythonScanService:
    """Pure Python implementation for port scanning and vulnerability assessment"""
    
    def __init__(self):
        self.scan_results = {}
        self.common_ports = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP", 
            110: "POP3", 143: "IMAP", 443: "HTTPS", 993: "IMAPS", 995: "POP3S",
            3306: "MySQL", 5432: "PostgreSQL", 27017: "MongoDB", 6379: "Redis",
            8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 9000: "Web-Alt", 9200: "Elasticsearch"
        }
        
        # Common vulnerabilities to check
        self.vulnerability_checks = {
            'sql_injection': {
                'name': 'SQL Injection',
                'description': 'Check for SQL injection vulnerabilities',
                'payloads': ["'", "1' OR '1'='1", "1; DROP TABLE users;--"]
            },
            'xss': {
                'name': 'Cross-Site Scripting',
                'description': 'Check for XSS vulnerabilities',
                'payloads': ['<script>alert("XSS")</script>', 'javascript:alert("XSS")']
            },
            'open_redirect': {
                'name': 'Open Redirect',
                'description': 'Check for open redirect vulnerabilities',
                'payloads': ['https://evil.com', '//evil.com']
            },
            'directory_traversal': {
                'name': 'Directory Traversal',
                'description': 'Check for directory traversal vulnerabilities',
                'payloads': ['../../../etc/passwd', '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts']
            }
        }
    
    def check_port_open(self, target: str, port: int, timeout: float = 1.0) -> Dict:
        """Check if a specific port is open"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((target, port))
            sock.close()
            
            if result == 0:
                # Try to get service information
                service_info = self.get_service_info(target, port)
                return {
                    'port': port,
                    'state': 'open',
                    'service': service_info.get('service', 'unknown'),
                    'product': service_info.get('product', ''),
                    'version': service_info.get('version', ''),
                    'banner': service_info.get('banner', '')
                }
            else:
                return {
                    'port': port,
                    'state': 'closed',
                    'service': 'unknown',
                    'product': '',
                    'version': '',
                    'banner': ''
                }
        except Exception as e:
            return {
                'port': port,
                'state': 'filtered',
                'service': 'unknown',
                'product': '',
                'version': '',
                'banner': '',
                'error': str(e)
            }
    
    def get_service_info(self, target: str, port: int, timeout: float = 2.0) -> Dict:
        """Get service information by connecting to the port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((target, port))
            
            # Send a basic probe
            if port in [80, 8080, 8443]:
                probe = b"GET / HTTP/1.1\r\nHost: " + target.encode() + b"\r\n\r\n"
            elif port in [22]:
                probe = b"SSH-2.0-OpenSSH_8.0\r\n"
            elif port in [21]:
                probe = b"USER anonymous\r\n"
            else:
                probe = b"\r\n"
            
            sock.send(probe)
            
            # Try to receive response
            try:
                response = sock.recv(1024).decode('utf-8', errors='ignore')
            except:
                response = ""
            
            sock.close()
            
            # Parse service information
            service_info = {
                'service': self.common_ports.get(port, 'unknown'),
                'product': '',
                'version': '',
                'banner': response.strip()
            }
            
            # Try to extract version information
            if response:
                # Look for common version patterns
                version_patterns = [
                    r'Server: ([^\r\n]+)',
                    r'SSH-(\d+\.\d+)',
                    r'FTP server \(([^)]+)\)',
                    r'([A-Za-z]+)/(\d+\.\d+)'
                ]
                
                for pattern in version_patterns:
                    match = re.search(pattern, response)
                    if match:
                        if len(match.groups()) == 1:
                            service_info['product'] = match.group(1)
                        else:
                            service_info['product'] = match.group(1)
                            service_info['version'] = match.group(2)
                        break
            
            return service_info
            
        except Exception as e:
            return {
                'service': self.common_ports.get(port, 'unknown'),
                'product': '',
                'version': '',
                'banner': '',
                'error': str(e)
            }
    
    def scan_ports(self, target: str, ports: List[int] = None, max_workers: int = 50) -> Dict:
        """Scan multiple ports concurrently"""
        if ports is None:
            ports = list(self.common_ports.keys())
        
        scan_results = []
        total_ports = len(ports)
        open_ports = 0
        
        print(f"Scanning {total_ports} ports on {target}...")
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all port checks
            future_to_port = {executor.submit(self.check_port_open, target, port): port for port in ports}
            
            # Collect results
            for future in as_completed(future_to_port):
                result = future.result()
                scan_results.append(result)
                
                if result['state'] == 'open':
                    open_ports += 1
                    print(f"Found open port: {result['port']} ({result['service']})")
        
        # Sort results by port number
        scan_results.sort(key=lambda x: x['port'])
        
        return {
            'type': 'port_scan',
            'target': target,
            'total_ports': total_ports,
            'open_ports': open_ports,
            'closed_ports': total_ports - open_ports,
            'data': scan_results,
            'services': list(set([r['service'] for r in scan_results if r['service'] != 'unknown']))
        }
    
    def check_ssl_certificate(self, target: str, port: int = 443) -> Dict:
        """Check SSL certificate information"""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((target, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=target) as ssock:
                    cert = ssock.getpeercert()
                    
                    return {
                        'valid': True,
                        'subject': dict(x[0] for x in cert['subject']),
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'version': cert['version'],
                        'serial_number': cert['serialNumber'],
                        'not_before': cert['notBefore'],
                        'not_after': cert['notAfter'],
                        'san': cert.get('subjectAltName', [])
                    }
        except Exception as e:
            return {
                'valid': False,
                'error': str(e)
            }
    
    def check_http_security_headers(self, url: str) -> Dict:
        """Check HTTP security headers"""
        try:
            if not url.startswith(('http://', 'https://')):
                url = f"http://{url}"
            
            response = requests.get(url, timeout=10, allow_redirects=False)
            headers = response.headers
            
            security_headers = {
                'strict_transport_security': headers.get('Strict-Transport-Security'),
                'content_security_policy': headers.get('Content-Security-Policy'),
                'x_frame_options': headers.get('X-Frame-Options'),
                'x_content_type_options': headers.get('X-Content-Type-Options'),
                'x_xss_protection': headers.get('X-XSS-Protection'),
                'referrer_policy': headers.get('Referrer-Policy'),
                'permissions_policy': headers.get('Permissions-Policy'),
                'cache_control': headers.get('Cache-Control')
            }
            
            return {
                'url': url,
                'status_code': response.status_code,
                'headers': security_headers,
                'missing_headers': [k for k, v in security_headers.items() if not v]
            }
        except Exception as e:
            return {
                'url': url,
                'error': str(e)
            }
    
    def check_vulnerability(self, url: str, vuln_type: str, payload: str) -> Dict:
        """Check for a specific vulnerability"""
        try:
            if not url.startswith(('http://', 'https://')):
                url = f"http://{url}"
            
            parsed_url = urlparse(url)
            base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
            
            # Test different injection points
            test_urls = [
                f"{base_url}/?id={payload}",
                f"{base_url}/search?q={payload}",
                f"{base_url}/page?param={payload}"
            ]
            
            for test_url in test_urls:
                try:
                    response = requests.get(test_url, timeout=5, allow_redirects=False)
                    
                    # Check for vulnerability indicators
                    indicators = {
                        'sql_injection': [
                            'sql syntax', 'mysql_fetch', 'oracle error', 'sql server error',
                            'postgresql error', 'sqlite error'
                        ],
                        'xss': [
                            '<script>alert("XSS")</script>', 'javascript:alert',
                            'onerror=', 'onload='
                        ],
                        'open_redirect': [
                            'location.href', 'window.location', 'redirect'
                        ]
                    }
                    
                    if vuln_type in indicators:
                        for indicator in indicators[vuln_type]:
                            if indicator.lower() in response.text.lower():
                                return {
                                    'vulnerable': True,
                                    'url': test_url,
                                    'payload': payload,
                                    'response_code': response.status_code,
                                    'evidence': indicator
                                }
                    
                    # Check for reflected XSS
                    if vuln_type == 'xss' and payload in response.text:
                        return {
                            'vulnerable': True,
                            'url': test_url,
                            'payload': payload,
                            'response_code': response.status_code,
                            'evidence': 'Reflected XSS detected'
                        }
                        
                except Exception as e:
                    continue
            
            return {
                'vulnerable': False,
                'url': url,
                'payload': payload
            }
            
        except Exception as e:
            return {
                'vulnerable': False,
                'url': url,
                'payload': payload,
                'error': str(e)
            }
    
    def vulnerability_scan(self, target: str, scan_types: List[str] = None) -> Dict:
        """Perform a comprehensive vulnerability scan"""
        if scan_types is None:
            scan_types = list(self.vulnerability_checks.keys())
        
        print(f"Starting vulnerability scan on {target}...")
        
        vulnerabilities = []
        security_headers = self.check_http_security_headers(target)
        ssl_info = self.check_ssl_certificate(target)
        
        # Check each vulnerability type
        for vuln_type in scan_types:
            if vuln_type in self.vulnerability_checks:
                vuln_info = self.vulnerability_checks[vuln_type]
                print(f"Checking {vuln_info['name']}...")
                
                for payload in vuln_info['payloads']:
                    result = self.check_vulnerability(target, vuln_type, payload)
                    if result.get('vulnerable', False):
                        vulnerabilities.append({
                            'type': vuln_type,
                            'name': vuln_info['name'],
                            'description': vuln_info['description'],
                            'severity': 'high' if vuln_type in ['sql_injection', 'xss'] else 'medium',
                            'evidence': result.get('evidence', ''),
                            'url': result.get('url', ''),
                            'payload': payload
                        })
        
        # Count vulnerabilities by severity
        high_vulns = len([v for v in vulnerabilities if v['severity'] == 'high'])
        medium_vulns = len([v for v in vulnerabilities if v['severity'] == 'medium'])
        low_vulns = len([v for v in vulnerabilities if v['severity'] == 'low'])
        
        return {
            'type': 'vulnerability_scan',
            'target': target,
            'total_vulnerabilities': len(vulnerabilities),
            'high_vulnerabilities': high_vulns,
            'medium_vulnerabilities': medium_vulns,
            'low_vulnerabilities': low_vulns,
            'vulnerabilities': vulnerabilities,
            'security_headers': security_headers,
            'ssl_certificate': ssl_info
        }
    
    def start_async_port_scan(self, target: str, ports: List[int] = None) -> Dict:
        """Start an asynchronous port scan"""
        scan_id = f"python_scan_{int(time.time())}"
        
        # Initialize scan status
        self.scan_results[scan_id] = {
            'status': 'running',
            'target': target,
            'scan_type': 'port_scan',
            'progress': 0,
            'timestamp': time.time()
        }
        
        def run_scan():
            try:
                # Perform the scan
                results = self.scan_ports(target, ports)
                
                # Update results
                self.scan_results[scan_id] = {
                    'status': 'completed',
                    'target': target,
                    'scan_type': 'port_scan',
                    'results': results,
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
            'scan_type': 'port_scan',
            'message': 'Port scan started successfully'
        }
    
    def start_async_vulnerability_scan(self, target: str, scan_types: List[str] = None) -> Dict:
        """Start an asynchronous vulnerability scan"""
        scan_id = f"python_vuln_scan_{int(time.time())}"
        
        # Initialize scan status
        self.scan_results[scan_id] = {
            'status': 'running',
            'target': target,
            'scan_type': 'vulnerability_scan',
            'progress': 0,
            'timestamp': time.time()
        }
        
        def run_scan():
            try:
                # Perform the scan
                results = self.vulnerability_scan(target, scan_types)
                
                # Update results
                self.scan_results[scan_id] = {
                    'status': 'completed',
                    'target': target,
                    'scan_type': 'vulnerability_scan',
                    'results': results,
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
            'scan_type': 'vulnerability_scan',
            'message': 'Vulnerability scan started successfully'
        }
    
    def get_scan_status(self, scan_id: str) -> Dict:
        """Get scan status and results"""
        if scan_id not in self.scan_results:
            return {'error': 'Scan not found'}
        
        scan_data = self.scan_results[scan_id]
        
        if scan_data['status'] == 'running':
            # Estimate progress based on time elapsed
            elapsed = time.time() - scan_data['timestamp']
            estimated_progress = min(90, int(elapsed / 10))  # Assume 30 seconds for full scan
            scan_data['progress'] = estimated_progress
        
        return scan_data
    
    def get_all_scans(self) -> Dict:
        """Get all scan results"""
        return {
            'scans': self.scan_results,
            'total_scans': len(self.scan_results)
        }
    
    def cancel_scan(self, scan_id: str) -> Dict:
        """Cancel a running scan"""
        if scan_id not in self.scan_results:
            return {'error': 'Scan not found'}
        
        scan_data = self.scan_results[scan_id]
        if scan_data['status'] != 'running':
            return {'error': 'Scan is not running'}
        
        # Mark as cancelled
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