import requests
import time
import json
from typing import Dict, List, Optional

class ZAPService:
    def __init__(self, zap_url: str = "http://localhost:8080", api_key: str = None):
        """
        Initialize ZAP service
        
        Args:
            zap_url: ZAP API URL (default: http://localhost:8080)
            api_key: ZAP API key (optional, can be set in ZAP)
        """
        self.zap_url = zap_url.rstrip('/')
        self.api_key = api_key
        self.session = requests.Session()
        
        # Set default headers
        self.session.headers.update({
            'Content-Type': 'application/x-www-form-urlencoded',
            'Accept': 'application/json'
        })
    
    def _make_request(self, endpoint: str, method: str = 'GET', data: Dict = None) -> Dict:
        """Make API request to ZAP"""
        url = f"{self.zap_url}{endpoint}"
        
        # Add API key if available
        if self.api_key and data:
            data['apikey'] = self.api_key
        
        try:
            if method.upper() == 'GET':
                response = self.session.get(url, params=data)
            else:
                response = self.session.post(url, data=data)
            
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            return {'error': f'ZAP API request failed: {str(e)}'}
        except json.JSONDecodeError:
            return {'error': 'Invalid JSON response from ZAP'}
    
    def check_zap_status(self) -> Dict:
        """Check if ZAP is running and accessible"""
        return self._make_request('/JSON/core/view/version/')
    
    def create_context(self, context_name: str = "default_context") -> Dict:
        """Create a new context for scanning"""
        data = {'contextName': context_name}
        return self._make_request('/JSON/context/action/newContext/', 'POST', data)
    
    def start_spider_scan(self, target: str, max_children: int = 10, recurse: bool = True) -> Dict:
        """Start a spider scan to discover URLs"""
        data = {
            'url': target,
            'maxChildren': str(max_children),
            'recurse': str(recurse).lower()
        }
        return self._make_request('/JSON/spider/action/scan/', 'POST', data)
    
    def start_active_scan(self, target: str, scan_policy: str = "Default Policy") -> Dict:
        """Start an active scan to find vulnerabilities"""
        data = {
            'url': target,
            'scanPolicyName': scan_policy
        }
        return self._make_request('/JSON/ascan/action/scan/', 'POST', data)
    
    def get_spider_status(self, scan_id: str) -> Dict:
        """Get spider scan status"""
        data = {'scanId': scan_id}
        return self._make_request('/JSON/spider/view/status/', 'GET', data)
    
    def get_active_scan_status(self, scan_id: str) -> Dict:
        """Get active scan status"""
        data = {'scanId': scan_id}
        return self._make_request('/JSON/ascan/view/status/', 'GET', data)
    
    def get_alerts(self, base_url: str = None, risk_level: str = None) -> Dict:
        """Get vulnerability alerts"""
        data = {}
        if base_url:
            data['baseurl'] = base_url
        if risk_level:
            data['riskId'] = risk_level
        
        return self._make_request('/JSON/core/view/alerts/', 'GET', data)
    
    def get_sites(self) -> Dict:
        """Get list of scanned sites"""
        return self._make_request('/JSON/core/view/sites/')
    
    def get_urls(self, base_url: str = None) -> Dict:
        """Get discovered URLs"""
        data = {}
        if base_url:
            data['baseurl'] = base_url
        return self._make_request('/JSON/core/view/urls/', 'GET', data)
    
    def wait_for_spider_completion(self, scan_id: str, timeout: int = 300) -> Dict:
        """Wait for spider scan to complete"""
        start_time = time.time()
        while time.time() - start_time < timeout:
            status = self.get_spider_status(scan_id)
            if status.get('status') == '100':
                return {'status': 'completed', 'scan_id': scan_id}
            elif status.get('status') == '-1':
                return {'status': 'failed', 'scan_id': scan_id, 'error': 'Scan failed'}
            time.sleep(5)
        
        return {'status': 'timeout', 'scan_id': scan_id}
    
    def wait_for_active_scan_completion(self, scan_id: str, timeout: int = 600) -> Dict:
        """Wait for active scan to complete"""
        start_time = time.time()
        while time.time() - start_time < timeout:
            status = self.get_active_scan_status(scan_id)
            if status.get('status') == '100':
                return {'status': 'completed', 'scan_id': scan_id}
            elif status.get('status') == '-1':
                return {'status': 'failed', 'scan_id': scan_id, 'error': 'Scan failed'}
            time.sleep(10)
        
        return {'status': 'timeout', 'scan_id': scan_id}
    
    def comprehensive_scan(self, target: str, wait_for_completion: bool = True) -> Dict:
        """Perform a comprehensive vulnerability scan"""
        try:
            # Check ZAP status
            status = self.check_zap_status()
            if 'error' in status:
                return status
            
            # Create context
            context_result = self.create_context(f"scan_{int(time.time())}")
            if 'error' in context_result:
                return context_result
            
            # Start spider scan
            spider_result = self.start_spider_scan(target)
            if 'error' in spider_result:
                return spider_result
            
            spider_scan_id = spider_result.get('scan')
            
            # Wait for spider to complete if requested
            if wait_for_completion:
                spider_completion = self.wait_for_spider_completion(spider_scan_id)
                if spider_completion.get('status') != 'completed':
                    return spider_completion
            
            # Start active scan
            active_result = self.start_active_scan(target)
            if 'error' in active_result:
                return active_result
            
            active_scan_id = active_result.get('scan')
            
            # Wait for active scan to complete if requested
            if wait_for_completion:
                active_completion = self.wait_for_active_scan_completion(active_scan_id)
                if active_completion.get('status') != 'completed':
                    return active_completion
            
            # Get results
            alerts = self.get_alerts(target)
            urls = self.get_urls(target)
            
            return {
                'status': 'completed',
                'target': target,
                'spider_scan_id': spider_scan_id,
                'active_scan_id': active_scan_id,
                'alerts': alerts,
                'urls': urls,
                'summary': {
                    'total_alerts': len(alerts.get('alerts', [])),
                    'total_urls': len(urls.get('urls', [])),
                    'critical_alerts': len([a for a in alerts.get('alerts', []) if a.get('risk') == 'High']),
                    'high_alerts': len([a for a in alerts.get('alerts', []) if a.get('risk') == 'High']),
                    'medium_alerts': len([a for a in alerts.get('alerts', []) if a.get('risk') == 'Medium']),
                    'low_alerts': len([a for a in alerts.get('alerts', []) if a.get('risk') == 'Low'])
                }
            }
            
        except Exception as e:
            return {'error': f'Comprehensive scan failed: {str(e)}'}
    
    def get_scan_progress(self, spider_scan_id: str = None, active_scan_id: str = None) -> Dict:
        """Get progress of running scans"""
        progress = {}
        
        if spider_scan_id:
            spider_status = self.get_spider_status(spider_scan_id)
            progress['spider'] = {
                'scan_id': spider_scan_id,
                'status': spider_status.get('status', '0'),
                'progress': f"{spider_status.get('status', '0')}%"
            }
        
        if active_scan_id:
            active_status = self.get_active_scan_status(active_scan_id)
            progress['active'] = {
                'scan_id': active_scan_id,
                'status': active_status.get('status', '0'),
                'progress': f"{active_status.get('status', '0')}%"
            }
        
        return progress 