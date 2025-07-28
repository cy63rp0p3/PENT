#!/usr/bin/env python3
"""
Quick Setup Script for ZAP and Nmap API Integration
This script helps verify and configure the API tools for the PEN-T Framework.
"""

import os
import sys
import subprocess
import requests
import json
import time
from pathlib import Path

class APIToolsSetup:
    def __init__(self):
        self.nmap_available = False
        self.zap_available = False
        self.nmap_path = None
        self.zap_url = "http://localhost:8080"
        
    def print_header(self, title):
        """Print a formatted header"""
        print("\n" + "="*60)
        print(f"🔧 {title}")
        print("="*60)
    
    def print_success(self, message):
        """Print success message"""
        print(f"✅ {message}")
    
    def print_error(self, message):
        """Print error message"""
        print(f"❌ {message}")
    
    def print_info(self, message):
        """Print info message"""
        print(f"ℹ️  {message}")
    
    def check_nmap_installation(self):
        """Check if Nmap is installed and accessible"""
        self.print_header("Checking Nmap Installation")
        
        # Try to find nmap in PATH
        try:
            result = subprocess.run(['nmap', '--version'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                self.nmap_available = True
                self.nmap_path = 'nmap'
                version_line = result.stdout.split('\n')[0]
                self.print_success(f"Nmap found: {version_line}")
                return True
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        
        # Check common installation paths
        common_paths = [
            r"C:\Program Files (x86)\Nmap\nmap.exe",
            r"C:\Program Files\Nmap\nmap.exe",
            r"C:\nmap\nmap.exe",
            "/usr/bin/nmap",
            "/usr/local/bin/nmap",
            "/opt/nmap/bin/nmap"
        ]
        
        for path in common_paths:
            if os.path.exists(path):
                try:
                    result = subprocess.run([path, '--version'], 
                                          capture_output=True, text=True, timeout=10)
                    if result.returncode == 0:
                        self.nmap_available = True
                        self.nmap_path = path
                        version_line = result.stdout.split('\n')[0]
                        self.print_success(f"Nmap found at {path}: {version_line}")
                        return True
                except (subprocess.TimeoutExpired, FileNotFoundError):
                    continue
        
        self.print_error("Nmap not found. Please install Nmap first.")
        self.print_info("Download from: https://nmap.org/download.html")
        return False
    
    def check_zap_installation(self):
        """Check if ZAP is installed and accessible"""
        self.print_header("Checking ZAP Installation")
        
        # Try to connect to ZAP API
        try:
            response = requests.get(f"{self.zap_url}/JSON/core/view/version/", timeout=5)
            if response.status_code == 200:
                data = response.json()
                version = data.get('version', 'Unknown')
                self.zap_available = True
                self.print_success(f"ZAP API accessible: Version {version}")
                return True
        except requests.exceptions.RequestException as e:
            self.print_error(f"ZAP API not accessible: {e}")
        
        # Check if ZAP is installed
        zap_commands = ['zap.sh', 'zap.bat', 'owasp-zap']
        for cmd in zap_commands:
            try:
                result = subprocess.run([cmd, '--version'], 
                                      capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    self.print_info(f"ZAP found: {cmd}")
                    self.print_info("Please start ZAP with API enabled:")
                    self.print_info("zap.sh -daemon -port 8080 -host 0.0.0.0 -config api.disablekey=true")
                    return False
            except (subprocess.TimeoutExpired, FileNotFoundError):
                continue
        
        self.print_error("ZAP not found. Please install ZAP first.")
        self.print_info("Download from: https://www.zaproxy.org/download/")
        return False
    
    def test_nmap_functionality(self):
        """Test Nmap functionality with a simple scan"""
        if not self.nmap_available:
            return False
        
        self.print_header("Testing Nmap Functionality")
        
        try:
            # Test with localhost ping scan
            cmd = [self.nmap_path, '-sP', '127.0.0.1']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                self.print_success("Nmap ping scan test passed")
                return True
            else:
                self.print_error(f"Nmap test failed: {result.stderr}")
                return False
                
        except subprocess.TimeoutExpired:
            self.print_error("Nmap test timed out")
            return False
        except Exception as e:
            self.print_error(f"Nmap test error: {e}")
            return False
    
    def test_zap_functionality(self):
        """Test ZAP functionality with API calls"""
        if not self.zap_available:
            return False
        
        self.print_header("Testing ZAP Functionality")
        
        try:
            # Test basic API calls
            endpoints = [
                '/JSON/core/view/version/',
                '/JSON/core/view/sites/',
                '/JSON/core/view/urls/'
            ]
            
            for endpoint in endpoints:
                response = requests.get(f"{self.zap_url}{endpoint}", timeout=5)
                if response.status_code == 200:
                    self.print_success(f"ZAP API endpoint {endpoint} working")
                else:
                    self.print_error(f"ZAP API endpoint {endpoint} failed")
                    return False
            
            return True
            
        except Exception as e:
            self.print_error(f"ZAP test error: {e}")
            return False
    
    def test_django_integration(self):
        """Test Django API integration"""
        self.print_header("Testing Django API Integration")
        
        django_url = "http://localhost:8000"
        
        try:
            # Test tools availability endpoint
            response = requests.get(f"{django_url}/api/scan/tools/availability/", timeout=5)
            if response.status_code == 200:
                data = response.json()
                self.print_success("Django API accessible")
                self.print_info(f"Nmap status: {data.get('nmap', {}).get('available', False)}")
                self.print_info(f"ZAP status: {'error' not in data.get('zap', {})}")
                return True
            else:
                self.print_error(f"Django API test failed: {response.status_code}")
                return False
                
        except requests.exceptions.RequestException as e:
            self.print_error(f"Django API not accessible: {e}")
            self.print_info("Make sure Django server is running on localhost:8000")
            return False
    
    def generate_config(self):
        """Generate configuration file"""
        self.print_header("Generating Configuration")
        
        config = {
            "nmap": {
                "available": self.nmap_available,
                "path": self.nmap_path,
                "timeout": 300
            },
            "zap": {
                "available": self.zap_available,
                "url": self.zap_url,
                "api_key": None
            },
            "django": {
                "url": "http://localhost:8000",
                "api_prefix": "/api"
            }
        }
        
        config_file = Path("api_config.json")
        with open(config_file, 'w') as f:
            json.dump(config, f, indent=2)
        
        self.print_success(f"Configuration saved to {config_file}")
        return config
    
    def run_setup(self):
        """Run the complete setup process"""
        self.print_header("PEN-T Framework API Tools Setup")
        
        print("This script will check and configure ZAP and Nmap for API integration.")
        print("No API keys are required - both tools are free and run locally.")
        
        # Check installations
        nmap_ok = self.check_nmap_installation()
        zap_ok = self.check_zap_installation()
        
        # Test functionality
        if nmap_ok:
            self.test_nmap_functionality()
        
        if zap_ok:
            self.test_zap_functionality()
        
        # Test Django integration
        django_ok = self.test_django_integration()
        
        # Generate configuration
        config = self.generate_config()
        
        # Summary
        self.print_header("Setup Summary")
        
        if nmap_ok:
            self.print_success("✅ Nmap: Ready for port scanning")
        else:
            self.print_error("❌ Nmap: Installation required")
        
        if zap_ok:
            self.print_success("✅ ZAP: Ready for vulnerability scanning")
        else:
            self.print_error("❌ ZAP: Installation or startup required")
        
        if django_ok:
            self.print_success("✅ Django API: Ready for integration")
        else:
            self.print_error("❌ Django API: Server not running")
        
        # Next steps
        self.print_header("Next Steps")
        
        if not nmap_ok:
            print("1. Install Nmap:")
            print("   - Windows: Download from https://nmap.org/download.html")
            print("   - macOS: brew install nmap")
            print("   - Linux: sudo apt install nmap")
        
        if not zap_ok:
            print("2. Install and start ZAP:")
            print("   - Download from https://www.zaproxy.org/download/")
            print("   - Start with: zap.sh -daemon -port 8080 -host 0.0.0.0 -config api.disablekey=true")
        
        if not django_ok:
            print("3. Start Django server:")
            print("   - cd backend")
            print("   - python manage.py runserver")
        
        if nmap_ok and zap_ok and django_ok:
            print("🎉 All tools are ready! You can now use the scanning features.")
            print("📖 See docs/API_INTEGRATION_GUIDE.md for usage examples.")
        
        return nmap_ok and zap_ok and django_ok

def main():
    """Main function"""
    setup = APIToolsSetup()
    
    try:
        success = setup.run_setup()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n\nSetup interrupted by user.")
        sys.exit(1)
    except Exception as e:
        print(f"\n\nSetup failed with error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main() 