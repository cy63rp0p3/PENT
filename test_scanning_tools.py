#!/usr/bin/env python3
"""
Test script to verify Nmap and ZAP installation
"""

import subprocess
import sys
import os

def test_nmap():
    """Test if Nmap is working"""
    print("Testing Nmap...")
    try:
        result = subprocess.run(['nmap', '--version'], capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            print("✅ Nmap is working!")
            print(f"Version: {result.stdout.split()[2]}")
            return True
        else:
            print("❌ Nmap failed to run")
            print(f"Error: {result.stderr}")
            return False
    except FileNotFoundError:
        print("❌ Nmap not found in PATH")
        return False
    except Exception as e:
        print(f"❌ Error testing Nmap: {e}")
        return False

def test_zap():
    """Test if ZAP is working"""
    print("\nTesting ZAP...")
    try:
        # Test ZAP version using the batch file
        zap_path = r"zap.bat"
        if not os.path.exists(zap_path):
            print("❌ ZAP batch file not found")
            return False
        
        result = subprocess.run([zap_path, '-version'], capture_output=True, text=True, timeout=30)
        if result.returncode == 0:
            print("✅ ZAP is working!")
            print(f"Version: {result.stdout.strip()}")
            return True
        else:
            print("❌ ZAP failed to run")
            print(f"Error: {result.stderr}")
            return False
    except Exception as e:
        print(f"❌ Error testing ZAP: {e}")
        return False

def test_java():
    """Test if Java 17 is available"""
    print("\nTesting Java...")
    try:
        result = subprocess.run(['java', '-version'], capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            if "17" in result.stderr:
                print("✅ Java 17 is working!")
                print(f"Version: {result.stderr.split()[2]}")
                return True
            else:
                print("❌ Java 17 not found (found different version)")
                print(f"Version: {result.stderr}")
                return False
        else:
            print("❌ Java failed to run")
            return False
    except FileNotFoundError:
        print("❌ Java not found in PATH")
        return False
    except Exception as e:
        print(f"❌ Error testing Java: {e}")
        return False

def main():
    print("🔧 Testing Scanning Tools Installation")
    print("=" * 50)
    
    nmap_ok = test_nmap()
    java_ok = test_java()
    zap_ok = test_zap()
    
    print("\n" + "=" * 50)
    print("📊 Summary:")
    print(f"Nmap: {'✅ Working' if nmap_ok else '❌ Failed'}")
    print(f"Java 17: {'✅ Working' if java_ok else '❌ Failed'}")
    print(f"ZAP: {'✅ Working' if zap_ok else '❌ Failed'}")
    
    if nmap_ok and java_ok and zap_ok:
        print("\n🎉 All tools are working! You can now use the scanning functionality.")
    else:
        print("\n⚠️  Some tools are not working. Please check the installation.")
    
    return nmap_ok and java_ok and zap_ok

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1) 