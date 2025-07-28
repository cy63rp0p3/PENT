# API Integration Guide - ZAP & Nmap

## 🎯 Overview

This guide explains how to set up and use the ZAP and Nmap API integrations for the PEN-T Framework. **No API keys are required** - both tools are free and run locally.

## 🔧 Prerequisites

### Required Tools
- **Python 3.8+**
- **Django 4.0+**
- **Nmap** (for port scanning)
- **ZAP** (for vulnerability scanning)

## 📦 Installation

### 1. Install Nmap

#### Windows:
```bash
# Download from https://nmap.org/download.html
# Or use Chocolatey:
choco install nmap

# Or use winget:
winget install nmap.nmap
```

#### macOS:
```bash
# Using Homebrew
brew install nmap

# Or download from https://nmap.org/download.html
```

#### Linux (Ubuntu/Debian):
```bash
sudo apt update
sudo apt install nmap
```

#### Linux (CentOS/RHEL):
```bash
sudo yum install nmap
# or
sudo dnf install nmap
```

### 2. Install ZAP

#### Windows:
```bash
# Download from https://www.zaproxy.org/download/
# Or use Chocolatey:
choco install owasp-zap
```

#### macOS:
```bash
# Using Homebrew
brew install --cask owasp-zap

# Or download from https://www.zaproxy.org/download/
```

#### Linux:
```bash
# Download from https://www.zaproxy.org/download/
# Extract and run:
./zap.sh
```

### 3. Verify Installation

#### Check Nmap:
```bash
nmap --version
```

#### Check ZAP:
```bash
# Start ZAP
zap.sh  # Linux/macOS
# or
zap.bat  # Windows
```

## 🚀 Setup Instructions

### 1. Start ZAP API

ZAP needs to be running with the API enabled:

#### Method 1: Command Line
```bash
# Start ZAP with API enabled
zap.sh -daemon -port 8080 -host 0.0.0.0 -config api.disablekey=true
```

#### Method 2: GUI Mode
1. Start ZAP
2. Go to **Tools** → **Options** → **API**
3. Set **API Key** to empty (disable authentication)
4. Set **Address** to `0.0.0.0`
5. Set **Port** to `8080`
6. Click **OK**

### 2. Configure Django Settings

Add the following to your Django settings:

```python
# settings.py

# ZAP Configuration
ZAP_URL = "http://localhost:8080"
ZAP_API_KEY = None  # Set to None for no authentication

# Nmap Configuration
NMAP_TIMEOUT = 300  # 5 minutes
NMAP_SCAN_TYPES = ['quick', 'full', 'stealth', 'aggressive']
```

### 3. Install Python Dependencies

```bash
pip install requests
pip install python-nmap  # Optional, for enhanced Nmap support
```

## 🔍 API Endpoints

### Tool Availability Check
```http
GET /api/scan/tools/availability/
```

**Response:**
```json
{
  "nmap": {
    "available": true,
    "version": "Nmap version 7.92",
    "path": "/usr/bin/nmap"
  },
  "zap": {
    "version": "2.12.0"
  },
  "all_available": true
}
```

### Port Scanning
```http
POST /api/scan/port/
Content-Type: application/json

{
  "target": "google.com",
  "scan_type": "quick",
  "options": {
    "portRange": "1-1000",
    "scanSpeed": "normal",
    "serviceDetection": true,
    "osDetection": false,
    "scriptScan": false
  }
}
```

**Response:**
```json
{
  "scan_id": "nmap_scan_1234567890",
  "status": "started",
  "target": "google.com",
  "scan_type": "quick",
  "message": "Scan started successfully"
}
```

### Check Scan Status
```http
GET /api/scan/nmap/status/{scan_id}/
```

**Response:**
```json
{
  "status": "completed",
  "target": "google.com",
  "scan_type": "quick",
  "results": {
    "type": "port_scan",
    "total_ports": 15,
    "open_ports": 3,
    "os_info": {
      "name": "Linux 3.2-4.9",
      "accuracy": "95"
    },
    "data": [...]
  }
}
```

### Vulnerability Scanning
```http
POST /api/scan/vulnerability/
Content-Type: application/json

{
  "target": "https://example.com",
  "scan_type": "active",
  "options": {
    "zapScanType": "active",
    "zapScanLevel": "medium",
    "zapIncludeContext": true
  }
}
```

## 🛠️ Usage Examples

### Python Client Example

```python
import requests

# Check tool availability
response = requests.get('http://localhost:8000/api/scan/tools/availability/')
tools_status = response.json()
print(f"Nmap available: {tools_status['nmap']['available']}")
print(f"ZAP available: {'error' not in tools_status['zap']}")

# Start port scan
scan_data = {
    "target": "google.com",
    "scan_type": "quick",
    "options": {
        "portRange": "80,443,22",
        "serviceDetection": True,
        "osDetection": True
    }
}

response = requests.post('http://localhost:8000/api/scan/port/', json=scan_data)
scan_result = response.json()
scan_id = scan_result['scan_id']

# Check scan progress
import time
while True:
    response = requests.get(f'http://localhost:8000/api/scan/nmap/status/{scan_id}/')
    status = response.json()
    
    if status['status'] == 'completed':
        print("Scan completed!")
        print(f"Open ports: {status['results']['open_ports']}")
        break
    elif status['status'] == 'failed':
        print(f"Scan failed: {status.get('error', 'Unknown error')}")
        break
    
    print(f"Progress: {status.get('progress', 0)}%")
    time.sleep(5)
```

### JavaScript Client Example

```javascript
// Check tool availability
async function checkTools() {
    const response = await fetch('/api/scan/tools/availability/');
    const tools = await response.json();
    
    if (tools.all_available) {
        console.log('All tools are available!');
    } else {
        console.log('Some tools are missing:', tools);
    }
}

// Start port scan
async function startPortScan(target) {
    const scanData = {
        target: target,
        scan_type: 'quick',
        options: {
            portRange: '1-1000',
            serviceDetection: true,
            osDetection: false
        }
    };
    
    const response = await fetch('/api/scan/port/', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(scanData)
    });
    
    const result = await response.json();
    return result.scan_id;
}

// Monitor scan progress
async function monitorScan(scanId) {
    while (true) {
        const response = await fetch(`/api/scan/nmap/status/${scanId}/`);
        const status = await response.json();
        
        if (status.status === 'completed') {
            console.log('Scan completed!', status.results);
            break;
        } else if (status.status === 'failed') {
            console.error('Scan failed:', status.error);
            break;
        }
        
        console.log(`Progress: ${status.progress || 0}%`);
        await new Promise(resolve => setTimeout(resolve, 5000));
    }
}
```

## 🔧 Troubleshooting

### Common Issues

#### 1. Nmap Not Found
**Error:** `Nmap not found. Please install Nmap and ensure it's in your PATH.`

**Solution:**
- Install Nmap from https://nmap.org/download.html
- Add Nmap to your system PATH
- Restart your terminal/IDE

#### 2. ZAP API Not Accessible
**Error:** `ZAP API request failed: Connection refused`

**Solution:**
- Ensure ZAP is running
- Check ZAP is listening on the correct port (default: 8080)
- Verify API is enabled in ZAP settings
- Check firewall settings

#### 3. Permission Denied
**Error:** `Permission denied` when running Nmap

**Solution:**
- On Linux/macOS, you may need to run with sudo for certain scan types
- Use `-sS` (SYN scan) instead of `-sT` (connect scan)
- Or run the application with appropriate privileges

#### 4. Scan Timeout
**Error:** `Nmap scan timed out after 5 minutes`

**Solution:**
- Reduce port range (e.g., `1-100` instead of `1-65535`)
- Use faster scan speed (`-T4` or `-T5`)
- Check network connectivity to target

### Debug Commands

#### Test Nmap Installation
```bash
# Test basic Nmap functionality
nmap -sP 127.0.0.1

# Test with specific options
nmap -sV -p 80,443 google.com
```

#### Test ZAP API
```bash
# Test ZAP API connectivity
curl http://localhost:8080/JSON/core/view/version/

# Test ZAP spider scan
curl -X POST http://localhost:8080/JSON/spider/action/scan/ \
  -d "url=https://example.com"
```

## 📊 Performance Tips

### 1. Optimize Scan Speed
- Use `quick` scan type for initial reconnaissance
- Limit port ranges to commonly used ports
- Use faster timing templates (`-T4` or `-T5`)

### 2. Reduce Resource Usage
- Run scans during off-peak hours
- Limit concurrent scans
- Use appropriate scan types for your needs

### 3. Network Considerations
- Ensure stable network connection
- Consider bandwidth limitations
- Be mindful of target network policies

## 🔒 Security Considerations

### 1. Legal Compliance
- Only scan systems you own or have permission to test
- Respect rate limits and network policies
- Follow responsible disclosure practices

### 2. Network Security
- Run scans from secure, controlled environments
- Use VPN if scanning remote targets
- Monitor for any unintended network impact

### 3. Data Protection
- Secure scan results and reports
- Implement proper access controls
- Follow data retention policies

## 📞 Support

If you encounter issues:

1. **Check the troubleshooting section above**
2. **Verify tool installations**
3. **Review Django logs for errors**
4. **Test API endpoints manually**
5. **Check network connectivity**

For additional help, refer to:
- [Nmap Documentation](https://nmap.org/docs.html)
- [ZAP Documentation](https://www.zaproxy.org/docs/)
- [Django Documentation](https://docs.djangoproject.com/) 