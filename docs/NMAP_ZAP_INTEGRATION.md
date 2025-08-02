# Nmap and ZAP Integration Guide

## 🎯 Overview

The PEN-T framework now integrates **Nmap** for port scanning and **ZAP (Zed Attack Proxy)** for vulnerability assessment, providing professional-grade security scanning capabilities.

## 🔧 Integration Architecture

### **Backend Services**
- **NmapService**: Handles port scanning with service and OS detection
- **ZAPService**: Manages comprehensive vulnerability assessments
- **Django API**: RESTful endpoints for scan management

### **Frontend Integration**
- **Unified Interface**: Single scanning page with three modes
- **Real-time Monitoring**: Live progress tracking and status updates
- **Result Management**: Comprehensive scan result display and history

## 📊 Scan Modes

### **1. Port Scan (Nmap)**
- **Purpose**: Network reconnaissance and service discovery
- **Tool**: Nmap with service and OS detection
- **Features**:
  - TCP port scanning
  - Service identification
  - Operating system detection
  - Banner grabbing
  - Custom port ranges

### **2. Vulnerability Scan (ZAP)**
- **Purpose**: Web application security assessment
- **Tool**: ZAP with comprehensive vulnerability testing
- **Features**:
  - Spider crawling
  - Active scanning
  - Passive scanning
  - Custom headers support
  - Multiple scan levels

### **3. Comprehensive Scan (Nmap + ZAP)**
- **Purpose**: Complete security assessment
- **Tools**: Both Nmap and ZAP
- **Features**:
  - Port scanning with Nmap
  - Vulnerability assessment with ZAP
  - Combined results display
  - Unified progress tracking

## 🚀 API Endpoints

### **Port Scanning (Nmap)**
```http
POST /api/scan/port/
{
    "target": "example.com",
    "scan_type": "basic",
    "options": {
        "portRange": "1-1000",
        "scanSpeed": "normal",
        "serviceDetection": true,
        "osDetection": true
    }
}
```

### **Vulnerability Scanning (ZAP)**
```http
POST /api/scan/vulnerability/
{
    "target": "example.com",
    "scan_type": "full",
    "options": {
        "zapScanType": "active",
        "zapScanLevel": "medium",
        "zapIncludeContext": true,
        "zapCustomHeaders": ""
    }
}
```

### **Comprehensive Scanning**
```http
POST /api/scan/comprehensive/
{
    "target": "example.com",
    "options": {
        "portRange": "1-1000",
        "scanSpeed": "normal",
        "serviceDetection": true,
        "osDetection": true,
        "zapScanType": "active",
        "zapScanLevel": "medium"
    }
}
```

### **Status and Control**
```http
GET /api/scan/nmap/status/{scan_id}/
GET /api/scan/zap/status/{scan_id}/
POST /api/scan/nmap/cancel/{scan_id}/
POST /api/scan/zap/cancel/{scan_id}/
GET /api/scan/tools/availability/
```

## 🔧 Configuration

### **Nmap Configuration**
```python
# Basic scan with service and OS detection
nmap_options = {
    'scan_type': 'basic',
    'ports': '1-1000',
    'serviceDetection': True,
    'osDetection': True,
    'scanSpeed': 'normal'
}
```

### **ZAP Configuration**
```python
# Comprehensive vulnerability scan
zap_options = {
    'scan_type': 'active',
    'scan_level': 'medium',
    'include_context': True,
    'custom_headers': ''
}
```

## 📋 Requirements

### **System Requirements**
- **Nmap**: Installed and accessible via command line
- **ZAP**: Running in daemon mode with API enabled
- **Python**: 3.8+ with required packages

### **Installation**
```bash
# Install Nmap
# Windows: Download from nmap.org
# Linux: sudo apt-get install nmap
# macOS: brew install nmap

# Install ZAP
# Download from owasp.org/zap
# Run: zap.sh -daemon -port 8080 -config api.disablekey=true
```

### **Python Dependencies**
```bash
pip install requests
pip install subprocess
pip install xml.etree.ElementTree
```

## 🎯 Usage Examples

### **Basic Port Scan**
```javascript
// Frontend
const startPortScan = async () => {
  const response = await fetch('/api/scan/port/', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      target: 'example.com',
      scan_type: 'basic',
      options: {
        portRange: '1-1000',
        serviceDetection: true,
        osDetection: true
      }
    })
  })
  return response.json()
}
```

### **Vulnerability Assessment**
```javascript
// Frontend
const startVulnScan = async () => {
  const response = await fetch('/api/scan/vulnerability/', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      target: 'example.com',
      scan_type: 'full',
      options: {
        zapScanType: 'active',
        zapScanLevel: 'medium'
      }
    })
  })
  return response.json()
}
```

### **Comprehensive Assessment**
```javascript
// Frontend
const startComprehensiveScan = async () => {
  const response = await fetch('/api/scan/comprehensive/', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      target: 'example.com',
      options: {
        portRange: '1-1000',
        serviceDetection: true,
        osDetection: true,
        zapScanType: 'active',
        zapScanLevel: 'medium'
      }
    })
  })
  return response.json()
}
```

## 📊 Result Formats

### **Nmap Port Scan Results**
```json
{
  "type": "port_scan",
  "target": "example.com",
  "open_ports": 5,
  "services": ["HTTP", "HTTPS", "SSH"],
  "os_info": {
    "os": "Linux",
    "version": "3.x",
    "accuracy": "95%"
  },
  "data": [
    {
      "port": 80,
      "state": "open",
      "service": "HTTP",
      "product": "nginx",
      "version": "1.18.0",
      "banner": "HTTP/1.1 200 OK"
    }
  ]
}
```

### **ZAP Vulnerability Scan Results**
```json
{
  "type": "vulnerability_scan",
  "target": "example.com",
  "total_vulnerabilities": 3,
  "high_vulnerabilities": 1,
  "medium_vulnerabilities": 2,
  "low_vulnerabilities": 0,
  "vulnerabilities": [
    {
      "type": "sql_injection",
      "name": "SQL Injection",
      "severity": "high",
      "evidence": "mysql_fetch",
      "url": "http://example.com/?id=1'",
      "payload": "1' OR '1'='1"
    }
  ]
}
```

### **Comprehensive Scan Results**
```json
{
  "type": "comprehensive_scan",
  "target": "example.com",
  "port_scan": {
    "type": "port_scan",
    "open_ports": 5,
    "services": ["HTTP", "HTTPS", "SSH"]
  },
  "vulnerability_scan": {
    "type": "vulnerability_scan",
    "total_vulnerabilities": 3,
    "high_vulnerabilities": 1
  }
}
```

## ⚡ Performance

### **Scan Times**
- **Port Scan (1-1000)**: 30-60 seconds
- **Vulnerability Scan**: 2-5 minutes
- **Comprehensive Scan**: 3-7 minutes

### **Resource Usage**
- **Memory**: 50-200MB per scan
- **CPU**: Moderate usage during active scanning
- **Network**: Varies based on target size

## 🛡️ Security Considerations

### **Legal Compliance**
- **Authorized Testing**: Only scan systems you own or have permission to test
- **Rate Limiting**: Built-in delays to avoid overwhelming targets
- **Responsible Disclosure**: Report vulnerabilities to system owners

### **Best Practices**
- **Test Environment**: Use dedicated test environments
- **Backup Data**: Ensure data backup before scanning
- **Monitoring**: Monitor scan progress and resource usage

## 🔧 Troubleshooting

### **Common Issues**

#### **Nmap Not Found**
```bash
# Check Nmap installation
nmap --version

# Add to PATH if needed
export PATH=$PATH:/usr/local/bin
```

#### **ZAP Connection Failed**
```bash
# Check ZAP daemon status
curl http://localhost:8080/JSON/core/view/version/

# Restart ZAP daemon
zap.sh -daemon -port 8080 -config api.disablekey=true
```

#### **Permission Denied**
```bash
# Run with appropriate permissions
sudo nmap -sS target.com

# Or configure sudo access for specific commands
```

### **Debug Mode**
```python
# Enable debug logging
import logging
logging.basicConfig(level=logging.DEBUG)

# Check service status
nmap_service.check_nmap_availability()
zap_service.check_zap_status()
```

## 📈 Monitoring and Logging

### **Scan Progress**
- **Real-time Updates**: Progress percentage and status
- **Log Files**: Detailed scan logs for debugging
- **Error Handling**: Graceful error recovery

### **Result Storage**
- **localStorage**: Client-side result caching
- **Database**: Optional result persistence
- **Export**: JSON/CSV result export

## 🎯 Future Enhancements

### **Planned Features**
- **Custom Scripts**: User-defined Nmap scripts
- **Advanced ZAP**: Custom scan policies
- **Report Generation**: PDF/HTML reports
- **Integration APIs**: Third-party tool integration

### **Performance Improvements**
- **Parallel Scanning**: Multi-target scanning
- **Caching**: Intelligent result caching
- **Optimization**: Scan parameter optimization

---

**🎉 The Nmap and ZAP integration provides professional-grade security scanning capabilities with a unified, user-friendly interface!** 