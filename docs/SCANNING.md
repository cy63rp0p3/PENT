# Security Scanning Documentation

## Overview

The Pentesting Framework includes advanced security scanning capabilities with integration for industry-standard tools:

- **Nmap** for port scanning and network discovery
- **OWASP ZAP** for web application vulnerability scanning
- **Custom scanning engine** for specialized security assessments

## Features

### 🔍 Port Scanning (Nmap Integration)

#### Scan Types
- **Quick Scan** (`-F -sV`): Fast scan of common ports with service detection
- **Full Scan** (`-sS -sV -O`): Comprehensive SYN scan with service and OS detection
- **Stealth Scan** (`-sS`): SYN scan only for stealth operations
- **Aggressive Scan** (`-A -T4`): Aggressive scan with all detection methods

#### Advanced Options
- **Port Range**: Custom port ranges (e.g., "1-1000", "80,443,8080")
- **Scan Speed**: T0 (slow) to T5 (aggressive)
- **Service Detection**: Enable/disable service version detection
- **OS Detection**: Enable/disable operating system detection
- **Script Scan**: Enable NSE (Nmap Scripting Engine) scans

### 🛡️ Vulnerability Scanning (ZAP Integration)

#### Scan Types
- **Basic Scan**: Spider crawl with passive vulnerability detection
- **Full Scan**: Active vulnerability scanning with automated attacks
- **API Scan**: Specialized scanning for API endpoints
- **Custom Scan**: User-defined scanning parameters

#### ZAP Features
- **Spider Crawling**: Automatic discovery of web application pages
- **Active Scanning**: Automated vulnerability testing
- **Passive Scanning**: Non-intrusive vulnerability detection
- **API Testing**: REST/GraphQL API security assessment
- **Authentication Support**: Session-based authenticated scanning

## Installation

### Prerequisites
- Python 3.8+
- Node.js 16+
- Nmap (will be installed by setup script)
- OWASP ZAP (will be installed by setup script)

### Quick Setup

#### Windows
```batch
scripts\setup-scanning-tools.bat
```

#### Linux/macOS
```bash
chmod +x scripts/setup-scanning-tools.sh
./scripts/setup-scanning-tools.sh
```

### Manual Installation

#### Nmap
- **Windows**: Download from [nmap.org](https://nmap.org/download.html)
- **Linux**: `sudo apt-get install nmap` (Ubuntu/Debian)
- **macOS**: `brew install nmap`

#### OWASP ZAP
- **All Platforms**: Download from [zaproxy.org](https://www.zaproxy.org/download/)

## Configuration

### Environment Variables

Create `backend/.env` file:

```env
# ZAP Configuration
ZAP_HOST=localhost
ZAP_PORT=8080
ZAP_API_KEY=your-secret-api-key-here

# Metasploit Configuration
MSF_RPC_HOST=localhost
MSF_RPC_PORT=55553
MSF_RPC_USER=msf
MSF_RPC_PASS=password

# Scanning Configuration
SCAN_TIMEOUT=600
MAX_CONCURRENT_SCANS=5
```

### ZAP Configuration

Create `~/.ZAP/zap.conf`:

```conf
# ZAP Configuration for Pentesting Framework
api.key=your-secret-api-key-here
api.enabled=true
api.addr=localhost
api.port=8080
api.nonssl=true
api.disablekey=false
```

## Usage

### Starting the Services

1. **Start ZAP in daemon mode**:
   ```bash
   zap.sh -daemon -port 8080
   ```

2. **Start Django backend**:
   ```bash
   cd backend
   python manage.py runserver
   ```

3. **Start Next.js frontend**:
   ```bash
   npm run dev
   ```

### Using the Scanning Interface

#### Port Scanning
1. Navigate to **Scanning** page
2. Select **Port** scan mode
3. Enter target IP/hostname
4. Choose scan type (Quick, Full, Stealth, Aggressive)
5. Configure advanced options if needed
6. Click **Start Port Scan**

#### Vulnerability Scanning
1. Navigate to **Scanning** page
2. Select **Vulnerability** scan mode
3. Enter target URL
4. Choose scan type (Basic, Full, API, Custom)
5. Configure advanced options if needed
6. Click **Start Vulnerability Scan**

## API Endpoints

### Port Scanning
```http
POST /api/scan/port/
Content-Type: application/json

{
  "target": "192.168.1.1",
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

### Vulnerability Scanning
```http
POST /api/scan/vulnerability/
Content-Type: application/json

{
  "target": "https://example.com",
  "scan_type": "full",
  "options": {
    "spiderDepth": 10,
    "activeScan": true,
    "apiScan": false
  }
}
```

### Progress Tracking
```http
GET /api/recon/progress/{scan_id}/
```

### Cancel Scan
```http
POST /api/recon/cancel/{scan_id}/
```

## Scan Results

### Port Scan Results
```json
{
  "type": "port_scan",
  "target": "192.168.1.1",
  "scan_type": "quick",
  "total_ports": 15,
  "open_ports": 3,
  "data": [
    {
      "port": 22,
      "protocol": "tcp",
      "state": "open",
      "service": "ssh",
      "version": "OpenSSH 8.2"
    }
  ]
}
```

### Vulnerability Scan Results
```json
{
  "type": "vulnerability_scan",
  "target": "https://example.com",
  "scan_type": "full",
  "total_vulnerabilities": 5,
  "critical_count": 1,
  "high_count": 2,
  "medium_count": 1,
  "low_count": 1,
  "data": [
    {
      "id": "10020",
      "title": "XSS Reflected",
      "description": "Cross-site scripting vulnerability",
      "severity": "high",
      "url": "https://example.com/search?q=test",
      "evidence": "<script>alert('xss')</script>"
    }
  ]
}
```

## Security Considerations

### Legal and Ethical
- **Authorized Testing Only**: Only scan systems you own or have explicit permission to test
- **Compliance**: Ensure compliance with local laws and regulations
- **Documentation**: Maintain proper documentation of testing scope and authorization

### Technical Security
- **Network Isolation**: Run scans in isolated environments when possible
- **Rate Limiting**: Implement appropriate rate limiting to avoid overwhelming targets
- **Logging**: Maintain comprehensive logs of all scanning activities
- **Access Control**: Restrict access to scanning tools and results

### Best Practices
- **Incremental Testing**: Start with non-intrusive scans before aggressive testing
- **Backup Systems**: Ensure target systems are backed up before testing
- **Monitoring**: Monitor target systems during scanning for unexpected behavior
- **Reporting**: Generate detailed reports for all findings

## Troubleshooting

### Common Issues

#### Nmap Not Found
```bash
# Check if Nmap is installed
nmap --version

# Add to PATH if needed
export PATH=$PATH:/usr/local/bin
```

#### ZAP Connection Failed
```bash
# Check if ZAP is running
curl http://localhost:8080/JSON/core/view/version/

# Start ZAP manually
zap.sh -daemon -port 8080
```

#### Permission Denied
```bash
# For Linux/macOS, ensure proper permissions
sudo chmod +x /usr/local/bin/nmap
sudo chmod +x /usr/local/bin/zap.sh
```

### Debug Mode

Enable debug logging in Django:

```python
# settings.py
DEBUG = True
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
        },
    },
    'loggers': {
        'django': {
            'handlers': ['console'],
            'level': 'DEBUG',
        },
    },
}
```

## Advanced Configuration

### Custom Nmap Scripts
```bash
# Create custom NSE scripts
mkdir -p ~/.nmap/scripts
# Add your custom scripts here
```

### ZAP Add-ons
```bash
# Install additional ZAP add-ons
# Access ZAP Marketplace through the GUI
```

### Performance Tuning
```python
# Adjust scan timeouts and concurrency
SCAN_TIMEOUT = 1200  # 20 minutes
MAX_CONCURRENT_SCANS = 3
```

## Contributing

### Adding New Scan Types
1. Extend the backend scanning functions
2. Add corresponding frontend UI components
3. Update API documentation
4. Add tests for new functionality

### Custom Integrations
1. Create new scanning modules in `backend/api/views.py`
2. Add configuration options
3. Implement progress tracking
4. Add result parsing and formatting

## Support

### Documentation
- [Nmap Documentation](https://nmap.org/docs.html)
- [ZAP Documentation](https://www.zaproxy.org/docs/)
- [Framework Documentation](README.md)

### Community
- GitHub Issues: [Report bugs and feature requests](https://github.com/your-repo/issues)
- Discussions: [Community forum](https://github.com/your-repo/discussions)

### Professional Support
For enterprise support and custom integrations, contact the development team. 