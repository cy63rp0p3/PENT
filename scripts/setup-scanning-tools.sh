#!/bin/bash

echo "🔧 Setting up scanning tools for Pentesting Framework"
echo "=================================================="

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   echo "❌ This script should not be run as root"
   exit 1
fi

# Detect OS
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    OS="linux"
elif [[ "$OSTYPE" == "darwin"* ]]; then
    OS="macos"
elif [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "cygwin" ]]; then
    OS="windows"
else
    echo "❌ Unsupported operating system: $OSTYPE"
    exit 1
fi

echo "📋 Detected OS: $OS"

# Install Nmap
echo "🔍 Installing Nmap..."

if [[ "$OS" == "linux" ]]; then
    # Ubuntu/Debian
    if command -v apt-get &> /dev/null; then
        sudo apt-get update
        sudo apt-get install -y nmap
    # CentOS/RHEL/Fedora
    elif command -v yum &> /dev/null; then
        sudo yum install -y nmap
    elif command -v dnf &> /dev/null; then
        sudo dnf install -y nmap
    else
        echo "❌ Package manager not found. Please install Nmap manually."
        exit 1
    fi
elif [[ "$OS" == "macos" ]]; then
    if command -v brew &> /dev/null; then
        brew install nmap
    else
        echo "❌ Homebrew not found. Please install Homebrew first: https://brew.sh/"
        exit 1
    fi
elif [[ "$OS" == "windows" ]]; then
    echo "⚠️  For Windows, please download and install Nmap from: https://nmap.org/download.html"
    echo "   Make sure to add Nmap to your PATH environment variable."
fi

# Verify Nmap installation
if command -v nmap &> /dev/null; then
    echo "✅ Nmap installed successfully: $(nmap --version | head -n 1)"
else
    echo "❌ Nmap installation failed or not found in PATH"
    exit 1
fi

# Install ZAP
echo "🕷️  Installing OWASP ZAP..."

if [[ "$OS" == "linux" ]]; then
    # Download ZAP
    ZAP_VERSION="2.14.0"
    ZAP_URL="https://github.com/zaproxy/zaproxy/releases/download/v${ZAP_VERSION}/ZAP_${ZAP_VERSION}_Linux.tar.gz"
    
    echo "📥 Downloading ZAP v${ZAP_VERSION}..."
    wget -O /tmp/zap.tar.gz "$ZAP_URL"
    
    if [ $? -eq 0 ]; then
        echo "📦 Extracting ZAP..."
        sudo tar -xzf /tmp/zap.tar.gz -C /opt/
        sudo ln -sf /opt/ZAP_${ZAP_VERSION}/zap.sh /usr/local/bin/zap.sh
        
        # Create desktop shortcut
        cat > ~/.local/share/applications/zap.desktop << EOF
[Desktop Entry]
Name=OWASP ZAP
Comment=The OWASP Zed Attack Proxy
Exec=/opt/ZAP_${ZAP_VERSION}/zap.sh
Icon=/opt/ZAP_${ZAP_VERSION}/zap.ico
Terminal=false
Type=Application
Categories=Security;Development;
EOF
        
        echo "✅ ZAP installed successfully in /opt/ZAP_${ZAP_VERSION}/"
    else
        echo "❌ Failed to download ZAP"
        exit 1
    fi
    
elif [[ "$OS" == "macos" ]]; then
    if command -v brew &> /dev/null; then
        brew install --cask owasp-zap
    else
        echo "⚠️  Please download ZAP from: https://www.zaproxy.org/download/"
    fi
elif [[ "$OS" == "windows" ]]; then
    echo "⚠️  For Windows, please download ZAP from: https://www.zaproxy.org/download/"
fi

# Verify ZAP installation
if command -v zap.sh &> /dev/null; then
    echo "✅ ZAP installed successfully"
elif [ -f "/opt/ZAP_*/zap.sh" ]; then
    echo "✅ ZAP installed successfully (use /opt/ZAP_*/zap.sh to run)"
else
    echo "⚠️  ZAP installation may have failed. Please install manually from: https://www.zaproxy.org/download/"
fi

# Install Python dependencies
echo "🐍 Installing Python dependencies..."
cd backend
pip install -r requirements.txt

if [ $? -eq 0 ]; then
    echo "✅ Python dependencies installed successfully"
else
    echo "❌ Failed to install Python dependencies"
    exit 1
fi

# Create ZAP configuration
echo "⚙️  Setting up ZAP configuration..."
mkdir -p ~/.ZAP
cat > ~/.ZAP/zap.conf << EOF
# ZAP Configuration for Pentesting Framework
# API Key for ZAP
api.key=your-secret-api-key-here
# API enabled
api.enabled=true
# API address
api.addr=localhost
# API port
api.port=8080
# API non-ssl
api.nonssl=true
# API disablekey
api.disablekey=false
EOF

echo "✅ ZAP configuration created at ~/.ZAP/zap.conf"
echo "⚠️  Please update the API key in ~/.ZAP/zap.conf"

# Create environment file
echo "🔐 Creating environment configuration..."
cat > backend/.env << EOF
# Pentesting Framework Environment Variables

# ZAP Configuration
ZAP_HOST=localhost
ZAP_PORT=8080
ZAP_API_KEY=your-secret-api-key-here

# Metasploit Configuration
MSF_RPC_HOST=localhost
MSF_RPC_PORT=55553
MSF_RPC_USER=msf
MSF_RPC_PASS=password

# Database Configuration
DATABASE_URL=sqlite:///db.sqlite3

# Security Configuration
SECRET_KEY=your-django-secret-key-here
DEBUG=True
ALLOWED_HOSTS=localhost,127.0.0.1

# Scanning Configuration
SCAN_TIMEOUT=600
MAX_CONCURRENT_SCANS=5
EOF

echo "✅ Environment configuration created at backend/.env"
echo "⚠️  Please update the configuration values in backend/.env"

echo ""
echo "🎉 Setup completed successfully!"
echo ""
echo "📋 Next steps:"
echo "1. Update the API key in ~/.ZAP/zap.conf"
echo "2. Update the configuration in backend/.env"
echo "3. Start ZAP: zap.sh -daemon -port 8080"
echo "4. Run the Django server: python manage.py runserver"
echo "5. Start the Next.js frontend: npm run dev"
echo ""
echo "🔗 Useful links:"
echo "- Nmap documentation: https://nmap.org/docs.html"
echo "- ZAP documentation: https://www.zaproxy.org/docs/"
echo "- Framework documentation: README.md" 