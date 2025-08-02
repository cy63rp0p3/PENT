#!/bin/bash

echo "🚀 Starting Pentesting Framework - Complete Setup"
echo "================================================"
echo ""

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   echo "❌ This script should not be run as root"
   exit 1
fi

echo "📋 Step 1: Checking NMAP installation..."
if command -v nmap &> /dev/null; then
    echo "✅ NMAP is installed and ready"
    nmap --version | head -n 1
else
    echo "❌ NMAP not found. Installing..."
    if [ -f "scripts/setup-scanning-tools.sh" ]; then
        chmod +x scripts/setup-scanning-tools.sh
        ./scripts/setup-scanning-tools.sh
        if [ $? -ne 0 ]; then
            echo "❌ Failed to install NMAP. Please install manually."
            exit 1
        fi
    else
        echo "❌ Setup script not found. Please install NMAP manually."
        exit 1
    fi
fi

echo ""
echo "📋 Step 2: Starting ZAP Daemon..."

# Try different ZAP installation paths
ZAP_PATHS=(
    "/opt/ZAP_2.14.0/zap.sh"
    "/usr/local/bin/zap.sh"
    "zap.sh"
    "$HOME/.local/bin/zap.sh"
)

ZAP_FOUND=false

for zap_path in "${ZAP_PATHS[@]}"; do
    if command -v "$zap_path" >/dev/null 2>&1 || [ -f "$zap_path" ]; then
        echo "✅ Found ZAP at: $zap_path"
        echo "🚀 Starting ZAP daemon on port 8080..."
        
        # Start ZAP in background
        nohup "$zap_path" -daemon -port 8080 -host 0.0.0.0 -config api.disablekey=true > zap.log 2>&1 &
        ZAP_PID=$!
        
        echo "📝 ZAP process started with PID: $ZAP_PID"
        echo "📄 Logs are being written to: zap.log"
        
        ZAP_FOUND=true
        break
    fi
done

if [ "$ZAP_FOUND" = false ]; then
    echo "❌ ZAP not found. Installing..."
    if [ -f "scripts/setup-scanning-tools.sh" ]; then
        chmod +x scripts/setup-scanning-tools.sh
        ./scripts/setup-scanning-tools.sh
        if [ $? -ne 0 ]; then
            echo "❌ Failed to install ZAP. Please install manually."
            exit 1
        fi
        
        # Try again after installation
        for zap_path in "${ZAP_PATHS[@]}"; do
            if command -v "$zap_path" >/dev/null 2>&1 || [ -f "$zap_path" ]; then
                echo "✅ Found ZAP at: $zap_path"
                echo "🚀 Starting ZAP daemon on port 8080..."
                
                nohup "$zap_path" -daemon -port 8080 -host 0.0.0.0 -config api.disablekey=true > zap.log 2>&1 &
                ZAP_PID=$!
                
                echo "📝 ZAP process started with PID: $ZAP_PID"
                echo "📄 Logs are being written to: zap.log"
                
                ZAP_FOUND=true
                break
            fi
        done
    fi
    
    if [ "$ZAP_FOUND" = false ]; then
        echo "❌ ZAP installation failed. Please install manually."
        exit 1
    fi
fi

echo "⏳ Waiting for ZAP to start..."
sleep 10

echo "🔍 Checking ZAP status..."
if curl -s http://localhost:8080/JSON/core/view/version/ >/dev/null 2>&1; then
    echo "✅ ZAP is running successfully on http://localhost:8080"
else
    echo "⚠️ ZAP may still be starting up... continuing anyway"
fi

echo ""
echo "📋 Step 3: Starting Django Backend..."

# Check if Python and Django are available
cd backend

if ! command -v python3 &> /dev/null && ! command -v python &> /dev/null; then
    echo "❌ Python not found. Please install Python 3.8+"
    exit 1
fi

# Use python3 if available, otherwise python
PYTHON_CMD="python3"
if ! command -v python3 &> /dev/null; then
    PYTHON_CMD="python"
fi

# Check if requirements are installed
echo "📦 Installing Python dependencies..."
$PYTHON_CMD -m pip install -r requirements.txt >/dev/null 2>&1

# Run Django migrations
echo "🔄 Running database migrations..."
$PYTHON_CMD manage.py migrate >/dev/null 2>&1

# Start Django server
echo "🚀 Starting Django server on http://localhost:8000..."
nohup $PYTHON_CMD manage.py runserver > django.log 2>&1 &
DJANGO_PID=$!

echo "📝 Django process started with PID: $DJANGO_PID"
echo "📄 Logs are being written to: django.log"

echo "⏳ Waiting for Django to start..."
sleep 5

echo "🔍 Checking Django status..."
if curl -s http://localhost:8000 >/dev/null 2>&1; then
    echo "✅ Django backend is running on http://localhost:8000"
else
    echo "⚠️ Django may still be starting up... continuing anyway"
fi

echo ""
echo "📋 Step 4: Starting Next.js Frontend..."

# Go back to project root
cd ..

# Check if Node.js is available
if ! command -v node &> /dev/null; then
    echo "❌ Node.js not found. Please install Node.js 16+"
    exit 1
fi

# Check if pnpm is available
if ! command -v pnpm &> /dev/null; then
    echo "📦 Installing pnpm..."
    npm install -g pnpm >/dev/null 2>&1
fi

# Install dependencies if needed
if [ ! -d "node_modules" ]; then
    echo "📦 Installing Node.js dependencies..."
    pnpm install >/dev/null 2>&1
fi

# Start Next.js development server
echo "🚀 Starting Next.js frontend on http://localhost:3000..."
nohup pnpm dev > nextjs.log 2>&1 &
NEXTJS_PID=$!

echo "📝 Next.js process started with PID: $NEXTJS_PID"
echo "📄 Logs are being written to: nextjs.log"

echo "⏳ Waiting for Next.js to start..."
sleep 10

echo "🔍 Checking Next.js status..."
if curl -s http://localhost:3000 >/dev/null 2>&1; then
    echo "✅ Next.js frontend is running on http://localhost:3000"
else
    echo "⚠️ Next.js may still be starting up... continuing anyway"
fi

echo ""
echo "🎉 Pentesting Framework is starting up!"
echo "======================================"
echo ""
echo "📊 Services Status:"
echo "✅ NMAP: Ready for port scanning"
echo "✅ ZAP: Running on http://localhost:8080 (PID: $ZAP_PID)"
echo "✅ Django Backend: Running on http://localhost:8000 (PID: $DJANGO_PID)"
echo "✅ Next.js Frontend: Running on http://localhost:3000 (PID: $NEXTJS_PID)"
echo ""
echo "🌐 Access your application at: http://localhost:3000"
echo "📚 API Documentation: http://localhost:8000/api/"
echo "🕷️ ZAP API: http://localhost:8080/JSON/"
echo ""
echo "📄 Log files:"
echo "- ZAP logs: zap.log"
echo "- Django logs: django.log"
echo "- Next.js logs: nextjs.log"
echo ""
echo "🛑 To stop all services:"
echo "kill $ZAP_PID $DJANGO_PID $NEXTJS_PID"
echo ""
echo "📋 Next steps:"
echo "1. Open http://localhost:3000 in your browser"
echo "2. Log in with your credentials"
echo "3. Start performing reconnaissance and vulnerability scans"
echo "" 