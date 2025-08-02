#!/bin/bash

echo "🕷️ Starting OWASP ZAP Daemon..."
echo "================================"

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
    echo "❌ ZAP not found in common locations"
    echo "📥 Please install ZAP from: https://www.zaproxy.org/download/"
    echo "📋 Or run: ./scripts/setup-scanning-tools.sh"
    exit 1
fi

echo ""
echo "⏳ Waiting for ZAP to start..."
sleep 5

echo "🔍 Checking ZAP status..."
if curl -s http://localhost:8080/JSON/core/view/version/ >/dev/null 2>&1; then
    echo "✅ ZAP is running successfully on http://localhost:8080"
    echo "📊 API is accessible without authentication"
    echo "🛑 To stop ZAP, run: kill $ZAP_PID"
else
    echo "⚠️ ZAP may still be starting up..."
    echo "🔄 Please wait a few more seconds and try accessing: http://localhost:8080"
    echo "📄 Check logs with: tail -f zap.log"
fi

echo ""
echo "📋 Next steps:"
echo "1. Start your Django backend: python manage.py runserver"
echo "2. Start your Next.js frontend: npm run dev"
echo "3. Run vulnerability scans through the web interface"
echo "" 