@echo off
echo 🕷️ Starting OWASP ZAP Daemon...
echo ================================

REM Try different ZAP installation paths
set ZAP_PATHS=(
    "C:\Program Files\ZAP_2.14.0\zap.bat"
    "C:\Program Files (x86)\ZAP_2.14.0\zap.bat"
    "C:\Program Files\ZAP\Zed Attack Proxy\zap.bat"
    "C:\Program Files (x86)\ZAP\Zed Attack Proxy\zap.bat"
    "zap.bat"
)

set ZAP_FOUND=false

for %%p in (%ZAP_PATHS%) do (
    if exist "%%p" (
        echo ✅ Found ZAP at: %%p
        echo 🚀 Starting ZAP daemon on port 8080...
        start "ZAP Daemon" "%%p" -daemon -port 8080 -host 0.0.0.0 -config api.disablekey=true
        set ZAP_FOUND=true
        goto :found
    )
)

:not_found
echo ❌ ZAP not found in common locations
echo 📥 Please install ZAP from: https://www.zaproxy.org/download/
echo 📋 Or run: scripts/setup-scanning-tools.bat
pause
exit /b 1

:found
echo.
echo ⏳ Waiting for ZAP to start...
timeout /t 5 /nobreak >nul

echo 🔍 Checking ZAP status...
curl -s http://localhost:8080/JSON/core/view/version/ >nul 2>&1
if %errorLevel% == 0 (
    echo ✅ ZAP is running successfully on http://localhost:8080
    echo 📊 API is accessible without authentication
    echo 🛑 To stop ZAP, close the ZAP Daemon window or kill the process
) else (
    echo ⚠️ ZAP may still be starting up...
    echo 🔄 Please wait a few more seconds and try accessing: http://localhost:8080
)

echo.
echo 📋 Next steps:
echo 1. Start your Django backend: python manage.py runserver
echo 2. Start your Next.js frontend: npm run dev
echo 3. Run vulnerability scans through the web interface
echo.
pause 