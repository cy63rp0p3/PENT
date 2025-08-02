@echo off
setlocal enabledelayedexpansion

echo 🚀 Starting Pentesting Framework - Complete Setup
echo ================================================
echo.

REM Check if running as administrator
net session >nul 2>&1
if %errorLevel% == 0 (
    echo ❌ This script should not be run as administrator
    pause
    exit /b 1
)

echo 📋 Step 1: Checking NMAP installation...
nmap --version >nul 2>&1
if %errorLevel% == 0 (
    echo ✅ NMAP is installed and ready
    nmap --version | findstr "Nmap version"
) else (
    echo ❌ NMAP not found. Installing...
    call scripts\setup-scanning-tools.bat
    if %errorLevel% neq 0 (
        echo ❌ Failed to install NMAP. Please install manually.
        pause
        exit /b 1
    )
)

echo.
echo 📋 Step 2: Starting ZAP Daemon...

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
        goto :zap_started
    )
)

:zap_not_found
echo ❌ ZAP not found. Installing...
call scripts\setup-scanning-tools.bat
if %errorLevel% neq 0 (
    echo ❌ Failed to install ZAP. Please install manually.
    pause
    exit /b 1
)

REM Try again after installation
for %%p in (%ZAP_PATHS%) do (
    if exist "%%p" (
        echo ✅ Found ZAP at: %%p
        echo 🚀 Starting ZAP daemon on port 8080...
        start "ZAP Daemon" "%%p" -daemon -port 8080 -host 0.0.0.0 -config api.disablekey=true
        set ZAP_FOUND=true
        goto :zap_started
    )
)

echo ❌ ZAP installation failed. Please install manually.
pause
exit /b 1

:zap_started
echo ⏳ Waiting for ZAP to start...
timeout /t 10 /nobreak >nul

echo 🔍 Checking ZAP status...
curl -s http://localhost:8080/JSON/core/view/version/ >nul 2>&1
if %errorLevel% == 0 (
    echo ✅ ZAP is running successfully on http://localhost:8080
) else (
    echo ⚠️ ZAP may still be starting up... continuing anyway
)

echo.
echo 📋 Step 3: Starting Django Backend...

REM Check if Python and Django are available
cd backend
python --version >nul 2>&1
if %errorLevel% neq 0 (
    echo ❌ Python not found. Please install Python 3.8+
    pause
    exit /b 1
)

REM Check if requirements are installed
echo 📦 Installing Python dependencies...
pip install -r requirements.txt >nul 2>&1

REM Run Django migrations
echo 🔄 Running database migrations...
python manage.py migrate >nul 2>&1

REM Start Django server
echo 🚀 Starting Django server on http://localhost:8000...
start "Django Backend" python manage.py runserver

echo ⏳ Waiting for Django to start...
timeout /t 5 /nobreak >nul

echo 🔍 Checking Django status...
curl -s http://localhost:8000 >nul 2>&1
if %errorLevel% == 0 (
    echo ✅ Django backend is running on http://localhost:8000
) else (
    echo ⚠️ Django may still be starting up... continuing anyway
)

echo.
echo 📋 Step 4: Starting Next.js Frontend...

REM Go back to project root
cd ..

REM Check if Node.js is available
node --version >nul 2>&1
if %errorLevel% neq 0 (
    echo ❌ Node.js not found. Please install Node.js 16+
    pause
    exit /b 1
)

REM Check if pnpm is available
pnpm --version >nul 2>&1
if %errorLevel% neq 0 (
    echo 📦 Installing pnpm...
    npm install -g pnpm >nul 2>&1
)

REM Install dependencies if needed
if not exist "node_modules" (
    echo 📦 Installing Node.js dependencies...
    pnpm install >nul 2>&1
)

REM Start Next.js development server
echo 🚀 Starting Next.js frontend on http://localhost:3000...
start "Next.js Frontend" pnpm dev

echo ⏳ Waiting for Next.js to start...
timeout /t 10 /nobreak >nul

echo 🔍 Checking Next.js status...
curl -s http://localhost:3000 >nul 2>&1
if %errorLevel% == 0 (
    echo ✅ Next.js frontend is running on http://localhost:3000
) else (
    echo ⚠️ Next.js may still be starting up... continuing anyway
)

echo.
echo 🎉 Pentesting Framework is starting up!
echo ======================================
echo.
echo 📊 Services Status:
echo ✅ NMAP: Ready for port scanning
echo ✅ ZAP: Running on http://localhost:8080
echo ✅ Django Backend: Running on http://localhost:8000
echo ✅ Next.js Frontend: Running on http://localhost:3000
echo.
echo 🌐 Access your application at: http://localhost:3000
echo 📚 API Documentation: http://localhost:8000/api/
echo 🕷️ ZAP API: http://localhost:8080/JSON/
echo.
echo 🛑 To stop all services:
echo - Close the terminal windows for each service
echo - Or use Task Manager to end the processes
echo.
echo 📋 Next steps:
echo 1. Open http://localhost:3000 in your browser
echo 2. Log in with your credentials
echo 3. Start performing reconnaissance and vulnerability scans
echo.
pause 