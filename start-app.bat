@echo off
setlocal enabledelayedexpansion

echo 🚀 Starting Pentesting Framework - Core Application
echo =================================================
echo.

echo 📋 Step 1: Starting Django Backend with Virtual Environment...

REM Navigate to backend directory
cd backend

REM Check if virtual environment exists
if not exist "venv" (
    echo ❌ Virtual environment not found. Please run setup-python-venv.bat first
    echo.
    echo 📋 To set up the virtual environment:
    echo 1. Go back to project root: cd ..
    echo 2. Run: setup-python-venv.bat
    echo 3. Then run this script again
    pause
    exit /b 1
)

REM Activate virtual environment
echo 🔄 Activating virtual environment...
call venv\Scripts\activate.bat
if %errorLevel% neq 0 (
    echo ❌ Failed to activate virtual environment
    pause
    exit /b 1
)

echo ✅ Virtual environment activated

REM Check if requirements are installed
echo 📦 Checking Python dependencies...
python -c "import django" >nul 2>&1
if %errorLevel% neq 0 (
    echo 📦 Installing Python dependencies...
    pip install -r requirements.txt
    if %errorLevel% neq 0 (
        echo ❌ Failed to install dependencies
        pause
        exit /b 1
    )
) else (
    echo ✅ Dependencies already installed
)

REM Run Django migrations
echo 🔄 Running database migrations...
python manage.py migrate

REM Start Django server
echo 🚀 Starting Django server on http://localhost:8000...
start "Django Backend" cmd /k "cd backend && call venv\Scripts\activate.bat && python manage.py runserver"

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
echo 📋 Step 2: Starting Next.js Frontend...

REM Go back to project root
cd ..

REM Check if Node.js is available
node --version >nul 2>&1
if %errorLevel% neq 0 (
    echo ❌ Node.js not found. Please install Node.js 16+
    echo Download from: https://nodejs.org/
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
echo ✅ Django Backend: Running on http://localhost:8000
echo ✅ Next.js Frontend: Running on http://localhost:3000
echo ⚠️ NMAP: Not installed (optional for port scanning)
echo ⚠️ ZAP: Not installed (optional for vulnerability scanning)
echo.
echo 🌐 Access your application at: http://localhost:3000
echo 📚 API Documentation: http://localhost:8000/api/
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
echo 💡 To install NMAP and ZAP later:
echo - Run: start-all.bat (includes NMAP/ZAP setup)
echo - Or install manually from their official websites
echo.
pause 