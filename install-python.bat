@echo off
setlocal enabledelayedexpansion

echo 🐍 Installing Python for Pentesting Framework
echo ============================================
echo.

REM Check if Python is already installed
python --version >nul 2>&1
if %errorLevel% == 0 (
    echo ✅ Python is already installed:
    python --version
    echo.
    echo 🚀 Ready to set up virtual environment!
    pause
    exit /b 0
)

echo 📦 Python not found. Installing Python 3.11...
echo.

REM Create temp directory
if not exist "temp" mkdir temp
cd temp

REM Download Python installer
echo 📥 Downloading Python 3.11 installer...
powershell -Command "& {[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -Uri 'https://www.python.org/ftp/python/3.11.8/python-3.11.8-amd64.exe' -OutFile 'python-installer.exe'}"

if not exist "python-installer.exe" (
    echo ❌ Failed to download Python installer
    echo.
    echo 📋 Please install Python manually:
    echo 1. Go to https://www.python.org/downloads/
    echo 2. Download Python 3.11 or later
    echo 3. Run the installer
    echo 4. Make sure to check "Add Python to PATH"
    echo 5. Restart your terminal
    pause
    exit /b 1
)

echo ✅ Python installer downloaded successfully
echo.
echo 🔧 Installing Python...
echo ⚠️ Please follow the installation prompts:
echo - Check "Add Python to PATH"
echo - Choose "Install Now" for standard installation
echo.

REM Run Python installer
python-installer.exe /quiet InstallAllUsers=1 PrependPath=1 Include_test=0

echo.
echo ⏳ Waiting for installation to complete...
timeout /t 10 /nobreak >nul

REM Go back to project directory
cd ..

REM Clean up temp directory
rmdir /s /q temp

echo.
echo 🔍 Verifying Python installation...
python --version >nul 2>&1
if %errorLevel% == 0 (
    echo ✅ Python installed successfully!
    python --version
    echo.
    echo 🚀 Ready to set up virtual environment!
    echo.
    echo 📋 Next steps:
    echo 1. Run: setup-python-venv.bat
    echo 2. Run: start-all.bat
) else (
    echo ❌ Python installation failed
    echo.
    echo 📋 Please install Python manually:
    echo 1. Go to https://www.python.org/downloads/
    echo 2. Download Python 3.11 or later
    echo 3. Run the installer
    echo 4. Make sure to check "Add Python to PATH"
    echo 5. Restart your terminal
)

pause 