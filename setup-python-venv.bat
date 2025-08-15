@echo off
setlocal enabledelayedexpansion

echo 🐍 Setting up Python Virtual Environment
echo =======================================
echo.

REM Check if Python is available
python --version >nul 2>&1
if %errorLevel% neq 0 (
    echo ❌ Python not found. Please install Python 3.8+ first
    echo Download from: https://www.python.org/downloads/
    pause
    exit /b 1
)

echo ✅ Python found:
python --version

REM Navigate to backend directory
cd backend

REM Check if virtual environment already exists
if exist "venv" (
    echo ⚠️ Virtual environment already exists at backend\venv
    echo Do you want to recreate it? (y/n)
    set /p choice=
    if /i "!choice!"=="y" (
        echo 🗑️ Removing existing virtual environment...
        rmdir /s /q venv
    ) else (
        echo ✅ Using existing virtual environment
        goto :activate_venv
    )
)

echo 🐍 Creating virtual environment...
python -m venv venv
if %errorLevel% neq 0 (
    echo ❌ Failed to create virtual environment
    pause
    exit /b 1
)

:activate_venv
echo 🔄 Activating virtual environment...
call venv\Scripts\activate.bat
if %errorLevel% neq 0 (
    echo ❌ Failed to activate virtual environment
    pause
    exit /b 1
)

echo ✅ Virtual environment activated successfully
echo 📦 Installing Python dependencies...

REM Upgrade pip first
python -m pip install --upgrade pip

REM Install requirements
pip install -r requirements.txt
if %errorLevel% neq 0 (
    echo ❌ Failed to install dependencies
    pause
    exit /b 1
)

echo ✅ All dependencies installed successfully
echo.
echo 🎉 Virtual environment setup complete!
echo ====================================
echo.
echo 📋 To activate the virtual environment manually:
echo cd backend
echo venv\Scripts\activate.bat
echo.
echo 📋 To deactivate:
echo deactivate
echo.
echo 📋 To run Django:
echo python manage.py runserver
echo.
echo 🚀 Ready to start the application!
pause 