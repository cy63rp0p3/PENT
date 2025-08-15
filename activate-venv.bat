@echo off
echo 🐍 Activating Python Virtual Environment
echo ======================================
echo.

REM Navigate to backend directory
cd backend

REM Check if virtual environment exists
if not exist "venv" (
    echo ❌ Virtual environment not found!
    echo.
    echo 📋 To create the virtual environment:
    echo 1. Go back to project root: cd ..
    echo 2. Run: setup-python-venv.bat
    pause
    exit /b 1
)

REM Activate virtual environment
echo 🔄 Activating virtual environment...
call venv\Scripts\activate.bat

if %errorLevel% == 0 (
    echo ✅ Virtual environment activated successfully!
    echo.
    echo 📋 You can now run Django commands:
    echo - python manage.py runserver
    echo - python manage.py migrate
    echo - python manage.py createsuperuser
    echo.
    echo 📋 To deactivate: deactivate
    echo.
    cmd /k
) else (
    echo ❌ Failed to activate virtual environment
    pause
    exit /b 1
) 