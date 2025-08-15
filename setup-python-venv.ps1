# PowerShell script to set up Python Virtual Environment
Write-Host "🐍 Setting up Python Virtual Environment" -ForegroundColor Green
Write-Host "=======================================" -ForegroundColor Green
Write-Host ""

# Check if Python is available
try {
    $pythonVersion = python --version 2>&1
    Write-Host "✅ Python found:" -ForegroundColor Green
    Write-Host $pythonVersion -ForegroundColor Cyan
} catch {
    Write-Host "❌ Python not found. Please install Python 3.8+ first" -ForegroundColor Red
    Write-Host "Download from: https://www.python.org/downloads/" -ForegroundColor Yellow
    Read-Host "Press Enter to exit"
    exit 1
}

# Navigate to backend directory
Set-Location backend

# Check if virtual environment already exists
if (Test-Path "venv") {
    Write-Host "⚠️ Virtual environment already exists at backend\venv" -ForegroundColor Yellow
    $choice = Read-Host "Do you want to recreate it? (y/n)"
    if ($choice -eq "y" -or $choice -eq "Y") {
        Write-Host "🗑️ Removing existing virtual environment..." -ForegroundColor Yellow
        Remove-Item -Recurse -Force venv
    } else {
        Write-Host "✅ Using existing virtual environment" -ForegroundColor Green
        goto :activate_venv
    }
}

Write-Host "🐍 Creating virtual environment..." -ForegroundColor Green
python -m venv venv
if ($LASTEXITCODE -ne 0) {
    Write-Host "❌ Failed to create virtual environment" -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}

:activate_venv
Write-Host "🔄 Activating virtual environment..." -ForegroundColor Green
& "venv\Scripts\Activate.ps1"
if ($LASTEXITCODE -ne 0) {
    Write-Host "❌ Failed to activate virtual environment" -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}

Write-Host "✅ Virtual environment activated successfully" -ForegroundColor Green
Write-Host "📦 Installing Python dependencies..." -ForegroundColor Green

# Upgrade pip first
python -m pip install --upgrade pip

# Install requirements
pip install -r requirements.txt
if ($LASTEXITCODE -ne 0) {
    Write-Host "❌ Failed to install dependencies" -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}

Write-Host "✅ All dependencies installed successfully" -ForegroundColor Green
Write-Host ""
Write-Host "🎉 Virtual environment setup complete!" -ForegroundColor Green
Write-Host "====================================" -ForegroundColor Green
Write-Host ""
Write-Host "📋 To activate the virtual environment manually:" -ForegroundColor Cyan
Write-Host "cd backend" -ForegroundColor White
Write-Host "venv\Scripts\Activate.ps1" -ForegroundColor White
Write-Host ""
Write-Host "📋 To deactivate:" -ForegroundColor Cyan
Write-Host "deactivate" -ForegroundColor White
Write-Host ""
Write-Host "📋 To run Django:" -ForegroundColor Cyan
Write-Host "python manage.py runserver" -ForegroundColor White
Write-Host ""
Write-Host "🚀 Ready to start the application!" -ForegroundColor Green
Read-Host "Press Enter to continue" 