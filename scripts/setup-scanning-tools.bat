@echo off
setlocal enabledelayedexpansion

echo 🔧 Setting up scanning tools for Pentesting Framework
echo ==================================================

REM Check if running as administrator
net session >nul 2>&1
if %errorLevel% == 0 (
    echo ❌ This script should not be run as administrator
    pause
    exit /b 1
)

echo 📋 Detected OS: Windows

REM Install Nmap using Chocolatey
echo 🔍 Installing Nmap...

REM Check if Chocolatey is installed
where choco >nul 2>&1
if %errorLevel% neq 0 (
    echo 📦 Installing Chocolatey...
    powershell -Command "Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))"
    if %errorLevel% neq 0 (
        echo ❌ Failed to install Chocolatey. Please install manually from: https://chocolatey.org/install
        pause
        exit /b 1
    )
)

REM Install Nmap
choco install nmap -y
if %errorLevel% neq 0 (
    echo ❌ Failed to install Nmap via Chocolatey
    echo ⚠️  Please download and install Nmap from: https://nmap.org/download.html
    echo    Make sure to add Nmap to your PATH environment variable.
)

REM Verify Nmap installation
where nmap >nul 2>&1
if %errorLevel% == 0 (
    echo ✅ Nmap installed successfully
    nmap --version | findstr "Nmap version"
) else (
    echo ❌ Nmap installation failed or not found in PATH
    pause
    exit /b 1
)

REM Install ZAP
echo 🕷️  Installing OWASP ZAP...

REM Download ZAP
set ZAP_VERSION=2.14.0
set ZAP_URL=https://github.com/zaproxy/zaproxy/releases/download/v%ZAP_VERSION%/ZAP_%ZAP_VERSION%_Windows.zip

echo 📥 Downloading ZAP v%ZAP_VERSION%...
powershell -Command "Invoke-WebRequest -Uri '%ZAP_URL%' -OutFile '%TEMP%\zap.zip'"

if %errorLevel% == 0 (
    echo 📦 Extracting ZAP...
    powershell -Command "Expand-Archive -Path '%TEMP%\zap.zip' -DestinationPath 'C:\Program Files' -Force"
    
    REM Add to PATH
    setx PATH "%PATH%;C:\Program Files\ZAP_%ZAP_VERSION%"
    
    echo ✅ ZAP installed successfully in C:\Program Files\ZAP_%ZAP_VERSION%\
) else (
    echo ❌ Failed to download ZAP
    echo ⚠️  Please download ZAP from: https://www.zaproxy.org/download/
)

REM Install Python dependencies
echo 🐍 Installing Python dependencies...
cd backend
pip install -r requirements.txt

if %errorLevel% == 0 (
    echo ✅ Python dependencies installed successfully
) else (
    echo ❌ Failed to install Python dependencies
    pause
    exit /b 1
)

REM Create ZAP configuration
echo ⚙️  Setting up ZAP configuration...
if not exist "%USERPROFILE%\.ZAP" mkdir "%USERPROFILE%\.ZAP"

echo # ZAP Configuration for Pentesting Framework > "%USERPROFILE%\.ZAP\zap.conf"
echo # API Key for ZAP >> "%USERPROFILE%\.ZAP\zap.conf"
echo api.key=your-secret-api-key-here >> "%USERPROFILE%\.ZAP\zap.conf"
echo # API enabled >> "%USERPROFILE%\.ZAP\zap.conf"
echo api.enabled=true >> "%USERPROFILE%\.ZAP\zap.conf"
echo # API address >> "%USERPROFILE%\.ZAP\zap.conf"
echo api.addr=localhost >> "%USERPROFILE%\.ZAP\zap.conf"
echo # API port >> "%USERPROFILE%\.ZAP\zap.conf"
echo api.port=8080 >> "%USERPROFILE%\.ZAP\zap.conf"
echo # API non-ssl >> "%USERPROFILE%\.ZAP\zap.conf"
echo api.nonssl=true >> "%USERPROFILE%\.ZAP\zap.conf"
echo # API disablekey >> "%USERPROFILE%\.ZAP\zap.conf"
echo api.disablekey=false >> "%USERPROFILE%\.ZAP\zap.conf"

echo ✅ ZAP configuration created at %USERPROFILE%\.ZAP\zap.conf
echo ⚠️  Please update the API key in %USERPROFILE%\.ZAP\zap.conf

REM Create environment file
echo 🔐 Creating environment configuration...
echo # Pentesting Framework Environment Variables > backend\.env
echo. >> backend\.env
echo # ZAP Configuration >> backend\.env
echo ZAP_HOST=localhost >> backend\.env
echo ZAP_PORT=8080 >> backend\.env
echo ZAP_API_KEY=your-secret-api-key-here >> backend\.env
echo. >> backend\.env
echo # Metasploit Configuration >> backend\.env
echo MSF_RPC_HOST=localhost >> backend\.env
echo MSF_RPC_PORT=55553 >> backend\.env
echo MSF_RPC_USER=msf >> backend\.env
echo MSF_RPC_PASS=password >> backend\.env
echo. >> backend\.env
echo # Database Configuration >> backend\.env
echo DATABASE_URL=sqlite:///db.sqlite3 >> backend\.env
echo. >> backend\.env
echo # Security Configuration >> backend\.env
echo SECRET_KEY=your-django-secret-key-here >> backend\.env
echo DEBUG=True >> backend\.env
echo ALLOWED_HOSTS=localhost,127.0.0.1 >> backend\.env
echo. >> backend\.env
echo # Scanning Configuration >> backend\.env
echo SCAN_TIMEOUT=600 >> backend\.env
echo MAX_CONCURRENT_SCANS=5 >> backend\.env

echo ✅ Environment configuration created at backend\.env
echo ⚠️  Please update the configuration values in backend\.env

echo.
echo 🎉 Setup completed successfully!
echo.
echo 📋 Next steps:
echo 1. Update the API key in %USERPROFILE%\.ZAP\zap.conf
echo 2. Update the configuration in backend\.env
echo 3. Start ZAP: "C:\Program Files\ZAP_%ZAP_VERSION%\zap.bat" -daemon -port 8080
echo 4. Run the Django server: python manage.py runserver
echo 5. Start the Next.js frontend: npm run dev
echo.
echo 🔗 Useful links:
echo - Nmap documentation: https://nmap.org/docs.html
echo - ZAP documentation: https://www.zaproxy.org/docs/
echo - Framework documentation: README.md

pause 