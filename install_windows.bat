@echo off
echo 🚀 ARAT Cross-Platform Installer for Windows
echo ================================================

REM Check if running as administrator
net session >nul 2>&1
if %errorLevel% == 0 (
    echo ✅ Running as administrator
) else (
    echo ❌ Please run as administrator
    pause
    exit /b 1
)

echo.
echo 📦 Installing system requirements...

REM Install Chocolatey if not present
where choco >nul 2>&1
if %errorLevel% neq 0 (
    echo 📦 Installing Chocolatey package manager...
    powershell -Command "Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))"
    if %errorLevel% neq 0 (
        echo ❌ Failed to install Chocolatey
        pause
        exit /b 1
    )
)

REM Install required tools via Chocolatey
echo 📦 Installing Git...
choco install git -y

echo 📦 Installing Go...
choco install golang -y

echo 📦 Installing Python...
choco install python -y

echo 📦 Installing pip...
python -m ensurepip --upgrade

echo.
echo 🐍 Installing Python packages...
pip install sublist3r python-whois

echo.
echo 🔧 Installing Go tools...
set GOPATH=%USERPROFILE%\go
set PATH=%PATH%;%GOPATH%\bin

go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/OJ/gobuster/v3@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/projectdiscovery/gospider/cmd/gospider@latest

echo.
echo 🔧 Setting up environment variables...
setx PATH "%PATH%;%USERPROFILE%\go\bin;%USERPROFILE%\.local\bin" /M

echo.
echo 🔍 Verifying installation...
where git
where go
where python
where pip
where sublist3r
where subfinder
where httpx
where gobuster

echo.
echo 🎉 Installation completed!
echo 🔄 Please restart your command prompt for PATH changes to take effect.
echo.
pause