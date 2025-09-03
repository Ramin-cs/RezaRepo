@echo off
REM Advanced Web Reconnaissance Tool - Windows Batch Launcher
REM This script launches the reconnaissance tool on Windows

echo 🔍 Advanced Web Reconnaissance Tool - Windows
echo ==========================================

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo ❌ Python is not installed or not in PATH
    echo Please install Python 3.7+ from https://python.org
    pause
    exit /b 1
)

REM Check if target is provided
if "%1"=="" (
    echo.
    echo 📋 Usage Examples:
    echo   run_recon.bat example.com
    echo   run_recon.bat https://example.com
    echo.
    echo 🔧 Advanced Usage:
    echo   python advanced_recon_tool.py -t example.com --threads 100 --verbose
    pause
    exit /b 1
)

REM Load environment variables from config.env if it exists
if exist config.env (
    echo Loading configuration from config.env...
    for /f "tokens=1,2 delims==" %%a in (config.env) do (
        if not "%%a"=="" if not "%%a"=="#" set %%a=%%b
    )
)

REM Run the Python launcher
python run_recon.py %*

if errorlevel 1 (
    echo.
    echo ❌ Tool execution failed
    echo Check the error messages above
    pause
    exit /b 1
)

echo.
echo ✅ Reconnaissance completed successfully!
echo Check the output directory for results
pause