@echo off
REM Quick demo script for Advanced XSS Scanner (Windows)

echo ╔══════════════════════════════════════════════════════════════╗
echo ║                    Advanced XSS Scanner                      ║
echo ║                       Quick Demo                             ║
echo ╚══════════════════════════════════════════════════════════════╝
echo.

REM Check if Python is available
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Python is required but not found!
    pause
    exit /b 1
)

echo 🚀 Starting demo vulnerable server...
start /b python demo.py -p 8080

REM Wait for server to start
timeout /t 3 /nobreak >nul

echo.
echo 🔍 Running XSS Scanner against demo server...
echo Target: http://localhost:8080
echo.

REM Run scanner with demo settings
python advanced_xss_scanner.py -u http://localhost:8080 -d 2 --delay 0.5 -t 3

echo.
echo 🛑 Stopping demo server...
taskkill /f /im python.exe /fi "WINDOWTITLE eq demo.py*" >nul 2>&1

echo ✅ Demo completed!
echo.
echo 📄 Check the generated reports:
echo   • HTML Report: xss_scan_report_*.html
echo   • JSON Report: xss_scan_report_*.json
echo   • Screenshots: screenshots/

pause