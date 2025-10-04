@echo off
echo ========================================
echo    ARAT - Advanced Reconnaissance Tool
echo ========================================
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH
    echo Please install Python 3.8+ from https://www.python.org/downloads/
    pause
    exit /b 1
)

echo Python found: 
python --version

REM Check if requirements are installed
echo.
echo Checking dependencies...
pip show fastapi >nul 2>&1
if errorlevel 1 (
    echo Installing dependencies...
    pip install -r requirements.txt
    if errorlevel 1 (
        echo ERROR: Failed to install dependencies
        pause
        exit /b 1
    )
) else (
    echo Dependencies are already installed
)

REM Start ARAT Web Panel
echo.
echo Starting ARAT Web Panel...
echo.
echo Access the web panel at: http://localhost:8080
echo.
echo Press Ctrl+C to stop the server
echo.

python main.py --web-panel --port 8080

pause