@echo off
echo Router Brute Force Chrome v2.0 - Windows Launcher
echo ================================================

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo Error: Python is not installed or not in PATH
    echo Please install Python 3.7+ from https://python.org
    pause
    exit /b 1
)

REM Check if the main script exists
if not exist "router_brute_force_chrome.py" (
    echo Error: router_brute_force_chrome.py not found
    echo Please make sure you're in the correct directory
    pause
    exit /b 1
)

REM Install dependencies if requirements.txt exists
if exist "requirements.txt" (
    echo Installing dependencies...
    python -m pip install -r requirements.txt
    if errorlevel 1 (
        echo Warning: Failed to install some dependencies
        echo You may need to install them manually
    )
)

REM Create screenshots directory
if not exist "screenshots" mkdir screenshots

echo.
echo Router Brute Force Chrome is ready!
echo.
echo Example usage:
echo   python router_brute_force_chrome.py -u http://192.168.1.1
echo.
echo For help:
echo   python router_brute_force_chrome.py --help
echo.

REM Interactive mode
:menu
echo Choose an option:
echo 1. Run with example URL (192.168.1.1)
echo 2. Enter custom URL
echo 3. Show help
echo 4. Exit
echo.
set /p choice="Enter your choice (1-4): "

if "%choice%"=="1" (
    set url=http://192.168.1.1
    goto run
)
if "%choice%"=="2" (
    set /p url="Enter router URL: "
    if not "%url%"=="" goto run
    echo Invalid URL
    goto menu
)
if "%choice%"=="3" (
    python router_brute_force_chrome.py --help
    goto menu
)
if "%choice%"=="4" (
    echo Goodbye!
    exit /b 0
)
echo Invalid choice
goto menu

:run
echo.
echo Running brute force attack on: %url%
echo Chrome browser will open visibly...
echo.
python router_brute_force_chrome.py -u %url%
echo.
echo Attack completed. Check the screenshots folder for results.
pause
goto menu