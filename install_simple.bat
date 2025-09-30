@echo off
echo ========================================
echo    ARAT - Simple Installation
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
echo.

REM Install simple requirements
echo Installing ARAT dependencies...
pip install -r requirements_simple.txt
if errorlevel 1 (
    echo.
    echo ERROR: Failed to install dependencies
    echo Trying individual packages...
    echo.
    
    pip install flask flask-socketio jinja2
    pip install requests pyyaml
    pip install click tqdm colorama
    
    if errorlevel 1 (
        echo.
        echo ERROR: Installation failed
        pause
        exit /b 1
    )
)

echo.
echo Installation completed successfully!
echo.
echo To start ARAT:
echo   python main_simple.py --web-panel --port 8080
echo.
pause