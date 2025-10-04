@echo off
echo ========================================
echo    ARAT - Minimal Installation
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

REM Upgrade pip
echo Upgrading pip...
python -m pip install --upgrade pip
echo.

REM Install minimal requirements
echo Installing minimal ARAT dependencies...
pip install -r requirements_minimal.txt
if errorlevel 1 (
    echo.
    echo ERROR: Failed to install dependencies
    echo Trying individual packages...
    echo.
    
    pip install flask flask-socketio jinja2
    pip install requests httpx
    pip install pyyaml python-dotenv
    pip install sqlalchemy aiosqlite
    pip install click tqdm colorama
    
    if errorlevel 1 (
        echo.
        echo ERROR: Installation failed
        pause
        exit /b 1
    )
)

echo.
echo Creating data directory...
if not exist "data" mkdir data

echo.
echo Installation completed successfully!
echo.
echo To start ARAT:
echo   python main_windows.py --web-panel --port 8080
echo.
pause