@echo off
echo ========================================
echo    ARAT - Windows Installation Script
echo ========================================
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH
    echo Please install Python 3.8+ from https://www.python.org/downloads/
    echo Make sure to check "Add Python to PATH" during installation
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

REM Install requirements for Windows
echo Installing ARAT dependencies for Windows...
pip install -r requirements_windows.txt
if errorlevel 1 (
    echo.
    echo ERROR: Failed to install some dependencies
    echo Trying alternative installation...
    echo.
    
    REM Try installing packages one by one
    echo Installing core packages...
    pip install fastapi uvicorn pydantic pydantic-settings
    pip install requests aiohttp httpx urllib3
    pip install sqlalchemy pyyaml python-dotenv
    pip install cryptography dnspython
    pip install beautifulsoup4 lxml
    pip install shodan virustotal-api
    pip install tqdm colorama rich loguru
    pip install pandas numpy matplotlib plotly
    pip install flask flask-socketio jinja2
    pip install pytest pytest-asyncio
    pip install click python-dateutil psutil
    
    if errorlevel 1 (
        echo.
        echo ERROR: Failed to install dependencies
        echo Please try installing manually:
        echo pip install fastapi flask sqlalchemy pyyaml requests
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
echo   python main.py --web-panel --port 8080
echo.
echo Or use: start_arat.bat
echo.
pause