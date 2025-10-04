@echo off
echo ========================================
echo    ARAT - Simple Start for Windows
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

REM Test installation
echo Testing installation...
python test_installation.py
if errorlevel 1 (
    echo.
    echo Installing missing packages...
    pip install fastapi flask sqlalchemy pyyaml requests
    pip install flask-socketio jinja2 tqdm colorama
)

echo.
echo Starting ARAT Web Panel...
echo.
echo Access the web panel at: http://localhost:8080
echo.
echo Press Ctrl+C to stop the server
echo.

python main_windows.py --web-panel --port 8080

pause