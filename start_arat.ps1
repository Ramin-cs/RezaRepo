# ARAT - Advanced Reconnaissance Tool
# PowerShell Startup Script

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "   ARAT - Advanced Reconnaissance Tool" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Check if Python is installed
try {
    $pythonVersion = python --version 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "Python found: $pythonVersion" -ForegroundColor Green
    } else {
        throw "Python not found"
    }
} catch {
    Write-Host "ERROR: Python is not installed or not in PATH" -ForegroundColor Red
    Write-Host "Please install Python 3.8+ from https://www.python.org/downloads/" -ForegroundColor Yellow
    Read-Host "Press Enter to exit"
    exit 1
}

# Check if requirements are installed
Write-Host ""
Write-Host "Checking dependencies..." -ForegroundColor Yellow

try {
    pip show fastapi > $null 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Installing dependencies..." -ForegroundColor Yellow
        pip install -r requirements.txt
        if ($LASTEXITCODE -ne 0) {
            Write-Host "ERROR: Failed to install dependencies" -ForegroundColor Red
            Read-Host "Press Enter to exit"
            exit 1
        }
    } else {
        Write-Host "Dependencies are already installed" -ForegroundColor Green
    }
} catch {
    Write-Host "ERROR: Failed to check dependencies" -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}

# Start ARAT Web Panel
Write-Host ""
Write-Host "Starting ARAT Web Panel..." -ForegroundColor Green
Write-Host ""
Write-Host "Access the web panel at: http://localhost:8080" -ForegroundColor Cyan
Write-Host ""
Write-Host "Press Ctrl+C to stop the server" -ForegroundColor Yellow
Write-Host ""

try {
    python main.py --web-panel --port 8080
} catch {
    Write-Host ""
    Write-Host "Server stopped" -ForegroundColor Yellow
}

Read-Host "Press Enter to exit"