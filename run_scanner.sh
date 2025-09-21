#!/bin/bash

# Advanced XSS Scanner Runner Script
# This script sets up the environment and runs the XSS scanner

echo "=========================================="
echo "    Advanced XSS Scanner v2.0 Setup"
echo "=========================================="

# Check if Python 3 is installed
if ! command -v python3 &> /dev/null; then
    echo "Error: Python 3 is not installed"
    exit 1
fi

# Check if pip is installed
if ! command -v pip3 &> /dev/null; then
    echo "Error: pip3 is not installed"
    exit 1
fi

# Install dependencies
echo "Installing dependencies..."
pip3 install -r requirements.txt

# Check if Chrome/Chromium is installed
if ! command -v google-chrome &> /dev/null && ! command -v chromium-browser &> /dev/null && ! command -v chromium &> /dev/null; then
    echo "Warning: Chrome/Chromium not found. Screenshot functionality may not work."
    echo "Please install Chrome or Chromium for full functionality."
fi

# Check if chromedriver is available
if ! command -v chromedriver &> /dev/null; then
    echo "Warning: chromedriver not found. Screenshot functionality may not work."
    echo "Please install chromedriver for full functionality."
fi

# Make the script executable
chmod +x advanced_xss_scanner.py

# Check if target URL is provided
if [ $# -eq 0 ]; then
    echo "Usage: $0 <target_url>"
    echo "Example: $0 https://example.com"
    exit 1
fi

# Run the scanner
echo "Starting Advanced XSS Scanner..."
echo "Target: $1"
echo "=========================================="

python3 advanced_xss_scanner.py "$1"