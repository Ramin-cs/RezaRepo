#!/bin/bash

# Advanced XSS Scanner Installation Script
# This script installs all dependencies and sets up the XSS scanner

echo "=== Advanced XSS Scanner Installation ==="
echo

# Check Python version
echo "Checking Python version..."
python3 --version
if [ $? -ne 0 ]; then
    echo "Error: Python 3 is not installed!"
    echo "Please install Python 3.8 or higher"
    exit 1
fi

# Check pip
echo "Checking pip..."
pip3 --version
if [ $? -ne 0 ]; then
    echo "Error: pip3 is not installed!"
    echo "Please install pip3"
    exit 1
fi

# Install system dependencies
echo "Installing system dependencies..."
sudo apt update
sudo apt install -y chromium-browser python3-pip python3-venv

# Create virtual environment
echo "Creating virtual environment..."
python3 -m venv xss_scanner_env
source xss_scanner_env/bin/activate

# Install Python dependencies
echo "Installing Python dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

# Install ChromeDriver
echo "Installing ChromeDriver..."
pip install webdriver-manager

# Make scripts executable
echo "Making scripts executable..."
chmod +x xss_scanner.py
chmod +x demo.py
chmod +x test_xss_scanner.py
chmod +x example_usage.py

# Test installation
echo "Testing installation..."
python3 test_xss_scanner.py

echo
echo "=== Installation Complete ==="
echo
echo "To use the XSS scanner:"
echo "1. Activate virtual environment: source xss_scanner_env/bin/activate"
echo "2. Run scanner: python3 xss_scanner.py https://example.com"
echo "3. Run demo: python3 demo.py"
echo "4. Run examples: python3 example_usage.py"
echo
echo "For more information, see README.md"