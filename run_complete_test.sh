#!/bin/bash

# Complete Test Suite for Advanced XSS Scanner
# This script runs the full test suite including the vulnerable app and scanner

echo "=========================================="
echo "    Advanced XSS Scanner - Complete Test"
echo "=========================================="

# Check if Python 3 is installed
if ! command -v python3 &> /dev/null; then
    echo "Error: Python 3 is not installed"
    exit 1
fi

# Install dependencies
echo "Installing dependencies..."
pip3 install -r requirements.txt
pip3 install -r test_requirements.txt

# Make scripts executable
chmod +x advanced_xss_scanner.py
chmod +x test_scanner.py
chmod +x test_vulnerable_app.py

# Run the test suite
echo "Running complete test suite..."
python3 test_scanner.py

# Check if test was successful
if [ $? -eq 0 ]; then
    echo ""
    echo "=========================================="
    echo "    Test completed successfully!"
    echo "=========================================="
    echo ""
    echo "You can now run the scanner on your own targets:"
    echo "  python3 advanced_xss_scanner.py <target_url>"
    echo ""
    echo "Or use the runner script:"
    echo "  ./run_scanner.sh <target_url>"
    echo ""
else
    echo ""
    echo "=========================================="
    echo "    Test failed!"
    echo "=========================================="
    echo ""
    echo "Please check the error messages above and try again."
    echo ""
fi