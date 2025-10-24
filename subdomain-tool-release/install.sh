#!/bin/bash

# Quick Installation Script for Subdomain Enumeration Tool v2.0
# Author: Security Researcher
# Version: 2.0.0

echo "🔍 Advanced Subdomain Enumeration Tool v2.0 - Quick Install"
echo "=========================================================="

# Check if Python 3 is installed
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is not installed. Please install Python 3.7+ first."
    exit 1
fi

# Check Python version
python_version=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
required_version="3.7"

if [ "$(printf '%s\n' "$required_version" "$python_version" | sort -V | head -n1)" != "$required_version" ]; then
    echo "❌ Python $required_version+ is required. Found: $python_version"
    exit 1
fi

echo "✅ Python $python_version found"

# Install requirements
echo "📦 Installing Python dependencies..."
pip3 install -r requirements.txt

if [ $? -eq 0 ]; then
    echo "✅ Dependencies installed successfully"
else
    echo "❌ Failed to install dependencies"
    exit 1
fi

# Check if nmap is installed
if command -v nmap &> /dev/null; then
    echo "✅ Nmap found - advanced network scanning enabled"
else
    echo "⚠️  Nmap not found - using alternative scanning methods"
    echo "   Install nmap for enhanced network scanning:"
    echo "   - Ubuntu/Debian: sudo apt install nmap"
    echo "   - CentOS/RHEL: sudo yum install nmap"
    echo "   - macOS: brew install nmap"
fi

# Create config file if it doesn't exist
if [ ! -f "config.py" ]; then
    echo "📝 Creating config.py from template..."
    cp config.py.example config.py
    echo "✅ Config file created. Edit config.py to add your API keys."
else
    echo "✅ Config file already exists"
fi

# Make scripts executable
chmod +x subdomains.py test.py

echo ""
echo "🎉 Installation completed successfully!"
echo ""
echo "📖 Quick Start:"
echo "   python3 subdomains.py -d example.com"
echo ""
echo "📖 Test the installation:"
echo "   python3 test.py"
echo ""
echo "📖 Check API configuration:"
echo "   python3 subdomains.py --show-apis"
echo ""
echo "📖 View help:"
echo "   python3 subdomains.py --help"
echo ""
echo "🔑 Don't forget to configure your API keys in config.py for enhanced discovery!"
echo ""
echo "Happy hunting! 🎯"