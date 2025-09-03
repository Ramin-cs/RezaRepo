#!/bin/bash
# Advanced Web Reconnaissance Tool - Unix/Linux Shell Launcher
# This script launches the reconnaissance tool on Unix-like systems

echo "🔍 Advanced Web Reconnaissance Tool - Unix/Linux"
echo "=============================================="

# Check if Python 3 is installed
if ! command -v python3 &> /dev/null; then
    if ! command -v python &> /dev/null; then
        echo "❌ Python is not installed"
        echo "Please install Python 3.7+ using your package manager"
        exit 1
    else
        PYTHON_CMD="python"
    fi
else
    PYTHON_CMD="python3"
fi

# Check Python version
PYTHON_VERSION=$($PYTHON_CMD -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
REQUIRED_VERSION="3.7"

if [ "$(printf '%s\n' "$REQUIRED_VERSION" "$PYTHON_VERSION" | sort -V | head -n1)" != "$REQUIRED_VERSION" ]; then
    echo "❌ Python 3.7+ is required (found $PYTHON_VERSION)"
    exit 1
fi

# Check if target is provided
if [ $# -eq 0 ]; then
    echo ""
    echo "📋 Usage Examples:"
    echo "  ./run_recon.sh example.com"
    echo "  ./run_recon.sh https://example.com"
    echo "  bash run_recon.sh example.com"
    echo ""
    echo "🔧 Advanced Usage:"
    echo "  $PYTHON_CMD advanced_recon_tool.py -t example.com --threads 100 --verbose"
    exit 1
fi

# Make script executable
chmod +x "$0" 2>/dev/null || true

# Load environment variables from config.env if it exists
if [ -f "config.env" ]; then
    echo "Loading configuration from config.env..."
    export $(grep -v '^#' config.env | xargs)
fi

# Check if dependencies are installed
echo "Checking dependencies..."
$PYTHON_CMD -c "
import sys
try:
    import requests, bs4, dns.resolver, whois
    print('✅ All Python dependencies are installed')
except ImportError as e:
    print(f'❌ Missing dependency: {e}')
    print('Run: $PYTHON_CMD setup.py')
    sys.exit(1)
" || exit 1

# Run the Python launcher
echo "Starting reconnaissance..."
$PYTHON_CMD run_recon.py "$@"

if [ $? -eq 0 ]; then
    echo ""
    echo "✅ Reconnaissance completed successfully!"
    echo "Check the output directory for results"
else
    echo ""
    echo "❌ Tool execution failed"
    echo "Check the error messages above"
    exit 1
fi