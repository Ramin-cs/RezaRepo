#!/bin/bash

# Professional Open Redirect Scanner - Dependency Installation Script
# This script installs all necessary dependencies for the scanner

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}🔧 Installing Professional Open Redirect Scanner Dependencies${NC}"
echo "=================================================================="

# Update system packages
echo -e "${YELLOW}📦 Updating system packages...${NC}"
if command -v apt-get &> /dev/null; then
    sudo apt-get update -qq
    sudo apt-get install -y python3 python3-pip python3-venv wget curl unzip
elif command -v yum &> /dev/null; then
    sudo yum update -y
    sudo yum install -y python3 python3-pip wget curl unzip
elif command -v brew &> /dev/null; then
    brew update
    brew install python3 wget curl
else
    echo -e "${RED}❌ Unsupported package manager. Please install Python 3.8+ manually.${NC}"
    exit 1
fi

# Install Google Chrome
echo -e "${YELLOW}🌐 Installing Google Chrome...${NC}"
if ! command -v google-chrome &> /dev/null; then
    if command -v apt-get &> /dev/null; then
        # Ubuntu/Debian
        wget -q -O - https://dl.google.com/linux/linux_signing_key.pub | sudo apt-key add -
        echo "deb [arch=amd64] http://dl.google.com/linux/chrome/deb/ stable main" | sudo tee /etc/apt/sources.list.d/google-chrome.list
        sudo apt-get update -qq
        sudo apt-get install -y google-chrome-stable
    elif command -v yum &> /dev/null; then
        # CentOS/RHEL/Fedora
        sudo yum install -y https://dl.google.com/linux/direct/google-chrome-stable_current_x86_64.rpm
    elif command -v brew &> /dev/null; then
        # macOS
        brew install --cask google-chrome
    else
        echo -e "${YELLOW}⚠️  Please install Google Chrome manually${NC}"
    fi
else
    echo -e "${GREEN}✅ Google Chrome already installed${NC}"
fi

# Create virtual environment
echo -e "${YELLOW}🐍 Setting up Python virtual environment...${NC}"
if [ ! -d "venv" ]; then
    python3 -m venv venv
fi

# Activate virtual environment
source venv/bin/activate

# Upgrade pip
echo -e "${YELLOW}📦 Upgrading pip...${NC}"
pip install --upgrade pip setuptools wheel

# Install Python dependencies
echo -e "${YELLOW}📚 Installing Python dependencies...${NC}"
pip install -r requirements.txt

# Install additional security tools
echo -e "${YELLOW}🔧 Installing additional security tools...${NC}"
pip install webdriver-manager chromedriver-autoinstaller

# Verify installations
echo -e "${YELLOW}🧪 Verifying installations...${NC}"

# Test Python imports
python3 -c "
import sys
print(f'Python version: {sys.version}')

modules = [
    'aiohttp', 'selenium', 'bs4', 'esprima', 'jsbeautifier', 
    'jinja2', 'requests', 'urllib3'
]

for module in modules:
    try:
        __import__(module)
        print(f'✅ {module}')
    except ImportError as e:
        print(f'❌ {module}: {e}')
        sys.exit(1)

print('All Python modules imported successfully!')
"

# Test Chrome WebDriver
echo -e "${YELLOW}🌐 Testing Chrome WebDriver...${NC}"
python3 -c "
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager

try:
    options = Options()
    options.add_argument('--headless')
    options.add_argument('--no-sandbox')
    options.add_argument('--disable-dev-shm-usage')
    
    # Auto-install ChromeDriver
    driver = webdriver.Chrome(ChromeDriverManager().install(), options=options)
    driver.get('data:text/html,<html><body>Test</body></html>')
    print('✅ Chrome WebDriver working correctly')
    driver.quit()
except Exception as e:
    print(f'❌ Chrome WebDriver test failed: {e}')
    exit(1)
"

# Create necessary directories
echo -e "${YELLOW}📁 Creating project directories...${NC}"
mkdir -p logs screenshots reports data bug_bounty_reports temp

# Set permissions
echo -e "${YELLOW}🔐 Setting file permissions...${NC}"
chmod +x enhanced_scanner.py
chmod +x setup.py
chmod +x run_scanner.sh
chmod +x bug_bounty_tester.py

# Create default configuration if it doesn't exist
if [ ! -f "config.json" ]; then
    echo -e "${YELLOW}⚙️  Creating default configuration...${NC}"
    python3 -c "
import json
config = {
    'scanner_settings': {
        'max_depth': 3,
        'max_pages': 200,
        'request_delay': 0.1,
        'timeout': 30
    },
    'payloads': {
        'use_all_payloads': True,
        'custom_domain': 'google.com',
        'test_javascript': True,
        'test_web3': True
    },
    'output': {
        'generate_html_report': True,
        'generate_json_report': True,
        'take_screenshots': True
    }
}
with open('config.json', 'w') as f:
    json.dump(config, f, indent=2)
print('Default configuration created')
    "
fi

echo ""
echo -e "${GREEN}🎉 Installation completed successfully!${NC}"
echo ""
echo -e "${CYAN}📖 Usage Examples:${NC}"
echo "  # Basic scan"
echo "  ./run_scanner.sh https://example.com"
echo ""
echo "  # Advanced scan with custom parameters"
echo "  python3 enhanced_scanner.py https://example.com --depth 4 --verbose"
echo ""
echo "  # Bug bounty testing"
echo "  python3 bug_bounty_tester.py --campaign"
echo ""
echo "  # Run tests"
echo "  python3 test_scanner.py"
echo ""
echo -e "${YELLOW}⚠️  Remember to only test on authorized targets!${NC}"
echo ""

# Deactivate virtual environment
deactivate 2>/dev/null || true