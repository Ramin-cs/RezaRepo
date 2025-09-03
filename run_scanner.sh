#!/bin/bash

# Professional Open Redirect Scanner Launcher
# This script sets up the environment and runs the scanner with proper configuration

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Banner
echo -e "${PURPLE}"
echo "╔═══════════════════════════════════════════════════════════════════╗"
echo "║                                                                   ║"
echo "║    🔍 Professional Open Redirect Vulnerability Scanner 🔍        ║"
echo "║                                                                   ║"
echo "║    Advanced Web Security Assessment Tool                          ║"
echo "║    ✓ Deep Crawling  ✓ JS Analysis  ✓ Web3 Support              ║"
echo "║                                                                   ║"
echo "╚═══════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Check if target URL is provided
if [ $# -eq 0 ]; then
    echo -e "${RED}❌ Error: No target URL provided${NC}"
    echo -e "${YELLOW}Usage: $0 <target_url> [options]${NC}"
    echo ""
    echo -e "${CYAN}Examples:${NC}"
    echo "  $0 https://example.com"
    echo "  $0 example.com --depth 4 --max-pages 300"
    echo "  $0 https://dapp.example.com --web3-mode --verbose"
    echo ""
    exit 1
fi

TARGET_URL=$1
shift

# Default options
DEPTH=3
MAX_PAGES=200
OUTPUT_DIR="./reports"
VERBOSE=false
WEB3_MODE=false

# Parse additional arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --depth)
            DEPTH="$2"
            shift 2
            ;;
        --max-pages)
            MAX_PAGES="$2"
            shift 2
            ;;
        --output-dir)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        --verbose|-v)
            VERBOSE=true
            shift
            ;;
        --web3-mode)
            WEB3_MODE=true
            shift
            ;;
        --help|-h)
            echo -e "${CYAN}Professional Open Redirect Scanner${NC}"
            echo ""
            echo -e "${YELLOW}Usage:${NC} $0 <target_url> [options]"
            echo ""
            echo -e "${YELLOW}Options:${NC}"
            echo "  --depth DEPTH         Maximum crawling depth (default: 3)"
            echo "  --max-pages PAGES     Maximum pages to crawl (default: 200)"
            echo "  --output-dir DIR      Output directory for reports (default: ./reports)"
            echo "  --verbose, -v         Enable verbose logging"
            echo "  --web3-mode          Enable enhanced Web3 detection"
            echo "  --help, -h           Show this help message"
            echo ""
            echo -e "${YELLOW}Examples:${NC}"
            echo "  $0 https://example.com"
            echo "  $0 example.com --depth 4 --max-pages 300 --verbose"
            echo "  $0 https://dapp.example.com --web3-mode"
            echo ""
            exit 0
            ;;
        *)
            echo -e "${RED}❌ Unknown option: $1${NC}"
            exit 1
            ;;
    esac
done

# Validate target URL
if [[ ! $TARGET_URL =~ ^https?:// ]]; then
    TARGET_URL="https://$TARGET_URL"
    echo -e "${YELLOW}ℹ️  Added HTTPS protocol to target URL: $TARGET_URL${NC}"
fi

# Create output directory
mkdir -p "$OUTPUT_DIR"
mkdir -p "./screenshots"
mkdir -p "./logs"
mkdir -p "./data"

# Pre-flight checks
echo -e "${BLUE}🔍 Pre-flight Checks${NC}"

# Check Python installation
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}❌ Python 3 not found. Please install Python 3.8+${NC}"
    exit 1
fi
echo -e "${GREEN}✅ Python 3 found${NC}"

# Check if requirements are installed
echo -e "${BLUE}📦 Checking dependencies...${NC}"
if ! python3 -c "import aiohttp, selenium, bs4" 2>/dev/null; then
    echo -e "${YELLOW}⚠️  Installing missing dependencies...${NC}"
    python3 -m pip install -r requirements.txt
fi
echo -e "${GREEN}✅ Dependencies verified${NC}"

# Check Chrome installation
echo -e "${BLUE}🌐 Checking Chrome WebDriver...${NC}"
if ! python3 -c "from selenium import webdriver; from selenium.webdriver.chrome.options import Options; options = Options(); options.add_argument('--headless'); driver = webdriver.Chrome(options=options); driver.quit()" 2>/dev/null; then
    echo -e "${YELLOW}⚠️  Setting up Chrome WebDriver...${NC}"
    python3 -c "from webdriver_manager.chrome import ChromeDriverManager; ChromeDriverManager().install()"
fi
echo -e "${GREEN}✅ Chrome WebDriver ready${NC}"

# Display scan configuration
echo ""
echo -e "${CYAN}🎯 Scan Configuration${NC}"
echo -e "Target URL:     ${YELLOW}$TARGET_URL${NC}"
echo -e "Max Depth:      ${YELLOW}$DEPTH${NC}"
echo -e "Max Pages:      ${YELLOW}$MAX_PAGES${NC}"
echo -e "Output Dir:     ${YELLOW}$OUTPUT_DIR${NC}"
echo -e "Verbose Mode:   ${YELLOW}$VERBOSE${NC}"
echo -e "Web3 Mode:      ${YELLOW}$WEB3_MODE${NC}"
echo ""

# Confirm before starting
read -p "$(echo -e ${CYAN}Continue with scan? [Y/n]: ${NC})" -n 1 -r
echo
if [[ $REPLY =~ ^[Nn]$ ]]; then
    echo -e "${YELLOW}🛑 Scan cancelled by user${NC}"
    exit 0
fi

# Start the scan
echo ""
echo -e "${GREEN}🚀 Starting Professional Open Redirect Scan...${NC}"
echo ""

# Build command
SCANNER_CMD="python3 enhanced_scanner.py \"$TARGET_URL\" --depth $DEPTH --max-pages $MAX_PAGES"

if [ "$VERBOSE" = true ]; then
    SCANNER_CMD="$SCANNER_CMD --verbose"
fi

if [ "$WEB3_MODE" = true ]; then
    SCANNER_CMD="$SCANNER_CMD --web3-mode"
fi

# Add output file with timestamp
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
OUTPUT_FILE="${OUTPUT_DIR}/scan_${TIMESTAMP}.html"
SCANNER_CMD="$SCANNER_CMD --output \"$OUTPUT_FILE\""

# Run the scanner
echo -e "${BLUE}Executing: $SCANNER_CMD${NC}"
echo ""

if eval $SCANNER_CMD; then
    echo ""
    echo -e "${GREEN}🎉 Scan completed successfully!${NC}"
    echo ""
    echo -e "${CYAN}📊 Results Available:${NC}"
    echo -e "   📄 HTML Report:    $OUTPUT_FILE"
    echo -e "   💾 JSON Data:      ./enhanced_parameters.json"
    echo -e "   📈 CSV Export:     ./parameters_analysis.csv"
    echo -e "   📸 Screenshots:    ./screenshots/"
    echo -e "   📋 Logs:          ./logs/enhanced_scanner.log"
    echo ""
    
    # Check if vulnerabilities were found
    if python3 -c "
import json
try:
    with open('enhanced_parameters.json', 'r') as f:
        data = json.load(f)
        vulns = len(data.get('vulnerabilities', []))
        if vulns > 0:
            print('VULNERABILITIES_FOUND')
        else:
            print('NO_VULNERABILITIES')
except:
    print('UNKNOWN')
" | grep -q "VULNERABILITIES_FOUND"; then
        echo -e "${RED}🚨 VULNERABILITIES DETECTED! 🚨${NC}"
        echo -e "${YELLOW}Please review the detailed report for security findings.${NC}"
    else
        echo -e "${GREEN}✅ No vulnerabilities detected in this scan.${NC}"
    fi
    
    echo ""
    echo -e "${PURPLE}📖 Next Steps:${NC}"
    echo "1. Review the HTML report for detailed findings"
    echo "2. Analyze the parameter data for manual testing"
    echo "3. Verify any vulnerabilities found"
    echo "4. Implement recommended security measures"
    echo ""
    
else
    echo ""
    echo -e "${RED}❌ Scan failed. Check the logs for details.${NC}"
    echo -e "${YELLOW}Log file: ./logs/enhanced_scanner.log${NC}"
    exit 1
fi