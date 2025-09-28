#!/bin/bash

# Open Redirect Scanner - Run Script
# This script provides easy ways to run the scanner

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_color() {
    local color=$1
    local message=$2
    echo -e "${color}${message}${NC}"
}

# Function to print banner
print_banner() {
    print_color $BLUE "
    ╔══════════════════════════════════════════════════════════════╗
    ║                                                              ║
    ║           🔍 Open Redirect Vulnerability Scanner            ║
    ║                                                              ║
    ║              Advanced Security Testing Tool                  ║
    ║                                                              ║
    ╚══════════════════════════════════════════════════════════════╝
    "
}

# Function to show usage
show_usage() {
    print_color $YELLOW "
    Usage: $0 [OPTIONS] <target_url>
    
    Options:
        -h, --help              Show this help message
        -v, --version           Show version information
        -i, --install           Install dependencies
        -t, --test              Run test scan
        -c, --config FILE       Use configuration file
        -p, --preset PRESET     Use preset configuration (fast|thorough|stealth|debug)
        -o, --output DIR        Output directory (default: scan_results)
        -j, --threads NUM       Number of threads (default: 10)
        -d, --depth NUM         Maximum depth (default: 3)
        --timeout NUM           Request timeout in seconds (default: 30)
        --no-headless           Run Chrome in visible mode
        --no-recon              Skip reconnaissance phase
        --no-payloads           Skip payload testing
        --no-screenshots        Skip screenshot capture
        --no-parallel           Disable parallel processing
        --max-payloads NUM      Maximum payloads per parameter (default: 100)
        --no-waf-bypass         Disable WAF bypass techniques
        --log-level LEVEL       Log level (DEBUG|INFO|WARNING|ERROR|CRITICAL)
        --target-domain DOMAIN  Target domain for redirect validation (default: google.com)
        --proxy-url URL         Proxy URL
        --proxy-username USER   Proxy username
        --proxy-password PASS   Proxy password
    
    Examples:
        $0 https://target-website.com
        $0 -p thorough https://target-website.com
        $0 -c config.json
        $0 -o results -j 20 https://target-website.com
        $0 --preset stealth --target-domain evil.com https://target-website.com
    
    Presets:
        fast      - Fast scan with minimal depth
        thorough  - Comprehensive scan with full depth
        stealth   - Stealth scan with delays
        debug     - Debug mode with detailed logging
    "
}

# Function to check dependencies
check_dependencies() {
    print_color $BLUE "🔍 Checking dependencies..."
    
    # Check Python
    if ! command -v python3 &> /dev/null; then
        print_color $RED "❌ Python 3 is not installed"
        exit 1
    fi
    
    # Check pip
    if ! command -v pip3 &> /dev/null; then
        print_color $RED "❌ pip3 is not installed"
        exit 1
    fi
    
    # Check if requirements.txt exists
    if [ ! -f "requirements.txt" ]; then
        print_color $RED "❌ requirements.txt not found"
        exit 1
    fi
    
    print_color $GREEN "✅ Dependencies check passed"
}

# Function to install dependencies
install_dependencies() {
    print_color $BLUE "📦 Installing dependencies..."
    
    # Check if virtual environment exists
    if [ ! -d "venv" ]; then
        print_color $YELLOW "Creating virtual environment..."
        python3 -m venv venv
    fi
    
    # Activate virtual environment
    source venv/bin/activate
    
    # Upgrade pip
    pip install --upgrade pip
    
    # Install requirements
    pip install -r requirements.txt
    
    print_color $GREEN "✅ Dependencies installed successfully"
}

# Function to run test scan
run_test() {
    print_color $BLUE "🧪 Running test scan..."
    
    # Activate virtual environment if it exists
    if [ -d "venv" ]; then
        source venv/bin/activate
    fi
    
    python3 test_scanner.py
    
    print_color $GREEN "✅ Test scan completed"
}

# Function to run performance test
run_performance_test() {
    print_color $BLUE "⚡ Running performance test..."
    
    # Activate virtual environment if it exists
    if [ -d "venv" ]; then
        source venv/bin/activate
    fi
    
    python3 performance_test.py
    
    print_color $GREEN "✅ Performance test completed"
}

# Function to run full test suite
run_test_suite() {
    print_color $BLUE "🧪 Running full test suite..."
    
    # Activate virtual environment if it exists
    if [ -d "venv" ]; then
        source venv/bin/activate
    fi
    
    python3 test_suite.py
    
    print_color $GREEN "✅ Test suite completed"
}

# Function to clean up
cleanup() {
    print_color $BLUE "🧹 Cleaning up..."
    
    # Remove generated files
    rm -rf scan_results/
    rm -rf test_results/
    rm -rf example_results/
    rm -rf advanced_results/
    rm -rf custom_results/
    rm -rf multi_target_results_*/
    rm -rf error_handling_results/
    rm -rf perf_test_output/
    rm -rf __pycache__/
    rm -rf *.pyc
    rm -rf .pytest_cache/
    
    print_color $GREEN "✅ Cleanup completed"
}

# Function to show version
show_version() {
    print_color $BLUE "Open Redirect Scanner v1.0.0"
    print_color $YELLOW "Advanced Security Testing Tool"
}

# Function to run scanner
run_scanner() {
    local target_url=""
    local config_file=""
    local preset=""
    local output_dir="scan_results"
    local threads=10
    local depth=3
    local timeout=30
    local log_level="INFO"
    local target_domain="google.com"
    local proxy_url=""
    local proxy_username=""
    local proxy_password=""
    local no_headless=false
    local no_recon=false
    local no_payloads=false
    local no_screenshots=false
    local no_parallel=false
    local max_payloads=100
    local no_waf_bypass=false
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_usage
                exit 0
                ;;
            -v|--version)
                show_version
                exit 0
                ;;
            -i|--install)
                install_dependencies
                exit 0
                ;;
            -t|--test)
                run_test
                exit 0
                ;;
            --performance-test)
                run_performance_test
                exit 0
                ;;
            --test-suite)
                run_test_suite
                exit 0
                ;;
            --cleanup)
                cleanup
                exit 0
                ;;
            -c|--config)
                config_file="$2"
                shift 2
                ;;
            -p|--preset)
                preset="$2"
                shift 2
                ;;
            -o|--output)
                output_dir="$2"
                shift 2
                ;;
            -j|--threads)
                threads="$2"
                shift 2
                ;;
            -d|--depth)
                depth="$2"
                shift 2
                ;;
            --timeout)
                timeout="$2"
                shift 2
                ;;
            --log-level)
                log_level="$2"
                shift 2
                ;;
            --target-domain)
                target_domain="$2"
                shift 2
                ;;
            --proxy-url)
                proxy_url="$2"
                shift 2
                ;;
            --proxy-username)
                proxy_username="$2"
                shift 2
                ;;
            --proxy-password)
                proxy_password="$2"
                shift 2
                ;;
            --no-headless)
                no_headless=true
                shift
                ;;
            --no-recon)
                no_recon=true
                shift
                ;;
            --no-payloads)
                no_payloads=true
                shift
                ;;
            --no-screenshots)
                no_screenshots=true
                shift
                ;;
            --no-parallel)
                no_parallel=true
                shift
                ;;
            --max-payloads)
                max_payloads="$2"
                shift 2
                ;;
            --no-waf-bypass)
                no_waf_bypass=true
                shift
                ;;
            -*)
                print_color $RED "❌ Unknown option: $1"
                show_usage
                exit 1
                ;;
            *)
                if [ -z "$target_url" ]; then
                    target_url="$1"
                else
                    print_color $RED "❌ Multiple target URLs provided"
                    exit 1
                fi
                shift
                ;;
        esac
    done
    
    # Check if target URL is provided
    if [ -z "$target_url" ] && [ -z "$config_file" ] && [ -z "$preset" ]; then
        print_color $RED "❌ Target URL is required"
        show_usage
        exit 1
    fi
    
    # Activate virtual environment if it exists
    if [ -d "venv" ]; then
        source venv/bin/activate
    fi
    
    # Build command
    local cmd="python3 main.py"
    
    if [ -n "$target_url" ]; then
        cmd="$cmd $target_url"
    fi
    
    if [ -n "$config_file" ]; then
        cmd="$cmd -c $config_file"
    fi
    
    if [ -n "$preset" ]; then
        cmd="$cmd --preset $preset"
    fi
    
    cmd="$cmd -o $output_dir -j $threads -d $depth --timeout $timeout --log-level $log_level --target-domain $target_domain"
    
    if [ -n "$proxy_url" ]; then
        cmd="$cmd --proxy-url $proxy_url"
    fi
    
    if [ -n "$proxy_username" ]; then
        cmd="$cmd --proxy-username $proxy_username"
    fi
    
    if [ -n "$proxy_password" ]; then
        cmd="$cmd --proxy-password $proxy_password"
    fi
    
    if [ "$no_headless" = true ]; then
        cmd="$cmd --no-headless"
    fi
    
    if [ "$no_recon" = true ]; then
        cmd="$cmd --no-recon"
    fi
    
    if [ "$no_payloads" = true ]; then
        cmd="$cmd --no-payloads"
    fi
    
    if [ "$no_screenshots" = true ]; then
        cmd="$cmd --no-screenshots"
    fi
    
    if [ "$no_parallel" = true ]; then
        cmd="$cmd --no-parallel"
    fi
    
    cmd="$cmd --max-payloads $max_payloads"
    
    if [ "$no_waf_bypass" = true ]; then
        cmd="$cmd --no-waf-bypass"
    fi
    
    # Run scanner
    print_color $BLUE "🚀 Running scanner with command: $cmd"
    eval $cmd
}

# Main function
main() {
    print_banner
    
    # Check if no arguments provided
    if [ $# -eq 0 ]; then
        show_usage
        exit 1
    fi
    
    # Run scanner
    run_scanner "$@"
}

# Run main function
main "$@"