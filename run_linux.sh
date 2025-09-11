#!/bin/bash

echo "Router Brute Force Chrome v2.0 - Linux/macOS Launcher"
echo "====================================================="

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo "Error: Python 3 is not installed or not in PATH"
    echo "Please install Python 3.7+ from your package manager"
    exit 1
fi

# Check if the main script exists
if [ ! -f "router_brute_force_chrome.py" ]; then
    echo "Error: router_brute_force_chrome.py not found"
    echo "Please make sure you're in the correct directory"
    exit 1
fi

# Install dependencies if requirements.txt exists
if [ -f "requirements.txt" ]; then
    echo "Installing dependencies..."
    python3 -m pip install -r requirements.txt
    if [ $? -ne 0 ]; then
        echo "Warning: Failed to install some dependencies"
        echo "You may need to install them manually"
    fi
fi

# Create screenshots directory
mkdir -p screenshots

echo ""
echo "Router Brute Force Chrome is ready!"
echo ""
echo "Example usage:"
echo "  python3 router_brute_force_chrome.py -u http://192.168.1.1"
echo ""
echo "For help:"
echo "  python3 router_brute_force_chrome.py --help"
echo ""

# Interactive mode
while true; do
    echo "Choose an option:"
    echo "1. Run with example URL (192.168.1.1)"
    echo "2. Enter custom URL"
    echo "3. Show help"
    echo "4. Exit"
    echo ""
    read -p "Enter your choice (1-4): " choice
    
    case $choice in
        1)
            url="http://192.168.1.1"
            ;;
        2)
            read -p "Enter router URL: " url
            if [ -z "$url" ]; then
                echo "Invalid URL"
                continue
            fi
            ;;
        3)
            python3 router_brute_force_chrome.py --help
            continue
            ;;
        4)
            echo "Goodbye!"
            exit 0
            ;;
        *)
            echo "Invalid choice"
            continue
            ;;
    esac
    
    echo ""
    echo "Running brute force attack on: $url"
    echo "Chrome browser will open visibly..."
    echo ""
    python3 router_brute_force_chrome.py -u "$url"
    echo ""
    echo "Attack completed. Check the screenshots folder for results."
    echo ""
    read -p "Press Enter to continue..."
done