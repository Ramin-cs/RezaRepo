#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Setup script for Advanced XSS Scanner
اسکریپت نصب برای ابزار پیشرفته تشخیص XSS
"""

import os
import sys
import subprocess
import platform
from pathlib import Path

def print_banner():
    print("""
╔══════════════════════════════════════════════════════════════╗
║                    Advanced XSS Scanner                      ║
║                     Setup & Installation                     ║
║                  ابزار پیشرفته تشخیص XSS                    ║
╚══════════════════════════════════════════════════════════════╝
    """)

def check_python_version():
    """Check if Python version is compatible"""
    if sys.version_info < (3, 7):
        print("❌ Python 3.7 or higher is required!")
        print(f"Current version: {sys.version}")
        sys.exit(1)
    else:
        print(f"✅ Python version: {sys.version.split()[0]}")

def install_pip_packages():
    """Install required pip packages"""
    print("\n📦 Installing Python packages...")
    
    try:
        subprocess.check_call([
            sys.executable, "-m", "pip", "install", "-r", "requirements.txt"
        ])
        print("✅ Python packages installed successfully!")
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to install Python packages: {e}")
        return False
    
    return True

def setup_chrome_driver():
    """Setup ChromeDriver for Selenium"""
    print("\n🌐 Setting up ChromeDriver...")
    
    system = platform.system().lower()
    
    if system == "linux":
        print("📋 For Linux systems, please install ChromeDriver manually:")
        print("   sudo apt-get update")
        print("   sudo apt-get install -y chromium-browser chromium-chromedriver")
        print("   Or download from: https://chromedriver.chromium.org/")
        
    elif system == "windows":
        print("📋 For Windows systems, please:")
        print("   1. Download ChromeDriver from: https://chromedriver.chromium.org/")
        print("   2. Extract and place chromedriver.exe in your PATH")
        print("   3. Or place it in the same directory as this script")
        
    elif system == "darwin":  # macOS
        print("📋 For macOS systems, you can use Homebrew:")
        print("   brew install chromedriver")
        print("   Or download from: https://chromedriver.chromium.org/")
    
    print("⚠️  Make sure Chrome browser is also installed on your system!")

def create_directories():
    """Create necessary directories"""
    print("\n📁 Creating directories...")
    
    directories = ["screenshots", "reports"]
    
    for directory in directories:
        Path(directory).mkdir(exist_ok=True)
        print(f"✅ Created directory: {directory}")

def test_installation():
    """Test if all components are working"""
    print("\n🧪 Testing installation...")
    
    try:
        # Test imports
        import requests
        import bs4
        import selenium
        import colorama
        print("✅ All Python packages imported successfully!")
        
        # Test ChromeDriver (basic test)
        try:
            from selenium import webdriver
            from selenium.webdriver.chrome.options import Options
            
            chrome_options = Options()
            chrome_options.add_argument('--headless')
            chrome_options.add_argument('--no-sandbox')
            chrome_options.add_argument('--disable-dev-shm-usage')
            
            driver = webdriver.Chrome(options=chrome_options)
            driver.get("data:text/html,<html><body><h1>Test</h1></body></html>")
            driver.quit()
            print("✅ ChromeDriver is working correctly!")
            
        except Exception as e:
            print(f"⚠️  ChromeDriver test failed: {e}")
            print("   Please make sure ChromeDriver is properly installed")
            
    except ImportError as e:
        print(f"❌ Import test failed: {e}")
        return False
    
    return True

def show_usage_examples():
    """Show usage examples"""
    print("\n📖 Usage Examples:")
    print("="*60)
    
    examples = [
        ("Basic scan", "python advanced_xss_scanner.py -u https://example.com"),
        ("Deep scan with custom settings", "python advanced_xss_scanner.py -u https://example.com -d 5 -t 10 --delay 2"),
        ("Scan with stored XSS server", "python advanced_xss_scanner.py -u https://example.com --stored-server http://your-server.com"),
        ("Show help", "python advanced_xss_scanner.py -h"),
    ]
    
    for description, command in examples:
        print(f"\n{description}:")
        print(f"  {command}")
    
    print("\n📋 Command Line Options:")
    print("  -u, --url          Target URL (required)")
    print("  -d, --depth        Maximum crawl depth (default: 3)")
    print("  -t, --threads      Number of threads (default: 5)")
    print("  --delay            Delay between requests (default: 1.0)")
    print("  --stored-server    Server for stored/blind XSS testing")
    print("  -h, --help         Show help message")

def main():
    print_banner()
    
    print("🚀 Starting setup process...\n")
    
    # Check Python version
    check_python_version()
    
    # Install packages
    if not install_pip_packages():
        print("\n❌ Setup failed during package installation!")
        sys.exit(1)
    
    # Setup ChromeDriver
    setup_chrome_driver()
    
    # Create directories
    create_directories()
    
    # Test installation
    if test_installation():
        print("\n🎉 Setup completed successfully!")
        print("✅ Advanced XSS Scanner is ready to use!")
    else:
        print("\n⚠️  Setup completed with warnings!")
        print("   Please check the error messages above")
    
    # Show usage examples
    show_usage_examples()
    
    print("\n" + "="*60)
    print("Happy scanning! 🔍")
    print("="*60)

if __name__ == "__main__":
    main()