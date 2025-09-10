#!/usr/bin/env python3
"""
Complete setup script for Router Brute Force Chrome v2.0
"""

import os
import sys
import subprocess
import platform

def run_command(command, description):
    """Run a command and handle errors"""
    print(f"Running: {description}")
    try:
        result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        print(f"✅ {description} - Success")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ {description} - Failed: {e}")
        return False

def main():
    """Main setup function"""
    print("=" * 60)
    print("Router Brute Force Chrome v2.0 - Complete Setup")
    print("=" * 60)
    
    # Check Python version
    if sys.version_info < (3, 7):
        print("❌ Python 3.7+ is required")
        sys.exit(1)
    
    print(f"✅ Python version: {sys.version}")
    
    # Install Python packages
    print("\n1. Installing Python packages...")
    if not run_command("pip install -r requirements.txt", "Installing requirements"):
        print("❌ Failed to install Python packages")
        sys.exit(1)
    
    # Download compatible ChromeDriver
    print("\n2. Setting up ChromeDriver...")
    if not run_command("python auto_chromedriver.py", "Downloading ChromeDriver"):
        print("❌ Failed to download ChromeDriver")
        sys.exit(1)
    
    # Test installation
    print("\n3. Testing installation...")
    if not run_command("python test_chrome.py", "Testing Chrome setup"):
        print("❌ Chrome setup test failed")
        sys.exit(1)
    
    print("\n" + "=" * 60)
    print("✅ Setup completed successfully!")
    print("=" * 60)
    print("\nUsage examples:")
    print("  python router_brute_force_chrome.py -u 'http://192.168.1.1'")
    print("  python test_single_url.py 'http://192.168.1.1'")
    print("\nFor help:")
    print("  python router_brute_force_chrome.py --help")

if __name__ == "__main__":
    main()