#!/usr/bin/env python3
"""
Cross-platform installer for Router Brute Force Chrome v2.0
Supports Windows, Linux, and macOS
"""

import os
import sys
import platform
import subprocess
import urllib.request
import zipfile
import shutil
from pathlib import Path

def get_os_info():
    """Get operating system information"""
    system = platform.system().lower()
    machine = platform.machine().lower()
    
    if system == "windows":
        return "windows", "win64" if "64" in machine else "win32"
    elif system == "darwin":
        return "macos", "mac64" if "arm" in machine else "mac64"
    elif system == "linux":
        return "linux", "linux64"
    else:
        return "unknown", "unknown"

def install_python_packages():
    """Install required Python packages"""
    print("Installing Python packages...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
        print("✅ Python packages installed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Error installing Python packages: {e}")
        return False

def download_chromedriver(os_name, arch):
    """Download appropriate ChromeDriver for the OS"""
    print(f"Downloading ChromeDriver for {os_name} {arch}...")
    
    # ChromeDriver download URLs
    base_url = "https://storage.googleapis.com/chrome-for-testing-public/140.0.7339.82"
    
    if os_name == "windows":
        url = f"{base_url}/win64/chromedriver-win64.zip"
        filename = "chromedriver-win64.zip"
        extract_path = "chromedriver-win64"
        driver_name = "chromedriver.exe"
    elif os_name == "macos":
        url = f"{base_url}/mac64/chromedriver-mac64.zip"
        filename = "chromedriver-mac64.zip"
        extract_path = "chromedriver-mac64"
        driver_name = "chromedriver"
    elif os_name == "linux":
        url = f"{base_url}/linux64/chromedriver-linux64.zip"
        filename = "chromedriver-linux64.zip"
        extract_path = "chromedriver-linux64"
        driver_name = "chromedriver"
    else:
        print(f"❌ Unsupported OS: {os_name}")
        return False
    
    try:
        # Download ChromeDriver
        print(f"Downloading from: {url}")
        urllib.request.urlretrieve(url, filename)
        print("✅ ChromeDriver downloaded successfully")
        
        # Extract ChromeDriver
        with zipfile.ZipFile(filename, 'r') as zip_ref:
            zip_ref.extractall()
        
        # Move ChromeDriver to current directory
        driver_path = os.path.join(extract_path, driver_name)
        if os.path.exists(driver_path):
            shutil.move(driver_path, driver_name)
            print(f"✅ ChromeDriver extracted to: {driver_name}")
            
            # Make executable on Unix systems
            if os_name != "windows":
                os.chmod(driver_name, 0o755)
                print("✅ ChromeDriver made executable")
            
            # Clean up
            shutil.rmtree(extract_path)
            os.remove(filename)
            print("✅ Cleanup completed")
            
            return True
        else:
            print(f"❌ ChromeDriver not found in extracted files")
            return False
            
    except Exception as e:
        print(f"❌ Error downloading ChromeDriver: {e}")
        return False

def check_chrome_installed():
    """Check if Chrome is installed"""
    print("Checking Chrome installation...")
    
    os_name, arch = get_os_info()
    
    if os_name == "windows":
        chrome_paths = [
            r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe"
        ]
    elif os_name == "macos":
        chrome_paths = [
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
        ]
    elif os_name == "linux":
        chrome_paths = [
            "/usr/bin/google-chrome",
            "/usr/bin/google-chrome-stable",
            "/usr/bin/chromium-browser",
            "/usr/bin/chromium"
        ]
    else:
        print("❌ Unsupported OS")
        return False
    
    for path in chrome_paths:
        if os.path.exists(path):
            print(f"✅ Chrome found at: {path}")
            return True
    
    print("❌ Chrome not found. Please install Google Chrome first.")
    print("Download from: https://www.google.com/chrome/")
    return False

def main():
    """Main installation function"""
    print("=" * 60)
    print("Router Brute Force Chrome v2.0 - Cross-platform Installer")
    print("=" * 60)
    
    # Get OS information
    os_name, arch = get_os_info()
    print(f"Detected OS: {os_name} {arch}")
    
    # Check Chrome installation
    if not check_chrome_installed():
        print("\nPlease install Google Chrome first, then run this installer again.")
        return False
    
    # Install Python packages
    if not install_python_packages():
        print("\nFailed to install Python packages.")
        return False
    
    # Download ChromeDriver
    if not download_chromedriver(os_name, arch):
        print("\nFailed to download ChromeDriver.")
        return False
    
    print("\n" + "=" * 60)
    print("✅ Installation completed successfully!")
    print("=" * 60)
    print("\nUsage:")
    print("  python3 router_brute_force_chrome.py -u 'http://192.168.1.1'")
    print("\nFor help:")
    print("  python3 router_brute_force_chrome.py --help")
    print("\nTest installation:")
    print("  python3 test_chrome.py")
    
    return True

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)