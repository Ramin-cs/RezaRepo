#!/usr/bin/env python3
"""
Auto ChromeDriver Downloader and Manager
Automatically downloads the correct ChromeDriver version for the installed Chrome
"""

import os
import sys
import platform
import subprocess
import urllib.request
import zipfile
import shutil
import json
import re
from pathlib import Path

def get_chrome_version():
    """Get installed Chrome version"""
    try:
        if platform.system() == "Windows":
            # Windows Chrome version detection - multiple methods
            chrome_paths = [
                r"C:\Program Files\Google\Chrome\Application\chrome.exe",
                r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
                r"C:\Users\{}\AppData\Local\Google\Chrome\Application\chrome.exe".format(os.getenv('USERNAME', '')),
                r"C:\Users\{}\AppData\Local\Google\Chrome\Application\chrome.exe".format(os.getenv('USERPROFILE', '').split('\\')[-1])
            ]
            
            print("Searching for Chrome in Windows...")
            for chrome_path in chrome_paths:
                print(f"Checking: {chrome_path}")
                if os.path.exists(chrome_path):
                    try:
                        print(f"Found Chrome at: {chrome_path}")
                        result = subprocess.run([chrome_path, "--version"], 
                                              capture_output=True, text=True, timeout=10)
                        version = result.stdout.strip().split()[-1]
                        print(f"Chrome version: {version}")
                        return version
                    except Exception as e:
                        print(f"Error getting version from {chrome_path}: {e}")
                        continue
            
            # Try registry method for Windows
            try:
                import winreg
                print("Trying Windows Registry method...")
                key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Google\Chrome\BLBeacon")
                version, _ = winreg.QueryValueEx(key, "version")
                winreg.CloseKey(key)
                print(f"Chrome version from registry: {version}")
                return version
            except:
                pass
                
            # Try alternative registry path
            try:
                import winreg
                print("Trying alternative registry method...")
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Google\Chrome\BLBeacon")
                version, _ = winreg.QueryValueEx(key, "version")
                winreg.CloseKey(key)
                print(f"Chrome version from registry: {version}")
                return version
            except:
                pass
                
        else:
            # Linux/macOS Chrome version detection
            print("Searching for Chrome in Linux/macOS...")
            chrome_commands = ["google-chrome", "chromium-browser", "chromium", "chrome"]
            
            for cmd in chrome_commands:
                try:
                    print(f"Trying command: {cmd}")
                    result = subprocess.run([cmd, "--version"], 
                                          capture_output=True, text=True, timeout=10)
                    version = result.stdout.strip().split()[-1]
                    print(f"Chrome version: {version}")
                    return version
                except Exception as e:
                    print(f"Command {cmd} failed: {e}")
                    continue
        
        print("Chrome not found in standard locations")
        return None
    except Exception as e:
        print(f"Error detecting Chrome version: {e}")
        return None

def get_chromedriver_version(chrome_version):
    """Get compatible ChromeDriver version for Chrome version"""
    try:
        # Get major version
        major_version = chrome_version.split('.')[0]
        
        # Get ChromeDriver version info
        url = f"https://googlechromelabs.github.io/chrome-for-testing/known-good-versions-with-downloads.json"
        
        with urllib.request.urlopen(url) as response:
            data = json.loads(response.read().decode())
        
        # Find compatible version
        for version_info in reversed(data['versions']):
            if version_info['version'].startswith(major_version + '.'):
                return version_info['version']
        
        return None
    except Exception as e:
        print(f"Error getting ChromeDriver version: {e}")
        return None

def download_chromedriver(chrome_version, chromedriver_version):
    """Download compatible ChromeDriver"""
    try:
        print(f"Downloading ChromeDriver {chromedriver_version} for Chrome {chrome_version}...")
        
        # Determine platform
        system = platform.system().lower()
        machine = platform.machine().lower()
        
        if system == "windows":
            platform_name = "win64"
            driver_name = "chromedriver.exe"
        elif system == "darwin":
            platform_name = "mac64"
            driver_name = "chromedriver"
        elif system == "linux":
            platform_name = "linux64"
            driver_name = "chromedriver"
        else:
            print(f"Unsupported platform: {system}")
            return False
        
        # Download URL
        url = f"https://storage.googleapis.com/chrome-for-testing-public/{chromedriver_version}/{platform_name}/chromedriver-{platform_name}.zip"
        
        print(f"Downloading from: {url}")
        
        # Download
        filename = f"chromedriver-{platform_name}.zip"
        urllib.request.urlretrieve(url, filename)
        
        # Extract
        with zipfile.ZipFile(filename, 'r') as zip_ref:
            zip_ref.extractall()
        
        # Move to current directory
        extract_path = f"chromedriver-{platform_name}"
        driver_path = os.path.join(extract_path, driver_name)
        
        if os.path.exists(driver_path):
            shutil.move(driver_path, driver_name)
            print(f"ChromeDriver extracted to: {driver_name}")
            
            # Make executable on Unix systems
            if system != "windows":
                os.chmod(driver_name, 0o755)
                print("ChromeDriver made executable")
            
            # Clean up
            shutil.rmtree(extract_path)
            os.remove(filename)
            print("Cleanup completed")
            
            return True
        else:
            print(f"ChromeDriver not found in extracted files")
            return False
            
    except Exception as e:
        print(f"Error downloading ChromeDriver: {e}")
        return False

def main():
    """Main function"""
    print("=" * 60)
    print("Auto ChromeDriver Downloader")
    print("=" * 60)
    
    # Get Chrome version
    chrome_version = get_chrome_version()
    if not chrome_version:
        print("❌ Chrome not found or version detection failed")
        print("Please install Google Chrome first")
        return False
    
    print(f"✅ Chrome version detected: {chrome_version}")
    
    # Get compatible ChromeDriver version
    chromedriver_version = get_chromedriver_version(chrome_version)
    if not chromedriver_version:
        print("❌ Could not find compatible ChromeDriver version")
        return False
    
    print(f"✅ Compatible ChromeDriver version: {chromedriver_version}")
    
    # Download ChromeDriver
    if download_chromedriver(chrome_version, chromedriver_version):
        print("✅ ChromeDriver downloaded successfully")
        return True
    else:
        print("❌ ChromeDriver download failed")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)