#!/usr/bin/env python3
"""
Find Chrome installation and version
"""

import os
import sys
import platform
import subprocess
import winreg

def find_chrome_windows():
    """Find Chrome on Windows"""
    print("Searching for Chrome on Windows...")
    
    # Method 1: Check common installation paths
    chrome_paths = [
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
        r"C:\Users\{}\AppData\Local\Google\Chrome\Application\chrome.exe".format(os.getenv('USERNAME', '')),
    ]
    
    for path in chrome_paths:
        if os.path.exists(path):
            print(f"✅ Found Chrome at: {path}")
            try:
                result = subprocess.run([path, "--version"], capture_output=True, text=True, timeout=10)
                version = result.stdout.strip().split()[-1]
                print(f"✅ Chrome version: {version}")
                return version
            except Exception as e:
                print(f"❌ Error getting version: {e}")
    
    # Method 2: Check registry
    print("Checking Windows Registry...")
    registry_paths = [
        (winreg.HKEY_CURRENT_USER, r"Software\Google\Chrome\BLBeacon"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Google\Chrome\BLBeacon"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Google\Chrome\BLBeacon"),
    ]
    
    for hkey, subkey in registry_paths:
        try:
            key = winreg.OpenKey(hkey, subkey)
            version, _ = winreg.QueryValueEx(key, "version")
            winreg.CloseKey(key)
            print(f"✅ Chrome version from registry: {version}")
            return version
        except:
            continue
    
    # Method 3: Search in Program Files
    print("Searching Program Files...")
    program_files = [r"C:\Program Files", r"C:\Program Files (x86)"]
    
    for pf in program_files:
        if os.path.exists(pf):
            for root, dirs, files in os.walk(pf):
                if "chrome.exe" in files:
                    chrome_path = os.path.join(root, "chrome.exe")
                    if "Google" in root:
                        print(f"✅ Found Chrome at: {chrome_path}")
                        try:
                            result = subprocess.run([chrome_path, "--version"], capture_output=True, text=True, timeout=10)
                            version = result.stdout.strip().split()[-1]
                            print(f"✅ Chrome version: {version}")
                            return version
                        except Exception as e:
                            print(f"❌ Error getting version: {e}")
    
    return None

def find_chrome_linux():
    """Find Chrome on Linux"""
    print("Searching for Chrome on Linux...")
    
    commands = ["google-chrome", "chromium-browser", "chromium", "chrome"]
    
    for cmd in commands:
        try:
            result = subprocess.run([cmd, "--version"], capture_output=True, text=True, timeout=10)
            version = result.stdout.strip().split()[-1]
            print(f"✅ Chrome version: {version}")
            return version
        except:
            continue
    
    return None

def main():
    """Main function"""
    print("=" * 60)
    print("Chrome Detection Tool")
    print("=" * 60)
    
    if platform.system() == "Windows":
        version = find_chrome_windows()
    else:
        version = find_chrome_linux()
    
    if version:
        print(f"\n✅ Chrome found! Version: {version}")
        return version
    else:
        print("\n❌ Chrome not found!")
        print("\nPlease install Google Chrome from:")
        print("https://www.google.com/chrome/")
        return None

if __name__ == "__main__":
    main()