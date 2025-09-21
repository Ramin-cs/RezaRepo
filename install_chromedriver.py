#!/usr/bin/env python3
"""
ChromeDriver Installation Script
This script helps install ChromeDriver for the XSS scanner
"""

import os
import sys
import platform
import subprocess
import requests
import zipfile
import shutil
from pathlib import Path

def get_chrome_version():
    """Get installed Chrome version"""
    system = platform.system().lower()
    
    if system == "windows":
        try:
            # Try to get Chrome version from registry
            import winreg
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Google\Chrome\BLBeacon")
            version, _ = winreg.QueryValueEx(key, "version")
            winreg.CloseKey(key)
            return version
        except:
            try:
                # Try alternative method
                result = subprocess.run(['reg', 'query', 'HKEY_CURRENT_USER\\Software\\Google\\Chrome\\BLBeacon', '/v', 'version'], 
                                      capture_output=True, text=True)
                if result.returncode == 0:
                    version_line = [line for line in result.stdout.split('\n') if 'version' in line]
                    if version_line:
                        version = version_line[0].split()[-1]
                        return version
            except:
                pass
    elif system == "darwin":  # macOS
        try:
            result = subprocess.run(['/Applications/Google Chrome.app/Contents/MacOS/Google Chrome', '--version'], 
                                  capture_output=True, text=True)
            if result.returncode == 0:
                version = result.stdout.strip().split()[-1]
                return version
        except:
            pass
    elif system == "linux":
        try:
            result = subprocess.run(['google-chrome', '--version'], capture_output=True, text=True)
            if result.returncode == 0:
                version = result.stdout.strip().split()[-1]
                return version
        except:
            try:
                result = subprocess.run(['chromium-browser', '--version'], capture_output=True, text=True)
                if result.returncode == 0:
                    version = result.stdout.strip().split()[-1]
                    return version
            except:
                pass
    
    return None

def download_chromedriver(version):
    """Download ChromeDriver for the given Chrome version"""
    try:
        # Get the major version
        major_version = version.split('.')[0]
        
        # Get available ChromeDriver versions
        api_url = f"https://chromedriver.storage.googleapis.com/LATEST_RELEASE_{major_version}"
        response = requests.get(api_url, timeout=10)
        
        if response.status_code == 200:
            chromedriver_version = response.text.strip()
        else:
            print(f"❌ Could not get ChromeDriver version for Chrome {major_version}")
            return False
        
        # Download ChromeDriver
        system = platform.system().lower()
        if system == "windows":
            filename = "chromedriver_win32.zip"
            executable_name = "chromedriver.exe"
        elif system == "darwin":
            filename = "chromedriver_mac64.zip"
            executable_name = "chromedriver"
        else:  # linux
            filename = "chromedriver_linux64.zip"
            executable_name = "chromedriver"
        
        download_url = f"https://chromedriver.storage.googleapis.com/{chromedriver_version}/{filename}"
        
        print(f"📥 Downloading ChromeDriver {chromedriver_version}...")
        response = requests.get(download_url, timeout=30)
        
        if response.status_code == 200:
            # Save and extract
            zip_path = Path(filename)
            with open(zip_path, 'wb') as f:
                f.write(response.content)
            
            # Extract
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extractall()
            
            # Move to appropriate location
            if system == "windows":
                target_dir = Path.home() / ".wdm" / "drivers" / "chromedriver" / "win64" / chromedriver_version
            else:
                target_dir = Path.home() / ".wdm" / "drivers" / "chromedriver" / "linux64" / chromedriver_version
            
            target_dir.mkdir(parents=True, exist_ok=True)
            
            # Move executable
            shutil.move(executable_name, target_dir / executable_name)
            
            # Make executable on Unix systems
            if system != "windows":
                os.chmod(target_dir / executable_name, 0o755)
            
            # Clean up
            zip_path.unlink()
            if (Path(executable_name)).exists():
                (Path(executable_name)).unlink()
            
            print(f"✅ ChromeDriver {chromedriver_version} installed successfully!")
            print(f"📍 Location: {target_dir / executable_name}")
            return True
        else:
            print(f"❌ Failed to download ChromeDriver: HTTP {response.status_code}")
            return False
            
    except Exception as e:
        print(f"❌ Error installing ChromeDriver: {e}")
        return False

def install_using_webdriver_manager():
    """Install ChromeDriver using webdriver-manager"""
    try:
        print("📥 Installing ChromeDriver using webdriver-manager...")
        from webdriver_manager.chrome import ChromeDriverManager
        
        # This will download and cache ChromeDriver
        driver_path = ChromeDriverManager().install()
        print(f"✅ ChromeDriver installed successfully!")
        print(f"📍 Location: {driver_path}")
        return True
    except Exception as e:
        print(f"❌ Error using webdriver-manager: {e}")
        return False

def main():
    """Main installation function"""
    print("🔧 ChromeDriver Installation Script")
    print("=" * 40)
    
    # Check if Chrome is installed
    chrome_version = get_chrome_version()
    if chrome_version:
        print(f"✅ Chrome version detected: {chrome_version}")
    else:
        print("⚠️  Chrome version not detected. Please ensure Google Chrome is installed.")
        print("   You can download it from: https://www.google.com/chrome/")
    
    # Try webdriver-manager first
    print("\n🔄 Attempting installation using webdriver-manager...")
    if install_using_webdriver_manager():
        print("\n🎉 ChromeDriver installation completed successfully!")
        print("   You can now run the XSS scanner.")
        return True
    
    # Fallback to manual installation
    if chrome_version:
        print("\n🔄 Attempting manual installation...")
        if download_chromedriver(chrome_version):
            print("\n🎉 ChromeDriver installation completed successfully!")
            print("   You can now run the XSS scanner.")
            return True
    
    print("\n❌ ChromeDriver installation failed.")
    print("   Please try one of the following:")
    print("   1. Install ChromeDriver manually from: https://chromedriver.chromium.org/")
    print("   2. Use a different browser or headless mode")
    print("   3. Run the scanner in fallback mode (without Chrome)")
    
    return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)