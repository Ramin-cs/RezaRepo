#!/usr/bin/env python3
"""
Simple ChromeDriver Downloader
"""

import os
import sys
import platform
import subprocess
import urllib.request
import zipfile
import shutil

def get_chrome_version_simple():
    """Get Chrome version using simple method"""
    try:
        if platform.system() == "Windows":
            # Try common paths
            paths = [
                r"C:\Program Files\Google\Chrome\Application\chrome.exe",
                r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe"
            ]
            
            for path in paths:
                if os.path.exists(path):
                    try:
                        result = subprocess.run([path, "--version"], 
                                              capture_output=True, text=True, timeout=10)
                        version = result.stdout.strip().split()[-1]
                        return version
                    except:
                        continue
        else:
            # Linux/macOS
            try:
                result = subprocess.run(["google-chrome", "--version"], 
                                      capture_output=True, text=True, timeout=10)
                version = result.stdout.strip().split()[-1]
                return version
            except:
                pass
        
        return None
    except:
        return None

def download_chromedriver_simple():
    """Download ChromeDriver with simple method"""
    try:
        print("=" * 60)
        print("Simple ChromeDriver Downloader")
        print("=" * 60)
        
        # Get Chrome version
        chrome_version = get_chrome_version_simple()
        if not chrome_version:
            print("❌ Chrome not found!")
            print("Please install Google Chrome first")
            return False
        
        print(f"✅ Chrome version: {chrome_version}")
        
        # Get major version
        major_version = chrome_version.split('.')[0]
        print(f"✅ Major version: {major_version}")
        
        # Determine platform
        system = platform.system().lower()
        if system == "windows":
            platform_name = "win64"
            driver_name = "chromedriver.exe"
        elif system == "darwin":
            platform_name = "mac64"
            driver_name = "chromedriver"
        else:
            platform_name = "linux64"
            driver_name = "chromedriver"
        
        print(f"✅ Platform: {platform_name}")
        
        # Try to find compatible version
        compatible_versions = [
            f"{major_version}.0.7258.154",  # Most common
            f"{major_version}.0.7258.155",
            f"{major_version}.0.7258.156",
            f"{major_version}.0.7258.157",
            f"{major_version}.0.7258.158",
            f"{major_version}.0.7258.159",
            f"{major_version}.0.7258.160",
        ]
        
        for version in compatible_versions:
            try:
                print(f"Trying ChromeDriver version: {version}")
                
                # Download URL
                url = f"https://storage.googleapis.com/chrome-for-testing-public/{version}/{platform_name}/chromedriver-{platform_name}.zip"
                
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
                    print(f"✅ ChromeDriver extracted to: {driver_name}")
                    
                    # Make executable on Unix systems
                    if system != "windows":
                        os.chmod(driver_name, 0o755)
                        print("✅ ChromeDriver made executable")
                    
                    # Clean up
                    shutil.rmtree(extract_path)
                    os.remove(filename)
                    print("✅ Cleanup completed")
                    
                    return True
                else:
                    print(f"❌ ChromeDriver not found in extracted files")
                    os.remove(filename)
                    if os.path.exists(extract_path):
                        shutil.rmtree(extract_path)
                    continue
                    
            except Exception as e:
                print(f"❌ Failed to download version {version}: {e}")
                if os.path.exists(filename):
                    os.remove(filename)
                if os.path.exists(extract_path):
                    shutil.rmtree(extract_path)
                continue
        
        print("❌ Could not find compatible ChromeDriver version")
        return False
        
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

def main():
    """Main function"""
    success = download_chromedriver_simple()
    
    if success:
        print("\n✅ ChromeDriver downloaded successfully!")
        print("You can now run the router brute force tool.")
    else:
        print("\n❌ Failed to download ChromeDriver")
        print("Please try manual installation:")
        print("1. Go to: https://chromedriver.chromium.org/downloads")
        print("2. Download the version matching your Chrome")
        print("3. Extract chromedriver.exe to this folder")
    
    return success

if __name__ == "__main__":
    main()