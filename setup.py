#!/usr/bin/env python3
"""
Setup script for Router Brute Force Chrome v2.0
This script helps install dependencies and setup the environment
"""

import os
import sys
import subprocess
import platform

def check_python_version():
    """Check if Python version is compatible"""
    if sys.version_info < (3, 7):
        print("Error: Python 3.7 or higher is required")
        print(f"Current version: {sys.version}")
        return False
    print(f"✓ Python version: {sys.version.split()[0]}")
    return True

def install_requirements():
    """Install required Python packages"""
    try:
        print("Installing Python dependencies...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
        print("✓ Python dependencies installed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"Error installing dependencies: {e}")
        return False

def check_chrome():
    """Check if Chrome is installed"""
    system = platform.system().lower()
    
    if system == "windows":
        chrome_paths = [
            r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe"
        ]
    elif system == "darwin":  # macOS
        chrome_paths = [
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
        ]
    else:  # Linux
        chrome_paths = [
            "/usr/bin/google-chrome",
            "/usr/bin/chromium-browser",
            "/usr/bin/chrome"
        ]
    
    for path in chrome_paths:
        if os.path.exists(path):
            print(f"✓ Chrome found: {path}")
            return True
    
    print("⚠ Chrome not found in common locations")
    print("Please install Google Chrome from: https://www.google.com/chrome/")
    return False

def check_chromedriver():
    """Check if ChromeDriver is available"""
    try:
        # Try to import selenium and check if chromedriver is available
        from selenium import webdriver
        from selenium.webdriver.chrome.options import Options
        
        chrome_options = Options()
        chrome_options.add_argument('--headless')
        chrome_options.add_argument('--no-sandbox')
        chrome_options.add_argument('--disable-dev-shm-usage')
        
        # Try to create a driver instance
        driver = webdriver.Chrome(options=chrome_options)
        driver.quit()
        
        print("✓ ChromeDriver is working correctly")
        return True
        
    except Exception as e:
        print(f"⚠ ChromeDriver issue: {e}")
        print("\nTo fix ChromeDriver issues:")
        print("1. Download ChromeDriver from: https://chromedriver.chromium.org/")
        print("2. Make sure it matches your Chrome version")
        print("3. Add it to your PATH or place it in the same directory as the script")
        
        if platform.system().lower() == "windows":
            print("4. On Windows, you can also use: pip install webdriver-manager")
        else:
            print("4. On Linux/macOS, you can also install via package manager:")
            print("   - Ubuntu/Debian: sudo apt-get install chromium-chromedriver")
            print("   - macOS: brew install chromedriver")
        
        return False

def create_directories():
    """Create necessary directories"""
    directories = ["screenshots"]
    
    for directory in directories:
        if not os.path.exists(directory):
            os.makedirs(directory)
            print(f"✓ Created directory: {directory}")
        else:
            print(f"✓ Directory exists: {directory}")

def test_installation():
    """Test if the installation works"""
    try:
        print("\nTesting installation...")
        
        # Try to import the main module
        import router_brute_force_chrome
        print("✓ Main module imports successfully")
        
        # Try to create a ChromeRouterBruteForce instance
        from router_brute_force_chrome import ChromeRouterBruteForce
        instance = ChromeRouterBruteForce("http://example.com", headless=True)
        print("✓ ChromeRouterBruteForce class works")
        
        return True
        
    except Exception as e:
        print(f"✗ Installation test failed: {e}")
        return False

def main():
    """Main setup function"""
    print("Router Brute Force Chrome v2.0 - Setup")
    print("=" * 40)
    
    # Check Python version
    if not check_python_version():
        return False
    
    # Install requirements
    if not install_requirements():
        return False
    
    # Check Chrome
    check_chrome()
    
    # Check ChromeDriver
    check_chromedriver()
    
    # Create directories
    create_directories()
    
    # Test installation
    if test_installation():
        print("\n" + "=" * 40)
        print("✓ Setup completed successfully!")
        print("\nYou can now run the tool with:")
        print("python router_brute_force_chrome.py -u http://192.168.1.1")
        print("\nFor help, run:")
        print("python router_brute_force_chrome.py --help")
        return True
    else:
        print("\n" + "=" * 40)
        print("✗ Setup completed with issues")
        print("Please check the error messages above and fix any problems")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)