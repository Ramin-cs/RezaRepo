#!/usr/bin/env python3
"""
Test script for Chrome Router Brute Force
"""

import sys
import os

def test_chrome_availability():
    """Test if Chrome and ChromeDriver are available"""
    try:
        from selenium import webdriver
        from selenium.webdriver.chrome.options import Options
        print("✅ Selenium imported successfully")
        
        # Test Chrome driver
        chrome_options = Options()
        chrome_options.add_argument('--headless')
        chrome_options.add_argument('--no-sandbox')
        chrome_options.add_argument('--disable-dev-shm-usage')
        
        driver = webdriver.Chrome(options=chrome_options)
        driver.get("https://www.google.com")
        print("✅ Chrome driver working")
        driver.quit()
        return True
        
    except ImportError as e:
        print(f"❌ Selenium import error: {e}")
        return False
    except Exception as e:
        print(f"❌ Chrome driver error: {e}")
        return False

def test_router_brute_force():
    """Test the router brute force module"""
    try:
        from router_brute_force_chrome import ChromeRouterBruteForce
        print("✅ Router brute force module imported successfully")
        return True
    except ImportError as e:
        print(f"❌ Module import error: {e}")
        return False

def main():
    print("🔍 Testing Chrome Router Brute Force Setup...")
    print("=" * 50)
    
    # Test 1: Chrome availability
    print("\n1. Testing Chrome availability...")
    chrome_ok = test_chrome_availability()
    
    # Test 2: Module import
    print("\n2. Testing module import...")
    module_ok = test_router_brute_force()
    
    # Summary
    print("\n" + "=" * 50)
    if chrome_ok and module_ok:
        print("✅ All tests passed! Ready to use Chrome Router Brute Force")
        print("\nExample usage:")
        print("python router_brute_force_chrome.py -u 'http://192.168.1.1'")
    else:
        print("❌ Some tests failed. Please check the errors above.")
        if not chrome_ok:
            print("\nTo fix Chrome issues:")
            print("1. Install ChromeDriver: https://chromedriver.chromium.org/")
            print("2. Add ChromeDriver to your PATH")
        if not module_ok:
            print("\nTo fix module issues:")
            print("1. Install requirements: pip install -r requirements.txt")

if __name__ == "__main__":
    main()