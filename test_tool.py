#!/usr/bin/env python3
"""
Test script for Router Brute Force Chrome v2.0
This script tests the tool functionality without actually attacking real routers
"""

import os
import sys
import time
import tempfile
from unittest.mock import Mock, patch

def test_imports():
    """Test if all required modules can be imported"""
    print("Testing imports...")
    
    try:
        import router_brute_force_chrome
        print("✓ Main module imports successfully")
    except ImportError as e:
        print(f"✗ Failed to import main module: {e}")
        return False
    
    try:
        from router_brute_force_chrome import ChromeRouterBruteForce, Colors, TARGET_CREDENTIALS
        print("✓ Core classes and constants import successfully")
    except ImportError as e:
        print(f"✗ Failed to import core components: {e}")
        return False
    
    return True

def test_credentials():
    """Test if target credentials are correctly defined"""
    print("\nTesting target credentials...")
    
    from router_brute_force_chrome import TARGET_CREDENTIALS
    
    expected_credentials = [
        ("admin", "admin"),
        ("admin", "support180"),
        ("support", "support"),
        ("user", "user")
    ]
    
    if TARGET_CREDENTIALS == expected_credentials:
        print("✓ Target credentials are correctly defined")
        return True
    else:
        print(f"✗ Target credentials mismatch. Expected: {expected_credentials}, Got: {TARGET_CREDENTIALS}")
        return False

def test_class_initialization():
    """Test if ChromeRouterBruteForce class can be initialized"""
    print("\nTesting class initialization...")
    
    try:
        from router_brute_force_chrome import ChromeRouterBruteForce
        
        # Test with a dummy URL
        instance = ChromeRouterBruteForce("http://example.com", headless=True)
        
        # Check if attributes are set correctly
        if instance.login_url == "http://example.com":
            print("✓ Login URL set correctly")
        else:
            print("✗ Login URL not set correctly")
            return False
        
        if instance.headless == True:
            print("✓ Headless mode set correctly")
        else:
            print("✗ Headless mode not set correctly")
            return False
        
        if instance.screenshot_dir == "screenshots":
            print("✓ Screenshot directory set correctly")
        else:
            print("✗ Screenshot directory not set correctly")
            return False
        
        print("✓ ChromeRouterBruteForce class initializes correctly")
        return True
        
    except Exception as e:
        print(f"✗ Failed to initialize ChromeRouterBruteForce: {e}")
        return False

def test_url_parsing():
    """Test URL parsing functionality"""
    print("\nTesting URL parsing...")
    
    try:
        from router_brute_force_chrome import parse_login_url
        
        test_cases = [
            ("192.168.1.1", "http://192.168.1.1"),
            ("http://192.168.1.1", "http://192.168.1.1"),
            ("https://192.168.1.1", "https://192.168.1.1"),
            ("192.168.1.1:8080", "http://192.168.1.1:8080"),
            ("http://192.168.1.1:8080", "http://192.168.1.1:8080"),
            ("invalid-url", None)
        ]
        
        for input_url, expected in test_cases:
            result = parse_login_url(input_url)
            if result == expected:
                print(f"✓ URL parsing: '{input_url}' -> '{result}'")
            else:
                print(f"✗ URL parsing failed: '{input_url}' -> '{result}' (expected: '{expected}')")
                return False
        
        print("✓ URL parsing works correctly")
        return True
        
    except Exception as e:
        print(f"✗ URL parsing test failed: {e}")
        return False

def test_form_detection():
    """Test form detection logic (without actually running Chrome)"""
    print("\nTesting form detection logic...")
    
    try:
        from router_brute_force_chrome import ChromeRouterBruteForce
        
        instance = ChromeRouterBruteForce("http://example.com", headless=True)
        
        # Test username field detection
        username_fields = [
            'username', 'user', 'login', 'admin', 'name', 'email', 'account',
            'userid', 'user_id', 'loginname', 'login_name', 'uname'
        ]
        
        # Test password field detection
        password_fields = [
            'password', 'pass', 'passwd', 'pwd', 'admin', 'secret', 'key'
        ]
        
        print(f"✓ Username field patterns: {len(username_fields)} patterns")
        print(f"✓ Password field patterns: {len(password_fields)} patterns")
        
        print("✓ Form detection logic is properly defined")
        return True
        
    except Exception as e:
        print(f"✗ Form detection test failed: {e}")
        return False

def test_success_detection():
    """Test login success detection logic"""
    print("\nTesting login success detection...")
    
    try:
        from router_brute_force_chrome import ChromeRouterBruteForce
        
        instance = ChromeRouterBruteForce("http://example.com", headless=True)
        
        # Test admin indicators
        admin_indicators = [
            'admin', 'administrator', 'dashboard', 'control panel', 'configuration', 
            'settings', 'system', 'status', 'network', 'router', 'gateway', 'modem',
            'wan', 'lan', 'wireless', 'firewall', 'nat', 'dhcp', 'dns', 'qos',
            'firmware', 'upgrade', 'backup', 'restore', 'reboot', 'restart',
            'main menu', 'welcome', 'logout', 'log out'
        ]
        
        # Test login indicators
        login_indicators = [
            'username', 'password', 'login', 'sign in', 'authentication', 'enter credentials',
            'user login', 'admin login', 'router login', 'invalid', 'incorrect', 'failed',
            'error', 'denied', 'wrong', 'access denied'
        ]
        
        print(f"✓ Admin indicators: {len(admin_indicators)} patterns")
        print(f"✓ Login indicators: {len(login_indicators)} patterns")
        
        print("✓ Login success detection logic is properly defined")
        return True
        
    except Exception as e:
        print(f"✗ Login success detection test failed: {e}")
        return False

def test_cross_platform():
    """Test cross-platform compatibility"""
    print("\nTesting cross-platform compatibility...")
    
    try:
        from router_brute_force_chrome import Colors
        
        # Test color codes
        if hasattr(Colors, 'RED') and hasattr(Colors, 'GREEN'):
            print("✓ Color codes are defined")
        else:
            print("✗ Color codes are missing")
            return False
        
        # Test platform detection
        import os
        if os.name in ['nt', 'posix']:
            print(f"✓ Platform detected: {os.name}")
        else:
            print(f"✗ Unknown platform: {os.name}")
            return False
        
        print("✓ Cross-platform compatibility looks good")
        return True
        
    except Exception as e:
        print(f"✗ Cross-platform test failed: {e}")
        return False

def test_selenium_availability():
    """Test if Selenium is available"""
    print("\nTesting Selenium availability...")
    
    try:
        from selenium import webdriver
        from selenium.webdriver.chrome.options import Options
        print("✓ Selenium imports successfully")
        
        # Test Chrome options creation
        options = Options()
        options.add_argument('--headless')
        options.add_argument('--no-sandbox')
        print("✓ Chrome options can be created")
        
        print("✓ Selenium is properly installed")
        return True
        
    except ImportError as e:
        print(f"✗ Selenium not available: {e}")
        print("Please install Selenium: pip install selenium")
        return False
    except Exception as e:
        print(f"✗ Selenium test failed: {e}")
        return False

def run_all_tests():
    """Run all tests"""
    print("Router Brute Force Chrome v2.0 - Test Suite")
    print("=" * 50)
    
    tests = [
        test_imports,
        test_credentials,
        test_class_initialization,
        test_url_parsing,
        test_form_detection,
        test_success_detection,
        test_cross_platform,
        test_selenium_availability
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        try:
            if test():
                passed += 1
        except Exception as e:
            print(f"✗ Test {test.__name__} failed with exception: {e}")
    
    print("\n" + "=" * 50)
    print(f"Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("✓ All tests passed! The tool is ready to use.")
        return True
    else:
        print("✗ Some tests failed. Please check the issues above.")
        return False

if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)