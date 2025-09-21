#!/usr/bin/env python3
"""
Quick test script for the XSS scanner
"""

import sys
import os

def test_imports():
    """Test if all required modules can be imported"""
    print("🔍 Testing imports...")
    
    try:
        import requests
        print("✅ requests")
    except ImportError as e:
        print(f"❌ requests: {e}")
        return False
    
    try:
        from bs4 import BeautifulSoup
        print("✅ beautifulsoup4")
    except ImportError as e:
        print(f"❌ beautifulsoup4: {e}")
        return False
    
    try:
        import selenium
        print("✅ selenium")
    except ImportError as e:
        print(f"❌ selenium: {e}")
        return False
    
    try:
        from webdriver_manager.chrome import ChromeDriverManager
        print("✅ webdriver-manager")
    except ImportError as e:
        print(f"❌ webdriver-manager: {e}")
        return False
    
    return True

def test_scanner_import():
    """Test if the scanner can be imported"""
    print("\n🔍 Testing scanner import...")
    
    try:
        import advanced_xss_scanner
        print("✅ advanced_xss_scanner imported successfully")
        return True
    except Exception as e:
        print(f"❌ advanced_xss_scanner import failed: {e}")
        return False

def test_chrome_detection():
    """Test Chrome detection"""
    print("\n🔍 Testing Chrome detection...")
    
    try:
        from advanced_xss_scanner import AdvancedXSSScanner
        from dataclasses import asdict
        
        # Create a dummy recon data
        from advanced_xss_scanner import XSSPoint
        from dataclasses import asdict
        
        recon_data = {
            'urls': ['http://testphp.vulnweb.com'],
            'forms': [],
            'parameters': ['test'],
            'xss_points': [asdict(XSSPoint(
                url='http://testphp.vulnweb.com',
                parameter='test',
                method='GET',
                context='html'
            ))],
            'technologies': [],
            'js_files': [],
            'api_endpoints': []
        }
        
        scanner = AdvancedXSSScanner(recon_data)
        
        if scanner.driver:
            print("✅ Chrome WebDriver initialized successfully")
            scanner.cleanup()
            return True
        else:
            print("⚠️  Chrome WebDriver not available (fallback mode will be used)")
            return True
            
    except Exception as e:
        print(f"❌ Chrome detection failed: {e}")
        return False

def main():
    """Main test function"""
    print("🧪 XSS Scanner Test Suite")
    print("=" * 30)
    
    # Test imports
    if not test_imports():
        print("\n❌ Import tests failed. Please install missing dependencies:")
        print("   pip install -r requirements.txt")
        return False
    
    # Test scanner import
    if not test_scanner_import():
        print("\n❌ Scanner import failed. Please check the code.")
        return False
    
    # Test Chrome detection
    if not test_chrome_detection():
        print("\n❌ Chrome detection failed.")
        return False
    
    print("\n🎉 All tests passed!")
    print("   The scanner is ready to use.")
    print("\n💡 To run the scanner:")
    print("   python advanced_xss_scanner.py http://testphp.vulnweb.com")
    
    return True

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)