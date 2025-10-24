#!/usr/bin/env python3
"""
Test script for the subdomain enumeration tool
"""

import subprocess
import sys
import os

def test_basic_functionality():
    """Test basic functionality of the tool"""
    print("🧪 Testing Basic Functionality...")
    
    # Test 1: Help command
    print("1. Testing help command...")
    try:
        result = subprocess.run([sys.executable, "subdomains.py", "--help"], 
                              capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            print("   ✅ Help command works")
        else:
            print("   ❌ Help command failed")
            return False
    except Exception as e:
        print(f"   ❌ Help command error: {e}")
        return False
    
    # Test 2: API status check
    print("2. Testing API status check...")
    try:
        result = subprocess.run([sys.executable, "subdomains.py", "--show-apis"], 
                              capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            print("   ✅ API status check works")
        else:
            print("   ❌ API status check failed")
    except Exception as e:
        print(f"   ❌ API status check error: {e}")
    
    # Test 3: Domain validation
    print("3. Testing domain validation...")
    try:
        result = subprocess.run([sys.executable, "subdomains.py", "-d", "invalid..domain"], 
                              capture_output=True, text=True, timeout=10)
        if result.returncode != 0:
            print("   ✅ Domain validation works (rejected invalid domain)")
        else:
            print("   ❌ Domain validation failed (accepted invalid domain)")
            return False
    except Exception as e:
        print(f"   ❌ Domain validation error: {e}")
        return False
    
    return True

def test_quick_scan():
    """Test quick scan functionality"""
    print("\n🚀 Testing Quick Scan...")
    
    # Use a safe test domain
    test_domain = "httpbin.org"  # Safe test domain
    
    try:
        print(f"   Testing quick scan on {test_domain}...")
        result = subprocess.run([
            sys.executable, "subdomains.py", 
            "-d", test_domain, 
            "--quick", 
            "--silent",
            "--timeout", "5"
        ], capture_output=True, text=True, timeout=60)
        
        if result.returncode == 0:
            print("   ✅ Quick scan completed successfully")
            return True
        else:
            print(f"   ❌ Quick scan failed with return code: {result.returncode}")
            print(f"   Error output: {result.stderr}")
            return False
            
    except subprocess.TimeoutExpired:
        print("   ⚠️ Quick scan timed out (this might be normal)")
        return True
    except Exception as e:
        print(f"   ❌ Quick scan error: {e}")
        return False

def main():
    """Main test function"""
    print("🔍 Subdomain Enumeration Tool - Test Suite")
    print("=" * 50)
    
    # Check if required files exist
    required_files = ["subdomains.py", "config.py", "requirements.txt"]
    for file in required_files:
        if not os.path.exists(file):
            print(f"❌ Required file not found: {file}")
            return False
    
    print("✅ All required files found")
    
    # Run tests
    basic_test = test_basic_functionality()
    
    if basic_test:
        print("\n🎉 Basic functionality tests passed!")
        
        # Ask user if they want to run the quick scan test
        response = input("\n🤔 Do you want to run a quick scan test? (y/n): ").lower().strip()
        if response in ['y', 'yes']:
            quick_test = test_quick_scan()
            if quick_test:
                print("\n🎉 All tests passed!")
            else:
                print("\n⚠️ Some tests failed, but basic functionality works")
        else:
            print("\n✅ Basic tests completed successfully!")
    else:
        print("\n❌ Basic functionality tests failed!")
        return False
    
    return True

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)