#!/usr/bin/env python3
"""
Test script for Smart Brute Forcer
"""

import asyncio
import time
from smart_brute_forcer_fixed import SmartBruteForcer, SmartDetectionTester

def test_basic_functionality():
    """Test basic functionality of the brute forcer"""
    print("🧪 Testing Basic Functionality")
    print("-" * 40)
    
    # Test target loading
    brute_forcer = SmartBruteForcer(mode="normal")
    
    # Test single target
    targets = brute_forcer.load_targets("192.168.1.1")
    assert len(targets) == 1, "Single target loading failed"
    print("✅ Single target loading: PASSED")
    
    # Test IP range
    targets = brute_forcer.load_targets("192.168.1.1-192.168.1.3")
    assert len(targets) == 3, "IP range loading failed"
    print("✅ IP range loading: PASSED")
    
    print("✅ Basic functionality tests completed\n")

async def test_http_functionality():
    """Test HTTP functionality with a dummy target"""
    print("🧪 Testing HTTP Functionality")
    print("-" * 40)
    
    brute_forcer = SmartBruteForcer(mode="normal")
    
    # Test with a non-existent target (should fail gracefully)
    result = await brute_forcer.http_test("192.168.999.999", "admin")
    
    assert result.success == False, "HTTP test should fail for invalid target"
    assert result.error is not None, "HTTP test should return error for invalid target"
    print("✅ HTTP error handling: PASSED")
    
    print("✅ HTTP functionality tests completed\n")

def test_chrome_setup():
    """Test Chrome driver setup"""
    print("🧪 Testing Chrome Setup")
    print("-" * 40)
    
    try:
        tester = SmartDetectionTester(headless=True)
        if tester.driver:
            print("✅ Chrome driver setup: PASSED")
            tester.close_chrome()
        else:
            print("⚠️ Chrome driver setup: FAILED (Chrome not available)")
    except Exception as e:
        print(f"⚠️ Chrome driver setup: FAILED ({e})")
    
    print("✅ Chrome setup tests completed\n")

def test_scoring_system():
    """Test the scoring system logic"""
    print("🧪 Testing Scoring System")
    print("-" * 40)
    
    tester = SmartDetectionTester(headless=True)
    
    # Test management page content
    management_content = """
    <html>
    <body>
        <h1>Router Management Dashboard</h1>
        <a href="/logout">Logout</a>
        <div>Wireless Settings</div>
        <div>Network Configuration</div>
        <div>System Status</div>
    </body>
    </html>
    """
    
    # Test login page content
    login_content = """
    <html>
    <body>
        <h1>Login</h1>
        <input type="password" name="password">
        <input type="text" name="username">
        <button>Sign In</button>
    </body>
    </html>
    """
    
    # Test scoring for management page
    mgmt_score, mgmt_indicators = tester.calculate_management_score(
        management_content.lower(), 
        "http://192.168.1.1/admin", 
        "Router Admin", 
        "http://192.168.1.1", 
        "Login Page"
    )
    
    # Test scoring for login page
    login_score, login_indicators = tester.calculate_management_score(
        login_content.lower(), 
        "http://192.168.1.1", 
        "Login Page", 
        "http://192.168.1.1", 
        "Login Page"
    )
    
    print(f"Management page score: {mgmt_score}")
    print(f"Login page score: {login_score}")
    
    assert mgmt_score > login_score, "Management page should score higher than login page"
    print("✅ Scoring system logic: PASSED")
    
    tester.close_chrome()
    print("✅ Scoring system tests completed\n")

async def run_all_tests():
    """Run all tests"""
    print("🚀 Starting Smart Brute Forcer Tests")
    print("=" * 50)
    
    try:
        # Basic functionality tests
        test_basic_functionality()
        
        # HTTP functionality tests
        await test_http_functionality()
        
        # Chrome setup tests
        test_chrome_setup()
        
        # Scoring system tests
        test_scoring_system()
        
        print("🎉 All tests completed successfully!")
        
    except Exception as e:
        print(f"❌ Test failed with error: {e}")
        raise

if __name__ == "__main__":
    asyncio.run(run_all_tests())