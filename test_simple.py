#!/usr/bin/env python3
"""
Test script for Simple Password Tester
"""

import asyncio
from simple_password_tester import SimplePasswordTester

async def test_functionality():
    """Test the simple password tester"""
    print("🧪 Testing Simple Password Tester")
    print("-" * 40)
    
    tester = SimplePasswordTester()
    
    # Test password list
    expected_passwords = ["admin", "JAMES1", "admin1", "user"]
    assert tester.password_list == expected_passwords, "Password list mismatch"
    print("✅ Password list correct:", tester.password_list)
    
    # Test Chrome setup
    if tester.driver:
        print("✅ Chrome driver setup: SUCCESS")
    else:
        print("⚠️ Chrome driver setup: FAILED (Chrome may not be available)")
    
    # Test HTTP functionality with invalid target
    print("\n🌐 Testing HTTP with invalid target...")
    result = await tester.test_password_http("192.168.999.999", "admin")
    assert result.success == False, "Should fail for invalid target"
    print("✅ HTTP error handling works")
    
    tester.close_chrome()
    print("\n✅ All tests passed!")

if __name__ == "__main__":
    asyncio.run(test_functionality())