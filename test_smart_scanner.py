#!/usr/bin/env python3
"""
Test script for Smart XSS Scanner
"""

import subprocess
import sys
import time

def test_smart_scanner():
    """Test the smart XSS scanner"""
    print("🧪 Testing Smart XSS Scanner")
    print("=" * 40)
    
    # Test URL
    test_url = "http://testphp.vulnweb.com"
    
    print(f"🎯 Testing with: {test_url}")
    print("⏳ Running scan (this may take a few minutes)...")
    
    try:
        # Run the scanner
        result = subprocess.run([
            sys.executable, "smart_xss_scanner.py", test_url
        ], capture_output=True, text=True, timeout=300)  # 5 minute timeout
        
        print("\n📊 SCAN RESULTS:")
        print("=" * 30)
        print("STDOUT:")
        print(result.stdout)
        
        if result.stderr:
            print("\nSTDERR:")
            print(result.stderr)
        
        print(f"\nReturn code: {result.returncode}")
        
        if result.returncode == 0:
            print("✅ Scan completed successfully!")
        else:
            print("❌ Scan failed!")
            
    except subprocess.TimeoutExpired:
        print("⏰ Scan timed out after 5 minutes")
    except Exception as e:
        print(f"❌ Error running scanner: {e}")

if __name__ == "__main__":
    test_smart_scanner()