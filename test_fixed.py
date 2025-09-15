#!/usr/bin/env python3
"""
Test Fixed XSS Scanner
Testing the fixed version with proper alert detection
"""

import sys
import os
from xss_scanner import XSSScanner

def test_fixed_scanner():
    """Test the fixed scanner with proper alert detection"""
    print("=" * 60)
    print("TESTING FIXED XSS SCANNER")
    print("=" * 60)
    print("Testing with proper alert detection and no false positives")
    print("=" * 60)
    
    # Test with a vulnerable target
    target_url = "http://testphp.vulnweb.com/"
    
    # Scanner options
    options = {
        'depth': 1,
        'max_urls': 10,
        'timeout': 5,
        'verbose': True,
        'headless': False  # Show Chrome browser
    }
    
    print(f"Target: {target_url}")
    print(f"Options: {options}")
    print("\nStarting fixed scan...")
    print("=" * 60)
    
    try:
        # Initialize scanner
        scanner = XSSScanner(target_url, options)
        
        # Run scan
        scanner.scan_target()
        
        print("\n" + "=" * 60)
        print("SCAN COMPLETED")
        print("=" * 60)
        
    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == '__main__':
    test_fixed_scanner()