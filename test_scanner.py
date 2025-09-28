#!/usr/bin/env python3
"""
Test script for Open Redirect Scanner
"""

import asyncio
import sys
from pathlib import Path

# Add current directory to Python path
sys.path.insert(0, str(Path(__file__).parent))

from open_redirect_scanner import OpenRedirectScanner

async def test_scanner():
    """Test the scanner with a simple target"""
    print("🧪 Testing Open Redirect Scanner...")
    
    # Test with a simple target
    target_url = "https://httpbin.org"
    output_dir = "test_results"
    threads = 5
    
    print(f"Target: {target_url}")
    print(f"Output: {output_dir}")
    print(f"Threads: {threads}")
    print("-" * 50)
    
    # Create scanner instance
    scanner = OpenRedirectScanner(target_url, output_dir, threads)
    
    try:
        # Initialize scanner
        if await scanner.initialize():
            print("✅ Scanner initialized successfully")
            
            # Run scan
            await scanner.scan()
            print("✅ Test scan completed")
            
        else:
            print("❌ Failed to initialize scanner")
            
    except Exception as e:
        print(f"❌ Test failed: {str(e)}")
        
    finally:
        # Cleanup
        await scanner.cleanup()
        print("🧹 Cleanup completed")

if __name__ == "__main__":
    asyncio.run(test_scanner())