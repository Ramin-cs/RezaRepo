#!/usr/bin/env python3
"""
Simple runner script for Open Redirect Scanner
"""

import sys
import os
import asyncio
from pathlib import Path

# Add current directory to Python path
sys.path.insert(0, str(Path(__file__).parent))

from open_redirect_scanner import OpenRedirectScanner

def main():
    """Main function"""
    if len(sys.argv) < 2:
        print("Usage: python run_scanner.py <target_url> [output_dir] [threads]")
        print("Example: python run_scanner.py https://example.com scan_results 10")
        sys.exit(1)
    
    target_url = sys.argv[1]
    output_dir = sys.argv[2] if len(sys.argv) > 2 else "scan_results"
    threads = int(sys.argv[3]) if len(sys.argv) > 3 else 10
    
    print(f"🔍 Starting Open Redirect Scanner")
    print(f"Target: {target_url}")
    print(f"Output: {output_dir}")
    print(f"Threads: {threads}")
    print("-" * 50)
    
    # Create scanner instance
    scanner = OpenRedirectScanner(target_url, output_dir, threads)
    
    # Run scan
    async def run_scan():
        try:
            if await scanner.initialize():
                print("✅ Scanner initialized successfully")
                await scanner.scan()
                print("✅ Scan completed successfully")
            else:
                print("❌ Failed to initialize scanner")
        except KeyboardInterrupt:
            print("\n⚠️ Scan interrupted by user")
        except Exception as e:
            print(f"❌ Scan failed: {str(e)}")
        finally:
            await scanner.cleanup()
            print("🧹 Cleanup completed")
    
    # Run the scan
    try:
        asyncio.run(run_scan())
    except Exception as e:
        print(f"❌ Fatal error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()