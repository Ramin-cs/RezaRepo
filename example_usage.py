#!/usr/bin/env python3
"""
Example usage of Open Redirect Scanner
Demonstrates various ways to use the scanner
"""

import asyncio
import sys
from pathlib import Path

# Add current directory to Python path
sys.path.insert(0, str(Path(__file__).parent))

from open_redirect_scanner import OpenRedirectScanner

async def example_basic_scan():
    """Basic scan example"""
    print("🔍 Example 1: Basic Scan")
    print("-" * 40)
    
    target_url = "https://httpbin.org"
    output_dir = "example_results"
    threads = 5
    
    scanner = OpenRedirectScanner(target_url, output_dir, threads)
    
    try:
        if await scanner.initialize():
            print("✅ Scanner initialized")
            await scanner.scan()
            print("✅ Basic scan completed")
        else:
            print("❌ Failed to initialize scanner")
    except Exception as e:
        print(f"❌ Error: {str(e)}")
    finally:
        await scanner.cleanup()

async def example_advanced_scan():
    """Advanced scan example with custom configuration"""
    print("\n🔍 Example 2: Advanced Scan")
    print("-" * 40)
    
    target_url = "https://httpbin.org"
    output_dir = "advanced_results"
    threads = 20  # More threads for faster scanning
    
    scanner = OpenRedirectScanner(target_url, output_dir, threads)
    
    try:
        if await scanner.initialize():
            print("✅ Scanner initialized with advanced configuration")
            await scanner.scan()
            print("✅ Advanced scan completed")
        else:
            print("❌ Failed to initialize scanner")
    except Exception as e:
        print(f"❌ Error: {str(e)}")
    finally:
        await scanner.cleanup()

async def example_custom_payloads():
    """Example with custom payloads"""
    print("\n🔍 Example 3: Custom Payloads")
    print("-" * 40)
    
    target_url = "https://httpbin.org"
    output_dir = "custom_results"
    threads = 10
    
    scanner = OpenRedirectScanner(target_url, output_dir, threads)
    
    # Add custom payloads
    custom_payloads = [
        "//evil.com",
        "https://evil.com",
        "javascript:alert(1)",
        "data:text/html,<script>alert(1)</script>",
        "ftp://evil.com",
        "file://evil.com"
    ]
    
    # Add custom payloads to scanner
    scanner.custom_payloads.extend(custom_payloads)
    
    try:
        if await scanner.initialize():
            print("✅ Scanner initialized with custom payloads")
            await scanner.scan()
            print("✅ Custom payload scan completed")
        else:
            print("❌ Failed to initialize scanner")
    except Exception as e:
        print(f"❌ Error: {str(e)}")
    finally:
        await scanner.cleanup()

async def example_multiple_targets():
    """Example scanning multiple targets"""
    print("\n🔍 Example 4: Multiple Targets")
    print("-" * 40)
    
    targets = [
        "https://httpbin.org",
        "https://httpbin.org/get",
        "https://httpbin.org/post"
    ]
    
    for i, target in enumerate(targets, 1):
        print(f"\nScanning target {i}/{len(targets)}: {target}")
        
        output_dir = f"multi_target_results_{i}"
        threads = 5
        
        scanner = OpenRedirectScanner(target, output_dir, threads)
        
        try:
            if await scanner.initialize():
                print(f"✅ Scanner initialized for {target}")
                await scanner.scan()
                print(f"✅ Scan completed for {target}")
            else:
                print(f"❌ Failed to initialize scanner for {target}")
        except Exception as e:
            print(f"❌ Error scanning {target}: {str(e)}")
        finally:
            await scanner.cleanup()

async def example_error_handling():
    """Example with error handling"""
    print("\n🔍 Example 5: Error Handling")
    print("-" * 40)
    
    # Test with invalid URL
    target_url = "https://invalid-url-that-does-not-exist.com"
    output_dir = "error_handling_results"
    threads = 5
    
    scanner = OpenRedirectScanner(target_url, output_dir, threads)
    
    try:
        if await scanner.initialize():
            print("✅ Scanner initialized (unexpected for invalid URL)")
            await scanner.scan()
            print("✅ Scan completed (unexpected for invalid URL)")
        else:
            print("❌ Failed to initialize scanner (expected for invalid URL)")
    except Exception as e:
        print(f"❌ Error (expected for invalid URL): {str(e)}")
    finally:
        await scanner.cleanup()

async def main():
    """Main function to run all examples"""
    print("🚀 Open Redirect Scanner - Example Usage")
    print("=" * 50)
    
    try:
        # Run all examples
        await example_basic_scan()
        await example_advanced_scan()
        await example_custom_payloads()
        await example_multiple_targets()
        await example_error_handling()
        
        print("\n✅ All examples completed successfully!")
        print("\n📁 Check the generated result directories for outputs:")
        print("   - example_results/")
        print("   - advanced_results/")
        print("   - custom_results/")
        print("   - multi_target_results_*/")
        print("   - error_handling_results/")
        
    except KeyboardInterrupt:
        print("\n⚠️ Examples interrupted by user")
    except Exception as e:
        print(f"\n❌ Fatal error: {str(e)}")

if __name__ == "__main__":
    asyncio.run(main())