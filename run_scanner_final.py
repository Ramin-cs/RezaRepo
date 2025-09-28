#!/usr/bin/env python3
"""
Final Open Redirect Scanner Runner
Simple script to run the scanner with proper error handling
"""

import asyncio
import sys
import os
from pathlib import Path

# Add current directory to Python path
sys.path.insert(0, str(Path(__file__).parent))

def print_banner():
    """Print scanner banner"""
    print("""
    ╔══════════════════════════════════════════════════════════════╗
    ║                                                              ║
    ║           🔍 Open Redirect Vulnerability Scanner            ║
    ║                                                              ║
    ║              Advanced Security Testing Tool                  ║
    ║                                                              ║
    ╚══════════════════════════════════════════════════════════════╝
    """)

def print_usage():
    """Print usage information"""
    print("""
    Usage: python run_scanner_final.py <target_url> [options]
    
    Examples:
        python run_scanner_final.py https://target-website.com
        python run_scanner_final.py https://target-website.com --output results --threads 20
        python run_scanner_final.py https://target-website.com --preset thorough
    
    Options:
        --output DIR          Output directory (default: scan_results)
        --threads NUM         Number of threads (default: 10)
        --depth NUM           Maximum depth (default: 3)
        --preset PRESET       Use preset (fast|thorough|stealth|debug)
        --help                Show this help message
    """)

def test_imports():
    """Test that all required modules can be imported"""
    try:
        from open_redirect_scanner import OpenRedirectScanner
        from recon_module import ReconModule
        from payload_module import PayloadModule
        from chrome_module import ChromeModule
        from report_module import ReportModule
        from logging_module import LoggingModule
        from configuration import ScannerConfig
        return True
    except ImportError as e:
        print(f"❌ Import error: {str(e)}")
        print("Please install dependencies: pip install -r requirements.txt")
        return False

def test_basic_functionality():
    """Test basic functionality without creating files"""
    try:
        from recon_module import ReconModule
        from payload_module import PayloadModule
        
        # Mock logger
        logger = type('MockLogger', (), {'info': lambda x: None, 'error': lambda x: None})()
        
        # Test recon module
        recon = ReconModule(logger)
        test_url = "https://httpbin.org?url=test&redirect=test2"
        params = recon._extract_url_parameters(test_url)
        
        # Test payload module
        payloads = PayloadModule(logger)
        test_payload = "//google.com"
        generated = payloads.generate_payloads(test_payload)
        
        print(f"✅ Recon module: {len(params)} parameters extracted")
        print(f"✅ Payload module: {len(generated)} payloads generated")
        return True
        
    except Exception as e:
        print(f"❌ Functionality test error: {str(e)}")
        return False

async def run_scanner(target_url, output_dir="scan_results", threads=10, depth=3, preset=None):
    """Run the scanner"""
    try:
        from open_redirect_scanner import OpenRedirectScanner
        
        print(f"🎯 Target: {target_url}")
        print(f"📁 Output: {output_dir}")
        print(f"🧵 Threads: {threads}")
        print(f"🔍 Depth: {depth}")
        print("-" * 50)
        
        # Create scanner
        scanner = OpenRedirectScanner(target_url, output_dir, threads)
        
        # Apply preset if specified
        if preset:
            from configuration import get_preset_config
            config = get_preset_config(preset)
            config.target_url = target_url
            print(f"📋 Using preset: {preset}")
        
        # Initialize scanner
        print("🚀 Initializing scanner...")
        if await scanner.initialize():
            print("✅ Scanner initialized successfully")
            
            # Run scan
            print("🔍 Starting scan...")
            await scanner.scan()
            print("✅ Scan completed successfully")
            
        else:
            print("❌ Failed to initialize scanner")
            return False
        
        # Cleanup
        await scanner.cleanup()
        print("🧹 Cleanup completed")
        
        print("\n🎉 Scan completed successfully!")
        print(f"📁 Results saved to: {output_dir}")
        print("📊 Check the generated reports for detailed results")
        
        return True
        
    except Exception as e:
        print(f"❌ Scanner error: {str(e)}")
        return False

def main():
    """Main function"""
    print_banner()
    
    # Check arguments
    if len(sys.argv) < 2:
        print("❌ Error: Target URL is required")
        print_usage()
        sys.exit(1)
    
    # Parse arguments
    target_url = sys.argv[1]
    output_dir = "scan_results"
    threads = 10
    depth = 3
    preset = None
    
    # Parse options
    i = 2
    while i < len(sys.argv):
        arg = sys.argv[i]
        
        if arg == "--help":
            print_usage()
            sys.exit(0)
        elif arg == "--output" and i + 1 < len(sys.argv):
            output_dir = sys.argv[i + 1]
            i += 2
        elif arg == "--threads" and i + 1 < len(sys.argv):
            threads = int(sys.argv[i + 1])
            i += 2
        elif arg == "--depth" and i + 1 < len(sys.argv):
            depth = int(sys.argv[i + 1])
            i += 2
        elif arg == "--preset" and i + 1 < len(sys.argv):
            preset = sys.argv[i + 1]
            i += 2
        else:
            print(f"❌ Unknown option: {arg}")
            print_usage()
            sys.exit(1)
    
    # Test imports
    print("🧪 Testing imports...")
    if not test_imports():
        sys.exit(1)
    print("✅ All modules imported successfully")
    
    # Test basic functionality
    print("🧪 Testing basic functionality...")
    if not test_basic_functionality():
        sys.exit(1)
    print("✅ Basic functionality test passed")
    
    # Run scanner
    print("\n🚀 Starting scanner...")
    try:
        success = asyncio.run(run_scanner(target_url, output_dir, threads, depth, preset))
        if success:
            print("\n🎉 Scanner completed successfully!")
            sys.exit(0)
        else:
            print("\n❌ Scanner failed!")
            sys.exit(1)
    except KeyboardInterrupt:
        print("\n⚠️ Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Fatal error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()