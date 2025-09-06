#!/usr/bin/env python3
"""
Simple runner script for Advanced XSS Scanner
This script provides an easy way to run the scanner with common options
"""

import sys
import os
import argparse
from datetime import datetime

def print_banner():
    """Print application banner"""
    banner = """
╔══════════════════════════════════════════════════════════════╗
║                  Advanced XSS Scanner v1.0.0                ║
║              Complete Reconnaissance & Exploitation          ║
║                                                              ║
║  Features:                                                   ║
║  ✓ Full Reconnaissance & Target Discovery                    ║
║  ✓ WAF Detection & Bypass                                    ║
║  ✓ Custom Popup System                                       ║
║  ✓ All XSS Types (Reflected, Stored, DOM, Blind)            ║
║  ✓ Screenshot PoC Generation                                 ║
║  ✓ Comprehensive Reporting                                   ║
╚══════════════════════════════════════════════════════════════╝
    """
    print(banner)

def check_dependencies():
    """Check if required dependencies are installed"""
    missing_deps = []
    
    try:
        import requests
    except ImportError:
        missing_deps.append("requests")
    
    try:
        import bs4
    except ImportError:
        missing_deps.append("beautifulsoup4")
    
    try:
        from selenium import webdriver
    except ImportError:
        missing_deps.append("selenium")
    
    if missing_deps:
        print(f"❌ Missing dependencies: {', '.join(missing_deps)}")
        print("Please install them using:")
        print("pip install " + " ".join(missing_deps))
        return False
    
    print("✅ All dependencies are installed")
    return True

def run_basic_scan(target_url):
    """Run a basic XSS scan"""
    try:
        from xss_scanner import XSSScanner
        
        print(f"\n🎯 Starting XSS scan for: {target_url}")
        print("⏳ Please wait...")
        
        # Initialize scanner with basic options
        scanner = XSSScanner(target_url)
        
        # Run scan
        results = scanner.run_scan()
        
        # Display results
        print(f"\n📊 Scan completed!")
        print(f"🔍 Target: {results['target']}")
        print(f"📅 Timestamp: {results['timestamp']}")
        print(f"🚨 Total Vulnerabilities: {results['summary']['total_vulnerabilities']}")
        print(f"   - Reflected XSS: {results['summary']['reflected_xss']}")
        print(f"   - Stored XSS: {results['summary']['stored_xss']}")
        print(f"   - DOM XSS: {results['summary']['dom_xss']}")
        print(f"   - Blind XSS: {results['summary']['blind_xss']}")
        
        if results['vulnerabilities']:
            print(f"\n🎯 Vulnerabilities Found:")
            for i, vuln in enumerate(results['vulnerabilities'], 1):
                print(f"   {i}. {vuln['type']}")
                print(f"      Parameter: {vuln.get('parameter', 'N/A')}")
                print(f"      Payload: {vuln.get('payload', 'N/A')[:60]}...")
                if vuln.get('waf_bypassed'):
                    print(f"      WAF Bypassed: {vuln.get('waf_type', 'Unknown')}")
                if vuln.get('poc_screenshot'):
                    print(f"      Screenshot: {vuln['poc_screenshot']}")
                print()
        else:
            print("\n✅ No vulnerabilities found!")
        
        # Save report
        report_file = f"xss_scan_report_{int(datetime.now().timestamp())}.json"
        scanner.save_report(results, report_file)
        print(f"📄 Report saved to: {report_file}")
        
        return True
        
    except Exception as e:
        print(f"❌ Error during scan: {e}")
        return False

def run_advanced_scan(target_url, options):
    """Run an advanced XSS scan with custom options"""
    try:
        from xss_scanner import XSSScanner
        
        print(f"\n🎯 Starting advanced XSS scan for: {target_url}")
        print("⚙️  Options:")
        for key, value in options.items():
            print(f"   - {key}: {value}")
        print("⏳ Please wait...")
        
        # Initialize scanner with custom options
        scanner = XSSScanner(target_url, options)
        
        # Run scan
        results = scanner.run_scan()
        
        # Display results
        print(f"\n📊 Advanced scan completed!")
        print(f"🔍 Target: {results['target']}")
        print(f"📅 Timestamp: {results['timestamp']}")
        print(f"🚨 Total Vulnerabilities: {results['summary']['total_vulnerabilities']}")
        
        # Show reconnaissance results
        recon = results.get('reconnaissance', {})
        print(f"🔍 Reconnaissance Results:")
        print(f"   - Parameters discovered: {len(recon.get('discovered_params', []))}")
        print(f"   - Forms discovered: {len(recon.get('discovered_forms', []))}")
        print(f"   - URLs discovered: {len(recon.get('discovered_urls', []))}")
        
        # Show WAF detection
        waf_info = recon.get('waf_detected', {})
        if waf_info.get('detected'):
            print(f"🛡️  WAF detected: {waf_info.get('type', 'Unknown')}")
        else:
            print("🛡️  No WAF detected")
        
        # Show vulnerabilities
        if results['vulnerabilities']:
            print(f"\n🎯 Vulnerabilities Found:")
            for i, vuln in enumerate(results['vulnerabilities'], 1):
                print(f"   {i}. {vuln['type']}")
                print(f"      Parameter: {vuln.get('parameter', 'N/A')}")
                print(f"      Payload: {vuln.get('payload', 'N/A')[:60]}...")
                if vuln.get('waf_bypassed'):
                    print(f"      WAF Bypassed: {vuln.get('waf_type', 'Unknown')}")
                if vuln.get('poc_screenshot'):
                    print(f"      Screenshot: {vuln['poc_screenshot']}")
                print()
        else:
            print("\n✅ No vulnerabilities found!")
        
        # Save report
        report_file = options.get('output', f"advanced_scan_report_{int(datetime.now().timestamp())}.json")
        scanner.save_report(results, report_file)
        print(f"📄 Report saved to: {report_file}")
        
        return True
        
    except Exception as e:
        print(f"❌ Error during advanced scan: {e}")
        return False

def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description='Advanced XSS Scanner - Easy Runner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 run_scanner.py https://example.com
  python3 run_scanner.py https://example.com --advanced
  python3 run_scanner.py https://example.com --advanced --output report.json
  python3 run_scanner.py https://example.com --demo
        """
    )
    
    parser.add_argument('target', nargs='?', help='Target URL to scan')
    parser.add_argument('--advanced', action='store_true', help='Run advanced scan with all features')
    parser.add_argument('--output', '-o', help='Output file for report')
    parser.add_argument('--no-crawl', action='store_true', help='Disable URL crawling')
    parser.add_argument('--callback-url', help='Callback URL for blind XSS testing')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    parser.add_argument('--demo', action='store_true', help='Run demo mode')
    parser.add_argument('--test', action='store_true', help='Run test suite')
    parser.add_argument('--check-deps', action='store_true', help='Check dependencies')
    
    args = parser.parse_args()
    
    # Print banner
    print_banner()
    
    # Check dependencies
    if args.check_deps:
        check_dependencies()
        return
    
    if not check_dependencies():
        print("\n💡 Install dependencies with: pip install -r requirements.txt")
        return
    
    # Handle different modes
    if args.demo:
        print("\n🎮 Running demo mode...")
        try:
            os.system("python3 demo.py")
        except Exception as e:
            print(f"❌ Error running demo: {e}")
        return
    
    if args.test:
        print("\n🧪 Running test suite...")
        try:
            os.system("python3 test_xss_scanner.py")
        except Exception as e:
            print(f"❌ Error running tests: {e}")
        return
    
    if not args.target:
        print("❌ Please provide a target URL")
        print("Usage: python3 run_scanner.py https://example.com")
        print("For help: python3 run_scanner.py --help")
        return
    
    # Validate target URL
    target_url = args.target
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'https://' + target_url
    
    print(f"🎯 Target: {target_url}")
    
    # Run appropriate scan
    if args.advanced:
        # Advanced scan with options
        options = {
            'crawl': not args.no_crawl,
            'callback_url': args.callback_url,
            'output': args.output
        }
        
        # Remove None values
        options = {k: v for k, v in options.items() if v is not None}
        
        success = run_advanced_scan(target_url, options)
    else:
        # Basic scan
        success = run_basic_scan(target_url)
    
    if success:
        print("\n✅ Scan completed successfully!")
    else:
        print("\n❌ Scan failed!")
        sys.exit(1)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        sys.exit(1)