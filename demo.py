#!/usr/bin/env python3
"""
Demo script for Advanced XSS Scanner
This script demonstrates the capabilities of the XSS scanner
"""

import sys
import json
from xss_scanner import XSSScanner

def demo_basic_scan():
    """Demo basic scanning functionality"""
    print("=== XSS Scanner Demo ===\n")
    
    # Example target (replace with your test target)
    target = "https://httpbin.org/get"
    
    print(f"Target: {target}")
    print("Starting scan...\n")
    
    # Initialize scanner
    options = {
        'crawl': False,  # Disable crawling for demo
        'callback_url': 'http://localhost:8080/callback'
    }
    
    scanner = XSSScanner(target, options)
    
    # Run scan
    results = scanner.run_scan()
    
    # Display results
    print("=== Scan Results ===")
    print(f"Target: {results['target']}")
    print(f"Timestamp: {results['timestamp']}")
    print(f"Total Vulnerabilities: {results['summary']['total_vulnerabilities']}")
    print(f"Reflected XSS: {results['summary']['reflected_xss']}")
    print(f"Stored XSS: {results['summary']['stored_xss']}")
    print(f"DOM XSS: {results['summary']['dom_xss']}")
    print(f"Blind XSS: {results['summary']['blind_xss']}")
    
    if results['vulnerabilities']:
        print("\n=== Vulnerabilities Found ===")
        for i, vuln in enumerate(results['vulnerabilities'], 1):
            print(f"{i}. {vuln['type']}")
            print(f"   Parameter: {vuln.get('parameter', 'N/A')}")
            print(f"   Payload: {vuln.get('payload', 'N/A')[:50]}...")
            if vuln.get('waf_bypassed'):
                print(f"   WAF Bypassed: {vuln.get('waf_type', 'Unknown')}")
            print()
    else:
        print("\nNo vulnerabilities found.")
    
    # Save report
    report_file = f"demo_report_{int(time.time())}.json"
    scanner.save_report(results, report_file)
    print(f"Report saved to: {report_file}")

def demo_waf_bypass():
    """Demo WAF bypass functionality"""
    print("=== WAF Bypass Demo ===\n")
    
    from waf_bypass import WAFBypassEngine
    
    bypass_engine = WAFBypassEngine()
    
    # Test payload
    payload = '<script>alert("XSS")</script>'
    print(f"Original payload: {payload}")
    
    # Generate bypass variants
    waf_info = {'detected': True, 'type': 'cloudflare', 'bypass_methods': ['encoding', 'case_variation']}
    bypass_payloads = bypass_engine.generate_bypass_payloads(payload, waf_info)
    
    print(f"\nGenerated {len(bypass_payloads)} bypass variants:")
    for i, bypass_payload in enumerate(bypass_payloads[:5], 1):  # Show first 5
        print(f"{i}. {bypass_payload}")
    
    print(f"\n... and {len(bypass_payloads) - 5} more variants")

def demo_custom_popup():
    """Demo custom popup system"""
    print("=== Custom Popup Demo ===\n")
    
    from custom_popup import CustomPopupSystem
    
    popup_system = CustomPopupSystem()
    
    # Generate popup payloads
    popup_payloads = popup_system.generate_popup_payload("Custom demo message!")
    
    print(f"Generated {len(popup_payloads)} popup payload variants:")
    for i, payload in enumerate(popup_payloads[:3], 1):  # Show first 3
        print(f"{i}. {payload[:80]}...")
    
    print(f"\nPopup ID: {popup_system.popup_id}")
    print("This popup system provides:")
    print("- Visual confirmation of XSS")
    print("- No interference with browser alerts")
    print("- Detailed page information")
    print("- Screenshot capability")

def demo_payload_generation():
    """Demo payload generation system"""
    print("=== Payload Generation Demo ===\n")
    
    from xss_scanner import XSSPayloads
    
    payload_gen = XSSPayloads()
    
    # Show different payload categories
    print("Basic payloads:")
    for i, payload in enumerate(payload_gen.payloads['basic'][:3], 1):
        print(f"{i}. {payload}")
    
    print("\nWAF bypass payloads:")
    for i, payload in enumerate(payload_gen.payloads['waf_bypass'][:3], 1):
        print(f"{i}. {payload}")
    
    print("\nContext-specific payloads:")
    for context, payloads in payload_gen.payloads['context_specific'].items():
        print(f"{context.upper()}: {payloads[0]}")
    
    # Show encoding examples
    print("\nEncoding examples:")
    test_payload = '<script>alert("test")</script>'
    for encoding in ['url', 'html_entities', 'unicode']:
        encoded = payload_gen.encode_payload(test_payload, encoding)
        print(f"{encoding.upper()}: {encoded[:50]}...")

def main():
    """Main demo function"""
    if len(sys.argv) > 1:
        target = sys.argv[1]
        print(f"Running demo with target: {target}")
        demo_basic_scan()
    else:
        print("XSS Scanner Demo - Choose an option:")
        print("1. Basic scan demo")
        print("2. WAF bypass demo")
        print("3. Custom popup demo")
        print("4. Payload generation demo")
        print("5. Run all demos")
        
        choice = input("\nEnter choice (1-5): ").strip()
        
        if choice == '1':
            demo_basic_scan()
        elif choice == '2':
            demo_waf_bypass()
        elif choice == '3':
            demo_custom_popup()
        elif choice == '4':
            demo_payload_generation()
        elif choice == '5':
            demo_waf_bypass()
            print("\n" + "="*50 + "\n")
            demo_custom_popup()
            print("\n" + "="*50 + "\n")
            demo_payload_generation()
        else:
            print("Invalid choice!")

if __name__ == '__main__':
    import time
    main()