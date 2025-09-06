#!/usr/bin/env python3
"""
Example usage of Advanced XSS Scanner
This file demonstrates various ways to use the XSS scanner
"""

import time
import json
from xss_scanner import XSSScanner
from waf_bypass import WAFBypassEngine
from custom_popup import CustomPopupSystem

def example_basic_scan():
    """Example: Basic XSS scan"""
    print("=== Example: Basic XSS Scan ===\n")
    
    # Target URL (replace with your test target)
    target = "https://httpbin.org/get"
    
    # Basic scanner with default options
    scanner = XSSScanner(target)
    
    print(f"Scanning: {target}")
    results = scanner.run_scan()
    
    # Print summary
    print(f"Scan completed!")
    print(f"Vulnerabilities found: {results['summary']['total_vulnerabilities']}")
    
    return results

def example_advanced_scan():
    """Example: Advanced scan with custom options"""
    print("=== Example: Advanced XSS Scan ===\n")
    
    target = "https://httpbin.org/get"
    
    # Custom options
    options = {
        'crawl': True,  # Enable URL crawling
        'callback_url': 'http://your-server.com/callback'  # For blind XSS
    }
    
    scanner = XSSScanner(target, options)
    
    print(f"Advanced scanning: {target}")
    print("Options:")
    for key, value in options.items():
        print(f"  {key}: {value}")
    
    results = scanner.run_scan()
    
    # Save detailed report
    report_file = f"advanced_scan_report_{int(time.time())}.json"
    scanner.save_report(results, report_file)
    
    print(f"Report saved to: {report_file}")
    return results

def example_waf_bypass():
    """Example: WAF bypass demonstration"""
    print("=== Example: WAF Bypass ===\n")
    
    # Initialize WAF bypass engine
    waf_engine = WAFBypassEngine()
    
    # Test payload
    payload = '<script>alert("XSS")</script>'
    print(f"Original payload: {payload}")
    
    # Simulate WAF detection
    waf_info = {
        'detected': True,
        'type': 'cloudflare',
        'bypass_methods': ['encoding', 'case_variation', 'comment_injection']
    }
    
    # Generate bypass payloads
    bypass_payloads = waf_engine.generate_bypass_payloads(payload, waf_info)
    
    print(f"\nGenerated {len(bypass_payloads)} bypass variants:")
    for i, bypass_payload in enumerate(bypass_payloads[:5], 1):
        print(f"{i}. {bypass_payload}")
    
    print(f"... and {len(bypass_payloads) - 5} more variants")
    
    return bypass_payloads

def example_custom_popup():
    """Example: Custom popup system"""
    print("=== Example: Custom Popup System ===\n")
    
    # Initialize popup system
    popup_system = CustomPopupSystem()
    
    print(f"Popup ID: {popup_system.popup_id}")
    
    # Generate popup payloads
    popup_payloads = popup_system.generate_popup_payload("Custom verification message!")
    
    print(f"Generated {len(popup_payloads)} popup payload variants:")
    for i, payload in enumerate(popup_payloads[:3], 1):
        print(f"{i}. {payload[:80]}...")
    
    # Generate stealth payloads
    stealth_payloads = popup_system.generate_stealth_payload('<script>alert("test")</script>')
    
    print(f"\nGenerated {len(stealth_payloads)} stealth payload variants:")
    for i, payload in enumerate(stealth_payloads[:3], 1):
        print(f"{i}. {payload[:80]}...")
    
    return popup_payloads, stealth_payloads

def example_context_aware_payloads():
    """Example: Context-aware payload generation"""
    print("=== Example: Context-Aware Payloads ===\n")
    
    from xss_scanner import XSSPayloads
    
    payload_gen = XSSPayloads()
    
    # Different contexts
    contexts = ['html', 'attribute', 'javascript', 'css', 'url']
    
    for context in contexts:
        print(f"{context.upper()} Context:")
        payloads = payload_gen.get_payloads_by_context(context)
        for i, payload in enumerate(payloads[:2], 1):
            print(f"  {i}. {payload}")
        print()

def example_encoding_variations():
    """Example: Payload encoding variations"""
    print("=== Example: Encoding Variations ===\n")
    
    from xss_scanner import XSSPayloads
    
    payload_gen = XSSPayloads()
    test_payload = '<script>alert("XSS")</script>'
    
    print(f"Original payload: {test_payload}")
    print("\nEncoded variants:")
    
    encodings = ['url', 'html_entities', 'unicode', 'base64', 'hex', 'mixed']
    
    for encoding in encodings:
        encoded = payload_gen.encode_payload(test_payload, encoding)
        print(f"{encoding.upper()}: {encoded}")
        print()

def example_comprehensive_scan():
    """Example: Comprehensive scan with all features"""
    print("=== Example: Comprehensive XSS Scan ===\n")
    
    target = "https://httpbin.org/get"
    
    # Full-featured options
    options = {
        'crawl': True,
        'callback_url': 'http://localhost:8080/callback',
        'max_depth': 2,
        'timeout': 30
    }
    
    print(f"Comprehensive scan of: {target}")
    print("Features enabled:")
    print("  ✓ Full reconnaissance")
    print("  ✓ URL crawling")
    print("  ✓ WAF detection & bypass")
    print("  ✓ Custom popup verification")
    print("  ✓ Screenshot capture")
    print("  ✓ All XSS types (Reflected, Stored, DOM, Blind)")
    print()
    
    scanner = XSSScanner(target, options)
    
    start_time = time.time()
    results = scanner.run_scan()
    end_time = time.time()
    
    # Detailed results
    print(f"Scan completed in {end_time - start_time:.2f} seconds")
    print("\n=== Detailed Results ===")
    
    # Reconnaissance results
    recon = results.get('reconnaissance', {})
    print(f"Parameters discovered: {len(recon.get('discovered_params', []))}")
    print(f"Forms discovered: {len(recon.get('discovered_forms', []))}")
    print(f"URLs discovered: {len(recon.get('discovered_urls', []))}")
    
    # WAF detection
    waf_info = recon.get('waf_detected', {})
    if waf_info.get('detected'):
        print(f"WAF detected: {waf_info.get('type', 'Unknown')}")
    else:
        print("No WAF detected")
    
    # Vulnerabilities
    vulns = results.get('vulnerabilities', [])
    print(f"\nVulnerabilities found: {len(vulns)}")
    
    for i, vuln in enumerate(vulns, 1):
        print(f"\n{i}. {vuln['type']}")
        print(f"   Parameter: {vuln.get('parameter', 'N/A')}")
        print(f"   Payload: {vuln.get('payload', 'N/A')[:60]}...")
        if vuln.get('waf_bypassed'):
            print(f"   WAF Bypassed: {vuln.get('waf_type', 'Unknown')}")
        if vuln.get('poc_screenshot'):
            print(f"   Screenshot: {vuln['poc_screenshot']}")
    
    # Save comprehensive report
    report_file = f"comprehensive_scan_{int(time.time())}.json"
    scanner.save_report(results, report_file)
    print(f"\nComprehensive report saved to: {report_file}")
    
    return results

def example_targeted_scan():
    """Example: Targeted scan for specific vulnerability types"""
    print("=== Example: Targeted XSS Scan ===\n")
    
    target = "https://httpbin.org/get"
    
    # Custom scanner for specific testing
    scanner = XSSScanner(target)
    
    # Run only reconnaissance first
    print("Running reconnaissance...")
    recon_results = scanner.run_reconnaissance()
    
    print(f"Discovered {len(recon_results['discovered_params'])} parameters")
    print(f"Discovered {len(recon_results['discovered_forms'])} forms")
    
    # Test only reflected XSS
    print("\nTesting Reflected XSS only...")
    reflected_results = scanner.test_reflected_xss(recon_results)
    
    print(f"Reflected XSS vulnerabilities: {len(reflected_results)}")
    
    # Test only stored XSS
    print("\nTesting Stored XSS only...")
    stored_results = scanner.test_stored_xss(recon_results)
    
    print(f"Stored XSS vulnerabilities: {len(stored_results)}")
    
    # Combine results
    all_results = reflected_results + stored_results
    
    print(f"\nTotal vulnerabilities found: {len(all_results)}")
    
    return all_results

def main():
    """Main function to run examples"""
    print("Advanced XSS Scanner - Usage Examples\n")
    
    examples = [
        ("Basic Scan", example_basic_scan),
        ("Advanced Scan", example_advanced_scan),
        ("WAF Bypass", example_waf_bypass),
        ("Custom Popup", example_custom_popup),
        ("Context-Aware Payloads", example_context_aware_payloads),
        ("Encoding Variations", example_encoding_variations),
        ("Targeted Scan", example_targeted_scan),
        ("Comprehensive Scan", example_comprehensive_scan),
    ]
    
    print("Available examples:")
    for i, (name, _) in enumerate(examples, 1):
        print(f"{i}. {name}")
    
    print(f"{len(examples) + 1}. Run all examples")
    print("0. Exit")
    
    try:
        choice = int(input(f"\nSelect example (0-{len(examples) + 1}): "))
        
        if choice == 0:
            print("Goodbye!")
            return
        
        if choice == len(examples) + 1:
            # Run all examples
            for name, example_func in examples:
                print(f"\n{'='*60}")
                print(f"Running: {name}")
                print('='*60)
                try:
                    example_func()
                    print(f"✓ {name} completed successfully")
                except Exception as e:
                    print(f"✗ {name} failed: {e}")
                time.sleep(1)
        elif 1 <= choice <= len(examples):
            # Run selected example
            name, example_func = examples[choice - 1]
            print(f"\n{'='*60}")
            print(f"Running: {name}")
            print('='*60)
            try:
                example_func()
                print(f"✓ {name} completed successfully")
            except Exception as e:
                print(f"✗ {name} failed: {e}")
        else:
            print("Invalid choice!")
            
    except ValueError:
        print("Please enter a valid number!")
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")

if __name__ == '__main__':
    main()