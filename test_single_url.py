#!/usr/bin/env python3
"""
Test single URL with Router Brute Force Chrome
"""

import sys
import os
from router_brute_force_chrome import ChromeRouterBruteForce

def test_single_url(url):
    """Test a single URL"""
    print(f"Testing URL: {url}")
    print("=" * 60)
    
    # Create brute force instance
    brute_force = ChromeRouterBruteForce([url], threads=1, timeout=15, headless=False, enable_screenshot=True)
    
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

def main():
    if len(sys.argv) != 2:
        print("Usage: python test_single_url.py <URL>")
        print("Example: python test_single_url.py http://192.168.1.1")
        sys.exit(1)
    
    url = sys.argv[1]
    results = test_single_url(url)
    
    if results:
        print(f"\n{Colors.GREEN}[+] Test completed successfully!{Colors.END}")
    else:
        print(f"\n{Colors.RED}[!] Test failed!{Colors.END}")

if __name__ == "__main__":
    main()