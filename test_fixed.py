#!/usr/bin/env python3
"""
Test fixed router brute force with improved validation
"""

import sys
import os
from router_brute_force_chrome import ChromeRouterBruteForce

def test_fixed_brute_force(url):
    """Test fixed brute force with improved validation"""
    print(f"Testing Fixed Brute Force: {url}")
    print("=" * 60)
    
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

def main():
    if len(sys.argv) != 2:
        print("Usage: python test_fixed.py <URL>")
        print("Example: python test_fixed.py http://111.220.143.231/")
        sys.exit(1)
    
    url = sys.argv[1]
    results = test_fixed_brute_force(url)
    
    if results:
        print(f"\n{Colors.GREEN}[+] Test completed successfully!{Colors.END}")
    else:
        print(f"\n{Colors.RED}[!] Test failed!{Colors.END}")

if __name__ == "__main__":
    main()