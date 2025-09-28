#!/usr/bin/env python3
"""
Quick XSS Scanner - Minimal Dependencies
Author: AI Assistant
"""

import urllib.request
import urllib.parse
import sys

def scan_xss(url):
    """Quick XSS scan"""
    print(f"[INFO] Scanning: {url}")
    
    # XSS payloads
    payloads = [
        '<script>alert("XSS")</script>',
        '<img src=x onerror=alert("XSS")>',
        '<svg onload=alert("XSS")>'
    ]
    
    vulnerabilities = []
    
    try:
        # Test URL parameters
        parsed_url = urllib.parse.urlparse(url)
        query_params = urllib.parse.parse_qs(parsed_url.query)
        
        for param_name in query_params:
            print(f"[TEST] Testing parameter: {param_name}")
            
            for payload in payloads:
                # Create test URL
                test_params = query_params.copy()
                test_params[param_name] = [payload]
                
                new_query = urllib.parse.urlencode(test_params, doseq=True)
                test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{new_query}"
                
                # Make request
                req = urllib.request.Request(test_url)
                req.add_header('User-Agent', 'Mozilla/5.0')
                
                try:
                    response = urllib.request.urlopen(req, timeout=10)
                    content = response.read().decode('utf-8', errors='ignore')
                    
                    # Check for XSS reflection
                    if payload in content:
                        vuln = {
                            'url': test_url,
                            'parameter': param_name,
                            'payload': payload,
                            'type': 'reflected_xss'
                        }
                        vulnerabilities.append(vuln)
                        print(f"[VULN] XSS found in parameter: {param_name}")
                        break
                        
                except Exception as e:
                    print(f"[ERROR] Request failed: {e}")
    
    except Exception as e:
        print(f"[ERROR] Scan failed: {e}")
    
    # Show results
    print("\n" + "="*50)
    print("SCAN RESULTS")
    print("="*50)
    print(f"Total vulnerabilities: {len(vulnerabilities)}")
    
    if vulnerabilities:
        for i, vuln in enumerate(vulnerabilities, 1):
            print(f"\nVulnerability #{i}:")
            print(f"  Type: {vuln['type']}")
            print(f"  Parameter: {vuln['parameter']}")
            print(f"  URL: {vuln['url']}")
            print(f"  Payload: {vuln['payload']}")
    else:
        print("No vulnerabilities found")
    
    return vulnerabilities

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 quick_xss_scanner.py <URL>")
        print("Example: python3 quick_xss_scanner.py http://testphp.vulnweb.com/search.php?test=query")
        sys.exit(1)
    
    target_url = sys.argv[1]
    scan_xss(target_url)