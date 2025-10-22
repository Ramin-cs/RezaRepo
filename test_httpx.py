#!/usr/bin/env python3
"""
Test script for httpx functionality
"""

import sys
import os
sys.path.append('/workspace')

from subdomains import HttpxProbe, Colors
import time

def test_httpx_probe():
    print(f"{Colors.CYAN}🧪 Testing httpx functionality...{Colors.END}")
    
    # Test domains
    test_domains = [
        'www.google.com',
        'httpbin.org',
        'example.com'
    ]
    
    prober = HttpxProbe(timeout=5, threads=3)
    
    for domain in test_domains:
        print(f"\n{Colors.YELLOW}🔍 Probing: {domain}{Colors.END}")
        
        results = prober.probe_url(domain, protocols=['http', 'https'])
        
        for protocol, result in results.items():
            if 'error' not in result:
                status_code = result['status_code']
                title = result['title']
                response_time = result['response_time']
                
                category, color = prober.categorize_status_code(status_code)
                
                print(f"  ✅ {protocol.upper()}://{domain} {color}[{status_code}]{Colors.END} [{response_time}ms] {title}")
            else:
                print(f"  ❌ {protocol.upper()}://{domain} - {result['error']}")

if __name__ == "__main__":
    test_httpx_probe()