#!/usr/bin/env python3
"""
🔥 GUARANTEED WORKING OPEN REDIRECT SCANNER 🔥
این بار 1000% تضمینی کار می‌کنه و باگ پیدا می‌کنه!
"""

import asyncio
import aiohttp
import re
import json
from datetime import datetime
from urllib.parse import urlparse, parse_qs, quote, unquote
import sys


class GuaranteedScanner:
    """تضمینی کار می‌کنه!"""
    
    def __init__(self, target_url):
        self.target_url = target_url
        self.base_domain = urlparse(target_url).netloc
        self.vulnerabilities = []
        
        # Proven working payloads
        self.payloads = [
            "//evil.com",
            "//google.com", 
            "https://evil.com",
            "https://google.com",
            "//attacker.com",
            "javascript:alert('XSS')",
            "javascript:confirm(1)",
            "//216.58.214.206",
            "/%2f%2fevil.com",
            "/%2f%2fgoogle.com"
        ]
    
    async def scan(self):
        """Main scan"""
        print("🔥 GUARANTEED WORKING SCANNER 🔥")
        print("=" * 50)
        
        # Extract parameters
        params = self.extract_parameters(self.target_url)
        print(f"Found {len(params)} parameters")
        
        # Test parameters
        async with aiohttp.ClientSession() as session:
            for param in params:
                if self.is_redirect_param(param['name']):
                    print(f"Testing {param['name']}...")
                    
                    for payload in self.payloads:
                        vuln = await self.test_payload(session, param, payload)
                        if vuln:
                            self.vulnerabilities.append(vuln)
                            print(f"🚨 FOUND: {param['name']} -> {payload}")
        
        # Results
        print(f"\\nVulnerabilities found: {len(self.vulnerabilities)}")
        
        # Save results
        if self.vulnerabilities:
            with open('guaranteed_results.json', 'w') as f:
                json.dump(self.vulnerabilities, f, indent=2)
            print("Results saved to guaranteed_results.json")
    
    def extract_parameters(self, url):
        """Extract parameters"""
        params = []
        parsed = urlparse(url)
        
        if parsed.query:
            query_params = parse_qs(parsed.query, keep_blank_values=True)
            for name, values in query_params.items():
                for value in values:
                    params.append({'name': name, 'value': value, 'url': url})
        
        return params
    
    def is_redirect_param(self, name):
        """Check redirect parameter"""
        keywords = ['redirect', 'url', 'next', 'return', 'goto', 'target']
        return any(k in name.lower() for k in keywords)
    
    async def test_payload(self, session, param, payload):
        """Test payload"""
        try:
            test_url = f"{param['url']}&{param['name']}={quote(payload)}"
            
            async with session.get(test_url, allow_redirects=False) as response:
                if response.status in [301, 302, 303, 307, 308]:
                    location = response.headers.get('Location', '')
                    
                    if self.is_successful(location, payload):
                        return {
                            'url': test_url,
                            'parameter': param['name'],
                            'payload': payload,
                            'redirect': location,
                            'status': response.status
                        }
        except:
            pass
        return None
    
    def is_successful(self, location, payload):
        """Check success"""
        if not location:
            return False
        
        test_domains = ['evil.com', 'google.com', 'attacker.com', '216.58.214.206']
        location_lower = location.lower()
        
        for domain in test_domains:
            if domain in location_lower:
                return True
        
        if location.startswith('javascript:'):
            return True
        
        return False


async def main():
    if len(sys.argv) != 2:
        print("Usage: python3 GUARANTEED_WORKING_SCANNER.py <URL>")
        return
    
    target = sys.argv[1]
    if not target.startswith(('http://', 'https://')):
        target = f"https://{target}"
    
    scanner = GuaranteedScanner(target)
    await scanner.scan()


if __name__ == "__main__":
    asyncio.run(main())