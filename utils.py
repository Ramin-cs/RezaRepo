#!/usr/bin/env python3
"""
Utility functions for Open Redirect Scanner
Contains helper functions for URL manipulation, encoding, and analysis
"""

import re
import urllib.parse
from urllib.parse import urlparse, urljoin, quote, unquote
import hashlib
import base64
import ipaddress
from typing import List, Dict, Set, Optional, Tuple
import logging


class URLUtils:
    """URL manipulation and analysis utilities"""
    
    @staticmethod
    def normalize_url(url: str) -> str:
        """Normalize URL for consistent processing"""
        if not url.startswith(('http://', 'https://')):
            url = f"https://{url}"
        
        parsed = urlparse(url)
        # Remove default ports
        netloc = parsed.netloc
        if netloc.endswith(':80') and parsed.scheme == 'http':
            netloc = netloc[:-3]
        elif netloc.endswith(':443') and parsed.scheme == 'https':
            netloc = netloc[:-4]
        
        return f"{parsed.scheme}://{netloc}{parsed.path}"
    
    @staticmethod
    def extract_domain(url: str) -> str:
        """Extract domain from URL"""
        try:
            return urlparse(url).netloc.lower()
        except:
            return ""
    
    @staticmethod
    def is_external_domain(url: str, base_domain: str) -> bool:
        """Check if URL points to external domain"""
        url_domain = URLUtils.extract_domain(url)
        return url_domain != base_domain.lower() and not url_domain.endswith(f'.{base_domain.lower()}')
    
    @staticmethod
    def decode_url_variations(url: str) -> List[str]:
        """Generate various decoded versions of URL"""
        variations = [url]
        
        try:
            # Standard URL decoding
            decoded = unquote(url)
            if decoded != url:
                variations.append(decoded)
            
            # Double decoding
            double_decoded = unquote(decoded)
            if double_decoded != decoded:
                variations.append(double_decoded)
            
            # HTML entity decoding
            import html
            html_decoded = html.unescape(url)
            if html_decoded != url:
                variations.append(html_decoded)
            
        except:
            pass
        
        return variations
    
    @staticmethod
    def generate_payload_variations(base_payload: str) -> List[str]:
        """Generate encoded variations of a payload"""
        variations = [base_payload]
        
        try:
            # URL encoding
            variations.append(quote(base_payload))
            variations.append(quote(base_payload, safe=''))
            
            # Double URL encoding
            variations.append(quote(quote(base_payload)))
            
            # HTML encoding
            import html
            variations.append(html.escape(base_payload))
            
            # Unicode encoding
            unicode_encoded = base_payload.encode('unicode_escape').decode('ascii')
            variations.append(unicode_encoded)
            
        except:
            pass
        
        return list(set(variations))


class PayloadGenerator:
    """Advanced payload generation for different contexts"""
    
    def __init__(self):
        self.test_domains = [
            'google.com', 'evil.com', 'attacker.com', 'malicious.site',
            'redirect-test.com', 'poc.security', 'test.example'
        ]
        
        self.ip_addresses = [
            '216.58.214.206',  # Google IP
            '8.8.8.8',         # Google DNS
            '1.1.1.1',         # Cloudflare DNS
            '127.0.0.1',       # Localhost
        ]
    
    def generate_basic_payloads(self, domain: str = 'google.com') -> List[str]:
        """Generate basic redirect payloads"""
        return [
            f"//{domain}",
            f"https://{domain}",
            f"http://{domain}",
            f"/{domain}",
            f".//{domain}",
            f"..//{domain}",
        ]
    
    def generate_encoded_payloads(self, domain: str = 'google.com') -> List[str]:
        """Generate encoded redirect payloads"""
        return [
            f"/%2f%2f{domain}",
            f"/%5c{domain}",
            f"%2f%2f{domain}",
            f"%68%74%74%70%3a%2f%2f{domain}",
            f"http://%{domain.encode('ascii').hex()}",
        ]
    
    def generate_protocol_bypass_payloads(self, domain: str = 'google.com') -> List[str]:
        """Generate protocol bypass payloads"""
        return [
            f"///{domain}",
            f"////{domain}",
            f"/////{domain}",
            f"https:{domain}",
            f"http:{domain}",
            f"ftp://{domain}",
        ]
    
    def generate_unicode_payloads(self, domain: str = 'google.com') -> List[str]:
        """Generate Unicode bypass payloads"""
        # Convert domain to various Unicode representations
        unicode_domain = domain.replace('.', '%E3%80%82')  # Unicode dot
        
        return [
            f"//{unicode_domain}",
            f"〱{domain}",
            f"〵{domain}",
            f"ゝ{domain}",
            f"ー{domain}",
            f"ｰ{domain}",
        ]
    
    def generate_ip_payloads(self) -> List[str]:
        """Generate IP-based payloads"""
        payloads = []
        
        for ip in self.ip_addresses:
            try:
                # Standard IP
                payloads.append(f"//{ip}")
                payloads.append(f"http://{ip}")
                
                # Hex representation
                ip_obj = ipaddress.IPv4Address(ip)
                hex_ip = hex(int(ip_obj))
                payloads.append(f"http://{hex_ip}")
                
                # Octal representation
                octets = ip.split('.')
                octal_ip = '.'.join([oct(int(octet)) for octet in octets])
                payloads.append(f"http://{octal_ip}")
                
                # Integer representation
                int_ip = int(ip_obj)
                payloads.append(f"http://{int_ip}")
                
            except:
                continue
        
        return payloads
    
    def generate_javascript_payloads(self) -> List[str]:
        """Generate JavaScript-based payloads"""
        return [
            "javascript:confirm(1)",
            "javascript:prompt(1)",
            "javascript:alert('Open Redirect')",
            "javascript:window.open('https://google.com')",
            "javascript:location.href='https://google.com'",
            "data:text/html,<script>alert('XSS')</script>",
            "data:text/html,<script>location.href='https://google.com'</script>",
        ]
    
    def generate_web3_payloads(self) -> List[str]:
        """Generate Web3-specific payloads"""
        return [
            "//metamask.io",
            "//wallet.connect",
            "//uniswap.org",
            "//opensea.io",
            "//etherscan.io",
            "web3://contract.eth",
            "ipfs://QmHash",
            "ens://vitalik.eth",
            "ethereum://0x1234567890123456789012345678901234567890",
        ]
    
    def generate_context_specific_payloads(self, context: str, domain: str = 'google.com') -> List[str]:
        """Generate payloads specific to context"""
        if context == 'query':
            return self.generate_basic_payloads(domain) + self.generate_encoded_payloads(domain)
        elif context == 'fragment':
            return [f"#{payload}" for payload in self.generate_basic_payloads(domain)]
        elif context == 'javascript':
            return self.generate_javascript_payloads()
        elif context == 'web3':
            return self.generate_web3_payloads()
        elif context == 'form':
            return self.generate_basic_payloads(domain) + self.generate_javascript_payloads()
        else:
            return self.generate_basic_payloads(domain)


class SecurityUtils:
    """Security-related utility functions"""
    
    @staticmethod
    def is_safe_url(url: str, allowed_domains: List[str]) -> bool:
        """Check if URL is safe (within allowed domains)"""
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            
            return any(domain == allowed.lower() or domain.endswith(f'.{allowed.lower()}') 
                      for allowed in allowed_domains)
        except:
            return False
    
    @staticmethod
    def detect_bypass_techniques(url: str) -> List[str]:
        """Detect bypass techniques used in URL"""
        techniques = []
        
        url_lower = url.lower()
        
        # Protocol bypasses
        if url.startswith('//'):
            techniques.append('protocol_relative')
        if url.count('/') > 3:
            techniques.append('multiple_slashes')
        
        # Encoding bypasses
        if '%' in url:
            techniques.append('url_encoding')
        if '\\' in url:
            techniques.append('backslash_bypass')
        
        # Unicode bypasses
        if any(ord(c) > 127 for c in url):
            techniques.append('unicode_bypass')
        
        # IP bypasses
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        if re.search(ip_pattern, url):
            techniques.append('ip_address')
        
        # Hex/Octal bypasses
        if '0x' in url_lower:
            techniques.append('hex_encoding')
        if re.search(r'0[0-7]+', url):
            techniques.append('octal_encoding')
        
        # JavaScript bypasses
        if url_lower.startswith('javascript:'):
            techniques.append('javascript_protocol')
        
        return techniques
    
    @staticmethod
    def calculate_risk_score(param_name: str, param_value: str, context: str) -> float:
        """Calculate risk score for parameter"""
        score = 0.0
        
        # Base score by parameter name
        high_risk_names = ['redirect', 'url', 'next', 'return', 'goto', 'location']
        medium_risk_names = ['link', 'href', 'target', 'destination', 'forward']
        
        param_lower = param_name.lower()
        if any(name in param_lower for name in high_risk_names):
            score += 0.4
        elif any(name in param_lower for name in medium_risk_names):
            score += 0.2
        
        # Score by parameter value
        if param_value:
            value_lower = param_value.lower()
            if value_lower.startswith(('http://', 'https://')):
                score += 0.3
            elif value_lower.startswith('//'):
                score += 0.25
            elif '.' in value_lower and len(value_lower) > 5:
                score += 0.15
        
        # Score by context
        context_scores = {
            'query': 0.2,
            'fragment': 0.25,
            'form_action': 0.3,
            'js_variable': 0.15,
            'http_header': 0.35
        }
        score += context_scores.get(context, 0.1)
        
        return min(score, 1.0)


class ReportUtils:
    """Report generation utilities"""
    
    @staticmethod
    def format_timestamp(timestamp: str) -> str:
        """Format timestamp for display"""
        try:
            dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
        except:
            return timestamp
    
    @staticmethod
    def truncate_text(text: str, max_length: int = 100) -> str:
        """Truncate text with ellipsis"""
        if len(text) <= max_length:
            return text
        return text[:max_length-3] + "..."
    
    @staticmethod
    def severity_color(severity: str) -> str:
        """Get color for severity level"""
        colors = {
            'CRITICAL': '#d32f2f',
            'HIGH': '#f44336',
            'MEDIUM': '#ff9800',
            'LOW': '#4caf50',
            'INFO': '#2196f3'
        }
        return colors.get(severity.upper(), '#666')
    
    @staticmethod
    def generate_executive_summary(vulnerabilities: List[Dict], parameters: List[Dict]) -> Dict[str, Any]:
        """Generate executive summary data"""
        total_vulns = len(vulnerabilities)
        total_params = len(parameters)
        
        # Categorize vulnerabilities by impact
        impact_counts = {}
        for vuln in vulnerabilities:
            impact = vuln.get('impact_assessment', 'UNKNOWN')
            impact_counts[impact] = impact_counts.get(impact, 0) + 1
        
        # Categorize parameters by source
        source_counts = {}
        for param in parameters:
            source = param.get('source', 'UNKNOWN')
            source_counts[source] = source_counts.get(source, 0) + 1
        
        return {
            'total_vulnerabilities': total_vulns,
            'total_parameters': total_params,
            'impact_distribution': impact_counts,
            'source_distribution': source_counts,
            'risk_level': 'HIGH' if total_vulns > 0 else 'LOW'
        }


class Web3Utils:
    """Web3-specific utility functions"""
    
    @staticmethod
    def is_web3_application(content: str) -> bool:
        """Detect if application uses Web3 technologies"""
        web3_indicators = [
            'web3', 'ethereum', 'metamask', 'wallet', 'dapp',
            'blockchain', 'crypto', 'nft', 'defi', 'contract',
            'ethers.js', 'web3.js', 'truffle', 'hardhat'
        ]
        
        content_lower = content.lower()
        return any(indicator in content_lower for indicator in web3_indicators)
    
    @staticmethod
    def extract_contract_addresses(content: str) -> List[str]:
        """Extract Ethereum contract addresses from content"""
        # Ethereum address pattern (0x followed by 40 hex characters)
        pattern = r'0x[a-fA-F0-9]{40}'
        return re.findall(pattern, content)
    
    @staticmethod
    def extract_ens_domains(content: str) -> List[str]:
        """Extract ENS domains from content"""
        # ENS domain pattern
        pattern = r'\b\w+\.eth\b'
        return re.findall(pattern, content, re.IGNORECASE)
    
    @staticmethod
    def detect_wallet_connections(js_content: str) -> List[Dict[str, Any]]:
        """Detect wallet connection patterns in JavaScript"""
        connections = []
        
        connection_patterns = [
            r'ethereum\.request\([^)]*\)',
            r'web3\.eth\.[^(]*\([^)]*\)',
            r'provider\.send\([^)]*\)',
            r'wallet\.connect\([^)]*\)',
            r'metamask\.request\([^)]*\)',
        ]
        
        lines = js_content.split('\n')
        for line_num, line in enumerate(lines, 1):
            for pattern in connection_patterns:
                matches = re.finditer(pattern, line, re.IGNORECASE)
                for match in matches:
                    connections.append({
                        'pattern': match.group(0),
                        'line_number': line_num,
                        'line_content': line.strip()
                    })
        
        return connections


class EncodingUtils:
    """Encoding and decoding utilities for bypass techniques"""
    
    @staticmethod
    def url_encode_variations(text: str) -> List[str]:
        """Generate various URL encoding variations"""
        variations = [text]
        
        # Standard encoding
        variations.append(quote(text))
        variations.append(quote(text, safe=''))
        
        # Double encoding
        variations.append(quote(quote(text)))
        
        # Mixed case encoding
        encoded = ""
        for char in text:
            if char.isalpha():
                hex_val = format(ord(char), 'x')
                encoded += f"%{hex_val}" if random.choice([True, False]) else f"%{hex_val.upper()}"
            else:
                encoded += char
        variations.append(encoded)
        
        return variations
    
    @staticmethod
    def unicode_encode_variations(text: str) -> List[str]:
        """Generate Unicode encoding variations"""
        variations = [text]
        
        try:
            # Unicode escape
            variations.append(text.encode('unicode_escape').decode('ascii'))
            
            # UTF-8 encoding
            utf8_encoded = ''.join([f'%{byte:02X}' for byte in text.encode('utf-8')])
            variations.append(utf8_encoded)
            
            # HTML entities
            import html
            variations.append(html.escape(text))
            
        except:
            pass
        
        return variations
    
    @staticmethod
    def generate_bypass_characters() -> Dict[str, List[str]]:
        """Generate character variations for bypassing filters"""
        return {
            '/': ['/', '%2f', '%2F', '\\', '%5c', '%5C', '%252f'],
            '.': ['.', '%2e', '%2E', '%252e', '。'],  # Last one is Unicode dot
            ':': [':', '%3a', '%3A', '%253a'],
            '?': ['?', '%3f', '%3F', '%253f'],
            '&': ['&', '%26', '%2526'],
            '#': ['#', '%23', '%2523'],
            ' ': [' ', '%20', '+', '%2B', '\t', '%09'],
        }


class ValidationUtils:
    """Input validation utilities"""
    
    @staticmethod
    def is_valid_url(url: str) -> bool:
        """Validate if string is a valid URL"""
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except:
            return False
    
    @staticmethod
    def sanitize_parameter_name(name: str) -> str:
        """Sanitize parameter name for safe usage"""
        # Remove dangerous characters
        sanitized = re.sub(r'[^a-zA-Z0-9_-]', '', name)
        return sanitized[:50]  # Limit length
    
    @staticmethod
    def is_suspicious_payload(payload: str) -> bool:
        """Check if payload contains suspicious patterns"""
        suspicious_patterns = [
            r'<script', r'javascript:', r'data:', r'vbscript:',
            r'file://', r'ftp://', r'gopher://',
            r'\\x[0-9a-f]{2}', r'%[0-9a-f]{2}'
        ]
        
        payload_lower = payload.lower()
        return any(re.search(pattern, payload_lower) for pattern in suspicious_patterns)


class PerformanceUtils:
    """Performance optimization utilities"""
    
    @staticmethod
    def batch_requests(items: List[Any], batch_size: int = 10) -> List[List[Any]]:
        """Batch items for parallel processing"""
        batches = []
        for i in range(0, len(items), batch_size):
            batches.append(items[i:i + batch_size])
        return batches
    
    @staticmethod
    def calculate_delay(request_count: int, max_rps: int = 10) -> float:
        """Calculate delay for rate limiting"""
        if max_rps <= 0:
            return 0.1
        return max(0.1, 1.0 / max_rps)
    
    @staticmethod
    def should_skip_url(url: str, skip_extensions: List[str] = None) -> bool:
        """Determine if URL should be skipped"""
        if skip_extensions is None:
            skip_extensions = [
                '.jpg', '.jpeg', '.png', '.gif', '.svg', '.ico',
                '.css', '.js', '.pdf', '.zip', '.tar', '.gz',
                '.mp4', '.avi', '.mov', '.mp3', '.wav'
            ]
        
        parsed = urlparse(url)
        path_lower = parsed.path.lower()
        
        return any(path_lower.endswith(ext) for ext in skip_extensions)


# Export all utility classes
__all__ = [
    'URLUtils', 'PayloadGenerator', 'EncodingUtils', 
    'ValidationUtils', 'PerformanceUtils', 'Web3Utils', 'SecurityUtils'
]