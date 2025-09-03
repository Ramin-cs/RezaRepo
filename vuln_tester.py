#!/usr/bin/env python3
"""
🔥 VULNERABILITY TESTER - Complete Testing Engine
"""

import asyncio
import re
import urllib.parse
from urllib.parse import urlparse, parse_qs, quote, unquote
from typing import List, Optional
from datetime import datetime
from data_models import Parameter, Vulnerability


class VulnTester:
    """Complete vulnerability testing engine"""
    
    def __init__(self, base_domain: str):
        self.base_domain = base_domain
    
    async def test_parameter(self, param: Parameter, payload: str, session) -> Optional[Vulnerability]:
        """Test parameter with payload"""
        try:
            test_url = self.construct_test_url(param, payload)
            
            async with session.get(test_url, allow_redirects=False) as response:
                if response.status in [301, 302, 303, 307, 308]:
                    location = response.headers.get('Location', '')
                    
                    if self.is_successful_redirect(location, payload):
                        return Vulnerability(
                            url=test_url,
                            parameter=param.name,
                            payload=payload,
                            method=param.method,
                            response_code=response.status,
                            redirect_url=location,
                            context=param.context,
                            timestamp=datetime.now().isoformat(),
                            vulnerability_type="open_redirect",
                            confidence=param.confidence + 0.2,
                            impact=self.assess_impact(location),
                            remediation=self.get_remediation(param.context),
                            cvss_score=self.calculate_cvss(param.context, location)
                        )
                
                # Check DOM-based
                content = await response.text()
                dom_vuln = self.check_dom_redirect(content, test_url, param, payload)
                if dom_vuln:
                    return dom_vuln
                    
        except:
            pass
        
        return None
    
    def construct_test_url(self, param: Parameter, payload: str) -> str:
        """Construct test URL"""
        parsed = urlparse(param.url)
        
        if param.context == 'query':
            query_params = parse_qs(parsed.query, keep_blank_values=True)
            query_params[param.name] = [payload]
            new_query = urllib.parse.urlencode(query_params, doseq=True)
            return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
        elif param.context == 'fragment':
            return f"{param.url.split('#')[0]}#{param.name}={quote(payload)}"
        else:
            separator = '&' if '?' in param.url else '?'
            return f"{param.url}{separator}{param.name}={quote(payload)}"
    
    def is_successful_redirect(self, location: str, payload: str) -> bool:
        """Check successful redirect"""
        if not location:
            return False
        
        location_lower = location.lower()
        decoded = unquote(location).lower()
        
        # Test domains
        test_domains = [
            'google.com', 'evil.com', 'malicious.com', 'metamask.io',
            'uniswap.org', 'opensea.io', '216.58.214.206', '3627734734'
        ]
        
        for domain in test_domains:
            if domain in location_lower or domain in decoded:
                return True
        
        # JavaScript
        if location_lower.startswith('javascript:') and 'confirm' in location_lower:
            return True
        
        # External domain
        if location.startswith(('http://', 'https://')):
            redirect_domain = urlparse(location).netloc
            if redirect_domain != self.base_domain:
                return True
        
        return False
    
    def check_dom_redirect(self, content: str, test_url: str, param: Parameter, payload: str) -> Optional[Vulnerability]:
        """Check DOM-based redirects"""
        dom_patterns = [
            r'location\.href\s*=\s*([^;]+)',
            r'window\.location\s*=\s*([^;]+)'
        ]
        
        for pattern in dom_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                if param.name in match or payload in match:
                    return Vulnerability(
                        url=test_url,
                        parameter=param.name,
                        payload=payload,
                        method=param.method,
                        response_code=200,
                        redirect_url=match,
                        context=param.context,
                        timestamp=datetime.now().isoformat(),
                        vulnerability_type="dom_based_redirect",
                        confidence=0.8,
                        impact="HIGH",
                        remediation="Sanitize user input before DOM manipulation"
                    )
        
        return None
    
    def assess_impact(self, redirect_url: str) -> str:
        """Assess impact"""
        if redirect_url.startswith('javascript:'):
            return "CRITICAL"
        elif redirect_url.startswith(('http://', 'https://')):
            return "HIGH"
        return "MEDIUM"
    
    def get_remediation(self, context: str) -> str:
        """Get remediation"""
        remediations = {
            'query': "Validate URL parameters against allowlist",
            'fragment': "Implement client-side validation",
            'form_input': "Validate form inputs server-side",
            'javascript': "Sanitize input before redirects",
            'web3_config': "Validate Web3 URLs against trusted providers"
        }
        return remediations.get(context, "Implement proper input validation")
    
    def calculate_cvss(self, context: str, redirect_url: str) -> float:
        """Calculate CVSS score"""
        base_score = 5.0
        
        if context in ['query', 'fragment']:
            base_score += 1.0
        
        if redirect_url.startswith('javascript:'):
            base_score += 2.0
        elif redirect_url.startswith(('http://', 'https://')):
            base_score += 1.0
        
        return min(base_score, 10.0)