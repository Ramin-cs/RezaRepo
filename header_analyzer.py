#!/usr/bin/env python3
"""
🔥 HTTP HEADER ANALYZER - Complete Header Analysis
"""

import asyncio
import re
from typing import List, Dict, Optional
from data_models import Parameter, Vulnerability


class HeaderAnalyzer:
    """Complete HTTP header analysis"""
    
    def __init__(self, base_domain: str):
        self.base_domain = base_domain
        
        # Redirect headers
        self.redirect_headers = {
            'Location': 0.95,
            'Refresh': 0.9,
            'Link': 0.7,
            'X-Redirect-To': 0.8,
            'X-Forward-To': 0.8,
            'X-Accel-Redirect': 0.85,
            'X-Sendfile': 0.6,
            'X-Lighttpd-Send-File': 0.6,
            'X-Nginx-Redirect': 0.8,
            'X-Apache-Redirect': 0.8
        }
        
        # Custom header patterns
        self.custom_patterns = [
            r'X-([A-Za-z-]*[Rr]edirect[A-Za-z-]*)',
            r'X-([A-Za-z-]*[Ff]orward[A-Za-z-]*)',
            r'X-([A-Za-z-]*[Ll]ocation[A-Za-z-]*)',
            r'X-([A-Za-z-]*[Uu]rl[A-Za-z-]*)',
        ]
        
        # Header injection payloads
        self.header_payloads = [
            "//evil.com",
            "https://evil.com",
            "http://evil.com",
            "//google.com",
            "javascript:confirm(1)"
        ]
    
    async def analyze_headers(self, headers: Dict[str, str], url: str) -> List[Parameter]:
        """Analyze HTTP headers for redirect parameters"""
        params = []
        
        print(f"[HEADER-ANALYZER] Analyzing {len(headers)} headers from {url}")
        
        # Check standard redirect headers
        for header_name, header_value in headers.items():
            confidence = self.redirect_headers.get(header_name, 0.0)
            
            if confidence > 0:
                params.append(Parameter(
                    name=header_name.lower(),
                    value=header_value,
                    source='http_header',
                    context='redirect_header',
                    url=url,
                    method='GET',
                    is_redirect_related=True,
                    confidence=confidence,
                    pattern_matched=f"standard:{header_name}"
                ))
        
        # Check custom redirect headers
        for header_name, header_value in headers.items():
            for pattern in self.custom_patterns:
                if re.match(pattern, header_name, re.IGNORECASE):
                    params.append(Parameter(
                        name=header_name.lower(),
                        value=header_value,
                        source='http_header',
                        context='custom_header',
                        url=url,
                        method='GET',
                        is_redirect_related=True,
                        confidence=0.7,
                        pattern_matched=f"custom:{pattern}"
                    ))
        
        # Analyze header values for parameters
        header_value_params = self.analyze_header_values(headers, url)
        params.extend(header_value_params)
        
        return params
    
    def analyze_header_values(self, headers: Dict[str, str], url: str) -> List[Parameter]:
        """Analyze header values for embedded parameters"""
        params = []
        
        for header_name, header_value in headers.items():
            # Check if header value contains URL parameters
            if '?' in header_value and '=' in header_value:
                # Parse parameters from header value
                try:
                    if header_value.startswith(('http://', 'https://')):
                        parsed_url = urlparse(header_value)
                        if parsed_url.query:
                            query_params = parse_qs(parsed_url.query, keep_blank_values=True)
                            
                            for param_name, param_values in query_params.items():
                                for value in param_values:
                                    params.append(Parameter(
                                        name=param_name,
                                        value=value,
                                        source='header_embedded',
                                        context='header_url_param',
                                        url=url,
                                        method='GET',
                                        is_redirect_related=True,
                                        confidence=0.8,
                                        pattern_matched=f"header_embed:{header_name}"
                                    ))
                except:
                    pass
            
            # Check for base64 encoded URLs in headers
            if len(header_value) > 20 and header_value.replace('=', '').replace('+', '').replace('/', '').isalnum():
                try:
                    import base64
                    decoded = base64.b64decode(header_value + '===').decode('utf-8', errors='ignore')
                    if decoded.startswith(('http://', 'https://', '//')):
                        params.append(Parameter(
                            name=f"{header_name.lower()}_decoded",
                            value=decoded,
                            source='header_base64',
                            context='encoded_header',
                            url=url,
                            method='GET',
                            is_redirect_related=True,
                            confidence=0.85,
                            pattern_matched=f"base64:{header_name}"
                        ))
                except:
                    pass
        
        return params
    
    async def test_header_injection(self, param: Parameter, payload: str, session) -> Optional[Vulnerability]:
        """Test header injection vulnerability"""
        try:
            # Construct injection headers
            injection_headers = {param.name: payload}
            
            async with session.get(param.url, headers=injection_headers, allow_redirects=False) as response:
                # Check if our injected header affects the response
                location = response.headers.get('Location', '')
                
                if location and payload in location:
                    return Vulnerability(
                        url=param.url,
                        parameter=param.name,
                        payload=payload,
                        method='GET',
                        response_code=response.status,
                        redirect_url=location,
                        context=param.context,
                        timestamp="",
                        vulnerability_type="header_injection_redirect",
                        confidence=0.95,
                        impact="CRITICAL",
                        remediation="Validate and sanitize all HTTP headers",
                        cvss_score=8.5,
                        exploitation_complexity="LOW",
                        business_impact="Full request routing control"
                    )
        except:
            pass
        
        return None
    
    def analyze_security_headers(self, headers: Dict[str, str]) -> Dict[str, any]:
        """Analyze security headers"""
        security_analysis = {
            'missing_headers': [],
            'weak_headers': [],
            'bypass_opportunities': []
        }
        
        # Critical security headers
        critical_headers = {
            'Content-Security-Policy': r'frame-ancestors|script-src',
            'X-Frame-Options': r'DENY|SAMEORIGIN',
            'X-Content-Type-Options': r'nosniff',
            'Referrer-Policy': r'strict-origin',
            'Permissions-Policy': r'geolocation|microphone'
        }
        
        for header_name, expected_pattern in critical_headers.items():
            header_value = headers.get(header_name, '')
            
            if not header_value:
                security_analysis['missing_headers'].append(header_name)
            elif not re.search(expected_pattern, header_value, re.IGNORECASE):
                security_analysis['weak_headers'].append({
                    'header': header_name,
                    'value': header_value,
                    'weakness': 'Insufficient protection'
                })
        
        # Check for bypass opportunities
        if 'X-Frame-Options' not in headers and 'Content-Security-Policy' not in headers:
            security_analysis['bypass_opportunities'].append('No clickjacking protection')
        
        return security_analysis
    
    def generate_header_report(self, all_headers: List[Dict], security_analysis: Dict) -> Dict:
        """Generate comprehensive header report"""
        unique_headers = set()
        redirect_headers_found = []
        
        for headers in all_headers:
            unique_headers.update(headers.keys())
            
            for header_name in headers.keys():
                if header_name in self.redirect_headers:
                    redirect_headers_found.append({
                        'name': header_name,
                        'value': headers[header_name],
                        'risk_level': self.redirect_headers[header_name]
                    })
        
        return {
            'total_unique_headers': len(unique_headers),
            'redirect_headers_found': len(redirect_headers_found),
            'redirect_headers_details': redirect_headers_found,
            'security_analysis': security_analysis,
            'header_injection_points': len([h for h in redirect_headers_found if h['risk_level'] > 0.8])
        }