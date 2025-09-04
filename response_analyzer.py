#!/usr/bin/env python3
"""
🔥 RESPONSE ANALYZER - Advanced Response Analysis
"""

import re
from typing import List, Dict, Set, Optional, Tuple
from urllib.parse import urlparse, unquote
from dataclasses import dataclass, field


@dataclass
class ResponseAnalysis:
    """Response analysis result"""
    url: str
    status_code: int
    headers: Dict[str, str]
    content: str
    is_redirect: bool = False
    redirect_url: Optional[str] = None
    redirect_type: Optional[str] = None  # http, javascript, meta
    vulnerability_indicators: List[str] = field(default_factory=list)
    security_headers: Dict[str, str] = field(default_factory=dict)
    content_type: str = ""
    content_length: int = 0
    response_time: float = 0.0
    is_vulnerable: bool = False
    confidence: float = 0.0


class ResponseAnalyzer:
    """Advanced response analyzer for vulnerability detection"""
    
    def __init__(self, base_domain: str):
        self.base_domain = base_domain
        
        # HTTP redirect status codes
        self.redirect_codes = [301, 302, 303, 307, 308]
        
        # JavaScript redirect patterns
        self.js_redirect_patterns = [
            r'location\.href\s*=\s*["\']([^"\']+)["\']',
            r'window\.location\s*=\s*["\']([^"\']+)["\']',
            r'location\.assign\s*\(\s*["\']([^"\']+)["\']',
            r'location\.replace\s*\(\s*["\']([^"\']+)["\']',
            r'window\.open\s*\(\s*["\']([^"\']+)["\']'
        ]
        
        # Meta refresh patterns
        self.meta_patterns = [
            r'<meta[^>]*http-equiv=["\']refresh["\'][^>]*content=["\'][^"\']*url=([^"\';\s]+)',
            r'<meta[^>]*content=["\'][^"\']*url=([^"\';\s]+)["\'][^>]*http-equiv=["\']refresh["\']'
        ]
        
        # Security headers to check
        self.security_headers = [
            'Content-Security-Policy',
            'X-Frame-Options', 
            'X-Content-Type-Options',
            'Strict-Transport-Security',
            'Referrer-Policy',
            'Permissions-Policy',
            'X-XSS-Protection'
        ]
        
        # Vulnerability indicators
        self.vuln_indicators = [
            # Open redirect indicators
            r'redirect.*success',
            r'url.*valid',
            r'location.*change',
            
            # Error messages that might indicate processing
            r'invalid.*url',
            r'malformed.*redirect',
            r'unauthorized.*redirect',
            
            # Debug information
            r'debug.*redirect',
            r'trace.*redirect',
            
            # Framework-specific indicators
            r'rails.*redirect',
            r'django.*redirect',
            r'spring.*redirect'
        ]
    
    def analyze_response(self, response_data: Dict, payload: str = "") -> ResponseAnalysis:
        """Comprehensive response analysis"""
        analysis = ResponseAnalysis(
            url=response_data['url'],
            status_code=response_data['status'],
            headers=response_data['headers'],
            content=response_data['content'],
            content_type=response_data['headers'].get('Content-Type', ''),
            content_length=len(response_data['content']),
            response_time=response_data.get('response_time', 0.0)
        )
        
        # Analyze redirects
        self._analyze_redirects(analysis, payload)
        
        # Extract security headers
        self._extract_security_headers(analysis)
        
        # Look for vulnerability indicators
        self._find_vulnerability_indicators(analysis, payload)
        
        # Calculate vulnerability confidence
        analysis.confidence = self._calculate_confidence(analysis, payload)
        analysis.is_vulnerable = analysis.confidence > 0.6
        
        return analysis
    
    def _analyze_redirects(self, analysis: ResponseAnalysis, payload: str = ""):
        """Analyze different types of redirects"""
        # HTTP redirects
        if analysis.status_code in self.redirect_codes:
            analysis.is_redirect = True
            analysis.redirect_type = 'http'
            analysis.redirect_url = analysis.headers.get('Location', '')
            
            if self._is_successful_redirect(analysis.redirect_url, payload):
                analysis.vulnerability_indicators.append('HTTP redirect to external domain')
        
        # JavaScript redirects
        js_redirects = self._find_js_redirects(analysis.content)
        if js_redirects:
            for redirect_url in js_redirects:
                if self._is_successful_redirect(redirect_url, payload):
                    analysis.is_redirect = True
                    analysis.redirect_type = 'javascript'
                    analysis.redirect_url = redirect_url
                    analysis.vulnerability_indicators.append('JavaScript redirect to external domain')
        
        # Meta refresh redirects
        meta_redirects = self._find_meta_redirects(analysis.content)
        if meta_redirects:
            for redirect_url in meta_redirects:
                if self._is_successful_redirect(redirect_url, payload):
                    analysis.is_redirect = True
                    analysis.redirect_type = 'meta'
                    analysis.redirect_url = redirect_url
                    analysis.vulnerability_indicators.append('Meta refresh redirect to external domain')
    
    def _find_js_redirects(self, content: str) -> List[str]:
        """Find JavaScript redirects in content"""
        redirects = []
        
        for pattern in self.js_redirect_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            redirects.extend(matches)
        
        return redirects
    
    def _find_meta_redirects(self, content: str) -> List[str]:
        """Find meta refresh redirects in content"""
        redirects = []
        
        for pattern in self.meta_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            redirects.extend(matches)
        
        return redirects
    
    def _is_successful_redirect(self, redirect_url: str, payload: str) -> bool:
        """Check if redirect indicates successful exploitation"""
        if not redirect_url:
            return False
        
        redirect_lower = redirect_url.lower()
        payload_lower = payload.lower()
        
        # Test domains that indicate successful redirect
        test_domains = [
            'google.com', 'evil.com', 'attacker.com', 'malicious.com',
            '216.58.214.206', '3627734734', 'fake-metamask.io',
            'phishing-opensea.io', 'malicious-compound.finance'
        ]
        
        # Check if any test domain appears in redirect URL
        for domain in test_domains:
            if domain in redirect_lower:
                return True
        
        # Check if payload domain appears in redirect
        if payload_lower:
            # Extract domain from payload
            if '//' in payload_lower:
                try:
                    domain_part = payload_lower.split('//')[1].split('/')[0]
                    if domain_part in redirect_lower:
                        return True
                except:
                    pass
        
        # JavaScript execution
        if redirect_lower.startswith('javascript:'):
            return True
        
        # Data URLs
        if redirect_lower.startswith('data:'):
            return True
        
        # External domain check
        if redirect_url.startswith(('http://', 'https://')):
            try:
                redirect_domain = urlparse(redirect_url).netloc
                if redirect_domain and redirect_domain.lower() != self.base_domain.lower():
                    return True
            except:
                pass
        
        return False
    
    def _extract_security_headers(self, analysis: ResponseAnalysis):
        """Extract security headers from response"""
        for header in self.security_headers:
            if header in analysis.headers:
                analysis.security_headers[header] = analysis.headers[header]
    
    def _find_vulnerability_indicators(self, analysis: ResponseAnalysis, payload: str):
        """Find vulnerability indicators in response"""
        content_lower = analysis.content.lower()
        
        # Check for vulnerability indicators in content
        for pattern in self.vuln_indicators:
            if re.search(pattern, content_lower):
                analysis.vulnerability_indicators.append(f"Content indicator: {pattern}")
        
        # Check for payload reflection
        if payload and payload.lower() in content_lower:
            analysis.vulnerability_indicators.append("Payload reflected in response")
        
        # Check for error messages
        error_patterns = [
            r'error.*redirect',
            r'exception.*redirect', 
            r'warning.*redirect',
            r'invalid.*parameter',
            r'malformed.*request'
        ]
        
        for pattern in error_patterns:
            if re.search(pattern, content_lower):
                analysis.vulnerability_indicators.append(f"Error indicator: {pattern}")
        
        # Check response headers for indicators
        for header_name, header_value in analysis.headers.items():
            if 'redirect' in header_name.lower() or 'location' in header_name.lower():
                analysis.vulnerability_indicators.append(f"Redirect header: {header_name}")
        
        # Check for missing security headers
        missing_headers = []
        for header in self.security_headers:
            if header not in analysis.headers:
                missing_headers.append(header)
        
        if missing_headers:
            analysis.vulnerability_indicators.append(f"Missing security headers: {', '.join(missing_headers)}")
    
    def _calculate_confidence(self, analysis: ResponseAnalysis, payload: str) -> float:
        """Calculate vulnerability confidence score"""
        confidence = 0.0
        
        # High confidence for successful redirects
        if analysis.is_redirect and analysis.redirect_url:
            if self._is_successful_redirect(analysis.redirect_url, payload):
                confidence += 0.8
        
        # Medium confidence for vulnerability indicators
        confidence += len(analysis.vulnerability_indicators) * 0.1
        
        # Boost for specific redirect types
        if analysis.redirect_type == 'http':
            confidence += 0.2
        elif analysis.redirect_type == 'javascript':
            confidence += 0.3  # Higher risk
        elif analysis.redirect_type == 'meta':
            confidence += 0.1
        
        # Reduce confidence for security headers presence
        if analysis.security_headers:
            confidence -= len(analysis.security_headers) * 0.05
        
        # Boost for payload reflection
        if payload and payload.lower() in analysis.content.lower():
            confidence += 0.2
        
        # Boost for specific status codes
        if analysis.status_code in [301, 302]:
            confidence += 0.1
        elif analysis.status_code in [307, 308]:
            confidence += 0.15  # Permanent redirects more suspicious
        
        return min(confidence, 1.0)
    
    def batch_analyze_responses(self, responses: List[Dict], payloads: List[str] = None) -> List[ResponseAnalysis]:
        """Analyze multiple responses"""
        analyses = []
        
        for i, response in enumerate(responses):
            payload = payloads[i] if payloads and i < len(payloads) else ""
            analysis = self.analyze_response(response, payload)
            analyses.append(analysis)
        
        return analyses
    
    def get_vulnerable_responses(self, analyses: List[ResponseAnalysis], threshold: float = 0.6) -> List[ResponseAnalysis]:
        """Get responses that indicate vulnerabilities"""
        return [a for a in analyses if a.confidence >= threshold]
    
    def get_redirect_responses(self, analyses: List[ResponseAnalysis]) -> List[ResponseAnalysis]:
        """Get responses that contain redirects"""
        return [a for a in analyses if a.is_redirect]
    
    def generate_response_report(self, analyses: List[ResponseAnalysis]) -> Dict:
        """Generate comprehensive response analysis report"""
        if not analyses:
            return {}
        
        vulnerable_responses = self.get_vulnerable_responses(analyses)
        redirect_responses = self.get_redirect_responses(analyses)
        
        # Status code distribution
        status_dist = {}
        for analysis in analyses:
            status_dist[analysis.status_code] = status_dist.get(analysis.status_code, 0) + 1
        
        # Redirect type distribution
        redirect_types = {}
        for analysis in redirect_responses:
            if analysis.redirect_type:
                redirect_types[analysis.redirect_type] = redirect_types.get(analysis.redirect_type, 0) + 1
        
        # Security header analysis
        security_header_stats = {}
        for header in self.security_headers:
            count = sum(1 for a in analyses if header in a.security_headers)
            security_header_stats[header] = {
                'present': count,
                'missing': len(analyses) - count,
                'percentage': (count / len(analyses)) * 100
            }
        
        # Vulnerability indicators frequency
        all_indicators = []
        for analysis in analyses:
            all_indicators.extend(analysis.vulnerability_indicators)
        
        indicator_counts = {}
        for indicator in all_indicators:
            indicator_counts[indicator] = indicator_counts.get(indicator, 0) + 1
        
        top_indicators = sorted(indicator_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        
        return {
            'summary': {
                'total_responses': len(analyses),
                'vulnerable_responses': len(vulnerable_responses),
                'redirect_responses': len(redirect_responses),
                'average_confidence': sum(a.confidence for a in analyses) / len(analyses),
                'average_response_time': sum(a.response_time for a in analyses) / len(analyses)
            },
            'status_code_distribution': status_dist,
            'redirect_type_distribution': redirect_types,
            'security_headers': security_header_stats,
            'top_vulnerability_indicators': top_indicators,
            'vulnerable_details': [
                {
                    'url': a.url,
                    'confidence': a.confidence,
                    'redirect_type': a.redirect_type,
                    'redirect_url': a.redirect_url,
                    'indicators': a.vulnerability_indicators,
                    'status_code': a.status_code
                }
                for a in vulnerable_responses
            ]
        }