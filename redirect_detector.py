#!/usr/bin/env python3
"""
🔥 REDIRECT DETECTOR - Advanced Redirect Pattern Detection
"""

import re
import asyncio
from typing import List, Dict, Set, Optional, Tuple
from urllib.parse import urlparse, unquote
from dataclasses import dataclass, field


@dataclass
class RedirectPattern:
    """Detected redirect pattern"""
    pattern_type: str  # url_based, js_based, meta_based, header_based
    location: str      # where the pattern was found
    confidence: float
    payload_compatible: bool
    description: str
    test_parameters: List[str] = field(default_factory=list)


class RedirectDetector:
    """Advanced redirect pattern detector"""
    
    def __init__(self):
        # URL-based redirect patterns
        self.url_patterns = [
            r'redirect=([^&]+)',
            r'url=([^&]+)', 
            r'next=([^&]+)',
            r'return=([^&]+)',
            r'goto=([^&]+)',
            r'target=([^&]+)',
            r'callback=([^&]+)',
            r'success_url=([^&]+)',
            r'failure_url=([^&]+)'
        ]
        
        # JavaScript redirect patterns
        self.js_redirect_patterns = [
            r'location\.href\s*=\s*([^;]+)',
            r'window\.location\s*=\s*([^;]+)',
            r'location\.assign\s*\(\s*([^)]+)\s*\)',
            r'location\.replace\s*\(\s*([^)]+)\s*\)',
            r'window\.open\s*\(\s*([^,)]+)',
            r'document\.location\s*=\s*([^;]+)'
        ]
        
        # Meta redirect patterns  
        self.meta_patterns = [
            r'<meta[^>]*http-equiv=["\']refresh["\'][^>]*content=["\'][^"\']*url=([^"\';\s]+)',
            r'<meta[^>]*content=["\'][^"\']*url=([^"\';\s]+)["\'][^>]*http-equiv=["\']refresh["\']'
        ]
        
        # Header redirect patterns
        self.header_patterns = [
            'Location', 'Refresh', 'Link'
        ]
    
    async def detect_redirect_patterns(self, response_data: Dict) -> List[RedirectPattern]:
        """Detect all redirect patterns in response"""
        patterns = []
        url = response_data['url']
        content = response_data['content']
        headers = response_data['headers']
        
        # Detect URL-based patterns
        url_patterns = self._detect_url_patterns(url)
        patterns.extend(url_patterns)
        
        # Detect JavaScript patterns
        js_patterns = self._detect_js_patterns(content, url)
        patterns.extend(js_patterns)
        
        # Detect meta patterns
        meta_patterns = self._detect_meta_patterns(content, url)
        patterns.extend(meta_patterns)
        
        # Detect header patterns
        header_patterns = self._detect_header_patterns(headers, url)
        patterns.extend(header_patterns)
        
        print(f"[REDIRECT-DETECTOR] Found {len(patterns)} redirect patterns")
        return patterns
    
    def _detect_url_patterns(self, url: str) -> List[RedirectPattern]:
        """Detect URL-based redirect patterns"""
        patterns = []
        
        for pattern in self.url_patterns:
            matches = re.findall(pattern, url, re.IGNORECASE)
            for match in matches:
                param_name = pattern.split('=')[0].replace('(', '').replace('[^&]+)', '')
                
                patterns.append(RedirectPattern(
                    pattern_type='url_based',
                    location=f"URL parameter: {param_name}",
                    confidence=0.9,
                    payload_compatible=True,
                    description=f"URL parameter '{param_name}' accepts redirect values",
                    test_parameters=[param_name]
                ))
        
        return patterns
    
    def _detect_js_patterns(self, content: str, url: str) -> List[RedirectPattern]:
        """Detect JavaScript redirect patterns"""
        patterns = []
        
        for pattern in self.js_redirect_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                sink = match.group(0).split('=')[0].strip()
                value = match.group(1).strip() if match.groups() else ""
                
                # Check if value comes from user input
                user_controlled = self._is_user_controlled(value, content)
                
                patterns.append(RedirectPattern(
                    pattern_type='js_based',
                    location=f"JavaScript: {sink}",
                    confidence=0.8 if user_controlled else 0.4,
                    payload_compatible=user_controlled,
                    description=f"JavaScript redirect using {sink}",
                    test_parameters=self._extract_js_parameters(value, content)
                ))
        
        return patterns
    
    def _detect_meta_patterns(self, content: str, url: str) -> List[RedirectPattern]:
        """Detect meta refresh redirect patterns"""
        patterns = []
        
        for pattern in self.meta_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                redirect_url = match.group(1) if match.groups() else ""
                
                patterns.append(RedirectPattern(
                    pattern_type='meta_based',
                    location="Meta refresh tag",
                    confidence=0.7,
                    payload_compatible=False,  # Usually hardcoded
                    description=f"Meta refresh redirect to: {redirect_url}",
                    test_parameters=[]
                ))
        
        return patterns
    
    def _detect_header_patterns(self, headers: Dict[str, str], url: str) -> List[RedirectPattern]:
        """Detect header-based redirect patterns"""
        patterns = []
        
        for header_name in self.header_patterns:
            if header_name in headers:
                header_value = headers[header_name]
                
                patterns.append(RedirectPattern(
                    pattern_type='header_based',
                    location=f"HTTP header: {header_name}",
                    confidence=0.95,
                    payload_compatible=True,
                    description=f"Server sends redirect via {header_name} header",
                    test_parameters=[header_name.lower()]
                ))
        
        return patterns
    
    def _is_user_controlled(self, value: str, content: str) -> bool:
        """Check if JavaScript value comes from user input"""
        user_sources = [
            'location.search', 'location.hash', 'URLSearchParams',
            'getParameter', 'document.URL', 'window.location'
        ]
        
        return any(source in value for source in user_sources)
    
    def _extract_js_parameters(self, value: str, content: str) -> List[str]:
        """Extract parameter names from JavaScript value"""
        params = []
        
        # Look for URLSearchParams.get('param')
        param_pattern = r'get\s*\(\s*["\']([^"\']+)["\']'
        matches = re.findall(param_pattern, value)
        params.extend(matches)
        
        # Look for variable names that might be parameters
        var_pattern = r'([a-zA-Z_$][a-zA-Z0-9_$]*(?:url|redirect|next|return)[a-zA-Z0-9_$]*)'
        var_matches = re.findall(var_pattern, value, re.IGNORECASE)
        params.extend(var_matches)
        
        return list(set(params))
    
    def get_testable_patterns(self, patterns: List[RedirectPattern]) -> List[RedirectPattern]:
        """Get patterns that can be tested with payloads"""
        return [p for p in patterns if p.payload_compatible]
    
    def get_high_confidence_patterns(self, patterns: List[RedirectPattern], threshold: float = 0.7) -> List[RedirectPattern]:
        """Get high confidence patterns"""
        return [p for p in patterns if p.confidence >= threshold]
    
    def generate_test_cases(self, patterns: List[RedirectPattern]) -> List[Dict]:
        """Generate test cases from detected patterns"""
        test_cases = []
        
        for pattern in patterns:
            if pattern.payload_compatible and pattern.test_parameters:
                for param in pattern.test_parameters:
                    test_case = {
                        'parameter': param,
                        'pattern_type': pattern.pattern_type,
                        'confidence': pattern.confidence,
                        'description': pattern.description,
                        'location': pattern.location
                    }
                    test_cases.append(test_case)
        
        return test_cases