#!/usr/bin/env python3
"""
🔥 JAVASCRIPT ANALYZER - Complete JS Analysis
"""

import re
import asyncio
from typing import List, Optional
from urllib.parse import urljoin
from data_models import Parameter


class JSModule:
    """Complete JavaScript analysis"""
    
    async def analyze_javascript(self, content: str, url: str, session) -> List[Parameter]:
        """Complete JavaScript analysis"""
        params = []
        
        # Extract inline scripts
        script_pattern = r'<script[^>]*>(.*?)</script>'
        scripts = re.findall(script_pattern, content, re.DOTALL | re.IGNORECASE)
        
        # External JS files
        src_pattern = r'<script[^>]*src=["\']([^"\']+)["\']'
        src_matches = re.findall(src_pattern, content, re.IGNORECASE)
        
        for src in src_matches:
            js_url = urljoin(url, src)
            js_content = await self.fetch_js_file(js_url, session)
            if js_content:
                scripts.append(js_content)
        
        # Analyze all JS
        for js_content in scripts:
            js_params = self.analyze_js_code(js_content, url)
            params.extend(js_params)
        
        return params
    
    async def fetch_js_file(self, js_url: str, session) -> Optional[str]:
        """Fetch JS file"""
        try:
            async with session.get(js_url) as response:
                if response.status == 200:
                    return await response.text()
        except:
            pass
        return None
    
    def analyze_js_code(self, js_content: str, source_url: str) -> List[Parameter]:
        """Analyze JS code"""
        params = []
        
        js_patterns = [
            r'location\.href\s*=\s*([^;]+)',
            r'window\.location\s*=\s*([^;]+)',
            r'location\.assign\(["\']?([^"\';\)]+)',
            r'URLSearchParams\([^)]*\)\.get\(["\']([^"\']+)["\']',
            r'localStorage\.getItem\(["\']([^"\']+)["\']',
            r'([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*["\']([^"\']*)["\']'
        ]
        
        lines = js_content.split('\n')
        for line_num, line in enumerate(lines, 1):
            for pattern in js_patterns:
                matches = re.finditer(pattern, line, re.IGNORECASE)
                for match in matches:
                    groups = match.groups()
                    if groups:
                        if len(groups) == 1:
                            param_name = f"js_param_{line_num}"
                            param_value = groups[0].strip('"\'')
                        else:
                            param_name = groups[0].strip('"\'')
                            param_value = groups[1].strip('"\'')
                        
                        is_redirect = self.is_redirect_param(param_name, param_value, line)
                        confidence = self.calculate_confidence(param_name, param_value, line)
                        
                        params.append(Parameter(
                            name=param_name,
                            value=param_value,
                            source='javascript',
                            context='js_variable',
                            url=source_url,
                            is_redirect_related=is_redirect,
                            confidence=confidence,
                            line_number=line_num
                        ))
        
        return params
    
    def is_redirect_param(self, param_name: str, param_value: str, line: str) -> bool:
        """Check if redirect parameter"""
        redirect_indicators = ['redirect', 'url', 'location', 'href']
        
        name_match = any(indicator in param_name.lower() for indicator in redirect_indicators)
        line_match = any(sink in line.lower() for sink in ['location.href', 'window.location'])
        
        return name_match or line_match
    
    def calculate_confidence(self, param_name: str, param_value: str, line: str) -> float:
        """Calculate confidence"""
        confidence = 0.4  # Base for JS
        
        if any(sink in line.lower() for sink in ['location.href', 'window.location']):
            confidence += 0.4
        
        if any(source in line.lower() for source in ['location.search', 'urlsearchparams']):
            confidence += 0.3
        
        return min(confidence, 1.0)