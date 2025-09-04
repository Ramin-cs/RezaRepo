#!/usr/bin/env python3
"""
🔥 DOM-BASED REDIRECT ANALYZER - Complete Client-Side Analysis
"""

import re
import asyncio
from typing import List, Dict, Optional
from urllib.parse import urlparse, unquote
from data_models import Parameter, Vulnerability


class DOMAnalyzer:
    """Complete DOM-based redirect analyzer"""
    
    def __init__(self, base_domain: str):
        self.base_domain = base_domain
        
        # DOM redirect sinks
        self.redirect_sinks = [
            'location.href', 'location.assign', 'location.replace',
            'window.location', 'window.location.href', 'window.open',
            'document.location', 'document.location.href',
            'history.pushState', 'history.replaceState'
        ]
        
        # DOM sources
        self.dom_sources = [
            'location.search', 'location.hash', 'location.href',
            'document.URL', 'document.documentURI', 'document.baseURI',
            'window.name', 'document.referrer', 'history.state'
        ]
        
        # Advanced patterns for DOM analysis
        self.dom_patterns = [
            # Direct assignment patterns
            r'(location\.href|window\.location)\s*=\s*([^;]+)',
            r'(location\.assign|location\.replace)\s*\(\s*([^)]+)\s*\)',
            r'window\.open\s*\(\s*([^,)]+)',
            
            # Indirect assignment patterns
            r'(\w+)\s*=\s*(location\.search|location\.hash)[^;]*;\s*(?:location\.href|window\.location)\s*=\s*\1',
            
            # Framework-specific patterns
            r'(?:router\.push|router\.replace|navigate)\s*\(\s*([^)]+)\s*\)',
            r'\$location\.url\s*\(\s*([^)]+)\s*\)',  # AngularJS
            r'window\.location\.assign\s*\(\s*([^)]+)\s*\)',
            
            # Event handler patterns
            r'onclick\s*=\s*["\'](?:location\.href|window\.location)\s*=\s*([^"\']+)["\']',
            
            # Template literal patterns
            r'(?:location\.href|window\.location)\s*=\s*`([^`]+)`',
        ]
    
    async def analyze_dom_redirects(self, content: str, url: str) -> List[Parameter]:
        """Analyze DOM-based redirects"""
        params = []
        
        print(f"[DOM-ANALYZER] Scanning {url} for client-side redirects...")
        
        # Extract all script content
        script_contents = self.extract_script_content(content)
        
        for script_content in script_contents:
            # Analyze each script for DOM redirects
            dom_params = self.analyze_script_for_redirects(script_content, url)
            params.extend(dom_params)
        
        # Analyze inline event handlers
        inline_params = self.analyze_inline_handlers(content, url)
        params.extend(inline_params)
        
        print(f"[DOM-ANALYZER] Found {len(params)} DOM parameters in {url}")
        return params
    
    def extract_script_content(self, content: str) -> List[str]:
        """Extract all script content"""
        scripts = []
        
        # Inline scripts
        script_pattern = r'<script[^>]*>(.*?)</script>'
        inline_scripts = re.findall(script_pattern, content, re.DOTALL | re.IGNORECASE)
        scripts.extend(inline_scripts)
        
        # Event handlers
        event_pattern = r'on\w+\s*=\s*["\']([^"\']+)["\']'
        event_handlers = re.findall(event_pattern, content, re.IGNORECASE)
        scripts.extend(event_handlers)
        
        return scripts
    
    def analyze_script_for_redirects(self, script_content: str, url: str) -> List[Parameter]:
        """Analyze script for redirect patterns"""
        params = []
        
        lines = script_content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            if not line:
                continue
            
            # Check each DOM pattern
            for pattern in self.dom_patterns:
                matches = re.finditer(pattern, line, re.IGNORECASE)
                
                for match in matches:
                    # Analyze the match
                    dom_param = self.analyze_dom_match(match, line, url, line_num)
                    if dom_param:
                        params.append(dom_param)
        
        return params
    
    def analyze_dom_match(self, match, line: str, url: str, line_num: int) -> Optional[Parameter]:
        """Analyze DOM redirect match"""
        groups = match.groups()
        if not groups:
            return None
        
        # Extract sink and source
        if len(groups) >= 2:
            sink = groups[0]
            source_expr = groups[1]
        else:
            sink = "unknown"
            source_expr = groups[0]
        
        # Check if source is user-controlled
        user_controlled = self.is_user_controlled_source(source_expr, line)
        
        if user_controlled:
            # Extract parameter name
            param_name = self.extract_param_name(source_expr, line)
            
            # Calculate confidence
            confidence = self.calculate_dom_confidence(sink, source_expr, line)
            
            return Parameter(
                name=param_name,
                value=source_expr,
                source='dom_analysis',
                context='dom_sink',
                url=url,
                method='GET',
                is_redirect_related=True,
                confidence=confidence,
                line_number=line_num,
                pattern_matched=f"dom:{sink}"
            )
        
        return None
    
    def is_user_controlled_source(self, source_expr: str, line: str) -> bool:
        """Check if source is user-controlled"""
        user_controlled_patterns = [
            r'location\.search', r'location\.hash', r'location\.href',
            r'document\.URL', r'window\.name', r'document\.referrer',
            r'URLSearchParams', r'getParameter', r'getQueryString',
            r'window\.location\.search', r'window\.location\.hash'
        ]
        
        for pattern in user_controlled_patterns:
            if re.search(pattern, source_expr, re.IGNORECASE):
                return True
        
        # Check if variable is assigned from user-controlled source
        var_pattern = r'(\w+)\s*=\s*(?:' + '|'.join(user_controlled_patterns) + ')'
        var_matches = re.findall(var_pattern, line, re.IGNORECASE)
        
        for var_name in var_matches:
            if var_name in source_expr:
                return True
        
        return False
    
    def extract_param_name(self, source_expr: str, line: str) -> str:
        """Extract parameter name from source expression"""
        # URLSearchParams.get('param')
        urlsearch_pattern = r'URLSearchParams[^)]*\.get\(["\']([^"\']+)["\']'
        match = re.search(urlsearch_pattern, source_expr, re.IGNORECASE)
        if match:
            return match.group(1)
        
        # getParameter('param')
        getparam_pattern = r'getParameter\(["\']([^"\']+)["\']'
        match = re.search(getparam_pattern, source_expr, re.IGNORECASE)
        if match:
            return match.group(1)
        
        # Variable name extraction
        var_pattern = r'(\w+)(?:\[|\.|$)'
        match = re.search(var_pattern, source_expr)
        if match:
            return match.group(1)
        
        # Default
        return f"dom_param_{abs(hash(source_expr)) % 1000}"
    
    def calculate_dom_confidence(self, sink: str, source_expr: str, line: str) -> float:
        """Calculate DOM confidence"""
        confidence = 0.5  # Base for DOM
        
        # High-risk sinks
        high_risk_sinks = ['location.href', 'window.location', 'location.assign']
        if any(sink_pattern in sink.lower() for sink_pattern in high_risk_sinks):
            confidence += 0.3
        
        # Direct user input
        if any(source in source_expr.lower() for source in ['location.search', 'location.hash']):
            confidence += 0.3
        
        # URLSearchParams usage
        if 'URLSearchParams' in source_expr:
            confidence += 0.2
        
        return min(confidence, 1.0)
    
    def analyze_inline_handlers(self, content: str, url: str) -> List[Parameter]:
        """Analyze inline event handlers"""
        params = []
        
        # Inline onclick handlers with redirects
        onclick_pattern = r'onclick\s*=\s*["\']([^"\']*(?:location|redirect)[^"\']*)["\']'
        matches = re.findall(onclick_pattern, content, re.IGNORECASE)
        
        for handler_code in matches:
            if any(sink in handler_code.lower() for sink in ['location.href', 'window.location']):
                param_name = f"onclick_redirect_{abs(hash(handler_code)) % 1000}"
                
                params.append(Parameter(
                    name=param_name,
                    value=handler_code,
                    source='inline_handler',
                    context='dom_event',
                    url=url,
                    method='GET',
                    is_redirect_related=True,
                    confidence=0.8,
                    pattern_matched="inline:onclick"
                ))
        
        return params
    
    async def test_dom_vulnerability(self, param: Parameter, payload: str, session) -> Optional[Vulnerability]:
        """Test DOM-based vulnerability"""
        try:
            # For DOM testing, we need to check if the parameter affects client-side behavior
            test_url = self.construct_dom_test_url(param, payload)
            
            async with session.get(test_url, allow_redirects=False) as response:
                content = await response.text()
                
                # Check if payload appears in dangerous contexts
                dangerous_contexts = [
                    f'location.href = "{payload}"',
                    f"location.href = '{payload}'",
                    f'window.location = "{payload}"',
                    f"window.location = '{payload}'",
                    f'location.assign("{payload}")',
                    f"location.assign('{payload}')"
                ]
                
                for context in dangerous_contexts:
                    if context in content or payload in content:
                        return Vulnerability(
                            url=test_url,
                            parameter=param.name,
                            payload=payload,
                            method=param.method,
                            response_code=response.status,
                            redirect_url=payload,
                            context=param.context,
                            timestamp="",
                            vulnerability_type="dom_based_redirect",
                            confidence=0.9,
                            impact="HIGH",
                            remediation="Implement client-side input validation and use allowlisted redirect URLs",
                            cvss_score=7.5,
                            exploitation_complexity="LOW",
                            business_impact="Phishing attacks, credential theft"
                        )
        except:
            pass
        
        return None
    
    def construct_dom_test_url(self, param: Parameter, payload: str) -> str:
        """Construct DOM test URL"""
        if param.context == 'fragment':
            return f"{param.url.split('#')[0]}#{param.name}={payload}"
        else:
            separator = '&' if '?' in param.url else '?'
            return f"{param.url}{separator}{param.name}={payload}"
    
    def generate_dom_report(self, params: List[Parameter]) -> Dict:
        """Generate DOM analysis report"""
        dom_params = [p for p in params if p.source in ['dom_analysis', 'inline_handler']]
        
        return {
            'total_dom_parameters': len(dom_params),
            'high_risk_dom': len([p for p in dom_params if p.confidence > 0.8]),
            'dom_sinks_found': len(set(p.pattern_matched for p in dom_params)),
            'client_side_risks': len([p for p in dom_params if p.context in ['dom_sink', 'dom_event']])
        }