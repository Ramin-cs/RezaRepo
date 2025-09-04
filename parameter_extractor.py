#!/usr/bin/env python3
"""
🔥 ADVANCED PARAMETER EXTRACTOR - Complete Parameter Discovery
"""

import re
import json
import base64
from typing import List, Dict, Set, Optional
from urllib.parse import urlparse, parse_qs, unquote, quote
from dataclasses import dataclass
from datetime import datetime

try:
    from bs4 import BeautifulSoup, Comment
    BS4_OK = True
except ImportError:
    BS4_OK = False


@dataclass
class ExtractedParameter:
    """Extracted parameter data structure"""
    name: str
    value: str
    source: str  # url, form, javascript, meta, cookie, header, config
    context: str  # query, fragment, input, variable, attribute, etc.
    url: str
    method: str = 'GET'
    confidence: float = 0.0
    is_redirect_related: bool = False
    extraction_method: str = ""
    line_number: Optional[int] = None
    pattern_matched: str = ""
    additional_info: Dict = None
    
    def __post_init__(self):
        if self.additional_info is None:
            self.additional_info = {}


class ParameterExtractor:
    """Advanced parameter extraction from all possible sources"""
    
    def __init__(self):
        # Redirect-related keywords for detection
        self.redirect_keywords = {
            'redirect', 'url', 'next', 'return', 'goto', 'target', 'destination',
            'continue', 'forward', 'redir', 'location', 'site', 'link', 'href',
            'returnurl', 'back', 'callback', 'success_url', 'failure_url',
            'cancel_url', 'exit_url', 'logout_url', 'login_redirect', 'referrer',
            'referer', 'source', 'from', 'origin', 'returnto', 'backurl',
            'successurl', 'errorurl', 'redirecturl', 'redirecturi', 'redirect_uri'
        }
        
        # JavaScript patterns for parameter extraction
        self.js_patterns = [
            # Variable assignments
            r'(?:var|let|const)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*["\']([^"\']*(?:redirect|url|next|return)[^"\']*)["\']',
            
            # Object properties
            r'["\']?([a-zA-Z_][a-zA-Z0-9_]*(?:url|redirect|next|return)[a-zA-Z0-9_]*)["\']?\s*:\s*["\']([^"\']+)["\']',
            
            # Function parameters
            r'function\s+\w*\([^)]*([a-zA-Z_$][a-zA-Z0-9_$]*(?:Url|Redirect|Next)[a-zA-Z0-9_$]*)[^)]*\)',
            
            # URLSearchParams
            r'URLSearchParams[^)]*\.get\(["\']([^"\']+)["\']',
            r'searchParams\.get\(["\']([^"\']+)["\']',
            
            # Location manipulation
            r'location\.(?:href|search|hash)\s*=\s*([^;]+)',
            r'window\.location\s*=\s*([^;]+)',
            
            # localStorage/sessionStorage
            r'(?:localStorage|sessionStorage)\.(?:getItem|setItem)\(["\']([^"\']*(?:redirect|url)[^"\']*)["\']',
            
            # Cookie access
            r'document\.cookie\s*=\s*["\']([^"\']*(?:redirect|url)[^"\']*)["\']',
            
            # AJAX/Fetch parameters
            r'(?:fetch|ajax|post|get)\(["\']?[^"\']*["\']?,\s*\{[^}]*["\']([^"\']*(?:redirect|url)[^"\']*)["\']',
            
            # Configuration objects
            r'(?:config|settings|options)\s*[:\[]\s*\{[^}]*["\']([^"\']*(?:redirect|url)[^"\']*)["\']?\s*:\s*["\']([^"\']+)["\']'
        ]
        
        # Meta tag patterns
        self.meta_patterns = [
            r'<meta[^>]*http-equiv=["\']refresh["\'][^>]*content=["\'][^"\']*url=([^"\';\s]+)',
            r'<meta[^>]*name=["\']([^"\']*redirect[^"\']*)["\'][^>]*content=["\']([^"\']+)["\']',
            r'<meta[^>]*property=["\']([^"\']*redirect[^"\']*)["\'][^>]*content=["\']([^"\']+)["\']'
        ]
        
        # Data attribute patterns
        self.data_patterns = [
            r'data-([a-zA-Z-]*(?:redirect|url|next|return)[a-zA-Z-]*)\s*=\s*["\']([^"\']+)["\']',
            r'data-([a-zA-Z-]*)\s*=\s*["\']([^"\']*(?:redirect|url|next|return)[^"\']*)["\']'
        ]
        
        # Configuration patterns (JSON-like)
        self.config_patterns = [
            r'(?:window\.|global\.|app\.)config\s*=\s*(\{[^}]+\})',
            r'(?:const|var|let)\s+config\s*=\s*(\{[^}]+\})',
            r'redirectConfig\s*[:=]\s*(\{[^}]+\})',
            r'urlConfig\s*[:=]\s*(\{[^}]+\})'
        ]
    
    async def extract_all_parameters(self, response_data: Dict) -> List[ExtractedParameter]:
        """Extract parameters from all sources"""
        parameters = []
        url = response_data['url']
        content = response_data['content']
        headers = response_data['headers']
        
        print(f"[PARAM-EXTRACTOR] Extracting from {url}")
        
        # Extract from URL
        url_params = self.extract_url_parameters(url)
        parameters.extend(url_params)
        
        # Extract from HTML forms
        form_params = self.extract_form_parameters(content, url)
        parameters.extend(form_params)
        
        # Extract from JavaScript
        js_params = self.extract_javascript_parameters(content, url)
        parameters.extend(js_params)
        
        # Extract from meta tags
        meta_params = self.extract_meta_parameters(content, url)
        parameters.extend(meta_params)
        
        # Extract from data attributes
        data_params = self.extract_data_attributes(content, url)
        parameters.extend(data_params)
        
        # Extract from configuration objects
        config_params = self.extract_config_parameters(content, url)
        parameters.extend(config_params)
        
        # Extract from HTTP headers
        header_params = self.extract_header_parameters(headers, url)
        parameters.extend(header_params)
        
        # Extract from comments
        comment_params = self.extract_comment_parameters(content, url)
        parameters.extend(comment_params)
        
        # Calculate confidence scores
        for param in parameters:
            param.confidence = self.calculate_confidence(param)
            param.is_redirect_related = self.is_redirect_related(param.name, param.value)
        
        print(f"[PARAM-EXTRACTOR] Found {len(parameters)} parameters")
        return parameters
    
    def extract_url_parameters(self, url: str) -> List[ExtractedParameter]:
        """Extract parameters from URL"""
        parameters = []
        parsed = urlparse(url)
        
        # Query parameters
        if parsed.query:
            query_params = parse_qs(parsed.query, keep_blank_values=True)
            for name, values in query_params.items():
                for value in values:
                    parameters.append(ExtractedParameter(
                        name=name,
                        value=value,
                        source='url',
                        context='query',
                        url=url,
                        method='GET',
                        extraction_method='urlparse',
                        pattern_matched=f"query:{name}={value}"
                    ))
        
        # Fragment parameters
        if parsed.fragment:
            fragment = unquote(parsed.fragment)
            
            # Try to parse as query string
            if '=' in fragment:
                try:
                    fragment_params = parse_qs(fragment, keep_blank_values=True)
                    for name, values in fragment_params.items():
                        for value in values:
                            parameters.append(ExtractedParameter(
                                name=name,
                                value=value,
                                source='url',
                                context='fragment',
                                url=url,
                                method='GET',
                                extraction_method='fragment_parse',
                                pattern_matched=f"fragment:{name}={value}"
                            ))
                except:
                    # Treat entire fragment as a parameter
                    parameters.append(ExtractedParameter(
                        name='fragment',
                        value=fragment,
                        source='url',
                        context='fragment',
                        url=url,
                        method='GET',
                        extraction_method='fragment_raw',
                        pattern_matched=f"fragment:{fragment}"
                    ))
        
        return parameters
    
    def extract_form_parameters(self, content: str, url: str) -> List[ExtractedParameter]:
        """Extract parameters from HTML forms"""
        parameters = []
        
        if BS4_OK:
            soup = BeautifulSoup(content, 'html.parser')
            
            for form in soup.find_all('form'):
                method = form.get('method', 'GET').upper()
                action = form.get('action', '')
                form_url = url if not action else urljoin(url, action)
                
                # Extract input fields
                for input_tag in form.find_all(['input', 'select', 'textarea']):
                    name = input_tag.get('name')
                    if not name:
                        continue
                    
                    value = input_tag.get('value', '')
                    input_type = input_tag.get('type', 'text')
                    
                    parameters.append(ExtractedParameter(
                        name=name,
                        value=value,
                        source='form',
                        context='input',
                        url=form_url,
                        method=method,
                        extraction_method='beautifulsoup',
                        pattern_matched=f"form:{input_type}:{name}",
                        additional_info={
                            'input_type': input_type,
                            'form_action': action,
                            'form_method': method
                        }
                    ))
        else:
            # Regex fallback
            form_pattern = r'<form[^>]*>(.*?)</form>'
            input_pattern = r'<input[^>]*name=["\']([^"\']+)["\'][^>]*(?:value=["\']([^"\']*)["\'])?[^>]*>'
            
            forms = re.findall(form_pattern, content, re.DOTALL | re.IGNORECASE)
            for form_content in forms:
                inputs = re.findall(input_pattern, form_content, re.IGNORECASE)
                for name, value in inputs:
                    parameters.append(ExtractedParameter(
                        name=name,
                        value=value,
                        source='form',
                        context='input',
                        url=url,
                        method='GET',
                        extraction_method='regex',
                        pattern_matched=f"form:{name}={value}"
                    ))
        
        return parameters
    
    def extract_javascript_parameters(self, content: str, url: str) -> List[ExtractedParameter]:
        """Extract parameters from JavaScript code"""
        parameters = []
        
        # Extract script content
        scripts = []
        if BS4_OK:
            soup = BeautifulSoup(content, 'html.parser')
            for script in soup.find_all('script'):
                if script.string:
                    scripts.append(script.string)
        else:
            script_pattern = r'<script[^>]*>(.*?)</script>'
            scripts = re.findall(script_pattern, content, re.DOTALL | re.IGNORECASE)
        
        # Analyze each script
        for script_content in scripts:
            lines = script_content.split('\n')
            
            for line_num, line in enumerate(lines, 1):
                for pattern in self.js_patterns:
                    matches = re.finditer(pattern, line, re.IGNORECASE)
                    
                    for match in matches:
                        groups = match.groups()
                        if len(groups) >= 1:
                            name = groups[0].strip('"\'')
                            value = groups[1] if len(groups) > 1 else ""
                            value = value.strip('"\'')
                            
                            parameters.append(ExtractedParameter(
                                name=name,
                                value=value,
                                source='javascript',
                                context='variable',
                                url=url,
                                method='GET',
                                extraction_method='regex',
                                line_number=line_num,
                                pattern_matched=pattern[:50] + "...",
                                additional_info={
                                    'script_line': line.strip()
                                }
                            ))
        
        return parameters
    
    def extract_meta_parameters(self, content: str, url: str) -> List[ExtractedParameter]:
        """Extract parameters from meta tags"""
        parameters = []
        
        for pattern in self.meta_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            
            for match in matches:
                groups = match.groups()
                if len(groups) >= 2:
                    name = groups[0].strip()
                    value = groups[1].strip()
                    
                    parameters.append(ExtractedParameter(
                        name=name,
                        value=value,
                        source='meta',
                        context='tag',
                        url=url,
                        method='GET',
                        extraction_method='regex',
                        pattern_matched=f"meta:{name}",
                        additional_info={
                            'meta_tag': match.group(0)[:100] + "..."
                        }
                    ))
        
        return parameters
    
    def extract_data_attributes(self, content: str, url: str) -> List[ExtractedParameter]:
        """Extract parameters from data attributes"""
        parameters = []
        
        for pattern in self.data_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            
            for match in matches:
                groups = match.groups()
                if len(groups) >= 2:
                    name = f"data-{groups[0]}"
                    value = groups[1]
                    
                    parameters.append(ExtractedParameter(
                        name=name,
                        value=value,
                        source='data_attribute',
                        context='attribute',
                        url=url,
                        method='GET',
                        extraction_method='regex',
                        pattern_matched=f"data:{groups[0]}",
                        additional_info={
                            'attribute_context': match.group(0)
                        }
                    ))
        
        return parameters
    
    def extract_config_parameters(self, content: str, url: str) -> List[ExtractedParameter]:
        """Extract parameters from configuration objects"""
        parameters = []
        
        for pattern in self.config_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE | re.DOTALL)
            
            for match in matches:
                config_block = match.group(1) if len(match.groups()) >= 1 else match.group(0)
                
                # Try to parse as JSON
                try:
                    config_data = json.loads(config_block)
                    if isinstance(config_data, dict):
                        for key, value in config_data.items():
                            if isinstance(value, str):
                                parameters.append(ExtractedParameter(
                                    name=key,
                                    value=value,
                                    source='config',
                                    context='json',
                                    url=url,
                                    method='GET',
                                    extraction_method='json_parse',
                                    pattern_matched=f"config:{key}"
                                ))
                except:
                    # Fallback to regex extraction
                    kv_pattern = r'["\']?([a-zA-Z_][a-zA-Z0-9_]*)["\']?\s*:\s*["\']([^"\']+)["\']'
                    kv_matches = re.findall(kv_pattern, config_block)
                    
                    for key, value in kv_matches:
                        parameters.append(ExtractedParameter(
                            name=key,
                            value=value,
                            source='config',
                            context='object',
                            url=url,
                            method='GET',
                            extraction_method='regex',
                            pattern_matched=f"config:{key}"
                        ))
        
        return parameters
    
    def extract_header_parameters(self, headers: Dict[str, str], url: str) -> List[ExtractedParameter]:
        """Extract parameters from HTTP headers"""
        parameters = []
        
        redirect_headers = [
            'Location', 'Refresh', 'Link', 'X-Redirect-To', 'X-Forward-To',
            'X-Accel-Redirect', 'X-Sendfile', 'X-Lighttpd-Send-File'
        ]
        
        for header_name, header_value in headers.items():
            # Direct redirect headers
            if header_name in redirect_headers:
                parameters.append(ExtractedParameter(
                    name=header_name.lower(),
                    value=header_value,
                    source='header',
                    context='redirect_header',
                    url=url,
                    method='GET',
                    extraction_method='header_analysis',
                    pattern_matched=f"header:{header_name}",
                    additional_info={
                        'header_type': 'redirect'
                    }
                ))
            
            # Headers containing parameters
            if '?' in header_value and '=' in header_value:
                try:
                    if header_value.startswith(('http://', 'https://')):
                        parsed_url = urlparse(header_value)
                        if parsed_url.query:
                            query_params = parse_qs(parsed_url.query, keep_blank_values=True)
                            for param_name, param_values in query_params.items():
                                for value in param_values:
                                    parameters.append(ExtractedParameter(
                                        name=param_name,
                                        value=value,
                                        source='header_embedded',
                                        context='header_url',
                                        url=url,
                                        method='GET',
                                        extraction_method='header_url_parse',
                                        pattern_matched=f"header_embed:{header_name}",
                                        additional_info={
                                            'parent_header': header_name,
                                            'embedded_url': header_value
                                        }
                                    ))
                except:
                    pass
        
        return parameters
    
    def extract_comment_parameters(self, content: str, url: str) -> List[ExtractedParameter]:
        """Extract parameters from HTML/JS comments"""
        parameters = []
        
        # HTML comments
        html_comment_pattern = r'<!--(.*?)-->'
        html_comments = re.findall(html_comment_pattern, content, re.DOTALL)
        
        # JS comments
        js_comment_pattern = r'//(.*)$'
        js_comments = re.findall(js_comment_pattern, content, re.MULTILINE)
        
        all_comments = html_comments + js_comments
        
        for comment in all_comments:
            # Look for URLs or parameters in comments
            url_pattern = r'(?:redirect|url|next|return)[=:\s]+([^\s]+)'
            matches = re.finditer(url_pattern, comment, re.IGNORECASE)
            
            for match in matches:
                value = match.group(1).strip()
                if value:
                    parameters.append(ExtractedParameter(
                        name='comment_url',
                        value=value,
                        source='comment',
                        context='comment',
                        url=url,
                        method='GET',
                        extraction_method='comment_analysis',
                        pattern_matched=f"comment:{match.group(0)}",
                        additional_info={
                            'comment_text': comment[:100] + "..." if len(comment) > 100 else comment
                        }
                    ))
        
        return parameters
    
    def is_redirect_related(self, param_name: str, param_value: str = "") -> bool:
        """Check if parameter is redirect-related"""
        name_lower = param_name.lower()
        value_lower = param_value.lower()
        
        # Check name
        name_match = any(keyword in name_lower for keyword in self.redirect_keywords)
        
        # Check value
        value_match = bool(
            re.match(r'https?://', value_lower) or
            re.match(r'//', value_lower) or
            re.match(r'[a-z0-9.-]+\.[a-z]{2,}', value_lower)
        )
        
        return name_match or value_match
    
    def calculate_confidence(self, param: ExtractedParameter) -> float:
        """Calculate confidence score for parameter"""
        confidence = 0.0
        
        # Base confidence by source
        source_scores = {
            'url': 0.8,
            'form': 0.6,
            'javascript': 0.7,
            'meta': 0.8,
            'data_attribute': 0.7,
            'config': 0.6,
            'header': 0.9,
            'header_embedded': 0.8,
            'comment': 0.3
        }
        
        confidence += source_scores.get(param.source, 0.5)
        
        # Boost for redirect-related names
        if self.is_redirect_related(param.name):
            confidence += 0.2
        
        # Boost for URL-like values
        if param.value:
            if param.value.startswith(('http://', 'https://')):
                confidence += 0.3
            elif param.value.startswith('//'):
                confidence += 0.25
            elif '.' in param.value and len(param.value.split('.')) >= 2:
                confidence += 0.15
        
        # Context boost
        context_scores = {
            'query': 0.1,
            'fragment': 0.15,
            'redirect_header': 0.2,
            'json': 0.1,
            'variable': 0.05
        }
        confidence += context_scores.get(param.context, 0.0)
        
        return min(confidence, 1.0)
    
    def get_extraction_stats(self, parameters: List[ExtractedParameter]) -> Dict:
        """Get extraction statistics"""
        if not parameters:
            return {}
        
        stats = {
            'total_parameters': len(parameters),
            'by_source': {},
            'by_context': {},
            'redirect_related': len([p for p in parameters if p.is_redirect_related]),
            'high_confidence': len([p for p in parameters if p.confidence > 0.7]),
            'average_confidence': sum(p.confidence for p in parameters) / len(parameters),
            'extraction_methods': set(p.extraction_method for p in parameters)
        }
        
        # Count by source
        for param in parameters:
            stats['by_source'][param.source] = stats['by_source'].get(param.source, 0) + 1
            stats['by_context'][param.context] = stats['by_context'].get(param.context, 0) + 1
        
        return stats