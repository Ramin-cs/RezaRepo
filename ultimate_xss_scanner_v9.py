#!/usr/bin/env python3
"""
Ultimate XSS Scanner - Version 9.0
Fixed comprehensive reconnaissance + Accurate validation
Author: AI Assistant
Version: 9.0 Ultimate Fixed
"""

import requests
import re
import urllib.parse
import time
import json
import threading
import os
from urllib.parse import urljoin, urlparse, parse_qs, urlunparse
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

class UltimateXSSScannerV9:
    def __init__(self, target_url, max_threads=8, delay=0.2, max_depth=4, timeout=10):
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
            "PHASE": Fore.CYAN + Style.BRIGHT,
            "TEST": Fore.BLUE
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
                "' onfocus='alert(\"XSS_CONFIRMED\")' autofocus='"
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
    
    def phase1_comprehensive_reconnaissance(self):
        """Phase 1: Comprehensive reconnaissance with all parameter types"""
        self.log("=" * 80, "PHASE")
        self.log("PHASE 1: COMPREHENSIVE RECONNAISSANCE", "PHASE")
        self.log("=" * 80, "PHASE")
        
        try:
            # Test target
            response = self.session.get(self.target_url, timeout=self.timeout)
            response.raise_for_status()
            self.log(f"Target accessible (Status: {response.status_code})", "SUCCESS")
            
            # Comprehensive crawling with all parameter types
            discovered_data = self._comprehensive_crawl()
            
            self.log(f"Discovered {len(discovered_data['urls'])} URLs", "SUCCESS")
            self.log(f"Found {len(discovered_data['forms'])} forms", "SUCCESS")
            self.log(f"Identified {len(discovered_data['url_params'])} URL parameters", "SUCCESS")
            self.log(f"Identified {len(discovered_data['form_params'])} form parameters", "SUCCESS")
            self.log(f"Identified {len(discovered_data['js_params'])} JavaScript parameters", "SUCCESS")
            self.log(f"Identified {len(discovered_data['header_params'])} header parameters", "SUCCESS")
            self.log(f"Identified {len(discovered_data['meta_params'])} meta parameters", "SUCCESS")
            self.log(f"Identified {len(discovered_data['cookie_params'])} cookie parameters", "SUCCESS")
            
            return discovered_data
            
        except Exception as e:
            self.log(f"Phase 1 failed: {str(e)}", "ERROR")
            return None
    
    def _comprehensive_crawl(self):
        """Comprehensive crawling with all parameter types - FIXED VERSION"""
        urls_to_visit = [(self.target_url, 0)]
        discovered_urls = set()
        all_forms = []
        all_url_params = set()
        all_form_params = set()
        all_js_params = set()
        all_header_params = set()
        all_meta_params = set()
        all_cookie_params = set()
        all_contexts = {}
        base_domain = urlparse(self.target_url).netloc
        
        self.log(f"Starting crawl from: {self.target_url}", "INFO")
        self.log(f"Base domain: {base_domain}", "INFO")
        
        while urls_to_visit:
            current_url, depth = urls_to_visit.pop(0)
            
            if (current_url in self.visited_urls or 
                depth > self.max_depth or 
                current_url in discovered_urls):
                continue
            
            self.visited_urls.add(current_url)
            discovered_urls.add(current_url)
            
            self.log(f"Crawling: {current_url} (depth: {depth})", "INFO")
            
            try:
                response = self.session.get(current_url, timeout=self.timeout)
                response.raise_for_status()
                
                # Comprehensive parameter discovery
                param_data = self._discover_all_parameters(response, current_url)
                
                all_url_params.update(param_data['url_params'])
                all_form_params.update(param_data['form_params'])
                all_js_params.update(param_data['js_params'])
                all_header_params.update(param_data['header_params'])
                all_meta_params.update(param_data['meta_params'])
                all_cookie_params.update(param_data['cookie_params'])
                
                # Extract forms
                forms = self._extract_forms_comprehensive(response.text, current_url)
                all_forms.extend(forms)
                
                # Store contexts
                all_contexts[current_url] = param_data['contexts']
                
                # Extract links - FIXED LINK EXTRACTION
                links = self._extract_links_comprehensive(response.text, current_url)
                self.log(f"Found {len(links)} links on {current_url}", "INFO")
                
                # Add same-origin links
                for link in links:
                    parsed = urlparse(link)
                    if (parsed.scheme in ('http', 'https') and 
                        parsed.netloc == base_domain and
                        link not in discovered_urls and
                        link not in self.visited_urls and
                        not self._is_static_resource(link)):
                        urls_to_visit.append((link, depth + 1))
                        self.log(f"Added to queue: {link}", "INFO")
                
                time.sleep(self.delay)
                
            except Exception as e:
                self.log(f"Error crawling {current_url}: {str(e)}", "ERROR")
                continue
        
        self.log(f"Crawl completed. Total URLs: {len(discovered_urls)}", "SUCCESS")
        
        return {
            'urls': list(discovered_urls),
            'forms': all_forms,
            'url_params': list(all_url_params),
            'form_params': list(all_form_params),
            'js_params': list(all_js_params),
            'header_params': list(all_header_params),
            'meta_params': list(all_meta_params),
            'cookie_params': list(all_cookie_params),
            'contexts': all_contexts
        }
    
    def _discover_all_parameters(self, response, url):
        """Discover all types of parameters"""
        params = {
            'url_params': set(),
            'form_params': set(),
            'js_params': set(),
            'header_params': set(),
            'meta_params': set(),
            'cookie_params': set(),
            'contexts': {}
        }
        
        # 1. URL Parameters (Query string + Fragment)
        parsed_url = urlparse(url)
        url_params = parse_qs(parsed_url.query)
        params['url_params'].update(url_params.keys())
        
        # Fragment parameters
        if parsed_url.fragment:
            fragment_params = parse_qs(parsed_url.fragment)
            params['url_params'].update(fragment_params.keys())
        
        # 2. Form Parameters
        soup = BeautifulSoup(response.text, 'html.parser')
        for form in soup.find_all('form'):
            for input_tag in form.find_all(['input', 'textarea', 'select']):
                name = input_tag.get('name', '')
                if name:
                    params['form_params'].add(name)
        
        # 3. JavaScript Variables
        js_params = self._extract_js_parameters(response.text)
        params['js_params'].update(js_params)
        
        # 4. HTTP Headers
        header_params = self._extract_header_parameters(response.headers)
        params['header_params'].update(header_params)
        
        # 5. Meta Tags
        meta_params = self._extract_meta_parameters(response.text)
        params['meta_params'].update(meta_params)
        
        # 6. Cookie Parameters
        cookie_params = self._extract_cookie_parameters(response.cookies)
        params['cookie_params'].update(cookie_params)
        
        # 7. Context Analysis
        params['contexts'] = self._analyze_contexts(response.text, url)
        
        return params
    
    def _extract_js_parameters(self, html_content):
        """Extract JavaScript parameters"""
        js_params = set()
        
        # Variable declarations
        patterns = [
            r'var\s+(\w+)\s*=',
            r'let\s+(\w+)\s*=',
            r'const\s+(\w+)\s*=',
            r'(\w+)\s*=\s*["\']',
            r'window\.(\w+)\s*=',
            r'this\.(\w+)\s*=',
            r'(\w+)\s*:\s*function',
            r'(\w+)\s*:\s*["\']'
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, html_content, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple):
                    js_params.add(match[0])
                else:
                    js_params.add(match)
        
        # URLSearchParams
        urlsearch_pattern = r'URLSearchParams\s*\(\s*["\']([^"\']+)["\']'
        urlsearch_matches = re.findall(urlsearch_pattern, html_content, re.IGNORECASE)
        for match in urlsearch_matches:
            js_params.add(match)
        
        return js_params
    
    def _extract_header_parameters(self, headers):
        """Extract header parameters"""
        header_params = set()
        
        # Custom headers
        for header_name in headers:
            if header_name.lower().startswith('x-'):
                header_params.add(header_name)
        
        # Location header
        if 'Location' in headers:
            location_url = headers['Location']
            parsed = urlparse(location_url)
            location_params = parse_qs(parsed.query)
            header_params.update(location_params.keys())
        
        return header_params
    
    def _extract_meta_parameters(self, html_content):
        """Extract meta tag parameters"""
        meta_params = set()
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # Meta refresh
        for meta in soup.find_all('meta', {'http-equiv': 'refresh'}):
            content = meta.get('content', '')
            if 'url=' in content:
                url_part = content.split('url=')[1]
                parsed = urlparse(url_part)
                meta_params.update(parse_qs(parsed.query).keys())
        
        # Meta redirect
        for meta in soup.find_all('meta', {'http-equiv': 'refresh'}):
            content = meta.get('content', '')
            if ';' in content:
                url_part = content.split(';')[1].strip()
                if url_part.startswith('url='):
                    url = url_part[4:]
                    parsed = urlparse(url)
                    meta_params.update(parse_qs(parsed.query).keys())
        
        return meta_params
    
    def _extract_cookie_parameters(self, cookies):
        """Extract cookie parameters"""
        cookie_params = set()
        
        for cookie in cookies:
            cookie_params.add(cookie.name)
        
        return cookie_params
    
    def _analyze_contexts(self, html_content, url):
        """Analyze contexts for XSS"""
        contexts = {
            'html_reflections': [],
            'attribute_reflections': [],
            'javascript_reflections': [],
            'css_reflections': [],
            'url_reflections': []
        }
        
        # This is a simplified version - in practice, you'd analyze actual parameter reflections
        return contexts
    
    def _extract_links_comprehensive(self, html_content, base_url):
        """Comprehensive link extraction - FIXED VERSION"""
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
        
        # Extract from BeautifulSoup for better accuracy
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # Extract all href attributes
        for link in soup.find_all('a', href=True):
            href = link['href']
            if href and not href.startswith('#') and not href.startswith('javascript:'):
                full_url = urljoin(base_url, href)
                links.append(full_url)
        
        # Extract form actions
        for form in soup.find_all('form', action=True):
            action = form['action']
            if action:
                full_url = urljoin(base_url, action)
                links.append(full_url)
        
        # Add regex matches
        all_matches = a_matches + js_matches + form_matches
        
        for href in all_matches:
            if href and not href.startswith('#') and not href.startswith('javascript:'):
                full_url = urljoin(base_url, href)
                links.append(full_url)
        
        # Remove duplicates
        links = list(set(links))
        
        return links
    
    def _extract_forms_comprehensive(self, html_content, base_url):
        """Comprehensive form extraction"""
        forms = []
        soup = BeautifulSoup(html_content, 'html.parser')
        
        for form in soup.find_all('form'):
            form_data = {
                'url': base_url,
                'action': form.get('action', ''),
                'method': form.get('method', 'GET').upper(),
                'enctype': form.get('enctype', ''),
                'inputs': []
            }
            
            for input_tag in form.find_all(['input', 'textarea', 'select']):
                input_data = {
                    'name': input_tag.get('name', ''),
                    'type': input_tag.get('type', 'text'),
                    'value': input_tag.get('value', ''),
                    'placeholder': input_tag.get('placeholder', ''),
                    'id': input_tag.get('id', ''),
                    'class': input_tag.get('class', [])
                }
                form_data['inputs'].append(input_data)
            
            if form_data['action']:
                form_data['action'] = urljoin(base_url, form_data['action'])
            else:
                form_data['action'] = base_url
            
            forms.append(form_data)
        
        return forms
    
    def _is_static_resource(self, url):
        """Check if URL is static resource"""
        static_extensions = ['.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.ico', '.svg', '.pdf', '.woff', '.woff2']
        return any(url.lower().endswith(ext) for ext in static_extensions)
    
    def phase2_accurate_validation(self, recon_data):
        """Phase 2: Accurate XSS validation with detailed logging"""
        self.log("=" * 80, "PHASE")
        self.log("PHASE 2: ACCURATE XSS VALIDATION", "PHASE")
        self.log("=" * 80, "PHASE")
        
        if not PLAYWRIGHT_AVAILABLE:
            self.log("Playwright not available, using string matching", "WARNING")
            self._string_matching_validation(recon_data)
            return
        
        if not self._init_browser():
            self.log("Browser init failed, using string matching", "WARNING")
            self._string_matching_validation(recon_data)
            return
        
        try:
            # Test all discovered parameters
            self._test_all_parameters(recon_data)
            
            self._close_browser()
            
        except Exception as e:
            self.log(f"Phase 2 failed: {str(e)}", "ERROR")
            self._close_browser()
    
    def _init_browser(self):
        """Initialize browser"""
        try:
            playwright = sync_playwright().start()
            self.browser = playwright.chromium.launch(
                headless=True, 
                args=['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage']
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
    
    def _test_all_parameters(self, recon_data):
        """Test all discovered parameters"""
        # Test URL parameters
        for url in recon_data['urls']:
            self._test_url_parameters(url, recon_data)
        
        # Test form parameters
        for form in recon_data['forms']:
            self._test_form_parameters(form, recon_data)
    
    def _test_url_parameters(self, url, recon_data):
        """Test URL parameters"""
        parsed_url = urlparse(url)
        url_params = parse_qs(parsed_url.query)
        
        for param_name in url_params:
            self.log(f"Testing URL parameter: {param_name} on {url}", "TEST")
            
            # Determine context
            context = self._determine_parameter_context(param_name, recon_data['contexts'].get(url, {}))
            payloads = self._get_payloads_for_context(context)
            
            for payload in payloads:
                try:
                    test_url = f"{url}?{param_name}={urllib.parse.quote(payload)}"
                    
                    self.log(f"Testing payload: {payload} (Context: {context})", "TEST")
                    
                    if self._validate_xss_accurate(test_url, None, payload, param_name, context):
                        return True
                    
                    time.sleep(self.delay)
                    
                except Exception as e:
                    self.log(f"Error testing payload: {str(e)}", "ERROR")
                    continue
        return False
    
    def _test_form_parameters(self, form, recon_data):
        """Test form parameters"""
        for input_field in form['inputs']:
            if input_field['name']:
                self.log(f"Testing form parameter: {input_field['name']} on {form['action']}", "TEST")
                
                # Determine context
                context = self._determine_parameter_context(input_field['name'], {})
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
                        
                        self.log(f"Testing payload: {payload} (Context: {context})", "TEST")
                        
                        if self._validate_xss_accurate(form['action'], form_data, payload, input_field['name'], context):
                            return True
                        
                        time.sleep(self.delay)
                        
                    except Exception as e:
                        self.log(f"Error testing payload: {str(e)}", "ERROR")
                        continue
        return False
    
    def _determine_parameter_context(self, param_name, contexts):
        """Determine parameter context"""
        param_name_lower = param_name.lower()
        
        if any(keyword in param_name_lower for keyword in ['search', 'query', 'q', 'term']):
            return 'html'
        elif any(keyword in param_name_lower for keyword in ['comment', 'message', 'text', 'content']):
            return 'attribute'
        elif any(keyword in param_name_lower for keyword in ['url', 'link', 'href']):
            return 'javascript'
        elif any(keyword in param_name_lower for keyword in ['style', 'css', 'color']):
            return 'css'
        else:
            return 'html'
    
    def _get_payloads_for_context(self, context):
        """Get appropriate payloads for context"""
        return self.payloads.get(context, self.payloads['html'])
    
    def _validate_xss_accurate(self, url, form_data, payload, param_name, context):
        """Accurate XSS validation - screenshot ONLY after confirmation"""
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
                
                # Fill form with better error handling
                for field_name, field_value in form_data.items():
                    try:
                        # Try different selectors
                        selectors = [
                            f'input[name="{field_name}"]',
                            f'textarea[name="{field_name}"]',
                            f'select[name="{field_name}"]',
                            f'[name="{field_name}"]'
                        ]
                        
                        for selector in selectors:
                            try:
                                page.fill(selector, field_value)
                                break
                            except:
                                continue
                    except:
                        pass
                
                # Submit form with better error handling
                try:
                    page.click('input[type="submit"]')
                except:
                    try:
                        page.click('button[type="submit"]')
                    except:
                        try:
                            page.click('button')
                        except:
                            pass
                
                page.wait_for_load_state("domcontentloaded", timeout=self.timeout * 1000)
            else:
                # Direct URL
                page.goto(url, wait_until="domcontentloaded", timeout=self.timeout * 1000)
            
            # Wait for potential XSS
            time.sleep(3)
            
            # Check if alert was triggered - ONLY take screenshot if confirmed
            if alert_dialog and "XSS_CONFIRMED" in alert_dialog.message:
                # XSS is CONFIRMED - now take screenshot
                screenshot_path = self._take_screenshot(page, param_name, payload)
                
                # Add to confirmed vulnerabilities
                with self.lock:
                    vuln = {
                        'url': url,
                        'parameter': param_name,
                        'payload': payload,
                        'context': context,
                        'screenshot': screenshot_path,
                        'timestamp': datetime.datetime.now().isoformat(),
                        'alert_message': alert_dialog.message,
                        'confirmed': True
                    }
                    self.confirmed_vulnerabilities.append(vuln)
                    self.log(f"✅ CONFIRMED XSS! Parameter: {param_name}", "VULN")
                    self.log(f"Context: {context}", "VULN")
                    self.log(f"Payload: {payload}", "VULN")
                    self.log(f"URL: {url}", "VULN")
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
    
    def _string_matching_validation(self, recon_data):
        """String matching validation as fallback"""
        self.log("Using string matching validation", "INFO")
        
        # Test forms
        for form in recon_data['forms']:
            for input_field in form['inputs']:
                if input_field['name']:
                    context = self._determine_parameter_context(input_field['name'], {})
                    payloads = self._get_payloads_for_context(context)
                    
                    for payload in payloads:
                        try:
                            form_data = {}
                            for field in form['inputs']:
                                if field['name'] == input_field['name']:
                                    form_data[field['name']] = payload
                                else:
                                    form_data[field['name']] = field['value']
                            
                            if form['method'] == 'POST':
                                response = self.session.post(form['action'], data=form_data, timeout=self.timeout)
                            else:
                                response = self.session.get(form['action'], params=form_data, timeout=self.timeout)
                            
                            if self._check_xss_indicators(response.text, payload):
                                with self.lock:
                                    vuln = {
                                        'url': form['action'],
                                        'parameter': input_field['name'],
                                        'payload': payload,
                                        'context': context,
                                        'screenshot': None,
                                        'timestamp': datetime.datetime.now().isoformat(),
                                        'alert_message': 'String matching detection',
                                        'confirmed': False
                                    }
                                    self.confirmed_vulnerabilities.append(vuln)
                                    self.log(f"⚠️ POTENTIAL XSS! Parameter: {input_field['name']}", "VULN")
                                    self.log(f"Context: {context}", "VULN")
                                    self.log(f"Payload: {payload}", "VULN")
                                
                                break
                            
                            time.sleep(self.delay)
                            
                        except Exception:
                            continue
        
        # Test URL parameters
        for url in recon_data['urls']:
            parsed_url = urlparse(url)
            url_params = parse_qs(parsed_url.query)
            
            for param_name in url_params:
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
                                    'context': context,
                                    'screenshot': None,
                                    'timestamp': datetime.datetime.now().isoformat(),
                                    'alert_message': 'String matching detection',
                                    'confirmed': False
                                }
                                self.confirmed_vulnerabilities.append(vuln)
                                self.log(f"⚠️ POTENTIAL XSS! Parameter: {param_name}", "VULN")
                                self.log(f"Context: {context}", "VULN")
                                self.log(f"Payload: {payload}", "VULN")
                            
                            break
                        
                        time.sleep(self.delay)
                        
                    except Exception:
                        continue
    
    def _check_xss_indicators(self, response_text, payload):
        """Check for XSS indicators"""
        if payload in response_text:
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
        report_path = os.path.join('reports', f'ultimate_xss_report_{timestamp}.html')
        
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Ultimate XSS Scanner Report - {self.target_url}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; }}
        .header {{ text-align: center; border-bottom: 2px solid #e74c3c; padding-bottom: 20px; margin-bottom: 30px; }}
        .header h1 {{ color: #e74c3c; }}
        .summary {{ background: #f8f9fa; padding: 20px; border-radius: 8px; margin-bottom: 30px; }}
        .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }}
        .stat {{ text-align: center; background: white; padding: 20px; border-radius: 8px; border-left: 4px solid #e74c3c; }}
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
            <h1>🔒 Ultimate XSS Scanner Report</h1>
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
                    <p><strong>Context:</strong> {vuln.get('context', 'N/A')}</p>
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
        
        self.log("🚀 Starting Ultimate XSS Scanner v9.0", "SUCCESS")
        self.log(f"Target: {self.target_url}", "INFO")
        
        try:
            # Phase 1: Comprehensive reconnaissance
            recon_data = self.phase1_comprehensive_reconnaissance()
            if not recon_data:
                self.log("Phase 1 failed, aborting scan", "ERROR")
                return
            
            # Phase 2: Accurate validation
            self.phase2_accurate_validation(recon_data)
            
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
        self.log("=" * 80, "PHASE")
        self.log("SCAN RESULTS", "PHASE")
        self.log("=" * 80, "PHASE")
        
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
                self.log(f"Context: {vuln.get('context', 'N/A')}", "VULN")
                self.log(f"Payload: {vuln['payload']}", "VULN")
                if vuln.get('screenshot'):
                    self.log(f"Screenshot: {vuln['screenshot']}", "VULN")
        else:
            self.log("\n✅ No XSS vulnerabilities found", "SUCCESS")
        
        if report_path:
            self.log(f"\n📄 HTML Report: {report_path}", "SUCCESS")
        
        self.log("\n🔒 Screenshots taken ONLY for confirmed XSS vulnerabilities", "SUCCESS")

def main():
    parser = argparse.ArgumentParser(description='Ultimate XSS Scanner v9.0')
    parser.add_argument('url', help='Target URL to scan')
    parser.add_argument('-t', '--threads', type=int, default=8, help='Number of threads (default: 8)')
    parser.add_argument('-d', '--delay', type=float, default=0.2, help='Delay between requests (default: 0.2)')
    parser.add_argument('--depth', type=int, default=4, help='Crawling depth (default: 4)')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout (default: 10)')
    
    args = parser.parse_args()
    
    scanner = UltimateXSSScannerV9(
        args.url,
        args.threads,
        args.delay,
        args.depth,
        args.timeout
    )
    
    scanner.scan()

if __name__ == "__main__":
    main()