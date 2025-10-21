#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Simple Parameter Discovery Tool
Cross-platform parameter mining without encoding issues
"""

import re
import argparse
import os
import sys
import time
import json
import random
import ssl
from urllib.parse import urlparse, parse_qs, urlencode, unquote, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
import urllib.request
import urllib.error
import warnings
from html.parser import HTMLParser
import threading
warnings.filterwarnings("ignore")

# Try to import requests with fallback
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

class Colors:
    """Cross-platform color support"""
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    END = '\033[0m'

class WebCrawler(HTMLParser):
    """HTML parser for crawling and extracting parameters"""
    
    def __init__(self, base_url):
        super().__init__()
        self.base_url = base_url
        self.links = set()
        self.forms = []
        self.js_files = set()
        self.parameters = set()
        self.current_form = None
        
    def handle_starttag(self, tag, attrs):
        attrs_dict = dict(attrs)
        
        # Extract links
        if tag == 'a' and 'href' in attrs_dict:
            href = attrs_dict['href']
            if href:
                full_url = urljoin(self.base_url, href)
                self.links.add(full_url)
                # Extract parameters from href
                self._extract_params_from_url(full_url)
        
        # Extract JavaScript files
        elif tag == 'script' and 'src' in attrs_dict:
            src = attrs_dict['src']
            if src:
                js_url = urljoin(self.base_url, src)
                self.js_files.add(js_url)
        
        # Extract forms
        elif tag == 'form':
            self.current_form = {
                'action': urljoin(self.base_url, attrs_dict.get('action', '')),
                'method': attrs_dict.get('method', 'GET').upper(),
                'inputs': []
            }
        
        # Extract form inputs
        elif tag == 'input' and self.current_form is not None:
            input_name = attrs_dict.get('name')
            input_type = attrs_dict.get('type', 'text')
            if input_name:
                self.current_form['inputs'].append({
                    'name': input_name,
                    'type': input_type,
                    'value': attrs_dict.get('value', '')
                })
                self.parameters.add(input_name)
        
        # Extract select and textarea
        elif tag in ['select', 'textarea'] and self.current_form is not None:
            name = attrs_dict.get('name')
            if name:
                self.current_form['inputs'].append({
                    'name': name,
                    'type': tag,
                    'value': ''
                })
                self.parameters.add(name)
    
    def handle_endtag(self, tag):
        if tag == 'form' and self.current_form:
            self.forms.append(self.current_form)
            self.current_form = None
    
    def _extract_params_from_url(self, url):
        """Extract parameters from URL"""
        try:
            parsed = urlparse(url)
            if parsed.query:
                params = parse_qs(parsed.query)
                for param in params.keys():
                    self.parameters.add(param)
        except:
            pass

class Logger:
    """Simple logging system"""
    
    @staticmethod
    def info(message):
        print(f"{Colors.BLUE}[INFO]{Colors.END} {message}")
    
    @staticmethod
    def success(message):
        print(f"{Colors.GREEN}[SUCCESS]{Colors.END} {message}")
    
    @staticmethod
    def warning(message):
        print(f"{Colors.YELLOW}[WARNING]{Colors.END} {message}")
    
    @staticmethod
    def error(message):
        print(f"{Colors.RED}[ERROR]{Colors.END} {message}")
    
    @staticmethod
    def found(message):
        print(f"{Colors.CYAN}[FOUND]{Colors.END} {message}")

class SimpleHTTPClient:
    """Simple HTTP client using urllib"""
    
    def __init__(self, timeout=30):
        self.timeout = timeout
    
    def get(self, url):
        """Simple GET request"""
        try:
            req = urllib.request.Request(url)
            req.add_header('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
            
            # Create SSL context
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
            
            with urllib.request.urlopen(req, timeout=self.timeout, context=ssl_context) as response:
                content = response.read()
                
                # Simple response object
                class SimpleResponse:
                    def __init__(self, code, content):
                        self.status_code = code
                        self.text = content.decode('utf-8', errors='ignore')
                        self.content = content
                
                return SimpleResponse(response.getcode(), content)
                
        except Exception as e:
            # Return error response
            class ErrorResponse:
                def __init__(self):
                    self.status_code = 0
                    self.text = ''
                    self.content = b''
            
            return ErrorResponse()

class SimpleParameterDiscovery:
    """Simple parameter discovery"""
    
    def __init__(self, domain, include_subdomains=True, timeout=30, quiet=False):
        self.domain = self.clean_domain(domain)
        self.include_subdomains = include_subdomains
        self.timeout = max(timeout, 30)  # Minimum 30 seconds
        self.quiet = quiet
        self.found_parameters = set()
        self.found_urls = []
        self.http_client = SimpleHTTPClient(timeout=self.timeout)
        self.crawled_urls = set()
        self.js_parameters = set()
        self.form_parameters = set()
        self.api_parameters = set()
        self.rate_limit_delay = 0.5  # 500ms between requests
        self.analyzed_js_files = set()  # Track analyzed JS files to avoid duplicates
        self.parameter_urls = {}  # Store parameter -> URLs mapping
        
        # Extensions to exclude
        self.blacklist_extensions = [
            ".jpg", ".jpeg", ".png", ".gif", ".pdf", ".svg", ".json",
            ".css", ".js", ".webp", ".woff", ".woff2", ".eot", ".ttf", 
            ".otf", ".mp4", ".txt", ".ico", ".xml", ".zip", ".rar"
        ]
    
    def clean_domain(self, domain):
        """Clean domain name"""
        domain = domain.strip().lower()
        domain = domain.replace('https://', '').replace('http://', '')
        domain = domain.replace('www.', '')
        if '/' in domain:
            domain = domain.split('/')[0]
        return domain
    
    def fetch_wayback_urls(self):
        """Fetch URLs from Wayback Machine with retry and fallback"""
        Logger.info(f"Fetching URLs from Wayback Machine for {self.domain}")
        
        # Multiple endpoints for better reliability
        if self.include_subdomains:
            wayback_urls = [
                f"http://web.archive.org/cdx/search/cdx?url=*.{self.domain}/*&output=txt&fl=original&collapse=urlkey&page=/",
                f"https://web.archive.org/cdx/search/cdx?url=*.{self.domain}/*&output=txt&fl=original&collapse=urlkey&page=/",
                f"http://web.archive.org/cdx/search/cdx?url=*.{self.domain}/*&output=json&collapse=urlkey&limit=10000"
            ]
        else:
            wayback_urls = [
                f"http://web.archive.org/cdx/search/cdx?url={self.domain}/*&output=txt&fl=original&collapse=urlkey&page=/",
                f"https://web.archive.org/cdx/search/cdx?url={self.domain}/*&output=txt&fl=original&collapse=urlkey&page=/",
                f"http://web.archive.org/cdx/search/cdx?url={self.domain}/*&output=json&collapse=urlkey&limit=10000"
            ]
        
        for attempt, wayback_url in enumerate(wayback_urls, 1):
            try:
                Logger.info(f"Attempt {attempt}/{len(wayback_urls)}: Connecting to Wayback Machine...")
                response = self.http_client.get(wayback_url)
                
                if response.status_code == 200:
                    response_text = response.text.strip()
                    if not response_text:
                        Logger.warning(f"Attempt {attempt} returned empty response")
                        continue
                        
                    if 'output=json' in wayback_url:
                        # Handle JSON response
                        try:
                            data = json.loads(response_text)
                            if data and len(data) > 1:
                                urls = []
                                for row in data[1:]:  # Skip header
                                    if len(row) >= 3:
                                        urls.append(unquote(row[2]))
                                
                                if urls:
                                    Logger.success(f"Retrieved {len(urls)} URLs from Wayback Machine")
                                    return urls
                            else:
                                Logger.warning(f"Attempt {attempt} returned empty JSON data")
                                continue
                        except json.JSONDecodeError as e:
                            Logger.warning(f"Attempt {attempt} JSON decode error: {e}")
                            continue
                    else:
                        # Handle text response
                        urls = response_text.split('\n')
                        urls = [unquote(url.strip()) for url in urls if url.strip()]
                        
                        if urls:
                            Logger.success(f"Retrieved {len(urls)} URLs from Wayback Machine")
                            return urls
                        else:
                            Logger.warning(f"Attempt {attempt} returned no valid URLs from text response")
                            continue
                else:
                    Logger.warning(f"Attempt {attempt} returned status code: {response.status_code}")
                    continue
                
                Logger.warning(f"Attempt {attempt} returned no valid URLs")
                
            except Exception as e:
                Logger.warning(f"Attempt {attempt} failed: {str(e)}")
                if attempt < len(wayback_urls):
                    Logger.info("Trying alternative endpoint...")
                    time.sleep(2)  # Wait before retry
                continue
        
        Logger.error("No URLs retrieved from Wayback Machine")
        
        # Fallback: Try CommonCrawl as last resort
        Logger.info("Trying CommonCrawl as fallback...")
        try:
            commoncrawl_url = f"http://index.commoncrawl.org/CC-MAIN-2024-10-index?url=*.{self.domain}/*&output=json"
            response = self.http_client.get(commoncrawl_url)
            
            if response.status_code == 200:
                lines = response.text.strip().split('\n')
                urls = []
                for line in lines:
                    try:
                        data = json.loads(line)
                        if 'url' in data:
                            urls.append(data['url'])
                    except:
                        continue
                
                if urls:
                    Logger.success(f"Retrieved {len(urls)} URLs from CommonCrawl fallback")
                    return urls
        except Exception as e:
            Logger.warning(f"CommonCrawl fallback also failed: {e}")
        
        return []
    
    def crawl_website(self, max_pages=10):
        """Crawl website to discover parameters from pages, forms, and JS"""
        Logger.info(f"Starting website crawling for {self.domain} (max {max_pages} pages)")
        
        # Start with main domain URLs
        start_urls = [
            f"https://{self.domain}",
            f"http://{self.domain}",
            f"https://www.{self.domain}",
            f"http://www.{self.domain}"
        ]
        
        crawled_count = 0
        urls_to_crawl = set(start_urls)
        all_parameters = set()
        
        while urls_to_crawl and crawled_count < max_pages:
            url = urls_to_crawl.pop()
            
            if url in self.crawled_urls:
                continue
                
            try:
                Logger.info(f"Crawling page {crawled_count + 1}/{max_pages}: {url}")
                
                # Rate limiting
                time.sleep(self.rate_limit_delay)
                
                response = self.http_client.get(url)
                if response.status_code == 200:
                    self.crawled_urls.add(url)
                    crawled_count += 1
                    
                    # Parse HTML content
                    crawler = WebCrawler(url)
                    try:
                        crawler.feed(response.text)
                        
                        # Collect parameters from forms
                        for form in crawler.forms:
                            for input_field in form['inputs']:
                                param_name = input_field['name']
                                if param_name:
                                    all_parameters.add(param_name)
                                    self.form_parameters.add(param_name)
                        
                        # Collect parameters from links
                        all_parameters.update(crawler.parameters)
                        
                        # Add new URLs to crawl (same domain only)
                        for link in crawler.links:
                            parsed_link = urlparse(link)
                            if (parsed_link.netloc.endswith(self.domain) and 
                                link not in self.crawled_urls and
                                len(urls_to_crawl) < max_pages * 2):
                                urls_to_crawl.add(link)
                        
                        # Analyze JavaScript files
                        js_params = self.analyze_javascript_files(crawler.js_files)
                        all_parameters.update(js_params)
                        
                        # Analyze HTML source for hidden parameters
                        source_params = self.analyze_html_source(response.text)
                        all_parameters.update(source_params)
                        
                    except Exception as e:
                        Logger.warning(f"Error parsing HTML from {url}: {e}")
                        
            except Exception as e:
                Logger.warning(f"Error crawling {url}: {e}")
        
        Logger.success(f"Website crawling completed: {len(all_parameters)} parameters from {crawled_count} pages")
        return all_parameters
    
    def analyze_javascript_files(self, js_urls, max_files=5):
        """Analyze JavaScript files for hidden parameters and API endpoints"""
        if not js_urls:
            return set()
            
        Logger.info(f"Analyzing {min(len(js_urls), max_files)} JavaScript files")
        js_parameters = set()
        
        # Common JS parameter patterns
        js_patterns = [
            r'["\']([a-zA-Z_][a-zA-Z0-9_]*)["\']:\s*["\']?[^,}\]]+',  # Object properties
            r'\.get\(["\']([^"\']+)["\']',  # GET requests
            r'\.post\(["\']([^"\']+)["\']',  # POST requests
            r'fetch\(["\']([^"\']+)["\']',  # Fetch API
            r'ajax\(["\']([^"\']+)["\']',  # AJAX calls
            r'param[s]?\[["\']([^"\']+)["\']',  # Parameter arrays
            r'data\[["\']([^"\']+)["\']',  # Data objects
            r'[?&]([a-zA-Z_][a-zA-Z0-9_]*)=',  # URL parameters
            r'FormData\(\)\.append\(["\']([^"\']+)["\']',  # FormData
            r'URLSearchParams\(["\']([^"\']+)["\']',  # URLSearchParams
        ]
        
        processed_files = 0
        for js_url in list(js_urls)[:max_files]:
            if processed_files >= max_files:
                break
            
            # Skip if already analyzed
            if js_url in self.analyzed_js_files:
                continue
                
            try:
                Logger.info(f"Analyzing JS file: {js_url}")
                self.analyzed_js_files.add(js_url)
                time.sleep(self.rate_limit_delay)
                
                response = self.http_client.get(js_url)
                if response.status_code == 200:
                    js_content = response.text
                    
                    # Extract parameters using regex patterns
                    for pattern in js_patterns:
                        matches = re.findall(pattern, js_content, re.IGNORECASE)
                        for match in matches:
                            if isinstance(match, tuple):
                                match = match[0]
                            if match and len(match) > 1 and match.isalnum() or '_' in match:
                                js_parameters.add(match)
                                self.js_parameters.add(match)
                    
                    # Look for API endpoints
                    api_endpoints = re.findall(r'["\']/?api/[^"\']*["\']', js_content, re.IGNORECASE)
                    for endpoint in api_endpoints:
                        endpoint = endpoint.strip('"\'')
                        # Extract parameters from API endpoints
                        api_params = re.findall(r'[?&]([a-zA-Z_][a-zA-Z0-9_]*)=', endpoint)
                        js_parameters.update(api_params)
                    
                    processed_files += 1
                    
            except Exception as e:
                Logger.warning(f"Error analyzing JS file {js_url}: {e}")
        
        if js_parameters:
            Logger.success(f"JavaScript analysis found {len(js_parameters)} parameters")
        
        return js_parameters
    
    def analyze_html_source(self, html_content):
        """Analyze HTML source code for hidden parameters in comments and meta tags"""
        source_parameters = set()
        
        # Extract parameters from HTML comments
        comment_patterns = [
            r'<!--.*?param[s]?[:\s]*([a-zA-Z_][a-zA-Z0-9_,\s]*).*?-->',
            r'<!--.*?[?&]([a-zA-Z_][a-zA-Z0-9_]*)=.*?-->',
        ]
        
        for pattern in comment_patterns:
            matches = re.findall(pattern, html_content, re.DOTALL | re.IGNORECASE)
            for match in matches:
                if ',' in match:
                    params = [p.strip() for p in match.split(',')]
                    source_parameters.update(params)
                else:
                    source_parameters.add(match.strip())
        
        # Extract from meta tags
        meta_pattern = r'<meta[^>]*content=["\']([^"\']*[?&]([a-zA-Z_][a-zA-Z0-9_]*)=.*?)["\']'
        meta_matches = re.findall(meta_pattern, html_content, re.IGNORECASE)
        for match in meta_matches:
            if len(match) > 1:
                source_parameters.add(match[1])
        
        # Extract from data attributes
        data_pattern = r'data-([a-zA-Z_][a-zA-Z0-9_-]*)'
        data_matches = re.findall(data_pattern, html_content, re.IGNORECASE)
        source_parameters.update(data_matches)
        
        # Clean up parameters
        clean_params = set()
        for param in source_parameters:
            if param and len(param) > 1 and param.replace('_', '').replace('-', '').isalnum():
                clean_params.add(param)
        
        return clean_params
    
    def discover_api_endpoints(self):
        """Discover API endpoints and their parameters"""
        Logger.info(f"Discovering API endpoints for {self.domain}")
        api_parameters = set()
        
        # Common API paths to check
        api_paths = [
            '/api', '/api/v1', '/api/v2', '/api/v3',
            '/rest', '/graphql', '/json', '/ajax',
            '/wp-json', '/api.php', '/api.json'
        ]
        
        base_urls = [f"https://{self.domain}", f"http://{self.domain}"]
        checked_endpoints = set()  # Track checked endpoints to avoid duplicates
        
        for base_url in base_urls:
            for api_path in api_paths:
                api_url = f"{base_url}{api_path}"
                if api_url in checked_endpoints:
                    continue
                checked_endpoints.add(api_url)
                try:
                    Logger.info(f"Checking API endpoint: {api_url}")
                    
                    time.sleep(self.rate_limit_delay)
                    response = self.http_client.get(api_url)
                    
                    if response.status_code in [200, 400, 401, 403]:
                        try:
                            # Try to parse as JSON
                            json_data = json.loads(response.text)
                            
                            # Extract parameter names from JSON structure
                            params = self.extract_json_parameters(json_data)
                            api_parameters.update(params)
                            self.api_parameters.update(params)
                            
                        except json.JSONDecodeError:
                            # Look for parameters in plain text response
                            param_matches = re.findall(r'["\']([a-zA-Z_][a-zA-Z0-9_]*)["\']', response.text)
                            for match in param_matches:
                                if len(match) > 2:
                                    api_parameters.add(match)
                    
                except Exception as e:
                    Logger.warning(f"Error checking API endpoint {api_url}: {e}")
        
        if api_parameters:
            Logger.success(f"API analysis found {len(api_parameters)} parameters")
        
        return api_parameters
    
    def extract_json_parameters(self, json_data, max_depth=3, current_depth=0):
        """Recursively extract parameter names from JSON data"""
        parameters = set()
        
        if current_depth >= max_depth:
            return parameters
        
        try:
            if isinstance(json_data, dict):
                for key, value in json_data.items():
                    if isinstance(key, str) and key.replace('_', '').isalnum():
                        parameters.add(key)
                    
                    # Recursively check nested structures
                    if isinstance(value, (dict, list)):
                        nested_params = self.extract_json_parameters(value, max_depth, current_depth + 1)
                        parameters.update(nested_params)
            
            elif isinstance(json_data, list):
                for item in json_data[:5]:  # Limit to first 5 items
                    if isinstance(item, (dict, list)):
                        nested_params = self.extract_json_parameters(item, max_depth, current_depth + 1)
                        parameters.update(nested_params)
        
        except Exception:
            pass
        
        return parameters
    
    def run_parameter_py_integration(self):
        """Run parameter.py tool for additional parameter discovery"""
        Logger.info("Phase 4: Running parameter.py integration")
        
        try:
            import subprocess
            import os
            
            # Check if parameter.py exists
            param_py_path = os.path.join(os.path.dirname(__file__), 'parameter.py')
            if not os.path.exists(param_py_path):
                Logger.warning("parameter.py not found, skipping integration")
                return set()
            
            # Run parameter.py
            cmd = [sys.executable, param_py_path, '-d', self.domain, '-t', str(self.timeout)]
            
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
                
                if result.returncode == 0:
                    # Parse parameter.py output for parameters
                    param_py_params = set()
                    lines = result.stdout.split('\n')
                    
                    for line in lines:
                        # Look for parameter patterns in output
                        if 'Parameter:' in line or 'Found:' in line:
                            # Extract parameter names
                            param_matches = re.findall(r'[a-zA-Z_][a-zA-Z0-9_]*', line)
                            for match in param_matches:
                                if len(match) > 1:
                                    param_py_params.add(match)
                    
                    if param_py_params:
                        Logger.success(f"parameter.py integration found {len(param_py_params)} additional parameters")
                        return param_py_params
                    else:
                        Logger.info("parameter.py integration found no additional parameters")
                        return set()
                else:
                    Logger.warning(f"parameter.py failed with exit code {result.returncode}")
                    return set()
                    
            except subprocess.TimeoutExpired:
                Logger.warning("parameter.py integration timed out")
                return set()
                
        except Exception as e:
            Logger.warning(f"parameter.py integration failed: {e}")
            return set()
    
    def has_excluded_extension(self, url):
        """Check if URL has excluded extension"""
        try:
            parsed_url = urlparse(url)
            path = parsed_url.path.lower()
            
            for ext in self.blacklist_extensions:
                if path.endswith(ext):
                    return True
            return False
        except:
            return False
    
    def extract_parameters_from_urls(self, urls):
        """Extract parameters from URLs"""
        Logger.info("Extracting parameters from URLs")
        
        parameter_urls = []
        parameters_found = set()
        
        # Pattern to match URLs with parameters
        param_pattern = re.compile(r'.*?://.*\?.*=.*')
        
        for url in urls:
            try:
                if not url.strip():
                    continue
                    
                # Skip URLs with excluded extensions
                if self.has_excluded_extension(url):
                    continue
                
                # Check if URL has parameters
                if param_pattern.match(url) and '?' in url:
                    parsed_url = urlparse(url)
                    query_params = parse_qs(parsed_url.query)
                    
                    if query_params:
                        # Extract parameter names and store URLs
                        for param_name in query_params.keys():
                            if param_name and len(param_name) > 0:
                                parameters_found.add(param_name)
                                # Store URL for this parameter
                                if param_name not in self.parameter_urls:
                                    self.parameter_urls[param_name] = set()
                                self.parameter_urls[param_name].add(url)
                        
                        # Create URL with placeholder values
                        cleaned_params = {key: "FUZZ" for key in query_params if key}
                        if cleaned_params:
                            cleaned_query = urlencode(cleaned_params, doseq=True)
                            cleaned_url = parsed_url._replace(query=cleaned_query).geturl()
                            parameter_urls.append(cleaned_url)
            except Exception:
                continue
        
        # Remove duplicates
        parameter_urls = list(set(parameter_urls))
        
        Logger.success(f"Found {len(parameters_found)} unique parameters in {len(parameter_urls)} URLs")
        
        # Display new parameters live
        new_params = parameters_found - self.found_parameters
        if new_params and not self.quiet:
            Logger.info(f"Found {len(new_params)} new parameters:")
            for i, param in enumerate(sorted(new_params), 1):
                # Show parameter with example URL if available
                if param in self.parameter_urls and self.parameter_urls[param]:
                    example_url = list(self.parameter_urls[param])[0]
                    Logger.found(f"Parameter #{i}: {param} (found in: {example_url})")
                else:
                    Logger.found(f"Parameter #{i}: {param}")
                # Add small delay for better readability in live mode
                if i % 10 == 0:
                    time.sleep(0.1)
        
        self.found_parameters.update(parameters_found)
        self.found_urls.extend(parameter_urls)
        
        return parameter_urls, parameters_found
    
    def run_discovery(self):
        """Run comprehensive parameter discovery"""
        start_time = time.time()
        Logger.info(f"Starting comprehensive parameter discovery for {self.domain}")
        
        all_parameters = set()
        sources_info = {}
        
        # 1. Wayback Machine Discovery
        Logger.info("Phase 1: Historical URL analysis (Wayback Machine)")
        wayback_urls = self.fetch_wayback_urls()
        wayback_params = set()
        
        if wayback_urls:
            parameter_urls, wayback_params = self.extract_parameters_from_urls(wayback_urls)
            all_parameters.update(wayback_params)
            sources_info['wayback_machine'] = {
                'urls_found': len(wayback_urls),
                'parameters_found': len(wayback_params)
            }
            Logger.success(f"Wayback Machine: {len(wayback_params)} parameters from {len(wayback_urls)} URLs")
        else:
            Logger.warning("Wayback Machine: No URLs retrieved")
            sources_info['wayback_machine'] = {'urls_found': 0, 'parameters_found': 0}
        
        # 2. Website Crawling
        Logger.info("Phase 2: Website crawling and spidering")
        crawl_params = self.crawl_website(max_pages=8)
        all_parameters.update(crawl_params)
        sources_info['website_crawling'] = {
            'pages_crawled': len(self.crawled_urls),
            'parameters_found': len(crawl_params)
        }
        
        # 3. API Endpoint Discovery
        Logger.info("Phase 3: API endpoint analysis")
        api_params = self.discover_api_endpoints()
        all_parameters.update(api_params)
        sources_info['api_endpoints'] = {
            'parameters_found': len(api_params)
        }
        
        # 4. parameter.py Integration (if available)
        param_py_params = self.run_parameter_py_integration()
        all_parameters.update(param_py_params)
        sources_info['parameter_py'] = {
            'parameters_found': len(param_py_params)
        }
        
        # Update found parameters
        self.found_parameters.update(all_parameters)
        
        execution_time = time.time() - start_time
        
        # Prepare comprehensive results
        results = {
            'domain': self.domain,
            'parameters': sorted(list(all_parameters)),
            'urls': sorted(list(set(self.found_urls))),
            'statistics': {
                'total_parameters': len(all_parameters),
                'total_urls': len(set(self.found_urls)),
                'execution_time': execution_time,
                'pages_crawled': len(self.crawled_urls),
                'comprehensive_scan': True
            },
            'sources': sources_info,
            'parameter_breakdown': {
                'wayback_machine': len(wayback_params),
                'website_crawling': len(crawl_params),
                'javascript_analysis': len(self.js_parameters),
                'form_analysis': len(self.form_parameters),
                'api_endpoints': len(self.api_parameters)
            }
        }
        
        Logger.success(f"Comprehensive discovery completed in {execution_time:.2f} seconds")
        Logger.success(f"Found {len(all_parameters)} unique parameters")
        Logger.info(f"Sources: Wayback({len(wayback_params)}), Crawling({len(crawl_params)}), JS({len(self.js_parameters)}), Forms({len(self.form_parameters)}), API({len(self.api_parameters)}), parameter.py({len(param_py_params)})")
        
        return results
    
    def save_results(self, results, output_file=None, format_type='txt'):
        """Save results to file"""
        if not output_file:
            output_file = f"{self.domain}_parameters"
        
        if format_type.lower() == 'json':
            filename = f"{output_file}.json"
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2, ensure_ascii=False)
            Logger.success(f"Results saved to {filename}")
        
        elif format_type.lower() == 'txt':
            filename = f"{output_file}.txt"
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(f"Parameter Discovery Report\n")
                f.write(f"Domain: {results['domain']}\n")
                f.write(f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Execution Time: {results['statistics']['execution_time']:.2f} seconds\n")
                f.write("=" * 60 + "\n\n")
                
                f.write(f"DISCOVERED PARAMETERS ({results['statistics']['total_parameters']}):\n")
                f.write("-" * 40 + "\n")
                for param in results['parameters']:
                    f.write(f"• {param}\n")
                
                f.write(f"\n\nURLS WITH PARAMETERS ({results['statistics']['total_urls']}):\n")
                f.write("-" * 40 + "\n")
                for url in results['urls']:
                    f.write(f"{url}\n")
                
                f.write(f"\n\nSTATISTICS:\n")
                f.write("-" * 40 + "\n")
                for key, value in results['statistics'].items():
                    f.write(f"{key.replace('_', ' ').title()}: {value}\n")
            
            Logger.success(f"Results saved to {filename}")

def print_banner():
    """Print simple banner"""
    print(f"""
{Colors.CYAN}===============================================================
                    PARAMETER DISCOVERY TOOL                   
                   Advanced Parameter Mining                   
                  Wayback Machine + Analysis                   
==============================================================={Colors.END}
{Colors.GREEN}Professional Parameter Discovery for Bug Bounty & Penetration Testing{Colors.END}
{Colors.YELLOW}Simple and reliable parameter mining tool{Colors.END}
""")

def main():
    print_banner()
    
    parser = argparse.ArgumentParser(description="Simple Parameter Discovery Tool")
    
    # Target options
    parser.add_argument('-d', '--domain', help='Target domain (e.g., example.com)')
    parser.add_argument('-l', '--list', help='File containing list of domains')
    
    # Discovery options
    parser.add_argument('--no-subs', action='store_true', help='Exclude subdomains from discovery')
    parser.add_argument('--timeout', type=int, default=30, help='Request timeout in seconds (default: 30)')
    parser.add_argument('--comprehensive', action='store_true', help='Enable comprehensive discovery (crawling, JS analysis, API discovery)')
    parser.add_argument('--max-pages', type=int, default=8, help='Maximum pages to crawl (default: 8)')
    parser.add_argument('--rate-limit', type=float, default=0.5, help='Rate limit delay between requests in seconds (default: 0.5)')
    
    # Output options
    parser.add_argument('-o', '--output', help='Output filename (without extension)')
    parser.add_argument('--format', choices=['txt', 'json'], default='txt', help='Output format (default: txt)')
    parser.add_argument('-q', '--quiet', action='store_true', help='Quiet mode - minimal output')
    
    args = parser.parse_args()
    
    # Validate arguments
    if not args.domain and not args.list:
        parser.error("Please provide either -d/--domain or -l/--list option")
    
    if args.domain and args.list:
        parser.error("Please provide either -d/--domain or -l/--list, not both")
    
    # Prepare domains list
    domains = []
    if args.domain:
        domains = [args.domain]
    elif args.list:
        try:
            with open(args.list, 'r') as f:
                domains = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            Logger.error(f"Domain list file not found: {args.list}")
            sys.exit(1)
    
    # Process each domain
    all_results = []
    
    for i, domain in enumerate(domains, 1):
        if len(domains) > 1:
            Logger.info(f"Processing domain {i}/{len(domains)}: {domain}")
        
        # Initialize discovery engine
        discovery = SimpleParameterDiscovery(
            domain=domain,
            include_subdomains=not args.no_subs,
            timeout=args.timeout,
            quiet=args.quiet
        )
        
        # Set comprehensive mode options
        if args.comprehensive:
            discovery.rate_limit_delay = args.rate_limit
        
        # Run discovery
        try:
            results = discovery.run_discovery()
            all_results.append(results)
            
            # Display results if not in quiet mode
            if not args.quiet:
                print(f"\n{Colors.GREEN}[RESULTS for {domain}]{Colors.END}")
                print(f"Parameters found: {len(results['parameters'])}")
                
                # Display parameters with their URLs
                if results['parameters']:
                    if len(results['parameters']) <= 10:
                        print("Parameters with example URLs:")
                        for param in results['parameters']:
                            if param in discovery.parameter_urls and discovery.parameter_urls[param]:
                                example_url = list(discovery.parameter_urls[param])[0]
                                print(f"  • {param}: {example_url}")
                            else:
                                print(f"  • {param}: (discovered via JS/API analysis)")
                    else:
                        print("Parameters:", ", ".join(results['parameters'][:10]))
                        if len(results['parameters']) > 10:
                            print(f"... and {len(results['parameters']) - 10} more")
                        print("\nTop 5 parameters with URLs:")
                        count = 0
                        for param in results['parameters']:
                            if count >= 5:
                                break
                            if param in discovery.parameter_urls and discovery.parameter_urls[param]:
                                example_url = list(discovery.parameter_urls[param])[0]
                                print(f"  • {param}: {example_url}")
                                count += 1
                
                print(f"URLs with parameters: {len(results['urls'])}")
            
            # Save individual results
            if args.output:
                output_name = f"{args.output}_{domain.replace('.', '_')}" if len(domains) > 1 else args.output
            else:
                output_name = f"{domain.replace('.', '_')}_parameters"
            
            discovery.save_results(results, output_name, args.format)
            
        except KeyboardInterrupt:
            Logger.warning("Discovery interrupted by user")
            break
        except Exception as e:
            Logger.error(f"Discovery failed for {domain}: {str(e)}")
            continue
    
    # Summary
    if all_results:
        total_params = sum(len(r['parameters']) for r in all_results)
        total_urls = sum(len(r['urls']) for r in all_results)
        
        print(f"\n{Colors.PURPLE}{'='*60}{Colors.END}")
        print(f"{Colors.BOLD}DISCOVERY SUMMARY{Colors.END}")
        print(f"{Colors.PURPLE}{'='*60}{Colors.END}")
        print(f"Domains processed: {len(all_results)}")
        print(f"Total parameters found: {total_params}")
        print(f"Total URLs with parameters: {total_urls}")
        print(f"{Colors.GREEN}Discovery completed successfully!{Colors.END}")

if __name__ == "__main__":
    main()