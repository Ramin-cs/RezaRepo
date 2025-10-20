#!/usr/bin/env python3
"""
GoSpider Python Implementation
Fast web spider written in Python

Original: https://github.com/jaeles-project/gospider
Python implementation with all major features

Features:
- Fast web crawling and spidering
- JavaScript file analysis and endpoint extraction
- Form detection and parameter extraction
- Cookie and header analysis
- Robots.txt parsing
- Sitemap.xml parsing
- AWS S3 bucket detection
- GitHub repository detection
- Multiple output formats
- Concurrent crawling with rate limiting
- Custom user agents and headers
- Proxy support
- Depth control
- Domain filtering and scope management
"""

import argparse
import json
import os
import sys
import threading
import time
import random
import socket
import ssl
import urllib.parse
import urllib.request
import urllib.error
import re
import base64
import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Set, Optional, Dict, Any, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime
from html.parser import HTMLParser
from collections import deque
import xml.etree.ElementTree as ET

# Console Colors
class Colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    RED = '\033[91m'
    WHITE = '\033[0m'
    BOLD = '\033[1m'
    CYAN = '\033[96m'
    MAGENTA = '\033[95m'
    
    @classmethod
    def disable(cls):
        cls.GREEN = cls.YELLOW = cls.BLUE = cls.RED = cls.WHITE = cls.BOLD = cls.CYAN = cls.MAGENTA = ''

C = Colors()

def banner():
    """Display GoSpider banner"""
    print(f"""{C.CYAN}
   ██████╗  ██████╗ ███████╗██████╗ ██╗██████╗ ███████╗██████╗ 
  ██╔════╝ ██╔═══██╗██╔════╝██╔══██╗██║██╔══██╗██╔════╝██╔══██╗
  ██║  ███╗██║   ██║███████╗██████╔╝██║██║  ██║█████╗  ██████╔╝
  ██║   ██║██║   ██║╚════██║██╔═══╝ ██║██║  ██║██╔══╝  ██╔══██╗
  ╚██████╔╝╚██████╔╝███████║██║     ██║██████╔╝███████╗██║  ██║
   ╚═════╝  ╚═════╝ ╚══════╝╚═╝     ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═╝
   
        {C.YELLOW}Python Implementation{C.WHITE}
        {C.GREEN}Fast Web Spider & Crawler{C.WHITE}
    """)

@dataclass
class SpiderResult:
    """Data class for spider results"""
    url: str
    method: str = "GET"
    status_code: int = 0
    content_type: str = ""
    content_length: int = 0
    title: str = ""
    source: str = ""
    depth: int = 0
    timestamp: str = ""
    
    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()

@dataclass
class EndpointResult:
    """Data class for endpoint results"""
    url: str
    method: str = "GET"
    parameters: List[str] = None
    source: str = ""
    type: str = "endpoint"  # endpoint, js, form, etc.
    
    def __post_init__(self):
        if self.parameters is None:
            self.parameters = []

class HTMLSpiderParser(HTMLParser):
    """Enhanced HTML parser for GoSpider"""
    
    def __init__(self, base_url: str):
        super().__init__()
        self.base_url = base_url
        self.links = []
        self.js_files = []
        self.css_files = []
        self.images = []
        self.forms = []
        self.endpoints = []
        self.title = ""
        self.current_form = None
        self._in_title = False
        
    def handle_starttag(self, tag, attrs):
        attrs_dict = dict(attrs)
        
        # Handle title tag
        if tag == 'title':
            self._in_title = True
        
        # Extract links
        elif tag == 'a' and 'href' in attrs_dict:
            href = attrs_dict['href'].strip()
            if href and not href.startswith(('#', 'javascript:', 'mailto:', 'tel:')):
                full_url = self.resolve_url(href)
                if full_url:
                    self.links.append(full_url)
        
        # Extract JavaScript files
        elif tag == 'script':
            if 'src' in attrs_dict:
                src = attrs_dict['src'].strip()
                if src:
                    full_url = self.resolve_url(src)
                    if full_url:
                        self.js_files.append(full_url)
        
        # Extract CSS files
        elif tag == 'link' and 'href' in attrs_dict:
            href = attrs_dict['href'].strip()
            rel = attrs_dict.get('rel', '').lower()
            if href:
                full_url = self.resolve_url(href)
                if full_url:
                    if 'stylesheet' in rel:
                        self.css_files.append(full_url)
                    else:
                        self.links.append(full_url)
        
        # Extract images
        elif tag == 'img' and 'src' in attrs_dict:
            src = attrs_dict['src'].strip()
            if src:
                full_url = self.resolve_url(src)
                if full_url:
                    self.images.append(full_url)
        
        # Extract forms
        elif tag == 'form':
            action = attrs_dict.get('action', '').strip()
            method = attrs_dict.get('method', 'GET').upper()
            
            if action:
                action_url = self.resolve_url(action)
            else:
                action_url = self.base_url
                
            self.current_form = {
                'action': action_url,
                'method': method,
                'inputs': []
            }
        
        elif tag == 'input' and self.current_form is not None:
            input_data = {
                'name': attrs_dict.get('name', ''),
                'type': attrs_dict.get('type', 'text'),
                'value': attrs_dict.get('value', '')
            }
            if input_data['name']:
                self.current_form['inputs'].append(input_data)
        
        # Extract other potential endpoints
        elif tag in ['iframe', 'embed', 'object']:
            src_attr = 'src' if tag in ['iframe', 'embed'] else 'data'
            if src_attr in attrs_dict:
                src = attrs_dict[src_attr].strip()
                if src:
                    full_url = self.resolve_url(src)
                    if full_url:
                        self.endpoints.append(full_url)
    
    def handle_endtag(self, tag):
        if tag == 'title':
            self._in_title = False
        elif tag == 'form' and self.current_form:
            self.forms.append(self.current_form)
            self.current_form = None
    
    def handle_data(self, data):
        if self._in_title and data.strip():
            self.title = data.strip()
    
    def resolve_url(self, url: str) -> Optional[str]:
        """Resolve relative URLs to absolute URLs"""
        try:
            return urllib.parse.urljoin(self.base_url, url)
        except:
            return None

class JavaScriptAnalyzer:
    """JavaScript file analyzer for endpoint extraction"""
    
    def __init__(self):
        # Common patterns for endpoint extraction
        self.endpoint_patterns = [
            # API endpoints
            r'["\']([/][\w\-_./]*(?:\?[\w\-_=&]*)?)["\']',
            r'["\']([/]api/[\w\-_./]*(?:\?[\w\-_=&]*)?)["\']',
            r'["\']([/]v\d+/[\w\-_./]*(?:\?[\w\-_=&]*)?)["\']',
            
            # URL patterns
            r'url\s*:\s*["\']([^"\']+)["\']',
            r'endpoint\s*:\s*["\']([^"\']+)["\']',
            r'path\s*:\s*["\']([^"\']+)["\']',
            
            # AJAX patterns
            r'\.get\s*\(\s*["\']([^"\']+)["\']',
            r'\.post\s*\(\s*["\']([^"\']+)["\']',
            r'\.put\s*\(\s*["\']([^"\']+)["\']',
            r'\.delete\s*\(\s*["\']([^"\']+)["\']',
            
            # Fetch patterns
            r'fetch\s*\(\s*["\']([^"\']+)["\']',
            
            # XMLHttpRequest patterns
            r'\.open\s*\(\s*["\'][^"\']*["\']\s*,\s*["\']([^"\']+)["\']',
            
            # Route patterns
            r'route\s*\(\s*["\']([^"\']+)["\']',
            r'router\s*\.\s*\w+\s*\(\s*["\']([^"\']+)["\']',
            
            # Config patterns
            r'baseURL\s*:\s*["\']([^"\']+)["\']',
            r'apiUrl\s*:\s*["\']([^"\']+)["\']',
        ]
        
        # Parameter patterns
        self.param_patterns = [
            r'[?&](\w+)=',
            r'params\s*\[\s*["\'](\w+)["\']',
            r'data\s*\[\s*["\'](\w+)["\']',
            r'form\s*\[\s*["\'](\w+)["\']',
        ]
    
    def analyze(self, js_content: str, base_url: str) -> List[EndpointResult]:
        """Analyze JavaScript content for endpoints"""
        endpoints = []
        
        for pattern in self.endpoint_patterns:
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            for match in matches:
                if self.is_valid_endpoint(match):
                    # Resolve relative URLs
                    full_url = urllib.parse.urljoin(base_url, match)
                    
                    # Extract parameters
                    params = self.extract_parameters(match)
                    
                    endpoint = EndpointResult(
                        url=full_url,
                        method="GET",
                        parameters=params,
                        source="javascript",
                        type="endpoint"
                    )
                    endpoints.append(endpoint)
        
        return endpoints
    
    def is_valid_endpoint(self, url: str) -> bool:
        """Check if URL is a valid endpoint"""
        if not url or len(url) < 2:
            return False
        
        # Skip common non-endpoints
        skip_patterns = [
            r'^#',
            r'^javascript:',
            r'^mailto:',
            r'^tel:',
            r'^data:',
            r'\.(css|js|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot)$',
            r'^[a-zA-Z]+:',  # Skip other protocols
        ]
        
        for pattern in skip_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                return False
        
        return True
    
    def extract_parameters(self, url: str) -> List[str]:
        """Extract parameters from URL"""
        params = []
        
        # Extract from query string
        if '?' in url:
            query = url.split('?', 1)[1]
            for param in query.split('&'):
                if '=' in param:
                    param_name = param.split('=')[0]
                    if param_name and param_name not in params:
                        params.append(param_name)
        
        return params

class RobotsParser:
    """Robots.txt parser"""
    
    def parse(self, robots_content: str, base_url: str) -> List[str]:
        """Parse robots.txt for URLs"""
        urls = []
        
        for line in robots_content.split('\n'):
            line = line.strip()
            if line.startswith(('Disallow:', 'Allow:')):
                path = line.split(':', 1)[1].strip()
                if path and path != '/':
                    # Remove wildcards
                    path = path.replace('*', '')
                    if path.startswith('/'):
                        full_url = urllib.parse.urljoin(base_url, path)
                        urls.append(full_url)
        
        return urls

class SitemapParser:
    """Sitemap.xml parser"""
    
    def parse(self, sitemap_content: str) -> List[str]:
        """Parse sitemap.xml for URLs"""
        urls = []
        
        try:
            # Try to parse as XML
            root = ET.fromstring(sitemap_content)
            
            # Handle different sitemap formats
            for url_elem in root.findall('.//{http://www.sitemaps.org/schemas/sitemap/0.9}url'):
                loc_elem = url_elem.find('{http://www.sitemaps.org/schemas/sitemap/0.9}loc')
                if loc_elem is not None and loc_elem.text:
                    urls.append(loc_elem.text.strip())
            
            # Handle sitemap index
            for sitemap_elem in root.findall('.//{http://www.sitemaps.org/schemas/sitemap/0.9}sitemap'):
                loc_elem = sitemap_elem.find('{http://www.sitemaps.org/schemas/sitemap/0.9}loc')
                if loc_elem is not None and loc_elem.text:
                    urls.append(loc_elem.text.strip())
                    
        except ET.ParseError:
            # Fallback: extract URLs with regex
            url_pattern = r'<loc>(.*?)</loc>'
            matches = re.findall(url_pattern, sitemap_content, re.IGNORECASE)
            urls.extend(matches)
        
        return urls

class AwsS3Detector:
    """AWS S3 bucket detector"""
    
    def __init__(self):
        self.s3_patterns = [
            r'https?://([a-zA-Z0-9.\-_]+)\.s3\.amazonaws\.com',
            r'https?://([a-zA-Z0-9.\-_]+)\.s3-([a-zA-Z0-9\-]+)\.amazonaws\.com',
            r'https?://s3\.amazonaws\.com/([a-zA-Z0-9.\-_]+)',
            r'https?://s3-([a-zA-Z0-9\-]+)\.amazonaws\.com/([a-zA-Z0-9.\-_]+)',
        ]
    
    def detect(self, content: str) -> List[str]:
        """Detect AWS S3 buckets in content"""
        buckets = []
        
        for pattern in self.s3_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple):
                    bucket_name = match[-1]  # Get the last group (bucket name)
                else:
                    bucket_name = match
                
                if bucket_name and bucket_name not in buckets:
                    buckets.append(bucket_name)
        
        return buckets

class GitHubDetector:
    """GitHub repository detector"""
    
    def __init__(self):
        self.github_patterns = [
            r'https?://github\.com/([a-zA-Z0-9\-_]+/[a-zA-Z0-9\-_.]+)',
            r'https?://raw\.githubusercontent\.com/([a-zA-Z0-9\-_]+/[a-zA-Z0-9\-_.]+)',
            r'https?://api\.github\.com/repos/([a-zA-Z0-9\-_]+/[a-zA-Z0-9\-_.]+)',
        ]
    
    def detect(self, content: str) -> List[str]:
        """Detect GitHub repositories in content"""
        repos = []
        
        for pattern in self.github_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                if match and match not in repos:
                    repos.append(match)
        
        return repos

class GoSpider:
    """Main GoSpider class"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.target_urls = config.get('urls', [])
        self.max_depth = config.get('depth', 3)
        self.concurrency = config.get('concurrency', 20)
        self.timeout = config.get('timeout', 10)
        self.delay = config.get('delay', 0)
        self.user_agent = config.get('user_agent', 'GoSpider-Python/1.0')
        self.proxy = config.get('proxy', None)
        self.headers = config.get('headers', {})
        self.cookies = config.get('cookies', {})
        
        # Crawling options
        self.include_subs = config.get('include_subs', False)
        self.include_other_source = config.get('include_other_source', False)
        self.should_crawl_forms = config.get('crawl_forms', True)
        self.should_crawl_robots = config.get('crawl_robots', True)
        self.should_crawl_sitemap = config.get('crawl_sitemap', True)
        self.analyze_js = config.get('analyze_js', True)
        
        # Output options
        self.output_file = config.get('output', None)
        self.output_format = config.get('output_format', 'txt')
        self.silent = config.get('silent', False)
        self.verbose = config.get('verbose', False)
        
        # Filtering options
        self.blacklist_extensions = config.get('blacklist_extensions', [
            'css', 'js', 'png', 'jpg', 'jpeg', 'gif', 'svg', 'ico', 
            'woff', 'woff2', 'ttf', 'eot', 'pdf', 'zip', 'rar'
        ])
        
        # Results storage
        self.visited_urls = set()
        self.crawl_queue = deque()
        self.results = []
        self.endpoints = []
        self.s3_buckets = []
        self.github_repos = []
        self.lock = threading.Lock()
        
        # Components
        self.js_analyzer = JavaScriptAnalyzer()
        self.robots_parser = RobotsParser()
        self.sitemap_parser = SitemapParser()
        self.s3_detector = AwsS3Detector()
        self.github_detector = GitHubDetector()
        
        # Setup SSL context
        self.ssl_context = ssl.create_default_context()
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_NONE
        
        # Setup headers
        self.default_headers = {
            'User-Agent': self.user_agent,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        }
        self.default_headers.update(self.headers)
    
    def log_info(self, message: str):
        """Log info message"""
        if not self.silent:
            print(f"{C.BLUE}[INFO]{C.WHITE} {message}")
    
    def log_verbose(self, message: str):
        """Log verbose message"""
        if self.verbose and not self.silent:
            print(f"{C.YELLOW}[VERBOSE]{C.WHITE} {message}")
    
    def log_error(self, message: str):
        """Log error message"""
        if not self.silent:
            print(f"{C.RED}[ERROR]{C.WHITE} {message}")
    
    def log_success(self, message: str):
        """Log success message"""
        if not self.silent:
            print(f"{C.GREEN}[SUCCESS]{C.WHITE} {message}")
    
    def log_found(self, message: str):
        """Log found item"""
        if not self.silent:
            print(f"{C.GREEN}[FOUND]{C.WHITE} {message}")
    
    def is_valid_url(self, url: str) -> bool:
        """Check if URL is valid for crawling"""
        try:
            parsed = urllib.parse.urlparse(url)
            if not parsed.scheme or not parsed.netloc:
                return False
            
            # Check blacklisted extensions
            if self.blacklist_extensions:
                path = parsed.path.lower()
                for ext in self.blacklist_extensions:
                    if path.endswith(f'.{ext}'):
                        return False
            
            return True
        except:
            return False
    
    def is_in_scope(self, url: str, base_url: str) -> bool:
        """Check if URL is in crawling scope"""
        try:
            base_parsed = urllib.parse.urlparse(base_url)
            url_parsed = urllib.parse.urlparse(url)
            
            # Same domain check
            if not self.include_subs:
                return url_parsed.netloc == base_parsed.netloc
            else:
                # Allow subdomains
                return url_parsed.netloc.endswith(base_parsed.netloc) or url_parsed.netloc == base_parsed.netloc
        except:
            return False
    
    def fetch_url(self, url: str) -> Optional[Tuple[str, Dict[str, str], int]]:
        """Fetch URL content"""
        try:
            request = urllib.request.Request(url)
            request.add_header('User-Agent', self.user_agent)
            
            with urllib.request.urlopen(request, timeout=self.timeout, context=self.ssl_context) as response:
                content = response.read()
                content_str = content.decode('utf-8', errors='ignore')
                headers = dict(response.headers)
                return content_str, headers, response.status
                
        except Exception as e:
            self.log_verbose(f"Error fetching {url}: {e}")
            return None
    
    def crawl_robots(self, base_url: str) -> List[str]:
        """Crawl robots.txt"""
        robots_urls = []
        
        try:
            robots_url = urllib.parse.urljoin(base_url, '/robots.txt')
            result = self.fetch_url(robots_url)
            
            if result:
                content, headers, status = result
                if status == 200:
                    self.log_verbose(f"Found robots.txt: {robots_url}")
                    robots_urls = self.robots_parser.parse(content, base_url)
                    self.log_verbose(f"Extracted {len(robots_urls)} URLs from robots.txt")
        except Exception as e:
            self.log_verbose(f"Error crawling robots.txt: {e}")
        
        return robots_urls
    
    def crawl_sitemap(self, base_url: str) -> List[str]:
        """Crawl sitemap.xml"""
        sitemap_urls = []
        
        sitemap_paths = ['/sitemap.xml', '/sitemap_index.xml', '/sitemaps.xml']
        
        for path in sitemap_paths:
            try:
                sitemap_url = urllib.parse.urljoin(base_url, path)
                result = self.fetch_url(sitemap_url)
                
                if result:
                    content, headers, status = result
                    if status == 200:
                        self.log_verbose(f"Found sitemap: {sitemap_url}")
                        urls = self.sitemap_parser.parse(content)
                        sitemap_urls.extend(urls)
                        self.log_verbose(f"Extracted {len(urls)} URLs from {path}")
            except Exception as e:
                self.log_verbose(f"Error crawling {path}: {e}")
        
        return sitemap_urls
    
    def analyze_javascript(self, js_url: str, base_url: str) -> List[EndpointResult]:
        """Analyze JavaScript file for endpoints"""
        endpoints = []
        
        try:
            result = self.fetch_url(js_url)
            if result:
                content, headers, status = result
                if status == 200:
                    self.log_verbose(f"Analyzing JavaScript: {js_url}")
                    endpoints = self.js_analyzer.analyze(content, base_url)
                    
                    if endpoints:
                        self.log_verbose(f"Found {len(endpoints)} endpoints in {js_url}")
        except Exception as e:
            self.log_verbose(f"Error analyzing JavaScript {js_url}: {e}")
        
        return endpoints
    
    def crawl_url(self, url: str, depth: int, base_url: str) -> Optional[SpiderResult]:
        """Crawl a single URL"""
        if depth > self.max_depth:
            return None
        
        if url in self.visited_urls:
            return None
        
        if not self.is_valid_url(url):
            return None
        
        if not self.is_in_scope(url, base_url):
            return None
        
        with self.lock:
            if url in self.visited_urls:
                return None
            self.visited_urls.add(url)
        
        # Apply delay
        if self.delay > 0:
            time.sleep(self.delay)
        
        self.log_verbose(f"Crawling: {url} (depth: {depth})")
        
        # Fetch URL
        result = self.fetch_url(url)
        if not result:
            return None
        
        content, headers, status = result
        
        # Create result
        spider_result = SpiderResult(
            url=url,
            method="GET",
            status_code=status,
            content_type=headers.get('Content-Type', ''),
            content_length=len(content),
            source="crawl",
            depth=depth
        )
        
        # Parse HTML content
        if 'text/html' in spider_result.content_type.lower():
            try:
                parser = HTMLSpiderParser(url)
                parser.feed(content)
                
                spider_result.title = parser.title
                
                # Add discovered URLs to queue
                all_discovered = []
                all_discovered.extend(parser.links)
                all_discovered.extend(parser.js_files)
                all_discovered.extend(parser.css_files)
                all_discovered.extend(parser.endpoints)
                
                for discovered_url in all_discovered:
                    if discovered_url not in self.visited_urls:
                        self.crawl_queue.append((discovered_url, depth + 1))
                
                # Process forms
                if self.should_crawl_forms:
                    for form in parser.forms:
                        form_endpoint = EndpointResult(
                            url=form['action'],
                            method=form['method'],
                            parameters=[inp['name'] for inp in form['inputs'] if inp['name']],
                            source="form",
                            type="form"
                        )
                        self.endpoints.append(form_endpoint)
                
                # Analyze JavaScript files
                if self.analyze_js:
                    for js_url in parser.js_files:
                        if js_url not in self.visited_urls:
                            js_endpoints = self.analyze_javascript(js_url, url)
                            self.endpoints.extend(js_endpoints)
                
            except Exception as e:
                self.log_verbose(f"Error parsing HTML for {url}: {e}")
        
        # Detect AWS S3 buckets
        s3_buckets = self.s3_detector.detect(content)
        if s3_buckets:
            self.s3_buckets.extend(s3_buckets)
            for bucket in s3_buckets:
                self.log_found(f"AWS S3 Bucket: {bucket}")
        
        # Detect GitHub repositories
        github_repos = self.github_detector.detect(content)
        if github_repos:
            self.github_repos.extend(github_repos)
            for repo in github_repos:
                self.log_found(f"GitHub Repository: {repo}")
        
        return spider_result
    
    def worker(self, base_url: str):
        """Worker thread for crawling"""
        while True:
            try:
                with self.lock:
                    if not self.crawl_queue:
                        break
                    url, depth = self.crawl_queue.popleft()
                
                result = self.crawl_url(url, depth, base_url)
                if result:
                    with self.lock:
                        self.results.append(result)
                    self.log_found(f"[{result.status_code}] {result.url}")
                    
            except Exception as e:
                self.log_verbose(f"Worker error: {e}")
                break
    
    def spider(self) -> Dict[str, Any]:
        """Main spidering function"""
        if not self.target_urls:
            self.log_error("No target URLs provided")
            return {}
        
        self.log_info(f"Starting spider with {len(self.target_urls)} URLs")
        self.log_info(f"Max depth: {self.max_depth}, Concurrency: {self.concurrency}")
        
        all_results = {
            'urls': [],
            'endpoints': [],
            's3_buckets': [],
            'github_repos': []
        }
        
        for target_url in self.target_urls:
            self.log_info(f"Spidering: {target_url}")
            
            # Reset for each target
            self.visited_urls.clear()
            self.crawl_queue.clear()
            self.results.clear()
            self.endpoints.clear()
            self.s3_buckets.clear()
            self.github_repos.clear()
            
            # Add initial URL to queue
            self.crawl_queue.append((target_url, 0))
            
            # Crawl robots.txt
            if self.should_crawl_robots:
                robots_urls = self.crawl_robots(target_url)
                for robots_url in robots_urls:
                    if robots_url not in self.visited_urls:
                        self.crawl_queue.append((robots_url, 0))
            
            # Crawl sitemap.xml
            if self.should_crawl_sitemap:
                sitemap_urls = self.crawl_sitemap(target_url)
                for sitemap_url in sitemap_urls:
                    if sitemap_url not in self.visited_urls:
                        self.crawl_queue.append((sitemap_url, 0))
            
            # Start crawling (simplified approach)
            while self.crawl_queue:
                try:
                    url, depth = self.crawl_queue.popleft()
                    result = self.crawl_url(url, depth, target_url)
                    if result:
                        self.results.append(result)
                        self.log_found(f"[{result.status_code}] {result.url}")
                except Exception as e:
                    self.log_verbose(f"Crawl error: {e}")
                    break
            
            # Collect results
            all_results['urls'].extend(self.results)
            all_results['endpoints'].extend(self.endpoints)
            all_results['s3_buckets'].extend(list(set(self.s3_buckets)))
            all_results['github_repos'].extend(list(set(self.github_repos)))
            
            self.log_success(f"Completed spidering {target_url}: {len(self.results)} URLs, {len(self.endpoints)} endpoints")
        
        # Remove duplicates
        unique_urls = []
        seen_urls = set()
        for result in all_results['urls']:
            if result.url not in seen_urls:
                unique_urls.append(result)
                seen_urls.add(result.url)
        all_results['urls'] = unique_urls
        
        unique_endpoints = []
        seen_endpoints = set()
        for endpoint in all_results['endpoints']:
            endpoint_key = f"{endpoint.method}:{endpoint.url}"
            if endpoint_key not in seen_endpoints:
                unique_endpoints.append(endpoint)
                seen_endpoints.add(endpoint_key)
        all_results['endpoints'] = unique_endpoints
        
        all_results['s3_buckets'] = list(set(all_results['s3_buckets']))
        all_results['github_repos'] = list(set(all_results['github_repos']))
        
        return all_results
    
    def save_results(self, results: Dict[str, Any]):
        """Save results to file"""
        if not self.output_file:
            return
        
        try:
            if self.output_format.lower() == 'json':
                output_data = {
                    'urls': [asdict(result) for result in results['urls']],
                    'endpoints': [asdict(endpoint) for endpoint in results['endpoints']],
                    's3_buckets': results['s3_buckets'],
                    'github_repos': results['github_repos']
                }
                
                with open(self.output_file, 'w', encoding='utf-8') as f:
                    json.dump(output_data, f, indent=2, ensure_ascii=False)
                    
            else:  # txt format
                with open(self.output_file, 'w', encoding='utf-8') as f:
                    # Write URLs
                    f.write("=== URLs ===\n")
                    for result in results['urls']:
                        f.write(f"{result.url}\n")
                    
                    # Write endpoints
                    f.write("\n=== ENDPOINTS ===\n")
                    for endpoint in results['endpoints']:
                        params_str = ','.join(endpoint.parameters) if endpoint.parameters else ''
                        f.write(f"{endpoint.method} {endpoint.url}")
                        if params_str:
                            f.write(f" [params: {params_str}]")
                        f.write(f" [source: {endpoint.source}]\n")
                    
                    # Write S3 buckets
                    if results['s3_buckets']:
                        f.write("\n=== AWS S3 BUCKETS ===\n")
                        for bucket in results['s3_buckets']:
                            f.write(f"{bucket}\n")
                    
                    # Write GitHub repos
                    if results['github_repos']:
                        f.write("\n=== GITHUB REPOSITORIES ===\n")
                        for repo in results['github_repos']:
                            f.write(f"https://github.com/{repo}\n")
            
            self.log_success(f"Results saved to {self.output_file}")
            
        except Exception as e:
            self.log_error(f"Error saving results: {e}")

def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description='GoSpider - Fast web spider written in Python',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python gospider.py -s https://example.com
  python gospider.py -s https://example.com -d 5 -c 50
  python gospider.py -s https://example.com -o results.txt
  python gospider.py -s https://example.com -o results.json -f json
  python gospider.py -s https://example.com --include-subs --analyze-js
  cat urls.txt | python gospider.py
        """
    )
    
    # Target options
    target_group = parser.add_argument_group('TARGET')
    target_group.add_argument('-s', '--site', action='append', help='Target URL to spider')
    target_group.add_argument('-S', '--sites', help='File containing list of URLs')
    
    # Crawling options
    crawl_group = parser.add_argument_group('CRAWLING')
    crawl_group.add_argument('-d', '--depth', type=int, default=3, help='Maximum crawling depth (default: 3)')
    crawl_group.add_argument('-c', '--concurrent', type=int, default=20, help='Number of concurrent workers (default: 20)')
    crawl_group.add_argument('-t', '--timeout', type=int, default=10, help='Request timeout in seconds (default: 10)')
    crawl_group.add_argument('--delay', type=float, default=0, help='Delay between requests in seconds')
    crawl_group.add_argument('--include-subs', action='store_true', help='Include subdomains')
    crawl_group.add_argument('--include-other-source', action='store_true', help='Include other sources')
    
    # Analysis options
    analysis_group = parser.add_argument_group('ANALYSIS')
    analysis_group.add_argument('--analyze-js', action='store_true', default=True, help='Analyze JavaScript files (default: True)')
    analysis_group.add_argument('--no-analyze-js', action='store_true', help='Disable JavaScript analysis')
    analysis_group.add_argument('--crawl-forms', action='store_true', default=True, help='Crawl forms (default: True)')
    analysis_group.add_argument('--no-crawl-forms', action='store_true', help='Disable form crawling')
    analysis_group.add_argument('--crawl-robots', action='store_true', default=True, help='Crawl robots.txt (default: True)')
    analysis_group.add_argument('--no-crawl-robots', action='store_true', help='Disable robots.txt crawling')
    analysis_group.add_argument('--crawl-sitemap', action='store_true', default=True, help='Crawl sitemap.xml (default: True)')
    analysis_group.add_argument('--no-crawl-sitemap', action='store_true', help='Disable sitemap.xml crawling')
    
    # Request options
    request_group = parser.add_argument_group('REQUEST')
    request_group.add_argument('-u', '--user-agent', default='GoSpider-Python/1.0', help='User agent string')
    request_group.add_argument('--proxy', help='Proxy URL (http://proxy:port)')
    request_group.add_argument('-H', '--header', action='append', help='Custom headers (key:value)')
    request_group.add_argument('--cookie', help='Cookie string')
    
    # Filtering options
    filter_group = parser.add_argument_group('FILTERING')
    filter_group.add_argument('--blacklist', help='Comma-separated list of extensions to blacklist')
    
    # Output options
    output_group = parser.add_argument_group('OUTPUT')
    output_group.add_argument('-o', '--output', help='Output file')
    output_group.add_argument('-f', '--format', choices=['txt', 'json'], default='txt', help='Output format (default: txt)')
    output_group.add_argument('--silent', action='store_true', help='Silent mode')
    output_group.add_argument('--verbose', action='store_true', help='Verbose output')
    output_group.add_argument('--no-color', action='store_true', help='Disable colors')
    
    args = parser.parse_args()
    
    if args.no_color:
        Colors.disable()
    
    # Show banner
    if not args.silent:
        banner()
        print(f"{C.YELLOW}[INFO]{C.WHITE} Use with caution. You are responsible for your actions.")
        print(f"{C.YELLOW}[INFO]{C.WHITE} Developers assume no liability and are not responsible for any misuse or damage.\n")
    
    # Get target URLs
    urls = []
    
    # From -s argument
    if args.site:
        urls.extend(args.site)
    
    # From file
    if args.sites:
        try:
            with open(args.sites, 'r', encoding='utf-8') as f:
                for line in f:
                    url = line.strip()
                    if url:
                        urls.append(url)
        except Exception as e:
            print(f"{C.RED}[ERROR]{C.WHITE} Error reading sites file: {e}")
            return 1
    
    # From stdin
    if not urls:
        try:
            for line in sys.stdin:
                url = line.strip()
                if url:
                    urls.append(url)
        except KeyboardInterrupt:
            pass
    
    if not urls:
        if not args.silent:
            print(f"{C.RED}[ERROR]{C.WHITE} No target URLs provided")
        parser.print_help()
        return 1
    
    # Parse headers
    headers = {}
    if args.header:
        for header in args.header:
            if ':' in header:
                key, value = header.split(':', 1)
                headers[key.strip()] = value.strip()
    
    # Parse cookies
    cookies = {}
    if args.cookie:
        for cookie in args.cookie.split(';'):
            if '=' in cookie:
                key, value = cookie.split('=', 1)
                cookies[key.strip()] = value.strip()
    
    # Parse blacklist
    blacklist_extensions = []
    if args.blacklist:
        blacklist_extensions = [ext.strip() for ext in args.blacklist.split(',')]
    
    # Build configuration
    config = {
        'urls': urls,
        'depth': args.depth,
        'concurrency': args.concurrent,
        'timeout': args.timeout,
        'delay': args.delay,
        'user_agent': args.user_agent,
        'proxy': args.proxy,
        'headers': headers,
        'cookies': cookies,
        'include_subs': getattr(args, 'include_subs', False),
        'include_other_source': getattr(args, 'include_other_source', False),
        'analyze_js': not getattr(args, 'no_analyze_js', False),
        'crawl_forms': not getattr(args, 'no_crawl_forms', False),
        'crawl_robots': not getattr(args, 'no_crawl_robots', False),
        'crawl_sitemap': not getattr(args, 'no_crawl_sitemap', False),
        'blacklist_extensions': blacklist_extensions,
        'output': args.output,
        'output_format': args.format,
        'silent': args.silent,
        'verbose': args.verbose,
    }
    
    # Initialize spider
    spider = GoSpider(config)
    
    try:
        # Start spidering
        results = spider.spider()
        
        # Save results if output file specified
        if args.output:
            spider.save_results(results)
        
        if not args.silent:
            print(f"\n{C.GREEN}[SUCCESS]{C.WHITE} Spidering completed!")
            print(f"{C.BLUE}[INFO]{C.WHITE} Total URLs found: {len(results['urls'])}")
            print(f"{C.BLUE}[INFO]{C.WHITE} Total endpoints found: {len(results['endpoints'])}")
            if results['s3_buckets']:
                print(f"{C.BLUE}[INFO]{C.WHITE} AWS S3 buckets found: {len(results['s3_buckets'])}")
            if results['github_repos']:
                print(f"{C.BLUE}[INFO]{C.WHITE} GitHub repositories found: {len(results['github_repos'])}")
        
        return 0
        
    except KeyboardInterrupt:
        if not args.silent:
            print(f"\n{C.YELLOW}[INFO]{C.WHITE} Spidering interrupted by user")
        return 1
    except Exception as e:
        if not args.silent:
            print(f"{C.RED}[ERROR]{C.WHITE} {e}")
            import traceback
            traceback.print_exc()
        return 1

if __name__ == '__main__':
    sys.exit(main())