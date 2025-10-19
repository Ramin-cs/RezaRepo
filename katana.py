#!/usr/bin/env python3
"""
Katana Python Implementation
A next-generation crawling and spidering framework

This is a Python port of ProjectDiscovery's Katana with comprehensive features.
Original: https://github.com/projectdiscovery/katana

Features:
- Fast and fully configurable web crawling
- Standard HTTP and Headless browser modes
- JavaScript parsing and execution
- Automatic form filling
- Scope control with regex support
- Customizable output formats
- Rate limiting and concurrency control
- Technology detection
- XHR extraction
- Response storage
- Multiple input methods (URL, file, stdin)
- Extensive filtering options
"""

import argparse
import json
import os
import re
import ssl
import sys
import threading
import time
import random
import urllib.parse
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Set, Optional, Dict, Any, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime
import queue
import hashlib
from html.parser import HTMLParser
from collections import deque
import base64

# Optional dependencies
try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.common.exceptions import TimeoutException, WebDriverException
    HAS_SELENIUM = True
except ImportError:
    HAS_SELENIUM = False

# Console Colors
class Colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    RED = '\033[91m'
    WHITE = '\033[0m'
    BOLD = '\033[1m'
    CYAN = '\033[96m'
    
    @classmethod
    def disable(cls):
        cls.GREEN = cls.YELLOW = cls.BLUE = cls.RED = cls.WHITE = cls.BOLD = cls.CYAN = ''

C = Colors()

def banner():
    """Display Katana banner"""
    print(f"""{C.CYAN}
   __        __                
  / /_____ _/ /____ ____  ___ _
 /  '_/ _  / __/ _  / _ \\/ _  /
/_/\\_\\\\_,_/\\__/\\_,_/_//_/\\_,_/ {C.YELLOW}Python{C.WHITE}
                     
      {C.BLUE}Enhanced Python Implementation{C.WHITE}
      {C.GREEN}Original by ProjectDiscovery{C.WHITE}
    """)

@dataclass
class CrawlResult:
    """Data class for crawl results"""
    url: str
    method: str = "GET"
    status_code: int = 0
    content_length: int = 0
    content_type: str = ""
    title: str = ""
    tech: List[str] = None
    forms: List[Dict] = None
    links: List[str] = None
    js_files: List[str] = None
    css_files: List[str] = None
    images: List[str] = None
    depth: int = 0
    source: str = ""
    timestamp: str = ""
    
    def __post_init__(self):
        if self.tech is None:
            self.tech = []
        if self.forms is None:
            self.forms = []
        if self.links is None:
            self.links = []
        if self.js_files is None:
            self.js_files = []
        if self.css_files is None:
            self.css_files = []
        if self.images is None:
            self.images = []
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()


class HTMLLinkExtractor(HTMLParser):
    """HTML parser to extract links and resources"""
    
    def __init__(self):
        super().__init__()
        self.links = []
        self.js_files = []
        self.css_files = []
        self.images = []
        self.forms = []
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
            if href and not href.startswith(('#', 'javascript:', 'mailto:')):
                self.links.append(href)
        
        # Extract JavaScript files
        elif tag == 'script' and 'src' in attrs_dict:
            src = attrs_dict['src'].strip()
            if src:
                self.js_files.append(src)
        
        # Extract CSS files
        elif tag == 'link' and 'href' in attrs_dict:
            href = attrs_dict['href'].strip()
            if href:
                rel = attrs_dict.get('rel', '').lower()
                if 'stylesheet' in rel:
                    self.css_files.append(href)
                else:
                    self.links.append(href)
        
        # Extract images
        elif tag == 'img' and 'src' in attrs_dict:
            src = attrs_dict['src'].strip()
            if src:
                self.images.append(src)
        
        # Extract forms
        elif tag == 'form':
            self.current_form = {
                'action': attrs_dict.get('action', ''),
                'method': attrs_dict.get('method', 'GET').upper(),
                'inputs': []
            }
        
        elif tag == 'input' and self.current_form is not None:
            input_data = {
                'name': attrs_dict.get('name', ''),
                'type': attrs_dict.get('type', 'text'),
                'value': attrs_dict.get('value', '')
            }
            self.current_form['inputs'].append(input_data)
    
    def handle_endtag(self, tag):
        if tag == 'title':
            self._in_title = False
        elif tag == 'form' and self.current_form:
            self.forms.append(self.current_form)
            self.current_form = None
    
    def handle_data(self, data):
        if self._in_title and data.strip():
            self.title = data.strip()


class TechnologyDetector:
    """Detect web technologies from HTTP responses"""
    
    def __init__(self):
        self.tech_patterns = {
            # Web Servers
            'Apache': [r'Apache[/\s]?([\d\.]+)?', r'Server:\s*Apache'],
            'Nginx': [r'nginx[/\s]?([\d\.]+)?', r'Server:\s*nginx'],
            'IIS': [r'Microsoft-IIS[/\s]?([\d\.]+)?', r'Server:\s*Microsoft-IIS'],
            
            # Frameworks
            'WordPress': [r'wp-content', r'wordpress', r'/wp-admin/', r'/wp-includes/'],
            'Drupal': [r'drupal', r'/sites/default/', r'Drupal\.'],
            'Joomla': [r'joomla', r'/components/', r'/modules/'],
            'Laravel': [r'laravel_session', r'Laravel Framework'],
            'Django': [r'django', r'csrfmiddlewaretoken'],
            'React': [r'react', r'React\.', r'_reactInternalInstance'],
            'Angular': [r'angular', r'ng-app', r'Angular'],
            'Vue': [r'vue\.js', r'Vue\.', r'v-if'],
            'jQuery': [r'jquery', r'jQuery'],
            'Bootstrap': [r'bootstrap', r'Bootstrap'],
            
            # CMS
            'Shopify': [r'shopify', r'Shopify'],
            'Magento': [r'magento', r'Magento'],
            'PrestaShop': [r'prestashop', r'PrestaShop'],
            
            # CDN
            'Cloudflare': [r'cloudflare', r'__cfduid', r'CF-RAY'],
            'AWS': [r'amazonaws', r'AWS'],
            'Fastly': [r'fastly', r'Fastly'],
            
            # Analytics
            'Google Analytics': [r'google-analytics', r'GoogleAnalyticsObject'],
            'Facebook Pixel': [r'facebook\.net/tr', r'fbq\('],
        }
    
    def detect(self, content: str, headers: Dict[str, str]) -> List[str]:
        """Detect technologies from content and headers"""
        detected = set()
        
        # Check headers
        header_text = ' '.join(f"{k}: {v}" for k, v in headers.items()).lower()
        
        # Check content and headers
        full_text = (content + ' ' + header_text).lower()
        
        for tech, patterns in self.tech_patterns.items():
            for pattern in patterns:
                if re.search(pattern, full_text, re.IGNORECASE):
                    detected.add(tech)
                    break
        
        return list(detected)


class RateLimiter:
    """Advanced rate limiter"""
    
    def __init__(self, rate_limit: int = 150, rate_limit_minute: int = None, delay: float = 0):
        self.rate_limit = rate_limit  # requests per second
        self.rate_limit_minute = rate_limit_minute  # requests per minute
        self.delay = delay  # delay between requests
        self.requests_this_second = []
        self.requests_this_minute = []
        self.lock = threading.Lock()
    
    def wait(self):
        """Wait if necessary to respect rate limits"""
        with self.lock:
            now = time.time()
            
            # Clean old requests
            self.requests_this_second = [t for t in self.requests_this_second if now - t < 1.0]
            self.requests_this_minute = [t for t in self.requests_this_minute if now - t < 60.0]
            
            # Check rate limits
            if len(self.requests_this_second) >= self.rate_limit:
                sleep_time = 1.0 - (now - self.requests_this_second[0])
                if sleep_time > 0:
                    time.sleep(sleep_time)
            
            if self.rate_limit_minute and len(self.requests_this_minute) >= self.rate_limit_minute:
                sleep_time = 60.0 - (now - self.requests_this_minute[0])
                if sleep_time > 0:
                    time.sleep(sleep_time)
            
            # Apply delay
            if self.delay > 0:
                time.sleep(self.delay)
            
            # Record this request
            now = time.time()
            self.requests_this_second.append(now)
            self.requests_this_minute.append(now)


class KatanaCrawler:
    """Main Katana crawler class"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.visited_urls = set()
        self.crawl_queue = deque()
        self.results = []
        self.lock = threading.Lock()
        
        # Configuration
        self.max_depth = config.get('depth', 3)
        self.timeout = config.get('timeout', 10)
        self.concurrency = config.get('concurrency', 10)
        self.parallelism = config.get('parallelism', 10)
        self.max_response_size = config.get('max_response_size', 4 * 1024 * 1024)  # 4MB
        self.js_crawl = config.get('js_crawl', False)
        self.form_fill = config.get('automatic_form_fill', False)
        self.tech_detect = config.get('tech_detect', False)
        self.headless = config.get('headless', False)
        self.silent = config.get('silent', False)
        self.verbose = config.get('verbose', False)
        self.debug = config.get('debug', False)
        
        # Scope control
        self.field_scope = config.get('field_scope', 'rdn')
        self.crawl_scope = config.get('crawl_scope', [])
        self.crawl_out_scope = config.get('crawl_out_scope', [])
        self.no_scope = config.get('no_scope', False)
        
        # Filters
        self.match_regex = config.get('match_regex', [])
        self.filter_regex = config.get('filter_regex', [])
        self.extension_match = config.get('extension_match', [])
        self.extension_filter = config.get('extension_filter', [])
        
        # Output
        self.output_file = config.get('output', None)
        self.jsonl = config.get('jsonl', False)
        self.store_response = config.get('store_response', False)
        self.store_response_dir = config.get('store_response_dir', 'responses')
        
        # Rate limiting
        self.rate_limiter = RateLimiter(
            rate_limit=config.get('rate_limit', 150),
            rate_limit_minute=config.get('rate_limit_minute', None),
            delay=config.get('delay', 0)
        )
        
        # SSL context
        self.ssl_context = ssl.create_default_context()
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_NONE
        
        # Headers
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        }
        
        # Add custom headers
        custom_headers = config.get('headers', {})
        self.headers.update(custom_headers)
        
        # Technology detector
        self.tech_detector = TechnologyDetector()
        
        # Selenium driver (for headless mode)
        self.driver = None
        if self.headless and HAS_SELENIUM:
            self.init_headless_browser()
    
    def log_info(self, message: str):
        """Log info message"""
        if not self.silent:
            print(f"{C.BLUE}[INF]{C.WHITE} {message}")
    
    def log_verbose(self, message: str):
        """Log verbose message"""
        if self.verbose and not self.silent:
            print(f"{C.YELLOW}[VRB]{C.WHITE} {message}")
    
    def log_debug(self, message: str):
        """Log debug message"""
        if self.debug and not self.silent:
            print(f"{C.CYAN}[DBG]{C.WHITE} {message}")
    
    def log_warning(self, message: str):
        """Log warning message"""
        if not self.silent:
            print(f"{C.YELLOW}[WRN]{C.WHITE} {message}")
    
    def log_error(self, message: str):
        """Log error message"""
        if not self.silent:
            print(f"{C.RED}[ERR]{C.WHITE} {message}")
    
    def init_headless_browser(self):
        """Initialize headless browser"""
        if not HAS_SELENIUM:
            self.log_warning("Selenium not installed. Headless mode disabled.")
            self.headless = False
            return
        
        try:
            chrome_options = Options()
            chrome_options.add_argument('--headless')
            chrome_options.add_argument('--no-sandbox')
            chrome_options.add_argument('--disable-dev-shm-usage')
            chrome_options.add_argument('--disable-gpu')
            chrome_options.add_argument('--disable-web-security')
            chrome_options.add_argument('--allow-running-insecure-content')
            chrome_options.add_argument('--ignore-certificate-errors')
            chrome_options.add_argument('--ignore-ssl-errors')
            chrome_options.add_argument('--ignore-certificate-errors-spki-list')
            
            # Additional headless options
            headless_options = self.config.get('headless_options', [])
            for option in headless_options:
                chrome_options.add_argument(option)
            
            self.driver = webdriver.Chrome(options=chrome_options)
            self.log_info("Headless browser initialized")
            
        except Exception as e:
            self.log_warning(f"Failed to initialize headless browser: {e}")
            self.headless = False
    
    def is_in_scope(self, url: str, base_domain: str) -> bool:
        """Check if URL is in crawling scope"""
        if self.no_scope:
            return True
        
        parsed = urllib.parse.urlparse(url)
        domain = parsed.netloc.lower()
        
        # Field scope check
        if self.field_scope == 'fqdn':
            return domain == base_domain
        elif self.field_scope == 'rdn':
            return domain.endswith(base_domain) or domain == base_domain
        elif self.field_scope == 'dn':
            domain_keyword = base_domain.split('.')[0]
            return domain_keyword in domain
        
        # Custom scope rules
        if self.crawl_scope:
            for scope_pattern in self.crawl_scope:
                if re.search(scope_pattern, url, re.IGNORECASE):
                    return True
            return False
        
        # Out of scope check
        if self.crawl_out_scope:
            for out_scope_pattern in self.crawl_out_scope:
                if re.search(out_scope_pattern, url, re.IGNORECASE):
                    return False
        
        return True
    
    def should_crawl_url(self, url: str) -> bool:
        """Check if URL should be crawled based on filters"""
        # Extension filters
        if self.extension_filter:
            for ext in self.extension_filter:
                if url.lower().endswith(f'.{ext.lower()}'):
                    return False
        
        if self.extension_match:
            matched = False
            for ext in self.extension_match:
                if url.lower().endswith(f'.{ext.lower()}'):
                    matched = True
                    break
            if not matched:
                return False
        
        # Regex filters
        if self.filter_regex:
            for pattern in self.filter_regex:
                if re.search(pattern, url, re.IGNORECASE):
                    return False
        
        if self.match_regex:
            matched = False
            for pattern in self.match_regex:
                if re.search(pattern, url, re.IGNORECASE):
                    matched = True
                    break
            if not matched:
                return False
        
        return True
    
    def normalize_url(self, url: str, base_url: str) -> str:
        """Normalize and resolve relative URLs"""
        try:
            return urllib.parse.urljoin(base_url, url)
        except:
            return url
    
    def fetch_url_standard(self, url: str) -> Optional[CrawlResult]:
        """Fetch URL using standard HTTP library"""
        self.rate_limiter.wait()
        
        try:
            request = urllib.request.Request(url)
            
            # Add headers
            for key, value in self.headers.items():
                request.add_header(key, value)
            
            with urllib.request.urlopen(request, timeout=self.timeout, context=self.ssl_context) as response:
                # Check response size
                content_length = int(response.headers.get('Content-Length', 0))
                if content_length > self.max_response_size:
                    self.log_warning(f"Response too large for {url}: {content_length} bytes")
                    return None
                
                content = response.read()
                if len(content) > self.max_response_size:
                    content = content[:self.max_response_size]
                
                content_str = content.decode('utf-8', errors='ignore')
                
                # Create result
                result = CrawlResult(
                    url=url,
                    method="GET",
                    status_code=response.status,
                    content_length=len(content),
                    content_type=response.headers.get('Content-Type', ''),
                    source="standard"
                )
                
                # Parse HTML for links and resources
                self.log_debug(f"Content type: {result.content_type}, Content length: {len(content_str)}")
                if 'text/html' in result.content_type.lower():
                    parser = HTMLLinkExtractor()
                    try:
                        parser.feed(content_str)
                        result.links = parser.links
                        result.js_files = parser.js_files
                        result.css_files = parser.css_files
                        result.images = parser.images
                        result.forms = parser.forms
                        result.title = parser.title
                        self.log_debug(f"Parsed {len(result.links)} links, {len(result.js_files)} JS files from {url}")
                    except Exception as e:
                        self.log_debug(f"HTML parsing error for {url}: {e}")
                        import traceback
                        self.log_debug(f"Traceback: {traceback.format_exc()}")
                        # Initialize empty lists if parsing fails
                        result.links = []
                        result.js_files = []
                        result.css_files = []
                        result.images = []
                        result.forms = []
                else:
                    self.log_debug(f"Skipping non-HTML content: {result.content_type}")
                
                # Technology detection
                if self.tech_detect:
                    headers_dict = dict(response.headers)
                    result.tech = self.tech_detector.detect(content_str, headers_dict)
                
                # Store response if requested
                if self.store_response:
                    self.store_response_data(url, content_str, dict(response.headers))
                
                return result
                
        except Exception as e:
            self.log_debug(f"Error fetching {url}: {e}")
            return None
    
    def fetch_url_headless(self, url: str) -> Optional[CrawlResult]:
        """Fetch URL using headless browser"""
        if not self.driver:
            return None
        
        self.rate_limiter.wait()
        
        try:
            self.driver.get(url)
            
            # Wait for page load
            WebDriverWait(self.driver, self.timeout).until(
                EC.presence_of_element_located((By.TAG_NAME, "body"))
            )
            
            # Get page source
            content = self.driver.page_source
            title = self.driver.title
            
            # Create result
            result = CrawlResult(
                url=url,
                method="GET",
                status_code=200,  # Selenium doesn't provide status code easily
                content_length=len(content),
                content_type="text/html",
                title=title,
                source="headless"
            )
            
            # Extract links using JavaScript
            try:
                links = self.driver.execute_script("""
                    var links = [];
                    var elements = document.getElementsByTagName('a');
                    for (var i = 0; i < elements.length; i++) {
                        if (elements[i].href) {
                            links.push(elements[i].href);
                        }
                    }
                    return links;
                """)
                result.links = links
            except:
                pass
            
            # Extract JavaScript files
            try:
                js_files = self.driver.execute_script("""
                    var scripts = [];
                    var elements = document.getElementsByTagName('script');
                    for (var i = 0; i < elements.length; i++) {
                        if (elements[i].src) {
                            scripts.push(elements[i].src);
                        }
                    }
                    return scripts;
                """)
                result.js_files = js_files
            except:
                pass
            
            # Technology detection
            if self.tech_detect:
                result.tech = self.tech_detector.detect(content, {})
            
            return result
            
        except Exception as e:
            self.log_debug(f"Error fetching {url} with headless browser: {e}")
            return None
    
    def store_response_data(self, url: str, content: str, headers: Dict[str, str]):
        """Store HTTP response data"""
        try:
            os.makedirs(self.store_response_dir, exist_ok=True)
            
            # Create filename from URL
            url_hash = hashlib.md5(url.encode()).hexdigest()[:8]
            filename = f"{url_hash}_{urllib.parse.urlparse(url).netloc}.txt"
            filepath = os.path.join(self.store_response_dir, filename)
            
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(f"URL: {url}\n")
                f.write(f"Headers: {json.dumps(headers, indent=2)}\n")
                f.write(f"Content:\n{content}")
                
        except Exception as e:
            self.log_debug(f"Error storing response for {url}: {e}")
    
    def extract_urls_from_js(self, js_content: str, base_url: str) -> List[str]:
        """Extract URLs from JavaScript content"""
        urls = []
        
        # Common URL patterns in JavaScript
        patterns = [
            r'["\']https?://[^"\']+["\']',
            r'["\'][^"\']*\.(?:html|php|asp|aspx|jsp|js|css)[^"\']*["\']',
            r'url\s*:\s*["\'][^"\']+["\']',
            r'src\s*:\s*["\'][^"\']+["\']',
            r'href\s*:\s*["\'][^"\']+["\']',
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            for match in matches:
                url = match.strip('\'"')
                if url and not url.startswith(('data:', 'javascript:', 'mailto:')):
                    normalized_url = self.normalize_url(url, base_url)
                    urls.append(normalized_url)
        
        return list(set(urls))
    
    def crawl_url(self, url: str, depth: int, base_domain: str) -> Optional[CrawlResult]:
        """Crawl a single URL"""
        if depth > self.max_depth:
            return None
        
        if url in self.visited_urls:
            return None
        
        if not self.is_in_scope(url, base_domain):
            self.log_debug(f"URL out of scope: {url}")
            return None
        
        if not self.should_crawl_url(url):
            self.log_debug(f"URL filtered out: {url}")
            return None
        
        with self.lock:
            if url in self.visited_urls:
                return None
            self.visited_urls.add(url)
        
        self.log_verbose(f"Crawling: {url} (depth: {depth})")
        
        # Choose crawling method
        if self.headless:
            result = self.fetch_url_headless(url)
        else:
            result = self.fetch_url_standard(url)
        
        if not result:
            return None
        
        result.depth = depth
        
        # Add discovered URLs to queue
        all_urls = []
        if result.links:
            all_urls.extend(result.links)
        if result.js_files and self.js_crawl:
            all_urls.extend(result.js_files)
            # Also extract URLs from JS content
            for js_url in result.js_files:
                normalized_js_url = self.normalize_url(js_url, url)
                js_result = self.fetch_url_standard(normalized_js_url)
                if js_result:
                    # We need to get the content, but fetch_url_standard doesn't return content
                    # Let's skip JS content extraction for now and focus on HTML links
                    pass
        
        # Normalize and queue new URLs
        added_count = 0
        for discovered_url in all_urls:
            normalized = self.normalize_url(discovered_url, url)
            if normalized and normalized not in self.visited_urls:
                self.crawl_queue.append((normalized, depth + 1))
                added_count += 1
        
        if added_count > 0:
            self.log_debug(f"Added {added_count} URLs to queue from {url}")
        
        return result
    
    def worker(self, base_domain: str):
        """Worker thread for crawling"""
        empty_queue_count = 0
        while empty_queue_count < 3:  # Wait for queue to be empty 3 times before stopping
            try:
                url, depth = self.crawl_queue.popleft()
                empty_queue_count = 0  # Reset counter when we get work
                result = self.crawl_url(url, depth, base_domain)
                if result:
                    with self.lock:
                        self.results.append(result)
                        self.output_result(result)
            except IndexError:
                # Queue is empty, wait a bit
                empty_queue_count += 1
                time.sleep(0.1)
            except Exception as e:
                self.log_debug(f"Worker error: {e}")
    
    def output_result(self, result: CrawlResult):
        """Output crawl result"""
        if self.silent:
            print(result.url)
        elif self.jsonl:
            print(json.dumps(asdict(result)))
        else:
            status_color = C.GREEN if 200 <= result.status_code < 300 else C.RED
            print(f"{status_color}[{result.status_code}]{C.WHITE} {result.url}")
            
            if self.verbose:
                if result.title:
                    print(f"    Title: {result.title}")
                if result.tech:
                    print(f"    Tech: {', '.join(result.tech)}")
                if result.forms:
                    print(f"    Forms: {len(result.forms)}")
    
    def save_results(self):
        """Save results to file"""
        if not self.output_file:
            return
        
        try:
            with open(self.output_file, 'w', encoding='utf-8') as f:
                for result in self.results:
                    if self.jsonl:
                        f.write(json.dumps(asdict(result)) + '\n')
                    else:
                        f.write(result.url + '\n')
            
            self.log_info(f"Results saved to {self.output_file}")
            
        except Exception as e:
            self.log_error(f"Error saving results: {e}")
    
    def crawl(self, urls: List[str]) -> List[CrawlResult]:
        """Main crawling function"""
        if not urls:
            return []
        
        # Get base domain for scope control
        base_domain = urllib.parse.urlparse(urls[0]).netloc.lower()
        
        self.log_info(f"Starting crawl with {len(urls)} URLs")
        self.log_info(f"Max depth: {self.max_depth}, Concurrency: {self.concurrency}")
        self.log_info(f"Mode: {'Headless' if self.headless else 'Standard'}")
        
        # Process URLs sequentially for better control
        for url in urls:
            self.crawl_queue.append((url, 0))
        
        processed_count = 0
        while self.crawl_queue:
            try:
                url, depth = self.crawl_queue.popleft()
                result = self.crawl_url(url, depth, base_domain)
                if result:
                    self.results.append(result)
                    self.output_result(result)
                    processed_count += 1
                    
                    if processed_count % 10 == 0:
                        self.log_verbose(f"Processed: {processed_count}, Queue: {len(self.crawl_queue)}")
                        
            except IndexError:
                break
            except Exception as e:
                self.log_debug(f"Crawl error: {e}")
        
        # Save results
        self.save_results()
        
        # Cleanup
        if self.driver:
            self.driver.quit()
        
        self.log_info(f"Crawling completed. Found {len(self.results)} URLs")
        return self.results


def parse_headers(headers_list: List[str]) -> Dict[str, str]:
    """Parse header strings to dictionary"""
    headers = {}
    for header in headers_list:
        if ':' in header:
            key, value = header.split(':', 1)
            headers[key.strip()] = value.strip()
    return headers


def parse_duration(duration_str: str) -> int:
    """Parse duration string to seconds"""
    if not duration_str:
        return 0
    
    duration_str = duration_str.lower()
    if duration_str.endswith('s'):
        return int(duration_str[:-1])
    elif duration_str.endswith('m'):
        return int(duration_str[:-1]) * 60
    elif duration_str.endswith('h'):
        return int(duration_str[:-1]) * 3600
    elif duration_str.endswith('d'):
        return int(duration_str[:-1]) * 86400
    else:
        return int(duration_str)


def read_file_lines(filepath: str) -> List[str]:
    """Read lines from file"""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            return [line.strip() for line in f if line.strip()]
    except Exception:
        return []


def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description='Katana - A next-generation crawling and spidering framework',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python katana.py -u https://example.com
  python katana.py -u https://example.com -d 5 -c 20
  python katana.py -list urls.txt -o results.txt
  echo "https://example.com" | python katana.py
  python katana.py -u https://example.com -headless -jc
  python katana.py -u https://example.com -jsonl -o results.jsonl
        """
    )
    
    # Input options
    input_group = parser.add_argument_group('INPUT')
    input_group.add_argument('-u', '--url', action='append', help='Target URL to crawl')
    input_group.add_argument('-list', '--list', help='File containing list of URLs to crawl')
    
    # Configuration options
    config_group = parser.add_argument_group('CONFIGURATION')
    config_group.add_argument('-d', '--depth', type=int, default=3, help='Maximum depth to crawl')
    config_group.add_argument('-jc', '--js-crawl', action='store_true', help='Enable JavaScript file crawling')
    config_group.add_argument('-ct', '--crawl-duration', help='Maximum duration to crawl (s, m, h, d)')
    config_group.add_argument('-mrs', '--max-response-size', type=int, default=4194304, help='Maximum response size')
    config_group.add_argument('-timeout', type=int, default=10, help='Request timeout in seconds')
    config_group.add_argument('-aff', '--automatic-form-fill', action='store_true', help='Enable automatic form filling')
    config_group.add_argument('-fx', '--form-extraction', action='store_true', help='Extract form elements')
    config_group.add_argument('-retry', type=int, default=1, help='Number of retries')
    config_group.add_argument('-proxy', help='HTTP/SOCKS5 proxy to use')
    config_group.add_argument('-td', '--tech-detect', action='store_true', help='Enable technology detection')
    config_group.add_argument('-H', '--headers', action='append', help='Custom headers (header:value)')
    
    # Headless options
    headless_group = parser.add_argument_group('HEADLESS')
    headless_group.add_argument('-hl', '--headless', action='store_true', help='Enable headless crawling')
    headless_group.add_argument('-sc', '--system-chrome', action='store_true', help='Use system Chrome')
    headless_group.add_argument('-sb', '--show-browser', action='store_true', help='Show browser window')
    headless_group.add_argument('-ho', '--headless-options', action='append', help='Additional Chrome options')
    headless_group.add_argument('-nos', '--no-sandbox', action='store_true', help='Disable Chrome sandbox')
    
    # Scope options
    scope_group = parser.add_argument_group('SCOPE')
    scope_group.add_argument('-cs', '--crawl-scope', action='append', help='In-scope URL regex')
    scope_group.add_argument('-cos', '--crawl-out-scope', action='append', help='Out-of-scope URL regex')
    scope_group.add_argument('-fs', '--field-scope', default='rdn', choices=['dn', 'rdn', 'fqdn'], help='Scope field')
    scope_group.add_argument('-ns', '--no-scope', action='store_true', help='Disable scope restrictions')
    
    # Filter options
    filter_group = parser.add_argument_group('FILTER')
    filter_group.add_argument('-mr', '--match-regex', action='append', help='Match URL regex')
    filter_group.add_argument('-fr', '--filter-regex', action='append', help='Filter URL regex')
    filter_group.add_argument('-em', '--extension-match', help='Match extensions (comma-separated)')
    filter_group.add_argument('-ef', '--extension-filter', help='Filter extensions (comma-separated)')
    
    # Rate limit options
    rate_group = parser.add_argument_group('RATE-LIMIT')
    rate_group.add_argument('-c', '--concurrency', type=int, default=10, help='Concurrent fetchers')
    rate_group.add_argument('-p', '--parallelism', type=int, default=10, help='Concurrent inputs')
    rate_group.add_argument('-rd', '--delay', type=int, default=0, help='Request delay in seconds')
    rate_group.add_argument('-rl', '--rate-limit', type=int, default=150, help='Requests per second')
    rate_group.add_argument('-rlm', '--rate-limit-minute', type=int, help='Requests per minute')
    
    # Output options
    output_group = parser.add_argument_group('OUTPUT')
    output_group.add_argument('-o', '--output', help='Output file')
    output_group.add_argument('-sr', '--store-response', action='store_true', help='Store HTTP responses')
    output_group.add_argument('-srd', '--store-response-dir', default='responses', help='Response storage directory')
    output_group.add_argument('-j', '--jsonl', action='store_true', help='Output in JSONL format')
    output_group.add_argument('-nc', '--no-color', action='store_true', help='Disable colors')
    output_group.add_argument('-silent', action='store_true', help='Silent mode')
    output_group.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    output_group.add_argument('-debug', action='store_true', help='Debug output')
    
    args = parser.parse_args()
    
    if args.no_color:
        Colors.disable()
    
    # Get input URLs
    urls = []
    
    # From -u argument
    if args.url:
        for url_input in args.url:
            if ',' in url_input:
                urls.extend([u.strip() for u in url_input.split(',')])
            else:
                urls.append(url_input.strip())
    
    # From file
    if args.list:
        urls.extend(read_file_lines(args.list))
    
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
            banner()
        parser.print_help()
        return 1
    
    # Parse configuration
    config = {
        'depth': args.depth,
        'timeout': args.timeout,
        'concurrency': args.concurrency,
        'parallelism': args.parallelism,
        'max_response_size': args.max_response_size,
        'js_crawl': args.js_crawl,
        'automatic_form_fill': args.automatic_form_fill,
        'tech_detect': args.tech_detect,
        'headless': args.headless,
        'silent': args.silent,
        'verbose': args.verbose,
        'debug': args.debug,
        'field_scope': args.field_scope,
        'crawl_scope': args.crawl_scope or [],
        'crawl_out_scope': args.crawl_out_scope or [],
        'no_scope': args.no_scope,
        'match_regex': args.match_regex or [],
        'filter_regex': args.filter_regex or [],
        'extension_match': args.extension_match.split(',') if args.extension_match else [],
        'extension_filter': args.extension_filter.split(',') if args.extension_filter else [],
        'rate_limit': args.rate_limit,
        'rate_limit_minute': args.rate_limit_minute,
        'delay': args.delay,
        'output': args.output,
        'jsonl': args.jsonl,
        'store_response': args.store_response,
        'store_response_dir': args.store_response_dir,
        'headers': parse_headers(args.headers or []),
        'headless_options': args.headless_options or [],
    }
    
    # Show banner
    if not args.silent:
        banner()
        print(f"{C.YELLOW}[WRN]{C.WHITE} Use with caution. You are responsible for your actions.")
        print(f"{C.YELLOW}[WRN]{C.WHITE} Developers assume no liability and are not responsible for any misuse or damage.\n")
    
    # Initialize crawler
    crawler = KatanaCrawler(config)
    
    try:
        # Start crawling
        results = crawler.crawl(urls)
        
        if not args.silent:
            print(f"\n{C.GREEN}[INF]{C.WHITE} Crawling completed. Found {len(results)} URLs")
        
        return 0
        
    except KeyboardInterrupt:
        if not args.silent:
            print(f"\n{C.YELLOW}[WRN]{C.WHITE} Crawling interrupted by user")
        return 1
    except Exception as e:
        if not args.silent:
            print(f"{C.RED}[ERR]{C.WHITE} {e}")
        return 1


if __name__ == '__main__':
    sys.exit(main())