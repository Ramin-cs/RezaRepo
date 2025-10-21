#!/usr/bin/env python3
"""
Discovery Master - Ultimate Directory/File/Content Discovery Tool
Combines the best features from multiple tools:
- Gobuster: Fast directory/file bruteforcing
- GoSpider: Web crawling and endpoint discovery  
- Hakrawler: Link extraction and crawling
- Katana: Next-gen crawling with JS support
- Kiterunner: API endpoint discovery
- xnLinkFinder: Advanced link finding
- GAU: Archive URL collection
- Waybackurls: Wayback Machine URLs
- Waymore: Enhanced wayback functionality

Features:
- Multi-threaded parallel processing
- Directory/File bruteforcing
- Web crawling and spidering
- JavaScript analysis and endpoint extraction
- Archive URL collection (Wayback Machine, Common Crawl, etc.)
- API endpoint discovery
- Link extraction and analysis
- Content discovery and analysis
- Multiple output formats
- Advanced filtering and scope control
- Rate limiting and stealth mode
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
from concurrent.futures import ThreadPoolExecutor, as_completed, Future
from typing import List, Set, Optional, Dict, Any, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime
from html.parser import HTMLParser
from collections import deque
import queue
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
    """Display Discovery Master banner"""
    print(f"""{C.CYAN}
██████╗ ██╗███████╗ ██████╗ ██████╗ ██╗   ██╗███████╗██████╗ ██╗   ██╗
██╔══██╗██║██╔════╝██╔════╝██╔═══██╗██║   ██║██╔════╝██╔══██╗╚██╗ ██╔╝
██║  ██║██║███████╗██║     ██║   ██║██║   ██║█████╗  ██████╔╝ ╚████╔╝ 
██║  ██║██║╚════██║██║     ██║   ██║╚██╗ ██╔╝██╔══╝  ██╔══██╗  ╚██╔╝  
██████╔╝██║███████║╚██████╗╚██████╔╝ ╚████╔╝ ███████╗██║  ██║   ██║   
╚═════╝ ╚═╝╚══════╝ ╚═════╝ ╚═════╝   ╚═══╝  ╚══════╝╚═╝  ╚═╝   ╚═╝   

███╗   ███╗ █████╗ ███████╗████████╗███████╗██████╗ 
████╗ ████║██╔══██╗██╔════╝╚══██╔══╝██╔════╝██╔══██╗
██╔████╔██║███████║███████╗   ██║   █████╗  ██████╔╝
██║╚██╔╝██║██╔══██║╚════██║   ██║   ██╔══╝  ██╔══██╗
██║ ╚═╝ ██║██║  ██║███████║   ██║   ███████╗██║  ██║
╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝

        {C.YELLOW}Ultimate Directory/File/Content Discovery Tool{C.WHITE}
        {C.GREEN}Combining the best of 9+ discovery tools{C.WHITE}
    """)

@dataclass
class DiscoveryResult:
    """Unified result structure for all discovery types"""
    url: str
    method: str = "GET"
    status_code: int = 0
    content_length: int = 0
    content_type: str = ""
    title: str = ""
    source: str = ""  # bruteforce, crawl, archive, api, etc.
    result_type: str = ""  # directory, file, endpoint, link, etc.
    depth: int = 0
    parameters: List[str] = None
    headers: Dict[str, str] = None
    timestamp: str = ""
    
    def __post_init__(self):
        if self.parameters is None:
            self.parameters = []
        if self.headers is None:
            self.headers = {}
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()

class ThreadSafeResults:
    """Thread-safe results container"""
    def __init__(self):
        self.results = []
        self.seen_urls = set()
        self.lock = threading.Lock()
    
    def add_result(self, result: DiscoveryResult) -> bool:
        """Add result if not already seen"""
        with self.lock:
            url_key = f"{result.method}:{result.url}"
            if url_key not in self.seen_urls:
                self.seen_urls.add(url_key)
                self.results.append(result)
                return True
            return False
    
    def get_results(self) -> List[DiscoveryResult]:
        """Get all results"""
        with self.lock:
            return self.results.copy()
    
    def count(self) -> int:
        """Get result count"""
        with self.lock:
            return len(self.results)

class RateLimiter:
    """Advanced rate limiter for stealth operations"""
    def __init__(self, requests_per_second: float = 100, burst_size: int = 10):
        self.requests_per_second = requests_per_second
        self.burst_size = burst_size
        self.tokens = burst_size
        self.last_update = time.time()
        self.lock = threading.Lock()
    
    def acquire(self):
        """Acquire permission to make a request"""
        with self.lock:
            now = time.time()
            elapsed = now - self.last_update
            self.last_update = now
            
            # Add tokens based on elapsed time
            self.tokens = min(self.burst_size, self.tokens + elapsed * self.requests_per_second)
            
            if self.tokens >= 1:
                self.tokens -= 1
                return True
            else:
                # Calculate wait time
                wait_time = (1 - self.tokens) / self.requests_per_second
                time.sleep(wait_time)
                self.tokens = 0
                return True

class HTTPClient:
    """Optimized HTTP client with connection pooling"""
    def __init__(self, timeout: int = 10, user_agent: str = None):
        self.timeout = timeout
        self.user_agent = user_agent or "DiscoveryMaster/1.0"
        self.session_cache = {}
        
        # SSL context
        self.ssl_context = ssl.create_default_context()
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_NONE
        
    def request(self, url: str, method: str = "GET", headers: Dict[str, str] = None) -> Optional[Tuple[int, Dict[str, str], bytes]]:
        """Make HTTP request"""
        try:
            request = urllib.request.Request(url, method=method)
            
            # Add default headers
            request.add_header('User-Agent', self.user_agent)
            request.add_header('Accept', '*/*')
            request.add_header('Connection', 'keep-alive')
            
            # Add custom headers
            if headers:
                for key, value in headers.items():
                    request.add_header(key, value)
            
            with urllib.request.urlopen(request, timeout=self.timeout, context=self.ssl_context) as response:
                content = response.read()
                response_headers = dict(response.headers)
                return response.status, response_headers, content
                
        except urllib.error.HTTPError as e:
            return e.code, {}, b""
        except Exception:
            return 0, {}, b""

class DirectoryBruteforcer:
    """High-performance directory/file bruteforcing (Gobuster-inspired)"""
    
    def __init__(self, http_client: HTTPClient, rate_limiter: RateLimiter, results: ThreadSafeResults):
        self.http_client = http_client
        self.rate_limiter = rate_limiter
        self.results = results
        
    def load_wordlist(self, wordlist_path: str) -> List[str]:
        """Load wordlist from file"""
        try:
            with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                return [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(f"{C.RED}[ERROR]{C.WHITE} Error loading wordlist: {e}")
            return []
    
    def generate_urls(self, base_url: str, wordlist: List[str], extensions: List[str] = None) -> List[str]:
        """Generate URLs to test"""
        urls = []
        base_url = base_url.rstrip('/')
        
        for word in wordlist:
            # Directory
            urls.append(f"{base_url}/{word}/")
            
            # File without extension
            urls.append(f"{base_url}/{word}")
            
            # Files with extensions
            if extensions:
                for ext in extensions:
                    urls.append(f"{base_url}/{word}.{ext}")
        
        return urls
    
    def test_url(self, url: str, expected_codes: List[int] = None) -> Optional[DiscoveryResult]:
        """Test a single URL"""
        if expected_codes is None:
            expected_codes = [200, 201, 202, 204, 301, 302, 307, 308, 401, 403]
        
        self.rate_limiter.acquire()
        
        status_code, headers, content = self.http_client.request(url)
        
        if status_code in expected_codes:
            # Determine result type
            result_type = "file"
            if url.endswith('/'):
                result_type = "directory"
            elif status_code in [301, 302, 307, 308]:
                result_type = "redirect"
            elif status_code in [401, 403]:
                result_type = "protected"
            
            return DiscoveryResult(
                url=url,
                method="GET",
                status_code=status_code,
                content_length=len(content),
                content_type=headers.get('Content-Type', ''),
                source="bruteforce",
                result_type=result_type,
                headers=headers
            )
        
        return None
    
    def bruteforce(self, base_url: str, wordlist: List[str], extensions: List[str] = None, 
                   threads: int = 50, expected_codes: List[int] = None) -> int:
        """Perform directory/file bruteforcing"""
        urls = self.generate_urls(base_url, wordlist, extensions)
        found_count = 0
        
        print(f"{C.BLUE}[INFO]{C.WHITE} Starting bruteforce with {len(urls)} URLs using {threads} threads")
        
        with ThreadPoolExecutor(max_workers=threads) as executor:
            future_to_url = {executor.submit(self.test_url, url, expected_codes): url for url in urls}
            
            for future in as_completed(future_to_url):
                try:
                    result = future.result()
                    if result and self.results.add_result(result):
                        found_count += 1
                        print(f"{C.GREEN}[FOUND]{C.WHITE} [{result.status_code}] {result.url} ({result.result_type})")
                except Exception as e:
                    pass
        
        return found_count

class WebCrawler:
    """Advanced web crawler (GoSpider/Katana/Hakrawler-inspired)"""
    
    def __init__(self, http_client: HTTPClient, rate_limiter: RateLimiter, results: ThreadSafeResults):
        self.http_client = http_client
        self.rate_limiter = rate_limiter
        self.results = results
        self.visited_urls = set()
        self.crawl_queue = deque()
        self.lock = threading.Lock()
    
    def extract_links(self, content: str, base_url: str) -> List[str]:
        """Extract links from HTML content"""
        links = []
        
        # HTML link patterns
        patterns = [
            r'href=["\']([^"\']+)["\']',
            r'src=["\']([^"\']+)["\']',
            r'action=["\']([^"\']+)["\']',
            r'data-url=["\']([^"\']+)["\']',
            r'url\(["\']?([^"\'()]+)["\']?\)',
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                if match and not match.startswith(('#', 'javascript:', 'mailto:', 'tel:', 'data:')):
                    full_url = urllib.parse.urljoin(base_url, match)
                    if full_url.startswith(('http://', 'https://')):
                        links.append(full_url)
        
        return list(set(links))
    
    def extract_js_endpoints(self, content: str, base_url: str) -> List[str]:
        """Extract endpoints from JavaScript content"""
        endpoints = []
        
        # JavaScript endpoint patterns
        js_patterns = [
            r'["\']([/][^"\']*)["\']',
            r'url\s*:\s*["\']([^"\']+)["\']',
            r'endpoint\s*:\s*["\']([^"\']+)["\']',
            r'api[^"\']*["\']([^"\']+)["\']',
            r'fetch\s*\(\s*["\']([^"\']+)["\']',
            r'\.get\s*\(\s*["\']([^"\']+)["\']',
            r'\.post\s*\(\s*["\']([^"\']+)["\']',
        ]
        
        for pattern in js_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                if len(match) > 1 and not match.startswith('#'):
                    full_url = urllib.parse.urljoin(base_url, match)
                    if full_url.startswith(('http://', 'https://')):
                        endpoints.append(full_url)
        
        return list(set(endpoints))
    
    def crawl_url(self, url: str, depth: int, max_depth: int) -> List[str]:
        """Crawl a single URL"""
        if depth > max_depth:
            return []
        
        with self.lock:
            if url in self.visited_urls:
                return []
            self.visited_urls.add(url)
        
        self.rate_limiter.acquire()
        
        status_code, headers, content = self.http_client.request(url)
        
        if status_code > 0:
            # Add result
            result = DiscoveryResult(
                url=url,
                method="GET",
                status_code=status_code,
                content_length=len(content),
                content_type=headers.get('Content-Type', ''),
                source="crawl",
                result_type="page",
                depth=depth,
                headers=headers
            )
            
            if self.results.add_result(result):
                print(f"{C.GREEN}[CRAWLED]{C.WHITE} [{status_code}] {url}")
            
            # Extract links if HTML content
            discovered_urls = []
            if content and 'text/html' in headers.get('Content-Type', '').lower():
                try:
                    content_str = content.decode('utf-8', errors='ignore')
                    links = self.extract_links(content_str, url)
                    discovered_urls.extend(links)
                except:
                    pass
            
            # Extract JS endpoints if JavaScript content
            elif content and 'javascript' in headers.get('Content-Type', '').lower():
                try:
                    content_str = content.decode('utf-8', errors='ignore')
                    endpoints = self.extract_js_endpoints(content_str, url)
                    discovered_urls.extend(endpoints)
                except:
                    pass
            
            return discovered_urls
        
        return []
    
    def crawl(self, start_urls: List[str], max_depth: int = 2, threads: int = 20) -> int:
        """Perform web crawling"""
        # Initialize queue
        for url in start_urls:
            self.crawl_queue.append((url, 0))
        
        found_count = 0
        print(f"{C.BLUE}[INFO]{C.WHITE} Starting crawl with {len(start_urls)} URLs, max depth: {max_depth}")
        
        while self.crawl_queue:
            # Process current batch
            current_batch = []
            batch_size = min(threads * 2, len(self.crawl_queue))
            
            for _ in range(batch_size):
                if self.crawl_queue:
                    current_batch.append(self.crawl_queue.popleft())
            
            if not current_batch:
                break
            
            # Crawl batch in parallel
            with ThreadPoolExecutor(max_workers=threads) as executor:
                future_to_url = {
                    executor.submit(self.crawl_url, url, depth, max_depth): (url, depth)
                    for url, depth in current_batch
                }
                
                for future in as_completed(future_to_url):
                    try:
                        discovered_urls = future.result()
                        url, depth = future_to_url[future]
                        
                        # Add discovered URLs to queue
                        for discovered_url in discovered_urls:
                            if discovered_url not in self.visited_urls:
                                self.crawl_queue.append((discovered_url, depth + 1))
                        
                        found_count += 1
                    except Exception as e:
                        pass
        
        return found_count

class ArchiveCollector:
    """Archive URL collector (GAU/Waybackurls/Waymore-inspired)"""
    
    def __init__(self, http_client: HTTPClient, results: ThreadSafeResults):
        self.http_client = http_client
        self.results = results
        
    def get_wayback_urls(self, domain: str) -> List[str]:
        """Get URLs from Wayback Machine"""
        urls = []
        try:
            wayback_url = f"http://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&collapse=urlkey"
            status_code, headers, content = self.http_client.request(wayback_url)
            
            if status_code == 200 and content:
                data = json.loads(content.decode('utf-8'))
                for entry in data[1:]:  # Skip header
                    if len(entry) > 2:
                        url = entry[2]
                        if url.startswith(('http://', 'https://')):
                            urls.append(url)
        except Exception as e:
            print(f"{C.YELLOW}[WARNING]{C.WHITE} Wayback Machine error: {e}")
        
        return list(set(urls))
    
    def get_commoncrawl_urls(self, domain: str) -> List[str]:
        """Get URLs from Common Crawl"""
        urls = []
        try:
            cc_url = f"http://index.commoncrawl.org/CC-MAIN-2023-50-index?url={domain}/*&output=json"
            status_code, headers, content = self.http_client.request(cc_url)
            
            if status_code == 200 and content:
                lines = content.decode('utf-8').split('\n')
                for line in lines:
                    if line.strip():
                        try:
                            data = json.loads(line)
                            url = data.get('url', '')
                            if url.startswith(('http://', 'https://')):
                                urls.append(url)
                        except:
                            pass
        except Exception as e:
            print(f"{C.YELLOW}[WARNING]{C.WHITE} Common Crawl error: {e}")
        
        return list(set(urls))
    
    def collect_archive_urls(self, domain: str) -> int:
        """Collect URLs from various archives"""
        print(f"{C.BLUE}[INFO]{C.WHITE} Collecting archive URLs for {domain}")
        
        all_urls = []
        
        # Wayback Machine
        wayback_urls = self.get_wayback_urls(domain)
        all_urls.extend(wayback_urls)
        print(f"{C.CYAN}[ARCHIVE]{C.WHITE} Found {len(wayback_urls)} URLs from Wayback Machine")
        
        # Common Crawl
        cc_urls = self.get_commoncrawl_urls(domain)
        all_urls.extend(cc_urls)
        print(f"{C.CYAN}[ARCHIVE]{C.WHITE} Found {len(cc_urls)} URLs from Common Crawl")
        
        # Add results
        found_count = 0
        for url in set(all_urls):
            result = DiscoveryResult(
                url=url,
                method="GET",
                source="archive",
                result_type="archived_url"
            )
            if self.results.add_result(result):
                found_count += 1
        
        print(f"{C.GREEN}[SUCCESS]{C.WHITE} Collected {found_count} unique archive URLs")
        return found_count

class APIEndpointDiscoverer:
    """API endpoint discovery (Kiterunner-inspired)"""
    
    def __init__(self, http_client: HTTPClient, rate_limiter: RateLimiter, results: ThreadSafeResults):
        self.http_client = http_client
        self.rate_limiter = rate_limiter
        self.results = results
        
    def get_api_wordlist(self) -> List[str]:
        """Get common API endpoints"""
        return [
            'api', 'v1', 'v2', 'v3', 'rest', 'graphql',
            'users', 'user', 'admin', 'auth', 'login', 'logout',
            'register', 'signup', 'profile', 'account', 'settings',
            'config', 'status', 'health', 'info', 'version',
            'search', 'data', 'export', 'import', 'upload',
            'download', 'files', 'images', 'docs', 'reports',
            'analytics', 'stats', 'metrics', 'logs', 'debug'
        ]
    
    def generate_api_paths(self, base_url: str) -> List[str]:
        """Generate API paths to test"""
        paths = []
        base_url = base_url.rstrip('/')
        wordlist = self.get_api_wordlist()
        
        # Common API patterns
        for word in wordlist:
            paths.extend([
                f"{base_url}/api/{word}",
                f"{base_url}/api/v1/{word}",
                f"{base_url}/api/v2/{word}",
                f"{base_url}/rest/{word}",
                f"{base_url}/{word}/api",
                f"{base_url}/{word}",
            ])
        
        return paths
    
    def test_api_endpoint(self, url: str) -> Optional[DiscoveryResult]:
        """Test API endpoint with multiple methods"""
        methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS']
        
        for method in methods:
            self.rate_limiter.acquire()
            
            status_code, headers, content = self.http_client.request(url, method)
            
            if status_code in [200, 201, 202, 204, 400, 401, 403, 404, 405, 500]:
                result = DiscoveryResult(
                    url=url,
                    method=method,
                    status_code=status_code,
                    content_length=len(content),
                    content_type=headers.get('Content-Type', ''),
                    source="api_discovery",
                    result_type="api_endpoint",
                    headers=headers
                )
                
                if self.results.add_result(result):
                    print(f"{C.MAGENTA}[API]{C.WHITE} [{method}] [{status_code}] {url}")
                    return result
        
        return None
    
    def discover_api_endpoints(self, base_url: str, threads: int = 30) -> int:
        """Discover API endpoints"""
        paths = self.generate_api_paths(base_url)
        found_count = 0
        
        print(f"{C.BLUE}[INFO]{C.WHITE} Discovering API endpoints with {len(paths)} paths")
        
        with ThreadPoolExecutor(max_workers=threads) as executor:
            future_to_url = {executor.submit(self.test_api_endpoint, path): path for path in paths}
            
            for future in as_completed(future_to_url):
                try:
                    result = future.result()
                    if result:
                        found_count += 1
                except Exception as e:
                    pass
        
        return found_count

class DiscoveryMaster:
    """Main discovery orchestrator"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.results = ThreadSafeResults()
        
        # Initialize components
        self.rate_limiter = RateLimiter(
            requests_per_second=config.get('rate_limit', 100),
            burst_size=config.get('burst_size', 20)
        )
        
        self.http_client = HTTPClient(
            timeout=config.get('timeout', 10),
            user_agent=config.get('user_agent', 'DiscoveryMaster/1.0')
        )
        
        self.bruteforcer = DirectoryBruteforcer(self.http_client, self.rate_limiter, self.results)
        self.crawler = WebCrawler(self.http_client, self.rate_limiter, self.results)
        self.archive_collector = ArchiveCollector(self.http_client, self.results)
        self.api_discoverer = APIEndpointDiscoverer(self.http_client, self.rate_limiter, self.results)
        
    def run_bruteforce(self, target_url: str, wordlist_path: str, extensions: List[str] = None) -> int:
        """Run directory/file bruteforcing"""
        if not os.path.exists(wordlist_path):
            print(f"{C.RED}[ERROR]{C.WHITE} Wordlist file not found: {wordlist_path}")
            return 0
        
        wordlist = self.bruteforcer.load_wordlist(wordlist_path)
        if not wordlist:
            return 0
        
        return self.bruteforcer.bruteforce(
            target_url, 
            wordlist, 
            extensions,
            threads=self.config.get('threads', 50)
        )
    
    def run_crawling(self, target_urls: List[str]) -> int:
        """Run web crawling"""
        return self.crawler.crawl(
            target_urls,
            max_depth=self.config.get('crawl_depth', 2),
            threads=self.config.get('threads', 20)
        )
    
    def run_archive_collection(self, domain: str) -> int:
        """Run archive URL collection"""
        return self.archive_collector.collect_archive_urls(domain)
    
    def run_api_discovery(self, target_url: str) -> int:
        """Run API endpoint discovery"""
        return self.api_discoverer.discover_api_endpoints(
            target_url,
            threads=self.config.get('threads', 30)
        )
    
    def save_results(self, output_file: str, output_format: str = 'json'):
        """Save results to file"""
        results = self.results.get_results()
        
        if not results:
            print(f"{C.YELLOW}[WARNING]{C.WHITE} No results to save")
            return
        
        try:
            if output_format.lower() == 'json':
                with open(output_file, 'w', encoding='utf-8') as f:
                    json.dump([asdict(result) for result in results], f, indent=2, ensure_ascii=False)
            
            elif output_format.lower() == 'txt':
                with open(output_file, 'w', encoding='utf-8') as f:
                    for result in results:
                        f.write(f"{result.url}\n")
            
            elif output_format.lower() == 'csv':
                import csv
                with open(output_file, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerow(['URL', 'Method', 'Status', 'Content-Type', 'Source', 'Type'])
                    
                    for result in results:
                        writer.writerow([
                            result.url, result.method, result.status_code,
                            result.content_type, result.source, result.result_type
                        ])
            
            print(f"{C.GREEN}[SUCCESS]{C.WHITE} Results saved to {output_file}")
            
        except Exception as e:
            print(f"{C.RED}[ERROR]{C.WHITE} Error saving results: {e}")
    
    def print_summary(self):
        """Print discovery summary"""
        results = self.results.get_results()
        
        if not results:
            print(f"{C.YELLOW}[INFO]{C.WHITE} No results found")
            return
        
        # Group by source and type
        by_source = {}
        by_type = {}
        by_status = {}
        
        for result in results:
            # By source
            by_source[result.source] = by_source.get(result.source, 0) + 1
            
            # By type
            by_type[result.result_type] = by_type.get(result.result_type, 0) + 1
            
            # By status
            by_status[result.status_code] = by_status.get(result.status_code, 0) + 1
        
        print(f"\n{C.CYAN}=== DISCOVERY SUMMARY ==={C.WHITE}")
        print(f"{C.GREEN}Total Results: {len(results)}{C.WHITE}")
        
        print(f"\n{C.BLUE}By Source:{C.WHITE}")
        for source, count in sorted(by_source.items()):
            print(f"  {source}: {count}")
        
        print(f"\n{C.BLUE}By Type:{C.WHITE}")
        for result_type, count in sorted(by_type.items()):
            print(f"  {result_type}: {count}")
        
        print(f"\n{C.BLUE}By Status Code:{C.WHITE}")
        for status, count in sorted(by_status.items()):
            color = C.GREEN if status == 200 else C.YELLOW if status < 400 else C.RED
            print(f"  {color}{status}{C.WHITE}: {count}")

def create_default_wordlist() -> str:
    """Create a default wordlist file"""
    wordlist_content = """admin
administrator
api
backup
config
data
db
debug
dev
docs
files
images
login
logs
private
public
root
static
test
tmp
upload
user
users
www"""
    
    wordlist_path = "default_wordlist.txt"
    try:
        with open(wordlist_path, 'w') as f:
            f.write(wordlist_content)
        return wordlist_path
    except:
        return None

def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description='Discovery Master - Ultimate Directory/File/Content Discovery Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Full discovery
  python discovery_master.py -u https://example.com --all
  
  # Directory bruteforcing
  python discovery_master.py -u https://example.com --bruteforce -w wordlist.txt
  
  # Web crawling
  python discovery_master.py -u https://example.com --crawl
  
  # Archive collection
  python discovery_master.py -d example.com --archive
  
  # API discovery
  python discovery_master.py -u https://example.com --api
  
  # Combined discovery with output
  python discovery_master.py -u https://example.com --all -o results.json
        """
    )
    
    # Target options
    target_group = parser.add_argument_group('TARGET')
    target_group.add_argument('-u', '--url', help='Target URL')
    target_group.add_argument('-d', '--domain', help='Target domain')
    target_group.add_argument('-l', '--list', help='File with list of targets')
    
    # Discovery modes
    mode_group = parser.add_argument_group('DISCOVERY MODES')
    mode_group.add_argument('--all', action='store_true', help='Run all discovery modes')
    mode_group.add_argument('--bruteforce', action='store_true', help='Directory/file bruteforcing')
    mode_group.add_argument('--crawl', action='store_true', help='Web crawling')
    mode_group.add_argument('--archive', action='store_true', help='Archive URL collection')
    mode_group.add_argument('--api', action='store_true', help='API endpoint discovery')
    
    # Bruteforce options
    brute_group = parser.add_argument_group('BRUTEFORCE OPTIONS')
    brute_group.add_argument('-w', '--wordlist', help='Wordlist file for bruteforcing')
    brute_group.add_argument('-x', '--extensions', help='File extensions (comma-separated)')
    brute_group.add_argument('--status-codes', help='Valid status codes (comma-separated)')
    
    # Crawling options
    crawl_group = parser.add_argument_group('CRAWLING OPTIONS')
    crawl_group.add_argument('--depth', type=int, default=2, help='Maximum crawl depth (default: 2)')
    
    # Performance options
    perf_group = parser.add_argument_group('PERFORMANCE')
    perf_group.add_argument('-t', '--threads', type=int, default=50, help='Number of threads (default: 50)')
    perf_group.add_argument('--rate-limit', type=float, default=100, help='Requests per second (default: 100)')
    perf_group.add_argument('--timeout', type=int, default=10, help='Request timeout (default: 10)')
    
    # Output options
    output_group = parser.add_argument_group('OUTPUT')
    output_group.add_argument('-o', '--output', help='Output file')
    output_group.add_argument('-f', '--format', choices=['json', 'txt', 'csv'], default='json', help='Output format')
    output_group.add_argument('--silent', action='store_true', help='Silent mode')
    output_group.add_argument('--verbose', action='store_true', help='Verbose output')
    output_group.add_argument('--no-color', action='store_true', help='Disable colors')
    
    # Request options
    req_group = parser.add_argument_group('REQUEST OPTIONS')
    req_group.add_argument('--user-agent', help='Custom User-Agent')
    req_group.add_argument('--headers', action='append', help='Custom headers (key:value)')
    
    args = parser.parse_args()
    
    if args.no_color:
        Colors.disable()
    
    # Show banner
    if not args.silent:
        banner()
        print(f"{C.YELLOW}[INFO]{C.WHITE} Use with caution. You are responsible for your actions.")
        print(f"{C.YELLOW}[INFO]{C.WHITE} Developers assume no liability and are not responsible for any misuse or damage.\n")
    
    # Validate arguments
    if not args.url and not args.domain and not args.list:
        print(f"{C.RED}[ERROR]{C.WHITE} Please provide a target URL, domain, or list file")
        parser.print_help()
        return 1
    
    if not any([args.all, args.bruteforce, args.crawl, args.archive, args.api]):
        print(f"{C.RED}[ERROR]{C.WHITE} Please specify at least one discovery mode")
        parser.print_help()
        return 1
    
    # Parse extensions
    extensions = []
    if args.extensions:
        extensions = [ext.strip() for ext in args.extensions.split(',')]
    
    # Parse status codes
    status_codes = None
    if args.status_codes:
        try:
            status_codes = [int(code.strip()) for code in args.status_codes.split(',')]
        except ValueError:
            print(f"{C.RED}[ERROR]{C.WHITE} Invalid status codes format")
            return 1
    
    # Build configuration
    config = {
        'threads': args.threads,
        'rate_limit': args.rate_limit,
        'timeout': args.timeout,
        'crawl_depth': args.depth,
        'user_agent': args.user_agent or 'DiscoveryMaster/1.0',
        'silent': args.silent,
        'verbose': args.verbose,
    }
    
    # Initialize Discovery Master
    discovery = DiscoveryMaster(config)
    
    try:
        total_found = 0
        
        # Get targets
        targets = []
        if args.url:
            targets.append(args.url)
        if args.list:
            try:
                with open(args.list, 'r') as f:
                    targets.extend([line.strip() for line in f if line.strip()])
            except Exception as e:
                print(f"{C.RED}[ERROR]{C.WHITE} Error reading targets file: {e}")
                return 1
        
        # Extract domain from URL if needed
        domain = args.domain
        if not domain and targets:
            parsed = urllib.parse.urlparse(targets[0])
            domain = parsed.netloc
        
        # Run discovery modes
        if args.all or args.bruteforce:
            if targets:
                wordlist_path = args.wordlist
                if not wordlist_path:
                    wordlist_path = create_default_wordlist()
                    if wordlist_path:
                        print(f"{C.YELLOW}[INFO]{C.WHITE} Using default wordlist: {wordlist_path}")
                
                if wordlist_path:
                    for target in targets:
                        found = discovery.run_bruteforce(target, wordlist_path, extensions)
                        total_found += found
        
        if args.all or args.crawl:
            if targets:
                found = discovery.run_crawling(targets)
                total_found += found
        
        if args.all or args.archive:
            if domain:
                found = discovery.run_archive_collection(domain)
                total_found += found
        
        if args.all or args.api:
            if targets:
                for target in targets:
                    found = discovery.run_api_discovery(target)
                    total_found += found
        
        # Print summary
        if not args.silent:
            discovery.print_summary()
        
        # Save results
        if args.output:
            discovery.save_results(args.output, args.format)
        
        if not args.silent:
            print(f"\n{C.GREEN}[SUCCESS]{C.WHITE} Discovery completed! Total results: {total_found}")
        
        return 0
        
    except KeyboardInterrupt:
        if not args.silent:
            print(f"\n{C.YELLOW}[INFO]{C.WHITE} Discovery interrupted by user")
        return 1
    except Exception as e:
        if not args.silent:
            print(f"{C.RED}[ERROR]{C.WHITE} {e}")
            import traceback
            traceback.print_exc()
        return 1

if __name__ == '__main__':
    sys.exit(main())