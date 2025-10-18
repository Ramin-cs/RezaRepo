#!/usr/bin/env python3
"""
HTTPX - Fast HTTP Prober
Python implementation inspired by projectdiscovery/httpx
Optimized for speed and reliability in subdomain verification
"""

import socket
import ssl
import time
import json
import re
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)

# Try to import optional dependencies
try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

try:
    import asyncio
    import aiohttp
    ASYNC_AVAILABLE = True
except ImportError:
    ASYNC_AVAILABLE = False

class Colors:
    """Color codes for output"""
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    END = '\033[0m'

class HTTPXResult:
    """Result object for HTTP probe"""
    
    def __init__(self, url, status_code=None, title=None, content_length=None, 
                 response_time=None, technologies=None, server=None, error=None):
        self.url = url
        self.status_code = status_code
        self.title = title
        self.content_length = content_length
        self.response_time = response_time
        self.technologies = technologies or []
        self.server = server
        self.error = error
        self.is_alive = status_code is not None and error is None
        
        # Categorize by status code
        if self.status_code:
            if self.status_code == 200:
                self.category = "Live (200 OK)"
            elif self.status_code in [301, 302, 303, 307, 308]:
                self.category = f"Redirect ({self.status_code})"
            elif self.status_code == 403:
                self.category = "Forbidden (403)"
            elif self.status_code == 404:
                self.category = "Not Found (404)"
            elif 400 <= self.status_code < 500:
                self.category = f"Client Error ({self.status_code})"
            elif 500 <= self.status_code < 600:
                self.category = f"Server Error ({self.status_code})"
            else:
                self.category = f"Other ({self.status_code})"
        else:
            self.category = "Unreachable"
    
    def __str__(self):
        if self.is_alive:
            return f"{self.url} [{self.status_code}] [{self.content_length}] [{self.response_time:.2f}s]"
        else:
            return f"{self.url} [FAILED]"

class HTTPX:
    """Fast HTTP prober with async support"""
    
    def __init__(self, timeout=5, max_redirects=3, threads=50, follow_redirects=True,
                 verify_ssl=False, user_agent=None, custom_headers=None):
        self.timeout = timeout
        self.max_redirects = max_redirects
        self.threads = threads
        self.follow_redirects = follow_redirects
        self.verify_ssl = verify_ssl
        self.user_agent = user_agent or "HTTPX/1.0 (Python)"
        self.custom_headers = custom_headers or {}
        
        # Default headers
        self.headers = {
            'User-Agent': self.user_agent,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            **self.custom_headers
        }
        
        # Technology detection patterns
        self.tech_patterns = {
            'Apache': [r'Server: Apache', r'Apache/[\d.]+'],
            'Nginx': [r'Server: nginx', r'nginx/[\d.]+'],
            'IIS': [r'Server: Microsoft-IIS', r'X-Powered-By: ASP.NET'],
            'Cloudflare': [r'Server: cloudflare', r'CF-RAY'],
            'jQuery': [r'jquery[.-]?(\d+(?:\.\d+)*)', r'/jquery[.-]?(\d+(?:\.\d+)*)'],
            'WordPress': [r'wp-content', r'WordPress', r'/wp-includes/'],
            'Bootstrap': [r'bootstrap[.-]?(\d+(?:\.\d+)*)', r'Bootstrap v(\d+(?:\.\d+)*)'],
            'React': [r'react[.-]?(\d+(?:\.\d+)*)', r'__REACT_DEVTOOLS_GLOBAL_HOOK__'],
            'Vue.js': [r'vue[.-]?(\d+(?:\.\d+)*)', r'Vue.js'],
            'Angular': [r'angular[.-]?(\d+(?:\.\d+)*)', r'ng-version'],
        }
    
    def _extract_title(self, html):
        """Extract title from HTML"""
        try:
            title_match = re.search(r'<title[^>]*>([^<]+)</title>', html, re.IGNORECASE)
            if title_match:
                return title_match.group(1).strip()
        except:
            pass
        return None
    
    def _detect_technologies(self, headers, html):
        """Detect web technologies"""
        technologies = []
        content = f"{str(headers)} {html}".lower()
        
        for tech, patterns in self.tech_patterns.items():
            for pattern in patterns:
                if re.search(pattern.lower(), content):
                    technologies.append(tech)
                    break
        
        return list(set(technologies))
    
    def _probe_single_url(self, url):
        """Probe a single URL synchronously"""
        if not REQUESTS_AVAILABLE:
            return HTTPXResult(url=url, error="requests library not available")
        
        try:
            session = requests.Session()
            
            # Configure retry strategy
            retry_strategy = Retry(
                total=2,
                backoff_factor=0.5,
                status_forcelist=[429, 500, 502, 503, 504],
            )
            
            adapter = HTTPAdapter(max_retries=retry_strategy)
            session.mount("http://", adapter)
            session.mount("https://", adapter)
            
            start_time = time.time()
            
            response = session.get(
                url,
                headers=self.headers,
                timeout=self.timeout,
                verify=self.verify_ssl,
                allow_redirects=self.follow_redirects,
                stream=True
            )
            
            response_time = time.time() - start_time
            
            # Get content for analysis (limit to first 10KB)
            content = ""
            try:
                content = response.text[:10240]  # First 10KB only
            except:
                pass
            
            # Extract information
            title = self._extract_title(content)
            technologies = self._detect_technologies(response.headers, content)
            server = response.headers.get('Server', 'Unknown')
            content_length = len(content)
            
            return HTTPXResult(
                url=url,
                status_code=response.status_code,
                title=title,
                content_length=content_length,
                response_time=response_time,
                technologies=technologies,
                server=server
            )
            
        except Exception as e:
            return HTTPXResult(url=url, error=str(e))
    
    def probe_urls(self, urls, show_progress=True):
        """Probe multiple URLs with threading"""
        results = []
        
        if show_progress:
            print(f"{Colors.BLUE}[HTTPX]{Colors.END} Probing {len(urls)} URLs with {self.threads} threads")
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            # Submit all tasks
            future_to_url = {executor.submit(self._probe_single_url, url): url for url in urls}
            
            # Collect results
            for future in as_completed(future_to_url):
                result = future.result()
                results.append(result)
                
                if show_progress and result.is_alive:
                    print(f"{Colors.GREEN}[HTTPX]{Colors.END} {result}")
        
        return results
    
    def probe_subdomains(self, subdomains, protocols=['https', 'http']):
        """Probe subdomains with multiple protocols"""
        urls = []
        
        # Generate URLs with different protocols
        for subdomain in subdomains:
            for protocol in protocols:
                urls.append(f"{protocol}://{subdomain}")
        
        # Probe all URLs
        all_results = self.probe_urls(urls)
        
        # Group results by subdomain (keep best result per subdomain)
        subdomain_results = {}
        
        for result in all_results:
            if result.is_alive:
                parsed = urlparse(result.url)
                subdomain = parsed.netloc
                
                # Keep the best result (prefer HTTPS, then by status code)
                if subdomain not in subdomain_results:
                    subdomain_results[subdomain] = result
                else:
                    current = subdomain_results[subdomain]
                    # Prefer HTTPS over HTTP
                    if parsed.scheme == 'https' and urlparse(current.url).scheme == 'http':
                        subdomain_results[subdomain] = result
                    # Prefer better status codes
                    elif (parsed.scheme == urlparse(current.url).scheme and 
                          result.status_code < current.status_code):
                        subdomain_results[subdomain] = result
        
        return list(subdomain_results.values())
    
    def export_results(self, results, output_file, format_type='json'):
        """Export results to file"""
        if format_type.lower() == 'json':
            data = []
            for result in results:
                if result.is_alive:
                    data.append({
                        'url': result.url,
                        'status_code': result.status_code,
                        'title': result.title,
                        'content_length': result.content_length,
                        'response_time': result.response_time,
                        'technologies': result.technologies,
                        'server': result.server,
                        'category': result.category
                    })
            
            with open(output_file, 'w') as f:
                json.dump(data, f, indent=2)
        
        elif format_type.lower() == 'txt':
            with open(output_file, 'w') as f:
                for result in results:
                    if result.is_alive:
                        f.write(f"{result.url} [{result.status_code}] [{result.content_length}] [{result.response_time:.2f}s]\n")
                        if result.title:
                            f.write(f"  Title: {result.title}\n")
                        if result.technologies:
                            f.write(f"  Tech: {', '.join(result.technologies)}\n")
                        f.write("\n")

def main():
    """CLI interface for HTTPX"""
    import argparse
    
    parser = argparse.ArgumentParser(description="HTTPX - Fast HTTP Prober")
    parser.add_argument('-l', '--list', help='File containing URLs/domains to probe')
    parser.add_argument('-u', '--url', help='Single URL to probe')
    parser.add_argument('-t', '--threads', type=int, default=50, help='Number of threads (default: 50)')
    parser.add_argument('--timeout', type=int, default=5, help='HTTP timeout (default: 5)')
    parser.add_argument('-o', '--output', help='Output file')
    parser.add_argument('--format', choices=['json', 'txt'], default='txt', help='Output format')
    parser.add_argument('--no-verify', action='store_true', help='Disable SSL verification')
    parser.add_argument('--follow-redirects', action='store_true', default=True, help='Follow redirects')
    
    args = parser.parse_args()
    
    # Initialize HTTPX
    httpx = HTTPX(
        timeout=args.timeout,
        threads=args.threads,
        verify_ssl=not args.no_verify,
        follow_redirects=args.follow_redirects
    )
    
    # Get URLs to probe
    urls = []
    if args.url:
        urls = [args.url]
    elif args.list:
        with open(args.list, 'r') as f:
            urls = [line.strip() for line in f if line.strip()]
    else:
        print("Please provide URLs via -u or -l")
        return
    
    # Add protocols if missing
    processed_urls = []
    for url in urls:
        if not url.startswith(('http://', 'https://')):
            processed_urls.extend([f'https://{url}', f'http://{url}'])
        else:
            processed_urls.append(url)
    
    # Probe URLs
    results = httpx.probe_urls(processed_urls)
    
    # Filter alive results
    alive_results = [r for r in results if r.is_alive]
    
    print(f"\n{Colors.GREEN}[HTTPX]{Colors.END} Found {len(alive_results)} alive URLs")
    
    # Export results
    if args.output:
        httpx.export_results(alive_results, args.output, args.format)
        print(f"{Colors.GREEN}[HTTPX]{Colors.END} Results saved to {args.output}")

if __name__ == "__main__":
    main()