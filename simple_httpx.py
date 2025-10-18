#!/usr/bin/env python3
"""
Simple HTTPX - Lightweight HTTP Prober
Cross-platform compatible version with minimal dependencies
"""

import socket
import ssl
import time
import json
import re
import urllib.request
import urllib.error
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
import warnings
warnings.filterwarnings("ignore")

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

class SimpleHTTPXResult:
    """Result object for HTTP probe"""
    
    def __init__(self, url, status_code=None, title=None, content_length=None, 
                 response_time=None, server=None, error=None):
        self.url = url
        self.status_code = status_code
        self.title = title
        self.content_length = content_length
        self.response_time = response_time
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

class SimpleHTTPX:
    """Simple HTTP prober using urllib"""
    
    def __init__(self, timeout=5, threads=20, user_agent=None):
        self.timeout = timeout
        self.threads = threads
        self.user_agent = user_agent or "SimpleHTTPX/1.0 (Python)"
    
    def _extract_title(self, html):
        """Extract title from HTML"""
        try:
            title_match = re.search(r'<title[^>]*>([^<]+)</title>', html, re.IGNORECASE)
            if title_match:
                return title_match.group(1).strip()
        except:
            pass
        return None
    
    def _probe_single_url(self, url):
        """Probe a single URL"""
        try:
            # Create request with headers
            req = urllib.request.Request(url)
            req.add_header('User-Agent', self.user_agent)
            req.add_header('Accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8')
            
            # Create SSL context that doesn't verify certificates
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
            
            start_time = time.time()
            
            # Make request
            with urllib.request.urlopen(req, timeout=self.timeout, context=ssl_context) as response:
                response_time = time.time() - start_time
                
                # Read content (limit to first 5KB)
                content = response.read(5120).decode('utf-8', errors='ignore')
                
                # Extract information
                status_code = response.getcode()
                title = self._extract_title(content)
                server = response.headers.get('Server', 'Unknown')
                content_length = len(content)
                
                return SimpleHTTPXResult(
                    url=url,
                    status_code=status_code,
                    title=title,
                    content_length=content_length,
                    response_time=response_time,
                    server=server
                )
                
        except urllib.error.HTTPError as e:
            # HTTP errors still give us status codes
            response_time = time.time() - start_time if 'start_time' in locals() else 0
            return SimpleHTTPXResult(
                url=url,
                status_code=e.code,
                response_time=response_time,
                error=str(e)
            )
        except Exception as e:
            return SimpleHTTPXResult(url=url, error=str(e))
    
    def probe_urls(self, urls, show_progress=True):
        """Probe multiple URLs with threading"""
        results = []
        
        if show_progress:
            print(f"{Colors.BLUE}[SimpleHTTPX]{Colors.END} Probing {len(urls)} URLs with {self.threads} threads")
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            # Submit all tasks
            future_to_url = {executor.submit(self._probe_single_url, url): url for url in urls}
            
            # Collect results
            for future in as_completed(future_to_url):
                result = future.result()
                results.append(result)
                
                if show_progress and result.is_alive:
                    print(f"{Colors.GREEN}[SimpleHTTPX]{Colors.END} {result}")
        
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
                parsed = urllib.parse.urlparse(result.url)
                subdomain = parsed.netloc
                
                # Keep the best result (prefer HTTPS, then by status code)
                if subdomain not in subdomain_results:
                    subdomain_results[subdomain] = result
                else:
                    current = subdomain_results[subdomain]
                    # Prefer HTTPS over HTTP
                    if parsed.scheme == 'https' and urllib.parse.urlparse(current.url).scheme == 'http':
                        subdomain_results[subdomain] = result
                    # Prefer better status codes
                    elif (parsed.scheme == urllib.parse.urlparse(current.url).scheme and 
                          result.status_code < current.status_code):
                        subdomain_results[subdomain] = result
        
        return list(subdomain_results.values())

# Create alias for compatibility
HTTPX = SimpleHTTPX
HTTPXResult = SimpleHTTPXResult

def main():
    """CLI interface for SimpleHTTPX"""
    import argparse
    
    parser = argparse.ArgumentParser(description="SimpleHTTPX - Lightweight HTTP Prober")
    parser.add_argument('-l', '--list', help='File containing URLs/domains to probe')
    parser.add_argument('-u', '--url', help='Single URL to probe')
    parser.add_argument('-t', '--threads', type=int, default=20, help='Number of threads (default: 20)')
    parser.add_argument('--timeout', type=int, default=5, help='HTTP timeout (default: 5)')
    parser.add_argument('-o', '--output', help='Output file')
    
    args = parser.parse_args()
    
    # Initialize SimpleHTTPX
    httpx = SimpleHTTPX(
        timeout=args.timeout,
        threads=args.threads
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
    
    print(f"\n{Colors.GREEN}[SimpleHTTPX]{Colors.END} Found {len(alive_results)} alive URLs")
    
    # Export results
    if args.output:
        with open(args.output, 'w') as f:
            for result in alive_results:
                f.write(f"{result.url} [{result.status_code}] [{result.content_length}] [{result.response_time:.2f}s]\n")
                if result.title:
                    f.write(f"  Title: {result.title}\n")
                f.write("\n")
        print(f"{Colors.GREEN}[SimpleHTTPX]{Colors.END} Results saved to {args.output}")

if __name__ == "__main__":
    main()