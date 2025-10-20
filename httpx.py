#!/usr/bin/env python3
"""
Simple HTTPX Implementation for Subdomain Verification
Fast HTTP probing for live subdomain detection
"""

import socket
import ssl
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
import urllib.request
import urllib.error
import re

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

class FastHTTPX:
    """Fast HTTP prober using threads"""
    
    def __init__(self, timeout=5, threads=20):
        self.timeout = timeout
        self.threads = threads
    
    def probe_subdomains(self, subdomains):
        """Probe subdomains quickly"""
        results = []
        
        def probe_single(subdomain):
            protocols = ['https', 'http']
            for protocol in protocols:
                try:
                    url = f"{protocol}://{subdomain}"
                    
                    # Create request
                    req = urllib.request.Request(url)
                    req.add_header('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
                    
                    # Create SSL context
                    ssl_context = ssl.create_default_context()
                    ssl_context.check_hostname = False
                    ssl_context.verify_mode = ssl.CERT_NONE
                    
                    start_time = time.time()
                    with urllib.request.urlopen(req, timeout=self.timeout, context=ssl_context) as response:
                        response_time = time.time() - start_time
                        content = response.read()
                        
                        # Extract title
                        title = None
                        try:
                            text = content.decode('utf-8', errors='ignore')
                            if len(text) < 50000:  # Only extract title from small responses
                                title_match = re.search(r'<title[^>]*>([^<]+)</title>', text[:5000], re.IGNORECASE)
                                if title_match:
                                    title = title_match.group(1).strip()[:50]
                        except:
                            pass
                        
                        # Categorize by status code
                        status_code = response.getcode()
                        if status_code == 200:
                            category = "Live (200 OK)"
                        elif status_code in [301, 302, 303, 307, 308]:
                            category = f"Redirect ({status_code})"
                        elif status_code == 403:
                            category = "Forbidden (403)"
                        elif status_code == 404:
                            category = "Not Found (404)"
                        elif status_code == 401:
                            category = "Client Error (401)"
                        elif 400 <= status_code < 500:
                            category = f"Client Error ({status_code})"
                        elif 500 <= status_code < 600:
                            category = f"Server Error ({status_code})"
                        else:
                            category = f"Other ({status_code})"
                        
                        result = {
                            'url': url,
                            'status_code': status_code,
                            'category': category,
                            'title': title,
                            'response_time': response_time,
                            'server': response.headers.get('Server', 'Unknown') if hasattr(response, 'headers') else 'Unknown',
                            'content_length': len(content)
                        }
                        
                        results.append((subdomain, result))
                        Logger.found(f"Live: {url} [{status_code}] [{response_time:.2f}s]")
                        return result
                        
                except urllib.error.HTTPError as e:
                    # Handle HTTP errors
                    if e.code in [403, 404, 401]:
                        response_time = time.time() - start_time
                        
                        if e.code == 403:
                            category = "Forbidden (403)"
                        elif e.code == 404:
                            category = "Not Found (404)"
                        elif e.code == 401:
                            category = "Client Error (401)"
                        else:
                            category = f"Client Error ({e.code})"
                        
                        result = {
                            'url': url,
                            'status_code': e.code,
                            'category': category,
                            'title': None,
                            'response_time': response_time,
                            'server': 'Unknown',
                            'content_length': 0
                        }
                        
                        results.append((subdomain, result))
                        Logger.found(f"Live: {url} [{e.code}] [{response_time:.2f}s]")
                        return result
                except Exception:
                    continue
            
            # If no protocol worked, return a "Not Responding" result
            return {
                'url': f"http://{subdomain}",
                'status_code': 0,
                'category': "Not Responding",
                'title': None,
                'response_time': 0,
                'server': 'Unknown',
                'content_length': 0
            }
        
        Logger.info(f"Probing {len(subdomains)} subdomains with {self.threads} threads")
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(probe_single, sub) for sub in subdomains]
            for future in as_completed(futures):
                result = future.result()
                if result:  # Add all results, even "Not Responding" ones
                    subdomain = result['url'].split('://', 1)[1]
                    results.append((subdomain, result))
        
        # Return best result per subdomain (prefer HTTPS)
        subdomain_results = {}
        for subdomain, result in results:
            if subdomain not in subdomain_results:
                subdomain_results[subdomain] = result
            else:
                current = subdomain_results[subdomain]
                parsed_new = urlparse(result['url'])
                parsed_current = urlparse(current['url'])
                
                # Prefer HTTPS over HTTP
                if parsed_new.scheme == 'https' and parsed_current.scheme == 'http':
                    subdomain_results[subdomain] = result
        
        return subdomain_results

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Fast HTTP subdomain prober")
    parser.add_argument('subdomains', nargs='+', help='Subdomains to probe')
    parser.add_argument('--timeout', type=int, default=5, help='Request timeout (default: 5)')
    parser.add_argument('--threads', type=int, default=20, help='Number of threads (default: 20)')
    
    args = parser.parse_args()
    
    httpx = FastHTTPX(timeout=args.timeout, threads=args.threads)
    results = httpx.probe_subdomains(args.subdomains)
    
    print(f"\n{Colors.GREEN}Results:{Colors.END}")
    for subdomain, info in results.items():
        print(f"  {info['url']} - {info['category']}")