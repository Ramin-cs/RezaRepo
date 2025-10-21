#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Professional Parameter Discovery Tool
Combines the best features from multiple ParamSpider implementations
Advanced parameter mining from web archives with intelligent filtering
"""

# Fix encoding for Windows
import sys
import os
if os.name == 'nt':  # Windows
    import codecs
    sys.stdout = codecs.getwriter('utf-8')(sys.stdout.detach())
    sys.stderr = codecs.getwriter('utf-8')(sys.stderr.detach())

#!/usr/bin/env python3
# Core imports that work everywhere
import re
import argparse
import os
import sys
import time
import json
import random
import threading
import ssl
from urllib.parse import urlparse, parse_qs, urlencode, unquote
from concurrent.futures import ThreadPoolExecutor, as_completed
import urllib.request
import urllib.error
import warnings
warnings.filterwarnings("ignore", category=SyntaxWarning)

# Try to import requests with complete fallback
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

class Logger:
    """Professional logging system"""
    
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

class HTTPClient:
    """Universal HTTP client that works everywhere"""
    
    def __init__(self, timeout=10):
        self.timeout = timeout
        self.session = None
        
        # Try to use requests if available
        if REQUESTS_AVAILABLE:
            try:
                self.session = requests.Session()
                self.session.headers.update({
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                })
                Logger.info("Using requests library for HTTP")
            except Exception as e:
                Logger.warning(f"Requests failed, using urllib: {str(e)}")
                self.session = None
        else:
            Logger.info("Using urllib for HTTP (requests not available)")
    
    def get(self, url, **kwargs):
        """Make HTTP GET request with automatic fallback"""
        if self.session and REQUESTS_AVAILABLE:
            try:
                return self.session.get(url, timeout=self.timeout, verify=False, **kwargs)
            except Exception as e:
                Logger.warning(f"Requests failed for {url}, using urllib fallback")
                pass
        
        # Fallback to urllib
        return self._urllib_get(url)
    
    def _urllib_get(self, url):
        """GET request using urllib"""
        try:
            req = urllib.request.Request(url)
            req.add_header('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
            
            # Create SSL context that ignores certificates
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
            
            start_time = time.time()
            with urllib.request.urlopen(req, timeout=self.timeout, context=ssl_context) as response:
                content = response.read()
                elapsed = time.time() - start_time
                
                # Create requests-like response object
                class UrllibResponse:
                    def __init__(self, urllib_response, content, elapsed):
                        self.status_code = urllib_response.getcode()
                        self.headers = dict(urllib_response.headers)
                        self.content = content
                        self.text = content.decode('utf-8', errors='ignore')
                        # Fix elapsed time object
                        class ElapsedTime:
                            def __init__(self, elapsed_seconds):
                                self._elapsed = elapsed_seconds
                            def total_seconds(self):
                                return self._elapsed
                        self.elapsed = ElapsedTime(elapsed)
                
                return UrllibResponse(response, content, elapsed)
                
        except urllib.error.HTTPError as e:
            # Still return response for HTTP errors
            class ErrorResponse:
                def __init__(self, code):
                    self.status_code = code
                    self.headers = {}
                    self.content = b''
                    self.text = ''
                    # Fix elapsed time object
                    class ElapsedTime:
                        def __init__(self, elapsed_seconds):
                            self._elapsed = elapsed_seconds
                        def total_seconds(self):
                            return self._elapsed
                    self.elapsed = ElapsedTime(0)
            
            return ErrorResponse(e.code)
        except Exception as e:
            raise Exception(f"HTTP request failed: {str(e)}")

class ParameterDiscovery:
    """Advanced parameter discovery engine"""
    
    def __init__(self, domain, include_subdomains=True, threads=20, timeout=30, retries=3, placeholder="FUZZ"):
        self.domain = self.clean_domain(domain)
        self.include_subdomains = include_subdomains
        self.threads = threads
        self.timeout = timeout
        self.retries = retries
        self.placeholder = placeholder
        self.found_parameters = set()
        self.found_urls = []
        self.http_client = HTTPClient(timeout=timeout)
        
        # File extensions to exclude
        self.blacklist_extensions = [
            ".jpg", ".jpeg", ".png", ".gif", ".pdf", ".svg", ".json",
            ".css", ".js", ".webp", ".woff", ".woff2", ".eot", ".ttf", 
            ".otf", ".mp4", ".txt", ".ico", ".xml", ".zip", ".rar",
            ".tar", ".gz", ".bz2", ".7z", ".exe", ".dmg", ".iso"
        ]
        
    def clean_domain(self, domain):
        """Clean and normalize domain"""
        domain = domain.strip().lower()
        domain = domain.replace('https://', '').replace('http://', '')
        domain = domain.replace('www.', '')
        if '/' in domain:
            domain = domain.split('/')[0]
        return domain
    
    
    def fetch_wayback_urls(self):
        """Fetch URLs from Wayback Machine"""
        Logger.info(f"Fetching URLs from Wayback Machine for {self.domain}")
        
        if self.include_subdomains:
            wayback_url = f"https://web.archive.org/cdx/search/cdx?url=*.{self.domain}/*&output=txt&fl=original&collapse=urlkey&page=/"
        else:
            wayback_url = f"https://web.archive.org/cdx/search/cdx?url={self.domain}/*&output=txt&fl=original&collapse=urlkey&page=/"
        
        retry_count = 0
        while retry_count <= self.retries:
            try:
                response = self.http_client.get(wayback_url)
                response.raise_for_status()
                
                urls = response.text.strip().split('\n')
                urls = [unquote(url) for url in urls if url.strip()]
                
                Logger.success(f"Retrieved {len(urls)} URLs from Wayback Machine")
                return urls
                
            except requests.exceptions.RequestException as e:
                retry_count += 1
                if retry_count <= self.retries:
                    Logger.warning(f"Request failed, retrying ({retry_count}/{self.retries}): {str(e)}")
                    time.sleep(2)
                else:
                    Logger.error(f"Failed to fetch URLs after {self.retries} retries: {str(e)}")
                    return []
        
        return []
    
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
                        # Extract parameter names
                        for param_name in query_params.keys():
                            if param_name and len(param_name) > 0:
                                parameters_found.add(param_name)
                        
                        # Create URL with placeholder values
                        cleaned_params = {key: self.placeholder for key in query_params if key}
                        if cleaned_params:
                            cleaned_query = urlencode(cleaned_params, doseq=True)
                            cleaned_url = parsed_url._replace(query=cleaned_query).geturl()
                            parameter_urls.append(cleaned_url)
            except Exception as e:
                # Skip problematic URLs
                continue
        
        # Remove duplicates
        parameter_urls = list(set(parameter_urls))
        
        Logger.success(f"Found {len(parameters_found)} unique parameters in {len(parameter_urls)} URLs")
        
        self.found_parameters.update(parameters_found)
        self.found_urls.extend(parameter_urls)
        
        return parameter_urls, parameters_found
    
    def advanced_parameter_extraction(self, urls):
        """Advanced parameter extraction with multiple techniques"""
        Logger.info("Performing advanced parameter extraction")
        
        all_params = set()
        
        # Extract from URL patterns
        for url in urls:
            try:
                # Extract from query parameters
                parsed = urlparse(url)
                if parsed.query:
                    params = parse_qs(parsed.query)
                    all_params.update([k for k in params.keys() if k])
                
                # Extract from path parameters (REST-style)
                if parsed.path:
                    path_params = re.findall(r'/([a-zA-Z_][a-zA-Z0-9_]*)/\d+', parsed.path)
                    all_params.update(path_params)
                
                # Extract from fragment parameters
                if parsed.fragment:
                    fragment_params = re.findall(r'([a-zA-Z_][a-zA-Z0-9_]*)[=:]', parsed.fragment)
                    all_params.update(fragment_params)
            except:
                continue
        
        # Extract parameters from JavaScript-like patterns in URLs
        js_patterns = [
            r'[?&]([a-zA-Z_][a-zA-Z0-9_]*)[=]',
            r'["\']([a-zA-Z_][a-zA-Z0-9_]*)["\']:\s*["\']',
            r'\.([a-zA-Z_][a-zA-Z0-9_]*)\s*=',
        ]
        
        for url in urls:
            try:
                for pattern in js_patterns:
                    matches = re.findall(pattern, url, re.IGNORECASE)
                    for match in matches:
                        if len(match) > 2 and match.lower() not in ['http', 'https', 'www', 'com', 'org']:
                            all_params.add(match)
            except:
                continue
        
        # Filter out common non-parameter strings
        filtered_params = set()
        for param in all_params:
            if param and len(param) > 1 and param.isalnum() or '_' in param:
                filtered_params.add(param)
        
        Logger.success(f"Advanced extraction found {len(filtered_params)} additional parameters")
        self.found_parameters.update(filtered_params)
        
        return filtered_params
    
    def generate_parameter_wordlist(self):
        """Generate comprehensive parameter wordlist"""
        common_params = [
            # Authentication & Session
            'id', 'user', 'username', 'email', 'password', 'token', 'key', 'api_key',
            'session', 'sessionid', 'sess', 'auth', 'login', 'logout', 'csrf', 'nonce',
            'access_token', 'refresh_token', 'client_id', 'client_secret', 'oauth',
            
            # Search & Filtering
            'search', 'q', 'query', 'keyword', 'filter', 'sort', 'order', 'limit',
            'page', 'offset', 'count', 'size', 'start', 'end', 'from', 'to',
            'category', 'type', 'status', 'mode', 'format', 'view', 'display',
            
            # Data & Content
            'data', 'value', 'param', 'arg', 'var', 'name', 'title', 'content',
            'text', 'message', 'description', 'body', 'payload', 'input', 'output',
            
            # File & Path
            'file', 'path', 'dir', 'directory', 'folder', 'url', 'link', 'src',
            'target', 'destination', 'location', 'redirect', 'return', 'callback',
            
            # System & Debug
            'debug', 'test', 'admin', 'config', 'settings', 'options', 'preferences',
            'lang', 'language', 'locale', 'timezone', 'currency', 'country', 'region',
            
            # API & JSONP
            'callback', 'jsonp', 'method', 'function', 'cmd', 'command', 'action',
            'operation', 'task', 'job', 'process', 'execute', 'run',
            
            # Common Web Parameters
            'ref', 'referrer', 'source', 'utm_source', 'utm_medium', 'utm_campaign',
            'gclid', 'fbclid', 'msclkid', 'yclid', 'affiliate', 'partner',
        ]
        
        return common_params
    
    def fuzzing_test(self, base_urls):
        """Perform parameter fuzzing on discovered URLs"""
        if not base_urls:
            return set()
        
        Logger.info("Performing parameter fuzzing test")
        
        wordlist = self.generate_parameter_wordlist()
        discovered_params = set()
        
        # Test a sample of URLs to avoid overwhelming the target
        test_urls = base_urls[:5] if len(base_urls) > 5 else base_urls
        
        def test_parameter(url, param):
            try:
                # Test GET parameter
                test_url = f"{url}{'&' if '?' in url else '?'}{param}={self.placeholder}"
                client = HTTPClient(timeout=5)
                response = client.get(test_url)
                
                # Simple heuristic: if response is different, parameter might be valid
                if response.status_code == 200 and len(response.content) > 0:
                    return param
            except:
                pass
            return None
        
        with ThreadPoolExecutor(max_workers=min(self.threads, 10)) as executor:
            futures = []
            for url in test_urls:
                for param in wordlist[:20]:  # Test top 20 parameters
                    if param not in self.found_parameters:
                        futures.append(executor.submit(test_parameter, url, param))
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    discovered_params.add(result)
                    Logger.found(f"Fuzzing discovered parameter: {result}")
        
        self.found_parameters.update(discovered_params)
        return discovered_params
    
    def run_discovery(self):
        """Run complete parameter discovery process"""
        start_time = time.time()
        
        Logger.info(f"Starting parameter discovery for {self.domain}")
        Logger.info(f"Include subdomains: {self.include_subdomains}")
        Logger.info(f"Threads: {self.threads}, Timeout: {self.timeout}s, Retries: {self.retries}")
        
        # Step 1: Fetch URLs from Wayback Machine
        wayback_urls = self.fetch_wayback_urls()
        if not wayback_urls:
            Logger.error("No URLs retrieved from Wayback Machine")
            return {
                'domain': self.domain,
                'parameters': list(self.found_parameters),
                'urls': self.found_urls,
                'statistics': {
                    'total_parameters': 0,
                    'total_urls': 0,
                    'execution_time': time.time() - start_time
                }
            }
        
        # Step 2: Extract parameters from URLs
        parameter_urls, basic_params = self.extract_parameters_from_urls(wayback_urls)
        
        # Step 3: Advanced parameter extraction
        advanced_params = self.advanced_parameter_extraction(wayback_urls)
        
        # Step 4: Optional fuzzing test (commented out to avoid being too aggressive)
        # fuzzing_params = self.fuzzing_test(parameter_urls[:3])
        
        execution_time = time.time() - start_time
        
        results = {
            'domain': self.domain,
            'parameters': sorted(list(self.found_parameters)),
            'urls': sorted(list(set(self.found_urls))),
            'statistics': {
                'total_parameters': len(self.found_parameters),
                'total_urls': len(set(self.found_urls)),
                'basic_params': len(basic_params),
                'advanced_params': len(advanced_params),
                'execution_time': execution_time
            }
        }
        
        Logger.success(f"Parameter discovery completed in {execution_time:.2f} seconds")
        Logger.success(f"Found {len(self.found_parameters)} unique parameters")
        Logger.success(f"Found {len(set(self.found_urls))} URLs with parameters")
        
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
    """Print tool banner"""
    try:
        # Try Unicode banner first
        banner = f"""
{Colors.CYAN}
╔═══════════════════════════════════════════════════════════════╗
║                    PARAMETER DISCOVERY TOOL                   ║
║                   Advanced Parameter Mining                   ║
║                  Wayback Machine + Fuzzing                   ║
╚═══════════════════════════════════════════════════════════════╝
{Colors.END}
{Colors.GREEN}Professional Parameter Discovery for Bug Bounty & Penetration Testing{Colors.END}
{Colors.YELLOW}Combines multiple ParamSpider techniques with intelligent filtering{Colors.END}
"""
        print(banner)
    except UnicodeEncodeError:
        # Fallback to ASCII banner for Windows
        banner = f"""
{Colors.CYAN}
===============================================================
                    PARAMETER DISCOVERY TOOL                   
                   Advanced Parameter Mining                   
                  Wayback Machine + Fuzzing                   
===============================================================
{Colors.END}
{Colors.GREEN}Professional Parameter Discovery for Bug Bounty & Penetration Testing{Colors.END}
{Colors.YELLOW}Combines multiple ParamSpider techniques with intelligent filtering{Colors.END}
"""
        print(banner)

def main():
    print_banner()
    
    parser = argparse.ArgumentParser(
        description="Advanced Parameter Discovery Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 parameter.py -d example.com
  python3 parameter.py -d example.com --no-subs -o results
  python3 parameter.py -d example.com -t 30 --format json
  python3 parameter.py -l domains.txt -q
        """
    )
    
    # Target options
    parser.add_argument('-d', '--domain', help='Target domain (e.g., example.com)')
    parser.add_argument('-l', '--list', help='File containing list of domains')
    
    # Discovery options
    parser.add_argument('--no-subs', action='store_true', help='Exclude subdomains from discovery')
    parser.add_argument('-t', '--threads', type=int, default=20, help='Number of threads (default: 20)')
    parser.add_argument('--timeout', type=int, default=30, help='Request timeout in seconds (default: 30)')
    parser.add_argument('-r', '--retries', type=int, default=3, help='Number of retries for failed requests (default: 3)')
    parser.add_argument('-p', '--placeholder', default='FUZZ', help='Placeholder for parameter values (default: FUZZ)')
    
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
        discovery = ParameterDiscovery(
            domain=domain,
            include_subdomains=not args.no_subs,
            threads=args.threads,
            timeout=args.timeout,
            retries=args.retries,
            placeholder=args.placeholder
        )
        
        # Run discovery
        try:
            results = discovery.run_discovery()
            all_results.append(results)
            
            # Display results if not in quiet mode
            if not args.quiet:
                print(f"\n{Colors.GREEN}[RESULTS for {domain}]{Colors.END}")
                print(f"Parameters found: {len(results['parameters'])}")
                if results['parameters']:
                    print("Parameters:", ", ".join(results['parameters'][:10]))
                    if len(results['parameters']) > 10:
                        print(f"... and {len(results['parameters']) - 10} more")
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