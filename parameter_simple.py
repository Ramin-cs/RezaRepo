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
from urllib.parse import urlparse, parse_qs, urlencode, unquote
from concurrent.futures import ThreadPoolExecutor, as_completed
import urllib.request
import urllib.error
import warnings
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
        self.timeout = timeout
        self.quiet = quiet
        self.found_parameters = set()
        self.found_urls = []
        self.http_client = SimpleHTTPClient(timeout=timeout)
        
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
        """Fetch URLs from Wayback Machine"""
        Logger.info(f"Fetching URLs from Wayback Machine for {self.domain}")
        
        if self.include_subdomains:
            wayback_url = f"https://web.archive.org/cdx/search/cdx?url=*.{self.domain}/*&output=txt&fl=original&collapse=urlkey&page=/"
        else:
            wayback_url = f"https://web.archive.org/cdx/search/cdx?url={self.domain}/*&output=txt&fl=original&collapse=urlkey&page=/"
        
        try:
            response = self.http_client.get(wayback_url)
            
            if response.status_code == 200:
                urls = response.text.strip().split('\n')
                urls = [unquote(url) for url in urls if url.strip()]
                Logger.success(f"Retrieved {len(urls)} URLs from Wayback Machine")
                return urls
            else:
                Logger.error("Failed to fetch URLs from Wayback Machine")
                return []
                
        except Exception as e:
            Logger.error(f"Failed to fetch URLs: {str(e)}")
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
                Logger.found(f"Parameter #{i}: {param}")
                # Add small delay for better readability in live mode
                if i % 10 == 0:
                    time.sleep(0.1)
        
        self.found_parameters.update(parameters_found)
        self.found_urls.extend(parameter_urls)
        
        return parameter_urls, parameters_found
    
    def run_discovery(self):
        """Run parameter discovery"""
        start_time = time.time()
        
        Logger.info(f"Starting parameter discovery for {self.domain}")
        
        # Fetch URLs from Wayback Machine
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
        
        # Extract parameters from URLs
        parameter_urls, basic_params = self.extract_parameters_from_urls(wayback_urls)
        
        execution_time = time.time() - start_time
        
        results = {
            'domain': self.domain,
            'parameters': sorted(list(self.found_parameters)),
            'urls': sorted(list(set(self.found_urls))),
            'statistics': {
                'total_parameters': len(self.found_parameters),
                'total_urls': len(set(self.found_urls)),
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