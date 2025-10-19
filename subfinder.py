#!/usr/bin/env python3
"""
Subfinder Python Implementation - Optimized Version
Find domains and subdomains potentially related to a given domain.

This is an optimized Python port of ProjectDiscovery's subfinder tool.
Original: https://github.com/projectdiscovery/subfinder

=== API Configuration ===
Set these environment variables for better results:

# Free APIs (No registration required)
- No API key needed for: crt.sh, hackertarget, anubis, alienvault

# APIs requiring registration:
- CHAOS_API_KEY: https://chaos.projectdiscovery.io/
- SHODAN_API_KEY: https://www.shodan.io/
- VIRUSTOTAL_API_KEY: https://developers.virustotal.com/reference
- SECURITYTRAILS_API_KEY: https://securitytrails.com/
- CENSYS_API_ID, CENSYS_SECRET: https://censys.io/api
"""

import argparse
import json
import os
import sys
import time
import base64
from typing import List, Set, Optional, Dict, Any
from urllib.parse import urlparse, quote
import urllib.request
import urllib.error
import ssl
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed


class SubfinderOptimized:
    """Optimized Subfinder class with real-time output"""
    
    def __init__(self, subs_only: bool = False, silent: bool = False, fast: bool = False):
        self.subs_only = subs_only
        self.silent = silent
        self.fast = fast
        self.timeout = 8 if fast else 12
        self.found_domains = set()
        self.lock = threading.Lock()
        
        # Create SSL context
        self.ssl_context = ssl.create_default_context()
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_NONE
        
    def log_info(self, message: str):
        """Log info message if not in silent mode"""
        if not self.silent:
            print(f"[INFO] {message}", file=sys.stderr)
    
    def log_progress(self, source: str, count: int, completed: int, total: int):
        """Log progress message if not in silent mode"""
        if not self.silent:
            status = "✓" if count > 0 else "✗"
            print(f"[{status}] {source}: {count} domains ({completed}/{total})", file=sys.stderr)
    
    def clean_domain(self, domain: str) -> str:
        """Clean and normalize domain name"""
        domain = domain.lower().strip()
        
        if len(domain) < 2:
            return domain
        
        if domain.startswith('*') or domain.startswith('%'):
            domain = domain[1:]
        
        if domain.startswith('.'):
            domain = domain[1:]
        
        return domain
    
    def add_domain(self, domain: str, target_domain: str):
        """Add domain to results with thread safety"""
        cleaned = self.clean_domain(domain)
        if not cleaned:
            return
        
        # Filter subdomains only if requested
        if self.subs_only and not cleaned.endswith(f'.{target_domain}') and cleaned != target_domain:
            return
        
        with self.lock:
            if cleaned not in self.found_domains:
                self.found_domains.add(cleaned)
                print(cleaned)  # Print immediately when found
    
    def fetch_json(self, url: str, headers: Dict[str, str] = None) -> Optional[dict]:
        """Fetch JSON data from URL"""
        try:
            request = urllib.request.Request(url)
            request.add_header('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
            
            if headers:
                for key, value in headers.items():
                    request.add_header(key, value)
            
            with urllib.request.urlopen(request, timeout=self.timeout, context=self.ssl_context) as response:
                if response.status == 200:
                    data = response.read().decode('utf-8')
                    return json.loads(data)
        except Exception:
            pass
        return None
    
    def fetch_text(self, url: str, headers: Dict[str, str] = None) -> Optional[str]:
        """Fetch text data from URL"""
        try:
            request = urllib.request.Request(url)
            request.add_header('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
            
            if headers:
                for key, value in headers.items():
                    request.add_header(key, value)
            
            with urllib.request.urlopen(request, timeout=self.timeout, context=self.ssl_context) as response:
                if response.status == 200:
                    return response.read().decode('utf-8')
        except Exception:
            pass
        return None
    
    def fetch_crtsh(self, domain: str) -> int:
        """Fetch domains from crt.sh"""
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        data = self.fetch_json(url)
        
        if not data:
            return 0
        
        count = 0
        for item in data:
            if 'name_value' in item:
                names = item['name_value'].split('\n')
                for name in names:
                    name = name.strip()
                    if name:
                        self.add_domain(name, domain)
                        count += 1
        
        return count
    
    def fetch_hackertarget(self, domain: str) -> int:
        """Fetch domains from HackerTarget"""
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        text = self.fetch_text(url)
        
        if not text:
            return 0
        
        count = 0
        for line in text.strip().split('\n'):
            parts = line.split(',', 1)
            if len(parts) == 2:
                self.add_domain(parts[0], domain)
                count += 1
        
        return count
    
    def fetch_anubis(self, domain: str) -> int:
        """Fetch domains from Anubis"""
        url = f"https://jldc.me/anubis/subdomains/{domain}"
        data = self.fetch_json(url)
        
        if not data or not isinstance(data, list):
            return 0
        
        count = 0
        for subdomain in data:
            self.add_domain(subdomain, domain)
            count += 1
        
        return count
    
    def fetch_alienvault(self, domain: str) -> int:
        """Fetch domains from AlienVault OTX"""
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
        data = self.fetch_json(url)
        
        if not data or 'passive_dns' not in data:
            return 0
        
        count = 0
        for item in data['passive_dns']:
            if 'hostname' in item:
                self.add_domain(item['hostname'], domain)
                count += 1
        
        return count
    
    def fetch_chaos(self, domain: str) -> int:
        """Fetch domains from Chaos"""
        api_key = os.getenv('CHAOS_API_KEY')
        if not api_key:
            return 0
        
        headers = {'Authorization': api_key}
        url = f"https://dns.projectdiscovery.io/dns/{domain}/subdomains"
        data = self.fetch_json(url, headers)
        
        if not data or 'subdomains' not in data:
            return 0
        
        count = 0
        for subdomain in data['subdomains']:
            self.add_domain(f"{subdomain}.{domain}", domain)
            count += 1
        
        return count
    
    def fetch_shodan(self, domain: str) -> int:
        """Fetch domains from Shodan"""
        api_key = os.getenv('SHODAN_API_KEY')
        if not api_key:
            return 0
        
        url = f"https://api.shodan.io/dns/domain/{domain}?key={api_key}"
        data = self.fetch_json(url)
        
        if not data or 'subdomains' not in data:
            return 0
        
        count = 0
        for subdomain in data['subdomains']:
            self.add_domain(f"{subdomain}.{domain}", domain)
            count += 1
        
        return count
    
    def fetch_virustotal(self, domain: str) -> int:
        """Fetch domains from VirusTotal"""
        api_key = os.getenv('VIRUSTOTAL_API_KEY')
        if not api_key:
            return 0
        
        headers = {'x-apikey': api_key}
        url = f"https://www.virustotal.com/vtapi/v2/domain/report?domain={domain}"
        data = self.fetch_json(url, headers)
        
        if not data or 'subdomains' not in data:
            return 0
        
        count = 0
        for subdomain in data['subdomains']:
            self.add_domain(subdomain, domain)
            count += 1
        
        return count
    
    def fetch_securitytrails(self, domain: str) -> int:
        """Fetch domains from SecurityTrails"""
        api_key = os.getenv('SECURITYTRAILS_API_KEY')
        if not api_key:
            return 0
        
        headers = {'APIKEY': api_key}
        url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
        data = self.fetch_json(url, headers)
        
        if not data or 'subdomains' not in data:
            return 0
        
        count = 0
        for subdomain in data['subdomains']:
            self.add_domain(f"{subdomain}.{domain}", domain)
            count += 1
        
        return count
    
    def fetch_censys(self, domain: str) -> int:
        """Fetch domains from Censys"""
        api_id = os.getenv('CENSYS_API_ID')
        secret = os.getenv('CENSYS_SECRET')
        if not (api_id and secret):
            return 0
        
        credentials = f"{api_id}:{secret}"
        encoded_credentials = base64.b64encode(credentials.encode()).decode()
        headers = {'Authorization': f'Basic {encoded_credentials}'}
        
        url = f"https://search.censys.io/api/v2/certificates/search?q=names:{domain}"
        data = self.fetch_json(url, headers)
        
        if not data or 'result' not in data or 'hits' not in data['result']:
            return 0
        
        count = 0
        for hit in data['result']['hits']:
            if 'names' in hit:
                for name in hit['names']:
                    self.add_domain(name, domain)
                    count += 1
        
        return count
    
    def run_source(self, source_name: str, source_func, domain: str, completed_counter: list, total: int):
        """Run a single source and update progress"""
        try:
            count = source_func(domain)
            completed_counter[0] += 1
            self.log_progress(source_name, count, completed_counter[0], total)
        except Exception:
            completed_counter[0] += 1
            self.log_progress(source_name, 0, completed_counter[0], total)
    
    def find_domains(self, domain: str):
        """Find all domains and subdomains for the given domain"""
        domain = domain.lower().strip()
        
        # Define sources based on mode
        if self.fast:
            sources = [
                ('crtsh', self.fetch_crtsh),
                ('hackertarget', self.fetch_hackertarget),
                ('anubis', self.fetch_anubis),
                ('chaos', self.fetch_chaos),
                ('shodan', self.fetch_shodan),
            ]
        else:
            sources = [
                ('crtsh', self.fetch_crtsh),
                ('hackertarget', self.fetch_hackertarget),
                ('anubis', self.fetch_anubis),
                ('alienvault', self.fetch_alienvault),
                ('chaos', self.fetch_chaos),
                ('shodan', self.fetch_shodan),
                ('virustotal', self.fetch_virustotal),
                ('securitytrails', self.fetch_securitytrails),
                ('censys', self.fetch_censys),
            ]
        
        # Filter enabled sources (check for API keys)
        enabled_sources = []
        for name, func in sources:
            if name in ['crtsh', 'hackertarget', 'anubis', 'alienvault']:
                enabled_sources.append((name, func))
            elif name == 'chaos' and os.getenv('CHAOS_API_KEY'):
                enabled_sources.append((name, func))
            elif name == 'shodan' and os.getenv('SHODAN_API_KEY'):
                enabled_sources.append((name, func))
            elif name == 'virustotal' and os.getenv('VIRUSTOTAL_API_KEY'):
                enabled_sources.append((name, func))
            elif name == 'securitytrails' and os.getenv('SECURITYTRAILS_API_KEY'):
                enabled_sources.append((name, func))
            elif name == 'censys' and os.getenv('CENSYS_API_ID') and os.getenv('CENSYS_SECRET'):
                enabled_sources.append((name, func))
        
        self.log_info(f"Using {len(enabled_sources)} sources")
        self.log_info(f"Results will appear below as they are found...")
        
        # Run sources in parallel
        completed_counter = [0]
        
        with ThreadPoolExecutor(max_workers=min(len(enabled_sources), 10)) as executor:
            futures = []
            for source_name, source_func in enabled_sources:
                future = executor.submit(self.run_source, source_name, source_func, domain, completed_counter, len(enabled_sources))
                futures.append(future)
            
            # Wait for all to complete
            for future in as_completed(futures):
                pass
        
        if not self.silent:
            print(f"\n[INFO] Found {len(self.found_domains)} unique domains", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(
        description='Find domains and subdomains related to a given domain (Optimized)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python subfinder_optimized.py example.com
  python subfinder_optimized.py -u example.com --fast
  python subfinder_optimized.py --subs-only example.com
  echo "example.com" | python subfinder_optimized.py
  
Environment Variables (Optional):
  CHAOS_API_KEY - Chaos API key
  SHODAN_API_KEY - Shodan API key  
  VIRUSTOTAL_API_KEY - VirusTotal API key
  SECURITYTRAILS_API_KEY - SecurityTrails API key
  CENSYS_API_ID, CENSYS_SECRET - Censys API credentials
        """
    )
    
    parser.add_argument('domain', nargs='?', help='Domain to search for')
    parser.add_argument('-u', '--url', help='Domain to search for (alternative to positional argument)')
    parser.add_argument('--subs-only', action='store_true',
                       help='Only include subdomains of search domain')
    parser.add_argument('--silent', action='store_true',
                       help='Show only results in output')
    parser.add_argument('--fast', action='store_true',
                       help='Fast mode - use only fastest sources')
    
    args = parser.parse_args()
    
    # Get domain from argument or -u flag or stdin
    target_domain = args.domain or args.url
    
    if target_domain:
        domains = [target_domain]
    else:
        domains = [line.strip() for line in sys.stdin if line.strip()]
    
    if not domains:
        parser.print_help()
        return 1
    
    # Process each domain
    for domain in domains:
        finder = SubfinderOptimized(subs_only=args.subs_only, silent=args.silent, fast=args.fast)
        finder.find_domains(domain)
    
    return 0


if __name__ == '__main__':
    try:
        exit_code = main()
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\nInterrupted by user", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)