#!/usr/bin/env python3
"""
AssetFinder Python Implementation
Find domains and subdomains potentially related to a given domain.

This is a Python port of tomnomnom's assetfinder tool with enhanced features.
Original: https://github.com/tomnomnom/assetfinder

Enhanced Features:
- All original sources implemented
- Additional modern sources
- Better error handling
- Rate limiting
- Concurrent processing
- Clean output formatting
- Support for stdin input
- API key management

Sources Implemented:
- crt.sh (Certificate Transparency)
- CertSpotter
- HackerTarget
- ThreatCrowd
- Facebook Certificate Transparency
- VirusTotal
- Spyse (FindSubDomains)
- URLScan.io
- BufferOver.run
- Wayback Machine (optional)
- Additional sources: Anubis, AlienVault, Chaos, Shodan, SecurityTrails

Environment Variables (Optional):
- FB_APP_ID, FB_APP_SECRET: Facebook API credentials
- VT_API_KEY: VirusTotal API key
- SPYSE_API_TOKEN: Spyse API token
- CHAOS_API_KEY: Chaos API key
- SHODAN_API_KEY: Shodan API key
- SECURITYTRAILS_API_KEY: SecurityTrails API key
"""

import argparse
import json
import os
import re
import ssl
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Set, Optional, Dict, Any
from urllib.parse import urlparse
import urllib.request
import urllib.error


class RateLimiter:
    """Rate limiter to prevent overwhelming APIs"""
    
    def __init__(self, delay: float = 1.0):
        self.delay = delay
        self.last_requests = {}
        self.lock = threading.Lock()
    
    def wait(self, key: str):
        """Wait if necessary to respect rate limits"""
        with self.lock:
            now = time.time()
            if key in self.last_requests:
                elapsed = now - self.last_requests[key]
                if elapsed < self.delay:
                    time.sleep(self.delay - elapsed)
            self.last_requests[key] = time.time()


class AssetFinder:
    """Main AssetFinder class"""
    
    def __init__(self, subs_only: bool = False, verbose: bool = False):
        self.subs_only = subs_only
        self.verbose = verbose
        self.timeout = 15
        self.rate_limiter = RateLimiter(1.0)
        self.found_domains = set()
        self.lock = threading.Lock()
        
        # SSL context for HTTPS requests
        self.ssl_context = ssl.create_default_context()
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_NONE
        
        # User agent for requests
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
    
    def log(self, message: str):
        """Log message if verbose mode is enabled"""
        if self.verbose:
            print(f"[DEBUG] {message}", file=sys.stderr)
    
    def clean_domain(self, domain: str) -> str:
        """Clean and normalize domain name"""
        domain = domain.lower().strip()
        
        if len(domain) < 2:
            return domain
        
        # Remove wildcards and dots
        if domain.startswith('*') or domain.startswith('%'):
            domain = domain[1:]
        
        if domain.startswith('.'):
            domain = domain[1:]
        
        return domain
    
    def is_valid_domain(self, domain: str) -> bool:
        """Check if domain is valid"""
        if not domain or len(domain) > 253:
            return False
        
        # Basic domain validation
        if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$', domain):
            return False
        
        return True
    
    def add_domain(self, domain: str, target_domain: str):
        """Add domain to results with filtering"""
        domain = self.clean_domain(domain)
        
        if not domain or not self.is_valid_domain(domain):
            return
        
        # Apply subs-only filter
        if self.subs_only and not domain.endswith(target_domain):
            return
        
        with self.lock:
            if domain not in self.found_domains:
                self.found_domains.add(domain)
                print(domain)
    
    def fetch_url(self, url: str, headers: Dict[str, str] = None) -> Optional[str]:
        """Fetch URL content"""
        try:
            request = urllib.request.Request(url)
            
            # Add default headers
            for key, value in self.headers.items():
                request.add_header(key, value)
            
            # Add custom headers
            if headers:
                for key, value in headers.items():
                    request.add_header(key, value)
            
            with urllib.request.urlopen(request, timeout=self.timeout, context=self.ssl_context) as response:
                if response.status == 200:
                    return response.read().decode('utf-8', errors='ignore')
        except Exception as e:
            self.log(f"Error fetching {url}: {e}")
        return None
    
    def fetch_json(self, url: str, headers: Dict[str, str] = None) -> Optional[dict]:
        """Fetch JSON data from URL"""
        content = self.fetch_url(url, headers)
        if content:
            try:
                return json.loads(content)
            except json.JSONDecodeError as e:
                self.log(f"JSON decode error for {url}: {e}")
        return None
    
    # Source implementations
    
    def fetch_crtsh(self, domain: str) -> List[str]:
        """Fetch domains from crt.sh"""
        self.rate_limiter.wait('crtsh')
        self.log(f"Fetching from crt.sh for {domain}")
        
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        data = self.fetch_json(url)
        
        domains = []
        if data:
            for item in data:
                if 'name_value' in item:
                    # Handle multiple domains in name_value field
                    names = item['name_value'].split('\n')
                    for name in names:
                        name = name.strip()
                        if name:
                            domains.append(name)
        
        self.log(f"crt.sh found {len(domains)} domains")
        return domains
    
    def fetch_certspotter(self, domain: str) -> List[str]:
        """Fetch domains from CertSpotter"""
        self.rate_limiter.wait('certspotter')
        self.log(f"Fetching from CertSpotter for {domain}")
        
        url = f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
        data = self.fetch_json(url)
        
        domains = []
        if data:
            for item in data:
                if 'dns_names' in item:
                    domains.extend(item['dns_names'])
        
        self.log(f"CertSpotter found {len(domains)} domains")
        return domains
    
    def fetch_hackertarget(self, domain: str) -> List[str]:
        """Fetch domains from HackerTarget"""
        self.rate_limiter.wait('hackertarget')
        self.log(f"Fetching from HackerTarget for {domain}")
        
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        content = self.fetch_url(url)
        
        domains = []
        if content:
            lines = content.strip().split('\n')
            for line in lines:
                parts = line.split(',', 1)
                if len(parts) == 2:
                    domains.append(parts[0])
        
        self.log(f"HackerTarget found {len(domains)} domains")
        return domains
    
    def fetch_threatcrowd(self, domain: str) -> List[str]:
        """Fetch domains from ThreatCrowd"""
        self.rate_limiter.wait('threatcrowd')
        self.log(f"Fetching from ThreatCrowd for {domain}")
        
        url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}"
        data = self.fetch_json(url)
        
        domains = []
        if data and 'subdomains' in data and data['subdomains']:
            domains = data['subdomains']
        
        self.log(f"ThreatCrowd found {len(domains)} domains")
        return domains
    
    def fetch_facebook(self, domain: str) -> List[str]:
        """Fetch domains from Facebook Certificate Transparency"""
        app_id = os.getenv('FB_APP_ID')
        app_secret = os.getenv('FB_APP_SECRET')
        
        if not app_id or not app_secret:
            self.log("Facebook API credentials not found, skipping")
            return []
        
        self.rate_limiter.wait('facebook')
        self.log(f"Fetching from Facebook CT for {domain}")
        
        # Get access token
        auth_url = f"https://graph.facebook.com/oauth/access_token?client_id={app_id}&client_secret={app_secret}&grant_type=client_credentials"
        auth_data = self.fetch_json(auth_url)
        
        if not auth_data or 'access_token' not in auth_data:
            self.log("Failed to get Facebook access token")
            return []
        
        access_token = auth_data['access_token']
        
        # Fetch certificates
        domains = []
        url = f"https://graph.facebook.com/certificates?fields=domains&access_token={access_token}&query=*.{domain}"
        
        while url:
            data = self.fetch_json(url)
            if not data:
                break
            
            if 'data' in data:
                for item in data['data']:
                    if 'domains' in item:
                        domains.extend(item['domains'])
            
            # Check for pagination
            url = data.get('paging', {}).get('next')
        
        self.log(f"Facebook CT found {len(domains)} domains")
        return domains
    
    def fetch_virustotal(self, domain: str) -> List[str]:
        """Fetch domains from VirusTotal"""
        api_key = os.getenv('VT_API_KEY')
        
        if not api_key:
            self.log("VirusTotal API key not found, skipping")
            return []
        
        self.rate_limiter.wait('virustotal')
        self.log(f"Fetching from VirusTotal for {domain}")
        
        url = f"https://www.virustotal.com/vtapi/v2/domain/report?domain={domain}&apikey={api_key}"
        data = self.fetch_json(url)
        
        domains = []
        if data and 'subdomains' in data and data['subdomains']:
            domains = data['subdomains']
        
        self.log(f"VirusTotal found {len(domains)} domains")
        return domains
    
    def fetch_findsubdomains(self, domain: str) -> List[str]:
        """Fetch domains from Spyse (FindSubDomains)"""
        api_token = os.getenv('SPYSE_API_TOKEN')
        
        if not api_token:
            self.log("Spyse API token not found, skipping")
            return []
        
        self.rate_limiter.wait('spyse')
        self.log(f"Fetching from Spyse for {domain}")
        
        domains = []
        
        # Try subdomains endpoint
        page = 1
        while page <= 5:  # Limit to 5 pages
            url = f"https://api.spyse.com/v1/subdomains?api_token={api_token}&domain={domain}&page={page}"
            data = self.fetch_json(url)
            
            if not data or 'records' not in data or not data['records']:
                break
            
            for record in data['records']:
                if 'domain' in record:
                    domains.append(record['domain'])
            
            page += 1
        
        self.log(f"Spyse found {len(domains)} domains")
        return domains
    
    def fetch_urlscan(self, domain: str) -> List[str]:
        """Fetch domains from URLScan.io"""
        self.rate_limiter.wait('urlscan')
        self.log(f"Fetching from URLScan.io for {domain}")
        
        url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}"
        data = self.fetch_json(url)
        
        domains = []
        if data and 'results' in data:
            for result in data['results']:
                # Extract from task URL
                if 'task' in result and 'url' in result['task']:
                    try:
                        parsed = urlparse(result['task']['url'])
                        if parsed.hostname:
                            domains.append(parsed.hostname)
                    except:
                        pass
                
                # Extract from page URL
                if 'page' in result and 'url' in result['page']:
                    try:
                        parsed = urlparse(result['page']['url'])
                        if parsed.hostname:
                            domains.append(parsed.hostname)
                    except:
                        pass
        
        self.log(f"URLScan.io found {len(domains)} domains")
        return list(set(domains))
    
    def fetch_bufferoverrun(self, domain: str) -> List[str]:
        """Fetch domains from BufferOver.run"""
        self.rate_limiter.wait('bufferover')
        self.log(f"Fetching from BufferOver.run for {domain}")
        
        url = f"https://dns.bufferover.run/dns?q=.{domain}"
        data = self.fetch_json(url)
        
        domains = []
        if data and 'FDNS_A' in data:
            for record in data['FDNS_A']:
                parts = record.split(',', 1)
                if len(parts) == 2:
                    domains.append(parts[1])
        
        self.log(f"BufferOver.run found {len(domains)} domains")
        return domains
    
    def fetch_wayback(self, domain: str) -> List[str]:
        """Fetch domains from Wayback Machine (optional, can be slow)"""
        self.rate_limiter.wait('wayback')
        self.log(f"Fetching from Wayback Machine for {domain}")
        
        url = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&collapse=urlkey"
        data = self.fetch_json(url)
        
        domains = []
        if data and isinstance(data, list):
            for item in data[1:]:  # Skip header
                if len(item) >= 3:
                    try:
                        parsed = urlparse(item[2])
                        if parsed.hostname:
                            domains.append(parsed.hostname)
                    except:
                        continue
        
        self.log(f"Wayback Machine found {len(domains)} domains")
        return list(set(domains))
    
    # Additional sources for enhanced functionality
    
    def fetch_anubis(self, domain: str) -> List[str]:
        """Fetch domains from Anubis"""
        self.rate_limiter.wait('anubis')
        self.log(f"Fetching from Anubis for {domain}")
        
        url = f"https://jldc.me/anubis/subdomains/{domain}"
        data = self.fetch_json(url)
        
        domains = []
        if data and isinstance(data, list):
            domains = data
        
        self.log(f"Anubis found {len(domains)} domains")
        return domains
    
    def fetch_alienvault(self, domain: str) -> List[str]:
        """Fetch domains from AlienVault OTX"""
        self.rate_limiter.wait('alienvault')
        self.log(f"Fetching from AlienVault OTX for {domain}")
        
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
        data = self.fetch_json(url)
        
        domains = []
        if data and 'passive_dns' in data:
            for item in data['passive_dns']:
                if 'hostname' in item:
                    domains.append(item['hostname'])
        
        self.log(f"AlienVault OTX found {len(domains)} domains")
        return domains
    
    def fetch_chaos(self, domain: str) -> List[str]:
        """Fetch domains from Chaos"""
        api_key = os.getenv('CHAOS_API_KEY')
        
        if not api_key:
            self.log("Chaos API key not found, skipping")
            return []
        
        self.rate_limiter.wait('chaos')
        self.log(f"Fetching from Chaos for {domain}")
        
        headers = {'Authorization': api_key}
        url = f"https://dns.projectdiscovery.io/dns/{domain}/subdomains"
        data = self.fetch_json(url, headers)
        
        domains = []
        if data and 'subdomains' in data:
            for subdomain in data['subdomains']:
                domains.append(f"{subdomain}.{domain}")
        
        self.log(f"Chaos found {len(domains)} domains")
        return domains
    
    def fetch_shodan(self, domain: str) -> List[str]:
        """Fetch domains from Shodan"""
        api_key = os.getenv('SHODAN_API_KEY')
        
        if not api_key:
            self.log("Shodan API key not found, skipping")
            return []
        
        self.rate_limiter.wait('shodan')
        self.log(f"Fetching from Shodan for {domain}")
        
        url = f"https://api.shodan.io/dns/domain/{domain}?key={api_key}"
        data = self.fetch_json(url)
        
        domains = []
        if data and 'subdomains' in data:
            for subdomain in data['subdomains']:
                domains.append(f"{subdomain}.{domain}")
        
        self.log(f"Shodan found {len(domains)} domains")
        return domains
    
    def fetch_securitytrails(self, domain: str) -> List[str]:
        """Fetch domains from SecurityTrails"""
        api_key = os.getenv('SECURITYTRAILS_API_KEY')
        
        if not api_key:
            self.log("SecurityTrails API key not found, skipping")
            return []
        
        self.rate_limiter.wait('securitytrails')
        self.log(f"Fetching from SecurityTrails for {domain}")
        
        headers = {'APIKEY': api_key}
        url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
        data = self.fetch_json(url, headers)
        
        domains = []
        if data and 'subdomains' in data:
            for subdomain in data['subdomains']:
                domains.append(f"{subdomain}.{domain}")
        
        self.log(f"SecurityTrails found {len(domains)} domains")
        return domains
    
    def run_source(self, source_func, domain: str):
        """Run a single source function"""
        try:
            domains = source_func(domain)
            for d in domains:
                self.add_domain(d, domain)
        except Exception as e:
            self.log(f"Error in {source_func.__name__}: {e}")
    
    def find_domains(self, domain: str, include_wayback: bool = False, 
                    enhanced_sources: bool = False) -> Set[str]:
        """Find domains using all available sources"""
        domain = domain.lower().strip()
        self.log(f"Starting domain enumeration for: {domain}")
        
        # Core sources (original assetfinder sources)
        core_sources = [
            self.fetch_crtsh,
            self.fetch_certspotter,
            self.fetch_hackertarget,
            self.fetch_threatcrowd,
            self.fetch_facebook,
            self.fetch_virustotal,
            self.fetch_findsubdomains,
            self.fetch_urlscan,
            self.fetch_bufferoverrun,
        ]
        
        # Optional wayback machine (can be slow)
        if include_wayback:
            core_sources.append(self.fetch_wayback)
        
        # Enhanced sources (additional modern sources)
        enhanced_source_list = [
            self.fetch_anubis,
            self.fetch_alienvault,
            self.fetch_chaos,
            self.fetch_shodan,
            self.fetch_securitytrails,
        ]
        
        sources = core_sources
        if enhanced_sources:
            sources.extend(enhanced_source_list)
        
        # Run sources concurrently
        with ThreadPoolExecutor(max_workers=min(len(sources), 10)) as executor:
            futures = [executor.submit(self.run_source, source, domain) for source in sources]
            
            # Wait for all to complete
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    self.log(f"Source execution error: {e}")
        
        self.log(f"Total unique domains found: {len(self.found_domains)}")
        return self.found_domains


def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description='Find domains and subdomains potentially related to a given domain',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python assetfinder.py example.com
  python assetfinder.py --subs-only example.com
  echo "example.com" | python assetfinder.py
  python assetfinder.py --enhanced --wayback example.com
  
Environment Variables (Optional):
  FB_APP_ID, FB_APP_SECRET - Facebook API credentials
  VT_API_KEY - VirusTotal API key
  SPYSE_API_TOKEN - Spyse API token
  CHAOS_API_KEY - Chaos API key
  SHODAN_API_KEY - Shodan API key
  SECURITYTRAILS_API_KEY - SecurityTrails API key
        """
    )
    
    parser.add_argument('domain', nargs='?', help='Domain to search for')
    parser.add_argument('--subs-only', action='store_true',
                       help='Only include subdomains of search domain')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Enable verbose output')
    parser.add_argument('--wayback', action='store_true',
                       help='Include Wayback Machine (can be slow)')
    parser.add_argument('--enhanced', action='store_true',
                       help='Use enhanced sources (Anubis, AlienVault, etc.)')
    
    args = parser.parse_args()
    
    # Get domain from argument or stdin
    if args.domain:
        domains = [args.domain]
    else:
        domains = []
        try:
            for line in sys.stdin:
                domain = line.strip()
                if domain:
                    domains.append(domain)
        except KeyboardInterrupt:
            pass
    
    if not domains:
        parser.print_help()
        return 1
    
    # Process each domain
    finder = AssetFinder(subs_only=args.subs_only, verbose=args.verbose)
    
    for domain in domains:
        finder.find_domains(domain, include_wayback=args.wayback, 
                          enhanced_sources=args.enhanced)
    
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nInterrupted by user", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)