#!/usr/bin/env python3
"""
AssetFinder Python Implementation (Simple Version)
Find domains and subdomains potentially related to a given domain.

This is a Python port of tomnomnom's assetfinder tool.
Original: https://github.com/tomnomnom/assetfinder

API Keys (Optional - برای عملکرد بهتر):
- Facebook API: https://developers.facebook.com/
  Set FB_APP_ID and FB_APP_SECRET environment variables
- VirusTotal API: https://developers.virustotal.com/reference
  Set VT_API_KEY environment variable  
- Spyse API: https://spyse.com/apidocs
  Set SPYSE_API_TOKEN environment variable
"""

import argparse
import json
import os
import sys
import time
from typing import List, Set, Optional
from urllib.parse import urlparse
import urllib.request
import urllib.error
import ssl
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed


class AssetFinder:
    """Main AssetFinder class"""
    
    def __init__(self, subs_only: bool = False):
        self.subs_only = subs_only
        self.timeout = 30
        # Create SSL context that doesn't verify certificates for problematic sites
        self.ssl_context = ssl.create_default_context()
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_NONE
        
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
    
    def fetch_json(self, url: str) -> Optional[dict]:
        """Fetch JSON data from URL"""
        try:
            request = urllib.request.Request(url)
            request.add_header('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
            
            with urllib.request.urlopen(request, timeout=self.timeout, context=self.ssl_context) as response:
                if response.status == 200:
                    data = response.read().decode('utf-8')
                    return json.loads(data)
        except Exception as e:
            print(f"Error fetching {url}: {e}", file=sys.stderr)
        return None
    
    def fetch_text(self, url: str) -> Optional[str]:
        """Fetch text data from URL"""
        try:
            request = urllib.request.Request(url)
            request.add_header('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
            
            with urllib.request.urlopen(request, timeout=self.timeout, context=self.ssl_context) as response:
                if response.status == 200:
                    return response.read().decode('utf-8')
        except Exception as e:
            print(f"Error fetching {url}: {e}", file=sys.stderr)
        return None
    
    def fetch_crtsh(self, domain: str) -> List[str]:
        """Fetch domains from crt.sh"""
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        data = self.fetch_json(url)
        
        if not data:
            return []
        
        domains = []
        for item in data:
            if 'name_value' in item:
                # Handle multiple domains in name_value field
                names = item['name_value'].split('\n')
                for name in names:
                    name = name.strip()
                    if name:
                        domains.append(name)
        
        return domains
    
    def fetch_certspotter(self, domain: str) -> List[str]:
        """Fetch domains from CertSpotter"""
        url = f"https://certspotter.com/api/v0/certs?domain={domain}"
        data = self.fetch_json(url)
        
        if not data:
            return []
        
        domains = []
        for item in data:
            if 'dns_names' in item:
                domains.extend(item['dns_names'])
        
        return domains
    
    def fetch_hackertarget(self, domain: str) -> List[str]:
        """Fetch domains from HackerTarget"""
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        text = self.fetch_text(url)
        
        if not text:
            return []
        
        domains = []
        for line in text.strip().split('\n'):
            parts = line.split(',', 1)
            if len(parts) == 2:
                domains.append(parts[0])
        
        return domains
    
    def fetch_threatcrowd(self, domain: str) -> List[str]:
        """Fetch domains from ThreatCrowd"""
        url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}"
        data = self.fetch_json(url)
        
        if not data or 'subdomains' not in data:
            return []
        
        return data['subdomains'] or []
    
    def fetch_facebook(self, domain: str) -> List[str]:
        """Fetch domains from Facebook CT API"""
        app_id = os.getenv('FB_APP_ID')
        app_secret = os.getenv('FB_APP_SECRET')
        
        if not app_id or not app_secret:
            return []
        
        # Get access token
        auth_url = f"https://graph.facebook.com/oauth/access_token?client_id={app_id}&client_secret={app_secret}&grant_type=client_credentials"
        auth_data = self.fetch_json(auth_url)
        
        if not auth_data or 'access_token' not in auth_data:
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
        
        return domains
    
    def fetch_virustotal(self, domain: str) -> List[str]:
        """Fetch domains from VirusTotal"""
        api_key = os.getenv('VT_API_KEY')
        
        if not api_key:
            return []
        
        url = f"https://www.virustotal.com/vtapi/v2/domain/report?domain={domain}&apikey={api_key}"
        data = self.fetch_json(url)
        
        if not data or 'subdomains' not in data:
            return []
        
        return data['subdomains'] or []
    
    def fetch_findsubdomains(self, domain: str) -> List[str]:
        """Fetch domains from Spyse (FindSubDomains)"""
        api_token = os.getenv('SPYSE_API_TOKEN')
        
        if not api_token:
            return []
        
        domains = []
        
        # Try subdomains-aggregate endpoint
        url = f"https://api.spyse.com/v1/subdomains-aggregate?api_token={api_token}&domain={domain}"
        data = self.fetch_json(url)
        
        if data and 'cidr' in data:
            for cidr_type in ['cidr16', 'cidr24']:
                if cidr_type in data['cidr'] and 'results' in data['cidr'][cidr_type]:
                    for result in data['cidr'][cidr_type]['results']:
                        if 'data' in result and 'domains' in result['data']:
                            domains.extend(result['data']['domains'])
        
        # Try subdomains endpoint
        page = 1
        while True:
            url = f"https://api.spyse.com/v1/subdomains?api_token={api_token}&domain={domain}&page={page}"
            data = self.fetch_json(url)
            
            if not data or 'records' not in data or not data['records']:
                break
            
            for record in data['records']:
                if 'domain' in record:
                    domains.append(record['domain'])
            
            page += 1
        
        return domains
    
    def fetch_urlscan(self, domain: str) -> List[str]:
        """Fetch domains from URLScan.io"""
        url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}"
        data = self.fetch_json(url)
        
        if not data or 'results' not in data:
            return []
        
        domains = []
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
        
        return domains
    
    def fetch_bufferoverrun(self, domain: str) -> List[str]:
        """Fetch domains from BufferOver.run"""
        url = f"https://dns.bufferover.run/dns?q=.{domain}"
        data = self.fetch_json(url)
        
        if not data or 'FDNS_A' not in data:
            return []
        
        domains = []
        for record in data['FDNS_A']:
            parts = record.split(',', 1)
            if len(parts) == 2:
                domains.append(parts[1])
        
        return domains
    
    def fetch_wayback(self, domain: str) -> List[str]:
        """Fetch domains from Wayback Machine"""
        url = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&collapse=urlkey"
        data = self.fetch_json(url)
        
        if not data or not isinstance(data, list):
            return []
        
        domains = []
        skip_first = True
        
        for item in data:
            if skip_first:
                skip_first = False
                continue
            
            if len(item) >= 3:
                try:
                    parsed = urlparse(item[2])
                    if parsed.hostname:
                        domains.append(parsed.hostname)
                except:
                    continue
        
        return domains
    
    def find_domains(self, domain: str) -> Set[str]:
        """Find all domains and subdomains for the given domain"""
        domain = domain.lower().strip()
        
        # List of fetch functions to run
        sources = [
            ("crt.sh", self.fetch_crtsh),
            ("certspotter", self.fetch_certspotter),
            ("hackertarget", self.fetch_hackertarget),
            ("threatcrowd", self.fetch_threatcrowd),
            ("facebook", self.fetch_facebook),
            ("virustotal", self.fetch_virustotal),
            ("findsubdomains", self.fetch_findsubdomains),
            ("urlscan", self.fetch_urlscan),
            ("bufferoverrun", self.fetch_bufferoverrun),
            # ("wayback", self.fetch_wayback),  # Commented out as it's slow
        ]
        
        # Run all sources in parallel using ThreadPoolExecutor
        all_domains = set()
        
        with ThreadPoolExecutor(max_workers=len(sources)) as executor:
            # Submit all tasks
            future_to_source = {
                executor.submit(source_func, domain): source_name 
                for source_name, source_func in sources
            }
            
            # Collect results as they complete
            for future in as_completed(future_to_source):
                source_name = future_to_source[future]
                try:
                    result = future.result()
                    if isinstance(result, list):
                        for d in result:
                            cleaned = self.clean_domain(d)
                            if cleaned:
                                # Filter subdomains only if requested
                                if self.subs_only and not cleaned.endswith(f'.{domain}') and cleaned != domain:
                                    continue
                                all_domains.add(cleaned)
                except Exception as e:
                    print(f"Error in {source_name}: {e}", file=sys.stderr)
        
        return all_domains


def main():
    parser = argparse.ArgumentParser(
        description='Find domains and subdomains related to a given domain',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python subfinder.py example.com
  python subfinder.py -u example.com
  python subfinder.py --subs-only example.com
  echo "example.com" | python subfinder.py
  
Environment Variables (Optional API Keys):
  FB_APP_ID, FB_APP_SECRET - Facebook API credentials
    Get from: https://developers.facebook.com/
  VT_API_KEY - VirusTotal API key
    Get from: https://developers.virustotal.com/reference
  SPYSE_API_TOKEN - Spyse API token
    Get from: https://spyse.com/apidocs
        """
    )
    
    parser.add_argument('domain', nargs='?', help='Domain to search for')
    parser.add_argument('-u', '--url', help='Domain to search for (alternative to positional argument)')
    parser.add_argument('--subs-only', action='store_true',
                       help='Only include subdomains of search domain')
    
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
    finder = AssetFinder(subs_only=args.subs_only)
    
    for domain in domains:
        found_domains = finder.find_domains(domain)
        
        # Print results
        for d in sorted(found_domains):
            print(d)
    
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