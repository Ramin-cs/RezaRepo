#!/usr/bin/env python3
"""
AssetFinder Python Implementation
Find domains and subdomains potentially related to a given domain.

This is a Python port of tomnomnom's assetfinder tool.
Original: https://github.com/tomnomnom/assetfinder
"""

import argparse
import asyncio
import json
import os
import re
import sys
import time
from typing import List, Set, Optional
from urllib.parse import urlparse
import aiohttp
import requests


class RateLimiter:
    """Rate limiter to control API request frequency"""
    
    def __init__(self, delay: float = 1.0):
        self.delay = delay
        self.ops = {}
    
    async def block(self, key: str):
        """Block until an operation for key is allowed to proceed"""
        now = time.time()
        
        if key not in self.ops:
            self.ops[key] = now
            return
        
        last_op = self.ops[key]
        deadline = last_op + self.delay
        
        if now >= deadline:
            self.ops[key] = now
            return
        
        remaining = deadline - now
        self.ops[key] = now + remaining
        await asyncio.sleep(remaining)


class AssetFinder:
    """Main AssetFinder class"""
    
    def __init__(self, subs_only: bool = False):
        self.subs_only = subs_only
        self.rate_limiter = RateLimiter(1.0)  # 1 second delay
        self.session = None
        
    async def __aenter__(self):
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=30),
            connector=aiohttp.TCPConnector(limit=100)
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
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
    
    async def fetch_json(self, url: str) -> Optional[dict]:
        """Fetch JSON data from URL"""
        try:
            async with self.session.get(url) as response:
                if response.status == 200:
                    return await response.json()
        except Exception as e:
            print(f"Error fetching {url}: {e}", file=sys.stderr)
        return None
    
    async def fetch_text(self, url: str) -> Optional[str]:
        """Fetch text data from URL"""
        try:
            async with self.session.get(url) as response:
                if response.status == 200:
                    return await response.text()
        except Exception as e:
            print(f"Error fetching {url}: {e}", file=sys.stderr)
        return None
    
    async def fetch_crtsh(self, domain: str) -> List[str]:
        """Fetch domains from crt.sh"""
        await self.rate_limiter.block("crtsh")
        
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        data = await self.fetch_json(url)
        
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
    
    async def fetch_certspotter(self, domain: str) -> List[str]:
        """Fetch domains from CertSpotter"""
        await self.rate_limiter.block("certspotter")
        
        url = f"https://certspotter.com/api/v0/certs?domain={domain}"
        data = await self.fetch_json(url)
        
        if not data:
            return []
        
        domains = []
        for item in data:
            if 'dns_names' in item:
                domains.extend(item['dns_names'])
        
        return domains
    
    async def fetch_hackertarget(self, domain: str) -> List[str]:
        """Fetch domains from HackerTarget"""
        await self.rate_limiter.block("hackertarget")
        
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        text = await self.fetch_text(url)
        
        if not text:
            return []
        
        domains = []
        for line in text.strip().split('\n'):
            parts = line.split(',', 1)
            if len(parts) == 2:
                domains.append(parts[0])
        
        return domains
    
    async def fetch_threatcrowd(self, domain: str) -> List[str]:
        """Fetch domains from ThreatCrowd"""
        await self.rate_limiter.block("threatcrowd")
        
        url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}"
        data = await self.fetch_json(url)
        
        if not data or 'subdomains' not in data:
            return []
        
        return data['subdomains'] or []
    
    async def fetch_facebook(self, domain: str) -> List[str]:
        """Fetch domains from Facebook CT API"""
        app_id = os.getenv('FB_APP_ID')
        app_secret = os.getenv('FB_APP_SECRET')
        
        if not app_id or not app_secret:
            return []
        
        await self.rate_limiter.block("facebook")
        
        # Get access token
        auth_url = f"https://graph.facebook.com/oauth/access_token?client_id={app_id}&client_secret={app_secret}&grant_type=client_credentials"
        auth_data = await self.fetch_json(auth_url)
        
        if not auth_data or 'access_token' not in auth_data:
            return []
        
        access_token = auth_data['access_token']
        
        # Fetch certificates
        domains = []
        url = f"https://graph.facebook.com/certificates?fields=domains&access_token={access_token}&query=*.{domain}"
        
        while url:
            data = await self.fetch_json(url)
            if not data:
                break
            
            if 'data' in data:
                for item in data['data']:
                    if 'domains' in item:
                        domains.extend(item['domains'])
            
            # Check for pagination
            url = data.get('paging', {}).get('next')
        
        return domains
    
    async def fetch_virustotal(self, domain: str) -> List[str]:
        """Fetch domains from VirusTotal"""
        api_key = os.getenv('VT_API_KEY')
        
        if not api_key:
            return []
        
        await self.rate_limiter.block("virustotal")
        
        url = f"https://www.virustotal.com/vtapi/v2/domain/report?domain={domain}&apikey={api_key}"
        data = await self.fetch_json(url)
        
        if not data or 'subdomains' not in data:
            return []
        
        return data['subdomains'] or []
    
    async def fetch_findsubdomains(self, domain: str) -> List[str]:
        """Fetch domains from Spyse (FindSubDomains)"""
        api_token = os.getenv('SPYSE_API_TOKEN')
        
        if not api_token:
            return []
        
        await self.rate_limiter.block("findsubdomains")
        
        domains = []
        
        # Try subdomains-aggregate endpoint
        url = f"https://api.spyse.com/v1/subdomains-aggregate?api_token={api_token}&domain={domain}"
        data = await self.fetch_json(url)
        
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
            data = await self.fetch_json(url)
            
            if not data or 'records' not in data or not data['records']:
                break
            
            for record in data['records']:
                if 'domain' in record:
                    domains.append(record['domain'])
            
            page += 1
        
        return domains
    
    async def fetch_urlscan(self, domain: str) -> List[str]:
        """Fetch domains from URLScan.io"""
        await self.rate_limiter.block("urlscan")
        
        url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}"
        data = await self.fetch_json(url)
        
        if not data or 'results' not in data:
            return []
        
        domains = []
        for result in data['results']:
            # Extract from task URL
            if 'task' in result and 'url' in result['task']:
                parsed = urlparse(result['task']['url'])
                if parsed.hostname:
                    domains.append(parsed.hostname)
            
            # Extract from page URL
            if 'page' in result and 'url' in result['page']:
                parsed = urlparse(result['page']['url'])
                if parsed.hostname:
                    domains.append(parsed.hostname)
        
        return domains
    
    async def fetch_bufferoverrun(self, domain: str) -> List[str]:
        """Fetch domains from BufferOver.run"""
        await self.rate_limiter.block("bufferoverrun")
        
        url = f"https://dns.bufferover.run/dns?q=.{domain}"
        data = await self.fetch_json(url)
        
        if not data or 'FDNS_A' not in data:
            return []
        
        domains = []
        for record in data['FDNS_A']:
            parts = record.split(',', 1)
            if len(parts) == 2:
                domains.append(parts[1])
        
        return domains
    
    async def fetch_wayback(self, domain: str) -> List[str]:
        """Fetch domains from Wayback Machine"""
        await self.rate_limiter.block("wayback")
        
        url = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&collapse=urlkey"
        data = await self.fetch_json(url)
        
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
    
    async def find_domains(self, domain: str) -> Set[str]:
        """Find all domains and subdomains for the given domain"""
        domain = domain.lower().strip()
        
        # List of fetch functions to run
        sources = [
            self.fetch_crtsh,
            self.fetch_certspotter,
            self.fetch_hackertarget,
            self.fetch_threatcrowd,
            self.fetch_facebook,
            self.fetch_virustotal,
            self.fetch_findsubdomains,
            self.fetch_urlscan,
            self.fetch_bufferoverrun,
            # self.fetch_wayback,  # Commented out as it's slow
        ]
        
        # Run all sources concurrently
        tasks = [source(domain) for source in sources]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Collect all domains
        all_domains = set()
        
        for result in results:
            if isinstance(result, list):
                for d in result:
                    cleaned = self.clean_domain(d)
                    if cleaned:
                        # Filter subdomains only if requested
                        if self.subs_only and not cleaned.endswith(f'.{domain}') and cleaned != domain:
                            continue
                        all_domains.add(cleaned)
        
        return all_domains


async def main():
    parser = argparse.ArgumentParser(
        description='Find domains and subdomains related to a given domain',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python subfinder.py example.com
  python subfinder.py --subs-only example.com
  echo "example.com" | python subfinder.py
  
Environment Variables:
  FB_APP_ID, FB_APP_SECRET - Facebook API credentials
  VT_API_KEY - VirusTotal API key
  SPYSE_API_TOKEN - Spyse API token
        """
    )
    
    parser.add_argument('domain', nargs='?', help='Domain to search for')
    parser.add_argument('--subs-only', action='store_true',
                       help='Only include subdomains of search domain')
    
    args = parser.parse_args()
    
    # Get domain from argument or stdin
    if args.domain:
        domains = [args.domain]
    else:
        domains = [line.strip() for line in sys.stdin if line.strip()]
    
    if not domains:
        parser.print_help()
        return 1
    
    # Process each domain
    async with AssetFinder(subs_only=args.subs_only) as finder:
        for domain in domains:
            found_domains = await finder.find_domains(domain)
            
            # Print results
            for d in sorted(found_domains):
                print(d)
    
    return 0


if __name__ == '__main__':
    try:
        exit_code = asyncio.run(main())
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\nInterrupted by user", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)