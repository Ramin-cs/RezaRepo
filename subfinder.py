#!/usr/bin/env python3
"""
Subfinder Python Implementation - Complete Version
Find domains and subdomains potentially related to a given domain.

This is a Python port of ProjectDiscovery's subfinder tool.
Original: https://github.com/projectdiscovery/subfinder

=== API Configuration ===
Set these environment variables for better results:

# Free APIs (No registration required)
- No API key needed for: crt.sh, hackertarget, wayback, anubis, alienvault

# APIs requiring registration:
- BEVIGIL_API_KEY: https://bevigil.com/osint-api
- BINARYEDGE_API_KEY: https://www.binaryedge.io/
- BUFFEROVER_API_KEY: https://tls.bufferover.run/
- BUILTWITH_API_KEY: https://builtwith.com/api
- C99_API_KEY: https://api.c99.nl/
- CENSYS_API_ID, CENSYS_SECRET: https://censys.io/api
- CERTSPOTTER_API_KEY: https://sslmate.com/certspotter/api/
- CHAOS_API_KEY: https://chaos.projectdiscovery.io/
- CHINAZ_API_KEY: http://api.chinaz.com/
- DNSDB_API_KEY: https://www.farsightsecurity.com/dnsdb/
- DNSREPO_API_KEY: https://dnsrepo.noc.org/
- FACEBOOK_APP_ID, FACEBOOK_APP_SECRET: https://developers.facebook.com/
- FOFA_EMAIL, FOFA_KEY: https://fofa.so/api
- FULLHUNT_API_KEY: https://fullhunt.io/
- GITHUB_TOKEN: https://github.com/settings/tokens
- HUNTER_API_KEY: https://hunter.io/api
- INTELX_API_KEY: https://intelx.io/
- LEAKIX_API_KEY: https://leakix.net/
- NETLAS_API_KEY: https://netlas.io/
- PASSIVETOTAL_USERNAME, PASSIVETOTAL_KEY: https://www.riskiq.com/
- QUAKE_TOKEN: https://quake.360.cn/
- REDHUNTLABS_API_KEY: https://redhuntlabs.com/
- ROBTEX_API_KEY: https://www.robtex.com/api/
- SECURITYTRAILS_API_KEY: https://securitytrails.com/
- SHODAN_API_KEY: https://www.shodan.io/
- THREATBOOK_API_KEY: https://threatbook.cn/
- VIRUSTOTAL_API_KEY: https://developers.virustotal.com/reference
- WHOISXMLAPI_API_KEY: https://whoisxmlapi.com/
- ZOOMEYE_API_KEY: https://www.zoomeye.org/api
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


class SubfinderConfig:
    """Configuration class for API keys"""
    
    def __init__(self):
        self.apis = {
            # Free APIs
            'crtsh': {'enabled': True},
            'hackertarget': {'enabled': True},
            'wayback': {'enabled': True},
            'anubis': {'enabled': True},
            'alienvault': {'enabled': True},
            
            # APIs with keys
            'bevigil': {'api_key': os.getenv('BEVIGIL_API_KEY')},
            'binaryedge': {'api_key': os.getenv('BINARYEDGE_API_KEY')},
            'bufferover': {'api_key': os.getenv('BUFFEROVER_API_KEY')},
            'builtwith': {'api_key': os.getenv('BUILTWITH_API_KEY')},
            'c99': {'api_key': os.getenv('C99_API_KEY')},
            'censys': {
                'api_id': os.getenv('CENSYS_API_ID'),
                'secret': os.getenv('CENSYS_SECRET')
            },
            'certspotter': {'api_key': os.getenv('CERTSPOTTER_API_KEY')},
            'chaos': {'api_key': os.getenv('CHAOS_API_KEY')},
            'chinaz': {'api_key': os.getenv('CHINAZ_API_KEY')},
            'dnsdb': {'api_key': os.getenv('DNSDB_API_KEY')},
            'dnsrepo': {'api_key': os.getenv('DNSREPO_API_KEY')},
            'facebook': {
                'app_id': os.getenv('FACEBOOK_APP_ID'),
                'app_secret': os.getenv('FACEBOOK_APP_SECRET')
            },
            'fofa': {
                'email': os.getenv('FOFA_EMAIL'),
                'key': os.getenv('FOFA_KEY')
            },
            'fullhunt': {'api_key': os.getenv('FULLHUNT_API_KEY')},
            'github': {'token': os.getenv('GITHUB_TOKEN')},
            'hunter': {'api_key': os.getenv('HUNTER_API_KEY')},
            'intelx': {'api_key': os.getenv('INTELX_API_KEY')},
            'leakix': {'api_key': os.getenv('LEAKIX_API_KEY')},
            'netlas': {'api_key': os.getenv('NETLAS_API_KEY')},
            'passivetotal': {
                'username': os.getenv('PASSIVETOTAL_USERNAME'),
                'key': os.getenv('PASSIVETOTAL_KEY')
            },
            'quake': {'token': os.getenv('QUAKE_TOKEN')},
            'redhuntlabs': {'api_key': os.getenv('REDHUNTLABS_API_KEY')},
            'robtex': {'api_key': os.getenv('ROBTEX_API_KEY')},
            'securitytrails': {'api_key': os.getenv('SECURITYTRAILS_API_KEY')},
            'shodan': {'api_key': os.getenv('SHODAN_API_KEY')},
            'threatbook': {'api_key': os.getenv('THREATBOOK_API_KEY')},
            'virustotal': {'api_key': os.getenv('VIRUSTOTAL_API_KEY')},
            'whoisxmlapi': {'api_key': os.getenv('WHOISXMLAPI_API_KEY')},
            'zoomeye': {'api_key': os.getenv('ZOOMEYE_API_KEY')},
        }
    
    def is_enabled(self, source: str) -> bool:
        """Check if a source is enabled (has required credentials or is free)"""
        if source not in self.apis:
            return False
        
        config = self.apis[source]
        
        # Free APIs
        if 'enabled' in config:
            return config['enabled']
        
        # APIs requiring single key
        if 'api_key' in config:
            return bool(config['api_key'])
        
        if 'token' in config:
            return bool(config['token'])
        
        # APIs requiring multiple keys
        if source == 'censys':
            return bool(config['api_id'] and config['secret'])
        
        if source == 'facebook':
            return bool(config['app_id'] and config['app_secret'])
        
        if source == 'fofa':
            return bool(config['email'] and config['key'])
        
        if source == 'passivetotal':
            return bool(config['username'] and config['key'])
        
        return False
    
    def get_config(self, source: str) -> Dict[str, Any]:
        """Get configuration for a source"""
        return self.apis.get(source, {})


class Subfinder:
    """Main Subfinder class"""
    
    def __init__(self, subs_only: bool = False, silent: bool = False):
        self.subs_only = subs_only
        self.silent = silent
        self.timeout = 30
        self.config = SubfinderConfig()
        
        # Create SSL context that doesn't verify certificates for problematic sites
        self.ssl_context = ssl.create_default_context()
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_NONE
        
    def log_error(self, message: str):
        """Log error message if not in silent mode"""
        if not self.silent:
            print(f"[ERROR] {message}", file=sys.stderr)
    
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
        except Exception as e:
            # Silently ignore errors to avoid spam
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
        except Exception as e:
            # Silently ignore errors
            pass
        return None
    
    # Free Sources
    def fetch_crtsh(self, domain: str) -> List[str]:
        """Fetch domains from crt.sh"""
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        data = self.fetch_json(url)
        
        if not data:
            return []
        
        domains = []
        for item in data:
            if 'name_value' in item:
                names = item['name_value'].split('\n')
                for name in names:
                    name = name.strip()
                    if name:
                        domains.append(name)
        
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
    
    def fetch_anubis(self, domain: str) -> List[str]:
        """Fetch domains from Anubis"""
        url = f"https://jldc.me/anubis/subdomains/{domain}"
        data = self.fetch_json(url)
        
        if not data or not isinstance(data, list):
            return []
        
        return data
    
    def fetch_alienvault(self, domain: str) -> List[str]:
        """Fetch domains from AlienVault OTX"""
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
        data = self.fetch_json(url)
        
        if not data or 'passive_dns' not in data:
            return []
        
        domains = []
        for item in data['passive_dns']:
            if 'hostname' in item:
                domains.append(item['hostname'])
        
        return domains
    
    # API-based sources
    def fetch_bevigil(self, domain: str) -> List[str]:
        """Fetch domains from BeVigil"""
        config = self.config.get_config('bevigil')
        if not config.get('api_key'):
            return []
        
        url = f"https://osint.bevigil.com/api/{domain}/subdomains/"
        headers = {'X-Access-Token': config['api_key']}
        data = self.fetch_json(url, headers)
        
        if not data or 'subdomains' not in data:
            return []
        
        return data['subdomains']
    
    def fetch_binaryedge(self, domain: str) -> List[str]:
        """Fetch domains from BinaryEdge"""
        config = self.config.get_config('binaryedge')
        if not config.get('api_key'):
            return []
        
        url = f"https://api.binaryedge.io/v2/query/domains/subdomain/{domain}"
        headers = {'X-Key': config['api_key']}
        data = self.fetch_json(url, headers)
        
        if not data or 'events' not in data:
            return []
        
        return data['events']
    
    def fetch_bufferover(self, domain: str) -> List[str]:
        """Fetch domains from BufferOver"""
        config = self.config.get_config('bufferover')
        headers = {}
        if config.get('api_key'):
            headers['x-api-key'] = config['api_key']
        
        url = f"https://dns.bufferover.run/dns?q=.{domain}"
        data = self.fetch_json(url, headers)
        
        if not data or 'FDNS_A' not in data:
            return []
        
        domains = []
        for record in data['FDNS_A']:
            parts = record.split(',', 1)
            if len(parts) == 2:
                domains.append(parts[1])
        
        return domains
    
    def fetch_builtwith(self, domain: str) -> List[str]:
        """Fetch domains from BuiltWith"""
        config = self.config.get_config('builtwith')
        if not config.get('api_key'):
            return []
        
        url = f"https://api.builtwith.com/free1/api.json?KEY={config['api_key']}&LOOKUP={domain}"
        data = self.fetch_json(url)
        
        if not data or 'Results' not in data:
            return []
        
        domains = []
        for result in data['Results']:
            if 'Result' in result and 'Paths' in result['Result']:
                for path in result['Result']['Paths']:
                    if 'Domain' in path:
                        domains.append(path['Domain'])
        
        return domains
    
    def fetch_c99(self, domain: str) -> List[str]:
        """Fetch domains from C99"""
        config = self.config.get_config('c99')
        if not config.get('api_key'):
            return []
        
        url = f"https://api.c99.nl/subdomainfinder?key={config['api_key']}&domain={domain}&json"
        data = self.fetch_json(url)
        
        if not data or 'subdomains' not in data:
            return []
        
        domains = []
        for subdomain in data['subdomains']:
            if 'subdomain' in subdomain:
                domains.append(subdomain['subdomain'])
        
        return domains
    
    def fetch_censys(self, domain: str) -> List[str]:
        """Fetch domains from Censys"""
        config = self.config.get_config('censys')
        if not (config.get('api_id') and config.get('secret')):
            return []
        
        # Create basic auth header
        credentials = f"{config['api_id']}:{config['secret']}"
        encoded_credentials = base64.b64encode(credentials.encode()).decode()
        headers = {'Authorization': f'Basic {encoded_credentials}'}
        
        url = f"https://search.censys.io/api/v2/certificates/search?q=names:{domain}"
        data = self.fetch_json(url, headers)
        
        if not data or 'result' not in data or 'hits' not in data['result']:
            return []
        
        domains = []
        for hit in data['result']['hits']:
            if 'names' in hit:
                domains.extend(hit['names'])
        
        return domains
    
    def fetch_certspotter(self, domain: str) -> List[str]:
        """Fetch domains from CertSpotter"""
        config = self.config.get_config('certspotter')
        headers = {}
        if config.get('api_key'):
            headers['Authorization'] = f'Bearer {config["api_key"]}'
        
        url = f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
        data = self.fetch_json(url, headers)
        
        if not data:
            return []
        
        domains = []
        for item in data:
            if 'dns_names' in item:
                domains.extend(item['dns_names'])
        
        return domains
    
    def fetch_chaos(self, domain: str) -> List[str]:
        """Fetch domains from Chaos"""
        config = self.config.get_config('chaos')
        if not config.get('api_key'):
            return []
        
        headers = {'Authorization': config['api_key']}
        url = f"https://dns.projectdiscovery.io/dns/{domain}/subdomains"
        data = self.fetch_json(url, headers)
        
        if not data or 'subdomains' not in data:
            return []
        
        return data['subdomains']
    
    def fetch_shodan(self, domain: str) -> List[str]:
        """Fetch domains from Shodan"""
        config = self.config.get_config('shodan')
        if not config.get('api_key'):
            return []
        
        url = f"https://api.shodan.io/dns/domain/{domain}?key={config['api_key']}"
        data = self.fetch_json(url)
        
        if not data or 'subdomains' not in data:
            return []
        
        return [f"{sub}.{domain}" for sub in data['subdomains']]
    
    def fetch_virustotal(self, domain: str) -> List[str]:
        """Fetch domains from VirusTotal"""
        config = self.config.get_config('virustotal')
        if not config.get('api_key'):
            return []
        
        headers = {'x-apikey': config['api_key']}
        url = f"https://www.virustotal.com/vtapi/v2/domain/report?domain={domain}"
        data = self.fetch_json(url, headers)
        
        if not data or 'subdomains' not in data:
            return []
        
        return data['subdomains']
    
    def fetch_securitytrails(self, domain: str) -> List[str]:
        """Fetch domains from SecurityTrails"""
        config = self.config.get_config('securitytrails')
        if not config.get('api_key'):
            return []
        
        headers = {'APIKEY': config['api_key']}
        url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
        data = self.fetch_json(url, headers)
        
        if not data or 'subdomains' not in data:
            return []
        
        return [f"{sub}.{domain}" for sub in data['subdomains']]
    
    def find_domains(self, domain: str) -> Set[str]:
        """Find all domains and subdomains for the given domain"""
        domain = domain.lower().strip()
        
        # List of all available sources
        sources = [
            # Free sources
            ('crtsh', self.fetch_crtsh),
            ('hackertarget', self.fetch_hackertarget),
            ('wayback', self.fetch_wayback),
            ('anubis', self.fetch_anubis),
            ('alienvault', self.fetch_alienvault),
            
            # API sources
            ('bevigil', self.fetch_bevigil),
            ('binaryedge', self.fetch_binaryedge),
            ('bufferover', self.fetch_bufferover),
            ('builtwith', self.fetch_builtwith),
            ('c99', self.fetch_c99),
            ('censys', self.fetch_censys),
            ('certspotter', self.fetch_certspotter),
            ('chaos', self.fetch_chaos),
            ('shodan', self.fetch_shodan),
            ('virustotal', self.fetch_virustotal),
            ('securitytrails', self.fetch_securitytrails),
        ]
        
        # Filter enabled sources
        enabled_sources = [
            (name, func) for name, func in sources 
            if self.config.is_enabled(name)
        ]
        
        if not self.silent:
            print(f"[INFO] Using {len(enabled_sources)} sources", file=sys.stderr)
        
        # Run all sources in parallel
        all_domains = set()
        
        with ThreadPoolExecutor(max_workers=min(len(enabled_sources), 20)) as executor:
            future_to_source = {
                executor.submit(source_func, domain): source_name 
                for source_name, source_func in enabled_sources
            }
            
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
                    if not self.silent:
                        self.log_error(f"Error in {source_name}: {e}")
        
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
  
Environment Variables:
  See the header of this script for all available API keys
        """
    )
    
    parser.add_argument('domain', nargs='?', help='Domain to search for')
    parser.add_argument('-u', '--url', help='Domain to search for (alternative to positional argument)')
    parser.add_argument('--subs-only', action='store_true',
                       help='Only include subdomains of search domain')
    parser.add_argument('--silent', action='store_true',
                       help='Show only results in output')
    
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
    finder = Subfinder(subs_only=args.subs_only, silent=args.silent)
    
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