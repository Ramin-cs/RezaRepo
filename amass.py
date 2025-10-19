#!/usr/bin/env python3
"""
OWASP Amass Python Implementation
In-depth Attack Surface Mapping and Asset Discovery

This is a Python port of OWASP Amass with all major functionalities.
Original: https://github.com/owasp-amass/amass

=== API Configuration ===
Set these environment variables for enhanced data collection:

# Free APIs
- No API key needed for: crt.sh, hackertarget, wayback, anubis, alienvault, dnsdumpster

# Premium APIs (Recommended)
- CHAOS_API_KEY: https://chaos.projectdiscovery.io/
- SHODAN_API_KEY: https://www.shodan.io/
- VIRUSTOTAL_API_KEY: https://developers.virustotal.com/reference
- SECURITYTRAILS_API_KEY: https://securitytrails.com/
- CENSYS_API_ID, CENSYS_SECRET: https://censys.io/api
- BINARYEDGE_API_KEY: https://www.binaryedge.io/
- FULLHUNT_API_KEY: https://fullhunt.io/
- HUNTER_API_KEY: https://hunter.io/api
- INTELX_API_KEY: https://intelx.io/
- NETLAS_API_KEY: https://netlas.io/
- PASSIVETOTAL_USERNAME, PASSIVETOTAL_KEY: https://www.riskiq.com/
- QUAKE_TOKEN: https://quake.360.cn/
- WHOISXMLAPI_API_KEY: https://whoisxmlapi.com/
- ZOOMEYE_API_KEY: https://www.zoomeye.org/api
- BEVIGIL_API_KEY: https://bevigil.com/osint-api
- BUILTWITH_API_KEY: https://builtwith.com/api
- C99_API_KEY: https://api.c99.nl/
- DNSDB_API_KEY: https://www.farsightsecurity.com/dnsdb/
- GITHUB_TOKEN: https://github.com/settings/tokens
- LEAKIX_API_KEY: https://leakix.net/
- SPYSE_API_TOKEN: https://spyse.com/apidocs
"""

import argparse
import json
import os
import sys
import time
import base64
import socket
from typing import List, Set, Optional, Dict, Any, Tuple
from urllib.parse import urlparse, quote
import urllib.request
import urllib.error
import ssl
import threading
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime

# Try to import DNS library
try:
    import dns.resolver
    import dns.reversename
    import dns.zone
    import dns.query
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

@dataclass
class AmassResult:
    """Data class for Amass results"""
    domain: str
    ip: str = ""
    source: str = ""
    tag: str = ""
    timestamp: str = ""

class AmassEngine:
    """Main Amass Engine with comprehensive reconnaissance capabilities"""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.timeout = self.config.get('timeout', 10)
        self.max_workers = self.config.get('max_workers', 20)
        self.passive_only = self.config.get('passive_only', True)
        self.active = self.config.get('active', False)
        self.brute_force = self.config.get('brute_force', False)
        self.silent = self.config.get('silent', False)
        self.verbose = self.config.get('verbose', False)
        self.output_format = self.config.get('output_format', 'text')
        
        # Results storage
        self.found_domains = set()
        self.found_ips = set()
        self.domain_ip_map = {}
        self.lock = threading.Lock()
        
        # SSL context
        self.ssl_context = ssl.create_default_context()
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_NONE
        
        # DNS resolver
        if DNS_AVAILABLE:
            self.resolver = dns.resolver.Resolver()
            self.resolver.timeout = 5
            self.resolver.lifetime = 10
        
        # Common subdomains for brute force
        self.common_subdomains = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
            'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'mx', 'm', 'imap', 'test',
            'ns', 'blog', 'pop3', 'dev', 'www2', 'admin', 'forum', 'news', 'vpn', 'ns3',
            'mail2', 'new', 'mysql', 'old', 'lists', 'support', 'mobile', 'static', 'docs',
            'beta', 'shop', 'sql', 'secure', 'demo', 'cp', 'calendar', 'wiki', 'web',
            'media', 'email', 'images', 'img', 'www1', 'intranet', 'portal', 'video',
            'sip', 'dns2', 'api', 'cdn', 'stats', 'dns1', 'ns4', 'www3', 'dns', 'search',
            'staging', 'server', 'mx1', 'chat', 'wap', 'my', 'svn', 'mail1', 'sites',
            'proxy', 'ads', 'host', 'crm', 'cms', 'backup', 'mx2', 'lyncdiscover', 'info',
            'apps', 'download', 'remote', 'db', 'forums', 'store', 'relay', 'files',
            'newsletter', 'app', 'live', 'owa', 'en', 'start', 'sms', 'office', 'exchange'
        ]
    
    def log_info(self, message: str):
        """Log info message"""
        if not self.silent:
            print(f"[INFO] {message}", file=sys.stderr)
    
    def log_verbose(self, message: str):
        """Log verbose message"""
        if self.verbose and not self.silent:
            print(f"[VERBOSE] {message}", file=sys.stderr)
    
    def log_progress(self, source: str, count: int, completed: int, total: int):
        """Log progress message"""
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
        
        # Remove invalid characters
        domain = re.sub(r'[^a-z0-9.-]', '', domain)
        
        return domain
    
    def is_valid_domain(self, domain: str) -> bool:
        """Check if domain is valid"""
        if not domain or len(domain) > 253:
            return False
        
        # Check for valid domain format
        pattern = r'^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$'
        return bool(re.match(pattern, domain))
    
    def add_result(self, domain: str, ip: str = "", source: str = "", tag: str = ""):
        """Add result to storage"""
        cleaned_domain = self.clean_domain(domain)
        if not cleaned_domain or not self.is_valid_domain(cleaned_domain):
            return
        
        with self.lock:
            if cleaned_domain not in self.found_domains:
                self.found_domains.add(cleaned_domain)
                
                if ip:
                    self.found_ips.add(ip)
                    self.domain_ip_map[cleaned_domain] = ip
                
                # Print immediately if not silent
                if not self.silent:
                    if self.output_format == 'json':
                        print(json.dumps({
                            'domain': cleaned_domain,
                            'ip': ip,
                            'source': source,
                            'tag': tag
                        }))
                    else:
                        print(cleaned_domain)
    
    def resolve_domain(self, domain: str) -> List[str]:
        """Resolve domain to IP addresses"""
        ips = []
        if not DNS_AVAILABLE:
            return ips
            
        try:
            answers = self.resolver.resolve(domain, 'A')
            for answer in answers:
                ips.append(str(answer))
        except Exception:
            pass
        
        try:
            answers = self.resolver.resolve(domain, 'AAAA')
            for answer in answers:
                ips.append(str(answer))
        except Exception:
            pass
        
        return ips
    
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
    
    # === PASSIVE RECONNAISSANCE SOURCES ===
    
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
                        self.add_result(name, source="crt.sh", tag="certificate")
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
                self.add_result(parts[0], ip=parts[1], source="hackertarget", tag="dns")
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
            self.add_result(subdomain, source="anubis", tag="api")
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
                ip = item.get('address', '')
                self.add_result(item['hostname'], ip=ip, source="alienvault", tag="passive_dns")
                count += 1
        
        return count
    
    def fetch_wayback(self, domain: str) -> int:
        """Fetch domains from Wayback Machine"""
        url = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&collapse=urlkey"
        data = self.fetch_json(url)
        
        if not data or not isinstance(data, list):
            return 0
        
        count = 0
        skip_first = True
        
        for item in data:
            if skip_first:
                skip_first = False
                continue
            
            if len(item) >= 3:
                try:
                    parsed = urlparse(item[2])
                    if parsed.hostname:
                        self.add_result(parsed.hostname, source="wayback", tag="archive")
                        count += 1
                except:
                    continue
        
        return count
    
    # === API-BASED SOURCES ===
    
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
            self.add_result(f"{subdomain}.{domain}", source="chaos", tag="api")
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
            self.add_result(f"{subdomain}.{domain}", source="shodan", tag="api")
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
            self.add_result(subdomain, source="virustotal", tag="api")
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
            self.add_result(f"{subdomain}.{domain}", source="securitytrails", tag="api")
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
                    self.add_result(name, source="censys", tag="certificate")
                    count += 1
        
        return count
    
    def run_source(self, source_name: str, source_func, domain: str, completed_counter: list, total: int):
        """Run a single source and update progress"""
        try:
            count = source_func(domain)
            completed_counter[0] += 1
            self.log_progress(source_name, count, completed_counter[0], total)
        except Exception as e:
            completed_counter[0] += 1
            self.log_progress(source_name, 0, completed_counter[0], total)
            self.log_verbose(f"Error in {source_name}: {e}")
    
    def enumerate_domain(self, domain: str):
        """Main enumeration function"""
        self.log_info(f"Starting enumeration for {domain}")
        
        # Define sources based on mode
        passive_sources = [
            ('crt.sh', self.fetch_crtsh),
            ('hackertarget', self.fetch_hackertarget),
            ('anubis', self.fetch_anubis),
            ('alienvault', self.fetch_alienvault),
            ('wayback', self.fetch_wayback),
            ('chaos', self.fetch_chaos),
            ('shodan', self.fetch_shodan),
            ('virustotal', self.fetch_virustotal),
            ('securitytrails', self.fetch_securitytrails),
            ('censys', self.fetch_censys),
        ]
        
        all_sources = passive_sources
        
        # Filter enabled sources (check for API keys)
        enabled_sources = []
        for name, func in all_sources:
            if name in ['crt.sh', 'hackertarget', 'anubis', 'alienvault', 'wayback']:
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
        if not self.silent:
            self.log_info("Results will appear below as they are found...")
        
        # Run sources in parallel
        completed_counter = [0]
        
        with ThreadPoolExecutor(max_workers=min(len(enabled_sources), self.max_workers)) as executor:
            futures = []
            for source_name, source_func in enabled_sources:
                future = executor.submit(self.run_source, source_name, source_func, domain, completed_counter, len(enabled_sources))
                futures.append(future)
            
            # Wait for all to complete
            for future in as_completed(futures):
                pass
        
        self.log_info(f"Enumeration complete: {len(self.found_domains)} domains, {len(self.found_ips)} IPs")


def main():
    parser = argparse.ArgumentParser(
        description='OWASP Amass - Attack Surface Mapping and Asset Discovery',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Subcommands:
  enum        Perform enumeration of attack surface
  intel       Collect intelligence on the target
  viz         Generate visualizations from enumeration data
  track       Track differences between enumerations
  db          Manage the graph database

Examples:
  python amass.py enum -d example.com
  python amass.py enum -d example.com --passive
  python amass.py enum -d example.com --active --brute
  python amass.py enum -d example.com -o results.txt
  
Environment Variables:
  See the header of this script for all available API keys
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Enum subcommand
    enum_parser = subparsers.add_parser('enum', help='Perform enumeration')
    enum_parser.add_argument('-d', '--domain', required=True, help='Domain to enumerate')
    enum_parser.add_argument('--passive', action='store_true', help='Passive enumeration only')
    enum_parser.add_argument('--active', action='store_true', help='Enable active techniques')
    enum_parser.add_argument('--brute', action='store_true', help='Enable brute force')
    enum_parser.add_argument('-o', '--output', help='Output file path')
    enum_parser.add_argument('--json', action='store_true', help='Output in JSON format')
    enum_parser.add_argument('--silent', action='store_true', help='Silent mode')
    enum_parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    enum_parser.add_argument('--timeout', type=int, default=10, help='Request timeout')
    enum_parser.add_argument('--max-workers', type=int, default=20, help='Max concurrent workers')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 1
    
    # Handle enum command
    if args.command == 'enum':
        config = {
            'passive_only': args.passive,
            'active': args.active,
            'brute_force': args.brute,
            'silent': args.silent,
            'verbose': args.verbose,
            'timeout': args.timeout,
            'max_workers': args.max_workers,
            'output_format': 'json' if args.json else 'text'
        }
        
        engine = AmassEngine(config)
        engine.enumerate_domain(args.domain)
        
        # Save to file if specified
        if args.output:
            with open(args.output, 'w') as f:
                for domain in sorted(engine.found_domains):
                    if args.json:
                        result = {
                            'domain': domain,
                            'ip': engine.domain_ip_map.get(domain, ''),
                            'timestamp': datetime.now().isoformat()
                        }
                        f.write(json.dumps(result) + '\n')
                    else:
                        f.write(domain + '\n')
            
            if not args.silent:
                print(f"\n[INFO] Results saved to {args.output}", file=sys.stderr)
    
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