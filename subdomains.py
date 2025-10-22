#!/usr/bin/env python3
"""
Ultimate Subdomain Discovery Tool - Combined Power of All Major Tools
ابزار نهایی کشف ساب‌دامنه - ترکیب قدرت تمام ابزارهای بزرگ

This tool combines the capabilities of:
- Sublist3r: Multi-source enumeration
- OWASP Amass: Comprehensive reconnaissance  
- Subfinder: Fast and optimized discovery
- AssetFinder: Wide range of sources
- Chaos Client: ProjectDiscovery API
- DNSx: Advanced DNS capabilities
- Knock: Brute force and wordlists
- GitHub Search: Code repository mining
- Findomain: Multi-platform discovery

Author: Combined Implementation
Version: 1.0.0
"""

import argparse
import asyncio
import base64
import json
import os
import re
import ssl
import sys
import threading
import time
import random
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import List, Set, Optional, Dict, Any, Tuple
from urllib.parse import urlparse, quote, urlencode
import urllib.request
import urllib.error

# Try to import DNS libraries
try:
    import dns.resolver
    import dns.reversename
    import dns.zone
    import dns.query
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False
    print("Warning: dnspython not found. Some DNS features will be disabled.")
    print("Install with: pip install dnspython")

# Colors for output
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    END = '\033[0m'

    @classmethod
    def disable(cls):
        cls.RED = cls.GREEN = cls.YELLOW = cls.BLUE = ''
        cls.PURPLE = cls.CYAN = cls.WHITE = cls.BOLD = cls.END = ''

@dataclass
class SubdomainResult:
    """Data class for subdomain results"""
    domain: str
    ip: str = ""
    source: str = ""
    timestamp: str = ""
    status_code: int = 0
    title: str = ""
    technology: str = ""

class RateLimiter:
    """Advanced rate limiter with per-source limits"""
    
    def __init__(self):
        self.limits = {
            'default': 1.0,
            'crtsh': 0.5,
            'hackertarget': 2.0,
            'virustotal': 15.0,
            'securitytrails': 1.0,
            'shodan': 1.0,
            'chaos': 0.5,
            'github': 10.0,
            'censys': 2.0
        }
        self.last_requests = {}
        self.lock = threading.Lock()
    
    def wait(self, source: str):
        """Wait if necessary to respect rate limits"""
        delay = self.limits.get(source, self.limits['default'])
        
        with self.lock:
            now = time.time()
            if source in self.last_requests:
                elapsed = now - self.last_requests[source]
                if elapsed < delay:
                    time.sleep(delay - elapsed)
            self.last_requests[source] = time.time()

class SubdomainDiscovery:
    """Ultimate subdomain discovery engine"""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.timeout = self.config.get('timeout', 15)
        self.max_workers = self.config.get('max_workers', 50)
        self.silent = self.config.get('silent', False)
        self.verbose = self.config.get('verbose', False)
        self.output_format = self.config.get('output_format', 'text')
        self.enable_bruteforce = self.config.get('bruteforce', False)
        self.enable_github = self.config.get('github', False)
        self.enable_dns_resolution = self.config.get('dns_resolution', False)
        self.wordlist_file = self.config.get('wordlist', None)
        
        # Results storage
        self.found_domains = set()
        self.results = {}
        self.lock = threading.Lock()
        
        # Rate limiter
        self.rate_limiter = RateLimiter()
        
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
            'newsletter', 'app', 'live', 'owa', 'en', 'start', 'sms', 'office', 'exchange',
            'webserver', 'direct', 'blog', 'wwww', 'ftp2', 'www4', 'ns5', 'upload', 'mx3',
            'secure2', 'www5', 'web2', 'news2', 'ww1', 'www6', 'ns6', 'www7', 'www8',
            'mail3', 'dev2', 'www9', 'mail4', 'www10', 'test2', 'ns7', 'www11', 'ftp3',
            'mail5', 'blog2', 'www12', 'ftp4', 'www13', 'www14', 'www15'
        ]
        
        # Load custom wordlist if provided
        if self.wordlist_file and os.path.exists(self.wordlist_file):
            try:
                with open(self.wordlist_file, 'r') as f:
                    custom_words = [line.strip() for line in f if line.strip()]
                    self.common_subdomains.extend(custom_words)
            except Exception as e:
                self.log_error(f"Failed to load wordlist: {e}")
    
    def log_info(self, message: str):
        """Log info message"""
        if not self.silent:
            print(f"{Colors.BLUE}[INFO]{Colors.END} {message}", file=sys.stderr)
    
    def log_success(self, message: str):
        """Log success message"""
        if not self.silent:
            print(f"{Colors.GREEN}[SUCCESS]{Colors.END} {message}", file=sys.stderr)
    
    def log_error(self, message: str):
        """Log error message"""
        if not self.silent:
            print(f"{Colors.RED}[ERROR]{Colors.END} {message}", file=sys.stderr)
    
    def log_verbose(self, message: str):
        """Log verbose message"""
        if self.verbose and not self.silent:
            print(f"{Colors.YELLOW}[VERBOSE]{Colors.END} {message}", file=sys.stderr)
    
    def log_progress(self, source: str, count: int, completed: int, total: int):
        """Log progress message"""
        if not self.silent:
            status = "✓" if count > 0 else "✗"
            print(f"{Colors.CYAN}[{status}]{Colors.END} {source}: {count} domains ({completed}/{total})", file=sys.stderr)
    
    def clean_domain(self, domain: str) -> str:
        """Clean and normalize domain name"""
        if not domain:
            return ""
        
        domain = domain.lower().strip()
        
        # Remove protocol
        if domain.startswith(('http://', 'https://')):
            domain = urlparse(domain).netloc
        
        # Remove wildcards
        if domain.startswith('*') or domain.startswith('%'):
            domain = domain[1:]
        
        if domain.startswith('.'):
            domain = domain[1:]
        
        # Remove port
        if ':' in domain and not domain.count(':') > 1:  # Not IPv6
            domain = domain.split(':')[0]
        
        # Remove invalid characters
        domain = re.sub(r'[^a-z0-9.-]', '', domain)
        
        return domain
    
    def is_valid_domain(self, domain: str) -> bool:
        """Check if domain is valid"""
        if not domain or len(domain) > 253 or len(domain) < 3:
            return False
        
        # Check for valid domain format
        pattern = r'^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$'
        return bool(re.match(pattern, domain))
    
    def resolve_domain(self, domain: str) -> List[str]:
        """Resolve domain to IP addresses"""
        ips = []
        if not DNS_AVAILABLE:
            return ips
        
        try:
            # A records
            answers = self.resolver.resolve(domain, 'A')
            for answer in answers:
                ips.append(str(answer))
        except Exception:
            pass
        
        try:
            # AAAA records (IPv6)
            answers = self.resolver.resolve(domain, 'AAAA')
            for answer in answers:
                ips.append(str(answer))
        except Exception:
            pass
        
        return ips
    
    def add_result(self, domain: str, source: str = "", ip: str = ""):
        """Add result to storage"""
        cleaned_domain = self.clean_domain(domain)
        if not cleaned_domain or not self.is_valid_domain(cleaned_domain):
            return False
        
        with self.lock:
            if cleaned_domain not in self.found_domains:
                self.found_domains.add(cleaned_domain)
                
                # Resolve IP if DNS resolution is enabled
                if self.enable_dns_resolution and not ip and DNS_AVAILABLE:
                    ips = self.resolve_domain(cleaned_domain)
                    ip = ips[0] if ips else ""
                
                # Store detailed result
                result = SubdomainResult(
                    domain=cleaned_domain,
                    ip=ip,
                    source=source,
                    timestamp=datetime.now().isoformat()
                )
                self.results[cleaned_domain] = result
                
                # Print immediately if not silent
                if not self.silent:
                    if self.output_format == 'json':
                        print(json.dumps(asdict(result)))
                    else:
                        print(cleaned_domain)
                
                return True
        return False
    
    def fetch_url(self, url: str, headers: Dict[str, str] = None) -> Optional[str]:
        """Fetch URL content using urllib"""
        try:
            request = urllib.request.Request(url)
            request.add_header('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
            
            if headers:
                for key, value in headers.items():
                    request.add_header(key, value)
            
            with urllib.request.urlopen(request, timeout=self.timeout, context=self.ssl_context) as response:
                if response.status == 200:
                    return response.read().decode('utf-8', errors='ignore')
        except Exception as e:
            self.log_verbose(f"Error fetching {url}: {e}")
        return None
    
    def fetch_json(self, url: str, headers: Dict[str, str] = None) -> Optional[dict]:
        """Fetch JSON data from URL"""
        content = self.fetch_url(url, headers)
        if content:
            try:
                return json.loads(content)
            except json.JSONDecodeError as e:
                self.log_verbose(f"JSON decode error for {url}: {e}")
        return None
    
    # === PASSIVE RECONNAISSANCE SOURCES ===
    
    def fetch_crtsh(self, domain: str) -> int:
        """Fetch domains from crt.sh (Certificate Transparency)"""
        self.rate_limiter.wait('crtsh')
        self.log_verbose(f"Querying crt.sh for {domain}")
        
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
                    if name and self.add_result(name, "crt.sh"):
                        count += 1
        
        return count
    
    def fetch_hackertarget(self, domain: str) -> int:
        """Fetch domains from HackerTarget"""
        self.rate_limiter.wait('hackertarget')
        self.log_verbose(f"Querying HackerTarget for {domain}")
        
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        content = self.fetch_url(url)
        
        if not content:
            return 0
        
        count = 0
        for line in content.strip().split('\n'):
            parts = line.split(',', 1)
            if len(parts) == 2:
                if self.add_result(parts[0], "hackertarget", parts[1]):
                    count += 1
        
        return count
    
    def fetch_anubis(self, domain: str) -> int:
        """Fetch domains from Anubis"""
        self.rate_limiter.wait('anubis')
        self.log_verbose(f"Querying Anubis for {domain}")
        
        url = f"https://jldc.me/anubis/subdomains/{domain}"
        data = self.fetch_json(url)
        
        if not data or not isinstance(data, list):
            return 0
        
        count = 0
        for subdomain in data:
            if self.add_result(subdomain, "anubis"):
                count += 1
        
        return count
    
    def fetch_alienvault(self, domain: str) -> int:
        """Fetch domains from AlienVault OTX"""
        self.rate_limiter.wait('alienvault')
        self.log_verbose(f"Querying AlienVault OTX for {domain}")
        
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
        data = self.fetch_json(url)
        
        if not data or 'passive_dns' not in data:
            return 0
        
        count = 0
        for item in data['passive_dns']:
            if 'hostname' in item:
                ip = item.get('address', '')
                if self.add_result(item['hostname'], "alienvault", ip):
                    count += 1
        
        return count
    
    def fetch_wayback(self, domain: str) -> int:
        """Fetch domains from Wayback Machine"""
        self.rate_limiter.wait('wayback')
        self.log_verbose(f"Querying Wayback Machine for {domain}")
        
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
                    if parsed.hostname and self.add_result(parsed.hostname, "wayback"):
                        count += 1
                except:
                    continue
        
        return count
    
    def fetch_threatcrowd(self, domain: str) -> int:
        """Fetch domains from ThreatCrowd"""
        self.rate_limiter.wait('threatcrowd')
        self.log_verbose(f"Querying ThreatCrowd for {domain}")
        
        url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}"
        data = self.fetch_json(url)
        
        if not data or 'subdomains' not in data:
            return 0
        
        count = 0
        for subdomain in data['subdomains']:
            if self.add_result(subdomain, "threatcrowd"):
                count += 1
        
        return count
    
    def fetch_urlscan(self, domain: str) -> int:
        """Fetch domains from URLScan.io"""
        self.rate_limiter.wait('urlscan')
        self.log_verbose(f"Querying URLScan.io for {domain}")
        
        url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}"
        data = self.fetch_json(url)
        
        if not data or 'results' not in data:
            return 0
        
        count = 0
        domains_found = set()
        
        for result in data['results']:
            # Extract from task URL
            if 'task' in result and 'url' in result['task']:
                try:
                    parsed = urlparse(result['task']['url'])
                    if parsed.hostname and parsed.hostname not in domains_found:
                        domains_found.add(parsed.hostname)
                        if self.add_result(parsed.hostname, "urlscan"):
                            count += 1
                except:
                    pass
            
            # Extract from page URL
            if 'page' in result and 'url' in result['page']:
                try:
                    parsed = urlparse(result['page']['url'])
                    if parsed.hostname and parsed.hostname not in domains_found:
                        domains_found.add(parsed.hostname)
                        if self.add_result(parsed.hostname, "urlscan"):
                            count += 1
                except:
                    pass
        
        return count
    
    def fetch_bufferover(self, domain: str) -> int:
        """Fetch domains from BufferOver.run"""
        self.rate_limiter.wait('bufferover')
        self.log_verbose(f"Querying BufferOver.run for {domain}")
        
        url = f"https://dns.bufferover.run/dns?q=.{domain}"
        data = self.fetch_json(url)
        
        if not data:
            return 0
        
        count = 0
        
        # FDNS_A records
        if 'FDNS_A' in data:
            for record in data['FDNS_A']:
                parts = record.split(',', 1)
                if len(parts) == 2:
                    if self.add_result(parts[1], "bufferover", parts[0]):
                        count += 1
        
        # RDNS records
        if 'RDNS' in data:
            for record in data['RDNS']:
                parts = record.split(',', 1)
                if len(parts) == 2:
                    if self.add_result(parts[1], "bufferover", parts[0]):
                        count += 1
        
        return count
    
    # === API-BASED SOURCES ===
    
    def fetch_chaos(self, domain: str) -> int:
        """Fetch domains from Chaos (ProjectDiscovery)"""
        api_key = os.getenv('CHAOS_API_KEY')
        if not api_key:
            return 0
        
        self.rate_limiter.wait('chaos')
        self.log_verbose(f"Querying Chaos API for {domain}")
        
        headers = {'Authorization': api_key}
        url = f"https://dns.projectdiscovery.io/dns/{domain}/subdomains"
        data = self.fetch_json(url, headers)
        
        if not data or 'subdomains' not in data:
            return 0
        
        count = 0
        for subdomain in data['subdomains']:
            if self.add_result(f"{subdomain}.{domain}", "chaos"):
                count += 1
        
        return count
    
    def fetch_shodan(self, domain: str) -> int:
        """Fetch domains from Shodan"""
        api_key = os.getenv('SHODAN_API_KEY')
        if not api_key:
            return 0
        
        self.rate_limiter.wait('shodan')
        self.log_verbose(f"Querying Shodan API for {domain}")
        
        url = f"https://api.shodan.io/dns/domain/{domain}?key={api_key}"
        data = self.fetch_json(url)
        
        if not data or 'subdomains' not in data:
            return 0
        
        count = 0
        for subdomain in data['subdomains']:
            if self.add_result(f"{subdomain}.{domain}", "shodan"):
                count += 1
        
        return count
    
    def fetch_virustotal(self, domain: str) -> int:
        """Fetch domains from VirusTotal"""
        api_key = os.getenv('VIRUSTOTAL_API_KEY')
        if not api_key:
            return 0
        
        self.rate_limiter.wait('virustotal')
        self.log_verbose(f"Querying VirusTotal API for {domain}")
        
        # Try both old and new API endpoints
        urls = [
            f"https://www.virustotal.com/vtapi/v2/domain/report?domain={domain}&apikey={api_key}",
            f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains"
        ]
        
        count = 0
        
        for i, url in enumerate(urls):
            headers = {'x-apikey': api_key} if i == 1 else {}
            data = self.fetch_json(url, headers)
            
            if not data:
                continue
            
            # Handle v2 API response
            if 'subdomains' in data and isinstance(data['subdomains'], list):
                for subdomain in data['subdomains']:
                    if self.add_result(subdomain, "virustotal"):
                        count += 1
            
            # Handle v3 API response
            elif 'data' in data:
                for item in data['data']:
                    if 'id' in item and self.add_result(item['id'], "virustotal"):
                        count += 1
        
        return count
    
    def fetch_securitytrails(self, domain: str) -> int:
        """Fetch domains from SecurityTrails"""
        api_key = os.getenv('SECURITYTRAILS_API_KEY')
        if not api_key:
            return 0
        
        self.rate_limiter.wait('securitytrails')
        self.log_verbose(f"Querying SecurityTrails API for {domain}")
        
        headers = {'APIKEY': api_key}
        url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
        data = self.fetch_json(url, headers)
        
        if not data or 'subdomains' not in data:
            return 0
        
        count = 0
        for subdomain in data['subdomains']:
            if self.add_result(f"{subdomain}.{domain}", "securitytrails"):
                count += 1
        
        return count
    
    def fetch_censys(self, domain: str) -> int:
        """Fetch domains from Censys"""
        api_id = os.getenv('CENSYS_API_ID')
        secret = os.getenv('CENSYS_SECRET')
        if not (api_id and secret):
            return 0
        
        self.rate_limiter.wait('censys')
        self.log_verbose(f"Querying Censys API for {domain}")
        
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
                    if self.add_result(name, "censys"):
                        count += 1
        
        return count
    
    def fetch_github(self, domain: str) -> int:
        """Fetch domains from GitHub search"""
        if not self.enable_github:
            return 0
        
        github_token = os.getenv('GITHUB_TOKEN')
        if not github_token:
            return 0
        
        self.rate_limiter.wait('github')
        self.log_verbose(f"Searching GitHub for {domain}")
        
        headers = {
            'Authorization': f'token {github_token}',
            'Accept': 'application/vnd.github.v3+json'
        }
        
        # Search for domain in code
        query = f'"{domain}" extension:txt OR extension:conf OR extension:config'
        url = f"https://api.github.com/search/code?q={quote(query)}&per_page=100"
        
        data = self.fetch_json(url, headers)
        
        if not data or 'items' not in data:
            return 0
        
        count = 0
        domain_pattern = re.compile(r'([a-z0-9-]+\.)*' + re.escape(domain), re.IGNORECASE)
        
        for item in data['items']:
            if 'html_url' in item:
                # Download file content
                download_url = item.get('download_url')
                if download_url:
                    content = self.fetch_url(download_url, headers)
                    if content:
                        matches = domain_pattern.findall(content)
                        for match in set(matches):
                            if match and self.add_result(match, "github"):
                                count += 1
        
        return count
    
    def bruteforce_subdomains(self, domain: str) -> int:
        """Brute force subdomains using wordlist"""
        if not self.enable_bruteforce or not DNS_AVAILABLE:
            return 0
        
        self.log_verbose(f"Starting brute force for {domain}")
        
        count = 0
        
        def check_subdomain(subdomain):
            full_domain = f"{subdomain}.{domain}"
            try:
                self.resolver.resolve(full_domain, 'A')
                if self.add_result(full_domain, "bruteforce"):
                    return 1
            except:
                pass
            return 0
        
        # Use ThreadPoolExecutor for brute force
        with ThreadPoolExecutor(max_workers=min(100, len(self.common_subdomains))) as executor:
            futures = [executor.submit(check_subdomain, sub) for sub in self.common_subdomains]
            
            for future in as_completed(futures):
                try:
                    count += future.result()
                except Exception:
                    pass
        
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
    
    def discover_subdomains(self, domain: str) -> Set[str]:
        """Main subdomain discovery function"""
        domain = self.clean_domain(domain)
        if not domain or not self.is_valid_domain(domain):
            self.log_error(f"Invalid domain: {domain}")
            return set()
        
        self.log_info(f"Starting comprehensive subdomain discovery for {domain}")
        
        # Define all available sources
        passive_sources = [
            ('crt.sh', self.fetch_crtsh),
            ('hackertarget', self.fetch_hackertarget),
            ('anubis', self.fetch_anubis),
            ('alienvault', self.fetch_alienvault),
            ('wayback', self.fetch_wayback),
            ('threatcrowd', self.fetch_threatcrowd),
            ('urlscan', self.fetch_urlscan),
            ('bufferover', self.fetch_bufferover),
        ]
        
        api_sources = [
            ('chaos', self.fetch_chaos),
            ('shodan', self.fetch_shodan),
            ('virustotal', self.fetch_virustotal),
            ('securitytrails', self.fetch_securitytrails),
            ('censys', self.fetch_censys),
        ]
        
        additional_sources = []
        if self.enable_github:
            additional_sources.append(('github', self.fetch_github))
        
        if self.enable_bruteforce:
            additional_sources.append(('bruteforce', self.bruteforce_subdomains))
        
        # Filter enabled sources (check for API keys)
        enabled_sources = []
        
        # Add passive sources (no API key required)
        enabled_sources.extend(passive_sources)
        
        # Add API sources (check for API keys)
        for name, func in api_sources:
            if name == 'chaos' and os.getenv('CHAOS_API_KEY'):
                enabled_sources.append((name, func))
            elif name == 'shodan' and os.getenv('SHODAN_API_KEY'):
                enabled_sources.append((name, func))
            elif name == 'virustotal' and os.getenv('VIRUSTOTAL_API_KEY'):
                enabled_sources.append((name, func))
            elif name == 'securitytrails' and os.getenv('SECURITYTRAILS_API_KEY'):
                enabled_sources.append((name, func))
            elif name == 'censys' and os.getenv('CENSYS_API_ID') and os.getenv('CENSYS_SECRET'):
                enabled_sources.append((name, func))
        
        # Add additional sources
        enabled_sources.extend(additional_sources)
        
        self.log_info(f"Using {len(enabled_sources)} discovery sources")
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
        
        self.log_success(f"Discovery complete: {len(self.found_domains)} unique subdomains found")
        return self.found_domains
    
    def save_results(self, output_file: str):
        """Save results to file"""
        try:
            with open(output_file, 'w') as f:
                if self.output_format == 'json':
                    results_list = [asdict(result) for result in self.results.values()]
                    json.dump(results_list, f, indent=2)
                elif self.output_format == 'csv':
                    if self.results:
                        fieldnames = list(asdict(list(self.results.values())[0]).keys())
                        writer = csv.DictWriter(f, fieldnames=fieldnames)
                        writer.writeheader()
                        for result in self.results.values():
                            writer.writerow(asdict(result))
                else:  # text format
                    for domain in sorted(self.found_domains):
                        f.write(f"{domain}\n")
            
            self.log_success(f"Results saved to {output_file}")
        except Exception as e:
            self.log_error(f"Failed to save results: {e}")

def print_banner():
    """Print tool banner"""
    banner = f"""{Colors.RED}
    ███████╗██╗   ██╗██████╗ ██████╗  ██████╗ ███╗   ███╗ █████╗ ██╗███╗   ██╗███████╗
    ██╔════╝██║   ██║██╔══██╗██╔══██╗██╔═══██╗████╗ ████║██╔══██╗██║████╗  ██║██╔════╝
    ███████╗██║   ██║██████╔╝██║  ██║██║   ██║██╔████╔██║███████║██║██╔██╗ ██║███████╗
    ╚════██║██║   ██║██╔══██╗██║  ██║██║   ██║██║╚██╔╝██║██╔══██║██║██║╚██╗██║╚════██║
    ███████║╚██████╔╝██████╔╝██████╔╝╚██████╔╝██║ ╚═╝ ██║██║  ██║██║██║ ╚████║███████║
    ╚══════╝ ╚═════╝ ╚═════╝ ╚═════╝  ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝╚══════╝
    {Colors.END}
    {Colors.YELLOW}Ultimate Subdomain Discovery Tool - Combined Power of All Major Tools{Colors.END}
    {Colors.CYAN}Combines: Sublist3r + Amass + Subfinder + AssetFinder + Chaos + DNSx + Knock + GitHub + Findomain{Colors.END}
    """
    print(banner)

def main():
    parser = argparse.ArgumentParser(
        description='Ultimate Subdomain Discovery Tool - Combined Power of All Major Tools',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python subdomains.py -d example.com
  python subdomains.py -d example.com --bruteforce --github
  python subdomains.py -d example.com -o results.txt --json
  python subdomains.py -d example.com --dns-resolution --verbose
  python subdomains.py -d example.com --wordlist custom.txt --threads 100
  echo "example.com" | python subdomains.py

Environment Variables (Optional API Keys):
  CHAOS_API_KEY - ProjectDiscovery Chaos API
  SHODAN_API_KEY - Shodan API  
  VIRUSTOTAL_API_KEY - VirusTotal API
  SECURITYTRAILS_API_KEY - SecurityTrails API
  CENSYS_API_ID, CENSYS_SECRET - Censys API
  GITHUB_TOKEN - GitHub API (for --github)

Sources Used:
  Free: crt.sh, hackertarget, anubis, alienvault, wayback, threatcrowd, urlscan, bufferover
  API: chaos, shodan, virustotal, securitytrails, censys
  Optional: github (with --github), bruteforce (with --bruteforce)
        """
    )
    
    parser.add_argument('-d', '--domain', help='Target domain to enumerate')
    parser.add_argument('-o', '--output', help='Output file path')
    parser.add_argument('--json', action='store_true', help='Output in JSON format')
    parser.add_argument('--csv', action='store_true', help='Output in CSV format')
    parser.add_argument('--silent', action='store_true', help='Silent mode - only output results')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--bruteforce', action='store_true', help='Enable brute force with wordlist')
    parser.add_argument('--github', action='store_true', help='Enable GitHub search (requires GITHUB_TOKEN)')
    parser.add_argument('--dns-resolution', action='store_true', help='Resolve domains to IP addresses')
    parser.add_argument('--wordlist', help='Custom wordlist file for brute force')
    parser.add_argument('--threads', type=int, default=50, help='Number of threads (default: 50)')
    parser.add_argument('--timeout', type=int, default=15, help='Request timeout in seconds (default: 15)')
    parser.add_argument('--no-color', action='store_true', help='Disable colored output')
    
    args = parser.parse_args()
    
    if args.no_color:
        Colors.disable()
    
    # Get domain from argument or stdin
    domain = args.domain
    if not domain:
        try:
            domain = input().strip() if not sys.stdin.isatty() else None
        except (EOFError, KeyboardInterrupt):
            pass
    
    if not domain:
        if not args.silent:
            print_banner()
        parser.print_help()
        return 1
    
    # Determine output format
    output_format = 'text'
    if args.json:
        output_format = 'json'
    elif args.csv:
        output_format = 'csv'
    
    # Configuration
    config = {
        'timeout': args.timeout,
        'max_workers': args.threads,
        'silent': args.silent,
        'verbose': args.verbose,
        'output_format': output_format,
        'bruteforce': args.bruteforce,
        'github': args.github,
        'dns_resolution': args.dns_resolution,
        'wordlist': args.wordlist
    }
    
    # Print banner if not silent
    if not args.silent:
        print_banner()
    
    # Create discovery engine and run
    try:
        discovery = SubdomainDiscovery(config)
        results = discovery.discover_subdomains(domain)
        
        # Save results if output file specified
        if args.output:
            discovery.save_results(args.output)
        
        return 0
    
    except KeyboardInterrupt:
        if not args.silent:
            print(f"\n{Colors.RED}[!] Interrupted by user{Colors.END}", file=sys.stderr)
        return 1
    except Exception as e:
        if not args.silent:
            print(f"{Colors.RED}[ERROR] {e}{Colors.END}", file=sys.stderr)
        return 1

if __name__ == '__main__':
    sys.exit(main())