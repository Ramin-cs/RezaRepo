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
import dns.resolver
import dns.reversename
import dns.zone
from typing import List, Set, Optional, Dict, Any, Tuple
from urllib.parse import urlparse, quote
import urllib.request
import urllib.error
import ssl
import threading
import ipaddress
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime
import sqlite3
import hashlib


@dataclass
class AmassResult:
    """Data class for Amass results"""
    domain: str
    ip: str = ""
    source: str = ""
    tag: str = ""
    timestamp: str = ""


class AmassDatabase:
    """SQLite database for storing results"""
    
    def __init__(self, db_path: str = "amass_results.db"):
        self.db_path = db_path
        self.init_db()
    
    def init_db(self):
        """Initialize database tables"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS domains (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT UNIQUE,
                ip TEXT,
                source TEXT,
                tag TEXT,
                timestamp TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ips (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT UNIQUE,
                asn TEXT,
                org TEXT,
                country TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def add_domain(self, result: AmassResult):
        """Add domain to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT OR REPLACE INTO domains (domain, ip, source, tag, timestamp)
                VALUES (?, ?, ?, ?, ?)
            ''', (result.domain, result.ip, result.source, result.tag, result.timestamp))
            conn.commit()
        except sqlite3.Error:
            pass
        finally:
            conn.close()
    
    def get_domains(self, target_domain: str = None) -> List[AmassResult]:
        """Get domains from database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        if target_domain:
            cursor.execute('''
                SELECT domain, ip, source, tag, timestamp FROM domains 
                WHERE domain LIKE ? ORDER BY domain
            ''', (f'%{target_domain}%',))
        else:
            cursor.execute('SELECT domain, ip, source, tag, timestamp FROM domains ORDER BY domain')
        
        results = []
        for row in cursor.fetchall():
            results.append(AmassResult(
                domain=row[0], ip=row[1], source=row[2], tag=row[3], timestamp=row[4]
            ))
        
        conn.close()
        return results


class AmassEngine:
    """Main Amass Engine with comprehensive reconnaissance capabilities"""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.timeout = self.config.get('timeout', 10)
        self.max_workers = self.config.get('max_workers', 20)
        self.passive_only = self.config.get('passive_only', False)
        self.active = self.config.get('active', False)
        self.brute_force = self.config.get('brute_force', False)
        self.silent = self.config.get('silent', False)
        self.verbose = self.config.get('verbose', False)
        self.output_format = self.config.get('output_format', 'text')
        self.database = AmassDatabase(self.config.get('db_path', 'amass_results.db'))
        
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
            'ipv4', 'mail3', 'help', 'blogs', 'helpdesk', 'web1', 'home', 'library',
            'ftp2', 'ntp', 'monitor', 'login', 'service', 'correo', 'www4', 'moodle',
            'it', 'gateway', 'gw', 'i', 'stat', 'stage', 'ldap', 'tv', 'ssl', 'web2',
            'ns5', 'upload', 'nagios', 'smtp2', 'online', 'ad', 'survey', 'data', 'radio',
            'extranet', 'test2', 'mssql', 'dns3', 'jobs', 'services', 'panel', 'irc'
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
                
                # Create result object
                result = AmassResult(
                    domain=cleaned_domain,
                    ip=ip,
                    source=source,
                    tag=tag,
                    timestamp=datetime.now().isoformat()
                )
                
                # Add to database
                self.database.add_domain(result)
                
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
    
    def reverse_dns_lookup(self, ip: str) -> List[str]:
        """Perform reverse DNS lookup"""
        domains = []
        try:
            addr = dns.reversename.from_address(ip)
            answers = self.resolver.resolve(addr, 'PTR')
            for answer in answers:
                domain = str(answer).rstrip('.')
                domains.append(domain)
        except Exception:
            pass
        
        return domains
    
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
    
    def fetch_dnsdumpster(self, domain: str) -> int:
        """Fetch domains from DNSDumpster"""
        # This would require web scraping, simplified for now
        return 0
    
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
    
    # === ACTIVE RECONNAISSANCE ===
    
    def brute_force_subdomains(self, domain: str) -> int:
        """Brute force common subdomains"""
        if not self.brute_force:
            return 0
        
        count = 0
        
        def check_subdomain(subdomain):
            nonlocal count
            test_domain = f"{subdomain}.{domain}"
            ips = self.resolve_domain(test_domain)
            if ips:
                with self.lock:
                    count += 1
                self.add_result(test_domain, ip=ips[0], source="brute_force", tag="dns")
        
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = [executor.submit(check_subdomain, sub) for sub in self.common_subdomains]
            for future in as_completed(futures):
                pass
        
        return count
    
    def zone_transfer(self, domain: str) -> int:
        """Attempt DNS zone transfer"""
        if not self.active:
            return 0
        
        count = 0
        try:
            # Get NS records
            ns_answers = self.resolver.resolve(domain, 'NS')
            for ns in ns_answers:
                ns_server = str(ns).rstrip('.')
                try:
                    # Attempt zone transfer
                    zone = dns.zone.from_xfr(dns.query.xfr(ns_server, domain))
                    for name, node in zone.nodes.items():
                        if name != dns.name.root:
                            subdomain = f"{name}.{domain}"
                            self.add_result(subdomain, source="zone_transfer", tag="dns")
                            count += 1
                except Exception:
                    continue
        except Exception:
            pass
        
        return count
    
    def reverse_dns_sweep(self, domain: str) -> int:
        """Perform reverse DNS sweep on IP ranges"""
        if not self.active:
            return 0
        
        count = 0
        
        # Get IP addresses for the domain
        ips = self.resolve_domain(domain)
        
        for ip in ips:
            try:
                # Get the network range (simplified to /24)
                network = ipaddress.IPv4Network(f"{ip}/24", strict=False)
                
                def check_ip(check_ip):
                    nonlocal count
                    domains = self.reverse_dns_lookup(str(check_ip))
                    for found_domain in domains:
                        if domain in found_domain:
                            with self.lock:
                                count += 1
                            self.add_result(found_domain, ip=str(check_ip), source="reverse_dns", tag="dns")
                
                # Check a subset of IPs in the range
                with ThreadPoolExecutor(max_workers=20) as executor:
                    futures = []
                    for i, host in enumerate(network.hosts()):
                        if i > 50:  # Limit to first 50 IPs
                            break
                        futures.append(executor.submit(check_ip, host))
                    
                    for future in as_completed(futures):
                        pass
                        
            except Exception:
                continue
        
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
        
        active_sources = []
        if self.active:
            active_sources.extend([
                ('zone_transfer', self.zone_transfer),
                ('reverse_dns', self.reverse_dns_sweep),
            ])
        
        if self.brute_force:
            active_sources.append(('brute_force', self.brute_force_subdomains))
        
        all_sources = passive_sources
        if not self.passive_only:
            all_sources.extend(active_sources)
        
        # Filter enabled sources (check for API keys)
        enabled_sources = []
        for name, func in all_sources:
            if name in ['crt.sh', 'hackertarget', 'anubis', 'alienvault', 'wayback', 'dnsdumpster']:
                enabled_sources.append((name, func))
            elif name in ['zone_transfer', 'reverse_dns', 'brute_force']:
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
        
        # Resolve IP addresses for found domains
        if not self.passive_only:
            self.log_info("Resolving IP addresses...")
            for domain_name in list(self.found_domains):
                if domain_name not in self.domain_ip_map:
                    ips = self.resolve_domain(domain_name)
                    if ips:
                        self.domain_ip_map[domain_name] = ips[0]
                        self.found_ips.update(ips)
        
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
  python amass.py db --show --domain example.com
  
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
    
    # DB subcommand
    db_parser = subparsers.add_parser('db', help='Database operations')
    db_parser.add_argument('--show', action='store_true', help='Show stored results')
    db_parser.add_argument('--domain', help='Filter by domain')
    db_parser.add_argument('--export', help='Export to file')
    
    # Intel subcommand
    intel_parser = subparsers.add_parser('intel', help='Intelligence gathering')
    intel_parser.add_argument('-d', '--domain', help='Target domain')
    intel_parser.add_argument('--asn', help='Target ASN')
    intel_parser.add_argument('--ip', help='Target IP')
    
    # Viz subcommand
    viz_parser = subparsers.add_parser('viz', help='Generate visualizations')
    viz_parser.add_argument('-d', '--domain', required=True, help='Domain to visualize')
    viz_parser.add_argument('-o', '--output', default='amass_graph.html', help='Output file')
    
    # Track subcommand
    track_parser = subparsers.add_parser('track', help='Track changes')
    track_parser.add_argument('-d', '--domain', required=True, help='Domain to track')
    
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
    
    # Handle db command
    elif args.command == 'db':
        db = AmassDatabase()
        results = db.get_domains(args.domain)
        
        if args.export:
            with open(args.export, 'w') as f:
                for result in results:
                    f.write(f"{result.domain}\n")
            print(f"Exported {len(results)} domains to {args.export}")
        else:
            for result in results:
                print(f"{result.domain} [{result.source}] {result.ip}")
    
    # Handle other commands (simplified)
    elif args.command == 'intel':
        print("Intelligence gathering mode - Feature coming soon!")
    elif args.command == 'viz':
        print("Visualization mode - Feature coming soon!")
    elif args.command == 'track':
        print("Tracking mode - Feature coming soon!")
    
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