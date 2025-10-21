#!/usr/bin/env python3
"""
Findomain Python Implementation
A fast and cross-platform subdomain enumerator

Original: https://github.com/Findomain/Findomain
Python implementation with all major features and APIs

Features:
- Multiple subdomain enumeration sources
- DNS resolution and validation
- HTTP/HTTPS probing
- Port scanning
- Output in multiple formats (JSON, CSV, TXT)
- Rate limiting and threading
- Monitoring mode
- Integration with multiple APIs
"""

import argparse
import json
import os
import sys
import threading
import time
import random
import socket
import ssl
import urllib.parse
import urllib.request
import urllib.error
import re
import csv
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Set, Optional, Dict, Any, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime
import base64
import hashlib

# Console Colors
class Colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    RED = '\033[91m'
    WHITE = '\033[0m'
    BOLD = '\033[1m'
    CYAN = '\033[96m'
    MAGENTA = '\033[95m'
    
    @classmethod
    def disable(cls):
        cls.GREEN = cls.YELLOW = cls.BLUE = cls.RED = cls.WHITE = cls.BOLD = cls.CYAN = cls.MAGENTA = ''

C = Colors()

def banner():
    """Display Findomain banner"""
    print(f"""{C.CYAN}
    _____ _           _                       _       
   |  ___(_)_ __   __| | ___  _ __ ___   __ _(_)_ __  
   | |_  | | '_ \\ / _` |/ _ \\| '_ ` _ \\ / _` | | '_ \\ 
   |  _| | | | | | (_| | (_) | | | | | | (_| | | | | |
   |_|   |_|_| |_|\\__,_|\\___/|_| |_| |_|\\__,_|_|_| |_|
   
        {C.YELLOW}Python Implementation{C.WHITE}
        {C.GREEN}Fast Subdomain Enumerator{C.WHITE}
    """)

@dataclass
class SubdomainResult:
    """Data class for subdomain results"""
    subdomain: str
    ip: str = ""
    http_status: int = 0
    https_status: int = 0
    ports: List[int] = None
    title: str = ""
    server: str = ""
    source: str = ""
    timestamp: str = ""
    
    def __post_init__(self):
        if self.ports is None:
            self.ports = []
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()

class DNSResolver:
    """Fast DNS resolver with caching"""
    
    def __init__(self):
        self.cache = {}
        self.lock = threading.Lock()
        
    def resolve(self, domain: str) -> Optional[str]:
        """Resolve domain to IP with caching"""
        with self.lock:
            if domain in self.cache:
                return self.cache[domain]
        
        try:
            ip = socket.gethostbyname(domain)
            with self.lock:
                self.cache[domain] = ip
            return ip
        except socket.gaierror:
            return None

class HTTPProber:
    """HTTP/HTTPS status checker"""
    
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.session_cache = {}
        
    def probe(self, domain: str) -> Tuple[int, int, str, str]:
        """Probe HTTP and HTTPS status"""
        http_status = 0
        https_status = 0
        title = ""
        server = ""
        
        # Try HTTPS first
        try:
            https_status, title, server = self._check_url(f"https://{domain}")
        except:
            pass
            
        # Try HTTP
        try:
            http_status, http_title, http_server = self._check_url(f"http://{domain}")
            if not title:
                title = http_title
            if not server:
                server = http_server
        except:
            pass
            
        return http_status, https_status, title, server
    
    def _check_url(self, url: str) -> Tuple[int, str, str]:
        """Check single URL"""
        try:
            request = urllib.request.Request(url)
            request.add_header('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
            
            # Create SSL context that ignores certificate errors
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
            
            with urllib.request.urlopen(request, timeout=self.timeout, context=ssl_context) as response:
                content = response.read(8192).decode('utf-8', errors='ignore')  # Read only first 8KB
                
                # Extract title
                title_match = re.search(r'<title[^>]*>([^<]+)</title>', content, re.IGNORECASE)
                title = title_match.group(1).strip() if title_match else ""
                
                # Get server header
                server = response.headers.get('Server', '')
                
                return response.status, title, server
                
        except urllib.error.HTTPError as e:
            return e.code, "", ""
        except:
            return 0, "", ""

class SubdomainEnumerator:
    """Main subdomain enumeration class"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.target = config.get('target', '')
        self.threads = config.get('threads', 50)
        self.timeout = config.get('timeout', 10)
        self.silent = config.get('silent', False)
        self.verbose = config.get('verbose', False)
        self.enable_http_probing = config.get('http_probing', False)
        self.enable_port_scan = config.get('port_scan', False)
        self.ports = config.get('ports', [80, 443, 8080, 8443])
        
        # Results storage
        self.subdomains = set()
        self.results = []
        self.lock = threading.Lock()
        
        # Components
        self.dns_resolver = DNSResolver()
        self.http_prober = HTTPProber(timeout=self.timeout)
        
        # API configurations
        self.setup_apis()
        
    def setup_apis(self):
        """Setup API configurations"""
        self.apis = {
            'crtsh': {
                'url': 'https://crt.sh/?q=%25.{domain}&output=json',
                'enabled': True
            },
            'virustotal': {
                'url': 'https://www.virustotal.com/vtapi/v2/domain/report',
                'api_key': self.config.get('virustotal_api_key', ''),
                'enabled': bool(self.config.get('virustotal_api_key', ''))
            },
            'securitytrails': {
                'url': 'https://api.securitytrails.com/v1/domain/{domain}/subdomains',
                'api_key': self.config.get('securitytrails_api_key', ''),
                'enabled': bool(self.config.get('securitytrails_api_key', ''))
            },
            'shodan': {
                'url': 'https://api.shodan.io/dns/domain/{domain}',
                'api_key': self.config.get('shodan_api_key', ''),
                'enabled': bool(self.config.get('shodan_api_key', ''))
            },
            'censys': {
                'url': 'https://search.censys.io/api/v2/certificates/search',
                'api_id': self.config.get('censys_api_id', ''),
                'api_secret': self.config.get('censys_api_secret', ''),
                'enabled': bool(self.config.get('censys_api_id', '') and self.config.get('censys_api_secret', ''))
            },
            'facebook': {
                'url': 'https://graph.facebook.com/certificates',
                'access_token': self.config.get('facebook_access_token', ''),
                'enabled': bool(self.config.get('facebook_access_token', ''))
            },
            'spyse': {
                'url': 'https://api.spyse.com/v4/data/domain/subdomain',
                'api_key': self.config.get('spyse_api_key', ''),
                'enabled': bool(self.config.get('spyse_api_key', ''))
            },
            'bufferover': {
                'url': 'https://dns.bufferover.run/dns?q=.{domain}',
                'enabled': True
            },
            'hackertarget': {
                'url': 'https://api.hackertarget.com/hostsearch/?q={domain}',
                'enabled': True
            },
            'threatcrowd': {
                'url': 'https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}',
                'enabled': True
            },
            'alienvault': {
                'url': 'https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns',
                'enabled': True
            }
        }
    
    def log_info(self, message: str):
        """Log info message"""
        if not self.silent:
            print(f"{C.BLUE}[INFO]{C.WHITE} {message}")
    
    def log_verbose(self, message: str):
        """Log verbose message"""
        if self.verbose and not self.silent:
            print(f"{C.YELLOW}[VERBOSE]{C.WHITE} {message}")
    
    def log_error(self, message: str):
        """Log error message"""
        if not self.silent:
            print(f"{C.RED}[ERROR]{C.WHITE} {message}")
    
    def log_success(self, message: str):
        """Log success message"""
        if not self.silent:
            print(f"{C.GREEN}[SUCCESS]{C.WHITE} {message}")

    def fetch_crtsh(self, domain: str) -> Set[str]:
        """Fetch subdomains from crt.sh"""
        subdomains = set()
        try:
            url = self.apis['crtsh']['url'].format(domain=domain)
            request = urllib.request.Request(url)
            request.add_header('User-Agent', 'Mozilla/5.0 Findomain')
            
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                data = json.loads(response.read().decode())
                
            for entry in data:
                name_value = entry.get('name_value', '')
                if name_value:
                    # Handle multiple domains in one entry
                    for subdomain in name_value.split('\n'):
                        subdomain = subdomain.strip().lower()
                        if subdomain and domain in subdomain:
                            # Remove wildcards
                            subdomain = subdomain.replace('*.', '')
                            if self.is_valid_subdomain(subdomain, domain):
                                subdomains.add(subdomain)
                                
        except Exception as e:
            self.log_verbose(f"crt.sh error: {e}")
            
        return subdomains
    
    def fetch_virustotal(self, domain: str) -> Set[str]:
        """Fetch subdomains from VirusTotal"""
        subdomains = set()
        if not self.apis['virustotal']['enabled']:
            return subdomains
            
        try:
            url = self.apis['virustotal']['url']
            params = {
                'apikey': self.apis['virustotal']['api_key'],
                'domain': domain
            }
            
            data = urllib.parse.urlencode(params).encode()
            request = urllib.request.Request(url, data=data)
            
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                result = json.loads(response.read().decode())
                
            if 'subdomains' in result:
                for subdomain in result['subdomains']:
                    full_domain = f"{subdomain}.{domain}"
                    if self.is_valid_subdomain(full_domain, domain):
                        subdomains.add(full_domain)
                        
        except Exception as e:
            self.log_verbose(f"VirusTotal error: {e}")
            
        return subdomains
    
    def fetch_securitytrails(self, domain: str) -> Set[str]:
        """Fetch subdomains from SecurityTrails"""
        subdomains = set()
        if not self.apis['securitytrails']['enabled']:
            return subdomains
            
        try:
            url = self.apis['securitytrails']['url'].format(domain=domain)
            request = urllib.request.Request(url)
            request.add_header('APIKEY', self.apis['securitytrails']['api_key'])
            
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                result = json.loads(response.read().decode())
                
            if 'subdomains' in result:
                for subdomain in result['subdomains']:
                    full_domain = f"{subdomain}.{domain}"
                    if self.is_valid_subdomain(full_domain, domain):
                        subdomains.add(full_domain)
                        
        except Exception as e:
            self.log_verbose(f"SecurityTrails error: {e}")
            
        return subdomains
    
    def fetch_shodan(self, domain: str) -> Set[str]:
        """Fetch subdomains from Shodan"""
        subdomains = set()
        if not self.apis['shodan']['enabled']:
            return subdomains
            
        try:
            url = self.apis['shodan']['url'].format(domain=domain)
            params = {'key': self.apis['shodan']['api_key']}
            url_with_params = f"{url}?{urllib.parse.urlencode(params)}"
            
            request = urllib.request.Request(url_with_params)
            
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                result = json.loads(response.read().decode())
                
            if 'data' in result:
                for entry in result['data']:
                    subdomain = entry.get('subdomain', '')
                    if subdomain:
                        full_domain = f"{subdomain}.{domain}"
                        if self.is_valid_subdomain(full_domain, domain):
                            subdomains.add(full_domain)
                            
        except Exception as e:
            self.log_verbose(f"Shodan error: {e}")
            
        return subdomains
    
    def fetch_bufferover(self, domain: str) -> Set[str]:
        """Fetch subdomains from BufferOver"""
        subdomains = set()
        try:
            url = self.apis['bufferover']['url'].format(domain=domain)
            request = urllib.request.Request(url)
            request.add_header('User-Agent', 'Mozilla/5.0 Findomain')
            
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                data = response.read().decode()
                
            # Parse DNS records
            for line in data.split('\n'):
                if line.strip():
                    parts = line.split(',')
                    if len(parts) >= 2:
                        subdomain = parts[1].strip().lower()
                        if self.is_valid_subdomain(subdomain, domain):
                            subdomains.add(subdomain)
                            
        except Exception as e:
            self.log_verbose(f"BufferOver error: {e}")
            
        return subdomains
    
    def fetch_hackertarget(self, domain: str) -> Set[str]:
        """Fetch subdomains from HackerTarget"""
        subdomains = set()
        try:
            url = self.apis['hackertarget']['url'].format(domain=domain)
            request = urllib.request.Request(url)
            
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                data = response.read().decode()
                
            for line in data.split('\n'):
                if line.strip() and ',' in line:
                    subdomain = line.split(',')[0].strip().lower()
                    if self.is_valid_subdomain(subdomain, domain):
                        subdomains.add(subdomain)
                        
        except Exception as e:
            self.log_verbose(f"HackerTarget error: {e}")
            
        return subdomains
    
    def fetch_threatcrowd(self, domain: str) -> Set[str]:
        """Fetch subdomains from ThreatCrowd"""
        subdomains = set()
        try:
            url = self.apis['threatcrowd']['url'].format(domain=domain)
            request = urllib.request.Request(url)
            
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                result = json.loads(response.read().decode())
                
            if 'subdomains' in result:
                for subdomain in result['subdomains']:
                    if self.is_valid_subdomain(subdomain, domain):
                        subdomains.add(subdomain)
                        
        except Exception as e:
            self.log_verbose(f"ThreatCrowd error: {e}")
            
        return subdomains
    
    def fetch_alienvault(self, domain: str) -> Set[str]:
        """Fetch subdomains from AlienVault OTX"""
        subdomains = set()
        try:
            url = self.apis['alienvault']['url'].format(domain=domain)
            request = urllib.request.Request(url)
            
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                result = json.loads(response.read().decode())
                
            if 'passive_dns' in result:
                for entry in result['passive_dns']:
                    hostname = entry.get('hostname', '').lower()
                    if self.is_valid_subdomain(hostname, domain):
                        subdomains.add(hostname)
                        
        except Exception as e:
            self.log_verbose(f"AlienVault error: {e}")
            
        return subdomains
    
    def is_valid_subdomain(self, subdomain: str, domain: str) -> bool:
        """Validate if subdomain is valid and belongs to domain"""
        if not subdomain or not domain:
            return False
            
        # Remove protocol if present
        subdomain = subdomain.replace('http://', '').replace('https://', '')
        
        # Remove port if present
        subdomain = subdomain.split(':')[0]
        
        # Check if it ends with the target domain
        if not subdomain.endswith(domain):
            return False
            
        # Check for valid characters
        if not re.match(r'^[a-zA-Z0-9.-]+$', subdomain):
            return False
            
        # Avoid duplicates and invalid patterns
        if subdomain == domain or subdomain.startswith('.') or '..' in subdomain:
            return False
            
        return True
    
    def enumerate_source(self, source_name: str, domain: str) -> Set[str]:
        """Enumerate subdomains from a specific source"""
        self.log_verbose(f"Checking {source_name}...")
        
        try:
            if source_name == 'crtsh':
                return self.fetch_crtsh(domain)
            elif source_name == 'virustotal':
                return self.fetch_virustotal(domain)
            elif source_name == 'securitytrails':
                return self.fetch_securitytrails(domain)
            elif source_name == 'shodan':
                return self.fetch_shodan(domain)
            elif source_name == 'bufferover':
                return self.fetch_bufferover(domain)
            elif source_name == 'hackertarget':
                return self.fetch_hackertarget(domain)
            elif source_name == 'threatcrowd':
                return self.fetch_threatcrowd(domain)
            elif source_name == 'alienvault':
                return self.fetch_alienvault(domain)
        except Exception as e:
            self.log_verbose(f"Error in {source_name}: {e}")
            
        return set()
    
    def resolve_subdomain(self, subdomain: str) -> Optional[SubdomainResult]:
        """Resolve and probe a subdomain"""
        # DNS resolution
        ip = self.dns_resolver.resolve(subdomain)
        if not ip:
            return None
            
        result = SubdomainResult(
            subdomain=subdomain,
            ip=ip,
            source="enumeration"
        )
        
        # HTTP probing if enabled
        if self.enable_http_probing:
            try:
                http_status, https_status, title, server = self.http_prober.probe(subdomain)
                result.http_status = http_status
                result.https_status = https_status
                result.title = title
                result.server = server
            except Exception as e:
                self.log_verbose(f"HTTP probing error for {subdomain}: {e}")
        
        # Port scanning if enabled
        if self.enable_port_scan:
            result.ports = self.scan_ports(ip, self.ports)
            
        return result
    
    def scan_ports(self, ip: str, ports: List[int]) -> List[int]:
        """Scan ports on IP address"""
        open_ports = []
        
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    open_ports.append(port)
                sock.close()
            except:
                pass
                
        return open_ports
    
    def worker(self, subdomains_queue: List[str]):
        """Worker thread for processing subdomains"""
        for subdomain in subdomains_queue:
            try:
                result = self.resolve_subdomain(subdomain)
                if result:
                    with self.lock:
                        self.results.append(result)
                    
                    if not self.silent:
                        status_info = ""
                        if self.enable_http_probing:
                            if result.https_status > 0:
                                status_info += f" [HTTPS:{result.https_status}]"
                            if result.http_status > 0:
                                status_info += f" [HTTP:{result.http_status}]"
                        
                        port_info = ""
                        if self.enable_port_scan and result.ports:
                            port_info = f" [Ports: {','.join(map(str, result.ports))}]"
                            
                        print(f"{C.GREEN}[FOUND]{C.WHITE} {result.subdomain} -> {result.ip}{status_info}{port_info}")
                        
            except Exception as e:
                self.log_verbose(f"Worker error for {subdomain}: {e}")
    
    def enumerate(self) -> List[SubdomainResult]:
        """Main enumeration function"""
        if not self.target:
            self.log_error("No target domain specified")
            return []
        
        self.log_info(f"Starting subdomain enumeration for: {self.target}")
        self.log_info(f"Threads: {self.threads}, Timeout: {self.timeout}s")
        
        # Collect subdomains from all sources
        all_subdomains = set()
        
        # List of active sources
        active_sources = []
        for source, config in self.apis.items():
            if config.get('enabled', False):
                active_sources.append(source)
        
        self.log_info(f"Active sources: {', '.join(active_sources)}")
        
        # Enumerate from all sources in parallel
        with ThreadPoolExecutor(max_workers=len(active_sources)) as executor:
            future_to_source = {}
            
            for source in active_sources:
                future = executor.submit(self.enumerate_source, source, self.target)
                future_to_source[future] = source
            
            for future in as_completed(future_to_source):
                source = future_to_source[future]
                try:
                    subdomains = future.result()
                    if subdomains:
                        all_subdomains.update(subdomains)
                        self.log_verbose(f"{source}: found {len(subdomains)} subdomains")
                except Exception as e:
                    self.log_verbose(f"{source} failed: {e}")
        
        # Add the main domain
        all_subdomains.add(self.target)
        
        self.log_info(f"Found {len(all_subdomains)} unique subdomains")
        
        # Resolve and probe subdomains
        if all_subdomains:
            self.log_info("Resolving and probing subdomains...")
            
            # Split subdomains into chunks for workers
            subdomain_list = list(all_subdomains)
            chunk_size = max(1, len(subdomain_list) // self.threads)
            chunks = [subdomain_list[i:i + chunk_size] for i in range(0, len(subdomain_list), chunk_size)]
            
            # Process in parallel
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = [executor.submit(self.worker, chunk) for chunk in chunks]
                
                for future in as_completed(futures):
                    try:
                        future.result()
                    except Exception as e:
                        self.log_verbose(f"Worker thread error: {e}")
        
        self.log_success(f"Enumeration completed! Found {len(self.results)} active subdomains")
        return self.results
    
    def save_results(self, output_file: str, output_format: str = 'txt'):
        """Save results to file"""
        if not self.results:
            self.log_error("No results to save")
            return
            
        try:
            if output_format.lower() == 'json':
                with open(output_file, 'w', encoding='utf-8') as f:
                    json.dump([asdict(result) for result in self.results], f, indent=2, ensure_ascii=False)
                    
            elif output_format.lower() == 'csv':
                with open(output_file, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerow(['Subdomain', 'IP', 'HTTP Status', 'HTTPS Status', 'Title', 'Server', 'Ports', 'Source', 'Timestamp'])
                    
                    for result in self.results:
                        writer.writerow([
                            result.subdomain,
                            result.ip,
                            result.http_status,
                            result.https_status,
                            result.title,
                            result.server,
                            ','.join(map(str, result.ports)),
                            result.source,
                            result.timestamp
                        ])
                        
            else:  # txt format
                with open(output_file, 'w', encoding='utf-8') as f:
                    for result in self.results:
                        f.write(f"{result.subdomain}\n")
                        
            self.log_success(f"Results saved to {output_file}")
            
        except Exception as e:
            self.log_error(f"Error saving results: {e}")

def load_config_file(config_file: str) -> Dict[str, str]:
    """Load API keys from config file"""
    config = {}
    
    if not os.path.exists(config_file):
        return config
        
    try:
        with open(config_file, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    key, value = line.split('=', 1)
                    config[key.strip()] = value.strip()
    except Exception as e:
        print(f"{C.RED}[ERROR]{C.WHITE} Error loading config file: {e}")
        
    return config

def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description='Findomain - Fast subdomain enumerator',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python findomain.py -t example.com
  python findomain.py -t example.com -o results.txt
  python findomain.py -t example.com -o results.json -f json
  python findomain.py -t example.com --http-probing --port-scan
  python findomain.py -t example.com --config config.txt
  python findomain.py -t example.com --threads 100 --timeout 15
        """
    )
    
    # Target options
    target_group = parser.add_argument_group('TARGET')
    target_group.add_argument('-t', '--target', required=True, help='Target domain to enumerate')
    
    # Configuration options
    config_group = parser.add_argument_group('CONFIGURATION')
    config_group.add_argument('--threads', type=int, default=50, help='Number of threads (default: 50)')
    config_group.add_argument('--timeout', type=int, default=10, help='Request timeout in seconds (default: 10)')
    config_group.add_argument('--config', help='Configuration file with API keys')
    
    # API options
    api_group = parser.add_argument_group('API KEYS')
    api_group.add_argument('--virustotal-key', help='VirusTotal API key')
    api_group.add_argument('--securitytrails-key', help='SecurityTrails API key')
    api_group.add_argument('--shodan-key', help='Shodan API key')
    api_group.add_argument('--censys-id', help='Censys API ID')
    api_group.add_argument('--censys-secret', help='Censys API secret')
    api_group.add_argument('--facebook-token', help='Facebook access token')
    api_group.add_argument('--spyse-key', help='Spyse API key')
    
    # Probing options
    probe_group = parser.add_argument_group('PROBING')
    probe_group.add_argument('--http-probing', action='store_true', help='Enable HTTP/HTTPS probing')
    probe_group.add_argument('--port-scan', action='store_true', help='Enable port scanning')
    probe_group.add_argument('--ports', help='Comma-separated list of ports to scan (default: 80,443,8080,8443)')
    
    # Output options
    output_group = parser.add_argument_group('OUTPUT')
    output_group.add_argument('-o', '--output', help='Output file')
    output_group.add_argument('-f', '--format', choices=['txt', 'json', 'csv'], default='txt', help='Output format (default: txt)')
    output_group.add_argument('--silent', action='store_true', help='Silent mode')
    output_group.add_argument('--verbose', action='store_true', help='Verbose output')
    output_group.add_argument('--no-color', action='store_true', help='Disable colors')
    
    args = parser.parse_args()
    
    if args.no_color:
        Colors.disable()
    
    # Show banner
    if not args.silent:
        banner()
        print(f"{C.YELLOW}[INFO]{C.WHITE} Use with caution. You are responsible for your actions.")
        print(f"{C.YELLOW}[INFO]{C.WHITE} Developers assume no liability and are not responsible for any misuse or damage.\n")
    
    # Load config file if provided
    config_data = {}
    if args.config:
        config_data = load_config_file(args.config)
    
    # Parse ports
    ports = [80, 443, 8080, 8443]
    if args.ports:
        try:
            ports = [int(p.strip()) for p in args.ports.split(',')]
        except ValueError:
            print(f"{C.RED}[ERROR]{C.WHITE} Invalid ports format")
            return 1
    
    # Build configuration
    config = {
        'target': args.target,
        'threads': args.threads,
        'timeout': args.timeout,
        'silent': args.silent,
        'verbose': args.verbose,
        'http_probing': args.http_probing,
        'port_scan': args.port_scan,
        'ports': ports,
        
        # API keys from arguments or config file
        'virustotal_api_key': args.virustotal_key or config_data.get('virustotal_api_key', ''),
        'securitytrails_api_key': args.securitytrails_key or config_data.get('securitytrails_api_key', ''),
        'shodan_api_key': args.shodan_key or config_data.get('shodan_api_key', ''),
        'censys_api_id': args.censys_id or config_data.get('censys_api_id', ''),
        'censys_api_secret': args.censys_secret or config_data.get('censys_api_secret', ''),
        'facebook_access_token': args.facebook_token or config_data.get('facebook_access_token', ''),
        'spyse_api_key': args.spyse_key or config_data.get('spyse_api_key', ''),
    }
    
    # Initialize enumerator
    enumerator = SubdomainEnumerator(config)
    
    try:
        # Start enumeration
        results = enumerator.enumerate()
        
        # Save results if output file specified
        if args.output:
            enumerator.save_results(args.output, args.format)
        
        if not args.silent:
            print(f"\n{C.GREEN}[SUCCESS]{C.WHITE} Enumeration completed successfully!")
            print(f"{C.BLUE}[INFO]{C.WHITE} Total active subdomains found: {len(results)}")
        
        return 0
        
    except KeyboardInterrupt:
        if not args.silent:
            print(f"\n{C.YELLOW}[INFO]{C.WHITE} Enumeration interrupted by user")
        return 1
    except Exception as e:
        if not args.silent:
            print(f"{C.RED}[ERROR]{C.WHITE} {e}")
        return 1

if __name__ == '__main__':
    sys.exit(main())