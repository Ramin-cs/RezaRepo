#!/usr/bin/env python3
"""
Sublist3r Enhanced - Simple Version (No External Dependencies)
Fast Subdomains Enumeration Tool

This version works with only Python standard library
Enhanced version of original Sublist3r by Ahmed Aboul-Ela (@aboul3la)
"""

import argparse
import json
import os
import re
import socket
import ssl
import sys
import threading
import time
import random
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Set, Optional, Dict, Any
from urllib.parse import urlparse, urlencode, quote
import urllib.request
import urllib.error

# Try to import DNS resolver
try:
    import dns.resolver
    HAS_DNS = True
except ImportError:
    HAS_DNS = False
    print("Warning: dnspython not found. Brute force will be disabled.")
    print("Install with: pip install dnspython")

# Console Colors
class Colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    RED = '\033[91m'
    WHITE = '\033[0m'
    BOLD = '\033[1m'
    
    @classmethod
    def disable(cls):
        cls.GREEN = cls.YELLOW = cls.BLUE = cls.RED = cls.WHITE = cls.BOLD = ''

# Global color instance
C = Colors()

def banner():
    """Display the banner"""
    ascii_art = f"""{C.RED}
                 ____        _     _ _     _   _____
                / ___| _   _| |__ | (_)___| |_|___ / _ __
                \\___ \\| | | | '_ \\| | / __| __| |_ \\| '__|
                 ___) | |_| | |_) | | \\__ \\ |_ ___) | |
                |____/ \\__,_|_.__/|_|_|___/\\__|____/|_|{C.WHITE}{C.YELLOW}

                # Enhanced Simple Version - No External Dependencies
                # Original by Ahmed Aboul-Ela - @aboul3la
    {C.WHITE}"""
    print(ascii_art)


class SubdomainEnumerator:
    """Base class for subdomain enumeration"""
    
    def __init__(self, domain: str, silent: bool = False, verbose: bool = True):
        self.domain = domain.lower().strip()
        self.silent = silent
        self.verbose = verbose
        self.subdomains = set()
        self.timeout = 10
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        
        # SSL context
        self.ssl_context = ssl.create_default_context()
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_NONE
        
    def print_found(self, subdomain: str, source: str):
        """Print found subdomain"""
        if not self.silent and self.verbose:
            print(f"{C.RED}{source}: {C.WHITE}{subdomain}")
    
    def clean_domain(self, domain: str) -> str:
        """Clean and validate domain"""
        domain = domain.lower().strip()
        
        # Remove protocol
        if domain.startswith(('http://', 'https://')):
            domain = urlparse(domain).netloc
        
        # Remove wildcards
        if domain.startswith('*.'):
            domain = domain[2:]
        
        # Remove port
        if ':' in domain:
            domain = domain.split(':')[0]
        
        return domain
    
    def is_valid_subdomain(self, subdomain: str) -> bool:
        """Check if subdomain is valid and belongs to target domain"""
        if not subdomain:
            return False
        
        subdomain = self.clean_domain(subdomain)
        
        # Basic validation
        if not subdomain:
            return False
        
        # Check if it belongs to target domain
        return subdomain.endswith(self.domain) or subdomain == self.domain
    
    def add_subdomain(self, subdomain: str, source: str):
        """Add subdomain to results"""
        subdomain = self.clean_domain(subdomain)
        
        if self.is_valid_subdomain(subdomain) and subdomain not in self.subdomains:
            self.subdomains.add(subdomain)
            self.print_found(subdomain, source)
    
    def fetch_url(self, url: str, headers: Dict[str, str] = None) -> Optional[str]:
        """Fetch URL content using urllib"""
        try:
            request = urllib.request.Request(url)
            
            # Add headers
            for key, value in self.headers.items():
                request.add_header(key, value)
            
            if headers:
                for key, value in headers.items():
                    request.add_header(key, value)
            
            with urllib.request.urlopen(request, timeout=self.timeout, context=self.ssl_context) as response:
                if response.status == 200:
                    return response.read().decode('utf-8', errors='ignore')
        except Exception:
            pass
        return None
    
    def fetch_json(self, url: str, headers: Dict[str, str] = None) -> Optional[dict]:
        """Fetch JSON data"""
        content = self.fetch_url(url, headers)
        if content:
            try:
                return json.loads(content)
            except:
                pass
        return None


class HackerTargetEnumerator(SubdomainEnumerator):
    """HackerTarget enumeration"""
    
    def __init__(self, domain: str, silent: bool = False, verbose: bool = True):
        super().__init__(domain, silent, verbose)
        self.engine_name = "HackerTarget"
        self.base_url = "https://api.hackertarget.com/hostsearch/?q={domain}"
    
    def enumerate(self) -> Set[str]:
        """Enumerate using HackerTarget"""
        try:
            url = self.base_url.format(domain=self.domain)
            content = self.fetch_url(url)
            
            if content:
                lines = content.strip().split('\n')
                for line in lines:
                    if ',' in line:
                        subdomain = line.split(',')[0].strip()
                        self.add_subdomain(subdomain, self.engine_name)
        
        except Exception:
            pass
        
        return self.subdomains


class CrtShEnumerator(SubdomainEnumerator):
    """crt.sh enumeration"""
    
    def __init__(self, domain: str, silent: bool = False, verbose: bool = True):
        super().__init__(domain, silent, verbose)
        self.engine_name = "crt.sh"
        self.base_url = "https://crt.sh/?q=%.{domain}&output=json"
    
    def enumerate(self) -> Set[str]:
        """Enumerate using crt.sh"""
        try:
            url = self.base_url.format(domain=self.domain)
            data = self.fetch_json(url)
            
            if data:
                for item in data:
                    if 'name_value' in item:
                        names = item['name_value'].split('\n')
                        for name in names:
                            name = name.strip()
                            if name:
                                self.add_subdomain(name, self.engine_name)
        
        except Exception:
            pass
        
        return self.subdomains


class AnubisEnumerator(SubdomainEnumerator):
    """Anubis enumeration"""
    
    def __init__(self, domain: str, silent: bool = False, verbose: bool = True):
        super().__init__(domain, silent, verbose)
        self.engine_name = "Anubis"
        self.base_url = "https://jldc.me/anubis/subdomains/{domain}"
    
    def enumerate(self) -> Set[str]:
        """Enumerate using Anubis"""
        try:
            url = self.base_url.format(domain=self.domain)
            data = self.fetch_json(url)
            
            if data and isinstance(data, list):
                for subdomain in data:
                    self.add_subdomain(subdomain, self.engine_name)
        
        except Exception:
            pass
        
        return self.subdomains


class AlienVaultEnumerator(SubdomainEnumerator):
    """AlienVault OTX enumeration"""
    
    def __init__(self, domain: str, silent: bool = False, verbose: bool = True):
        super().__init__(domain, silent, verbose)
        self.engine_name = "AlienVault"
        self.base_url = "https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    
    def enumerate(self) -> Set[str]:
        """Enumerate using AlienVault OTX"""
        try:
            url = self.base_url.format(domain=self.domain)
            data = self.fetch_json(url)
            
            if data and 'passive_dns' in data:
                for item in data['passive_dns']:
                    if 'hostname' in item:
                        self.add_subdomain(item['hostname'], self.engine_name)
        
        except Exception:
            pass
        
        return self.subdomains


class ThreatCrowdEnumerator(SubdomainEnumerator):
    """ThreatCrowd enumeration"""
    
    def __init__(self, domain: str, silent: bool = False, verbose: bool = True):
        super().__init__(domain, silent, verbose)
        self.engine_name = "ThreatCrowd"
        self.base_url = "https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}"
    
    def enumerate(self) -> Set[str]:
        """Enumerate using ThreatCrowd"""
        try:
            url = self.base_url.format(domain=self.domain)
            data = self.fetch_json(url)
            
            if data and 'subdomains' in data:
                for subdomain in data['subdomains']:
                    self.add_subdomain(subdomain, self.engine_name)
        
        except Exception:
            pass
        
        return self.subdomains


class WaybackEnumerator(SubdomainEnumerator):
    """Wayback Machine enumeration"""
    
    def __init__(self, domain: str, silent: bool = False, verbose: bool = True):
        super().__init__(domain, silent, verbose)
        self.engine_name = "Wayback"
        self.base_url = "http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&collapse=urlkey"
    
    def enumerate(self) -> Set[str]:
        """Enumerate using Wayback Machine"""
        try:
            url = self.base_url.format(domain=self.domain)
            data = self.fetch_json(url)
            
            if data and isinstance(data, list):
                for item in data[1:]:  # Skip header
                    if len(item) >= 3:
                        try:
                            parsed_url = urlparse(item[2])
                            if parsed_url.hostname:
                                self.add_subdomain(parsed_url.hostname, self.engine_name)
                        except:
                            continue
        
        except Exception:
            pass
        
        return self.subdomains


class BruteForceEnumerator(SubdomainEnumerator):
    """Brute force enumeration"""
    
    def __init__(self, domain: str, wordlist: List[str] = None, threads: int = 50, silent: bool = False, verbose: bool = True):
        super().__init__(domain, silent, verbose)
        self.wordlist = wordlist or self.get_default_wordlist()
        self.threads = threads
        
        if HAS_DNS:
            self.resolver = dns.resolver.Resolver()
            self.resolver.timeout = 2
            self.resolver.lifetime = 5
    
    def get_default_wordlist(self) -> List[str]:
        """Get default subdomain wordlist"""
        return [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
            'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'mx', 'm', 'imap', 'test',
            'ns', 'blog', 'pop3', 'dev', 'www2', 'admin', 'forum', 'news', 'vpn', 'ns3',
            'mail2', 'new', 'mysql', 'old', 'lists', 'support', 'mobile', 'static', 'docs',
            'beta', 'shop', 'sql', 'secure', 'demo', 'cp', 'calendar', 'wiki', 'web',
            'media', 'email', 'images', 'img', 'www1', 'intranet', 'portal', 'video',
            'sip', 'dns2', 'api', 'cdn', 'stats', 'dns1', 'ns4', 'www3', 'dns', 'search',
            'staging', 'server', 'mx1', 'chat', 'wap', 'my', 'svn', 'mail1', 'sites',
            'proxy', 'ads', 'host', 'crm', 'cms', 'backup', 'mx2', 'lyncdiscover', 'info',
            'apps', 'download', 'remote', 'db', 'forums', 'store', 'relay', 'files'
        ]
    
    def check_subdomain(self, subdomain: str) -> bool:
        """Check if subdomain exists"""
        if not HAS_DNS:
            return False
        
        try:
            full_domain = f"{subdomain}.{self.domain}"
            self.resolver.resolve(full_domain, 'A')
            self.add_subdomain(full_domain, "BruteForce")
            return True
        except:
            return False
    
    def enumerate(self) -> Set[str]:
        """Enumerate using brute force"""
        if not HAS_DNS:
            if not self.silent:
                print(f"{C.YELLOW}[!] Brute force disabled - dnspython not installed{C.WHITE}")
            return self.subdomains
        
        if not self.silent:
            print(f"{C.YELLOW}[*] Starting brute force with {len(self.wordlist)} words{C.WHITE}")
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(self.check_subdomain, word) for word in self.wordlist]
            
            for future in as_completed(futures):
                try:
                    future.result()
                except:
                    pass
        
        return self.subdomains


class PortScanner:
    """Port scanner for found subdomains"""
    
    def __init__(self, ports: List[int], timeout: int = 3, threads: int = 100):
        self.ports = ports
        self.timeout = timeout
        self.threads = threads
    
    def scan_port(self, host: str, port: int) -> bool:
        """Scan single port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except:
            return False
    
    def scan_host(self, host: str) -> Dict[int, bool]:
        """Scan all ports for a host"""
        results = {}
        
        with ThreadPoolExecutor(max_workers=min(len(self.ports), 20)) as executor:
            futures = {executor.submit(self.scan_port, host, port): port for port in self.ports}
            
            for future in as_completed(futures):
                port = futures[future]
                try:
                    results[port] = future.result()
                except:
                    results[port] = False
        
        return results
    
    def scan_subdomains(self, subdomains: Set[str]) -> Dict[str, Dict[int, bool]]:
        """Scan ports for all subdomains"""
        results = {}
        
        with ThreadPoolExecutor(max_workers=min(len(subdomains), 50)) as executor:
            futures = {executor.submit(self.scan_host, host): host for host in subdomains}
            
            for future in as_completed(futures):
                host = futures[future]
                try:
                    results[host] = future.result()
                except:
                    results[host] = {}
        
        return results


class Sublist3r:
    """Main Sublist3r class"""
    
    def __init__(self, domain: str, engines: List[str] = None, threads: int = 50, 
                 silent: bool = False, verbose: bool = True, enable_bruteforce: bool = False,
                 ports: List[int] = None, savefile: str = None):
        self.domain = domain.lower().strip()
        self.engines = engines or ['all']
        self.threads = threads
        self.silent = silent
        self.verbose = verbose
        self.enable_bruteforce = enable_bruteforce
        self.ports = ports
        self.savefile = savefile
        self.subdomains = set()
        
        # Available engines
        self.available_engines = {
            'hackertarget': HackerTargetEnumerator,
            'crtsh': CrtShEnumerator,
            'anubis': AnubisEnumerator,
            'alienvault': AlienVaultEnumerator,
            'threatcrowd': ThreatCrowdEnumerator,
            'wayback': WaybackEnumerator,
        }
        
        if 'all' in self.engines or not self.engines:
            self.engines = list(self.available_engines.keys())
    
    def print_info(self, message: str):
        """Print info message"""
        if not self.silent:
            print(f"{C.YELLOW}[*] {message}{C.WHITE}")
    
    def enumerate_sources(self):
        """Enumerate using available sources"""
        self.print_info(f"Enumerating subdomains for {self.domain}")
        
        def run_engine(engine_name):
            if engine_name in self.available_engines:
                try:
                    engine_class = self.available_engines[engine_name]
                    enumerator = engine_class(self.domain, self.silent, self.verbose)
                    domains = enumerator.enumerate()
                    return domains
                except Exception as e:
                    if self.verbose:
                        print(f"{C.RED}Error with {engine_name}: {e}{C.WHITE}")
                    return set()
            return set()
        
        # Run engines in parallel
        with ThreadPoolExecutor(max_workers=min(len(self.engines), 6)) as executor:
            futures = {executor.submit(run_engine, engine): engine for engine in self.engines}
            
            for future in as_completed(futures):
                engine = futures[future]
                try:
                    domains = future.result()
                    self.subdomains.update(domains)
                except Exception as e:
                    if self.verbose:
                        print(f"{C.RED}Error with {engine}: {e}{C.WHITE}")
    
    def run_bruteforce(self):
        """Run brute force enumeration"""
        if self.enable_bruteforce:
            self.print_info("Starting brute force enumeration")
            brute_forcer = BruteForceEnumerator(self.domain, threads=self.threads, 
                                              silent=self.silent, verbose=self.verbose)
            domains = brute_forcer.enumerate()
            self.subdomains.update(domains)
    
    def scan_ports(self):
        """Scan ports on found subdomains"""
        if self.ports:
            self.print_info(f"Scanning ports {self.ports} on found subdomains")
            scanner = PortScanner(self.ports, threads=self.threads)
            results = scanner.scan_subdomains(self.subdomains)
            
            # Filter subdomains with open ports
            filtered_subdomains = set()
            for host, port_results in results.items():
                if any(port_results.values()):
                    filtered_subdomains.add(host)
                    if self.verbose:
                        open_ports = [port for port, is_open in port_results.items() if is_open]
                        print(f"{C.GREEN}[+] {host} - Open ports: {open_ports}{C.WHITE}")
            
            self.subdomains = filtered_subdomains
    
    def save_results(self):
        """Save results to file"""
        if self.savefile:
            try:
                with open(self.savefile, 'w') as f:
                    for subdomain in sorted(self.subdomains):
                        f.write(f"{subdomain}\n")
                self.print_info(f"Results saved to {self.savefile}")
            except Exception as e:
                print(f"{C.RED}Error saving file: {e}{C.WHITE}")
    
    def run(self) -> Set[str]:
        """Main enumeration function"""
        if not self.silent:
            banner()
            self.print_info(f"Starting enumeration for {self.domain}")
        
        # Run different enumeration methods
        self.enumerate_sources()
        self.run_bruteforce()
        
        # Scan ports if specified
        self.scan_ports()
        
        # Save results
        self.save_results()
        
        # Print summary
        if not self.silent:
            print(f"\n{C.GREEN}[+] Total unique subdomains found: {len(self.subdomains)}{C.WHITE}")
            
            if self.verbose:
                for subdomain in sorted(self.subdomains):
                    print(f"{C.WHITE}{subdomain}")
        else:
            # In silent mode, just print the subdomains
            for subdomain in sorted(self.subdomains):
                print(subdomain)
        
        return self.subdomains


def main(domain: str = None, no_threads: int = 50, savefile: str = None, 
         ports: List[int] = None, silent: bool = False, verbose: bool = True, 
         enable_bruteforce: bool = False, engines: List[str] = None) -> Set[str]:
    """Main function for module usage"""
    
    if not domain:
        return set()
    
    sublist3r = Sublist3r(
        domain=domain,
        engines=engines,
        threads=no_threads,
        silent=silent,
        verbose=verbose,
        enable_bruteforce=enable_bruteforce,
        ports=ports,
        savefile=savefile
    )
    
    return sublist3r.run()


def parse_ports(ports_str: str) -> List[int]:
    """Parse ports string to list of integers"""
    if not ports_str:
        return []
    
    ports = []
    for part in ports_str.split(','):
        part = part.strip()
        if '-' in part:
            start, end = map(int, part.split('-'))
            ports.extend(range(start, end + 1))
        else:
            ports.append(int(part))
    
    return ports


def cli():
    """Command line interface"""
    parser = argparse.ArgumentParser(
        description='Sublist3r Enhanced - Simple Version (No External Dependencies)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python sublist3r_simple.py -d example.com
  python sublist3r_simple.py -d example.com -b -v
  python sublist3r_simple.py -d example.com -p 80,443 -o results.txt
  python sublist3r_simple.py -d example.com -e hackertarget,crtsh
  python sublist3r_simple.py -d example.com -t 100 --silent

Available engines: hackertarget, crtsh, anubis, alienvault, threatcrowd, wayback
        """
    )
    
    parser.add_argument('-d', '--domain', required=True,
                       help='Domain name to enumerate subdomains')
    parser.add_argument('-b', '--bruteforce', action='store_true',
                       help='Enable brute force enumeration (requires dnspython)')
    parser.add_argument('-p', '--ports', 
                       help='Scan found subdomains against specified tcp ports')
    parser.add_argument('-t', '--threads', type=int, default=50,
                       help='Number of threads (default: 50)')
    parser.add_argument('-e', '--engines',
                       help='Specify comma-separated list of engines')
    parser.add_argument('-o', '--output',
                       help='Save results to text file')
    parser.add_argument('-v', '--verbose', action='store_true', default=True,
                       help='Enable verbose mode (default)')
    parser.add_argument('--silent', action='store_true',
                       help='Enable silent mode')
    parser.add_argument('--no-color', action='store_true',
                       help='Disable colored output')
    
    args = parser.parse_args()
    
    if args.no_color:
        Colors.disable()
    
    if args.silent:
        args.verbose = False
    
    # Parse engines
    engines = None
    if args.engines:
        engines = [e.strip().lower() for e in args.engines.split(',')]
    
    # Parse ports
    ports = None
    if args.ports:
        ports = parse_ports(args.ports)
    
    # Run enumeration
    try:
        subdomains = main(
            domain=args.domain,
            no_threads=args.threads,
            savefile=args.output,
            ports=ports,
            silent=args.silent,
            verbose=args.verbose,
            enable_bruteforce=args.bruteforce,
            engines=engines
        )
        
        return len(subdomains)
    
    except KeyboardInterrupt:
        print(f"\n{C.RED}[!] Enumeration interrupted by user{C.WHITE}")
        return 0
    except Exception as e:
        print(f"{C.RED}[!] Error: {e}{C.WHITE}")
        return 0


if __name__ == '__main__':
    sys.exit(cli())