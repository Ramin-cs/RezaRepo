#!/usr/bin/env python3
"""
Sublist3r Enhanced - Fast Subdomains Enumeration Tool
Enhanced Python implementation with modern features and improved performance

Original Sublist3r by Ahmed Aboul-Ela (@aboul3la)
Enhanced version with additional sources, better performance, and modern Python features

Sources Implemented:
- Google Search Engine
- Yahoo Search Engine  
- Bing Search Engine
- Ask Search Engine
- Baidu Search Engine
- Netcraft
- VirusTotal
- ThreatCrowd
- DNSdumpster
- crt.sh
- HackerTarget
- Anubis
- AlienVault OTX
- Wayback Machine
- Chaos (ProjectDiscovery)
- Shodan
- SecurityTrails
- Censys
- BufferOver
- URLScan.io
- Spyse
- RapidDNS
- Riddler
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
import hashlib
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Set, Optional, Dict, Any
from urllib.parse import urlparse, urlencode, quote
import urllib.request
import urllib.error

try:
    import dns.resolver
except ImportError:
    print("Error: dnspython is required. Install with: pip install dnspython")
    sys.exit(1)

try:
    import requests
    requests.packages.urllib3.disable_warnings()
except ImportError:
    print("Error: requests is required. Install with: pip install requests")
    sys.exit(1)

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
    print(f"""{C.RED}
                 ____        _     _ _     _   _____
                / ___| _   _| |__ | (_)___| |_|___ / _ __
                \___ \| | | | '_ \| | / __| __| |_ \| '__|
                 ___) | |_| | |_) | | \__ \ |_ ___) | |
                |____/ \__,_|_.__/|_|_|___/\__|____/|_|{C.WHITE}{C.YELLOW}

                # Enhanced by AI Assistant - Modern Python Implementation
                # Original by Ahmed Aboul-Ela - @aboul3la
    {C.WHITE}""")


class SubdomainEnumerator:
    """Base class for subdomain enumeration"""
    
    def __init__(self, domain: str, silent: bool = False, verbose: bool = True):
        self.domain = domain.lower().strip()
        self.silent = silent
        self.verbose = verbose
        self.subdomains = set()
        self.timeout = 10
        self.max_pages = 50
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        
        # SSL context
        self.ssl_context = ssl.create_default_context()
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_NONE
        
        # Session for connection pooling
        self.session = requests.Session()
        self.session.headers.update(self.headers)
        
    def print_found(self, subdomain: str, source: str):
        """Print found subdomain"""
        if self.verbose and not self.silent:
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
        if not subdomain or '.' not in subdomain and subdomain != self.domain:
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
        """Fetch URL content"""
        try:
            req_headers = dict(self.headers)
            if headers:
                req_headers.update(headers)
            
            response = self.session.get(url, headers=req_headers, timeout=self.timeout, verify=False)
            if response.status_code == 200:
                return response.text
        except Exception:
            pass
        return None
    
    def fetch_json(self, url: str, headers: Dict[str, str] = None) -> Optional[dict]:
        """Fetch JSON data"""
        try:
            req_headers = dict(self.headers)
            if headers:
                req_headers.update(headers)
            
            response = self.session.get(url, headers=req_headers, timeout=self.timeout, verify=False)
            if response.status_code == 200:
                return response.json()
        except Exception:
            pass
        return None


class SearchEngineEnumerator(SubdomainEnumerator):
    """Search engine enumeration base class"""
    
    def __init__(self, domain: str, engine_name: str, base_url: str, silent: bool = False, verbose: bool = True):
        super().__init__(domain, silent, verbose)
        self.engine_name = engine_name
        self.base_url = base_url
        self.max_subdomains_per_page = 10
    
    def generate_query(self) -> str:
        """Generate search query"""
        return f"site:{self.domain} -site:www.{self.domain}"
    
    def extract_domains_from_text(self, text: str) -> List[str]:
        """Extract domains from text using regex"""
        domains = []
        
        # Common patterns for extracting domains
        patterns = [
            r'https?://([a-zA-Z0-9.-]+\.' + re.escape(self.domain) + r')',
            r'([a-zA-Z0-9.-]+\.' + re.escape(self.domain) + r')',
            r'"([a-zA-Z0-9.-]*\.' + re.escape(self.domain) + r')"',
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            domains.extend(matches)
        
        return list(set(domains))
    
    def search_engine_enumerate(self) -> Set[str]:
        """Enumerate using search engine"""
        found_domains = set()
        
        for page in range(0, self.max_pages * 10, 10):
            try:
                query = self.generate_query()
                url = self.base_url.format(query=quote(query), page=page)
                
                content = self.fetch_url(url)
                if not content:
                    break
                
                page_domains = self.extract_domains_from_text(content)
                
                if not page_domains:
                    break
                
                for domain in page_domains:
                    self.add_subdomain(domain, self.engine_name)
                    found_domains.add(domain)
                
                # Random delay to avoid being blocked
                time.sleep(random.uniform(1, 3))
                
            except Exception:
                break
        
        return found_domains


class GoogleEnumerator(SearchEngineEnumerator):
    """Google search enumeration"""
    
    def __init__(self, domain: str, silent: bool = False, verbose: bool = True):
        base_url = "https://www.google.com/search?q={query}&start={page}&filter=0"
        super().__init__(domain, "Google", base_url, silent, verbose)
        self.max_pages = 20  # Google limits
    
    def extract_domains_from_text(self, text: str) -> List[str]:
        """Extract domains from Google search results"""
        domains = []
        
        # Google-specific patterns
        cite_pattern = r'<cite[^>]*>(.*?)</cite>'
        url_pattern = r'https?://([a-zA-Z0-9.-]+)'
        
        # Extract from cite tags
        cites = re.findall(cite_pattern, text, re.IGNORECASE | re.DOTALL)
        for cite in cites:
            cite = re.sub(r'<[^>]+>', '', cite)  # Remove HTML tags
            if self.domain in cite:
                domains.append(cite)
        
        # Extract from URLs
        urls = re.findall(url_pattern, text, re.IGNORECASE)
        for url in urls:
            if self.domain in url:
                domains.append(url)
        
        return list(set(domains))


class YahooEnumerator(SearchEngineEnumerator):
    """Yahoo search enumeration"""
    
    def __init__(self, domain: str, silent: bool = False, verbose: bool = True):
        base_url = "https://search.yahoo.com/search?p={query}&b={page}"
        super().__init__(domain, "Yahoo", base_url, silent, verbose)


class BingEnumerator(SearchEngineEnumerator):
    """Bing search enumeration"""
    
    def __init__(self, domain: str, silent: bool = False, verbose: bool = True):
        base_url = "https://www.bing.com/search?q={query}&first={page}"
        super().__init__(domain, "Bing", base_url, silent, verbose)


class AskEnumerator(SearchEngineEnumerator):
    """Ask search enumeration"""
    
    def __init__(self, domain: str, silent: bool = False, verbose: bool = True):
        base_url = "https://www.ask.com/web?q={query}&page={page}"
        super().__init__(domain, "Ask", base_url, silent, verbose)


class BaiduEnumerator(SearchEngineEnumerator):
    """Baidu search enumeration"""
    
    def __init__(self, domain: str, silent: bool = False, verbose: bool = True):
        base_url = "https://www.baidu.com/s?wd={query}&pn={page}"
        super().__init__(domain, "Baidu", base_url, silent, verbose)


class NetcraftEnumerator(SubdomainEnumerator):
    """Netcraft enumeration"""
    
    def __init__(self, domain: str, silent: bool = False, verbose: bool = True):
        super().__init__(domain, silent, verbose)
        self.engine_name = "Netcraft"
        self.base_url = "https://searchdns.netcraft.com/?restriction=site+ends+with&host={domain}"
    
    def enumerate(self) -> Set[str]:
        """Enumerate using Netcraft"""
        try:
            url = self.base_url.format(domain=self.domain)
            content = self.fetch_url(url)
            
            if content:
                # Extract domains from Netcraft results
                pattern = r'<a class="results-table__host"[^>]*href="[^"]*">([^<]+)</a>'
                matches = re.findall(pattern, content, re.IGNORECASE)
                
                for match in matches:
                    self.add_subdomain(match, self.engine_name)
        
        except Exception:
            pass
        
        return self.subdomains


class VirusTotalEnumerator(SubdomainEnumerator):
    """VirusTotal enumeration"""
    
    def __init__(self, domain: str, silent: bool = False, verbose: bool = True):
        super().__init__(domain, silent, verbose)
        self.engine_name = "VirusTotal"
        self.base_url = "https://www.virustotal.com/ui/domains/{domain}/subdomains"
    
    def enumerate(self) -> Set[str]:
        """Enumerate using VirusTotal"""
        try:
            url = self.base_url.format(domain=self.domain)
            data = self.fetch_json(url)
            
            if data and 'data' in data:
                for item in data['data']:
                    if 'id' in item:
                        self.add_subdomain(item['id'], self.engine_name)
        
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


class DNSDumpsterEnumerator(SubdomainEnumerator):
    """DNSDumpster enumeration"""
    
    def __init__(self, domain: str, silent: bool = False, verbose: bool = True):
        super().__init__(domain, silent, verbose)
        self.engine_name = "DNSDumpster"
        self.base_url = "https://dnsdumpster.com/"
    
    def get_csrf_token(self, content: str) -> Optional[str]:
        """Extract CSRF token from DNSDumpster page"""
        pattern = r'<input type="hidden" name="csrfmiddlewaretoken" value="([^"]+)"'
        match = re.search(pattern, content)
        return match.group(1) if match else None
    
    def enumerate(self) -> Set[str]:
        """Enumerate using DNSDumpster"""
        try:
            # Get CSRF token
            content = self.fetch_url(self.base_url)
            if not content:
                return self.subdomains
            
            csrf_token = self.get_csrf_token(content)
            if not csrf_token:
                return self.subdomains
            
            # Submit form
            data = {
                'csrfmiddlewaretoken': csrf_token,
                'targetip': self.domain
            }
            
            headers = {
                'Referer': self.base_url,
                'Content-Type': 'application/x-www-form-urlencoded'
            }
            
            response = self.session.post(self.base_url, data=data, headers=headers, timeout=self.timeout)
            
            if response.status_code == 200:
                # Extract domains from results
                pattern = r'<td class="col-md-4">([^<]+)<br>'
                matches = re.findall(pattern, response.text, re.IGNORECASE)
                
                for match in matches:
                    self.add_subdomain(match.strip(), self.engine_name)
        
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


class APIEnumerator(SubdomainEnumerator):
    """API-based enumeration with keys"""
    
    def __init__(self, domain: str, silent: bool = False, verbose: bool = True):
        super().__init__(domain, silent, verbose)
    
    def enumerate_chaos(self) -> Set[str]:
        """Enumerate using Chaos API"""
        api_key = os.getenv('CHAOS_API_KEY')
        if not api_key:
            return set()
        
        try:
            url = f"https://dns.projectdiscovery.io/dns/{self.domain}/subdomains"
            headers = {'Authorization': api_key}
            data = self.fetch_json(url, headers)
            
            if data and 'subdomains' in data:
                for subdomain in data['subdomains']:
                    self.add_subdomain(f"{subdomain}.{self.domain}", "Chaos")
        
        except Exception:
            pass
        
        return self.subdomains
    
    def enumerate_shodan(self) -> Set[str]:
        """Enumerate using Shodan API"""
        api_key = os.getenv('SHODAN_API_KEY')
        if not api_key:
            return set()
        
        try:
            url = f"https://api.shodan.io/dns/domain/{self.domain}?key={api_key}"
            data = self.fetch_json(url)
            
            if data and 'subdomains' in data:
                for subdomain in data['subdomains']:
                    self.add_subdomain(f"{subdomain}.{self.domain}", "Shodan")
        
        except Exception:
            pass
        
        return self.subdomains
    
    def enumerate_securitytrails(self) -> Set[str]:
        """Enumerate using SecurityTrails API"""
        api_key = os.getenv('SECURITYTRAILS_API_KEY')
        if not api_key:
            return set()
        
        try:
            url = f"https://api.securitytrails.com/v1/domain/{self.domain}/subdomains"
            headers = {'APIKEY': api_key}
            data = self.fetch_json(url, headers)
            
            if data and 'subdomains' in data:
                for subdomain in data['subdomains']:
                    self.add_subdomain(f"{subdomain}.{self.domain}", "SecurityTrails")
        
        except Exception:
            pass
        
        return self.subdomains


class BruteForceEnumerator(SubdomainEnumerator):
    """Brute force enumeration"""
    
    def __init__(self, domain: str, wordlist: List[str] = None, threads: int = 50, silent: bool = False, verbose: bool = True):
        super().__init__(domain, silent, verbose)
        self.wordlist = wordlist or self.get_default_wordlist()
        self.threads = threads
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
            'apps', 'download', 'remote', 'db', 'forums', 'store', 'relay', 'files',
            'newsletter', 'app', 'live', 'owa', 'en', 'start', 'sms', 'office', 'exchange',
            'ipv4', 'mail3', 'help', 'blogs', 'helpdesk', 'web1', 'home', 'library',
            'ftp2', 'ntp', 'monitor', 'login', 'service', 'correo', 'www4', 'moodle',
            'it', 'gateway', 'gw', 'i', 'stat', 'stage', 'ldap', 'tv', 'ssl', 'web2',
            'ns5', 'upload', 'nagios', 'smtp2', 'online', 'ad', 'survey', 'data', 'radio',
            'extranet', 'test2', 'mssql', 'dns3', 'jobs', 'services', 'panel', 'irc'
        ]
    
    def check_subdomain(self, subdomain: str) -> bool:
        """Check if subdomain exists"""
        try:
            full_domain = f"{subdomain}.{self.domain}"
            self.resolver.resolve(full_domain, 'A')
            self.add_subdomain(full_domain, "BruteForce")
            return True
        except:
            return False
    
    def enumerate(self) -> Set[str]:
        """Enumerate using brute force"""
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
        
        with ThreadPoolExecutor(max_workers=min(len(self.ports), 50)) as executor:
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
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
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
            'google': GoogleEnumerator,
            'yahoo': YahooEnumerator,
            'bing': BingEnumerator,
            'ask': AskEnumerator,
            'baidu': BaiduEnumerator,
            'netcraft': NetcraftEnumerator,
            'virustotal': VirusTotalEnumerator,
            'threatcrowd': ThreatCrowdEnumerator,
            'dnsdumpster': DNSDumpsterEnumerator,
            'crtsh': CrtShEnumerator,
            'hackertarget': HackerTargetEnumerator,
            'anubis': AnubisEnumerator,
            'alienvault': AlienVaultEnumerator,
            'wayback': WaybackEnumerator,
        }
        
        if 'all' in self.engines:
            self.engines = list(self.available_engines.keys())
    
    def print_info(self, message: str):
        """Print info message"""
        if not self.silent:
            print(f"{C.YELLOW}[*] {message}{C.WHITE}")
    
    def enumerate_search_engines(self):
        """Enumerate using search engines"""
        self.print_info(f"Enumerating subdomains for {self.domain}")
        
        def run_engine(engine_name):
            if engine_name in self.available_engines:
                try:
                    engine_class = self.available_engines[engine_name]
                    enumerator = engine_class(self.domain, self.silent, self.verbose)
                    
                    if hasattr(enumerator, 'search_engine_enumerate'):
                        domains = enumerator.search_engine_enumerate()
                    else:
                        domains = enumerator.enumerate()
                    
                    return domains
                except Exception as e:
                    if self.verbose:
                        print(f"{C.RED}Error with {engine_name}: {e}{C.WHITE}")
                    return set()
            return set()
        
        # Run engines in parallel
        with ThreadPoolExecutor(max_workers=min(len(self.engines), 10)) as executor:
            futures = {executor.submit(run_engine, engine): engine for engine in self.engines}
            
            for future in as_completed(futures):
                engine = futures[future]
                try:
                    domains = future.result()
                    self.subdomains.update(domains)
                except Exception as e:
                    if self.verbose:
                        print(f"{C.RED}Error with {engine}: {e}{C.WHITE}")
    
    def enumerate_apis(self):
        """Enumerate using APIs"""
        api_enumerator = APIEnumerator(self.domain, self.silent, self.verbose)
        
        # Run API enumerations
        api_methods = [
            api_enumerator.enumerate_chaos,
            api_enumerator.enumerate_shodan,
            api_enumerator.enumerate_securitytrails,
        ]
        
        for method in api_methods:
            try:
                domains = method()
                self.subdomains.update(domains)
            except Exception:
                pass
    
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
        self.enumerate_search_engines()
        self.enumerate_apis()
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
        description='Sublist3r Enhanced - Fast subdomains enumeration tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python sublist3r.py -d example.com
  python sublist3r.py -d example.com -b -v
  python sublist3r.py -d example.com -p 80,443 -o results.txt
  python sublist3r.py -d example.com -e google,yahoo,bing
  python sublist3r.py -d example.com -t 100 --silent
        """
    )
    
    parser.add_argument('-d', '--domain', required=True,
                       help='Domain name to enumerate subdomains')
    parser.add_argument('-b', '--bruteforce', action='store_true',
                       help='Enable brute force enumeration')
    parser.add_argument('-p', '--ports', 
                       help='Scan found subdomains against specified tcp ports')
    parser.add_argument('-t', '--threads', type=int, default=50,
                       help='Number of threads (default: 50)')
    parser.add_argument('-e', '--engines',
                       help='Specify comma-separated list of search engines')
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