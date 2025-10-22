#!/usr/bin/env python3
"""
🔍 Advanced Subdomain Enumeration Tool
Combines the best features from multiple tools:
- Certificate Transparency (crt.sh, Censys)
- DNS Brute Force (with wordlists)
- Search Engines (Google, Bing, Yahoo)
- GitHub Code Search
- Chaos API (ProjectDiscovery)
- DNS Zone Transfer
- Reverse DNS Lookups
- VHost Discovery
- Passive DNS Sources
- Shodan Integration
- VirusTotal API
- SecurityTrails API
- Web Archives (Wayback Machine)
"""

import requests
import json
import re
import dns.resolver
import dns.zone
import dns.query
import time
import threading
import argparse
import sys
import os
import socket
import ssl
import urllib.parse
from urllib.parse import urlparse
import base64
import random
import concurrent.futures
from datetime import datetime
import subprocess
import hashlib
from collections import defaultdict
import ipaddress
from urllib3.exceptions import InsecureRequestWarning
import warnings

# Suppress SSL warnings
warnings.filterwarnings('ignore', category=InsecureRequestWarning)

class Colors:
    """ANSI color codes for terminal output"""
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

class HttpxProbe:
    """HTTP/HTTPS probing functionality similar to httpx"""
    
    def __init__(self, timeout=10, threads=50):
        self.timeout = timeout
        self.threads = threads
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            'User-Agent': 'httpx/1.3.0',
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive'
        })
    
    def probe_url(self, url, protocols=['http', 'https']):
        """Probe a URL with HTTP/HTTPS protocols"""
        results = {}
        
        for protocol in protocols:
            full_url = f"{protocol}://{url}"
            try:
                start_time = time.time()
                response = self.session.get(
                    full_url, 
                    timeout=self.timeout, 
                    allow_redirects=True,
                    stream=True
                )
                response_time = round((time.time() - start_time) * 1000, 2)
                
                # Get title from HTML
                title = self.extract_title(response)
                
                # Get content length
                content_length = len(response.content) if response.content else 0
                
                # Get server header
                server = response.headers.get('Server', 'Unknown')
                
                results[protocol] = {
                    'status_code': response.status_code,
                    'title': title,
                    'content_length': content_length,
                    'response_time': response_time,
                    'server': server,
                    'url': full_url,
                    'final_url': response.url
                }
                
            except requests.exceptions.Timeout:
                results[protocol] = {'error': 'timeout'}
            except requests.exceptions.ConnectionError:
                results[protocol] = {'error': 'connection_error'}
            except requests.exceptions.RequestException as e:
                results[protocol] = {'error': str(e)}
            except Exception as e:
                results[protocol] = {'error': f'unknown_error: {str(e)}'}
        
        return results
    
    def extract_title(self, response):
        """Extract title from HTML response"""
        try:
            if 'text/html' in response.headers.get('Content-Type', ''):
                content = response.text
                title_match = re.search(r'<title[^>]*>(.*?)</title>', content, re.IGNORECASE | re.DOTALL)
                if title_match:
                    title = title_match.group(1).strip()
                    # Clean up title
                    title = re.sub(r'\s+', ' ', title)
                    return title[:100]  # Limit title length
            return 'No Title'
        except:
            return 'No Title'
    
    def categorize_status_code(self, status_code):
        """Categorize HTTP status codes"""
        if 200 <= status_code < 300:
            return 'success', Colors.GREEN
        elif 300 <= status_code < 400:
            return 'redirect', Colors.YELLOW
        elif 400 <= status_code < 500:
            return 'client_error', Colors.RED
        elif 500 <= status_code < 600:
            return 'server_error', Colors.MAGENTA
        else:
            return 'unknown', Colors.WHITE

class SubdomainEnumerator:
    def __init__(self, domain, output_file=None, threads=50, timeout=10, verbose=False, httpx_check=True):
        self.domain = domain.lower().strip()
        self.output_file = output_file or f"{self.domain}_subdomains.txt"
        self.threads = threads
        self.timeout = timeout
        self.verbose = verbose
        self.httpx_check = httpx_check
        self.subdomains = set()
        self.live_subdomains = {}  # Store live subdomains with their status
        self.lock = threading.Lock()
        self.session = requests.Session()
        
        # Configure session for httpx-like behavior
        self.session.verify = False
        self.session.headers.update({
            'User-Agent': 'httpx/1.3.0'
        })
        
        # User agents for rotation
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0'
        ]
        
        # Common subdomain wordlist
        self.wordlist = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk', 'ns2',
            'cpanel', 'whm', 'autodiscover', 'autoconfig', 'mx', 'm', 'imap', 'test', 'ns', 'blog',
            'pop3', 'dev', 'www2', 'admin', 'forum', 'news', 'vpn', 'ns3', 'mail2', 'new', 'mysql',
            'old', 'lists', 'support', 'mobile', 'static', 'docs', 'beta', 'shop', 'sql', 'secure',
            'demo', 'cp', 'calendar', 'wiki', 'web', 'media', 'email', 'images', 'img', 'www1',
            'intranet', 'portal', 'video', 'sip', 'dns2', 'api', 'cdn', 'stats', 'dns1', 'ns4',
            'www3', 'dns', 'search', 'staging', 'server', 'mx1', 'chat', 'wap', 'my', 'svn',
            'mail1', 'sites', 'proxy', 'ads', 'host', 'crm', 'cms', 'backup', 'mx2', 'lyncdiscover',
            'info', 'apps', 'download', 'remote', 'db', 'forums', 'store', 'relay', 'files',
            'newsletter', 'app', 'live', 'owa', 'en', 'start', 'sms', 'office', 'exchange',
            'ipv4', 'mail3', 'help', 'blogs', 'helpdesk', 'web1', 'home', 'library', 'ftp2',
            'ntp', 'monitor', 'login', 'service', 'correo', 'www4', 'moodle', 'it', 'gateway',
            'gw', 'i', 'stat', 'stage', 'ldap', 'tv', 'ssl', 'web2', 'ns5', 'upload', 'nagios',
            'smtp2', 'online', 'ad', 'survey', 'data', 'radio', 'extranet', 'test2', 'mssql',
            'dns3', 'jobs', 'services', 'panel', 'irc', 'hosting', 'cloud', 'de', 'gmail',
            's', 'bbs', 'cs', 'ww', 'mrtg', 'review', 'avalon', 'cc', 'xe', 'www5', 'ovpn',
            'links', 'logs', 'rss', 'move', 'weather', 'www6', 'c', 'find', 'ssl2', 'sql2'
        ]
        
        # Extended wordlist for thorough enumeration
        self.extended_wordlist = [
            'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p',
            'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5',
            '6', '7', '8', '9', '10', 'api1', 'api2', 'api3', 'app1', 'app2', 'app3', 'db1',
            'db2', 'db3', 'web01', 'web02', 'web03', 'prod', 'production', 'staging1', 'staging2',
            'dev1', 'dev2', 'dev3', 'test1', 'test3', 'qa', 'uat', 'preprod', 'sandbox',
            # Persian/Farsi common subdomains
            'panel', 'control', 'manage', 'manager', 'dashboard', 'console2', 'cp2', 'admin2',
            'backend', 'internal', 'private', 'secure2', 'protected', 'restricted', 'hidden',
            # Technical subdomains
            'prometheus', 'grafana', 'kibana', 'elastic', 'redis', 'mongo', 'postgres', 'mysql2',
            'docker', 'k8s', 'kubernetes', 'jenkins', 'gitlab', 'github', 'bitbucket', 'ci',
            'cd', 'deploy', 'deployment', 'build', 'release', 'artifact', 'registry', 'repo',
            # Cloud and CDN
            'aws', 'azure', 'gcp', 'cloud2', 'cdn2', 'static2', 'assets2', 'media2', 'images2',
            'uploads', 'downloads', 'files2', 'storage2', 'backup2', 'archive', 'vault',
            # Monitoring and logging
            'monitor2', 'logs2', 'metrics', 'analytics2', 'stats2', 'health', 'status2', 'ping',
            'uptime', 'alerts', 'notifications', 'events', 'audit', 'trace', 'debug',
            # API and services
            'rest', 'soap', 'graphql', 'grpc', 'webhook', 'callback', 'notify', 'push',
            'realtime', 'ws', 'websocket', 'stream', 'feed', 'rss2', 'atom', 'json', 'xml2'
        ]

    def print_banner(self):
        """Print tool banner"""
        httpx_status = "✅ Enabled" if self.httpx_check else "❌ Disabled"
        banner = f"""
{Colors.CYAN}╔══════════════════════════════════════════════════════════════════════════════╗
║                    🔍 ADVANCED SUBDOMAIN ENUMERATOR                         ║
║              Comprehensive Subdomain Discovery & Intelligence               ║
║                                                                              ║
║  🌐 Certificate Transparency  |  🔍 DNS Brute Force                        ║
║  🔎 Search Engine Discovery   |  📊 GitHub Code Search                      ║
║  🚀 httpx HTTP/HTTPS Probing  |  🌍 Web Archive Mining                      ║
║  🛡️  Security Intelligence    |  📡 Passive DNS Sources                     ║
╚══════════════════════════════════════════════════════════════════════════════╝{Colors.END}

{Colors.YELLOW}[*] Target Domain: {Colors.WHITE}{self.domain}{Colors.END}
{Colors.YELLOW}[*] Output File: {Colors.WHITE}{self.output_file}{Colors.END}
{Colors.YELLOW}[*] Threads: {Colors.WHITE}{self.threads}{Colors.END}
{Colors.YELLOW}[*] Timeout: {Colors.WHITE}{self.timeout}s{Colors.END}
{Colors.YELLOW}[*] HTTP Probing: {Colors.WHITE}{httpx_status}{Colors.END}
{Colors.YELLOW}[*] Starting comprehensive subdomain enumeration...{Colors.END}
"""
        print(banner)

    def log(self, message, color=Colors.WHITE):
        """Log message with timestamp"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"{Colors.BLUE}[{timestamp}]{Colors.END} {color}{message}{Colors.END}")

    def add_subdomain(self, subdomain):
        """Thread-safe method to add subdomain"""
        subdomain = subdomain.lower().strip()
        # Skip wildcard subdomains
        if subdomain.startswith('*.'):
            return
        if subdomain and subdomain.endswith(f'.{self.domain}') and not subdomain.startswith('*'):
            with self.lock:
                if subdomain not in self.subdomains:
                    self.subdomains.add(subdomain)
                    # Always show found subdomains live
                    self.log(f"🎯 Found: {subdomain}", Colors.GREEN)

    def get_random_user_agent(self):
        """Get random user agent"""
        return random.choice(self.user_agents)

    def certificate_transparency(self):
        """Certificate Transparency logs enumeration"""
        self.log("🔍 Searching Certificate Transparency logs...", Colors.CYAN)
        
        sources = [
            {
                'name': 'crt.sh',
                'url': f"https://crt.sh/?q=%.{self.domain}&output=json",
                'parser': self.parse_crtsh_response
            },
            {
                'name': 'crt.sh_exact',
                'url': f"https://crt.sh/?q={self.domain}&output=json",
                'parser': self.parse_crtsh_response
            },
            {
                'name': 'certspotter',
                'url': f"https://api.certspotter.com/v1/issuances?domain={self.domain}&include_subdomains=true&expand=dns_names",
                'parser': self.parse_certspotter_response
            }
        ]
        
        found_count = 0
        
        for source in sources:
            try:
                headers = {
                    'User-Agent': self.get_random_user_agent(),
                    'Accept': 'application/json'
                }
                response = self.session.get(source['url'], headers=headers, timeout=self.timeout * 2)
                
                if response.status_code == 200:
                    count = source['parser'](response)
                    found_count += count
                    time.sleep(1)  # Rate limiting
                elif response.status_code == 429:
                    if self.verbose:
                        self.log(f"{source['name']} rate limited", Colors.YELLOW)
                    time.sleep(5)
                        
            except Exception as e:
                if self.verbose:
                    self.log(f"{source['name']} error: {e}", Colors.YELLOW)
        
        if self.verbose and found_count > 0:
            self.log(f"Certificate Transparency found {found_count} subdomains", Colors.GREEN)
    
    def parse_crtsh_response(self, response):
        """Parse crt.sh JSON response"""
        count = 0
        try:
            data = response.json()
            for cert in data:
                if 'name_value' in cert:
                    names = cert['name_value'].split('\n')
                    for name in names:
                        name = name.strip().lower()
                        if name.endswith(f'.{self.domain}') and not name.startswith('*'):
                            self.add_subdomain(name)
                            count += 1
        except Exception as e:
            if self.verbose:
                self.log(f"crt.sh parse error: {e}", Colors.YELLOW)
        return count
    
    def parse_certspotter_response(self, response):
        """Parse CertSpotter JSON response"""
        count = 0
        try:
            data = response.json()
            for cert in data:
                if 'dns_names' in cert:
                    for name in cert['dns_names']:
                        name = name.strip().lower()
                        if name.endswith(f'.{self.domain}') and not name.startswith('*'):
                            self.add_subdomain(name)
                            count += 1
        except Exception as e:
            if self.verbose:
                self.log(f"CertSpotter parse error: {e}", Colors.YELLOW)
        return count

    def search_engines(self):
        """Search engine enumeration"""
        self.log("🔎 Searching via Search Engines...", Colors.CYAN)
        
        # Multiple search engines and queries
        search_sources = [
            {
                'name': 'Google',
                'url': 'https://www.google.com/search?q={}&num=100',
                'queries': [f"site:{self.domain}", f"site:*.{self.domain}", f"inurl:{self.domain}"]
            },
            {
                'name': 'Bing',
                'url': 'https://www.bing.com/search?q={}&count=100',
                'queries': [f"site:{self.domain}", f"domain:{self.domain}"]
            },
            {
                'name': 'DuckDuckGo',
                'url': 'https://duckduckgo.com/html/?q={}',
                'queries': [f"site:{self.domain}"]
            }
        ]
        
        for source in search_sources:
            for query in source['queries']:
                try:
                    url = source['url'].format(urllib.parse.quote(query))
                    headers = {
                        'User-Agent': self.get_random_user_agent(),
                        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                        'Accept-Language': 'en-US,en;q=0.5',
                        'Accept-Encoding': 'gzip, deflate',
                        'Connection': 'keep-alive',
                        'Upgrade-Insecure-Requests': '1'
                    }
                    
                    response = self.session.get(url, headers=headers, timeout=self.timeout)
                    
                    if response.status_code == 200:
                        # Extract subdomains from search results
                        patterns = [
                            r'https?://([a-zA-Z0-9.-]+\.' + re.escape(self.domain) + r')',
                            r'href="https?://([a-zA-Z0-9.-]+\.' + re.escape(self.domain) + r')',
                            r'url=https?://([a-zA-Z0-9.-]+\.' + re.escape(self.domain) + r')'
                        ]
                        
                        for pattern in patterns:
                            matches = re.findall(pattern, response.text, re.IGNORECASE)
                            for match in matches:
                                self.add_subdomain(match)
                    
                    time.sleep(2)  # Rate limiting
                    
                except Exception as e:
                    if self.verbose:
                        self.log(f"{source['name']} search error: {e}", Colors.RED)

    def github_search(self):
        """GitHub code search for subdomains"""
        self.log("📊 Searching GitHub repositories...", Colors.CYAN)
        
        try:
            # Multiple search strategies
            queries = [
                f'"{self.domain}" extension:txt',
                f'"{self.domain}" extension:json', 
                f'"{self.domain}" extension:xml',
                f'"{self.domain}" extension:yml',
                f'"{self.domain}" extension:yaml',
                f'"{self.domain}" extension:config',
                f'"{self.domain}" extension:conf',
                f'"{self.domain}" extension:env',
                f'"{self.domain}" filename:config',
                f'"{self.domain}" filename:.env',
                f'"*.{self.domain}"',
                f'{self.domain} subdomain',
                f'{self.domain} API endpoint'
            ]
            
            found_count = 0
            
            for query in queries[:5]:  # Limit to avoid rate limiting
                try:
                    url = f"https://api.github.com/search/code?q={urllib.parse.quote(query)}&per_page=30"
                    headers = {
                        'User-Agent': self.get_random_user_agent(),
                        'Accept': 'application/vnd.github.v3+json'
                    }
                    
                    response = self.session.get(url, headers=headers, timeout=self.timeout)
                    
                    if response.status_code == 200:
                        data = response.json()
                        for item in data.get('items', [])[:10]:  # Limit items per query
                            # Get file content
                            download_url = item.get('download_url')
                            if download_url:
                                try:
                                    content_response = self.session.get(download_url, timeout=5)
                                    if content_response.status_code == 200:
                                        content = content_response.text
                                        
                                        # Multiple patterns for subdomain extraction
                                        patterns = [
                                            r'([a-zA-Z0-9.-]+\.' + re.escape(self.domain) + r')',
                                            r'"([a-zA-Z0-9.-]+\.' + re.escape(self.domain) + r')"',
                                            r"'([a-zA-Z0-9.-]+\." + re.escape(self.domain) + r")'",
                                            r'https?://([a-zA-Z0-9.-]+\.' + re.escape(self.domain) + r')',
                                            r'://([a-zA-Z0-9.-]+\.' + re.escape(self.domain) + r')'
                                        ]
                                        
                                        for pattern in patterns:
                                            matches = re.findall(pattern, content, re.IGNORECASE)
                                            for match in matches:
                                                if not match.startswith('*'):
                                                    self.add_subdomain(match)
                                                    found_count += 1
                                        
                                except Exception as e:
                                    if self.verbose:
                                        self.log(f"GitHub content error: {e}", Colors.YELLOW)
                                    continue
                    
                    elif response.status_code == 403:
                        if self.verbose:
                            self.log("GitHub API rate limit reached", Colors.YELLOW)
                        break
                    
                    time.sleep(3)  # GitHub rate limiting
                    
                except Exception as e:
                    if self.verbose:
                        self.log(f"GitHub query error: {e}", Colors.YELLOW)
                    continue
            
            if self.verbose and found_count > 0:
                self.log(f"GitHub search found {found_count} subdomains", Colors.GREEN)
                
        except Exception as e:
            if self.verbose:
                self.log(f"GitHub search error: {e}", Colors.RED)

    def wayback_machine(self):
        """Wayback Machine archive search"""
        self.log("🌍 Mining Web Archive data...", Colors.CYAN)
        
        try:
            # Multiple Wayback Machine queries
            queries = [
                f"http://web.archive.org/cdx/search/cdx?url=*.{self.domain}/*&output=json&collapse=urlkey&limit=1000",
                f"http://web.archive.org/cdx/search/cdx?url={self.domain}/*&output=json&collapse=urlkey&limit=1000"
            ]
            
            found_count = 0
            
            for query_url in queries:
                try:
                    headers = {
                        'User-Agent': self.get_random_user_agent(),
                        'Accept': 'application/json'
                    }
                    response = self.session.get(query_url, headers=headers, timeout=self.timeout)
                    
                    if response.status_code == 200:
                        try:
                            data = response.json()
                            if isinstance(data, list) and len(data) > 1:
                                for entry in data[1:]:  # Skip header
                                    if len(entry) > 2:
                                        archived_url = entry[2]
                                        try:
                                            parsed = urlparse(archived_url)
                                            hostname = parsed.hostname
                                            
                                            if hostname and hostname.endswith(f'.{self.domain}') and not hostname.startswith('*'):
                                                self.add_subdomain(hostname)
                                                found_count += 1
                                        except:
                                            continue
                        except json.JSONDecodeError:
                            # Try to extract from text response
                            lines = response.text.split('\n')
                            for line in lines[1:]:  # Skip header
                                if line.strip():
                                    parts = line.split(' ')
                                    if len(parts) > 2:
                                        try:
                                            archived_url = parts[2]
                                            parsed = urlparse(archived_url)
                                            hostname = parsed.hostname
                                            
                                            if hostname and hostname.endswith(f'.{self.domain}') and not hostname.startswith('*'):
                                                self.add_subdomain(hostname)
                                                found_count += 1
                                        except:
                                            continue
                    
                    time.sleep(1)  # Rate limiting
                    
                except Exception as e:
                    if self.verbose:
                        self.log(f"Wayback query error: {e}", Colors.YELLOW)
                    continue
            
            if self.verbose and found_count > 0:
                self.log(f"Wayback Machine found {found_count} subdomains", Colors.GREEN)
                
        except Exception as e:
            if self.verbose:
                self.log(f"Wayback Machine error: {e}", Colors.RED)

    def virustotal_api(self):
        """VirusTotal API enumeration (requires API key)"""
        self.log("🛡️ Querying VirusTotal API...", Colors.CYAN)
        
        # This would require an API key - implementing passive version
        try:
            url = f"https://www.virustotal.com/vtapi/v2/domain/report"
            params = {'domain': self.domain, 'apikey': 'demo'}  # Demo key for passive
            headers = {'User-Agent': self.get_random_user_agent()}
            
            # Note: This is a demo implementation
            # In real usage, you'd need a valid VirusTotal API key
            
        except Exception as e:
            if self.verbose:
                self.log(f"VirusTotal API error: {e}", Colors.RED)

    def dns_brute_force(self):
        """DNS brute force enumeration"""
        self.log("🔍 Starting DNS brute force attack...", Colors.CYAN)
        
        def check_subdomain(subdomain):
            full_domain = f"{subdomain}.{self.domain}"
            try:
                # Try A record
                dns.resolver.resolve(full_domain, 'A')
                self.add_subdomain(full_domain)
                return True
            except:
                try:
                    # Try CNAME record
                    dns.resolver.resolve(full_domain, 'CNAME')
                    self.add_subdomain(full_domain)
                    return True
                except:
                    return False
        
        # Combine wordlists
        all_wordlist = self.wordlist + self.extended_wordlist
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(check_subdomain, all_wordlist)

    def zone_transfer(self):
        """DNS Zone Transfer attempt"""
        self.log("📡 Attempting DNS Zone Transfer...", Colors.CYAN)
        
        try:
            # Get nameservers
            ns_records = dns.resolver.resolve(self.domain, 'NS')
            
            for ns in ns_records:
                try:
                    ns_ip = str(dns.resolver.resolve(str(ns), 'A')[0])
                    zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, self.domain))
                    
                    for name in zone.nodes.keys():
                        subdomain = f"{name}.{self.domain}"
                        if subdomain != self.domain:
                            self.add_subdomain(subdomain)
                            
                except Exception as e:
                    if self.verbose:
                        self.log(f"Zone transfer failed for {ns}: {e}", Colors.YELLOW)
                        
        except Exception as e:
            if self.verbose:
                self.log(f"Zone transfer error: {e}", Colors.RED)

    def reverse_dns(self):
        """Reverse DNS lookups"""
        self.log("🔄 Performing reverse DNS lookups...", Colors.CYAN)
        
        try:
            # Get IP range for domain
            ip = socket.gethostbyname(self.domain)
            network = ipaddress.IPv4Network(f"{ip}/24", strict=False)
            
            def reverse_lookup(ip_addr):
                try:
                    hostname = socket.gethostbyaddr(str(ip_addr))[0]
                    if hostname.endswith(f'.{self.domain}'):
                        self.add_subdomain(hostname)
                except:
                    pass
            
            # Limit to first 50 IPs to avoid too many requests
            ip_list = list(network.hosts())[:50]
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                executor.map(reverse_lookup, ip_list)
                
        except Exception as e:
            if self.verbose:
                self.log(f"Reverse DNS error: {e}", Colors.RED)

    def vhost_discovery(self):
        """Virtual host discovery"""
        self.log("🌐 Discovering virtual hosts...", Colors.CYAN)
        
        try:
            # Get main domain IP
            main_ip = socket.gethostbyname(self.domain)
            
            def check_vhost(subdomain):
                full_domain = f"{subdomain}.{self.domain}"
                try:
                    # Check if subdomain resolves to same IP
                    sub_ip = socket.gethostbyname(full_domain)
                    if sub_ip == main_ip:
                        # Try HTTP request with Host header
                        headers = {
                            'Host': full_domain,
                            'User-Agent': self.get_random_user_agent()
                        }
                        
                        response = self.session.get(f"http://{main_ip}", 
                                                  headers=headers, 
                                                  timeout=5,
                                                  allow_redirects=False)
                        
                        # Check if response differs from default
                        if response.status_code not in [404, 400]:
                            self.add_subdomain(full_domain)
                            
                except:
                    pass
            
            # Test common vhost names
            vhost_wordlist = ['www', 'mail', 'ftp', 'admin', 'test', 'dev', 'api', 'app']
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                executor.map(check_vhost, vhost_wordlist)
                
        except Exception as e:
            if self.verbose:
                self.log(f"VHost discovery error: {e}", Colors.RED)

    def shodan_search(self):
        """Shodan passive search (without API key)"""
        self.log("🔍 Searching Shodan data...", Colors.CYAN)
        
        try:
            # Passive Shodan search via web interface
            url = f"https://www.shodan.io/search?query=hostname:{self.domain}"
            headers = {'User-Agent': self.get_random_user_agent()}
            response = self.session.get(url, headers=headers, timeout=self.timeout)
            
            # Extract hostnames from results
            pattern = r'([a-zA-Z0-9.-]+\.' + re.escape(self.domain) + r')'
            matches = re.findall(pattern, response.text, re.IGNORECASE)
            
            for match in matches:
                self.add_subdomain(match)
                
        except Exception as e:
            if self.verbose:
                self.log(f"Shodan search error: {e}", Colors.RED)

    def chaos_api(self):
        """ProjectDiscovery Chaos API (requires API key)"""
        self.log("🚀 Querying Chaos API...", Colors.CYAN)
        
        # This would require a Chaos API key
        # Implementing placeholder for now
        try:
            # url = f"https://dns.projectdiscovery.io/dns/{self.domain}/subdomains"
            # This requires authentication
            pass
        except Exception as e:
            if self.verbose:
                self.log(f"Chaos API error: {e}", Colors.RED)

    def security_trails_api(self):
        """SecurityTrails API enumeration (requires API key)"""
        self.log("🛡️ Querying SecurityTrails API...", Colors.CYAN)
        
        # This would require a SecurityTrails API key
        # Implementing placeholder for now
        try:
            # url = f"https://api.securitytrails.com/v1/domain/{self.domain}/subdomains"
            # This requires authentication
            pass
        except Exception as e:
            if self.verbose:
                self.log(f"SecurityTrails API error: {e}", Colors.RED)

    def passive_dns_sources(self):
        """Query multiple passive DNS sources"""
        self.log("📡 Querying passive DNS sources...", Colors.CYAN)
        
        # DNS over HTTPS sources
        dns_sources = [
            {
                'name': 'Google DNS',
                'url': f"https://dns.google/resolve?name={self.domain}&type=ANY"
            },
            {
                'name': 'Cloudflare DNS', 
                'url': f"https://cloudflare-dns.com/dns-query?name={self.domain}&type=ANY"
            }
        ]
        
        # Additional passive DNS sources
        passive_sources = [
            {
                'name': 'DNSDumpster',
                'url': f"https://dnsdumpster.com/",
                'method': self.query_dnsdumpster
            },
            {
                'name': 'Threatcrowd',
                'url': f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={self.domain}",
                'method': self.query_threatcrowd
            }
        ]
        
        # Query DNS over HTTPS
        for source in dns_sources:
            try:
                headers = {
                    'User-Agent': self.get_random_user_agent(),
                    'Accept': 'application/dns-json'
                }
                
                response = self.session.get(source['url'], headers=headers, timeout=self.timeout)
                
                if response.status_code == 200:
                    data = response.json()
                    if 'Answer' in data:
                        for record in data['Answer']:
                            if 'data' in record:
                                # Extract potential subdomains from DNS data
                                pattern = r'([a-zA-Z0-9.-]+\.' + re.escape(self.domain) + r')'
                                matches = re.findall(pattern, record['data'], re.IGNORECASE)
                                
                                for match in matches:
                                    self.add_subdomain(match)
                                    
            except Exception as e:
                if self.verbose:
                    self.log(f"{source['name']} error: {e}", Colors.YELLOW)
        
        # Query additional passive sources
        for source in passive_sources:
            try:
                source['method']()
                time.sleep(1)
            except Exception as e:
                if self.verbose:
                    self.log(f"{source['name']} error: {e}", Colors.YELLOW)
    
    def query_threatcrowd(self):
        """Query Threatcrowd API"""
        try:
            url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={self.domain}"
            headers = {'User-Agent': self.get_random_user_agent()}
            
            response = self.session.get(url, headers=headers, timeout=self.timeout)
            
            if response.status_code == 200:
                data = response.json()
                if 'subdomains' in data:
                    for subdomain in data['subdomains']:
                        if subdomain.endswith(f'.{self.domain}'):
                            self.add_subdomain(subdomain)
                            
        except Exception as e:
            if self.verbose:
                self.log(f"Threatcrowd query error: {e}", Colors.YELLOW)
    
    def query_dnsdumpster(self):
        """Query DNSDumpster (requires web scraping)"""
        try:
            # This would require more complex implementation with CSRF tokens
            # For now, we'll skip this to avoid complexity
            pass
        except Exception as e:
            if self.verbose:
                self.log(f"DNSDumpster query error: {e}", Colors.YELLOW)

    def ssl_certificate_search(self):
        """SSL Certificate search and analysis"""
        self.log("🔒 Analyzing SSL certificates...", Colors.CYAN)
        
        def check_ssl_cert(subdomain):
            try:
                context = ssl.create_default_context()
                with socket.create_connection((subdomain, 443), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=subdomain) as ssock:
                        cert = ssock.getpeercert()
                        
                        # Extract Subject Alternative Names
                        if 'subjectAltName' in cert:
                            for san_type, san_value in cert['subjectAltName']:
                                if san_type == 'DNS' and san_value.endswith(f'.{self.domain}'):
                                    self.add_subdomain(san_value)
                                    
            except:
                pass
        
        # Check SSL certs for known subdomains
        known_subdomains = ['www', 'mail', 'api', 'app', 'secure']
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            full_domains = [f"{sub}.{self.domain}" for sub in known_subdomains]
            executor.map(check_ssl_cert, full_domains)

    def httpx_probe_subdomains(self):
        """Probe discovered subdomains using httpx-like functionality"""
        if not self.httpx_check or not self.subdomains:
            return
        
        self.log("🚀 Starting HTTP/HTTPS probing (httpx-style)...", Colors.CYAN)
        
        # Remove duplicates and sort
        unique_subdomains = sorted(list(self.subdomains))
        
        self.log(f"📊 Probing {len(unique_subdomains)} unique subdomains...", Colors.YELLOW)
        
        httpx_prober = HttpxProbe(timeout=self.timeout, threads=self.threads)
        
        def probe_subdomain(subdomain):
            try:
                results = httpx_prober.probe_url(subdomain)
                
                for protocol, result in results.items():
                    if 'error' not in result:
                        status_code = result['status_code']
                        title = result['title']
                        response_time = result['response_time']
                        content_length = result['content_length']
                        
                        # Categorize status code
                        category, color = httpx_prober.categorize_status_code(status_code)
                        
                        # Store live subdomain
                        with self.lock:
                            key = f"{protocol}://{subdomain}"
                            self.live_subdomains[key] = {
                                'subdomain': subdomain,
                                'protocol': protocol,
                                'status_code': status_code,
                                'title': title,
                                'response_time': response_time,
                                'content_length': content_length,
                                'category': category,
                                'url': result['url']
                            }
                        
                        # Live display
                        self.log(f"✅ {protocol.upper()}://{subdomain} [{color}{status_code}{Colors.END}] [{response_time}ms] {title}", Colors.WHITE)
                    
            except Exception as e:
                if self.verbose:
                    self.log(f"❌ Error probing {subdomain}: {e}", Colors.RED)
        
        # Probe subdomains with threading
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(probe_subdomain, unique_subdomains)

    def run_enumeration(self):
        """Run all enumeration techniques"""
        self.print_banner()
        
        # List of enumeration methods
        methods = [
            self.certificate_transparency,
            self.dns_brute_force,
            self.search_engines,
            self.github_search,
            self.wayback_machine,
            self.zone_transfer,
            self.reverse_dns,
            self.vhost_discovery,
            self.shodan_search,
            self.passive_dns_sources,
            self.ssl_certificate_search,
            # API methods (require keys)
            # self.chaos_api,
            # self.virustotal_api,
            # self.security_trails_api,
        ]
        
        # Run enumeration methods
        for method in methods:
            try:
                method()
                time.sleep(0.5)  # Brief pause between methods
            except KeyboardInterrupt:
                self.log("Enumeration interrupted by user", Colors.YELLOW)
                break
            except Exception as e:
                if self.verbose:
                    self.log(f"Method {method.__name__} failed: {e}", Colors.RED)
        
        # After enumeration, probe subdomains with httpx
        if self.httpx_check:
            self.httpx_probe_subdomains()

    def save_results(self):
        """Save results to file"""
        if self.httpx_check and self.live_subdomains:
            # Save live subdomains with status codes
            live_output_file = self.output_file.replace('.txt', '_live.txt')
            
            # Categorize by status code
            status_categories = {
                'success': [],      # 2xx
                'redirect': [],     # 3xx
                'client_error': [], # 4xx
                'server_error': [], # 5xx
                'unknown': []       # others
            }
            
            for url, info in self.live_subdomains.items():
                category = info['category']
                status_categories[category].append({
                    'url': url,
                    'status_code': info['status_code'],
                    'title': info['title'],
                    'response_time': info['response_time'],
                    'content_length': info['content_length']
                })
            
            # Save categorized results
            with open(live_output_file, 'w', encoding='utf-8') as f:
                f.write(f"# Live Subdomains for {self.domain}\n")
                f.write(f"# Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"# Total live subdomains: {len(self.live_subdomains)}\n\n")
                
                for category, urls in status_categories.items():
                    if urls:
                        f.write(f"## {category.upper().replace('_', ' ')} ({len(urls)} subdomains)\n")
                        for item in sorted(urls, key=lambda x: x['url']):
                            f.write(f"{item['url']} [{item['status_code']}] [{item['response_time']}ms] {item['title']}\n")
                        f.write("\n")
            
            # Also save simple list
            simple_output_file = self.output_file.replace('.txt', '_simple.txt')
            with open(simple_output_file, 'w', encoding='utf-8') as f:
                for url in sorted(self.live_subdomains.keys()):
                    f.write(f"{url}\n")
            
            self.log(f"💾 Live results saved to: {live_output_file}", Colors.GREEN)
            self.log(f"💾 Simple list saved to: {simple_output_file}", Colors.GREEN)
            self.log(f"📊 Total live subdomains: {len(self.live_subdomains)}", Colors.GREEN)
            
            # Print summary
            print(f"\n{Colors.CYAN}╔══════════════════════════════════════════════════════════════════════════════╗")
            print(f"║                           🎯 HTTPX PROBING COMPLETE                         ║")
            print(f"╚══════════════════════════════════════════════════════════════════════════════╝{Colors.END}")
            
            print(f"\n{Colors.GREEN}✅ Found {len(self.subdomains)} total subdomains for {self.domain}{Colors.END}")
            print(f"{Colors.GREEN}🚀 Found {len(self.live_subdomains)} live subdomains{Colors.END}")
            print(f"{Colors.YELLOW}📁 Live results: {live_output_file}{Colors.END}")
            print(f"{Colors.YELLOW}📁 Simple list: {simple_output_file}{Colors.END}")
            
            # Show status code breakdown
            print(f"\n{Colors.CYAN}📊 Status Code Breakdown:{Colors.END}")
            for category, urls in status_categories.items():
                if urls:
                    color = Colors.GREEN if category == 'success' else Colors.YELLOW if category == 'redirect' else Colors.RED
                    print(f"{color}  {category.replace('_', ' ').title()}: {len(urls)} subdomains{Colors.END}")
            
            # Show first 10 live results as preview
            if self.live_subdomains:
                print(f"\n{Colors.CYAN}🔍 Live Subdomains Preview (first 10):{Colors.END}")
                live_list = sorted(self.live_subdomains.items())
                for i, (url, info) in enumerate(live_list[:10], 1):
                    status_code = info['status_code']
                    title = info['title'][:50] + "..." if len(info['title']) > 50 else info['title']
                    category, color = HttpxProbe(self.timeout, self.threads).categorize_status_code(status_code)
                    print(f"{Colors.WHITE}{i:2d}. {url} {color}[{status_code}]{Colors.END} {title}{Colors.END}")
                
                if len(self.live_subdomains) > 10:
                    print(f"{Colors.YELLOW}   ... and {len(self.live_subdomains) - 10} more{Colors.END}")
        
        elif self.subdomains:
            # Fallback to original behavior if httpx is disabled
            sorted_subdomains = sorted(list(self.subdomains))
            
            with open(self.output_file, 'w', encoding='utf-8') as f:
                for subdomain in sorted_subdomains:
                    f.write(f"{subdomain}\n")
            
            self.log(f"💾 Results saved to: {self.output_file}", Colors.GREEN)
            self.log(f"📊 Total subdomains found: {len(sorted_subdomains)}", Colors.GREEN)
            
            print(f"\n{Colors.CYAN}╔══════════════════════════════════════════════════════════════════════════════╗")
            print(f"║                           🎯 ENUMERATION COMPLETE                           ║")
            print(f"╚══════════════════════════════════════════════════════════════════════════════╝{Colors.END}")
            print(f"\n{Colors.GREEN}✅ Found {len(sorted_subdomains)} unique subdomains for {self.domain}{Colors.END}")
            print(f"{Colors.YELLOW}📁 Results saved to: {self.output_file}{Colors.END}")
        else:
            self.log("❌ No subdomains found", Colors.RED)

def main():
    parser = argparse.ArgumentParser(
        description="🔍 Advanced Subdomain Enumeration Tool with httpx Integration",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 subdomains.py -d example.com
  python3 subdomains.py -d example.com -o results.txt -t 100 -v
  python3 subdomains.py -d example.com --timeout 15 --verbose
  python3 subdomains.py -d example.com --no-httpx  # Skip HTTP probing
        """
    )
    
    parser.add_argument('-d', '--domain', required=True, help='Target domain')
    parser.add_argument('-o', '--output', help='Output file (default: domain_subdomains.txt)')
    parser.add_argument('-t', '--threads', type=int, default=50, help='Number of threads (default: 50)')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout in seconds (default: 10)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--no-httpx', action='store_true', help='Skip HTTP/HTTPS probing (httpx functionality)')
    
    args = parser.parse_args()
    
    # Validate domain
    domain_pattern = re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    )
    
    if not domain_pattern.match(args.domain):
        print(f"{Colors.RED}❌ Invalid domain format: {args.domain}{Colors.END}")
        sys.exit(1)
    
    try:
        # Initialize enumerator
        enumerator = SubdomainEnumerator(
            domain=args.domain,
            output_file=args.output,
            threads=args.threads,
            timeout=args.timeout,
            verbose=args.verbose,
            httpx_check=not args.no_httpx
        )
        
        # Run enumeration
        enumerator.run_enumeration()
        
        # Save results
        enumerator.save_results()
        
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}⚠️ Enumeration interrupted by user{Colors.END}")
        sys.exit(0)
    except Exception as e:
        print(f"{Colors.RED}❌ Fatal error: {e}{Colors.END}")
        sys.exit(1)

if __name__ == "__main__":
    main()