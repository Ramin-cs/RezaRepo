#!/usr/bin/env python3
"""
Advanced Subdomain and Parameter Discovery Tool
Professional reconnaissance tool for security researchers and penetration testers

Features:
- Advanced subdomain discovery using multiple techniques
- Parameter discovery with intelligent fuzzing
- Cross-platform compatibility (Windows/Linux)
- Multi-threading for performance
- Multiple output formats
- Built-in wordlists and smart detection
"""

import dns.resolver
import dns.zone
import dns.query
import ssl
import socket
import threading
import time
import json
import csv
import re
import random
import argparse
import sys
import os
import platform
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, urljoin, parse_qs
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import warnings
warnings.filterwarnings("ignore", category=requests.packages.urllib3.exceptions.InsecureRequestWarning)

class Colors:
    """ANSI color codes for cross-platform terminal output"""
    if platform.system() == "Windows":
        # Enable ANSI colors on Windows
        os.system('color')
    
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

class Logger:
    """Enhanced logging with colors and levels"""
    
    @staticmethod
    def info(message):
        print(f"{Colors.BLUE}[INFO]{Colors.END} {message}")
    
    @staticmethod
    def success(message):
        print(f"{Colors.GREEN}[SUCCESS]{Colors.END} {message}")
    
    @staticmethod
    def warning(message):
        print(f"{Colors.YELLOW}[WARNING]{Colors.END} {message}")
    
    @staticmethod
    def error(message):
        print(f"{Colors.RED}[ERROR]{Colors.END} {message}")
    
    @staticmethod
    def found(message):
        print(f"{Colors.CYAN}[FOUND]{Colors.END} {message}")

class SubdomainDiscovery:
    """Advanced subdomain discovery using multiple techniques"""
    
    def __init__(self, domain, threads=50, timeout=10):
        self.domain = domain
        self.threads = threads
        self.timeout = timeout
        self.found_subdomains = set()
        self.session = self._create_session()
        
        # Built-in wordlist for subdomain discovery
        self.subdomain_wordlist = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk', 'ns2',
            'cpanel', 'whm', 'autodiscover', 'autoconfig', 'mx', 'dns', 'ns', 'secure', 'download',
            'wap', 'admin', 'sql', 'api', 'dev', 'staging', 'test', 'demo', 'beta', 'mobile',
            'blog', 'shop', 'store', 'forum', 'support', 'help', 'docs', 'portal', 'app', 'apps',
            'cdn', 'static', 'assets', 'media', 'images', 'img', 'js', 'css', 'files', 'upload',
            'vpn', 'ssh', 'remote', 'proxy', 'gateway', 'firewall', 'router', 'switch', 'wifi',
            'intranet', 'extranet', 'internal', 'external', 'private', 'public', 'secure', 'ssl',
            'tls', 'https', 'http', 'web', 'website', 'site', 'page', 'home', 'index', 'main',
            'old', 'new', 'backup', 'bak', 'archive', 'temp', 'tmp', 'cache', 'log', 'logs',
            'db', 'database', 'mysql', 'postgres', 'oracle', 'mssql', 'redis', 'mongo', 'elastic',
            'search', 'solr', 'kibana', 'grafana', 'prometheus', 'nagios', 'zabbix', 'monitoring',
            'status', 'health', 'check', 'ping', 'trace', 'debug', 'error', 'exception', 'crash',
            'git', 'svn', 'cvs', 'hg', 'repo', 'repository', 'code', 'source', 'build', 'ci',
            'jenkins', 'bamboo', 'travis', 'circleci', 'gitlab', 'github', 'bitbucket', 'docker',
            'k8s', 'kubernetes', 'helm', 'terraform', 'ansible', 'puppet', 'chef', 'salt', 'vagrant'
        ]
    
    def _create_session(self):
        """Create HTTP session with retry strategy"""
        session = requests.Session()
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        return session
    
    def dns_bruteforce(self):
        """DNS brute-force subdomain discovery"""
        Logger.info(f"Starting DNS brute-force for {self.domain}")
        
        def check_subdomain(subdomain):
            full_domain = f"{subdomain}.{self.domain}"
            try:
                dns.resolver.resolve(full_domain, 'A')
                self.found_subdomains.add(full_domain)
                Logger.found(f"DNS: {full_domain}")
                return full_domain
            except:
                pass
            return None
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(check_subdomain, sub) for sub in self.subdomain_wordlist]
            for future in as_completed(futures):
                future.result()
    
    def certificate_transparency(self):
        """Certificate Transparency logs mining"""
        Logger.info(f"Searching Certificate Transparency logs for {self.domain}")
        
        ct_urls = [
            f"https://crt.sh/?q=%.{self.domain}&output=json",
            f"https://certspotter.com/api/v1/issuances?domain={self.domain}&include_subdomains=true&expand=dns_names"
        ]
        
        for url in ct_urls:
            try:
                response = self.session.get(url, timeout=self.timeout)
                if response.status_code == 200:
                    if 'crt.sh' in url:
                        data = response.json()
                        for cert in data:
                            name_value = cert.get('name_value', '')
                            for domain in name_value.split('\n'):
                                domain = domain.strip()
                                if domain and self.domain in domain and domain not in self.found_subdomains:
                                    self.found_subdomains.add(domain)
                                    Logger.found(f"CT: {domain}")
                    elif 'certspotter' in url:
                        data = response.json()
                        for cert in data:
                            dns_names = cert.get('dns_names', [])
                            for domain_name in dns_names:
                                if domain_name and self.domain in domain_name and domain_name not in self.found_subdomains:
                                    self.found_subdomains.add(domain_name)
                                    Logger.found(f"CT: {domain_name}")
            except Exception as e:
                Logger.warning(f"CT search failed for {url}: {str(e)}")
    
    def search_engine_dorking(self):
        """Search engine dorking for subdomain discovery"""
        Logger.info(f"Performing search engine dorking for {self.domain}")
        
        search_queries = [
            f"site:*.{self.domain}",
            f"site:{self.domain} -www",
            f"inurl:{self.domain}",
        ]
        
        # Note: In a real implementation, you would use search engine APIs
        # This is a placeholder for the concept
        Logger.warning("Search engine dorking requires API keys - implement with Google/Bing APIs")
    
    def zone_transfer(self):
        """Attempt DNS zone transfer"""
        Logger.info(f"Attempting DNS zone transfer for {self.domain}")
        
        try:
            # Get NS records
            ns_records = dns.resolver.resolve(self.domain, 'NS')
            for ns in ns_records:
                ns_server = str(ns).rstrip('.')
                try:
                    zone = dns.zone.from_xfr(dns.query.xfr(ns_server, self.domain))
                    for name, node in zone.nodes.items():
                        subdomain = f"{name}.{self.domain}"
                        if subdomain not in self.found_subdomains:
                            self.found_subdomains.add(subdomain)
                            Logger.found(f"Zone Transfer: {subdomain}")
                except Exception as e:
                    Logger.warning(f"Zone transfer failed for {ns_server}: {str(e)}")
        except Exception as e:
            Logger.warning(f"Could not get NS records for {self.domain}: {str(e)}")
    
    def reverse_dns_lookup(self):
        """Reverse DNS lookup on IP ranges"""
        Logger.info(f"Performing reverse DNS lookup for {self.domain}")
        
        try:
            # Get IP of main domain
            ip = socket.gethostbyname(self.domain)
            ip_parts = ip.split('.')
            base_ip = '.'.join(ip_parts[:3])
            
            def check_reverse_dns(ip_addr):
                try:
                    hostname = socket.gethostbyaddr(ip_addr)[0]
                    if self.domain in hostname and hostname not in self.found_subdomains:
                        self.found_subdomains.add(hostname)
                        Logger.found(f"Reverse DNS: {hostname}")
                except:
                    pass
            
            # Check a small range around the main IP
            with ThreadPoolExecutor(max_workers=20) as executor:
                futures = []
                for i in range(1, 255):
                    test_ip = f"{base_ip}.{i}"
                    futures.append(executor.submit(check_reverse_dns, test_ip))
                
                for future in as_completed(futures):
                    future.result()
                    
        except Exception as e:
            Logger.warning(f"Reverse DNS lookup failed: {str(e)}")
    
    def wildcard_detection(self):
        """Detect and filter wildcard DNS responses"""
        Logger.info(f"Detecting wildcards for {self.domain}")
        
        # Test with random subdomains
        random_subs = [''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=10)) for _ in range(5)]
        wildcard_ips = set()
        
        for random_sub in random_subs:
            try:
                result = dns.resolver.resolve(f"{random_sub}.{self.domain}", 'A')
                for ip in result:
                    wildcard_ips.add(str(ip))
            except:
                pass
        
        if wildcard_ips:
            Logger.warning(f"Wildcard detected for {self.domain}: {wildcard_ips}")
            # Filter out wildcard responses from found subdomains
            filtered_subdomains = set()
            for subdomain in self.found_subdomains:
                try:
                    result = dns.resolver.resolve(subdomain, 'A')
                    subdomain_ips = {str(ip) for ip in result}
                    if not subdomain_ips.intersection(wildcard_ips):
                        filtered_subdomains.add(subdomain)
                except:
                    filtered_subdomains.add(subdomain)
            
            self.found_subdomains = filtered_subdomains
    
    def discover_all(self):
        """Run all subdomain discovery techniques"""
        Logger.info(f"Starting comprehensive subdomain discovery for {self.domain}")
        
        techniques = [
            self.dns_bruteforce,
            self.certificate_transparency,
            self.zone_transfer,
            self.reverse_dns_lookup,
        ]
        
        for technique in techniques:
            try:
                technique()
            except Exception as e:
                Logger.error(f"Technique failed: {str(e)}")
        
        # Run wildcard detection last to filter results
        self.wildcard_detection()
        
        Logger.success(f"Found {len(self.found_subdomains)} subdomains for {self.domain}")
        return list(self.found_subdomains)

class ParameterDiscovery:
    """Advanced parameter discovery using multiple techniques"""
    
    def __init__(self, url, threads=20, timeout=10):
        self.url = url
        self.threads = threads
        self.timeout = timeout
        self.found_parameters = set()
        self.session = self._create_session()
        
        # Built-in parameter wordlist
        self.parameter_wordlist = [
            'id', 'user', 'username', 'email', 'password', 'pass', 'token', 'key', 'api_key',
            'search', 'q', 'query', 'keyword', 'term', 'filter', 'sort', 'order', 'limit', 'offset',
            'page', 'per_page', 'count', 'size', 'max', 'min', 'start', 'end', 'from', 'to',
            'category', 'type', 'status', 'state', 'mode', 'format', 'output', 'callback', 'jsonp',
            'action', 'method', 'function', 'cmd', 'command', 'exec', 'system', 'shell', 'run',
            'file', 'filename', 'path', 'dir', 'directory', 'folder', 'upload', 'download', 'view',
            'edit', 'delete', 'create', 'update', 'insert', 'modify', 'change', 'set', 'get', 'post',
            'data', 'value', 'val', 'param', 'parameter', 'arg', 'argument', 'var', 'variable',
            'name', 'title', 'description', 'content', 'text', 'message', 'comment', 'note', 'memo',
            'url', 'link', 'href', 'src', 'source', 'target', 'destination', 'redirect', 'return',
            'next', 'prev', 'previous', 'continue', 'submit', 'send', 'save', 'cancel', 'reset',
            'debug', 'test', 'demo', 'example', 'sample', 'template', 'default', 'config', 'settings',
            'admin', 'administrator', 'root', 'superuser', 'guest', 'anonymous', 'public', 'private',
            'session', 'cookie', 'csrf', 'nonce', 'hash', 'signature', 'checksum', 'verify', 'auth',
            'login', 'logout', 'signin', 'signout', 'register', 'signup', 'activate', 'confirm'
        ]
    
    def _create_session(self):
        """Create HTTP session with retry strategy"""
        session = requests.Session()
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        return session
    
    def wordlist_fuzzing(self):
        """Wordlist-based parameter fuzzing"""
        Logger.info(f"Starting wordlist-based parameter fuzzing for {self.url}")
        
        def test_parameter(param):
            test_values = ['1', 'test', 'true', 'false', '0', '']
            
            for value in test_values:
                try:
                    # Test GET parameters
                    parsed_url = urlparse(self.url)
                    test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{param}={value}"
                    
                    response = self.session.get(test_url, timeout=self.timeout, verify=False)
                    
                    # Check for parameter reflection or different response
                    if (param in response.text.lower() or 
                        value in response.text or 
                        len(response.content) != len(self.session.get(self.url, timeout=self.timeout, verify=False).content)):
                        
                        self.found_parameters.add(param)
                        Logger.found(f"Parameter: {param} (GET)")
                        return param
                    
                    # Test POST parameters
                    post_data = {param: value}
                    response = self.session.post(self.url, data=post_data, timeout=self.timeout, verify=False)
                    
                    if (param in response.text.lower() or 
                        value in response.text or 
                        'error' in response.text.lower()):
                        
                        self.found_parameters.add(param)
                        Logger.found(f"Parameter: {param} (POST)")
                        return param
                        
                except Exception as e:
                    pass
            return None
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(test_parameter, param) for param in self.parameter_wordlist]
            for future in as_completed(futures):
                future.result()
    
    def javascript_parsing(self):
        """Parse JavaScript files for hidden parameters"""
        Logger.info(f"Parsing JavaScript for hidden parameters in {self.url}")
        
        try:
            response = self.session.get(self.url, timeout=self.timeout, verify=False)
            
            # Find JavaScript files
            js_urls = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', response.text)
            js_urls.extend(re.findall(r'src=["\']([^"\']*\.js[^"\']*)["\']', response.text))
            
            # Also check inline JavaScript
            inline_js = re.findall(r'<script[^>]*>(.*?)</script>', response.text, re.DOTALL)
            
            all_js_content = '\n'.join(inline_js)
            
            # Fetch external JS files
            for js_url in js_urls:
                try:
                    if js_url.startswith('//'):
                        js_url = 'https:' + js_url
                    elif js_url.startswith('/'):
                        parsed_url = urlparse(self.url)
                        js_url = f"{parsed_url.scheme}://{parsed_url.netloc}{js_url}"
                    elif not js_url.startswith('http'):
                        js_url = urljoin(self.url, js_url)
                    
                    js_response = self.session.get(js_url, timeout=self.timeout, verify=False)
                    all_js_content += '\n' + js_response.text
                except:
                    pass
            
            # Extract potential parameters from JavaScript
            param_patterns = [
                r'["\']([a-zA-Z_][a-zA-Z0-9_]*)["\']:\s*["\']?[^,}]+["\']?',  # Object properties
                r'\.([a-zA-Z_][a-zA-Z0-9_]*)\s*=',  # Property assignments
                r'data\[["\'"]([^"\']+)["\'"]',  # Data array access
                r'params\.([a-zA-Z_][a-zA-Z0-9_]*)',  # params.parameter
                r'[?&]([a-zA-Z_][a-zA-Z0-9_]*)=',  # URL parameters
            ]
            
            for pattern in param_patterns:
                matches = re.findall(pattern, all_js_content, re.IGNORECASE)
                for match in matches:
                    if len(match) > 2 and match not in self.found_parameters:
                        self.found_parameters.add(match)
                        Logger.found(f"JS Parameter: {match}")
                        
        except Exception as e:
            Logger.warning(f"JavaScript parsing failed: {str(e)}")
    
    def error_based_discovery(self):
        """Error-based parameter discovery"""
        Logger.info(f"Starting error-based parameter discovery for {self.url}")
        
        error_payloads = [
            "' OR '1'='1",
            "\" OR \"1\"=\"1",
            "<script>alert(1)</script>",
            "../../../../etc/passwd",
            "{{7*7}}",
            "${7*7}",
            "<%=7*7%>",
        ]
        
        def test_error_param(param):
            for payload in error_payloads:
                try:
                    # Test GET
                    parsed_url = urlparse(self.url)
                    test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{param}={payload}"
                    
                    response = self.session.get(test_url, timeout=self.timeout, verify=False)
                    
                    error_indicators = [
                        'error', 'exception', 'warning', 'fatal', 'mysql', 'postgresql', 
                        'oracle', 'sqlite', 'syntax', 'unexpected', 'undefined', 'null'
                    ]
                    
                    response_lower = response.text.lower()
                    if any(indicator in response_lower for indicator in error_indicators):
                        if param not in self.found_parameters:
                            self.found_parameters.add(param)
                            Logger.found(f"Error-based Parameter: {param}")
                            return param
                            
                except Exception:
                    pass
            return None
        
        # Test a subset of common parameters for error-based discovery
        common_params = ['id', 'user', 'file', 'page', 'search', 'query', 'data', 'input']
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(test_error_param, param) for param in common_params]
            for future in as_completed(futures):
                future.result()
    
    def http_method_tampering(self):
        """Test different HTTP methods for parameter discovery"""
        Logger.info(f"Testing HTTP method tampering for {self.url}")
        
        methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']
        test_params = ['id', 'action', 'method', 'data']
        
        for method in methods:
            for param in test_params:
                try:
                    if method == 'GET':
                        parsed_url = urlparse(self.url)
                        test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{param}=test"
                        response = self.session.request(method, test_url, timeout=self.timeout, verify=False)
                    else:
                        data = {param: 'test'}
                        response = self.session.request(method, self.url, data=data, timeout=self.timeout, verify=False)
                    
                    if response.status_code not in [404, 405, 501] and param in response.text.lower():
                        if param not in self.found_parameters:
                            self.found_parameters.add(param)
                            Logger.found(f"Method Parameter: {param} ({method})")
                            
                except Exception:
                    pass
    
    def discover_all(self):
        """Run all parameter discovery techniques"""
        Logger.info(f"Starting comprehensive parameter discovery for {self.url}")
        
        techniques = [
            self.wordlist_fuzzing,
            self.javascript_parsing,
            self.error_based_discovery,
            self.http_method_tampering,
        ]
        
        for technique in techniques:
            try:
                technique()
            except Exception as e:
                Logger.error(f"Parameter discovery technique failed: {str(e)}")
        
        Logger.success(f"Found {len(self.found_parameters)} parameters for {self.url}")
        return list(self.found_parameters)

class ReconTool:
    """Main reconnaissance tool class"""
    
    def __init__(self):
        self.results = {
            'subdomains': [],
            'parameters': [],
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'target': None
        }
    
    def save_results(self, filename, format_type='json'):
        """Save results in different formats"""
        if format_type.lower() == 'json':
            with open(f"{filename}.json", 'w') as f:
                json.dump(self.results, f, indent=2)
            Logger.success(f"Results saved to {filename}.json")
        
        elif format_type.lower() == 'csv':
            # Save subdomains
            if self.results['subdomains']:
                with open(f"{filename}_subdomains.csv", 'w', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow(['Subdomain'])
                    for subdomain in self.results['subdomains']:
                        writer.writerow([subdomain])
                Logger.success(f"Subdomains saved to {filename}_subdomains.csv")
            
            # Save parameters
            if self.results['parameters']:
                with open(f"{filename}_parameters.csv", 'w', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow(['Parameter'])
                    for param in self.results['parameters']:
                        writer.writerow([param])
                Logger.success(f"Parameters saved to {filename}_parameters.csv")
        
        elif format_type.lower() == 'txt':
            with open(f"{filename}.txt", 'w') as f:
                f.write(f"Reconnaissance Results for {self.results['target']}\n")
                f.write(f"Timestamp: {self.results['timestamp']}\n")
                f.write("=" * 50 + "\n\n")
                
                f.write("SUBDOMAINS:\n")
                f.write("-" * 20 + "\n")
                for subdomain in self.results['subdomains']:
                    f.write(f"{subdomain}\n")
                
                f.write(f"\nPARAMETERS:\n")
                f.write("-" * 20 + "\n")
                for param in self.results['parameters']:
                    f.write(f"{param}\n")
            
            Logger.success(f"Results saved to {filename}.txt")
    
    def run_subdomain_discovery(self, domain, threads=50, timeout=10):
        """Run subdomain discovery"""
        self.results['target'] = domain
        subdomain_tool = SubdomainDiscovery(domain, threads, timeout)
        subdomains = subdomain_tool.discover_all()
        self.results['subdomains'] = sorted(subdomains)
        return subdomains
    
    def run_parameter_discovery(self, url, threads=20, timeout=10):
        """Run parameter discovery"""
        if not self.results['target']:
            self.results['target'] = url
        param_tool = ParameterDiscovery(url, threads, timeout)
        parameters = param_tool.discover_all()
        self.results['parameters'] = sorted(parameters)
        return parameters

def print_banner():
    """Print tool banner"""
    banner = f"""
{Colors.CYAN}
 █████╗ ██████╗ ██╗   ██╗ █████╗ ███╗   ██╗ ██████╗███████╗██████╗ 
██╔══██╗██╔══██╗██║   ██║██╔══██╗████╗  ██║██╔════╝██╔════╝██╔══██╗
███████║██║  ██║██║   ██║███████║██╔██╗ ██║██║     █████╗  ██║  ██║
██╔══██║██║  ██║╚██╗ ██╔╝██╔══██║██║╚██╗██║██║     ██╔══╝  ██║  ██║
██║  ██║██████╔╝ ╚████╔╝ ██║  ██║██║ ╚████║╚██████╗███████╗██████╔╝
╚═╝  ╚═╝╚═════╝   ╚═══╝  ╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝╚══════╝╚═════╝ 
                                                                     
██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗    ████████╗ ██████╗  ██████╗ ██╗     
██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║    ╚══██╔══╝██╔═══██╗██╔═══██╗██║     
██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║       ██║   ██║   ██║██║   ██║██║     
██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║       ██║   ██║   ██║██║   ██║██║     
██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║       ██║   ╚██████╔╝╚██████╔╝███████╗
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝       ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝
{Colors.END}
{Colors.BOLD}Advanced Subdomain & Parameter Discovery Tool{Colors.END}
{Colors.YELLOW}Professional reconnaissance for security researchers{Colors.END}
{Colors.GREEN}Cross-platform | Multi-threaded | Multiple Techniques{Colors.END}
"""
    print(banner)

def main():
    print_banner()
    
    parser = argparse.ArgumentParser(
        description="Advanced Subdomain and Parameter Discovery Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python advanced_recon_tool.py -d example.com --subdomains
  python advanced_recon_tool.py -u https://example.com --parameters
  python advanced_recon_tool.py -d example.com -u https://example.com --both
  python advanced_recon_tool.py -d example.com --subdomains -o results --format json
        """
    )
    
    parser.add_argument('-d', '--domain', help='Target domain for subdomain discovery')
    parser.add_argument('-u', '--url', help='Target URL for parameter discovery')
    parser.add_argument('--subdomains', action='store_true', help='Run subdomain discovery')
    parser.add_argument('--parameters', action='store_true', help='Run parameter discovery')
    parser.add_argument('--both', action='store_true', help='Run both subdomain and parameter discovery')
    parser.add_argument('-t', '--threads', type=int, default=50, help='Number of threads (default: 50)')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout in seconds (default: 10)')
    parser.add_argument('-o', '--output', help='Output filename (without extension)')
    parser.add_argument('--format', choices=['json', 'csv', 'txt'], default='json', help='Output format (default: json)')
    parser.add_argument('--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    if not any([args.subdomains, args.parameters, args.both]):
        Logger.error("Please specify --subdomains, --parameters, or --both")
        parser.print_help()
        sys.exit(1)
    
    if (args.subdomains or args.both) and not args.domain:
        Logger.error("Domain is required for subdomain discovery")
        sys.exit(1)
    
    if (args.parameters or args.both) and not args.url:
        Logger.error("URL is required for parameter discovery")
        sys.exit(1)
    
    recon_tool = ReconTool()
    
    try:
        if args.subdomains or args.both:
            Logger.info(f"Starting subdomain discovery for {args.domain}")
            subdomains = recon_tool.run_subdomain_discovery(args.domain, args.threads, args.timeout)
            
            print(f"\n{Colors.GREEN}[SUBDOMAIN RESULTS]{Colors.END}")
            print(f"Found {len(subdomains)} subdomains:")
            for subdomain in subdomains:
                print(f"  • {subdomain}")
        
        if args.parameters or args.both:
            Logger.info(f"Starting parameter discovery for {args.url}")
            parameters = recon_tool.run_parameter_discovery(args.url, args.threads, args.timeout)
            
            print(f"\n{Colors.GREEN}[PARAMETER RESULTS]{Colors.END}")
            print(f"Found {len(parameters)} parameters:")
            for param in parameters:
                print(f"  • {param}")
        
        if args.output:
            recon_tool.save_results(args.output, args.format)
        
        Logger.success("Reconnaissance completed successfully!")
        
    except KeyboardInterrupt:
        Logger.warning("Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        Logger.error(f"An error occurred: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()