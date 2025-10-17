#!/usr/bin/env python3
"""
Professional Reconnaissance Tool
Advanced subdomain and parameter discovery for bug bounty hunters

Based on research of top bug bounty tools like:
- Subfinder, Amass, Assetfinder for subdomain discovery
- Arjun, ParamSpider, GAP for parameter discovery
- Nuclei, httpx for validation and probing
"""

import requests
import dns.resolver
import dns.zone
import dns.query
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
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, urljoin, parse_qs, urlunparse
import warnings
warnings.filterwarnings("ignore", category=requests.packages.urllib3.exceptions.InsecureRequestWarning)

class Colors:
    """Cross-platform color support"""
    if platform.system() == "Windows":
        os.system('color')
    
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    END = '\033[0m'

class Logger:
    """Professional logging system"""
    
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
    
    @staticmethod
    def phase(message):
        print(f"\n{Colors.PURPLE}{'='*60}{Colors.END}")
        print(f"{Colors.PURPLE}[PHASE]{Colors.END} {Colors.BOLD}{message}{Colors.END}")
        print(f"{Colors.PURPLE}{'='*60}{Colors.END}")

class TargetParser:
    """Smart target parsing for flexible input handling"""
    
    @staticmethod
    def parse_target(target):
        """Parse target and extract domain and URL components"""
        # Remove common prefixes and clean the input
        target = target.strip()
        
        # Handle different input formats
        if target.startswith(('http://', 'https://')):
            parsed = urlparse(target)
            domain = parsed.netloc
            base_url = f"{parsed.scheme}://{parsed.netloc}"
        elif target.startswith('www.'):
            domain = target
            base_url = f"https://{target}"
        else:
            # Assume it's a domain
            domain = target
            base_url = f"https://{target}"
        
        # Clean domain (remove port if present)
        if ':' in domain:
            domain = domain.split(':')[0]
        
        return {
            'domain': domain,
            'base_url': base_url,
            'original': target
        }

class SubdomainHunter:
    """Professional subdomain discovery module"""
    
    def __init__(self, domain, threads=50, timeout=10, wordlist_size='medium'):
        self.domain = domain
        self.threads = threads
        self.timeout = timeout
        self.found_subdomains = set()
        self.session = self._create_session()
        self.wordlist = self._load_wordlist(wordlist_size)
    
    def _create_session(self):
        """Create optimized HTTP session"""
        session = requests.Session()
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        return session
    
    def _load_wordlist(self, size):
        """Load wordlist based on size preference"""
        base_wordlist = [
            'www', 'mail', 'ftp', 'admin', 'api', 'dev', 'test', 'staging', 'beta',
            'app', 'mobile', 'blog', 'shop', 'support', 'help', 'docs', 'portal',
            'cdn', 'static', 'assets', 'media', 'images', 'js', 'css', 'upload',
            'vpn', 'ssh', 'remote', 'internal', 'secure', 'ssl', 'tls', 'web',
            'old', 'new', 'backup', 'archive', 'temp', 'cache', 'log', 'db',
            'mysql', 'postgres', 'redis', 'mongo', 'elastic', 'search', 'monitoring',
            'git', 'svn', 'jenkins', 'gitlab', 'docker', 'k8s', 'prod', 'live'
        ]
        
        if size == 'small':
            return base_wordlist[:25]
        elif size == 'large':
            extended = [
                'webmail', 'smtp', 'pop', 'imap', 'ns1', 'ns2', 'dns', 'mx',
                'cpanel', 'whm', 'autodiscover', 'autoconfig', 'exchange',
                'owa', 'outlook', 'calendar', 'contacts', 'directory',
                'ldap', 'ad', 'dc', 'domain', 'forest', 'kerberos',
                'radius', 'tacacs', 'ntp', 'snmp', 'syslog', 'nagios',
                'zabbix', 'cacti', 'munin', 'grafana', 'prometheus',
                'kibana', 'logstash', 'splunk', 'elk', 'graylog',
                'sonar', 'nexus', 'artifactory', 'registry', 'harbor',
                'vault', 'consul', 'etcd', 'zookeeper', 'kafka',
                'rabbitmq', 'activemq', 'redis-cluster', 'memcached',
                'haproxy', 'nginx', 'apache', 'tomcat', 'jboss',
                'websphere', 'weblogic', 'iis', 'lighttpd', 'caddy'
            ]
            return base_wordlist + extended
        else:  # medium
            return base_wordlist
    
    def dns_bruteforce(self):
        """High-performance DNS brute-forcing"""
        Logger.info(f"DNS brute-force attack on {self.domain} ({len(self.wordlist)} subdomains)")
        
        def check_subdomain(subdomain):
            full_domain = f"{subdomain}.{self.domain}"
            try:
                answers = dns.resolver.resolve(full_domain, 'A')
                ips = [str(ip) for ip in answers]
                self.found_subdomains.add(full_domain)
                Logger.found(f"{full_domain} -> {', '.join(ips)}")
                return full_domain
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
                pass
            except Exception as e:
                pass
            return None
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(check_subdomain, sub) for sub in self.wordlist]
            for future in as_completed(futures):
                future.result()
    
    def certificate_transparency(self):
        """Certificate Transparency log mining"""
        Logger.info(f"Mining Certificate Transparency logs for {self.domain}")
        
        ct_sources = [
            f"https://crt.sh/?q=%.{self.domain}&output=json",
            f"https://api.certspotter.com/v1/issuances?domain={self.domain}&include_subdomains=true&expand=dns_names"
        ]
        
        for source in ct_sources:
            try:
                response = self.session.get(source, timeout=15)
                if response.status_code == 200:
                    if 'crt.sh' in source:
                        data = response.json()
                        for cert in data:
                            name_value = cert.get('name_value', '')
                            for domain in name_value.split('\n'):
                                domain = domain.strip().lower()
                                if domain and self.domain in domain and '*' not in domain:
                                    if domain not in self.found_subdomains:
                                        self.found_subdomains.add(domain)
                                        Logger.found(f"CT: {domain}")
                    elif 'certspotter' in source:
                        data = response.json()
                        for cert in data:
                            dns_names = cert.get('dns_names', [])
                            for domain_name in dns_names:
                                domain_name = domain_name.strip().lower()
                                if domain_name and self.domain in domain_name and '*' not in domain_name:
                                    if domain_name not in self.found_subdomains:
                                        self.found_subdomains.add(domain_name)
                                        Logger.found(f"CT: {domain_name}")
            except Exception as e:
                Logger.warning(f"CT source failed: {str(e)}")
    
    def search_engine_recon(self):
        """Search engine reconnaissance (passive)"""
        Logger.info(f"Search engine reconnaissance for {self.domain}")
        
        # Google dorking simulation (would need API in real implementation)
        search_patterns = [
            f"site:*.{self.domain}",
            f"site:{self.domain} -www",
            f"inurl:{self.domain}"
        ]
        
        Logger.info("Search engine dorking patterns prepared (API integration required)")
    
    def dns_zone_transfer(self):
        """Attempt DNS zone transfer"""
        Logger.info(f"Attempting DNS zone transfer for {self.domain}")
        
        try:
            ns_records = dns.resolver.resolve(self.domain, 'NS')
            for ns in ns_records:
                ns_server = str(ns).rstrip('.')
                try:
                    zone = dns.zone.from_xfr(dns.query.xfr(ns_server, self.domain))
                    for name, node in zone.nodes.items():
                        subdomain = f"{name}.{self.domain}" if name != '@' else self.domain
                        if subdomain not in self.found_subdomains:
                            self.found_subdomains.add(subdomain)
                            Logger.found(f"Zone Transfer: {subdomain}")
                except Exception:
                    pass
        except Exception as e:
            Logger.warning(f"Zone transfer not possible: {str(e)}")
    
    def wildcard_detection_and_filter(self):
        """Detect and filter wildcard responses"""
        Logger.info(f"Wildcard detection for {self.domain}")
        
        # Test random subdomains
        random_tests = [''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=12)) for _ in range(3)]
        wildcard_ips = set()
        
        for random_sub in random_tests:
            try:
                answers = dns.resolver.resolve(f"{random_sub}.{self.domain}", 'A')
                for ip in answers:
                    wildcard_ips.add(str(ip))
            except:
                pass
        
        if wildcard_ips:
            Logger.warning(f"Wildcard detected: {wildcard_ips}")
            # Filter wildcards from results
            filtered = set()
            for subdomain in self.found_subdomains:
                try:
                    answers = dns.resolver.resolve(subdomain, 'A')
                    subdomain_ips = {str(ip) for ip in answers}
                    if not subdomain_ips.intersection(wildcard_ips):
                        filtered.add(subdomain)
                except:
                    filtered.add(subdomain)
            self.found_subdomains = filtered
    
    def run_discovery(self):
        """Execute all subdomain discovery techniques"""
        Logger.phase(f"SUBDOMAIN DISCOVERY - {self.domain}")
        
        techniques = [
            ("DNS Brute-force", self.dns_bruteforce),
            ("Certificate Transparency", self.certificate_transparency),
            ("DNS Zone Transfer", self.dns_zone_transfer),
        ]
        
        for name, technique in techniques:
            try:
                technique()
            except Exception as e:
                Logger.error(f"{name} failed: {str(e)}")
        
        # Always run wildcard detection last
        self.wildcard_detection_and_filter()
        
        results = sorted(list(self.found_subdomains))
        Logger.success(f"Subdomain discovery completed: {len(results)} subdomains found")
        return results

class ParameterHunter:
    """Professional parameter discovery module"""
    
    def __init__(self, target_url, threads=20, timeout=10, wordlist_size='medium'):
        self.target_url = target_url
        self.threads = threads
        self.timeout = timeout
        self.found_parameters = set()
        self.session = self._create_session()
        self.wordlist = self._load_wordlist(wordlist_size)
        self.baseline_response = None
    
    def _create_session(self):
        """Create optimized HTTP session"""
        session = requests.Session()
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        return session
    
    def _load_wordlist(self, size):
        """Load parameter wordlist based on size"""
        base_params = [
            'id', 'user', 'username', 'email', 'password', 'token', 'key', 'api_key',
            'search', 'q', 'query', 'keyword', 'filter', 'sort', 'order', 'limit',
            'page', 'offset', 'count', 'size', 'start', 'end', 'from', 'to',
            'category', 'type', 'status', 'mode', 'format', 'callback', 'jsonp',
            'action', 'method', 'function', 'cmd', 'file', 'path', 'dir', 'url',
            'data', 'value', 'param', 'arg', 'var', 'name', 'title', 'content',
            'debug', 'test', 'admin', 'session', 'csrf', 'nonce', 'auth', 'login'
        ]
        
        if size == 'small':
            return base_params[:20]
        elif size == 'large':
            extended = [
                'access_token', 'refresh_token', 'client_id', 'client_secret',
                'redirect_uri', 'response_type', 'grant_type', 'scope', 'state',
                'code', 'error', 'error_description', 'error_uri', 'locale',
                'language', 'lang', 'timezone', 'currency', 'country', 'region',
                'lat', 'lng', 'latitude', 'longitude', 'address', 'city', 'zip',
                'phone', 'mobile', 'fax', 'website', 'company', 'department',
                'role', 'permission', 'group', 'team', 'project', 'task', 'issue',
                'ticket', 'message', 'comment', 'note', 'description', 'summary',
                'priority', 'severity', 'urgency', 'impact', 'category_id',
                'subcategory', 'tag', 'tags', 'label', 'labels', 'metadata'
            ]
            return base_params + extended
        else:  # medium
            return base_params
    
    def get_baseline(self):
        """Get baseline response for comparison"""
        Logger.info(f"Getting baseline response from {self.target_url}")
        try:
            response = self.session.get(self.target_url, timeout=self.timeout, verify=False)
            self.baseline_response = {
                'status_code': response.status_code,
                'content_length': len(response.content),
                'response_time': response.elapsed.total_seconds(),
                'headers': dict(response.headers)
            }
            Logger.success(f"Baseline established: {response.status_code} ({len(response.content)} bytes)")
        except Exception as e:
            Logger.error(f"Failed to get baseline: {str(e)}")
    
    def parameter_fuzzing(self):
        """Advanced parameter fuzzing with multiple techniques"""
        Logger.info(f"Parameter fuzzing on {self.target_url} ({len(self.wordlist)} parameters)")
        
        test_values = ['1', 'test', 'true', 'false', '0', '', 'admin', 'null', '[]', '{}']
        
        def test_parameter(param):
            found_methods = []
            
            for value in test_values:
                try:
                    # Test GET parameters
                    parsed_url = urlparse(self.target_url)
                    test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{param}={value}"
                    
                    response = self.session.get(test_url, timeout=self.timeout, verify=False)
                    
                    # Check for differences from baseline
                    if self._is_different_response(response, param, value):
                        found_methods.append('GET')
                    
                    # Test POST parameters
                    post_data = {param: value}
                    response = self.session.post(self.target_url, data=post_data, timeout=self.timeout, verify=False)
                    
                    if self._is_different_response(response, param, value):
                        found_methods.append('POST')
                    
                    if found_methods:
                        break
                        
                except Exception:
                    continue
            
            if found_methods:
                methods_str = '/'.join(set(found_methods))
                self.found_parameters.add(param)
                Logger.found(f"Parameter: {param} ({methods_str})")
                return param
            return None
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(test_parameter, param) for param in self.wordlist]
            for future in as_completed(futures):
                future.result()
    
    def _is_different_response(self, response, param, value):
        """Check if response is significantly different from baseline"""
        if not self.baseline_response:
            return False
        
        # Check status code changes
        if response.status_code != self.baseline_response['status_code']:
            return True
        
        # Check content length changes (significant difference)
        length_diff = abs(len(response.content) - self.baseline_response['content_length'])
        if length_diff > 50:  # Significant change
            return True
        
        # Check for parameter reflection
        response_text = response.text.lower()
        if param.lower() in response_text or str(value).lower() in response_text:
            return True
        
        # Check for error indicators
        error_indicators = ['error', 'exception', 'warning', 'invalid', 'missing', 'required']
        if any(indicator in response_text for indicator in error_indicators):
            return True
        
        return False
    
    def javascript_parameter_extraction(self):
        """Extract parameters from JavaScript files"""
        Logger.info(f"JavaScript analysis for {self.target_url}")
        
        try:
            response = self.session.get(self.target_url, timeout=self.timeout, verify=False)
            
            # Find JavaScript files
            js_urls = re.findall(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', response.text, re.IGNORECASE)
            
            # Add inline JavaScript
            inline_js = re.findall(r'<script[^>]*>(.*?)</script>', response.text, re.DOTALL | re.IGNORECASE)
            all_js_content = '\n'.join(inline_js)
            
            # Fetch external JS files
            for js_url in js_urls[:10]:  # Limit to first 10 JS files
                try:
                    if js_url.startswith('//'):
                        js_url = 'https:' + js_url
                    elif js_url.startswith('/'):
                        parsed = urlparse(self.target_url)
                        js_url = f"{parsed.scheme}://{parsed.netloc}{js_url}"
                    elif not js_url.startswith('http'):
                        js_url = urljoin(self.target_url, js_url)
                    
                    js_response = self.session.get(js_url, timeout=self.timeout, verify=False)
                    all_js_content += '\n' + js_response.text
                except:
                    continue
            
            # Extract parameters using regex patterns
            param_patterns = [
                r'["\']([a-zA-Z_][a-zA-Z0-9_]{2,})["\']:\s*["\']?[^,}]+',  # Object properties
                r'\.([a-zA-Z_][a-zA-Z0-9_]{2,})\s*=',  # Property assignments
                r'data\[["\'"]([^"\']+)["\'"]',  # Data array access
                r'params\.([a-zA-Z_][a-zA-Z0-9_]{2,})',  # params.parameter
                r'[?&]([a-zA-Z_][a-zA-Z0-9_]{2,})=',  # URL parameters
                r'name=["\']([a-zA-Z_][a-zA-Z0-9_]{2,})["\']',  # Form field names
            ]
            
            js_params = set()
            for pattern in param_patterns:
                matches = re.findall(pattern, all_js_content, re.IGNORECASE)
                for match in matches:
                    if len(match) > 2 and match.lower() not in ['function', 'return', 'var', 'let', 'const']:
                        js_params.add(match)
            
            # Add found parameters to main list
            for param in js_params:
                if param not in self.found_parameters:
                    self.found_parameters.add(param)
                    Logger.found(f"JS Parameter: {param}")
                    
        except Exception as e:
            Logger.warning(f"JavaScript analysis failed: {str(e)}")
    
    def error_based_discovery(self):
        """Error-based parameter discovery"""
        Logger.info(f"Error-based parameter discovery for {self.target_url}")
        
        error_payloads = [
            "' OR '1'='1",
            "\" OR \"1\"=\"1",
            "<script>alert(1)</script>",
            "../../../../etc/passwd",
            "{{7*7}}",
            "${7*7}",
            "<%=7*7%>",
            "../../../windows/win.ini",
            "<?php phpinfo(); ?>",
        ]
        
        common_error_params = ['id', 'user', 'file', 'page', 'search', 'data', 'input', 'name']
        
        def test_error_param(param):
            for payload in error_payloads:
                try:
                    # Test GET
                    parsed_url = urlparse(self.target_url)
                    test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{param}={payload}"
                    
                    response = self.session.get(test_url, timeout=self.timeout, verify=False)
                    
                    if self._has_error_indicators(response):
                        if param not in self.found_parameters:
                            self.found_parameters.add(param)
                            Logger.found(f"Error-based Parameter: {param}")
                            return param
                            
                except Exception:
                    pass
            return None
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(test_error_param, param) for param in common_error_params]
            for future in as_completed(futures):
                future.result()
    
    def _has_error_indicators(self, response):
        """Check if response contains error indicators"""
        error_indicators = [
            'mysql', 'postgresql', 'oracle', 'sqlite', 'mssql',
            'syntax error', 'parse error', 'fatal error', 'warning:',
            'undefined index', 'undefined variable', 'notice:',
            'exception', 'stack trace', 'debug', 'traceback',
            'error in', 'line', 'file not found', 'permission denied'
        ]
        
        response_text = response.text.lower()
        return any(indicator in response_text for indicator in error_indicators)
    
    def run_discovery(self):
        """Execute all parameter discovery techniques"""
        Logger.phase(f"PARAMETER DISCOVERY - {self.target_url}")
        
        # Get baseline first
        self.get_baseline()
        
        techniques = [
            ("Parameter Fuzzing", self.parameter_fuzzing),
            ("JavaScript Analysis", self.javascript_parameter_extraction),
            ("Error-based Discovery", self.error_based_discovery),
        ]
        
        for name, technique in techniques:
            try:
                technique()
            except Exception as e:
                Logger.error(f"{name} failed: {str(e)}")
        
        results = sorted(list(self.found_parameters))
        Logger.success(f"Parameter discovery completed: {len(results)} parameters found")
        return results

class ProfessionalRecon:
    """Main reconnaissance orchestrator"""
    
    def __init__(self):
        self.results = {
            'target': None,
            'subdomains': [],
            'parameters': [],
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'statistics': {}
        }
    
    def run_subdomain_phase(self, target, threads=50, timeout=10, wordlist_size='medium'):
        """Run subdomain discovery phase"""
        parsed_target = TargetParser.parse_target(target)
        self.results['target'] = parsed_target['original']
        
        hunter = SubdomainHunter(
            domain=parsed_target['domain'],
            threads=threads,
            timeout=timeout,
            wordlist_size=wordlist_size
        )
        
        subdomains = hunter.run_discovery()
        self.results['subdomains'] = subdomains
        self.results['statistics']['subdomains_found'] = len(subdomains)
        
        return subdomains
    
    def run_parameter_phase(self, target, threads=20, timeout=10, wordlist_size='medium'):
        """Run parameter discovery phase"""
        parsed_target = TargetParser.parse_target(target)
        if not self.results['target']:
            self.results['target'] = parsed_target['original']
        
        hunter = ParameterHunter(
            target_url=parsed_target['base_url'],
            threads=threads,
            timeout=timeout,
            wordlist_size=wordlist_size
        )
        
        parameters = hunter.run_discovery()
        self.results['parameters'] = parameters
        self.results['statistics']['parameters_found'] = len(parameters)
        
        return parameters
    
    def save_results(self, filename, format_type='json'):
        """Save results in professional format"""
        if format_type.lower() == 'json':
            with open(f"{filename}.json", 'w') as f:
                json.dump(self.results, f, indent=2, ensure_ascii=False)
            Logger.success(f"Results saved to {filename}.json")
        
        elif format_type.lower() == 'txt':
            with open(f"{filename}.txt", 'w', encoding='utf-8') as f:
                f.write(f"Professional Reconnaissance Report\n")
                f.write(f"Target: {self.results['target']}\n")
                f.write(f"Timestamp: {self.results['timestamp']}\n")
                f.write("=" * 60 + "\n\n")
                
                f.write(f"SUBDOMAINS ({len(self.results['subdomains'])} found):\n")
                f.write("-" * 30 + "\n")
                for subdomain in self.results['subdomains']:
                    f.write(f"{subdomain}\n")
                
                f.write(f"\nPARAMETERS ({len(self.results['parameters'])} found):\n")
                f.write("-" * 30 + "\n")
                for param in self.results['parameters']:
                    f.write(f"{param}\n")
            
            Logger.success(f"Results saved to {filename}.txt")

def print_banner():
    """Print professional banner"""
    banner = f"""
{Colors.CYAN}
 ██████╗ ██████╗  ██████╗ ███████╗███████╗███████╗██╗ ██████╗ ███╗   ██╗ █████╗ ██╗     
 ██╔══██╗██╔══██╗██╔═══██╗██╔════╝██╔════╝██╔════╝██║██╔═══██╗████╗  ██║██╔══██╗██║     
 ██████╔╝██████╔╝██║   ██║█████╗  █████╗  ███████╗██║██║   ██║██╔██╗ ██║███████║██║     
 ██╔═══╝ ██╔══██╗██║   ██║██╔══╝  ██╔══╝  ╚════██║██║██║   ██║██║╚██╗██║██╔══██║██║     
 ██║     ██║  ██║╚██████╔╝██║     ███████╗███████║██║╚██████╔╝██║ ╚████║██║  ██║███████╗
 ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═╝     ╚══════╝╚══════╝╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝
                                                                                          
 ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗    ████████╗ ██████╗  ██████╗ ██╗         
 ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║    ╚══██╔══╝██╔═══██╗██╔═══██╗██║         
 ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║       ██║   ██║   ██║██║   ██║██║         
 ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║       ██║   ██║   ██║██║   ██║██║         
 ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║       ██║   ╚██████╔╝╚██████╔╝███████╗    
 ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝       ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝    
{Colors.END}
{Colors.BOLD}Professional Bug Bounty Reconnaissance Tool{Colors.END}
{Colors.YELLOW}Advanced Subdomain & Parameter Discovery{Colors.END}
{Colors.GREEN}Cross-Platform | Multi-Threaded | Modular Architecture{Colors.END}
"""
    print(banner)

def main():
    print_banner()
    
    parser = argparse.ArgumentParser(
        description="Professional Reconnaissance Tool for Bug Bounty Hunters",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Single target - both phases (default)
  python professional_recon.py -t example.com
  python professional_recon.py -t https://example.com
  
  # Specific phases
  python professional_recon.py -t example.com --subdomains-only
  python professional_recon.py -t https://example.com --parameters-only
  
  # Advanced options
  python professional_recon.py -t example.com --threads 100 --wordlist large -o results
  python professional_recon.py -t example.com --timeout 15 --format txt
        """
    )
    
    parser.add_argument('-t', '--target', required=True, help='Target domain or URL')
    parser.add_argument('--subdomains-only', action='store_true', help='Run only subdomain discovery')
    parser.add_argument('--parameters-only', action='store_true', help='Run only parameter discovery')
    parser.add_argument('--threads', type=int, default=50, help='Number of threads (default: 50)')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout (default: 10)')
    parser.add_argument('--wordlist', choices=['small', 'medium', 'large'], default='medium', help='Wordlist size (default: medium)')
    parser.add_argument('-o', '--output', help='Output filename (without extension)')
    parser.add_argument('--format', choices=['json', 'txt'], default='json', help='Output format (default: json)')
    
    args = parser.parse_args()
    
    # Initialize reconnaissance tool
    recon = ProfessionalRecon()
    
    try:
        # Determine which phases to run
        run_subdomains = not args.parameters_only
        run_parameters = not args.subdomains_only
        
        # Run subdomain discovery phase
        if run_subdomains:
            subdomains = recon.run_subdomain_phase(
                target=args.target,
                threads=args.threads,
                timeout=args.timeout,
                wordlist_size=args.wordlist
            )
            
            print(f"\n{Colors.GREEN}[SUBDOMAIN RESULTS]{Colors.END}")
            print(f"Found {len(subdomains)} subdomains:")
            for subdomain in subdomains:
                print(f"  • {subdomain}")
        
        # Run parameter discovery phase
        if run_parameters:
            parameters = recon.run_parameter_phase(
                target=args.target,
                threads=min(args.threads, 30),  # Limit threads for parameters
                timeout=args.timeout,
                wordlist_size=args.wordlist
            )
            
            print(f"\n{Colors.GREEN}[PARAMETER RESULTS]{Colors.END}")
            print(f"Found {len(parameters)} parameters:")
            for param in parameters:
                print(f"  • {param}")
        
        # Save results if requested
        if args.output:
            recon.save_results(args.output, args.format)
        
        # Final summary
        Logger.phase("RECONNAISSANCE COMPLETED")
        total_subdomains = len(recon.results.get('subdomains', []))
        total_parameters = len(recon.results.get('parameters', []))
        print(f"{Colors.GREEN}Total Subdomains: {total_subdomains}{Colors.END}")
        print(f"{Colors.GREEN}Total Parameters: {total_parameters}{Colors.END}")
        print(f"{Colors.GREEN}Target: {recon.results.get('target', 'Unknown')}{Colors.END}")
        
    except KeyboardInterrupt:
        Logger.warning("Reconnaissance interrupted by user")
        sys.exit(1)
    except Exception as e:
        Logger.error(f"Reconnaissance failed: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()