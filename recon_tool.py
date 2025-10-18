#!/usr/bin/env python3
"""
Professional Reconnaissance Tool - Cross-Platform Compatible
Advanced subdomain and parameter discovery without problematic dependencies
Works on Windows and Linux without any import issues
"""

# Core imports that work everywhere
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
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, urljoin, parse_qs, urlunparse
import urllib.request
import urllib.error
import warnings

# Try to import requests with complete fallback
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

class Colors:
    """Cross-platform color support"""
    if platform.system() == "Windows":
        try:
            os.system('color')
        except:
            pass
    
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

class HTTPClient:
    """Universal HTTP client that works everywhere"""
    
    def __init__(self, timeout=10):
        self.timeout = timeout
        self.session = None
        
        # Try to use requests if available
        if REQUESTS_AVAILABLE:
            try:
                self.session = requests.Session()
                self.session.headers.update({
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                })
                Logger.info("Using requests library for HTTP")
            except Exception as e:
                Logger.warning(f"Requests failed, using urllib: {str(e)}")
                self.session = None
        else:
            Logger.info("Using urllib for HTTP (requests not available)")
    
    def get(self, url, **kwargs):
        """Make HTTP GET request with automatic fallback"""
        if self.session and REQUESTS_AVAILABLE:
            try:
                return self.session.get(url, timeout=self.timeout, verify=False, **kwargs)
            except Exception as e:
                Logger.warning(f"Requests failed for {url}, using urllib fallback")
                pass
        
        # Fallback to urllib
        return self._urllib_get(url)
    
    def post(self, url, data=None, **kwargs):
        """Make HTTP POST request with automatic fallback"""
        if self.session and REQUESTS_AVAILABLE:
            try:
                return self.session.post(url, data=data, timeout=self.timeout, verify=False, **kwargs)
            except Exception as e:
                Logger.warning(f"Requests POST failed for {url}, using urllib fallback")
                pass
        
        # Fallback to urllib
        return self._urllib_post(url, data)
    
    def _urllib_get(self, url):
        """GET request using urllib"""
        try:
            req = urllib.request.Request(url)
            req.add_header('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
            
            # Create SSL context that ignores certificates
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
            
            start_time = time.time()
            with urllib.request.urlopen(req, timeout=self.timeout, context=ssl_context) as response:
                content = response.read()
                elapsed = time.time() - start_time
                
                # Create requests-like response object
                class UrllibResponse:
                    def __init__(self, urllib_response, content, elapsed):
                        self.status_code = urllib_response.getcode()
                        self.headers = dict(urllib_response.headers)
                        self.content = content
                        self.text = content.decode('utf-8', errors='ignore')
                        self.elapsed = type('obj', (object,), {'total_seconds': lambda: elapsed})()
                
                return UrllibResponse(response, content, elapsed)
                
        except urllib.error.HTTPError as e:
            # Still return response for HTTP errors
            class ErrorResponse:
                def __init__(self, code):
                    self.status_code = code
                    self.headers = {}
                    self.content = b''
                    self.text = ''
                    self.elapsed = type('obj', (object,), {'total_seconds': lambda: 0})()
            
            return ErrorResponse(e.code)
        except Exception as e:
            raise Exception(f"HTTP request failed: {str(e)}")
    
    def _urllib_post(self, url, data=None):
        """POST request using urllib"""
        try:
            if data:
                if isinstance(data, dict):
                    data = '&'.join([f"{k}={v}" for k, v in data.items()])
                data = data.encode('utf-8')
            
            req = urllib.request.Request(url, data=data, method='POST')
            req.add_header('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
            req.add_header('Content-Type', 'application/x-www-form-urlencoded')
            
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
            
            start_time = time.time()
            with urllib.request.urlopen(req, timeout=self.timeout, context=ssl_context) as response:
                content = response.read()
                elapsed = time.time() - start_time
                
                class UrllibResponse:
                    def __init__(self, urllib_response, content, elapsed):
                        self.status_code = urllib_response.getcode()
                        self.headers = dict(urllib_response.headers)
                        self.content = content
                        self.text = content.decode('utf-8', errors='ignore')
                        self.elapsed = type('obj', (object,), {'total_seconds': lambda: elapsed})()
                
                return UrllibResponse(response, content, elapsed)
                
        except Exception as e:
            raise Exception(f"HTTP POST failed: {str(e)}")

class FastHTTPX:
    """Fast HTTP prober using threads"""
    
    def __init__(self, timeout=5, threads=20):
        self.timeout = timeout
        self.threads = threads
    
    def probe_subdomains(self, subdomains):
        """Probe subdomains quickly"""
        results = []
        
        def probe_single(subdomain):
            protocols = ['https', 'http']
            for protocol in protocols:
                try:
                    url = f"{protocol}://{subdomain}"
                    client = HTTPClient(timeout=self.timeout)
                    
                    start_time = time.time()
                    response = client.get(url)
                    response_time = time.time() - start_time
                    
                    if response.status_code:
                        # Extract title
                        title = None
                        try:
                            title_match = re.search(r'<title[^>]*>([^<]+)</title>', response.text, re.IGNORECASE)
                            if title_match:
                                title = title_match.group(1).strip()
                        except:
                            pass
                        
                        # Categorize by status code
                        if response.status_code == 200:
                            category = "Live (200 OK)"
                        elif response.status_code in [301, 302, 303, 307, 308]:
                            category = f"Redirect ({response.status_code})"
                        elif response.status_code == 403:
                            category = "Forbidden (403)"
                        elif response.status_code == 404:
                            category = "Not Found (404)"
                        elif 400 <= response.status_code < 500:
                            category = f"Client Error ({response.status_code})"
                        elif 500 <= response.status_code < 600:
                            category = f"Server Error ({response.status_code})"
                        else:
                            category = f"Other ({response.status_code})"
                        
                        result = {
                            'url': url,
                            'status_code': response.status_code,
                            'category': category,
                            'title': title,
                            'response_time': response_time,
                            'server': response.headers.get('Server', 'Unknown'),
                            'content_length': len(response.content)
                        }
                        
                        results.append((subdomain, result))
                        Logger.found(f"Live: {url} [{response.status_code}] [{response_time:.2f}s]")
                        return result
                        
                except Exception:
                    continue
            return None
        
        Logger.info(f"Probing {len(subdomains)} subdomains with {self.threads} threads")
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(probe_single, sub) for sub in subdomains]
            for future in as_completed(futures):
                future.result()
        
        # Return best result per subdomain (prefer HTTPS)
        subdomain_results = {}
        for subdomain, result in results:
            if subdomain not in subdomain_results:
                subdomain_results[subdomain] = result
            else:
                current = subdomain_results[subdomain]
                parsed_new = urlparse(result['url'])
                parsed_current = urlparse(current['url'])
                
                # Prefer HTTPS over HTTP
                if parsed_new.scheme == 'https' and parsed_current.scheme == 'http':
                    subdomain_results[subdomain] = result
        
        return subdomain_results

class TargetParser:
    """Smart target parsing"""
    
    @staticmethod
    def parse_target(target):
        target = target.strip()
        
        if target.startswith(('http://', 'https://')):
            parsed = urlparse(target)
            domain = parsed.netloc
            base_url = f"{parsed.scheme}://{parsed.netloc}"
        elif target.startswith('www.'):
            domain = target
            base_url = f"https://{target}"
        else:
            domain = target
            base_url = f"https://{target}"
        
        if ':' in domain:
            domain = domain.split(':')[0]
        
        return {
            'domain': domain,
            'base_url': base_url,
            'original': target
        }

class SubdomainHunter:
    """Professional subdomain discovery"""
    
    def __init__(self, domain, threads=50, timeout=10, wordlist_size='medium'):
        self.domain = domain
        self.threads = threads
        self.timeout = timeout
        self.found_subdomains = set()
        self.http_client = HTTPClient(timeout=timeout)
        self.wordlist = self._load_wordlist(wordlist_size)
    
    def _load_wordlist(self, size):
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
                'vault', 'consul', 'etcd', 'zookeeper', 'kafka'
            ]
            return base_wordlist + extended
        else:
            return base_wordlist
    
    def dns_bruteforce(self):
        """DNS brute-force attack"""
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
            except Exception:
                pass
            return None
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(check_subdomain, sub) for sub in self.wordlist]
            for future in as_completed(futures):
                future.result()
    
    def certificate_transparency(self):
        """Certificate Transparency logs"""
        Logger.info(f"Mining Certificate Transparency logs for {self.domain}")
        
        try:
            url = f"https://crt.sh/?q=%.{self.domain}&output=json"
            response = self.http_client.get(url)
            
            if response.status_code == 200:
                data = json.loads(response.text)
                for cert in data:
                    name_value = cert.get('name_value', '')
                    for domain in name_value.split('\n'):
                        domain = domain.strip().lower()
                        if domain and self.domain in domain and '*' not in domain:
                            if domain not in self.found_subdomains:
                                self.found_subdomains.add(domain)
                                Logger.found(f"CT: {domain}")
        except Exception as e:
            Logger.warning(f"CT search failed: {str(e)}")
    
    def dns_zone_transfer(self):
        """DNS zone transfer attempt"""
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
            Logger.warning(f"Zone transfer failed: {str(e)}")
    
    def wildcard_detection(self):
        """Wildcard detection and filtering"""
        Logger.info(f"Wildcard detection for {self.domain}")
        
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
    
    def verify_live_subdomains(self):
        """Verify live subdomains with internal/external separation"""
        Logger.info(f"Verifying live subdomains for {self.domain}")
        
        # Separate internal and public subdomains
        public_subdomains = []
        internal_subdomains = []
        
        for subdomain in self.found_subdomains:
            try:
                ip = socket.gethostbyname(subdomain)
                if (ip.startswith('10.') or 
                    ip.startswith('192.168.') or 
                    ip.startswith('172.') or 
                    ip.startswith('127.') or
                    ip == '0.0.0.0'):
                    internal_subdomains.append((subdomain, ip))
                else:
                    public_subdomains.append(subdomain)
            except:
                public_subdomains.append(subdomain)
        
        # Show internal subdomains
        live_subdomains = {}
        if internal_subdomains:
            Logger.info(f"Found {len(internal_subdomains)} internal subdomains:")
            for subdomain, ip in internal_subdomains:
                Logger.warning(f"Internal: {subdomain} -> {ip}")
                live_subdomains[subdomain] = {
                    'url': f"http://{subdomain}",
                    'status_code': None,
                    'category': f"Internal ({ip})",
                    'protocol': 'internal',
                    'title': None,
                    'content_length': None,
                    'response_time': None,
                    'server': 'Internal Network'
                }
        
        # Probe public subdomains
        if public_subdomains:
            Logger.info(f"Probing {len(public_subdomains)} public subdomains")
            httpx = FastHTTPX(timeout=5, threads=min(30, len(public_subdomains)))
            public_results = httpx.probe_subdomains(public_subdomains)
            live_subdomains.update(public_results)
        
        return live_subdomains
    
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
        
        self.wildcard_detection()
        live_subdomains = self.verify_live_subdomains()
        
        Logger.success(f"Subdomain discovery completed: {len(live_subdomains)} subdomains found")
        return live_subdomains

class ParameterHunter:
    """Professional parameter discovery"""
    
    def __init__(self, target_url, threads=20, timeout=10, wordlist_size='medium'):
        self.target_url = target_url
        self.threads = threads
        self.timeout = timeout
        self.found_parameters = set()
        self.parameter_details = {}
        self.http_client = HTTPClient(timeout=timeout)
        self.wordlist = self._load_wordlist(wordlist_size)
        self.baseline_response = None
    
    def _load_wordlist(self, size):
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
                'language', 'lang', 'timezone', 'currency', 'country', 'region'
            ]
            return base_params + extended
        else:
            return base_params
    
    def get_baseline(self):
        """Get baseline response"""
        Logger.info(f"Getting baseline response from {self.target_url}")
        try:
            response = self.http_client.get(self.target_url)
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
        """Parameter fuzzing"""
        Logger.info(f"Parameter fuzzing on {self.target_url} ({len(self.wordlist)} parameters)")
        
        test_values = ['1', 'test', 'true', 'false', '0', '', 'admin']
        
        def test_parameter(param):
            found_methods = []
            working_urls = []
            
            for value in test_values:
                try:
                    # Test GET
                    parsed_url = urlparse(self.target_url)
                    test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{param}={value}"
                    
                    response = self.http_client.get(test_url)
                    
                    if self._is_different_response(response, param, value):
                        found_methods.append('GET')
                        working_urls.append(test_url)
                    
                    # Test POST
                    post_data = {param: value}
                    response = self.http_client.post(self.target_url, data=post_data)
                    
                    if self._is_different_response(response, param, value):
                        found_methods.append('POST')
                        working_urls.append(f"{self.target_url} (POST: {param}=test)")
                    
                    if found_methods:
                        break
                        
                except Exception:
                    continue
            
            if found_methods:
                param_info = {
                    'name': param,
                    'methods': found_methods,
                    'urls': working_urls
                }
                self.found_parameters.add(param)
                
                if working_urls:
                    Logger.found(f"Parameter: {param} ({'/'.join(set(found_methods))}) -> {working_urls[0]}")
                
                return param_info
            return None
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(test_parameter, param) for param in self.wordlist]
            for future in as_completed(futures):
                result = future.result()
                if result:
                    self.parameter_details[result['name']] = result
    
    def _is_different_response(self, response, param, value):
        """Check if response is different from baseline"""
        if not self.baseline_response:
            return False
        
        try:
            # Check status code changes
            if response.status_code != self.baseline_response['status_code']:
                return True
            
            # Check content length changes
            length_diff = abs(len(response.content) - self.baseline_response['content_length'])
            if length_diff > 50:
                return True
            
            # Check for parameter reflection
            response_text = response.text.lower()
            if param.lower() in response_text or str(value).lower() in response_text:
                return True
            
            # Check for error indicators
            error_indicators = ['error', 'exception', 'warning', 'invalid', 'missing']
            if any(indicator in response_text for indicator in error_indicators):
                return True
        except:
            pass
        
        return False
    
    def javascript_analysis(self):
        """JavaScript parameter extraction"""
        Logger.info(f"JavaScript analysis for {self.target_url}")
        
        try:
            response = self.http_client.get(self.target_url)
            
            # Find JS files
            js_urls = re.findall(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', response.text, re.IGNORECASE)
            inline_js = re.findall(r'<script[^>]*>(.*?)</script>', response.text, re.DOTALL | re.IGNORECASE)
            all_js_content = '\n'.join(inline_js)
            
            # Fetch external JS files (limit to 5)
            for js_url in js_urls[:5]:
                try:
                    if js_url.startswith('//'):
                        js_url = 'https:' + js_url
                    elif js_url.startswith('/'):
                        parsed = urlparse(self.target_url)
                        js_url = f"{parsed.scheme}://{parsed.netloc}{js_url}"
                    elif not js_url.startswith('http'):
                        js_url = urljoin(self.target_url, js_url)
                    
                    js_response = self.http_client.get(js_url)
                    all_js_content += '\n' + js_response.text
                except:
                    continue
            
            # Extract parameters
            param_patterns = [
                r'["\']([a-zA-Z_][a-zA-Z0-9_]{2,})["\']:\s*["\']?[^,}]+',
                r'\.([a-zA-Z_][a-zA-Z0-9_]{2,})\s*=',
                r'[?&]([a-zA-Z_][a-zA-Z0-9_]{2,})=',
                r'name=["\']([a-zA-Z_][a-zA-Z0-9_]{2,})["\']',
            ]
            
            js_params = set()
            for pattern in param_patterns:
                matches = re.findall(pattern, all_js_content, re.IGNORECASE)
                for match in matches:
                    if len(match) > 2 and match.lower() not in ['function', 'return', 'var']:
                        js_params.add(match)
            
            for param in js_params:
                if param not in self.found_parameters:
                    self.found_parameters.add(param)
                    Logger.found(f"JS Parameter: {param}")
                    
        except Exception as e:
            Logger.warning(f"JavaScript analysis failed: {str(e)}")
    
    def run_discovery(self):
        """Execute parameter discovery"""
        Logger.phase(f"PARAMETER DISCOVERY - {self.target_url}")
        
        self.get_baseline()
        
        techniques = [
            ("Parameter Fuzzing", self.parameter_fuzzing),
            ("JavaScript Analysis", self.javascript_analysis),
        ]
        
        for name, technique in techniques:
            try:
                technique()
            except Exception as e:
                Logger.error(f"{name} failed: {str(e)}")
        
        Logger.success(f"Parameter discovery completed: {len(self.parameter_details)} parameters found")
        return self.parameter_details

class ProfessionalRecon:
    """Main reconnaissance orchestrator"""
    
    def __init__(self):
        self.results = {
            'target': None,
            'subdomains': {},
            'parameters': {},
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'statistics': {}
        }
    
    def run_subdomain_phase(self, target, threads=50, timeout=10, wordlist_size='medium'):
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
        return subdomains
    
    def run_parameter_phase(self, target, threads=20, timeout=10, wordlist_size='medium'):
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
        return parameters
    
    def save_results(self, filename, format_type='txt'):
        """Save results"""
        if format_type.lower() == 'json':
            with open(f"{filename}.json", 'w') as f:
                json.dump(self.results, f, indent=2, ensure_ascii=False)
            Logger.success(f"Results saved to {filename}.json")
        
        elif format_type.lower() == 'txt':
            with open(f"{filename}.txt", 'w', encoding='utf-8') as f:
                f.write(f"Professional Reconnaissance Report\n")
                f.write(f"Target: {self.results['target']}\n")
                f.write(f"Timestamp: {self.results['timestamp']}\n")
                f.write("=" * 80 + "\n\n")
                
                # Subdomains
                f.write(f"SUBDOMAINS ({len(self.results['subdomains'])} found):\n")
                f.write("-" * 50 + "\n")
                
                categories = {}
                for subdomain, info in self.results['subdomains'].items():
                    category = info['category']
                    if category not in categories:
                        categories[category] = []
                    categories[category].append((subdomain, info))
                
                for category, subdomains in sorted(categories.items()):
                    f.write(f"\n{category}:\n")
                    for subdomain, info in sorted(subdomains):
                        f.write(f"  {info['url']}")
                        if info.get('response_time'):
                            f.write(f" [{info['response_time']:.2f}s]")
                        if info.get('title'):
                            f.write(f" - {info['title'][:50]}")
                        f.write(f"\n")
                
                # Parameters
                f.write(f"\n\nPARAMETERS ({len(self.results['parameters'])} found):\n")
                f.write("-" * 50 + "\n")
                
                for param_name, param_info in sorted(self.results['parameters'].items()):
                    f.write(f"\nParameter: {param_name}\n")
                    f.write(f"Methods: {', '.join(param_info.get('methods', []))}\n")
                    f.write(f"Test URLs:\n")
                    for url in param_info.get('urls', []):
                        f.write(f"  {url}\n")
            
            Logger.success(f"Results saved to {filename}.txt")

def print_banner():
    """Print banner"""
    banner = f"""
{Colors.GREEN}
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
{Colors.BOLD}{Colors.GREEN}Professional Bug Bounty Reconnaissance Tool{Colors.END}
{Colors.GREEN}Advanced Subdomain & Parameter Discovery{Colors.END}
{Colors.GREEN}Cross-Platform | Multi-Threaded | Zero Dependencies{Colors.END}
"""
    print(banner)

def run_external_parameter_discovery(target, output_file=None):
    """Run external parameter discovery tool"""
    Logger.phase("EXTERNAL PARAMETER DISCOVERY")
    
    try:
        # Check if parameter.py exists
        param_tool_path = os.path.join(os.path.dirname(__file__), 'parameter.py')
        if not os.path.exists(param_tool_path):
            Logger.error("parameter.py tool not found in current directory")
            return {}
        
        Logger.info(f"Running external parameter discovery for {target}")
        
        # Prepare command
        cmd = [sys.executable, param_tool_path, '-d', target, '-q']
        if output_file:
            cmd.extend(['-o', f"{output_file}_external_params"])
        
        # Run the external tool
        import subprocess
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        
        if result.returncode == 0:
            Logger.success("External parameter discovery completed successfully")
            
            # Try to parse results from output file
            if output_file:
                result_file = f"{output_file}_external_params.txt"
                if os.path.exists(result_file):
                    Logger.info(f"External parameter results saved to {result_file}")
                    return {'status': 'success', 'output_file': result_file}
            
            return {'status': 'success', 'message': 'External parameter discovery completed'}
        else:
            Logger.error(f"External parameter discovery failed: {result.stderr}")
            return {'status': 'error', 'message': result.stderr}
            
    except subprocess.TimeoutExpired:
        Logger.error("External parameter discovery timed out (5 minutes)")
        return {'status': 'timeout'}
    except Exception as e:
        Logger.error(f"Failed to run external parameter discovery: {str(e)}")
        return {'status': 'error', 'message': str(e)}

def main():
    print_banner()
    
    parser = argparse.ArgumentParser(description="Professional Reconnaissance Tool")
    parser.add_argument('-t', '--target', required=True, help='Target domain or URL')
    parser.add_argument('--subdomains-only', action='store_true', help='Run only subdomain discovery')
    parser.add_argument('--parameters-only', action='store_true', help='Run only parameter discovery')
    parser.add_argument('--external-params', action='store_true', help='Run external parameter discovery tool')
    parser.add_argument('--threads', type=int, default=50, help='Number of threads (default: 50)')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout (default: 10)')
    parser.add_argument('--wordlist', choices=['small', 'medium', 'large'], default='medium', help='Wordlist size')
    parser.add_argument('-o', '--output', help='Output filename')
    parser.add_argument('--format', choices=['json', 'txt'], default='txt', help='Output format')
    
    args = parser.parse_args()
    
    recon = ProfessionalRecon()
    
    try:
        run_subdomains = not args.parameters_only and not args.external_params
        run_parameters = not args.subdomains_only and not args.external_params
        run_external_params = args.external_params or (not args.subdomains_only and not args.parameters_only)
        
        if run_subdomains:
            subdomains = recon.run_subdomain_phase(
                target=args.target,
                threads=args.threads,
                timeout=args.timeout,
                wordlist_size=args.wordlist
            )
            
            print(f"\n{Colors.GREEN}[SUBDOMAIN RESULTS]{Colors.END}")
            print(f"Found {len(subdomains)} subdomains:")
            
            categories = {}
            for subdomain, info in subdomains.items():
                category = info['category']
                if category not in categories:
                    categories[category] = []
                categories[category].append((subdomain, info))
            
            for category, subs in sorted(categories.items()):
                print(f"\n{Colors.YELLOW}{category}:{Colors.END}")
                for subdomain, info in sorted(subs):
                    print(f"  • {info['url']}")
        
        if run_parameters:
            parameters = recon.run_parameter_phase(
                target=args.target,
                threads=min(args.threads, 30),
                timeout=args.timeout,
                wordlist_size=args.wordlist
            )
            
            print(f"\n{Colors.GREEN}[PARAMETER RESULTS]{Colors.END}")
            print(f"Found {len(parameters)} parameters:")
            
            for param_name, param_info in sorted(parameters.items()):
                methods = ', '.join(param_info.get('methods', []))
                urls = param_info.get('urls', [])
                print(f"  • {param_name} ({methods})")
                if urls:
                    print(f"    URL: {urls[0]}")
        
        # Run external parameter discovery if requested
        if run_external_params and not args.parameters_only:
            external_result = run_external_parameter_discovery(
                args.target, 
                args.output or f"recon_{TargetParser.parse_target(args.target)['domain'].replace('.', '_')}_{int(time.time())}"
            )
            
            if external_result.get('status') == 'success':
                Logger.success("External parameter discovery completed")
                if external_result.get('output_file'):
                    print(f"{Colors.CYAN}External parameter results: {external_result['output_file']}{Colors.END}")
            else:
                Logger.warning(f"External parameter discovery failed: {external_result.get('message', 'Unknown error')}")
        
        # Save results
        if args.output:
            output_file = args.output
        else:
            parsed_target = TargetParser.parse_target(args.target)
            domain_name = parsed_target['domain'].replace('.', '_')
            output_file = f"recon_{domain_name}_{int(time.time())}"
        
        recon.save_results(output_file, args.format)
        
        Logger.phase("RECONNAISSANCE COMPLETED")
        total_subdomains = len(recon.results.get('subdomains', {}))
        total_parameters = len(recon.results.get('parameters', {}))
        print(f"{Colors.GREEN}Total Subdomains: {total_subdomains}{Colors.END}")
        print(f"{Colors.GREEN}Total Parameters: {total_parameters}{Colors.END}")
        print(f"{Colors.GREEN}Target: {recon.results.get('target', 'Unknown')}{Colors.END}")
        print(f"{Colors.CYAN}Results saved to: {output_file}.{args.format}{Colors.END}")
        
        if run_external_params and not args.parameters_only:
            print(f"{Colors.YELLOW}Note: External parameter discovery results are saved separately{Colors.END}")
        
    except KeyboardInterrupt:
        Logger.warning("Reconnaissance interrupted by user")
        sys.exit(1)
    except Exception as e:
        Logger.error(f"Reconnaissance failed: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()