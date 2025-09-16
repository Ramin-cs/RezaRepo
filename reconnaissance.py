#!/usr/bin/env python3
"""
Advanced Reconnaissance Tool for Bug Bounty
Comprehensive reconnaissance and vulnerability scanning tool

Author: Security Researcher
Version: 1.0.0
"""

import requests
import dns.resolver
import socket
import re
import json
import time
import threading
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
from colorama import init, Fore, Style
from tqdm import tqdm
import concurrent.futures
from fake_useragent import UserAgent
import whois
import subprocess
import os
from datetime import datetime

# Initialize colorama for colored output
init(autoreset=True)

class ReconnaissanceTool:
    """
    Advanced reconnaissance tool that performs comprehensive information gathering
    including subdomain discovery, directory enumeration, parameter discovery, and WAF detection
    """
    
    def __init__(self, target_domain, output_dir="recon_results"):
        """
        Initialize the reconnaissance tool
        
        Args:
            target_domain (str): Target domain to perform reconnaissance on
            output_dir (str): Directory to save results
        """
        self.target_domain = target_domain
        self.output_dir = output_dir
        self.session = requests.Session()
        self.ua = UserAgent()
        self.results = {
            'target': target_domain,
            'timestamp': datetime.now().isoformat(),
            'subdomains': [],
            'directories': [],
            'parameters': [],
            'waf_info': {},
            'vulnerabilities': []
        }
        
        # Create output directory
        os.makedirs(output_dir, exist_ok=True)
        
        # Set up session headers
        self.session.headers.update({
            'User-Agent': self.ua.random,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        })
        
        self.print_banner()
    
    def print_banner(self):
        """Print tool banner"""
        banner = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗
║                    ADVANCED RECONNAISSANCE TOOL                    ║
║                        Bug Bounty Edition                          ║
╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}

{Fore.YELLOW}Target: {self.target_domain}
Output Directory: {self.output_dir}
Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Style.RESET_ALL}
"""
        print(banner)
    
    def log(self, message, level="INFO"):
        """Log messages with timestamps and colors"""
        timestamp = datetime.now().strftime('%H:%M:%S')
        colors = {
            'INFO': Fore.BLUE,
            'SUCCESS': Fore.GREEN,
            'WARNING': Fore.YELLOW,
            'ERROR': Fore.RED,
            'CRITICAL': Fore.MAGENTA
        }
        color = colors.get(level, Fore.WHITE)
        print(f"{color}[{timestamp}] [{level}] {message}{Style.RESET_ALL}")
    
    def save_results(self):
        """Save results to JSON file"""
        output_file = os.path.join(self.output_dir, f"{self.target_domain}_recon.json")
        with open(output_file, 'w') as f:
            json.dump(self.results, f, indent=2)
        self.log(f"Results saved to {output_file}", "SUCCESS")
    
    def passive_subdomain_discovery(self):
        """
        Perform passive subdomain discovery using various sources
        """
        self.log("Starting passive subdomain discovery...", "INFO")
        
        subdomains = set()
        
        # Common subdomain wordlist
        common_subdomains = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk', 'ns2',
            'cpanel', 'whm', 'autodiscover', 'autoconfig', 'm', 'imap', 'test', 'ns', 'blog',
            'pop3', 'dev', 'www2', 'admin', 'forum', 'news', 'vpn', 'ns3', 'mail2', 'new',
            'mysql', 'old', 'www1', 'beta', 'shop', 'api', 'secure', 'demo', 'www3', 'dns2',
            'mail3', 'search', 'staging', 'server', 'mx', 'chat', 'wap', 'my', 'svn', 'mail1',
            'sites', 'proxy', 'ads', 'host', 'crm', 'cms', 'backup', 'mx1', 'static', 'docs',
            'beta', 'staging', 'app', 'dev2', 'admin2', 'mx2', 'cdn', 'api2', 'secure2',
            'test2', 'mail4', 'static2', 'beta2', 'staging2', 'app2', 'dev3', 'admin3'
        ]
        
        # DNS brute force for common subdomains
        self.log("Performing DNS brute force for common subdomains...", "INFO")
        for subdomain in tqdm(common_subdomains, desc="DNS Brute Force"):
            try:
                full_domain = f"{subdomain}.{self.target_domain}"
                dns.resolver.resolve(full_domain, 'A')
                subdomains.add(full_domain)
                self.log(f"Found subdomain: {full_domain}", "SUCCESS")
            except:
                pass
        
        # Certificate Transparency logs
        self.log("Checking Certificate Transparency logs...", "INFO")
        try:
            ct_subdomains = self.check_certificate_transparency()
            subdomains.update(ct_subdomains)
        except Exception as e:
            self.log(f"Error checking CT logs: {e}", "WARNING")
        
        # Search engines (simulated)
        self.log("Checking search engines for subdomains...", "INFO")
        try:
            search_subdomains = self.search_engines_subdomain_discovery()
            subdomains.update(search_subdomains)
        except Exception as e:
            self.log(f"Error in search engine discovery: {e}", "WARNING")
        
        self.results['subdomains'] = list(subdomains)
        self.log(f"Passive discovery found {len(subdomains)} subdomains", "SUCCESS")
        return list(subdomains)
    
    def check_certificate_transparency(self):
        """Check Certificate Transparency logs for subdomains"""
        subdomains = set()
        try:
            # Using crt.sh API
            url = f"https://crt.sh/?q=%.{self.target_domain}&output=json"
            response = self.session.get(url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                for cert in data:
                    if 'name_value' in cert:
                        names = cert['name_value'].split('\n')
                        for name in names:
                            if self.target_domain in name and '*' not in name:
                                subdomains.add(name.strip())
        except Exception as e:
            self.log(f"Error checking CT logs: {e}", "WARNING")
        
        return subdomains
    
    def search_engines_subdomain_discovery(self):
        """Simulate search engine subdomain discovery"""
        subdomains = set()
        
        # This is a simplified version - in real implementation, you would use
        # actual search engine APIs or scraping techniques
        search_queries = [
            f"site:{self.target_domain}",
            f"site:*.{self.target_domain}",
            f"inurl:{self.target_domain}"
        ]
        
        # For demonstration, we'll add some common patterns
        common_patterns = [
            f"admin.{self.target_domain}",
            f"api.{self.target_domain}",
            f"staging.{self.target_domain}",
            f"dev.{self.target_domain}",
            f"test.{self.target_domain}"
        ]
        
        for pattern in common_patterns:
            subdomains.add(pattern)
        
        return subdomains
    
    def active_subdomain_discovery(self, subdomains):
        """
        Perform active subdomain discovery and validation
        
        Args:
            subdomains (list): List of potential subdomains to validate
        """
        self.log("Starting active subdomain validation...", "INFO")
        
        valid_subdomains = []
        
        def check_subdomain(subdomain):
            try:
                # Check if subdomain resolves
                socket.gethostbyname(subdomain)
                
                # Check if it's accessible via HTTP/HTTPS
                for protocol in ['http', 'https']:
                    try:
                        url = f"{protocol}://{subdomain}"
                        response = self.session.get(url, timeout=5, allow_redirects=True)
                        if response.status_code in [200, 301, 302, 403, 401]:
                            valid_subdomains.append({
                                'subdomain': subdomain,
                                'protocol': protocol,
                                'status_code': response.status_code,
                                'title': self.extract_title(response.text),
                                'server': response.headers.get('Server', 'Unknown')
                            })
                            self.log(f"Valid subdomain: {subdomain} ({protocol}) - {response.status_code}", "SUCCESS")
                            break
                    except:
                        continue
            except:
                pass
        
        # Use thread pool for concurrent checking
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            executor.map(check_subdomain, subdomains)
        
        self.results['valid_subdomains'] = valid_subdomains
        self.log(f"Active validation found {len(valid_subdomains)} valid subdomains", "SUCCESS")
        return valid_subdomains
    
    def extract_title(self, html_content):
        """Extract page title from HTML content"""
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            title = soup.find('title')
            return title.text.strip() if title else "No title"
        except:
            return "Error extracting title"
    
    def directory_discovery(self, base_url):
        """
        Perform directory and file discovery
        
        Args:
            base_url (str): Base URL to perform directory discovery on
        """
        self.log(f"Starting directory discovery on {base_url}...", "INFO")
        
        # Common directory and file wordlist
        wordlist = [
            'admin', 'administrator', 'login', 'wp-admin', 'phpmyadmin', 'admin.php',
            'config', 'configuration', 'backup', 'backups', 'old', 'test', 'testing',
            'dev', 'development', 'staging', 'api', 'v1', 'v2', 'docs', 'documentation',
            'files', 'uploads', 'images', 'img', 'css', 'js', 'assets', 'static',
            'robots.txt', 'sitemap.xml', '.htaccess', '.env', 'config.php', 'wp-config.php',
            'database', 'db', 'sql', 'mysql', 'postgres', 'oracle', 'mssql',
            'logs', 'log', 'error', 'errors', 'debug', 'info', 'status',
            'cgi-bin', 'bin', 'tmp', 'temp', 'cache', 'session', 'sessions',
            'user', 'users', 'profile', 'profiles', 'account', 'accounts',
            'search', 'find', 'query', 'results', 'index', 'home', 'main',
            'about', 'contact', 'help', 'support', 'faq', 'terms', 'privacy'
        ]
        
        found_directories = []
        
        def check_directory(path):
            try:
                url = urljoin(base_url, path)
                response = self.session.get(url, timeout=5, allow_redirects=False)
                
                if response.status_code in [200, 301, 302, 403, 401]:
                    found_directories.append({
                        'path': path,
                        'url': url,
                        'status_code': response.status_code,
                        'content_length': len(response.content),
                        'server': response.headers.get('Server', 'Unknown')
                    })
                    self.log(f"Found: {path} - {response.status_code}", "SUCCESS")
            except:
                pass
        
        # Use thread pool for concurrent directory checking
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            executor.map(check_directory, wordlist)
        
        self.results['directories'] = found_directories
        self.log(f"Directory discovery found {len(found_directories)} directories/files", "SUCCESS")
        return found_directories
    
    def parameter_discovery(self, base_url):
        """
        Perform comprehensive parameter discovery using various techniques
        
        Args:
            base_url (str): Base URL to discover parameters for
        """
        self.log(f"Starting comprehensive parameter discovery on {base_url}...", "INFO")
        
        parameters = set()
        
        # 1. Check Wayback Machine for historical URLs
        self.log("Checking Wayback Machine for historical URLs...", "INFO")
        try:
            wayback_params = self.check_wayback_machine(base_url)
            parameters.update(wayback_params)
        except Exception as e:
            self.log(f"Error checking Wayback Machine: {e}", "WARNING")
        
        # 2. Extract parameters from current page forms
        self.log("Extracting parameters from HTML forms...", "INFO")
        try:
            form_params = self.extract_form_parameters(base_url)
            parameters.update(form_params)
        except Exception as e:
            self.log(f"Error extracting form parameters: {e}", "WARNING")
        
        # 3. Extract parameters from JavaScript files
        self.log("Extracting parameters from JavaScript files...", "INFO")
        try:
            js_params = self.extract_js_parameters(base_url)
            parameters.update(js_params)
        except Exception as e:
            self.log(f"Error extracting JS parameters: {e}", "WARNING")
        
        # 4. Extract parameters from HTTP headers
        self.log("Extracting parameters from HTTP headers...", "INFO")
        try:
            header_params = self.extract_header_parameters(base_url)
            parameters.update(header_params)
        except Exception as e:
            self.log(f"Error extracting header parameters: {e}", "WARNING")
        
        # 5. Extract parameters from cookies
        self.log("Extracting parameters from cookies...", "INFO")
        try:
            cookie_params = self.extract_cookie_parameters(base_url)
            parameters.update(cookie_params)
        except Exception as e:
            self.log(f"Error extracting cookie parameters: {e}", "WARNING")
        
        # 6. Common parameter wordlist
        common_params = [
            'id', 'page', 'view', 'action', 'cmd', 'command', 'exec', 'execute',
            'file', 'path', 'dir', 'directory', 'url', 'link', 'href', 'src',
            'user', 'username', 'pass', 'password', 'email', 'mail', 'phone',
            'name', 'title', 'subject', 'message', 'content', 'text', 'data',
            'search', 'query', 'q', 'find', 'filter', 'sort', 'order', 'limit',
            'offset', 'start', 'end', 'from', 'to', 'date', 'time', 'year',
            'month', 'day', 'category', 'type', 'format', 'mode', 'lang',
            'language', 'locale', 'country', 'region', 'state', 'city',
            'zip', 'code', 'key', 'token', 'session', 'sid', 'uid', 'pid',
            'ref', 'referer', 'return', 'redirect', 'next', 'callback',
            'jsonp', 'callback', 'format', 'output', 'response', 'result',
            # Additional common parameters
            'callback', 'jsonp', 'format', 'output', 'response', 'result',
            'debug', 'test', 'admin', 'api', 'v1', 'v2', 'version', 'ver',
            'lang', 'language', 'locale', 'country', 'region', 'state',
            'city', 'zip', 'code', 'key', 'token', 'session', 'sid',
            'uid', 'pid', 'ref', 'referer', 'return', 'redirect', 'next',
            'continue', 'goto', 'target', 'destination', 'success', 'error',
            'status', 'state', 'mode', 'action', 'method', 'type', 'kind',
            'class', 'style', 'theme', 'color', 'size', 'width', 'height',
            'x', 'y', 'z', 'lat', 'lng', 'latitude', 'longitude', 'coords',
            'address', 'location', 'place', 'venue', 'building', 'room',
            'floor', 'level', 'section', 'area', 'zone', 'region', 'district',
            'neighborhood', 'block', 'street', 'avenue', 'road', 'lane',
            'drive', 'way', 'circle', 'court', 'place', 'plaza', 'square'
        ]
        
        # 7. Test common parameters with response analysis
        self.log("Testing common parameters with response analysis...", "INFO")
        for param in tqdm(common_params, desc="Parameter Testing"):
            try:
                test_url = f"{base_url}?{param}=test"
                response = self.session.get(test_url, timeout=5)
                
                # Check if parameter affects response
                baseline_response = self.session.get(base_url, timeout=5)
                
                # Multiple checks for parameter validation
                if self.validate_parameter_impact(response, baseline_response, param):
                    parameters.add(param)
                    self.log(f"Found parameter: {param}", "SUCCESS")
            except:
                continue
        
        self.results['parameters'] = list(parameters)
        self.log(f"Comprehensive parameter discovery found {len(parameters)} parameters", "SUCCESS")
        return list(parameters)
    
    def extract_form_parameters(self, base_url):
        """Extract parameters from HTML forms"""
        parameters = set()
        try:
            response = self.session.get(base_url, timeout=5)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Find all forms
            forms = soup.find_all('form')
            for form in forms:
                # Get form action
                action = form.get('action', '')
                
                # Find all input fields
                inputs = form.find_all(['input', 'textarea', 'select'])
                for input_field in inputs:
                    name = input_field.get('name')
                    if name:
                        parameters.add(name)
                
                # Find all hidden fields
                hidden_inputs = form.find_all('input', {'type': 'hidden'})
                for hidden in hidden_inputs:
                    name = hidden.get('name')
                    if name:
                        parameters.add(name)
            
            # Find standalone input fields outside forms
            standalone_inputs = soup.find_all(['input', 'textarea', 'select'])
            for input_field in standalone_inputs:
                name = input_field.get('name')
                if name:
                    parameters.add(name)
                    
        except Exception as e:
            self.log(f"Error extracting form parameters: {e}", "WARNING")
        
        return parameters
    
    def extract_js_parameters(self, base_url):
        """Extract parameters from JavaScript files"""
        parameters = set()
        try:
            response = self.session.get(base_url, timeout=5)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Find all script tags
            scripts = soup.find_all('script')
            for script in scripts:
                if script.string:
                    # Look for common parameter patterns in JS
                    js_content = script.string
                    
                    # Pattern 1: URL parameters
                    import re
                    url_patterns = re.findall(r'[?&]([a-zA-Z_][a-zA-Z0-9_]*)=', js_content)
                    parameters.update(url_patterns)
                    
                    # Pattern 2: Form data
                    form_patterns = re.findall(r'\.([a-zA-Z_][a-zA-Z0-9_]*)\s*=', js_content)
                    parameters.update(form_patterns)
                    
                    # Pattern 3: AJAX parameters
                    ajax_patterns = re.findall(r'data\s*:\s*\{([^}]+)\}', js_content)
                    for ajax_match in ajax_patterns:
                        param_matches = re.findall(r'([a-zA-Z_][a-zA-Z0-9_]*)\s*:', ajax_match)
                        parameters.update(param_matches)
            
            # Find external JS files
            script_srcs = soup.find_all('script', src=True)
            for script_src in script_srcs:
                try:
                    js_url = urljoin(base_url, script_src['src'])
                    js_response = self.session.get(js_url, timeout=5)
                    if js_response.status_code == 200:
                        js_content = js_response.text
                        
                        # Extract parameters from external JS
                        url_patterns = re.findall(r'[?&]([a-zA-Z_][a-zA-Z0-9_]*)=', js_content)
                        parameters.update(url_patterns)
                        
                        form_patterns = re.findall(r'\.([a-zA-Z_][a-zA-Z0-9_]*)\s*=', js_content)
                        parameters.update(form_patterns)
                except:
                    continue
                    
        except Exception as e:
            self.log(f"Error extracting JS parameters: {e}", "WARNING")
        
        return parameters
    
    def extract_header_parameters(self, base_url):
        """Extract parameters from HTTP headers"""
        parameters = set()
        try:
            response = self.session.get(base_url, timeout=5)
            
            # Check for parameters in headers
            headers_to_check = [
                'User-Agent', 'Referer', 'X-Forwarded-For', 'X-Real-IP',
                'X-Forwarded-Host', 'X-Forwarded-Proto', 'X-Original-URL',
                'X-Rewrite-URL', 'X-Forwarded-Server', 'X-Host', 'X-Forwarded',
                'X-Cluster-Client-IP', 'X-Client-IP', 'X-Remote-IP', 'X-Remote-Addr'
            ]
            
            for header in headers_to_check:
                if header in response.request.headers:
                    # Extract potential parameters from header values
                    header_value = response.request.headers[header]
                    if '=' in header_value:
                        # Split by common separators
                        parts = re.split(r'[;&,]', header_value)
                        for part in parts:
                            if '=' in part:
                                param_name = part.split('=')[0].strip()
                                if param_name:
                                    parameters.add(param_name)
                                    
        except Exception as e:
            self.log(f"Error extracting header parameters: {e}", "WARNING")
        
        return parameters
    
    def extract_cookie_parameters(self, base_url):
        """Extract parameters from cookies"""
        parameters = set()
        try:
            response = self.session.get(base_url, timeout=5)
            
            # Check cookies for parameters
            for cookie in self.session.cookies:
                cookie_name = cookie.name
                parameters.add(cookie_name)
                
                # Check cookie value for parameters
                cookie_value = cookie.value
                if '=' in cookie_value:
                    parts = re.split(r'[;&,]', cookie_value)
                    for part in parts:
                        if '=' in part:
                            param_name = part.split('=')[0].strip()
                            if param_name:
                                parameters.add(param_name)
                                
        except Exception as e:
            self.log(f"Error extracting cookie parameters: {e}", "WARNING")
        
        return parameters
    
    def validate_parameter_impact(self, test_response, baseline_response, param):
        """Validate if parameter actually affects the response"""
        try:
            # Check content length difference
            if len(test_response.content) != len(baseline_response.content):
                return True
            
            # Check for parameter reflection in response
            if param in test_response.text:
                return True
            
            # Check for different status codes
            if test_response.status_code != baseline_response.status_code:
                return True
            
            # Check for different headers
            test_headers = set(test_response.headers.keys())
            baseline_headers = set(baseline_response.headers.keys())
            if test_headers != baseline_headers:
                return True
            
            # Check for different response times (basic check)
            if abs(len(test_response.content) - len(baseline_response.content)) > 100:
                return True
            
            return False
            
        except:
            return False
    
    def check_wayback_machine(self, base_url):
        """Check Wayback Machine for historical URLs and parameters"""
        parameters = set()
        try:
            # Wayback Machine API
            wayback_url = f"http://web.archive.org/cdx/search/cdx?url={base_url}/*&output=json&fl=original&collapse=urlkey"
            response = self.session.get(wayback_url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                for url_data in data[1:]:  # Skip header
                    url = url_data[0]
                    parsed = urlparse(url)
                    if parsed.query:
                        query_params = parsed.query.split('&')
                        for param in query_params:
                            if '=' in param:
                                param_name = param.split('=')[0]
                                parameters.add(param_name)
        except Exception as e:
            self.log(f"Error accessing Wayback Machine: {e}", "WARNING")
        
        return parameters
    
    def waf_detection(self, base_url):
        """
        Detect Web Application Firewall (WAF)
        
        Args:
            base_url (str): Base URL to test for WAF
        """
        self.log(f"Starting WAF detection on {base_url}...", "INFO")
        
        waf_info = {
            'detected': False,
            'type': 'Unknown',
            'confidence': 0,
            'indicators': []
        }
        
        # WAF detection payloads
        waf_payloads = [
            # SQL Injection payloads
            "' OR '1'='1",
            "'; DROP TABLE users; --",
            "1' UNION SELECT 1,2,3--",
            
            # XSS payloads
            "<script>alert('XSS')</script>",
            "javascript:alert('XSS')",
            "<img src=x onerror=alert('XSS')>",
            
            # Path traversal
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            
            # Command injection
            "; ls -la",
            "| whoami",
            "&& id"
        ]
        
        for payload in waf_payloads:
            try:
                # Test with different parameter names
                test_urls = [
                    f"{base_url}?id={payload}",
                    f"{base_url}?search={payload}",
                    f"{base_url}?q={payload}",
                    f"{base_url}?file={payload}"
                ]
                
                for test_url in test_urls:
                    response = self.session.get(test_url, timeout=5)
                    
                    # Check for WAF indicators in response
                    waf_indicators = self.check_waf_indicators(response)
                    if waf_indicators:
                        waf_info['detected'] = True
                        waf_info['indicators'].extend(waf_indicators)
                        waf_info['confidence'] += 10
                        
            except:
                continue
        
        # Check response headers for WAF signatures
        try:
            response = self.session.get(base_url, timeout=5)
            header_indicators = self.check_waf_headers(response.headers)
            if header_indicators:
                waf_info['detected'] = True
                waf_info['indicators'].extend(header_indicators)
                waf_info['confidence'] += 20
        except:
            pass
        
        # Determine WAF type based on indicators
        if waf_info['detected']:
            waf_info['type'] = self.determine_waf_type(waf_info['indicators'])
        
        self.results['waf_info'] = waf_info
        self.log(f"WAF detection completed - Detected: {waf_info['detected']}, Type: {waf_info['type']}", "SUCCESS")
        return waf_info
    
    def check_waf_indicators(self, response):
        """Check response for WAF indicators"""
        indicators = []
        
        # Common WAF response patterns
        waf_patterns = [
            r'blocked by.*firewall',
            r'access denied',
            r'forbidden',
            r'security.*violation',
            r'request.*blocked',
            r'cloudflare',
            r'incapsula',
            r'akamai',
            r'barracuda',
            r'f5',
            r'fortinet',
            r'checkpoint',
            r'palo alto',
            r'juniper',
            r'cisco',
            r'aws.*waf',
            r'azure.*waf'
        ]
        
        content = response.text.lower()
        for pattern in waf_patterns:
            if re.search(pattern, content):
                indicators.append(f"Content pattern: {pattern}")
        
        # Check status codes
        if response.status_code in [403, 406, 418, 429, 503]:
            indicators.append(f"Suspicious status code: {response.status_code}")
        
        return indicators
    
    def check_waf_headers(self, headers):
        """Check response headers for WAF signatures"""
        indicators = []
        
        waf_headers = {
            'cf-ray': 'Cloudflare',
            'x-sucuri-id': 'Sucuri',
            'x-sucuri-cache': 'Sucuri',
            'x-akamai-transformed': 'Akamai',
            'x-cache': 'Akamai',
            'x-imforwards': 'Incapsula',
            'x-iinfo': 'Incapsula',
            'x-protected-by': 'Various WAFs',
            'x-security': 'Various WAFs',
            'server': 'WAF Server Header'
        }
        
        for header, waf_type in waf_headers.items():
            if header in headers:
                indicators.append(f"Header {header}: {waf_type}")
        
        return indicators
    
    def determine_waf_type(self, indicators):
        """Determine WAF type based on indicators"""
        waf_types = {
            'cloudflare': 0,
            'incapsula': 0,
            'akamai': 0,
            'sucuri': 0,
            'barracuda': 0,
            'f5': 0,
            'aws': 0,
            'azure': 0
        }
        
        for indicator in indicators:
            indicator_lower = indicator.lower()
            for waf_type in waf_types:
                if waf_type in indicator_lower:
                    waf_types[waf_type] += 1
        
        # Return WAF type with highest score
        if max(waf_types.values()) > 0:
            return max(waf_types, key=waf_types.get).title()
        else:
            return 'Unknown'
    
    def run_complete_reconnaissance(self):
        """
        Run complete reconnaissance process
        """
        self.log("Starting complete reconnaissance process...", "CRITICAL")
        
        try:
            # Phase 1: Passive subdomain discovery
            subdomains = self.passive_subdomain_discovery()
            
            # Phase 2: Active subdomain validation
            valid_subdomains = self.active_subdomain_discovery(subdomains)
            
            # Phase 3: Directory discovery on main domain
            main_url = f"https://{self.target_domain}"
            directories = self.directory_discovery(main_url)
            
            # Phase 4: Parameter discovery
            parameters = self.parameter_discovery(main_url)
            
            # Phase 5: WAF detection
            waf_info = self.waf_detection(main_url)
            
            # Save results
            self.save_results()
            
            self.log("Reconnaissance completed successfully!", "SUCCESS")
            return self.results
            
        except Exception as e:
            self.log(f"Error during reconnaissance: {e}", "ERROR")
            return None

if __name__ == "__main__":
    # Example usage
    target = input("Enter target domain: ").strip()
    if target:
        recon = ReconnaissanceTool(target)
        results = recon.run_complete_reconnaissance()
        if results:
            print(f"\n{Fore.GREEN}Reconnaissance completed! Check {recon.output_dir} for results.{Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}Please provide a valid target domain.{Style.RESET_ALL}")