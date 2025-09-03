#!/usr/bin/env python3
"""
Advanced Web Reconnaissance Tool
A comprehensive information gathering tool for bug bounty and penetration testing

Features:
- Subdomain discovery using multiple techniques
- Parameter extraction from JavaScript and configuration files
- Sensitive file discovery
- Real IP discovery through various methods
- Cross-platform compatibility
- Comprehensive reporting

Author: AI Assistant
Version: 1.0
"""

import os
import sys
import json
import time
import hashlib
import socket
import ssl
import subprocess
import urllib.request
import urllib.parse
import urllib.error
from urllib.parse import urlparse, urljoin, parse_qs
import re
import threading
import concurrent.futures
from datetime import datetime
import argparse
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import dns.resolver
import dns.reversename
import whois
from bs4 import BeautifulSoup
import tldextract
from advanced_modules import (
    AdvancedSubdomainDiscovery, 
    AdvancedParameterExtraction,
    AdvancedIPDiscovery,
    AdvancedFileDiscovery,
    AdvancedTechnologyDetection,
    AdvancedVulnerabilityScanning,
    AdvancedNetworkAnalysis,
    AdvancedReportGenerator
)
from external_tools import ExternalToolsManager

class Colors:
    """Color codes for terminal output"""
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
    """Enhanced logging system"""
    
    def __init__(self, filename=None):
        self.filename = filename
        self.start_time = datetime.now()
        
    def log(self, message, level="INFO", color=Colors.WHITE):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        formatted_message = f"[{timestamp}] [{level}] {message}"
        
        # Print to console with colors
        print(f"{color}{formatted_message}{Colors.END}")
        
        # Write to file if specified
        if self.filename:
            with open(self.filename, 'a', encoding='utf-8') as f:
                f.write(formatted_message + '\n')
    
    def info(self, message):
        self.log(message, "INFO", Colors.CYAN)
    
    def success(self, message):
        self.log(message, "SUCCESS", Colors.GREEN)
    
    def warning(self, message):
        self.log(message, "WARNING", Colors.YELLOW)
    
    def error(self, message):
        self.log(message, "ERROR", Colors.RED)
    
    def phase(self, message):
        self.log(message, "PHASE", Colors.BOLD + Colors.PURPLE)

class WebReconTool:
    """Main reconnaissance tool class"""
    
    def __init__(self, target_domain, output_dir="recon_output"):
        self.target_domain = self.normalize_domain(target_domain)
        self.output_dir = output_dir
        self.session = self.create_session()
        self.logger = Logger(os.path.join(output_dir, "recon.log"))
        
        # Results storage
        self.results = {
            'target': self.target_domain,
            'timestamp': datetime.now().isoformat(),
            'subdomains': set(),
            'parameters': set(),
            'sensitive_files': [],
            'real_ips': set(),
            'technologies': set(),
            'endpoints': set(),
            'javascript_files': [],
            'config_files': [],
            'archives': [],
            'dns_records': {},
            'whois_info': {},
            'favicon_hash': None,
            'certificates': [],
            'security_headers': {},
            'robots_txt': None,
            'sitemap_xml': None
        }
        
        # Create output directory
        os.makedirs(output_dir, exist_ok=True)
        
        # Initialize advanced modules
        self.advanced_subdomain = AdvancedSubdomainDiscovery(self.session, self.logger, self.target_domain)
        self.advanced_params = AdvancedParameterExtraction(self.session, self.logger, self.target_domain)
        self.advanced_ip = AdvancedIPDiscovery(self.session, self.logger, self.target_domain)
        self.advanced_files = AdvancedFileDiscovery(self.session, self.logger, self.target_domain)
        self.advanced_tech = AdvancedTechnologyDetection(self.session, self.logger, self.target_domain)
        self.advanced_vuln = AdvancedVulnerabilityScanning(self.session, self.logger, self.target_domain)
        self.advanced_network = AdvancedNetworkAnalysis(self.session, self.logger, self.target_domain)
        self.advanced_report = AdvancedReportGenerator(self.logger, self.target_domain, self.output_dir)
        self.external_tools = ExternalToolsManager(self.logger)
        
        # Common sensitive files patterns
        self.sensitive_files_patterns = {
            'php': [
                'config.php', 'configuration.php', 'settings.php', 'database.php',
                'db.php', 'connect.php', 'connection.php', 'wp-config.php',
                'config.inc.php', 'config.local.php', 'config.dev.php'
            ],
            'javascript': [
                'package.json', 'package-lock.json', 'yarn.lock', 'webpack.config.js',
                'gulpfile.js', 'gruntfile.js', 'rollup.config.js', 'next.config.js',
                'nuxt.config.js', 'vue.config.js', 'angular.json'
            ],
            'python': [
                'requirements.txt', 'setup.py', 'setup.cfg', 'pyproject.toml',
                'Pipfile', 'Pipfile.lock', 'conda.yaml', 'environment.yml'
            ],
            'general': [
                '.env', '.env.local', '.env.production', '.env.development',
                '.htaccess', '.htpasswd', 'web.config', 'app.config',
                'database.yml', 'secrets.yml', 'credentials.yml',
                'docker-compose.yml', 'Dockerfile', 'Makefile',
                'README.md', 'CHANGELOG.md', 'LICENSE', 'robots.txt',
                'sitemap.xml', 'crossdomain.xml', 'clientaccesspolicy.xml',
                'backup.sql', 'dump.sql', 'database.sql'
            ]
        }
        
        # Common parameter names to search for
        self.common_parameters = [
            'id', 'user', 'username', 'email', 'password', 'pass', 'token',
            'api_key', 'apikey', 'key', 'secret', 'auth', 'session',
            'redirect', 'return', 'url', 'link', 'path', 'file', 'page',
            'search', 'query', 'q', 'keyword', 'term', 'filter', 'sort',
            'limit', 'offset', 'start', 'end', 'from', 'to', 'date',
            'callback', 'jsonp', 'format', 'type', 'action', 'cmd',
            'debug', 'test', 'dev', 'admin', 'manage', 'control'
        ]

    def normalize_domain(self, domain):
        """Normalize domain name"""
        domain = domain.strip()
        if domain.startswith('http://') or domain.startswith('https://'):
            domain = urlparse(domain).netloc
        return domain.lower()

    def create_session(self):
        """Create HTTP session with retry strategy"""
        session = requests.Session()
        retry_strategy = Retry(
            total=3,
            status_forcelist=[429, 500, 502, 503, 504],
            method_whitelist=["HEAD", "GET", "OPTIONS"]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        return session

    def banner(self):
        """Display tool banner"""
        banner_text = f"""
{Colors.BOLD}{Colors.CYAN}
╔══════════════════════════════════════════════════════════════╗
║                    Advanced Web Recon Tool                   ║
║                  Comprehensive Information Gathering         ║
║                        Bug Bounty Edition                    ║
╚══════════════════════════════════════════════════════════════╝
{Colors.END}
{Colors.YELLOW}Target Domain: {self.target_domain}{Colors.END}
{Colors.YELLOW}Output Directory: {self.output_dir}{Colors.END}
{Colors.YELLOW}Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Colors.END}
"""
        print(banner_text)

    def phase_1_subdomain_discovery(self):
        """Phase 1: Comprehensive subdomain discovery"""
        self.logger.phase("Phase 1: Subdomain Discovery")
        
        # Method 1: Certificate Transparency Logs
        self.discover_subdomains_crt()
        
        # Method 2: DNS Brute Force
        self.discover_subdomains_dns_bruteforce()
        
        # Method 3: Search Engine Dorking
        self.discover_subdomains_search_engines()
        
        # Method 4: Archive Analysis
        self.discover_subdomains_archives()
        
        # Method 5: JavaScript Analysis
        self.discover_subdomains_javascript()
        
        # Method 6: Passive DNS
        self.discover_subdomains_passive_dns()
        
        # Method 7: Advanced API-based discovery (if API keys available)
        self.discover_subdomains_advanced_apis()
        
        # Method 8: External tools integration
        self.discover_subdomains_external_tools()
        
        self.logger.success(f"Found {len(self.results['subdomains'])} unique subdomains")

    def discover_subdomains_crt(self):
        """Discover subdomains using Certificate Transparency logs"""
        self.logger.info("Searching Certificate Transparency logs...")
        
        try:
            url = f"https://crt.sh/?q=%.{self.target_domain}&output=json"
            response = self.session.get(url, timeout=30)
            
            if response.status_code == 200:
                certificates = response.json()
                for cert in certificates:
                    name_value = cert.get('name_value', '')
                    for domain in name_value.split('\n'):
                        domain = domain.strip()
                        if domain and self.target_domain in domain:
                            self.results['subdomains'].add(domain)
                            
        except Exception as e:
            self.logger.error(f"Certificate Transparency search failed: {str(e)}")

    def discover_subdomains_dns_bruteforce(self):
        """Discover subdomains using DNS brute force"""
        self.logger.info("Performing DNS brute force...")
        
        # Common subdomain wordlist
        common_subdomains = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
            'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'mx', 'test', 'staging',
            'dev', 'development', 'prod', 'production', 'admin', 'administrator', 'api',
            'blog', 'shop', 'store', 'support', 'help', 'docs', 'documentation', 'wiki',
            'forum', 'community', 'news', 'media', 'static', 'assets', 'cdn', 'img',
            'images', 'js', 'css', 'files', 'download', 'downloads', 'upload', 'uploads',
            'backup', 'backups', 'old', 'new', 'demo', 'beta', 'alpha', 'preview',
            'mobile', 'm', 'wap', 'app', 'apps', 'secure', 'security', 'vpn', 'ssl',
            'git', 'svn', 'repo', 'repository', 'code', 'gitlab', 'github', 'bitbucket',
            'jenkins', 'ci', 'build', 'deploy', 'deployment', 'docker', 'k8s', 'kubernetes'
        ]
        
        def check_subdomain(subdomain):
            try:
                full_domain = f"{subdomain}.{self.target_domain}"
                socket.gethostbyname(full_domain)
                self.results['subdomains'].add(full_domain)
                return full_domain
            except socket.gaierror:
                return None
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            futures = [executor.submit(check_subdomain, sub) for sub in common_subdomains]
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    self.logger.info(f"Found subdomain: {result}")

    def discover_subdomains_search_engines(self):
        """Discover subdomains using search engine dorking"""
        self.logger.info("Searching via search engines...")
        
        # Google dorking for subdomains
        search_queries = [
            f"site:{self.target_domain}",
            f"site:*.{self.target_domain}",
            f"inurl:{self.target_domain}",
            f"intitle:{self.target_domain}"
        ]
        
        for query in search_queries:
            try:
                # Note: In a real implementation, you would use proper search APIs
                # This is a simplified version for demonstration
                self.logger.info(f"Searching: {query}")
                time.sleep(1)  # Rate limiting
            except Exception as e:
                self.logger.error(f"Search engine query failed: {str(e)}")

    def discover_subdomains_archives(self):
        """Discover subdomains from web archives"""
        self.logger.info("Searching web archives...")
        
        try:
            # Wayback Machine API
            url = f"http://web.archive.org/cdx/search/cdx?url=*.{self.target_domain}&output=json&fl=original&collapse=urlkey"
            response = self.session.get(url, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                for entry in data[1:]:  # Skip header
                    if entry and len(entry) > 0:
                        archived_url = entry[0]
                        try:
                            parsed = urlparse(archived_url)
                            if parsed.netloc and self.target_domain in parsed.netloc:
                                self.results['subdomains'].add(parsed.netloc)
                                self.results['archives'].append(archived_url)
                        except:
                            continue
                            
        except Exception as e:
            self.logger.error(f"Archive search failed: {str(e)}")

    def discover_subdomains_javascript(self):
        """Discover subdomains by analyzing JavaScript files"""
        self.logger.info("Analyzing JavaScript files for subdomains...")
        
        try:
            # First, find JavaScript files
            js_files = self.find_javascript_files()
            
            # Regex patterns for subdomain discovery
            subdomain_patterns = [
                rf'["\']https?://([a-zA-Z0-9\-\.]*\.{re.escape(self.target_domain)})["\']',
                rf'["\']//([a-zA-Z0-9\-\.]*\.{re.escape(self.target_domain)})["\']',
                rf'["\']([a-zA-Z0-9\-\.]*\.{re.escape(self.target_domain)})["\']'
            ]
            
            for js_file in js_files:
                try:
                    response = self.session.get(js_file, timeout=15)
                    if response.status_code == 200:
                        content = response.text
                        
                        for pattern in subdomain_patterns:
                            matches = re.findall(pattern, content, re.IGNORECASE)
                            for match in matches:
                                if match and self.target_domain in match:
                                    self.results['subdomains'].add(match)
                                    
                except Exception as e:
                    self.logger.error(f"Failed to analyze JS file {js_file}: {str(e)}")
                    
        except Exception as e:
            self.logger.error(f"JavaScript analysis failed: {str(e)}")

    def find_javascript_files(self):
        """Find JavaScript files from the target domain"""
        js_files = []
        
        try:
            # Try to get the main page
            main_url = f"https://{self.target_domain}"
            response = self.session.get(main_url, timeout=15)
            
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Find script tags
                script_tags = soup.find_all('script', src=True)
                for script in script_tags:
                    src = script.get('src')
                    if src:
                        if src.startswith('//'):
                            src = 'https:' + src
                        elif src.startswith('/'):
                            src = main_url + src
                        elif not src.startswith('http'):
                            src = urljoin(main_url, src)
                        
                        if src.endswith('.js'):
                            js_files.append(src)
                            self.results['javascript_files'].append(src)
                            
        except Exception as e:
            self.logger.error(f"Failed to find JavaScript files: {str(e)}")
            
        return js_files

    def discover_subdomains_passive_dns(self):
        """Discover subdomains using passive DNS"""
        self.logger.info("Querying passive DNS sources...")
        
        try:
            # Try to resolve DNS records
            for record_type in ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT']:
                try:
                    answers = dns.resolver.resolve(self.target_domain, record_type)
                    self.results['dns_records'][record_type] = []
                    for answer in answers:
                        self.results['dns_records'][record_type].append(str(answer))
                except:
                    continue
                    
        except Exception as e:
            self.logger.error(f"Passive DNS query failed: {str(e)}")

    def discover_subdomains_advanced_apis(self):
        """Discover subdomains using advanced API sources"""
        self.logger.info("Using advanced API sources for subdomain discovery...")
        
        # Note: API keys would be provided via environment variables or config
        shodan_key = os.getenv('SHODAN_API_KEY')
        vt_key = os.getenv('VIRUSTOTAL_API_KEY')
        st_key = os.getenv('SECURITYTRAILS_API_KEY')
        
        if shodan_key:
            shodan_subs = self.advanced_subdomain.discover_via_shodan(shodan_key)
            self.results['subdomains'].update(shodan_subs)
            self.logger.info(f"Shodan found {len(shodan_subs)} subdomains")
        
        if vt_key:
            vt_subs = self.advanced_subdomain.discover_via_virustotal(vt_key)
            self.results['subdomains'].update(vt_subs)
            self.logger.info(f"VirusTotal found {len(vt_subs)} subdomains")
        
        if st_key:
            st_subs = self.advanced_subdomain.discover_via_security_trails(st_key)
            self.results['subdomains'].update(st_subs)
            self.logger.info(f"SecurityTrails found {len(st_subs)} subdomains")

    def discover_subdomains_external_tools(self):
        """Discover subdomains using external tools"""
        self.logger.info("Using external tools for subdomain discovery...")
        
        # Run external tools if available
        external_results = self.external_tools.run_all_external_tools(self.target_domain)
        
        # Merge results
        self.results['subdomains'].update(external_results['subdomains'])
        
        # Store additional data
        if external_results['alive_hosts']:
            self.results['alive_hosts'] = external_results['alive_hosts']
        
        if external_results['vulnerabilities']:
            if 'vulnerabilities' not in self.results:
                self.results['vulnerabilities'] = []
            self.results['vulnerabilities'].extend(external_results['vulnerabilities'])
        
        if external_results['port_scans']:
            self.results['port_scans'] = external_results['port_scans']

    def phase_2_parameter_extraction(self):
        """Phase 2: Extract parameters from various sources"""
        self.logger.phase("Phase 2: Parameter Extraction")
        
        # Method 1: Analyze JavaScript files for parameters
        self.extract_parameters_javascript()
        
        # Method 2: Analyze HTML forms
        self.extract_parameters_forms()
        
        # Method 3: Analyze URL patterns
        self.extract_parameters_urls()
        
        # Method 4: Analyze configuration files
        self.extract_parameters_config()
        
        # Method 5: Extract from Swagger/OpenAPI documentation
        swagger_params = self.advanced_params.extract_from_swagger_docs()
        self.results['parameters'].update(swagger_params)
        
        # Method 6: Extract from GraphQL introspection
        graphql_params = self.advanced_params.extract_from_graphql_introspection()
        self.results['parameters'].update(graphql_params)
        
        self.logger.success(f"Found {len(self.results['parameters'])} unique parameters")

    def extract_parameters_javascript(self):
        """Extract parameters from JavaScript files"""
        self.logger.info("Extracting parameters from JavaScript files...")
        
        # Parameter patterns in JavaScript
        param_patterns = [
            r'["\']([a-zA-Z_][a-zA-Z0-9_]*)["\']:\s*["\']?[^,}\]]+',
            r'\.([a-zA-Z_][a-zA-Z0-9_]*)\s*=',
            r'params\.([a-zA-Z_][a-zA-Z0-9_]*)',
            r'data\.([a-zA-Z_][a-zA-Z0-9_]*)',
            r'[?&]([a-zA-Z_][a-zA-Z0-9_]*)=',
            r'FormData\(\)\.append\(["\']([^"\']+)["\']',
            r'getElementById\(["\']([^"\']+)["\']'
        ]
        
        for js_file in self.results['javascript_files']:
            try:
                response = self.session.get(js_file, timeout=15)
                if response.status_code == 200:
                    content = response.text
                    
                    for pattern in param_patterns:
                        matches = re.findall(pattern, content, re.IGNORECASE)
                        for match in matches:
                            if isinstance(match, tuple):
                                match = match[0]
                            if match and len(match) > 1 and match.isalnum():
                                self.results['parameters'].add(match)
                                
            except Exception as e:
                self.logger.error(f"Failed to extract parameters from {js_file}: {str(e)}")

    def extract_parameters_forms(self):
        """Extract parameters from HTML forms"""
        self.logger.info("Extracting parameters from HTML forms...")
        
        try:
            main_url = f"https://{self.target_domain}"
            response = self.session.get(main_url, timeout=15)
            
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Find all form inputs
                inputs = soup.find_all(['input', 'select', 'textarea'])
                for input_tag in inputs:
                    name = input_tag.get('name')
                    if name:
                        self.results['parameters'].add(name)
                        
        except Exception as e:
            self.logger.error(f"Failed to extract form parameters: {str(e)}")

    def extract_parameters_urls(self):
        """Extract parameters from URL patterns"""
        self.logger.info("Extracting parameters from URLs...")
        
        try:
            # Analyze archived URLs for parameter patterns
            for archived_url in self.results['archives']:
                parsed = urlparse(archived_url)
                if parsed.query:
                    params = parse_qs(parsed.query)
                    for param_name in params.keys():
                        self.results['parameters'].add(param_name)
                        
        except Exception as e:
            self.logger.error(f"Failed to extract URL parameters: {str(e)}")

    def extract_parameters_config(self):
        """Extract parameters from configuration files"""
        self.logger.info("Extracting parameters from configuration files...")
        
        # Check common config files for parameters
        config_files = [
            'config.js', 'config.json', 'settings.json', 'app.config',
            'web.config', '.env.example', 'config.yml', 'config.yaml'
        ]
        
        for config_file in config_files:
            try:
                url = f"https://{self.target_domain}/{config_file}"
                response = self.session.get(url, timeout=10)
                
                if response.status_code == 200:
                    content = response.text
                    self.results['config_files'].append(url)
                    
                    # Extract parameters from JSON config
                    if config_file.endswith('.json'):
                        try:
                            json_data = json.loads(content)
                            self.extract_params_from_json(json_data)
                        except:
                            pass
                    
                    # Extract parameters from YAML config
                    elif config_file.endswith(('.yml', '.yaml')):
                        param_pattern = r'^([a-zA-Z_][a-zA-Z0-9_]*)\s*:'
                        matches = re.findall(param_pattern, content, re.MULTILINE)
                        for match in matches:
                            self.results['parameters'].add(match)
                    
                    # Extract parameters from ENV files
                    elif '.env' in config_file:
                        env_pattern = r'^([A-Z_][A-Z0-9_]*)\s*='
                        matches = re.findall(env_pattern, content, re.MULTILINE)
                        for match in matches:
                            self.results['parameters'].add(match)
                    
                    # General parameter extraction
                    general_patterns = [
                        r'["\']([a-zA-Z_][a-zA-Z0-9_]*)["\']:\s*["\']',
                        r'name=["\']([a-zA-Z_][a-zA-Z0-9_]*)["\']',
                        r'id=["\']([a-zA-Z_][a-zA-Z0-9_]*)["\']'
                    ]
                    
                    for pattern in general_patterns:
                        matches = re.findall(pattern, content)
                        for match in matches:
                            if len(match) > 1:
                                self.results['parameters'].add(match)
                                
            except Exception as e:
                continue

    def extract_params_from_json(self, json_data, prefix=""):
        """Recursively extract parameters from JSON data"""
        if isinstance(json_data, dict):
            for key, value in json_data.items():
                param_name = f"{prefix}.{key}" if prefix else key
                self.results['parameters'].add(param_name)
                
                if isinstance(value, (dict, list)):
                    self.extract_params_from_json(value, param_name)
        elif isinstance(json_data, list):
            for i, item in enumerate(json_data):
                if isinstance(item, (dict, list)):
                    self.extract_params_from_json(item, f"{prefix}[{i}]" if prefix else f"[{i}]")

    def phase_3_sensitive_file_discovery(self):
        """Phase 3: Discover sensitive files"""
        self.logger.phase("Phase 3: Sensitive File Discovery")
        
        # Method 1: Technology-based file discovery
        self.discover_sensitive_files_by_technology()
        
        # Method 2: Common sensitive files
        self.discover_common_sensitive_files()
        
        # Method 3: Backup and temporary files
        self.discover_backup_files()
        
        # Method 4: Version control files
        self.discover_version_control_files()
        
        # Method 5: Advanced Git file discovery
        git_files = self.advanced_files.discover_git_exposed_files()
        self.results['sensitive_files'].extend(git_files)
        
        # Method 6: Docker configuration files
        docker_files = self.advanced_files.discover_docker_files()
        self.results['sensitive_files'].extend(docker_files)
        
        # Method 7: Cloud configuration files
        cloud_files = self.advanced_files.discover_cloud_config_files()
        self.results['sensitive_files'].extend(cloud_files)
        
        self.logger.success(f"Found {len(self.results['sensitive_files'])} sensitive files")

    def discover_sensitive_files_by_technology(self):
        """Discover sensitive files based on detected technologies"""
        self.logger.info("Discovering technology-specific sensitive files...")
        
        # Detect technologies first
        self.detect_technologies()
        
        # Check files based on detected technologies
        for tech in self.results['technologies']:
            tech_lower = tech.lower()
            
            if 'php' in tech_lower:
                self.check_files(self.sensitive_files_patterns['php'])
            elif any(js_tech in tech_lower for js_tech in ['javascript', 'node', 'react', 'vue', 'angular']):
                self.check_files(self.sensitive_files_patterns['javascript'])
            elif any(py_tech in tech_lower for py_tech in ['python', 'django', 'flask']):
                self.check_files(self.sensitive_files_patterns['python'])
        
        # Always check general files
        self.check_files(self.sensitive_files_patterns['general'])

    def detect_technologies(self):
        """Detect technologies used by the target"""
        self.logger.info("Detecting technologies...")
        
        try:
            main_url = f"https://{self.target_domain}"
            response = self.session.get(main_url, timeout=15)
            
            if response.status_code == 200:
                # Check headers
                headers = response.headers
                
                # Server header
                server = headers.get('Server', '')
                if server:
                    self.results['technologies'].add(server)
                
                # X-Powered-By header
                powered_by = headers.get('X-Powered-By', '')
                if powered_by:
                    self.results['technologies'].add(powered_by)
                
                # Content analysis
                content = response.text.lower()
                
                # Technology signatures
                tech_signatures = {
                    'WordPress': ['wp-content', 'wp-includes', 'wordpress'],
                    'Drupal': ['drupal', '/sites/default/files'],
                    'Joomla': ['joomla', '/components/', '/modules/'],
                    'PHP': ['<?php', '.php'],
                    'ASP.NET': ['asp.net', '__viewstate', '__dopostback'],
                    'React': ['react', 'reactjs'],
                    'Vue.js': ['vue.js', 'vuejs'],
                    'Angular': ['angular', 'ng-'],
                    'jQuery': ['jquery'],
                    'Bootstrap': ['bootstrap']
                }
                
                for tech, signatures in tech_signatures.items():
                    if any(sig in content for sig in signatures):
                        self.results['technologies'].add(tech)
                        
        except Exception as e:
            self.logger.error(f"Technology detection failed: {str(e)}")

    def check_files(self, file_list):
        """Check if files exist on the target"""
        
        def check_single_file(filename):
            try:
                url = f"https://{self.target_domain}/{filename}"
                response = self.session.head(url, timeout=10)
                
                if response.status_code == 200:
                    self.results['sensitive_files'].append({
                        'file': filename,
                        'url': url,
                        'status_code': response.status_code,
                        'content_type': response.headers.get('Content-Type', 'Unknown')
                    })
                    self.logger.success(f"Found sensitive file: {url}")
                    
            except Exception as e:
                pass  # File doesn't exist or error occurred
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(check_single_file, filename) for filename in file_list]
            concurrent.futures.wait(futures)

    def discover_common_sensitive_files(self):
        """Discover common sensitive files"""
        self.logger.info("Checking common sensitive files...")
        
        # Check robots.txt
        self.check_robots_txt()
        
        # Check sitemap.xml
        self.check_sitemap_xml()

    def check_robots_txt(self):
        """Check and analyze robots.txt"""
        try:
            url = f"https://{self.target_domain}/robots.txt"
            response = self.session.get(url, timeout=10)
            
            if response.status_code == 200:
                self.results['robots_txt'] = response.text
                self.logger.success("Found robots.txt")
                
                # Extract disallowed paths
                for line in response.text.split('\n'):
                    if line.strip().lower().startswith('disallow:'):
                        path = line.split(':', 1)[1].strip()
                        if path and path != '/':
                            self.results['endpoints'].add(path)
                            
        except Exception as e:
            self.logger.error(f"Failed to check robots.txt: {str(e)}")

    def check_sitemap_xml(self):
        """Check and analyze sitemap.xml"""
        try:
            url = f"https://{self.target_domain}/sitemap.xml"
            response = self.session.get(url, timeout=10)
            
            if response.status_code == 200:
                self.results['sitemap_xml'] = response.text
                self.logger.success("Found sitemap.xml")
                
                # Parse sitemap for URLs
                soup = BeautifulSoup(response.text, 'xml')
                urls = soup.find_all('loc')
                for url_tag in urls:
                    if url_tag.text:
                        parsed = urlparse(url_tag.text)
                        self.results['endpoints'].add(parsed.path)
                        
        except Exception as e:
            self.logger.error(f"Failed to check sitemap.xml: {str(e)}")

    def discover_backup_files(self):
        """Discover backup and temporary files"""
        self.logger.info("Searching for backup files...")
        
        backup_extensions = ['.bak', '.backup', '.old', '.orig', '.tmp', '.temp', '~', '.save']
        common_files = ['index', 'config', 'database', 'admin', 'login', 'user']
        
        backup_files = []
        for file in common_files:
            for ext in backup_extensions:
                backup_files.extend([
                    f"{file}{ext}",
                    f"{file}.php{ext}",
                    f"{file}.html{ext}",
                    f"{file}.js{ext}",
                    f"{file}.sql{ext}"
                ])
        
        self.check_files(backup_files)

    def discover_version_control_files(self):
        """Discover version control files"""
        self.logger.info("Searching for version control files...")
        
        vc_files = [
            '.git/config', '.git/HEAD', '.git/logs/HEAD',
            '.svn/entries', '.svn/wc.db',
            '.hg/hgrc', '.bzr/branch-format',
            'CVS/Root', 'CVS/Entries'
        ]
        
        self.check_files(vc_files)

    def phase_4_real_ip_discovery(self):
        """Phase 4: Discover real IP addresses"""
        self.logger.phase("Phase 4: Real IP Discovery")
        
        # Method 1: Favicon hash analysis
        self.discover_ip_favicon()
        
        # Method 2: DNS history analysis
        self.discover_ip_dns_history()
        
        # Method 3: Certificate analysis
        self.discover_ip_certificates()
        
        # Method 4: Direct DNS resolution
        self.discover_ip_direct_dns()
        
        # Method 5: Advanced Shodan/Censys search
        if os.getenv('SHODAN_API_KEY'):
            shodan_ips = self.advanced_ip.discover_via_favicon_shodan(self.results.get('favicon_hash'))
            self.results['real_ips'].update(shodan_ips)
        
        # Method 6: DNS history analysis
        history_ips = self.advanced_ip.discover_via_dns_history()
        self.results['real_ips'].update(history_ips)
        
        # Method 7: Certificate transparency IP discovery
        ct_ips = self.advanced_ip.discover_via_ssl_certificate_transparency()
        self.results['real_ips'].update(ct_ips)
        
        self.logger.success(f"Found {len(self.results['real_ips'])} potential real IP addresses")

    def discover_ip_favicon(self):
        """Discover real IP using favicon hash analysis"""
        self.logger.info("Analyzing favicon for IP discovery...")
        
        try:
            favicon_url = f"https://{self.target_domain}/favicon.ico"
            response = self.session.get(favicon_url, timeout=10)
            
            if response.status_code == 200:
                favicon_hash = hashlib.md5(response.content).hexdigest()
                self.results['favicon_hash'] = favicon_hash
                self.logger.info(f"Favicon hash: {favicon_hash}")
                
                # In a real implementation, you would query Shodan or similar services
                # with this hash to find servers with the same favicon
                
        except Exception as e:
            self.logger.error(f"Favicon analysis failed: {str(e)}")

    def discover_ip_dns_history(self):
        """Discover IPs through DNS history"""
        self.logger.info("Analyzing DNS history...")
        
        try:
            # Get current IP
            ip = socket.gethostbyname(self.target_domain)
            self.results['real_ips'].add(ip)
            self.logger.info(f"Current IP: {ip}")
            
        except Exception as e:
            self.logger.error(f"DNS resolution failed: {str(e)}")

    def discover_ip_certificates(self):
        """Discover IPs through certificate analysis"""
        self.logger.info("Analyzing SSL certificates...")
        
        try:
            # Get SSL certificate
            context = ssl.create_default_context()
            with socket.create_connection((self.target_domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=self.target_domain) as ssock:
                    cert = ssock.getpeercert()
                    self.results['certificates'].append(cert)
                    
                    # Extract Subject Alternative Names
                    san_list = []
                    if 'subjectAltName' in cert:
                        for san_type, san_value in cert['subjectAltName']:
                            if san_type == 'DNS':
                                san_list.append(san_value)
                                if self.target_domain in san_value:
                                    self.results['subdomains'].add(san_value)
                    
                    self.logger.info(f"Certificate SAN entries: {len(san_list)}")
                    
        except Exception as e:
            self.logger.error(f"Certificate analysis failed: {str(e)}")

    def discover_ip_direct_dns(self):
        """Direct DNS resolution for all discovered subdomains"""
        self.logger.info("Resolving IPs for discovered subdomains...")
        
        def resolve_subdomain(subdomain):
            try:
                ip = socket.gethostbyname(subdomain)
                self.results['real_ips'].add(ip)
                return f"{subdomain} -> {ip}"
            except:
                return None
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(resolve_subdomain, sub) for sub in self.results['subdomains']]
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    self.logger.info(result)

    def phase_5_additional_reconnaissance(self):
        """Phase 5: Additional reconnaissance techniques"""
        self.logger.phase("Phase 5: Additional Reconnaissance")
        
        # Method 1: WHOIS information
        self.gather_whois_info()
        
        # Method 2: Security headers analysis
        self.analyze_security_headers()
        
        # Method 3: Directory enumeration
        self.enumerate_directories()
        
        # Method 4: Technology fingerprinting
        self.advanced_technology_fingerprinting()
        
        # Method 5: Advanced technology detection
        advanced_techs = self.advanced_tech.detect_cms_and_frameworks()
        self.results['technologies'].update(advanced_techs)
        
        # Method 6: WAF and security solution detection
        security_solutions = self.advanced_tech.detect_waf_and_security_solutions()
        self.results['technologies'].update(security_solutions)
        
        # Method 7: SSL/TLS analysis
        ssl_info = self.advanced_network.analyze_ssl_configuration()
        if ssl_info:
            self.results['ssl_analysis'] = ssl_info
        
        # Method 8: HTTP methods analysis
        methods_info = self.advanced_network.analyze_http_methods()
        self.results['http_methods'] = methods_info
        
        # Method 9: CORS configuration check
        cors_info = self.advanced_network.check_cors_configuration()
        if cors_info:
            self.results['cors_analysis'] = cors_info

    def gather_whois_info(self):
        """Gather WHOIS information"""
        self.logger.info("Gathering WHOIS information...")
        
        try:
            w = whois.whois(self.target_domain)
            self.results['whois_info'] = {
                'registrar': str(w.registrar) if w.registrar else None,
                'creation_date': str(w.creation_date) if w.creation_date else None,
                'expiration_date': str(w.expiration_date) if w.expiration_date else None,
                'name_servers': [str(ns) for ns in w.name_servers] if w.name_servers else [],
                'status': str(w.status) if w.status else None
            }
            self.logger.success("WHOIS information gathered")
            
        except Exception as e:
            self.logger.error(f"WHOIS lookup failed: {str(e)}")

    def analyze_security_headers(self):
        """Analyze security headers"""
        self.logger.info("Analyzing security headers...")
        
        try:
            main_url = f"https://{self.target_domain}"
            response = self.session.get(main_url, timeout=15)
            
            security_headers = [
                'Strict-Transport-Security', 'Content-Security-Policy', 'X-Frame-Options',
                'X-XSS-Protection', 'X-Content-Type-Options', 'Referrer-Policy',
                'Feature-Policy', 'Permissions-Policy'
            ]
            
            for header in security_headers:
                value = response.headers.get(header)
                self.results['security_headers'][header] = value
                
            self.logger.success("Security headers analyzed")
            
        except Exception as e:
            self.logger.error(f"Security header analysis failed: {str(e)}")

    def enumerate_directories(self):
        """Enumerate common directories"""
        self.logger.info("Enumerating directories...")
        
        common_dirs = [
            'admin', 'administrator', 'login', 'dashboard', 'panel', 'control',
            'api', 'v1', 'v2', 'docs', 'documentation', 'help', 'support',
            'uploads', 'files', 'assets', 'static', 'public', 'private',
            'backup', 'backups', 'old', 'test', 'testing', 'dev', 'development',
            'staging', 'prod', 'production', 'config', 'configuration',
            'database', 'db', 'sql', 'phpmyadmin', 'mysql', 'postgresql'
        ]
        
        def check_directory(directory):
            try:
                url = f"https://{self.target_domain}/{directory}/"
                response = self.session.head(url, timeout=5)
                
                if response.status_code in [200, 301, 302, 403]:
                    self.results['endpoints'].add(f"/{directory}/")
                    return f"/{directory}/ -> {response.status_code}"
            except:
                pass
            return None
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(check_directory, dir_name) for dir_name in common_dirs]
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    self.logger.info(f"Found directory: {result}")

    def advanced_technology_fingerprinting(self):
        """Advanced technology fingerprinting"""
        self.logger.info("Performing advanced technology fingerprinting...")
        
        try:
            main_url = f"https://{self.target_domain}"
            response = self.session.get(main_url, timeout=15)
            
            if response.status_code == 200:
                content = response.text
                
                # Framework detection patterns
                framework_patterns = {
                    'Laravel': [r'laravel_token', r'Laravel Framework'],
                    'CodeIgniter': [r'codeigniter', r'CI_Controller'],
                    'Symfony': [r'symfony', r'Symfony\\'],
                    'Django': [r'django', r'csrftoken'],
                    'Flask': [r'flask', r'werkzeug'],
                    'Express.js': [r'express', r'X-Powered-By.*Express'],
                    'Spring Boot': [r'spring', r'Whitelabel Error Page'],
                    'ASP.NET Core': [r'asp\.net core', r'__RequestVerificationToken']
                }
                
                for framework, patterns in framework_patterns.items():
                    if any(re.search(pattern, content, re.IGNORECASE) for pattern in patterns):
                        self.results['technologies'].add(framework)
                        
        except Exception as e:
            self.logger.error(f"Advanced fingerprinting failed: {str(e)}")

    def phase_6_vulnerability_assessment(self):
        """Phase 6: Basic vulnerability assessment"""
        self.logger.phase("Phase 6: Vulnerability Assessment")
        
        # Method 1: Scan for common vulnerabilities
        common_vulns = self.advanced_vuln.scan_for_common_vulnerabilities()
        self.results['vulnerabilities'] = common_vulns
        
        # Method 2: Directory traversal testing
        traversal_vulns = self.advanced_vuln.scan_for_directory_traversal()
        self.results['vulnerabilities'].extend(traversal_vulns)
        
        self.logger.success(f"Vulnerability assessment completed - {len(self.results.get('vulnerabilities', []))} potential issues found")

    def generate_report(self):
        """Generate comprehensive report"""
        self.logger.phase("Generating Comprehensive Report")
        
        # Convert sets to lists for JSON serialization
        report_data = {}
        for key, value in self.results.items():
            if isinstance(value, set):
                report_data[key] = sorted(list(value))
            else:
                report_data[key] = value
        
        # Generate JSON report
        json_report_path = os.path.join(self.output_dir, f"{self.target_domain}_recon_report.json")
        with open(json_report_path, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)
        
        # Generate HTML report
        html_report_path = os.path.join(self.output_dir, f"{self.target_domain}_recon_report.html")
        self.generate_html_report(html_report_path, report_data)
        
        # Generate text summary
        txt_report_path = os.path.join(self.output_dir, f"{self.target_domain}_summary.txt")
        self.generate_text_summary(txt_report_path, report_data)
        
        # Generate additional reports using advanced modules
        nuclei_path = self.advanced_report.generate_nuclei_compatible_report(report_data)
        csv_path = self.advanced_report.generate_csv_report(report_data)
        md_path = self.advanced_report.generate_markdown_report(report_data)
        
        self.logger.success(f"Reports generated:")
        self.logger.success(f"  JSON: {json_report_path}")
        self.logger.success(f"  HTML: {html_report_path}")
        self.logger.success(f"  Summary: {txt_report_path}")
        self.logger.success(f"  Nuclei Template: {nuclei_path}")
        self.logger.success(f"  CSV: {csv_path}")
        self.logger.success(f"  Markdown: {md_path}")

    def generate_html_report(self, filepath, data):
        """Generate HTML report"""
        
        html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reconnaissance Report - {data['target']}</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 40px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 0 20px rgba(0,0,0,0.1); }}
        h1 {{ color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }}
        h2 {{ color: #34495e; margin-top: 30px; }}
        .info-box {{ background: #ecf0f1; padding: 15px; border-radius: 5px; margin: 10px 0; }}
        .success {{ color: #27ae60; }}
        .warning {{ color: #f39c12; }}
        .error {{ color: #e74c3c; }}
        .code {{ font-family: 'Courier New', monospace; background: #2c3e50; color: #ecf0f1; padding: 10px; border-radius: 5px; }}
        ul {{ list-style-type: none; padding: 0; }}
        li {{ background: #f8f9fa; margin: 5px 0; padding: 10px; border-radius: 3px; border-left: 4px solid #3498db; }}
        .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }}
        .stat-card {{ background: #3498db; color: white; padding: 20px; border-radius: 5px; text-align: center; }}
        .stat-number {{ font-size: 2em; font-weight: bold; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 Advanced Reconnaissance Report</h1>
        
        <div class="info-box">
            <h3>Target Information</h3>
            <p><strong>Domain:</strong> {data['target']}</p>
            <p><strong>Scan Date:</strong> {data['timestamp']}</p>
        </div>
        
        <div class="stats">
            <div class="stat-card">
                <div class="stat-number">{len(data.get('subdomains', []))}</div>
                <div>Subdomains</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{len(data.get('parameters', []))}</div>
                <div>Parameters</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{len(data.get('sensitive_files', []))}</div>
                <div>Sensitive Files</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{len(data.get('real_ips', []))}</div>
                <div>IP Addresses</div>
            </div>
        </div>
        
        <h2>🌐 Discovered Subdomains</h2>
        <ul>
"""
        
        for subdomain in data.get('subdomains', []):
            html_content += f"            <li>{subdomain}</li>\n"
        
        html_content += f"""
        </ul>
        
        <h2>⚙️ Extracted Parameters</h2>
        <ul>
"""
        
        for param in data.get('parameters', []):
            html_content += f"            <li>{param}</li>\n"
        
        html_content += f"""
        </ul>
        
        <h2>🔒 Sensitive Files</h2>
        <ul>
"""
        
        for file_info in data.get('sensitive_files', []):
            if isinstance(file_info, dict):
                html_content += f"            <li><strong>{file_info['file']}</strong> - Status: {file_info['status_code']} - <a href='{file_info['url']}' target='_blank'>{file_info['url']}</a></li>\n"
            else:
                html_content += f"            <li>{file_info}</li>\n"
        
        html_content += f"""
        </ul>
        
        <h2>🌍 IP Addresses</h2>
        <ul>
"""
        
        for ip in data.get('real_ips', []):
            html_content += f"            <li>{ip}</li>\n"
        
        html_content += f"""
        </ul>
        
        <h2>🛠️ Technologies Detected</h2>
        <ul>
"""
        
        for tech in data.get('technologies', []):
            html_content += f"            <li>{tech}</li>\n"
        
        html_content += """
        </ul>
        
        <h2>📊 Additional Information</h2>
        
        <h3>Security Headers</h3>
        <div class="code">
"""
        
        for header, value in data.get('security_headers', {}).items():
            status = "✅" if value else "❌"
            html_content += f"{status} {header}: {value or 'Not Set'}<br>\n"
        
        html_content += """
        </div>
        
        <h3>DNS Records</h3>
        <div class="code">
"""
        
        for record_type, records in data.get('dns_records', {}).items():
            html_content += f"{record_type}: {', '.join(records) if records else 'None'}<br>\n"
        
        html_content += f"""
        </div>
        
        <div class="info-box">
            <p><strong>Favicon Hash:</strong> {data.get('favicon_hash', 'Not Found')}</p>
        </div>
        
    </div>
</body>
</html>
"""
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html_content)

    def generate_text_summary(self, filepath, data):
        """Generate text summary report"""
        
        summary = f"""
ADVANCED RECONNAISSANCE REPORT
==============================

Target: {data['target']}
Scan Date: {data['timestamp']}

SUMMARY STATISTICS:
- Subdomains Found: {len(data.get('subdomains', []))}
- Parameters Extracted: {len(data.get('parameters', []))}
- Sensitive Files: {len(data.get('sensitive_files', []))}
- IP Addresses: {len(data.get('real_ips', []))}
- Technologies: {len(data.get('technologies', []))}

DISCOVERED SUBDOMAINS:
{chr(10).join(f"- {sub}" for sub in data.get('subdomains', []))}

EXTRACTED PARAMETERS:
{chr(10).join(f"- {param}" for param in data.get('parameters', []))}

SENSITIVE FILES FOUND:
"""
        
        for file_info in data.get('sensitive_files', []):
            if isinstance(file_info, dict):
                summary += f"- {file_info['file']} (Status: {file_info['status_code']}) - {file_info['url']}\n"
            else:
                summary += f"- {file_info}\n"
        
        summary += f"""
IP ADDRESSES:
{chr(10).join(f"- {ip}" for ip in data.get('real_ips', []))}

TECHNOLOGIES DETECTED:
{chr(10).join(f"- {tech}" for tech in data.get('technologies', []))}

FAVICON HASH: {data.get('favicon_hash', 'Not Found')}

SECURITY HEADERS:
"""
        
        for header, value in data.get('security_headers', {}).items():
            status = "Present" if value else "Missing"
            summary += f"- {header}: {status}\n"
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(summary)

    def run_comprehensive_scan(self):
        """Run comprehensive reconnaissance scan"""
        
        self.banner()
        
        try:
            # Phase 1: Subdomain Discovery
            self.phase_1_subdomain_discovery()
            
            # Phase 2: Parameter Extraction
            self.phase_2_parameter_extraction()
            
            # Phase 3: Sensitive File Discovery
            self.phase_3_sensitive_file_discovery()
            
            # Phase 4: Real IP Discovery
            self.phase_4_real_ip_discovery()
            
            # Phase 5: Additional Reconnaissance
            self.phase_5_additional_reconnaissance()
            
            # Phase 6: Vulnerability Assessment
            self.phase_6_vulnerability_assessment()
            
            # Generate comprehensive report
            self.generate_report()
            
            # Final summary
            elapsed_time = datetime.now() - self.logger.start_time
            self.logger.success(f"Reconnaissance completed in {elapsed_time}")
            self.logger.success(f"Results saved to: {self.output_dir}")
            
        except KeyboardInterrupt:
            self.logger.warning("Scan interrupted by user")
        except Exception as e:
            self.logger.error(f"Scan failed: {str(e)}")

def main():
    """Main function"""
    
    parser = argparse.ArgumentParser(
        description="Advanced Web Reconnaissance Tool - Comprehensive Information Gathering",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python advanced_recon_tool.py -t example.com
  python advanced_recon_tool.py -t https://example.com -o custom_output
  python advanced_recon_tool.py -t example.com --threads 100
        """
    )
    
    parser.add_argument('-t', '--target', required=True, 
                       help='Target domain (e.g., example.com or https://example.com)')
    parser.add_argument('-o', '--output', default='recon_output',
                       help='Output directory (default: recon_output)')
    parser.add_argument('--threads', type=int, default=50,
                       help='Number of threads for concurrent operations (default: 50)')
    parser.add_argument('--timeout', type=int, default=15,
                       help='Request timeout in seconds (default: 15)')
    parser.add_argument('--verbose', action='store_true',
                       help='Enable verbose output')
    
    args = parser.parse_args()
    
    if not args.target:
        print(f"{Colors.RED}Error: Target domain is required{Colors.END}")
        parser.print_help()
        sys.exit(1)
    
    # Create reconnaissance tool instance
    recon_tool = WebReconTool(args.target, args.output)
    
    # Run comprehensive scan
    recon_tool.run_comprehensive_scan()

if __name__ == "__main__":
    main()