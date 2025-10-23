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

# Import API configuration
try:
    from config import API_KEYS, API_ENDPOINTS, API_CONFIG, is_api_configured, get_api_key
except ImportError:
    print("⚠️  Warning: config.py not found. Premium APIs will be disabled.")
    API_KEYS = {}
    API_ENDPOINTS = {}
    API_CONFIG = {'RATE_LIMITS': {}, 'TIMEOUTS': {'DEFAULT': 10}}
    is_api_configured = lambda x: False
    get_api_key = lambda x: ''

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
    def __init__(self, domain, output_file=None, threads=100, timeout=15, verbose=True, 
                 httpx_check=True, passive_only=False, active_only=False, sources=None,
                 wordlist_file=None, resolvers_file=None, max_depth=5, rate_limit=200,
                 silent=False, json_output=False, csv_output=False, use_all=True, quick_mode=False):
        self.domain = domain.lower().strip()
        self.output_file = output_file or f"{self.domain}_subdomains.txt"
        
        # Optimized defaults for maximum subdomain discovery
        self.threads = threads
        self.timeout = timeout
        self.verbose = verbose and not silent
        self.silent = silent
        self.httpx_check = httpx_check
        self.passive_only = passive_only
        self.active_only = active_only
        self.quick_mode = quick_mode
        
        # Use ALL sources by default for maximum coverage
        self.sources = sources or ['ct', 'dns', 'search', 'github', 'wayback', 'shodan', 'apis', 'zone', 'reverse', 'vhost', 'ssl', 'passive']
        
        self.wordlist_file = wordlist_file
        self.resolvers_file = resolvers_file
        self.max_depth = max_depth
        self.rate_limit = rate_limit
        self.json_output = json_output
        self.csv_output = csv_output
        
        # Enable ALL methods by default for comprehensive discovery
        self.use_all = use_all
        
        self.subdomains = set()
        self.live_subdomains = {}  # Store live subdomains with their status
        self.lock = threading.Lock()
        self.session = requests.Session()
        
        # Configure session for httpx-like behavior
        self.session.verify = False
        self.session.headers.update({
            'User-Agent': 'httpx/1.3.0'
        })
        
        # Load custom wordlist if provided
        if self.wordlist_file and os.path.exists(self.wordlist_file):
            self.load_custom_wordlist()
        
        # Load custom resolvers if provided
        if self.resolvers_file and os.path.exists(self.resolvers_file):
            self.load_custom_resolvers()
        
        # User agents for rotation
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0'
        ]
        
        # Comprehensive subdomain wordlist for maximum discovery
        self.wordlist = [
            # Basic and common
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
            
            # Extended common subdomains
            'api1', 'api2', 'api3', 'app1', 'app2', 'app3', 'web01', 'web02', 'web03', 'web1', 'web2', 'web3',
            'srv1', 'srv2', 'srv3', 'server1', 'server2', 'server3', 'host1', 'host2', 'host3',
            'node1', 'node2', 'node3', 'cluster1', 'cluster2', 'lb1', 'lb2', 'proxy1', 'proxy2',
            
            # Cloud and modern infrastructure
            'aws', 'azure', 'gcp', 'cloud', 'k8s', 'kubernetes', 'docker', 'container', 'registry',
            'harbor', 'nexus', 'artifactory', 'jenkins', 'ci', 'cd', 'pipeline', 'build', 'deploy',
            'gitlab', 'github', 'bitbucket', 'git', 'repo', 'scm', 'source', 'code',
            
            # Monitoring and observability
            'grafana', 'prometheus', 'kibana', 'elastic', 'elasticsearch', 'logstash', 'beats',
            'splunk', 'datadog', 'newrelic', 'sentry', 'jaeger', 'zipkin', 'trace', 'metrics',
            'logs', 'monitor', 'monitoring', 'observability', 'health', 'status', 'uptime',
            'ping', 'check', 'probe', 'heartbeat', 'alerts', 'notifications', 'pager',
            
            # Databases and storage
            'db1', 'db2', 'db3', 'database', 'mysql1', 'mysql2', 'postgres', 'postgresql', 'mongo',
            'mongodb', 'redis', 'memcached', 'cassandra', 'elasticsearch', 'solr', 'neo4j',
            'influxdb', 'clickhouse', 'bigquery', 'snowflake', 'redshift', 'athena',
            'storage', 'minio', 's3', 'blob', 'bucket', 'vault', 'secrets', 'kms',
            
            # Security and authentication
            'auth', 'oauth', 'sso', 'saml', 'ldap', 'ad', 'directory', 'identity', 'iam',
            'keycloak', 'okta', 'auth0', 'cognito', 'firebase', 'supabase',
            'security', 'sec', 'firewall', 'waf', 'ids', 'ips', 'siem', 'soar',
            'vault', 'secrets', 'cert', 'certificate', 'ca', 'pki', 'ssl', 'tls',
            
            # API and microservices
            'rest', 'graphql', 'grpc', 'soap', 'webhook', 'callback', 'notify', 'push',
            'realtime', 'ws', 'websocket', 'socket', 'stream', 'sse', 'mqtt', 'amqp',
            'kafka', 'rabbitmq', 'redis', 'pubsub', 'queue', 'worker', 'job', 'task',
            'scheduler', 'cron', 'batch', 'etl', 'pipeline', 'workflow', 'orchestrator',
            
            # Content and media
            'assets', 'static', 'cdn1', 'cdn2', 'edge', 'cache', 'images', 'img1', 'img2',
            'media1', 'media2', 'video', 'audio', 'podcast', 'stream', 'live', 'broadcast',
            'upload', 'downloads', 'files1', 'files2', 'share', 'drive', 'sync',
            
            # Business applications
            'crm1', 'crm2', 'erp', 'hr', 'finance', 'accounting', 'billing', 'invoice',
            'payment', 'checkout', 'cart', 'shop1', 'shop2', 'ecommerce', 'store1', 'store2',
            'inventory', 'warehouse', 'logistics', 'shipping', 'tracking', 'orders',
            'customers', 'users', 'accounts', 'profiles', 'settings', 'preferences',
            
            # Development and testing
            'dev1', 'dev2', 'dev3', 'development', 'test1', 'test2', 'test3', 'testing',
            'qa', 'qe', 'uat', 'acceptance', 'integration', 'e2e', 'performance', 'load',
            'stress', 'chaos', 'canary', 'blue', 'green', 'preview', 'review', 'pr',
            'feature', 'hotfix', 'patch', 'release', 'rc', 'alpha', 'beta', 'gamma',
            
            # Geographic and language
            'us', 'eu', 'asia', 'apac', 'emea', 'latam', 'na', 'sa', 'af', 'oc',
            'us-east', 'us-west', 'eu-west', 'eu-central', 'ap-south', 'ap-southeast',
            'en', 'es', 'fr', 'de', 'it', 'pt', 'ru', 'zh', 'ja', 'ko', 'ar', 'fa',
            'www-en', 'www-es', 'www-fr', 'www-de', 'api-us', 'api-eu', 'cdn-us', 'cdn-eu',
            
            # Single letters and numbers (for comprehensive coverage)
            'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p',
            'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
            '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13', '14', '15',
            '01', '02', '03', '04', '05', '06', '07', '08', '09',
            
            # Persian/Farsi specific
            'panel', 'control', 'manage', 'manager', 'dashboard', 'console', 'admin1', 'admin2',
            'backend', 'internal', 'private', 'restricted', 'hidden', 'secret', 'protected'
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
        if self.silent:
            return
            
        httpx_status = "✅ Enabled" if self.httpx_check else "❌ Disabled"
        
        # Count configured APIs
        try:
            from config import validate_api_keys
            valid_keys, invalid_keys = validate_api_keys()
            api_status = f"✅ {len(valid_keys)}/{len(valid_keys) + len(invalid_keys)} APIs"
        except:
            api_status = "❌ No config.py"
        
        # Mode description
        if self.quick_mode:
            mode = "🚀 Quick Mode (Fast & Essential)"
        elif self.passive_only:
            mode = "🔍 Passive Only"
        elif self.active_only:
            mode = "⚡ Active Only"
        elif self.use_all:
            mode = "🔥 Maximum Discovery (All Methods)"
        else:
            mode = f"🎯 Selected Sources: {', '.join(self.sources)}"
        
        banner = f"""
{Colors.CYAN}╔══════════════════════════════════════════════════════════════════════════════╗
║                    🔍 ADVANCED SUBDOMAIN ENUMERATOR v2.0                   ║
║              Comprehensive Subdomain Discovery & Intelligence               ║
║                                                                              ║
║  🌐 Certificate Transparency  |  🔍 DNS Brute Force                        ║
║  🔎 Search Engine Discovery   |  📊 GitHub Code Search                      ║
║  🚀 httpx HTTP/HTTPS Probing  |  🌍 Web Archive Mining                      ║
║  🛡️  Premium API Integration  |  📡 Passive DNS Sources                     ║
╚══════════════════════════════════════════════════════════════════════════════╝{Colors.END}

{Colors.YELLOW}[*] Target Domain: {Colors.WHITE}{self.domain}{Colors.END}
{Colors.YELLOW}[*] Mode: {Colors.WHITE}{mode}{Colors.END}
{Colors.YELLOW}[*] Output File: {Colors.WHITE}{self.output_file}{Colors.END}
{Colors.YELLOW}[*] Threads: {Colors.WHITE}{self.threads}{Colors.END}
{Colors.YELLOW}[*] Timeout: {Colors.WHITE}{self.timeout}s{Colors.END}
{Colors.YELLOW}[*] HTTP Probing: {Colors.WHITE}{httpx_status}{Colors.END}
{Colors.YELLOW}[*] API Status: {Colors.WHITE}{api_status}{Colors.END}
{Colors.YELLOW}[*] Starting comprehensive subdomain enumeration...{Colors.END}
"""
        print(banner)

    def log(self, message, color=Colors.WHITE):
        """Log message with timestamp"""
        if not self.silent:
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
    
    def load_custom_wordlist(self):
        """Load custom wordlist from file"""
        try:
            with open(self.wordlist_file, 'r', encoding='utf-8') as f:
                custom_words = [line.strip() for line in f if line.strip()]
                self.wordlist.extend(custom_words)
                if self.verbose:
                    self.log(f"Loaded {len(custom_words)} words from custom wordlist", Colors.GREEN)
        except Exception as e:
            if self.verbose:
                self.log(f"Error loading wordlist: {e}", Colors.RED)
    
    def load_custom_resolvers(self):
        """Load custom DNS resolvers from file"""
        try:
            with open(self.resolvers_file, 'r') as f:
                resolvers = [line.strip() for line in f if line.strip()]
                # Configure DNS resolver
                resolver = dns.resolver.Resolver()
                resolver.nameservers = resolvers
                if self.verbose:
                    self.log(f"Loaded {len(resolvers)} custom DNS resolvers", Colors.GREEN)
        except Exception as e:
            if self.verbose:
                self.log(f"Error loading resolvers: {e}", Colors.RED)
    
    def should_run_method(self, method_name):
        """Check if a method should run based on configuration"""
        if self.use_all:
            return True
            
        # Passive methods
        passive_methods = ['ct', 'search', 'github', 'wayback', 'shodan', 'apis']
        # Active methods  
        active_methods = ['dns', 'zone', 'reverse', 'vhost', 'ssl']
        
        if self.passive_only:
            return any(source in method_name.lower() for source in passive_methods)
        
        if self.active_only:
            return any(source in method_name.lower() for source in active_methods)
        
        # Check specific sources
        return any(source in method_name.lower() for source in self.sources)

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
    
    def censys_api(self):
        """Censys API enumeration (requires API key)"""
        if not is_api_configured('CENSYS'):
            if self.verbose:
                self.log("🔍 Censys API key not configured", Colors.YELLOW)
            return
            
        self.log("🔍 Querying Censys API...", Colors.CYAN)
        
        try:
            api_id = API_KEYS.get('CENSYS_API_ID', '')
            api_secret = API_KEYS.get('CENSYS_SECRET', '')
            
            if not api_id or not api_secret:
                if self.verbose:
                    self.log("Censys API credentials incomplete", Colors.RED)
                return
            
            # Censys search queries
            queries = [
                f"names: {self.domain}",
                f"names: *.{self.domain}",
                f"parsed.names: {self.domain}",
                f"parsed.subject_dn: {self.domain}"
            ]
            
            found_count = 0
            
            for query in queries:
                try:
                    url = f"{API_ENDPOINTS.get('CENSYS', 'https://search.censys.io/api/v2')}/certificates/search"
                    
                    headers = {
                        'User-Agent': self.get_random_user_agent(),
                        'Accept': 'application/json'
                    }
                    
                    params = {
                        'q': query,
                        'per_page': 100
                    }
                    
                    response = self.session.get(
                        url, 
                        params=params, 
                        headers=headers, 
                        auth=(api_id, api_secret),
                        timeout=self.timeout
                    )
                    
                    if response.status_code == 200:
                        data = response.json()
                        
                        for result in data.get('result', {}).get('hits', []):
                            # Extract names from certificate
                            names = result.get('names', [])
                            for name in names:
                                if name.endswith(f'.{self.domain}') and not name.startswith('*'):
                                    self.add_subdomain(name)
                                    found_count += 1
                            
                            # Extract from parsed certificate data
                            parsed = result.get('parsed', {})
                            if 'names' in parsed:
                                for name in parsed['names']:
                                    if name.endswith(f'.{self.domain}') and not name.startswith('*'):
                                        self.add_subdomain(name)
                                        found_count += 1
                    
                    elif response.status_code == 401:
                        if self.verbose:
                            self.log("Censys API credentials invalid", Colors.RED)
                        break
                    elif response.status_code == 429:
                        if self.verbose:
                            self.log("Censys API rate limit reached", Colors.YELLOW)
                        time.sleep(5)
                    
                    time.sleep(1)  # Rate limiting
                    
                except Exception as e:
                    if self.verbose:
                        self.log(f"Censys query error: {e}", Colors.YELLOW)
                    continue
            
            if self.verbose and found_count > 0:
                self.log(f"Censys API found {found_count} subdomains", Colors.GREEN)
                
        except Exception as e:
            if self.verbose:
                self.log(f"Censys API error: {e}", Colors.RED)

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
                    
                    # Add GitHub token if available
                    github_token = get_api_key('GITHUB')
                    if github_token:
                        headers['Authorization'] = f'token {github_token}'
                    
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
        if not is_api_configured('VIRUSTOTAL'):
            if self.verbose:
                self.log("🛡️ VirusTotal API key not configured", Colors.YELLOW)
            return
            
        self.log("🛡️ Querying VirusTotal API...", Colors.CYAN)
        
        try:
            api_key = get_api_key('VIRUSTOTAL')
            url = f"{API_ENDPOINTS.get('VIRUSTOTAL', 'https://www.virustotal.com/vtapi/v2')}/domain/report"
            
            params = {
                'domain': self.domain,
                'apikey': api_key
            }
            
            headers = {'User-Agent': self.get_random_user_agent()}
            response = self.session.get(url, params=params, headers=headers, timeout=self.timeout)
            
            if response.status_code == 200:
                data = response.json()
                
                # Extract subdomains from VirusTotal response
                if 'subdomains' in data:
                    for subdomain in data['subdomains']:
                        if subdomain.endswith(f'.{self.domain}'):
                            self.add_subdomain(subdomain)
                
                # Extract from detected URLs
                if 'detected_urls' in data:
                    for url_data in data['detected_urls']:
                        url = url_data.get('url', '')
                        parsed = urlparse(url)
                        if parsed.hostname and parsed.hostname.endswith(f'.{self.domain}'):
                            self.add_subdomain(parsed.hostname)
            
            elif response.status_code == 204:
                if self.verbose:
                    self.log("VirusTotal API rate limit reached", Colors.YELLOW)
            elif response.status_code == 403:
                if self.verbose:
                    self.log("VirusTotal API key invalid", Colors.RED)
                    
            time.sleep(15)  # VirusTotal rate limiting
            
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
        
        # Combine wordlists based on mode
        if self.quick_mode:
            # Quick mode: use only essential subdomains
            quick_wordlist = [
                'www', 'mail', 'ftp', 'admin', 'api', 'app', 'blog', 'dev', 'test', 'staging',
                'cdn', 'static', 'assets', 'images', 'media', 'docs', 'support', 'help',
                'shop', 'store', 'portal', 'dashboard', 'panel', 'console', 'manage',
                'secure', 'ssl', 'vpn', 'remote', 'backup', 'monitor', 'status', 'health'
            ]
            all_wordlist = quick_wordlist
        else:
            # Full mode: use comprehensive wordlist
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
        """Shodan API search (requires API key)"""
        if not is_api_configured('SHODAN'):
            # Fallback to passive search
            self.shodan_passive_search()
            return
            
        self.log("🔍 Querying Shodan API...", Colors.CYAN)
        
        try:
            api_key = get_api_key('SHODAN')
            
            # Search for domain
            search_queries = [
                f"hostname:{self.domain}",
                f"ssl:{self.domain}",
                f"html:{self.domain}",
                f"http.title:{self.domain}"
            ]
            
            found_count = 0
            
            for query in search_queries:
                try:
                    url = f"{API_ENDPOINTS.get('SHODAN', 'https://api.shodan.io')}/shodan/host/search"
                    params = {
                        'key': api_key,
                        'query': query,
                        'facets': 'domain'
                    }
                    
                    response = self.session.get(url, params=params, timeout=self.timeout)
                    
                    if response.status_code == 200:
                        data = response.json()
                        
                        # Extract hostnames from results
                        for result in data.get('matches', []):
                            # From hostnames
                            hostnames = result.get('hostnames', [])
                            for hostname in hostnames:
                                if hostname.endswith(f'.{self.domain}'):
                                    self.add_subdomain(hostname)
                                    found_count += 1
                            
                            # From SSL certificates
                            ssl_data = result.get('ssl', {})
                            if 'cert' in ssl_data:
                                cert = ssl_data['cert']
                                # Subject alternative names
                                if 'extensions' in cert:
                                    for ext in cert['extensions']:
                                        if ext.get('name') == 'subjectAltName':
                                            san_data = ext.get('data', '')
                                            # Parse SAN data for subdomains
                                            pattern = r'DNS:([a-zA-Z0-9.-]+\.' + re.escape(self.domain) + r')'
                                            matches = re.findall(pattern, san_data)
                                            for match in matches:
                                                self.add_subdomain(match)
                                                found_count += 1
                    
                    elif response.status_code == 401:
                        if self.verbose:
                            self.log("Shodan API key invalid", Colors.RED)
                        break
                    elif response.status_code == 429:
                        if self.verbose:
                            self.log("Shodan API rate limit reached", Colors.YELLOW)
                        time.sleep(5)
                    
                    time.sleep(1)  # Rate limiting
                    
                except Exception as e:
                    if self.verbose:
                        self.log(f"Shodan query error: {e}", Colors.YELLOW)
                    continue
            
            if self.verbose and found_count > 0:
                self.log(f"Shodan API found {found_count} subdomains", Colors.GREEN)
                
        except Exception as e:
            if self.verbose:
                self.log(f"Shodan API error: {e}", Colors.RED)
    
    def shodan_passive_search(self):
        """Shodan passive search via web interface"""
        self.log("🔍 Searching Shodan data (passive)...", Colors.CYAN)
        
        try:
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
                self.log(f"Shodan passive search error: {e}", Colors.RED)

    def chaos_api(self):
        """ProjectDiscovery Chaos API (requires API key)"""
        if not is_api_configured('CHAOS'):
            if self.verbose:
                self.log("🚀 Chaos API key not configured", Colors.YELLOW)
            return
            
        self.log("🚀 Querying Chaos API...", Colors.CYAN)
        
        try:
            api_key = get_api_key('CHAOS')
            url = f"{API_ENDPOINTS.get('CHAOS', 'https://dns.projectdiscovery.io/dns')}/{self.domain}/subdomains"
            
            headers = {
                'User-Agent': self.get_random_user_agent(),
                'Authorization': f'Bearer {api_key}',
                'Accept': 'application/json'
            }
            
            response = self.session.get(url, headers=headers, timeout=self.timeout)
            
            if response.status_code == 200:
                data = response.json()
                
                # Chaos API returns subdomains in different formats
                if isinstance(data, dict):
                    subdomains = data.get('subdomains', [])
                elif isinstance(data, list):
                    subdomains = data
                else:
                    subdomains = []
                
                found_count = 0
                for subdomain in subdomains:
                    if isinstance(subdomain, dict):
                        subdomain = subdomain.get('subdomain', '')
                    
                    if subdomain and subdomain.endswith(f'.{self.domain}'):
                        self.add_subdomain(subdomain)
                        found_count += 1
                
                if self.verbose and found_count > 0:
                    self.log(f"Chaos API found {found_count} subdomains", Colors.GREEN)
            
            elif response.status_code == 401:
                if self.verbose:
                    self.log("Chaos API key invalid", Colors.RED)
            elif response.status_code == 429:
                if self.verbose:
                    self.log("Chaos API rate limit reached", Colors.YELLOW)
            elif response.status_code == 404:
                if self.verbose:
                    self.log("Domain not found in Chaos dataset", Colors.YELLOW)
                    
        except Exception as e:
            if self.verbose:
                self.log(f"Chaos API error: {e}", Colors.RED)

    def security_trails_api(self):
        """SecurityTrails API enumeration (requires API key)"""
        if not is_api_configured('SECURITYTRAILS'):
            if self.verbose:
                self.log("🛡️ SecurityTrails API key not configured", Colors.YELLOW)
            return
            
        self.log("🛡️ Querying SecurityTrails API...", Colors.CYAN)
        
        try:
            api_key = get_api_key('SECURITYTRAILS')
            
            # Multiple SecurityTrails endpoints
            endpoints = [
                f"/domain/{self.domain}/subdomains",
                f"/domain/{self.domain}/associated",
                f"/history/{self.domain}/dns/a"
            ]
            
            found_count = 0
            
            for endpoint in endpoints:
                try:
                    url = f"{API_ENDPOINTS.get('SECURITYTRAILS', 'https://api.securitytrails.com/v1')}{endpoint}"
                    
                    headers = {
                        'User-Agent': self.get_random_user_agent(),
                        'APIKEY': api_key,
                        'Accept': 'application/json'
                    }
                    
                    response = self.session.get(url, headers=headers, timeout=self.timeout)
                    
                    if response.status_code == 200:
                        data = response.json()
                        
                        # Handle different response formats
                        if 'subdomains' in data:
                            # Subdomains endpoint
                            for subdomain in data['subdomains']:
                                full_subdomain = f"{subdomain}.{self.domain}"
                                self.add_subdomain(full_subdomain)
                                found_count += 1
                        
                        elif 'associated' in data:
                            # Associated domains endpoint
                            for domain in data['associated']:
                                if domain.endswith(f'.{self.domain}'):
                                    self.add_subdomain(domain)
                                    found_count += 1
                        
                        elif 'records' in data:
                            # DNS history endpoint
                            for record in data['records']:
                                if 'values' in record:
                                    for value in record['values']:
                                        hostname = value.get('hostname', '')
                                        if hostname and hostname.endswith(f'.{self.domain}'):
                                            self.add_subdomain(hostname)
                                            found_count += 1
                    
                    elif response.status_code == 401:
                        if self.verbose:
                            self.log("SecurityTrails API key invalid", Colors.RED)
                        break
                    elif response.status_code == 429:
                        if self.verbose:
                            self.log("SecurityTrails API rate limit reached", Colors.YELLOW)
                        time.sleep(5)
                    
                    time.sleep(1)  # Rate limiting
                    
                except Exception as e:
                    if self.verbose:
                        self.log(f"SecurityTrails endpoint error: {e}", Colors.YELLOW)
                    continue
            
            if self.verbose and found_count > 0:
                self.log(f"SecurityTrails API found {found_count} subdomains", Colors.GREEN)
                
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
        
        # Define method mappings
        method_map = {
            'ct': self.certificate_transparency,
            'dns': self.dns_brute_force,
            'search': self.search_engines,
            'github': self.github_search,
            'wayback': self.wayback_machine,
            'zone': self.zone_transfer,
            'reverse': self.reverse_dns,
            'vhost': self.vhost_discovery,
            'shodan': self.shodan_search,
            'passive': self.passive_dns_sources,
            'ssl': self.ssl_certificate_search,
            'apis': [self.chaos_api, self.virustotal_api, self.security_trails_api, self.censys_api]
        }
        
        # Build methods list based on configuration
        methods = []
        
        if self.use_all or not (self.passive_only or self.active_only):
            # Use all methods
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
                self.chaos_api,
                self.virustotal_api,
                self.security_trails_api,
                self.censys_api,
            ]
        else:
            # Build based on sources and passive/active flags
            for source in self.sources:
                if source in method_map:
                    if isinstance(method_map[source], list):
                        methods.extend(method_map[source])
                    else:
                        methods.append(method_map[source])
        
        # Filter methods based on passive/active flags
        if self.passive_only:
            passive_methods = [
                self.certificate_transparency, self.search_engines, self.github_search,
                self.wayback_machine, self.shodan_search, self.passive_dns_sources,
                self.chaos_api, self.virustotal_api, self.security_trails_api, self.censys_api
            ]
            methods = [m for m in methods if m in passive_methods]
        
        elif self.active_only:
            active_methods = [
                self.dns_brute_force, self.zone_transfer, self.reverse_dns,
                self.vhost_discovery, self.ssl_certificate_search
            ]
            methods = [m for m in methods if m in active_methods]
        
        # Remove duplicates while preserving order
        seen = set()
        unique_methods = []
        for method in methods:
            if method not in seen:
                seen.add(method)
                unique_methods.append(method)
        
        # Run enumeration methods
        for method in unique_methods:
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
            
            # Categorize by status code and title
            status_categories = {
                'success': [],      # 2xx
                'redirect': [],     # 3xx
                'client_error': [], # 4xx
                'server_error': [], # 5xx
                'unknown': []       # others
            }
            
            # Group by title within each category
            title_groups = {}
            
            for url, info in self.live_subdomains.items():
                category = info['category']
                title = info['title']
                
                # Create title groups
                if category not in title_groups:
                    title_groups[category] = {}
                
                if title not in title_groups[category]:
                    title_groups[category][title] = []
                
                title_groups[category][title].append(url)
            
            # Save categorized results with improved format
            with open(live_output_file, 'w', encoding='utf-8') as f:
                f.write(f"# Live Subdomains for {self.domain}\n")
                f.write(f"# Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"# Total live subdomains: {len(self.live_subdomains)}\n\n")
                
                # Define category order and names
                category_names = {
                    'success': 'SUCCESS (2xx)',
                    'redirect': 'REDIRECT (3xx)', 
                    'client_error': 'CLIENT ERROR (4xx)',
                    'server_error': 'SERVER ERROR (5xx)',
                    'unknown': 'UNKNOWN'
                }
                
                for category in ['success', 'redirect', 'client_error', 'server_error', 'unknown']:
                    if category in title_groups and title_groups[category]:
                        total_urls = sum(len(urls) for urls in title_groups[category].values())
                        f.write(f"## {category_names[category]} ({total_urls} subdomains)\n\n")
                        
                        # Sort titles, put 'No Title' at the end
                        sorted_titles = sorted(title_groups[category].keys(), 
                                             key=lambda x: (x == 'No Title', x.lower()))
                        
                        for title in sorted_titles:
                            urls = title_groups[category][title]
                            if len(urls) > 1:
                                f.write(f"### {title} ({len(urls)} subdomains)\n")
                                for url in sorted(urls):
                                    f.write(f"{url}\n")
                                f.write("\n")
                            else:
                                # Single subdomain with unique title
                                f.write(f"{urls[0]}\n")
                        
                        f.write("\n")
            
            # Also save simple list
            simple_output_file = self.output_file.replace('.txt', '_simple.txt')
            with open(simple_output_file, 'w', encoding='utf-8') as f:
                for url in sorted(self.live_subdomains.keys()):
                    f.write(f"{url}\n")
            
            # Save JSON format if requested
            if self.json_output:
                json_output_file = self.output_file.replace('.txt', '.json')
                json_data = {
                    'domain': self.domain,
                    'timestamp': datetime.now().isoformat(),
                    'total_subdomains': len(self.subdomains),
                    'live_subdomains': len(self.live_subdomains),
                    'results': []
                }
                
                for url, info in self.live_subdomains.items():
                    json_data['results'].append({
                        'url': url,
                        'subdomain': info['subdomain'],
                        'protocol': info['protocol'],
                        'status_code': info['status_code'],
                        'title': info['title'],
                        'response_time': info['response_time'],
                        'content_length': info['content_length'],
                        'category': info['category']
                    })
                
                with open(json_output_file, 'w', encoding='utf-8') as f:
                    json.dump(json_data, f, indent=2, ensure_ascii=False)
                
                if not self.silent:
                    self.log(f"💾 JSON results saved to: {json_output_file}", Colors.GREEN)
            
            # Save CSV format if requested
            if self.csv_output:
                csv_output_file = self.output_file.replace('.txt', '.csv')
                with open(csv_output_file, 'w', encoding='utf-8') as f:
                    f.write("URL,Subdomain,Protocol,Status Code,Title,Response Time (ms),Content Length,Category\n")
                    for url, info in sorted(self.live_subdomains.items()):
                        f.write(f'"{url}","{info["subdomain"]}","{info["protocol"]}",{info["status_code"]},"{info["title"]}",{info["response_time"]},{info["content_length"]},"{info["category"]}"\n')
                
                if not self.silent:
                    self.log(f"💾 CSV results saved to: {csv_output_file}", Colors.GREEN)
            
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
        description="🔍 Advanced Subdomain Enumeration Tool with httpx Integration & Premium APIs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Maximum discovery (default - comprehensive scan)
  python3 subdomains.py -d example.com
  
  # Quick scan (fast results)
  python3 subdomains.py -d example.com --quick
  
  # Aggressive scan (maximum resources)
  python3 subdomains.py -d example.com --aggressive
  
  # Passive only (no active DNS queries)
  python3 subdomains.py -d example.com --passive
  
  # Custom output formats
  python3 subdomains.py -d example.com --json --csv
  
  # Silent mode (only results)
  python3 subdomains.py -d example.com --silent
  
  # Check API configuration
  python3 subdomains.py --show-apis
        """
    )
    
    parser.add_argument('-d', '--domain', help='Target domain')
    parser.add_argument('-o', '--output', help='Output file (default: domain_subdomains.txt)')
    parser.add_argument('-t', '--threads', type=int, default=100, help='Number of threads (default: 100 - optimized for speed)')
    parser.add_argument('--timeout', type=int, default=15, help='Request timeout in seconds (default: 15 - optimized for reliability)')
    parser.add_argument('-v', '--verbose', action='store_true', default=True, help='Verbose output (default: enabled)')
    parser.add_argument('--no-httpx', action='store_true', help='Skip HTTP/HTTPS probing (httpx functionality)')
    parser.add_argument('--show-apis', action='store_true', help='Show API configuration status and exit')
    
    # Advanced enumeration options (optimized defaults for maximum discovery)
    parser.add_argument('--all', action='store_true', default=True, help='Use all enumeration techniques (default: enabled for comprehensive discovery)')
    parser.add_argument('--passive', action='store_true', help='Use only passive enumeration (overrides --all)')
    parser.add_argument('--active', action='store_true', help='Use only active enumeration (overrides --all)')
    parser.add_argument('--sources', nargs='+', help='Specify sources to use (default: all sources)', 
                       choices=['ct', 'dns', 'search', 'github', 'wayback', 'shodan', 'apis', 'zone', 'reverse', 'vhost', 'ssl', 'passive'])
    parser.add_argument('--wordlist', help='Custom wordlist file for DNS brute force (default: comprehensive built-in wordlist)')
    parser.add_argument('--resolvers', help='Custom DNS resolvers file (default: system resolvers)')
    parser.add_argument('--max-depth', type=int, default=5, help='Maximum recursion depth for subdomain discovery (default: 5 - deep discovery)')
    parser.add_argument('--rate-limit', type=int, default=200, help='Rate limit requests per second (default: 200 - optimized for speed)')
    parser.add_argument('--silent', action='store_true', help='Silent mode - only output results')
    parser.add_argument('--json', action='store_true', help='Output results in JSON format')
    parser.add_argument('--csv', action='store_true', help='Output results in CSV format')
    parser.add_argument('--quick', action='store_true', help='Quick scan mode (reduced wordlist and sources for faster results)')
    parser.add_argument('--aggressive', action='store_true', help='Aggressive mode (maximum threads, timeout, and comprehensive discovery)')
    
    args = parser.parse_args()
    
    # Show API status if requested
    if args.show_apis:
        try:
            from config import print_api_status, USAGE_INSTRUCTIONS
            print(USAGE_INSTRUCTIONS)
            print_api_status()
        except ImportError:
            print(f"{Colors.RED}❌ config.py not found. Please create config.py with your API keys.{Colors.END}")
        sys.exit(0)
    
    # Validate domain
    if not args.domain:
        print(f"{Colors.RED}❌ Domain is required. Use -d/--domain to specify target domain.{Colors.END}")
        sys.exit(1)
        
    domain_pattern = re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    )
    
    if not domain_pattern.match(args.domain):
        print(f"{Colors.RED}❌ Invalid domain format: {args.domain}{Colors.END}")
        sys.exit(1)
    
    try:
        # Apply mode-specific optimizations
        threads = args.threads
        timeout = args.timeout
        use_all = args.all
        sources = args.sources
        max_depth = args.max_depth
        rate_limit = args.rate_limit
        
        # Override defaults based on mode
        if args.quick:
            # Quick mode: faster but less comprehensive
            threads = min(50, threads)
            timeout = min(8, timeout)
            use_all = False
            sources = sources or ['ct', 'dns', 'search']
            max_depth = min(2, max_depth)
            rate_limit = min(100, rate_limit)
            if not args.silent:
                print(f"{Colors.YELLOW}🚀 Quick mode enabled: faster scan with reduced coverage{Colors.END}")
        
        elif args.aggressive:
            # Aggressive mode: maximum discovery
            threads = max(200, threads)
            timeout = max(20, timeout)
            use_all = True
            sources = ['ct', 'dns', 'search', 'github', 'wayback', 'shodan', 'apis', 'zone', 'reverse', 'vhost', 'ssl', 'passive']
            max_depth = max(7, max_depth)
            rate_limit = max(300, rate_limit)
            if not args.silent:
                print(f"{Colors.RED}🔥 Aggressive mode enabled: maximum discovery with high resource usage{Colors.END}")
        
        # Override if passive/active specified
        if args.passive:
            use_all = False
            if not args.silent:
                print(f"{Colors.CYAN}🔍 Passive mode: using only passive enumeration techniques{Colors.END}")
        elif args.active:
            use_all = False
            if not args.silent:
                print(f"{Colors.MAGENTA}⚡ Active mode: using only active enumeration techniques{Colors.END}")
        
        # Initialize enumerator with optimized settings
        enumerator = SubdomainEnumerator(
            domain=args.domain,
            output_file=args.output,
            threads=threads,
            timeout=timeout,
            verbose=args.verbose and not args.silent,
            httpx_check=not args.no_httpx,
            passive_only=args.passive,
            active_only=args.active,
            sources=sources,
            wordlist_file=args.wordlist,
            resolvers_file=args.resolvers,
            max_depth=max_depth,
            rate_limit=rate_limit,
            silent=args.silent,
            json_output=args.json,
            csv_output=args.csv,
            use_all=use_all,
            quick_mode=args.quick
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