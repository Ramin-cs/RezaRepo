#!/usr/bin/env python3
"""
Proof of Concept Capture Module for XSS Scanner
Advanced screenshot capture and PoC generation with Selenium WebDriver
"""

import os
import time
import base64
import hashlib
from typing import Dict, List, Optional, Tuple
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, WebDriverException, NoSuchElementException
from selenium.webdriver.common.action_chains import ActionChains
from selenium.webdriver.common.keys import Keys
import requests
from urllib.parse import urljoin, urlparse

class PoCCapture:
    """Advanced PoC capture with screenshot and video recording"""
    
    def __init__(self, options: Dict):
        self.options = options
        self.driver = None
        self.screenshots_dir = "poc_screenshots"
        self.videos_dir = "poc_videos"
        self.ensure_directories()
        
    def ensure_directories(self):
        """Ensure screenshot and video directories exist"""
        if not os.path.exists(self.screenshots_dir):
            os.makedirs(self.screenshots_dir)
        if not os.path.exists(self.videos_dir):
            os.makedirs(self.videos_dir)
            
    def setup_driver(self) -> bool:
        """Setup Chrome WebDriver with advanced options"""
        try:
            chrome_options = Options()
            
            # Basic options
            chrome_options.add_argument('--no-sandbox')
            chrome_options.add_argument('--disable-dev-shm-usage')
            chrome_options.add_argument('--disable-gpu')
            chrome_options.add_argument('--disable-extensions')
            chrome_options.add_argument('--disable-plugins')
            chrome_options.add_argument('--disable-images')
            chrome_options.add_argument('--disable-javascript')
            chrome_options.add_argument('--disable-css')
            chrome_options.add_argument('--disable-web-security')
            chrome_options.add_argument('--disable-features=VizDisplayCompositor')
            
            # Window size
            chrome_options.add_argument('--window-size=1920,1080')
            chrome_options.add_argument('--start-maximized')
            
            # Performance options
            chrome_options.add_argument('--memory-pressure-off')
            chrome_options.add_argument('--max_old_space_size=4096')
            
            # Security options
            chrome_options.add_argument('--disable-blink-features=AutomationControlled')
            chrome_options.add_experimental_option("excludeSwitches", ["enable-automation"])
            chrome_options.add_experimental_option('useAutomationExtension', False)
            
            # User agent
            chrome_options.add_argument('--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36')
            
            # Headless mode (disabled for live demonstration)
            if self.options.get('headless', False):
                chrome_options.add_argument('--headless')
            else:
                # Make Chrome visible for live demonstration
                chrome_options.add_argument('--start-maximized')
                chrome_options.add_argument('--disable-web-security')
                chrome_options.add_argument('--disable-features=VizDisplayCompositor')
                
            # Initialize driver
            self.driver = webdriver.Chrome(options=chrome_options)
            
            # Execute script to remove webdriver property
            self.driver.execute_script("Object.defineProperty(navigator, 'webdriver', {get: () => undefined})")
            
            # Set timeouts
            self.driver.set_page_load_timeout(30)
            self.driver.implicitly_wait(10)
            
            return True
            
        except Exception as e:
            print(f"❌ Failed to setup WebDriver: {e}")
            return False
            
    def capture_xss_poc(self, url: str, payload: str, input_point: Dict) -> Dict:
        """Capture comprehensive PoC for XSS vulnerability"""
        if not self.driver:
            if not self.setup_driver():
                return {'success': False, 'error': 'Failed to setup WebDriver'}
                
        try:
            print(f"📸 Capturing PoC for: {url}")
            
            # Navigate to the page
            self.driver.get(url)
            
            # Wait for page to load
            WebDriverWait(self.driver, 10).until(
                EC.presence_of_element_located((By.TAG_NAME, "body"))
            )
            
            # Take initial screenshot
            initial_screenshot = self._take_screenshot("initial")
            
            # Inject payload
            injection_success = self._inject_payload_interactive(input_point, payload)
            
            if not injection_success:
                return {'success': False, 'error': 'Failed to inject payload'}
                
            # Wait for potential XSS execution
            time.sleep(2)
            
            # Take screenshot after injection
            injection_screenshot = self._take_screenshot("injection")
            
            # Check for alert dialogs
            alert_detected = self._check_for_alerts()
            
            if alert_detected:
                # Take screenshot of alert
                alert_screenshot = self._take_screenshot("alert")
                
                # Handle alert
                self._handle_alert()
                
                # Take screenshot after alert handling
                post_alert_screenshot = self._take_screenshot("post_alert")
            else:
                alert_screenshot = ""
                post_alert_screenshot = ""
                
            # Generate PoC report
            poc_data = {
                'success': True,
                'url': url,
                'payload': payload,
                'input_point': input_point,
                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                'screenshots': {
                    'initial': initial_screenshot,
                    'injection': injection_screenshot,
                    'alert': alert_screenshot,
                    'post_alert': post_alert_screenshot
                },
                'alert_detected': alert_detected,
                'page_source': self.driver.page_source,
                'page_title': self.driver.title,
                'current_url': self.driver.current_url
            }
            
            # Save PoC data
            self._save_poc_data(poc_data)
            
            return poc_data
            
        except Exception as e:
            print(f"❌ PoC capture failed: {e}")
            return {'success': False, 'error': str(e)}
            
    def _inject_payload_interactive(self, input_point: Dict, payload: str) -> bool:
        """Inject payload using interactive browser automation"""
        try:
            if input_point['type'] == 'form':
                return self._inject_form_payload(input_point, payload)
            elif input_point['type'] == 'url_params':
                return self._inject_url_payload(input_point, payload)
            else:
                return False
                
        except Exception as e:
            print(f"❌ Payload injection failed: {e}")
            return False
            
    def _inject_form_payload(self, form: Dict, payload: str) -> bool:
        """Inject payload into form fields"""
        try:
            # Find form elements
            form_elements = self.driver.find_elements(By.TAG_NAME, "form")
            
            for form_element in form_elements:
                # Check if this is the target form
                action = form_element.get_attribute("action")
                if action and action in form.get('action', ''):
                    # Find input fields
                    inputs = form_element.find_elements(By.TAG_NAME, "input")
                    textareas = form_element.find_elements(By.TAG_NAME, "textarea")
                    selects = form_element.find_elements(By.TAG_NAME, "select")
                    
                    all_inputs = inputs + textareas + selects
                    
                    for input_field in all_inputs:
                        field_name = input_field.get_attribute("name")
                        field_type = input_field.get_attribute("type")
                        
                        # Check if this is a text input field
                        if field_name and field_type in ['text', 'email', 'search', 'url', 'password']:
                            # Clear field and inject payload
                            input_field.clear()
                            input_field.send_keys(payload)
                            
                    # Submit form
                    submit_button = form_element.find_element(By.CSS_SELECTOR, "input[type='submit'], button[type='submit'], button")
                    submit_button.click()
                    
                    return True
                    
            return False
            
        except Exception as e:
            print(f"❌ Form injection failed: {e}")
            return False
            
    def _inject_url_payload(self, url_params: Dict, payload: str) -> bool:
        """Inject payload into URL parameters"""
        try:
            # Construct URL with payload
            base_url = url_params['url']
            params = url_params['params'].copy()
            
            # Inject payload into first parameter
            first_param = list(params.keys())[0]
            params[first_param] = payload
            
            # Build URL
            param_string = "&".join([f"{k}={v}" for k, v in params.items()])
            target_url = f"{base_url}?{param_string}"
            
            # Navigate to URL with payload
            self.driver.get(target_url)
            
            return True
            
        except Exception as e:
            print(f"❌ URL injection failed: {e}")
            return False
            
    def _check_for_alerts(self) -> bool:
        """Check for JavaScript alert dialogs"""
        try:
            # Check for alert
            WebDriverWait(self.driver, 3).until(EC.alert_is_present())
            return True
        except TimeoutException:
            return False
        except Exception:
            return False
            
    def _handle_alert(self):
        """Handle JavaScript alert dialog"""
        try:
            alert = self.driver.switch_to.alert
            alert.accept()
        except Exception:
            pass
            
    def _take_screenshot(self, name: str) -> str:
        """Take screenshot and return filename"""
        try:
            timestamp = int(time.time())
            filename = f"{name}_{timestamp}.png"
            filepath = os.path.join(self.screenshots_dir, filename)
            
            self.driver.save_screenshot(filepath)
            return filepath
            
        except Exception as e:
            print(f"❌ Screenshot failed: {e}")
            return ""
            
    def _save_poc_data(self, poc_data: Dict):
        """Save PoC data to file"""
        try:
            timestamp = int(time.time())
            filename = f"poc_data_{timestamp}.json"
            filepath = os.path.join(self.screenshots_dir, filename)
            
            # Convert to JSON-serializable format
            json_data = {
                'success': poc_data['success'],
                'url': poc_data['url'],
                'payload': poc_data['payload'],
                'input_point': poc_data['input_point'],
                'timestamp': poc_data['timestamp'],
                'screenshots': poc_data['screenshots'],
                'alert_detected': poc_data['alert_detected'],
                'page_title': poc_data['page_title'],
                'current_url': poc_data['current_url']
            }
            
            import json
            with open(filepath, 'w') as f:
                json.dump(json_data, f, indent=2)
                
        except Exception as e:
            print(f"❌ Failed to save PoC data: {e}")
            
    def capture_video_poc(self, url: str, payload: str, input_point: Dict) -> str:
        """Capture video PoC (requires additional setup)"""
        try:
            # This would require additional tools like ffmpeg
            # For now, return empty string
            return ""
            
        except Exception as e:
            print(f"❌ Video capture failed: {e}")
            return ""
            
    def generate_poc_report(self, poc_data: Dict) -> str:
        """Generate comprehensive PoC report"""
        if not poc_data.get('success'):
            return f"PoC capture failed: {poc_data.get('error', 'Unknown error')}"
            
        report = f"""
XSS Vulnerability Proof of Concept Report
========================================

Target URL: {poc_data['url']}
Payload: {poc_data['payload']}
Timestamp: {poc_data['timestamp']}
Alert Detected: {poc_data['alert_detected']}

Input Point Details:
- Type: {poc_data['input_point']['type']}
- URL: {poc_data['input_point']['url']}

Screenshots:
- Initial: {poc_data['screenshots']['initial']}
- Injection: {poc_data['screenshots']['injection']}
- Alert: {poc_data['screenshots']['alert']}
- Post Alert: {poc_data['screenshots']['post_alert']}

Page Information:
- Title: {poc_data['page_title']}
- Current URL: {poc_data['current_url']}

Reproduction Steps:
1. Navigate to: {poc_data['url']}
2. Inject payload: {poc_data['payload']}
3. Submit form or navigate to URL
4. Observe XSS execution
5. Alert dialog should appear (if payload successful)

Remediation:
- Implement proper input validation
- Use output encoding
- Implement Content Security Policy (CSP)
- Sanitize user input before rendering
        """
        
        return report
        
    def cleanup(self):
        """Cleanup WebDriver resources"""
        if self.driver:
            try:
                self.driver.quit()
            except Exception:
                pass
            self.driver = None
            
    def __del__(self):
        """Destructor to ensure cleanup"""
        self.cleanup()