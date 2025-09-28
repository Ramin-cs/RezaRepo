"""
Chrome Automation Module for Open Redirect Scanner
Handles browser automation, redirect testing, and screenshot capture
"""

import asyncio
import os
import time
import logging
from pathlib import Path
from typing import Dict, Optional, List
from urllib.parse import urlparse, urljoin
import base64
import json

try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.chrome.service import Service
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.common.exceptions import TimeoutException, WebDriverException
    from webdriver_manager.chrome import ChromeDriverManager
except ImportError:
    print("Selenium not installed. Installing...")
    os.system("pip install selenium webdriver-manager")
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.chrome.service import Service
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.common.exceptions import TimeoutException, WebDriverException
    from webdriver_manager.chrome import ChromeDriverManager

class ChromeModule:
    """
    Chrome automation module for redirect testing and screenshot capture
    """
    
    def __init__(self, logger, output_dir: Path):
        self.logger = logger
        self.output_dir = output_dir
        self.driver = None
        self.screenshots_dir = output_dir / "screenshots"
        self.screenshots_dir.mkdir(exist_ok=True)
        
        # Target domain for redirect validation
        self.target_domain = "google.com"
        
    async def initialize(self):
        """Initialize Chrome driver"""
        try:
            self.logger.info("Initializing Chrome driver...")
            
            # Chrome options
            chrome_options = Options()
            chrome_options.add_argument("--headless")
            chrome_options.add_argument("--no-sandbox")
            chrome_options.add_argument("--disable-dev-shm-usage")
            chrome_options.add_argument("--disable-gpu")
            chrome_options.add_argument("--window-size=1920,1080")
            chrome_options.add_argument("--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
            chrome_options.add_argument("--disable-blink-features=AutomationControlled")
            chrome_options.add_experimental_option("excludeSwitches", ["enable-automation"])
            chrome_options.add_experimental_option('useAutomationExtension', False)
            
            # Initialize driver
            service = Service(ChromeDriverManager().install())
            self.driver = webdriver.Chrome(service=service, options=chrome_options)
            
            # Execute script to remove webdriver property
            self.driver.execute_script("Object.defineProperty(navigator, 'webdriver', {get: () => undefined})")
            
            self.logger.info("Chrome driver initialized successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to initialize Chrome driver: {str(e)}")
            return False
    
    async def test_redirect(self, test_url: str, payload: str) -> Optional[Dict]:
        """Test if a URL redirects to target domain"""
        try:
            self.logger.info(f"Testing redirect: {test_url}")
            
            # Navigate to test URL
            self.driver.get(test_url)
            
            # Wait for page to load
            await asyncio.sleep(2)
            
            # Get current URL after potential redirect
            current_url = self.driver.current_url
            
            # Check if redirected to target domain
            parsed_url = urlparse(current_url)
            is_redirected = self.target_domain in parsed_url.netloc.lower()
            
            if is_redirected:
                self.logger.info(f"Redirect detected: {current_url}")
                
                # Take screenshot
                screenshot_path = await self._take_screenshot(test_url, payload)
                
                return {
                    'vulnerable': True,
                    'original_url': test_url,
                    'redirect_url': current_url,
                    'payload': payload,
                    'screenshot_path': screenshot_path,
                    'timestamp': time.time()
                }
            else:
                return {
                    'vulnerable': False,
                    'original_url': test_url,
                    'current_url': current_url,
                    'payload': payload,
                    'timestamp': time.time()
                }
                
        except Exception as e:
            self.logger.error(f"Error testing redirect {test_url}: {str(e)}")
            return None
    
    async def _take_screenshot(self, test_url: str, payload: str) -> str:
        """Take screenshot of the redirected page"""
        try:
            # Generate unique filename
            timestamp = int(time.time())
            url_hash = hashlib.md5(test_url.encode()).hexdigest()[:8]
            payload_hash = hashlib.md5(payload.encode()).hexdigest()[:8]
            
            filename = f"redirect_{timestamp}_{url_hash}_{payload_hash}.png"
            screenshot_path = self.screenshots_dir / filename
            
            # Take screenshot
            self.driver.save_screenshot(str(screenshot_path))
            
            self.logger.info(f"Screenshot saved: {screenshot_path}")
            return str(screenshot_path)
            
        except Exception as e:
            self.logger.error(f"Error taking screenshot: {str(e)}")
            return ""
    
    async def test_form_redirect(self, form_data: Dict, payload: str) -> Optional[Dict]:
        """Test form-based redirect"""
        try:
            self.logger.info(f"Testing form redirect with payload: {payload}")
            
            # Navigate to form page
            self.driver.get(form_data['url'])
            
            # Wait for form to load
            await asyncio.sleep(2)
            
            # Find form elements
            form = self.driver.find_element(By.TAG_NAME, "form")
            
            # Fill form with payload
            for field_name, field_value in form_data['fields'].items():
                try:
                    field = form.find_element(By.NAME, field_name)
                    field.clear()
                    field.send_keys(payload)
                except:
                    continue
            
            # Submit form
            form.submit()
            
            # Wait for redirect
            await asyncio.sleep(3)
            
            # Check current URL
            current_url = self.driver.current_url
            parsed_url = urlparse(current_url)
            is_redirected = self.target_domain in parsed_url.netloc.lower()
            
            if is_redirected:
                screenshot_path = await self._take_screenshot(form_data['url'], payload)
                
                return {
                    'vulnerable': True,
                    'form_url': form_data['url'],
                    'redirect_url': current_url,
                    'payload': payload,
                    'screenshot_path': screenshot_path,
                    'timestamp': time.time()
                }
            else:
                return {
                    'vulnerable': False,
                    'form_url': form_data['url'],
                    'current_url': current_url,
                    'payload': payload,
                    'timestamp': time.time()
                }
                
        except Exception as e:
            self.logger.error(f"Error testing form redirect: {str(e)}")
            return None
    
    async def test_javascript_redirect(self, js_code: str, payload: str) -> Optional[Dict]:
        """Test JavaScript-based redirect"""
        try:
            self.logger.info(f"Testing JavaScript redirect with payload: {payload}")
            
            # Create test page with JavaScript
            test_page = f"""
            <!DOCTYPE html>
            <html>
            <head><title>Redirect Test</title></head>
            <body>
                <script>
                    {js_code.replace('PAYLOAD_PLACEHOLDER', payload)}
                </script>
            </body>
            </html>
            """
            
            # Save test page
            test_file = self.output_dir / "test_page.html"
            with open(test_file, 'w') as f:
                f.write(test_page)
            
            # Navigate to test page
            file_url = f"file://{test_file.absolute()}"
            self.driver.get(file_url)
            
            # Wait for JavaScript execution
            await asyncio.sleep(2)
            
            # Check current URL
            current_url = self.driver.current_url
            parsed_url = urlparse(current_url)
            is_redirected = self.target_domain in parsed_url.netloc.lower()
            
            if is_redirected:
                screenshot_path = await self._take_screenshot(file_url, payload)
                
                return {
                    'vulnerable': True,
                    'test_url': file_url,
                    'redirect_url': current_url,
                    'payload': payload,
                    'screenshot_path': screenshot_path,
                    'timestamp': time.time()
                }
            else:
                return {
                    'vulnerable': False,
                    'test_url': file_url,
                    'current_url': current_url,
                    'payload': payload,
                    'timestamp': time.time()
                }
                
        except Exception as e:
            self.logger.error(f"Error testing JavaScript redirect: {str(e)}")
            return None
    
    async def test_header_redirect(self, headers: Dict, payload: str) -> Optional[Dict]:
        """Test header-based redirect"""
        try:
            self.logger.info(f"Testing header redirect with payload: {payload}")
            
            # This would require custom HTTP client implementation
            # For now, return placeholder
            return {
                'vulnerable': False,
                'message': 'Header redirect testing not implemented',
                'payload': payload,
                'timestamp': time.time()
            }
            
        except Exception as e:
            self.logger.error(f"Error testing header redirect: {str(e)}")
            return None
    
    async def test_cookie_redirect(self, cookies: Dict, payload: str) -> Optional[Dict]:
        """Test cookie-based redirect"""
        try:
            self.logger.info(f"Testing cookie redirect with payload: {payload}")
            
            # Set cookies
            for cookie_name, cookie_value in cookies.items():
                self.driver.add_cookie({
                    'name': cookie_name,
                    'value': cookie_value.replace('PAYLOAD_PLACEHOLDER', payload),
                    'domain': urlparse(cookies.get('url', '')).netloc
                })
            
            # Navigate to page
            self.driver.get(cookies.get('url', ''))
            
            # Wait for page load
            await asyncio.sleep(2)
            
            # Check current URL
            current_url = self.driver.current_url
            parsed_url = urlparse(current_url)
            is_redirected = self.target_domain in parsed_url.netloc.lower()
            
            if is_redirected:
                screenshot_path = await self._take_screenshot(cookies.get('url', ''), payload)
                
                return {
                    'vulnerable': True,
                    'cookie_url': cookies.get('url', ''),
                    'redirect_url': current_url,
                    'payload': payload,
                    'screenshot_path': screenshot_path,
                    'timestamp': time.time()
                }
            else:
                return {
                    'vulnerable': False,
                    'cookie_url': cookies.get('url', ''),
                    'current_url': current_url,
                    'payload': payload,
                    'timestamp': time.time()
                }
                
        except Exception as e:
            self.logger.error(f"Error testing cookie redirect: {str(e)}")
            return None
    
    async def cleanup(self):
        """Cleanup Chrome driver"""
        try:
            if self.driver:
                self.driver.quit()
                self.logger.info("Chrome driver cleaned up")
        except Exception as e:
            self.logger.error(f"Error cleaning up Chrome driver: {str(e)}")
    
    def _is_valid_redirect(self, url: str) -> bool:
        """Check if URL is a valid redirect to target domain"""
        try:
            parsed = urlparse(url)
            return self.target_domain in parsed.netloc.lower()
        except:
            return False