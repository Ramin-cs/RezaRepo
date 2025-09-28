#!/usr/bin/env python3
"""
Advanced Chrome Automation Module for Open Redirect Scanner
Handles browser automation, redirect testing, and screenshot capture
"""

import asyncio
import os
import time
import logging
import hashlib
import base64
import json
from pathlib import Path
from typing import Dict, Optional, List, Any
from urllib.parse import urlparse, urljoin
import subprocess
import platform

try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.chrome.service import Service
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.webdriver.common.action_chains import ActionChains
    from selenium.webdriver.common.keys import Keys
    from selenium.common.exceptions import TimeoutException, WebDriverException, NoSuchElementException
    from webdriver_manager.chrome import ChromeDriverManager
    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False

class AdvancedChromeModule:
    """
    Advanced Chrome automation module for comprehensive redirect testing
    """
    
    def __init__(self, logger, output_dir: Path, target_domain: str = "google.com"):
        self.logger = logger
        self.output_dir = output_dir
        self.target_domain = target_domain
        self.driver = None
        self.screenshots_dir = output_dir / "screenshots"
        self.screenshots_dir.mkdir(parents=True, exist_ok=True)
        
        # Chrome configuration
        self.chrome_options = None
        self.service = None
        
        # Performance metrics
        self.test_count = 0
        self.success_count = 0
        self.failure_count = 0
        
    async def initialize(self, headless: bool = True, window_size: str = "1920,1080") -> bool:
        """Initialize Chrome driver with advanced configuration"""
        try:
            if not SELENIUM_AVAILABLE:
                self.logger.warning("⚠️ Selenium not available. Chrome automation disabled.")
                return False
            
            self.logger.info("🌐 Initializing Advanced Chrome driver...")
            
            # Setup Chrome options
            self.chrome_options = Options()
            
            if headless:
                self.chrome_options.add_argument("--headless")
            
            # Performance and stability options
            self.chrome_options.add_argument("--no-sandbox")
            self.chrome_options.add_argument("--disable-dev-shm-usage")
            self.chrome_options.add_argument("--disable-gpu")
            self.chrome_options.add_argument("--disable-software-rasterizer")
            self.chrome_options.add_argument("--disable-background-timer-throttling")
            self.chrome_options.add_argument("--disable-backgrounding-occluded-windows")
            self.chrome_options.add_argument("--disable-renderer-backgrounding")
            self.chrome_options.add_argument("--disable-features=TranslateUI")
            self.chrome_options.add_argument("--disable-ipc-flooding-protection")
            
            # Window size
            self.chrome_options.add_argument(f"--window-size={window_size}")
            
            # User agent
            self.chrome_options.add_argument("--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
            
            # Anti-detection options
            self.chrome_options.add_argument("--disable-blink-features=AutomationControlled")
            self.chrome_options.add_experimental_option("excludeSwitches", ["enable-automation"])
            self.chrome_options.add_experimental_option('useAutomationExtension', False)
            
            # Additional options for better performance
            self.chrome_options.add_argument("--disable-extensions")
            self.chrome_options.add_argument("--disable-plugins")
            self.chrome_options.add_argument("--disable-images")
            self.chrome_options.add_argument("--disable-javascript")
            self.chrome_options.add_argument("--disable-css")
            self.chrome_options.add_argument("--disable-web-security")
            self.chrome_options.add_argument("--allow-running-insecure-content")
            self.chrome_options.add_argument("--disable-features=VizDisplayCompositor")
            
            # Memory and performance
            self.chrome_options.add_argument("--memory-pressure-off")
            self.chrome_options.add_argument("--max_old_space_size=4096")
            
            # Network options
            self.chrome_options.add_argument("--aggressive-cache-discard")
            self.chrome_options.add_argument("--disable-background-networking")
            
            # Logging
            self.chrome_options.add_argument("--log-level=3")
            self.chrome_options.add_argument("--silent")
            
            # Initialize driver
            try:
                self.service = Service(ChromeDriverManager().install())
                self.driver = webdriver.Chrome(service=self.service, options=self.chrome_options)
                
                # Execute anti-detection scripts
                self.driver.execute_script("Object.defineProperty(navigator, 'webdriver', {get: () => undefined})")
                self.driver.execute_script("Object.defineProperty(navigator, 'plugins', {get: () => [1, 2, 3, 4, 5]})")
                self.driver.execute_script("Object.defineProperty(navigator, 'languages', {get: () => ['en-US', 'en']})")
                self.driver.execute_script("Object.defineProperty(navigator, 'permissions', {get: () => ({query: () => Promise.resolve({state: 'granted'})})})")
                
                # Set timeouts
                self.driver.set_page_load_timeout(30)
                self.driver.implicitly_wait(10)
                
                self.logger.info("✅ Advanced Chrome driver initialized successfully")
                return True
                
            except Exception as e:
                self.logger.error(f"❌ Chrome driver initialization failed: {str(e)}")
                return False
                
        except Exception as e:
            self.logger.error(f"❌ Chrome initialization failed: {str(e)}")
            return False
    
    async def test_redirect(self, test_url: str, payload: str, timeout: int = 10) -> Optional[Dict]:
        """Test if a URL redirects to target domain with advanced detection"""
        try:
            self.test_count += 1
            self.logger.debug(f"🧪 Testing redirect: {test_url}")
            
            # Navigate to test URL
            self.driver.get(test_url)
            
            # Wait for page to load
            await asyncio.sleep(2)
            
            # Get current URL after potential redirect
            current_url = self.driver.current_url
            
            # Check for redirect patterns
            redirect_detected = await self._detect_redirect_patterns(test_url, current_url, payload)
            
            if redirect_detected['vulnerable']:
                self.success_count += 1
                
                # Take screenshot
                screenshot_path = await self._take_screenshot(test_url, payload, "redirect")
                
                result = {
                    'vulnerable': True,
                    'original_url': test_url,
                    'redirect_url': redirect_detected['redirect_url'],
                    'payload': payload,
                    'screenshot_path': screenshot_path,
                    'detection_method': redirect_detected['method'],
                    'timestamp': time.time(),
                    'test_id': self.test_count
                }
                
                self.logger.info(f"🎯 Redirect vulnerability found: {test_url}")
                return result
            else:
                self.failure_count += 1
                return {
                    'vulnerable': False,
                    'original_url': test_url,
                    'current_url': current_url,
                    'payload': payload,
                    'timestamp': time.time(),
                    'test_id': self.test_count
                }
                
        except Exception as e:
            self.failure_count += 1
            self.logger.error(f"❌ Error testing redirect {test_url}: {str(e)}")
            return None
    
    async def _detect_redirect_patterns(self, original_url: str, current_url: str, payload: str) -> Dict:
        """Detect various redirect patterns"""
        try:
            # Check URL-based redirect
            if self._is_redirect_to_target(current_url):
                return {
                    'vulnerable': True,
                    'redirect_url': current_url,
                    'method': 'URL_redirect'
                }
            
            # Check JavaScript redirects
            js_redirect = await self._check_javascript_redirects()
            if js_redirect['found']:
                return {
                    'vulnerable': True,
                    'redirect_url': js_redirect['url'],
                    'method': 'JavaScript_redirect'
                }
            
            # Check meta refresh redirects
            meta_redirect = await self._check_meta_refresh()
            if meta_redirect['found']:
                return {
                    'vulnerable': True,
                    'redirect_url': meta_redirect['url'],
                    'method': 'Meta_refresh'
                }
            
            # Check iframe redirects
            iframe_redirect = await self._check_iframe_redirects()
            if iframe_redirect['found']:
                return {
                    'vulnerable': True,
                    'redirect_url': iframe_redirect['url'],
                    'method': 'Iframe_redirect'
                }
            
            # Check form redirects
            form_redirect = await self._check_form_redirects()
            if form_redirect['found']:
                return {
                    'vulnerable': True,
                    'redirect_url': form_redirect['url'],
                    'method': 'Form_redirect'
                }
            
            return {
                'vulnerable': False,
                'redirect_url': current_url,
                'method': 'None'
            }
            
        except Exception as e:
            self.logger.error(f"❌ Error detecting redirect patterns: {str(e)}")
            return {
                'vulnerable': False,
                'redirect_url': current_url,
                'method': 'Error'
            }
    
    def _is_redirect_to_target(self, url: str) -> bool:
        """Check if URL redirects to target domain"""
        try:
            parsed = urlparse(url)
            return self.target_domain in parsed.netloc.lower()
        except:
            return False
    
    async def _check_javascript_redirects(self) -> Dict:
        """Check for JavaScript-based redirects"""
        try:
            # Get page source
            page_source = self.driver.page_source
            
            # Check for common redirect patterns
            redirect_patterns = [
                r'window\.location\s*=\s*["\']([^"\']+)["\']',
                r'window\.location\.href\s*=\s*["\']([^"\']+)["\']',
                r'document\.location\s*=\s*["\']([^"\']+)["\']',
                r'location\.href\s*=\s*["\']([^"\']+)["\']',
                r'location\.assign\s*\(\s*["\']([^"\']+)["\']',
                r'location\.replace\s*\(\s*["\']([^"\']+)["\']',
                r'top\.location\s*=\s*["\']([^"\']+)["\']',
                r'parent\.location\s*=\s*["\']([^"\']+)["\']',
                r'self\.location\s*=\s*["\']([^"\']+)["\']'
            ]
            
            import re
            for pattern in redirect_patterns:
                matches = re.findall(pattern, page_source, re.IGNORECASE)
                for match in matches:
                    if self.target_domain in match.lower():
                        return {
                            'found': True,
                            'url': match
                        }
            
            return {'found': False, 'url': None}
            
        except Exception as e:
            self.logger.error(f"❌ Error checking JavaScript redirects: {str(e)}")
            return {'found': False, 'url': None}
    
    async def _check_meta_refresh(self) -> Dict:
        """Check for meta refresh redirects"""
        try:
            # Find meta refresh tags
            meta_tags = self.driver.find_elements(By.CSS_SELECTOR, 'meta[http-equiv="refresh"]')
            
            for meta in meta_tags:
                content = meta.get_attribute('content')
                if content:
                    # Extract URL from refresh content
                    import re
                    url_match = re.search(r'url\s*=\s*([^;]+)', content, re.IGNORECASE)
                    if url_match:
                        redirect_url = url_match.group(1).strip()
                        if self.target_domain in redirect_url.lower():
                            return {
                                'found': True,
                                'url': redirect_url
                            }
            
            return {'found': False, 'url': None}
            
        except Exception as e:
            self.logger.error(f"❌ Error checking meta refresh: {str(e)}")
            return {'found': False, 'url': None}
    
    async def _check_iframe_redirects(self) -> Dict:
        """Check for iframe-based redirects"""
        try:
            # Find iframes
            iframes = self.driver.find_elements(By.TAG_NAME, 'iframe')
            
            for iframe in iframes:
                src = iframe.get_attribute('src')
                if src and self.target_domain in src.lower():
                    return {
                        'found': True,
                        'url': src
                    }
            
            return {'found': False, 'url': None}
            
        except Exception as e:
            self.logger.error(f"❌ Error checking iframe redirects: {str(e)}")
            return {'found': False, 'url': None}
    
    async def _check_form_redirects(self) -> Dict:
        """Check for form-based redirects"""
        try:
            # Find forms
            forms = self.driver.find_elements(By.TAG_NAME, 'form')
            
            for form in forms:
                action = form.get_attribute('action')
                if action and self.target_domain in action.lower():
                    return {
                        'found': True,
                        'url': action
                    }
            
            return {'found': False, 'url': None}
            
        except Exception as e:
            self.logger.error(f"❌ Error checking form redirects: {str(e)}")
            return {'found': False, 'url': None}
    
    async def test_form_redirect(self, form_data: Dict, payload: str) -> Optional[Dict]:
        """Test form-based redirect with advanced interaction"""
        try:
            self.logger.info(f"🧪 Testing form redirect with payload: {payload}")
            
            # Navigate to form page
            self.driver.get(form_data['url'])
            
            # Wait for form to load
            await asyncio.sleep(2)
            
            # Find form
            form = self.driver.find_element(By.TAG_NAME, "form")
            
            # Fill form with payload
            for field_name, field_value in form_data['fields'].items():
                try:
                    field = form.find_element(By.NAME, field_name)
                    field.clear()
                    field.send_keys(payload)
                except NoSuchElementException:
                    continue
            
            # Submit form
            form.submit()
            
            # Wait for redirect
            await asyncio.sleep(3)
            
            # Check for redirect
            redirect_detected = await self._detect_redirect_patterns(
                form_data['url'], 
                self.driver.current_url, 
                payload
            )
            
            if redirect_detected['vulnerable']:
                screenshot_path = await self._take_screenshot(form_data['url'], payload, "form")
                
                return {
                    'vulnerable': True,
                    'form_url': form_data['url'],
                    'redirect_url': redirect_detected['redirect_url'],
                    'payload': payload,
                    'screenshot_path': screenshot_path,
                    'detection_method': redirect_detected['method'],
                    'timestamp': time.time()
                }
            else:
                return {
                    'vulnerable': False,
                    'form_url': form_data['url'],
                    'current_url': self.driver.current_url,
                    'payload': payload,
                    'timestamp': time.time()
                }
                
        except Exception as e:
            self.logger.error(f"❌ Error testing form redirect: {str(e)}")
            return None
    
    async def test_javascript_redirect(self, js_code: str, payload: str) -> Optional[Dict]:
        """Test JavaScript-based redirect"""
        try:
            self.logger.info(f"🧪 Testing JavaScript redirect with payload: {payload}")
            
            # Create test page with JavaScript
            test_page = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>Redirect Test</title>
                <meta charset="UTF-8">
            </head>
            <body>
                <div id="test-area">Testing JavaScript redirect...</div>
                <script>
                    {js_code.replace('PAYLOAD_PLACEHOLDER', payload)}
                </script>
            </body>
            </html>
            """
            
            # Save test page
            test_file = self.output_dir / "js_test_page.html"
            with open(test_file, 'w', encoding='utf-8') as f:
                f.write(test_page)
            
            # Navigate to test page
            file_url = f"file://{test_file.absolute()}"
            self.driver.get(file_url)
            
            # Wait for JavaScript execution
            await asyncio.sleep(2)
            
            # Check for redirect
            redirect_detected = await self._detect_redirect_patterns(
                file_url, 
                self.driver.current_url, 
                payload
            )
            
            if redirect_detected['vulnerable']:
                screenshot_path = await self._take_screenshot(file_url, payload, "javascript")
                
                return {
                    'vulnerable': True,
                    'test_url': file_url,
                    'redirect_url': redirect_detected['redirect_url'],
                    'payload': payload,
                    'screenshot_path': screenshot_path,
                    'detection_method': redirect_detected['method'],
                    'timestamp': time.time()
                }
            else:
                return {
                    'vulnerable': False,
                    'test_url': file_url,
                    'current_url': self.driver.current_url,
                    'payload': payload,
                    'timestamp': time.time()
                }
                
        except Exception as e:
            self.logger.error(f"❌ Error testing JavaScript redirect: {str(e)}")
            return None
    
    async def _take_screenshot(self, test_url: str, payload: str, test_type: str) -> str:
        """Take screenshot of the test result"""
        try:
            # Generate unique filename
            timestamp = int(time.time())
            url_hash = hashlib.md5(test_url.encode()).hexdigest()[:8]
            payload_hash = hashlib.md5(payload.encode()).hexdigest()[:8]
            
            filename = f"{test_type}_redirect_{timestamp}_{url_hash}_{payload_hash}.png"
            screenshot_path = self.screenshots_dir / filename
            
            # Take screenshot
            self.driver.save_screenshot(str(screenshot_path))
            
            self.logger.debug(f"📸 Screenshot saved: {screenshot_path}")
            return str(screenshot_path)
            
        except Exception as e:
            self.logger.error(f"❌ Error taking screenshot: {str(e)}")
            return ""
    
    async def test_cookie_redirect(self, cookies: Dict, payload: str) -> Optional[Dict]:
        """Test cookie-based redirect"""
        try:
            self.logger.info(f"🧪 Testing cookie redirect with payload: {payload}")
            
            # Set cookies
            for cookie_name, cookie_value in cookies.items():
                if cookie_name != 'url':
                    self.driver.add_cookie({
                        'name': cookie_name,
                        'value': cookie_value.replace('PAYLOAD_PLACEHOLDER', payload),
                        'domain': urlparse(cookies.get('url', '')).netloc
                    })
            
            # Navigate to page
            self.driver.get(cookies.get('url', ''))
            
            # Wait for page load
            await asyncio.sleep(2)
            
            # Check for redirect
            redirect_detected = await self._detect_redirect_patterns(
                cookies.get('url', ''), 
                self.driver.current_url, 
                payload
            )
            
            if redirect_detected['vulnerable']:
                screenshot_path = await self._take_screenshot(cookies.get('url', ''), payload, "cookie")
                
                return {
                    'vulnerable': True,
                    'cookie_url': cookies.get('url', ''),
                    'redirect_url': redirect_detected['redirect_url'],
                    'payload': payload,
                    'screenshot_path': screenshot_path,
                    'detection_method': redirect_detected['method'],
                    'timestamp': time.time()
                }
            else:
                return {
                    'vulnerable': False,
                    'cookie_url': cookies.get('url', ''),
                    'current_url': self.driver.current_url,
                    'payload': payload,
                    'timestamp': time.time()
                }
                
        except Exception as e:
            self.logger.error(f"❌ Error testing cookie redirect: {str(e)}")
            return None
    
    def get_performance_metrics(self) -> Dict:
        """Get performance metrics"""
        return {
            'total_tests': self.test_count,
            'successful_tests': self.success_count,
            'failed_tests': self.failure_count,
            'success_rate': (self.success_count / self.test_count * 100) if self.test_count > 0 else 0
        }
    
    async def cleanup(self):
        """Cleanup Chrome driver and resources"""
        try:
            if self.driver:
                self.driver.quit()
                self.logger.info("🧹 Chrome driver cleaned up")
            
            # Log performance metrics
            metrics = self.get_performance_metrics()
            self.logger.info(f"📊 Chrome performance metrics: {metrics}")
            
        except Exception as e:
            self.logger.error(f"❌ Error cleaning up Chrome driver: {str(e)}")
    
    def _is_valid_redirect(self, url: str) -> bool:
        """Check if URL is a valid redirect to target domain"""
        try:
            parsed = urlparse(url)
            return self.target_domain in parsed.netloc.lower()
        except:
            return False