#!/usr/bin/env python3
"""
Router Password Tester - PRECISE VERIFICATION
Accurate detection with proper flow and scoring system
"""

import asyncio
import aiohttp
import time
import argparse
import re
from dataclasses import dataclass
from typing import List, Optional, Tuple
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, WebDriverException
from selenium.webdriver.common.keys import Keys

@dataclass
class TestResult:
    target: str
    password: str
    success: bool
    response_time: float
    method: str
    details: str
    verification_steps: List[str]
    confidence_score: int

class RouterPasswordTester:
    def __init__(self, headless: bool = True):
        self.driver = None
        self.headless = headless
        # Only the 4 passwords you requested
        self.password_list = ["admin", "JAMES1", "admin1", "user"]
        self.setup_chrome()
    
    def setup_chrome(self):
        """Setup Chrome driver with optimized settings"""
        try:
            chrome_options = Options()
            
            if self.headless:
                chrome_options.add_argument('--headless=new')
            
            # Essential options
            chrome_options.add_argument('--no-sandbox')
            chrome_options.add_argument('--disable-dev-shm-usage')
            chrome_options.add_argument('--disable-gpu')
            chrome_options.add_argument('--window-size=1200,800')
            chrome_options.add_argument('--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
            chrome_options.add_argument('--disable-blink-features=AutomationControlled')
            chrome_options.add_experimental_option("excludeSwitches", ["enable-automation"])
            chrome_options.add_experimental_option('useAutomationExtension', False)
            
            # Disable unnecessary features to reduce errors
            chrome_options.add_argument('--disable-extensions')
            chrome_options.add_argument('--disable-plugins-discovery')
            chrome_options.add_argument('--disable-background-timer-throttling')
            chrome_options.add_argument('--disable-backgrounding-occluded-windows')
            chrome_options.add_argument('--disable-renderer-backgrounding')
            chrome_options.add_argument('--disable-features=TranslateUI')
            chrome_options.add_argument('--disable-ipc-flooding-protection')
            
            # Clear session data for fresh start
            chrome_options.add_argument('--disable-web-security')
            chrome_options.add_argument('--disable-features=VizDisplayCompositor')
            
            self.driver = webdriver.Chrome(options=chrome_options)
            self.driver.set_page_load_timeout(20)
            self.driver.implicitly_wait(3)
            
            # Remove webdriver property
            self.driver.execute_script("Object.defineProperty(navigator, 'webdriver', {get: () => undefined})")
            
            print("✅ Chrome driver ready")
            
        except WebDriverException as e:
            print(f"❌ Chrome error: {e}")
            self.driver = None
    
    def clear_session(self, target_url: str):
        """Clear all cookies and session data for fresh start"""
        try:
            print("🧹 Clearing session data...")
            
            # Navigate to target first to set domain
            if not target_url.startswith(('http://', 'https://')):
                url = f"http://{target_url}"
            else:
                url = target_url
            
            self.driver.get(url)
            time.sleep(2)
            
            # Clear all cookies
            self.driver.delete_all_cookies()
            
            # Clear local storage and session storage
            self.driver.execute_script("window.localStorage.clear();")
            self.driver.execute_script("window.sessionStorage.clear();")
            
            # Clear cache (if possible)
            self.driver.execute_script("window.location.reload(true);")
            
            time.sleep(2)
            print("✅ Session cleared")
            
        except Exception as e:
            print(f"⚠️ Session clear error: {e}")
    
    def check_session_cookies(self) -> Tuple[bool, List[str]]:
        """Check for session cookies that indicate successful login"""
        session_indicators = []
        has_session = False
        
        try:
            cookies = self.driver.get_cookies()
            
            # Look for common session cookie names
            session_cookie_names = [
                'sessionid', 'session', 'sid', 'jsessionid',
                'phpsessid', 'aspsessionid', 'auth', 'token',
                'login', 'user', 'admin', 'authenticated'
            ]
            
            for cookie in cookies:
                cookie_name = cookie.get('name', '').lower()
                cookie_value = cookie.get('value', '')
                
                # Check for session cookie names
                for session_name in session_cookie_names:
                    if session_name in cookie_name and cookie_value:
                        has_session = True
                        session_indicators.append(f"Session cookie: {cookie['name']}={cookie_value[:20]}...")
                        break
                
                # Check for non-empty valuable cookies
                if len(cookie_value) > 10 and not cookie_value.startswith('deleted'):
                    session_indicators.append(f"Cookie: {cookie['name']}={cookie_value[:15]}...")
            
            if has_session:
                print(f"✅ Session cookies detected: {len([c for c in cookies if c.get('value')])}")
            
        except Exception as e:
            session_indicators.append(f"Cookie check error: {e}")
        
        return has_session, session_indicators
    
    def close_chrome(self):
        """Close Chrome driver"""
        if self.driver:
            try:
                self.driver.quit()
                print("🔒 Chrome closed")
            except:
                pass
    
    def handle_alerts_and_popups(self):
        """Enhanced popup handling including login confirmation popup"""
        handled = False
        
        try:
            # Handle JavaScript alerts first
            try:
                WebDriverWait(self.driver, 3).until(EC.alert_is_present())
                alert = self.driver.switch_to.alert
                alert_text = alert.text.lower()
                print(f"🚨 Alert detected: {alert_text[:50]}...")
                alert.accept()
                time.sleep(1)
                handled = True
            except TimeoutException:
                pass
            
            # Handle specific login confirmation popup
            login_popup_texts = [
                "only one device can log in at a time",
                "do you want to continue and force",
                "force the other device to log out"
            ]
            
            page_source = self.driver.page_source.lower()
            popup_detected = any(text in page_source for text in login_popup_texts)
            
            if popup_detected:
                print("🔍 Login confirmation popup detected!")
                
                # Look for "Log in" button specifically
                login_button_selectors = [
                    "button:contains('Log in')",
                    "input[value*='Log in']",
                    "button[onclick*='login']",
                    "input[type='button'][value*='Log in']",
                    ".btn:contains('Log in')",
                    "[onclick*='forceLogin']",
                    "[onclick*='force']"
                ]
                
                for selector in login_button_selectors:
                    try:
                        elements = self.driver.find_elements(By.CSS_SELECTOR, selector)
                        for element in elements:
                            if element.is_displayed() and element.is_enabled():
                                element_text = element.text.lower()
                                element_value = element.get_attribute('value')
                                if element_value:
                                    element_value = element_value.lower()
                                
                                if ('log in' in element_text or 
                                    (element_value and 'log in' in element_value) or
                                    'continue' in element_text or
                                    'force' in element_text):
                                    print(f"✅ Clicking login confirmation button: {element_text or element_value}")
                                    element.click()
                                    time.sleep(2)
                                    handled = True
                                    break
                        if handled:
                            break
                    except Exception as e:
                        continue
                
                # Fallback: look for any button with "Log in" text
                if not handled:
                    try:
                        buttons = self.driver.find_elements(By.TAG_NAME, "button")
                        inputs = self.driver.find_elements(By.CSS_SELECTOR, "input[type='button'], input[type='submit']")
                        
                        all_elements = buttons + inputs
                        
                        for element in all_elements:
                            if element.is_displayed() and element.is_enabled():
                                text = element.text.lower()
                                value = element.get_attribute('value')
                                if value:
                                    value = value.lower()
                                
                                if ('log in' in text or 
                                    (value and 'log in' in value) or
                                    'continue' in text or
                                    'force' in text):
                                    print(f"✅ Clicking fallback login button: {text or value}")
                                    element.click()
                                    time.sleep(2)
                                    handled = True
                                    break
                    except Exception as e:
                        print(f"⚠️ Fallback button search error: {e}")
            
            # Handle other modal dialogs
            if not handled:
                popup_selectors = [
                    "button[onclick*='ok']", "button[onclick*='confirm']",
                    "input[type='button'][value*='ok']", "input[type='button'][value*='confirm']",
                    ".modal button", ".popup button", ".dialog button"
                ]
                
                for selector in popup_selectors:
                    try:
                        elements = self.driver.find_elements(By.CSS_SELECTOR, selector)
                        for element in elements:
                            if element.is_displayed() and element.is_enabled():
                                element.click()
                                time.sleep(0.5)
                                handled = True
                                break
                        if handled:
                            break
                    except:
                        continue
                        
        except Exception as e:
            print(f"⚠️ Popup handling error: {e}")
        
        return handled
    
    def wait_for_page_load(self, timeout=15):
        """Wait for page to fully load"""
        try:
            WebDriverWait(self.driver, timeout).until(
                lambda driver: driver.execute_script("return document.readyState") == "complete"
            )
            time.sleep(2)  # Additional wait for dynamic content
            return True
        except TimeoutException:
            print("⚠️ Page load timeout")
            return False
        except Exception as e:
            print(f"⚠️ Page load error: {e}")
            return False
    
    def find_login_elements(self):
        """Find login form elements"""
        password_field = None
        login_button = None
        
        # Find password field (most important)
        password_selectors = [
            "input[type='password']",
            "input[name='password']", "input[name='pass']", "input[name='pwd']",
            "input[id='password']", "input[id='pass']", "input[id='pwd']"
        ]
        
        for selector in password_selectors:
            try:
                element = self.driver.find_element(By.CSS_SELECTOR, selector)
                if element.is_displayed() and element.is_enabled():
                    password_field = element
                    break
            except:
                continue
        
        # Find login button
        button_selectors = [
            "input[type='submit']", "button[type='submit']",
            "input[value*='login']", "input[value*='sign in']", "input[value*='log in']",
            ".login-btn", "#login-btn", ".btn-login", "#loginBtn"
        ]
        
        for selector in button_selectors:
            try:
                elements = self.driver.find_elements(By.CSS_SELECTOR, selector)
                for element in elements:
                    if element.is_displayed() and element.is_enabled():
                        login_button = element
                        break
                if login_button:
                    break
            except:
                continue
        
        # Fallback: find any button with login text
        if not login_button:
            try:
                buttons = self.driver.find_elements(By.TAG_NAME, "button")
                for button in buttons:
                    if button.is_displayed() and button.is_enabled():
                        text = button.text.lower()
                        if any(keyword in text for keyword in ['login', 'log in', 'sign in', 'submit', 'enter']):
                            login_button = button
                            break
            except:
                pass
        
        return password_field, login_button
    
    def analyze_management_panel(self, original_url: str, original_title: str) -> Tuple[bool, str, int, List[str]]:
        """PRECISE analysis of management panel with detailed scoring"""
        verification_steps = []
        confidence_score = 0
        
        try:
            current_url = self.driver.current_url
            current_title = self.driver.title
            page_source = self.driver.page_source.lower()
            
            verification_steps.append(f"Original URL: {original_url}")
            verification_steps.append(f"Current URL: {current_url}")
            verification_steps.append(f"Original Title: {original_title}")
            verification_steps.append(f"Current Title: {current_title}")
            
            print(f"🔍 PRECISE ANALYSIS:")
            print(f"   Original: {original_url}")
            print(f"   Current: {current_url}")
            print(f"   Title: {current_title[:50]}...")
            
            # CRITICAL CHECK 0: Session cookies (Very Important)
            has_session, session_info = self.check_session_cookies()
            if has_session:
                confidence_score += 40  # Big bonus for session
                verification_steps.append("✅ CRITICAL: Session cookies detected")
                verification_steps.extend(session_info[:3])  # Add first 3 cookie info
                print("   ✅ CRITICAL: Session cookies detected")
            else:
                verification_steps.append("⚠️ No session cookies found")
                print("   ⚠️ No session cookies found")
            
            # CRITICAL CHECK 1: Password field should be GONE (Most Important)
            password_field_present = False
            try:
                password_fields = self.driver.find_elements(By.CSS_SELECTOR, "input[type='password']")
                visible_password_fields = [pf for pf in password_fields if pf.is_displayed()]
                
                if visible_password_fields:
                    password_field_present = True
                    confidence_score -= 50  # Heavy penalty
                    verification_steps.append("❌ CRITICAL: Password field still visible")
                    print("   ❌ CRITICAL: Password field still visible")
                else:
                    confidence_score += 30  # Big bonus
                    verification_steps.append("✅ CRITICAL: Password field removed")
                    print("   ✅ CRITICAL: Password field removed")
            except Exception as e:
                verification_steps.append(f"Error checking password fields: {e}")
            
            # CRITICAL CHECK 2: Strong management indicators
            strong_indicators = {
                'logout': 25, 'log out': 25, 'sign out': 25, 'signout': 25,
                'dashboard': 20, 'administration': 20, 'admin panel': 20,
                'management console': 18, 'management panel': 18,
                'configuration': 15, 'system status': 15, 'device status': 15,
                'router status': 15, 'network status': 15, 'wireless settings': 15
            }
            
            strong_found = []
            strong_score = 0
            for indicator, weight in strong_indicators.items():
                count = page_source.count(indicator)
                if count > 0:
                    contribution = weight * min(count, 2)  # Cap at 2 occurrences
                    confidence_score += contribution
                    strong_score += contribution
                    strong_found.append(f"{indicator}({count})")
            
            if strong_found:
                verification_steps.append(f"✅ Strong indicators: {', '.join(strong_found[:3])}")
                print(f"   ✅ Strong indicators: {', '.join(strong_found[:3])}")
            
            # CHECK 3: Medium management indicators
            medium_indicators = {
                'wireless': 10, 'network': 8, 'wan': 8, 'lan': 8, 'wifi': 10,
                'firewall': 8, 'nat': 8, 'dhcp': 8, 'qos': 8, 'vpn': 8,
                'port forwarding': 8, 'access control': 8, 'security': 8,
                'firmware': 6, 'backup': 6, 'restore': 6, 'reboot': 6,
                'router': 5, 'modem': 5, 'gateway': 5, 'settings': 5
            }
            
            medium_found = []
            medium_score = 0
            for indicator, weight in medium_indicators.items():
                count = page_source.count(indicator)
                if count > 0:
                    contribution = weight * min(count, 3)
                    confidence_score += contribution
                    medium_score += contribution
                    medium_found.append(f"{indicator}({count})")
            
            if medium_found:
                verification_steps.append(f"✅ Medium indicators: {', '.join(medium_found[:3])}")
                print(f"   ✅ Medium indicators: {', '.join(medium_found[:3])}")
            
            # CHECK 4: Negative indicators (LOGIN PAGE ELEMENTS)
            negative_indicators = {
                'login': -12, 'sign in': -12, 'please login': -15,
                'username': -8, 'user name': -8, 'enter username': -10,
                'authentication required': -15, 'access denied': -20,
                'invalid password': -20, 'login failed': -20,
                'forgot password': -10, 'remember me': -8,
                'please enter': -8, 'required field': -6
            }
            
            negative_found = []
            negative_score = 0
            for indicator, weight in negative_indicators.items():
                count = page_source.count(indicator)
                if count > 0:
                    contribution = weight * min(count, 2)  # Negative weight
                    confidence_score += contribution
                    negative_score += abs(contribution)
                    negative_found.append(f"{indicator}({count})")
            
            if negative_found:
                verification_steps.append(f"❌ Negative indicators: {', '.join(negative_found[:3])}")
                print(f"   ❌ Negative indicators: {', '.join(negative_found[:3])}")
            
            # CHECK 5: URL and title changes
            url_changed = current_url != original_url
            title_changed = current_title != original_title
            
            if url_changed:
                confidence_score += 20
                verification_steps.append("✅ URL changed (navigation occurred)")
                print("   ✅ URL changed (navigation occurred)")
            
            if title_changed:
                confidence_score += 15
                verification_steps.append("✅ Title changed")
                print("   ✅ Title changed")
            
            # CHECK 6: Specific management page elements
            management_elements = [
                r'<title>[^<]*admin[^<]*</title>',
                r'<title>[^<]*management[^<]*</title>',
                r'<title>[^<]*configuration[^<]*</title>',
                r'<title>[^<]*dashboard[^<]*</title>',
                r'href=["\'][^"\']*logout[^"\']*["\']',
                r'onclick=["\'][^"\']*logout[^"\']*["\']',
                r'<a[^>]*>.*logout.*</a>',
                r'<button[^>]*>.*logout.*</button>'
            ]
            
            element_found = False
            for pattern in management_elements:
                if re.search(pattern, page_source):
                    element_found = True
                    confidence_score += 15
                    break
            
            if element_found:
                verification_steps.append("✅ Management page elements found")
                print("   ✅ Management page elements found")
            
            # FINAL SCORING
            verification_steps.append(f"📊 Final confidence score: {confidence_score}")
            verification_steps.append(f"📊 Strong: {strong_score}, Medium: {medium_score}, Negative: {negative_score}")
            
            print(f"   📊 Final confidence score: {confidence_score}")
            print(f"   📊 Strong: {strong_score}, Medium: {medium_score}, Negative: {negative_score}")
            
            # DECISION LOGIC - Enhanced with session detection
            if password_field_present and not has_session:
                return False, f"LOGIN FAILED - Password field still present, no session (score: {confidence_score})", confidence_score, verification_steps
            elif has_session and confidence_score >= 60:
                return True, f"SESSION CONFIRMED - Management panel access (score: {confidence_score})", confidence_score, verification_steps
            elif confidence_score >= 100:
                return True, f"HIGH CONFIDENCE management panel (score: {confidence_score})", confidence_score, verification_steps
            elif confidence_score >= 80 and strong_score >= 30:
                return True, f"GOOD CONFIDENCE with strong indicators (score: {confidence_score})", confidence_score, verification_steps
            elif confidence_score >= 60 and url_changed and strong_score >= 25:
                return True, f"MODERATE CONFIDENCE with navigation (score: {confidence_score})", confidence_score, verification_steps
            elif has_session and confidence_score >= 40 and strong_score >= 20:
                return True, f"SESSION DETECTED with management indicators (score: {confidence_score})", confidence_score, verification_steps
            elif confidence_score >= 50 and strong_score >= 50 and negative_score <= 30:
                return True, f"STRONG INDICATORS with minimal negatives (score: {confidence_score})", confidence_score, verification_steps
            else:
                return False, f"INSUFFICIENT CONFIDENCE - Likely still on login page (score: {confidence_score})", confidence_score, verification_steps
            
        except Exception as e:
            error_msg = f"Analysis error: {e}"
            verification_steps.append(f"❌ {error_msg}")
            print(f"   ❌ {error_msg}")
            return False, error_msg, 0, verification_steps
    
    def test_password_chrome(self, target: str, password: str) -> TestResult:
        """Test password with Chrome and precise verification"""
        if not self.driver:
            return TestResult(
                target=target,
                password=password,
                success=False,
                response_time=0,
                method="chrome",
                details="Chrome not available",
                verification_steps=["Chrome driver not available"],
                confidence_score=0
            )
        
        start_time = time.time()
        verification_steps = []
        
        try:
            print(f"🔑 Testing password: {password}")
            
            # Step 1: Clear session for fresh start
            if not target.startswith(('http://', 'https://')):
                url = f"http://{target}"
            else:
                url = target
            
            self.clear_session(url)
            
            # Step 2: Load login page
            self.driver.get(url)
            self.wait_for_page_load()
            
            original_url = self.driver.current_url
            original_title = self.driver.title
            verification_steps.append(f"Loaded login page: {original_url}")
            
            # Step 3: Handle initial popups
            self.handle_alerts_and_popups()
            
            # Step 3: Find login elements
            password_field, login_button = self.find_login_elements()
            
            if not password_field:
                verification_steps.append("❌ No password field found")
                return TestResult(
                    target=target,
                    password=password,
                    success=False,
                    response_time=time.time() - start_time,
                    method="chrome",
                    details="No password field found",
                    verification_steps=verification_steps,
                    confidence_score=0
                )
            
            # Step 4: Enter password (skip username as requested)
            password_field.clear()
            password_field.send_keys(password)
            verification_steps.append("Password entered (username skipped)")
            print("   Password entered (username skipped)")
            
            # Step 5: Submit form
            if login_button:
                login_button.click()
                verification_steps.append("Login button clicked")
                print("   Login button clicked")
            else:
                password_field.send_keys(Keys.RETURN)
                verification_steps.append("Form submitted with Enter")
                print("   Form submitted with Enter")
            
            # Step 6: Wait for response and handle popups (CRITICAL)
            print("⏳ Waiting for login response...")
            time.sleep(3)  # Initial wait
            
            # Handle immediate popups (like login confirmation)
            popup_handled = self.handle_alerts_and_popups()
            if popup_handled:
                print("✅ Login popup handled, waiting for navigation...")
                time.sleep(4)  # Wait for navigation after popup
            
            # Additional popup check
            self.handle_alerts_and_popups()
            
            # Wait for page to stabilize
            self.wait_for_page_load(timeout=15)
            time.sleep(2)  # Final wait for dynamic content
            
            # One more popup check after page load
            self.handle_alerts_and_popups()
            
            # Step 7: PRECISE VERIFICATION
            is_management, reason, confidence, verify_steps = self.analyze_management_panel(original_url, original_title)
            verification_steps.extend(verify_steps)
            
            response_time = time.time() - start_time
            
            if is_management:
                print(f"🎉 SUCCESS! Password '{password}' works!")
                print(f"   Reason: {reason}")
                
                return TestResult(
                    target=target,
                    password=password,
                    success=True,
                    response_time=response_time,
                    method="chrome",
                    details=reason,
                    verification_steps=verification_steps,
                    confidence_score=confidence
                )
            else:
                print(f"❌ Failed: {reason}")
                
                return TestResult(
                    target=target,
                    password=password,
                    success=False,
                    response_time=response_time,
                    method="chrome",
                    details=reason,
                    verification_steps=verification_steps,
                    confidence_score=confidence
                )
            
        except Exception as e:
            response_time = time.time() - start_time
            error_msg = f"Test error: {str(e)}"
            verification_steps.append(error_msg)
            
            print(f"❌ Error: {error_msg}")
            
            return TestResult(
                target=target,
                password=password,
                success=False,
                response_time=response_time,
                method="chrome",
                details=error_msg,
                verification_steps=verification_steps,
                confidence_score=0
            )
    
    async def test_password_http(self, target: str, password: str) -> TestResult:
        """Test password using HTTP (quick check)"""
        start_time = time.time()
        
        try:
            if not target.startswith(('http://', 'https://')):
                url = f"http://{target}"
            else:
                url = target
            
            timeout = aiohttp.ClientTimeout(total=10)
            
            async with aiohttp.ClientSession(timeout=timeout) as session:
                # Try password-only login
                login_data = {'password': password}
                
                try:
                    async with session.post(url, data=login_data, ssl=False, allow_redirects=True) as response:
                        final_url = str(response.url)
                        response_text = await response.text()
                        response_lower = response_text.lower()
                        
                        # Quick analysis
                        management_count = sum(1 for indicator in ['logout', 'dashboard', 'management', 'configuration'] 
                                             if indicator in response_lower)
                        login_count = sum(1 for indicator in ['password', 'login', 'sign in'] 
                                        if indicator in response_lower)
                        
                        url_changed = final_url.lower() != url.lower()
                        
                        # Simple success criteria for HTTP
                        success = (url_changed and management_count >= 2 and login_count <= 2)
                        
                        response_time = time.time() - start_time
                        
                        if success:
                            return TestResult(
                                target=target,
                                password=password,
                                success=True,
                                response_time=response_time,
                                method="http",
                                details=f"HTTP success: Management={management_count}, Login={login_count}, URL_changed={url_changed}",
                                verification_steps=[f"HTTP quick check passed"],
                                confidence_score=50
                            )
                        else:
                            return TestResult(
                                target=target,
                                password=password,
                                success=False,
                                response_time=response_time,
                                method="http",
                                details=f"HTTP failed: Management={management_count}, Login={login_count}, URL_changed={url_changed}",
                                verification_steps=[f"HTTP quick check failed"],
                                confidence_score=0
                            )
                            
                except Exception as e:
                    response_time = time.time() - start_time
                    return TestResult(
                        target=target,
                        password=password,
                        success=False,
                        response_time=response_time,
                        method="http",
                        details=f"HTTP error: {str(e)}",
                        verification_steps=[f"HTTP error: {str(e)}"],
                        confidence_score=0
                    )
                    
        except Exception as e:
            response_time = time.time() - start_time
            return TestResult(
                target=target,
                password=password,
                success=False,
                response_time=response_time,
                method="http",
                details=f"HTTP error: {str(e)}",
                verification_steps=[f"HTTP error: {str(e)}"],
                confidence_score=0
            )
    
    async def test_target(self, target: str, mode: str = "both"):
        """Test all passwords on target with proper flow"""
        print(f"\n🎯 Testing target: {target}")
        print(f"🔐 Passwords to test: {self.password_list}")
        print(f"🎮 Mode: {mode}")
        print("-" * 50)
        
        results = []
        
        for i, password in enumerate(self.password_list, 1):
            print(f"\n[{i}/{len(self.password_list)}] Testing password: {password}")
            
            success = False
            
            # Try HTTP first (faster, but less reliable)
            if mode in ["http", "both"]:
                print("   🌐 HTTP test...")
                result = await self.test_password_http(target, password)
                results.append(result)
                
                if result.success:
                    print(f"   🎉 HTTP indicates possible success")
                    # Don't stop here, verify with Chrome
                    success = True
            
            # Always use Chrome for final verification (most reliable)
            if mode in ["chrome", "both"]:
                print("   🔍 Chrome test...")
                result = self.test_password_chrome(target, password)
                results.append(result)
                
                if result.success:
                    print(f"🎉 PASSWORD FOUND: {password}")
                    print(f"   Confidence: {result.confidence_score}")
                    print(f"   Details: {result.details}")
                    print("🛑 STOPPING - Password verified with management panel access!")
                    return results
            
            print(f"   ❌ Password '{password}' failed")
            
            # Small delay between passwords
            await asyncio.sleep(0.5)
        
        print("❌ No working password found")
        return results

def main():
    print("🚀 ROUTER PASSWORD TESTER")
    print("=" * 40)
    print("Password-only mode (no username)")
    print("Stops immediately after finding correct password")
    print("=" * 40)
    
    parser = argparse.ArgumentParser(description='Router Password Tester')
    parser.add_argument('--target', '-t', required=True, help='Target IP or URL')
    parser.add_argument('--mode', '-m', choices=['http', 'chrome', 'both'], 
                       default='both', help='Test mode (default: both)')
    parser.add_argument('--visible', '-v', action='store_true', help='Show Chrome browser')
    
    args = parser.parse_args()
    
    print(f"🎯 Target: {args.target}")
    print(f"🎮 Mode: {args.mode}")
    
    tester = RouterPasswordTester(headless=not args.visible)
    
    try:
        results = asyncio.run(tester.test_target(args.target, args.mode))
        
        # Show final results
        print("\n" + "=" * 50)
        print("FINAL RESULTS")
        print("=" * 50)
        
        successful = [r for r in results if r.success]
        
        if successful:
            # Show the Chrome result (most reliable)
            chrome_results = [r for r in successful if r.method == "chrome"]
            if chrome_results:
                result = chrome_results[0]
                print(f"🎉 SUCCESS!")
                print(f"Target: {result.target}")
                print(f"Password: {result.password}")
                print(f"Method: {result.method}")
                print(f"Confidence: {result.confidence_score}")
                print(f"Time: {result.response_time:.1f}s")
                print(f"Details: {result.details}")
            else:
                result = successful[0]
                print(f"🎉 SUCCESS!")
                print(f"Target: {result.target}")
                print(f"Password: {result.password}")
                print(f"Method: {result.method}")
                print(f"Time: {result.response_time:.1f}s")
                print(f"Details: {result.details}")
        else:
            print("❌ No working password found")
            print("💡 Make sure:")
            print("   - Target is accessible")
            print("   - Target has a web login interface")
            print("   - One of the 4 passwords is correct")
        
        print(f"\nTotal tests: {len(results)}")
        
    except KeyboardInterrupt:
        print("\n⚠️ Testing interrupted by user")
    except Exception as e:
        print(f"❌ Error: {e}")
    finally:
        tester.close_chrome()

if __name__ == "__main__":
    main()