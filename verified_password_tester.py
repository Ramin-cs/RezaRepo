#!/usr/bin/env python3
"""
Verified Password Tester - REAL LOGIN VERIFICATION
Always uses Chrome to actually login and verify management panel access
"""

import asyncio
import time
import argparse
from dataclasses import dataclass
from typing import List, Optional
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
    details: str
    verification_steps: List[str]

class VerifiedPasswordTester:
    def __init__(self, headless: bool = True):
        self.driver = None
        self.headless = headless
        # Only the 4 passwords you requested
        self.password_list = ["admin", "JAMES1", "admin1", "user"]
        self.setup_chrome()
    
    def setup_chrome(self):
        """Setup Chrome driver for real verification"""
        try:
            chrome_options = Options()
            
            if self.headless:
                chrome_options.add_argument('--headless=new')
            
            chrome_options.add_argument('--no-sandbox')
            chrome_options.add_argument('--disable-dev-shm-usage')
            chrome_options.add_argument('--disable-gpu')
            chrome_options.add_argument('--window-size=1200,800')
            chrome_options.add_argument('--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36')
            chrome_options.add_argument('--disable-blink-features=AutomationControlled')
            chrome_options.add_experimental_option("excludeSwitches", ["enable-automation"])
            chrome_options.add_experimental_option('useAutomationExtension', False)
            
            self.driver = webdriver.Chrome(options=chrome_options)
            self.driver.set_page_load_timeout(20)
            self.driver.implicitly_wait(5)
            
            # Remove webdriver property
            self.driver.execute_script("Object.defineProperty(navigator, 'webdriver', {get: () => undefined})")
            
            print("✅ Chrome driver ready for REAL verification")
            
        except WebDriverException as e:
            print(f"❌ Chrome error: {e}")
            self.driver = None
    
    def close_chrome(self):
        """Close Chrome driver"""
        if self.driver:
            try:
                self.driver.quit()
                print("🔒 Chrome closed")
            except:
                pass
    
    def handle_alerts_and_popups(self):
        """Handle any alerts or popups"""
        try:
            # Handle JavaScript alerts
            try:
                WebDriverWait(self.driver, 2).until(EC.alert_is_present())
                alert = self.driver.switch_to.alert
                print(f"🚨 Alert detected: {alert.text[:50]}...")
                alert.accept()
                time.sleep(1)
                return True
            except TimeoutException:
                pass
            
            # Handle modal dialogs
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
                            return True
                except:
                    continue
                    
        except Exception as e:
            print(f"⚠️ Popup handling error: {e}")
        
        return False
    
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
        username_field = None
        password_field = None
        login_button = None
        
        # Find password field (most important)
        password_selectors = [
            "input[type='password']",
            "input[name='password']", "input[name='pass']", "input[name='pwd']",
            "input[id='password']", "input[id='pass']", "input[id='pwd']",
            "input[placeholder*='password']", "input[class*='password']"
        ]
        
        for selector in password_selectors:
            try:
                element = self.driver.find_element(By.CSS_SELECTOR, selector)
                if element.is_displayed() and element.is_enabled():
                    password_field = element
                    break
            except:
                continue
        
        # Find username field (optional)
        username_selectors = [
            "input[name='username']", "input[name='user']", "input[name='login']",
            "input[id='username']", "input[id='user']", "input[id='login']",
            "input[type='text']:first-of-type"
        ]
        
        for selector in username_selectors:
            try:
                element = self.driver.find_element(By.CSS_SELECTOR, selector)
                if element.is_displayed() and element.is_enabled():
                    username_field = element
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
        
        return username_field, password_field, login_button
    
    def verify_management_panel(self, original_url: str, original_title: str) -> tuple[bool, str, List[str]]:
        """STRICT verification of management panel access"""
        verification_steps = []
        
        try:
            current_url = self.driver.current_url
            current_title = self.driver.title
            page_source = self.driver.page_source.lower()
            
            verification_steps.append(f"Original URL: {original_url}")
            verification_steps.append(f"Current URL: {current_url}")
            verification_steps.append(f"Original Title: {original_title}")
            verification_steps.append(f"Current Title: {current_title}")
            
            print(f"🔍 STRICT VERIFICATION:")
            print(f"   Original URL: {original_url}")
            print(f"   Current URL: {current_url}")
            print(f"   Title: {current_title[:60]}...")
            
            # CRITICAL CHECK 1: Password field should be GONE
            try:
                password_fields = self.driver.find_elements(By.CSS_SELECTOR, "input[type='password']")
                visible_password_fields = [pf for pf in password_fields if pf.is_displayed()]
                
                if visible_password_fields:
                    verification_steps.append("❌ Password field still visible")
                    print("❌ FAILED: Password field still visible - login failed")
                    return False, "Password field still present - login failed", verification_steps
                else:
                    verification_steps.append("✅ Password field removed")
                    print("✅ Password field removed - good sign")
            except Exception as e:
                verification_steps.append(f"Error checking password fields: {e}")
            
            # CRITICAL CHECK 2: Look for STRONG management indicators
            strong_management_indicators = [
                'logout', 'log out', 'sign out', 'signout',
                'dashboard', 'administration', 'admin panel',
                'management', 'configuration', 'settings',
                'system status', 'device status', 'router status'
            ]
            
            medium_management_indicators = [
                'wireless', 'network', 'wan', 'lan', 'wifi',
                'firewall', 'nat', 'dhcp', 'qos', 'vpn',
                'port forwarding', 'access control', 'security',
                'firmware', 'backup', 'restore', 'reboot'
            ]
            
            # Count strong indicators
            strong_count = 0
            found_strong = []
            for indicator in strong_management_indicators:
                if indicator in page_source:
                    strong_count += 1
                    found_strong.append(indicator)
            
            # Count medium indicators
            medium_count = 0
            found_medium = []
            for indicator in medium_management_indicators:
                if indicator in page_source:
                    medium_count += 1
                    found_medium.append(indicator)
            
            # Count negative indicators (login page elements)
            negative_indicators = [
                'enter password', 'password required', 'login required',
                'sign in', 'please login', 'authentication required'
            ]
            
            negative_count = 0
            found_negative = []
            for indicator in negative_indicators:
                if indicator in page_source:
                    negative_count += 1
                    found_negative.append(indicator)
            
            verification_steps.append(f"Strong indicators: {strong_count} ({found_strong[:3]})")
            verification_steps.append(f"Medium indicators: {medium_count} ({found_medium[:3]})")
            verification_steps.append(f"Negative indicators: {negative_count} ({found_negative})")
            
            print(f"   Strong management indicators: {strong_count}")
            print(f"   Found: {found_strong[:3]}")
            print(f"   Medium management indicators: {medium_count}")
            print(f"   Found: {found_medium[:3]}")
            print(f"   Negative indicators: {negative_count}")
            
            # CRITICAL CHECK 3: URL or title change
            url_changed = current_url != original_url
            title_changed = current_title != original_title
            
            verification_steps.append(f"URL changed: {url_changed}")
            verification_steps.append(f"Title changed: {title_changed}")
            
            print(f"   URL changed: {url_changed}")
            print(f"   Title changed: {title_changed}")
            
            # STRICT DECISION LOGIC
            # Rule 1: Must have at least 2 strong indicators OR 4+ medium indicators
            has_strong_indicators = strong_count >= 2 or medium_count >= 4
            
            # Rule 2: Must have URL or title change (shows navigation happened)
            has_navigation = url_changed or title_changed
            
            # Rule 3: Must not have negative indicators
            no_negative_indicators = negative_count == 0
            
            print(f"   Has strong indicators: {has_strong_indicators}")
            print(f"   Has navigation: {has_navigation}")
            print(f"   No negative indicators: {no_negative_indicators}")
            
            # FINAL DECISION
            if has_strong_indicators and has_navigation and no_negative_indicators:
                reason = f"VERIFIED: Strong indicators={strong_count}, Medium={medium_count}, Navigation=True, Clean=True"
                verification_steps.append(f"✅ {reason}")
                print(f"✅ {reason}")
                return True, reason, verification_steps
            
            elif strong_count >= 3 and no_negative_indicators:  # Very strong indicators even without navigation
                reason = f"VERIFIED: Very strong indicators={strong_count}, Clean=True"
                verification_steps.append(f"✅ {reason}")
                print(f"✅ {reason}")
                return True, reason, verification_steps
            
            else:
                reason = f"FAILED: Insufficient evidence - Strong={strong_count}, Medium={medium_count}, Navigation={has_navigation}, Negative={negative_count}"
                verification_steps.append(f"❌ {reason}")
                print(f"❌ {reason}")
                return False, reason, verification_steps
            
        except Exception as e:
            error_msg = f"Verification error: {e}"
            verification_steps.append(f"❌ {error_msg}")
            print(f"❌ {error_msg}")
            return False, error_msg, verification_steps
    
    def test_password_real_verification(self, target: str, password: str) -> TestResult:
        """Test password with REAL Chrome verification"""
        if not self.driver:
            return TestResult(
                target=target,
                password=password,
                success=False,
                response_time=0,
                details="Chrome not available",
                verification_steps=["Chrome driver not available"]
            )
        
        start_time = time.time()
        verification_steps = []
        
        try:
            print(f"\n🔑 REAL VERIFICATION TEST: {password}")
            print("=" * 50)
            
            # Prepare URL
            if not target.startswith(('http://', 'https://')):
                url = f"http://{target}"
            else:
                url = target
            
            # Step 1: Load login page
            print("📄 Step 1: Loading login page...")
            self.driver.get(url)
            self.wait_for_page_load()
            
            original_url = self.driver.current_url
            original_title = self.driver.title
            verification_steps.append(f"Loaded login page: {original_url}")
            
            print(f"   Login page loaded: {original_url}")
            print(f"   Title: {original_title[:50]}...")
            
            # Step 2: Handle initial popups
            self.handle_alerts_and_popups()
            
            # Step 3: Find login elements
            print("🔍 Step 2: Finding login elements...")
            username_field, password_field, login_button = self.find_login_elements()
            
            if not password_field:
                verification_steps.append("❌ No password field found")
                return TestResult(
                    target=target,
                    password=password,
                    success=False,
                    response_time=time.time() - start_time,
                    details="No password field found",
                    verification_steps=verification_steps
                )
            
            print("   ✅ Password field found")
            if username_field:
                print("   ⚠️ Username field found but will be skipped")
            if login_button:
                print("   ✅ Login button found")
            
            # Step 4: Enter password (skip username as requested)
            print("🔐 Step 3: Entering password...")
            password_field.clear()
            password_field.send_keys(password)
            verification_steps.append(f"Password entered: {password}")
            print(f"   Password '{password}' entered")
            
            # Step 5: Submit form
            print("📤 Step 4: Submitting login form...")
            if login_button:
                login_button.click()
                verification_steps.append("Login button clicked")
                print("   Login button clicked")
            else:
                password_field.send_keys(Keys.RETURN)
                verification_steps.append("Form submitted with Enter key")
                print("   Form submitted with Enter key")
            
            # Step 6: Wait for response
            print("⏳ Step 5: Waiting for login response...")
            time.sleep(4)  # Wait for login processing
            
            # Handle post-login popups
            self.handle_alerts_and_popups()
            
            # Wait for page to stabilize
            self.wait_for_page_load(timeout=10)
            time.sleep(2)  # Additional wait
            
            # Step 7: STRICT VERIFICATION
            print("🔍 Step 6: STRICT MANAGEMENT PANEL VERIFICATION...")
            is_management, reason, verify_steps = self.verify_management_panel(original_url, original_title)
            verification_steps.extend(verify_steps)
            
            response_time = time.time() - start_time
            
            if is_management:
                print(f"\n🎉 REAL LOGIN SUCCESS!")
                print(f"   Target: {target}")
                print(f"   Password: {password}")
                print(f"   Verification: {reason}")
                print(f"   Time: {response_time:.1f}s")
                print("=" * 50)
                
                return TestResult(
                    target=target,
                    password=password,
                    success=True,
                    response_time=response_time,
                    details=reason,
                    verification_steps=verification_steps
                )
            else:
                print(f"\n❌ LOGIN FAILED!")
                print(f"   Password: {password}")
                print(f"   Reason: {reason}")
                print(f"   Time: {response_time:.1f}s")
                print("=" * 50)
                
                return TestResult(
                    target=target,
                    password=password,
                    success=False,
                    response_time=response_time,
                    details=reason,
                    verification_steps=verification_steps
                )
            
        except Exception as e:
            response_time = time.time() - start_time
            error_msg = f"Test error: {str(e)}"
            verification_steps.append(error_msg)
            
            print(f"\n❌ TEST ERROR!")
            print(f"   Password: {password}")
            print(f"   Error: {error_msg}")
            print("=" * 50)
            
            return TestResult(
                target=target,
                password=password,
                success=False,
                response_time=response_time,
                details=error_msg,
                verification_steps=verification_steps
            )
    
    def test_target(self, target: str):
        """Test all passwords with REAL verification"""
        print(f"\n🎯 REAL VERIFICATION TESTING")
        print(f"Target: {target}")
        print(f"Passwords: {self.password_list}")
        print("=" * 60)
        
        results = []
        
        for i, password in enumerate(self.password_list, 1):
            print(f"\n[{i}/{len(self.password_list)}] TESTING PASSWORD: {password}")
            
            result = self.test_password_real_verification(target, password)
            results.append(result)
            
            if result.success:
                print(f"\n🎉 PASSWORD FOUND AND VERIFIED: {password}")
                print("🛑 STOPPING TESTS - Management panel access confirmed!")
                break
            
            print(f"❌ Password '{password}' failed verification")
            
            # Brief pause between tests
            time.sleep(1)
        
        return results

def main():
    print("🚀 VERIFIED PASSWORD TESTER")
    print("=" * 50)
    print("REAL Chrome verification - Actually logs in and verifies management panel")
    print("=" * 50)
    
    parser = argparse.ArgumentParser(description='Verified Password Tester with Real Login')
    parser.add_argument('--target', '-t', required=True, help='Target IP or URL')
    parser.add_argument('--visible', '-v', action='store_true', help='Show Chrome browser (not headless)')
    
    args = parser.parse_args()
    
    print(f"🎯 Target: {args.target}")
    print(f"👁️ Visible: {args.visible}")
    
    tester = VerifiedPasswordTester(headless=not args.visible)
    
    if not tester.driver:
        print("❌ Chrome driver not available")
        return
    
    try:
        results = tester.test_target(args.target)
        
        # Final results
        print("\n" + "=" * 60)
        print("FINAL VERIFICATION RESULTS")
        print("=" * 60)
        
        successful = [r for r in results if r.success]
        
        if successful:
            result = successful[0]
            print(f"🎉 REAL LOGIN SUCCESS VERIFIED!")
            print(f"Target: {result.target}")
            print(f"Password: {result.password}")
            print(f"Verification: {result.details}")
            print(f"Time: {result.response_time:.1f}s")
            print(f"Total verification steps: {len(result.verification_steps)}")
            
            print(f"\n📋 Verification Steps:")
            for step in result.verification_steps[-5:]:  # Show last 5 steps
                print(f"   {step}")
        else:
            print("❌ NO VALID PASSWORD FOUND")
            print("💡 All passwords failed REAL verification")
            print("   This means none of the passwords actually provide")
            print("   access to the management panel")
        
        print(f"\nTotal tests performed: {len(results)}")
        
    except KeyboardInterrupt:
        print("\n⚠️ Testing interrupted by user")
    except Exception as e:
        print(f"❌ Error: {e}")
    finally:
        tester.close_chrome()

if __name__ == "__main__":
    main()