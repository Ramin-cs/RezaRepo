#!/usr/bin/env python3
"""
Patient Router Password Tester - FOR SLOW SITES
Extra patient version with very long timeouts
"""

import asyncio
import time
import argparse
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
    details: str
    confidence_score: int

class PatientRouterTester:
    def __init__(self, headless: bool = True):
        self.driver = None
        self.headless = headless
        self.password_list = ["admin", "JAMES1", "admin1", "user"]
        self.setup_chrome()
    
    def setup_chrome(self):
        """Setup Chrome with VERY patient settings"""
        try:
            chrome_options = Options()
            
            if self.headless:
                chrome_options.add_argument('--headless=new')
            
            # Patient settings
            chrome_options.add_argument('--no-sandbox')
            chrome_options.add_argument('--disable-dev-shm-usage')
            chrome_options.add_argument('--disable-gpu')
            chrome_options.add_argument('--window-size=1200,800')
            chrome_options.add_argument('--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
            
            # Disable things that might cause timeouts
            chrome_options.add_argument('--disable-extensions')
            chrome_options.add_argument('--disable-plugins')
            chrome_options.add_argument('--disable-images')  # Faster loading
            chrome_options.add_argument('--disable-javascript')  # Disable JS for faster loading
            chrome_options.add_argument('--disable-web-security')
            chrome_options.add_argument('--disable-features=VizDisplayCompositor')
            
            # Reduce logging
            chrome_options.add_argument('--log-level=3')
            chrome_options.add_argument('--silent')
            chrome_options.add_experimental_option('excludeSwitches', ['enable-logging'])
            chrome_options.add_experimental_option('useAutomationExtension', False)
            
            self.driver = webdriver.Chrome(options=chrome_options)
            
            # VERY patient timeouts
            self.driver.set_page_load_timeout(120)  # 2 minutes!
            self.driver.implicitly_wait(15)  # 15 seconds implicit wait
            
            print("✅ Patient Chrome driver ready (120s timeout)")
            
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
    
    def patient_wait(self, message: str, seconds: int):
        """Patient waiting with countdown"""
        print(f"⏳ {message} (waiting {seconds}s)")
        for i in range(seconds, 0, -5):
            print(f"   ⏳ {i}s remaining...")
            time.sleep(5)
        print(f"   ✅ Wait complete")
    
    def wait_for_page_load(self, timeout=90):
        """VERY patient page loading"""
        try:
            print(f"⏳ Waiting patiently for page to load (up to {timeout}s)...")
            
            # Wait for document ready
            WebDriverWait(self.driver, timeout).until(
                lambda driver: driver.execute_script("return document.readyState") == "complete"
            )
            print("   ✅ Document ready state achieved")
            
            # Extra patient wait for dynamic content
            self.patient_wait("Waiting for dynamic content", 10)
            
            return True
                
        except TimeoutException:
            print(f"   ⚠️ Page load timeout after {timeout}s, but continuing...")
            return False
        except Exception as e:
            print(f"   ⚠️ Page load error: {e}, but continuing...")
            return False
    
    def find_login_elements_patient(self, timeout=60):
        """VERY patient element detection"""
        password_field = None
        login_button = None
        
        print("🔍 Patiently looking for login elements...")
        
        # Wait VERY patiently for password field
        password_selectors = [
            "input[type='password']",
            "input[name='password']", 
            "input[name='pass']", 
            "input[name='pwd']"
        ]
        
        for selector in password_selectors:
            try:
                print(f"   ⏳ Waiting up to {timeout}s for: {selector}")
                element = WebDriverWait(self.driver, timeout).until(
                    EC.presence_of_element_located((By.CSS_SELECTOR, selector))
                )
                
                # Additional wait for element to be ready
                time.sleep(3)
                
                if element.is_displayed() and element.is_enabled():
                    password_field = element
                    print(f"   ✅ Password field found and ready: {selector}")
                    break
                else:
                    print(f"   ⚠️ Password field found but not ready: {selector}")
                    
            except TimeoutException:
                print(f"   ❌ Timeout waiting for: {selector}")
                continue
            except Exception as e:
                print(f"   ⚠️ Error with {selector}: {e}")
                continue
        
        # If password field found, look for login button
        if password_field:
            print("🔍 Looking for login button...")
            
            # Wait a bit more for button to appear
            time.sleep(5)
            
            button_selectors = [
                "input[type='submit']", 
                "button[type='submit']",
                "input[value*='login']", 
                "input[value*='Login']", 
                "button"
            ]
            
            for selector in button_selectors:
                try:
                    elements = self.driver.find_elements(By.CSS_SELECTOR, selector)
                    for element in elements:
                        if element.is_displayed() and element.is_enabled():
                            text = element.text.lower() if element.text else ""
                            value = element.get_attribute('value')
                            if value:
                                value = value.lower()
                            
                            if (selector in ["input[type='submit']", "button[type='submit']"] or
                                'login' in text or 'log in' in text or
                                (value and ('login' in value or 'log in' in value))):
                                login_button = element
                                print(f"   ✅ Login button found: {text or value or selector}")
                                break
                    if login_button:
                        break
                except Exception as e:
                    continue
        
        if not password_field:
            print("   ❌ No password field found after patient waiting")
        if not login_button:
            print("   ⚠️ No login button found (will use Enter key)")
        
        return password_field, login_button
    
    def handle_login_popup_patient(self):
        """Patient popup handling"""
        handled = False
        
        try:
            # Wait a bit for popup to appear
            time.sleep(3)
            
            page_source = self.driver.page_source.lower()
            
            if "only one device can log in at a time" in page_source:
                print("🔍 Login confirmation popup detected!")
                
                # Look for buttons patiently
                buttons = self.driver.find_elements(By.TAG_NAME, "button")
                inputs = self.driver.find_elements(By.CSS_SELECTOR, "input[type='button'], input[type='submit']")
                
                all_elements = buttons + inputs
                
                for element in all_elements:
                    try:
                        if element.is_displayed() and element.is_enabled():
                            text = element.text.lower()
                            value = element.get_attribute('value')
                            if value:
                                value = value.lower()
                            
                            if ('log in' in text or 
                                (value and 'log in' in value) or
                                'continue' in text or
                                'force' in text):
                                print(f"✅ Clicking login confirmation: {text or value}")
                                element.click()
                                self.patient_wait("Waiting after popup click", 8)
                                handled = True
                                break
                    except Exception:
                        continue
            
            # Handle JavaScript alerts
            try:
                WebDriverWait(self.driver, 5).until(EC.alert_is_present())
                alert = self.driver.switch_to.alert
                print(f"🚨 Alert: {alert.text[:30]}...")
                alert.accept()
                time.sleep(3)
                handled = True
            except TimeoutException:
                pass
                
        except Exception as e:
            print(f"⚠️ Popup handling error: {e}")
        
        return handled
    
    def check_management_panel_patient(self, original_url: str) -> Tuple[bool, str, int]:
        """Patient management panel detection"""
        try:
            current_url = self.driver.current_url
            page_source = self.driver.page_source.lower()
            
            print(f"🔍 Patient analysis:")
            print(f"   Original: {original_url}")
            print(f"   Current: {current_url}")
            
            score = 0
            
            # Check 1: Password field gone?
            try:
                password_fields = self.driver.find_elements(By.CSS_SELECTOR, "input[type='password']")
                visible_fields = [pf for pf in password_fields if pf.is_displayed()]
                
                if visible_fields:
                    score -= 50
                    print("   ❌ Password field still visible")
                else:
                    score += 50
                    print("   ✅ Password field removed")
            except:
                pass
            
            # Check 2: Management indicators
            management_words = ['logout', 'dashboard', 'administration', 'wireless', 'network', 'status']
            found_management = []
            
            for word in management_words:
                count = page_source.count(word)
                if count > 0:
                    score += count * 8
                    found_management.append(f"{word}({count})")
            
            if found_management:
                print(f"   ✅ Management indicators: {', '.join(found_management[:3])}")
            
            # Check 3: URL change
            if current_url != original_url:
                score += 25
                print("   ✅ URL changed")
            
            print(f"   📊 Final score: {score}")
            
            # Patient decision
            if score >= 40:
                return True, f"Management panel detected (score: {score})", score
            else:
                return False, f"Still on login page (score: {score})", score
                
        except Exception as e:
            return False, f"Analysis error: {e}", 0
    
    def test_password_patient(self, target: str, password: str) -> TestResult:
        """VERY patient password testing"""
        if not self.driver:
            return TestResult(target, password, False, 0, "Chrome not available", 0)
        
        start_time = time.time()
        
        try:
            print(f"\n🔑 Patiently testing password: {password}")
            print("=" * 60)
            
            # Prepare URL
            if not target.startswith(('http://', 'https://')):
                url = f"http://{target}"
            else:
                url = target
            
            # Load page VERY patiently
            print("📄 Loading login page (this may take a while)...")
            self.driver.get(url)
            self.wait_for_page_load(timeout=120)  # 2 minutes!
            
            original_url = self.driver.current_url
            print(f"✅ Page loaded: {original_url}")
            
            # Find login elements VERY patiently
            password_field, login_button = self.find_login_elements_patient(timeout=90)
            
            if not password_field:
                return TestResult(target, password, False, time.time() - start_time, 
                                "No password field found after patient waiting", 0)
            
            # Enter password
            print("🔐 Entering password...")
            password_field.clear()
            time.sleep(2)
            password_field.send_keys(password)
            time.sleep(2)
            print("   ✅ Password entered")
            
            # Submit form
            if login_button:
                print("🖱️ Clicking login button...")
                login_button.click()
                print("   ✅ Login button clicked")
            else:
                print("⌨️ Pressing Enter...")
                password_field.send_keys(Keys.RETURN)
                print("   ✅ Enter pressed")
            
            # VERY patient waiting for response
            self.patient_wait("Waiting for server response", 15)
            
            # Check for popup multiple times
            for i in range(5):
                popup_handled = self.handle_login_popup_patient()
                if popup_handled:
                    print(f"✅ Login popup handled (attempt {i+1})")
                    break
                time.sleep(3)
            
            # Wait for page to stabilize after login
            print("⏳ Waiting for management page to load...")
            self.wait_for_page_load(timeout=90)
            self.patient_wait("Final wait for page stabilization", 10)
            
            # Check result
            is_management, reason, confidence = self.check_management_panel_patient(original_url)
            
            response_time = time.time() - start_time
            
            if is_management:
                print(f"🎉 SUCCESS! Password '{password}' works!")
                print(f"   Reason: {reason}")
                print(f"   Time: {response_time:.1f}s")
                
                return TestResult(target, password, True, response_time, reason, confidence)
            else:
                print(f"❌ Failed: {reason}")
                print(f"   Time: {response_time:.1f}s")
                
                return TestResult(target, password, False, response_time, reason, confidence)
            
        except Exception as e:
            response_time = time.time() - start_time
            error_msg = f"Test error: {str(e)}"
            print(f"❌ Error: {error_msg}")
            
            return TestResult(target, password, False, response_time, error_msg, 0)
    
    async def test_target(self, target: str):
        """Test all passwords with EXTREME patience"""
        print(f"\n🎯 PATIENT TESTING: {target}")
        print(f"🔐 Passwords: {self.password_list}")
        print("⏳ This will take time - please be patient!")
        print("=" * 60)
        
        results = []
        
        for i, password in enumerate(self.password_list, 1):
            print(f"\n[{i}/{len(self.password_list)}] PATIENT TEST: {password}")
            
            result = self.test_password_patient(target, password)
            results.append(result)
            
            if result.success:
                print(f"\n🎉 PASSWORD FOUND: {password}")
                print(f"   Confidence: {result.confidence_score}")
                print(f"   Total time: {result.response_time:.1f}s")
                print("🛑 STOPPING - Password found!")
                break
            
            print(f"❌ Password '{password}' failed")
            
            # Brief pause between tests
            if i < len(self.password_list):
                self.patient_wait("Resting between tests", 5)
        
        return results

def main():
    print("🐌 PATIENT ROUTER PASSWORD TESTER")
    print("=" * 60)
    print("EXTRA PATIENT VERSION FOR SLOW SITES")
    print("This version waits up to 2 minutes for pages to load!")
    print("=" * 60)
    
    parser = argparse.ArgumentParser(description='Patient Router Password Tester')
    parser.add_argument('--target', '-t', required=True, help='Target IP or URL')
    parser.add_argument('--visible', '-v', action='store_true', help='Show Chrome browser')
    
    args = parser.parse_args()
    
    print(f"🎯 Target: {args.target}")
    print(f"👁️ Visible: {args.visible}")
    print(f"⏳ Patience Level: MAXIMUM")
    
    tester = PatientRouterTester(headless=not args.visible)
    
    if not tester.driver:
        print("❌ Chrome driver not available")
        return
    
    try:
        start_time = time.time()
        results = asyncio.run(tester.test_target(args.target))
        total_time = time.time() - start_time
        
        # Show final results
        print("\n" + "=" * 60)
        print("PATIENT TESTING COMPLETE")
        print("=" * 60)
        
        successful = [r for r in results if r.success]
        
        if successful:
            result = successful[0]
            print(f"🎉 SUCCESS!")
            print(f"Target: {result.target}")
            print(f"Password: {result.password}")
            print(f"Confidence: {result.confidence_score}")
            print(f"Test time: {result.response_time:.1f}s")
            print(f"Total time: {total_time:.1f}s")
            print(f"Details: {result.details}")
        else:
            print("❌ No working password found")
            print("💡 All passwords failed patient verification")
            print(f"Total time spent: {total_time:.1f}s")
        
        print(f"\nTotal tests: {len(results)}")
        
    except KeyboardInterrupt:
        print("\n⚠️ Testing interrupted by user")
    except Exception as e:
        print(f"❌ Error: {e}")
    finally:
        tester.close_chrome()

if __name__ == "__main__":
    main()