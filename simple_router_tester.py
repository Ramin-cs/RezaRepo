#!/usr/bin/env python3
"""
Simple Router Password Tester - NO TIMEOUT ISSUES
Simplified version without complex session clearing
"""

import asyncio
import aiohttp
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
    method: str
    details: str
    verification_steps: List[str]
    confidence_score: int

class SimpleRouterTester:
    def __init__(self, headless: bool = True):
        self.driver = None
        self.headless = headless
        # Only the 4 passwords you requested
        self.password_list = ["admin", "JAMES1", "admin1", "user"]
        self.setup_chrome()
    
    def setup_chrome(self):
        """Setup Chrome driver with minimal settings"""
        try:
            chrome_options = Options()
            
            if self.headless:
                chrome_options.add_argument('--headless=new')
            
            # Minimal essential options
            chrome_options.add_argument('--no-sandbox')
            chrome_options.add_argument('--disable-dev-shm-usage')
            chrome_options.add_argument('--disable-gpu')
            chrome_options.add_argument('--window-size=1200,800')
            chrome_options.add_argument('--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
            
            # Disable problematic features
            chrome_options.add_argument('--disable-extensions')
            chrome_options.add_argument('--disable-plugins-discovery')
            chrome_options.add_argument('--disable-background-timer-throttling')
            chrome_options.add_argument('--disable-backgrounding-occluded-windows')
            chrome_options.add_argument('--disable-renderer-backgrounding')
            chrome_options.add_argument('--disable-features=TranslateUI')
            chrome_options.add_argument('--disable-ipc-flooding-protection')
            chrome_options.add_argument('--disable-web-security')
            
            # Reduce logging
            chrome_options.add_argument('--log-level=3')
            chrome_options.add_argument('--silent')
            chrome_options.add_experimental_option('excludeSwitches', ['enable-logging'])
            chrome_options.add_experimental_option('useAutomationExtension', False)
            
            self.driver = webdriver.Chrome(options=chrome_options)
            self.driver.set_page_load_timeout(25)
            self.driver.implicitly_wait(5)
            
            print("✅ Chrome driver ready")
            
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
    
    def handle_login_popup(self):
        """Handle login confirmation popup"""
        handled = False
        
        try:
            # Check for login confirmation popup text
            page_source = self.driver.page_source.lower()
            
            if "only one device can log in at a time" in page_source:
                print("🔍 Login confirmation popup detected!")
                
                # Look for buttons with "log in" text
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
                                time.sleep(3)
                                handled = True
                                break
                    except Exception:
                        continue
            
            # Handle JavaScript alerts
            try:
                WebDriverWait(self.driver, 2).until(EC.alert_is_present())
                alert = self.driver.switch_to.alert
                print(f"🚨 Alert: {alert.text[:30]}...")
                alert.accept()
                time.sleep(1)
                handled = True
            except TimeoutException:
                pass
                
        except Exception as e:
            print(f"⚠️ Popup handling error: {e}")
        
        return handled
    
    def wait_for_page_load(self, timeout=20):
        """Simple page load waiting"""
        try:
            WebDriverWait(self.driver, timeout).until(
                lambda driver: driver.execute_script("return document.readyState") == "complete"
            )
            time.sleep(2)
            return True
        except TimeoutException:
            print("⚠️ Page load timeout")
            return False
        except Exception as e:
            print(f"⚠️ Page load error: {e}")
            return False
    
    def find_login_elements(self):
        """Find password field and login button"""
        password_field = None
        login_button = None
        
        # Find password field
        password_selectors = [
            "input[type='password']",
            "input[name='password']", "input[name='pass']", "input[name='pwd']"
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
            "input[value*='login']", "button:contains('Login')"
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
        
        return password_field, login_button
    
    def check_management_panel(self, original_url: str) -> Tuple[bool, str, int]:
        """Simple management panel detection"""
        try:
            current_url = self.driver.current_url
            page_source = self.driver.page_source.lower()
            
            print(f"🔍 Analysis:")
            print(f"   Original: {original_url}")
            print(f"   Current: {current_url}")
            
            score = 0
            reasons = []
            
            # Check 1: Password field gone?
            try:
                password_fields = self.driver.find_elements(By.CSS_SELECTOR, "input[type='password']")
                visible_fields = [pf for pf in password_fields if pf.is_displayed()]
                
                if visible_fields:
                    score -= 30
                    reasons.append("Password field still visible")
                    print("   ❌ Password field still visible")
                else:
                    score += 40
                    reasons.append("Password field removed")
                    print("   ✅ Password field removed")
            except:
                pass
            
            # Check 2: Management indicators
            management_words = ['logout', 'dashboard', 'administration', 'wireless', 'network']
            found_management = []
            
            for word in management_words:
                count = page_source.count(word)
                if count > 0:
                    score += count * 5
                    found_management.append(f"{word}({count})")
            
            if found_management:
                reasons.append(f"Management: {', '.join(found_management[:3])}")
                print(f"   ✅ Management indicators: {', '.join(found_management[:3])}")
            
            # Check 3: Login indicators (negative)
            login_words = ['login', 'password', 'username']
            found_login = []
            
            for word in login_words:
                count = page_source.count(word)
                if count > 0:
                    score -= count * 2
                    found_login.append(f"{word}({count})")
            
            if found_login:
                reasons.append(f"Login: {', '.join(found_login[:3])}")
                print(f"   ❌ Login indicators: {', '.join(found_login[:3])}")
            
            # Check 4: URL change
            if current_url != original_url:
                score += 15
                reasons.append("URL changed")
                print("   ✅ URL changed")
            
            print(f"   📊 Final score: {score}")
            
            # Decision
            if score >= 30:
                return True, f"Management panel detected (score: {score})", score
            else:
                return False, f"Still on login page (score: {score})", score
                
        except Exception as e:
            return False, f"Analysis error: {e}", 0
    
    def test_password_simple(self, target: str, password: str) -> TestResult:
        """Simple password testing without complex features"""
        if not self.driver:
            return TestResult(
                target=target, password=password, success=False, response_time=0,
                method="chrome", details="Chrome not available", verification_steps=[], confidence_score=0
            )
        
        start_time = time.time()
        verification_steps = []
        
        try:
            print(f"🔑 Testing password: {password}")
            
            # Prepare URL
            if not target.startswith(('http://', 'https://')):
                url = f"http://{target}"
            else:
                url = target
            
            # Load page (no session clearing to avoid timeout)
            print("📄 Loading login page...")
            self.driver.get(url)
            self.wait_for_page_load()
            
            original_url = self.driver.current_url
            verification_steps.append(f"Loaded: {original_url}")
            
            # Find login elements
            password_field, login_button = self.find_login_elements()
            
            if not password_field:
                return TestResult(
                    target=target, password=password, success=False,
                    response_time=time.time() - start_time, method="chrome",
                    details="No password field found", verification_steps=verification_steps,
                    confidence_score=0
                )
            
            # Enter password
            print("🔐 Entering password...")
            password_field.clear()
            password_field.send_keys(password)
            verification_steps.append("Password entered")
            
            # Submit form
            if login_button:
                login_button.click()
                verification_steps.append("Login button clicked")
                print("   Login button clicked")
            else:
                password_field.send_keys(Keys.RETURN)
                verification_steps.append("Form submitted with Enter")
                print("   Form submitted with Enter")
            
            # Wait and handle popup
            print("⏳ Waiting for response...")
            time.sleep(4)
            
            popup_handled = self.handle_login_popup()
            if popup_handled:
                print("✅ Login popup handled")
                time.sleep(4)
            
            # Wait for page to stabilize
            self.wait_for_page_load(timeout=15)
            time.sleep(2)
            
            # Check result
            is_management, reason, confidence = self.check_management_panel(original_url)
            verification_steps.append(f"Result: {reason}")
            
            response_time = time.time() - start_time
            
            if is_management:
                print(f"🎉 SUCCESS! Password '{password}' works!")
                print(f"   Reason: {reason}")
                
                return TestResult(
                    target=target, password=password, success=True,
                    response_time=response_time, method="chrome",
                    details=reason, verification_steps=verification_steps,
                    confidence_score=confidence
                )
            else:
                print(f"❌ Failed: {reason}")
                
                return TestResult(
                    target=target, password=password, success=False,
                    response_time=response_time, method="chrome",
                    details=reason, verification_steps=verification_steps,
                    confidence_score=confidence
                )
            
        except Exception as e:
            response_time = time.time() - start_time
            error_msg = f"Test error: {str(e)}"
            print(f"❌ Error: {error_msg}")
            
            return TestResult(
                target=target, password=password, success=False,
                response_time=response_time, method="chrome",
                details=error_msg, verification_steps=verification_steps,
                confidence_score=0
            )
    
    async def test_target(self, target: str):
        """Test all passwords on target"""
        print(f"\n🎯 Testing target: {target}")
        print(f"🔐 Passwords to test: {self.password_list}")
        print("-" * 50)
        
        results = []
        
        for i, password in enumerate(self.password_list, 1):
            print(f"\n[{i}/{len(self.password_list)}] Testing password: {password}")
            
            result = self.test_password_simple(target, password)
            results.append(result)
            
            if result.success:
                print(f"🎉 PASSWORD FOUND: {password}")
                print(f"   Confidence: {result.confidence_score}")
                print(f"   Details: {result.details}")
                print("🛑 STOPPING - Password found!")
                break
            
            print(f"   ❌ Password '{password}' failed")
            
            # Brief pause between tests
            await asyncio.sleep(1)
        
        return results

def main():
    print("🚀 SIMPLE ROUTER PASSWORD TESTER")
    print("=" * 50)
    print("Simplified version - No timeout issues")
    print("=" * 50)
    
    parser = argparse.ArgumentParser(description='Simple Router Password Tester')
    parser.add_argument('--target', '-t', required=True, help='Target IP or URL')
    parser.add_argument('--visible', '-v', action='store_true', help='Show Chrome browser')
    
    args = parser.parse_args()
    
    print(f"🎯 Target: {args.target}")
    print(f"👁️ Visible: {args.visible}")
    
    tester = SimpleRouterTester(headless=not args.visible)
    
    if not tester.driver:
        print("❌ Chrome driver not available")
        return
    
    try:
        results = asyncio.run(tester.test_target(args.target))
        
        # Show final results
        print("\n" + "=" * 50)
        print("FINAL RESULTS")
        print("=" * 50)
        
        successful = [r for r in results if r.success]
        
        if successful:
            result = successful[0]
            print(f"🎉 SUCCESS!")
            print(f"Target: {result.target}")
            print(f"Password: {result.password}")
            print(f"Confidence: {result.confidence_score}")
            print(f"Time: {result.response_time:.1f}s")
            print(f"Details: {result.details}")
        else:
            print("❌ No working password found")
            print("💡 All passwords failed verification")
        
        print(f"\nTotal tests: {len(results)}")
        
    except KeyboardInterrupt:
        print("\n⚠️ Testing interrupted by user")
    except Exception as e:
        print(f"❌ Error: {e}")
    finally:
        tester.close_chrome()

if __name__ == "__main__":
    main()