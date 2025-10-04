#!/usr/bin/env python3
"""
Simple Password Tester - Password Only Mode
Only tests passwords without username, stops immediately after finding correct password
"""

import asyncio
import aiohttp
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
    method: str
    details: str = ""

class SimplePasswordTester:
    def __init__(self):
        self.driver = None
        # Only the 4 passwords you requested
        self.password_list = ["admin", "JAMES1", "admin1", "user"]
        self.setup_chrome()
    
    def setup_chrome(self):
        """Setup Chrome driver"""
        try:
            chrome_options = Options()
            chrome_options.add_argument('--headless=new')
            chrome_options.add_argument('--no-sandbox')
            chrome_options.add_argument('--disable-dev-shm-usage')
            chrome_options.add_argument('--disable-gpu')
            chrome_options.add_argument('--window-size=1200,800')
            chrome_options.add_argument('--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
            
            self.driver = webdriver.Chrome(options=chrome_options)
            self.driver.set_page_load_timeout(15)
            self.driver.implicitly_wait(3)
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
    
    def is_management_page(self, original_url: str) -> tuple[bool, str]:
        """Check if current page is management panel"""
        try:
            current_url = self.driver.current_url
            page_source = self.driver.page_source.lower()
            
            # Check if password field still exists (most reliable indicator)
            try:
                password_fields = self.driver.find_elements(By.CSS_SELECTOR, "input[type='password']")
                visible_password_fields = [pf for pf in password_fields if pf.is_displayed()]
                
                if visible_password_fields:
                    return False, "Password field still visible - login failed"
            except:
                pass
            
            # Look for management indicators
            management_indicators = [
                'logout', 'log out', 'dashboard', 'administration', 
                'management', 'configuration', 'status', 'wireless',
                'network', 'wan', 'lan', 'firewall', 'system info'
            ]
            
            login_indicators = [
                'password', 'login', 'sign in', 'username', 'enter password'
            ]
            
            management_count = sum(1 for indicator in management_indicators if indicator in page_source)
            login_count = sum(1 for indicator in login_indicators if indicator in page_source)
            url_changed = current_url != original_url
            
            # Simple scoring
            score = management_count * 3 - login_count * 2
            if url_changed:
                score += 5
            
            print(f"   Management indicators: {management_count}")
            print(f"   Login indicators: {login_count}")
            print(f"   URL changed: {url_changed}")
            print(f"   Score: {score}")
            
            # Decision logic
            if score >= 8:
                return True, f"Management panel detected (score: {score})"
            elif url_changed and management_count >= 2:
                return True, f"URL changed with management indicators (score: {score})"
            else:
                return False, f"Still on login page (score: {score})"
                
        except Exception as e:
            return False, f"Error checking page: {e}"
    
    def test_password_chrome(self, target: str, password: str) -> TestResult:
        """Test password using Chrome (password-only)"""
        if not self.driver:
            return TestResult(target, password, False, 0, "chrome", "Chrome not available")
        
        start_time = time.time()
        
        try:
            print(f"🔑 Testing password: {password}")
            
            # Load page
            url = f"http://{target}" if not target.startswith('http') else target
            self.driver.get(url)
            time.sleep(3)
            
            original_url = self.driver.current_url
            
            # Find password field (skip username)
            try:
                password_field = WebDriverWait(self.driver, 5).until(
                    EC.presence_of_element_located((By.CSS_SELECTOR, "input[type='password']"))
                )
            except TimeoutException:
                return TestResult(target, password, False, time.time() - start_time, 
                                "chrome", "No password field found")
            
            # Find login button
            login_button = None
            try:
                login_button = self.driver.find_element(By.CSS_SELECTOR, "input[type='submit'], button[type='submit']")
            except:
                try:
                    buttons = self.driver.find_elements(By.TAG_NAME, "button")
                    for btn in buttons:
                        if btn.is_displayed() and any(word in btn.text.lower() for word in ['login', 'sign in', 'submit']):
                            login_button = btn
                            break
                except:
                    pass
            
            # Enter password only (no username)
            password_field.clear()
            password_field.send_keys(password)
            print("   Password entered (username skipped)")
            
            # Submit
            if login_button:
                login_button.click()
                print("   Login button clicked")
            else:
                password_field.send_keys(Keys.RETURN)
                print("   Form submitted with Enter")
            
            # Wait for response
            time.sleep(4)
            
            # Handle any alerts
            try:
                alert = self.driver.switch_to.alert
                alert.accept()
                time.sleep(1)
            except:
                pass
            
            # Check if we're in management panel
            is_management, reason = self.is_management_page(original_url)
            response_time = time.time() - start_time
            
            if is_management:
                print(f"🎉 SUCCESS! Password '{password}' works!")
                print(f"   Reason: {reason}")
                return TestResult(target, password, True, response_time, "chrome", reason)
            else:
                print(f"❌ Failed: {reason}")
                return TestResult(target, password, False, response_time, "chrome", reason)
                
        except Exception as e:
            response_time = time.time() - start_time
            print(f"❌ Error: {e}")
            return TestResult(target, password, False, response_time, "chrome", str(e))
    
    async def test_password_http(self, target: str, password: str) -> TestResult:
        """Test password using HTTP (password-only)"""
        start_time = time.time()
        
        try:
            url = f"http://{target}" if not target.startswith('http') else target
            timeout = aiohttp.ClientTimeout(total=8)
            
            async with aiohttp.ClientSession(timeout=timeout) as session:
                # Try different password field names
                for field_name in ['password', 'pass', 'pwd']:
                    try:
                        login_data = {field_name: password}
                        
                        async with session.post(url, data=login_data, ssl=False, allow_redirects=True) as response:
                            final_url = str(response.url)
                            response_text = await response.text()
                            response_lower = response_text.lower()
                            
                            # Check for management indicators
                            management_indicators = ['logout', 'dashboard', 'management', 'status', 'wireless', 'configuration']
                            login_indicators = ['password', 'login', 'sign in', 'username']
                            
                            management_count = sum(1 for indicator in management_indicators if indicator in response_lower)
                            login_count = sum(1 for indicator in login_indicators if indicator in response_lower)
                            url_changed = final_url.lower() != url.lower()
                            
                            # Simple success criteria
                            if url_changed and management_count >= 2 and login_count <= 1:
                                response_time = time.time() - start_time
                                details = f"URL changed, Management: {management_count}, Login: {login_count}"
                                print(f"🎉 HTTP SUCCESS! Password '{password}' works!")
                                print(f"   {details}")
                                return TestResult(target, password, True, response_time, "http", details)
                                
                    except:
                        continue
                
                # If no success
                response_time = time.time() - start_time
                return TestResult(target, password, False, response_time, "http", "No management panel detected")
                
        except Exception as e:
            response_time = time.time() - start_time
            return TestResult(target, password, False, response_time, "http", str(e))
    
    async def test_target(self, target: str, mode: str = "both"):
        """Test all passwords on target until success"""
        print(f"\n🎯 Testing target: {target}")
        print(f"🔐 Passwords to test: {self.password_list}")
        print(f"🎮 Mode: {mode}")
        print("-" * 50)
        
        results = []
        
        for i, password in enumerate(self.password_list, 1):
            print(f"\n[{i}/{len(self.password_list)}] Testing password: {password}")
            
            success = False
            
            # Try HTTP first (faster)
            if mode in ["http", "both"]:
                print("   🌐 HTTP test...")
                result = await self.test_password_http(target, password)
                results.append(result)
                
                if result.success:
                    print(f"🎉 PASSWORD FOUND: {password}")
                    print("🛑 Stopping tests - Password verified!")
                    return results
            
            # Try Chrome if HTTP failed
            if mode in ["chrome", "both"] and not success:
                print("   🔍 Chrome test...")
                result = self.test_password_chrome(target, password)
                results.append(result)
                
                if result.success:
                    print(f"🎉 PASSWORD FOUND: {password}")
                    print("🛑 Stopping tests - Management panel verified!")
                    return results
            
            print(f"   ❌ Password '{password}' failed")
            
            # Small delay between passwords
            await asyncio.sleep(0.5)
        
        print("❌ No working password found")
        return results

def main():
    print("🚀 SIMPLE PASSWORD TESTER")
    print("=" * 40)
    print("Password-only mode (no username)")
    print("Stops immediately after finding correct password")
    print("=" * 40)
    
    parser = argparse.ArgumentParser(description='Simple Password Tester')
    parser.add_argument('--target', '-t', required=True, help='Target IP or URL')
    parser.add_argument('--mode', '-m', choices=['http', 'chrome', 'both'], 
                       default='both', help='Test mode (default: both)')
    
    args = parser.parse_args()
    
    print(f"🎯 Target: {args.target}")
    print(f"🎮 Mode: {args.mode}")
    
    tester = SimplePasswordTester()
    
    try:
        results = asyncio.run(tester.test_target(args.target, args.mode))
        
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