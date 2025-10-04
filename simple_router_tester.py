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
import os
from datetime import datetime

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
            self.driver.set_page_load_timeout(60)  # Increased for slow sites
            self.driver.implicitly_wait(5)  # Reduced from 10 to 5 for faster element search
            
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
        """Handle login confirmation popup - no duplicate messages"""
        handled = False
        
        try:
            # Check for login confirmation popup text
            page_source = self.driver.page_source.lower()
            
            if "only one device can log in at a time" in page_source:
                if not hasattr(self, '_popup_detected'):
                    print("🔍 Login confirmation popup detected!")
                    self._popup_detected = True
                
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
                                if not hasattr(self, '_popup_clicked'):
                                    print(f"✅ Clicking login confirmation")
                                    self._popup_clicked = True
                                element.click()
                                time.sleep(1)  # Reduced from 3 to 1 second
                                handled = True
                                break
                    except Exception:
                        continue
            
            # Handle JavaScript alerts
            try:
                WebDriverWait(self.driver, 2).until(EC.alert_is_present())
                alert = self.driver.switch_to.alert
                print(f"🚨 Alert detected")
                alert.accept()
                time.sleep(1)
                handled = True
            except TimeoutException:
                pass
                
        except Exception as e:
            print(f"⚠️ Popup handling error: {e}")
        
        return handled
    
    def wait_for_page_load(self, timeout=45):
        """Smart page load waiting with multiple checks"""
        try:
            print(f"⏳ Waiting for page to load (up to {timeout}s)...")
            
            # Wait for document ready
            WebDriverWait(self.driver, timeout).until(
                lambda driver: driver.execute_script("return document.readyState") == "complete"
            )
            print("   ✅ Document ready")
            
            # Additional wait for dynamic content
            time.sleep(5)
            
            # Check if page is still loading (look for loading indicators)
            loading_indicators = ['loading', 'spinner', 'wait', 'please wait']
            page_source = self.driver.page_source.lower()
            
            if any(indicator in page_source for indicator in loading_indicators):
                print("   ⏳ Page still loading, waiting more...")
                time.sleep(10)
            
            # Final check
            try:
                self.driver.execute_script("return document.readyState")
                print("   ✅ Page fully loaded")
                return True
            except:
                print("   ⚠️ Page load check failed, continuing...")
                return True
                
        except TimeoutException:
            print(f"   ⚠️ Page load timeout after {timeout}s, continuing...")
            return False
        except Exception as e:
            print(f"   ⚠️ Page load error: {e}, continuing...")
            return False
    
    def find_login_elements(self, timeout=15):
        """Fast element detection - reduced timeout"""
        password_field = None
        login_button = None
        
        print("🔍 Looking for login elements...")
        
        # Wait for password field to appear
        password_selectors = [
            "input[type='password']",
            "input[name='password']", "input[name='pass']", "input[name='pwd']"
        ]
        
        for selector in password_selectors:
            try:
                element = WebDriverWait(self.driver, timeout).until(
                    EC.element_to_be_clickable((By.CSS_SELECTOR, selector))
                )
                if element.is_displayed() and element.is_enabled():
                    password_field = element
                    print(f"   ✅ Password field found")
                    break
            except TimeoutException:
                continue
            except Exception:
                continue
        
        # If password field found, quickly look for login button
        if password_field:
            button_selectors = [
                "input[type='submit']", "button[type='submit']",
                "input[value*='login']", "input[value*='Login']", "input[value*='log in']",
                "button", "input[type='button']"
            ]
            
            for selector in button_selectors:
                try:
                    elements = self.driver.find_elements(By.CSS_SELECTOR, selector)
                    for element in elements:
                        if element.is_displayed() and element.is_enabled():
                            # Quick check button text/value
                            text = element.text.lower() if element.text else ""
                            value = element.get_attribute('value')
                            if value:
                                value = value.lower()
                            
                            if (selector in ["input[type='submit']", "button[type='submit']"] or
                                'login' in text or 'log in' in text or
                                (value and ('login' in value or 'log in' in value))):
                                login_button = element
                                print(f"   ✅ Login button found")
                                break
                    if login_button:
                        break
                except Exception:
                    continue
        
        if not password_field:
            print("   ❌ No password field found")
        if not login_button:
            print("   ⚠️ No login button found (will use Enter key)")
        
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
            
            # Enter password immediately
            print("🔐 Entering password...")
            password_field.clear()
            password_field.send_keys(password)
            verification_steps.append("Password entered")
            
            # Submit form quickly
            if login_button:
                print("   Login button clicked")
                login_button.click()
                verification_steps.append("Login button clicked")
            else:
                print("   Form submitted with Enter")
                password_field.send_keys(Keys.RETURN)
                verification_steps.append("Form submitted with Enter")
            
            # Smart waiting for response
            print("⏳ Waiting for login response...")
            time.sleep(4)  # Reduced initial wait from 6 to 4 seconds
            
            # Check for popup multiple times
            for i in range(3):
                popup_handled = self.handle_login_popup()
                if popup_handled:
                    print(f"✅ Login popup handled (attempt {i+1})")
                    time.sleep(3)  # Reduced from 5 to 3 seconds
                    break
                time.sleep(1)  # Reduced from 2 to 1 second
            
            # Wait for page to stabilize after login
            print("⏳ Waiting for page to stabilize...")
            self.wait_for_page_load(timeout=30)
            time.sleep(2)  # Reduced from 3 to 2 seconds
            
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
    
    def load_targets_from_file(self, file_path: str) -> List[str]:
        """Load targets from file"""
        targets = []
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if line and not line.startswith('#'):
                        targets.append(line)
            print(f"📁 Loaded {len(targets)} targets from file")
            return targets
        except Exception as e:
            print(f"❌ Error reading file {file_path}: {e}")
            return []
    
    def load_targets(self, target_input: str) -> List[str]:
        """Load targets from input (single target or file)"""
        # Check if it's a file
        if os.path.exists(target_input):
            return self.load_targets_from_file(target_input)
        else:
            # Single target
            return [target_input]
    
    def save_successful_result(self, target: str, password: str, confidence: int, response_time: float, filename: str = "successful_logins.txt"):
        """Save successful login to file"""
        try:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            # Create result line
            result_line = f"{timestamp} | {target} | {password} | Score: {confidence} | Time: {response_time:.1f}s\n"
            
            # Check if file exists to add header
            file_exists = os.path.exists(filename)
            
            with open(filename, 'a', encoding='utf-8') as f:
                # Add header if file is new
                if not file_exists:
                    f.write("# Successful Router Login Results\n")
                    f.write("# Format: Timestamp | Target | Password | Score | Time\n")
                    f.write("# " + "="*70 + "\n")
                
                f.write(result_line)
            
            print(f"💾 Result saved to: {filename}")
            
        except Exception as e:
            print(f"⚠️ Error saving result: {e}")
    
    def save_bulk_summary(self, successful_targets: List[dict], total_targets: int, filename: str = "bulk_summary.txt"):
        """Save bulk testing summary"""
        try:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            with open(filename, 'w', encoding='utf-8') as f:
                f.write("# Bulk Testing Summary\n")
                f.write(f"# Generated: {timestamp}\n")
                f.write("# " + "="*70 + "\n\n")
                
                f.write(f"Total targets tested: {total_targets}\n")
                f.write(f"Successful logins: {len(successful_targets)}\n")
                f.write(f"Failed attempts: {total_targets - len(successful_targets)}\n")
                if total_targets > 0:
                    f.write(f"Success rate: {len(successful_targets)/total_targets*100:.1f}%\n")
                f.write("\n" + "="*70 + "\n")
                f.write("SUCCESSFUL TARGETS:\n")
                f.write("="*70 + "\n")
                
                if successful_targets:
                    for success in successful_targets:
                        f.write(f"Target: {success['target']}\n")
                        f.write(f"Password: {success['password']}\n")
                        f.write(f"Confidence: {success['confidence']}\n")
                        f.write(f"Time: {success.get('time', 'N/A')}\n")
                        f.write("-" * 40 + "\n")
                else:
                    f.write("No successful logins found.\n")
            
            print(f"📊 Summary saved to: {filename}")
            
        except Exception as e:
            print(f"⚠️ Error saving summary: {e}")
    
    async def test_target(self, target: str):
        """Test all passwords on single target"""
        print(f"\n🎯 Testing target: {target}")
        print(f"🔐 Passwords: {self.password_list}")
        print("-" * 50)
        
        # Reset popup flags for each target
        if hasattr(self, '_popup_detected'):
            delattr(self, '_popup_detected')
        if hasattr(self, '_popup_clicked'):
            delattr(self, '_popup_clicked')
        
        results = []
        
        for i, password in enumerate(self.password_list, 1):
            print(f"\n[{i}/{len(self.password_list)}] Testing password: {password}")
            
            result = self.test_password_simple(target, password)
            results.append(result)
            
            if result.success:
                print(f"🎉 PASSWORD FOUND: {password}")
                print(f"   Confidence: {result.confidence_score}")
                print(f"   Details: {result.details}")
                
                # Save successful result to file
                self.save_successful_result(target, password, result.confidence_score, result.response_time)
                
                print("🛑 STOPPING - Password found!")
                break
            
            print(f"   ❌ Password '{password}' failed")
            
            # Brief pause between tests
            await asyncio.sleep(1)
        
        return results
    
    async def test_multiple_targets(self, targets: List[str]):
        """Test multiple targets"""
        if not targets:
            print("❌ No targets to test")
            return []
        
        print(f"\n🚀 BULK TESTING")
        print(f"📊 Total targets: {len(targets)}")
        print(f"🔐 Passwords per target: {len(self.password_list)}")
        print("=" * 60)
        
        all_results = []
        successful_targets = []
        
        for i, target in enumerate(targets, 1):
            print(f"\n📋 TARGET {i}/{len(targets)}: {target}")
            
            target_results = await self.test_target(target)
            all_results.extend(target_results)
            
            # Check if any password worked for this target
            successful = [r for r in target_results if r.success]
            if successful:
                successful_targets.append({
                    'target': target,
                    'password': successful[0].password,
                    'confidence': successful[0].confidence_score,
                    'time': successful[0].response_time
                })
                print(f"✅ SUCCESS: {target} | Password: {successful[0].password}")
            else:
                print(f"❌ FAILED: {target} | No working password")
            
            # Brief pause between targets
            if i < len(targets):
                await asyncio.sleep(2)
        
        # Summary
        print(f"\n" + "=" * 60)
        print("BULK TESTING SUMMARY")
        print("=" * 60)
        
        if successful_targets:
            print(f"🎉 SUCCESSFUL TARGETS: {len(successful_targets)}")
            for success in successful_targets:
                print(f"   {success['target']} | {success['password']} | Score: {success['confidence']}")
        else:
            print("❌ No successful targets found")
        
        print(f"\nTotal targets tested: {len(targets)}")
        print(f"Successful: {len(successful_targets)}")
        print(f"Failed: {len(targets) - len(successful_targets)}")
        if len(targets) > 0:
            print(f"Success rate: {len(successful_targets)/len(targets)*100:.1f}%")
        
        # Save bulk summary
        if len(targets) > 1:  # Only for bulk testing
            self.save_bulk_summary(successful_targets, len(targets))
        
        return all_results

def main():
    print("🚀 SIMPLE ROUTER PASSWORD TESTER")
    print("=" * 50)
    print("Supports single targets and bulk file testing")
    print("=" * 50)
    
    parser = argparse.ArgumentParser(description='Simple Router Password Tester')
    parser.add_argument('--target', '-t', required=True, 
                       help='Target IP/URL or path to file with targets')
    parser.add_argument('--visible', '-v', action='store_true', 
                       help='Show Chrome browser')
    
    args = parser.parse_args()
    
    tester = SimpleRouterTester(headless=not args.visible)
    
    if not tester.driver:
        print("❌ Chrome driver not available")
        return
    
    try:
        # Load targets (single or from file)
        targets = tester.load_targets(args.target)
        
        if not targets:
            print("❌ No valid targets found")
            return
        
        print(f"🎯 Targets: {len(targets)}")
        print(f"👁️ Visible: {args.visible}")
        
        if len(targets) == 1:
            # Single target
            results = asyncio.run(tester.test_target(targets[0]))
            
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
        else:
            # Multiple targets
            results = asyncio.run(tester.test_multiple_targets(targets))
        
    except KeyboardInterrupt:
        print("\n⚠️ Testing interrupted by user")
    except Exception as e:
        print(f"❌ Error: {e}")
    finally:
        tester.close_chrome()

if __name__ == "__main__":
    main()