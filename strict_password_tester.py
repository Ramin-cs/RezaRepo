#!/usr/bin/env python3
"""
Strict Password Tester - HTTP with STRICT verification
Uses multiple verification steps to ensure real login success
"""

import asyncio
import aiohttp
import time
import argparse
import re
from dataclasses import dataclass
from typing import List, Optional, Tuple

@dataclass
class TestResult:
    target: str
    password: str
    success: bool
    response_time: float
    details: str
    verification_steps: List[str]
    confidence_score: int

class StrictPasswordTester:
    def __init__(self):
        # Only the 4 passwords you requested
        self.password_list = ["admin", "JAMES1", "admin1", "user"]
        print(f"🔐 Loaded {len(self.password_list)} passwords: {self.password_list}")
    
    async def analyze_response_strict(self, response_text: str, final_url: str, original_url: str, status_code: int) -> Tuple[bool, str, int, List[str]]:
        """STRICT analysis of HTTP response to detect real management panel"""
        analysis_steps = []
        confidence_score = 0
        
        response_lower = response_text.lower()
        
        # Step 1: Check for password fields (CRITICAL - should be GONE)
        password_field_patterns = [
            r'<input[^>]*type=["\']password["\'][^>]*>',
            r'<input[^>]*name=["\']password["\'][^>]*>',
            r'<input[^>]*id=["\']password["\'][^>]*>',
            r'password.*required',
            r'enter.*password',
            r'please.*login'
        ]
        
        password_field_found = False
        for pattern in password_field_patterns:
            if re.search(pattern, response_lower):
                password_field_found = True
                break
        
        if password_field_found:
            analysis_steps.append("❌ Password field still present")
            confidence_score -= 20
        else:
            analysis_steps.append("✅ No password field found")
            confidence_score += 15
        
        # Step 2: Strong management indicators (HIGH VALUE)
        strong_indicators = {
            'logout': 15, 'log out': 15, 'sign out': 15, 'signout': 15,
            'dashboard': 12, 'administration': 12, 'admin panel': 12,
            'management console': 10, 'management panel': 10,
            'configuration': 8, 'system status': 8, 'device status': 8
        }
        
        strong_found = []
        for indicator, weight in strong_indicators.items():
            count = response_lower.count(indicator)
            if count > 0:
                confidence_score += weight * min(count, 2)  # Cap at 2 occurrences
                strong_found.append(f"{indicator}({count})")
        
        if strong_found:
            analysis_steps.append(f"✅ Strong indicators: {', '.join(strong_found[:3])}")
        else:
            analysis_steps.append("❌ No strong management indicators")
        
        # Step 3: Medium management indicators
        medium_indicators = {
            'wireless': 5, 'network': 5, 'wan': 5, 'lan': 5, 'wifi': 5,
            'firewall': 4, 'nat': 4, 'dhcp': 4, 'qos': 4, 'vpn': 4,
            'port forwarding': 4, 'access control': 4, 'security': 4,
            'firmware': 3, 'backup': 3, 'restore': 3, 'reboot': 3,
            'router': 3, 'modem': 3, 'gateway': 3
        }
        
        medium_found = []
        for indicator, weight in medium_indicators.items():
            count = response_lower.count(indicator)
            if count > 0:
                confidence_score += weight * min(count, 2)
                medium_found.append(f"{indicator}({count})")
        
        if medium_found:
            analysis_steps.append(f"✅ Medium indicators: {', '.join(medium_found[:3])}")
        
        # Step 4: Negative indicators (LOGIN PAGE ELEMENTS)
        negative_indicators = {
            'login': -5, 'sign in': -5, 'please login': -8,
            'username': -3, 'user name': -3, 'enter username': -5,
            'authentication required': -8, 'access denied': -10,
            'invalid password': -10, 'login failed': -10,
            'forgot password': -5, 'remember me': -3
        }
        
        negative_found = []
        for indicator, weight in negative_indicators.items():
            count = response_lower.count(indicator)
            if count > 0:
                confidence_score += weight * min(count, 2)  # Negative weight
                negative_found.append(f"{indicator}({count})")
        
        if negative_found:
            analysis_steps.append(f"❌ Negative indicators: {', '.join(negative_found[:3])}")
        
        # Step 5: URL analysis
        url_changed = final_url.lower() != original_url.lower()
        if url_changed:
            confidence_score += 10
            analysis_steps.append(f"✅ URL changed: {original_url} → {final_url}")
        else:
            analysis_steps.append("⚠️ URL unchanged")
        
        # Step 6: HTTP status analysis
        if status_code == 200:
            confidence_score += 5
            analysis_steps.append("✅ HTTP 200 OK")
        elif status_code in [301, 302, 303, 307, 308]:
            confidence_score += 8
            analysis_steps.append(f"✅ HTTP {status_code} Redirect")
        else:
            confidence_score -= 5
            analysis_steps.append(f"⚠️ HTTP {status_code}")
        
        # Step 7: Content length analysis
        content_length = len(response_text)
        if content_length > 5000:  # Substantial content suggests a real page
            confidence_score += 5
            analysis_steps.append(f"✅ Substantial content: {content_length} chars")
        elif content_length < 500:  # Very short content might be error page
            confidence_score -= 5
            analysis_steps.append(f"⚠️ Short content: {content_length} chars")
        
        # Step 8: Look for specific management page elements
        management_elements = [
            r'<title>[^<]*admin[^<]*</title>',
            r'<title>[^<]*management[^<]*</title>',
            r'<title>[^<]*configuration[^<]*</title>',
            r'<title>[^<]*dashboard[^<]*</title>',
            r'href=["\'][^"\']*logout[^"\']*["\']',
            r'onclick=["\'][^"\']*logout[^"\']*["\']',
            r'<form[^>]*action=["\'][^"\']*logout[^"\']*["\']'
        ]
        
        element_found = False
        for pattern in management_elements:
            if re.search(pattern, response_lower):
                element_found = True
                confidence_score += 8
                break
        
        if element_found:
            analysis_steps.append("✅ Management page elements found")
        
        # FINAL DECISION LOGIC
        analysis_steps.append(f"📊 Final confidence score: {confidence_score}")
        
        # Strict thresholds
        if confidence_score >= 40:
            return True, f"HIGH CONFIDENCE management panel (score: {confidence_score})", confidence_score, analysis_steps
        elif confidence_score >= 25 and url_changed and not password_field_found:
            return True, f"GOOD CONFIDENCE with URL change (score: {confidence_score})", confidence_score, analysis_steps
        elif confidence_score >= 15 and len(strong_found) >= 2:
            return True, f"MODERATE CONFIDENCE with strong indicators (score: {confidence_score})", confidence_score, analysis_steps
        else:
            return False, f"INSUFFICIENT CONFIDENCE (score: {confidence_score})", confidence_score, analysis_steps
    
    async def test_password_strict(self, target: str, password: str) -> TestResult:
        """Test password with STRICT HTTP verification"""
        start_time = time.time()
        verification_steps = []
        
        try:
            # Prepare URL
            if not target.startswith(('http://', 'https://')):
                url = f"http://{target}"
            else:
                url = target
            
            verification_steps.append(f"Testing URL: {url}")
            verification_steps.append(f"Testing password: {password}")
            
            print(f"🔑 STRICT TEST: {password}")
            print(f"   Target: {url}")
            
            timeout = aiohttp.ClientTimeout(total=15)
            
            async with aiohttp.ClientSession(timeout=timeout) as session:
                # Try multiple login data formats
                login_variations = [
                    {'password': password},  # Password only (as requested)
                    {'pass': password},
                    {'pwd': password},
                    {'Password': password},  # Case variations
                    {'PASS': password},
                    {'PWD': password}
                ]
                
                best_result = None
                best_confidence = -100
                
                for i, login_data in enumerate(login_variations, 1):
                    try:
                        verification_steps.append(f"Attempt {i}: {list(login_data.keys())[0]}={password}")
                        
                        async with session.post(url, data=login_data, ssl=False, allow_redirects=True) as response:
                            final_url = str(response.url)
                            response_text = await response.text()
                            status_code = response.status
                            
                            # STRICT ANALYSIS
                            is_management, reason, confidence, analysis_steps = await self.analyze_response_strict(
                                response_text, final_url, url, status_code
                            )
                            
                            verification_steps.extend(analysis_steps)
                            
                            print(f"   Attempt {i}: Confidence {confidence}")
                            
                            if confidence > best_confidence:
                                best_confidence = confidence
                                best_result = (is_management, reason, confidence)
                            
                            # If we found a high-confidence success, stop trying
                            if is_management and confidence >= 40:
                                break
                                
                    except asyncio.TimeoutError:
                        verification_steps.append(f"Attempt {i}: Timeout")
                        continue
                    except Exception as e:
                        verification_steps.append(f"Attempt {i}: Error - {str(e)}")
                        continue
                
                response_time = time.time() - start_time
                
                if best_result:
                    is_management, reason, confidence = best_result
                    
                    if is_management:
                        print(f"🎉 STRICT SUCCESS!")
                        print(f"   Password: {password}")
                        print(f"   Confidence: {confidence}")
                        print(f"   Reason: {reason}")
                        
                        return TestResult(
                            target=target,
                            password=password,
                            success=True,
                            response_time=response_time,
                            details=reason,
                            verification_steps=verification_steps,
                            confidence_score=confidence
                        )
                    else:
                        print(f"❌ STRICT FAILED")
                        print(f"   Password: {password}")
                        print(f"   Confidence: {confidence}")
                        print(f"   Reason: {reason}")
                        
                        return TestResult(
                            target=target,
                            password=password,
                            success=False,
                            response_time=response_time,
                            details=reason,
                            verification_steps=verification_steps,
                            confidence_score=confidence
                        )
                else:
                    return TestResult(
                        target=target,
                        password=password,
                        success=False,
                        response_time=response_time,
                        details="All attempts failed",
                        verification_steps=verification_steps,
                        confidence_score=-100
                    )
                    
        except Exception as e:
            response_time = time.time() - start_time
            error_msg = f"Test error: {str(e)}"
            verification_steps.append(error_msg)
            
            return TestResult(
                target=target,
                password=password,
                success=False,
                response_time=response_time,
                details=error_msg,
                verification_steps=verification_steps,
                confidence_score=-100
            )
    
    async def test_target(self, target: str):
        """Test all passwords with STRICT verification"""
        print(f"\n🎯 STRICT PASSWORD TESTING")
        print(f"Target: {target}")
        print(f"Passwords: {self.password_list}")
        print("=" * 60)
        
        results = []
        
        for i, password in enumerate(self.password_list, 1):
            print(f"\n[{i}/{len(self.password_list)}] STRICT TESTING: {password}")
            print("-" * 40)
            
            result = await self.test_password_strict(target, password)
            results.append(result)
            
            if result.success:
                print(f"\n🎉 STRICT VERIFICATION SUCCESS!")
                print(f"Password: {password}")
                print(f"Confidence: {result.confidence_score}")
                print(f"Details: {result.details}")
                print("🛑 STOPPING - Password verified with strict analysis!")
                break
            
            print(f"❌ Password '{password}' failed strict verification")
            print(f"   Confidence: {result.confidence_score}")
            
            # Brief pause between tests
            await asyncio.sleep(0.5)
        
        return results

def main():
    print("🚀 STRICT PASSWORD TESTER")
    print("=" * 50)
    print("HTTP-based with STRICT multi-step verification")
    print("Uses advanced analysis to detect real management panel access")
    print("=" * 50)
    
    parser = argparse.ArgumentParser(description='Strict Password Tester')
    parser.add_argument('--target', '-t', required=True, help='Target IP or URL')
    parser.add_argument('--verbose', '-v', action='store_true', help='Show detailed verification steps')
    
    args = parser.parse_args()
    
    print(f"🎯 Target: {args.target}")
    print(f"📝 Verbose: {args.verbose}")
    
    tester = StrictPasswordTester()
    
    try:
        results = asyncio.run(tester.test_target(args.target))
        
        # Final results
        print("\n" + "=" * 60)
        print("STRICT VERIFICATION RESULTS")
        print("=" * 60)
        
        successful = [r for r in results if r.success]
        
        if successful:
            result = successful[0]
            print(f"🎉 STRICT VERIFICATION SUCCESS!")
            print(f"Target: {result.target}")
            print(f"Password: {result.password}")
            print(f"Confidence Score: {result.confidence_score}")
            print(f"Details: {result.details}")
            print(f"Response Time: {result.response_time:.1f}s")
            
            if args.verbose:
                print(f"\n📋 Detailed Verification Steps:")
                for step in result.verification_steps:
                    print(f"   {step}")
        else:
            print("❌ NO VALID PASSWORD FOUND")
            print("💡 All passwords failed STRICT verification")
            print("\n📊 Confidence Scores:")
            for result in results:
                print(f"   {result.password}: {result.confidence_score}")
            
            if args.verbose:
                print(f"\n📋 Last Test Details:")
                for step in results[-1].verification_steps[-5:]:
                    print(f"   {step}")
        
        print(f"\nTotal tests performed: {len(results)}")
        
    except KeyboardInterrupt:
        print("\n⚠️ Testing interrupted by user")
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    main()