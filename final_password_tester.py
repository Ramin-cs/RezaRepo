#!/usr/bin/env python3
"""
Final Password Tester - Pure Python with REAL verification
Uses only standard Python libraries with strict verification
"""

import urllib.request
import urllib.parse
import urllib.error
import time
import argparse
import re
import ssl
from dataclasses import dataclass
from typing import List, Tuple

@dataclass
class TestResult:
    target: str
    password: str
    success: bool
    response_time: float
    details: str
    verification_steps: List[str]
    confidence_score: int

class FinalPasswordTester:
    def __init__(self):
        # Only the 4 passwords you requested
        self.password_list = ["admin", "JAMES1", "admin1", "user"]
        print(f"🔐 Loaded {len(self.password_list)} passwords: {self.password_list}")
        
        # Create SSL context that doesn't verify certificates
        self.ssl_context = ssl.create_default_context()
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_NONE
    
    def analyze_response_strict(self, response_text: str, final_url: str, original_url: str, status_code: int) -> Tuple[bool, str, int, List[str]]:
        """STRICT analysis of HTTP response to detect real management panel"""
        analysis_steps = []
        confidence_score = 0
        
        response_lower = response_text.lower()
        
        print(f"   📊 Analyzing response...")
        print(f"      Status: {status_code}")
        print(f"      Content length: {len(response_text)} chars")
        print(f"      URL: {original_url} → {final_url}")
        
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
            confidence_score -= 25
            print("      ❌ Password field still present")
        else:
            analysis_steps.append("✅ No password field found")
            confidence_score += 20
            print("      ✅ No password field found")
        
        # Step 2: Strong management indicators (HIGH VALUE)
        strong_indicators = {
            'logout': 20, 'log out': 20, 'sign out': 20, 'signout': 20,
            'dashboard': 15, 'administration': 15, 'admin panel': 15,
            'management console': 12, 'management panel': 12,
            'configuration': 10, 'system status': 10, 'device status': 10,
            'router status': 10, 'network status': 10
        }
        
        strong_found = []
        strong_score = 0
        for indicator, weight in strong_indicators.items():
            count = response_lower.count(indicator)
            if count > 0:
                contribution = weight * min(count, 2)  # Cap at 2 occurrences
                confidence_score += contribution
                strong_score += contribution
                strong_found.append(f"{indicator}({count})")
        
        if strong_found:
            analysis_steps.append(f"✅ Strong indicators: {', '.join(strong_found[:3])}")
            print(f"      ✅ Strong indicators: {', '.join(strong_found[:3])}")
        else:
            analysis_steps.append("❌ No strong management indicators")
            print("      ❌ No strong management indicators")
        
        # Step 3: Medium management indicators
        medium_indicators = {
            'wireless': 8, 'network': 8, 'wan': 8, 'lan': 8, 'wifi': 8,
            'firewall': 6, 'nat': 6, 'dhcp': 6, 'qos': 6, 'vpn': 6,
            'port forwarding': 6, 'access control': 6, 'security': 6,
            'firmware': 5, 'backup': 5, 'restore': 5, 'reboot': 5,
            'router': 4, 'modem': 4, 'gateway': 4, 'settings': 4
        }
        
        medium_found = []
        medium_score = 0
        for indicator, weight in medium_indicators.items():
            count = response_lower.count(indicator)
            if count > 0:
                contribution = weight * min(count, 2)
                confidence_score += contribution
                medium_score += contribution
                medium_found.append(f"{indicator}({count})")
        
        if medium_found:
            analysis_steps.append(f"✅ Medium indicators: {', '.join(medium_found[:3])}")
            print(f"      ✅ Medium indicators: {', '.join(medium_found[:3])}")
        
        # Step 4: Negative indicators (LOGIN PAGE ELEMENTS)
        negative_indicators = {
            'login': -8, 'sign in': -8, 'please login': -12,
            'username': -5, 'user name': -5, 'enter username': -8,
            'authentication required': -12, 'access denied': -15,
            'invalid password': -15, 'login failed': -15,
            'forgot password': -8, 'remember me': -5,
            'please enter': -6, 'required field': -4
        }
        
        negative_found = []
        negative_score = 0
        for indicator, weight in negative_indicators.items():
            count = response_lower.count(indicator)
            if count > 0:
                contribution = weight * min(count, 2)  # Negative weight
                confidence_score += contribution
                negative_score += abs(contribution)
                negative_found.append(f"{indicator}({count})")
        
        if negative_found:
            analysis_steps.append(f"❌ Negative indicators: {', '.join(negative_found[:3])}")
            print(f"      ❌ Negative indicators: {', '.join(negative_found[:3])}")
        
        # Step 5: URL analysis
        url_changed = final_url.lower() != original_url.lower()
        if url_changed:
            confidence_score += 15
            analysis_steps.append(f"✅ URL changed")
            print(f"      ✅ URL changed")
        else:
            analysis_steps.append("⚠️ URL unchanged")
            print(f"      ⚠️ URL unchanged")
        
        # Step 6: HTTP status analysis
        if status_code == 200:
            confidence_score += 5
            analysis_steps.append("✅ HTTP 200 OK")
        elif status_code in [301, 302, 303, 307, 308]:
            confidence_score += 12
            analysis_steps.append(f"✅ HTTP {status_code} Redirect")
            print(f"      ✅ HTTP {status_code} Redirect")
        else:
            confidence_score -= 8
            analysis_steps.append(f"⚠️ HTTP {status_code}")
        
        # Step 7: Content analysis
        content_length = len(response_text)
        if content_length > 8000:  # Substantial content
            confidence_score += 8
            analysis_steps.append(f"✅ Rich content: {content_length} chars")
        elif content_length < 500:  # Very short content
            confidence_score -= 8
            analysis_steps.append(f"⚠️ Short content: {content_length} chars")
        
        # Step 8: Look for specific management page elements
        management_elements = [
            r'<title>[^<]*admin[^<]*</title>',
            r'<title>[^<]*management[^<]*</title>',
            r'<title>[^<]*configuration[^<]*</title>',
            r'<title>[^<]*dashboard[^<]*</title>',
            r'href=["\'][^"\']*logout[^"\']*["\']',
            r'onclick=["\'][^"\']*logout[^"\']*["\']',
            r'<form[^>]*action=["\'][^"\']*logout[^"\']*["\']',
            r'<a[^>]*>.*logout.*</a>',
            r'<button[^>]*>.*logout.*</button>'
        ]
        
        element_found = False
        for pattern in management_elements:
            if re.search(pattern, response_lower):
                element_found = True
                confidence_score += 12
                break
        
        if element_found:
            analysis_steps.append("✅ Management page elements found")
            print("      ✅ Management page elements found")
        
        # FINAL DECISION LOGIC
        analysis_steps.append(f"📊 Final confidence score: {confidence_score}")
        print(f"      📊 Final confidence score: {confidence_score}")
        print(f"      📊 Strong score: {strong_score}, Medium score: {medium_score}, Negative score: {negative_score}")
        
        # VERY STRICT thresholds - Password field presence is CRITICAL
        if password_field_found:
            return False, f"LOGIN FAILED - Password field still present (score: {confidence_score})", confidence_score, analysis_steps
        elif confidence_score >= 60 and strong_score >= 30:
            return True, f"HIGH CONFIDENCE management panel (score: {confidence_score})", confidence_score, analysis_steps
        elif confidence_score >= 45 and url_changed and strong_score >= 20:
            return True, f"GOOD CONFIDENCE with URL change (score: {confidence_score})", confidence_score, analysis_steps
        elif confidence_score >= 35 and strong_score >= 40 and negative_score <= 10:
            return True, f"STRONG INDICATORS with minimal negatives (score: {confidence_score})", confidence_score, analysis_steps
        else:
            return False, f"INSUFFICIENT CONFIDENCE - Likely still on login page (score: {confidence_score})", confidence_score, analysis_steps
    
    def test_password_strict(self, target: str, password: str) -> TestResult:
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
                    print(f"   Attempt {i}: {list(login_data.keys())[0]}={password}")
                    
                    # Prepare POST data
                    post_data = urllib.parse.urlencode(login_data).encode('utf-8')
                    
                    # Create request
                    req = urllib.request.Request(url, data=post_data, method='POST')
                    req.add_header('Content-Type', 'application/x-www-form-urlencoded')
                    req.add_header('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
                    
                    # Make request
                    try:
                        with urllib.request.urlopen(req, timeout=15, context=self.ssl_context) as response:
                            final_url = response.geturl()
                            response_text = response.read().decode('utf-8', errors='ignore')
                            status_code = response.getcode()
                    except urllib.error.HTTPError as e:
                        # Handle HTTP errors but still analyze the response
                        final_url = e.geturl() if hasattr(e, 'geturl') else url
                        response_text = e.read().decode('utf-8', errors='ignore') if hasattr(e, 'read') else ""
                        status_code = e.code
                    
                    # STRICT ANALYSIS
                    is_management, reason, confidence, analysis_steps = self.analyze_response_strict(
                        response_text, final_url, url, status_code
                    )
                    
                    verification_steps.extend(analysis_steps)
                    
                    print(f"   Result: {'SUCCESS' if is_management else 'FAILED'} (Confidence: {confidence})")
                    
                    if confidence > best_confidence:
                        best_confidence = confidence
                        best_result = (is_management, reason, confidence)
                    
                    # If we found a high-confidence success, stop trying
                    if is_management and confidence >= 50:
                        break
                        
                except Exception as e:
                    verification_steps.append(f"Attempt {i}: Error - {str(e)}")
                    print(f"   Attempt {i}: Error - {str(e)}")
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
    
    def test_target(self, target: str):
        """Test all passwords with STRICT verification"""
        print(f"\n🎯 STRICT PASSWORD TESTING")
        print(f"Target: {target}")
        print(f"Passwords: {self.password_list}")
        print("=" * 60)
        
        results = []
        
        for i, password in enumerate(self.password_list, 1):
            print(f"\n[{i}/{len(self.password_list)}] STRICT TESTING: {password}")
            print("-" * 50)
            
            result = self.test_password_strict(target, password)
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
            time.sleep(1)
        
        return results

def main():
    print("🚀 FINAL PASSWORD TESTER")
    print("=" * 50)
    print("Pure Python with STRICT multi-step verification")
    print("Uses advanced analysis to detect REAL management panel access")
    print("=" * 50)
    
    parser = argparse.ArgumentParser(description='Final Password Tester')
    parser.add_argument('--target', '-t', required=True, help='Target IP or URL')
    parser.add_argument('--verbose', '-v', action='store_true', help='Show detailed verification steps')
    
    args = parser.parse_args()
    
    print(f"🎯 Target: {args.target}")
    print(f"📝 Verbose: {args.verbose}")
    
    tester = FinalPasswordTester()
    
    try:
        results = tester.test_target(args.target)
        
        # Final results
        print("\n" + "=" * 60)
        print("FINAL STRICT VERIFICATION RESULTS")
        print("=" * 60)
        
        successful = [r for r in results if r.success]
        
        if successful:
            result = successful[0]
            print(f"🎉 REAL LOGIN SUCCESS VERIFIED!")
            print(f"Target: {result.target}")
            print(f"Password: {result.password}")
            print(f"Confidence Score: {result.confidence_score}")
            print(f"Details: {result.details}")
            print(f"Response Time: {result.response_time:.1f}s")
            print(f"Verification Steps: {len(result.verification_steps)}")
            
            if args.verbose:
                print(f"\n📋 Detailed Verification Steps:")
                for step in result.verification_steps:
                    print(f"   {step}")
        else:
            print("❌ NO VALID PASSWORD FOUND")
            print("💡 All passwords failed STRICT verification")
            print("   This means none of the passwords provide REAL access")
            print("\n📊 Confidence Scores:")
            for result in results:
                print(f"   {result.password}: {result.confidence_score}")
            
            if args.verbose and results:
                print(f"\n📋 Last Test Details:")
                for step in results[-1].verification_steps[-8:]:
                    print(f"   {step}")
        
        print(f"\nTotal tests performed: {len(results)}")
        
    except KeyboardInterrupt:
        print("\n⚠️ Testing interrupted by user")
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    main()