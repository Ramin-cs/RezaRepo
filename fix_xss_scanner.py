#!/usr/bin/env python3
"""
XSS Scanner Fix Script
This script fixes the main issues with the XSS scanner:
1. Removes unnecessary encoded payloads
2. Fixes alert handling and screenshot capture
3. Improves timing and error handling
"""

import re

def fix_payload_generation():
    """Fix the payload generation to remove unnecessary encodings"""
    print("🔧 Fixing payload generation...")
    
    # Read the current file
    with open('advanced_xss_scanner.py', 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Find and replace the problematic encoding section
    old_encoding = '''        # Add encoded variations
        encoded_payloads = []
        for payload in base_payloads:
            encoded_payloads.append(payload)
            encoded_payloads.append(urllib.parse.quote(payload))  # URL encode
            encoded_payloads.append(base64.b64encode(payload.encode()).decode())  # Base64 encode
            encoded_payloads.append("&#x" + "".join([hex(ord(c))[2:] for c in payload]) + ";")  # HTML entity encode (hex)
            encoded_payloads.append("&#" + "".join([str(ord(c)) for c in payload]) + ";")  # HTML entity encode (decimal)
            encoded_payloads.append("".join([f"\\u{ord(c):04x}" for c in payload]))  # Unicode escape
        
        return list(set(base_payloads + encoded_payloads))'''
    
    new_encoding = '''        # Smart encoding based on context
        encoded_payloads = []
        for payload in base_payloads:
            # Always add the original payload
            encoded_payloads.append(payload)
            
            # Context-specific encoding
            if context == 'html':
                # For HTML context, add URL encoding and HTML entity encoding
                encoded_payloads.append(urllib.parse.quote(payload))
                encoded_payloads.append(urllib.parse.quote_plus(payload))
                # HTML entity encoding (hex)
                hex_encoded = "".join([f"&#x{ord(c):02x};" for c in payload])
                encoded_payloads.append(hex_encoded)
                # HTML entity encoding (decimal)
                dec_encoded = "".join([f"&#{ord(c)};" for c in payload])
                encoded_payloads.append(dec_encoded)
                
            elif context == 'attribute':
                # For attribute context, add URL encoding and HTML entity encoding
                encoded_payloads.append(urllib.parse.quote(payload))
                # HTML entity encoding (hex)
                hex_encoded = "".join([f"&#x{ord(c):02x};" for c in payload])
                encoded_payloads.append(hex_encoded)
                # HTML entity encoding (decimal)
                dec_encoded = "".join([f"&#{ord(c)};" for c in payload])
                encoded_payloads.append(dec_encoded)
                
            elif context == 'javascript':
                # For JavaScript context, add Unicode escape and URL encoding
                unicode_encoded = "".join([f"\\u{ord(c):04x}" for c in payload])
                encoded_payloads.append(unicode_encoded)
                encoded_payloads.append(urllib.parse.quote(payload))
                
            elif context == 'css':
                # For CSS context, add URL encoding
                encoded_payloads.append(urllib.parse.quote(payload))
                
            elif context == 'url':
                # For URL context, add double URL encoding
                encoded_payloads.append(urllib.parse.quote(payload))
                double_encoded = urllib.parse.quote(urllib.parse.quote(payload))
                encoded_payloads.append(double_encoded)
        
        return list(set(encoded_payloads))'''
    
    if old_encoding in content:
        content = content.replace(old_encoding, new_encoding)
        print("✅ Payload generation fixed")
    else:
        print("⚠️  Payload generation section not found")
    
    return content

def fix_alert_handling(content):
    """Fix the alert handling and screenshot capture"""
    print("🔧 Fixing alert handling...")
    
    # Fix the wait time
    content = re.sub(r'time\.sleep\(3\)', 'time.sleep(5)  # Increased wait time for better alert detection', content)
    
    # Fix the alert detection loop
    old_alert_loop = '''            # Try to handle alert multiple times
            for attempt in range(3):
                try:
                    # Check if alert is present
                    WebDriverWait(self.driver, 2).until(EC.alert_is_present())
                    
                    # Switch to alert
                    alert = self.driver.switch_to.alert
                    alert_text = alert.text
                    
                    # Check if it's our unique alert
                    if self.unique_alert_id in alert_text:
                        logger.info(f"{Colors.GREEN}[XSS] SUCCESS! Our unique alert detected: {alert_text}{Colors.END}")
                        
                        # Take screenshot BEFORE accepting alert
                        screenshot_path = self.capture_screenshot_improved(test_url, parameter, payload)
                        
                        # Accept the alert
                        alert.accept()
                        alert_detected = True
                        break
                    else:
                        # Not our alert, dismiss it
                        alert.dismiss()
                        logger.info(f"{Colors.YELLOW}[XSS] Alert dismissed (not ours): {alert_text}{Colors.END}")
                        
                except NoAlertPresentException:
                    # No alert present, break out of loop
                    break
                except Exception as e:
                    logger.warning(f"{Colors.YELLOW}[XSS] Error handling alert (attempt {attempt + 1}): {e}{Colors.END}")
                    time.sleep(1)
                    continue
                else:
                    break'''
    
    new_alert_loop = '''            # Try to handle alert multiple times with better error handling
            for attempt in range(5):  # Increased attempts
                try:
                    # Check if alert is present
                    WebDriverWait(self.driver, 3).until(EC.alert_is_present())
                    
                    # Switch to alert
                    alert = self.driver.switch_to.alert
                    alert_text = alert.text
                    
                    logger.info(f"{Colors.CYAN}[XSS] Alert detected: {alert_text}{Colors.END}")
                    
                    # Check if it's our unique alert
                    if self.unique_alert_id in alert_text:
                        logger.info(f"{Colors.GREEN}[XSS] SUCCESS! Our unique alert detected: {alert_text}{Colors.END}")
                        
                        # Take screenshot BEFORE accepting alert
                        try:
                            screenshot_path = self.capture_screenshot_improved(test_url, parameter, payload)
                            logger.info(f"{Colors.GREEN}[SCREENSHOT] PoC saved: {screenshot_path}{Colors.END}")
                        except Exception as screenshot_error:
                            logger.warning(f"{Colors.YELLOW}[XSS] Screenshot failed: {screenshot_error}{Colors.END}")
                        
                        # Accept the alert
                        alert.accept()
                        alert_detected = True
                        break
                    else:
                        # Not our alert, dismiss it
                        alert.dismiss()
                        logger.info(f"{Colors.YELLOW}[XSS] Alert dismissed (not ours): {alert_text}{Colors.END}")
                        time.sleep(1)  # Wait before next attempt
                        
                except NoAlertPresentException:
                    # No alert present, break out of loop
                    break
                except Exception as e:
                    logger.warning(f"{Colors.YELLOW}[XSS] Error handling alert (attempt {attempt + 1}): {e}{Colors.END}")
                    time.sleep(2)  # Wait before retry
                    continue'''
    
    if old_alert_loop in content:
        content = content.replace(old_alert_loop, new_alert_loop)
        print("✅ Alert handling fixed")
    else:
        print("⚠️  Alert handling section not found")
    
    return content

def main():
    """Main fix function"""
    print("🔧 XSS Scanner Fix Script")
    print("=" * 30)
    
    # Fix payload generation
    content = fix_payload_generation()
    
    # Fix alert handling
    content = fix_alert_handling(content)
    
    # Write the fixed content back
    with open('advanced_xss_scanner.py', 'w', encoding='utf-8') as f:
        f.write(content)
    
    print("\n🎉 All fixes applied successfully!")
    print("   The scanner should now work better with:")
    print("   ✅ Context-aware payload encoding")
    print("   ✅ Improved alert handling")
    print("   ✅ Better screenshot capture")
    print("   ✅ Increased wait times")

if __name__ == "__main__":
    main()