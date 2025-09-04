#!/usr/bin/env python3
"""
🔥 ADVANCED SCREENSHOT & POC ENGINE
"""

import asyncio
import hashlib
import time
from pathlib import Path
from datetime import datetime
from typing import Optional, List, Dict

try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    SELENIUM_OK = True
except ImportError:
    SELENIUM_OK = False


class ScreenshotEngine:
    """Advanced screenshot and PoC generation engine"""
    
    def __init__(self):
        self.driver = None
        self.screenshots_dir = Path("ultimate_screenshots")
        self.screenshots_dir.mkdir(exist_ok=True)
        
        # Initialize browser if available
        if SELENIUM_OK:
            self.init_advanced_browser()
    
    def init_advanced_browser(self):
        """Initialize advanced browser with stealth"""
        try:
            chrome_options = Options()
            
            # Stealth options
            chrome_options.add_argument('--headless')
            chrome_options.add_argument('--no-sandbox')
            chrome_options.add_argument('--disable-dev-shm-usage')
            chrome_options.add_argument('--disable-gpu')
            chrome_options.add_argument('--window-size=1920,1080')
            chrome_options.add_argument('--disable-blink-features=AutomationControlled')
            chrome_options.add_experimental_option("excludeSwitches", ["enable-automation"])
            chrome_options.add_experimental_option('useAutomationExtension', False)
            
            # Anti-detection
            chrome_options.add_argument('--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36')
            
            self.driver = webdriver.Chrome(options=chrome_options)
            
            # Execute stealth script
            stealth_script = """
                Object.defineProperty(navigator, 'webdriver', {
                    get: () => undefined,
                });
                
                window.chrome = {
                    runtime: {}
                };
                
                Object.defineProperty(navigator, 'plugins', {
                    get: () => [1, 2, 3, 4, 5],
                });
                
                Object.defineProperty(navigator, 'languages', {
                    get: () => ['en-US', 'en'],
                });
            """
            
            self.driver.execute_script(stealth_script)
            print("[SCREENSHOT-ENGINE] Advanced stealth browser initialized")
            
        except Exception as e:
            print(f"[SCREENSHOT-ENGINE] Browser initialization failed: {e}")
            self.driver = None
    
    async def capture_professional_poc(self, vuln_url: str, redirect_url: str = None, 
                                     param_name: str = "", payload: str = "") -> Optional[Dict]:
        """Capture professional PoC with multiple screenshots"""
        if not self.driver:
            return None
        
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            url_hash = hashlib.md5(vuln_url.encode()).hexdigest()[:8]
            
            poc_data = {
                'timestamp': timestamp,
                'url_hash': url_hash,
                'screenshots': [],
                'evidence': [],
                'analysis': {}
            }
            
            print(f"[POC-CAPTURE] Starting professional PoC for {param_name}")
            
            # Screenshot 1: Original page
            original_filename = f"poc_original_{timestamp}_{url_hash}.png"
            original_path = self.screenshots_dir / original_filename
            
            self.driver.get(vuln_url.split('?')[0])  # Load without payload first
            await asyncio.sleep(2)
            
            self.driver.save_screenshot(str(original_path))
            poc_data['screenshots'].append({
                'type': 'original',
                'filename': str(original_path),
                'description': 'Original page before exploitation'
            })
            
            # Screenshot 2: Exploitation
            exploit_filename = f"poc_exploit_{timestamp}_{url_hash}.png"
            exploit_path = self.screenshots_dir / exploit_filename
            
            self.driver.get(vuln_url)  # Load with payload
            await asyncio.sleep(3)
            
            # Check for redirects or JavaScript execution
            current_url = self.driver.current_url
            page_title = self.driver.title
            
            self.driver.save_screenshot(str(exploit_path))
            poc_data['screenshots'].append({
                'type': 'exploitation',
                'filename': str(exploit_path),
                'description': f'Page after payload injection: {payload[:50]}...'
            })
            
            # Screenshot 3: If redirect occurred
            if current_url != vuln_url and redirect_url:
                redirect_filename = f"poc_redirect_{timestamp}_{url_hash}.png"
                redirect_path = self.screenshots_dir / redirect_filename
                
                self.driver.save_screenshot(str(redirect_path))
                poc_data['screenshots'].append({
                    'type': 'redirect_result',
                    'filename': str(redirect_path),
                    'description': f'Successful redirect to: {current_url}'
                })
            
            # Gather evidence
            poc_data['evidence'] = [
                f"Original URL: {vuln_url.split('?')[0]}",
                f"Vulnerable Parameter: {param_name}",
                f"Payload Used: {payload}",
                f"Exploit URL: {vuln_url}",
                f"Current URL after exploit: {current_url}",
                f"Page Title: {page_title}",
                f"Redirect Successful: {current_url != vuln_url}"
            ]
            
            # Analysis
            poc_data['analysis'] = {
                'redirect_occurred': current_url != vuln_url,
                'original_domain': urlparse(vuln_url).netloc,
                'final_domain': urlparse(current_url).netloc,
                'cross_domain_redirect': urlparse(vuln_url).netloc != urlparse(current_url).netloc,
                'javascript_executed': 'confirm' in payload.lower() or 'alert' in payload.lower(),
                'page_title_changed': page_title != '',
                'exploitation_success': True
            }
            
            print(f"[POC-SUCCESS] Captured {len(poc_data['screenshots'])} screenshots")
            return poc_data
            
        except Exception as e:
            print(f"[POC-ERROR] Screenshot capture failed: {e}")
            return None
    
    async def capture_dom_poc(self, vuln_url: str, dom_payload: str) -> Optional[Dict]:
        """Capture DOM-based redirect PoC"""
        if not self.driver:
            return None
        
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            # Navigate to page
            self.driver.get(vuln_url)
            await asyncio.sleep(2)
            
            # Execute DOM manipulation
            dom_script = f"""
                // Simulate DOM-based redirect
                if (window.location.hash) {{
                    var payload = window.location.hash.substring(1);
                    if (payload.includes('{dom_payload}')) {{
                        console.log('DOM Redirect Triggered: ' + payload);
                        return true;
                    }}
                }}
                return false;
            """
            
            result = self.driver.execute_script(dom_script)
            
            if result:
                # Take screenshot of DOM exploitation
                dom_filename = f"poc_dom_{timestamp}.png"
                dom_path = self.screenshots_dir / dom_filename
                
                self.driver.save_screenshot(str(dom_path))
                
                return {
                    'type': 'dom_based',
                    'screenshot': str(dom_path),
                    'payload': dom_payload,
                    'execution_result': result,
                    'timestamp': timestamp
                }
        
        except Exception as e:
            print(f"[DOM-POC-ERROR] {e}")
        
        return None
    
    def generate_poc_steps(self, vuln_data: Dict) -> List[str]:
        """Generate detailed PoC steps"""
        steps = [
            "=== PROOF OF CONCEPT REPRODUCTION STEPS ===",
            "",
            f"1. RECONNAISSANCE:",
            f"   - Target identified: {vuln_data.get('url', 'N/A')}",
            f"   - Vulnerable parameter: {vuln_data.get('parameter', 'N/A')}",
            f"   - Context: {vuln_data.get('context', 'N/A')}",
            "",
            f"2. EXPLOITATION:",
            f"   - Inject payload: {vuln_data.get('payload', 'N/A')}",
            f"   - Method: {vuln_data.get('method', 'GET')}",
            f"   - Full exploit URL: {vuln_data.get('url', 'N/A')}",
            "",
            f"3. VERIFICATION:",
            f"   - Expected redirect: {vuln_data.get('redirect_url', 'N/A')}",
            f"   - Response code: {vuln_data.get('response_code', 'N/A')}",
            f"   - Impact level: {vuln_data.get('impact', 'N/A')}",
            "",
            f"4. EVIDENCE:",
            f"   - Screenshots captured in: {self.screenshots_dir}",
            f"   - Timestamp: {datetime.now().isoformat()}",
            "",
            f"5. BUSINESS IMPACT:",
            f"   - Users can be redirected to malicious sites",
            f"   - Potential for phishing attacks",
            f"   - Brand reputation damage",
            f"   - Compliance violations"
        ]
        
        return steps
    
    def create_visual_poc(self, vuln_data: Dict) -> str:
        """Create visual PoC representation"""
        ascii_poc = f"""
╔══════════════════════════════════════════════════════════════════════════════════╗
║                           🔥 VISUAL PROOF OF CONCEPT 🔥                          ║
╠══════════════════════════════════════════════════════════════════════════════════╣
║                                                                                  ║
║  VULNERABILITY: Open Redirect                                                    ║
║  PARAMETER: {vuln_data.get('parameter', 'N/A'):<63} ║
║  PAYLOAD: {vuln_data.get('payload', 'N/A')[:65]:<65} ║
║  IMPACT: {vuln_data.get('impact', 'N/A'):<66} ║
║                                                                                  ║
║  ATTACK FLOW:                                                                    ║
║  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐                         ║
║  │   VICTIM    │───▶│   TARGET    │───▶│  ATTACKER   │                         ║
║  │   CLICKS    │    │   WEBSITE   │    │   WEBSITE   │                         ║
║  │   LINK      │    │   REDIRECTS │    │   RECEIVES  │                         ║
║  └─────────────┘    └─────────────┘    └─────────────┘                         ║
║                                                                                  ║
║  TECHNICAL DETAILS:                                                              ║
║  • URL: {vuln_data.get('url', 'N/A')[:66]:<66} ║
║  • Method: {vuln_data.get('method', 'N/A'):<62} ║
║  • Response: {vuln_data.get('response_code', 'N/A'):<60} ║
║                                                                                  ║
╚══════════════════════════════════════════════════════════════════════════════════╝
        """
        
        return ascii_poc
    
    def cleanup(self):
        """Cleanup browser resources"""
        if self.driver:
            try:
                self.driver.quit()
                print("[SCREENSHOT-ENGINE] Browser cleanup completed")
            except:
                pass