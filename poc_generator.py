#!/usr/bin/env python3
"""
🔥 POC GENERATOR - Professional PoC Generation
"""

import asyncio
import hashlib
from pathlib import Path
from datetime import datetime
from typing import Optional, List

try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    SELENIUM_OK = True
except ImportError:
    SELENIUM_OK = False


class PoCGenerator:
    """Professional PoC generation"""
    
    def __init__(self):
        self.driver = None
        self.init_driver()
    
    def init_driver(self):
        """Initialize browser"""
        if not SELENIUM_OK:
            return
        
        try:
            chrome_options = Options()
            chrome_options.add_argument('--headless')
            chrome_options.add_argument('--no-sandbox')
            chrome_options.add_argument('--disable-dev-shm-usage')
            chrome_options.add_argument('--window-size=1920,1080')
            
            self.driver = webdriver.Chrome(options=chrome_options)
            print("[POC] Screenshot system initialized")
        except Exception as e:
            print(f"[POC] Screenshot system failed: {e}")
            self.driver = None
    
    async def take_screenshot(self, url: str, redirect_url: str = None) -> Optional[str]:
        """Take professional screenshot"""
        if not self.driver:
            return None
        
        try:
            screenshots_dir = Path("screenshots")
            screenshots_dir.mkdir(exist_ok=True)
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            url_hash = hashlib.md5(url.encode()).hexdigest()[:8]
            filename = f"ultimate_poc_{timestamp}_{url_hash}.png"
            screenshot_path = screenshots_dir / filename
            
            # Take screenshot
            self.driver.get(url)
            await asyncio.sleep(3)
            self.driver.save_screenshot(str(screenshot_path))
            
            print(f"[POC] Screenshot saved: {screenshot_path}")
            return str(screenshot_path)
            
        except Exception as e:
            print(f"[POC-ERROR] Screenshot failed: {e}")
            return None
    
    def generate_poc_steps(self, vuln) -> List[str]:
        """Generate PoC steps"""
        return [
            f"1. Navigate to: {vuln.url}",
            f"2. Observe parameter: {vuln.parameter}",
            f"3. Inject payload: {vuln.payload}",
            f"4. Verify redirect to: {vuln.redirect_url}"
        ]
    
    def cleanup(self):
        """Cleanup resources"""
        if self.driver:
            self.driver.quit()