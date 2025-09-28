#!/usr/bin/env python3
"""
Optimized XSS Scanner - Fast and Professional
Phase 1: Fast reconnaissance with requests
Phase 2: Smart XSS validation with browser
Author: AI Assistant
Version: 3.1 Optimized
"""

import requests
import re
import urllib.parse
import time
import json
import threading
import os
from urllib.parse import urljoin, urlparse, parse_qs, urlunparse
from bs4 import BeautifulSoup
import argparse
from colorama import init, Fore, Style
from concurrent.futures import ThreadPoolExecutor, as_completed
import datetime

# Try to import Playwright, fallback if not available
try:
    from playwright.sync_api import sync_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False

# Initialize colorama
init()

class OptimizedXSSScanner:
    def __init__(self, target_url, max_threads=8, delay=0.3, max_depth=2, timeout=10):
        self.target_url = target_url
        self.max_threads = max_threads
        self.delay = delay
        self.max_depth = max_depth
        self.timeout = timeout
        
        # Session configuration
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        })
        
        # Data structures
        self.visited_urls = set()
        self.confirmed_vulnerabilities = []
        self.lock = threading.Lock()
        
        # Browser for validation
        self.browser = None
        self.context = None
        
        # Optimized payloads
        self.payloads = self._load_optimized_payloads()
        
        # Create directories
        self.create_directories()
        
    def create_directories(self):
        """Create necessary directories"""
        os.makedirs('screenshots', exist_ok=True)
        os.makedirs('reports', exist_ok=True)
    
    def log(self, message, level="INFO"):
        """Enhanced logging"""
        colors = {
            "INFO": Fore.CYAN,
            "SUCCESS": Fore.GREEN,
            "WARNING": Fore.YELLOW,
            "ERROR": Fore.RED,
            "VULN": Fore.MAGENTA,
            "PHASE": Fore.CYAN + Style.BRIGHT
        }
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        print(f"{colors.get(level, Fore.WHITE)}[{timestamp}] [{level}] {message}{Style.RESET_ALL}")
    
    def _load_optimized_payloads(self):
        """Load optimized XSS payloads"""
        return [
            '<script>alert("XSS_CONFIRMED")</script>',
            '<img src=x onerror=alert("XSS_CONFIRMED")>',
            '<svg onload=alert("XSS_CONFIRMED")>',
            '<iframe src="javascript:alert(\'XSS_CONFIRMED\')">',
            '<body onload=alert("XSS_CONFIRMED")>',
            '<input onfocus=alert("XSS_CONFIRMED") autofocus>',
            '<script>prompt("XSS_CONFIRMED")</script>',
            '<img src=x onerror=prompt("XSS_CONFIRMED")>',
            '" onmouseover="alert(\'XSS_CONFIRMED\')" x="',
            "' onmouseover='alert(\"XSS_CONFIRMED\")' x='",
            '" onfocus="alert(\'XSS_CONFIRMED\')" autofocus="',
            "' onfocus='alert(\"XSS_CONFIRMED\")' autofocus='"
        ]
    
    def phase1_reconnaissance(self):
        """Phase 1: Fast reconnaissance"""
        self.log("=" * 60, "PHASE")
        self.log("PHASE 1: FAST RECONNAISSANCE", "PHASE")
        self.log("=" * 60, "PHASE")
        
        try:
            # Test target accessibility
            response = self.session.get(self.target_url, timeout=self.timeout)
            response.raise_for_status()
            self.log(f"Target accessible (Status: {response.status_code})", "SUCCESS")
            
            # Fast crawling
            discovered_urls = self._fast_crawl()
            self.log(f"Discovered {len(discovered_urls)} URLs", "SUCCESS")
            
            # Extract data
            forms = self._extract_forms_threaded(discovered_urls)
            self.log(f"Found {len(forms)} forms", "SUCCESS")
            
            return {
                'urls': discovered_urls,
                'forms': forms
            }
            
        except Exception as e:
            self.log(f"Phase 1 failed: {str(e)}", "ERROR")
            return None
    
    def _fast_crawl(self):
        """Fast crawling with threading"""
        urls_to_visit = [(self.target_url, 0)]
        discovered_urls = set()
        base_domain = urlparse(self.target_url).netloc
        
        while urls_to_visit:
            current_url, depth = urls_to_visit.pop(0)
            
            if (current_url in self.visited_urls or 
                depth > self.max_depth or 
                current_url in discovered_urls):
                continue
            
            self.visited_urls.add(current_url)
            discovered_urls.add(current_url)
            
            try:
                response = self.session.get(current_url, timeout=3)
                response.raise_for_status()
                
                # Extract links
                links = self._extract_links(response.text, current_url)
                
                # Add same-origin links
                for link in links:
                    parsed = urlparse(link)
                    if (parsed.scheme in ('http', 'https') and 
                        parsed.netloc == base_domain and
                        link not in discovered_urls and
                        not self._is_static_resource(link)):
                        urls_to_visit.append((link, depth + 1))
                
                time.sleep(0.1)  # Minimal delay
                
            except Exception:
                continue
        
        return list(discovered_urls)
    
    def _extract_links(self, html_content, base_url):
        """Extract links from HTML"""
        links = []
        soup = BeautifulSoup(html_content, 'html.parser')
        
        for link in soup.find_all('a', href=True):
            href = link['href']
            full_url = urljoin(base_url, href)
            links.append(full_url)
        
        return links
    
    def _is_static_resource(self, url):
        """Check if URL is static resource"""
        static_extensions = ['.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.ico', '.svg', '.pdf']
        return any(url.lower().endswith(ext) for ext in static_extensions)
    
    def _extract_forms_threaded(self, urls):
        """Extract forms using threading"""
        all_forms = []
        
        def extract_forms_from_url(url):
            try:
                response = self.session.get(url, timeout=5)
                response.raise_for_status()
                
                forms = []
                soup = BeautifulSoup(response.text, 'html.parser')
                
                for form in soup.find_all('form'):
                    form_data = {
                        'url': url,
                        'action': form.get('action', ''),
                        'method': form.get('method', 'GET').upper(),
                        'inputs': []
                    }
                    
                    for input_tag in form.find_all(['input', 'textarea', 'select']):
                        input_data = {
                            'name': input_tag.get('name', ''),
                            'type': input_tag.get('type', 'text'),
                            'value': input_tag.get('value', '')
                        }
                        form_data['inputs'].append(input_data)
                    
                    # Convert action to absolute URL
                    if form_data['action']:
                        form_data['action'] = urljoin(url, form_data['action'])
                    else:
                        form_data['action'] = url
                    
                    forms.append(form_data)
                
                return forms
                
            except Exception:
                return []
        
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = [executor.submit(extract_forms_from_url, url) for url in urls]
            
            for future in as_completed(futures):
                try:
                    forms = future.result()
                    all_forms.extend(forms)
                except Exception:
                    continue
        
        return all_forms
    
    def phase2_xss_validation(self, recon_data):
        """Phase 2: XSS validation"""
        self.log("=" * 60, "PHASE")
        self.log("PHASE 2: XSS VALIDATION", "PHASE")
        self.log("=" * 60, "PHASE")
        
        if not PLAYWRIGHT_AVAILABLE:
            self.log("Playwright not available, using string matching", "WARNING")
            self._string_matching_validation(recon_data)
            return
        
        if not self._init_browser():
            self.log("Browser init failed, using string matching", "WARNING")
            self._string_matching_validation(recon_data)
            return
        
        try:
            # Test forms
            for form in recon_data['forms']:
                self._test_form_browser(form)
            
            # Test URL parameters
            for url in recon_data['urls']:
                params = self._extract_parameters(url)
                for param_name in params:
                    self._test_parameter_browser(url, param_name)
            
            self._close_browser()
            
        except Exception as e:
            self.log(f"Phase 2 failed: {str(e)}", "ERROR")
            self._close_browser()
    
    def _extract_parameters(self, url):
        """Extract parameters from URL"""
        parsed_url = urlparse(url)
        params = parse_qs(parsed_url.query)
        return params
    
    def _init_browser(self):
        """Initialize browser"""
        try:
            playwright = sync_playwright().start()
            self.browser = playwright.chromium.launch(headless=True, args=['--no-sandbox'])
            self.context = self.browser.new_context()
            return True
        except Exception as e:
            self.log(f"Browser init error: {str(e)}", "ERROR")
            return False
    
    def _close_browser(self):
        """Close browser"""
        try:
            if self.context:
                self.context.close()
            if self.browser:
                self.browser.close()
        except Exception:
            pass
    
    def _test_form_browser(self, form):
        """Test form with browser"""
        for input_field in form['inputs']:
            if input_field['name']:
                for payload in self.payloads:
                    try:
                        # Prepare form data
                        form_data = {}
                        for field in form['inputs']:
                            if field['name'] == input_field['name']:
                                form_data[field['name']] = payload
                            else:
                                form_data[field['name']] = field['value']
                        
                        # Test with browser
                        if self._validate_xss_browser(form['action'], form_data, payload, input_field['name']):
                            return True
                        
                        time.sleep(self.delay)
                        
                    except Exception:
                        continue
        return False
    
    def _test_parameter_browser(self, url, param_name):
        """Test parameter with browser"""
        for payload in self.payloads:
            try:
                test_url = f"{url}?{param_name}={urllib.parse.quote(payload)}"
                
                if self._validate_xss_browser(test_url, None, payload, param_name):
                    return True
                
                time.sleep(self.delay)
                
            except Exception:
                continue
        return False
    
    def _validate_xss_browser(self, url, form_data, payload, param_name):
        """Validate XSS with browser"""
        try:
            page = self.context.new_page()
            
            # Set up alert handler
            alert_dialog = None
            def handle_dialog(dialog):
                nonlocal alert_dialog
                alert_dialog = dialog
                dialog.accept()
            
            page.on("dialog", handle_dialog)
            
            if form_data:
                # Form submission
                page.goto(url, wait_until="networkidle", timeout=10000)
                
                # Fill form
                for field_name, field_value in form_data.items():
                    try:
                        page.fill(f'input[name="{field_name}"], textarea[name="{field_name}"]', field_value)
                    except:
                        pass
                
                # Submit
                page.click('input[type="submit"], button[type="submit"]')
                page.wait_for_load_state("networkidle", timeout=10000)
            else:
                # Direct URL
                page.goto(url, wait_until="networkidle", timeout=10000)
            
            # Wait for potential XSS
            time.sleep(2)
            
            # Check if alert was triggered
            if alert_dialog:
                # Take screenshot
                screenshot_path = self._take_screenshot(page, param_name, payload)
                
                # Add to confirmed vulnerabilities
                with self.lock:
                    vuln = {
                        'url': url,
                        'parameter': param_name,
                        'payload': payload,
                        'screenshot': screenshot_path,
                        'timestamp': datetime.datetime.now().isoformat(),
                        'alert_message': alert_dialog.message
                    }
                    self.confirmed_vulnerabilities.append(vuln)
                    self.log(f"CONFIRMED XSS! Parameter: {param_name}", "VULN")
                    self.log(f"Payload: {payload}", "VULN")
                    self.log(f"Screenshot: {screenshot_path}", "VULN")
                
                page.close()
                return True
            
            page.close()
            return False
            
        except Exception as e:
            self.log(f"Browser validation error: {str(e)}", "ERROR")
            try:
                page.close()
            except:
                pass
            return False
    
    def _take_screenshot(self, page, param_name, payload):
        """Take screenshot"""
        try:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            safe_param = re.sub(r'[^\w\-_]', '_', param_name)
            safe_payload = re.sub(r'[^\w\-_]', '_', payload[:15])
            
            filename = f"xss_{safe_param}_{safe_payload}_{timestamp}.png"
            screenshot_path = os.path.join('screenshots', filename)
            
            page.screenshot(path=screenshot_path, full_page=True)
            return screenshot_path
            
        except Exception as e:
            self.log(f"Screenshot error: {str(e)}", "ERROR")
            return None
    
    def _string_matching_validation(self, recon_data):
        """Fallback string matching validation"""
        self.log("Using string matching validation", "INFO")
        
        for form in recon_data['forms']:
            for input_field in form['inputs']:
                if input_field['name']:
                    for payload in self.payloads:
                        try:
                            # Prepare form data
                            form_data = {}
                            for field in form['inputs']:
                                if field['name'] == input_field['name']:
                                    form_data[field['name']] = payload
                                else:
                                    form_data[field['name']] = field['value']
                            
                            # Test with requests
                            if form['method'] == 'POST':
                                response = self.session.post(form['action'], data=form_data, timeout=self.timeout)
                            else:
                                response = self.session.get(form['action'], params=form_data, timeout=self.timeout)
                            
                            # Check for XSS indicators
                            if self._check_xss_indicators(response.text, payload):
                                with self.lock:
                                    vuln = {
                                        'url': form['action'],
                                        'parameter': input_field['name'],
                                        'payload': payload,
                                        'screenshot': None,
                                        'timestamp': datetime.datetime.now().isoformat(),
                                        'alert_message': 'String matching detection'
                                    }
                                    self.confirmed_vulnerabilities.append(vuln)
                                    self.log(f"POTENTIAL XSS! Parameter: {input_field['name']}", "VULN")
                                    self.log(f"Payload: {payload}", "VULN")
                                
                                break  # Found XSS for this parameter, move to next
                            
                            time.sleep(self.delay)
                            
                        except Exception:
                            continue
        
        # Test URL parameters
        for url in recon_data['urls']:
            params = self._extract_parameters(url)
            for param_name in params:
                for payload in self.payloads:
                    try:
                        test_url = f"{url}?{param_name}={urllib.parse.quote(payload)}"
                        response = self.session.get(test_url, timeout=self.timeout)
                        
                        if self._check_xss_indicators(response.text, payload):
                            with self.lock:
                                vuln = {
                                    'url': url,
                                    'parameter': param_name,
                                    'payload': payload,
                                    'screenshot': None,
                                    'timestamp': datetime.datetime.now().isoformat(),
                                    'alert_message': 'String matching detection'
                                }
                                self.confirmed_vulnerabilities.append(vuln)
                                self.log(f"POTENTIAL XSS! Parameter: {param_name}", "VULN")
                                self.log(f"Payload: {payload}", "VULN")
                            
                            break  # Found XSS for this parameter, move to next
                        
                        time.sleep(self.delay)
                        
                    except Exception:
                        continue
    
    def _check_xss_indicators(self, response_text, payload):
        """Check for XSS indicators in response"""
        # Check if payload is reflected
        if payload in response_text:
            # Check for execution indicators
            execution_indicators = [
                'alert(',
                'prompt(',
                'confirm(',
                '<script>',
                'onerror=',
                'onload=',
                'onclick=',
                'onmouseover='
            ]
            
            for indicator in execution_indicators:
                if indicator in response_text:
                    return True
        
        return False
    
    def generate_html_report(self):
        """Generate HTML report"""
        self.log("Generating HTML report...", "INFO")
        
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = os.path.join('reports', f'xss_report_{timestamp}.html')
        
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>XSS Scanner Report - {self.target_url}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1000px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; }}
        .header {{ text-align: center; border-bottom: 2px solid #e74c3c; padding-bottom: 20px; margin-bottom: 30px; }}
        .header h1 {{ color: #e74c3c; }}
        .summary {{ background: #f8f9fa; padding: 20px; border-radius: 8px; margin-bottom: 30px; }}
        .stats {{ display: flex; justify-content: space-around; margin: 20px 0; }}
        .stat {{ text-align: center; }}
        .stat-number {{ font-size: 2em; font-weight: bold; color: #e74c3c; }}
        .vulnerability {{ background: #fff5f5; border: 1px solid #fecaca; padding: 20px; margin: 20px 0; border-radius: 8px; }}
        .vulnerability h3 {{ color: #dc2626; margin-top: 0; }}
        .screenshot {{ max-width: 100%; border: 1px solid #ddd; margin: 10px 0; }}
        .poc {{ background: #f0f0f0; padding: 10px; border-radius: 5px; font-family: monospace; word-break: break-all; }}
        .no-vulns {{ text-align: center; color: #28a745; font-size: 1.2em; padding: 40px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 XSS Scanner Report</h1>
            <p>Target: {self.target_url}</p>
            <p>Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
        
        <div class="summary">
            <h2>📊 Scan Summary</h2>
            <div class="stats">
                <div class="stat">
                    <div class="stat-number">{len(self.confirmed_vulnerabilities)}</div>
                    <div>Confirmed XSS</div>
                </div>
                <div class="stat">
                    <div class="stat-number">{len(self.visited_urls)}</div>
                    <div>URLs Scanned</div>
                </div>
                <div class="stat">
                    <div class="stat-number">{len(self.payloads)}</div>
                    <div>Payloads Tested</div>
                </div>
            </div>
        </div>
        
        <h2>🎯 XSS Vulnerabilities</h2>
"""
        
        if not self.confirmed_vulnerabilities:
            html_content += '<div class="no-vulns">✅ No XSS vulnerabilities found</div>'
        else:
            for i, vuln in enumerate(self.confirmed_vulnerabilities, 1):
                html_content += f"""
                <div class="vulnerability">
                    <h3>Vulnerability #{i}</h3>
                    <p><strong>URL:</strong> {vuln['url']}</p>
                    <p><strong>Parameter:</strong> {vuln['parameter']}</p>
                    <p><strong>Payload:</strong> {vuln['payload']}</p>
                    <p><strong>Alert Message:</strong> {vuln.get('alert_message', 'N/A')}</p>
                    <p><strong>Timestamp:</strong> {vuln['timestamp']}</p>
                    
                    <strong>POC URL:</strong>
                    <div class="poc">{vuln['url']}?{vuln['parameter']}={urllib.parse.quote(vuln['payload'])}</div>
                    
                    {f'<img src="../{vuln["screenshot"]}" alt="XSS Screenshot" class="screenshot">' if vuln.get('screenshot') else ''}
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
            
            self.log(f"HTML report generated: {report_path}", "SUCCESS")
            return report_path
            
        except Exception as e:
            self.log(f"Error generating report: {str(e)}", "ERROR")
            return None
    
    def scan(self):
        """Main scanning method"""
        start_time = time.time()
        
        self.log("🚀 Starting Optimized XSS Scanner v3.1", "SUCCESS")
        self.log(f"Target: {self.target_url}", "INFO")
        
        try:
            # Phase 1: Fast Reconnaissance
            recon_data = self.phase1_reconnaissance()
            if not recon_data:
                self.log("Phase 1 failed, aborting scan", "ERROR")
                return
            
            # Phase 2: XSS Validation
            self.phase2_xss_validation(recon_data)
            
            # Generate report
            report_path = self.generate_html_report()
            
            # Show results
            self._show_results(report_path)
            
            elapsed_time = time.time() - start_time
            self.log(f"Scan completed in {elapsed_time:.2f} seconds", "SUCCESS")
            
        except Exception as e:
            self.log(f"Scan failed: {str(e)}", "ERROR")
    
    def _show_results(self, report_path):
        """Show scan results"""
        self.log("=" * 60, "PHASE")
        self.log("SCAN RESULTS", "PHASE")
        self.log("=" * 60, "PHASE")
        
        self.log(f"Total confirmed XSS vulnerabilities: {len(self.confirmed_vulnerabilities)}", "SUCCESS")
        
        if self.confirmed_vulnerabilities:
            self.log("\n🎯 CONFIRMED XSS VULNERABILITIES:", "VULN")
            for i, vuln in enumerate(self.confirmed_vulnerabilities, 1):
                self.log(f"\n--- Vulnerability #{i} ---", "VULN")
                self.log(f"URL: {vuln['url']}", "VULN")
                self.log(f"Parameter: {vuln['parameter']}", "VULN")
                self.log(f"Payload: {vuln['payload']}", "VULN")
                if vuln.get('screenshot'):
                    self.log(f"Screenshot: {vuln['screenshot']}", "VULN")
        
        if report_path:
            self.log(f"\n📄 HTML Report: {report_path}", "SUCCESS")

def main():
    parser = argparse.ArgumentParser(description='Optimized XSS Scanner v3.1')
    parser.add_argument('url', help='Target URL to scan')
    parser.add_argument('-t', '--threads', type=int, default=8, help='Number of threads (default: 8)')
    parser.add_argument('-d', '--delay', type=float, default=0.3, help='Delay between requests (default: 0.3)')
    parser.add_argument('--depth', type=int, default=2, help='Crawling depth (default: 2)')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout (default: 10)')
    
    args = parser.parse_args()
    
    scanner = OptimizedXSSScanner(
        args.url,
        args.threads,
        args.delay,
        args.depth,
        args.timeout
    )
    
    scanner.scan()

if __name__ == "__main__":
    main()