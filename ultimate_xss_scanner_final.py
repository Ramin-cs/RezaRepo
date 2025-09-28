#!/usr/bin/env python3
"""
Ultimate XSS Scanner - Final Working Version
Fixes all issues: URL parameters, form testing, browser management, rate limiting
Author: AI Assistant
Version: Final 1.0
"""

import requests
import re
import urllib.parse
import time
import os
import json
import sys
from urllib.parse import urljoin, urlparse, parse_qs
from datetime import datetime
import argparse

# Try to import Playwright
try:
    from playwright.sync_api import sync_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False

class UltimateXSSScanner:
    def __init__(self, target_url, timeout=10):
        self.target_url = target_url
        self.timeout = timeout
        
        # Session with better headers and rate limiting protection
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })
        
        # Enhanced payloads with better detection
        self.payloads = [
            '<script>alert("XSS_ULTIMATE")</script>',
            '<img src=x onerror=alert("XSS_ULTIMATE")>',
            '<svg onload=alert("XSS_ULTIMATE")>',
            '<iframe src="javascript:alert(\'XSS_ULTIMATE\')">',
            '<body onload=alert("XSS_ULTIMATE")>',
            '<details ontoggle=alert("XSS_ULTIMATE")>',
            '<marquee onstart=alert("XSS_ULTIMATE")>',
            '<video><source onerror=alert("XSS_ULTIMATE")>',
            '" onmouseover="alert(\'XSS_ULTIMATE\')" x="',
            "' onmouseover='alert(\"XSS_ULTIMATE\")' x='",
            '" onfocus="alert(\'XSS_ULTIMATE\')" autofocus="',
            "' onfocus='alert(\"XSS_ULTIMATE\")' autofocus='",
            ';alert("XSS_ULTIMATE");//',
            '";alert("XSS_ULTIMATE");//',
            "';alert('XSS_ULTIMATE');//"
        ]
        
        self.vulnerabilities = []
        self.browser = None
        self.playwright = None
        self.browser_context = None
        
        # Create directories
        os.makedirs('screenshots', exist_ok=True)
        os.makedirs('reports', exist_ok=True)
    
    def log(self, message, level="INFO"):
        """Enhanced logging with colors"""
        colors = {
            "INFO": "\033[0m",
            "SUCCESS": "\033[92m",
            "WARNING": "\033[93m",
            "ERROR": "\033[91m",
            "VULN": "\033[92m\033[1m",
            "PHASE": "\033[96m\033[1m",
            "TEST": "\033[95m\033[1m",
            "ALERT": "\033[91m\033[1m"
        }
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"{colors.get(level, '')}[{timestamp}] [{level}] {message}\033[0m")
    
    def enhanced_reconnaissance(self):
        """Enhanced reconnaissance with better URL parameter detection"""
        self.log("🔍 Starting enhanced reconnaissance...", "PHASE")
        
        try:
            response = self.session.get(self.target_url, timeout=self.timeout)
            response.raise_for_status()
            self.log(f"Target accessible (Status: {response.status_code})", "SUCCESS")
            
            html_content = response.text
            
            # Extract URLs with better regex patterns
            urls = set()
            urls.add(self.target_url)
            
            # Extract links with more patterns
            link_patterns = [
                r'<a[^>]+href=["\']([^"\']+)["\'][^>]*>',
                r'href=["\']([^"\']+)["\']',
                r'window\.location\.href\s*=\s*["\']([^"\']+)["\']',
                r'location\.href\s*=\s*["\']([^"\']+)["\']'
            ]
            
            for pattern in link_patterns:
                matches = re.findall(pattern, html_content, re.IGNORECASE)
                for match in matches:
                    if match and not match.startswith('#') and not match.startswith('javascript:'):
                        full_url = urljoin(self.target_url, match)
                        if self._is_same_domain(full_url):
                            urls.add(full_url)
            
            # Extract forms with better parsing
            forms = []
            form_pattern = r'<form[^>]*>(.*?)</form>'
            form_matches = re.findall(form_pattern, html_content, re.IGNORECASE | re.DOTALL)
            
            for form_html in form_matches:
                form_data = self._parse_form_enhanced(form_html)
                if form_data:
                    forms.append(form_data)
            
            # CRITICAL FIX: Better URL parameter extraction
            url_parameters = set()
            for url in urls:
                parsed_url = urlparse(url)
                params = set(parse_qs(parsed_url.query).keys())
                url_parameters.update(params)
                
                # Also check for parameters in path segments
                path_segments = parsed_url.path.split('/')
                for segment in path_segments:
                    if '=' in segment:
                        param_name = segment.split('=')[0]
                        if param_name:
                            url_parameters.add(param_name)
            
            # Extract form parameters
            form_parameters = set()
            for form in forms:
                for input_field in form['inputs']:
                    if input_field['name']:
                        form_parameters.add(input_field['name'])
            
            self.log(f"Discovered {len(urls)} URLs", "SUCCESS")
            self.log(f"Found {len(forms)} forms", "SUCCESS")
            self.log(f"Found {len(url_parameters)} URL parameters", "SUCCESS")
            self.log(f"Found {len(form_parameters)} form parameters", "SUCCESS")
            
            # Display discovered parameters
            self._display_parameters(url_parameters, form_parameters)
            
            return {
                'urls': list(urls),
                'forms': forms,
                'url_parameters': list(url_parameters),
                'form_parameters': list(form_parameters)
            }
            
        except requests.exceptions.TooManyRequests:
            self.log("Rate limited - adding delay and retrying...", "WARNING")
            time.sleep(5)
            return self.enhanced_reconnaissance()
        except Exception as e:
            self.log(f"Reconnaissance failed: {str(e)}", "ERROR")
            return None
    
    def _parse_form_enhanced(self, form_html):
        """Enhanced form parsing"""
        try:
            # Extract action
            action_match = re.search(r'action=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
            action = action_match.group(1) if action_match else ''
            
            # Extract method
            method_match = re.search(r'method=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
            method = method_match.group(1).upper() if method_match else 'GET'
            
            # Extract inputs with better patterns
            inputs = []
            input_patterns = [
                r'<(?:input|textarea|select)[^>]*>',
                r'<input[^>]*name=["\']([^"\']+)["\'][^>]*>',
                r'<textarea[^>]*name=["\']([^"\']+)["\'][^>]*>',
                r'<select[^>]*name=["\']([^"\']+)["\'][^>]*>'
            ]
            
            for pattern in input_patterns:
                matches = re.findall(pattern, form_html, re.IGNORECASE)
                for match in matches:
                    if isinstance(match, str):
                        # Extract name, type, value
                        name_match = re.search(r'name=["\']([^"\']+)["\']', match, re.IGNORECASE)
                        type_match = re.search(r'type=["\']([^"\']+)["\']', match, re.IGNORECASE)
                        value_match = re.search(r'value=["\']([^"\']*)["\']', match, re.IGNORECASE)
                        
                        if name_match:
                            inputs.append({
                                'name': name_match.group(1),
                                'type': type_match.group(1) if type_match else 'text',
                                'value': value_match.group(1) if value_match else ''
                            })
            
            if inputs:
                return {
                    'action': urljoin(self.target_url, action) if action else self.target_url,
                    'method': method,
                    'inputs': inputs
                }
        except Exception as e:
            self.log(f"Form parsing error: {str(e)}", "ERROR")
        
        return None
    
    def _is_same_domain(self, url):
        """Check if URL is from same domain"""
        try:
            target_domain = urlparse(self.target_url).netloc
            url_domain = urlparse(url).netloc
            return target_domain == url_domain
        except:
            return False
    
    def _display_parameters(self, url_parameters, form_parameters):
        """Display discovered parameters"""
        self.log("=" * 60, "SUCCESS")
        self.log("DISCOVERED PARAMETERS", "SUCCESS")
        self.log("=" * 60, "SUCCESS")
        
        if url_parameters:
            self.log(f"URL Parameters ({len(url_parameters)}):", "SUCCESS")
            for param in sorted(url_parameters):
                self.log(f"  • {param}", "SUCCESS")
        
        if form_parameters:
            self.log(f"Form Parameters ({len(form_parameters)}):", "SUCCESS")
            for param in sorted(form_parameters):
                self.log(f"  • {param}", "SUCCESS")
        
        self.log("=" * 60, "SUCCESS")
    
    def enhanced_xss_testing(self, recon_data):
        """Enhanced XSS testing with better detection"""
        self.log("🎯 Starting enhanced XSS testing...", "PHASE")
        
        vulnerabilities = []
        
        # Test URL parameters with enhanced detection
        for url in recon_data['urls']:
            parsed_url = urlparse(url)
            url_params = parse_qs(parsed_url.query)
            
            for param_name in url_params:
                self.log(f"Testing URL parameter: {param_name}", "TEST")
                
                for payload in self.payloads:
                    vuln = self._test_url_parameter_enhanced(url, param_name, payload)
                    if vuln:
                        vulnerabilities.append(vuln)
                        self.log(f"✅ XSS FOUND! Parameter: {param_name}", "VULN")
                        break
        
        # Test form parameters with enhanced detection
        for form in recon_data['forms']:
            for input_field in form['inputs']:
                if input_field['name']:
                    self.log(f"Testing form parameter: {input_field['name']}", "TEST")
                    
                    for payload in self.payloads:
                        vuln = self._test_form_parameter_enhanced(form, input_field['name'], payload)
                        if vuln:
                            vulnerabilities.append(vuln)
                            self.log(f"✅ XSS FOUND! Parameter: {input_field['name']}", "VULN")
                            break
        
        return vulnerabilities
    
    def _test_url_parameter_enhanced(self, url, param_name, payload):
        """Enhanced URL parameter testing with better detection"""
        try:
            parsed_url = urlparse(url)
            query_params = parse_qs(parsed_url.query)
            query_params[param_name] = [payload]
            
            new_query = urllib.parse.urlencode(query_params, doseq=True)
            test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{new_query}"
            
            # Add delay to avoid rate limiting
            time.sleep(0.5)
            
            response = self.session.get(test_url, timeout=self.timeout)
            
            # Enhanced XSS detection - check multiple indicators
            response_text = response.text.lower()
            payload_lower = payload.lower()
            
            # Check for direct reflection
            if payload in response.text:
                return {
                    'type': 'reflected_xss',
                    'url': test_url,
                    'parameter': param_name,
                    'payload': payload,
                    'confidence': 'high',
                    'method': 'GET'
                }
            
            # Check for encoded reflection
            encoded_payloads = [
                urllib.parse.quote(payload),
                payload.replace('<', '&lt;').replace('>', '&gt;'),
                payload.replace('"', '&quot;').replace("'", '&#x27;')
            ]
            
            for encoded_payload in encoded_payloads:
                if encoded_payload in response.text:
                    return {
                        'type': 'reflected_xss_encoded',
                        'url': test_url,
                        'parameter': param_name,
                        'payload': payload,
                        'confidence': 'medium',
                        'method': 'GET'
                    }
        
        except requests.exceptions.TooManyRequests:
            self.log("Rate limited - waiting...", "WARNING")
            time.sleep(3)
            return None
        except Exception as e:
            self.log(f"Error testing URL parameter: {str(e)}", "ERROR")
        
        return None
    
    def _test_form_parameter_enhanced(self, form, param_name, payload):
        """Enhanced form parameter testing with better detection"""
        try:
            form_data = {}
            for field in form['inputs']:
                if field['name'] == param_name:
                    form_data[field['name']] = payload
                else:
                    form_data[field['name']] = field['value']
            
            # Add delay to avoid rate limiting
            time.sleep(0.5)
            
            if form['method'] == 'POST':
                response = self.session.post(form['action'], data=form_data, timeout=self.timeout)
            else:
                response = self.session.get(form['action'], params=form_data, timeout=self.timeout)
            
            # Enhanced XSS detection
            if payload in response.text:
                return {
                    'type': 'reflected_xss',
                    'url': form['action'],
                    'parameter': param_name,
                    'payload': payload,
                    'confidence': 'high',
                    'method': form['method']
                }
        
        except requests.exceptions.TooManyRequests:
            self.log("Rate limited - waiting...", "WARNING")
            time.sleep(3)
            return None
        except Exception as e:
            self.log(f"Error testing form parameter: {str(e)}", "ERROR")
        
        return None
    
    def browser_validation(self, vulnerabilities):
        """Browser-based validation for confirmed vulnerabilities"""
        if not PLAYWRIGHT_AVAILABLE or not vulnerabilities:
            return vulnerabilities
        
        self.log("🌐 Starting browser validation...", "PHASE")
        
        if not self._init_browser():
            self.log("Browser initialization failed", "ERROR")
            return vulnerabilities
        
        try:
            validated_vulnerabilities = []
            
            for vuln in vulnerabilities:
                if vuln['confidence'] == 'high':
                    validated_vuln = self._validate_with_browser(vuln)
                    if validated_vuln:
                        validated_vulnerabilities.append(validated_vuln)
                    else:
                        # Keep original if browser validation fails
                        validated_vulnerabilities.append(vuln)
                else:
                    validated_vulnerabilities.append(vuln)
            
            return validated_vulnerabilities
        
        finally:
            self._close_browser()
    
    def _init_browser(self):
        """Initialize browser with better settings"""
        try:
            self.playwright = sync_playwright().start()
            self.browser = self.playwright.chromium.launch(
                headless=True,  # Use headless for stability
                args=[
                    '--no-sandbox',
                    '--disable-setuid-sandbox',
                    '--disable-web-security',
                    '--disable-font-subpixel-positioning'
                ]
            )
            self.browser_context = self.browser.new_context(
                viewport={'width': 1920, 'height': 1080},
                user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
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
        except Exception as e:
            self.log(f"Browser close error: {str(e)}", "ERROR")
    
    def _validate_with_browser(self, vuln):
        """Validate vulnerability with browser"""
        try:
            page = self.browser_context.new_page()
            
            # Set up dialog handler
            dialog_handled = False
            alert_message = ""
            
            def handle_dialog(dialog):
                nonlocal dialog_handled, alert_message
                dialog_handled = True
                alert_message = dialog.message
                dialog.accept()
            
            page.on("dialog", handle_dialog)
            
            # Navigate to vulnerable URL
            page.goto(vuln['url'], timeout=15000)
            time.sleep(2)
            
            if dialog_handled and 'XSS_ULTIMATE' in alert_message:
                vuln['browser_validated'] = True
                vuln['alert_message'] = alert_message
                page.close()
                return vuln
            
            page.close()
            return None
        
        except Exception as e:
            self.log(f"Browser validation error: {str(e)}", "ERROR")
            return None
    
    def generate_final_report(self, vulnerabilities):
        """Generate final HTML report"""
        self.log("📊 Generating final report...", "SUCCESS")
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = os.path.join('reports', f'ultimate_xss_report_{timestamp}.html')
        
        total_vulns = len(vulnerabilities)
        browser_validated = len([v for v in vulnerabilities if v.get('browser_validated', False)])
        
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Ultimate XSS Scanner Report - {self.target_url}</title>
    <style>
        body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 0; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: #333; }}
        .container {{ max-width: 1200px; margin: 20px auto; background: white; border-radius: 15px; box-shadow: 0 10px 30px rgba(0,0,0,0.2); overflow: hidden; }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; }}
        .header h1 {{ margin: 0; font-size: 2.5em; }}
        .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; padding: 30px; }}
        .stat {{ background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%); color: white; padding: 25px; border-radius: 10px; text-align: center; }}
        .stat-number {{ font-size: 2.5em; font-weight: bold; margin-bottom: 10px; }}
        .vulnerability {{ background: #f8f9fa; border-left: 5px solid #28a745; margin: 20px; padding: 25px; border-radius: 8px; }}
        .payload-display {{ background: #f8f9fa; padding: 10px; border-radius: 5px; font-family: monospace; word-break: break-all; margin: 10px 0; }}
        .browser-badge {{ background: #28a745; color: white; padding: 3px 8px; border-radius: 10px; font-size: 0.8em; font-weight: bold; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Ultimate XSS Scanner Report</h1>
            <p>Target: {self.target_url}</p>
            <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
        
        <div class="stats">
            <div class="stat">
                <div class="stat-number">{total_vulns}</div>
                <div>Total Vulnerabilities</div>
            </div>
            <div class="stat">
                <div class="stat-number">{browser_validated}</div>
                <div>Browser Validated</div>
            </div>
        </div>
        
        <div style="padding: 30px;">
            <h2>🎯 Vulnerability Details</h2>
"""
        
        if not vulnerabilities:
            html_content += '<div style="text-align: center; padding: 40px; color: #28a745; font-size: 1.2em;">✅ No vulnerabilities found</div>'
        else:
            for i, vuln in enumerate(vulnerabilities, 1):
                browser_badge = '<span class="browser-badge">BROWSER VALIDATED</span>' if vuln.get('browser_validated', False) else ''
                html_content += f"""
                <div class="vulnerability">
                    <h3>🔍 Vulnerability #{i} {browser_badge}</h3>
                    <p><strong>Type:</strong> {vuln.get('type', 'unknown')}</p>
                    <p><strong>URL:</strong> {vuln.get('url', 'unknown')}</p>
                    <p><strong>Parameter:</strong> {vuln.get('parameter', 'unknown')}</p>
                    <p><strong>Payload:</strong></p>
                    <div class="payload-display">{vuln.get('payload', 'unknown')}</div>
                    <p><strong>Method:</strong> {vuln.get('method', 'GET')}</p>
                    <p><strong>Confidence:</strong> {vuln.get('confidence', 'unknown')}</p>
                    {f'<p><strong>Alert Message:</strong> {vuln.get("alert_message", "N/A")}</p>' if vuln.get('alert_message') else ''}
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
            
            self.log(f"Final report generated: {report_path}", "SUCCESS")
            return report_path
            
        except Exception as e:
            self.log(f"Error generating report: {str(e)}", "ERROR")
            return None
    
    def scan(self):
        """Main scanning method"""
        self.log("🚀 Starting Ultimate XSS Scanner Final", "SUCCESS")
        self.log(f"Target: {self.target_url}", "INFO")
        self.log("=" * 80, "SUCCESS")
        
        try:
            # Phase 1: Enhanced Reconnaissance
            recon_data = self.enhanced_reconnaissance()
            if not recon_data:
                return []
            
            # Phase 2: Enhanced XSS Testing
            vulnerabilities = self.enhanced_xss_testing(recon_data)
            
            # Phase 3: Browser Validation (optional)
            if vulnerabilities:
                vulnerabilities = self.browser_validation(vulnerabilities)
            
            # Phase 4: Generate Report
            report_path = self.generate_final_report(vulnerabilities)
            
            # Phase 5: Show Results
            self._show_final_results(vulnerabilities)
            
            return vulnerabilities
            
        except Exception as e:
            self.log(f"Scan failed: {str(e)}", "ERROR")
            return []
    
    def _show_final_results(self, vulnerabilities):
        """Show final scan results"""
        self.log("=" * 80, "SUCCESS")
        self.log("FINAL SCAN RESULTS", "SUCCESS")
        self.log("=" * 80, "SUCCESS")
        
        total_vulns = len(vulnerabilities)
        browser_validated = len([v for v in vulnerabilities if v.get('browser_validated', False)])
        
        self.log(f"Total vulnerabilities: {total_vulns}", "SUCCESS")
        self.log(f"Browser validated: {browser_validated}", "SUCCESS")
        
        if vulnerabilities:
            self.log("\nVulnerabilities found:", "VULN")
            for i, vuln in enumerate(vulnerabilities, 1):
                browser_status = " [BROWSER VALIDATED]" if vuln.get('browser_validated', False) else ""
                self.log(f"  {i}. {vuln.get('type', 'unknown')} - {vuln.get('parameter', 'unknown')} - {vuln.get('confidence', 'unknown')}{browser_status}", "VULN")
        else:
            self.log("No vulnerabilities found", "INFO")

def main():
    parser = argparse.ArgumentParser(description='Ultimate XSS Scanner Final')
    parser.add_argument('url', help='Target URL to scan')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout (default: 10)')
    
    args = parser.parse_args()
    
    scanner = UltimateXSSScanner(args.url, args.timeout)
    scanner.scan()

if __name__ == "__main__":
    main()