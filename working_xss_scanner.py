#!/usr/bin/env python3
"""
Working XSS Scanner - No External Dependencies
Author: AI Assistant
Version: 1.0
"""

import urllib.request
import urllib.parse
import urllib.error
import re
import sys
import time
from datetime import datetime

class WorkingXSSScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.vulnerabilities = []
        
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
    
    def log(self, message, level="INFO"):
        """Simple logging"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"[{timestamp}] [{level}] {message}")
    
    def scan(self):
        """Main scanning method"""
        self.log("🚀 Starting Working XSS Scanner", "SUCCESS")
        self.log(f"Target: {self.target_url}", "INFO")
        
        try:
            # Test basic connectivity
            self.log("Testing connectivity...", "INFO")
            response = self._make_request(self.target_url)
            
            if not response:
                self.log("Failed to connect to target", "ERROR")
                return []
            
            self.log(f"Target accessible (Status: {response.getcode()})", "SUCCESS")
            
            # Extract URLs from response
            self.log("Extracting URLs and parameters...", "INFO")
            urls = self._extract_urls(response.read().decode('utf-8', errors='ignore'))
            
            self.log(f"Found {len(urls)} URLs to test", "SUCCESS")
            
            # Test each URL for XSS
            self.log("Testing for XSS vulnerabilities...", "INFO")
            vulnerabilities = self._test_urls(urls)
            
            # Show results
            self._show_results(vulnerabilities)
            
            return vulnerabilities
            
        except Exception as e:
            self.log(f"Scan failed: {str(e)}", "ERROR")
            return []
    
    def _make_request(self, url):
        """Make HTTP request"""
        try:
            req = urllib.request.Request(
                url,
                headers={
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                }
            )
            response = urllib.request.urlopen(req, timeout=10)
            return response
        except Exception as e:
            self.log(f"Request failed: {str(e)}", "ERROR")
            return None
    
    def _extract_urls(self, html_content):
        """Extract URLs from HTML content"""
        urls = set()
        urls.add(self.target_url)
        
        # Extract links using regex
        link_pattern = r'<a[^>]+href=["\']([^"\']+)["\'][^>]*>'
        matches = re.findall(link_pattern, html_content, re.IGNORECASE)
        
        for match in matches:
            if match and not match.startswith('#') and not match.startswith('javascript:'):
                # Convert relative URL to absolute
                if match.startswith('http'):
                    full_url = match
                else:
                    base_url = self.target_url.rstrip('/')
                    if match.startswith('/'):
                        full_url = base_url + match
                    else:
                        full_url = base_url + '/' + match
                
                # Check if it's from same domain
                if self._is_same_domain(full_url):
                    urls.add(full_url)
        
        # Extract forms
        form_pattern = r'<form[^>]+action=["\']([^"\']*)["\'][^>]*>'
        form_matches = re.findall(form_pattern, html_content, re.IGNORECASE)
        
        for match in form_matches:
            if match:
                if match.startswith('http'):
                    full_url = match
                else:
                    base_url = self.target_url.rstrip('/')
                    if match.startswith('/'):
                        full_url = base_url + match
                    else:
                        full_url = base_url + '/' + match
                
                if self._is_same_domain(full_url):
                    urls.add(full_url)
            else:
                # Form without action (submits to same page)
                urls.add(self.target_url)
        
        return list(urls)
    
    def _is_same_domain(self, url):
        """Check if URL is from same domain"""
        try:
            from urllib.parse import urlparse
            target_domain = urlparse(self.target_url).netloc
            url_domain = urlparse(url).netloc
            return target_domain == url_domain
        except:
            return False
    
    def _test_urls(self, urls):
        """Test URLs for XSS vulnerabilities"""
        vulnerabilities = []
        
        for url in urls:
            # Extract parameters from URL
            params = self._extract_url_parameters(url)
            
            if params:
                for param_name in params:
                    self.log(f"Testing parameter: {param_name} on {url}", "TEST")
                    
                    for payload in self.payloads:
                        vuln = self._test_parameter(url, param_name, payload)
                        if vuln:
                            vulnerabilities.append(vuln)
                            self.log(f"✅ XSS FOUND! Parameter: {param_name}", "VULN")
                            break
        
        return vulnerabilities
    
    def _extract_url_parameters(self, url):
        """Extract parameters from URL"""
        try:
            from urllib.parse import urlparse, parse_qs
            parsed_url = urlparse(url)
            query_params = parse_qs(parsed_url.query)
            return list(query_params.keys())
        except:
            return []
    
    def _test_parameter(self, url, param_name, payload):
        """Test parameter for XSS"""
        try:
            from urllib.parse import urlparse, parse_qs, urlencode
            
            # Parse URL and modify parameter
            parsed_url = urlparse(url)
            query_params = parse_qs(parsed_url.query)
            query_params[param_name] = [payload]
            
            # Rebuild URL
            new_query = urlencode(query_params, doseq=True)
            test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{new_query}"
            
            # Make request
            response = self._make_request(test_url)
            
            if not response:
                return None
            
            # Check response
            response_content = response.read().decode('utf-8', errors='ignore')
            
            # Check for XSS reflection
            if payload in response_content and 'XSS_CONFIRMED' in payload:
                return {
                    'type': 'reflected_xss',
                    'url': test_url,
                    'parameter': param_name,
                    'payload': payload,
                    'confidence': 'high'
                }
        
        except Exception as e:
            self.log(f"Error testing parameter {param_name}: {str(e)}", "ERROR")
        
        return None
    
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
    if len(sys.argv) != 2:
        print("Usage: python3 working_xss_scanner.py <URL>")
        print("Example: python3 working_xss_scanner.py http://testphp.vulnweb.com")
        sys.exit(1)
    
    target_url = sys.argv[1]
    scanner = WorkingXSSScanner(target_url)
    scanner.scan()

if __name__ == "__main__":
    main()