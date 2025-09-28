#!/usr/bin/env python3
"""
Professional Open Redirect Vulnerability Scanner
Advanced scanner with comprehensive testing and WAF bypass techniques
Author: Security Expert
Version: 2.0
"""

import asyncio
import aiohttp
import json
import logging
import os
import sys
import time
import urllib.parse
import hashlib
import random
import string
import re
import base64
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Set, Tuple, Optional, Any
import argparse
from urllib.parse import urljoin, urlparse, parse_qs, unquote
import threading
from queue import Queue
import subprocess
import platform

# Advanced imports
try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.chrome.service import Service
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.common.exceptions import TimeoutException, WebDriverException
    from webdriver_manager.chrome import ChromeDriverManager
    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False
    print("⚠️ Selenium not available. Chrome automation disabled.")

try:
    from bs4 import BeautifulSoup
    BEAUTIFULSOUP_AVAILABLE = True
except ImportError:
    BEAUTIFULSOUP_AVAILABLE = False
    print("⚠️ BeautifulSoup not available. HTML parsing disabled.")

class ProfessionalOpenRedirectScanner:
    """
    Professional Open Redirect Vulnerability Scanner
    Comprehensive testing with advanced WAF bypass techniques
    """
    
    def __init__(self, target_url: str, output_dir: str = "scan_results", 
                 max_threads: int = 10, max_depth: int = 3, timeout: int = 30,
                 target_domain: str = "google.com"):
        self.target_url = target_url
        self.output_dir = Path(output_dir)
        self.max_threads = max_threads
        self.max_depth = max_depth
        self.timeout = timeout
        self.target_domain = target_domain
        self.results = []
        self.vulnerabilities = []
        self.scanned_urls = set()
        self.session = None
        self.driver = None
        
        # Create output directory
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Setup logging
        self._setup_logging()
        
        # Load advanced payloads
        self.payloads = self._load_advanced_payloads()
        
        # Common redirect parameter names
        self.redirect_params = {
            'url', 'redirect', 'next', 'continue', 'return', 'returnTo', 'return_to',
            'goto', 'target', 'destination', 'link', 'href', 'src', 'action',
            'redirect_uri', 'redirect_url', 'callback', 'callback_url', 'returnUrl',
            'return_url', 'success_url', 'failure_url', 'cancel_url', 'back_url',
            'forward_url', 'jump', 'jump_to', 'navigate', 'navigate_to', 'path',
            'route', 'to', 'from', 'referer', 'referrer', 'ref', 'source',
            'origin', 'origin_url', 'base_url', 'home_url', 'login_url', 'logout_url',
            'profile_url', 'account_url', 'dashboard_url', 'admin_url', 'api_url',
            'endpoint', 'uri', 'pathname', 'location'
        }
    
    def _setup_logging(self):
        """Setup comprehensive logging"""
        log_dir = self.output_dir / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)
        
        # Create logger
        self.logger = logging.getLogger('ProfessionalOpenRedirectScanner')
        self.logger.setLevel(logging.INFO)
        
        # Clear existing handlers
        self.logger.handlers.clear()
        
        # Console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.INFO)
        console_formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s',
            datefmt='%H:%M:%S'
        )
        console_handler.setFormatter(console_formatter)
        self.logger.addHandler(console_handler)
        
        # File handler
        log_file = log_dir / f"scanner_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        file_handler.setLevel(logging.DEBUG)
        file_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(file_formatter)
        self.logger.addHandler(file_handler)
        
        # Prevent duplicate logs
        self.logger.propagate = False
    
    def _load_advanced_payloads(self) -> List[str]:
        """Load advanced payloads with WAF bypass techniques"""
        base_payloads = [
            f"//{self.target_domain}",
            f"///{self.target_domain}",
            f"////{self.target_domain}",
            f"/////{self.target_domain}",
            f"http://{self.target_domain}",
            f"https://{self.target_domain}",
            f"javascript:alert(1)",
            f"data:text/html,<script>alert(1)</script>",
            f"ftp://{self.target_domain}",
            f"file://{self.target_domain}",
            f"gopher://{self.target_domain}",
            f"ldap://{self.target_domain}",
            f"ldaps://{self.target_domain}",
            f"dict://{self.target_domain}",
            f"sftp://{self.target_domain}",
            f"tftp://{self.target_domain}",
            f"ws://{self.target_domain}",
            f"wss://{self.target_domain}"
        ]
        
        # Advanced WAF bypass payloads
        advanced_payloads = []
        
        for base in base_payloads:
            # URL encoding variations
            advanced_payloads.extend([
                urllib.parse.quote(base),
                urllib.parse.quote(urllib.parse.quote(base)),  # Double encoding
                urllib.parse.quote(base, safe=''),
                base.replace('/', '%2f'),
                base.replace(':', '%3a'),
                base.replace('?', '%3f'),
                base.replace('#', '%23'),
                base.replace('&', '%26'),
                base.replace('=', '%3d'),
                base.replace('+', '%2b'),
                base.replace(' ', '%20'),
                base.replace(' ', '+'),
            ])
            
            # Unicode and special character variations
            advanced_payloads.extend([
                base.replace('a', 'а'),  # Cyrillic 'a'
                base.replace('e', 'е'),  # Cyrillic 'e'
                base.replace('o', 'о'),  # Cyrillic 'o'
                base.replace('p', 'р'),  # Cyrillic 'p'
                base.replace('c', 'с'),  # Cyrillic 'c'
                base.replace('x', 'х'),  # Cyrillic 'x'
                base.replace('y', 'у'),  # Cyrillic 'y'
                base.replace('A', 'А'),  # Cyrillic 'A'
                base.replace('E', 'Е'),  # Cyrillic 'E'
                base.replace('O', 'О'),  # Cyrillic 'O'
                base.replace('P', 'Р'),  # Cyrillic 'P'
                base.replace('C', 'С'),  # Cyrillic 'C'
                base.replace('X', 'Х'),  # Cyrillic 'X'
                base.replace('Y', 'У'),  # Cyrillic 'Y'
            ])
            
            # Control character injections
            control_chars = ['\x00', '\x01', '\x02', '\x03', '\x04', '\x05', '\x06', '\x07',
                           '\x08', '\x0b', '\x0c', '\x0e', '\x0f', '\x10', '\x11', '\x12',
                           '\x13', '\x14', '\x15', '\x16', '\x17', '\x18', '\x19', '\x1a',
                           '\x1b', '\x1c', '\x1d', '\x1e', '\x1f']
            
            for char in control_chars[:5]:  # Limit to 5 control chars
                advanced_payloads.append(base + char)
                advanced_payloads.append(char + base)
                advanced_payloads.append(base.replace('/', char + '/'))
            
            # Whitespace variations
            whitespace_chars = ['\t', '\n', '\r', '\f', '\v', '\u00a0', '\u2000', '\u2001',
                              '\u2002', '\u2003', '\u2004', '\u2005', '\u2006', '\u2007',
                              '\u2008', '\u2009', '\u200a', '\u200b', '\u200c', '\u200d',
                              '\u200e', '\u200f', '\u2028', '\u2029', '\u202a', '\u202b',
                              '\u202c', '\u202d', '\u202e', '\u202f', '\u205f', '\u2060', '\u3000']
            
            for ws in whitespace_chars[:3]:  # Limit to 3 whitespace chars
                advanced_payloads.append(base.replace(' ', ws))
                advanced_payloads.append(ws + base)
                advanced_payloads.append(base + ws)
            
            # Case variations
            advanced_payloads.extend([
                base.upper(),
                base.lower(),
                base.capitalize(),
                base.swapcase(),
            ])
            
            # HTML entity encoding
            html_entities = {
                '<': '&lt;', '>': '&gt;', '&': '&amp;', '"': '&quot;', "'": '&#39;',
                ' ': '&nbsp;', '!': '&#33;', '#': '&#35;', '$': '&#36;', '%': '&#37;',
                '(': '&#40;', ')': '&#41;', '*': '&#42;', '+': '&#43;', ',': '&#44;',
                '-': '&#45;', '.': '&#46;', '/': '&#47;', ':': '&#58;', ';': '&#59;',
                '=': '&#61;', '?': '&#63;', '@': '&#64;', '[': '&#91;', '\\': '&#92;',
                ']': '&#93;', '^': '&#94;', '_': '&#95;', '`': '&#96;', '{': '&#123;',
                '|': '&#124;', '}': '&#125;', '~': '&#126;'
            }
            
            html_encoded = base
            for char, entity in html_entities.items():
                html_encoded = html_encoded.replace(char, entity)
            advanced_payloads.append(html_encoded)
            
            # Base64 encoding
            try:
                b64_encoded = base64.b64encode(base.encode()).decode()
                advanced_payloads.append(b64_encoded)
            except:
                pass
            
            # Hex encoding
            try:
                hex_encoded = base.encode().hex()
                advanced_payloads.append(hex_encoded)
            except:
                pass
        
        # Remove duplicates while preserving order
        seen = set()
        unique_payloads = []
        for payload in advanced_payloads:
            if payload not in seen and len(payload) < 1000:  # Limit payload length
                seen.add(payload)
                unique_payloads.append(payload)
        
        return unique_payloads[:500]  # Limit to 500 payloads
    
    async def initialize(self):
        """Initialize the scanner"""
        try:
            self.logger.info("🚀 Initializing Professional Open Redirect Scanner...")
            
            # Initialize HTTP session
            connector = aiohttp.TCPConnector(limit=100, limit_per_host=30)
            timeout = aiohttp.ClientTimeout(total=self.timeout, connect=10)
            self.session = aiohttp.ClientSession(
                connector=connector,
                timeout=timeout,
                headers={
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
                }
            )
            
            # Initialize Chrome if available
            if SELENIUM_AVAILABLE:
                await self._initialize_chrome()
            
            self.logger.info("✅ Scanner initialized successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"❌ Failed to initialize scanner: {str(e)}")
            return False
    
    async def _initialize_chrome(self):
        """Initialize Chrome driver for advanced testing"""
        try:
            self.logger.info("🌐 Initializing Chrome driver...")
            
            chrome_options = Options()
            chrome_options.add_argument("--headless")
            chrome_options.add_argument("--no-sandbox")
            chrome_options.add_argument("--disable-dev-shm-usage")
            chrome_options.add_argument("--disable-gpu")
            chrome_options.add_argument("--window-size=1920,1080")
            chrome_options.add_argument("--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
            chrome_options.add_argument("--disable-blink-features=AutomationControlled")
            chrome_options.add_experimental_option("excludeSwitches", ["enable-automation"])
            chrome_options.add_experimental_option('useAutomationExtension', False)
            
            # Try to install Chrome driver
            try:
                service = Service(ChromeDriverManager().install())
                self.driver = webdriver.Chrome(service=service, options=chrome_options)
                self.driver.execute_script("Object.defineProperty(navigator, 'webdriver', {get: () => undefined})")
                self.logger.info("✅ Chrome driver initialized successfully")
            except Exception as e:
                self.logger.warning(f"⚠️ Chrome driver initialization failed: {str(e)}")
                self.driver = None
                
        except Exception as e:
            self.logger.warning(f"⚠️ Chrome initialization failed: {str(e)}")
            self.driver = None
    
    async def scan(self):
        """Main scanning function"""
        try:
            self.logger.info(f"🎯 Starting comprehensive scan of: {self.target_url}")
            
            # Phase 1: Reconnaissance
            self.logger.info("🔍 Phase 1: Advanced Reconnaissance...")
            injection_points = await self._perform_reconnaissance()
            
            if not injection_points:
                self.logger.warning("⚠️ No injection points found")
                return False
            
            self.logger.info(f"✅ Found {len(injection_points)} injection points")
            
            # Phase 2: Payload Testing
            self.logger.info("🧪 Phase 2: Advanced Payload Testing...")
            vulnerabilities = await self._test_payloads_parallel(injection_points)
            
            # Phase 3: Report Generation
            self.logger.info("📊 Phase 3: Report Generation...")
            await self._generate_reports(vulnerabilities)
            
            self.logger.info(f"✅ Scan completed. Found {len(vulnerabilities)} vulnerabilities")
            return True
            
        except Exception as e:
            self.logger.error(f"❌ Scan failed: {str(e)}")
            return False
    
    async def _perform_reconnaissance(self) -> List[Dict]:
        """Perform comprehensive reconnaissance"""
        injection_points = []
        
        try:
            # Test target URL directly
            injection_points.extend(await self._extract_url_parameters(self.target_url))
            
            # Crawl for additional URLs
            if self.max_depth > 0:
                crawled_urls = await self._crawl_website()
                for url in crawled_urls:
                    injection_points.extend(await self._extract_url_parameters(url))
            
            return injection_points
            
        except Exception as e:
            self.logger.error(f"❌ Reconnaissance failed: {str(e)}")
            return []
    
    async def _extract_url_parameters(self, url: str) -> List[Dict]:
        """Extract parameters from URL"""
        injection_points = []
        
        try:
            parsed = urlparse(url)
            query_params = parse_qs(parsed.query)
            
            for param_name, param_values in query_params.items():
                if (param_name.lower() in self.redirect_params or 
                    'redirect' in param_name.lower() or 
                    'url' in param_name.lower() or
                    'next' in param_name.lower() or
                    'goto' in param_name.lower()):
                    
                    for value in param_values:
                        injection_points.append({
                            'type': 'url',
                            'parameter': param_name,
                            'value': value,
                            'url': url,
                            'context': 'query_parameter'
                        })
            
            # Also check for form parameters if we can parse the page
            if BEAUTIFULSOUP_AVAILABLE:
                form_params = await self._extract_form_parameters(url)
                injection_points.extend(form_params)
            
        except Exception as e:
            self.logger.error(f"❌ Error extracting parameters from {url}: {str(e)}")
        
        return injection_points
    
    async def _extract_form_parameters(self, url: str) -> List[Dict]:
        """Extract form parameters from page"""
        injection_points = []
        
        try:
            async with self.session.get(url) as response:
                if response.status == 200:
                    content = await response.text()
                    soup = BeautifulSoup(content, 'html.parser')
                    
                    forms = soup.find_all('form')
                    for form in forms:
                        action = form.get('action', '')
                        if action:
                            form_url = urljoin(url, action)
                        else:
                            form_url = url
                        
                        inputs = form.find_all(['input', 'select', 'textarea'])
                        for input_field in inputs:
                            name = input_field.get('name')
                            if name and (name.lower() in self.redirect_params or 
                                       'redirect' in name.lower() or 
                                       'url' in name.lower()):
                                injection_points.append({
                                    'type': 'form',
                                    'parameter': name,
                                    'value': input_field.get('value', ''),
                                    'url': form_url,
                                    'context': 'form_input',
                                    'input_type': input_field.get('type', 'text')
                                })
        
        except Exception as e:
            self.logger.error(f"❌ Error extracting form parameters from {url}: {str(e)}")
        
        return injection_points
    
    async def _crawl_website(self) -> List[str]:
        """Crawl website for additional URLs"""
        urls_to_crawl = [self.target_url]
        crawled_urls = set()
        found_urls = set()
        
        for depth in range(self.max_depth):
            if not urls_to_crawl:
                break
            
            current_urls = urls_to_crawl.copy()
            urls_to_crawl.clear()
            
            for url in current_urls:
                if url in crawled_urls:
                    continue
                
                crawled_urls.add(url)
                
                try:
                    async with self.session.get(url) as response:
                        if response.status == 200:
                            content = await response.text()
                            
                            if BEAUTIFULSOUP_AVAILABLE:
                                soup = BeautifulSoup(content, 'html.parser')
                                
                                # Extract links
                                for link in soup.find_all('a', href=True):
                                    href = link.get('href')
                                    if href:
                                        full_url = urljoin(url, href)
                                        parsed = urlparse(full_url)
                                        
                                        # Only crawl same domain
                                        if parsed.netloc == urlparse(self.target_url).netloc:
                                            if full_url not in found_urls:
                                                found_urls.add(full_url)
                                                urls_to_crawl.append(full_url)
                
                except Exception as e:
                    self.logger.error(f"❌ Error crawling {url}: {str(e)}")
        
        return list(found_urls)
    
    async def _test_payloads_parallel(self, injection_points: List[Dict]) -> List[Dict]:
        """Test payloads using parallel processing"""
        vulnerabilities = []
        
        # Create task queue
        task_queue = Queue()
        total_tasks = 0
        
        for point in injection_points:
            for payload in self.payloads:
                task_queue.put((point, payload))
                total_tasks += 1
        
        self.logger.info(f"🧪 Testing {total_tasks} payloads across {len(injection_points)} injection points...")
        self.logger.info(f"🧵 Using {self.max_threads} threads for parallel processing")
        
        # Process tasks in parallel
        completed_tasks = 0
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = []
            
            while not task_queue.empty():
                point, payload = task_queue.get()
                future = executor.submit(self._test_single_payload, point, payload)
                futures.append(future)
            
            # Collect results with progress tracking
            for future in as_completed(futures):
                try:
                    result = future.result()
                    completed_tasks += 1
                    
                    # Show progress every 50 tasks
                    if completed_tasks % 50 == 0 or completed_tasks == total_tasks:
                        progress = (completed_tasks / total_tasks) * 100
                        self.logger.info(f"📊 Progress: {completed_tasks}/{total_tasks} ({progress:.1f}%)")
                    
                    if result and result.get('vulnerable'):
                        vulnerabilities.append(result)
                        self.logger.warning(f"🎯 Vulnerability found! {result.get('url', 'Unknown')}")
                        
                except Exception as e:
                    self.logger.error(f"❌ Payload test failed: {str(e)}")
                    completed_tasks += 1
        
        self.logger.info(f"✅ Payload testing completed. Found {len(vulnerabilities)} vulnerabilities")
        return vulnerabilities
    
    def _test_single_payload(self, injection_point: Dict, payload: str) -> Optional[Dict]:
        """Test a single payload against an injection point"""
        try:
            # Create test URL with payload
            test_url = self._construct_test_url(injection_point, payload)
            
            # Test with HTTP request
            result = asyncio.run(self._test_http_redirect(test_url, payload))
            
            if result and result.get('vulnerable'):
                vulnerability = {
                    'url': test_url,
                    'parameter': injection_point.get('parameter'),
                    'payload': payload,
                    'redirect_url': result.get('redirect_url'),
                    'injection_type': injection_point.get('type'),
                    'context': injection_point.get('context'),
                    'timestamp': datetime.now().isoformat(),
                    'severity': self._get_severity(injection_point.get('type'))
                }
                
                self.logger.info(f"🎯 Vulnerability found: {test_url}")
                return vulnerability
            
            return None
            
        except Exception as e:
            self.logger.error(f"❌ Error testing payload {payload}: {str(e)}")
            return None
    
    def _construct_test_url(self, injection_point: Dict, payload: str) -> str:
        """Construct test URL with payload"""
        base_url = injection_point['url']
        param_name = injection_point['parameter']
        param_type = injection_point['type']
        
        if param_type == 'url':
            # URL parameter
            parsed = urlparse(base_url)
            query_params = parse_qs(parsed.query)
            query_params[param_name] = [payload]
            
            new_query = '&'.join([f"{k}={v[0]}" for k, v in query_params.items()])
            return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
        
        elif param_type == 'form':
            # Form parameter - would need to submit form
            return base_url
        
        else:
            return base_url
    
    async def _test_http_redirect(self, test_url: str, payload: str) -> Optional[Dict]:
        """Test HTTP redirect using aiohttp"""
        try:
            async with self.session.get(test_url, allow_redirects=False) as response:
                # Check for redirect status codes
                if response.status in [301, 302, 303, 307, 308]:
                    location = response.headers.get('Location', '')
                    
                    # Check if redirected to target domain
                    if self.target_domain in location.lower():
                        return {
                            'vulnerable': True,
                            'original_url': test_url,
                            'redirect_url': location,
                            'payload': payload,
                            'status_code': response.status
                        }
                
                # Also check if the response contains redirect patterns
                content = await response.text()
                if self._check_redirect_patterns(content, payload):
                    return {
                        'vulnerable': True,
                        'original_url': test_url,
                        'redirect_url': 'JavaScript/HTML redirect detected',
                        'payload': payload,
                        'status_code': response.status
                    }
                
                return {
                    'vulnerable': False,
                    'original_url': test_url,
                    'payload': payload,
                    'status_code': response.status
                }
                
        except Exception as e:
            self.logger.error(f"❌ Error testing HTTP redirect {test_url}: {str(e)}")
            return None
    
    def _check_redirect_patterns(self, content: str, payload: str) -> bool:
        """Check for redirect patterns in content"""
        redirect_patterns = [
            r'window\.location\s*=\s*["\']([^"\']+)["\']',
            r'window\.location\.href\s*=\s*["\']([^"\']+)["\']',
            r'document\.location\s*=\s*["\']([^"\']+)["\']',
            r'location\.href\s*=\s*["\']([^"\']+)["\']',
            r'<meta[^>]*http-equiv\s*=\s*["\']refresh["\'][^>]*content\s*=\s*["\']([^"\']+)["\']',
            r'<meta[^>]*content\s*=\s*["\']([^"\']+)["\'][^>]*http-equiv\s*=\s*["\']refresh["\']'
        ]
        
        for pattern in redirect_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                if self.target_domain in match.lower():
                    return True
        
        return False
    
    def _get_severity(self, injection_type: str) -> str:
        """Determine vulnerability severity"""
        if injection_type == 'url':
            return 'High'
        elif injection_type == 'form':
            return 'Medium'
        else:
            return 'Low'
    
    async def _generate_reports(self, vulnerabilities: List[Dict]):
        """Generate comprehensive reports"""
        try:
            # Generate HTML report
            html_report = self._generate_html_report(vulnerabilities)
            html_file = self.output_dir / f"open_redirect_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
            with open(html_file, 'w', encoding='utf-8') as f:
                f.write(html_report)
            
            # Generate JSON report
            json_report = {
                'target_url': self.target_url,
                'scan_timestamp': datetime.now().isoformat(),
                'vulnerabilities': vulnerabilities,
                'total_vulnerabilities': len(vulnerabilities),
                'scan_summary': self._generate_scan_summary(vulnerabilities)
            }
            
            json_file = self.output_dir / f"open_redirect_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(json_file, 'w', encoding='utf-8') as f:
                json.dump(json_report, f, indent=2, ensure_ascii=False)
            
            self.logger.info(f"📊 Reports generated: {html_file}, {json_file}")
            
        except Exception as e:
            self.logger.error(f"❌ Error generating reports: {str(e)}")
    
    def _generate_scan_summary(self, vulnerabilities: List[Dict]) -> Dict:
        """Generate scan summary statistics"""
        summary = {
            'total_vulnerabilities': len(vulnerabilities),
            'high_severity': 0,
            'medium_severity': 0,
            'low_severity': 0,
            'vulnerability_types': {}
        }
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'Low')
            if severity == 'High':
                summary['high_severity'] += 1
            elif severity == 'Medium':
                summary['medium_severity'] += 1
            else:
                summary['low_severity'] += 1
            
            vuln_type = vuln.get('injection_type', 'unknown')
            summary['vulnerability_types'][vuln_type] = summary['vulnerability_types'].get(vuln_type, 0) + 1
        
        return summary
    
    def _generate_html_report(self, vulnerabilities: List[Dict]) -> str:
        """Generate HTML report content"""
        vulnerabilities_html = ''
        
        if not vulnerabilities:
            vulnerabilities_html = '<div class="no-vulns">✅ No vulnerabilities found</div>'
        else:
            for vuln in vulnerabilities:
                severity = vuln.get('severity', 'Low').lower()
                vulnerabilities_html += f'''
                <div class="vulnerability {severity}">
                    <h3>🎯 {vuln.get("parameter", "Unknown Parameter")}</h3>
                    <p><strong>URL:</strong> {vuln.get("url", "Unknown")}</p>
                    <p><strong>Payload:</strong> <code>{vuln.get("payload", "Unknown")}</code></p>
                    <p><strong>Type:</strong> {vuln.get("injection_type", "Unknown")}</p>
                    <p><strong>Context:</strong> {vuln.get("context", "Unknown")}</p>
                    <p><strong>Redirect URL:</strong> {vuln.get("redirect_url", "Unknown")}</p>
                    <p><strong>Severity:</strong> {vuln.get("severity", "Unknown")}</p>
                    <p><strong>Timestamp:</strong> {vuln.get("timestamp", "Unknown")}</p>
                </div>
                '''
        
        return f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Professional Open Redirect Vulnerability Report</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
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
            background: linear-gradient(135deg, #2c3e50 0%, #34495e 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }}
        
        .header h1 {{
            margin: 0;
            font-size: 2.5em;
            font-weight: 300;
        }}
        
        .header p {{
            margin: 10px 0 0 0;
            opacity: 0.8;
            font-size: 1.1em;
        }}
        
        .summary {{
            background: #f8f9fa;
            padding: 30px;
            border-bottom: 1px solid #e9ecef;
        }}
        
        .summary h2 {{
            color: #2c3e50;
            margin-top: 0;
            font-size: 1.8em;
        }}
        
        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }}
        
        .stat-card {{
            background: white;
            padding: 20px;
            border-radius: 10px;
            text-align: center;
            box-shadow: 0 5px 15px rgba(0,0,0,0.08);
        }}
        
        .stat-number {{
            font-size: 2.5em;
            font-weight: bold;
            color: #3498db;
        }}
        
        .stat-label {{
            color: #7f8c8d;
            margin-top: 5px;
        }}
        
        .vulnerabilities {{
            padding: 30px;
        }}
        
        .vulnerabilities h2 {{
            color: #2c3e50;
            margin-top: 0;
            font-size: 1.8em;
        }}
        
        .vulnerability {{
            border: 1px solid #e9ecef;
            margin: 20px 0;
            padding: 25px;
            border-radius: 10px;
            transition: all 0.3s ease;
        }}
        
        .vulnerability:hover {{
            transform: translateY(-2px);
            box-shadow: 0 10px 25px rgba(0,0,0,0.1);
        }}
        
        .high {{ border-left: 5px solid #e74c3c; }}
        .medium {{ border-left: 5px solid #f39c12; }}
        .low {{ border-left: 5px solid #27ae60; }}
        
        .vulnerability h3 {{
            margin-top: 0;
            color: #2c3e50;
            font-size: 1.3em;
        }}
        
        .vulnerability p {{
            margin: 10px 0;
            line-height: 1.6;
        }}
        
        .vulnerability code {{
            background: #f8f9fa;
            padding: 2px 6px;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
            color: #e74c3c;
            word-break: break-all;
        }}
        
        .no-vulns {{
            text-align: center;
            color: #27ae60;
            font-size: 1.2em;
            padding: 40px;
            background: #f8f9fa;
            border-radius: 10px;
        }}
        
        .footer {{
            background: #2c3e50;
            color: white;
            padding: 20px;
            text-align: center;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 Professional Open Redirect Scanner</h1>
            <p>Advanced Security Testing Report</p>
        </div>
        
        <div class="summary">
            <h2>📊 Scan Summary</h2>
            <p><strong>Target URL:</strong> {self.target_url}</p>
            <p><strong>Scan Time:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p><strong>Total Vulnerabilities:</strong> {len(vulnerabilities)}</p>
            
            <div class="stats">
                <div class="stat-card">
                    <div class="stat-number">{len([v for v in vulnerabilities if v.get('severity') == 'High'])}</div>
                    <div class="stat-label">High Severity</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{len([v for v in vulnerabilities if v.get('severity') == 'Medium'])}</div>
                    <div class="stat-label">Medium Severity</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{len([v for v in vulnerabilities if v.get('severity') == 'Low'])}</div>
                    <div class="stat-label">Low Severity</div>
                </div>
            </div>
        </div>
        
        <div class="vulnerabilities">
            <h2>🎯 Vulnerabilities Found</h2>
            {vulnerabilities_html}
        </div>
        
        <div class="footer">
            <p>Generated by Professional Open Redirect Scanner v2.0</p>
        </div>
    </div>
</body>
</html>
"""
    
    async def cleanup(self):
        """Cleanup resources"""
        try:
            if self.session:
                await self.session.close()
            
            if self.driver:
                self.driver.quit()
            
            self.logger.info("🧹 Cleanup completed")
            
        except Exception as e:
            self.logger.error(f"❌ Cleanup error: {str(e)}")

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description='Professional Open Redirect Scanner')
    parser.add_argument('target', help='Target URL to scan')
    parser.add_argument('-o', '--output', default='scan_results', help='Output directory')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of threads')
    parser.add_argument('-d', '--depth', type=int, default=3, help='Maximum crawling depth')
    parser.add_argument('--timeout', type=int, default=30, help='Request timeout in seconds')
    parser.add_argument('--domain', default='google.com', help='Target domain for redirect validation')
    
    args = parser.parse_args()
    
    # Create scanner instance
    scanner = ProfessionalOpenRedirectScanner(
        args.target, 
        args.output, 
        args.threads, 
        args.depth, 
        args.timeout,
        args.domain
    )
    
    # Run scan
    async def run_scan():
        if await scanner.initialize():
            await scanner.scan()
        await scanner.cleanup()
    
    # Run the scan
    asyncio.run(run_scan())

if __name__ == "__main__":
    main()