#!/usr/bin/env python3
"""
Enhanced Professional Open Redirect Scanner with Web3 Support
Advanced version with comprehensive JavaScript analysis and Web3 detection
"""

import asyncio
import aiohttp
import re
import json
import time
import urllib.parse
from urllib.parse import urljoin, urlparse, parse_qs, unquote
from dataclasses import dataclass, asdict
from typing import List, Dict, Set, Optional, Tuple, Any
from pathlib import Path
import logging
import argparse
from datetime import datetime
import hashlib
import base64
import random
import string
import os

# Selenium for screenshot capture and DOM analysis
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, WebDriverException

# BeautifulSoup for HTML parsing
from bs4 import BeautifulSoup

# Import our advanced JavaScript analyzer
from js_analyzer import JavaScriptAnalyzer, AdvancedDOMAnalyzer, JSParameter

# Report generation
from jinja2 import Template
import html


@dataclass
class EnhancedParameter:
    """Enhanced parameter representation with additional metadata"""
    name: str
    value: str
    source: str  # 'url', 'form', 'javascript', 'headers', 'web3'
    context: str  # 'query', 'path', 'fragment', 'form_action', 'js_variable', 'web3_contract'
    url: str
    method: str = 'GET'
    is_redirect_related: bool = False
    confidence: float = 0.0
    js_analysis: Optional[Dict[str, Any]] = None
    web3_metadata: Optional[Dict[str, Any]] = None


@dataclass
class EnhancedVulnerability:
    """Enhanced vulnerability representation"""
    url: str
    parameter: str
    payload: str
    method: str
    response_code: int
    redirect_url: str
    context: str
    screenshot_path: Optional[str] = None
    timestamp: str = ""
    vulnerability_type: str = "open_redirect"  # or "dom_based_redirect", "web3_redirect"
    confidence: float = 0.0
    exploitation_complexity: str = "LOW"  # LOW, MEDIUM, HIGH
    impact_assessment: str = "MEDIUM"
    remediation_suggestion: str = ""
    js_flow_analysis: Optional[Dict[str, Any]] = None


class EnhancedOpenRedirectScanner:
    """Enhanced Professional Open Redirect Scanner with Web3 support"""
    
    def __init__(self, target_url: str, max_depth: int = 3, max_pages: int = 200):
        self.target_url = target_url.rstrip('/')
        self.base_domain = urlparse(target_url).netloc
        self.max_depth = max_depth
        self.max_pages = max_pages
        
        # Storage
        self.discovered_urls: Set[str] = set()
        self.parameters: List[EnhancedParameter] = []
        self.vulnerabilities: List[EnhancedVulnerability] = []
        self.js_files: Set[str] = set()
        self.web3_endpoints: Set[str] = set()
        
        # Analyzers
        self.js_analyzer = JavaScriptAnalyzer()
        self.dom_analyzer = AdvancedDOMAnalyzer()
        
        # Session management
        self.session: Optional[aiohttp.ClientSession] = None
        self.driver: Optional[webdriver.Chrome] = None
        
        # Configuration
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        ]
        
        # Setup logging
        self.setup_logging()
        
        # Load enhanced payloads
        self.payloads = self.load_enhanced_payloads()
        
        # Web3-specific patterns
        self.web3_patterns = [
            r'web3', r'ethereum', r'metamask', r'wallet', r'dapp',
            r'blockchain', r'crypto', r'nft', r'defi', r'contract'
        ]
        
        # Enhanced redirect patterns
        self.redirect_patterns = [
            r'redirect', r'url', r'next', r'return', r'goto', r'target',
            r'destination', r'continue', r'forward', r'redir', r'location',
            r'site', r'link', r'href', r'returnurl', r'returnto', r'back',
            r'callback', r'success', r'failure', r'done', r'exit',
            r'referrer', r'referer', r'origin', r'source', r'from'
        ]
    
    def setup_logging(self):
        """Setup enhanced logging configuration"""
        log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        
        # Create logs directory
        Path("/workspace/logs").mkdir(exist_ok=True)
        
        logging.basicConfig(
            level=logging.INFO,
            format=log_format,
            handlers=[
                logging.FileHandler('/workspace/logs/enhanced_scanner.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def load_enhanced_payloads(self) -> Dict[str, List[str]]:
        """Load enhanced payloads categorized by context and technique"""
        return {
            'basic_redirect': [
                "//google.com",
                "https://google.com",
                "http://google.com",
                "//evil.com",
                "https://evil.com"
            ],
            'encoded_redirect': [
                "/%2f%2fgoogle.com",
                "/%5cgoogle.com",
                "%2f%2fgoogle.com",
                "%68%74%74%70%3a%2f%2f%67%6f%6f%67%6c%65%2e%63%6f%6d",
                "http://%67%6f%6f%67%6c%65%2e%63%6f%6d"
            ],
            'protocol_bypass': [
                "//google.com",
                "///google.com",
                "////google.com",
                "/////google.com",
                "https:google.com",
                "http:google.com"
            ],
            'unicode_bypass': [
                "//google%E3%80%82com",
                "〱google.com",
                "〵google.com",
                "ゝgoogle.com",
                "ーgoogle.com",
                "ｰgoogle.com"
            ],
            'ip_bypass': [
                "//216.58.214.206",
                "http://0xd8.0x3a.0xd6.0xce",
                "http://3627734734",
                "http://472.314.470.462"
            ],
            'javascript_payload': [
                "javascript:confirm(1)",
                "javascript:prompt(1)",
                "javascript:alert('XSS')",
                "data:text/html,<script>alert(1)</script>"
            ],
            'web3_specific': [
                "//metamask.io",
                "//wallet.connect",
                "//uniswap.org",
                "//opensea.io",
                "web3://contract.eth",
                "ipfs://QmHash",
                "ens://vitalik.eth"
            ],
            'path_traversal': [
                "//google.com/%2e%2e",
                "//google.com/%2e%2e%2f",
                "//google.com/%2f%2e%2e",
                "////google.com/%2e%2e",
                "../google.com"
            ]
        }
    
    async def init_session(self):
        """Initialize enhanced HTTP session with better error handling"""
        timeout = aiohttp.ClientTimeout(total=45)
        connector = aiohttp.TCPConnector(
            limit=150,
            limit_per_host=30,
            ssl=False,
            enable_cleanup_closed=True
        )
        
        self.session = aiohttp.ClientSession(
            timeout=timeout,
            connector=connector,
            headers={
                'User-Agent': random.choice(self.user_agents),
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate, br',
                'Connection': 'keep-alive',
                'Cache-Control': 'no-cache',
                'Sec-Fetch-Dest': 'document',
                'Sec-Fetch-Mode': 'navigate',
                'Sec-Fetch-Site': 'none'
            }
        )
    
    def init_enhanced_driver(self):
        """Initialize enhanced Chrome WebDriver with better capabilities"""
        chrome_options = Options()
        chrome_options.add_argument('--headless')
        chrome_options.add_argument('--no-sandbox')
        chrome_options.add_argument('--disable-dev-shm-usage')
        chrome_options.add_argument('--disable-gpu')
        chrome_options.add_argument('--window-size=1920,1080')
        chrome_options.add_argument('--disable-web-security')
        chrome_options.add_argument('--allow-running-insecure-content')
        chrome_options.add_argument('--ignore-certificate-errors')
        chrome_options.add_argument('--disable-blink-features=AutomationControlled')
        chrome_options.add_argument('--disable-extensions')
        chrome_options.add_argument('--no-first-run')
        chrome_options.add_argument('--disable-default-apps')
        chrome_options.add_experimental_option("excludeSwitches", ["enable-automation"])
        chrome_options.add_experimental_option('useAutomationExtension', False)
        
        try:
            self.driver = webdriver.Chrome(options=chrome_options)
            # Execute script to hide webdriver property
            self.driver.execute_script("Object.defineProperty(navigator, 'webdriver', {get: () => undefined})")
            self.logger.info("Enhanced Chrome WebDriver initialized successfully")
        except Exception as e:
            self.logger.error(f"Failed to initialize Chrome WebDriver: {e}")
            self.driver = None
    
    async def enhanced_crawl_website(self) -> Set[str]:
        """Enhanced website crawling with JavaScript rendering"""
        self.logger.info(f"Starting enhanced deep crawl of {self.target_url}")
        
        urls_to_crawl = {self.target_url}
        crawled_urls = set()
        depth = 0
        
        while urls_to_crawl and depth < self.max_depth and len(crawled_urls) < self.max_pages:
            current_level_urls = list(urls_to_crawl)[:20]  # Process in batches
            urls_to_crawl.clear()
            
            # Crawl with both static and dynamic analysis
            tasks = []
            for url in current_level_urls:
                if url not in crawled_urls:
                    tasks.append(self.enhanced_crawl_single_page(url))
            
            if tasks:
                results = await asyncio.gather(*tasks, return_exceptions=True)
                
                for result in results:
                    if isinstance(result, Exception):
                        self.logger.error(f"Enhanced crawling error: {result}")
                        continue
                    
                    if result:
                        url, new_urls, params = result
                        crawled_urls.add(url)
                        self.parameters.extend(params)
                        
                        # Add new URLs for next depth level
                        for new_url in new_urls:
                            if self.is_same_domain(new_url) and new_url not in crawled_urls:
                                urls_to_crawl.add(new_url)
            
            depth += 1
            self.logger.info(f"Enhanced crawl depth {depth} completed: {len(crawled_urls)} URLs, {len(self.parameters)} parameters")
            
            # Rate limiting between depth levels
            await asyncio.sleep(1)
        
        self.discovered_urls = crawled_urls
        self.logger.info(f"Enhanced crawling completed. Total URLs: {len(crawled_urls)}, Parameters: {len(self.parameters)}")
        return crawled_urls
    
    async def enhanced_crawl_single_page(self, url: str) -> Optional[Tuple[str, Set[str], List[EnhancedParameter]]]:
        """Enhanced single page crawling with comprehensive analysis"""
        try:
            # Static analysis
            async with self.session.get(url, allow_redirects=False) as response:
                content = await response.text()
                headers = dict(response.headers)
                
                # Parse HTML
                soup = BeautifulSoup(content, 'html.parser')
                
                # Extract URLs from links
                new_urls = set()
                for link in soup.find_all(['a', 'link'], href=True):
                    href = link['href']
                    full_url = urljoin(url, href)
                    if self.is_same_domain(full_url):
                        new_urls.add(full_url)
                
                # Enhanced parameter extraction
                params = []
                
                # 1. URL parameters
                params.extend(self.extract_enhanced_url_parameters(url))
                
                # 2. Form parameters
                params.extend(self.extract_enhanced_form_parameters(soup, url))
                
                # 3. Header parameters
                params.extend(self.extract_header_parameters(headers, url))
                
                # 4. JavaScript analysis
                js_params = await self.comprehensive_js_analysis(soup, url)
                params.extend(js_params)
                
                # 5. Web3-specific analysis
                web3_params = self.analyze_web3_patterns(content, url)
                params.extend(web3_params)
                
                # 6. Dynamic analysis with Selenium (for critical pages)
                if self.should_perform_dynamic_analysis(url, content):
                    dynamic_params = await self.dynamic_page_analysis(url)
                    params.extend(dynamic_params)
                
                return url, new_urls, params
                
        except Exception as e:
            self.logger.error(f"Error in enhanced crawling {url}: {e}")
            return None
    
    def extract_enhanced_url_parameters(self, url: str) -> List[EnhancedParameter]:
        """Enhanced URL parameter extraction with better analysis"""
        params = []
        parsed = urlparse(url)
        
        # Query parameters
        query_params = parse_qs(parsed.query, keep_blank_values=True)
        for param_name, param_values in query_params.items():
            for value in param_values:
                is_redirect = self.is_enhanced_redirect_parameter(param_name, value)
                confidence = self.calculate_parameter_confidence(param_name, value, 'query')
                
                params.append(EnhancedParameter(
                    name=param_name,
                    value=value,
                    source='url',
                    context='query',
                    url=url,
                    is_redirect_related=is_redirect,
                    confidence=confidence
                ))
        
        # Fragment parameters
        if parsed.fragment:
            # Handle both query-style fragments and simple fragments
            if '=' in parsed.fragment:
                fragment_params = parse_qs(parsed.fragment, keep_blank_values=True)
                for param_name, param_values in fragment_params.items():
                    for value in param_values:
                        is_redirect = self.is_enhanced_redirect_parameter(param_name, value)
                        confidence = self.calculate_parameter_confidence(param_name, value, 'fragment')
                        
                        params.append(EnhancedParameter(
                            name=param_name,
                            value=value,
                            source='url',
                            context='fragment',
                            url=url,
                            is_redirect_related=is_redirect,
                            confidence=confidence
                        ))
            else:
                # Simple fragment
                params.append(EnhancedParameter(
                    name='fragment',
                    value=parsed.fragment,
                    source='url',
                    context='fragment',
                    url=url,
                    is_redirect_related=True,
                    confidence=0.6
                ))
        
        return params
    
    def extract_enhanced_form_parameters(self, soup: BeautifulSoup, url: str) -> List[EnhancedParameter]:
        """Enhanced form parameter extraction"""
        params = []
        
        for form in soup.find_all('form'):
            action = form.get('action', '')
            method = form.get('method', 'GET').upper()
            form_url = urljoin(url, action) if action else url
            
            # Analyze form action for redirect patterns
            if action and self.is_enhanced_redirect_parameter('action', action):
                params.append(EnhancedParameter(
                    name='form_action',
                    value=action,
                    source='form',
                    context='form_action',
                    url=form_url,
                    method=method,
                    is_redirect_related=True,
                    confidence=0.8
                ))
            
            # Extract input parameters
            for input_tag in form.find_all(['input', 'select', 'textarea']):
                name = input_tag.get('name')
                value = input_tag.get('value', '')
                input_type = input_tag.get('type', 'text')
                
                if name:
                    is_redirect = self.is_enhanced_redirect_parameter(name, value)
                    confidence = self.calculate_parameter_confidence(name, value, 'form_input')
                    
                    # Boost confidence for hidden inputs with redirect-like values
                    if input_type == 'hidden' and is_redirect:
                        confidence += 0.2
                    
                    params.append(EnhancedParameter(
                        name=name,
                        value=value,
                        source='form',
                        context='form_input',
                        url=form_url,
                        method=method,
                        is_redirect_related=is_redirect,
                        confidence=min(confidence, 1.0)
                    ))
        
        return params
    
    def extract_header_parameters(self, headers: Dict[str, str], url: str) -> List[EnhancedParameter]:
        """Extract parameters from HTTP headers"""
        params = []
        
        redirect_headers = ['Location', 'Refresh', 'Link', 'Content-Location']
        
        for header_name, header_value in headers.items():
            if header_name in redirect_headers:
                params.append(EnhancedParameter(
                    name=header_name.lower(),
                    value=header_value,
                    source='headers',
                    context='http_header',
                    url=url,
                    is_redirect_related=True,
                    confidence=0.9
                ))
        
        return params
    
    async def comprehensive_js_analysis(self, soup: BeautifulSoup, base_url: str) -> List[EnhancedParameter]:
        """Comprehensive JavaScript analysis using advanced analyzer"""
        params = []
        
        # Analyze external JavaScript files
        for script in soup.find_all('script', src=True):
            src = script['src']
            js_url = urljoin(base_url, src)
            if self.is_same_domain(js_url):
                self.js_files.add(js_url)
                js_params = await self.analyze_external_js_file(js_url)
                params.extend(js_params)
        
        # Analyze inline JavaScript
        for script in soup.find_all('script'):
            if script.string:
                inline_params = self.analyze_inline_javascript(script.string, base_url)
                params.extend(inline_params)
        
        return params
    
    async def analyze_external_js_file(self, js_url: str) -> List[EnhancedParameter]:
        """Analyze external JavaScript file with advanced techniques"""
        params = []
        
        try:
            async with self.session.get(js_url) as response:
                js_content = await response.text()
                
                # Comprehensive analysis using our advanced analyzer
                analysis_result = self.js_analyzer.comprehensive_analysis(js_content, js_url)
                
                # Convert JSParameter to EnhancedParameter
                for js_param in analysis_result['parameters']:
                    enhanced_param = EnhancedParameter(
                        name=js_param.name,
                        value=js_param.value,
                        source='javascript',
                        context=js_param.context,
                        url=js_url,
                        is_redirect_related=js_param.is_redirect_sink or js_param.is_user_controlled,
                        confidence=js_param.confidence,
                        js_analysis={
                            'data_flows': analysis_result['data_flows'],
                            'dom_sinks': analysis_result['dom_sinks'],
                            'url_patterns': analysis_result['url_patterns'],
                            'event_handlers': analysis_result['event_handlers']
                        }
                    )
                    params.append(enhanced_param)
                
        except Exception as e:
            self.logger.error(f"Error analyzing JavaScript file {js_url}: {e}")
        
        return params
    
    def analyze_inline_javascript(self, js_content: str, base_url: str) -> List[EnhancedParameter]:
        """Analyze inline JavaScript with enhanced detection"""
        params = []
        
        # Use comprehensive analysis
        analysis_result = self.js_analyzer.comprehensive_analysis(js_content, f"{base_url}#inline")
        
        # Convert results
        for js_param in analysis_result['parameters']:
            enhanced_param = EnhancedParameter(
                name=js_param.name,
                value=js_param.value,
                source='javascript',
                context='inline_js',
                url=base_url,
                is_redirect_related=js_param.is_redirect_sink or js_param.is_user_controlled,
                confidence=js_param.confidence,
                js_analysis=analysis_result
            )
            params.append(enhanced_param)
        
        return params
    
    def analyze_web3_patterns(self, content: str, url: str) -> List[EnhancedParameter]:
        """Analyze Web3-specific patterns and parameters"""
        params = []
        
        # Check if this is a Web3 application
        if not any(pattern in content.lower() for pattern in self.web3_patterns):
            return params
        
        self.logger.info(f"Detected Web3 application at {url}")
        
        # Web3-specific parameter patterns
        web3_param_patterns = [
            r'contract\s*:\s*["\']([^"\']+)["\']',
            r'address\s*:\s*["\']([^"\']+)["\']',
            r'chainId\s*:\s*["\']?([^"\']+)["\']?',
            r'network\s*:\s*["\']([^"\']+)["\']',
            r'provider\s*:\s*["\']([^"\']+)["\']',
            r'wallet\s*:\s*["\']([^"\']+)["\']',
            r'connect\(["\']([^"\']+)["\']\)',
            r'switchChain\(["\']?([^"\']+)["\']?\)',
        ]
        
        lines = content.split('\n')
        for line_num, line in enumerate(lines, 1):
            for pattern in web3_param_patterns:
                matches = re.finditer(pattern, line, re.IGNORECASE)
                for match in matches:
                    param_value = match.group(1)
                    param_name = f"web3_{match.group(0).split(':')[0].split('(')[0].strip()}"
                    
                    params.append(EnhancedParameter(
                        name=param_name,
                        value=param_value,
                        source='web3',
                        context='web3_config',
                        url=url,
                        is_redirect_related=True,
                        confidence=0.7,
                        web3_metadata={
                            'pattern': pattern,
                            'line_number': line_num,
                            'is_contract_related': 'contract' in param_name.lower()
                        }
                    ))
        
        return params
    
    def should_perform_dynamic_analysis(self, url: str, content: str) -> bool:
        """Determine if dynamic analysis is needed for this page"""
        # Perform dynamic analysis for:
        # 1. Pages with significant JavaScript
        # 2. Pages with forms
        # 3. Pages with Web3 content
        # 4. Pages with SPA patterns
        
        indicators = [
            len(re.findall(r'<script[^>]*>', content)) > 3,  # Many scripts
            'react' in content.lower() or 'vue' in content.lower() or 'angular' in content.lower(),  # SPA
            any(pattern in content.lower() for pattern in self.web3_patterns),  # Web3
            len(re.findall(r'<form[^>]*>', content)) > 0,  # Forms
            'addEventListener' in content or 'onclick' in content  # Event handlers
        ]
        
        return any(indicators)
    
    async def dynamic_page_analysis(self, url: str) -> List[EnhancedParameter]:
        """Perform dynamic analysis using Selenium"""
        params = []
        
        if not self.driver:
            return params
        
        try:
            self.driver.get(url)
            await asyncio.sleep(3)  # Wait for JavaScript execution
            
            # Execute JavaScript to extract runtime parameters
            js_extract_script = """
            var params = [];
            
            // Extract URL parameters
            if (window.location.search) {
                var urlParams = new URLSearchParams(window.location.search);
                for (let [key, value] of urlParams) {
                    params.push({name: key, value: value, source: 'url_runtime', context: 'query'});
                }
            }
            
            // Extract hash parameters
            if (window.location.hash) {
                var hashParams = window.location.hash.substring(1);
                if (hashParams.includes('=')) {
                    var hashUrlParams = new URLSearchParams(hashParams);
                    for (let [key, value] of hashUrlParams) {
                        params.push({name: key, value: value, source: 'url_runtime', context: 'hash'});
                    }
                }
            }
            
            // Extract form data
            var forms = document.querySelectorAll('form');
            forms.forEach(function(form, formIndex) {
                var formData = new FormData(form);
                for (let [key, value] of formData) {
                    params.push({name: key, value: value, source: 'form_runtime', context: 'form_data'});
                }
            });
            
            // Extract global variables
            for (var prop in window) {
                if (typeof window[prop] === 'string' && window[prop].length < 1000) {
                    if (prop.toLowerCase().includes('url') || prop.toLowerCase().includes('redirect')) {
                        params.push({name: prop, value: window[prop], source: 'global_runtime', context: 'global_var'});
                    }
                }
            }
            
            return params;
            """
            
            runtime_params = self.driver.execute_script(js_extract_script)
            
            # Convert runtime parameters to EnhancedParameter objects
            for param_data in runtime_params:
                is_redirect = self.is_enhanced_redirect_parameter(param_data['name'], param_data['value'])
                confidence = self.calculate_parameter_confidence(param_data['name'], param_data['value'], param_data['context'])
                
                params.append(EnhancedParameter(
                    name=param_data['name'],
                    value=param_data['value'],
                    source=param_data['source'],
                    context=param_data['context'],
                    url=url,
                    is_redirect_related=is_redirect,
                    confidence=confidence
                ))
            
        except Exception as e:
            self.logger.error(f"Dynamic analysis failed for {url}: {e}")
        
        return params
    
    def is_enhanced_redirect_parameter(self, param_name: str, param_value: str = "") -> bool:
        """Enhanced redirect parameter detection"""
        param_lower = param_name.lower()
        value_lower = param_value.lower()
        
        # Check parameter name
        name_match = any(pattern in param_lower for pattern in self.redirect_patterns)
        
        # Check parameter value for URL patterns
        value_match = bool(re.match(r'https?://', value_lower) or 
                          re.match(r'//', value_lower) or
                          '.' in value_lower and len(value_lower) > 3)
        
        # Web3-specific redirect patterns
        web3_match = any(pattern in param_lower for pattern in [
            'contract', 'address', 'chain', 'network', 'provider'
        ]) and any(pattern in value_lower for pattern in [
            'http', 'ipfs', 'ens', 'eth'
        ])
        
        return name_match or value_match or web3_match
    
    def calculate_parameter_confidence(self, param_name: str, param_value: str, context: str) -> float:
        """Calculate confidence score for parameter relevance"""
        confidence = 0.0
        
        # Base confidence by context
        context_scores = {
            'query': 0.6,
            'fragment': 0.7,
            'form_input': 0.5,
            'form_action': 0.8,
            'js_variable': 0.4,
            'inline_js': 0.6,
            'http_header': 0.9,
            'web3_config': 0.7
        }
        confidence += context_scores.get(context, 0.3)
        
        # Boost for redirect-related names
        if self.is_enhanced_redirect_parameter(param_name):
            confidence += 0.3
        
        # Boost for URL-like values
        if param_value and (param_value.startswith(('http', '//', 'javascript:')) or 
                           '.' in param_value and len(param_value) > 5):
            confidence += 0.2
        
        return min(confidence, 1.0)
    
    def is_same_domain(self, url: str) -> bool:
        """Enhanced domain checking with subdomain support"""
        try:
            parsed = urlparse(url)
            target_domain = parsed.netloc.lower()
            base_domain = self.base_domain.lower()
            
            # Exact match
            if target_domain == base_domain:
                return True
            
            # Subdomain match
            if target_domain.endswith(f'.{base_domain}'):
                return True
            
            # Handle www prefixes
            if target_domain.startswith('www.') and target_domain[4:] == base_domain:
                return True
            if base_domain.startswith('www.') and base_domain[4:] == target_domain:
                return True
            
            return False
        except:
            return False
    
    async def enhanced_vulnerability_testing(self) -> List[EnhancedVulnerability]:
        """Enhanced vulnerability testing with context-aware payloads"""
        self.logger.info("Starting enhanced vulnerability testing")
        
        vulnerabilities = []
        
        # Sort parameters by confidence and redirect-relevance
        sorted_params = sorted(
            self.parameters, 
            key=lambda p: (p.is_redirect_related, p.confidence), 
            reverse=True
        )
        
        # Test high-confidence parameters first
        high_confidence_params = [p for p in sorted_params if p.confidence > 0.6]
        medium_confidence_params = [p for p in sorted_params if 0.3 <= p.confidence <= 0.6]
        
        self.logger.info(f"Testing {len(high_confidence_params)} high-confidence parameters")
        
        # Test high-confidence parameters with all payload categories
        for param in high_confidence_params:
            context = self.detect_enhanced_context(param)
            payloads = self.get_context_aware_payloads(context, param)
            
            for payload in payloads:
                vuln = await self.test_enhanced_parameter(param, payload)
                if vuln:
                    vulnerabilities.append(vuln)
                
                await asyncio.sleep(0.1)  # Rate limiting
        
        # Test medium-confidence parameters with limited payloads
        self.logger.info(f"Testing {len(medium_confidence_params)} medium-confidence parameters")
        
        for param in medium_confidence_params[:50]:  # Limit to first 50
            context = self.detect_enhanced_context(param)
            payloads = self.get_context_aware_payloads(context, param)[:3]  # Only top 3 payloads
            
            for payload in payloads:
                vuln = await self.test_enhanced_parameter(param, payload)
                if vuln:
                    vulnerabilities.append(vuln)
                
                await asyncio.sleep(0.1)
        
        # DOM-based testing
        dom_vulns = await self.test_dom_based_redirects()
        vulnerabilities.extend(dom_vulns)
        
        self.vulnerabilities = vulnerabilities
        self.logger.info(f"Enhanced testing completed. Found {len(vulnerabilities)} vulnerabilities")
        return vulnerabilities
    
    def detect_enhanced_context(self, param: EnhancedParameter) -> str:
        """Enhanced context detection for better payload selection"""
        # Use existing context if available
        if param.context in ['query', 'fragment', 'form_action', 'http_header']:
            return param.context
        
        # Analyze parameter value for context clues
        value = param.value.lower()
        name = param.name.lower()
        
        # JavaScript context
        if param.source == 'javascript' or 'js' in param.context:
            if 'location' in value or 'href' in value:
                return 'js_location'
            elif 'url' in name or 'redirect' in name:
                return 'js_url_param'
            else:
                return 'js_generic'
        
        # Web3 context
        elif param.source == 'web3':
            return 'web3_redirect'
        
        # URL context analysis
        elif value.startswith(('http', '//', 'javascript:')):
            return 'url_value'
        
        # Form context
        elif param.source == 'form':
            if param.context == 'form_action':
                return 'form_action'
            else:
                return 'form_input'
        
        return 'generic'
    
    def get_context_aware_payloads(self, context: str, param: EnhancedParameter) -> List[str]:
        """Get enhanced context-aware payloads"""
        all_payloads = self.payloads
        
        context_mapping = {
            'query': all_payloads['basic_redirect'] + all_payloads['encoded_redirect'],
            'fragment': all_payloads['basic_redirect'] + all_payloads['protocol_bypass'],
            'form_action': all_payloads['basic_redirect'] + all_payloads['encoded_redirect'],
            'form_input': all_payloads['basic_redirect'] + all_payloads['javascript_payload'],
            'js_location': all_payloads['javascript_payload'] + all_payloads['basic_redirect'],
            'js_url_param': all_payloads['basic_redirect'] + all_payloads['encoded_redirect'],
            'js_generic': all_payloads['basic_redirect'],
            'web3_redirect': all_payloads['web3_specific'] + all_payloads['basic_redirect'],
            'url_value': all_payloads['protocol_bypass'] + all_payloads['unicode_bypass'],
            'http_header': all_payloads['basic_redirect'],
            'generic': all_payloads['basic_redirect'][:5]
        }
        
        payloads = context_mapping.get(context, all_payloads['basic_redirect'][:5])
        
        # Add context-specific modifications
        if param.web3_metadata:
            # Add Web3-specific payloads
            payloads.extend(all_payloads['web3_specific'])
        
        return payloads
    
    async def test_enhanced_parameter(self, param: EnhancedParameter, payload: str) -> Optional[EnhancedVulnerability]:
        """Enhanced parameter testing with better detection"""
        try:
            # Construct test URL
            test_url = self.construct_enhanced_test_url(param, payload)
            
            # Test with HTTP request
            async with self.session.get(test_url, allow_redirects=False) as response:
                # Check for redirect responses
                if response.status in [301, 302, 303, 307, 308]:
                    location = response.headers.get('Location', '')
                    
                    if self.is_successful_enhanced_redirect(location, payload):
                        self.logger.info(f"Found open redirect: {test_url}")
                        
                        # Calculate vulnerability metrics
                        confidence = self.calculate_vulnerability_confidence(param, payload, response)
                        complexity = self.assess_exploitation_complexity(param, payload)
                        impact = self.assess_impact(param, location)
                        remediation = self.suggest_remediation(param, payload)
                        
                        # Take screenshot
                        screenshot_path = await self.take_enhanced_screenshot(test_url, location)
                        
                        return EnhancedVulnerability(
                            url=test_url,
                            parameter=param.name,
                            payload=payload,
                            method=param.method,
                            response_code=response.status,
                            redirect_url=location,
                            context=param.context,
                            screenshot_path=screenshot_path,
                            timestamp=datetime.now().isoformat(),
                            vulnerability_type="open_redirect",
                            confidence=confidence,
                            exploitation_complexity=complexity,
                            impact_assessment=impact,
                            remediation_suggestion=remediation,
                            js_flow_analysis=param.js_analysis
                        )
                
                # Check response content for DOM-based redirects
                content = await response.text()
                dom_vuln = self.check_enhanced_dom_redirect(content, test_url, param, payload)
                if dom_vuln:
                    return dom_vuln
                    
        except Exception as e:
            self.logger.debug(f"Error testing enhanced parameter {param.name} with payload {payload}: {e}")
        
        return None
    
    def construct_enhanced_test_url(self, param: EnhancedParameter, payload: str) -> str:
        """Enhanced test URL construction with better encoding handling"""
        parsed = urlparse(param.url)
        
        if param.context == 'query':
            query_params = parse_qs(parsed.query, keep_blank_values=True)
            query_params[param.name] = [payload]
            new_query = urllib.parse.urlencode(query_params, doseq=True, safe=':/?#[]@!$&\'()*+,;=')
            return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
        
        elif param.context in ['fragment', 'hash']:
            return f"{param.url.split('#')[0]}#{param.name}={urllib.parse.quote(payload, safe=':/?#[]@!$&\'()*+,;=')}"
        
        elif param.context == 'form_action':
            # For form actions, test by replacing the action value
            return payload if payload.startswith(('http', '//')) else urljoin(param.url, payload)
        
        elif param.context in ['form_input', 'form_data']:
            separator = '&' if '?' in param.url else '?'
            encoded_payload = urllib.parse.quote(payload, safe=':/?#[]@!$&\'()*+,;=')
            return f"{param.url}{separator}{param.name}={encoded_payload}"
        
        else:
            # Generic parameter injection
            separator = '&' if '?' in param.url else '?'
            encoded_payload = urllib.parse.quote(payload, safe=':/?#[]@!$&\'()*+,;=')
            return f"{param.url}{separator}{param.name}={encoded_payload}"
    
    def is_successful_enhanced_redirect(self, location: str, payload: str) -> bool:
        """Enhanced redirect success detection"""
        if not location:
            return False
        
        # Normalize location
        location_lower = location.lower()
        decoded_location = unquote(location).lower()
        
        # Check for our test domains
        test_domains = ['google.com', 'evil.com', 'example.com']
        for domain in test_domains:
            if domain in location_lower or domain in decoded_location:
                return True
        
        # Check for IP addresses
        ip_patterns = [
            '216.58.214.206', '0xd8.0x3a.0xd6.0xce', '3627734734',
            '472.314.470.462', '0330.072.0326.0316'
        ]
        for ip in ip_patterns:
            if ip in location or ip in decoded_location:
                return True
        
        # Check for Web3-specific redirects
        web3_indicators = ['metamask.io', 'wallet.connect', 'uniswap.org', 'opensea.io']
        for indicator in web3_indicators:
            if indicator in location_lower or indicator in decoded_location:
                return True
        
        # Check for JavaScript protocol
        if location_lower.startswith('javascript:') and ('confirm' in location_lower or 'prompt' in location_lower):
            return True
        
        return False
    
    def calculate_vulnerability_confidence(self, param: EnhancedParameter, payload: str, response: Any) -> float:
        """Calculate confidence score for vulnerability"""
        confidence = param.confidence
        
        # Boost for direct redirects
        if response.status in [301, 302]:
            confidence += 0.2
        elif response.status in [303, 307, 308]:
            confidence += 0.1
        
        # Boost for redirect-related parameter names
        if param.is_redirect_related:
            confidence += 0.2
        
        # Boost for high-confidence contexts
        if param.context in ['form_action', 'http_header']:
            confidence += 0.1
        
        return min(confidence, 1.0)
    
    def assess_exploitation_complexity(self, param: EnhancedParameter, payload: str) -> str:
        """Assess exploitation complexity"""
        if param.context in ['query', 'fragment']:
            return "LOW"
        elif param.context in ['form_input', 'form_action']:
            return "MEDIUM"
        elif param.source == 'javascript':
            return "HIGH"
        else:
            return "MEDIUM"
    
    def assess_impact(self, param: EnhancedParameter, redirect_url: str) -> str:
        """Assess vulnerability impact"""
        # Check if redirect goes to external domain
        if redirect_url.startswith(('http://', 'https://')):
            redirect_domain = urlparse(redirect_url).netloc
            if redirect_domain != self.base_domain:
                return "HIGH"
        
        # Check for JavaScript execution
        if redirect_url.startswith('javascript:'):
            return "CRITICAL"
        
        # Check for data protocol
        if redirect_url.startswith('data:'):
            return "HIGH"
        
        return "MEDIUM"
    
    def suggest_remediation(self, param: EnhancedParameter, payload: str) -> str:
        """Suggest remediation for the vulnerability"""
        remediations = {
            'query': "Validate and sanitize URL parameters. Use allowlist of permitted redirect URLs.",
            'fragment': "Implement client-side validation for fragment parameters.",
            'form_action': "Validate form action URLs against allowlist of permitted destinations.",
            'form_input': "Implement server-side validation for all form inputs.",
            'js_variable': "Sanitize user input before using in JavaScript redirects.",
            'http_header': "Validate redirect headers on server-side."
        }
        
        return remediations.get(param.context, "Implement proper input validation and use allowlist approach.")
    
    async def test_dom_based_redirects(self) -> List[EnhancedVulnerability]:
        """Test for DOM-based redirect vulnerabilities"""
        dom_vulnerabilities = []
        
        if not self.driver:
            return dom_vulnerabilities
        
        # Test each discovered URL for DOM-based redirects
        for url in list(self.discovered_urls)[:20]:  # Limit for performance
            try:
                self.driver.get(url)
                await asyncio.sleep(2)
                
                # Inject DOM-based payloads
                dom_payloads = [
                    "//google.com",
                    "javascript:confirm(1)",
                    "https://evil.com"
                ]
                
                for payload in dom_payloads:
                    # Test hash-based injection
                    test_url = f"{url}#{payload}"
                    dom_vuln = await self.test_dom_redirect(test_url, payload)
                    if dom_vuln:
                        dom_vulnerabilities.append(dom_vuln)
                
            except Exception as e:
                self.logger.error(f"DOM testing error for {url}: {e}")
        
        return dom_vulnerabilities
    
    async def test_dom_redirect(self, test_url: str, payload: str) -> Optional[EnhancedVulnerability]:
        """Test individual DOM-based redirect"""
        try:
            self.driver.get(test_url)
            await asyncio.sleep(3)
            
            # Check if redirect occurred
            current_url = self.driver.current_url
            if current_url != test_url and self.is_successful_enhanced_redirect(current_url, payload):
                screenshot_path = await self.take_enhanced_screenshot(test_url, current_url)
                
                return EnhancedVulnerability(
                    url=test_url,
                    parameter="hash_fragment",
                    payload=payload,
                    method="GET",
                    response_code=200,
                    redirect_url=current_url,
                    context="dom_based",
                    screenshot_path=screenshot_path,
                    timestamp=datetime.now().isoformat(),
                    vulnerability_type="dom_based_redirect",
                    confidence=0.9,
                    exploitation_complexity="MEDIUM",
                    impact_assessment="HIGH",
                    remediation_suggestion="Implement client-side input validation for hash parameters."
                )
            
        except Exception as e:
            self.logger.debug(f"DOM redirect test failed for {test_url}: {e}")
        
        return None
    
    def check_enhanced_dom_redirect(self, content: str, test_url: str, param: EnhancedParameter, payload: str) -> Optional[EnhancedVulnerability]:
        """Enhanced DOM-based redirect detection in response content"""
        # Use advanced DOM analyzer
        dom_sources = self.dom_analyzer.analyze_dom_sources(content)
        data_flows = self.dom_analyzer.trace_data_flow(content)
        
        # Check if parameter is used in dangerous data flows
        for flow in data_flows:
            if param.name in flow.get('variable', '') or payload in flow.get('flow_path', ''):
                return EnhancedVulnerability(
                    url=test_url,
                    parameter=param.name,
                    payload=payload,
                    method=param.method,
                    response_code=200,
                    redirect_url=flow.get('sink', ''),
                    context=param.context,
                    timestamp=datetime.now().isoformat(),
                    vulnerability_type="dom_based_redirect",
                    confidence=flow.get('confidence', 0.7),
                    exploitation_complexity="HIGH",
                    impact_assessment="HIGH",
                    remediation_suggestion="Sanitize user input before DOM manipulation.",
                    js_flow_analysis=flow
                )
        
        return None
    
    async def take_enhanced_screenshot(self, test_url: str, redirect_url: str = None) -> Optional[str]:
        """Take enhanced screenshot with better error handling"""
        if not self.driver:
            return None
        
        try:
            # Create screenshots directory
            screenshots_dir = Path("/workspace/screenshots")
            screenshots_dir.mkdir(exist_ok=True)
            
            # Generate unique filename
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
            url_hash = hashlib.md5(test_url.encode()).hexdigest()[:8]
            filename = f"poc_{timestamp}_{url_hash}.png"
            screenshot_path = screenshots_dir / filename
            
            # Navigate to test URL
            self.driver.get(test_url)
            await asyncio.sleep(3)  # Wait for page load and JavaScript execution
            
            # Take full page screenshot
            self.driver.save_screenshot(str(screenshot_path))
            
            # If redirect occurred, also screenshot the final page
            if redirect_url and redirect_url != test_url:
                final_filename = f"final_{timestamp}_{url_hash}.png"
                final_screenshot_path = screenshots_dir / final_filename
                
                self.driver.get(redirect_url)
                await asyncio.sleep(2)
                self.driver.save_screenshot(str(final_screenshot_path))
            
            self.logger.info(f"Enhanced screenshot saved: {screenshot_path}")
            return str(screenshot_path)
            
        except Exception as e:
            self.logger.error(f"Error taking enhanced screenshot for {test_url}: {e}")
            return None
    
    def save_enhanced_parameters(self, filename: str = "enhanced_parameters.json"):
        """Save all parameters with enhanced metadata"""
        # Prepare enhanced data structure
        params_data = {
            'scan_metadata': {
                'target_url': self.target_url,
                'scan_date': datetime.now().isoformat(),
                'total_parameters': len(self.parameters),
                'redirect_related_count': len([p for p in self.parameters if p.is_redirect_related]),
                'high_confidence_count': len([p for p in self.parameters if p.confidence > 0.7]),
                'web3_parameters_count': len([p for p in self.parameters if p.source == 'web3']),
                'js_parameters_count': len([p for p in self.parameters if p.source == 'javascript'])
            },
            'parameters': [asdict(param) for param in self.parameters],
            'vulnerabilities': [asdict(vuln) for vuln in self.vulnerabilities],
            'statistics': {
                'urls_crawled': len(self.discovered_urls),
                'js_files_analyzed': len(self.js_files),
                'web3_endpoints_found': len(self.web3_endpoints)
            }
        }
        
        output_path = Path("/workspace") / filename
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(params_data, f, indent=2, ensure_ascii=False)
        
        self.logger.info(f"Enhanced parameters saved to {output_path}")
        
        # Also save CSV for easy analysis
        self.save_parameters_csv()
    
    def save_parameters_csv(self):
        """Save parameters in CSV format for analysis"""
        import csv
        
        csv_path = Path("/workspace") / "parameters_analysis.csv"
        
        with open(csv_path, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = [
                'name', 'value', 'source', 'context', 'url', 'method',
                'is_redirect_related', 'confidence', 'vulnerability_found'
            ]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            # Check which parameters have vulnerabilities
            vuln_params = {v.parameter for v in self.vulnerabilities}
            
            for param in self.parameters:
                writer.writerow({
                    'name': param.name,
                    'value': param.value[:100],  # Truncate long values
                    'source': param.source,
                    'context': param.context,
                    'url': param.url,
                    'method': param.method,
                    'is_redirect_related': param.is_redirect_related,
                    'confidence': param.confidence,
                    'vulnerability_found': param.name in vuln_params
                })
    
    def generate_enhanced_report(self, output_file: str = "enhanced_open_redirect_report.html"):
        """Generate comprehensive enhanced HTML report"""
        template_str = """
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Enhanced Open Redirect Vulnerability Report</title>
            <style>
                body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); }
                .container { max-width: 1400px; margin: 0 auto; background: white; border-radius: 12px; box-shadow: 0 10px 30px rgba(0,0,0,0.3); overflow: hidden; }
                .header { background: linear-gradient(135deg, #d32f2f 0%, #f44336 100%); color: white; padding: 30px; text-align: center; }
                .header h1 { margin: 0; font-size: 2.5em; font-weight: 300; }
                .header p { margin: 10px 0 0 0; opacity: 0.9; }
                .content { padding: 30px; }
                .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }
                .summary-card { background: #f8f9fa; border-radius: 8px; padding: 20px; text-align: center; border-left: 4px solid #2196f3; }
                .summary-card h3 { margin: 0 0 10px 0; color: #333; }
                .summary-card .number { font-size: 2em; font-weight: bold; color: #2196f3; }
                .vulnerability { background: #ffebee; border-radius: 8px; padding: 20px; margin-bottom: 20px; border-left: 6px solid #f44336; }
                .vulnerability.critical { border-left-color: #d32f2f; background: #fce4ec; }
                .vulnerability.high { border-left-color: #f44336; background: #ffebee; }
                .vulnerability.medium { border-left-color: #ff9800; background: #fff3e0; }
                .vulnerability.low { border-left-color: #4caf50; background: #e8f5e8; }
                .vuln-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px; }
                .vuln-title { font-size: 1.3em; font-weight: bold; margin: 0; }
                .confidence-badge { padding: 4px 12px; border-radius: 20px; font-size: 0.8em; font-weight: bold; }
                .confidence-high { background: #4caf50; color: white; }
                .confidence-medium { background: #ff9800; color: white; }
                .confidence-low { background: #f44336; color: white; }
                .parameter { background: #f3e5f5; border-radius: 6px; padding: 15px; margin-bottom: 15px; border-left: 4px solid #9c27b0; }
                .parameter.redirect-related { border-left-color: #f44336; background: #ffebee; }
                .parameter.high-confidence { border-left-color: #4caf50; }
                .screenshot { max-width: 100%; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.15); margin: 10px 0; }
                .code { background: #2d2d2d; color: #f8f8f2; padding: 15px; border-radius: 6px; font-family: 'Courier New', monospace; overflow-x: auto; font-size: 0.9em; }
                .metadata { font-size: 0.9em; color: #666; margin-top: 10px; }
                .success { color: #4caf50; font-weight: bold; }
                .warning { color: #ff9800; font-weight: bold; }
                .error { color: #f44336; font-weight: bold; }
                .critical { color: #d32f2f; font-weight: bold; }
                .tabs { display: flex; border-bottom: 1px solid #ddd; margin-bottom: 20px; }
                .tab { padding: 12px 24px; cursor: pointer; border-bottom: 2px solid transparent; }
                .tab.active { border-bottom-color: #2196f3; background: #e3f2fd; }
                .tab-content { display: none; }
                .tab-content.active { display: block; }
                .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 15px; margin: 20px 0; }
                .stat-item { background: #f8f9fa; padding: 15px; border-radius: 6px; }
            </style>
            <script>
                function showTab(tabName) {
                    // Hide all tab contents
                    var contents = document.querySelectorAll('.tab-content');
                    contents.forEach(function(content) {
                        content.classList.remove('active');
                    });
                    
                    // Remove active class from all tabs
                    var tabs = document.querySelectorAll('.tab');
                    tabs.forEach(function(tab) {
                        tab.classList.remove('active');
                    });
                    
                    // Show selected tab content
                    document.getElementById(tabName).classList.add('active');
                    event.target.classList.add('active');
                }
            </script>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🔍 Enhanced Open Redirect Scanner</h1>
                    <p>Professional Security Assessment with Advanced Analysis</p>
                </div>
                
                <div class="content">
                    <div class="summary">
                        <div class="summary-card">
                            <h3>Target</h3>
                            <div class="number">{{ target_domain }}</div>
                        </div>
                        <div class="summary-card">
                            <h3>URLs Crawled</h3>
                            <div class="number">{{ urls_crawled }}</div>
                        </div>
                        <div class="summary-card">
                            <h3>Parameters Found</h3>
                            <div class="number">{{ total_parameters }}</div>
                        </div>
                        <div class="summary-card">
                            <h3>Redirect Parameters</h3>
                            <div class="number">{{ redirect_parameters }}</div>
                        </div>
                        <div class="summary-card">
                            <h3>Vulnerabilities</h3>
                            <div class="number {% if vulnerabilities_count > 0 %}error{% else %}success{% endif %}">{{ vulnerabilities_count }}</div>
                        </div>
                        <div class="summary-card">
                            <h3>JS Files Analyzed</h3>
                            <div class="number">{{ js_files_count }}</div>
                        </div>
                    </div>
                    
                    <div class="tabs">
                        <div class="tab active" onclick="showTab('vulnerabilities')">🚨 Vulnerabilities</div>
                        <div class="tab" onclick="showTab('parameters')">🔍 Parameters</div>
                        <div class="tab" onclick="showTab('statistics')">📊 Statistics</div>
                        <div class="tab" onclick="showTab('methodology')">🔬 Methodology</div>
                    </div>
                    
                    <div id="vulnerabilities" class="tab-content active">
                        {% if vulnerabilities %}
                        <h2>🚨 Discovered Vulnerabilities</h2>
                        {% for vuln in vulnerabilities %}
                        <div class="vulnerability {{ vuln.impact_assessment.lower() }}">
                            <div class="vuln-header">
                                <h3 class="vuln-title">{{ vuln.vulnerability_type|title }} #{{ loop.index }}</h3>
                                <span class="confidence-badge confidence-{{ 'high' if vuln.confidence > 0.7 else 'medium' if vuln.confidence > 0.4 else 'low' }}">
                                    Confidence: {{ "%.1f"|format(vuln.confidence * 100) }}%
                                </span>
                            </div>
                            
                            <div class="stats-grid">
                                <div class="stat-item">
                                    <strong>URL:</strong><br>
                                    <code>{{ vuln.url }}</code>
                                </div>
                                <div class="stat-item">
                                    <strong>Parameter:</strong><br>
                                    <code>{{ vuln.parameter }}</code>
                                </div>
                                <div class="stat-item">
                                    <strong>Method:</strong><br>
                                    {{ vuln.method }}
                                </div>
                                <div class="stat-item">
                                    <strong>Response Code:</strong><br>
                                    {{ vuln.response_code }}
                                </div>
                                <div class="stat-item">
                                    <strong>Impact:</strong><br>
                                    <span class="{{ vuln.impact_assessment.lower() }}">{{ vuln.impact_assessment }}</span>
                                </div>
                                <div class="stat-item">
                                    <strong>Complexity:</strong><br>
                                    {{ vuln.exploitation_complexity }}
                                </div>
                            </div>
                            
                            <p><strong>Payload:</strong></p>
                            <div class="code">{{ vuln.payload }}</div>
                            
                            <p><strong>Redirect URL:</strong></p>
                            <div class="code">{{ vuln.redirect_url }}</div>
                            
                            <p><strong>Remediation:</strong></p>
                            <div style="background: #e8f5e8; padding: 10px; border-radius: 4px; border-left: 4px solid #4caf50;">
                                {{ vuln.remediation_suggestion }}
                            </div>
                            
                            {% if vuln.screenshot_path %}
                            <div class="screenshot-container">
                                <h4>📸 Proof of Concept Screenshot:</h4>
                                <img src="{{ vuln.screenshot_path }}" alt="PoC Screenshot" class="screenshot">
                            </div>
                            {% endif %}
                            
                            <div class="metadata">
                                <strong>Timestamp:</strong> {{ vuln.timestamp }} | 
                                <strong>Context:</strong> {{ vuln.context }} |
                                <strong>Type:</strong> {{ vuln.vulnerability_type }}
                            </div>
                        </div>
                        {% endfor %}
                        {% else %}
                        <div style="text-align: center; padding: 40px; background: #e8f5e8; border-radius: 8px;">
                            <h2 class="success">✅ No Open Redirect Vulnerabilities Found</h2>
                            <p>The target application appears to be properly protected against open redirect attacks.</p>
                        </div>
                        {% endif %}
                    </div>
                    
                    <div id="parameters" class="tab-content">
                        <h2>🔍 Discovered Parameters Analysis</h2>
                        <p><strong>Total parameters:</strong> {{ total_parameters }}</p>
                        <p><strong>Redirect-related:</strong> {{ redirect_parameters }}</p>
                        <p><strong>High confidence:</strong> {{ high_confidence_parameters }}</p>
                        
                        <h3>🎯 High-Priority Parameters</h3>
                        {% for param in high_priority_params %}
                        <div class="parameter {% if param.is_redirect_related %}redirect-related{% endif %} {% if param.confidence > 0.7 %}high-confidence{% endif %}">
                            <h4>{{ param.name }} 
                                {% if param.is_redirect_related %}<span class="error">(Redirect-Related)</span>{% endif %}
                                <span class="confidence-badge confidence-{{ 'high' if param.confidence > 0.7 else 'medium' if param.confidence > 0.4 else 'low' }}">
                                    {{ "%.1f"|format(param.confidence * 100) }}%
                                </span>
                            </h4>
                            <p><strong>Value:</strong> <code>{{ param.value[:200] }}{% if param.value|length > 200 %}...{% endif %}</code></p>
                            <p><strong>Source:</strong> {{ param.source }} | <strong>Context:</strong> {{ param.context }}</p>
                            <p><strong>URL:</strong> <code>{{ param.url }}</code></p>
                            {% if param.web3_metadata %}
                            <p><strong>Web3 Metadata:</strong> {{ param.web3_metadata }}</p>
                            {% endif %}
                        </div>
                        {% endfor %}
                    </div>
                    
                    <div id="statistics" class="tab-content">
                        <h2>📊 Detailed Statistics</h2>
                        
                        <div class="stats-grid">
                            <div class="stat-item">
                                <h4>Crawling Statistics</h4>
                                <p>URLs Discovered: {{ urls_crawled }}</p>
                                <p>Maximum Depth: {{ max_depth }}</p>
                                <p>JavaScript Files: {{ js_files_count }}</p>
                                <p>Web3 Endpoints: {{ web3_endpoints_count }}</p>
                            </div>
                            
                            <div class="stat-item">
                                <h4>Parameter Distribution</h4>
                                <p>URL Parameters: {{ url_params_count }}</p>
                                <p>Form Parameters: {{ form_params_count }}</p>
                                <p>JavaScript Parameters: {{ js_params_count }}</p>
                                <p>Web3 Parameters: {{ web3_params_count }}</p>
                            </div>
                            
                            <div class="stat-item">
                                <h4>Confidence Distribution</h4>
                                <p>High (>70%): {{ high_confidence_count }}</p>
                                <p>Medium (30-70%): {{ medium_confidence_count }}</p>
                                <p>Low (<30%): {{ low_confidence_count }}</p>
                            </div>
                            
                            <div class="stat-item">
                                <h4>Vulnerability Assessment</h4>
                                <p>Critical: {{ critical_vulns }}</p>
                                <p>High: {{ high_vulns }}</p>
                                <p>Medium: {{ medium_vulns }}</p>
                                <p>Low: {{ low_vulns }}</p>
                            </div>
                        </div>
                    </div>
                    
                    <div id="methodology" class="tab-content">
                        <h2>🔬 Scanning Methodology</h2>
                        
                        <h3>1. Deep Crawling Phase</h3>
                        <ul>
                            <li>Recursive URL discovery up to {{ max_depth }} levels deep</li>
                            <li>JavaScript-rendered content analysis</li>
                            <li>Form and input field enumeration</li>
                            <li>HTTP header parameter extraction</li>
                        </ul>
                        
                        <h3>2. JavaScript Analysis Phase</h3>
                        <ul>
                            <li>AST-based static analysis of JavaScript files</li>
                            <li>Data flow analysis from sources to sinks</li>
                            <li>DOM-based redirect sink detection</li>
                            <li>Runtime parameter extraction via Selenium</li>
                        </ul>
                        
                        <h3>3. Web3 Detection Phase</h3>
                        <ul>
                            <li>Smart contract interaction analysis</li>
                            <li>Wallet connection parameter extraction</li>
                            <li>DApp-specific redirect pattern detection</li>
                            <li>Blockchain network configuration analysis</li>
                        </ul>
                        
                        <h3>4. Vulnerability Testing Phase</h3>
                        <ul>
                            <li>Context-aware payload injection</li>
                            <li>Multi-encoding bypass techniques</li>
                            <li>DOM-based redirect testing</li>
                            <li>Screenshot-based proof of concept generation</li>
                        </ul>
                        
                        <h3>5. Payload Categories Used</h3>
                        <ul>
                            <li><strong>Basic Redirects:</strong> Standard HTTP redirects</li>
                            <li><strong>Encoded Bypasses:</strong> URL encoding variations</li>
                            <li><strong>Protocol Bypasses:</strong> Protocol-relative URLs</li>
                            <li><strong>Unicode Bypasses:</strong> Unicode character variations</li>
                            <li><strong>JavaScript Payloads:</strong> Client-side execution</li>
                            <li><strong>Web3 Payloads:</strong> Blockchain-specific redirects</li>
                        </ul>
                    </div>
                    
                    <div class="metadata" style="text-align: center; margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd;">
                        <p><strong>Report generated by Enhanced Professional Open Redirect Scanner v2.0</strong></p>
                        <p>Scan completed on {{ scan_date }}</p>
                        <p>Total scan time: {{ scan_duration }}</p>
                    </div>
                </div>
            </div>
        </body>
        </html>
        """
        
        template = Template(template_str)
        
        # Prepare comprehensive data for template
        redirect_params = [p for p in self.parameters if p.is_redirect_related]
        high_priority_params = [p for p in self.parameters if p.confidence > 0.6 or p.is_redirect_related]
        
        # Calculate statistics
        param_sources = {}
        confidence_distribution = {'high': 0, 'medium': 0, 'low': 0}
        vuln_impact_distribution = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        
        for param in self.parameters:
            param_sources[param.source] = param_sources.get(param.source, 0) + 1
            if param.confidence > 0.7:
                confidence_distribution['high'] += 1
            elif param.confidence > 0.3:
                confidence_distribution['medium'] += 1
            else:
                confidence_distribution['low'] += 1
        
        for vuln in self.vulnerabilities:
            impact_key = vuln.impact_assessment.lower()
            vuln_impact_distribution[impact_key] = vuln_impact_distribution.get(impact_key, 0) + 1
        
        report_data = {
            'target_url': self.target_url,
            'target_domain': self.base_domain,
            'scan_date': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'scan_duration': "N/A",  # Calculate actual duration
            'max_depth': self.max_depth,
            'urls_crawled': len(self.discovered_urls),
            'total_parameters': len(self.parameters),
            'redirect_parameters': len(redirect_params),
            'high_confidence_parameters': len([p for p in self.parameters if p.confidence > 0.7]),
            'vulnerabilities_count': len(self.vulnerabilities),
            'js_files_count': len(self.js_files),
            'web3_endpoints_count': len(self.web3_endpoints),
            'vulnerabilities': [asdict(v) for v in self.vulnerabilities],
            'high_priority_params': [asdict(p) for p in high_priority_params[:20]],  # Limit for display
            'url_params_count': param_sources.get('url', 0),
            'form_params_count': param_sources.get('form', 0),
            'js_params_count': param_sources.get('javascript', 0),
            'web3_params_count': param_sources.get('web3', 0),
            'high_confidence_count': confidence_distribution['high'],
            'medium_confidence_count': confidence_distribution['medium'],
            'low_confidence_count': confidence_distribution['low'],
            'critical_vulns': vuln_impact_distribution['critical'],
            'high_vulns': vuln_impact_distribution['high'],
            'medium_vulns': vuln_impact_distribution['medium'],
            'low_vulns': vuln_impact_distribution['low']
        }
        
        # Generate report
        report_html = template.render(**report_data)
        
        output_path = Path("/workspace") / output_file
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(report_html)
        
        self.logger.info(f"Enhanced report generated: {output_path}")
    
    async def run_enhanced_scan(self):
        """Run the complete enhanced scanning process"""
        start_time = time.time()
        self.logger.info("🚀 Starting Enhanced Professional Open Redirect Scanner")
        
        try:
            # Initialize components
            await self.init_session()
            self.init_enhanced_driver()
            
            # Phase 1: Enhanced deep crawling
            self.logger.info("Phase 1: Enhanced deep crawling and comprehensive parameter extraction")
            await self.enhanced_crawl_website()
            
            # Phase 2: Advanced parameter analysis
            self.logger.info("Phase 2: Advanced parameter analysis and confidence scoring")
            redirect_params = [p for p in self.parameters if p.is_redirect_related]
            high_conf_params = [p for p in self.parameters if p.confidence > 0.7]
            self.logger.info(f"Found {len(redirect_params)} redirect-related and {len(high_conf_params)} high-confidence parameters")
            
            # Phase 3: Enhanced vulnerability testing
            self.logger.info("Phase 3: Enhanced vulnerability testing with context-aware payloads")
            await self.enhanced_vulnerability_testing()
            
            # Phase 4: Results and reporting
            self.logger.info("Phase 4: Generating comprehensive results and reports")
            self.save_enhanced_parameters()
            self.generate_enhanced_report()
            
            # Final summary
            scan_duration = time.time() - start_time
            self.logger.info("🎯 Enhanced Scan Summary:")
            self.logger.info(f"   Scan Duration: {scan_duration:.2f} seconds")
            self.logger.info(f"   URLs Crawled: {len(self.discovered_urls)}")
            self.logger.info(f"   Parameters Found: {len(self.parameters)}")
            self.logger.info(f"   Redirect Parameters: {len(redirect_params)}")
            self.logger.info(f"   High-Confidence Parameters: {len(high_conf_params)}")
            self.logger.info(f"   JavaScript Files Analyzed: {len(self.js_files)}")
            self.logger.info(f"   Vulnerabilities Found: {len(self.vulnerabilities)}")
            
            # Vulnerability breakdown
            if self.vulnerabilities:
                impact_counts = {}
                for vuln in self.vulnerabilities:
                    impact_counts[vuln.impact_assessment] = impact_counts.get(vuln.impact_assessment, 0) + 1
                
                self.logger.info("   Vulnerability Breakdown:")
                for impact, count in impact_counts.items():
                    self.logger.info(f"     {impact}: {count}")
            
        except Exception as e:
            self.logger.error(f"Enhanced scan failed: {e}")
            raise
        finally:
            # Cleanup
            if self.session:
                await self.session.close()
            if self.driver:
                self.driver.quit()


async def main():
    """Enhanced main function with better argument handling"""
    parser = argparse.ArgumentParser(description='Enhanced Professional Open Redirect Vulnerability Scanner')
    parser.add_argument('target', help='Target URL to scan')
    parser.add_argument('--depth', type=int, default=3, help='Maximum crawling depth (default: 3)')
    parser.add_argument('--max-pages', type=int, default=200, help='Maximum pages to crawl (default: 200)')
    parser.add_argument('--output', default='enhanced_open_redirect_report.html', help='Output report filename')
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose logging')
    parser.add_argument('--web3-mode', action='store_true', help='Enable enhanced Web3 detection')
    
    args = parser.parse_args()
    
    # Setup logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Validate and normalize URL
    if not args.target.startswith(('http://', 'https://')):
        args.target = f"https://{args.target}"
    
    # Create enhanced scanner and run
    scanner = EnhancedOpenRedirectScanner(args.target, args.depth, args.max_pages)
    await scanner.run_enhanced_scan()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n🛑 Scan interrupted by user")
    except Exception as e:
        print(f"❌ Scan failed: {e}")
        logging.error(f"Fatal error: {e}", exc_info=True)