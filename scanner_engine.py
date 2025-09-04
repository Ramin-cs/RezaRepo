#!/usr/bin/env python3
"""
🔥 SCANNER ENGINE - Complete Scanning Engine
موتور کاملاً عملی اسکن - تضمینی کار می‌کنه
"""

import asyncio
import aiohttp
import time
import re
import hashlib
import random
import os
from datetime import datetime
from urllib.parse import urlparse, parse_qs, urljoin, quote, unquote
from typing import List, Dict, Set, Optional, Tuple
from dataclasses import dataclass

try:
    from bs4 import BeautifulSoup
    BS4_OK = True
except ImportError:
    BS4_OK = False

try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    SELENIUM_OK = True
except ImportError:
    SELENIUM_OK = False

# Import payloads
from complete_payloads import CompletePayloads


@dataclass
class Parameter:
    """Parameter data structure"""
    name: str
    value: str
    source: str
    context: str
    url: str
    method: str = 'GET'
    is_redirect_related: bool = False
    confidence: float = 0.0
    input_type: str = ""


@dataclass
class Vulnerability:
    """Vulnerability data structure"""
    url: str
    parameter: str
    payload: str
    method: str
    response_code: int
    redirect_url: str
    context: str
    timestamp: str
    vulnerability_type: str = "open_redirect"
    confidence: float = 0.0
    impact: str = "HIGH"
    screenshot_path: str = ""
    source: str = ""


class ScannerEngine:
    """🔥 Complete Scanner Engine - Guaranteed to work 🔥"""
    
    def __init__(self, target_url: str):
        self.target_url = target_url.rstrip('/')
        self.base_domain = urlparse(target_url).netloc
        self.session = None
        self.driver = None
        
        # Initialize payload module
        self.payloads_module = CompletePayloads()
        
        # Storage
        self.discovered_urls = set()
        self.parameters = []
        self.vulnerabilities = []
        
        # Redirect detection keywords
        self.redirect_keywords = [
            'redirect', 'url', 'next', 'return', 'goto', 'target', 'destination',
            'continue', 'forward', 'redir', 'location', 'site', 'link', 'href',
            'callback', 'success_url', 'failure_url', 'cancel_url', 'exit_url',
            'logout_url', 'login_redirect', 'returnurl', 'redirecturl', 'redirecturi',
            'back', 'backurl', 'from', 'origin', 'source', 'referrer', 'referer'
        ]
        
        # Statistics
        self.stats = {
            'start_time': 0,
            'urls_crawled': 0,
            'parameters_found': 0,
            'payloads_tested': 0,
            'vulnerabilities_found': 0,
            'screenshots_taken': 0,
            'requests_sent': 0
        }
    
    async def initialize(self):
        """Initialize all systems"""
        print("[ENGINE] Initializing complete scanning engine...")
        
        # Initialize HTTP session
        await self.init_session()
        
        # Initialize browser for screenshots
        self.init_browser()
        
        print("[ENGINE] ✅ All systems initialized")
    
    async def init_session(self):
        """Initialize HTTP session with stealth"""
        # Anti-detection headers
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate',
            'Cache-Control': 'no-cache',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        }
        
        # WAF bypass headers
        bypass_headers = random.choice([
            {'X-Originating-IP': '127.0.0.1', 'X-Forwarded-For': '127.0.0.1'},
            {'X-Real-IP': '127.0.0.1', 'X-Remote-Addr': '127.0.0.1'},
            {'X-Client-IP': '127.0.0.1', 'CF-Connecting-IP': '127.0.0.1'}
        ])
        headers.update(bypass_headers)
        
        timeout = aiohttp.ClientTimeout(total=30)
        connector = aiohttp.TCPConnector(limit=50, ssl=False)
        
        self.session = aiohttp.ClientSession(
            timeout=timeout,
            connector=connector, 
            headers=headers
        )
        
        print("[SESSION] ✅ Stealth session initialized")
    
    def init_browser(self):
        """Initialize browser for screenshots"""
        if not SELENIUM_OK:
            print("[BROWSER] ⚠️ Selenium not available - screenshots disabled")
            return
        
        try:
            chrome_options = Options()
            chrome_options.add_argument('--headless')
            chrome_options.add_argument('--no-sandbox')
            chrome_options.add_argument('--disable-dev-shm-usage')
            chrome_options.add_argument('--window-size=1920,1080')
            chrome_options.add_argument('--disable-blink-features=AutomationControlled')
            
            self.driver = webdriver.Chrome(options=chrome_options)
            print("[BROWSER] ✅ Screenshot engine ready")
        except Exception as e:
            print(f"[BROWSER] ⚠️ Browser failed: {e}")
            self.driver = None
    
    async def crawl_and_extract(self, max_urls: int = 5):
        """Crawl target and extract parameters"""
        print(f"[CRAWL] Starting reconnaissance on {self.target_url}")
        
        # Add initial URL
        self.discovered_urls.add(self.target_url)
        
        # Crawl URLs
        urls_to_crawl = list(self.discovered_urls)[:max_urls]
        
        for url in urls_to_crawl:
            await self.analyze_url(url)
            await asyncio.sleep(0.2)  # Rate limiting
        
        print(f"[CRAWL] Analyzed {self.stats['urls_crawled']} URLs")
        print(f"[CRAWL] Found {self.stats['parameters_found']} parameters")
        
        # Filter redirect parameters
        redirect_params = [p for p in self.parameters if p.is_redirect_related]
        print(f"[CRAWL] Identified {len(redirect_params)} redirect parameters")
        
        return redirect_params
    
    async def analyze_url(self, url: str):
        """Analyze single URL"""
        try:
            self.stats['requests_sent'] += 1
            async with self.session.get(url) as response:
                if response.status == 200:
                    content = await response.text()
                    headers = dict(response.headers)
                    
                    # Extract URLs
                    new_urls = self.extract_urls(content, url)
                    self.discovered_urls.update(new_urls)
                    
                    # Extract parameters
                    params = self.extract_all_parameters(url, content, headers)
                    self.parameters.extend(params)
                    
                    self.stats['urls_crawled'] += 1
                    self.stats['parameters_found'] += len(params)
                    
                    print(f"[ANALYZE] {url}: {len(params)} parameters")
        except Exception as e:
            print(f"[ERROR] Failed to analyze {url}: {e}")
    
    def extract_urls(self, content: str, base_url: str) -> Set[str]:
        """Extract URLs from content"""
        urls = set()
        
        if BS4_OK:
            soup = BeautifulSoup(content, 'html.parser')
            for tag in soup.find_all(['a', 'form'], href=True):
                href = tag.get('href') or tag.get('action')
                if href and not href.startswith(('javascript:', 'mailto:', '#')):
                    full_url = urljoin(base_url, href)
                    if self.is_same_domain(full_url):
                        urls.add(full_url)
        else:
            # Regex fallback
            patterns = [r'href=["\']([^"\']+)["\']', r'action=["\']([^"\']+)["\']']
            for pattern in patterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                for match in matches:
                    if not match.startswith(('javascript:', 'mailto:', '#')):
                        full_url = urljoin(base_url, match)
                        if self.is_same_domain(full_url):
                            urls.add(full_url)
        
        return urls
    
    def extract_all_parameters(self, url: str, content: str, headers: Dict[str, str]) -> List[Parameter]:
        """Extract parameters from all sources"""
        parameters = []
        
        # 1. URL parameters
        parsed = urlparse(url)
        if parsed.query:
            query_params = parse_qs(parsed.query, keep_blank_values=True)
            for name, values in query_params.items():
                for value in values:
                    parameters.append(Parameter(
                        name=name,
                        value=value,
                        source='url_query',
                        context='query',
                        url=url,
                        method='GET',
                        is_redirect_related=self.is_redirect_parameter(name, value),
                        confidence=self.calculate_confidence(name, value, 'query')
                    ))
        
        # 2. Fragment parameters
        if parsed.fragment and '=' in parsed.fragment:
            fragment = unquote(parsed.fragment)
            try:
                fragment_params = parse_qs(fragment, keep_blank_values=True)
                for name, values in fragment_params.items():
                    for value in values:
                        parameters.append(Parameter(
                            name=name,
                            value=value,
                            source='url_fragment',
                            context='fragment',
                            url=url,
                            method='GET',
                            is_redirect_related=self.is_redirect_parameter(name, value),
                            confidence=self.calculate_confidence(name, value, 'fragment') + 0.1
                        ))
            except:
                pass
        
        # 3. Form parameters
        if BS4_OK and content:
            form_params = self.extract_form_parameters(content, url)
            parameters.extend(form_params)
        
        # 4. JavaScript parameters
        if content:
            js_params = self.extract_js_parameters(content, url)
            parameters.extend(js_params)
        
        # 5. Meta tag parameters
        if content:
            meta_params = self.extract_meta_parameters(content, url)
            parameters.extend(meta_params)
        
        # 6. Header parameters
        header_params = self.extract_header_parameters(headers, url)
        parameters.extend(header_params)
        
        return parameters
    
    def extract_form_parameters(self, content: str, url: str) -> List[Parameter]:
        """Extract form parameters"""
        parameters = []
        
        soup = BeautifulSoup(content, 'html.parser')
        for form in soup.find_all('form'):
            method = form.get('method', 'GET').upper()
            action = form.get('action', '')
            form_url = urljoin(url, action) if action else url
            
            for input_tag in form.find_all(['input', 'select', 'textarea']):
                name = input_tag.get('name')
                if name:
                    value = input_tag.get('value', '')
                    input_type = input_tag.get('type', 'text')
                    
                    confidence = self.calculate_confidence(name, value, 'form')
                    if input_type == 'hidden':
                        confidence += 0.2
                    
                    parameters.append(Parameter(
                        name=name,
                        value=value,
                        source='form',
                        context='form_input',
                        url=form_url,
                        method=method,
                        is_redirect_related=self.is_redirect_parameter(name, value),
                        confidence=confidence,
                        input_type=input_type
                    ))
        
        return parameters
    
    def extract_js_parameters(self, content: str, url: str) -> List[Parameter]:
        """Extract JavaScript parameters"""
        parameters = []
        
        # Extract script content
        scripts = []
        if BS4_OK:
            soup = BeautifulSoup(content, 'html.parser')
            for script in soup.find_all('script'):
                if script.string and not script.get('src'):
                    scripts.append(script.string)
        else:
            script_pattern = r'<script[^>]*>(.*?)</script>'
            scripts = re.findall(script_pattern, content, re.DOTALL | re.IGNORECASE)
        
        # JavaScript patterns
        js_patterns = [
            r'(?:var|let|const)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*["\']([^"\']*(?:redirect|url|next|return)[^"\']*)["\']',
            r'["\']?([a-zA-Z_][a-zA-Z0-9_]*(?:url|redirect|next|return)[a-zA-Z0-9_]*)["\']?\s*:\s*["\']([^"\']+)["\']',
            r'URLSearchParams[^)]*\.get\(["\']([^"\']+)["\']',
            r'location\.(?:href|search|hash)\s*=\s*([^;]+)',
            r'window\.location\s*=\s*([^;]+)',
            r'localStorage\.getItem\(["\']([^"\']*(?:redirect|url)[^"\']*)["\']'
        ]
        
        for script_content in scripts:
            lines = script_content.split('\n')
            for line_num, line in enumerate(lines, 1):
                for pattern in js_patterns:
                    matches = re.finditer(pattern, line, re.IGNORECASE)
                    for match in matches:
                        groups = match.groups()
                        if groups:
                            if len(groups) >= 2:
                                name, value = groups[0], groups[1]
                            else:
                                name, value = groups[0], ""
                            
                            name = name.strip('"\'')
                            value = value.strip('"\'')
                            
                            parameters.append(Parameter(
                                name=name,
                                value=value,
                                source='javascript',
                                context='js_variable',
                                url=url,
                                is_redirect_related=self.is_redirect_parameter(name, value),
                                confidence=self.calculate_confidence(name, value, 'javascript')
                            ))
        
        return parameters
    
    def extract_meta_parameters(self, content: str, url: str) -> List[Parameter]:
        """Extract meta tag parameters"""
        parameters = []
        
        meta_patterns = [
            r'<meta[^>]*http-equiv=["\']refresh["\'][^>]*content=["\'][^"\']*url=([^"\';\s]+)',
            r'<meta[^>]*name=["\']([^"\']*redirect[^"\']*)["\'][^>]*content=["\']([^"\']+)["\']'
        ]
        
        for pattern in meta_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                groups = match.groups()
                if len(groups) >= 2:
                    name, value = groups[0], groups[1]
                elif len(groups) == 1:
                    name, value = 'meta_redirect', groups[0]
                else:
                    continue
                
                parameters.append(Parameter(
                    name=name,
                    value=value,
                    source='meta_tag',
                    context='meta_refresh',
                    url=url,
                    is_redirect_related=True,
                    confidence=0.8
                ))
        
        return parameters
    
    def extract_header_parameters(self, headers: Dict[str, str], url: str) -> List[Parameter]:
        """Extract header parameters"""
        parameters = []
        
        redirect_headers = ['Location', 'Refresh', 'Link', 'X-Redirect-To', 'X-Forward-To']
        
        for header_name, header_value in headers.items():
            if (header_name in redirect_headers or 
                'redirect' in header_name.lower() or
                'location' in header_name.lower()):
                
                parameters.append(Parameter(
                    name=header_name.lower(),
                    value=header_value,
                    source='http_header',
                    context='http_header',
                    url=url,
                    is_redirect_related=True,
                    confidence=0.9
                ))
        
        return parameters
    
    def is_same_domain(self, url: str) -> bool:
        """Check if URL belongs to same domain"""
        try:
            parsed = urlparse(url)
            return parsed.netloc.lower() == self.base_domain.lower()
        except:
            return False
    
    def is_redirect_parameter(self, name: str, value: str = "") -> bool:
        """Check if parameter is redirect-related"""
        name_lower = name.lower()
        value_lower = value.lower()
        
        # Check name against keywords
        name_match = any(keyword in name_lower for keyword in self.redirect_keywords)
        
        # Check value for URL patterns
        value_match = bool(
            re.match(r'https?://', value_lower) or
            re.match(r'//', value_lower) or
            re.match(r'[a-z0-9.-]+\.[a-z]{2,}', value_lower)
        )
        
        return name_match or value_match
    
    def calculate_confidence(self, name: str, value: str, context: str) -> float:
        """Calculate confidence score"""
        confidence = 0.0
        
        # Base confidence by context
        context_scores = {
            'query': 0.6, 'fragment': 0.7, 'form': 0.5, 'javascript': 0.6,
            'meta_refresh': 0.8, 'http_header': 0.9
        }
        confidence += context_scores.get(context, 0.4)
        
        # Boost for redirect-related names
        if self.is_redirect_parameter(name):
            confidence += 0.3
        
        # Boost for URL-like values
        if value:
            if value.startswith(('http://', 'https://')):
                confidence += 0.3
            elif value.startswith('//'):
                confidence += 0.25
            elif '.' in value and len(value.split('.')) >= 2:
                confidence += 0.15
        
        return min(confidence, 1.0)
    
    async def test_vulnerabilities(self):
        """Test for vulnerabilities"""
        print("[TEST] Starting vulnerability testing...")
        
        # Get high-priority parameters
        redirect_params = [p for p in self.parameters if p.is_redirect_related]
        high_conf_params = [p for p in self.parameters if p.confidence > 0.6]
        
        # Combine and deduplicate
        test_params = redirect_params + high_conf_params
        unique_params = []
        seen = set()
        for param in test_params:
            key = f"{param.name}:{param.url}"
            if key not in seen:
                unique_params.append(param)
                seen.add(key)
        
        print(f"[TEST] Testing {len(unique_params)} high-priority parameters")
        
        # Test each parameter
        for i, param in enumerate(unique_params, 1):
            print(f"[TEST] Parameter {i}/{len(unique_params)}: {param.name}")
            
            # Get appropriate payloads
            payloads = self.get_payloads_for_parameter(param)
            
            # Test payloads
            for j, payload in enumerate(payloads, 1):
                print(f"\r  Testing {j}/{len(payloads)}: {payload[:30]}...", end='')
                
                vuln = await self.test_single_payload(param, payload)
                if vuln:
                    self.vulnerabilities.append(vuln)
                    self.stats['vulnerabilities_found'] += 1
                    
                    # Take screenshot
                    if self.driver:
                        screenshot_path = await self.take_screenshot(vuln.url)
                        if screenshot_path:
                            vuln.screenshot_path = screenshot_path
                            self.stats['screenshots_taken'] += 1
                    
                    print(f"\n  🚨 [VULNERABILITY] {param.name} -> {payload[:30]}... [{vuln.impact}]")
                
                self.stats['payloads_tested'] += 1
                await asyncio.sleep(0.05)  # Rate limiting
            
            print()  # New line after testing parameter
        
        print(f"[TEST] ✅ Testing completed - Found {len(self.vulnerabilities)} vulnerabilities")
    
    def get_payloads_for_parameter(self, param: Parameter) -> List[str]:
        """Get appropriate payloads for parameter"""
        # Detect context
        context = 'default'
        
        if param.context == 'fragment':
            context = 'fragment'
        elif param.source == 'javascript':
            context = 'javascript'
        elif any(indicator in param.url.lower() for indicator in ['web3', 'defi', 'nft', 'wallet']):
            context = 'web3'
        elif any(indicator in param.url.lower() for indicator in ['oauth', 'auth', 'login']):
            context = 'oauth'
        
        # Get context-specific payloads
        payloads = self.payloads_module.get_context_payloads(context)
        
        return payloads[:20]  # Limit to 20 payloads per parameter
    
    async def test_single_payload(self, param: Parameter, payload: str) -> Optional[Vulnerability]:
        """Test single payload on parameter"""
        try:
            # Construct test URL
            if param.context == 'fragment':
                base_url = param.url.split('#')[0]
                test_url = f"{base_url}#{param.name}={quote(payload)}"
            elif param.method == 'POST':
                test_url = param.url
            else:
                separator = '&' if '?' in param.url else '?'
                test_url = f"{param.url}{separator}{param.name}={quote(payload)}"
            
            # Make request
            self.stats['requests_sent'] += 1
            
            if param.method == 'POST':
                data = {param.name: payload}
                async with self.session.post(param.url, data=data, allow_redirects=False) as response:
                    return await self.analyze_response(param, payload, response, test_url)
            else:
                async with self.session.get(test_url, allow_redirects=False) as response:
                    return await self.analyze_response(param, payload, response, test_url)
        
        except Exception as e:
            return None
    
    async def analyze_response(self, param: Parameter, payload: str, response, test_url: str) -> Optional[Vulnerability]:
        """Analyze response for vulnerability"""
        # Check HTTP redirects
        if response.status in [301, 302, 303, 307, 308]:
            location = response.headers.get('Location', '')
            
            if self.is_successful_redirect(location, payload):
                return Vulnerability(
                    url=test_url,
                    parameter=param.name,
                    payload=payload,
                    method=param.method,
                    response_code=response.status,
                    redirect_url=location,
                    context=param.context,
                    timestamp=datetime.now().isoformat(),
                    vulnerability_type="http_redirect",
                    confidence=param.confidence + 0.2,
                    impact=self.assess_impact(location),
                    source=param.source
                )
        
        # Check DOM-based redirects
        try:
            content = await response.text()
            if self.check_dom_redirect(content, payload, param):
                return Vulnerability(
                    url=test_url,
                    parameter=param.name,
                    payload=payload,
                    method=param.method,
                    response_code=response.status,
                    redirect_url=payload,
                    context=param.context,
                    timestamp=datetime.now().isoformat(),
                    vulnerability_type="dom_based_redirect",
                    confidence=0.8,
                    impact="HIGH",
                    source=param.source
                )
        except:
            pass
        
        return None
    
    def is_successful_redirect(self, location: str, payload: str) -> bool:
        """Check if redirect indicates successful exploitation"""
        if not location:
            return False
        
        location_lower = location.lower()
        decoded = unquote(location).lower()
        
        # Test domains that indicate successful redirect
        test_domains = [
            'google.com', 'evil.com', 'attacker.com', 'malicious.com',
            '216.58.214.206', '3627734734', '127.0.0.1',
            'fake-metamask.io', 'phishing-opensea.io', 'malicious-compound.finance'
        ]
        
        for domain in test_domains:
            if domain in location_lower or domain in decoded:
                return True
        
        # JavaScript execution
        if location_lower.startswith('javascript:'):
            return True
        
        # Data URLs
        if location_lower.startswith('data:'):
            return True
        
        # External domain redirect
        if location.startswith(('http://', 'https://')):
            try:
                redirect_domain = urlparse(location).netloc
                if redirect_domain and redirect_domain != self.base_domain:
                    return True
            except:
                pass
        
        # Protocol-relative URLs
        if location.startswith('//'):
            try:
                redirect_domain = location.split('/')[2]
                if redirect_domain != self.base_domain:
                    return True
            except:
                pass
        
        return False
    
    def check_dom_redirect(self, content: str, payload: str, param: Parameter) -> bool:
        """Check for DOM-based redirects"""
        content_lower = content.lower()
        payload_lower = payload.lower()
        
        # Check if payload appears in dangerous JavaScript contexts
        dangerous_patterns = [
            f'location.href = "{payload}"',
            f"location.href = '{payload}'",
            f'window.location = "{payload}"',
            f"window.location = '{payload}'",
            f'location.assign("{payload}")',
            f"location.assign('{payload}')"
        ]
        
        for pattern in dangerous_patterns:
            if pattern.lower() in content_lower:
                return True
        
        # Check if parameter is reflected in JavaScript redirect context
        if (param.name.lower() in content_lower and 
            payload_lower in content_lower and
            any(sink in content_lower for sink in ['location.href', 'window.location', 'location.assign'])):
            return True
        
        return False
    
    def assess_impact(self, redirect_url: str) -> str:
        """Assess vulnerability impact"""
        if redirect_url.startswith('javascript:'):
            return "CRITICAL"
        elif redirect_url.startswith(('http://', 'https://')):
            return "HIGH"
        elif redirect_url.startswith('//'):
            return "HIGH"
        return "MEDIUM"
    
    async def take_screenshot(self, url: str) -> Optional[str]:
        """Take screenshot for PoC"""
        if not self.driver:
            return None
        
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            url_hash = hashlib.md5(url.encode()).hexdigest()[:8]
            filename = f"vuln_poc_{timestamp}_{url_hash}.png"
            
            # Create directory
            os.makedirs("vulnerability_screenshots", exist_ok=True)
            screenshot_path = f"vulnerability_screenshots/{filename}"
            
            # Take screenshot
            self.driver.get(url)
            await asyncio.sleep(2)  # Wait for page load
            self.driver.save_screenshot(screenshot_path)
            
            print(f"[SCREENSHOT] ✅ Captured: {filename}")
            return screenshot_path
            
        except Exception as e:
            print(f"[SCREENSHOT] ❌ Failed: {e}")
            return None
    
    def detect_web3_context(self, url: str, content: str) -> bool:
        """Detect Web3/DeFi context"""
        web3_indicators = ['web3', 'metamask', 'wallet', 'defi', 'nft', 'ethereum', 'crypto']
        
        url_lower = url.lower()
        content_lower = content.lower()
        
        # Check URL
        url_matches = sum(1 for indicator in web3_indicators if indicator in url_lower)
        
        # Check content
        content_matches = sum(1 for indicator in web3_indicators if indicator in content_lower)
        
        return url_matches >= 1 or content_matches >= 2
    
    def get_statistics(self) -> Dict:
        """Get scan statistics"""
        redirect_params = [p for p in self.parameters if p.is_redirect_related]
        high_conf_params = [p for p in self.parameters if p.confidence > 0.7]
        
        return {
            'urls_discovered': len(self.discovered_urls),
            'urls_crawled': self.stats['urls_crawled'],
            'total_parameters': len(self.parameters),
            'redirect_parameters': len(redirect_params),
            'high_confidence_parameters': len(high_conf_params),
            'payloads_tested': self.stats['payloads_tested'],
            'vulnerabilities_found': len(self.vulnerabilities),
            'requests_sent': self.stats['requests_sent'],
            'screenshots_taken': self.stats['screenshots_taken']
        }
    
    async def cleanup(self):
        """Cleanup resources"""
        if self.session:
            await self.session.close()
        if self.driver:
            self.driver.quit()
        print("[ENGINE] ✅ Resources cleaned up")


# Test the engine
if __name__ == "__main__":
    async def test_engine():
        engine = ScannerEngine("https://httpbin.org/get?url=test")
        await engine.initialize()
        
        redirect_params = await engine.crawl_and_extract()
        print(f"Found {len(redirect_params)} redirect parameters")
        
        if redirect_params:
            await engine.test_vulnerabilities()
        
        stats = engine.get_statistics()
        print(f"Statistics: {stats}")
        
        await engine.cleanup()
    
    print("🔥 TESTING SCANNER ENGINE 🔥")
    asyncio.run(test_engine())