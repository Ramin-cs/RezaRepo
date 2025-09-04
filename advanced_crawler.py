#!/usr/bin/env python3
"""
🔥 ADVANCED STEALTH CRAWLER - Complete Reconnaissance Engine
"""

import asyncio
import aiohttp
import re
import time
import random
from urllib.parse import urljoin, urlparse, parse_qs, unquote
from typing import Set, List, Dict, Tuple, Optional
from data_models import Parameter

try:
    from bs4 import BeautifulSoup
    BS4_OK = True
except ImportError:
    BS4_OK = False


class AdvancedCrawler:
    """Advanced stealth crawler with complete reconnaissance"""
    
    def __init__(self, base_domain: str, session: aiohttp.ClientSession):
        self.base_domain = base_domain
        self.session = session
        self.crawled_urls = set()
        self.discovered_urls = set()
        self.parameters = []
        self.js_files = set()
        self.form_endpoints = set()
        self.api_endpoints = set()
        self.robots_disallowed = set()
        
        # Stealth settings
        self.request_delay = (0.1, 0.5)
        self.max_retries = 3
        
        # URL patterns for deeper discovery
        self.discovery_patterns = [
            r'href=["\']([^"\']*\?[^"\']*)["\']',  # URLs with parameters
            r'action=["\']([^"\']+)["\']',         # Form actions
            r'src=["\']([^"\']*\.js[^"\']*)["\']', # JS files
            r'url\(["\']?([^"\']*)["\']?\)',       # CSS URLs
            r'fetch\(["\']([^"\']+)["\']',         # Fetch API
            r'ajax\(["\']([^"\']+)["\']',          # AJAX calls
            r'api/[a-zA-Z0-9/_-]+',                # API endpoints
        ]
        
        # Parameter extraction patterns
        self.param_patterns = [
            # Meta tags
            r'<meta[^>]*name=["\']([^"\']*redirect[^"\']*)["\'][^>]*content=["\']([^"\']+)["\']',
            # Data attributes
            r'data-([a-zA-Z-]*(?:redirect|url|next|return)[a-zA-Z-]*)[=\s]*["\']([^"\']+)["\']',
            # Hidden inputs
            r'<input[^>]*type=["\']hidden["\'][^>]*name=["\']([^"\']+)["\'][^>]*value=["\']([^"\']+)["\']',
            # Config objects
            r'(?:config|settings|options)\s*[:\[]\s*["\']?([^"\']*(?:redirect|url|next)[^"\']*)["\']?\s*:\s*["\']([^"\']+)["\']',
        ]
    
    async def crawl_with_stealth(self, start_url: str, max_depth: int = 3, max_pages: int = 100) -> Tuple[Set[str], List[Parameter]]:
        """Advanced stealth crawling"""
        print(f"[STEALTH-CRAWLER] Initiating deep reconnaissance on {self.base_domain}")
        
        # Phase 1: robots.txt analysis
        await self.analyze_robots_txt(start_url)
        
        # Phase 2: sitemap discovery
        await self.discover_sitemaps(start_url)
        
        # Phase 3: deep crawling
        urls_to_crawl = {start_url}
        depth = 0
        
        while urls_to_crawl and depth < max_depth and len(self.crawled_urls) < max_pages:
            current_batch = list(urls_to_crawl)[:20]  # Process in batches
            urls_to_crawl.clear()
            
            print(f"[CRAWLER] Depth {depth + 1}: Processing {len(current_batch)} URLs...")
            
            # Process batch with stealth timing
            for url in current_batch:
                if url not in self.crawled_urls:
                    new_urls, params = await self.crawl_single_page(url)
                    
                    self.discovered_urls.update(new_urls)
                    self.parameters.extend(params)
                    self.crawled_urls.add(url)
                    
                    # Add new URLs for next depth
                    for new_url in new_urls:
                        if (self.is_same_domain(new_url) and 
                            new_url not in self.crawled_urls and
                            len(urls_to_crawl) < 50):  # Limit queue size
                            urls_to_crawl.add(new_url)
                    
                    # Stealth delay
                    await asyncio.sleep(random.uniform(*self.request_delay))
            
            depth += 1
            print(f"[CRAWLER] Completed depth {depth}: {len(self.crawled_urls)} URLs, {len(self.parameters)} parameters")
        
        return self.discovered_urls, self.parameters
    
    async def analyze_robots_txt(self, base_url: str):
        """Analyze robots.txt for hidden paths"""
        try:
            robots_url = urljoin(base_url, '/robots.txt')
            async with self.session.get(robots_url) as response:
                if response.status == 200:
                    content = await response.text()
                    
                    # Extract disallowed paths
                    disallow_pattern = r'Disallow:\s*([^\s]+)'
                    matches = re.findall(disallow_pattern, content, re.IGNORECASE)
                    
                    for path in matches:
                        if path != '/' and '?' in path:  # Paths with parameters
                            full_url = urljoin(base_url, path)
                            self.robots_disallowed.add(full_url)
                    
                    print(f"[ROBOTS] Found {len(self.robots_disallowed)} disallowed paths with parameters")
        except:
            pass
    
    async def discover_sitemaps(self, base_url: str):
        """Discover and parse sitemaps"""
        sitemap_urls = [
            '/sitemap.xml', '/sitemap_index.xml', '/sitemaps.xml',
            '/sitemap1.xml', '/robots.txt'
        ]
        
        for sitemap_path in sitemap_urls:
            try:
                sitemap_url = urljoin(base_url, sitemap_path)
                async with self.session.get(sitemap_url) as response:
                    if response.status == 200:
                        content = await response.text()
                        
                        # Extract URLs from sitemap
                        url_pattern = r'<loc>([^<]+)</loc>'
                        urls = re.findall(url_pattern, content)
                        
                        for url in urls:
                            if self.is_same_domain(url) and '?' in url:
                                self.discovered_urls.add(url)
                        
                        print(f"[SITEMAP] Discovered {len(urls)} URLs from {sitemap_path}")
            except:
                continue
    
    async def crawl_single_page(self, url: str) -> Tuple[Set[str], List[Parameter]]:
        """Crawl single page with complete analysis"""
        new_urls = set()
        parameters = []
        
        try:
            async with self.session.get(url, allow_redirects=True) as response:
                if response.status != 200:
                    return new_urls, parameters
                
                content = await response.text()
                headers = dict(response.headers)
                
                print(f"[PAGE-SCAN] {url[:80]}...")
                
                # Extract all URLs
                new_urls = self.extract_all_urls(content, url)
                
                # Extract all parameters
                parameters.extend(self.extract_url_parameters(url))
                parameters.extend(self.extract_form_parameters(content, url))
                parameters.extend(self.extract_meta_parameters(content, url))
                parameters.extend(self.extract_data_attributes(content, url))
                parameters.extend(self.extract_config_parameters(content, url))
                parameters.extend(self.extract_header_parameters(headers, url))
                
                # Track special files
                if url.endswith('.js'):
                    self.js_files.add(url)
                elif 'api/' in url or url.endswith('/api'):
                    self.api_endpoints.add(url)
                
        except Exception as e:
            print(f"[CRAWLER-ERROR] {url}: {e}")
        
        return new_urls, parameters
    
    def extract_all_urls(self, content: str, base_url: str) -> Set[str]:
        """Extract all URLs with advanced patterns"""
        urls = set()
        
        if BS4_OK:
            soup = BeautifulSoup(content, 'html.parser')
            
            # Standard links
            for tag in soup.find_all(['a', 'link', 'form'], href=True):
                href = tag.get('href') or tag.get('action')
                if href:
                    full_url = urljoin(base_url, href)
                    if self.is_same_domain(full_url):
                        urls.add(full_url)
            
            # Script sources
            for script in soup.find_all('script', src=True):
                src = script['src']
                full_url = urljoin(base_url, src)
                if self.is_same_domain(full_url):
                    urls.add(full_url)
                    self.js_files.add(full_url)
        
        # Regex patterns for additional discovery
        for pattern in self.discovery_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple):
                    match = match[0]
                
                full_url = urljoin(base_url, match)
                if self.is_same_domain(full_url):
                    urls.add(full_url)
        
        return urls
    
    def extract_url_parameters(self, url: str) -> List[Parameter]:
        """Extract URL parameters with confidence scoring"""
        params = []
        parsed = urlparse(url)
        
        # Query parameters
        if parsed.query:
            query_params = parse_qs(parsed.query, keep_blank_values=True)
            for param_name, param_values in query_params.items():
                for value in param_values:
                    confidence = self.calculate_param_confidence(param_name, value, 'query')
                    is_redirect = self.is_redirect_parameter(param_name, value)
                    
                    params.append(Parameter(
                        name=param_name,
                        value=value,
                        source='url_query',
                        context='query',
                        url=url,
                        method='GET',
                        is_redirect_related=is_redirect,
                        confidence=confidence,
                        pattern_matched=f"query:{param_name}"
                    ))
        
        # Fragment parameters
        if parsed.fragment:
            fragment = unquote(parsed.fragment)
            if '=' in fragment:
                # Parse fragment as query string
                try:
                    fragment_params = parse_qs(fragment, keep_blank_values=True)
                    for param_name, param_values in fragment_params.items():
                        for value in param_values:
                            confidence = self.calculate_param_confidence(param_name, value, 'fragment')
                            is_redirect = self.is_redirect_parameter(param_name, value)
                            
                            params.append(Parameter(
                                name=param_name,
                                value=value,
                                source='url_fragment',
                                context='fragment',
                                url=url,
                                method='GET',
                                is_redirect_related=is_redirect,
                                confidence=confidence + 0.1,  # Fragments often used for client-side routing
                                pattern_matched=f"fragment:{param_name}"
                            ))
                except:
                    pass
        
        return params
    
    def extract_form_parameters(self, content: str, url: str) -> List[Parameter]:
        """Extract form parameters with method detection"""
        params = []
        
        if BS4_OK:
            soup = BeautifulSoup(content, 'html.parser')
            
            for form in soup.find_all('form'):
                method = form.get('method', 'GET').upper()
                action = form.get('action', '')
                form_url = urljoin(url, action) if action else url
                
                # Track form endpoints
                self.form_endpoints.add(form_url)
                
                for input_tag in form.find_all(['input', 'select', 'textarea']):
                    name = input_tag.get('name')
                    value = input_tag.get('value', '')
                    input_type = input_tag.get('type', 'text').lower()
                    
                    if name:
                        confidence = self.calculate_param_confidence(name, value, 'form')
                        is_redirect = self.is_redirect_parameter(name, value)
                        
                        # Boost confidence for hidden inputs
                        if input_type == 'hidden':
                            confidence += 0.2
                        
                        params.append(Parameter(
                            name=name,
                            value=value,
                            source='form',
                            context='form_input',
                            url=form_url,
                            method=method,
                            is_redirect_related=is_redirect,
                            confidence=confidence,
                            pattern_matched=f"form:{input_type}:{name}"
                        ))
        
        return params
    
    def extract_meta_parameters(self, content: str, url: str) -> List[Parameter]:
        """Extract meta tag parameters"""
        params = []
        
        for pattern in self.param_patterns:
            if 'meta' in pattern:
                matches = re.findall(pattern, content, re.IGNORECASE)
                for match in matches:
                    if len(match) >= 2:
                        param_name, param_value = match[0], match[1]
                        confidence = self.calculate_param_confidence(param_name, param_value, 'meta')
                        is_redirect = self.is_redirect_parameter(param_name, param_value)
                        
                        params.append(Parameter(
                            name=param_name,
                            value=param_value,
                            source='meta_tag',
                            context='meta_refresh',
                            url=url,
                            method='GET',
                            is_redirect_related=is_redirect,
                            confidence=confidence,
                            pattern_matched=f"meta:{param_name}"
                        ))
        
        return params
    
    def extract_data_attributes(self, content: str, url: str) -> List[Parameter]:
        """Extract data-* attributes"""
        params = []
        
        data_pattern = r'data-([a-zA-Z-]*(?:redirect|url|next|return|goto|link)[a-zA-Z-]*)[=\s]*["\']([^"\']+)["\']'
        matches = re.findall(data_pattern, content, re.IGNORECASE)
        
        for param_name, param_value in matches:
            confidence = self.calculate_param_confidence(param_name, param_value, 'data_attribute')
            is_redirect = True  # Data attributes with redirect keywords are highly suspicious
            
            params.append(Parameter(
                name=f"data-{param_name}",
                value=param_value,
                source='data_attribute',
                context='html_data',
                url=url,
                method='GET',
                is_redirect_related=is_redirect,
                confidence=confidence + 0.3,  # High confidence for data attributes
                pattern_matched=f"data:{param_name}"
            ))
        
        return params
    
    def extract_config_parameters(self, content: str, url: str) -> List[Parameter]:
        """Extract configuration parameters"""
        params = []
        
        config_patterns = [
            r'(?:window\.|global\.|app\.)config\s*[=\[]\s*\{([^}]+)\}',
            r'(?:const|var|let)\s+config\s*=\s*\{([^}]+)\}',
            r'settings\s*:\s*\{([^}]+)\}',
            r'redirectConfig\s*:\s*\{([^}]+)\}',
        ]
        
        for pattern in config_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE | re.DOTALL)
            for config_block in matches:
                # Extract key-value pairs from config block
                kv_pattern = r'["\']?([a-zA-Z_][a-zA-Z0-9_]*)["\']?\s*:\s*["\']([^"\']+)["\']'
                kv_matches = re.findall(kv_pattern, config_block)
                
                for param_name, param_value in kv_matches:
                    confidence = self.calculate_param_confidence(param_name, param_value, 'config')
                    is_redirect = self.is_redirect_parameter(param_name, param_value)
                    
                    params.append(Parameter(
                        name=param_name,
                        value=param_value,
                        source='config',
                        context='js_config',
                        url=url,
                        method='GET',
                        is_redirect_related=is_redirect,
                        confidence=confidence,
                        pattern_matched=f"config:{param_name}"
                    ))
        
        return params
    
    def extract_header_parameters(self, headers: Dict[str, str], url: str) -> List[Parameter]:
        """Extract header-based parameters"""
        params = []
        
        redirect_headers = [
            'Location', 'Refresh', 'Link', 'X-Redirect-To', 'X-Forward-To',
            'X-Accel-Redirect', 'X-Sendfile', 'X-Lighttpd-Send-File'
        ]
        
        for header_name, header_value in headers.items():
            # Direct redirect headers
            if header_name in redirect_headers:
                params.append(Parameter(
                    name=header_name.lower(),
                    value=header_value,
                    source='http_header',
                    context='http_header',
                    url=url,
                    method='GET',
                    is_redirect_related=True,
                    confidence=0.95,
                    pattern_matched=f"header:{header_name}"
                ))
            
            # Headers containing redirect keywords
            elif any(keyword in header_name.lower() for keyword in ['redirect', 'location', 'forward']):
                params.append(Parameter(
                    name=header_name.lower(),
                    value=header_value,
                    source='http_header',
                    context='http_header',
                    url=url,
                    method='GET',
                    is_redirect_related=True,
                    confidence=0.8,
                    pattern_matched=f"header:{header_name}"
                ))
        
        return params
    
    def is_same_domain(self, url: str) -> bool:
        """Check if URL belongs to same domain"""
        try:
            parsed = urlparse(url)
            if not parsed.netloc:
                return True  # Relative URL
            
            target_domain = parsed.netloc.lower()
            base_domain = self.base_domain.lower()
            
            return (target_domain == base_domain or 
                   target_domain.endswith(f'.{base_domain}'))
        except:
            return False
    
    def is_redirect_parameter(self, param_name: str, param_value: str = "") -> bool:
        """Enhanced redirect parameter detection"""
        redirect_keywords = [
            'redirect', 'url', 'next', 'return', 'goto', 'target', 'destination',
            'continue', 'forward', 'redir', 'location', 'site', 'link', 'href',
            'returnurl', 'back', 'callback', 'success_url', 'failure_url',
            'cancel_url', 'exit_url', 'logout_url', 'login_redirect'
        ]
        
        param_lower = param_name.lower()
        value_lower = param_value.lower()
        
        # Name-based detection
        name_match = any(keyword in param_lower for keyword in redirect_keywords)
        
        # Value-based detection
        value_match = bool(
            re.match(r'https?://', value_lower) or
            re.match(r'//', value_lower) or
            re.match(r'[a-z0-9.-]+\.[a-z]{2,}', value_lower)  # Domain pattern
        )
        
        return name_match or value_match
    
    def calculate_param_confidence(self, param_name: str, param_value: str, context: str) -> float:
        """Calculate parameter confidence score"""
        confidence = 0.0
        
        # Base confidence by context
        context_scores = {
            'query': 0.6,
            'fragment': 0.7,
            'form': 0.5,
            'meta': 0.8,
            'data_attribute': 0.7,
            'config': 0.6,
            'header': 0.9
        }
        confidence += context_scores.get(context, 0.3)
        
        # Boost for redirect-related names
        if self.is_redirect_parameter(param_name):
            confidence += 0.3
        
        # Boost for URL-like values
        if param_value:
            if param_value.startswith(('http://', 'https://')):
                confidence += 0.3
            elif param_value.startswith('//'):
                confidence += 0.25
            elif '.' in param_value and len(param_value.split('.')) >= 2:
                confidence += 0.2
        
        # Boost for suspicious patterns
        suspicious_patterns = ['callback', 'success', 'failure', 'cancel', 'exit']
        if any(pattern in param_name.lower() for pattern in suspicious_patterns):
            confidence += 0.15
        
        return min(confidence, 1.0)
    
    async def deep_parameter_discovery(self, content: str, url: str) -> List[Parameter]:
        """Deep parameter discovery using multiple techniques"""
        params = []
        
        # Advanced regex patterns
        advanced_patterns = [
            # JavaScript variable assignments
            r'(?:var|let|const)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*["\']([^"\']*(?:redirect|url)[^"\']*)["\']',
            # Function parameters
            r'function\s+\w*\([^)]*([a-zA-Z_$][a-zA-Z0-9_$]*(?:Url|Redirect|Next)[a-zA-Z0-9_$]*)[^)]*\)',
            # Object properties
            r'["\']?([a-zA-Z_][a-zA-Z0-9_]*(?:Url|Redirect|Next)[a-zA-Z0-9_]*)["\']?\s*:\s*["\']([^"\']+)["\']',
            # localStorage/sessionStorage
            r'(?:localStorage|sessionStorage)\.(?:getItem|setItem)\(["\']([^"\']*(?:redirect|url)[^"\']*)["\']',
            # Cookie parameters
            r'document\.cookie\s*=\s*["\']([^"\']*(?:redirect|url)[^"\']*)["\']',
        ]
        
        for pattern in advanced_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple) and len(match) >= 2:
                    param_name, param_value = match[0], match[1]
                elif isinstance(match, tuple):
                    param_name, param_value = match[0], ""
                else:
                    param_name, param_value = match, ""
                
                confidence = self.calculate_param_confidence(param_name, param_value, 'advanced_js')
                is_redirect = self.is_redirect_parameter(param_name, param_value)
                
                params.append(Parameter(
                    name=param_name,
                    value=param_value,
                    source='advanced_analysis',
                    context='js_advanced',
                    url=url,
                    method='GET',
                    is_redirect_related=is_redirect,
                    confidence=confidence,
                    pattern_matched=f"advanced:{pattern[:20]}..."
                ))
        
        return params
    
    def get_crawl_statistics(self) -> Dict:
        """Get crawling statistics"""
        redirect_params = [p for p in self.parameters if p.is_redirect_related]
        high_conf_params = [p for p in self.parameters if p.confidence > 0.7]
        
        return {
            'total_urls': len(self.discovered_urls),
            'crawled_urls': len(self.crawled_urls),
            'total_parameters': len(self.parameters),
            'redirect_parameters': len(redirect_params),
            'high_confidence_parameters': len(high_conf_params),
            'js_files': len(self.js_files),
            'form_endpoints': len(self.form_endpoints),
            'api_endpoints': len(self.api_endpoints),
            'robots_disallowed': len(self.robots_disallowed)
        }