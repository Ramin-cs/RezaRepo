#!/usr/bin/env python3
"""
Advanced Reconnaissance Module for Open Redirect Scanner
Comprehensive parameter extraction from various sources
"""

import asyncio
import aiohttp
import re
import json
import urllib.parse
from typing import List, Dict, Set, Optional, Tuple, Any
from urllib.parse import urljoin, urlparse, parse_qs, unquote
import logging
import time
import random
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    from bs4 import BeautifulSoup
    BEAUTIFULSOUP_AVAILABLE = True
except ImportError:
    BEAUTIFULSOUP_AVAILABLE = False

class AdvancedReconModule:
    """
    Advanced reconnaissance module for comprehensive parameter extraction
    """
    
    def __init__(self, logger, max_depth: int = 3, max_threads: int = 10):
        self.logger = logger
        self.max_depth = max_depth
        self.max_threads = max_threads
        self.visited_urls = set()
        self.injection_points = []
        self.session = None
        
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
            'endpoint', 'uri', 'pathname', 'location', 'window.location', 'document.location',
            'self.location', 'top.location', 'parent.location', 'opener.location',
            'window.open', 'document.URL', 'document.documentURI', 'location.href',
            'location.pathname', 'location.search', 'location.hash', 'location.assign',
            'location.replace', 'location.reload', 'history.back', 'history.forward',
            'history.go', 'history.pushState', 'history.replaceState', 'popstate',
            'beforeunload', 'unload', 'load', 'DOMContentLoaded', 'readystatechange',
            'onload', 'onbeforeunload', 'onunload', 'onerror', 'onabort', 'onfocus',
            'onblur', 'onchange', 'onclick', 'ondblclick', 'onmousedown', 'onmouseup',
            'onmouseover', 'onmouseout', 'onmousemove', 'onkeydown', 'onkeyup',
            'onkeypress', 'onsubmit', 'onreset', 'onselect', 'onresize', 'onscroll',
            'oncontextmenu', 'ondrag', 'ondragend', 'ondragenter', 'ondragleave',
            'ondragover', 'ondragstart', 'ondrop', 'oninput', 'oninvalid', 'onreset',
            'onsearch', 'onselect', 'ontoggle', 'onwheel', 'onauxclick', 'oncanplay',
            'oncanplaythrough', 'onchange', 'onclick', 'onclose', 'oncontextmenu',
            'oncuechange', 'ondblclick', 'ondrag', 'ondragend', 'ondragenter',
            'ondragleave', 'ondragover', 'ondragstart', 'ondrop', 'ondurationchange',
            'onemptied', 'onended', 'onerror', 'onfocus', 'onformdata', 'oninput',
            'oninvalid', 'onkeydown', 'onkeypress', 'onkeyup', 'onload', 'onloadeddata',
            'onloadedmetadata', 'onloadstart', 'onmousedown', 'onmouseenter',
            'onmouseleave', 'onmousemove', 'onmouseout', 'onmouseover', 'onmouseup',
            'onmousewheel', 'onoffline', 'ononline', 'onpagehide', 'onpageshow',
            'onpaste', 'onpause', 'onplay', 'onplaying', 'onpopstate', 'onprogress',
            'onratechange', 'onresize', 'onscroll', 'onsearch', 'onseeked', 'onseeking',
            'onselect', 'onstalled', 'onstorage', 'onsubmit', 'onsuspend', 'ontimeupdate',
            'ontoggle', 'onunload', 'onvolumechange', 'onwaiting', 'onwheel'
        }
        
        # JavaScript redirect patterns
        self.js_redirect_patterns = [
            r'window\.location\s*=\s*["\']([^"\']+)["\']',
            r'window\.location\.href\s*=\s*["\']([^"\']+)["\']',
            r'window\.location\.assign\s*\(\s*["\']([^"\']+)["\']',
            r'window\.location\.replace\s*\(\s*["\']([^"\']+)["\']',
            r'document\.location\s*=\s*["\']([^"\']+)["\']',
            r'document\.location\.href\s*=\s*["\']([^"\']+)["\']',
            r'location\s*=\s*["\']([^"\']+)["\']',
            r'location\.href\s*=\s*["\']([^"\']+)["\']',
            r'location\.assign\s*\(\s*["\']([^"\']+)["\']',
            r'location\.replace\s*\(\s*["\']([^"\']+)["\']',
            r'top\.location\s*=\s*["\']([^"\']+)["\']',
            r'top\.location\.href\s*=\s*["\']([^"\']+)["\']',
            r'parent\.location\s*=\s*["\']([^"\']+)["\']',
            r'parent\.location\.href\s*=\s*["\']([^"\']+)["\']',
            r'self\.location\s*=\s*["\']([^"\']+)["\']',
            r'self\.location\.href\s*=\s*["\']([^"\']+)["\']',
            r'window\.open\s*\(\s*["\']([^"\']+)["\']',
            r'history\.pushState\s*\(\s*[^,]+,\s*[^,]+,\s*["\']([^"\']+)["\']',
            r'history\.replaceState\s*\(\s*[^,]+,\s*[^,]+,\s*["\']([^"\']+)["\']',
            r'history\.go\s*\(\s*["\']([^"\']+)["\']',
            r'history\.back\s*\(\s*["\']([^"\']+)["\']',
            r'history\.forward\s*\(\s*["\']([^"\']+)["\']',
            r'location\.reload\s*\(\s*["\']([^"\']+)["\']',
            r'location\.pathname\s*=\s*["\']([^"\']+)["\']',
            r'location\.search\s*=\s*["\']([^"\']+)["\']',
            r'location\.hash\s*=\s*["\']([^"\']+)["\']',
            r'document\.URL\s*=\s*["\']([^"\']+)["\']',
            r'document\.documentURI\s*=\s*["\']([^"\']+)["\']',
            r'window\.location\.pathname\s*=\s*["\']([^"\']+)["\']',
            r'window\.location\.search\s*=\s*["\']([^"\']+)["\']',
            r'window\.location\.hash\s*=\s*["\']([^"\']+)["\']',
            r'document\.location\.pathname\s*=\s*["\']([^"\']+)["\']',
            r'document\.location\.search\s*=\s*["\']([^"\']+)["\']',
            r'document\.location\.hash\s*=\s*["\']([^"\']+)["\']',
            r'top\.location\.pathname\s*=\s*["\']([^"\']+)["\']',
            r'top\.location\.search\s*=\s*["\']([^"\']+)["\']',
            r'top\.location\.hash\s*=\s*["\']([^"\']+)["\']',
            r'parent\.location\.pathname\s*=\s*["\']([^"\']+)["\']',
            r'parent\.location\.search\s*=\s*["\']([^"\']+)["\']',
            r'parent\.location\.hash\s*=\s*["\']([^"\']+)["\']',
            r'self\.location\.pathname\s*=\s*["\']([^"\']+)["\']',
            r'self\.location\.search\s*=\s*["\']([^"\']+)["\']',
            r'self\.location\.hash\s*=\s*["\']([^"\']+)["\']'
        ]
        
        # Meta refresh patterns
        self.meta_refresh_patterns = [
            r'<meta[^>]*http-equiv\s*=\s*["\']refresh["\'][^>]*content\s*=\s*["\']([^"\']+)["\']',
            r'<meta[^>]*content\s*=\s*["\']([^"\']+)["\'][^>]*http-equiv\s*=\s*["\']refresh["\']',
            r'<meta[^>]*http-equiv\s*=\s*["\']refresh["\'][^>]*content\s*=\s*["\']([^"\']+)["\']',
            r'<meta[^>]*content\s*=\s*["\']([^"\']+)["\'][^>]*http-equiv\s*=\s*["\']refresh["\']'
        ]
        
        # HTTP header redirect patterns
        self.header_redirect_patterns = [
            'Location', 'Refresh', 'X-Redirect-URL', 'X-Forwarded-For',
            'X-Forwarded-Host', 'X-Forwarded-Proto', 'X-Original-URL',
            'X-Rewrite-URL', 'X-Forwarded-Server', 'X-Forwarded-Ssl',
            'X-Forwarded-Port', 'X-Forwarded-Prefix', 'X-Real-IP',
            'X-Client-IP', 'X-Cluster-Client-IP', 'X-Forwarded',
            'X-Forwarded-By', 'X-Forwarded-For-Original', 'X-Forwarded-For-Original-IP',
            'X-Forwarded-For-Original-Port', 'X-Forwarded-For-Original-Proto',
            'X-Forwarded-For-Original-Server', 'X-Forwarded-For-Original-Ssl',
            'X-Forwarded-For-Original-Port', 'X-Forwarded-For-Original-Prefix',
            'X-Forwarded-For-Original-Real-IP', 'X-Forwarded-For-Original-Client-IP',
            'X-Forwarded-For-Original-Cluster-Client-IP', 'X-Forwarded-For-Original-Forwarded',
            'X-Forwarded-For-Original-Forwarded-By', 'X-Forwarded-For-Original-Forwarded-For-Original',
            'X-Forwarded-For-Original-Forwarded-For-Original-IP', 'X-Forwarded-For-Original-Forwarded-For-Original-Port',
            'X-Forwarded-For-Original-Forwarded-For-Original-Proto', 'X-Forwarded-For-Original-Forwarded-For-Original-Server',
            'X-Forwarded-For-Original-Forwarded-For-Original-Ssl', 'X-Forwarded-For-Original-Forwarded-For-Original-Port',
            'X-Forwarded-For-Original-Forwarded-For-Original-Prefix', 'X-Forwarded-For-Original-Forwarded-For-Original-Real-IP',
            'X-Forwarded-For-Original-Forwarded-For-Original-Client-IP', 'X-Forwarded-For-Original-Forwarded-For-Original-Cluster-Client-IP',
            'X-Forwarded-For-Original-Forwarded-For-Original-Forwarded', 'X-Forwarded-For-Original-Forwarded-For-Original-Forwarded-By'
        ]
        
        # Additional parameter patterns
        self.parameter_patterns = [
            r'(\w+)\s*=\s*["\']([^"\']+)["\']',
            r'(\w+)\s*:\s*["\']([^"\']+)["\']',
            r'(\w+)\s*=\s*([^&\s]+)',
            r'(\w+)\s*:\s*([^&\s]+)',
            r'(\w+)\s*=\s*\{([^}]+)\}',
            r'(\w+)\s*:\s*\{([^}]+)\}',
            r'(\w+)\s*=\s*\[([^\]]+)\]',
            r'(\w+)\s*:\s*\[([^\]]+)\]'
        ]
    
    async def initialize(self, session: aiohttp.ClientSession):
        """Initialize the reconnaissance module"""
        self.session = session
        self.logger.info("🔍 Advanced Reconnaissance Module initialized")
        return True
    
    async def perform_recon(self, target_url: str) -> Dict:
        """
        Perform comprehensive reconnaissance
        """
        try:
            self.logger.info(f"🔍 Starting advanced reconnaissance for: {target_url}")
            
            recon_results = {
                'target_url': target_url,
                'urls': [],
                'forms': [],
                'javascript_vars': [],
                'meta_tags': [],
                'cookies': [],
                'headers': [],
                'injection_points': [],
                'api_endpoints': [],
                'sitemap_urls': [],
                'robots_urls': [],
                'error_pages': []
            }
            
            # Phase 1: Basic URL analysis
            self.logger.info("📊 Phase 1: Basic URL analysis...")
            await self._analyze_target_url(target_url, recon_results)
            
            # Phase 2: Crawl website
            self.logger.info("🕷️ Phase 2: Website crawling...")
            await self._crawl_website(target_url, recon_results)
            
            # Phase 3: API endpoint discovery
            self.logger.info("🔌 Phase 3: API endpoint discovery...")
            await self._discover_api_endpoints(target_url, recon_results)
            
            # Phase 4: Sitemap and robots.txt analysis
            self.logger.info("🗺️ Phase 4: Sitemap and robots.txt analysis...")
            await self._analyze_sitemap_robots(target_url, recon_results)
            
            # Phase 5: Error page analysis
            self.logger.info("❌ Phase 5: Error page analysis...")
            await self._analyze_error_pages(target_url, recon_results)
            
            # Phase 6: Extract injection points
            self.logger.info("🎯 Phase 6: Injection point extraction...")
            recon_results['injection_points'] = self._extract_injection_points(recon_results)
            
            self.logger.info(f"✅ Reconnaissance completed. Found {len(recon_results['injection_points'])} injection points")
            return recon_results
            
        except Exception as e:
            self.logger.error(f"❌ Reconnaissance failed: {str(e)}")
            return {}
    
    async def _analyze_target_url(self, target_url: str, results: Dict):
        """Analyze the target URL for parameters"""
        try:
            # Extract URL parameters
            url_params = self._extract_url_parameters(target_url)
            results['urls'].extend(url_params)
            
            # Extract form parameters
            form_params = await self._extract_form_parameters(target_url)
            results['forms'].extend(form_params)
            
            # Extract JavaScript variables
            js_vars = await self._extract_javascript_variables(target_url)
            results['javascript_vars'].extend(js_vars)
            
            # Extract meta tags
            meta_tags = await self._extract_meta_tags(target_url)
            results['meta_tags'].extend(meta_tags)
            
            # Extract cookies
            cookies = await self._extract_cookies(target_url)
            results['cookies'].extend(cookies)
            
            # Extract headers
            headers = await self._extract_headers(target_url)
            results['headers'].extend(headers)
            
        except Exception as e:
            self.logger.error(f"❌ Error analyzing target URL: {str(e)}")
    
    async def _crawl_website(self, target_url: str, results: Dict):
        """Crawl website for additional URLs and parameters"""
        try:
            urls_to_crawl = [target_url]
            crawled_urls = set()
            
            for depth in range(self.max_depth):
                if not urls_to_crawl:
                    break
                
                current_urls = urls_to_crawl.copy()
                urls_to_crawl.clear()
                
                # Process URLs in parallel
                with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                    futures = []
                    
                    for url in current_urls:
                        if url not in crawled_urls:
                            future = executor.submit(self._crawl_single_url, url, results)
                            futures.append(future)
                    
                    # Collect results
                    for future in as_completed(futures):
                        try:
                            new_urls = future.result()
                            for new_url in new_urls:
                                if new_url not in crawled_urls:
                                    crawled_urls.add(new_url)
                                    urls_to_crawl.append(new_url)
                        except Exception as e:
                            self.logger.error(f"❌ Error crawling URL: {str(e)}")
                
                # Add delay between depth levels
                await asyncio.sleep(0.5)
            
        except Exception as e:
            self.logger.error(f"❌ Error crawling website: {str(e)}")
    
    def _crawl_single_url(self, url: str, results: Dict) -> List[str]:
        """Crawl a single URL and extract parameters"""
        new_urls = []
        
        try:
            if url in self.visited_urls:
                return new_urls
            
            self.visited_urls.add(url)
            
            # Make request
            response = asyncio.run(self._make_request(url))
            if not response:
                return new_urls
            
            content = response.get('content', '')
            if not content:
                return new_urls
            
            # Extract parameters
            url_params = self._extract_url_parameters(url)
            results['urls'].extend(url_params)
            
            if BEAUTIFULSOUP_AVAILABLE:
                soup = BeautifulSoup(content, 'html.parser')
                
                # Extract form parameters
                form_params = self._extract_form_parameters_from_soup(soup, url)
                results['forms'].extend(form_params)
                
                # Extract JavaScript variables
                js_vars = self._extract_javascript_variables_from_content(content, url)
                results['javascript_vars'].extend(js_vars)
                
                # Extract meta tags
                meta_tags = self._extract_meta_tags_from_soup(soup, url)
                results['meta_tags'].extend(meta_tags)
                
                # Extract links for further crawling
                new_urls = self._extract_links_from_soup(soup, url)
            
            # Extract cookies
            cookies = self._extract_cookies_from_response(response, url)
            results['cookies'].extend(cookies)
            
            # Extract headers
            headers = self._extract_headers_from_response(response, url)
            results['headers'].extend(headers)
            
        except Exception as e:
            self.logger.error(f"❌ Error crawling {url}: {str(e)}")
        
        return new_urls
    
    async def _make_request(self, url: str) -> Optional[Dict]:
        """Make HTTP request to URL"""
        try:
            async with self.session.get(url) as response:
                content = await response.text()
                return {
                    'url': url,
                    'status_code': response.status,
                    'headers': dict(response.headers),
                    'content': content
                }
        except Exception as e:
            self.logger.error(f"❌ Error making request to {url}: {str(e)}")
            return None
    
    def _extract_url_parameters(self, url: str) -> List[Dict]:
        """Extract parameters from URL"""
        params = []
        
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
                        params.append({
                            'type': 'url',
                            'parameter': param_name,
                            'value': value,
                            'url': url,
                            'context': 'query_parameter'
                        })
        
        except Exception as e:
            self.logger.error(f"❌ Error extracting URL parameters from {url}: {str(e)}")
        
        return params
    
    async def _extract_form_parameters(self, url: str) -> List[Dict]:
        """Extract form parameters from URL"""
        params = []
        
        try:
            response = await self._make_request(url)
            if not response or not BEAUTIFULSOUP_AVAILABLE:
                return params
            
            soup = BeautifulSoup(response['content'], 'html.parser')
            params = self._extract_form_parameters_from_soup(soup, url)
            
        except Exception as e:
            self.logger.error(f"❌ Error extracting form parameters from {url}: {str(e)}")
        
        return params
    
    def _extract_form_parameters_from_soup(self, soup: BeautifulSoup, base_url: str) -> List[Dict]:
        """Extract form parameters from BeautifulSoup object"""
        params = []
        
        try:
            forms = soup.find_all('form')
            
            for form in forms:
                action = form.get('action', '')
                if action:
                    form_url = urljoin(base_url, action)
                else:
                    form_url = base_url
                
                # Extract input fields
                inputs = form.find_all(['input', 'select', 'textarea'])
                
                for input_field in inputs:
                    name = input_field.get('name')
                    if name and (name.lower() in self.redirect_params or 
                               'redirect' in name.lower() or 
                               'url' in name.lower()):
                        params.append({
                            'type': 'form',
                            'parameter': name,
                            'value': input_field.get('value', ''),
                            'url': form_url,
                            'context': 'form_input',
                            'input_type': input_field.get('type', 'text')
                        })
        
        except Exception as e:
            self.logger.error(f"❌ Error extracting form parameters: {str(e)}")
        
        return params
    
    async def _extract_javascript_variables(self, url: str) -> List[Dict]:
        """Extract JavaScript variables from URL"""
        params = []
        
        try:
            response = await self._make_request(url)
            if not response:
                return params
            
            params = self._extract_javascript_variables_from_content(response['content'], url)
            
        except Exception as e:
            self.logger.error(f"❌ Error extracting JavaScript variables from {url}: {str(e)}")
        
        return params
    
    def _extract_javascript_variables_from_content(self, content: str, url: str) -> List[Dict]:
        """Extract JavaScript variables from content"""
        params = []
        
        try:
            # Extract JavaScript redirect patterns
            for pattern in self.js_redirect_patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
                for match in matches:
                    if len(match.groups()) > 0:
                        redirect_url = match.group(1)
                        if redirect_url and not redirect_url.startswith(('http://', 'https://', 'javascript:', 'data:')):
                            params.append({
                                'type': 'javascript',
                                'parameter': 'javascript_redirect',
                                'value': redirect_url,
                                'url': url,
                                'context': 'javascript_redirect',
                                'pattern': pattern
                            })
            
            # Extract variable assignments
            var_patterns = [
                r'var\s+(\w+)\s*=\s*["\']([^"\']+)["\']',
                r'let\s+(\w+)\s*=\s*["\']([^"\']+)["\']',
                r'const\s+(\w+)\s*=\s*["\']([^"\']+)["\']',
                r'(\w+)\s*=\s*["\']([^"\']+)["\']'
            ]
            
            for pattern in var_patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
                for match in matches:
                    var_name = match.group(1)
                    var_value = match.group(2)
                    
                    if (var_name.lower() in self.redirect_params or 
                        'redirect' in var_name.lower() or 
                        'url' in var_name.lower() or
                        'location' in var_name.lower()):
                        
                        params.append({
                            'type': 'javascript',
                            'parameter': var_name,
                            'value': var_value,
                            'url': url,
                            'context': 'javascript_variable'
                        })
        
        except Exception as e:
            self.logger.error(f"❌ Error extracting JavaScript variables: {str(e)}")
        
        return params
    
    async def _extract_meta_tags(self, url: str) -> List[Dict]:
        """Extract meta tags from URL"""
        params = []
        
        try:
            response = await self._make_request(url)
            if not response or not BEAUTIFULSOUP_AVAILABLE:
                return params
            
            soup = BeautifulSoup(response['content'], 'html.parser')
            params = self._extract_meta_tags_from_soup(soup, url)
            
        except Exception as e:
            self.logger.error(f"❌ Error extracting meta tags from {url}: {str(e)}")
        
        return params
    
    def _extract_meta_tags_from_soup(self, soup: BeautifulSoup, url: str) -> List[Dict]:
        """Extract meta tags from BeautifulSoup object"""
        params = []
        
        try:
            meta_tags = soup.find_all('meta')
            
            for meta in meta_tags:
                http_equiv = meta.get('http-equiv', '').lower()
                content = meta.get('content', '')
                
                if http_equiv == 'refresh' and content:
                    # Extract URL from refresh content
                    refresh_match = re.search(r'url\s*=\s*([^;]+)', content, re.IGNORECASE)
                    if refresh_match:
                        redirect_url = refresh_match.group(1).strip()
                        params.append({
                            'type': 'meta',
                            'parameter': 'meta_refresh',
                            'value': redirect_url,
                            'url': url,
                            'context': 'meta_refresh'
                        })
        
        except Exception as e:
            self.logger.error(f"❌ Error extracting meta tags: {str(e)}")
        
        return params
    
    async def _extract_cookies(self, url: str) -> List[Dict]:
        """Extract cookies from URL"""
        params = []
        
        try:
            response = await self._make_request(url)
            if not response:
                return params
            
            params = self._extract_cookies_from_response(response, url)
            
        except Exception as e:
            self.logger.error(f"❌ Error extracting cookies from {url}: {str(e)}")
        
        return params
    
    def _extract_cookies_from_response(self, response: Dict, url: str) -> List[Dict]:
        """Extract cookies from response"""
        params = []
        
        try:
            headers = response.get('headers', {})
            set_cookie = headers.get('Set-Cookie', '')
            if set_cookie:
                # Parse cookies
                cookies = set_cookie.split(',')
                for cookie in cookies:
                    if '=' in cookie:
                        name, value = cookie.split('=', 1)
                        name = name.strip()
                        value = value.split(';')[0].strip()
                        
                        if (name.lower() in self.redirect_params or 
                            'redirect' in name.lower() or 
                            'url' in name.lower()):
                            
                            params.append({
                                'type': 'cookie',
                                'parameter': name,
                                'value': value,
                                'url': url,
                                'context': 'cookie'
                            })
        
        except Exception as e:
            self.logger.error(f"❌ Error extracting cookies: {str(e)}")
        
        return params
    
    async def _extract_headers(self, url: str) -> List[Dict]:
        """Extract headers from URL"""
        params = []
        
        try:
            response = await self._make_request(url)
            if not response:
                return params
            
            params = self._extract_headers_from_response(response, url)
            
        except Exception as e:
            self.logger.error(f"❌ Error extracting headers from {url}: {str(e)}")
        
        return params
    
    def _extract_headers_from_response(self, response: Dict, url: str) -> List[Dict]:
        """Extract headers from response"""
        params = []
        
        try:
            headers = response.get('headers', {})
            
            for header_name in self.header_redirect_patterns:
                header_value = headers.get(header_name)
                if header_value:
                    params.append({
                        'type': 'header',
                        'parameter': header_name,
                        'value': header_value,
                        'url': url,
                        'context': 'http_header'
                    })
        
        except Exception as e:
            self.logger.error(f"❌ Error extracting headers: {str(e)}")
        
        return params
    
    def _extract_links_from_soup(self, soup: BeautifulSoup, base_url: str) -> List[str]:
        """Extract links from BeautifulSoup object"""
        links = []
        
        try:
            if not soup:
                return links
                
            # Extract all links
            for link in soup.find_all('a', href=True):
                href = link.get('href')
                if href:
                    full_url = urljoin(base_url, href)
                    
                    # Only crawl same domain
                    if self._is_same_domain(base_url, full_url):
                        links.append(full_url)
            
            # Extract form actions
            for form in soup.find_all('form', action=True):
                action = form.get('action')
                if action:
                    full_url = urljoin(base_url, action)
                    
                    if self._is_same_domain(base_url, full_url):
                        links.append(full_url)
        
        except Exception as e:
            self.logger.error(f"❌ Error extracting links: {str(e)}")
        
        return links
    
    def _is_same_domain(self, url1: str, url2: str) -> bool:
        """Check if two URLs are from the same domain"""
        try:
            domain1 = urlparse(url1).netloc
            domain2 = urlparse(url2).netloc
            return domain1 == domain2
        except:
            return False
    
    async def _discover_api_endpoints(self, target_url: str, results: Dict):
        """Discover API endpoints"""
        try:
            base_domain = urlparse(target_url).netloc
            common_api_paths = [
                '/api', '/api/v1', '/api/v2', '/api/v3',
                '/rest', '/rest/api', '/rest/v1', '/rest/v2',
                '/graphql', '/graphql/v1', '/graphql/v2',
                '/webhook', '/webhooks', '/callback', '/callbacks',
                '/oauth', '/oauth2', '/auth', '/authentication',
                '/login', '/logout', '/register', '/signup',
                '/password', '/reset', '/forgot', '/verify',
                '/confirm', '/activate', '/deactivate', '/suspend',
                '/admin', '/administrator', '/management', '/manage',
                '/dashboard', '/panel', '/control', '/settings',
                '/config', '/configuration', '/setup', '/install',
                '/update', '/upgrade', '/migrate', '/backup',
                '/export', '/import', '/download', '/upload',
                '/file', '/files', '/document', '/documents',
                '/image', '/images', '/photo', '/photos',
                '/video', '/videos', '/media', '/assets',
                '/static', '/public', '/private', '/secure',
                '/internal', '/external', '/public', '/private'
            ]
            
            for path in common_api_paths:
                api_url = f"{urlparse(target_url).scheme}://{base_domain}{path}"
                response = await self._make_request(api_url)
                if response and response['status_code'] in [200, 201, 202, 204, 301, 302, 307, 308]:
                    results['api_endpoints'].append({
                        'url': api_url,
                        'status_code': response['status_code'],
                        'headers': response['headers']
                    })
        
        except Exception as e:
            self.logger.error(f"❌ Error discovering API endpoints: {str(e)}")
    
    async def _analyze_sitemap_robots(self, target_url: str, results: Dict):
        """Analyze sitemap and robots.txt"""
        try:
            base_domain = urlparse(target_url).netloc
            base_scheme = urlparse(target_url).scheme
            
            # Check robots.txt
            robots_url = f"{base_scheme}://{base_domain}/robots.txt"
            robots_response = await self._make_request(robots_url)
            if robots_response and robots_response['status_code'] == 200:
                # Extract URLs from robots.txt
                content = robots_response['content']
                urls = re.findall(r'https?://[^\s]+', content)
                for url in urls:
                    results['robots_urls'].append(url)
            
            # Check sitemap.xml
            sitemap_urls = [
                f"{base_scheme}://{base_domain}/sitemap.xml",
                f"{base_scheme}://{base_domain}/sitemap_index.xml",
                f"{base_scheme}://{base_domain}/sitemaps.xml"
            ]
            
            for sitemap_url in sitemap_urls:
                sitemap_response = await self._make_request(sitemap_url)
                if sitemap_response and sitemap_response['status_code'] == 200:
                    # Extract URLs from sitemap
                    content = sitemap_response['content']
                    urls = re.findall(r'<loc>(https?://[^<]+)</loc>', content)
                    for url in urls:
                        results['sitemap_urls'].append(url)
        
        except Exception as e:
            self.logger.error(f"❌ Error analyzing sitemap/robots: {str(e)}")
    
    async def _analyze_error_pages(self, target_url: str, results: Dict):
        """Analyze error pages for potential redirects"""
        try:
            base_domain = urlparse(target_url).netloc
            base_scheme = urlparse(target_url).scheme
            
            # Common error pages
            error_paths = [
                '/404', '/404.html', '/404.php', '/404.asp', '/404.aspx',
                '/500', '/500.html', '/500.php', '/500.asp', '/500.aspx',
                '/error', '/error.html', '/error.php', '/error.asp', '/error.aspx',
                '/notfound', '/not-found', '/not_found', '/notfound.html',
                '/forbidden', '/403', '/403.html', '/403.php',
                '/unauthorized', '/401', '/401.html', '/401.php',
                '/badrequest', '/400', '/400.html', '/400.php',
                '/timeout', '/408', '/408.html', '/408.php',
                '/gone', '/410', '/410.html', '/410.php',
                '/teapot', '/418', '/418.html', '/418.php'
            ]
            
            for path in error_paths:
                error_url = f"{base_scheme}://{base_domain}{path}"
                response = await self._make_request(error_url)
                if response and response['status_code'] in [200, 301, 302, 307, 308]:
                    results['error_pages'].append({
                        'url': error_url,
                        'status_code': response['status_code'],
                        'headers': response['headers']
                    })
        
        except Exception as e:
            self.logger.error(f"❌ Error analyzing error pages: {str(e)}")
    
    def _extract_injection_points(self, recon_results: Dict) -> List[Dict]:
        """Extract all potential injection points for testing"""
        injection_points = []
        
        try:
            if not recon_results:
                return injection_points
                
            # URL parameters
            for param in recon_results.get('urls', []):
                if param and isinstance(param, dict):
                    injection_points.append({
                        'type': 'url',
                        'parameter': param.get('parameter', ''),
                        'url': param.get('url', ''),
                        'context': param.get('context', '')
                    })
            
            # Form parameters
            for param in recon_results.get('forms', []):
                if param and isinstance(param, dict):
                    injection_points.append({
                        'type': 'form',
                        'parameter': param.get('parameter', ''),
                        'url': param.get('url', ''),
                        'context': param.get('context', '')
                    })
            
            # JavaScript variables
            for param in recon_results.get('javascript_vars', []):
                if param and isinstance(param, dict):
                    injection_points.append({
                        'type': 'javascript',
                        'parameter': param.get('parameter', ''),
                        'url': param.get('url', ''),
                        'context': param.get('context', '')
                    })
            
            # Meta tags
            for param in recon_results.get('meta_tags', []):
                if param and isinstance(param, dict):
                    injection_points.append({
                        'type': 'meta',
                        'parameter': param.get('parameter', ''),
                        'url': param.get('url', ''),
                        'context': param.get('context', '')
                    })
            
            # Cookies
            for param in recon_results.get('cookies', []):
                if param and isinstance(param, dict):
                    injection_points.append({
                        'type': 'cookie',
                        'parameter': param.get('parameter', ''),
                        'url': param.get('url', ''),
                        'context': param.get('context', '')
                    })
            
            # Headers
            for param in recon_results.get('headers', []):
                if param and isinstance(param, dict):
                    injection_points.append({
                        'type': 'header',
                        'parameter': param.get('parameter', ''),
                        'url': param.get('url', ''),
                        'context': param.get('context', '')
                    })
        
        except Exception as e:
            self.logger.error(f"❌ Error extracting injection points: {str(e)}")
        
        return injection_points