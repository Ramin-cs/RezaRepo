"""
Advanced Reconnaissance Module for Open Redirect Scanner
Comprehensive parameter extraction from various sources
"""

import asyncio
import aiohttp
import re
import json
import urllib.parse
from typing import List, Dict, Set, Optional, Tuple
from urllib.parse import urljoin, urlparse, parse_qs, unquote
from bs4 import BeautifulSoup
import logging

class ReconModule:
    """
    Advanced reconnaissance module for comprehensive parameter extraction
    Extracts parameters from URLs, forms, JavaScript, headers, meta tags, cookies
    """
    
    def __init__(self, logger):
        self.logger = logger
        self.visited_urls = set()
        self.injection_points = []
        
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
    
    async def perform_recon(self, target_url: str, session: aiohttp.ClientSession) -> Dict:
        """
        Perform comprehensive reconnaissance
        """
        try:
            self.logger.info(f"Starting reconnaissance for: {target_url}")
            
            recon_results = {
                'target_url': target_url,
                'urls': [],
                'forms': [],
                'javascript_vars': [],
                'meta_tags': [],
                'cookies': [],
                'headers': [],
                'injection_points': []
            }
            
            # Start crawling from target URL
            await self._crawl_url(target_url, session, recon_results)
            
            # Extract injection points
            recon_results['injection_points'] = self.extract_injection_points(recon_results)
            
            self.logger.info(f"Reconnaissance completed. Found {len(recon_results['injection_points'])} injection points")
            return recon_results
            
        except Exception as e:
            self.logger.error(f"Reconnaissance failed: {str(e)}")
            return {}
    
    async def _crawl_url(self, url: str, session: aiohttp.ClientSession, results: Dict, depth: int = 0, max_depth: int = 3):
        """
        Crawl a single URL and extract parameters
        """
        if depth > max_depth or url in self.visited_urls:
            return
        
        self.visited_urls.add(url)
        
        try:
            self.logger.info(f"Crawling: {url} (depth: {depth})")
            
            # Make request
            async with session.get(url) as response:
                if response.status != 200:
                    return
                
                content = await response.text()
                soup = BeautifulSoup(content, 'html.parser')
                
                # Extract URL parameters
                url_params = self._extract_url_parameters(url)
                results['urls'].extend(url_params)
                
                # Extract form parameters
                form_params = self._extract_form_parameters(soup, url)
                results['forms'].extend(form_params)
                
                # Extract JavaScript variables
                js_vars = self._extract_javascript_variables(content, url)
                results['javascript_vars'].extend(js_vars)
                
                # Extract meta tags
                meta_tags = self._extract_meta_tags(soup, url)
                results['meta_tags'].extend(meta_tags)
                
                # Extract cookies
                cookies = self._extract_cookies(response.headers, url)
                results['cookies'].extend(cookies)
                
                # Extract headers
                headers = self._extract_headers(response.headers, url)
                results['headers'].extend(headers)
                
                # Find new URLs to crawl
                new_urls = self._extract_links(soup, url)
                
                # Crawl new URLs
                for new_url in new_urls:
                    if new_url not in self.visited_urls:
                        await self._crawl_url(new_url, session, results, depth + 1, max_depth)
                
        except Exception as e:
            self.logger.error(f"Error crawling {url}: {str(e)}")
    
    def _extract_url_parameters(self, url: str) -> List[Dict]:
        """Extract parameters from URL"""
        params = []
        
        try:
            parsed = urlparse(url)
            query_params = parse_qs(parsed.query)
            
            for param_name, param_values in query_params.items():
                if param_name.lower() in self.redirect_params or 'redirect' in param_name.lower() or 'url' in param_name.lower():
                    for value in param_values:
                        params.append({
                            'type': 'url',
                            'parameter': param_name,
                            'value': value,
                            'url': url,
                            'context': 'query_parameter'
                        })
        
        except Exception as e:
            self.logger.error(f"Error extracting URL parameters from {url}: {str(e)}")
        
        return params
    
    def _extract_form_parameters(self, soup: BeautifulSoup, base_url: str) -> List[Dict]:
        """Extract parameters from forms"""
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
                    if name and (name.lower() in self.redirect_params or 'redirect' in name.lower() or 'url' in name.lower()):
                        params.append({
                            'type': 'form',
                            'parameter': name,
                            'value': input_field.get('value', ''),
                            'url': form_url,
                            'context': 'form_input',
                            'input_type': input_field.get('type', 'text')
                        })
        
        except Exception as e:
            self.logger.error(f"Error extracting form parameters: {str(e)}")
        
        return params
    
    def _extract_javascript_variables(self, content: str, url: str) -> List[Dict]:
        """Extract JavaScript variables and redirect patterns"""
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
            self.logger.error(f"Error extracting JavaScript variables: {str(e)}")
        
        return params
    
    def _extract_meta_tags(self, soup: BeautifulSoup, url: str) -> List[Dict]:
        """Extract meta tags with redirect information"""
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
            self.logger.error(f"Error extracting meta tags: {str(e)}")
        
        return params
    
    def _extract_cookies(self, headers, url: str) -> List[Dict]:
        """Extract cookies with redirect information"""
        params = []
        
        try:
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
            self.logger.error(f"Error extracting cookies: {str(e)}")
        
        return params
    
    def _extract_headers(self, headers, url: str) -> List[Dict]:
        """Extract headers with redirect information"""
        params = []
        
        try:
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
            self.logger.error(f"Error extracting headers: {str(e)}")
        
        return params
    
    def _extract_links(self, soup: BeautifulSoup, base_url: str) -> List[str]:
        """Extract links from page for further crawling"""
        links = []
        
        try:
            # Extract all links
            for link in soup.find_all('a', href=True):
                href = link['href']
                full_url = urljoin(base_url, href)
                
                # Only crawl same domain
                if self._is_same_domain(base_url, full_url):
                    links.append(full_url)
            
            # Extract form actions
            for form in soup.find_all('form', action=True):
                action = form['action']
                full_url = urljoin(base_url, action)
                
                if self._is_same_domain(base_url, full_url):
                    links.append(full_url)
        
        except Exception as e:
            self.logger.error(f"Error extracting links: {str(e)}")
        
        return links
    
    def _is_same_domain(self, url1: str, url2: str) -> bool:
        """Check if two URLs are from the same domain"""
        try:
            domain1 = urlparse(url1).netloc
            domain2 = urlparse(url2).netloc
            return domain1 == domain2
        except:
            return False
    
    def extract_injection_points(self, recon_results: Dict) -> List[Dict]:
        """Extract all potential injection points for testing"""
        injection_points = []
        
        try:
            # URL parameters
            for param in recon_results.get('urls', []):
                injection_points.append({
                    'type': 'url',
                    'parameter': param['parameter'],
                    'url': param['url'],
                    'context': param['context']
                })
            
            # Form parameters
            for param in recon_results.get('forms', []):
                injection_points.append({
                    'type': 'form',
                    'parameter': param['parameter'],
                    'url': param['url'],
                    'context': param['context']
                })
            
            # JavaScript variables
            for param in recon_results.get('javascript_vars', []):
                injection_points.append({
                    'type': 'javascript',
                    'parameter': param['parameter'],
                    'url': param['url'],
                    'context': param['context']
                })
            
            # Meta tags
            for param in recon_results.get('meta_tags', []):
                injection_points.append({
                    'type': 'meta',
                    'parameter': param['parameter'],
                    'url': param['url'],
                    'context': param['context']
                })
            
            # Cookies
            for param in recon_results.get('cookies', []):
                injection_points.append({
                    'type': 'cookie',
                    'parameter': param['parameter'],
                    'url': param['url'],
                    'context': param['context']
                })
            
            # Headers
            for param in recon_results.get('headers', []):
                injection_points.append({
                    'type': 'header',
                    'parameter': param['parameter'],
                    'url': param['url'],
                    'context': param['context']
                })
        
        except Exception as e:
            self.logger.error(f"Error extracting injection points: {str(e)}")
        
        return injection_points