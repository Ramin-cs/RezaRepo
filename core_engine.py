#!/usr/bin/env python3
"""
🔥 CORE ENGINE - Ultimate Hunter Core Functionality
"""

import asyncio
import aiohttp
import re
import json
import time
from urllib.parse import urljoin, urlparse, parse_qs, unquote, quote
from dataclasses import dataclass, asdict
from typing import List, Dict, Set, Optional, Tuple
import logging
from datetime import datetime
import random
import sys

try:
    from bs4 import BeautifulSoup
    BS4_OK = True
except ImportError:
    BS4_OK = False


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
    remediation: str = ""


class CoreEngine:
    """Core scanning engine"""
    
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
        
        # Session
        self.session = None
        
        # Patterns
        self.redirect_patterns = [
            'redirect', 'url', 'next', 'return', 'goto', 'target', 'destination',
            'continue', 'forward', 'redir', 'location', 'site', 'link', 'href',
            'returnurl', 'returnto', 'back', 'callback', 'success', 'failure',
            'done', 'exit', 'referrer', 'referer', 'origin', 'source', 'from'
        ]
        
        # User agents
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"
        ]
    
    async def init_session(self):
        """Initialize HTTP session"""
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
    
    async def crawl_website(self):
        """Core crawling functionality"""
        urls_to_crawl = {self.target_url}
        crawled_urls = set()
        depth = 0
        
        while urls_to_crawl and depth < self.max_depth and len(crawled_urls) < self.max_pages:
            current_urls = list(urls_to_crawl)[:20]
            urls_to_crawl.clear()
            
            print(f"[CORE] Scanning depth {depth + 1}...")
            
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
            print(f"[CORE] Depth {depth}: {len(crawled_urls)} URLs, {len(self.parameters)} parameters")
        
        self.discovered_urls = crawled_urls
    
    async def crawl_single_page(self, url: str):
        """Crawl single page"""
        try:
            async with self.session.get(url, allow_redirects=False) as response:
                content = await response.text()
                headers = dict(response.headers)
                
                # Extract URLs
                if BS4_OK:
                    soup = BeautifulSoup(content, 'html.parser')
                    new_urls = self.extract_urls_bs4(soup, url)
                    params = self.extract_form_params_bs4(soup, url)
                else:
                    new_urls = self.extract_urls_regex(content, url)
                    params = self.extract_form_params_regex(content, url)
                
                # URL parameters
                params.extend(self.extract_url_parameters(url))
                
                # Header parameters
                params.extend(self.extract_header_parameters(headers, url))
                
                return url, new_urls, params
                
        except:
            return None
    
    def extract_urls_bs4(self, soup, base_url: str):
        """Extract URLs with BeautifulSoup"""
        urls = set()
        for link in soup.find_all(['a', 'link', 'form'], href=True):
            href = link['href']
            full_url = urljoin(base_url, href)
            if self.is_same_domain(full_url):
                urls.add(full_url)
        
        # Form actions
        for form in soup.find_all('form'):
            action = form.get('action')
            if action:
                full_url = urljoin(base_url, action)
                if self.is_same_domain(full_url):
                    urls.add(full_url)
        
        return urls
    
    def extract_urls_regex(self, content: str, base_url: str):
        """Extract URLs with regex"""
        urls = set()
        patterns = [r'href=["\']([^"\']+)["\']', r'action=["\']([^"\']+)["\']']
        
        for pattern in patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                full_url = urljoin(base_url, match)
                if self.is_same_domain(full_url):
                    urls.add(full_url)
        
        return urls
    
    def extract_form_params_bs4(self, soup, url: str):
        """Extract form parameters"""
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
    
    def extract_form_params_regex(self, content: str, url: str):
        """Extract form parameters with regex"""
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
        """Extract URL parameters"""
        params = []
        parsed = urlparse(url)
        
        # Query parameters
        if parsed.query:
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
    
    def extract_header_parameters(self, headers: Dict[str, str], url: str):
        """Extract header parameters"""
        params = []
        
        redirect_headers = ['Location', 'Refresh', 'Link', 'Content-Location']
        
        for header_name, header_value in headers.items():
            if (header_name in redirect_headers or 
                'redirect' in header_name.lower() or
                'location' in header_name.lower()):
                
                params.append(Parameter(
                    name=header_name.lower(),
                    value=header_value,
                    source='headers',
                    context='http_header',
                    url=url,
                    is_redirect_related=True,
                    confidence=0.95
                ))
        
        return params
    
    def is_same_domain(self, url: str):
        """Check same domain"""
        try:
            parsed = urlparse(url)
            target_domain = parsed.netloc.lower()
            base_domain = self.base_domain.lower()
            
            return target_domain == base_domain or target_domain.endswith(f'.{base_domain}')
        except:
            return False
    
    def is_redirect_parameter(self, param_name: str, param_value: str = ""):
        """Check if redirect parameter"""
        param_lower = param_name.lower()
        value_lower = param_value.lower()
        
        name_match = any(pattern in param_lower for pattern in self.redirect_patterns)
        value_match = bool(re.match(r'https?://', value_lower) or re.match(r'//', value_lower))
        
        return name_match or value_match
    
    def calculate_confidence(self, param_name: str, param_value: str, context: str):
        """Calculate confidence"""
        confidence = 0.0
        
        context_scores = {'query': 0.6, 'fragment': 0.7, 'form_input': 0.5, 'http_header': 0.9}
        confidence += context_scores.get(context, 0.3)
        
        if self.is_redirect_parameter(param_name):
            confidence += 0.3
        
        if param_value and (param_value.startswith(('http', '//')) or '.' in param_value):
            confidence += 0.2
        
        return min(confidence, 1.0)