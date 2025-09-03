#!/usr/bin/env python3
"""
🔥 WEB3 & JAVASCRIPT ANALYZER - Complete Analysis Module
"""

import re
import asyncio
from typing import List, Dict, Optional
from urllib.parse import urljoin
from core_engine import Parameter


class Web3Analyzer:
    """Complete Web3/DeFi/NFT analysis engine"""
    
    def detect_web3_application(self, content: str) -> bool:
        """Detect Web3 application"""
        web3_indicators = [
            'web3', 'ethereum', 'metamask', 'wallet', 'dapp', 'defi', 'nft',
            'uniswap', 'pancakeswap', 'compound', 'aave', 'opensea', 'rarible'
        ]
        
        content_lower = content.lower()
        detected_count = sum(1 for indicator in web3_indicators if indicator in content_lower)
        
        return detected_count >= 2
    
    def analyze_web3_patterns(self, content: str, url: str) -> List[Parameter]:
        """Complete Web3 pattern analysis"""
        params = []
        
        if not self.detect_web3_application(content):
            return params
        
        print(f"[WEB3-DETECTED] DeFi/DApp/NFT platform: {url}")
        
        # Web3 patterns
        web3_patterns = [
            r'wallet[_-]?redirect["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            r'connect[_-]?callback["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            r'swap[_-]?redirect["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            r'nft[_-]?redirect["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            r'contract[_-]?callback["\']?\s*[:=]\s*["\']([^"\']+)["\']'
        ]
        
        for pattern in web3_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                param_name = self.extract_web3_param_name(pattern)
                
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
    
    def extract_web3_param_name(self, pattern: str) -> str:
        """Extract parameter name"""
        if 'wallet' in pattern:
            return 'wallet_redirect_url'
        elif 'connect' in pattern:
            return 'wallet_connect_callback'
        elif 'swap' in pattern:
            return 'defi_swap_redirect'
        elif 'nft' in pattern:
            return 'nft_marketplace_redirect'
        elif 'contract' in pattern:
            return 'smart_contract_callback'
        else:
            return 'web3_parameter'


class JavaScriptAnalyzer:
    """Complete JavaScript analysis engine"""
    
    async def analyze_javascript(self, content: str, url: str, session) -> List[Parameter]:
        """Complete JavaScript analysis"""
        params = []
        
        # Extract JS blocks
        script_pattern = r'<script[^>]*>(.*?)</script>'
        scripts = re.findall(script_pattern, content, re.DOTALL | re.IGNORECASE)
        
        # External JS files
        src_pattern = r'<script[^>]*src=["\']([^"\']+)["\']'
        src_matches = re.findall(src_pattern, content, re.IGNORECASE)
        
        for src in src_matches:
            js_url = urljoin(url, src)
            js_content = await self.fetch_js_file(js_url, session)
            if js_content:
                scripts.append(js_content)
        
        # Analyze all JS
        for js_content in scripts:
            js_params = self.analyze_js_code(js_content, url)
            params.extend(js_params)
        
        return params
    
    async def fetch_js_file(self, js_url: str, session) -> Optional[str]:
        """Fetch JS file"""
        try:
            async with session.get(js_url) as response:
                if response.status == 200:
                    return await response.text()
        except:
            pass
        return None
    
    def analyze_js_code(self, js_content: str, source_url: str) -> List[Parameter]:
        """Analyze JS code"""
        params = []
        
        js_patterns = [
            r'location\.href\s*=\s*([^;]+)',
            r'window\.location\s*=\s*([^;]+)',
            r'location\.assign\(["\']?([^"\';\)]+)',
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
                        
                        is_redirect = self.is_redirect_js_param(param_name, param_value, line)
                        confidence = self.calculate_js_confidence(param_name, param_value, line)
                        
                        params.append(Parameter(
                            name=param_name,
                            value=param_value,
                            source='javascript',
                            context='js_variable',
                            url=source_url,
                            is_redirect_related=is_redirect,
                            confidence=confidence
                        ))
        
        return params
    
    def is_redirect_js_param(self, param_name: str, param_value: str, line: str) -> bool:
        """Check if JS parameter is redirect-related"""
        redirect_indicators = ['redirect', 'url', 'location', 'href', 'goto']
        
        name_match = any(indicator in param_name.lower() for indicator in redirect_indicators)
        value_match = any(indicator in param_value.lower() for indicator in redirect_indicators)
        line_match = any(sink in line.lower() for sink in ['location.href', 'window.location'])
        
        return name_match or value_match or line_match
    
    def calculate_js_confidence(self, param_name: str, param_value: str, line: str) -> float:
        """Calculate JS parameter confidence"""
        confidence = 0.4  # Base for JS
        
        # Boost for redirect sinks
        if any(sink in line.lower() for sink in ['location.href', 'window.location']):
            confidence += 0.4
        
        # Boost for user sources
        if any(source in line.lower() for source in ['location.search', 'urlsearchparams']):
            confidence += 0.3
        
        # Boost for redirect names
        if any(indicator in param_name.lower() for indicator in ['redirect', 'url', 'location']):
            confidence += 0.2
        
        return min(confidence, 1.0)