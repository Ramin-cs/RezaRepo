#!/usr/bin/env python3
"""
🔥 WEB3 ANALYZER - Complete Web3/DeFi/NFT Analysis
"""

import re
from typing import List
from data_models import Parameter


class Web3Module:
    """Complete Web3 analysis"""
    
    def detect_web3_app(self, content: str) -> bool:
        """Detect Web3 application"""
        indicators = ['web3', 'ethereum', 'metamask', 'wallet', 'dapp', 'defi', 'nft']
        content_lower = content.lower()
        return sum(1 for indicator in indicators if indicator in content_lower) >= 2
    
    def analyze_web3(self, content: str, url: str) -> List[Parameter]:
        """Analyze Web3 patterns"""
        params = []
        
        if not self.detect_web3_app(content):
            return params
        
        print(f"[WEB3-DETECTED] DeFi/DApp platform: {url}")
        
        patterns = [
            r'wallet[_-]?redirect["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            r'connect[_-]?callback["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            r'swap[_-]?redirect["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            r'nft[_-]?redirect["\']?\s*[:=]\s*["\']([^"\']+)["\']'
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                param_name = self.get_param_name(pattern)
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
    
    def get_param_name(self, pattern: str) -> str:
        """Get parameter name"""
        if 'wallet' in pattern:
            return 'wallet_redirect_url'
        elif 'swap' in pattern:
            return 'defi_swap_redirect'
        elif 'nft' in pattern:
            return 'nft_marketplace_redirect'
        else:
            return 'web3_parameter'