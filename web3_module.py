#!/usr/bin/env python3
"""
Ultimate Web3/DeFi Open Redirect Detection Module
The most advanced Web3 vulnerability scanner
"""

import re
from typing import List, Dict, Any
from dataclasses import dataclass


@dataclass(frozen=True)
class Web3Parameter:
    """Web3-specific parameter"""
    name: str
    value: str
    context: str
    confidence: float
    vulnerability_type: str


class UltimateWeb3Scanner:
    """Ultimate Web3/DeFi vulnerability scanner"""
    
    def __init__(self):
        # DeFi protocols and platforms
        self.defi_platforms = [
            'uniswap', 'pancakeswap', 'sushiswap', 'curve', 'balancer',
            'compound', 'aave', 'maker', 'yearn', 'convex', 'frax',
            'lido', 'rocket', 'euler', 'morpho', 'radiant'
        ]
        
        # Web3 wallets
        self.web3_wallets = [
            'metamask', 'walletconnect', 'coinbase', 'trust', 'rainbow',
            'argent', 'gnosis', 'ledger', 'trezor', 'phantom', 'solflare'
        ]
        
        # NFT marketplaces
        self.nft_platforms = [
            'opensea', 'rarible', 'foundation', 'superrare', 'nifty',
            'async', 'makersplace', 'known', 'portion', 'ghostmarket'
        ]
    
    def analyze_web3_redirects(self, content: str, url: str) -> List[Web3Parameter]:
        """Analyze Web3-specific redirect patterns"""
        params = []
        
        # Wallet connection redirects
        params.extend(self.scan_wallet_redirects(content, url))
        
        # DeFi protocol redirects
        params.extend(self.scan_defi_redirects(content, url))
        
        # NFT marketplace redirects
        params.extend(self.scan_nft_redirects(content, url))
        
        # Smart contract interaction redirects
        params.extend(self.scan_contract_redirects(content, url))
        
        return params
    
    def scan_wallet_redirects(self, content: str, url: str) -> List[Web3Parameter]:
        """Scan for wallet connection redirect vulnerabilities"""
        params = []
        
        wallet_patterns = [
            r'connectWallet\(["\']?([^"\';\)]+)',
            r'walletConnect\(["\']?([^"\';\)]+)', 
            r'metamask\.request\([^)]*["\']([^"\']+)["\']',
            r'ethereum\.request\([^)]*["\']([^"\']+)["\']',
            r'window\.ethereum\.[^(]+\(["\']?([^"\';\)]+)',
            r'wallet[_\-]?redirect["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            r'connect[_\-]?callback["\']?\s*[:=]\s*["\']([^"\']+)["\']'
        ]
        
        for pattern in wallet_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                params.append(Web3Parameter(
                    name='wallet_redirect',
                    value=match,
                    context='wallet_connect',
                    confidence=0.9,
                    vulnerability_type='web3_wallet_redirect'
                ))
        
        return params
    
    def scan_defi_redirects(self, content: str, url: str) -> List[Web3Parameter]:
        """Scan for DeFi protocol redirect vulnerabilities"""
        params = []
        
        defi_patterns = [
            r'swap[_\-]?redirect["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            r'liquidity[_\-]?redirect["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            r'stake[_\-]?redirect["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            r'farm[_\-]?redirect["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            r'bridge[_\-]?url["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            r'protocol[_\-]?redirect["\']?\s*[:=]\s*["\']([^"\']+)["\']'
        ]
        
        for pattern in defi_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                params.append(Web3Parameter(
                    name='defi_redirect',
                    value=match,
                    context='defi_protocol',
                    confidence=0.85,
                    vulnerability_type='web3_defi_redirect'
                ))
        
        return params
    
    def scan_nft_redirects(self, content: str, url: str) -> List[Web3Parameter]:
        """Scan for NFT marketplace redirect vulnerabilities"""
        params = []
        
        nft_patterns = [
            r'nft[_\-]?redirect["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            r'marketplace[_\-]?url["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            r'collection[_\-]?redirect["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            r'mint[_\-]?redirect["\']?\s*[:=]\s*["\']([^"\']+)["\']'
        ]
        
        for pattern in nft_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                params.append(Web3Parameter(
                    name='nft_redirect',
                    value=match,
                    context='nft_marketplace',
                    confidence=0.8,
                    vulnerability_type='web3_nft_redirect'
                ))
        
        return params
    
    def scan_contract_redirects(self, content: str, url: str) -> List[Web3Parameter]:
        """Scan for smart contract interaction redirects"""
        params = []
        
        contract_patterns = [
            r'contract\.methods\.[^(]+\(["\']?([^"\';\)]+)',
            r'web3\.eth\.[^(]+\(["\']?([^"\';\)]+)',
            r'transaction[_\-]?redirect["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            r'contract[_\-]?callback["\']?\s*[:=]\s*["\']([^"\']+)["\']'
        ]
        
        for pattern in contract_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                params.append(Web3Parameter(
                    name='contract_redirect',
                    value=match,
                    context='smart_contract',
                    confidence=0.75,
                    vulnerability_type='web3_contract_redirect'
                ))
        
        return params
    
    def generate_web3_payloads(self) -> List[str]:
        """Generate Web3-specific malicious payloads"""
        payloads = []
        
        # Fake DeFi platforms
        for platform in self.defi_platforms:
            payloads.extend([
                f"//fake-{platform}.com",
                f"https://phishing-{platform}.io",
                f"//evil-{platform}.finance"
            ])
        
        # Fake wallets
        for wallet in self.web3_wallets:
            payloads.extend([
                f"//fake-{wallet}.io",
                f"https://phishing-{wallet}.com"
            ])
        
        # Fake NFT platforms
        for nft in self.nft_platforms:
            payloads.extend([
                f"//fake-{nft}.io",
                f"https://phishing-{nft}.com"
            ])
        
        # Protocol-specific payloads
        payloads.extend([
            "web3://malicious-contract.eth",
            "ipfs://QmMaliciousHash",
            "ens://hacker.eth",
            "ethereum://0x1234567890123456789012345678901234567890",
            "//evil.defi",
            "//malicious.finance",
            "//phishing-dapp.com"
        ])
        
        return payloads