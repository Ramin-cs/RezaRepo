#!/usr/bin/env python3
"""
🔥 URL PATTERN ANALYZER - Advanced URL Analysis
"""

import re
import tldextract
from typing import List, Dict, Set, Optional, Tuple
from urllib.parse import urlparse, parse_qs, unquote, quote
from dataclasses import dataclass


@dataclass
class URLAnalysis:
    """URL analysis result"""
    url: str
    domain: str
    subdomain: str
    path: str
    query_params: Dict[str, List[str]]
    fragment: str
    is_suspicious: bool = False
    suspicion_reasons: List[str] = None
    redirect_indicators: List[str] = None
    risk_score: float = 0.0
    url_type: str = "normal"  # normal, api, admin, auth, payment, web3
    
    def __post_init__(self):
        if self.suspicion_reasons is None:
            self.suspicion_reasons = []
        if self.redirect_indicators is None:
            self.redirect_indicators = []


class URLAnalyzer:
    """Advanced URL pattern analysis"""
    
    def __init__(self):
        # Suspicious URL patterns
        self.suspicious_patterns = [
            # Redirect patterns
            r'redirect',
            r'forward',
            r'goto',
            r'next',
            r'return',
            r'continue',
            r'back',
            r'exit',
            
            # Authentication patterns
            r'login',
            r'logout',
            r'auth',
            r'signin',
            r'signout',
            r'sso',
            
            # Admin patterns
            r'admin',
            r'panel',
            r'dashboard',
            r'control',
            r'manage',
            
            # API patterns
            r'api',
            r'rest',
            r'graphql',
            r'webhook',
            
            # Payment patterns
            r'pay',
            r'payment',
            r'checkout',
            r'billing',
            r'invoice',
            
            # Web3 patterns
            r'web3',
            r'defi',
            r'nft',
            r'wallet',
            r'metamask',
            r'uniswap',
            r'opensea'
        ]
        
        # High-risk path patterns
        self.high_risk_paths = [
            r'/admin/',
            r'/api/',
            r'/auth/',
            r'/login',
            r'/logout',
            r'/redirect',
            r'/forward',
            r'/goto',
            r'/panel/',
            r'/dashboard/',
            r'/control/',
            r'/manage/',
            r'/payment/',
            r'/checkout/',
            r'/billing/',
            r'/wallet/',
            r'/web3/',
            r'/defi/',
            r'/nft/'
        ]
        
        # Parameter patterns that indicate redirects
        self.redirect_param_patterns = [
            r'redirect',
            r'url',
            r'next',
            r'return',
            r'goto',
            r'target',
            r'destination',
            r'continue',
            r'forward',
            r'redir',
            r'location',
            r'site',
            r'link',
            r'href',
            r'callback',
            r'success_url',
            r'failure_url',
            r'cancel_url',
            r'exit_url',
            r'logout_url',
            r'login_redirect'
        ]
        
        # URL encoding patterns
        self.encoding_patterns = [
            r'%[0-9a-fA-F]{2}',  # URL encoding
            r'\\u[0-9a-fA-F]{4}',  # Unicode encoding
            r'\\x[0-9a-fA-F]{2}',  # Hex encoding
        ]
        
        # Web3/DeFi specific patterns
        self.web3_patterns = [
            r'0x[a-fA-F0-9]{40}',  # Ethereum address
            r'\.eth$',  # ENS domain
            r'ipfs://',  # IPFS protocol
            r'web3://',  # Web3 protocol
            r'ethereum://',  # Ethereum protocol
        ]
    
    def analyze_url(self, url: str) -> URLAnalysis:
        """Comprehensive URL analysis"""
        parsed = urlparse(url)
        extracted = tldextract.extract(url)
        
        analysis = URLAnalysis(
            url=url,
            domain=extracted.domain + '.' + extracted.suffix if extracted.suffix else extracted.domain,
            subdomain=extracted.subdomain,
            path=parsed.path,
            query_params=parse_qs(parsed.query, keep_blank_values=True),
            fragment=parsed.fragment
        )
        
        # Analyze suspicion
        analysis.is_suspicious, analysis.suspicion_reasons = self._analyze_suspicion(analysis)
        
        # Analyze redirect indicators
        analysis.redirect_indicators = self._find_redirect_indicators(analysis)
        
        # Calculate risk score
        analysis.risk_score = self._calculate_risk_score(analysis)
        
        # Determine URL type
        analysis.url_type = self._determine_url_type(analysis)
        
        return analysis
    
    def _analyze_suspicion(self, analysis: URLAnalysis) -> Tuple[bool, List[str]]:
        """Analyze URL for suspicious patterns"""
        reasons = []
        
        # Check path for suspicious patterns
        for pattern in self.suspicious_patterns:
            if re.search(pattern, analysis.path, re.IGNORECASE):
                reasons.append(f"Suspicious path pattern: {pattern}")
        
        # Check for high-risk paths
        for pattern in self.high_risk_paths:
            if re.search(pattern, analysis.path, re.IGNORECASE):
                reasons.append(f"High-risk path: {pattern}")
        
        # Check query parameters
        for param_name in analysis.query_params.keys():
            for pattern in self.redirect_param_patterns:
                if re.search(pattern, param_name, re.IGNORECASE):
                    reasons.append(f"Redirect parameter: {param_name}")
        
        # Check for encoding in URL
        for pattern in self.encoding_patterns:
            if re.search(pattern, analysis.url):
                reasons.append(f"Encoded content detected: {pattern}")
        
        # Check for Web3 patterns
        for pattern in self.web3_patterns:
            if re.search(pattern, analysis.url, re.IGNORECASE):
                reasons.append(f"Web3 pattern detected: {pattern}")
        
        # Check subdomain
        if analysis.subdomain:
            suspicious_subdomains = ['admin', 'api', 'auth', 'login', 'panel', 'dashboard', 'wallet', 'pay']
            if analysis.subdomain.lower() in suspicious_subdomains:
                reasons.append(f"Suspicious subdomain: {analysis.subdomain}")
        
        # Check for multiple redirects in path
        redirect_count = len(re.findall(r'redirect|forward|goto', analysis.path, re.IGNORECASE))
        if redirect_count > 1:
            reasons.append(f"Multiple redirect indicators in path: {redirect_count}")
        
        return len(reasons) > 0, reasons
    
    def _find_redirect_indicators(self, analysis: URLAnalysis) -> List[str]:
        """Find redirect indicators in URL"""
        indicators = []
        
        # Check path
        path_redirects = re.findall(r'(redirect|forward|goto|next|return)', analysis.path, re.IGNORECASE)
        indicators.extend([f"path:{indicator}" for indicator in path_redirects])
        
        # Check query parameters
        for param_name, param_values in analysis.query_params.items():
            # Parameter name indicates redirect
            for pattern in self.redirect_param_patterns:
                if re.search(pattern, param_name, re.IGNORECASE):
                    indicators.append(f"param_name:{param_name}")
            
            # Parameter value indicates redirect
            for value in param_values:
                if self._is_redirect_value(value):
                    indicators.append(f"param_value:{param_name}={value}")
        
        # Check fragment
        if analysis.fragment:
            if any(re.search(pattern, analysis.fragment, re.IGNORECASE) for pattern in self.redirect_param_patterns):
                indicators.append(f"fragment:{analysis.fragment}")
        
        return list(set(indicators))  # Remove duplicates
    
    def _is_redirect_value(self, value: str) -> bool:
        """Check if parameter value indicates a redirect"""
        if not value:
            return False
        
        value_lower = value.lower()
        
        # URL patterns
        if re.match(r'https?://', value_lower):
            return True
        if re.match(r'//', value_lower):
            return True
        if re.match(r'[a-z0-9.-]+\.[a-z]{2,}', value_lower):
            return True
        
        # JavaScript patterns
        if value_lower.startswith('javascript:'):
            return True
        
        # Data URL patterns
        if value_lower.startswith('data:'):
            return True
        
        return False
    
    def _calculate_risk_score(self, analysis: URLAnalysis) -> float:
        """Calculate risk score (0.0 - 1.0)"""
        score = 0.0
        
        # Base score for having query parameters
        if analysis.query_params:
            score += 0.1
        
        # Score for suspicious patterns
        score += len(analysis.suspicion_reasons) * 0.1
        
        # Score for redirect indicators
        score += len(analysis.redirect_indicators) * 0.15
        
        # High-risk paths get higher scores
        for pattern in self.high_risk_paths:
            if re.search(pattern, analysis.path, re.IGNORECASE):
                score += 0.2
                break
        
        # Admin/API paths
        if re.search(r'/(admin|api|auth)/', analysis.path, re.IGNORECASE):
            score += 0.3
        
        # Multiple parameters increase risk
        param_count = len(analysis.query_params)
        if param_count > 5:
            score += 0.1
        elif param_count > 10:
            score += 0.2
        
        # Encoding increases risk
        if any(re.search(pattern, analysis.url) for pattern in self.encoding_patterns):
            score += 0.15
        
        # Web3 patterns
        if any(re.search(pattern, analysis.url, re.IGNORECASE) for pattern in self.web3_patterns):
            score += 0.1
        
        return min(score, 1.0)
    
    def _determine_url_type(self, analysis: URLAnalysis) -> str:
        """Determine URL type"""
        path_lower = analysis.path.lower()
        
        # API endpoints
        if re.search(r'/(api|rest|graphql)/', path_lower):
            return "api"
        
        # Admin panels
        if re.search(r'/(admin|panel|dashboard|control|manage)/', path_lower):
            return "admin"
        
        # Authentication
        if re.search(r'/(auth|login|logout|signin|signout|sso)/', path_lower):
            return "auth"
        
        # Payment
        if re.search(r'/(pay|payment|checkout|billing|invoice)/', path_lower):
            return "payment"
        
        # Web3/DeFi
        if re.search(r'/(web3|defi|nft|wallet|metamask|uniswap|opensea)/', path_lower):
            return "web3"
        
        # Check subdomain
        if analysis.subdomain:
            subdomain_lower = analysis.subdomain.lower()
            if subdomain_lower in ['api', 'rest']:
                return "api"
            elif subdomain_lower in ['admin', 'panel', 'dashboard']:
                return "admin"
            elif subdomain_lower in ['auth', 'login', 'sso']:
                return "auth"
            elif subdomain_lower in ['pay', 'payment', 'checkout']:
                return "payment"
            elif subdomain_lower in ['wallet', 'defi', 'web3']:
                return "web3"
        
        return "normal"
    
    def batch_analyze_urls(self, urls: List[str]) -> List[URLAnalysis]:
        """Analyze multiple URLs"""
        analyses = []
        
        for url in urls:
            try:
                analysis = self.analyze_url(url)
                analyses.append(analysis)
            except Exception as e:
                print(f"[URL-ANALYZER] Error analyzing {url}: {e}")
        
        return analyses
    
    def get_high_risk_urls(self, analyses: List[URLAnalysis], threshold: float = 0.5) -> List[URLAnalysis]:
        """Get high-risk URLs"""
        return [analysis for analysis in analyses if analysis.risk_score >= threshold]
    
    def get_redirect_urls(self, analyses: List[URLAnalysis]) -> List[URLAnalysis]:
        """Get URLs with redirect indicators"""
        return [analysis for analysis in analyses if analysis.redirect_indicators]
    
    def get_urls_by_type(self, analyses: List[URLAnalysis], url_type: str) -> List[URLAnalysis]:
        """Get URLs by type"""
        return [analysis for analysis in analyses if analysis.url_type == url_type]
    
    def generate_url_report(self, analyses: List[URLAnalysis]) -> Dict:
        """Generate comprehensive URL analysis report"""
        if not analyses:
            return {}
        
        total_urls = len(analyses)
        suspicious_urls = [a for a in analyses if a.is_suspicious]
        high_risk_urls = [a for a in analyses if a.risk_score >= 0.5]
        redirect_urls = [a for a in analyses if a.redirect_indicators]
        
        # Group by type
        type_distribution = {}
        for analysis in analyses:
            type_distribution[analysis.url_type] = type_distribution.get(analysis.url_type, 0) + 1
        
        # Risk distribution
        risk_ranges = {'low': 0, 'medium': 0, 'high': 0, 'critical': 0}
        for analysis in analyses:
            if analysis.risk_score < 0.3:
                risk_ranges['low'] += 1
            elif analysis.risk_score < 0.6:
                risk_ranges['medium'] += 1
            elif analysis.risk_score < 0.8:
                risk_ranges['high'] += 1
            else:
                risk_ranges['critical'] += 1
        
        # Top suspicion reasons
        all_reasons = []
        for analysis in analyses:
            all_reasons.extend(analysis.suspicion_reasons)
        
        reason_counts = {}
        for reason in all_reasons:
            reason_counts[reason] = reason_counts.get(reason, 0) + 1
        
        top_reasons = sorted(reason_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        
        return {
            'summary': {
                'total_urls': total_urls,
                'suspicious_urls': len(suspicious_urls),
                'high_risk_urls': len(high_risk_urls),
                'redirect_urls': len(redirect_urls),
                'average_risk_score': sum(a.risk_score for a in analyses) / total_urls
            },
            'type_distribution': type_distribution,
            'risk_distribution': risk_ranges,
            'top_suspicion_reasons': top_reasons,
            'high_risk_details': [
                {
                    'url': a.url,
                    'risk_score': a.risk_score,
                    'type': a.url_type,
                    'reasons': a.suspicion_reasons,
                    'redirect_indicators': a.redirect_indicators
                }
                for a in high_risk_urls
            ]
        }
    
    def extract_potential_targets(self, analyses: List[URLAnalysis]) -> List[str]:
        """Extract URLs that are likely to have redirect vulnerabilities"""
        targets = []
        
        for analysis in analyses:
            # High priority: URLs with redirect parameters
            if analysis.redirect_indicators:
                targets.append(analysis.url)
            
            # Medium priority: High-risk URLs
            elif analysis.risk_score >= 0.5:
                targets.append(analysis.url)
            
            # Low priority: URLs with query parameters
            elif analysis.query_params:
                targets.append(analysis.url)
        
        return list(set(targets))  # Remove duplicates
    
    def suggest_test_parameters(self, analysis: URLAnalysis) -> List[str]:
        """Suggest parameters to test based on URL analysis"""
        suggestions = []
        
        # Existing parameters that might be redirect-related
        for param_name in analysis.query_params.keys():
            if any(re.search(pattern, param_name, re.IGNORECASE) for pattern in self.redirect_param_patterns):
                suggestions.append(param_name)
        
        # Common redirect parameters to try
        common_redirect_params = [
            'redirect', 'url', 'next', 'return', 'goto', 'target',
            'callback', 'success_url', 'returnUrl', 'redirectUrl'
        ]
        
        # Add common parameters that aren't already present
        for param in common_redirect_params:
            if param not in analysis.query_params and param not in suggestions:
                suggestions.append(param)
        
        # Context-specific suggestions based on URL type
        if analysis.url_type == 'auth':
            suggestions.extend(['login_redirect', 'logout_url', 'success_url'])
        elif analysis.url_type == 'payment':
            suggestions.extend(['success_url', 'cancel_url', 'failure_url'])
        elif analysis.url_type == 'web3':
            suggestions.extend(['wallet_redirect', 'connect_callback', 'swap_redirect'])
        
        return list(set(suggestions))[:10]  # Limit to 10 suggestions