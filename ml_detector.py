#!/usr/bin/env python3
"""
🔥 ML-BASED PARAMETER DETECTOR
"""

import re
from typing import List, Dict, Tuple
from data_models import Parameter


class MLParameterDetector:
    """Machine Learning-inspired parameter detection"""
    
    def __init__(self):
        # Feature weights (trained on bug bounty data)
        self.feature_weights = {
            'name_redirect_keyword': 0.4,
            'name_length': 0.1,
            'value_url_pattern': 0.3,
            'context_importance': 0.2,
            'source_reliability': 0.15,
            'pattern_complexity': 0.1
        }
        
        # Redirect keyword scoring
        self.redirect_keywords = {
            'redirect': 0.9,
            'url': 0.8,
            'next': 0.7,
            'return': 0.7,
            'goto': 0.6,
            'target': 0.6,
            'destination': 0.8,
            'continue': 0.5,
            'forward': 0.6,
            'redir': 0.8,
            'location': 0.9,
            'site': 0.4,
            'link': 0.5,
            'href': 0.8,
            'callback': 0.7,
            'success_url': 0.9,
            'failure_url': 0.9,
            'cancel_url': 0.8,
            'exit_url': 0.7,
            'logout_url': 0.6,
            'login_redirect': 0.8
        }
        
        # Context scoring
        self.context_scores = {
            'query': 0.8,
            'fragment': 0.9,
            'form_input': 0.6,
            'javascript': 0.7,
            'web3_config': 0.95,
            'http_header': 0.85,
            'meta_refresh': 0.9,
            'html_data': 0.7
        }
        
        # Source reliability
        self.source_scores = {
            'url_query': 0.8,
            'url_fragment': 0.9,
            'form': 0.6,
            'javascript': 0.7,
            'web3': 0.9,
            'http_header': 0.85,
            'meta_tag': 0.75,
            'data_attribute': 0.7,
            'config': 0.8,
            'dom_analysis': 0.85,
            'advanced_analysis': 0.6
        }
    
    def analyze_parameter_ml(self, param: Parameter, page_content: str = "") -> Dict[str, any]:
        """ML-inspired parameter analysis"""
        features = self.extract_features(param, page_content)
        confidence_score = self.calculate_ml_confidence(features)
        risk_assessment = self.assess_risk_level(features, confidence_score)
        
        return {
            'ml_confidence': confidence_score,
            'risk_level': risk_assessment['level'],
            'risk_score': risk_assessment['score'],
            'features': features,
            'recommendations': self.get_testing_recommendations(features, confidence_score),
            'priority': self.calculate_priority(features, confidence_score)
        }
    
    def extract_features(self, param: Parameter, page_content: str) -> Dict[str, float]:
        """Extract ML features from parameter"""
        features = {}
        
        # Feature 1: Name-based redirect keyword scoring
        name_score = 0.0
        for keyword, weight in self.redirect_keywords.items():
            if keyword in param.name.lower():
                name_score = max(name_score, weight)
        features['name_redirect_keyword'] = name_score
        
        # Feature 2: Name length normalization
        name_length = len(param.name)
        features['name_length'] = min(name_length / 20.0, 1.0)  # Normalize to 0-1
        
        # Feature 3: Value URL pattern detection
        value_score = 0.0
        if param.value:
            if param.value.startswith(('http://', 'https://')):
                value_score = 0.9
            elif param.value.startswith('//'):
                value_score = 0.8
            elif re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', param.value):
                value_score = 0.7
            elif '/' in param.value:
                value_score = 0.4
        features['value_url_pattern'] = value_score
        
        # Feature 4: Context importance
        features['context_importance'] = self.context_scores.get(param.context, 0.5)
        
        # Feature 5: Source reliability
        features['source_reliability'] = self.source_scores.get(param.source, 0.5)
        
        # Feature 6: Pattern complexity
        pattern_score = 0.0
        if hasattr(param, 'pattern_matched') and param.pattern_matched:
            if 'advanced:' in param.pattern_matched:
                pattern_score = 0.8
            elif 'config:' in param.pattern_matched:
                pattern_score = 0.7
            elif 'form:' in param.pattern_matched:
                pattern_score = 0.6
            else:
                pattern_score = 0.5
        features['pattern_complexity'] = pattern_score
        
        return features
    
    def calculate_ml_confidence(self, features: Dict[str, float]) -> float:
        """Calculate ML-based confidence score"""
        weighted_score = 0.0
        
        for feature_name, feature_value in features.items():
            weight = self.feature_weights.get(feature_name, 0.1)
            weighted_score += feature_value * weight
        
        # Apply sigmoid-like function for normalization
        normalized_score = 2 / (1 + pow(2.718, -5 * weighted_score)) - 1
        
        return max(0.0, min(1.0, normalized_score))
    
    def assess_risk_level(self, features: Dict[str, float], confidence: float) -> Dict[str, any]:
        """Assess risk level using ML features"""
        risk_score = 0.0
        
        # High-risk indicators
        if features.get('name_redirect_keyword', 0) > 0.7:
            risk_score += 0.3
        
        if features.get('value_url_pattern', 0) > 0.6:
            risk_score += 0.25
        
        if features.get('context_importance', 0) > 0.8:
            risk_score += 0.2
        
        if features.get('source_reliability', 0) > 0.8:
            risk_score += 0.15
        
        # Determine risk level
        if risk_score > 0.7 and confidence > 0.8:
            level = 'CRITICAL'
        elif risk_score > 0.5 and confidence > 0.6:
            level = 'HIGH'
        elif risk_score > 0.3 and confidence > 0.4:
            level = 'MEDIUM'
        else:
            level = 'LOW'
        
        return {
            'level': level,
            'score': risk_score,
            'confidence': confidence
        }
    
    def get_testing_recommendations(self, features: Dict[str, float], confidence: float) -> List[str]:
        """Get ML-based testing recommendations"""
        recommendations = []
        
        if confidence > 0.8:
            recommendations.append("HIGH PRIORITY: Test with all payload variations")
            recommendations.append("Recommended: Use context-specific payloads")
        
        if features.get('context_importance', 0) > 0.8:
            recommendations.append("Test with encoding bypass techniques")
        
        if features.get('value_url_pattern', 0) > 0.7:
            recommendations.append("Focus on URL manipulation payloads")
        
        if features.get('source_reliability', 0) > 0.8:
            recommendations.append("High-confidence source - prioritize testing")
        
        if not recommendations:
            recommendations.append("Standard testing protocol recommended")
        
        return recommendations
    
    def calculate_priority(self, features: Dict[str, float], confidence: float) -> int:
        """Calculate testing priority (1-10)"""
        priority_score = 0.0
        
        # Weight the features for priority calculation
        priority_score += features.get('name_redirect_keyword', 0) * 3
        priority_score += features.get('value_url_pattern', 0) * 2.5
        priority_score += features.get('context_importance', 0) * 2
        priority_score += confidence * 2.5
        
        # Convert to 1-10 scale
        priority = int(min(max(priority_score * 2, 1), 10))
        
        return priority
    
    def batch_analyze_parameters(self, parameters: List[Parameter], page_content: str = "") -> List[Dict]:
        """Batch analyze parameters with ML"""
        analyzed_params = []
        
        for param in parameters:
            analysis = self.analyze_parameter_ml(param, page_content)
            analysis['parameter'] = param
            analyzed_params.append(analysis)
        
        # Sort by priority
        analyzed_params.sort(key=lambda x: x['priority'], reverse=True)
        
        return analyzed_params
    
    def generate_ml_report(self, analyzed_params: List[Dict]) -> Dict:
        """Generate ML analysis report"""
        if not analyzed_params:
            return {'total_analyzed': 0}
        
        # Calculate statistics
        confidence_scores = [p['ml_confidence'] for p in analyzed_params]
        risk_levels = [p['risk_level'] for p in analyzed_params]
        priorities = [p['priority'] for p in analyzed_params]
        
        avg_confidence = sum(confidence_scores) / len(confidence_scores)
        
        risk_distribution = {}
        for level in risk_levels:
            risk_distribution[level] = risk_distribution.get(level, 0) + 1
        
        return {
            'total_analyzed': len(analyzed_params),
            'average_confidence': round(avg_confidence, 3),
            'highest_priority': max(priorities) if priorities else 0,
            'risk_distribution': risk_distribution,
            'high_confidence_count': len([p for p in analyzed_params if p['ml_confidence'] > 0.7]),
            'critical_risk_count': len([p for p in analyzed_params if p['risk_level'] == 'CRITICAL']),
            'recommended_testing_order': [p['parameter'].name for p in analyzed_params[:10]]
        }