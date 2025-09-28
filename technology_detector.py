#!/usr/bin/env python3
"""
Technology Detection Module
Detects website technology and determines scanning strategy
Author: AI Assistant
Version: 1.0
"""

import requests
import re
from bs4 import BeautifulSoup
from urllib.parse import urlparse

class TechnologyDetector:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def detect_technology(self, url):
        """Detect website technology and return scanning strategy"""
        try:
            response = self.session.get(url, timeout=10)
            response.raise_for_status()
            
            html_content = response.text
            soup = BeautifulSoup(html_content, 'html.parser')
            
            # Detect technology stack
            detection_result = {
                'url': url,
                'type': 'traditional',
                'framework': None,
                'features': [],
                'scanning_strategy': 'traditional',
                'confidence': 0
            }
            
            # Check for modern frameworks
            framework_score = self._detect_frameworks(html_content, soup)
            spa_score = self._detect_spa_features(html_content, soup)
            modern_score = self._detect_modern_features(html_content, soup)
            
            total_score = framework_score + spa_score + modern_score
            detection_result['confidence'] = total_score
            
            # Determine website type
            if total_score >= 70:
                detection_result['type'] = 'modern_spa'
                detection_result['scanning_strategy'] = 'modern_spa'
            elif total_score >= 40:
                detection_result['type'] = 'hybrid'
                detection_result['scanning_strategy'] = 'hybrid'
            else:
                detection_result['type'] = 'traditional'
                detection_result['scanning_strategy'] = 'traditional'
            
            return detection_result
            
        except Exception as e:
            return {
                'url': url,
                'type': 'traditional',
                'framework': None,
                'features': [],
                'scanning_strategy': 'traditional',
                'confidence': 0,
                'error': str(e)
            }
    
    def _detect_frameworks(self, html_content, soup):
        """Detect JavaScript frameworks"""
        score = 0
        
        # React detection
        react_indicators = [
            'data-reactroot', 'react', 'ReactDOM', '__REACT_DEVTOOLS_GLOBAL_HOOK__',
            'webpackJsonp', 'react-dom', 'react-router'
        ]
        
        for indicator in react_indicators:
            if indicator in html_content:
                score += 20
                break
        
        # Vue.js detection
        vue_indicators = [
            'vue', 'Vue.js', 'vue-router', 'vuex', 'v-if', 'v-for', 'v-model',
            '__VUE__', 'vue-loader'
        ]
        
        for indicator in vue_indicators:
            if indicator in html_content:
                score += 20
                break
        
        # Angular detection
        angular_indicators = [
            'angular', 'ng-app', 'ng-controller', 'ng-model', 'ng-repeat',
            'angular.module', '@angular', 'zone.js'
        ]
        
        for indicator in angular_indicators:
            if indicator in html_content:
                score += 20
                break
        
        # jQuery detection
        if 'jquery' in html_content.lower() or '$(' in html_content:
            score += 10
        
        return min(score, 50)  # Cap at 50 points
    
    def _detect_spa_features(self, html_content, soup):
        """Detect SPA features"""
        score = 0
        
        # SPA indicators
        spa_indicators = [
            'history.pushState', 'history.replaceState', 'window.location.hash',
            'router', 'route', 'navigate', 'history-api',
            'fetch(', 'axios', 'XMLHttpRequest'
        ]
        
        for indicator in spa_indicators:
            if indicator in html_content:
                score += 5
        
        # Single page app structure
        if len(soup.find_all('div', {'id': 'app'})) > 0:
            score += 15
        
        if len(soup.find_all('div', {'id': 'root'})) > 0:
            score += 15
        
        # Dynamic content loading
        dynamic_patterns = [
            r'innerHTML\s*=',
            r'appendChild\s*\(',
            r'insertAdjacentHTML\s*\(',
            r'document\.write\s*\('
        ]
        
        for pattern in dynamic_patterns:
            if re.search(pattern, html_content, re.IGNORECASE):
                score += 10
        
        return min(score, 30)  # Cap at 30 points
    
    def _detect_modern_features(self, html_content, soup):
        """Detect modern web features"""
        score = 0
        
        # Modern JavaScript features
        modern_js = [
            'const ', 'let ', 'arrow function', '=>', 'async ', 'await ',
            'Promise', 'class ', 'import ', 'export ', 'modules'
        ]
        
        for feature in modern_js:
            if feature in html_content:
                score += 3
        
        # API endpoints
        api_patterns = [
            r'/api/[^"\']+',
            r'/v\d+/[^"\']+',
            r'/graphql',
            r'/rest/[^"\']+'
        ]
        
        for pattern in api_patterns:
            if re.search(pattern, html_content, re.IGNORECASE):
                score += 10
                break
        
        # WebSocket usage
        if 'WebSocket' in html_content or 'ws://' in html_content or 'wss://' in html_content:
            score += 10
        
        # Service Workers
        if 'serviceWorker' in html_content or 'sw.js' in html_content:
            score += 10
        
        return min(score, 20)  # Cap at 20 points