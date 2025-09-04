#!/usr/bin/env python3
"""
🔥 JAVASCRIPT EXTRACTOR - Advanced JS Parameter Extraction
"""

import re
import json
import ast
from typing import List, Dict, Set, Optional, Tuple
from urllib.parse import urljoin, urlparse
from dataclasses import dataclass, field

try:
    from bs4 import BeautifulSoup
    BS4_OK = True
except ImportError:
    BS4_OK = False


@dataclass
class JSParameter:
    """JavaScript parameter information"""
    name: str
    value: str
    source: str  # inline, external, event_handler, config
    context: str  # variable, function_param, object_property, etc.
    url: str
    line_number: Optional[int] = None
    column_number: Optional[int] = None
    confidence: float = 0.0
    is_redirect_related: bool = False
    extraction_method: str = ""
    pattern_matched: str = ""
    code_snippet: str = ""
    additional_info: Dict = field(default_factory=dict)


@dataclass
class JSAnalysis:
    """JavaScript analysis result"""
    url: str
    script_url: Optional[str] = None
    script_type: str = "inline"  # inline, external, event_handler
    parameters: List[JSParameter] = field(default_factory=list)
    functions_found: List[str] = field(default_factory=list)
    dom_sinks: List[str] = field(default_factory=list)
    sources: List[str] = field(default_factory=list)
    is_suspicious: bool = False
    suspicion_reasons: List[str] = field(default_factory=list)
    lines_analyzed: int = 0
    
    @property
    def redirect_parameters(self) -> List[JSParameter]:
        """Get redirect-related parameters"""
        return [p for p in self.parameters if p.is_redirect_related]
    
    @property
    def high_confidence_parameters(self) -> List[JSParameter]:
        """Get high-confidence parameters"""
        return [p for p in self.parameters if p.confidence > 0.7]


class JSExtractor:
    """Advanced JavaScript parameter extractor"""
    
    def __init__(self):
        # DOM redirect sinks
        self.dom_sinks = [
            'location.href', 'location.assign', 'location.replace',
            'window.location', 'window.location.href', 'window.open',
            'document.location', 'document.location.href',
            'history.pushState', 'history.replaceState',
            'window.navigate', 'document.URL'
        ]
        
        # DOM sources (user-controlled input)
        self.dom_sources = [
            'location.search', 'location.hash', 'location.href',
            'document.URL', 'document.documentURI', 'document.baseURI',
            'window.name', 'document.referrer', 'history.state',
            'URLSearchParams', 'localStorage.getItem', 'sessionStorage.getItem'
        ]
        
        # JavaScript extraction patterns
        self.js_patterns = [
            # Variable declarations with redirect-related values
            r'(?:var|let|const)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*["\']([^"\']*(?:redirect|url|next|return|goto|callback)[^"\']*)["\']',
            
            # Object properties
            r'["\']?([a-zA-Z_][a-zA-Z0-9_]*(?:url|redirect|next|return|goto|callback)[a-zA-Z0-9_]*)["\']?\s*:\s*["\']([^"\']+)["\']',
            
            # Function parameters
            r'function\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\([^)]*([a-zA-Z_$][a-zA-Z0-9_$]*(?:Url|Redirect|Next|Return|Goto|Callback)[a-zA-Z0-9_$]*)[^)]*\)',
            
            # URLSearchParams usage
            r'(?:new\s+)?URLSearchParams[^)]*\.get\(["\']([^"\']+)["\']',
            r'searchParams\.get\(["\']([^"\']+)["\']',
            r'getParameter\(["\']([^"\']+)["\']',
            
            # Location manipulation
            r'(location\.(?:href|search|hash))\s*=\s*([^;]+)',
            r'(window\.location)\s*=\s*([^;]+)',
            r'(location\.assign|location\.replace)\s*\(\s*([^)]+)\s*\)',
            r'(window\.open)\s*\(\s*([^,)]+)',
            
            # Storage access
            r'(?:localStorage|sessionStorage)\.(?:getItem|setItem)\(["\']([^"\']*(?:redirect|url|next|return)[^"\']*)["\']',
            
            # Cookie manipulation
            r'document\.cookie\s*=\s*["\']([^"\']*(?:redirect|url|next|return)[^"\']*)["\']',
            
            # AJAX/Fetch parameters
            r'(?:fetch|ajax|post|get|request)\s*\([^)]*["\']([^"\']*(?:redirect|url|next|return|callback)[^"\']*)["\']',
            
            # Configuration objects
            r'(?:config|settings|options|params)\s*[:\[=]\s*\{[^}]*["\']([^"\']*(?:redirect|url|next|return)[^"\']*)["\']?\s*:\s*["\']([^"\']+)["\']',
            
            # Event handlers
            r'(?:onclick|onload|onsubmit)\s*=\s*["\']([^"\']*(?:location|redirect)[^"\']*)["\']',
            
            # React/Vue component props
            r'(?:props|this\.props)\.([a-zA-Z_][a-zA-Z0-9_]*(?:url|redirect|next|return)[a-zA-Z0-9_]*)',
            
            # Angular/Vue data binding
            r'\{\{([^}]*(?:redirect|url|next|return)[^}]*)\}\}',
            
            # Template literals
            r'`([^`]*(?:redirect|url|next|return)[^`]*)`',
            
            # Regular expressions for URL patterns
            r'new\s+RegExp\(["\']([^"\']*(?:redirect|url)[^"\']*)["\']',
            
            # Form action manipulation
            r'(?:form|element)\.action\s*=\s*([^;]+)',
            
            # Dynamic script loading
            r'(?:script\.src|loadScript)\s*=\s*([^;]+)'
        ]
        
        # Suspicious function patterns
        self.suspicious_functions = [
            'eval', 'setTimeout', 'setInterval', 'Function',
            'execScript', 'msWriteProfilerMark'
        ]
        
        # Framework-specific patterns
        self.framework_patterns = {
            'react': [
                r'React\.createElement',
                r'useState\s*\(',
                r'useEffect\s*\(',
                r'props\.([a-zA-Z_][a-zA-Z0-9_]*(?:url|redirect)[a-zA-Z0-9_]*)'
            ],
            'vue': [
                r'Vue\.component',
                r'this\.\$router',
                r'this\.\$route',
                r'v-model=["\']([^"\']*(?:redirect|url)[^"\']*)["\']'
            ],
            'angular': [
                r'\$scope\.',
                r'\$location\.',
                r'\$routeParams\.',
                r'ng-model=["\']([^"\']*(?:redirect|url)[^"\']*)["\']'
            ],
            'jquery': [
                r'\$\s*\(',
                r'jQuery\s*\(',
                r'\.ajax\s*\(',
                r'\.get\s*\(',
                r'\.post\s*\('
            ]
        }
    
    async def analyze_javascript(self, content: str, base_url: str, session=None) -> List[JSAnalysis]:
        """Analyze JavaScript in HTML content"""
        analyses = []
        
        # Extract and analyze inline scripts
        inline_scripts = self._extract_inline_scripts(content)
        for i, script_content in enumerate(inline_scripts):
            analysis = self._analyze_js_content(
                script_content, base_url, f"inline_script_{i}", "inline"
            )
            analyses.append(analysis)
        
        # Extract and analyze external scripts
        external_scripts = self._extract_external_scripts(content, base_url)
        for script_url in external_scripts:
            if session:
                script_content = await self._fetch_external_script(script_url, session)
                if script_content:
                    analysis = self._analyze_js_content(
                        script_content, base_url, script_url, "external"
                    )
                    analyses.append(analysis)
        
        # Extract and analyze event handlers
        event_handlers = self._extract_event_handlers(content)
        for i, handler_content in enumerate(event_handlers):
            analysis = self._analyze_js_content(
                handler_content, base_url, f"event_handler_{i}", "event_handler"
            )
            analyses.append(analysis)
        
        print(f"[JS-EXTRACTOR] Analyzed {len(analyses)} JavaScript sources")
        return analyses
    
    def _extract_inline_scripts(self, content: str) -> List[str]:
        """Extract inline script content"""
        scripts = []
        
        if BS4_OK:
            soup = BeautifulSoup(content, 'html.parser')
            for script in soup.find_all('script'):
                if script.string and not script.get('src'):
                    scripts.append(script.string)
        else:
            # Regex fallback
            pattern = r'<script[^>]*>(.*?)</script>'
            matches = re.findall(pattern, content, re.DOTALL | re.IGNORECASE)
            scripts.extend(matches)
        
        return scripts
    
    def _extract_external_scripts(self, content: str, base_url: str) -> List[str]:
        """Extract external script URLs"""
        scripts = []
        
        if BS4_OK:
            soup = BeautifulSoup(content, 'html.parser')
            for script in soup.find_all('script', src=True):
                src = script['src']
                full_url = urljoin(base_url, src)
                scripts.append(full_url)
        else:
            # Regex fallback
            pattern = r'<script[^>]*src=["\']([^"\']+)["\']'
            matches = re.findall(pattern, content, re.IGNORECASE)
            for src in matches:
                full_url = urljoin(base_url, src)
                scripts.append(full_url)
        
        return scripts
    
    def _extract_event_handlers(self, content: str) -> List[str]:
        """Extract event handler content"""
        handlers = []
        
        # Event handler attributes
        event_pattern = r'on\w+\s*=\s*["\']([^"\']+)["\']'
        matches = re.findall(event_pattern, content, re.IGNORECASE)
        handlers.extend(matches)
        
        # JavaScript URLs
        js_url_pattern = r'href\s*=\s*["\']javascript:([^"\']+)["\']'
        js_matches = re.findall(js_url_pattern, content, re.IGNORECASE)
        handlers.extend(js_matches)
        
        return handlers
    
    async def _fetch_external_script(self, script_url: str, session) -> Optional[str]:
        """Fetch external script content"""
        try:
            async with session.get(script_url) as response:
                if response.status == 200:
                    return await response.text()
        except:
            pass
        return None
    
    def _analyze_js_content(self, content: str, base_url: str, source_id: str, script_type: str) -> JSAnalysis:
        """Analyze JavaScript content for parameters"""
        analysis = JSAnalysis(
            url=base_url,
            script_url=source_id if script_type == "external" else None,
            script_type=script_type
        )
        
        lines = content.split('\n')
        analysis.lines_analyzed = len(lines)
        
        # Extract parameters using patterns
        for line_num, line in enumerate(lines, 1):
            line_params = self._extract_parameters_from_line(
                line, base_url, source_id, script_type, line_num
            )
            analysis.parameters.extend(line_params)
        
        # Detect DOM sinks and sources
        analysis.dom_sinks = self._find_dom_sinks(content)
        analysis.sources = self._find_dom_sources(content)
        
        # Extract function names
        analysis.functions_found = self._extract_function_names(content)
        
        # Analyze suspicion
        analysis.is_suspicious, analysis.suspicion_reasons = self._analyze_suspicion(content, analysis)
        
        # Calculate confidence for all parameters
        for param in analysis.parameters:
            param.confidence = self._calculate_parameter_confidence(param, analysis)
            param.is_redirect_related = self._is_redirect_related(param.name, param.value)
        
        return analysis
    
    def _extract_parameters_from_line(self, line: str, base_url: str, source_id: str, 
                                    script_type: str, line_num: int) -> List[JSParameter]:
        """Extract parameters from a single line of JavaScript"""
        parameters = []
        line_stripped = line.strip()
        
        if not line_stripped or line_stripped.startswith('//'):
            return parameters
        
        for pattern in self.js_patterns:
            matches = re.finditer(pattern, line, re.IGNORECASE)
            
            for match in matches:
                groups = match.groups()
                if not groups:
                    continue
                
                # Determine parameter name and value
                if len(groups) >= 2:
                    name = groups[0].strip('"\'')
                    value = groups[1].strip('"\'')
                elif len(groups) == 1:
                    # Single group - could be name or value depending on pattern
                    group_value = groups[0].strip('"\'')
                    if any(sink in pattern for sink in ['location', 'URLSearchParams']):
                        name = 'js_extracted_param'
                        value = group_value
                    else:
                        name = group_value
                        value = ""
                else:
                    continue
                
                # Determine context
                context = self._determine_context(pattern, line)
                
                # Create parameter
                param = JSParameter(
                    name=name,
                    value=value,
                    source=script_type,
                    context=context,
                    url=base_url,
                    line_number=line_num,
                    extraction_method="regex",
                    pattern_matched=pattern[:50] + "...",
                    code_snippet=line_stripped[:100] + "..." if len(line_stripped) > 100 else line_stripped,
                    additional_info={
                        'source_id': source_id,
                        'match_start': match.start(),
                        'match_end': match.end()
                    }
                )
                
                parameters.append(param)
        
        return parameters
    
    def _determine_context(self, pattern: str, line: str) -> str:
        """Determine parameter context from pattern and line"""
        line_lower = line.lower()
        
        if 'location' in pattern:
            return 'location_manipulation'
        elif 'URLSearchParams' in pattern:
            return 'url_params'
        elif 'function' in pattern:
            return 'function_parameter'
        elif 'config' in pattern or 'settings' in pattern:
            return 'configuration'
        elif 'localStorage' in pattern or 'sessionStorage' in pattern:
            return 'storage'
        elif 'cookie' in pattern:
            return 'cookie'
        elif 'ajax' in pattern or 'fetch' in pattern:
            return 'ajax_request'
        elif 'onclick' in pattern or 'onload' in pattern:
            return 'event_handler'
        elif 'var' in pattern or 'let' in pattern or 'const' in pattern:
            return 'variable_declaration'
        elif ':' in line and '{' in line:
            return 'object_property'
        else:
            return 'unknown'
    
    def _find_dom_sinks(self, content: str) -> List[str]:
        """Find DOM redirect sinks in JavaScript"""
        sinks_found = []
        
        for sink in self.dom_sinks:
            if sink in content:
                sinks_found.append(sink)
        
        return sinks_found
    
    def _find_dom_sources(self, content: str) -> List[str]:
        """Find DOM sources in JavaScript"""
        sources_found = []
        
        for source in self.dom_sources:
            if source in content:
                sources_found.append(source)
        
        return sources_found
    
    def _extract_function_names(self, content: str) -> List[str]:
        """Extract function names from JavaScript"""
        functions = []
        
        # Function declarations
        func_pattern = r'function\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\('
        matches = re.findall(func_pattern, content)
        functions.extend(matches)
        
        # Arrow functions assigned to variables
        arrow_pattern = r'(?:var|let|const)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*\([^)]*\)\s*=>'
        arrow_matches = re.findall(arrow_pattern, content)
        functions.extend(arrow_matches)
        
        return list(set(functions))  # Remove duplicates
    
    def _analyze_suspicion(self, content: str, analysis: JSAnalysis) -> Tuple[bool, List[str]]:
        """Analyze JavaScript for suspicious patterns"""
        reasons = []
        
        # Check for suspicious functions
        for func in self.suspicious_functions:
            if func in content:
                reasons.append(f"Uses suspicious function: {func}")
        
        # Check for DOM manipulation with user input
        if analysis.dom_sinks and analysis.sources:
            reasons.append("Contains both DOM sinks and user-controlled sources")
        
        # Check for dynamic script loading
        if re.search(r'createElement\s*\(\s*["\']script["\']', content, re.IGNORECASE):
            reasons.append("Dynamic script loading detected")
        
        # Check for obfuscation
        if len(re.findall(r'\\x[0-9a-fA-F]{2}', content)) > 10:
            reasons.append("Potential obfuscation (hex encoding)")
        
        # Check for minification
        lines = content.split('\n')
        avg_line_length = sum(len(line) for line in lines) / max(len(lines), 1)
        if avg_line_length > 200:
            reasons.append("Potentially minified code")
        
        # Check for redirect-related functionality
        redirect_indicators = ['redirect', 'forward', 'goto', 'location.href']
        redirect_count = sum(1 for indicator in redirect_indicators if indicator in content.lower())
        if redirect_count >= 3:
            reasons.append(f"Multiple redirect indicators: {redirect_count}")
        
        # Check for framework usage
        for framework, patterns in self.framework_patterns.items():
            if any(re.search(pattern, content, re.IGNORECASE) for pattern in patterns):
                reasons.append(f"Uses {framework} framework")
        
        return len(reasons) > 0, reasons
    
    def _is_redirect_related(self, name: str, value: str = "") -> bool:
        """Check if parameter is redirect-related"""
        redirect_keywords = [
            'redirect', 'url', 'next', 'return', 'goto', 'target',
            'destination', 'continue', 'forward', 'redir', 'location',
            'callback', 'success', 'failure', 'cancel', 'exit'
        ]
        
        name_lower = name.lower()
        value_lower = value.lower()
        
        # Check name
        name_match = any(keyword in name_lower for keyword in redirect_keywords)
        
        # Check value
        value_match = bool(
            re.match(r'https?://', value_lower) or
            re.match(r'//', value_lower) or
            re.match(r'[a-z0-9.-]+\.[a-z]{2,}', value_lower)
        )
        
        return name_match or value_match
    
    def _calculate_parameter_confidence(self, param: JSParameter, analysis: JSAnalysis) -> float:
        """Calculate confidence score for parameter"""
        confidence = 0.0
        
        # Base confidence by source type
        source_scores = {
            'inline': 0.7,
            'external': 0.6,
            'event_handler': 0.8
        }
        confidence += source_scores.get(param.source, 0.5)
        
        # Context-based confidence
        context_scores = {
            'location_manipulation': 0.9,
            'url_params': 0.8,
            'configuration': 0.6,
            'storage': 0.5,
            'ajax_request': 0.7,
            'event_handler': 0.8,
            'variable_declaration': 0.4,
            'object_property': 0.5
        }
        confidence += context_scores.get(param.context, 0.3) * 0.3
        
        # Boost for redirect-related names
        if self._is_redirect_related(param.name):
            confidence += 0.2
        
        # Boost for URL-like values
        if param.value:
            if param.value.startswith(('http://', 'https://')):
                confidence += 0.3
            elif param.value.startswith('//'):
                confidence += 0.25
        
        # Boost if found in suspicious script
        if analysis.is_suspicious:
            confidence += 0.1
        
        # Boost if DOM sinks and sources present
        if analysis.dom_sinks and analysis.sources:
            confidence += 0.15
        
        return min(confidence, 1.0)
    
    def get_all_parameters(self, analyses: List[JSAnalysis]) -> List[JSParameter]:
        """Get all parameters from all analyses"""
        all_params = []
        for analysis in analyses:
            all_params.extend(analysis.parameters)
        return all_params
    
    def get_high_risk_parameters(self, analyses: List[JSAnalysis], threshold: float = 0.7) -> List[JSParameter]:
        """Get high-risk parameters"""
        all_params = self.get_all_parameters(analyses)
        return [param for param in all_params if param.confidence >= threshold]
    
    def generate_js_report(self, analyses: List[JSAnalysis]) -> Dict:
        """Generate JavaScript analysis report"""
        if not analyses:
            return {}
        
        all_params = self.get_all_parameters(analyses)
        redirect_params = [p for p in all_params if p.is_redirect_related]
        high_conf_params = [p for p in all_params if p.confidence > 0.7]
        
        # Source type distribution
        source_dist = {}
        for analysis in analyses:
            source_dist[analysis.script_type] = source_dist.get(analysis.script_type, 0) + 1
        
        # Context distribution
        context_dist = {}
        for param in all_params:
            context_dist[param.context] = context_dist.get(param.context, 0) + 1
        
        # Suspicious scripts
        suspicious_scripts = [a for a in analyses if a.is_suspicious]
        
        return {
            'summary': {
                'total_scripts': len(analyses),
                'total_parameters': len(all_params),
                'redirect_parameters': len(redirect_params),
                'high_confidence_parameters': len(high_conf_params),
                'suspicious_scripts': len(suspicious_scripts),
                'total_lines_analyzed': sum(a.lines_analyzed for a in analyses)
            },
            'source_distribution': source_dist,
            'context_distribution': context_dist,
            'dom_analysis': {
                'scripts_with_sinks': len([a for a in analyses if a.dom_sinks]),
                'scripts_with_sources': len([a for a in analyses if a.sources]),
                'potentially_vulnerable': len([a for a in analyses if a.dom_sinks and a.sources])
            },
            'suspicious_details': [
                {
                    'script_type': a.script_type,
                    'script_url': a.script_url,
                    'reasons': a.suspicion_reasons,
                    'parameters_found': len(a.parameters),
                    'dom_sinks': a.dom_sinks,
                    'sources': a.sources
                }
                for a in suspicious_scripts
            ]
        }