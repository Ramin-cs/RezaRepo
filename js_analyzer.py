#!/usr/bin/env python3
"""
Advanced JavaScript Analyzer for Open Redirect Detection
Specialized module for deep JavaScript analysis and parameter extraction
"""

import re
import json
import logging
from typing import List, Dict, Set, Optional, Tuple, Any
from urllib.parse import urljoin, urlparse
import esprima
import jsbeautifier
from dataclasses import dataclass


@dataclass
class JSParameter:
    """JavaScript-specific parameter representation"""
    name: str
    value: str
    context: str  # 'variable', 'function_param', 'object_property', 'redirect_call'
    line_number: int
    source_file: str
    is_user_controlled: bool = False
    is_redirect_sink: bool = False
    confidence: float = 0.0


class JavaScriptAnalyzer:
    """Advanced JavaScript analyzer for security research"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # Redirect sink patterns - functions/properties that can cause redirects
        self.redirect_sinks = [
            'location.href', 'window.location', 'document.location',
            'location.assign', 'location.replace', 'window.open',
            'history.pushState', 'history.replaceState',
            'document.write', 'document.writeln',
            'iframe.src', 'frame.src', 'embed.src',
            'meta.content', 'link.href'
        ]
        
        # Source patterns - where user input might come from
        self.user_input_sources = [
            'location.search', 'location.hash', 'location.href',
            'window.location.search', 'window.location.hash',
            'document.URL', 'document.documentURI', 'document.baseURI',
            'document.referrer', 'window.name',
            'postMessage', 'addEventListener',
            'URLSearchParams', 'new URL',
            'localStorage.getItem', 'sessionStorage.getItem',
            'document.cookie', 'window.history'
        ]
        
        # Parameter extraction patterns
        self.param_patterns = [
            # URL parameter extraction
            r'new\s+URLSearchParams\([^)]*\)\.get\(["\']([^"\']+)["\']\)',
            r'new\s+URL\([^)]*\)\.searchParams\.get\(["\']([^"\']+)["\']\)',
            r'location\.search\.match\(/[\?\&]([^=&]+)=/\)',
            r'location\.hash\.match\(/#([^=&]+)=/\)',
            
            # Object property access
            r'\.([a-zA-Z_$][a-zA-Z0-9_$]*)\s*(?:\[|\.)',
            r'\[[\"\']([a-zA-Z_$][a-zA-Z0-9_$]*)[\"\']\]',
            
            # Function parameters
            r'function\s+\w*\s*\(\s*([^)]*)\s*\)',
            r'=>\s*\(\s*([^)]*)\s*\)',
            
            # Variable assignments
            r'(?:var|let|const)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=',
            
            # Redirect function calls
            r'(location\.(?:href|assign|replace))\s*=?\s*([^;]+)',
            r'(window\.(?:location|open))\s*[=\(]\s*([^;)]+)',
        ]
    
    def beautify_javascript(self, js_content: str) -> str:
        """Beautify JavaScript code for better analysis"""
        try:
            return jsbeautifier.beautify(js_content)
        except Exception as e:
            self.logger.warning(f"Failed to beautify JavaScript: {e}")
            return js_content
    
    def extract_parameters_regex(self, js_content: str, source_file: str) -> List[JSParameter]:
        """Extract parameters using regex patterns"""
        parameters = []
        lines = js_content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            for pattern in self.param_patterns:
                matches = re.finditer(pattern, line, re.IGNORECASE)
                for match in matches:
                    groups = match.groups()
                    if groups:
                        param_name = groups[0] if groups[0] else f"param_{line_num}_{match.start()}"
                        param_value = groups[1] if len(groups) > 1 and groups[1] else ""
                        
                        # Determine context
                        context = self.determine_js_context(line, match.group(0))
                        
                        # Check if it's user-controlled
                        is_user_controlled = self.is_user_controlled_input(line, param_name)
                        
                        # Check if it's a redirect sink
                        is_redirect_sink = self.is_redirect_sink(line, param_name)
                        
                        # Calculate confidence
                        confidence = self.calculate_confidence(param_name, param_value, context, line)
                        
                        parameters.append(JSParameter(
                            name=param_name,
                            value=param_value,
                            context=context,
                            line_number=line_num,
                            source_file=source_file,
                            is_user_controlled=is_user_controlled,
                            is_redirect_sink=is_redirect_sink,
                            confidence=confidence
                        ))
        
        return parameters
    
    def analyze_ast(self, js_content: str, source_file: str) -> List[JSParameter]:
        """Analyze JavaScript using AST parsing"""
        parameters = []
        
        try:
            # Parse JavaScript to AST
            ast = esprima.parseScript(js_content, {'loc': True, 'range': True})
            
            # Traverse AST to find parameters and potential vulnerabilities
            self.traverse_ast_node(ast, parameters, source_file, js_content)
            
        except Exception as e:
            self.logger.warning(f"AST analysis failed for {source_file}: {e}")
        
        return parameters
    
    def traverse_ast_node(self, node: Any, parameters: List[JSParameter], source_file: str, js_content: str):
        """Recursively traverse AST nodes"""
        if not hasattr(node, 'type'):
            return
        
        # Variable declarations
        if node.type == 'VariableDeclaration':
            for declaration in getattr(node, 'declarations', []):
                if hasattr(declaration, 'id') and hasattr(declaration.id, 'name'):
                    param_name = declaration.id.name
                    param_value = ""
                    
                    if hasattr(declaration, 'init') and declaration.init:
                        param_value = self.extract_value_from_node(declaration.init)
                    
                    line_num = getattr(declaration.loc, 'start', {}).get('line', 0) if hasattr(declaration, 'loc') else 0
                    
                    parameters.append(JSParameter(
                        name=param_name,
                        value=param_value,
                        context='variable_declaration',
                        line_number=line_num,
                        source_file=source_file,
                        is_user_controlled=self.is_user_controlled_variable(param_name, param_value),
                        is_redirect_sink=False,
                        confidence=0.5
                    ))
        
        # Assignment expressions
        elif node.type == 'AssignmentExpression':
            if hasattr(node, 'left') and hasattr(node, 'right'):
                param_name = self.extract_name_from_node(node.left)
                param_value = self.extract_value_from_node(node.right)
                
                line_num = getattr(node.loc, 'start', {}).get('line', 0) if hasattr(node, 'loc') else 0
                
                # Check if this is a redirect assignment
                is_redirect = self.is_redirect_assignment(param_name, param_value)
                is_user_controlled = self.is_user_controlled_assignment(param_name, param_value)
                
                parameters.append(JSParameter(
                    name=param_name,
                    value=param_value,
                    context='assignment',
                    line_number=line_num,
                    source_file=source_file,
                    is_user_controlled=is_user_controlled,
                    is_redirect_sink=is_redirect,
                    confidence=0.8 if is_redirect else 0.4
                ))
        
        # Function calls (especially redirect-related)
        elif node.type == 'CallExpression':
            if hasattr(node, 'callee'):
                func_name = self.extract_name_from_node(node.callee)
                args = getattr(node, 'arguments', [])
                
                if self.is_redirect_function(func_name):
                    for i, arg in enumerate(args):
                        arg_value = self.extract_value_from_node(arg)
                        line_num = getattr(node.loc, 'start', {}).get('line', 0) if hasattr(node, 'loc') else 0
                        
                        parameters.append(JSParameter(
                            name=f"{func_name}_arg_{i}",
                            value=arg_value,
                            context='function_call',
                            line_number=line_num,
                            source_file=source_file,
                            is_user_controlled=self.contains_user_input(arg_value),
                            is_redirect_sink=True,
                            confidence=0.9
                        ))
        
        # Object property access
        elif node.type == 'MemberExpression':
            property_name = self.extract_name_from_node(node)
            if self.is_redirect_property(property_name):
                line_num = getattr(node.loc, 'start', {}).get('line', 0) if hasattr(node, 'loc') else 0
                
                parameters.append(JSParameter(
                    name=property_name,
                    value="",
                    context='property_access',
                    line_number=line_num,
                    source_file=source_file,
                    is_user_controlled=False,
                    is_redirect_sink=True,
                    confidence=0.7
                ))
        
        # Recursively traverse child nodes
        for key, value in node.__dict__.items():
            if isinstance(value, list):
                for item in value:
                    if hasattr(item, 'type'):
                        self.traverse_ast_node(item, parameters, source_file, js_content)
            elif hasattr(value, 'type'):
                self.traverse_ast_node(value, parameters, source_file, js_content)
    
    def extract_name_from_node(self, node: Any) -> str:
        """Extract name from AST node"""
        if not node:
            return ""
        
        if hasattr(node, 'name'):
            return node.name
        elif hasattr(node, 'property') and hasattr(node.property, 'name'):
            object_name = self.extract_name_from_node(getattr(node, 'object', None))
            property_name = node.property.name
            return f"{object_name}.{property_name}" if object_name else property_name
        elif hasattr(node, 'type') and node.type == 'Literal':
            return str(getattr(node, 'value', ''))
        
        return ""
    
    def extract_value_from_node(self, node: Any) -> str:
        """Extract value from AST node"""
        if not node:
            return ""
        
        if hasattr(node, 'value'):
            return str(node.value)
        elif hasattr(node, 'name'):
            return node.name
        elif hasattr(node, 'type'):
            if node.type == 'BinaryExpression':
                left = self.extract_value_from_node(getattr(node, 'left', None))
                right = self.extract_value_from_node(getattr(node, 'right', None))
                operator = getattr(node, 'operator', '')
                return f"{left} {operator} {right}"
            elif node.type == 'MemberExpression':
                return self.extract_name_from_node(node)
        
        return ""
    
    def determine_js_context(self, line: str, match: str) -> str:
        """Determine the context of JavaScript parameter usage"""
        line_lower = line.lower().strip()
        
        if 'function' in line_lower and '(' in line and ')' in line:
            return 'function_parameter'
        elif any(sink in line_lower for sink in ['location.href', 'window.location', 'location.assign']):
            return 'redirect_sink'
        elif 'var ' in line_lower or 'let ' in line_lower or 'const ' in line_lower:
            return 'variable_declaration'
        elif '=' in line and not '==' in line and not '===' in line:
            return 'assignment'
        elif '{' in line and '}' in line and ':' in line:
            return 'object_property'
        elif 'addEventListener' in line_lower or 'onclick' in line_lower:
            return 'event_handler'
        else:
            return 'generic'
    
    def is_user_controlled_input(self, line: str, param_name: str) -> bool:
        """Check if parameter comes from user-controlled input"""
        line_lower = line.lower()
        
        # Check for direct user input sources
        user_sources = [
            'location.search', 'location.hash', 'location.href',
            'document.url', 'document.referrer', 'window.name',
            'urlsearchparams', 'getparameter', 'getattribute',
            'postmessage', 'localstorage', 'sessionstorage'
        ]
        
        return any(source in line_lower for source in user_sources)
    
    def is_redirect_sink(self, line: str, param_name: str) -> bool:
        """Check if parameter is used in a redirect sink"""
        line_lower = line.lower()
        return any(sink in line_lower for sink in [
            'location.href', 'window.location', 'location.assign',
            'location.replace', 'window.open', 'document.location'
        ])
    
    def is_user_controlled_variable(self, param_name: str, param_value: str) -> bool:
        """Check if variable is likely user-controlled"""
        user_indicators = [
            'url', 'param', 'query', 'search', 'hash', 'input',
            'user', 'request', 'get', 'post', 'data'
        ]
        
        name_lower = param_name.lower()
        value_lower = param_value.lower()
        
        return (any(indicator in name_lower for indicator in user_indicators) or
                any(indicator in value_lower for indicator in user_indicators))
    
    def is_redirect_assignment(self, param_name: str, param_value: str) -> bool:
        """Check if assignment is redirect-related"""
        redirect_indicators = [
            'location', 'href', 'url', 'redirect', 'goto',
            'navigate', 'forward', 'back'
        ]
        
        name_lower = param_name.lower()
        return any(indicator in name_lower for indicator in redirect_indicators)
    
    def is_redirect_function(self, func_name: str) -> bool:
        """Check if function is redirect-related"""
        redirect_functions = [
            'assign', 'replace', 'open', 'navigate',
            'redirect', 'forward', 'goto'
        ]
        
        func_lower = func_name.lower()
        return any(func in func_lower for func in redirect_functions)
    
    def is_redirect_property(self, property_name: str) -> bool:
        """Check if property is redirect-related"""
        return any(sink in property_name.lower() for sink in [
            'location.href', 'window.location', 'document.location'
        ])
    
    def contains_user_input(self, value: str) -> bool:
        """Check if value contains user input sources"""
        value_lower = value.lower()
        return any(source in value_lower for source in [
            'location.search', 'location.hash', 'urlsearchparams',
            'document.url', 'window.name', 'postmessage'
        ])
    
    def calculate_confidence(self, param_name: str, param_value: str, context: str, line: str) -> float:
        """Calculate confidence score for parameter relevance"""
        confidence = 0.0
        
        # Base confidence by context
        context_scores = {
            'redirect_sink': 0.9,
            'function_parameter': 0.7,
            'assignment': 0.6,
            'variable_declaration': 0.5,
            'object_property': 0.4,
            'event_handler': 0.3,
            'generic': 0.2
        }
        confidence += context_scores.get(context, 0.2)
        
        # Boost for redirect-related names
        if self.is_redirect_assignment(param_name, param_value):
            confidence += 0.2
        
        # Boost for user input sources
        if self.is_user_controlled_input(line, param_name):
            confidence += 0.3
        
        # Boost for redirect sinks
        if self.is_redirect_sink(line, param_name):
            confidence += 0.3
        
        return min(confidence, 1.0)
    
    def find_data_flows(self, js_content: str, source_file: str) -> List[Dict[str, Any]]:
        """Find data flows from user input to redirect sinks"""
        flows = []
        lines = js_content.split('\n')
        
        # Track variables and their sources
        variable_sources = {}
        
        for line_num, line in enumerate(lines, 1):
            line_clean = line.strip()
            
            # Track variable assignments from user input
            for source in self.user_input_sources:
                if source in line_clean:
                    # Extract variable name being assigned
                    var_match = re.search(r'(?:var|let|const)\s+(\w+)\s*=|(\w+)\s*=', line_clean)
                    if var_match:
                        var_name = var_match.group(1) or var_match.group(2)
                        variable_sources[var_name] = {
                            'source': source,
                            'line': line_num,
                            'content': line_clean
                        }
            
            # Check for redirect sinks using tracked variables
            for sink in self.redirect_sinks:
                if sink in line_clean:
                    # Look for variables used in this sink
                    for var_name, var_info in variable_sources.items():
                        if var_name in line_clean:
                            flows.append({
                                'source': var_info['source'],
                                'source_line': var_info['line'],
                                'sink': sink,
                                'sink_line': line_num,
                                'variable': var_name,
                                'flow_path': f"{var_info['source']} -> {var_name} -> {sink}",
                                'source_file': source_file,
                                'confidence': 0.9
                            })
        
        return flows
    
    def detect_dom_based_sinks(self, js_content: str, source_file: str) -> List[Dict[str, Any]]:
        """Detect DOM-based redirect sinks"""
        sinks = []
        lines = js_content.split('\n')
        
        dom_sink_patterns = [
            r'(location\.href)\s*=\s*([^;]+)',
            r'(window\.location)\s*=\s*([^;]+)',
            r'(document\.location)\s*=\s*([^;]+)',
            r'(location\.assign)\s*\(\s*([^)]+)\s*\)',
            r'(location\.replace)\s*\(\s*([^)]+)\s*\)',
            r'(window\.open)\s*\(\s*([^,)]+)',
            r'(history\.pushState)\s*\([^,]*,\s*[^,]*,\s*([^)]+)\)',
            r'(history\.replaceState)\s*\([^,]*,\s*[^,]*,\s*([^)]+)\)',
        ]
        
        for line_num, line in enumerate(lines, 1):
            for pattern in dom_sink_patterns:
                matches = re.finditer(pattern, line, re.IGNORECASE)
                for match in matches:
                    sink_name = match.group(1)
                    sink_value = match.group(2) if len(match.groups()) > 1 else ""
                    
                    # Check if sink value contains user input
                    contains_user_input = self.contains_user_input(sink_value)
                    
                    sinks.append({
                        'sink_name': sink_name,
                        'sink_value': sink_value,
                        'line_number': line_num,
                        'source_file': source_file,
                        'contains_user_input': contains_user_input,
                        'line_content': line.strip(),
                        'confidence': 0.8 if contains_user_input else 0.4
                    })
        
        return sinks
    
    def extract_url_construction_patterns(self, js_content: str, source_file: str) -> List[Dict[str, Any]]:
        """Extract URL construction patterns that might be vulnerable"""
        patterns = []
        lines = js_content.split('\n')
        
        url_construction_patterns = [
            r'["\']https?://["\']?\s*\+\s*([^;]+)',  # URL concatenation
            r'`https?://[^`]*\$\{([^}]+)\}[^`]*`',   # Template literals
            r'new\s+URL\s*\(\s*([^,)]+)',            # URL constructor
            r'encodeURIComponent\s*\(\s*([^)]+)\)',  # URL encoding
            r'decodeURIComponent\s*\(\s*([^)]+)\)',  # URL decoding
        ]
        
        for line_num, line in enumerate(lines, 1):
            for pattern in url_construction_patterns:
                matches = re.finditer(pattern, line, re.IGNORECASE)
                for match in matches:
                    variable_part = match.group(1)
                    
                    patterns.append({
                        'pattern_type': 'url_construction',
                        'variable_part': variable_part,
                        'line_number': line_num,
                        'source_file': source_file,
                        'line_content': line.strip(),
                        'is_user_controlled': self.contains_user_input(variable_part),
                        'confidence': 0.7
                    })
        
        return patterns
    
    def analyze_event_handlers(self, js_content: str, source_file: str) -> List[Dict[str, Any]]:
        """Analyze event handlers for potential redirect vulnerabilities"""
        handlers = []
        lines = js_content.split('\n')
        
        event_patterns = [
            r'addEventListener\s*\(\s*["\']([^"\']+)["\'],\s*([^)]+)\)',
            r'on(\w+)\s*=\s*([^;]+)',
            r'\.on(\w+)\s*=\s*([^;]+)',
        ]
        
        for line_num, line in enumerate(lines, 1):
            for pattern in event_patterns:
                matches = re.finditer(pattern, line, re.IGNORECASE)
                for match in matches:
                    groups = match.groups()
                    event_type = groups[0] if groups else "unknown"
                    handler_code = groups[1] if len(groups) > 1 else groups[0]
                    
                    # Check if handler contains redirect code
                    if any(sink in handler_code.lower() for sink in ['location', 'redirect', 'href']):
                        handlers.append({
                            'event_type': event_type,
                            'handler_code': handler_code,
                            'line_number': line_num,
                            'source_file': source_file,
                            'line_content': line.strip(),
                            'contains_redirect': True,
                            'confidence': 0.8
                        })
        
        return handlers
    
    def comprehensive_analysis(self, js_content: str, source_file: str) -> Dict[str, Any]:
        """Perform comprehensive JavaScript analysis"""
        # Beautify code first
        beautified_content = self.beautify_javascript(js_content)
        
        # Extract parameters using multiple methods
        regex_params = self.extract_parameters_regex(beautified_content, source_file)
        ast_params = self.analyze_ast(beautified_content, source_file)
        
        # Find data flows
        data_flows = self.find_data_flows(beautified_content, source_file)
        
        # Detect DOM sinks
        dom_sinks = self.detect_dom_based_sinks(beautified_content, source_file)
        
        # Analyze URL construction
        url_patterns = self.extract_url_construction_patterns(beautified_content, source_file)
        
        # Analyze event handlers
        event_handlers = self.analyze_event_handlers(beautified_content, source_file)
        
        # Combine all parameters and remove duplicates
        all_params = regex_params + ast_params
        unique_params = []
        seen_params = set()
        
        for param in all_params:
            param_key = f"{param.name}:{param.line_number}:{param.context}"
            if param_key not in seen_params:
                seen_params.add(param_key)
                unique_params.append(param)
        
        # Sort by confidence
        unique_params.sort(key=lambda x: x.confidence, reverse=True)
        
        return {
            'parameters': unique_params,
            'data_flows': data_flows,
            'dom_sinks': dom_sinks,
            'url_patterns': url_patterns,
            'event_handlers': event_handlers,
            'total_parameters': len(unique_params),
            'high_confidence_params': [p for p in unique_params if p.confidence > 0.7],
            'redirect_related_params': [p for p in unique_params if p.is_redirect_sink or p.is_user_controlled]
        }


class AdvancedDOMAnalyzer:
    """Advanced DOM-based vulnerability analyzer"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def analyze_dom_sources(self, js_content: str) -> List[Dict[str, Any]]:
        """Analyze DOM sources that can be controlled by attackers"""
        sources = []
        
        dom_source_patterns = [
            r'(location\.search)',
            r'(location\.hash)',
            r'(location\.href)',
            r'(document\.URL)',
            r'(document\.documentURI)',
            r'(document\.baseURI)',
            r'(document\.referrer)',
            r'(window\.name)',
            r'(document\.cookie)',
            r'(localStorage\.getItem\([^)]+\))',
            r'(sessionStorage\.getItem\([^)]+\))',
        ]
        
        lines = js_content.split('\n')
        for line_num, line in enumerate(lines, 1):
            for pattern in dom_source_patterns:
                matches = re.finditer(pattern, line, re.IGNORECASE)
                for match in matches:
                    sources.append({
                        'source': match.group(1),
                        'line_number': line_num,
                        'line_content': line.strip(),
                        'risk_level': self.calculate_source_risk(match.group(1))
                    })
        
        return sources
    
    def calculate_source_risk(self, source: str) -> str:
        """Calculate risk level for DOM source"""
        high_risk = ['location.hash', 'window.name', 'document.referrer']
        medium_risk = ['location.search', 'document.URL']
        
        if any(hr in source for hr in high_risk):
            return 'HIGH'
        elif any(mr in source for mr in medium_risk):
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def trace_data_flow(self, js_content: str) -> List[Dict[str, Any]]:
        """Trace data flow from sources to sinks"""
        flows = []
        lines = js_content.split('\n')
        
        # Simple data flow analysis
        variables = {}  # Track variable assignments
        
        for line_num, line in enumerate(lines, 1):
            line_clean = line.strip()
            
            # Track variable assignments
            var_match = re.search(r'(?:var|let|const)\s+(\w+)\s*=\s*([^;]+)', line_clean)
            if var_match:
                var_name = var_match.group(1)
                var_value = var_match.group(2)
                variables[var_name] = {
                    'value': var_value,
                    'line': line_num,
                    'is_user_controlled': self.is_user_controlled_source(var_value)
                }
            
            # Track property assignments
            prop_match = re.search(r'(\w+)\s*=\s*([^;]+)', line_clean)
            if prop_match and '==' not in line_clean and '===' not in line_clean:
                var_name = prop_match.group(1)
                var_value = prop_match.group(2)
                variables[var_name] = {
                    'value': var_value,
                    'line': line_num,
                    'is_user_controlled': self.is_user_controlled_source(var_value)
                }
            
            # Check for sink usage
            for sink in ['location.href', 'window.location', 'location.assign', 'location.replace']:
                if sink in line_clean:
                    # Check if any tracked variables are used
                    for var_name, var_info in variables.items():
                        if var_name in line_clean and var_info['is_user_controlled']:
                            flows.append({
                                'source_variable': var_name,
                                'source_value': var_info['value'],
                                'source_line': var_info['line'],
                                'sink': sink,
                                'sink_line': line_num,
                                'sink_content': line_clean,
                                'risk_level': 'HIGH',
                                'exploitable': True
                            })
        
        return flows
    
    def is_user_controlled_source(self, value: str) -> bool:
        """Check if value comes from user-controlled source"""
        user_sources = [
            'location.search', 'location.hash', 'location.href',
            'document.URL', 'document.referrer', 'window.name',
            'localStorage', 'sessionStorage', 'postMessage'
        ]
        
        return any(source in value for source in user_sources)


# Export classes for use in main scanner
__all__ = ['JavaScriptAnalyzer', 'AdvancedDOMAnalyzer', 'JSParameter']