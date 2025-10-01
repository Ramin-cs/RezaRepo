#!/usr/bin/env python3
"""
Phase 6: Advanced Parameter Discovery & JS Analysis
Comprehensive parameter discovery using multiple tools and JavaScript analysis
"""

import requests
import subprocess
import platform
import os
from datetime import datetime
from typing import Dict, Any, List
import json
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

# Import cross-platform manager
try:
    import sys
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from utils.platform_manager import get_platform_manager
    platform_manager = get_platform_manager()
except ImportError:
    platform_manager = None

class Phase6ParameterDiscovery:
    """Advanced Parameter Discovery and JS Analysis with comprehensive techniques"""
    
    def __init__(self):
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        self.parameter_wordlist = [
            'id', 'user_id', 'userid', 'username', 'user_name', 'user-name', 'user',
            'email', 'mail', 'phone', 'mobile', 'name', 'firstname', 'lastname', 'fullname',
            'password', 'pass', 'pwd', 'confirm_password', 'confirm-password', 'new_password',
            'page', 'p', 'offset', 'limit', 'size', 'count', 'per_page', 'per-page',
            'start', 'end', 'from', 'to', 'since', 'until', 'before', 'after',
            'search', 'query', 'q', 'filter', 'sort', 'order', 'orderby', 'order-by',
            'file', 'files', 'upload', 'upload_file', 'upload-file', 'image', 'img',
            'photo', 'picture', 'avatar', 'document', 'doc', 'pdf', 'excel', 'csv',
            'config', 'setting', 'settings', 'option', 'options', 'preference', 'preferences',
            'mode', 'theme', 'language', 'lang', 'locale', 'timezone', 'currency',
            'security', 'secure', 'encrypt', 'decrypt', 'hash', 'salt', 'iv', 'cipher',
            'ssl', 'tls', 'cert', 'certificate', 'verify', 'validation', 'validate',
            'db', 'database', 'table', 'column', 'field', 'value', 'values', 'record',
            'select', 'insert', 'update', 'delete', 'where', 'join', 'group', 'having',
            'url', 'link', 'href', 'src', 'source', 'target', 'destination',
            'next', 'previous', 'back', 'forward', 'continue', 'cancel', 'abort',
            'title', 'description', 'content', 'body', 'text', 'message', 'subject',
            'comment', 'comments', 'reply', 'replies', 'post', 'posts', 'article', 'articles',
            'facebook', 'twitter', 'instagram', 'linkedin', 'youtube', 'vimeo',
            'social', 'share', 'like', 'follow', 'follower', 'following', 'friend', 'friends',
            'product', 'products', 'category', 'categories', 'brand', 'brands',
            'price', 'cost', 'quantity', 'amount', 'total', 'subtotal', 'tax',
            'shipping', 'discount', 'coupon', 'cart', 'checkout', 'payment',
            'analytics', 'tracking', 'track', 'event', 'events', 'action', 'actions',
            'metric', 'metrics', 'stat', 'stats', 'report', 'reports', 'dashboard',
            'debug', 'test', 'testing', 'dev', 'development', 'staging', 'stage',
            'prod', 'production', 'version', 'build', 'release', 'deploy', 'environment'
        ]
    
    def run_phase(self, target: str) -> Dict[str, Any]:
        """Run Phase 6: Advanced Parameter Discovery"""
        print(f"🔍 Phase 6: Advanced Parameter Discovery for {target}")
        results = {
            'target': target,
            'phase': 6,
            'start_time': datetime.now().isoformat(),
            'parameters_found': [],
            'js_analysis': {},
            'js_files': [],
            'endpoints_found': [],
            'api_keys': [],
            'secrets': [],
            'tool_results': {},
            'techniques_used': [],
            'errors': []
        }
        
        try:
            # Technique 1: JavaScript Analysis
            print("   📜 JavaScript Analysis...")
            results['techniques_used'].append('JavaScript Analysis')
            
            try:
                response = requests.get(f"https://{target}", headers=self.headers, timeout=10, allow_redirects=True)
                content = response.text
                
                # Extract JavaScript files
                js_patterns = re.findall(r'<script[^>]*src=["\']([^"\']*\.js[^"\']*)["\'][^>]*>', content, re.IGNORECASE)
                inline_scripts = re.findall(r'<script[^>]*>(.*?)</script>', content, re.DOTALL | re.IGNORECASE)
                
                results['js_analysis'] = {
                    'external_scripts': len(js_patterns),
                    'inline_scripts': len(inline_scripts),
                    'total_scripts': len(js_patterns) + len(inline_scripts)
                }
                
                # Analyze each JavaScript file
                for js_url in js_patterns[:10]:  # Limit to first 10 for speed
                    try:
                        if not js_url.startswith('http'):
                            js_url = f"https://{target}{js_url}"
                        
                        js_response = requests.get(js_url, headers=self.headers, timeout=5)
                        if js_response.status_code == 200:
                            js_content = js_response.text
                            
                            # Extract endpoints from JavaScript
                            endpoint_patterns = [
                                r'["\']([^"\']*\/api\/[^"\']*)["\']',
                                r'["\']([^"\']*\/rest\/[^"\']*)["\']',
                                r'["\']([^"\']*\/graphql[^"\']*)["\']',
                                r'["\']([^"\']*\/v[0-9]+\/[^"\']*)["\']',
                                r'fetch\(["\']([^"\']*)["\']',
                                r'axios\.[a-z]+\(["\']([^"\']*)["\']',
                                r'\.get\(["\']([^"\']*)["\']',
                                r'\.post\(["\']([^"\']*)["\']',
                                r'\.put\(["\']([^"\']*)["\']',
                                r'\.delete\(["\']([^"\']*)["\']'
                            ]
                            
                            for pattern in endpoint_patterns:
                                matches = re.findall(pattern, js_content, re.IGNORECASE)
                                for match in matches:
                                    if match.startswith('/') and match not in results['endpoints_found']:
                                        results['endpoints_found'].append(match)
                                        print(f"   ✅ Endpoint found in JS: {match}")
                            
                            # Extract API keys and secrets
                            secret_patterns = [
                                r'["\'](sk_[a-zA-Z0-9]{20,})["\']',  # Stripe
                                r'["\'](pk_[a-zA-Z0-9]{20,})["\']',  # Stripe
                                r'["\'](AIza[0-9A-Za-z\\-_]{35})["\']',  # Google API
                                r'["\'](AKIA[0-9A-Z]{16})["\']',  # AWS
                                r'["\']([0-9a-f]{32})["\']',  # MD5 hash
                                r'["\']([0-9a-f]{40})["\']',  # SHA1 hash
                                r'["\']([0-9a-f]{64})["\']',  # SHA256 hash
                                r'["\'](Bearer\s+[a-zA-Z0-9\-_=]+)["\']',  # Bearer token
                                r'["\'](api_key["\']\s*:\s*["\'][^"\']+["\'])',  # API key pattern
                                r'["\'](secret["\']\s*:\s*["\'][^"\']+["\'])',  # Secret pattern
                                r'["\'](password["\']\s*:\s*["\'][^"\']+["\'])',  # Password pattern
                                r'["\'](token["\']\s*:\s*["\'][^"\']+["\'])'  # Token pattern
                            ]
                            
                            for pattern in secret_patterns:
                                matches = re.findall(pattern, js_content, re.IGNORECASE)
                                for match in matches:
                                    if match not in results['secrets']:
                                        results['secrets'].append(match)
                                        print(f"   🔑 Secret found in JS: {match[:50]}...")
                            
                            results['js_files'].append({
                                'url': js_url,
                                'size': len(js_content),
                                'endpoints_found': len([e for e in results['endpoints_found'] if e.startswith('/')]),
                                'secrets_found': len(results['secrets'])
                            })
                            
                    except Exception as e:
                        results['errors'].append(f"JS file analysis failed for {js_url}: {str(e)}")
                
                # Analyze inline scripts
                for script_content in inline_scripts:
                    # Extract endpoints from inline scripts
                    for pattern in [
                        r'["\']([^"\']*\/api\/[^"\']*)["\']',
                        r'["\']([^"\']*\/rest\/[^"\']*)["\']',
                        r'["\']([^"\']*\/graphql[^"\']*)["\']'
                    ]:
                        matches = re.findall(pattern, script_content, re.IGNORECASE)
                        for match in matches:
                            if match.startswith('/') and match not in results['endpoints_found']:
                                results['endpoints_found'].append(match)
                                print(f"   ✅ Endpoint found in inline JS: {match}")
                
            except Exception as e:
                results['errors'].append(f"JavaScript analysis failed: {str(e)}")
            
            # Technique 2: Comprehensive Parameter Discovery
            print("   🔍 Comprehensive Parameter Discovery...")
            results['techniques_used'].append('Comprehensive Parameter Discovery')
            
            # Initialize parameter categories
            results['url_parameters'] = []
            results['form_parameters'] = []
            results['javascript_variables'] = []
            results['http_headers'] = []
            results['meta_tags'] = []
            results['cookie_parameters'] = []
            
            # Extended parameter wordlist
            extended_params = self.parameter_wordlist + [
                # API parameters
                'api_key', 'apikey', 'api-key', 'access_token', 'access-token', 'access_token',
                'bearer', 'bearer_token', 'bearer-token', 'oauth_token', 'oauth-token',
                'client_id', 'client-id', 'client_secret', 'client-secret', 'client_secret',
                
                # Authentication
                'auth', 'authorization', 'auth_token', 'auth-token', 'session', 'sessionid',
                'session_id', 'session-id', 'csrf', 'csrf_token', 'csrf-token', 'csrf_token',
                'nonce', 'state', 'callback', 'redirect', 'return', 'return_url', 'return-url',
                
                # Common web parameters
                'id', 'user_id', 'user-id', 'userid', 'username', 'user_name', 'user-name',
                'email', 'mail', 'phone', 'mobile', 'name', 'firstname', 'lastname', 'fullname',
                'password', 'pass', 'pwd', 'confirm_password', 'confirm-password', 'new_password',
                
                # Pagination and filtering
                'page', 'p', 'offset', 'limit', 'size', 'count', 'per_page', 'per-page',
                'start', 'end', 'from', 'to', 'since', 'until', 'before', 'after',
                'search', 'query', 'q', 'filter', 'sort', 'order', 'orderby', 'order-by',
                
                # File upload
                'file', 'files', 'upload', 'upload_file', 'upload-file', 'image', 'img',
                'photo', 'picture', 'avatar', 'document', 'doc', 'pdf', 'excel', 'csv',
                
                # Configuration
                'config', 'setting', 'settings', 'option', 'options', 'preference', 'preferences',
                'mode', 'theme', 'language', 'lang', 'locale', 'timezone', 'currency',
                
                # Security
                'security', 'secure', 'encrypt', 'decrypt', 'hash', 'salt', 'iv', 'cipher',
                'ssl', 'tls', 'cert', 'certificate', 'verify', 'validation', 'validate',
                
                # Database
                'db', 'database', 'table', 'column', 'field', 'value', 'values', 'record',
                'select', 'insert', 'update', 'delete', 'where', 'join', 'group', 'having',
                
                # URL parameters
                'url', 'link', 'href', 'src', 'source', 'target', 'destination',
                'next', 'previous', 'back', 'forward', 'continue', 'cancel', 'abort',
                
                # Content
                'title', 'description', 'content', 'body', 'text', 'message', 'subject',
                'comment', 'comments', 'reply', 'replies', 'post', 'posts', 'article', 'articles',
                
                # Social
                'facebook', 'twitter', 'instagram', 'linkedin', 'youtube', 'vimeo',
                'social', 'share', 'like', 'follow', 'follower', 'following', 'friend', 'friends',
                
                # E-commerce
                'product', 'products', 'category', 'categories', 'brand', 'brands',
                'price', 'cost', 'quantity', 'amount', 'total', 'subtotal', 'tax',
                'shipping', 'discount', 'coupon', 'cart', 'checkout', 'payment',
                
                # Analytics
                'analytics', 'tracking', 'track', 'event', 'events', 'action', 'actions',
                'metric', 'metrics', 'stat', 'stats', 'report', 'reports', 'dashboard',
                
                # Development
                'debug', 'test', 'testing', 'dev', 'development', 'staging', 'stage',
                'prod', 'production', 'version', 'build', 'release', 'deploy', 'environment'
            ]
            
            # Categorize parameters
            param_categories = {
                'authentication': ['auth', 'login', 'password', 'token', 'session', 'csrf', 'oauth'],
                'api': ['api', 'key', 'token', 'bearer', 'client', 'secret'],
                'pagination': ['page', 'offset', 'limit', 'size', 'count', 'per_page'],
                'filtering': ['search', 'query', 'filter', 'sort', 'order', 'category'],
                'file_upload': ['file', 'upload', 'image', 'document', 'attachment'],
                'configuration': ['config', 'setting', 'option', 'preference', 'mode', 'theme'],
                'security': ['security', 'secure', 'encrypt', 'hash', 'cert', 'ssl'],
                'database': ['db', 'table', 'column', 'field', 'record', 'query'],
                'content': ['title', 'description', 'content', 'body', 'text', 'message'],
                'ecommerce': ['product', 'category', 'price', 'cart', 'checkout', 'payment'],
                'analytics': ['analytics', 'tracking', 'metric', 'stat', 'report', 'dashboard']
            }
            
            for param in extended_params[:200]:  # Increased to 200 parameters
                category = 'other'
                for cat, keywords in param_categories.items():
                    if any(keyword in param.lower() for keyword in keywords):
                        category = cat
                        break
                
                results['parameters_found'].append({
                    'parameter': param,
                    'type': category,
                    'source': 'wordlist',
                    'risk_level': self._assess_parameter_risk(param)
                })
            
            # Technique 3: ParamSpider Integration
            print("   🔍 ParamSpider Integration...")
            results['techniques_used'].append('ParamSpider Integration')
            
            if self._is_paramspider_available():
                try:
                    paramspider_results = self._run_paramspider(target)
                    if paramspider_results and paramspider_results.get('success'):
                        results['tool_results']['paramspider'] = paramspider_results
                        
                        # Extract parameters from ParamSpider results
                        if 'parameters' in paramspider_results and paramspider_results['parameters']:
                            for param in paramspider_results['parameters']:
                                if param not in [p['parameter'] for p in results['parameters_found']]:
                                    results['parameters_found'].append({
                                        'parameter': param,
                                        'type': 'paramspider',
                                        'source': 'paramspider',
                                        'risk_level': self._assess_parameter_risk(param)
                                    })
                                    print(f"   ✅ ParamSpider found: {param}")
                        
                        print(f"   ✅ ParamSpider scan completed")
                    else:
                        error_msg = paramspider_results.get('error', 'No results') if paramspider_results else 'No results'
                        print(f"   ⚠️ ParamSpider completed but no results: {error_msg}")
                except Exception as e:
                    results['errors'].append(f"ParamSpider scan failed: {str(e)}")
                    print(f"   ❌ ParamSpider failed: {str(e)}")
            else:
                print("   ℹ️ ParamSpider not available, skipping")
            
            # Technique 4: x8 Integration
            print("   🔍 x8 Integration...")
            results['techniques_used'].append('x8 Integration')
            
            if self._is_x8_available():
                try:
                    x8_results = self._run_x8(target)
                    if x8_results:
                        results['tool_results']['x8'] = x8_results
                        print(f"   ✅ x8 scan completed")
                except Exception as e:
                    results['errors'].append(f"x8 scan failed: {str(e)}")
            else:
                print("   ℹ️ x8 not available, skipping")
            
            # Technique 5: Wayback Machine Integration
            print("   🕰️ Wayback Machine Integration...")
            results['techniques_used'].append('Wayback Machine Integration')
            
            try:
                wayback_results = self._run_wayback_machine(target)
                if wayback_results:
                    results['tool_results']['wayback'] = wayback_results
                    print(f"   ✅ Wayback Machine scan completed")
            except Exception as e:
                results['errors'].append(f"Wayback Machine scan failed: {str(e)}")
            
            # Technique 6: URL Parameters Analysis
            print("   🔗 URL Parameters Analysis...")
            results['techniques_used'].append('URL Parameters Analysis')
            
            try:
                response = requests.get(f"https://{target}", headers=self.headers, timeout=10)
                
                # Parse current URL for existing parameters
                from urllib.parse import urlparse, parse_qs
                parsed_url = urlparse(response.url)
                if parsed_url.query:
                    query_params = parse_qs(parsed_url.query)
                    for param, values in query_params.items():
                        results['url_parameters'].append({
                            'parameter': param,
                            'values': values,
                            'source': 'current_url',
                            'type': 'query_string'
                        })
                        print(f"   ✅ URL parameter found: {param} = {values}")
                
                # Test common parameters with different values
                test_params = ['id', 'user', 'page', 'search', 'category', 'type', 'status', 'sort', 'filter', 'limit', 'offset']
                test_values = ['1', 'admin', 'test', 'debug', 'true', 'false', 'null', 'undefined']
                
                for param in test_params:
                    for value in test_values:
                        try:
                            url = f"https://{target}/?{param}={value}"
                            test_response = requests.get(url, headers=self.headers, timeout=3, allow_redirects=False)
                            
                            if test_response.status_code not in [404, 400]:  # Not a standard error
                                results['url_parameters'].append({
                                    'parameter': param,
                                    'test_value': value,
                                    'response_code': test_response.status_code,
                                    'content_length': len(test_response.content),
                                    'source': 'parameter_testing',
                                    'type': 'query_string',
                                    'risk_level': self._assess_parameter_risk(param)
                                })
                                print(f"   ✅ Parameter test: {param}={value} -> {test_response.status_code}")
                        except:
                            pass
                            
            except Exception as e:
                results['errors'].append(f"URL parameters analysis failed: {str(e)}")
            
            # Technique 7: Form Parameters Discovery
            print("   📝 Form Parameters Discovery...")
            results['techniques_used'].append('Form Parameters Discovery')
            
            try:
                response = requests.get(f"https://{target}", headers=self.headers, timeout=10)
                content = response.text
                
                # Extract form parameters with detailed analysis
                form_patterns = [
                    r'<input[^>]*name=["\']([^"\']*)["\'][^>]*(?:type=["\']([^"\']*)["\'])?[^>]*>',
                    r'<select[^>]*name=["\']([^"\']*)["\'][^>]*>',
                    r'<textarea[^>]*name=["\']([^"\']*)["\'][^>]*>',
                    r'<button[^>]*name=["\']([^"\']*)["\'][^>]*>'
                ]
                
                for pattern in form_patterns:
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    for match in matches:
                        param_name = match[0] if isinstance(match, tuple) else match
                        param_type = match[1] if isinstance(match, tuple) and len(match) > 1 else 'text'
                        
                        # Check if it's hidden field
                        is_hidden = 'hidden' in pattern.lower() if isinstance(match, tuple) else False
                        
                        results['form_parameters'].append({
                            'parameter': param_name,
                            'type': param_type,
                            'is_hidden': is_hidden,
                            'source': 'html_form_analysis',
                            'risk_level': self._assess_parameter_risk(param_name)
                        })
                        print(f"   ✅ Form parameter found: {param_name} ({param_type})")
                
                # Extract GET/POST forms
                form_actions = re.findall(r'<form[^>]*action=["\']([^"\']*)["\'][^>]*method=["\']([^"\']*)["\'][^>]*>', content, re.IGNORECASE)
                for action, method in form_actions:
                    results['form_parameters'].append({
                        'parameter': f"form_action_{action}",
                        'type': 'form_action',
                        'method': method.upper(),
                        'action': action,
                        'source': 'html_form_analysis',
                        'risk_level': 'medium'
                    })
                    print(f"   ✅ Form action found: {action} ({method})")
                
            except Exception as e:
                results['errors'].append(f"Form parameters discovery failed: {str(e)}")
            
            results['end_time'] = datetime.now().isoformat()
            results['status'] = 'completed'
            results['summary'] = f"Found {len(results['parameters_found'])} parameters, {len(results['endpoints_found'])} endpoints, {len(results['secrets'])} secrets"
            
            print(f"   ✅ Phase 6 completed: {results['summary']}")
            return results
            
        except Exception as e:
            results['errors'].append(f"Phase 6 failed: {str(e)}")
            results['status'] = 'error'
            print(f"   ❌ Phase 6 failed: {e}")
            return results
    
    def _assess_parameter_risk(self, parameter: str) -> str:
        """Assess risk level of a parameter"""
        high_risk_keywords = ['password', 'passwd', 'secret', 'key', 'token', 'auth', 'admin', 'root']
        medium_risk_keywords = ['id', 'user', 'email', 'phone', 'session', 'csrf']
        
        param_lower = parameter.lower()
        
        if any(keyword in param_lower for keyword in high_risk_keywords):
            return 'high'
        elif any(keyword in param_lower for keyword in medium_risk_keywords):
            return 'medium'
        else:
            return 'low'
    
    def _is_paramspider_available(self) -> bool:
        """Check if paramspider is available"""
        if platform_manager:
            return platform_manager.is_tool_available('paramspider') or platform_manager.is_tool_available('python3')
        
        # Fallback for older versions
        try:
            subprocess.run(['paramspider', '--help'], capture_output=True, timeout=5)
            return True
        except:
            try:
                subprocess.run(['python3', '-c', 'import paramspider'], capture_output=True, timeout=5)
                return True
            except:
                return False
    
    def _run_paramspider(self, target: str) -> Dict[str, Any]:
        """Run paramspider if available"""
        try:
            # Try different paramspider commands
            commands = [
                ['python3', '-m', 'paramspider', '-d', target, '--quiet'],
                ['paramspider', '-d', target, '--quiet'],
                ['python3', 'paramspider.py', '-d', target, '--quiet']
            ]
            
            for cmd in commands:
                try:
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                    
                    if result.returncode == 0 and result.stdout:
                        # Parse paramspider output to extract parameters
                        parameters = []
                        lines = result.stdout.split('\n')
                        for line in lines:
                            line = line.strip()
                            if line and ('?' in line or '=' in line):
                                # Extract parameters from URLs
                                if '?' in line:
                                    url_part = line.split('?')[1]
                                    if '&' in url_part:
                                        params = url_part.split('&')
                                    else:
                                        params = [url_part]
                                    
                                    for param in params:
                                        if '=' in param:
                                            param_name = param.split('=')[0]
                                            if param_name not in parameters:
                                                parameters.append(param_name)
                        
                        return {
                            'stdout': result.stdout,
                            'stderr': result.stderr,
                            'success': True,
                            'parameters': parameters,
                            'tool_results': {
                                'parameters': parameters,
                                'output': result.stdout
                            }
                        }
                except:
                    continue
                    
        except Exception as e:
            return {'success': False, 'error': str(e), 'tool': 'paramspider'}
        
        return {'success': False, 'error': 'No results', 'tool': 'paramspider'}
    
    def _is_x8_available(self) -> bool:
        """Check if x8 is available"""
        try:
            subprocess.run(['x8', '--help'], capture_output=True, timeout=5)
            return True
        except:
            return False
    
    def _run_x8(self, target: str) -> Dict[str, Any]:
        """Run x8 if available"""
        try:
            # Try different wordlist paths
            wordlist_paths = [
                '/workspace/wordlists/assetnote_parameters.txt',
                '/usr/share/wordlists/assetnote_parameters.txt',
                '/opt/wordlists/assetnote_parameters.txt'
            ]
            
            wordlist = None
            for path in wordlist_paths:
                if os.path.exists(path):
                    wordlist = path
                    break
            
            if wordlist:
                cmd = ['x8', '-u', f"https://{target}", '-w', wordlist, '--quiet', '-o', '/tmp/x8_output.txt']
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                
                # Read output file if it exists
                output_content = ""
                if os.path.exists('/tmp/x8_output.txt'):
                    with open('/tmp/x8_output.txt', 'r') as f:
                        output_content = f.read()
                    os.remove('/tmp/x8_output.txt')
                
                if result.returncode == 0 or output_content:
                    return {
                        'stdout': result.stdout + output_content,
                        'stderr': result.stderr,
                        'success': True,
                        'wordlist_used': wordlist
                    }
            else:
                # Fallback to default x8 run
                cmd = ['x8', '-u', f"https://{target}", '--quiet', '-o', '/tmp/x8_output.txt']
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                
                # Read output file if it exists
                output_content = ""
                if os.path.exists('/tmp/x8_output.txt'):
                    with open('/tmp/x8_output.txt', 'r') as f:
                        output_content = f.read()
                    os.remove('/tmp/x8_output.txt')
                
                if result.returncode == 0 or output_content:
                    return {
                        'stdout': result.stdout + output_content,
                        'stderr': result.stderr,
                        'success': True,
                        'wordlist_used': 'default'
                    }
        except Exception as e:
            print(f"   ❌ x8 error: {e}")
        return None
    
    def _run_wayback_machine(self, target: str) -> Dict[str, Any]:
        """Run wayback machine analysis"""
        try:
            wayback_url = f"http://web.archive.org/cdx/search/cdx?url={target}/*&output=json&fl=original&collapse=urlkey"
            response = requests.get(wayback_url, headers=self.headers, timeout=30)
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    urls = []
                    for item in data[1:]:  # Skip header
                        if item and len(item) > 0:
                            urls.append(item[0])
                    
                    return {
                        'urls_found': len(urls),
                        'sample_urls': urls[:10],
                        'success': True
                    }
                except:
                    pass
        except:
            pass
        return None

if __name__ == "__main__":
    phase = Phase6ParameterDiscovery()
    result = phase.run_phase("example.com")
    print(json.dumps(result, indent=2))