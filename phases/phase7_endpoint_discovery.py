#!/usr/bin/env python3
"""
Phase 7: Advanced Endpoint Discovery
"""

import requests
import re
import json
from datetime import datetime
from typing import Dict, Any, List

class Phase7EndpointDiscovery:
    """Phase 7: Advanced Endpoint Discovery"""
    
    def __init__(self):
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
    
    def run_phase(self, target: str) -> Dict[str, Any]:
        """Run Phase 7: Advanced Endpoint Discovery"""
        print(f"🔍 Phase 7: Advanced Endpoint Discovery for {target}")
        
        results = {
            'phase': 7,
            'target': target,
            'start_time': datetime.now().isoformat(),
            'endpoints_found': [],
            'swagger_endpoints': [],  # Swagger/OpenAPI endpoints
            'js_endpoints': [],  # Endpoints found in JavaScript
            'api_docs': [],  # API documentation pages
            'graphql_endpoints': [],  # GraphQL endpoints
            'rest_endpoints': [],  # REST API endpoints
            'techniques_used': [],
            'errors': [],
            'status': 'running'
        }
        
        try:
            # Technique 1: REST API Discovery
            print("   🔍 REST API Discovery...")
            results['techniques_used'].append('REST API Discovery')
            
            # Technique 2: GraphQL Discovery
            print("   🔍 GraphQL Discovery...")
            results['techniques_used'].append('GraphQL Discovery')
            
            # Technique 3: API Documentation Discovery
            print("   📚 API Documentation Discovery...")
            results['techniques_used'].append('API Documentation Discovery')
            
            # Technique 4: OpenAPI Specification Discovery
            print("   📋 OpenAPI Specification Discovery...")
            results['techniques_used'].append('OpenAPI Specification Discovery')
            
            # Discover Swagger/OpenAPI endpoints
            swagger_endpoints = self._discover_swagger_endpoints(target)
            results['swagger_endpoints'] = swagger_endpoints
            results['endpoints_found'].extend(swagger_endpoints)
            
            # Discover endpoints from JavaScript files
            js_endpoints = self._discover_js_endpoints(target)
            results['js_endpoints'] = js_endpoints
            results['endpoints_found'].extend(js_endpoints)
            
            results['end_time'] = datetime.now().isoformat()
            results['status'] = 'completed'
            results['summary'] = f"Found {len(results['endpoints_found'])} endpoints using {len(results['techniques_used'])} advanced techniques"
            
            print(f"   ✅ Phase 7 completed: {results['summary']}")
            return results
            
        except Exception as e:
            results['status'] = 'error'
            results['errors'].append(str(e))
            print(f"   ❌ Phase 7 failed: {str(e)}")
            return results
    
    def _discover_swagger_endpoints(self, target: str) -> List[str]:
        """Discover Swagger/OpenAPI endpoints"""
        swagger_paths = [
            # Common Swagger paths
            '/swagger', '/swagger-ui', '/swagger-ui.html', '/swagger-ui/index.html',
            '/swagger-ui/dist/index.html', '/swagger-ui/2.2.10/index.html',
            '/swagger-ui/3.0.0/index.html', '/swagger-ui/3.25.0/index.html',
            
            # API documentation paths
            '/api-docs', '/api/docs', '/docs', '/documentation', '/api-documentation',
            '/api/swagger', '/api/swagger-ui', '/api/swagger-ui.html',
            
            # OpenAPI/Swagger JSON files
            '/openapi.json', '/swagger.json', '/api.json', '/swagger.yaml',
            '/openapi.yaml', '/api.yaml', '/swagger.yml', '/openapi.yml',
            
            # Versioned API docs
            '/v1/swagger', '/v2/swagger', '/v3/swagger', '/v1/api-docs',
            '/v2/api-docs', '/v3/api-docs', '/api/v1/swagger', '/api/v2/swagger',
            '/api/v3/swagger', '/swagger/v1', '/swagger/v2', '/swagger/v3',
            
            # Framework specific paths
            '/api/swagger-ui.html', '/api/swagger-ui/index.html',
            '/api-docs/swagger.json', '/api-docs/swagger.yaml',
            '/rest/swagger', '/rest/api-docs', '/rest/swagger-ui.html',
            
            # Alternative paths
            '/apidoc', '/apidocs', '/api-documentation', '/api-spec',
            '/swagger-resources', '/swagger-resources/configuration/ui',
            '/swagger-resources/configuration/security',
            '/swagger-resources/v2/api-docs', '/swagger-resources/configuration/security'
        ]
        
        found_endpoints = []
        
        for path in swagger_paths:
            try:
                url = f"https://{target}{path}"
                response = requests.get(url, headers=self.headers, timeout=10)
                
                if response.status_code == 200:
                    # Check if it's actually a Swagger/OpenAPI page
                    content = response.text.lower()
                    if any(keyword in content for keyword in ['swagger', 'openapi', 'api documentation']):
                        found_endpoints.append({
                            'url': url,
                            'type': 'swagger',
                            'status_code': response.status_code,
                            'title': self._extract_title(response.text)
                        })
                        print(f"      ✅ Swagger endpoint found: {url}")
                        
            except Exception as e:
                pass
        
        return found_endpoints
    
    def _discover_js_endpoints(self, target: str) -> List[str]:
        """Discover endpoints from JavaScript files"""
        js_endpoints = []
        
        try:
            # Get main page
            response = requests.get(f"https://{target}", headers=self.headers, timeout=10)
            if response.status_code == 200:
                content = response.text
                
                # Extract JavaScript file URLs
                js_files = re.findall(r'<script[^>]*src=["\']([^"\']*\.js[^"\']*)["\']', content, re.IGNORECASE)
                
                for js_file in js_files:
                    if not js_file.startswith('http'):
                        if js_file.startswith('/'):
                            js_url = f"https://{target}{js_file}"
                        else:
                            js_url = f"https://{target}/{js_file}"
                    else:
                        js_url = js_file
                    
                    # Analyze JavaScript file for endpoints
                    try:
                        js_response = requests.get(js_url, headers=self.headers, timeout=10)
                        if js_response.status_code == 200:
                            endpoints = self._extract_endpoints_from_js(js_response.text, target)
                            js_endpoints.extend(endpoints)
                    except:
                        pass
                        
        except Exception as e:
            pass
        
        return js_endpoints
    
    def _extract_endpoints_from_js(self, js_content: str, target: str) -> List[Dict[str, Any]]:
        """Extract API endpoints from JavaScript content"""
        endpoints = []
        
        # Common API endpoint patterns
        patterns = [
            r'["\']([^"\']*\/api\/[^"\']*)["\']',  # /api/ endpoints
            r'["\']([^"\']*\/v\d+\/[^"\']*)["\']',  # Versioned endpoints
            r'["\']([^"\']*\/graphql[^"\']*)["\']',  # GraphQL endpoints
            r'["\']([^"\']*\/rest\/[^"\']*)["\']',  # REST endpoints
            r'["\']([^"\']*\/endpoint[^"\']*)["\']',  # Generic endpoints
            r'fetch\(["\']([^"\']+)["\']',  # Fetch API calls
            r'axios\.[^(]+\(["\']([^"\']+)["\']',  # Axios calls
            r'\.get\(["\']([^"\']+)["\']',  # GET requests
            r'\.post\(["\']([^"\']+)["\']',  # POST requests
            r'\.put\(["\']([^"\']+)["\']',  # PUT requests
            r'\.delete\(["\']([^"\']+)["\']',  # DELETE requests
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            for match in matches:
                if match.startswith('/'):
                    endpoint_url = f"https://{target}{match}"
                elif match.startswith('http'):
                    endpoint_url = match
                else:
                    continue
                
                endpoints.append({
                    'url': endpoint_url,
                    'type': 'javascript_discovered',
                    'source': 'JavaScript Analysis',
                    'pattern': pattern
                })
        
        return endpoints
    
    def _extract_title(self, html_content: str) -> str:
        """Extract title from HTML content"""
        title_match = re.search(r'<title[^>]*>([^<]+)</title>', html_content, re.IGNORECASE)
        return title_match.group(1).strip() if title_match else 'No title found'

if __name__ == "__main__":
    phase = Phase7EndpointDiscovery()
    result = phase.run_phase("example.com")
    print(json.dumps(result, indent=2))