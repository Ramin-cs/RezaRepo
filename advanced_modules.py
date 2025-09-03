#!/usr/bin/env python3
"""
Advanced Modules for Web Reconnaissance Tool
Additional specialized modules for comprehensive information gathering
"""

import requests
import json
import re
import socket
import ssl
import hashlib
import base64
import subprocess
import os
import threading
import time
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
import concurrent.futures

class AdvancedSubdomainDiscovery:
    """Advanced subdomain discovery techniques"""
    
    def __init__(self, session, logger, target_domain):
        self.session = session
        self.logger = logger
        self.target_domain = target_domain

    def discover_via_shodan(self, api_key=None):
        """Discover subdomains via Shodan API"""
        if not api_key:
            return []
        
        try:
            url = f"https://api.shodan.io/dns/domain/{self.target_domain}?key={api_key}"
            response = self.session.get(url, timeout=15)
            
            if response.status_code == 200:
                data = response.json()
                subdomains = []
                for subdomain in data.get('subdomains', []):
                    full_domain = f"{subdomain}.{self.target_domain}"
                    subdomains.append(full_domain)
                return subdomains
        except Exception as e:
            self.logger.error(f"Shodan API error: {str(e)}")
        
        return []

    def discover_via_virustotal(self, api_key=None):
        """Discover subdomains via VirusTotal API"""
        if not api_key:
            return []
        
        try:
            url = f"https://www.virustotal.com/vtapi/v2/domain/report"
            params = {'apikey': api_key, 'domain': self.target_domain}
            response = self.session.get(url, params=params, timeout=15)
            
            if response.status_code == 200:
                data = response.json()
                return data.get('subdomains', [])
        except Exception as e:
            self.logger.error(f"VirusTotal API error: {str(e)}")
        
        return []

    def discover_via_security_trails(self, api_key=None):
        """Discover subdomains via SecurityTrails API"""
        if not api_key:
            return []
        
        try:
            url = f"https://api.securitytrails.com/v1/domain/{self.target_domain}/subdomains"
            headers = {'APIKEY': api_key}
            response = self.session.get(url, headers=headers, timeout=15)
            
            if response.status_code == 200:
                data = response.json()
                subdomains = []
                for subdomain in data.get('subdomains', []):
                    full_domain = f"{subdomain}.{self.target_domain}"
                    subdomains.append(full_domain)
                return subdomains
        except Exception as e:
            self.logger.error(f"SecurityTrails API error: {str(e)}")
        
        return []

class AdvancedParameterExtraction:
    """Advanced parameter extraction techniques"""
    
    def __init__(self, session, logger, target_domain):
        self.session = session
        self.logger = logger
        self.target_domain = target_domain

    def extract_from_swagger_docs(self):
        """Extract parameters from Swagger/OpenAPI documentation"""
        swagger_paths = [
            '/swagger.json', '/swagger.yaml', '/swagger-ui.html',
            '/api-docs', '/api/docs', '/docs', '/documentation',
            '/openapi.json', '/openapi.yaml', '/api/swagger.json'
        ]
        
        parameters = set()
        
        for path in swagger_paths:
            try:
                url = f"https://{self.target_domain}{path}"
                response = self.session.get(url, timeout=10)
                
                if response.status_code == 200:
                    content = response.text
                    
                    # Try to parse as JSON
                    try:
                        swagger_data = json.loads(content)
                        self.extract_params_from_swagger(swagger_data, parameters)
                    except:
                        # Try regex patterns for YAML or malformed JSON
                        param_patterns = [
                            r'parameters?:\s*\[\s*{[^}]*name:\s*["\']([^"\']+)["\']',
                            r'["\']([a-zA-Z_][a-zA-Z0-9_]*)["\']:\s*{[^}]*type:',
                            r'properties:\s*{[^}]*["\']([a-zA-Z_][a-zA-Z0-9_]*)["\']'
                        ]
                        
                        for pattern in param_patterns:
                            matches = re.findall(pattern, content)
                            parameters.update(matches)
                            
            except Exception as e:
                continue
        
        return parameters

    def extract_params_from_swagger(self, swagger_data, parameters):
        """Extract parameters from parsed Swagger data"""
        if isinstance(swagger_data, dict):
            # Check paths
            paths = swagger_data.get('paths', {})
            for path, methods in paths.items():
                if isinstance(methods, dict):
                    for method, details in methods.items():
                        if isinstance(details, dict):
                            # Extract parameters
                            params = details.get('parameters', [])
                            for param in params:
                                if isinstance(param, dict) and 'name' in param:
                                    parameters.add(param['name'])
                            
                            # Extract request body properties
                            request_body = details.get('requestBody', {})
                            if isinstance(request_body, dict):
                                content = request_body.get('content', {})
                                for content_type, schema_info in content.items():
                                    schema = schema_info.get('schema', {})
                                    self.extract_schema_properties(schema, parameters)

    def extract_schema_properties(self, schema, parameters):
        """Extract properties from schema definitions"""
        if isinstance(schema, dict):
            properties = schema.get('properties', {})
            for prop_name in properties.keys():
                parameters.add(prop_name)
            
            # Check nested schemas
            for key in ['allOf', 'oneOf', 'anyOf']:
                if key in schema:
                    for nested_schema in schema[key]:
                        self.extract_schema_properties(nested_schema, parameters)

    def extract_from_graphql_introspection(self):
        """Extract parameters from GraphQL introspection"""
        graphql_endpoints = ['/graphql', '/api/graphql', '/v1/graphql', '/query']
        
        parameters = set()
        
        introspection_query = {
            "query": """
            query IntrospectionQuery {
              __schema {
                types {
                  name
                  fields {
                    name
                    args {
                      name
                      type {
                        name
                      }
                    }
                  }
                }
              }
            }
            """
        }
        
        for endpoint in graphql_endpoints:
            try:
                url = f"https://{self.target_domain}{endpoint}"
                response = self.session.post(
                    url, 
                    json=introspection_query,
                    headers={'Content-Type': 'application/json'},
                    timeout=10
                )
                
                if response.status_code == 200:
                    data = response.json()
                    schema = data.get('data', {}).get('__schema', {})
                    types = schema.get('types', [])
                    
                    for type_info in types:
                        fields = type_info.get('fields', [])
                        for field in fields:
                            if field.get('name'):
                                parameters.add(field['name'])
                            
                            args = field.get('args', [])
                            for arg in args:
                                if arg.get('name'):
                                    parameters.add(arg['name'])
                                    
            except Exception as e:
                continue
        
        return parameters

class AdvancedIPDiscovery:
    """Advanced real IP discovery techniques"""
    
    def __init__(self, session, logger, target_domain):
        self.session = session
        self.logger = logger
        self.target_domain = target_domain

    def discover_via_favicon_shodan(self, favicon_hash):
        """Discover IPs via Shodan favicon search"""
        # Note: Requires Shodan API key
        # This is a placeholder for the actual implementation
        ips = set()
        
        try:
            # In real implementation, you would use Shodan API:
            # https://api.shodan.io/shodan/host/search?key=API_KEY&query=http.favicon.hash:HASH
            self.logger.info(f"Searching Shodan for favicon hash: {favicon_hash}")
        except Exception as e:
            self.logger.error(f"Shodan favicon search failed: {str(e)}")
        
        return ips

    def discover_via_censys(self, api_id=None, api_secret=None):
        """Discover IPs via Censys API"""
        if not api_id or not api_secret:
            return set()
        
        ips = set()
        
        try:
            # Censys API search
            url = "https://search.censys.io/api/v2/hosts/search"
            auth = (api_id, api_secret)
            
            # Search for certificates containing the domain
            query = f"services.tls.certificates.leaf_data.subject.common_name:{self.target_domain}"
            
            params = {'q': query, 'per_page': 100}
            response = self.session.get(url, auth=auth, params=params, timeout=15)
            
            if response.status_code == 200:
                data = response.json()
                results = data.get('result', {}).get('hits', [])
                
                for result in results:
                    ip = result.get('ip')
                    if ip:
                        ips.add(ip)
                        
        except Exception as e:
            self.logger.error(f"Censys search failed: {str(e)}")
        
        return ips

    def discover_via_dns_history(self):
        """Discover historical IPs via DNS history"""
        ips = set()
        
        # Check multiple DNS history sources
        history_sources = [
            f"https://api.hackertarget.com/hostsearch/?q={self.target_domain}",
            f"https://dns.bufferover.run/dns?q={self.target_domain}"
        ]
        
        for source in history_sources:
            try:
                response = self.session.get(source, timeout=15)
                if response.status_code == 200:
                    content = response.text
                    
                    # Extract IP addresses from response
                    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
                    found_ips = re.findall(ip_pattern, content)
                    ips.update(found_ips)
                    
            except Exception as e:
                continue
        
        return ips

    def discover_via_ssl_certificate_transparency(self):
        """Discover IPs via SSL certificate transparency logs"""
        ips = set()
        
        try:
            # Get certificates from crt.sh
            url = f"https://crt.sh/?q={self.target_domain}&output=json"
            response = self.session.get(url, timeout=30)
            
            if response.status_code == 200:
                certificates = response.json()
                
                # For each certificate, try to resolve the IP
                for cert in certificates[:10]:  # Limit to first 10 for performance
                    common_name = cert.get('common_name', '')
                    if common_name and self.target_domain in common_name:
                        try:
                            ip = socket.gethostbyname(common_name)
                            ips.add(ip)
                        except:
                            continue
                            
        except Exception as e:
            self.logger.error(f"Certificate transparency search failed: {str(e)}")
        
        return ips

class AdvancedFileDiscovery:
    """Advanced sensitive file discovery"""
    
    def __init__(self, session, logger, target_domain):
        self.session = session
        self.logger = logger
        self.target_domain = target_domain

    def discover_git_exposed_files(self):
        """Discover exposed Git files and extract information"""
        git_files = [
            '.git/config', '.git/HEAD', '.git/index', '.git/packed-refs',
            '.git/logs/HEAD', '.git/logs/refs/heads/master', '.git/logs/refs/heads/main',
            '.git/refs/heads/master', '.git/refs/heads/main', '.git/refs/heads/develop',
            '.git/objects/info/packs', '.git/info/refs'
        ]
        
        found_files = []
        
        for git_file in git_files:
            try:
                url = f"https://{self.target_domain}/{git_file}"
                response = self.session.get(url, timeout=10)
                
                if response.status_code == 200:
                    found_files.append({
                        'file': git_file,
                        'url': url,
                        'content': response.text[:500],  # First 500 chars
                        'size': len(response.content)
                    })
                    self.logger.success(f"Found Git file: {git_file}")
                    
            except Exception as e:
                continue
        
        return found_files

    def discover_docker_files(self):
        """Discover Docker-related files"""
        docker_files = [
            'Dockerfile', 'docker-compose.yml', 'docker-compose.yaml',
            '.dockerignore', 'docker-compose.override.yml',
            'docker-compose.prod.yml', 'docker-compose.dev.yml'
        ]
        
        found_files = []
        
        for docker_file in docker_files:
            try:
                url = f"https://{self.target_domain}/{docker_file}"
                response = self.session.get(url, timeout=10)
                
                if response.status_code == 200:
                    found_files.append({
                        'file': docker_file,
                        'url': url,
                        'content': response.text
                    })
                    self.logger.success(f"Found Docker file: {docker_file}")
                    
            except Exception as e:
                continue
        
        return found_files

    def discover_cloud_config_files(self):
        """Discover cloud configuration files"""
        cloud_files = [
            # AWS
            '.aws/credentials', '.aws/config', 'aws-exports.js',
            # Azure
            'azure-pipelines.yml', '.azure/config',
            # Google Cloud
            'gcloud-service-key.json', 'google-credentials.json',
            # Kubernetes
            'kubernetes.yaml', 'k8s.yaml', 'deployment.yaml',
            # Terraform
            'terraform.tfvars', 'terraform.tf', 'main.tf',
            # Ansible
            'ansible.cfg', 'playbook.yml', 'inventory.ini'
        ]
        
        found_files = []
        
        for cloud_file in cloud_files:
            try:
                url = f"https://{self.target_domain}/{cloud_file}"
                response = self.session.get(url, timeout=10)
                
                if response.status_code == 200:
                    found_files.append({
                        'file': cloud_file,
                        'url': url,
                        'content': response.text[:1000]  # First 1000 chars
                    })
                    self.logger.success(f"Found cloud config: {cloud_file}")
                    
            except Exception as e:
                continue
        
        return found_files

class AdvancedTechnologyDetection:
    """Advanced technology detection and fingerprinting"""
    
    def __init__(self, session, logger, target_domain):
        self.session = session
        self.logger = logger
        self.target_domain = target_domain

    def detect_cms_and_frameworks(self):
        """Detect CMS and frameworks using multiple techniques"""
        technologies = set()
        
        try:
            main_url = f"https://{self.target_domain}"
            response = self.session.get(main_url, timeout=15)
            
            if response.status_code == 200:
                content = response.text.lower()
                headers = response.headers
                
                # CMS Detection patterns
                cms_patterns = {
                    'WordPress': [
                        r'wp-content', r'wp-includes', r'wordpress',
                        r'/wp-admin/', r'wp-json'
                    ],
                    'Drupal': [
                        r'drupal', r'/sites/default/files', r'/core/',
                        r'drupal\.settings', r'drupal\.behaviors'
                    ],
                    'Joomla': [
                        r'joomla', r'/components/', r'/modules/',
                        r'joomla\.', r'/administrator/'
                    ],
                    'Magento': [
                        r'magento', r'/skin/frontend/', r'mage/',
                        r'magento_', r'/js/mage/'
                    ],
                    'Shopify': [
                        r'shopify', r'cdn\.shopify\.com', r'myshopify\.com',
                        r'shopify\.', r'liquid'
                    ],
                    'PrestaShop': [
                        r'prestashop', r'/modules/ps_', r'prestashop_',
                        r'/themes/classic/'
                    ]
                }
                
                # Framework Detection patterns
                framework_patterns = {
                    'Laravel': [
                        r'laravel_token', r'laravel framework', r'/vendor/laravel/',
                        r'csrf-token', r'laravel_session'
                    ],
                    'CodeIgniter': [
                        r'codeigniter', r'ci_session', r'/application/',
                        r'ci_controller'
                    ],
                    'Symfony': [
                        r'symfony', r'symfony\\', r'_profiler',
                        r'/bundles/'
                    ],
                    'Django': [
                        r'django', r'csrftoken', r'django\.', r'/static/admin/'
                    ],
                    'Flask': [
                        r'flask', r'werkzeug', r'flask_', r'jinja2'
                    ],
                    'Express.js': [
                        r'express', r'x-powered-by.*express', r'connect\.sid'
                    ],
                    'Spring Boot': [
                        r'spring', r'whitelabel error page', r'/actuator/',
                        r'spring framework'
                    ],
                    'ASP.NET': [
                        r'asp\.net', r'__viewstate', r'__dopostback',
                        r'aspnetcdn'
                    ],
                    'React': [
                        r'react', r'reactjs', r'react-dom', r'jsx'
                    ],
                    'Vue.js': [
                        r'vue\.js', r'vuejs', r'vue-', r'v-if'
                    ],
                    'Angular': [
                        r'angular', r'ng-', r'angularjs', r'@angular'
                    ]
                }
                
                # Check all patterns
                all_patterns = {**cms_patterns, **framework_patterns}
                
                for tech, patterns in all_patterns.items():
                    for pattern in patterns:
                        if re.search(pattern, content):
                            technologies.add(tech)
                            break
                
                # Check headers for additional info
                server = headers.get('Server', '').lower()
                if 'nginx' in server:
                    technologies.add('Nginx')
                elif 'apache' in server:
                    technologies.add('Apache')
                elif 'iis' in server:
                    technologies.add('IIS')
                
                powered_by = headers.get('X-Powered-By', '').lower()
                if powered_by:
                    technologies.add(f"X-Powered-By: {powered_by}")
                
        except Exception as e:
            self.logger.error(f"Technology detection failed: {str(e)}")
        
        return technologies

    def detect_waf_and_security_solutions(self):
        """Detect WAF and security solutions"""
        security_solutions = set()
        
        try:
            main_url = f"https://{self.target_domain}"
            response = self.session.get(main_url, timeout=15)
            
            headers = response.headers
            
            # WAF detection patterns
            waf_headers = {
                'Cloudflare': ['cf-ray', 'cf-cache-status', '__cfduid'],
                'AWS CloudFront': ['x-amz-cf-id', 'x-amz-cf-pop'],
                'Akamai': ['akamai-ghost-ip', 'akamai-grn'],
                'Incapsula': ['x-iinfo', 'incap_ses'],
                'Sucuri': ['x-sucuri-id', 'x-sucuri-cache'],
                'ModSecurity': ['mod_security', 'modsecurity'],
                'F5 BIG-IP': ['f5-ltm-pool', 'bigipserver'],
                'Barracuda': ['barra', 'barracuda'],
                'Fortinet': ['fortigate', 'fortiweb']
            }
            
            for waf, header_patterns in waf_headers.items():
                for pattern in header_patterns:
                    for header_name, header_value in headers.items():
                        if pattern.lower() in header_name.lower() or pattern.lower() in str(header_value).lower():
                            security_solutions.add(waf)
                            break
            
            # Check response content for WAF signatures
            content = response.text.lower()
            content_patterns = {
                'Cloudflare': ['cloudflare', 'cf-ray'],
                'AWS WAF': ['aws', 'request blocked'],
                'Imperva': ['imperva', 'incapsula'],
                'Akamai': ['akamai', 'ghost']
            }
            
            for waf, patterns in content_patterns.items():
                if any(pattern in content for pattern in patterns):
                    security_solutions.add(waf)
                    
        except Exception as e:
            self.logger.error(f"WAF detection failed: {str(e)}")
        
        return security_solutions

class AdvancedVulnerabilityScanning:
    """Advanced vulnerability scanning capabilities"""
    
    def __init__(self, session, logger, target_domain):
        self.session = session
        self.logger = logger
        self.target_domain = target_domain

    def scan_for_common_vulnerabilities(self):
        """Scan for common web vulnerabilities"""
        vulnerabilities = []
        
        # SQL Injection test payloads
        sql_payloads = ["'", '"', "1'", "1\"", "' OR '1'='1", "\" OR \"1\"=\"1"]
        
        # XSS test payloads
        xss_payloads = ["<script>alert(1)</script>", "javascript:alert(1)", "<img src=x onerror=alert(1)>"]
        
        # Command injection payloads
        cmd_payloads = [";ls", "&&ls", "|ls", "`ls`", "$(ls)"]
        
        # Test common vulnerable parameters
        test_params = ['id', 'user', 'search', 'q', 'query', 'page', 'file', 'path']
        
        for param in test_params:
            # Test SQL injection
            for payload in sql_payloads[:2]:  # Limit payloads for demo
                try:
                    test_url = f"https://{self.target_domain}/?{param}={payload}"
                    response = self.session.get(test_url, timeout=5)
                    
                    # Check for SQL error messages
                    sql_errors = [
                        'mysql', 'sql syntax', 'ora-', 'postgresql',
                        'sqlite', 'mssql', 'odbc', 'jdbc'
                    ]
                    
                    content = response.text.lower()
                    for error in sql_errors:
                        if error in content:
                            vulnerabilities.append({
                                'type': 'Potential SQL Injection',
                                'parameter': param,
                                'payload': payload,
                                'url': test_url,
                                'evidence': f"Found SQL error: {error}"
                            })
                            break
                            
                except Exception as e:
                    continue
        
        return vulnerabilities

    def scan_for_directory_traversal(self):
        """Scan for directory traversal vulnerabilities"""
        vulnerabilities = []
        
        traversal_payloads = [
            '../../../etc/passwd',
            '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
            '....//....//....//etc/passwd',
            '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd'
        ]
        
        file_params = ['file', 'path', 'page', 'include', 'doc', 'document']
        
        for param in file_params:
            for payload in traversal_payloads[:2]:  # Limit for demo
                try:
                    test_url = f"https://{self.target_domain}/?{param}={payload}"
                    response = self.session.get(test_url, timeout=5)
                    
                    # Check for file content indicators
                    file_indicators = [
                        'root:', '/bin/bash', '/bin/sh', 'daemon:',
                        '[boot loader]', 'windows nt', '# hosts file'
                    ]
                    
                    content = response.text.lower()
                    for indicator in file_indicators:
                        if indicator in content:
                            vulnerabilities.append({
                                'type': 'Potential Directory Traversal',
                                'parameter': param,
                                'payload': payload,
                                'url': test_url,
                                'evidence': f"Found file content: {indicator}"
                            })
                            break
                            
                except Exception as e:
                    continue
        
        return vulnerabilities

class AdvancedNetworkAnalysis:
    """Advanced network analysis capabilities"""
    
    def __init__(self, session, logger, target_domain):
        self.session = session
        self.logger = logger
        self.target_domain = target_domain

    def analyze_ssl_configuration(self):
        """Analyze SSL/TLS configuration"""
        ssl_info = {}
        
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((self.target_domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=self.target_domain) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()
                    
                    ssl_info = {
                        'version': version,
                        'cipher': cipher,
                        'certificate': {
                            'subject': dict(x[0] for x in cert.get('subject', [])),
                            'issuer': dict(x[0] for x in cert.get('issuer', [])),
                            'version': cert.get('version'),
                            'serial_number': cert.get('serialNumber'),
                            'not_before': cert.get('notBefore'),
                            'not_after': cert.get('notAfter'),
                            'signature_algorithm': cert.get('signatureAlgorithm')
                        }
                    }
                    
                    # Check for weak configurations
                    if version in ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']:
                        ssl_info['weakness'] = f"Weak SSL/TLS version: {version}"
                    
                    if cipher and cipher[1] in ['RC4', 'DES', '3DES']:
                        ssl_info['weak_cipher'] = f"Weak cipher: {cipher[1]}"
                        
        except Exception as e:
            self.logger.error(f"SSL analysis failed: {str(e)}")
        
        return ssl_info

    def analyze_http_methods(self):
        """Analyze supported HTTP methods"""
        methods_info = {}
        
        http_methods = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH', 'TRACE']
        
        for method in http_methods:
            try:
                url = f"https://{self.target_domain}/"
                response = self.session.request(method, url, timeout=10)
                
                methods_info[method] = {
                    'status_code': response.status_code,
                    'allowed': response.status_code not in [405, 501]
                }
                
                # Check for dangerous methods
                if method in ['PUT', 'DELETE', 'TRACE'] and response.status_code == 200:
                    methods_info[method]['warning'] = f"Potentially dangerous method {method} is allowed"
                    
            except Exception as e:
                methods_info[method] = {'error': str(e)}
        
        return methods_info

    def check_cors_configuration(self):
        """Check CORS configuration"""
        cors_info = {}
        
        try:
            url = f"https://{self.target_domain}/"
            headers = {'Origin': 'https://evil.com'}
            response = self.session.get(url, headers=headers, timeout=10)
            
            cors_headers = [
                'Access-Control-Allow-Origin',
                'Access-Control-Allow-Credentials',
                'Access-Control-Allow-Methods',
                'Access-Control-Allow-Headers',
                'Access-Control-Expose-Headers',
                'Access-Control-Max-Age'
            ]
            
            for header in cors_headers:
                value = response.headers.get(header)
                if value:
                    cors_info[header] = value
            
            # Check for dangerous CORS configurations
            origin = cors_info.get('Access-Control-Allow-Origin')
            if origin == '*':
                cors_info['warning'] = "Wildcard CORS origin detected - potential security risk"
            elif origin == 'https://evil.com':
                cors_info['warning'] = "CORS reflects arbitrary origins - potential security risk"
                
        except Exception as e:
            self.logger.error(f"CORS analysis failed: {str(e)}")
        
        return cors_info

class AdvancedReportGenerator:
    """Advanced report generation with multiple formats"""
    
    def __init__(self, logger, target_domain, output_dir):
        self.logger = logger
        self.target_domain = target_domain
        self.output_dir = output_dir

    def generate_nuclei_compatible_report(self, data):
        """Generate Nuclei-compatible YAML report"""
        nuclei_template = f"""id: custom-recon-{self.target_domain}

info:
  name: Reconnaissance Results for {self.target_domain}
  author: Advanced Recon Tool
  severity: info
  description: Comprehensive reconnaissance results
  
  metadata:
    subdomains_found: {len(data.get('subdomains', []))}
    parameters_found: {len(data.get('parameters', []))}
    sensitive_files: {len(data.get('sensitive_files', []))}
    
variables:
  target: "{self.target_domain}"

http:
  - method: GET
    path:
      - "{{{{BaseURL}}}}"
    
    matchers:
      - type: status
        status:
          - 200

# Discovered Subdomains:
{chr(10).join(f"# - {sub}" for sub in data.get('subdomains', []))}

# Extracted Parameters:
{chr(10).join(f"# - {param}" for param in data.get('parameters', []))}

# Sensitive Files Found:
"""
        
        for file_info in data.get('sensitive_files', []):
            if isinstance(file_info, dict):
                nuclei_template += f"# - {file_info['file']} (Status: {file_info['status_code']})\n"
        
        nuclei_path = os.path.join(self.output_dir, f"{self.target_domain}_nuclei_template.yaml")
        with open(nuclei_path, 'w', encoding='utf-8') as f:
            f.write(nuclei_template)
        
        return nuclei_path

    def generate_csv_report(self, data):
        """Generate CSV report for spreadsheet analysis"""
        import csv
        
        csv_path = os.path.join(self.output_dir, f"{self.target_domain}_detailed.csv")
        
        with open(csv_path, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            
            # Write subdomains
            writer.writerow(['Type', 'Value', 'Details', 'Status'])
            
            for subdomain in data.get('subdomains', []):
                writer.writerow(['Subdomain', subdomain, 'Discovered subdomain', 'Active'])
            
            for param in data.get('parameters', []):
                writer.writerow(['Parameter', param, 'Extracted parameter', 'Found'])
            
            for file_info in data.get('sensitive_files', []):
                if isinstance(file_info, dict):
                    writer.writerow([
                        'Sensitive File', 
                        file_info['file'], 
                        file_info['url'], 
                        file_info['status_code']
                    ])
            
            for ip in data.get('real_ips', []):
                writer.writerow(['IP Address', ip, 'Resolved IP address', 'Active'])
        
        return csv_path

    def generate_markdown_report(self, data):
        """Generate Markdown report"""
        md_content = f"""# Advanced Reconnaissance Report

## Target Information
- **Domain:** {data['target']}
- **Scan Date:** {data['timestamp']}
- **Subdomains Found:** {len(data.get('subdomains', []))}
- **Parameters Extracted:** {len(data.get('parameters', []))}
- **Sensitive Files:** {len(data.get('sensitive_files', []))}
- **IP Addresses:** {len(data.get('real_ips', []))}

## 🌐 Discovered Subdomains

```
{chr(10).join(data.get('subdomains', []))}
```

## ⚙️ Extracted Parameters

```
{chr(10).join(data.get('parameters', []))}
```

## 🔒 Sensitive Files

| File | Status | URL |
|------|--------|-----|
"""
        
        for file_info in data.get('sensitive_files', []):
            if isinstance(file_info, dict):
                md_content += f"| {file_info['file']} | {file_info['status_code']} | {file_info['url']} |\n"
        
        md_content += f"""

## 🌍 IP Addresses

```
{chr(10).join(data.get('real_ips', []))}
```

## 🛠️ Technologies Detected

```
{chr(10).join(data.get('technologies', []))}
```

## 📊 Security Headers

| Header | Status |
|--------|--------|
"""
        
        for header, value in data.get('security_headers', {}).items():
            status = "✅ Present" if value else "❌ Missing"
            md_content += f"| {header} | {status} |\n"
        
        md_content += f"""

## Additional Information

- **Favicon Hash:** {data.get('favicon_hash', 'Not Found')}
- **WHOIS Registrar:** {data.get('whois_info', {}).get('registrar', 'Unknown')}

---
*Generated by Advanced Recon Tool*
"""
        
        md_path = os.path.join(self.output_dir, f"{self.target_domain}_report.md")
        with open(md_path, 'w', encoding='utf-8') as f:
            f.write(md_content)
        
        return md_path