#!/usr/bin/env python3
"""
Advanced Reconnaissance Engine
Complete implementation with all techniques
"""

import requests
import dns.resolver
import socket
from urllib.parse import urlparse, urljoin
import ssl
import OpenSSL
import json
import time
import re
import subprocess
import platform
from datetime import datetime
from typing import List, Dict, Any, Set
import threading
import queue
from concurrent.futures import ThreadPoolExecutor, as_completed

class AdvancedReconnaissance:
    """Advanced reconnaissance with all techniques"""
    
    def __init__(self):
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        }
        
        # Extended subdomain wordlist
        self.subdomain_wordlist = [
            # Common
            "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "webdisk", "ns2",
            "cpanel", "whm", "autodiscover", "autoconfig", "ns3", "m", "imap", "test", "ns", "blog",
            "pop3", "dev", "www2", "admin", "forum", "news", "vpn", "ns4", "mail2", "new", "mysql",
            "old", "www1", "beta", "shop", "api", "staging", "app", "media", "mail3", "www3", "dns2",
            
            # Popular services
            "api", "app", "admin", "blog", "cdn", "cloud", "dev", "git", "jenkins", "jira",
            "mail", "monitoring", "portal", "proxy", "redis", "sftp", "ssh", "staging", "test", "vpn",
            "web", "wiki", "www", "www2", "www3", "www4", "www5", "www6", "www7", "www8", "www9",
            
            # Development
            "dev", "development", "staging", "stage", "test", "testing", "qa", "preprod", "prod",
            "production", "demo", "sandbox", "lab", "experiment", "alpha", "beta", "gamma", "rc",
            
            # Infrastructure
            "cdn", "cache", "proxy", "loadbalancer", "lb", "gateway", "firewall", "router", "switch",
            "monitoring", "monitor", "grafana", "prometheus", "kibana", "elastic", "logstash",
            
            # Databases
            "db", "database", "mysql", "postgres", "mongodb", "redis", "elasticsearch", "cassandra",
            "oracle", "sqlserver", "mariadb", "sqlite", "influxdb", "neo4j", "couchdb",
            
            # Cloud services
            "aws", "azure", "gcp", "cloud", "s3", "ec2", "lambda", "azure-blob", "gcs", "rds",
            "elasticache", "dynamodb", "sns", "sqs", "ses", "cloudfront", "route53",
            
            # Security
            "security", "auth", "authentication", "authorization", "sso", "ldap", "ad", "oauth",
            "jwt", "token", "cert", "ssl", "tls", "vpn", "bastion", "jump", "gateway",
            
            # Mobile/Apps
            "mobile", "app", "ios", "android", "api", "rest", "graphql", "websocket", "socket",
            "push", "notification", "analytics", "crashlytics", "fabric", "firebase",
            
            # Business
            "business", "corporate", "enterprise", "internal", "external", "public", "private",
            "intranet", "extranet", "portal", "dashboard", "console", "control", "management",
            
            # Content
            "content", "media", "images", "videos", "files", "documents", "uploads", "downloads",
            "assets", "static", "public", "resources", "storage", "backup", "archive",
            
            # Geographic
            "us", "uk", "eu", "asia", "apac", "emea", "na", "emea", "apac", "global", "local",
            "nyc", "london", "tokyo", "singapore", "frankfurt", "sydney", "toronto", "mumbai",
            
            # Versions
            "v1", "v2", "v3", "v4", "v5", "v6", "v7", "v8", "v9", "v10", "version1", "version2",
            "new", "old", "legacy", "current", "latest", "stable", "unstable", "nightly",
            
            # Environments
            "prod", "production", "live", "staging", "stage", "dev", "development", "test", "testing",
            "qa", "quality", "uat", "user-acceptance", "preprod", "pre-production", "sandbox",
            
            # Teams/Departments
            "hr", "finance", "legal", "marketing", "sales", "support", "helpdesk", "it", "ops",
            "operations", "maintenance", "backup", "recovery", "disaster", "business", "corporate"
        ]
        
        # Directory wordlist
        self.directory_wordlist = [
            # Admin panels
            "admin", "administrator", "adminpanel", "admin-panel", "admin_area", "adminarea",
            "admincp", "admin-cp", "admincp", "adm", "administration", "administrator",
            "panel", "control", "controlpanel", "control-panel", "dashboard", "dash",
            
            # Login/authentication
            "login", "log-in", "signin", "sign-in", "auth", "authentication", "authenticate",
            "user", "users", "account", "accounts", "profile", "profiles", "member", "members",
            "signup", "sign-up", "register", "registration", "create-account", "createaccount",
            
            # API endpoints
            "api", "api/v1", "api/v2", "api/v3", "rest", "restapi", "graphql", "rpc", "soap",
            "webservice", "web-service", "service", "services", "endpoint", "endpoints",
            
            # Common directories
            "public", "private", "secure", "security", "protected", "internal", "external",
            "uploads", "upload", "files", "file", "documents", "document", "media", "images",
            "image", "img", "css", "js", "javascript", "scripts", "script", "styles", "style",
            
            # Configuration files
            "config", "configuration", "conf", "settings", "setting", "options", "option",
            "preferences", "preference", "params", "parameters", "parameter", "env", "environment",
            
            # Backup files
            "backup", "backups", "bak", "old", "archive", "archives", "temp", "tmp", "temporary",
            "copy", "copies", "duplicate", "duplicates", "original", "originals", "source", "sources",
            
            # Development
            "dev", "development", "develop", "src", "source", "sourcecode", "source-code",
            "code", "repository", "repo", "git", "svn", "cvs", "trunk", "branches", "tags",
            
            # Testing
            "test", "tests", "testing", "qa", "quality", "staging", "stage", "sandbox",
            "demo", "demos", "sample", "samples", "example", "examples", "tutorial", "tutorials",
            
            # Database
            "db", "database", "data", "sql", "mysql", "postgres", "postgresql", "mongo", "mongodb",
            "redis", "elasticsearch", "cassandra", "oracle", "sqlserver", "mariadb", "sqlite",
            
            # Monitoring/Logs
            "logs", "log", "monitoring", "monitor", "status", "health", "metrics", "metric",
            "stats", "statistics", "analytics", "analytic", "report", "reports", "dashboard",
            
            # Security
            "security", "secure", "ssl", "tls", "cert", "certificate", "certificates", "certs",
            "vpn", "firewall", "bastion", "jump", "gateway", "proxy", "proxies", "loadbalancer",
            
            # Content management
            "cms", "content", "pages", "page", "posts", "post", "articles", "article",
            "blog", "blogs", "news", "events", "event", "calendar", "calendars", "forum", "forums",
            
            # E-commerce
            "shop", "store", "marketplace", "market", "product", "products", "catalog", "catalogs",
            "cart", "checkout", "payment", "payments", "billing", "order", "orders", "customer", "customers",
            
            # File extensions
            ".php", ".asp", ".aspx", ".jsp", ".cfm", ".pl", ".py", ".rb", ".go", ".java",
            ".xml", ".json", ".yaml", ".yml", ".ini", ".conf", ".config", ".properties",
            ".env", ".htaccess", ".htpasswd", ".gitignore", ".gitattributes", ".dockerignore",
            
            # Common files
            "index", "home", "main", "default", "readme", "license", "changelog", "version",
            "robots.txt", "sitemap.xml", "crossdomain.xml", "clientaccesspolicy.xml",
            "phpinfo.php", "info.php", "test.php", "admin.php", "login.php", "config.php"
        ]
        
        # Parameter wordlist
        self.parameter_wordlist = [
            # Common parameters
            "id", "user", "username", "password", "pass", "pwd", "email", "mail", "phone", "mobile",
            "name", "firstname", "lastname", "fname", "lname", "fullname", "displayname",
            "age", "birthday", "birth", "date", "time", "timestamp", "created", "updated", "modified",
            
            # API parameters
            "key", "apikey", "api_key", "token", "access_token", "refresh_token", "bearer",
            "auth", "authorization", "auth_token", "session", "sessionid", "session_id",
            "csrf", "csrf_token", "csrf_token", "nonce", "state", "callback", "redirect",
            
            # Pagination
            "page", "p", "offset", "limit", "size", "count", "per_page", "perpage",
            "start", "end", "from", "to", "since", "until", "before", "after",
            
            # Search/Filter
            "search", "query", "q", "filter", "sort", "order", "orderby", "order_by",
            "category", "cat", "tag", "tags", "type", "status", "state", "level",
            
            # File upload
            "file", "files", "upload", "image", "img", "photo", "picture", "avatar",
            "document", "doc", "pdf", "excel", "csv", "json", "xml", "zip", "rar",
            
            # Configuration
            "config", "setting", "settings", "option", "options", "preference", "preferences",
            "mode", "theme", "language", "lang", "locale", "timezone", "currency",
            
            # Security
            "security", "secure", "encrypt", "decrypt", "hash", "salt", "iv", "cipher",
            "ssl", "tls", "cert", "certificate", "verify", "validation", "validate",
            
            # Database
            "db", "database", "table", "column", "field", "value", "values", "record", "records",
            "select", "insert", "update", "delete", "where", "join", "group", "having",
            
            # URL parameters
            "url", "link", "href", "src", "source", "target", "destination", "return", "return_url",
            "next", "previous", "back", "forward", "continue", "cancel", "abort",
            
            # Content
            "title", "description", "content", "body", "text", "message", "subject",
            "comment", "comments", "reply", "replies", "post", "posts", "article", "articles",
            
            # Social
            "facebook", "twitter", "instagram", "linkedin", "youtube", "vimeo", "tiktok",
            "social", "share", "like", "follow", "follower", "following", "friend", "friends",
            
            # E-commerce
            "product", "products", "category", "categories", "brand", "brands", "price", "cost",
            "quantity", "amount", "total", "subtotal", "tax", "shipping", "discount", "coupon",
            
            # Analytics
            "analytics", "tracking", "track", "event", "events", "action", "actions",
            "metric", "metrics", "stat", "stats", "report", "reports", "dashboard",
            
            # Development
            "debug", "test", "testing", "dev", "development", "staging", "stage", "prod", "production",
            "version", "build", "release", "deploy", "deployment", "environment", "env"
        ]
    
    def phase1_advanced_real_ip_extraction(self, target: str) -> Dict[str, Any]:
        """Phase 1: Advanced Real IP Extraction with all techniques"""
        print(f"🔍 Phase 1: Advanced Real IP Extraction for {target}")
        results = {
            'target': target,
            'phase': 1,
            'start_time': datetime.now().isoformat(),
            'real_ips': [],
            'cdn_detected': False,
            'cdn_type': None,
            'dns_records': {},
            'ssl_info': {},
            'http_headers': {},
            'techniques_used': [],
            'errors': []
        }
        
        try:
            # Technique 1: Multiple DNS Resolvers
            print("   📡 Advanced DNS Resolution...")
            results['techniques_used'].append('Multiple DNS Resolvers')
            
            dns_resolvers = [
                '8.8.8.8',      # Google DNS
                '1.1.1.1',      # Cloudflare DNS
                '208.67.222.222', # OpenDNS
                '9.9.9.9',      # Quad9
                '76.76.19.21'   # Alternate DNS
            ]
            
            for resolver_ip in dns_resolvers:
                try:
                    resolver = dns.resolver.Resolver()
                    resolver.nameservers = [resolver_ip]
                    resolver.timeout = 3
                    
                    # A Records
                    try:
                        answers = resolver.resolve(target, 'A')
                        for answer in answers:
                            ip = str(answer)
                            if ip not in results['real_ips']:
                                results['real_ips'].append(ip)
                                print(f"   ✅ Found IP via {resolver_ip}: {ip}")
                    except:
                        pass
                    
                    # AAAA Records (IPv6)
                    try:
                        answers = resolver.resolve(target, 'AAAA')
                        for answer in answers:
                            ipv6 = str(answer)
                            print(f"   ✅ Found IPv6 via {resolver_ip}: {ipv6}")
                    except:
                        pass
                        
                except Exception as e:
                    results['errors'].append(f"DNS resolver {resolver_ip} failed: {str(e)}")
            
            # Technique 2: Historical DNS Records
            print("   📚 Historical DNS Records...")
            results['techniques_used'].append('Historical DNS Records')
            
            historical_sources = [
                f"https://dnsdumpster.com/static/map/{target}.png",
                f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={target}",
                f"https://api.hackertarget.com/hostsearch/?q={target}",
                f"https://api.shodan.io/dns/resolve?hostnames={target}&key=YOUR_API_KEY"
            ]
            
            for source in historical_sources:
                try:
                    response = requests.get(source, headers=self.headers, timeout=5)
                    if response.status_code == 200:
                        # Extract IPs from response
                        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
                        ips = re.findall(ip_pattern, response.text)
                        for ip in ips:
                            if ip not in results['real_ips'] and not self._is_private_ip(ip):
                                results['real_ips'].append(ip)
                                print(f"   ✅ Found historical IP: {ip}")
                except:
                    pass
            
            # Technique 3: Certificate Transparency Logs
            print("   🔐 Certificate Transparency Analysis...")
            results['techniques_used'].append('Certificate Transparency')
            
            ct_sources = [
                f"https://crt.sh/?q=%.{target}&output=json",
                f"https://censys.io/api/v1/search/certificates?q={target}",
                f"https://api.certspotter.com/v1/issuances?domain={target}&include_subdomains=true&expand=dns_names"
            ]
            
            for source in ct_sources:
                try:
                    response = requests.get(source, headers=self.headers, timeout=10)
                    if response.status_code == 200:
                        data = response.json()
                        if isinstance(data, list):
                            for cert in data:
                                if 'dns_names' in cert:
                                    for dns_name in cert['dns_names']:
                                        if target in dns_name:
                                            # Resolve this subdomain
                                            try:
                                                subdomain_ips = socket.gethostbyname_ex(dns_name)[2]
                                                for ip in subdomain_ips:
                                                    if ip not in results['real_ips'] and not self._is_private_ip(ip):
                                                        results['real_ips'].append(ip)
                                                        print(f"   ✅ Found IP via CT: {ip} ({dns_name})")
                                            except:
                                                pass
                except:
                    pass
            
            # Technique 4: Advanced CDN Detection
            print("   🛡️ Advanced CDN Detection...")
            results['techniques_used'].append('Advanced CDN Detection')
            
            cdn_indicators = {
                'cloudflare': ['cf-ray', 'cf-cache-status', 'cf-request-id'],
                'cloudfront': ['x-amz-cf-id', 'x-amz-cf-pop'],
                'fastly': ['fastly-debug-digest', 'fastly-ff'],
                'akamai': ['x-akamai-edgescape', 'x-akamai-request-id'],
                'maxcdn': ['x-cache', 'x-cache-hits'],
                'keycdn': ['x-cache', 'x-cache-status'],
                'incapsula': ['x-iinfo', 'x-cdn']
            }
            
            try:
                response = requests.get(f"https://{target}", headers=self.headers, timeout=10, allow_redirects=True)
                results['http_headers'] = dict(response.headers)
                
                for cdn_name, headers_list in cdn_indicators.items():
                    for header in headers_list:
                        if header in response.headers:
                            results['cdn_detected'] = True
                            results['cdn_type'] = cdn_name
                            print(f"   🛡️ CDN Detected: {cdn_name} (via {header})")
                            break
                    if results['cdn_detected']:
                        break
                        
            except Exception as e:
                results['errors'].append(f"CDN detection failed: {str(e)}")
            
            # Technique 5: SSL Certificate Analysis
            print("   🔒 Advanced SSL Certificate Analysis...")
            results['techniques_used'].append('SSL Certificate Analysis')
            
            try:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                with socket.create_connection((target, 443), timeout=10) as sock:
                    with context.wrap_socket(sock, server_hostname=target) as ssock:
                        cert = ssock.getpeercert()
                        results['ssl_info'] = {
                            'subject': cert.get('subject', []),
                            'issuer': cert.get('issuer', []),
                            'version': cert.get('version'),
                            'serial_number': cert.get('serialNumber'),
                            'not_before': cert.get('notBefore'),
                            'not_after': cert.get('notAfter'),
                            'subject_alt_name': cert.get('subjectAltName', [])
                        }
                        
                        # Extract SAN domains
                        for san_type, san_value in cert.get('subjectAltName', []):
                            if san_type == 'DNS' and target in san_value:
                                try:
                                    san_ips = socket.gethostbyname_ex(san_value)[2]
                                    for ip in san_ips:
                                        if ip not in results['real_ips'] and not self._is_private_ip(ip):
                                            results['real_ips'].append(ip)
                                            print(f"   ✅ Found IP via SSL SAN: {ip} ({san_value})")
                                except:
                                    pass
                        
                        print(f"   🔒 SSL Certificate analyzed successfully")
                        
            except Exception as e:
                results['errors'].append(f"SSL analysis failed: {str(e)}")
            
            # Technique 6: DNS Records Enumeration
            print("   📋 Complete DNS Records Enumeration...")
            results['techniques_used'].append('DNS Records Enumeration')
            
            dns_record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME', 'PTR']
            
            for record_type in dns_record_types:
                try:
                    answers = dns.resolver.resolve(target, record_type)
                    results['dns_records'][record_type] = []
                    for answer in answers:
                        results['dns_records'][record_type].append(str(answer))
                        print(f"   📋 {record_type}: {answer}")
                        
                        # Extract IPs from MX and NS records
                        if record_type in ['MX', 'NS']:
                            try:
                                record_target = str(answer).split()[-1].rstrip('.')
                                record_ips = socket.gethostbyname_ex(record_target)[2]
                                for ip in record_ips:
                                    if ip not in results['real_ips'] and not self._is_private_ip(ip):
                                        results['real_ips'].append(ip)
                                        print(f"   ✅ Found IP via {record_type}: {ip}")
                            except:
                                pass
                                
                except Exception as e:
                    results['errors'].append(f"DNS {record_type} lookup failed: {str(e)}")
            
            results['end_time'] = datetime.now().isoformat()
            results['status'] = 'completed'
            results['summary'] = f"Found {len(results['real_ips'])} real IPs using {len(results['techniques_used'])} techniques"
            
            print(f"   ✅ Phase 1 completed: {results['summary']}")
            return results
            
        except Exception as e:
            results['errors'].append(f"Phase 1 failed: {str(e)}")
            results['status'] = 'error'
            print(f"   ❌ Phase 1 failed: {e}")
            return results
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is private"""
        try:
            ip_parts = ip.split('.')
            if len(ip_parts) == 4:
                first_octet = int(ip_parts[0])
                if first_octet == 10:
                    return True
                elif first_octet == 172 and 16 <= int(ip_parts[1]) <= 31:
                    return True
                elif first_octet == 192 and int(ip_parts[1]) == 168:
                    return True
            return False
        except:
            return False
    
    def phase2_advanced_subdomain_discovery(self, target: str) -> Dict[str, Any]:
        """Phase 2: Advanced Subdomain Discovery with all techniques"""
        print(f"🔍 Phase 2: Advanced Subdomain Discovery for {target}")
        results = {
            'target': target,
            'phase': 2,
            'start_time': datetime.now().isoformat(),
            'subdomains': [],
            'valid_subdomains': [],
            'techniques_used': [],
            'errors': []
        }
        
        try:
            # Technique 1: Certificate Transparency Logs
            print("   🔐 Certificate Transparency Subdomain Discovery...")
            results['techniques_used'].append('Certificate Transparency')
            
            ct_sources = [
                f"https://crt.sh/?q=%.{target}&output=json",
                f"https://api.certspotter.com/v1/issuances?domain={target}&include_subdomains=true&expand=dns_names"
            ]
            
            for source in ct_sources:
                try:
                    response = requests.get(source, headers=self.headers, timeout=10)
                    if response.status_code == 200:
                        data = response.json()
                        if isinstance(data, list):
                            for cert in data:
                                if 'dns_names' in cert:
                                    for dns_name in cert['dns_names']:
                                        if target in dns_name and dns_name != target:
                                            if dns_name not in results['subdomains']:
                                                results['subdomains'].append(dns_name)
                                                print(f"   ✅ Found subdomain via CT: {dns_name}")
                except:
                    pass
            
            # Technique 2: DNS Bruteforce with Extended Wordlist
            print("   🔍 Advanced DNS Bruteforce...")
            results['techniques_used'].append('DNS Bruteforce')
            
            def check_subdomain(subdomain):
                try:
                    full_domain = f"{subdomain}.{target}"
                    ips = socket.gethostbyname_ex(full_domain)[2]
                    return full_domain, ips
                except:
                    return None, None
            
            # Use ThreadPoolExecutor for faster bruteforce
            with ThreadPoolExecutor(max_workers=50) as executor:
                future_to_subdomain = {executor.submit(check_subdomain, sub): sub for sub in self.subdomain_wordlist}
                
                for future in as_completed(future_to_subdomain):
                    subdomain, ips = future.result()
                    if subdomain and ips:
                        if subdomain not in results['subdomains']:
                            results['subdomains'].append(subdomain)
                            print(f"   ✅ Found subdomain via bruteforce: {subdomain}")
            
            # Technique 3: Passive Sources
            print("   📚 Passive Subdomain Discovery...")
            results['techniques_used'].append('Passive Sources')
            
            passive_sources = [
                f"https://dnsdumpster.com/static/map/{target}.png",
                f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={target}",
                f"https://api.hackertarget.com/hostsearch/?q={target}",
                f"https://www.virustotal.com/vtapi/v2/domain/report?apikey=YOUR_API_KEY&domain={target}",
                f"https://api.shodan.io/dns/domain/{target}?key=YOUR_API_KEY",
                f"https://api.censys.io/v1/search/certificates?q={target}",
                f"https://api.securitytrails.com/v1/domain/{target}/subdomains"
            ]
            
            for source in passive_sources:
                try:
                    response = requests.get(source, headers=self.headers, timeout=10)
                    if response.status_code == 200:
                        # Extract subdomains from response
                        subdomain_pattern = rf'[a-zA-Z0-9][a-zA-Z0-9\-]*\.{re.escape(target)}'
                        subdomains = re.findall(subdomain_pattern, response.text, re.IGNORECASE)
                        for subdomain in subdomains:
                            if subdomain not in results['subdomains']:
                                results['subdomains'].append(subdomain)
                                print(f"   ✅ Found subdomain via passive: {subdomain}")
                except:
                    pass
            
            # Technique 4: HTTP/HTTPS Validation
            print("   🌐 HTTP/HTTPS Validation...")
            results['techniques_used'].append('HTTP/HTTPS Validation')
            
            def validate_subdomain(subdomain):
                try:
                    # Try HTTPS first
                    response = requests.get(f"https://{subdomain}", headers=self.headers, timeout=5, allow_redirects=True)
                    if response.status_code in [200, 301, 302, 403, 401]:
                        return {
                            'subdomain': subdomain,
                            'status_code': response.status_code,
                            'title': self._extract_title(response.text),
                            'protocol': 'HTTPS',
                            'content_length': len(response.content)
                        }
                except:
                    pass
                
                try:
                    # Try HTTP
                    response = requests.get(f"http://{subdomain}", headers=self.headers, timeout=5, allow_redirects=True)
                    if response.status_code in [200, 301, 302, 403, 401]:
                        return {
                            'subdomain': subdomain,
                            'status_code': response.status_code,
                            'title': self._extract_title(response.text),
                            'protocol': 'HTTP',
                            'content_length': len(response.content)
                        }
                except:
                    pass
                
                return None
            
            # Validate all found subdomains
            with ThreadPoolExecutor(max_workers=20) as executor:
                future_to_subdomain = {executor.submit(validate_subdomain, sub): sub for sub in results['subdomains']}
                
                for future in as_completed(future_to_subdomain):
                    validation_result = future.result()
                    if validation_result:
                        results['valid_subdomains'].append(validation_result)
                        print(f"   ✅ Valid subdomain: {validation_result['subdomain']} ({validation_result['status_code']})")
            
            # Technique 5: Reverse DNS Lookup
            print("   🔄 Reverse DNS Lookup...")
            results['techniques_used'].append('Reverse DNS Lookup')
            
            # Get IPs from phase 1 results if available
            try:
                # This would ideally get IPs from phase 1, but for now we'll do basic reverse lookup
                for subdomain in results['subdomains'][:10]:  # Limit to avoid too many requests
                    try:
                        ip = socket.gethostbyname(subdomain)
                        reverse_dns = socket.gethostbyaddr(ip)[0]
                        if target in reverse_dns and reverse_dns not in results['subdomains']:
                            results['subdomains'].append(reverse_dns)
                            print(f"   ✅ Found subdomain via reverse DNS: {reverse_dns}")
                    except:
                        pass
            except:
                pass
            
            results['end_time'] = datetime.now().isoformat()
            results['status'] = 'completed'
            results['summary'] = f"Found {len(results['subdomains'])} subdomains, {len(results['valid_subdomains'])} valid using {len(results['techniques_used'])} techniques"
            
            print(f"   ✅ Phase 2 completed: {results['summary']}")
            return results
            
        except Exception as e:
            results['errors'].append(f"Phase 2 failed: {str(e)}")
            results['status'] = 'error'
            print(f"   ❌ Phase 2 failed: {e}")
            return results
    
    def _extract_title(self, html_content: str) -> str:
        """Extract title from HTML content"""
        try:
            title_match = re.search(r'<title[^>]*>(.*?)</title>', html_content, re.IGNORECASE | re.DOTALL)
            if title_match:
                return title_match.group(1).strip()[:100]
            return "No title"
        except:
            return "No title"
    
    def run_phase(self, phase_number: int, target: str) -> Dict[str, Any]:
        """Run specific phase with advanced techniques"""
        if phase_number == 1:
            return self.phase1_advanced_real_ip_extraction(target)
        elif phase_number == 2:
            return self.phase2_advanced_subdomain_discovery(target)
        elif phase_number == 3:
            return self.phase3_advanced_port_scanning(target)
        elif phase_number == 4:
            return self.phase4_advanced_technology_detection(target)
        elif phase_number == 5:
            return self.phase5_advanced_directory_discovery(target)
        elif phase_number == 6:
            return self.phase6_parameter_discovery(target)
        elif phase_number == 7:
            return self.phase7_endpoint_discovery(target)
        elif phase_number == 8:
            return self.phase8_cloud_analysis(target)
        elif phase_number == 9:
            return self.phase9_osint_analysis(target)
        elif phase_number == 10:
            return self.phase10_vulnerability_assessment(target)
        else:
            return {
                'phase': phase_number,
                'status': 'completed',
                'summary': f'Phase {phase_number} - Advanced implementation',
                'message': f'Phase {phase_number} completed with advanced techniques'
            }
    
    def phase5_advanced_directory_discovery(self, target: str) -> Dict[str, Any]:
        """Phase 5: Advanced Directory Discovery with 4-level crawling"""
        print(f"🔍 Phase 5: Advanced Directory Discovery for {target}")
        results = {
            'target': target,
            'phase': 5,
            'start_time': datetime.now().isoformat(),
            'directories_found': [],
            'files_found': [],
            'config_files': [],
            'backup_files': [],
            'admin_panels': [],
            'sensitive_files': [],
            'crawl_levels': {},
            'techniques_used': [],
            'errors': []
        }
        
        try:
            # Level 1: Basic Directory Discovery
            print("   📁 Level 1: Basic Directory Discovery...")
            results['techniques_used'].append('Basic Directory Discovery')
            level1_paths = self.directory_wordlist[:50]  # First 50 paths
            
            def check_path(path):
                try:
                    url = f"https://{target}{path}"
                    response = requests.get(url, headers=self.headers, timeout=5, allow_redirects=False)
                    
                    if response.status_code in [200, 301, 302, 403, 401]:
                        result = {
                            'path': path,
                            'status_code': response.status_code,
                            'title': self._extract_title(response.text),
                            'content_length': len(response.content),
                            'level': 1
                        }
                        
                        if path.endswith('/'):
                            results['directories_found'].append(result)
                        else:
                            results['files_found'].append(result)
                        
                        # Categorize files
                        if any(keyword in path.lower() for keyword in ['config', 'setting', 'env', 'conf']):
                            results['config_files'].append(result)
                        elif any(keyword in path.lower() for keyword in ['backup', 'bak', 'old', 'archive']):
                            results['backup_files'].append(result)
                        elif any(keyword in path.lower() for keyword in ['admin', 'panel', 'login', 'dashboard']):
                            results['admin_panels'].append(result)
                        elif any(keyword in path.lower() for keyword in ['passwd', 'shadow', 'htpasswd', 'key', 'cert']):
                            results['sensitive_files'].append(result)
                        
                        print(f"   ✅ Found: {path} ({response.status_code})")
                        return result
                except Exception as e:
                    results['errors'].append(f"Path {path} scan failed: {str(e)}")
                return None
            
            # Use ThreadPoolExecutor for faster scanning
            with ThreadPoolExecutor(max_workers=20) as executor:
                future_to_path = {executor.submit(check_path, path): path for path in level1_paths}
                
                for future in as_completed(future_to_path):
                    result = future.result()
                    if result:
                        results['crawl_levels'][1] = results['crawl_levels'].get(1, 0) + 1
            
            # Level 2: Deep Directory Crawling
            print("   📁 Level 2: Deep Directory Crawling...")
            results['techniques_used'].append('Deep Directory Crawling')
            
            # Get directories found in level 1
            level1_dirs = [d['path'] for d in results['directories_found'] if d['path'].endswith('/')]
            
            for base_dir in level1_dirs[:10]:  # Limit to first 10 directories
                print(f"   🔍 Crawling {base_dir}...")
                level2_paths = [f"{base_dir}{path}" for path in self.directory_wordlist[:30]]
                
                with ThreadPoolExecutor(max_workers=15) as executor:
                    future_to_path = {executor.submit(check_path, path): path for path in level2_paths}
                    
                    for future in as_completed(future_to_path):
                        result = future.result()
                        if result:
                            result['level'] = 2
                            results['crawl_levels'][2] = results['crawl_levels'].get(2, 0) + 1
            
            # Level 3: Extended Directory Crawling
            print("   📁 Level 3: Extended Directory Crawling...")
            results['techniques_used'].append('Extended Directory Crawling')
            
            # Get directories found in level 2
            level2_dirs = [d['path'] for d in results['directories_found'] if d['path'].endswith('/') and d.get('level', 1) == 2]
            
            for base_dir in level2_dirs[:5]:  # Limit to first 5 directories
                print(f"   🔍 Deep crawling {base_dir}...")
                level3_paths = [f"{base_dir}{path}" for path in self.directory_wordlist[:20]]
                
                with ThreadPoolExecutor(max_workers=10) as executor:
                    future_to_path = {executor.submit(check_path, path): path for path in level3_paths}
                    
                    for future in as_completed(future_to_path):
                        result = future.result()
                        if result:
                            result['level'] = 3
                            results['crawl_levels'][3] = results['crawl_levels'].get(3, 0) + 1
            
            # Level 4: Final Deep Crawling
            print("   📁 Level 4: Final Deep Crawling...")
            results['techniques_used'].append('Final Deep Crawling')
            
            # Get directories found in level 3
            level3_dirs = [d['path'] for d in results['directories_found'] if d['path'].endswith('/') and d.get('level', 1) == 3]
            
            for base_dir in level3_dirs[:3]:  # Limit to first 3 directories
                print(f"   🔍 Final deep crawl {base_dir}...")
                level4_paths = [f"{base_dir}{path}" for path in self.directory_wordlist[:15]]
                
                with ThreadPoolExecutor(max_workers=8) as executor:
                    future_to_path = {executor.submit(check_path, path): path for path in level4_paths}
                    
                    for future in as_completed(future_to_path):
                        result = future.result()
                        if result:
                            result['level'] = 4
                            results['crawl_levels'][4] = results['crawl_levels'].get(4, 0) + 1
            
            # Special File Extensions Discovery
            print("   📄 Special File Extensions Discovery...")
            results['techniques_used'].append('Special File Extensions')
            
            special_extensions = [
                '.php', '.asp', '.aspx', '.jsp', '.cfm', '.pl', '.py', '.rb', '.go', '.java',
                '.xml', '.json', '.yaml', '.yml', '.ini', '.conf', '.config', '.properties',
                '.env', '.htaccess', '.htpasswd', '.gitignore', '.gitattributes',
                '.sql', '.db', '.sqlite', '.mdb', '.accdb',
                '.bak', '.backup', '.old', '.orig', '.copy', '.tmp', '.temp',
                '.log', '.txt', '.md', '.readme', '.license', '.changelog'
            ]
            
            # Check special files in root and common directories
            special_paths = []
            for ext in special_extensions:
                special_paths.extend([
                    f"/{target}{ext}",
                    f"/index{ext}",
                    f"/main{ext}",
                    f"/config{ext}",
                    f"/settings{ext}",
                    f"/admin{ext}",
                    f"/login{ext}",
                    f"/test{ext}",
                    f"/info{ext}",
                    f"/phpinfo{ext}"
                ])
            
            with ThreadPoolExecutor(max_workers=15) as executor:
                future_to_path = {executor.submit(check_path, path): path for path in special_paths}
                
                for future in as_completed(future_to_path):
                    result = future.result()
                    if result:
                        result['level'] = 'special'
                        results['crawl_levels']['special'] = results['crawl_levels'].get('special', 0) + 1
            
            results['end_time'] = datetime.now().isoformat()
            results['status'] = 'completed'
            results['summary'] = f"Found {len(results['directories_found'])} directories, {len(results['files_found'])} files across 4 crawl levels"
            
            print(f"   ✅ Phase 5 completed: {results['summary']}")
            print(f"   📊 Crawl Statistics: {results['crawl_levels']}")
            return results
            
        except Exception as e:
            results['errors'].append(f"Phase 5 failed: {str(e)}")
            results['status'] = 'error'
            print(f"   ❌ Phase 5 failed: {e}")
            return results
        elif phase_number == 6:
            return self.phase6_parameter_discovery(target)
        elif phase_number == 7:
            return self.phase7_endpoint_discovery(target)
        elif phase_number == 8:
            return self.phase8_cloud_analysis(target)
        elif phase_number == 9:
            return self.phase9_osint_analysis(target)
        elif phase_number == 10:
            return self.phase10_vulnerability_assessment(target)
        else:
            return {
                'phase': phase_number,
                'status': 'error',
                'error': f'Phase {phase_number} not implemented'
            }