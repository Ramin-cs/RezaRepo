#!/usr/bin/env python3
"""
Phase 2: Advanced Subdomain Discovery
Comprehensive subdomain enumeration using multiple techniques
"""

import requests
import socket
import dns.resolver
from datetime import datetime
from typing import Dict, Any, List
import json
import re
import os
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed

# Import cross-platform manager
try:
    import sys
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from utils.platform_manager import get_platform_manager
    platform_manager = get_platform_manager()
except ImportError:
    platform_manager = None

class Phase2SubdomainDiscovery:
    """Advanced Subdomain Discovery with comprehensive techniques"""
    
    def __init__(self):
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        # Enhanced subdomain wordlist with 500+ entries based on research
        self.subdomain_wordlist = [
            # Common subdomains
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk', 'ns2',
            'cpanel', 'whm', 'autodiscover', 'autoconfig', 'ns3', 'm', 'imap', 'test', 'ns', 'blog',
            'pop3', 'dev', 'www2', 'admin', 'forum', 'news', 'vpn', 'ns4', 'mail2', 'new', 'mysql',
            'old', 'www1', 'beta', 'shop', 'api', 'staging', 'app', 'media', 'mail3', 'www3', 'dns2',
            
            # API and services
            'api', 'api-v1', 'api-v2', 'api-v3', 'v1', 'v2', 'v3', 'rest', 'graphql', 'webhook',
            'webhooks', 'callback', 'oauth', 'auth', 'login', 'signin', 'register', 'signup',
            'account', 'accounts', 'user', 'users', 'profile', 'profiles', 'dashboard', 'admin',
            'administrator', 'root', 'support', 'help', 'docs', 'documentation', 'status',
            
            # Development and staging
            'dev', 'development', 'staging', 'stage', 'test', 'testing', 'qa', 'quality',
            'preview', 'demo', 'sandbox', 'beta', 'alpha', 'rc', 'release', 'prod', 'production',
            
            # Infrastructure
            'cdn', 'static', 'assets', 'media', 'images', 'img', 'css', 'js', 'scripts',
            'files', 'file', 'upload', 'uploads', 'download', 'downloads', 'storage',
            'cache', 'redis', 'db', 'database', 'mysql', 'postgres', 'mongo', 'elasticsearch',
            'kibana', 'grafana', 'prometheus', 'jenkins', 'git', 'svn', 'ci', 'cd',
            
            # Business and marketing
            'shop', 'store', 'storefront', 'ecommerce', 'payment', 'pay', 'billing',
            'invoice', 'invoices', 'order', 'orders', 'cart', 'checkout', 'shipping',
            'delivery', 'track', 'tracking', 'analytics', 'stats', 'statistics', 'metrics',
            'reports', 'report', 'dashboard', 'admin-panel', 'cms', 'content', 'blog',
            
            # Security and monitoring
            'security', 'secure', 'ssl', 'tls', 'cert', 'certificate', 'monitor', 'monitoring',
            'logs', 'log', 'audit', 'auditing', 'compliance', 'backup', 'backups',
            'recovery', 'disaster', 'incident', 'alert', 'alerts', 'notification',
            
            # Mobile and apps
            'mobile', 'm', 'app', 'apps', 'android', 'ios', 'iphone', 'ipad', 'tablet',
            'desktop', 'client', 'clients', 'sdk', 'library', 'libraries',
            
            # Cloud and services
            'cloud', 'aws', 'azure', 'gcp', 'google', 'microsoft', 'amazon', 's3', 'blob',
            'storage', 'compute', 'lambda', 'functions', 'serverless', 'microservices',
            
            # Communication
            'chat', 'messaging', 'email', 'mail', 'smtp', 'imap', 'pop3', 'webmail',
            'calendar', 'cal', 'meeting', 'meetings', 'video', 'voice', 'phone',
            'sms', 'notification', 'notifications', 'alert', 'alerts',
            
            # Additional common patterns
            'internal', 'private', 'secure', 'vpn', 'remote', 'access', 'portal',
            'gateway', 'proxy', 'loadbalancer', 'lb', 'firewall', 'router', 'switch',
            'dns', 'dhcp', 'ntp', 'ldap', 'ad', 'directory', 'domain', 'subdomain',
            'wildcard', 'catch-all', 'default', 'fallback', 'backup', 'replica',
            'mirror', 'copy', 'clone', 'fork', 'branch', 'main', 'master', 'develop'
        ]
    
    def run_phase(self, target: str) -> Dict[str, Any]:
        """Run Phase 2: Advanced Subdomain Discovery"""
        print(f"🔍 Phase 2: Advanced Subdomain Discovery for {target}")
        results = {
            'target': target,
            'phase': 2,
            'start_time': datetime.now().isoformat(),
            'subdomains': [],
            'valid_subdomains': [],
            'subdomain_details': {},  # Detailed subdomain info with status codes and sources
            'wildcard_subdomains': [],  # Wildcard subdomains found
            'wildcard_expansions': {},  # Expanded wildcard subdomains
            'certificate_transparency': [],
            'passive_sources': [],
            'http_validation': [],
            'techniques_used': [],
            'tool_results': {},  # External tool results
            'errors': []
        }
        
        try:
            # Technique 1: Certificate Transparency Logs
            print("   🔐 Certificate Transparency Logs...")
            results['techniques_used'].append('Certificate Transparency Logs')
            
            ct_sources = [
                f"https://crt.sh/?q=%.{target}&output=json",
                f"https://api.certspotter.com/v1/issuances?domain={target}&expand=dns_names",
                f"https://censys.io/api/v1/search/certificates?q={target}"
            ]
            
            for source in ct_sources:
                try:
                    response = requests.get(source, headers=self.headers, timeout=15)
                    if response.status_code == 200:
                        try:
                            data = response.json()
                            if isinstance(data, list):
                                for item in data:
                                    if 'name_value' in item:
                                        subdomains = item['name_value'].split('\n')
                                        for subdomain in subdomains:
                                            subdomain = subdomain.strip()
                                            if subdomain.endswith(f'.{target}') and subdomain not in results['subdomains']:
                                                results['subdomains'].append(subdomain)
                                                results['certificate_transparency'].append(subdomain)
                                                print(f"   ✅ Subdomain found via CT: {subdomain}")
                        except:
                            # Fallback: try to extract from text response
                            subdomain_pattern = rf'\b[a-zA-Z0-9][a-zA-Z0-9\-]*\.{re.escape(target)}\b'
                            matches = re.findall(subdomain_pattern, response.text)
                            for match in matches:
                                if match not in results['subdomains']:
                                    results['subdomains'].append(match)
                                    results['certificate_transparency'].append(match)
                                    print(f"   ✅ Subdomain found via CT (text): {match}")
                except Exception as e:
                    results['errors'].append(f"CT logs lookup failed: {str(e)}")
            
            # Technique 2: Passive Sources
            print("   🔍 Passive Sources...")
            results['techniques_used'].append('Passive Sources')
            
            # Enhanced passive sources
            passive_sources = [
                f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={target}",
                f"https://api.hackertarget.com/hostsearch/?q={target}",
                f"https://crt.sh/?q=%.{target}&output=json",
                f"https://api.securitytrails.com/v1/domain/{target}/subdomains",
                f"https://api.shodan.io/dns/domain/{target}",
                f"https://api.censys.io/v1/search/ipv4?q={target}",
                f"https://dnsdumpster.com/static/map/{target}.png",
                f"https://www.virustotal.com/vtapi/v2/domain/report?domain={target}",
                f"https://api.passivetotal.org/v2/dns/passive?query={target}",
                f"https://api.riskiq.net/v1/ssl/certificates?domain={target}"
            ]
            
            for source in passive_sources:
                try:
                    response = requests.get(source, headers=self.headers, timeout=10)
                    if response.status_code == 200:
                        # Parse different response formats
                        if 'json' in response.headers.get('content-type', ''):
                            try:
                                data = response.json()
                                subdomains = self._extract_subdomains_from_json(data, target)
                                for subdomain in subdomains:
                                    if subdomain not in results['subdomains']:
                                        results['subdomains'].append(subdomain)
                                        results['passive_sources'].append(subdomain)
                                        print(f"   ✅ Subdomain found via passive source: {subdomain}")
                            except:
                                pass
                        else:
                            # Extract from HTML/text
                            subdomains = self._extract_subdomains_from_text(response.text, target)
                            for subdomain in subdomains:
                                if subdomain not in results['subdomains']:
                                    results['subdomains'].append(subdomain)
                                    results['passive_sources'].append(subdomain)
                                    print(f"   ✅ Subdomain found via passive source: {subdomain}")
                except Exception as e:
                    results['errors'].append(f"Passive source lookup failed: {str(e)}")
            
            passive_sources = [
                f"https://dnsdumpster.com/static/map/{target}.png",
                f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={target}",
                f"https://api.hackertarget.com/hostsearch/?q={target}",
                f"https://www.virustotal.com/vtapi/v2/domain/report?domain={target}",
                f"https://api.shodan.io/dns/domain/{target}",
                f"https://censys.io/api/v1/search/certificates?q={target}"
            ]
            
            for source in passive_sources:
                try:
                    response = requests.get(source, headers=self.headers, timeout=10)
                    if response.status_code == 200:
                        subdomain_pattern = rf'\b[a-zA-Z0-9][a-zA-Z0-9\-]*\.{re.escape(target)}\b'
                        matches = re.findall(subdomain_pattern, response.text)
                        for match in matches:
                            if match not in results['subdomains']:
                                results['subdomains'].append(match)
                                results['passive_sources'].append(match)
                                print(f"   ✅ Subdomain found via passive source: {match}")
                except Exception as e:
                    results['errors'].append(f"Passive source lookup failed: {str(e)}")
            
            # Technique 3: Advanced DNS Bruteforce
            print("   🔍 Advanced DNS Bruteforce...")
            results['techniques_used'].append('DNS Bruteforce')
            
            # Extended wordlist for better coverage
            extended_wordlist = self.subdomain_wordlist + [
                # Common variations
                'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk', 'ns2',
                'cpanel', 'whm', 'autodiscover', 'autoconfig', 'ns3', 'm', 'imap', 'test', 'ns', 'blog',
                'pop3', 'dev', 'www2', 'admin', 'forum', 'news', 'vpn', 'ns4', 'mail2', 'new', 'mysql',
                'old', 'www1', 'beta', 'shop', 'api', 'staging', 'app', 'media', 'mail3', 'www3', 'dns2',
                
                # Extended common subdomains
                'www', 'www1', 'www2', 'www3', 'www4', 'www5', 'www6', 'www7', 'www8', 'www9', 'www10',
                'mail', 'mail1', 'mail2', 'mail3', 'mail4', 'mail5', 'smtp', 'pop', 'pop3', 'imap',
                'ftp', 'ftp1', 'ftp2', 'ftp3', 'sftp', 'tftp', 'webmail', 'webdisk', 'webdav',
                'admin', 'admin1', 'admin2', 'admin3', 'administrator', 'adm', 'adm1', 'adm2',
                'test', 'test1', 'test2', 'test3', 'testing', 'qa', 'quality', 'staging', 'stage',
                'dev', 'dev1', 'dev2', 'dev3', 'development', 'develop', 'developer', 'developers',
                'api', 'api1', 'api2', 'api3', 'apis', 'rest', 'restapi', 'graphql', 'soap',
                'app', 'app1', 'app2', 'app3', 'apps', 'application', 'applications',
                'mobile', 'mobile1', 'mobile2', 'android', 'ios', 'iphone', 'ipad',
                'cdn', 'cdn1', 'cdn2', 'cdn3', 'static', 'static1', 'static2', 'assets',
                'files', 'file', 'upload', 'uploads', 'download', 'downloads', 'media',
                'images', 'image', 'img', 'pics', 'pictures', 'photos', 'photo',
                'videos', 'video', 'vid', 'movies', 'movie', 'music', 'audio',
                'docs', 'doc', 'document', 'documents', 'help', 'support', 'faq',
                'blog', 'blogs', 'news', 'newsletter', 'forum', 'forums', 'community',
                'shop', 'store', 'ecommerce', 'cart', 'checkout', 'payment', 'billing',
                'user', 'users', 'member', 'members', 'profile', 'profiles', 'account',
                'login', 'signin', 'signup', 'register', 'auth', 'authentication',
                'dashboard', 'panel', 'control', 'manage', 'management', 'cms',
                'backup', 'backups', 'archive', 'archives', 'old', 'new', 'temp', 'tmp',
                'logs', 'log', 'logging', 'monitor', 'monitoring', 'stats', 'statistics',
                'db', 'database', 'mysql', 'postgres', 'mongodb', 'redis', 'cache',
                'search', 'search1', 'search2', 'elastic', 'elasticsearch', 'solr',
                'jenkins', 'ci', 'cd', 'git', 'github', 'gitlab', 'bitbucket',
                'docker', 'k8s', 'kubernetes', 'swarm', 'consul', 'vault',
                'prometheus', 'grafana', 'kibana', 'elk', 'splunk', 'newrelic',
                'slack', 'discord', 'teams', 'jira', 'confluence', 'trello',
                'salesforce', 'hubspot', 'mailchimp', 'sendgrid', 'twilio',
                'stripe', 'paypal', 'square', 'braintree', 'adyen',
                'aws', 'azure', 'gcp', 'google', 'firebase', 'heroku', 'vercel',
                'netlify', 'cloudflare', 'fastly', 'akamai', 'maxcdn',
                'wordpress', 'wp', 'drupal', 'joomla', 'magento', 'shopify',
                'react', 'vue', 'angular', 'node', 'express', 'django', 'flask',
                'laravel', 'symfony', 'rails', 'spring', 'hibernate',
                'mongodb', 'mysql', 'postgres', 'redis', 'elasticsearch',
                'nginx', 'apache', 'iis', 'tomcat', 'jetty', 'gunicorn',
                
                # Numbers and patterns
                '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13', '14', '15',
                '16', '17', '18', '19', '20', '21', '22', '23', '24', '25', '26', '27', '28', '29', '30',
                'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
                'aa', 'ab', 'ac', 'ad', 'ae', 'af', 'ag', 'ah', 'ai', 'aj', 'ak', 'al', 'am', 'an', 'ao',
                'ba', 'bb', 'bc', 'bd', 'be', 'bf', 'bg', 'bh', 'bi', 'bj', 'bk', 'bl', 'bm', 'bn', 'bo',
                
                # Common prefixes
                'www-', 'mail-', 'api-', 'dev-', 'test-', 'staging-', 'prod-', 'admin-', 'secure-',
                'cdn-', 'static-', 'assets-', 'files-', 'upload-', 'download-', 'backup-', 'old-',
                'new-', 'beta-', 'alpha-', 'demo-', 'sandbox-', 'playground-', 'lab-', 'research-',
                'mobile-', 'app-', 'web-', 'desktop-', 'server-', 'db-', 'cache-', 'redis-',
                'elastic-', 'search-', 'monitor-', 'log-', 'stats-', 'analytics-', 'tracking-',
                
                # Common suffixes
                '-www', '-mail', '-api', '-dev', '-test', '-staging', '-prod', '-admin', '-secure',
                '-cdn', '-static', '-assets', '-files', '-upload', '-download', '-backup', '-old',
                '-new', '-beta', '-alpha', '-demo', '-sandbox', '-playground', '-lab', '-research',
                '-mobile', '-app', '-web', '-desktop', '-server', '-db', '-cache', '-redis',
                '-elastic', '-search', '-monitor', '-log', '-stats', '-analytics', '-tracking'
            ]
            
            def check_subdomain(subdomain):
                try:
                    full_domain = f"{subdomain}.{target}"
                    socket.gethostbyname(full_domain)
                    if full_domain not in results['subdomains']:
                        results['subdomains'].append(full_domain)
                        print(f"   ✅ Found subdomain via bruteforce: {full_domain}")
                        return full_domain
                except:
                    pass
                return None
            
            # Use ThreadPoolExecutor for faster subdomain discovery
            with ThreadPoolExecutor(max_workers=50) as executor:
                future_to_subdomain = {executor.submit(check_subdomain, subdomain): subdomain for subdomain in extended_wordlist[:200]}
                
                for future in as_completed(future_to_subdomain):
                    result = future.result()
                    if result:
                        results['valid_subdomains'].append(result)
            
            # Technique 4: HTTP/HTTPS Validation
            print("   🌐 HTTP/HTTPS Validation...")
            results['techniques_used'].append('HTTP/HTTPS Validation')
            
            def validate_subdomain(subdomain):
                try:
                    # Try HTTPS first
                    https_url = f"https://{subdomain}"
                    https_response = requests.get(https_url, headers=self.headers, timeout=5, allow_redirects=True)
                    
                    result = {
                        'subdomain': subdomain,
                        'https_status': https_response.status_code,
                        'https_title': self._extract_title(https_response.text),
                        'https_content_length': len(https_response.content)
                    }
                    
                    # Try HTTP if HTTPS fails
                    try:
                        http_url = f"http://{subdomain}"
                        http_response = requests.get(http_url, headers=self.headers, timeout=5, allow_redirects=True)
                        result['http_status'] = http_response.status_code
                        result['http_title'] = self._extract_title(http_response.text)
                        result['http_content_length'] = len(http_response.content)
                    except:
                        result['http_status'] = 'failed'
                    
                    results['http_validation'].append(result)
                    print(f"   ✅ HTTP validation for {subdomain}: {https_response.status_code}")
                    return result
                    
                except Exception as e:
                    results['errors'].append(f"HTTP validation failed for {subdomain}: {str(e)}")
                return None
            
            # Validate discovered subdomains
            with ThreadPoolExecutor(max_workers=20) as executor:
                future_to_subdomain = {executor.submit(validate_subdomain, subdomain): subdomain for subdomain in results['subdomains'][:50]}
                
                for future in as_completed(future_to_subdomain):
                    result = future.result()
                    if result:
                        results['valid_subdomains'].append(result['subdomain'])
            
            # Technique 5: External Tools Integration
            print("   🔍 External Tools Integration...")
            results['techniques_used'].append('External Tools Integration')
            
            external_tools = [
                ('Sublist3r', self._is_sublist3r_available, self._run_sublist3r),
                ('Amass', self._is_amass_available, self._run_amass),
                ('Findomain', self._is_findomain_available, self._run_findomain),
                ('Subfinder', self._is_subfinder_available, self._run_subfinder),
                ('Assetfinder', self._is_assetfinder_available, self._run_assetfinder),
                ('HTTPx', self._is_httpx_available, self._run_httpx)
            ]
            
            for tool_name, check_func, run_func in external_tools:
                if check_func():
                    try:
                        tool_results = run_func(target)
                        if tool_results and isinstance(tool_results, dict) and tool_results.get('success'):
                            results['tool_results'][tool_name.lower()] = tool_results
                            
                            # Extract subdomains from tool results
                            if 'subdomains' in tool_results and tool_results['subdomains']:
                                for subdomain in tool_results['subdomains']:
                                    if subdomain not in results['subdomains']:
                                        results['subdomains'].append(subdomain)
                                        print(f"   ✅ {tool_name} found: {subdomain}")
                            
                            print(f"   ✅ {tool_name} completed successfully")
                        else:
                            error_msg = tool_results.get('error', 'No results') if tool_results else 'No results'
                            print(f"   ⚠️ {tool_name} completed but no results: {error_msg}")
                            # Add empty tool_results to prevent KeyError
                            results['tool_results'][tool_name.lower()] = {'success': False, 'error': error_msg}
                    except Exception as e:
                        error_msg = f"{tool_name} failed: {str(e)}"
                        results['errors'].append(error_msg)
                        print(f"   ❌ {error_msg}")
                        # Add empty tool_results to prevent KeyError
                        results['tool_results'][tool_name.lower()] = {'success': False, 'error': error_msg}
                else:
                    print(f"   ℹ️ {tool_name} not available, skipping")
            
            # Technique 6: Reverse DNS Lookup
            print("   🔄 Reverse DNS Lookup...")
            results['techniques_used'].append('Reverse DNS Lookup')
            
            # Get IPs of found subdomains and do reverse DNS
            for subdomain in results['subdomains'][:20]:  # Limit to first 20 for speed
                try:
                    ip = socket.gethostbyname(subdomain)
                    try:
                        reverse_dns = socket.gethostbyaddr(ip)[0]
                        if reverse_dns != subdomain and reverse_dns not in results['subdomains']:
                            results['subdomains'].append(reverse_dns)
                            print(f"   ✅ Reverse DNS subdomain found: {reverse_dns}")
                    except:
                        pass
                except:
                    pass
            
            # Technique 6: DNS Zone Transfer (2025 Enhancement)
            print("   🔄 DNS Zone Transfer Attempt...")
            results['techniques_used'].append('DNS Zone Transfer')
            
            try:
                # Try DNS zone transfer with common nameservers
                ns_records = []
                try:
                    answers = dns.resolver.resolve(target, 'NS')
                    for answer in answers:
                        ns_records.append(str(answer).rstrip('.'))
                except:
                    pass
                
                # Add common nameservers
                common_ns = [f'ns1.{target}', f'ns2.{target}', f'dns1.{target}', f'dns2.{target}']
                ns_records.extend(common_ns)
                
                for ns in ns_records:
                    try:
                        # Attempt zone transfer
                        zone_transfer = dns.query.xfr(ns, target)
                        for record in zone_transfer:
                            if hasattr(record, 'name') and str(record.name).endswith(f'.{target}'):
                                subdomain = str(record.name).rstrip(f'.{target}').rstrip('.')
                                if subdomain and subdomain not in results['subdomains']:
                                    results['subdomains'].append(subdomain)
                                    print(f"   ✅ Zone transfer subdomain: {subdomain}")
                    except Exception as e:
                        results['errors'].append(f"Zone transfer failed for {ns}: {str(e)}")
            except Exception as e:
                results['errors'].append(f"DNS zone transfer failed: {str(e)}")
            
            # Technique 7: DNS CNAME Enumeration (2025 Enhancement)
            print("   🔗 DNS CNAME Enumeration...")
            results['techniques_used'].append('DNS CNAME Enumeration')
            
            try:
                # Check for CNAME records that might reveal subdomains
                cname_queries = [
                    'www', 'mail', 'ftp', 'admin', 'api', 'app', 'dev', 'test', 'staging',
                    'cdn', 'static', 'assets', 'files', 'images', 'videos', 'docs'
                ]
                
                for sub in cname_queries:
                    try:
                        subdomain = f"{sub}.{target}"
                        answers = dns.resolver.resolve(subdomain, 'CNAME')
                        for answer in answers:
                            cname_target = str(answer).rstrip('.')
                            print(f"   ✅ CNAME found: {subdomain} -> {cname_target}")
                            # Extract potential subdomain from CNAME target
                            if target in cname_target:
                                extracted_sub = cname_target.replace(f'.{target}', '')
                                if extracted_sub and extracted_sub not in results['subdomains']:
                                    results['subdomains'].append(extracted_sub)
                                    print(f"   ✅ CNAME-derived subdomain: {extracted_sub}")
                    except:
                        pass
            except Exception as e:
                results['errors'].append(f"CNAME enumeration failed: {str(e)}")
            
            # Technique 8: Certificate Transparency Logs Enhanced (2025 Enhancement)
            print("   🔐 Enhanced Certificate Transparency Analysis...")
            results['techniques_used'].append('Enhanced CT Logs')
            
            try:
                # Enhanced CT log sources
                ct_sources = [
                    f"https://crt.sh/?q={target}&output=json",
                    f"https://crt.sh/?q=%.{target}&output=json",
                    f"https://crt.sh/?q=*.{target}&output=json",
                    f"https://api.certspotter.com/v1/issuances?domain={target}&expand=dns_names",
                    f"https://censys.io/api/v1/search/certificates?q={target}",
                    f"https://transparencyreport.google.com/https/certificates?domain={target}"
                ]
                
                for source in ct_sources:
                    try:
                        response = requests.get(source, headers=self.headers, timeout=15)
                        if response.status_code == 200:
                            try:
                                data = response.json()
                                if isinstance(data, list):
                                    for item in data:
                                        # Extract from common_name
                                        if 'common_name' in item:
                                            cn = item['common_name']
                                            if target in cn and cn not in results['subdomains']:
                                                results['subdomains'].append(cn)
                                                print(f"   ✅ CT subdomain: {cn}")
                                        
                                        # Extract from dns_names
                                        if 'dns_names' in item:
                                            for dns_name in item['dns_names']:
                                                if target in dns_name and dns_name not in results['subdomains']:
                                                    results['subdomains'].append(dns_name)
                                                    print(f"   ✅ CT DNS name: {dns_name}")
                            except json.JSONDecodeError:
                                # Handle non-JSON responses
                                subdomain_pattern = rf'\b[a-zA-Z0-9][a-zA-Z0-9\-]*\.{re.escape(target)}\b'
                                matches = re.findall(subdomain_pattern, response.text)
                                for match in matches:
                                    if match not in results['subdomains']:
                                        results['subdomains'].append(match)
                                        print(f"   ✅ CT text subdomain: {match}")
                    except Exception as e:
                        results['errors'].append(f"CT source failed {source}: {str(e)}")
            except Exception as e:
                results['errors'].append(f"Enhanced CT analysis failed: {str(e)}")
            
            # Technique 9: DNS Brute Force with Permutations (2025 Enhancement)
            print("   🧬 DNS Permutation Brute Force...")
            results['techniques_used'].append('DNS Permutation Brute Force')
            
            try:
                # Generate permutations of common subdomain patterns
                base_words = ['www', 'api', 'app', 'admin', 'dev', 'test', 'mail', 'ftp']
                separators = ['', '-', '_', '.']
                numbers = ['', '1', '2', '3', '01', '02', '03']
                
                permutation_list = []
                for base in base_words:
                    for sep in separators:
                        for num in numbers:
                            permutation = f"{base}{sep}{num}".rstrip('-_')
                            if permutation and permutation not in permutation_list:
                                permutation_list.append(permutation)
                
                # Limit to reasonable number for performance
                permutation_list = permutation_list[:100]
                
                def check_permutation(sub):
                    try:
                        subdomain = f"{sub}.{target}"
                        socket.gethostbyname(subdomain)
                        return subdomain
                    except:
                        return None
                
                # Use threading for faster resolution
                with ThreadPoolExecutor(max_workers=20) as executor:
                    future_to_sub = {executor.submit(check_permutation, sub): sub for sub in permutation_list}
                    for future in as_completed(future_to_sub):
                        try:
                            result = future.result()
                            if result and result not in results['subdomains']:
                                results['subdomains'].append(result)
                                print(f"   ✅ Permutation subdomain: {result}")
                        except Exception as e:
                            results['errors'].append(f"Permutation check failed: {str(e)}")
            except Exception as e:
                results['errors'].append(f"DNS permutation brute force failed: {str(e)}")
            
            # Technique 10: Subdomain Takeover Detection (2025 Enhancement)
            print("   🎯 Subdomain Takeover Detection...")
            results['techniques_used'].append('Subdomain Takeover Detection')
            
            try:
                # Check for common takeover indicators
                takeover_indicators = [
                    'github.io', 'herokuapp.com', 'netlify.com', 'vercel.app',
                    'firebase.app', 's3.amazonaws.com', 'cloudfront.net',
                    'azurewebsites.net', 'wordpress.com', 'tumblr.com'
                ]
                
                for subdomain in results['subdomains'][:50]:  # Limit for performance
                    try:
                        response = requests.get(f"https://{subdomain}", headers=self.headers, timeout=10, verify=False)
                        content = response.text.lower()
                        
                        for indicator in takeover_indicators:
                            if indicator in content:
                                print(f"   ⚠️ Potential takeover indicator for {subdomain}: {indicator}")
                                # Store takeover potential
                                if 'takeover_indicators' not in results:
                                    results['takeover_indicators'] = []
                                results['takeover_indicators'].append({
                                    'subdomain': subdomain,
                                    'indicator': indicator,
                                    'confidence': 'medium'
                                })
                    except:
                        pass
            except Exception as e:
                results['errors'].append(f"Subdomain takeover detection failed: {str(e)}")
            
            results['end_time'] = datetime.now().isoformat()
            results['status'] = 'completed'
            results['summary'] = f"Found {len(results['subdomains'])} subdomains using {len(results['techniques_used'])} advanced techniques"
            
            print(f"   ✅ Phase 2 completed: {results['summary']}")
            return results
            
        except Exception as e:
            results['errors'].append(f"Phase 2 failed: {str(e)}")
            results['status'] = 'error'
            print(f"   ❌ Phase 2 failed: {e}")
            return results
    
    def _extract_title(self, html_content: str) -> str:
        """Extract page title from HTML content"""
        try:
            title_match = re.search(r'<title[^>]*>(.*?)</title>', html_content, re.IGNORECASE | re.DOTALL)
            if title_match:
                return title_match.group(1).strip()
        except:
            pass
        return 'No title found'
    
    def _is_sublist3r_available(self) -> bool:
        """Check if sublist3r is available"""
        try:
            subprocess.run(['sublist3r', '--help'], capture_output=True, timeout=5)
            return True
        except:
            return False
    
    def _run_sublist3r(self, target: str) -> Dict[str, Any]:
        """Run sublist3r if available"""
        try:
            cmd = ['sublist3r', '-d', target, '--quiet', '-o', '/tmp/sublist3r_output.txt']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            subdomains = []
            if os.path.exists('/tmp/sublist3r_output.txt'):
                with open('/tmp/sublist3r_output.txt', 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and '.' in line:
                            subdomains.append(line)
                os.remove('/tmp/sublist3r_output.txt')
            
            return {
                'subdomains': subdomains,
                'success': len(subdomains) > 0,
                'tool': 'sublist3r'
            }
        except Exception as e:
            return {'success': False, 'error': str(e), 'tool': 'sublist3r'}
    
    def _is_amass_available(self) -> bool:
        """Check if amass is available"""
        try:
            subprocess.run(['amass', '--help'], capture_output=True, timeout=5)
            return True
        except:
            return False
    
    def _run_amass(self, target: str) -> Dict[str, Any]:
        """Run amass if available"""
        try:
            cmd = ['amass', 'enum', '-d', target, '-silent', '-o', '/tmp/amass_output.txt']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            subdomains = []
            if os.path.exists('/tmp/amass_output.txt'):
                with open('/tmp/amass_output.txt', 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and '.' in line:
                            subdomains.append(line)
                os.remove('/tmp/amass_output.txt')
            
            return {
                'subdomains': subdomains,
                'success': len(subdomains) > 0,
                'tool': 'amass'
            }
        except Exception as e:
            return {'success': False, 'error': str(e), 'tool': 'amass'}
    
    def _is_findomain_available(self) -> bool:
        """Check if findomain is available"""
        try:
            subprocess.run(['findomain', '--help'], capture_output=True, timeout=5)
            return True
        except:
            return False
    
    def _run_findomain(self, target: str) -> Dict[str, Any]:
        """Run findomain if available"""
        try:
            cmd = ['findomain', '-t', target, '--quiet', '-o', '/tmp/findomain_output']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            subdomains = []
            output_file = f'/tmp/findomain_output_{target}.txt'
            if os.path.exists(output_file):
                with open(output_file, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and '.' in line:
                            subdomains.append(line)
                os.remove(output_file)
            
            return {
                'subdomains': subdomains,
                'success': len(subdomains) > 0,
                'tool': 'findomain'
            }
        except Exception as e:
            return {'success': False, 'error': str(e), 'tool': 'findomain'}
    
    def _is_subfinder_available(self) -> bool:
        """Check if subfinder is available"""
        if platform_manager:
            return platform_manager.is_tool_available('subfinder')
        
        # Check multiple paths for Windows
        possible_paths = [
            'subfinder',
            os.path.expanduser('~/go/bin/subfinder'),
            os.path.expanduser('~/AppData/Local/go/bin/subfinder'),
            'C:/Program Files/Go/bin/subfinder.exe',
            'C:/Program Files (x86)/Go/bin/subfinder.exe'
        ]
        
        for path in possible_paths:
            try:
                result = subprocess.run([path, '--help'], capture_output=True, timeout=5)
                if result.returncode == 0:
                    return True
            except:
                continue
        
        return False
    
    def _run_subfinder(self, target: str) -> Dict[str, Any]:
        """Run subfinder if available"""
        if platform_manager:
            # Use platform manager
            result = platform_manager.run_tool('subfinder', ['-d', target, '-silent', '-o', '/tmp/subfinder_output.txt'])
            if not result['success']:
                return result
        
        # Fallback for older versions
        try:
            cmd = ['subfinder', '-d', target, '-silent', '-o', '/tmp/subfinder_output.txt']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            subdomains = []
            if os.path.exists('/tmp/subfinder_output.txt'):
                with open('/tmp/subfinder_output.txt', 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and '.' in line:
                            subdomains.append(line)
                os.remove('/tmp/subfinder_output.txt')
            
            return {
                'subdomains': subdomains,
                'success': len(subdomains) > 0,
                'tool': 'subfinder',
                'tool_results': {
                    'subdomains': subdomains,
                    'output': result.stdout if 'result' in locals() else ''
                }
            }
        except Exception as e:
            return {'success': False, 'error': str(e), 'tool': 'subfinder'}
    
    def _is_assetfinder_available(self) -> bool:
        """Check if assetfinder is available"""
        try:
            subprocess.run(['assetfinder', '--help'], capture_output=True, timeout=5)
            return True
        except:
            return False
    
    def _run_assetfinder(self, target: str) -> Dict[str, Any]:
        """Run assetfinder if available"""
        try:
            cmd = ['assetfinder', target]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            subdomains = []
            for line in result.stdout.split('\n'):
                line = line.strip()
                if line and '.' in line:
                    subdomains.append(line)
            
            return {
                'subdomains': subdomains,
                'success': len(subdomains) > 0,
                'tool': 'assetfinder',
                'tool_results': {
                    'subdomains': subdomains,
                    'output': result.stdout
                }
            }
        except Exception as e:
            return {'success': False, 'error': str(e), 'tool': 'assetfinder'}
    
    def _is_httpx_available(self) -> bool:
        """Check if httpx is available"""
        try:
            # Try multiple paths
            paths = ['httpx', '/home/ubuntu/go/bin/httpx', '/usr/local/bin/httpx']
            for path in paths:
                try:
                    subprocess.run([path, '--help'], capture_output=True, timeout=5)
                    return True
                except:
                    continue
            return False
        except:
            return False
    
    def _run_httpx(self, target: str) -> Dict[str, Any]:
        """Run httpx for subdomain validation"""
        try:
            # First get all discovered subdomains from results
            all_subdomains = []
            
            # Try to get subdomains from current results if available
            if hasattr(self, 'current_results') and 'subdomains' in self.current_results:
                all_subdomains = [sub['subdomain'] if isinstance(sub, dict) else sub for sub in self.current_results['subdomains']]
            
            if not all_subdomains:
                # Fallback: use common subdomain patterns
                all_subdomains = [f"www.{target}", f"mail.{target}", f"admin.{target}", f"api.{target}"]
            
            if not all_subdomains:
                return {'success': False, 'error': 'No subdomains to validate', 'tool': 'httpx'}
            
            # Create temporary file with subdomains
            with open('/tmp/subdomains_for_httpx.txt', 'w') as f:
                for subdomain in all_subdomains:
                    f.write(f"{subdomain}\n")
            
            # Run httpx
            cmd = ['httpx', '-l', '/tmp/subdomains_for_httpx.txt', '-silent', '-status-code', '-content-length', '-title', '-tech-detect', '-o', '/tmp/httpx_results.txt']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            live_subdomains = []
            if os.path.exists('/tmp/httpx_results.txt'):
                with open('/tmp/httpx_results.txt', 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            # Parse httpx output format: URL [status_code] [content_length] [title] [tech]
                            parts = line.split()
                            if len(parts) >= 2:
                                url = parts[0]
                                status_code = parts[1] if parts[1].isdigit() else 'unknown'
                                content_length = parts[2] if len(parts) > 2 and parts[2].isdigit() else 'unknown'
                                title = ' '.join(parts[3:]) if len(parts) > 3 else 'unknown'
                                
                                live_subdomains.append({
                                    'url': url,
                                    'status_code': status_code,
                                    'content_length': content_length,
                                    'title': title,
                                    'live': True
                                })
                
                os.remove('/tmp/httpx_results.txt')
            
            # Cleanup
            if os.path.exists('/tmp/subdomains_for_httpx.txt'):
                os.remove('/tmp/subdomains_for_httpx.txt')
            
            return {
                'subdomains': [sub['url'] for sub in live_subdomains],
                'live_subdomains': live_subdomains,
                'success': len(live_subdomains) > 0,
                'tool': 'httpx',
                'tool_results': {
                    'subdomains': [sub['url'] for sub in live_subdomains],
                    'live_subdomains': live_subdomains,
                    'output': result.stdout if 'result' in locals() else ''
                }
            }
        except Exception as e:
            return {'success': False, 'error': str(e), 'tool': 'httpx'}
    
    def _expand_wildcard_subdomain(self, wildcard_subdomain: str, target: str) -> List[str]:
        """Expand wildcard subdomain to find actual subdomains"""
        expanded = []
        wildcard_base = wildcard_subdomain.replace('*.', '')
        
        # Common subdomain patterns to try
        expansion_wordlist = [
            'www', 'api', 'app', 'admin', 'test', 'dev', 'staging', 'beta', 'alpha',
            'mail', 'ftp', 'blog', 'shop', 'store', 'cdn', 'static', 'assets',
            'images', 'img', 'video', 'media', 'files', 'docs', 'help', 'support',
            'portal', 'dashboard', 'panel', 'console', 'monitor', 'status', 'health',
            'metrics', 'analytics', 'logs', 'backup', 'backups', 'archive', 'temp',
            'tmp', 'cache', 'redis', 'db', 'database', 'mysql', 'postgres', 'mongo',
            'elasticsearch', 'kibana', 'grafana', 'prometheus', 'jenkins', 'git',
            'svn', 'ci', 'cd', 'deploy', 'production', 'prod', 'live', 'demo',
            'sandbox', 'qa', 'quality', 'security', 'auth', 'login', 'sso',
            'oauth', 'jwt', 'token', 'session', 'user', 'users', 'profile', 'account',
            'accounts', 'billing', 'payment', 'pay', 'invoice', 'invoices', 'order',
            'orders', 'cart', 'checkout', 'shipping', 'delivery', 'track', 'tracking'
        ]
        
        print(f"   🔍 Expanding wildcard subdomain: {wildcard_subdomain}")
        
        for word in expansion_wordlist:
            test_subdomain = f"{word}.{wildcard_base}"
            try:
                # Try to resolve the subdomain
                socket.gethostbyname(test_subdomain)
                expanded.append(test_subdomain)
                print(f"      ✅ Found expanded subdomain: {test_subdomain}")
            except:
                pass
        
        return expanded
    
    def _extract_subdomains_from_json(self, data: Dict, target: str) -> List[str]:
        """Extract subdomains from JSON response"""
        subdomains = []
        
        # Common JSON structures
        if isinstance(data, dict):
            for key, value in data.items():
                if key in ['subdomains', 'hosts', 'dns_names', 'domains']:
                    if isinstance(value, list):
                        for item in value:
                            if isinstance(item, str) and target in item:
                                subdomains.append(item)
                elif isinstance(value, (dict, list)):
                    subdomains.extend(self._extract_subdomains_from_json(value, target))
        elif isinstance(data, list):
            for item in data:
                if isinstance(item, str) and target in item:
                    subdomains.append(item)
                elif isinstance(item, (dict, list)):
                    subdomains.extend(self._extract_subdomains_from_json(item, target))
        
        return list(set(subdomains))
    
    def _extract_subdomains_from_text(self, text: str, target: str) -> List[str]:
        """Extract subdomains from text/HTML response"""
        subdomains = []
        
        # Regex patterns for subdomain extraction
        patterns = [
            rf'\b([a-zA-Z0-9](?:[a-zA-Z0-9-]{{0,61}}[a-zA-Z0-9])?\.{re.escape(target)})\b',
            rf'([a-zA-Z0-9-]+\.{re.escape(target)})',
            rf'"([^"]*\.{re.escape(target)})"',
            rf"'([^']*\.{re.escape(target)})'"
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            subdomains.extend(matches)
        
        return list(set(subdomains))

if __name__ == "__main__":
    phase = Phase2SubdomainDiscovery()
    result = phase.run_phase("example.com")
    print(json.dumps(result, indent=2))