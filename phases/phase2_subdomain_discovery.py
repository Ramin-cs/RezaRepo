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
from concurrent.futures import ThreadPoolExecutor, as_completed

class Phase2SubdomainDiscovery:
    """Advanced Subdomain Discovery with comprehensive techniques"""
    
    def __init__(self):
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        self.subdomain_wordlist = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk', 'ns2',
            'cpanel', 'whm', 'autodiscover', 'autoconfig', 'ns3', 'm', 'imap', 'test', 'ns', 'blog',
            'pop3', 'dev', 'www2', 'admin', 'forum', 'news', 'vpn', 'ns4', 'mail2', 'new', 'mysql',
            'old', 'www1', 'beta', 'shop', 'api', 'staging', 'app', 'media', 'mail3', 'www3', 'dns2',
            'cpanel', 'whm', 'autodiscover', 'autoconfig', 'ns3', 'm', 'imap', 'test', 'ns', 'blog'
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
            'certificate_transparency': [],
            'passive_sources': [],
            'http_validation': [],
            'techniques_used': [],
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
            
            # Technique 5: Reverse DNS Lookup
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

if __name__ == "__main__":
    phase = Phase2SubdomainDiscovery()
    result = phase.run_phase("example.com")
    print(json.dumps(result, indent=2))