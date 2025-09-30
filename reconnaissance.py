"""
ARAT Real Reconnaissance Implementation
"""

import requests
import socket
import dns.resolver
import subprocess
import re
import json
from urllib.parse import urlparse
from datetime import datetime
import time


class RealReconnaissance:
    """Real reconnaissance implementation"""
    
    def __init__(self):
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        self.results = {}
    
    def phase1_real_ip_extraction(self, target):
        """Phase 1: Real IP Extraction & CDN Bypass"""
        print(f"🔍 Phase 1: Real IP Extraction for {target}")
        results = {
            'target': target,
            'phase': 1,
            'start_time': datetime.now().isoformat(),
            'cdn_detected': False,
            'real_ips': [],
            'dns_records': {},
            'ssl_info': {},
            'http_headers': {},
            'errors': []
        }
        
        try:
            # 1. DNS Resolution
            print("   📡 Resolving DNS...")
            try:
                answers = dns.resolver.resolve(target, 'A')
                results['dns_records']['A'] = [str(rdata) for rdata in answers]
                print(f"   ✅ A records: {results['dns_records']['A']}")
            except Exception as e:
                results['errors'].append(f"DNS A resolution failed: {str(e)}")
                print(f"   ❌ DNS A resolution failed: {e}")
            
            # 2. Check for CDN
            print("   🛡️ Checking for CDN...")
            cdn_indicators = ['cloudflare', 'cloudfront', 'fastly', 'akamai', 'maxcdn']
            try:
                response = requests.get(f"http://{target}", headers=self.headers, timeout=10)
                results['http_headers'] = dict(response.headers)
                
                server_header = response.headers.get('Server', '').lower()
                for cdn in cdn_indicators:
                    if cdn in server_header:
                        results['cdn_detected'] = True
                        results['cdn_type'] = cdn
                        print(f"   ⚠️ CDN detected: {cdn}")
                        break
                
                if not results['cdn_detected']:
                    print("   ✅ No CDN detected")
                    
            except Exception as e:
                results['errors'].append(f"HTTP request failed: {str(e)}")
                print(f"   ❌ HTTP request failed: {e}")
            
            # 3. SSL Certificate Analysis
            print("   🔐 Analyzing SSL certificate...")
            try:
                import ssl
                context = ssl.create_default_context()
                with socket.create_connection((target, 443), timeout=10) as sock:
                    with context.wrap_socket(sock, server_hostname=target) as ssock:
                        cert = ssock.getpeercert()
                        results['ssl_info'] = {
                            'subject': dict(x[0] for x in cert['subject']),
                            'issuer': dict(x[0] for x in cert['issuer']),
                            'version': cert['version'],
                            'not_before': cert['notBefore'],
                            'not_after': cert['notAfter']
                        }
                        print(f"   ✅ SSL certificate analyzed")
            except Exception as e:
                results['errors'].append(f"SSL analysis failed: {str(e)}")
                print(f"   ❌ SSL analysis failed: {e}")
            
            # 4. Try to find real IP (simple method)
            print("   🎯 Attempting to find real IP...")
            try:
                # Try direct IP access
                if results['dns_records'].get('A'):
                    for ip in results['dns_records']['A']:
                        try:
                            response = requests.get(f"http://{ip}", 
                                                  headers={'Host': target}, 
                                                  timeout=5, 
                                                  allow_redirects=False)
                            if response.status_code in [200, 301, 302, 403]:
                                results['real_ips'].append(ip)
                                print(f"   ✅ Real IP found: {ip}")
                        except:
                            pass
            except Exception as e:
                results['errors'].append(f"Real IP detection failed: {str(e)}")
            
            results['end_time'] = datetime.now().isoformat()
            results['status'] = 'completed'
            results['summary'] = f"Found {len(results['real_ips'])} real IPs, CDN: {results['cdn_detected']}"
            
            print(f"   ✅ Phase 1 completed: {results['summary']}")
            return results
            
        except Exception as e:
            results['errors'].append(f"Phase 1 failed: {str(e)}")
            results['status'] = 'error'
            print(f"   ❌ Phase 1 failed: {e}")
            return results
    
    def phase2_subdomain_discovery(self, target):
        """Phase 2: Subdomain Discovery"""
        print(f"🔍 Phase 2: Subdomain Discovery for {target}")
        results = {
            'target': target,
            'phase': 2,
            'start_time': datetime.now().isoformat(),
            'subdomains': [],
            'valid_subdomains': [],
            'passive_sources': {},
            'active_sources': {},
            'errors': []
        }
        
        try:
            # Common subdomains list
            common_subdomains = [
                'www', 'mail', 'ftp', 'admin', 'api', 'dev', 'test', 'staging',
                'blog', 'shop', 'store', 'support', 'help', 'docs', 'portal',
                'app', 'mobile', 'cdn', 'static', 'assets', 'img', 'images',
                'js', 'css', 'lib', 'cdn', 'media', 'video', 'audio',
                'secure', 'ssl', 'vpn', 'remote', 'ssh', 'telnet',
                'ns1', 'ns2', 'dns1', 'dns2', 'mx', 'mx1', 'mx2',
                'webmail', 'email', 'smtp', 'pop', 'imap', 'calendar',
                'news', 'forum', 'community', 'chat', 'irc', 'misc',
                'demo', 'sandbox', 'beta', 'alpha', 'gamma', 'delta',
                'backup', 'bak', 'old', 'archive', 'temp', 'tmp',
                'files', 'file', 'download', 'uploads', 'upload',
                'search', 'find', 'query', 'db', 'database', 'sql',
                'internal', 'private', 'secret', 'hidden', 'admin'
            ]
            
            # 1. Passive Discovery (DNS brute force)
            print("   🔍 Passive subdomain discovery...")
            passive_found = []
            for subdomain in common_subdomains:
                try:
                    full_domain = f"{subdomain}.{target}"
                    answers = dns.resolver.resolve(full_domain, 'A')
                    ips = [str(rdata) for rdata in answers]
                    passive_found.append({
                        'subdomain': full_domain,
                        'ips': ips,
                        'type': 'A'
                    })
                    print(f"   ✅ Found: {full_domain} -> {ips}")
                except:
                    pass
            
            results['passive_sources']['dns_bruteforce'] = passive_found
            results['subdomains'].extend([s['subdomain'] for s in passive_found])
            
            # 2. Active Discovery (HTTP requests)
            print("   🌐 Active subdomain discovery...")
            active_found = []
            for subdomain_info in passive_found:
                subdomain = subdomain_info['subdomain']
                try:
                    # Try HTTP
                    response = requests.get(f"http://{subdomain}", 
                                          headers=self.headers, 
                                          timeout=5, 
                                          allow_redirects=False)
                    if response.status_code in [200, 301, 302, 403, 401]:
                        active_found.append({
                            'subdomain': subdomain,
                            'status_code': response.status_code,
                            'title': self._extract_title(response.text),
                            'server': response.headers.get('Server', 'Unknown'),
                            'protocol': 'http'
                        })
                        print(f"   ✅ HTTP: {subdomain} -> {response.status_code}")
                except:
                    pass
                
                try:
                    # Try HTTPS
                    response = requests.get(f"https://{subdomain}", 
                                          headers=self.headers, 
                                          timeout=5, 
                                          allow_redirects=False)
                    if response.status_code in [200, 301, 302, 403, 401]:
                        active_found.append({
                            'subdomain': subdomain,
                            'status_code': response.status_code,
                            'title': self._extract_title(response.text),
                            'server': response.headers.get('Server', 'Unknown'),
                            'protocol': 'https'
                        })
                        print(f"   ✅ HTTPS: {subdomain} -> {response.status_code}")
                except:
                    pass
            
            results['active_sources']['http_requests'] = active_found
            results['valid_subdomains'] = active_found
            
            # 3. Additional DNS records
            print("   📋 Checking additional DNS records...")
            additional_records = {}
            record_types = ['MX', 'NS', 'TXT', 'CNAME']
            
            for record_type in record_types:
                try:
                    answers = dns.resolver.resolve(target, record_type)
                    additional_records[record_type] = [str(rdata) for rdata in answers]
                    print(f"   ✅ {record_type}: {additional_records[record_type]}")
                except:
                    pass
            
            results['dns_additional'] = additional_records
            
            results['end_time'] = datetime.now().isoformat()
            results['status'] = 'completed'
            results['summary'] = f"Found {len(results['subdomains'])} subdomains, {len(results['valid_subdomains'])} valid"
            
            print(f"   ✅ Phase 2 completed: {results['summary']}")
            return results
            
        except Exception as e:
            results['errors'].append(f"Phase 2 failed: {str(e)}")
            results['status'] = 'error'
            print(f"   ❌ Phase 2 failed: {e}")
            return results
    
    def _extract_title(self, html):
        """Extract title from HTML"""
        try:
            title_match = re.search(r'<title[^>]*>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
            if title_match:
                return title_match.group(1).strip()[:100]
            return "No title"
        except:
            return "No title"
    
    def run_phase(self, phase_number, target):
        """Run specific phase"""
        if phase_number == 1:
            return self.phase1_real_ip_extraction(target)
        elif phase_number == 2:
            return self.phase2_subdomain_discovery(target)
        else:
            return {
                'phase': phase_number,
                'status': 'error',
                'error': f'Phase {phase_number} not implemented yet'
            }