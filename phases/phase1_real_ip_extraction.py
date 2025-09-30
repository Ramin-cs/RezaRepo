#!/usr/bin/env python3
"""
Phase 1: Advanced Real IP Extraction & CDN Bypass
Advanced techniques for finding real server IPs behind CDNs
"""

import requests
import socket
import dns.resolver
from datetime import datetime
from typing import Dict, Any, List
import json
import re

class Phase1RealIPExtraction:
    """Advanced Real IP Extraction with CDN Bypass techniques"""
    
    def __init__(self):
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
    
    def run_phase(self, target: str) -> Dict[str, Any]:
        """Run Phase 1: Advanced Real IP Extraction"""
        print(f"🔍 Phase 1: Advanced Real IP Extraction for {target}")
        results = {
            'target': target,
            'phase': 1,
            'start_time': datetime.now().isoformat(),
            'real_ips': [],
            'cdn_detected': False,
            'cdn_provider': None,
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
                '76.76.19.21',  # Alternate DNS
                '8.8.4.4',      # Google DNS Secondary
                '1.0.0.1',      # Cloudflare DNS Secondary
                '208.67.220.220', # OpenDNS Secondary
                '9.9.9.10',     # Quad9 Secondary
                '76.76.2.22'    # Alternate DNS Secondary
            ]
            
            for resolver in dns_resolvers:
                try:
                    resolver_obj = dns.resolver.Resolver()
                    resolver_obj.nameservers = [resolver]
                    answers = resolver_obj.resolve(target, 'A')
                    for answer in answers:
                        ip = str(answer)
                        if not self._is_private_ip(ip) and ip not in results['real_ips']:
                            results['real_ips'].append(ip)
                            print(f"   ✅ Real IP found via {resolver}: {ip}")
                except Exception as e:
                    results['errors'].append(f"DNS resolution failed for {resolver}: {str(e)}")
            
            # Technique 2: Historical DNS Records
            print("   📚 Historical DNS Records...")
            results['techniques_used'].append('Historical DNS Records')
            
            historical_sources = [
                f"https://dnsdumpster.com/static/map/{target}.png",
                f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={target}",
                f"https://api.hackertarget.com/hostsearch/?q={target}"
            ]
            
            for source in historical_sources:
                try:
                    response = requests.get(source, headers=self.headers, timeout=10)
                    if response.status_code == 200:
                        # Extract IPs from response
                        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
                        ips = re.findall(ip_pattern, response.text)
                        for ip in ips:
                            if not self._is_private_ip(ip) and ip not in results['real_ips']:
                                results['real_ips'].append(ip)
                                print(f"   ✅ Historical IP found: {ip}")
                except Exception as e:
                    results['errors'].append(f"Historical DNS lookup failed: {str(e)}")
            
            # Technique 3: Certificate Transparency Logs
            print("   🔐 Certificate Transparency Logs...")
            results['techniques_used'].append('Certificate Transparency Logs')
            
            ct_sources = [
                f"https://crt.sh/?q={target}&output=json",
                f"https://api.certspotter.com/v1/issuances?domain={target}&expand=dns_names",
                f"https://censys.io/api/v1/search/certificates?q={target}"
            ]
            
            for source in ct_sources:
                try:
                    response = requests.get(source, headers=self.headers, timeout=10)
                    if response.status_code == 200:
                        try:
                            data = response.json()
                            # Extract IPs from certificate data
                            if isinstance(data, list):
                                for item in data:
                                    if 'common_name' in item:
                                        try:
                                            ip = socket.gethostbyname(item['common_name'])
                                            if not self._is_private_ip(ip) and ip not in results['real_ips']:
                                                results['real_ips'].append(ip)
                                                print(f"   ✅ CT IP found: {ip}")
                                        except:
                                            pass
                        except:
                            pass
                except Exception as e:
                    results['errors'].append(f"CT logs lookup failed: {str(e)}")
            
            # Technique 4: Advanced CDN Detection
            print("   🛡️ Advanced CDN Detection...")
            results['techniques_used'].append('Advanced CDN Detection')
            
            try:
                response = requests.get(f"https://{target}", headers=self.headers, timeout=10)
                headers = response.headers
                
                # Detect CDN providers
                cdn_indicators = {
                    'cloudflare': ['cf-ray', 'cf-cache-status', 'cf-request-id'],
                    'cloudfront': ['x-amz-cf-id', 'x-amz-cf-pop'],
                    'fastly': ['fastly-debug-digest', 'fastly-ff'],
                    'akamai': ['akamai-grn', 'akamai-origin-hop'],
                    'maxcdn': ['x-maxcdn-id', 'x-maxcdn-cache'],
                    'keycdn': ['x-edge-location'],
                    'incapsula': ['x-iinfo', 'x-cdn']
                }
                
                for cdn, indicators in cdn_indicators.items():
                    if any(indicator.lower() in [h.lower() for h in headers.keys()] for indicator in indicators):
                        results['cdn_detected'] = True
                        results['cdn_provider'] = cdn
                        print(f"   ✅ CDN detected: {cdn}")
                        break
                
            except Exception as e:
                results['errors'].append(f"CDN detection failed: {str(e)}")
            
            # Technique 5: Reverse DNS Lookup
            print("   🔄 Reverse DNS Lookup...")
            results['techniques_used'].append('Reverse DNS Lookup')
            
            for ip in results['real_ips']:
                try:
                    hostname = socket.gethostbyaddr(ip)[0]
                    if hostname and hostname != ip:
                        print(f"   ✅ Reverse DNS for {ip}: {hostname}")
                except:
                    pass
            
            # Technique 6: SSL Certificate Analysis
            print("   🔒 SSL Certificate Analysis...")
            results['techniques_used'].append('SSL Certificate Analysis')
            
            try:
                import ssl
                context = ssl.create_default_context()
                with socket.create_connection((target, 443), timeout=10) as sock:
                    with context.wrap_socket(sock, server_hostname=target) as ssock:
                        cert = ssock.getpeercert()
                        print(f"   ✅ SSL Certificate analyzed")
            except Exception as e:
                results['errors'].append(f"SSL analysis failed: {str(e)}")
            
            results['end_time'] = datetime.now().isoformat()
            results['status'] = 'completed'
            results['summary'] = f"Found {len(results['real_ips'])} real IPs using {len(results['techniques_used'])} advanced techniques"
            
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
            import ipaddress
            return ipaddress.ip_address(ip).is_private
        except:
            # Fallback for older Python versions
            private_ranges = [
                '10.', '172.16.', '172.17.', '172.18.', '172.19.',
                '172.20.', '172.21.', '172.22.', '172.23.', '172.24.',
                '172.25.', '172.26.', '172.27.', '172.28.', '172.29.',
                '172.30.', '172.31.', '192.168.'
            ]
            return any(ip.startswith(range_prefix) for range_prefix in private_ranges)

if __name__ == "__main__":
    phase = Phase1RealIPExtraction()
    result = phase.run_phase("example.com")
    print(json.dumps(result, indent=2))