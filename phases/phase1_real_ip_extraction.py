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
            'ip_mapping': {},  # Detailed IP mapping with source and domain info
            'ip_to_subdomain': {},  # Mapping IP to subdomains that use it
            'cdn_detected': False,
            'cdn_provider': None,
            'techniques_used': [],
            'errors': []
        }
        
        try:
            # Technique 1: Advanced DNS Resolution with Multiple Resolvers
            print("   📡 Advanced DNS Resolution...")
            results['techniques_used'].append('Advanced DNS Resolution')
            
            # 2025 Enhanced DNS Resolvers
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
                '76.76.2.22',   # Alternate DNS Secondary
                '94.140.14.14', # AdGuard DNS
                '185.228.168.168', # CleanBrowsing
                '1.1.1.3',      # Cloudflare Family DNS
                '8.26.56.26',   # Comodo Secure DNS
                '84.200.69.80', # DNS.WATCH
                '8.8.8.8',      # Google DNS (IPv4)
                '2001:4860:4860::8888', # Google DNS (IPv6)
                '2606:4700:4700::1111', # Cloudflare DNS (IPv6)
                '2620:0:ccc::2', # OpenDNS (IPv6)
                '2620:fe::fe'   # Quad9 (IPv6)
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
                            # Get reverse DNS for this IP
                            reverse_dns = self._get_reverse_dns(ip)
                            results['ip_mapping'][ip] = {
                                'domain': target,
                                'resolver': resolver,
                                'source': 'DNS Resolution',
                                'reverse_dns': reverse_dns,
                                'technique': 'Multiple DNS Resolvers'
                            }
                            print(f"   ✅ Real IP found via {resolver}: {ip}")
                            if reverse_dns:
                                print(f"      🔄 Reverse DNS: {reverse_dns}")
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
                                reverse_dns = self._get_reverse_dns(ip)
                                results['ip_mapping'][ip] = {
                                    'domain': target,
                                    'source': 'Historical DNS',
                                    'source_url': source,
                                    'reverse_dns': reverse_dns,
                                    'technique': 'Historical DNS Records'
                                }
                                print(f"   ✅ Historical IP found: {ip}")
                                if reverse_dns:
                                    print(f"      🔄 Reverse DNS: {reverse_dns}")
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
            
            # Technique 7: IP to Subdomain Mapping Analysis
            print("   🔗 IP to Subdomain Mapping Analysis...")
            results['techniques_used'].append('IP to Subdomain Mapping Analysis')
            
            # Common subdomains to check for IP mapping
            common_subdomains = [
                'www', 'mail', 'ftp', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk', 'ns2',
                'cpanel', 'whm', 'autodiscover', 'autoconfig', 'ns3', 'm', 'imap', 'test', 'ns', 'blog',
                'pop3', 'dev', 'www2', 'admin', 'forum', 'news', 'vpn', 'ns4', 'mail2', 'new', 'mysql',
                'old', 'www1', 'beta', 'shop', 'api', 'staging', 'app', 'media', 'mail3', 'www3', 'dns2',
                'api', 'v1', 'v2', 'v3', 'rest', 'graphql', 'webhook', 'oauth', 'auth', 'login',
                'dashboard', 'panel', 'admin', 'manage', 'config', 'backup', 'database', 'db'
            ]
            
            # Create IP to subdomain mapping
            for ip in results['real_ips']:
                if ip not in results['ip_to_subdomain']:
                    results['ip_to_subdomain'][ip] = []
                
                # Check common subdomains for this IP
                for subdomain in common_subdomains:
                    test_domain = f"{subdomain}.{target}"
                    try:
                        resolved_ip = socket.gethostbyname(test_domain)
                        if resolved_ip == ip and test_domain not in results['ip_to_subdomain'][ip]:
                            results['ip_to_subdomain'][ip].append(test_domain)
                            print(f"   🔗 IP {ip} -> {test_domain}")
                    except:
                        pass
                
                # Also add main domain if it resolves to this IP
                try:
                    main_ip = socket.gethostbyname(target)
                    if main_ip == ip and target not in results['ip_to_subdomain'][ip]:
                        results['ip_to_subdomain'][ip].append(target)
                        print(f"   🔗 IP {ip} -> {target}")
                except:
                    pass
            
            try:
                import ssl
                context = ssl.create_default_context()
                with socket.create_connection((target, 443), timeout=10) as sock:
                    with context.wrap_socket(sock, server_hostname=target) as ssock:
                        cert = ssock.getpeercert()
                        print(f"   ✅ SSL Certificate analyzed")
            except Exception as e:
                results['errors'].append(f"SSL analysis failed: {str(e)}")
            
            # Technique 7: IPv6 Discovery (2025 Enhancement)
            print("   🌐 IPv6 Discovery...")
            results['techniques_used'].append('IPv6 Discovery')
            
            try:
                # Try to resolve IPv6 addresses
                ipv6_addresses = socket.getaddrinfo(target, None, socket.AF_INET6)
                for addr_info in ipv6_addresses:
                    ipv6 = addr_info[4][0]
                    if ipv6 not in results['real_ips']:
                        results['real_ips'].append(ipv6)
                        results['ip_mapping'][ipv6] = {
                            'domain': target,
                            'source': 'IPv6 Resolution',
                            'reverse_dns': None,
                            'technique': 'IPv6 Discovery'
                        }
                        print(f"   ✅ IPv6 found: {ipv6}")
            except Exception as e:
                results['errors'].append(f"IPv6 discovery failed: {str(e)}")
            
            # Technique 8: DNS Cache Poisoning Detection (2025 Enhancement)
            print("   🕵️ DNS Cache Poisoning Detection...")
            results['techniques_used'].append('DNS Cache Poisoning Detection')
            
            try:
                # Check for DNS cache poisoning indicators
                for resolver in ['8.8.8.8', '1.1.1.1', '9.9.9.9']:
                    try:
                        resolver_obj = dns.resolver.Resolver()
                        resolver_obj.nameservers = [resolver]
                        answers = resolver_obj.resolve(target, 'A')
                        
                        # Check for unusual TTL values that might indicate cache poisoning
                        for answer in answers:
                            if hasattr(answer, 'ttl') and answer.ttl < 60:
                                print(f"   ⚠️ Low TTL detected: {answer.ttl}s (possible cache poisoning)")
                    except Exception as e:
                        results['errors'].append(f"DNS cache poisoning check failed for {resolver}: {str(e)}")
            except Exception as e:
                results['errors'].append(f"DNS cache poisoning detection failed: {str(e)}")
            
            # Technique 9: ASN (Autonomous System Number) Analysis (2025 Enhancement)
            print("   🏢 ASN Analysis...")
            results['techniques_used'].append('ASN Analysis')
            
            try:
                import ipwhois
                for ip in results['real_ips'][:5]:  # Limit to first 5 IPs to avoid rate limiting
                    try:
                        if not self._is_private_ip(ip):
                            obj = ipwhois.IPWhois(ip)
                            results_whois = obj.lookup_rdap()
                            if 'asn' in results_whois:
                                asn_info = results_whois['asn']
                                print(f"   ✅ ASN for {ip}: {asn_info}")
                                # Store ASN info in ip_mapping
                                if ip in results['ip_mapping']:
                                    results['ip_mapping'][ip]['asn'] = asn_info
                    except Exception as e:
                        results['errors'].append(f"ASN lookup failed for {ip}: {str(e)}")
            except ImportError:
                results['errors'].append("ipwhois module not available for ASN analysis")
            except Exception as e:
                results['errors'].append(f"ASN analysis failed: {str(e)}")
            
            # Technique 10: DNS-over-HTTPS (DoH) Resolution (2025 Enhancement)
            print("   🔒 DNS-over-HTTPS Resolution...")
            results['techniques_used'].append('DNS-over-HTTPS Resolution')
            
            doh_providers = [
                'https://dns.google/dns-query',
                'https://cloudflare-dns.com/dns-query',
                'https://dns.quad9.net/dns-query',
                'https://dns.adguard.com/dns-query'
            ]
            
            for doh_url in doh_providers:
                try:
                    # Simple DoH query (simplified implementation)
                    params = {
                        'name': target,
                        'type': 'A'
                    }
                    headers = {'Accept': 'application/dns-json'}
                    response = requests.get(doh_url, params=params, headers=headers, timeout=10)
                    if response.status_code == 200:
                        data = response.json()
                        if 'Answer' in data:
                            for answer in data['Answer']:
                                if answer['type'] == 1:  # A record
                                    ip = answer['data']
                                    if not self._is_private_ip(ip) and ip not in results['real_ips']:
                                        results['real_ips'].append(ip)
                                        results['ip_mapping'][ip] = {
                                            'domain': target,
                                            'source': 'DoH',
                                            'doh_provider': doh_url,
                                            'reverse_dns': None,
                                            'technique': 'DNS-over-HTTPS'
                                        }
                                        print(f"   ✅ DoH IP found: {ip}")
                except Exception as e:
                    results['errors'].append(f"DoH resolution failed for {doh_url}: {str(e)}")
            
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
    
    def _get_reverse_dns(self, ip: str) -> str:
        """Get reverse DNS for IP address"""
        try:
            reverse_dns = socket.gethostbyaddr(ip)[0]
            return reverse_dns
        except:
            return None

if __name__ == "__main__":
    phase = Phase1RealIPExtraction()
    result = phase.run_phase("example.com")
    print(json.dumps(result, indent=2))