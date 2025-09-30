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
    
    def phase3_port_scanning(self, target):
        """Phase 3: Port Scanning & Service Detection"""
        print(f"🔍 Phase 3: Port Scanning for {target}")
        results = {
            'target': target,
            'phase': 3,
            'start_time': datetime.now().isoformat(),
            'open_ports': [],
            'services': {},
            'os_detection': {},
            'errors': []
        }
        
        try:
            # Common ports to scan
            common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3389, 5432, 3306, 8080, 8443]
            
            print("   🔍 Scanning common ports...")
            for port in common_ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(3)
                    result = sock.connect_ex((target, port))
                    sock.close()
                    
                    if result == 0:
                        results['open_ports'].append(port)
                        print(f"   ✅ Port {port} is open")
                        
                        # Try to detect service
                        service = self._detect_service(target, port)
                        results['services'][port] = service
                        
                except Exception as e:
                    results['errors'].append(f"Port {port} scan failed: {str(e)}")
            
            # OS Detection via TTL
            print("   🖥️ OS Detection via TTL...")
            try:
                ttl = self._get_ttl(target)
                os_guess = self._guess_os_from_ttl(ttl)
                results['os_detection'] = {
                    'ttl': ttl,
                    'os_guess': os_guess
                }
                print(f"   ✅ TTL: {ttl}, OS guess: {os_guess}")
            except Exception as e:
                results['errors'].append(f"OS detection failed: {str(e)}")
            
            results['end_time'] = datetime.now().isoformat()
            results['status'] = 'completed'
            results['summary'] = f"Found {len(results['open_ports'])} open ports"
            
            print(f"   ✅ Phase 3 completed: {results['summary']}")
            return results
            
        except Exception as e:
            results['errors'].append(f"Phase 3 failed: {str(e)}")
            results['status'] = 'error'
            print(f"   ❌ Phase 3 failed: {e}")
            return results
    
    def phase4_technology_detection(self, target):
        """Phase 4: Technology Detection"""
        print(f"🔍 Phase 4: Technology Detection for {target}")
        results = {
            'target': target,
            'phase': 4,
            'start_time': datetime.now().isoformat(),
            'technologies': {},
            'headers_analysis': {},
            'content_analysis': {},
            'errors': []
        }
        
        try:
            # Get main page
            print("   🌐 Analyzing main page...")
            try:
                response = requests.get(f"https://{target}", headers=self.headers, timeout=10, allow_redirects=True)
                results['headers_analysis'] = dict(response.headers)
                
                # Analyze headers
                technologies = []
                server = response.headers.get('Server', '').lower()
                if 'nginx' in server:
                    technologies.append('Nginx')
                elif 'apache' in server:
                    technologies.append('Apache')
                
                x_powered_by = response.headers.get('X-Powered-By', '').lower()
                if 'php' in x_powered_by:
                    technologies.append('PHP')
                elif 'asp.net' in x_powered_by:
                    technologies.append('ASP.NET')
                
                # Analyze content
                content = response.text.lower()
                if 'wordpress' in content or '/wp-content/' in content:
                    technologies.append('WordPress')
                if 'react' in content or 'reactjs' in content:
                    technologies.append('React')
                if 'angular' in content or 'angularjs' in content:
                    technologies.append('Angular')
                if 'vue' in content or 'vuejs' in content:
                    technologies.append('Vue.js')
                if 'jquery' in content:
                    technologies.append('jQuery')
                
                # Check for specific files
                common_files = ['/wp-admin/', '/admin/', '/.env', '/robots.txt', '/sitemap.xml']
                for file_path in common_files:
                    try:
                        file_response = requests.get(f"https://{target}{file_path}", headers=self.headers, timeout=5)
                        if file_response.status_code == 200:
                            if file_path == '/wp-admin/':
                                technologies.append('WordPress Admin')
                            elif file_path == '/.env':
                                technologies.append('Environment File Exposed')
                            print(f"   ✅ Found: {file_path}")
                    except:
                        pass
                
                results['technologies'] = list(set(technologies))
                results['content_analysis'] = {
                    'title': self._extract_title(response.text),
                    'technologies_found': len(technologies)
                }
                
                print(f"   ✅ Technologies found: {results['technologies']}")
                
            except Exception as e:
                results['errors'].append(f"Main page analysis failed: {str(e)}")
            
            results['end_time'] = datetime.now().isoformat()
            results['status'] = 'completed'
            results['summary'] = f"Found {len(results['technologies'])} technologies"
            
            print(f"   ✅ Phase 4 completed: {results['summary']}")
            return results
            
        except Exception as e:
            results['errors'].append(f"Phase 4 failed: {str(e)}")
            results['status'] = 'error'
            print(f"   ❌ Phase 4 failed: {e}")
            return results
    
    def phase5_directory_discovery(self, target):
        """Phase 5: Directory Discovery"""
        print(f"🔍 Phase 5: Directory Discovery for {target}")
        results = {
            'target': target,
            'phase': 5,
            'start_time': datetime.now().isoformat(),
            'directories_found': [],
            'files_found': [],
            'config_files': [],
            'backup_files': [],
            'errors': []
        }
        
        try:
            # Common directories and files
            common_paths = [
                '/admin/', '/administrator/', '/wp-admin/', '/login/', '/dashboard/',
                '/api/', '/v1/', '/v2/', '/api/v1/', '/api/v2/',
                '/backup/', '/backups/', '/bak/', '/old/', '/temp/', '/tmp/',
                '/config/', '/configuration/', '/settings/', '/setup/',
                '/uploads/', '/files/', '/documents/', '/images/',
                '/test/', '/testing/', '/dev/', '/development/',
                '/.env', '/.git/', '/.svn/', '/.htaccess', '/robots.txt',
                '/sitemap.xml', '/crossdomain.xml', '/phpinfo.php',
                '/info.php', '/test.php', '/admin.php'
            ]
            
            print("   🔍 Scanning common directories and files...")
            for path in common_paths:
                try:
                    url = f"https://{target}{path}"
                    response = requests.get(url, headers=self.headers, timeout=5, allow_redirects=False)
                    
                    if response.status_code in [200, 301, 302, 403, 401]:
                        if path.endswith('/'):
                            results['directories_found'].append({
                                'path': path,
                                'status_code': response.status_code,
                                'title': self._extract_title(response.text)
                            })
                        else:
                            results['files_found'].append({
                                'path': path,
                                'status_code': response.status_code,
                                'size': len(response.content)
                            })
                        
                        # Categorize files
                        if any(keyword in path.lower() for keyword in ['config', 'setting', 'env']):
                            results['config_files'].append(path)
                        elif any(keyword in path.lower() for keyword in ['backup', 'bak', 'old']):
                            results['backup_files'].append(path)
                        
                        print(f"   ✅ Found: {path} ({response.status_code})")
                        
                except Exception as e:
                    results['errors'].append(f"Path {path} scan failed: {str(e)}")
            
            results['end_time'] = datetime.now().isoformat()
            results['status'] = 'completed'
            results['summary'] = f"Found {len(results['directories_found'])} directories, {len(results['files_found'])} files"
            
            print(f"   ✅ Phase 5 completed: {results['summary']}")
            return results
            
        except Exception as e:
            results['errors'].append(f"Phase 5 failed: {str(e)}")
            results['status'] = 'error'
            print(f"   ❌ Phase 5 failed: {e}")
            return results
    
    def _detect_service(self, target, port):
        """Detect service running on port"""
        try:
            if port == 80:
                return "HTTP"
            elif port == 443:
                return "HTTPS"
            elif port == 22:
                return "SSH"
            elif port == 21:
                return "FTP"
            elif port == 25:
                return "SMTP"
            elif port == 53:
                return "DNS"
            elif port == 110:
                return "POP3"
            elif port == 143:
                return "IMAP"
            elif port == 993:
                return "IMAPS"
            elif port == 995:
                return "POP3S"
            elif port == 3389:
                return "RDP"
            elif port == 5432:
                return "PostgreSQL"
            elif port == 3306:
                return "MySQL"
            elif port == 8080:
                return "HTTP-Alt"
            elif port == 8443:
                return "HTTPS-Alt"
            else:
                return "Unknown"
        except:
            return "Unknown"
    
    def _get_ttl(self, target):
        """Get TTL for OS detection"""
        try:
            import subprocess
            import platform
            
            if platform.system().lower() == "windows":
                result = subprocess.run(['ping', '-n', '1', target], capture_output=True, text=True)
            else:
                result = subprocess.run(['ping', '-c', '1', target], capture_output=True, text=True)
            
            # Extract TTL from ping output
            output = result.stdout
            ttl_match = re.search(r'TTL[=\s]*(\d+)', output, re.IGNORECASE)
            if ttl_match:
                return int(ttl_match.group(1))
            return None
        except:
            return None
    
    def _guess_os_from_ttl(self, ttl):
        """Guess OS from TTL"""
        if ttl is None:
            return "Unknown"
        elif ttl <= 64:
            return "Linux/Unix"
        elif ttl <= 128:
            return "Windows"
        elif ttl <= 255:
            return "Cisco/Network Device"
        else:
            return "Unknown"
    
    def run_phase(self, phase_number, target):
        """Run specific phase"""
        if phase_number == 1:
            return self.phase1_real_ip_extraction(target)
        elif phase_number == 2:
            return self.phase2_subdomain_discovery(target)
        elif phase_number == 3:
            return self.phase3_port_scanning(target)
        elif phase_number == 4:
            return self.phase4_technology_detection(target)
        elif phase_number == 5:
            return self.phase5_directory_discovery(target)
        else:
            return {
                'phase': phase_number,
                'status': 'completed',
                'summary': f'Phase {phase_number} - Demo mode (not fully implemented)',
                'message': f'Phase {phase_number} completed in demo mode'
            }