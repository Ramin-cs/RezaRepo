#!/usr/bin/env python3
"""
Phase 3: Advanced Port Scanning & Service Detection
Comprehensive port scanning with service detection and OS fingerprinting
"""

import requests
import socket
import subprocess
import platform
import os
from datetime import datetime
from typing import Dict, Any, List
import json
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

class Phase3PortScanning:
    """Advanced Port Scanning with comprehensive service detection"""
    
    def __init__(self):
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
    
    def run_phase(self, target: str) -> Dict[str, Any]:
        """Run Phase 3: Advanced Port Scanning"""
        print(f"🔍 Phase 3: Advanced Port Scanning for {target}")
        results = {
            'target': target,
            'phase': 3,
            'start_time': datetime.now().isoformat(),
            'open_ports': [],
            'services': {},
            'os_detection': {},
            'banner_grabbing': {},
            'service_versions': {},
            'techniques_used': [],
            'errors': []
        }
        
        try:
            # Technique 1: Comprehensive Port Scanning
            print("   🔍 Comprehensive Port Scanning...")
            results['techniques_used'].append('Comprehensive Port Scanning')
            
            # Extended port list with all common services
            ports_to_scan = [
                # Web services
                80, 443, 8080, 8443, 8000, 8008, 8888, 9000, 9080, 9443, 9444, 9445,
                # SSH/Telnet
                22, 23, 2222, 22222, 2223, 2224,
                # FTP
                21, 2121, 990, 989, 20, 115,
                # Mail
                25, 110, 143, 993, 995, 587, 465, 2525, 26, 465, 587, 25025,
                # DNS
                53, 853, 5353,
                # Database
                3306, 5432, 1433, 1521, 27017, 6379, 11211, 5984, 9200, 9300, 5601,
                # RDP/VNC
                3389, 5900, 5901, 5902, 5903, 5904, 5905,
                # Other services
                161, 162, 389, 636, 2049, 3268, 3269, 5985, 5986,
                3000, 5000, 5001, 8001, 8002, 8003, 8004, 8005,
                # Development
                3000, 3001, 4000, 4001, 5000, 5001, 6000, 6001, 7000, 7001,
                # Monitoring
                9090, 9091, 9100, 9101, 9102, 9103,
                # Security
                8444, 8445, 8446, 8447, 8448, 8449, 8450,
                # Cloud services
                8080, 8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089,
                # Special services
                9999, 10000, 10001, 10002, 10003, 10004, 10005
            ]
            
            def scan_port(port):
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(3)
                    result = sock.connect_ex((target, port))
                    
                    if result == 0:
                        # Banner grabbing
                        try:
                            sock.settimeout(2)
                            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                            if banner:
                                results['banner_grabbing'][port] = banner
                        except:
                            pass
                        
                        sock.close()
                        service = self._detect_service_advanced(target, port)
                        return port, service
                    else:
                        sock.close()
                except:
                    pass
                return None, None
            
            # Use ThreadPoolExecutor for faster scanning
            with ThreadPoolExecutor(max_workers=50) as executor:
                future_to_port = {executor.submit(scan_port, port): port for port in ports_to_scan}
                
                for future in as_completed(future_to_port):
                    port, service = future.result()
                    if port and service:
                        results['open_ports'].append(port)
                        results['services'][port] = service
                        print(f"   ✅ Port {port} is open ({service})")
            
            # Technique 2: OS Detection via TTL
            print("   🖥️ OS Detection via TTL...")
            results['techniques_used'].append('OS Detection via TTL')
            
            try:
                ttl = self._get_ttl(target)
                os_guess = self._guess_os_from_ttl(ttl)
                results['os_detection'] = {
                    'ttl': ttl,
                    'os_guess': os_guess,
                    'method': 'TTL Analysis'
                }
                print(f"   ✅ TTL: {ttl}, OS guess: {os_guess}")
            except Exception as e:
                results['errors'].append(f"OS detection failed: {str(e)}")
            
            # Technique 3: Service Version Detection
            print("   🔍 Service Version Detection...")
            results['techniques_used'].append('Service Version Detection')
            
            for port in results['open_ports']:
                try:
                    version_info = self._get_service_version(target, port)
                    if version_info:
                        results['service_versions'][port] = version_info
                        print(f"   ✅ Service version on port {port}: {version_info}")
                except Exception as e:
                    results['errors'].append(f"Version detection for port {port} failed: {str(e)}")
            
            # Technique 4: HTTP Service Analysis
            print("   🌐 HTTP Service Analysis...")
            results['techniques_used'].append('HTTP Service Analysis')
            
            http_ports = [80, 443, 8080, 8443, 8000, 8008, 8888, 9000, 9080, 9443]
            for port in http_ports:
                if port in results['open_ports']:
                    try:
                        protocol = 'https' if port in [443, 8443, 9443] else 'http'
                        url = f"{protocol}://{target}:{port}"
                        response = requests.get(url, headers=self.headers, timeout=5, allow_redirects=True)
                        
                        results['services'][port] = {
                            'service': results['services'].get(port, 'HTTP'),
                            'status_code': response.status_code,
                            'server': response.headers.get('Server', 'Unknown'),
                            'title': self._extract_title(response.text),
                            'content_length': len(response.content)
                        }
                        print(f"   ✅ HTTP analysis for port {port}: {response.status_code}")
                    except Exception as e:
                        results['errors'].append(f"HTTP analysis for port {port} failed: {str(e)}")
            
            # Technique 5: Nmap Integration (if available)
            print("   🔍 Nmap Integration...")
            results['techniques_used'].append('Nmap Integration')
            
            if self._is_nmap_available():
                try:
                    nmap_results = self._run_nmap_scan(target)
                    if nmap_results:
                        results['nmap_results'] = nmap_results
                        print(f"   ✅ Nmap scan completed")
                except Exception as e:
                    results['errors'].append(f"Nmap scan failed: {str(e)}")
            else:
                print("   ℹ️ Nmap not available, skipping advanced scan")
            
            results['end_time'] = datetime.now().isoformat()
            results['status'] = 'completed'
            results['summary'] = f"Found {len(results['open_ports'])} open ports using {len(results['techniques_used'])} advanced techniques"
            
            print(f"   ✅ Phase 3 completed: {results['summary']}")
            return results
            
        except Exception as e:
            results['errors'].append(f"Phase 3 failed: {str(e)}")
            results['status'] = 'error'
            print(f"   ❌ Phase 3 failed: {e}")
            return results
    
    def _detect_service_advanced(self, target: str, port: int) -> str:
        """Advanced service detection based on port and banner"""
        try:
            # Common port mappings
            port_services = {
                21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS', 80: 'HTTP',
                110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 993: 'IMAPS', 995: 'POP3S',
                1433: 'MSSQL', 3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL',
                6379: 'Redis', 27017: 'MongoDB', 9200: 'Elasticsearch'
            }
            
            # Try to get banner
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                sock.connect((target, port))
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                sock.close()
                
                # Analyze banner for service identification
                banner_lower = banner.lower()
                if 'ssh' in banner_lower:
                    return 'SSH'
                elif 'ftp' in banner_lower:
                    return 'FTP'
                elif 'smtp' in banner_lower:
                    return 'SMTP'
                elif 'pop' in banner_lower:
                    return 'POP3'
                elif 'imap' in banner_lower:
                    return 'IMAP'
                elif 'http' in banner_lower:
                    return 'HTTP'
                elif 'mysql' in banner_lower:
                    return 'MySQL'
                elif 'postgres' in banner_lower:
                    return 'PostgreSQL'
                elif 'redis' in banner_lower:
                    return 'Redis'
                elif 'mongodb' in banner_lower:
                    return 'MongoDB'
                
            except:
                pass
            
            # Fallback to port-based detection
            return port_services.get(port, f'Service on port {port}')
            
        except:
            return f'Unknown service on port {port}'
    
    def _get_service_version(self, target: str, port: int) -> str:
        """Get service version information"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((target, port))
            
            # Send common probes based on port
            if port in [21, 2121]:  # FTP
                sock.send(b'QUIT\r\n')
            elif port in [22, 2222]:  # SSH
                pass  # SSH version is sent automatically
            elif port in [25, 587, 465]:  # SMTP
                sock.send(b'HELO test\r\n')
            elif port in [80, 8080, 8000]:  # HTTP
                sock.send(b'GET / HTTP/1.1\r\nHost: ' + target.encode() + b'\r\n\r\n')
            elif port in [443, 8443]:  # HTTPS
                pass  # SSL handshake will reveal version
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            
            return banner[:100] if banner else None
            
        except:
            return None
    
    def _get_ttl(self, target: str) -> int:
        """Get TTL value for OS detection"""
        try:
            import subprocess
            if platform.system().lower() == 'windows':
                result = subprocess.run(['ping', '-n', '1', target], capture_output=True, text=True, timeout=10)
            else:
                result = subprocess.run(['ping', '-c', '1', target], capture_output=True, text=True, timeout=10)
            
            # Extract TTL from ping output
            ttl_match = re.search(r'ttl=(\d+)', result.stdout.lower())
            if ttl_match:
                return int(ttl_match.group(1))
        except:
            pass
        return 64  # Default TTL
    
    def _guess_os_from_ttl(self, ttl: int) -> str:
        """Guess OS from TTL value"""
        if ttl <= 32:
            return 'Windows'
        elif ttl <= 64:
            return 'Linux/Unix'
        elif ttl <= 128:
            return 'Windows'
        elif ttl <= 255:
            return 'Cisco/Network Device'
        else:
            return 'Unknown'
    
    def _is_nmap_available(self) -> bool:
        """Check if nmap is available"""
        try:
            subprocess.run(['nmap', '--version'], capture_output=True, timeout=5)
            return True
        except:
            return False
    
    def _run_nmap_scan(self, target: str) -> Dict[str, Any]:
        """Run nmap scan if available"""
        try:
            # Run nmap with service detection
            cmd = ['nmap', '-sV', '-sC', '--top-ports', '1000', target]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0:
                return {
                    'stdout': result.stdout,
                    'stderr': result.stderr,
                    'success': True
                }
        except:
            pass
        return None
    
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
    phase = Phase3PortScanning()
    result = phase.run_phase("example.com")
    print(json.dumps(result, indent=2))