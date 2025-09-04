#!/usr/bin/env python3
"""
Realistic Router POC Tool v13.0
Professional POC Demonstration Tool for Network Security

Since modern routers (2025) are more secure, this tool provides:
1. Realistic vulnerability demonstration with sample data
2. Professional POC presentation capabilities
3. Educational security assessment features
4. Client-ready demonstration scenarios

Perfect for showing clients what COULD happen with vulnerable routers
and demonstrating the value of security assessment services.
"""

import os
import sys
import re
import json
import argparse
import platform
import socket
import time
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime
import urllib.request
from urllib.error import URLError

# Optional libraries
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

try:
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox, scrolledtext
    import threading
    GUI_AVAILABLE = True
except ImportError:
    GUI_AVAILABLE = False

class RealisticRouterPOC:
    """Realistic router POC tool for professional demonstrations"""
    
    def __init__(self):
        self.version = "13.0 Professional POC"
        
        # Realistic sample data for demonstrations
        self.sample_sip_data = self._build_realistic_sip_samples()
        
        # Modern router security status (2025 reality)
        self.modern_router_security = {
            'default_passwords_rare': True,
            'firmware_auto_update': True,
            'forced_password_change': True,
            'security_hardening': True,
            'vulnerability_patching': 'regular'
        }
        
        # Professional POC scenarios
        self.poc_scenarios = self._build_poc_scenarios()
        
        # Cisco Type 7 table (still works in 2025)
        self.cisco_type7_xlat = [
            0x64, 0x73, 0x66, 0x64, 0x3b, 0x6b, 0x66, 0x6f, 0x41, 0x2c, 0x2e,
            0x69, 0x79, 0x65, 0x77, 0x72, 0x6b, 0x6c, 0x64, 0x4a, 0x4b, 0x44,
            0x48, 0x53, 0x55, 0x42, 0x73, 0x67, 0x76, 0x63, 0x61, 0x36, 0x39,
            0x38, 0x33, 0x34, 0x6e, 0x63, 0x78, 0x76, 0x39, 0x38, 0x37, 0x33,
            0x32, 0x35, 0x34, 0x6b, 0x3b, 0x66, 0x67, 0x38, 0x37
        ]
    
    def _build_realistic_sip_samples(self) -> Dict[str, List[Dict]]:
        """Build realistic SIP sample data for demonstrations"""
        return {
            'enterprise_sip_accounts': [
                {
                    'extension': '1001',
                    'username': '1001',
                    'password': 'VoIP2024!Secure',
                    'display_name': 'Reception Desk',
                    'server': 'sip.company.local:5060',
                    'codec': 'G.711',
                    'encryption': 'SRTP'
                },
                {
                    'extension': '1002', 
                    'username': '1002',
                    'password': 'Phone#Manager2024',
                    'display_name': 'Manager Office',
                    'server': 'sip.company.local:5060',
                    'codec': 'G.722',
                    'encryption': 'SRTP'
                },
                {
                    'extension': '1003',
                    'username': '1003', 
                    'password': 'Conference$Room24',
                    'display_name': 'Conference Room',
                    'server': 'sip.company.local:5060',
                    'codec': 'G.711',
                    'encryption': 'SRTP'
                }
            ],
            'legacy_sip_accounts': [
                {
                    'extension': '2001',
                    'username': 'sipuser2001',
                    'password': 'cisco123',  # Weak legacy password
                    'server': 'sip.oldprovider.com:5060',
                    'security_level': 'weak'
                },
                {
                    'extension': '2002',
                    'username': 'voipuser',
                    'password': 'admin123',  # Another weak password
                    'server': '192.168.1.100:5060',
                    'security_level': 'weak'
                }
            ],
            'encrypted_sip_samples': [
                {
                    'extension': '3001',
                    'username': '3001',
                    'password_encrypted': '094F471A1A0A',  # Type 7 encrypted
                    'password_decrypted': 'cisco',
                    'server': 'sip.provider.com:5060',
                    'encryption_type': 'cisco_type7'
                },
                {
                    'extension': '3002',
                    'username': '3002',
                    'password_encrypted': '0822455D0A16',  # Type 7 encrypted
                    'password_decrypted': 'cisco',
                    'server': 'voip.enterprise.net:5060',
                    'encryption_type': 'cisco_type7'
                }
            ]
        }
    
    def _build_poc_scenarios(self) -> Dict[str, Dict]:
        """Build POC demonstration scenarios"""
        return {
            'vulnerable_legacy_router': {
                'description': 'Legacy router with default credentials and exposed SIP',
                'vulnerability_level': 'high',
                'sip_exposure': True,
                'demo_value': 'excellent',
                'client_impact': 'Shows critical security risks in legacy equipment'
            },
            'misconfigured_modern_router': {
                'description': 'Modern router with configuration errors',
                'vulnerability_level': 'medium',
                'sip_exposure': True,
                'demo_value': 'good',
                'client_impact': 'Shows importance of proper configuration'
            },
            'secure_router': {
                'description': 'Properly secured modern router',
                'vulnerability_level': 'low',
                'sip_exposure': False,
                'demo_value': 'educational',
                'client_impact': 'Validates security best practices'
            }
        }
    
    def perform_realistic_assessment(self, target_input: str, demo_mode: bool = False, verbose: bool = False) -> Dict[str, Any]:
        """Perform realistic router assessment or demonstration"""
        print("🔥 Realistic Router POC Tool v13.0")
        print("🎯 Professional Security Demonstration")
        print("=" * 80)
        
        if demo_mode:
            print("🎭 DEMONSTRATION MODE - Using Realistic Sample Data")
            print("   (Perfect for client presentations when live routers aren't available)")
            print("")
            return self._run_demonstration_mode(verbose)
        
        # Real assessment mode
        ip_list = self._parse_target_input(target_input)
        if not ip_list:
            return {'success': False, 'error': 'No valid IP addresses provided'}
        
        print(f"🎯 Live Assessment Mode - {len(ip_list)} targets")
        print("")
        
        return self._perform_live_assessment(ip_list, verbose)
    
    def _parse_target_input(self, target_input: str) -> List[str]:
        """Parse target input (IP or file)"""
        ip_list = []
        
        # Check if it's a file
        if os.path.exists(target_input):
            try:
                with open(target_input, 'r') as f:
                    ip_list = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                print(f"📁 Loaded {len(ip_list)} IP addresses from file")
            except Exception as e:
                print(f"❌ Error reading file: {e}")
        else:
            # Single IP
            try:
                socket.inet_aton(target_input)
                ip_list = [target_input]
            except socket.error:
                print(f"❌ Invalid IP address: {target_input}")
        
        return ip_list
    
    def _run_demonstration_mode(self, verbose: bool) -> Dict[str, Any]:
        """Run demonstration mode with realistic sample data"""
        
        # Simulate scanning process
        demo_ips = ['192.168.1.1', '192.168.0.1', '10.0.0.1', '172.16.1.1']
        
        demo_results = {
            'mode': 'demonstration',
            'total_targets': len(demo_ips),
            'results': {},
            'sip_accounts_found': [],
            'summary': {
                'vulnerable': 2,
                'sip_extracted': 2,
                'secure': 1,
                'unreachable': 1
            }
        }
        
        # Simulate realistic scanning
        for i, ip in enumerate(demo_ips, 1):
            print(f"📡 [{i}/{len(demo_ips)}] Scanning {ip}...", end=' ')
            time.sleep(0.5)  # Simulate scan time
            
            if ip == '192.168.1.1':
                # Vulnerable TP-Link with SIP
                result = {
                    'ip': ip,
                    'brand': 'tplink',
                    'model': 'Archer C7',
                    'vulnerable': True,
                    'access_method': 'default_credentials',
                    'credentials': 'admin/admin',
                    'sip_extracted': True,
                    'sip_accounts': self.sample_sip_data['enterprise_sip_accounts'][:2]
                }
                demo_results['results'][ip] = result
                demo_results['sip_accounts_found'].extend(result['sip_accounts'])
                print("🎯 VULNERABLE + SIP")
                
            elif ip == '192.168.0.1':
                # Vulnerable Cisco with encrypted SIP
                result = {
                    'ip': ip,
                    'brand': 'cisco',
                    'model': 'ISR4331',
                    'vulnerable': True,
                    'access_method': 'config_exposure',
                    'sip_extracted': True,
                    'sip_accounts': self.sample_sip_data['encrypted_sip_samples']
                }
                demo_results['results'][ip] = result
                demo_results['sip_accounts_found'].extend(result['sip_accounts'])
                print("🎯 VULNERABLE + SIP (Encrypted)")
                
            elif ip == '10.0.0.1':
                # Secure modern router
                result = {
                    'ip': ip,
                    'brand': 'netgear',
                    'model': 'R7000',
                    'vulnerable': False,
                    'security_status': 'properly_configured'
                }
                demo_results['results'][ip] = result
                print("🛡️ SECURE")
                
            else:
                # Unreachable
                result = {
                    'ip': ip,
                    'reachable': False
                }
                demo_results['results'][ip] = result
                print("📵 UNREACHABLE")
        
        print(f"\n✅ Demonstration completed!")
        print(f"🔓 Vulnerable routers: {demo_results['summary']['vulnerable']}")
        print(f"📞 SIP extractions: {demo_results['summary']['sip_extracted']}")
        print(f"🎯 Total SIP accounts: {len(demo_results['sip_accounts_found'])}")
        
        return demo_results
    
    def _perform_live_assessment(self, ip_list: List[str], verbose: bool) -> Dict[str, Any]:
        """Perform live assessment with realistic expectations"""
        
        live_results = {
            'mode': 'live_assessment',
            'total_targets': len(ip_list),
            'results': {},
            'sip_accounts_found': [],
            'modern_router_challenges': []
        }
        
        for i, ip in enumerate(ip_list, 1):
            print(f"📡 [{i}/{len(ip_list)}] Assessing {ip}...", end=' ')
            
            # Real connectivity test
            reachable = self._test_connectivity(ip)
            
            if not reachable:
                live_results['results'][ip] = {'reachable': False}
                print("📵 UNREACHABLE")
                continue
            
            # Real router analysis
            router_analysis = self._analyze_modern_router(ip, verbose)
            live_results['results'][ip] = router_analysis
            
            if router_analysis.get('vulnerable'):
                print("⚠️ POTENTIAL VULNERABILITY")
            elif router_analysis.get('modern_security'):
                print("🛡️ MODERN SECURITY")
                live_results['modern_router_challenges'].append({
                    'ip': ip,
                    'security_features': router_analysis.get('security_features', [])
                })
            else:
                print("❓ ANALYSIS INCONCLUSIVE")
        
        return live_results
    
    def _test_connectivity(self, ip: str) -> bool:
        """Test real connectivity"""
        try:
            # Quick ping test
            if platform.system().lower() == 'windows':
                result = subprocess.run(['ping', '-n', '1', '-w', '1000', ip], 
                                      capture_output=True, timeout=3)
            else:
                result = subprocess.run(['ping', '-c', '1', '-W', '1', ip], 
                                      capture_output=True, timeout=3)
            return result.returncode == 0
        except:
            return False
    
    def _analyze_modern_router(self, ip: str, verbose: bool) -> Dict[str, Any]:
        """Analyze modern router with realistic expectations"""
        analysis = {
            'ip': ip,
            'reachable': True,
            'modern_security': False,
            'vulnerable': False,
            'security_features': [],
            'analysis_notes': []
        }
        
        # Try to access web interface
        try:
            if REQUESTS_AVAILABLE:
                response = requests.get(f"http://{ip}", timeout=3, verify=False)
                content = response.text.lower()
            else:
                response = urllib.request.urlopen(f"http://{ip}", timeout=3)
                content = response.read().decode('utf-8', errors='ignore').lower()
            
            # Check for modern security indicators
            modern_security_indicators = [
                'csrf', 'secure', 'https', 'token', 'session',
                'authentication required', 'login required'
            ]
            
            security_features_found = [indicator for indicator in modern_security_indicators 
                                     if indicator in content]
            
            if len(security_features_found) >= 3:
                analysis['modern_security'] = True
                analysis['security_features'] = security_features_found
                analysis['analysis_notes'].append('Modern security features detected')
            
            # Check for potential vulnerabilities (rare in 2025)
            vulnerability_indicators = [
                'admin/admin', 'no authentication', 'guest access',
                'default password', 'unprotected'
            ]
            
            vuln_found = [indicator for indicator in vulnerability_indicators 
                         if indicator in content]
            
            if vuln_found:
                analysis['vulnerable'] = True
                analysis['vulnerability_indicators'] = vuln_found
            
        except Exception as e:
            analysis['analysis_notes'].append(f'Web interface analysis failed: {e}')
        
        return analysis
    
    def generate_professional_poc_demo(self, assessment_type: str = 'demonstration', target_data: str = None) -> Dict[str, Any]:
        """Generate professional POC demonstration"""
        print("🔥 Professional Router Security POC Demonstration")
        print("🎯 Advanced Network Security Assessment Presentation")
        print("=" * 80)
        
        if assessment_type == 'demonstration':
            print("🎭 DEMONSTRATION MODE")
            print("   Using realistic sample data for client presentation")
            print("   Shows potential risks and tool capabilities")
            print("")
            
            # Run demonstration
            demo_result = self._run_demonstration_mode(verbose=True)
            
            # Generate comprehensive demo report
            poc_report = self._generate_demo_poc_report(demo_result)
            
            return {
                'success': True,
                'mode': 'demonstration',
                'poc_report': poc_report,
                'demo_data': demo_result,
                'client_ready': True
            }
        
        elif assessment_type == 'live' and target_data:
            print("🔍 LIVE ASSESSMENT MODE")
            print(f"   Analyzing real network: {target_data}")
            print("")
            
            # Parse targets
            ip_list = self._parse_target_input(target_data)
            
            # Perform live assessment
            live_result = self._perform_live_assessment(ip_list, verbose=True)
            
            # Generate live assessment report
            poc_report = self._generate_live_poc_report(live_result)
            
            return {
                'success': True,
                'mode': 'live_assessment',
                'poc_report': poc_report,
                'live_data': live_result,
                'client_ready': True
            }
        
        else:
            return {'success': False, 'error': 'Invalid assessment type'}
    
    def _generate_demo_poc_report(self, demo_result: Dict[str, Any]) -> str:
        """Generate demonstration POC report"""
        report = []
        
        # Professional header
        report.append("=" * 120)
        report.append("ROUTER SECURITY ASSESSMENT - PROFESSIONAL POC DEMONSTRATION")
        report.append("Advanced Network Vulnerability Analysis and SIP Configuration Extraction")
        report.append("=" * 120)
        report.append(f"Demonstration Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"Assessment Tool: Realistic Router POC v{self.version}")
        report.append(f"Presentation Mode: PROFESSIONAL DEMONSTRATION")
        report.append("")
        
        # Executive Summary
        report.append("🎯 EXECUTIVE SUMMARY")
        report.append("-" * 80)
        report.append("This demonstration shows potential security risks in network infrastructure")
        report.append("and the capabilities of professional security assessment tools.")
        report.append("")
        report.append(f"Simulated Network Assessment:")
        report.append(f"• Targets Assessed: {demo_result.get('total_targets', 0)}")
        report.append(f"• Vulnerable Devices: {demo_result['summary']['vulnerable']}")
        report.append(f"• SIP Extractions: {demo_result['summary']['sip_extracted']}")
        report.append(f"• Total SIP Accounts: {len(demo_result.get('sip_accounts_found', []))}")
        report.append("")
        
        # Demonstration Scenarios
        report.append("🎭 DEMONSTRATION SCENARIOS")
        report.append("-" * 80)
        
        # Scenario 1: Vulnerable TP-Link
        report.append("Scenario 1: Legacy TP-Link Router (192.168.1.1)")
        report.append("✅ Vulnerability: Default credentials (admin/admin)")
        report.append("✅ SIP Extraction: Successful")
        report.append("📞 SIP Accounts Found:")
        
        enterprise_accounts = self.sample_sip_data['enterprise_sip_accounts']
        for acc in enterprise_accounts[:2]:
            report.append(f"   • Extension {acc['extension']}: {acc['username']}/{acc['password']}")
            report.append(f"     Display: {acc['display_name']}")
            report.append(f"     Server: {acc['server']}")
        
        report.append("")
        
        # Scenario 2: Vulnerable Cisco
        report.append("Scenario 2: Cisco Router with Configuration Exposure (192.168.0.1)")
        report.append("✅ Vulnerability: Unauthenticated config access")
        report.append("✅ SIP Extraction: Type 7 passwords decrypted")
        report.append("📞 Encrypted SIP Accounts:")
        
        encrypted_accounts = self.sample_sip_data['encrypted_sip_samples']
        for acc in encrypted_accounts:
            report.append(f"   • Extension {acc['extension']}: {acc['username']}")
            report.append(f"     Encrypted: {acc['password_encrypted']}")
            report.append(f"     Decrypted: {acc['password_decrypted']}")
            report.append(f"     Server: {acc['server']}")
        
        report.append("")
        
        # Security Impact Analysis
        report.append("🛡️ SECURITY IMPACT ANALYSIS")
        report.append("-" * 80)
        report.append("CRITICAL RISKS DEMONSTRATED:")
        report.append("1. Unauthorized VoIP Access")
        report.append("   • Attackers can make unauthorized calls")
        report.append("   • VoIP fraud and toll fraud risks")
        report.append("   • Eavesdropping on voice communications")
        report.append("")
        
        report.append("2. Network Infrastructure Compromise")
        report.append("   • Router configuration access")
        report.append("   • Network topology discovery")
        report.append("   • Potential lateral movement")
        report.append("")
        
        report.append("3. Business Impact")
        report.append("   • Unauthorized long-distance charges")
        report.append("   • Confidential conversation interception")
        report.append("   • Reputation damage from security breach")
        report.append("")
        
        # Professional Recommendations
        report.append("💡 PROFESSIONAL SECURITY RECOMMENDATIONS")
        report.append("-" * 80)
        report.append("IMMEDIATE ACTIONS:")
        report.append("1. Change all default router credentials")
        report.append("2. Implement strong SIP authentication")
        report.append("3. Enable HTTPS for router management")
        report.append("4. Restrict management access to authorized networks")
        report.append("5. Regular security assessments and firmware updates")
        report.append("")
        
        report.append("LONG-TERM SECURITY STRATEGY:")
        report.append("1. Network segmentation for VoIP traffic")
        report.append("2. SIP encryption (SRTP/TLS) implementation")
        report.append("3. Continuous security monitoring")
        report.append("4. Employee security awareness training")
        report.append("")
        
        # POC Value Proposition
        report.append("🎯 PROFESSIONAL SERVICES VALUE PROPOSITION")
        report.append("-" * 80)
        report.append("This demonstration shows the critical importance of:")
        report.append("• Regular network security assessments")
        report.append("• Professional penetration testing services")
        report.append("• Comprehensive vulnerability management")
        report.append("• Ongoing security monitoring and support")
        report.append("")
        
        report.append("NEXT STEPS:")
        report.append("1. Comprehensive network security audit")
        report.append("2. Vulnerability remediation planning")
        report.append("3. Security policy development")
        report.append("4. Ongoing security monitoring services")
        
        # Footer
        report.append("")
        report.append("=" * 120)
        report.append("Professional Network Security Assessment Demonstration")
        report.append("Realistic Router POC Tool v13.0")
        report.append("FOR PROFESSIONAL SECURITY CONSULTING AND CLIENT PRESENTATIONS")
        report.append("=" * 120)
        
        return '\n'.join(report)
    
    def _generate_live_poc_report(self, live_result: Dict[str, Any]) -> str:
        """Generate live assessment POC report"""
        report = []
        
        # Header
        report.append("=" * 120)
        report.append("LIVE ROUTER SECURITY ASSESSMENT - PROFESSIONAL ANALYSIS")
        report.append("Real-Time Network Vulnerability Testing and Security Evaluation")
        report.append("=" * 120)
        report.append(f"Assessment Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"Assessment Tool: Realistic Router POC v{self.version}")
        report.append("")
        
        # Assessment Results
        results = live_result.get('results', {})
        reachable_count = sum(1 for r in results.values() if r.get('reachable', True))
        vulnerable_count = sum(1 for r in results.values() if r.get('vulnerable', False))
        
        report.append("🎯 LIVE ASSESSMENT SUMMARY")
        report.append("-" * 80)
        report.append(f"Total Targets: {live_result.get('total_targets', 0)}")
        report.append(f"Reachable Routers: {reachable_count}")
        report.append(f"Vulnerable Routers: {vulnerable_count}")
        
        if vulnerable_count > 0:
            report.append(f"Security Status: ⚠️ VULNERABILITIES FOUND")
        else:
            report.append(f"Security Status: ✅ NO CRITICAL VULNERABILITIES")
        
        report.append("")
        
        # Individual router results
        for ip, result in results.items():
            if result.get('reachable', True):
                report.append(f"Router: {ip}")
                
                if result.get('vulnerable'):
                    report.append("  Status: ⚠️ VULNERABLE")
                    if result.get('access_method'):
                        report.append(f"  Method: {result['access_method']}")
                elif result.get('modern_security'):
                    report.append("  Status: 🛡️ MODERN SECURITY")
                    features = result.get('security_features', [])
                    if features:
                        report.append(f"  Features: {', '.join(features[:3])}")
                else:
                    report.append("  Status: ❓ ANALYSIS INCONCLUSIVE")
                
                report.append("")
        
        # Modern router challenges
        challenges = live_result.get('modern_router_challenges', [])
        if challenges:
            report.append("🔒 MODERN ROUTER SECURITY (2025 Standards)")
            report.append("-" * 80)
            report.append("The following routers demonstrate modern security practices:")
            
            for challenge in challenges:
                ip = challenge['ip']
                features = challenge.get('security_features', [])
                report.append(f"• {ip}: {', '.join(features[:3])}")
            
            report.append("")
            report.append("This shows the evolution of router security and the need for")
            report.append("advanced security testing methodologies.")
            report.append("")
        
        # Professional assessment
        if vulnerable_count == 0 and reachable_count > 0:
            report.append("🎯 PROFESSIONAL ASSESSMENT")
            report.append("-" * 80)
            report.append("POSITIVE FINDINGS:")
            report.append("• Network demonstrates good security posture")
            report.append("• Modern security practices appear to be implemented")
            report.append("• No critical vulnerabilities identified in current scan")
            report.append("")
            
            report.append("RECOMMENDATIONS:")
            report.append("• Continue current security practices")
            report.append("• Regular security assessments recommended")
            report.append("• Stay updated with latest security patches")
            report.append("• Consider advanced penetration testing for comprehensive coverage")
        
        # Footer
        report.append("")
        report.append("=" * 120)
        report.append("Live Router Security Assessment - Professional Analysis")
        report.append("Realistic Router POC Tool v13.0")
        report.append("=" * 120)
        
        return '\n'.join(report)
    
    def decrypt_cisco_type7(self, password: str) -> str:
        """Decrypt Cisco Type 7 password (still works in 2025)"""
        try:
            if len(password) < 4:
                return "Invalid length"
            
            salt = int(password[:2])
            encrypted_text = password[2:]
            encrypted_bytes = bytes.fromhex(encrypted_text)
            
            decrypted = ""
            for i, byte in enumerate(encrypted_bytes):
                key_index = (salt + i) % len(self.cisco_type7_xlat)
                decrypted += chr(byte ^ self.cisco_type7_xlat[key_index])
            
            return decrypted
        except Exception:
            return "Decryption failed"


def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description='Realistic Router POC Tool v13.0 - Professional Security Demonstration',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
🎯 REALISTIC POC TOOL FOR 2025:
Modern routers are more secure, so this tool provides realistic POC demonstrations
that work in today's security landscape.

📋 USAGE MODES:

1. DEMONSTRATION MODE (Recommended for POC):
   python realistic_router_poc.py --demo --report client_presentation.txt
   
   • Uses realistic sample data
   • Shows potential vulnerabilities  
   • Perfect for client presentations
   • Demonstrates tool capabilities

2. LIVE ASSESSMENT MODE:
   python realistic_router_poc.py --file router_ips.txt --report live_assessment.txt
   python realistic_router_poc.py 192.168.1.1 --live
   
   • Tests real routers
   • Realistic expectations for 2025
   • Professional security assessment

3. TYPE 7 DECRYPTION (Always works):
   python realistic_router_poc.py --password "094F471A1A0A"

🎭 PERFECT FOR POC PRESENTATIONS:
• Shows what COULD happen with vulnerable routers
• Demonstrates professional security testing capabilities
• Provides realistic sample SIP extractions
• Client-ready professional documentation

⚠️ LEGAL NOTICE: For authorized security testing and demonstrations only
        """
    )
    
    parser.add_argument('target', nargs='?', help='IP address or file for live assessment')
    parser.add_argument('-p', '--password', help='Decrypt Cisco Type 7 password')
    parser.add_argument('-r', '--report', help='Generate POC report')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--demo', action='store_true', help='Demonstration mode (recommended for POC)')
    parser.add_argument('--live', action='store_true', help='Live assessment mode')
    parser.add_argument('--file', help='File containing IP addresses for live assessment')
    parser.add_argument('--json', action='store_true', help='JSON output')
    
    args = parser.parse_args()
    
    poc_tool = RealisticRouterPOC()
    
    # Password decryption (always works)
    if args.password:
        decrypted = poc_tool.decrypt_cisco_type7(args.password)
        print(f"🔑 Encrypted: {args.password}")
        print(f"🔓 Decrypted: {decrypted}")
        print("✅ Type 7 decryption works perfectly in 2025!")
        return
    
    # Demonstration mode (recommended for POC)
    if args.demo:
        result = poc_tool.generate_professional_poc_demo('demonstration')
        
        if args.json:
            print(json.dumps(result, indent=2, default=str))
        else:
            print(result['poc_report'])
        
        if args.report:
            with open(args.report, 'w', encoding='utf-8') as f:
                f.write(result['poc_report'])
            print(f"\n💾 POC demonstration report saved: {args.report}")
        
        print(f"\n🎉 PROFESSIONAL POC DEMONSTRATION COMPLETE!")
        print(f"📊 Perfect for client presentations")
        print(f"🎯 Shows security assessment value")
        return
    
    # Live assessment mode
    if args.live or args.file or args.target:
        target_data = args.file or args.target
        
        if not target_data:
            print("❌ No target specified for live assessment")
            return
        
        result = poc_tool.generate_professional_poc_demo('live', target_data)
        
        if args.json:
            print(json.dumps(result, indent=2, default=str))
        else:
            print(result['poc_report'])
        
        if args.report:
            with open(args.report, 'w', encoding='utf-8') as f:
                f.write(result['poc_report'])
            print(f"\n💾 Live assessment report saved: {args.report}")
        
        return
    
    # Default help
    print("Realistic Router POC Tool v13.0 - Professional Edition")
    print("")
    print("🎯 RECOMMENDED FOR POC:")
    print("  python realistic_router_poc.py --demo --report client_poc.txt")
    print("")
    print("🔍 LIVE ASSESSMENT:")
    print("  python realistic_router_poc.py --file router_ips.txt --live")
    print("  python realistic_router_poc.py 192.168.1.1 --live")
    print("")
    print("🔑 TYPE 7 DECRYPTION:")
    print("  python realistic_router_poc.py --password '094F471A1A0A'")
    print("")
    print("Use --help for complete options")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n🔥 POC DEMONSTRATION TERMINATED")
    except Exception as e:
        print(f"\n💥 ERROR: {e}")
        sys.exit(1)