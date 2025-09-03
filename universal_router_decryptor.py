#!/usr/bin/env python3
"""
Universal Router Configuration Decryptor
A comprehensive tool for decrypting and analyzing router configuration files

Supports multiple router brands:
- Cisco (IOS, Type 7 passwords)
- MikroTik (RouterOS backups)
- TP-Link, D-Link, NetComm
- Generic encrypted configs (AES, DES, 3DES)
- Base64 encoded files

Author: Network Security Tool
Version: 2.0
"""

import base64
import hashlib
import struct
import os
import sys
import argparse
import json
import re
import binascii
# Try to import GUI libraries (optional)
try:
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox, scrolledtext
    import threading
    GUI_AVAILABLE = True
except ImportError:
    GUI_AVAILABLE = False
from pathlib import Path
from typing import Optional, Dict, Any, List, Tuple
import xml.etree.ElementTree as ET

# Try to import crypto libraries
try:
    from Crypto.Cipher import AES, DES, DES3
    from Crypto.Util.Padding import unpad
    CRYPTO_AVAILABLE = True
except ImportError:
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.backends import default_backend
        CRYPTO_AVAILABLE = True
    except ImportError:
        CRYPTO_AVAILABLE = False

class UniversalRouterDecryptor:
    """Universal router configuration decryptor supporting multiple brands"""
    
    def __init__(self):
        # Cisco Type 7 translation table
        self.cisco_type7_xlat = [
            0x64, 0x73, 0x66, 0x64, 0x3b, 0x6b, 0x66, 0x6f, 0x41, 0x2c, 0x2e,
            0x69, 0x79, 0x65, 0x77, 0x72, 0x6b, 0x6c, 0x64, 0x4a, 0x4b, 0x44,
            0x48, 0x53, 0x55, 0x42, 0x73, 0x67, 0x76, 0x63, 0x61, 0x36, 0x39,
            0x38, 0x33, 0x34, 0x6e, 0x63, 0x78, 0x76, 0x39, 0x38, 0x37, 0x33,
            0x32, 0x35, 0x34, 0x6b, 0x3b, 0x66, 0x67, 0x38, 0x37
        ]
        
        # Common router passwords for brute force
        self.common_passwords = [
            'admin', 'password', '123456', 'cisco', 'mikrotik',
            'router', 'switch', 'default', '', 'root', 'administrator',
            'netcomm', 'tplink', 'dlink', 'linksys', 'netgear',
            '1234', '12345', 'qwerty', 'abc123', 'letmein'
        ]
        
        # Router brand signatures - Extended support
        self.router_signatures = {
            'cisco': [b'version ', b'interface ', b'router ', b'hostname ', b'cisco', b'IOS'],
            'mikrotik': [b'MIKROTIK', b'RouterOS', b'/interface', b'/ip', b'winbox'],
            'tplink': [b'TP-LINK', b'TL-', b'Archer', b'wireless', b'tplink', b'tp-link'],
            'dlink': [b'D-Link', b'DI-', b'DIR-', b'wireless', b'd-link', b'dlink'],
            'netcomm': [b'NetComm', b'NF-', b'NL-', b'wireless', b'netcomm'],
            'juniper': [b'JUNOS', b'juniper', b'set interfaces', b'commit'],
            'huawei': [b'Huawei', b'VRP', b'interface GigabitEthernet', b'huawei'],
            'asus': [b'ASUS', b'RT-', b'wireless', b'asus', b'router'],
            'linksys': [b'Linksys', b'WRT', b'EA-', b'linksys'],
            'netgear': [b'NETGEAR', b'R6000', b'R7000', b'netgear'],
            'ubiquiti': [b'Ubiquiti', b'EdgeOS', b'UniFi', b'ubnt'],
            'fortinet': [b'FortiGate', b'FortiOS', b'fortinet'],
            'pfsense': [b'pfSense', b'FreeBSD', b'pfsense'],
            'openwrt': [b'OpenWrt', b'LEDE', b'openwrt']
        }
    
    def detect_file_type_and_brand(self, file_path: str) -> Tuple[str, str]:
        """Detect file type and router brand"""
        try:
            with open(file_path, 'rb') as f:
                content = f.read(2048)  # Read first 2KB
            
            file_extension = Path(file_path).suffix.lower()
            
            # Check for specific file extensions
            if file_extension == '.backup':
                return 'mikrotik_backup', 'mikrotik'
            elif file_extension == '.rsc':
                return 'mikrotik_export', 'mikrotik'
            elif file_extension in ['.cfg', '.conf', '.txt']:
                # Try to detect brand from content
                brand = self.detect_router_brand(content)
                
                # Check if it's encrypted
                if self.is_text_config(content):
                    return f'{brand}_text', brand
                elif self.is_base64_encoded(content):
                    return f'{brand}_base64', brand
                else:
                    return f'{brand}_encrypted', brand
            
            # Generic detection
            if self.is_base64_encoded(content):
                brand = self.detect_router_brand(base64.b64decode(content))
                return f'{brand}_base64', brand
            elif self.is_text_config(content):
                brand = self.detect_router_brand(content)
                return f'{brand}_text', brand
            else:
                brand = self.detect_router_brand(content)
                return f'{brand}_binary', brand
                
        except Exception as e:
            return 'unknown', 'unknown'
    
    def detect_router_brand(self, content: bytes) -> str:
        """Detect router brand from content"""
        content_lower = content.lower()
        
        for brand, signatures in self.router_signatures.items():
            for signature in signatures:
                if signature.lower() in content_lower:
                    return brand
        
        return 'generic'
    
    def is_text_config(self, content: bytes) -> bool:
        """Check if content is readable text configuration"""
        try:
            text = content.decode('utf-8', errors='ignore')
            # Check for common config keywords
            keywords = ['interface', 'ip', 'router', 'version', 'hostname', 'password']
            found_keywords = sum(1 for keyword in keywords if keyword.lower() in text.lower())
            
            # Check if mostly printable characters
            printable_ratio = len([c for c in text if c.isprintable()]) / len(text) if text else 0
            
            return found_keywords >= 2 and printable_ratio > 0.8
        except:
            return False
    
    def is_base64_encoded(self, content: bytes) -> bool:
        """Check if content is Base64 encoded"""
        try:
            # Remove whitespace and check if valid base64
            cleaned = re.sub(rb'[\r\n\s]', b'', content)
            if len(cleaned) % 4 != 0:
                return False
            
            decoded = base64.b64decode(cleaned)
            # Check if decoded content looks like config
            return self.is_text_config(decoded)
        except:
            return False
    
    def decrypt_cisco_type7(self, password: str) -> str:
        """Decrypt Cisco Type 7 passwords"""
        try:
            if len(password) < 4:
                return "Password too short"
            
            # Extract salt and encrypted text
            salt = int(password[:2])
            encrypted_text = password[2:]
            
            # Convert hex to bytes
            try:
                encrypted_bytes = bytes.fromhex(encrypted_text)
            except ValueError:
                return "Invalid password format"
            
            # Decrypt
            decrypted = ""
            for i, byte in enumerate(encrypted_bytes):
                key_index = (salt + i) % len(self.cisco_type7_xlat)
                decrypted += chr(byte ^ self.cisco_type7_xlat[key_index])
            
            return decrypted
            
        except Exception as e:
            return f"Decryption error: {e}"
    
    def decrypt_base64_config(self, file_path: str) -> str:
        """Decode Base64 encoded configuration files"""
        try:
            with open(file_path, 'rb') as f:
                encoded_content = f.read()
            
            # Clean up whitespace
            cleaned_content = re.sub(rb'[\r\n\s]', b'', encoded_content)
            decoded = base64.b64decode(cleaned_content)
            return decoded.decode('utf-8', errors='ignore')
            
        except Exception as e:
            return f"Base64 decode error: {e}"
    
    def try_aes_decryption(self, data: bytes, password: str) -> Optional[bytes]:
        """Try AES decryption with given password"""
        if not CRYPTO_AVAILABLE:
            return None
        
        try:
            # Generate key from password
            key = hashlib.sha256(password.encode()).digest()[:32]
            
            # Try different AES modes
            modes_to_try = [
                (b'\x00' * 16, 'CBC'),  # Zero IV
                (data[:16], 'CBC'),     # First block as IV
                (None, 'ECB')           # ECB mode
            ]
            
            for iv_data, mode_name in modes_to_try:
                try:
                    if CRYPTO_AVAILABLE and 'Crypto' in sys.modules:
                        # Using PyCryptodome
                        if mode_name == 'CBC':
                            cipher = AES.new(key, AES.MODE_CBC, iv_data)
                            decrypted = cipher.decrypt(data[16:] if iv_data == data[:16] else data)
                        else:
                            cipher = AES.new(key, AES.MODE_ECB)
                            decrypted = cipher.decrypt(data)
                    else:
                        # Using cryptography library
                        backend = default_backend()
                        if mode_name == 'CBC':
                            cipher = Cipher(algorithms.AES(key), modes.CBC(iv_data), backend=backend)
                            decryptor = cipher.decryptor()
                            decrypted = decryptor.update(data[16:] if iv_data == data[:16] else data)
                            decrypted += decryptor.finalize()
                        else:
                            cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
                            decryptor = cipher.decryptor()
                            decrypted = decryptor.update(data) + decryptor.finalize()
                    
                    # Try to remove padding
                    try:
                        if CRYPTO_AVAILABLE and 'Crypto' in sys.modules:
                            from Crypto.Util.Padding import unpad
                            decrypted = unpad(decrypted, 16)
                    except:
                        pass
                    
                    # Check if result looks valid
                    if self.is_valid_decrypted_config(decrypted):
                        return decrypted
                        
                except Exception:
                    continue
            
            return None
                
        except Exception:
            return None
    
    def try_des_decryption(self, data: bytes, password: str) -> Optional[bytes]:
        """Try DES decryption with given password"""
        if not CRYPTO_AVAILABLE:
            return None
        
        try:
            # Generate 8-byte key for DES
            key = hashlib.md5(password.encode()).digest()[:8]
            
            if 'Crypto' in sys.modules:
                cipher = DES.new(key, DES.MODE_ECB)
                decrypted = cipher.decrypt(data)
            else:
                # Using cryptography library
                backend = default_backend()
                cipher = Cipher(algorithms.TripleDES(key), modes.ECB(), backend=backend)
                decryptor = cipher.decryptor()
                decrypted = decryptor.update(data) + decryptor.finalize()
            
            if self.is_valid_decrypted_config(decrypted):
                return decrypted
            
            return None
            
        except Exception:
            return None
    
    def is_valid_decrypted_config(self, data: bytes) -> bool:
        """Check if decrypted data looks like valid configuration"""
        try:
            text = data.decode('utf-8', errors='ignore')
            
            # Configuration keywords
            keywords = [
                'interface', 'router', 'ip', 'version', 'hostname',
                'access-list', 'vlan', 'enable', 'password', 'username',
                'wireless', 'ssid', 'network', 'dhcp', 'gateway'
            ]
            
            found_keywords = sum(1 for keyword in keywords if keyword.lower() in text.lower())
            
            # Check printable character ratio
            printable_ratio = len([c for c in text if c.isprintable()]) / len(text) if text else 0
            
            return found_keywords >= 2 and printable_ratio > 0.7
            
        except:
            return False
    
    def brute_force_decrypt(self, data: bytes) -> List[Dict[str, Any]]:
        """Brute force decryption with common passwords"""
        results = []
        
        if not CRYPTO_AVAILABLE:
            return results
        
        for password in self.common_passwords:
            # Try AES
            aes_result = self.try_aes_decryption(data, password)
            if aes_result:
                results.append({
                    'method': 'AES',
                    'password': password,
                    'data': aes_result,
                    'text': aes_result.decode('utf-8', errors='ignore')
                })
            
            # Try DES
            des_result = self.try_des_decryption(data, password)
            if des_result:
                results.append({
                    'method': 'DES',
                    'password': password,
                    'data': des_result,
                    'text': des_result.decode('utf-8', errors='ignore')
                })
        
        return results
    
    def parse_cisco_config(self, content: str) -> Dict[str, Any]:
        """Parse Cisco configuration and extract important information"""
        info = {
            'hostname': None,
            'interfaces': [],
            'passwords': [],
            'users': [],
            'routing': [],
            'vlans': [],
            'access_lists': [],
            'ip_addresses': [],
            'networks': []
        }
        
        lines = content.split('\n')
        
        for line in lines:
            line = line.strip()
            
            # Extract hostname
            if line.startswith('hostname '):
                info['hostname'] = line.split(' ', 1)[1]
            
            # Extract interfaces
            if line.startswith('interface '):
                info['interfaces'].append(line)
            
            # Extract Type 7 passwords
            if 'password 7 ' in line:
                match = re.search(r'password 7 ([A-Fa-f0-9]+)', line)
                if match:
                    encrypted_pass = match.group(1)
                    decrypted_pass = self.decrypt_cisco_type7(encrypted_pass)
                    info['passwords'].append({
                        'line': line,
                        'encrypted': encrypted_pass,
                        'decrypted': decrypted_pass,
                        'type': 'cisco_type7'
                    })
            
            # Extract users
            if line.startswith('username '):
                info['users'].append(line)
            
            # Extract routing information
            if line.startswith('ip route') or line.startswith('router '):
                info['routing'].append(line)
            
            # Extract VLANs
            if line.startswith('vlan ') or 'switchport access vlan' in line:
                info['vlans'].append(line)
            
            # Extract Access Lists
            if line.startswith('access-list') or line.startswith('ip access-list'):
                info['access_lists'].append(line)
            
            # Extract IP addresses
            ip_matches = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line)
            info['ip_addresses'].extend(ip_matches)
            
            # Extract networks
            network_matches = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}\b', line)
            info['networks'].extend(network_matches)
        
        # Remove duplicates
        info['ip_addresses'] = list(set(info['ip_addresses']))
        info['networks'] = list(set(info['networks']))
        
        return info
    
    def parse_generic_config(self, content: str, brand: str) -> Dict[str, Any]:
        """Parse generic router configuration with brand-specific handling"""
        info = {
            'brand': brand,
            'passwords': [],
            'wireless_settings': [],
            'network_settings': [],
            'ip_addresses': [],
            'users': [],
            'security_settings': [],
            'port_forwarding': [],
            'firewall_rules': []
        }
        
        lines = content.split('\n')
        
        for line_orig in lines:
            line = line_orig.strip()
            line_lower = line.lower()
            
            # Brand-specific password extraction
            if brand in ['tplink', 'dlink', 'netcomm']:
                # TP-Link, D-Link, NetComm style configs
                password_patterns = [
                    r'password[=:\s]*([^\s\n\r]+)',
                    r'passwd[=:\s]*([^\s\n\r]+)',
                    r'key[=:\s]*([^\s\n\r]+)',
                    r'secret[=:\s]*([^\s\n\r]+)',
                    r'admin\.password[=:\s]*([^\s\n\r]+)',
                    r'wireless.*password[=:\s]*([^\s\n\r]+)'
                ]
            else:
                # Generic patterns
                password_patterns = [
                    r'password[=:\s]+([^\s\n]+)',
                    r'passwd[=:\s]+([^\s\n]+)',
                    r'key[=:\s]+([^\s\n]+)',
                    r'secret[=:\s]+([^\s\n]+)'
                ]
            
            for pattern in password_patterns:
                matches = re.findall(pattern, line, re.IGNORECASE)
                for match in matches:
                    if len(match) > 2 and match not in ['none', 'null', 'auto']:
                        info['passwords'].append({
                            'line': line_orig,
                            'password': match,
                            'type': f'{brand}_password'
                        })
            
            # Extract wireless settings
            wireless_keywords = ['ssid', 'wireless', 'wifi', 'wlan', 'wpa', 'wep', 'security']
            if any(keyword in line_lower for keyword in wireless_keywords):
                info['wireless_settings'].append(line_orig)
            
            # Extract network settings
            network_keywords = ['dhcp', 'gateway', 'dns', 'subnet', 'netmask', 'lan', 'wan']
            if any(keyword in line_lower for keyword in network_keywords):
                info['network_settings'].append(line_orig)
            
            # Extract security settings
            security_keywords = ['firewall', 'acl', 'filter', 'block', 'allow', 'deny']
            if any(keyword in line_lower for keyword in security_keywords):
                info['security_settings'].append(line_orig)
            
            # Extract port forwarding
            if any(keyword in line_lower for keyword in ['forward', 'port', 'nat', 'redirect']):
                info['port_forwarding'].append(line_orig)
            
            # Extract IP addresses
            ip_matches = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line)
            info['ip_addresses'].extend(ip_matches)
            
            # Extract users and admin accounts
            user_keywords = ['user', 'admin', 'login', 'account']
            if any(keyword in line_lower for keyword in user_keywords):
                info['users'].append(line_orig)
        
        # Remove duplicates
        info['ip_addresses'] = list(set(info['ip_addresses']))
        
        # Limit arrays to prevent overflow
        for key in info:
            if isinstance(info[key], list) and len(info[key]) > 50:
                info[key] = info[key][:50]
        
        return info
    
    def analyze_mikrotik_backup(self, file_path: str) -> Dict[str, Any]:
        """Analyze MikroTik backup files"""
        info = {
            'file_type': 'MikroTik Backup',
            'brand': 'mikrotik',
            'status': 'encrypted',
            'note': 'MikroTik .backup files can only be restored on the same or similar device',
            'extractable_info': []
        }
        
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
            
            info['file_size'] = len(content)
            
            # Try to find readable strings
            readable_strings = []
            current_string = ""
            
            for byte in content:
                if 32 <= byte <= 126:  # Printable ASCII
                    current_string += chr(byte)
                else:
                    if len(current_string) > 4:
                        readable_strings.append(current_string)
                    current_string = ""
            
            # Add final string if exists
            if len(current_string) > 4:
                readable_strings.append(current_string)
            
            # Filter meaningful strings
            meaningful_strings = []
            for s in readable_strings:
                if any(keyword in s.lower() for keyword in ['interface', 'ip', 'user', 'password', 'admin']):
                    meaningful_strings.append(s)
            
            info['extractable_info'] = meaningful_strings[:20]  # Limit to first 20
            
            return info
            
        except Exception as e:
            info['error'] = str(e)
            return info
    
    def decrypt_file(self, file_path: str, output_path: Optional[str] = None) -> Dict[str, Any]:
        """Main decryption function"""
        if not os.path.exists(file_path):
            return {'error': 'File does not exist', 'success': False}
        
        file_type, brand = self.detect_file_type_and_brand(file_path)
        
        result = {
            'file_path': file_path,
            'file_type': file_type,
            'brand': brand,
            'file_size': os.path.getsize(file_path),
            'success': False
        }
        
        try:
            if 'text' in file_type:
                # Plain text configuration
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                result['content'] = content
                result['success'] = True
                
                # Parse based on brand
                if brand == 'cisco':
                    parsed_info = self.parse_cisco_config(content)
                    result.update(parsed_info)
                else:
                    parsed_info = self.parse_generic_config(content, brand)
                    result.update(parsed_info)
                
            elif 'base64' in file_type:
                # Base64 encoded configuration
                decoded_content = self.decrypt_base64_config(file_path)
                result['content'] = decoded_content
                result['success'] = True
                
                # Parse decoded content
                if brand == 'cisco':
                    parsed_info = self.parse_cisco_config(decoded_content)
                    result.update(parsed_info)
                else:
                    parsed_info = self.parse_generic_config(decoded_content, brand)
                    result.update(parsed_info)
                
            elif file_type == 'mikrotik_backup':
                # MikroTik backup file
                mikrotik_info = self.analyze_mikrotik_backup(file_path)
                result.update(mikrotik_info)
                result['success'] = True
                
            elif 'encrypted' in file_type or 'binary' in file_type:
                # Try brute force decryption
                with open(file_path, 'rb') as f:
                    encrypted_data = f.read()
                
                brute_results = self.brute_force_decrypt(encrypted_data)
                
                if brute_results:
                    result['brute_force_results'] = brute_results
                    result['content'] = brute_results[0]['text']
                    result['success'] = True
                    result['decryption_method'] = brute_results[0]['method']
                    result['decryption_password'] = brute_results[0]['password']
                    
                    # Parse decrypted content
                    if brand == 'cisco':
                        parsed_info = self.parse_cisco_config(brute_results[0]['text'])
                        result.update(parsed_info)
                    else:
                        parsed_info = self.parse_generic_config(brute_results[0]['text'], brand)
                        result.update(parsed_info)
                else:
                    result['error'] = 'Could not decrypt with common passwords'
            
            else:
                result['error'] = f'Unsupported file type: {file_type}'
            
            # Save output if requested
            if output_path and result.get('content'):
                with open(output_path, 'w', encoding='utf-8') as f:
                    f.write(result['content'])
                result['output_saved'] = output_path
                
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def format_results(self, result: Dict[str, Any]) -> str:
        """Format results for display"""
        output = []
        output.append("=" * 80)
        output.append("ROUTER CONFIGURATION ANALYSIS RESULTS")
        output.append("=" * 80)
        
        # Basic file information
        output.append(f"File Path: {result['file_path']}")
        output.append(f"File Type: {result['file_type']}")
        output.append(f"Router Brand: {result['brand'].upper()}")
        output.append(f"File Size: {result['file_size']} bytes")
        output.append(f"Status: {'SUCCESS' if result['success'] else 'FAILED'}")
        
        if 'error' in result:
            output.append(f"Error: {result['error']}")
            return '\n'.join(output)
        
        # Decryption information
        if 'decryption_method' in result:
            output.append(f"Decryption Method: {result['decryption_method']}")
            output.append(f"Password Used: {result['decryption_password']}")
        
        # Hostname
        if result.get('hostname'):
            output.append(f"\n🏷️  HOSTNAME: {result['hostname']}")
        
        # Passwords found
        if 'passwords' in result and result['passwords']:
            output.append(f"\n🔑 PASSWORDS FOUND ({len(result['passwords'])}):")
            for i, pwd in enumerate(result['passwords'][:10], 1):
                if pwd.get('type') == 'cisco_type7':
                    output.append(f"  {i}. Encrypted: {pwd['encrypted']}")
                    output.append(f"     Decrypted: {pwd['decrypted']}")
                    output.append(f"     Line: {pwd['line']}")
                else:
                    output.append(f"  {i}. Password: {pwd['password']}")
                    output.append(f"     Line: {pwd['line']}")
                output.append("")
        
        # Network interfaces
        if 'interfaces' in result and result['interfaces']:
            output.append(f"🌐 NETWORK INTERFACES ({len(result['interfaces'])}):")
            for interface in result['interfaces'][:10]:
                output.append(f"  • {interface}")
            if len(result['interfaces']) > 10:
                output.append(f"  ... and {len(result['interfaces']) - 10} more")
            output.append("")
        
        # IP addresses
        if 'ip_addresses' in result and result['ip_addresses']:
            output.append(f"🔢 IP ADDRESSES ({len(result['ip_addresses'])}):")
            for ip in result['ip_addresses'][:15]:
                output.append(f"  • {ip}")
            if len(result['ip_addresses']) > 15:
                output.append(f"  ... and {len(result['ip_addresses']) - 15} more")
            output.append("")
        
        # Users
        if 'users' in result and result['users']:
            output.append(f"👤 USER ACCOUNTS ({len(result['users'])}):")
            for user in result['users'][:5]:
                output.append(f"  • {user}")
            output.append("")
        
        # Wireless settings
        if 'wireless_settings' in result and result['wireless_settings']:
            output.append(f"📶 WIRELESS SETTINGS ({len(result['wireless_settings'])}):")
            for setting in result['wireless_settings'][:5]:
                output.append(f"  • {setting}")
            if len(result['wireless_settings']) > 5:
                output.append(f"  ... and {len(result['wireless_settings']) - 5} more")
            output.append("")
        
        # Security settings
        if 'security_settings' in result and result['security_settings']:
            output.append(f"🛡️  SECURITY SETTINGS ({len(result['security_settings'])}):")
            for setting in result['security_settings'][:5]:
                output.append(f"  • {setting}")
            output.append("")
        
        # Port forwarding
        if 'port_forwarding' in result and result['port_forwarding']:
            output.append(f"🚪 PORT FORWARDING ({len(result['port_forwarding'])}):")
            for rule in result['port_forwarding'][:5]:
                output.append(f"  • {rule}")
            output.append("")
        
        # Routing information
        if 'routing' in result and result['routing']:
            output.append(f"🛣️  ROUTING INFO ({len(result['routing'])}):")
            for route in result['routing'][:5]:
                output.append(f"  • {route}")
            output.append("")
        
        # MikroTik specific info
        if result.get('file_type') == 'MikroTik Backup':
            if 'extractable_info' in result:
                output.append("🔍 EXTRACTABLE INFORMATION:")
                for info_item in result['extractable_info']:
                    output.append(f"  • {info_item}")
                output.append("")
        
        # Brute force results
        if 'brute_force_results' in result:
            output.append("🔓 BRUTE FORCE DECRYPTION RESULTS:")
            for br_result in result['brute_force_results']:
                output.append(f"  Method: {br_result['method']}")
                output.append(f"  Password: {br_result['password']}")
                output.append(f"  Preview: {br_result['text'][:100]}...")
                output.append("")
        
        if 'output_saved' in result:
            output.append(f"💾 Output saved to: {result['output_saved']}")
        
        output.append("=" * 80)
        
        return '\n'.join(output)


class RouterDecryptorGUI:
    """Graphical user interface for the router decryptor"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("Universal Router Config Decryptor")
        self.root.geometry("900x700")
        self.root.configure(bg='#f0f0f0')
        
        # Create decryptor
        self.decryptor = UniversalRouterDecryptor()
        
        self.setup_gui()
    
    def setup_gui(self):
        """Setup the graphical user interface"""
        
        # Title
        title_frame = tk.Frame(self.root, bg='#2c3e50', height=70)
        title_frame.pack(fill='x', pady=(0, 10))
        title_frame.pack_propagate(False)
        
        title_label = tk.Label(
            title_frame, 
            text="🔧 Universal Router Config Decryptor", 
            font=('Arial', 18, 'bold'),
            fg='white', 
            bg='#2c3e50'
        )
        title_label.pack(expand=True)
        
        subtitle_label = tk.Label(
            title_frame, 
            text="Supports Cisco, MikroTik, TP-Link, D-Link, NetComm & More", 
            font=('Arial', 10),
            fg='#ecf0f1', 
            bg='#2c3e50'
        )
        subtitle_label.pack()
        
        # Main frame
        main_frame = tk.Frame(self.root, bg='#f0f0f0')
        main_frame.pack(fill='both', expand=True, padx=20, pady=10)
        
        # File selection
        file_frame = tk.LabelFrame(main_frame, text="File Selection", font=('Arial', 11, 'bold'))
        file_frame.pack(fill='x', pady=(0, 10))
        
        self.file_path_var = tk.StringVar()
        file_entry = tk.Entry(file_frame, textvariable=self.file_path_var, width=70, font=('Consolas', 10))
        file_entry.pack(side='left', padx=10, pady=10, fill='x', expand=True)
        
        browse_btn = tk.Button(
            file_frame, 
            text="Browse File", 
            command=self.browse_file,
            bg='#3498db',
            fg='white',
            font=('Arial', 10, 'bold'),
            width=12
        )
        browse_btn.pack(side='right', padx=10, pady=10)
        
        # Options
        options_frame = tk.LabelFrame(main_frame, text="Decryption Options", font=('Arial', 11, 'bold'))
        options_frame.pack(fill='x', pady=(0, 10))
        
        # Router brand selection
        brand_frame = tk.Frame(options_frame)
        brand_frame.pack(fill='x', padx=10, pady=8)
        
        tk.Label(brand_frame, text="Router Brand:", font=('Arial', 10)).pack(side='left')
        
        self.router_brand = tk.StringVar(value="auto")
        brand_combo = ttk.Combobox(
            brand_frame, 
            textvariable=self.router_brand,
            values=["auto", "cisco", "mikrotik", "tplink", "dlink", "netcomm", "juniper", "huawei", "asus", "linksys"],
            state="readonly",
            width=15,
            font=('Arial', 9)
        )
        brand_combo.pack(side='left', padx=(10, 20))
        
        # Type 7 password field
        tk.Label(brand_frame, text="Cisco Type 7 Password:", font=('Arial', 10)).pack(side='left')
        
        self.type7_password = tk.StringVar()
        password_entry = tk.Entry(brand_frame, textvariable=self.type7_password, width=25, font=('Consolas', 9))
        password_entry.pack(side='left', padx=(10, 5))
        
        decrypt_pass_btn = tk.Button(
            brand_frame,
            text="Decrypt",
            command=self.decrypt_password_only,
            bg='#e67e22',
            fg='white',
            font=('Arial', 9, 'bold'),
            width=8
        )
        decrypt_pass_btn.pack(side='left', padx=5)
        
        # Action buttons
        buttons_frame = tk.Frame(main_frame)
        buttons_frame.pack(fill='x', pady=15)
        
        decrypt_btn = tk.Button(
            buttons_frame,
            text="🔓 DECRYPT FILE",
            command=self.decrypt_file,
            bg='#27ae60',
            fg='white',
            font=('Arial', 12, 'bold'),
            height=2,
            width=20
        )
        decrypt_btn.pack(side='left', padx=(0, 15))
        
        analyze_btn = tk.Button(
            buttons_frame,
            text="🔍 DEEP ANALYSIS",
            command=self.deep_analysis,
            bg='#8e44ad',
            fg='white',
            font=('Arial', 12, 'bold'),
            height=2,
            width=20
        )
        analyze_btn.pack(side='left', padx=(0, 15))
        
        save_btn = tk.Button(
            buttons_frame,
            text="💾 SAVE RESULTS",
            command=self.save_results,
            bg='#f39c12',
            fg='white',
            font=('Arial', 12, 'bold'),
            height=2,
            width=20
        )
        save_btn.pack(side='left', padx=(0, 15))
        
        clear_btn = tk.Button(
            buttons_frame,
            text="🗑️ CLEAR",
            command=self.clear_results,
            bg='#e74c3c',
            fg='white',
            font=('Arial', 12, 'bold'),
            height=2,
            width=15
        )
        clear_btn.pack(side='left')
        
        # Results area
        results_frame = tk.LabelFrame(main_frame, text="Results", font=('Arial', 11, 'bold'))
        results_frame.pack(fill='both', expand=True, pady=(15, 0))
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(results_frame)
        self.notebook.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Analysis results tab
        self.analysis_tab = tk.Frame(self.notebook)
        self.notebook.add(self.analysis_tab, text="📊 Analysis Results")
        
        self.analysis_text = scrolledtext.ScrolledText(
            self.analysis_tab,
            wrap=tk.WORD,
            font=('Consolas', 10),
            bg='#2c3e50',
            fg='#ecf0f1'
        )
        self.analysis_text.pack(fill='both', expand=True)
        
        # Raw content tab
        self.content_tab = tk.Frame(self.notebook)
        self.notebook.add(self.content_tab, text="📄 Raw Content")
        
        self.content_text = scrolledtext.ScrolledText(
            self.content_tab,
            wrap=tk.WORD,
            font=('Consolas', 9),
            bg='#34495e',
            fg='#ecf0f1'
        )
        self.content_text.pack(fill='both', expand=True)
        
        # Status bar
        self.status_var = tk.StringVar(value="Ready - Select a config file to decrypt")
        status_bar = tk.Label(
            self.root,
            textvariable=self.status_var,
            relief=tk.SUNKEN,
            anchor=tk.W,
            bg='#bdc3c7',
            font=('Arial', 10)
        )
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)
    
    def browse_file(self):
        """Browse for configuration file"""
        file_types = [
            ("All Config Files", "*.cfg;*.conf;*.txt;*.backup;*.rsc"),
            ("Cisco Configs", "*.cfg;*.conf;*.txt"),
            ("MikroTik Files", "*.backup;*.rsc"),
            ("All Files", "*.*")
        ]
        
        filename = filedialog.askopenfilename(
            title="Select Router Configuration File",
            filetypes=file_types
        )
        
        if filename:
            self.file_path_var.set(filename)
            self.status_var.set(f"Selected: {os.path.basename(filename)}")
    
    def decrypt_password_only(self):
        """Decrypt only Type 7 password"""
        password = self.type7_password.get().strip()
        if not password:
            messagebox.showwarning("Warning", "Please enter a Type 7 password")
            return
        
        self.status_var.set("Decrypting password...")
        
        try:
            decrypted = self.decryptor.decrypt_cisco_type7(password)
            
            result_text = f"Encrypted Password: {password}\n"
            result_text += f"Decrypted Password: {decrypted}\n"
            result_text += f"Status: {'Success' if 'error' not in decrypted.lower() else 'Failed'}\n"
            
            self.analysis_text.delete(1.0, tk.END)
            self.analysis_text.insert(1.0, result_text)
            
            self.status_var.set("Password decrypted successfully")
            
        except Exception as e:
            messagebox.showerror("Error", f"Password decryption failed: {e}")
            self.status_var.set("Password decryption failed")
    
    def decrypt_file(self):
        """Decrypt configuration file"""
        file_path = self.file_path_var.get().strip()
        if not file_path:
            messagebox.showwarning("Warning", "Please select a file")
            return
        
        if not os.path.exists(file_path):
            messagebox.showerror("Error", "File does not exist")
            return
        
        # Run in separate thread
        threading.Thread(target=self._decrypt_file_thread, args=(file_path,), daemon=True).start()
    
    def _decrypt_file_thread(self, file_path):
        """Thread for file decryption"""
        self.root.after(0, lambda: self.status_var.set("Decrypting file... Please wait"))
        
        try:
            result = self.decryptor.decrypt_file(file_path)
            
            # Show results in UI thread
            self.root.after(0, lambda: self._show_results(result))
            
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Error", f"Decryption failed: {e}"))
            self.root.after(0, lambda: self.status_var.set("Decryption failed"))
    
    def _show_results(self, result):
        """Display decryption results"""
        # Clear previous results
        self.analysis_text.delete(1.0, tk.END)
        self.content_text.delete(1.0, tk.END)
        
        # Format and show analysis
        formatted_results = self.decryptor.format_results(result)
        self.analysis_text.insert(1.0, formatted_results)
        
        # Show raw content
        if 'content' in result:
            self.content_text.insert(1.0, result['content'])
        
        # Update status
        if result['success']:
            self.status_var.set(f"Successfully processed {result['brand'].upper()} {result['file_type']}")
        else:
            self.status_var.set(f"Failed to process file: {result.get('error', 'Unknown error')}")
    
    def deep_analysis(self):
        """Perform deep analysis with brute force"""
        file_path = self.file_path_var.get().strip()
        if not file_path:
            messagebox.showwarning("Warning", "Please select a file")
            return
        
        # Ask for confirmation for brute force
        if not messagebox.askyesno("Confirm", "Deep analysis may take longer. Continue?"):
            return
        
        threading.Thread(target=self._deep_analysis_thread, args=(file_path,), daemon=True).start()
    
    def _deep_analysis_thread(self, file_path):
        """Thread for deep analysis"""
        self.root.after(0, lambda: self.status_var.set("Performing deep analysis... This may take a while"))
        
        try:
            result = self.decryptor.decrypt_file(file_path)
            
            # Additional analysis for encrypted files
            if not result['success'] and os.path.exists(file_path):
                with open(file_path, 'rb') as f:
                    data = f.read()
                
                # Try more extensive brute force
                extended_passwords = self.decryptor.common_passwords + [
                    'admin123', 'password123', 'router123', 'default123',
                    '111111', '000000', '123123', 'qwerty123'
                ]
                
                for password in extended_passwords:
                    aes_result = self.decryptor.try_aes_decryption(data, password)
                    if aes_result:
                        result['content'] = aes_result.decode('utf-8', errors='ignore')
                        result['success'] = True
                        result['decryption_method'] = 'AES Extended'
                        result['decryption_password'] = password
                        break
            
            self.root.after(0, lambda: self._show_results(result))
            
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Error", f"Deep analysis failed: {e}"))
            self.root.after(0, lambda: self.status_var.set("Deep analysis failed"))
    
    def save_results(self):
        """Save results to file"""
        content = self.content_text.get(1.0, tk.END).strip()
        if not content:
            content = self.analysis_text.get(1.0, tk.END).strip()
        
        if not content:
            messagebox.showwarning("Warning", "No content to save")
            return
        
        filename = filedialog.asksaveasfilename(
            title="Save Results",
            defaultextension=".txt",
            filetypes=[
                ("Text Files", "*.txt"),
                ("Config Files", "*.cfg"),
                ("All Files", "*.*")
            ]
        )
        
        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(content)
                messagebox.showinfo("Success", f"Results saved to {filename}")
                self.status_var.set(f"Results saved to {os.path.basename(filename)}")
            except Exception as e:
                messagebox.showerror("Error", f"Save failed: {e}")
    
    def clear_results(self):
        """Clear all results"""
        self.analysis_text.delete(1.0, tk.END)
        self.content_text.delete(1.0, tk.END)
        self.file_path_var.set("")
        self.type7_password.set("")
        self.status_var.set("Ready - Select a config file to decrypt")


def create_sample_files():
    """Create sample configuration files for testing"""
    
    # Sample Cisco configuration
    cisco_config = """!
version 15.1
service timestamps debug datetime msec
service timestamps log datetime msec
no service password-encryption
!
hostname NetworkRouter
!
enable secret 5 $1$mERr$hx5rVt7rPNoS4wqbXKX7m0
enable password 7 0822455D0A16
!
username admin privilege 15 password 7 094F471A1A0A
username guest password 7 05080F1C2243
username netadmin secret 5 $1$salt$qJH7.N4xYta6E2z5.vS2C1
!
interface GigabitEthernet0/0
 description LAN Interface
 ip address 192.168.1.1 255.255.255.0
 no shutdown
!
interface GigabitEthernet0/1
 description WAN Interface
 ip address dhcp
 no shutdown
!
interface Vlan10
 description VLAN 10 - Management
 ip address 10.0.10.1 255.255.255.0
!
ip route 0.0.0.0 0.0.0.0 192.168.1.254
ip route 10.0.0.0 255.255.0.0 10.0.10.254
!
access-list 100 permit tcp any any eq www
access-list 100 permit tcp any any eq 443
access-list 100 deny ip any any
!
vlan 10
 name Management
vlan 20
 name Users
!
line con 0
 password 7 060506324F41
 login
line vty 0 4
 password 7 121A0C041104
 login
!
snmp-server community public RO
snmp-server community private RW
!
end
"""
    
    # Sample TP-Link style configuration
    tplink_config = """#TP-LINK Configuration File
#Model: Archer C7
#Version: 3.15.3

wireless.2g.ssid=MyNetwork_2G
wireless.2g.password=MyWiFiPassword123
wireless.2g.security=WPA2-PSK

wireless.5g.ssid=MyNetwork_5G
wireless.5g.password=MyWiFiPassword123
wireless.5g.security=WPA2-PSK

lan.ip=192.168.0.1
lan.subnet=255.255.255.0
lan.dhcp.enable=1
lan.dhcp.start=192.168.0.100
lan.dhcp.end=192.168.0.199

wan.type=dhcp
wan.dns1=8.8.8.8
wan.dns2=8.8.4.4

admin.username=admin
admin.password=admin123

firewall.enable=1
firewall.level=medium
"""
    
    # Create files
    with open('/workspace/sample_cisco_config.txt', 'w') as f:
        f.write(cisco_config)
    
    with open('/workspace/sample_tplink_config.txt', 'w') as f:
        f.write(tplink_config)
    
    # Create Base64 encoded version
    encoded_cisco = base64.b64encode(cisco_config.encode()).decode()
    with open('/workspace/sample_base64_config.txt', 'w') as f:
        f.write(encoded_cisco)
    
    print("✅ Sample configuration files created:")
    print("   • sample_cisco_config.txt")
    print("   • sample_tplink_config.txt")
    print("   • sample_base64_config.txt")


def main():
    """Main function - entry point"""
    parser = argparse.ArgumentParser(
        description='Universal Router Configuration Decryptor',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Usage Examples:
  python universal_router_decryptor.py config.txt
  python universal_router_decryptor.py backup.backup -o decrypted.txt
  python universal_router_decryptor.py -p "094F471A1A0A"
  python universal_router_decryptor.py --gui
  python universal_router_decryptor.py --create-samples

Supported Router Brands:
  • Cisco (IOS, Type 7 passwords)
  • MikroTik (RouterOS backups)
  • TP-Link, D-Link, NetComm
  • Juniper, Huawei, ASUS, Linksys
  • Generic encrypted configs
        """
    )
    
    parser.add_argument('file', nargs='?', help='Configuration file path')
    parser.add_argument('-o', '--output', help='Output file path')
    parser.add_argument('-p', '--password', help='Decrypt Cisco Type 7 password')
    parser.add_argument('-b', '--brand', choices=['auto', 'cisco', 'mikrotik', 'tplink', 'dlink', 'netcomm'], 
                       default='auto', help='Router brand (auto-detect if not specified)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--gui', action='store_true', help='Launch graphical interface')
    parser.add_argument('--create-samples', action='store_true', help='Create sample files for testing')
    parser.add_argument('--deep-analysis', action='store_true', help='Perform deep analysis with brute force')
    
    args = parser.parse_args()
    
    # Create decryptor instance
    decryptor = UniversalRouterDecryptor()
    
    # Handle different modes
    if args.gui:
        if not GUI_AVAILABLE:
            print("Error: GUI libraries not available. Install tkinter to use graphical interface.")
            print("Use command line interface instead.")
            return
        
        # Launch GUI
        root = tk.Tk()
        app = RouterDecryptorGUI(root)
        
        # Add context menu for copy/paste
        def show_context_menu(event):
            context_menu = tk.Menu(root, tearoff=0)
            context_menu.add_command(label="Copy", command=lambda: event.widget.event_generate("<<Copy>>"))
            context_menu.add_command(label="Select All", command=lambda: event.widget.event_generate("<<SelectAll>>"))
            
            try:
                context_menu.tk_popup(event.x_root, event.y_root)
            finally:
                context_menu.grab_release()
        
        app.analysis_text.bind("<Button-3>", show_context_menu)
        app.content_text.bind("<Button-3>", show_context_menu)
        
        root.mainloop()
        return
    
    if args.create_samples:
        create_sample_files()
        return
    
    if args.password:
        # Decrypt single password
        decrypted = decryptor.decrypt_cisco_type7(args.password)
        print(f"Encrypted Password: {args.password}")
        print(f"Decrypted Password: {decrypted}")
        return
    
    if not args.file:
        print("Error: Please specify a configuration file or use --gui for graphical interface")
        parser.print_help()
        return
    
    # Process file
    print("🔍 Analyzing configuration file...")
    result = decryptor.decrypt_file(args.file, args.output)
    
    # Display results
    formatted_output = decryptor.format_results(result)
    print(formatted_output)
    
    # Show raw content if verbose
    if args.verbose and 'content' in result:
        print("\n" + "=" * 80)
        print("RAW CONFIGURATION CONTENT:")
        print("=" * 80)
        content = result['content']
        if len(content) > 5000:
            print(content[:5000])
            print(f"\n... (showing first 5000 characters, total: {len(content)})")
        else:
            print(content)
    
    # Deep analysis if requested
    if args.deep_analysis and not result['success']:
        print("\n🔬 Performing deep analysis...")
        with open(args.file, 'rb') as f:
            data = f.read()
        
        brute_results = decryptor.brute_force_decrypt(data)
        if brute_results:
            print("✅ Deep analysis successful!")
            for br_result in brute_results:
                print(f"Method: {br_result['method']}, Password: {br_result['password']}")
                print(f"Preview: {br_result['text'][:200]}...")
        else:
            print("❌ Deep analysis could not decrypt the file")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nProgram interrupted by user. Goodbye!")
    except Exception as e:
        print(f"\nUnexpected error: {e}")
        print("Please try again or contact support")