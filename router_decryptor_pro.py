#!/usr/bin/env python3
"""
Router Decryptor Pro v4.0
The Ultimate Single-File Router Configuration Analysis Tool

Professional tool for network security contractors
Supports ALL router brands with advanced decryption
Cross-platform: Windows, Linux, macOS
"""

import os
import sys
import re
import base64
import hashlib
import binascii
import json
import argparse
import platform
import math
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime

# Optional GUI support
try:
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox, scrolledtext
    import threading
    GUI_AVAILABLE = True
except ImportError:
    GUI_AVAILABLE = False

# Advanced crypto support
try:
    from Crypto.Cipher import AES, DES, DES3
    from Crypto.Util.Padding import unpad
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

class RouterDecryptorPro:
    """Professional router configuration decryptor"""
    
    def __init__(self):
        self.version = "4.0 Professional"
        
        # Cisco Type 7 decryption table
        self.cisco_type7_xlat = [
            0x64, 0x73, 0x66, 0x64, 0x3b, 0x6b, 0x66, 0x6f, 0x41, 0x2c, 0x2e,
            0x69, 0x79, 0x65, 0x77, 0x72, 0x6b, 0x6c, 0x64, 0x4a, 0x4b, 0x44,
            0x48, 0x53, 0x55, 0x42, 0x73, 0x67, 0x76, 0x63, 0x61, 0x36, 0x39,
            0x38, 0x33, 0x34, 0x6e, 0x63, 0x78, 0x76, 0x39, 0x38, 0x37, 0x33,
            0x32, 0x35, 0x34, 0x6b, 0x3b, 0x66, 0x67, 0x38, 0x37
        ]
        
        # Comprehensive password database
        self.password_database = [
            # Default passwords
            'admin', 'password', '123456', 'admin123', 'Password1',
            'root', 'toor', 'administrator', 'guest', '',
            
            # Router brands
            'cisco', 'mikrotik', 'juniper', 'huawei', 'fortinet',
            'tplink', 'dlink', 'netcomm', 'asus', 'netgear', 'linksys',
            
            # Common variations
            'router', 'switch', 'network', 'default', 'config',
            '1234', '12345', '123123', 'qwerty', 'abc123',
            
            # Professional patterns
            'Admin@123', 'Password123!', 'Network123', 'Router123',
            'Cisco123', 'Admin2024', 'Password2024', 'Secure123',
            
            # Brand specific
            'Huawei12#$', 'Admin@huawei', 'tp-link', 'D-Link',
            'NetComm123', 'ASUS123', 'Netgear1', 'Linksys123'
        ]
        
        # Router brand signatures
        self.router_brands = {
            'cisco': [b'version ', b'interface ', b'router ', b'hostname ', b'cisco', b'IOS'],
            'mikrotik': [b'MIKROTIK', b'RouterOS', b'/interface', b'/ip'],
            'tplink': [b'TP-LINK', b'TL-', b'Archer', b'tplink'],
            'dlink': [b'D-Link', b'DI-', b'DIR-', b'd-link'],
            'netcomm': [b'NetComm', b'NF-', b'NL-', b'netcomm'],
            'juniper': [b'JUNOS', b'juniper', b'set interfaces'],
            'huawei': [b'Huawei', b'VRP', b'interface GigabitEthernet'],
            'fortinet': [b'FortiGate', b'FortiOS', b'config system'],
            'ubiquiti': [b'Ubiquiti', b'EdgeOS', b'UniFi'],
            'asus': [b'ASUS', b'RT-', b'AsusWRT'],
            'netgear': [b'NETGEAR', b'R6000', b'R7000'],
            'linksys': [b'Linksys', b'WRT', b'EA-']
        }
    
    def calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data"""
        if not data:
            return 0
        
        # Count byte frequencies
        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1
        
        # Calculate entropy
        entropy = 0
        data_len = len(data)
        for count in byte_counts:
            if count > 0:
                probability = count / data_len
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    def detect_router_brand(self, data: bytes) -> str:
        """Detect router brand from content"""
        data_lower = data.lower()
        
        # Also try decoded versions
        test_data = [data_lower]
        
        # Try Base64 decode
        try:
            decoded = base64.b64decode(data)
            test_data.append(decoded.lower())
        except:
            pass
        
        # Check all test data
        for test_content in test_data:
            for brand, signatures in self.router_brands.items():
                for signature in signatures:
                    if signature.lower() in test_content:
                        return brand
        
        return 'generic'
    
    def is_text_config(self, data: bytes) -> bool:
        """Check if data looks like text configuration"""
        try:
            text = data.decode('utf-8', errors='ignore')
            
            # Check for config keywords
            keywords = ['interface', 'router', 'ip', 'version', 'hostname', 'password', 'wireless', 'admin']
            found_keywords = sum(1 for keyword in keywords if keyword.lower() in text.lower())
            
            # Check printable ratio
            printable_chars = sum(1 for c in text if c.isprintable())
            printable_ratio = printable_chars / len(text) if text else 0
            
            return found_keywords >= 2 and printable_ratio > 0.7
        except:
            return False
    
    def decrypt_cisco_type7(self, password: str) -> str:
        """Decrypt Cisco Type 7 password"""
        try:
            if len(password) < 4:
                return "Password too short"
            
            salt = int(password[:2])
            encrypted_text = password[2:]
            encrypted_bytes = bytes.fromhex(encrypted_text)
            
            decrypted = ""
            for i, byte in enumerate(encrypted_bytes):
                key_index = (salt + i) % len(self.cisco_type7_xlat)
                decrypted += chr(byte ^ self.cisco_type7_xlat[key_index])
            
            return decrypted
        except Exception as e:
            return f"Decryption failed: {e}"
    
    def try_base64_decode(self, data: bytes) -> Optional[str]:
        """Try to decode Base64 data"""
        try:
            # Clean whitespace
            cleaned = re.sub(rb'[\r\n\s]', b'', data)
            
            # Check if valid Base64
            if len(cleaned) % 4 == 0 and re.match(rb'^[A-Za-z0-9+/]*={0,2}$', cleaned):
                decoded = base64.b64decode(cleaned)
                
                # Check if decoded content looks like config
                if self.is_text_config(decoded):
                    return decoded.decode('utf-8', errors='ignore')
        except:
            pass
        
        return None
    
    def try_hex_decode(self, data: bytes) -> Optional[str]:
        """Try to decode hex data"""
        try:
            # Clean and check if hex
            cleaned = data.replace(b' ', b'').replace(b'\n', b'').replace(b'\r', b'')
            if re.match(rb'^[A-Fa-f0-9]*$', cleaned):
                decoded = binascii.unhexlify(cleaned)
                
                if self.is_text_config(decoded):
                    return decoded.decode('utf-8', errors='ignore')
        except:
            pass
        
        return None
    
    def try_aes_decrypt(self, data: bytes, password: str) -> Optional[str]:
        """Try AES decryption"""
        if not CRYPTO_AVAILABLE:
            return None
        
        try:
            # Generate key from password
            key = hashlib.sha256(password.encode()).digest()
            
            # Try ECB mode first
            try:
                cipher = AES.new(key, AES.MODE_ECB)
                decrypted = cipher.decrypt(data)
                
                # Remove padding if needed
                try:
                    decrypted = unpad(decrypted, 16)
                except:
                    pass
                
                if self.is_text_config(decrypted):
                    return decrypted.decode('utf-8', errors='ignore')
            except:
                pass
            
            # Try CBC mode
            if len(data) >= 16:
                try:
                    iv = data[:16]
                    cipher = AES.new(key, AES.MODE_CBC, iv)
                    decrypted = cipher.decrypt(data[16:])
                    
                    try:
                        decrypted = unpad(decrypted, 16)
                    except:
                        pass
                    
                    if self.is_text_config(decrypted):
                        return decrypted.decode('utf-8', errors='ignore')
                except:
                    pass
        
        except Exception:
            pass
        
        return None
    
    def try_des_decrypt(self, data: bytes, password: str) -> Optional[str]:
        """Try DES decryption"""
        if not CRYPTO_AVAILABLE:
            return None
        
        try:
            # Generate 8-byte key
            key = hashlib.md5(password.encode()).digest()[:8]
            
            cipher = DES.new(key, DES.MODE_ECB)
            decrypted = cipher.decrypt(data)
            
            if self.is_text_config(decrypted):
                return decrypted.decode('utf-8', errors='ignore')
        
        except Exception:
            pass
        
        return None
    
    def try_xor_decrypt(self, data: bytes) -> Optional[str]:
        """Try XOR decryption with common keys"""
        xor_keys = [0xFF, 0xAA, 0x55, 0x42, 0x13, 0x37]
        
        for key in xor_keys:
            try:
                decrypted = bytes(b ^ key for b in data)
                if self.is_text_config(decrypted):
                    return decrypted.decode('utf-8', errors='ignore')
            except:
                continue
        
        return None
    
    def extract_strings_from_binary(self, data: bytes, min_length: int = 4) -> List[str]:
        """Extract readable strings from binary data"""
        strings = []
        current_string = ""
        
        for byte in data:
            if 32 <= byte <= 126:  # Printable ASCII
                current_string += chr(byte)
            else:
                if len(current_string) >= min_length:
                    strings.append(current_string)
                current_string = ""
        
        # Add final string
        if len(current_string) >= min_length:
            strings.append(current_string)
        
        return strings
    
    def analyze_file(self, file_path: str, verbose: bool = False) -> Dict[str, Any]:
        """Comprehensive file analysis with debugging"""
        if not os.path.exists(file_path):
            return {'success': False, 'error': 'File not found'}
        
        try:
            with open(file_path, 'rb') as f:
                raw_data = f.read()
        except Exception as e:
            return {'success': False, 'error': f'Cannot read file: {e}'}
        
        # Basic file info
        result = {
            'file_path': file_path,
            'file_size': len(raw_data),
            'entropy': self.calculate_entropy(raw_data),
            'detected_brand': self.detect_router_brand(raw_data),
            'success': False,
            'attempted_methods': [],
            'debug_info': {}
        }
        
        print(f"📊 File: {os.path.basename(file_path)} ({len(raw_data)} bytes)")
        print(f"🔍 Entropy: {result['entropy']:.2f}")
        print(f"🏷️ Brand: {result['detected_brand'].upper()}")
        
        # Debug info
        if verbose:
            print(f"📋 File extension: {Path(file_path).suffix}")
            print(f"📋 First 50 bytes (hex): {raw_data[:50].hex()}")
            print(f"📋 First 50 bytes (ascii): {repr(raw_data[:50])}")
        
        result['debug_info'] = {
            'first_50_hex': raw_data[:50].hex(),
            'first_50_ascii': repr(raw_data[:50]),
            'file_extension': Path(file_path).suffix,
            'crypto_available': CRYPTO_AVAILABLE
        }
        
        print("")
        
        # Try different decryption methods
        content = None
        method_used = None
        
        # Method 1: Check if already plaintext
        print("🔍 Checking if file is plaintext...")
        if self.is_text_config(raw_data):
            content = raw_data.decode('utf-8', errors='ignore')
            method_used = 'plaintext'
            result['attempted_methods'].append('plaintext')
            print("✅ File is readable plaintext")
        
        # Special handling for .conf backup files
        elif Path(file_path).suffix.lower() == '.conf' and not content:
            print("🔍 Detected .conf backup file - trying special methods...")
            
            # Try to detect if it's a compressed backup
            if raw_data.startswith(b'\x1f\x8b'):  # GZIP header
                print("   Detected GZIP compression...")
                try:
                    import gzip
                    decompressed = gzip.decompress(raw_data)
                    if self.is_text_config(decompressed):
                        content = decompressed.decode('utf-8', errors='ignore')
                        method_used = 'gzip_decompress'
                        result['attempted_methods'].append('gzip')
                        print("✅ Successfully decompressed GZIP backup")
                except Exception as e:
                    print(f"   GZIP decompression failed: {e}")
            
            # Try to detect if it's a ZIP archive
            elif raw_data.startswith(b'PK'):  # ZIP header
                print("   Detected ZIP archive...")
                try:
                    import zipfile
                    import io
                    with zipfile.ZipFile(io.BytesIO(raw_data)) as zf:
                        for filename in zf.namelist():
                            if any(ext in filename.lower() for ext in ['.cfg', '.conf', '.txt', '.xml']):
                                extracted = zf.read(filename)
                                if self.is_text_config(extracted):
                                    content = extracted.decode('utf-8', errors='ignore')
                                    method_used = f'zip_extract_{filename}'
                                    result['attempted_methods'].append('zip_extract')
                                    print(f"✅ Successfully extracted from ZIP: {filename}")
                                    break
                except Exception as e:
                    print(f"   ZIP extraction failed: {e}")
        
        # Method 2: Try Base64 decoding
        if not content:
            print("🔍 Trying Base64 decoding...")
            decoded = self.try_base64_decode(raw_data)
            if decoded:
                content = decoded
                method_used = 'base64'
                result['attempted_methods'].append('base64')
                print("✅ Successfully decoded Base64")
        
        # Method 3: Try hex decoding
        if not content:
            print("🔍 Trying hex decoding...")
            decoded = self.try_hex_decode(raw_data)
            if decoded:
                content = decoded
                method_used = 'hex'
                result['attempted_methods'].append('hex')
                print("✅ Successfully decoded hex")
        
        # Method 4: Try XOR decryption
        if not content:
            print("🔍 Trying XOR decryption...")
            decoded = self.try_xor_decrypt(raw_data)
            if decoded:
                content = decoded
                method_used = 'xor'
                result['attempted_methods'].append('xor')
                print("✅ Successfully decrypted with XOR")
        
        # Method 5: Try AES with common passwords
        if not content and CRYPTO_AVAILABLE and len(raw_data) >= 16:
            print("🔍 Trying AES decryption with common passwords...")
            print("   This may take a moment for encrypted files...")
            
            # Try more passwords for encrypted files
            extended_passwords = self.password_database + [
                # Additional common router passwords
                'router123', 'switch123', 'network123', 'backup123',
                'config123', 'settings123', 'device123', 'system123',
                # Manufacturer specific
                'cisco123', 'Cisco@123', 'mikrotik123', 'tplink123',
                'dlink123', 'netcomm123', 'admin@123', 'Admin@123',
                # Numerical patterns
                '111111', '000000', '123321', '654321', '987654',
                # Year patterns
                '2020', '2021', '2022', '2023', '2024', 'admin2024'
            ]
            
            for i, password in enumerate(extended_passwords[:50]):  # Try 50 passwords
                if i % 10 == 0:
                    print(f"   Trying password set {i//10 + 1}/5...")
                
                decoded = self.try_aes_decrypt(raw_data, password)
                if decoded:
                    content = decoded
                    method_used = f'aes_password_{password}'
                    result['attempted_methods'].append('aes_bruteforce')
                    print(f"✅ Successfully decrypted with AES (password: {password})")
                    break
        
        # Method 6: Try DES with common passwords
        if not content and CRYPTO_AVAILABLE and len(raw_data) % 8 == 0:
            print("🔍 Trying DES decryption with common passwords...")
            for password in self.password_database[:20]:
                decoded = self.try_des_decrypt(raw_data, password)
                if decoded:
                    content = decoded
                    method_used = f'des_password_{password}'
                    result['attempted_methods'].append('des_bruteforce')
                    print(f"✅ Successfully decrypted with DES (password: {password})")
                    break
        
        # Method 7: Try advanced encryption methods for backup files
        if not content and result['entropy'] > 6:
            print("🔍 Trying advanced encryption methods for backup files...")
            
            # Try with empty password (some backups use no password)
            decoded = self.try_aes_decrypt(raw_data, "")
            if decoded:
                content = decoded
                method_used = 'aes_no_password'
                result['attempted_methods'].append('aes_no_password')
                print("✅ Successfully decrypted with AES (no password)")
            
            # Try DES with empty password
            if not content:
                decoded = self.try_des_decrypt(raw_data, "")
                if decoded:
                    content = decoded
                    method_used = 'des_no_password'
                    result['attempted_methods'].append('des_no_password')
                    print("✅ Successfully decrypted with DES (no password)")
            
            # Try common backup file passwords
            backup_passwords = [
                'backup', 'config', 'settings', 'router', 'admin',
                'backup123', 'config123', 'settings123'
            ]
            
            for password in backup_passwords:
                if content:
                    break
                    
                # Try AES
                decoded = self.try_aes_decrypt(raw_data, password)
                if decoded:
                    content = decoded
                    method_used = f'aes_backup_{password}'
                    result['attempted_methods'].append('aes_backup')
                    print(f"✅ Successfully decrypted with AES backup password: {password}")
                    break
                
                # Try DES
                decoded = self.try_des_decrypt(raw_data, password)
                if decoded:
                    content = decoded
                    method_used = f'des_backup_{password}'
                    result['attempted_methods'].append('des_backup')
                    print(f"✅ Successfully decrypted with DES backup password: {password}")
                    break
        
        # Method 8: Extract strings from binary (last resort)
        if not content:
            print("🔍 Extracting readable strings from binary data...")
            strings = self.extract_strings_from_binary(raw_data, min_length=4)
            
            # Filter for config-like strings
            config_strings = []
            important_strings = []
            
            for string in strings:
                string_lower = string.lower()
                if any(keyword in string_lower for keyword in ['interface', 'ip', 'password', 'admin', 'wireless', 'router', 'hostname', 'ssid']):
                    config_strings.append(string)
                elif any(keyword in string_lower for keyword in ['user', 'pass', 'key', 'net', 'wan', 'lan']):
                    important_strings.append(string)
            
            if config_strings or important_strings:
                all_strings = config_strings + important_strings
                content = '\n'.join(all_strings[:100])  # Limit to first 100 strings
                method_used = 'string_extraction'
                result['attempted_methods'].append('string_extraction')
                print(f"✅ Extracted {len(config_strings)} config strings + {len(important_strings)} important strings")
                
                # Add note about partial extraction
                content = f"# PARTIAL EXTRACTION FROM ENCRYPTED BACKUP FILE\n# Found {len(all_strings)} readable strings\n\n" + content
        
        # Process results
        if content:
            result['success'] = True
            result['content'] = content
            result['decryption_method'] = method_used
            result['analysis'] = self.analyze_configuration_content(content, result['detected_brand'])
            print(f"🎉 SUCCESS! Decrypted using: {method_used}")
            print(f"📝 Content preview: {content[:200].replace(chr(10), ' ')[:100]}...")
        else:
            result['success'] = False
            result['error'] = f'Could not decrypt file with {len(result["attempted_methods"])} methods'
            result['recommendations'] = self.get_failure_recommendations(result)
            print(f"❌ FAILED after trying {len(result['attempted_methods'])} methods")
            print("💡 Recommendations:")
            for i, rec in enumerate(result['recommendations'][:3], 1):
                print(f"   {i}. {rec}")
            
            # Show what we found anyway
            strings = self.extract_strings_from_binary(raw_data, min_length=4)
            if strings:
                print(f"🔍 Found {len(strings)} readable strings in file:")
                for string in strings[:10]:
                    if len(string) > 6:
                        print(f"   • {string}")
                if len(strings) > 10:
                    print(f"   ... and {len(strings) - 10} more strings")
                
                # Create partial content from strings
                result['partial_content'] = '\n'.join(strings)
                result['partial_success'] = True
        
        return result
    
    def analyze_configuration_content(self, content: str, brand: str) -> Dict[str, Any]:
        """Analyze decrypted configuration content"""
        analysis = {
            'hostname': None,
            'credentials': [],
            'ip_addresses': [],
            'interfaces': [],
            'wireless_config': [],
            'security_issues': [],
            'network_info': []
        }
        
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            line_lower = line.lower()
            
            # Extract hostname
            if 'hostname' in line_lower:
                if '=' in line:
                    analysis['hostname'] = line.split('=', 1)[1].strip()
                elif ' ' in line and line.startswith('hostname'):
                    analysis['hostname'] = line.split(' ', 1)[1].strip()
            
            # Extract Cisco Type 7 passwords
            type7_match = re.search(r'password 7 ([A-Fa-f0-9]+)', line)
            if type7_match:
                encrypted = type7_match.group(1)
                decrypted = self.decrypt_cisco_type7(encrypted)
                analysis['credentials'].append({
                    'line': line_num,
                    'type': 'cisco_type7',
                    'encrypted': encrypted,
                    'decrypted': decrypted,
                    'strength': 'very_weak'
                })
            
            # Extract other passwords
            password_patterns = [
                (r'password[=:\s>]+([^<\s\n\r]+)', 'password'),
                (r'<password>([^<]+)</password>', 'xml_password'),
                (r'admin[=:\s>]+([^<\s\n\r]+)', 'admin'),
                (r'key[=:\s>]+([^<\s\n\r]+)', 'key'),
                (r'ssid[=:\s>]+([^<\s\n\r]+)', 'ssid'),
                (r'wpa[^=]*[=:\s>]+([^<\s\n\r]+)', 'wpa_key')
            ]
            
            for pattern, cred_type in password_patterns:
                matches = re.findall(pattern, line, re.IGNORECASE)
                for match in matches:
                    if len(match) > 2 and match.lower() not in ['none', 'null', 'auto', '****']:
                        analysis['credentials'].append({
                            'line': line_num,
                            'type': cred_type,
                            'value': match,
                            'strength': self.assess_password_strength(match)
                        })
            
            # Extract IP addresses
            ip_matches = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line)
            analysis['ip_addresses'].extend(ip_matches)
            
            # Extract interfaces
            if any(keyword in line_lower for keyword in ['interface', 'eth', 'wlan']):
                analysis['interfaces'].append(line)
            
            # Extract wireless config
            if any(keyword in line_lower for keyword in ['wireless', 'wifi', 'ssid', 'wpa']):
                analysis['wireless_config'].append(line)
            
            # Check for security issues
            if any(issue in line_lower for issue in ['telnet', 'no password', 'public', 'private']):
                analysis['security_issues'].append({
                    'line': line_num,
                    'issue': line,
                    'type': 'security_concern'
                })
        
        # Remove duplicates and clean up
        analysis['ip_addresses'] = list(set(analysis['ip_addresses']))
        
        return analysis
    
    def assess_password_strength(self, password: str) -> str:
        """Assess password strength"""
        if len(password) < 4:
            return 'very_weak'
        elif len(password) < 6:
            return 'weak'
        elif len(password) < 8:
            return 'medium'
        else:
            # Check complexity
            has_upper = any(c.isupper() for c in password)
            has_lower = any(c.islower() for c in password)
            has_digit = any(c.isdigit() for c in password)
            has_special = any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in password)
            
            complexity = sum([has_upper, has_lower, has_digit, has_special])
            
            if complexity >= 3 and len(password) >= 12:
                return 'very_strong'
            elif complexity >= 3:
                return 'strong'
            elif complexity >= 2:
                return 'medium'
            else:
                return 'weak'
    
    def get_failure_recommendations(self, result: Dict[str, Any]) -> List[str]:
        """Get specific recommendations when decryption fails"""
        recommendations = []
        
        entropy = result.get('entropy', 0)
        file_size = result.get('file_size', 0)
        brand = result.get('detected_brand', 'unknown')
        file_ext = result.get('debug_info', {}).get('file_extension', '').lower()
        
        # Specific recommendations for .conf backup files
        if file_ext == '.conf':
            recommendations.append("BACKUP FILE DETECTED (.conf extension)")
            recommendations.append("This appears to be a router backup/settings file")
            
            if entropy > 7.5:
                recommendations.append("STRONG ENCRYPTION: File is professionally encrypted")
                recommendations.append("You need the specific backup password or device master key")
            elif entropy > 6:
                recommendations.append("MEDIUM ENCRYPTION: Try these approaches:")
                recommendations.append("- Check if backup was created with a password")
                recommendations.append("- Try the device's admin password as decryption key")
                recommendations.append("- Look for backup creation logs on the device")
        
        if file_size > 40000:
            recommendations.append("LARGE BACKUP: Contains comprehensive device settings")
            if file_size > 100000:
                recommendations.append("May include firmware components - try firmware extraction tools")
        
        if brand != 'generic':
            recommendations.append(f"ROUTER BRAND: {brand.upper()}")
            
            # Brand-specific advice
            brand_advice = {
                'cisco': "Use 'show running-config' or TFTP backup from device",
                'mikrotik': "Export as .rsc file: /export file=config",
                'tplink': "Use web interface: System Tools > Backup & Restore",
                'dlink': "Use web interface: Tools > System > Save Configuration",
                'netcomm': "Access device web interface for configuration export",
                'juniper': "Use 'show configuration' command",
                'huawei': "Use 'display current-configuration' command"
            }
            
            if brand in brand_advice:
                recommendations.append(f"SOLUTION: {brand_advice[brand]}")
        
        recommendations.append("ALTERNATIVE APPROACHES:")
        recommendations.append("1. Access router directly and export config in plain text")
        recommendations.append("2. Reset router and reconfigure (if acceptable)")
        recommendations.append("3. Contact router manufacturer support")
        recommendations.append("4. Use manufacturer-specific configuration tools")
        
        if not CRYPTO_AVAILABLE:
            recommendations.append("INSTALL CRYPTO LIBRARIES: pip install cryptography pycryptodome")
        
        return recommendations
    
    def generate_professional_report(self, result: Dict[str, Any]) -> str:
        """Generate professional analysis report"""
        report = []
        
        # Header
        report.append("=" * 80)
        report.append("ROUTER CONFIGURATION PROFESSIONAL ANALYSIS REPORT")
        report.append("=" * 80)
        report.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"Tool: Router Decryptor Pro v{self.version}")
        report.append(f"Platform: {platform.system()}")
        report.append("")
        
        # Executive Summary
        report.append("EXECUTIVE SUMMARY")
        report.append("-" * 40)
        report.append(f"File: {os.path.basename(result['file_path'])}")
        report.append(f"Size: {result['file_size']} bytes")
        report.append(f"Brand: {result['detected_brand'].upper()}")
        report.append(f"Status: {'SUCCESS' if result['success'] else 'FAILED'}")
        
        if result['success']:
            report.append(f"Method: {result['decryption_method']}")
        else:
            report.append(f"Error: {result.get('error', 'Unknown')}")
        
        report.append("")
        
        # Technical Details
        report.append("TECHNICAL ANALYSIS")
        report.append("-" * 40)
        report.append(f"File Entropy: {result['entropy']:.2f}")
        report.append(f"Attempted Methods: {len(result['attempted_methods'])}")
        
        if result['attempted_methods']:
            report.append("Methods Tried:")
            for method in result['attempted_methods']:
                report.append(f"  • {method}")
        
        report.append("")
        
        # Results
        if result['success']:
            analysis = result.get('analysis', {})
            
            # Device info
            if analysis.get('hostname'):
                report.append(f"🏷️ HOSTNAME: {analysis['hostname']}")
                report.append("")
            
            # Credentials
            credentials = analysis.get('credentials', [])
            if credentials:
                report.append(f"🔑 CREDENTIALS FOUND ({len(credentials)}):")
                for i, cred in enumerate(credentials, 1):
                    report.append(f"  {i}. Type: {cred['type']}")
                    if cred.get('decrypted'):
                        report.append(f"     Encrypted: {cred['encrypted']}")
                        report.append(f"     Decrypted: {cred['decrypted']}")
                    else:
                        report.append(f"     Value: {cred.get('value', 'N/A')}")
                    report.append(f"     Strength: {cred.get('strength', 'unknown').upper()}")
                    report.append(f"     Line: {cred['line']}")
                    report.append("")
            
            # Network information
            ip_addresses = analysis.get('ip_addresses', [])
            if ip_addresses:
                report.append(f"🌐 IP ADDRESSES ({len(ip_addresses)}):")
                for ip in sorted(set(ip_addresses))[:15]:
                    report.append(f"  • {ip}")
                if len(set(ip_addresses)) > 15:
                    report.append(f"  ... and {len(set(ip_addresses)) - 15} more")
                report.append("")
            
            # Interfaces
            interfaces = analysis.get('interfaces', [])
            if interfaces:
                report.append(f"🔌 INTERFACES ({len(interfaces)}):")
                for interface in interfaces[:10]:
                    report.append(f"  • {interface}")
                if len(interfaces) > 10:
                    report.append(f"  ... and {len(interfaces) - 10} more")
                report.append("")
            
            # Wireless configuration
            wireless = analysis.get('wireless_config', [])
            if wireless:
                report.append(f"📶 WIRELESS CONFIG ({len(wireless)}):")
                for config in wireless[:5]:
                    report.append(f"  • {config}")
                report.append("")
            
            # Security issues
            security_issues = analysis.get('security_issues', [])
            if security_issues:
                report.append(f"⚠️ SECURITY ISSUES ({len(security_issues)}):")
                for issue in security_issues:
                    report.append(f"  • Line {issue['line']}: {issue['issue']}")
                report.append("")
        
        else:
            # Failed analysis
            report.append("❌ DECRYPTION FAILED")
            report.append("-" * 40)
            report.append(f"Error: {result.get('error', 'Unknown error')}")
            report.append("")
            
            # Show debug information
            debug_info = result.get('debug_info', {})
            if debug_info:
                report.append("🔍 DEBUG INFORMATION:")
                report.append(f"File Extension: {debug_info.get('file_extension', 'Unknown')}")
                report.append(f"Crypto Libraries: {'Available' if debug_info.get('crypto_available') else 'Not Available'}")
                report.append(f"First 50 bytes (hex): {debug_info.get('first_50_hex', 'N/A')}")
                report.append("")
            
            # Show partial content if available
            if result.get('partial_success') and result.get('partial_content'):
                report.append("🔍 PARTIAL EXTRACTION RESULTS:")
                report.append("-" * 40)
                partial_content = result['partial_content']
                lines = partial_content.split('\n')[:20]  # First 20 lines
                for line in lines:
                    if line.strip():
                        report.append(f"  {line}")
                if len(partial_content.split('\n')) > 20:
                    report.append("  ... (more content available)")
                report.append("")
            
            # Recommendations
            recommendations = result.get('recommendations', [])
            if recommendations:
                report.append("💡 RECOMMENDATIONS:")
                for i, rec in enumerate(recommendations, 1):
                    report.append(f"  {i}. {rec}")
                report.append("")
        
        # Footer
        report.append("=" * 80)
        report.append("Router Decryptor Pro v4.0 - Professional Network Security Tool")
        report.append("=" * 80)
        
        return '\n'.join(report)


class SimpleGUI:
    """Simple and reliable GUI interface"""
    
    def __init__(self, root):
        self.root = root
        self.decryptor = RouterDecryptorPro()
        self.current_result = None
        
        self.setup_gui()
    
    def setup_gui(self):
        """Setup simple GUI"""
        self.root.title("Router Decryptor Pro v4.0")
        self.root.geometry("900x600")
        
        # Main frame
        main_frame = tk.Frame(self.root)
        main_frame.pack(fill='both', expand=True, padx=20, pady=20)
        
        # Title
        title_label = tk.Label(
            main_frame,
            text="🔥 Router Decryptor Pro v4.0",
            font=('Arial', 16, 'bold'),
            fg='#cc0000'
        )
        title_label.pack(pady=(0, 20))
        
        # File selection
        file_frame = tk.LabelFrame(main_frame, text="Select Configuration File", font=('Arial', 11, 'bold'))
        file_frame.pack(fill='x', pady=(0, 20))
        
        self.file_path_var = tk.StringVar()
        file_entry = tk.Entry(file_frame, textvariable=self.file_path_var, font=('Consolas', 10), width=70)
        file_entry.pack(side='left', padx=10, pady=10, fill='x', expand=True)
        
        browse_btn = tk.Button(file_frame, text="Browse", command=self.browse_file, bg='#0066cc', fg='white', font=('Arial', 10, 'bold'))
        browse_btn.pack(side='right', padx=10, pady=10)
        
        # Buttons
        button_frame = tk.Frame(main_frame)
        button_frame.pack(fill='x', pady=(0, 20))
        
        decrypt_btn = tk.Button(
            button_frame,
            text="🔓 DECRYPT FILE",
            command=self.decrypt_file,
            bg='#cc0000',
            fg='white',
            font=('Arial', 12, 'bold'),
            height=2
        )
        decrypt_btn.pack(side='left', fill='x', expand=True, padx=(0, 10))
        
        save_btn = tk.Button(
            button_frame,
            text="💾 SAVE REPORT",
            command=self.save_report,
            bg='#009900',
            fg='white',
            font=('Arial', 12, 'bold'),
            height=2
        )
        save_btn.pack(side='left', fill='x', expand=True)
        
        # Results area
        results_frame = tk.LabelFrame(main_frame, text="Analysis Results", font=('Arial', 11, 'bold'))
        results_frame.pack(fill='both', expand=True)
        
        self.results_text = scrolledtext.ScrolledText(
            results_frame,
            wrap=tk.WORD,
            font=('Consolas', 10),
            bg='#f8f8f8'
        )
        self.results_text.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Status
        self.status_var = tk.StringVar(value="Ready - Select encrypted configuration file")
        status_label = tk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_label.pack(side=tk.BOTTOM, fill=tk.X)
    
    def browse_file(self):
        """Browse for file"""
        filename = filedialog.askopenfilename(
            title="Select Router Configuration File",
            filetypes=[
                ("All Files", "*.*"),
                ("Config Files", "*.cfg;*.conf;*.txt"),
                ("Backup Files", "*.backup;*.bak"),
                ("XML Files", "*.xml")
            ]
        )
        
        if filename:
            self.file_path_var.set(filename)
            self.status_var.set(f"Selected: {os.path.basename(filename)}")
    
    def decrypt_file(self):
        """Decrypt selected file"""
        file_path = self.file_path_var.get().strip()
        if not file_path:
            messagebox.showwarning("Warning", "Please select a file")
            return
        
        self.status_var.set("Analyzing and decrypting...")
        threading.Thread(target=self._decrypt_thread, args=(file_path,), daemon=True).start()
    
    def _decrypt_thread(self, file_path):
        """Decryption thread"""
        try:
            result = self.decryptor.analyze_file(file_path)
            self.current_result = result
            
            self.root.after(0, lambda: self._show_results(result))
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Error", f"Analysis failed: {e}"))
    
    def _show_results(self, result):
        """Show analysis results"""
        self.results_text.delete(1.0, tk.END)
        
        report = self.decryptor.generate_professional_report(result)
        self.results_text.insert(1.0, report)
        
        if result['success']:
            self.status_var.set(f"SUCCESS - Decrypted using {result['decryption_method']}")
        else:
            self.status_var.set(f"FAILED - {result.get('error', 'Unknown error')}")
    
    def save_report(self):
        """Save current report"""
        if not self.current_result:
            messagebox.showwarning("Warning", "No analysis results to save")
            return
        
        filename = filedialog.asksaveasfilename(
            title="Save Analysis Report",
            defaultextension=".txt",
            filetypes=[("Text Files", "*.txt"), ("JSON Files", "*.json")]
        )
        
        if filename:
            try:
                if filename.endswith('.json'):
                    with open(filename, 'w') as f:
                        json.dump(self.current_result, f, indent=2, default=str)
                else:
                    report = self.decryptor.generate_professional_report(self.current_result)
                    with open(filename, 'w', encoding='utf-8') as f:
                        f.write(report)
                
                messagebox.showinfo("Success", f"Report saved to {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Save failed: {e}")


def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description='Router Decryptor Pro v4.0 - The Ultimate Router Analysis Tool',
        epilog="""
Examples:
  python router_decryptor_pro.py config.cfg
  python router_decryptor_pro.py --gui
  python router_decryptor_pro.py -p "094F471A1A0A"
  python router_decryptor_pro.py config.cfg --report report.txt
        """
    )
    
    parser.add_argument('file', nargs='?', help='Configuration file to analyze')
    parser.add_argument('-p', '--password', help='Decrypt Cisco Type 7 password')
    parser.add_argument('-o', '--output', help='Save decrypted content')
    parser.add_argument('-r', '--report', help='Save professional report')
    parser.add_argument('--gui', action='store_true', help='Launch GUI')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--json', action='store_true', help='JSON output')
    
    args = parser.parse_args()
    
    decryptor = RouterDecryptorPro()
    
    # GUI mode
    if args.gui:
        if not GUI_AVAILABLE:
            print("❌ GUI not available. Install tkinter or use command line.")
            return
        
        root = tk.Tk()
        app = SimpleGUI(root)
        root.mainloop()
        return
    
    # Password mode
    if args.password:
        decrypted = decryptor.decrypt_cisco_type7(args.password)
        print(f"Encrypted: {args.password}")
        print(f"Decrypted: {decrypted}")
        return
    
    # File analysis mode
    if not args.file:
        print("Router Decryptor Pro v4.0 - The Ultimate Tool")
        print("Usage: python router_decryptor_pro.py <config_file>")
        print("       python router_decryptor_pro.py --gui")
        print("       python router_decryptor_pro.py --help")
        return
    
    # Analyze file
    print("🔥 Router Decryptor Pro v4.0 - Ultimate Analysis")
    print("=" * 60)
    
    result = decryptor.analyze_file(args.file, verbose=args.verbose)
    
    # Output
    if args.json:
        print(json.dumps(result, indent=2, default=str))
    else:
        report = decryptor.generate_professional_report(result)
        print(report)
    
    # Save files
    if args.output and result.get('content'):
        with open(args.output, 'w', encoding='utf-8') as f:
            f.write(result['content'])
        print(f"\n💾 Content saved: {args.output}")
    
    if args.report:
        report = decryptor.generate_professional_report(result)
        with open(args.report, 'w', encoding='utf-8') as f:
            f.write(report)
        print(f"📊 Report saved: {args.report}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nProgram interrupted. Goodbye!")
    except Exception as e:
        print(f"\nError: {e}")
        sys.exit(1)