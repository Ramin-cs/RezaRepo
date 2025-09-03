#!/usr/bin/env python3
"""
Advanced Router Configuration Decryptor
ابزار پیشرفته Decrypt کردن فایل‌های کانفیگ روتر

این نسخه پیشرفته شامل روش‌های بیشتری برای decrypt کردن است
"""

import base64
import hashlib
import struct
import os
import sys
import argparse
import json
from pathlib import Path
from typing import Optional, Dict, Any, List
import re
import binascii

try:
    from Crypto.Cipher import AES, DES, DES3
    from Crypto.Util.Padding import unpad
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

class AdvancedRouterDecryptor:
    """کلاس پیشرفته برای decrypt کردن فایل‌های کانفیگ"""
    
    def __init__(self):
        # Cisco Type 7 translation table
        self.cisco_type7_xlat = [
            0x64, 0x73, 0x66, 0x64, 0x3b, 0x6b, 0x66, 0x6f, 0x41, 0x2c, 0x2e,
            0x69, 0x79, 0x65, 0x77, 0x72, 0x6b, 0x6c, 0x64, 0x4a, 0x4b, 0x44,
            0x48, 0x53, 0x55, 0x42, 0x73, 0x67, 0x76, 0x63, 0x61, 0x36, 0x39,
            0x38, 0x33, 0x34, 0x6e, 0x63, 0x78, 0x76, 0x39, 0x38, 0x37, 0x33,
            0x32, 0x35, 0x34, 0x6b, 0x3b, 0x66, 0x67, 0x38, 0x37
        ]
        
        # Common router default passwords for brute force
        self.common_passwords = [
            'admin', 'password', '123456', 'cisco', 'mikrotik',
            'router', 'switch', 'default', '', 'root'
        ]
    
    def detect_encryption_method(self, data: bytes) -> str:
        """تشخیص روش رمزنگاری"""
        # بررسی AES (معمولاً block size 16)
        if len(data) % 16 == 0 and len(data) > 16:
            return 'aes_candidate'
        
        # بررسی DES (block size 8)
        if len(data) % 8 == 0 and len(data) > 8:
            return 'des_candidate'
        
        # بررسی Base64
        try:
            base64.b64decode(data)
            return 'base64'
        except:
            pass
        
        # بررسی Hex
        try:
            binascii.unhexlify(data)
            return 'hex_encoded'
        except:
            pass
        
        return 'unknown'
    
    def try_aes_decryption(self, data: bytes, password: str) -> Optional[bytes]:
        """تلاش برای decrypt با AES"""
        if not CRYPTO_AVAILABLE:
            return None
        
        try:
            # ایجاد کلید از پسورد
            key = hashlib.sha256(password.encode()).digest()[:32]
            
            # تلاش با IV صفر
            iv = b'\x00' * 16
            cipher = AES.new(key, AES.MODE_CBC, iv)
            decrypted = cipher.decrypt(data)
            
            # بررسی padding
            try:
                return unpad(decrypted, 16)
            except:
                return decrypted
                
        except Exception:
            return None
    
    def try_des_decryption(self, data: bytes, password: str) -> Optional[bytes]:
        """تلاش برای decrypt با DES"""
        if not CRYPTO_AVAILABLE:
            return None
        
        try:
            # ایجاد کلید از پسورد (8 بایت برای DES)
            key = hashlib.md5(password.encode()).digest()[:8]
            
            cipher = DES.new(key, DES.MODE_ECB)
            decrypted = cipher.decrypt(data)
            
            return decrypted
            
        except Exception:
            return None
    
    def brute_force_decrypt(self, data: bytes) -> Optional[Dict[str, Any]]:
        """تلاش برای decrypt با پسوردهای رایج"""
        results = []
        
        for password in self.common_passwords:
            # تلاش با AES
            aes_result = self.try_aes_decryption(data, password)
            if aes_result and self.is_valid_config(aes_result):
                results.append({
                    'method': 'AES',
                    'password': password,
                    'data': aes_result
                })
            
            # تلاش با DES
            des_result = self.try_des_decryption(data, password)
            if des_result and self.is_valid_config(des_result):
                results.append({
                    'method': 'DES',
                    'password': password,
                    'data': des_result
                })
        
        return results if results else None
    
    def is_valid_config(self, data: bytes) -> bool:
        """بررسی اینکه آیا داده decrypt شده مثل کانفیگ معتبر است"""
        try:
            text = data.decode('utf-8', errors='ignore')
            
            # کلمات کلیدی که در کانفیگ‌های روتر وجود دارند
            keywords = [
                'interface', 'router', 'ip', 'version', 'hostname',
                'access-list', 'vlan', 'enable', 'password', 'username'
            ]
            
            found_keywords = sum(1 for keyword in keywords if keyword in text.lower())
            
            # اگر حداقل 2 کلمه کلیدی پیدا شد و متن قابل چاپ باشد
            return found_keywords >= 2 and len([c for c in text if c.isprintable()]) > len(text) * 0.8
            
        except:
            return False
    
    def extract_network_info(self, content: str) -> Dict[str, Any]:
        """استخراج اطلاعات شبکه از کانفیگ"""
        info = {
            'hostname': None,
            'ip_addresses': [],
            'networks': [],
            'users': [],
            'services': [],
            'security': []
        }
        
        lines = content.split('\n')
        
        for line in lines:
            line = line.strip()
            
            # استخراج hostname
            if line.startswith('hostname '):
                info['hostname'] = line.split(' ', 1)[1]
            
            # استخراج IP addresses
            ip_matches = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line)
            info['ip_addresses'].extend(ip_matches)
            
            # استخراج networks
            network_matches = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}\b', line)
            info['networks'].extend(network_matches)
            
            # استخراج کاربران
            if line.startswith('username '):
                info['users'].append(line)
            
            # استخراج سرویس‌ها
            if any(service in line for service in ['ssh', 'telnet', 'http', 'snmp', 'ftp']):
                info['services'].append(line)
            
            # استخراج تنظیمات امنیتی
            if any(security in line for security in ['crypto', 'certificate', 'key', 'secure']):
                info['security'].append(line)
        
        # حذف تکراری‌ها
        info['ip_addresses'] = list(set(info['ip_addresses']))
        info['networks'] = list(set(info['networks']))
        
        return info
    
    def analyze_file(self, file_path: str) -> Dict[str, Any]:
        """تجزیه و تحلیل کامل فایل"""
        result = {
            'file_info': {
                'path': file_path,
                'size': os.path.getsize(file_path),
                'exists': os.path.exists(file_path)
            }
        }
        
        try:
            with open(file_path, 'rb') as f:
                raw_data = f.read()
            
            # تشخیص نوع رمزنگاری
            encryption_method = self.detect_encryption_method(raw_data)
            result['encryption_method'] = encryption_method
            
            # تلاش برای decrypt
            if encryption_method == 'base64':
                try:
                    decoded = base64.b64decode(raw_data)
                    result['decrypted_data'] = decoded.decode('utf-8', errors='ignore')
                    result['success'] = True
                except Exception as e:
                    result['error'] = f"خطا در decode Base64: {e}"
            
            elif encryption_method in ['aes_candidate', 'des_candidate']:
                brute_results = self.brute_force_decrypt(raw_data)
                if brute_results:
                    result['brute_force_results'] = brute_results
                    result['success'] = True
                else:
                    result['error'] = 'نتوانست با پسوردهای رایج decrypt شود'
            
            # اگر فایل متنی است
            try:
                text_content = raw_data.decode('utf-8', errors='ignore')
                if self.is_valid_config(text_content.encode()):
                    result['text_content'] = text_content
                    result['success'] = True
            except:
                pass
            
            # استخراج اطلاعات شبکه
            if 'decrypted_data' in result:
                network_info = self.extract_network_info(result['decrypted_data'])
                result['network_info'] = network_info
            elif 'text_content' in result:
                network_info = self.extract_network_info(result['text_content'])
                result['network_info'] = network_info
                
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def generate_report(self, result: Dict[str, Any], output_file: str = None):
        """تولید گزارش کامل"""
        report = []
        report.append("🔧 گزارش تجزیه فایل کانفیگ روتر")
        report.append("=" * 50)
        
        # اطلاعات فایل
        file_info = result.get('file_info', {})
        report.append(f"📁 مسیر فایل: {file_info.get('path', 'نامشخص')}")
        report.append(f"📊 اندازه فایل: {file_info.get('size', 0)} بایت")
        report.append(f"🔐 روش رمزنگاری: {result.get('encryption_method', 'نامشخص')}")
        report.append(f"✅ وضعیت: {'موفق' if result.get('success') else 'ناموفق'}")
        
        if 'error' in result:
            report.append(f"❌ خطا: {result['error']}")
        
        # اطلاعات شبکه
        network_info = result.get('network_info', {})
        if network_info:
            report.append("\n🌐 اطلاعات شبکه:")
            report.append("-" * 30)
            
            if network_info.get('hostname'):
                report.append(f"🏷️ نام میزبان: {network_info['hostname']}")
            
            if network_info.get('ip_addresses'):
                report.append(f"🔢 آدرس‌های IP ({len(network_info['ip_addresses'])} عدد):")
                for ip in network_info['ip_addresses'][:10]:
                    report.append(f"   • {ip}")
            
            if network_info.get('networks'):
                report.append(f"🛣️ شبکه‌ها ({len(network_info['networks'])} عدد):")
                for net in network_info['networks'][:5]:
                    report.append(f"   • {net}")
            
            if network_info.get('users'):
                report.append(f"👤 کاربران ({len(network_info['users'])} عدد):")
                for user in network_info['users'][:5]:
                    report.append(f"   • {user}")
        
        # نتایج brute force
        if 'brute_force_results' in result:
            report.append("\n🔓 نتایج Brute Force:")
            report.append("-" * 30)
            for br_result in result['brute_force_results']:
                report.append(f"روش: {br_result['method']}, پسورد: {br_result['password']}")
        
        report_text = '\n'.join(report)
        
        # نمایش گزارش
        print(report_text)
        
        # ذخیره گزارش
        if output_file:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(report_text)
            print(f"\n💾 گزارش در {output_file} ذخیره شد")


def create_sample_configs():
    """ایجاد فایل‌های نمونه برای تست"""
    
    # نمونه کانفیگ سیسکو
    cisco_config = """!
version 15.1
service timestamps debug datetime msec
service timestamps log datetime msec
no service password-encryption
!
hostname Router1
!
boot-start-marker
boot-end-marker
!
enable secret 5 $1$mERr$hx5rVt7rPNoS4wqbXKX7m0
enable password 7 0822455D0A16
!
username admin privilege 15 password 7 094F471A1A0A
username guest password 7 05080F1C2243
!
interface FastEthernet0/0
 ip address 192.168.1.1 255.255.255.0
 no shutdown
!
interface FastEthernet0/1
 ip address 10.0.0.1 255.255.255.0
 no shutdown
!
ip route 0.0.0.0 0.0.0.0 192.168.1.254
!
access-list 100 permit tcp any any eq www
access-list 100 permit tcp any any eq 443
!
line con 0
line vty 0 4
 password 7 060506324F41
 login
!
end
"""
    
    # ذخیره نمونه
    with open('/workspace/sample_cisco_config.txt', 'w') as f:
        f.write(cisco_config)
    
    # نمونه Base64
    encoded_config = base64.b64encode(cisco_config.encode()).decode()
    with open('/workspace/sample_base64_config.txt', 'w') as f:
        f.write(encoded_config)
    
    print("✅ فایل‌های نمونه ایجاد شدند:")
    print("   • sample_cisco_config.txt")
    print("   • sample_base64_config.txt")


def main():
    """تابع اصلی"""
    parser = argparse.ArgumentParser(
        description='ابزار پیشرفته Decrypt فایل‌های کانفیگ روتر',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
مثال‌های استفاده:
  python advanced_router_decryptor.py config.txt
  python advanced_router_decryptor.py backup.backup --report report.txt
  python advanced_router_decryptor.py --create-samples
        """
    )
    
    parser.add_argument('file', nargs='?', help='مسیر فایل کانفیگ')
    parser.add_argument('--report', help='ذخیره گزارش در فایل')
    parser.add_argument('--create-samples', action='store_true', help='ایجاد فایل‌های نمونه')
    parser.add_argument('--verbose', action='store_true', help='نمایش اطلاعات تکمیلی')
    
    args = parser.parse_args()
    
    if args.create_samples:
        create_sample_configs()
        return
    
    if not args.file:
        print("لطفاً مسیر فایل کانفیگ را وارد کنید یا --create-samples برای ایجاد نمونه")
        parser.print_help()
        return
    
    decryptor = AdvancedRouterDecryptor()
    
    print("🔍 در حال تجزیه فایل...")
    result = decryptor.analyze_file(args.file)
    
    print("\n")
    decryptor.generate_report(result, args.report)


if __name__ == "__main__":
    main()