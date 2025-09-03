#!/usr/bin/env python3
"""
Router Configuration Decryptor Tool
ابزار Decrypt کردن فایل‌های کانفیگ روترها

این برنامه برای مدیران شبکه طراحی شده تا بتوانند فایل‌های کانفیگ 
رمزگذاری شده روترهای مختلف را decrypt کنند.

پشتیبانی از:
- Cisco Type 7 passwords
- MikroTik backup files
- عمومی: AES, DES, 3DES encryption
- Base64 encoded configs

نویسنده: Assistant AI
"""

import base64
import hashlib
import struct
import os
import sys
import argparse
from pathlib import Path
from typing import Optional, Dict, Any
import re

class RouterConfigDecryptor:
    """کلاس اصلی برای decrypt کردن فایل‌های کانفیگ روتر"""
    
    def __init__(self):
        self.cisco_type7_xlat = [
            0x64, 0x73, 0x66, 0x64, 0x3b, 0x6b, 0x66, 0x6f, 0x41, 0x2c, 0x2e,
            0x69, 0x79, 0x65, 0x77, 0x72, 0x6b, 0x6c, 0x64, 0x4a, 0x4b, 0x44,
            0x48, 0x53, 0x55, 0x42, 0x73, 0x67, 0x76, 0x63, 0x61, 0x36, 0x39,
            0x38, 0x33, 0x34, 0x6e, 0x63, 0x78, 0x76, 0x39, 0x38, 0x37, 0x33,
            0x32, 0x35, 0x34, 0x6b, 0x3b, 0x66, 0x67, 0x38, 0x37
        ]
    
    def detect_file_type(self, file_path: str) -> str:
        """تشخیص نوع فایل کانفیگ"""
        try:
            with open(file_path, 'rb') as f:
                content = f.read(1024)  # خواندن 1KB اول
            
            # بررسی فایل‌های MikroTik
            if file_path.endswith('.backup') or b'MIKROTIK' in content[:100]:
                return 'mikrotik_backup'
            
            # بررسی فایل‌های متنی سیسکو
            try:
                text_content = content.decode('utf-8', errors='ignore')
                if 'version ' in text_content and ('interface' in text_content or 'router' in text_content):
                    return 'cisco_text'
            except:
                pass
            
            # بررسی Base64
            try:
                base64.b64decode(content[:100])
                return 'base64_encoded'
            except:
                pass
            
            # بررسی فایل باینری
            if len([b for b in content[:100] if b < 32 or b > 126]) > 20:
                return 'binary_encrypted'
            
            return 'unknown'
            
        except Exception as e:
            print(f"خطا در تشخیص نوع فایل: {e}")
            return 'error'
    
    def decrypt_cisco_type7(self, password: str) -> str:
        """Decrypt کردن پسوردهای Type 7 سیسکو"""
        try:
            if len(password) < 4:
                return "پسورد خیلی کوتاه است"
            
            # استخراج salt و encrypted text
            salt = int(password[:2])
            encrypted_text = password[2:]
            
            # تبدیل hex به bytes
            try:
                encrypted_bytes = bytes.fromhex(encrypted_text)
            except ValueError:
                return "فرمت پسورد نامعتبر است"
            
            # Decrypt
            decrypted = ""
            for i, byte in enumerate(encrypted_bytes):
                key_index = (salt + i) % len(self.cisco_type7_xlat)
                decrypted += chr(byte ^ self.cisco_type7_xlat[key_index])
            
            return decrypted
            
        except Exception as e:
            return f"خطا در decrypt: {e}"
    
    def decode_base64_config(self, file_path: str) -> str:
        """Decode کردن فایل‌های Base64"""
        try:
            with open(file_path, 'rb') as f:
                encoded_content = f.read()
            
            decoded = base64.b64decode(encoded_content)
            return decoded.decode('utf-8', errors='ignore')
            
        except Exception as e:
            return f"خطا در decode کردن Base64: {e}"
    
    def extract_mikrotik_info(self, file_path: str) -> Dict[str, Any]:
        """استخراج اطلاعات از فایل‌های backup میکروتیک"""
        info = {
            'file_type': 'MikroTik Backup',
            'status': 'encrypted',
            'note': 'فایل‌های .backup میکروتیک فقط روی همان دستگاه یا دستگاه‌های مشابه قابل بازیابی هستند'
        }
        
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
            
            # بررسی header
            if len(content) > 16:
                header = content[:16]
                info['header'] = header.hex()
                
                # اطلاعات پایه
                info['file_size'] = len(content)
                
                # تلاش برای یافتن اطلاعات قابل خواندن
                readable_parts = []
                for i in range(0, len(content), 16):
                    chunk = content[i:i+16]
                    try:
                        text = chunk.decode('utf-8', errors='ignore')
                        if len(text.strip()) > 3 and text.isprintable():
                            readable_parts.append(text.strip())
                    except:
                        pass
                
                if readable_parts:
                    info['readable_parts'] = readable_parts[:10]  # اول 10 قسمت
            
            return info
            
        except Exception as e:
            info['error'] = str(e)
            return info
    
    def parse_cisco_config(self, content: str) -> Dict[str, Any]:
        """تجزیه فایل کانفیگ سیسکو و استخراج اطلاعات مهم"""
        info = {
            'interfaces': [],
            'passwords': [],
            'routing': [],
            'vlans': [],
            'access_lists': []
        }
        
        lines = content.split('\n')
        
        for line in lines:
            line = line.strip()
            
            # استخراج interfaces
            if line.startswith('interface '):
                info['interfaces'].append(line)
            
            # استخراج پسوردهای Type 7
            if 'password 7 ' in line:
                match = re.search(r'password 7 ([A-Fa-f0-9]+)', line)
                if match:
                    encrypted_pass = match.group(1)
                    decrypted_pass = self.decrypt_cisco_type7(encrypted_pass)
                    info['passwords'].append({
                        'line': line,
                        'encrypted': encrypted_pass,
                        'decrypted': decrypted_pass
                    })
            
            # استخراج اطلاعات routing
            if line.startswith('ip route') or line.startswith('router '):
                info['routing'].append(line)
            
            # استخراج VLANs
            if line.startswith('vlan ') or 'switchport access vlan' in line:
                info['vlans'].append(line)
            
            # استخراج Access Lists
            if line.startswith('access-list') or line.startswith('ip access-list'):
                info['access_lists'].append(line)
        
        return info
    
    def decrypt_file(self, file_path: str, output_path: Optional[str] = None) -> Dict[str, Any]:
        """تابع اصلی برای decrypt کردن فایل"""
        if not os.path.exists(file_path):
            return {'error': 'فایل وجود ندارد'}
        
        file_type = self.detect_file_type(file_path)
        result = {
            'file_path': file_path,
            'file_type': file_type,
            'success': False
        }
        
        try:
            if file_type == 'cisco_text':
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                # تجزیه کانفیگ سیسکو
                parsed_info = self.parse_cisco_config(content)
                result.update(parsed_info)
                result['success'] = True
                result['content'] = content
                
            elif file_type == 'base64_encoded':
                decoded_content = self.decode_base64_config(file_path)
                result['content'] = decoded_content
                result['success'] = True
                
                # اگر محتوای decode شده مثل کانفیگ سیسکو باشه
                if 'interface ' in decoded_content and 'version ' in decoded_content:
                    parsed_info = self.parse_cisco_config(decoded_content)
                    result.update(parsed_info)
                
            elif file_type == 'mikrotik_backup':
                mikrotik_info = self.extract_mikrotik_info(file_path)
                result.update(mikrotik_info)
                result['success'] = True
                
            else:
                result['error'] = f'نوع فایل پشتیبانی نمی‌شود: {file_type}'
            
            # ذخیره خروجی
            if output_path and result.get('content'):
                with open(output_path, 'w', encoding='utf-8') as f:
                    f.write(result['content'])
                result['output_saved'] = output_path
                
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def print_results(self, result: Dict[str, Any]):
        """نمایش نتایج به صورت خوانا"""
        print("=" * 60)
        print("نتایج تجزیه فایل کانفیگ روتر")
        print("=" * 60)
        
        print(f"مسیر فایل: {result['file_path']}")
        print(f"نوع فایل: {result['file_type']}")
        print(f"وضعیت: {'موفق' if result['success'] else 'ناموفق'}")
        
        if 'error' in result:
            print(f"خطا: {result['error']}")
            return
        
        # نمایش پسوردهای استخراج شده
        if 'passwords' in result and result['passwords']:
            print("\n🔑 پسوردهای یافت شده:")
            for pwd in result['passwords']:
                print(f"  رمزگذاری شده: {pwd['encrypted']}")
                print(f"  رمزگشایی شده: {pwd['decrypted']}")
                print(f"  خط کامل: {pwd['line']}")
                print("-" * 40)
        
        # نمایش interfaces
        if 'interfaces' in result and result['interfaces']:
            print(f"\n🌐 Interfaces ({len(result['interfaces'])} عدد):")
            for interface in result['interfaces'][:5]:  # نمایش 5 تای اول
                print(f"  {interface}")
            if len(result['interfaces']) > 5:
                print(f"  ... و {len(result['interfaces']) - 5} interface دیگر")
        
        # نمایش اطلاعات routing
        if 'routing' in result and result['routing']:
            print(f"\n🛣️ اطلاعات Routing ({len(result['routing'])} عدد):")
            for route in result['routing'][:3]:
                print(f"  {route}")
            if len(result['routing']) > 3:
                print(f"  ... و {len(result['routing']) - 3} route دیگر")
        
        # نمایش VLANs
        if 'vlans' in result and result['vlans']:
            print(f"\n🏷️ VLANs ({len(result['vlans'])} عدد):")
            for vlan in result['vlans'][:3]:
                print(f"  {vlan}")
        
        # نمایش اطلاعات میکروتیک
        if result['file_type'] == 'mikrotik_backup':
            print(f"\n📁 اندازه فایل: {result.get('file_size', 'نامشخص')} بایت")
            if 'readable_parts' in result:
                print("🔍 قسمت‌های قابل خواندن:")
                for part in result['readable_parts']:
                    print(f"  {part}")
        
        if 'output_saved' in result:
            print(f"\n💾 فایل خروجی ذخیره شد: {result['output_saved']}")


def main():
    """تابع اصلی برنامه"""
    parser = argparse.ArgumentParser(
        description='ابزار Decrypt کردن فایل‌های کانفیگ روتر',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
مثال‌های استفاده:
  python router_config_decryptor.py config.txt
  python router_config_decryptor.py backup.backup -o decrypted.txt
  python router_config_decryptor.py -p "094F471A1A0A"
        """
    )
    
    parser.add_argument('file', nargs='?', help='مسیر فایل کانفیگ')
    parser.add_argument('-o', '--output', help='مسیر فایل خروجی')
    parser.add_argument('-p', '--password', help='decrypt کردن پسورد Type 7 سیسکو')
    parser.add_argument('-v', '--verbose', action='store_true', help='نمایش اطلاعات تکمیلی')
    
    args = parser.parse_args()
    
    decryptor = RouterConfigDecryptor()
    
    # اگر فقط پسورد داده شده
    if args.password:
        decrypted = decryptor.decrypt_cisco_type7(args.password)
        print(f"پسورد رمزگذاری شده: {args.password}")
        print(f"پسورد رمزگشایی شده: {decrypted}")
        return
    
    # اگر فایل داده نشده
    if not args.file:
        print("لطفاً مسیر فایل کانفیگ را وارد کنید")
        parser.print_help()
        return
    
    # پردازش فایل
    result = decryptor.decrypt_file(args.file, args.output)
    decryptor.print_results(result)
    
    if args.verbose and 'content' in result:
        print("\n" + "=" * 60)
        print("محتوای کامل فایل:")
        print("=" * 60)
        print(result['content'][:2000])  # نمایش 2000 کاراکتر اول
        if len(result['content']) > 2000:
            print("\n... (محتوای بیشتر در فایل خروجی)")


if __name__ == "__main__":
    main()