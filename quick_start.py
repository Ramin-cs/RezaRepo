#!/usr/bin/env python3
"""
Quick Start Guide - راهنمای سریع
ابزار Decrypt کانفیگ روتر
"""

import os
import sys
from pathlib import Path

def show_quick_guide():
    """نمایش راهنمای سریع"""
    print("🔧 ابزار Decrypt کانفیگ روتر - راهنمای سریع")
    print("=" * 60)
    print()
    
    print("📋 فایل‌های موجود:")
    files = [
        ("router_config_decryptor.py", "ابزار ساده و سریع"),
        ("advanced_router_decryptor.py", "ابزار پیشرفته با قابلیت‌های بیشتر"),
        ("router_gui.py", "رابط گرافیکی"),
        ("sample_cisco_config.txt", "نمونه کانفیگ سیسکو"),
        ("sample_base64_config.txt", "نمونه فایل Base64")
    ]
    
    for filename, description in files:
        status = "✅" if os.path.exists(filename) else "❌"
        print(f"  {status} {filename:<30} - {description}")
    
    print()
    print("🚀 روش‌های اجرا:")
    print()
    
    print("1️⃣ ابزار ساده (توصیه شده برای شروع):")
    print("   python3 router_config_decryptor.py فایل_کانفیگ.txt")
    print("   python3 router_config_decryptor.py -p \"094F471A1A0A\"")
    print()
    
    print("2️⃣ ابزار پیشرفته:")
    print("   python3 advanced_router_decryptor.py فایل_کانفیگ.backup")
    print("   python3 advanced_router_decryptor.py config.txt --report گزارش.txt")
    print()
    
    print("3️⃣ رابط گرافیکی (آسان‌ترین):")
    print("   python3 router_gui.py")
    print()
    
    print("🔑 مثال‌های عملی:")
    print()
    
    print("• تست با فایل نمونه:")
    print("  python3 router_config_decryptor.py sample_cisco_config.txt")
    print()
    
    print("• decrypt پسورد Type 7:")
    print("  python3 router_config_decryptor.py -p \"094F471A1A0A\"")
    print("  نتیجه: cisco")
    print()
    
    print("• تجزیه Base64:")
    print("  python3 router_config_decryptor.py sample_base64_config.txt")
    print()
    
    print("📊 انواع فایل‌های پشتیبانی شده:")
    print("  ✅ Cisco IOS configs (.cfg, .txt)")
    print("  ✅ MikroTik backups (.backup)")
    print("  ✅ Base64 encoded files")
    print("  ✅ فایل‌های متنی ساده")
    print("  ⚠️  فایل‌های AES/DES encrypted (نیاز به پسورد)")
    print()
    
    print("💡 نکات مهم:")
    print("  • همیشه از فایل‌های اصلی backup تهیه کنید")
    print("  • فقط روی تجهیزات خودتان استفاده کنید")
    print("  • پس از استفاده، فایل‌های decrypt شده را حذف کنید")
    print()
    
    print("🆘 رفع مشکلات:")
    print("  • اگر ماژولی یافت نشد: pip3 install -r requirements.txt")
    print("  • اگر فایل خوانده نشد: بررسی کنید فایل موجود باشد")
    print("  • اگر decrypt نشد: سعی کنید نسخه پیشرفته را امتحان کنید")
    print()


def interactive_mode():
    """حالت تعاملی"""
    print("🎯 حالت تعاملی - ابزار Decrypt کانفیگ روتر")
    print("=" * 50)
    
    while True:
        print("\nچه کاری می‌خواهید انجام دهید؟")
        print("1. Decrypt فایل کانفیگ")
        print("2. Decrypt پسورد Type 7")
        print("3. نمایش راهنما")
        print("4. اجرای رابط گرافیکی")
        print("5. خروج")
        
        choice = input("\nانتخاب شما (1-5): ").strip()
        
        if choice == '1':
            file_path = input("مسیر فایل کانفیگ: ").strip()
            if file_path and os.path.exists(file_path):
                os.system(f"python3 router_config_decryptor.py \"{file_path}\"")
            else:
                print("❌ فایل یافت نشد")
        
        elif choice == '2':
            password = input("پسورد Type 7: ").strip()
            if password:
                os.system(f"python3 router_config_decryptor.py -p \"{password}\"")
            else:
                print("❌ پسورد وارد نشد")
        
        elif choice == '3':
            show_quick_guide()
        
        elif choice == '4':
            print("🖥️ اجرای رابط گرافیکی...")
            os.system("python3 router_gui.py")
        
        elif choice == '5':
            print("👋 خداحافظ!")
            break
        
        else:
            print("❌ انتخاب نامعتبر")


def main():
    """تابع اصلی"""
    if len(sys.argv) > 1 and sys.argv[1] == '--interactive':
        interactive_mode()
    else:
        show_quick_guide()
        
        print("\n🎯 برای حالت تعاملی:")
        print("python3 quick_start.py --interactive")


if __name__ == "__main__":
    main()