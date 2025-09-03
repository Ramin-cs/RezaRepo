#!/usr/bin/env python3
"""
🔧 ابزار Decrypt کانفیگ روتر
نقطه شروع اصلی برنامه

برای مدیران شبکه عزیز
"""

import os
import sys
import subprocess

def check_dependencies():
    """بررسی وابستگی‌ها"""
    print("🔍 بررسی وابستگی‌ها...")
    
    required_modules = ['tkinter', 'argparse', 'pathlib']
    missing_modules = []
    
    for module in required_modules:
        try:
            __import__(module)
        except ImportError:
            missing_modules.append(module)
    
    if missing_modules:
        print(f"❌ ماژول‌های ناموجود: {', '.join(missing_modules)}")
        return False
    
    print("✅ همه وابستگی‌ها موجود است")
    return True

def install_requirements():
    """نصب requirements"""
    print("📦 نصب وابستگی‌ها...")
    try:
        subprocess.check_call([sys.executable, '-m', 'pip', 'install', '-r', 'requirements.txt'])
        print("✅ وابستگی‌ها نصب شدند")
        return True
    except subprocess.CalledProcessError:
        print("❌ خطا در نصب وابستگی‌ها")
        return False

def main_menu():
    """منوی اصلی"""
    while True:
        print("\n" + "=" * 60)
        print("🔧 ابزار Decrypt کانفیگ روتر")
        print("=" * 60)
        print("سلام عزیزم! چه کاری می‌خواهید انجام دهید؟")
        print()
        print("1️⃣  شروع سریع - رابط گرافیکی (توصیه شده)")
        print("2️⃣  ابزار خط فرمان ساده")
        print("3️⃣  ابزار پیشرفته خط فرمان")
        print("4️⃣  Decrypt فقط پسورد Type 7")
        print("5️⃣  نمایش راهنمای کامل")
        print("6️⃣  تست با فایل‌های نمونه")
        print("7️⃣  نصب/بررسی وابستگی‌ها")
        print("8️⃣  خروج")
        print()
        
        choice = input("انتخاب شما (1-8): ").strip()
        
        if choice == '1':
            print("🖥️  اجرای رابط گرافیکی...")
            os.system("python3 router_gui.py")
        
        elif choice == '2':
            file_path = input("مسیر فایل کانفیگ: ").strip()
            if file_path:
                os.system(f"python3 router_config_decryptor.py \"{file_path}\"")
        
        elif choice == '3':
            file_path = input("مسیر فایل کانفیگ: ").strip()
            if file_path:
                report_file = input("مسیر فایل گزارش (اختیاری): ").strip()
                cmd = f"python3 advanced_router_decryptor.py \"{file_path}\""
                if report_file:
                    cmd += f" --report \"{report_file}\""
                os.system(cmd)
        
        elif choice == '4':
            password = input("پسورد Type 7: ").strip()
            if password:
                os.system(f"python3 router_config_decryptor.py -p \"{password}\"")
        
        elif choice == '5':
            os.system("python3 quick_start.py")
        
        elif choice == '6':
            print("📝 ایجاد فایل‌های نمونه...")
            os.system("python3 advanced_router_decryptor.py --create-samples")
            print("\n🧪 تست با نمونه سیسکو:")
            os.system("python3 router_config_decryptor.py sample_cisco_config.txt")
        
        elif choice == '7':
            if not check_dependencies():
                install_requirements()
            else:
                print("✅ همه چیز آماده است!")
        
        elif choice == '8':
            print("👋 خداحافظ عزیزم! موفق باشید")
            break
        
        else:
            print("❌ انتخاب نامعتبر. لطفاً عددی بین 1 تا 8 وارد کنید")
        
        input("\n⏎ Enter را بزنید تا ادامه دهید...")

if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        print("\n\n👋 برنامه متوقف شد. خداحافظ!")
    except Exception as e:
        print(f"\n❌ خطای غیرمنتظره: {e}")
        print("لطفاً مجدداً تلاش کنید یا با پشتیبانی تماس بگیرید")