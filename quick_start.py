#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
راه‌اندازی سریع سیستم ارسال ایمیل
Quick Start Email Sender

برای شروع سریع، فقط این فایل را اجرا کنید و مراحل را دنبال کنید.
"""

from email_sender import ProfessionalEmailSender
import os
import json

def quick_setup():
    """راه‌اندازی سریع سیستم"""
    print("🚀 خوش آمدید به سیستم ارسال ایمیل حرفه‌ای!")
    print("=" * 60)
    
    # ایجاد نمونه
    email_sender = ProfessionalEmailSender()
    
    print("\n📧 لطفاً اطلاعات زیر را وارد کنید:")
    
    # انتخاب سرور
    print("\n🌐 انتخاب سرور ایمیل:")
    print("1. Gmail")
    print("2. Outlook/Hotmail") 
    print("3. Yahoo")
    print("4. Office 365")
    print("5. سرور سفارشی")
    
    choice = input("\nانتخاب کنید (1-5): ").strip()
    
    smtp_configs = {
        '1': {'server': 'smtp.gmail.com', 'port': 587, 'security': 'tls', 'name': 'Gmail'},
        '2': {'server': 'smtp-mail.outlook.com', 'port': 587, 'security': 'tls', 'name': 'Outlook'},
        '3': {'server': 'smtp.mail.yahoo.com', 'port': 587, 'security': 'tls', 'name': 'Yahoo'},
        '4': {'server': 'smtp.office365.com', 'port': 587, 'security': 'tls', 'name': 'Office 365'},
    }
    
    if choice in smtp_configs:
        smtp_config = smtp_configs[choice]
        print(f"✅ {smtp_config['name']} انتخاب شد")
    else:
        smtp_config = {
            'server': input("آدرس سرور SMTP: "),
            'port': int(input("پورت (معمولاً 587): ") or "587"),
            'security': 'tls',
            'name': 'Custom'
        }
    
    # اطلاعات احراز هویت
    print(f"\n🔐 اطلاعات احراز هویت برای {smtp_config['name']}:")
    smtp_config['username'] = input("آدرس ایمیل: ")
    smtp_config['password'] = input("رمز عبور (یا App Password): ")
    
    # تست اتصال
    print("\n🔍 تست اتصال...")
    try:
        import smtplib
        import ssl
        
        if smtp_config.get('security') == 'ssl':
            context = ssl.create_default_context()
            server = smtplib.SMTP_SSL(smtp_config['server'], smtp_config['port'], context=context)
        else:
            server = smtplib.SMTP(smtp_config['server'], smtp_config['port'])
            if smtp_config.get('security') == 'tls':
                context = ssl.create_default_context()
                server.starttls(context=context)
        
        server.login(smtp_config['username'], smtp_config['password'])
        server.quit()
        print("✅ اتصال موفقیت‌آمیز!")
        
    except Exception as e:
        print(f"❌ خطا در اتصال: {e}")
        print("لطفاً اطلاعات را بررسی کنید.")
        return None
    
    # ذخیره تنظیمات
    config = {
        'smtp_config': smtp_config,
        'setup_completed': True
    }
    
    with open('quick_config.json', 'w', encoding='utf-8') as f:
        json.dump(config, f, ensure_ascii=False, indent=4)
    
    print("💾 تنظیمات ذخیره شد!")
    return smtp_config

def send_test_email(smtp_config):
    """ارسال ایمیل تستی"""
    email_sender = ProfessionalEmailSender()
    
    print("\n📧 ارسال ایمیل تستی:")
    
    sender_email = smtp_config['username']
    sender_name = input("نام فرستنده: ") or "تست"
    recipient_email = input("آدرس گیرنده (برای تست): ")
    
    if not recipient_email:
        print("❌ آدرس گیرنده الزامی است!")
        return
    
    # ایمیل تستی ساده
    html_content = f"""
    <!DOCTYPE html>
    <html lang="fa" dir="rtl">
    <head>
        <meta charset="UTF-8">
        <style>
            body {{
                font-family: Tahoma, Arial, sans-serif;
                max-width: 600px;
                margin: 0 auto;
                padding: 20px;
                background-color: #f4f4f4;
            }}
            .container {{
                background-color: white;
                padding: 30px;
                border-radius: 10px;
                box-shadow: 0 0 10px rgba(0,0,0,0.1);
            }}
            .success {{
                background-color: #d4edda;
                color: #155724;
                padding: 15px;
                border-radius: 5px;
                border: 1px solid #c3e6cb;
                text-align: center;
                margin: 20px 0;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🎉 تبریک!</h1>
            <div class="success">
                <strong>سیستم ارسال ایمیل با موفقیت راه‌اندازی شد!</strong>
            </div>
            <p>این ایمیل تستی است که نشان می‌دهد سیستم شما درست کار می‌کند.</p>
            <h3>ویژگی‌های سیستم:</h3>
            <ul>
                <li>✅ ارسال ایمیل تکی و انبوه</li>
                <li>✅ قالب‌های HTML زیبا</li>
                <li>✅ هدرهای ضد اسپم</li>
                <li>✅ پشتیبانی از سرورهای مختلف</li>
                <li>✅ گزارش‌گیری کامل</li>
            </ul>
            <p><strong>حالا می‌توانید از سیستم استفاده کنید!</strong></p>
            <hr>
            <p style="font-size: 12px; color: #666;">
                ارسال شده توسط سیستم ارسال ایمیل حرفه‌ای<br>
                تاریخ: {email_sender._get_current_date()}
            </p>
        </div>
    </body>
    </html>
    """
    
    print("\n🚀 در حال ارسال ایمیل تستی...")
    
    success = email_sender.send_email(
        smtp_config=smtp_config,
        sender_email=sender_email,
        sender_name=sender_name,
        recipient_email=recipient_email,
        recipient_name="کاربر تست",
        subject="🎉 تست موفق سیستم ارسال ایمیل",
        html_content=html_content,
        company_name="سیستم ارسال ایمیل",
        department="تست",
        priority="normal"
    )
    
    if success:
        print("✅ ایمیل تستی با موفقیت ارسال شد!")
        print(f"📬 ایمیل را در صندوق ورودی {recipient_email} بررسی کنید.")
    else:
        print("❌ خطا در ارسال ایمیل تستی!")

def main_menu(smtp_config):
    """منوی اصلی"""
    email_sender = ProfessionalEmailSender()
    
    while True:
        print("\n" + "="*50)
        print("📧 سیستم ارسال ایمیل حرفه‌ای")
        print("="*50)
        print("1. ارسال ایمیل تکی")
        print("2. ارسال ایمیل انبوه") 
        print("3. ایجاد قالب جدید")
        print("4. مشاهده قالب‌های موجود")
        print("5. تست اتصال مجدد")
        print("6. تغییر تنظیمات")
        print("0. خروج")
        
        choice = input("\nانتخاب کنید (0-6): ").strip()
        
        if choice == '1':
            send_single_email_simple(email_sender, smtp_config)
        elif choice == '2':
            send_bulk_email_simple(email_sender, smtp_config)
        elif choice == '3':
            create_template_simple()
        elif choice == '4':
            show_templates()
        elif choice == '5':
            test_connection(smtp_config)
        elif choice == '6':
            smtp_config = quick_setup()
            if not smtp_config:
                break
        elif choice == '0':
            print("👋 خداحافظ!")
            break
        else:
            print("❌ انتخاب نامعتبر!")

def send_single_email_simple(email_sender, smtp_config):
    """ارسال ایمیل تکی ساده"""
    print("\n📧 ارسال ایمیل تکی")
    print("-" * 30)
    
    sender_email = smtp_config['username']
    sender_name = input("نام فرستنده: ") or "فرستنده"
    recipient_email = input("آدرس گیرنده: ")
    recipient_name = input("نام گیرنده (اختیاری): ") or "گیرنده"
    subject = input("موضوع ایمیل: ")
    
    print("\nنوع پیام:")
    print("1. متن ساده")
    print("2. استفاده از قالب")
    
    msg_type = input("انتخاب (1-2): ").strip()
    
    if msg_type == '1':
        message = input("متن پیام: ")
        html_content = f"""
        <html><body style="font-family: Tahoma, Arial; direction: rtl;">
        <h2>سلام {recipient_name}!</h2>
        <p>{message}</p>
        <hr>
        <p style="font-size: 12px; color: #666;">ارسال شده توسط {sender_name}</p>
        </body></html>
        """
    else:
        templates = ['templates/professional.html', 'templates/newsletter.html']
        print("\nقالب‌های موجود:")
        for i, template in enumerate(templates, 1):
            if os.path.exists(template):
                print(f"{i}. {os.path.basename(template)}")
        
        template_choice = input("انتخاب قالب (شماره): ").strip()
        if template_choice == '1' and os.path.exists('templates/professional.html'):
            variables = {
                'recipient_name': recipient_name,
                'sender_name': sender_name,
                'company_name': input("نام شرکت: ") or "شرکت",
                'main_message': input("پیام اصلی: ") or "پیام تست",
                'button_text': input("متن دکمه (اختیاری): ") or "کلیک کنید",
                'button_link': input("لینک دکمه (اختیاری): ") or "#"
            }
            html_content = email_sender.load_template('templates/professional.html', variables)
        else:
            print("❌ قالب یافت نشد! از متن ساده استفاده می‌شود.")
            html_content = f"<html><body><h2>سلام!</h2><p>پیام تست</p></body></html>"
    
    print("\n🚀 در حال ارسال...")
    success = email_sender.send_email(
        smtp_config=smtp_config,
        sender_email=sender_email,
        sender_name=sender_name,
        recipient_email=recipient_email,
        recipient_name=recipient_name,
        subject=subject,
        html_content=html_content
    )
    
    if success:
        print("✅ ایمیل با موفقیت ارسال شد!")
    else:
        print("❌ خطا در ارسال ایمیل!")

def send_bulk_email_simple(email_sender, smtp_config):
    """ارسال انبوه ساده"""
    print("\n📧 ارسال ایمیل انبوه")
    print("-" * 30)
    
    if not os.path.exists('examples/recipients.json'):
        print("❌ فایل گیرندگان یافت نشد!")
        print("لطفاً فایل examples/recipients.json را بررسی کنید.")
        return
    
    try:
        with open('examples/recipients.json', 'r', encoding='utf-8') as f:
            recipients = json.load(f)
        
        print(f"📊 {len(recipients)} گیرنده یافت شد.")
        
        sender_email = smtp_config['username']
        sender_name = input("نام فرستنده: ") or "فرستنده"
        subject = input("موضوع ایمیل: ")
        
        # قالب ساده
        html_template = """
        <html>
        <body style="font-family: Tahoma, Arial; direction: rtl; max-width: 600px; margin: 0 auto;">
            <div style="background: white; padding: 30px; border-radius: 10px;">
                <h2>سلام {{first_name}} عزیز!</h2>
                <p>{{custom_message}}</p>
                <div style="background: #f0f8ff; padding: 15px; border-radius: 5px; text-align: center; margin: 20px 0;">
                    <strong>پیشنهاد ویژه: {{special_offer}}</strong>
                </div>
                <p>این پیشنهاد تا {{expiry_date}} معتبر است.</p>
                <p>با تشکر،<br>{{sender_name}}</p>
            </div>
        </body>
        </html>
        """
        
        delay = int(input("تاخیر بین ارسال‌ها (ثانیه) [2]: ") or "2")
        
        print(f"\n🚀 شروع ارسال انبوه به {len(recipients)} گیرنده...")
        
        stats = email_sender.bulk_send(
            smtp_config=smtp_config,
            sender_email=sender_email,
            sender_name=sender_name,
            recipients=recipients,
            subject=subject,
            html_template=html_template,
            delay=delay
        )
        
        print(f"\n📊 نتایج:")
        print(f"✅ موفق: {stats['sent']}")
        print(f"❌ ناموفق: {stats['failed']}")
        
    except Exception as e:
        print(f"❌ خطا: {e}")

def show_templates():
    """نمایش قالب‌های موجود"""
    print("\n🎨 قالب‌های موجود:")
    print("-" * 30)
    
    template_dir = 'templates'
    if os.path.exists(template_dir):
        templates = [f for f in os.listdir(template_dir) if f.endswith('.html')]
        if templates:
            for i, template in enumerate(templates, 1):
                print(f"{i}. {template}")
        else:
            print("هیچ قالبی یافت نشد.")
    else:
        print("پوشه قالب‌ها یافت نشد.")

def create_template_simple():
    """ایجاد قالب ساده"""
    print("\n🎨 ایجاد قالب جدید")
    print("-" * 30)
    
    name = input("نام قالب: ")
    if not name:
        print("❌ نام قالب الزامی است!")
        return
    
    # قالب پایه
    template_content = f"""<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
    <meta charset="UTF-8">
    <title>{{{{subject}}}}</title>
    <style>
        body {{
            font-family: Tahoma, Arial, sans-serif;
            max-width: 600px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f4f4f4;
        }}
        .container {{
            background-color: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }}
        .header {{
            text-align: center;
            border-bottom: 2px solid #007bff;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>{{{{company_name}}}}</h1>
        </div>
        <h2>سلام {{{{recipient_name}}}} عزیز!</h2>
        <p>{{{{main_message}}}}</p>
        <p>با تشکر،<br>{{{{sender_name}}}}</p>
    </div>
</body>
</html>"""
    
    os.makedirs('templates', exist_ok=True)
    template_path = f'templates/{name}.html'
    
    try:
        with open(template_path, 'w', encoding='utf-8') as f:
            f.write(template_content)
        print(f"✅ قالب {name} ایجاد شد!")
        print(f"📁 مسیر: {template_path}")
    except Exception as e:
        print(f"❌ خطا در ایجاد قالب: {e}")

def test_connection(smtp_config):
    """تست اتصال"""
    print("\n🔍 تست اتصال...")
    try:
        import smtplib
        import ssl
        
        if smtp_config.get('security') == 'ssl':
            context = ssl.create_default_context()
            server = smtplib.SMTP_SSL(smtp_config['server'], smtp_config['port'], context=context)
        else:
            server = smtplib.SMTP(smtp_config['server'], smtp_config['port'])
            if smtp_config.get('security') == 'tls':
                context = ssl.create_default_context()
                server.starttls(context=context)
        
        server.login(smtp_config['username'], smtp_config['password'])
        server.quit()
        print("✅ اتصال موفقیت‌آمیز!")
        
    except Exception as e:
        print(f"❌ خطا در اتصال: {e}")

def main():
    """تابع اصلی"""
    print("🚀 سیستم ارسال ایمیل حرفه‌ای")
    print("راه‌اندازی سریع")
    print("=" * 50)
    
    # بررسی تنظیمات موجود
    if os.path.exists('quick_config.json'):
        try:
            with open('quick_config.json', 'r', encoding='utf-8') as f:
                config = json.load(f)
            
            if config.get('setup_completed'):
                print("✅ تنظیمات قبلی یافت شد!")
                use_existing = input("از تنظیمات موجود استفاده شود? (y/n) [y]: ").lower()
                
                if use_existing != 'n':
                    smtp_config = config['smtp_config']
                    print(f"📧 استفاده از: {smtp_config.get('name', 'Custom')}")
                    
                    # تست ایمیل
                    test_email = input("ایمیل تستی ارسال شود? (y/n) [n]: ").lower()
                    if test_email == 'y':
                        send_test_email(smtp_config)
                    
                    main_menu(smtp_config)
                    return
        except:
            pass
    
    # راه‌اندازی جدید
    smtp_config = quick_setup()
    if not smtp_config:
        print("❌ راه‌اندازی ناموفق!")
        return
    
    # تست ایمیل
    test_email = input("\nایمیل تستی ارسال شود? (y/n) [y]: ").lower()
    if test_email != 'n':
        send_test_email(smtp_config)
    
    # ورود به منوی اصلی
    main_menu(smtp_config)

if __name__ == "__main__":
    main()