#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
مثال ارسال ایمیل انبوه
Bulk Email Sending Example

این مثال نحوه استفاده از سیستم برای ارسال ایمیل انبوه با قالب‌های سفارشی را نشان می‌دهد.
"""

import sys
import os
import json
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from email_sender import ProfessionalEmailSender

def create_sample_recipients():
    """ایجاد فایل نمونه گیرندگان"""
    recipients = [
        {
            "email": "user1@example.com",
            "name": "احمد محمدی",
            "variables": {
                "first_name": "احمد",
                "last_name": "محمدی",
                "company": "شرکت الف",
                "position": "مدیر فروش",
                "special_offer": "20% تخفیف",
                "expiry_date": "۳۱ دی ۱۴۰۳"
            }
        },
        {
            "email": "user2@example.com",
            "name": "فاطمه کریمی",
            "variables": {
                "first_name": "فاطمه",
                "last_name": "کریمی",
                "company": "شرکت ب",
                "position": "مدیر بازاریابی",
                "special_offer": "15% تخفیف",
                "expiry_date": "۳۱ دی ۱۴۰۳"
            }
        },
        {
            "email": "user3@example.com",
            "name": "علی رضایی",
            "variables": {
                "first_name": "علی",
                "last_name": "رضایی",
                "company": "شرکت ج",
                "position": "مدیر IT",
                "special_offer": "25% تخفیف",
                "expiry_date": "۳۱ دی ۱۴۰۳"
            }
        }
    ]
    
    with open('recipients.json', 'w', encoding='utf-8') as f:
        json.dump(recipients, f, ensure_ascii=False, indent=4)
    
    print("✅ فایل recipients.json ایجاد شد!")
    return recipients

def main():
    # ایجاد نمونه از سیستم ارسال ایمیل
    email_sender = ProfessionalEmailSender()
    
    # تنظیمات SMTP
    smtp_config = {
        'server': 'smtp.gmail.com',
        'port': 587,
        'security': 'tls',
        'username': 'your_email@gmail.com',  # آدرس ایمیل خود را وارد کنید
        'password': 'your_app_password'      # App Password خود را وارد کنید
    }
    
    # اطلاعات فرستنده
    sender_email = 'your_email@gmail.com'
    sender_name = 'تیم بازاریابی'
    subject = 'پیشنهاد ویژه برای {{first_name}} عزیز'
    
    # قالب HTML با متغیرهای قابل جایگذاری
    html_template = """
    <!DOCTYPE html>
    <html lang="fa" dir="rtl">
    <head>
        <meta charset="UTF-8">
        <style>
            body {
                font-family: Tahoma, Arial, sans-serif;
                line-height: 1.6;
                color: #333;
                max-width: 600px;
                margin: 0 auto;
                padding: 20px;
                background-color: #f4f4f4;
            }
            .container {
                background-color: white;
                padding: 30px;
                border-radius: 10px;
                box-shadow: 0 0 10px rgba(0,0,0,0.1);
            }
            .header {
                text-align: center;
                background: linear-gradient(135deg, #667eea, #764ba2);
                color: white;
                padding: 30px;
                border-radius: 10px;
                margin-bottom: 30px;
            }
            .offer-box {
                background: linear-gradient(135deg, #ffeaa7, #fdcb6e);
                padding: 20px;
                border-radius: 10px;
                text-align: center;
                margin: 20px 0;
            }
            .offer-box h2 {
                color: #2d3436;
                font-size: 24px;
                margin: 0;
            }
            .button {
                display: inline-block;
                padding: 15px 30px;
                background: linear-gradient(135deg, #00b894, #00cec9);
                color: white;
                text-decoration: none;
                border-radius: 25px;
                font-weight: bold;
                margin: 20px 0;
                transition: transform 0.3s ease;
            }
            .button:hover {
                transform: translateY(-2px);
            }
            .footer {
                text-align: center;
                margin-top: 30px;
                padding-top: 20px;
                border-top: 1px solid #eee;
                color: #666;
                font-size: 12px;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>پیشنهاد ویژه</h1>
                <p>مخصوص مشتریان عزیز</p>
            </div>
            
            <h2>سلام {{first_name}} عزیز،</h2>
            
            <p>امیدواریم که حال شما در {{company}} عالی باشد.</p>
            
            <p>به عنوان {{position}} محترم، پیشنهاد ویژه‌ای برای شما داریم:</p>
            
            <div class="offer-box">
                <h2>{{special_offer}}</h2>
                <p>روی تمام محصولات ما</p>
                <p><strong>تا تاریخ: {{expiry_date}}</strong></p>
            </div>
            
            <p>این پیشنهاد محدود به مدت است و فقط برای مشتریان ویژه مانند شما در نظر گرفته شده است.</p>
            
            <div style="text-align: center;">
                <a href="https://example.com/offer" class="button">استفاده از پیشنهاد</a>
            </div>
            
            <p>در صورت داشتن هرگونه سوال، با ما تماس بگیرید.</p>
            
            <p>با احترام،<br>
            تیم فروش<br>
            شرکت نمونه</p>
            
            <div class="footer">
                <p>این ایمیل برای {{email}} ارسال شده است.</p>
                <p>برای لغو اشتراک <a href="#">اینجا کلیک کنید</a>.</p>
            </div>
        </div>
    </body>
    </html>
    """
    
    # ایجاد فایل نمونه گیرندگان
    recipients = create_sample_recipients()
    
    print("🚀 شروع ارسال ایمیل انبوه...")
    
    # ارسال انبوه
    stats = email_sender.bulk_send(
        smtp_config=smtp_config,
        sender_email=sender_email,
        sender_name=sender_name,
        recipients=recipients,
        subject=subject,
        html_template=html_template,
        delay=2,  # تاخیر 2 ثانیه بین هر ارسال
        company_name="شرکت نمونه",
        department="بخش بازاریابی",
        priority="normal"
    )
    
    print("\n📊 گزارش نهایی:")
    print(f"کل ایمیل‌ها: {stats['total']}")
    print(f"ارسال موفق: {stats['sent']}")
    print(f"ارسال ناموفق: {stats['failed']}")
    
    if stats['errors']:
        print("\n❌ خطاها:")
        for error in stats['errors']:
            print(f"  - {error}")

if __name__ == "__main__":
    main()