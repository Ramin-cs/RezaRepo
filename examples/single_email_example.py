#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
مثال ارسال ایمیل تکی
Single Email Sending Example

این مثال نحوه استفاده از سیستم ارسال ایمیل برای ارسال یک ایمیل تکی را نشان می‌دهد.
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from email_sender import ProfessionalEmailSender

def main():
    # ایجاد نمونه از سیستم ارسال ایمیل
    email_sender = ProfessionalEmailSender()
    
    # تنظیمات SMTP (Gmail)
    smtp_config = {
        'server': 'smtp.gmail.com',
        'port': 587,
        'security': 'tls',
        'username': 'your_email@gmail.com',  # آدرس ایمیل خود را وارد کنید
        'password': 'your_app_password'      # App Password خود را وارد کنید
    }
    
    # اطلاعات ایمیل
    sender_email = 'your_email@gmail.com'
    sender_name = 'نام شما'
    recipient_email = 'recipient@example.com'
    recipient_name = 'نام گیرنده'
    subject = 'تست ارسال ایمیل حرفه‌ای'
    
    # محتوای HTML ایمیل
    html_content = """
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
                border-bottom: 2px solid #007bff;
                padding-bottom: 20px;
                margin-bottom: 30px;
            }
            .button {
                display: inline-block;
                padding: 12px 24px;
                background-color: #007bff;
                color: white;
                text-decoration: none;
                border-radius: 5px;
                margin: 20px 0;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>تست سیستم ارسال ایمیل</h1>
            </div>
            <h2>سلام!</h2>
            <p>این یک ایمیل تستی است که با استفاده از سیستم ارسال ایمیل حرفه‌ای ارسال شده است.</p>
            <p>ویژگی‌های این سیستم:</p>
            <ul>
                <li>پشتیبانی از قالب‌های HTML زیبا</li>
                <li>هدرهای پیشرفته برای جلوگیری از اسپم</li>
                <li>پشتیبانی از سرورهای SMTP مختلف</li>
                <li>امکان ارسال انبوه</li>
                <li>قابلیت اضافه کردن فایل ضمیمه</li>
            </ul>
            <div style="text-align: center;">
                <a href="https://github.com" class="button">مشاهده پروژه</a>
            </div>
            <p>با تشکر،<br>تیم توسعه</p>
        </div>
    </body>
    </html>
    """
    
    # هدرهای سفارشی
    custom_headers = {
        'X-Campaign-ID': 'test-campaign-001',
        'X-Email-Type': 'transactional'
    }
    
    # ارسال ایمیل
    print("🚀 شروع ارسال ایمیل...")
    
    success = email_sender.send_email(
        smtp_config=smtp_config,
        sender_email=sender_email,
        sender_name=sender_name,
        recipient_email=recipient_email,
        recipient_name=recipient_name,
        subject=subject,
        html_content=html_content,
        custom_headers=custom_headers,
        company_name="شرکت تست",
        department="بخش IT",
        priority="normal"
    )
    
    if success:
        print("✅ ایمیل با موفقیت ارسال شد!")
    else:
        print("❌ خطا در ارسال ایمیل!")

if __name__ == "__main__":
    main()