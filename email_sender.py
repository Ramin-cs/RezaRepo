#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
سیستم ارسال ایمیل حرفه‌ای
Professional Email Sender System

این سیستم امکان ارسال ایمیل‌های حرفه‌ای با قالب‌های سفارشی و هدرهای پیشرفته را فراهم می‌کند
تا از رفتن ایمیل‌ها به پوشه spam جلوگیری کند.

نویسنده: Assistant
تاریخ: 2024
"""

import smtplib
import ssl
import json
import os
import sys
import time
import random
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from datetime import datetime
from typing import Dict, List, Optional, Union
import re
from pathlib import Path

class ProfessionalEmailSender:
    """
    کلاس اصلی برای ارسال ایمیل‌های حرفه‌ای
    """
    
    def __init__(self, config_file: str = "email_config.json"):
        """
        راه‌اندازی سیستم ارسال ایمیل
        
        Args:
            config_file: مسیر فایل تنظیمات
        """
        self.config_file = config_file
        self.config = self.load_config()
        self.smtp_servers = self.get_smtp_servers()
        
    def load_config(self) -> Dict:
        """بارگیری تنظیمات از فایل JSON"""
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception as e:
                print(f"خطا در بارگیری تنظیمات: {e}")
                return {}
        return {}
    
    def save_config(self, config: Dict) -> bool:
        """ذخیره تنظیمات در فایل JSON"""
        try:
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(config, f, ensure_ascii=False, indent=4)
            return True
        except Exception as e:
            print(f"خطا در ذخیره تنظیمات: {e}")
            return False
    
    def get_smtp_servers(self) -> Dict:
        """لیست سرورهای SMTP معروف"""
        return {
            'gmail': {
                'server': 'smtp.gmail.com',
                'port': 587,
                'security': 'tls',
                'name': 'Gmail'
            },
            'outlook': {
                'server': 'smtp-mail.outlook.com',
                'port': 587,
                'security': 'tls',
                'name': 'Outlook/Hotmail'
            },
            'yahoo': {
                'server': 'smtp.mail.yahoo.com',
                'port': 587,
                'security': 'tls',
                'name': 'Yahoo Mail'
            },
            'office365': {
                'server': 'smtp.office365.com',
                'port': 587,
                'security': 'tls',
                'name': 'Office 365'
            },
            'zoho': {
                'server': 'smtp.zoho.com',
                'port': 587,
                'security': 'tls',
                'name': 'Zoho Mail'
            },
            'custom': {
                'server': '',
                'port': 587,
                'security': 'tls',
                'name': 'Custom SMTP'
            }
        }
    
    def generate_professional_headers(self, 
                                    sender_email: str,
                                    recipient_email: str,
                                    subject: str,
                                    company_name: str = None,
                                    department: str = None,
                                    priority: str = "normal") -> Dict:
        """
        تولید هدرهای حرفه‌ای برای جلوگیری از اسپم
        
        Args:
            sender_email: آدرس فرستنده
            recipient_email: آدرس گیرنده
            subject: موضوع ایمیل
            company_name: نام شرکت
            department: نام بخش
            priority: اولویت ایمیل (low, normal, high)
        
        Returns:
            دیکشنری حاوی هدرهای ایمیل
        """
        
        # تولید Message-ID منحصر به فرد
        timestamp = str(int(time.time()))
        random_num = str(random.randint(100000, 999999))
        domain = sender_email.split('@')[1] if '@' in sender_email else 'localhost'
        message_id = f"<{timestamp}.{random_num}@{domain}>"
        
        # هدرهای اساسی
        headers = {
            'Message-ID': message_id,
            'Date': datetime.now().strftime('%a, %d %b %Y %H:%M:%S %z'),
            'MIME-Version': '1.0',
            'Content-Type': 'multipart/alternative',
            'X-Mailer': 'Professional Email Sender v1.0',
            'X-Priority': self._get_priority_value(priority),
            'Importance': priority.title(),
        }
        
        # هدرهای شرکتی
        if company_name:
            headers['X-Organization'] = company_name
            headers['Organization'] = company_name
            
        if department:
            headers['X-Department'] = department
            
        # هدرهای امنیتی و اعتبارسنجی
        headers.update({
            'X-Auto-Response-Suppress': 'OOF, DR, RN, NRN',
            'X-MSMail-Priority': priority.title(),
            'X-Originating-IP': '[127.0.0.1]',  # IP داخلی
            'X-Spam-Status': 'No',
            'X-Spam-Score': '0.0',
            'List-Unsubscribe': f'<mailto:{sender_email}?subject=Unsubscribe>',
            'Precedence': 'bulk' if priority == 'low' else 'normal',
        })
        
        # هدرهای بازگشتی
        headers['Return-Path'] = f'<{sender_email}>'
        headers['Reply-To'] = sender_email
        
        return headers
    
    def _get_priority_value(self, priority: str) -> str:
        """تبدیل اولویت به مقدار عددی"""
        priority_map = {
            'high': '1',
            'normal': '3',
            'low': '5'
        }
        return priority_map.get(priority.lower(), '3')
    
    def load_template(self, template_path: str, variables: Dict = None) -> str:
        """
        بارگیری قالب HTML و جایگذاری متغیرها
        
        Args:
            template_path: مسیر فایل قالب
            variables: متغیرهای قابل جایگذاری
        
        Returns:
            محتوای HTML نهایی
        """
        try:
            with open(template_path, 'r', encoding='utf-8') as f:
                template_content = f.read()
            
            if variables:
                for key, value in variables.items():
                    placeholder = f"{{{{{key}}}}}"
                    template_content = template_content.replace(placeholder, str(value))
            
            return template_content
        except Exception as e:
            print(f"خطا در بارگیری قالب: {e}")
            return ""
    
    def validate_email(self, email: str) -> bool:
        """اعتبارسنجی آدرس ایمیل"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None
    
    def create_professional_message(self,
                                  sender_email: str,
                                  sender_name: str,
                                  recipient_email: str,
                                  recipient_name: str,
                                  subject: str,
                                  html_content: str,
                                  text_content: str = None,
                                  custom_headers: Dict = None,
                                  company_name: str = None,
                                  department: str = None,
                                  priority: str = "normal") -> MIMEMultipart:
        """
        ایجاد پیام ایمیل حرفه‌ای
        
        Args:
            sender_email: آدرس ایمیل فرستنده
            sender_name: نام فرستنده
            recipient_email: آدرس ایمیل گیرنده
            recipient_name: نام گیرنده
            subject: موضوع ایمیل
            html_content: محتوای HTML
            text_content: محتوای متنی (اختیاری)
            custom_headers: هدرهای سفارشی
            company_name: نام شرکت
            department: نام بخش
            priority: اولویت ایمیل
        
        Returns:
            شیء MIMEMultipart آماده ارسال
        """
        
        # ایجاد پیام اصلی
        msg = MIMEMultipart('alternative')
        
        # تنظیم هدرهای اصلی
        msg['From'] = f"{sender_name} <{sender_email}>" if sender_name else sender_email
        msg['To'] = f"{recipient_name} <{recipient_email}>" if recipient_name else recipient_email
        msg['Subject'] = subject
        
        # اضافه کردن هدرهای حرفه‌ای
        professional_headers = self.generate_professional_headers(
            sender_email, recipient_email, subject, company_name, department, priority
        )
        
        for key, value in professional_headers.items():
            if key not in ['From', 'To', 'Subject']:  # جلوگیری از تکرار
                msg[key] = value
        
        # اضافه کردن هدرهای سفارشی
        if custom_headers:
            for key, value in custom_headers.items():
                msg[key] = value
        
        # اضافه کردن محتوای متنی (fallback)
        if text_content:
            text_part = MIMEText(text_content, 'plain', 'utf-8')
            msg.attach(text_part)
        else:
            # تولید محتوای متنی از HTML
            text_content = self._html_to_text(html_content)
            text_part = MIMEText(text_content, 'plain', 'utf-8')
            msg.attach(text_part)
        
        # اضافه کردن محتوای HTML
        html_part = MIMEText(html_content, 'html', 'utf-8')
        msg.attach(html_part)
        
        return msg
    
    def _html_to_text(self, html_content: str) -> str:
        """تبدیل ساده HTML به متن"""
        # حذف تگ‌های HTML
        import re
        text = re.sub(r'<[^>]+>', '', html_content)
        # تمیز کردن فاصله‌های اضافی
        text = re.sub(r'\s+', ' ', text).strip()
        return text
    
    def _get_current_date(self) -> str:
        """دریافت تاریخ فعلی"""
        return datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    def send_email(self,
                   smtp_config: Dict,
                   sender_email: str,
                   sender_name: str,
                   recipient_email: str,
                   recipient_name: str,
                   subject: str,
                   html_content: str,
                   text_content: str = None,
                   custom_headers: Dict = None,
                   company_name: str = None,
                   department: str = None,
                   priority: str = "normal",
                   attachments: List[str] = None) -> bool:
        """
        ارسال ایمیل با تنظیمات کامل
        
        Args:
            smtp_config: تنظیمات سرور SMTP
            sender_email: آدرس فرستنده
            sender_name: نام فرستنده
            recipient_email: آدرس گیرنده
            recipient_name: نام گیرنده
            subject: موضوع ایمیل
            html_content: محتوای HTML
            text_content: محتوای متنی
            custom_headers: هدرهای سفارشی
            company_name: نام شرکت
            department: نام بخش
            priority: اولویت
            attachments: لیست فایل‌های ضمیمه
        
        Returns:
            True در صورت موفقیت، False در صورت خطا
        """
        
        try:
            # اعتبارسنجی آدرس‌های ایمیل
            if not self.validate_email(sender_email):
                print(f"آدرس فرستنده نامعتبر: {sender_email}")
                return False
                
            if not self.validate_email(recipient_email):
                print(f"آدرس گیرنده نامعتبر: {recipient_email}")
                return False
            
            # ایجاد پیام
            msg = self.create_professional_message(
                sender_email, sender_name, recipient_email, recipient_name,
                subject, html_content, text_content, custom_headers,
                company_name, department, priority
            )
            
            # اضافه کردن فایل‌های ضمیمه
            if attachments:
                for file_path in attachments:
                    if os.path.exists(file_path):
                        self._add_attachment(msg, file_path)
                    else:
                        print(f"فایل ضمیمه یافت نشد: {file_path}")
            
            # اتصال به سرور SMTP
            print(f"اتصال به سرور SMTP: {smtp_config['server']}:{smtp_config['port']}")
            
            if smtp_config.get('security') == 'ssl':
                context = ssl.create_default_context()
                server = smtplib.SMTP_SSL(smtp_config['server'], smtp_config['port'], context=context)
            else:
                server = smtplib.SMTP(smtp_config['server'], smtp_config['port'])
                if smtp_config.get('security') == 'tls':
                    context = ssl.create_default_context()
                    server.starttls(context=context)
            
            # احراز هویت
            if smtp_config.get('username') and smtp_config.get('password'):
                print("احراز هویت...")
                server.login(smtp_config['username'], smtp_config['password'])
            
            # ارسال ایمیل
            print(f"ارسال ایمیل به {recipient_email}...")
            server.sendmail(sender_email, recipient_email, msg.as_string())
            server.quit()
            
            print("✅ ایمیل با موفقیت ارسال شد!")
            return True
            
        except smtplib.SMTPAuthenticationError as e:
            print(f"❌ خطای احراز هویت: {e}")
            return False
        except smtplib.SMTPRecipientsRefused as e:
            print(f"❌ آدرس گیرنده رد شد: {e}")
            return False
        except smtplib.SMTPServerDisconnected as e:
            print(f"❌ اتصال به سرور قطع شد: {e}")
            return False
        except Exception as e:
            print(f"❌ خطای غیرمنتظره: {e}")
            return False
    
    def _add_attachment(self, msg: MIMEMultipart, file_path: str):
        """اضافه کردن فایل ضمیمه"""
        try:
            with open(file_path, "rb") as attachment:
                part = MIMEBase('application', 'octet-stream')
                part.set_payload(attachment.read())
            
            encoders.encode_base64(part)
            part.add_header(
                'Content-Disposition',
                f'attachment; filename= {os.path.basename(file_path)}'
            )
            msg.attach(part)
            print(f"فایل ضمیمه اضافه شد: {file_path}")
        except Exception as e:
            print(f"خطا در اضافه کردن فایل ضمیمه {file_path}: {e}")
    
    def bulk_send(self,
                  smtp_config: Dict,
                  sender_email: str,
                  sender_name: str,
                  recipients: List[Dict],
                  subject: str,
                  html_template: str,
                  delay: int = 1,
                  **kwargs) -> Dict:
        """
        ارسال انبوه ایمیل
        
        Args:
            smtp_config: تنظیمات SMTP
            sender_email: آدرس فرستنده
            sender_name: نام فرستنده
            recipients: لیست گیرندگان
            subject: موضوع ایمیل
            html_template: قالب HTML
            delay: تاخیر بین ارسال‌ها (ثانیه)
            **kwargs: سایر پارامترها
        
        Returns:
            آمار ارسال
        """
        
        stats = {
            'total': len(recipients),
            'sent': 0,
            'failed': 0,
            'errors': []
        }
        
        for i, recipient in enumerate(recipients):
            try:
                print(f"\nارسال ایمیل {i+1} از {len(recipients)}...")
                
                # جایگذاری متغیرها در قالب
                html_content = html_template
                for key, value in recipient.get('variables', {}).items():
                    html_content = html_content.replace(f"{{{{{key}}}}}", str(value))
                
                # ارسال ایمیل
                success = self.send_email(
                    smtp_config=smtp_config,
                    sender_email=sender_email,
                    sender_name=sender_name,
                    recipient_email=recipient['email'],
                    recipient_name=recipient.get('name', ''),
                    subject=subject,
                    html_content=html_content,
                    **kwargs
                )
                
                if success:
                    stats['sent'] += 1
                else:
                    stats['failed'] += 1
                    stats['errors'].append(f"خطا در ارسال به {recipient['email']}")
                
                # تاخیر بین ارسال‌ها
                if i < len(recipients) - 1 and delay > 0:
                    print(f"انتظار {delay} ثانیه...")
                    time.sleep(delay)
                    
            except Exception as e:
                stats['failed'] += 1
                stats['errors'].append(f"خطا در ارسال به {recipient.get('email', 'نامشخص')}: {e}")
        
        print(f"\n📊 آمار نهایی:")
        print(f"کل: {stats['total']}")
        print(f"ارسال شده: {stats['sent']}")
        print(f"ناموفق: {stats['failed']}")
        
        return stats


def main():
    """تابع اصلی برنامه"""
    print("🚀 سیستم ارسال ایمیل حرفه‌ای")
    print("=" * 50)
    
    # ایجاد نمونه از کلاس
    email_sender = ProfessionalEmailSender()
    
    # منوی اصلی
    while True:
        print("\n📧 منوی اصلی:")
        print("1. ارسال ایمیل تکی")
        print("2. ارسال ایمیل انبوه")
        print("3. تنظیم سرور SMTP")
        print("4. ایجاد قالب ایمیل")
        print("5. تست اتصال SMTP")
        print("0. خروج")
        
        choice = input("\nانتخاب کنید (0-5): ").strip()
        
        if choice == '1':
            send_single_email(email_sender)
        elif choice == '2':
            send_bulk_email(email_sender)
        elif choice == '3':
            setup_smtp(email_sender)
        elif choice == '4':
            create_template()
        elif choice == '5':
            test_smtp_connection(email_sender)
        elif choice == '0':
            print("خداحافظ! 👋")
            break
        else:
            print("❌ انتخاب نامعتبر!")


def send_single_email(email_sender: ProfessionalEmailSender):
    """ارسال ایمیل تکی"""
    print("\n📧 ارسال ایمیل تکی")
    print("-" * 30)
    
    # دریافت اطلاعات SMTP
    smtp_config = get_smtp_config(email_sender)
    if not smtp_config:
        return
    
    # دریافت اطلاعات ایمیل
    sender_email = input("آدرس ایمیل فرستنده: ").strip()
    sender_name = input("نام فرستنده (اختیاری): ").strip()
    recipient_email = input("آدرس ایمیل گیرنده: ").strip()
    recipient_name = input("نام گیرنده (اختیاری): ").strip()
    subject = input("موضوع ایمیل: ").strip()
    
    # انتخاب نوع محتوا
    print("\nنوع محتوا:")
    print("1. متن ساده")
    print("2. HTML")
    print("3. بارگیری از فایل")
    
    content_type = input("انتخاب کنید (1-3): ").strip()
    
    html_content = ""
    if content_type == '1':
        text = input("متن ایمیل: ")
        html_content = f"<html><body><p>{text}</p></body></html>"
    elif content_type == '2':
        html_content = input("کد HTML: ")
    elif content_type == '3':
        file_path = input("مسیر فایل HTML: ").strip()
        if os.path.exists(file_path):
            html_content = email_sender.load_template(file_path)
        else:
            print("❌ فایل یافت نشد!")
            return
    
    # اطلاعات اضافی
    company_name = input("نام شرکت (اختیاری): ").strip()
    department = input("نام بخش (اختیاری): ").strip()
    
    # ارسال ایمیل
    success = email_sender.send_email(
        smtp_config=smtp_config,
        sender_email=sender_email,
        sender_name=sender_name,
        recipient_email=recipient_email,
        recipient_name=recipient_name,
        subject=subject,
        html_content=html_content,
        company_name=company_name,
        department=department
    )
    
    if success:
        print("✅ ایمیل با موفقیت ارسال شد!")
    else:
        print("❌ خطا در ارسال ایمیل!")


def send_bulk_email(email_sender: ProfessionalEmailSender):
    """ارسال ایمیل انبوه"""
    print("\n📧 ارسال ایمیل انبوه")
    print("-" * 30)
    
    # دریافت اطلاعات SMTP
    smtp_config = get_smtp_config(email_sender)
    if not smtp_config:
        return
    
    # دریافت اطلاعات فرستنده
    sender_email = input("آدرس ایمیل فرستنده: ").strip()
    sender_name = input("نام فرستنده: ").strip()
    subject = input("موضوع ایمیل: ").strip()
    
    # بارگیری قالب
    template_path = input("مسیر فایل قالب HTML: ").strip()
    if not os.path.exists(template_path):
        print("❌ فایل قالب یافت نشد!")
        return
    
    html_template = email_sender.load_template(template_path)
    
    # بارگیری لیست گیرندگان
    recipients_file = input("مسیر فایل لیست گیرندگان (JSON): ").strip()
    if not os.path.exists(recipients_file):
        print("❌ فایل گیرندگان یافت نشد!")
        return
    
    try:
        with open(recipients_file, 'r', encoding='utf-8') as f:
            recipients = json.load(f)
    except Exception as e:
        print(f"❌ خطا در بارگیری فایل گیرندگان: {e}")
        return
    
    # تاخیر بین ارسال‌ها
    delay = int(input("تاخیر بین ارسال‌ها (ثانیه) [1]: ").strip() or "1")
    
    # ارسال انبوه
    stats = email_sender.bulk_send(
        smtp_config=smtp_config,
        sender_email=sender_email,
        sender_name=sender_name,
        recipients=recipients,
        subject=subject,
        html_template=html_template,
        delay=delay
    )


def get_smtp_config(email_sender: ProfessionalEmailSender) -> Dict:
    """دریافت تنظیمات SMTP از کاربر"""
    print("\n⚙️ تنظیمات SMTP:")
    
    # نمایش سرورهای از پیش تعریف شده
    servers = email_sender.get_smtp_servers()
    print("\nسرورهای موجود:")
    for key, server in servers.items():
        print(f"{key}: {server['name']}")
    
    server_choice = input("\nانتخاب سرور (یا 'custom' برای سفارشی): ").strip().lower()
    
    if server_choice in servers and server_choice != 'custom':
        smtp_config = servers[server_choice].copy()
    else:
        smtp_config = {
            'server': input("آدرس سرور SMTP: ").strip(),
            'port': int(input("پورت [587]: ").strip() or "587"),
            'security': input("نوع امنیت (tls/ssl/none) [tls]: ").strip().lower() or "tls"
        }
    
    smtp_config['username'] = input("نام کاربری: ").strip()
    smtp_config['password'] = input("رمز عبور: ").strip()
    
    return smtp_config


def setup_smtp(email_sender: ProfessionalEmailSender):
    """تنظیم و ذخیره پیکربندی SMTP"""
    print("\n⚙️ تنظیم سرور SMTP")
    print("-" * 30)
    
    smtp_config = get_smtp_config(email_sender)
    config_name = input("نام این پیکربندی: ").strip()
    
    # ذخیره در فایل تنظیمات
    current_config = email_sender.load_config()
    if 'smtp_configs' not in current_config:
        current_config['smtp_configs'] = {}
    
    current_config['smtp_configs'][config_name] = smtp_config
    
    if email_sender.save_config(current_config):
        print(f"✅ پیکربندی '{config_name}' ذخیره شد!")
    else:
        print("❌ خطا در ذخیره پیکربندی!")


def create_template():
    """ایجاد قالب ایمیل"""
    print("\n🎨 ایجاد قالب ایمیل")
    print("-" * 30)
    
    template_name = input("نام قالب: ").strip()
    
    # قالب پایه حرفه‌ای
    template_content = """<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{subject}}</title>
    <style>
        body {
            font-family: 'Tahoma', 'Arial', sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 600px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f4f4f4;
        }
        .container {
            background-color: #ffffff;
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
        .header h1 {
            color: #007bff;
            margin: 0;
        }
        .content {
            text-align: right;
        }
        .footer {
            text-align: center;
            margin-top: 30px;
            padding-top: 20px;
            border-top: 1px solid #eee;
            color: #666;
            font-size: 12px;
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
        .button:hover {
            background-color: #0056b3;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>{{company_name}}</h1>
        </div>
        
        <div class="content">
            <h2>{{greeting}} {{recipient_name}}،</h2>
            
            <p>{{main_message}}</p>
            
            {{#if_button}}
            <a href="{{button_link}}" class="button">{{button_text}}</a>
            {{/if_button}}
            
            <p>{{closing_message}}</p>
            
            <p>با احترام،<br>
            {{sender_name}}<br>
            {{sender_title}}</p>
        </div>
        
        <div class="footer">
            <p>این ایمیل از طرف {{company_name}} ارسال شده است.</p>
            <p>{{company_address}}</p>
        </div>
    </div>
</body>
</html>"""
    
    # ذخیره قالب
    template_path = f"templates/{template_name}.html"
    os.makedirs("templates", exist_ok=True)
    
    try:
        with open(template_path, 'w', encoding='utf-8') as f:
            f.write(template_content)
        print(f"✅ قالب در مسیر {template_path} ذخیره شد!")
        
        # ایجاد فایل متغیرها
        variables_example = {
            "subject": "موضوع ایمیل",
            "company_name": "نام شرکت شما",
            "recipient_name": "نام گیرنده",
            "greeting": "سلام",
            "main_message": "متن اصلی پیام شما",
            "button_text": "کلیک کنید",
            "button_link": "https://example.com",
            "closing_message": "پیام پایانی",
            "sender_name": "نام فرستنده",
            "sender_title": "سمت فرستنده",
            "company_address": "آدرس شرکت"
        }
        
        variables_path = f"templates/{template_name}_variables.json"
        with open(variables_path, 'w', encoding='utf-8') as f:
            json.dump(variables_example, f, ensure_ascii=False, indent=4)
        
        print(f"✅ فایل متغیرها در مسیر {variables_path} ذخیره شد!")
        
    except Exception as e:
        print(f"❌ خطا در ذخیره قالب: {e}")


def test_smtp_connection(email_sender: ProfessionalEmailSender):
    """تست اتصال SMTP"""
    print("\n🔍 تست اتصال SMTP")
    print("-" * 30)
    
    smtp_config = get_smtp_config(email_sender)
    
    try:
        if smtp_config.get('security') == 'ssl':
            context = ssl.create_default_context()
            server = smtplib.SMTP_SSL(smtp_config['server'], smtp_config['port'], context=context)
        else:
            server = smtplib.SMTP(smtp_config['server'], smtp_config['port'])
            if smtp_config.get('security') == 'tls':
                context = ssl.create_default_context()
                server.starttls(context=context)
        
        if smtp_config.get('username') and smtp_config.get('password'):
            server.login(smtp_config['username'], smtp_config['password'])
        
        server.quit()
        print("✅ اتصال به سرور SMTP موفقیت‌آمیز بود!")
        
    except Exception as e:
        print(f"❌ خطا در اتصال: {e}")


if __name__ == "__main__":
    main()