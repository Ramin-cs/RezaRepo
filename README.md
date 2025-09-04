# 🚀 سیستم ارسال ایمیل حرفه‌ای
# Professional Email Sender System

یک سیستم کامل و حرفه‌ای برای ارسال ایمیل‌های تک یا انبوه با قابلیت‌های پیشرفته برای جلوگیری از رفتن ایمیل‌ها به پوشه اسپم.

## ✨ ویژگی‌ها

### 🎯 ویژگی‌های اصلی
- **ارسال ایمیل تکی و انبوه** با قابلیت تنظیم تاخیر
- **پشتیبانی از قالب‌های HTML زیبا** با امکان جایگذاری متغیرها
- **هدرهای پیشرفته و حرفه‌ای** برای جلوگیری از اسپم
- **پشتیبانی از انواع سرورهای SMTP** (Gmail, Outlook, Yahoo, Office365, Zoho و سفارشی)
- **اعتبارسنجی آدرس‌های ایمیل** قبل از ارسال
- **گزارش‌گیری کامل** از وضعیت ارسال‌ها

### 🔒 امنیت و قابلیت اعتماد
- **اتصالات امن SSL/TLS**
- **احراز هویت پیشرفته**
- **هدرهای ضد اسپم**
- **Message-ID منحصر به فرد**
- **SPF و DKIM ready**

### 🎨 قالب‌سازی
- **قالب‌های HTML واکنش‌گرا**
- **سیستم متغیرهای قابل جایگذاری**
- **قالب‌های از پیش طراحی شده**
- **پشتیبانی از CSS پیشرفته**

## 📦 نصب و راه‌اندازی

### پیش‌نیازها
- Python 3.6 یا بالاتر
- دسترسی به سرور SMTP

### نصب
```bash
git clone <repository-url>
cd professional-email-sender
pip install -r requirements.txt
```

### راه‌اندازی سریع
```bash
python email_sender.py
```

## 🚀 نحوه استفاده

### 1. ارسال ایمیل تکی

```python
from email_sender import ProfessionalEmailSender

# ایجاد نمونه
email_sender = ProfessionalEmailSender()

# تنظیمات SMTP
smtp_config = {
    'server': 'smtp.gmail.com',
    'port': 587,
    'security': 'tls',
    'username': 'your_email@gmail.com',
    'password': 'your_app_password'
}

# ارسال ایمیل
success = email_sender.send_email(
    smtp_config=smtp_config,
    sender_email='your_email@gmail.com',
    sender_name='نام شما',
    recipient_email='recipient@example.com',
    recipient_name='نام گیرنده',
    subject='موضوع ایمیل',
    html_content='<h1>سلام!</h1><p>این یک ایمیل تست است.</p>',
    company_name='نام شرکت',
    department='بخش IT'
)
```

### 2. استفاده از قالب‌ها

```python
# بارگیری قالب
html_content = email_sender.load_template(
    'templates/professional.html',
    variables={
        'recipient_name': 'احمد محمدی',
        'company_name': 'شرکت تست',
        'main_message': 'پیام اصلی شما',
        'sender_name': 'تیم پشتیبانی'
    }
)

# ارسال با قالب
email_sender.send_email(
    smtp_config=smtp_config,
    sender_email='sender@example.com',
    sender_name='فرستنده',
    recipient_email='recipient@example.com',
    recipient_name='گیرنده',
    subject='موضوع',
    html_content=html_content
)
```

### 3. ارسال انبوه

```python
# لیست گیرندگان
recipients = [
    {
        'email': 'user1@example.com',
        'name': 'کاربر اول',
        'variables': {
            'first_name': 'احمد',
            'special_offer': '20% تخفیف'
        }
    },
    {
        'email': 'user2@example.com',
        'name': 'کاربر دوم',
        'variables': {
            'first_name': 'فاطمه',
            'special_offer': '15% تخفیف'
        }
    }
]

# قالب با متغیرها
html_template = '''
<h1>سلام {{first_name}} عزیز!</h1>
<p>پیشنهاد ویژه: {{special_offer}}</p>
'''

# ارسال انبوه
stats = email_sender.bulk_send(
    smtp_config=smtp_config,
    sender_email='sender@example.com',
    sender_name='تیم بازاریابی',
    recipients=recipients,
    subject='پیشنهاد ویژه برای {{first_name}}',
    html_template=html_template,
    delay=2  # تاخیر 2 ثانیه بین ارسال‌ها
)

print(f"ارسال شده: {stats['sent']}, ناموفق: {stats['failed']}")
```

## 📁 ساختار پروژه

```
professional-email-sender/
├── email_sender.py          # فایل اصلی سیستم
├── email_config.json        # فایل تنظیمات
├── requirements.txt         # وابستگی‌ها
├── README.md               # راهنمای استفاده
├── templates/              # پوشه قالب‌ها
│   ├── professional.html   # قالب حرفه‌ای
│   └── newsletter.html     # قالب خبرنامه
└── examples/               # مثال‌های کاربردی
    ├── single_email_example.py
    └── bulk_email_example.py
```

## ⚙️ تنظیمات SMTP

### Gmail
```json
{
    "server": "smtp.gmail.com",
    "port": 587,
    "security": "tls",
    "username": "your_email@gmail.com",
    "password": "your_app_password"
}
```

**نکته:** برای Gmail باید از App Password استفاده کنید.

### Outlook/Hotmail
```json
{
    "server": "smtp-mail.outlook.com",
    "port": 587,
    "security": "tls",
    "username": "your_email@outlook.com",
    "password": "your_password"
}
```

### Yahoo Mail
```json
{
    "server": "smtp.mail.yahoo.com",
    "port": 587,
    "security": "tls",
    "username": "your_email@yahoo.com",
    "password": "your_app_password"
}
```

### Office 365
```json
{
    "server": "smtp.office365.com",
    "port": 587,
    "security": "tls",
    "username": "your_email@yourdomain.com",
    "password": "your_password"
}
```

## 🎨 قالب‌سازی

### متغیرهای قابل استفاده در قالب‌ها

| متغیر | توضیح | مثال |
|--------|--------|--------|
| `{{recipient_name}}` | نام گیرنده | احمد محمدی |
| `{{sender_name}}` | نام فرستنده | تیم پشتیبانی |
| `{{company_name}}` | نام شرکت | شرکت نمونه |
| `{{subject}}` | موضوع ایمیل | اطلاعیه مهم |
| `{{main_message}}` | پیام اصلی | محتوای اصلی ایمیل |
| `{{button_text}}` | متن دکمه | کلیک کنید |
| `{{button_link}}` | لینک دکمه | https://example.com |

### ایجاد قالب سفارشی

1. فایل HTML جدید در پوشه `templates` ایجاد کنید
2. از متغیرهای `{{variable_name}}` استفاده کنید
3. CSS inline یا در تگ `<style>` اضافه کنید
4. قالب را با `load_template()` بارگیری کنید

## 🛡️ جلوگیری از اسپم

### هدرهای خودکار
- `Message-ID` منحصر به فرد
- `Date` و `MIME-Version` استاندارد
- `X-Mailer` و `X-Priority`
- `List-Unsubscribe` برای لغو اشتراک
- `Return-Path` و `Reply-To`

### توصیه‌ها
1. **محتوای با کیفیت:** از کلمات اسپم خودداری کنید
2. **تعادل متن/تصویر:** متن کافی در ایمیل داشته باشید
3. **لینک‌های معتبر:** از لینک‌های کوتاه‌شده زیاد استفاده نکنید
4. **تنظیمات DNS:** SPF, DKIM و DMARC را تنظیم کنید
5. **فرکانس ارسال:** تاخیر مناسب بین ارسال‌ها رعایت کنید

## 📊 گزارش‌گیری

سیستم گزارش کاملی از وضعیت ارسال‌ها ارائه می‌دهد:

```python
stats = {
    'total': 100,      # کل ایمیل‌ها
    'sent': 95,        # ارسال موفق
    'failed': 5,       # ارسال ناموفق
    'errors': [...]    # لیست خطاها
}
```

## 🔧 عیب‌یابی

### خطاهای رایج

#### خطای احراز هویت
```
SMTPAuthenticationError: (535, 'Authentication failed')
```
**راه‌حل:** 
- برای Gmail از App Password استفاده کنید
- 2FA را فعال کرده و App Password تولید کنید

#### خطای اتصال
```
SMTPServerDisconnected: Connection unexpectedly closed
```
**راه‌حل:**
- تنظیمات فایروال را بررسی کنید
- پورت و سرور را دوباره چک کنید

#### ایمیل به اسپم می‌رود
**راه‌حل:**
- محتوای ایمیل را بهبود دهید
- SPF/DKIM تنظیم کنید
- از سرور معتبر استفاده کنید

## 🤝 مشارکت

برای مشارکت در بهبود این پروژه:

1. Repository را Fork کنید
2. Branch جدید ایجاد کنید
3. تغییرات را Commit کنید
4. Pull Request ارسال کنید

## 📄 مجوز

این پروژه تحت مجوز MIT منتشر شده است.

## 📞 پشتیبانی

برای سوالات و پشتیبانی:
- Issue در GitHub ایجاد کنید
- ایمیل به: support@example.com

---

**توجه:** این سیستم برای اهداف قانونی و مشروع طراحی شده است. از آن برای ارسال اسپم یا فیشینگ استفاده نکنید.