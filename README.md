# Professional Reconnaissance Tool

ابزار حرفه‌ای ریکان برای باگ بانتی هانترها - کشف ساب‌دامین و پارامتر با تکنیک‌های پیشرفته

## ویژگی‌ها

### کشف ساب‌دامین
- **DNS Brute-force**: حمله DNS با کارایی بالا
- **Certificate Transparency**: استخراج از لاگ‌های CT
- **DNS Zone Transfer**: تست انتقال زون DNS
- **Wildcard Detection**: تشخیص و فیلتر کردن wildcard ها

### کشف پارامتر
- **Parameter Fuzzing**: فازینگ هوشمند پارامترها
- **JavaScript Analysis**: استخراج پارامتر از فایل‌های JS
- **Error-based Discovery**: کشف بر اساس خطاها
- **Baseline Comparison**: مقایسه با پاسخ پایه

## نصب و راه‌اندازی

```bash
# نصب وابستگی‌ها
pip3 install requests dnspython

# اجرای ابزار
python3 professional_recon.py -t example.com
```

## استفاده

### حالت پیشفرض (هر دو فاز)
```bash
python3 professional_recon.py -t example.com
python3 professional_recon.py -t https://example.com
```

### فازهای جداگانه
```bash
# فقط ساب‌دامین
python3 professional_recon.py -t example.com --subdomains-only

# فقط پارامتر
python3 professional_recon.py -t https://example.com --parameters-only
```

### گزینه‌های پیشرفته
```bash
# تنظیم thread و timeout
python3 professional_recon.py -t example.com --threads 100 --timeout 15

# انتخاب اندازه wordlist
python3 professional_recon.py -t example.com --wordlist large

# ذخیره نتایج
python3 professional_recon.py -t example.com -o results --format txt
```

## مثال خروجی

```
[SUBDOMAIN RESULTS]
Found 7 subdomains:
  • api.example.com
  • www.example.com
  • admin.example.com
  • beta.example.com

[PARAMETER RESULTS]
Found 25 parameters:
  • id
  • user
  • search
  • token
  • api_key
```

## تنظیمات

- **Threads**: تعداد thread ها (پیشفرض: 50)
- **Timeout**: زمان انتظار (پیشفرض: 10 ثانیه)
- **Wordlist**: اندازه wordlist (small/medium/large)
- **Format**: فرمت خروجی (json/txt)

## نکات امنیتی

⚠️ **هشدار**: فقط روی سیستم‌هایی که مالک آن هستید یا مجوز تست دارید استفاده کنید.

## ویژگی‌های تکنیکی

- **Cross-platform**: ویندوز و لینوکس
- **Multi-threaded**: پردازش موازی
- **Modular**: معماری ماژولار
- **Professional**: خروجی حرفه‌ای

---
**Happy Bug Hunting! 🎯**