# Advanced XSS Scanner - ابزار کامل شناسایی و اکسپلویت باگ XSS

## ویژگی‌های کلیدی

### 🔍 Reconnaissance کامل
- **Web Crawling**: شناسایی خودکار URL ها و صفحات
- **Parameter Discovery**: کشف پارامترهای مخفی و پنهان
- **Form Analysis**: تحلیل کامل فرم‌ها و فیلدهای ورودی
- **Header Analysis**: بررسی هدرها و کوکی‌ها
- **Response Analysis**: تحلیل پاسخ‌ها برای نقاط تزریق

### 🛡️ WAF Detection & Bypass
- **شناسایی WAF**: تشخیص Cloudflare، Incapsula، Akamai، AWS WAF و سایر
- **Bypass Techniques**: 
  - Encoding variations (URL, HTML entities, Unicode, Base64)
  - Case manipulation
  - Comment injection
  - Parameter pollution
  - Header injection
  - Chunked encoding
  - Null byte injection
  - Unicode normalization

### 🎯 پشتیبانی از تمام انواع XSS
- **Reflected XSS**: تست کامل با WAF bypass
- **Stored XSS**: تست با custom popup verification
- **DOM-based XSS**: تست با browser automation
- **Blind XSS**: تست با callback server

### 🎨 Custom Popup System
- **عدم تداخل**: با popup های مرورگر تداخل نمی‌کند
- **اطلاعات کامل**: نمایش URL، زمان، کوکی‌ها و جزئیات
- **Screenshot**: گرفتن عکس از PoC
- **Unique ID**: شناسه منحصر به فرد برای هر popup

### 📊 گزارش‌گیری کامل
- **JSON Report**: گزارش کامل در فرمت JSON
- **Screenshot PoC**: عکس از اثبات مفهوم
- **WAF Analysis**: تحلیل WAF و روش‌های bypass
- **Detailed Logging**: لاگ کامل عملیات

## نصب و راه‌اندازی

### پیش‌نیازها
```bash
# Python 3.8+
sudo apt update
sudo apt install python3 python3-pip

# Chrome/Chromium
sudo apt install chromium-browser

# ChromeDriver
pip install webdriver-manager
```

### نصب dependencies
```bash
pip install -r requirements.txt
```

## استفاده

### استفاده پایه
```bash
python3 xss_scanner.py https://example.com
```

### استفاده پیشرفته
```bash
# با گزارش سفارشی
python3 xss_scanner.py https://example.com -o custom_report.json

# بدون crawling
python3 xss_scanner.py https://example.com --no-crawl

# با callback URL برای Blind XSS
python3 xss_scanner.py https://example.com --callback-url http://your-server.com/callback

# با verbose output
python3 xss_scanner.py https://example.com -v
```

### استفاده برنامه‌نویسی
```python
from xss_scanner import XSSScanner

# تنظیمات
options = {
    'crawl': True,
    'callback_url': 'http://your-server.com/callback'
}

# ایجاد scanner
scanner = XSSScanner('https://example.com', options)

# اجرای اسکن
results = scanner.run_scan()

# ذخیره گزارش
scanner.save_report(results, 'my_report.json')
```

## انواع XSS قابل تست

### ✅ کاملاً قابل پیاده‌سازی:
1. **Reflected XSS**: ✅
2. **Stored XSS**: ✅  
3. **DOM-based XSS**: ✅
4. **Blind XSS**: ✅

### ⚠️ پیاده‌سازی محدود:
1. **Self-XSS**: نیاز به تعامل کاربر
2. **Mutation XSS**: پیچیده و browser-specific

## ویژگی‌های پیشرفته

### Context-Aware Payloads
- **HTML Context**: `<script>`, `<img>`, `<svg>`, `<iframe>`
- **Attribute Context**: `onmouseover`, `onfocus`, `onerror`
- **JavaScript Context**: `;alert()`, `';alert()`, `";alert()`
- **CSS Context**: `expression()`, `url()`, `@import`
- **URL Context**: `javascript:`, `data:`, `vbscript:`

### WAF Bypass Techniques
- **Cloudflare**: Encoding, case variation, comment injection
- **Incapsula**: Double encoding, null bytes, chunked encoding
- **Akamai**: Header injection, parameter fragmentation
- **AWS WAF**: Encoding variations, case manipulation
- **ModSecurity**: Unicode normalization, comment bypass

### Custom Popup Features
- **Visual Confirmation**: تایید بصری باگ
- **No Browser Conflicts**: عدم تداخل با alert های مرورگر
- **Detailed Information**: اطلاعات کامل صفحه و زمان
- **Screenshot Capability**: قابلیت گرفتن عکس
- **Unique Identification**: شناسه منحصر به فرد

## نمونه خروجی

### گزارش JSON
```json
{
  "target": "https://example.com",
  "timestamp": "2024-01-15T10:30:00",
  "summary": {
    "total_vulnerabilities": 3,
    "reflected_xss": 2,
    "stored_xss": 1,
    "dom_xss": 0,
    "blind_xss": 0
  },
  "vulnerabilities": [
    {
      "type": "Reflected XSS (WAF Bypassed)",
      "parameter": "search",
      "payload": "<ScRiPt>alert(\"XSS\")</ScRiPt>",
      "waf_type": "cloudflare",
      "url": "https://example.com?search=<ScRiPt>alert(\"XSS\")</ScRiPt>",
      "poc_screenshot": "/tmp/xss_poc_1642248600.png"
    }
  ]
}
```

### خروجی کنسول
```
=== XSS Scan Summary ===
Target: https://example.com
Total Vulnerabilities: 3
Reflected XSS: 2
Stored XSS: 1
DOM XSS: 0
Blind XSS: 0

=== Vulnerabilities Found ===
1. Reflected XSS (WAF Bypassed) - search parameter
2. Stored XSS - comment field
3. Reflected XSS - user parameter
```

## نکات امنیتی

⚠️ **هشدار**: این ابزار فقط برای تست امنیتی مجاز استفاده شود. استفاده غیرمجاز از این ابزار ممنوع است.

### توصیه‌ها:
- فقط روی سیستم‌های خود یا با مجوز کتبی استفاده کنید
- قبل از استفاده، قوانین محلی را بررسی کنید
- نتایج را محرمانه نگه دارید
- گزارش‌های یافت شده را به مالک سایت گزارش دهید

## عیب‌یابی

### مشکلات رایج:
1. **ChromeDriver Error**: `pip install webdriver-manager`
2. **Permission Denied**: `chmod +x xss_scanner.py`
3. **Import Error**: `pip install -r requirements.txt`

### لاگ‌ها:
- لاگ‌ها در فایل `xss_scanner.log` ذخیره می‌شوند
- برای debug بیشتر از `-v` استفاده کنید

## مشارکت

برای مشارکت در توسعه این ابزار:
1. Fork کنید
2. Branch جدید بسازید
3. تغییرات را commit کنید
4. Pull Request ارسال کنید

## مجوز

این پروژه تحت مجوز MIT منتشر شده است.

---

**نکته**: این ابزار برای اهداف آموزشی و تست امنیتی طراحی شده است. استفاده مسئولانه داشته باشید.