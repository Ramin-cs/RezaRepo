# Advanced XSS Scanner
## ابزار پیشرفته تشخیص XSS

یک ابزار حرفه‌ای و پیشرفته برای تشخیص آسیب‌پذیری‌های Cross-Site Scripting (XSS) که با الهام از `store.xss0r.com` طراحی شده است.

## ویژگی‌های کلیدی

### 🔍 **Crawling و Reconnaissance عمیق**
- شناسایی خودکار نقاط تست (پارامترها، فرم‌ها، هدرها)
- Crawling عمیق لینک‌های داخلی تا عمق قابل تنظیم
- تحلیل فایل‌های JavaScript برای DOM XSS
- شناسایی endpoint های مخفی

### 🎯 **تست‌های پیشرفته**
- **Context-Aware Testing**: تشخیص context و استفاده از پیلود مناسب
- **Fuzzing پیشرفته**: تست کاراکترهای مسدود و فیلتر شده
- **WAF Bypass**: تکنیک‌های مختلف دور زدن Web Application Firewall
- **Multi-Method Testing**: تست GET و POST
- **Header Testing**: تست هدرهای HTTP برای XSS
- **CRLF Injection**: تست تزریق CRLF در تمام پارامترها

### 🛡️ **امنیت و مخفی‌کاری**
- Rate limiting برای جلوگیری از تشخیص WAF
- User-Agent های متنوع و تصادفی
- تاخیر قابل تنظیم بین درخواست‌ها
- پردازش موازی با کنترل تعداد thread

### ✅ **سیستم تایید باگ**
- **Popup مخصوص**: استفاده از popup منحصر به فرد برای تایید
- **Selenium Integration**: تایید باگ با WebDriver
- **Screenshot**: گرفتن عکس از باگ‌های تایید شده
- **امتیازبندی هوشمند**: سیستم امتیازدهی بر اساس نوع و تاثیر باگ

### 📊 **گزارش‌گیری حرفه‌ای**
- گزارش HTML زیبا و کامل
- گزارش JSON برای پردازش خودکار
- نمایش آمار کامل اسکن
- ذخیره اسکرین‌شات باگ‌های تایید شده

## نصب و راه‌اندازی

### پیش‌نیازها
- Python 3.7+
- Google Chrome Browser
- ChromeDriver

### نصب خودکار
```bash
# دانلود فایل‌ها
git clone [repository-url]
cd advanced-xss-scanner

# اجرای اسکریپت نصب
python setup.py
```

### نصب دستی
```bash
# نصب پکیج‌های Python
pip install -r requirements.txt

# نصب ChromeDriver (Linux)
sudo apt-get install chromium-chromedriver

# نصب ChromeDriver (macOS)
brew install chromedriver

# نصب ChromeDriver (Windows)
# دانلود از https://chromedriver.chromium.org/
```

## استفاده

### استفاده پایه
```bash
python advanced_xss_scanner.py -u https://example.com
```

### استفاده پیشرفته
```bash
# اسکن عمیق با تنظیمات سفارشی
python advanced_xss_scanner.py -u https://example.com -d 5 -t 10 --delay 2

# اسکن با سرور Stored XSS
python advanced_xss_scanner.py -u https://example.com --stored-server http://your-server.com

# نمایش راهنما
python advanced_xss_scanner.py -h
```

### پارامترهای خط فرمان
- `-u, --url`: URL هدف (اجباری)
- `-d, --depth`: حداکثر عمق crawling (پیش‌فرض: 3)
- `-t, --threads`: تعداد thread ها (پیش‌فرض: 5)
- `--delay`: تاخیر بین درخواست‌ها به ثانیه (پیش‌فرض: 1.0)
- `--stored-server`: سرور برای تست Stored/Blind XSS

## انواع آسیب‌پذیری‌های قابل تشخیص

### 1. Reflected XSS
- تست پارامترهای URL
- تست فیلدهای فرم
- تست هدرهای HTTP

### 2. Stored XSS
- تست فرم‌هایی که داده ذخیره می‌کنند
- بررسی بازتاب در صفحات مختلف

### 3. DOM-based XSS
- تحلیل کد JavaScript
- تست پارامترهای پردازش شده در سمت کلاینت

### 4. CRLF Injection
- تست تزریق در هدرهای HTTP
- بررسی امکان تزریق Set-Cookie

## Context های پشتیبانی شده

### HTML Context
```html
<div>USER_INPUT</div>
```
پیلودها: `<script>`, `<img>`, `<svg>`, و غیره

### Attribute Context
```html
<input value="USER_INPUT">
```
پیلودها: `" onmouseover="`, `" onfocus="`, و غیره

### JavaScript Context
```html
<script>var data = 'USER_INPUT';</script>
```
پیلودها: `'; alert(1); //`, `</script><script>`, و غیره

### URL Context
```html
<a href="USER_INPUT">
```
پیلودها: `javascript:alert(1)`, `data:text/html,`, و غیره

## تکنیک‌های WAF Bypass

- **Case Manipulation**: `<ScRiPt>alert(1)</ScRiPt>`
- **URL Encoding**: `%3Cscript%3Ealert(1)%3C/script%3E`
- **HTML Entities**: `&lt;script&gt;alert(1)&lt;/script&gt;`
- **Alternative Tags**: `<img>`, `<svg>`, `<iframe>`
- **Event Handlers**: `onload`, `onerror`, `onfocus`
- **JavaScript Alternatives**: `eval()`, `setTimeout()`

## سیستم امتیازبندی

### معیارهای امتیازدهی
- **Reflected XSS**: 20 امتیاز
- **Stored XSS**: 25 امتیاز
- **Header-based XSS**: 15 امتیاز
- **CRLF Injection**: 15 امتیاز

### شرایط تایید باگ
1. **اجرا در Context درست**: پیلود باید در context مناسب اجرا شود
2. **نمایش Popup مخصوص**: popup با signature منحصر به فرد نمایش داده شود
3. **تایید با Selenium**: باگ توسط WebDriver تایید شود
4. **Screenshot**: عکس از باگ تایید شده گرفته شود

## فایل‌های خروجی

### گزارش HTML
- گزارش کامل و زیبا
- آمار تفصیلی اسکن
- نمایش تمام باگ‌های یافت شده
- لینک به اسکرین‌شات‌ها

### گزارش JSON
- داده‌های خام برای پردازش
- قابل import در سایر ابزارها
- شامل تمام جزئیات تکنیکی

### اسکرین‌شات‌ها
- عکس از هر باگ تایید شده
- ذخیره در پوشه `screenshots/`
- نام‌گذاری منظم و قابل ردیابی

## مثال خروجی

```
╔══════════════════════════════════════════════════════════════╗
║                    Advanced XSS Scanner                      ║
║                  ابزار پیشرفته تشخیص XSS                    ║
╠══════════════════════════════════════════════════════════════╣
║ Target: https://example.com                                  ║
║ Max Depth: 3   | Threads: 5   | Delay: 1.0s                 ║
╚══════════════════════════════════════════════════════════════╝

============================================================
Phase 1: شناسایی نقاط تست و Crawling عمیق
============================================================

🔍 Crawling: https://example.com (depth: 0)
  ✓ Form found: /contact (3 inputs)
  ✓ Parameter found: search

============================================================
Phase 2: کشف پیشرفته و Fuzzing
============================================================

🔍 Testing URL Parameters...
  Testing parameter: search in https://example.com

✓ CONFIRMED XSS: search in https://example.com
  Payload: <script>alert("XSS_SCANNER_CONFIRMED_abc123")</script>
  Score: 20/20
  📸 Screenshot saved: screenshots/xss_param_search_1.png
```

## توجهات امنیتی

⚠️ **هشدار مهم**: این ابزار فقط برای تست امنیت سایت‌های مجاز خودتان استفاده کنید. استفاده غیرمجاز از این ابزار ممکن است مغایر با قوانین محلی و بین‌المللی باشد.

## سازگاری

- ✅ Linux (Ubuntu, CentOS, Debian)
- ✅ Windows (10, 11)
- ✅ macOS (Big Sur, Monterey, Ventura)

## لایسنس

این پروژه تحت لایسنس MIT منتشر شده است.

## حمایت و گزارش باگ

برای گزارش باگ یا درخواست ویژگی جدید، لطفاً یک issue ایجاد کنید.

---

**Happy Hunting! 🔍🛡️**