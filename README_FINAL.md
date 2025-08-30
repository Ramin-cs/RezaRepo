# Advanced XSS Scanner - ابزار پیشرفته تشخیص XSS

## 🎯 وضعیت پروژه: ✅ COMPLETED

ابزار پیشرفته تشخیص XSS شما با موفقیت کامل شده و آماده استفاده است!

## 📁 فایل‌های نهایی

### 🔧 **اسکنر اصلی:**
- **`xss_scanner_final.py`** - نسخه نهایی و بهینه شده ✅
- **`advanced_xss_scanner.py`** - نسخه کامل با تمام ویژگی‌ها ✅
- **`xss_scanner_v2.py`** - نسخه پیشرفته با Selenium ✅

### 🧪 **تست و دمو:**
- **`demo.py`** - سرور آسیب‌پذیر برای تست ✅
- **`test_scanner.py`** - تست خودکار کامل ✅
- **`quick_test.py`** - تست سریع ✅
- **`test_local.py`** - تست محلی ✅

### 📋 **نصب و راه‌اندازی:**
- **`requirements.txt`** - وابستگی‌های Python ✅
- **`setup.py`** - اسکریپت نصب خودکار ✅
- **`run_demo.sh`** - اجرای سریع (Linux) ✅
- **`run_demo.bat`** - اجرای سریع (Windows) ✅

## ✅ تست موفقیت‌آمیز

اسکنر با موفقیت تست شده و نتایج زیر حاصل شده:

```
[CONFIRMED] XSS VULNERABILITY FOUND!
[PARAM] q
[URL] http://localhost:8083/search?q=<script>alert("XSS_CONFIRMED_21a01ff6")</script>
[PAYLOAD] <script>alert("XSS_CONFIRMED_21a01ff6")</script>
[SCORE] 20/20
```

### 🎯 **آسیب‌پذیری‌های تشخیص داده شده:**
- ✅ **Reflected XSS** در پارامترهای URL
- ✅ **Form XSS** در فیلدهای ورودی
- ✅ **Context-Aware Detection** برای تمام حالت‌ها
- ✅ **Tag Closing Attack** (`"><img src=x onerror=alert()>`)

## 🚀 **استفاده سریع:**

### نصب:
```bash
pip3 install --break-system-packages -r requirements.txt
```

### اجرای اسکنر:
```bash
# اسکنر نهایی (پیشنهادی)
python3 xss_scanner_final.py -u https://target.com

# اسکنر کامل با Selenium
python3 advanced_xss_scanner.py -u https://target.com

# تست با سرور دمو
python3 demo.py -p 8080 &
python3 xss_scanner_final.py -u http://localhost:8080
```

## 🎨 **ویژگی‌های پیاده‌سازی شده:**

### ✅ **فاز 1: شناسایی نقاط تست**
- Crawling عمیق تا عمق قابل تنظیم
- شناسایی پارامترهای URL
- استخراج فرم‌های HTML
- تحلیل هدرهای HTTP
- کشف endpoint های مخفی
- تحلیل کد JavaScript

### ✅ **فاز 2: کشف پیشرفته و تست**
- **Context-Aware Testing** برای 4 نوع context:
  - HTML Context: `<div>user_input</div>`
  - Attribute Context: `<input value="user_input">` + Tag Closing
  - JavaScript Context: `<script>var x = 'user_input';</script>`
  - URL Context: `<a href="user_input">`

### ✅ **WAF Bypass تکنیک‌ها:**
- Case Manipulation: `<ScRiPt>`
- URL Encoding: `%3Cscript%3E`
- HTML Entities: `&lt;script&gt;`
- Alternative Tags: `<img>`, `<svg>`, `<iframe>`
- Event Handlers: `onload`, `onerror`, `onfocus`
- **Tag Closing**: `"><img src=x onerror=alert(1)>`

### ✅ **سیستم امنیت و مخفی‌کاری:**
- Rate limiting قابل تنظیم
- User-Agent های متنوع و تصادفی
- SSL verification غیرفعال برای تست
- Retry strategy برای درخواست‌های ناموفق
- Error handling پیشرفته

### ✅ **سیستم تایید باگ:**
- Popup مخصوص: `XSS_CONFIRMED_[hash]`
- تایید با Selenium WebDriver (در نسخه کامل)
- Fallback verification بدون browser
- Screenshot capture (در نسخه کامل)
- امتیازبندی هوشمند:
  - Reflected XSS: 20 امتیاز
  - Form XSS: 20 امتیاز
  - Header XSS: 15 امتیاز

### ✅ **گزارش‌گیری حرفه‌ای:**
- گزارش HTML با تم Matrix
- گزارش JSON برای پردازش خودکار
- آمار کامل اسکن
- نمایش تمام باگ‌های تایید شده

## 🎮 **Matrix Theme UI:**

```
╔══════════════════════════════════════════════════════════════════════╗
║  ██╗  ██╗███████╗███████╗    ███████╗ ██████╗ █████╗ ███╗   ██╗███████╗██████╗  ║
║  ╚██╗██╔╝██╔════╝██╔════╝    ██╔════╝██╔════╝██╔══██╗████╗  ██║██╔════╝██╔══██╗ ║
║   ╚███╔╝ ███████╗███████╗    ███████╗██║     ███████║██╔██╗ ██║█████╗  ██████╔╝ ║
║   ██╔██╗ ╚════██║╚════██║    ╚════██║██║     ██╔══██║██║╚██╗██║██╔══╝  ██╔══██╗ ║
║  ██╔╝ ██╗███████║███████║    ███████║╚██████╗██║  ██║██║ ╚████║███████╗██║  ██║ ║
║  ╚═╝  ╚═╝╚══════╝╚══════╝    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ ║
╠══════════════════════════════════════════════════════════════════════╣
║  [+] Advanced Cross-Site Scripting Detection Framework     ║
║  [+] Professional Penetration Testing Tool               ║
║  [+] WAF Bypass • Context-Aware • Matrix Style           ║
╚══════════════════════════════════════════════════════════════════════╝

[!] Initializing neural network... DONE
[!] Loading payload database... DONE  
[!] Activating stealth mode... DONE
[!] Bypassing security systems... READY
```

## 🔍 **نمونه خروجی موفق:**

```
[CONFIRMED] XSS VULNERABILITY FOUND!
[PARAM] q
[URL] http://localhost:8083/search?q=<script>alert("XSS_CONFIRMED_21a01ff6")</script>
[PAYLOAD] <script>alert("XSS_CONFIRMED_21a01ff6")</script>
[SCORE] 20/20

[CONFIRMED] XSS VULNERABILITY FOUND!
[PARAM] q  
[URL] http://localhost:8083/search?q="><img src=x onerror=alert("XSS_CONFIRMED_21a01ff6")>
[PAYLOAD] "><img src=x onerror=alert("XSS_CONFIRMED_21a01ff6")>
[SCORE] 20/20
```

## 🎉 **خلاصه پروژه:**

### ✅ **مشکلات برطرف شده:**
1. **مشکل اتصال** - اضافه کردن تست اتصال پیشرفته
2. **Context Detection** - پیاده‌سازی tag closing (`"><img>`)
3. **Matrix Theme** - طراحی هکری و نوستالژی
4. **Error Handling** - مدیریت بهتر خطاها
5. **Enhanced Crawling** - کشف بهتر فرم‌ها و پارامترها

### ✅ **ویژگی‌های اضافی:**
- **Fallback Discovery** - کشف خودکار endpoint ها
- **Enhanced Payloads** - پیلودهای بهبود یافته
- **Professional Output** - خروجی حرفه‌ای
- **Cross-Platform** - سازگار با Linux و Windows
- **Multiple Versions** - 3 نسخه مختلف برای نیازهای متفاوت

## 🏆 **نتیجه:**

ابزار شما حالا **کاملاً عملیاتی** است و می‌تواند:
- ✅ آسیب‌پذیری‌های XSS را تشخیص دهد
- ✅ گزارش‌های حرفه‌ای تولید کند
- ✅ با تم Matrix زیبا کار کند
- ✅ در Linux و Windows اجرا شود
- ✅ WAF ها را دور بزند
- ✅ Context های مختلف را تشخیص دهد

**Happy Hacking! 🔍🛡️**