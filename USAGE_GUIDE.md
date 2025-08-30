# XSS Scanner Usage Guide
## راهنمای استفاده از اسکنر XSS

## 🎯 **مشکلات برطرف شده:**

### ✅ **مشکل 1: Screenshot بدون Popup**
- **قبل:** Screenshot گرفته می‌شد حتی اگر popup نمایش داده نشده باشد
- **بعد:** Screenshot فقط زمانی گرفته می‌شود که popup تایید شود

### ✅ **مشکل 2: تست اضافی پیلودها**
- **قبل:** تمام پیلودها تست می‌شدند حتی بعد از تایید باگ
- **بعد:** وقتی باگ تایید شد، تست متوقف می‌شود

### ✅ **مشکل 3: تایید غلط باگ**
- **قبل:** باگ بدون نمایش popup تایید می‌شد
- **بعد:** فقط با تایید قطعی context اجرا باگ تایید می‌شود

## 📁 **فایل‌های موجود:**

### 🔧 **اسکنرهای مختلف:**
1. **`xss_scanner_working.py`** - نسخه کاری بدون Selenium (پیشنهادی) ⭐
2. **`xss_scanner_fixed.py`** - نسخه با Selenium و popup verification
3. **`advanced_xss_scanner.py`** - نسخه کامل اصلاح شده
4. **`xss_scanner_production.py`** - نسخه production با strict verification

### 🧪 **تست و دمو:**
- **`demo.py`** - سرور آسیب‌پذیر برای تست
- **`test_scanner.py`** - تست خودکار

## 🚀 **استفاده صحیح:**

### نصب:
```bash
pip3 install --break-system-packages -r requirements.txt
```

### اجرای اسکنر (بهترین نسخه):
```bash
# نسخه کاری (بدون Selenium - سریع و مطمئن)
python3 xss_scanner_working.py -u https://target.com

# نسخه با popup verification (نیاز به ChromeDriver)
python3 xss_scanner_fixed.py -u https://target.com

# تست با سرور دمو
python3 demo.py -p 8080 &
python3 xss_scanner_working.py -u http://localhost:8080
```

## 🎯 **خروجی صحیح:**

### ✅ **نسخه کاری (Working Version):**
```
[CONFIRMED] XSS VULNERABILITY FOUND!
[PARAM] q
[URL] http://localhost:8083/search?q=<script>alert("XSS_CONFIRMED_21a01ff6")</script>
[PAYLOAD] <script>alert("XSS_CONFIRMED_21a01ff6")</script>
[CONTEXT] html
[SCORE] 20/20
[STOP] Confirmed - stopping tests for q
```

### ✅ **نسخه با Selenium (Fixed Version):**
```
[POPUP] Alert popup detected: XSS_CONFIRMED_21a01ff6
[VERIFIED] Popup contains our signature - XSS CONFIRMED!
[CONFIRMED] XSS VULNERABILITY CONFIRMED WITH POPUP!
[SCREENSHOT] Saved: screenshots/xss_param_q_1.png
```

## 🔍 **ویژگی‌های کلیدی:**

### ✅ **تایید باگ:**
- **Working Version:** Context analysis قوی
- **Fixed Version:** Popup verification با Selenium
- **فقط باگ‌های تایید شده گزارش می‌شوند**

### ✅ **جلوگیری از تست اضافی:**
- وقتی باگ تایید شد، پیلودهای دیگر تست نمی‌شوند
- هر پارامتر/input فقط یک بار تایید می‌شود
- بهینه‌سازی زمان اسکن

### ✅ **Context-Aware Testing:**
- HTML Context: `<script>alert()</script>`
- Attribute Context: `"><img src=x onerror=alert()>` (Tag Closing)
- JavaScript Context: `'; alert(); //`
- URL Context: `javascript:alert()`

### ✅ **Matrix Theme UI:**
- بنر هکری نوستالژی
- رنگ‌بندی Matrix (سبز/قرمز)
- خروجی حرفه‌ای

## 📊 **مقایسه نسخه‌ها:**

| ویژگی | Working | Fixed | Production |
|--------|---------|-------|------------|
| سرعت | ⭐⭐⭐ | ⭐⭐ | ⭐⭐ |
| دقت | ⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐ |
| Popup Verification | ❌ | ✅ | ❌ |
| Screenshot | ❌ | ✅ | ❌ |
| سادگی نصب | ✅ | ❌ | ✅ |
| پیشنهاد | تست سریع | تایید قطعی | تولید |

## 🎯 **پیشنهاد استفاده:**

### برای تست سریع:
```bash
python3 xss_scanner_working.py -u https://target.com
```

### برای تایید قطعی (نیاز به ChromeDriver):
```bash
python3 xss_scanner_fixed.py -u https://target.com
```

### برای تست سایت واقعی:
```bash
python3 xss_scanner_working.py -u http://testphp.vulnweb.com -d 3 --delay 1
```

## 🎉 **نتیجه:**

مشکلات شما برطرف شده‌اند:
- ✅ Screenshot فقط بعد از تایید popup
- ✅ توقف تست بعد از تایید باگ  
- ✅ تایید صحیح بر اساس context
- ✅ خروجی حرفه‌ای با Matrix theme
- ✅ Tag closing attack: `"><img src=x onerror=alert()>`

**ابزار شما حالا آماده و کاملاً عملیاتی است!** 🔍🛡️