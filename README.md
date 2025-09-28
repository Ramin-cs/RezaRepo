# XSS Scanner - اسکنر باگ XSS پیشرفته

یک اسکنر XSS کامل و پیشرفته که شامل reconnaissance، شناسایی context ها و تست پیلودهای مناسب است.

## ویژگی‌ها

- **Reconnaissance کامل**: استخراج فرم‌ها، لینک‌ها و پارامترها
- **شناسایی Context**: تشخیص HTML، Attribute، JavaScript، CSS و URL contexts
- **پیلودهای متنوع**: بیش از 100 پیلود XSS برای context های مختلف
- **تست خودکار**: تست خودکار پیلودها و تشخیص موفقیت
- **گزارش‌گیری**: نمایش POC و ذخیره نتایج در JSON
- **رنگ‌بندی**: خروجی رنگی برای بهتر دیدن نتایج

## نصب

```bash
pip install -r requirements.txt
```

## استفاده

### استفاده ساده
```bash
python xss_scanner.py https://example.com
```

### استفاده با تنظیمات
```bash
python xss_scanner.py https://example.com -t 20 -d 0.5
```

### پارامترها
- `url`: URL هدف برای اسکن
- `-t, --threads`: تعداد thread ها (پیش‌فرض: 10)
- `-d, --delay`: تاخیر بین درخواست‌ها در ثانیه (پیش‌فرض: 1)

## مثال خروجی

```
[INFO] شروع فاز Reconnaissance...
[SUCCESS] درخواست موفق به https://example.com
[INFO] تعداد فرم‌های یافت شده: 3
[INFO] تعداد لینک‌های یافت شده: 15
[INFO] تعداد پارامترهای URL: 2
[INFO] شروع اسکن XSS...
[INFO] اسکن پارامترهای URL...
[INFO] اسکن پارامتر: search
[INFO] تست context: html
[VULN] XSS یافت شد! پارامتر: search, Context: html
[VULN] پیلود: <script>alert("XSS")</script>
==================================================
نتایج اسکن XSS
==================================================
[SUCCESS] تعداد آسیب‌پذیری‌های یافت شده: 1

--- آسیب‌پذیری 1 ---
[VULN] URL: https://example.com
[VULN] پارامتر: search
[VULN] Context: html
[VULN] Method: GET
[VULN] پیلود: <script>alert("XSS")</script>
[VULN] POC: https://example.com?search=%3Cscript%3Ealert%28%22XSS%22%29%3C%2Fscript%3E
[SUCCESS] نتایج در فایل xss_results.json ذخیره شد
```

## Context های پشتیبانی شده

1. **HTML Context**: پیلودهای HTML مستقیم
2. **Attribute Context**: پیلودهای برای attribute ها
3. **JavaScript Context**: پیلودهای برای کد JavaScript
4. **CSS Context**: پیلودهای برای CSS
5. **URL Context**: پیلودهای برای URL ها

## فایل‌های خروجی

- `xss_results.json`: نتایج کامل اسکن در فرمت JSON

## نکات امنیتی

- این ابزار فقط برای تست امنیتی وب‌سایت‌های خودتان استفاده کنید
- قبل از استفاده، مجوزهای لازم را دریافت کنید
- از استفاده غیرقانونی این ابزار خودداری کنید

## پشتیبانی

برای گزارش باگ یا پیشنهادات، لطفاً issue ایجاد کنید.