# 🚀 XSS Scanner - راهنمای شروع سریع

## نصب سریع
```bash
# 1. نصب dependencies
sudo apt update
sudo apt install python3-pip python3-venv chromium-browser

# 2. ایجاد virtual environment
python3 -m venv xss_env
source xss_env/bin/activate

# 3. نصب packages
pip install requests beautifulsoup4 selenium aiohttp lxml webdriver-manager

# 4. اجرای scanner
python3 xss_scanner.py https://example.com
```

## استفاده سریع
```bash
# اسکن پایه
python3 xss_scanner.py https://example.com

# اسکن پیشرفته
python3 xss_scanner.py https://example.com -o report.json -v

# اجرای demo
python3 demo.py

# اجرای مثال‌ها
python3 example_usage.py
```

## ویژگی‌های کلیدی
- ✅ **Reconnaissance کامل**: کشف خودکار پارامترها و فرم‌ها
- ✅ **WAF Bypass**: تشخیص و دور زدن 8 نوع WAF
- ✅ **Custom Popup**: سیستم popup مخصوص برای تایید باگ
- ✅ **تمام انواع XSS**: Reflected, Stored, DOM, Blind
- ✅ **Screenshot PoC**: گرفتن عکس از اثبات مفهوم
- ✅ **گزارش JSON**: گزارش کامل با جزئیات

## فایل‌های مهم
- `xss_scanner.py` - فایل اصلی scanner
- `waf_bypass.py` - سیستم WAF bypass
- `custom_popup.py` - سیستم popup مخصوص
- `demo.py` - فایل demo
- `example_usage.py` - مثال‌های کاربردی

## نمونه خروجی
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

## نکات مهم
- ⚠️ فقط برای تست‌های امنیتی مجاز استفاده کنید
- 🔒 نتایج را محرمانه نگه دارید
- 📊 گزارش‌ها را به مالک سایت ارسال کنید
- 🛡️ از WAF bypass مسئولانه استفاده کنید

---
**برای اطلاعات کامل، README.md را مطالعه کنید.**