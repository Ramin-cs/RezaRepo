# 🔍 Ultimate Web Reconnaissance Tool

## 🚀 فقط یک فایل - همه قابلیت‌ها!

این ابزار کاملترین ابزار جمع‌آوری اطلاعات وب است که در یک فایل واحد تمام قابلیت‌های لازم برای باگ بانتی و تست نفوذ را دارد.

## ⚡ استفاده فوری

```bash
# فقط این دستور را اجرا کنید:
python3 ultimate_recon_tool.py -t yourdomain.com
```

## 🎯 این برنامه چه کار می‌کند؟

### فاز ۱: کشف ساب‌دامنه‌ها (۱۰+ روش)
- 🔍 **Certificate Transparency** - جستجو در لاگ‌های گواهی SSL
- 🔍 **DNS Brute Force** - تست ۶۰+ ساب‌دامنه رایج
- 🔍 **JavaScript Analysis** - تحلیل عمیق فایل‌های JS برای ساب‌دامنه‌های مخفی
- 🔍 **Archive Analysis** - جستجو در آرشیو Wayback Machine
- 🔍 **SSL Certificate SAN** - استخراج از Subject Alternative Names
- 🔍 **Search Engine Dorking** - جستجو در موتورهای جستجو
- 🔍 **Reverse DNS** - DNS معکوس روی IP های کشف شده

### فاز ۲: استخراج پارامترها
- ⚙️ **JavaScript Parameters** - استخراج از کدهای JS
- ⚙️ **HTML Form Analysis** - تحلیل فرم‌های HTML
- ⚙️ **Config File Analysis** - بررسی فایل‌های پیکربندی
- ⚙️ **API Documentation** - استخراج از Swagger/OpenAPI
- ⚙️ **URL Pattern Analysis** - تحلیل الگوهای URL
- ⚙️ **Common Parameter Brute Force** - تست پارامترهای رایج

### فاز ۳: کشف فایل‌های حساس
- 🔒 **Technology-Based Discovery** - کشف بر اساس تکنولوژی تشخیص داده شده
- 🔒 **PHP Files**: `config.php`, `wp-config.php`, `database.php`
- 🔒 **JavaScript Files**: `package.json`, `.env`, `webpack.config.js`
- 🔒 **Python Files**: `requirements.txt`, `settings.py`, `manage.py`
- 🔒 **General Files**: `.htaccess`, `robots.txt`, `sitemap.xml`, `.git/config`
- 🔒 **Directory Enumeration** - کشف دایرکتوری‌های مخفی

### فاز ۴: کشف IP واقعی
- 🌍 **Direct DNS Resolution** - حل مستقیم DNS
- 🌍 **Favicon Hash Analysis** - تحلیل هش favicon
- 🌍 **SSL Certificate Analysis** - تحلیل گواهی‌های SSL
- 🌍 **Subdomain IP Resolution** - حل IP تمام ساب‌دامنه‌ها

### فاز ۵: تحلیل امنیتی
- 🛡️ **Security Headers Analysis** - بررسی header های امنیتی
- 🛡️ **Technology Fingerprinting** - شناسایی تکنولوژی‌ها
- 🛡️ **WAF Detection** - تشخیص Cloudflare، Akamai و سایر WAF ها
- 🛡️ **WHOIS Information** - اطلاعات ثبت دامنه
- 🛡️ **Basic Vulnerability Scanning** - تست آسیب‌پذیری‌های پایه

## 📊 خروجی‌های تولید شده

بعد از اجرا، این فایل‌ها تولید می‌شوند:

1. **`domain_complete_report.json`** - داده‌های کامل JSON
2. **`domain_report.html`** - گزارش زیبای وب (باز کنید در مرورگر)
3. **`domain_summary.txt`** - خلاصه متنی
4. **`domain_data.csv`** - فایل Excel/CSV
5. **`recon.log`** - لاگ دقیق عملیات

## 🎮 نحوه استفاده

### استفاده پایه
```bash
python3 ultimate_recon_tool.py -t example.com
```

### تنظیمات پیشرفته
```bash
# خروجی سفارشی
python3 ultimate_recon_tool.py -t example.com -o my_results

# سرعت بالا (thread بیشتر)
python3 ultimate_recon_tool.py -t example.com --threads 100

# timeout بیشتر برای سایت‌های کند
python3 ultimate_recon_tool.py -t example.com --timeout 30

# حالت verbose
python3 ultimate_recon_tool.py -t example.com --verbose
```

### گزینه‌های موجود
```
-t, --target      دامنه هدف (ضروری)
-o, --output      پوشه خروجی (پیش‌فرض: ultimate_recon_results)
--threads         تعداد thread (پیش‌فرض: 50)
--timeout         timeout درخواست (پیش‌فرض: 15 ثانیه)
--verbose         نمایش جزئیات بیشتر
```

## 🎯 نتایج نمونه

```
📊 QUICK STATS:
🌐 Subdomains: 25        # ساب‌دامنه‌های کشف شده
⚙️ Parameters: 45       # پارامترهای استخراج شده
🔒 Sensitive Files: 8   # فایل‌های حساس یافت شده
🌍 IP Addresses: 12     # آدرس‌های IP
🛠️ Technologies: 6      # تکنولوژی‌های تشخیص داده شده
⚠️ Vulnerabilities: 3   # آسیب‌پذیری‌های احتمالی
```

## 🛡️ ویژگی‌های امنیتی

### تشخیص WAF
- Cloudflare
- AWS CloudFront  
- Akamai
- Incapsula
- ModSecurity

### تشخیص CMS
- WordPress
- Drupal
- Joomla
- Laravel
- Django

### تحلیل SSL
- نسخه SSL/TLS
- الگوریتم رمزگذاری
- اطلاعات گواهی
- Subject Alternative Names

## ⚠️ نکات مهم

### قانونی
- ❗ **فقط روی دامنه‌هایی استفاده کنید که مالک آن هستید**
- ❗ **یا مجوز کتبی تست دارید**
- ❗ **برای اهداف آموزشی و تست مجاز**

### فنی
- ✅ **بدون نیاز به نصب** - فقط Python 3.7+
- ✅ **کراس‌پلتفرم** - Windows, Linux, macOS
- ✅ **Rate Limited** - احترام به سرور هدف
- ✅ **Multi-threaded** - سرعت بالا

## 🔧 عیب‌یابی

### اگر خطا گرفتید:
```bash
# بررسی نسخه Python
python3 --version

# اجرا با جزئیات بیشتر
python3 ultimate_recon_tool.py -t example.com --verbose

# کاهش سرعت برای شبکه‌های کند
python3 ultimate_recon_tool.py -t example.com --threads 20 --timeout 30
```

### اگر نتیجه کمی گرفتید:
- سایت ممکن است WAF داشته باشد
- سایت ممکن است محافظت شده باشد
- اتصال اینترنت را بررسی کنید

---

## 🎉 **این ابزار شامل چیست؟**

✅ **کشف ساب‌دامنه** با ۱۰+ روش مختلف  
✅ **استخراج پارامتر** از JS، HTML، Config ها  
✅ **کشف فایل حساس** بر اساس تکنولوژی  
✅ **پیدا کردن IP واقعی** برای دور زدن CDN  
✅ **تشخیص تکنولوژی** و WAF  
✅ **تحلیل امنیتی** header ها و SSL  
✅ **اسکن آسیب‌پذیری پایه**  
✅ **گزارش‌گیری کامل** در ۴ فرمت  
✅ **کراس‌پلتفرم** - همه جا کار می‌کند  
✅ **فقط یک فایل** - نصب آسان  

**فقط یک دستور: `python3 ultimate_recon_tool.py -t yourdomain.com`**