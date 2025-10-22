# 🔍 Advanced Subdomain Enumerator

**ابزار قدرتمند کشف و شمارش ساب‌دامین‌ها با ترکیب بهترین تکنیک‌های موجود**

## 🚀 ویژگی‌های کلیدی

### 🌐 منابع متنوع اطلاعات
- **Certificate Transparency**: جستجو در لاگ‌های گواهی‌نامه SSL/TLS
- **DNS Brute Force**: حمله brute force با wordlist گسترده
- **Search Engines**: جستجو در موتورهای جستجو (Google, Bing)
- **GitHub Code Search**: جستجو در کدهای منبع GitHub
- **Web Archive Mining**: استخراج از آرشیو وب Wayback Machine
- **Passive DNS**: منابع DNS غیرفعال متعدد
- **Zone Transfer**: تلاش برای انتقال zone DNS
- **Reverse DNS**: جستجوی معکوس DNS
- **VHost Discovery**: کشف virtual host ها
- **SSL Certificate Analysis**: تجزیه و تحلیل گواهی‌نامه‌های SSL

### 🛡️ قابلیت‌های پیشرفته
- **حذف خودکار Duplicate**: سیستم هوشمند حذف تکراری‌ها
- **Multi-threading**: پردازش موازی برای سرعت بالا
- **User-Agent Rotation**: چرخش User-Agent برای جلوگیری از تشخیص
- **Rate Limiting**: کنترل نرخ درخواست‌ها
- **خروجی تمیز**: فایل txt مرتب و بدون تکرار
- **گزارش‌دهی زنده**: نمایش real-time نتایج

## 📦 نصب و راه‌اندازی

### پیش‌نیازها
```bash
# نصب Python 3.7+
sudo apt update
sudo apt install python3 python3-pip

# نصب کتابخانه‌های مورد نیاز
pip3 install -r requirements.txt
```

### دانلود و راه‌اندازی
```bash
# اجرای مستقیم
python3 subdomains.py -d example.com

# اجرا با مجوز اجرا
chmod +x subdomains.py
./subdomains.py -d example.com
```

## 💻 نحوه استفاده

### دستورات پایه
```bash
# اسکن ساده یک دامین
python3 subdomains.py -d example.com

# تعیین فایل خروجی سفارشی
python3 subdomains.py -d example.com -o my_results.txt

# استفاده از thread های بیشتر برای سرعت بالاتر
python3 subdomains.py -d example.com -t 100

# فعال‌سازی حالت verbose
python3 subdomains.py -d example.com -v

# تنظیم timeout سفارشی
python3 subdomains.py -d example.com --timeout 15
```

### پارامترهای پیشرفته
```bash
# اسکن کامل با تمام گزینه‌ها
python3 subdomains.py -d target.com -o results.txt -t 100 --timeout 15 -v

# اسکن سریع با thread کم
python3 subdomains.py -d target.com -t 20 --timeout 5

# اسکن عمیق با timeout بالا
python3 subdomains.py -d target.com -t 200 --timeout 20 -v
```

## 📊 خروجی نمونه

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                    🔍 ADVANCED SUBDOMAIN ENUMERATOR                         ║
║              Comprehensive Subdomain Discovery & Intelligence               ║
║                                                                              ║
║  🌐 Certificate Transparency  |  🔍 DNS Brute Force                        ║
║  🔎 Search Engine Discovery   |  📊 GitHub Code Search                      ║
║  🚀 Chaos API Integration     |  🌍 Web Archive Mining                      ║
║  🛡️  Security Intelligence    |  📡 Passive DNS Sources                     ║
╚══════════════════════════════════════════════════════════════════════════════╝

[*] Target Domain: example.com
[*] Output File: example.com_subdomains.txt
[*] Threads: 50
[*] Timeout: 10s
[*] Starting comprehensive subdomain enumeration...

[12:34:56] 🔍 Searching Certificate Transparency logs...
[12:34:57] Found: www.example.com
[12:34:57] Found: mail.example.com
[12:34:58] Found: api.example.com
[12:34:59] 🔍 Starting DNS brute force attack...
[12:35:02] Found: admin.example.com
[12:35:03] Found: test.example.com
[12:35:04] 🔎 Searching via Search Engines...
[12:35:07] Found: blog.example.com
[12:35:08] Found: shop.example.com

╔══════════════════════════════════════════════════════════════════════════════╗
║                           🎯 ENUMERATION COMPLETE                           ║
╚══════════════════════════════════════════════════════════════════════════════╝

✅ Found 25 unique subdomains for example.com
📁 Results saved to: example.com_subdomains.txt

🔍 Preview (first 10 results):
 1. admin.example.com
 2. api.example.com
 3. blog.example.com
 4. dev.example.com
 5. mail.example.com
 6. shop.example.com
 7. test.example.com
 8. www.example.com
 ... and 17 more
```

## 🔧 تکنیک‌های پیاده‌شده

### 1. Certificate Transparency
- جستجو در crt.sh
- CertSpotter API
- استخراج Subject Alternative Names

### 2. DNS Brute Force
- Wordlist گسترده (200+ کلمه)
- پشتیبانی از A و CNAME records
- Multi-threading برای سرعت بالا

### 3. Search Engine Discovery
- Google dorking
- جستجوی هوشمند با کوئری‌های مختلف
- استخراج از نتایج جستجو

### 4. GitHub Code Search
- جستجو در فایل‌های مختلف (txt, json, xml, yml)
- تجزیه محتوای فایل‌ها
- استخراج subdomain از کدهای منبع

### 5. Web Archive Mining
- Wayback Machine CDX API
- استخراج از URL های آرشیو شده
- تجزیه hostname ها

### 6. Passive DNS Sources
- Google DNS over HTTPS
- Cloudflare DNS over HTTPS
- تجزیه پاسخ‌های DNS

### 7. SSL Certificate Analysis
- اتصال مستقیم SSL
- استخراج Subject Alternative Names
- تجزیه گواهی‌نامه‌های SSL

### 8. Zone Transfer
- تلاش برای AXFR
- جستجو در nameserver ها
- استخراج تمام رکوردهای zone

### 9. Reverse DNS
- جستجوی معکوس در رنج IP
- شناسایی hostname های مرتبط
- تجزیه شبکه هدف

### 10. Virtual Host Discovery
- تست با Host header
- شناسایی vhost های مختلف
- مقایسه پاسخ‌های HTTP

## 🎯 نقاط قوت ابزار

### ✅ مزایای کلیدی
- **جامع**: ترکیب 10+ تکنیک مختلف
- **سریع**: Multi-threading و بهینه‌سازی
- **دقیق**: حذف خودکار false positive ها
- **قابل اعتماد**: مدیریت خطا و exception handling
- **کاربرپسند**: رابط ساده و خروجی زیبا
- **قابل تنظیم**: پارامترهای قابل تغییر
- **Cross-platform**: سازگار با Windows, Linux, macOS

### 🔍 پوشش کامل
- **Public Subdomains**: ساب‌دامین‌های عمومی
- **Private Subdomains**: ساب‌دامین‌های خصوصی
- **Historical Data**: داده‌های تاریخی از آرشیو
- **Certificate Data**: اطلاعات گواهی‌نامه
- **DNS Records**: تمام انواع رکوردهای DNS
- **Code Repositories**: کدهای منبع و فایل‌های config

## ⚙️ تنظیمات پیشرفته

### Thread Count
- **پیش‌فرض**: 50 thread
- **شبکه سریع**: 100-200 thread
- **شبکه کند**: 20-50 thread
- **محدودیت منابع**: 10-20 thread

### Timeout Settings
- **پیش‌فرض**: 10 ثانیه
- **شبکه سریع**: 5-8 ثانیه
- **شبکه کند**: 15-20 ثانیه
- **اتصال ناپایدار**: 20-30 ثانیه

### Wordlist Customization
```python
# اضافه کردن کلمات سفارشی
custom_words = ['internal', 'staging', 'preprod', 'uat']
# ویرایش فایل subdomains.py و اضافه کردن به wordlist
```

## 🛡️ ملاحظات امنیتی

### Rate Limiting
- تاخیر بین درخواست‌ها
- User-Agent rotation
- جلوگیری از blocking

### Legal Compliance
- استفاده فقط روی دامین‌های مجاز
- رعایت قوانین محلی
- اجتناب از فعالیت‌های مخرب

### Responsible Disclosure
- گزارش مسئولانه آسیب‌پذیری‌ها
- عدم سوءاستفاده از اطلاعات
- رعایت اصول اخلاقی

## 📈 بهینه‌سازی عملکرد

### برای دامین‌های بزرگ
```bash
# افزایش thread ها
python3 subdomains.py -d large-domain.com -t 200

# کاهش timeout
python3 subdomains.py -d large-domain.com --timeout 5

# ترکیب هر دو
python3 subdomains.py -d large-domain.com -t 150 --timeout 7
```

### برای شبکه‌های کند
```bash
# کاهش thread ها
python3 subdomains.py -d domain.com -t 20

# افزایش timeout
python3 subdomains.py -d domain.com --timeout 20

# حالت محافظه‌کارانه
python3 subdomains.py -d domain.com -t 10 --timeout 25
```

## 🔧 عیب‌یابی

### مشکلات رایج
1. **DNS Resolution Error**: بررسی اتصال اینترنت
2. **Timeout Errors**: افزایش مقدار timeout
3. **Rate Limiting**: کاهش تعداد thread ها
4. **Permission Denied**: اجرا با مجوزهای مناسب

### لاگ‌های مفید
```bash
# فعال‌سازی verbose mode
python3 subdomains.py -d domain.com -v

# ذخیره لاگ‌ها
python3 subdomains.py -d domain.com -v 2>&1 | tee scan.log
```

## 🚀 ویژگی‌های آینده

### در حال توسعه
- [ ] API Key integration (VirusTotal, SecurityTrails, Chaos)
- [ ] Export به فرمت‌های مختلف (JSON, CSV, XML)
- [ ] Web interface
- [ ] Database storage
- [ ] Scheduled scanning
- [ ] Email notifications
- [ ] Integration با Nmap
- [ ] Vulnerability assessment

## 📞 پشتیبانی

### گزارش مشکلات
- ایجاد Issue در GitHub
- ارسال لاگ‌های خطا
- توضیح مراحل بازتولید مشکل

### درخواست ویژگی
- پیشنهاد ویژگی‌های جدید
- بهبود عملکرد
- پشتیبانی از منابع جدید

---

**🔍 Advanced Subdomain Enumerator - ابزار جامع کشف ساب‌دامین**

*"کشف هر ساب‌دامین، از عمومی تا خصوصی"* 🎯

---

**Happy Hunting! 🚀✨**