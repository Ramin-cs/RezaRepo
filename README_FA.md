# ابزار پیشرفته جمع‌آوری اطلاعات وب

یک ابزار جامع و کراس‌پلتفرم برای جمع‌آوری اطلاعات که ویژه باگ بانتی هانترها و تست‌کنندگان نفوذ طراحی شده است. این ابزار از طریق چندین فاز، جمع‌آوری گسترده اطلاعات را انجام می‌دهد تا حداکثر اطلاعات از دامنه‌های هدف استخراج کند.

## 🌟 ویژگی‌ها

### فاز ۱: کشف ساب‌دامنه‌ها
- **لاگ‌های شفافیت گواهی** - استخراج ساب‌دامنه‌ها از CT logs
- **حمله brute force DNS** - تست الگوهای رایج ساب‌دامنه
- **جستجوی موتورهای جستجو** - استفاده از موتورهای جستجو برای یافتن ساب‌دامنه‌ها
- **تحلیل آرشیو** - جستجو در آرشیو Wayback Machine
- **تحلیل جاوااسکریپت** - تحلیل عمیق فایل‌های JS برای ساب‌دامنه‌های مخفی
- **DNS غیرفعال** - جستجو در منابع مختلف DNS
- **یکپارچگی API** - APIهای Shodan، VirusTotal، SecurityTrails

### فاز ۲: استخراج پارامترها
- **تحلیل جاوااسکریپت** - استخراج پارامترها از فایل‌های JS
- **تحلیل فرم‌های HTML** - کشف پارامترهای فرم
- **تحلیل الگوی URL** - استخراج پارامترها از URLهای آرشیو شده
- **تحلیل فایل پیکربندی** - تحلیل فایل‌های config برای پارامترها
- **کشف Swagger/OpenAPI** - استخراج پارامترهای API
- **بازرسی GraphQL** - کشف پارامترهای GraphQL

### فاز ۳: کشف فایل‌های حساس
- **کشف مبتنی بر تکنولوژی** - یافتن فایل‌ها بر اساس تکنولوژی‌های تشخیص داده شده
- **فایل‌های حساس رایج** - robots.txt، sitemap.xml و غیره
- **کشف فایل‌های پشتیبان** - جستجو برای فایل‌های backup و موقت
- **فایل‌های کنترل نسخه** - فایل‌های Git، SVN، Mercurial
- **پیکربندی Docker** - فایل‌های config Docker و container
- **پیکربندی ابری** - فایل‌های config AWS، Azure، GCP

### فاز ۴: کشف IP واقعی
- **تحلیل هش Favicon** - استفاده از هش favicon برای کشف IP
- **تحلیل تاریخچه DNS** - جستجو در رکوردهای تاریخی DNS
- **تحلیل گواهی** - استخراج IPها از گواهی‌های SSL
- **حل مستقیم DNS** - حل تمام ساب‌دامنه‌های کشف شده
- **یکپارچگی Shodan/Censys** - کشف پیشرفته IP از طریق APIها

### فاز ۵: جمع‌آوری اطلاعات اضافی
- **اطلاعات WHOIS** - اطلاعات جامع دامنه
- **تحلیل هدرهای امنیتی** - بررسی پیاده‌سازی header امنیتی
- **شمارش دایرکتوری** - کشف دایرکتوری‌های مخفی
- **اثرانگشت تکنولوژی** - تشخیص پیشرفته تکنولوژی
- **تشخیص WAF** - شناسایی راه‌حل‌های امنیتی
- **تحلیل SSL/TLS** - تحلیل پیکربندی رمزگذاری
- **تست متدهای HTTP** - تست متدهای HTTP پشتیبانی شده
- **تحلیل CORS** - بررسی پیکربندی CORS

### فاز ۶: ارزیابی آسیب‌پذیری
- **تست SQL Injection** - تشخیص پایه SQL injection
- **تست Directory Traversal** - تست آسیب‌پذیری path traversal
- **تشخیص XSS** - تست پایه آسیب‌پذیری XSS
- **تست Command Injection** - تشخیص command injection

## 🚀 نصب

### نصب سریع
```bash
# دانلود یا clone ابزار
git clone <repository> یا دانلود فایل‌ها

# اجرای اسکریپت نصب
python install.py

# (اختیاری) پیکربندی کلیدهای API
python api_manager.py --setup
```

### نصب دستی
```bash
# نصب وابستگی‌های Python
pip install -r requirements.txt

# نصب وابستگی‌های سیستم (Linux/Ubuntu)
sudo apt-get update
sudo apt-get install -y dnsutils whois nmap

# نصب وابستگی‌های سیستم (macOS)
brew install bind whois nmap

# نصب وابستگی‌های سیستم (Windows)
# استفاده از Windows Subsystem for Linux (WSL) برای بهترین سازگاری
```

## 📖 استفاده

### استفاده پایه
```bash
# جمع‌آوری اطلاعات پایه
python advanced_recon_tool.py -t example.com

# دایرکتوری خروجی سفارشی
python advanced_recon_tool.py -t example.com -o my_recon_results

# خروجی verbose با تعداد thread سفارشی
python advanced_recon_tool.py -t https://example.com --threads 100 --verbose
```

### استفاده پیشرفته با کلیدهای API
```bash
# تنظیم کلیدهای API به عنوان متغیرهای محیطی
export SHODAN_API_KEY="your_key_here"
export VIRUSTOTAL_API_KEY="your_key_here"
export SECURITYTRAILS_API_KEY="your_key_here"

# یا استفاده از فایل config
python advanced_recon_tool.py -t example.com
```

### اجرای آسان
```bash
# Linux/macOS
./run_recon.sh example.com

# Windows
run_recon.bat example.com

# کراس‌پلتفرم
python run_recon.py example.com
```

## 📊 فرمت‌های خروجی

ابزار چندین فرمت خروجی تولید می‌کند:

1. **گزارش JSON** - نتایج دقیق قابل خواندن توسط ماشین
2. **گزارش HTML** - گزارش زیبای وب‌محور با آمار
3. **خلاصه متنی** - نمای کلی سریع از یافته‌ها
4. **قالب Nuclei** - سازگار با اسکنر Nuclei
5. **گزارش CSV** - فرمت سازگار با صفحه گسترده
6. **گزارش Markdown** - مستندات سازگار با GitHub

## 🔧 پیکربندی

### کلیدهای API (اختیاری اما توصیه شده)
برای باز کردن قابلیت کامل، کلیدهای API را از اینجا دریافت کنید:

- **Shodan** (https://account.shodan.io/) - برای کشف پیشرفته IP
- **VirusTotal** (https://www.virustotal.com/gui/my-apikey) - برای کشف ساب‌دامنه
- **SecurityTrails** (https://securitytrails.com/corp/api) - برای تاریخچه DNS
- **Censys** (https://censys.io/api) - برای تحلیل گواهی

### مدیریت کلیدهای API
```bash
# نصب تعاملی
python api_manager.py --setup

# نمایش وضعیت
python api_manager.py --status

# تست کلیدها
python api_manager.py --test
```

## 🛡️ اطلاعیه امنیتی و قانونی

**مهم:** این ابزار فقط برای اهداف تست امنیتی مشروع طراحی شده است.

- ✅ فقط روی دامنه‌هایی استفاده کنید که مالک آن هستید یا مجوز صریح تست دارید
- ✅ از شیوه‌های افشای مسئولانه پیروی کنید
- ✅ به محدودیت‌های نرخ و شرایط خدمات احترام بگذارید
- ❌ برای اهداف مخرب استفاده نکنید
- ❌ بدون مجوز مناسب تست نکنید

## 🔍 چه چیزی این ابزار را ویژه می‌کند

### پوشش جامع
- **کشف چند منبعه** - ترکیب منابع داده متعدد برای حداکثر پوشش
- **تحلیل عمیق جاوااسکریپت** - استخراج endpointها و پارامترهای مخفی
- **آگاه از تکنولوژی** - تطبیق اسکن بر اساس تکنولوژی‌های تشخیص داده شده
- **داده‌های تاریخی** - استفاده از آرشیو وب و تاریخچه DNS
- **یکپارچگی API** - بهره‌برداری از APIهای premium در صورت وجود

### تکنیک‌های پیشرفته
- **تطبیق هش Favicon** - کشف IPهای واقعی پشت CDNها
- **شفافیت گواهی** - یافتن ساب‌دامنه‌ها از گواهی‌های SSL
- **بازرسی GraphQL** - کشف schema و پارامترهای GraphQL
- **تحلیل Swagger/OpenAPI** - استخراج مستندات API
- **تشخیص WAF** - شناسایی راه‌حل‌های امنیتی

### طراحی کراس‌پلتفرم
- **مبتنی بر Python** - روی Windows، Linux و macOS اجرا می‌شود
- **وابستگی‌های کم** - با کتابخانه‌های استاندارد Python کار می‌کند
- **تنزل مناسب** - حتی بدون ابزارهای اختیاری عمل می‌کند
- **فرمت‌های خروجی متعدد** - سازگار با ابزارهای تحلیل مختلف

## 🎯 موارد استفاده

### شکار باگ بانتی
- شمارش جامع ساب‌دامنه
- کشف پارامترهای مخفی
- شناسایی فایل‌های حساس
- کشف IP واقعی برای دور زدن CDNها

### تست نفوذ
- فاز جمع‌آوری اطلاعات اولیه
- نقشه‌برداری سطح حمله
- شناسایی پشته تکنولوژی
- آماده‌سازی ارزیابی آسیب‌پذیری

### ارزیابی امنیتی
- تحلیل سطح حمله خارجی
- تشخیص نشت اطلاعات
- بررسی امنیت پیکربندی
- بررسی انطباق

## 📈 عملکرد

- **پردازش همزمان** - چندنخی برای سرعت
- **محدودیت نرخ** - احترام به منابع سرور هدف
- **کارآمد حافظه** - مدیریت مجموعه داده‌های بزرگ
- **قابل ادامه** - امکان ادامه اسکن‌های قطع شده

## 🛠️ نصب و راه‌اندازی

### نصب خودکار (توصیه شده)
```bash
# ۱. اجرای نصب‌کننده کامل
python install.py

# ۲. تنظیم کلیدهای API (اختیاری)
python api_manager.py --setup

# ۳. تست ابزار
python test_tool.py
```

### راه‌اندازی سریع
```bash
# نصب ساده
python setup.py

# اجرای ابزار
python run_recon.py example.com
```

### نصب ابزارهای خارجی
```bash
# نصب ابزارهای Go-based
python external_tools.py

# یا نصب دستی
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
```

## 📋 راهنمای استفاده

### دستورات پایه
```bash
# اسکن پایه
python advanced_recon_tool.py -t example.com

# اسکن با تنظیمات سفارشی
python advanced_recon_tool.py -t example.com -o results --threads 100 --verbose

# استفاده از launcher ساده
python run_recon.py example.com

# Windows
run_recon.bat example.com

# Linux/macOS
./run_recon.sh example.com
```

### گزینه‌های خط فرمان
```
-t, --target      دامنه هدف (ضروری)
-o, --output      دایرکتوری خروجی (پیش‌فرض: recon_output)
--threads         تعداد thread (پیش‌فرض: 50)
--timeout         timeout درخواست به ثانیه (پیش‌فرض: 15)
--verbose         فعال‌سازی خروجی verbose
```

## 🔑 مدیریت API

### تنظیم کلیدهای API
```bash
# راه‌اندازی تعاملی
python api_manager.py --setup

# نمایش وضعیت فعلی
python api_manager.py --status

# تست اعتبار کلیدها
python api_manager.py --test
```

### کلیدهای API پشتیبانی شده
- **Shodan API** - کشف IP واقعی، جستجوی هش favicon
- **VirusTotal API** - کشف ساب‌دامنه، DNS غیرفعال
- **SecurityTrails API** - تاریخچه DNS، نظارت بر گواهی
- **Censys API** - تحلیل گواهی، تشخیص سرویس

## 📊 فرمت‌های گزارش

### گزارش‌های تولید شده
1. **`domain_recon_report.json`** - داده‌های کامل JSON
2. **`domain_recon_report.html`** - گزارش زیبای وب
3. **`domain_summary.txt`** - خلاصه متنی
4. **`domain_nuclei_template.yaml`** - قالب Nuclei
5. **`domain_detailed.csv`** - فرمت CSV
6. **`domain_report.md`** - گزارش Markdown
7. **`recon.log`** - لاگ‌های دقیق

### نمونه ساختار خروجی
```
recon_output/
├── example.com_recon_report.json
├── example.com_recon_report.html
├── example.com_summary.txt
├── example.com_nuclei_template.yaml
├── example.com_detailed.csv
├── example.com_report.md
└── recon.log
```

## 🧪 تست و اعتبارسنجی

### اجرای تست
```bash
# تست کامل ابزار
python test_tool.py

# تست کلیدهای API
python api_manager.py --test

# بررسی نصب
python -c "from advanced_recon_tool import WebReconTool; print('✅ Installation OK')"
```

## 🔧 عیب‌یابی

### مشکلات رایج

**خطای import:**
```bash
# نصب مجدد وابستگی‌ها
pip install -r requirements.txt

# بررسی نسخه Python
python --version
```

**خطای دسترسی:**
```bash
# اجازه اجرا دادن
chmod +x run_recon.sh advanced_recon_tool.py

# اجرا با sudo در صورت نیاز (فقط برای نصب ابزارهای سیستم)
sudo python install.py
```

**مشکل کلید API:**
```bash
# بررسی پیکربندی
python api_manager.py --status

# تست کلیدها
python api_manager.py --test
```

## 🎓 نکات استفاده

### برای باگ بانتی
1. همیشه ابتدا ساب‌دامنه‌ها را کشف کنید
2. پارامترهای مخفی را دقیقاً بررسی کنید
3. فایل‌های حساس را برای نشت اطلاعات چک کنید
4. IP واقعی را برای دور زدن WAF پیدا کنید

### برای تست نفوذ
1. از گزارش JSON برای ابزارهای خودکار استفاده کنید
2. قالب Nuclei را برای اسکن آسیب‌پذیری اجرا کنید
3. فایل CSV را برای تحلیل در Excel استفاده کنید

### بهینه‌سازی عملکرد
```bash
# برای اهداف بزرگ
python advanced_recon_tool.py -t example.com --threads 200

# برای شبکه‌های کند
python advanced_recon_tool.py -t example.com --timeout 30 --threads 20
```

## 🔄 به‌روزرسانی و توسعه

### اضافه کردن تکنیک‌های جدید
1. تکنیک‌های جدید را به `advanced_modules.py` اضافه کنید
2. ابزارهای خارجی جدید را به `external_tools.py` اضافه کنید
3. الگوهای فایل حساس جدید را به لیست اضافه کنید

### سفارشی‌سازی
- فایل‌های pattern در کلاس `WebReconTool` قابل تغییر هستند
- timeout ها و thread count قابل تنظیم هستند
- فرمت‌های گزارش قابل توسعه هستند

## ⚠️ هشدارها و محدودیت‌ها

### محدودیت‌های قانونی
- فقط روی دامنه‌های مجاز استفاده کنید
- از rate limiting احترام کنید
- شرایط خدمات APIها را رعایت کنید

### محدودیت‌های فنی
- برخی تکنیک‌ها نیاز به کلید API دارند
- ابزارهای خارجی اختیاری هستند
- عملکرد به اتصال اینترنت وابسته است

## 📞 پشتیبانی

برای مشکلات یا سوالات:
1. فایل‌های log تولید شده را برای اطلاعات دقیق خطا بررسی کنید
2. اطمینان حاصل کنید که تمام وابستگی‌ها درست نصب شده‌اند
3. اتصال شبکه و مجوزها را تأیید کنید
4. فرمت دامنه هدف را بررسی کنید

---

**سلب مسئولیت:** این ابزار فقط برای اهداف آموزشی و تست مجاز ارائه شده است. کاربران مسئول اطمینان از داشتن مجوز مناسب قبل از تست هر هدف هستند.