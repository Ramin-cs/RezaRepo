# Ultimate Subdomain Discovery Tool 🔍

ابزار نهایی کشف ساب‌دامنه - ترکیب قدرت تمام ابزارهای بزرگ

## ویژگی‌های کلیدی

این ابزار ترکیبی از قابلیت‌های تمام ابزارهای معروف subdomain discovery است:

### ابزارهای ترکیب شده:
- **Sublist3r**: Multi-source enumeration
- **OWASP Amass**: Comprehensive reconnaissance  
- **Subfinder**: Fast and optimized discovery
- **AssetFinder**: Wide range of sources
- **Chaos Client**: ProjectDiscovery API
- **DNSx**: Advanced DNS capabilities
- **Knock**: Brute force and wordlists
- **GitHub Search**: Code repository mining
- **Findomain**: Multi-platform discovery

### منابع داده:

#### منابع رایگان (بدون نیاز به API Key):
- **crt.sh** - Certificate Transparency logs
- **HackerTarget** - DNS and subdomain data
- **Anubis** - Subdomain enumeration service
- **AlienVault OTX** - Open Threat Exchange
- **Wayback Machine** - Internet Archive
- **ThreatCrowd** - Threat intelligence
- **URLScan.io** - URL and domain analysis
- **BufferOver.run** - DNS data

#### منابع API (نیاز به کلید API):
- **Chaos** - ProjectDiscovery's subdomain data
- **Shodan** - Internet-connected devices
- **VirusTotal** - File and URL analysis
- **SecurityTrails** - DNS and domain intelligence
- **Censys** - Internet-wide scanning
- **GitHub** - Code repository search

#### قابلیت‌های اضافی:
- **Brute Force** - Dictionary-based subdomain discovery
- **DNS Resolution** - IP address resolution
- **Custom Wordlists** - Use your own wordlists

## نصب و راه‌اندازی

### پیش‌نیازها:
```bash
pip install dnspython
```

### دانلود:
```bash
git clone <repository>
cd <repository>
chmod +x subdomains.py
```

## استفاده

### استفاده ساده:
```bash
python subdomains.py -d example.com
```

### استفاده پیشرفته:
```bash
# با تمام قابلیت‌ها
python subdomains.py -d example.com --bruteforce --github --dns-resolution -v

# ذخیره نتایج در فایل JSON
python subdomains.py -d example.com -o results.json --json

# استفاده از wordlist سفارشی
python subdomains.py -d example.com --wordlist custom.txt --bruteforce

# افزایش تعداد threads برای سرعت بیشتر
python subdomains.py -d example.com --threads 100

# حالت خاموش (فقط نتایج)
python subdomains.py -d example.com --silent

# از stdin
echo "example.com" | python subdomains.py
```

## تنظیم API Keys

برای استفاده کامل از تمام منابع، متغیرهای محیطی زیر را تنظیم کنید:

```bash
# Chaos API (ProjectDiscovery)
export CHAOS_API_KEY="your_chaos_api_key"

# Shodan API
export SHODAN_API_KEY="your_shodan_api_key"

# VirusTotal API
export VIRUSTOTAL_API_KEY="your_virustotal_api_key"

# SecurityTrails API
export SECURITYTRAILS_API_KEY="your_securitytrails_api_key"

# Censys API
export CENSYS_API_ID="your_censys_api_id"
export CENSYS_SECRET="your_censys_secret"

# GitHub Token (برای جستجو در کد)
export GITHUB_TOKEN="your_github_token"
```

### نحوه دریافت API Keys:

1. **Chaos API**: https://chaos.projectdiscovery.io/
2. **Shodan API**: https://www.shodan.io/
3. **VirusTotal API**: https://developers.virustotal.com/reference
4. **SecurityTrails API**: https://securitytrails.com/
5. **Censys API**: https://censys.io/api
6. **GitHub Token**: https://github.com/settings/tokens

## گزینه‌های خط فرمان

```
-d, --domain          دامنه هدف برای enumeration
-o, --output          مسیر فایل خروجی
--json               خروجی در فرمت JSON
--csv                خروجی در فرمت CSV
--silent             حالت خاموش - فقط نتایج
-v, --verbose        خروجی کامل
--bruteforce         فعال‌سازی brute force با wordlist
--github             فعال‌سازی جستجو در GitHub
--dns-resolution     resolve کردن دامنه‌ها به IP
--wordlist           فایل wordlist سفارشی برای brute force
--threads            تعداد threads (پیش‌فرض: 50)
--timeout            timeout درخواست‌ها به ثانیه (پیش‌فرض: 15)
--no-color           غیرفعال کردن رنگ‌ها
```

## فرمت‌های خروجی

### Text (پیش‌فرض):
```
subdomain1.example.com
subdomain2.example.com
subdomain3.example.com
```

### JSON:
```json
[
  {
    "domain": "subdomain1.example.com",
    "ip": "192.168.1.1",
    "source": "crt.sh",
    "timestamp": "2024-01-01T12:00:00"
  }
]
```

### CSV:
```csv
domain,ip,source,timestamp
subdomain1.example.com,192.168.1.1,crt.sh,2024-01-01T12:00:00
```

## مثال‌های کاربردی

### 1. Reconnaissance ساده:
```bash
python subdomains.py -d target.com -o results.txt
```

### 2. Reconnaissance کامل:
```bash
python subdomains.py -d target.com \
  --bruteforce \
  --github \
  --dns-resolution \
  --verbose \
  -o complete_results.json \
  --json
```

### 3. Brute force با wordlist سفارشی:
```bash
python subdomains.py -d target.com \
  --bruteforce \
  --wordlist /path/to/custom_wordlist.txt \
  --threads 200
```

### 4. استفاده در pipeline:
```bash
echo "target.com" | python subdomains.py --silent | httpx -silent
```

## بهینه‌سازی عملکرد

### تنظیمات سرعت:
- `--threads 100`: افزایش threads برای سرعت بیشتر
- `--timeout 10`: کاهش timeout برای سرعت بیشتر
- `--silent`: حذف پیام‌های اضافی

### تنظیمات دقت:
- `--bruteforce`: استفاده از brute force
- `--github`: جستجو در کدهای GitHub
- `--dns-resolution`: resolve کردن IP addresses

## Rate Limiting

ابزار دارای سیستم هوشمند rate limiting است که برای هر منبع تنظیم شده:

- **crt.sh**: 0.5 ثانیه
- **HackerTarget**: 2 ثانیه  
- **VirusTotal**: 15 ثانیه
- **GitHub**: 10 ثانیه
- **سایر منابع**: 1 ثانیه

## مقایسه با ابزارهای دیگر

| ویژگی | subdomains.py | Amass | Subfinder | AssetFinder |
|--------|---------------|--------|-----------|-------------|
| منابع رایگان | ✅ 8+ | ✅ 5+ | ✅ 4+ | ✅ 6+ |
| منابع API | ✅ 5+ | ✅ 10+ | ✅ 6+ | ✅ 3+ |
| Brute Force | ✅ | ✅ | ❌ | ❌ |
| GitHub Search | ✅ | ✅ | ❌ | ❌ |
| DNS Resolution | ✅ | ✅ | ❌ | ❌ |
| JSON Output | ✅ | ✅ | ❌ | ❌ |
| Rate Limiting | ✅ | ✅ | ✅ | ✅ |
| Cross-Platform | ✅ | ✅ | ✅ | ✅ |

## عیب‌یابی

### مشکلات رایج:

1. **DNS Resolution خطا**:
   ```bash
   pip install dnspython
   ```

2. **API Key نامعتبر**:
   ```bash
   # بررسی متغیرهای محیطی
   echo $CHAOS_API_KEY
   ```

3. **Timeout خطاها**:
   ```bash
   # افزایش timeout
   python subdomains.py -d example.com --timeout 30
   ```

4. **Rate Limiting**:
   ```bash
   # کاهش threads
   python subdomains.py -d example.com --threads 10
   ```

## مشارکت

برای مشارکت در توسعه این ابزار:

1. Fork کنید
2. Branch جدید ایجاد کنید
3. تغییرات را commit کنید
4. Pull Request ارسال کنید

## لایسنس

این ابزار تحت لایسنس MIT منتشر شده است.

## تماس و پشتیبانی

برای گزارش باگ یا درخواست ویژگی جدید، لطفاً Issue ایجاد کنید.

---

**نکته**: این ابزار برای اهداف آموزشی و تست امنیتی قانونی طراحی شده است. از آن فقط روی دامنه‌هایی که مجوز تست دارید استفاده کنید.