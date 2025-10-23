# 🔑 راهنمای تنظیم API Keys

## 🚀 **قدرت کامل ابزار با API Keys**

برای استفاده از **تمام قدرت ابزار** و دسترسی به **میلیون‌ها ساب‌دامین** از منابع premium، باید API keyهای زیر رو تهیه کنی:

---

## 📋 **لیست API های پشتیبانی شده**

### 🌟 **اولویت بالا (بیشترین نتیجه)**

#### 1. 🌐 **CENSYS** - Certificate Search Engine
```
🔗 ثبت‌نام: https://censys.io/register
🔑 API Keys: https://censys.io/account/api
💰 رایگان: 250 query/month
💎 پولی: $99/month (unlimited)

نتایج: Certificate Transparency با جزئیات کامل
```

#### 2. 🔍 **SHODAN** - Internet Scanner
```
🔗 ثبت‌نام: https://shodan.io/
🔑 API Key: https://account.shodan.io/
💰 رایگان: 100 query/month
💎 پولی: $49/month (10,000 queries)

نتایج: SSL certificates, hostnames, services
```

#### 3. 🛡️ **VIRUSTOTAL** - Security Scanner
```
🔗 ثبت‌نام: https://virustotal.com/
🔑 API Key: https://virustotal.com/gui/my-apikey
💰 رایگان: 1000 requests/day
💎 پولی: $180/month (premium)

نتایج: Subdomains, detected URLs, passive DNS
```

#### 4. 🔒 **SECURITYTRAILS** - DNS Intelligence
```
🔗 ثبت‌نام: https://securitytrails.com/
🔑 API Key: https://securitytrails.com/app/account/credentials
💰 رایگان: 50 queries/month
💎 پولی: $50/month (5000 queries)

نتایج: Historical DNS, subdomains, associated domains
```

#### 5. 🚀 **CHAOS** - ProjectDiscovery
```
🔗 ثبت‌نام: https://chaos.projectdiscovery.io/
🔑 API Key: Dashboard -> API Keys
💰 رایگان: محدود
💎 پولی: Contact for pricing

نتایج: Massive subdomain dataset
```

### 🌟 **اولویت متوسط**

#### 6. 🐙 **GITHUB** - Code Search
```
🔗 تنظیمات: https://github.com/settings/tokens
🔑 Personal Access Token
💰 رایگان: 5000 requests/hour (authenticated)
Scopes مورد نیاز: public_repo, read:org

نتایج: Subdomains در کدهای منبع
```

#### 7. 📊 **BINARYEDGE** - Internet Scanner
```
🔗 ثبت‌نام: https://binaryedge.io/
🔑 API Key: https://app.binaryedge.io/account/api
💰 رایگان: 250 queries/month
💎 پولی: $10/month (10,000 queries)

نتایج: Internet-wide scanning data
```

#### 8. 🌍 **PASSIVETOTAL** - RiskIQ
```
🔗 ثبت‌نام: https://community.riskiq.com/
🔑 API Key: Account Settings -> API Access
💰 رایگان: محدود
💎 پولی: Enterprise pricing

نتایج: Passive DNS, WHOIS, certificates
```

### 🌟 **اولویت پایین (اختیاری)**

#### 9. 🔍 **FOFA** - Search Engine
```
🔗 ثبت‌نام: https://fofa.info/
🔑 API Key: User Center -> API
💰 رایگان: محدود
💎 پولی: Various plans

نتایج: Internet assets search
```

#### 10. 👁️ **ZOOMEYE** - Cyberspace Scanner
```
🔗 ثبت‌نام: https://zoomeye.org/
🔑 API Key: Profile -> API Key
💰 رایگان: محدود
💎 پولی: Various plans

نتایج: Network device scanning
```

---

## ⚙️ **نحوه تنظیم**

### 1. **ویرایش فایل config.py**
```python
API_KEYS = {
    # اولویت بالا
    'CENSYS_API_ID': 'your-censys-api-id-here',
    'CENSYS_SECRET': 'your-censys-secret-here',
    'SHODAN_API_KEY': 'your-shodan-key-here',
    'VIRUSTOTAL_API_KEY': 'your-virustotal-key-here',
    'SECURITYTRAILS_API_KEY': 'your-securitytrails-key-here',
    'CHAOS_API_KEY': 'your-chaos-key-here',
    
    # اولویت متوسط
    'GITHUB_TOKEN': 'your-github-token-here',
    'BINARYEDGE_API_KEY': 'your-binaryedge-key-here',
    'PASSIVETOTAL_API_KEY': 'your-passivetotal-key-here',
    'PASSIVETOTAL_SECRET': 'your-passivetotal-secret-here',
    
    # اختیاری
    'FOFA_API_KEY': 'your-fofa-key-here',
    'ZOOMEYE_API_KEY': 'your-zoomeye-key-here',
    # ... سایر API ها
}
```

### 2. **بررسی وضعیت API ها**
```bash
python3 subdomains.py --show-apis
```

### 3. **اجرای ابزار با قدرت کامل**
```bash
python3 subdomains.py -d target.com -v
```

---

## 📊 **مقایسه نتایج**

| حالت | تعداد منابع | ساب‌دامین‌های احتمالی | سرعت |
|------|-------------|---------------------|-------|
| **بدون API** | 8 منبع | 10-50 subdomain | متوسط |
| **با 3 API کلیدی** | 11 منبع | 50-200 subdomain | سریع |
| **با همه API ها** | 15+ منبع | 200-1000+ subdomain | خیلی سریع |

---

## 🎯 **توصیه‌های بهینه‌سازی**

### **برای شروع (رایگان):**
1. CENSYS (250 query/month)
2. SHODAN (100 query/month) 
3. VIRUSTOTAL (1000 requests/day)
4. GITHUB Token (رایگان)

### **برای استفاده حرفه‌ای:**
- همه API های اولویت بالا
- نسخه‌های پولی برای حد بالاتر
- SecurityTrails Premium
- Chaos Pro

### **برای شرکت‌ها:**
- Enterprise plans
- Custom rate limits
- Priority support
- Advanced features

---

## 🔧 **نکات مهم**

### **امنیت:**
- API keyها رو در فایل config.py نگه دار
- فایل config.py رو به git اضافه نکن
- از environment variables استفاده کن (اختیاری)

### **Rate Limiting:**
- هر API محدودیت نرخ داره
- ابزار خودکار rate limit رو رعایت می‌کنه
- برای سرعت بیشتر، نسخه پولی تهیه کن

### **خطایابی:**
```bash
# نمایش جزئیات API ها
python3 subdomains.py --show-apis

# اجرا با verbose برای دیدن خطاها
python3 subdomains.py -d target.com -v
```

---

## 🚀 **مثال عملی**

```bash
# 1. تنظیم API ها
vim config.py

# 2. بررسی وضعیت
python3 subdomains.py --show-apis

# 3. اجرای قدرتمند
python3 subdomains.py -d example.com -t 100 -v

# نتیجه: 500+ subdomain بجای 20!
```

---

## 💡 **نکته طلایی**

**با تنظیم فقط 4 API کلیدی (CENSYS, SHODAN, VIRUSTOTAL, GITHUB)، قدرت ابزار 10 برابر می‌شه!** 🔥

**بدون API**: 20-50 subdomain  
**با API**: 200-1000+ subdomain

---

**🎯 آماده برای کشف هزاران ساب‌دامین؟ API keyهات رو تنظیم کن! 🚀**