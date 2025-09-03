# ابزار Decrypt کانفیگ روتر 🔧

این ابزار برای مدیران شبکه طراحی شده تا بتوانند فایل‌های کانفیگ رمزگذاری شده روترهای مختلف را decrypt کنند و اطلاعات مهم آن‌ها را استخراج کنند.

## ویژگی‌ها 🚀

- **پشتیبانی از انواع مختلف روتر:**
  - Cisco (Type 7 passwords, IOS configs)
  - MikroTik (backup files)
  - سایر روترها (Base64, AES, DES)

- **روش‌های Decrypt:**
  - Cisco Type 7 password decryption
  - Base64 decoding
  - AES/DES brute force با پسوردهای رایج
  - تشخیص خودکار نوع فایل

- **استخراج اطلاعات:**
  - پسوردها و کاربران
  - تنظیمات Interface
  - اطلاعات Routing
  - VLANs و Access Lists
  - آدرس‌های IP و Networks

## نصب و راه‌اندازی 📦

### 1. نصب وابستگی‌ها

```bash
pip install -r requirements.txt
```

### 2. اجرای برنامه

#### نسخه خط فرمان (ساده):
```bash
python router_config_decryptor.py config.txt
```

#### نسخه خط فرمان (پیشرفته):
```bash
python advanced_router_decryptor.py config.txt --report report.txt
```

#### نسخه گرافیکی:
```bash
python router_gui.py
```

## مثال‌های استفاده 📋

### 1. Decrypt کردن پسورد Type 7 سیسکو
```bash
python router_config_decryptor.py -p "094F471A1A0A"
```

### 2. تجزیه فایل کانفیگ
```bash
python router_config_decryptor.py sample_cisco_config.txt -v
```

### 3. ایجاد فایل‌های نمونه برای تست
```bash
python advanced_router_decryptor.py --create-samples
```

### 4. تجزیه پیشرفته با گزارش
```bash
python advanced_router_decryptor.py config.backup --report detailed_report.txt
```

## انواع فایل‌های پشتیبانی شده 📂

### Cisco
- فایل‌های متنی کانفیگ (`.cfg`, `.txt`)
- فایل‌های Base64 encoded
- پسوردهای Type 7

### MikroTik
- فایل‌های `.backup` (اطلاعات محدود)
- فایل‌های `.rsc` export

### عمومی
- فایل‌های Base64 encoded
- فایل‌های رمزگذاری شده با AES/DES

## نکات امنیتی ⚠️

1. **حفظ امنیت:** همیشه از فایل‌های کانفیگ خود backup تهیه کنید
2. **دسترسی محدود:** این ابزار را فقط روی سیستم‌های امن اجرا کنید
3. **حذف فایل‌های موقت:** پس از استفاده، فایل‌های decrypt شده را حذف کنید
4. **مجوزهای قانونی:** فقط روی تجهیزات خودتان استفاده کنید

## ساختار فایل‌ها 📁

```
workspace/
├── router_config_decryptor.py     # نسخه ساده
├── advanced_router_decryptor.py   # نسخه پیشرفته
├── router_gui.py                  # رابط گرافیکی
├── requirements.txt               # وابستگی‌ها
├── README_FA.md                   # این فایل
└── sample_cisco_config.txt        # نمونه کانفیگ (پس از اجرا)
```

## مثال خروجی 📄

```
نتایج تجزیه فایل کانفیگ روتر
==================================================
📁 مسیر فایل: sample_cisco_config.txt
📊 اندازه فایل: 1234 بایت
🔐 روش رمزنگاری: cisco_text
✅ وضعیت: موفق

🔑 پسوردهای یافت شده:
   • cisco (از: 094F471A1A0A)
   • admin123 (از: 05080F1C2243)

🌐 Interfaces (2 عدد):
   • interface FastEthernet0/0
   • interface FastEthernet0/1

🛣️ اطلاعات Routing (1 عدد):
   • ip route 0.0.0.0 0.0.0.0 192.168.1.254
```

## رفع مشکلات 🔧

### خطای "ماژول یافت نشد"
```bash
pip install cryptography pycryptodome
```

### خطای "فایل قابل خواندن نیست"
- بررسی کنید فایل واقعاً رمزگذاری شده باشد
- از نسخه پیشرفته برای تجزیه بیشتر استفاده کنید

### خطای "نوع فایل پشتیبانی نمی‌شود"
- فایل ممکن است از روتر پشتیبانی نشده باشد
- سعی کنید فایل را به فرمت متنی export کنید

## توسعه و بهبود 🛠️

برای افزودن پشتیبانی از روترهای جدید:

1. روش decrypt جدید را به کلاس اضافه کنید
2. تابع `detect_file_type` را به‌روزرسانی کنید
3. parser مخصوص آن نوع روتر را اضافه کنید

## مجوز و مسئولیت ⚖️

این ابزار فقط برای استفاده قانونی و روی تجهیزات شخصی طراحی شده است. 
مسئولیت استفاده نادرست بر عهده کاربر است.

---
**نوشته شده برای مدیران شبکه ایرانی با ❤️**