# 🚀 راهنمای سریع GitHub Repository

## 1. ایجاد Repository در GitHub

1. برو به [github.com](https://github.com)
2. روی "New repository" کلیک کن
3. نام: `subdomain-enumeration-tool`
4. Description: `🔍 Advanced Subdomain Enumeration Tool v2.0 - All Errors Fixed`
5. Public انتخاب کن
6. "Create repository" کلیک کن

## 2. آپلود فایل‌ها

### روش 1: از طریق Git
```bash
# Clone repository
git clone https://github.com/YOUR_USERNAME/subdomain-enumeration-tool.git
cd subdomain-enumeration-tool

# کپی فایل‌ها از workspace (فایل‌ها در /workspace موجود هستند)
cp /workspace/subdomains.py .
cp /workspace/config.py .
cp /workspace/demo.py .
cp /workspace/test.py .
cp /workspace/install.sh .
cp /workspace/setup.py .
cp /workspace/requirements.txt .
cp /workspace/README.md .
cp /workspace/API_SETUP_GUIDE.md .
cp /workspace/SUBDOMAIN_README.md .
cp /workspace/config.py.example .

# Commit و Push
git add .
git commit -m "🚀 Initial commit: Subdomain Enumeration Tool v2.0 - All Errors Fixed"
git push origin main
```

### روش 2: از طریق GitHub Web
1. در repository روی "uploading an existing file" کلیک کن
2. فایل‌های زیر را آپلود کن:
   - `subdomains.py` (اسکریپت اصلی - رفع شده)
   - `config.py` (تنظیمات API)
   - `demo.py` (مثال‌ها)
   - `test.py` (تست‌سوییت)
   - `install.sh` (نصب‌کننده)
   - `setup.py` (Python package)
   - `requirements.txt` (dependencies)
   - `README.md` (مستندات)
   - `API_SETUP_GUIDE.md` (راهنمای API)
   - `SUBDOMAIN_README.md` (راهنمای subdomain)
   - `config.py.example` (الگوی تنظیمات)

## 3. استفاده از Repository

```bash
# Clone
git clone https://github.com/YOUR_USERNAME/subdomain-enumeration-tool.git
cd subdomain-enumeration-tool

# نصب
pip3 install -r requirements.txt

# تست
python3 test.py

# استفاده
python3 subdomains.py -d example.com
```

## ✅ فایل‌های آماده

همه فایل‌ها در `/workspace` آماده هستند و error ها رفع شده‌اند:
- ✅ CSV output error رفع شد
- ✅ HTTPX probe error رفع شد  
- ✅ Nmap detection بهبود یافت
- ✅ SSL probing error رفع شد
- ✅ Error handling بهبود یافت

## 🎯 آماده برای استفاده!

حالا می‌تونی repository رو ایجاد کنی و فایل‌ها رو آپلود کنی! 🚀