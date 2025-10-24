# 🚀 راهنمای ایجاد GitHub Repository

## مرحله 1: ایجاد Repository در GitHub

### روش 1: از طریق وب‌سایت GitHub

1. **وارد GitHub شوید:**
   - به [github.com](https://github.com) بروید
   - وارد حساب کاربری خود شوید

2. **Repository جدید ایجاد کنید:**
   - روی دکمه سبز "New" یا "+" کلیک کنید
   - "New repository" را انتخاب کنید

3. **تنظیمات Repository:**
   ```
   Repository name: subdomain-enumeration-tool
   Description: 🔍 Advanced Subdomain Enumeration Tool with HTTP/HTTPS Probing & Premium APIs
   Visibility: Public (یا Private اگر می‌خواهید)
   Initialize with: README (تایید کنید)
   Add .gitignore: Python (انتخاب کنید)
   Choose a license: MIT License (انتخاب کنید)
   ```

4. **Repository را ایجاد کنید:**
   - روی "Create repository" کلیک کنید

### روش 2: از طریق GitHub CLI (اگر نصب دارید)

```bash
# نصب GitHub CLI (اگر ندارید)
# Ubuntu/Debian:
sudo apt install gh

# macOS:
brew install gh

# Windows:
winget install GitHub.cli

# ورود به GitHub
gh auth login

# ایجاد repository
gh repo create subdomain-enumeration-tool --public --description "🔍 Advanced Subdomain Enumeration Tool with HTTP/HTTPS Probing & Premium APIs"
```

## مرحله 2: آپلود فایل‌ها

### روش 1: از طریق Git Commands

```bash
# Clone repository
git clone https://github.com/YOUR_USERNAME/subdomain-enumeration-tool.git
cd subdomain-enumeration-tool

# کپی کردن فایل‌ها از workspace
# (فایل‌های آماده شده در /workspace موجود هستند)

# اضافه کردن فایل‌ها
git add .

# Commit
git commit -m "🚀 Initial commit: Advanced Subdomain Enumeration Tool v2.0

✨ Features:
- Comprehensive subdomain enumeration with multiple discovery methods
- HTTP/HTTPS probing with live subdomain verification
- Premium API integration (Shodan, VirusTotal, SecurityTrails, etc.)
- Multiple output formats (JSON, CSV, TXT)
- Network scanning with Nmap integration
- Robust error handling and graceful fallbacks

🐛 Fixes in v2.0:
- Fixed CSV output file error (cannot access local variable)
- Fixed HTTPX probe error (cannot unpack non-iterable NoneType)
- Improved Nmap detection and PATH checking
- Fixed SSL certificate probing error
- Enhanced error handling throughout"

# Push به GitHub
git push origin main
```

### روش 2: از طریق GitHub Web Interface

1. **فایل‌ها را آپلود کنید:**
   - در صفحه repository روی "uploading an existing file" کلیک کنید
   - فایل‌های زیر را آپلود کنید:
     - `subdomains.py`
     - `config.py`
     - `demo.py`
     - `test.py`
     - `install.sh`
     - `setup.py`
     - `requirements.txt`
     - `README.md`
     - `API_SETUP_GUIDE.md`
     - `SUBDOMAIN_README.md`
     - `config.py.example`

2. **Commit message:**
   ```
   🚀 Initial commit: Advanced Subdomain Enumeration Tool v2.0
   ```

## مرحله 3: تنظیم Repository

### 1. اضافه کردن Topics/Tags:
```
subdomain, enumeration, security, penetration-testing, reconnaissance, httpx, nmap, python
```

### 2. اضافه کردن Badges (اختیاری):
```markdown
![Python](https://img.shields.io/badge/python-3.7+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Status](https://img.shields.io/badge/status-stable-brightgreen.svg)
```

### 3. تنظیم About Section:
```
🔍 Advanced Subdomain Enumeration Tool with HTTP/HTTPS Probing & Premium APIs. Comprehensive subdomain discovery with multiple techniques, live verification, and robust error handling.
```

## مرحله 4: ایجاد Release

1. **برو به Releases:**
   - در repository روی "Releases" کلیک کنید
   - "Create a new release" را انتخاب کنید

2. **تنظیمات Release:**
   ```
   Tag version: v2.0.0
   Release title: 🚀 Subdomain Enumeration Tool v2.0 - All Errors Fixed
   Description: 
   ## ✨ What's New in v2.0
   - Fixed all major errors
   - Enhanced error handling
   - Improved performance
   - Added comprehensive test suite
   - Ready for production use
   ```

3. **آپلود فایل‌ها:**
   - فایل‌های ZIP و TAR.GZ را آپلود کنید

## مرحله 5: استفاده از Repository

### Clone Repository:
```bash
git clone https://github.com/YOUR_USERNAME/subdomain-enumeration-tool.git
cd subdomain-enumeration-tool
```

### Download ZIP:
- از صفحه repository روی "Code" > "Download ZIP" کلیک کنید

### استفاده:
```bash
# نصب dependencies
pip3 install -r requirements.txt

# تست
python3 test.py

# استفاده
python3 subdomains.py -d example.com
```

## 🎯 فایل‌های آماده در Workspace

فایل‌های زیر در `/workspace` آماده هستند:
- `subdomains.py` - اسکریپت اصلی (رفع شده)
- `config.py` - تنظیمات API
- `demo.py` - مثال‌های استفاده
- `test.py` - تست‌سوییت
- `install.sh` - نصب‌کننده خودکار
- `setup.py` - نصب Python package
- `requirements.txt` - dependencies
- `README.md` - مستندات کامل
- `API_SETUP_GUIDE.md` - راهنمای API
- `SUBDOMAIN_README.md` - راهنمای subdomain enumeration
- `config.py.example` - الگوی تنظیمات

## 🚀 آماده برای استفاده!

حالا می‌تونی repository رو ایجاد کنی و فایل‌ها رو آپلود کنی. همه error ها رفع شدن و tool کاملاً functional هست! 🎯