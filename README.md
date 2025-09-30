# ARAT - Advanced Reconnaissance & Assessment Tool

یک ابزار جامع و پیشرفته برای reconnaissance و security assessment

## ویژگی‌های اصلی

### 🔍 10 فاز کامل Reconnaissance
- **فاز 1**: Real IP extraction و CDN bypass
- **فاز 2**: Subdomain discovery (active/passive)  
- **فاز 3**: Port scanning و service detection
- **فاز 4**: Technology detection
- **فاز 5**: Directory discovery و crawling
- **فاز 6**: Parameter discovery و JS analysis
- **فاز 7**: Endpoint discovery
- **فاز 8**: Cloud analysis
- **فاز 9**: OSINT analysis
- **فاز 10**: Vulnerability assessment

### 🌐 پنل وب پیشرفته
- رابط کاربری مدرن و responsive
- مدیریت real-time فازها
- نمایش گزارش‌های بصری

### 🔧 قابلیت‌های تکنیکی
- پردازش موازی نامحدود
- سیستم لاگ‌گیری پیشرفته
- مدیریت API keys
- پشتیبانی از 15+ سرویس خارجی

## نصب و راه‌اندازی

```bash
# نصب dependencies
pip install -r requirements.txt

# اجرای ابزار
python main.py --target example.com --all-phases

# شروع پنل وب
python main.py --web-panel --port 8080
```

## استفاده

### خط فرمان
```bash
# اجرای تمامی فازها
python main.py --target example.com --all-phases

# اجرای فاز مشخص
python main.py --target example.com --phase 2

# شروع پنل وب
python main.py --web-panel
```

## تنظیمات

فایل `config/config.yaml` را ویرایش کنید:

```yaml
api_keys:
  shodan: "your-api-key"
  virustotal: "your-api-key"
  # ... سایر API keys
```

## مجوز

این پروژه تحت مجوز MIT منتشر شده است.

**نکته امنیتی**: این ابزار فقط برای تست نفوذ قانونی استفاده شود.