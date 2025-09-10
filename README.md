# Router Brute Force Chrome v2.0

یک ابزار پیشرفته برای تست brute force روی روترها با استفاده از Chrome automation و گرفتن اسکرین‌شات از صفحه مدیریت.

## ویژگی‌ها

- **Chrome Automation**: استفاده از Chrome برای تست credential ها
- **تشخیص خودکار فرم لاگین**: پیدا کردن فیلدهای username و password
- **گرفتن اسکرین‌شات**: تصویربرداری از صفحه مدیریت پس از ورود موفق
- **استخراج اطلاعات روتر**: MAC address، firmware، model و غیره
- **پشتیبانی از چندین credential**: تست ترکیبات مختلف username/password
- **رابط کاربری رنگی**: نمایش نتایج با رنگ‌های مختلف

## نصب

1. نصب dependencies:
```bash
pip install -r requirements.txt
```

2. نصب ChromeDriver:
- **Windows**: دانلود از [ChromeDriver](https://chromedriver.chromium.org/) و اضافه کردن به PATH
- **Linux**: 
```bash
sudo apt-get install chromium-chromedriver
```
- **macOS**:
```bash
brew install chromedriver
```

## استفاده

### استفاده پایه
```bash
python router_brute_force_chrome.py -u "http://192.168.1.1"
```

### استفاده با چندین URL
```bash
python router_brute_force_chrome.py -u "http://192.168.1.1,http://192.168.1.2,http://192.168.1.3"
```

### استفاده با فایل
```bash
python router_brute_force_chrome.py -u urls.txt
```

### گزینه‌های اضافی
```bash
python router_brute_force_chrome.py -u "http://192.168.1.1" --no-headless --timeout 15
```

## پارامترها

- `-u, --urls`: URL(های) لاگین (اجباری)
- `-T, --threads`: تعداد thread ها (پیش‌فرض: 1)
- `--timeout`: timeout در ثانیه (پیش‌فرض: 10)
- `--no-headless`: اجرای Chrome در حالت قابل مشاهده
- `--no-screenshot`: غیرفعال کردن گرفتن اسکرین‌شات

## Credential های پیش‌فرض

ابزار این ترکیبات را تست می‌کند:
- admin:admin
- admin:support180
- support:support
- user:user
- admin:password
- admin:1234
- admin:12345
- admin:123456
- root:root
- root:admin
- admin:(خالی)
- (خالی):admin
- admin:admin123
- admin:password123
- guest:guest

## خروجی

- **اسکرین‌شات**: تصاویر با نام `screenshot_IP_username_password_timestamp.png`
- **اطلاعات روتر**: MAC address، firmware، model، SSID و غیره
- **گزارش کنسول**: نمایش نتایج با رنگ‌های مختلف

## مثال خروجی

```
[+] Admin access verified!
🔒 VULNERABLE: admin:admin works!
[+] Admin URL: http://192.168.1.1/dashboard
[*] Router Information:
[+] Page Title: Router Admin Panel
[+] Mac Address: 00:11:22:33:44:55
[+] Firmware Version: v1.2.3
[+] Model: TL-WR841N
[+] Screenshot saved: screenshot_192_168_1_1_admin_admin_20241201_143022.png
```

## نکات مهم

- این ابزار فقط برای تست امنیتی مجاز استفاده شود
- قبل از استفاده، مطمئن شوید که ChromeDriver نصب شده است
- در صورت بروز مشکل، Chrome را در حالت visible اجرا کنید (`--no-headless`)
- اسکرین‌شات‌ها در همان پوشه‌ای که اسکریپت اجرا می‌شود ذخیره می‌شوند

## عیب‌یابی

### خطای ChromeDriver
```
Error: ChromeDriver not found
```
**راه حل**: ChromeDriver را نصب کنید و به PATH اضافه کنید

### خطای Selenium
```
Error: Selenium not installed
```
**راه حل**: 
```bash
pip install selenium
```

### مشکل در تشخیص فرم لاگین
**راه حل**: Chrome را در حالت visible اجرا کنید تا ببینید چه اتفاقی می‌افتد:
```bash
python router_brute_force_chrome.py -u "http://192.168.1.1" --no-headless
```