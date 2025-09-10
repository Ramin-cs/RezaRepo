# Chrome Detection & ChromeDriver Fix

## مشکل: Chrome not found or version detection failed

### راه حل 1: تشخیص Chrome (تست کنید)
```bash
python find_chrome.py
```

### راه حل 2: دانلود ساده ChromeDriver
```bash
python simple_chromedriver.py
```

### راه حل 3: نصب دستی Chrome

#### Windows:
1. برو به: https://www.google.com/chrome/
2. دانلود و نصب کنید
3. Chrome را باز کنید و version را چک کنید

#### Linux:
```bash
# Ubuntu/Debian
sudo apt update
sudo apt install google-chrome-stable

# یا
wget -q -O - https://dl.google.com/linux/linux_signing_key.pub | sudo apt-key add -
echo "deb [arch=amd64] http://dl.google.com/linux/chrome/deb/ stable main" | sudo tee /etc/apt/sources.list.d/google-chrome.list
sudo apt update
sudo apt install google-chrome-stable
```

#### macOS:
```bash
# با Homebrew
brew install --cask google-chrome

# یا از سایت دانلود کنید
# https://www.google.com/chrome/
```

### راه حل 4: دانلود دستی ChromeDriver

1. Chrome version خود را پیدا کنید:
   - Chrome را باز کنید
   - برو به: chrome://version/
   - نسخه را کپی کنید (مثل: 139.0.7258.155)

2. ChromeDriver دانلود کنید:
   - برو به: https://chromedriver.chromium.org/downloads
   - نسخه متناسب با Chrome خود را دانلود کنید
   - فایل را extract کنید
   - `chromedriver.exe` را در پوشه پروژه قرار دهید

### تست نهایی:
```bash
python test_chrome.py
```

## اگر هنوز مشکل دارید:

### Windows:
```bash
# بررسی مسیر Chrome
where chrome
where chrome.exe

# بررسی در registry
reg query "HKEY_CURRENT_USER\Software\Google\Chrome\BLBeacon" /v version
```

### Linux:
```bash
# بررسی مسیر Chrome
which google-chrome
which chromium-browser

# بررسی version
google-chrome --version
chromium-browser --version
```

### macOS:
```bash
# بررسی مسیر Chrome
which google-chrome
which chromium

# بررسی version
google-chrome --version
chromium --version
```

## خروجی مورد انتظار:
```
============================================================
Chrome Detection Tool
============================================================
Searching for Chrome on Windows...
Checking: C:\Program Files\Google\Chrome\Application\chrome.exe
Found Chrome at: C:\Program Files\Google\Chrome\Application\chrome.exe
Chrome version: 139.0.7258.155

✅ Chrome found! Version: 139.0.7258.155
```

## بعد از حل مشکل:
```bash
# تست کامل
python router_brute_force_chrome.py -u "http://192.168.1.1"

# یا تست تک URL
python test_single_url.py "http://192.168.1.1"
```