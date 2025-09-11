# Router Brute Force Chrome v2.0

## 🎯 Features
- **Chrome Automation**: Always visible Chrome browser
- **4 Target Credentials**: admin:admin, admin:support180, support:support, user:user
- **7 Authentication Types**: HTTP Basic, Digest, Form, API, Redirect, JavaScript, Cookie
- **Alert Handling**: Automatic detection and handling of login failure alerts
- **Screenshot Capture**: Takes screenshots of successful admin panel access
- **HTML & TXT Reports**: Comprehensive reports with embedded screenshots
- **Cross-platform**: Windows, Linux, macOS

## 🚀 Quick Start

### 1. Setup
```bash
# Install dependencies
pip install -r requirements.txt

# Download ChromeDriver (if needed)
python simple_chromedriver.py
```

### 2. Usage
```bash
# Test single URL
python test_single_url.py "http://192.168.1.1"

# Full scan
python router_brute_force_chrome.py -u "http://192.168.1.1"

# Multiple URLs
python router_brute_force_chrome.py -u "http://192.168.1.1,http://192.168.1.2"
```

### 3. Help
```bash
python router_brute_force_chrome.py --help
```

## 📊 Output

### Console Output
```
[>] Testing: admin:admin
[*] Detected auth type: form_based
[+] Login successful!
[+] Admin access verified!
🔒 VULNERABLE: admin:admin works!
[+] Admin URL: http://192.168.1.1/dashboard
[+] Screenshot saved: screenshot_192_168_1_1_admin_admin_20241201_143022.png
[+] HTML report generated: router_brute_force_report_20241201_143022.html
[+] TXT report generated: router_brute_force_report_20241201_143022.txt
```

### Reports
- **HTML Report**: Interactive report with embedded screenshots
- **TXT Report**: Plain text summary with all details
- **Screenshots**: PNG files of successful admin panel access

## 🔧 Troubleshooting

### ChromeDriver Issues
```bash
python simple_chromedriver.py
```

### Chrome Detection
```bash
python find_chrome.py
```

### Test Installation
```bash
python test_chrome.py
```

## 📁 Files
- `router_brute_force_chrome.py` - Main script
- `test_single_url.py` - Single URL tester
- `test_chrome.py` - Chrome setup tester
- `simple_chromedriver.py` - ChromeDriver downloader
- `find_chrome.py` - Chrome detection tool
- `requirements.txt` - Python dependencies
- `README_FINAL.md` - This file

## ⚠️ Important Notes
- Use only on authorized networks
- Respect rate limiting
- Use responsibly for security testing
- Keep credentials secure

## 🎯 Target Credentials
1. admin:admin
2. admin:support180
3. support:support
4. user:user

## 🔐 Authentication Types
1. HTTP Basic Authentication
2. HTTP Digest Authentication
3. Form-based Authentication
4. API-based Authentication
5. Redirect-based Authentication
6. JavaScript-based Authentication
7. Cookie-based Authentication