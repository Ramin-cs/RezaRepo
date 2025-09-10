# Quick Fix for ChromeDriver Version Mismatch

## Problem
The error you're seeing is because ChromeDriver version 140 is incompatible with Chrome version 139.

## Solution

### Option 1: Automatic Fix (Recommended)
```bash
python auto_chromedriver.py
```

### Option 2: Complete Setup
```bash
python setup.py
```

### Option 3: Manual Fix
1. Delete the current ChromeDriver:
   ```bash
   del chromedriver.exe  # Windows
   rm chromedriver       # Linux/macOS
   ```

2. Download compatible ChromeDriver:
   ```bash
   python auto_chromedriver.py
   ```

3. Test the fix:
   ```bash
   python test_chrome.py
   ```

## What's New in v2.0

### ✅ Fixed Issues
- **ChromeDriver Version Mismatch**: Auto-downloads compatible version
- **Multiple Authentication Types**: Supports 7 different auth methods
- **Better Login Detection**: Improved success/failure detection
- **Session Management**: Maintains login session for admin panel navigation

### 🔧 Authentication Types Supported
1. **HTTP Basic Authentication**
2. **HTTP Digest Authentication** 
3. **Form-based Authentication**
4. **API-based Authentication**
5. **Redirect-based Authentication**
6. **JavaScript-based Authentication**
7. **Cookie-based Authentication**

### 🚀 Usage
```bash
# Test single URL
python test_single_url.py "http://192.168.1.1"

# Full scan
python router_brute_force_chrome.py -u "http://192.168.1.1"

# Multiple URLs
python router_brute_force_chrome.py -u "http://192.168.1.1,http://192.168.1.2"
```

### 📊 Features
- **Always Visible Chrome**: You can see the entire process
- **Smart Detection**: Automatically detects authentication type
- **Session Persistence**: Maintains login session for admin panel
- **Comprehensive Reports**: HTML and TXT reports with screenshots
- **Cross-platform**: Works on Windows, Linux, macOS

## Troubleshooting

### ChromeDriver Error
```bash
python auto_chromedriver.py
```

### Chrome Not Found
Install Google Chrome from: https://www.google.com/chrome/

### Test Installation
```bash
python test_chrome.py
```

## Expected Output
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