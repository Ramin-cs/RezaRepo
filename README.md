# Advanced XSS Scanner
## Professional XSS Detection Tool with Matrix Theme

A professional Cross-Site Scripting (XSS) detection tool with popup verification and comprehensive reporting.

## 🎯 Main File

**`xss_scanner.py`** - The complete XSS scanner (69KB)

This is the ONLY file you need to run. All functionality is included in this single file.

## 🚀 Quick Start

### 1. Install Dependencies
```bash
pip3 install --break-system-packages -r requirements.txt
```

### 2. Run Scanner
```bash
# Basic scan
python3 xss_scanner.py -u https://target.com

# Advanced scan
python3 xss_scanner.py -u https://target.com -d 5 --delay 2

# Quick test with demo server
python3 demo.py -p 8080 &
python3 xss_scanner.py -u http://localhost:8080
```

## 🎯 Features

### ✅ **Advanced Detection**
- Context-aware payload testing (HTML, Attribute, JavaScript, URL)
- Tag closing attacks: `"><img src=x onerror=alert()>`
- WAF bypass techniques
- Deep crawling and reconnaissance

### ✅ **Verification System**
- Popup verification with Selenium (when available)
- Fallback verification with context analysis
- Screenshot capture WITH popup visible
- Only confirmed vulnerabilities reported

### ✅ **Professional Output**
- Matrix-style hacker interface
- Stops testing after vulnerability confirmed
- Beautiful HTML reports
- JSON reports for automation

## 🎮 Matrix Theme UI

```
╔══════════════════════════════════════════════════════════════════════╗
║  ██╗  ██╗███████╗███████╗    ███████╗ ██████╗ █████╗ ███╗   ██╗███████╗██████╗  ║
║  [+] Advanced Cross-Site Scripting Detection Framework     ║
║  [+] Professional Penetration Testing Tool               ║
║  [+] WAF Bypass • Context-Aware • Popup Verified         ║
╚══════════════════════════════════════════════════════════════════════╝

[CONFIRMED] XSS VULNERABILITY CONFIRMED!
[PARAM] q
[PAYLOAD] <img src=x onerror=alert("XSS_SCANNER_CONFIRMED_abc123")>
[SCORE] 20/20
[SUCCESS] Vulnerability confirmed - stopping tests for q
```

## 📁 File Structure

### 🔧 **Essential Files:**
- **`xss_scanner.py`** - Main scanner (USE THIS FILE) ⭐
- **`requirements.txt`** - Python dependencies
- **`README.md`** - This guide

### 🧪 **Optional Files:**
- **`demo.py`** - Vulnerable server for testing
- **`setup.py`** - Installation helper
- **`test_scanner.py`** - Automated testing
- **`run_demo.sh/bat`** - Quick demo scripts

## 🎯 Command Line Options

- `-u, --url`: Target URL (required)
- `-d, --depth`: Crawl depth (default: 3)
- `--delay`: Delay between requests (default: 1.0)
- `--timeout`: Request timeout (default: 15)

## 🔍 Example Usage

```bash
# Test real vulnerable site
python3 xss_scanner.py -u http://testphp.vulnweb.com

# Quick scan
python3 xss_scanner.py -u https://target.com -d 2 --delay 0.5

# Deep scan
python3 xss_scanner.py -u https://target.com -d 5 --delay 2
```

## 📊 Output Files

After scanning, you'll get:
- `xss_scan_report_YYYYMMDD_HHMMSS.html` - Beautiful HTML report
- `xss_scan_report_YYYYMMDD_HHMMSS.json` - JSON data
- `screenshots/` - Screenshots of confirmed vulnerabilities (if Selenium available)

## ⚠️ Important Notes

1. **Only use on authorized targets**
2. **Install ChromeDriver for popup verification** (optional but recommended)
3. **Check internet connection if scanning external sites**
4. **Use demo server for testing functionality**

## 🎯 What Makes This Special

- ✅ **Single file solution** - No confusion about which file to run
- ✅ **Popup verification** - Only confirms real vulnerabilities
- ✅ **Smart testing** - Stops after finding vulnerability
- ✅ **Matrix theme** - Professional hacker interface
- ✅ **Tag closing attacks** - Advanced payload techniques
- ✅ **WAF bypass** - Multiple evasion techniques

---

**Run `python3 xss_scanner.py -u TARGET_URL` and start hunting! 🔍🛡️**