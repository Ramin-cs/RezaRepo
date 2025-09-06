# 🚀 How to Run Advanced XSS Scanner

## 🎯 Quick Start (Easiest Way)

### 1. Install Dependencies
```bash
# Automatic installation (recommended)
./install.sh

# OR Manual installation
sudo apt update
sudo apt install python3 python3-pip python3-venv chromium-browser
pip3 install requests beautifulsoup4 selenium aiohttp lxml webdriver-manager
```

### 2. Run the Scanner
```bash
# Simple scan
python3 run_scanner.py https://example.com

# Advanced scan with all features
python3 run_scanner.py https://example.com --advanced

# With custom report file
python3 run_scanner.py https://example.com --advanced --output my_report.json
```

## 🔧 Alternative Methods

### Method 1: Using the Main Scanner
```bash
# Basic usage
python3 xss_scanner.py https://example.com

# Advanced usage
python3 xss_scanner.py https://example.com -o report.json -v

# Without crawling
python3 xss_scanner.py https://example.com --no-crawl
```

### Method 2: Using Virtual Environment
```bash
# Create virtual environment
python3 -m venv xss_env
source xss_env/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run scanner
python3 xss_scanner.py https://example.com
```

## 🎮 Demo and Examples

### Run Demo
```bash
python3 run_scanner.py --demo
# OR
python3 demo.py
```

### Run Examples
```bash
python3 example_usage.py
```

### Run Tests
```bash
python3 run_scanner.py --test
# OR
python3 test_xss_scanner.py
```

## 📋 Command Options

### Basic Options
```bash
python3 run_scanner.py [TARGET_URL] [OPTIONS]

Options:
  --advanced            Run advanced scan with all features
  --output, -o FILE     Output file for report
  --no-crawl           Disable URL crawling
  --callback-url URL   Callback URL for blind XSS testing
  --verbose, -v        Verbose output
  --demo               Run demo mode
  --test               Run test suite
  --check-deps         Check dependencies
```

### Advanced Options
```bash
# Full feature scan
python3 xss_scanner.py https://example.com \
  --advanced \
  --output detailed_report.json \
  --callback-url http://your-server.com/callback \
  --verbose

# Quick scan without crawling
python3 xss_scanner.py https://example.com \
  --no-crawl \
  --output quick_report.json
```

## 🎯 Example Commands

### 1. Basic Scan
```bash
python3 run_scanner.py https://httpbin.org/get
```

### 2. Advanced Scan
```bash
python3 run_scanner.py https://example.com --advanced --output report.json
```

### 3. Demo Mode
```bash
python3 run_scanner.py --demo
```

### 4. Test Dependencies
```bash
python3 run_scanner.py --check-deps
```

## 📊 Expected Output

### Console Output
```
╔══════════════════════════════════════════════════════════════╗
║                  Advanced XSS Scanner v1.0.0                ║
║              Complete Reconnaissance & Exploitation          ║
╚══════════════════════════════════════════════════════════════╝

🎯 Target: https://example.com
⏳ Please wait...

📊 Scan completed!
🔍 Target: https://example.com
📅 Timestamp: 2024-01-15T10:30:00
🚨 Total Vulnerabilities: 3
   - Reflected XSS: 2
   - Stored XSS: 1
   - DOM XSS: 0
   - Blind XSS: 0

🎯 Vulnerabilities Found:
   1. Reflected XSS (WAF Bypassed)
      Parameter: search
      Payload: <ScRiPt>alert("XSS")</ScRiPt>...
      WAF Bypassed: cloudflare
      Screenshot: /tmp/xss_poc_1642248600.png

📄 Report saved to: xss_scan_report_1642248600.json

✅ Scan completed successfully!
```

### JSON Report File
```json
{
  "target": "https://example.com",
  "timestamp": "2024-01-15T10:30:00",
  "summary": {
    "total_vulnerabilities": 3,
    "reflected_xss": 2,
    "stored_xss": 1,
    "dom_xss": 0,
    "blind_xss": 0
  },
  "vulnerabilities": [
    {
      "type": "Reflected XSS (WAF Bypassed)",
      "parameter": "search",
      "payload": "<ScRiPt>alert(\"XSS\")</ScRiPt>",
      "waf_type": "cloudflare",
      "url": "https://example.com?search=<ScRiPt>alert(\"XSS\")</ScRiPt>",
      "poc_screenshot": "/tmp/xss_poc_1642248600.png"
    }
  ],
  "reconnaissance": {
    "discovered_params": ["search", "id", "user"],
    "discovered_forms": 2,
    "discovered_urls": 15,
    "waf_detected": {
      "detected": true,
      "type": "cloudflare",
      "confidence": 85
    }
  }
}
```

## 🛠️ Troubleshooting

### Common Issues and Solutions

#### 1. "Module not found" Error
```bash
# Install missing dependencies
pip3 install requests beautifulsoup4 selenium

# Or install all dependencies
pip3 install -r requirements.txt
```

#### 2. "Permission denied" Error
```bash
# Make scripts executable
chmod +x xss_scanner.py run_scanner.py

# Or run with python3 directly
python3 xss_scanner.py https://example.com
```

#### 3. "ChromeDriver" Error
```bash
# Install webdriver-manager
pip3 install webdriver-manager

# Or install ChromeDriver manually
sudo apt install chromium-browser
```

#### 4. "Virtual environment" Error
```bash
# Install python3-venv
sudo apt install python3-venv

# Create virtual environment
python3 -m venv xss_env
source xss_env/bin/activate
pip install -r requirements.txt
```

### Debug Mode
```bash
# Run with verbose output
python3 run_scanner.py https://example.com --verbose

# Check log file
tail -f xss_scanner.log
```

## 🔒 Security Notes

### Important Reminders:
- ✅ **Only test systems you own or have permission to test**
- ✅ **Follow responsible disclosure practices**
- ✅ **Respect rate limits and don't overload servers**
- ❌ **Never use for malicious purposes**
- ❌ **Don't test systems without permission**

### Best Practices:
1. Always get written permission before testing
2. Use appropriate delays between requests
3. Report findings responsibly
4. Keep results confidential until fixed
5. Follow responsible disclosure timeline

## 📞 Getting Help

### Check Dependencies
```bash
python3 run_scanner.py --check-deps
```

### Run Tests
```bash
python3 run_scanner.py --test
```

### View Logs
```bash
cat xss_scanner.log
```

### Documentation
- `README_ENGLISH.md` - Complete documentation
- `INSTALLATION_GUIDE.md` - Detailed installation guide
- `FINAL_SUMMARY.md` - Project overview

---

**Ready to scan? Start with:**
```bash
python3 run_scanner.py https://example.com
```