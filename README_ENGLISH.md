# Advanced XSS Scanner - Complete XSS Vulnerability Detection & Exploitation Tool

## 🎯 Key Features

### 🔍 Complete Reconnaissance
- **Web Crawling**: Automatic URL and page discovery
- **Parameter Discovery**: Hidden and embedded parameter detection
- **Form Analysis**: Complete form and input field analysis
- **Header Analysis**: Headers and cookies examination
- **Response Analysis**: Response analysis for injection points

### 🛡️ WAF Detection & Bypass
- **WAF Detection**: Cloudflare, Incapsula, Akamai, AWS WAF, and others
- **Bypass Techniques**: 
  - Encoding variations (URL, HTML entities, Unicode, Base64)
  - Case manipulation
  - Comment injection
  - Parameter pollution
  - Header injection
  - Chunked encoding
  - Null byte injection
  - Unicode normalization

### 🎯 Support for All XSS Types
- **Reflected XSS**: Complete testing with WAF bypass
- **Stored XSS**: Testing with custom popup verification
- **DOM-based XSS**: Testing with browser automation
- **Blind XSS**: Testing with callback server

### 🎨 Custom Popup System
- **No Interference**: Won't interfere with browser popups
- **Complete Information**: Display URL, time, cookies, and details
- **Screenshot**: PoC screenshot capture
- **Unique ID**: Unique identifier for each popup

### 📊 Complete Reporting
- **JSON Report**: Complete report in JSON format
- **Screenshot PoC**: Proof of concept screenshot
- **WAF Analysis**: WAF analysis and bypass methods
- **Detailed Logging**: Complete operation logging

## 🚀 Installation & Setup

### Prerequisites
```bash
# Python 3.8+
sudo apt update
sudo apt install python3 python3-pip

# Chrome/Chromium
sudo apt install chromium-browser

# ChromeDriver
pip install webdriver-manager
```

### Install Dependencies
```bash
pip install -r requirements.txt
```

## 💻 Usage

### Quick Start
```bash
# Simple run
python3 run_scanner.py https://example.com

# Advanced run
python3 run_scanner.py https://example.com --advanced

# Run with custom options
python3 run_scanner.py https://example.com --advanced --output report.json
```

### Basic Usage
```bash
python3 xss_scanner.py https://example.com
```

### Advanced Usage
```bash
# With custom report
python3 xss_scanner.py https://example.com -o custom_report.json

# Without crawling
python3 xss_scanner.py https://example.com --no-crawl

# With callback URL for Blind XSS
python3 xss_scanner.py https://example.com --callback-url http://your-server.com/callback

# With verbose output
python3 xss_scanner.py https://example.com -v
```

### Programmatic Usage
```python
from xss_scanner import XSSScanner

# Configuration
options = {
    'crawl': True,
    'callback_url': 'http://your-server.com/callback'
}

# Create scanner
scanner = XSSScanner('https://example.com', options)

# Run scan
results = scanner.run_scan()

# Save report
scanner.save_report(results, 'my_report.json')
```

## 🎯 XSS Types Support

### ✅ Fully Implementable:
1. **Reflected XSS**: ✅
2. **Stored XSS**: ✅  
3. **DOM-based XSS**: ✅
4. **Blind XSS**: ✅

### ⚠️ Limited Implementation:
1. **Self-XSS**: Requires user interaction
2. **Mutation XSS**: Complex and browser-specific

## 🔧 Advanced Features

### Context-Aware Payloads
- **HTML Context**: `<script>`, `<img>`, `<svg>`, `<iframe>`
- **Attribute Context**: `onmouseover`, `onfocus`, `onerror`
- **JavaScript Context**: `;alert()`, `';alert()`, `";alert()`
- **CSS Context**: `expression()`, `url()`, `@import`
- **URL Context**: `javascript:`, `data:`, `vbscript:`

### WAF Bypass Techniques
- **Cloudflare**: Encoding, case variation, comment injection
- **Incapsula**: Double encoding, null bytes, chunked encoding
- **Akamai**: Header injection, parameter fragmentation
- **AWS WAF**: Encoding variations, case manipulation
- **ModSecurity**: Unicode normalization, comment bypass

### Custom Popup Features
- **Visual Confirmation**: Visual vulnerability confirmation
- **No Browser Conflicts**: No interference with browser alerts
- **Detailed Information**: Complete page and time information
- **Screenshot Capability**: Screenshot functionality
- **Unique Identification**: Unique identifier

## 📊 Sample Output

### JSON Report
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
  ]
}
```

### Console Output
```
=== XSS Scan Summary ===
Target: https://example.com
Total Vulnerabilities: 3
Reflected XSS: 2
Stored XSS: 1
DOM XSS: 0
Blind XSS: 0

=== Vulnerabilities Found ===
1. Reflected XSS (WAF Bypassed) - search parameter
2. Stored XSS - comment field
3. Reflected XSS - user parameter
```

## 🔒 Security Considerations

⚠️ **Warning**: This tool should only be used for authorized security testing. Unauthorized use is prohibited.

### Recommendations:
- Only use on systems you own or have written permission to test
- Check local laws before use
- Keep results confidential
- Report findings to website owners

## 🛠️ Troubleshooting

### Common Issues:
1. **ChromeDriver Error**: `pip install webdriver-manager`
2. **Permission Denied**: `chmod +x xss_scanner.py`
3. **Import Error**: `pip install -r requirements.txt`

### Logs:
- Logs are saved in `xss_scanner.log` file
- Use `-v` for more detailed debugging

## 📁 File Structure

```
/workspace/
├── xss_scanner.py          # Main scanner file
├── waf_bypass.py           # WAF bypass system
├── custom_popup.py         # Custom popup system
├── run_scanner.py          # Easy runner script
├── demo.py                 # Demo file
├── test_xss_scanner.py     # Complete tests
├── example_usage.py        # Usage examples
├── requirements.txt        # Dependencies
├── setup.py               # Package installation
├── install.sh             # Installation script
├── INSTALLATION_GUIDE.md  # Installation guide
├── README_ENGLISH.md      # This file
└── QUICK_START.md         # Quick start guide
```

## 🚀 Quick Commands

```bash
# Install and run
./install.sh
python3 run_scanner.py https://example.com

# Run demo
python3 demo.py

# Run examples
python3 example_usage.py

# Run tests
python3 test_xss_scanner.py
```

## 📈 Contributing

To contribute to this project:
1. Fork the repository
2. Create a new branch
3. Make your changes
4. Submit a pull request

## 📄 License

This project is released under the MIT License.

---

**Note**: This tool is designed for educational and security testing purposes. Use responsibly.