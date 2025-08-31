# Advanced XSS Scanner
## Professional XSS Detection Tool

A professional and advanced Cross-Site Scripting (XSS) detection tool with Matrix-style interface, popup verification, and comprehensive reporting.

## 🎯 Key Features

### 🔍 **Deep Reconnaissance**
- Automatic test point identification (parameters, forms, headers)
- Deep crawling of internal links
- JavaScript analysis for DOM XSS
- Hidden endpoint discovery

### 🎯 **Advanced Testing**
- **Context-Aware Testing**: Detects context and uses appropriate payloads
- **Advanced Fuzzing**: Tests blocked and filtered characters
- **WAF Bypass**: Multiple techniques to bypass Web Application Firewalls
- **Multi-Method Testing**: Tests both GET and POST methods
- **Header Testing**: Tests HTTP headers for XSS
- **CRLF Injection**: Tests CRLF injection in all parameters

### 🛡️ **Security & Stealth**
- Rate limiting to avoid WAF detection
- Random User-Agent rotation
- Configurable delays between requests
- Parallel processing with thread control

### ✅ **Bug Verification System**
- **Custom Popup**: Uses unique popup signature for verification
- **Selenium Integration**: Confirms bugs with WebDriver (when available)
- **Screenshot Capture**: Takes screenshots of confirmed bugs WITH popup visible
- **Smart Scoring**: Intelligent scoring system based on bug type and impact

### 📊 **Professional Reporting**
- Beautiful HTML reports with Matrix theme
- JSON reports for automated processing
- Complete scan statistics
- Screenshot storage for confirmed bugs

## 🚀 Installation & Setup

### Prerequisites
- Python 3.7+
- Google Chrome Browser (optional, for popup verification)
- ChromeDriver (optional, for popup verification)

### Quick Install
```bash
# Install Python packages
pip3 install --break-system-packages -r requirements.txt

# Optional: Install ChromeDriver for popup verification
# Linux: sudo apt-get install chromium-chromedriver
# macOS: brew install chromedriver
# Windows: Download from https://chromedriver.chromium.org/
```

## 📖 Usage

### Basic Usage
```bash
python3 xss_scanner.py -u https://example.com
```

### Advanced Usage
```bash
# Deep scan with custom settings
python3 xss_scanner.py -u https://example.com -d 5 --delay 2

# Quick scan
python3 xss_scanner.py -u https://target.com -d 2 --delay 0.5

# Test with vulnerable demo
python3 demo.py -p 8080 &
python3 xss_scanner.py -u http://localhost:8080
```

### Command Line Options
- `-u, --url`: Target URL (required)
- `-d, --depth`: Maximum crawl depth (default: 3)
- `--delay`: Delay between requests in seconds (default: 1.0)
- `--timeout`: Request timeout in seconds (default: 15)
- `-h, --help`: Show help message

## 🎯 Vulnerability Types Detected

### 1. Reflected XSS
- URL parameter testing
- Form field testing
- HTTP header testing

### 2. Form XSS
- All form input fields
- POST and GET methods
- Context-aware payload testing

### 3. Header-based XSS
- User-Agent, Referer, X-Forwarded-For
- Custom header injection

### 4. CRLF Injection
- HTTP header injection
- Set-Cookie injection testing

## 🔧 Supported Contexts

### HTML Context
```html
<div>USER_INPUT</div>
```
Payloads: `<script>`, `<img>`, `<svg>`, etc.

### Attribute Context (with Tag Closing)
```html
<input value="USER_INPUT">
```
Payloads: `"><img src=x onerror=alert()>`, `" onmouseover="alert()"`, etc.

### JavaScript Context
```html
<script>var data = 'USER_INPUT';</script>
```
Payloads: `'; alert(); //`, `</script><script>alert()</script>`, etc.

### URL Context
```html
<a href="USER_INPUT">
```
Payloads: `javascript:alert()`, `data:text/html,<script>`, etc.

## 🛡️ WAF Bypass Techniques

- **Case Manipulation**: `<ScRiPt>alert(1)</ScRiPt>`
- **URL Encoding**: `%3Cscript%3Ealert(1)%3C/script%3E`
- **HTML Entities**: `&lt;script&gt;alert(1)&lt;/script&gt;`
- **Alternative Tags**: `<img>`, `<svg>`, `<iframe>`
- **Event Handlers**: `onload`, `onerror`, `onfocus`
- **Tag Closing**: `"><img src=x onerror=alert(1)>`

## 📊 Scoring System

### Scoring Criteria
- **Reflected XSS**: 20 points
- **Form XSS**: 20 points
- **Header-based XSS**: 15 points
- **CRLF Injection**: 15 points

### Verification Requirements
1. **Correct Context Execution**: Payload must execute in appropriate context
2. **Popup Verification**: Custom signature popup must be shown (when Selenium available)
3. **Screenshot Capture**: Screenshot taken WITH popup visible
4. **Strict Analysis**: Only confirmed executable vulnerabilities reported

## 📁 Output Files

### HTML Report
- Complete and beautiful report with Matrix theme
- Detailed scan statistics
- All confirmed vulnerabilities displayed
- Links to screenshots

### JSON Report
- Raw data for processing
- Importable into other tools
- Complete technical details

### Screenshots
- Captured for each confirmed bug
- Shows popup when visible
- Stored in `screenshots/` directory
- Systematic naming for tracking

## 🎮 Matrix Theme Interface

```
╔══════════════════════════════════════════════════════════════════════╗
║  ██╗  ██╗███████╗███████╗    ███████╗ ██████╗ █████╗ ███╗   ██╗███████╗██████╗  ║
║  [+] Advanced Cross-Site Scripting Detection Framework     ║
║  [+] Professional Penetration Testing Tool               ║
║  [+] WAF Bypass • Context-Aware • Popup Verified         ║
╚══════════════════════════════════════════════════════════════════════╝

[!] Initializing neural network... DONE
[!] Loading payload database... DONE  
[!] Activating stealth mode... DONE
[!] Popup verification system... READY
```

## 🎯 Example Output

```
[CONFIRMED] XSS VULNERABILITY CONFIRMED!
[PARAM] q
[URL] https://target.com/search?q=<script>alert("XSS_SCANNER_CONFIRMED_abc123")</script>
[PAYLOAD] <script>alert("XSS_SCANNER_CONFIRMED_abc123")</script>
[CONTEXT] html_context
[SCORE] 20/20
[SCREENSHOT] Captured popup: screenshots/xss_param_q_1_popup.png
```

## 🔧 Files Structure

- **`xss_scanner.py`** - Main scanner (complete tool)
- **`demo.py`** - Vulnerable server for testing
- **`test_scanner.py`** - Automated testing
- **`requirements.txt`** - Python dependencies
- **`setup.py`** - Installation script
- **`run_demo.sh/bat`** - Quick demo scripts

## ⚠️ Security Notice

**Important Warning**: This tool should only be used on websites you own or have explicit permission to test. Unauthorized use may violate local and international laws.

## 🎯 Compatibility

- ✅ Linux (Ubuntu, CentOS, Debian)
- ✅ Windows (10, 11)
- ✅ macOS (Big Sur, Monterey, Ventura)

## 🔍 Testing

Test the scanner with the included vulnerable demo server:

```bash
# Start demo server
python3 demo.py -p 8080 &

# Run scanner against demo
python3 xss_scanner.py -u http://localhost:8080

# Check results
ls screenshots/
```

## 📝 License

This project is released under the MIT License.

## 🐛 Support & Bug Reports

For bug reports or feature requests, please create an issue.

---

**Happy Hunting! 🔍🛡️**