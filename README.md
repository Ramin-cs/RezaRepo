# 🔍 Open Redirect Vulnerability Scanner

A professional-grade Open Redirect vulnerability scanner that performs comprehensive reconnaissance and testing with advanced WAF bypass techniques.

## 🚀 Quick Start

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Run the Scanner
```bash
# Basic scan
python SCAN.py https://target-website.com

# Advanced scan
python SCAN.py https://target-website.com --output results --threads 20 --depth 3

# Using presets
python SCAN.py --preset thorough https://target-website.com
```

### 3. Test Functionality
```bash
# Test all modules
python SCAN.py --test

# Show capabilities
python SCAN.py --capabilities
```

## 📋 Features

### 🔍 Comprehensive Reconnaissance
- **URL Parameters**: Extracts all redirect-related parameters
- **Form Parameters**: Analyzes forms for redirect fields
- **JavaScript Variables**: Scans for redirect-related JS variables
- **Meta Tags**: Checks for meta refresh redirects
- **HTTP Headers**: Analyzes custom redirect headers
- **Cookie Parameters**: Examines redirect-related cookies

### 🎯 Advanced Payload Generation
- **149 Redirect Parameters**: Comprehensive parameter detection
- **43 JavaScript Patterns**: Advanced JS redirect detection
- **4 Meta Refresh Patterns**: Meta tag redirect detection
- **43 Header Patterns**: HTTP header redirect detection
- **18 Base Payloads**: Core redirect payloads
- **78 Bypass Techniques**: Advanced WAF bypass methods

### 🛡️ WAF Bypass Techniques
- **Encoding**: URL, Unicode, Hex, Octal, Base64, HTML/XML Entity
- **Character Manipulation**: Case, Whitespace, Control Characters
- **Advanced**: Unicode Normalization, IDN Homograph, Punycode

### 🖼️ Proof of Concept
- **Screenshot Capture**: Automatic PoC screenshots
- **Chrome Integration**: Real browser testing
- **Redirect Verification**: Confirms actual redirects

### 📊 Professional Reporting
- **HTML Reports**: Beautiful, detailed vulnerability reports
- **Request Details**: Complete request/response information
- **Screenshot Evidence**: Visual proof of vulnerabilities
- **Logging**: Comprehensive debug and error logging

## 🏗️ Project Structure

```
open_redirect_scanner/
├── SCAN.py                     # Main executable file (USE THIS)
├── RUN_SCANNER.py              # Alternative executable file
├── main.py                     # Alternative entry point
├── open_redirect_scanner.py    # Core scanner class
├── recon_module.py             # Reconnaissance module
├── payload_module.py           # Payload generation module
├── chrome_module.py            # Chrome automation module
├── report_module.py            # HTML report generation
├── logging_module.py           # Logging system
├── configuration.py            # Configuration management
├── requirements.txt            # Python dependencies
├── README.md                   # This file
└── scan_results/              # Output directory (created automatically)
```

## 🔧 Configuration

### Presets
- **fast**: Quick scan with basic parameters
- **thorough**: Comprehensive scan with all techniques
- **stealth**: Stealth mode with minimal detection
- **debug**: Debug mode with verbose logging

### Options
- `--output DIR`: Output directory (default: scan_results)
- `--threads NUM`: Number of threads (default: 10)
- `--depth NUM`: Maximum depth (default: 3)
- `--preset PRESET`: Use preset configuration

## 🎯 Vulnerability Types Detected

### URL Parameter Redirects
- `?url=`, `?redirect=`, `?next=`, `?return=`, `?goto=`
- And 144+ more redirect parameters

### Form Parameter Redirects
- Hidden fields with redirect values
- Form actions with redirect URLs
- Input values containing redirects

### JavaScript Variable Redirects
- `window.location` assignments
- `document.location` modifications
- `location.href` changes
- And 40+ more JS patterns

### Meta Tag Redirects
- `<meta http-equiv="refresh">` tags
- Meta refresh with redirect URLs

### Cookie Parameter Redirects
- Redirect-related cookie values
- Session redirect parameters

### HTTP Header Redirects
- Custom redirect headers
- Location header modifications

## 🛡️ WAF Bypass Techniques

### Encoding Techniques
- **URL Encoding**: Single and double encoding
- **Unicode Encoding**: Unicode character variations
- **Hex Encoding**: Hexadecimal representation
- **Octal Encoding**: Octal character codes
- **Mixed Encoding**: Combination of encoding methods
- **Base64 Encoding**: Base64 encoded payloads
- **HTML/XML Entity Encoding**: Entity character codes

### Character Manipulation
- **Case Variations**: Uppercase, lowercase, mixed case
- **Whitespace Variations**: Spaces, tabs, newlines
- **Control Character Injection**: Null bytes, control chars
- **Newline Injection**: Line break variations
- **Tab Injection**: Tab character variations

### Advanced Techniques
- **Unicode Normalization**: Unicode character normalization
- **IDN Homograph Attacks**: Internationalized domain names
- **Punycode Encoding**: Punycode representation
- **Protocol Variations**: HTTP, HTTPS, FTP, etc.
- **Path Manipulation**: URL path variations

## 📊 Example Payloads

The scanner generates 144+ payloads for each target, including:

```
//google.com
//\u0067oo\u0067le.com
//g\u006f\u006fgle.c\u006fm
//goog\u006ce.com
2f2f676f6f676c652e636f6d
//\147oo\147le.com
//g\157\157gle.c\157m
//goog\154e.com
//%67%6f%6fg%6ce.com
//GOOGLE.COM
```

## 🚀 Usage Examples

### Basic Usage
```bash
python SCAN.py https://target-website.com
```

### Advanced Usage
```bash
python SCAN.py https://target-website.com --output results --threads 20 --depth 3
```

### Preset Usage
```bash
python SCAN.py --preset thorough https://target-website.com
python SCAN.py --preset stealth https://target-website.com
python SCAN.py --preset debug https://target-website.com
```

### Testing
```bash
python SCAN.py --test
python SCAN.py --capabilities
```

## 📋 Requirements

### System Requirements
- Python 3.8+
- Chrome browser (for full functionality)
- 4GB+ RAM recommended
- 1GB+ free disk space

### Python Dependencies
- `aiohttp`: Async HTTP client
- `beautifulsoup4`: HTML parsing
- `selenium`: Browser automation
- `webdriver-manager`: Chrome driver management
- `lxml`: XML/HTML processing
- `urllib3`: HTTP utilities
- `requests`: HTTP library
- `pathlib`: Path utilities
- `json5`: JSON parsing

## 🔧 Installation

### 1. Clone Repository
```bash
git clone <repository-url>
cd open_redirect_scanner
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Install Chrome
```bash
# Ubuntu/Debian
sudo apt-get install google-chrome-stable

# CentOS/RHEL
sudo yum install google-chrome-stable

# macOS
brew install --cask google-chrome

# Windows
# Download from https://www.google.com/chrome/
```

### 4. Run Scanner
```bash
python SCAN.py --test
```

## 📊 Output

### HTML Report
- Beautiful, professional vulnerability report
- Screenshot evidence for each vulnerability
- Complete request/response details
- Vulnerability classification and severity

### Log Files
- Comprehensive debug logging
- Error tracking and reporting
- Performance metrics
- Scan progress tracking

### Screenshots
- PoC screenshots for confirmed vulnerabilities
- Redirect verification images
- Evidence of successful exploitation

## 🛡️ Security Notice

This tool is designed for authorized security testing only. Always ensure you have proper authorization before testing any target. The authors are not responsible for any misuse of this tool.

## 🤝 Contributing

Contributions are welcome! Please read the contributing guidelines and submit pull requests for any improvements.

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 Support

For support, please:
1. Check the documentation
2. Run `python SCAN.py --test` to verify installation
3. Check log files for error details
4. Submit issues with detailed information

## 🚀 Performance Tips

- Use appropriate thread counts (10-20 for most systems)
- Adjust depth based on target complexity
- Use stealth preset for sensitive targets
- Monitor system resources during scanning

## 📈 Updates

Regular updates include:
- New payload techniques
- WAF bypass methods
- Performance improvements
- Bug fixes and enhancements

---

**Ready to scan? Run: `python SCAN.py --test`**

## 🎯 Quick Commands

```bash
# Test everything
python SCAN.py --test

# Show capabilities
python SCAN.py --capabilities

# Run a scan
python SCAN.py https://target-website.com

# Advanced scan
python SCAN.py https://target-website.com --output results --threads 20 --depth 3

# Using presets
python SCAN.py --preset thorough https://target-website.com
```

The scanner is ready to use! 🎉

## 🔧 Fixed Issues

- ✅ Fixed directory creation error (`parents=True` added)
- ✅ Removed duplicate executable files
- ✅ Cleaned up project structure
- ✅ Fixed Windows path issues
- ✅ Improved error handling

## 📁 Files to Use

- **Main File**: `SCAN.py` - Use this for scanning
- **Alternative**: `RUN_SCANNER.py` - Alternative executable
- **Full Scanner**: `main.py` - Complete scanner with all features
- **Documentation**: `README.md` - This file

## 🚀 Ready to Use!

The scanner is now fully functional and ready to use. All directory creation issues have been fixed, and the scanner will work properly on both Windows and Linux systems.

**Start scanning now:**
```bash
python SCAN.py https://static.mgm.mo/redirection/tc/?targetURL= --output results --threads 20 --depth 3
```