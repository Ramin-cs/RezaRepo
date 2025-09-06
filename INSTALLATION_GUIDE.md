# Advanced XSS Scanner - Installation & Usage Guide

## 🚀 Quick Installation

### Method 1: Automatic Installation (Recommended)
```bash
# Make the installation script executable
chmod +x install.sh

# Run the installation script
./install.sh
```

### Method 2: Manual Installation
```bash
# 1. Install system dependencies
sudo apt update
sudo apt install python3 python3-pip python3-venv chromium-browser

# 2. Create virtual environment
python3 -m venv xss_scanner_env
source xss_scanner_env/bin/activate

# 3. Install Python packages
pip install --upgrade pip
pip install -r requirements.txt

# 4. Install ChromeDriver
pip install webdriver-manager

# 5. Make scripts executable
chmod +x xss_scanner.py demo.py test_xss_scanner.py example_usage.py
```

## 🎯 How to Run

### Basic Usage
```bash
# Activate virtual environment (if using manual installation)
source xss_scanner_env/bin/activate

# Basic scan
python3 xss_scanner.py https://example.com

# Advanced scan with options
python3 xss_scanner.py https://example.com -o report.json -v

# Scan without crawling
python3 xss_scanner.py https://example.com --no-crawl

# Scan with callback URL for Blind XSS
python3 xss_scanner.py https://example.com --callback-url http://your-server.com/callback
```

### Demo and Examples
```bash
# Run interactive demo
python3 demo.py

# Run usage examples
python3 example_usage.py

# Run test suite
python3 test_xss_scanner.py
```

## 📋 Command Line Options

```bash
python3 xss_scanner.py [TARGET_URL] [OPTIONS]

Options:
  -o, --output FILE        Output file for scan report
  --no-crawl              Disable URL crawling
  --callback-url URL      Callback URL for blind XSS testing
  -v, --verbose           Verbose output with detailed logging
  -h, --help              Show help message
```

## 🔧 Configuration

### Environment Variables
```bash
# Set custom timeout (default: 30 seconds)
export XSS_TIMEOUT=60

# Set custom user agent
export XSS_USER_AGENT="Custom User Agent"

# Set proxy (optional)
export HTTP_PROXY=http://proxy:8080
export HTTPS_PROXY=http://proxy:8080
```

### Configuration File
Create `config.json`:
```json
{
  "timeout": 30,
  "max_depth": 2,
  "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
  "callback_url": "http://localhost:8080/callback",
  "enable_crawling": true,
  "screenshot_enabled": true,
  "waf_detection": true
}
```

## 🛠️ Troubleshooting

### Common Issues

#### 1. ChromeDriver Error
```bash
# Install webdriver-manager
pip install webdriver-manager

# Or install ChromeDriver manually
wget https://chromedriver.storage.googleapis.com/LATEST_RELEASE
```

#### 2. Permission Denied
```bash
# Make scripts executable
chmod +x xss_scanner.py

# Or run with python3 directly
python3 xss_scanner.py https://example.com
```

#### 3. Module Import Error
```bash
# Install missing dependencies
pip install -r requirements.txt

# Or install individually
pip install requests beautifulsoup4 selenium aiohttp lxml
```

#### 4. Virtual Environment Issues
```bash
# Create new virtual environment
python3 -m venv new_env
source new_env/bin/activate
pip install -r requirements.txt
```

### Debug Mode
```bash
# Enable debug logging
python3 xss_scanner.py https://example.com -v

# Check log file
tail -f xss_scanner.log
```

## 📊 Output Examples

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

## 🔒 Security Considerations

### Legal Usage
- ✅ Only use on systems you own or have explicit permission to test
- ✅ Follow responsible disclosure practices
- ✅ Respect robots.txt and rate limiting
- ❌ Do not use for malicious purposes
- ❌ Do not test on systems without permission

### Best Practices
1. **Always get permission** before testing
2. **Use responsibly** - don't overload target servers
3. **Report findings** to website owners
4. **Keep results confidential** until fixed
5. **Follow responsible disclosure** timeline

## 📈 Performance Tips

### Optimization
```bash
# Use faster settings for large scans
python3 xss_scanner.py https://example.com --no-crawl -t 10

# Run multiple instances for different targets
python3 xss_scanner.py https://site1.com &
python3 xss_scanner.py https://site2.com &
```

### Resource Management
- Monitor CPU and memory usage during scans
- Use `--no-crawl` for faster scans
- Set appropriate timeouts for your network
- Consider running scans during off-peak hours

## 🆘 Getting Help

### Documentation
- `README.md` - Complete documentation
- `FINAL_SUMMARY.md` - Project overview
- `QUICK_START.md` - Quick start guide

### Support
- Check log files for error details
- Run test suite: `python3 test_xss_scanner.py`
- Use verbose mode: `python3 xss_scanner.py -v`

### Community
- Report issues and bugs
- Contribute improvements
- Share your findings (responsibly)

---

**Remember**: This tool is for authorized security testing only. Always get permission before scanning any target!