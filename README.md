# Advanced XSS Scanner

Complete XSS vulnerability detection tool with all functionality in one file.

## Features

- ✅ **Full Reconnaissance**: Automatic parameter and form discovery
- ✅ **WAF Detection**: Detect and bypass WAF protection
- ✅ **Custom Popup System**: Unique popup for XSS verification
- ✅ **All XSS Types**: Reflected, Stored, DOM-based, and Blind XSS
- ✅ **Comprehensive Reporting**: Detailed JSON reports

## Installation

```bash
# Install dependencies
pip install -r requirements.txt

# Make executable
chmod +x xss_scanner.py
```

## Usage

```bash
# Basic scan
python3 xss_scanner.py https://example.com

# Advanced scan with report
python3 xss_scanner.py https://example.com -o report.json -v

# Without crawling
python3 xss_scanner.py https://example.com --no-crawl
```

## Example Output

```
╔══════════════════════════════════════════════════════════════╗
║                  Advanced XSS Scanner v1.0.0                ║
║              Complete Reconnaissance & Exploitation          ║
╚══════════════════════════════════════════════════════════════╝

=== XSS Scan Summary ===
Target: https://example.com
Total Vulnerabilities: 2
Reflected XSS: 1
Stored XSS: 1

=== Vulnerabilities Found ===
1. Reflected XSS - search parameter
2. Stored XSS - comment field
```

## Security Note

⚠️ **Only use on systems you own or have permission to test!**

This tool is for authorized security testing only.