# Advanced XSS Scanner

A focused XSS scanner that performs targeted reconnaissance and **real Chrome browser-based XSS testing** with context-aware payload injection.

## Features

- **XSS-Focused Reconnaissance**: Finds forms, parameters, and XSS testing points
- **Real Chrome Testing**: Uses actual Chrome browser to test XSS payloads
- **Alert Detection**: Automatically detects JavaScript alerts as proof of XSS
- **Context Detection**: Automatically detects HTML, JavaScript, CSS, and Attribute contexts
- **Context-Aware Payloads**: Tests only relevant payloads for each detected context
- **WAF Bypass**: Multiple encoding techniques (URL, Base64, Unicode, HTML entities)
- **PoC Screenshots**: Automatic screenshots of confirmed XSS vulnerabilities
- **False Positive Elimination**: Real browser testing eliminates false positives

## Installation

```bash
pip install -r requirements.txt
```

## Usage

```bash
python3 advanced_xss_scanner.py <target_url>
```

### Example
```bash
python3 advanced_xss_scanner.py https://example.com
```

## Output

- `xss_recon_report.json` - XSS reconnaissance findings
- `xss_report.json` - XSS vulnerability report
- `xss_poc_*.png` - Screenshots of confirmed vulnerabilities
- `xss_scanner.log` - Detailed logs

## Context-Aware Testing

The scanner automatically:
1. Detects the context where user input is reflected
2. Generates payloads specific to that context
3. Tests only relevant payloads for maximum efficiency
4. Reduces false positives by context-specific validation

## Security Notice

This tool is for educational and authorized testing purposes only. Always ensure you have proper authorization before testing any target.