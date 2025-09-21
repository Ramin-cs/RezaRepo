# Advanced XSS Scanner v2.0

A comprehensive XSS scanner that performs deep reconnaissance and advanced XSS testing with context detection and WAF bypass capabilities.

## Features

### Phase 1: Deep Reconnaissance
- **DNS Enumeration**: Discovers subdomains and DNS records
- **Port Scanning**: Identifies open ports and services
- **Web Crawling**: Comprehensive crawling with depth control
- **Form Discovery**: Extracts all forms and input parameters
- **Technology Detection**: Identifies web technologies and frameworks
- **Sensitive File Discovery**: Finds potentially sensitive files and directories

### Phase 2: XSS Scanning
- **Context Detection**: Automatically detects HTML, JavaScript, CSS, and URL contexts
- **Advanced Payloads**: Comprehensive payload library with encoding variations
- **WAF Bypass**: Multiple encoding and obfuscation techniques
- **Screenshot Capture**: Automatic PoC screenshots for confirmed vulnerabilities
- **False Positive Reduction**: Advanced detection mechanisms to minimize false positives

## Installation

1. Install Python 3.7 or higher
2. Install required dependencies:
```bash
pip install -r requirements.txt
```

3. Install Chrome WebDriver (for screenshot capture):
```bash
# Ubuntu/Debian
sudo apt-get install chromium-chromedriver

# macOS
brew install chromedriver

# Windows
# Download from https://chromedriver.chromium.org/
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

The scanner generates two main reports:

1. **recon_report.json**: Detailed reconnaissance findings
2. **xss_report.json**: XSS vulnerability report with PoC screenshots

## Advanced Features

### Context-Aware Payloads
- **HTML Context**: Script tags, event handlers, and HTML elements
- **Attribute Context**: Event handlers in HTML attributes
- **JavaScript Context**: Code injection in JavaScript blocks
- **CSS Context**: Expression and URL functions in CSS
- **URL Context**: JavaScript and data protocols in URLs

### WAF Bypass Techniques
- URL encoding and decoding
- HTML entity encoding
- Base64 encoding
- Unicode encoding
- Case variation
- Whitespace manipulation
- Comment injection
- Alternative HTML tags

### Payload Categories
- Basic XSS payloads
- Polyglot payloads
- Encoded variations
- Context-specific payloads
- WAF bypass payloads

## Configuration

The scanner can be configured by modifying the following parameters in the code:

- `max_depth`: Maximum crawling depth (default: 3)
- `max_threads`: Maximum concurrent threads (default: 10)
- `timeout`: Request timeout in seconds (default: 10)

## Screenshots

When a vulnerability is confirmed, the scanner automatically:
1. Takes a screenshot of the vulnerable page
2. Saves it with a timestamp and URL hash
3. Includes the screenshot path in the vulnerability report

## Logging

The scanner provides detailed logging with different levels:
- INFO: General information and progress
- WARNING: Non-critical issues
- ERROR: Critical errors and failures

Logs are saved to `xss_scanner.log` and displayed in the console.

## Security Notice

This tool is for educational and authorized testing purposes only. Always ensure you have proper authorization before testing any target. The authors are not responsible for any misuse of this tool.

## Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for bugs and feature requests.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- XSStrike for inspiration and payload techniques
- OWASP for security guidelines
- The security community for continuous research and development