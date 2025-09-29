# XSS Scanner - Advanced Chrome Edition

A comprehensive XSS scanner that uses Chrome/Playwright for complete reconnaissance, multi-level crawling, DOM sink detection, and browser-based payload testing. Generates POC upon successful injection.

## Features

- **Chrome-Based Reconnaissance**: Full browser crawling with JavaScript execution
- **Multi-Level Crawling**: Discovers and analyzes multiple pages automatically
- **DOM Sink Detection**: Precise context identification using browser DOM analysis
- **Context-Aware Testing**: HTML, Attribute, JavaScript, CSS, and URL contexts
- **Rich Payload Set**: 100+ XSS payloads mapped to contexts
- **Browser-Based Testing**: Real alert detection using Chrome
- **Fallback Support**: Falls back to requests if browser fails
- **Comprehensive Reporting**: POCs and detailed findings in JSON

## Install

```bash
pip install -r requirements.txt
playwright install chromium
```

## Usage

```bash
# Basic scan
python xss_scanner.py https://example.com

# Advanced scan with custom settings
python xss_scanner.py https://example.com -t 20 -d 0.5 --depth 5

# Visible browser mode (for debugging)
python xss_scanner.py https://example.com --no-headless
```

### Arguments
- `url`: Target URL to scan
- `-t, --threads`: Number of threads (default: 10)
- `-d, --delay`: Delay between requests in seconds (default: 1)
- `--depth`: Crawling depth levels (default: 3)
- `--no-headless`: Run browser in visible mode (default: headless)

## Sample Output

```
[INFO] Starting browser-based reconnaissance phase...
[SUCCESS] Browser initialized successfully
[INFO] Starting browser-based crawling (depth: 3)
[SUCCESS] Crawling completed. Found 25 URLs
[INFO] Total forms found: 8
[INFO] Total unique parameters: 15
[INFO] Starting comprehensive XSS scan...
[INFO] Scanning 25 URLs
[INFO] Scanning parameters for https://example.com...
[INFO] DOM sinks detected: ['html', 'attribute']
[INFO] Testing context: html
[VULN] XSS FOUND! Parameter: search, Context: html
[VULN] Payload: <script>alert("XSS")</script>
==================================================
XSS Scan Results
==================================================
[SUCCESS] Total findings: 3

--- Vulnerability 1 ---
[VULN] URL: https://example.com
[VULN] Parameter: search
[VULN] Context: html
[VULN] Method: GET
[VULN] Payload: <script>alert("XSS")</script>
[VULN] POC: https://example.com?search=%3Cscript%3Ealert%28%22XSS%22%29%3C%2Fscript%3E
[SUCCESS] Results saved to xss_results.json
[INFO] Browser closed successfully
```

## Advanced Features

### Multi-Level Crawling
- Automatically discovers and crawls linked pages
- Configurable depth levels
- Respects robots.txt (if available)

### DOM Sink Detection
- Analyzes actual DOM structure in browser
- Identifies precise reflection contexts
- Detects JavaScript execution contexts

### Browser-Based Testing
- Real alert() detection using Chrome
- Handles complex JavaScript applications
- Better detection of DOM-based XSS

## Output Files

- `xss_results.json`: Complete findings with browser detection flags

## Requirements

- Python 3.7+
- Chrome/Chromium browser
- Playwright (installed via pip and playwright install)

## Security Notes

- Use this tool only on targets you own or are authorized to test
- Obtain all required permissions before scanning
- Do not use this tool for illegal purposes
- Browser mode may be detected by some security systems

## Support

Open an issue for bugs or feature requests.