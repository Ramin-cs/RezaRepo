# XSS Scanner - Advanced

A complete XSS scanner that performs reconnaissance, identifies reflection contexts, and tests context-aware payloads. Generates POC upon successful injection.

## Features

- **Full Reconnaissance**: Extracts forms, links, and URL parameters
- **Context Detection**: HTML, Attribute, JavaScript, CSS, and URL contexts
- **Rich Payload Set**: 100+ XSS payloads mapped to contexts
- **Automated Testing**: GET and POST testing, success detection via `alert`
- **Reporting**: Prints POCs and saves findings to JSON
- **Colored Output**: Easier-to-read logs

## Install

```bash
pip install -r requirements.txt
```

## Usage

```bash
# Basic
python xss_scanner.py https://example.com

# With options
python xss_scanner.py https://example.com -t 20 -d 0.5
```

### Arguments
- `url`: Target URL to scan
- `-t, --threads`: Number of threads (default: 10)
- `-d, --delay`: Delay between requests in seconds (default: 1)

## Sample Output

```
[INFO] Starting Reconnaissance phase...
[SUCCESS] Successful request to https://example.com
[INFO] Number of forms found: 3
[INFO] Number of links found: 15
[INFO] Number of URL parameters: 2
[INFO] Starting XSS scan...
[INFO] Scanning URL parameters...
[INFO] Scanning parameter: search
[INFO] Testing context: html
[VULN] XSS FOUND! Parameter: search, Context: html
[VULN] Payload: <script>alert("XSS")</script>
==================================================
XSS Scan Results
==================================================
[SUCCESS] Total findings: 1

--- Vulnerability 1 ---
[VULN] URL: https://example.com
[VULN] Parameter: search
[VULN] Context: html
[VULN] Method: GET
[VULN] Payload: <script>alert("XSS")</script>
[VULN] POC: https://example.com?search=%3Cscript%3Ealert%28%22XSS%22%29%3C%2Fscript%3E
[SUCCESS] Results saved to xss_results.json
```

## Output Files

- `xss_results.json`: Full findings in JSON format

## Security Notes

- Use this tool only on targets you own or are authorized to test
- Obtain all required permissions before scanning
- Do not use this tool for illegal purposes

## Support

Open an issue for bugs or feature requests.