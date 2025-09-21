# Advanced XSS Scanner

A focused XSS scanner that performs targeted reconnaissance and **real Chrome browser-based XSS testing** with context-aware payload injection and **improved alert handling**.

## Features

- **XSS-Focused Reconnaissance**: Finds forms, parameters, and XSS testing points
- **Real Chrome Testing**: Uses actual Chrome browser to test XSS payloads
- **Improved Alert Detection**: Enhanced alert handling with unique IDs and multiple detection attempts
- **Context Detection**: Automatically detects HTML, JavaScript, CSS, and Attribute contexts
- **Context-Aware Payloads**: Tests only relevant payloads for each detected context
- **WAF Bypass**: Multiple encoding techniques (URL, Base64, Unicode, HTML entities)
- **PoC Screenshots**: Automatic screenshots of confirmed XSS vulnerabilities
- **False Positive Elimination**: Real browser testing eliminates false positives
- **Enhanced JavaScript Analysis**: Deep analysis of JS files for parameter discovery
- **Parallel Processing**: Unlimited parallel processing for speed optimization

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
python3 advanced_xss_scanner.py http://testphp.vulnweb.com
```

## Key Improvements

### Alert Handling
- **Unique Alert IDs**: Each scan uses a unique alert identifier to avoid confusion with site alerts
- **Multiple Detection Attempts**: The scanner tries multiple times to detect and handle alerts
- **Improved Screenshot Timing**: Screenshots are captured before alert dismissal
- **Better Error Handling**: Robust error handling for Selenium WebDriver issues

### Enhanced Reconnaissance
- **Deeper JavaScript Analysis**: Analyzes more JS files and extracts more parameters
- **Removed Irrelevant Phases**: Removed "Sensitive Files" reconnaissance as it's not XSS-relevant
- **Better Parameter Discovery**: Enhanced parameter discovery from multiple sources

## Output

The scanner generates:
- Console output with real-time progress
- `xss_vulnerabilities_report.json` - Detailed JSON report
- `screenshots/` directory with PoC screenshots

## Troubleshooting

If you encounter the "unexpected alert open" error:
1. The scanner now handles this automatically with improved alert detection
2. Multiple detection attempts are made before giving up
3. Screenshots are captured before alert dismissal to ensure PoC generation

## Technical Details

### Alert Detection Algorithm
1. **Unique ID Generation**: Each scan generates a unique alert ID (e.g., `XSS_SCANNER_56217`)
2. **Payload Injection**: Payloads are modified to include the unique ID
3. **Multi-Attempt Detection**: Multiple attempts to detect and handle alerts
4. **Screenshot Capture**: Screenshots are taken before alert dismissal
5. **Reflection Check**: If no alert, checks for payload reflection in executable context

### Error Resolution
The "unexpected alert open" error has been resolved by:
- Implementing robust alert detection with multiple attempts
- Proper screenshot timing before alert dismissal
- Enhanced error handling for WebDriver exceptions
- Fallback to reflection checking when alerts fail