# Router Brute Force Chrome v2.0

Advanced Chrome-based router brute force tool with screenshot capture and cross-platform support.

## Features

- **Chrome Automation**: Uses Chrome browser for credential testing
- **Automatic Login Form Detection**: Finds username and password fields automatically
- **Screenshot Capture**: Takes screenshots of admin panels after successful login
- **Router Information Extraction**: MAC address, firmware, model, etc.
- **Cross-platform Support**: Windows, Linux, macOS
- **Always Visible Chrome**: Chrome runs in visible mode for user interaction
- **Comprehensive Reporting**: HTML and TXT reports with screenshots
- **Limited Credentials**: Tests only 4 specific credential combinations

## Quick Installation

**Automated Installation (Recommended):**
```bash
python3 install.py
```

**Manual Installation:**

1. Install Python packages:
```bash
pip install -r requirements.txt
```

2. Install ChromeDriver:
- **Windows**: Download from [ChromeDriver](https://chromedriver.chromium.org/) and add to PATH
- **Linux**: 
```bash
sudo apt-get install chromium-chromedriver
```
- **macOS**:
```bash
brew install chromedriver
```

## Usage

### Basic Usage
```bash
python3 router_brute_force_chrome.py -u "http://192.168.1.1"
```

### Multiple URLs
```bash
python3 router_brute_force_chrome.py -u "http://192.168.1.1,http://192.168.1.2,http://192.168.1.3"
```

### From File
```bash
python3 router_brute_force_chrome.py -u urls.txt
```

### Additional Options
```bash
python3 router_brute_force_chrome.py -u "http://192.168.1.1" --timeout 15
```

## Parameters

- `-u, --urls`: Login URL(s) (required)
- `-T, --threads`: Number of threads (default: 1)
- `--timeout`: Request timeout in seconds (default: 10)
- `--no-headless`: Run Chrome in visible mode (default: always visible)
- `--no-screenshot`: Disable screenshot capture (default: enabled)

## Target Credentials

The tool tests only these 4 combinations:
- admin:admin
- admin:support180
- support:support
- user:user

## Output

- **Screenshots**: Images with name `screenshot_IP_username_password_timestamp.png`
- **Router Information**: MAC address, firmware, model, SSID, etc.
- **HTML Report**: Comprehensive report with screenshots embedded
- **TXT Report**: Detailed text report with all findings
- **Console Output**: Colored results display

## Example Output

```
[+] Admin access verified!
🔒 VULNERABLE: admin:admin works!
[+] Admin URL: http://192.168.1.1/dashboard
[*] Router Information:
[+] Page Title: Router Admin Panel
[+] Mac Address: 00:11:22:33:44:55
[+] Firmware Version: v1.2.3
[+] Model: TL-WR841N
[+] Screenshot saved: screenshot_192_168_1_1_admin_admin_20241201_143022.png
[+] HTML report generated: router_brute_force_report_20241201_143022.html
[+] TXT report generated: router_brute_force_report_20241201_143022.txt
```

## Important Notes

- This tool is for authorized security testing only
- Chrome always runs in visible mode for user interaction
- Screenshots are saved in the same directory as the script
- Reports are generated automatically after each scan
- Cross-platform support: Windows, Linux, macOS

## Troubleshooting

### ChromeDriver Error
```
Error: ChromeDriver not found
```
**Solution**: Run the installer: `python3 install.py`

### Selenium Error
```
Error: Selenium not installed
```
**Solution**: 
```bash
pip install selenium
```

### Chrome Not Found
**Solution**: Install Google Chrome from https://www.google.com/chrome/

### Test Installation
```bash
python3 test_chrome.py
```