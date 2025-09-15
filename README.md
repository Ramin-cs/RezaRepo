# Router Brute Force Chrome v2.0

A Chrome-based router login brute force tool that opens a visible browser and tests default credentials sequentially.

## Features

- **Chrome-based**: Uses Selenium WebDriver with Chrome for realistic browser automation
- **Visible Browser**: Chrome runs visibly so you can see the attack in real-time
- **Sequential Testing**: Tests credentials one by one in order
- **Screenshot Capture**: Takes screenshots of successful logins and failed attempts
- **Cross-platform**: Works on Windows, Linux, and macOS
- **English Interface**: All messages and output in English
- **Target Credentials**: Tests exactly 4 credential sets as specified

## Target Credentials

The tool tests these exact credentials in order:
1. `admin:admin`
2. `admin:support180`
3. `support:support`
4. `user:user`

## Installation

1. Install Python 3.7 or higher
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Install ChromeDriver:
   - **Windows**: Download from https://chromedriver.chromium.org/ and add to PATH
   - **Linux**: `sudo apt-get install chromium-chromedriver` or download manually
   - **macOS**: `brew install chromedriver` or download manually

## Usage

### Basic Usage
```bash
python router_brute_force_chrome.py -u http://192.168.1.1
```

### Advanced Usage
```bash
# Run with custom timeout
python router_brute_force_chrome.py -u http://192.168.1.1 --timeout 15

# Run in headless mode (invisible browser)
python router_brute_force_chrome.py -u http://192.168.1.1 --headless

# Custom screenshot directory
python router_brute_force_chrome.py -u http://192.168.1.1 --screenshot-dir my_screenshots
```

### Command Line Options

- `-u, --url`: Login URL to test (required)
- `--timeout`: Page load timeout in seconds (default: 10)
- `--headless`: Run Chrome in headless mode (default: visible)
- `--screenshot-dir`: Directory to save screenshots (default: screenshots)

## How It Works

1. **Initialize Chrome**: Opens Chrome browser (visible by default)
2. **Navigate to URL**: Goes to the specified login page
3. **Detect Form**: Automatically finds username and password fields
4. **Test Credentials**: Tests each credential set sequentially:
   - Fills username and password fields
   - Clicks submit button or presses Enter
   - Waits for page to load
   - Analyzes page content to determine success
5. **Screenshot**: Takes screenshots of all attempts
6. **Report Results**: Shows which credentials worked

## Screenshots

The tool creates a `screenshots` directory and saves:
- `initial_page_[username]_[password].png` - Initial page load
- `success_[username]_[password].png` - Successful login
- `failed_[username]_[password].png` - Failed login attempt

## Success Detection

The tool determines login success by analyzing:
- Page content for admin panel indicators
- URL changes from login page
- Presence of router management elements
- Absence of login form elements

## Cross-Platform Support

### Windows
- Uses `chromedriver.exe`
- Checks common installation paths
- Supports Windows-style paths

### Linux
- Uses `chromedriver` binary
- Checks system paths like `/usr/bin/chromedriver`
- Supports package manager installations

### macOS
- Uses `chromedriver` binary
- Checks Homebrew and system paths
- Supports macOS-specific Chrome installations

## Security Notice

This tool is for authorized security testing only. Only use on:
- Your own routers
- Routers you have explicit permission to test
- Routers in controlled lab environments

## Troubleshooting

### ChromeDriver Issues
- Ensure ChromeDriver is installed and in PATH
- Check ChromeDriver version matches your Chrome version
- Try running with `--headless` if display issues occur

### Network Issues
- Check if the router URL is accessible
- Try different timeout values with `--timeout`
- Ensure no firewall is blocking the connection

### Form Detection Issues
- Some routers use non-standard form field names
- The tool tries multiple common field name patterns
- Check screenshots to see what the tool detected

## Example Output

```
[*] STARTING CHROME BRUTE FORCE ATTACK
[*] Target URL: http://192.168.1.1
============================================================

[1/4] Testing credential set 1
[>] Testing credentials: admin:admin
[+] Screenshot saved: screenshots/initial_page_admin_admin.png
[-] Login failed: Admin indicators: 1, Login indicators: 3
[+] Screenshot saved: screenshots/failed_admin_admin.png

[2/4] Testing credential set 2
[>] Testing credentials: admin:support180
[+] Screenshot saved: screenshots/initial_page_admin_support180.png
[+] Login successful! Strong admin content detected: 4 indicators
🔒 VULNERABLE: admin:support180 works!
[+] Screenshot saved: screenshots/success_admin_support180.png

[+] BRUTE FORCE ATTACK COMPLETED
============================================================
[!] VULNERABLE CREDENTIALS FOUND:
  • admin:support180
    Screenshot: screenshots/success_admin_support180.png
```

## License

For authorized security testing only. Use responsibly and legally.