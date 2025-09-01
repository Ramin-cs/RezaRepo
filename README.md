# 🔒 Router Scanner Pro v7.0

**Comprehensive Brand Detection & Session Management - Professional Network Security Tool**

## 🚀 **What's New in Version 7.0?**

### **🔍 Comprehensive Global Brand Detection**
- **18+ Router Brands**: TP-Link, Huawei, ZTE, Netgear, Linksys, D-Link, ASUS, FritzBox, DrayTek, MikroTik, Ubiquiti, Cisco, Belkin, Buffalo, Tenda, Xiaomi, Technicolor, Sagemcom
- **Multi-method detection**: Content, headers, server headers, and paths
- **Model identification**: Detects specific router models and series
- **Priority-based testing**: Brand-specific paths tested first

### **🎯 Advanced Session Management**
- **Real admin verification**: Actually enters admin panel with proper session
- **Session cookies**: Checks for valid authentication cookies
- **Logout detection**: Identifies logout buttons/links for verification
- **Credential optimization**: Stops testing after finding valid credentials

### **🚫 Smart False Positive Filtering**
- **Router-aware filtering**: Only filters if no router indicators present
- **Context-sensitive**: Considers router-related keywords
- **Reduced false positives**: More accurate detection of genuine router pages

### **📊 Professional HTML Reporting**
- **Beautiful reports**: Modern, responsive HTML design
- **Comprehensive data**: All scan results with detailed information
- **Visual indicators**: Color-coded vulnerabilities and status
- **Export ready**: Professional reports for documentation

## 🎨 **Features**

### **🔍 Global Brand Detection System**
- **18+ Router Brands**: Comprehensive coverage of global router manufacturers
- **Model identification**: Specific router models and series detection
- **Priority paths**: Brand-specific login paths tested first
- **Smart fallback**: Generic paths if brand not detected

### **🎯 Session Management**
- **Real admin access**: Actually enters admin panel
- **Session verification**: Checks for valid authentication cookies
- **Admin indicators**: Dashboard, status, configuration, control panel
- **Information extraction**: MAC address, firmware, model, WAN IP, SSID, SIP

### **🚫 False Positive Prevention**
- **Router-aware filtering**: Only filters non-router pages
- **Context analysis**: Considers router-related keywords
- **Smart detection**: Advanced pattern matching for accuracy

### **📊 HTML Reporting**
- **Professional design**: Modern, responsive HTML reports
- **Comprehensive data**: All scan results with detailed information
- **Visual indicators**: Color-coded vulnerabilities and status
- **Export ready**: Professional reports for documentation

## 🎯 **Target Credentials**

The tool tests these specific credentials:
- `admin:admin`
- `admin:support180`
- `support:support`
- `user:user`

## 🚀 **Installation**

### **Requirements**
```bash
pip install requests urllib3
```

### **Download & Setup**
```bash
# Download the tool
# Make executable (Linux/macOS)
chmod +x router_scanner_pro.py

# Windows users can run directly
python router_scanner_pro.py
```

## 💻 **Usage**

### **Basic Commands**
```bash
# Scan single IP
python3 router_scanner_pro.py -t 192.168.1.1

# Scan CIDR range
python3 router_scanner_pro.py -t 192.168.1.0/24

# Scan IP range
python3 router_scanner_pro.py -t 192.168.1.1-192.168.1.254

# Scan from file
python3 router_scanner_pro.py -t targets.txt
```

### **Advanced Options**
```bash
# Custom timeout
python3 router_scanner_pro.py -t targets.txt --timeout 15

# Single thread for organized output (default)
python3 router_scanner_pro.py -t targets.txt -T 1
```

## 📊 **Live Output Example**

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                    ROUTER SCANNER PRO - v7.0                                ║
║            Comprehensive Brand Detection & Session Management               ║
║                                                                              ║
║  🔍 Global Brand Detection  |  🎯 Session Management                       ║
║  📊 HTML Reporting          |  📸 Screenshot Capture                       ║
╚══════════════════════════════════════════════════════════════════════════════╝

[+] Loaded 3 targets
[+] Starting organized scan of 3 targets
[*] Target credentials: admin:admin, admin:support180, support:support, user:user
[*] Scanning ports: 80, 8080, 443, 8443, 8000, 8081, 8888, 8090, 9000, 9090
[*] Comprehensive brand detection with session management
[*] Organized workflow: Ports → Brand → Login → Brute Force → Admin Verification → HTML Report
--------------------------------------------------------------------------------

============================================================
[*] SCANNING TARGET: 192.168.1.1
============================================================
[1/4] Port Scanning...
[+] Found 1 open ports: [80]
[2/4] Brand Detection & Login Discovery...
[*] Detected brand: TP-LINK
[+] LOGIN PAGE FOUND: http://192.168.1.1:80/userRpm/LoginRpm.htm (form_based)
[3/4] Brute Force Attack...
[>] Testing: admin:admin
🔒 VULNERABLE: admin:admin works!
[+] Admin URL: http://192.168.1.1/admin
[4/4] Admin Verification & Information Extraction...
[+] Admin access verified!
[+] Mac Address: 00:1A:2B:3C:4D:5E
[+] Firmware Version: v1.0.0
[+] Model: TL-WR840N
[+] Wan Ip: 192.168.1.1
[+] Ssid: MyWiFi_Network
[+] Sip Info: sip@provider.com
[+] Uptime: 5 days 12 hours
[+] Connection Type: PPPoE
[+] Target 192.168.1.1 scan completed
[*] Progress: 1/3 (33.3%) - Login pages: 1, Vulnerable: 1

============================================================
[+] SCAN COMPLETE!
============================================================
[*] Summary:
  - Total targets scanned: 3
  - Login pages found: 1
  - Vulnerable routers: 1
  - Scan duration: 45.2 seconds
  - Average speed: 0.1 targets/second
[*] Advanced detection and verification completed successfully
[*] Generating HTML report...
[+] HTML report generated: router_scan_report_20250901_210936.html
[+] Report saved: router_scan_report_20250901_210936.html
```

## 🔧 **Comprehensive Brand Detection**

### **Supported Router Brands**
```python
BRAND_PATTERNS = {
    'tp-link': ['tp-link', 'tplink', 'TP-LINK', 'TPLINK', 'archer', 'TL-'],
    'huawei': ['huawei', 'HUAWEI', 'HG', 'B593', 'E5186', 'HG8245'],
    'zte': ['zte', 'ZTE', 'ZXHN', 'MF28G', 'F660', 'F670L'],
    'netgear': ['netgear', 'NETGEAR', 'WNDR', 'R7000', 'N600', 'WNR'],
    'linksys': ['linksys', 'LINKSYS', 'WRT', 'E1200', 'E2500', 'E3200'],
    'd-link': ['d-link', 'D-LINK', 'DIR', 'DSL', 'DSL-', 'DAP'],
    'asus': ['asus', 'ASUS', 'RT-', 'GT-', 'DSL-', 'RT-AC'],
    'fritzbox': ['fritz', 'fritzbox', 'FRITZ', 'AVM', 'Fritz!Box'],
    'draytek': ['draytek', 'DRAYTEK', 'Vigor', 'VIGOR', 'VigorRouter'],
    'mikrotik': ['mikrotik', 'MIKROTIK', 'RouterOS', 'routerboard', 'RB'],
    'ubiquiti': ['ubiquiti', 'UBIQUITI', 'UniFi', 'EdgeRouter', 'EdgeSwitch'],
    'cisco': ['cisco', 'CISCO', 'Linksys', 'Meraki', 'Catalyst'],
    'belkin': ['belkin', 'BELKIN', 'F9K', 'N300', 'N600', 'AC1200'],
    'buffalo': ['buffalo', 'BUFFALO', 'WZR', 'WHR', 'WCR', 'AirStation'],
    'tenda': ['tenda', 'TENDA', 'AC', 'N', 'F', 'W', 'AC6'],
    'xiaomi': ['xiaomi', 'XIAOMI', 'mi router', 'MI ROUTER', 'Redmi'],
    'technicolor': ['technicolor', 'TECHNICOLOR', 'TG', 'TC', 'TG789'],
    'sagemcom': ['sagemcom', 'SAGEMCOM', 'Fast', 'FAST', 'F@ST']
}
```

### **Smart False Positive Filtering**
```python
# Router-aware filtering
router_indicators = ['router', 'gateway', 'modem', 'access point', 'wireless', 'network', 'admin', 'login']
if any(router_indicator in content_lower for router_indicator in router_indicators):
    continue  # Don't filter if it contains router indicators
```

### **Session Management**
```python
# Real admin verification
admin_session = requests.Session()
# Check for session cookies
session_cookies = any('session' in cookie.lower() or 'auth' in cookie.lower() 
                    for cookie in admin_session.cookies.keys())
# Check for logout button/link
logout_indicators = ['logout', 'log out', 'sign out', 'exit']
has_logout = any(indicator in content for indicator in logout_indicators)
```

## 🔧 **Configuration**

### **Thread Count**
- **Default**: 1 thread (for organized output)
- **Recommended**: 1 for clean output
- **Multi-threaded**: Use -T flag for faster scanning

### **Timeout Settings**
- **Default**: 8 seconds
- **Fast networks**: 5-8 seconds
- **Slow networks**: 10-15 seconds

### **Port Selection**
Automatically scans these ports:
```
80, 8080, 443, 8443, 8000, 8081, 8888, 8090, 9000, 9090
```

## 🎨 **Color Coding**

### **Information Types**
- **🔵 Blue**: Brand detection and system information
- **🟡 Yellow**: Process steps and progress
- **🟢 Green**: Success messages and found information
- **🔴 Red**: Vulnerabilities and errors
- **🟣 Magenta**: Extracted router information
- **🟦 Cyan**: Target scanning and URLs

## 🛡️ **Security Features**

### **Anti-Detection**
- **User-Agent rotation**: 7 different browser User-Agents
- **Random selection**: Different User-Agent per request
- **Rate limiting**: Prevents router blocking
- **Session management**: Efficient connections

### **False Positive Prevention**
- **Router-aware filtering**: Only filters non-router pages
- **Context analysis**: Considers router-related keywords
- **Smart detection**: Advanced pattern matching

### **Safe Operation**
- **Ctrl+C handling**: Clean shutdown
- **Resource cleanup**: Memory management
- **Exception handling**: Robust recovery
- **Duplicate removal**: Automatic IP deduplication

## 📈 **Performance Metrics**

### **Speed Benchmarks**
- **Small networks** (1-254 IPs): 2-8 minutes
- **Medium networks** (1-4096 IPs): 15-60 minutes
- **Large networks** (1-65536 IPs): 2-8 hours

### **Resource Usage**
- **Memory**: ~30-80MB for 1000 targets
- **CPU**: Single-threaded for organized output
- **Network**: Optimized connections with User-Agent rotation

## 🔍 **Detection Capabilities**

### **Router Brands Supported**
- **Asian**: TP-Link, Huawei, ZTE, Xiaomi, Tenda
- **European**: AVM Fritz!Box, Technicolor, Sagemcom
- **American**: Netgear, Linksys, D-Link, Cisco, Belkin, Buffalo
- **Global**: ASUS, DrayTek, MikroTik, Ubiquiti, and many more

### **Authentication Types**
- **HTTP Basic Auth**: 401 response detection
- **Form-based Auth**: Multiple form field combinations
- **API-based Auth**: JSON and REST endpoints
- **Redirect-based Auth**: Follows redirect patterns

### **Information Extraction**
- **MAC Address**: Physical device address
- **Firmware Version**: Software version
- **Router Model**: Device model and series
- **WAN IP**: External IP address
- **SSID**: Wireless network name
- **SIP Information**: VoIP configuration
- **Uptime**: Device running time
- **Connection Type**: Internet connection type

## 📊 **HTML Report Features**

### **Professional Design**
- **Modern interface**: Responsive HTML design
- **Color-coded results**: Visual indicators for vulnerabilities
- **Comprehensive data**: All scan results with details
- **Export ready**: Professional reports for documentation

### **Report Contents**
- **Scan summary**: Overview of all targets
- **Detailed results**: Per-target information
- **Vulnerability details**: Credentials, admin URLs, router info
- **Visual indicators**: Color-coded status and severity

## ⚠️ **Legal Notice**

**FOR EDUCATIONAL AND AUTHORIZED TESTING ONLY**

This tool is designed for:
- Network security professionals
- Penetration testers
- Network administrators
- Security contractors
- Educational purposes

**Users are responsible for:**
- Obtaining proper authorization
- Complying with local laws
- Following ethical guidelines
- Using responsibly

## 🚀 **Quick Start**

```bash
# Install dependencies
pip install requests urllib3

# Run your first scan
python3 router_scanner_pro.py -t 192.168.1.1

# Scan your local network
python3 router_scanner_pro.py -t 192.168.1.0/24

# Use targets file
python3 router_scanner_pro.py -t targets.txt
```

## 🎯 **Why Router Scanner Pro v7.0?**

1. **Comprehensive Brand Detection**: 18+ router brands with global coverage
2. **Advanced Session Management**: Real admin panel access verification
3. **Smart False Positive Filtering**: Router-aware filtering system
4. **Professional HTML Reporting**: Beautiful, comprehensive reports
5. **Credential Optimization**: Stops testing after finding valid credentials
6. **Organized Workflow**: Clean, sequential processing
7. **Information Extraction**: Comprehensive router information
8. **User-Agent Rotation**: Anti-detection with multiple User-Agents
9. **Cross-Platform**: Works on Windows, Linux, macOS
10. **Professional**: Single file, easy to use

---

**🔒 Router Scanner Pro v7.0 - The Ultimate Comprehensive Network Security Assessment Tool**

*"Follow the white rabbit..."* 🐰

---

**Happy Scanning! 🚀✨**