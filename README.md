# 🔒 Router Scanner Pro v5.0

**Organized Scanning & Smart Detection - Professional Network Security Tool**

## 🚀 **What's New in Version 5.0?**

### **🎯 Organized Workflow**
- **Sequential processing**: One target at a time for clean output
- **4-phase scanning**: Ports → Brand → Login → Brute Force → Info
- **No duplicate testing**: Each test runs only once
- **Clean professional output**: Organized and easy to read

### **🧠 Smart Brand Detection**
- **Priority-based testing**: Brand-specific paths tested first
- **Intelligent path selection**: Based on detected router brand
- **Fallback mechanisms**: Generic paths if brand not detected
- **Efficient scanning**: Reduces unnecessary tests

### **🎨 Enhanced Hacker Theme**
- **Matrix-style interface** with professional colors
- **Color-coded information**: Different colors for different types of data
- **Clean sections**: Organized output with clear separators
- **Professional aesthetics**: Beautiful terminal interface

## 🎨 **Features**

### **🔍 Organized Scanning Workflow**
- **Phase 1**: Port scanning with live output
- **Phase 2**: Brand detection and login page discovery
- **Phase 3**: Brute force attack with credential testing
- **Phase 4**: Information extraction from admin panel

### **🧠 Smart Detection System**
- **Brand detection**: Identifies router manufacturer
- **Priority paths**: Tests brand-specific paths first
- **Authentication types**: HTTP Basic, Form-based, API-based
- **Information extraction**: Router details from admin panel

### **🎨 Professional Output**
- **Color-coded results**: Different colors for different information types
- **Organized sections**: Clear separation between targets
- **Progress tracking**: Real-time progress updates
- **Clean formatting**: Easy to read and understand

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
║                    ROUTER SCANNER PRO - v5.0                                ║
║                    Organized Scanning & Smart Detection                      ║
║                                                                              ║
║  🔍 Smart Brand Detection  |  🔓 Priority-based Testing                    ║
║  🚀 Organized Workflow     |  📊 Clean Professional Output                 ║
╚══════════════════════════════════════════════════════════════════════════════╝

[+] Loaded 3 targets
[+] Starting organized scan of 3 targets
[*] Target credentials: admin:admin, admin:support180, support:support, user:user
[*] Scanning ports: 80, 8080, 443, 8443, 8000, 8081, 8888, 8090, 9000, 9090
[*] Smart brand detection with priority-based testing
[*] Organized workflow: Ports → Brand → Login → Brute Force → Info
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
[4/4] Information Extraction...
[+] Model: TL-WR840N
[+] Firmware Version: v1.0.0
[+] Wan Ip: 192.168.1.1
[+] Ssid: MyWiFi_Network
[+] Target 192.168.1.1 scan completed
[*] Progress: 1/3 (33.3%) - Login pages: 1, Vulnerable: 1

============================================================
[*] SCANNING TARGET: 192.168.1.254
============================================================
[1/4] Port Scanning...
[+] Found 1 open ports: [80]
[2/4] Brand Detection & Login Discovery...
[*] Detected brand: GENERIC
[+] LOGIN PAGE FOUND: http://192.168.1.254:80/admin (form_based)
[3/4] Brute Force Attack...
[>] Testing: admin:admin
[>] Testing: admin:support180
[>] Testing: support:support
[>] Testing: user:user
[-] No valid credentials found
[+] Target 192.168.1.254 scan completed
[*] Progress: 2/3 (66.7%) - Login pages: 1, Vulnerable: 1

============================================================
[+] SCAN COMPLETE!
============================================================
[*] Summary:
  - Total targets scanned: 3
  - Login pages found: 2
  - Vulnerable routers: 1
  - Scan duration: 45.2 seconds
  - Average speed: 0.1 targets/second
[*] Organized workflow completed successfully
```

## 🔧 **Smart Detection System**

### **Brand Detection**
```python
# Detects router brand from main page
brand_indicators = {
    'tp-link': ['tp-link', 'tplink', 'TP-LINK', 'TPLINK', 'archer'],
    'huawei': ['huawei', 'HUAWEI', 'HG', 'B593', 'E5186'],
    'zte': ['zte', 'ZTE', 'ZXHN', 'MF28G', 'F660'],
    'netgear': ['netgear', 'NETGEAR', 'WNDR', 'R7000'],
    'linksys': ['linksys', 'LINKSYS', 'WRT', 'E1200'],
    'd-link': ['d-link', 'D-LINK', 'DIR', 'DSL'],
    'asus': ['asus', 'ASUS', 'RT-', 'GT-'],
    'fritzbox': ['fritz', 'fritzbox', 'FRITZ', 'AVM']
}
```

### **Priority-based Path Testing**
```python
# Brand-specific paths tested first
BRAND_PATHS = {
    'tp-link': ['/userRpm/LoginRpm.htm', '/cgi-bin/luci', '/admin'],
    'huawei': ['/html/index.html', '/asp/login.asp', '/login.cgi'],
    'zte': ['/login.gch', '/start.gch', '/getpage.gch'],
    'netgear': ['/setup.cgi', '/genie.cgi', '/cgi-bin/'],
    'generic': ['/', '/admin', '/login', '/login.htm']
}
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
- **Rate limiting**: Prevents router blocking
- **Professional headers**: Browser-like requests
- **Session management**: Efficient connections
- **Error handling**: Graceful failures

### **Safe Operation**
- **Ctrl+C handling**: Clean shutdown
- **Resource cleanup**: Memory management
- **Exception handling**: Robust recovery

## 📈 **Performance Metrics**

### **Speed Benchmarks**
- **Small networks** (1-254 IPs): 2-8 minutes
- **Medium networks** (1-4096 IPs): 15-60 minutes
- **Large networks** (1-65536 IPs): 2-8 hours

### **Resource Usage**
- **Memory**: ~30-80MB for 1000 targets
- **CPU**: Single-threaded for organized output
- **Network**: Optimized connections

## 🔍 **Detection Capabilities**

### **Router Brands Supported**
- **Asian**: TP-Link, Huawei, ZTE, Xiaomi, Tenda
- **European**: AVM Fritz!Box, Technicolor
- **American**: Netgear, Linksys, D-Link
- **Global**: ASUS, and many more

### **Authentication Types**
- **HTTP Basic Auth**: 401 response detection
- **Form-based Auth**: Multiple form field combinations
- **API-based Auth**: JSON and REST endpoints
- **Redirect-based Auth**: Follows redirect patterns

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

## 🎯 **Why Router Scanner Pro v5.0?**

1. **Organized Workflow**: Clean, sequential processing
2. **Smart Detection**: Brand-based priority testing
3. **No Duplicates**: Each test runs only once
4. **Professional Output**: Color-coded and organized
5. **Hacker Theme**: Beautiful terminal interface
6. **Information Extraction**: Router details from admin panel
7. **Cross-Platform**: Works on Windows, Linux, macOS
8. **Fast**: Optimized for speed and efficiency
9. **Accurate**: Real router testing, not just analysis
10. **Simple**: Single file, easy to use

---

**🔒 Router Scanner Pro v5.0 - The Ultimate Organized Network Security Assessment Tool**

*"Follow the white rabbit..."* 🐰

---

**Happy Scanning! 🚀✨**