# 🔒 Router Scanner Pro v6.0

**Advanced Brand Detection & False Positive Filtering - Professional Network Security Tool**

## 🚀 **What's New in Version 6.0?**

### **🔍 Advanced Brand Detection**
- **Multi-method detection**: Content, headers, server headers, and paths
- **Brand-specific patterns**: Detailed patterns for each router brand
- **Model identification**: Detects specific router models
- **Priority-based testing**: Brand-specific paths tested first

### **🚫 False Positive Filtering**
- **VPN detection**: Filters out VPN login pages
- **Email/Social filtering**: Removes email and social login pages
- **Smart indicators**: Advanced pattern matching for false positives
- **Clean results**: Only genuine router login pages

### **🎯 Admin Verification**
- **Real admin access**: Verifies actual entry to admin panel
- **Admin indicators**: Checks for dashboard, status, configuration
- **Information extraction**: Extracts MAC, firmware, model, SIP info
- **Verified vulnerabilities**: Only reports confirmed access

### **🔄 User-Agent Rotation**
- **Anti-detection**: Multiple User-Agents to avoid blocking
- **Random selection**: Different User-Agent for each request
- **Browser simulation**: Realistic browser headers
- **Stealth mode**: Harder to detect automated scanning

## 🎨 **Features**

### **🔍 Advanced Detection System**
- **Brand detection**: TP-Link, Huawei, ZTE, Netgear, Linksys, D-Link, ASUS, FritzBox
- **Model identification**: Specific router models and series
- **Priority paths**: Brand-specific login paths tested first
- **False positive filtering**: VPN, email, social login detection

### **🎯 Admin Verification**
- **Real access testing**: Actually enters admin panel
- **Admin indicators**: Dashboard, status, configuration, control panel
- **Information extraction**: MAC address, firmware, model, WAN IP, SSID, SIP
- **Verified results**: Only confirmed vulnerabilities reported

### **🔄 Anti-Detection Features**
- **User-Agent rotation**: 7 different browser User-Agents
- **Random selection**: Different User-Agent per request
- **Realistic headers**: Browser-like request headers
- **Stealth scanning**: Harder to detect automated tools

### **📊 Information Extraction**
- **MAC address**: Physical address extraction
- **Firmware version**: Software version detection
- **Router model**: Device model identification
- **WAN IP**: External IP address
- **SSID**: Wireless network name
- **SIP information**: VoIP configuration
- **Uptime**: Device running time
- **Connection type**: Internet connection type

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
║                    ROUTER SCANNER PRO - v6.0                                ║
║              Advanced Brand Detection & False Positive Filtering             ║
║                                                                              ║
║  🔍 Smart Brand Detection  |  🚫 False Positive Filtering                  ║
║  🎯 Admin Verification     |  📊 Advanced Information Extraction            ║
╚══════════════════════════════════════════════════════════════════════════════╝

[+] Loaded 3 targets
[+] Starting organized scan of 3 targets
[*] Target credentials: admin:admin, admin:support180, support:support, user:user
[*] Scanning ports: 80, 8080, 443, 8443, 8000, 8081, 8888, 8090, 9000, 9090
[*] Advanced brand detection with false positive filtering
[*] Organized workflow: Ports → Brand → Login → Brute Force → Admin Verification
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
[*] SCANNING TARGET: 192.168.1.100
============================================================
[1/4] Port Scanning...
[+] Found 1 open ports: [80]
[2/4] Brand Detection & Login Discovery...
[*] Detected brand: GENERIC
[!] False positive detected: vpn
[+] Target 192.168.1.100 scan completed
[*] Progress: 3/3 (100.0%) - Login pages: 1, Vulnerable: 1

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
```

## 🔧 **Advanced Detection System**

### **Brand Detection Patterns**
```python
BRAND_PATTERNS = {
    'tp-link': {
        'content': ['tp-link', 'tplink', 'TP-LINK', 'TPLINK', 'archer', 'TL-'],
        'headers': ['tp-link', 'tplink'],
        'paths': ['/userRpm/LoginRpm.htm', '/cgi-bin/luci', '/admin'],
        'models': ['TL-', 'Archer', 'Deco', 'Omada']
    },
    'huawei': {
        'content': ['huawei', 'HUAWEI', 'HG', 'B593', 'E5186', 'HG8245'],
        'headers': ['huawei', 'HUAWEI'],
        'paths': ['/html/index.html', '/asp/login.asp', '/login.cgi'],
        'models': ['HG', 'B593', 'E5186', 'HG8245']
    }
    # ... more brands
}
```

### **False Positive Filtering**
```python
FALSE_POSITIVE_INDICATORS = [
    # VPN indicators
    'vpn', 'openvpn', 'wireguard', 'ipsec', 'l2tp', 'pptp',
    
    # Email/Social indicators
    'email', 'e-mail', 'gmail', 'yahoo', 'outlook', 'hotmail',
    'microsoft', 'google', 'facebook', 'twitter', 'instagram',
    
    # Other non-router indicators
    'github', 'gitlab', 'slack', 'discord', 'zoom', 'teams'
]
```

### **Admin Verification**
```python
ADMIN_INDICATORS = [
    'dashboard', 'status', 'configuration', 'admin panel', 'control panel',
    'welcome', 'logout', 'system information', 'device status', 'main menu',
    'router', 'gateway', 'modem', 'access point', 'network', 'wireless'
]
```

## 🔧 **Configuration**

### **User-Agent Rotation**
```python
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36...',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36...',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101...',
    # ... 7 different User-Agents
]
```

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
- **VPN filtering**: Detects and filters VPN login pages
- **Email filtering**: Removes email-based login pages
- **Social filtering**: Filters social media login pages
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
- **European**: AVM Fritz!Box, Technicolor
- **American**: Netgear, Linksys, D-Link
- **Global**: ASUS, and many more

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

## 🎯 **Why Router Scanner Pro v6.0?**

1. **Advanced Brand Detection**: Multi-method brand identification
2. **False Positive Filtering**: VPN, email, social login detection
3. **Admin Verification**: Real admin panel access verification
4. **Information Extraction**: Comprehensive router information
5. **User-Agent Rotation**: Anti-detection with multiple User-Agents
6. **Organized Workflow**: Clean, sequential processing
7. **Smart Detection**: Brand-specific path testing
8. **Verified Results**: Only confirmed vulnerabilities reported
9. **Cross-Platform**: Works on Windows, Linux, macOS
10. **Professional**: Single file, easy to use

---

**🔒 Router Scanner Pro v6.0 - The Ultimate Advanced Network Security Assessment Tool**

*"Follow the white rabbit..."* 🐰

---

**Happy Scanning! 🚀✨**