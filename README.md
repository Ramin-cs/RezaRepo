# 🔒 Router Scanner Pro v4.0

**Advanced Authentication Detection - Professional Network Security Tool**

## 🚀 **What's New in Version 4.0?**

### **🔍 Advanced Authentication Detection**
- **HTTP Basic Authentication** - Detects and tests basic auth
- **Form-based Authentication** - Multiple form field combinations
- **API-based Authentication** - JSON and REST API endpoints
- **Redirect-based Authentication** - Follows redirect patterns
- **JavaScript-based Authentication** - Detects JS auth mechanisms
- **Cookie-based Authentication** - Session and cookie detection

### **🎯 Enhanced Login Path Detection**
- **46 different login paths** tested per port
- **Router-specific paths** for major brands
- **API endpoints** for modern routers
- **Generic paths** for unknown devices

## 🎨 **Features**

### **🔍 Multi-Authentication Detection**
- **Real-time authentication type detection**
- **Live brute force testing** with multiple methods
- **Comprehensive credential testing** across all auth types
- **Live vulnerability reporting** as they're found

### **🎨 Hacker Theme**
- **Matrix-style interface** with professional colors
- **Cross-platform support** (Windows, Linux, macOS)
- **Beautiful terminal output** with emojis and colors
- **Nostalgic hacker aesthetic** for security professionals

### **⚡ Performance**
- **Multi-threaded scanning** (configurable threads)
- **Fast port detection** with socket-based scanning
- **Smart timeout management** for network efficiency
- **Resource optimization** for large networks

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
# High-speed scan with 100 threads
python3 router_scanner_pro.py -t 10.0.0.0/16 -T 100

# Custom timeout
python3 router_scanner_pro.py -t targets.txt --timeout 15
```

## 📊 **Live Output Example**

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                    ROUTER SCANNER PRO - v4.0                                ║
║                    Advanced Authentication Detection                         ║
║                                                                              ║
║  🔍 Multi-Auth Detection  |  🔓 HTTP Basic & Form Testing                 ║
║  🚀 API Endpoint Discovery |  📊 Professional Reporting                    ║
╚══════════════════════════════════════════════════════════════════════════════╝

[+] Loaded 8 targets
[+] Starting enhanced scan of 8 targets with 50 threads
[*] Target credentials: admin:admin, admin:support180, support:support, user:user
[*] Scanning ports: 80, 8080, 443, 8443, 8000, 8081, 8888, 8090, 9000, 9090
[*] Authentication types: HTTP Basic, Form-based, API-based, Redirect-based
[*] Login paths: 46 different paths tested
--------------------------------------------------------------------------------
[*] Scanning ports on 192.168.1.1...
[+] 192.168.1.1: Found 1 open ports: [80]
[*] Testing http://192.168.1.1:80/ for authentication...
[*] HTTP Basic Auth detected on http://192.168.1.1:80/
[+] AUTHENTICATION FOUND: http://192.168.1.1:80/ - Types: http_basic
[*] Starting comprehensive brute force on http://192.168.1.1:80/...
[>] Testing: admin:admin
🔒 VULNERABLE: 192.168.1.1 - admin:admin works! (HTTP Basic Auth)
[+] Admin URL: http://192.168.1.1/admin
[*] Progress: 1/8 (12.5%) - Login pages: 1, Vulnerable: 1

[*] Testing http://192.168.1.1:80/api/login for authentication...
[*] API-based auth detected on http://192.168.1.1:80/api/login
[+] AUTHENTICATION FOUND: http://192.168.1.1:80/api/login - Types: api_based
[*] Starting comprehensive brute force on http://192.168.1.1:80/api/login...
[>] Testing: admin:admin
🔒 VULNERABLE: 192.168.1.1 - admin:admin works! (API-based Auth)
[+] Admin URL: http://192.168.1.1/api/login

[+] Enhanced Scan Complete!
[*] Summary:
  - Total targets scanned: 8
  - Login pages found: 2
  - Vulnerable routers: 2
  - Scan duration: 45.2 seconds
  - Average speed: 5.6 targets/second
[*] Multiple authentication types tested
```

## 🔧 **Authentication Types Supported**

### **HTTP Basic Authentication**
- Detects 401 responses
- Tests with Authorization headers
- Base64 encoded credentials

### **Form-based Authentication**
- 15 different form field combinations
- Multiple submit button variations
- Success/failure content analysis

### **API-based Authentication**
- JSON payload testing
- REST API endpoints
- Token-based authentication

### **Redirect-based Authentication**
- Follows redirect chains
- Detects location headers
- Analyzes redirect patterns

### **JavaScript-based Authentication**
- Detects JS auth mechanisms
- Form fallback testing
- Dynamic content analysis

### **Cookie-based Authentication**
- Session cookie detection
- Cookie-based login testing
- Session persistence

## 🔧 **Configuration**

### **Thread Count**
- **Default**: 50 threads
- **Recommended**: 50-200 for most networks
- **High-speed**: 200+ for large scans

### **Timeout Settings**
- **Default**: 8 seconds
- **Fast networks**: 5-8 seconds
- **Slow networks**: 10-15 seconds

### **Port Selection**
Automatically scans these ports:
```
80, 8080, 443, 8443, 8000, 8081, 8888, 8090, 9000, 9090
```

### **Login Paths**
Tests 46 different paths including:
- Common paths: `/`, `/admin`, `/login`
- Brand-specific: `/userRpm/LoginRpm.htm`, `/cgi-bin/luci`
- API endpoints: `/api/login`, `/rest/auth`
- Generic paths: `/manager`, `/control`, `/config`

## 🎨 **Cross-Platform Support**

### **Windows**
- **Colors**: Disabled for compatibility
- **Execution**: `python router_scanner_pro.py`
- **File paths**: Windows-style

### **Linux/macOS**
- **Colors**: Full color support
- **Execution**: `python3 router_scanner_pro.py` or `./router_scanner_pro.py`
- **File paths**: Unix-style

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
- **Small networks** (1-254 IPs): 2-5 minutes
- **Medium networks** (1-4096 IPs): 10-30 minutes
- **Large networks** (1-65536 IPs): 60-300 minutes

### **Resource Usage**
- **Memory**: ~50-120MB for 1000 targets
- **CPU**: Efficient multi-threading
- **Network**: Optimized connections

## 🔍 **Detection Capabilities**

### **Router Brands Supported**
- **Asian**: TP-Link, Huawei, ZTE, Xiaomi, Tenda
- **European**: AVM Fritz!Box, Technicolor
- **American**: Netgear, Linksys, D-Link
- **Global**: ASUS, and many more

### **Authentication Detection**
- **Multi-type detection**: Identifies all auth methods
- **Content analysis**: Smart pattern recognition
- **Response analysis**: HTTP status and content
- **Comprehensive testing**: All methods tested

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
python3 router_scanner_pro.py -t 192.168.1.0/24 -T 100

# Use targets file
python3 router_scanner_pro.py -t targets.txt
```

## 🎯 **Why Router Scanner Pro v4.0?**

1. **Advanced Detection**: Multiple authentication types
2. **Comprehensive Testing**: 46 different login paths
3. **Live Output**: See everything happening in real-time
4. **Cross-Platform**: Works on Windows, Linux, macOS
5. **Professional**: Beautiful hacker-themed interface
6. **Fast**: Multi-threaded for high performance
7. **Accurate**: Real router testing, not just analysis
8. **Simple**: Single file, easy to use
9. **Secure**: Anti-detection features
10. **Reliable**: Robust error handling

---

**🔒 Router Scanner Pro v4.0 - The Ultimate Professional Network Security Assessment Tool**

*"Follow the white rabbit..."* 🐰

---

**Happy Scanning! 🚀✨**