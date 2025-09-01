# 🔒 Router Scanner Pro v3.0

**Professional Network Security Tool with Live Output & Hacker Theme**

## 🚀 **Features**

### **🔍 Live Detection & Testing**
- **Real-time port scanning** with live output
- **Live login page detection** showing each step
- **Live brute force testing** with credential attempts
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
║                    ROUTER SCANNER PRO - v3.0                                ║
║                         Professional Network Security Tool                   ║
║                                                                              ║
║  🔍 Live Login Detection  |  🔓 Real Router Testing                       ║
║  🚀 High-Speed Multi-Threaded |  📊 Professional Reporting                 ║
╚══════════════════════════════════════════════════════════════════════════════╝

[+] Loaded 8 targets
[+] Starting scan of 8 targets with 50 threads
[*] Target credentials: admin:admin, admin:support180, support:support, user:user
[*] Scanning ports: 80, 8080, 443, 8443, 8000, 8081, 8888, 8090, 9000, 9090
--------------------------------------------------------------------------------
[*] Scanning ports on 192.168.1.1...
[+] 192.168.1.1: Found 1 open ports: [80]
[*] Testing http://192.168.1.1:80/ for login page...
[+] LOGIN PAGE FOUND: http://192.168.1.1:80/
[*] Starting brute force on http://192.168.1.1:80/...
[>] Testing: admin:admin
🔒 VULNERABLE: 192.168.1.1 - admin:admin works!
[+] Admin URL: http://192.168.1.1/admin
[*] Progress: 1/8 (12.5%) - Login pages: 1, Vulnerable: 1

[*] Scanning ports on 192.168.1.254...
[+] 192.168.1.254: Found 1 open ports: [80]
[*] Testing http://192.168.1.254:80/ for login page...
[+] LOGIN PAGE FOUND: http://192.168.1.254:80/
[*] Starting brute force on http://192.168.1.254:80/...
[>] Testing: admin:admin
[>] Testing: admin:support180
[>] Testing: support:support
[>] Testing: user:user
[-] No valid credentials found

[+] Scan Complete!
[*] Summary:
  - Total targets scanned: 8
  - Login pages found: 2
  - Vulnerable routers: 1
  - Scan duration: 45.2 seconds
  - Average speed: 5.6 targets/second
```

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
- **Small networks** (1-254 IPs): 1-3 minutes
- **Medium networks** (1-4096 IPs): 5-20 minutes
- **Large networks** (1-65536 IPs): 30-180 minutes

### **Resource Usage**
- **Memory**: ~30-80MB for 1000 targets
- **CPU**: Efficient multi-threading
- **Network**: Optimized connections

## 🔍 **Detection Capabilities**

### **Router Brands Supported**
- **Asian**: TP-Link, Huawei, ZTE, Xiaomi, Tenda
- **European**: AVM Fritz!Box, Technicolor
- **American**: Netgear, Linksys, D-Link
- **Global**: ASUS, and many more

### **Login Page Detection**
- **Form analysis**: HTML form detection
- **Content analysis**: Keyword matching
- **Pattern recognition**: Smart scoring system

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

## 🎯 **Why Router Scanner Pro?**

1. **Live Output**: See everything happening in real-time
2. **Cross-Platform**: Works on Windows, Linux, macOS
3. **Professional**: Beautiful hacker-themed interface
4. **Fast**: Multi-threaded for high performance
5. **Accurate**: Real router testing, not just analysis
6. **Simple**: Single file, easy to use
7. **Secure**: Anti-detection features
8. **Reliable**: Robust error handling

---

**🔒 Router Scanner Pro v3.0 - The Professional Choice for Live Network Security Assessment**

*"Follow the white rabbit..."* 🐰

---

**Happy Scanning! 🚀✨**