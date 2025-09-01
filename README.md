# 🔒 Advanced Router Login Scanner & Brute Force Tool

**Professional Network Security Assessment Tool for Network Engineers and Contractors**

## 🎯 Overview

This is a **high-performance, intelligent router security scanner** designed specifically for network security professionals. The tool focuses on **finding router login pages** and **testing default credentials** to identify vulnerable routers in your network infrastructure.

## ✨ Key Features

### 🚀 **Performance & Speed**
- **Multi-threaded scanning**: Up to 200+ concurrent threads
- **Fast port detection**: Socket-based port scanning with 1-second timeout
- **Optimized HTTP sessions**: Connection pooling and retry strategies
- **Smart rate limiting**: Prevents detection while maintaining speed

### 🧠 **Intelligent Detection**
- **Advanced login page detection**: AI-powered scoring system
- **Brand recognition**: Automatic router manufacturer identification
- **Confidence scoring**: High/Medium/Low confidence levels
- **Pattern matching**: Sophisticated detection algorithms

### 🔓 **Targeted Brute Force**
- **Specific credentials**: Tests only the credentials you need
- **Multiple login methods**: Adapts to different router interfaces
- **Success verification**: Intelligent login success detection
- **Router information extraction**: Gets firmware, model, and network details

### 📊 **Professional Reporting**
- **HTML reports**: Beautiful, responsive web reports
- **JSON exports**: Machine-readable data for integration
- **Real-time statistics**: Live progress and vulnerability counts
- **Detailed findings**: Complete vulnerability chain documentation

## 🎯 Target Credentials

The tool tests these specific credentials:
- `admin:admin`
- `admin:support180`
- `support:support`
- `user:user`

## 🏗️ Architecture

### **4-Phase Scanning Process**

1. **Port Discovery** 🔍
   - Fast socket-based port scanning
   - Tests common web ports: 80, 8080, 443, 8443, 8000, 8081, 8888, 8090, 9000, 9090, 3000, 5000, 7000

2. **Login Page Detection** 🎯
   - Intelligent scoring system (minimum 4 points required)
   - Form detection, keyword analysis, brand recognition
   - Confidence levels: Low (0-3), Medium (4-5), High (6+)

3. **Brute Force Attack** 🔓
   - Tests specified credentials with rate limiting
   - Multiple login field combinations
   - Success/failure pattern analysis

4. **Information Extraction** 📋
   - Router model and firmware detection
   - Network configuration details
   - Vulnerability documentation

## 🚀 Installation

### Requirements
- Python 3.7+
- pip package manager

### Setup
```bash
# Clone or download the scanner
# Install dependencies
pip install -r requirements.txt

# Make executable (Linux/macOS)
chmod +x advanced_router_scanner.py
```

## 💻 Usage

### Basic Commands
```bash
# Scan single IP
python advanced_router_scanner.py -t 192.168.1.1

# Scan CIDR range
python advanced_router_scanner.py -t 192.168.1.0/24

# Scan IP range
python advanced_router_scanner.py -t 192.168.1.1-192.168.1.254

# Scan from file
python advanced_router_scanner.py -t targets.txt
```

### Advanced Options
```bash
# High-speed scan with 200 threads
python advanced_router_scanner.py -t 10.0.0.0/16 -T 200

# Custom timeout and output directory
python advanced_router_scanner.py -t targets.txt --timeout 15 -o custom_reports
```

### Target File Format
Create a `targets.txt` file with one IP per line:
```
192.168.1.1
192.168.1.254
10.0.0.1
172.16.0.1
```

## 📊 Output Examples

### Terminal Output
```
🔒 VULNERABLE: 192.168.1.1 - Default credentials work!
[+] Admin URL: http://192.168.1.1/admin
[+] Model: TL-WR840N
[+] Firmware: v1.0.0

[+] Scan Complete!
[*] Summary:
  - Total targets scanned: 254
  - Login pages found: 12
  - Vulnerable routers: 3
  - Scan duration: 45.2 seconds
  - Average speed: 5.6 targets/second
```

### Report Files
- **JSON**: `router_scan_report_20241218_143022.json`
- **HTML**: `router_scan_report_20241218_143022.html`

## 🔧 Configuration

### Thread Count
- **Default**: 100 threads
- **Recommended**: 50-200 for most networks
- **High-speed**: 200+ for large scans

### Timeout Settings
- **Default**: 8 seconds
- **Fast networks**: 5-8 seconds
- **Slow networks**: 10-15 seconds

### Port Selection
The tool automatically scans these ports:
```python
COMMON_PORTS = [80, 8080, 443, 8443, 8000, 8081, 8888, 8090, 9000, 9090, 3000, 5000, 7000]
```

## 🛡️ Security Features

### Anti-Detection
- **User-Agent rotation**: Professional browser headers
- **Rate limiting**: Intelligent timing to avoid blocks
- **Connection persistence**: Efficient resource usage
- **Error handling**: Graceful failure management

### Safe Operation
- **Ctrl+C handling**: Clean shutdown
- **Resource cleanup**: Memory and connection management
- **Exception handling**: Robust error recovery

## 📈 Performance Metrics

### Speed Benchmarks
- **Small networks** (1-254 IPs): 1-2 minutes
- **Medium networks** (1-4096 IPs): 5-15 minutes
- **Large networks** (1-65536 IPs): 30-120 minutes

### Resource Usage
- **Memory**: ~50-100MB for 1000 targets
- **CPU**: Efficient multi-threading
- **Network**: Optimized connection pooling

## 🎨 Report Features

### HTML Report
- **Professional dashboard**: Clean, modern interface
- **Statistics cards**: Key metrics at a glance
- **Target details**: Individual IP analysis
- **Vulnerability matrix**: Severity-based categorization
- **Responsive design**: Works on all devices

### JSON Report
- **Structured data**: Complete scan metadata
- **API integration**: Ready for automation
- **Audit trail**: Full timestamp information
- **Machine readable**: Easy parsing and analysis

## 🔍 Detection Capabilities

### Router Brands Supported
- **Asian**: TP-Link, Huawei, ZTE, Xiaomi, Tenda
- **European**: AVM Fritz!Box, Technicolor
- **American**: Netgear, Linksys, D-Link
- **Global**: ASUS, and many more

### Login Page Detection
- **Form analysis**: Input field detection
- **Content analysis**: Keyword matching
- **Header analysis**: Server information
- **Brand detection**: Manufacturer identification

## ⚠️ Legal Notice

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

## 🆘 Troubleshooting

### Common Issues
1. **Permission denied**: Run with appropriate privileges
2. **Network timeout**: Increase timeout value
3. **Memory issues**: Reduce thread count
4. **False positives**: Adjust confidence threshold

### Performance Tips
- Use appropriate thread count for your network
- Set reasonable timeout values
- Monitor system resources during large scans
- Use SSD storage for report generation

## 🤝 Support

For issues, questions, or contributions:
- Review the code for implementation details
- Check error messages for troubleshooting
- Verify network connectivity and permissions
- Ensure target authorization

## 📝 Changelog

### Version 2.0 (Current)
- Complete rewrite with modern architecture
- Advanced login page detection
- Professional reporting system
- Performance optimizations
- Brand recognition system

### Version 1.0
- Basic router scanning
- Simple credential testing
- Basic reporting

---

**Created with ❤️ for the Network Security Community**

*"Follow the white rabbit..."* 🐰

---

## 🚀 Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Run your first scan
python advanced_router_scanner.py -t 192.168.1.1

# Scan your local network
python advanced_router_scanner.py -t 192.168.1.0/24 -T 100

# Generate detailed reports
python advanced_router_scanner.py -t targets.txt -o detailed_reports
```

**Happy Scanning! 🔒✨**