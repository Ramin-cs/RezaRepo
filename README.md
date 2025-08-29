# Advanced Router Vulnerability Scanner - Phase 3

🔒 **Professional Router Security Assessment Tool**

## Overview

This is a comprehensive router vulnerability scanner designed for Phase 3 security assessments, focusing on brute force attacks against router login pages and configuration extraction.

## Features

### 🎯 Core Capabilities
- **Multi-threaded Scanning**: High-speed parallel processing for large networks
- **Smart Login Detection**: AI-powered scoring system for accurate login page identification
- **Brand Recognition**: Comprehensive database of router brands with specific indicators
- **Brute Force Engine**: Intelligent credential testing with rate limiting and evasion
- **Configuration Extraction**: Automated config file discovery and SIP data extraction
- **Professional Reporting**: Beautiful HTML and JSON reports with detailed findings

### 🌍 Supported Router Brands
- **Asian**: TP-Link, Huawei, ZTE, Xiaomi, Tenda
- **European**: AVM Fritz!Box, Technicolor
- **American**: Netgear, Linksys, D-Link
- **Global**: ASUS, and many more
- **Legacy & Generic**: Comprehensive fallback support

### 🛡️ Anti-Detection Features
- Random user agents rotation
- Rate limiting with jitter
- Request timing randomization
- Connection persistence
- Header randomization

## Installation

### Requirements
- Python 3.7+
- pip package manager

### Setup
```bash
# Clone or download the scanner
# Install dependencies
pip install -r requirements.txt

# Make executable (Linux/macOS)
chmod +x router_vulnerability_scanner.py
```

## Usage

### Basic Usage
```bash
# Scan single IP
python router_vulnerability_scanner.py -t 192.168.1.1

# Scan CIDR range
python router_vulnerability_scanner.py -t 192.168.1.0/24

# Scan IP range
python router_vulnerability_scanner.py -t 192.168.1.1-192.168.1.254

# Scan from file
python router_vulnerability_scanner.py -t targets.txt
```

### Advanced Options
```bash
# High-speed scan with 100 threads
python router_vulnerability_scanner.py -t 10.0.0.0/16 -T 100

# Custom timeout
python router_vulnerability_scanner.py -t targets.txt --timeout 15
```

### Target File Format
Create a `targets.txt` file with one IP per line:
```
192.168.1.1
192.168.1.254
10.0.0.1
172.16.0.1
```

## Scanning Process

### Phase 1: Port Discovery
- Scans common web ports (80, 8080, 443, 8443, etc.)
- Fast socket-based detection
- Parallel port scanning

### Phase 2: Login Page Detection
Uses intelligent scoring system based on:
- **Form Analysis**: Detects login forms and input fields
- **Content Analysis**: Searches for authentication keywords
- **Header Analysis**: Examines server headers
- **Brand Detection**: Identifies router manufacturers
- **Scoring Threshold**: Requires score ≥3 for positive detection

### Phase 3: Brute Force Attack
- **Smart Credentials**: Uses brand-specific default credentials
- **Rate Limiting**: Prevents detection and blocking
- **Live Display**: Shows current credential attempts
- **Success Detection**: Multiple verification methods
- **Anti-Lockout**: Intelligent timing and retry logic

### Phase 4: Post-Exploitation
- **Admin Panel Access**: Extracts management information
- **Configuration Files**: Discovers and downloads config files
- **SIP Extraction**: Extracts VoIP credentials as POC
- **Information Gathering**: Collects firmware, model, network data

## Scoring System

The scanner uses a comprehensive scoring system:

| Phase | Success Criteria | Points |
|-------|------------------|--------|
| Login Detection | Page score ≥3 | +1 |
| Credential Success | Valid login found | +2 |
| Config Access | Files discovered | +1 |
| **Total Maximum** | **All phases complete** | **4** |

## Report Generation

### HTML Report
- **Visual Dashboard**: Clean, professional interface
- **IP Cards**: Individual profiles for each target
- **Vulnerability Details**: Complete exploitation chain
- **Configuration Data**: Extracted sensitive information
- **Matrix Theme**: Hacker-aesthetic design

### JSON Report
- **Structured Data**: Machine-readable format
- **Detailed Results**: Complete scan metadata
- **Integration Ready**: API-compatible output
- **Timestamps**: Full audit trail

## Example Output

```
🔒 VULNERABLE: 192.168.1.1 - Default credentials work!
[+] SUCCESS! Default credential found: admin:admin
[+] Configuration file found: http://192.168.1.1/config.bin
[+] SIP credentials extracted: user@sip.provider.com

[+] Reports generated:
  - JSON: router_scan_report_20241218_143022.json
  - HTML: router_scan_report_20241218_143022.html
```

## Safety Features

- **Ctrl+C Handling**: Graceful shutdown
- **Rate Limiting**: Prevents network flooding
- **Error Handling**: Robust exception management
- **Resource Management**: Efficient memory usage
- **Clean Exit**: Proper session cleanup

## Legal Notice

⚠️ **FOR EDUCATIONAL AND AUTHORIZED TESTING ONLY**

This tool is designed for:
- Security professionals
- Penetration testers
- Network administrators
- Educational purposes

**Users are responsible for:**
- Obtaining proper authorization
- Complying with local laws
- Following ethical guidelines
- Using responsibly

## Technical Details

### Architecture
- **Async HTTP**: High-performance networking
- **Thread Pool**: Concurrent execution
- **Session Management**: Connection reuse
- **Memory Efficient**: Optimized for large scans

### Database Structure
```python
ROUTER_DATABASE = {
    "Brand": {
        "models": [...],
        "default_credentials": [...],
        "indicators": [...],
        "login_paths": [...],
        "config_paths": [...]
    }
}
```

### Performance
- **Large Networks**: Supports thousands of IPs
- **Multi-threading**: Configurable thread count
- **Memory Usage**: ~50MB for 1000 targets
- **Speed**: 100+ IPs/minute (network dependent)

## Support

For issues, questions, or contributions:
- Review the code for implementation details
- Check error messages for troubleshooting
- Verify network connectivity and permissions
- Ensure target authorization

---

**Created with ❤️ for the cybersecurity community**

*"Follow the white rabbit..."* 🐰