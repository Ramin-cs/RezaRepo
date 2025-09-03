# 🔍 Advanced Web Reconnaissance Tool - Complete Guide

## 📋 Table of Contents
1. [Quick Start](#quick-start)
2. [Tool Architecture](#tool-architecture)
3. [Installation Options](#installation-options)
4. [Usage Examples](#usage-examples)
5. [API Configuration](#api-configuration)
6. [Output Formats](#output-formats)
7. [Advanced Features](#advanced-features)
8. [Troubleshooting](#troubleshooting)

---

## 🚀 Quick Start

### Immediate Use (No Setup Required)
```bash
# Download the tool and run immediately
python3 simple_recon_tool.py -t yourdomain.com
```

### Full Feature Setup
```bash
# One-time setup
python3 recon_master.py --setup

# Run comprehensive scan
python3 recon_master.py yourdomain.com
```

---

## 🏗️ Tool Architecture

### File Structure
```
Advanced-Recon-Tool/
├── 🎯 Core Tools
│   ├── advanced_recon_tool.py      # Main comprehensive tool
│   ├── simple_recon_tool.py        # Standalone simple tool
│   └── recon_master.py             # Universal launcher
│
├── 🧩 Modules  
│   ├── advanced_modules.py         # Advanced techniques
│   └── external_tools.py           # External tool integration
│
├── 🛠️ Setup & Management
│   ├── setup.py                    # Basic setup
│   ├── install.py                  # Complete installation
│   ├── api_manager.py              # API key management
│   └── final_check.py              # Verification tool
│
├── 🚀 Launchers
│   ├── run_recon.py               # Cross-platform launcher
│   ├── run_recon.sh               # Unix/Linux launcher  
│   └── run_recon.bat              # Windows launcher
│
├── 🧪 Testing
│   └── test_tool.py               # Test suite
│
└── 📚 Documentation
    ├── README.md                  # English documentation
    ├── README_FA.md               # Persian documentation
    ├── QUICKSTART.md              # Quick start guide
    └── COMPLETE_GUIDE.md          # This file
```

### Tool Comparison

| Feature | Simple Tool | Advanced Tool |
|---------|-------------|---------------|
| Dependencies | None (stdlib only) | Multiple Python packages |
| External Tools | Not required | Optional (enhanced features) |
| API Integration | No | Yes (Shodan, VirusTotal, etc.) |
| Setup Time | Instant | 5-10 minutes |
| Subdomain Discovery | Basic (5 methods) | Advanced (15+ methods) |
| Parameter Extraction | Basic | Comprehensive |
| Vulnerability Scanning | No | Yes |
| Output Formats | 3 formats | 6+ formats |

---

## 💾 Installation Options

### Option 1: Zero Setup (Recommended for Testing)
```bash
# Just download and run
python3 simple_recon_tool.py -t target.com
```

### Option 2: Quick Setup  
```bash
# Install Python dependencies only
python3 setup.py
python3 advanced_recon_tool.py -t target.com
```

### Option 3: Complete Setup
```bash
# Full installation with external tools
python3 install.py
python3 recon_master.py target.com
```

### Option 4: Manual Setup
```bash
# Install Python packages
pip3 install requests beautifulsoup4 dnspython python-whois

# Install Go tools (optional)
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest

# Install system tools (optional)
sudo apt install nmap dnsutils whois  # Linux
brew install nmap bind whois          # macOS
```

---

## 🎮 Usage Examples

### Basic Reconnaissance
```bash
# Simple scan
python3 simple_recon_tool.py -t example.com

# Advanced scan
python3 advanced_recon_tool.py -t example.com

# Using master launcher
python3 recon_master.py example.com
```

### Custom Configuration
```bash
# Custom output directory
python3 advanced_recon_tool.py -t example.com -o my_results

# High-performance scan
python3 advanced_recon_tool.py -t example.com --threads 200 --timeout 30

# Verbose output
python3 advanced_recon_tool.py -t example.com --verbose
```

### Platform-Specific
```bash
# Linux/macOS
./run_recon.sh example.com

# Windows
run_recon.bat example.com

# Cross-platform
python3 run_recon.py example.com
```

### Batch Processing
```bash
# Multiple domains
for domain in google.com facebook.com twitter.com; do
    python3 advanced_recon_tool.py -t $domain -o results_$domain
done
```

---

## 🔑 API Configuration

### Interactive Setup
```bash
# Guided API setup
python3 api_manager.py --setup

# Check current status
python3 api_manager.py --status

# Test API keys
python3 api_manager.py --test
```

### Manual Configuration
Create `config.env` file:
```bash
# Shodan API (https://account.shodan.io/)
SHODAN_API_KEY=your_shodan_key_here

# VirusTotal API (https://www.virustotal.com/gui/my-apikey)
VIRUSTOTAL_API_KEY=your_virustotal_key_here

# SecurityTrails API (https://securitytrails.com/corp/api)
SECURITYTRAILS_API_KEY=your_securitytrails_key_here

# Censys API (https://censys.io/api)
CENSYS_API_ID=your_censys_id_here
CENSYS_API_SECRET=your_censys_secret_here
```

### Environment Variables
```bash
# Set for current session
export SHODAN_API_KEY="your_key"
export VIRUSTOTAL_API_KEY="your_key"

# Run tool
python3 advanced_recon_tool.py -t example.com
```

---

## 📊 Output Formats

### Generated Files
| File | Description | Use Case |
|------|-------------|----------|
| `*_report.json` | Complete data | Tool integration |
| `*_report.html` | Web report | Human review |
| `*_summary.txt` | Quick overview | Command line |
| `*_nuclei_template.yaml` | Nuclei template | Vulnerability scanning |
| `*_detailed.csv` | Spreadsheet data | Analysis |
| `*_report.md` | Markdown report | Documentation |
| `recon.log` | Execution log | Debugging |

### Report Contents
```
📊 Statistics Dashboard
├── Subdomains discovered
├── Parameters extracted  
├── Sensitive files found
└── IP addresses identified

🌐 Detailed Findings
├── Complete subdomain list
├── Parameter inventory
├── Sensitive file locations
├── Technology stack
├── Security headers analysis
└── Vulnerability indicators
```

---

## 🎯 Advanced Features

### Reconnaissance Phases

**Phase 1: Subdomain Discovery**
- Certificate Transparency logs
- DNS brute force
- JavaScript analysis
- Archive.org crawling
- Search engine dorking
- API-based discovery

**Phase 2: Parameter Extraction**
- JavaScript file analysis
- HTML form parsing
- URL pattern analysis
- Configuration file scanning
- API documentation parsing

**Phase 3: Sensitive File Discovery**
- Technology-specific files
- Backup file detection
- Version control exposure
- Cloud configuration files
- Docker files

**Phase 4: Real IP Discovery**
- Favicon hash analysis
- DNS history lookup
- Certificate analysis
- Shodan/Censys integration

**Phase 5: Additional Intelligence**
- WHOIS information
- Security header analysis
- Technology fingerprinting
- WAF detection

**Phase 6: Vulnerability Assessment**
- SQL injection testing
- Directory traversal testing
- XSS detection
- Configuration issues

### Integration Capabilities

**External Tools Supported:**
- subfinder, amass, assetfinder (subdomain discovery)
- httpx (HTTP probing)
- nuclei (vulnerability scanning)  
- nmap (port scanning)

**API Integrations:**
- Shodan (device search)
- VirusTotal (threat intelligence)
- SecurityTrails (DNS intelligence)
- Censys (internet scanning)

---

## 🔧 Troubleshooting

### Common Issues

**1. "Module not found" Error**
```bash
# Solution A: Use simple tool
python3 simple_recon_tool.py -t target.com

# Solution B: Install dependencies  
pip3 install requests beautifulsoup4 dnspython python-whois

# Solution C: Run setup
python3 setup.py
```

**2. "Permission denied" Error**
```bash
# Make files executable
chmod +x *.py *.sh

# Or run with python explicitly
python3 advanced_recon_tool.py -t target.com
```

**3. "Python not found" Error**
```bash
# Try different commands
python3 advanced_recon_tool.py -t target.com
python advanced_recon_tool.py -t target.com

# Check Python installation
which python3
which python
```

**4. Slow Performance**
```bash
# Reduce threads for slow networks
python3 advanced_recon_tool.py -t target.com --threads 20

# Increase timeout for slow targets
python3 advanced_recon_tool.py -t target.com --timeout 30
```

**5. API Errors**
```bash
# Check API key status
python3 api_manager.py --status

# Test API connectivity
python3 api_manager.py --test

# Run without APIs
unset SHODAN_API_KEY VIRUSTOTAL_API_KEY
python3 advanced_recon_tool.py -t target.com
```

### Verification Steps

**1. Check Installation**
```bash
python3 final_check.py
```

**2. Test Basic Functionality**
```bash
python3 test_tool.py
```

**3. Verify Output**
```bash
# Check if reports are generated
ls -la recon_output/

# Verify log file
cat recon_output/recon.log
```

---

## 🎯 Best Practices

### For Bug Bounty
1. **Start with subdomains** - They often have fewer protections
2. **Check JavaScript files** - Rich source of hidden endpoints
3. **Look for sensitive files** - Configuration files leak information
4. **Find real IPs** - Bypass WAFs and CDNs
5. **Document everything** - Use generated reports for tracking

### For Penetration Testing
1. **Use JSON output** - Easy integration with other tools
2. **Run Nuclei templates** - Automated vulnerability detection
3. **Analyze port scans** - Understand attack surface
4. **Check SSL configuration** - Find weak encryption
5. **Review security headers** - Identify missing protections

### Performance Optimization
```bash
# For large targets
python3 advanced_recon_tool.py -t target.com --threads 100

# For slow networks
python3 advanced_recon_tool.py -t target.com --threads 20 --timeout 30

# For quick overview
python3 simple_recon_tool.py -t target.com
```

---

## 🔄 Updates and Maintenance

### Keeping Current
```bash
# Update external tools
go install -a github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Update Python packages
pip3 install --upgrade requests beautifulsoup4

# Check for tool updates
python3 final_check.py
```

### Adding New Techniques
1. Add new methods to `advanced_modules.py`
2. Update patterns in main tool classes
3. Test with `python3 test_tool.py`
4. Update documentation

---

## 📞 Support Matrix

| Issue Type | Solution |
|------------|----------|
| Installation problems | Run `python3 setup.py` |
| Missing dependencies | Use `simple_recon_tool.py` |
| API key issues | Use `python3 api_manager.py --setup` |
| Performance issues | Adjust `--threads` and `--timeout` |
| Output problems | Check `recon.log` for details |
| General questions | Read `README.md` and `README_FA.md` |

---

**🎉 You now have the most comprehensive web reconnaissance tool available!**

The tool combines cutting-edge techniques from the latest bug bounty research, OSINT methodologies, and penetration testing frameworks to provide unparalleled information gathering capabilities.