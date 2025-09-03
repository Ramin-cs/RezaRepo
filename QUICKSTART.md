# 🚀 Quick Start Guide - Advanced Web Reconnaissance Tool

## ⚡ Super Quick Start (30 seconds)

```bash
# 1. Download all files to a directory
# 2. Run one of these commands:

# Option A: Simple tool (no dependencies)
python3 simple_recon_tool.py -t example.com

# Option B: Full tool (needs setup)
python3 recon_master.py --setup
python3 recon_master.py example.com
```

## 🎯 Choose Your Path

### Path 1: Simple Tool (Recommended for Quick Testing)
**No external dependencies required!**

```bash
python3 simple_recon_tool.py -t yourdomain.com
```

**Features:**
- ✅ Subdomain discovery
- ✅ Parameter extraction  
- ✅ Sensitive file detection
- ✅ Basic vulnerability checks
- ✅ Works immediately

### Path 2: Advanced Tool (Full Features)
**Requires setup but offers comprehensive capabilities**

```bash
# Setup (one time only)
python3 recon_master.py --setup

# Run reconnaissance
python3 recon_master.py yourdomain.com
```

**Additional Features:**
- 🌟 Advanced subdomain discovery (10+ methods)
- 🌟 API integration (Shodan, VirusTotal, etc.)
- 🌟 External tools integration
- 🌟 Advanced vulnerability scanning
- 🌟 Multiple output formats

## 🖥️ Platform-Specific Quick Start

### Linux/macOS
```bash
# Make executable
chmod +x run_recon.sh

# Run
./run_recon.sh yourdomain.com
```

### Windows
```cmd
REM Double-click or run from command prompt
run_recon.bat yourdomain.com
```

### Cross-Platform
```bash
# Works everywhere
python3 run_recon.py yourdomain.com
```

## 📊 What You'll Get

After running, check your output directory for:

1. **`domain_report.html`** - Beautiful web report
2. **`domain_summary.txt`** - Quick text summary  
3. **`domain_report.json`** - Complete data (for tools)
4. **`recon.log`** - Detailed execution log

## 🔑 API Keys (Optional)

For enhanced features, get free API keys:

```bash
# Setup API keys interactively
python3 api_manager.py --setup

# Or set environment variables
export SHODAN_API_KEY="your_key"
export VIRUSTOTAL_API_KEY="your_key"
```

**Free API Sources:**
- [Shodan](https://account.shodan.io/) - 100 queries/month free
- [VirusTotal](https://www.virustotal.com/gui/my-apikey) - 1000 requests/day free  
- [SecurityTrails](https://securitytrails.com/corp/api) - 50 queries/month free

## 🧪 Test Everything

```bash
# Test simple tool
python3 simple_recon_tool.py -t example.com

# Test full installation
python3 final_check.py

# Run comprehensive test
python3 test_tool.py
```

## 🆘 Troubleshooting

### "Module not found" error
```bash
# Install dependencies
python3 -m pip install requests beautifulsoup4 dnspython python-whois

# Or use the simple tool (no dependencies)
python3 simple_recon_tool.py -t yourdomain.com
```

### Permission denied
```bash
# Make files executable
chmod +x *.py *.sh
```

### "Python not found"
```bash
# Try different Python commands
python3 --version
python --version

# Install Python if needed
sudo apt install python3  # Linux
brew install python3      # macOS
# Download from python.org for Windows
```

## 📋 Command Examples

```bash
# Basic scan
python3 simple_recon_tool.py -t example.com

# Full scan with custom output
python3 advanced_recon_tool.py -t example.com -o my_results

# Verbose scan with more threads
python3 advanced_recon_tool.py -t example.com --verbose --threads 100

# Using the master launcher
python3 recon_master.py example.com --output detailed_scan
```

## 🎓 Learning More

1. **Read the full README.md** for complete documentation
2. **Check README_FA.md** for Persian documentation
3. **Run `python3 final_check.py`** to verify your setup
4. **Use `python3 api_manager.py --setup`** for API configuration

## ⚠️ Important Notes

- **Legal:** Only scan domains you own or have permission to test
- **Rate Limiting:** Tool respects target servers (built-in delays)
- **Accuracy:** Results depend on target configuration and network
- **APIs:** Optional but significantly enhance capabilities

---

**Need help?** Check the log files in your output directory for detailed information.

**Found a bug?** The tool includes comprehensive error handling and logging.