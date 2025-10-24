# 🔍 Advanced Subdomain Enumeration Tool

A comprehensive subdomain enumeration tool with HTTP/HTTPS probing, premium API integration, and multiple discovery techniques.

## ✨ Features

- **Passive Discovery**: Certificate Transparency, Search Engines, Web Archives, Passive DNS
- **Active Discovery**: DNS Brute Force, Zone Transfer, Reverse DNS, Virtual Host Discovery
- **HTTP/HTTPS Probing**: Live subdomain verification with status codes, titles, response times
- **Premium API Integration**: Shodan, VirusTotal, SecurityTrails, Chaos, Censys
- **Multiple Output Formats**: JSON, CSV, TXT
- **Network Scanning**: Nmap integration for port scanning and service discovery
- **Error Handling**: Robust error handling and graceful fallbacks

## 🚀 Quick Start

### Installation

1. **Clone the repository:**
```bash
git clone <repository-url>
cd subdomain-enumeration-tool
```

2. **Install dependencies:**
```bash
pip install -r requirements.txt
```

3. **Configure API keys (optional):**
```bash
cp config.py.example config.py
# Edit config.py with your API keys
```

### Basic Usage

```bash
# Basic enumeration
python3 subdomains.py -d example.com

# Quick scan
python3 subdomains.py -d example.com --quick

# Aggressive scan with all features
python3 subdomains.py -d example.com --aggressive

# Passive only (no active DNS queries)
python3 subdomains.py -d example.com --passive

# Custom output formats
python3 subdomains.py -d example.com --json --csv

# Silent mode (only results)
python3 subdomains.py -d example.com --silent
```

## 📋 Requirements

- Python 3.7+
- Internet connection
- Optional: Nmap (for advanced network scanning)
- Optional: API keys for premium services

## 🔧 Configuration

### API Keys Setup

Edit `config.py` to add your API keys:

```python
API_KEYS = {
    'shodan': 'your_shodan_api_key',
    'virustotal': 'your_virustotal_api_key',
    'securitytrails': 'your_securitytrails_api_key',
    'chaos': 'your_chaos_api_key',
    'censys': 'your_censys_api_key'
}
```

### Check API Status

```bash
python3 subdomains.py --show-apis
```

## 📊 Output Files

The tool generates several output files:

- `domain_subdomains.txt` - Complete subdomain list
- `domain_live_subdomains.txt` - Live subdomains with details
- `domain_simple_list.txt` - Simple subdomain list
- `domain_subdomains.json` - JSON format (if --json specified)
- `domain_subdomains.csv` - CSV format (if --csv specified)
- `domain_internal_ips.txt` - Internal IPs discovered (if any)

## 🛠️ Recent Fixes

### Version 2.0 - Error Fixes

- ✅ **Fixed CSV Output Error**: Resolved `cannot access local variable 'csv_output_file'` error
- ✅ **Fixed HTTPX Probe Error**: Resolved `cannot unpack non-iterable NoneType object` error
- ✅ **Improved Nmap Detection**: Enhanced detection to check if nmap binary is in PATH
- ✅ **Fixed SSL Probing Error**: Added proper error handling for certificate parsing
- ✅ **Enhanced Error Handling**: Better validation and error recovery throughout

## 📖 Advanced Usage

### Command Line Options

```bash
python3 subdomains.py -h
```

### Examples

```bash
# Maximum discovery (default)
python3 subdomains.py -d example.com

# Quick scan with reduced coverage
python3 subdomains.py -d example.com --quick

# Aggressive mode with maximum resources
python3 subdomains.py -d example.com --aggressive

# Custom thread count and timeout
python3 subdomains.py -d example.com -t 200 --timeout 20

# Specific sources only
python3 subdomains.py -d example.com --sources ct dns search

# Custom wordlist
python3 subdomains.py -d example.com --wordlist custom_wordlist.txt
```

## 🔍 Discovery Methods

### Passive Methods
- Certificate Transparency logs
- Search engines (Bing)
- Web archives (Wayback Machine)
- Passive DNS (Google DNS, Cloudflare DNS)
- GitHub search
- Premium APIs (Shodan, VirusTotal, etc.)

### Active Methods
- DNS brute force
- DNS zone transfer attempts
- Reverse DNS lookups
- Virtual host discovery
- SSL certificate probing
- Network scanning (Nmap)
- Port scanning

## 🐛 Troubleshooting

### Common Issues

1. **Nmap not found**: Install nmap or the tool will use alternative methods
2. **API rate limits**: The tool handles rate limiting automatically
3. **Network timeouts**: Adjust timeout with `--timeout` parameter
4. **Permission errors**: Ensure write permissions for output directory

### Debug Mode

```bash
python3 subdomains.py -d example.com -v
```

## 📝 License

This project is for educational and authorized testing purposes only. Use responsibly and in accordance with applicable laws and regulations.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.

## ⚠️ Disclaimer

This tool is intended for authorized security testing and educational purposes only. Users are responsible for ensuring they have proper authorization before testing any domains or networks.