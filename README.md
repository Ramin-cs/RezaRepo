# Advanced Web Reconnaissance Tool

A comprehensive, cross-platform information gathering tool designed for bug bounty hunters and penetration testers. This tool performs extensive reconnaissance through multiple phases to extract maximum information from target domains.

## 🌟 Features

### Phase 1: Subdomain Discovery
- **Certificate Transparency Logs** - Extracts subdomains from CT logs
- **DNS Brute Force** - Tests common subdomain patterns
- **Search Engine Dorking** - Uses search engines to find subdomains
- **Archive Analysis** - Searches Wayback Machine archives
- **JavaScript Analysis** - Deep analysis of JS files for hidden subdomains
- **Passive DNS** - Queries multiple DNS sources
- **API Integration** - Shodan, VirusTotal, SecurityTrails APIs

### Phase 2: Parameter Extraction
- **JavaScript Analysis** - Extracts parameters from JS files
- **HTML Form Analysis** - Discovers form parameters
- **URL Pattern Analysis** - Extracts parameters from archived URLs
- **Configuration File Analysis** - Analyzes config files for parameters
- **Swagger/OpenAPI Discovery** - Extracts API parameters
- **GraphQL Introspection** - Discovers GraphQL parameters

### Phase 3: Sensitive File Discovery
- **Technology-Based Discovery** - Finds files based on detected technologies
- **Common Sensitive Files** - robots.txt, sitemap.xml, etc.
- **Backup File Discovery** - Searches for backup and temporary files
- **Version Control Files** - Git, SVN, Mercurial files
- **Docker Configuration** - Docker and container config files
- **Cloud Configuration** - AWS, Azure, GCP config files

### Phase 4: Real IP Discovery
- **Favicon Hash Analysis** - Uses favicon hashes for IP discovery
- **DNS History Analysis** - Searches historical DNS records
- **Certificate Analysis** - Extracts IPs from SSL certificates
- **Direct DNS Resolution** - Resolves all discovered subdomains
- **Shodan/Censys Integration** - Advanced IP discovery via APIs

### Phase 5: Additional Reconnaissance
- **WHOIS Information** - Comprehensive domain information
- **Security Headers Analysis** - Checks security header implementation
- **Directory Enumeration** - Discovers hidden directories
- **Technology Fingerprinting** - Advanced technology detection
- **WAF Detection** - Identifies security solutions
- **SSL/TLS Analysis** - Analyzes encryption configuration
- **HTTP Methods Testing** - Tests supported HTTP methods
- **CORS Analysis** - Checks CORS configuration

### Phase 6: Vulnerability Assessment
- **SQL Injection Testing** - Basic SQL injection detection
- **Directory Traversal Testing** - Path traversal vulnerability testing
- **XSS Detection** - Basic XSS vulnerability testing
- **Command Injection Testing** - Command injection detection

## 🚀 Installation

### Quick Setup
```bash
# Clone or download the tool
git clone <repository> or download the files

# Run the setup script
python setup.py

# (Optional) Configure API keys
cp config.env.template config.env
# Edit config.env with your API keys
```

### Manual Installation
```bash
# Install Python dependencies
pip install -r requirements.txt

# Install system dependencies (Linux/Ubuntu)
sudo apt-get update
sudo apt-get install -y dnsutils whois nmap

# Install system dependencies (macOS)
brew install bind whois nmap

# Install system dependencies (Windows)
# Use Windows Subsystem for Linux (WSL) for best compatibility
```

## 📖 Usage

### Basic Usage
```bash
# Basic reconnaissance
python advanced_recon_tool.py -t example.com

# Custom output directory
python advanced_recon_tool.py -t example.com -o my_recon_results

# Verbose output with custom thread count
python advanced_recon_tool.py -t https://example.com --threads 100 --verbose
```

### Advanced Usage with API Keys
```bash
# Set API keys as environment variables
export SHODAN_API_KEY="your_key_here"
export VIRUSTOTAL_API_KEY="your_key_here"
export SECURITYTRAILS_API_KEY="your_key_here"

# Or use config file
python advanced_recon_tool.py -t example.com
```

### Command Line Options
```
-t, --target      Target domain (required)
-o, --output      Output directory (default: recon_output)
--threads         Number of threads (default: 50)
--timeout         Request timeout in seconds (default: 15)
--verbose         Enable verbose output
```

## 📊 Output Formats

The tool generates multiple output formats:

1. **JSON Report** - Machine-readable detailed results
2. **HTML Report** - Beautiful web-based report with statistics
3. **Text Summary** - Quick overview of findings
4. **Nuclei Template** - Compatible with Nuclei scanner
5. **CSV Report** - Spreadsheet-compatible format
6. **Markdown Report** - GitHub-compatible documentation

## 🔧 Configuration

### API Keys (Optional but Recommended)
To unlock full functionality, obtain API keys from:

- **Shodan** (https://account.shodan.io/) - For advanced IP discovery
- **VirusTotal** (https://www.virustotal.com/gui/my-apikey) - For subdomain discovery
- **SecurityTrails** (https://securitytrails.com/corp/api) - For DNS history
- **Censys** (https://censys.io/api) - For certificate analysis

### Environment Variables
```bash
export SHODAN_API_KEY="your_shodan_key"
export VIRUSTOTAL_API_KEY="your_virustotal_key"
export SECURITYTRAILS_API_KEY="your_securitytrails_key"
export CENSYS_API_ID="your_censys_id"
export CENSYS_API_SECRET="your_censys_secret"
```

## 🛡️ Security and Legal Notice

**IMPORTANT:** This tool is designed for legitimate security testing purposes only.

- ✅ Use only on domains you own or have explicit permission to test
- ✅ Follow responsible disclosure practices
- ✅ Respect rate limits and terms of service
- ❌ Do not use for malicious purposes
- ❌ Do not test without proper authorization

## 🔍 What Makes This Tool Special

### Comprehensive Coverage
- **Multi-Source Discovery** - Combines multiple data sources for maximum coverage
- **Deep JavaScript Analysis** - Extracts hidden endpoints and parameters
- **Technology-Aware** - Adapts scanning based on detected technologies
- **Historical Data** - Uses web archives and DNS history
- **API Integration** - Leverages premium APIs when available

### Advanced Techniques
- **Favicon Hash Matching** - Discovers real IPs behind CDNs
- **Certificate Transparency** - Finds subdomains from SSL certificates
- **GraphQL Introspection** - Discovers GraphQL schemas and parameters
- **Swagger/OpenAPI Analysis** - Extracts API documentation
- **WAF Detection** - Identifies security solutions

### Cross-Platform Design
- **Python-Based** - Runs on Windows, Linux, and macOS
- **Minimal Dependencies** - Works with standard Python libraries
- **Graceful Degradation** - Functions even without optional tools
- **Multiple Output Formats** - Compatible with various analysis tools

## 🎯 Use Cases

### Bug Bounty Hunting
- Comprehensive subdomain enumeration
- Hidden parameter discovery
- Sensitive file identification
- Real IP discovery for bypassing CDNs

### Penetration Testing
- Initial reconnaissance phase
- Attack surface mapping
- Technology stack identification
- Vulnerability assessment preparation

### Security Assessment
- External attack surface analysis
- Information leakage detection
- Configuration security review
- Compliance checking

## 📈 Performance

- **Concurrent Processing** - Multi-threaded for speed
- **Rate Limiting** - Respects target server resources
- **Memory Efficient** - Handles large datasets
- **Resumable** - Can continue interrupted scans

## 🤝 Contributing

This tool incorporates the latest reconnaissance techniques from:
- Bug bounty writeups and methodologies
- Open source intelligence (OSINT) research
- Penetration testing frameworks
- Security research papers

## 📞 Support

For issues or questions:
1. Check the generated log files for detailed error information
2. Ensure all dependencies are properly installed
3. Verify network connectivity and permissions
4. Review the target domain format

## 🔄 Updates

This tool is designed to be easily extensible. New modules can be added to `advanced_modules.py` to incorporate emerging techniques and data sources.

---

**Disclaimer:** This tool is provided for educational and authorized testing purposes only. Users are responsible for ensuring they have proper authorization before testing any target.