# 🛡️ Advanced Bug Bounty Tool

A comprehensive reconnaissance and vulnerability scanning tool designed for bug bounty hunters and security researchers. This tool performs thorough information gathering followed by targeted vulnerability scanning for XSS, SQL Injection, and Open Redirect vulnerabilities.

## 🌟 Features

### Phase 1: Comprehensive Reconnaissance
- **Subdomain Discovery**: Passive and active subdomain enumeration
- **Directory Discovery**: Automated directory and file enumeration
- **Parameter Discovery**: Historical parameter extraction using Wayback Machine
- **WAF Detection**: Web Application Firewall identification and fingerprinting
- **Live Validation**: Real-time validation of discovered assets

### Phase 2: Vulnerability Scanning
- **XSS Detection**: Comprehensive Cross-Site Scripting vulnerability scanning
- **SQL Injection**: Advanced SQL injection testing with multiple techniques
- **Open Redirect**: Unvalidated redirect vulnerability detection
- **False Positive Reduction**: Smart filtering to minimize false positives

### Phase 3: Professional Reporting
- **HTML Reports**: Beautiful, comprehensive HTML reports with detailed findings
- **JSON Export**: Machine-readable results for further analysis
- **Live Progress**: Real-time progress tracking and status updates
- **Executive Summary**: High-level overview with statistics and metrics

## 🚀 Quick Start

### Python Version

1. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

2. **Run Complete Assessment**
   ```bash
   python main.py example.com
   ```

3. **Run Specific Phases**
   ```bash
   # Reconnaissance only
   python main.py example.com --recon-only
   
   # Vulnerability scanning only
   python main.py example.com --vuln-only
   ```

### C# Version

1. **Build the Project**
   ```bash
   dotnet build BugBountyTool.csproj
   ```

2. **Run Complete Assessment**
   ```bash
   dotnet run -- example.com
   ```

3. **Run Specific Phases**
   ```bash
   # Reconnaissance only
   dotnet run -- example.com --recon-only
   
   # Vulnerability scanning only
   dotnet run -- example.com --vuln-only
   ```

## 📋 Requirements

### Python Version
- Python 3.7+
- Required packages (see `requirements.txt`):
  - `requests` - HTTP client library
  - `beautifulsoup4` - HTML parsing
  - `colorama` - Colored terminal output
  - `tqdm` - Progress bars
  - `dnspython` - DNS resolution
  - `python-nmap` - Network scanning
  - `selenium` - Web automation
  - `fake-useragent` - User agent rotation

### C# Version
- .NET 6.0+
- Required NuGet packages (see `BugBountyTool.csproj`):
  - `Newtonsoft.Json` - JSON serialization
  - `HtmlAgilityPack` - HTML parsing
  - `System.Net.Http` - HTTP client
  - `CommandLineParser` - Command line parsing
  - `Colorful.Console` - Colored terminal output
  - `DnsClient` - DNS resolution

## 🔧 Installation

### Python Installation

1. **Clone or Download**
   ```bash
   git clone <repository-url>
   cd bug-bounty-tool
   ```

2. **Create Virtual Environment** (Recommended)
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

### C# Installation

1. **Clone or Download**
   ```bash
   git clone <repository-url>
   cd bug-bounty-tool
   ```

2. **Restore Dependencies**
   ```bash
   dotnet restore
   ```

3. **Build Project**
   ```bash
   dotnet build
   ```

## 📖 Usage Examples

### Basic Usage

```bash
# Python
python main.py target.com

# C# 
dotnet run -- target.com
```

### Advanced Usage

```bash
# Custom output directory
python main.py target.com --output-dir /path/to/results

# Reconnaissance only
python main.py target.com --recon-only

# Vulnerability scanning only (requires existing recon results)
python main.py target.com --vuln-only
```

### Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `target` | Target domain to test | Required |
| `--output-dir` | Output directory for results | `bug_bounty_results` |
| `--recon-only` | Run only reconnaissance phase | `false` |
| `--vuln-only` | Run only vulnerability scanning | `false` |

## 🔍 How It Works

### Phase 1: Reconnaissance

1. **Passive Subdomain Discovery**
   - DNS brute force with common subdomain wordlist
   - Certificate Transparency logs analysis
   - Search engine result parsing
   - Historical data analysis

2. **Active Subdomain Validation**
   - HTTP/HTTPS connectivity testing
   - Response analysis and title extraction
   - Server header identification
   - Status code validation

3. **Directory Discovery**
   - Common directory and file enumeration
   - Response analysis and content length checking
   - Server fingerprinting
   - Status code analysis

4. **Parameter Discovery**
   - Wayback Machine historical URL analysis
   - Common parameter testing
   - Response comparison for parameter validation
   - URL structure analysis

5. **WAF Detection**
   - Malicious payload testing
   - Response header analysis
   - Error message pattern matching
   - WAF signature identification

### Phase 2: Vulnerability Scanning

1. **XSS Testing**
   - Reflected XSS payload injection
   - Stored XSS detection
   - DOM-based XSS testing
   - Context-aware payload generation

2. **SQL Injection Testing**
   - Union-based injection testing
   - Boolean-based blind injection
   - Time-based blind injection
   - Error-based injection testing
   - NoSQL injection testing

3. **Open Redirect Testing**
   - External domain redirect testing
   - Protocol-relative URL testing
   - JavaScript URL testing
   - Data URL testing
   - URL encoding bypass testing

### Phase 3: Report Generation

1. **Data Aggregation**
   - Vulnerability classification
   - Severity assessment
   - Evidence collection
   - Statistics calculation

2. **HTML Report Generation**
   - Professional report template
   - Interactive vulnerability details
   - Executive summary
   - Technical findings

3. **JSON Export**
   - Machine-readable results
   - API integration support
   - Further analysis capabilities

## 📊 Output Structure

```
bug_bounty_results/
├── target.com_recon.json          # Reconnaissance results
├── target.com_summary.json        # Scan summary
├── vulnerabilities_timestamp.json # Vulnerability details
└── bug_bounty_report_target.com_timestamp.html # HTML report
```

## 🎯 Vulnerability Types

### XSS (Cross-Site Scripting)
- **Reflected XSS**: Payload reflected in response
- **Stored XSS**: Payload stored on server
- **DOM-based XSS**: Client-side script execution

### SQL Injection
- **Union-based**: Data extraction via UNION queries
- **Boolean-based Blind**: Inference via boolean responses
- **Time-based Blind**: Inference via response timing
- **Error-based**: Information disclosure via errors

### Open Redirect
- **External Domain**: Redirects to external domains
- **Protocol-relative**: Protocol-relative URL redirects
- **JavaScript**: JavaScript-based redirects
- **Data URLs**: Data URL redirects

## ⚠️ Important Notes

### Legal and Ethical Considerations
- **Authorization Required**: Only use on systems you own or have explicit permission to test
- **Responsible Disclosure**: Report vulnerabilities through proper channels
- **Rate Limiting**: Tool includes built-in delays to avoid overwhelming targets
- **Compliance**: Ensure compliance with local laws and regulations

### Performance Considerations
- **Concurrent Requests**: Tool uses thread pools for efficient scanning
- **Rate Limiting**: Built-in delays prevent overwhelming target servers
- **Resource Usage**: Monitor system resources during large scans
- **Timeout Handling**: Proper timeout configuration for network requests

### False Positives
- **Smart Filtering**: Advanced filtering to reduce false positives
- **Manual Verification**: Always verify findings manually
- **Context Analysis**: Consider application context when interpreting results
- **Regular Updates**: Keep payloads and detection methods updated

## 🔧 Configuration

### Python Configuration

Create a `config.py` file for custom configuration:

```python
# Custom wordlists
SUBDOMAIN_WORDLIST = ['custom1', 'custom2', ...]
DIRECTORY_WORDLIST = ['admin', 'api', ...]
PARAMETER_WORDLIST = ['id', 'page', ...]

# Request settings
REQUEST_TIMEOUT = 10
MAX_CONCURRENT_REQUESTS = 20
USER_AGENT = 'Custom User Agent'

# Output settings
OUTPUT_FORMAT = 'html'  # html, json, both
VERBOSE_LOGGING = True
```

### C# Configuration

Modify `appsettings.json` for custom configuration:

```json
{
  "RequestSettings": {
    "Timeout": 10,
    "MaxConcurrentRequests": 20,
    "UserAgent": "Custom User Agent"
  },
  "OutputSettings": {
    "Format": "html",
    "VerboseLogging": true
  }
}
```

## 🐛 Troubleshooting

### Common Issues

1. **Import Errors**
   ```bash
   # Install missing dependencies
   pip install -r requirements.txt
   ```

2. **Permission Errors**
   ```bash
   # Check file permissions
   chmod +x main.py
   ```

3. **Network Timeouts**
   ```bash
   # Increase timeout in configuration
   REQUEST_TIMEOUT = 30
   ```

4. **Memory Issues**
   ```bash
   # Reduce concurrent requests
   MAX_CONCURRENT_REQUESTS = 10
   ```

### Debug Mode

Enable debug mode for detailed logging:

```bash
# Python
python main.py target.com --debug

# C#
dotnet run -- target.com --debug
```

## 🤝 Contributing

We welcome contributions! Please follow these guidelines:

1. **Fork the repository**
2. **Create a feature branch**
3. **Make your changes**
4. **Add tests for new functionality**
5. **Submit a pull request**

### Development Setup

```bash
# Python
git clone <repository-url>
cd bug-bounty-tool
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install -r requirements-dev.txt

# C#
git clone <repository-url>
cd bug-bounty-tool
dotnet restore
dotnet build
```

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This tool is for educational and authorized testing purposes only. Users are responsible for ensuring they have proper authorization before testing any systems. The authors are not responsible for any misuse or damage caused by this tool.

## 🙏 Acknowledgments

- OWASP for vulnerability classification standards
- Security researchers who contributed payloads and techniques
- Open source community for various libraries and tools
- Bug bounty community for feedback and improvements

## 📞 Support

For support, questions, or bug reports:

- **Issues**: Create an issue on GitHub
- **Discussions**: Use GitHub Discussions
- **Security**: Report security issues privately

## 🔄 Updates

### Version 1.0.0
- Initial release
- Complete reconnaissance functionality
- XSS, SQL Injection, and Open Redirect scanning
- HTML report generation
- Both Python and C# implementations

### Planned Features
- Additional vulnerability types (CSRF, SSRF, etc.)
- API integration capabilities
- GUI interface
- Cloud deployment options
- Advanced evasion techniques

---

**Happy Hunting! 🎯**

Remember to always test responsibly and within legal boundaries. Good luck with your bug bounty journey!