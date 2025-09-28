# 🔍 Advanced Open Redirect Vulnerability Scanner

A comprehensive, professional-grade scanner for detecting Open Redirect vulnerabilities with advanced WAF bypass techniques and Chrome-based automation.

## ✨ What You Get

- **🔍 Comprehensive Reconnaissance**: Extracts parameters from URLs, forms, JavaScript, headers, meta tags, and cookies
- **🎯 Advanced Payload Testing**: Tests hundreds of payloads with 78+ WAF bypass techniques
- **🌐 Chrome Automation**: Uses real browser automation for accurate redirect testing
- **📸 Screenshot Capture**: Automatically captures PoC screenshots for confirmed vulnerabilities
- **⚡ Parallel Processing**: Multi-threaded scanning for faster results
- **📊 Professional Reporting**: Generates detailed HTML reports with vulnerability analysis
- **📝 Comprehensive Logging**: Detailed logging system for debugging and analysis
- **🛡️ WAF Bypass**: Advanced techniques to bypass common WAFs and filters
- **🔧 Configurable**: Extensive configuration options and presets
- **🐳 Docker Support**: Ready-to-use Docker containers

## 🚀 Quick Start

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Test the Scanner
```bash
python3 run_simple.py
```

### 3. Run a Scan
```bash
# Basic scan
python3 main.py https://target-website.com

# Advanced scan
python3 main.py https://target-website.com -o results -j 20 -d 3

# Using presets
python3 main.py --preset thorough https://target-website.com
```

## 📊 Scanner Capabilities

### Vulnerability Types Detected
- **URL Parameter Redirects**: `?url=`, `?redirect=`, `?next=`, `?return=`, `?goto=`, etc.
- **Form Parameter Redirects**: Hidden fields, form actions, input values
- **JavaScript Variable Redirects**: `window.location`, `document.location`, etc.
- **Meta Tag Redirects**: `<meta http-equiv="refresh">`
- **Cookie Parameter Redirects**: Redirect-related cookies
- **HTTP Header Redirects**: Custom headers, Location header

### WAF Bypass Techniques (78+)
- **Encoding Techniques**: URL encoding, Unicode encoding, Hex encoding, Octal encoding, Mixed encoding, Base64 encoding, HTML/XML entity encoding
- **Character Manipulation**: Case variations, Whitespace variations, Control character injection, Null byte injection, Newline injection, Tab injection
- **Advanced Techniques**: Unicode normalization, IDN homograph attacks, Punycode encoding, Protocol variations, Path manipulation

### Payload Generation
- **Base Payloads**: 18 different base payload types
- **Generated Payloads**: 144+ payloads per base payload
- **Custom Payloads**: 200+ custom payloads included
- **Total Payloads**: Thousands of unique payloads for comprehensive testing

## 🎯 Usage Examples

### Basic Scanning
```bash
# Simple scan
python3 main.py https://example.com

# Scan with custom output directory
python3 main.py https://example.com -o my_results

# Scan with more threads for faster results
python3 main.py https://example.com -j 20
```

### Advanced Scanning
```bash
# Thorough scan with maximum depth
python3 main.py --preset thorough https://example.com

# Stealth scan with delays
python3 main.py --preset stealth https://example.com

# Debug mode with detailed logging
python3 main.py --preset debug https://example.com

# Custom configuration
python3 main.py -c my_config.json https://example.com
```

### Using Run Script
```bash
# Make executable
chmod +x run.sh

# Basic scan
./run.sh https://example.com

# Advanced scan
./run.sh -o results -j 20 -d 3 https://example.com

# Using presets
./run.sh --preset thorough https://example.com
```

### Using Docker
```bash
# Build image
docker build -t open-redirect-scanner .

# Run scan
docker run --rm -v $(pwd)/results:/app/scan_results open-redirect-scanner https://example.com

# Using docker-compose
docker-compose up
```

## 📁 Project Structure

```
open-redirect-scanner/
├── main.py                    # Main entry point
├── open_redirect_scanner.py   # Core scanner class
├── recon_module.py            # Reconnaissance module
├── payload_module.py          # Payload testing module
├── chrome_module.py           # Chrome automation module
├── report_module.py           # Report generation module
├── logging_module.py          # Logging system
├── configuration.py           # Configuration management
├── run.sh                     # Run script
├── run_simple.py              # Simple test script
├── quick_test.py              # Quick test script
├── test_suite.py              # Full test suite
├── performance_test.py        # Performance tests
├── example_usage.py           # Usage examples
├── requirements.txt           # Python dependencies
├── setup.py                   # Package setup
├── pyproject.toml             # Modern Python packaging
├── Dockerfile                 # Docker configuration
├── docker-compose.yml         # Docker Compose
├── Makefile                   # Build automation
├── README.md                  # Detailed documentation
├── FINAL_README.md            # This file
├── LICENSE                    # MIT License
├── CHANGELOG.md               # Version history
├── CONTRIBUTING.md            # Contribution guidelines
├── SECURITY.md                # Security policy
└── .github/
    └── workflows/
        └── ci.yml             # CI/CD pipeline
```

## 🔧 Configuration Options

### Command Line Options
```bash
# Basic options
-o, --output DIR          Output directory
-j, --threads NUM         Number of threads
-d, --depth NUM           Maximum depth
--timeout NUM             Request timeout

# Chrome options
--no-headless             Run Chrome in visible mode
--chrome-window-size      Chrome window size

# Scanning options
--no-recon                Skip reconnaissance
--no-payloads             Skip payload testing
--no-screenshots          Skip screenshots
--no-parallel             Disable parallel processing

# Payload options
--max-payloads NUM        Max payloads per parameter
--no-waf-bypass           Disable WAF bypass

# Logging options
--log-level LEVEL         Log level
--no-log-file             Disable file logging
--no-log-console          Disable console logging

# Security options
--ignore-robots           Ignore robots.txt
--max-requests-per-second Max requests per second
--delay                   Delay between requests

# Proxy options
--proxy-url URL           Proxy URL
--proxy-username USER     Proxy username
--proxy-password PASS     Proxy password
```

### Presets
- **`fast`**: Fast scan with minimal depth
- **`thorough`**: Comprehensive scan with full depth
- **`stealth`**: Stealth scan with delays
- **`debug`**: Debug mode with detailed logging

## 📊 Output and Reports

The scanner generates comprehensive outputs:

### 1. HTML Report
- **Location**: `scan_results/reports/open_redirect_report_YYYYMMDD_HHMMSS.html`
- **Content**: Detailed vulnerability analysis with screenshots
- **Features**: Interactive interface, severity classification, PoC screenshots

### 2. JSON Report
- **Location**: `scan_results/reports/open_redirect_report_YYYYMMDD_HHMMSS.json`
- **Content**: Machine-readable vulnerability data
- **Features**: Structured data for integration with other tools

### 3. Screenshots
- **Location**: `scan_results/screenshots/`
- **Content**: PoC screenshots for confirmed vulnerabilities
- **Format**: PNG files with descriptive names

### 4. Logs
- **Location**: `scan_results/logs/`
- **Content**: Detailed scan logs
- **Files**: Main log, error log, debug log

## 🧪 Testing

### Run Tests
```bash
# Quick functionality test
python3 run_simple.py

# Full test suite
python3 test_suite.py

# Performance test
python3 performance_test.py

# Using run script
./run.sh --test
./run.sh --test-suite
./run.sh --performance-test
```

## 🚨 Security Notice

⚠️ **IMPORTANT**: This tool is designed for authorized security testing only. Always ensure you have proper authorization before testing any website or application.

### Legal Compliance
- Only test systems you own or have explicit permission to test
- Follow all applicable laws and regulations
- Use the tool responsibly and ethically
- Report any security issues you discover

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Areas for Contribution
- New WAF bypass techniques
- Additional payload types
- Performance improvements
- Better error handling
- Enhanced reporting features
- Documentation improvements

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

### Getting Help
- Check the [documentation](README.md)
- Look at [examples](example_usage.py)
- Run [tests](test_suite.py)
- Open an [issue](https://github.com/example/open-redirect-scanner/issues)

### Troubleshooting
- Ensure Chrome is installed and accessible
- Check Python version (3.8+)
- Verify all dependencies are installed
- Check log files for detailed error information

## 📈 Performance

### System Requirements
- **CPU**: 2+ cores recommended
- **RAM**: 4GB+ recommended
- **Storage**: 1GB+ free space
- **Network**: Stable internet connection

### Optimization Tips
- Use appropriate thread count for your system
- Adjust max depth based on target size
- Use presets for common scenarios
- Monitor memory usage during scans

## 🔄 Updates

### Version History
See [CHANGELOG.md](CHANGELOG.md) for detailed version history.

### Updating
```bash
git pull origin main
pip install -r requirements.txt --upgrade
```

## 📞 Contact

- **Issues**: [GitHub Issues](https://github.com/example/open-redirect-scanner/issues)
- **Discussions**: [GitHub Discussions](https://github.com/example/open-redirect-scanner/discussions)
- **Security**: [Security Policy](SECURITY.md)

## 🙏 Acknowledgments

- Security community for research and techniques
- Open source contributors
- Bug bounty researchers
- Penetration testing community

---

**Happy Hunting! 🎯**

## 🎉 What's Included

This scanner includes everything you need for comprehensive Open Redirect testing:

- **200+ Custom Payloads** - Ready-to-use payloads for testing
- **78+ WAF Bypass Techniques** - Advanced techniques to bypass common filters
- **149 Redirect Parameters** - Comprehensive parameter detection
- **43 JavaScript Patterns** - Advanced JavaScript redirect detection
- **43 Header Patterns** - HTTP header redirect detection
- **4 Meta Refresh Patterns** - Meta tag redirect detection
- **18 Base Payload Types** - Multiple payload categories
- **144+ Generated Payloads** - Per base payload for comprehensive testing

The scanner is production-ready and includes professional documentation, testing, and CI/CD pipeline.