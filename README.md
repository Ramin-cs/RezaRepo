# Professional XSS Scanner

A comprehensive, context-aware XSS vulnerability scanner with advanced reconnaissance capabilities and intelligent payload injection.

## Features

### 🔍 Advanced Reconnaissance
- **Complete Website Crawling**: Discovers all URLs, forms, and input points
- **Context-Aware Analysis**: Analyzes injection contexts (HTML, JavaScript, CSS, URL, etc.)
- **Input Point Discovery**: Identifies forms, parameters, and user input fields
- **Smart URL Discovery**: Follows links and discovers hidden endpoints

### 🎯 Intelligent Payload Injection
- **Context-Specific Payloads**: Different payloads for different injection contexts
- **Filter Bypass Techniques**: Advanced evasion methods for WAF and filters
- **Encoding Bypass**: Multiple encoding techniques (URL, HTML, Unicode, etc.)
- **Polyglot Payloads**: Multi-context payloads for complex scenarios

### 🛡️ Advanced Detection Engine
- **Pattern-Based Detection**: Comprehensive XSS pattern matching
- **Reflection Analysis**: Analyzes payload reflection and encoding
- **Context Analysis**: Determines injection context and vulnerability type
- **False Positive Reduction**: Advanced validation to reduce false positives

### 📊 Comprehensive Reporting
- **Multiple Output Formats**: JSON, HTML, CSV, XML, and Text reports
- **Executive Summary**: High-level risk assessment and recommendations
- **Detailed Evidence**: Complete vulnerability details with proof of concept
- **Visual Reports**: Beautiful HTML reports with charts and statistics

## Installation

### Prerequisites
- Python 3.7 or higher
- pip package manager

### Install Dependencies
```bash
pip install -r requirements.txt
```

### Quick Start
```bash
python xss_scanner.py https://example.com
```

## Usage

### Basic Usage
```bash
# Scan a single URL
python xss_scanner.py https://example.com

# Scan with custom depth and URL limit
python xss_scanner.py https://example.com --depth 5 --max-urls 200

# Verbose output
python xss_scanner.py https://example.com --verbose

# Custom timeout
python xss_scanner.py https://example.com --timeout 15
```

### Advanced Usage
```bash
# Deep scan with maximum coverage
python xss_scanner.py https://example.com --depth 10 --max-urls 500 --verbose

# Quick scan for testing
python xss_scanner.py https://example.com --depth 2 --max-urls 50
```

## Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `target` | Target URL to scan | Required |
| `--depth` | Maximum crawl depth | 3 |
| `--max-urls` | Maximum URLs to crawl | 100 |
| `--timeout` | Request timeout in seconds | 10 |
| `--verbose` | Enable verbose output | False |

## Architecture

### Core Components

1. **XSSScanner**: Main scanner class that orchestrates the scanning process
2. **ContextAnalyzer**: Analyzes injection contexts and suggests appropriate payloads
3. **VulnerabilityDetector**: Detects and validates XSS vulnerabilities
4. **ReportGenerator**: Generates comprehensive reports in multiple formats

### Scanning Process

1. **Reconnaissance Phase**: Discovers all URLs and input points
2. **Context Analysis**: Analyzes each input point for injection context
3. **Payload Injection**: Injects context-specific payloads
4. **Vulnerability Detection**: Detects and validates XSS vulnerabilities
5. **Report Generation**: Creates comprehensive reports

## Payload Categories

### Basic Payloads
- Standard XSS payloads for common scenarios
- Script tag injections
- Event handler injections
- JavaScript URL injections

### Filter Bypass Payloads
- Case variation techniques
- Encoding bypass methods
- WAF evasion techniques
- Character substitution

### Context-Specific Payloads
- **HTML Content**: Script tags, event handlers
- **HTML Attributes**: Event handler attributes
- **JavaScript Context**: Code injection payloads
- **CSS Context**: Expression and URL injections
- **URL Context**: JavaScript and data URLs

### Advanced Payloads
- **Polyglot Payloads**: Multi-context payloads
- **Encoding Variants**: Multiple encoding techniques
- **DOM-based**: Client-side XSS payloads
- **Stored XSS**: Persistent XSS payloads

## Detection Methods

### Pattern Matching
- Comprehensive regex patterns for XSS detection
- Script tag detection
- Event handler detection
- JavaScript URL detection
- CSS expression detection

### Reflection Analysis
- Payload reflection detection
- Encoding detection
- Filtering detection
- Partial reflection analysis

### Context Analysis
- HTML context detection
- JavaScript context detection
- CSS context detection
- URL context detection
- Comment context detection

## Report Formats

### JSON Report
- Machine-readable format
- Complete vulnerability details
- Metadata and statistics
- Easy integration with other tools

### HTML Report
- Beautiful visual reports
- Interactive elements
- Charts and statistics
- Executive summary

### CSV Report
- Spreadsheet-compatible format
- Easy data analysis
- Vulnerability details
- Filtering and sorting

### XML Report
- Structured data format
- Tool integration
- Complete vulnerability information
- Metadata included

### Text Report
- Human-readable format
- Console-friendly output
- Executive summary
- Detailed vulnerability information

## Configuration

### Advanced Configuration
The scanner can be configured through the `config.py` file:

- **Payload Customization**: Add custom payloads
- **Detection Patterns**: Modify detection patterns
- **Scanner Settings**: Adjust timeout, headers, etc.
- **Output Options**: Configure report generation

### Custom Payloads
Add custom payloads to the configuration:

```python
CUSTOM_PAYLOADS = {
    'my_context': [
        'custom_payload_1',
        'custom_payload_2'
    ]
}
```

## Security Considerations

### Ethical Use
- Only scan applications you own or have explicit permission to test
- Respect robots.txt and rate limiting
- Do not perform destructive testing
- Follow responsible disclosure practices

### Legal Compliance
- Ensure compliance with local laws and regulations
- Obtain proper authorization before testing
- Respect terms of service
- Follow responsible disclosure guidelines

## Performance Optimization

### Scanning Speed
- Adjust `--max-urls` for faster scans
- Use `--depth` to limit crawling depth
- Configure appropriate timeouts
- Use concurrent scanning for large applications

### Memory Usage
- Monitor memory usage during large scans
- Adjust batch sizes for large applications
- Use streaming for large responses
- Implement proper cleanup

## Troubleshooting

### Common Issues

1. **Connection Timeouts**
   - Increase timeout value
   - Check network connectivity
   - Verify target availability

2. **Rate Limiting**
   - Reduce scan speed
   - Add delays between requests
   - Use different user agents

3. **False Positives**
   - Review detection patterns
   - Adjust confidence thresholds
   - Validate findings manually

### Debug Mode
Enable verbose output for debugging:

```bash
python xss_scanner.py https://example.com --verbose
```

## Contributing

### Development Setup
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

### Code Style
- Follow PEP 8 guidelines
- Add docstrings to functions
- Include type hints
- Write comprehensive tests

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This tool is for educational and authorized testing purposes only. Users are responsible for ensuring they have proper authorization before testing any application. The authors are not responsible for any misuse of this tool.

## Support

For support, issues, or feature requests, please:
1. Check the documentation
2. Search existing issues
3. Create a new issue with detailed information
4. Provide sample code and error messages

## Changelog

### Version 1.0.0
- Initial release
- Advanced reconnaissance capabilities
- Context-aware payload injection
- Comprehensive vulnerability detection
- Multiple report formats
- Filter bypass techniques
- Encoding evasion methods

## Acknowledgments

- OWASP for security guidelines
- Security researchers for payload contributions
- Open source community for inspiration
- Beta testers for feedback and improvements