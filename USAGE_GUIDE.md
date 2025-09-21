# Advanced XSS Scanner - Usage Guide

## Quick Start

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Run the Scanner
```bash
python3 advanced_xss_scanner.py https://target-website.com
```

### 3. View Results
- Check `recon_report.json` for reconnaissance findings
- Check `xss_report.json` for XSS vulnerabilities
- View screenshots in the current directory

## Testing with Local Vulnerable Application

### 1. Start Test Application
```bash
# Install Flask
pip install -r test_requirements.txt

# Start the vulnerable test application
python3 test_vulnerable_app.py
```

### 2. Test the Scanner
```bash
# In another terminal
python3 advanced_xss_scanner.py http://localhost:5000
```

## Understanding the Output

### Reconnaissance Report (recon_report.json)
```json
{
  "target": "https://example.com",
  "timestamp": "2024-01-01T12:00:00",
  "subdomains": ["www.example.com", "api.example.com"],
  "discovered_urls": ["https://example.com/page1", "https://example.com/page2"],
  "forms": [
    {
      "action": "https://example.com/search",
      "method": "POST",
      "inputs": [
        {"name": "query", "type": "text", "required": false}
      ]
    }
  ],
  "parameters": ["search", "id", "category"],
  "technologies": ["Apache", "PHP", "jQuery"],
  "sensitive_files": ["https://example.com/admin", "https://example.com/config.php"]
}
```

### XSS Vulnerability Report (xss_report.json)
```json
{
  "scan_info": {
    "target": "https://example.com",
    "timestamp": "2024-01-01T12:00:00",
    "total_vulnerabilities": 2
  },
  "vulnerabilities": [
    {
      "type": "XSS",
      "url": "https://example.com/search",
      "parameter": "query",
      "payload": "<script>alert('XSS')</script>",
      "context": "html",
      "method": "POST",
      "severity": "High",
      "timestamp": "2024-01-01T12:00:00",
      "screenshot": "xss_poc_20240101_120000_abc12345.png"
    }
  ]
}
```

## Advanced Configuration

### Customizing Scan Parameters
Edit the scanner code to modify:

```python
# In DeepReconnaissance class
max_depth = 5        # Maximum crawling depth
max_threads = 20     # Concurrent threads

# In AdvancedXSSScanner class
timeout = 15         # Request timeout
```

### Adding Custom Payloads
Add your own payloads to the `generate_payloads()` method:

```python
def generate_payloads(self):
    payloads = {
        'html_context': [
            # Add your custom payloads here
            '<script>console.log("XSS")</script>',
            '<img src=x onerror=console.log("XSS")>',
        ],
        # ... other contexts
    }
```

## Troubleshooting

### Common Issues

1. **ChromeDriver not found**
   ```bash
   # Install ChromeDriver
   sudo apt-get install chromium-chromedriver
   # or
   brew install chromedriver
   ```

2. **Permission denied**
   ```bash
   chmod +x advanced_xss_scanner.py
   ```

3. **Module not found**
   ```bash
   pip install -r requirements.txt
   ```

4. **Screenshot not working**
   - Ensure Chrome/Chromium is installed
   - Check ChromeDriver installation
   - Verify display settings (for headless mode)

### Debug Mode
Enable debug logging by modifying the logging level:

```python
logging.basicConfig(level=logging.DEBUG)
```

## Security Considerations

### Legal and Ethical Use
- Only test systems you own or have explicit permission to test
- Respect robots.txt and rate limiting
- Do not perform denial-of-service attacks
- Report vulnerabilities responsibly

### Best Practices
- Use in isolated test environments
- Keep the scanner updated
- Review results carefully before taking action
- Document findings properly

## Performance Optimization

### For Large Targets
- Increase `max_threads` for faster scanning
- Adjust `max_depth` based on target size
- Use specific URL patterns to limit scope

### For Slow Networks
- Increase timeout values
- Reduce concurrent threads
- Use headless mode for screenshots

## Integration

### CI/CD Pipeline
```yaml
# Example GitHub Actions workflow
- name: Run XSS Scanner
  run: |
    pip install -r requirements.txt
    python3 advanced_xss_scanner.py ${{ secrets.TARGET_URL }}
```

### Custom Reporting
Modify the `generate_xss_report()` method to output in your preferred format (HTML, PDF, etc.).

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## Support

For issues and questions:
1. Check the troubleshooting section
2. Review the logs in `xss_scanner.log`
3. Create an issue with detailed information
4. Include target URL (if safe to share) and error messages