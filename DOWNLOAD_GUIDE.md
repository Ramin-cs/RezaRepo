# 🎯 Subdomain Enumeration Tool v2.0 - Release Package

## 📥 Download Files

### Option 1: Complete Package (Recommended)
**File**: `subdomain-tool-v2.0.tar.gz`

This is the complete package with all files ready for use.

### Option 2: ZIP Files
- `subdomain-enumeration-tool-complete-v2.0.zip` (42.5 KB)
- `subdomain-enumeration-tool-v2.0.zip` (41.4 KB)

## 🚀 Quick Setup

1. **Download and extract:**
```bash
# For tar.gz file
tar -xzf subdomain-tool-v2.0.tar.gz
cd subdomain-tool-v2.0

# For zip files
unzip subdomain-enumeration-tool-complete-v2.0.zip
cd subdomain-enumeration-tool-complete-v2.0
```

2. **Install dependencies:**
```bash
pip3 install -r requirements.txt
```

3. **Run installation script (if available):**
```bash
chmod +x install.sh
./install.sh
```

4. **Test the installation:**
```bash
python3 test.py
```

5. **Start using:**
```bash
python3 subdomains.py -d example.com
```

## ✨ What's Fixed in v2.0

- ✅ **CSV Output Error**: Fixed `cannot access local variable 'csv_output_file'` error
- ✅ **HTTPX Probe Error**: Fixed `cannot unpack non-iterable NoneType object` error  
- ✅ **Nmap Detection**: Improved detection and graceful fallback
- ✅ **SSL Probing Error**: Fixed certificate parsing error
- ✅ **Enhanced Error Handling**: Better validation throughout

## 📁 File Structure

```
subdomain-tool-v2.0/
├── subdomains.py              # Main enumeration script (FIXED)
├── config.py                  # API configuration
├── config.py.example          # API configuration template
├── demo.py                    # Usage examples
├── test.py                    # Test suite
├── install.sh                 # Installation script
├── setup.py                   # Python package setup
├── requirements.txt           # Python dependencies
├── README.md                  # Complete documentation
├── API_SETUP_GUIDE.md         # API setup instructions
├── SUBDOMAIN_README.md        # Subdomain enumeration guide
└── DOWNLOAD_INSTRUCTIONS.md   # Download instructions
```

## 🧪 Testing

The tool has been tested and verified to work correctly:

```bash
# Basic functionality test
python3 test.py

# Quick scan test
python3 subdomains.py -d httpbin.org --quick --silent

# Help command
python3 subdomains.py --help

# API status check
python3 subdomains.py --show-apis
```

## 🎯 Usage Examples

```bash
# Basic enumeration
python3 subdomains.py -d example.com

# Quick scan
python3 subdomains.py -d example.com --quick

# Aggressive scan
python3 subdomains.py -d example.com --aggressive

# With JSON and CSV output
python3 subdomains.py -d example.com --json --csv

# Silent mode
python3 subdomains.py -d example.com --silent
```

## 🔧 Configuration

1. **Copy config template:**
```bash
cp config.py.example config.py
```

2. **Edit config.py with your API keys:**
```python
API_KEYS = {
    'shodan': 'your_api_key_here',
    'virustotal': 'your_api_key_here',
    # ... other APIs
}
```

## 📞 Support

If you encounter any issues:
1. Check the README.md for detailed documentation
2. Run `python3 test.py` to verify installation
3. Check API configuration with `python3 subdomains.py --show-apis`

## 🎉 Ready to Use!

All major errors have been fixed and the tool is ready for production use. Happy subdomain hunting! 🎯