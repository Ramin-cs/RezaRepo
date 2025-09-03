# Universal Router Configuration Decryptor 🔧

A comprehensive tool designed for network administrators to decrypt and analyze encrypted router configuration files from various manufacturers.

## Features 🚀

### Supported Router Brands
- **Cisco** (IOS, Type 7 passwords, encrypted configs)
- **MikroTik** (RouterOS backup files)
- **TP-Link** (Archer series, configuration exports)
- **D-Link** (DIR series, wireless routers)
- **NetComm** (NF/NL series, wireless routers)
- **Juniper** (JunOS configurations)
- **Huawei** (VRP configurations)
- **ASUS** (RT series routers)
- **Linksys** (WRT series)
- **Netgear** (R series routers)
- **Ubiquiti** (EdgeOS, UniFi)
- **FortiNet** (FortiGate)
- **pfSense** (FreeBSD-based)
- **OpenWrt** (Linux-based)

### Decryption Methods
- **Cisco Type 7 Password Decryption** ✅
- **Base64 Decoding** ✅
- **AES Encryption** (with brute force) ✅
- **DES/3DES Encryption** (with brute force) ✅
- **Binary Analysis** ✅
- **Automatic Format Detection** ✅

### Information Extraction
- 🔑 **Passwords and Credentials**
- 🌐 **Network Interfaces**
- 🔢 **IP Addresses and Networks**
- 👤 **User Accounts**
- 📶 **Wireless Settings (SSID, Security)**
- 🛡️ **Security Configurations**
- 🚪 **Port Forwarding Rules**
- 🛣️ **Routing Information**
- 🏷️ **VLANs and Access Lists**

## Installation 📦

### Quick Install
```bash
# Install dependencies
pip install cryptography pycryptodome

# Make executable
chmod +x universal_router_decryptor.py
```

### Full Installation
```bash
# Clone or download the tool
# Install all dependencies
pip install -r requirements.txt

# Set permissions
chmod +x universal_router_decryptor.py
```

## Usage 📋

### Command Line Interface

#### Basic Usage
```bash
# Analyze any router config file
python3 universal_router_decryptor.py config.txt

# Specify output file
python3 universal_router_decryptor.py config.backup -o decrypted.txt

# Verbose output with raw content
python3 universal_router_decryptor.py config.cfg -v
```

#### Decrypt Single Password
```bash
# Cisco Type 7 password
python3 universal_router_decryptor.py -p "094F471A1A0A"
# Output: cisco
```

#### Advanced Analysis
```bash
# Deep analysis with brute force
python3 universal_router_decryptor.py encrypted.bin --deep-analysis

# Specify router brand
python3 universal_router_decryptor.py config.txt -b cisco
```

#### Graphical Interface
```bash
# Launch GUI (if tkinter available)
python3 universal_router_decryptor.py --gui
```

#### Create Test Files
```bash
# Generate sample configuration files
python3 universal_router_decryptor.py --create-samples
```

### GUI Interface

The graphical interface provides:
- **File Browser** for easy file selection
- **Brand Selection** for optimized parsing
- **Multiple Tabs** for organized results
- **Save Functionality** for exporting results
- **Deep Analysis** with brute force options

## Supported File Types 📂

| File Type | Extension | Description | Support Level |
|-----------|-----------|-------------|---------------|
| Cisco IOS | `.cfg`, `.txt` | Plain text configs | ✅ Full |
| MikroTik Backup | `.backup` | Binary backup files | ⚠️ Limited |
| MikroTik Export | `.rsc` | Text export files | ✅ Full |
| Base64 Encoded | `.txt`, `.cfg` | Base64 encoded configs | ✅ Full |
| Encrypted Binary | `.bin`, `.enc` | AES/DES encrypted | 🔄 Brute Force |
| XML Configs | `.xml` | XML-based configs | ✅ Partial |

## Example Output 📄

```
================================================================================
ROUTER CONFIGURATION ANALYSIS RESULTS
================================================================================
File Path: router_config.txt
File Type: cisco_text
Router Brand: CISCO
File Size: 2048 bytes
Status: SUCCESS

🏷️  HOSTNAME: MainRouter

🔑 PASSWORDS FOUND (3):
  1. Encrypted: 094F471A1A0A
     Decrypted: admin123
     Line: username admin password 7 094F471A1A0A

🌐 NETWORK INTERFACES (4):
  • interface GigabitEthernet0/0
  • interface GigabitEthernet0/1
  • interface Vlan10
  • interface Loopback0

🔢 IP ADDRESSES (5):
  • 192.168.1.1
  • 10.0.0.1
  • 172.16.1.1
  • 8.8.8.8
  • 1.1.1.1

📶 WIRELESS SETTINGS (2):
  • ssid MyNetwork
  • wpa-psk MySecretKey
```

## Security Notes ⚠️

### Important Warnings
1. **Backup First**: Always backup original configuration files
2. **Legal Use Only**: Use only on equipment you own or have permission to access
3. **Secure Environment**: Run the tool only on trusted systems
4. **Clean Up**: Delete decrypted files after use
5. **Access Control**: Restrict tool access to authorized personnel

### Ethical Guidelines
- This tool is designed for legitimate network administration
- Do not use for unauthorized access to network equipment
- Respect privacy and security policies
- Follow your organization's security procedures

## Troubleshooting 🔧

### Common Issues

#### "Module not found" Error
```bash
pip install cryptography pycryptodome
# or
pip install -r requirements.txt
```

#### "File cannot be read"
- Check if file exists and is readable
- Verify file is actually encrypted
- Try different router brand detection

#### "Decryption failed"
- File may use unsupported encryption
- Try deep analysis mode: `--deep-analysis`
- Check if file is corrupted

#### "GUI not available"
```bash
# Install tkinter (Ubuntu/Debian)
sudo apt-get install python3-tk

# Or use command line interface
python3 universal_router_decryptor.py config.txt
```

### Performance Tips
- Use brand specification (`-b cisco`) for faster processing
- For large files, redirect output: `> results.txt`
- Use deep analysis only when standard methods fail

## Development 🛠️

### Adding New Router Support

To add support for a new router brand:

1. **Add brand signature** in `router_signatures`
2. **Create brand-specific parser** in `parse_generic_config`
3. **Add encryption method** if needed
4. **Test with sample files**

Example:
```python
# Add to router_signatures
'newbrand': [b'NewBrand', b'Model-', b'signature'],

# Add parsing logic
if brand == 'newbrand':
    # Custom parsing logic here
    pass
```

### File Structure
```
universal_router_decryptor.py  # Main unified tool
├── UniversalRouterDecryptor   # Core decryption class
├── RouterDecryptorGUI         # GUI interface class
├── Sample file generators     # Test file creation
└── CLI interface              # Command line handling
```

## Version History 📝

- **v2.0**: Unified tool with all features
- **v1.5**: Added GUI interface
- **v1.0**: Basic Cisco Type 7 support

## License ⚖️

This tool is provided for legitimate network administration purposes only.
Users are responsible for ensuring legal and ethical use.

---

**Made for Network Administrators with ❤️**

For questions or issues, please check the troubleshooting section or review the source code comments.