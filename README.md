# 🕵️ Router Vulnerability Scanner v11.0

## Professional Penetration Testing and SIP Extraction Tool

**Perfect for POC security demonstrations - extracts SIP passwords from live routers without authentication!**

## 🎯 Exactly What You Need for POC

This tool demonstrates **router security vulnerabilities** by:
- ✅ **Accessing router without authentication**
- ✅ **Extracting SIP/VoIP passwords** from live devices
- ✅ **Testing known vulnerabilities** automatically
- ✅ **Generating professional reports** for POC presentations

## 🚀 Simple Usage for POC

```bash
# Test router security and extract SIP passwords
python3 router_vulnerability_scanner.py 192.168.1.1 -v

# Generate professional POC report
python3 router_vulnerability_scanner.py 192.168.1.1 --report poc_security_demo.txt

# Test Type 7 decryption (for demo)
python3 router_vulnerability_scanner.py --password "094F471A1A0A"
```

## 🔍 How It Works (Penetration Testing)

### **Step 1: Router Discovery**
- Tests connectivity to target IP
- Identifies router brand and model
- Fingerprints web interface

### **Step 2: Vulnerability Assessment**
- Tests known CVE vulnerabilities
- Checks for unauthenticated endpoints
- Identifies configuration exposure

### **Step 3: Unauthorized Access**
- Attempts unauthenticated config access
- Tests default credentials
- Bypasses authentication where possible

### **Step 4: SIP Extraction**
- Extracts SIP/VoIP configurations
- Recovers SIP usernames and passwords
- Decrypts Type 7 passwords
- Maps VoIP server settings

## 📊 Perfect POC Demonstration

### **Scenario 1: Vulnerable Router Found**
```
🎉 PENETRATION TEST SUCCESSFUL!
🔓 Unauthorized access achieved
📞 SIP accounts extracted: 3
   • Username: 1001, Password: sippass123
   • Username: 1002, Password: voipuser456
   • SIP Server: sip.provider.com:5060

🎯 Perfect for POC security demonstration!
```

### **Scenario 2: Secure Router**
```
✅ ROUTER APPEARS SECURE
🛡️ No unauthorized access achieved
📋 Shows importance of proper security

🎯 Still valuable POC - shows security assessment capabilities
```

## 🛡️ Vulnerability Testing Methods

### **Unauthenticated Access Tests:**
- `/cgi-bin/config.exp` - Direct config export
- `/config.xml` - XML configuration access
- `/backup.conf` - Backup file access  
- `/running-config` - Live configuration dump
- `/voice.xml` - VoIP configuration exposure

### **Default Credential Testing:**
- `admin/admin`, `admin/password`, `admin/[blank]`
- `root/root`, `cisco/cisco`, `user/user`
- Brand-specific defaults
- Weak password patterns

### **SIP Extraction Endpoints:**
- `/voip.xml` - VoIP configuration
- `/cgi-bin/voip_config` - SIP settings
- `/admin/voice.html` - Voice configuration
- `/api/voip/config` - API-based extraction

## 🎯 POC Usage Instructions

### **For Your Security Demonstration:**

#### **Step 1: Identify Target Router**
```bash
# Find router IP (common addresses)
python3 router_vulnerability_scanner.py 192.168.1.1 -v
python3 router_vulnerability_scanner.py 192.168.0.1 -v
python3 router_vulnerability_scanner.py 10.0.0.1 -v
```

#### **Step 2: Generate POC Report**
```bash
# Professional security assessment
python3 router_vulnerability_scanner.py [ROUTER_IP] --report security_poc.txt -v
```

#### **Step 3: Present Results**
- Show unauthorized access to router
- Display extracted SIP passwords
- Demonstrate security vulnerabilities
- Present professional recommendations

## 🏆 POC Value Guarantee

**This tool guarantees POC value by:**

✅ **Testing real vulnerabilities** - Known CVE exploits  
✅ **Extracting actual SIP passwords** - Real VoIP credentials  
✅ **Professional reporting** - Client-ready documentation  
✅ **Security assessment** - Comprehensive vulnerability analysis  
✅ **Live demonstration** - Real-time penetration testing  

### **POC Scenarios:**

#### **High Value POC:**
- Router has vulnerabilities
- SIP passwords extracted
- Perfect security demonstration

#### **Medium Value POC:**
- Router access achieved
- Configuration vulnerabilities shown
- Good security assessment

#### **Educational POC:**
- Router properly secured
- Shows security testing capabilities
- Demonstrates professional tools

## ⚠️ Legal and Ethical Use

### **IMPORTANT:**
- ✅ **Use only on your own equipment**
- ✅ **Get explicit permission** before testing client routers
- ✅ **Follow responsible disclosure** for vulnerabilities found
- ✅ **Respect privacy and confidentiality**

### **Professional Guidelines:**
- Document all testing activities
- Provide security recommendations
- Help improve router security
- Use for legitimate security assessment only

## 🔒 Installation

### **Zero Dependencies Required**
```bash
# Download and run immediately
chmod +x router_vulnerability_scanner.py
./router_vulnerability_scanner.py 192.168.1.1 -v
```

### **Enhanced Features (Optional)**
```bash
pip install requests
```

## 🎉 Perfect POC Solution

**This tool provides the perfect POC solution because:**

🔥 **Tests real security vulnerabilities** in routers  
🔥 **Extracts actual SIP passwords** when vulnerabilities exist  
🔥 **Generates professional reports** for client presentations  
🔥 **Shows practical security risks** and their impact  
🔥 **Demonstrates value of security testing** services  

**Use this for your POC demonstration to show real router vulnerabilities and SIP password extraction capabilities!** 🚀

---

*Router Vulnerability Scanner v11.0 - Professional Security Assessment Tool*

**For authorized penetration testing and security demonstrations only.**