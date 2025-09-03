#!/usr/bin/env python3
"""
Setup script for Advanced Web Reconnaissance Tool
Handles installation and dependency management across platforms
"""

import os
import sys
import subprocess
import platform

def install_requirements():
    """Install Python requirements"""
    print("Installing Python dependencies...")
    
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
        print("✅ Python dependencies installed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to install Python dependencies: {e}")
        return False

def install_system_dependencies():
    """Install system-level dependencies based on OS"""
    os_type = platform.system().lower()
    
    print(f"Detected OS: {platform.system()}")
    
    if os_type == "linux":
        # Try different package managers
        package_managers = [
            ("apt-get", ["sudo", "apt-get", "update", "&&", "sudo", "apt-get", "install", "-y", "dnsutils", "whois", "nmap"]),
            ("yum", ["sudo", "yum", "install", "-y", "bind-utils", "whois", "nmap"]),
            ("dnf", ["sudo", "dnf", "install", "-y", "bind-utils", "whois", "nmap"]),
            ("pacman", ["sudo", "pacman", "-S", "--noconfirm", "dnsutils", "whois", "nmap"])
        ]
        
        for pm, cmd in package_managers:
            if subprocess.run(["which", pm], capture_output=True).returncode == 0:
                try:
                    subprocess.run(cmd, check=True, shell=True)
                    print(f"✅ System dependencies installed using {pm}")
                    return True
                except subprocess.CalledProcessError:
                    continue
    
    elif os_type == "darwin":  # macOS
        # Check if Homebrew is installed
        if subprocess.run(["which", "brew"], capture_output=True).returncode == 0:
            try:
                subprocess.check_call(["brew", "install", "bind", "whois", "nmap"])
                print("✅ System dependencies installed using Homebrew")
                return True
            except subprocess.CalledProcessError as e:
                print(f"❌ Failed to install with Homebrew: {e}")
    
    elif os_type == "windows":
        print("ℹ️  Windows detected. Please ensure you have:")
        print("   - Python 3.7+ installed")
        print("   - Windows Subsystem for Linux (WSL) for best compatibility")
        print("   - Or use PowerShell with administrative privileges")
    
    print("⚠️  Some system tools may not be available. Tool will work with reduced functionality.")
    return False

def create_config_template():
    """Create configuration template for API keys"""
    config_content = """# Advanced Recon Tool Configuration
# Copy this file to config.env and add your API keys

# Shodan API Key (for advanced IP discovery)
# Get from: https://account.shodan.io/
SHODAN_API_KEY=your_shodan_api_key_here

# VirusTotal API Key (for subdomain discovery)
# Get from: https://www.virustotal.com/gui/my-apikey
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here

# SecurityTrails API Key (for DNS history)
# Get from: https://securitytrails.com/corp/api
SECURITYTRAILS_API_KEY=your_securitytrails_api_key_here

# Censys API Credentials (for certificate analysis)
# Get from: https://censys.io/api
CENSYS_API_ID=your_censys_api_id_here
CENSYS_API_SECRET=your_censys_api_secret_here

# Note: All API keys are optional. The tool will work without them but with reduced functionality.
"""
    
    with open("config.env.template", "w") as f:
        f.write(config_content)
    
    print("✅ Configuration template created: config.env.template")

def check_python_version():
    """Check Python version compatibility"""
    if sys.version_info < (3, 7):
        print("❌ Python 3.7 or higher is required")
        print(f"   Current version: {sys.version}")
        return False
    
    print(f"✅ Python version OK: {sys.version}")
    return True

def main():
    """Main setup function"""
    print("🚀 Advanced Web Reconnaissance Tool Setup")
    print("=" * 50)
    
    # Check Python version
    if not check_python_version():
        sys.exit(1)
    
    # Install Python requirements
    if not install_requirements():
        print("⚠️  Warning: Some Python dependencies failed to install")
        print("   Tool may work with reduced functionality")
    
    # Install system dependencies
    install_system_dependencies()
    
    # Create configuration template
    create_config_template()
    
    print("\n🎉 Setup completed!")
    print("\nNext steps:")
    print("1. (Optional) Copy config.env.template to config.env and add your API keys")
    print("2. Run the tool: python advanced_recon_tool.py -t example.com")
    print("3. Check the generated reports in the output directory")
    
    print("\nExample usage:")
    print("  python advanced_recon_tool.py -t example.com")
    print("  python advanced_recon_tool.py -t https://example.com -o custom_output")
    print("  python advanced_recon_tool.py -t example.com --threads 100 --verbose")

if __name__ == "__main__":
    main()