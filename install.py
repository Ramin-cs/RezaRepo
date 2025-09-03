#!/usr/bin/env python3
"""
Complete Installation Script for Advanced Web Reconnaissance Tool
This script handles complete setup including external tools
"""

import os
import sys
import subprocess
import platform
import urllib.request
import zipfile
import tarfile
import shutil
from pathlib import Path

class CompleteInstaller:
    """Complete installation manager"""
    
    def __init__(self):
        self.os_type = platform.system().lower()
        self.arch = platform.machine().lower()
        
    def print_banner(self):
        """Print installation banner"""
        print("""
🚀 Advanced Web Reconnaissance Tool - Complete Installer
========================================================

This installer will set up:
✅ Python dependencies
✅ System tools (nmap, dig, whois)
✅ Go-based tools (subfinder, httpx, nuclei, amass)
✅ Configuration templates
✅ Cross-platform scripts

""")

    def check_python(self):
        """Check Python installation"""
        if sys.version_info < (3, 7):
            print(f"❌ Python 3.7+ required (found {sys.version_info.major}.{sys.version_info.minor})")
            return False
        
        print(f"✅ Python {sys.version_info.major}.{sys.version_info.minor} detected")
        return True

    def install_python_deps(self):
        """Install Python dependencies"""
        print("\n📦 Installing Python dependencies...")
        
        try:
            subprocess.check_call([
                sys.executable, "-m", "pip", "install", "--upgrade", "pip"
            ])
            subprocess.check_call([
                sys.executable, "-m", "pip", "install", "-r", "requirements.txt"
            ])
            print("✅ Python dependencies installed")
            return True
        except Exception as e:
            print(f"❌ Failed to install Python dependencies: {e}")
            return False

    def install_go(self):
        """Install Go programming language"""
        print("\n🐹 Installing Go...")
        
        # Check if Go is already installed
        try:
            result = subprocess.run(['go', 'version'], capture_output=True, text=True)
            if result.returncode == 0:
                print("✅ Go is already installed")
                return True
        except FileNotFoundError:
            pass
        
        # Download and install Go based on OS
        go_version = "1.21.5"
        
        if self.os_type == "linux":
            if "64" in self.arch:
                go_url = f"https://golang.org/dl/go{go_version}.linux-amd64.tar.gz"
            else:
                go_url = f"https://golang.org/dl/go{go_version}.linux-386.tar.gz"
            
            try:
                print("Downloading Go...")
                urllib.request.urlretrieve(go_url, "go.tar.gz")
                
                print("Installing Go...")
                subprocess.run(['sudo', 'rm', '-rf', '/usr/local/go'], check=False)
                subprocess.run(['sudo', 'tar', '-C', '/usr/local', '-xzf', 'go.tar.gz'], check=True)
                
                # Add to PATH
                with open(os.path.expanduser("~/.bashrc"), "a") as f:
                    f.write("\nexport PATH=$PATH:/usr/local/go/bin\n")
                
                os.environ['PATH'] = os.environ['PATH'] + ":/usr/local/go/bin"
                os.remove("go.tar.gz")
                
                print("✅ Go installed successfully")
                return True
                
            except Exception as e:
                print(f"❌ Failed to install Go: {e}")
                return False
        
        elif self.os_type == "darwin":  # macOS
            try:
                if shutil.which('brew'):
                    subprocess.run(['brew', 'install', 'go'], check=True)
                    print("✅ Go installed via Homebrew")
                    return True
                else:
                    print("❌ Homebrew not found. Please install Go manually from https://golang.org/")
                    return False
            except Exception as e:
                print(f"❌ Failed to install Go: {e}")
                return False
        
        elif self.os_type == "windows":
            print("⚠️  Please install Go manually from https://golang.org/dl/")
            print("   Then restart your command prompt and run this installer again")
            return False
        
        return False

    def install_go_tools(self):
        """Install Go-based reconnaissance tools"""
        print("\n🔧 Installing Go-based tools...")
        
        go_tools = {
            'subfinder': 'github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest',
            'httpx': 'github.com/projectdiscovery/httpx/cmd/httpx@latest',
            'nuclei': 'github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest',
            'assetfinder': 'github.com/tomnomnom/assetfinder@latest',
            'amass': 'github.com/OWASP/Amass/v3/...@master',
            'waybackurls': 'github.com/tomnomnom/waybackurls@latest',
            'gau': 'github.com/lc/gau@latest',
            'anew': 'github.com/tomnomnom/anew@latest'
        }
        
        for tool, package in go_tools.items():
            try:
                print(f"Installing {tool}...")
                subprocess.run([
                    'go', 'install', '-v', package
                ], check=True, timeout=120)
                print(f"✅ {tool} installed")
            except subprocess.CalledProcessError:
                print(f"❌ Failed to install {tool}")
            except subprocess.TimeoutExpired:
                print(f"⏰ Timeout installing {tool}")

    def install_system_tools(self):
        """Install system-level tools"""
        print("\n🛠️  Installing system tools...")
        
        if self.os_type == "linux":
            # Detect Linux distribution
            try:
                with open('/etc/os-release', 'r') as f:
                    os_info = f.read().lower()
                
                if 'ubuntu' in os_info or 'debian' in os_info:
                    self.install_debian_tools()
                elif 'centos' in os_info or 'rhel' in os_info or 'fedora' in os_info:
                    self.install_rhel_tools()
                elif 'arch' in os_info:
                    self.install_arch_tools()
                else:
                    print("⚠️  Unknown Linux distribution - trying apt-get")
                    self.install_debian_tools()
                    
            except Exception:
                self.install_debian_tools()
        
        elif self.os_type == "darwin":
            self.install_macos_tools()
        
        elif self.os_type == "windows":
            self.install_windows_tools()

    def install_debian_tools(self):
        """Install tools on Debian/Ubuntu"""
        tools = ['nmap', 'dnsutils', 'whois', 'curl', 'wget', 'git']
        
        try:
            subprocess.run(['sudo', 'apt-get', 'update'], check=True)
            subprocess.run(['sudo', 'apt-get', 'install', '-y'] + tools, check=True)
            print("✅ System tools installed (apt)")
        except Exception as e:
            print(f"❌ Failed to install system tools: {e}")

    def install_rhel_tools(self):
        """Install tools on RHEL/CentOS/Fedora"""
        tools = ['nmap', 'bind-utils', 'whois', 'curl', 'wget', 'git']
        
        try:
            # Try dnf first (Fedora), then yum (CentOS/RHEL)
            if shutil.which('dnf'):
                subprocess.run(['sudo', 'dnf', 'install', '-y'] + tools, check=True)
                print("✅ System tools installed (dnf)")
            else:
                subprocess.run(['sudo', 'yum', 'install', '-y'] + tools, check=True)
                print("✅ System tools installed (yum)")
        except Exception as e:
            print(f"❌ Failed to install system tools: {e}")

    def install_arch_tools(self):
        """Install tools on Arch Linux"""
        tools = ['nmap', 'dnsutils', 'whois', 'curl', 'wget', 'git']
        
        try:
            subprocess.run(['sudo', 'pacman', '-S', '--noconfirm'] + tools, check=True)
            print("✅ System tools installed (pacman)")
        except Exception as e:
            print(f"❌ Failed to install system tools: {e}")

    def install_macos_tools(self):
        """Install tools on macOS"""
        if not shutil.which('brew'):
            print("❌ Homebrew not found")
            print("Please install Homebrew first: https://brew.sh/")
            return False
        
        tools = ['nmap', 'bind', 'whois', 'curl', 'wget', 'git']
        
        try:
            subprocess.run(['brew', 'install'] + tools, check=True)
            print("✅ System tools installed (brew)")
        except Exception as e:
            print(f"❌ Failed to install system tools: {e}")

    def install_windows_tools(self):
        """Install tools on Windows"""
        print("⚠️  Windows detected")
        print("For best compatibility, please:")
        print("1. Install Windows Subsystem for Linux (WSL)")
        print("2. Install Python 3.7+ from python.org")
        print("3. Install Git for Windows")
        print("4. (Optional) Install nmap from nmap.org")

    def setup_environment(self):
        """Setup environment and configuration"""
        print("\n⚙️  Setting up environment...")
        
        # Create config template
        config_template = """# Advanced Recon Tool Configuration
# Set your API keys here for enhanced functionality

# Shodan API Key (https://account.shodan.io/)
SHODAN_API_KEY=

# VirusTotal API Key (https://www.virustotal.com/gui/my-apikey)
VIRUSTOTAL_API_KEY=

# SecurityTrails API Key (https://securitytrails.com/corp/api)
SECURITYTRAILS_API_KEY=

# Censys API Credentials (https://censys.io/api)
CENSYS_API_ID=
CENSYS_API_SECRET=

# Tool Configuration
MAX_THREADS=50
REQUEST_TIMEOUT=15
VERBOSE=false
"""
        
        with open("config.env", "w") as f:
            f.write(config_template)
        
        print("✅ Configuration file created: config.env")
        
        # Create example usage script
        example_script = """#!/bin/bash
# Example usage script for Advanced Recon Tool

echo "🔍 Advanced Recon Tool - Example Usage"
echo "====================================="

# Load configuration
if [ -f "config.env" ]; then
    export $(grep -v '^#' config.env | xargs)
fi

# Example 1: Basic scan
echo "Example 1: Basic reconnaissance"
python3 advanced_recon_tool.py -t example.com

# Example 2: Verbose scan with custom output
echo "Example 2: Verbose scan with custom settings"
python3 advanced_recon_tool.py -t example.com -o detailed_results --threads 100 --verbose

# Example 3: Using the simple launcher
echo "Example 3: Using simple launcher"
python3 run_recon.py example.com

echo "✅ Examples completed!"
"""
        
        with open("examples.sh", "w") as f:
            f.write(example_script)
        
        os.chmod("examples.sh", 0o755)
        print("✅ Example script created: examples.sh")

    def verify_installation(self):
        """Verify that everything is installed correctly"""
        print("\n🔍 Verifying installation...")
        
        # Check Python modules
        required_modules = [
            'requests', 'bs4', 'dns.resolver', 'whois'
        ]
        
        missing_modules = []
        for module in required_modules:
            try:
                __import__(module)
            except ImportError:
                missing_modules.append(module)
        
        if missing_modules:
            print(f"❌ Missing Python modules: {', '.join(missing_modules)}")
            return False
        
        print("✅ Python modules verified")
        
        # Check external tools
        external_tools = ['nmap', 'dig', 'whois']
        available_tools = []
        
        for tool in external_tools:
            if shutil.which(tool):
                available_tools.append(tool)
        
        print(f"✅ Available system tools: {', '.join(available_tools)}")
        
        # Check Go tools
        go_tools = ['subfinder', 'httpx', 'nuclei', 'assetfinder']
        available_go_tools = []
        
        for tool in go_tools:
            if shutil.which(tool):
                available_go_tools.append(tool)
        
        if available_go_tools:
            print(f"✅ Available Go tools: {', '.join(available_go_tools)}")
        else:
            print("⚠️  No Go tools found - limited functionality")
        
        return True

    def create_desktop_shortcut(self):
        """Create desktop shortcut (Linux/Windows)"""
        if self.os_type == "linux":
            desktop_entry = f"""[Desktop Entry]
Version=1.0
Type=Application
Name=Advanced Recon Tool
Comment=Comprehensive Web Reconnaissance Tool
Exec=python3 {os.path.abspath('run_recon.py')} %U
Icon=applications-internet
Terminal=true
Categories=Network;Security;
"""
            
            desktop_path = os.path.expanduser("~/Desktop/AdvancedReconTool.desktop")
            try:
                with open(desktop_path, "w") as f:
                    f.write(desktop_entry)
                os.chmod(desktop_path, 0o755)
                print(f"✅ Desktop shortcut created: {desktop_path}")
            except Exception as e:
                print(f"⚠️  Could not create desktop shortcut: {e}")

    def install(self):
        """Run complete installation"""
        self.print_banner()
        
        # Check Python
        if not self.check_python():
            return False
        
        # Install Python dependencies
        if not self.install_python_deps():
            return False
        
        # Install Go
        self.install_go()
        
        # Install Go tools
        self.install_go_tools()
        
        # Install system tools
        self.install_system_tools()
        
        # Setup environment
        self.setup_environment()
        
        # Create desktop shortcut
        self.create_desktop_shortcut()
        
        # Verify installation
        if self.verify_installation():
            print("\n🎉 Installation completed successfully!")
            print("\n📋 Next steps:")
            print("1. Edit config.env to add your API keys (optional)")
            print("2. Run a test: python test_tool.py")
            print("3. Start reconnaissance: python run_recon.py example.com")
            print("\n📚 Documentation: README.md")
            return True
        else:
            print("\n❌ Installation verification failed")
            return False

def main():
    """Main installation function"""
    installer = CompleteInstaller()
    
    try:
        success = installer.install()
        if not success:
            print("\n💡 Manual installation steps:")
            print("1. pip install -r requirements.txt")
            print("2. Install Go from https://golang.org/")
            print("3. go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest")
            print("4. Install nmap, dig, whois using your package manager")
            sys.exit(1)
    except KeyboardInterrupt:
        print("\n⚠️  Installation interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Installation failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()