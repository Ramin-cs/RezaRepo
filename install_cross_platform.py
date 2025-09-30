#!/usr/bin/env python3
"""
Cross-Platform Installer for ARAT External Tools
Automatically installs required tools based on the operating system
"""

import os
import sys
import platform
import subprocess
import urllib.request
import zipfile
import shutil
from pathlib import Path

class CrossPlatformInstaller:
    """Cross-platform installer for external tools"""
    
    def __init__(self):
        self.system = platform.system().lower()
        self.architecture = platform.machine().lower()
        self.install_dir = self._get_install_directory()
        
    def _get_install_directory(self) -> str:
        """Get platform-specific installation directory"""
        if self.system == 'windows':
            return os.path.join(os.environ.get('USERPROFILE', ''), 'ARAT_Tools')
        else:
            return os.path.expanduser('~/ARAT_Tools')
    
    def _run_command(self, command: str, shell: bool = True) -> tuple:
        """Run command with platform-specific handling"""
        try:
            if self.system == 'windows':
                result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=300)
            else:
                result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=300)
            
            return result.returncode == 0, result.stdout, result.stderr
        except Exception as e:
            return False, "", str(e)
    
    def install_go_tools(self):
        """Install Go-based tools"""
        print("🔧 Installing Go-based tools...")
        
        # Check if Go is installed
        success, _, _ = self._run_command('go version')
        if not success:
            print("❌ Go is not installed. Please install Go first.")
            return False
        
        tools = [
            ('github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest', 'subfinder'),
            ('github.com/projectdiscovery/httpx/cmd/httpx@latest', 'httpx'),
            ('github.com/OJ/gobuster/v3@latest', 'gobuster'),
            ('github.com/projectdiscovery/katana/cmd/katana@latest', 'katana'),
            ('github.com/projectdiscovery/gospider/cmd/gospider@latest', 'gospider'),
        ]
        
        for tool_repo, tool_name in tools:
            print(f"  📦 Installing {tool_name}...")
            success, stdout, stderr = self._run_command(f'go install {tool_repo}')
            if success:
                print(f"  ✅ {tool_name} installed successfully")
            else:
                print(f"  ❌ Failed to install {tool_name}: {stderr}")
        
        return True
    
    def install_python_tools(self):
        """Install Python-based tools"""
        print("🐍 Installing Python-based tools...")
        
        tools = [
            'sublist3r',
            'python-whois',
        ]
        
        for tool in tools:
            print(f"  📦 Installing {tool}...")
            success, stdout, stderr = self._run_command(f'pip install {tool}')
            if success:
                print(f"  ✅ {tool} installed successfully")
            else:
                print(f"  ❌ Failed to install {tool}: {stderr}")
        
        return True
    
    def install_system_tools(self):
        """Install system-specific tools"""
        print("🖥️ Installing system tools...")
        
        if self.system == 'windows':
            print("  ℹ️ For Windows, please manually install:")
            print("    - Git for Windows")
            print("    - Go for Windows")
            print("    - Python 3.8+")
            
        elif self.system == 'darwin':  # macOS
            # Check if Homebrew is installed
            success, _, _ = self._run_command('brew --version')
            if success:
                print("  📦 Installing tools via Homebrew...")
                tools = ['git', 'go']
                for tool in tools:
                    success, _, _ = self._run_command(f'brew install {tool}')
                    if success:
                        print(f"  ✅ {tool} installed successfully")
                    else:
                        print(f"  ⚠️ {tool} may already be installed")
            else:
                print("  ℹ️ Please install Homebrew first: /bin/bash -c \"$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\"")
                
        else:  # Linux
            print("  📦 Installing tools via package manager...")
            
            # Try apt (Ubuntu/Debian)
            success, _, _ = self._run_command('apt --version')
            if success:
                tools = ['git', 'golang-go', 'python3-pip']
                for tool in tools:
                    success, _, _ = self._run_command(f'sudo apt update && sudo apt install -y {tool}')
                    if success:
                        print(f"  ✅ {tool} installed successfully")
                    else:
                        print(f"  ⚠️ {tool} may already be installed")
            
            # Try yum (CentOS/RHEL)
            elif self._run_command('yum --version')[0]:
                tools = ['git', 'golang', 'python3-pip']
                for tool in tools:
                    success, _, _ = self._run_command(f'sudo yum install -y {tool}')
                    if success:
                        print(f"  ✅ {tool} installed successfully")
                    else:
                        print(f"  ⚠️ {tool} may already be installed")
        
        return True
    
    def setup_environment(self):
        """Setup environment variables"""
        print("🔧 Setting up environment...")
        
        if self.system == 'windows':
            print("  ℹ️ For Windows, please add to PATH:")
            print(f"    - %USERPROFILE%\\go\\bin")
            print(f"    - %USERPROFILE%\\.local\\bin")
            
        else:
            # Add to shell profile
            profile_files = [
                os.path.expanduser('~/.bashrc'),
                os.path.expanduser('~/.zshrc'),
                os.path.expanduser('~/.profile')
            ]
            
            path_addition = '''
# ARAT Tools PATH
export PATH="$PATH:$HOME/go/bin:$HOME/.local/bin"
'''
            
            for profile_file in profile_files:
                if os.path.exists(profile_file):
                    print(f"  📝 Adding PATH to {profile_file}")
                    with open(profile_file, 'a') as f:
                        f.write(path_addition)
                    break
    
    def verify_installation(self):
        """Verify that all tools are installed correctly"""
        print("🔍 Verifying installation...")
        
        tools = [
            'git',
            'go',
            'python3',
            'pip',
            'sublist3r',
            'subfinder',
            'httpx',
            'gobuster'
        ]
        
        all_installed = True
        for tool in tools:
            success, _, _ = self._run_command(f'which {tool}' if self.system != 'windows' else f'where {tool}')
            if success:
                print(f"  ✅ {tool} is available")
            else:
                print(f"  ❌ {tool} is not available")
                all_installed = False
        
        return all_installed
    
    def install_all(self):
        """Install all tools"""
        print(f"🚀 Installing ARAT external tools for {self.system} ({self.architecture})")
        print(f"📁 Installation directory: {self.install_dir}")
        
        # Create installation directory
        os.makedirs(self.install_dir, exist_ok=True)
        
        # Install tools
        success = True
        success &= self.install_system_tools()
        success &= self.install_python_tools()
        success &= self.install_go_tools()
        
        # Setup environment
        self.setup_environment()
        
        # Verify installation
        if self.verify_installation():
            print("\n🎉 All tools installed successfully!")
            print("🔄 Please restart your terminal/shell for PATH changes to take effect.")
        else:
            print("\n⚠️ Some tools may not be installed correctly.")
            print("Please check the installation manually.")
        
        return success

def main():
    """Main installation function"""
    installer = CrossPlatformInstaller()
    installer.install_all()

if __name__ == "__main__":
    main()