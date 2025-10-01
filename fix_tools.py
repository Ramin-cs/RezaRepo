#!/usr/bin/env python3
"""
Fix External Tools Integration
"""

import os
import sys
import subprocess
from pathlib import Path

def fix_phase2_tools():
    """Fix Phase 2 tool integration"""
    print("🔧 Fixing Phase 2 tool integration...")
    
    # Check if Go tools are in PATH
    go_bin_paths = [
        os.path.expanduser("~/go/bin"),
        "/usr/local/go/bin",
        "/opt/homebrew/bin",
        "/usr/bin",
        "/usr/local/bin"
    ]
    
    # Add Go tools to PATH
    current_path = os.environ.get('PATH', '')
    for path in go_bin_paths:
        if os.path.exists(path) and path not in current_path:
            current_path = f"{current_path}{os.pathsep}{path}"
    
    os.environ['PATH'] = current_path
    print(f"✅ Updated PATH: {os.environ['PATH']}")
    
    # Test tools
    tools_to_test = ['subfinder', 'httpx', 'assetfinder', 'gobuster']
    
    for tool in tools_to_test:
        try:
            result = subprocess.run([tool, '--help'], capture_output=True, timeout=5)
            if result.returncode == 0:
                print(f"✅ {tool} is available")
            else:
                print(f"⚠️ {tool} not working properly")
        except FileNotFoundError:
            print(f"❌ {tool} not found")
        except subprocess.TimeoutExpired:
            print(f"⚠️ {tool} timeout")
        except Exception as e:
            print(f"❌ {tool} error: {e}")

def fix_phase5_tools():
    """Fix Phase 5 tool integration"""
    print("🔧 Fixing Phase 5 tool integration...")
    
    tools_to_test = ['gobuster', 'dirsearch', 'feroxbuster', 'katana', 'gospider']
    
    for tool in tools_to_test:
        try:
            result = subprocess.run([tool, '--help'], capture_output=True, timeout=5)
            if result.returncode == 0:
                print(f"✅ {tool} is available")
            else:
                print(f"⚠️ {tool} not working properly")
        except FileNotFoundError:
            print(f"❌ {tool} not found")
        except subprocess.TimeoutExpired:
            print(f"⚠️ {tool} timeout")
        except Exception as e:
            print(f"❌ {tool} error: {e}")

def install_missing_tools():
    """Install missing tools"""
    print("🔧 Installing missing tools...")
    
    # Install Go tools
    go_tools = [
        "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
        "github.com/projectdiscovery/httpx/cmd/httpx@latest",
        "github.com/tomnomnom/assetfinder@latest",
        "github.com/OJ/gobuster/v3@latest",
        "github.com/projectdiscovery/katana/cmd/katana@latest"
    ]
    
    for tool in go_tools:
        try:
            print(f"📦 Installing {tool}...")
            result = subprocess.run(['go', 'install', tool], capture_output=True, timeout=60)
            if result.returncode == 0:
                print(f"✅ {tool} installed successfully")
            else:
                print(f"❌ {tool} installation failed: {result.stderr.decode()}")
        except Exception as e:
            print(f"❌ {tool} installation error: {e}")

def main():
    print("🚀 ARAT Tools Fix Script")
    print("=" * 50)
    
    # Fix Phase 2 tools
    fix_phase2_tools()
    print()
    
    # Fix Phase 5 tools
    fix_phase5_tools()
    print()
    
    # Ask user if they want to install missing tools
    response = input("Do you want to install missing Go tools? (y/n): ")
    if response.lower() == 'y':
        install_missing_tools()
    
    print("✅ Tools fix completed!")

if __name__ == "__main__":
    main()