#!/usr/bin/env python3
"""
Fix Windows External Tools Integration
"""

import os
import sys
import subprocess
import platform
from pathlib import Path

def get_windows_tool_paths():
    """Get common Windows tool paths"""
    paths = []
    
    # Common Windows paths
    common_paths = [
        os.path.expanduser("~/go/bin"),
        os.path.expanduser("~/AppData/Local/go/bin"),
        "C:/Program Files/Go/bin",
        "C:/Program Files (x86)/Go/bin",
        os.path.expanduser("~/AppData/Roaming/go/bin"),
        "C:/tools/go/bin",
        os.path.expanduser("~/bin"),
        os.path.expanduser("~/tools/bin"),
        "C:/tools/bin",
        "C:/bin"
    ]
    
    # Check if paths exist
    for path in common_paths:
        if os.path.exists(path):
            paths.append(path)
    
    return paths

def update_path_for_windows():
    """Update PATH for Windows"""
    print("🔧 Updating PATH for Windows...")
    
    current_path = os.environ.get('PATH', '')
    new_paths = get_windows_tool_paths()
    
    for path in new_paths:
        if path not in current_path:
            current_path = f"{current_path};{path}" if current_path else path
    
    os.environ['PATH'] = current_path
    print(f"✅ Updated PATH: {os.environ['PATH']}")
    
    return new_paths

def test_tools():
    """Test available tools"""
    tools_to_test = ['subfinder', 'httpx', 'assetfinder', 'gobuster', 'katana']
    
    print("🧪 Testing tools...")
    for tool in tools_to_test:
        try:
            result = subprocess.run([tool, '--help'], capture_output=True, timeout=10)
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

def install_go_tools():
    """Install Go tools on Windows"""
    print("📦 Installing Go tools...")
    
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
            result = subprocess.run(['go', 'install', tool], capture_output=True, timeout=120)
            if result.returncode == 0:
                print(f"✅ {tool} installed successfully")
            else:
                print(f"❌ {tool} installation failed: {result.stderr.decode()}")
        except Exception as e:
            print(f"❌ {tool} installation error: {e}")

def main():
    print("🚀 ARAT Windows Tools Fix")
    print("=" * 50)
    
    if platform.system() != 'Windows':
        print("⚠️ This script is designed for Windows")
        return
    
    # Update PATH
    paths = update_path_for_windows()
    print(f"📁 Found {len(paths)} tool paths")
    
    # Test tools
    test_tools()
    
    # Ask user if they want to install missing tools
    response = input("\nDo you want to install missing Go tools? (y/n): ")
    if response.lower() == 'y':
        install_go_tools()
        print("\n🧪 Testing tools after installation...")
        test_tools()
    
    print("\n✅ Windows tools fix completed!")

if __name__ == "__main__":
    main()