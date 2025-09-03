#!/usr/bin/env python3
"""
Advanced Web Reconnaissance Tool - Cross-Platform Launcher
This script handles environment setup and launches the reconnaissance tool
"""

import os
import sys
import subprocess
import platform
from pathlib import Path

def load_config():
    """Load configuration from config.env file"""
    config_file = Path("config.env")
    if config_file.exists():
        with open(config_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    key, value = line.split('=', 1)
                    os.environ[key.strip()] = value.strip()

def check_dependencies():
    """Check if all dependencies are installed"""
    try:
        import requests
        import beautifulsoup4
        import dns.resolver
        import whois
        return True
    except ImportError as e:
        print(f"❌ Missing dependency: {e}")
        print("Run 'python setup.py' to install dependencies")
        return False

def main():
    """Main launcher function"""
    print("🔍 Advanced Web Reconnaissance Tool")
    print("=" * 40)
    
    # Load configuration
    load_config()
    
    # Check dependencies
    if not check_dependencies():
        print("\n🛠️  Installing dependencies...")
        try:
            subprocess.check_call([sys.executable, "setup.py"])
        except subprocess.CalledProcessError:
            print("❌ Failed to install dependencies automatically")
            print("Please run 'python setup.py' manually")
            sys.exit(1)
    
    # Check if target is provided
    if len(sys.argv) < 2:
        print("\n📋 Usage Examples:")
        print("  python run_recon.py example.com")
        print("  python run_recon.py https://example.com")
        print("  python run_recon.py example.com --output my_results")
        print("\n🔧 Advanced Usage:")
        print("  python advanced_recon_tool.py -t example.com --threads 100 --verbose")
        sys.exit(1)
    
    # Prepare arguments for the main tool
    args = sys.argv[1:]
    
    # If first argument doesn't start with '-', assume it's the target
    if not args[0].startswith('-'):
        target = args[0]
        remaining_args = args[1:]
        final_args = ['-t', target] + remaining_args
    else:
        final_args = args
    
    # Launch the main reconnaissance tool
    try:
        cmd = [sys.executable, 'advanced_recon_tool.py'] + final_args
        subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError as e:
        print(f"❌ Tool execution failed: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n⚠️  Scan interrupted by user")
    except FileNotFoundError:
        print("❌ advanced_recon_tool.py not found in current directory")
        sys.exit(1)

if __name__ == "__main__":
    main()