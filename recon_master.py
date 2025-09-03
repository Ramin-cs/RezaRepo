#!/usr/bin/env python3
"""
Advanced Web Reconnaissance Tool - Master Launcher
Single file to rule them all - handles everything automatically
"""

import os
import sys
import subprocess
import platform
from pathlib import Path

def check_and_install():
    """Check dependencies and install if needed"""
    
    print("🔍 Advanced Web Reconnaissance Tool - Master Launcher")
    print("=" * 55)
    
    # Check Python version
    if sys.version_info < (3, 7):
        print(f"❌ Python 3.7+ required (found {sys.version_info.major}.{sys.version_info.minor})")
        return False
    
    # Check if main tool exists
    if not Path("advanced_recon_tool.py").exists():
        print("❌ Main tool file not found")
        return False
    
    # Try to import required modules
    missing_modules = []
    required_modules = {
        'requests': 'requests',
        'bs4': 'beautifulsoup4',
        'dns.resolver': 'dnspython',
        'whois': 'python-whois'
    }
    
    for module, package in required_modules.items():
        try:
            __import__(module)
        except ImportError:
            missing_modules.append(package)
    
    # Install missing modules
    if missing_modules:
        print(f"📦 Installing missing modules: {', '.join(missing_modules)}")
        try:
            subprocess.check_call([
                sys.executable, "-m", "pip", "install"
            ] + missing_modules)
            print("✅ Dependencies installed")
        except subprocess.CalledProcessError:
            print("❌ Failed to install dependencies")
            print("Please run: pip install -r requirements.txt")
            return False
    
    return True

def load_config():
    """Load configuration from config.env"""
    config_file = Path("config.env")
    if config_file.exists():
        with open(config_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    key, value = line.split('=', 1)
                    if value.strip():  # Only set non-empty values
                        os.environ[key.strip()] = value.strip()

def show_usage():
    """Show usage information"""
    print("\n📋 Usage Examples:")
    print("  python recon_master.py example.com")
    print("  python recon_master.py https://example.com")
    print("  python recon_master.py example.com --output my_results")
    print("  python recon_master.py example.com --threads 100 --verbose")
    
    print("\n🔧 Available Options:")
    print("  --output DIR     Output directory")
    print("  --threads N      Number of threads (default: 50)")
    print("  --timeout N      Request timeout (default: 15)")
    print("  --verbose        Enable verbose output")
    
    print("\n⚙️  Setup Commands:")
    print("  python recon_master.py --setup      # Interactive setup")
    print("  python recon_master.py --install    # Install external tools")
    print("  python recon_master.py --test       # Test installation")

def interactive_setup():
    """Interactive setup wizard"""
    print("\n🛠️  Interactive Setup Wizard")
    print("=" * 30)
    
    # Run setup
    try:
        subprocess.run([sys.executable, "setup.py"], check=True)
    except subprocess.CalledProcessError:
        print("❌ Setup failed")
        return False
    
    # API setup
    response = input("\nWould you like to configure API keys? (y/N): ").lower().strip()
    if response in ['y', 'yes']:
        try:
            subprocess.run([sys.executable, "api_manager.py", "--setup"], check=True)
        except subprocess.CalledProcessError:
            print("⚠️  API setup failed, but you can configure later")
    
    # External tools
    response = input("\nWould you like to install external tools (subfinder, nuclei, etc.)? (y/N): ").lower().strip()
    if response in ['y', 'yes']:
        try:
            subprocess.run([sys.executable, "external_tools.py"], check=True)
        except subprocess.CalledProcessError:
            print("⚠️  External tools installation failed")
    
    print("\n✅ Setup completed!")
    return True

def run_test():
    """Run test suite"""
    print("\n🧪 Running Tests...")
    print("=" * 20)
    
    try:
        subprocess.run([sys.executable, "test_tool.py"], check=True)
    except subprocess.CalledProcessError:
        print("❌ Tests failed")
        return False
    
    return True

def main():
    """Main launcher function"""
    
    # Handle special commands
    if len(sys.argv) > 1:
        if sys.argv[1] == "--setup":
            interactive_setup()
            return
        elif sys.argv[1] == "--install":
            subprocess.run([sys.executable, "install.py"])
            return
        elif sys.argv[1] == "--test":
            run_test()
            return
        elif sys.argv[1] in ["--help", "-h"]:
            show_usage()
            return
    
    # Check dependencies
    if not check_and_install():
        print("\n🛠️  Run setup first:")
        print("  python recon_master.py --setup")
        sys.exit(1)
    
    # Check if target is provided
    if len(sys.argv) < 2:
        show_usage()
        sys.exit(1)
    
    # Load configuration
    load_config()
    
    # Prepare arguments
    args = sys.argv[1:]
    
    # If first argument doesn't start with '-', assume it's the target
    if not args[0].startswith('-'):
        target = args[0]
        remaining_args = args[1:]
        final_args = ['-t', target] + remaining_args
    else:
        final_args = args
    
    # Launch the main tool
    try:
        print("\n🚀 Launching Advanced Reconnaissance Tool...")
        print("-" * 45)
        
        cmd = [sys.executable, 'advanced_recon_tool.py'] + final_args
        subprocess.run(cmd, check=True)
        
        print("\n🎉 Reconnaissance completed successfully!")
        
    except subprocess.CalledProcessError as e:
        print(f"\n❌ Tool execution failed (exit code: {e.returncode})")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n⚠️  Scan interrupted by user")
    except FileNotFoundError:
        print("\n❌ Main tool file not found")
        print("Make sure all files are in the same directory")
        sys.exit(1)

if __name__ == "__main__":
    main()