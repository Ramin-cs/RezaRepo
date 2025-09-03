#!/usr/bin/env python3
"""
Final Check Script for Advanced Web Reconnaissance Tool
Performs comprehensive verification of the complete tool suite
"""

import os
import sys
import subprocess
import importlib
from pathlib import Path

class FinalChecker:
    """Final verification and testing"""
    
    def __init__(self):
        self.errors = []
        self.warnings = []
        self.success_count = 0
        self.total_checks = 0

    def check(self, description, condition, error_msg=None, warning_msg=None):
        """Perform a check and track results"""
        self.total_checks += 1
        
        if condition:
            print(f"✅ {description}")
            self.success_count += 1
            return True
        else:
            if error_msg:
                print(f"❌ {description} - {error_msg}")
                self.errors.append(f"{description}: {error_msg}")
            elif warning_msg:
                print(f"⚠️  {description} - {warning_msg}")
                self.warnings.append(f"{description}: {warning_msg}")
            else:
                print(f"❌ {description}")
                self.errors.append(description)
            return False

    def check_files(self):
        """Check if all required files exist"""
        print("\n📁 Checking Files...")
        print("-" * 20)
        
        required_files = [
            "advanced_recon_tool.py",
            "advanced_modules.py", 
            "external_tools.py",
            "requirements.txt",
            "setup.py",
            "install.py",
            "run_recon.py",
            "run_recon.sh",
            "run_recon.bat",
            "api_manager.py",
            "test_tool.py",
            "recon_master.py",
            "README.md",
            "README_FA.md"
        ]
        
        for filename in required_files:
            exists = Path(filename).exists()
            self.check(f"File {filename}", exists, f"File {filename} is missing")

    def check_python_modules(self):
        """Check Python module imports"""
        print("\n🐍 Checking Python Modules...")
        print("-" * 30)
        
        required_modules = {
            'requests': 'requests',
            'bs4': 'beautifulsoup4',
            'dns.resolver': 'dnspython', 
            'whois': 'python-whois',
            'concurrent.futures': 'built-in',
            'threading': 'built-in',
            'json': 'built-in',
            'urllib.parse': 'built-in'
        }
        
        for module, package in required_modules.items():
            try:
                importlib.import_module(module)
                self.check(f"Module {module}", True)
            except ImportError:
                self.check(f"Module {module}", False, f"Install with: pip install {package}")

    def check_tool_syntax(self):
        """Check Python syntax of all tools"""
        print("\n🔧 Checking Tool Syntax...")
        print("-" * 25)
        
        python_files = [
            "advanced_recon_tool.py",
            "advanced_modules.py",
            "external_tools.py", 
            "setup.py",
            "install.py",
            "run_recon.py",
            "api_manager.py",
            "test_tool.py",
            "recon_master.py"
        ]
        
        for filename in python_files:
            if Path(filename).exists():
                try:
                    result = subprocess.run([
                        sys.executable, "-m", "py_compile", filename
                    ], capture_output=True, text=True, timeout=10)
                    
                    self.check(f"Syntax {filename}", result.returncode == 0, 
                              f"Syntax error in {filename}")
                except Exception as e:
                    self.check(f"Syntax {filename}", False, f"Error checking {filename}: {e}")

    def check_executability(self):
        """Check if scripts are executable"""
        print("\n🔐 Checking Executability...")
        print("-" * 25)
        
        executable_files = [
            "run_recon.sh",
            "advanced_recon_tool.py",
            "recon_master.py"
        ]
        
        for filename in executable_files:
            if Path(filename).exists():
                # Check if file is executable
                is_executable = os.access(filename, os.X_OK)
                self.check(f"Executable {filename}", is_executable,
                          f"Run: chmod +x {filename}")

    def check_external_tools(self):
        """Check availability of external tools"""
        print("\n🛠️  Checking External Tools...")
        print("-" * 30)
        
        system_tools = {
            'nmap': 'Network mapper for port scanning',
            'dig': 'DNS lookup utility',
            'whois': 'Domain registration information',
            'curl': 'HTTP client for web requests',
            'wget': 'Web content retrieval'
        }
        
        go_tools = {
            'subfinder': 'Fast subdomain discovery tool',
            'httpx': 'HTTP toolkit for probing',
            'nuclei': 'Vulnerability scanner',
            'assetfinder': 'Asset discovery tool',
            'amass': 'Network mapping tool'
        }
        
        # Check system tools
        for tool, description in system_tools.items():
            available = subprocess.run(['which', tool], capture_output=True).returncode == 0
            self.check(f"System tool {tool}", available, 
                      warning_msg=f"Install {tool} for enhanced functionality")
        
        # Check Go tools
        for tool, description in go_tools.items():
            available = subprocess.run(['which', tool], capture_output=True).returncode == 0
            self.check(f"Go tool {tool}", available,
                      warning_msg=f"Install {tool} for enhanced subdomain discovery")

    def check_api_config(self):
        """Check API configuration"""
        print("\n🔑 Checking API Configuration...")
        print("-" * 30)
        
        config_file = Path("config.env")
        config_exists = config_file.exists()
        
        self.check("Config file exists", config_exists,
                  warning_msg="Run 'python api_manager.py --setup' to configure APIs")
        
        if config_exists:
            api_keys = ['SHODAN_API_KEY', 'VIRUSTOTAL_API_KEY', 'SECURITYTRAILS_API_KEY']
            configured_keys = 0
            
            with open(config_file, 'r') as f:
                content = f.read()
                for key in api_keys:
                    if f"{key}=" in content and not f"{key}=\n" in content and not f"{key}= " in content:
                        configured_keys += 1
            
            self.check(f"API keys configured", configured_keys > 0,
                      warning_msg=f"Only {configured_keys}/{len(api_keys)} API keys configured")

    def run_quick_test(self):
        """Run a quick functionality test"""
        print("\n🧪 Running Quick Test...")
        print("-" * 20)
        
        try:
            # Test basic import
            sys.path.insert(0, '.')
            from advanced_recon_tool import WebReconTool
            
            # Create a test instance
            test_tool = WebReconTool("example.com", "test_output_temp")
            
            self.check("Tool instantiation", True)
            
            # Clean up
            import shutil
            if Path("test_output_temp").exists():
                shutil.rmtree("test_output_temp")
            
        except Exception as e:
            self.check("Tool instantiation", False, f"Error: {e}")

    def generate_summary(self):
        """Generate final summary"""
        print("\n" + "=" * 60)
        print("🎯 FINAL CHECK SUMMARY")
        print("=" * 60)
        
        success_rate = (self.success_count / self.total_checks) * 100 if self.total_checks > 0 else 0
        
        print(f"✅ Successful checks: {self.success_count}/{self.total_checks} ({success_rate:.1f}%)")
        
        if self.errors:
            print(f"\n❌ Errors ({len(self.errors)}):")
            for error in self.errors:
                print(f"   • {error}")
        
        if self.warnings:
            print(f"\n⚠️  Warnings ({len(self.warnings)}):")
            for warning in self.warnings:
                print(f"   • {warning}")
        
        if not self.errors:
            print("\n🎉 ALL CRITICAL CHECKS PASSED!")
            print("\n📋 Ready to use:")
            print("   python recon_master.py example.com")
            print("   python advanced_recon_tool.py -t example.com")
            print("   ./run_recon.sh example.com")
            
            if self.warnings:
                print(f"\n💡 {len(self.warnings)} optional features not available")
                print("   Tool will work with reduced functionality")
                print("   Run 'python recon_master.py --install' for full features")
        else:
            print(f"\n🔧 {len(self.errors)} critical issues found")
            print("   Please fix these issues before using the tool")
            print("   Run 'python recon_master.py --setup' for guided setup")

    def run_all_checks(self):
        """Run all verification checks"""
        print("🔍 Advanced Web Reconnaissance Tool - Final Verification")
        print("=" * 60)
        
        # Run all checks
        self.check_files()
        self.check_python_modules()
        self.check_tool_syntax()
        self.check_executability()
        self.check_external_tools()
        self.check_api_config()
        self.run_quick_test()
        
        # Generate summary
        self.generate_summary()
        
        return len(self.errors) == 0

def main():
    """Main verification function"""
    checker = FinalChecker()
    
    try:
        success = checker.run_all_checks()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n⚠️  Verification interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Verification failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()