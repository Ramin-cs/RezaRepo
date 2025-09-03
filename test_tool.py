#!/usr/bin/env python3
"""
Test script for Advanced Web Reconnaissance Tool
This script tests the tool functionality with a safe target
"""

import os
import sys
import subprocess
import time

def test_tool():
    """Test the reconnaissance tool"""
    
    print("🧪 Testing Advanced Web Reconnaissance Tool")
    print("=" * 50)
    
    # Test target (using a safe, well-known domain)
    test_target = "example.com"
    test_output = "test_output"
    
    print(f"Test Target: {test_target}")
    print(f"Output Directory: {test_output}")
    
    # Clean up previous test results
    if os.path.exists(test_output):
        import shutil
        shutil.rmtree(test_output)
        print("Cleaned up previous test results")
    
    # Test command
    cmd = [
        sys.executable, 
        "advanced_recon_tool.py",
        "-t", test_target,
        "-o", test_output,
        "--threads", "20",
        "--timeout", "10"
    ]
    
    print("\nStarting test scan...")
    print(f"Command: {' '.join(cmd)}")
    print("-" * 50)
    
    start_time = time.time()
    
    try:
        # Run the tool
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        
        end_time = time.time()
        duration = end_time - start_time
        
        print(f"\nTest completed in {duration:.2f} seconds")
        
        if result.returncode == 0:
            print("✅ Tool executed successfully!")
            
            # Check if output files were created
            expected_files = [
                f"{test_target}_recon_report.json",
                f"{test_target}_recon_report.html",
                f"{test_target}_summary.txt",
                "recon.log"
            ]
            
            print("\nChecking output files:")
            for filename in expected_files:
                filepath = os.path.join(test_output, filename)
                if os.path.exists(filepath):
                    size = os.path.getsize(filepath)
                    print(f"  ✅ {filename} ({size} bytes)")
                else:
                    print(f"  ❌ {filename} (missing)")
            
            print(f"\nTest results saved to: {test_output}/")
            
        else:
            print("❌ Tool execution failed!")
            print(f"Exit code: {result.returncode}")
            if result.stderr:
                print(f"Error output: {result.stderr}")
    
    except subprocess.TimeoutExpired:
        print("❌ Test timed out after 5 minutes")
    except Exception as e:
        print(f"❌ Test failed with exception: {e}")

def check_setup():
    """Check if the tool is properly set up"""
    
    print("🔍 Checking tool setup...")
    
    # Check if main files exist
    required_files = [
        "advanced_recon_tool.py",
        "advanced_modules.py",
        "requirements.txt",
        "setup.py"
    ]
    
    missing_files = []
    for filename in required_files:
        if not os.path.exists(filename):
            missing_files.append(filename)
    
    if missing_files:
        print(f"❌ Missing files: {', '.join(missing_files)}")
        return False
    
    # Check Python version
    if sys.version_info < (3, 7):
        print(f"❌ Python 3.7+ required (found {sys.version_info.major}.{sys.version_info.minor})")
        return False
    
    print("✅ Setup check passed")
    return True

def main():
    """Main test function"""
    
    if not check_setup():
        print("\n🛠️  Please run setup.py first:")
        print("  python setup.py")
        sys.exit(1)
    
    # Ask user if they want to run the test
    print("\nThis will run a test scan on example.com")
    response = input("Continue? (y/N): ").lower().strip()
    
    if response in ['y', 'yes']:
        test_tool()
    else:
        print("Test cancelled")
        
        # Show usage examples instead
        print("\n📋 Usage Examples:")
        print("  python advanced_recon_tool.py -t example.com")
        print("  python run_recon.py example.com")
        print("  ./run_recon.sh example.com  (Unix/Linux)")
        print("  run_recon.bat example.com   (Windows)")

if __name__ == "__main__":
    main()