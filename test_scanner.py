#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test script for Advanced XSS Scanner
اسکریپت تست برای ابزار پیشرفته تشخیص XSS
"""

import subprocess
import threading
import time
import requests
import sys
import os
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

def print_banner():
    """Print test banner"""
    banner = f"""
{Fore.CYAN}
╔══════════════════════════════════════════════════════════════╗
║                  XSS Scanner Test Suite                     ║
║                مجموعه تست ابزار اسکن XSS                    ║
╚══════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}
"""
    print(banner)

def start_demo_server():
    """Start the demo vulnerable server"""
    print(f"{Fore.YELLOW}🚀 Starting demo vulnerable server...")
    
    try:
        # Start demo server in background
        demo_process = subprocess.Popen([
            sys.executable, 'demo.py', '-p', '8080'
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        # Wait for server to start
        time.sleep(3)
        
        # Check if server is running
        try:
            response = requests.get('http://localhost:8080', timeout=5)
            if response.status_code == 200:
                print(f"{Fore.GREEN}✅ Demo server started successfully on port 8080")
                return demo_process
            else:
                print(f"{Fore.RED}❌ Demo server responded with status {response.status_code}")
                return None
        except requests.exceptions.RequestException as e:
            print(f"{Fore.RED}❌ Failed to connect to demo server: {e}")
            demo_process.terminate()
            return None
            
    except Exception as e:
        print(f"{Fore.RED}❌ Failed to start demo server: {e}")
        return None

def run_scanner_test():
    """Run the XSS scanner against demo server"""
    print(f"\n{Fore.YELLOW}🔍 Running XSS Scanner test...")
    
    try:
        # Run scanner with limited depth for quick test
        result = subprocess.run([
            sys.executable, 'advanced_xss_scanner.py',
            '-u', 'http://localhost:8080',
            '-d', '2',  # Limited depth
            '--delay', '0.5',  # Faster testing
            '-t', '3'  # Limited threads
        ], capture_output=True, text=True, timeout=120)
        
        print(f"\n{Fore.BLUE}Scanner Output:")
        print("="*60)
        print(result.stdout)
        
        if result.stderr:
            print(f"\n{Fore.RED}Scanner Errors:")
            print("="*60)
            print(result.stderr)
        
        if result.returncode == 0:
            print(f"\n{Fore.GREEN}✅ Scanner completed successfully!")
        else:
            print(f"\n{Fore.RED}❌ Scanner completed with errors (return code: {result.returncode})")
        
        return result.returncode == 0
        
    except subprocess.TimeoutExpired:
        print(f"{Fore.RED}❌ Scanner test timed out after 2 minutes")
        return False
    except Exception as e:
        print(f"{Fore.RED}❌ Failed to run scanner test: {e}")
        return False

def test_individual_components():
    """Test individual components"""
    print(f"\n{Fore.YELLOW}🧪 Testing individual components...")
    
    tests = [
        ("Python imports", test_imports),
        ("Demo server connectivity", test_demo_server),
        ("Scanner basic functionality", test_scanner_basic),
    ]
    
    results = []
    for test_name, test_func in tests:
        print(f"\n{Fore.BLUE}Testing: {test_name}")
        try:
            success = test_func()
            if success:
                print(f"{Fore.GREEN}  ✅ {test_name}: PASSED")
            else:
                print(f"{Fore.RED}  ❌ {test_name}: FAILED")
            results.append((test_name, success))
        except Exception as e:
            print(f"{Fore.RED}  ❌ {test_name}: ERROR - {e}")
            results.append((test_name, False))
    
    return results

def test_imports():
    """Test if all required modules can be imported"""
    try:
        import requests
        import bs4
        import selenium
        import colorama
        import urllib.parse
        return True
    except ImportError as e:
        print(f"    Import error: {e}")
        return False

def test_demo_server():
    """Test demo server endpoints"""
    try:
        base_url = 'http://localhost:8080'
        
        # Test main page
        response = requests.get(base_url, timeout=5)
        if response.status_code != 200:
            return False
        
        # Test search page
        response = requests.get(f'{base_url}/search?q=test', timeout=5)
        if response.status_code != 200:
            return False
        
        # Test contact page
        response = requests.get(f'{base_url}/contact', timeout=5)
        if response.status_code != 200:
            return False
        
        return True
    except Exception as e:
        print(f"    Server test error: {e}")
        return False

def test_scanner_basic():
    """Test basic scanner functionality"""
    try:
        # Import scanner class
        sys.path.insert(0, '.')
        from advanced_xss_scanner import AdvancedXSSScanner
        
        # Create scanner instance
        scanner = AdvancedXSSScanner('http://localhost:8080', max_depth=1, delay=0.1)
        
        # Test basic methods
        if not hasattr(scanner, 'crawl_website'):
            return False
        
        if not hasattr(scanner, 'perform_fuzzing'):
            return False
        
        if not hasattr(scanner, 'generate_html_report'):
            return False
        
        return True
    except Exception as e:
        print(f"    Scanner test error: {e}")
        return False

def check_output_files():
    """Check if output files were created"""
    print(f"\n{Fore.YELLOW}📁 Checking output files...")
    
    files_to_check = [
        ("HTML reports", "*.html"),
        ("JSON reports", "*.json"),
        ("Screenshots", "screenshots/"),
    ]
    
    for file_type, pattern in files_to_check:
        if pattern.endswith('/'):
            # Directory
            if os.path.exists(pattern):
                files = os.listdir(pattern)
                if files:
                    print(f"{Fore.GREEN}  ✅ {file_type}: Found {len(files)} files")
                else:
                    print(f"{Fore.YELLOW}  ⚠️  {file_type}: Directory exists but empty")
            else:
                print(f"{Fore.RED}  ❌ {file_type}: Directory not found")
        else:
            # Files with pattern
            import glob
            files = glob.glob(pattern)
            if files:
                print(f"{Fore.GREEN}  ✅ {file_type}: Found {len(files)} files")
                for file in files:
                    print(f"    - {file}")
            else:
                print(f"{Fore.RED}  ❌ {file_type}: No files found")

def print_test_summary(component_results, scanner_success):
    """Print test summary"""
    print(f"\n{Fore.CYAN}{'='*60}")
    print(f"{Fore.CYAN}TEST SUMMARY - خلاصه تست‌ها")
    print(f"{Fore.CYAN}{'='*60}")
    
    # Component tests
    print(f"\n{Fore.BLUE}Component Tests:")
    passed = 0
    total = len(component_results)
    
    for test_name, success in component_results:
        status = f"{Fore.GREEN}PASSED" if success else f"{Fore.RED}FAILED"
        print(f"  • {test_name}: {status}")
        if success:
            passed += 1
    
    print(f"\n{Fore.BLUE}Component Tests Result: {passed}/{total} passed")
    
    # Scanner test
    print(f"\n{Fore.BLUE}Full Scanner Test:")
    if scanner_success:
        print(f"  • {Fore.GREEN}XSS Scanner: PASSED")
    else:
        print(f"  • {Fore.RED}XSS Scanner: FAILED")
    
    # Overall result
    overall_success = (passed == total) and scanner_success
    
    print(f"\n{Fore.CYAN}{'='*60}")
    if overall_success:
        print(f"{Fore.GREEN}🎉 ALL TESTS PASSED! Scanner is ready to use.")
    else:
        print(f"{Fore.RED}❌ SOME TESTS FAILED! Please check the errors above.")
    print(f"{Fore.CYAN}{'='*60}")
    
    return overall_success

def main():
    """Main test function"""
    print_banner()
    
    print(f"{Fore.YELLOW}Starting comprehensive test of Advanced XSS Scanner...")
    print(f"{Fore.YELLOW}This will test all components and run a live scan.\n")
    
    demo_process = None
    scanner_success = False
    
    try:
        # Start demo server
        demo_process = start_demo_server()
        if not demo_process:
            print(f"{Fore.RED}❌ Cannot proceed without demo server")
            return False
        
        # Test individual components
        component_results = test_individual_components()
        
        # Run full scanner test
        scanner_success = run_scanner_test()
        
        # Check output files
        check_output_files()
        
        # Print summary
        overall_success = print_test_summary(component_results, scanner_success)
        
        return overall_success
        
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Test interrupted by user.")
        return False
    except Exception as e:
        print(f"\n{Fore.RED}Unexpected error during testing: {e}")
        return False
    finally:
        # Clean up demo server
        if demo_process:
            print(f"\n{Fore.YELLOW}🛑 Stopping demo server...")
            demo_process.terminate()
            demo_process.wait()
            print(f"{Fore.GREEN}✅ Demo server stopped")

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)