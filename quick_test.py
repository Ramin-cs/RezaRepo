#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Quick test script to verify scanner functionality
"""

import subprocess
import sys
import threading
import time
import requests
from colorama import Fore, Style, init

init(autoreset=True)

def test_with_demo_server():
    """Test scanner with local demo server"""
    print(f"{Fore.GREEN}[{Fore.RED}TEST{Fore.GREEN}] {Fore.WHITE}Starting demo server for testing...")
    
    # Start demo server
    demo_process = subprocess.Popen([
        sys.executable, 'demo.py', '-p', '8081'
    ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    
    time.sleep(3)  # Wait for server to start
    
    try:
        # Test if server is running
        response = requests.get('http://localhost:8081', timeout=5)
        if response.status_code == 200:
            print(f"{Fore.GREEN}[{Fore.RED}DEMO{Fore.GREEN}] {Fore.WHITE}Server started successfully")
            
            # Run scanner
            print(f"{Fore.GREEN}[{Fore.RED}SCAN{Fore.GREEN}] {Fore.WHITE}Running scanner against demo server...")
            result = subprocess.run([
                sys.executable, 'advanced_xss_scanner.py',
                '-u', 'http://localhost:8081',
                '-d', '2',
                '--delay', '0.5'
            ], timeout=60)
            
            if result.returncode == 0:
                print(f"{Fore.GREEN}[{Fore.RED}SUCCESS{Fore.GREEN}] {Fore.WHITE}Scanner test completed successfully!")
            else:
                print(f"{Fore.RED}[{Fore.YELLOW}FAIL{Fore.RED}] {Fore.WHITE}Scanner test failed")
        else:
            print(f"{Fore.RED}[{Fore.YELLOW}ERROR{Fore.RED}] {Fore.WHITE}Demo server not responding")
    
    except Exception as e:
        print(f"{Fore.RED}[{Fore.YELLOW}ERROR{Fore.RED}] {Fore.WHITE}Test failed: {e}")
    
    finally:
        demo_process.terminate()
        demo_process.wait()
        print(f"{Fore.GREEN}[{Fore.RED}CLEANUP{Fore.GREEN}] {Fore.WHITE}Demo server stopped")

def test_with_external_target():
    """Test scanner with external target"""
    print(f"{Fore.GREEN}[{Fore.RED}TEST{Fore.GREEN}] {Fore.WHITE}Testing with external target...")
    
    # Test with a reliable external target
    target = 'https://httpbin.org'
    
    try:
        result = subprocess.run([
            sys.executable, 'advanced_xss_scanner.py',
            '-u', target,
            '-d', '1',
            '--delay', '1'
        ], timeout=60)
        
        if result.returncode == 0:
            print(f"{Fore.GREEN}[{Fore.RED}SUCCESS{Fore.GREEN}] {Fore.WHITE}External test completed successfully!")
        else:
            print(f"{Fore.RED}[{Fore.YELLOW}FAIL{Fore.RED}] {Fore.WHITE}External test failed")
    
    except Exception as e:
        print(f"{Fore.RED}[{Fore.YELLOW}ERROR{Fore.RED}] {Fore.WHITE}External test failed: {e}")

if __name__ == "__main__":
    print(f"""
{Fore.GREEN}
╔══════════════════════════════════════════════════════════════╗
║                    Scanner Quick Test                        ║
║                   تست سریع اسکنر                            ║
╚══════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}
""")
    
    print("Choose test method:")
    print("1. Test with local demo server (recommended)")
    print("2. Test with external target (httpbin.org)")
    print("3. Both tests")
    
    choice = input("Enter choice (1-3): ").strip()
    
    if choice == '1':
        test_with_demo_server()
    elif choice == '2':
        test_with_external_target()
    elif choice == '3':
        test_with_demo_server()
        print("\n" + "="*50)
        test_with_external_target()
    else:
        print("Invalid choice. Running demo server test...")
        test_with_demo_server()