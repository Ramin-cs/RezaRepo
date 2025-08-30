#!/usr/bin/env python3
"""
Quick local test for XSS Scanner v2
"""

import subprocess
import sys
import time
import threading
from colorama import Fore, Style, init

init(autoreset=True)

def start_demo_server():
    """Start demo server in background"""
    demo_process = subprocess.Popen([
        sys.executable, 'demo.py', '-p', '8082'
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    time.sleep(3)  # Wait for server
    return demo_process

def test_scanner():
    """Test the v2 scanner"""
    print(f"""
{Fore.GREEN}
╔══════════════════════════════════════════════════════════════╗
║                    Scanner V2 Test                          ║
╚══════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}
""")
    
    # Start demo server
    print(f"{Fore.GREEN}[{Fore.RED}DEMO{Fore.GREEN}] {Fore.WHITE}Starting demo server...")
    demo_process = start_demo_server()
    
    try:
        # Test scanner
        print(f"{Fore.GREEN}[{Fore.RED}TEST{Fore.GREEN}] {Fore.WHITE}Running scanner v2...")
        
        result = subprocess.run([
            sys.executable, 'xss_scanner_v2.py',
            '-u', 'http://localhost:8082',
            '-d', '2',
            '--delay', '0.5',
            '--timeout', '10'
        ], timeout=120)
        
        if result.returncode == 0:
            print(f"{Fore.GREEN}[{Fore.RED}SUCCESS{Fore.GREEN}] {Fore.WHITE}Scanner test completed!")
        else:
            print(f"{Fore.RED}[{Fore.YELLOW}FAIL{Fore.RED}] {Fore.WHITE}Scanner test failed")
    
    except subprocess.TimeoutExpired:
        print(f"{Fore.RED}[{Fore.YELLOW}TIMEOUT{Fore.RED}] {Fore.WHITE}Scanner test timed out")
    except Exception as e:
        print(f"{Fore.RED}[{Fore.YELLOW}ERROR{Fore.RED}] {Fore.WHITE}Test failed: {e}")
    
    finally:
        demo_process.terminate()
        demo_process.wait()
        print(f"{Fore.GREEN}[{Fore.RED}CLEANUP{Fore.GREEN}] {Fore.WHITE}Demo server stopped")

if __name__ == "__main__":
    test_scanner()