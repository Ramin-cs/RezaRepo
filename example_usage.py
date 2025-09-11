#!/usr/bin/env python3
"""
Example usage script for Router Brute Force Chrome v2.0
This script demonstrates how to use the Chrome-based router brute force tool
"""

import subprocess
import sys
import os

def run_example():
    """Run example usage of the router brute force tool"""
    
    print("Router Brute Force Chrome v2.0 - Example Usage")
    print("=" * 50)
    
    # Example URLs (replace with actual router IPs)
    example_urls = [
        "http://192.168.1.1",      # Common router IP
        "http://192.168.0.1",      # Another common router IP
        "http://10.0.0.1",         # Some routers use this
        "http://192.168.100.1"     # Some modems use this
    ]
    
    print("Example router URLs to test:")
    for i, url in enumerate(example_urls, 1):
        print(f"  {i}. {url}")
    
    print("\nExample commands:")
    print("1. Basic usage:")
    print("   python router_brute_force_chrome.py -u http://192.168.1.1")
    
    print("\n2. With custom timeout:")
    print("   python router_brute_force_chrome.py -u http://192.168.1.1 --timeout 15")
    
    print("\n3. Headless mode (invisible browser):")
    print("   python router_brute_force_chrome.py -u http://192.168.1.1 --headless")
    
    print("\n4. Custom screenshot directory:")
    print("   python router_brute_force_chrome.py -u http://192.168.1.1 --screenshot-dir my_screenshots")
    
    print("\n5. Combined options:")
    print("   python router_brute_force_chrome.py -u http://192.168.1.1 --timeout 20 --screenshot-dir router_tests")
    
    print("\n" + "=" * 50)
    print("IMPORTANT SECURITY NOTICE:")
    print("- Only test routers you own or have permission to test")
    print("- This tool is for authorized security testing only")
    print("- Use responsibly and legally")
    print("=" * 50)
    
    # Interactive mode
    while True:
        print("\nOptions:")
        print("1. Run with example URL")
        print("2. Enter custom URL")
        print("3. Show help")
        print("4. Exit")
        
        choice = input("\nEnter your choice (1-4): ").strip()
        
        if choice == "1":
            url = input(f"Enter URL (default: {example_urls[0]}): ").strip()
            if not url:
                url = example_urls[0]
            run_brute_force(url)
            
        elif choice == "2":
            url = input("Enter router URL: ").strip()
            if url:
                run_brute_force(url)
            else:
                print("Invalid URL")
                
        elif choice == "3":
            show_help()
            
        elif choice == "4":
            print("Goodbye!")
            break
            
        else:
            print("Invalid choice. Please enter 1-4.")

def run_brute_force(url):
    """Run the brute force tool with given URL"""
    try:
        print(f"\nRunning brute force attack on: {url}")
        print("Chrome browser will open visibly...")
        
        # Run the brute force tool
        cmd = [sys.executable, "router_brute_force_chrome.py", "-u", url]
        result = subprocess.run(cmd, capture_output=False, text=True)
        
        if result.returncode == 0:
            print("\nBrute force attack completed successfully!")
        else:
            print(f"\nBrute force attack failed with return code: {result.returncode}")
            
    except FileNotFoundError:
        print("Error: router_brute_force_chrome.py not found in current directory")
    except Exception as e:
        print(f"Error running brute force attack: {e}")

def show_help():
    """Show help information"""
    try:
        cmd = [sys.executable, "router_brute_force_chrome.py", "--help"]
        subprocess.run(cmd)
    except FileNotFoundError:
        print("Error: router_brute_force_chrome.py not found in current directory")
    except Exception as e:
        print(f"Error showing help: {e}")

if __name__ == "__main__":
    run_example()