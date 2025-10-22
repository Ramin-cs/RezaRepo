#!/usr/bin/env python3
"""
Demo script to showcase the Advanced Subdomain Enumerator
"""

import subprocess
import sys
import time

def print_colored(text, color_code):
    """Print colored text"""
    print(f"\033[{color_code}m{text}\033[0m")

def main():
    print_colored("🔍 Advanced Subdomain Enumerator - Demo", "96")
    print_colored("=" * 50, "93")
    
    print("\n📋 Available commands:")
    print_colored("1. python3 subdomains.py -d example.com", "92")
    print_colored("2. python3 subdomains.py -d example.com -o results.txt -t 100 -v", "92")
    print_colored("3. python3 subdomains.py -d example.com --timeout 15 --verbose", "92")
    
    print("\n🎯 Features included:")
    features = [
        "Certificate Transparency logs",
        "DNS Brute Force with extensive wordlist",
        "Search Engine discovery",
        "GitHub Code Search",
        "Web Archive mining",
        "Passive DNS sources",
        "Zone Transfer attempts",
        "Reverse DNS lookups",
        "Virtual Host discovery",
        "SSL Certificate analysis",
        "Automatic duplicate removal",
        "Clean TXT output"
    ]
    
    for i, feature in enumerate(features, 1):
        print_colored(f"  {i:2d}. ✅ {feature}", "97")
    
    print("\n📊 Sample output format:")
    print_colored("admin.target.com", "92")
    print_colored("api.target.com", "92")
    print_colored("app.target.com", "92")
    print_colored("blog.target.com", "92")
    print_colored("dev.target.com", "92")
    print_colored("mail.target.com", "92")
    print_colored("www.target.com", "92")
    
    print("\n🚀 Ready to use!")
    print_colored("Usage: python3 subdomains.py -d YOUR_DOMAIN", "93")

if __name__ == "__main__":
    main()