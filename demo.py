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
    print_colored("4. python3 subdomains.py -d example.com --no-httpx  # Skip HTTP probing", "93")
    
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
        "🚀 httpx HTTP/HTTPS probing",
        "📊 Live subdomain checking",
        "🎯 Status code categorization",
        "⚡ Response time measurement",
        "📝 Title extraction",
        "Automatic duplicate removal",
        "Clean TXT output with status codes"
    ]
    
    for i, feature in enumerate(features, 1):
        print_colored(f"  {i:2d}. ✅ {feature}", "97")
    
    print("\n📊 Sample output format:")
    print_colored("✅ https://www.target.com [200] [89ms] Target Website", "92")
    print_colored("✅ http://api.target.com [200] [156ms] API Documentation", "92")
    print_colored("✅ https://admin.target.com [403] [203ms] Access Denied", "91")
    print_colored("✅ http://blog.target.com [200] [178ms] Company Blog", "92")
    print_colored("✅ https://mail.target.com [301] [87ms] Redirected", "93")
    print_colored("✅ http://dev.target.com [200] [298ms] Development", "92")
    print_colored("✅ https://app.target.com [200] [234ms] Web Application", "92")
    
    print("\n🚀 Ready to use!")
    print_colored("Usage: python3 subdomains.py -d YOUR_DOMAIN", "93")

if __name__ == "__main__":
    main()