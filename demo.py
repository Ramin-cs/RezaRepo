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
    print_colored("🔍 Advanced Subdomain Enumerator v2.0 - Demo", "96")
    print_colored("=" * 60, "93")
    
    print("\n📋 Available commands:")
    print_colored("1. python3 subdomains.py -d example.com  # Maximum discovery (default)", "92")
    print_colored("2. python3 subdomains.py -d example.com --quick  # Fast scan", "93")
    print_colored("3. python3 subdomains.py -d example.com --aggressive  # Maximum resources", "91")
    print_colored("4. python3 subdomains.py -d example.com --passive  # Passive only", "94")
    print_colored("5. python3 subdomains.py -d example.com --silent  # Silent mode", "95")
    print_colored("6. python3 subdomains.py --show-apis  # Show API status", "96")
    
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
        "🔑 Premium API integration (26 APIs)",
        "🌟 Censys, Shodan, VirusTotal APIs",
        "🔍 SecurityTrails, Chaos APIs",
        "🐙 GitHub, BinaryEdge APIs",
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
    
    print("\n🔑 API Power:")
    print_colored("  • Without APIs: 50-200 subdomains", "93")
    print_colored("  • With APIs: 500-2000+ subdomains", "92")
    print_colored("  • Setup guide: API_SETUP_GUIDE.md", "94")
    
    print("\n⚡ Performance Modes:")
    print_colored("  • Quick mode: 30 seconds, essential subdomains", "93")
    print_colored("  • Default mode: 2-5 minutes, comprehensive discovery", "92")
    print_colored("  • Aggressive mode: 5-15 minutes, maximum coverage", "91")
    
    print("\n🚀 Ready to use!")
    print_colored("Just run: python3 subdomains.py -d YOUR_DOMAIN", "92")
    print_colored("That's it! Optimized defaults will do the rest.", "94")

if __name__ == "__main__":
    main()