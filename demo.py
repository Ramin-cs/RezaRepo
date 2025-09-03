#!/usr/bin/env python3
"""
Professional Open Redirect Scanner - Demonstration Script
Shows the capabilities of the scanner with example usage
"""

import asyncio
import json
import time
from pathlib import Path
import logging

# Import scanner components
from enhanced_scanner import EnhancedOpenRedirectScanner
from bug_bounty_tester import BugBountyTester
from utils import PayloadGenerator, URLUtils


def print_banner():
    """Print professional banner"""
    banner = """
╔═══════════════════════════════════════════════════════════════════════╗
║                                                                       ║
║    🔍 Professional Open Redirect Vulnerability Scanner 🔍             ║
║                                                                       ║
║    ✨ Features:                                                       ║
║    • Deep Web Crawling with JavaScript Rendering                     ║
║    • Advanced JavaScript AST Analysis                                ║
║    • DOM-based Vulnerability Detection                               ║
║    • Web3 & Blockchain Application Support                           ║
║    • Context-aware Payload Injection                                 ║
║    • Professional PoC Screenshot Generation                          ║
║    • Comprehensive Security Reporting                                ║
║                                                                       ║
║    🎯 Designed for Bug Bounty Hunters & Security Researchers         ║
║                                                                       ║
╚═══════════════════════════════════════════════════════════════════════╝
"""
    print(banner)


def demonstrate_payload_categories():
    """Demonstrate different payload categories"""
    print("🎯 Payload Categories Demonstration")
    print("=" * 50)
    
    generator = PayloadGenerator()
    
    categories = {
        "Basic Redirects": generator.generate_basic_payloads(),
        "Encoded Bypasses": generator.generate_encoded_payloads(),
        "Protocol Bypasses": generator.generate_protocol_bypass_payloads(),
        "Unicode Bypasses": generator.generate_unicode_payloads(),
        "IP Address Bypasses": generator.generate_ip_payloads(),
        "JavaScript Payloads": generator.generate_javascript_payloads(),
        "Web3 Payloads": generator.generate_web3_payloads()
    }
    
    for category, payloads in categories.items():
        print(f"\n📂 {category}:")
        for i, payload in enumerate(payloads[:3], 1):  # Show first 3 examples
            print(f"   {i}. {payload}")
        if len(payloads) > 3:
            print(f"   ... and {len(payloads) - 3} more")


def demonstrate_context_detection():
    """Demonstrate context detection capabilities"""
    print("\n🔍 Context Detection Demonstration")
    print("=" * 50)
    
    # Example parameters with different contexts
    examples = [
        {
            "name": "redirect_uri",
            "value": "https://example.com",
            "context": "query",
            "description": "OAuth redirect parameter in URL query"
        },
        {
            "name": "target",
            "value": "//evil.com",
            "context": "fragment", 
            "description": "Hash-based redirect parameter"
        },
        {
            "name": "wallet_redirect",
            "value": "metamask://connect",
            "context": "web3_config",
            "description": "Web3 wallet connection redirect"
        },
        {
            "name": "form_action",
            "value": "/redirect",
            "context": "form_action",
            "description": "Form action URL for POST redirects"
        }
    ]
    
    for example in examples:
        print(f"\n📌 Parameter: {example['name']}")
        print(f"   Value: {example['value']}")
        print(f"   Context: {example['context']}")
        print(f"   Description: {example['description']}")


def show_scanner_capabilities():
    """Show scanner capabilities and features"""
    print("\n🚀 Scanner Capabilities")
    print("=" * 50)
    
    capabilities = {
        "🕷️ Deep Web Crawling": [
            "Recursive crawling up to configurable depth",
            "JavaScript-rendered content analysis",
            "Form and input field enumeration",
            "HTTP header parameter extraction"
        ],
        "🔬 JavaScript Analysis": [
            "AST-based static analysis",
            "Data flow tracing from sources to sinks",
            "DOM-based redirect sink detection",
            "Runtime parameter extraction"
        ],
        "🌐 Web3 Support": [
            "Smart contract interaction analysis",
            "Wallet connection parameter extraction",
            "DApp-specific redirect patterns",
            "ENS domain and contract address discovery"
        ],
        "🎯 Advanced Testing": [
            "Context-aware payload injection",
            "Multi-encoding bypass techniques",
            "Protocol-relative URL testing",
            "JavaScript protocol execution"
        ],
        "📊 Professional Reporting": [
            "Interactive HTML reports",
            "JSON data export for automation",
            "CSV analysis for spreadsheets",
            "Executive summary with risk assessment"
        ]
    }
    
    for category, features in capabilities.items():
        print(f"\n{category}")
        for feature in features:
            print(f"   ✓ {feature}")


def show_usage_examples():
    """Show usage examples"""
    print("\n📖 Usage Examples")
    print("=" * 50)
    
    examples = [
        {
            "title": "Basic Scan",
            "command": "./run_scanner.sh https://example.com",
            "description": "Simple scan with default settings"
        },
        {
            "title": "Advanced Web2 Scan",
            "command": "python3 enhanced_scanner.py https://webapp.com --depth 4 --max-pages 500 --verbose",
            "description": "Deep scan of traditional web application"
        },
        {
            "title": "Web3 DApp Scan",
            "command": "python3 enhanced_scanner.py https://dapp.example.com --web3-mode --verbose",
            "description": "Specialized scan for Web3 decentralized applications"
        },
        {
            "title": "Bug Bounty Campaign",
            "command": "python3 bug_bounty_tester.py --campaign",
            "description": "Run systematic testing on multiple bug bounty targets"
        },
        {
            "title": "Custom Configuration",
            "command": "python3 enhanced_scanner.py https://target.com --depth 2 --max-pages 100",
            "description": "Scan with custom depth and page limits"
        }
    ]
    
    for example in examples:
        print(f"\n📌 {example['title']}")
        print(f"   Command: {example['command']}")
        print(f"   Description: {example['description']}")


async def run_demo_scan():
    """Run a demonstration scan on a test page"""
    print("\n🧪 Running Demonstration Scan")
    print("=" * 50)
    
    # Create a simple test HTML page
    test_html = """
    <!DOCTYPE html>
    <html>
    <head><title>Test Page</title></head>
    <body>
        <h1>Test Page for Open Redirect Scanner</h1>
        <a href="/redirect?url=https://example.com">Test Link</a>
        <form action="/submit">
            <input name="redirect_url" placeholder="Redirect URL">
            <input name="next" placeholder="Next Page">
            <button type="submit">Submit</button>
        </form>
        <script>
            var targetUrl = new URLSearchParams(location.search).get('target');
            if (targetUrl) {
                console.log('Redirect target:', targetUrl);
                // Simulated redirect (commented for safety)
                // location.href = targetUrl;
            }
        </script>
    </body>
    </html>
    """
    
    # Save test page
    test_page_path = Path("/workspace/demo_test_page.html")
    with open(test_page_path, 'w') as f:
        f.write(test_html)
    
    print(f"📄 Created test page: {test_page_path}")
    print("🔍 This demonstrates the types of patterns the scanner detects:")
    print("   • URL parameters (url, target, next)")
    print("   • Form inputs (redirect_url, next)")
    print("   • JavaScript parameter extraction")
    print("   • DOM-based redirect patterns")


def show_security_considerations():
    """Show important security considerations"""
    print("\n🛡️ Security & Ethical Considerations")
    print("=" * 50)
    
    considerations = [
        "✅ Only test on authorized targets (own applications, bug bounty programs)",
        "✅ Respect rate limits and avoid overwhelming target servers",
        "✅ Follow responsible disclosure practices for any vulnerabilities found",
        "✅ Obtain proper authorization before testing third-party applications",
        "❌ Do NOT use for unauthorized testing or malicious purposes",
        "❌ Do NOT violate terms of service or applicable laws",
        "❌ Do NOT test production systems without permission",
        "⚠️  Always verify vulnerabilities manually before reporting"
    ]
    
    for consideration in considerations:
        print(f"   {consideration}")


def main():
    """Main demonstration function"""
    print_banner()
    
    print("\n🎓 Welcome to the Professional Open Redirect Scanner Demo!")
    print("\nThis demonstration shows the capabilities of our advanced security scanner.")
    
    # Show different sections
    demonstrate_payload_categories()
    demonstrate_context_detection()
    show_scanner_capabilities()
    show_usage_examples()
    
    # Run demo scan
    asyncio.run(run_demo_scan())
    
    # Security considerations
    show_security_considerations()
    
    print("\n" + "=" * 70)
    print("🚀 Ready to start scanning!")
    print("\n📚 Next Steps:")
    print("1. Run: ./install_dependencies.sh (if not already done)")
    print("2. Configure targets in config.json")
    print("3. Start scanning: ./run_scanner.sh <target_url>")
    print("4. Review reports in the reports/ directory")
    print("\n🎯 Happy Bug Hunting! (Responsibly)")


if __name__ == "__main__":
    main()