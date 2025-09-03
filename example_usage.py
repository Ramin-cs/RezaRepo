#!/usr/bin/env python3
"""
Professional Open Redirect Scanner - Example Usage
Demonstrates how to use the scanner programmatically
"""

import asyncio
import logging
from pathlib import Path
import json

from enhanced_scanner import EnhancedOpenRedirectScanner, EnhancedParameter
from bug_bounty_tester import BugBountyTester, BugBountyTarget
from utils import PayloadGenerator, URLUtils, Web3Utils


async def example_basic_scan():
    """Example: Basic website scan"""
    print("🔍 Example 1: Basic Website Scan")
    print("-" * 40)
    
    target_url = "https://httpbin.org"  # Safe testing target
    
    # Create scanner instance
    scanner = EnhancedOpenRedirectScanner(
        target_url=target_url,
        max_depth=2,
        max_pages=20
    )
    
    try:
        # Initialize scanner
        await scanner.init_session()
        scanner.init_enhanced_driver()
        
        # Run crawling phase
        print(f"📡 Crawling {target_url}...")
        urls = await scanner.enhanced_crawl_website()
        print(f"   Found {len(urls)} URLs")
        print(f"   Extracted {len(scanner.parameters)} parameters")
        
        # Analyze parameters
        redirect_params = [p for p in scanner.parameters if p.is_redirect_related]
        high_conf_params = [p for p in scanner.parameters if p.confidence > 0.7]
        
        print(f"   Redirect-related parameters: {len(redirect_params)}")
        print(f"   High-confidence parameters: {len(high_conf_params)}")
        
        # Show some examples
        if redirect_params:
            print("\n📋 Sample redirect-related parameters:")
            for param in redirect_params[:3]:
                print(f"   • {param.name} = {param.value[:50]}...")
        
        return {
            "urls_found": len(urls),
            "parameters_found": len(scanner.parameters),
            "redirect_parameters": len(redirect_params)
        }
        
    except Exception as e:
        print(f"❌ Scan failed: {e}")
        return {"error": str(e)}
    finally:
        if scanner.session:
            await scanner.session.close()
        if scanner.driver:
            scanner.driver.quit()


async def example_javascript_analysis():
    """Example: JavaScript analysis capabilities"""
    print("\n🔬 Example 2: JavaScript Analysis")
    print("-" * 40)
    
    # Sample JavaScript code with potential vulnerabilities
    sample_js = """
    // Sample JavaScript with redirect patterns
    function handleRedirect() {
        var redirectUrl = new URLSearchParams(location.search).get('redirect');
        var nextPage = localStorage.getItem('next_page');
        var targetSite = document.getElementById('target').value;
        
        if (redirectUrl) {
            // Potential open redirect vulnerability
            location.href = redirectUrl;
        }
        
        if (nextPage && nextPage.startsWith('http')) {
            window.location.assign(nextPage);
        }
        
        // Web3 wallet connection
        if (window.ethereum) {
            var walletUrl = sessionStorage.getItem('wallet_redirect');
            if (walletUrl) {
                window.open(walletUrl);
            }
        }
    }
    
    // DOM-based redirect
    if (location.hash) {
        var target = location.hash.substring(1);
        if (target.startsWith('redirect=')) {
            document.location = decodeURIComponent(target.substring(9));
        }
    }
    """
    
    # Analyze JavaScript
    from js_analyzer import JavaScriptAnalyzer
    analyzer = JavaScriptAnalyzer()
    
    analysis_result = analyzer.comprehensive_analysis(sample_js, "example.js")
    
    print(f"📊 Analysis Results:")
    print(f"   Parameters found: {analysis_result['total_parameters']}")
    print(f"   High-confidence params: {len(analysis_result['high_confidence_params'])}")
    print(f"   Redirect-related params: {len(analysis_result['redirect_related_params'])}")
    print(f"   Data flows detected: {len(analysis_result['data_flows'])}")
    print(f"   DOM sinks found: {len(analysis_result['dom_sinks'])}")
    
    # Show some examples
    if analysis_result['parameters']:
        print("\n📋 Sample detected parameters:")
        for param in analysis_result['parameters'][:3]:
            print(f"   • {param.name} (confidence: {param.confidence:.1%})")
    
    if analysis_result['data_flows']:
        print("\n🔄 Sample data flows:")
        for flow in analysis_result['data_flows'][:2]:
            print(f"   • {flow.get('flow_path', 'N/A')}")


def example_payload_generation():
    """Example: Payload generation for different contexts"""
    print("\n🎯 Example 3: Context-Aware Payload Generation")
    print("-" * 40)
    
    generator = PayloadGenerator()
    
    contexts = [
        ("URL Query Parameter", "query"),
        ("Hash Fragment", "fragment"), 
        ("JavaScript Variable", "javascript"),
        ("Web3 Application", "web3"),
        ("Form Action", "form")
    ]
    
    for context_name, context_type in contexts:
        print(f"\n📂 {context_name}:")
        payloads = generator.generate_context_specific_payloads(context_type)
        for payload in payloads[:2]:  # Show first 2 examples
            print(f"   • {payload}")


def example_web3_detection():
    """Example: Web3 detection capabilities"""
    print("\n🌐 Example 4: Web3 Detection")
    print("-" * 40)
    
    # Sample Web3 application content
    sample_web3_content = """
    <html>
    <head>
        <script src="https://cdn.jsdelivr.net/npm/web3@latest/dist/web3.min.js"></script>
    </head>
    <body>
        <div id="app">
            <button onclick="connectWallet()">Connect Wallet</button>
            <button onclick="switchNetwork()">Switch Network</button>
        </div>
        
        <script>
            const contractAddress = "0x1234567890123456789012345678901234567890";
            const providerUrl = "https://mainnet.infura.io/v3/YOUR_PROJECT_ID";
            
            async function connectWallet() {
                const redirectUrl = localStorage.getItem('wallet_callback');
                if (window.ethereum) {
                    await window.ethereum.request({ method: 'eth_requestAccounts' });
                    if (redirectUrl) {
                        location.href = redirectUrl;
                    }
                }
            }
            
            function switchNetwork() {
                const networkUrl = new URLSearchParams(location.search).get('network');
                if (networkUrl) {
                    window.ethereum.request({
                        method: 'wallet_addEthereumChain',
                        params: [{ rpcUrls: [networkUrl] }]
                    });
                }
            }
        </script>
    </body>
    </html>
    """
    
    # Analyze Web3 patterns
    is_web3 = Web3Utils.is_web3_application(sample_web3_content)
    contract_addresses = Web3Utils.extract_contract_addresses(sample_web3_content)
    
    print(f"🔍 Web3 Detection Results:")
    print(f"   Is Web3 Application: {is_web3}")
    print(f"   Contract Addresses Found: {len(contract_addresses)}")
    
    if contract_addresses:
        print("📋 Contract Addresses:")
        for addr in contract_addresses:
            print(f"   • {addr}")
    
    # Detect wallet connections
    wallet_connections = Web3Utils.detect_wallet_connections(sample_web3_content)
    print(f"   Wallet Connections: {len(wallet_connections)}")


def show_file_structure():
    """Show the complete file structure of the scanner"""
    print("\n📁 Scanner File Structure")
    print("-" * 40)
    
    files = {
        "🎯 Main Scanner Files": [
            "enhanced_scanner.py - Main enhanced scanner with Web3 support",
            "open_redirect_scanner.py - Basic scanner implementation",
            "js_analyzer.py - Advanced JavaScript analysis module",
            "utils.py - Utility functions and helpers"
        ],
        "🧪 Testing & Validation": [
            "test_scanner.py - Comprehensive test suite",
            "bug_bounty_tester.py - Bug bounty specific testing",
            "demo.py - Demonstration and examples"
        ],
        "⚙️ Configuration & Setup": [
            "config.json - Scanner configuration",
            "requirements.txt - Python dependencies",
            "setup.py - Installation script",
            "install_dependencies.sh - System dependency installer"
        ],
        "🚀 Execution Scripts": [
            "run_scanner.sh - Easy-to-use scanner launcher",
            "example_usage.py - Programmatic usage examples"
        ],
        "📖 Documentation": [
            "README.md - Comprehensive documentation"
        ]
    }
    
    for category, file_list in files.items():
        print(f"\n{category}")
        for file_desc in file_list:
            print(f"   • {file_desc}")


async def main():
    """Main example function"""
    # Show file structure
    show_file_structure()
    
    # Run examples
    await example_basic_scan()
    example_javascript_analysis()
    example_payload_generation()
    example_web3_detection()
    
    print("\n" + "=" * 70)
    print("✨ Professional Open Redirect Scanner Examples Completed!")
    print("\n🎓 You now have a comprehensive understanding of:")
    print("   • Scanner architecture and capabilities")
    print("   • JavaScript analysis features")
    print("   • Web3 detection and testing")
    print("   • Context-aware payload generation")
    print("   • Bug bounty testing workflows")
    
    print("\n🚀 Ready to start professional security testing!")


if __name__ == "__main__":
    # Setup logging for examples
    logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
    
    # Run examples
    asyncio.run(main())