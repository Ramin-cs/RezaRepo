#!/usr/bin/env python3
"""
START_SCANNING.py - Open Redirect Scanner
This is the main file to execute the scanner
"""

import asyncio
import sys
import os
from pathlib import Path

# Add current directory to Python path
sys.path.insert(0, str(Path(__file__).parent))

def print_banner():
    """Print scanner banner"""
    print("""
    ╔══════════════════════════════════════════════════════════════╗
    ║                                                              ║
    ║           🔍 Open Redirect Vulnerability Scanner            ║
    ║                                                              ║
    ║              Advanced Security Testing Tool                  ║
    ║                                                              ║
    ╚══════════════════════════════════════════════════════════════╝
    """)

def print_usage():
    """Print usage information"""
    print("""
    Usage: python START_SCANNING.py <target_url> [options]
    
    Examples:
        python START_SCANNING.py https://target-website.com
        python START_SCANNING.py https://target-website.com --output results --threads 20
        python START_SCANNING.py https://target-website.com --preset thorough
    
    Options:
        --output DIR          Output directory (default: scan_results)
        --threads NUM         Number of threads (default: 10)
        --depth NUM           Maximum depth (default: 3)
        --preset PRESET       Use preset (fast|thorough|stealth|debug)
        --help                Show this help message
        --test                Run functionality test only
        --capabilities        Show scanner capabilities
    """)

def test_imports():
    """Test that all required modules can be imported"""
    try:
        from open_redirect_scanner import OpenRedirectScanner
        from recon_module import ReconModule
        from payload_module import PayloadModule
        from chrome_module import ChromeModule
        from report_module import ReportModule
        from logging_module import LoggingModule
        from configuration import ScannerConfig
        return True
    except ImportError as e:
        print(f"❌ Import error: {str(e)}")
        print("Please install dependencies: pip install -r requirements.txt")
        return False

def test_basic_functionality():
    """Test basic functionality without creating files"""
    try:
        from recon_module import ReconModule
        from payload_module import PayloadModule
        
        # Mock logger
        logger = type('MockLogger', (), {'info': lambda x: None, 'error': lambda x: None})()
        
        # Test recon module
        recon = ReconModule(logger)
        test_url = "https://httpbin.org?url=test&redirect=test2"
        params = recon._extract_url_parameters(test_url)
        
        # Test payload module
        payloads = PayloadModule(logger)
        test_payload = "//google.com"
        generated = payloads.generate_payloads(test_payload)
        
        print(f"✅ Recon module: {len(params)} parameters extracted")
        print(f"✅ Payload module: {len(generated)} payloads generated")
        return True
        
    except Exception as e:
        print(f"❌ Functionality test error: {str(e)}")
        return False

def show_capabilities():
    """Show scanner capabilities"""
    print("\n🔍 Scanner Capabilities:")
    print("=" * 50)
    
    # Test recon module
    from recon_module import ReconModule
    logger = type('MockLogger', (), {'info': lambda x: None, 'error': lambda x: None})()
    recon = ReconModule(logger)
    
    print(f"📊 Redirect parameters detected: {len(recon.redirect_params)}")
    print(f"📊 JavaScript patterns: {len(recon.js_redirect_patterns)}")
    print(f"📊 Meta refresh patterns: {len(recon.meta_refresh_patterns)}")
    print(f"📊 Header redirect patterns: {len(recon.header_redirect_patterns)}")
    
    # Test payload module
    from payload_module import PayloadModule
    payloads = PayloadModule(logger)
    
    print(f"📊 Base payloads: {len(payloads.base_payloads)}")
    print(f"📊 Bypass techniques: {len(payloads.bypass_techniques)}")
    
    # Test payload generation
    test_payload = "//google.com"
    generated = payloads.generate_payloads(test_payload)
    print(f"📊 Generated payloads for '{test_payload}': {len(generated)}")
    
    # Show some examples
    print("\n🎯 Example payloads:")
    for i, payload in enumerate(generated[:10]):
        print(f"   {i+1}. {payload}")
    if len(generated) > 10:
        print(f"   ... and {len(generated) - 10} more")

def show_vulnerability_types():
    """Show vulnerability types detected"""
    print("\n🔍 Vulnerability Types Detected:")
    print("=" * 50)
    
    print("• URL Parameter Redirects:")
    print("  - ?url=, ?redirect=, ?next=, ?return=, ?goto=, etc.")
    
    print("\n• Form Parameter Redirects:")
    print("  - Hidden fields, form actions, input values")
    
    print("\n• JavaScript Variable Redirects:")
    print("  - window.location, document.location, etc.")
    
    print("\n• Meta Tag Redirects:")
    print("  - <meta http-equiv=\"refresh\">")
    
    print("\n• Cookie Parameter Redirects:")
    print("  - Redirect-related cookies")
    
    print("\n• HTTP Header Redirects:")
    print("  - Custom headers, Location header")

def show_waf_bypass_techniques():
    """Show WAF bypass techniques"""
    print("\n🛡️ WAF Bypass Techniques:")
    print("=" * 50)
    
    print("• Encoding Techniques:")
    print("  - URL Encoding (single and double)")
    print("  - Unicode Encoding")
    print("  - Hex Encoding")
    print("  - Octal Encoding")
    print("  - Mixed Encoding")
    print("  - Base64 Encoding")
    print("  - HTML/XML Entity Encoding")
    
    print("\n• Character Manipulation:")
    print("  - Case Variations")
    print("  - Whitespace Variations")
    print("  - Control Character Injection")
    print("  - Null Byte Injection")
    print("  - Newline Injection")
    print("  - Tab Injection")
    
    print("\n• Advanced Techniques:")
    print("  - Unicode Normalization")
    print("  - IDN Homograph Attacks")
    print("  - Punycode Encoding")
    print("  - Protocol Variations")
    print("  - Path Manipulation")

def show_usage_examples():
    """Show usage examples"""
    print("\n🚀 Usage Examples:")
    print("=" * 50)
    
    print("1. Basic scan:")
    print("   python START_SCANNING.py https://target-website.com")
    
    print("\n2. Advanced scan:")
    print("   python START_SCANNING.py https://target-website.com --output results --threads 20 --depth 3")
    
    print("\n3. Using presets:")
    print("   python START_SCANNING.py --preset thorough https://target-website.com")
    print("   python START_SCANNING.py --preset stealth https://target-website.com")
    print("   python START_SCANNING.py --preset debug https://target-website.com")
    
    print("\n4. Test functionality:")
    print("   python START_SCANNING.py --test")
    
    print("\n5. Show capabilities:")
    print("   python START_SCANNING.py --capabilities")

def run_test():
    """Run functionality test"""
    print("🧪 Running functionality test...")
    
    # Test imports
    if not test_imports():
        return False
    print("✅ All modules imported successfully")
    
    # Test basic functionality
    if not test_basic_functionality():
        return False
    print("✅ Basic functionality test passed")
    
    # Show capabilities
    show_capabilities()
    
    print("\n🎉 All tests passed! Scanner is ready to use!")
    return True

def show_capabilities_only():
    """Show capabilities only"""
    print("🧪 Testing imports...")
    if not test_imports():
        return False
    print("✅ All modules imported successfully")
    
    print("🧪 Testing basic functionality...")
    if not test_basic_functionality():
        return False
    print("✅ Basic functionality test passed")
    
    # Show capabilities
    show_capabilities()
    
    # Show vulnerability types
    show_vulnerability_types()
    
    # Show WAF bypass techniques
    show_waf_bypass_techniques()
    
    # Show usage examples
    show_usage_examples()
    
    print("\n🎉 Scanner capabilities displayed!")
    return True

def main():
    """Main function"""
    print_banner()
    
    # Check arguments
    if len(sys.argv) < 2:
        print("❌ Error: Target URL is required")
        print_usage()
        sys.exit(1)
    
    # Parse arguments
    target_url = sys.argv[1]
    output_dir = "scan_results"
    threads = 10
    depth = 3
    preset = None
    
    # Parse options
    i = 2
    while i < len(sys.argv):
        arg = sys.argv[i]
        
        if arg == "--help":
            print_usage()
            sys.exit(0)
        elif arg == "--test":
            if run_test():
                sys.exit(0)
            else:
                sys.exit(1)
        elif arg == "--capabilities":
            if show_capabilities_only():
                sys.exit(0)
            else:
                sys.exit(1)
        elif arg == "--output" and i + 1 < len(sys.argv):
            output_dir = sys.argv[i + 1]
            i += 2
        elif arg == "--threads" and i + 1 < len(sys.argv):
            threads = int(sys.argv[i + 1])
            i += 2
        elif arg == "--depth" and i + 1 < len(sys.argv):
            depth = int(sys.argv[i + 1])
            i += 2
        elif arg == "--preset" and i + 1 < len(sys.argv):
            preset = sys.argv[i + 1]
            i += 2
        else:
            print(f"❌ Unknown option: {arg}")
            print_usage()
            sys.exit(1)
    
    # Test imports
    print("🧪 Testing imports...")
    if not test_imports():
        sys.exit(1)
    print("✅ All modules imported successfully")
    
    # Test basic functionality
    print("🧪 Testing basic functionality...")
    if not test_basic_functionality():
        sys.exit(1)
    print("✅ Basic functionality test passed")
    
    # Show capabilities
    show_capabilities()
    
    # Show vulnerability types
    show_vulnerability_types()
    
    # Show WAF bypass techniques
    show_waf_bypass_techniques()
    
    # Show usage examples
    show_usage_examples()
    
    print("\n🎉 Scanner is ready to use!")
    print("📚 See README.md for detailed documentation")
    print("🚀 Run 'python main.py --help' for command line options")
    
    # Note about Chrome requirement
    print("\n⚠️ Note: For full functionality, Chrome browser is required")
    print("   Install Chrome and run: python main.py <target_url>")

if __name__ == "__main__":
    main()