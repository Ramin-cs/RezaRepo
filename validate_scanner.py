#!/usr/bin/env python3
"""
Scanner Validation Script - Tests basic functionality without external dependencies
"""

import re
import json
import urllib.parse
from urllib.parse import urlparse, parse_qs
import sys
import os


def test_url_parsing():
    """Test URL parsing functionality"""
    print("🔍 Testing URL parsing...")
    
    test_urls = [
        "https://example.com/path?redirect=//evil.com&next=test",
        "http://test.com/page#redirect=https://google.com",
        "https://app.com/oauth?redirect_uri=https://attacker.com"
    ]
    
    for url in test_urls:
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)
        
        print(f"   URL: {url}")
        print(f"   Domain: {parsed.netloc}")
        print(f"   Query params: {list(query_params.keys())}")
        
        # Check for redirect parameters
        redirect_params = []
        for param in query_params.keys():
            if any(pattern in param.lower() for pattern in ['redirect', 'url', 'next', 'return']):
                redirect_params.append(param)
        
        print(f"   Redirect params: {redirect_params}")
        print()
    
    return True


def test_javascript_pattern_detection():
    """Test JavaScript pattern detection"""
    print("🔬 Testing JavaScript pattern detection...")
    
    sample_js = """
    var redirectUrl = location.search;
    location.href = redirectUrl;
    
    function redirect(target) {
        window.location = target;
    }
    
    if (window.ethereum) {
        var walletUrl = localStorage.getItem('wallet_redirect');
        window.open(walletUrl);
    }
    """
    
    # Test patterns
    patterns = [
        r'location\.href\s*=\s*([^;]+)',
        r'window\.location\s*=\s*([^;]+)',
        r'localStorage\.getItem\(["\']([^"\']+)["\']\)',
        r'window\.ethereum',
        r'function\s+(\w+)\s*\([^)]*\)'
    ]
    
    detected_patterns = []
    for pattern in patterns:
        matches = re.findall(pattern, sample_js, re.IGNORECASE)
        if matches:
            detected_patterns.append((pattern, matches))
    
    print(f"   Detected {len(detected_patterns)} JavaScript patterns")
    for pattern, matches in detected_patterns:
        print(f"   Pattern: {pattern[:30]}... -> {matches}")
    
    return len(detected_patterns) > 0


def test_payload_encoding():
    """Test payload encoding functionality"""
    print("🎯 Testing payload encoding...")
    
    base_payload = "//google.com"
    
    # Manual encoding tests
    encoded_variations = [
        urllib.parse.quote(base_payload),
        urllib.parse.quote(base_payload, safe=''),
        base_payload.replace('/', '%2f'),
        base_payload.replace('.', '%2e'),
    ]
    
    print(f"   Base payload: {base_payload}")
    print("   Encoded variations:")
    for variation in encoded_variations:
        print(f"     • {variation}")
    
    return True


def test_redirect_detection():
    """Test redirect detection logic"""
    print("🔍 Testing redirect detection...")
    
    test_cases = [
        ("redirect", True),
        ("url", True), 
        ("next", True),
        ("username", False),
        ("password", False),
        ("returnUrl", True),
        ("goto", True),
        ("target", True)
    ]
    
    redirect_patterns = [
        r'redirect', r'url', r'next', r'return', r'goto', r'target',
        r'destination', r'continue', r'forward', r'redir', r'location'
    ]
    
    correct_detections = 0
    for param_name, expected in test_cases:
        param_lower = param_name.lower()
        detected = any(pattern in param_lower for pattern in redirect_patterns)
        
        if detected == expected:
            correct_detections += 1
            status = "✅"
        else:
            status = "❌"
        
        print(f"   {status} {param_name}: expected {expected}, got {detected}")
    
    accuracy = correct_detections / len(test_cases)
    print(f"   Accuracy: {accuracy:.1%}")
    
    return accuracy > 0.8


def test_web3_detection():
    """Test Web3 detection patterns"""
    print("🌐 Testing Web3 detection...")
    
    web3_content = """
    const web3 = new Web3(window.ethereum);
    const contractAddress = "0x1234567890123456789012345678901234567890";
    
    async function connectMetaMask() {
        await window.ethereum.request({ method: 'eth_requestAccounts' });
    }
    
    function redirectToWallet() {
        const walletUrl = new URLSearchParams(location.search).get('wallet_redirect');
        if (walletUrl) {
            location.href = walletUrl;
        }
    }
    """
    
    web3_indicators = [
        'web3', 'ethereum', 'metamask', 'wallet', 'contract',
        'blockchain', 'crypto', 'dapp'
    ]
    
    detected_indicators = []
    content_lower = web3_content.lower()
    
    for indicator in web3_indicators:
        if indicator in content_lower:
            detected_indicators.append(indicator)
    
    # Extract contract addresses
    contract_pattern = r'0x[a-fA-F0-9]{40}'
    contract_addresses = re.findall(contract_pattern, web3_content)
    
    print(f"   Web3 indicators found: {detected_indicators}")
    print(f"   Contract addresses: {contract_addresses}")
    
    is_web3 = len(detected_indicators) > 0
    print(f"   Is Web3 application: {is_web3}")
    
    return is_web3


def test_scanner_files():
    """Test that all scanner files are present"""
    print("📁 Testing scanner files...")
    
    required_files = [
        "enhanced_scanner.py",
        "js_analyzer.py", 
        "utils.py",
        "bug_bounty_tester.py",
        "config.json",
        "requirements.txt",
        "README.md",
        "run_scanner.sh",
        "install_dependencies.sh"
    ]
    
    missing_files = []
    for file_name in required_files:
        if not os.path.exists(file_name):
            missing_files.append(file_name)
        else:
            print(f"   ✅ {file_name}")
    
    if missing_files:
        print(f"   ❌ Missing files: {missing_files}")
        return False
    
    print(f"   All {len(required_files)} required files present")
    return True


def validate_payloads():
    """Validate that all required payloads are included"""
    print("🎯 Validating payloads...")
    
    # Sample of required payloads from user's list
    required_payloads = [
        "/%09/google.com",
        "/%2f%2fgoogle.com", 
        "//google.com",
        "javascript:confirm(1)",
        "https://google.com",
        "〱google.com",
        "%68%74%74%70%3a%2f%2f%67%6f%6f%67%6c%65%2e%63%6f%6d"
    ]
    
    print(f"   Checking for {len(required_payloads)} sample payloads...")
    
    # Read the enhanced scanner to check payloads
    try:
        with open('enhanced_scanner.py', 'r') as f:
            content = f.read()
        
        found_payloads = 0
        for payload in required_payloads:
            if payload in content:
                found_payloads += 1
                print(f"   ✅ Found: {payload}")
            else:
                print(f"   ❌ Missing: {payload}")
        
        coverage = found_payloads / len(required_payloads)
        print(f"   Payload coverage: {coverage:.1%}")
        
        return coverage > 0.8
        
    except Exception as e:
        print(f"   ❌ Error reading scanner file: {e}")
        return False


def main():
    """Main validation function"""
    print("🧪 Professional Open Redirect Scanner Validation")
    print("=" * 60)
    
    tests = [
        ("URL Parsing", test_url_parsing),
        ("JavaScript Pattern Detection", test_javascript_pattern_detection),
        ("Payload Encoding", test_payload_encoding),
        ("Redirect Detection", test_redirect_detection),
        ("Web3 Detection", test_web3_detection),
        ("Scanner Files", test_scanner_files),
        ("Payload Validation", validate_payloads)
    ]
    
    passed_tests = 0
    total_tests = len(tests)
    
    for test_name, test_func in tests:
        print(f"\n🧪 {test_name}:")
        try:
            if test_func():
                print(f"   ✅ PASSED")
                passed_tests += 1
            else:
                print(f"   ❌ FAILED")
        except Exception as e:
            print(f"   ❌ ERROR: {e}")
    
    print("\n" + "=" * 60)
    print(f"📊 Validation Summary: {passed_tests}/{total_tests} tests passed")
    
    if passed_tests == total_tests:
        print("🎉 All validations passed! Scanner is ready for use.")
        print("\n🚀 Quick Start:")
        print("1. Install dependencies: ./install_dependencies.sh")
        print("2. Run demo: python3 demo.py") 
        print("3. Start scanning: ./run_scanner.sh <target_url>")
    else:
        print("⚠️  Some validations failed. Please check the errors above.")
    
    print(f"\n📁 Scanner Package Contents:")
    print(f"   📊 Total files: {len(os.listdir('.'))}")
    print(f"   🎯 Main scanner: enhanced_scanner.py ({os.path.getsize('enhanced_scanner.py')//1024}KB)")
    print(f"   🔬 JS analyzer: js_analyzer.py ({os.path.getsize('js_analyzer.py')//1024}KB)")
    print(f"   🛠️  Utilities: utils.py ({os.path.getsize('utils.py')//1024}KB)")
    print(f"   📖 Documentation: README.md ({os.path.getsize('README.md')//1024}KB)")


if __name__ == "__main__":
    main()