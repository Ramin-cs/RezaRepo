#!/usr/bin/env python3
"""
Quick test script for Open Redirect Scanner
Tests basic functionality without full Chrome automation
"""

import asyncio
import sys
from pathlib import Path

# Add current directory to Python path
sys.path.insert(0, str(Path(__file__).parent))

def test_imports():
    """Test that all modules can be imported"""
    print("🧪 Testing imports...")
    
    try:
        from open_redirect_scanner import OpenRedirectScanner
        print("✅ OpenRedirectScanner imported successfully")
        
        from recon_module import ReconModule
        print("✅ ReconModule imported successfully")
        
        from payload_module import PayloadModule
        print("✅ PayloadModule imported successfully")
        
        from chrome_module import ChromeModule
        print("✅ ChromeModule imported successfully")
        
        from report_module import ReportModule
        print("✅ ReportModule imported successfully")
        
        from logging_module import LoggingModule
        print("✅ LoggingModule imported successfully")
        
        from configuration import ConfigManager, ScannerConfig
        print("✅ Configuration modules imported successfully")
        
        return True
        
    except ImportError as e:
        print(f"❌ Import error: {str(e)}")
        return False

def test_basic_functionality():
    """Test basic functionality without Chrome"""
    print("\n🧪 Testing basic functionality...")
    
    try:
        # Test configuration
        from configuration import ScannerConfig, ConfigManager
        
        config = ScannerConfig()
        config.target_url = "https://httpbin.org"
        config.output_dir = "test_output"
        config.max_threads = 2
        
        print("✅ Configuration created successfully")
        
        # Test logging
        from logging_module import LoggingModule
        
        logger = LoggingModule(Path("test_output"))
        logger.info("Test log message")
        
        print("✅ Logging module works")
        
        # Test recon module
        from recon_module import ReconModule
        
        recon = ReconModule(logger)
        test_url = "https://httpbin.org?url=test&redirect=test2"
        params = recon._extract_url_parameters(test_url)
        
        print(f"✅ Recon module extracted {len(params)} parameters")
        
        # Test payload module
        from payload_module import PayloadModule
        
        payloads = PayloadModule(logger)
        test_payload = "//google.com"
        generated = payloads.generate_payloads(test_payload)
        
        print(f"✅ Payload module generated {len(generated)} payloads")
        
        # Test report module
        from report_module import ReportModule
        
        report = ReportModule(Path("test_output"))
        test_vuln = {
            'url': 'https://example.com',
            'parameter': 'redirect',
            'payload': '//google.com',
            'redirect_url': 'https://google.com',
            'injection_type': 'url',
            'timestamp': '2024-01-01T00:00:00'
        }
        
        severity = report._determine_severity(test_vuln)
        print(f"✅ Report module determined severity: {severity}")
        
        return True
        
    except Exception as e:
        print(f"❌ Functionality test error: {str(e)}")
        return False

def test_scanner_creation():
    """Test scanner creation"""
    print("\n🧪 Testing scanner creation...")
    
    try:
        from open_redirect_scanner import OpenRedirectScanner
        
        scanner = OpenRedirectScanner(
            target_url="https://httpbin.org",
            output_dir="test_output",
            max_threads=2
        )
        
        print("✅ Scanner created successfully")
        print(f"   Target: {scanner.target_url}")
        print(f"   Output: {scanner.output_dir}")
        print(f"   Threads: {scanner.max_threads}")
        print(f"   Custom payloads: {len(scanner.custom_payloads)}")
        
        return True
        
    except Exception as e:
        print(f"❌ Scanner creation error: {str(e)}")
        return False

def test_payload_generation():
    """Test payload generation"""
    print("\n🧪 Testing payload generation...")
    
    try:
        from payload_module import PayloadModule
        from logging_module import LoggingModule
        
        logger = LoggingModule(Path("test_output"))
        payloads = PayloadModule(logger)
        
        test_payloads = [
            "//google.com",
            "https://google.com",
            "javascript:alert(1)",
            "data:text/html,<script>alert(1)</script>"
        ]
        
        total_generated = 0
        for payload in test_payloads:
            generated = payloads.generate_payloads(payload)
            total_generated += len(generated)
            print(f"   {payload} -> {len(generated)} variations")
        
        print(f"✅ Generated {total_generated} total payload variations")
        
        return True
        
    except Exception as e:
        print(f"❌ Payload generation error: {str(e)}")
        return False

def test_url_parameter_extraction():
    """Test URL parameter extraction"""
    print("\n🧪 Testing URL parameter extraction...")
    
    try:
        from recon_module import ReconModule
        from logging_module import LoggingModule
        
        logger = LoggingModule(Path("test_output"))
        recon = ReconModule(logger)
        
        test_urls = [
            "https://example.com?url=test&redirect=test2&other=value",
            "https://example.com?next=test&return=test2",
            "https://example.com?goto=test&target=test2",
            "https://example.com?callback=test&returnUrl=test2"
        ]
        
        total_params = 0
        for url in test_urls:
            params = recon._extract_url_parameters(url)
            total_params += len(params)
            print(f"   {url} -> {len(params)} parameters")
        
        print(f"✅ Extracted {total_params} total parameters")
        
        return True
        
    except Exception as e:
        print(f"❌ URL parameter extraction error: {str(e)}")
        return False

def cleanup_test_files():
    """Clean up test files"""
    print("\n🧹 Cleaning up test files...")
    
    try:
        import shutil
        
        test_dirs = [
            "test_output",
            "scan_results",
            "test_results",
            "example_results",
            "advanced_results",
            "custom_results",
            "multi_target_results_1",
            "multi_target_results_2",
            "multi_target_results_3",
            "error_handling_results",
            "perf_test_output"
        ]
        
        for dir_name in test_dirs:
            if Path(dir_name).exists():
                shutil.rmtree(dir_name)
                print(f"   Removed {dir_name}/")
        
        print("✅ Cleanup completed")
        
    except Exception as e:
        print(f"⚠️ Cleanup error: {str(e)}")

def main():
    """Main test function"""
    print("🚀 Open Redirect Scanner - Quick Test")
    print("=" * 50)
    
    # Run tests
    tests = [
        ("Import Test", test_imports),
        ("Basic Functionality", test_basic_functionality),
        ("Scanner Creation", test_scanner_creation),
        ("Payload Generation", test_payload_generation),
        ("URL Parameter Extraction", test_url_parameter_extraction)
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        print(f"\n🔍 Running {test_name}...")
        try:
            if test_func():
                passed += 1
                print(f"✅ {test_name} passed")
            else:
                print(f"❌ {test_name} failed")
        except Exception as e:
            print(f"❌ {test_name} failed with exception: {str(e)}")
    
    # Print summary
    print("\n" + "=" * 50)
    print(f"📊 Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed! The scanner is ready to use.")
        print("\nTo run a real scan:")
        print("  python main.py https://target-website.com")
        print("  ./run.sh https://target-website.com")
    else:
        print("⚠️ Some tests failed. Please check the errors above.")
    
    # Cleanup
    cleanup_test_files()
    
    return passed == total

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)