#!/usr/bin/env python3
"""
Test suite for Professional Open Redirect Scanner
Validates scanner functionality and accuracy
"""

import asyncio
import unittest
from unittest.mock import Mock, patch, AsyncMock
import tempfile
import os
import json
from pathlib import Path

# Import scanner modules
from enhanced_scanner import EnhancedOpenRedirectScanner, EnhancedParameter, EnhancedVulnerability
from js_analyzer import JavaScriptAnalyzer, JSParameter
from utils import URLUtils, PayloadGenerator, SecurityUtils


class TestOpenRedirectScanner(unittest.TestCase):
    """Test cases for Open Redirect Scanner"""
    
    def setUp(self):
        """Set up test environment"""
        self.test_url = "https://example.com"
        self.scanner = EnhancedOpenRedirectScanner(self.test_url, max_depth=2, max_pages=10)
    
    def test_url_normalization(self):
        """Test URL normalization functionality"""
        # Test cases
        test_cases = [
            ("example.com", "https://example.com"),
            ("http://example.com", "http://example.com"),
            ("https://example.com:443", "https://example.com"),
            ("http://example.com:80", "http://example.com"),
        ]
        
        for input_url, expected in test_cases:
            result = URLUtils.normalize_url(input_url)
            self.assertEqual(result, expected, f"Failed for input: {input_url}")
    
    def test_domain_extraction(self):
        """Test domain extraction from URLs"""
        test_cases = [
            ("https://example.com/path", "example.com"),
            ("http://sub.example.com", "sub.example.com"),
            ("https://example.com:8080", "example.com:8080"),
        ]
        
        for input_url, expected in test_cases:
            result = URLUtils.extract_domain(input_url)
            self.assertEqual(result, expected, f"Failed for input: {input_url}")
    
    def test_redirect_parameter_detection(self):
        """Test redirect parameter detection"""
        test_cases = [
            ("redirect", True),
            ("url", True),
            ("next", True),
            ("username", False),
            ("password", False),
            ("returnUrl", True),
        ]
        
        for param_name, expected in test_cases:
            result = self.scanner.is_enhanced_redirect_parameter(param_name)
            self.assertEqual(result, expected, f"Failed for parameter: {param_name}")
    
    def test_payload_generation(self):
        """Test payload generation"""
        generator = PayloadGenerator()
        
        # Test basic payloads
        basic_payloads = generator.generate_basic_payloads("test.com")
        self.assertGreater(len(basic_payloads), 0)
        self.assertIn("//test.com", basic_payloads)
        
        # Test encoded payloads
        encoded_payloads = generator.generate_encoded_payloads("test.com")
        self.assertGreater(len(encoded_payloads), 0)
        
        # Test JavaScript payloads
        js_payloads = generator.generate_javascript_payloads()
        self.assertGreater(len(js_payloads), 0)
        self.assertIn("javascript:confirm(1)", js_payloads)
    
    def test_context_detection(self):
        """Test context detection functionality"""
        test_param = EnhancedParameter(
            name="redirect_url",
            value="https://example.com",
            source="url",
            context="query",
            url="https://test.com",
            confidence=0.8
        )
        
        context = self.scanner.detect_enhanced_context(test_param)
        self.assertEqual(context, "query")
    
    def test_vulnerability_confidence_calculation(self):
        """Test vulnerability confidence calculation"""
        test_param = EnhancedParameter(
            name="redirect",
            value="//evil.com",
            source="url",
            context="query",
            url="https://test.com",
            is_redirect_related=True,
            confidence=0.7
        )
        
        mock_response = Mock()
        mock_response.status = 302
        
        confidence = self.scanner.calculate_vulnerability_confidence(
            test_param, "//google.com", mock_response
        )
        
        self.assertGreater(confidence, 0.7)
        self.assertLessEqual(confidence, 1.0)


class TestJavaScriptAnalyzer(unittest.TestCase):
    """Test cases for JavaScript Analyzer"""
    
    def setUp(self):
        """Set up test environment"""
        self.analyzer = JavaScriptAnalyzer()
    
    def test_parameter_extraction_regex(self):
        """Test regex-based parameter extraction"""
        test_js = """
        var redirectUrl = location.search;
        location.href = redirectUrl;
        function redirect(url) {
            window.location = url;
        }
        """
        
        params = self.analyzer.extract_parameters_regex(test_js, "test.js")
        self.assertGreater(len(params), 0)
        
        # Check for redirect-related parameters
        redirect_params = [p for p in params if p.is_redirect_sink]
        self.assertGreater(len(redirect_params), 0)
    
    def test_dom_sink_detection(self):
        """Test DOM sink detection"""
        test_js = """
        location.href = userInput;
        window.location = getUrlParam('redirect');
        document.location.assign(targetUrl);
        """
        
        sinks = self.analyzer.detect_dom_based_sinks(test_js, "test.js")
        self.assertGreater(len(sinks), 0)
        
        # Verify sink detection
        sink_names = [sink['sink_name'] for sink in sinks]
        self.assertIn('location.href', sink_names)
    
    def test_data_flow_analysis(self):
        """Test data flow analysis"""
        test_js = """
        var userUrl = location.search.substring(1);
        var redirectTarget = decodeURIComponent(userUrl);
        location.href = redirectTarget;
        """
        
        flows = self.analyzer.find_data_flows(test_js, "test.js")
        self.assertGreater(len(flows), 0)
        
        # Check for user-controlled flow
        user_flows = [f for f in flows if f['risk_level'] == 'HIGH']
        self.assertGreater(len(user_flows), 0)


class TestIntegration(unittest.TestCase):
    """Integration tests for complete scanner functionality"""
    
    @patch('aiohttp.ClientSession.get')
    async def test_basic_scan_flow(self, mock_get):
        """Test basic scanning flow"""
        # Mock HTTP response
        mock_response = AsyncMock()
        mock_response.text = AsyncMock(return_value="""
        <html>
        <body>
            <a href="/redirect?url=example.com">Link</a>
            <form action="/submit">
                <input name="redirect_url" value="">
                <input type="submit" value="Submit">
            </form>
            <script>
                var targetUrl = location.search;
                if (targetUrl) {
                    location.href = targetUrl;
                }
            </script>
        </body>
        </html>
        """)
        mock_response.status = 200
        mock_response.headers = {}
        mock_get.return_value.__aenter__.return_value = mock_response
        
        # Create scanner and run limited test
        scanner = EnhancedOpenRedirectScanner("https://example.com", max_depth=1, max_pages=5)
        
        # Mock session initialization
        scanner.session = Mock()
        scanner.session.get = mock_get
        
        # Test parameter extraction
        await scanner.enhanced_crawl_website()
        
        # Verify parameters were extracted
        self.assertGreater(len(scanner.parameters), 0)
        
        # Check for redirect-related parameters
        redirect_params = [p for p in scanner.parameters if p.is_redirect_related]
        self.assertGreater(len(redirect_params), 0)


class TestSecurityValidation(unittest.TestCase):
    """Test security validation and safety measures"""
    
    def test_safe_url_validation(self):
        """Test URL safety validation"""
        allowed_domains = ["example.com", "test.com"]
        
        test_cases = [
            ("https://example.com", True),
            ("https://sub.example.com", True),
            ("https://evil.com", False),
            ("javascript:alert(1)", False),
            ("data:text/html,<script>alert(1)</script>", False),
        ]
        
        for url, expected in test_cases:
            result = SecurityUtils.is_safe_url(url, allowed_domains)
            self.assertEqual(result, expected, f"Failed for URL: {url}")
    
    def test_bypass_technique_detection(self):
        """Test bypass technique detection"""
        test_cases = [
            ("//evil.com", ["protocol_relative"]),
            ("////evil.com", ["multiple_slashes"]),
            ("%2f%2fevil.com", ["url_encoding"]),
            ("\\evil.com", ["backslash_bypass"]),
            ("http://127.0.0.1", ["ip_address"]),
            ("javascript:alert(1)", ["javascript_protocol"]),
        ]
        
        for url, expected_techniques in test_cases:
            detected = SecurityUtils.detect_bypass_techniques(url)
            for technique in expected_techniques:
                self.assertIn(technique, detected, f"Failed to detect {technique} in {url}")


def create_test_html_file():
    """Create test HTML file for manual testing"""
    test_html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Open Redirect Test Page</title>
    </head>
    <body>
        <h1>Open Redirect Test Cases</h1>
        
        <!-- URL parameter redirect -->
        <a href="/redirect?url=https://google.com">URL Parameter Test</a><br>
        
        <!-- Form-based redirect -->
        <form action="/submit" method="POST">
            <input name="return_url" placeholder="Return URL">
            <input type="submit" value="Submit">
        </form>
        
        <!-- JavaScript-based redirect -->
        <button onclick="redirectUser()">JS Redirect</button>
        
        <!-- Web3 wallet connection -->
        <button onclick="connectWallet()">Connect Wallet</button>
        
        <script>
            function redirectUser() {
                var target = new URLSearchParams(location.search).get('target');
                if (target) {
                    location.href = target;
                }
            }
            
            function connectWallet() {
                var walletUrl = localStorage.getItem('wallet_redirect');
                if (walletUrl) {
                    window.open(walletUrl);
                }
            }
            
            // DOM-based redirect vulnerability
            if (location.hash) {
                var redirectTo = location.hash.substring(1);
                if (redirectTo.startsWith('redirect=')) {
                    location.href = redirectTo.substring(9);
                }
            }
        </script>
    </body>
    </html>
    """
    
    with open('/workspace/test_page.html', 'w') as f:
        f.write(test_html)


def run_all_tests():
    """Run all test suites"""
    print("🧪 Running Professional Open Redirect Scanner Tests")
    print("=" * 60)
    
    # Create test HTML file
    create_test_html_file()
    
    # Discover and run tests
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromModule(sys.modules[__name__])
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Print summary
    print("\n" + "=" * 60)
    if result.wasSuccessful():
        print("✅ All tests passed successfully!")
    else:
        print(f"❌ {len(result.failures)} test(s) failed")
        print(f"❌ {len(result.errors)} test(s) had errors")
    
    return result.wasSuccessful()


if __name__ == "__main__":
    import sys
    success = run_all_tests()
    sys.exit(0 if success else 1)