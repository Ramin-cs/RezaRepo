#!/usr/bin/env python3
"""
Test suite for Advanced XSS Scanner
This script tests the functionality of various components
"""

import unittest
import sys
import os
import time
from unittest.mock import Mock, patch, MagicMock

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from xss_scanner import XSSPayloads, ReconnaissanceEngine
from waf_bypass import WAFBypassEngine
from custom_popup import CustomPopupSystem

class TestXSSPayloads(unittest.TestCase):
    """Test XSS payload generation"""
    
    def setUp(self):
        self.payload_gen = XSSPayloads()
    
    def test_basic_payloads(self):
        """Test basic payload generation"""
        self.assertGreater(len(self.payload_gen.payloads['basic']), 0)
        
        # Check that basic payloads contain expected elements
        basic_payloads = self.payload_gen.payloads['basic']
        self.assertTrue(any('<script>' in payload for payload in basic_payloads))
        self.assertTrue(any('alert(' in payload for payload in basic_payloads))
    
    def test_context_specific_payloads(self):
        """Test context-specific payload generation"""
        contexts = ['html', 'attribute', 'javascript', 'css', 'url']
        
        for context in contexts:
            payloads = self.payload_gen.get_payloads_by_context(context)
            self.assertGreater(len(payloads), 0)
    
    def test_payload_encoding(self):
        """Test payload encoding functionality"""
        test_payload = '<script>alert("test")</script>'
        
        # Test URL encoding
        url_encoded = self.payload_gen.encode_payload(test_payload, 'url')
        self.assertNotEqual(test_payload, url_encoded)
        
        # Test HTML entities encoding
        html_encoded = self.payload_gen.encode_payload(test_payload, 'html_entities')
        self.assertNotEqual(test_payload, html_encoded)
        
        # Test that encoding is reversible for some types
        # (This is a basic test - in reality, some encodings may not be perfectly reversible)
    
    def test_payload_variants(self):
        """Test payload variant generation"""
        test_payload = '<script>alert("test")</script>'
        variants = self.payload_gen.generate_variants(test_payload)
        
        self.assertGreater(len(variants), 1)  # Should have at least original + encoded variants
        self.assertIn(test_payload, variants)  # Original should be included

class TestWAFBypass(unittest.TestCase):
    """Test WAF bypass functionality"""
    
    def setUp(self):
        self.waf_engine = WAFBypassEngine()
    
    def test_waf_signatures(self):
        """Test WAF signature detection"""
        self.assertIn('cloudflare', self.waf_engine.waf_signatures)
        self.assertIn('incapsula', self.waf_engine.waf_signatures)
        self.assertIn('akamai', self.waf_engine.waf_signatures)
        
        # Check that each WAF has required fields
        for waf_name, config in self.waf_engine.waf_signatures.items():
            self.assertIn('headers', config)
            self.assertIn('indicators', config)
            self.assertIn('bypass_methods', config)
    
    def test_bypass_techniques(self):
        """Test bypass technique generation"""
        test_payload = '<script>alert("test")</script>'
        
        # Test encoding bypass
        encoding_variants = self.waf_engine._encoding_bypass(test_payload)
        self.assertGreater(len(encoding_variants), 1)
        
        # Test case variation bypass
        case_variants = self.waf_engine._case_variation(test_payload)
        self.assertGreater(len(case_variants), 1)
        
        # Test comment injection bypass
        comment_variants = self.waf_engine._comment_injection(test_payload)
        self.assertGreater(len(comment_variants), 1)
    
    def test_bypass_payload_generation(self):
        """Test bypass payload generation"""
        test_payload = '<script>alert("test")</script>'
        waf_info = {
            'detected': True,
            'type': 'cloudflare',
            'bypass_methods': ['encoding', 'case_variation']
        }
        
        bypass_payloads = self.waf_engine.generate_bypass_payloads(test_payload, waf_info)
        self.assertGreater(len(bypass_payloads), 1)
        self.assertIn(test_payload, bypass_payloads)  # Original should be included
    
    def test_advanced_bypass_payloads(self):
        """Test advanced bypass payload generation"""
        test_payload = '<script>alert("test")</script>'
        advanced_payloads = self.waf_engine.generate_advanced_bypass_payloads(test_payload)
        
        self.assertGreater(len(advanced_payloads), 1)
        self.assertIn(test_payload, advanced_payloads)

class TestCustomPopup(unittest.TestCase):
    """Test custom popup system"""
    
    def setUp(self):
        self.popup_system = CustomPopupSystem()
    
    def test_popup_initialization(self):
        """Test popup system initialization"""
        self.assertIsNotNone(self.popup_system.popup_id)
        self.assertIsNotNone(self.popup_system.popup_style)
        self.assertIsNotNone(self.popup_system.popup_script)
        
        # Check that popup ID is unique
        self.assertIn('xss_verification_', self.popup_system.popup_id)
    
    def test_popup_style_generation(self):
        """Test popup style generation"""
        style = self.popup_system.popup_style
        
        # Check that style contains expected CSS classes
        self.assertIn('xss-popup-container', style)
        self.assertIn('xss-popup-title', style)
        self.assertIn('xss-popup-content', style)
        self.assertIn('position: fixed', style)
    
    def test_popup_script_generation(self):
        """Test popup script generation"""
        script = self.popup_system.popup_script
        
        # Check that script contains expected elements
        self.assertIn('xss-popup-', script)
        self.assertIn('window.location', script)
        self.assertIn('document.title', script)
        self.assertIn('navigator.userAgent', script)
    
    def test_popup_payload_generation(self):
        """Test popup payload generation"""
        payloads = self.popup_system.generate_popup_payload()
        
        self.assertGreater(len(payloads), 0)
        
        # Check that payloads contain popup script
        for payload in payloads:
            self.assertIn('<script>', payload)
    
    def test_stealth_payload_generation(self):
        """Test stealth payload generation"""
        base_payload = '<script>alert("test")</script>'
        stealth_payloads = self.popup_system.generate_stealth_payload(base_payload)
        
        self.assertGreater(len(stealth_payloads), 0)
        
        # Check that stealth payloads contain time delays or conditions
        has_timeout = any('setTimeout' in payload for payload in stealth_payloads)
        has_condition = any('if(' in payload for payload in stealth_payloads)
        
        self.assertTrue(has_timeout or has_condition)

class TestReconnaissance(unittest.TestCase):
    """Test reconnaissance functionality"""
    
    def setUp(self):
        self.recon = ReconnaissanceEngine()
    
    def test_parameter_discovery(self):
        """Test parameter discovery"""
        test_url = "https://example.com/search?q=test&page=1"
        params = self.recon.discover_parameters(test_url)
        
        # Should discover existing parameters
        self.assertIn('q', params)
        self.assertIn('page', params)
        
        # Should also include common parameters
        self.assertIn('id', params)
        self.assertIn('user', params)
    
    def test_form_discovery(self):
        """Test form discovery"""
        html_content = """
        <html>
        <body>
            <form action="/submit" method="POST">
                <input type="text" name="username" value="test">
                <input type="password" name="password">
                <textarea name="comment"></textarea>
                <input type="submit" value="Submit">
            </form>
        </body>
        </html>
        """
        
        base_url = "https://example.com"
        forms = self.recon.discover_forms(html_content, base_url)
        
        self.assertEqual(len(forms), 1)
        form = forms[0]
        
        self.assertEqual(form['action'], 'https://example.com/submit')
        self.assertEqual(form['method'], 'POST')
        self.assertEqual(len(form['inputs']), 4)
        
        # Check input fields
        input_names = [inp['name'] for inp in form['inputs']]
        self.assertIn('username', input_names)
        self.assertIn('password', input_names)
        self.assertIn('comment', input_names)
    
    def test_response_analysis(self):
        """Test response analysis"""
        # Mock response object
        mock_response = Mock()
        mock_response.text = '<div>Hello <span>World</span>!</div>'
        mock_response.headers = {'Content-Type': 'text/html'}
        mock_response.status_code = 200
        
        analysis = self.recon.analyze_response(mock_response)
        
        self.assertIn('reflection_points', analysis)
        self.assertIn('context_info', analysis)
        self.assertIn('headers', analysis)
        self.assertEqual(analysis['status_code'], 200)

class TestIntegration(unittest.TestCase):
    """Integration tests"""
    
    def test_scanner_initialization(self):
        """Test scanner initialization"""
        from xss_scanner import XSSScanner
        
        scanner = XSSScanner("https://example.com")
        
        self.assertIsNotNone(scanner.target_url)
        self.assertIsNotNone(scanner.payloads)
        self.assertIsNotNone(scanner.waf_detector)
        self.assertIsNotNone(scanner.popup_system)
        self.assertIsNotNone(scanner.recon)
    
    def test_waf_detection_integration(self):
        """Test WAF detection integration"""
        from waf_bypass import WAFBypassEngine
        
        # Mock response with WAF headers
        mock_response = Mock()
        mock_response.headers = {'cf-ray': '123456789', 'cf-cache-status': 'HIT'}
        mock_response.text = 'Normal response'
        mock_response.status_code = 200
        
        waf_engine = WAFBypassEngine()
        waf_info = waf_engine.detect_waf(mock_response)
        
        self.assertTrue(waf_info['detected'])
        self.assertEqual(waf_info['type'], 'cloudflare')

def run_tests():
    """Run all tests"""
    print("Running XSS Scanner Test Suite...\n")
    
    # Create test suite
    test_suite = unittest.TestSuite()
    
    # Add test cases
    test_classes = [
        TestXSSPayloads,
        TestWAFBypass,
        TestCustomPopup,
        TestReconnaissance,
        TestIntegration
    ]
    
    for test_class in test_classes:
        tests = unittest.TestLoader().loadTestsFromTestCase(test_class)
        test_suite.addTests(tests)
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(test_suite)
    
    # Print summary
    print(f"\n{'='*50}")
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Success rate: {((result.testsRun - len(result.failures) - len(result.errors)) / result.testsRun * 100):.1f}%")
    
    if result.failures:
        print("\nFailures:")
        for test, traceback in result.failures:
            print(f"- {test}: {traceback.split('AssertionError: ')[-1].split('\\n')[0]}")
    
    if result.errors:
        print("\nErrors:")
        for test, traceback in result.errors:
            print(f"- {test}: {traceback.split('\\n')[-2]}")
    
    return result.wasSuccessful()

if __name__ == '__main__':
    success = run_tests()
    sys.exit(0 if success else 1)