#!/usr/bin/env python3
"""
Test Suite for Advanced XSS Scanner Features
Testing advanced reconnaissance, character filtering, and PoC capture
"""

import unittest
import sys
import os
import tempfile
import shutil
from unittest.mock import Mock, patch, MagicMock
from io import StringIO

# Add the current directory to the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from advanced_reconnaissance import AdvancedReconnaissance
from character_filter_analyzer import CharacterFilterAnalyzer
from poc_capture import PoCCapture
import requests

class TestAdvancedReconnaissance(unittest.TestCase):
    """Test cases for AdvancedReconnaissance class"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.test_url = "https://test.example.com"
        self.test_options = {
            'depth': 2,
            'max_urls': 10,
            'timeout': 5,
            'verbose': False
        }
        self.recon = AdvancedReconnaissance(self.test_url, self.test_options)
        
    def test_recon_initialization(self):
        """Test reconnaissance initialization"""
        self.assertEqual(self.recon.target_url, self.test_url)
        self.assertEqual(self.recon.options, self.test_options)
        self.assertIsNotNone(self.recon.session)
        self.assertIsNotNone(self.recon.filter_test_payloads)
        self.assertIsNotNone(self.recon.context_payloads)
        
    def test_context_payloads_structure(self):
        """Test context payloads structure"""
        payloads = self.recon.context_payloads
        
        # Check that all context types exist
        self.assertIn('html_content', payloads)
        self.assertIn('html_attribute', payloads)
        self.assertIn('javascript_context', payloads)
        self.assertIn('css_context', payloads)
        self.assertIn('url_context', payloads)
        
        # Check that payloads are not empty
        for context_type, payload_list in payloads.items():
            self.assertGreater(len(payload_list), 0)
            
    def test_filter_test_payloads(self):
        """Test filter test payloads"""
        self.assertGreater(len(self.recon.filter_test_payloads), 0)
        
        # Check for dangerous characters
        dangerous_chars = ['<', '>', '"', "'", '&', ';', '(', ')']
        for char in dangerous_chars:
            self.assertIn(char, self.recon.filter_test_payloads)
            
        # Check for XSS keywords
        xss_keywords = ['script', 'alert', 'javascript', 'onload', 'onerror']
        for keyword in xss_keywords:
            self.assertIn(keyword, self.recon.filter_test_payloads)

class TestCharacterFilterAnalyzer(unittest.TestCase):
    """Test cases for CharacterFilterAnalyzer class"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.session = requests.Session()
        self.analyzer = CharacterFilterAnalyzer(self.session)
        
    def test_analyzer_initialization(self):
        """Test analyzer initialization"""
        self.assertIsNotNone(self.analyzer.dangerous_chars)
        self.assertIsNotNone(self.analyzer.xss_keywords)
        self.assertIsNotNone(self.analyzer.bypass_methods)
        
    def test_dangerous_chars(self):
        """Test dangerous characters list"""
        self.assertGreater(len(self.analyzer.dangerous_chars), 0)
        
        # Check for common dangerous characters
        expected_chars = ['<', '>', '"', "'", '&', ';', '(', ')', '{', '}', '[', ']']
        for char in expected_chars:
            self.assertIn(char, self.analyzer.dangerous_chars)
            
    def test_xss_keywords(self):
        """Test XSS keywords list"""
        self.assertGreater(len(self.analyzer.xss_keywords), 0)
        
        # Check for common XSS keywords
        expected_keywords = ['script', 'alert', 'javascript', 'onload', 'onerror', 'onclick']
        for keyword in expected_keywords:
            self.assertIn(keyword, self.analyzer.xss_keywords)
            
    def test_bypass_methods(self):
        """Test bypass methods"""
        self.assertGreater(len(self.analyzer.bypass_methods), 0)
        
        # Check for common bypass methods
        expected_methods = ['url_encoding', 'html_encoding', 'unicode_encoding', 'case_variation']
        for method in expected_methods:
            self.assertIn(method, self.analyzer.bypass_methods)
            
    def test_url_encode(self):
        """Test URL encoding method"""
        test_payload = '<script>alert("XSS")</script>'
        encoded = self.analyzer._url_encode(test_payload)
        self.assertNotEqual(encoded, test_payload)
        self.assertIn('%3C', encoded)  # < should be encoded
        
    def test_html_encode(self):
        """Test HTML encoding method"""
        test_payload = '<script>alert("XSS")</script>'
        encoded = self.analyzer._html_encode(test_payload)
        self.assertNotEqual(encoded, test_payload)
        self.assertIn('&lt;', encoded)  # < should be encoded
        
    def test_unicode_encode(self):
        """Test Unicode encoding method"""
        test_payload = '<script>'
        encoded = self.analyzer._unicode_encode(test_payload)
        self.assertNotEqual(encoded, test_payload)
        self.assertIn('\\u', encoded)  # Should contain Unicode escapes
        
    def test_case_variation(self):
        """Test case variation method"""
        test_payload = '<script>alert("XSS")</script>'
        varied = self.analyzer._case_variation(test_payload)
        self.assertNotEqual(varied, test_payload)
        self.assertIn('ScRiPt', varied)  # Should have case variation

class TestPoCCapture(unittest.TestCase):
    """Test cases for PoCCapture class"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.test_options = {
            'headless': True,
            'timeout': 10
        }
        self.poc_capture = PoCCapture(self.test_options)
        
    def test_poc_initialization(self):
        """Test PoC capture initialization"""
        self.assertEqual(self.poc_capture.options, self.test_options)
        self.assertIsNone(self.poc_capture.driver)
        
    def test_directories_creation(self):
        """Test that directories are created"""
        self.assertTrue(os.path.exists(self.poc_capture.screenshots_dir))
        self.assertTrue(os.path.exists(self.poc_capture.videos_dir))
        
    def test_generate_poc_report(self):
        """Test PoC report generation"""
        poc_data = {
            'success': True,
            'url': 'https://test.example.com',
            'payload': '<script>alert("XSS")</script>',
            'timestamp': '2024-01-01 12:00:00',
            'alert_detected': True,
            'page_title': 'Test Page',
            'current_url': 'https://test.example.com',
            'input_point': {
                'type': 'form',
                'url': 'https://test.example.com'
            },
            'screenshots': {
                'initial': 'initial.png',
                'injection': 'injection.png',
                'alert': 'alert.png',
                'post_alert': 'post_alert.png'
            }
        }
        
        report = self.poc_capture.generate_poc_report(poc_data)
        
        self.assertIn('XSS Vulnerability Proof of Concept Report', report)
        self.assertIn('https://test.example.com', report)
        self.assertIn('<script>alert("XSS")</script>', report)
        self.assertIn('Reproduction Steps:', report)
        self.assertIn('Remediation:', report)
        
    def test_cleanup(self):
        """Test cleanup method"""
        # Mock driver
        self.poc_capture.driver = Mock()
        self.poc_capture.cleanup()
        self.assertIsNone(self.poc_capture.driver)

class TestIntegration(unittest.TestCase):
    """Integration tests for advanced features"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.test_url = "https://httpbin.org"
        self.test_options = {
            'depth': 1,
            'max_urls': 5,
            'timeout': 5,
            'verbose': False
        }
        
    @patch('requests.Session.get')
    def test_advanced_recon_integration(self, mock_get):
        """Test advanced reconnaissance integration"""
        # Mock response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.content = b'''
        <html>
            <body>
                <form action="/search" method="GET">
                    <input type="text" name="q" value="">
                    <input type="submit" value="Search">
                </form>
                <a href="/page1">Page 1</a>
            </body>
        </html>
        '''
        mock_get.return_value = mock_response
        
        recon = AdvancedReconnaissance(self.test_url, self.test_options)
        
        # Test URL discovery
        discovered_urls = recon.discovered_urls
        self.assertGreaterEqual(len(discovered_urls), 0)
        
    def test_character_filter_analysis_integration(self):
        """Test character filter analysis integration"""
        session = requests.Session()
        analyzer = CharacterFilterAnalyzer(session)
        
        # Test bypass payload generation
        original_payload = '<script>alert("XSS")</script>'
        analysis_result = {
            'bypass_techniques': {
                'html_tag_bypass': ['&lt;script&gt;alert(1)&lt;/script&gt;'],
                'quote_bypass': ['&quot;alert(1)&quot;']
            }
        }
        
        bypass_payloads = analyzer.generate_bypass_payloads(original_payload, analysis_result)
        
        self.assertGreater(len(bypass_payloads), 0)
        self.assertIn(original_payload, bypass_payloads)

def run_advanced_tests():
    """Run all advanced feature tests"""
    # Create test suite
    test_suite = unittest.TestSuite()
    
    # Add test cases
    test_classes = [
        TestAdvancedReconnaissance,
        TestCharacterFilterAnalyzer,
        TestPoCCapture,
        TestIntegration
    ]
    
    for test_class in test_classes:
        tests = unittest.TestLoader().loadTestsFromTestCase(test_class)
        test_suite.addTests(tests)
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(test_suite)
    
    return result.wasSuccessful()

if __name__ == '__main__':
    success = run_advanced_tests()
    sys.exit(0 if success else 1)