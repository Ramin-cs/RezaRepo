#!/usr/bin/env python3
"""
Test Suite for XSS Scanner
Comprehensive testing for all scanner components
"""

import unittest
import sys
import os
import json
import tempfile
import shutil
from unittest.mock import Mock, patch, MagicMock
from io import StringIO

# Add the current directory to the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from xss_scanner import XSSScanner
from context_analyzer import ContextAnalyzer
from vulnerability_detector import VulnerabilityDetector
from report_generator import ReportGenerator

class TestXSSScanner(unittest.TestCase):
    """Test cases for XSSScanner class"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.test_url = "https://test.example.com"
        self.test_options = {
            'depth': 2,
            'max_urls': 10,
            'timeout': 5,
            'verbose': False
        }
        self.scanner = XSSScanner(self.test_url, self.test_options)
        
    def test_scanner_initialization(self):
        """Test scanner initialization"""
        self.assertEqual(self.scanner.target_url, self.test_url)
        self.assertEqual(self.scanner.options, self.test_options)
        self.assertIsNotNone(self.scanner.session)
        self.assertIsNotNone(self.scanner.payloads)
        
    def test_payload_loading(self):
        """Test payload loading"""
        payloads = self.scanner._load_payloads()
        
        # Check that all payload categories exist
        self.assertIn('basic', payloads)
        self.assertIn('filter_bypass', payloads)
        self.assertIn('encoding_bypass', payloads)
        self.assertIn('context_specific', payloads)
        
        # Check that payloads are not empty
        self.assertGreater(len(payloads['basic']), 0)
        self.assertGreater(len(payloads['filter_bypass']), 0)
        
    def test_session_configuration(self):
        """Test session configuration"""
        self.scanner._configure_session()
        
        # Check that headers are set
        self.assertIn('User-Agent', self.scanner.session.headers)
        self.assertIn('Accept', self.scanner.session.headers)
        
    @patch('requests.Session.get')
    def test_discover_urls(self, mock_get):
        """Test URL discovery"""
        # Mock response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.content = b'''
        <html>
            <body>
                <a href="/page1">Page 1</a>
                <a href="/page2">Page 2</a>
                <a href="https://external.com">External</a>
            </body>
        </html>
        '''
        mock_get.return_value = mock_response
        
        discovered_urls = self.scanner.discover_urls()
        
        # Should discover the main URL and internal links
        self.assertGreater(len(discovered_urls), 0)
        self.assertIn(self.test_url, discovered_urls)
        
    @patch('requests.Session.get')
    def test_find_input_points(self, mock_get):
        """Test input point discovery"""
        # Mock response with forms
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.content = b'''
        <html>
            <body>
                <form action="/search" method="GET">
                    <input type="text" name="q" value="">
                    <input type="submit" value="Search">
                </form>
                <form action="/login" method="POST">
                    <input type="text" name="username">
                    <input type="password" name="password">
                    <input type="submit" value="Login">
                </form>
            </body>
        </html>
        '''
        mock_get.return_value = mock_response
        
        input_points = self.scanner.find_input_points(self.test_url)
        
        # Should find forms
        self.assertGreater(len(input_points), 0)
        
        # Check form structure
        for point in input_points:
            if point['type'] == 'form':
                self.assertIn('inputs', point)
                self.assertIn('method', point)
                self.assertIn('action', point)

class TestContextAnalyzer(unittest.TestCase):
    """Test cases for ContextAnalyzer class"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.analyzer = ContextAnalyzer()
        
    def test_analyzer_initialization(self):
        """Test analyzer initialization"""
        self.assertIsNotNone(self.analyzer.context_patterns)
        self.assertIn('html_content', self.analyzer.context_patterns)
        self.assertIn('html_attribute', self.analyzer.context_patterns)
        self.assertIn('javascript_context', self.analyzer.context_patterns)
        
    def test_analyze_input_context(self):
        """Test input context analysis"""
        html_content = '''
        <html>
            <body>
                <div>User input: <script>alert("XSS")</script></div>
            </body>
        </html>
        '''
        
        context_info = self.analyzer.analyze_input_context(
            html_content, '<script>alert("XSS")</script>'
        )
        
        self.assertIsNotNone(context_info)
        self.assertIn('context_type', context_info)
        self.assertIn('confidence', context_info)
        self.assertIn('suggested_payloads', context_info)
        
    def test_detect_html_encoding(self):
        """Test HTML encoding detection"""
        surrounding = '&lt;script&gt;alert("XSS")&lt;/script&gt;'
        result = self.analyzer._detect_html_encoding(surrounding, 'test')
        self.assertTrue(result)
        
    def test_detect_filters(self):
        """Test filter detection"""
        surrounding = 'This request was blocked by WAF security filter'
        filters = self.analyzer._detect_filters(surrounding)
        self.assertIn('waf', filters)
        
    def test_generate_context_payloads(self):
        """Test context-specific payload generation"""
        payloads = self.analyzer._generate_context_payloads('html_content', [])
        self.assertGreater(len(payloads), 0)
        
        # Check that payloads are appropriate for HTML content
        for payload in payloads:
            self.assertIn('<', payload)  # Should contain HTML tags

class TestVulnerabilityDetector(unittest.TestCase):
    """Test cases for VulnerabilityDetector class"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.detector = VulnerabilityDetector()
        
    def test_detector_initialization(self):
        """Test detector initialization"""
        self.assertIsNotNone(self.detector.xss_patterns)
        self.assertIsNotNone(self.detector.compiled_patterns)
        self.assertIsNotNone(self.detector.xss_indicators)
        
    def test_quick_xss_check(self):
        """Test quick XSS check"""
        # Test positive case
        response_with_xss = '<script>alert("XSS")</script>'
        self.assertTrue(self.detector._quick_xss_check(response_with_xss))
        
        # Test negative case
        response_without_xss = '<p>Normal content</p>'
        self.assertFalse(self.detector._quick_xss_check(response_without_xss))
        
    def test_pattern_based_detection(self):
        """Test pattern-based detection"""
        response_with_xss = '<script>alert("XSS")</script>'
        matches = self.detector._pattern_based_detection(response_with_xss)
        self.assertGreater(len(matches), 0)
        
    def test_analyze_payload_reflection(self):
        """Test payload reflection analysis"""
        response_text = 'User input: <script>alert("XSS")</script>'
        payload = '<script>alert("XSS")</script>'
        
        analysis = self.detector._analyze_payload_reflection(response_text, payload)
        
        self.assertTrue(analysis['reflected'])
        self.assertGreater(analysis['reflection_count'], 0)
        
    def test_detect_xss_vulnerability(self):
        """Test XSS vulnerability detection"""
        response_text = '<html><body><script>alert("XSS")</script></body></html>'
        payload = '<script>alert("XSS")</script>'
        
        detection = self.detector.detect_xss_vulnerability(response_text, payload)
        
        self.assertTrue(detection['is_vulnerable'])
        self.assertGreater(detection['confidence'], 0.0)
        self.assertIn('evidence', detection)
        
    def test_generate_encoded_variants(self):
        """Test encoded variant generation"""
        payload = '<script>alert("XSS")</script>'
        variants = self.detector._generate_encoded_variants(payload)
        
        self.assertGreater(len(variants), 0)
        
        # Check that variants are different from original
        for variant in variants:
            self.assertNotEqual(variant, payload)

class TestReportGenerator(unittest.TestCase):
    """Test cases for ReportGenerator class"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.temp_dir = tempfile.mkdtemp()
        self.generator = ReportGenerator(self.temp_dir)
        
        # Sample scan results
        self.sample_results = {
            'target_url': 'https://test.example.com',
            'scan_timestamp': '2024-01-01 12:00:00',
            'scan_duration': 120,
            'total_urls': 50,
            'vulnerabilities': [
                {
                    'url': 'https://test.example.com/search',
                    'vulnerability_type': 'reflected_xss_html_context',
                    'severity': 'high',
                    'confidence': 0.9,
                    'payload': '<script>alert("XSS")</script>',
                    'evidence': ['XSS pattern 1 matched', 'Payload successfully reflected'],
                    'timestamp': '2024-01-01 12:00:00',
                    'context_analysis': {
                        'context_type': 'html_content',
                        'encoding_detected': False
                    },
                    'payload_reflected': True
                }
            ],
            'discovered_urls': ['https://test.example.com', 'https://test.example.com/search'],
            'statistics': {'total_requests': 100, 'successful_requests': 95}
        }
        
    def tearDown(self):
        """Clean up test fixtures"""
        shutil.rmtree(self.temp_dir)
        
    def test_generator_initialization(self):
        """Test generator initialization"""
        self.assertEqual(self.generator.output_dir, self.temp_dir)
        self.assertTrue(os.path.exists(self.temp_dir))
        
    def test_generate_json_report(self):
        """Test JSON report generation"""
        filename = self.generator._generate_json_report(self.sample_results, 'test')
        
        self.assertTrue(os.path.exists(filename))
        
        # Load and validate JSON
        with open(filename, 'r') as f:
            data = json.load(f)
            
        self.assertIn('scan_metadata', data)
        self.assertIn('summary', data)
        self.assertIn('vulnerabilities', data)
        
    def test_generate_html_report(self):
        """Test HTML report generation"""
        filename = self.generator._generate_html_report(self.sample_results, 'test')
        
        self.assertTrue(os.path.exists(filename))
        
        # Check HTML content
        with open(filename, 'r') as f:
            content = f.read()
            
        self.assertIn('<html', content)
        self.assertIn('XSS Vulnerability Scan Report', content)
        
    def test_generate_csv_report(self):
        """Test CSV report generation"""
        filename = self.generator._generate_csv_report(self.sample_results, 'test')
        
        self.assertTrue(os.path.exists(filename))
        
        # Check CSV content
        with open(filename, 'r') as f:
            content = f.read()
            
        self.assertIn('url,vulnerability_type,severity', content)
        
    def test_generate_text_report(self):
        """Test text report generation"""
        filename = self.generator._generate_text_report(self.sample_results, 'test')
        
        self.assertTrue(os.path.exists(filename))
        
        # Check text content
        with open(filename, 'r') as f:
            content = f.read()
            
        self.assertIn('XSS VULNERABILITY SCAN REPORT', content)
        self.assertIn('SUMMARY', content)
        
    def test_calculate_statistics(self):
        """Test statistics calculation"""
        vulnerabilities = [
            {'severity': 'critical'},
            {'severity': 'high'},
            {'severity': 'medium'},
            {'severity': 'low'}
        ]
        
        stats = self.generator._calculate_statistics(vulnerabilities)
        
        self.assertEqual(stats['critical'], 1)
        self.assertEqual(stats['high'], 1)
        self.assertEqual(stats['medium'], 1)
        self.assertEqual(stats['low'], 1)
        
    def test_generate_executive_summary(self):
        """Test executive summary generation"""
        summary = self.generator.generate_executive_summary(self.sample_results)
        
        self.assertIn('EXECUTIVE SUMMARY', summary)
        self.assertIn('Target:', summary)
        self.assertIn('VULNERABILITY SUMMARY:', summary)

class TestIntegration(unittest.TestCase):
    """Integration tests for the complete scanner"""
    
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
    def test_end_to_end_scan(self, mock_get):
        """Test end-to-end scanning process"""
        # Mock responses for different endpoints
        def mock_response(url, **kwargs):
            response = Mock()
            response.status_code = 200
            
            if 'forms' in url:
                response.content = b'''
                <html>
                    <body>
                        <form action="/search" method="GET">
                            <input type="text" name="q" value="">
                            <input type="submit" value="Search">
                        </form>
                    </body>
                </html>
                '''
            else:
                response.content = b'''
                <html>
                    <body>
                        <a href="/forms">Forms</a>
                        <a href="/search">Search</a>
                    </body>
                </html>
                '''
            return response
            
        mock_get.side_effect = mock_response
        
        scanner = XSSScanner(self.test_url, self.test_options)
        
        # Test URL discovery
        discovered_urls = scanner.discover_urls()
        self.assertGreater(len(discovered_urls), 0)
        
        # Test input point discovery
        input_points = scanner.find_input_points(self.test_url)
        self.assertGreaterEqual(len(input_points), 0)

def run_tests():
    """Run all tests"""
    # Create test suite
    test_suite = unittest.TestSuite()
    
    # Add test cases
    test_classes = [
        TestXSSScanner,
        TestContextAnalyzer,
        TestVulnerabilityDetector,
        TestReportGenerator,
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
    success = run_tests()
    sys.exit(0 if success else 1)