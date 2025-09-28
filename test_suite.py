#!/usr/bin/env python3
"""
Comprehensive test suite for Open Redirect Scanner
"""

import asyncio
import sys
import unittest
from pathlib import Path
from unittest.mock import Mock, patch, AsyncMock

# Add current directory to Python path
sys.path.insert(0, str(Path(__file__).parent))

from open_redirect_scanner import OpenRedirectScanner
from recon_module import ReconModule
from payload_module import PayloadModule
from chrome_module import ChromeModule
from report_module import ReportModule
from logging_module import LoggingModule

class TestReconModule(unittest.TestCase):
    """Test cases for ReconModule"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.logger = Mock()
        self.recon = ReconModule(self.logger)
    
    def test_redirect_params_initialization(self):
        """Test redirect parameters initialization"""
        self.assertIsInstance(self.recon.redirect_params, set)
        self.assertGreater(len(self.recon.redirect_params), 0)
        self.assertIn('url', self.recon.redirect_params)
        self.assertIn('redirect', self.recon.redirect_params)
    
    def test_js_redirect_patterns_initialization(self):
        """Test JavaScript redirect patterns initialization"""
        self.assertIsInstance(self.recon.js_redirect_patterns, list)
        self.assertGreater(len(self.recon.js_redirect_patterns), 0)
    
    def test_extract_url_parameters(self):
        """Test URL parameter extraction"""
        test_url = "https://example.com?url=test&redirect=test2&other=value"
        params = self.recon._extract_url_parameters(test_url)
        
        self.assertIsInstance(params, list)
        self.assertGreater(len(params), 0)
        
        # Check if redirect parameters are found
        param_names = [p['parameter'] for p in params]
        self.assertIn('url', param_names)
        self.assertIn('redirect', param_names)
    
    def test_is_same_domain(self):
        """Test same domain checking"""
        self.assertTrue(self.recon._is_same_domain("https://example.com", "https://example.com/path"))
        self.assertTrue(self.recon._is_same_domain("https://example.com", "http://example.com/path"))
        self.assertFalse(self.recon._is_same_domain("https://example.com", "https://other.com/path"))

class TestPayloadModule(unittest.TestCase):
    """Test cases for PayloadModule"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.logger = Mock()
        self.payloads = PayloadModule(self.logger)
    
    def test_base_payloads_initialization(self):
        """Test base payloads initialization"""
        self.assertIsInstance(self.payloads.base_payloads, list)
        self.assertGreater(len(self.payloads.base_payloads), 0)
    
    def test_bypass_techniques_initialization(self):
        """Test bypass techniques initialization"""
        self.assertIsInstance(self.payloads.bypass_techniques, list)
        self.assertGreater(len(self.payloads.bypass_techniques), 0)
    
    def test_url_encoding(self):
        """Test URL encoding bypass"""
        payload = "//google.com"
        result = self.payloads._url_encoding(payload)
        
        self.assertIsInstance(result, list)
        self.assertGreater(len(result), 0)
        self.assertIn(urllib.parse.quote(payload), result)
    
    def test_case_variations(self):
        """Test case variation bypass"""
        payload = "//google.com"
        result = self.payloads._case_variations(payload)
        
        self.assertIsInstance(result, list)
        self.assertGreater(len(result), 0)
        self.assertIn(payload.upper(), result)
        self.assertIn(payload.lower(), result)
    
    def test_generate_payloads(self):
        """Test payload generation"""
        base_payload = "//google.com"
        result = self.payloads.generate_payloads(base_payload)
        
        self.assertIsInstance(result, list)
        self.assertGreater(len(result), 0)
        self.assertIn(base_payload, result)

class TestChromeModule(unittest.TestCase):
    """Test cases for ChromeModule"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.logger = Mock()
        self.output_dir = Path("test_output")
        self.output_dir.mkdir(exist_ok=True)
        self.chrome = ChromeModule(self.logger, self.output_dir)
    
    def tearDown(self):
        """Clean up test fixtures"""
        import shutil
        if self.output_dir.exists():
            shutil.rmtree(self.output_dir)
    
    def test_initialization(self):
        """Test Chrome module initialization"""
        self.assertIsNone(self.chrome.driver)
        self.assertEqual(self.chrome.target_domain, "google.com")
        self.assertTrue(self.chrome.screenshots_dir.exists())
    
    def test_is_valid_redirect(self):
        """Test redirect validation"""
        self.assertTrue(self.chrome._is_valid_redirect("https://google.com"))
        self.assertTrue(self.chrome._is_valid_redirect("https://www.google.com"))
        self.assertFalse(self.chrome._is_valid_redirect("https://example.com"))
        self.assertFalse(self.chrome._is_valid_redirect("invalid-url"))

class TestReportModule(unittest.TestCase):
    """Test cases for ReportModule"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.output_dir = Path("test_output")
        self.output_dir.mkdir(exist_ok=True)
        self.report = ReportModule(self.output_dir)
    
    def tearDown(self):
        """Clean up test fixtures"""
        import shutil
        if self.output_dir.exists():
            shutil.rmtree(self.output_dir)
    
    def test_initialization(self):
        """Test report module initialization"""
        self.assertTrue(self.report.reports_dir.exists())
    
    def test_determine_severity(self):
        """Test severity determination"""
        # Test different vulnerability types
        vuln1 = {'injection_type': 'javascript', 'parameter': 'redirect'}
        self.assertEqual(self.report._determine_severity(vuln1), 'high')
        
        vuln2 = {'injection_type': 'url', 'parameter': 'redirect'}
        self.assertEqual(self.report._determine_severity(vuln2), 'high')
        
        vuln3 = {'injection_type': 'form', 'parameter': 'other'}
        self.assertEqual(self.report._determine_severity(vuln3), 'medium')
        
        vuln4 = {'injection_type': 'unknown', 'parameter': 'unknown'}
        self.assertEqual(self.report._determine_severity(vuln4), 'low')

class TestLoggingModule(unittest.TestCase):
    """Test cases for LoggingModule"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.output_dir = Path("test_output")
        self.output_dir.mkdir(exist_ok=True)
        self.logging = LoggingModule(self.output_dir)
    
    def tearDown(self):
        """Clean up test fixtures"""
        import shutil
        if self.output_dir.exists():
            shutil.rmtree(self.output_dir)
    
    def test_initialization(self):
        """Test logging module initialization"""
        self.assertIsNotNone(self.logging.logger)
        self.assertTrue(self.logging.logs_dir.exists())
    
    def test_log_methods(self):
        """Test logging methods"""
        # Test that logging methods don't raise exceptions
        self.logging.info("Test info message")
        self.logging.warning("Test warning message")
        self.logging.error("Test error message")
        self.logging.debug("Test debug message")
        self.logging.critical("Test critical message")
    
    def test_get_log_files(self):
        """Test log file path retrieval"""
        log_files = self.logging.get_log_files()
        self.assertIsInstance(log_files, dict)
        self.assertIn('main_log', log_files)
        self.assertIn('error_log', log_files)
        self.assertIn('debug_log', log_files)

class TestOpenRedirectScanner(unittest.TestCase):
    """Test cases for OpenRedirectScanner"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.target_url = "https://example.com"
        self.output_dir = "test_output"
        self.threads = 5
        self.scanner = OpenRedirectScanner(self.target_url, self.output_dir, self.threads)
    
    def tearDown(self):
        """Clean up test fixtures"""
        import shutil
        if Path(self.output_dir).exists():
            shutil.rmtree(self.output_dir)
    
    def test_initialization(self):
        """Test scanner initialization"""
        self.assertEqual(self.scanner.target_url, self.target_url)
        self.assertEqual(self.scanner.output_dir, Path(self.output_dir))
        self.assertEqual(self.scanner.max_threads, self.threads)
        self.assertIsInstance(self.scanner.custom_payloads, list)
        self.assertGreater(len(self.scanner.custom_payloads), 0)
    
    def test_custom_payloads_loading(self):
        """Test custom payloads loading"""
        self.assertIsInstance(self.scanner.custom_payloads, list)
        self.assertGreater(len(self.scanner.custom_payloads), 0)
        
        # Check for some expected payloads
        payloads = self.scanner.custom_payloads
        self.assertIn("/%09/google.com", payloads)
        self.assertIn("//google.com", payloads)
        self.assertIn("javascript:confirm(1)", payloads)
    
    def test_construct_test_url(self):
        """Test test URL construction"""
        injection_point = {
            'url': 'https://example.com',
            'parameter': 'redirect',
            'type': 'url'
        }
        payload = "//google.com"
        
        result = self.scanner._construct_test_url(injection_point, payload)
        
        self.assertIsInstance(result, str)
        self.assertIn('redirect', result)
        self.assertIn('google.com', result)

class TestIntegration(unittest.TestCase):
    """Integration test cases"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.target_url = "https://httpbin.org"
        self.output_dir = "test_integration"
        self.threads = 2
        self.scanner = OpenRedirectScanner(self.target_url, self.output_dir, self.threads)
    
    def tearDown(self):
        """Clean up test fixtures"""
        import shutil
        if Path(self.output_dir).exists():
            shutil.rmtree(self.output_dir)
    
    @patch('open_redirect_scanner.ChromeModule')
    @patch('open_redirect_scanner.ReconModule')
    async def test_scan_initialization(self, mock_recon, mock_chrome):
        """Test scan initialization"""
        # Mock the modules
        mock_recon.return_value.perform_recon.return_value = {
            'urls': [],
            'forms': [],
            'javascript_vars': [],
            'meta_tags': [],
            'cookies': [],
            'headers': [],
            'injection_points': []
        }
        mock_chrome.return_value.initialize.return_value = True
        
        # Test initialization
        result = await self.scanner.initialize()
        self.assertTrue(result)
    
    def test_module_imports(self):
        """Test that all modules can be imported"""
        try:
            from open_redirect_scanner import OpenRedirectScanner
            from recon_module import ReconModule
            from payload_module import PayloadModule
            from chrome_module import ChromeModule
            from report_module import ReportModule
            from logging_module import LoggingModule
        except ImportError as e:
            self.fail(f"Failed to import modules: {e}")

def run_tests():
    """Run all tests"""
    print("🧪 Running Open Redirect Scanner Test Suite")
    print("=" * 50)
    
    # Create test suite
    test_suite = unittest.TestSuite()
    
    # Add test cases
    test_classes = [
        TestReconModule,
        TestPayloadModule,
        TestChromeModule,
        TestReportModule,
        TestLoggingModule,
        TestOpenRedirectScanner,
        TestIntegration
    ]
    
    for test_class in test_classes:
        tests = unittest.TestLoader().loadTestsFromTestCase(test_class)
        test_suite.addTests(tests)
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(test_suite)
    
    # Print summary
    print("\n" + "=" * 50)
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Success rate: {((result.testsRun - len(result.failures) - len(result.errors)) / result.testsRun * 100):.1f}%")
    
    if result.failures:
        print("\n❌ Failures:")
        for test, traceback in result.failures:
            print(f"  - {test}: {traceback}")
    
    if result.errors:
        print("\n❌ Errors:")
        for test, traceback in result.errors:
            print(f"  - {test}: {traceback}")
    
    return result.wasSuccessful()

if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)