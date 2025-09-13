#!/usr/bin/env python3
"""
Test Suite for Live Progress Module
Testing live progress tracking and display functionality
"""

import unittest
import sys
import os
import time
from unittest.mock import Mock, patch
from io import StringIO

# Add the current directory to the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from live_progress import LiveProgress

class TestLiveProgress(unittest.TestCase):
    """Test cases for LiveProgress class"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.progress = LiveProgress()
        
    def test_progress_initialization(self):
        """Test progress initialization"""
        self.assertEqual(self.progress.current_phase, "")
        self.assertEqual(self.progress.current_task, "")
        self.assertEqual(self.progress.is_running, False)
        self.assertEqual(len(self.progress.vulnerabilities_found), 0)
        
    def test_start_phase(self):
        """Test phase start"""
        self.progress.start_phase("Test Phase", "Test description")
        self.assertEqual(self.progress.current_phase, "Test Phase")
        self.assertEqual(self.progress.current_task, "Test description")
        self.assertEqual(self.progress.is_running, True)
        
    def test_update_task(self):
        """Test task update"""
        self.progress.update_task("New task")
        self.assertEqual(self.progress.current_task, "New task")
        
    def test_show_progress(self):
        """Test progress display"""
        # This test checks that the method doesn't raise an exception
        self.progress.show_progress(5, 10, "Testing")
        self.progress.show_progress(0, 0, "Testing")  # Edge case
        
    def test_show_url_discovery(self):
        """Test URL discovery display"""
        # Test different statuses
        self.progress.show_url_discovery("https://example.com", "discovered")
        self.progress.show_url_discovery("https://example.com", "crawling")
        self.progress.show_url_discovery("https://example.com", "error")
        
    def test_show_input_point(self):
        """Test input point display"""
        # Test form input point
        form_input = {
            'type': 'form',
            'url': 'https://example.com',
            'action': '/search',
            'method': 'GET',
            'inputs': [{'name': 'q', 'type': 'text'}]
        }
        self.progress.show_input_point(form_input)
        
        # Test URL params input point
        url_params_input = {
            'type': 'url_params',
            'url': 'https://example.com',
            'params': {'q': 'test', 'page': '1'}
        }
        self.progress.show_input_point(url_params_input)
        
        # Test JavaScript variables input point
        js_vars_input = {
            'type': 'javascript_variables',
            'url': 'https://example.com',
            'variables': [{'name': 'userInput', 'value': 'test'}]
        }
        self.progress.show_input_point(js_vars_input)
        
    def test_show_character_filter_test(self):
        """Test character filter test display"""
        self.progress.show_character_filter_test('<', 'https://example.com', True)
        self.progress.show_character_filter_test('>', 'https://example.com', False)
        
    def test_show_payload_injection(self):
        """Test payload injection display"""
        payload = '<script>alert("XSS")</script>'
        self.progress.show_payload_injection(payload, 'https://example.com', 'html_content')
        
    def test_show_vulnerability_found(self):
        """Test vulnerability found display"""
        vulnerability = {
            'url': 'https://example.com',
            'payload': '<script>alert("XSS")</script>',
            'context_type': 'html_content'
        }
        self.progress.show_vulnerability_found(vulnerability)
        
        # Check that vulnerability was added to the list
        self.assertEqual(len(self.progress.vulnerabilities_found), 1)
        self.assertEqual(self.progress.vulnerabilities_found[0], vulnerability)
        
    def test_show_chrome_execution(self):
        """Test Chrome execution display"""
        self.progress.show_chrome_execution('https://example.com', '<script>alert("XSS")</script>')
        
    def test_show_screenshot_capture(self):
        """Test screenshot capture display"""
        self.progress.show_screenshot_capture('screenshot_1234567890.png')
        
    def test_show_alert_detected(self):
        """Test alert detection display"""
        self.progress.show_alert_detected()
        
    def test_show_phase_complete(self):
        """Test phase completion display"""
        results = {
            'items_processed': 10,
            'successful': 8,
            'failed': 2
        }
        self.progress.show_phase_complete("Test Phase", results)
        
    def test_show_final_summary(self):
        """Test final summary display"""
        # Add some vulnerabilities
        self.progress.vulnerabilities_found = [
            {'url': 'https://example.com', 'payload': '<script>alert("XSS")</script>'},
            {'url': 'https://test.com', 'payload': '<img src=x onerror=alert("XSS")>'}
        ]
        
        self.progress.show_final_summary()
        
    def test_show_error(self):
        """Test error display"""
        self.progress.show_error("Test error message")
        
    def test_show_warning(self):
        """Test warning display"""
        self.progress.show_warning("Test warning message")
        
    def test_show_info(self):
        """Test info display"""
        self.progress.show_info("Test info message")
        
    def test_show_success(self):
        """Test success display"""
        self.progress.show_success("Test success message")
        
    def test_clear_line(self):
        """Test line clearing"""
        self.progress.clear_line()
        
    def test_update_stats(self):
        """Test stats update"""
        stats = {'requests': 100, 'successful': 95, 'failed': 5}
        self.progress.update_stats(stats)
        self.assertEqual(self.progress.progress_data, stats)
        
    def test_stop(self):
        """Test progress stop"""
        self.progress.is_running = True
        self.progress.stop()
        self.assertEqual(self.progress.is_running, False)

class TestLiveProgressIntegration(unittest.TestCase):
    """Integration tests for LiveProgress"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.progress = LiveProgress()
        
    def test_full_workflow(self):
        """Test complete workflow"""
        # Start phase
        self.progress.start_phase("Test Phase", "Testing complete workflow")
        
        # Update task
        self.progress.update_task("Processing items")
        
        # Show progress
        self.progress.show_progress(5, 10, "Processing")
        
        # Show URL discovery
        self.progress.show_url_discovery("https://example.com", "discovered")
        
        # Show input point
        input_point = {
            'type': 'form',
            'url': 'https://example.com',
            'action': '/search',
            'method': 'GET',
            'inputs': [{'name': 'q', 'type': 'text'}]
        }
        self.progress.show_input_point(input_point)
        
        # Show payload injection
        self.progress.show_payload_injection('<script>alert("XSS")</script>', 'https://example.com', 'html_content')
        
        # Show vulnerability found
        vulnerability = {
            'url': 'https://example.com',
            'payload': '<script>alert("XSS")</script>',
            'context_type': 'html_content'
        }
        self.progress.show_vulnerability_found(vulnerability)
        
        # Show Chrome execution
        self.progress.show_chrome_execution('https://example.com', '<script>alert("XSS")</script>')
        
        # Show alert detected
        self.progress.show_alert_detected()
        
        # Show screenshot capture
        self.progress.show_screenshot_capture('screenshot_1234567890.png')
        
        # Show phase complete
        results = {'items_processed': 10, 'successful': 8, 'failed': 2}
        self.progress.show_phase_complete("Test Phase", results)
        
        # Show final summary
        self.progress.show_final_summary()
        
        # Stop
        self.progress.stop()
        
        # Verify state
        self.assertEqual(len(self.progress.vulnerabilities_found), 1)
        self.assertEqual(self.progress.is_running, False)

def run_live_progress_tests():
    """Run all live progress tests"""
    # Create test suite
    test_suite = unittest.TestSuite()
    
    # Add test cases
    test_classes = [
        TestLiveProgress,
        TestLiveProgressIntegration
    ]
    
    for test_class in test_classes:
        tests = unittest.TestLoader().loadTestsFromTestCase(test_class)
        test_suite.addTests(tests)
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(test_suite)
    
    return result.wasSuccessful()

if __name__ == '__main__':
    success = run_live_progress_tests()
    sys.exit(0 if success else 1)