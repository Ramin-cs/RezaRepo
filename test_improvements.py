#!/usr/bin/env python3
"""
Test Suite for XSS Scanner Improvements
Testing improved live progress, context breakdown, and parallel processing
"""

import unittest
import sys
import os
import time
import concurrent.futures
from unittest.mock import Mock, patch
from io import StringIO

# Add the current directory to the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from context_breakdown import ContextBreakdown
from live_progress import LiveProgress

class TestContextBreakdown(unittest.TestCase):
    """Test cases for ContextBreakdown class"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.breakdown = ContextBreakdown()
        
    def test_breakdown_initialization(self):
        """Test breakdown initialization"""
        self.assertIsNotNone(self.breakdown.context_stats)
        self.assertEqual(self.breakdown.context_stats['html_content'], 0)
        self.assertEqual(self.breakdown.context_stats['html_attribute'], 0)
        self.assertEqual(self.breakdown.context_stats['javascript_context'], 0)
        
    def test_analyze_input_points(self):
        """Test input points analysis"""
        sample_input_points = [
            {
                'type': 'form',
                'url': 'https://example.com/search',
                'inputs': [
                    {'name': 'q', 'type': 'text'},
                    {'name': 'category', 'type': 'select'}
                ]
            },
            {
                'type': 'url_params',
                'url': 'https://example.com/product?id=123',
                'params': {'id': '123'}
            },
            {
                'type': 'javascript_variables',
                'url': 'https://example.com/dashboard',
                'variables': [{'name': 'userInput', 'value': 'test'}]
            }
        ]
        
        result = self.breakdown.analyze_input_points(sample_input_points)
        
        self.assertIn('forms', result)
        self.assertIn('url_params', result)
        self.assertIn('js_variables', result)
        self.assertIn('context_stats', result)
        
        self.assertEqual(len(result['forms']), 1)
        self.assertEqual(len(result['url_params']), 1)
        self.assertEqual(len(result['js_variables']), 1)
        
    def test_get_context_specific_payloads(self):
        """Test context-specific payload generation"""
        # Test HTML content payloads
        html_payloads = self.breakdown.get_context_specific_payloads('html_content')
        self.assertGreater(len(html_payloads), 0)
        self.assertIn('<script>alert("XSS")</script>', html_payloads)
        
        # Test HTML attribute payloads
        attr_payloads = self.breakdown.get_context_specific_payloads('html_attribute')
        self.assertGreater(len(attr_payloads), 0)
        self.assertIn('" onmouseover="alert(\'XSS\')" x="', attr_payloads)
        
        # Test JavaScript context payloads
        js_payloads = self.breakdown.get_context_specific_payloads('javascript_context')
        self.assertGreater(len(js_payloads), 0)
        self.assertIn(';alert("XSS");', js_payloads)
        
        # Test CSS context payloads
        css_payloads = self.breakdown.get_context_specific_payloads('css_context')
        self.assertGreater(len(css_payloads), 0)
        self.assertIn('expression(alert("XSS"))', css_payloads)
        
        # Test URL context payloads
        url_payloads = self.breakdown.get_context_specific_payloads('url_context')
        self.assertGreater(len(url_payloads), 0)
        self.assertIn('javascript:alert("XSS")', url_payloads)
        
    def test_generate_testing_plan(self):
        """Test testing plan generation"""
        breakdown = {
            'forms': [{'type': 'form'}, {'type': 'form'}],
            'url_params': [{'type': 'url_params'}],
            'js_variables': [{'type': 'js_variables'}]
        }
        
        plan = self.breakdown.generate_testing_plan(breakdown)
        
        self.assertEqual(plan['total_inputs'], 4)
        self.assertEqual(plan['forms_to_test'], 2)
        self.assertEqual(plan['url_params_to_test'], 1)
        self.assertEqual(plan['js_vars_to_test'], 1)
        self.assertGreater(plan['total_tests'], 0)
        self.assertGreater(plan['estimated_time'], 0)

class TestParallelProcessing(unittest.TestCase):
    """Test cases for parallel processing functionality"""
    
    def test_parallel_execution(self):
        """Test parallel execution with ThreadPoolExecutor"""
        def test_function(x):
            time.sleep(0.1)  # Simulate work
            return x * 2
            
        inputs = [1, 2, 3, 4, 5]
        
        # Sequential execution
        start_time = time.time()
        sequential_results = [test_function(x) for x in inputs]
        sequential_time = time.time() - start_time
        
        # Parallel execution
        start_time = time.time()
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
            parallel_results = list(executor.map(test_function, inputs))
        parallel_time = time.time() - start_time
        
        # Results should be the same
        self.assertEqual(sequential_results, parallel_results)
        
        # Parallel should be faster (allowing for some variance)
        self.assertLess(parallel_time, sequential_time * 1.5)
        
    def test_concurrent_futures_completion(self):
        """Test concurrent futures completion order"""
        def test_function(x):
            time.sleep(0.1 * x)  # Variable delay
            return x
            
        inputs = [3, 1, 2, 4, 5]
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
            futures = [executor.submit(test_function, x) for x in inputs]
            results = []
            
            for future in concurrent.futures.as_completed(futures):
                results.append(future.result())
                
        # Results should contain all inputs
        self.assertEqual(set(results), set(inputs))
        
    def test_exception_handling_in_parallel(self):
        """Test exception handling in parallel execution"""
        def test_function(x):
            if x == 3:
                raise ValueError("Test error")
            return x * 2
            
        inputs = [1, 2, 3, 4, 5]
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
            futures = [executor.submit(test_function, x) for x in inputs]
            results = []
            exceptions = []
            
            for future in concurrent.futures.as_completed(futures):
                try:
                    results.append(future.result())
                except Exception as e:
                    exceptions.append(e)
                    
        # Should have 4 successful results and 1 exception
        self.assertEqual(len(results), 4)
        self.assertEqual(len(exceptions), 1)
        self.assertIsInstance(exceptions[0], ValueError)

class TestLiveProgressImprovements(unittest.TestCase):
    """Test cases for improved live progress functionality"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.progress = LiveProgress()
        
    def test_improved_progress_display(self):
        """Test improved progress display"""
        # Test progress with different values
        self.progress.show_progress(5, 10, "Testing")
        self.progress.show_progress(0, 0, "Testing")  # Edge case
        self.progress.show_progress(10, 10, "Testing")  # Complete
        
    def test_enhanced_url_discovery_display(self):
        """Test enhanced URL discovery display"""
        self.progress.show_url_discovery("https://example.com", "discovered")
        self.progress.show_url_discovery("https://example.com", "crawling")
        self.progress.show_url_discovery("https://example.com", "error")
        
    def test_detailed_input_point_display(self):
        """Test detailed input point display"""
        form_input = {
            'type': 'form',
            'url': 'https://example.com',
            'action': '/search',
            'method': 'GET',
            'inputs': [{'name': 'q', 'type': 'text'}]
        }
        self.progress.show_input_point(form_input)
        
        url_params_input = {
            'type': 'url_params',
            'url': 'https://example.com',
            'params': {'q': 'test', 'page': '1'}
        }
        self.progress.show_input_point(url_params_input)
        
        js_vars_input = {
            'type': 'javascript_variables',
            'url': 'https://example.com',
            'variables': [{'name': 'userInput', 'value': 'test'}]
        }
        self.progress.show_input_point(js_vars_input)

class TestIntegration(unittest.TestCase):
    """Integration tests for improved features"""
    
    def test_context_breakdown_integration(self):
        """Test context breakdown integration"""
        breakdown = ContextBreakdown()
        
        # Sample input points
        input_points = [
            {
                'type': 'form',
                'url': 'https://example.com/search',
                'inputs': [{'name': 'q', 'type': 'text'}]
            },
            {
                'type': 'url_params',
                'url': 'https://example.com/product?id=123',
                'params': {'id': '123'}
            }
        ]
        
        # Analyze input points
        result = breakdown.analyze_input_points(input_points)
        
        # Generate testing plan
        plan = breakdown.generate_testing_plan(result)
        
        # Verify integration
        self.assertIsNotNone(result)
        self.assertIsNotNone(plan)
        self.assertGreater(plan['total_inputs'], 0)
        
    def test_parallel_processing_integration(self):
        """Test parallel processing integration"""
        def simulate_filter_test(input_point):
            time.sleep(0.1)
            return f"Tested {input_point['type']} on {input_point['url']}"
            
        input_points = [
            {'type': 'form', 'url': 'https://example.com/form1'},
            {'type': 'form', 'url': 'https://example.com/form2'},
            {'type': 'url_params', 'url': 'https://example.com/params1'},
            {'type': 'url_params', 'url': 'https://example.com/params2'}
        ]
        
        # Test parallel processing
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            futures = [executor.submit(simulate_filter_test, ip) for ip in input_points]
            results = [future.result() for future in concurrent.futures.as_completed(futures)]
            
        self.assertEqual(len(results), len(input_points))

def run_improvement_tests():
    """Run all improvement tests"""
    # Create test suite
    test_suite = unittest.TestSuite()
    
    # Add test cases
    test_classes = [
        TestContextBreakdown,
        TestParallelProcessing,
        TestLiveProgressImprovements,
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
    success = run_improvement_tests()
    sys.exit(0 if success else 1)