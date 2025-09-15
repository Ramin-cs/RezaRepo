#!/usr/bin/env python3
"""
Improved Demo for XSS Scanner
Demonstrates improved live progress, context breakdown, and parallel processing
"""

import sys
import time
from xss_scanner import XSSScanner
from live_progress import live_progress

def demo_improved_scanning():
    """Demonstrate improved scanning with live progress and context breakdown"""
    print("=" * 60)
    print("IMPROVED XSS SCANNER DEMO")
    print("=" * 60)
    print("This demo shows improved features:")
    print("- Live progress tracking for all phases")
    print("- Context breakdown analysis")
    print("- Parallel processing for character filter analysis")
    print("- Optimized testing with reduced timeouts")
    print("=" * 60)
    
    # Test with a vulnerable target
    target_url = "http://testphp.vulnweb.com/"
    
    # Scanner options
    options = {
        'depth': 2,
        'max_urls': 20,
        'timeout': 5,
        'verbose': True,
        'headless': False  # Show Chrome browser
    }
    
    print(f"Target: {target_url}")
    print(f"Options: {options}")
    print("\nStarting improved scan...")
    print("=" * 60)
    
    try:
        # Initialize scanner
        scanner = XSSScanner(target_url, options)
        
        # Start live progress tracking
        live_progress.start_phase("Improved Demo", "Demonstrating improved XSS scanning with live progress")
        
        # Run scan
        scanner.scan_target()
        
        # Show final results
        live_progress.show_final_summary()
        
    except Exception as e:
        live_progress.show_error(f"Demo failed: {e}")
        print(f"Error: {e}")
        
    finally:
        live_progress.stop()

def demo_context_breakdown():
    """Demonstrate context breakdown analysis"""
    print("=" * 60)
    print("CONTEXT BREAKDOWN DEMO")
    print("=" * 60)
    
    from context_breakdown import ContextBreakdown
    
    # Sample input points
    sample_input_points = [
        {
            'type': 'form',
            'url': 'https://example.com/search',
            'action': '/search',
            'method': 'GET',
            'inputs': [
                {'name': 'q', 'type': 'text', 'placeholder': 'Search...'},
                {'name': 'category', 'type': 'select', 'value': 'all'}
            ]
        },
        {
            'type': 'form',
            'url': 'https://example.com/contact',
            'action': '/contact',
            'method': 'POST',
            'inputs': [
                {'name': 'name', 'type': 'text', 'placeholder': 'Your name'},
                {'name': 'email', 'type': 'email', 'placeholder': 'Your email'},
                {'name': 'message', 'type': 'textarea', 'placeholder': 'Your message'}
            ]
        },
        {
            'type': 'url_params',
            'url': 'https://example.com/product?id=123&category=electronics',
            'params': {'id': '123', 'category': 'electronics'}
        },
        {
            'type': 'url_params',
            'url': 'https://example.com/search?q=test&page=1',
            'params': {'q': 'test', 'page': '1'}
        },
        {
            'type': 'javascript_variables',
            'url': 'https://example.com/dashboard',
            'variables': [
                {'name': 'userInput', 'value': 'test'},
                {'name': 'searchQuery', 'value': 'example'}
            ]
        }
    ]
    
    # Create context breakdown analyzer
    breakdown_analyzer = ContextBreakdown()
    
    # Analyze input points
    context_breakdown = breakdown_analyzer.analyze_input_points(sample_input_points)
    
    # Generate testing plan
    testing_plan = breakdown_analyzer.generate_testing_plan(context_breakdown)
    
    from colorama import Fore, Style
    print(f"\n{Fore.GREEN}📊 TESTING PLAN:{Style.RESET_ALL}")
    print(f"  Total Input Points: {testing_plan['total_inputs']}")
    print(f"  Forms to Test: {testing_plan['forms_to_test']}")
    print(f"  URL Parameters to Test: {testing_plan['url_params_to_test']}")
    print(f"  JS Variables to Test: {testing_plan['js_vars_to_test']}")
    print(f"  Total Tests: {testing_plan['total_tests']}")
    print(f"  Estimated Time: {testing_plan['estimated_time']} seconds")

def demo_parallel_processing():
    """Demonstrate parallel processing capabilities"""
    print("=" * 60)
    print("PARALLEL PROCESSING DEMO")
    print("=" * 60)
    
    import concurrent.futures
    import time
    
    def simulate_character_filter_test(input_point):
        """Simulate character filter testing"""
        time.sleep(0.5)  # Simulate network request
        return f"Tested {input_point}"
    
    # Sample input points
    input_points = [
        {'type': 'form', 'url': 'https://example.com/form1'},
        {'type': 'form', 'url': 'https://example.com/form2'},
        {'type': 'url_params', 'url': 'https://example.com/params1'},
        {'type': 'url_params', 'url': 'https://example.com/params2'},
        {'type': 'form', 'url': 'https://example.com/form3'},
        {'type': 'url_params', 'url': 'https://example.com/params3'},
        {'type': 'form', 'url': 'https://example.com/form4'},
        {'type': 'url_params', 'url': 'https://example.com/params4'},
        {'type': 'form', 'url': 'https://example.com/form5'},
        {'type': 'url_params', 'url': 'https://example.com/params5'}
    ]
    
    print(f"Testing {len(input_points)} input points...")
    
    # Sequential processing
    print(f"\n{Fore.YELLOW}🔄 Sequential Processing:{Style.RESET_ALL}")
    start_time = time.time()
    for input_point in input_points:
        result = simulate_character_filter_test(input_point)
        print(f"  {result}")
    sequential_time = time.time() - start_time
    print(f"  Sequential time: {sequential_time:.2f} seconds")
    
    # Parallel processing
    print(f"\n{Fore.GREEN}⚡ Parallel Processing:{Style.RESET_ALL}")
    start_time = time.time()
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(simulate_character_filter_test, input_point) for input_point in input_points]
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            print(f"  {result}")
    parallel_time = time.time() - start_time
    print(f"  Parallel time: {parallel_time:.2f} seconds")
    
    # Calculate speedup
    speedup = sequential_time / parallel_time
    print(f"\n{Fore.CYAN}📈 Performance Improvement:{Style.RESET_ALL}")
    print(f"  Speedup: {speedup:.2f}x faster")
    print(f"  Time saved: {sequential_time - parallel_time:.2f} seconds")

def main():
    """Main demo function"""
    print("XSS Scanner - Improved Features Demo")
    print("=" * 60)
    print("Choose demo mode:")
    print("1. Context Breakdown Demo")
    print("2. Parallel Processing Demo")
    print("3. Improved Scanning Demo (real scan)")
    print("=" * 60)
    
    try:
        choice = input("Enter choice (1, 2, or 3): ").strip()
        
        if choice == "1":
            demo_context_breakdown()
        elif choice == "2":
            demo_parallel_processing()
        elif choice == "3":
            demo_improved_scanning()
        else:
            print("Invalid choice. Running context breakdown demo...")
            demo_context_breakdown()
            
    except KeyboardInterrupt:
        print("\nDemo interrupted by user.")
    except Exception as e:
        print(f"Demo error: {e}")
    finally:
        live_progress.stop()

if __name__ == '__main__':
    main()