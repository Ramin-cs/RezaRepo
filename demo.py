#!/usr/bin/env python3
"""
Demo script for XSS Scanner
Demonstrates the capabilities of the Professional XSS Scanner
"""

import sys
import time
from xss_scanner import XSSScanner
from context_analyzer import ContextAnalyzer
from vulnerability_detector import VulnerabilityDetector
from report_generator import ReportGenerator

def demo_context_analysis():
    """Demonstrate context analysis capabilities"""
    print("=" * 60)
    print("CONTEXT ANALYSIS DEMO")
    print("=" * 60)
    
    analyzer = ContextAnalyzer()
    
    # Test different contexts
    test_cases = [
        {
            'name': 'HTML Content Context',
            'html': '<div>User input: <script>alert("XSS")</script></div>',
            'input': '<script>alert("XSS")</script>'
        },
        {
            'name': 'HTML Attribute Context',
            'html': '<img src="image.jpg" alt="User input: " onmouseover="alert(\'XSS\')" x="">',
            'input': '" onmouseover="alert(\'XSS\')" x="'
        },
        {
            'name': 'JavaScript Context',
            'html': '<script>var userInput = ";alert("XSS");//";</script>',
            'input': '";alert("XSS");//'
        },
        {
            'name': 'CSS Context',
            'html': '<style>body { background: expression(alert("XSS")); }</style>',
            'input': 'expression(alert("XSS"))'
        }
    ]
    
    for case in test_cases:
        print(f"\n{case['name']}:")
        print("-" * 40)
        
        context_info = analyzer.analyze_input_context(
            case['html'], case['input']
        )
        
        print(f"Context Type: {context_info['context_type']}")
        print(f"Confidence: {context_info['confidence']:.2f}")
        print(f"Encoding Detected: {context_info['encoding_detected']}")
        print(f"Filter Indicators: {context_info['filter_indicators']}")
        print(f"Suggested Payloads: {len(context_info['suggested_payloads'])}")
        
        if context_info['suggested_payloads']:
            print("Sample Payloads:")
            for i, payload in enumerate(context_info['suggested_payloads'][:3]):
                print(f"  {i+1}. {payload}")

def demo_vulnerability_detection():
    """Demonstrate vulnerability detection capabilities"""
    print("\n" + "=" * 60)
    print("VULNERABILITY DETECTION DEMO")
    print("=" * 60)
    
    detector = VulnerabilityDetector()
    
    # Test different vulnerability scenarios
    test_cases = [
        {
            'name': 'Reflected XSS - Script Tag',
            'response': '<html><body><script>alert("XSS")</script></body></html>',
            'payload': '<script>alert("XSS")</script>'
        },
        {
            'name': 'Reflected XSS - Event Handler',
            'response': '<img src="image.jpg" onerror="alert(\'XSS\')">',
            'payload': '" onerror="alert(\'XSS\')"'
        },
        {
            'name': 'Reflected XSS - JavaScript URL',
            'response': '<a href="javascript:alert(\'XSS\')">Click me</a>',
            'payload': 'javascript:alert(\'XSS\')'
        },
        {
            'name': 'No Vulnerability',
            'response': '<html><body><p>Normal content</p></body></html>',
            'payload': '<script>alert("XSS")</script>'
        }
    ]
    
    for case in test_cases:
        print(f"\n{case['name']}:")
        print("-" * 40)
        
        detection = detector.detect_xss_vulnerability(
            case['response'], case['payload']
        )
        
        print(f"Vulnerable: {detection['is_vulnerable']}")
        print(f"Confidence: {detection['confidence']:.2f}")
        print(f"Vulnerability Type: {detection['vulnerability_type']}")
        print(f"Severity: {detection['severity']}")
        print(f"Evidence: {len(detection['evidence'])} items")
        
        if detection['evidence']:
            print("Evidence Details:")
            for evidence in detection['evidence']:
                print(f"  - {evidence}")

def demo_payload_generation():
    """Demonstrate payload generation capabilities"""
    print("\n" + "=" * 60)
    print("PAYLOAD GENERATION DEMO")
    print("=" * 60)
    
    analyzer = ContextAnalyzer()
    
    # Test different contexts
    contexts = ['html_content', 'html_attribute', 'javascript_context', 'css_context', 'url_context']
    
    for context in contexts:
        print(f"\n{context.replace('_', ' ').title()}:")
        print("-" * 40)
        
        payloads = analyzer._generate_context_payloads(context, [])
        
        print(f"Generated {len(payloads)} payloads:")
        for i, payload in enumerate(payloads[:5]):  # Show first 5
            print(f"  {i+1}. {payload}")
        
        if len(payloads) > 5:
            print(f"  ... and {len(payloads) - 5} more")

def demo_report_generation():
    """Demonstrate report generation capabilities"""
    print("\n" + "=" * 60)
    print("REPORT GENERATION DEMO")
    print("=" * 60)
    
    # Sample scan results
    sample_results = {
        'target_url': 'https://demo.example.com',
        'scan_timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
        'scan_duration': 120,
        'total_urls': 25,
        'vulnerabilities': [
            {
                'url': 'https://demo.example.com/search',
                'vulnerability_type': 'reflected_xss_html_context',
                'severity': 'high',
                'confidence': 0.9,
                'payload': '<script>alert("XSS")</script>',
                'evidence': ['XSS pattern 1 matched', 'Payload successfully reflected'],
                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                'context_analysis': {
                    'context_type': 'html_content',
                    'encoding_detected': False
                },
                'payload_reflected': True
            },
            {
                'url': 'https://demo.example.com/contact',
                'vulnerability_type': 'reflected_xss_attribute_context',
                'severity': 'medium',
                'confidence': 0.7,
                'payload': '" onmouseover="alert(\'XSS\')" x="',
                'evidence': ['XSS pattern 2 matched'],
                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                'context_analysis': {
                    'context_type': 'html_attribute',
                    'encoding_detected': False
                },
                'payload_reflected': True
            }
        ],
        'discovered_urls': [
            'https://demo.example.com',
            'https://demo.example.com/search',
            'https://demo.example.com/contact',
            'https://demo.example.com/about'
        ],
        'statistics': {
            'total_requests': 50,
            'successful_requests': 48,
            'failed_requests': 2
        }
    }
    
    generator = ReportGenerator("demo_reports")
    
    print("Generating reports...")
    
    # Generate different report formats
    reports = generator.generate_comprehensive_report(sample_results)
    
    print(f"\nGenerated Reports:")
    for format_name, filename in reports.items():
        print(f"  {format_name.upper()}: {filename}")
    
    # Generate executive summary
    summary = generator.generate_executive_summary(sample_results)
    print(f"\nExecutive Summary:")
    print(summary)

def demo_scanner_capabilities():
    """Demonstrate scanner capabilities"""
    print("\n" + "=" * 60)
    print("SCANNER CAPABILITIES DEMO")
    print("=" * 60)
    
    # Create scanner instance
    options = {
        'depth': 2,
        'max_urls': 10,
        'timeout': 5,
        'verbose': False
    }
    
    scanner = XSSScanner("https://httpbin.org", options)
    
    print("Scanner Configuration:")
    print(f"  Target URL: {scanner.target_url}")
    print(f"  Max Depth: {scanner.options['depth']}")
    print(f"  Max URLs: {scanner.options['max_urls']}")
    print(f"  Timeout: {scanner.options['timeout']}s")
    
    print(f"\nPayload Categories:")
    payloads = scanner._load_payloads()
    for category, payload_list in payloads.items():
        if isinstance(payload_list, list):
            print(f"  {category}: {len(payload_list)} payloads")
        elif isinstance(payload_list, dict):
            print(f"  {category}:")
            for subcategory, sub_payloads in payload_list.items():
                print(f"    {subcategory}: {len(sub_payloads)} payloads")
    
    print(f"\nScanner Features:")
    print("  ✓ Advanced reconnaissance")
    print("  ✓ Context-aware payload injection")
    print("  ✓ Filter bypass techniques")
    print("  ✓ Encoding evasion methods")
    print("  ✓ Comprehensive vulnerability detection")
    print("  ✓ Multiple report formats")
    print("  ✓ False positive reduction")
    print("  ✓ Performance optimization")

def main():
    """Main demo function"""
    print("Professional XSS Scanner - Demo")
    print("=" * 60)
    print("This demo showcases the capabilities of the XSS Scanner")
    print("including context analysis, vulnerability detection,")
    print("payload generation, and report generation.")
    print("=" * 60)
    
    try:
        # Run demos
        demo_scanner_capabilities()
        demo_context_analysis()
        demo_vulnerability_detection()
        demo_payload_generation()
        demo_report_generation()
        
        print("\n" + "=" * 60)
        print("DEMO COMPLETED SUCCESSFULLY")
        print("=" * 60)
        print("The XSS Scanner is ready for use!")
        print("Run 'python xss_scanner.py <target_url>' to start scanning.")
        
    except Exception as e:
        print(f"\nDemo error: {e}")
        print("Please check your installation and try again.")

if __name__ == '__main__':
    main()