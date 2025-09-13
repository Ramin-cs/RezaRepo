#!/usr/bin/env python3
"""
Live Demo for XSS Scanner
Demonstrates live progress tracking and Chrome execution
"""

import sys
import time
from xss_scanner import XSSScanner
from live_progress import live_progress

def demo_live_scanning():
    """Demonstrate live scanning with progress tracking"""
    print("=" * 60)
    print("LIVE XSS SCANNER DEMO")
    print("=" * 60)
    print("This demo shows live progress tracking and Chrome execution")
    print("Watch as the scanner discovers URLs, analyzes filters, and tests payloads")
    print("=" * 60)
    
    # Test with a simple target
    target_url = "https://httpbin.org"
    
    # Scanner options
    options = {
        'depth': 1,
        'max_urls': 5,
        'timeout': 10,
        'verbose': True,
        'headless': False  # Show Chrome browser
    }
    
    print(f"Target: {target_url}")
    print(f"Options: {options}")
    print("\nStarting live scan...")
    print("=" * 60)
    
    try:
        # Initialize scanner
        scanner = XSSScanner(target_url, options)
        
        # Start live progress tracking
        live_progress.start_phase("Live Demo", "Demonstrating live XSS scanning with Chrome execution")
        
        # Run scan
        scanner.scan_target()
        
        # Show final results
        live_progress.show_final_summary()
        
    except Exception as e:
        live_progress.show_error(f"Demo failed: {e}")
        print(f"Error: {e}")
        
    finally:
        live_progress.stop()

def demo_live_progress():
    """Demonstrate live progress features"""
    print("=" * 60)
    print("LIVE PROGRESS DEMO")
    print("=" * 60)
    
    # Simulate different phases
    phases = [
        ("URL Discovery", "Discovering all accessible URLs"),
        ("Input Point Discovery", "Finding user input points"),
        ("Character Filter Analysis", "Testing character filters"),
        ("Context Analysis", "Analyzing injection contexts"),
        ("Vulnerability Testing", "Testing XSS payloads with Chrome")
    ]
    
    for phase_name, description in phases:
        live_progress.start_phase(phase_name, description)
        
        # Simulate progress
        for i in range(5):
            live_progress.update_task(f"Processing item {i+1}/5")
            live_progress.show_progress(i+1, 5, f"Phase: {phase_name}")
            time.sleep(0.5)
            
        # Simulate some results
        results = {
            'items_processed': 5,
            'successful': 4,
            'failed': 1
        }
        
        live_progress.show_phase_complete(phase_name, results)
        time.sleep(1)
        
    # Simulate vulnerability found
    vulnerability = {
        'url': 'https://demo.example.com/search',
        'payload': '<script>alert("XSS")</script>',
        'context_type': 'html_content'
    }
    
    live_progress.show_vulnerability_found(vulnerability)
    live_progress.show_chrome_execution(vulnerability['url'], vulnerability['payload'])
    live_progress.show_alert_detected()
    live_progress.show_screenshot_capture("screenshot_1234567890.png")
    
    # Show final summary
    live_progress.show_final_summary()

def main():
    """Main demo function"""
    print("XSS Scanner - Live Demo")
    print("=" * 60)
    print("Choose demo mode:")
    print("1. Live Progress Demo (simulated)")
    print("2. Live Scanning Demo (real scan)")
    print("=" * 60)
    
    try:
        choice = input("Enter choice (1 or 2): ").strip()
        
        if choice == "1":
            demo_live_progress()
        elif choice == "2":
            demo_live_scanning()
        else:
            print("Invalid choice. Running live progress demo...")
            demo_live_progress()
            
    except KeyboardInterrupt:
        print("\nDemo interrupted by user.")
    except Exception as e:
        print(f"Demo error: {e}")
    finally:
        live_progress.stop()

if __name__ == '__main__':
    main()