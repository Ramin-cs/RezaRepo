#!/usr/bin/env python3
"""
Test script for Advanced XSS Scanner
This script tests the scanner against a local vulnerable application
"""

import subprocess
import time
import json
import os
import signal
import sys
from threading import Thread

def start_test_app():
    """Start the test vulnerable application"""
    print("Starting test vulnerable application...")
    process = subprocess.Popen([
        sys.executable, 'test_vulnerable_app.py'
    ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return process

def run_scanner():
    """Run the XSS scanner against the test application"""
    print("Running XSS scanner against test application...")
    try:
        result = subprocess.run([
            sys.executable, 'advanced_xss_scanner.py', 'http://localhost:5000'
        ], capture_output=True, text=True, timeout=300)
        
        print("Scanner output:")
        print(result.stdout)
        
        if result.stderr:
            print("Scanner errors:")
            print(result.stderr)
        
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        print("Scanner timed out after 5 minutes")
        return False
    except Exception as e:
        print(f"Error running scanner: {e}")
        return False

def check_results():
    """Check if the scanner found vulnerabilities"""
    print("\nChecking results...")
    
    # Check if reports exist
    if os.path.exists('recon_report.json'):
        print("✓ Reconnaissance report generated")
        with open('recon_report.json', 'r') as f:
            recon_data = json.load(f)
            print(f"  - URLs discovered: {len(recon_data.get('discovered_urls', []))}")
            print(f"  - Forms found: {len(recon_data.get('forms', []))}")
            print(f"  - Parameters found: {len(recon_data.get('parameters', []))}")
    else:
        print("✗ Reconnaissance report not found")
    
    if os.path.exists('xss_report.json'):
        print("✓ XSS vulnerability report generated")
        with open('xss_report.json', 'r') as f:
            xss_data = json.load(f)
            vulns = xss_data.get('vulnerabilities', [])
            print(f"  - Vulnerabilities found: {len(vulns)}")
            
            for i, vuln in enumerate(vulns, 1):
                print(f"    {i}. {vuln.get('type', 'Unknown')} in {vuln.get('url', 'Unknown')}")
                print(f"       Parameter: {vuln.get('parameter', 'Unknown')}")
                print(f"       Context: {vuln.get('context', 'Unknown')}")
                print(f"       Payload: {vuln.get('payload', 'Unknown')}")
                if 'screenshot' in vuln:
                    print(f"       Screenshot: {vuln['screenshot']}")
    else:
        print("✗ XSS vulnerability report not found")
    
    # Check for screenshots
    screenshots = [f for f in os.listdir('.') if f.startswith('xss_poc_') and f.endswith('.png')]
    if screenshots:
        print(f"✓ Screenshots captured: {len(screenshots)}")
        for screenshot in screenshots:
            print(f"  - {screenshot}")
    else:
        print("✗ No screenshots captured")

def main():
    """Main test function"""
    print("=" * 60)
    print("Advanced XSS Scanner - Test Suite")
    print("=" * 60)
    
    # Check if required files exist
    required_files = [
        'advanced_xss_scanner.py',
        'test_vulnerable_app.py',
        'requirements.txt'
    ]
    
    for file in required_files:
        if not os.path.exists(file):
            print(f"✗ Required file not found: {file}")
            return False
        else:
            print(f"✓ Found: {file}")
    
    # Install dependencies
    print("\nInstalling dependencies...")
    try:
        subprocess.run([sys.executable, '-m', 'pip', 'install', '-r', 'requirements.txt'], 
                      check=True, capture_output=True)
        print("✓ Dependencies installed")
    except subprocess.CalledProcessError as e:
        print(f"✗ Failed to install dependencies: {e}")
        return False
    
    # Start test application
    test_app = start_test_app()
    
    try:
        # Wait for test app to start
        print("Waiting for test application to start...")
        time.sleep(3)
        
        # Run scanner
        success = run_scanner()
        
        if success:
            print("✓ Scanner completed successfully")
        else:
            print("✗ Scanner failed")
        
        # Check results
        check_results()
        
        return success
        
    finally:
        # Clean up
        print("\nCleaning up...")
        test_app.terminate()
        test_app.wait()
        print("✓ Test application stopped")

if __name__ == "__main__":
    success = main()
    if success:
        print("\n✓ Test completed successfully!")
        sys.exit(0)
    else:
        print("\n✗ Test failed!")
        sys.exit(1)