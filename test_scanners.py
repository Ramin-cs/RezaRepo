#!/usr/bin/env python3
"""
Test script to debug scanner modules
Author: AI Assistant
"""

import sys
import traceback

def test_imports():
    """Test if all modules can be imported"""
    print("Testing imports...")
    
    try:
        from technology_detector import TechnologyDetector
        print("✅ TechnologyDetector imported successfully")
    except Exception as e:
        print(f"❌ TechnologyDetector import failed: {e}")
        traceback.print_exc()
    
    try:
        from traditional_scanner import TraditionalScanner
        print("✅ TraditionalScanner imported successfully")
    except Exception as e:
        print(f"❌ TraditionalScanner import failed: {e}")
        traceback.print_exc()
    
    try:
        from modern_spa_scanner import ModernSPAScanner
        print("✅ ModernSPAScanner imported successfully")
    except Exception as e:
        print(f"❌ ModernSPAScanner import failed: {e}")
        traceback.print_exc()
    
    try:
        from hybrid_scanner import HybridScanner
        print("✅ HybridScanner imported successfully")
    except Exception as e:
        print(f"❌ HybridScanner import failed: {e}")
        traceback.print_exc()

def test_technology_detection():
    """Test technology detection"""
    print("\nTesting technology detection...")
    
    try:
        from technology_detector import TechnologyDetector
        detector = TechnologyDetector()
        result = detector.detect_technology("http://testphp.vulnweb.com")
        print(f"✅ Detection result: {result}")
    except Exception as e:
        print(f"❌ Technology detection failed: {e}")
        traceback.print_exc()

def test_traditional_scanner():
    """Test traditional scanner"""
    print("\nTesting traditional scanner...")
    
    try:
        from traditional_scanner import TraditionalScanner
        scanner = TraditionalScanner("http://testphp.vulnweb.com")
        vulnerabilities = scanner.scan()
        print(f"✅ Traditional scanner completed. Found {len(vulnerabilities)} vulnerabilities")
        if vulnerabilities:
            print("Sample vulnerability:", vulnerabilities[0])
    except Exception as e:
        print(f"❌ Traditional scanner failed: {e}")
        traceback.print_exc()

if __name__ == "__main__":
    test_imports()
    test_technology_detection()
    test_traditional_scanner()