#!/usr/bin/env python3
"""
Setup script for Professional Open Redirect Scanner
Installs dependencies and configures the environment
"""

import subprocess
import sys
import os
from pathlib import Path


def install_requirements():
    """Install Python requirements"""
    print("📦 Installing Python dependencies...")
    
    try:
        subprocess.check_call([
            sys.executable, '-m', 'pip', 'install', '-r', 'requirements.txt'
        ])
        print("✅ Python dependencies installed successfully")
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to install Python dependencies: {e}")
        return False
    
    return True


def setup_chrome_driver():
    """Setup Chrome WebDriver"""
    print("🌐 Setting up Chrome WebDriver...")
    
    try:
        # Install webdriver-manager for automatic Chrome driver management
        subprocess.check_call([
            sys.executable, '-m', 'pip', 'install', 'webdriver-manager'
        ])
        
        # Test Chrome installation
        from selenium import webdriver
        from selenium.webdriver.chrome.options import Options
        from webdriver_manager.chrome import ChromeDriverManager
        
        chrome_options = Options()
        chrome_options.add_argument('--headless')
        chrome_options.add_argument('--no-sandbox')
        chrome_options.add_argument('--disable-dev-shm-usage')
        
        # This will download and setup Chrome driver automatically
        driver = webdriver.Chrome(
            ChromeDriverManager().install(),
            options=chrome_options
        )
        driver.quit()
        
        print("✅ Chrome WebDriver setup completed")
        return True
        
    except Exception as e:
        print(f"❌ Chrome WebDriver setup failed: {e}")
        print("💡 Please install Google Chrome manually if not available")
        return False


def create_directories():
    """Create necessary directories"""
    print("📁 Creating project directories...")
    
    directories = [
        'logs',
        'screenshots',
        'reports',
        'data',
        'temp'
    ]
    
    for directory in directories:
        Path(directory).mkdir(exist_ok=True)
        print(f"   Created: {directory}/")
    
    print("✅ Directories created successfully")


def create_config_file():
    """Create default configuration file"""
    print("⚙️  Creating configuration file...")
    
    config = {
        "scanner_settings": {
            "max_depth": 3,
            "max_pages": 200,
            "request_delay": 0.1,
            "timeout": 30,
            "max_redirects": 10
        },
        "payloads": {
            "use_all_payloads": True,
            "custom_domain": "google.com",
            "test_javascript": True,
            "test_web3": True
        },
        "output": {
            "generate_html_report": True,
            "generate_json_report": True,
            "generate_csv_export": True,
            "take_screenshots": True
        },
        "advanced": {
            "enable_js_analysis": True,
            "enable_dom_analysis": True,
            "enable_dynamic_analysis": True,
            "user_agent_rotation": True
        }
    }
    
    import json
    with open('config.json', 'w') as f:
        json.dump(config, f, indent=2)
    
    print("✅ Configuration file created: config.json")


def run_tests():
    """Run basic tests to verify installation"""
    print("🧪 Running installation tests...")
    
    tests_passed = 0
    total_tests = 4
    
    # Test 1: Import main modules
    try:
        import aiohttp
        import selenium
        import beautifulsoup4
        print("✅ Test 1: Core modules import successful")
        tests_passed += 1
    except ImportError as e:
        print(f"❌ Test 1: Module import failed: {e}")
    
    # Test 2: JavaScript analysis
    try:
        import esprima
        import jsbeautifier
        print("✅ Test 2: JavaScript analysis modules available")
        tests_passed += 1
    except ImportError as e:
        print(f"❌ Test 2: JavaScript modules failed: {e}")
    
    # Test 3: Report generation
    try:
        import jinja2
        print("✅ Test 3: Report generation modules available")
        tests_passed += 1
    except ImportError as e:
        print(f"❌ Test 3: Report modules failed: {e}")
    
    # Test 4: Chrome WebDriver
    try:
        from selenium import webdriver
        from selenium.webdriver.chrome.options import Options
        
        chrome_options = Options()
        chrome_options.add_argument('--headless')
        chrome_options.add_argument('--no-sandbox')
        chrome_options.add_argument('--disable-dev-shm-usage')
        
        # Quick test
        driver = webdriver.Chrome(options=chrome_options)
        driver.get("data:text/html,<html><body>Test</body></html>")
        driver.quit()
        
        print("✅ Test 4: Chrome WebDriver functional")
        tests_passed += 1
    except Exception as e:
        print(f"❌ Test 4: Chrome WebDriver test failed: {e}")
    
    print(f"\n📊 Tests completed: {tests_passed}/{total_tests} passed")
    return tests_passed == total_tests


def main():
    """Main setup function"""
    print("🚀 Professional Open Redirect Scanner Setup")
    print("=" * 50)
    
    setup_steps = [
        ("Installing Python dependencies", install_requirements),
        ("Creating project directories", create_directories),
        ("Setting up Chrome WebDriver", setup_chrome_driver),
        ("Creating configuration file", create_config_file),
        ("Running installation tests", run_tests)
    ]
    
    for step_name, step_func in setup_steps:
        print(f"\n{step_name}...")
        if not step_func():
            print(f"❌ Setup failed at: {step_name}")
            return False
    
    print("\n" + "=" * 50)
    print("🎉 Setup completed successfully!")
    print("\n📖 Usage:")
    print("   python enhanced_scanner.py <target_url>")
    print("   python enhanced_scanner.py https://example.com --depth 4 --max-pages 300")
    print("\n📁 Output files will be saved in:")
    print("   📊 Reports: ./reports/")
    print("   📸 Screenshots: ./screenshots/")
    print("   📋 Logs: ./logs/")
    print("   💾 Data: ./data/")
    
    return True


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)