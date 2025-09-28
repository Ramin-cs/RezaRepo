#!/usr/bin/env python3
"""
Main entry point for Open Redirect Scanner
Comprehensive scanner with all modules integrated
"""

import asyncio
import argparse
import sys
import os
from pathlib import Path
from typing import Optional

# Add current directory to Python path
sys.path.insert(0, str(Path(__file__).parent))

from open_redirect_scanner import OpenRedirectScanner
from configuration import ConfigManager, load_config_from_env, get_preset_config, validate_and_fix_config

def print_banner():
    """Print scanner banner"""
    banner = """
    ╔══════════════════════════════════════════════════════════════╗
    ║                                                              ║
    ║           🔍 Open Redirect Vulnerability Scanner            ║
    ║                                                              ║
    ║              Advanced Security Testing Tool                  ║
    ║                                                              ║
    ║  Features:                                                   ║
    ║  • Comprehensive Reconnaissance                             ║
    ║  • Advanced WAF Bypass Techniques                           ║
    ║  • Chrome-based Automation                                  ║
    ║  • Screenshot Capture for PoC                               ║
    ║  • Parallel Processing                                      ║
    ║  • Professional HTML Reports                                ║
    ║                                                              ║
    ╚══════════════════════════════════════════════════════════════╝
    """
    print(banner)

def print_usage():
    """Print usage information"""
    usage = """
    Usage Examples:
    
    Basic scan:
        python main.py https://target-website.com
    
    Advanced scan with custom settings:
        python main.py https://target-website.com -o results -t 20 -d 3
    
    Using configuration file:
        python main.py -c config.json
    
    Using preset configuration:
        python main.py https://target-website.com --preset thorough
    
    Environment variables:
        TARGET_URL=https://target-website.com python main.py
        MAX_THREADS=20 python main.py https://target-website.com
    
    Available presets:
        fast      - Fast scan with minimal depth
        thorough  - Comprehensive scan with full depth
        stealth   - Stealth scan with delays
        debug     - Debug mode with detailed logging
    """
    print(usage)

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="Advanced Open Redirect Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=print_usage()
    )
    
    # Target URL
    parser.add_argument(
        'target',
        nargs='?',
        help='Target URL to scan'
    )
    
    # Output directory
    parser.add_argument(
        '-o', '--output',
        default='scan_results',
        help='Output directory for results (default: scan_results)'
    )
    
    # Threads
    parser.add_argument(
        '-t', '--threads',
        type=int,
        default=10,
        help='Number of parallel threads (default: 10)'
    )
    
    # Max depth
    parser.add_argument(
        '-d', '--depth',
        type=int,
        default=3,
        help='Maximum crawling depth (default: 3)'
    )
    
    # Timeout
    parser.add_argument(
        '--timeout',
        type=int,
        default=30,
        help='Request timeout in seconds (default: 30)'
    )
    
    # Configuration file
    parser.add_argument(
        '-c', '--config',
        help='Configuration file path'
    )
    
    # Preset configuration
    parser.add_argument(
        '--preset',
        choices=['fast', 'thorough', 'stealth', 'debug'],
        help='Use preset configuration'
    )
    
    # Chrome settings
    parser.add_argument(
        '--no-headless',
        action='store_true',
        help='Run Chrome in visible mode (not headless)'
    )
    
    parser.add_argument(
        '--chrome-window-size',
        default='1920,1080',
        help='Chrome window size (default: 1920,1080)'
    )
    
    # Scanning options
    parser.add_argument(
        '--no-recon',
        action='store_true',
        help='Skip reconnaissance phase'
    )
    
    parser.add_argument(
        '--no-payloads',
        action='store_true',
        help='Skip payload testing phase'
    )
    
    parser.add_argument(
        '--no-screenshots',
        action='store_true',
        help='Skip screenshot capture'
    )
    
    parser.add_argument(
        '--no-parallel',
        action='store_true',
        help='Disable parallel processing'
    )
    
    # Payload options
    parser.add_argument(
        '--max-payloads',
        type=int,
        default=100,
        help='Maximum payloads per parameter (default: 100)'
    )
    
    parser.add_argument(
        '--no-waf-bypass',
        action='store_true',
        help='Disable WAF bypass techniques'
    )
    
    parser.add_argument(
        '--custom-payloads',
        help='Custom payload file path'
    )
    
    # Logging options
    parser.add_argument(
        '--log-level',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
        default='INFO',
        help='Log level (default: INFO)'
    )
    
    parser.add_argument(
        '--no-log-file',
        action='store_true',
        help='Disable logging to file'
    )
    
    parser.add_argument(
        '--no-log-console',
        action='store_true',
        help='Disable console logging'
    )
    
    # Report options
    parser.add_argument(
        '--no-html-report',
        action='store_true',
        help='Disable HTML report generation'
    )
    
    parser.add_argument(
        '--no-json-report',
        action='store_true',
        help='Disable JSON report generation'
    )
    
    parser.add_argument(
        '--no-screenshots-report',
        action='store_true',
        help='Exclude screenshots from reports'
    )
    
    # Security options
    parser.add_argument(
        '--ignore-robots',
        action='store_true',
        help='Ignore robots.txt'
    )
    
    parser.add_argument(
        '--max-requests-per-second',
        type=int,
        default=10,
        help='Maximum requests per second (default: 10)'
    )
    
    parser.add_argument(
        '--delay',
        type=float,
        default=0.1,
        help='Delay between requests in seconds (default: 0.1)'
    )
    
    # Target domain
    parser.add_argument(
        '--target-domain',
        default='google.com',
        help='Target domain for redirect validation (default: google.com)'
    )
    
    # Proxy settings
    parser.add_argument(
        '--proxy-url',
        help='Proxy URL (e.g., http://proxy:8080)'
    )
    
    parser.add_argument(
        '--proxy-username',
        help='Proxy username'
    )
    
    parser.add_argument(
        '--proxy-password',
        help='Proxy password'
    )
    
    # WAF bypass options
    parser.add_argument(
        '--no-encoding-bypass',
        action='store_true',
        help='Disable encoding bypass techniques'
    )
    
    parser.add_argument(
        '--no-case-variations',
        action='store_true',
        help='Disable case variation techniques'
    )
    
    parser.add_argument(
        '--no-whitespace-variations',
        action='store_true',
        help='Disable whitespace variation techniques'
    )
    
    parser.add_argument(
        '--no-control-characters',
        action='store_true',
        help='Disable control character techniques'
    )
    
    parser.add_argument(
        '--no-unicode-attacks',
        action='store_true',
        help='Disable Unicode attack techniques'
    )
    
    # Other options
    parser.add_argument(
        '--version',
        action='version',
        version='Open Redirect Scanner 1.0.0'
    )
    
    parser.add_argument(
        '--help-examples',
        action='store_true',
        help='Show usage examples'
    )
    
    return parser.parse_args()

def create_config_from_args(args) -> 'ScannerConfig':
    """Create configuration from command line arguments"""
    from configuration import ScannerConfig
    
    config = ScannerConfig()
    
    # Basic settings
    if args.target:
        config.target_url = args.target
    
    config.output_dir = args.output
    config.max_threads = args.threads
    config.max_depth = args.depth
    config.timeout = args.timeout
    
    # Chrome settings
    config.chrome_headless = not args.no_headless
    config.chrome_window_size = args.chrome_window_size
    
    # Scanning options
    config.enable_recon = not args.no_recon
    config.enable_payload_testing = not args.no_payloads
    config.enable_screenshot = not args.no_screenshots
    config.enable_parallel_processing = not args.no_parallel
    
    # Payload options
    config.max_payloads_per_parameter = args.max_payloads
    config.enable_waf_bypass = not args.no_waf_bypass
    config.custom_payload_file = args.custom_payloads
    
    # Logging options
    config.log_level = args.log_level
    config.log_to_file = not args.no_log_file
    config.log_to_console = not args.no_log_console
    
    # Report options
    config.generate_html_report = not args.no_html_report
    config.generate_json_report = not args.no_json_report
    config.include_screenshots = not args.no_screenshots_report
    
    # Security options
    config.respect_robots_txt = not args.ignore_robots
    config.max_requests_per_second = args.max_requests_per_second
    config.delay_between_requests = args.delay
    
    # Target domain
    config.target_domain = args.target_domain
    
    # Proxy settings
    config.proxy_url = args.proxy_url
    config.proxy_username = args.proxy_username
    config.proxy_password = args.proxy_password
    
    # WAF bypass options
    config.enable_encoding_bypass = not args.no_encoding_bypass
    config.enable_case_variations = not args.no_case_variations
    config.enable_whitespace_variations = not args.no_whitespace_variations
    config.enable_control_characters = not args.no_control_characters
    config.enable_unicode_attacks = not args.no_unicode_attacks
    
    return config

async def main():
    """Main function"""
    try:
        # Parse arguments
        args = parse_arguments()
        
        # Show help examples if requested
        if args.help_examples:
            print_usage()
            return
        
        # Print banner
        print_banner()
        
        # Load configuration
        config_manager = ConfigManager()
        
        if args.config:
            # Load from config file
            config = config_manager.load_config(args.config)
        elif args.preset:
            # Load preset configuration
            config = get_preset_config(args.preset)
            if args.target:
                config.target_url = args.target
        else:
            # Load from environment variables
            config = load_config_from_env()
            
            # Override with command line arguments
            if args.target:
                config.target_url = args.target
            
            # Apply command line overrides
            config = create_config_from_args(args)
        
        # Validate and fix configuration
        config = validate_and_fix_config(config)
        
        # Check if target URL is provided
        if not config.target_url:
            print("❌ Error: Target URL is required")
            print("Usage: python main.py <target_url>")
            print("Or use --help for more options")
            sys.exit(1)
        
        # Print configuration summary
        print(f"🎯 Target: {config.target_url}")
        print(f"📁 Output: {config.output_dir}")
        print(f"🧵 Threads: {config.max_threads}")
        print(f"🔍 Depth: {config.max_depth}")
        print(f"⏱️ Timeout: {config.timeout}s")
        print(f"🌐 Target Domain: {config.target_domain}")
        print(f"📊 Log Level: {config.log_level}")
        print("-" * 60)
        
        # Create scanner instance
        scanner = OpenRedirectScanner(
            config.target_url,
            config.output_dir,
            config.max_threads
        )
        
        # Run scan
        print("🚀 Starting scan...")
        
        if await scanner.initialize():
            print("✅ Scanner initialized successfully")
            await scanner.scan()
            print("✅ Scan completed successfully")
        else:
            print("❌ Failed to initialize scanner")
            sys.exit(1)
        
        # Cleanup
        await scanner.cleanup()
        print("🧹 Cleanup completed")
        
        print("\n🎉 Scan completed successfully!")
        print(f"📁 Results saved to: {config.output_dir}")
        print("📊 Check the generated reports for detailed results")
        
    except KeyboardInterrupt:
        print("\n⚠️ Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Fatal error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())