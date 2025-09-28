#!/usr/bin/env python3
"""
Professional Open Redirect Scanner Runner
Comprehensive scanner with all advanced modules integrated
"""

import asyncio
import argparse
import sys
import os
import time
import json
from pathlib import Path
from typing import Optional, Dict, List, Any
from datetime import datetime
import logging

# Import our advanced modules
from professional_open_redirect_scanner import ProfessionalOpenRedirectScanner
from advanced_chrome_module import AdvancedChromeModule
from advanced_payload_module import AdvancedPayloadModule
from advanced_recon_module import AdvancedReconModule
from advanced_testing_module import AdvancedTestingModule

class ProfessionalRunner:
    """
    Professional runner for Open Redirect Scanner
    Integrates all advanced modules for comprehensive testing
    """
    
    def __init__(self, target_url: str, output_dir: str = "scan_results", 
                 max_threads: int = 10, max_depth: int = 3, timeout: int = 30,
                 target_domain: str = "google.com", headless: bool = True):
        self.target_url = target_url
        self.output_dir = Path(output_dir)
        self.max_threads = max_threads
        self.max_depth = max_depth
        self.timeout = timeout
        self.target_domain = target_domain
        self.headless = headless
        
        # Create output directory
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Setup logging
        self._setup_logging()
        
        # Initialize modules
        self.scanner = None
        self.chrome_module = None
        self.payload_module = None
        self.recon_module = None
        self.testing_module = None
        
        # Results
        self.scan_results = {
            'target_url': target_url,
            'start_time': None,
            'end_time': None,
            'duration': 0,
            'vulnerabilities': [],
            'injection_points': [],
            'performance_metrics': {},
            'scan_summary': {}
        }
    
    def _setup_logging(self):
        """Setup comprehensive logging"""
        log_dir = self.output_dir / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)
        
        # Create logger
        self.logger = logging.getLogger('ProfessionalRunner')
        self.logger.setLevel(logging.INFO)
        
        # Clear existing handlers
        self.logger.handlers.clear()
        
        # Console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.INFO)
        console_formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s',
            datefmt='%H:%M:%S'
        )
        console_handler.setFormatter(console_formatter)
        self.logger.addHandler(console_handler)
        
        # File handler
        log_file = log_dir / f"professional_runner_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        file_handler.setLevel(logging.DEBUG)
        file_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(file_formatter)
        self.logger.addHandler(file_handler)
        
        # Prevent duplicate logs
        self.logger.propagate = False
    
    async def initialize(self) -> bool:
        """Initialize all modules"""
        try:
            self.logger.info("🚀 Initializing Professional Open Redirect Scanner...")
            
            # Initialize main scanner
            self.scanner = ProfessionalOpenRedirectScanner(
                self.target_url,
                str(self.output_dir),
                self.max_threads,
                self.max_depth,
                self.timeout,
                self.target_domain
            )
            
            # Initialize Chrome module
            self.chrome_module = AdvancedChromeModule(
                self.logger,
                self.output_dir,
                self.target_domain
            )
            
            # Initialize payload module
            self.payload_module = AdvancedPayloadModule(
                self.logger,
                self.target_domain
            )
            
            # Initialize recon module
            self.recon_module = AdvancedReconModule(
                self.logger,
                self.max_depth,
                self.max_threads
            )
            
            # Initialize testing module
            self.testing_module = AdvancedTestingModule(
                self.logger,
                self.target_domain
            )
            
            # Initialize all modules
            if not await self.scanner.initialize():
                self.logger.error("❌ Failed to initialize main scanner")
                return False
            
            if not await self.chrome_module.initialize(self.headless):
                self.logger.warning("⚠️ Chrome module initialization failed, continuing without Chrome")
            
            if not await self.recon_module.initialize(self.scanner.session):
                self.logger.error("❌ Failed to initialize recon module")
                return False
            
            if not await self.testing_module.initialize(self.scanner.session):
                self.logger.error("❌ Failed to initialize testing module")
                return False
            
            self.logger.info("✅ All modules initialized successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"❌ Failed to initialize: {str(e)}")
            return False
    
    async def run_comprehensive_scan(self) -> bool:
        """Run comprehensive scan with all modules"""
        try:
            self.scan_results['start_time'] = datetime.now().isoformat()
            start_time = time.time()
            
            self.logger.info("🎯 Starting comprehensive Open Redirect scan...")
            self.logger.info(f"Target: {self.target_url}")
            self.logger.info(f"Output: {self.output_dir}")
            self.logger.info(f"Threads: {self.max_threads}")
            self.logger.info(f"Depth: {self.max_depth}")
            self.logger.info(f"Target Domain: {self.target_domain}")
            self.logger.info("-" * 60)
            
            # Phase 1: Advanced Reconnaissance
            self.logger.info("🔍 Phase 1: Advanced Reconnaissance...")
            recon_results = await self.recon_module.perform_recon(self.target_url)
            
            if not recon_results:
                self.logger.error("❌ Reconnaissance failed, aborting scan")
                return False
            
            injection_points = recon_results.get('injection_points', [])
            self.scan_results['injection_points'] = injection_points
            
            self.logger.info(f"✅ Found {len(injection_points)} injection points")
            
            # Phase 2: Advanced Payload Generation
            self.logger.info("🧪 Phase 2: Advanced Payload Generation...")
            payloads = self.payload_module.generate_payloads(f"//{self.target_domain}")
            
            self.logger.info(f"✅ Generated {len(payloads)} payloads")
            
            # Phase 3: Advanced Testing
            self.logger.info("🎯 Phase 3: Advanced Testing...")
            vulnerabilities = await self._test_all_injection_points(injection_points, payloads)
            
            self.scan_results['vulnerabilities'] = vulnerabilities
            
            # Phase 4: Chrome-based Testing (if available)
            if self.chrome_module.driver:
                self.logger.info("🌐 Phase 4: Chrome-based Testing...")
                chrome_vulnerabilities = await self._test_with_chrome(injection_points, payloads)
                self.scan_results['vulnerabilities'].extend(chrome_vulnerabilities)
            
            # Phase 5: Generate Reports
            self.logger.info("📊 Phase 5: Report Generation...")
            await self._generate_comprehensive_reports()
            
            # Calculate metrics
            end_time = time.time()
            self.scan_results['end_time'] = datetime.now().isoformat()
            self.scan_results['duration'] = end_time - start_time
            
            # Performance metrics
            self.scan_results['performance_metrics'] = {
                'total_tests': self.testing_module.get_performance_metrics().get('total_tests', 0),
                'successful_tests': self.testing_module.get_performance_metrics().get('successful_tests', 0),
                'failed_tests': self.testing_module.get_performance_metrics().get('failed_tests', 0),
                'scan_duration': self.scan_results['duration'],
                'vulnerabilities_found': len(self.scan_results['vulnerabilities']),
                'injection_points_tested': len(injection_points),
                'payloads_tested': len(payloads)
            }
            
            # Scan summary
            self.scan_results['scan_summary'] = self._generate_scan_summary()
            
            self.logger.info(f"✅ Scan completed successfully!")
            self.logger.info(f"Duration: {self.scan_results['duration']:.2f} seconds")
            self.logger.info(f"Vulnerabilities found: {len(self.scan_results['vulnerabilities'])}")
            self.logger.info(f"Results saved to: {self.output_dir}")
            
            return True
            
        except Exception as e:
            self.logger.error(f"❌ Scan failed: {str(e)}")
            return False
    
    async def _test_all_injection_points(self, injection_points: List[Dict], payloads: List[str]) -> List[Dict]:
        """Test all injection points with all payloads"""
        vulnerabilities = []
        
        try:
            total_tests = len(injection_points) * len(payloads)
            self.logger.info(f"🧪 Testing {total_tests} combinations...")
            
            completed_tests = 0
            
            # Test each injection point with each payload
            for injection_point in injection_points:
                for payload in payloads:
                    try:
                        result = await self.testing_module.test_injection_point(injection_point, payload)
                        
                        if result and result.get('vulnerable'):
                            vulnerabilities.append(result)
                            self.logger.warning(f"🎯 Vulnerability found: {result.get('test_url', 'Unknown')}")
                        
                        completed_tests += 1
                        
                        # Show progress every 100 tests
                        if completed_tests % 100 == 0 or completed_tests == total_tests:
                            progress = (completed_tests / total_tests) * 100
                            self.logger.info(f"📊 Progress: {completed_tests}/{total_tests} ({progress:.1f}%)")
                        
                        # Add small delay to avoid overwhelming the target
                        await asyncio.sleep(0.01)
                        
                    except Exception as e:
                        self.logger.error(f"❌ Error testing {injection_point.get('parameter', 'Unknown')}: {str(e)}")
                        completed_tests += 1
            
            self.logger.info(f"✅ Testing completed. Found {len(vulnerabilities)} vulnerabilities")
            return vulnerabilities
            
        except Exception as e:
            self.logger.error(f"❌ Error testing injection points: {str(e)}")
            return []
    
    async def _test_with_chrome(self, injection_points: List[Dict], payloads: List[str]) -> List[Dict]:
        """Test with Chrome automation"""
        vulnerabilities = []
        
        try:
            if not self.chrome_module.driver:
                return vulnerabilities
            
            self.logger.info("🌐 Testing with Chrome automation...")
            
            # Test a subset of injection points with Chrome
            test_count = min(10, len(injection_points))  # Limit to 10 injection points
            
            for i, injection_point in enumerate(injection_points[:test_count]):
                if injection_point.get('type') == 'url':
                    # Test with a few payloads
                    test_payloads = payloads[:5]  # Limit to 5 payloads per injection point
                    
                    for payload in test_payloads:
                        try:
                            test_url = self._construct_test_url(injection_point, payload)
                            result = await self.chrome_module.test_redirect(test_url, payload)
                            
                            if result and result.get('vulnerable'):
                                vulnerabilities.append(result)
                                self.logger.warning(f"🎯 Chrome vulnerability found: {test_url}")
                            
                        except Exception as e:
                            self.logger.error(f"❌ Chrome test error: {str(e)}")
            
            self.logger.info(f"✅ Chrome testing completed. Found {len(vulnerabilities)} additional vulnerabilities")
            return vulnerabilities
            
        except Exception as e:
            self.logger.error(f"❌ Chrome testing failed: {str(e)}")
            return []
    
    def _construct_test_url(self, injection_point: Dict, payload: str) -> str:
        """Construct test URL with payload"""
        base_url = injection_point['url']
        param_name = injection_point['parameter']
        
        from urllib.parse import urlparse, parse_qs
        
        parsed = urlparse(base_url)
        query_params = parse_qs(parsed.query)
        query_params[param_name] = [payload]
        
        new_query = '&'.join([f"{k}={v[0]}" for k, v in query_params.items()])
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
    
    async def _generate_comprehensive_reports(self):
        """Generate comprehensive reports"""
        try:
            # Generate HTML report
            html_report = self._generate_html_report()
            html_file = self.output_dir / f"comprehensive_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
            with open(html_file, 'w', encoding='utf-8') as f:
                f.write(html_report)
            
            # Generate JSON report
            json_file = self.output_dir / f"comprehensive_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(json_file, 'w', encoding='utf-8') as f:
                json.dump(self.scan_results, f, indent=2, ensure_ascii=False)
            
            # Generate CSV report
            csv_file = self.output_dir / f"vulnerabilities_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            self._generate_csv_report(csv_file)
            
            self.logger.info(f"📊 Reports generated:")
            self.logger.info(f"  - HTML: {html_file}")
            self.logger.info(f"  - JSON: {json_file}")
            self.logger.info(f"  - CSV: {csv_file}")
            
        except Exception as e:
            self.logger.error(f"❌ Error generating reports: {str(e)}")
    
    def _generate_html_report(self) -> str:
        """Generate comprehensive HTML report"""
        vulnerabilities = self.scan_results.get('vulnerabilities', [])
        performance = self.scan_results.get('performance_metrics', {})
        
        vulnerabilities_html = ''
        if not vulnerabilities:
            vulnerabilities_html = '<div class="no-vulns">✅ No vulnerabilities found</div>'
        else:
            for vuln in vulnerabilities:
                severity = self._get_severity(vuln.get('test_type', ''))
                vulnerabilities_html += f'''
                <div class="vulnerability {severity}">
                    <h3>🎯 {vuln.get('injection_point', {}).get('parameter', 'Unknown Parameter')}</h3>
                    <p><strong>Type:</strong> {vuln.get('test_type', 'Unknown')}</p>
                    <p><strong>URL:</strong> {vuln.get('test_url', 'Unknown')}</p>
                    <p><strong>Payload:</strong> <code>{vuln.get('payload', 'Unknown')}</code></p>
                    <p><strong>Redirect URL:</strong> {vuln.get('redirect_url', 'Unknown')}</p>
                    <p><strong>Detection Method:</strong> {vuln.get('detection_method', 'Unknown')}</p>
                    <p><strong>Timestamp:</strong> {vuln.get('timestamp', 'Unknown')}</p>
                </div>
                '''
        
        return f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Professional Open Redirect Scanner - Comprehensive Report</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
        }}
        
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 15px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            overflow: hidden;
        }}
        
        .header {{
            background: linear-gradient(135deg, #2c3e50 0%, #34495e 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }}
        
        .header h1 {{
            margin: 0;
            font-size: 3em;
            font-weight: 300;
        }}
        
        .header p {{
            margin: 15px 0 0 0;
            opacity: 0.8;
            font-size: 1.2em;
        }}
        
        .summary {{
            background: #f8f9fa;
            padding: 40px;
            border-bottom: 1px solid #e9ecef;
        }}
        
        .summary h2 {{
            color: #2c3e50;
            margin-top: 0;
            font-size: 2em;
        }}
        
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-top: 30px;
        }}
        
        .stat-card {{
            background: white;
            padding: 25px;
            border-radius: 10px;
            text-align: center;
            box-shadow: 0 5px 15px rgba(0,0,0,0.08);
            transition: transform 0.3s ease;
        }}
        
        .stat-card:hover {{
            transform: translateY(-5px);
        }}
        
        .stat-number {{
            font-size: 3em;
            font-weight: bold;
            color: #3498db;
            margin-bottom: 10px;
        }}
        
        .stat-label {{
            color: #7f8c8d;
            font-size: 1.1em;
            font-weight: 500;
        }}
        
        .vulnerabilities {{
            padding: 40px;
        }}
        
        .vulnerabilities h2 {{
            color: #2c3e50;
            margin-top: 0;
            font-size: 2em;
        }}
        
        .vulnerability {{
            border: 1px solid #e9ecef;
            margin: 25px 0;
            padding: 30px;
            border-radius: 10px;
            transition: all 0.3s ease;
        }}
        
        .vulnerability:hover {{
            transform: translateY(-2px);
            box-shadow: 0 10px 25px rgba(0,0,0,0.1);
        }}
        
        .high {{ border-left: 5px solid #e74c3c; }}
        .medium {{ border-left: 5px solid #f39c12; }}
        .low {{ border-left: 5px solid #27ae60; }}
        
        .vulnerability h3 {{
            margin-top: 0;
            color: #2c3e50;
            font-size: 1.4em;
        }}
        
        .vulnerability p {{
            margin: 12px 0;
            line-height: 1.6;
        }}
        
        .vulnerability code {{
            background: #f8f9fa;
            padding: 3px 8px;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
            color: #e74c3c;
            word-break: break-all;
        }}
        
        .no-vulns {{
            text-align: center;
            color: #27ae60;
            font-size: 1.3em;
            padding: 50px;
            background: #f8f9fa;
            border-radius: 10px;
        }}
        
        .footer {{
            background: #2c3e50;
            color: white;
            padding: 30px;
            text-align: center;
        }}
        
        .performance {{
            background: #ecf0f1;
            padding: 30px;
            margin: 20px 0;
            border-radius: 10px;
        }}
        
        .performance h3 {{
            color: #2c3e50;
            margin-top: 0;
        }}
        
        .performance-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-top: 20px;
        }}
        
        .perf-item {{
            background: white;
            padding: 15px;
            border-radius: 8px;
            text-align: center;
        }}
        
        .perf-value {{
            font-size: 1.5em;
            font-weight: bold;
            color: #3498db;
        }}
        
        .perf-label {{
            color: #7f8c8d;
            font-size: 0.9em;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 Professional Open Redirect Scanner</h1>
            <p>Comprehensive Security Testing Report</p>
        </div>
        
        <div class="summary">
            <h2>📊 Scan Summary</h2>
            <p><strong>Target URL:</strong> {self.target_url}</p>
            <p><strong>Scan Time:</strong> {self.scan_results.get('start_time', 'Unknown')}</p>
            <p><strong>Duration:</strong> {self.scan_results.get('duration', 0):.2f} seconds</p>
            <p><strong>Total Vulnerabilities:</strong> {len(vulnerabilities)}</p>
            
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-number">{len(vulnerabilities)}</div>
                    <div class="stat-label">Total Vulnerabilities</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{performance.get('total_tests', 0)}</div>
                    <div class="stat-label">Total Tests</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{performance.get('injection_points_tested', 0)}</div>
                    <div class="stat-label">Injection Points</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{performance.get('payloads_tested', 0)}</div>
                    <div class="stat-label">Payloads Tested</div>
                </div>
            </div>
            
            <div class="performance">
                <h3>⚡ Performance Metrics</h3>
                <div class="performance-grid">
                    <div class="perf-item">
                        <div class="perf-value">{performance.get('successful_tests', 0)}</div>
                        <div class="perf-label">Successful Tests</div>
                    </div>
                    <div class="perf-item">
                        <div class="perf-value">{performance.get('failed_tests', 0)}</div>
                        <div class="perf-label">Failed Tests</div>
                    </div>
                    <div class="perf-item">
                        <div class="perf-value">{performance.get('scan_duration', 0):.2f}s</div>
                        <div class="perf-label">Scan Duration</div>
                    </div>
                    <div class="perf-item">
                        <div class="perf-value">{len(vulnerabilities)}</div>
                        <div class="perf-label">Vulnerabilities Found</div>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="vulnerabilities">
            <h2>🎯 Vulnerabilities Found</h2>
            {vulnerabilities_html}
        </div>
        
        <div class="footer">
            <p>Generated by Professional Open Redirect Scanner v2.0</p>
            <p>Advanced Security Testing Tool</p>
        </div>
    </div>
</body>
</html>
"""
    
    def _generate_csv_report(self, csv_file: Path):
        """Generate CSV report"""
        try:
            import csv
            
            with open(csv_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                
                # Write header
                writer.writerow([
                    'Parameter', 'Type', 'URL', 'Payload', 'Redirect URL',
                    'Detection Method', 'Timestamp', 'Severity'
                ])
                
                # Write vulnerabilities
                for vuln in self.scan_results.get('vulnerabilities', []):
                    writer.writerow([
                        vuln.get('injection_point', {}).get('parameter', ''),
                        vuln.get('test_type', ''),
                        vuln.get('test_url', ''),
                        vuln.get('payload', ''),
                        vuln.get('redirect_url', ''),
                        vuln.get('detection_method', ''),
                        vuln.get('timestamp', ''),
                        self._get_severity(vuln.get('test_type', ''))
                    ])
            
        except Exception as e:
            self.logger.error(f"❌ Error generating CSV report: {str(e)}")
    
    def _get_severity(self, test_type: str) -> str:
        """Determine vulnerability severity"""
        if test_type in ['url_redirect', 'javascript_redirect']:
            return 'High'
        elif test_type in ['form_redirect', 'meta_refresh_redirect']:
            return 'Medium'
        else:
            return 'Low'
    
    def _generate_scan_summary(self) -> Dict:
        """Generate scan summary"""
        vulnerabilities = self.scan_results.get('vulnerabilities', [])
        
        summary = {
            'total_vulnerabilities': len(vulnerabilities),
            'high_severity': 0,
            'medium_severity': 0,
            'low_severity': 0,
            'by_type': {},
            'by_detection_method': {}
        }
        
        for vuln in vulnerabilities:
            severity = self._get_severity(vuln.get('test_type', ''))
            if severity == 'High':
                summary['high_severity'] += 1
            elif severity == 'Medium':
                summary['medium_severity'] += 1
            else:
                summary['low_severity'] += 1
            
            vuln_type = vuln.get('test_type', 'unknown')
            summary['by_type'][vuln_type] = summary['by_type'].get(vuln_type, 0) + 1
            
            detection_method = vuln.get('detection_method', 'unknown')
            summary['by_detection_method'][detection_method] = summary['by_detection_method'].get(detection_method, 0) + 1
        
        return summary
    
    async def cleanup(self):
        """Cleanup all modules"""
        try:
            if self.chrome_module:
                await self.chrome_module.cleanup()
            
            if self.scanner:
                await self.scanner.cleanup()
            
            self.logger.info("🧹 Cleanup completed")
            
        except Exception as e:
            self.logger.error(f"❌ Cleanup error: {str(e)}")

def print_banner():
    """Print professional banner"""
    banner = """
    ╔══════════════════════════════════════════════════════════════════════════════╗
    ║                                                                              ║
    ║                    🔍 Professional Open Redirect Scanner                     ║
    ║                                                                              ║
    ║                        Advanced Security Testing Tool                        ║
    ║                                                                              ║
    ║  Features:                                                                   ║
    ║  • Advanced Reconnaissance with Multi-threaded Crawling                     ║
    ║  • Comprehensive WAF Bypass Techniques                                      ║
    ║  • Chrome-based Automation with Screenshot Capture                          ║
    ║  • Advanced Testing with Multiple Validation Methods                        ║
    ║  • Professional HTML/JSON/CSV Reports                                       ║
    ║  • Performance Metrics and Detailed Logging                                 ║
    ║                                                                              ║
    ╚══════════════════════════════════════════════════════════════════════════════╝
    """
    print(banner)

def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description='Professional Open Redirect Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('target', help='Target URL to scan')
    parser.add_argument('-o', '--output', default='scan_results', help='Output directory')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of threads')
    parser.add_argument('-d', '--depth', type=int, default=3, help='Maximum crawling depth')
    parser.add_argument('--timeout', type=int, default=30, help='Request timeout in seconds')
    parser.add_argument('--domain', default='google.com', help='Target domain for redirect validation')
    parser.add_argument('--no-headless', action='store_true', help='Run Chrome in visible mode')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    # Print banner
    print_banner()
    
    # Create runner
    runner = ProfessionalRunner(
        args.target,
        args.output,
        args.threads,
        args.depth,
        args.timeout,
        args.domain,
        not args.no_headless
    )
    
    # Run scan
    async def run_scan():
        if await runner.initialize():
            success = await runner.run_comprehensive_scan()
            await runner.cleanup()
            return success
        return False
    
    # Run the scan
    try:
        success = asyncio.run(run_scan())
        if success:
            print("\n🎉 Scan completed successfully!")
            print(f"📁 Results saved to: {args.output}")
            sys.exit(0)
        else:
            print("\n❌ Scan failed!")
            sys.exit(1)
    except KeyboardInterrupt:
        print("\n⚠️ Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Fatal error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()