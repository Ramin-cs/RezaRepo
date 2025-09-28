#!/usr/bin/env python3
"""
Modular XSS Scanner - Main Orchestrator
Detects website technology and routes to appropriate scanner module
Author: AI Assistant
Version: 1.0
"""

import sys
import argparse
import json
import os
from datetime import datetime
from colorama import init, Fore, Style

# Import scanner modules
from technology_detector import TechnologyDetector
from traditional_scanner import TraditionalScanner
from modern_spa_scanner import ModernSPAScanner
from hybrid_scanner import HybridScanner

# Initialize colorama
init()

class ModularXSSScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.detector = TechnologyDetector()
        self.vulnerabilities = []
        
        # Create output directories
        os.makedirs('reports', exist_ok=True)
        os.makedirs('screenshots', exist_ok=True)
    
    def log(self, message, level="INFO"):
        """Enhanced logging with colors"""
        colors = {
            "INFO": Fore.WHITE,
            "SUCCESS": Fore.GREEN,
            "WARNING": Fore.YELLOW,
            "ERROR": Fore.RED,
            "DETECTION": Fore.CYAN + Style.BRIGHT,
            "SCANNING": Fore.MAGENTA + Style.BRIGHT,
            "VULN": Fore.GREEN + Style.BRIGHT,
            "REPORT": Fore.BLUE + Style.BRIGHT
        }
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"{colors.get(level, Fore.WHITE)}[{timestamp}] [{level}] {message}{Style.RESET_ALL}")
    
    def scan(self):
        """Main scanning orchestrator"""
        self.log("🚀 Starting Modular XSS Scanner", "SUCCESS")
        self.log(f"Target: {self.target_url}", "INFO")
        self.log("=" * 80, "DETECTION")
        
        # Phase 1: Technology Detection
        self.log("PHASE 1: TECHNOLOGY DETECTION", "DETECTION")
        detection_result = self.detector.detect_technology(self.target_url)
        
        self.log(f"Website Type: {detection_result['type'].upper()}", "DETECTION")
        self.log(f"Confidence: {detection_result['confidence']}/100", "DETECTION")
        self.log(f"Scanning Strategy: {detection_result['scanning_strategy']}", "DETECTION")
        
        if detection_result.get('framework'):
            self.log(f"Framework: {detection_result['framework']}", "DETECTION")
        
        if detection_result.get('features'):
            self.log(f"Features: {', '.join(detection_result['features'])}", "DETECTION")
        
        self.log("=" * 80, "SCANNING")
        
        # Phase 2: Route to Appropriate Scanner
        self.log("PHASE 2: MODULAR SCANNING", "SCANNING")
        
        if detection_result['scanning_strategy'] == 'traditional':
            self.log("Using Traditional Scanner Module", "SCANNING")
            scanner = TraditionalScanner(self.target_url)
            self.vulnerabilities = scanner.scan()
        
        elif detection_result['scanning_strategy'] == 'modern_spa':
            self.log("Using Modern SPA Scanner Module", "SCANNING")
            scanner = ModernSPAScanner(self.target_url)
            self.vulnerabilities = scanner.scan()
        
        elif detection_result['scanning_strategy'] == 'hybrid':
            self.log("Using Hybrid Scanner Module", "SCANNING")
            scanner = HybridScanner(self.target_url)
            self.vulnerabilities = scanner.scan()
        
        else:
            self.log("Unknown scanning strategy, defaulting to Traditional", "WARNING")
            scanner = TraditionalScanner(self.target_url)
            self.vulnerabilities = scanner.scan()
        
        # Phase 3: Generate Report
        self.log("=" * 80, "REPORT")
        self.log("PHASE 3: REPORT GENERATION", "REPORT")
        
        self._generate_report(detection_result)
        self._show_results()
    
    def _generate_report(self, detection_result):
        """Generate comprehensive report"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = os.path.join('reports', f'modular_xss_report_{timestamp}.html')
        
        # Calculate statistics
        total_vulns = len(self.vulnerabilities)
        high_confidence = len([v for v in self.vulnerabilities if v.get('confidence') == 'high'])
        medium_confidence = len([v for v in self.vulnerabilities if v.get('confidence') == 'medium'])
        
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Modular XSS Scanner Report - {self.target_url}</title>
    <style>
        body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 0; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: #333; }}
        .container {{ max-width: 1200px; margin: 20px auto; background: white; border-radius: 15px; box-shadow: 0 10px 30px rgba(0,0,0,0.2); overflow: hidden; }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; }}
        .header h1 {{ margin: 0; font-size: 2.5em; }}
        .detection-info {{ background: #f8f9fa; padding: 20px; border-left: 5px solid #17a2b8; margin: 20px; border-radius: 8px; }}
        .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; padding: 30px; }}
        .stat {{ background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%); color: white; padding: 25px; border-radius: 10px; text-align: center; }}
        .stat-number {{ font-size: 2.5em; font-weight: bold; margin-bottom: 10px; }}
        .vulnerability {{ background: #f8f9fa; border-left: 5px solid #28a745; margin: 20px; padding: 25px; border-radius: 8px; }}
        .payload-display {{ background: #f8f9fa; padding: 10px; border-radius: 5px; font-family: monospace; word-break: break-all; margin: 10px 0; }}
        .confidence-badge {{ padding: 3px 8px; border-radius: 10px; font-size: 0.8em; font-weight: bold; }}
        .high-confidence {{ background: #dc3545; color: white; }}
        .medium-confidence {{ background: #ffc107; color: black; }}
        .low-confidence {{ background: #6c757d; color: white; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Modular XSS Scanner Report</h1>
            <p>Target: {self.target_url}</p>
            <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
        
        <div class="detection-info">
            <h3>🔍 Technology Detection Results</h3>
            <p><strong>Website Type:</strong> {detection_result['type'].upper()}</p>
            <p><strong>Scanning Strategy:</strong> {detection_result['scanning_strategy']}</p>
            <p><strong>Confidence:</strong> {detection_result['confidence']}/100</p>
            {f'<p><strong>Framework:</strong> {detection_result["framework"]}</p>' if detection_result.get('framework') else ''}
            {f'<p><strong>Features:</strong> {", ".join(detection_result["features"])}</p>' if detection_result.get('features') else ''}
        </div>
        
        <div class="stats">
            <div class="stat">
                <div class="stat-number">{total_vulns}</div>
                <div>Total Vulnerabilities</div>
            </div>
            <div class="stat">
                <div class="stat-number">{high_confidence}</div>
                <div>High Confidence</div>
            </div>
            <div class="stat">
                <div class="stat-number">{medium_confidence}</div>
                <div>Medium Confidence</div>
            </div>
        </div>
        
        <div style="padding: 30px;">
            <h2>🎯 Vulnerability Details</h2>
"""
        
        if not self.vulnerabilities:
            html_content += '<div style="text-align: center; padding: 40px; color: #28a745; font-size: 1.2em;">✅ No vulnerabilities found</div>'
        else:
            for i, vuln in enumerate(self.vulnerabilities, 1):
                confidence_class = f"{vuln.get('confidence', 'low')}-confidence"
                html_content += f"""
                <div class="vulnerability">
                    <h3>🔍 Vulnerability #{i} 
                        <span class="confidence-badge {confidence_class}">{vuln.get('confidence', 'unknown').upper()}</span>
                    </h3>
                    <p><strong>Type:</strong> {vuln.get('type', 'unknown')}</p>
                    <p><strong>URL/Endpoint:</strong> {vuln.get('url', vuln.get('endpoint', vuln.get('route', 'unknown')))}</p>
                    <p><strong>Parameter:</strong> {vuln.get('parameter', 'unknown')}</p>
                    <p><strong>Payload Type:</strong> {vuln.get('payload_type', 'unknown')}</p>
                    <p><strong>Payload:</strong></p>
                    <div class="payload-display">{vuln.get('payload', 'unknown')}</div>
                    <p><strong>Method:</strong> {vuln.get('method', 'unknown')}</p>
                    {f'<p><strong>Alert Message:</strong> {vuln.get("alert_message", "N/A")}</p>' if vuln.get('alert_message') else ''}
                </div>
"""
        
        html_content += """
        </div>
    </div>
</body>
</html>
"""
        
        try:
            with open(report_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            self.log(f"Report generated: {report_path}", "REPORT")
            return report_path
            
        except Exception as e:
            self.log(f"Error generating report: {str(e)}", "ERROR")
            return None
    
    def _show_results(self):
        """Show final results"""
        self.log("=" * 80, "SUCCESS")
        self.log("SCAN RESULTS", "SUCCESS")
        self.log("=" * 80, "SUCCESS")
        
        total_vulns = len(self.vulnerabilities)
        high_confidence = len([v for v in self.vulnerabilities if v.get('confidence') == 'high'])
        medium_confidence = len([v for v in self.vulnerabilities if v.get('confidence') == 'medium'])
        
        self.log(f"Total vulnerabilities: {total_vulns}", "SUCCESS")
        self.log(f"High confidence: {high_confidence}", "SUCCESS")
        self.log(f"Medium confidence: {medium_confidence}", "SUCCESS")
        
        if total_vulns > 0:
            self.log("\nVulnerabilities found:", "VULN")
            for i, vuln in enumerate(self.vulnerabilities, 1):
                self.log(f"  {i}. {vuln.get('type', 'unknown')} - {vuln.get('parameter', 'unknown')} - {vuln.get('confidence', 'unknown')}", "VULN")

def main():
    parser = argparse.ArgumentParser(description='Modular XSS Scanner - Detects technology and routes to appropriate scanner')
    parser.add_argument('url', help='Target URL to scan')
    parser.add_argument('--output', '-o', help='Output directory for reports', default='reports')
    
    args = parser.parse_args()
    
    scanner = ModularXSSScanner(args.url)
    scanner.scan()

if __name__ == "__main__":
    main()