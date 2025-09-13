#!/usr/bin/env python3
"""
Report Generator for XSS Scanner
Comprehensive reporting system with multiple output formats
"""

import json
import csv
import html
import time
from typing import Dict, List, Optional
from datetime import datetime
import os

class ReportGenerator:
    """Advanced report generator for XSS scan results"""
    
    def __init__(self, output_dir: str = "reports"):
        self.output_dir = output_dir
        self.ensure_output_dir()
        
    def ensure_output_dir(self):
        """Ensure output directory exists"""
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
            
    def generate_comprehensive_report(self, scan_results: Dict) -> Dict:
        """Generate comprehensive report in multiple formats"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Generate different report formats
        reports = {
            'json': self._generate_json_report(scan_results, timestamp),
            'html': self._generate_html_report(scan_results, timestamp),
            'csv': self._generate_csv_report(scan_results, timestamp),
            'txt': self._generate_text_report(scan_results, timestamp),
            'xml': self._generate_xml_report(scan_results, timestamp)
        }
        
        return reports
        
    def _generate_json_report(self, scan_results: Dict, timestamp: str) -> str:
        """Generate JSON report"""
        filename = f"{self.output_dir}/xss_scan_report_{timestamp}.json"
        
        report_data = {
            'scan_metadata': {
                'scan_timestamp': scan_results.get('scan_timestamp', ''),
                'target_url': scan_results.get('target_url', ''),
                'scanner_version': '1.0.0',
                'scan_duration': scan_results.get('scan_duration', 0),
                'total_urls_scanned': scan_results.get('total_urls', 0),
                'total_vulnerabilities': len(scan_results.get('vulnerabilities', []))
            },
            'summary': {
                'critical_vulnerabilities': 0,
                'high_vulnerabilities': 0,
                'medium_vulnerabilities': 0,
                'low_vulnerabilities': 0,
                'vulnerability_types': {},
                'affected_urls': set()
            },
            'vulnerabilities': scan_results.get('vulnerabilities', []),
            'urls_discovered': list(scan_results.get('discovered_urls', [])),
            'scan_statistics': scan_results.get('statistics', {})
        }
        
        # Calculate summary statistics
        for vuln in report_data['vulnerabilities']:
            severity = vuln.get('severity', 'low')
            if severity == 'critical':
                report_data['summary']['critical_vulnerabilities'] += 1
            elif severity == 'high':
                report_data['summary']['high_vulnerabilities'] += 1
            elif severity == 'medium':
                report_data['summary']['medium_vulnerabilities'] += 1
            else:
                report_data['summary']['low_vulnerabilities'] += 1
                
            # Count vulnerability types
            vuln_type = vuln.get('vulnerability_type', 'unknown')
            report_data['summary']['vulnerability_types'][vuln_type] = \
                report_data['summary']['vulnerability_types'].get(vuln_type, 0) + 1
                
            # Track affected URLs
            report_data['summary']['affected_urls'].add(vuln.get('url', ''))
            
        # Convert set to list for JSON serialization
        report_data['summary']['affected_urls'] = list(report_data['summary']['affected_urls'])
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)
            
        return filename
        
    def _generate_html_report(self, scan_results: Dict, timestamp: str) -> str:
        """Generate HTML report"""
        filename = f"{self.output_dir}/xss_scan_report_{timestamp}.html"
        
        vulnerabilities = scan_results.get('vulnerabilities', [])
        
        # Calculate statistics
        stats = self._calculate_statistics(vulnerabilities)
        
        html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>XSS Scanner Report - {scan_results.get('target_url', 'Unknown')}</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
            color: #333;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            overflow: hidden;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }}
        .header h1 {{
            margin: 0;
            font-size: 2.5em;
            font-weight: 300;
        }}
        .header p {{
            margin: 10px 0 0 0;
            opacity: 0.9;
        }}
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            padding: 30px;
            background: #f8f9fa;
        }}
        .stat-card {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }}
        .stat-card.critical {{ border-left: 4px solid #dc3545; }}
        .stat-card.high {{ border-left: 4px solid #fd7e14; }}
        .stat-card.medium {{ border-left: 4px solid #ffc107; }}
        .stat-card.low {{ border-left: 4px solid #28a745; }}
        .stat-number {{
            font-size: 2em;
            font-weight: bold;
            margin-bottom: 5px;
        }}
        .stat-label {{
            color: #666;
            font-size: 0.9em;
        }}
        .vulnerabilities {{
            padding: 30px;
        }}
        .vuln-item {{
            background: #f8f9fa;
            border-radius: 8px;
            margin-bottom: 20px;
            overflow: hidden;
            border-left: 4px solid #007bff;
        }}
        .vuln-header {{
            background: white;
            padding: 20px;
            border-bottom: 1px solid #dee2e6;
        }}
        .vuln-title {{
            font-size: 1.2em;
            font-weight: bold;
            margin-bottom: 10px;
        }}
        .vuln-meta {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            font-size: 0.9em;
            color: #666;
        }}
        .vuln-body {{
            padding: 20px;
        }}
        .payload {{
            background: #2d3748;
            color: #e2e8f0;
            padding: 15px;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            margin: 10px 0;
            overflow-x: auto;
        }}
        .evidence {{
            background: #fff3cd;
            border: 1px solid #ffeaa7;
            padding: 15px;
            border-radius: 4px;
            margin: 10px 0;
        }}
        .severity-critical {{ color: #dc3545; font-weight: bold; }}
        .severity-high {{ color: #fd7e14; font-weight: bold; }}
        .severity-medium {{ color: #ffc107; font-weight: bold; }}
        .severity-low {{ color: #28a745; font-weight: bold; }}
        .footer {{
            background: #343a40;
            color: white;
            padding: 20px;
            text-align: center;
            font-size: 0.9em;
        }}
        .no-vulns {{
            text-align: center;
            padding: 60px 20px;
            color: #28a745;
        }}
        .no-vulns h2 {{
            font-size: 2em;
            margin-bottom: 10px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>XSS Vulnerability Scan Report</h1>
            <p>Target: {scan_results.get('target_url', 'Unknown')}</p>
            <p>Scan Date: {scan_results.get('scan_timestamp', 'Unknown')}</p>
        </div>
        
        <div class="summary">
            <div class="stat-card critical">
                <div class="stat-number">{stats['critical']}</div>
                <div class="stat-label">Critical</div>
            </div>
            <div class="stat-card high">
                <div class="stat-number">{stats['high']}</div>
                <div class="stat-label">High</div>
            </div>
            <div class="stat-card medium">
                <div class="stat-number">{stats['medium']}</div>
                <div class="stat-label">Medium</div>
            </div>
            <div class="stat-card low">
                <div class="stat-number">{stats['low']}</div>
                <div class="stat-label">Low</div>
            </div>
        </div>
        
        <div class="vulnerabilities">
            {self._generate_vulnerability_html(vulnerabilities)}
        </div>
        
        <div class="footer">
            <p>Generated by Professional XSS Scanner v1.0.0</p>
            <p>Report generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
    </div>
</body>
</html>
        """
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html_content)
            
        return filename
        
    def _generate_vulnerability_html(self, vulnerabilities: List[Dict]) -> str:
        """Generate HTML for vulnerabilities section"""
        if not vulnerabilities:
            return '''
            <div class="no-vulns">
                <h2>✅ No XSS Vulnerabilities Found</h2>
                <p>The target application appears to be secure against XSS attacks.</p>
            </div>
            '''
            
        html_parts = []
        for i, vuln in enumerate(vulnerabilities, 1):
            severity_class = f"severity-{vuln.get('severity', 'low')}"
            severity_text = vuln.get('severity', 'low').upper()
            
            evidence_html = ""
            if vuln.get('evidence'):
                evidence_list = "".join([f"<li>{html.escape(evidence)}</li>" for evidence in vuln['evidence']])
                evidence_html = f'''
                <div class="evidence">
                    <strong>Evidence:</strong>
                    <ul>{evidence_list}</ul>
                </div>
                '''
                
            html_parts.append(f'''
            <div class="vuln-item">
                <div class="vuln-header">
                    <div class="vuln-title">Vulnerability #{i}: {html.escape(vuln.get('vulnerability_type', 'Unknown'))}</div>
                    <div class="vuln-meta">
                        <div><strong>URL:</strong> {html.escape(vuln.get('url', 'Unknown'))}</div>
                        <div><strong>Severity:</strong> <span class="{severity_class}">{severity_text}</span></div>
                        <div><strong>Confidence:</strong> {vuln.get('confidence', 0.0):.2f}</div>
                        <div><strong>Timestamp:</strong> {vuln.get('timestamp', 'Unknown')}</div>
                    </div>
                </div>
                <div class="vuln-body">
                    <div class="payload">
                        <strong>Payload:</strong><br>
                        {html.escape(vuln.get('payload', 'N/A'))}
                    </div>
                    {evidence_html}
                </div>
            </div>
            ''')
            
        return "".join(html_parts)
        
    def _generate_csv_report(self, scan_results: Dict, timestamp: str) -> str:
        """Generate CSV report"""
        filename = f"{self.output_dir}/xss_scan_report_{timestamp}.csv"
        
        vulnerabilities = scan_results.get('vulnerabilities', [])
        
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            if vulnerabilities:
                fieldnames = [
                    'url', 'vulnerability_type', 'severity', 'confidence', 'payload',
                    'evidence', 'timestamp', 'context_type', 'reflected', 'encoding_detected'
                ]
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                
                for vuln in vulnerabilities:
                    row = {
                        'url': vuln.get('url', ''),
                        'vulnerability_type': vuln.get('vulnerability_type', ''),
                        'severity': vuln.get('severity', ''),
                        'confidence': vuln.get('confidence', 0.0),
                        'payload': vuln.get('payload', ''),
                        'evidence': '; '.join(vuln.get('evidence', [])),
                        'timestamp': vuln.get('timestamp', ''),
                        'context_type': vuln.get('context_analysis', {}).get('context_type', ''),
                        'reflected': vuln.get('payload_reflected', False),
                        'encoding_detected': vuln.get('context_analysis', {}).get('encoding_detected', False)
                    }
                    writer.writerow(row)
            else:
                # Write header even if no vulnerabilities
                f.write("No XSS vulnerabilities found\n")
                
        return filename
        
    def _generate_text_report(self, scan_results: Dict, timestamp: str) -> str:
        """Generate text report"""
        filename = f"{self.output_dir}/xss_scan_report_{timestamp}.txt"
        
        vulnerabilities = scan_results.get('vulnerabilities', [])
        stats = self._calculate_statistics(vulnerabilities)
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write("=" * 80 + "\n")
            f.write("XSS VULNERABILITY SCAN REPORT\n")
            f.write("=" * 80 + "\n\n")
            
            f.write(f"Target URL: {scan_results.get('target_url', 'Unknown')}\n")
            f.write(f"Scan Date: {scan_results.get('scan_timestamp', 'Unknown')}\n")
            f.write(f"Scanner Version: 1.0.0\n")
            f.write(f"Total URLs Scanned: {scan_results.get('total_urls', 0)}\n")
            f.write(f"Scan Duration: {scan_results.get('scan_duration', 0)} seconds\n\n")
            
            f.write("SUMMARY\n")
            f.write("-" * 40 + "\n")
            f.write(f"Critical Vulnerabilities: {stats['critical']}\n")
            f.write(f"High Vulnerabilities: {stats['high']}\n")
            f.write(f"Medium Vulnerabilities: {stats['medium']}\n")
            f.write(f"Low Vulnerabilities: {stats['low']}\n")
            f.write(f"Total Vulnerabilities: {len(vulnerabilities)}\n\n")
            
            if vulnerabilities:
                f.write("VULNERABILITIES\n")
                f.write("-" * 40 + "\n\n")
                
                for i, vuln in enumerate(vulnerabilities, 1):
                    f.write(f"Vulnerability #{i}\n")
                    f.write(f"URL: {vuln.get('url', 'Unknown')}\n")
                    f.write(f"Type: {vuln.get('vulnerability_type', 'Unknown')}\n")
                    f.write(f"Severity: {vuln.get('severity', 'Unknown').upper()}\n")
                    f.write(f"Confidence: {vuln.get('confidence', 0.0):.2f}\n")
                    f.write(f"Payload: {vuln.get('payload', 'N/A')}\n")
                    f.write(f"Timestamp: {vuln.get('timestamp', 'Unknown')}\n")
                    
                    if vuln.get('evidence'):
                        f.write("Evidence:\n")
                        for evidence in vuln['evidence']:
                            f.write(f"  - {evidence}\n")
                            
                    f.write("\n" + "-" * 40 + "\n\n")
            else:
                f.write("No XSS vulnerabilities found.\n")
                f.write("The target application appears to be secure against XSS attacks.\n\n")
                
            f.write("=" * 80 + "\n")
            f.write("End of Report\n")
            f.write("=" * 80 + "\n")
            
        return filename
        
    def _generate_xml_report(self, scan_results: Dict, timestamp: str) -> str:
        """Generate XML report"""
        filename = f"{self.output_dir}/xss_scan_report_{timestamp}.xml"
        
        vulnerabilities = scan_results.get('vulnerabilities', [])
        stats = self._calculate_statistics(vulnerabilities)
        
        xml_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<xss_scan_report>
    <metadata>
        <target_url>{scan_results.get('target_url', 'Unknown')}</target_url>
        <scan_timestamp>{scan_results.get('scan_timestamp', 'Unknown')}</scan_timestamp>
        <scanner_version>1.0.0</scanner_version>
        <total_urls_scanned>{scan_results.get('total_urls', 0)}</total_urls_scanned>
        <scan_duration>{scan_results.get('scan_duration', 0)}</scan_duration>
    </metadata>
    
    <summary>
        <critical_vulnerabilities>{stats['critical']}</critical_vulnerabilities>
        <high_vulnerabilities>{stats['high']}</high_vulnerabilities>
        <medium_vulnerabilities>{stats['medium']}</medium_vulnerabilities>
        <low_vulnerabilities>{stats['low']}</low_vulnerabilities>
        <total_vulnerabilities>{len(vulnerabilities)}</total_vulnerabilities>
    </summary>
    
    <vulnerabilities>
"""
        
        for i, vuln in enumerate(vulnerabilities, 1):
            evidence_xml = ""
            if vuln.get('evidence'):
                evidence_xml = "        <evidence>\n"
                for evidence in vuln['evidence']:
                    evidence_xml += f"            <item>{self._escape_xml(evidence)}</item>\n"
                evidence_xml += "        </evidence>\n"
                
            xml_content += f"""        <vulnerability id="{i}">
            <url>{self._escape_xml(vuln.get('url', 'Unknown'))}</url>
            <type>{self._escape_xml(vuln.get('vulnerability_type', 'Unknown'))}</type>
            <severity>{self._escape_xml(vuln.get('severity', 'Unknown'))}</severity>
            <confidence>{vuln.get('confidence', 0.0):.2f}</confidence>
            <payload>{self._escape_xml(vuln.get('payload', 'N/A'))}</payload>
            <timestamp>{self._escape_xml(vuln.get('timestamp', 'Unknown'))}</timestamp>
            {evidence_xml}
        </vulnerability>
"""
            
        xml_content += """    </vulnerabilities>
</xss_scan_report>"""
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(xml_content)
            
        return filename
        
    def _calculate_statistics(self, vulnerabilities: List[Dict]) -> Dict:
        """Calculate vulnerability statistics"""
        stats = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'low')
            if severity in stats:
                stats[severity] += 1
                
        return stats
        
    def _escape_xml(self, text: str) -> str:
        """Escape XML special characters"""
        return (text.replace('&', '&amp;')
                   .replace('<', '&lt;')
                   .replace('>', '&gt;')
                   .replace('"', '&quot;')
                   .replace("'", '&apos;'))
                   
    def generate_executive_summary(self, scan_results: Dict) -> str:
        """Generate executive summary"""
        vulnerabilities = scan_results.get('vulnerabilities', [])
        stats = self._calculate_statistics(vulnerabilities)
        
        summary = f"""
EXECUTIVE SUMMARY
================

Target: {scan_results.get('target_url', 'Unknown')}
Scan Date: {scan_results.get('scan_timestamp', 'Unknown')}
Total URLs Scanned: {scan_results.get('total_urls', 0)}

VULNERABILITY SUMMARY:
- Critical: {stats['critical']}
- High: {stats['high']}
- Medium: {stats['medium']}
- Low: {stats['low']}
- Total: {len(vulnerabilities)}

RISK ASSESSMENT:
"""
        
        if stats['critical'] > 0:
            summary += "🔴 CRITICAL RISK - Immediate action required\n"
        elif stats['high'] > 0:
            summary += "🟠 HIGH RISK - Address within 24-48 hours\n"
        elif stats['medium'] > 0:
            summary += "🟡 MEDIUM RISK - Address within 1-2 weeks\n"
        elif stats['low'] > 0:
            summary += "🟢 LOW RISK - Address during next maintenance window\n"
        else:
            summary += "✅ NO VULNERABILITIES FOUND - Application appears secure\n"
            
        summary += f"""
RECOMMENDATIONS:
- Implement proper input validation and output encoding
- Use Content Security Policy (CSP) headers
- Regular security testing and code reviews
- Keep all software components updated
- Implement Web Application Firewall (WAF)

For detailed information, please refer to the complete scan report.
        """
        
        return summary