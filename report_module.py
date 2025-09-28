"""
Advanced Report Module for Open Redirect Scanner
Generates comprehensive HTML reports with screenshots and detailed analysis
"""

import json
import base64
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional, Any
import logging

class ReportModule:
    """
    Advanced report generation module
    """
    
    def __init__(self, output_dir: Path):
        self.output_dir = output_dir
        self.reports_dir = output_dir / "reports"
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        
    async def generate_report(self, vulnerabilities: List[Dict], target_url: str) -> str:
        """Generate comprehensive HTML report"""
        try:
            report_data = {
                'target_url': target_url,
                'scan_timestamp': datetime.now().isoformat(),
                'vulnerabilities': vulnerabilities,
                'total_vulnerabilities': len(vulnerabilities),
                'scan_summary': self._generate_scan_summary(vulnerabilities)
            }
            
            # Generate HTML report
            html_content = self._generate_html_report(report_data)
            
            # Save report
            report_file = self.reports_dir / f"open_redirect_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
            with open(report_file, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            # Generate JSON report
            json_file = self.reports_dir / f"open_redirect_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(json_file, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=2, ensure_ascii=False)
            
            return str(report_file)
            
        except Exception as e:
            print(f"Error generating report: {str(e)}")
            return ""
    
    def _generate_scan_summary(self, vulnerabilities: List[Dict]) -> Dict:
        """Generate scan summary statistics"""
        summary = {
            'total_vulnerabilities': len(vulnerabilities),
            'vulnerability_types': {},
            'injection_points': {},
            'payloads_used': set(),
            'redirect_domains': set(),
            'severity_breakdown': {
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0
            }
        }
        
        for vuln in vulnerabilities:
            # Count vulnerability types
            vuln_type = vuln.get('injection_type', 'unknown')
            summary['vulnerability_types'][vuln_type] = summary['vulnerability_types'].get(vuln_type, 0) + 1
            
            # Count injection points
            injection_point = vuln.get('parameter', 'unknown')
            summary['injection_points'][injection_point] = summary['injection_points'].get(injection_point, 0) + 1
            
            # Collect payloads
            summary['payloads_used'].add(vuln.get('payload', ''))
            
            # Collect redirect domains
            redirect_url = vuln.get('redirect_url', '')
            if redirect_url:
                from urllib.parse import urlparse
                domain = urlparse(redirect_url).netloc
                summary['redirect_domains'].add(domain)
            
            # Determine severity
            severity = self._determine_severity(vuln)
            summary['severity_breakdown'][severity] += 1
        
        # Convert sets to lists for JSON serialization
        summary['payloads_used'] = list(summary['payloads_used'])
        summary['redirect_domains'] = list(summary['redirect_domains'])
        
        return summary
    
    def _determine_severity(self, vulnerability: Dict) -> str:
        """Determine vulnerability severity"""
        # Simple severity determination based on context
        injection_type = vulnerability.get('injection_type', '')
        parameter = vulnerability.get('parameter', '').lower()
        
        if 'javascript' in injection_type or 'meta' in injection_type:
            return 'high'
        elif 'url' in injection_type and any(keyword in parameter for keyword in ['redirect', 'url', 'next', 'return']):
            return 'high'
        elif 'form' in injection_type:
            return 'medium'
        elif 'cookie' in injection_type or 'header' in injection_type:
            return 'medium'
        else:
            return 'low'
    
    def _generate_html_report(self, report_data: Dict) -> str:
        """Generate HTML report content"""
        html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Open Redirect Vulnerability Report</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background-color: #f5f5f5;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }
        
        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        
        .header p {
            font-size: 1.2em;
            opacity: 0.9;
        }
        
        .summary-cards {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .card {
            background: white;
            padding: 25px;
            border-radius: 10px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
            text-align: center;
        }
        
        .card h3 {
            color: #667eea;
            margin-bottom: 10px;
            font-size: 1.5em;
        }
        
        .card .number {
            font-size: 2.5em;
            font-weight: bold;
            color: #333;
        }
        
        .vulnerabilities {
            background: white;
            border-radius: 10px;
            padding: 30px;
            margin-bottom: 30px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
        }
        
        .vulnerability {
            border: 1px solid #e0e0e0;
            border-radius: 8px;
            margin-bottom: 20px;
            overflow: hidden;
        }
        
        .vulnerability-header {
            background: #f8f9fa;
            padding: 15px 20px;
            border-bottom: 1px solid #e0e0e0;
            cursor: pointer;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .vulnerability-header:hover {
            background: #e9ecef;
        }
        
        .vulnerability-title {
            font-weight: bold;
            color: #333;
        }
        
        .severity {
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.8em;
            font-weight: bold;
            text-transform: uppercase;
        }
        
        .severity-critical {
            background: #dc3545;
            color: white;
        }
        
        .severity-high {
            background: #fd7e14;
            color: white;
        }
        
        .severity-medium {
            background: #ffc107;
            color: #333;
        }
        
        .severity-low {
            background: #28a745;
            color: white;
        }
        
        .vulnerability-content {
            padding: 20px;
            display: none;
        }
        
        .vulnerability-content.active {
            display: block;
        }
        
        .vulnerability-details {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-bottom: 20px;
        }
        
        .detail-group {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
        }
        
        .detail-group h4 {
            color: #667eea;
            margin-bottom: 10px;
        }
        
        .detail-group p {
            margin-bottom: 5px;
            word-break: break-all;
        }
        
        .screenshot {
            margin-top: 20px;
            text-align: center;
        }
        
        .screenshot img {
            max-width: 100%;
            height: auto;
            border: 1px solid #ddd;
            border-radius: 5px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
        }
        
        .code-block {
            background: #f8f9fa;
            border: 1px solid #e9ecef;
            border-radius: 5px;
            padding: 15px;
            margin: 10px 0;
            font-family: 'Courier New', monospace;
            overflow-x: auto;
        }
        
        .footer {
            text-align: center;
            padding: 20px;
            color: #666;
            background: white;
            border-radius: 10px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
        }
        
        .no-vulnerabilities {
            text-align: center;
            padding: 50px;
            color: #666;
        }
        
        .no-vulnerabilities h3 {
            color: #28a745;
            margin-bottom: 10px;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin: 20px 0;
        }
        
        .stat-item {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            text-align: center;
        }
        
        .stat-item .label {
            font-size: 0.9em;
            color: #666;
            margin-bottom: 5px;
        }
        
        .stat-item .value {
            font-size: 1.5em;
            font-weight: bold;
            color: #333;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 Open Redirect Vulnerability Report</h1>
            <p>Target: {target_url}</p>
            <p>Scan Date: {scan_timestamp}</p>
        </div>
        
        <div class="summary-cards">
            <div class="card">
                <h3>Total Vulnerabilities</h3>
                <div class="number">{total_vulnerabilities}</div>
            </div>
            <div class="card">
                <h3>Critical</h3>
                <div class="number">{critical_count}</div>
            </div>
            <div class="card">
                <h3>High</h3>
                <div class="number">{high_count}</div>
            </div>
            <div class="card">
                <h3>Medium</h3>
                <div class="number">{medium_count}</div>
            </div>
            <div class="card">
                <h3>Low</h3>
                <div class="number">{low_count}</div>
            </div>
        </div>
        
        {vulnerabilities_section}
        
        <div class="footer">
            <p>Report generated by Open Redirect Scanner</p>
            <p>Generated on {scan_timestamp}</p>
        </div>
    </div>
    
    <script>
        // Toggle vulnerability details
        document.querySelectorAll('.vulnerability-header').forEach(header => {{
            header.addEventListener('click', function() {{
                const content = this.nextElementSibling;
                content.classList.toggle('active');
            }});
        }});
    </script>
</body>
</html>
        """
        
        # Generate vulnerabilities section
        vulnerabilities_section = self._generate_vulnerabilities_section(report_data['vulnerabilities'])
        
        # Fill template
        html_content = html_template.format(
            target_url=report_data['target_url'],
            scan_timestamp=report_data['scan_timestamp'],
            total_vulnerabilities=report_data['total_vulnerabilities'],
            critical_count=report_data['scan_summary']['severity_breakdown']['critical'],
            high_count=report_data['scan_summary']['severity_breakdown']['high'],
            medium_count=report_data['scan_summary']['severity_breakdown']['medium'],
            low_count=report_data['scan_summary']['severity_breakdown']['low'],
            vulnerabilities_section=vulnerabilities_section
        )
        
        return html_content
    
    def _generate_vulnerabilities_section(self, vulnerabilities: List[Dict]) -> str:
        """Generate vulnerabilities section HTML"""
        if not vulnerabilities:
            return """
            <div class="vulnerabilities">
                <div class="no-vulnerabilities">
                    <h3>✅ No Vulnerabilities Found</h3>
                    <p>The target appears to be secure against open redirect attacks.</p>
                </div>
            </div>
            """
        
        vulnerabilities_html = '<div class="vulnerabilities"><h2>🚨 Vulnerabilities Found</h2>'
        
        for i, vuln in enumerate(vulnerabilities):
            severity = self._determine_severity(vuln)
            severity_class = f"severity-{severity}"
            
            vulnerabilities_html += f"""
            <div class="vulnerability">
                <div class="vulnerability-header">
                    <div class="vulnerability-title">
                        Vulnerability #{i+1}: {vuln.get('parameter', 'Unknown Parameter')}
                    </div>
                    <div class="severity {severity_class}">{severity.upper()}</div>
                </div>
                <div class="vulnerability-content">
                    <div class="vulnerability-details">
                        <div class="detail-group">
                            <h4>🔗 URL</h4>
                            <p>{vuln.get('url', 'N/A')}</p>
                        </div>
                        <div class="detail-group">
                            <h4>📝 Parameter</h4>
                            <p>{vuln.get('parameter', 'N/A')}</p>
                        </div>
                        <div class="detail-group">
                            <h4>🎯 Payload</h4>
                            <div class="code-block">{vuln.get('payload', 'N/A')}</div>
                        </div>
                        <div class="detail-group">
                            <h4>🔄 Redirect URL</h4>
                            <p>{vuln.get('redirect_url', 'N/A')}</p>
                        </div>
                        <div class="detail-group">
                            <h4>📊 Injection Type</h4>
                            <p>{vuln.get('injection_type', 'N/A')}</p>
                        </div>
                        <div class="detail-group">
                            <h4>⏰ Timestamp</h4>
                            <p>{vuln.get('timestamp', 'N/A')}</p>
                        </div>
                    </div>
                    {self._generate_screenshot_section(vuln)}
                </div>
            </div>
            """
        
        vulnerabilities_html += '</div>'
        return vulnerabilities_html
    
    def _generate_screenshot_section(self, vulnerability: Dict) -> str:
        """Generate screenshot section HTML"""
        screenshot_path = vulnerability.get('screenshot_path')
        
        if not screenshot_path or not Path(screenshot_path).exists():
            return ""
        
        try:
            # Convert image to base64 for embedding
            with open(screenshot_path, 'rb') as img_file:
                img_data = base64.b64encode(img_file.read()).decode()
                img_extension = Path(screenshot_path).suffix.lower()
                mime_type = f"image/{img_extension[1:]}" if img_extension else "image/png"
                
                return f"""
                <div class="screenshot">
                    <h4>📸 Proof of Concept Screenshot</h4>
                    <img src="data:{mime_type};base64,{img_data}" alt="Vulnerability Screenshot">
                </div>
                """
        except Exception as e:
            return f"""
            <div class="screenshot">
                <h4>📸 Proof of Concept Screenshot</h4>
                <p>Error loading screenshot: {str(e)}</p>
            </div>
            """
    
    def generate_summary_report(self, vulnerabilities: List[Dict], target_url: str) -> str:
        """Generate a summary report"""
        try:
            summary_data = {
                'target_url': target_url,
                'scan_timestamp': datetime.now().isoformat(),
                'total_vulnerabilities': len(vulnerabilities),
                'vulnerability_summary': self._generate_vulnerability_summary(vulnerabilities)
            }
            
            summary_file = self.reports_dir / f"summary_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(summary_file, 'w', encoding='utf-8') as f:
                json.dump(summary_data, f, indent=2, ensure_ascii=False)
            
            return str(summary_file)
            
        except Exception as e:
            print(f"Error generating summary report: {str(e)}")
            return ""
    
    def _generate_vulnerability_summary(self, vulnerabilities: List[Dict]) -> Dict:
        """Generate vulnerability summary"""
        summary = {
            'by_type': {},
            'by_parameter': {},
            'by_severity': {},
            'unique_payloads': set(),
            'redirect_domains': set()
        }
        
        for vuln in vulnerabilities:
            # By type
            vuln_type = vuln.get('injection_type', 'unknown')
            summary['by_type'][vuln_type] = summary['by_type'].get(vuln_type, 0) + 1
            
            # By parameter
            parameter = vuln.get('parameter', 'unknown')
            summary['by_parameter'][parameter] = summary['by_parameter'].get(parameter, 0) + 1
            
            # By severity
            severity = self._determine_severity(vuln)
            summary['by_severity'][severity] = summary['by_severity'].get(severity, 0) + 1
            
            # Unique payloads
            summary['unique_payloads'].add(vuln.get('payload', ''))
            
            # Redirect domains
            redirect_url = vuln.get('redirect_url', '')
            if redirect_url:
                from urllib.parse import urlparse
                domain = urlparse(redirect_url).netloc
                summary['redirect_domains'].add(domain)
        
        # Convert sets to lists
        summary['unique_payloads'] = list(summary['unique_payloads'])
        summary['redirect_domains'] = list(summary['redirect_domains'])
        
        return summary