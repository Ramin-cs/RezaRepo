"""
Advanced Report Module for Open Redirect Scanner
Generates comprehensive HTML and JSON reports
"""

import json
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any

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
            'high_severity': 0,
            'medium_severity': 0,
            'low_severity': 0,
            'vulnerability_types': {}
        }
        
        for vuln in vulnerabilities:
            severity = self._get_severity(vuln.get('injection_type', ''))
            if severity == 'high':
                summary['high_severity'] += 1
            elif severity == 'medium':
                summary['medium_severity'] += 1
            else:
                summary['low_severity'] += 1
            
            vuln_type = vuln.get('injection_type', 'unknown')
            summary['vulnerability_types'][vuln_type] = summary['vulnerability_types'].get(vuln_type, 0) + 1
        
        return summary
    
    def _get_severity(self, injection_type: str) -> str:
        """Determine vulnerability severity"""
        if 'url' in injection_type:
            return 'high'
        elif 'form' in injection_type or 'javascript' in injection_type:
            return 'medium'
        elif 'cookie' in injection_type or 'header' in injection_type:
            return 'medium'
        else:
            return 'low'
    
    def _generate_html_report(self, report_data: Dict) -> str:
        """Generate HTML report content"""
        vulnerabilities = report_data.get('vulnerabilities', [])
        
        if not vulnerabilities:
            vulnerabilities_content = '<div class="no-vulns">✅ No vulnerabilities found</div>'
        else:
            vulnerabilities_content = ''
            for vuln in vulnerabilities:
                severity = self._get_severity(vuln.get('injection_type', ''))
                vulnerabilities_content += f'''
                <div class="vulnerability {severity}">
                    <h3>🎯 {vuln.get("parameter", "Unknown Parameter")}</h3>
                    <p><strong>URL:</strong> {vuln.get("url", "Unknown")}</p>
                    <p><strong>Payload:</strong> {vuln.get("payload", "Unknown")}</p>
                    <p><strong>Type:</strong> {vuln.get("injection_type", "Unknown")}</p>
                    <p><strong>Redirect URL:</strong> {vuln.get("redirect_url", "Unknown")}</p>
                </div>
                '''
        
        html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Open Redirect Vulnerability Report</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 20px;
            line-height: 1.6;
            color: #333;
            background-color: #f5f5f5;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        
        h1 {{
            color: #2c3e50;
            text-align: center;
            margin-bottom: 30px;
        }}
        
        .summary {{
            background: #ecf0f1;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
        }}
        
        .vulnerability {{
            border: 1px solid #ddd;
            margin: 10px 0;
            padding: 15px;
            border-radius: 5px;
        }}
        
        .high {{ border-left: 5px solid #e74c3c; }}
        .medium {{ border-left: 5px solid #f39c12; }}
        .low {{ border-left: 5px solid #27ae60; }}
        
        .no-vulns {{
            text-align: center;
            color: #27ae60;
            font-size: 18px;
            padding: 40px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 Open Redirect Vulnerability Report</h1>
        
        <div class="summary">
            <h2>📊 Scan Summary</h2>
            <p><strong>Target URL:</strong> {report_data.get('target_url', 'Unknown')}</p>
            <p><strong>Scan Time:</strong> {report_data.get('scan_timestamp', 'Unknown')}</p>
            <p><strong>Total Vulnerabilities:</strong> {report_data.get('total_vulnerabilities', 0)}</p>
        </div>
        
        {vulnerabilities_content}
    </div>
</body>
</html>
"""
        
        return html_content