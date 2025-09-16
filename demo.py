#!/usr/bin/env python3
"""
Demo script for Advanced Bug Bounty Tool
This script demonstrates how to use the tool programmatically
"""

import json
import os
import sys
from datetime import datetime

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def demo_reconnaissance():
    """Demonstrate reconnaissance functionality"""
    print("🔍 Demo: Reconnaissance Phase")
    print("=" * 50)
    
    # Simulate reconnaissance results
    recon_results = {
        'target': 'demo.example.com',
        'timestamp': datetime.now().isoformat(),
        'subdomains': [
            'www.demo.example.com',
            'api.demo.example.com',
            'admin.demo.example.com',
            'staging.demo.example.com',
            'dev.demo.example.com'
        ],
        'valid_subdomains': [
            {
                'subdomain': 'www.demo.example.com',
                'protocol': 'https',
                'status_code': 200,
                'title': 'Demo Website - Home',
                'server': 'nginx/1.18.0'
            },
            {
                'subdomain': 'api.demo.example.com',
                'protocol': 'https',
                'status_code': 200,
                'title': 'API Documentation',
                'server': 'nginx/1.18.0'
            },
            {
                'subdomain': 'admin.demo.example.com',
                'protocol': 'https',
                'status_code': 403,
                'title': 'Access Denied',
                'server': 'nginx/1.18.0'
            }
        ],
        'directories': [
            {
                'path': '/admin',
                'url': 'https://demo.example.com/admin',
                'status_code': 403,
                'content_length': 1234,
                'server': 'nginx/1.18.0'
            },
            {
                'path': '/api',
                'url': 'https://demo.example.com/api',
                'status_code': 200,
                'content_length': 5678,
                'server': 'nginx/1.18.0'
            },
            {
                'path': '/robots.txt',
                'url': 'https://demo.example.com/robots.txt',
                'status_code': 200,
                'content_length': 234,
                'server': 'nginx/1.18.0'
            }
        ],
        'parameters': [
            'id', 'page', 'search', 'q', 'url', 'redirect', 'return', 'next', 'callback'
        ],
        'waf_info': {
            'detected': True,
            'type': 'Cloudflare',
            'confidence': 85,
            'indicators': [
                'cf-ray header detected',
                'Cloudflare error page pattern',
                'Rate limiting behavior'
            ]
        }
    }
    
    print(f"✅ Found {len(recon_results['subdomains'])} subdomains")
    print(f"✅ Validated {len(recon_results['valid_subdomains'])} subdomains")
    print(f"✅ Discovered {len(recon_results['directories'])} directories")
    print(f"✅ Found {len(recon_results['parameters'])} parameters")
    print(f"✅ WAF detected: {recon_results['waf_info']['type']}")
    
    return recon_results

def demo_vulnerability_scanning():
    """Demonstrate vulnerability scanning functionality"""
    print("\n🚨 Demo: Vulnerability Scanning Phase")
    print("=" * 50)
    
    # Simulate vulnerability scan results
    vulnerabilities = [
        {
            'type': 'XSS',
            'subtype': 'Reflected XSS',
            'url': 'https://demo.example.com/search?q=<script>alert("XSS")</script>',
            'parameter': 'q',
            'payload': '<script>alert("XSS")</script>',
            'severity': 'High',
            'description': 'Reflected XSS found in search parameter',
            'evidence': 'Payload reflected in response without proper encoding',
            'target_subdomain': 'www.demo.example.com',
            'scan_timestamp': datetime.now().isoformat()
        },
        {
            'type': 'SQL Injection',
            'subtype': 'Union-based SQL Injection',
            'url': 'https://demo.example.com/user?id=1\' UNION SELECT 1,2,3--',
            'parameter': 'id',
            'payload': '1\' UNION SELECT 1,2,3--',
            'severity': 'Critical',
            'description': 'SQL Injection found in user ID parameter',
            'evidence': 'SQL error message detected in response',
            'target_subdomain': 'www.demo.example.com',
            'scan_timestamp': datetime.now().isoformat()
        },
        {
            'type': 'Open Redirect',
            'subtype': 'Unvalidated Redirect',
            'url': 'https://demo.example.com/redirect?url=http://evil.com',
            'parameter': 'url',
            'payload': 'http://evil.com',
            'severity': 'Medium',
            'description': 'Open Redirect found in redirect parameter',
            'evidence': 'Redirects to external domain without validation',
            'target_subdomain': 'www.demo.example.com',
            'scan_timestamp': datetime.now().isoformat()
        }
    ]
    
    print(f"✅ Found {len(vulnerabilities)} vulnerabilities:")
    for vuln in vulnerabilities:
        print(f"   - {vuln['type']} ({vuln['severity']}): {vuln['description']}")
    
    return vulnerabilities

def demo_html_report_generation(recon_results, vulnerabilities):
    """Demonstrate HTML report generation"""
    print("\n📄 Demo: HTML Report Generation")
    print("=" * 50)
    
    # Calculate statistics
    total_vulnerabilities = len(vulnerabilities)
    critical_count = len([v for v in vulnerabilities if v['severity'].lower() == 'critical'])
    high_count = len([v for v in vulnerabilities if v['severity'].lower() == 'high'])
    medium_count = len([v for v in vulnerabilities if v['severity'].lower() == 'medium'])
    subdomains_count = len(recon_results['subdomains'])
    directories_count = len(recon_results['directories'])
    
    # Generate HTML report
    html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Bug Bounty Report - Demo</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background-color: #f5f5f5;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }}
        
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
            text-align: center;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }}
        
        .header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
        }}
        
        .summary {{
            background: white;
            padding: 25px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
        }}
        
        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 20px;
        }}
        
        .stat-card {{
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            border-left: 4px solid #667eea;
        }}
        
        .stat-number {{
            font-size: 2em;
            font-weight: bold;
            color: #667eea;
        }}
        
        .vulnerability {{
            background: #fff5f5;
            border: 1px solid #fed7d7;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 15px;
        }}
        
        .vulnerability.critical {{
            background: #fff5f5;
            border-color: #f56565;
        }}
        
        .vulnerability.high {{
            background: #fffaf0;
            border-color: #ed8936;
        }}
        
        .vulnerability.medium {{
            background: #f0fff4;
            border-color: #48bb78;
        }}
        
        .severity {{
            padding: 5px 15px;
            border-radius: 20px;
            color: white;
            font-weight: bold;
            text-transform: uppercase;
            font-size: 0.8em;
            display: inline-block;
            margin-bottom: 10px;
        }}
        
        .severity.critical {{
            background: #e53e3e;
        }}
        
        .severity.high {{
            background: #dd6b20;
        }}
        
        .severity.medium {{
            background: #38a169;
        }}
        
        .code-block {{
            background: #2d3748;
            color: #e2e8f0;
            padding: 15px;
            border-radius: 5px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            overflow-x: auto;
            margin: 10px 0;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Bug Bounty Security Report</h1>
            <p>Target: demo.example.com</p>
            <p>Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
        
        <div class="summary">
            <h2>📊 Executive Summary</h2>
            <div class="stats">
                <div class="stat-card">
                    <div class="stat-number">{total_vulnerabilities}</div>
                    <div>Total Vulnerabilities</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{critical_count}</div>
                    <div>Critical</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{high_count}</div>
                    <div>High</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{medium_count}</div>
                    <div>Medium</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{subdomains_count}</div>
                    <div>Subdomains Found</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{directories_count}</div>
                    <div>Directories Found</div>
                </div>
            </div>
        </div>
        
        <div class="summary">
            <h2>🚨 Vulnerabilities Found</h2>"""
    
    # Add vulnerabilities
    for vuln in vulnerabilities:
        html_content += f"""
            <div class="vulnerability {vuln['severity'].lower()}">
                <div class="severity {vuln['severity'].lower()}">{vuln['severity']}</div>
                <h3>{vuln['type']} - {vuln['subtype']}</h3>
                <p><strong>Description:</strong> {vuln['description']}</p>
                <p><strong>URL:</strong> {vuln['url']}</p>
                <p><strong>Parameter:</strong> {vuln['parameter']}</p>
                <p><strong>Evidence:</strong> {vuln['evidence']}</p>
                <div class="code-block">
                    <strong>Payload:</strong><br>
                    {vuln['payload']}
                </div>
            </div>"""
    
    html_content += """
        </div>
    </div>
</body>
</html>"""
    
    # Save HTML report
    with open('demo_report.html', 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    print(f"✅ Generated HTML report with {total_vulnerabilities} vulnerabilities")
    print("📄 Report saved as 'demo_report.html'")
    
    return 'demo_report.html'

def demo_json_export(recon_results, vulnerabilities):
    """Demonstrate JSON export functionality"""
    print("\n📋 Demo: JSON Export")
    print("=" * 50)
    
    # Create complete scan result
    scan_result = {
        'target': 'demo.example.com',
        'timestamp': datetime.now().isoformat(),
        'reconnaissance': recon_results,
        'vulnerabilities': vulnerabilities,
        'summary': {
            'total_vulnerabilities': len(vulnerabilities),
            'critical_vulnerabilities': len([v for v in vulnerabilities if v['severity'].lower() == 'critical']),
            'high_vulnerabilities': len([v for v in vulnerabilities if v['severity'].lower() == 'high']),
            'medium_vulnerabilities': len([v for v in vulnerabilities if v['severity'].lower() == 'medium']),
            'subdomains_found': len(recon_results['subdomains']),
            'directories_found': len(recon_results['directories']),
            'parameters_found': len(recon_results['parameters']),
            'waf_detected': recon_results['waf_info']['detected']
        }
    }
    
    # Save JSON export
    with open('demo_results.json', 'w', encoding='utf-8') as f:
        json.dump(scan_result, f, indent=2)
    
    print("✅ Exported complete scan results to JSON")
    print("📄 Results saved as 'demo_results.json'")
    
    return 'demo_results.json'

def main():
    """Run the complete demo"""
    print("🎯 Advanced Bug Bounty Tool - Demo")
    print("=" * 60)
    print("This demo shows the complete workflow of the bug bounty tool")
    print("=" * 60)
    
    try:
        # Phase 1: Reconnaissance
        recon_results = demo_reconnaissance()
        
        # Phase 2: Vulnerability Scanning
        vulnerabilities = demo_vulnerability_scanning()
        
        # Phase 3: Report Generation
        html_report = demo_html_report_generation(recon_results, vulnerabilities)
        json_export = demo_json_export(recon_results, vulnerabilities)
        
        print("\n" + "=" * 60)
        print("🎉 Demo completed successfully!")
        print("=" * 60)
        print("Generated files:")
        print(f"  📄 HTML Report: {html_report}")
        print(f"  📋 JSON Export: {json_export}")
        print("\nTo run the actual tool:")
        print("  python main.py target.com")
        print("\nFor more information, see README.md")
        
    except Exception as e:
        print(f"\n❌ Demo failed: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())