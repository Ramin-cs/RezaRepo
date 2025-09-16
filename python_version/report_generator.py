#!/usr/bin/env python3
"""
HTML Report Generator for Bug Bounty Tool
Generates comprehensive HTML reports from reconnaissance and vulnerability scan results

Author: Security Researcher
Version: 1.0.0
"""

import json
import os
from datetime import datetime
from jinja2 import Template

class HTMLReportGenerator:
    """
    Generates comprehensive HTML reports from reconnaissance and vulnerability scan results
    """
    
    def __init__(self, output_dir="reports"):
        """
        Initialize the HTML report generator
        
        Args:
            output_dir (str): Directory to save HTML reports
        """
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
    
    def generate_report(self, recon_results, vuln_results, target_domain):
        """
        Generate comprehensive HTML report
        
        Args:
            recon_results (dict): Reconnaissance results
            vuln_results (list): Vulnerability scan results
            target_domain (str): Target domain
        """
        # HTML template
        html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Bug Bounty Report - {{ target_domain }}</title>
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
            text-align: center;
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
        
        .summary {
            background: white;
            padding: 25px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
        }
        
        .summary h2 {
            color: #667eea;
            margin-bottom: 20px;
            border-bottom: 2px solid #667eea;
            padding-bottom: 10px;
        }
        
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 20px;
        }
        
        .stat-card {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            border-left: 4px solid #667eea;
        }
        
        .stat-number {
            font-size: 2em;
            font-weight: bold;
            color: #667eea;
        }
        
        .stat-label {
            color: #666;
            margin-top: 5px;
        }
        
        .section {
            background: white;
            padding: 25px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
        }
        
        .section h2 {
            color: #667eea;
            margin-bottom: 20px;
            border-bottom: 2px solid #667eea;
            padding-bottom: 10px;
        }
        
        .vulnerability {
            background: #fff5f5;
            border: 1px solid #fed7d7;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 15px;
        }
        
        .vulnerability.critical {
            background: #fff5f5;
            border-color: #f56565;
        }
        
        .vulnerability.high {
            background: #fffaf0;
            border-color: #ed8936;
        }
        
        .vulnerability.medium {
            background: #f0fff4;
            border-color: #48bb78;
        }
        
        .vulnerability.low {
            background: #f7fafc;
            border-color: #4299e1;
        }
        
        .vuln-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }
        
        .vuln-type {
            font-size: 1.2em;
            font-weight: bold;
            color: #2d3748;
        }
        
        .severity {
            padding: 5px 15px;
            border-radius: 20px;
            color: white;
            font-weight: bold;
            text-transform: uppercase;
            font-size: 0.8em;
        }
        
        .severity.critical {
            background: #e53e3e;
        }
        
        .severity.high {
            background: #dd6b20;
        }
        
        .severity.medium {
            background: #38a169;
        }
        
        .severity.low {
            background: #3182ce;
        }
        
        .vuln-details {
            margin-bottom: 15px;
        }
        
        .vuln-details p {
            margin-bottom: 10px;
        }
        
        .vuln-details strong {
            color: #2d3748;
        }
        
        .code-block {
            background: #2d3748;
            color: #e2e8f0;
            padding: 15px;
            border-radius: 5px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            overflow-x: auto;
            margin: 10px 0;
        }
        
        .subdomain-list, .directory-list, .parameter-list {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
            gap: 10px;
        }
        
        .list-item {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            border-left: 4px solid #667eea;
        }
        
        .waf-info {
            background: #f0f4f8;
            padding: 20px;
            border-radius: 8px;
            border-left: 4px solid #4299e1;
        }
        
        .waf-detected {
            background: #fff5f5;
            border-left-color: #f56565;
        }
        
        .footer {
            text-align: center;
            padding: 30px;
            color: #666;
            border-top: 1px solid #e2e8f0;
            margin-top: 30px;
        }
        
        .timestamp {
            color: #a0aec0;
            font-size: 0.9em;
        }
        
        @media (max-width: 768px) {
            .container {
                padding: 10px;
            }
            
            .header h1 {
                font-size: 2em;
            }
            
            .stats {
                grid-template-columns: 1fr;
            }
            
            .vuln-header {
                flex-direction: column;
                align-items: flex-start;
            }
            
            .severity {
                margin-top: 10px;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Bug Bounty Security Report</h1>
            <p>Target: {{ target_domain }}</p>
            <p class="timestamp">Generated on {{ timestamp }}</p>
        </div>
        
        <div class="summary">
            <h2>📊 Executive Summary</h2>
            <div class="stats">
                <div class="stat-card">
                    <div class="stat-number">{{ total_vulnerabilities }}</div>
                    <div class="stat-label">Total Vulnerabilities</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{{ critical_count }}</div>
                    <div class="stat-label">Critical</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{{ high_count }}</div>
                    <div class="stat-label">High</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{{ medium_count }}</div>
                    <div class="stat-label">Medium</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{{ subdomains_count }}</div>
                    <div class="stat-label">Subdomains Found</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{{ directories_count }}</div>
                    <div class="stat-label">Directories Found</div>
                </div>
            </div>
        </div>
        
        {% if vulnerabilities %}
        <div class="section">
            <h2>🚨 Vulnerabilities Found</h2>
            {% for vuln in vulnerabilities %}
            <div class="vulnerability {{ vuln.severity.lower() }}">
                <div class="vuln-header">
                    <div class="vuln-type">{{ vuln.type }} - {{ vuln.subtype }}</div>
                    <div class="severity {{ vuln.severity.lower() }}">{{ vuln.severity }}</div>
                </div>
                <div class="vuln-details">
                    <p><strong>Description:</strong> {{ vuln.description }}</p>
                    <p><strong>URL:</strong> {{ vuln.url }}</p>
                    <p><strong>Parameter:</strong> {{ vuln.parameter }}</p>
                    <p><strong>Evidence:</strong> {{ vuln.evidence }}</p>
                    <div class="code-block">
                        <strong>Payload:</strong><br>
                        {{ vuln.payload }}
                    </div>
                </div>
            </div>
            {% endfor %}
        </div>
        {% endif %}
        
        {% if recon_results.subdomains %}
        <div class="section">
            <h2>🌐 Subdomains Discovered</h2>
            <div class="subdomain-list">
                {% for subdomain in recon_results.subdomains %}
                <div class="list-item">
                    <strong>{{ subdomain }}</strong>
                </div>
                {% endfor %}
            </div>
        </div>
        {% endif %}
        
        {% if recon_results.valid_subdomains %}
        <div class="section">
            <h2>✅ Valid Subdomains</h2>
            <div class="subdomain-list">
                {% for subdomain in recon_results.valid_subdomains %}
                <div class="list-item">
                    <strong>{{ subdomain.subdomain }}</strong><br>
                    <small>Protocol: {{ subdomain.protocol }} | Status: {{ subdomain.status_code }} | Server: {{ subdomain.server }}</small>
                </div>
                {% endfor %}
            </div>
        </div>
        {% endif %}
        
        {% if recon_results.directories %}
        <div class="section">
            <h2>📁 Directories & Files Found</h2>
            <div class="directory-list">
                {% for directory in recon_results.directories %}
                <div class="list-item">
                    <strong>{{ directory.path }}</strong><br>
                    <small>Status: {{ directory.status_code }} | Size: {{ directory.content_length }} bytes</small>
                </div>
                {% endfor %}
            </div>
        </div>
        {% endif %}
        
        {% if recon_results.parameters %}
        <div class="section">
            <h2>🔍 Parameters Discovered</h2>
            <div class="parameter-list">
                {% for param in recon_results.parameters %}
                <div class="list-item">
                    <strong>{{ param }}</strong>
                </div>
                {% endfor %}
            </div>
        </div>
        {% endif %}
        
        {% if recon_results.waf_info %}
        <div class="section">
            <h2>🛡️ WAF Detection Results</h2>
            <div class="waf-info {% if recon_results.waf_info.detected %}waf-detected{% endif %}">
                <p><strong>WAF Detected:</strong> {{ 'Yes' if recon_results.waf_info.detected else 'No' }}</p>
                {% if recon_results.waf_info.detected %}
                <p><strong>WAF Type:</strong> {{ recon_results.waf_info.type }}</p>
                <p><strong>Confidence:</strong> {{ recon_results.waf_info.confidence }}%</p>
                {% if recon_results.waf_info.indicators %}
                <p><strong>Indicators:</strong></p>
                <ul>
                    {% for indicator in recon_results.waf_info.indicators %}
                    <li>{{ indicator }}</li>
                    {% endfor %}
                </ul>
                {% endif %}
                {% endif %}
            </div>
        </div>
        {% endif %}
        
        <div class="footer">
            <p>Report generated by Advanced Bug Bounty Tool</p>
            <p class="timestamp">Generated on {{ timestamp }}</p>
        </div>
    </div>
</body>
</html>
        """
        
        # Calculate statistics
        total_vulnerabilities = len(vuln_results)
        critical_count = len([v for v in vuln_results if v.get('severity', '').lower() == 'critical'])
        high_count = len([v for v in vuln_results if v.get('severity', '').lower() == 'high'])
        medium_count = len([v for v in vuln_results if v.get('severity', '').lower() == 'medium'])
        subdomains_count = len(recon_results.get('subdomains', []))
        directories_count = len(recon_results.get('directories', []))
        
        # Render template
        template = Template(html_template)
        html_content = template.render(
            target_domain=target_domain,
            timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            total_vulnerabilities=total_vulnerabilities,
            critical_count=critical_count,
            high_count=high_count,
            medium_count=medium_count,
            subdomains_count=subdomains_count,
            directories_count=directories_count,
            vulnerabilities=vuln_results,
            recon_results=recon_results
        )
        
        # Save HTML report
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"bug_bounty_report_{target_domain}_{timestamp}.html"
        filepath = os.path.join(self.output_dir, filename)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return filepath

if __name__ == "__main__":
    # Example usage
    generator = HTMLReportGenerator()
    
    # Example data
    recon_results = {
        'subdomains': ['www.example.com', 'api.example.com', 'admin.example.com'],
        'valid_subdomains': [
            {'subdomain': 'www.example.com', 'protocol': 'https', 'status_code': 200, 'server': 'nginx'},
            {'subdomain': 'api.example.com', 'protocol': 'https', 'status_code': 200, 'server': 'nginx'}
        ],
        'directories': [
            {'path': '/admin', 'status_code': 403, 'content_length': 1234},
            {'path': '/api', 'status_code': 200, 'content_length': 5678}
        ],
        'parameters': ['id', 'page', 'search', 'redirect'],
        'waf_info': {
            'detected': True,
            'type': 'Cloudflare',
            'confidence': 85,
            'indicators': ['cf-ray header detected', 'Cloudflare error page']
        }
    }
    
    vuln_results = [
        {
            'type': 'XSS',
            'subtype': 'Reflected XSS',
            'url': 'https://example.com/search?q=<script>alert("XSS")</script>',
            'parameter': 'q',
            'payload': '<script>alert("XSS")</script>',
            'severity': 'High',
            'description': 'Reflected XSS found in search parameter',
            'evidence': 'Payload reflected in response without proper encoding'
        }
    ]
    
    report_path = generator.generate_report(recon_results, vuln_results, 'example.com')
    print(f"Report generated: {report_path}")