#!/usr/bin/env python3
"""
🔥 REPORT GENERATOR - Complete Reporting System
"""

import json
import csv
from datetime import datetime
from typing import List
from data_models import Parameter, Vulnerability, ScanResults


class ReportGenerator:
    """Complete reporting system"""
    
    def __init__(self, target_url: str, base_domain: str):
        self.target_url = target_url
        self.base_domain = base_domain
    
    def save_json_results(self, parameters: List[Parameter], vulnerabilities: List[Vulnerability], 
                         discovered_urls: set, js_files: set, payloads: List[str], scan_duration: float):
        """Save complete JSON results"""
        redirect_params = [p for p in parameters if p.is_redirect_related]
        web3_params = [p for p in parameters if p.source == 'web3']
        js_params = [p for p in parameters if p.source == 'javascript']
        
        results_data = {
            'scan_info': {
                'target_url': self.target_url,
                'scan_date': datetime.now().isoformat(),
                'scanner_version': 'Ultimate Hunter v3.0 - Complete Modular Edition',
                'scan_duration': scan_duration,
                'total_parameters': len(parameters),
                'redirect_parameters': len(redirect_params),
                'web3_parameters': len(web3_params),
                'javascript_parameters': len(js_params),
                'vulnerabilities_found': len(vulnerabilities),
                'urls_discovered': len(discovered_urls),
                'js_files_analyzed': len(js_files),
                'payload_arsenal_size': len(payloads),
                'web3_detected': len(web3_params) > 0
            },
            'statistics': {
                'high_confidence_params': len([p for p in parameters if p.confidence > 0.7]),
                'medium_confidence_params': len([p for p in parameters if 0.4 <= p.confidence <= 0.7]),
                'low_confidence_params': len([p for p in parameters if p.confidence < 0.4]),
                'critical_vulns': len([v for v in vulnerabilities if v.impact == 'CRITICAL']),
                'high_vulns': len([v for v in vulnerabilities if v.impact == 'HIGH']),
                'medium_vulns': len([v for v in vulnerabilities if v.impact == 'MEDIUM'])
            },
            'parameters': [
                {
                    'name': p.name,
                    'value': p.value,
                    'source': p.source,
                    'context': p.context,
                    'url': p.url,
                    'method': p.method,
                    'is_redirect_related': p.is_redirect_related,
                    'confidence': p.confidence,
                    'line_number': p.line_number,
                    'pattern_matched': p.pattern_matched
                } for p in parameters
            ],
            'vulnerabilities': [
                {
                    'url': v.url,
                    'parameter': v.parameter,
                    'payload': v.payload,
                    'method': v.method,
                    'response_code': v.response_code,
                    'redirect_url': v.redirect_url,
                    'context': v.context,
                    'screenshot_path': v.screenshot_path,
                    'timestamp': v.timestamp,
                    'vulnerability_type': v.vulnerability_type,
                    'confidence': v.confidence,
                    'impact': v.impact,
                    'remediation': v.remediation,
                    'cvss_score': v.cvss_score,
                    'exploitation_complexity': v.exploitation_complexity,
                    'business_impact': v.business_impact,
                    'poc_steps': v.poc_steps
                } for v in vulnerabilities
            ]
        }
        
        with open('ULTIMATE_COMPLETE_RESULTS.json', 'w', encoding='utf-8') as f:
            json.dump(results_data, f, indent=2, ensure_ascii=False)
        
        print("[STORAGE] Complete results: ULTIMATE_COMPLETE_RESULTS.json")
    
    def save_csv_analysis(self, parameters: List[Parameter], vulnerabilities: List[Vulnerability]):
        """Save CSV analysis"""
        with open('ULTIMATE_COMPLETE_ANALYSIS.csv', 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = [
                'name', 'value', 'source', 'context', 'url', 'method',
                'is_redirect_related', 'confidence', 'line_number', 'vulnerability_found'
            ]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            vuln_params = {v.parameter for v in vulnerabilities}
            
            for param in parameters:
                writer.writerow({
                    'name': param.name,
                    'value': param.value[:200],
                    'source': param.source,
                    'context': param.context,
                    'url': param.url,
                    'method': param.method,
                    'is_redirect_related': param.is_redirect_related,
                    'confidence': f"{param.confidence:.3f}",
                    'line_number': param.line_number,
                    'vulnerability_found': param.name in vuln_params
                })
        
        print("[STORAGE] CSV analysis: ULTIMATE_COMPLETE_ANALYSIS.csv")
    
    def generate_matrix_html_report(self, parameters: List[Parameter], vulnerabilities: List[Vulnerability], 
                                  discovered_urls: set, payloads: List[str]):
        """Generate Matrix-themed HTML report"""
        redirect_params = [p for p in parameters if p.is_redirect_related]
        web3_params = [p for p in parameters if p.source == 'web3']
        js_params = [p for p in parameters if p.source == 'javascript']
        
        html_content = f'''<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>🔥 ULTIMATE HUNTER MATRIX REPORT 🔥</title>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700;900&display=swap');
        
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        
        body {{
            font-family: 'Orbitron', 'Courier New', monospace;
            background: linear-gradient(135deg, #0a0a0a 0%, #1a1a2e 50%, #16213e 100%);
            color: #00ff41;
            min-height: 100vh;
            overflow-x: hidden;
        }}
        
        .matrix-bg {{
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background-image: 
                radial-gradient(circle at 25% 25%, #00ff41 1px, transparent 1px),
                radial-gradient(circle at 75% 75%, #00ff41 1px, transparent 1px);
            background-size: 50px 50px;
            opacity: 0.1;
            z-index: -1;
            animation: matrix-move 20s infinite linear;
        }}
        
        @keyframes matrix-move {{
            0% {{ transform: translateY(0); }}
            100% {{ transform: translateY(50px); }}
        }}
        
        .container {{
            max-width: 1400px;
            margin: 20px auto;
            background: rgba(0, 0, 0, 0.95);
            border: 2px solid #00ff41;
            border-radius: 12px;
            box-shadow: 0 0 40px #00ff41;
            position: relative;
            z-index: 1;
        }}
        
        .header {{
            background: linear-gradient(135deg, #000000 0%, #1a1a2e 100%);
            color: #00ff41;
            padding: 40px;
            text-align: center;
            border-bottom: 3px solid #00ff41;
            position: relative;
        }}
        
        .header::before {{
            content: '';
            position: absolute;
            top: 0;
            left: -100%;
            width: 100%;
            height: 100%;
            background: linear-gradient(90deg, transparent, rgba(0, 255, 65, 0.3), transparent);
            animation: scan 3s infinite;
        }}
        
        @keyframes scan {{
            0% {{ left: -100%; }}
            100% {{ left: 100%; }}
        }}
        
        .header h1 {{
            font-size: 3em;
            font-weight: 900;
            text-shadow: 0 0 30px #00ff41;
            letter-spacing: 3px;
            margin-bottom: 10px;
        }}
        
        .content {{
            padding: 40px;
        }}
        
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 20px;
            margin-bottom: 40px;
        }}
        
        .summary-card {{
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            border: 2px solid #00ff41;
            border-radius: 10px;
            padding: 20px;
            text-align: center;
            box-shadow: 0 0 20px rgba(0, 255, 65, 0.3);
        }}
        
        .number {{
            font-size: 2.5em;
            font-weight: 900;
            color: #00ff41;
            text-shadow: 0 0 15px #00ff41;
        }}
        
        .vulnerability {{
            background: linear-gradient(135deg, #2d1b1b 0%, #1a0f0f 100%);
            border: 3px solid #ff4444;
            border-radius: 10px;
            padding: 25px;
            margin: 25px 0;
            box-shadow: 0 0 25px rgba(255, 68, 68, 0.4);
        }}
        
        .vulnerability.critical {{
            border-color: #ff0000;
            box-shadow: 0 0 30px rgba(255, 0, 0, 0.6);
        }}
        
        .parameter {{
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            border: 2px solid #00ff41;
            border-radius: 8px;
            padding: 20px;
            margin: 20px 0;
        }}
        
        .parameter.redirect {{
            border-color: #ff4444;
            box-shadow: 0 0 15px rgba(255, 68, 68, 0.3);
        }}
        
        .code {{
            background: #000000;
            color: #00ff41;
            padding: 15px;
            border-radius: 8px;
            font-family: 'Courier New', monospace;
            border: 2px solid #00ff41;
            overflow-x: auto;
        }}
        
        .success {{ color: #00ff41; font-weight: bold; }}
        .error {{ color: #ff4444; font-weight: bold; }}
        .critical {{ color: #ff0000; font-weight: bold; }}
        
        .screenshot {{
            max-width: 100%;
            border: 3px solid #00ff41;
            border-radius: 10px;
            margin: 15px 0;
        }}
        
        .blink {{
            animation: blink 1.5s infinite;
        }}
        
        @keyframes blink {{
            0%, 50% {{ opacity: 1; }}
            51%, 100% {{ opacity: 0; }}
        }}
    </style>
</head>
<body>
    <div class="matrix-bg"></div>
    <div class="container">
        <div class="header">
            <h1>🔥 ULTIMATE HUNTER REPORT 🔥</h1>
            <p class="blink">● CLASSIFIED SECURITY ASSESSMENT ●</p>
        </div>
        
        <div class="content">
            <div style="background: #000; color: #00ff41; padding: 25px; border: 2px solid #00ff41; border-radius: 10px; margin-bottom: 30px;">
                <h3>📊 MISSION PARAMETERS</h3>
                <p>TARGET: {self.target_url}</p>
                <p>SCAN DATE: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                <p>SCANNER: Ultimate Hunter v3.0 - Complete Modular Edition</p>
                <p>PAYLOAD ARSENAL: {len(payloads)} custom payloads</p>
                <p>CLASSIFICATION: CONFIDENTIAL</p>
            </div>
            
            <div class="summary">
                <div class="summary-card">
                    <h3>TARGET</h3>
                    <div class="number">{self.base_domain}</div>
                </div>
                <div class="summary-card">
                    <h3>URLs</h3>
                    <div class="number">{len(discovered_urls)}</div>
                </div>
                <div class="summary-card">
                    <h3>PARAMETERS</h3>
                    <div class="number">{len(parameters)}</div>
                </div>
                <div class="summary-card">
                    <h3>REDIRECT</h3>
                    <div class="number">{len(redirect_params)}</div>
                </div>
                <div class="summary-card">
                    <h3>WEB3</h3>
                    <div class="number">{len(web3_params)}</div>
                </div>
                <div class="summary-card">
                    <h3>PAYLOADS</h3>
                    <div class="number">{len(payloads)}</div>
                </div>
                <div class="summary-card">
                    <h3>VULNERABILITIES</h3>
                    <div class="number {'error' if len(vulnerabilities) > 0 else 'success'}">{len(vulnerabilities)}</div>
                </div>
            </div>
'''
        
        if vulnerabilities:
            html_content += "<h2 class='error'>🚨 VULNERABILITIES DETECTED 🚨</h2>\\n"
            for i, vuln in enumerate(vulnerabilities, 1):
                html_content += f'''
            <div class="vulnerability {vuln.impact.lower()}">
                <h3>VULNERABILITY #{i}: {vuln.vulnerability_type.upper()}</h3>
                <p><strong>PARAMETER:</strong> <code>{vuln.parameter}</code></p>
                <p><strong>PAYLOAD:</strong></p>
                <div class="code">{vuln.payload}</div>
                <p><strong>REDIRECT URL:</strong></p>
                <div class="code">{vuln.redirect_url}</div>
                <p><strong>IMPACT:</strong> <span class="{vuln.impact.lower()}">{vuln.impact}</span></p>
                <p><strong>CVSS:</strong> {vuln.cvss_score:.1f}</p>
'''
                if vuln.screenshot_path:
                    html_content += f'<p><strong>SCREENSHOT:</strong><br><img src="{vuln.screenshot_path}" class="screenshot"></p>'
                html_content += "</div>\\n"
        else:
            html_content += '''
            <div style="text-align: center; padding: 50px; background: rgba(0, 255, 65, 0.1); border-radius: 12px;">
                <h2 class="success">✅ NO VULNERABILITIES DETECTED ✅</h2>
                <p>TARGET APPEARS SECURE</p>
            </div>
'''
        
        html_content += '''
        </div>
    </div>
</body>
</html>
'''
        
        with open('ULTIMATE_MATRIX_REPORT.html', 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print("[REPORT] Matrix report: ULTIMATE_MATRIX_REPORT.html")
    
    def generate_bug_bounty_reports(self, vulnerabilities: List[Vulnerability]):
        """Generate bug bounty reports"""
        for i, vuln in enumerate(vulnerabilities, 1):
            # English report
            english_report = f"""# Open Redirect Vulnerability Report #{i}

## Summary
- **Target**: {self.target_url}
- **Severity**: {vuln.impact}
- **CVSS**: {vuln.cvss_score:.1f}
- **Parameter**: {vuln.parameter}

## Details
- **URL**: `{vuln.url}`
- **Payload**: `{vuln.payload}`
- **Redirect**: `{vuln.redirect_url}`

## PoC
1. Navigate to: `{vuln.url}`
2. Inject: `{vuln.payload}`
3. Observe redirect to: `{vuln.redirect_url}`

## Impact
This allows attackers to redirect users to malicious sites.

## Remediation
{vuln.remediation}

---
Report by Ultimate Hunter v3.0
"""
            
            # Persian report
            persian_report = f"""# گزارش آسیب‌پذیری Open Redirect شماره {i}

## خلاصه
- **هدف**: {self.target_url}
- **شدت**: {vuln.impact}
- **امتیاز CVSS**: {vuln.cvss_score:.1f}
- **پارامتر**: {vuln.parameter}

## جزئیات
- **URL**: `{vuln.url}`
- **Payload**: `{vuln.payload}`
- **انتقال**: `{vuln.redirect_url}`

## اثبات مفهوم
1. به آدرس بروید: `{vuln.url}`
2. تزریق کنید: `{vuln.payload}`
3. انتقال را مشاهده کنید: `{vuln.redirect_url}`

## تأثیر
این آسیب‌پذیری امکان هدایت کاربران به سایت‌های مخرب را فراهم می‌کند.

## راه حل
{vuln.remediation}

---
گزارش توسط Ultimate Hunter v3.0
"""
            
            # Save reports
            with open(f'BUG_BOUNTY_REPORT_{i}_ENGLISH.md', 'w', encoding='utf-8') as f:
                f.write(english_report)
            
            with open(f'BUG_BOUNTY_REPORT_{i}_PERSIAN.md', 'w', encoding='utf-8') as f:
                f.write(persian_report)
        
        print(f"[BUG-BOUNTY] Generated {len(vulnerabilities)} professional reports")