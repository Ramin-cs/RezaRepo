#!/usr/bin/env python3
"""
Working XSS Scanner - No Timeouts, Simple & Effective
Author: AI Assistant
Version: Working 1.0
"""

import requests
import re
import urllib.parse
import os
from urllib.parse import urljoin, urlparse, parse_qs
from datetime import datetime

def log(message, level="INFO"):
    colors = {"INFO": "\033[0m", "SUCCESS": "\033[92m", "VULN": "\033[92m\033[1m", "TEST": "\033[95m\033[1m"}
    timestamp = datetime.now().strftime("%H:%M:%S")
    print(f"{colors.get(level, '')}[{timestamp}] [{level}] {message}\033[0m")

def scan_xss(target_url):
    """Main XSS scanning function"""
    log("🚀 Starting Working XSS Scanner", "SUCCESS")
    log(f"Target: {target_url}", "INFO")
    log("=" * 60, "SUCCESS")
    
    # Setup session
    session = requests.Session()
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    })
    
    # Simple payloads
    payloads = [
        '<script>alert("XSS")</script>',
        '<img src=x onerror=alert("XSS")>',
        '" onmouseover="alert(\'XSS\')" x="'
    ]
    
    vulnerabilities = []
    
    try:
        # Step 1: Get main page
        log("🔍 Getting main page...", "INFO")
        response = session.get(target_url, timeout=3)
        log(f"Target accessible (Status: {response.status_code})", "SUCCESS")
        
        html_content = response.text
        
        # Step 2: Find URLs with parameters
        log("🔍 Finding URLs with parameters...", "INFO")
        urls_with_params = set()
        urls_with_params.add(target_url)
        
        # Find links with parameters
        links = re.findall(r'href=["\']([^"\']+)["\']', html_content, re.IGNORECASE)
        for link in links:
            if '=' in link and not link.startswith('#') and not link.startswith('javascript:'):
                full_url = urljoin(target_url, link)
                if is_same_domain(target_url, full_url):
                    urls_with_params.add(full_url)
                    if len(urls_with_params) >= 5:  # Limit for speed
                        break
        
        # Step 3: Find forms
        log("🔍 Finding forms...", "INFO")
        forms = []
        form_matches = re.findall(r'<form[^>]*>(.*?)</form>', html_content, re.IGNORECASE | re.DOTALL)
        
        for form_html in form_matches:
            form_data = parse_form_simple(form_html, target_url)
            if form_data:
                forms.append(form_data)
        
        # Step 4: Extract parameters
        url_parameters = set()
        for url in urls_with_params:
            parsed_url = urlparse(url)
            params = parse_qs(parsed_url.query)
            url_parameters.update(params.keys())
        
        form_parameters = set()
        for form in forms:
            for input_field in form['inputs']:
                if input_field['name']:
                    form_parameters.add(input_field['name'])
        
        log(f"Discovered {len(urls_with_params)} URLs", "SUCCESS")
        log(f"Found {len(forms)} forms", "SUCCESS")
        log(f"Found {len(url_parameters)} URL parameters", "SUCCESS")
        log(f"Found {len(form_parameters)} form parameters", "SUCCESS")
        
        # Show parameters
        if url_parameters:
            log("URL Parameters:", "SUCCESS")
            for param in sorted(url_parameters):
                log(f"  • {param}", "SUCCESS")
        
        if form_parameters:
            log("Form Parameters:", "SUCCESS")
            for param in sorted(form_parameters):
                log(f"  • {param}", "SUCCESS")
        
        # Step 5: Test URL parameters
        log("🎯 Testing URL parameters...", "INFO")
        for url in urls_with_params:
            parsed_url = urlparse(url)
            url_params = parse_qs(parsed_url.query)
            
            for param_name in url_params:
                log(f"Testing URL parameter: {param_name}", "TEST")
                
                for payload in payloads:
                    vuln = test_url_parameter(session, url, param_name, payload)
                    if vuln:
                        vulnerabilities.append(vuln)
                        log(f"✅ XSS FOUND! Parameter: {param_name}", "VULN")
                        break
        
        # Step 6: Test form parameters
        log("🎯 Testing form parameters...", "INFO")
        for form in forms:
            for input_field in form['inputs']:
                if input_field['name']:
                    log(f"Testing form parameter: {input_field['name']}", "TEST")
                    
                    for payload in payloads:
                        vuln = test_form_parameter(session, form, input_field['name'], payload)
                        if vuln:
                            vulnerabilities.append(vuln)
                            log(f"✅ XSS FOUND! Parameter: {input_field['name']}", "VULN")
                            break
        
        # Step 7: Generate report
        generate_report(target_url, vulnerabilities)
        
        # Step 8: Show results
        log("=" * 60, "SUCCESS")
        log("SCAN RESULTS", "SUCCESS")
        log("=" * 60, "SUCCESS")
        
        total_vulns = len(vulnerabilities)
        log(f"Total vulnerabilities: {total_vulns}", "SUCCESS")
        
        if vulnerabilities:
            log("\nVulnerabilities found:", "VULN")
            for i, vuln in enumerate(vulnerabilities, 1):
                log(f"  {i}. {vuln.get('type', 'unknown')} - {vuln.get('parameter', 'unknown')}", "VULN")
                log(f"     URL: {vuln.get('url', 'unknown')}", "VULN")
        else:
            log("No vulnerabilities found", "INFO")
        
        return vulnerabilities
        
    except Exception as e:
        log(f"Scan failed: {str(e)}", "ERROR")
        return []

def is_same_domain(target_url, url):
    """Check if URL is from same domain"""
    try:
        target_domain = urlparse(target_url).netloc
        url_domain = urlparse(url).netloc
        return target_domain == url_domain
    except:
        return False

def parse_form_simple(form_html, base_url):
    """Simple form parsing"""
    try:
        # Extract action
        action_match = re.search(r'action=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
        action = action_match.group(1) if action_match else ''
        
        # Extract method
        method_match = re.search(r'method=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
        method = method_match.group(1).upper() if method_match else 'GET'
        
        # Extract inputs
        inputs = []
        input_matches = re.findall(r'<(?:input|textarea|select)[^>]*name=["\']([^"\']+)["\'][^>]*>', form_html, re.IGNORECASE)
        
        for name in input_matches:
            inputs.append({
                'name': name,
                'type': 'text',
                'value': ''
            })
        
        if inputs:
            return {
                'action': urljoin(base_url, action) if action else base_url,
                'method': method,
                'inputs': inputs
            }
    except:
        pass
    
    return None

def test_url_parameter(session, url, param_name, payload):
    """Test URL parameter for XSS"""
    try:
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        query_params[param_name] = [payload]
        
        new_query = urllib.parse.urlencode(query_params, doseq=True)
        test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{new_query}"
        
        response = session.get(test_url, timeout=3)
        
        # Simple detection
        if payload in response.text:
            return {
                'type': 'reflected_xss',
                'url': test_url,
                'parameter': param_name,
                'payload': payload,
                'confidence': 'high',
                'method': 'GET'
            }
    
    except Exception as e:
        log(f"Error testing URL parameter: {str(e)}", "ERROR")
    
    return None

def test_form_parameter(session, form, param_name, payload):
    """Test form parameter for XSS"""
    try:
        form_data = {}
        for field in form['inputs']:
            if field['name'] == param_name:
                form_data[field['name']] = payload
            else:
                form_data[field['name']] = 'test'
        
        if form['method'] == 'POST':
            response = session.post(form['action'], data=form_data, timeout=3)
        else:
            response = session.get(form['action'], params=form_data, timeout=3)
        
        # Simple detection
        if payload in response.text:
            return {
                'type': 'reflected_xss',
                'url': form['action'],
                'parameter': param_name,
                'payload': payload,
                'confidence': 'high',
                'method': form['method']
            }
    
    except Exception as e:
        log(f"Error testing form parameter: {str(e)}", "ERROR")
    
    return None

def generate_report(target_url, vulnerabilities):
    """Generate HTML report"""
    log("📊 Generating report...", "INFO")
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    os.makedirs('reports', exist_ok=True)
    report_path = f'reports/working_report_{timestamp}.html'
    
    html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Working XSS Scanner Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .container {{ max-width: 800px; margin: 0 auto; background: white; padding: 20px; border-radius: 10px; }}
        .header {{ text-align: center; color: #333; }}
        .vulnerability {{ background: #f8f9fa; border-left: 4px solid #28a745; margin: 15px 0; padding: 15px; }}
        .payload {{ background: #e9ecef; padding: 10px; font-family: monospace; word-break: break-all; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🚀 Working XSS Scanner Report</h1>
            <p>Target: {target_url}</p>
            <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p>Total Vulnerabilities: {len(vulnerabilities)}</p>
        </div>
"""
    
    if not vulnerabilities:
        html_content += '<div style="text-align: center; color: #28a745; font-size: 1.2em;">✅ No vulnerabilities found</div>'
    else:
        for i, vuln in enumerate(vulnerabilities, 1):
            html_content += f"""
            <div class="vulnerability">
                <h3>🔍 Vulnerability #{i}</h3>
                <p><strong>Type:</strong> {vuln.get('type', 'unknown')}</p>
                <p><strong>URL:</strong> {vuln.get('url', 'unknown')}</p>
                <p><strong>Parameter:</strong> {vuln.get('parameter', 'unknown')}</p>
                <p><strong>Payload:</strong></p>
                <div class="payload">{vuln.get('payload', 'unknown')}</div>
                <p><strong>Method:</strong> {vuln.get('method', 'GET')}</p>
            </div>
"""
    
    html_content += """
    </div>
</body>
</html>
"""
    
    try:
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        log(f"Report generated: {report_path}", "SUCCESS")
        return report_path
        
    except Exception as e:
        log(f"Error generating report: {str(e)}", "ERROR")
        return None

def main():
    import sys
    if len(sys.argv) != 2:
        print("Usage: python working_xss_scanner.py <URL>")
        sys.exit(1)
    
    target_url = sys.argv[1]
    scan_xss(target_url)

if __name__ == "__main__":
    main()