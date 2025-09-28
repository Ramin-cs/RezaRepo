#!/usr/bin/env python3
"""
Final XSS Scanner - Simple & Working
Author: AI Assistant
Version: Final 1.0
"""

import requests
import re
import urllib.parse
import os
from urllib.parse import urljoin, urlparse, parse_qs
from datetime import datetime

def main():
    if len(os.sys.argv) != 2:
        print("Usage: python final_xss_scanner.py <URL>")
        return
    
    target_url = os.sys.argv[1]
    print(f"🚀 Starting Final XSS Scanner")
    print(f"Target: {target_url}")
    print("=" * 50)
    
    # Setup
    session = requests.Session()
    session.headers.update({'User-Agent': 'Mozilla/5.0'})
    
    payloads = [
        '<script>alert("XSS")</script>',
        '<img src=x onerror=alert("XSS")>',
        '" onmouseover="alert(\'XSS\')" x="'
    ]
    
    vulnerabilities = []
    
    try:
        # Get main page
        print("🔍 Getting main page...")
        response = session.get(target_url, timeout=2)
        print(f"✅ Target accessible (Status: {response.status_code})")
        
        html_content = response.text
        
        # Find URLs with parameters
        print("🔍 Finding URLs with parameters...")
        urls_with_params = set()
        urls_with_params.add(target_url)
        
        # Simple link extraction
        links = re.findall(r'href=["\']([^"\']+)["\']', html_content, re.IGNORECASE)
        for link in links:
            if '=' in link and not link.startswith('#') and not link.startswith('javascript:'):
                full_url = urljoin(target_url, link)
                if is_same_domain(target_url, full_url):
                    urls_with_params.add(full_url)
                    if len(urls_with_params) >= 5:
                        break
        
        # Find forms
        print("🔍 Finding forms...")
        forms = []
        form_matches = re.findall(r'<form[^>]*>(.*?)</form>', html_content, re.IGNORECASE | re.DOTALL)
        
        for form_html in form_matches:
            form_data = parse_form_simple(form_html, target_url)
            if form_data:
                forms.append(form_data)
        
        # Extract parameters
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
        
        print(f"✅ Discovered {len(urls_with_params)} URLs")
        print(f"✅ Found {len(forms)} forms")
        print(f"✅ Found {len(url_parameters)} URL parameters")
        print(f"✅ Found {len(form_parameters)} form parameters")
        
        # Show parameters
        if url_parameters:
            print("URL Parameters:")
            for param in sorted(url_parameters):
                print(f"  • {param}")
        
        if form_parameters:
            print("Form Parameters:")
            for param in sorted(form_parameters):
                print(f"  • {param}")
        
        # Test URL parameters
        print("🎯 Testing URL parameters...")
        for url in urls_with_params:
            parsed_url = urlparse(url)
            url_params = parse_qs(parsed_url.query)
            
            for param_name in url_params:
                print(f"Testing URL parameter: {param_name}")
                
                for payload in payloads:
                    vuln = test_url_parameter(session, url, param_name, payload)
                    if vuln:
                        vulnerabilities.append(vuln)
                        print(f"✅ XSS FOUND! Parameter: {param_name}")
                        break
        
        # Test form parameters
        print("🎯 Testing form parameters...")
        for form in forms:
            for input_field in form['inputs']:
                if input_field['name']:
                    print(f"Testing form parameter: {input_field['name']}")
                    
                    for payload in payloads:
                        vuln = test_form_parameter(session, form, input_field['name'], payload)
                        if vuln:
                            vulnerabilities.append(vuln)
                            print(f"✅ XSS FOUND! Parameter: {input_field['name']}")
                            break
        
        # Show results
        print("=" * 50)
        print("SCAN RESULTS")
        print("=" * 50)
        
        total_vulns = len(vulnerabilities)
        print(f"Total vulnerabilities: {total_vulns}")
        
        if vulnerabilities:
            print("\nVulnerabilities found:")
            for i, vuln in enumerate(vulnerabilities, 1):
                print(f"  {i}. {vuln.get('type', 'unknown')} - {vuln.get('parameter', 'unknown')}")
                print(f"     URL: {vuln.get('url', 'unknown')}")
        else:
            print("No vulnerabilities found")
        
        # Generate simple report
        generate_simple_report(target_url, vulnerabilities)
        
    except Exception as e:
        print(f"❌ Scan failed: {str(e)}")

def is_same_domain(target_url, url):
    try:
        target_domain = urlparse(target_url).netloc
        url_domain = urlparse(url).netloc
        return target_domain == url_domain
    except:
        return False

def parse_form_simple(form_html, base_url):
    try:
        action_match = re.search(r'action=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
        action = action_match.group(1) if action_match else ''
        
        method_match = re.search(r'method=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
        method = method_match.group(1).upper() if method_match else 'GET'
        
        inputs = []
        input_matches = re.findall(r'<(?:input|textarea|select)[^>]*name=["\']([^"\']+)["\'][^>]*>', form_html, re.IGNORECASE)
        
        for name in input_matches:
            inputs.append({'name': name, 'type': 'text', 'value': ''})
        
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
    try:
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        query_params[param_name] = [payload]
        
        new_query = urllib.parse.urlencode(query_params, doseq=True)
        test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{new_query}"
        
        response = session.get(test_url, timeout=2)
        
        if payload in response.text:
            return {
                'type': 'reflected_xss',
                'url': test_url,
                'parameter': param_name,
                'payload': payload,
                'confidence': 'high',
                'method': 'GET'
            }
    except:
        pass
    
    return None

def test_form_parameter(session, form, param_name, payload):
    try:
        form_data = {}
        for field in form['inputs']:
            if field['name'] == param_name:
                form_data[field['name']] = payload
            else:
                form_data[field['name']] = 'test'
        
        if form['method'] == 'POST':
            response = session.post(form['action'], data=form_data, timeout=2)
        else:
            response = session.get(form['action'], params=form_data, timeout=2)
        
        if payload in response.text:
            return {
                'type': 'reflected_xss',
                'url': form['action'],
                'parameter': param_name,
                'payload': payload,
                'confidence': 'high',
                'method': form['method']
            }
    except:
        pass
    
    return None

def generate_simple_report(target_url, vulnerabilities):
    try:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        os.makedirs('reports', exist_ok=True)
        report_path = f'reports/final_report_{timestamp}.html'
        
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Final XSS Scanner Report</title>
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
            <h1>🚀 Final XSS Scanner Report</h1>
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
        
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"📊 Report generated: {report_path}")
        
    except Exception as e:
        print(f"❌ Error generating report: {str(e)}")

if __name__ == "__main__":
    main()