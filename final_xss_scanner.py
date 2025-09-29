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
from collections import deque
from bs4 import BeautifulSoup

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
        # Phase 1: Deep same-origin crawling (depth=4)
        print("🔍 Starting deep reconnaissance (same-origin, depth=4)...")
        crawled_urls, page_html_map = crawl_site(session, target_url, max_depth=4)
        
        # Phase 1.1: Extract forms from all pages
        forms = []
        for page_url, html_content in page_html_map.items():
            page_forms = extract_forms_from_html(html_content, page_url)
            forms.extend(page_forms)
        
        # Phase 1.2: Collect URL parameters from all URLs discovered
        url_parameters = set()
        for url in crawled_urls:
            parsed_url = urlparse(url)
            params = parse_qs(parsed_url.query)
            url_parameters.update(params.keys())
        
        # Phase 1.3: Collect form parameters
        form_parameters = set()
        for form in forms:
            for input_field in form['inputs']:
                if input_field['name']:
                    form_parameters.add(input_field['name'])
        
        print(f"✅ Discovered {len(crawled_urls)} URLs")
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
        for url in crawled_urls:
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

def extract_forms_from_html(html_content, base_url):
    forms = []
    try:
        soup = BeautifulSoup(html_content, 'html.parser')
        for form in soup.find_all('form'):
            action = form.get('action', '')
            method = form.get('method', 'GET').upper()
            inputs = []
            for input_field in form.find_all(['input', 'textarea', 'select']):
                name = input_field.get('name')
                if not name:
                    continue
                value = input_field.get('value', '')
                inputs.append({'name': name, 'type': input_field.get('type', 'text'), 'value': value})
            if inputs:
                forms.append({
                    'action': urljoin(base_url, action) if action else base_url,
                    'method': method,
                    'inputs': inputs
                })
    except Exception:
        return forms
    return forms

def crawl_site(session, start_url, max_depth=4):
    visited = set()
    queue = deque()
    queue.append((start_url, 0))
    visited.add(start_url)
    discovered_urls = set([start_url])
    page_html_map = {}
    base_domain = urlparse(start_url).netloc
    
    while queue:
        current_url, depth = queue.popleft()
        try:
            resp = session.get(current_url, timeout=5)
        except Exception:
            continue
        if resp.status_code != 200 or not resp.headers.get('content-type', '').startswith('text'):
            continue
        html = resp.text
        page_html_map[current_url] = html
        if depth >= max_depth:
            continue
        links = extract_links_from_html(html, current_url, base_domain)
        for link in links:
            if link in visited:
                continue
            visited.add(link)
            discovered_urls.add(link)
            queue.append((link, depth + 1))
    return list(discovered_urls), page_html_map

def extract_links_from_html(html_content, base_url, base_domain):
    links = set()
    try:
        soup = BeautifulSoup(html_content, 'html.parser')
        # a[href]
        for a in soup.find_all('a', href=True):
            href = a['href']
            if href.startswith('#') or href.lower().startswith('javascript:'):
                continue
            full = urljoin(base_url, href)
            if urlparse(full).netloc == base_domain and not is_static_resource(full):
                links.add(full)
        # form action
        for form in soup.find_all('form', action=True):
            action = form['action']
            full = urljoin(base_url, action)
            if urlparse(full).netloc == base_domain and not is_static_resource(full):
                links.add(full)
        # JS patterns
        js_patterns = [
            r'window\.location\s*=\s*["\']([^"\']+)["\']',
            r'location\.href\s*=\s*["\']([^"\']+)["\']',
            r'window\.open\s*\(\s*["\']([^"\']+)["\']',
            r'href\s*=\s*["\']([^"\']+)["\']'
        ]
        for pattern in js_patterns:
            for m in re.findall(pattern, html_content, flags=re.IGNORECASE):
                if m.startswith('#') or m.lower().startswith('javascript:'):
                    continue
                full = urljoin(base_url, m)
                if urlparse(full).netloc == base_domain and not is_static_resource(full):
                    links.add(full)
    except Exception:
        return list(links)
    return list(links)

def is_static_resource(url):
    static_exts = ('.png', '.jpg', '.jpeg', '.gif', '.svg', '.css', '.ico', '.woff', '.woff2', '.ttf', '.otf', '.eot', '.pdf', '.zip', '.rar', '.7z', '.mp4', '.webm', '.mp3', '.wav', '.avi', '.mov', '.mkv', '.json')
    path = urlparse(url).path.lower()
    return path.endswith(static_exts)

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