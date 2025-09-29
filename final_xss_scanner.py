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
import html as html_escape_mod

# Optional Playwright for live browser validation
try:
    from playwright.sync_api import sync_playwright
    PLAYWRIGHT_AVAILABLE = True
except Exception:
    PLAYWRIGHT_AVAILABLE = False

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
    
    # Use a unique marker so dialog text is recognizable
    payloads = [
        '<script>alert("XSS_CONFIRMED")</script>',
        '<img src=x onerror=alert("XSS_CONFIRMED")>',
        '<svg onload=alert("XSS_CONFIRMED")>',
        '" onmouseover="alert(\'XSS_CONFIRMED\')" x="'
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
                print(f"[TEST] URL param: {param_name} | on: {url}")
                
                for payload in payloads:
                    print(f"  ├─ context=html | payload={payload}")
                    vuln = test_url_parameter(session, url, param_name, payload)
                    if vuln:
                        vuln['context'] = 'html'
                        vuln['poc_url'] = vuln.get('url')
                        vuln['score'] = score_vuln(vuln, confirmed=False)
                        vulnerabilities.append(vuln)
                        print(f"  ✅ reflected detected | param={param_name} | url={vuln.get('url')}")
                        break
        
        # Test form parameters
        print("🎯 Testing form parameters...")
        for form in forms:
            for input_field in form['inputs']:
                if input_field['name']:
                    print(f"[TEST] Form param: {input_field['name']} | on: {form['action']} | method={form['method']}")
                    
                    for payload in payloads:
                        print(f"  ├─ context=html | payload={payload}")
                        vuln = test_form_parameter(session, form, input_field['name'], payload)
                        if vuln:
                            vuln['context'] = 'html'
                            vuln['poc_url'] = vuln.get('url')
                            vuln['score'] = score_vuln(vuln, confirmed=False)
                            vulnerabilities.append(vuln)
                            print(f"  ✅ reflected detected | param={input_field['name']} | url={vuln.get('url')}")
                            break
        
        # Phase 2: Live browser validation (Chrome) - KEEP ONLY CONFIRMED
        confirmed_vulns = []
        if PLAYWRIGHT_AVAILABLE and vulnerabilities:
            print("🌐 Launching Chrome for live validation (non-headless)...")
            confirmed_vulns = browser_validate_and_screenshot(vulnerabilities)

        # Show results
        print("=" * 50)
        print("SCAN RESULTS")
        print("=" * 50)
        
        total_vulns = len(confirmed_vulns)
        print(f"Total vulnerabilities: {total_vulns}")
        
        if confirmed_vulns:
            print("\nVulnerabilities found:")
            for i, vuln in enumerate(confirmed_vulns, 1):
                print(f"  {i}. {vuln.get('type', 'unknown')} - {vuln.get('parameter', 'unknown')} | context={vuln.get('context','?')} | score={vuln.get('score',0)}")
                print(f"     POC: {vuln.get('poc_url', vuln.get('url','unknown'))}")
                if vuln.get('browser_validated'):
                    print(f"     LIVE: confirmed in Chrome | alert='{vuln.get('alert_message','')}' | screenshot={vuln.get('screenshot','-')}")
        else:
            print("No vulnerabilities found")
        
        # Generate report (only confirmed)
        generate_simple_report(target_url, confirmed_vulns)
        
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

def score_vuln(vuln, confirmed=False):
    score = 50  # base for reflection
    if vuln.get('context') == 'html':
        score += 10
    if 'script' in (vuln.get('payload') or '').lower():
        score += 10
    if confirmed:
        score += 30
    return score

def browser_validate_and_screenshot(vulnerabilities):
    try:
        pw = sync_playwright().start()
        browser = pw.chromium.launch(headless=False, args=['--no-sandbox','--disable-setuid-sandbox'])
        context = browser.new_context()
    except Exception as e:
        print(f"[BROWSER] init failed: {e}")
        return vulnerabilities

    confirmed = []
    try:
        for vuln in vulnerabilities:
            # Create a fresh page per test to avoid listener cleanup
            page = context.new_page()
            dialog_message = {'text': None, 'shot': None}
            def on_dialog(dialog):
                dialog_message['text'] = dialog.message
                # Take screenshot before accept
                try:
                    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
                    os.makedirs('screenshots', exist_ok=True)
                    shot_path = f"screenshots/xss_{ts}.png"
                    page.screenshot(path=shot_path)
                    dialog_message['shot'] = shot_path
                except Exception:
                    pass
                try:
                    dialog.accept()
                except Exception:
                    pass

            page.on('dialog', on_dialog)
            try:
                page.goto(vuln.get('poc_url') or vuln.get('url'), timeout=20000)
            except Exception:
                try:
                    page.close()
                except Exception:
                    pass
                continue
            # small wait
            try:
                page.wait_for_timeout(1200)
            except Exception:
                pass
            try:
                page.close()
            except Exception:
                pass
            if dialog_message['text'] and 'XSS_CONFIRMED' in dialog_message['text']:
                vuln['browser_validated'] = True
                vuln['alert_message'] = dialog_message['text']
                if dialog_message['shot']:
                    vuln['screenshot'] = dialog_message['shot']
                vuln['score'] = score_vuln(vuln, confirmed=True)
                confirmed.append(vuln)
        # close
        context.close()
        browser.close()
        pw.stop()
    except Exception as e:
        print(f"[BROWSER] validation error: {e}")
        try:
            context.close()
            browser.close()
            pw.stop()
        except Exception:
            pass
        # if browser fails, return original reflections (no confirm)
        return vulnerabilities
    return confirmed

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
                safe_url = html_escape_mod.escape(vuln.get('url', 'unknown') or '')
                safe_param = html_escape_mod.escape(vuln.get('parameter', 'unknown') or '')
                safe_ctx = html_escape_mod.escape(vuln.get('context','?') or '')
                safe_score = html_escape_mod.escape(str(vuln.get('score',0)))
                safe_payload = html_escape_mod.escape(vuln.get('payload', 'unknown') or '')
                safe_alert = html_escape_mod.escape(vuln.get('alert_message','') or '')
                safe_shot = html_escape_mod.escape(vuln.get('screenshot','') or '')
                html_content += f"""
                <div class="vulnerability">
                    <h3>🔍 Vulnerability #{i}</h3>
                    <p><strong>Type:</strong> {html_escape_mod.escape(vuln.get('type', 'unknown'))}</p>
                    <p><strong>URL:</strong> {safe_url}</p>
                    <p><strong>Parameter:</strong> {safe_param}</p>
                    <p><strong>Context:</strong> {safe_ctx}</p>
                    <p><strong>Score:</strong> {safe_score}</p>
                    <p><strong>Payload:</strong></p>
                    <div class="payload">{safe_payload}</div>
                    <p><strong>Method:</strong> {html_escape_mod.escape(vuln.get('method', 'GET'))}</p>
                    {f"<p><strong>Alert:</strong> {safe_alert}</p>" if vuln.get('browser_validated') else ''}
                    {f"<p><strong>Screenshot:</strong> {safe_shot}</p>" if vuln.get('browser_validated') else ''}
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