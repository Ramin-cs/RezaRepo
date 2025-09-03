#!/usr/bin/env python3
"""
Simple Web Reconnaissance Tool - No External Dependencies
A comprehensive reconnaissance tool using only Python standard library
"""

import os
import sys
import json
import time
import hashlib
import socket
import ssl
import subprocess
import urllib.request
import urllib.parse
import urllib.error
from urllib.parse import urlparse, urljoin, parse_qs
import re
import threading
from datetime import datetime
import argparse
from html.parser import HTMLParser

class Colors:
    """Color codes for terminal output"""
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    END = '\033[0m'

class SimpleHTMLParser(HTMLParser):
    """Simple HTML parser for extracting information"""
    
    def __init__(self):
        super().__init__()
        self.links = []
        self.scripts = []
        self.forms = []
        self.current_form = None
        
    def handle_starttag(self, tag, attrs):
        attrs_dict = dict(attrs)
        
        if tag == 'a' and 'href' in attrs_dict:
            self.links.append(attrs_dict['href'])
        
        elif tag == 'script' and 'src' in attrs_dict:
            self.scripts.append(attrs_dict['src'])
        
        elif tag == 'form':
            self.current_form = {'inputs': [], 'action': attrs_dict.get('action', ''), 'method': attrs_dict.get('method', 'GET')}
            self.forms.append(self.current_form)
        
        elif tag == 'input' and self.current_form is not None:
            self.current_form['inputs'].append(attrs_dict)

class SimpleLogger:
    """Simple logging system"""
    
    def __init__(self, filename=None):
        self.filename = filename
        self.start_time = datetime.now()
        
    def log(self, message, level="INFO", color=Colors.WHITE):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        formatted_message = f"[{timestamp}] [{level}] {message}"
        
        print(f"{color}{formatted_message}{Colors.END}")
        
        if self.filename:
            with open(self.filename, 'a', encoding='utf-8') as f:
                f.write(formatted_message + '\n')
    
    def info(self, message):
        self.log(message, "INFO", Colors.CYAN)
    
    def success(self, message):
        self.log(message, "SUCCESS", Colors.GREEN)
    
    def warning(self, message):
        self.log(message, "WARNING", Colors.YELLOW)
    
    def error(self, message):
        self.log(message, "ERROR", Colors.RED)
    
    def phase(self, message):
        self.log(message, "PHASE", Colors.BOLD + Colors.PURPLE)

class SimpleReconTool:
    """Simple reconnaissance tool using only standard library"""
    
    def __init__(self, target_domain, output_dir="simple_recon_output"):
        self.target_domain = self.normalize_domain(target_domain)
        self.output_dir = output_dir
        self.logger = SimpleLogger(os.path.join(output_dir, "recon.log"))
        
        # Results storage
        self.results = {
            'target': self.target_domain,
            'timestamp': datetime.now().isoformat(),
            'subdomains': set(),
            'parameters': set(),
            'sensitive_files': [],
            'ips': set(),
            'technologies': set(),
            'endpoints': set(),
            'javascript_files': [],
            'forms': [],
            'links': [],
            'security_headers': {},
            'robots_txt': None,
            'sitemap_xml': None,
            'favicon_hash': None
        }
        
        # Create output directory
        os.makedirs(output_dir, exist_ok=True)
        
        # User agent
        self.user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'

    def normalize_domain(self, domain):
        """Normalize domain name"""
        domain = domain.strip()
        if domain.startswith('http://') or domain.startswith('https://'):
            domain = urlparse(domain).netloc
        return domain.lower()

    def make_request(self, url, timeout=15):
        """Make HTTP request using urllib"""
        try:
            req = urllib.request.Request(url)
            req.add_header('User-Agent', self.user_agent)
            
            with urllib.request.urlopen(req, timeout=timeout) as response:
                return {
                    'status_code': response.getcode(),
                    'headers': dict(response.headers),
                    'content': response.read().decode('utf-8', errors='ignore'),
                    'url': response.geturl()
                }
        except Exception as e:
            return None

    def banner(self):
        """Display tool banner"""
        banner_text = f"""
{Colors.BOLD}{Colors.CYAN}
╔══════════════════════════════════════════════════════════════╗
║               Simple Web Reconnaissance Tool                 ║
║              No External Dependencies Required               ║
║                    Bug Bounty Edition                       ║
╚══════════════════════════════════════════════════════════════╝
{Colors.END}
{Colors.YELLOW}Target Domain: {self.target_domain}{Colors.END}
{Colors.YELLOW}Output Directory: {self.output_dir}{Colors.END}
{Colors.YELLOW}Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Colors.END}
"""
        print(banner_text)

    def phase_1_basic_discovery(self):
        """Phase 1: Basic discovery using standard methods"""
        self.logger.phase("Phase 1: Basic Discovery")
        
        # Get main page
        main_url = f"https://{self.target_domain}"
        response = self.make_request(main_url)
        
        if response:
            self.analyze_main_page(response)
            self.extract_links_and_resources(response)
            self.analyze_security_headers(response)
        
        # Check common files
        self.check_common_files()
        
        # Basic subdomain discovery
        self.basic_subdomain_discovery()
        
        self.logger.success(f"Phase 1 completed - Found {len(self.results['subdomains'])} subdomains")

    def analyze_main_page(self, response):
        """Analyze main page content"""
        self.logger.info("Analyzing main page...")
        
        content = response['content'].lower()
        
        # Technology detection
        tech_patterns = {
            'WordPress': ['wp-content', 'wp-includes', 'wordpress'],
            'Drupal': ['drupal', '/sites/default/files'],
            'Joomla': ['joomla', '/components/'],
            'PHP': ['<?php', '.php'],
            'ASP.NET': ['asp.net', '__viewstate'],
            'React': ['react', 'reactjs'],
            'Vue.js': ['vue.js', 'vuejs'],
            'Angular': ['angular', 'ng-'],
            'jQuery': ['jquery'],
            'Bootstrap': ['bootstrap']
        }
        
        for tech, signatures in tech_patterns.items():
            if any(sig in content for sig in signatures):
                self.results['technologies'].add(tech)

    def extract_links_and_resources(self, response):
        """Extract links and resources from HTML"""
        self.logger.info("Extracting links and resources...")
        
        parser = SimpleHTMLParser()
        try:
            parser.feed(response['content'])
            
            # Store results
            self.results['links'] = parser.links
            self.results['javascript_files'] = parser.scripts
            self.results['forms'] = parser.forms
            
            # Extract parameters from forms
            for form in parser.forms:
                for input_field in form['inputs']:
                    name = input_field.get('name')
                    if name:
                        self.results['parameters'].add(name)
            
            # Process JavaScript files for subdomains
            for script_src in parser.scripts:
                if script_src.startswith('/'):
                    script_url = f"https://{self.target_domain}{script_src}"
                elif not script_src.startswith('http'):
                    script_url = urljoin(f"https://{self.target_domain}", script_src)
                else:
                    script_url = script_src
                
                self.analyze_javascript_file(script_url)
            
        except Exception as e:
            self.logger.error(f"HTML parsing failed: {e}")

    def analyze_javascript_file(self, js_url):
        """Analyze JavaScript file for subdomains and parameters"""
        try:
            response = self.make_request(js_url, timeout=10)
            if response and response['status_code'] == 200:
                content = response['content']
                
                # Extract subdomains
                subdomain_pattern = rf'["\']https?://([a-zA-Z0-9\-\.]*\.{re.escape(self.target_domain)})["\']'
                matches = re.findall(subdomain_pattern, content, re.IGNORECASE)
                for match in matches:
                    self.results['subdomains'].add(match)
                
                # Extract parameters
                param_patterns = [
                    r'["\']([a-zA-Z_][a-zA-Z0-9_]*)["\']:\s*["\']',
                    r'\.([a-zA-Z_][a-zA-Z0-9_]*)\s*=',
                    r'[?&]([a-zA-Z_][a-zA-Z0-9_]*)='
                ]
                
                for pattern in param_patterns:
                    matches = re.findall(pattern, content)
                    for match in matches:
                        if len(match) > 1:
                            self.results['parameters'].add(match)
                            
        except Exception as e:
            self.logger.error(f"JavaScript analysis failed for {js_url}: {e}")

    def analyze_security_headers(self, response):
        """Analyze security headers"""
        self.logger.info("Analyzing security headers...")
        
        security_headers = [
            'Strict-Transport-Security', 'Content-Security-Policy', 'X-Frame-Options',
            'X-XSS-Protection', 'X-Content-Type-Options', 'Referrer-Policy'
        ]
        
        for header in security_headers:
            value = response['headers'].get(header, response['headers'].get(header.lower()))
            self.results['security_headers'][header] = value

    def check_common_files(self):
        """Check for common sensitive files"""
        self.logger.info("Checking common files...")
        
        common_files = [
            'robots.txt', 'sitemap.xml', '.env', 'config.php', 'package.json',
            '.htaccess', 'web.config', 'config.json', 'settings.json',
            'admin.php', 'login.php', 'phpmyadmin', 'wp-config.php',
            'database.sql', 'backup.sql', '.git/config', '.svn/entries'
        ]
        
        def check_file(filename):
            url = f"https://{self.target_domain}/{filename}"
            response = self.make_request(url, timeout=5)
            
            if response and response['status_code'] == 200:
                self.results['sensitive_files'].append({
                    'file': filename,
                    'url': url,
                    'status_code': response['status_code'],
                    'size': len(response['content'])
                })
                self.logger.success(f"Found: {filename}")
                
                # Special handling for robots.txt
                if filename == 'robots.txt':
                    self.results['robots_txt'] = response['content']
                    self.extract_paths_from_robots(response['content'])
                
                # Special handling for sitemap.xml
                elif filename == 'sitemap.xml':
                    self.results['sitemap_xml'] = response['content']
        
        # Use threading for faster checking
        threads = []
        for filename in common_files:
            t = threading.Thread(target=check_file, args=(filename,))
            t.start()
            threads.append(t)
        
        # Wait for all threads
        for t in threads:
            t.join()

    def extract_paths_from_robots(self, robots_content):
        """Extract paths from robots.txt"""
        for line in robots_content.split('\n'):
            line = line.strip()
            if line.lower().startswith('disallow:'):
                path = line.split(':', 1)[1].strip()
                if path and path != '/':
                    self.results['endpoints'].add(path)

    def basic_subdomain_discovery(self):
        """Basic subdomain discovery"""
        self.logger.info("Performing basic subdomain discovery...")
        
        # Common subdomains
        common_subs = [
            'www', 'mail', 'ftp', 'admin', 'api', 'blog', 'dev', 'test',
            'staging', 'prod', 'app', 'mobile', 'support', 'help', 'docs',
            'shop', 'store', 'cdn', 'static', 'assets', 'img', 'images'
        ]
        
        def check_subdomain(subdomain):
            try:
                full_domain = f"{subdomain}.{self.target_domain}"
                socket.gethostbyname(full_domain)
                self.results['subdomains'].add(full_domain)
                
                # Try to get IP
                ip = socket.gethostbyname(full_domain)
                self.results['ips'].add(ip)
                
                return full_domain
            except socket.gaierror:
                return None
        
        threads = []
        for subdomain in common_subs:
            t = threading.Thread(target=check_subdomain, args=(subdomain,))
            t.start()
            threads.append(t)
        
        for t in threads:
            t.join()

    def phase_2_certificate_analysis(self):
        """Phase 2: SSL Certificate analysis"""
        self.logger.phase("Phase 2: Certificate Analysis")
        
        try:
            # Get SSL certificate
            context = ssl.create_default_context()
            with socket.create_connection((self.target_domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=self.target_domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Extract Subject Alternative Names
                    if 'subjectAltName' in cert:
                        for san_type, san_value in cert['subjectAltName']:
                            if san_type == 'DNS' and self.target_domain in san_value:
                                self.results['subdomains'].add(san_value)
                    
                    self.logger.success("Certificate analysis completed")
                    
        except Exception as e:
            self.logger.error(f"Certificate analysis failed: {e}")

    def phase_3_favicon_analysis(self):
        """Phase 3: Favicon analysis for IP discovery"""
        self.logger.phase("Phase 3: Favicon Analysis")
        
        try:
            favicon_url = f"https://{self.target_domain}/favicon.ico"
            response = self.make_request(favicon_url, timeout=10)
            
            if response and response['status_code'] == 200:
                favicon_hash = hashlib.md5(response['content'].encode()).hexdigest()
                self.results['favicon_hash'] = favicon_hash
                self.logger.success(f"Favicon hash: {favicon_hash}")
                
        except Exception as e:
            self.logger.error(f"Favicon analysis failed: {e}")

    def phase_4_dns_analysis(self):
        """Phase 4: DNS analysis"""
        self.logger.phase("Phase 4: DNS Analysis")
        
        try:
            # Get main IP
            main_ip = socket.gethostbyname(self.target_domain)
            self.results['ips'].add(main_ip)
            self.logger.info(f"Main IP: {main_ip}")
            
            # Try reverse DNS
            try:
                reverse_name = socket.gethostbyaddr(main_ip)
                if reverse_name[0] != self.target_domain:
                    self.logger.info(f"Reverse DNS: {reverse_name[0]}")
            except:
                pass
                
        except Exception as e:
            self.logger.error(f"DNS analysis failed: {e}")

    def phase_5_directory_enumeration(self):
        """Phase 5: Basic directory enumeration"""
        self.logger.phase("Phase 5: Directory Enumeration")
        
        common_dirs = [
            'admin', 'administrator', 'login', 'dashboard', 'panel',
            'api', 'docs', 'help', 'support', 'uploads', 'files',
            'backup', 'test', 'dev', 'staging', 'config'
        ]
        
        def check_directory(directory):
            url = f"https://{self.target_domain}/{directory}/"
            response = self.make_request(url, timeout=5)
            
            if response and response['status_code'] in [200, 301, 302, 403]:
                self.results['endpoints'].add(f"/{directory}/")
                self.logger.success(f"Found directory: /{directory}/ (Status: {response['status_code']})")
        
        threads = []
        for directory in common_dirs:
            t = threading.Thread(target=check_directory, args=(directory,))
            t.start()
            threads.append(t)
        
        for t in threads:
            t.join()

    def phase_6_wayback_analysis(self):
        """Phase 6: Wayback Machine analysis"""
        self.logger.phase("Phase 6: Wayback Machine Analysis")
        
        try:
            wayback_url = f"http://web.archive.org/cdx/search/cdx?url=*.{self.target_domain}&output=json&fl=original&collapse=urlkey"
            response = self.make_request(wayback_url, timeout=30)
            
            if response and response['status_code'] == 200:
                try:
                    data = json.loads(response['content'])
                    for entry in data[1:10]:  # Limit to first 10
                        if entry and len(entry) > 0:
                            archived_url = entry[0]
                            parsed = urlparse(archived_url)
                            
                            if parsed.netloc and self.target_domain in parsed.netloc:
                                self.results['subdomains'].add(parsed.netloc)
                            
                            if parsed.query:
                                params = parse_qs(parsed.query)
                                for param_name in params.keys():
                                    self.results['parameters'].add(param_name)
                                    
                except json.JSONDecodeError:
                    pass
                    
            self.logger.success("Wayback analysis completed")
            
        except Exception as e:
            self.logger.error(f"Wayback analysis failed: {e}")

    def generate_simple_report(self):
        """Generate simple reports"""
        self.logger.phase("Generating Reports")
        
        # Convert sets to lists
        report_data = {}
        for key, value in self.results.items():
            if isinstance(value, set):
                report_data[key] = sorted(list(value))
            else:
                report_data[key] = value
        
        # JSON report
        json_path = os.path.join(self.output_dir, f"{self.target_domain}_simple_report.json")
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)
        
        # Text summary
        summary_path = os.path.join(self.output_dir, f"{self.target_domain}_simple_summary.txt")
        self.generate_text_summary(summary_path, report_data)
        
        # HTML report
        html_path = os.path.join(self.output_dir, f"{self.target_domain}_simple_report.html")
        self.generate_html_report(html_path, report_data)
        
        self.logger.success(f"Reports generated:")
        self.logger.success(f"  JSON: {json_path}")
        self.logger.success(f"  HTML: {html_path}")
        self.logger.success(f"  Summary: {summary_path}")

    def generate_text_summary(self, filepath, data):
        """Generate text summary"""
        summary = f"""
SIMPLE RECONNAISSANCE REPORT
============================

Target: {data['target']}
Scan Date: {data['timestamp']}

STATISTICS:
- Subdomains: {len(data.get('subdomains', []))}
- Parameters: {len(data.get('parameters', []))}
- Sensitive Files: {len(data.get('sensitive_files', []))}
- IP Addresses: {len(data.get('ips', []))}
- Technologies: {len(data.get('technologies', []))}
- Endpoints: {len(data.get('endpoints', []))}

SUBDOMAINS FOUND:
{chr(10).join(f"- {sub}" for sub in data.get('subdomains', []))}

PARAMETERS FOUND:
{chr(10).join(f"- {param}" for param in data.get('parameters', []))}

SENSITIVE FILES:
"""
        
        for file_info in data.get('sensitive_files', []):
            if isinstance(file_info, dict):
                summary += f"- {file_info['file']} (Status: {file_info['status_code']}) - {file_info['url']}\n"
        
        summary += f"""
IP ADDRESSES:
{chr(10).join(f"- {ip}" for ip in data.get('ips', []))}

TECHNOLOGIES:
{chr(10).join(f"- {tech}" for tech in data.get('technologies', []))}

FAVICON HASH: {data.get('favicon_hash', 'Not found')}

SECURITY HEADERS:
"""
        
        for header, value in data.get('security_headers', {}).items():
            status = "Present" if value else "Missing"
            summary += f"- {header}: {status}\n"
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(summary)

    def generate_html_report(self, filepath, data):
        """Generate simple HTML report"""
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Simple Recon Report - {data['target']}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }}
        .container {{ max-width: 1000px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; }}
        h1 {{ color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }}
        h2 {{ color: #34495e; margin-top: 25px; }}
        .stat {{ background: #ecf0f1; padding: 10px; margin: 5px 0; border-radius: 5px; }}
        .found {{ color: #27ae60; font-weight: bold; }}
        ul {{ list-style-type: none; padding: 0; }}
        li {{ background: #f8f9fa; margin: 3px 0; padding: 8px; border-radius: 3px; }}
        .code {{ font-family: monospace; background: #2c3e50; color: white; padding: 10px; border-radius: 5px; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 Simple Reconnaissance Report</h1>
        
        <div class="stat">
            <strong>Target:</strong> {data['target']}<br>
            <strong>Scan Date:</strong> {data['timestamp']}
        </div>
        
        <div class="stat">
            <span class="found">{len(data.get('subdomains', []))}</span> Subdomains |
            <span class="found">{len(data.get('parameters', []))}</span> Parameters |
            <span class="found">{len(data.get('sensitive_files', []))}</span> Sensitive Files |
            <span class="found">{len(data.get('ips', []))}</span> IP Addresses
        </div>
        
        <h2>🌐 Subdomains</h2>
        <ul>
"""
        
        for subdomain in data.get('subdomains', []):
            html_content += f"            <li>{subdomain}</li>\n"
        
        html_content += """
        </ul>
        
        <h2>⚙️ Parameters</h2>
        <ul>
"""
        
        for param in data.get('parameters', []):
            html_content += f"            <li>{param}</li>\n"
        
        html_content += """
        </ul>
        
        <h2>🔒 Sensitive Files</h2>
        <ul>
"""
        
        for file_info in data.get('sensitive_files', []):
            if isinstance(file_info, dict):
                html_content += f"            <li><strong>{file_info['file']}</strong> - Status: {file_info['status_code']} - <a href='{file_info['url']}' target='_blank'>View</a></li>\n"
        
        html_content += f"""
        </ul>
        
        <h2>🌍 IP Addresses</h2>
        <ul>
"""
        
        for ip in data.get('ips', []):
            html_content += f"            <li>{ip}</li>\n"
        
        html_content += f"""
        </ul>
        
        <h2>🛠️ Technologies</h2>
        <ul>
"""
        
        for tech in data.get('technologies', []):
            html_content += f"            <li>{tech}</li>\n"
        
        html_content += f"""
        </ul>
        
        <h2>📊 Security Headers</h2>
        <div class="code">
"""
        
        for header, value in data.get('security_headers', {}).items():
            status = "✅" if value else "❌"
            html_content += f"{status} {header}: {value or 'Not Set'}<br>\n"
        
        html_content += f"""
        </div>
        
        <div class="stat">
            <strong>Favicon Hash:</strong> {data.get('favicon_hash', 'Not found')}
        </div>
        
    </div>
</body>
</html>
"""
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html_content)

    def run_scan(self):
        """Run complete scan"""
        self.banner()
        
        try:
            self.phase_1_basic_discovery()
            self.phase_2_certificate_analysis()
            self.phase_3_favicon_analysis()
            self.phase_4_dns_analysis()
            self.phase_5_directory_enumeration()
            self.phase_6_wayback_analysis()
            
            self.generate_simple_report()
            
            elapsed_time = datetime.now() - self.logger.start_time
            self.logger.success(f"Scan completed in {elapsed_time}")
            
        except KeyboardInterrupt:
            self.logger.warning("Scan interrupted by user")
        except Exception as e:
            self.logger.error(f"Scan failed: {e}")

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description="Simple Web Reconnaissance Tool")
    parser.add_argument('-t', '--target', required=True, help='Target domain')
    parser.add_argument('-o', '--output', default='simple_recon_output', help='Output directory')
    
    args = parser.parse_args()
    
    if not args.target:
        print("❌ Target domain is required")
        parser.print_help()
        sys.exit(1)
    
    # Create and run tool
    tool = SimpleReconTool(args.target, args.output)
    tool.run_scan()

if __name__ == "__main__":
    main()