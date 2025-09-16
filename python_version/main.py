#!/usr/bin/env python3
"""
Advanced Bug Bounty Tool - Main Entry Point
Comprehensive reconnaissance and vulnerability scanning tool

Author: Security Researcher
Version: 2.0.0
"""

import argparse
import sys
import os
import time
from datetime import datetime
from colorama import init, Fore, Style, Back
from reconnaissance import Reconnaissance
from bug_scanner import BugScanner
from report_generator import HTMLReportGenerator

# Initialize Colorama for cross-platform colored output
init(autoreset=True)

class BugBountyTool:
    """
    Main Bug Bounty Tool class
    """
    
    def __init__(self):
        self.start_time = None
        self.end_time = None
        
    def print_banner(self):
        """Print beautiful banner"""
        banner = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║  {Fore.YELLOW}🚀 ADVANCED BUG BOUNTY TOOL v2.0 🚀{Fore.CYAN}                                    ║
║                                                                              ║
║  {Fore.GREEN}🔍 Comprehensive Reconnaissance & Vulnerability Scanning{Fore.CYAN}              ║
║  {Fore.GREEN}🎯 XSS • SQLi • Open Redirect • RFI • RCE • SSRF{Fore.CYAN}                      ║
║  {Fore.GREEN}⚡ Parallel Processing • Live Output • Professional Reports{Fore.CYAN}           ║
║                                                                              ║
║  {Fore.MAGENTA}Author: Security Researcher{Fore.CYAN}                                              ║
║  {Fore.MAGENTA}Version: 2.0.0{Fore.CYAN}                                                         ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
        """
        print(banner)
    
    def print_progress_bar(self, current, total, description="Progress"):
        """Print beautiful progress bar"""
        percentage = (current / total) * 100
        bar_length = 50
        filled_length = int(bar_length * current // total)
        bar = '█' * filled_length + '░' * (bar_length - filled_length)
        
        print(f"\r{Fore.CYAN}🔄 {description}: {Fore.YELLOW}[{bar}]{Fore.CYAN} {percentage:.1f}% ({current}/{total}){Style.RESET_ALL}", end='', flush=True)
        
        if current == total:
            print()  # New line when complete
    
    def print_section_header(self, title, emoji="🔍"):
        """Print section header"""
        print(f"\n{Fore.MAGENTA}{'='*80}{Style.RESET_ALL}")
        print(f"{Fore.MAGENTA}{emoji} {title}{Style.RESET_ALL}")
        print(f"{Fore.MAGENTA}{'='*80}{Style.RESET_ALL}")
    
    def print_success(self, message):
        """Print success message"""
        print(f"{Fore.GREEN}✅ {message}{Style.RESET_ALL}")
    
    def print_warning(self, message):
        """Print warning message"""
        print(f"{Fore.YELLOW}⚠️  {message}{Style.RESET_ALL}")
    
    def print_error(self, message):
        """Print error message"""
        print(f"{Fore.RED}❌ {message}{Style.RESET_ALL}")
    
    def print_info(self, message):
        """Print info message"""
        print(f"{Fore.CYAN}ℹ️  {message}{Style.RESET_ALL}")
    
    def print_vulnerability(self, vuln_type, severity, url, confidence=None):
        """Print vulnerability found"""
        severity_colors = {
            'Critical': Fore.RED,
            'High': Fore.YELLOW,
            'Medium': Fore.BLUE,
            'Low': Fore.GREEN
        }
        
        color = severity_colors.get(severity, Fore.WHITE)
        confidence_text = f" (Confidence: {confidence}%)" if confidence else ""
        
        print(f"{color}🚨 {vuln_type} ({severity}){confidence_text}{Style.RESET_ALL}")
        print(f"{color}   📍 URL: {url}{Style.RESET_ALL}")
    
    def run_reconnaissance(self, target_domain):
        """Run reconnaissance phase"""
        self.print_section_header("RECONNAISSANCE PHASE", "🔍")
        
        print(f"{Fore.CYAN}🎯 Target: {Fore.YELLOW}{target_domain}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}⏰ Started: {Fore.YELLOW}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Style.RESET_ALL}")
        
        try:
            # Initialize reconnaissance
            recon = Reconnaissance(target_domain)
            
            # Run reconnaissance with live updates
            print(f"\n{Fore.CYAN}🚀 Starting reconnaissance...{Style.RESET_ALL}")
            recon_results = recon.run_recon()
            
            # Display results
            self.print_section_header("RECONNAISSANCE RESULTS", "📊")
            
            subdomains = recon_results.get('subdomains', [])
            directories = recon_results.get('directories', [])
            parameters = recon_results.get('parameters', [])
            sensitive_files = recon_results.get('sensitive_files', [])
            waf_info = recon_results.get('waf', {})
            
            print(f"{Fore.GREEN}🌐 Subdomains Found: {Fore.YELLOW}{len(subdomains)}{Style.RESET_ALL}")
            for subdomain in subdomains[:5]:  # Show first 5
                print(f"   • {subdomain}")
            if len(subdomains) > 5:
                print(f"   ... and {len(subdomains) - 5} more")
            
            print(f"\n{Fore.GREEN}📁 Directories Found: {Fore.YELLOW}{len(directories)}{Style.RESET_ALL}")
            for directory in directories[:5]:  # Show first 5
                print(f"   • {directory.get('path', 'N/A')} (Status: {directory.get('status_code', 'N/A')})")
            if len(directories) > 5:
                print(f"   ... and {len(directories) - 5} more")
            
            print(f"\n{Fore.GREEN}🔧 Parameters Found: {Fore.YELLOW}{len(parameters)}{Style.RESET_ALL}")
            for param in parameters[:5]:  # Show first 5
                print(f"   • {param}")
            if len(parameters) > 5:
                print(f"   ... and {len(parameters) - 5} more")
            
            print(f"\n{Fore.GREEN}📄 Sensitive Files Found: {Fore.YELLOW}{len(sensitive_files)}{Style.RESET_ALL}")
            for file_info in sensitive_files[:5]:  # Show first 5
                print(f"   • {file_info.get('path', 'N/A')} (Size: {file_info.get('size_category', 'N/A')})")
            if len(sensitive_files) > 5:
                print(f"   ... and {len(sensitive_files) - 5} more")
            
            print(f"\n{Fore.GREEN}🛡️  WAF Detected: {Fore.YELLOW}{waf_info.get('name', 'None')}{Style.RESET_ALL}")
            
            return recon_results
            
        except Exception as e:
            self.print_error(f"Reconnaissance failed: {e}")
            return None
    
    def run_vulnerability_scan(self, target_url, parameters):
        """Run vulnerability scanning phase"""
        self.print_section_header("VULNERABILITY SCANNING PHASE", "🚨")
        
        print(f"{Fore.CYAN}🎯 Target URL: {Fore.YELLOW}{target_url}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}🔧 Parameters to test: {Fore.YELLOW}{len(parameters)}{Style.RESET_ALL}")
        
        try:
            # Initialize bug scanner
            scanner = BugScanner(target_url)
            
            # Run vulnerability scan with live updates
            print(f"\n{Fore.CYAN}🚀 Starting vulnerability scan...{Style.RESET_ALL}")
            vulnerabilities = scanner.run_scan(parameters)
            
            # Display results
            self.print_section_header("VULNERABILITY SCAN RESULTS", "📊")
            
            if not vulnerabilities:
                self.print_success("No vulnerabilities found! 🎉")
                return []
            
            # Group vulnerabilities by type
            vuln_by_type = {}
            for vuln in vulnerabilities:
                vuln_type = vuln.get('type', 'Unknown')
                if vuln_type not in vuln_by_type:
                    vuln_by_type[vuln_type] = []
                vuln_by_type[vuln_type].append(vuln)
            
            # Display vulnerabilities by type
            for vuln_type, vulns in vuln_by_type.items():
                print(f"\n{Fore.RED}🚨 {vuln_type}: {Fore.YELLOW}{len(vulns)} found{Style.RESET_ALL}")
                for vuln in vulns:
                    self.print_vulnerability(
                        vuln_type,
                        vuln.get('severity', 'Unknown'),
                        vuln.get('url', 'N/A'),
                        vuln.get('confidence', None)
                    )
            
            return vulnerabilities
            
        except Exception as e:
            self.print_error(f"Vulnerability scan failed: {e}")
            return []
    
    def generate_report(self, target_domain, recon_results, vulnerabilities):
        """Generate comprehensive report"""
        self.print_section_header("REPORT GENERATION", "📄")
        
        try:
            # Initialize report generator
            report_generator = HTMLReportGenerator()
            
            # Generate HTML report
            print(f"{Fore.CYAN}📝 Generating HTML report...{Style.RESET_ALL}")
            html_file = report_generator.generate_report(recon_results, vulnerabilities, target_domain)
            
            # Generate JSON report
            print(f"{Fore.CYAN}📝 Generating JSON report...{Style.RESET_ALL}")
            json_file = report_generator.export_json(recon_results, vulnerabilities, target_domain)
            
            self.print_success(f"HTML report generated: {html_file}")
            self.print_success(f"JSON report generated: {json_file}")
            
            return html_file, json_file
            
        except Exception as e:
            self.print_error(f"Report generation failed: {e}")
            return None, None
    
    def print_summary(self, target_domain, recon_results, vulnerabilities, html_file, json_file):
        """Print final summary"""
        self.print_section_header("SCAN SUMMARY", "📋")
        
        # Calculate scan duration
        duration = self.end_time - self.start_time if self.end_time and self.start_time else None
        
        print(f"{Fore.CYAN}🎯 Target: {Fore.YELLOW}{target_domain}{Style.RESET_ALL}")
        if duration:
            print(f"{Fore.CYAN}⏱️  Duration: {Fore.YELLOW}{duration.total_seconds():.2f} seconds{Style.RESET_ALL}")
        print(f"{Fore.CYAN}📅 Completed: {Fore.YELLOW}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Style.RESET_ALL}")
        
        # Reconnaissance summary
        subdomains = len(recon_results.get('subdomains', [])) if recon_results else 0
        directories = len(recon_results.get('directories', [])) if recon_results else 0
        parameters = len(recon_results.get('parameters', [])) if recon_results else 0
        sensitive_files = len(recon_results.get('sensitive_files', [])) if recon_results else 0
        
        print(f"\n{Fore.GREEN}🔍 Reconnaissance Results:{Style.RESET_ALL}")
        print(f"   • Subdomains: {Fore.YELLOW}{subdomains}{Style.RESET_ALL}")
        print(f"   • Directories: {Fore.YELLOW}{directories}{Style.RESET_ALL}")
        print(f"   • Parameters: {Fore.YELLOW}{parameters}{Style.RESET_ALL}")
        print(f"   • Sensitive Files: {Fore.YELLOW}{sensitive_files}{Style.RESET_ALL}")
        
        # Vulnerability summary
        total_vulns = len(vulnerabilities) if vulnerabilities else 0
        vuln_by_severity = {}
        if vulnerabilities:
            for vuln in vulnerabilities:
                severity = vuln.get('severity', 'Unknown')
                vuln_by_severity[severity] = vuln_by_severity.get(severity, 0) + 1
        
        print(f"\n{Fore.RED}🚨 Vulnerability Results:{Style.RESET_ALL}")
        print(f"   • Total Vulnerabilities: {Fore.YELLOW}{total_vulns}{Style.RESET_ALL}")
        
        for severity, count in vuln_by_severity.items():
            severity_colors = {
                'Critical': Fore.RED,
                'High': Fore.YELLOW,
                'Medium': Fore.BLUE,
                'Low': Fore.GREEN
            }
            color = severity_colors.get(severity, Fore.WHITE)
            print(f"   • {color}{severity}: {count}{Style.RESET_ALL}")
        
        # Report files
        print(f"\n{Fore.GREEN}📄 Reports Generated:{Style.RESET_ALL}")
        if html_file:
            print(f"   • HTML Report: {Fore.YELLOW}{html_file}{Style.RESET_ALL}")
        if json_file:
            print(f"   • JSON Report: {Fore.YELLOW}{json_file}{Style.RESET_ALL}")
        
        # Final message
        if total_vulns > 0:
            print(f"\n{Fore.RED}⚠️  {total_vulns} vulnerabilities found! Please review the reports.{Style.RESET_ALL}")
        else:
            print(f"\n{Fore.GREEN}🎉 No vulnerabilities found! Target appears secure.{Style.RESET_ALL}")
    
    def run(self, target_domain, output_dir="reports"):
        """Run the complete bug bounty scan"""
        self.start_time = datetime.now()
        
        try:
            # Print banner
            self.print_banner()
            
            # Phase 1: Reconnaissance
            recon_results = self.run_reconnaissance(target_domain)
            if not recon_results:
                self.print_error("Reconnaissance failed. Exiting.")
                return False
            
            # Phase 2: Vulnerability Scanning
            target_url = f"https://{target_domain}"
            parameters = recon_results.get('parameters', [])
            
            if not parameters:
                self.print_warning("No parameters found for vulnerability scanning.")
                vulnerabilities = []
            else:
                vulnerabilities = self.run_vulnerability_scan(target_url, parameters)
            
            # Phase 3: Report Generation
            html_file, json_file = self.generate_report(target_domain, recon_results, vulnerabilities)
            
            # Phase 4: Summary
            self.end_time = datetime.now()
            self.print_summary(target_domain, recon_results, vulnerabilities, html_file, json_file)
            
            return True
            
        except KeyboardInterrupt:
            self.print_warning("Scan interrupted by user.")
            return False
        except Exception as e:
            self.print_error(f"Scan failed: {e}")
            return False

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="Advanced Bug Bounty Tool - Comprehensive reconnaissance and vulnerability scanning",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py example.com
  python main.py example.com --output-dir my_reports
  python main.py example.com --verbose
        """
    )
    
    parser.add_argument("target", help="Target domain to scan (e.g., example.com)")
    parser.add_argument("-o", "--output-dir", default="reports", 
                       help="Output directory for reports (default: reports)")
    parser.add_argument("-v", "--verbose", action="store_true", 
                       help="Enable verbose output")
    
    args = parser.parse_args()
    
    # Validate target
    if not args.target:
        print(f"{Fore.RED}❌ Error: Target domain is required{Style.RESET_ALL}")
        sys.exit(1)
    
    # Create output directory
    os.makedirs(args.output_dir, exist_ok=True)
    
    # Run the tool
    tool = BugBountyTool()
    success = tool.run(args.target, args.output_dir)
    
    # Exit with appropriate code
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()