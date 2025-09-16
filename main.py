#!/usr/bin/env python3
"""
Advanced Bug Bounty Tool - Main Entry Point
Combines reconnaissance and vulnerability scanning with comprehensive reporting

Author: Security Researcher
Version: 1.0.0
"""

import sys
import os
import argparse
import json
from datetime import datetime
from colorama import init, Fore, Style

# Import our modules
from reconnaissance import ReconnaissanceTool
from bug_scanner import BugScanner
from report_generator import HTMLReportGenerator

# Initialize colorama
init(autoreset=True)

class BugBountyTool:
    """
    Main Bug Bounty Tool that orchestrates reconnaissance and vulnerability scanning
    """
    
    def __init__(self, target_domain, output_dir="bug_bounty_results"):
        """
        Initialize the Bug Bounty Tool
        
        Args:
            target_domain (str): Target domain to test
            output_dir (str): Output directory for results
        """
        self.target_domain = target_domain
        self.output_dir = output_dir
        self.recon_results = None
        self.vuln_results = []
        
        # Create output directory
        os.makedirs(output_dir, exist_ok=True)
        
        self.print_banner()
    
    def print_banner(self):
        """Print main tool banner"""
        banner = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════════════════════╗
║                        ADVANCED BUG BOUNTY TOOL                              ║
║                    Reconnaissance + Vulnerability Scanner                     ║
║                              Version 1.0.0                                   ║
╚══════════════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}

{Fore.YELLOW}Target Domain: {self.target_domain}
Output Directory: {self.output_dir}
Start Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Style.RESET_ALL}

{Fore.GREEN}Starting comprehensive security assessment...{Style.RESET_ALL}
"""
        print(banner)
    
    def log(self, message, level="INFO"):
        """Log messages with timestamps and colors"""
        timestamp = datetime.now().strftime('%H:%M:%S')
        colors = {
            'INFO': Fore.BLUE,
            'SUCCESS': Fore.GREEN,
            'WARNING': Fore.YELLOW,
            'ERROR': Fore.RED,
            'CRITICAL': Fore.MAGENTA,
            'PHASE': Fore.CYAN
        }
        color = colors.get(level, Fore.WHITE)
        print(f"{color}[{timestamp}] [{level}] {message}{Style.RESET_ALL}")
    
    def run_reconnaissance_phase(self):
        """
        Phase 1: Run comprehensive reconnaissance
        """
        self.log("=" * 60, "PHASE")
        self.log("PHASE 1: RECONNAISSANCE", "PHASE")
        self.log("=" * 60, "PHASE")
        
        try:
            # Initialize reconnaissance tool
            recon_tool = ReconnaissanceTool(self.target_domain, self.output_dir)
            
            # Run complete reconnaissance
            self.recon_results = recon_tool.run_complete_reconnaissance()
            
            if self.recon_results:
                self.log("Reconnaissance phase completed successfully!", "SUCCESS")
                return True
            else:
                self.log("Reconnaissance phase failed!", "ERROR")
                return False
                
        except Exception as e:
            self.log(f"Error during reconnaissance phase: {e}", "ERROR")
            return False
    
    def run_vulnerability_scanning_phase(self):
        """
        Phase 2: Run vulnerability scanning based on reconnaissance results
        """
        self.log("=" * 60, "PHASE")
        self.log("PHASE 2: VULNERABILITY SCANNING", "PHASE")
        self.log("=" * 60, "PHASE")
        
        if not self.recon_results:
            self.log("No reconnaissance results available. Skipping vulnerability scanning.", "WARNING")
            return False
        
        try:
            # Get parameters from reconnaissance results
            parameters = self.recon_results.get('parameters', [])
            
            # Add common parameters if none found
            if not parameters:
                parameters = ['id', 'page', 'search', 'q', 'url', 'redirect', 'return', 'next', 'callback']
                self.log("No parameters found in reconnaissance. Using common parameters.", "WARNING")
            
            # Get valid subdomains for scanning
            valid_subdomains = self.recon_results.get('valid_subdomains', [])
            
            # Add main domain if no subdomains found
            if not valid_subdomains:
                valid_subdomains = [{'subdomain': self.target_domain, 'protocol': 'https'}]
            
            # Scan each valid subdomain
            for subdomain_info in valid_subdomains:
                subdomain = subdomain_info['subdomain']
                protocol = subdomain_info.get('protocol', 'https')
                target_url = f"{protocol}://{subdomain}"
                
                self.log(f"Scanning {target_url} for vulnerabilities...", "INFO")
                
                # Initialize bug scanner
                scanner = BugScanner(target_url, self.output_dir)
                
                # Run vulnerability scan
                vuln_results = scanner.run_complete_scan(parameters)
                
                if vuln_results:
                    # Add subdomain info to each vulnerability
                    for vuln in vuln_results:
                        vuln['target_subdomain'] = subdomain
                        vuln['scan_timestamp'] = datetime.now().isoformat()
                    
                    self.vuln_results.extend(vuln_results)
                    self.log(f"Found {len(vuln_results)} vulnerabilities on {subdomain}", "SUCCESS")
                else:
                    self.log(f"No vulnerabilities found on {subdomain}", "INFO")
            
            self.log(f"Vulnerability scanning completed! Total vulnerabilities found: {len(self.vuln_results)}", "SUCCESS")
            return True
            
        except Exception as e:
            self.log(f"Error during vulnerability scanning phase: {e}", "ERROR")
            return False
    
    def generate_final_report(self):
        """
        Phase 3: Generate comprehensive HTML report
        """
        self.log("=" * 60, "PHASE")
        self.log("PHASE 3: REPORT GENERATION", "PHASE")
        self.log("=" * 60, "PHASE")
        
        try:
            # Initialize report generator
            report_generator = HTMLReportGenerator(self.output_dir)
            
            # Generate HTML report
            report_path = report_generator.generate_report(
                self.recon_results or {},
                self.vuln_results,
                self.target_domain
            )
            
            self.log(f"HTML report generated: {report_path}", "SUCCESS")
            
            # Save JSON summary
            summary = {
                'target': self.target_domain,
                'scan_timestamp': datetime.now().isoformat(),
                'reconnaissance_results': self.recon_results,
                'vulnerabilities': self.vuln_results,
                'summary': {
                    'total_vulnerabilities': len(self.vuln_results),
                    'critical_vulnerabilities': len([v for v in self.vuln_results if v.get('severity', '').lower() == 'critical']),
                    'high_vulnerabilities': len([v for v in self.vuln_results if v.get('severity', '').lower() == 'high']),
                    'medium_vulnerabilities': len([v for v in self.vuln_results if v.get('severity', '').lower() == 'medium']),
                    'low_vulnerabilities': len([v for v in self.vuln_results if v.get('severity', '').lower() == 'low']),
                    'subdomains_found': len(self.recon_results.get('subdomains', [])) if self.recon_results else 0,
                    'directories_found': len(self.recon_results.get('directories', [])) if self.recon_results else 0,
                    'parameters_found': len(self.recon_results.get('parameters', [])) if self.recon_results else 0,
                    'waf_detected': self.recon_results.get('waf_info', {}).get('detected', False) if self.recon_results else False
                }
            }
            
            summary_path = os.path.join(self.output_dir, f"{self.target_domain}_summary.json")
            with open(summary_path, 'w') as f:
                json.dump(summary, f, indent=2)
            
            self.log(f"JSON summary saved: {summary_path}", "SUCCESS")
            
            return report_path
            
        except Exception as e:
            self.log(f"Error generating report: {e}", "ERROR")
            return None
    
    def print_final_summary(self):
        """Print final summary of the scan"""
        self.log("=" * 60, "PHASE")
        self.log("SCAN COMPLETED - FINAL SUMMARY", "PHASE")
        self.log("=" * 60, "PHASE")
        
        if self.recon_results:
            self.log(f"Subdomains discovered: {len(self.recon_results.get('subdomains', []))}", "INFO")
            self.log(f"Valid subdomains: {len(self.recon_results.get('valid_subdomains', []))}", "INFO")
            self.log(f"Directories found: {len(self.recon_results.get('directories', []))}", "INFO")
            self.log(f"Parameters discovered: {len(self.recon_results.get('parameters', []))}", "INFO")
            
            waf_info = self.recon_results.get('waf_info', {})
            if waf_info.get('detected'):
                self.log(f"WAF detected: {waf_info.get('type', 'Unknown')} (Confidence: {waf_info.get('confidence', 0)}%)", "WARNING")
            else:
                self.log("No WAF detected", "INFO")
        
        self.log(f"Total vulnerabilities found: {len(self.vuln_results)}", "INFO")
        
        if self.vuln_results:
            critical = len([v for v in self.vuln_results if v.get('severity', '').lower() == 'critical'])
            high = len([v for v in self.vuln_results if v.get('severity', '').lower() == 'high'])
            medium = len([v for v in self.vuln_results if v.get('severity', '').lower() == 'medium'])
            low = len([v for v in self.vuln_results if v.get('severity', '').lower() == 'low'])
            
            if critical > 0:
                self.log(f"Critical vulnerabilities: {critical}", "ERROR")
            if high > 0:
                self.log(f"High vulnerabilities: {high}", "ERROR")
            if medium > 0:
                self.log(f"Medium vulnerabilities: {medium}", "WARNING")
            if low > 0:
                self.log(f"Low vulnerabilities: {low}", "INFO")
        
        self.log(f"Results saved in: {self.output_dir}", "SUCCESS")
        self.log("Check the HTML report for detailed findings!", "SUCCESS")
    
    def run_complete_assessment(self):
        """
        Run complete bug bounty assessment
        """
        start_time = datetime.now()
        
        try:
            # Phase 1: Reconnaissance
            if not self.run_reconnaissance_phase():
                self.log("Reconnaissance phase failed. Exiting.", "ERROR")
                return False
            
            # Phase 2: Vulnerability Scanning
            if not self.run_vulnerability_scanning_phase():
                self.log("Vulnerability scanning phase failed. Exiting.", "ERROR")
                return False
            
            # Phase 3: Report Generation
            report_path = self.generate_final_report()
            if not report_path:
                self.log("Report generation failed.", "ERROR")
                return False
            
            # Print final summary
            self.print_final_summary()
            
            end_time = datetime.now()
            duration = end_time - start_time
            
            self.log(f"Total scan duration: {duration}", "SUCCESS")
            self.log("Bug bounty assessment completed successfully!", "SUCCESS")
            
            return True
            
        except KeyboardInterrupt:
            self.log("Scan interrupted by user.", "WARNING")
            return False
        except Exception as e:
            self.log(f"Unexpected error during assessment: {e}", "ERROR")
            return False

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="Advanced Bug Bounty Tool - Comprehensive reconnaissance and vulnerability scanning",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py example.com
  python main.py example.com --output-dir /path/to/results
  python main.py example.com --recon-only
  python main.py example.com --vuln-only
        """
    )
    
    parser.add_argument(
        'target',
        help='Target domain to test (e.g., example.com)'
    )
    
    parser.add_argument(
        '--output-dir',
        default='bug_bounty_results',
        help='Output directory for results (default: bug_bounty_results)'
    )
    
    parser.add_argument(
        '--recon-only',
        action='store_true',
        help='Run only reconnaissance phase'
    )
    
    parser.add_argument(
        '--vuln-only',
        action='store_true',
        help='Run only vulnerability scanning phase (requires existing recon results)'
    )
    
    args = parser.parse_args()
    
    # Validate target domain
    if not args.target or '.' not in args.target:
        print(f"{Fore.RED}Error: Please provide a valid target domain (e.g., example.com){Style.RESET_ALL}")
        sys.exit(1)
    
    # Initialize tool
    tool = BugBountyTool(args.target, args.output_dir)
    
    try:
        if args.recon_only:
            # Run only reconnaissance
            success = tool.run_reconnaissance_phase()
        elif args.vuln_only:
            # Run only vulnerability scanning
            success = tool.run_vulnerability_scanning_phase()
        else:
            # Run complete assessment
            success = tool.run_complete_assessment()
        
        if success:
            print(f"\n{Fore.GREEN}✅ Assessment completed successfully!{Style.RESET_ALL}")
            sys.exit(0)
        else:
            print(f"\n{Fore.RED}❌ Assessment failed!{Style.RESET_ALL}")
            sys.exit(1)
            
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}⚠️  Assessment interrupted by user.{Style.RESET_ALL}")
        sys.exit(1)
    except Exception as e:
        print(f"\n{Fore.RED}❌ Unexpected error: {e}{Style.RESET_ALL}")
        sys.exit(1)

if __name__ == "__main__":
    main()