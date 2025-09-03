#!/usr/bin/env python3
"""
External Tools Integration for Advanced Web Reconnaissance Tool
Integrates with popular external reconnaissance tools when available
"""

import subprocess
import os
import json
import tempfile
from pathlib import Path

class ExternalToolsManager:
    """Manager for external reconnaissance tools"""
    
    def __init__(self, logger):
        self.logger = logger
        self.available_tools = self.check_available_tools()

    def check_available_tools(self):
        """Check which external tools are available"""
        tools = {}
        
        # List of external tools to check
        tool_commands = {
            'subfinder': 'subfinder -version',
            'amass': 'amass -version',
            'assetfinder': 'assetfinder --help',
            'httpx': 'httpx -version',
            'nuclei': 'nuclei -version',
            'nmap': 'nmap --version',
            'dig': 'dig -v',
            'whois': 'whois --version',
            'curl': 'curl --version',
            'wget': 'wget --version'
        }
        
        for tool, check_cmd in tool_commands.items():
            try:
                result = subprocess.run(
                    check_cmd.split(), 
                    capture_output=True, 
                    text=True, 
                    timeout=5
                )
                tools[tool] = result.returncode == 0
            except:
                tools[tool] = False
        
        available = [tool for tool, available in tools.items() if available]
        if available:
            self.logger.info(f"Available external tools: {', '.join(available)}")
        else:
            self.logger.warning("No external tools found - using built-in methods only")
        
        return tools

    def run_subfinder(self, domain):
        """Run subfinder for subdomain discovery"""
        if not self.available_tools.get('subfinder'):
            return []
        
        try:
            self.logger.info("Running subfinder...")
            cmd = ['subfinder', '-d', domain, '-silent', '-o', '-']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0:
                subdomains = [line.strip() for line in result.stdout.split('\n') if line.strip()]
                self.logger.success(f"Subfinder found {len(subdomains)} subdomains")
                return subdomains
        except Exception as e:
            self.logger.error(f"Subfinder failed: {e}")
        
        return []

    def run_amass(self, domain):
        """Run amass for subdomain discovery"""
        if not self.available_tools.get('amass'):
            return []
        
        try:
            self.logger.info("Running amass...")
            cmd = ['amass', 'enum', '-d', domain, '-silent']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            
            if result.returncode == 0:
                subdomains = [line.strip() for line in result.stdout.split('\n') if line.strip()]
                self.logger.success(f"Amass found {len(subdomains)} subdomains")
                return subdomains
        except Exception as e:
            self.logger.error(f"Amass failed: {e}")
        
        return []

    def run_assetfinder(self, domain):
        """Run assetfinder for subdomain discovery"""
        if not self.available_tools.get('assetfinder'):
            return []
        
        try:
            self.logger.info("Running assetfinder...")
            cmd = ['assetfinder', '--subs-only', domain]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0:
                subdomains = [line.strip() for line in result.stdout.split('\n') if line.strip()]
                self.logger.success(f"Assetfinder found {len(subdomains)} subdomains")
                return subdomains
        except Exception as e:
            self.logger.error(f"Assetfinder failed: {e}")
        
        return []

    def run_httpx(self, subdomains):
        """Run httpx to check which subdomains are alive"""
        if not self.available_tools.get('httpx') or not subdomains:
            return []
        
        try:
            self.logger.info(f"Running httpx on {len(subdomains)} subdomains...")
            
            # Create temporary file with subdomains
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
                for subdomain in subdomains:
                    f.write(f"{subdomain}\n")
                temp_file = f.name
            
            cmd = [
                'httpx', '-l', temp_file, '-silent', '-status-code', 
                '-content-length', '-title', '-tech-detect', '-json'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
            
            # Clean up temp file
            os.unlink(temp_file)
            
            if result.returncode == 0:
                alive_hosts = []
                for line in result.stdout.split('\n'):
                    if line.strip():
                        try:
                            host_data = json.loads(line)
                            alive_hosts.append(host_data)
                        except:
                            continue
                
                self.logger.success(f"Httpx verified {len(alive_hosts)} alive hosts")
                return alive_hosts
                
        except Exception as e:
            self.logger.error(f"Httpx failed: {e}")
        
        return []

    def run_nuclei(self, targets, templates=None):
        """Run nuclei for vulnerability scanning"""
        if not self.available_tools.get('nuclei') or not targets:
            return []
        
        try:
            self.logger.info("Running nuclei vulnerability scan...")
            
            # Create temporary file with targets
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
                for target in targets:
                    if isinstance(target, dict):
                        f.write(f"{target.get('url', target.get('input', ''))}\n")
                    else:
                        f.write(f"{target}\n")
                temp_file = f.name
            
            cmd = ['nuclei', '-l', temp_file, '-silent', '-json']
            
            if templates:
                cmd.extend(['-t', templates])
            else:
                # Use common templates
                cmd.extend(['-t', 'cves/', '-t', 'vulnerabilities/', '-t', 'misconfiguration/'])
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            # Clean up temp file
            os.unlink(temp_file)
            
            if result.returncode == 0:
                vulnerabilities = []
                for line in result.stdout.split('\n'):
                    if line.strip():
                        try:
                            vuln_data = json.loads(line)
                            vulnerabilities.append(vuln_data)
                        except:
                            continue
                
                self.logger.success(f"Nuclei found {len(vulnerabilities)} potential vulnerabilities")
                return vulnerabilities
                
        except Exception as e:
            self.logger.error(f"Nuclei failed: {e}")
        
        return []

    def run_nmap_port_scan(self, ips):
        """Run nmap for port scanning"""
        if not self.available_tools.get('nmap') or not ips:
            return {}
        
        try:
            self.logger.info(f"Running nmap on {len(ips)} IP addresses...")
            
            scan_results = {}
            
            for ip in list(ips)[:5]:  # Limit to first 5 IPs for demo
                cmd = [
                    'nmap', '-sS', '-T4', '-p', '80,443,22,21,25,53,110,143,993,995,3389,5432,3306',
                    '--open', ip
                ]
                
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
                
                if result.returncode == 0:
                    scan_results[ip] = result.stdout
            
            self.logger.success(f"Nmap completed for {len(scan_results)} IPs")
            return scan_results
            
        except Exception as e:
            self.logger.error(f"Nmap failed: {e}")
        
        return {}

    def run_all_external_tools(self, domain):
        """Run all available external tools"""
        results = {
            'subdomains': set(),
            'alive_hosts': [],
            'vulnerabilities': [],
            'port_scans': {}
        }
        
        # Subdomain discovery
        if self.available_tools.get('subfinder'):
            subfinder_subs = self.run_subfinder(domain)
            results['subdomains'].update(subfinder_subs)
        
        if self.available_tools.get('amass'):
            amass_subs = self.run_amass(domain)
            results['subdomains'].update(amass_subs)
        
        if self.available_tools.get('assetfinder'):
            assetfinder_subs = self.run_assetfinder(domain)
            results['subdomains'].update(assetfinder_subs)
        
        # Convert to list for further processing
        all_subdomains = list(results['subdomains'])
        
        # Check alive hosts
        if self.available_tools.get('httpx') and all_subdomains:
            alive_hosts = self.run_httpx(all_subdomains)
            results['alive_hosts'] = alive_hosts
        
        # Vulnerability scanning (if nuclei is available and we have alive hosts)
        if self.available_tools.get('nuclei') and results['alive_hosts']:
            vulnerabilities = self.run_nuclei(results['alive_hosts'])
            results['vulnerabilities'] = vulnerabilities
        
        return results

class ToolInstaller:
    """Installer for external tools"""
    
    def __init__(self, logger):
        self.logger = logger

    def install_go_tools(self):
        """Install Go-based tools"""
        go_tools = {
            'subfinder': 'go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest',
            'httpx': 'go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest',
            'nuclei': 'go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest',
            'assetfinder': 'go install github.com/tomnomnom/assetfinder@latest'
        }
        
        # Check if Go is installed
        try:
            subprocess.run(['go', 'version'], capture_output=True, check=True)
            self.logger.info("Go is installed, installing Go tools...")
            
            for tool, install_cmd in go_tools.items():
                try:
                    self.logger.info(f"Installing {tool}...")
                    subprocess.run(install_cmd.split(), check=True, timeout=120)
                    self.logger.success(f"{tool} installed successfully")
                except subprocess.CalledProcessError:
                    self.logger.error(f"Failed to install {tool}")
                except subprocess.TimeoutExpired:
                    self.logger.error(f"Timeout installing {tool}")
                    
        except subprocess.CalledProcessError:
            self.logger.warning("Go is not installed - skipping Go tools")

    def install_system_tools(self):
        """Install system tools based on OS"""
        os_type = platform.system().lower()
        
        if os_type == "linux":
            # Ubuntu/Debian
            try:
                subprocess.run([
                    'sudo', 'apt-get', 'update', '&&',
                    'sudo', 'apt-get', 'install', '-y', 
                    'nmap', 'dnsutils', 'whois', 'curl', 'wget'
                ], shell=True, check=True)
                self.logger.success("System tools installed (apt)")
            except:
                # Try yum/dnf for RedHat/CentOS/Fedora
                try:
                    subprocess.run([
                        'sudo', 'yum', 'install', '-y',
                        'nmap', 'bind-utils', 'whois', 'curl', 'wget'
                    ], check=True)
                    self.logger.success("System tools installed (yum)")
                except:
                    self.logger.warning("Could not install system tools automatically")
        
        elif os_type == "darwin":  # macOS
            try:
                subprocess.run([
                    'brew', 'install', 'nmap', 'bind', 'whois', 'curl', 'wget'
                ], check=True)
                self.logger.success("System tools installed (brew)")
            except:
                self.logger.warning("Could not install system tools - please install Homebrew")

def main():
    """Main installer function"""
    from advanced_recon_tool import Logger
    
    logger = Logger()
    installer = ToolInstaller(logger)
    
    print("🛠️  External Tools Installer")
    print("=" * 30)
    
    # Install Go tools
    installer.install_go_tools()
    
    # Install system tools
    installer.install_system_tools()
    
    print("\n✅ External tools installation completed!")
    print("Run 'python test_tool.py' to verify everything works")

if __name__ == "__main__":
    import platform
    main()