#!/usr/bin/env python3
"""
Phase 5: Advanced Directory Discovery
Comprehensive directory and file discovery using multiple tools and techniques
"""

import requests
import subprocess
import platform
import os
from datetime import datetime
from typing import Dict, Any, List
import json
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

class Phase5DirectoryDiscovery:
    """Advanced Directory Discovery with comprehensive crawling"""
    
    def __init__(self):
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        self.directory_wordlist = [
            '/admin', '/administrator', '/login', '/dashboard', '/panel', '/control',
            '/api', '/rest', '/graphql', '/docs', '/documentation', '/help',
            '/config', '/configuration', '/settings', '/options', '/preferences',
            '/backup', '/backups', '/bak', '/old', '/archive', '/archives',
            '/files', '/file', '/uploads', '/upload', '/download', '/downloads',
            '/media', '/assets', '/images', '/image', '/img', '/css', '/js',
            '/scripts', '/script', '/styles', '/style', '/themes', '/theme',
            '/templates', '/template', '/includes', '/include', '/lib', '/library',
            '/vendor', '/vendors', '/third-party', '/external', '/plugins',
            '/modules', '/components', '/widgets', '/extensions', '/addons',
            '/cgi-bin', '/cgi', '/bin', '/sbin', '/usr', '/var', '/tmp', '/temp',
            '/logs', '/log', '/cache', '/session', '/sessions', '/data',
            '/database', '/db', '/sql', '/mysql', '/postgres', '/mongo',
            '/redis', '/elasticsearch', '/search', '/index', '/sitemap',
            '/robots.txt', '/sitemap.xml', '/crossdomain.xml', '/favicon.ico',
            '/.htaccess', '/.htpasswd', '/.git', '/.svn', '/.hg', '/.bzr',
            '/.env', '/.env.local', '/.env.production', '/.env.development',
            '/package.json', '/composer.json', '/requirements.txt', '/pom.xml',
            '/build.xml', '/Dockerfile', '/docker-compose.yml', '/.gitignore',
            '/.gitattributes', '/.dockerignore', '/.editorconfig', '/.eslintrc',
            '/.prettierrc', '/tsconfig.json', '/webpack.config.js', '/gulpfile.js',
            '/gruntfile.js', '/bower.json', '/yarn.lock', '/package-lock.json',
            '/index.php', '/index.html', '/index.htm', '/default.html',
            '/home.html', '/main.php', '/main.html', '/start.php', '/start.html',
            '/welcome.php', '/welcome.html', '/test.php', '/test.html',
            '/info.php', '/phpinfo.php', '/admin.php', '/login.php', '/config.php',
            '/web.config', '/app.config', '/application.yml', '/application.properties'
        ]
    
    def run_phase(self, target: str) -> Dict[str, Any]:
        """Run Phase 5: Advanced Directory Discovery"""
        print(f"🔍 Phase 5: Advanced Directory Discovery for {target}")
        results = {
            'target': target,
            'phase': 5,
            'start_time': datetime.now().isoformat(),
            'directories_found': [],
            'files_found': [],
            'config_files': [],
            'backup_files': [],
            'admin_panels': [],
            'sensitive_files': [],
            'api_endpoints': [],
            'development_files': [],
            'tool_results': {},
            'techniques_used': [],
            'errors': []
        }
        
        try:
            # Technique 1: Comprehensive Directory Discovery
            print("   📁 Comprehensive Directory Discovery...")
            results['techniques_used'].append('Comprehensive Directory Discovery')
            
            # Extended directory wordlist
            extended_directories = self.directory_wordlist + [
                # API endpoints
                '/api', '/api/v1', '/api/v2', '/api/v3', '/rest', '/graphql', '/rpc', '/soap',
                '/swagger', '/swagger-ui', '/docs', '/documentation', '/openapi.json',
                
                # Development
                '/dev', '/development', '/staging', '/stage', '/test', '/testing', '/qa', '/preprod', '/prod', '/production',
                '/debug', '/logs', '/log', '/tmp', '/temp', '/cache', '/session', '/sessions',
                
                # Admin panels
                '/admin', '/administrator', '/adminpanel', '/admin-panel', '/admin_area', '/adminarea',
                '/admincp', '/admin-cp', '/admincp', '/adm', '/administration', '/administrator',
                '/panel', '/control', '/controlpanel', '/control-panel', '/dashboard', '/dash',
                '/wp-admin', '/wp-login.php', '/administrator', '/user', '/users', '/account', '/accounts',
                
                # File management
                '/files', '/file', '/uploads', '/upload', '/download', '/downloads', '/media', '/assets',
                '/images', '/image', '/img', '/css', '/js', '/javascript', '/scripts', '/script',
                '/styles', '/style', '/themes', '/theme', '/templates', '/template',
                
                # Database and config
                '/db', '/database', '/sql', '/mysql', '/postgres', '/postgresql', '/mongo', '/mongodb',
                '/redis', '/elasticsearch', '/cassandra', '/oracle', '/sqlserver', '/mariadb', '/sqlite',
                '/config', '/configuration', '/conf', '/settings', '/setting', '/options', '/option',
                '/preferences', '/preference', '/params', '/parameters', '/parameter', '/env', '/environment',
                
                # Backup and archives
                '/backup', '/backups', '/bak', '/old', '/archive', '/archives', '/temp', '/tmp', '/temporary',
                '/copy', '/copies', '/duplicate', '/duplicates', '/original', '/originals', '/source', '/sources',
                '/.git', '/.svn', '/.hg', '/.bzr', '/.cvs',
                
                # Security
                '/security', '/secure', '/ssl', '/tls', '/cert', '/certificate', '/certificates', '/certs',
                '/vpn', '/firewall', '/bastion', '/jump', '/gateway', '/proxy', '/proxies', '/loadbalancer',
                '/.htaccess', '/.htpasswd', '/robots.txt', '/sitemap.xml', '/crossdomain.xml',
                
                # Special files
                '/phpinfo.php', '/info.php', '/test.php', '/admin.php', '/login.php', '/config.php',
                '/web.config', '/app.config', '/application.yml', '/application.properties',
                '/package.json', '/composer.json', '/requirements.txt', '/pom.xml', '/build.xml',
                '/Dockerfile', '/docker-compose.yml', '/.env', '/.env.local', '/.env.production',
                '/index.php', '/index.html', '/index.htm', '/default.html', '/home.html',
                '/main.php', '/main.html', '/start.php', '/start.html', '/welcome.php', '/welcome.html'
            ]
            
            def check_path(path):
                try:
                    url = f"https://{target}{path}"
                    response = requests.get(url, headers=self.headers, timeout=5, allow_redirects=False)
                    
                    if response.status_code in [200, 301, 302, 403, 401]:
                        result = {
                            'path': path,
                            'url': url,
                            'status_code': response.status_code,
                            'title': self._extract_title(response.text),
                            'content_length': len(response.content),
                            'server': response.headers.get('Server', 'Unknown'),
                            'content_type': response.headers.get('Content-Type', 'Unknown')
                        }
                        
                        if path.endswith('/'):
                            results['directories_found'].append(result)
                        else:
                            results['files_found'].append(result)
                        
                        # Advanced categorization
                        path_lower = path.lower()
                        
                        # Config files
                        if any(keyword in path_lower for keyword in ['config', 'setting', 'env', 'conf', 'ini', 'xml', 'yml', 'yaml', 'properties', 'json']):
                            results['config_files'].append(result)
                        
                        # Backup files
                        elif any(keyword in path_lower for keyword in ['backup', 'bak', 'old', 'archive', 'copy', 'duplicate', '.git', '.svn']):
                            results['backup_files'].append(result)
                        
                        # Admin panels
                        elif any(keyword in path_lower for keyword in ['admin', 'panel', 'login', 'dashboard', 'control', 'manage', 'wp-admin', 'administrator']):
                            results['admin_panels'].append(result)
                        
                        # API endpoints
                        elif any(keyword in path_lower for keyword in ['api', 'rest', 'graphql', 'swagger', 'docs', 'documentation', 'openapi']):
                            results['api_endpoints'].append(result)
                        
                        # Development files
                        elif any(keyword in path_lower for keyword in ['dev', 'test', 'debug', 'log', 'tmp', 'temp', 'cache', 'session']):
                            results['development_files'].append(result)
                        
                        # Sensitive files
                        elif any(keyword in path_lower for keyword in ['passwd', 'shadow', 'htpasswd', 'key', 'cert', 'secret', 'password', 'credential']):
                            results['sensitive_files'].append(result)
                        
                        print(f"   ✅ Found: {path} ({response.status_code}) - {result['content_length']} bytes")
                        return result
                except Exception as e:
                    results['errors'].append(f"Path {path} scan failed: {str(e)}")
                return None
            
            # Use ThreadPoolExecutor for faster scanning
            with ThreadPoolExecutor(max_workers=30) as executor:
                future_to_path = {executor.submit(check_path, path): path for path in extended_directories[:200]}
                
                for future in as_completed(future_to_path):
                    result = future.result()
                    if result:
                        results['techniques_used'].append('Directory Discovery')
            
            # Technique 2: Gobuster Integration
            print("   🔍 Gobuster Integration...")
            results['techniques_used'].append('Gobuster Integration')
            
            if self._is_gobuster_available():
                try:
                    gobuster_results = self._run_gobuster(target)
                    if gobuster_results:
                        results['tool_results']['gobuster'] = gobuster_results
                        print(f"   ✅ Gobuster scan completed")
                except Exception as e:
                    results['errors'].append(f"Gobuster scan failed: {str(e)}")
            else:
                print("   ℹ️ Gobuster not available, skipping")
            
            # Technique 3: Dirsearch Integration
            print("   🔍 Dirsearch Integration...")
            results['techniques_used'].append('Dirsearch Integration')
            
            if self._is_dirsearch_available():
                try:
                    dirsearch_results = self._run_dirsearch(target)
                    if dirsearch_results:
                        results['tool_results']['dirsearch'] = dirsearch_results
                        print(f"   ✅ Dirsearch scan completed")
                except Exception as e:
                    results['errors'].append(f"Dirsearch scan failed: {str(e)}")
            else:
                print("   ℹ️ Dirsearch not available, skipping")
            
            # Technique 4: Feroxbuster Integration
            print("   🔍 Feroxbuster Integration...")
            results['techniques_used'].append('Feroxbuster Integration')
            
            if self._is_feroxbuster_available():
                try:
                    feroxbuster_results = self._run_feroxbuster(target)
                    if feroxbuster_results:
                        results['tool_results']['feroxbuster'] = feroxbuster_results
                        print(f"   ✅ Feroxbuster scan completed")
                except Exception as e:
                    results['errors'].append(f"Feroxbuster scan failed: {str(e)}")
            else:
                print("   ℹ️ Feroxbuster not available, skipping")
            
            # Technique 5: Katana Integration (for crawling)
            print("   🕷️ Katana Integration...")
            results['techniques_used'].append('Katana Integration')
            
            if self._is_katana_available():
                try:
                    katana_results = self._run_katana(target)
                    if katana_results:
                        results['tool_results']['katana'] = katana_results
                        print(f"   ✅ Katana crawling completed")
                except Exception as e:
                    results['errors'].append(f"Katana crawling failed: {str(e)}")
            else:
                print("   ℹ️ Katana not available, skipping")
            
            # Technique 6: Gospider Integration
            print("   🕷️ Gospider Integration...")
            results['techniques_used'].append('Gospider Integration')
            
            if self._is_gospider_available():
                try:
                    gospider_results = self._run_gospider(target)
                    if gospider_results:
                        results['tool_results']['gospider'] = gospider_results
                        print(f"   ✅ Gospider crawling completed")
                except Exception as e:
                    results['errors'].append(f"Gospider crawling failed: {str(e)}")
            else:
                print("   ℹ️ Gospider not available, skipping")
            
            # Technique 7: HTTP Methods Testing
            print("   🔍 HTTP Methods Testing...")
            results['techniques_used'].append('HTTP Methods Testing')
            
            methods_to_test = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS', 'TRACE', 'CONNECT']
            allowed_methods = []
            
            for method in methods_to_test:
                try:
                    response = requests.request(method, f"https://{target}/", headers=self.headers, timeout=5)
                    if response.status_code not in [405, 501]:  # Method not allowed
                        allowed_methods.append({
                            'method': method,
                            'status_code': response.status_code,
                            'allowed': True
                        })
                        print(f"   ✅ HTTP {method} allowed: {response.status_code}")
                except Exception as e:
                    allowed_methods.append({
                        'method': method,
                        'status_code': 'error',
                        'allowed': False
                    })
            
            results['http_methods'] = allowed_methods
            
            results['end_time'] = datetime.now().isoformat()
            results['status'] = 'completed'
            results['summary'] = f"Found {len(results['directories_found'])} directories, {len(results['files_found'])} files using {len(results['techniques_used'])} advanced techniques"
            
            print(f"   ✅ Phase 5 completed: {results['summary']}")
            return results
            
        except Exception as e:
            results['errors'].append(f"Phase 5 failed: {str(e)}")
            results['status'] = 'error'
            print(f"   ❌ Phase 5 failed: {e}")
            return results
    
    def _extract_title(self, html_content: str) -> str:
        """Extract page title from HTML content"""
        try:
            title_match = re.search(r'<title[^>]*>(.*?)</title>', html_content, re.IGNORECASE | re.DOTALL)
            if title_match:
                return title_match.group(1).strip()
        except:
            pass
        return 'No title found'
    
    def _is_gobuster_available(self) -> bool:
        """Check if gobuster is available"""
        try:
            subprocess.run(['gobuster', '--version'], capture_output=True, timeout=5)
            return True
        except:
            return False
    
    def _run_gobuster(self, target: str) -> Dict[str, Any]:
        """Run gobuster if available"""
        try:
            # Try different wordlist paths
            wordlist_paths = [
                '/usr/share/wordlists/dirb/common.txt',
                '/usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt',
                '/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt',
                '/usr/share/wordlists/dirb/big.txt',
                '/opt/SecLists/Discovery/Web-Content/common.txt'
            ]
            
            wordlist = None
            for path in wordlist_paths:
                if os.path.exists(path):
                    wordlist = path
                    break
            
            if wordlist:
                cmd = ['gobuster', 'dir', '-u', f"https://{target}", '-w', wordlist, '-t', '50', '-q', '-o', '/tmp/gobuster_output.txt']
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                
                # Read output file if it exists
                output_content = ""
                if os.path.exists('/tmp/gobuster_output.txt'):
                    with open('/tmp/gobuster_output.txt', 'r') as f:
                        output_content = f.read()
                    os.remove('/tmp/gobuster_output.txt')
                
                if result.returncode == 0 or output_content:
                    return {
                        'stdout': result.stdout + output_content,
                        'stderr': result.stderr,
                        'success': True,
                        'wordlist_used': wordlist
                    }
        except Exception as e:
            print(f"   ❌ Gobuster error: {e}")
        return None
    
    def _is_dirsearch_available(self) -> bool:
        """Check if dirsearch is available"""
        try:
            subprocess.run(['dirsearch', '--version'], capture_output=True, timeout=5)
            return True
        except:
            return False
    
    def _run_dirsearch(self, target: str) -> Dict[str, Any]:
        """Run dirsearch if available"""
        try:
            cmd = ['dirsearch', '-u', f"https://{target}", '-t', '50', '--quiet']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0:
                return {
                    'stdout': result.stdout,
                    'stderr': result.stderr,
                    'success': True
                }
        except:
            pass
        return None
    
    def _is_feroxbuster_available(self) -> bool:
        """Check if feroxbuster is available"""
        try:
            subprocess.run(['feroxbuster', '--version'], capture_output=True, timeout=5)
            return True
        except:
            return False
    
    def _run_feroxbuster(self, target: str) -> Dict[str, Any]:
        """Run feroxbuster if available"""
        try:
            cmd = ['feroxbuster', '-u', f"https://{target}", '-t', '50', '--quiet']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0:
                return {
                    'stdout': result.stdout,
                    'stderr': result.stderr,
                    'success': True
                }
        except:
            pass
        return None
    
    def _is_katana_available(self) -> bool:
        """Check if katana is available"""
        try:
            subprocess.run(['katana', '--version'], capture_output=True, timeout=5)
            return True
        except:
            return False
    
    def _run_katana(self, target: str) -> Dict[str, Any]:
        """Run katana if available"""
        try:
            cmd = ['katana', '-u', f"https://{target}", '-d', '3', '-j', '50', '-q']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0:
                return {
                    'stdout': result.stdout,
                    'stderr': result.stderr,
                    'success': True
                }
        except:
            pass
        return None
    
    def _is_gospider_available(self) -> bool:
        """Check if gospider is available"""
        try:
            subprocess.run(['gospider', '--version'], capture_output=True, timeout=5)
            return True
        except:
            return False
    
    def _run_gospider(self, target: str) -> Dict[str, Any]:
        """Run gospider if available"""
        try:
            cmd = ['gospider', '-s', f"https://{target}", '-d', '3', '-t', '50', '-q']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0:
                return {
                    'stdout': result.stdout,
                    'stderr': result.stderr,
                    'success': True
                }
        except:
            pass
        return None

if __name__ == "__main__":
    phase = Phase5DirectoryDiscovery()
    result = phase.run_phase("example.com")
    print(json.dumps(result, indent=2))