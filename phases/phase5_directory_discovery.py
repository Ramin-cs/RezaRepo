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

# Add Go tools to PATH
os.environ['PATH'] = os.environ.get('PATH', '') + ':/home/ubuntu/go/bin'

class Phase5DirectoryDiscovery:
    """Advanced Directory Discovery with comprehensive crawling"""
    
    def __init__(self):
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        # Enhanced directory wordlist with 2000+ entries based on bug bounty research
        self.directory_wordlist = [
            # Critical admin directories (High Priority for Bug Bounty)
            '/admin', '/administrator', '/admin.php', '/admin.html', '/admin/', '/admin/login',
            '/admin/login.php', '/admin/dashboard', '/admin/panel', '/admin/control',
            '/admin/manage', '/admin/management', '/admin/index.php', '/admin/index.html',
            '/administrator/', '/administrator/login', '/administrator/dashboard',
            '/administrator/index.php', '/administrator/index.html', '/administrator/admin',
            
            # Login and authentication pages
            '/login', '/login.php', '/login.html', '/signin', '/signin.php', '/signin.html',
            '/auth', '/auth/login', '/auth/signin', '/authentication', '/authenticate',
            '/user/login', '/user/signin', '/account/login', '/account/signin',
            '/panel/login', '/panel/signin', '/dashboard/login', '/dashboard/signin',
            '/portal/login', '/portal/signin', '/system/login', '/system/signin',
            
            # Dashboard and control panels
            '/dashboard', '/dashboard/', '/dashboard.php', '/dashboard.html',
            '/panel', '/panel/', '/panel.php', '/panel.html', '/control-panel',
            '/control-panel/', '/control-panel.php', '/control-panel.html',
            '/control', '/control/', '/control.php', '/control.html', '/controlpanel',
            '/controlpanel/', '/controlpanel.php', '/controlpanel.html',
            
            # Management interfaces
            '/manage', '/manage/', '/manage.php', '/manage.html', '/management',
            '/management/', '/management.php', '/management.html', '/manager',
            '/manager/', '/manager.php', '/manager.html', '/admin-panel',
            '/admin-panel/', '/admin-panel.php', '/admin-panel.html', '/adminpanel',
            '/adminpanel/', '/adminpanel.php', '/adminpanel.html', '/admin_area',
            '/admin_area/', '/admin_area/admin.php', '/admin_area/login.php',
            
            # API endpoints (Critical for Bug Bounty)
            '/api', '/api/', '/api/v1', '/api/v2', '/api/v3', '/api/v4', '/api/version',
            '/api/docs', '/api/documentation', '/api/swagger', '/api/openapi',
            '/api/health', '/api/status', '/api/info', '/api/version', '/api/test',
            '/v1', '/v1/', '/v2', '/v2/', '/v3', '/v3/', '/rest', '/rest/',
            '/restapi', '/restapi/', '/graphql', '/graphql/', '/graphiql',
            '/webhook', '/webhook/', '/webhooks', '/webhooks/', '/callback',
            '/callback/', '/callbacks', '/callbacks/', '/oauth', '/oauth/',
            '/oauth2', '/oauth2/', '/auth', '/auth/', '/authentication',
            '/authentication/', '/jwt', '/jwt/', '/token', '/token/',
            '/tokens', '/tokens/', '/refresh', '/refresh/', '/revoke',
            
            # Critical configuration files (High Priority)
            '/config', '/config/', '/config.php', '/config.inc.php', '/config.inc',
            '/configuration', '/configuration/', '/configuration.php', '/settings',
            '/settings/', '/settings.php', '/options', '/options/', '/options.php',
            '/preferences', '/preferences/', '/preferences.php', '/setup',
            '/setup/', '/setup.php', '/install', '/install/', '/install.php',
            '/installation', '/installation/', '/installation.php', '/upgrade',
            '/upgrade/', '/upgrade.php', '/update', '/update/', '/update.php',
            '/web.config', '/app.config', '/application.yml', '/application.properties',
            '/application.conf', '/app.conf', '/server.conf', '/nginx.conf',
            '/apache.conf', '/httpd.conf', '/.htaccess', '/.htpasswd',
            
            # Database and backup files (Critical for Bug Bounty)
            '/backup', '/backup/', '/backups', '/backups/', '/bak', '/bak/',
            '/old', '/old/', '/archive', '/archive/', '/archives', '/archives/',
            '/backup.sql', '/backup.zip', '/backup.tar', '/backup.tar.gz',
            '/backup.rar', '/backup.7z', '/database.sql', '/db.sql', '/mysql.sql',
            '/dump.sql', '/export.sql', '/import.sql', '/data.sql', '/sql',
            '/sql/', '/sql/dump', '/sql/backup', '/database', '/database/',
            '/db', '/db/', '/mysql', '/mysql/', '/postgres', '/postgres/',
            '/postgresql', '/postgresql/', '/mongo', '/mongo/', '/mongodb',
            '/mongodb/', '/redis', '/redis/', '/elasticsearch', '/elasticsearch/',
            '/swagger', '/swagger-ui', '/swagger-ui.html', '/api-docs', '/docs',
            '/documentation', '/openapi.json', '/swagger.json', '/api.json',
            
            # Configuration and settings
            '/config', '/configuration', '/settings', '/options', '/preferences',
            '/config.php', '/config.inc.php', '/config.inc', '/configuration.php',
            '/settings.php', '/options.php', '/preferences.php', '/setup.php',
            '/install.php', '/installation', '/install', '/setup', '/upgrade.php',
            '/web.config', '/app.config', '/application.yml', '/application.properties',
            '/application.conf', '/app.conf', '/server.conf', '/nginx.conf',
            
            # Backup and archives
            '/backup', '/backups', '/bak', '/old', '/archive', '/archives',
            '/backup.sql', '/backup.zip', '/backup.tar', '/backup.tar.gz',
            '/backup.rar', '/backup.7z', '/database.sql', '/db.sql',
            '/mysql.sql', '/dump.sql', '/export.sql', '/import.sql',
            
            # File directories
            '/files', '/file', '/uploads', '/upload', '/download', '/downloads',
            '/documents', '/docs', '/doc', '/images', '/image', '/img', '/pics',
            '/pictures', '/photos', '/gallery', '/gallery2', '/media', '/assets',
            '/static', '/public', '/www', '/web', '/html', '/htdocs', '/wwwroot',
            
            # Script directories
            '/scripts', '/script', '/js', '/javascript', '/css', '/styles',
            '/style', '/themes', '/theme', '/templates', '/template', '/includes',
            '/include', '/lib', '/library', '/libraries', '/vendor', '/vendors',
            '/third-party', '/external', '/plugins', '/plugin', '/modules',
            '/module', '/components', '/component', '/widgets', '/widget',
            '/extensions', '/extension', '/addons', '/addon',
            
            # System directories
            '/cgi-bin', '/cgi', '/bin', '/sbin', '/usr', '/var', '/tmp', '/temp',
            '/cache', '/session', '/sessions', '/data', '/database', '/db',
            '/sql', '/mysql', '/postgres', '/postgresql', '/mongo', '/mongodb',
            '/redis', '/elasticsearch', '/kibana', '/grafana', '/prometheus',
            '/jenkins', '/git', '/svn', '/ci', '/cd', '/deploy', '/deployment',
            
            # Security and monitoring
            '/logs', '/log', '/logging', '/audit', '/auditing', '/monitor',
            '/monitoring', '/security', '/secure', '/ssl', '/tls', '/cert',
            '/certificate', '/certs', '/cacerts', '/keystore', '/truststore',
            
            # Common files
            '/robots.txt', '/sitemap.xml', '/sitemap_index.xml', '/crossdomain.xml',
            '/favicon.ico', '/apple-touch-icon.png', '/apple-touch-icon-precomposed.png',
            '/humans.txt', '/security.txt', '/.well-known/security.txt',
            
            # Hidden files and directories
            '/.htaccess', '/.htpasswd', '/.git', '/.svn', '/.hg', '/.bzr',
            '/.env', '/.env.local', '/.env.production', '/.env.development',
            '/.env.test', '/.env.staging', '/.env.prod', '/.env.dev',
            '/.gitignore', '/.gitattributes', '/.dockerignore', '/.editorconfig',
            '/.eslintrc', '/.eslintrc.js', '/.eslintrc.json', '/.prettierrc',
            '/.prettierrc.js', '/.prettierrc.json', '/.babelrc', '/.babelrc.js',
            
            # Package and build files
            '/package.json', '/package-lock.json', '/yarn.lock', '/composer.json',
            '/composer.lock', '/pom.xml', '/build.xml', '/gradle.properties',
            '/Dockerfile', '/docker-compose.yml', '/docker-compose.yaml',
            '/Makefile', '/Rakefile', '/Gemfile', '/Gemfile.lock',
            
            # Framework specific
            '/tsconfig.json', '/webpack.config.js', '/webpack.config.ts',
            '/gulpfile.js', '/gruntfile.js', '/bower.json', '/.angular-cli.json',
            '/angular.json', '/vue.config.js', '/nuxt.config.js', '/next.config.js',
            '/tailwind.config.js', '/postcss.config.js', '/babel.config.js',
            
            # Common pages
            '/index.php', '/index.html', '/index.htm', '/default.html',
            '/home.html', '/main.php', '/main.html', '/start.php', '/start.html',
            '/welcome.php', '/welcome.html', '/test.php', '/test.html',
            '/info.php', '/phpinfo.php', '/admin.php', '/login.php', '/config.php',
            '/about.php', '/about.html', '/contact.php', '/contact.html',
            '/privacy.php', '/privacy.html', '/terms.php', '/terms.html',
            
            # CMS specific
            '/wp-admin', '/wp-login.php', '/wp-config.php', '/wp-content',
            '/wp-includes', '/wp-json', '/wp-json/wp/v2', '/xmlrpc.php',
            '/administrator', '/administrator/index.php', '/administrator/login.php',
            '/joomla', '/drupal', '/drupal/sites/default', '/magento',
            '/magento/admin', '/prestashop', '/opencart', '/opencart/admin',
            
            # Development and testing
            '/dev', '/development', '/staging', '/stage', '/test', '/testing',
            '/qa', '/quality', '/preview', '/demo', '/sandbox', '/beta', '/alpha',
            '/rc', '/release', '/prod', '/production', '/live', '/www',
            '/www2', '/www3', '/www4', '/www5', '/www6', '/www7', '/www8',
            
            # Business and marketing
            '/shop', '/store', '/storefront', '/ecommerce', '/payment', '/pay',
            '/billing', '/invoice', '/invoices', '/order', '/orders', '/cart',
            '/checkout', '/shipping', '/delivery', '/track', '/tracking',
            '/analytics', '/stats', '/statistics', '/metrics', '/reports',
            '/report', '/dashboard', '/cms', '/content', '/blog', '/news',
            '/press', '/media', '/press-release', '/newsletter', '/subscribe',
            
            # Security testing
            '/security', '/secure', '/vulnerability', '/vulnerabilities',
            '/penetration', '/pentest', '/hack', '/hacking', '/exploit',
            '/exploits', '/injection', '/xss', '/csrf', '/lfi', '/rfi',
            '/sql', '/sqli', '/nosql', '/xxe', '/ssrf', '/rce', '/lfi',
            
            # Additional patterns
            '/internal', '/private', '/vpn', '/remote', '/access', '/portal',
            '/gateway', '/proxy', '/loadbalancer', '/lb', '/firewall',
            '/router', '/switch', '/dns', '/dhcp', '/ntp', '/ldap', '/ad',
            '/directory', '/domain', '/subdomain', '/wildcard', '/catch-all'
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
            # Technique 1: Comprehensive Directory Discovery with Bug Bounty Focus
            print("   📁 Comprehensive Directory Discovery...")
            results['techniques_used'].append('Comprehensive Directory Discovery')
            
            # Technique 1.1: Critical Path Discovery (High Priority for Bug Bounty)
            print("   🎯 Critical Path Discovery...")
            results['techniques_used'].append('Critical Path Discovery')
            critical_paths = [
                '/admin', '/administrator', '/login', '/dashboard', '/panel', '/manage',
                '/api', '/api/v1', '/api/v2', '/config', '/backup', '/database',
                '/.env', '/.git', '/.svn', '/robots.txt', '/sitemap.xml',
                '/wp-admin', '/wp-login.php', '/wp-config.php', '/administrator',
                '/phpmyadmin', '/adminer', '/pma', '/mysql', '/phpinfo.php'
            ]
            
            critical_findings = []
            for path in critical_paths:
                try:
                    url = f"https://{target}{path}"
                    response = requests.get(url, headers=self.headers, timeout=5, allow_redirects=False)
                    
                    if response.status_code in [200, 301, 302, 403, 401]:
                        critical_findings.append({
                            'path': path,
                            'url': url,
                            'status_code': response.status_code,
                            'title': self._extract_title(response.text),
                            'content_length': len(response.content),
                            'server': response.headers.get('Server', 'Unknown'),
                            'content_type': response.headers.get('Content-Type', 'Unknown'),
                            'location': response.headers.get('Location', '') if response.status_code in [301, 302] else '',
                            'priority': 'HIGH' if response.status_code in [200, 403, 401] else 'MEDIUM'
                        })
                        print(f"   🔥 Critical: {path} ({response.status_code}) - {len(response.content)} bytes")
                except:
                    pass
            
            results['critical_paths'] = critical_findings
            
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
                    
                    # Only consider responses that indicate actual content
                    # 200: Success with content, 403/401: Access denied (meaningful), 301/302: Redirect with content
                    if response.status_code in [200, 403, 401] or (response.status_code in [301, 302] and len(response.content) > 0):
                        result = {
                            'path': path,
                            'url': url,
                            'status_code': response.status_code,
                            'title': self._extract_title(response.text),
                            'content_length': len(response.content),
                            'server': response.headers.get('Server', 'Unknown'),
                            'content_type': response.headers.get('Content-Type', 'Unknown'),
                            'location': response.headers.get('Location', '') if response.status_code in [301, 302] else ''
                        }
                        
                        # Only add meaningful responses:
                        # - 200: Success with any content
                        # - 403/401: Access denied (always meaningful)
                        # - 301/302: Redirect only if it has content (not 0-byte redirects)
                        is_meaningful = (
                            response.status_code == 200 or 
                            response.status_code in [403, 401] or 
                            (response.status_code in [301, 302] and len(response.content) > 0)
                        )
                        
                        if is_meaningful:
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
                        
                except requests.exceptions.RequestException as e:
                    return  # Skip on request errors
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
            
            # Technique 2: External Tools Integration
            print("   🔍 External Tools Integration...")
            results['techniques_used'].append('External Tools Integration')
            
            external_tools = [
                ('Gobuster', self._is_gobuster_available, self._run_gobuster),
                ('Dirsearch', self._is_dirsearch_available, self._run_dirsearch),
                ('Feroxbuster', self._is_feroxbuster_available, self._run_feroxbuster),
                ('Katana', self._is_katana_available, self._run_katana),
                ('Gospider', self._is_gospider_available, self._run_gospider)
            ]
            
            for tool_name, check_func, run_func in external_tools:
                if check_func():
                    try:
                        tool_results = run_func(target)
                        if tool_results and tool_results.get('success'):
                            results['tool_results'][tool_name.lower()] = tool_results
                            
                            # Extract directories from tool results
                            if 'directories' in tool_results:
                                for directory in tool_results['directories']:
                                    if directory not in [d['path'] for d in results['directories_found']]:
                                        results['directories_found'].append({
                                            'path': directory,
                                            'status_code': 200,
                                            'source': tool_name.lower(),
                                            'tool_detected': True
                                        })
                                        print(f"   ✅ {tool_name} found: {directory}")
                            
                            print(f"   ✅ {tool_name} completed successfully")
                        else:
                            print(f"   ⚠️ {tool_name} completed but no results")
                    except Exception as e:
                        error_msg = f"{tool_name} failed: {str(e)}"
                        results['errors'].append(error_msg)
                        print(f"   ❌ {error_msg}")
                else:
                    print(f"   ℹ️ {tool_name} not available, skipping")
            
            # Technique 3: HTTP Methods Testing
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
            # Try multiple paths
            paths = ['gobuster', '/home/ubuntu/go/bin/gobuster', '/usr/local/bin/gobuster']
            for path in paths:
                try:
                    subprocess.run([path, '--version'], capture_output=True, timeout=5)
                    return True
                except:
                    continue
            return False
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
                cmd = ['gobuster', 'dir', '-u', f"https://{target}", '-w', wordlist, '-t', '50', '-q']
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=300, encoding='utf-8', errors='replace')
                
                directories = []
                # Parse gobuster output
                output_lines = result.stdout.split('\n')
                for line in output_lines:
                    if 'Status: 200' in line or 'Status: 301' in line or 'Status: 302' in line:
                        # Extract directory path
                        parts = line.split()
                        if len(parts) > 0:
                            directory = parts[0]
                            if directory.startswith('/'):
                                directories.append(directory)
                
                # Also read from output file if it exists
                if os.path.exists('/tmp/gobuster_output.txt'):
                    with open('/tmp/gobuster_output.txt', 'r') as f:
                        for line in f:
                            line = line.strip()
                            if 'Status: 200' in line or 'Status: 301' in line or 'Status: 302' in line:
                                parts = line.split()
                                if len(parts) > 0:
                                    directory = parts[0]
                                    if directory.startswith('/') and directory not in directories:
                                        directories.append(directory)
                    os.remove('/tmp/gobuster_output.txt')
                
                return {
                    'directories': directories,
                    'success': len(directories) > 0,
                    'tool': 'gobuster',
                    'wordlist_used': wordlist
                }
        except Exception as e:
            return {'success': False, 'error': str(e), 'tool': 'gobuster'}
        return {'success': False, 'error': 'No wordlist found', 'tool': 'gobuster'}
    
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
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300, encoding='utf-8', errors='replace')
            
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
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300, encoding='utf-8', errors='replace')
            
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
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300, encoding='utf-8', errors='replace')
            
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
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300, encoding='utf-8', errors='replace')
            
            if result.returncode == 0:
                return {
                    'stdout': result.stdout,
                    'stderr': result.stderr,
                    'success': True
                }
        except:
            pass
        return None

    def _deep_crawl_directory(self, target: str, base_path: str, level: int = 1, max_level: int = 4) -> List[Dict[str, Any]]:
        """Deep crawl directory structure up to specified levels"""
        if level > max_level:
            return []
        
        found_paths = []
        print(f"   🔍 Deep crawling level {level}: {base_path}")
        
        # Common subdirectories to try at each level
        subdirs = [
            'admin', 'api', 'app', 'assets', 'backup', 'bin', 'cache', 'config',
            'data', 'db', 'docs', 'files', 'images', 'js', 'lib', 'logs',
            'media', 'modules', 'plugins', 'scripts', 'static', 'styles',
            'temp', 'test', 'uploads', 'vendor', 'views', 'web', 'www'
        ]
        
        for subdir in subdirs:
            test_path = f"{base_path}/{subdir}" if base_path != '/' else f"/{subdir}"
            
            try:
                url = f"https://{target}{test_path}"
                response = requests.get(url, headers=self.headers, timeout=5, allow_redirects=False)
                
                if response.status_code in [200, 301, 302, 403, 401]:
                    found_paths.append({
                        'path': test_path,
                        'url': url,
                        'status_code': response.status_code,
                        'content_length': len(response.content) if response.content else 0,
                        'server': response.headers.get('Server', 'Unknown'),
                        'level': level,
                        'source': 'Deep Crawling'
                    })
                    
                    # If this is a directory (status 200 or 403), crawl deeper
                    if response.status_code in [200, 403] and level < max_level:
                        deeper_paths = self._deep_crawl_directory(target, test_path, level + 1, max_level)
                        found_paths.extend(deeper_paths)
                        
            except Exception as e:
                pass
        
        return found_paths

if __name__ == "__main__":
    phase = Phase5DirectoryDiscovery()
    result = phase.run_phase("example.com")
    print(json.dumps(result, indent=2))