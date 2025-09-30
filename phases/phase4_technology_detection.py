#!/usr/bin/env python3
"""
Phase 4: Advanced Technology Detection
Comprehensive technology stack analysis with framework and CMS detection
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

class Phase4TechnologyDetection:
    """Advanced Technology Detection with comprehensive analysis"""
    
    def __init__(self):
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
    
    def run_phase(self, target: str) -> Dict[str, Any]:
        """Run Phase 4: Advanced Technology Detection"""
        print(f"🔍 Phase 4: Advanced Technology Detection for {target}")
        results = {
            'target': target,
            'phase': 4,
            'start_time': datetime.now().isoformat(),
            'technologies': [],
            'headers_analysis': {},
            'content_analysis': {},
            'javascript_analysis': {},
            'css_analysis': {},
            'cms_detection': {},
            'framework_detection': {},
            'server_detection': {},
            'techniques_used': [],
            'errors': []
        }
        
        try:
            # Technique 1: Comprehensive Technology Analysis
            print("   🌐 Comprehensive Technology Analysis...")
            results['techniques_used'].append('Comprehensive Technology Analysis')
            
            try:
                response = requests.get(f"https://{target}", headers=self.headers, timeout=10, allow_redirects=True)
                results['headers_analysis'] = dict(response.headers)
                content = response.text.lower()
                
                # Advanced technology detection
                technologies = []
                
                # Server detection
                print("   🖥️ Server Detection...")
                results['techniques_used'].append('Server Detection')
                
                server = response.headers.get('Server', '').lower()
                server_headers = response.headers.get('X-Server', '').lower()
                
                server_patterns = {
                    'nginx': ['nginx', 'ngx'],
                    'apache': ['apache', 'httpd'],
                    'iis': ['iis', 'microsoft-iis'],
                    'lighttpd': ['lighttpd', 'lighty'],
                    'tomcat': ['tomcat', 'apache-tomcat'],
                    'jetty': ['jetty'],
                    'node': ['node', 'nodejs'],
                    'cloudflare': ['cloudflare'],
                    'cloudfront': ['cloudfront']
                }
                
                for server_name, patterns in server_patterns.items():
                    if any(pattern in server for pattern in patterns) or any(pattern in server_headers for pattern in patterns):
                        technologies.append(server_name.title())
                        results['server_detection'][server_name] = {
                            'detected': True,
                            'version': self._extract_version(server),
                            'header': server
                        }
                        print(f"   ✅ Server detected: {server_name}")
                
                # Framework detection
                print("   🔧 Framework Detection...")
                results['techniques_used'].append('Framework Detection')
                
                x_powered_by = response.headers.get('X-Powered-By', '').lower()
                framework_patterns = {
                    'php': ['php', 'x-powered-by'],
                    'asp.net': ['asp.net', 'aspnet'],
                    'express.js': ['express', 'expressjs'],
                    'django': ['django'],
                    'flask': ['flask'],
                    'rails': ['rails', 'ruby'],
                    'laravel': ['laravel'],
                    'symfony': ['symfony'],
                    'spring': ['spring'],
                    'angular': ['angular']
                }
                
                for framework, patterns in framework_patterns.items():
                    if any(pattern in x_powered_by for pattern in patterns) or any(pattern in content for pattern in patterns):
                        technologies.append(framework.title())
                        results['framework_detection'][framework] = {
                            'detected': True,
                            'version': self._extract_version(x_powered_by),
                            'source': 'header' if any(pattern in x_powered_by for pattern in patterns) else 'content'
                        }
                        print(f"   ✅ Framework detected: {framework}")
                
                # CMS detection
                print("   📝 CMS Detection...")
                results['techniques_used'].append('CMS Detection')
                
                cms_patterns = {
                    'wordpress': ['wordpress', '/wp-content/', '/wp-includes/', 'wp-json', 'xmlrpc.php'],
                    'drupal': ['drupal', '/sites/default/', 'drupal.js', 'drupal.css'],
                    'joomla': ['joomla', '/media/system/', '/templates/', 'joomla.js'],
                    'magento': ['magento', '/skin/frontend/', '/js/magento/'],
                    'prestashop': ['prestashop', '/themes/', '/modules/'],
                    'shopify': ['shopify', 'shopify.com', 'cdn.shopify.com'],
                    'squarespace': ['squarespace', 'squarespace.com'],
                    'wix': ['wix', 'wix.com', 'wixstatic.com'],
                    'ghost': ['ghost', '/ghost/', 'ghost.js'],
                    'hugo': ['hugo', 'hugo.js']
                }
                
                for cms, patterns in cms_patterns.items():
                    if any(pattern in content for pattern in patterns):
                        technologies.append(cms.title())
                        results['cms_detection'][cms] = {
                            'detected': True,
                            'patterns_found': [p for p in patterns if p in content],
                            'confidence': len([p for p in patterns if p in content]) / len(patterns)
                        }
                        print(f"   ✅ CMS detected: {cms}")
                
                # Frontend frameworks
                print("   🎨 Frontend Framework Detection...")
                results['techniques_used'].append('Frontend Framework Detection')
                
                frontend_patterns = {
                    'react': ['react', 'reactjs', 'react-dom', 'react.js', 'react.min.js'],
                    'angular': ['angular', 'angularjs', 'ng-app', 'angular.js'],
                    'vue.js': ['vue', 'vuejs', 'vue.js', 'vue.min.js'],
                    'jquery': ['jquery', 'jquery.js', 'jquery.min.js'],
                    'bootstrap': ['bootstrap', 'bootstrap.js', 'bootstrap.css'],
                    'foundation': ['foundation', 'foundation.js'],
                    'materialize': ['materialize', 'materialize.js'],
                    'bulma': ['bulma', 'bulma.css'],
                    'tailwind': ['tailwind', 'tailwindcss'],
                    'sass': ['sass', 'scss', 'sass.js'],
                    'less': ['less', 'less.js'],
                    'typescript': ['typescript', 'ts.js']
                }
                
                for framework, patterns in frontend_patterns.items():
                    if any(pattern in content for pattern in patterns):
                        technologies.append(framework.title())
                        print(f"   ✅ Frontend framework detected: {framework}")
                
                # JavaScript analysis
                print("   📜 JavaScript Analysis...")
                results['techniques_used'].append('JavaScript Analysis')
                
                js_patterns = re.findall(r'<script[^>]*src=["\']([^"\']*)["\'][^>]*>', response.text, re.IGNORECASE)
                results['javascript_analysis'] = {
                    'scripts_found': len(js_patterns),
                    'external_scripts': [script for script in js_patterns if not script.startswith('/')],
                    'inline_scripts': len(re.findall(r'<script[^>]*>(.*?)</script>', response.text, re.DOTALL | re.IGNORECASE))
                }
                
                # CSS analysis
                print("   🎨 CSS Analysis...")
                results['techniques_used'].append('CSS Analysis')
                
                css_patterns = re.findall(r'<link[^>]*href=["\']([^"\']*\.css[^"\']*)["\'][^>]*>', response.text, re.IGNORECASE)
                results['css_analysis'] = {
                    'stylesheets_found': len(css_patterns),
                    'external_stylesheets': [css for css in css_patterns if not css.startswith('/')],
                    'inline_styles': len(re.findall(r'<style[^>]*>(.*?)</style>', response.text, re.DOTALL | re.IGNORECASE))
                }
                
                results['technologies'] = list(set(technologies))
                results['content_analysis'] = {
                    'title': self._extract_title(response.text),
                    'technologies_found': len(technologies),
                    'content_length': len(response.content),
                    'meta_tags': len(re.findall(r'<meta[^>]*>', response.text, re.IGNORECASE)),
                    'images': len(re.findall(r'<img[^>]*>', response.text, re.IGNORECASE)),
                    'links': len(re.findall(r'<a[^>]*>', response.text, re.IGNORECASE))
                }
                
                print(f"   ✅ Technologies found: {results['technologies']}")
                
            except Exception as e:
                results['errors'].append(f"Main page analysis failed: {str(e)}")
            
            # Technique 2: Robots.txt Analysis
            print("   🤖 Robots.txt Analysis...")
            results['techniques_used'].append('Robots.txt Analysis')
            
            try:
                robots_response = requests.get(f"https://{target}/robots.txt", headers=self.headers, timeout=5)
                if robots_response.status_code == 200:
                    results['content_analysis']['robots_txt'] = {
                        'found': True,
                        'content': robots_response.text[:500],
                        'disallowed_paths': re.findall(r'Disallow:\s*(.*)', robots_response.text, re.IGNORECASE),
                        'sitemaps': re.findall(r'Sitemap:\s*(.*)', robots_response.text, re.IGNORECASE)
                    }
                    print(f"   ✅ Robots.txt found with {len(results['content_analysis']['robots_txt']['disallowed_paths'])} disallowed paths")
            except Exception as e:
                results['errors'].append(f"Robots.txt analysis failed: {str(e)}")
            
            # Technique 3: Sitemap Analysis
            print("   🗺️ Sitemap Analysis...")
            results['techniques_used'].append('Sitemap Analysis')
            
            sitemap_urls = [
                f"https://{target}/sitemap.xml",
                f"https://{target}/sitemap_index.xml",
                f"https://{target}/sitemap.xml.gz"
            ]
            
            for sitemap_url in sitemap_urls:
                try:
                    sitemap_response = requests.get(sitemap_url, headers=self.headers, timeout=5)
                    if sitemap_response.status_code == 200:
                        results['content_analysis']['sitemap'] = {
                            'found': True,
                            'url': sitemap_url,
                            'content_length': len(sitemap_response.content)
                        }
                        print(f"   ✅ Sitemap found: {sitemap_url}")
                        break
                except:
                    pass
            
            # Technique 4: Wappalyzer Integration (if available)
            print("   🔍 Wappalyzer Integration...")
            results['techniques_used'].append('Wappalyzer Integration')
            
            if self._is_wappalyzer_available():
                try:
                    wappalyzer_results = self._run_wappalyzer(target)
                    if wappalyzer_results:
                        results['wappalyzer_results'] = wappalyzer_results
                        print(f"   ✅ Wappalyzer analysis completed")
                except Exception as e:
                    results['errors'].append(f"Wappalyzer analysis failed: {str(e)}")
            else:
                print("   ℹ️ Wappalyzer not available, skipping")
            
            # Technique 5: Whatweb Integration (if available)
            print("   🔍 Whatweb Integration...")
            results['techniques_used'].append('Whatweb Integration')
            
            if self._is_whatweb_available():
                try:
                    whatweb_results = self._run_whatweb(target)
                    if whatweb_results:
                        results['whatweb_results'] = whatweb_results
                        print(f"   ✅ Whatweb analysis completed")
                except Exception as e:
                    results['errors'].append(f"Whatweb analysis failed: {str(e)}")
            else:
                print("   ℹ️ Whatweb not available, skipping")
            
            results['end_time'] = datetime.now().isoformat()
            results['status'] = 'completed'
            results['summary'] = f"Found {len(results['technologies'])} technologies using {len(results['techniques_used'])} advanced techniques"
            
            print(f"   ✅ Phase 4 completed: {results['summary']}")
            return results
            
        except Exception as e:
            results['errors'].append(f"Phase 4 failed: {str(e)}")
            results['status'] = 'error'
            print(f"   ❌ Phase 4 failed: {e}")
            return results
    
    def _extract_version(self, text: str) -> str:
        """Extract version from text"""
        version_pattern = r'(\d+\.\d+(?:\.\d+)?(?:\.\d+)?)'
        match = re.search(version_pattern, text)
        return match.group(1) if match else 'Unknown'
    
    def _extract_title(self, html_content: str) -> str:
        """Extract page title from HTML content"""
        try:
            title_match = re.search(r'<title[^>]*>(.*?)</title>', html_content, re.IGNORECASE | re.DOTALL)
            if title_match:
                return title_match.group(1).strip()
        except:
            pass
        return 'No title found'
    
    def _is_wappalyzer_available(self) -> bool:
        """Check if wappalyzer is available"""
        try:
            subprocess.run(['wappalyzer', '--version'], capture_output=True, timeout=5)
            return True
        except:
            return False
    
    def _run_wappalyzer(self, target: str) -> Dict[str, Any]:
        """Run wappalyzer if available"""
        try:
            cmd = ['wappalyzer', target]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0:
                return {
                    'stdout': result.stdout,
                    'stderr': result.stderr,
                    'success': True
                }
        except:
            pass
        return None
    
    def _is_whatweb_available(self) -> bool:
        """Check if whatweb is available"""
        try:
            subprocess.run(['whatweb', '--version'], capture_output=True, timeout=5)
            return True
        except:
            return False
    
    def _run_whatweb(self, target: str) -> Dict[str, Any]:
        """Run whatweb if available"""
        try:
            cmd = ['whatweb', '--no-errors', '--quiet', target]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
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
    phase = Phase4TechnologyDetection()
    result = phase.run_phase("example.com")
    print(json.dumps(result, indent=2))