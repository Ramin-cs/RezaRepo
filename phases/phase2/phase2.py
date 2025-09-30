"""
فاز 2: Subdomain Discovery (Active & Passive)
"""

import asyncio
import aiohttp
import socket
import dns.resolver
import subprocess
import json
from typing import Dict, List, Any, Optional, Set
from datetime import datetime
import logging
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor
import random
import re

from ..phase_manager import BasePhase


class Phase2(BasePhase):
    """فاز 2: Subdomain Discovery"""
    
    name = "Subdomain Discovery"
    description = "کشف ساب‌دامین‌ها به روش‌های active و passive"
    dependencies = [1]  # وابسته به فاز 1
    parallel_safe = True
    
    def __init__(self, config, database, api_manager):
        super().__init__(config, database, api_manager)
        self.executor = ThreadPoolExecutor(max_workers=50)
        self.discovered_subdomains = set()
        self.validated_subdomains = set()
        self.failed_subdomains = set()
        
        # منابع passive discovery
        self.passive_sources = [
            'virustotal', 'censys', 'securitytrails', 'github', 
            'wayback_machine', 'common_crawl', 'crt_sh', 'dnsdumpster',
            'hunter', 'shodan', 'passivetotal', 'threatcrowd'
        ]
        
        # ابزارهای active discovery
        self.active_tools = [
            'sublist3r', 'amass', 'assetfinder', 'subfinder', 
            'findomain', 'chaos', 'hakrawler'
        ]
    
    async def run(self, target: str, **kwargs) -> Dict[str, Any]:
        """اجرای فاز 2"""
        try:
            self.logger.info(f"شروع فاز 2 برای {target}")
            
            # دریافت نتایج فاز 1
            phase1_results = await self.get_previous_results(target, 1)
            
            results = {
                'target': target,
                'start_time': datetime.now().isoformat(),
                'passive_discovery': {},
                'active_discovery': {},
                'subdomains': [],
                'validated_subdomains': [],
                'live_subdomains': [],
                'statistics': {},
                'validation_results': {},
                'httpx_results': {},
                'recommendations': []
            }
            
            # 1. Passive Discovery
            self.logger.info("شروع Passive Discovery")
            passive_results = await self.passive_discovery(target)
            results['passive_discovery'] = passive_results
            
            # 2. Active Discovery
            self.logger.info("شروع Active Discovery")
            active_results = await self.active_discovery(target)
            results['active_discovery'] = active_results
            
            # 3. ترکیب نتایج
            all_subdomains = self.combine_discovery_results(passive_results, active_results)
            results['subdomains'] = list(all_subdomains)
            
            # 4. Validation
            self.logger.info("شروع Validation")
            validation_results = await self.validate_subdomains(list(all_subdomains))
            results['validated_subdomains'] = validation_results['valid']
            results['validation_results'] = validation_results
            
            # 5. Live Host Detection
            self.logger.info("شروع Live Host Detection")
            live_results = await self.detect_live_hosts(validation_results['valid'])
            results['live_subdomains'] = live_results['live']
            results['httpx_results'] = live_results
            
            # 6. آمارگیری
            results['statistics'] = self.calculate_statistics(results)
            
            # 7. تولید توصیه‌ها
            results['recommendations'] = await self.generate_recommendations(results)
            
            results['end_time'] = datetime.now().isoformat()
            results['success'] = True
            
            # ذخیره نتایج در دیتابیس
            await self.save_subdomains_to_db(target, results)
            
            self.logger.info(f"فاز 2 برای {target} تکمیل شد")
            return results
            
        except Exception as e:
            self.logger.error(f"خطا در فاز 2: {e}")
            raise
    
    async def passive_discovery(self, target: str) -> Dict[str, Any]:
        """Passive Subdomain Discovery"""
        try:
            passive_results = {
                'virustotal': [],
                'censys': [],
                'securitytrails': [],
                'github': [],
                'wayback_machine': [],
                'common_crawl': [],
                'crt_sh': [],
                'dnsdumpster': [],
                'hunter': [],
                'shodan': [],
                'total_found': 0
            }
            
            # ایجاد tasks برای منابع مختلف
            tasks = []
            
            # VirusTotal
            if self.api_manager.has_api_key('virustotal'):
                tasks.append(self.discover_from_virustotal(target))
            else:
                passive_results['virustotal'] = []
            
            # Censys
            if self.api_manager.has_api_key('censys'):
                tasks.append(self.discover_from_censys(target))
            else:
                passive_results['censys'] = []
            
            # SecurityTrails
            if self.api_manager.has_api_key('securitytrails'):
                tasks.append(self.discover_from_securitytrails(target))
            else:
                passive_results['securitytrails'] = []
            
            # GitHub
            if self.api_manager.has_api_key('github'):
                tasks.append(self.discover_from_github(target))
            else:
                passive_results['github'] = []
            
            # Wayback Machine
            tasks.append(self.discover_from_wayback_machine(target))
            
            # Common Crawl
            tasks.append(self.discover_from_common_crawl(target))
            
            # crt.sh
            tasks.append(self.discover_from_crt_sh(target))
            
            # DNSDumpster
            tasks.append(self.discover_from_dnsdumpster(target))
            
            # Hunter
            if self.api_manager.has_api_key('hunter'):
                tasks.append(self.discover_from_hunter(target))
            else:
                passive_results['hunter'] = []
            
            # Shodan
            if self.api_manager.has_api_key('shodan'):
                tasks.append(self.discover_from_shodan(target))
            else:
                passive_results['shodan'] = []
            
            # اجرای موازی
            if tasks:
                results = await asyncio.gather(*tasks, return_exceptions=True)
                
                for i, result in enumerate(results):
                    if isinstance(result, Exception):
                        self.logger.error(f"خطا در passive discovery: {result}")
                    else:
                        source = list(passive_results.keys())[i]
                        passive_results[source] = result
                        passive_results['total_found'] += len(result)
            
            self.logger.info(f"Passive discovery: {passive_results['total_found']} ساب‌دامین پیدا شد")
            return passive_results
            
        except Exception as e:
            self.logger.error(f"خطا در passive discovery: {e}")
            return {}
    
    async def discover_from_virustotal(self, target: str) -> List[str]:
        """کشف ساب‌دامین از VirusTotal"""
        try:
            subdomains = set()
            
            # جستجو در VirusTotal
            response = await self.api_manager.virustotal_domain_report(target)
            if response.success and response.data:
                data = response.data
                
                # استخراج ساب‌دامین‌ها از subdomains
                if 'subdomains' in data:
                    for subdomain in data['subdomains']:
                        if subdomain.endswith(f'.{target}'):
                            subdomains.add(subdomain)
                
                # استخراج از resolutions
                if 'resolutions' in data:
                    for resolution in data['resolutions']:
                        if 'hostname' in resolution:
                            hostname = resolution['hostname']
                            if hostname.endswith(f'.{target}'):
                                subdomains.add(hostname)
            
            return list(subdomains)
            
        except Exception as e:
            self.logger.error(f"خطا در VirusTotal discovery: {e}")
            return []
    
    async def discover_from_censys(self, target: str) -> List[str]:
        """کشف ساب‌دامین از Censys"""
        try:
            subdomains = set()
            
            # جستجو در Censys
            query = f"parsed.names:{target}"
            response = await self.api_manager.censys_search(query, 'websites')
            
            if response.success and response.data:
                data = response.data
                
                # استخراج از results
                if 'results' in data:
                    for result in data['results']:
                        if 'parsed' in result and 'names' in result['parsed']:
                            for name in result['parsed']['names']:
                                if name.endswith(f'.{target}'):
                                    subdomains.add(name)
            
            return list(subdomains)
            
        except Exception as e:
            self.logger.error(f"خطا در Censys discovery: {e}")
            return []
    
    async def discover_from_securitytrails(self, target: str) -> List[str]:
        """کشف ساب‌دامین از SecurityTrails"""
        try:
            subdomains = set()
            
            response = await self.api_manager.securitytrails_subdomains(target)
            if response.success and response.data:
                data = response.data
                
                # استخراج از subdomains
                if 'subdomains' in data:
                    for subdomain in data['subdomains']:
                        full_subdomain = f"{subdomain}.{target}"
                        subdomains.add(full_subdomain)
            
            return list(subdomains)
            
        except Exception as e:
            self.logger.error(f"خطا در SecurityTrails discovery: {e}")
            return []
    
    async def discover_from_github(self, target: str) -> List[str]:
        """کشف ساب‌دامین از GitHub"""
        try:
            subdomains = set()
            
            # جستجو در GitHub
            queries = [
                f'"{target}"',
                f'"{target}" subdomain',
                f'"{target}" dns',
                f'site:github.com "{target}"'
            ]
            
            for query in queries:
                response = await self.api_manager.github_search(query)
                if response.success and response.data:
                    data = response.data
                    
                    # استخراج از items
                    if 'items' in data:
                        for item in data['items']:
                            # استخراج ساب‌دامین از content
                            content = item.get('content', '')
                            subdomain_matches = re.findall(rf'[a-zA-Z0-9-]+\.{re.escape(target)}', content)
                            subdomains.update(subdomain_matches)
            
            return list(subdomains)
            
        except Exception as e:
            self.logger.error(f"خطا در GitHub discovery: {e}")
            return []
    
    async def discover_from_wayback_machine(self, target: str) -> List[str]:
        """کشف ساب‌دامین از Wayback Machine"""
        try:
            subdomains = set()
            
            response = await self.api_manager.wayback_machine_urls(target)
            if response.success and response.data:
                data = response.data
                
                # استخراج ساب‌دامین‌ها از URLs
                for url_entry in data:
                    if len(url_entry) >= 3:
                        url = url_entry[2]
                        parsed_url = urlparse(url)
                        hostname = parsed_url.hostname
                        
                        if hostname and hostname.endswith(f'.{target}'):
                            subdomains.add(hostname)
            
            return list(subdomains)
            
        except Exception as e:
            self.logger.error(f"خطا در Wayback Machine discovery: {e}")
            return []
    
    async def discover_from_common_crawl(self, target: str) -> List[str]:
        """کشف ساب‌دامین از Common Crawl"""
        try:
            subdomains = set()
            
            # Common Crawl API
            url = "https://index.commoncrawl.org/CC-MAIN-2023-23-index"
            params = {
                'url': f'*.{target}',
                'output': 'json'
            }
            
            response = await self.api_manager.make_request('common_crawl', url, params=params)
            if response.success and response.data:
                # پردازش نتایج Common Crawl
                lines = response.data.strip().split('\n')
                for line in lines:
                    try:
                        data = json.loads(line)
                        url = data.get('url', '')
                        parsed_url = urlparse(url)
                        hostname = parsed_url.hostname
                        
                        if hostname and hostname.endswith(f'.{target}'):
                            subdomains.add(hostname)
                    except json.JSONDecodeError:
                        continue
            
            return list(subdomains)
            
        except Exception as e:
            self.logger.error(f"خطا در Common Crawl discovery: {e}")
            return []
    
    async def discover_from_crt_sh(self, target: str) -> List[str]:
        """کشف ساب‌دامین از crt.sh"""
        try:
            subdomains = set()
            
            response = await self.api_manager.crt_sh_certificates(target)
            if response.success and response.data:
                for cert in response.data:
                    # استخراج از common_name
                    common_name = cert.get('common_name', '')
                    if common_name and common_name.endswith(f'.{target}'):
                        subdomains.add(common_name)
                    
                    # استخراج از name_value
                    name_value = cert.get('name_value', '')
                    if name_value:
                        for name in name_value.split('\n'):
                            name = name.strip()
                            if name and name.endswith(f'.{target}'):
                                subdomains.add(name)
            
            return list(subdomains)
            
        except Exception as e:
            self.logger.error(f"خطا در crt.sh discovery: {e}")
            return []
    
    async def discover_from_dnsdumpster(self, target: str) -> List[str]:
        """کشف ساب‌دامین از DNSDumpster"""
        try:
            subdomains = set()
            
            response = await self.api_manager.dnsdumpster_subdomains(target)
            if response.success and response.data:
                # پردازش HTML response از DNSDumpster
                html_content = response.data
                
                # استخراج ساب‌دامین‌ها با regex
                subdomain_pattern = rf'[a-zA-Z0-9-]+\.{re.escape(target)}'
                matches = re.findall(subdomain_pattern, html_content)
                subdomains.update(matches)
            
            return list(subdomains)
            
        except Exception as e:
            self.logger.error(f"خطا در DNSDumpster discovery: {e}")
            return []
    
    async def discover_from_hunter(self, target: str) -> List[str]:
        """کشف ساب‌دامین از Hunter"""
        try:
            subdomains = set()
            
            response = await self.api_manager.hunter_domain_search(target)
            if response.success and response.data:
                data = response.data
                
                # استخراج از emails
                if 'emails' in data:
                    for email in data['emails']:
                        domain = email.get('domain', '')
                        if domain.endswith(f'.{target}'):
                            subdomains.add(domain)
            
            return list(subdomains)
            
        except Exception as e:
            self.logger.error(f"خطا در Hunter discovery: {e}")
            return []
    
    async def discover_from_shodan(self, target: str) -> List[str]:
        """کشف ساب‌دامین از Shodan"""
        try:
            subdomains = set()
            
            response = await self.api_manager.shodan_search(f"hostname:{target}")
            if response.success and response.data:
                data = response.data
                
                # استخراج از matches
                if 'matches' in data:
                    for match in data['matches']:
                        hostname = match.get('hostnames', [])
                        for host in hostname:
                            if host.endswith(f'.{target}'):
                                subdomains.add(host)
            
            return list(subdomains)
            
        except Exception as e:
            self.logger.error(f"خطا در Shodan discovery: {e}")
            return []
    
    async def active_discovery(self, target: str) -> Dict[str, Any]:
        """Active Subdomain Discovery"""
        try:
            active_results = {
                'sublist3r': [],
                'amass': [],
                'assetfinder': [],
                'subfinder': [],
                'findomain': [],
                'chaos': [],
                'hakrawler': [],
                'dns_bruteforce': [],
                'total_found': 0
            }
            
            # ایجاد tasks برای ابزارهای مختلف
            tasks = []
            
            # Sublist3r
            tasks.append(self.run_sublist3r(target))
            
            # Amass
            tasks.append(self.run_amass(target))
            
            # Assetfinder
            tasks.append(self.run_assetfinder(target))
            
            # Subfinder
            tasks.append(self.run_subfinder(target))
            
            # Findomain
            tasks.append(self.run_findomain(target))
            
            # Chaos
            if self.api_manager.has_api_key('chaos'):
                tasks.append(self.run_chaos(target))
            else:
                active_results['chaos'] = []
            
            # Hakrawler
            tasks.append(self.run_hakrawler(target))
            
            # DNS Brute Force
            tasks.append(self.dns_bruteforce(target))
            
            # اجرای موازی
            if tasks:
                results = await asyncio.gather(*tasks, return_exceptions=True)
                
                for i, result in enumerate(results):
                    if isinstance(result, Exception):
                        self.logger.error(f"خطا در active discovery: {result}")
                    else:
                        tool_name = list(active_results.keys())[i]
                        active_results[tool_name] = result
                        active_results['total_found'] += len(result)
            
            self.logger.info(f"Active discovery: {active_results['total_found']} ساب‌دامین پیدا شد")
            return active_results
            
        except Exception as e:
            self.logger.error(f"خطا در active discovery: {e}")
            return {}
    
    async def run_sublist3r(self, target: str) -> List[str]:
        """اجرای Sublist3r"""
        try:
            cmd = ['sublist3r', '-d', target, '-o', '/tmp/sublist3r.txt']
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                # خواندن فایل خروجی
                with open('/tmp/sublist3r.txt', 'r') as f:
                    subdomains = [line.strip() for line in f.readlines() if line.strip()]
                return subdomains
            else:
                self.logger.error(f"خطا در Sublist3r: {stderr.decode()}")
                return []
                
        except Exception as e:
            self.logger.error(f"خطا در اجرای Sublist3r: {e}")
            return []
    
    async def run_amass(self, target: str) -> List[str]:
        """اجرای Amass"""
        try:
            cmd = ['amass', 'enum', '-d', target, '-silent']
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                subdomains = stdout.decode().strip().split('\n')
                return [s for s in subdomains if s.strip()]
            else:
                self.logger.error(f"خطا در Amass: {stderr.decode()}")
                return []
                
        except Exception as e:
            self.logger.error(f"خطا در اجرای Amass: {e}")
            return []
    
    async def run_assetfinder(self, target: str) -> List[str]:
        """اجرای Assetfinder"""
        try:
            cmd = ['assetfinder', '-subs-only', target]
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                subdomains = stdout.decode().strip().split('\n')
                return [s for s in subdomains if s.strip()]
            else:
                self.logger.error(f"خطا در Assetfinder: {stderr.decode()}")
                return []
                
        except Exception as e:
            self.logger.error(f"خطا در اجرای Assetfinder: {e}")
            return []
    
    async def run_subfinder(self, target: str) -> List[str]:
        """اجرای Subfinder"""
        try:
            cmd = ['subfinder', '-d', target, '-silent']
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                subdomains = stdout.decode().strip().split('\n')
                return [s for s in subdomains if s.strip()]
            else:
                self.logger.error(f"خطا در Subfinder: {stderr.decode()}")
                return []
                
        except Exception as e:
            self.logger.error(f"خطا در اجرای Subfinder: {e}")
            return []
    
    async def run_findomain(self, target: str) -> List[str]:
        """اجرای Findomain"""
        try:
            cmd = ['findomain', '-t', target, '-q']
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                subdomains = stdout.decode().strip().split('\n')
                return [s for s in subdomains if s.strip()]
            else:
                self.logger.error(f"خطا در Findomain: {stderr.decode()}")
                return []
                
        except Exception as e:
            self.logger.error(f"خطا در اجرای Findomain: {e}")
            return []
    
    async def run_chaos(self, target: str) -> List[str]:
        """اجرای Chaos"""
        try:
            cmd = ['chaos', '-d', target, '-silent']
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                subdomains = stdout.decode().strip().split('\n')
                return [s for s in subdomains if s.strip()]
            else:
                self.logger.error(f"خطا در Chaos: {stderr.decode()}")
                return []
                
        except Exception as e:
            self.logger.error(f"خطا در اجرای Chaos: {e}")
            return []
    
    async def run_hakrawler(self, target: str) -> List[str]:
        """اجرای Hakrawler"""
        try:
            cmd = ['hakrawler', '-url', f'https://{target}', '-subs']
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                urls = stdout.decode().strip().split('\n')
                subdomains = set()
                for url in urls:
                    parsed_url = urlparse(url)
                    hostname = parsed_url.hostname
                    if hostname and hostname.endswith(f'.{target}'):
                        subdomains.add(hostname)
                return list(subdomains)
            else:
                self.logger.error(f"خطا در Hakrawler: {stderr.decode()}")
                return []
                
        except Exception as e:
            self.logger.error(f"خطا در اجرای Hakrawler: {e}")
            return []
    
    async def dns_bruteforce(self, target: str) -> List[str]:
        """DNS Brute Force"""
        try:
            subdomains = set()
            
            # خواندن wordlist
            wordlist_path = self.config.get_wordlist_path('subdomains')
            if not wordlist_path:
                return []
            
            with open(wordlist_path, 'r') as f:
                wordlist = [line.strip() for line in f.readlines() if line.strip()]
            
            # ایجاد tasks برای DNS resolution
            tasks = []
            for word in wordlist[:1000]:  # محدود کردن به 1000 کلمه
                subdomain = f"{word}.{target}"
                tasks.append(self.resolve_subdomain(subdomain))
            
            # اجرای موازی
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for i, result in enumerate(results):
                if isinstance(result, bool) and result:
                    subdomain = f"{wordlist[i]}.{target}"
                    subdomains.add(subdomain)
            
            return list(subdomains)
            
        except Exception as e:
            self.logger.error(f"خطا در DNS brute force: {e}")
            return []
    
    async def resolve_subdomain(self, subdomain: str) -> bool:
        """حل DNS برای ساب‌دامین"""
        try:
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                self.executor,
                socket.gethostbyname_ex,
                subdomain
            )
            return len(result[2]) > 0  # اگر IP پیدا شد
        except Exception:
            return False
    
    def combine_discovery_results(self, passive_results: Dict, active_results: Dict) -> Set[str]:
        """ترکیب نتایج discovery"""
        try:
            all_subdomains = set()
            
            # اضافه کردن نتایج passive
            for source, subdomains in passive_results.items():
                if isinstance(subdomains, list):
                    all_subdomains.update(subdomains)
            
            # اضافه کردن نتایج active
            for tool, subdomains in active_results.items():
                if isinstance(subdomains, list):
                    all_subdomains.update(subdomains)
            
            # حذف تکراری‌ها
            return all_subdomains
            
        except Exception as e:
            self.logger.error(f"خطا در ترکیب نتایج: {e}")
            return set()
    
    async def validate_subdomains(self, subdomains: List[str]) -> Dict[str, Any]:
        """اعتبارسنجی ساب‌دامین‌ها"""
        try:
            validation_results = {
                'valid': [],
                'invalid': [],
                'dns_resolved': [],
                'http_accessible': [],
                'https_accessible': [],
                'statistics': {}
            }
            
            # ایجاد tasks برای validation
            tasks = []
            for subdomain in subdomains:
                tasks.append(self.validate_single_subdomain(subdomain))
            
            # اجرای موازی
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for i, result in enumerate(results):
                if isinstance(result, Exception):
                    validation_results['invalid'].append({
                        'subdomain': subdomains[i],
                        'error': str(result)
                    })
                else:
                    subdomain_info = result
                    if subdomain_info['dns_resolved']:
                        validation_results['valid'].append(subdomain_info)
                        validation_results['dns_resolved'].append(subdomain_info)
                        
                        if subdomain_info['http_status']:
                            validation_results['http_accessible'].append(subdomain_info)
                        
                        if subdomain_info['https_status']:
                            validation_results['https_accessible'].append(subdomain_info)
                    else:
                        validation_results['invalid'].append(subdomain_info)
            
            # آمارگیری
            validation_results['statistics'] = {
                'total': len(subdomains),
                'valid': len(validation_results['valid']),
                'invalid': len(validation_results['invalid']),
                'dns_resolved': len(validation_results['dns_resolved']),
                'http_accessible': len(validation_results['http_accessible']),
                'https_accessible': len(validation_results['https_accessible'])
            }
            
            return validation_results
            
        except Exception as e:
            self.logger.error(f"خطا در validation: {e}")
            return {'valid': [], 'invalid': [], 'statistics': {}}
    
    async def validate_single_subdomain(self, subdomain: str) -> Dict[str, Any]:
        """اعتبارسنجی یک ساب‌دامین"""
        try:
            subdomain_info = {
                'subdomain': subdomain,
                'dns_resolved': False,
                'ip_addresses': [],
                'http_status': None,
                'https_status': None,
                'title': '',
                'server': '',
                'response_time': None
            }
            
            # DNS Resolution
            try:
                loop = asyncio.get_event_loop()
                result = await loop.run_in_executor(
                    self.executor,
                    socket.gethostbyname_ex,
                    subdomain
                )
                subdomain_info['ip_addresses'] = result[2]
                subdomain_info['dns_resolved'] = len(result[2]) > 0
            except Exception:
                pass
            
            if not subdomain_info['dns_resolved']:
                return subdomain_info
            
            # HTTP/HTTPS Test
            try:
                session = await self.api_manager.get_session()
                
                # HTTP Test
                try:
                    async with session.get(f"http://{subdomain}", timeout=aiohttp.ClientTimeout(total=5)) as response:
                        subdomain_info['http_status'] = response.status
                        subdomain_info['title'] = await self.extract_title(await response.text())
                        subdomain_info['server'] = response.headers.get('Server', '')
                except Exception:
                    pass
                
                # HTTPS Test
                try:
                    async with session.get(f"https://{subdomain}", timeout=aiohttp.ClientTimeout(total=5)) as response:
                        subdomain_info['https_status'] = response.status
                        if not subdomain_info['title']:
                            subdomain_info['title'] = await self.extract_title(await response.text())
                        if not subdomain_info['server']:
                            subdomain_info['server'] = response.headers.get('Server', '')
                except Exception:
                    pass
                
            except Exception:
                pass
            
            return subdomain_info
            
        except Exception as e:
            self.logger.error(f"خطا در validation {subdomain}: {e}")
            return {'subdomain': subdomain, 'error': str(e)}
    
    async def extract_title(self, html_content: str) -> str:
        """استخراج title از HTML"""
        try:
            import re
            title_match = re.search(r'<title[^>]*>(.*?)</title>', html_content, re.IGNORECASE | re.DOTALL)
            if title_match:
                title = title_match.group(1).strip()
                # حذف whitespace اضافی
                title = re.sub(r'\s+', ' ', title)
                return title[:100]  # محدود کردن طول
            return ''
        except Exception:
            return ''
    
    async def detect_live_hosts(self, validated_subdomains: List[Dict[str, Any]]) -> Dict[str, Any]:
        """تشخیص live hosts با httpx"""
        try:
            live_results = {
                'live': [],
                'dead': [],
                'httpx_output': [],
                'statistics': {}
            }
            
            # ایجاد لیست URLs برای httpx
            urls = []
            for subdomain_info in validated_subdomains:
                subdomain = subdomain_info['subdomain']
                urls.extend([f"http://{subdomain}", f"https://{subdomain}"])
            
            # اجرای httpx
            httpx_results = await self.run_httpx(urls)
            live_results['httpx_output'] = httpx_results
            
            # پردازش نتایج httpx
            live_subdomains = set()
            for result in httpx_results:
                if result.get('status_code') and result['status_code'] < 400:
                    url = result.get('url', '')
                    parsed_url = urlparse(url)
                    hostname = parsed_url.hostname
                    if hostname:
                        live_subdomains.add(hostname)
            
            # تقسیم ساب‌دامین‌ها به live و dead
            for subdomain_info in validated_subdomains:
                subdomain = subdomain_info['subdomain']
                if subdomain in live_subdomains:
                    live_results['live'].append(subdomain_info)
                else:
                    live_results['dead'].append(subdomain_info)
            
            # آمارگیری
            live_results['statistics'] = {
                'total_validated': len(validated_subdomains),
                'live': len(live_results['live']),
                'dead': len(live_results['dead'])
            }
            
            return live_results
            
        except Exception as e:
            self.logger.error(f"خطا در تشخیص live hosts: {e}")
            return {'live': [], 'dead': [], 'statistics': {}}
    
    async def run_httpx(self, urls: List[str]) -> List[Dict[str, Any]]:
        """اجرای httpx"""
        try:
            # نوشتن URLs در فایل
            with open('/tmp/urls.txt', 'w') as f:
                for url in urls:
                    f.write(f"{url}\n")
            
            # اجرای httpx
            cmd = ['httpx', '-l', '/tmp/urls.txt', '-json', '-silent']
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                results = []
                lines = stdout.decode().strip().split('\n')
                for line in lines:
                    if line.strip():
                        try:
                            result = json.loads(line)
                            results.append(result)
                        except json.JSONDecodeError:
                            continue
                return results
            else:
                self.logger.error(f"خطا در httpx: {stderr.decode()}")
                return []
                
        except Exception as e:
            self.logger.error(f"خطا در اجرای httpx: {e}")
            return []
    
    def calculate_statistics(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """محاسبه آمار"""
        try:
            stats = {
                'total_discovered': len(results['subdomains']),
                'total_validated': len(results['validated_subdomains']),
                'total_live': len(results['live_subdomains']),
                'passive_sources': len([s for s in results['passive_discovery'].values() if isinstance(s, list)]),
                'active_tools': len([t for t in results['active_discovery'].values() if isinstance(t, list)]),
                'discovery_ratio': {
                    'passive': 0,
                    'active': 0
                }
            }
            
            # محاسبه نسبت discovery
            passive_total = results['passive_discovery'].get('total_found', 0)
            active_total = results['active_discovery'].get('total_found', 0)
            
            if passive_total + active_total > 0:
                stats['discovery_ratio']['passive'] = passive_total / (passive_total + active_total) * 100
                stats['discovery_ratio']['active'] = active_total / (passive_total + active_total) * 100
            
            return stats
            
        except Exception as e:
            self.logger.error(f"خطا در محاسبه آمار: {e}")
            return {}
    
    async def save_subdomains_to_db(self, target: str, results: Dict[str, Any]):
        """ذخیره ساب‌دامین‌ها در دیتابیس"""
        try:
            target_id = await self.db.get_target_id(target)
            if not target_id:
                target_id = await self.db.save_target(target)
            
            # ذخیره ساب‌دامین‌های live
            for subdomain_info in results['live_subdomains']:
                await self.db.save_subdomain(
                    target_id=target_id,
                    subdomain=subdomain_info['subdomain'],
                    ip_address=subdomain_info.get('ip_addresses', [None])[0] if subdomain_info.get('ip_addresses') else None,
                    status='alive',
                    http_status=subdomain_info.get('http_status'),
                    https_status=subdomain_info.get('https_status'),
                    title=subdomain_info.get('title'),
                    server=subdomain_info.get('server'),
                    verified=True
                )
            
            self.logger.info(f"تعداد {len(results['live_subdomains'])} ساب‌دامین در دیتابیس ذخیره شد")
            
        except Exception as e:
            self.logger.error(f"خطا در ذخیره ساب‌دامین‌ها: {e}")
    
    async def generate_recommendations(self, results: Dict[str, Any]) -> List[str]:
        """تولید توصیه‌ها"""
        try:
            recommendations = []
            
            # توصیه بر اساس تعداد ساب‌دامین‌ها
            total_discovered = len(results['subdomains'])
            if total_discovered > 100:
                recommendations.append(
                    f"تعداد زیادی ساب‌دامین ({total_discovered}) پیدا شد. "
                    "بررسی امنیتی تمامی آن‌ها توصیه می‌شود."
                )
            
            # توصیه بر اساس live hosts
            live_count = len(results['live_subdomains'])
            if live_count > 50:
                recommendations.append(
                    f"تعداد زیادی live host ({live_count}) پیدا شد. "
                    "تست نفوذ روی آن‌ها ضروری است."
                )
            
            # توصیه بر اساس منابع passive
            passive_sources = len([s for s in results['passive_discovery'].values() if isinstance(s, list) and len(s) > 0])
            if passive_sources < 3:
                recommendations.append(
                    "تعداد کمی منبع passive نتیجه داد. "
                    "استفاده از API keys بیشتر توصیه می‌شود."
                )
            
            # توصیه بر اساس ابزارهای active
            active_tools = len([t for t in results['active_discovery'].values() if isinstance(t, list) and len(t) > 0])
            if active_tools < 3:
                recommendations.append(
                    "تعداد کمی ابزار active نتیجه داد. "
                    "نصب و پیکربندی ابزارهای بیشتر توصیه می‌شود."
                )
            
            return recommendations
            
        except Exception as e:
            self.logger.error(f"خطا در تولید توصیه‌ها: {e}")
            return []
    
    async def cleanup(self):
        """پاکسازی منابع"""
        try:
            self.executor.shutdown(wait=True)
            self.logger.info("فاز 2 پاکسازی شد")
        except Exception as e:
            self.logger.error(f"خطا در پاکسازی فاز 2: {e}")