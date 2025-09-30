"""
فاز 1: Real IP extraction و CDN bypass
"""

import asyncio
import socket
import dns.resolver
import requests
import aiohttp
from typing import Dict, List, Any, Optional
from datetime import datetime
import logging
from urllib.parse import urlparse
import hashlib
import json
import time
import random
from concurrent.futures import ThreadPoolExecutor

from ..phase_manager import BasePhase


class Phase1(BasePhase):
    """فاز 1: Real IP extraction و CDN bypass"""
    
    name = "Real IP Extraction & CDN Bypass"
    description = "استخراج IP واقعی و بایپس CDN با روش‌های مختلف"
    dependencies = []
    parallel_safe = True
    
    def __init__(self, config, database, api_manager):
        super().__init__(config, database, api_manager)
        self.cdn_providers = [
            'cloudflare', 'cloudfront', 'akamai', 'maxcdn', 'incapsula',
            'sucuri', 'keycdn', 'bunnycdn', 'fastly', 'stackpath'
        ]
        self.executor = ThreadPoolExecutor(max_workers=20)
    
    async def run(self, target: str, **kwargs) -> Dict[str, Any]:
        """اجرای فاز 1"""
        try:
            self.logger.info(f"شروع فاز 1 برای {target}")
            
            # اعتبارسنجی هدف
            if not await self.validate_target(target):
                raise ValueError(f"هدف نامعتبر: {target}")
            
            results = {
                'target': target,
                'start_time': datetime.now().isoformat(),
                'real_ips': [],
                'cdn_detected': False,
                'cdn_provider': None,
                'bypass_methods': [],
                'dns_history': [],
                'ssl_certificates': [],
                'favicon_hash': None,
                'http_headers_analysis': {},
                'subdomain_old_records': [],
                'ip_differences': {},
                'recommendations': []
            }
            
            # ذخیره هدف در دیتابیس
            target_id = await self.db.save_target(target)
            results['target_id'] = target_id
            
            # 1. تشخیص CDN
            cdn_info = await self.detect_cdn(target)
            results['cdn_detected'] = cdn_info['detected']
            results['cdn_provider'] = cdn_info['provider']
            
            # 2. استخراج IP واقعی
            real_ips = await self.extract_real_ips(target)
            results['real_ips'] = real_ips
            
            # 3. DNS History
            dns_history = await self.get_dns_history(target)
            results['dns_history'] = dns_history
            
            # 4. SSL Certificate Analysis
            ssl_certs = await self.analyze_ssl_certificates(target)
            results['ssl_certificates'] = ssl_certs
            
            # 5. Favicon Hashing
            favicon_hash = await self.get_favicon_hash(target)
            results['favicon_hash'] = favicon_hash
            
            # 6. HTTP Headers Analysis
            headers_analysis = await self.analyze_http_headers(target)
            results['http_headers_analysis'] = headers_analysis
            
            # 7. Subdomain Old Records
            old_records = await self.get_old_subdomain_records(target)
            results['subdomain_old_records'] = old_records
            
            # 8. IP Differences Analysis
            ip_differences = await self.analyze_ip_differences(target)
            results['ip_differences'] = ip_differences
            
            # 9. Bypass Methods
            bypass_methods = await self.get_bypass_methods(target, results)
            results['bypass_methods'] = bypass_methods
            
            # 10. تولید توصیه‌ها
            recommendations = await self.generate_recommendations(results)
            results['recommendations'] = recommendations
            
            results['end_time'] = datetime.now().isoformat()
            results['success'] = True
            
            # ذخیره نتایج
            await self.save_results(target, results)
            
            self.logger.info(f"فاز 1 برای {target} تکمیل شد")
            return results
            
        except Exception as e:
            self.logger.error(f"خطا در فاز 1: {e}")
            raise
    
    async def detect_cdn(self, target: str) -> Dict[str, Any]:
        """تشخیص CDN"""
        try:
            self.logger.info(f"تشخیص CDN برای {target}")
            
            cdn_info = {
                'detected': False,
                'provider': None,
                'confidence': 0.0,
                'indicators': []
            }
            
            # بررسی headers
            headers = await self.get_http_headers(target)
            
            # بررسی server header
            server_header = headers.get('server', '').lower()
            cf_ray = headers.get('cf-ray', '')
            x_cache = headers.get('x-cache', '').lower()
            
            # Cloudflare
            if 'cloudflare' in server_header or cf_ray or 'cloudflare' in x_cache:
                cdn_info['detected'] = True
                cdn_info['provider'] = 'Cloudflare'
                cdn_info['confidence'] = 0.9
                cdn_info['indicators'].append('Cloudflare headers detected')
            
            # CloudFront
            elif 'cloudfront' in server_header or 'cloudfront' in x_cache:
                cdn_info['detected'] = True
                cdn_info['provider'] = 'CloudFront'
                cdn_info['confidence'] = 0.9
                cdn_info['indicators'].append('CloudFront headers detected')
            
            # بررسی سایر CDN ها
            for cdn in self.cdn_providers:
                if cdn in server_header or cdn in x_cache:
                    cdn_info['detected'] = True
                    cdn_info['provider'] = cdn.title()
                    cdn_info['confidence'] = 0.8
                    cdn_info['indicators'].append(f'{cdn} headers detected')
                    break
            
            # بررسی IP ranges
            ip_ranges = await self.check_cdn_ip_ranges(target)
            if ip_ranges:
                cdn_info['detected'] = True
                cdn_info['provider'] = ip_ranges[0]
                cdn_info['confidence'] = 0.7
                cdn_info['indicators'].append(f'CDN IP range detected: {ip_ranges[0]}')
            
            self.logger.info(f"CDN detection result: {cdn_info}")
            return cdn_info
            
        except Exception as e:
            self.logger.error(f"خطا در تشخیص CDN: {e}")
            return {'detected': False, 'provider': None, 'confidence': 0.0, 'indicators': []}
    
    async def extract_real_ips(self, target: str) -> List[Dict[str, Any]]:
        """استخراج IP واقعی"""
        try:
            self.logger.info(f"استخراج IP واقعی برای {target}")
            
            real_ips = []
            
            # 1. DNS Resolution
            dns_ips = await self.resolve_domain(target)
            for ip in dns_ips:
                real_ips.append({
                    'ip': ip,
                    'source': 'dns_resolution',
                    'method': 'standard_dns',
                    'confidence': 0.5
                })
            
            # 2. DNS over HTTPS
            doh_ips = await self.resolve_doh(target)
            for ip in doh_ips:
                if not any(r['ip'] == ip for r in real_ips):
                    real_ips.append({
                        'ip': ip,
                        'source': 'dns_over_https',
                        'method': 'doh',
                        'confidence': 0.6
                    })
            
            # 3. DNS over TLS
            dot_ips = await self.resolve_dot(target)
            for ip in dot_ips:
                if not any(r['ip'] == ip for r in real_ips):
                    real_ips.append({
                        'ip': ip,
                        'source': 'dns_over_tls',
                        'method': 'dot',
                        'confidence': 0.7
                    })
            
            # 4. Historical DNS
            historical_ips = await self.get_historical_dns(target)
            for ip in historical_ips:
                if not any(r['ip'] == ip for r in real_ips):
                    real_ips.append({
                        'ip': ip,
                        'source': 'historical_dns',
                        'method': 'dns_history',
                        'confidence': 0.8
                    })
            
            # 5. Certificate Transparency
            cert_ips = await self.get_certificate_ips(target)
            for ip in cert_ips:
                if not any(r['ip'] == ip for r in real_ips):
                    real_ips.append({
                        'ip': ip,
                        'source': 'certificate_transparency',
                        'method': 'ct_logs',
                        'confidence': 0.9
                    })
            
            # 6. Shodan Search
            if self.api_manager.has_api_key('shodan'):
                shodan_ips = await self.get_shodan_ips(target)
                for ip in shodan_ips:
                    if not any(r['ip'] == ip for r in real_ips):
                        real_ips.append({
                            'ip': ip,
                            'source': 'shodan',
                            'method': 'shodan_search',
                            'confidence': 0.9
                        })
            
            # حذف IP های تکراری و مرتب‌سازی بر اساس confidence
            unique_ips = {}
            for ip_info in real_ips:
                ip = ip_info['ip']
                if ip not in unique_ips or ip_info['confidence'] > unique_ips[ip]['confidence']:
                    unique_ips[ip] = ip_info
            
            real_ips = sorted(unique_ips.values(), key=lambda x: x['confidence'], reverse=True)
            
            self.logger.info(f"تعداد {len(real_ips)} IP واقعی پیدا شد")
            return real_ips
            
        except Exception as e:
            self.logger.error(f"خطا در استخراج IP واقعی: {e}")
            return []
    
    async def resolve_domain(self, domain: str) -> List[str]:
        """حل DNS استاندارد"""
        try:
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                self.executor,
                socket.gethostbyname_ex,
                domain
            )
            return result[2]  # لیست IP ها
        except Exception as e:
            self.logger.error(f"خطا در حل DNS {domain}: {e}")
            return []
    
    async def resolve_doh(self, domain: str) -> List[str]:
        """حل DNS over HTTPS"""
        try:
            doh_servers = [
                'https://1.1.1.1/dns-query',
                'https://1.0.0.1/dns-query',
                'https://8.8.8.8/dns-query',
                'https://8.8.4.4/dns-query'
            ]
            
            ips = []
            for doh_server in doh_servers:
                try:
                    params = {
                        'name': domain,
                        'type': 'A'
                    }
                    
                    response = await self.api_manager.make_request(
                        'default',
                        doh_server,
                        params=params,
                        headers={'Accept': 'application/dns-json'}
                    )
                    
                    if response.success and 'Answer' in response.data:
                        for answer in response.data['Answer']:
                            if answer['type'] == 1:  # A record
                                ips.append(answer['data'])
                
                except Exception:
                    continue
            
            return list(set(ips))
            
        except Exception as e:
            self.logger.error(f"خطا در DoH {domain}: {e}")
            return []
    
    async def resolve_dot(self, domain: str) -> List[str]:
        """حل DNS over TLS"""
        try:
            # استفاده از dnspython برای DoT
            resolver = dns.resolver.Resolver()
            resolver.nameservers = ['1.1.1.1', '1.0.0.1']
            
            ips = []
            try:
                result = resolver.resolve(domain, 'A')
                for rdata in result:
                    ips.append(str(rdata))
            except Exception:
                pass
            
            return ips
            
        except Exception as e:
            self.logger.error(f"خطا در DoT {domain}: {e}")
            return []
    
    async def get_historical_dns(self, domain: str) -> List[str]:
        """دریافت DNS تاریخی"""
        try:
            historical_ips = []
            
            # SecurityTrails
            if self.api_manager.has_api_key('securitytrails'):
                response = await self.api_manager.securitytrails_domain_history(domain)
                if response.success and 'dns_records' in response.data:
                    for record in response.data['dns_records']:
                        if record.get('type') == 'A':
                            historical_ips.append(record['value'])
            
            # PassiveTotal (در صورت داشتن API key)
            # TODO: اضافه کردن PassiveTotal
            
            return list(set(historical_ips))
            
        except Exception as e:
            self.logger.error(f"خطا در دریافت DNS تاریخی: {e}")
            return []
    
    async def get_certificate_ips(self, domain: str) -> List[str]:
        """دریافت IP از Certificate Transparency"""
        try:
            # دریافت گواهینامه‌ها از crt.sh
            response = await self.api_manager.crt_sh_certificates(domain)
            if not response.success:
                return []
            
            ips = []
            for cert in response.data:
                # استخراج IP از common_name و name_value
                for field in ['common_name', 'name_value']:
                    value = cert.get(field, '')
                    # بررسی IP در فیلد
                    import re
                    ip_matches = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', value)
                    ips.extend(ip_matches)
            
            return list(set(ips))
            
        except Exception as e:
            self.logger.error(f"خطا در دریافت IP از گواهینامه‌ها: {e}")
            return []
    
    async def get_shodan_ips(self, domain: str) -> List[str]:
        """دریافت IP از Shodan"""
        try:
            ips = []
            
            # جستجو در Shodan
            response = await self.api_manager.shodan_search(f"hostname:{domain}")
            if response.success and 'matches' in response.data:
                for match in response.data['matches']:
                    if 'ip' in match:
                        ips.append(match['ip'])
            
            return list(set(ips))
            
        except Exception as e:
            self.logger.error(f"خطا در دریافت IP از Shodan: {e}")
            return []
    
    async def get_dns_history(self, target: str) -> List[Dict[str, Any]]:
        """دریافت تاریخچه DNS"""
        try:
            dns_history = []
            
            # SecurityTrails
            if self.api_manager.has_api_key('securitytrails'):
                response = await self.api_manager.securitytrails_domain_history(target)
                if response.success:
                    dns_history.append({
                        'source': 'securitytrails',
                        'data': response.data
                    })
            
            # PassiveTotal
            # TODO: اضافه کردن PassiveTotal
            
            return dns_history
            
        except Exception as e:
            self.logger.error(f"خطا در دریافت تاریخچه DNS: {e}")
            return []
    
    async def analyze_ssl_certificates(self, target: str) -> List[Dict[str, Any]]:
        """تحلیل گواهینامه‌های SSL"""
        try:
            certificates = []
            
            # دریافت از crt.sh
            response = await self.api_manager.crt_sh_certificates(target)
            if response.success:
                for cert in response.data:
                    certificates.append({
                        'common_name': cert.get('common_name', ''),
                        'name_value': cert.get('name_value', ''),
                        'issuer_name': cert.get('issuer_name', ''),
                        'not_before': cert.get('not_before', ''),
                        'not_after': cert.get('not_after', ''),
                        'source': 'crt.sh'
                    })
            
            return certificates
            
        except Exception as e:
            self.logger.error(f"خطا در تحلیل SSL: {e}")
            return []
    
    async def get_favicon_hash(self, target: str) -> Optional[str]:
        """دریافت hash فاویکون"""
        try:
            return await self.api_manager.get_favicon_hash(f"https://{target}")
        except Exception as e:
            self.logger.error(f"خطا در دریافت favicon hash: {e}")
            return None
    
    async def get_http_headers(self, target: str) -> Dict[str, str]:
        """دریافت HTTP headers"""
        try:
            return await self.api_manager.get_http_headers(f"https://{target}")
        except Exception as e:
            self.logger.error(f"خطا در دریافت headers: {e}")
            return {}
    
    async def analyze_http_headers(self, target: str) -> Dict[str, Any]:
        """تحلیل HTTP headers"""
        try:
            headers = await self.get_http_headers(target)
            
            analysis = {
                'headers': headers,
                'cdn_indicators': [],
                'server_info': headers.get('server', ''),
                'security_headers': {},
                'caching_headers': {},
                'load_balancer_indicators': []
            }
            
            # بررسی CDN indicators
            cdn_headers = ['cf-ray', 'x-cache', 'x-amz-cf-id', 'x-served-by']
            for header in cdn_headers:
                if header in headers:
                    analysis['cdn_indicators'].append({
                        'header': header,
                        'value': headers[header]
                    })
            
            # بررسی security headers
            security_headers = ['x-frame-options', 'x-xss-protection', 'strict-transport-security']
            for header in security_headers:
                if header in headers:
                    analysis['security_headers'][header] = headers[header]
            
            # بررسی caching headers
            cache_headers = ['cache-control', 'expires', 'etag', 'last-modified']
            for header in cache_headers:
                if header in headers:
                    analysis['caching_headers'][header] = headers[header]
            
            # بررسی load balancer indicators
            lb_headers = ['x-forwarded-for', 'x-real-ip', 'x-original-forwarded-for']
            for header in lb_headers:
                if header in headers:
                    analysis['load_balancer_indicators'].append({
                        'header': header,
                        'value': headers[header]
                    })
            
            return analysis
            
        except Exception as e:
            self.logger.error(f"خطا در تحلیل headers: {e}")
            return {}
    
    async def get_old_subdomain_records(self, target: str) -> List[Dict[str, Any]]:
        """دریافت رکوردهای قدیمی ساب‌دامین‌ها"""
        try:
            old_records = []
            
            # Wayback Machine
            response = await self.api_manager.wayback_machine_urls(target)
            if response.success:
                old_records.append({
                    'source': 'wayback_machine',
                    'data': response.data
                })
            
            # Common Crawl
            # TODO: اضافه کردن Common Crawl
            
            return old_records
            
        except Exception as e:
            self.logger.error(f"خطا در دریافت رکوردهای قدیمی: {e}")
            return []
    
    async def analyze_ip_differences(self, target: str) -> Dict[str, Any]:
        """تحلیل تفاوت‌های IP"""
        try:
            differences = {
                'direct_ip_access': {},
                'cdn_ip_access': {},
                'differences': []
            }
            
            # دریافت IP های مختلف
            real_ips = await self.extract_real_ips(target)
            cdn_ip = await self.resolve_domain(target)
            
            # تست دسترسی مستقیم
            for real_ip in real_ips[:3]:  # فقط 3 IP اول
                try:
                    response = await self.api_manager.make_request(
                        'default',
                        f"http://{real_ip['ip']}",
                        headers={'Host': target}
                    )
                    differences['direct_ip_access'][real_ip['ip']] = {
                        'status_code': response.status_code,
                        'headers': response.data.get('headers', {}) if response.data else {}
                    }
                except Exception:
                    continue
            
            # تست دسترسی از طریق CDN
            if cdn_ip:
                try:
                    response = await self.api_manager.make_request(
                        'default',
                        f"https://{target}"
                    )
                    differences['cdn_ip_access'] = {
                        'status_code': response.status_code,
                        'headers': response.data.get('headers', {}) if response.data else {}
                    }
                except Exception:
                    pass
            
            # مقایسه تفاوت‌ها
            for ip, direct_data in differences['direct_ip_access'].items():
                if differences['cdn_ip_access']:
                    cdn_data = differences['cdn_ip_access']
                    
                    # مقایسه headers
                    direct_headers = direct_data.get('headers', {})
                    cdn_headers = cdn_data.get('headers', {})
                    
                    header_differences = []
                    for header, value in direct_headers.items():
                        if header not in cdn_headers or cdn_headers[header] != value:
                            header_differences.append({
                                'header': header,
                                'direct_value': value,
                                'cdn_value': cdn_headers.get(header, 'N/A')
                            })
                    
                    if header_differences:
                        differences['differences'].append({
                            'ip': ip,
                            'type': 'header_differences',
                            'differences': header_differences
                        })
            
            return differences
            
        except Exception as e:
            self.logger.error(f"خطا در تحلیل تفاوت‌های IP: {e}")
            return {}
    
    async def check_cdn_ip_ranges(self, target: str) -> List[str]:
        """بررسی IP ranges مربوط به CDN"""
        try:
            # دریافت IP دامنه
            ips = await self.resolve_domain(target)
            if not ips:
                return []
            
            cdn_providers = []
            
            # بررسی IP ranges شناخته شده CDN
            cdn_ranges = {
                'Cloudflare': [
                    '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22',
                    '103.31.4.0/22', '141.101.64.0/18', '108.162.192.0/18'
                ],
                'CloudFront': [
                    '13.32.0.0/15', '13.35.0.0/16', '18.238.0.0/15'
                ],
                'Akamai': [
                    '23.32.0.0/11', '23.64.0.0/13', '23.72.0.0/13'
                ]
            }
            
            # بررسی هر IP
            for ip in ips:
                for provider, ranges in cdn_ranges.items():
                    if self.ip_in_ranges(ip, ranges):
                        cdn_providers.append(provider)
                        break
            
            return list(set(cdn_providers))
            
        except Exception as e:
            self.logger.error(f"خطا در بررسی CDN IP ranges: {e}")
            return []
    
    def ip_in_ranges(self, ip: str, ranges: List[str]) -> bool:
        """بررسی قرارگیری IP در ranges"""
        try:
            import ipaddress
            
            ip_obj = ipaddress.ip_address(ip)
            for range_str in ranges:
                if ip_obj in ipaddress.ip_network(range_str):
                    return True
            return False
            
        except Exception:
            return False
    
    async def get_bypass_methods(self, target: str, results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """دریافت روش‌های bypass"""
        try:
            bypass_methods = []
            
            # DNS History bypass
            if results['dns_history']:
                bypass_methods.append({
                    'method': 'dns_history',
                    'description': 'استفاده از تاریخچه DNS برای پیدا کردن IP های قدیمی',
                    'confidence': 0.8,
                    'data': results['dns_history']
                })
            
            # Favicon hash bypass
            if results['favicon_hash']:
                bypass_methods.append({
                    'method': 'favicon_hash',
                    'description': 'استفاده از hash فاویکون برای جستجو در Shodan',
                    'confidence': 0.9,
                    'data': {'hash': results['favicon_hash']}
                })
            
            # Certificate transparency bypass
            if results['ssl_certificates']:
                bypass_methods.append({
                    'method': 'certificate_transparency',
                    'description': 'استفاده از Certificate Transparency logs',
                    'confidence': 0.9,
                    'data': results['ssl_certificates']
                })
            
            # Header differences bypass
            if results['ip_differences']['differences']:
                bypass_methods.append({
                    'method': 'header_differences',
                    'description': 'تحلیل تفاوت headers در دسترسی مستقیم و CDN',
                    'confidence': 0.7,
                    'data': results['ip_differences']
                })
            
            return bypass_methods
            
        except Exception as e:
            self.logger.error(f"خطا در دریافت روش‌های bypass: {e}")
            return []
    
    async def generate_recommendations(self, results: Dict[str, Any]) -> List[str]:
        """تولید توصیه‌ها"""
        try:
            recommendations = []
            
            # توصیه بر اساس CDN detection
            if results['cdn_detected']:
                recommendations.append(
                    f"CDN {results['cdn_provider']} تشخیص داده شد. "
                    "برای دسترسی مستقیم به سرور، از IP های واقعی استفاده کنید."
                )
            
            # توصیه بر اساس تعداد IP های واقعی
            if len(results['real_ips']) > 1:
                recommendations.append(
                    f"تعداد {len(results['real_ips'])} IP واقعی پیدا شد. "
                    "همه آن‌ها را برای دسترسی مستقیم تست کنید."
                )
            
            # توصیه بر اساس favicon hash
            if results['favicon_hash']:
                recommendations.append(
                    "فاویکون hash پیدا شد. می‌توانید از آن برای جستجو در Shodan استفاده کنید."
                )
            
            # توصیه بر اساس تفاوت‌های IP
            if results['ip_differences']['differences']:
                recommendations.append(
                    "تفاوت‌هایی در headers بین دسترسی مستقیم و CDN پیدا شد. "
                    "از این تفاوت‌ها برای شناسایی سرور واقعی استفاده کنید."
                )
            
            return recommendations
            
        except Exception as e:
            self.logger.error(f"خطا در تولید توصیه‌ها: {e}")
            return []
    
    async def cleanup(self):
        """پاکسازی منابع"""
        try:
            self.executor.shutdown(wait=True)
            self.logger.info("فاز 1 پاکسازی شد")
        except Exception as e:
            self.logger.error(f"خطا در پاکسازی فاز 1: {e}")