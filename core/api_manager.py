"""
مدیریت API ها و سرویس‌های خارجی برای ARAT
"""

import asyncio
import aiohttp
import requests
import time
import json
from typing import Dict, List, Any, Optional, Union
from datetime import datetime, timedelta
import logging
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse
import hashlib
import base64
from concurrent.futures import ThreadPoolExecutor
import random


@dataclass
class APIResponse:
    """ساختار پاسخ API"""
    success: bool
    data: Any = None
    error: str = None
    status_code: int = None
    response_time: float = None
    rate_limit_remaining: int = None
    rate_limit_reset: datetime = None


class RateLimiter:
    """مدیریت محدودیت نرخ درخواست"""
    
    def __init__(self, requests_per_minute: int = 100):
        self.requests_per_minute = requests_per_minute
        self.requests = []
        self.lock = asyncio.Lock()
    
    async def acquire(self):
        """دریافت مجوز برای درخواست"""
        async with self.lock:
            now = datetime.now()
            
            # حذف درخواست‌های قدیمی
            self.requests = [req_time for req_time in self.requests 
                           if now - req_time < timedelta(minutes=1)]
            
            # بررسی محدودیت نرخ
            if len(self.requests) >= self.requests_per_minute:
                # محاسبه زمان انتظار
                oldest_request = min(self.requests)
                wait_time = (oldest_request + timedelta(minutes=1) - now).total_seconds()
                if wait_time > 0:
                    await asyncio.sleep(wait_time)
                    return await self.acquire()
            
            # ثبت درخواست جدید
            self.requests.append(now)


class APIManager:
    """مدیر API ها و سرویس‌های خارجی"""
    
    def __init__(self, config):
        self.config = config
        self.api_keys = {}
        self.rate_limiters = {}
        self.session = None
        self.logger = logging.getLogger('arat.api_manager')
        self.executor = ThreadPoolExecutor(max_workers=20)
        
        # تنظیم rate limiter برای هر سرویس
        self._setup_rate_limiters()
    
    def _setup_rate_limiters(self):
        """تنظیم rate limiter ها"""
        # محدودیت‌های مختلف برای سرویس‌های مختلف
        limits = {
            'shodan': 1,  # 1 request per second
            'virustotal': 4,  # 4 requests per minute
            'censys': 1,  # 1 request per second
            'securitytrails': 1,  # 1 request per second
            'github': 5000,  # 5000 requests per hour
            'wayback_machine': 100,  # 100 requests per minute
            'common_crawl': 10,  # 10 requests per minute
            'crt_sh': 100,  # 100 requests per minute
            'dnsdumpster': 10,  # 10 requests per minute
            'hunter': 100,  # 100 requests per minute
            'builtwith': 100,  # 100 requests per minute
            'wappalyzer': 100,  # 100 requests per minute
            'default': 100  # 100 requests per minute
        }
        
        for service, limit in limits.items():
            self.rate_limiters[service] = RateLimiter(limit)
    
    async def load_api_keys(self):
        """بارگذاری API keys"""
        try:
            self.api_keys = self.config.api_keys.copy()
            
            # بررسی API keys موجود
            available_services = []
            for service, key in self.api_keys.items():
                if key:
                    available_services.append(service)
            
            self.logger.info(f"API keys بارگذاری شدند: {', '.join(available_services)}")
            
        except Exception as e:
            self.logger.error(f"خطا در بارگذاری API keys: {e}")
    
    async def get_session(self) -> aiohttp.ClientSession:
        """دریافت session"""
        if not self.session:
            timeout = aiohttp.ClientTimeout(total=self.config.api.timeout)
            headers = {
                'User-Agent': random.choice(self.config.api.user_agents)
            }
            
            self.session = aiohttp.ClientSession(
                timeout=timeout,
                headers=headers,
                connector=aiohttp.TCPConnector(limit=100, limit_per_host=30)
            )
        
        return self.session
    
    async def close_session(self):
        """بستن session"""
        if self.session:
            await self.session.close()
            self.session = None
    
    def get_rate_limiter(self, service: str) -> RateLimiter:
        """دریافت rate limiter برای سرویس"""
        return self.rate_limiters.get(service, self.rate_limiters['default'])
    
    async def make_request(self, service: str, url: str, method: str = 'GET', 
                          params: Dict = None, data: Dict = None, 
                          headers: Dict = None, **kwargs) -> APIResponse:
        """انجام درخواست API"""
        start_time = time.time()
        
        try:
            # بررسی API key
            api_key = self.api_keys.get(service)
            if not api_key and service != 'default':
                return APIResponse(
                    success=False,
                    error=f"API key برای {service} تنظیم نشده است"
                )
            
            # اعمال rate limiting
            rate_limiter = self.get_rate_limiter(service)
            await rate_limiter.acquire()
            
            # تنظیم headers
            request_headers = headers or {}
            if api_key:
                if service == 'shodan':
                    request_headers['X-API-Key'] = api_key
                elif service == 'virustotal':
                    request_headers['X-Apikey'] = api_key
                elif service == 'censys':
                    request_headers['Authorization'] = f'Basic {api_key}'
                elif service == 'securitytrails':
                    request_headers['APIKEY'] = api_key
                elif service == 'github':
                    request_headers['Authorization'] = f'token {api_key}'
                else:
                    request_headers['Authorization'] = f'Bearer {api_key}'
            
            # تنظیم params
            request_params = params or {}
            if service == 'virustotal' and 'apikey' not in request_params:
                request_params['apikey'] = api_key
            elif service == 'hunter' and 'api_key' not in request_params:
                request_params['api_key'] = api_key
            
            # انجام درخواست
            session = await self.get_session()
            
            async with session.request(
                method=method,
                url=url,
                params=request_params,
                json=data,
                headers=request_headers,
                **kwargs
            ) as response:
                
                response_time = time.time() - start_time
                
                # خواندن پاسخ
                try:
                    if response.content_type == 'application/json':
                        response_data = await response.json()
                    else:
                        response_data = await response.text()
                except Exception as e:
                    response_data = await response.text()
                
                # استخراج اطلاعات rate limit
                rate_limit_remaining = None
                rate_limit_reset = None
                
                if 'X-RateLimit-Remaining' in response.headers:
                    rate_limit_remaining = int(response.headers['X-RateLimit-Remaining'])
                
                if 'X-RateLimit-Reset' in response.headers:
                    rate_limit_reset = datetime.fromtimestamp(
                        int(response.headers['X-RateLimit-Reset'])
                    )
                
                # ثبت لاگ API call
                await self._log_api_call(
                    service=service,
                    endpoint=url,
                    method=method,
                    status_code=response.status,
                    response_time=response_time,
                    rate_limit_remaining=rate_limit_remaining
                )
                
                return APIResponse(
                    success=response.status == 200,
                    data=response_data,
                    status_code=response.status,
                    response_time=response_time,
                    rate_limit_remaining=rate_limit_remaining,
                    rate_limit_reset=rate_limit_reset
                )
        
        except asyncio.TimeoutError:
            response_time = time.time() - start_time
            await self._log_api_call(
                service=service,
                endpoint=url,
                method=method,
                status_code=None,
                response_time=response_time,
                error_message="Timeout"
            )
            
            return APIResponse(
                success=False,
                error="Timeout",
                response_time=response_time
            )
        
        except Exception as e:
            response_time = time.time() - start_time
            await self._log_api_call(
                service=service,
                endpoint=url,
                method=method,
                status_code=None,
                response_time=response_time,
                error_message=str(e)
            )
            
            return APIResponse(
                success=False,
                error=str(e),
                response_time=response_time
            )
    
    async def _log_api_call(self, service: str, endpoint: str = None, method: str = None,
                           status_code: int = None, response_time: float = None,
                           rate_limit_remaining: int = None, error_message: str = None):
        """ثبت لاگ API call"""
        try:
            # اینجا می‌توان لاگ را در دیتابیس ذخیره کرد
            self.logger.debug(
                f"API Call - {service}: {method} {endpoint} - "
                f"Status: {status_code}, Time: {response_time:.2f}s"
            )
        except Exception as e:
            self.logger.error(f"خطا در ثبت لاگ API: {e}")
    
    # متدهای مخصوص هر سرویس
    
    async def shodan_search(self, query: str) -> APIResponse:
        """جستجو در Shodan"""
        url = "https://api.shodan.io/shodan/host/search"
        params = {'query': query}
        
        return await self.make_request('shodan', url, params=params)
    
    async def shodan_host(self, ip: str) -> APIResponse:
        """دریافت اطلاعات host از Shodan"""
        url = f"https://api.shodan.io/shodan/host/{ip}"
        
        return await self.make_request('shodan', url)
    
    async def virustotal_domain_report(self, domain: str) -> APIResponse:
        """دریافت گزارش دامنه از VirusTotal"""
        url = f"https://www.virustotal.com/vtapi/v2/domain/report"
        params = {'domain': domain}
        
        return await self.make_request('virustotal', url, params=params)
    
    async def virustotal_ip_report(self, ip: str) -> APIResponse:
        """دریافت گزارش IP از VirusTotal"""
        url = f"https://www.virustotal.com/vtapi/v2/ip-address/report"
        params = {'ip': ip}
        
        return await self.make_request('virustotal', url, params=params)
    
    async def censys_search(self, query: str, index: str = 'websites') -> APIResponse:
        """جستجو در Censys"""
        url = f"https://search.censys.io/api/v1/search/{index}"
        data = {'query': query}
        
        return await self.make_request('censys', url, method='POST', data=data)
    
    async def securitytrails_domain_history(self, domain: str) -> APIResponse:
        """دریافت تاریخچه دامنه از SecurityTrails"""
        url = f"https://api.securitytrails.com/v1/domain/{domain}/history"
        
        return await self.make_request('securitytrails', url)
    
    async def securitytrails_subdomains(self, domain: str) -> APIResponse:
        """دریافت ساب‌دامین‌ها از SecurityTrails"""
        url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
        
        return await self.make_request('securitytrails', url)
    
    async def github_search(self, query: str, sort: str = 'indexed') -> APIResponse:
        """جستجو در GitHub"""
        url = "https://api.github.com/search/code"
        params = {
            'q': query,
            'sort': sort,
            'order': 'desc'
        }
        
        return await self.make_request('github', url, params=params)
    
    async def wayback_machine_urls(self, domain: str) -> APIResponse:
        """دریافت URL های Wayback Machine"""
        url = f"http://web.archive.org/cdx/search/cdx"
        params = {
            'url': f"*.{domain}/*",
            'output': 'json',
            'collapse': 'urlkey'
        }
        
        return await self.make_request('wayback_machine', url, params=params)
    
    async def crt_sh_certificates(self, domain: str) -> APIResponse:
        """دریافت گواهینامه‌ها از crt.sh"""
        url = "https://crt.sh/"
        params = {
            'q': f"%.{domain}",
            'output': 'json'
        }
        
        return await self.make_request('crt_sh', url, params=params)
    
    async def dnsdumpster_subdomains(self, domain: str) -> APIResponse:
        """دریافت ساب‌دامین‌ها از DNSDumpster"""
        url = "https://dnsdumpster.com/"
        
        # ابتدا صفحه اصلی را دریافت می‌کنیم
        response = await self.make_request('dnsdumpster', url)
        if not response.success:
            return response
        
        # استخراج CSRF token (در صورت نیاز)
        # سپس درخواست جستجو
        search_url = "https://dnsdumpster.com/"
        data = {
            'targetip': domain,
            'user': 'free'
        }
        
        return await self.make_request('dnsdumpster', search_url, method='POST', data=data)
    
    async def hunter_domain_search(self, domain: str) -> APIResponse:
        """جستجو دامنه در Hunter"""
        url = f"https://api.hunter.io/v2/domain-search"
        params = {
            'domain': domain,
            'limit': 100
        }
        
        return await self.make_request('hunter', url, params=params)
    
    async def builtwith_technology_lookup(self, domain: str) -> APIResponse:
        """جستجوی تکنولوژی در BuiltWith"""
        url = f"https://api.builtwith.com/v20/api.json"
        params = {
            'KEY': self.api_keys.get('builtwith'),
            'LOOKUP': domain,
            'HIDETEXT': 'yes',
            'HIDEDL': 'yes'
        }
        
        return await self.make_request('builtwith', url, params=params)
    
    async def wappalyzer_analyze(self, url: str) -> APIResponse:
        """تحلیل تکنولوژی با Wappalyzer"""
        api_url = f"https://api.wappalyzer.com/v2/lookup"
        params = {'url': url}
        
        return await self.make_request('wappalyzer', api_url, params=params)
    
    # متدهای کمکی
    
    async def resolve_domain(self, domain: str) -> List[str]:
        """حل DNS دامنه"""
        try:
            import socket
            
            loop = asyncio.get_event_loop()
            ips = await loop.run_in_executor(
                self.executor,
                socket.gethostbyname_ex,
                domain
            )
            
            return ips[2]  # لیست IP ها
            
        except Exception as e:
            self.logger.error(f"خطا در حل DNS {domain}: {e}")
            return []
    
    async def reverse_dns_lookup(self, ip: str) -> Optional[str]:
        """جستجوی معکوس DNS"""
        try:
            import socket
            
            loop = asyncio.get_event_loop()
            hostname = await loop.run_in_executor(
                self.executor,
                socket.gethostbyaddr,
                ip
            )
            
            return hostname[0]
            
        except Exception as e:
            self.logger.error(f"خطا در جستجوی معکوس DNS {ip}: {e}")
            return None
    
    async def get_favicon_hash(self, url: str) -> Optional[str]:
        """محاسبه hash فاویکون"""
        try:
            session = await self.get_session()
            
            # تلاش برای دریافت favicon
            favicon_urls = [
                urljoin(url, '/favicon.ico'),
                urljoin(url, '/favicon.png'),
                urljoin(url, '/apple-touch-icon.png'),
                urljoin(url, '/apple-touch-icon-precomposed.png')
            ]
            
            for favicon_url in favicon_urls:
                try:
                    async with session.get(favicon_url, timeout=aiohttp.ClientTimeout(total=10)) as response:
                        if response.status == 200:
                            favicon_data = await response.read()
                            
                            # محاسبه hash
                            favicon_hash = hashlib.md5(favicon_data).hexdigest()
                            
                            # جستجو در Shodan
                            shodan_response = await self.shodan_search(f"http.favicon.hash:{favicon_hash}")
                            
                            if shodan_response.success:
                                return favicon_hash
                            
                            break
                            
                except Exception:
                    continue
            
            return None
            
        except Exception as e:
            self.logger.error(f"خطا در دریافت favicon hash {url}: {e}")
            return None
    
    async def get_http_headers(self, url: str) -> Dict[str, str]:
        """دریافت HTTP headers"""
        try:
            session = await self.get_session()
            
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as response:
                return dict(response.headers)
                
        except Exception as e:
            self.logger.error(f"خطا در دریافت headers {url}: {e}")
            return {}
    
    async def check_cloudflare_bypass(self, domain: str) -> List[str]:
        """بررسی bypass Cloudflare"""
        try:
            # روش‌های مختلف bypass
            bypass_methods = []
            
            # 1. بررسی DNS history
            dns_history_response = await self.securitytrails_domain_history(domain)
            if dns_history_response.success:
                bypass_methods.append("dns_history")
            
            # 2. بررسی favicon hash
            favicon_hash = await self.get_favicon_hash(f"https://{domain}")
            if favicon_hash:
                bypass_methods.append("favicon_hash")
            
            # 3. بررسی subdomain takeover
            subdomains_response = await self.securitytrails_subdomains(domain)
            if subdomains_response.success:
                bypass_methods.append("subdomain_check")
            
            return bypass_methods
            
        except Exception as e:
            self.logger.error(f"خطا در بررسی Cloudflare bypass {domain}: {e}")
            return []
    
    async def get_ssl_certificates(self, domain: str) -> List[Dict[str, Any]]:
        """دریافت گواهینامه‌های SSL"""
        try:
            certificates = []
            
            # دریافت از crt.sh
            crt_response = await self.crt_sh_certificates(domain)
            if crt_response.success and isinstance(crt_response.data, list):
                for cert in crt_response.data:
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
            self.logger.error(f"خطا در دریافت SSL certificates {domain}: {e}")
            return []
    
    async def batch_request(self, requests: List[Dict[str, Any]]) -> List[APIResponse]:
        """انجام درخواست‌های دسته‌ای"""
        try:
            tasks = []
            
            for req in requests:
                service = req.get('service', 'default')
                url = req.get('url')
                method = req.get('method', 'GET')
                params = req.get('params')
                data = req.get('data')
                headers = req.get('headers')
                
                task = self.make_request(
                    service=service,
                    url=url,
                    method=method,
                    params=params,
                    data=data,
                    headers=headers
                )
                tasks.append(task)
            
            # انجام تمام درخواست‌ها به صورت موازی
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # تبدیل exceptions به APIResponse
            api_responses = []
            for result in results:
                if isinstance(result, Exception):
                    api_responses.append(APIResponse(
                        success=False,
                        error=str(result)
                    ))
                else:
                    api_responses.append(result)
            
            return api_responses
            
        except Exception as e:
            self.logger.error(f"خطا در درخواست‌های دسته‌ای: {e}")
            return []
    
    async def cleanup(self):
        """پاکسازی منابع"""
        try:
            await self.close_session()
            self.executor.shutdown(wait=True)
            self.logger.info("API Manager پاکسازی شد")
        except Exception as e:
            self.logger.error(f"خطا در پاکسازی API Manager: {e}")