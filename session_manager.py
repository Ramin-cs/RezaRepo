#!/usr/bin/env python3
"""
🔥 SESSION MANAGER - Advanced HTTP Session Management
"""

import asyncio
import aiohttp
import random
import time
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse
from dataclasses import dataclass, field


@dataclass
class SessionConfig:
    """Session configuration"""
    timeout: int = 30
    max_connections: int = 100
    max_connections_per_host: int = 20
    ssl_verify: bool = False
    follow_redirects: bool = False
    max_retries: int = 3
    retry_delay: Tuple[float, float] = (0.1, 0.5)
    rate_limit: float = 0.1  # Delay between requests
    user_agent_rotation: bool = True
    proxy_rotation: bool = False
    cookie_jar: bool = True


@dataclass
class RequestResult:
    """HTTP request result"""
    url: str
    status: int
    headers: Dict[str, str]
    content: str
    response_time: float
    final_url: str
    cookies: Dict[str, str] = field(default_factory=dict)
    error: Optional[str] = None
    retry_count: int = 0


class SessionManager:
    """Advanced HTTP session manager with stealth capabilities"""
    
    def __init__(self, config: SessionConfig = None):
        self.config = config or SessionConfig()
        self.session: Optional[aiohttp.ClientSession] = None
        
        # Request statistics
        self.stats = {
            'total_requests': 0,
            'successful_requests': 0,
            'failed_requests': 0,
            'retries': 0,
            'total_bytes': 0,
            'average_response_time': 0.0,
            'start_time': time.time()
        }
        
        # User agent pool for rotation
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/121.0",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
            "Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
            "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
            "Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)"
        ]
        
        # Stealth headers
        self.stealth_headers = {
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'Cache-Control': 'no-cache',
            'Pragma': 'no-cache',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1'
        }
        
        # WAF bypass headers
        self.bypass_headers = [
            {'X-Originating-IP': '127.0.0.1'},
            {'X-Forwarded-For': '127.0.0.1'},
            {'X-Real-IP': '127.0.0.1'},
            {'X-Remote-Addr': '127.0.0.1'},
            {'X-Client-IP': '127.0.0.1'},
            {'CF-Connecting-IP': '127.0.0.1'},
            {'True-Client-IP': '127.0.0.1'},
            {'X-Cluster-Client-IP': '127.0.0.1'}
        ]
    
    async def initialize(self) -> bool:
        """Initialize HTTP session"""
        try:
            # Create connector
            connector = aiohttp.TCPConnector(
                limit=self.config.max_connections,
                limit_per_host=self.config.max_connections_per_host,
                ssl=self.config.ssl_verify,
                enable_cleanup_closed=True
            )
            
            # Create timeout
            timeout = aiohttp.ClientTimeout(total=self.config.timeout)
            
            # Create cookie jar
            cookie_jar = aiohttp.CookieJar() if self.config.cookie_jar else None
            
            # Create session
            self.session = aiohttp.ClientSession(
                connector=connector,
                timeout=timeout,
                cookie_jar=cookie_jar,
                headers=self._get_session_headers()
            )
            
            print("[SESSION-MANAGER] ✅ Advanced session initialized")
            return True
            
        except Exception as e:
            print(f"[SESSION-MANAGER] ❌ Initialization failed: {e}")
            return False
    
    def _get_session_headers(self) -> Dict[str, str]:
        """Get session headers with rotation"""
        headers = self.stealth_headers.copy()
        
        # Rotate user agent
        if self.config.user_agent_rotation:
            headers['User-Agent'] = random.choice(self.user_agents)
        
        # Add random bypass headers
        bypass_headers = random.choice(self.bypass_headers)
        headers.update(bypass_headers)
        
        return headers
    
    async def request(self, method: str, url: str, **kwargs) -> RequestResult:
        """Make HTTP request with advanced features"""
        if not self.session:
            raise RuntimeError("Session not initialized")
        
        start_time = time.time()
        self.stats['total_requests'] += 1
        
        # Apply rate limiting
        if self.stats['total_requests'] > 1:
            await asyncio.sleep(self.config.rate_limit)
        
        # Try request with retries
        for attempt in range(self.config.max_retries + 1):
            try:
                # Rotate headers for each attempt
                if attempt > 0:
                    kwargs['headers'] = kwargs.get('headers', {})
                    kwargs['headers'].update(self._get_session_headers())
                
                async with self.session.request(
                    method, url, 
                    allow_redirects=self.config.follow_redirects,
                    **kwargs
                ) as response:
                    content = await response.text()
                    response_time = time.time() - start_time
                    
                    # Update statistics
                    self.stats['successful_requests'] += 1
                    self.stats['total_bytes'] += len(content.encode('utf-8'))
                    self._update_average_response_time(response_time)
                    
                    # Extract cookies
                    cookies = {}
                    if self.session.cookie_jar:
                        for cookie in self.session.cookie_jar:
                            cookies[cookie.key] = cookie.value
                    
                    return RequestResult(
                        url=url,
                        status=response.status,
                        headers=dict(response.headers),
                        content=content,
                        response_time=response_time,
                        final_url=str(response.url),
                        cookies=cookies,
                        retry_count=attempt
                    )
                    
            except asyncio.TimeoutError:
                if attempt < self.config.max_retries:
                    self.stats['retries'] += 1
                    delay = random.uniform(*self.config.retry_delay)
                    await asyncio.sleep(delay)
                    continue
                else:
                    self.stats['failed_requests'] += 1
                    return RequestResult(
                        url=url, status=0, headers={}, content="",
                        response_time=time.time() - start_time,
                        final_url=url, error="Timeout",
                        retry_count=attempt
                    )
            
            except Exception as e:
                if attempt < self.config.max_retries:
                    self.stats['retries'] += 1
                    delay = random.uniform(*self.config.retry_delay)
                    await asyncio.sleep(delay)
                    continue
                else:
                    self.stats['failed_requests'] += 1
                    return RequestResult(
                        url=url, status=0, headers={}, content="",
                        response_time=time.time() - start_time,
                        final_url=url, error=str(e),
                        retry_count=attempt
                    )
        
        # Should not reach here
        self.stats['failed_requests'] += 1
        return RequestResult(
            url=url, status=0, headers={}, content="",
            response_time=time.time() - start_time,
            final_url=url, error="Max retries exceeded"
        )
    
    def _update_average_response_time(self, response_time: float):
        """Update average response time"""
        current_avg = self.stats['average_response_time']
        successful_count = self.stats['successful_requests']
        
        if successful_count == 1:
            self.stats['average_response_time'] = response_time
        else:
            self.stats['average_response_time'] = (
                (current_avg * (successful_count - 1) + response_time) / successful_count
            )
    
    async def get(self, url: str, **kwargs) -> RequestResult:
        """GET request"""
        return await self.request('GET', url, **kwargs)
    
    async def post(self, url: str, **kwargs) -> RequestResult:
        """POST request"""
        return await self.request('POST', url, **kwargs)
    
    async def head(self, url: str, **kwargs) -> RequestResult:
        """HEAD request"""
        return await self.request('HEAD', url, **kwargs)
    
    async def options(self, url: str, **kwargs) -> RequestResult:
        """OPTIONS request"""
        return await self.request('OPTIONS', url, **kwargs)
    
    def get_statistics(self) -> Dict:
        """Get session statistics"""
        uptime = time.time() - self.stats['start_time']
        success_rate = (self.stats['successful_requests'] / max(self.stats['total_requests'], 1)) * 100
        requests_per_second = self.stats['total_requests'] / max(uptime, 1)
        
        return {
            'total_requests': self.stats['total_requests'],
            'successful_requests': self.stats['successful_requests'],
            'failed_requests': self.stats['failed_requests'],
            'retries': self.stats['retries'],
            'success_rate_percentage': round(success_rate, 2),
            'average_response_time': round(self.stats['average_response_time'], 3),
            'total_bytes_downloaded': self.stats['total_bytes'],
            'requests_per_second': round(requests_per_second, 2),
            'session_uptime': round(uptime, 2)
        }
    
    async def test_connectivity(self, url: str) -> bool:
        """Test connectivity to target"""
        try:
            result = await self.head(url)
            return result.status < 400
        except:
            return False
    
    async def cleanup(self):
        """Cleanup session resources"""
        if self.session:
            await self.session.close()
            print("[SESSION-MANAGER] ✅ Session cleaned up")
    
    def __str__(self) -> str:
        """String representation"""
        stats = self.get_statistics()
        return f"SessionManager(requests={stats['total_requests']}, success_rate={stats['success_rate_percentage']}%)"