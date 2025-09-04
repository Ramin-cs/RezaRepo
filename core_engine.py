#!/usr/bin/env python3
"""
🔥 CORE SCANNING ENGINE - Heart of the Ultimate Scanner
"""

import asyncio
import aiohttp
import time
from typing import List, Dict, Set, Optional, Tuple
from urllib.parse import urlparse, urljoin
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class ScanTarget:
    """Scan target information"""
    url: str
    domain: str = ""
    scheme: str = ""
    port: int = None
    path: str = "/"
    
    def __post_init__(self):
        parsed = urlparse(self.url)
        self.domain = parsed.netloc
        self.scheme = parsed.scheme
        self.port = parsed.port
        self.path = parsed.path or "/"


@dataclass
class ScanResults:
    """Complete scan results"""
    target: ScanTarget
    start_time: datetime
    end_time: Optional[datetime] = None
    total_urls: int = 0
    total_parameters: int = 0
    total_vulnerabilities: int = 0
    phases_completed: int = 0
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    
    @property
    def duration(self) -> float:
        if self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return (datetime.now() - self.start_time).total_seconds()


class CoreEngine:
    """Core scanning engine that orchestrates all modules"""
    
    def __init__(self, target_url: str, config: Dict = None):
        self.target = ScanTarget(target_url)
        self.config = config or {}
        self.results = ScanResults(self.target, datetime.now())
        
        # Session management
        self.session = None
        self.session_config = {
            'timeout': aiohttp.ClientTimeout(total=30),
            'connector': aiohttp.TCPConnector(limit=100, limit_per_host=20, ssl=False),
            'headers': self._get_default_headers()
        }
        
        # Storage for discovered data
        self.discovered_urls: Set[str] = set()
        self.crawled_urls: Set[str] = set()
        self.parameters: List[Dict] = []
        self.vulnerabilities: List[Dict] = []
        
        # Module status tracking
        self.module_status = {
            'parameter_extractor': False,
            'url_analyzer': False,
            'form_analyzer': False,
            'js_extractor': False,
            'meta_analyzer': False,
            'cookie_analyzer': False,
            'redirect_detector': False,
            'payload_injector': False,
            'response_analyzer': False,
            'poc_engine': False,
            'report_engine': False
        }
        
        # Performance metrics
        self.metrics = {
            'requests_sent': 0,
            'responses_received': 0,
            'parameters_found': 0,
            'vulnerabilities_found': 0,
            'errors_encountered': 0,
            'average_response_time': 0.0,
            'total_bytes_downloaded': 0
        }
    
    def _get_default_headers(self) -> Dict[str, str]:
        """Get default HTTP headers"""
        return {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate',
            'Cache-Control': 'no-cache',
            'Pragma': 'no-cache',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        }
    
    async def initialize_session(self) -> bool:
        """Initialize HTTP session with advanced configuration"""
        try:
            self.session = aiohttp.ClientSession(**self.session_config)
            
            # Test connectivity
            test_response = await self._test_connectivity()
            if test_response:
                print(f"[CORE-ENGINE] ✅ Session initialized - Target accessible")
                return True
            else:
                print(f"[CORE-ENGINE] ❌ Target not accessible")
                return False
                
        except Exception as e:
            self.results.errors.append(f"Session initialization failed: {e}")
            print(f"[CORE-ENGINE] ❌ Session initialization failed: {e}")
            return False
    
    async def _test_connectivity(self) -> bool:
        """Test connectivity to target"""
        try:
            async with self.session.head(self.target.url, allow_redirects=True) as response:
                self.metrics['requests_sent'] += 1
                if response.status < 400:
                    self.metrics['responses_received'] += 1
                    return True
                return False
        except:
            return False
    
    async def fetch_url(self, url: str, method: str = 'GET', **kwargs) -> Optional[Dict]:
        """Fetch URL with metrics tracking"""
        if not self.session:
            return None
        
        start_time = time.time()
        
        try:
            self.metrics['requests_sent'] += 1
            
            async with self.session.request(method, url, **kwargs) as response:
                content = await response.text()
                response_time = time.time() - start_time
                
                # Update metrics
                self.metrics['responses_received'] += 1
                self.metrics['total_bytes_downloaded'] += len(content.encode('utf-8'))
                
                # Update average response time
                current_avg = self.metrics['average_response_time']
                total_responses = self.metrics['responses_received']
                self.metrics['average_response_time'] = ((current_avg * (total_responses - 1)) + response_time) / total_responses
                
                return {
                    'url': str(response.url),
                    'status': response.status,
                    'headers': dict(response.headers),
                    'content': content,
                    'response_time': response_time,
                    'content_length': len(content),
                    'final_url': str(response.url)  # After redirects
                }
                
        except Exception as e:
            self.metrics['errors_encountered'] += 1
            self.results.errors.append(f"Failed to fetch {url}: {e}")
            return None
    
    def register_module(self, module_name: str, status: bool = True):
        """Register module status"""
        if module_name in self.module_status:
            self.module_status[module_name] = status
            print(f"[CORE-ENGINE] Module {module_name}: {'✅ LOADED' if status else '❌ FAILED'}")
    
    def get_module_status(self) -> Dict[str, bool]:
        """Get all module statuses"""
        return self.module_status.copy()
    
    def add_discovered_url(self, url: str) -> bool:
        """Add discovered URL"""
        if self._is_valid_url(url) and self._is_same_domain(url):
            self.discovered_urls.add(url)
            return True
        return False
    
    def add_parameter(self, param_data: Dict):
        """Add discovered parameter"""
        self.parameters.append(param_data)
        self.metrics['parameters_found'] += 1
        self.results.total_parameters += 1
    
    def add_vulnerability(self, vuln_data: Dict):
        """Add discovered vulnerability"""
        self.vulnerabilities.append(vuln_data)
        self.metrics['vulnerabilities_found'] += 1
        self.results.total_vulnerabilities += 1
    
    def _is_valid_url(self, url: str) -> bool:
        """Check if URL is valid"""
        try:
            parsed = urlparse(url)
            return bool(parsed.scheme and parsed.netloc)
        except:
            return False
    
    def _is_same_domain(self, url: str) -> bool:
        """Check if URL belongs to target domain"""
        try:
            parsed = urlparse(url)
            target_domain = self.target.domain.lower()
            url_domain = parsed.netloc.lower()
            
            return (url_domain == target_domain or 
                   url_domain.endswith(f'.{target_domain}'))
        except:
            return False
    
    def get_crawl_queue(self, max_urls: int = 100) -> List[str]:
        """Get URLs to crawl"""
        uncrawled = self.discovered_urls - self.crawled_urls
        return list(uncrawled)[:max_urls]
    
    def mark_url_crawled(self, url: str):
        """Mark URL as crawled"""
        self.crawled_urls.add(url)
        self.results.total_urls = len(self.crawled_urls)
    
    def get_statistics(self) -> Dict:
        """Get comprehensive statistics"""
        return {
            'scan_duration': self.results.duration,
            'target_info': {
                'url': self.target.url,
                'domain': self.target.domain,
                'scheme': self.target.scheme
            },
            'discovery_stats': {
                'discovered_urls': len(self.discovered_urls),
                'crawled_urls': len(self.crawled_urls),
                'pending_urls': len(self.discovered_urls - self.crawled_urls)
            },
            'parameter_stats': {
                'total_parameters': len(self.parameters),
                'unique_names': len(set(p.get('name', '') for p in self.parameters)),
                'redirect_related': len([p for p in self.parameters if p.get('is_redirect_related', False)])
            },
            'vulnerability_stats': {
                'total_vulnerabilities': len(self.vulnerabilities),
                'by_severity': self._get_vulnerability_by_severity()
            },
            'performance_metrics': self.metrics,
            'module_status': self.module_status,
            'phases_completed': self.results.phases_completed,
            'errors': len(self.results.errors),
            'warnings': len(self.results.warnings)
        }
    
    def _get_vulnerability_by_severity(self) -> Dict[str, int]:
        """Get vulnerability count by severity"""
        severity_count = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for vuln in self.vulnerabilities:
            severity = vuln.get('severity', 'MEDIUM')
            if severity in severity_count:
                severity_count[severity] += 1
        return severity_count
    
    def update_phase(self, phase_name: str):
        """Update current phase"""
        self.results.phases_completed += 1
        print(f"[CORE-ENGINE] Phase {self.results.phases_completed}: {phase_name} completed")
    
    def add_warning(self, message: str):
        """Add warning message"""
        self.results.warnings.append(message)
        print(f"[CORE-ENGINE] ⚠️ WARNING: {message}")
    
    def add_error(self, message: str):
        """Add error message"""
        self.results.errors.append(message)
        print(f"[CORE-ENGINE] ❌ ERROR: {message}")
    
    async def cleanup(self):
        """Cleanup resources"""
        if self.session:
            await self.session.close()
        
        self.results.end_time = datetime.now()
        print(f"[CORE-ENGINE] 🧹 Cleanup completed - Total duration: {self.results.duration:.2f}s")
    
    def get_health_status(self) -> Dict:
        """Get engine health status"""
        total_modules = len(self.module_status)
        loaded_modules = sum(1 for status in self.module_status.values() if status)
        
        return {
            'status': 'HEALTHY' if loaded_modules == total_modules else 'DEGRADED',
            'modules_loaded': f"{loaded_modules}/{total_modules}",
            'session_active': self.session is not None and not self.session.closed,
            'errors': len(self.results.errors),
            'warnings': len(self.results.warnings),
            'uptime': self.results.duration,
            'performance': {
                'requests_per_second': self.metrics['requests_sent'] / max(self.results.duration, 1),
                'success_rate': (self.metrics['responses_received'] / max(self.metrics['requests_sent'], 1)) * 100,
                'average_response_time': self.metrics['average_response_time']
            }
        }
    
    def __str__(self) -> str:
        """String representation"""
        stats = self.get_statistics()
        return f"CoreEngine(target={self.target.url}, urls={stats['discovery_stats']['crawled_urls']}, params={stats['parameter_stats']['total_parameters']}, vulns={stats['vulnerability_stats']['total_vulnerabilities']})"