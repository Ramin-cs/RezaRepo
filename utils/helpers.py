"""
توابع کمکی برای ARAT
"""

import re
import socket
import asyncio
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse
import logging


def print_banner():
    """نمایش بنر ARAT"""
    banner = """
    ╔══════════════════════════════════════════════════════════════╗
    ║                                                              ║
    ║        █████╗ ██████╗  █████╗ ████████╗                    ║
    ║       ██╔══██╗██╔══██╗██╔══██╗╚══██╔══╝                    ║
    ║       ███████║██████╔╝███████║   ██║                       ║
    ║       ██╔══██║██╔══██╗██╔══██║   ██║                       ║
    ║       ██║  ██║██║  ██║██║  ██║   ██║                       ║
    ║       ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝                       ║
    ║                                                              ║
    ║           Advanced Reconnaissance & Assessment Tool          ║
    ║                        Version 1.0                          ║
    ║                                                              ║
    ╚══════════════════════════════════════════════════════════════╝
    """
    print(banner)


def validate_target(target: str) -> bool:
    """اعتبارسنجی هدف"""
    try:
        # الگوهای مختلف برای هدف
        patterns = [
            r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$',  # domain
            r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$',  # IPv4
            r'^[0-9a-fA-F]{1,4}(:[0-9a-fA-F]{1,4}){7}$',  # IPv6
        ]
        
        return any(re.match(pattern, target) for pattern in patterns)
    except Exception:
        return False


def is_valid_domain(domain: str) -> bool:
    """بررسی معتبر بودن دامنه"""
    try:
        if not domain or len(domain) > 255:
            return False
        
        # بررسی ساختار دامنه
        if domain.endswith('.'):
            domain = domain[:-1]
        
        # تقسیم به قسمت‌ها
        parts = domain.split('.')
        if len(parts) < 2:
            return False
        
        # بررسی هر قسمت
        for part in parts:
            if not part or len(part) > 63:
                return False
            if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?$', part):
                return False
        
        return True
    except Exception:
        return False


def is_valid_ip(ip: str) -> bool:
    """بررسی معتبر بودن IP"""
    try:
        # IPv4
        if '.' in ip:
            parts = ip.split('.')
            if len(parts) != 4:
                return False
            for part in parts:
                try:
                    num = int(part)
                    if not 0 <= num <= 255:
                        return False
                except ValueError:
                    return False
            return True
        
        # IPv6
        elif ':' in ip:
            # بررسی ساده IPv6
            return len(ip) <= 39 and all(c in '0123456789abcdefABCDEF:' for c in ip)
        
        return False
    except Exception:
        return False


def is_valid_url(url: str) -> bool:
    """بررسی معتبر بودن URL"""
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except Exception:
        return False


async def resolve_domain(domain: str) -> List[str]:
    """حل DNS دامنه"""
    try:
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, socket.gethostbyname_ex, domain)
        return result[2]  # لیست IP ها
    except Exception as e:
        logging.error(f"خطا در حل DNS {domain}: {e}")
        return []


async def reverse_dns_lookup(ip: str) -> Optional[str]:
    """جستجوی معکوس DNS"""
    try:
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, socket.gethostbyaddr, ip)
        return result[0]
    except Exception as e:
        logging.error(f"خطا در جستجوی معکوس DNS {ip}: {e}")
        return None


def extract_domain_from_url(url: str) -> Optional[str]:
    """استخراج دامنه از URL"""
    try:
        parsed = urlparse(url)
        return parsed.netloc.lower()
    except Exception:
        return None


def normalize_domain(domain: str) -> str:
    """نرمال‌سازی دامنه"""
    try:
        domain = domain.lower().strip()
        if domain.startswith('www.'):
            domain = domain[4:]
        if domain.endswith('.'):
            domain = domain[:-1]
        return domain
    except Exception:
        return domain


def extract_subdomains_from_text(text: str, domain: str) -> List[str]:
    """استخراج ساب‌دامین‌ها از متن"""
    try:
        pattern = rf'[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?\.{re.escape(domain)}'
        matches = re.findall(pattern, text, re.IGNORECASE)
        
        # اضافه کردن دامنه اصلی به ساب‌دامین‌ها
        subdomains = [f"{match}.{domain}" for match in matches]
        
        # حذف تکراری‌ها
        return list(set(subdomains))
    except Exception:
        return []


def extract_ips_from_text(text: str) -> List[str]:
    """استخراج IP ها از متن"""
    try:
        # IPv4
        ipv4_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        ipv4_matches = re.findall(ipv4_pattern, text)
        
        # IPv6 (ساده)
        ipv6_pattern = r'\b[0-9a-fA-F]{1,4}(:[0-9a-fA-F]{1,4}){7}\b'
        ipv6_matches = re.findall(ipv6_pattern, text)
        
        return ipv4_matches + ipv6_matches
    except Exception:
        return []


def extract_emails_from_text(text: str) -> List[str]:
    """استخراج ایمیل‌ها از متن"""
    try:
        pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        matches = re.findall(pattern, text)
        return matches
    except Exception:
        return []


def extract_urls_from_text(text: str) -> List[str]:
    """استخراج URL ها از متن"""
    try:
        pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        matches = re.findall(pattern, text)
        return matches
    except Exception:
        return []


def calculate_hash(data: str) -> str:
    """محاسبه hash"""
    try:
        import hashlib
        return hashlib.md5(data.encode()).hexdigest()
    except Exception:
        return ""


def format_bytes(size: int) -> str:
    """فرمت کردن اندازه فایل"""
    try:
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024.0:
                return f"{size:.1f} {unit}"
            size /= 1024.0
        return f"{size:.1f} PB"
    except Exception:
        return "0 B"


def format_duration(seconds: float) -> str:
    """فرمت کردن مدت زمان"""
    try:
        if seconds < 60:
            return f"{seconds:.1f} ثانیه"
        elif seconds < 3600:
            minutes = seconds / 60
            return f"{minutes:.1f} دقیقه"
        else:
            hours = seconds / 3600
            return f"{hours:.1f} ساعت"
    except Exception:
        return "0 ثانیه"


def get_random_user_agent() -> str:
    """دریافت user agent تصادفی"""
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0",
    ]
    
    import random
    return random.choice(user_agents)


def sanitize_filename(filename: str) -> str:
    """پاکسازی نام فایل"""
    try:
        # حذف کاراکترهای غیرمجاز
        filename = re.sub(r'[<>:"/\\|?*]', '_', filename)
        # حذف فاصله‌های اضافی
        filename = re.sub(r'\s+', '_', filename)
        # محدود کردن طول
        if len(filename) > 100:
            filename = filename[:100]
        return filename
    except Exception:
        return "sanitized_filename"


def parse_cidr(cidr: str) -> List[str]:
    """تجزیه CIDR به لیست IP"""
    try:
        import ipaddress
        network = ipaddress.ip_network(cidr, strict=False)
        return [str(ip) for ip in network.hosts()]
    except Exception:
        return []


def is_private_ip(ip: str) -> bool:
    """بررسی IP خصوصی"""
    try:
        import ipaddress
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private
    except Exception:
        return False


def is_reserved_ip(ip: str) -> bool:
    """بررسی IP محفوظ"""
    try:
        import ipaddress
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_reserved
    except Exception:
        return False


def get_ip_info(ip: str) -> Dict[str, Any]:
    """دریافت اطلاعات IP"""
    try:
        import ipaddress
        ip_obj = ipaddress.ip_address(ip)
        
        return {
            'ip': ip,
            'version': ip_obj.version,
            'is_private': ip_obj.is_private,
            'is_reserved': ip_obj.is_reserved,
            'is_loopback': ip_obj.is_loopback,
            'is_multicast': ip_obj.is_multicast,
            'is_link_local': ip_obj.is_link_local
        }
    except Exception:
        return {'ip': ip, 'error': 'Invalid IP'}


def chunk_list(lst: List[Any], chunk_size: int) -> List[List[Any]]:
    """تقسیم لیست به قطعات کوچک‌تر"""
    try:
        return [lst[i:i + chunk_size] for i in range(0, len(lst), chunk_size)]
    except Exception:
        return [lst]


def merge_dicts(*dicts: Dict[str, Any]) -> Dict[str, Any]:
    """ترکیب چندین dictionary"""
    try:
        result = {}
        for d in dicts:
            result.update(d)
        return result
    except Exception:
        return {}


def deep_merge_dicts(dict1: Dict[str, Any], dict2: Dict[str, Any]) -> Dict[str, Any]:
    """ترکیب عمیق dictionary ها"""
    try:
        result = dict1.copy()
        
        for key, value in dict2.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = deep_merge_dicts(result[key], value)
            else:
                result[key] = value
        
        return result
    except Exception:
        return dict1


def flatten_dict(d: Dict[str, Any], parent_key: str = '', sep: str = '.') -> Dict[str, Any]:
    """تخت کردن dictionary"""
    try:
        items = []
        for k, v in d.items():
            new_key = f"{parent_key}{sep}{k}" if parent_key else k
            if isinstance(v, dict):
                items.extend(flatten_dict(v, new_key, sep=sep).items())
            else:
                items.append((new_key, v))
        return dict(items)
    except Exception:
        return d


def retry_on_exception(max_retries: int = 3, delay: float = 1.0):
    """دکوریتور برای retry در صورت خطا"""
    def decorator(func):
        async def wrapper(*args, **kwargs):
            for attempt in range(max_retries):
                try:
                    return await func(*args, **kwargs)
                except Exception as e:
                    if attempt == max_retries - 1:
                        raise e
                    await asyncio.sleep(delay * (2 ** attempt))  # exponential backoff
            return None
        return wrapper
    return decorator


def timeout_after(seconds: float):
    """دکوریتور برای timeout"""
    def decorator(func):
        async def wrapper(*args, **kwargs):
            return await asyncio.wait_for(func(*args, **kwargs), timeout=seconds)
        return wrapper
    return decorator


class ProgressTracker:
    """ردیابی پیشرفت"""
    
    def __init__(self, total: int, description: str = "Processing"):
        self.total = total
        self.current = 0
        self.description = description
        self.start_time = None
    
    def start(self):
        """شروع ردیابی"""
        import time
        self.start_time = time.time()
    
    def update(self, increment: int = 1):
        """به‌روزرسانی پیشرفت"""
        self.current += increment
    
    def get_progress(self) -> Dict[str, Any]:
        """دریافت وضعیت پیشرفت"""
        import time
        
        if not self.start_time:
            return {'current': self.current, 'total': self.total, 'percentage': 0}
        
        elapsed = time.time() - self.start_time
        percentage = (self.current / self.total) * 100 if self.total > 0 else 0
        
        if self.current > 0:
            eta = (elapsed / self.current) * (self.total - self.current)
        else:
            eta = 0
        
        return {
            'current': self.current,
            'total': self.total,
            'percentage': percentage,
            'elapsed': elapsed,
            'eta': eta,
            'description': self.description
        }
    
    def is_complete(self) -> bool:
        """بررسی تکمیل"""
        return self.current >= self.total