"""
سیستم لاگ گیری پیشرفته برای ARAT
"""

import logging
import logging.handlers
import sys
from pathlib import Path
from typing import Optional
import json
from datetime import datetime
import colorama
from colorama import Fore, Back, Style
from loguru import logger
import threading


class ColoredFormatter(logging.Formatter):
    """فرمت کننده رنگی برای لاگ‌ها"""
    
    COLORS = {
        'DEBUG': Fore.CYAN,
        'INFO': Fore.GREEN,
        'WARNING': Fore.YELLOW,
        'ERROR': Fore.RED,
        'CRITICAL': Fore.RED + Back.WHITE + Style.BRIGHT,
    }
    
    def __init__(self, fmt: str = None):
        super().__init__(fmt)
        colorama.init(autoreset=True)
    
    def format(self, record):
        # اضافه کردن رنگ به level name
        if record.levelname in self.COLORS:
            record.levelname = f"{self.COLORS[record.levelname]}{record.levelname}{Style.RESET_ALL}"
        
        # اضافه کردن رنگ به پیام
        if record.levelname.startswith('\x1b[31m'):  # ERROR or CRITICAL
            record.msg = f"{Fore.RED}{record.msg}{Style.RESET_ALL}"
        elif record.levelname.startswith('\x1b[33m'):  # WARNING
            record.msg = f"{Fore.YELLOW}{record.msg}{Style.RESET_ALL}"
        elif record.levelname.startswith('\x1b[32m'):  # INFO
            record.msg = f"{Fore.GREEN}{record.msg}{Style.RESET_ALL}"
        elif record.levelname.startswith('\x1b[36m'):  # DEBUG
            record.msg = f"{Fore.CYAN}{record.msg}{Style.RESET_ALL}"
        
        return super().format(record)


class JSONFormatter(logging.Formatter):
    """فرمت کننده JSON برای لاگ‌ها"""
    
    def format(self, record):
        log_entry = {
            'timestamp': datetime.fromtimestamp(record.created).isoformat(),
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno,
            'thread': threading.current_thread().name,
            'process': record.process,
        }
        
        # اضافه کردن exception info اگر وجود دارد
        if record.exc_info:
            log_entry['exception'] = self.formatException(record.exc_info)
        
        # اضافه کردن extra fields
        if hasattr(record, 'extra_fields'):
            log_entry.update(record.extra_fields)
        
        return json.dumps(log_entry, ensure_ascii=False)


class PhaseFilter(logging.Filter):
    """فیلتر برای لاگ‌های فازها"""
    
    def __init__(self, phase_number: Optional[int] = None):
        super().__init__()
        self.phase_number = phase_number
    
    def filter(self, record):
        if self.phase_number is None:
            return True
        
        # بررسی اگر لاگ مربوط به فاز مشخص است
        if hasattr(record, 'phase_number'):
            return record.phase_number == self.phase_number
        
        return True


class TargetFilter(logging.Filter):
    """فیلتر برای لاگ‌های هدف مشخص"""
    
    def __init__(self, target: Optional[str] = None):
        super().__init__()
        self.target = target
    
    def filter(self, record):
        if self.target is None:
            return True
        
        # بررسی اگر لاگ مربوط به هدف مشخص است
        if hasattr(record, 'target'):
            return record.target == self.target
        
        return True


class LogManager:
    """مدیر لاگ‌ها"""
    
    def __init__(self, config):
        self.config = config
        self.loggers = {}
        self._setup_main_logger()
    
    def _setup_main_logger(self):
        """تنظیم لاگر اصلی"""
        # ایجاد دایرکتوری لاگ
        log_dir = Path(self.config.logging.file_path).parent
        log_dir.mkdir(parents=True, exist_ok=True)
        
        # تنظیم سطح لاگ
        level = getattr(logging, self.config.logging.level.upper(), logging.INFO)
        
        # ایجاد logger اصلی
        main_logger = logging.getLogger('arat')
        main_logger.setLevel(level)
        
        # حذف handlers موجود
        for handler in main_logger.handlers[:]:
            main_logger.removeHandler(handler)
        
        # Handler برای فایل
        file_handler = logging.handlers.RotatingFileHandler(
            self.config.logging.file_path,
            maxBytes=self.config.logging.max_size,
            backupCount=self.config.logging.backup_count,
            encoding='utf-8'
        )
        file_handler.setLevel(level)
        
        # فرمت برای فایل (JSON)
        file_formatter = JSONFormatter()
        file_handler.setFormatter(file_formatter)
        
        main_logger.addHandler(file_handler)
        
        # Handler برای کنسول
        if self.config.logging.enable_console:
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setLevel(level)
            
            # فرمت برای کنسول (رنگی)
            console_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            console_formatter = ColoredFormatter(console_format)
            console_handler.setFormatter(console_formatter)
            
            main_logger.addHandler(console_handler)
        
        # Handler برای فایل جداگانه errors
        error_handler = logging.handlers.RotatingFileHandler(
            str(log_dir / 'errors.log'),
            maxBytes=self.config.logging.max_size,
            backupCount=self.config.logging.backup_count,
            encoding='utf-8'
        )
        error_handler.setLevel(logging.ERROR)
        error_handler.setFormatter(file_formatter)
        error_handler.addFilter(lambda record: record.levelno >= logging.ERROR)
        
        main_logger.addHandler(error_handler)
        
        self.loggers['main'] = main_logger
    
    def get_logger(self, name: str, phase_number: Optional[int] = None, target: Optional[str] = None) -> logging.Logger:
        """دریافت لاگر برای نام مشخص"""
        logger_key = f"{name}_{phase_number}_{target}" if phase_number or target else name
        
        if logger_key not in self.loggers:
            logger = logging.getLogger(f'arat.{name}')
            logger.setLevel(getattr(logging, self.config.logging.level.upper(), logging.INFO))
            
            # اضافه کردن فیلترها
            if phase_number is not None:
                logger.addFilter(PhaseFilter(phase_number))
            
            if target is not None:
                logger.addFilter(TargetFilter(target))
            
            self.loggers[logger_key] = logger
        
        return self.loggers[logger_key]
    
    def get_phase_logger(self, phase_number: int, target: str) -> logging.Logger:
        """دریافت لاگر مخصوص فاز"""
        return self.get_logger(f'phase_{phase_number}', phase_number, target)
    
    def get_web_logger(self) -> logging.Logger:
        """دریافت لاگر مخصوص پنل وب"""
        return self.get_logger('web')
    
    def get_api_logger(self) -> logging.Logger:
        """دریافت لاگر مخصوص API"""
        return self.get_logger('api')
    
    def get_database_logger(self) -> logging.Logger:
        """دریافت لاگر مخصوص دیتابیس"""
        return self.get_logger('database')


class LogContext:
    """Context manager برای لاگ‌گیری با اطلاعات اضافی"""
    
    def __init__(self, logger: logging.Logger, **extra_fields):
        self.logger = logger
        self.extra_fields = extra_fields
        self.start_time = None
    
    def __enter__(self):
        self.start_time = datetime.now()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        duration = (datetime.now() - self.start_time).total_seconds()
        
        if exc_type is None:
            self.logger.info(
                f"عملیات با موفقیت تکمیل شد - مدت زمان: {duration:.2f} ثانیه",
                extra={'extra_fields': {**self.extra_fields, 'duration': duration}}
            )
        else:
            self.logger.error(
                f"خطا در عملیات: {exc_val} - مدت زمان: {duration:.2f} ثانیه",
                extra={'extra_fields': {**self.extra_fields, 'duration': duration, 'exception': str(exc_val)}},
                exc_info=True
            )
    
    def info(self, message: str, **kwargs):
        """لاگ info با اطلاعات اضافی"""
        extra_fields = {**self.extra_fields, **kwargs}
        self.logger.info(message, extra={'extra_fields': extra_fields})
    
    def warning(self, message: str, **kwargs):
        """لاگ warning با اطلاعات اضافی"""
        extra_fields = {**self.extra_fields, **kwargs}
        self.logger.warning(message, extra={'extra_fields': extra_fields})
    
    def error(self, message: str, **kwargs):
        """لاگ error با اطلاعات اضافی"""
        extra_fields = {**self.extra_fields, **kwargs}
        self.logger.error(message, extra={'extra_fields': extra_fields})
    
    def debug(self, message: str, **kwargs):
        """لاگ debug با اطلاعات اضافی"""
        extra_fields = {**self.extra_fields, **kwargs}
        self.logger.debug(message, extra={'extra_fields': extra_fields})


def setup_logger(config) -> LogManager:
    """تنظیم سیستم لاگ‌گیری"""
    return LogManager(config)


def get_logger(name: str = 'arat') -> logging.Logger:
    """دریافت لاگر"""
    return logging.getLogger(name)


def log_execution_time(func):
    """دکوریتور برای لاگ زمان اجرای تابع"""
    def wrapper(*args, **kwargs):
        logger = get_logger()
        start_time = datetime.now()
        
        try:
            result = func(*args, **kwargs)
            duration = (datetime.now() - start_time).total_seconds()
            logger.info(f"تابع {func.__name__} در {duration:.2f} ثانیه تکمیل شد")
            return result
        except Exception as e:
            duration = (datetime.now() - start_time).total_seconds()
            logger.error(f"خطا در تابع {func.__name__} بعد از {duration:.2f} ثانیه: {e}")
            raise
    
    return wrapper


def log_async_execution_time(func):
    """دکوریتور برای لاگ زمان اجرای تابع async"""
    async def wrapper(*args, **kwargs):
        logger = get_logger()
        start_time = datetime.now()
        
        try:
            result = await func(*args, **kwargs)
            duration = (datetime.now() - start_time).total_seconds()
            logger.info(f"تابع async {func.__name__} در {duration:.2f} ثانیه تکمیل شد")
            return result
        except Exception as e:
            duration = (datetime.now() - start_time).total_seconds()
            logger.error(f"خطا در تابع async {func.__name__} بعد از {duration:.2f} ثانیه: {e}")
            raise
    
    return wrapper


class LogBuffer:
    """بافر برای ذخیره لاگ‌ها در حافظه"""
    
    def __init__(self, max_size: int = 1000):
        self.max_size = max_size
        self.buffer = []
        self.lock = threading.Lock()
    
    def add(self, log_entry: dict):
        """اضافه کردن لاگ به بافر"""
        with self.lock:
            self.buffer.append(log_entry)
            if len(self.buffer) > self.max_size:
                self.buffer.pop(0)
    
    def get_logs(self, level: Optional[str] = None, limit: Optional[int] = None) -> list:
        """دریافت لاگ‌ها از بافر"""
        with self.lock:
            logs = self.buffer.copy()
        
        if level:
            logs = [log for log in logs if log.get('level') == level]
        
        if limit:
            logs = logs[-limit:]
        
        return logs
    
    def clear(self):
        """پاک کردن بافر"""
        with self.lock:
            self.buffer.clear()
    
    def size(self) -> int:
        """اندازه بافر"""
        with self.lock:
            return len(self.buffer)


# ایجاد instance جهانی
_log_manager = None


def init_logging(config):
    """مقداردهی اولیه سیستم لاگ‌گیری"""
    global _log_manager
    _log_manager = setup_logger(config)
    return _log_manager


def get_log_manager() -> LogManager:
    """دریافت LogManager جهانی"""
    if _log_manager is None:
        raise RuntimeError("سیستم لاگ‌گیری مقداردهی نشده است")
    return _log_manager