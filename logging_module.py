"""
Advanced Logging Module for Open Redirect Scanner
Comprehensive logging system with multiple output formats
"""

import logging
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any
import json
import traceback

class LoggingModule:
    """
    Advanced logging module with multiple output formats and levels
    """
    
    def __init__(self, output_dir: Path, log_level: str = "INFO"):
        self.output_dir = output_dir
        self.log_level = log_level
        self.logger = None
        self.log_file = None
        self.error_log_file = None
        self.debug_log_file = None
        
        # Create logs directory
        self.logs_dir = output_dir / "logs"
        self.logs_dir.mkdir(exist_ok=True)
        
        # Initialize logging
        self._setup_logging()
    
    def _setup_logging(self):
        """Setup comprehensive logging system"""
        try:
            # Create logger
            self.logger = logging.getLogger('OpenRedirectScanner')
            self.logger.setLevel(getattr(logging, self.log_level.upper()))
            
            # Clear existing handlers
            self.logger.handlers.clear()
            
            # Create formatters
            detailed_formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
            
            simple_formatter = logging.Formatter(
                '%(asctime)s - %(levelname)s - %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
            
            # Console handler
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setLevel(logging.INFO)
            console_handler.setFormatter(simple_formatter)
            self.logger.addHandler(console_handler)
            
            # Main log file handler
            self.log_file = self.logs_dir / f"scanner_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
            file_handler = logging.FileHandler(self.log_file, encoding='utf-8')
            file_handler.setLevel(logging.DEBUG)
            file_handler.setFormatter(detailed_formatter)
            self.logger.addHandler(file_handler)
            
            # Error log file handler
            self.error_log_file = self.logs_dir / f"errors_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
            error_handler = logging.FileHandler(self.error_log_file, encoding='utf-8')
            error_handler.setLevel(logging.ERROR)
            error_handler.setFormatter(detailed_formatter)
            self.logger.addHandler(error_handler)
            
            # Debug log file handler
            self.debug_log_file = self.logs_dir / f"debug_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
            debug_handler = logging.FileHandler(self.debug_log_file, encoding='utf-8')
            debug_handler.setLevel(logging.DEBUG)
            debug_handler.setFormatter(detailed_formatter)
            self.logger.addHandler(debug_handler)
            
            # Prevent duplicate logs
            self.logger.propagate = False
            
            self.info("Logging system initialized successfully")
            
        except Exception as e:
            print(f"Failed to setup logging: {str(e)}")
            sys.exit(1)
    
    def info(self, message: str, extra_data: Optional[Dict[str, Any]] = None):
        """Log info message"""
        self._log(logging.INFO, message, extra_data)
    
    def warning(self, message: str, extra_data: Optional[Dict[str, Any]] = None):
        """Log warning message"""
        self._log(logging.WARNING, message, extra_data)
    
    def error(self, message: str, extra_data: Optional[Dict[str, Any]] = None, exc_info: bool = False):
        """Log error message"""
        self._log(logging.ERROR, message, extra_data, exc_info)
    
    def debug(self, message: str, extra_data: Optional[Dict[str, Any]] = None):
        """Log debug message"""
        self._log(logging.DEBUG, message, extra_data)
    
    def critical(self, message: str, extra_data: Optional[Dict[str, Any]] = None, exc_info: bool = False):
        """Log critical message"""
        self._log(logging.CRITICAL, message, extra_data, exc_info)
    
    def _log(self, level: int, message: str, extra_data: Optional[Dict[str, Any]] = None, exc_info: bool = False):
        """Internal logging method"""
        try:
            if extra_data:
                message = f"{message} | Extra: {json.dumps(extra_data, default=str)}"
            
            if exc_info:
                self.logger.log(level, message, exc_info=True)
            else:
                self.logger.log(level, message)
                
        except Exception as e:
            print(f"Logging error: {str(e)}")
    
    def log_scan_start(self, target_url: str, scan_id: str):
        """Log scan start"""
        self.info(f"Scan started", {
            'target_url': target_url,
            'scan_id': scan_id,
            'timestamp': datetime.now().isoformat()
        })
    
    def log_scan_end(self, scan_id: str, vulnerabilities_found: int, total_tests: int):
        """Log scan end"""
        self.info(f"Scan completed", {
            'scan_id': scan_id,
            'vulnerabilities_found': vulnerabilities_found,
            'total_tests': total_tests,
            'timestamp': datetime.now().isoformat()
        })
    
    def log_recon_phase(self, phase: str, urls_found: int, parameters_found: int):
        """Log reconnaissance phase"""
        self.info(f"Reconnaissance phase: {phase}", {
            'phase': phase,
            'urls_found': urls_found,
            'parameters_found': parameters_found
        })
    
    def log_payload_test(self, payload: str, injection_point: str, result: str, redirect_url: Optional[str] = None):
        """Log payload test result"""
        self.info(f"Payload test: {result}", {
            'payload': payload,
            'injection_point': injection_point,
            'result': result,
            'redirect_url': redirect_url
        })
    
    def log_vulnerability_found(self, vulnerability: Dict):
        """Log vulnerability found"""
        self.warning(f"Vulnerability found: {vulnerability.get('url', 'Unknown')}", {
            'vulnerability': vulnerability
        })
    
    def log_chrome_error(self, error: str, url: str):
        """Log Chrome automation error"""
        self.error(f"Chrome automation error: {error}", {
            'error': error,
            'url': url
        })
    
    def log_network_error(self, error: str, url: str, status_code: Optional[int] = None):
        """Log network error"""
        self.error(f"Network error: {error}", {
            'error': error,
            'url': url,
            'status_code': status_code
        })
    
    def log_waf_bypass(self, technique: str, payload: str, success: bool):
        """Log WAF bypass attempt"""
        self.debug(f"WAF bypass attempt: {technique}", {
            'technique': technique,
            'payload': payload,
            'success': success
        })
    
    def log_parallel_processing(self, thread_id: int, task: str, status: str):
        """Log parallel processing activity"""
        self.debug(f"Thread {thread_id}: {task} - {status}", {
            'thread_id': thread_id,
            'task': task,
            'status': status
        })
    
    def log_performance_metric(self, metric_name: str, value: float, unit: str = "seconds"):
        """Log performance metric"""
        self.info(f"Performance metric: {metric_name} = {value} {unit}", {
            'metric_name': metric_name,
            'value': value,
            'unit': unit
        })
    
    def log_configuration(self, config: Dict):
        """Log configuration"""
        self.info("Configuration loaded", {
            'config': config
        })
    
    def log_exception(self, exception: Exception, context: str = ""):
        """Log exception with full traceback"""
        self.error(f"Exception in {context}: {str(exception)}", {
            'exception_type': type(exception).__name__,
            'exception_message': str(exception),
            'context': context,
            'traceback': traceback.format_exc()
        }, exc_info=True)
    
    def get_log_files(self) -> Dict[str, str]:
        """Get log file paths"""
        return {
            'main_log': str(self.log_file) if self.log_file else None,
            'error_log': str(self.error_log_file) if self.error_log_file else None,
            'debug_log': str(self.debug_log_file) if self.debug_log_file else None
        }
    
    def cleanup_old_logs(self, days_to_keep: int = 7):
        """Cleanup old log files"""
        try:
            import time
            current_time = time.time()
            cutoff_time = current_time - (days_to_keep * 24 * 60 * 60)
            
            for log_file in self.logs_dir.glob("*.log"):
                if log_file.stat().st_mtime < cutoff_time:
                    log_file.unlink()
                    self.info(f"Deleted old log file: {log_file}")
                    
        except Exception as e:
            self.error(f"Error cleaning up old logs: {str(e)}")
    
    def export_logs_to_json(self, output_file: Optional[Path] = None) -> str:
        """Export logs to JSON format"""
        try:
            if not output_file:
                output_file = self.logs_dir / f"logs_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            
            logs_data = {
                'export_timestamp': datetime.now().isoformat(),
                'log_files': self.get_log_files(),
                'scan_summary': {
                    'total_logs': 0,
                    'info_logs': 0,
                    'warning_logs': 0,
                    'error_logs': 0,
                    'debug_logs': 0
                }
            }
            
            # Count log entries (simplified)
            if self.log_file and self.log_file.exists():
                with open(self.log_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                    logs_data['scan_summary']['total_logs'] = content.count('\n')
                    logs_data['scan_summary']['info_logs'] = content.count(' - INFO -')
                    logs_data['scan_summary']['warning_logs'] = content.count(' - WARNING -')
                    logs_data['scan_summary']['error_logs'] = content.count(' - ERROR -')
                    logs_data['scan_summary']['debug_logs'] = content.count(' - DEBUG -')
            
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(logs_data, f, indent=2, ensure_ascii=False)
            
            self.info(f"Logs exported to JSON: {output_file}")
            return str(output_file)
            
        except Exception as e:
            self.error(f"Error exporting logs to JSON: {str(e)}")
            return ""
    
    def get_scan_statistics(self) -> Dict[str, Any]:
        """Get scan statistics from logs"""
        try:
            stats = {
                'total_logs': 0,
                'vulnerabilities_found': 0,
                'payloads_tested': 0,
                'errors_encountered': 0,
                'scan_duration': 0,
                'start_time': None,
                'end_time': None
            }
            
            if self.log_file and self.log_file.exists():
                with open(self.log_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                    
                    stats['total_logs'] = content.count('\n')
                    stats['vulnerabilities_found'] = content.count('Vulnerability found')
                    stats['payloads_tested'] = content.count('Payload test')
                    stats['errors_encountered'] = content.count(' - ERROR -')
                    
                    # Extract start and end times
                    lines = content.split('\n')
                    for line in lines:
                        if 'Scan started' in line:
                            stats['start_time'] = line.split(' - ')[0]
                        elif 'Scan completed' in line:
                            stats['end_time'] = line.split(' - ')[0]
            
            return stats
            
        except Exception as e:
            self.error(f"Error getting scan statistics: {str(e)}")
            return {}