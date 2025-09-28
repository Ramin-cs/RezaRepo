"""
Configuration module for Open Redirect Scanner
Centralized configuration management
"""

import os
import json
from pathlib import Path
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, asdict

@dataclass
class ScannerConfig:
    """Scanner configuration class"""
    
    # Basic settings
    target_url: str = ""
    output_dir: str = "scan_results"
    max_threads: int = 10
    max_depth: int = 3
    timeout: int = 30
    
    # Chrome settings
    chrome_headless: bool = True
    chrome_window_size: str = "1920,1080"
    chrome_user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    
    # Scanning settings
    enable_recon: bool = True
    enable_payload_testing: bool = True
    enable_screenshot: bool = True
    enable_parallel_processing: bool = True
    
    # Payload settings
    max_payloads_per_parameter: int = 100
    enable_waf_bypass: bool = True
    custom_payload_file: Optional[str] = None
    
    # Logging settings
    log_level: str = "INFO"
    log_to_file: bool = True
    log_to_console: bool = True
    log_rotation: bool = True
    max_log_size: int = 10 * 1024 * 1024  # 10MB
    backup_count: int = 5
    
    # Report settings
    generate_html_report: bool = True
    generate_json_report: bool = True
    include_screenshots: bool = True
    report_template: str = "default"
    
    # Security settings
    respect_robots_txt: bool = True
    max_requests_per_second: int = 10
    delay_between_requests: float = 0.1
    
    # WAF bypass settings
    enable_encoding_bypass: bool = True
    enable_case_variations: bool = True
    enable_whitespace_variations: bool = True
    enable_control_characters: bool = True
    enable_unicode_attacks: bool = True
    
    # Target domain for redirect validation
    target_domain: str = "google.com"
    
    # Custom headers
    custom_headers: Dict[str, str] = None
    
    # Custom cookies
    custom_cookies: Dict[str, str] = None
    
    # Proxy settings
    proxy_url: Optional[str] = None
    proxy_username: Optional[str] = None
    proxy_password: Optional[str] = None
    
    def __post_init__(self):
        """Post-initialization processing"""
        if self.custom_headers is None:
            self.custom_headers = {}
        if self.custom_cookies is None:
            self.custom_cookies = {}

class ConfigManager:
    """Configuration manager class"""
    
    def __init__(self, config_file: Optional[str] = None):
        self.config_file = config_file or "scanner_config.json"
        self.config = ScannerConfig()
    
    def load_config(self, config_file: Optional[str] = None) -> ScannerConfig:
        """Load configuration from file"""
        if config_file:
            self.config_file = config_file
        
        if Path(self.config_file).exists():
            try:
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    config_data = json.load(f)
                
                # Update config with loaded data
                for key, value in config_data.items():
                    if hasattr(self.config, key):
                        setattr(self.config, key, value)
                
                print(f"✅ Configuration loaded from {self.config_file}")
                
            except Exception as e:
                print(f"⚠️ Error loading config file: {str(e)}")
                print("Using default configuration")
        else:
            print(f"ℹ️ Config file {self.config_file} not found, using default configuration")
        
        return self.config
    
    def save_config(self, config: ScannerConfig, config_file: Optional[str] = None) -> bool:
        """Save configuration to file"""
        if config_file:
            self.config_file = config_file
        
        try:
            config_data = asdict(config)
            
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(config_data, f, indent=2, ensure_ascii=False)
            
            print(f"✅ Configuration saved to {self.config_file}")
            return True
            
        except Exception as e:
            print(f"❌ Error saving config file: {str(e)}")
            return False
    
    def create_default_config(self, config_file: str = "scanner_config.json") -> bool:
        """Create default configuration file"""
        try:
            default_config = ScannerConfig()
            return self.save_config(default_config, config_file)
        except Exception as e:
            print(f"❌ Error creating default config: {str(e)}")
            return False
    
    def validate_config(self, config: ScannerConfig) -> List[str]:
        """Validate configuration and return list of issues"""
        issues = []
        
        # Validate basic settings
        if not config.target_url:
            issues.append("Target URL is required")
        
        if config.max_threads < 1:
            issues.append("Max threads must be at least 1")
        
        if config.max_depth < 1:
            issues.append("Max depth must be at least 1")
        
        if config.timeout < 1:
            issues.append("Timeout must be at least 1 second")
        
        # Validate Chrome settings
        if not config.chrome_window_size or ',' not in config.chrome_window_size:
            issues.append("Chrome window size must be in format 'width,height'")
        
        # Validate payload settings
        if config.max_payloads_per_parameter < 1:
            issues.append("Max payloads per parameter must be at least 1")
        
        # Validate logging settings
        valid_log_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
        if config.log_level.upper() not in valid_log_levels:
            issues.append(f"Log level must be one of: {', '.join(valid_log_levels)}")
        
        # Validate security settings
        if config.max_requests_per_second < 1:
            issues.append("Max requests per second must be at least 1")
        
        if config.delay_between_requests < 0:
            issues.append("Delay between requests must be non-negative")
        
        return issues
    
    def get_config_summary(self, config: ScannerConfig) -> Dict[str, Any]:
        """Get configuration summary"""
        return {
            'target_url': config.target_url,
            'output_dir': config.output_dir,
            'max_threads': config.max_threads,
            'max_depth': config.max_depth,
            'timeout': config.timeout,
            'chrome_headless': config.chrome_headless,
            'enable_recon': config.enable_recon,
            'enable_payload_testing': config.enable_payload_testing,
            'enable_screenshot': config.enable_screenshot,
            'enable_parallel_processing': config.enable_parallel_processing,
            'max_payloads_per_parameter': config.max_payloads_per_parameter,
            'enable_waf_bypass': config.enable_waf_bypass,
            'log_level': config.log_level,
            'generate_html_report': config.generate_html_report,
            'generate_json_report': config.generate_json_report,
            'respect_robots_txt': config.respect_robots_txt,
            'max_requests_per_second': config.max_requests_per_second,
            'delay_between_requests': config.delay_between_requests,
            'target_domain': config.target_domain
        }

# Environment variable configuration
def load_config_from_env() -> ScannerConfig:
    """Load configuration from environment variables"""
    config = ScannerConfig()
    
    # Basic settings
    if os.getenv('TARGET_URL'):
        config.target_url = os.getenv('TARGET_URL')
    
    if os.getenv('OUTPUT_DIR'):
        config.output_dir = os.getenv('OUTPUT_DIR')
    
    if os.getenv('MAX_THREADS'):
        try:
            config.max_threads = int(os.getenv('MAX_THREADS'))
        except ValueError:
            pass
    
    if os.getenv('MAX_DEPTH'):
        try:
            config.max_depth = int(os.getenv('MAX_DEPTH'))
        except ValueError:
            pass
    
    if os.getenv('TIMEOUT'):
        try:
            config.timeout = int(os.getenv('TIMEOUT'))
        except ValueError:
            pass
    
    # Chrome settings
    if os.getenv('CHROME_HEADLESS'):
        config.chrome_headless = os.getenv('CHROME_HEADLESS').lower() == 'true'
    
    if os.getenv('CHROME_WINDOW_SIZE'):
        config.chrome_window_size = os.getenv('CHROME_WINDOW_SIZE')
    
    if os.getenv('CHROME_USER_AGENT'):
        config.chrome_user_agent = os.getenv('CHROME_USER_AGENT')
    
    # Scanning settings
    if os.getenv('ENABLE_RECON'):
        config.enable_recon = os.getenv('ENABLE_RECON').lower() == 'true'
    
    if os.getenv('ENABLE_PAYLOAD_TESTING'):
        config.enable_payload_testing = os.getenv('ENABLE_PAYLOAD_TESTING').lower() == 'true'
    
    if os.getenv('ENABLE_SCREENSHOT'):
        config.enable_screenshot = os.getenv('ENABLE_SCREENSHOT').lower() == 'true'
    
    if os.getenv('ENABLE_PARALLEL_PROCESSING'):
        config.enable_parallel_processing = os.getenv('ENABLE_PARALLEL_PROCESSING').lower() == 'true'
    
    # Payload settings
    if os.getenv('MAX_PAYLOADS_PER_PARAMETER'):
        try:
            config.max_payloads_per_parameter = int(os.getenv('MAX_PAYLOADS_PER_PARAMETER'))
        except ValueError:
            pass
    
    if os.getenv('ENABLE_WAF_BYPASS'):
        config.enable_waf_bypass = os.getenv('ENABLE_WAF_BYPASS').lower() == 'true'
    
    if os.getenv('CUSTOM_PAYLOAD_FILE'):
        config.custom_payload_file = os.getenv('CUSTOM_PAYLOAD_FILE')
    
    # Logging settings
    if os.getenv('LOG_LEVEL'):
        config.log_level = os.getenv('LOG_LEVEL')
    
    if os.getenv('LOG_TO_FILE'):
        config.log_to_file = os.getenv('LOG_TO_FILE').lower() == 'true'
    
    if os.getenv('LOG_TO_CONSOLE'):
        config.log_to_console = os.getenv('LOG_TO_CONSOLE').lower() == 'true'
    
    # Report settings
    if os.getenv('GENERATE_HTML_REPORT'):
        config.generate_html_report = os.getenv('GENERATE_HTML_REPORT').lower() == 'true'
    
    if os.getenv('GENERATE_JSON_REPORT'):
        config.generate_json_report = os.getenv('GENERATE_JSON_REPORT').lower() == 'true'
    
    if os.getenv('INCLUDE_SCREENSHOTS'):
        config.include_screenshots = os.getenv('INCLUDE_SCREENSHOTS').lower() == 'true'
    
    # Security settings
    if os.getenv('RESPECT_ROBOTS_TXT'):
        config.respect_robots_txt = os.getenv('RESPECT_ROBOTS_TXT').lower() == 'true'
    
    if os.getenv('MAX_REQUESTS_PER_SECOND'):
        try:
            config.max_requests_per_second = int(os.getenv('MAX_REQUESTS_PER_SECOND'))
        except ValueError:
            pass
    
    if os.getenv('DELAY_BETWEEN_REQUESTS'):
        try:
            config.delay_between_requests = float(os.getenv('DELAY_BETWEEN_REQUESTS'))
        except ValueError:
            pass
    
    # WAF bypass settings
    if os.getenv('ENABLE_ENCODING_BYPASS'):
        config.enable_encoding_bypass = os.getenv('ENABLE_ENCODING_BYPASS').lower() == 'true'
    
    if os.getenv('ENABLE_CASE_VARIATIONS'):
        config.enable_case_variations = os.getenv('ENABLE_CASE_VARIATIONS').lower() == 'true'
    
    if os.getenv('ENABLE_WHITESPACE_VARIATIONS'):
        config.enable_whitespace_variations = os.getenv('ENABLE_WHITESPACE_VARIATIONS').lower() == 'true'
    
    if os.getenv('ENABLE_CONTROL_CHARACTERS'):
        config.enable_control_characters = os.getenv('ENABLE_CONTROL_CHARACTERS').lower() == 'true'
    
    if os.getenv('ENABLE_UNICODE_ATTACKS'):
        config.enable_unicode_attacks = os.getenv('ENABLE_UNICODE_ATTACKS').lower() == 'true'
    
    # Target domain
    if os.getenv('TARGET_DOMAIN'):
        config.target_domain = os.getenv('TARGET_DOMAIN')
    
    # Proxy settings
    if os.getenv('PROXY_URL'):
        config.proxy_url = os.getenv('PROXY_URL')
    
    if os.getenv('PROXY_USERNAME'):
        config.proxy_username = os.getenv('PROXY_USERNAME')
    
    if os.getenv('PROXY_PASSWORD'):
        config.proxy_password = os.getenv('PROXY_PASSWORD')
    
    return config

# Default configuration presets
def get_preset_config(preset: str) -> ScannerConfig:
    """Get configuration preset"""
    presets = {
        'fast': ScannerConfig(
            max_threads=20,
            max_depth=1,
            timeout=10,
            max_payloads_per_parameter=50,
            delay_between_requests=0.05
        ),
        'thorough': ScannerConfig(
            max_threads=5,
            max_depth=5,
            timeout=60,
            max_payloads_per_parameter=200,
            delay_between_requests=0.2
        ),
        'stealth': ScannerConfig(
            max_threads=1,
            max_depth=2,
            timeout=30,
            max_payloads_per_parameter=100,
            delay_between_requests=1.0,
            max_requests_per_second=2
        ),
        'debug': ScannerConfig(
            max_threads=1,
            max_depth=1,
            timeout=60,
            max_payloads_per_parameter=10,
            log_level='DEBUG',
            enable_screenshot=False
        )
    }
    
    return presets.get(preset, ScannerConfig())

# Configuration validation
def validate_and_fix_config(config: ScannerConfig) -> ScannerConfig:
    """Validate and fix configuration issues"""
    issues = ConfigManager().validate_config(config)
    
    if issues:
        print("⚠️ Configuration issues found:")
        for issue in issues:
            print(f"  - {issue}")
        print("Using default values for invalid settings")
    
    # Fix common issues
    if config.max_threads < 1:
        config.max_threads = 1
    
    if config.max_depth < 1:
        config.max_depth = 1
    
    if config.timeout < 1:
        config.timeout = 30
    
    if config.max_payloads_per_parameter < 1:
        config.max_payloads_per_parameter = 100
    
    if config.delay_between_requests < 0:
        config.delay_between_requests = 0.1
    
    if config.max_requests_per_second < 1:
        config.max_requests_per_second = 10
    
    return config