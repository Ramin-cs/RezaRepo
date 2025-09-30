#!/usr/bin/env python3
"""
Configuration Manager for ARAT
Handles API keys, settings, and configuration management
"""

import json
import os
from typing import Dict, Any, Optional
from pathlib import Path

class ConfigManager:
    """Configuration Manager for ARAT"""
    
    def __init__(self, config_dir: str = "/workspace/config"):
        self.config_dir = Path(config_dir)
        self.config_dir.mkdir(exist_ok=True)
        
        self.api_keys_file = self.config_dir / "api_keys.json"
        self.settings_file = self.config_dir / "settings.json"
        
        # Initialize default configs
        self._init_default_configs()
    
    def _init_default_configs(self):
        """Initialize default configuration files"""
        # Default API keys structure
        if not self.api_keys_file.exists():
            default_api_keys = {
                "github": {
                    "api_key": "",
                    "username": "",
                    "token": "",
                    "description": "GitHub API key for repository analysis and code scanning"
                },
                "securitytrails": {
                    "api_key": "",
                    "description": "SecurityTrails API key for historical DNS and subdomain data"
                },
                "shodan": {
                    "api_key": "",
                    "description": "Shodan API key for device and service discovery"
                },
                "censys": {
                    "api_id": "",
                    "api_secret": "",
                    "description": "Censys API credentials for certificate and host data"
                },
                "virustotal": {
                    "api_key": "",
                    "description": "VirusTotal API key for threat intelligence"
                },
                "threatcrowd": {
                    "api_key": "",
                    "description": "ThreatCrowd API key for threat intelligence"
                },
                "passivetotal": {
                    "username": "",
                    "api_key": "",
                    "description": "PassiveTotal API credentials for passive DNS data"
                },
                "dnsdb": {
                    "api_key": "",
                    "description": "DNSDB API key for DNS historical data"
                },
                "crtsh": {
                    "api_key": "",
                    "description": "crt.sh API key for certificate transparency data"
                },
                "wayback": {
                    "api_key": "",
                    "description": "Wayback Machine API key for historical web data"
                }
            }
            self.save_api_keys(default_api_keys)
        
        # Default settings
        if not self.settings_file.exists():
            default_settings = {
                "general": {
                    "max_workers": 50,
                    "timeout": 30,
                    "enable_parallel": True,
                    "cross_platform": True,
                    "live_output": True
                },
                "phases": {
                    "enable_all": True,
                    "custom_phases": [],
                    "skip_phases": [],
                    "phase_timeout": 300
                },
                "tools": {
                    "enable_external_tools": True,
                    "tools_path": "/usr/local/bin",
                    "wordlists_path": "/usr/share/wordlists"
                },
                "output": {
                    "save_results": True,
                    "results_format": "json",
                    "verbose_output": True,
                    "live_updates": True
                },
                "security": {
                    "rate_limit": True,
                    "max_requests_per_second": 10,
                    "user_agent_rotation": True,
                    "proxy_support": False
                }
            }
            self.save_settings(default_settings)
    
    def load_api_keys(self) -> Dict[str, Any]:
        """Load API keys from config file"""
        try:
            with open(self.api_keys_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"Error loading API keys: {e}")
            return {}
    
    def save_api_keys(self, api_keys: Dict[str, Any]) -> bool:
        """Save API keys to config file"""
        try:
            with open(self.api_keys_file, 'w') as f:
                json.dump(api_keys, f, indent=2)
            return True
        except Exception as e:
            print(f"Error saving API keys: {e}")
            return False
    
    def get_api_key(self, service: str) -> Optional[str]:
        """Get API key for a specific service"""
        api_keys = self.load_api_keys()
        if service in api_keys:
            return api_keys[service].get('api_key', '')
        return None
    
    def set_api_key(self, service: str, api_key: str) -> bool:
        """Set API key for a specific service"""
        api_keys = self.load_api_keys()
        if service in api_keys:
            api_keys[service]['api_key'] = api_key
            return self.save_api_keys(api_keys)
        return False
    
    def load_settings(self) -> Dict[str, Any]:
        """Load settings from config file"""
        try:
            with open(self.settings_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"Error loading settings: {e}")
            return {}
    
    def save_settings(self, settings: Dict[str, Any]) -> bool:
        """Save settings to config file"""
        try:
            with open(self.settings_file, 'w') as f:
                json.dump(settings, f, indent=2)
            return True
        except Exception as e:
            print(f"Error saving settings: {e}")
            return False
    
    def get_setting(self, section: str, key: str, default: Any = None) -> Any:
        """Get a specific setting value"""
        settings = self.load_settings()
        if section in settings and key in settings[section]:
            return settings[section][key]
        return default
    
    def set_setting(self, section: str, key: str, value: Any) -> bool:
        """Set a specific setting value"""
        settings = self.load_settings()
        if section not in settings:
            settings[section] = {}
        settings[section][key] = value
        return self.save_settings(settings)
    
    def is_api_configured(self, service: str) -> bool:
        """Check if API is configured for a service"""
        api_key = self.get_api_key(service)
        return bool(api_key and api_key.strip())
    
    def get_configured_apis(self) -> list:
        """Get list of configured APIs"""
        api_keys = self.load_api_keys()
        configured = []
        for service, config in api_keys.items():
            if config.get('api_key', '').strip():
                configured.append(service)
        return configured
    
    def validate_config(self) -> Dict[str, Any]:
        """Validate current configuration"""
        validation_result = {
            'valid': True,
            'errors': [],
            'warnings': [],
            'configured_apis': []
        }
        
        # Check API keys
        api_keys = self.load_api_keys()
        for service, config in api_keys.items():
            api_key = config.get('api_key', '')
            if api_key and api_key.strip():
                validation_result['configured_apis'].append(service)
            else:
                validation_result['warnings'].append(f"API key not configured for {service}")
        
        # Check settings
        settings = self.load_settings()
        if not settings:
            validation_result['errors'].append("Settings file is empty or corrupted")
            validation_result['valid'] = False
        
        return validation_result

# Global config manager instance
config_manager = ConfigManager()

if __name__ == "__main__":
    # Test the config manager
    cm = ConfigManager()
    
    print("API Keys:")
    print(json.dumps(cm.load_api_keys(), indent=2))
    
    print("\nSettings:")
    print(json.dumps(cm.load_settings(), indent=2))
    
    print("\nValidation:")
    print(json.dumps(cm.validate_config(), indent=2))