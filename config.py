#!/usr/bin/env python3
"""
🔑 API Keys Configuration File
Configure your API keys here for maximum subdomain discovery power!
"""

# ============================================================================
# 🚀 PREMIUM API KEYS - اضافه کردن کلیدهای API برای قدرت بیشتر
# ============================================================================

API_KEYS = {
    # 🌐 Certificate Transparency & SSL
    'CENSYS_API_ID': '',                    # https://censys.io/api
    'CENSYS_SECRET': '',                    # Censys API Secret
    
    # 🔍 Search & Intelligence
    'SHODAN_API_KEY': '',                   # https://shodan.io/api
    'VIRUSTOTAL_API_KEY': '',               # https://virustotal.com/api
    'SECURITYTRAILS_API_KEY': '',           # https://securitytrails.com/api
    'BINARYEDGE_API_KEY': '',               # https://binaryedge.io/api
    'SPYSE_API_KEY': '',                    # https://spyse.com/api
    
    # 🚀 ProjectDiscovery APIs
    'CHAOS_API_KEY': '',                    # https://chaos.projectdiscovery.io/
    'PDTM_API_KEY': '',                     # ProjectDiscovery Team API
    
    # 🐙 GitHub & Code Search
    'GITHUB_TOKEN': '',                     # https://github.com/settings/tokens
    'GITLAB_TOKEN': '',                     # GitLab Personal Access Token
    
    # 🌍 Web Archives & Historical Data
    'WAYBACK_API_KEY': '',                  # Internet Archive API
    'COMMONCRAWL_API_KEY': '',              # Common Crawl API
    
    # 📊 DNS & Network Intelligence
    'DNSDB_API_KEY': '',                    # Farsight DNSDB
    'PASSIVETOTAL_API_KEY': '',             # PassiveTotal/RiskIQ
    'PASSIVETOTAL_SECRET': '',              # PassiveTotal Secret
    'CIRCL_API_KEY': '',                    # CIRCL Passive DNS
    
    # 🔒 Threat Intelligence
    'ALIENVAULT_API_KEY': '',               # AlienVault OTX
    'THREATBOOK_API_KEY': '',               # ThreatBook API
    'URLVOID_API_KEY': '',                  # URLVoid API
    
    # ☁️ Cloud & Infrastructure
    'FOFA_API_KEY': '',                     # FOFA Search Engine
    'ZOOMEYE_API_KEY': '',                  # ZoomEye API
    'HUNTER_API_KEY': '',                   # Hunter.io API
    
    # 🌐 Additional Sources
    'FULLHUNT_API_KEY': '',                 # FullHunt.io API
    'BEVIGIL_API_KEY': '',                  # BeVigil API
    'BUILTWITH_API_KEY': '',                # BuiltWith API
}

# ============================================================================
# 🔧 API ENDPOINTS - آدرس‌های API
# ============================================================================

API_ENDPOINTS = {
    'CENSYS': 'https://search.censys.io/api/v2',
    'SHODAN': 'https://api.shodan.io',
    'VIRUSTOTAL': 'https://www.virustotal.com/vtapi/v2',
    'SECURITYTRAILS': 'https://api.securitytrails.com/v1',
    'BINARYEDGE': 'https://api.binaryedge.io/v2',
    'CHAOS': 'https://dns.projectdiscovery.io/dns',
    'GITHUB': 'https://api.github.com',
    'DNSDB': 'https://api.dnsdb.info/lookup',
    'PASSIVETOTAL': 'https://api.passivetotal.org/v2',
    'FOFA': 'https://fofa.info/api/v1',
    'ZOOMEYE': 'https://api.zoomeye.org',
    'FULLHUNT': 'https://fullhunt.io/api/v1',
    'BEVIGIL': 'https://osint.bevigil.com/api',
    'THREATBOOK': 'https://api.threatbook.cn/v3',
}

# ============================================================================
# ⚙️ API CONFIGURATION - تنظیمات API
# ============================================================================

API_CONFIG = {
    'RATE_LIMITS': {
        'SHODAN': 1,        # 1 request per second
        'VIRUSTOTAL': 4,    # 4 requests per minute (free)
        'SECURITYTRAILS': 1, # 1 request per second
        'GITHUB': 30,       # 30 requests per minute (authenticated)
        'CHAOS': 10,        # 10 requests per second
        'CENSYS': 1,        # 1 request per second
    },
    
    'TIMEOUTS': {
        'DEFAULT': 10,
        'SLOW_APIS': 30,
        'FAST_APIS': 5,
    },
    
    'RETRY_CONFIG': {
        'MAX_RETRIES': 3,
        'BACKOFF_FACTOR': 2,
        'RETRY_CODES': [429, 500, 502, 503, 504],
    }
}

# ============================================================================
# 🎯 API KEY VALIDATION - اعتبارسنجی کلیدهای API
# ============================================================================

def validate_api_keys():
    """Validate configured API keys"""
    valid_keys = {}
    invalid_keys = []
    
    for key_name, key_value in API_KEYS.items():
        if key_value and key_value.strip():
            valid_keys[key_name] = key_value.strip()
        else:
            invalid_keys.append(key_name)
    
    return valid_keys, invalid_keys

def get_api_key(service_name):
    """Get API key for a specific service"""
    return API_KEYS.get(service_name.upper() + '_API_KEY', '')

def is_api_configured(service_name):
    """Check if API key is configured for a service"""
    key = get_api_key(service_name)
    return bool(key and key.strip())

# ============================================================================
# 📋 USAGE INSTRUCTIONS - راهنمای استفاده
# ============================================================================

USAGE_INSTRUCTIONS = """
🔑 نحوه دریافت API Keys:

1. 🌐 CENSYS (Certificate Search):
   - ثبت‌نام در: https://censys.io/register
   - API Keys: https://censys.io/account/api
   - رایگان: 250 query/month

2. 🔍 SHODAN (Internet Scanner):
   - ثبت‌نام در: https://shodan.io/
   - API Key: https://account.shodan.io/
   - رایگان: 100 query/month

3. 🛡️ VIRUSTOTAL (Malware Scanner):
   - ثبت‌نام در: https://virustotal.com/
   - API Key: https://virustotal.com/gui/my-apikey
   - رایگان: 1000 requests/day

4. 🔒 SECURITYTRAILS (DNS History):
   - ثبت‌نام در: https://securitytrails.com/
   - API Key: https://securitytrails.com/app/account/credentials
   - رایگان: 50 queries/month

5. 🚀 CHAOS (ProjectDiscovery):
   - ثبت‌نام در: https://chaos.projectdiscovery.io/
   - API Key: Dashboard -> API Keys
   - رایگان: محدود

6. 🐙 GITHUB (Code Search):
   - Settings -> Developer settings -> Personal access tokens
   - https://github.com/settings/tokens
   - Scopes: public_repo, read:org

7. 📊 BINARYEDGE (Internet Scanner):
   - ثبت‌نام در: https://binaryedge.io/
   - API Key: https://app.binaryedge.io/account/api
   - رایگان: 250 queries/month

8. 🌍 PASSIVETOTAL (RiskIQ):
   - ثبت‌نام در: https://community.riskiq.com/
   - API Key: Account Settings -> API Access
   - رایگان: محدود

9. 🔍 FOFA (Search Engine):
   - ثبت‌نام در: https://fofa.info/
   - API Key: User Center -> API
   - رایگان: محدود

10. 👁️ ZOOMEYE (Cyberspace Scanner):
    - ثبت‌نام در: https://zoomeye.org/
    - API Key: Profile -> API Key
    - رایگان: محدود

💡 نکته مهم: 
- API keyها رو در فایل config.py وارد کن
- برای استفاده تجاری، نسخه‌های پولی رو تهیه کن
- Rate limit ها رو رعایت کن
"""

# ============================================================================
# 🎨 COLORED OUTPUT FOR API STATUS
# ============================================================================

class APIColors:
    GREEN = '\033[92m'    # Available
    RED = '\033[91m'      # Not configured
    YELLOW = '\033[93m'   # Limited
    BLUE = '\033[94m'     # Info
    END = '\033[0m'       # Reset

def print_api_status():
    """Print API configuration status"""
    print(f"\n{APIColors.BLUE}🔑 API Keys Status:{APIColors.END}")
    print("=" * 50)
    
    valid_keys, invalid_keys = validate_api_keys()
    
    # Show configured APIs
    if valid_keys:
        print(f"{APIColors.GREEN}✅ Configured APIs:{APIColors.END}")
        for key in valid_keys:
            service = key.replace('_API_KEY', '').replace('_SECRET', '').replace('_API_ID', '')
            print(f"  • {service}")
    
    # Show missing APIs
    if invalid_keys:
        print(f"\n{APIColors.RED}❌ Missing APIs:{APIColors.END}")
        for key in invalid_keys:
            service = key.replace('_API_KEY', '').replace('_SECRET', '').replace('_API_ID', '')
            print(f"  • {service}")
    
    print(f"\n{APIColors.YELLOW}💡 Total APIs: {len(API_KEYS)} | Configured: {len(valid_keys)}{APIColors.END}")

if __name__ == "__main__":
    print(USAGE_INSTRUCTIONS)
    print_api_status()