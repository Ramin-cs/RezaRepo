"""
مدیریت تنظیمات و پیکربندی ARAT
"""

import os
import json
import yaml
from pathlib import Path
from typing import Dict, Any, Optional, List
from pydantic import BaseModel, Field
from dataclasses import dataclass
import logging


@dataclass
class DatabaseConfig:
    """تنظیمات دیتابیس"""
    url: str = "sqlite:///./data/arat.db"
    pool_size: int = 10
    max_overflow: int = 20
    echo: bool = False


@dataclass
class APIConfig:
    """تنظیمات API"""
    timeout: int = 30
    max_retries: int = 3
    rate_limit: int = 100  # requests per minute
    user_agents: List[str] = None
    
    def __post_init__(self):
        if self.user_agents is None:
            self.user_agents = [
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
                "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0",
            ]


@dataclass
class PhaseConfig:
    """تنظیمات فازها"""
    max_workers: int = 100
    timeout: int = 30
    retry_count: int = 3
    enable_parallel: bool = True
    enable_cache: bool = True


@dataclass
class WebConfig:
    """تنظیمات پنل وب"""
    host: str = "0.0.0.0"
    port: int = 8080
    debug: bool = False
    secret_key: str = "your-secret-key-here"
    enable_auth: bool = False
    username: str = "admin"
    password: str = "admin"


@dataclass
class LogConfig:
    """تنظیمات لاگ"""
    level: str = "INFO"
    format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    file_path: str = "logs/arat.log"
    max_size: int = 10 * 1024 * 1024  # 10MB
    backup_count: int = 5
    enable_console: bool = True


class Config:
    """کلاس اصلی مدیریت تنظیمات"""
    
    def __init__(self, config_path: Optional[str] = None):
        self.config_path = config_path or "config/config.yaml"
        self._load_config()
    
    def _load_config(self):
        """بارگذاری تنظیمات از فایل"""
        try:
            config_file = Path(self.config_path)
            
            if config_file.exists():
                if config_file.suffix.lower() == '.json':
                    with open(config_file, 'r', encoding='utf-8') as f:
                        config_data = json.load(f)
                elif config_file.suffix.lower() in ['.yml', '.yaml']:
                    with open(config_file, 'r', encoding='utf-8') as f:
                        config_data = yaml.safe_load(f)
                else:
                    raise ValueError(f"فرمت فایل تنظیمات پشتیبانی نمی‌شود: {config_file.suffix}")
            else:
                # تنظیمات پیش‌فرض
                config_data = self._get_default_config()
                self._save_default_config(config_file, config_data)
            
            # بارگذاری تنظیمات
            self.database = DatabaseConfig(**config_data.get('database', {}))
            self.api = APIConfig(**config_data.get('api', {}))
            self.phases = PhaseConfig(**config_data.get('phases', {}))
            self.web = WebConfig(**config_data.get('web', {}))
            self.logging = LogConfig(**config_data.get('logging', {}))
            
            # تنظیمات محیطی
            self.environment = os.getenv('ENVIRONMENT', 'development')
            self.debug = os.getenv('DEBUG', 'false').lower() == 'true'
            
            # تنظیمات API keys
            self.api_keys = self._load_api_keys(config_data.get('api_keys', {}))
            
            # تنظیمات wordlists
            self.wordlists = self._load_wordlists(config_data.get('wordlists', {}))
            
            # تنظیمات فیلترها
            self.filters = config_data.get('filters', {})
            
            # تنظیمات خروجی
            self.output = config_data.get('output', {
                'format': 'json',
                'directory': 'output',
                'include_screenshots': True,
                'include_har': True
            })
            
        except Exception as e:
            logging.error(f"خطا در بارگذاری تنظیمات: {e}")
            raise
    
    def _get_default_config(self) -> Dict[str, Any]:
        """تنظیمات پیش‌فرض"""
        return {
            'database': {
                'url': 'sqlite:///./data/arat.db',
                'pool_size': 10,
                'max_overflow': 20,
                'echo': False
            },
            'api': {
                'timeout': 30,
                'max_retries': 3,
                'rate_limit': 100,
                'user_agents': []
            },
            'phases': {
                'max_workers': 100,
                'timeout': 30,
                'retry_count': 3,
                'enable_parallel': True,
                'enable_cache': True
            },
            'web': {
                'host': '0.0.0.0',
                'port': 8080,
                'debug': False,
                'secret_key': 'your-secret-key-here',
                'enable_auth': False,
                'username': 'admin',
                'password': 'admin'
            },
            'logging': {
                'level': 'INFO',
                'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                'file_path': 'logs/arat.log',
                'max_size': 10485760,
                'backup_count': 5,
                'enable_console': True
            },
            'api_keys': {
                'shodan': '',
                'virustotal': '',
                'censys': '',
                'securitytrails': '',
                'github': '',
                'wayback_machine': '',
                'common_crawl': '',
                'crt_sh': '',
                'dnsdumpster': '',
                'hunter': '',
                'builtwith': '',
                'wappalyzer': '',
                'nmap': '',
                'masscan': '',
                'nuclei': ''
            },
            'wordlists': {
                'subdomains': 'wordlists/subdomains.txt',
                'directories': 'wordlists/directories.txt',
                'parameters': 'wordlists/parameters.txt',
                'technology': 'wordlists/technology.txt',
                'endpoints': 'wordlists/endpoints.txt'
            },
            'filters': {
                'exclude_status_codes': [404, 403],
                'exclude_content_types': ['image/', 'video/', 'audio/'],
                'exclude_extensions': ['.jpg', '.png', '.gif', '.css', '.js'],
                'min_content_length': 100,
                'max_response_time': 10
            },
            'output': {
                'format': 'json',
                'directory': 'output',
                'include_screenshots': True,
                'include_har': True
            }
        }
    
    def _save_default_config(self, config_file: Path, config_data: Dict[str, Any]):
        """ذخیره تنظیمات پیش‌فرض"""
        try:
            config_file.parent.mkdir(parents=True, exist_ok=True)
            
            if config_file.suffix.lower() == '.json':
                with open(config_file, 'w', encoding='utf-8') as f:
                    json.dump(config_data, f, indent=2, ensure_ascii=False)
            elif config_file.suffix.lower() in ['.yml', '.yaml']:
                with open(config_file, 'w', encoding='utf-8') as f:
                    yaml.dump(config_data, f, default_flow_style=False, allow_unicode=True)
            
            logging.info(f"تنظیمات پیش‌فرض در {config_file} ذخیره شد")
            
        except Exception as e:
            logging.error(f"خطا در ذخیره تنظیمات پیش‌فرض: {e}")
    
    def _load_api_keys(self, api_keys_config: Dict[str, str]) -> Dict[str, str]:
        """بارگذاری API keys"""
        api_keys = {}
        
        for service, key in api_keys_config.items():
            # اولویت با متغیرهای محیطی
            env_key = os.getenv(f"{service.upper()}_API_KEY")
            if env_key:
                api_keys[service] = env_key
            elif key:
                api_keys[service] = key
        
        return api_keys
    
    def _load_wordlists(self, wordlists_config: Dict[str, str]) -> Dict[str, str]:
        """بارگذاری مسیرهای wordlist"""
        wordlists = {}
        
        for name, path in wordlists_config.items():
            wordlist_path = Path(path)
            if wordlist_path.exists():
                wordlists[name] = str(wordlist_path)
            else:
                # ایجاد wordlist پیش‌فرض
                wordlists[name] = self._create_default_wordlist(name, wordlist_path)
        
        return wordlists
    
    def _create_default_wordlist(self, name: str, path: Path) -> str:
        """ایجاد wordlist پیش‌فرض"""
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            
            if name == 'subdomains':
                content = """www
mail
ftp
localhost
webmail
smtp
pop
ns1
webdisk
ns2
cpanel
whm
autodiscover
autoconfig
m
imap
test
ns
blog
pop3
dev
www2
admin
forum
news
vpn
ns3
mail2
new
mysql
old
www1
beta
shop
staging
staging2
api
www3
dns2
www4
mail3
smtp2
search
staging3
mx
cdn
api2
www5
mx2
staging4
mail4
staging5
www6
info
apps
cdn2
mx3
www7
mail5
mx4
staging6
www8
staging7
mx5
www9
mail6
staging8
mx6
www10
staging9
mail7
staging10
mx7
staging11
mail8
mx8
staging12
mail9
mx9
staging13
mail10
mx10
staging14
staging15
staging16
staging17
staging18
staging19
staging20
"""
            elif name == 'directories':
                content = """/
/admin
/login
/panel
/dashboard
/cp
/cpanel
/control
/manager
/admin.php
/admin.html
/admin/
/administrator
/administrator/
/administrator/index.php
/administrator/login.php
/administrator/account.php
/administrator/admin.php
/administrator/login.html
/administrator/account.html
/administrator/admin.html
/administrator/index.html
/administrator/login.asp
/administrator/account.asp
/administrator/admin.asp
/administrator/index.asp
/administrator/login.aspx
/administrator/account.aspx
/administrator/admin.aspx
/administrator/index.aspx
/phpMyAdmin
/phpmyadmin
/pma
/myadmin
/sql
/db
/database
/dbadmin
/mysql
/mysqladmin
/phpmyadmin2
/phpmyadmin3
/phpmyadmin4
/phpmyadmin5
/phpmyadmin6
/phpmyadmin7
/phpmyadmin8
/phpmyadmin9
/phpmyadmin10
/wp-admin
/wp-login
/wp-content
/wp-includes
/wordpress
/wp
/blog
/bbs
/forum
/forums
/community
/board
/boards
/guestbook
/guest
/guests
/members
/member
/user
/users
/account
/accounts
/profile
/profiles
/settings
/setting
/config
/configuration
/configure
/setup
/install
/installation
/upgrade
/updates
/update
/backup
/backups
/old
/archive
/archives
/temp
/tmp
/temporary
/cache
/logs
/log
/error
/errors
/404
/403
/500
/test
/testing
/tests
/debug
/dev
/development
/staging
/stage
/production
/prod
/live
/beta
/alpha
/api
/apis
/rest
/soap
/wsdl
/xml
/json
/rss
/atom
/feed
/feeds
/uploads
/upload
/files
/file
/download
/downloads
/docs
/documentation
/doc
/help
/support
/contact
/about
/info
/legal
/privacy
/terms
/sitemap
/sitemap.xml
/robots.txt
/favicon.ico
"""
            elif name == 'parameters':
                content = """id
page
search
query
q
s
sort
order
limit
offset
start
count
size
format
type
category
tag
author
date
year
month
day
lang
language
locale
timezone
currency
price
cost
amount
total
subtotal
tax
shipping
discount
coupon
promo
code
token
key
secret
password
pass
pwd
user
username
email
mail
phone
tel
address
city
state
country
zip
postal
company
organization
org
department
dept
role
title
name
first
last
middle
gender
age
birth
birthday
birthdate
nationality
race
ethnicity
religion
political
education
degree
school
university
college
work
job
occupation
profession
income
salary
wage
social
security
ssn
driver
license
passport
visa
status
active
inactive
enabled
disabled
visible
hidden
public
private
protected
admin
administrator
moderator
editor
author
contributor
subscriber
guest
anonymous
test
demo
sample
example
debug
verbose
quiet
silent
force
confirm
yes
no
true
false
on
off
enable
disable
allow
deny
permit
block
ban
unban
lock
unlock
freeze
unfreeze
suspend
unsuspend
activate
deactivate
approve
reject
accept
decline
submit
cancel
save
delete
remove
add
create
update
edit
modify
change
replace
rename
move
copy
clone
duplicate
import
export
upload
download
backup
restore
reset
clear
flush
refresh
reload
restart
stop
start
pause
resume
play
stop
next
previous
first
last
top
bottom
left
right
center
middle
begin
end
open
close
show
hide
display
view
print
preview
zoom
in
out
up
down
forward
backward
next
prev
skip
jump
goto
select
choose
pick
filter
search
find
lookup
browse
navigate
scroll
swipe
drag
drop
click
tap
touch
hover
focus
blur
load
unload
ready
complete
success
error
warning
info
debug
trace
log
audit
monitor
track
trace
profile
analyze
report
statistics
stats
metrics
kpi
dashboard
chart
graph
table
list
grid
tree
menu
navigation
breadcrumb
pagination
tabs
accordion
modal
popup
dialog
alert
notification
message
tooltip
hint
help
guide
tutorial
faq
documentation
manual
reference
api
sdk
library
framework
plugin
extension
addon
module
component
widget
element
control
field
input
output
button
link
image
video
audio
file
folder
directory
path
url
uri
endpoint
route
method
action
event
callback
handler
listener
observer
subscriber
publisher
producer
consumer
client
server
service
daemon
agent
worker
thread
process
task
job
queue
stack
heap
buffer
cache
session
cookie
token
auth
authentication
authorization
permission
role
privilege
access
control
security
encryption
decryption
hash
signature
certificate
ssl
tls
https
http
ftp
sftp
ssh
telnet
smtp
pop3
imap
dns
dhcp
ntp
snmp
ldap
kerberos
oauth
openid
saml
jwt
csrf
xss
sql
injection
"""
            else:
                content = ""
            
            with open(path, 'w', encoding='utf-8') as f:
                f.write(content)
            
            return str(path)
            
        except Exception as e:
            logging.error(f"خطا در ایجاد wordlist {name}: {e}")
            return ""
    
    def get_api_key(self, service: str) -> Optional[str]:
        """دریافت API key برای سرویس مشخص"""
        return self.api_keys.get(service)
    
    def has_api_key(self, service: str) -> bool:
        """بررسی وجود API key برای سرویس مشخص"""
        return bool(self.get_api_key(service))
    
    def get_wordlist_path(self, name: str) -> Optional[str]:
        """دریافت مسیر wordlist"""
        return self.wordlists.get(name)
    
    def update_config(self, section: str, key: str, value: Any):
        """به‌روزرسانی تنظیمات"""
        try:
            config_file = Path(self.config_path)
            
            if config_file.exists():
                if config_file.suffix.lower() == '.json':
                    with open(config_file, 'r', encoding='utf-8') as f:
                        config_data = json.load(f)
                elif config_file.suffix.lower() in ['.yml', '.yaml']:
                    with open(config_file, 'r', encoding='utf-8') as f:
                        config_data = yaml.safe_load(f)
                
                if section not in config_data:
                    config_data[section] = {}
                
                config_data[section][key] = value
                
                if config_file.suffix.lower() == '.json':
                    with open(config_file, 'w', encoding='utf-8') as f:
                        json.dump(config_data, f, indent=2, ensure_ascii=False)
                elif config_file.suffix.lower() in ['.yml', '.yaml']:
                    with open(config_file, 'w', encoding='utf-8') as f:
                        yaml.dump(config_data, f, default_flow_style=False, allow_unicode=True)
                
                logging.info(f"تنظیمات {section}.{key} به‌روزرسانی شد")
                
        except Exception as e:
            logging.error(f"خطا در به‌روزرسانی تنظیمات: {e}")
    
    @property
    def log_level(self) -> str:
        """سطح لاگ"""
        return self.logging.level
    
    @property
    def database_url(self) -> str:
        """URL دیتابیس"""
        return self.database.url
    
    @property
    def max_workers(self) -> int:
        """حداکثر تعداد worker"""
        return self.phases.max_workers
    
    @property
    def timeout(self) -> int:
        """timeout"""
        return self.phases.timeout
    
    @property
    def enable_parallel(self) -> bool:
        """فعال بودن پردازش موازی"""
        return self.phases.enable_parallel