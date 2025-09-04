#!/usr/bin/env python3
"""
🔥 STEGANOGRAPHY & ENCODING BYPASS SYSTEM
"""

import base64
import binascii
import urllib.parse
import random
import re
from typing import List, Dict


class SteganographyBypass:
    """Advanced encoding and steganography bypass techniques"""
    
    def __init__(self):
        # Encoding techniques
        self.encoding_techniques = {
            'base64': self.base64_encode,
            'hex': self.hex_encode,
            'url': self.url_encode,
            'html': self.html_encode,
            'unicode': self.unicode_encode,
            'rot13': self.rot13_encode,
            'binary': self.binary_encode,
            'octal': self.octal_encode
        }
        
        # Steganography techniques
        self.stego_techniques = {
            'zero_width': self.zero_width_embed,
            'homoglyph': self.homoglyph_replace,
            'invisible_chars': self.invisible_chars_embed,
            'unicode_confusables': self.unicode_confusables
        }
    
    def generate_all_encodings(self, payload: str) -> List[Dict[str, str]]:
        """Generate all encoding variations"""
        encoded_payloads = []
        
        for technique_name, technique_func in self.encoding_techniques.items():
            try:
                encoded = technique_func(payload)
                if encoded and encoded != payload:
                    encoded_payloads.append({
                        'technique': technique_name,
                        'payload': encoded,
                        'description': f"Payload encoded using {technique_name}"
                    })
            except:
                continue
        
        return encoded_payloads
    
    def generate_stego_payloads(self, payload: str) -> List[Dict[str, str]]:
        """Generate steganographic payloads"""
        stego_payloads = []
        
        for technique_name, technique_func in self.stego_techniques.items():
            try:
                stego = technique_func(payload)
                if stego and stego != payload:
                    stego_payloads.append({
                        'technique': technique_name,
                        'payload': stego,
                        'description': f"Payload with {technique_name} steganography"
                    })
            except:
                continue
        
        return stego_payloads
    
    # Encoding functions
    def base64_encode(self, payload: str) -> str:
        """Base64 encoding"""
        return base64.b64encode(payload.encode()).decode()
    
    def hex_encode(self, payload: str) -> str:
        """Hex encoding"""
        return ''.join(f'\\x{ord(c):02x}' for c in payload)
    
    def url_encode(self, payload: str) -> str:
        """URL encoding with variations"""
        return urllib.parse.quote(payload, safe='')
    
    def html_encode(self, payload: str) -> str:
        """HTML entity encoding"""
        return ''.join(f'&#{ord(c)};' for c in payload)
    
    def unicode_encode(self, payload: str) -> str:
        """Unicode encoding"""
        return ''.join(f'\\u{ord(c):04x}' for c in payload)
    
    def rot13_encode(self, payload: str) -> str:
        """ROT13 encoding"""
        return ''.join(
            chr((ord(c) - ord('a') + 13) % 26 + ord('a')) if 'a' <= c <= 'z'
            else chr((ord(c) - ord('A') + 13) % 26 + ord('A')) if 'A' <= c <= 'Z'
            else c for c in payload
        )
    
    def binary_encode(self, payload: str) -> str:
        """Binary encoding"""
        return ' '.join(format(ord(c), '08b') for c in payload)
    
    def octal_encode(self, payload: str) -> str:
        """Octal encoding"""
        return ''.join(f'\\{ord(c):03o}' for c in payload)
    
    # Steganography functions
    def zero_width_embed(self, payload: str) -> str:
        """Embed zero-width characters"""
        zero_width_chars = ['\\u200b', '\\u200c', '\\u200d', '\\ufeff']
        
        # Insert zero-width chars between characters
        result = ""
        for i, char in enumerate(payload):
            result += char
            if i < len(payload) - 1:
                result += random.choice(zero_width_chars)
        
        return result
    
    def homoglyph_replace(self, payload: str) -> str:
        """Replace with homoglyphs"""
        homoglyphs = {
            'a': 'а',  # Cyrillic 'a'
            'e': 'е',  # Cyrillic 'e'
            'o': 'о',  # Cyrillic 'o'
            'p': 'р',  # Cyrillic 'p'
            'c': 'с',  # Cyrillic 'c'
            'x': 'х',  # Cyrillic 'x'
            's': 'ѕ',  # Cyrillic 's'
        }
        
        result = payload
        for latin, cyrillic in homoglyphs.items():
            if latin in result.lower():
                result = result.replace(latin, cyrillic)
                result = result.replace(latin.upper(), cyrillic.upper())
        
        return result
    
    def invisible_chars_embed(self, payload: str) -> str:
        """Embed invisible characters"""
        invisible_chars = ['\\u2060', '\\u2061', '\\u2062', '\\u2063']
        
        # Add invisible chars at strategic positions
        positions = [0, len(payload)//2, len(payload)]
        result = payload
        
        for pos in reversed(positions):  # Insert from end to maintain positions
            if pos <= len(result):
                char = random.choice(invisible_chars)
                result = result[:pos] + char + result[pos:]
        
        return result
    
    def unicode_confusables(self, payload: str) -> str:
        """Use Unicode confusable characters"""
        confusables_map = {
            'google.com': 'ɡoogle.com',
            'evil.com': 'еvil.com',
            'http': 'һttp',
            'https': 'һttps',
            'www': 'ԝww'
        }
        
        result = payload
        for original, confusable in confusables_map.items():
            if original in result.lower():
                result = result.replace(original, confusable)
        
        return result
    
    def detect_encoding_in_response(self, content: str) -> Dict[str, List[str]]:
        """Detect encoding in response content"""
        detected_encodings = {
            'base64': [],
            'hex': [],
            'unicode': [],
            'html_entities': []
        }
        
        # Base64 detection
        base64_pattern = r'[A-Za-z0-9+/]{20,}={0,2}'
        base64_matches = re.findall(base64_pattern, content)
        for match in base64_matches:
            try:
                decoded = base64.b64decode(match + '===').decode('utf-8', errors='ignore')
                if decoded.isprintable():
                    detected_encodings['base64'].append({
                        'encoded': match,
                        'decoded': decoded
                    })
            except:
                continue
        
        # Hex detection
        hex_pattern = r'(?:\\x[0-9a-fA-F]{2})+'
        hex_matches = re.findall(hex_pattern, content)
        for match in hex_matches:
            try:
                decoded = bytes.fromhex(match.replace('\\x', '')).decode('utf-8', errors='ignore')
                if decoded.isprintable():
                    detected_encodings['hex'].append({
                        'encoded': match,
                        'decoded': decoded
                    })
            except:
                continue
        
        return detected_encodings