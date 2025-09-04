#!/usr/bin/env python3
"""
🔥 FORM ANALYZER - Advanced HTML Form Analysis
"""

import re
from typing import List, Dict, Set, Optional, Tuple
from urllib.parse import urljoin, urlparse
from dataclasses import dataclass, field

try:
    from bs4 import BeautifulSoup
    BS4_OK = True
except ImportError:
    BS4_OK = False


@dataclass
class FormField:
    """Form field information"""
    name: str
    field_type: str
    value: str = ""
    required: bool = False
    placeholder: str = ""
    pattern: str = ""
    min_length: Optional[int] = None
    max_length: Optional[int] = None
    is_redirect_related: bool = False
    confidence: float = 0.0
    attributes: Dict[str, str] = field(default_factory=dict)


@dataclass
class FormAnalysis:
    """Complete form analysis"""
    url: str
    action: str
    method: str
    encoding: str = "application/x-www-form-urlencoded"
    fields: List[FormField] = field(default_factory=list)
    hidden_fields: List[FormField] = field(default_factory=list)
    csrf_token: Optional[str] = None
    is_suspicious: bool = False
    suspicion_reasons: List[str] = field(default_factory=list)
    redirect_potential: float = 0.0
    form_id: Optional[str] = None
    form_class: Optional[str] = None
    
    @property
    def redirect_fields(self) -> List[FormField]:
        """Get redirect-related fields"""
        return [f for f in self.fields if f.is_redirect_related]
    
    @property
    def high_confidence_fields(self) -> List[FormField]:
        """Get high-confidence fields"""
        return [f for f in self.fields if f.confidence > 0.7]


class FormAnalyzer:
    """Advanced HTML form analyzer"""
    
    def __init__(self):
        # Redirect-related field patterns
        self.redirect_patterns = [
            'redirect', 'url', 'next', 'return', 'goto', 'target',
            'destination', 'continue', 'forward', 'redir', 'location',
            'site', 'link', 'href', 'callback', 'success_url', 'failure_url',
            'cancel_url', 'exit_url', 'logout_url', 'login_redirect',
            'returnurl', 'redirecturl', 'redirecturi', 'back', 'backurl'
        ]
        
        # Suspicious form patterns
        self.suspicious_patterns = [
            # Authentication forms
            r'login', r'signin', r'auth', r'sso',
            
            # Payment forms
            r'payment', r'checkout', r'billing', r'pay',
            
            # Admin forms
            r'admin', r'panel', r'dashboard', r'control',
            
            # File upload forms
            r'upload', r'file', r'attachment',
            
            # Contact forms
            r'contact', r'message', r'feedback'
        ]
        
        # CSRF token patterns
        self.csrf_patterns = [
            r'csrf', r'token', r'authenticity_token', r'_token',
            r'csrfmiddlewaretoken', r'__token', r'security_token'
        ]
        
        # Hidden field patterns that might contain redirects
        self.hidden_redirect_patterns = [
            r'redirect', r'next', r'return', r'success', r'failure',
            r'callback', r'url', r'target', r'destination'
        ]
        
        # Input types that are interesting for security
        self.interesting_types = [
            'hidden', 'text', 'email', 'url', 'password',
            'search', 'tel', 'number'
        ]
    
    def analyze_forms(self, content: str, base_url: str) -> List[FormAnalysis]:
        """Analyze all forms in HTML content"""
        forms = []
        
        if BS4_OK:
            forms = self._analyze_with_beautifulsoup(content, base_url)
        else:
            forms = self._analyze_with_regex(content, base_url)
        
        # Post-process forms
        for form in forms:
            self._analyze_form_suspicion(form)
            self._calculate_redirect_potential(form)
            self._analyze_field_confidence(form)
        
        print(f"[FORM-ANALYZER] Analyzed {len(forms)} forms")
        return forms
    
    def _analyze_with_beautifulsoup(self, content: str, base_url: str) -> List[FormAnalysis]:
        """Analyze forms using BeautifulSoup"""
        forms = []
        soup = BeautifulSoup(content, 'html.parser')
        
        for form_tag in soup.find_all('form'):
            form = self._extract_form_info(form_tag, base_url)
            forms.append(form)
        
        return forms
    
    def _analyze_with_regex(self, content: str, base_url: str) -> List[FormAnalysis]:
        """Analyze forms using regex (fallback)"""
        forms = []
        form_pattern = r'<form[^>]*>(.*?)</form>'
        
        for match in re.finditer(form_pattern, content, re.DOTALL | re.IGNORECASE):
            form_html = match.group(0)
            form_content = match.group(1)
            
            form = self._extract_form_info_regex(form_html, form_content, base_url)
            forms.append(form)
        
        return forms
    
    def _extract_form_info(self, form_tag, base_url: str) -> FormAnalysis:
        """Extract form information using BeautifulSoup"""
        action = form_tag.get('action', '')
        if action:
            action = urljoin(base_url, action)
        else:
            action = base_url
        
        method = form_tag.get('method', 'GET').upper()
        encoding = form_tag.get('enctype', 'application/x-www-form-urlencoded')
        form_id = form_tag.get('id')
        form_class = form_tag.get('class')
        
        form = FormAnalysis(
            url=base_url,
            action=action,
            method=method,
            encoding=encoding,
            form_id=form_id,
            form_class=' '.join(form_class) if form_class else None
        )
        
        # Extract fields
        for input_tag in form_tag.find_all(['input', 'select', 'textarea']):
            field = self._extract_field_info(input_tag)
            if field:
                if field.field_type == 'hidden':
                    form.hidden_fields.append(field)
                else:
                    form.fields.append(field)
                
                # Check for CSRF token
                if any(pattern in field.name.lower() for pattern in self.csrf_patterns):
                    form.csrf_token = field.value
        
        return form
    
    def _extract_form_info_regex(self, form_html: str, form_content: str, base_url: str) -> FormAnalysis:
        """Extract form information using regex"""
        # Extract form attributes
        action_match = re.search(r'action=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
        action = action_match.group(1) if action_match else ''
        if action:
            action = urljoin(base_url, action)
        else:
            action = base_url
        
        method_match = re.search(r'method=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
        method = method_match.group(1).upper() if method_match else 'GET'
        
        form = FormAnalysis(
            url=base_url,
            action=action,
            method=method
        )
        
        # Extract input fields
        input_pattern = r'<input[^>]*>'
        for input_match in re.finditer(input_pattern, form_content, re.IGNORECASE):
            input_html = input_match.group(0)
            field = self._extract_field_info_regex(input_html)
            if field:
                if field.field_type == 'hidden':
                    form.hidden_fields.append(field)
                else:
                    form.fields.append(field)
        
        return form
    
    def _extract_field_info(self, input_tag) -> Optional[FormField]:
        """Extract field information from input tag"""
        name = input_tag.get('name')
        if not name:
            return None
        
        field_type = input_tag.get('type', 'text').lower()
        value = input_tag.get('value', '')
        required = input_tag.has_attr('required')
        placeholder = input_tag.get('placeholder', '')
        pattern = input_tag.get('pattern', '')
        
        # Get min/max length
        min_length = None
        max_length = None
        try:
            if input_tag.get('minlength'):
                min_length = int(input_tag.get('minlength'))
            if input_tag.get('maxlength'):
                max_length = int(input_tag.get('maxlength'))
        except:
            pass
        
        # Get all attributes
        attributes = dict(input_tag.attrs)
        
        field = FormField(
            name=name,
            field_type=field_type,
            value=value,
            required=required,
            placeholder=placeholder,
            pattern=pattern,
            min_length=min_length,
            max_length=max_length,
            attributes=attributes
        )
        
        # Check if redirect-related
        field.is_redirect_related = self._is_redirect_field(field)
        
        return field
    
    def _extract_field_info_regex(self, input_html: str) -> Optional[FormField]:
        """Extract field information using regex"""
        name_match = re.search(r'name=["\']([^"\']*)["\']', input_html, re.IGNORECASE)
        if not name_match:
            return None
        
        name = name_match.group(1)
        
        type_match = re.search(r'type=["\']([^"\']*)["\']', input_html, re.IGNORECASE)
        field_type = type_match.group(1).lower() if type_match else 'text'
        
        value_match = re.search(r'value=["\']([^"\']*)["\']', input_html, re.IGNORECASE)
        value = value_match.group(1) if value_match else ''
        
        required = 'required' in input_html.lower()
        
        placeholder_match = re.search(r'placeholder=["\']([^"\']*)["\']', input_html, re.IGNORECASE)
        placeholder = placeholder_match.group(1) if placeholder_match else ''
        
        field = FormField(
            name=name,
            field_type=field_type,
            value=value,
            required=required,
            placeholder=placeholder
        )
        
        field.is_redirect_related = self._is_redirect_field(field)
        
        return field
    
    def _is_redirect_field(self, field: FormField) -> bool:
        """Check if field is redirect-related"""
        name_lower = field.name.lower()
        value_lower = field.value.lower()
        placeholder_lower = field.placeholder.lower()
        
        # Check field name
        name_match = any(pattern in name_lower for pattern in self.redirect_patterns)
        
        # Check field value
        value_match = bool(
            re.match(r'https?://', value_lower) or
            re.match(r'//', value_lower) or
            re.match(r'[a-z0-9.-]+\.[a-z]{2,}', value_lower)
        )
        
        # Check placeholder
        placeholder_match = any(pattern in placeholder_lower for pattern in self.redirect_patterns)
        
        return name_match or value_match or placeholder_match
    
    def _analyze_form_suspicion(self, form: FormAnalysis):
        """Analyze form for suspicious patterns"""
        reasons = []
        
        # Check action URL
        action_lower = form.action.lower()
        for pattern in self.suspicious_patterns:
            if re.search(pattern, action_lower):
                reasons.append(f"Suspicious action URL pattern: {pattern}")
        
        # Check form ID and class
        if form.form_id:
            id_lower = form.form_id.lower()
            for pattern in self.suspicious_patterns:
                if re.search(pattern, id_lower):
                    reasons.append(f"Suspicious form ID: {form.form_id}")
        
        if form.form_class:
            class_lower = form.form_class.lower()
            for pattern in self.suspicious_patterns:
                if re.search(pattern, class_lower):
                    reasons.append(f"Suspicious form class: {form.form_class}")
        
        # Check for redirect fields
        redirect_fields = [f for f in form.fields + form.hidden_fields if f.is_redirect_related]
        if redirect_fields:
            reasons.append(f"Contains {len(redirect_fields)} redirect-related fields")
        
        # Check for hidden redirect fields
        hidden_redirects = [f for f in form.hidden_fields if f.is_redirect_related]
        if hidden_redirects:
            reasons.append(f"Contains {len(hidden_redirects)} hidden redirect fields")
        
        # Check method
        if form.method == 'GET' and len(form.fields) > 0:
            reasons.append("GET form with parameters (potential for URL manipulation)")
        
        # Check encoding
        if 'multipart' in form.encoding.lower():
            reasons.append("File upload form detected")
        
        # Check for password fields without HTTPS
        password_fields = [f for f in form.fields if f.field_type == 'password']
        if password_fields and not form.url.startswith('https://'):
            reasons.append("Password field on non-HTTPS page")
        
        form.suspicion_reasons = reasons
        form.is_suspicious = len(reasons) > 0
    
    def _calculate_redirect_potential(self, form: FormAnalysis):
        """Calculate redirect potential score"""
        score = 0.0
        
        # Base score for having fields
        if form.fields:
            score += 0.1
        
        # Score for redirect fields
        redirect_fields = [f for f in form.fields + form.hidden_fields if f.is_redirect_related]
        score += len(redirect_fields) * 0.3
        
        # Score for hidden redirect fields (higher risk)
        hidden_redirects = [f for f in form.hidden_fields if f.is_redirect_related]
        score += len(hidden_redirects) * 0.4
        
        # Score for GET method (easier to manipulate)
        if form.method == 'GET':
            score += 0.2
        
        # Score for suspicious action URL
        if any(pattern in form.action.lower() for pattern in ['redirect', 'forward', 'goto']):
            score += 0.3
        
        # Score for lack of CSRF protection
        if not form.csrf_token and form.method == 'POST':
            score += 0.1
        
        form.redirect_potential = min(score, 1.0)
    
    def _analyze_field_confidence(self, form: FormAnalysis):
        """Analyze confidence for each field"""
        for field in form.fields + form.hidden_fields:
            confidence = 0.0
            
            # Base confidence for redirect fields
            if field.is_redirect_related:
                confidence += 0.5
            
            # Higher confidence for hidden fields
            if field.field_type == 'hidden':
                confidence += 0.2
            
            # Higher confidence for URL-type fields
            if field.field_type == 'url':
                confidence += 0.3
            
            # Higher confidence for fields with URL values
            if field.value:
                if field.value.startswith(('http://', 'https://')):
                    confidence += 0.3
                elif field.value.startswith('//'):
                    confidence += 0.25
                elif '.' in field.value and len(field.value.split('.')) >= 2:
                    confidence += 0.15
            
            # Confidence based on field name patterns
            name_lower = field.name.lower()
            high_confidence_patterns = ['redirect', 'url', 'next', 'return', 'callback']
            if any(pattern in name_lower for pattern in high_confidence_patterns):
                confidence += 0.2
            
            # Confidence based on placeholder
            if field.placeholder:
                placeholder_lower = field.placeholder.lower()
                if any(pattern in placeholder_lower for pattern in self.redirect_patterns):
                    confidence += 0.1
            
            field.confidence = min(confidence, 1.0)
    
    def get_high_risk_forms(self, forms: List[FormAnalysis], threshold: float = 0.5) -> List[FormAnalysis]:
        """Get forms with high redirect potential"""
        return [form for form in forms if form.redirect_potential >= threshold]
    
    def get_forms_with_redirects(self, forms: List[FormAnalysis]) -> List[FormAnalysis]:
        """Get forms that have redirect-related fields"""
        return [form for form in forms if form.redirect_fields]
    
    def extract_test_cases(self, forms: List[FormAnalysis]) -> List[Dict]:
        """Extract test cases for form testing"""
        test_cases = []
        
        for form in forms:
            if form.redirect_fields:
                for field in form.redirect_fields:
                    test_case = {
                        'url': form.action,
                        'method': form.method,
                        'parameter': field.name,
                        'original_value': field.value,
                        'field_type': field.field_type,
                        'confidence': field.confidence,
                        'form_info': {
                            'encoding': form.encoding,
                            'csrf_token': form.csrf_token,
                            'other_fields': [
                                {'name': f.name, 'value': f.value} 
                                for f in form.fields + form.hidden_fields 
                                if f.name != field.name
                            ]
                        }
                    }
                    test_cases.append(test_case)
        
        return test_cases
    
    def generate_form_report(self, forms: List[FormAnalysis]) -> Dict:
        """Generate comprehensive form analysis report"""
        if not forms:
            return {}
        
        total_forms = len(forms)
        suspicious_forms = [f for f in forms if f.is_suspicious]
        high_risk_forms = [f for f in forms if f.redirect_potential >= 0.5]
        forms_with_redirects = [f for f in forms if f.redirect_fields]
        
        # Method distribution
        method_dist = {}
        for form in forms:
            method_dist[form.method] = method_dist.get(form.method, 0) + 1
        
        # Field type distribution
        field_types = {}
        for form in forms:
            for field in form.fields + form.hidden_fields:
                field_types[field.field_type] = field_types.get(field.field_type, 0) + 1
        
        # Redirect potential distribution
        potential_ranges = {'low': 0, 'medium': 0, 'high': 0}
        for form in forms:
            if form.redirect_potential < 0.3:
                potential_ranges['low'] += 1
            elif form.redirect_potential < 0.7:
                potential_ranges['medium'] += 1
            else:
                potential_ranges['high'] += 1
        
        return {
            'summary': {
                'total_forms': total_forms,
                'suspicious_forms': len(suspicious_forms),
                'high_risk_forms': len(high_risk_forms),
                'forms_with_redirects': len(forms_with_redirects),
                'average_redirect_potential': sum(f.redirect_potential for f in forms) / total_forms
            },
            'method_distribution': method_dist,
            'field_type_distribution': field_types,
            'redirect_potential_distribution': potential_ranges,
            'high_risk_details': [
                {
                    'url': f.url,
                    'action': f.action,
                    'method': f.method,
                    'redirect_potential': f.redirect_potential,
                    'redirect_fields': [field.name for field in f.redirect_fields],
                    'suspicion_reasons': f.suspicion_reasons
                }
                for f in high_risk_forms
            ],
            'test_cases': len(self.extract_test_cases(forms))
        }