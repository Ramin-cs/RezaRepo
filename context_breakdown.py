#!/usr/bin/env python3
"""
Context Breakdown Module for XSS Scanner
Detailed context analysis and breakdown display
"""

from typing import Dict, List, Set
from live_progress import live_progress

class ContextBreakdown:
    """Context breakdown analyzer and display"""
    
    def __init__(self):
        self.context_stats = {
            'html_content': 0,
            'html_attribute': 0,
            'javascript_context': 0,
            'css_context': 0,
            'url_context': 0,
            'comment_context': 0
        }
        
    def analyze_input_points(self, input_points: List[Dict]) -> Dict:
        """Analyze input points and break down by context"""
        live_progress.update_task("Analyzing input points by context...")
        
        context_breakdown = {
            'forms': [],
            'url_params': [],
            'js_variables': [],
            'context_stats': self.context_stats.copy()
        }
        
        for input_point in input_points:
            if input_point['type'] == 'form':
                context_breakdown['forms'].append(input_point)
                self._analyze_form_context(input_point)
            elif input_point['type'] == 'url_params':
                context_breakdown['url_params'].append(input_point)
                self._analyze_url_context(input_point)
            elif input_point['type'] == 'javascript_variables':
                context_breakdown['js_variables'].append(input_point)
                self._analyze_js_context(input_point)
                
        context_breakdown['context_stats'] = self.context_stats.copy()
        
        # Display breakdown
        self._display_context_breakdown(context_breakdown)
        
        return context_breakdown
        
    def _analyze_form_context(self, form: Dict):
        """Analyze form context"""
        # Count form inputs by type
        input_types = {}
        for input_field in form.get('inputs', []):
            input_type = input_field.get('type', 'text')
            input_types[input_type] = input_types.get(input_type, 0) + 1
            
        # Determine likely context
        if any(input_type in ['text', 'email', 'search', 'url', 'textarea'] for input_type in input_types.keys()):
            self.context_stats['html_content'] += 1
            
        live_progress.show_info(f"Form context: {form['url']} - {len(form.get('inputs', []))} inputs")
        
    def _analyze_url_context(self, url_params: Dict):
        """Analyze URL parameter context"""
        param_count = len(url_params.get('params', {}))
        self.context_stats['url_context'] += 1
        
        live_progress.show_info(f"URL context: {url_params['url']} - {param_count} parameters")
        
    def _analyze_js_context(self, js_vars: Dict):
        """Analyze JavaScript variable context"""
        var_count = len(js_vars.get('variables', []))
        self.context_stats['javascript_context'] += 1
        
        live_progress.show_info(f"JS context: {js_vars['url']} - {var_count} variables")
        
    def _display_context_breakdown(self, breakdown: Dict):
        """Display context breakdown"""
        live_progress.update_task("Displaying context breakdown...")
        
        from colorama import Fore, Style
        print(f"\n{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗")
        print(f"║                    CONTEXT BREAKDOWN                        ║")
        print(f"╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}")
        
        # Display forms
        forms = breakdown['forms']
        if forms:
            print(f"\n{Fore.YELLOW}📝 FORMS ({len(forms)} found):{Style.RESET_ALL}")
            for i, form in enumerate(forms[:10], 1):  # Show first 10
                action = form.get('action', 'N/A')
                method = form.get('method', 'GET')
                inputs_count = len(form.get('inputs', []))
                print(f"  {i}. {form['url']}")
                print(f"     Action: {action} | Method: {method} | Inputs: {inputs_count}")
                
                # Show input details
                for input_field in form.get('inputs', [])[:3]:  # Show first 3 inputs
                    name = input_field.get('name', 'N/A')
                    input_type = input_field.get('type', 'text')
                    placeholder = input_field.get('placeholder', '')
                    print(f"       - {name} ({input_type}) {placeholder}")
                    
            if len(forms) > 10:
                print(f"     ... and {len(forms) - 10} more forms")
                
        # Display URL parameters
        url_params = breakdown['url_params']
        if url_params:
            print(f"\n{Fore.YELLOW}🔗 URL PARAMETERS ({len(url_params)} found):{Style.RESET_ALL}")
            for i, url_param in enumerate(url_params[:10], 1):  # Show first 10
                params = url_param.get('params', {})
                print(f"  {i}. {url_param['url']}")
                print(f"     Parameters: {', '.join(params.keys())}")
                
            if len(url_params) > 10:
                print(f"     ... and {len(url_params) - 10} more URL parameter sets")
                
        # Display JavaScript variables
        js_vars = breakdown['js_variables']
        if js_vars:
            print(f"\n{Fore.YELLOW}⚡ JAVASCRIPT VARIABLES ({len(js_vars)} found):{Style.RESET_ALL}")
            for i, js_var in enumerate(js_vars[:10], 1):  # Show first 10
                variables = js_var.get('variables', [])
                print(f"  {i}. {js_var['url']}")
                for var in variables[:3]:  # Show first 3 variables
                    name = var.get('name', 'N/A')
                    value = var.get('value', '')[:50]
                    print(f"       - {name}: {value}")
                    
            if len(js_vars) > 10:
                print(f"     ... and {len(js_vars) - 10} more JS variable sets")
                
        # Display context statistics
        stats = breakdown['context_stats']
        print(f"\n{Fore.YELLOW}📊 CONTEXT STATISTICS:{Style.RESET_ALL}")
        print(f"  HTML Content: {stats['html_content']}")
        print(f"  HTML Attribute: {stats['html_attribute']}")
        print(f"  JavaScript Context: {stats['javascript_context']}")
        print(f"  CSS Context: {stats['css_context']}")
        print(f"  URL Context: {stats['url_context']}")
        print(f"  Comment Context: {stats['comment_context']}")
        
        # Display testing recommendations
        self._display_testing_recommendations(breakdown)
        
    def _display_testing_recommendations(self, breakdown: Dict):
        """Display testing recommendations based on context"""
        from colorama import Fore, Style
        print(f"\n{Fore.GREEN}🎯 TESTING RECOMMENDATIONS:{Style.RESET_ALL}")
        
        forms = breakdown['forms']
        url_params = breakdown['url_params']
        js_vars = breakdown['js_variables']
        
        if forms:
            print(f"  📝 Forms: Test {len(forms)} forms with HTML content payloads")
            print(f"     - Use <script>alert('XSS')</script> for basic testing")
            print(f"     - Use <img src=x onerror=alert('XSS')> for filter bypass")
            print(f"     - Use <svg onload=alert('XSS')> for SVG context")
            
        if url_params:
            print(f"  🔗 URL Parameters: Test {len(url_params)} parameter sets")
            print(f"     - Use javascript:alert('XSS') for URL context")
            print(f"     - Use data:text/html,<script>alert('XSS')</script> for data URI")
            print(f"     - Use vbscript:alert('XSS') for VBScript context")
            
        if js_vars:
            print(f"  ⚡ JavaScript Variables: Test {len(js_vars)} variable sets")
            print(f"     - Use ;alert('XSS'); for statement injection")
            print(f"     - Use \";alert('XSS');// for string termination")
            print(f"     - Use ';alert('XSS');// for single quote termination")
            
        # Priority recommendations
        total_inputs = len(forms) + len(url_params) + len(js_vars)
        if total_inputs > 0:
            print(f"\n{Fore.CYAN}⚡ PRIORITY TESTING ORDER:{Style.RESET_ALL}")
            print(f"  1. Forms with text inputs (highest priority)")
            print(f"  2. URL parameters (medium priority)")
            print(f"  3. JavaScript variables (lower priority)")
            print(f"  4. Test with context-specific payloads for each type")
            
    def get_context_specific_payloads(self, context_type: str) -> List[str]:
        """Get context-specific payloads for testing"""
        payloads = {
            'html_content': [
                '<script>alert("XSS")</script>',
                '<img src=x onerror=alert("XSS")>',
                '<svg onload=alert("XSS")>',
                '<iframe src=javascript:alert("XSS")></iframe>',
                '<object data=javascript:alert("XSS")></object>'
            ],
            'html_attribute': [
                '" onmouseover="alert(\'XSS\')" x="',
                "' onmouseover='alert(\"XSS\")' x='",
                '" onfocus="alert(\'XSS\')" autofocus="',
                "' onfocus='alert(\"XSS\")' autofocus='"
            ],
            'javascript_context': [
                ';alert("XSS");',
                '";alert("XSS");//',
                "';alert('XSS');//",
                '`;alert("XSS");//',
                '${alert("XSS")}'
            ],
            'css_context': [
                'expression(alert("XSS"))',
                'url("javascript:alert(\'XSS\')")',
                'url(javascript:alert("XSS"))'
            ],
            'url_context': [
                'javascript:alert("XSS")',
                'data:text/html,<script>alert("XSS")</script>',
                'vbscript:alert("XSS")'
            ],
            'comment_context': [
                '<!--<script>alert("XSS")</script>-->',
                '/*<script>alert("XSS")</script>*/',
                '//<script>alert("XSS")</script>'
            ]
        }
        
        return payloads.get(context_type, [])
        
    def generate_testing_plan(self, breakdown: Dict) -> Dict:
        """Generate a testing plan based on context breakdown"""
        plan = {
            'total_inputs': len(breakdown['forms']) + len(breakdown['url_params']) + len(breakdown['js_variables']),
            'forms_to_test': len(breakdown['forms']),
            'url_params_to_test': len(breakdown['url_params']),
            'js_vars_to_test': len(breakdown['js_variables']),
            'estimated_time': 0,
            'payloads_per_input': 5,
            'total_tests': 0
        }
        
        # Calculate estimated time
        plan['total_tests'] = plan['total_inputs'] * plan['payloads_per_input']
        plan['estimated_time'] = plan['total_tests'] * 2  # 2 seconds per test
        
        return plan