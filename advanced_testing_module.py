#!/usr/bin/env python3
"""
Advanced Testing Module for Open Redirect Scanner
Comprehensive testing with advanced techniques and validation
"""

import asyncio
import aiohttp
import time
import logging
import hashlib
import base64
import json
import random
import string
from typing import List, Dict, Optional, Any, Set
from urllib.parse import urljoin, urlparse, parse_qs, unquote
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

class AdvancedTestingModule:
    """
    Advanced testing module with comprehensive validation techniques
    """
    
    def __init__(self, logger, target_domain: str = "google.com"):
        self.logger = logger
        self.target_domain = target_domain
        self.test_results = []
        self.vulnerabilities = []
        self.performance_metrics = {
            'total_tests': 0,
            'successful_tests': 0,
            'failed_tests': 0,
            'start_time': None,
            'end_time': None
        }
        
        # Test categories
        self.test_categories = {
            'url': self._test_url_redirect,
            'url_redirect': self._test_url_redirect,
            'form': self._test_form_redirect,
            'form_redirect': self._test_form_redirect,
            'javascript': self._test_javascript_redirect,
            'javascript_redirect': self._test_javascript_redirect,
            'meta_refresh': self._test_meta_refresh_redirect,
            'meta_refresh_redirect': self._test_meta_refresh_redirect,
            'header': self._test_header_redirect,
            'header_redirect': self._test_header_redirect,
            'cookie': self._test_cookie_redirect,
            'cookie_redirect': self._test_cookie_redirect,
            'iframe': self._test_iframe_redirect,
            'iframe_redirect': self._test_iframe_redirect,
            'css': self._test_css_redirect,
            'css_redirect': self._test_css_redirect,
            'svg': self._test_svg_redirect,
            'svg_redirect': self._test_svg_redirect,
            'xml': self._test_xml_redirect,
            'xml_redirect': self._test_xml_redirect,
            'json': self._test_json_redirect,
            'json_redirect': self._test_json_redirect,
            'yaml': self._test_yaml_redirect,
            'yaml_redirect': self._test_yaml_redirect,
            'csv': self._test_csv_redirect,
            'csv_redirect': self._test_csv_redirect,
            'pdf': self._test_pdf_redirect,
            'pdf_redirect': self._test_pdf_redirect,
            'image': self._test_image_redirect,
            'image_redirect': self._test_image_redirect,
            'video': self._test_video_redirect,
            'video_redirect': self._test_video_redirect,
            'audio': self._test_audio_redirect,
            'audio_redirect': self._test_audio_redirect,
            'font': self._test_font_redirect,
            'font_redirect': self._test_font_redirect,
            'archive': self._test_archive_redirect,
            'archive_redirect': self._test_archive_redirect,
            'executable': self._test_executable_redirect,
            'executable_redirect': self._test_executable_redirect
        }
        
        # Redirect detection patterns
        self.redirect_patterns = {
            'http_redirects': [301, 302, 303, 307, 308],
            'javascript_redirects': [
                r'window\.location\s*=\s*["\']([^"\']+)["\']',
                r'window\.location\.href\s*=\s*["\']([^"\']+)["\']',
                r'document\.location\s*=\s*["\']([^"\']+)["\']',
                r'location\.href\s*=\s*["\']([^"\']+)["\']',
                r'location\.assign\s*\(\s*["\']([^"\']+)["\']',
                r'location\.replace\s*\(\s*["\']([^"\']+)["\']',
                r'top\.location\s*=\s*["\']([^"\']+)["\']',
                r'parent\.location\s*=\s*["\']([^"\']+)["\']',
                r'self\.location\s*=\s*["\']([^"\']+)["\']'
            ],
            'meta_refresh_redirects': [
                r'<meta[^>]*http-equiv\s*=\s*["\']refresh["\'][^>]*content\s*=\s*["\']([^"\']+)["\']',
                r'<meta[^>]*content\s*=\s*["\']([^"\']+)["\'][^>]*http-equiv\s*=\s*["\']refresh["\']'
            ],
            'iframe_redirects': [
                r'<iframe[^>]*src\s*=\s*["\']([^"\']+)["\']',
                r'<iframe[^>]*src\s*=\s*([^>\s]+)'
            ],
            'css_redirects': [
                r'@import\s+["\']([^"\']+)["\']',
                r'url\s*\(\s*["\']?([^"\')\s]+)["\']?\s*\)'
            ],
            'svg_redirects': [
                r'<image[^>]*href\s*=\s*["\']([^"\']+)["\']',
                r'<use[^>]*href\s*=\s*["\']([^"\']+)["\']'
            ]
        }
        
        # Validation techniques (placeholder for future implementation)
        self.validation_techniques = []
    
    async def initialize(self, session: aiohttp.ClientSession):
        """Initialize the testing module"""
        self.session = session
        self.performance_metrics['start_time'] = time.time()
        self.logger.info("🧪 Advanced Testing Module initialized")
        return True
    
    async def test_injection_point(self, injection_point: Dict, payload: str) -> Optional[Dict]:
        """Test a single injection point with a payload"""
        try:
            self.performance_metrics['total_tests'] += 1
            
            # Determine test type based on injection point
            test_type = injection_point.get('type', 'url')
            
            if test_type in self.test_categories:
                test_function = self.test_categories[test_type]
                result = await test_function(injection_point, payload)
                
                if result and result.get('vulnerable'):
                    self.performance_metrics['successful_tests'] += 1
                    self.vulnerabilities.append(result)
                    return result
                else:
                    self.performance_metrics['failed_tests'] += 1
                    return result
            else:
                self.logger.warning(f"⚠️ Unknown test type: {test_type}")
                return None
                
        except Exception as e:
            self.logger.error(f"❌ Error testing injection point: {str(e)}")
            self.performance_metrics['failed_tests'] += 1
            return None
    
    async def _test_url_redirect(self, injection_point: Dict, payload: str) -> Optional[Dict]:
        """Test URL-based redirect"""
        try:
            # Construct test URL
            test_url = self._construct_test_url(injection_point, payload)
            
            # Test with HTTP request
            result = await self._test_http_redirect(test_url, payload)
            
            if result and result.get('vulnerable'):
                return {
                    'vulnerable': True,
                    'test_type': 'url_redirect',
                    'injection_point': injection_point,
                    'payload': payload,
                    'test_url': test_url,
                    'redirect_url': result.get('redirect_url'),
                    'detection_method': result.get('detection_method'),
                    'timestamp': datetime.now().isoformat()
                }
            
            return {
                'vulnerable': False,
                'test_type': 'url_redirect',
                'injection_point': injection_point,
                'payload': payload,
                'test_url': test_url,
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"❌ Error testing URL redirect: {str(e)}")
            return None
    
    async def _test_form_redirect(self, injection_point: Dict, payload: str) -> Optional[Dict]:
        """Test form-based redirect"""
        try:
            # This would require form submission
            # For now, return placeholder
            return {
                'vulnerable': False,
                'test_type': 'form_redirect',
                'injection_point': injection_point,
                'payload': payload,
                'message': 'Form redirect testing not fully implemented',
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"❌ Error testing form redirect: {str(e)}")
            return None
    
    async def _test_javascript_redirect(self, injection_point: Dict, payload: str) -> Optional[Dict]:
        """Test JavaScript-based redirect"""
        try:
            # Create test page with JavaScript
            test_page = self._create_javascript_test_page(injection_point, payload)
            
            # Test JavaScript execution
            result = await self._test_javascript_execution(test_page, payload)
            
            if result and result.get('vulnerable'):
                return {
                    'vulnerable': True,
                    'test_type': 'javascript_redirect',
                    'injection_point': injection_point,
                    'payload': payload,
                    'redirect_url': result.get('redirect_url'),
                    'detection_method': 'javascript_execution',
                    'timestamp': datetime.now().isoformat()
                }
            
            return {
                'vulnerable': False,
                'test_type': 'javascript_redirect',
                'injection_point': injection_point,
                'payload': payload,
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"❌ Error testing JavaScript redirect: {str(e)}")
            return None
    
    async def _test_meta_refresh_redirect(self, injection_point: Dict, payload: str) -> Optional[Dict]:
        """Test meta refresh redirect"""
        try:
            # Create test page with meta refresh
            test_page = self._create_meta_refresh_test_page(injection_point, payload)
            
            # Test meta refresh
            result = await self._test_meta_refresh_execution(test_page, payload)
            
            if result and result.get('vulnerable'):
                return {
                    'vulnerable': True,
                    'test_type': 'meta_refresh_redirect',
                    'injection_point': injection_point,
                    'payload': payload,
                    'redirect_url': result.get('redirect_url'),
                    'detection_method': 'meta_refresh',
                    'timestamp': datetime.now().isoformat()
                }
            
            return {
                'vulnerable': False,
                'test_type': 'meta_refresh_redirect',
                'injection_point': injection_point,
                'payload': payload,
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"❌ Error testing meta refresh redirect: {str(e)}")
            return None
    
    async def _test_header_redirect(self, injection_point: Dict, payload: str) -> Optional[Dict]:
        """Test header-based redirect"""
        try:
            # Test with custom headers
            result = await self._test_custom_headers(injection_point, payload)
            
            if result and result.get('vulnerable'):
                return {
                    'vulnerable': True,
                    'test_type': 'header_redirect',
                    'injection_point': injection_point,
                    'payload': payload,
                    'redirect_url': result.get('redirect_url'),
                    'detection_method': 'header_injection',
                    'timestamp': datetime.now().isoformat()
                }
            
            return {
                'vulnerable': False,
                'test_type': 'header_redirect',
                'injection_point': injection_point,
                'payload': payload,
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"❌ Error testing header redirect: {str(e)}")
            return None
    
    async def _test_cookie_redirect(self, injection_point: Dict, payload: str) -> Optional[Dict]:
        """Test cookie-based redirect"""
        try:
            # Test with custom cookies
            result = await self._test_custom_cookies(injection_point, payload)
            
            if result and result.get('vulnerable'):
                return {
                    'vulnerable': True,
                    'test_type': 'cookie_redirect',
                    'injection_point': injection_point,
                    'payload': payload,
                    'redirect_url': result.get('redirect_url'),
                    'detection_method': 'cookie_injection',
                    'timestamp': datetime.now().isoformat()
                }
            
            return {
                'vulnerable': False,
                'test_type': 'cookie_redirect',
                'injection_point': injection_point,
                'payload': payload,
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"❌ Error testing cookie redirect: {str(e)}")
            return None
    
    async def _test_iframe_redirect(self, injection_point: Dict, payload: str) -> Optional[Dict]:
        """Test iframe-based redirect"""
        try:
            # Create test page with iframe
            test_page = self._create_iframe_test_page(injection_point, payload)
            
            # Test iframe redirect
            result = await self._test_iframe_execution(test_page, payload)
            
            if result and result.get('vulnerable'):
                return {
                    'vulnerable': True,
                    'test_type': 'iframe_redirect',
                    'injection_point': injection_point,
                    'payload': payload,
                    'redirect_url': result.get('redirect_url'),
                    'detection_method': 'iframe_injection',
                    'timestamp': datetime.now().isoformat()
                }
            
            return {
                'vulnerable': False,
                'test_type': 'iframe_redirect',
                'injection_point': injection_point,
                'payload': payload,
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"❌ Error testing iframe redirect: {str(e)}")
            return None
    
    async def _test_css_redirect(self, injection_point: Dict, payload: str) -> Optional[Dict]:
        """Test CSS-based redirect"""
        try:
            # Create test CSS with redirect
            test_css = self._create_css_test_content(injection_point, payload)
            
            # Test CSS redirect
            result = await self._test_css_execution(test_css, payload)
            
            if result and result.get('vulnerable'):
                return {
                    'vulnerable': True,
                    'test_type': 'css_redirect',
                    'injection_point': injection_point,
                    'payload': payload,
                    'redirect_url': result.get('redirect_url'),
                    'detection_method': 'css_injection',
                    'timestamp': datetime.now().isoformat()
                }
            
            return {
                'vulnerable': False,
                'test_type': 'css_redirect',
                'injection_point': injection_point,
                'payload': payload,
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"❌ Error testing CSS redirect: {str(e)}")
            return None
    
    async def _test_svg_redirect(self, injection_point: Dict, payload: str) -> Optional[Dict]:
        """Test SVG-based redirect"""
        try:
            # Create test SVG with redirect
            test_svg = self._create_svg_test_content(injection_point, payload)
            
            # Test SVG redirect
            result = await self._test_svg_execution(test_svg, payload)
            
            if result and result.get('vulnerable'):
                return {
                    'vulnerable': True,
                    'test_type': 'svg_redirect',
                    'injection_point': injection_point,
                    'payload': payload,
                    'redirect_url': result.get('redirect_url'),
                    'detection_method': 'svg_injection',
                    'timestamp': datetime.now().isoformat()
                }
            
            return {
                'vulnerable': False,
                'test_type': 'svg_redirect',
                'injection_point': injection_point,
                'payload': payload,
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"❌ Error testing SVG redirect: {str(e)}")
            return None
    
    async def _test_xml_redirect(self, injection_point: Dict, payload: str) -> Optional[Dict]:
        """Test XML-based redirect"""
        try:
            # Create test XML with redirect
            test_xml = self._create_xml_test_content(injection_point, payload)
            
            # Test XML redirect
            result = await self._test_xml_execution(test_xml, payload)
            
            if result and result.get('vulnerable'):
                return {
                    'vulnerable': True,
                    'test_type': 'xml_redirect',
                    'injection_point': injection_point,
                    'payload': payload,
                    'redirect_url': result.get('redirect_url'),
                    'detection_method': 'xml_injection',
                    'timestamp': datetime.now().isoformat()
                }
            
            return {
                'vulnerable': False,
                'test_type': 'xml_redirect',
                'injection_point': injection_point,
                'payload': payload,
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"❌ Error testing XML redirect: {str(e)}")
            return None
    
    async def _test_json_redirect(self, injection_point: Dict, payload: str) -> Optional[Dict]:
        """Test JSON-based redirect"""
        try:
            # Create test JSON with redirect
            test_json = self._create_json_test_content(injection_point, payload)
            
            # Test JSON redirect
            result = await self._test_json_execution(test_json, payload)
            
            if result and result.get('vulnerable'):
                return {
                    'vulnerable': True,
                    'test_type': 'json_redirect',
                    'injection_point': injection_point,
                    'payload': payload,
                    'redirect_url': result.get('redirect_url'),
                    'detection_method': 'json_injection',
                    'timestamp': datetime.now().isoformat()
                }
            
            return {
                'vulnerable': False,
                'test_type': 'json_redirect',
                'injection_point': injection_point,
                'payload': payload,
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"❌ Error testing JSON redirect: {str(e)}")
            return None
    
    async def _test_yaml_redirect(self, injection_point: Dict, payload: str) -> Optional[Dict]:
        """Test YAML-based redirect"""
        try:
            # Create test YAML with redirect
            test_yaml = self._create_yaml_test_content(injection_point, payload)
            
            # Test YAML redirect
            result = await self._test_yaml_execution(test_yaml, payload)
            
            if result and result.get('vulnerable'):
                return {
                    'vulnerable': True,
                    'test_type': 'yaml_redirect',
                    'injection_point': injection_point,
                    'payload': payload,
                    'redirect_url': result.get('redirect_url'),
                    'detection_method': 'yaml_injection',
                    'timestamp': datetime.now().isoformat()
                }
            
            return {
                'vulnerable': False,
                'test_type': 'yaml_redirect',
                'injection_point': injection_point,
                'payload': payload,
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"❌ Error testing YAML redirect: {str(e)}")
            return None
    
    async def _test_csv_redirect(self, injection_point: Dict, payload: str) -> Optional[Dict]:
        """Test CSV-based redirect"""
        try:
            # Create test CSV with redirect
            test_csv = self._create_csv_test_content(injection_point, payload)
            
            # Test CSV redirect
            result = await self._test_csv_execution(test_csv, payload)
            
            if result and result.get('vulnerable'):
                return {
                    'vulnerable': True,
                    'test_type': 'csv_redirect',
                    'injection_point': injection_point,
                    'payload': payload,
                    'redirect_url': result.get('redirect_url'),
                    'detection_method': 'csv_injection',
                    'timestamp': datetime.now().isoformat()
                }
            
            return {
                'vulnerable': False,
                'test_type': 'csv_redirect',
                'injection_point': injection_point,
                'payload': payload,
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"❌ Error testing CSV redirect: {str(e)}")
            return None
    
    async def _test_pdf_redirect(self, injection_point: Dict, payload: str) -> Optional[Dict]:
        """Test PDF-based redirect"""
        try:
            # Create test PDF with redirect
            test_pdf = self._create_pdf_test_content(injection_point, payload)
            
            # Test PDF redirect
            result = await self._test_pdf_execution(test_pdf, payload)
            
            if result and result.get('vulnerable'):
                return {
                    'vulnerable': True,
                    'test_type': 'pdf_redirect',
                    'injection_point': injection_point,
                    'payload': payload,
                    'redirect_url': result.get('redirect_url'),
                    'detection_method': 'pdf_injection',
                    'timestamp': datetime.now().isoformat()
                }
            
            return {
                'vulnerable': False,
                'test_type': 'pdf_redirect',
                'injection_point': injection_point,
                'payload': payload,
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"❌ Error testing PDF redirect: {str(e)}")
            return None
    
    async def _test_image_redirect(self, injection_point: Dict, payload: str) -> Optional[Dict]:
        """Test image-based redirect"""
        try:
            # Create test image with redirect
            test_image = self._create_image_test_content(injection_point, payload)
            
            # Test image redirect
            result = await self._test_image_execution(test_image, payload)
            
            if result and result.get('vulnerable'):
                return {
                    'vulnerable': True,
                    'test_type': 'image_redirect',
                    'injection_point': injection_point,
                    'payload': payload,
                    'redirect_url': result.get('redirect_url'),
                    'detection_method': 'image_injection',
                    'timestamp': datetime.now().isoformat()
                }
            
            return {
                'vulnerable': False,
                'test_type': 'image_redirect',
                'injection_point': injection_point,
                'payload': payload,
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"❌ Error testing image redirect: {str(e)}")
            return None
    
    async def _test_video_redirect(self, injection_point: Dict, payload: str) -> Optional[Dict]:
        """Test video-based redirect"""
        try:
            # Create test video with redirect
            test_video = self._create_video_test_content(injection_point, payload)
            
            # Test video redirect
            result = await self._test_video_execution(test_video, payload)
            
            if result and result.get('vulnerable'):
                return {
                    'vulnerable': True,
                    'test_type': 'video_redirect',
                    'injection_point': injection_point,
                    'payload': payload,
                    'redirect_url': result.get('redirect_url'),
                    'detection_method': 'video_injection',
                    'timestamp': datetime.now().isoformat()
                }
            
            return {
                'vulnerable': False,
                'test_type': 'video_redirect',
                'injection_point': injection_point,
                'payload': payload,
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"❌ Error testing video redirect: {str(e)}")
            return None
    
    async def _test_audio_redirect(self, injection_point: Dict, payload: str) -> Optional[Dict]:
        """Test audio-based redirect"""
        try:
            # Create test audio with redirect
            test_audio = self._create_audio_test_content(injection_point, payload)
            
            # Test audio redirect
            result = await self._test_audio_execution(test_audio, payload)
            
            if result and result.get('vulnerable'):
                return {
                    'vulnerable': True,
                    'test_type': 'audio_redirect',
                    'injection_point': injection_point,
                    'payload': payload,
                    'redirect_url': result.get('redirect_url'),
                    'detection_method': 'audio_injection',
                    'timestamp': datetime.now().isoformat()
                }
            
            return {
                'vulnerable': False,
                'test_type': 'audio_redirect',
                'injection_point': injection_point,
                'payload': payload,
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"❌ Error testing audio redirect: {str(e)}")
            return None
    
    async def _test_font_redirect(self, injection_point: Dict, payload: str) -> Optional[Dict]:
        """Test font-based redirect"""
        try:
            # Create test font with redirect
            test_font = self._create_font_test_content(injection_point, payload)
            
            # Test font redirect
            result = await self._test_font_execution(test_font, payload)
            
            if result and result.get('vulnerable'):
                return {
                    'vulnerable': True,
                    'test_type': 'font_redirect',
                    'injection_point': injection_point,
                    'payload': payload,
                    'redirect_url': result.get('redirect_url'),
                    'detection_method': 'font_injection',
                    'timestamp': datetime.now().isoformat()
                }
            
            return {
                'vulnerable': False,
                'test_type': 'font_redirect',
                'injection_point': injection_point,
                'payload': payload,
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"❌ Error testing font redirect: {str(e)}")
            return None
    
    async def _test_archive_redirect(self, injection_point: Dict, payload: str) -> Optional[Dict]:
        """Test archive-based redirect"""
        try:
            # Create test archive with redirect
            test_archive = self._create_archive_test_content(injection_point, payload)
            
            # Test archive redirect
            result = await self._test_archive_execution(test_archive, payload)
            
            if result and result.get('vulnerable'):
                return {
                    'vulnerable': True,
                    'test_type': 'archive_redirect',
                    'injection_point': injection_point,
                    'payload': payload,
                    'redirect_url': result.get('redirect_url'),
                    'detection_method': 'archive_injection',
                    'timestamp': datetime.now().isoformat()
                }
            
            return {
                'vulnerable': False,
                'test_type': 'archive_redirect',
                'injection_point': injection_point,
                'payload': payload,
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"❌ Error testing archive redirect: {str(e)}")
            return None
    
    async def _test_executable_redirect(self, injection_point: Dict, payload: str) -> Optional[Dict]:
        """Test executable-based redirect"""
        try:
            # Create test executable with redirect
            test_executable = self._create_executable_test_content(injection_point, payload)
            
            # Test executable redirect
            result = await self._test_executable_execution(test_executable, payload)
            
            if result and result.get('vulnerable'):
                return {
                    'vulnerable': True,
                    'test_type': 'executable_redirect',
                    'injection_point': injection_point,
                    'payload': payload,
                    'redirect_url': result.get('redirect_url'),
                    'detection_method': 'executable_injection',
                    'timestamp': datetime.now().isoformat()
                }
            
            return {
                'vulnerable': False,
                'test_type': 'executable_redirect',
                'injection_point': injection_point,
                'payload': payload,
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"❌ Error testing executable redirect: {str(e)}")
            return None
    
    def _construct_test_url(self, injection_point: Dict, payload: str) -> str:
        """Construct test URL with payload"""
        base_url = injection_point['url']
        param_name = injection_point['parameter']
        param_type = injection_point['type']
        
        if param_type == 'url':
            # URL parameter
            parsed = urlparse(base_url)
            query_params = parse_qs(parsed.query)
            query_params[param_name] = [payload]
            
            new_query = '&'.join([f"{k}={v[0]}" for k, v in query_params.items()])
            return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
        
        else:
            return base_url
    
    async def _test_http_redirect(self, test_url: str, payload: str) -> Optional[Dict]:
        """Test HTTP redirect using aiohttp"""
        try:
            async with self.session.get(test_url, allow_redirects=False) as response:
                # Check for redirect status codes
                if response.status in self.redirect_patterns['http_redirects']:
                    location = response.headers.get('Location', '')
                    
                    # Check if redirected to target domain
                    if self.target_domain in location.lower():
                        return {
                            'vulnerable': True,
                            'original_url': test_url,
                            'redirect_url': location,
                            'payload': payload,
                            'status_code': response.status,
                            'detection_method': 'http_redirect'
                        }
                
                # Also check if the response contains redirect patterns
                content = await response.text()
                if self._check_redirect_patterns(content, payload):
                    return {
                        'vulnerable': True,
                        'original_url': test_url,
                        'redirect_url': 'JavaScript/HTML redirect detected',
                        'payload': payload,
                        'status_code': response.status,
                        'detection_method': 'content_redirect'
                    }
                
                return {
                    'vulnerable': False,
                    'original_url': test_url,
                    'payload': payload,
                    'status_code': response.status
                }
                
        except Exception as e:
            self.logger.error(f"❌ Error testing HTTP redirect {test_url}: {str(e)}")
            return None
    
    def _check_redirect_patterns(self, content: str, payload: str) -> bool:
        """Check for redirect patterns in content"""
        for pattern_type, patterns in self.redirect_patterns.items():
            if pattern_type == 'http_redirects':
                continue
            
            for pattern in patterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                for match in matches:
                    if self.target_domain in match.lower():
                        return True
        
        return False
    
    def _create_javascript_test_page(self, injection_point: Dict, payload: str) -> str:
        """Create test page with JavaScript redirect"""
        return f"""
        <!DOCTYPE html>
        <html>
        <head><title>JavaScript Redirect Test</title></head>
        <body>
            <script>
                var {injection_point.get('parameter', 'redirect')} = "{payload}";
                window.location = {injection_point.get('parameter', 'redirect')};
            </script>
        </body>
        </html>
        """
    
    def _create_meta_refresh_test_page(self, injection_point: Dict, payload: str) -> str:
        """Create test page with meta refresh redirect"""
        return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Meta Refresh Redirect Test</title>
            <meta http-equiv="refresh" content="0;url={payload}">
        </head>
        <body>
            <p>Redirecting...</p>
        </body>
        </html>
        """
    
    def _create_iframe_test_page(self, injection_point: Dict, payload: str) -> str:
        """Create test page with iframe redirect"""
        return f"""
        <!DOCTYPE html>
        <html>
        <head><title>Iframe Redirect Test</title></head>
        <body>
            <iframe src="{payload}" width="100%" height="100%"></iframe>
        </body>
        </html>
        """
    
    def _create_css_test_content(self, injection_point: Dict, payload: str) -> str:
        """Create test CSS with redirect"""
        return f"""
        @import url("{payload}");
        body {{
            background-image: url("{payload}");
        }}
        """
    
    def _create_svg_test_content(self, injection_point: Dict, payload: str) -> str:
        """Create test SVG with redirect"""
        return f"""
        <svg xmlns="http://www.w3.org/2000/svg">
            <image href="{payload}" width="100" height="100"/>
            <use href="{payload}"/>
        </svg>
        """
    
    def _create_xml_test_content(self, injection_point: Dict, payload: str) -> str:
        """Create test XML with redirect"""
        return f"""
        <?xml version="1.0" encoding="UTF-8"?>
        <root>
            <redirect>{payload}</redirect>
            <url>{payload}</url>
        </root>
        """
    
    def _create_json_test_content(self, injection_point: Dict, payload: str) -> str:
        """Create test JSON with redirect"""
        return json.dumps({
            "redirect": payload,
            "url": payload,
            "location": payload
        })
    
    def _create_yaml_test_content(self, injection_point: Dict, payload: str) -> str:
        """Create test YAML with redirect"""
        return f"""
        redirect: {payload}
        url: {payload}
        location: {payload}
        """
    
    def _create_csv_test_content(self, injection_point: Dict, payload: str) -> str:
        """Create test CSV with redirect"""
        return f"""
        redirect,url,location
        {payload},{payload},{payload}
        """
    
    def _create_pdf_test_content(self, injection_point: Dict, payload: str) -> str:
        """Create test PDF with redirect"""
        # This would require PDF generation library
        return f"PDF content with redirect: {payload}"
    
    def _create_image_test_content(self, injection_point: Dict, payload: str) -> str:
        """Create test image with redirect"""
        # This would require image generation library
        return f"Image content with redirect: {payload}"
    
    def _create_video_test_content(self, injection_point: Dict, payload: str) -> str:
        """Create test video with redirect"""
        # This would require video generation library
        return f"Video content with redirect: {payload}"
    
    def _create_audio_test_content(self, injection_point: Dict, payload: str) -> str:
        """Create test audio with redirect"""
        # This would require audio generation library
        return f"Audio content with redirect: {payload}"
    
    def _create_font_test_content(self, injection_point: Dict, payload: str) -> str:
        """Create test font with redirect"""
        # This would require font generation library
        return f"Font content with redirect: {payload}"
    
    def _create_archive_test_content(self, injection_point: Dict, payload: str) -> str:
        """Create test archive with redirect"""
        # This would require archive generation library
        return f"Archive content with redirect: {payload}"
    
    def _create_executable_test_content(self, injection_point: Dict, payload: str) -> str:
        """Create test executable with redirect"""
        # This would require executable generation library
        return f"Executable content with redirect: {payload}"
    
    async def _test_javascript_execution(self, test_page: str, payload: str) -> Optional[Dict]:
        """Test JavaScript execution"""
        # This would require JavaScript engine
        return {'vulnerable': False, 'message': 'JavaScript execution not implemented'}
    
    async def _test_meta_refresh_execution(self, test_page: str, payload: str) -> Optional[Dict]:
        """Test meta refresh execution"""
        # This would require HTML parser
        return {'vulnerable': False, 'message': 'Meta refresh execution not implemented'}
    
    async def _test_iframe_execution(self, test_page: str, payload: str) -> Optional[Dict]:
        """Test iframe execution"""
        # This would require iframe testing
        return {'vulnerable': False, 'message': 'Iframe execution not implemented'}
    
    async def _test_css_execution(self, test_css: str, payload: str) -> Optional[Dict]:
        """Test CSS execution"""
        # This would require CSS parser
        return {'vulnerable': False, 'message': 'CSS execution not implemented'}
    
    async def _test_svg_execution(self, test_svg: str, payload: str) -> Optional[Dict]:
        """Test SVG execution"""
        # This would require SVG parser
        return {'vulnerable': False, 'message': 'SVG execution not implemented'}
    
    async def _test_xml_execution(self, test_xml: str, payload: str) -> Optional[Dict]:
        """Test XML execution"""
        # This would require XML parser
        return {'vulnerable': False, 'message': 'XML execution not implemented'}
    
    async def _test_json_execution(self, test_json: str, payload: str) -> Optional[Dict]:
        """Test JSON execution"""
        # This would require JSON parser
        return {'vulnerable': False, 'message': 'JSON execution not implemented'}
    
    async def _test_yaml_execution(self, test_yaml: str, payload: str) -> Optional[Dict]:
        """Test YAML execution"""
        # This would require YAML parser
        return {'vulnerable': False, 'message': 'YAML execution not implemented'}
    
    async def _test_csv_execution(self, test_csv: str, payload: str) -> Optional[Dict]:
        """Test CSV execution"""
        # This would require CSV parser
        return {'vulnerable': False, 'message': 'CSV execution not implemented'}
    
    async def _test_pdf_execution(self, test_pdf: str, payload: str) -> Optional[Dict]:
        """Test PDF execution"""
        # This would require PDF parser
        return {'vulnerable': False, 'message': 'PDF execution not implemented'}
    
    async def _test_image_execution(self, test_image: str, payload: str) -> Optional[Dict]:
        """Test image execution"""
        # This would require image parser
        return {'vulnerable': False, 'message': 'Image execution not implemented'}
    
    async def _test_video_execution(self, test_video: str, payload: str) -> Optional[Dict]:
        """Test video execution"""
        # This would require video parser
        return {'vulnerable': False, 'message': 'Video execution not implemented'}
    
    async def _test_audio_execution(self, test_audio: str, payload: str) -> Optional[Dict]:
        """Test audio execution"""
        # This would require audio parser
        return {'vulnerable': False, 'message': 'Audio execution not implemented'}
    
    async def _test_font_execution(self, test_font: str, payload: str) -> Optional[Dict]:
        """Test font execution"""
        # This would require font parser
        return {'vulnerable': False, 'message': 'Font execution not implemented'}
    
    async def _test_archive_execution(self, test_archive: str, payload: str) -> Optional[Dict]:
        """Test archive execution"""
        # This would require archive parser
        return {'vulnerable': False, 'message': 'Archive execution not implemented'}
    
    async def _test_executable_execution(self, test_executable: str, payload: str) -> Optional[Dict]:
        """Test executable execution"""
        # This would require executable parser
        return {'vulnerable': False, 'message': 'Executable execution not implemented'}
    
    async def _test_custom_headers(self, injection_point: Dict, payload: str) -> Optional[Dict]:
        """Test custom headers"""
        # This would require custom header testing
        return {'vulnerable': False, 'message': 'Custom header testing not implemented'}
    
    async def _test_custom_cookies(self, injection_point: Dict, payload: str) -> Optional[Dict]:
        """Test custom cookies"""
        # This would require custom cookie testing
        return {'vulnerable': False, 'message': 'Custom cookie testing not implemented'}
    
    def get_performance_metrics(self) -> Dict:
        """Get performance metrics"""
        self.performance_metrics['end_time'] = time.time()
        if self.performance_metrics['start_time']:
            self.performance_metrics['duration'] = self.performance_metrics['end_time'] - self.performance_metrics['start_time']
        return self.performance_metrics
    
    def get_vulnerabilities(self) -> List[Dict]:
        """Get all vulnerabilities found"""
        return self.vulnerabilities
    
    def get_vulnerability_count(self) -> int:
        """Get vulnerability count"""
        return len(self.vulnerabilities)
    
    def get_vulnerability_summary(self) -> Dict:
        """Get vulnerability summary"""
        summary = {
            'total_vulnerabilities': len(self.vulnerabilities),
            'by_type': {},
            'by_severity': {'high': 0, 'medium': 0, 'low': 0}
        }
        
        for vuln in self.vulnerabilities:
            vuln_type = vuln.get('test_type', 'unknown')
            summary['by_type'][vuln_type] = summary['by_type'].get(vuln_type, 0) + 1
            
            # Determine severity based on test type
            if vuln_type in ['url_redirect', 'javascript_redirect']:
                summary['by_severity']['high'] += 1
            elif vuln_type in ['form_redirect', 'meta_refresh_redirect']:
                summary['by_severity']['medium'] += 1
            else:
                summary['by_severity']['low'] += 1
        
        return summary