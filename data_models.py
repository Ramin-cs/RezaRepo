#!/usr/bin/env python3
"""
🔥 DATA MODELS - Complete Data Structures
"""

from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class Parameter:
    """Complete parameter model"""
    name: str
    value: str
    source: str  # 'url', 'form', 'javascript', 'headers', 'web3', 'meta', 'data_attribute'
    context: str  # 'query', 'fragment', 'form_input', 'js_variable', 'web3_config', 'http_header', 'meta_tag'
    url: str
    method: str = 'GET'
    is_redirect_related: bool = False
    confidence: float = 0.0
    line_number: int = 0
    pattern_matched: str = ""


@dataclass
class Vulnerability:
    """Complete vulnerability model"""
    url: str
    parameter: str
    payload: str
    method: str
    response_code: int
    redirect_url: str
    context: str
    screenshot_path: Optional[str] = None
    timestamp: str = ""
    vulnerability_type: str = "open_redirect"  # or "dom_based_redirect", "web3_redirect"
    confidence: float = 0.0
    impact: str = "MEDIUM"  # LOW, MEDIUM, HIGH, CRITICAL
    remediation: str = ""
    cvss_score: float = 5.0
    exploitation_complexity: str = "LOW"  # LOW, MEDIUM, HIGH
    business_impact: str = ""
    poc_steps: list = None
    exploitation_technique: Optional[str] = None
    chained_vulnerabilities: Optional[list] = None


@dataclass
class ScanResults:
    """Complete scan results model"""
    target_url: str
    scan_date: str
    scanner_version: str
    total_parameters: int
    redirect_parameters: int
    web3_parameters: int
    javascript_parameters: int
    vulnerabilities_found: int
    urls_discovered: int
    js_files_analyzed: int
    payload_count: int
    scan_duration: float
    waf_detected: bool
    waf_type: str = ""
    web3_detected: bool = False


@dataclass
class WAFInfo:
    """WAF detection information"""
    detected: bool = False
    type: str = "unknown"
    confidence: float = 0.0
    bypass_methods: list = None
    rate_limit: bool = False
    load_balancer: bool = False
    headers_detected: list = None