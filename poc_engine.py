#!/usr/bin/env python3
"""
🔥 POC ENGINE - Professional Proof of Concept Generation
"""

import asyncio
import hashlib
import time
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Optional
from dataclasses import dataclass, field

try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    SELENIUM_OK = True
except ImportError:
    SELENIUM_OK = False


@dataclass
class PoCEvidence:
    """PoC evidence data"""
    vulnerability_type: str
    url: str
    parameter: str
    payload: str
    evidence_type: str  # screenshot, network_log, response_header
    file_path: Optional[str] = None
    description: str = ""
    timestamp: str = ""
    additional_info: Dict = field(default_factory=dict)


@dataclass
class PoCReport:
    """Complete PoC report"""
    vulnerability_id: str
    target_url: str
    parameter: str
    payload: str
    impact: str
    cvss_score: float
    evidence: List[PoCEvidence] = field(default_factory=list)
    steps: List[str] = field(default_factory=list)
    remediation: str = ""
    business_impact: str = ""
    technical_details: Dict = field(default_factory=dict)


class PoCEngine:
    """Professional Proof of Concept generation engine"""
    
    def __init__(self):
        self.driver = None
        self.screenshots_dir = Path("ultimate_poc_evidence")
        self.screenshots_dir.mkdir(exist_ok=True)
        
        # PoC templates
        self.poc_templates = {
            'open_redirect': {
                'steps': [
                    "Navigate to the vulnerable endpoint",
                    "Inject malicious redirect payload",
                    "Observe successful redirect to attacker domain",
                    "Document evidence of exploitation"
                ],
                'impact': "Attackers can redirect users to malicious sites for phishing attacks",
                'remediation': "Implement URL validation with allowlist approach"
            },
            'dom_redirect': {
                'steps': [
                    "Navigate to the vulnerable page",
                    "Inject payload into DOM-controlled parameter",
                    "Observe client-side redirect execution",
                    "Capture evidence of DOM manipulation"
                ],
                'impact': "Client-side redirect bypass enables sophisticated phishing attacks",
                'remediation': "Sanitize user input before DOM manipulation"
            },
            'header_injection': {
                'steps': [
                    "Craft request with malicious header",
                    "Send request to vulnerable endpoint", 
                    "Observe header injection in response",
                    "Verify redirect header manipulation"
                ],
                'impact': "HTTP header injection can lead to cache poisoning and redirects",
                'remediation': "Validate and sanitize all HTTP headers"
            }
        }
        
        if SELENIUM_OK:
            self._init_browser()
    
    def _init_browser(self):
        """Initialize stealth browser"""
        try:
            chrome_options = Options()
            chrome_options.add_argument('--headless')
            chrome_options.add_argument('--no-sandbox') 
            chrome_options.add_argument('--disable-dev-shm-usage')
            chrome_options.add_argument('--disable-gpu')
            chrome_options.add_argument('--window-size=1920,1080')
            chrome_options.add_argument('--disable-blink-features=AutomationControlled')
            chrome_options.add_experimental_option("excludeSwitches", ["enable-automation"])
            chrome_options.add_experimental_option('useAutomationExtension', False)
            
            self.driver = webdriver.Chrome(options=chrome_options)
            
            # Anti-detection script
            stealth_script = """
                Object.defineProperty(navigator, 'webdriver', {
                    get: () => undefined,
                });
                window.chrome = { runtime: {} };
                Object.defineProperty(navigator, 'plugins', {
                    get: () => [1, 2, 3, 4, 5],
                });
            """
            self.driver.execute_script(stealth_script)
            
            print("[POC-ENGINE] Professional browser initialized")
            
        except Exception as e:
            print(f"[POC-ENGINE] Browser initialization failed: {e}")
            self.driver = None
    
    async def generate_poc(self, vulnerability_data: Dict) -> PoCReport:
        """Generate comprehensive PoC"""
        vuln_id = self._generate_vuln_id(vulnerability_data)
        vuln_type = vulnerability_data.get('vulnerability_type', 'open_redirect')
        
        poc_report = PoCReport(
            vulnerability_id=vuln_id,
            target_url=vulnerability_data['url'],
            parameter=vulnerability_data['parameter'],
            payload=vulnerability_data['payload'],
            impact=vulnerability_data.get('impact', 'HIGH'),
            cvss_score=vulnerability_data.get('cvss_score', 7.5)
        )
        
        # Generate evidence
        evidence = await self._generate_evidence(vulnerability_data)
        poc_report.evidence = evidence
        
        # Generate steps
        poc_report.steps = self._generate_steps(vulnerability_data, vuln_type)
        
        # Add technical details
        poc_report.technical_details = self._extract_technical_details(vulnerability_data)
        
        # Add remediation
        template = self.poc_templates.get(vuln_type, self.poc_templates['open_redirect'])
        poc_report.remediation = template['remediation']
        poc_report.business_impact = template['impact']
        
        print(f"[POC-ENGINE] Generated comprehensive PoC: {vuln_id}")
        return poc_report
    
    async def _generate_evidence(self, vulnerability_data: Dict) -> List[PoCEvidence]:
        """Generate multiple types of evidence"""
        evidence = []
        
        # Screenshot evidence
        if self.driver:
            screenshot_evidence = await self._capture_screenshot_evidence(vulnerability_data)
            if screenshot_evidence:
                evidence.append(screenshot_evidence)
        
        # Response header evidence
        if 'response_headers' in vulnerability_data:
            header_evidence = self._capture_header_evidence(vulnerability_data)
            if header_evidence:
                evidence.append(header_evidence)
        
        # Network log evidence
        network_evidence = self._capture_network_evidence(vulnerability_data)
        if network_evidence:
            evidence.append(network_evidence)
        
        return evidence
    
    async def _capture_screenshot_evidence(self, vulnerability_data: Dict) -> Optional[PoCEvidence]:
        """Capture screenshot evidence"""
        if not self.driver:
            return None
        
        try:
            url = vulnerability_data['url']
            payload = vulnerability_data['payload']
            
            # Generate filename
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            url_hash = hashlib.md5(url.encode()).hexdigest()[:8]
            filename = f"poc_screenshot_{timestamp}_{url_hash}.png"
            screenshot_path = self.screenshots_dir / filename
            
            # Navigate and capture
            self.driver.get(url)
            await asyncio.sleep(3)  # Wait for page load
            
            # Take screenshot
            self.driver.save_screenshot(str(screenshot_path))
            
            # Try to capture redirect if it occurs
            current_url = self.driver.current_url
            page_title = self.driver.title
            
            return PoCEvidence(
                vulnerability_type=vulnerability_data.get('vulnerability_type', 'open_redirect'),
                url=url,
                parameter=vulnerability_data['parameter'],
                payload=payload,
                evidence_type='screenshot',
                file_path=str(screenshot_path),
                description=f"Screenshot showing exploitation of {vulnerability_data['parameter']} parameter",
                timestamp=datetime.now().isoformat(),
                additional_info={
                    'current_url': current_url,
                    'page_title': page_title,
                    'redirect_occurred': current_url != url
                }
            )
            
        except Exception as e:
            print(f"[POC-ENGINE] Screenshot capture failed: {e}")
            return None
    
    def _capture_header_evidence(self, vulnerability_data: Dict) -> Optional[PoCEvidence]:
        """Capture response header evidence"""
        headers = vulnerability_data.get('response_headers', {})
        if not headers:
            return None
        
        # Look for redirect headers
        redirect_headers = {}
        for header_name, header_value in headers.items():
            if header_name.lower() in ['location', 'refresh', 'link']:
                redirect_headers[header_name] = header_value
        
        if redirect_headers:
            return PoCEvidence(
                vulnerability_type=vulnerability_data.get('vulnerability_type', 'open_redirect'),
                url=vulnerability_data['url'],
                parameter=vulnerability_data['parameter'],
                payload=vulnerability_data['payload'],
                evidence_type='response_header',
                description="HTTP response headers showing redirect behavior",
                timestamp=datetime.now().isoformat(),
                additional_info={
                    'redirect_headers': redirect_headers,
                    'all_headers': dict(headers)
                }
            )
        
        return None
    
    def _capture_network_evidence(self, vulnerability_data: Dict) -> Optional[PoCEvidence]:
        """Capture network request/response evidence"""
        return PoCEvidence(
            vulnerability_type=vulnerability_data.get('vulnerability_type', 'open_redirect'),
            url=vulnerability_data['url'],
            parameter=vulnerability_data['parameter'],
            payload=vulnerability_data['payload'],
            evidence_type='network_log',
            description="Network request/response demonstrating vulnerability",
            timestamp=datetime.now().isoformat(),
            additional_info={
                'request_url': vulnerability_data['url'],
                'response_code': vulnerability_data.get('response_code', 0),
                'redirect_url': vulnerability_data.get('redirect_url', ''),
                'method': vulnerability_data.get('method', 'GET')
            }
        )
    
    def _generate_steps(self, vulnerability_data: Dict, vuln_type: str) -> List[str]:
        """Generate detailed reproduction steps"""
        template = self.poc_templates.get(vuln_type, self.poc_templates['open_redirect'])
        base_steps = template['steps'].copy()
        
        # Customize steps with actual data
        detailed_steps = [
            f"1. Navigate to: {vulnerability_data['url']}",
            f"2. Identify vulnerable parameter: {vulnerability_data['parameter']}",
            f"3. Inject malicious payload: {vulnerability_data['payload']}",
            f"4. Observe response code: {vulnerability_data.get('response_code', 'N/A')}",
        ]
        
        if vulnerability_data.get('redirect_url'):
            detailed_steps.append(f"5. Verify redirect to: {vulnerability_data['redirect_url']}")
        
        detailed_steps.extend([
            "6. Document evidence of successful exploitation",
            "7. Assess business impact and create report"
        ])
        
        return detailed_steps
    
    def _extract_technical_details(self, vulnerability_data: Dict) -> Dict:
        """Extract technical details for PoC"""
        return {
            'vulnerability_type': vulnerability_data.get('vulnerability_type', 'open_redirect'),
            'attack_vector': 'Network',
            'attack_complexity': 'Low',
            'privileges_required': 'None',
            'user_interaction': 'Required',
            'scope': 'Changed',
            'confidentiality_impact': 'Low',
            'integrity_impact': 'Low', 
            'availability_impact': 'None',
            'exploit_url': vulnerability_data['url'],
            'vulnerable_parameter': vulnerability_data['parameter'],
            'payload_used': vulnerability_data['payload'],
            'http_method': vulnerability_data.get('method', 'GET'),
            'response_code': vulnerability_data.get('response_code', 0),
            'redirect_location': vulnerability_data.get('redirect_url', ''),
            'exploitation_time': datetime.now().isoformat()
        }
    
    def _generate_vuln_id(self, vulnerability_data: Dict) -> str:
        """Generate unique vulnerability ID"""
        data_string = f"{vulnerability_data['url']}{vulnerability_data['parameter']}{vulnerability_data['payload']}"
        hash_obj = hashlib.md5(data_string.encode())
        return f"OPENREDIR-{hash_obj.hexdigest()[:8].upper()}"
    
    def generate_visual_poc(self, poc_report: PoCReport) -> str:
        """Generate visual ASCII PoC representation"""
        return f"""
╔══════════════════════════════════════════════════════════════════════════════════╗
║                           🔥 PROFESSIONAL PROOF OF CONCEPT 🔥                    ║
╠══════════════════════════════════════════════════════════════════════════════════╣
║                                                                                  ║
║  VULNERABILITY ID: {poc_report.vulnerability_id:<52} ║
║  TARGET: {poc_report.target_url[:66]:<66} ║
║  PARAMETER: {poc_report.parameter:<61} ║
║  PAYLOAD: {poc_report.payload[:63]:<63} ║
║  IMPACT: {poc_report.impact:<66} ║
║  CVSS SCORE: {poc_report.cvss_score:<60} ║
║                                                                                  ║
║  EXPLOITATION FLOW:                                                              ║
║  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐                         ║
║  │   VICTIM    │───▶│   TARGET    │───▶│  ATTACKER   │                         ║
║  │   CLICKS    │    │   WEBSITE   │    │   WEBSITE   │                         ║
║  │   LINK      │    │   REDIRECTS │    │   RECEIVES  │                         ║
║  └─────────────┘    └─────────────┘    └─────────────┘                         ║
║                                                                                  ║
║  EVIDENCE COLLECTED:                                                             ║
║  • Screenshots: {len([e for e in poc_report.evidence if e.evidence_type == 'screenshot']):<59} ║
║  • Network Logs: {len([e for e in poc_report.evidence if e.evidence_type == 'network_log']):<58} ║
║  • Header Analysis: {len([e for e in poc_report.evidence if e.evidence_type == 'response_header']):<55} ║
║                                                                                  ║
╚══════════════════════════════════════════════════════════════════════════════════╝
        """
    
    def generate_bug_bounty_report(self, poc_report: PoCReport, language: str = 'english') -> str:
        """Generate professional bug bounty report"""
        if language == 'persian':
            return self._generate_persian_report(poc_report)
        else:
            return self._generate_english_report(poc_report)
    
    def _generate_english_report(self, poc_report: PoCReport) -> str:
        """Generate English bug bounty report"""
        steps_text = '\n'.join(f"{i}. {step}" for i, step in enumerate(poc_report.steps, 1))
        evidence_text = '\n'.join(f"- {e.evidence_type}: {e.description}" for e in poc_report.evidence)
        
        return f"""# Open Redirect Vulnerability Report

## Executive Summary
A critical open redirect vulnerability has been identified in the target application that allows attackers to redirect users to malicious domains.

## Vulnerability Details
- **Vulnerability ID**: {poc_report.vulnerability_id}
- **Target URL**: `{poc_report.target_url}`
- **Vulnerable Parameter**: `{poc_report.parameter}`
- **CVSS Score**: {poc_report.cvss_score}/10.0
- **Impact**: {poc_report.impact}

## Proof of Concept
### Reproduction Steps
{steps_text}

### Payload Used
```
{poc_report.payload}
```

### Evidence Collected
{evidence_text}

## Technical Impact
{poc_report.business_impact}

## Remediation
{poc_report.remediation}

## Business Risk
This vulnerability allows attackers to:
- Conduct phishing attacks by redirecting users to malicious sites
- Bypass security controls and filters
- Damage brand reputation through association with malicious content
- Facilitate social engineering attacks

## Recommendation Priority
**HIGH** - This vulnerability should be addressed immediately due to its potential for abuse in phishing campaigns.

---
*Report generated by Ultimate Open Redirect Hunter v4.0*
*Timestamp: {datetime.now().isoformat()}*
"""
    
    def _generate_persian_report(self, poc_report: PoCReport) -> str:
        """Generate Persian bug bounty report"""
        steps_text = '\n'.join(f"{i}. {step}" for i, step in enumerate(poc_report.steps, 1))
        evidence_text = '\n'.join(f"- {e.evidence_type}: {e.description}" for e in poc_report.evidence)
        
        return f"""# گزارش آسیب‌پذیری Open Redirect

## خلاصه اجرایی
یک آسیب‌پذیری بحرانی Open Redirect در برنامه هدف شناسایی شده که به مهاجمان امکان هدایت کاربران به دامنه‌های مخرب را می‌دهد.

## جزئیات آسیب‌پذیری
- **شناسه آسیب‌پذیری**: {poc_report.vulnerability_id}
- **URL هدف**: `{poc_report.target_url}`
- **پارامتر آسیب‌پذیر**: `{poc_report.parameter}`
- **امتیاز CVSS**: {poc_report.cvss_score}/10.0
- **تأثیر**: {poc_report.impact}

## اثبات مفهوم
### مراحل بازتولید
{steps_text}

### Payload استفاده شده
```
{poc_report.payload}
```

### شواهد جمع‌آوری شده
{evidence_text}

## تأثیر فنی
{poc_report.business_impact}

## راه‌حل
{poc_report.remediation}

## ریسک تجاری
این آسیب‌پذیری به مهاجمان امکان موارد زیر را می‌دهد:
- انجام حملات فیشینگ از طریق هدایت کاربران به سایت‌های مخرب
- دور زدن کنترل‌ها و فیلترهای امنیتی
- آسیب به اعتبار برند از طریق ارتباط با محتوای مخرب
- تسهیل حملات مهندسی اجتماعی

## اولویت توصیه
**بالا** - این آسیب‌پذیری باید فوراً به دلیل پتانسیل سوءاستفاده در کمپین‌های فیشینگ رفع شود.

---
*گزارش تولید شده توسط Ultimate Open Redirect Hunter v4.0*
*زمان: {datetime.now().isoformat()}*
"""
    
    def cleanup(self):
        """Cleanup browser resources"""
        if self.driver:
            try:
                self.driver.quit()
                print("[POC-ENGINE] Browser cleanup completed")
            except:
                pass