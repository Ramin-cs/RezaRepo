#!/usr/bin/env python3
"""
Bug Bounty Testing Module for Open Redirect Scanner
Specialized testing for Web2 and Web3 bug bounty targets
"""

import asyncio
import aiohttp
import json
import logging
from typing import List, Dict, Set, Optional, Any
from dataclasses import dataclass
from pathlib import Path
import time
from urllib.parse import urlparse

from enhanced_scanner import EnhancedOpenRedirectScanner
from utils import URLUtils, PayloadGenerator, Web3Utils


@dataclass
class BugBountyTarget:
    """Bug bounty target configuration"""
    name: str
    url: str
    platform: str  # 'web2', 'web3', 'hybrid'
    scope: List[str]  # List of in-scope domains/subdomains
    out_of_scope: List[str]  # List of out-of-scope patterns
    special_notes: str = ""
    rate_limit: float = 0.1  # Delay between requests
    max_depth: int = 3
    max_pages: int = 100
    priority_parameters: List[str] = None  # High-priority parameters to focus on


class BugBountyTester:
    """Specialized tester for bug bounty programs"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.results: Dict[str, Any] = {}
        
        # Load known bug bounty targets (examples)
        self.targets = self.load_example_targets()
    
    def load_example_targets(self) -> List[BugBountyTarget]:
        """Load example bug bounty targets (for educational purposes)"""
        return [
            # Web2 Examples
            BugBountyTarget(
                name="Generic Web2 App",
                url="https://example-web2.com",
                platform="web2",
                scope=["*.example-web2.com"],
                out_of_scope=["admin.example-web2.com", "internal.example-web2.com"],
                special_notes="Focus on authentication flows and redirects",
                priority_parameters=["redirect_uri", "return_url", "next", "callback"]
            ),
            
            # Web3 Examples  
            BugBountyTarget(
                name="Generic DApp",
                url="https://example-dapp.com",
                platform="web3",
                scope=["*.example-dapp.com", "app.example-dapp.com"],
                out_of_scope=["api.example-dapp.com"],
                special_notes="Test wallet connections and contract interactions",
                priority_parameters=["wallet_redirect", "connect_url", "provider_url", "network_url"]
            ),
            
            # Hybrid Examples
            BugBountyTarget(
                name="Hybrid Platform",
                url="https://example-hybrid.com", 
                platform="hybrid",
                scope=["*.example-hybrid.com"],
                out_of_scope=["cdn.example-hybrid.com"],
                special_notes="Test both traditional web and Web3 features",
                priority_parameters=["redirect", "url", "wallet_callback", "dapp_redirect"]
            )
        ]
    
    async def test_bug_bounty_target(self, target: BugBountyTarget) -> Dict[str, Any]:
        """Test a specific bug bounty target"""
        self.logger.info(f"🎯 Testing bug bounty target: {target.name}")
        
        # Validate target is in scope
        if not self.is_target_in_scope(target.url, target.scope, target.out_of_scope):
            self.logger.warning(f"Target {target.url} appears to be out of scope")
            return {"error": "Out of scope"}
        
        # Create specialized scanner for this target
        scanner = EnhancedOpenRedirectScanner(
            target.url, 
            max_depth=target.max_depth, 
            max_pages=target.max_pages
        )
        
        # Customize scanner for bug bounty testing
        await self.customize_scanner_for_target(scanner, target)
        
        # Run scan with target-specific configuration
        start_time = time.time()
        
        try:
            await scanner.init_session()
            scanner.init_enhanced_driver()
            
            # Phase 1: Reconnaissance
            self.logger.info(f"Phase 1: Reconnaissance for {target.name}")
            await scanner.enhanced_crawl_website()
            
            # Phase 2: Focused parameter analysis
            self.logger.info(f"Phase 2: Focused parameter analysis")
            priority_params = self.extract_priority_parameters(scanner.parameters, target)
            
            # Phase 3: Targeted vulnerability testing
            self.logger.info(f"Phase 3: Targeted vulnerability testing")
            vulnerabilities = await self.focused_vulnerability_testing(scanner, priority_params, target)
            
            # Phase 4: Specialized testing based on platform
            if target.platform == "web3":
                web3_vulns = await self.test_web3_specific_vulnerabilities(scanner, target)
                vulnerabilities.extend(web3_vulns)
            
            scan_duration = time.time() - start_time
            
            # Compile results
            results = {
                "target": target.name,
                "url": target.url,
                "platform": target.platform,
                "scan_duration": scan_duration,
                "urls_discovered": len(scanner.discovered_urls),
                "parameters_found": len(scanner.parameters),
                "priority_parameters": len(priority_params),
                "vulnerabilities": [asdict(v) for v in vulnerabilities],
                "vulnerability_count": len(vulnerabilities),
                "high_impact_vulns": len([v for v in vulnerabilities if v.impact_assessment == "HIGH"]),
                "recommendations": self.generate_bug_bounty_recommendations(vulnerabilities, target)
            }
            
            # Save target-specific report
            await self.save_bug_bounty_report(results, target)
            
            return results
            
        except Exception as e:
            self.logger.error(f"Bug bounty testing failed for {target.name}: {e}")
            return {"error": str(e)}
        finally:
            if scanner.session:
                await scanner.session.close()
            if scanner.driver:
                scanner.driver.quit()
    
    def is_target_in_scope(self, url: str, scope: List[str], out_of_scope: List[str]) -> bool:
        """Check if target is within bug bounty scope"""
        domain = URLUtils.extract_domain(url)
        
        # Check out of scope first
        for oos_pattern in out_of_scope:
            if self.matches_pattern(domain, oos_pattern):
                return False
        
        # Check in scope
        for scope_pattern in scope:
            if self.matches_pattern(domain, scope_pattern):
                return True
        
        return False
    
    def matches_pattern(self, domain: str, pattern: str) -> bool:
        """Check if domain matches scope pattern"""
        if pattern.startswith('*.'):
            # Wildcard subdomain
            base_domain = pattern[2:]
            return domain == base_domain or domain.endswith(f'.{base_domain}')
        else:
            return domain == pattern
    
    async def customize_scanner_for_target(self, scanner: EnhancedOpenRedirectScanner, target: BugBountyTarget):
        """Customize scanner configuration for specific target"""
        # Adjust rate limiting
        scanner.request_delay = target.rate_limit
        
        # Add target-specific payloads
        if target.platform == "web3":
            # Add Web3-specific test domain
            web3_payloads = [
                "//metamask.io",
                "//wallet.connect", 
                "//uniswap.org",
                "web3://test.eth",
                "ipfs://QmTest"
            ]
            scanner.payloads['web3_specific'].extend(web3_payloads)
        
        # Configure scope checking
        scanner.scope_domains = target.scope
        scanner.out_of_scope_domains = target.out_of_scope
    
    def extract_priority_parameters(self, all_params: List, target: BugBountyTarget) -> List:
        """Extract priority parameters based on target configuration"""
        if not target.priority_parameters:
            # Default priority: redirect-related parameters
            return [p for p in all_params if p.is_redirect_related]
        
        # Filter by priority parameter names
        priority_params = []
        for param in all_params:
            if any(priority in param.name.lower() for priority in target.priority_parameters):
                priority_params.append(param)
        
        # Also include high-confidence redirect parameters
        for param in all_params:
            if param.is_redirect_related and param.confidence > 0.7:
                if param not in priority_params:
                    priority_params.append(param)
        
        return priority_params
    
    async def focused_vulnerability_testing(self, scanner, priority_params: List, target: BugBountyTarget) -> List:
        """Focused testing on priority parameters"""
        vulnerabilities = []
        
        self.logger.info(f"Testing {len(priority_params)} priority parameters for {target.name}")
        
        for param in priority_params:
            # Get context-specific payloads
            context = scanner.detect_enhanced_context(param)
            
            # Select appropriate payload category based on target platform
            if target.platform == "web3":
                payloads = (scanner.payloads['web3_specific'] + 
                           scanner.payloads['basic_redirect'] +
                           scanner.payloads['javascript_payload'])
            else:
                payloads = scanner.get_context_aware_payloads(context, param)
            
            # Test each payload
            for payload in payloads[:10]:  # Limit payloads per parameter
                vuln = await scanner.test_enhanced_parameter(param, payload)
                if vuln:
                    # Enhance vulnerability with bug bounty specific data
                    vuln = self.enhance_vulnerability_for_bug_bounty(vuln, target)
                    vulnerabilities.append(vuln)
                
                # Respect rate limiting
                await asyncio.sleep(target.rate_limit)
        
        return vulnerabilities
    
    async def test_web3_specific_vulnerabilities(self, scanner, target: BugBountyTarget) -> List:
        """Test Web3-specific vulnerability patterns"""
        web3_vulns = []
        
        if target.platform not in ["web3", "hybrid"]:
            return web3_vulns
        
        self.logger.info(f"Running Web3-specific tests for {target.name}")
        
        # Test wallet connection redirects
        wallet_patterns = [
            "wallet_redirect_uri",
            "connect_callback", 
            "provider_url",
            "network_redirect",
            "dapp_callback"
        ]
        
        for pattern in wallet_patterns:
            # Create synthetic parameter for testing
            test_param = scanner.parameters[0] if scanner.parameters else None
            if test_param:
                web3_param = EnhancedParameter(
                    name=pattern,
                    value="",
                    source="web3",
                    context="web3_config",
                    url=target.url,
                    is_redirect_related=True,
                    confidence=0.8
                )
                
                # Test with Web3-specific payloads
                for payload in scanner.payloads['web3_specific']:
                    vuln = await scanner.test_enhanced_parameter(web3_param, payload)
                    if vuln:
                        vuln.vulnerability_type = "web3_redirect"
                        web3_vulns.append(vuln)
                    
                    await asyncio.sleep(target.rate_limit)
        
        return web3_vulns
    
    def enhance_vulnerability_for_bug_bounty(self, vuln, target: BugBountyTarget):
        """Enhance vulnerability with bug bounty specific information"""
        # Add bug bounty specific metadata
        vuln.bug_bounty_metadata = {
            "target_name": target.name,
            "platform": target.platform,
            "scope_verified": True,
            "reproduction_steps": self.generate_reproduction_steps(vuln),
            "business_impact": self.assess_business_impact(vuln, target),
            "cvss_score": self.calculate_cvss_score(vuln),
            "report_template": self.generate_report_template(vuln, target)
        }
        
        return vuln
    
    def generate_reproduction_steps(self, vuln) -> List[str]:
        """Generate step-by-step reproduction instructions"""
        steps = [
            f"1. Navigate to the vulnerable URL: {vuln.url}",
            f"2. Identify the vulnerable parameter: {vuln.parameter}",
            f"3. Inject the payload: {vuln.payload}",
            f"4. Observe the redirect to: {vuln.redirect_url}",
            "5. Verify the redirect leads to attacker-controlled domain"
        ]
        
        if vuln.vulnerability_type == "dom_based_redirect":
            steps.insert(3, "3.1. Wait for JavaScript execution to complete")
        
        return steps
    
    def assess_business_impact(self, vuln, target: BugBountyTarget) -> str:
        """Assess business impact for bug bounty reporting"""
        impact_factors = []
        
        # Base impact by vulnerability type
        if vuln.vulnerability_type == "dom_based_redirect":
            impact_factors.append("Client-side redirect allows bypassing server-side protections")
        
        # Platform-specific impacts
        if target.platform == "web3":
            impact_factors.extend([
                "Potential wallet connection hijacking",
                "Smart contract interaction redirection",
                "Cryptocurrency transaction manipulation risk"
            ])
        else:
            impact_factors.extend([
                "Phishing attack facilitation",
                "Session hijacking potential",
                "OAuth flow manipulation"
            ])
        
        # Context-specific impacts
        if vuln.context in ["form_action", "http_header"]:
            impact_factors.append("High reliability exploitation")
        
        return "; ".join(impact_factors)
    
    def calculate_cvss_score(self, vuln) -> float:
        """Calculate CVSS score for vulnerability"""
        # Simplified CVSS calculation
        base_score = 5.0  # Medium base for open redirect
        
        # Adjust based on context
        if vuln.context in ["query", "fragment"]:
            base_score += 1.0  # Easy to exploit
        elif vuln.context == "form_action":
            base_score += 0.5
        
        # Adjust based on vulnerability type
        if vuln.vulnerability_type == "dom_based_redirect":
            base_score += 1.5  # Harder to detect and mitigate
        
        # Adjust based on impact
        if vuln.impact_assessment == "HIGH":
            base_score += 1.0
        elif vuln.impact_assessment == "CRITICAL":
            base_score += 2.0
        
        return min(base_score, 10.0)
    
    def generate_report_template(self, vuln, target: BugBountyTarget) -> Dict[str, str]:
        """Generate bug bounty report template"""
        return {
            "title": f"Open Redirect Vulnerability in {target.name}",
            "severity": vuln.impact_assessment,
            "description": f"An open redirect vulnerability was discovered in the {vuln.parameter} parameter of {target.name}. This vulnerability allows an attacker to redirect users to malicious websites.",
            "impact": vuln.bug_bounty_metadata.get("business_impact", ""),
            "poc": f"Navigate to: {vuln.url}\nPayload used: {vuln.payload}\nRedirect observed: {vuln.redirect_url}",
            "remediation": vuln.remediation_suggestion,
            "references": [
                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client_Side_Testing/04-Testing_for_Client_Side_URL_Redirect",
                "https://cwe.mitre.org/data/definitions/601.html"
            ]
        }
    
    async def run_bug_bounty_campaign(self, target_names: List[str] = None) -> Dict[str, Any]:
        """Run bug bounty testing campaign on specified targets"""
        if target_names is None:
            targets_to_test = self.targets
        else:
            targets_to_test = [t for t in self.targets if t.name in target_names]
        
        self.logger.info(f"🚀 Starting bug bounty campaign on {len(targets_to_test)} targets")
        
        campaign_results = {
            "campaign_start": time.time(),
            "targets_tested": len(targets_to_test),
            "results": {}
        }
        
        for target in targets_to_test:
            self.logger.info(f"Testing target: {target.name}")
            
            try:
                result = await self.test_bug_bounty_target(target)
                campaign_results["results"][target.name] = result
                
                # Log summary
                if "vulnerability_count" in result:
                    vuln_count = result["vulnerability_count"]
                    if vuln_count > 0:
                        self.logger.info(f"✅ {target.name}: Found {vuln_count} vulnerabilities")
                    else:
                        self.logger.info(f"ℹ️  {target.name}: No vulnerabilities found")
                
                # Delay between targets
                await asyncio.sleep(5)
                
            except Exception as e:
                self.logger.error(f"Failed to test {target.name}: {e}")
                campaign_results["results"][target.name] = {"error": str(e)}
        
        campaign_results["campaign_end"] = time.time()
        campaign_results["total_duration"] = campaign_results["campaign_end"] - campaign_results["campaign_start"]
        
        # Generate campaign summary
        await self.generate_campaign_report(campaign_results)
        
        return campaign_results
    
    async def save_bug_bounty_report(self, results: Dict[str, Any], target: BugBountyTarget):
        """Save bug bounty specific report"""
        # Create bug bounty reports directory
        reports_dir = Path("/workspace/bug_bounty_reports")
        reports_dir.mkdir(exist_ok=True)
        
        # Generate filename
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        filename = f"{target.name.replace(' ', '_').lower()}_{timestamp}.json"
        
        # Save detailed results
        report_path = reports_dir / filename
        with open(report_path, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        
        self.logger.info(f"Bug bounty report saved: {report_path}")
        
        # Generate markdown report for easy copying
        md_report = self.generate_markdown_report(results, target)
        md_path = reports_dir / f"{target.name.replace(' ', '_').lower()}_{timestamp}.md"
        with open(md_path, 'w') as f:
            f.write(md_report)
    
    def generate_markdown_report(self, results: Dict[str, Any], target: BugBountyTarget) -> str:
        """Generate markdown report suitable for bug bounty submission"""
        vulnerabilities = results.get("vulnerabilities", [])
        
        md_content = f"""# Open Redirect Vulnerability Report - {target.name}

## Summary
- **Target**: {target.url}
- **Platform**: {target.platform}
- **Scan Date**: {time.strftime("%Y-%m-%d %H:%M:%S")}
- **Vulnerabilities Found**: {len(vulnerabilities)}

## Scope Verification
✅ Target is within authorized scope:
- **In Scope**: {', '.join(target.scope)}
- **Out of Scope**: {', '.join(target.out_of_scope)}

"""
        
        if vulnerabilities:
            md_content += "## Vulnerabilities Discovered\n\n"
            
            for i, vuln in enumerate(vulnerabilities, 1):
                md_content += f"""### Vulnerability #{i}: {vuln['vulnerability_type'].title()}

**Severity**: {vuln['impact_assessment']}  
**Confidence**: {vuln['confidence']:.1%}  
**CVSS Score**: {vuln.get('bug_bounty_metadata', {}).get('cvss_score', 'N/A')}

#### Details
- **URL**: `{vuln['url']}`
- **Parameter**: `{vuln['parameter']}`
- **Method**: `{vuln['method']}`
- **Context**: `{vuln['context']}`

#### Proof of Concept
```
Payload: {vuln['payload']}
Response Code: {vuln['response_code']}
Redirect URL: {vuln['redirect_url']}
```

#### Reproduction Steps
"""
                
                steps = vuln.get('bug_bounty_metadata', {}).get('reproduction_steps', [])
                for step in steps:
                    md_content += f"{step}\n"
                
                md_content += f"""
#### Business Impact
{vuln.get('bug_bounty_metadata', {}).get('business_impact', 'Standard open redirect impact')}

#### Remediation
{vuln['remediation_suggestion']}

---

"""
        else:
            md_content += "## No Vulnerabilities Found\n\nThe target application appears to be properly protected against open redirect vulnerabilities.\n\n"
        
        md_content += f"""## Scan Statistics
- **URLs Crawled**: {results.get('urls_discovered', 0)}
- **Parameters Analyzed**: {results.get('parameters_found', 0)}
- **Priority Parameters**: {results.get('priority_parameters', 0)}
- **Scan Duration**: {results.get('scan_duration', 0):.2f} seconds

## Methodology
This assessment used a professional open redirect scanner with:
- Deep web crawling with JavaScript rendering
- Advanced JavaScript AST analysis
- DOM-based vulnerability detection
- Context-aware payload injection
- Web3-specific testing capabilities

## References
- [OWASP Testing Guide - Open Redirect](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client_Side_Testing/04-Testing_for_Client_Side_URL_Redirect)
- [CWE-601: URL Redirection to Untrusted Site](https://cwe.mitre.org/data/definitions/601.html)
"""
        
        return md_content
    
    async def generate_campaign_report(self, campaign_results: Dict[str, Any]):
        """Generate overall campaign report"""
        reports_dir = Path("/workspace/bug_bounty_reports")
        reports_dir.mkdir(exist_ok=True)
        
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        campaign_report_path = reports_dir / f"campaign_summary_{timestamp}.json"
        
        # Calculate campaign statistics
        total_vulns = 0
        total_targets = len(campaign_results["results"])
        successful_targets = 0
        
        for target_name, result in campaign_results["results"].items():
            if "vulnerability_count" in result:
                total_vulns += result["vulnerability_count"]
                successful_targets += 1
        
        campaign_summary = {
            **campaign_results,
            "summary": {
                "total_vulnerabilities": total_vulns,
                "targets_with_vulns": len([r for r in campaign_results["results"].values() 
                                         if r.get("vulnerability_count", 0) > 0]),
                "success_rate": successful_targets / total_targets if total_targets > 0 else 0,
                "average_scan_time": sum([r.get("scan_duration", 0) for r in campaign_results["results"].values()]) / successful_targets if successful_targets > 0 else 0
            }
        }
        
        # Save campaign report
        with open(campaign_report_path, 'w') as f:
            json.dump(campaign_summary, f, indent=2, default=str)
        
        self.logger.info(f"Campaign report saved: {campaign_report_path}")
        
        # Log campaign summary
        self.logger.info("🎯 Bug Bounty Campaign Summary:")
        self.logger.info(f"   Targets Tested: {total_targets}")
        self.logger.info(f"   Successful Scans: {successful_targets}")
        self.logger.info(f"   Total Vulnerabilities: {total_vulns}")
        self.logger.info(f"   Targets with Vulnerabilities: {campaign_summary['summary']['targets_with_vulns']}")
        self.logger.info(f"   Campaign Duration: {campaign_summary['total_duration']:.2f} seconds")
    
    def generate_bug_bounty_recommendations(self, vulnerabilities: List, target: BugBountyTarget) -> List[str]:
        """Generate bug bounty specific recommendations"""
        recommendations = []
        
        if not vulnerabilities:
            recommendations.append("✅ No open redirect vulnerabilities detected")
            recommendations.append("Continue monitoring for new features and endpoints")
            return recommendations
        
        # General recommendations
        recommendations.append("🔒 Implement strict URL validation using allowlists")
        recommendations.append("🔍 Review all redirect functionality for proper validation")
        
        # Platform-specific recommendations
        if target.platform == "web3":
            recommendations.extend([
                "🌐 Validate wallet connection URLs against trusted providers",
                "⛓️ Implement contract address validation for redirects",
                "🔐 Use secure redirect patterns for DApp integrations"
            ])
        
        # Context-specific recommendations
        contexts = set(v.context for v in vulnerabilities)
        if "query" in contexts:
            recommendations.append("📝 Sanitize and validate all query parameters")
        if "fragment" in contexts:
            recommendations.append("🔗 Implement client-side hash parameter validation")
        if "form_action" in contexts:
            recommendations.append("📋 Validate all form action URLs server-side")
        
        return recommendations


async def main():
    """Main function for bug bounty testing"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Bug Bounty Open Redirect Tester')
    parser.add_argument('--target', help='Specific target name to test')
    parser.add_argument('--list-targets', action='store_true', help='List available targets')
    parser.add_argument('--campaign', action='store_true', help='Run full campaign on all targets')
    
    args = parser.parse_args()
    
    tester = BugBountyTester()
    
    if args.list_targets:
        print("Available Bug Bounty Targets:")
        for target in tester.targets:
            print(f"  - {target.name} ({target.platform}): {target.url}")
        return
    
    if args.campaign:
        print("🚀 Starting bug bounty campaign...")
        results = await tester.run_bug_bounty_campaign()
        print(f"✅ Campaign completed. Results saved to bug_bounty_reports/")
    elif args.target:
        target_names = [args.target]
        results = await tester.run_bug_bounty_campaign(target_names)
    else:
        print("Please specify --target, --campaign, or --list-targets")


if __name__ == "__main__":
    asyncio.run(main())