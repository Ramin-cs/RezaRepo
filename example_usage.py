#!/usr/bin/env python3
"""
Example usage of the Advanced Recon Tool
Demonstrates different ways to use the tool programmatically
"""

from advanced_recon_tool import ReconTool, SubdomainDiscovery, ParameterDiscovery, Logger
import time

def example_subdomain_discovery():
    """Example of subdomain discovery"""
    print("\n" + "="*60)
    print("EXAMPLE 1: Subdomain Discovery")
    print("="*60)
    
    # Initialize the tool
    recon_tool = ReconTool()
    
    # Example domain (use a domain you own or have permission to test)
    domain = "example.com"
    
    Logger.info(f"Starting subdomain discovery example for {domain}")
    
    # Run subdomain discovery with custom settings
    subdomains = recon_tool.run_subdomain_discovery(
        domain=domain,
        threads=25,  # Reduced threads for example
        timeout=10
    )
    
    # Display results
    print(f"\nFound {len(subdomains)} subdomains:")
    for subdomain in subdomains[:10]:  # Show first 10 results
        print(f"  • {subdomain}")
    
    if len(subdomains) > 10:
        print(f"  ... and {len(subdomains) - 10} more")
    
    # Save results
    recon_tool.save_results("example_subdomains", "json")

def example_parameter_discovery():
    """Example of parameter discovery"""
    print("\n" + "="*60)
    print("EXAMPLE 2: Parameter Discovery")
    print("="*60)
    
    # Initialize the tool
    recon_tool = ReconTool()
    
    # Example URL (use a URL you own or have permission to test)
    url = "https://httpbin.org/get"
    
    Logger.info(f"Starting parameter discovery example for {url}")
    
    # Run parameter discovery with custom settings
    parameters = recon_tool.run_parameter_discovery(
        url=url,
        threads=10,  # Reduced threads for example
        timeout=10
    )
    
    # Display results
    print(f"\nFound {len(parameters)} parameters:")
    for param in parameters[:10]:  # Show first 10 results
        print(f"  • {param}")
    
    if len(parameters) > 10:
        print(f"  ... and {len(parameters) - 10} more")
    
    # Save results
    recon_tool.save_results("example_parameters", "json")

def example_comprehensive_scan():
    """Example of comprehensive scan (both techniques)"""
    print("\n" + "="*60)
    print("EXAMPLE 3: Comprehensive Scan")
    print("="*60)
    
    # Initialize the tool
    recon_tool = ReconTool()
    
    # Example targets (use targets you own or have permission to test)
    domain = "httpbin.org"
    url = "https://httpbin.org/get"
    
    Logger.info(f"Starting comprehensive scan for {domain}")
    
    # Run both subdomain and parameter discovery
    print("\n--- Subdomain Discovery ---")
    subdomains = recon_tool.run_subdomain_discovery(
        domain=domain,
        threads=20,
        timeout=10
    )
    
    print("\n--- Parameter Discovery ---")
    parameters = recon_tool.run_parameter_discovery(
        url=url,
        threads=10,
        timeout=10
    )
    
    # Display comprehensive results
    print(f"\n--- COMPREHENSIVE RESULTS ---")
    print(f"Target Domain: {domain}")
    print(f"Target URL: {url}")
    print(f"Subdomains Found: {len(subdomains)}")
    print(f"Parameters Found: {len(parameters)}")
    
    # Save comprehensive results in different formats
    recon_tool.save_results("comprehensive_scan", "json")
    recon_tool.save_results("comprehensive_scan", "csv")
    recon_tool.save_results("comprehensive_scan", "txt")

def example_custom_wordlist():
    """Example of using custom wordlists"""
    print("\n" + "="*60)
    print("EXAMPLE 4: Custom Wordlist Usage")
    print("="*60)
    
    # Initialize subdomain discovery with custom settings
    domain = "example.com"
    subdomain_tool = SubdomainDiscovery(domain, threads=10, timeout=5)
    
    # Add custom subdomains to the wordlist
    custom_subdomains = [
        'app', 'application', 'apps', 'service', 'services', 'microservice',
        'k8s', 'kubernetes', 'docker', 'container', 'pod', 'cluster',
        'prod', 'production', 'live', 'staging', 'stage', 'dev', 'development',
        'qa', 'quality', 'testing', 'test', 'sandbox', 'demo', 'preview',
        'v1', 'v2', 'v3', 'version1', 'version2', 'api-v1', 'api-v2',
        'internal', 'private', 'corp', 'corporate', 'company', 'organization'
    ]
    
    # Extend the built-in wordlist
    subdomain_tool.subdomain_wordlist.extend(custom_subdomains)
    
    Logger.info(f"Using extended wordlist with {len(subdomain_tool.subdomain_wordlist)} entries")
    
    # Run DNS brute-force with extended wordlist
    subdomain_tool.dns_bruteforce()
    
    print(f"Found {len(subdomain_tool.found_subdomains)} subdomains with custom wordlist")

def example_performance_testing():
    """Example of performance testing with different configurations"""
    print("\n" + "="*60)
    print("EXAMPLE 5: Performance Testing")
    print("="*60)
    
    domain = "httpbin.org"
    
    # Test different thread configurations
    thread_configs = [10, 25, 50]
    
    for threads in thread_configs:
        Logger.info(f"Testing with {threads} threads")
        
        start_time = time.time()
        
        # Initialize and run subdomain discovery
        subdomain_tool = SubdomainDiscovery(domain, threads=threads, timeout=5)
        subdomain_tool.dns_bruteforce()
        
        end_time = time.time()
        duration = end_time - start_time
        
        print(f"  Threads: {threads:2d} | Time: {duration:.2f}s | Found: {len(subdomain_tool.found_subdomains):2d} subdomains")

def main():
    """Run all examples"""
    print("Advanced Recon Tool - Usage Examples")
    print("=" * 60)
    print("This script demonstrates various ways to use the recon tool")
    print("Make sure to only test against domains/URLs you own or have permission to test!")
    print("=" * 60)
    
    try:
        # Run examples (comment out any you don't want to run)
        example_subdomain_discovery()
        example_parameter_discovery()
        example_comprehensive_scan()
        example_custom_wordlist()
        example_performance_testing()
        
        print("\n" + "="*60)
        print("All examples completed successfully!")
        print("Check the generated output files for results.")
        print("="*60)
        
    except KeyboardInterrupt:
        Logger.warning("Examples interrupted by user")
    except Exception as e:
        Logger.error(f"An error occurred during examples: {str(e)}")

if __name__ == "__main__":
    main()