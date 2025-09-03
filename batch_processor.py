#!/usr/bin/env python3
"""
Enterprise Router Analyzer - Batch Processing Module
Process multiple configuration files simultaneously
"""

import os
import sys
import json
import threading
import time
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from enterprise_router_analyzer import EnterpriseRouterAnalyzer

class BatchProcessor:
    """Professional batch processing for multiple router configurations"""
    
    def __init__(self, max_workers: int = 4):
        self.analyzer = EnterpriseRouterAnalyzer()
        self.max_workers = max_workers
        self.results = {}
        self.progress_callback = None
    
    def set_progress_callback(self, callback):
        """Set progress callback for GUI integration"""
        self.progress_callback = callback
    
    def find_config_files(self, directory: str) -> List[str]:
        """Find all configuration files in directory"""
        config_extensions = [
            '.cfg', '.conf', '.txt', '.backup', '.rsc', 
            '.xml', '.json', '.bin', '.enc'
        ]
        
        config_files = []
        directory_path = Path(directory)
        
        if directory_path.is_file():
            return [str(directory_path)]
        
        for ext in config_extensions:
            config_files.extend(directory_path.glob(f"**/*{ext}"))
        
        return [str(f) for f in config_files]
    
    def analyze_file_batch(self, file_path: str) -> Dict[str, Any]:
        """Analyze single file in batch context"""
        try:
            start_time = time.time()
            
            # Perform analysis
            result = self.analyzer.analyze_configuration(file_path)
            
            # Add batch-specific metadata
            result['batch_metadata'] = {
                'processing_time': time.time() - start_time,
                'file_path': file_path,
                'file_size': os.path.getsize(file_path) if os.path.exists(file_path) else 0
            }
            
            return result
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'file_path': file_path,
                'batch_metadata': {
                    'processing_time': 0,
                    'file_path': file_path,
                    'error': str(e)
                }
            }
    
    def process_batch(self, file_paths: List[str]) -> Dict[str, Any]:
        """Process multiple files concurrently"""
        print(f"🔄 Starting batch processing of {len(file_paths)} files...")
        
        batch_results = {
            'total_files': len(file_paths),
            'successful': 0,
            'failed': 0,
            'results': {},
            'summary': {
                'brands_detected': {},
                'total_credentials': 0,
                'total_vulnerabilities': 0,
                'processing_time': 0
            }
        }
        
        start_time = time.time()
        
        # Process files concurrently
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all tasks
            future_to_file = {
                executor.submit(self.analyze_file_batch, file_path): file_path 
                for file_path in file_paths
            }
            
            # Collect results as they complete
            completed = 0
            for future in as_completed(future_to_file):
                file_path = future_to_file[future]
                
                try:
                    result = future.result()
                    batch_results['results'][file_path] = result
                    
                    if result['success']:
                        batch_results['successful'] += 1
                        
                        # Update summary statistics
                        brand = result.get('brand', 'unknown')
                        batch_results['summary']['brands_detected'][brand] = \
                            batch_results['summary']['brands_detected'].get(brand, 0) + 1
                        
                        batch_results['summary']['total_credentials'] += \
                            len(result.get('credentials', []))
                        
                        batch_results['summary']['total_vulnerabilities'] += \
                            len(result.get('vulnerabilities', []))
                    else:
                        batch_results['failed'] += 1
                    
                    completed += 1
                    
                    # Progress callback
                    if self.progress_callback:
                        self.progress_callback(completed, len(file_paths))
                    
                    print(f"✅ Processed: {os.path.basename(file_path)} ({completed}/{len(file_paths)})")
                    
                except Exception as e:
                    batch_results['failed'] += 1
                    batch_results['results'][file_path] = {
                        'success': False,
                        'error': str(e),
                        'file_path': file_path
                    }
                    print(f"❌ Failed: {os.path.basename(file_path)} - {e}")
        
        batch_results['summary']['processing_time'] = time.time() - start_time
        
        print(f"\n📊 Batch processing completed!")
        print(f"   Successful: {batch_results['successful']}")
        print(f"   Failed: {batch_results['failed']}")
        print(f"   Total time: {batch_results['summary']['processing_time']:.2f} seconds")
        
        return batch_results
    
    def generate_batch_report(self, batch_results: Dict[str, Any]) -> str:
        """Generate comprehensive batch analysis report"""
        report = []
        
        # Header
        report.append("=" * 100)
        report.append("ENTERPRISE BATCH ROUTER CONFIGURATION ANALYSIS REPORT")
        report.append("=" * 100)
        report.append(f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"Total Files Processed: {batch_results['total_files']}")
        report.append(f"Processing Time: {batch_results['summary']['processing_time']:.2f} seconds")
        report.append("")
        
        # Executive Summary
        report.append("EXECUTIVE SUMMARY")
        report.append("-" * 50)
        report.append(f"Files Successfully Analyzed: {batch_results['successful']}")
        report.append(f"Files Failed: {batch_results['failed']}")
        report.append(f"Success Rate: {(batch_results['successful'] / batch_results['total_files'] * 100):.1f}%")
        report.append("")
        
        # Brand distribution
        brands = batch_results['summary']['brands_detected']
        if brands:
            report.append("ROUTER BRAND DISTRIBUTION")
            report.append("-" * 50)
            for brand, count in sorted(brands.items(), key=lambda x: x[1], reverse=True):
                percentage = (count / batch_results['successful'] * 100) if batch_results['successful'] > 0 else 0
                report.append(f"{brand.upper():<15} {count:>3} files ({percentage:>5.1f}%)")
            report.append("")
        
        # Security overview
        total_creds = batch_results['summary']['total_credentials']
        total_vulns = batch_results['summary']['total_vulnerabilities']
        
        report.append("SECURITY OVERVIEW")
        report.append("-" * 50)
        report.append(f"Total Credentials Found: {total_creds}")
        report.append(f"Total Vulnerabilities: {total_vulns}")
        
        if batch_results['successful'] > 0:
            avg_creds = total_creds / batch_results['successful']
            avg_vulns = total_vulns / batch_results['successful']
            report.append(f"Average Credentials per Device: {avg_creds:.1f}")
            report.append(f"Average Vulnerabilities per Device: {avg_vulns:.1f}")
        
        report.append("")
        
        # Detailed results
        report.append("DETAILED ANALYSIS RESULTS")
        report.append("-" * 50)
        
        for file_path, result in batch_results['results'].items():
            filename = os.path.basename(file_path)
            
            if result['success']:
                brand = result.get('brand', 'unknown').upper()
                cred_count = len(result.get('credentials', []))
                vuln_count = len(result.get('vulnerabilities', []))
                security_score = result.get('security_analysis', {}).get('security_score', 0)
                
                report.append(f"\n📁 {filename}")
                report.append(f"   Brand: {brand}")
                report.append(f"   Security Score: {security_score}/100")
                report.append(f"   Credentials: {cred_count}")
                report.append(f"   Vulnerabilities: {vuln_count}")
                
                # Show critical findings
                critical_creds = [c for c in result.get('credentials', []) 
                                if c.get('strength') in ['very_weak', 'weak']]
                if critical_creds:
                    report.append(f"   ⚠️ Weak Credentials: {len(critical_creds)}")
                
            else:
                report.append(f"\n❌ {filename}")
                report.append(f"   Error: {result.get('error', 'Unknown error')}")
        
        # Recommendations
        report.append("\n\nBATCH ANALYSIS RECOMMENDATIONS")
        report.append("-" * 50)
        
        # Calculate overall risk
        if batch_results['successful'] > 0:
            high_risk_devices = sum(1 for result in batch_results['results'].values() 
                                  if result.get('success') and 
                                  result.get('security_analysis', {}).get('security_score', 100) < 50)
            
            risk_percentage = (high_risk_devices / batch_results['successful'] * 100)
            
            if risk_percentage > 70:
                report.append("🚨 CRITICAL: Majority of devices have high security risks")
                report.append("   Immediate security review and remediation required")
            elif risk_percentage > 30:
                report.append("⚠️ WARNING: Significant number of devices need security attention")
                report.append("   Schedule security updates and configuration reviews")
            else:
                report.append("✅ GOOD: Most devices have acceptable security configurations")
                report.append("   Continue regular security monitoring")
        
        report.append("")
        report.append("NEXT STEPS:")
        report.append("1. Review individual device reports for detailed findings")
        report.append("2. Prioritize devices with security scores below 50")
        report.append("3. Update weak passwords and encryption methods")
        report.append("4. Implement security best practices across all devices")
        
        # Footer
        report.append("\n" + "=" * 100)
        report.append("END OF BATCH ANALYSIS REPORT")
        report.append("Enterprise Router Configuration Analyzer v3.0")
        report.append("=" * 100)
        
        return '\n'.join(report)
    
    def save_batch_results(self, batch_results: Dict[str, Any], output_dir: str = "batch_results"):
        """Save comprehensive batch results"""
        output_path = Path(output_dir)
        output_path.mkdir(exist_ok=True)
        
        # Save summary report
        summary_report = self.generate_batch_report(batch_results)
        with open(output_path / 'batch_summary_report.txt', 'w', encoding='utf-8') as f:
            f.write(summary_report)
        
        # Save detailed JSON results
        with open(output_path / 'batch_results.json', 'w', encoding='utf-8') as f:
            json.dump(batch_results, f, indent=2, default=str)
        
        # Save individual device reports
        device_reports_dir = output_path / 'device_reports'
        device_reports_dir.mkdir(exist_ok=True)
        
        for file_path, result in batch_results['results'].items():
            if result['success']:
                filename = Path(file_path).stem
                device_report = self.analyzer.generate_professional_report(result)
                
                with open(device_reports_dir / f'{filename}_report.txt', 'w', encoding='utf-8') as f:
                    f.write(device_report)
        
        print(f"💾 Batch results saved to: {output_path}")
        return output_path


def main():
    """Batch processor main function"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Enterprise Router Analyzer - Batch Processor')
    parser.add_argument('input_path', help='Directory or file path to process')
    parser.add_argument('-o', '--output', default='batch_results', help='Output directory')
    parser.add_argument('-w', '--workers', type=int, default=4, help='Number of worker threads')
    parser.add_argument('--report-only', action='store_true', help='Generate report only (skip analysis)')
    
    args = parser.parse_args()
    
    processor = BatchProcessor(max_workers=args.workers)
    
    # Find files to process
    config_files = processor.find_config_files(args.input_path)
    
    if not config_files:
        print(f"❌ No configuration files found in: {args.input_path}")
        return
    
    print(f"📁 Found {len(config_files)} configuration files")
    
    # Process files
    batch_results = processor.process_batch(config_files)
    
    # Save results
    output_path = processor.save_batch_results(batch_results, args.output)
    
    print(f"\n📊 Batch processing summary:")
    print(f"   Total files: {batch_results['total_files']}")
    print(f"   Successful: {batch_results['successful']}")
    print(f"   Failed: {batch_results['failed']}")
    print(f"   Output saved to: {output_path}")


if __name__ == "__main__":
    main()