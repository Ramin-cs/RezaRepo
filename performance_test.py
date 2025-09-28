#!/usr/bin/env python3
"""
Performance testing for Open Redirect Scanner
"""

import asyncio
import time
import sys
import psutil
import os
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
import statistics

# Add current directory to Python path
sys.path.insert(0, str(Path(__file__).parent))

from open_redirect_scanner import OpenRedirectScanner
from recon_module import ReconModule
from payload_module import PayloadModule
from chrome_module import ChromeModule
from report_module import ReportModule
from logging_module import LoggingModule

class PerformanceTest:
    """Performance testing class"""
    
    def __init__(self):
        self.results = {}
        self.start_time = None
        self.end_time = None
    
    def start_timer(self):
        """Start performance timer"""
        self.start_time = time.time()
    
    def end_timer(self):
        """End performance timer"""
        self.end_time = time.time()
        return self.end_time - self.start_time
    
    def get_memory_usage(self):
        """Get current memory usage"""
        process = psutil.Process(os.getpid())
        return process.memory_info().rss / 1024 / 1024  # MB
    
    def get_cpu_usage(self):
        """Get current CPU usage"""
        return psutil.cpu_percent()
    
    async def test_recon_performance(self, target_url: str, iterations: int = 5):
        """Test reconnaissance performance"""
        print(f"🔍 Testing Reconnaissance Performance ({iterations} iterations)")
        
        times = []
        memory_usage = []
        
        for i in range(iterations):
            print(f"  Iteration {i+1}/{iterations}")
            
            # Create fresh module
            logger = LoggingModule(Path("perf_test_output"))
            recon = ReconModule(logger)
            
            # Measure performance
            start_time = time.time()
            start_memory = self.get_memory_usage()
            
            # Mock session for testing
            class MockSession:
                async def get(self, url):
                    class MockResponse:
                        status = 200
                        headers = {}
                        async def text(self):
                            return "<html><body><a href='/test'>Test</a></body></html>"
                    return MockResponse()
            
            session = MockSession()
            result = await recon.perform_recon(target_url, session)
            
            end_time = time.time()
            end_memory = self.get_memory_usage()
            
            times.append(end_time - start_time)
            memory_usage.append(end_memory - start_memory)
        
        self.results['recon'] = {
            'avg_time': statistics.mean(times),
            'min_time': min(times),
            'max_time': max(times),
            'std_dev': statistics.stdev(times) if len(times) > 1 else 0,
            'avg_memory': statistics.mean(memory_usage),
            'iterations': iterations
        }
        
        print(f"  ✅ Average time: {self.results['recon']['avg_time']:.2f}s")
        print(f"  ✅ Memory usage: {self.results['recon']['avg_memory']:.2f}MB")
    
    async def test_payload_performance(self, iterations: int = 10):
        """Test payload generation performance"""
        print(f"🎯 Testing Payload Performance ({iterations} iterations)")
        
        times = []
        payload_counts = []
        
        logger = LoggingModule(Path("perf_test_output"))
        payloads = PayloadModule(logger)
        
        test_payloads = [
            "//google.com",
            "https://google.com",
            "javascript:alert(1)",
            "data:text/html,<script>alert(1)</script>"
        ]
        
        for i in range(iterations):
            print(f"  Iteration {i+1}/{iterations}")
            
            start_time = time.time()
            
            total_payloads = 0
            for base_payload in test_payloads:
                generated = payloads.generate_payloads(base_payload)
                total_payloads += len(generated)
            
            end_time = time.time()
            
            times.append(end_time - start_time)
            payload_counts.append(total_payloads)
        
        self.results['payloads'] = {
            'avg_time': statistics.mean(times),
            'min_time': min(times),
            'max_time': max(times),
            'std_dev': statistics.stdev(times) if len(times) > 1 else 0,
            'avg_payloads': statistics.mean(payload_counts),
            'iterations': iterations
        }
        
        print(f"  ✅ Average time: {self.results['payloads']['avg_time']:.2f}s")
        print(f"  ✅ Average payloads: {self.results['payloads']['avg_payloads']:.0f}")
    
    async def test_parallel_processing(self, target_url: str, max_threads: int = 10):
        """Test parallel processing performance"""
        print(f"⚡ Testing Parallel Processing (max {max_threads} threads)")
        
        # Test different thread counts
        thread_counts = [1, 2, 4, 8, max_threads]
        results = {}
        
        for thread_count in thread_counts:
            print(f"  Testing with {thread_count} threads")
            
            times = []
            
            for i in range(3):  # 3 iterations per thread count
                start_time = time.time()
                
                # Simulate parallel processing
                with ThreadPoolExecutor(max_workers=thread_count) as executor:
                    futures = []
                    for j in range(10):  # 10 tasks
                        future = executor.submit(self._mock_task, j)
                        futures.append(future)
                    
                    # Wait for completion
                    for future in futures:
                        future.result()
                
                end_time = time.time()
                times.append(end_time - start_time)
            
            results[thread_count] = {
                'avg_time': statistics.mean(times),
                'min_time': min(times),
                'max_time': max(times),
                'std_dev': statistics.stdev(times) if len(times) > 1 else 0
            }
        
        self.results['parallel'] = results
        
        # Find optimal thread count
        best_threads = min(results.keys(), key=lambda x: results[x]['avg_time'])
        print(f"  ✅ Best performance with {best_threads} threads")
        print(f"  ✅ Speedup: {results[1]['avg_time'] / results[best_threads]['avg_time']:.2f}x")
    
    def _mock_task(self, task_id: int):
        """Mock task for parallel processing test"""
        time.sleep(0.1)  # Simulate work
        return f"Task {task_id} completed"
    
    async def test_memory_usage(self, target_url: str):
        """Test memory usage over time"""
        print("💾 Testing Memory Usage")
        
        memory_samples = []
        times = []
        
        # Monitor memory during scan
        start_time = time.time()
        
        for i in range(10):
            memory = self.get_memory_usage()
            current_time = time.time() - start_time
            
            memory_samples.append(memory)
            times.append(current_time)
            
            print(f"  Sample {i+1}/10: {memory:.2f}MB at {current_time:.2f}s")
            
            await asyncio.sleep(1)
        
        self.results['memory'] = {
            'samples': memory_samples,
            'times': times,
            'max_memory': max(memory_samples),
            'min_memory': min(memory_samples),
            'avg_memory': statistics.mean(memory_samples)
        }
        
        print(f"  ✅ Max memory: {self.results['memory']['max_memory']:.2f}MB")
        print(f"  ✅ Average memory: {self.results['memory']['avg_memory']:.2f}MB")
    
    async def test_scanner_performance(self, target_url: str, iterations: int = 3):
        """Test full scanner performance"""
        print(f"🚀 Testing Full Scanner Performance ({iterations} iterations)")
        
        times = []
        memory_usage = []
        
        for i in range(iterations):
            print(f"  Iteration {i+1}/{iterations}")
            
            # Create fresh scanner
            scanner = OpenRedirectScanner(target_url, f"perf_test_{i}", 5)
            
            start_time = time.time()
            start_memory = self.get_memory_usage()
            
            try:
                if await scanner.initialize():
                    await scanner.scan()
                await scanner.cleanup()
            except Exception as e:
                print(f"    ⚠️ Error in iteration {i+1}: {str(e)}")
            
            end_time = time.time()
            end_memory = self.get_memory_usage()
            
            times.append(end_time - start_time)
            memory_usage.append(end_memory - start_memory)
        
        self.results['scanner'] = {
            'avg_time': statistics.mean(times),
            'min_time': min(times),
            'max_time': max(times),
            'std_dev': statistics.stdev(times) if len(times) > 1 else 0,
            'avg_memory': statistics.mean(memory_usage),
            'iterations': iterations
        }
        
        print(f"  ✅ Average time: {self.results['scanner']['avg_time']:.2f}s")
        print(f"  ✅ Memory usage: {self.results['scanner']['avg_memory']:.2f}MB")
    
    def generate_performance_report(self):
        """Generate performance report"""
        print("\n📊 Performance Report")
        print("=" * 50)
        
        for test_name, results in self.results.items():
            print(f"\n{test_name.upper()}:")
            
            if test_name == 'parallel':
                for threads, data in results.items():
                    print(f"  {threads} threads: {data['avg_time']:.2f}s ± {data['std_dev']:.2f}s")
            elif test_name == 'memory':
                print(f"  Max memory: {results['max_memory']:.2f}MB")
                print(f"  Average memory: {results['avg_memory']:.2f}MB")
                print(f"  Memory range: {results['min_memory']:.2f}MB - {results['max_memory']:.2f}MB")
            else:
                print(f"  Average time: {results['avg_time']:.2f}s ± {results['std_dev']:.2f}s")
                if 'avg_memory' in results:
                    print(f"  Memory usage: {results['avg_memory']:.2f}MB")
                if 'avg_payloads' in results:
                    print(f"  Average payloads: {results['avg_payloads']:.0f}")
    
    async def run_all_tests(self, target_url: str):
        """Run all performance tests"""
        print("🧪 Open Redirect Scanner Performance Tests")
        print("=" * 60)
        
        try:
            # Test reconnaissance performance
            await self.test_recon_performance(target_url)
            
            # Test payload performance
            await self.test_payload_performance()
            
            # Test parallel processing
            await self.test_parallel_processing(target_url)
            
            # Test memory usage
            await self.test_memory_usage(target_url)
            
            # Test full scanner performance
            await self.test_scanner_performance(target_url)
            
            # Generate report
            self.generate_performance_report()
            
            print("\n✅ All performance tests completed!")
            
        except Exception as e:
            print(f"\n❌ Performance test failed: {str(e)}")
            raise

async def main():
    """Main function"""
    target_url = "https://httpbin.org"
    
    print("🚀 Starting Performance Tests")
    print(f"Target: {target_url}")
    print(f"System: {psutil.cpu_count()} CPU cores, {psutil.virtual_memory().total / 1024 / 1024 / 1024:.1f}GB RAM")
    print("-" * 60)
    
    # Create performance test instance
    perf_test = PerformanceTest()
    
    # Run all tests
    await perf_test.run_all_tests(target_url)
    
    # Cleanup
    import shutil
    for path in Path(".").glob("perf_test*"):
        if path.is_dir():
            shutil.rmtree(path)

if __name__ == "__main__":
    asyncio.run(main())