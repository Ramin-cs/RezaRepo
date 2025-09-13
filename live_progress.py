#!/usr/bin/env python3
"""
Live Progress Display Module for XSS Scanner
Real-time progress tracking and live demonstration
"""

import time
import threading
from typing import Dict, List, Optional
from colorama import init, Fore, Style
from tqdm import tqdm
import sys

# Initialize colorama
init(autoreset=True)

class LiveProgress:
    """Live progress display with real-time updates"""
    
    def __init__(self):
        self.current_phase = ""
        self.current_task = ""
        self.progress_data = {}
        self.vulnerabilities_found = []
        self.is_running = False
        
    def start_phase(self, phase_name: str, description: str = ""):
        """Start a new phase"""
        self.current_phase = phase_name
        self.current_task = description
        self.is_running = True
        
        print(f"\n{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗")
        print(f"║                    {phase_name:<50} ║")
        print(f"╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}")
        
        if description:
            print(f"{Fore.YELLOW}📋 {description}{Style.RESET_ALL}")
            
    def update_task(self, task: str):
        """Update current task"""
        self.current_task = task
        print(f"{Fore.BLUE}🔄 {task}{Style.RESET_ALL}")
        
    def show_progress(self, current: int, total: int, description: str = ""):
        """Show progress bar"""
        if total > 0:
            percentage = (current / total) * 100
            bar_length = 50
            filled_length = int(bar_length * current // total)
            bar = '█' * filled_length + '-' * (bar_length - filled_length)
            
            print(f"\r{Fore.GREEN}Progress: |{bar}| {percentage:.1f}% ({current}/{total}) {description}{Style.RESET_ALL}", end='', flush=True)
            
    def show_url_discovery(self, url: str, status: str = "discovered"):
        """Show URL discovery progress"""
        if status == "discovered":
            print(f"{Fore.GREEN}✅ Discovered: {url}{Style.RESET_ALL}")
        elif status == "crawling":
            print(f"{Fore.BLUE}🔍 Crawling: {url}{Style.RESET_ALL}")
        elif status == "error":
            print(f"{Fore.RED}❌ Error: {url}{Style.RESET_ALL}")
            
    def show_input_point(self, input_point: Dict):
        """Show input point discovery"""
        input_type = input_point.get('type', 'unknown')
        url = input_point.get('url', 'unknown')
        
        if input_type == 'form':
            action = input_point.get('action', '')
            method = input_point.get('method', 'GET')
            inputs_count = len(input_point.get('inputs', []))
            print(f"{Fore.CYAN}📝 Form found: {url} -> {action} ({method}) - {inputs_count} inputs{Style.RESET_ALL}")
        elif input_type == 'url_params':
            params_count = len(input_point.get('params', {}))
            print(f"{Fore.CYAN}🔗 URL params: {url} - {params_count} parameters{Style.RESET_ALL}")
        elif input_type == 'javascript_variables':
            vars_count = len(input_point.get('variables', []))
            print(f"{Fore.CYAN}⚡ JS variables: {url} - {vars_count} variables{Style.RESET_ALL}")
            
    def show_character_filter_test(self, char: str, url: str, filtered: bool):
        """Show character filter testing"""
        if filtered:
            print(f"{Fore.RED}🚫 Filtered: '{char}' on {url}{Style.RESET_ALL}")
        else:
            print(f"{Fore.GREEN}✅ Allowed: '{char}' on {url}{Style.RESET_ALL}")
            
    def show_payload_injection(self, payload: str, url: str, context: str = ""):
        """Show payload injection progress"""
        print(f"{Fore.YELLOW}💉 Injecting: {payload[:50]}{'...' if len(payload) > 50 else ''} into {url}{Style.RESET_ALL}")
        if context:
            print(f"{Fore.MAGENTA}   Context: {context}{Style.RESET_ALL}")
            
    def show_vulnerability_found(self, vulnerability: Dict):
        """Show vulnerability found"""
        url = vulnerability.get('url', 'unknown')
        payload = vulnerability.get('payload', 'unknown')
        context = vulnerability.get('context_type', 'unknown')
        
        print(f"\n{Fore.RED}🎯 VULNERABILITY FOUND!{Style.RESET_ALL}")
        print(f"{Fore.RED}📍 URL: {url}{Style.RESET_ALL}")
        print(f"{Fore.RED}💉 Payload: {payload}{Style.RESET_ALL}")
        print(f"{Fore.RED}🎭 Context: {context}{Style.RESET_ALL}")
        print(f"{Fore.RED}⏰ Time: {time.strftime('%H:%M:%S')}{Style.RESET_ALL}")
        print("-" * 60)
        
        self.vulnerabilities_found.append(vulnerability)
        
    def show_chrome_execution(self, url: str, payload: str):
        """Show Chrome execution progress"""
        print(f"\n{Fore.CYAN}🌐 Opening Chrome for live demonstration...{Style.RESET_ALL}")
        print(f"{Fore.CYAN}🔗 URL: {url}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}💉 Payload: {payload}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}⏳ Please watch Chrome browser for live XSS execution...{Style.RESET_ALL}")
        
    def show_screenshot_capture(self, screenshot_path: str):
        """Show screenshot capture"""
        print(f"{Fore.GREEN}📸 Screenshot captured: {screenshot_path}{Style.RESET_ALL}")
        
    def show_alert_detected(self):
        """Show alert detection"""
        print(f"{Fore.RED}🚨 ALERT DETECTED! XSS payload executed successfully!{Style.RESET_ALL}")
        
    def show_phase_complete(self, phase_name: str, results: Dict):
        """Show phase completion"""
        print(f"\n{Fore.GREEN}✅ {phase_name} completed!{Style.RESET_ALL}")
        
        for key, value in results.items():
            if isinstance(value, (list, set)):
                print(f"{Fore.GREEN}   {key}: {len(value)}{Style.RESET_ALL}")
            else:
                print(f"{Fore.GREEN}   {key}: {value}{Style.RESET_ALL}")
                
    def show_final_summary(self):
        """Show final summary"""
        print(f"\n{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗")
        print(f"║                    SCAN COMPLETED                    ║")
        print(f"╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}")
        
        print(f"{Fore.YELLOW}📊 Total Vulnerabilities Found: {len(self.vulnerabilities_found)}{Style.RESET_ALL}")
        
        if self.vulnerabilities_found:
            print(f"\n{Fore.RED}🎯 VULNERABILITIES SUMMARY:{Style.RESET_ALL}")
            for i, vuln in enumerate(self.vulnerabilities_found, 1):
                print(f"{Fore.RED}[{i}] {vuln.get('url', 'unknown')} - {vuln.get('payload', 'unknown')[:30]}...{Style.RESET_ALL}")
        else:
            print(f"{Fore.GREEN}✅ No vulnerabilities found{Style.RESET_ALL}")
            
    def show_error(self, error: str):
        """Show error message"""
        print(f"{Fore.RED}❌ Error: {error}{Style.RESET_ALL}")
        
    def show_warning(self, warning: str):
        """Show warning message"""
        print(f"{Fore.YELLOW}⚠️ Warning: {warning}{Style.RESET_ALL}")
        
    def show_info(self, info: str):
        """Show info message"""
        print(f"{Fore.BLUE}ℹ️ Info: {info}{Style.RESET_ALL}")
        
    def show_success(self, message: str):
        """Show success message"""
        print(f"{Fore.GREEN}✅ {message}{Style.RESET_ALL}")
        
    def clear_line(self):
        """Clear current line"""
        print("\r" + " " * 100 + "\r", end='', flush=True)
        
    def show_live_stats(self):
        """Show live statistics"""
        while self.is_running:
            time.sleep(1)
            if self.progress_data:
                print(f"\r{Fore.CYAN}📊 Live Stats: {self.progress_data}{Style.RESET_ALL}", end='', flush=True)
                
    def update_stats(self, stats: Dict):
        """Update live statistics"""
        self.progress_data.update(stats)
        
    def stop(self):
        """Stop live progress"""
        self.is_running = False
        print(f"\n{Fore.GREEN}🏁 Live progress stopped{Style.RESET_ALL}")

# Global progress instance
live_progress = LiveProgress()