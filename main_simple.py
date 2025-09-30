#!/usr/bin/env python3
"""
ARAT - Ultra Simple Version (No Database)
Advanced Reconnaissance & Assessment Tool
"""

import sys
import argparse
from pathlib import Path
import json
import os
from datetime import datetime

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description='ARAT - Advanced Reconnaissance Tool')
    parser.add_argument('--target', help='Target domain or IP address')
    parser.add_argument('--phase', type=int, help='Phase number (1-2)')
    parser.add_argument('--all-phases', action='store_true', help='Run all phases')
    parser.add_argument('--web-panel', action='store_true', help='Start web panel')
    parser.add_argument('--port', type=int, default=8080, help='Web panel port')
    parser.add_argument('--host', default='127.0.0.1', help='Web panel host')
    
    args = parser.parse_args()
    
    print("🚀 ARAT - Advanced Reconnaissance Tool")
    print("=" * 50)
    
    try:
        if args.web_panel:
            start_web_panel(args.host, args.port)
        elif args.target:
            if args.all_phases:
                run_all_phases(args.target)
            elif args.phase:
                run_single_phase(args.target, args.phase)
            else:
                print("❌ Please specify phase number or --all-phases")
                sys.exit(1)
        else:
            print("❌ Please specify target (--target) or web panel (--web-panel)")
            parser.print_help()
            sys.exit(1)
            
    except KeyboardInterrupt:
        print("\n⏹️  Operation stopped")
        sys.exit(0)
    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)

def start_web_panel(host, port):
    """Start web panel"""
    try:
        print(f"🌐 Starting web panel on {host}:{port}")
        print("📱 Access: http://localhost:8080")
        print("⏹️  Press Ctrl+C to stop")
        
        # Test essential imports
        try:
            import yaml
            import flask
            import flask_socketio
            print("✅ All essential modules available")
        except ImportError as e:
            print(f"❌ Missing module: {e}")
            print("💡 Please install dependencies:")
            print("   pip install -r requirements_simple.txt")
            return
        
        # Start simple web panel
        from web.simple_panel import SimpleWebPanel
        
        web_panel = SimpleWebPanel()
        web_panel.start(host, port)
        
    except Exception as e:
        print(f"❌ Error starting web panel: {e}")
        print("💡 Please install dependencies:")
        print("   pip install -r requirements_simple.txt")

def run_single_phase(target, phase):
    """Run single phase"""
    print(f"🎯 Target: {target}")
    print(f"⚙️  Phase: {phase}")
    print("=" * 30)
    
    try:
        from reconnaissance import RealReconnaissance
        recon = RealReconnaissance()
        result = recon.run_phase(phase, target)
        
        if result['status'] == 'completed':
            print(f"✅ Phase {phase} completed successfully!")
            print(f"📊 Summary: {result.get('summary', 'No summary available')}")
            
            # Show key results
            if phase == 1:
                if result.get('real_ips'):
                    print(f"🎯 Real IPs found: {result['real_ips']}")
                if result.get('cdn_detected'):
                    print(f"🛡️ CDN detected: {result.get('cdn_type', 'Unknown')}")
                    
            elif phase == 2:
                subdomains = result.get('subdomains', [])
                valid = result.get('valid_subdomains', [])
                print(f"🔍 Subdomains found: {len(subdomains)}")
                print(f"✅ Valid subdomains: {len(valid)}")
                if valid:
                    print("📋 Valid subdomains:")
                    for sub in valid[:5]:  # Show first 5
                        print(f"   - {sub.get('subdomain', 'Unknown')} ({sub.get('status_code', 'Unknown')})")
                        
            elif phase == 3:
                ports = result.get('open_ports', [])
                services = result.get('services', {})
                print(f"🔍 Open ports found: {len(ports)}")
                if ports:
                    print("📋 Open ports:")
                    for port in ports[:10]:  # Show first 10
                        service = services.get(port, 'Unknown')
                        print(f"   - Port {port} ({service})")
                        
            elif phase == 4:
                technologies = result.get('technologies', [])
                print(f"🔍 Technologies found: {len(technologies)}")
                if technologies:
                    print("📋 Technologies:")
                    for tech in technologies:
                        print(f"   - {tech}")
                        
            elif phase == 5:
                directories = result.get('directories_found', [])
                files = result.get('files_found', [])
                print(f"🔍 Directories found: {len(directories)}")
                print(f"📄 Files found: {len(files)}")
                if directories:
                    print("📋 Directories:")
                    for dir_info in directories[:5]:
                        print(f"   - {dir_info.get('path', 'Unknown')} ({dir_info.get('status_code', 'Unknown')})")
                        
        else:
            print(f"❌ Phase {phase} failed")
            if result.get('errors'):
                print("Errors:")
                for error in result['errors']:
                    print(f"   - {error}")
                    
    except Exception as e:
        print(f"❌ Error running phase {phase}: {e}")
        print("💡 Available phases: 1, 2")

def run_all_phases(target):
    """Run all phases"""
    print(f"🎯 Target: {target}")
    print("🚀 Running all phases...")
    print("=" * 30)
    
    phases = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]  # All phases
    
    for phase in phases:
        print(f"\n⚙️  Phase {phase}:")
        run_single_phase(target, phase)

if __name__ == "__main__":
    main()