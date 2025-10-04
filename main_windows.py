#!/usr/bin/env python3
"""
ARAT - Advanced Reconnaissance & Assessment Tool
Simplified version for Windows
"""

import asyncio
import sys
import argparse
from pathlib import Path

# Add project path
sys.path.append(str(Path(__file__).parent))

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description='ARAT - Advanced Reconnaissance Tool')
    parser.add_argument('--target', help='Target domain or IP address')
    parser.add_argument('--phase', type=int, help='Phase number (1-10)')
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
            import aiosqlite
            print("✅ All essential modules available")
        except ImportError as e:
            print(f"❌ Missing module: {e}")
            print("💡 Please install dependencies first:")
            print("   pip install -r requirements_windows.txt")
            return
        
        # Start web panel
        from web.panel import WebPanel
        
        # Create simple config
        config = SimpleConfig()
        database = SimpleDatabase()
        phase_manager = SimplePhaseManager()
        
        web_panel = WebPanel(config, database, phase_manager)
        web_panel.start(host, port)
        
    except Exception as e:
        print(f"❌ Error starting web panel: {e}")
        print("💡 Please install dependencies:")
        print("   pip install -r requirements_windows.txt")

def run_single_phase(target, phase):
    """Run single phase"""
    print(f"🎯 Target: {target}")
    print(f"⚙️  Phase: {phase}")
    print("=" * 30)
    
    if phase == 1:
        print("🔍 Phase 1: Real IP Extraction & CDN Bypass")
        print("   - CDN Detection")
        print("   - Real IP Extraction")
        print("   - DNS History Analysis")
        print("✅ Phase 1 completed (demo)")
        
    elif phase == 2:
        print("🔍 Phase 2: Subdomain Discovery")
        print("   - Passive discovery")
        print("   - Active discovery")
        print("   - Validation")
        print("✅ Phase 2 completed (demo)")
        
    else:
        print(f"⚠️  Phase {phase} not implemented yet")
        print("💡 Available phases: 1, 2")

def run_all_phases(target):
    """Run all phases"""
    print(f"🎯 Target: {target}")
    print("🚀 Running all phases...")
    print("=" * 30)
    
    phases = [1, 2]  # Available phases
    
    for phase in phases:
        print(f"\n⚙️  Phase {phase}:")
        run_single_phase(target, phase)

class SimpleConfig:
    """Simple config class"""
    def __init__(self):
        self.web = SimpleWebConfig()
        self.database = SimpleDatabaseConfig()
        self.api_keys = {}
    
    def get_setting(self, section, key, default=None):
        return default
    
    def update_config(self, section, key, value):
        pass

class SimpleWebConfig:
    def __init__(self):
        self.host = "127.0.0.1"
        self.port = 8080
        self.debug = False
        self.secret_key = "your-secret-key-here"

class SimpleDatabaseConfig:
    def __init__(self):
        self.url = "sqlite:///data/arat.db"

class SimpleDatabase:
    """Simple database class"""
    async def connect(self):
        pass
    
    async def disconnect(self):
        pass
    
    async def save_target(self, target, metadata=None):
        return 1
    
    async def get_targets(self):
        return []

class SimplePhaseManager:
    """Simple phase manager class"""
    async def initialize(self):
        pass
    
    async def get_available_phases(self):
        return [
            {"number": 1, "name": "Real IP Extraction", "description": "Extract real IP address", "dependencies": []},
            {"number": 2, "name": "Subdomain Discovery", "description": "Discover subdomains", "dependencies": [1]}
        ]
    
    async def run_phase(self, phase, target):
        return {"phase": phase, "target": target, "status": "completed", "results": {}}

if __name__ == "__main__":
    main()