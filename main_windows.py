#!/usr/bin/env python3
"""
ARAT - نسخه ساده شده برای Windows
"""

import asyncio
import sys
import argparse
from pathlib import Path

# اضافه کردن مسیر پروژه
sys.path.append(str(Path(__file__).parent))

def main():
    """تابع اصلی"""
    parser = argparse.ArgumentParser(description='ARAT - Advanced Reconnaissance Tool')
    parser.add_argument('--target', help='هدف (دامنه یا IP)')
    parser.add_argument('--phase', type=int, help='شماره فاز (1-10)')
    parser.add_argument('--all-phases', action='store_true', help='اجرای تمام فازها')
    parser.add_argument('--web-panel', action='store_true', help='شروع پنل وب')
    parser.add_argument('--port', type=int, default=8080, help='پورت پنل وب')
    parser.add_argument('--host', default='127.0.0.1', help='هاست پنل وب')
    
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
                print("❌ لطفاً فاز یا --all-phases را مشخص کنید")
                sys.exit(1)
        else:
            print("❌ لطفاً هدف (--target) یا پنل وب (--web-panel) را مشخص کنید")
            parser.print_help()
            sys.exit(1)
            
    except KeyboardInterrupt:
        print("\n⏹️  عملیات متوقف شد")
        sys.exit(0)
    except Exception as e:
        print(f"❌ خطا: {e}")
        sys.exit(1)

def start_web_panel(host, port):
    """شروع پنل وب"""
    try:
        print(f"🌐 شروع پنل وب روی {host}:{port}")
        print("📱 دسترسی: http://localhost:8080")
        print("⏹️  برای توقف Ctrl+C بزنید")
        
        # تست import های ضروری
        try:
            import yaml
            import flask
            import flask_socketio
            print("✅ تمام ماژول‌های ضروری موجود است")
        except ImportError as e:
            print(f"❌ ماژول مفقود: {e}")
            print("💡 لطفاً ابتدا dependencies را نصب کنید:")
            print("   pip install -r requirements_windows.txt")
            return
        
        # شروع پنل وب
        from web.panel import WebPanel
        
        # ایجاد config ساده
        config = SimpleConfig()
        database = SimpleDatabase()
        phase_manager = SimplePhaseManager()
        
        web_panel = WebPanel(config, database, phase_manager)
        web_panel.start(host, port)
        
    except Exception as e:
        print(f"❌ خطا در شروع پنل وب: {e}")
        print("💡 لطفاً dependencies را نصب کنید:")
        print("   pip install -r requirements_windows.txt")

def run_single_phase(target, phase):
    """اجرای یک فاز"""
    print(f"🎯 هدف: {target}")
    print(f"⚙️  فاز: {phase}")
    print("=" * 30)
    
    if phase == 1:
        print("🔍 فاز 1: Real IP Extraction & CDN Bypass")
        print("   - تشخیص CDN")
        print("   - استخراج IP واقعی")
        print("   - تحلیل DNS History")
        print("✅ فاز 1 تکمیل شد (نمونه)")
        
    elif phase == 2:
        print("🔍 فاز 2: Subdomain Discovery")
        print("   - Passive discovery")
        print("   - Active discovery")
        print("   - Validation")
        print("✅ فاز 2 تکمیل شد (نمونه)")
        
    else:
        print(f"⚠️  فاز {phase} هنوز پیاده‌سازی نشده")
        print("💡 فازهای موجود: 1, 2")

def run_all_phases(target):
    """اجرای تمام فازها"""
    print(f"🎯 هدف: {target}")
    print("🚀 اجرای تمام فازها...")
    print("=" * 30)
    
    phases = [1, 2]  # فازهای موجود
    
    for phase in phases:
        print(f"\n⚙️  فاز {phase}:")
        run_single_phase(target, phase)

class SimpleConfig:
    """کلاس config ساده"""
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
    """کلاس database ساده"""
    async def connect(self):
        pass
    
    async def disconnect(self):
        pass
    
    async def save_target(self, target, metadata=None):
        return 1
    
    async def get_targets(self):
        return []

class SimplePhaseManager:
    """کلاس phase manager ساده"""
    async def initialize(self):
        pass
    
    async def get_available_phases(self):
        return [
            {"number": 1, "name": "Real IP Extraction", "description": "استخراج IP واقعی", "dependencies": []},
            {"number": 2, "name": "Subdomain Discovery", "description": "کشف ساب‌دامین", "dependencies": [1]}
        ]
    
    async def run_phase(self, phase, target):
        return {"phase": phase, "target": target, "status": "completed", "results": {}}

if __name__ == "__main__":
    main()