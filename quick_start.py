#!/usr/bin/env python3
"""
ARAT Quick Start Script
اجرای سریع ARAT با تنظیمات پیش‌فرض
"""

import asyncio
import sys
import argparse
from pathlib import Path

# اضافه کردن مسیر پروژه
sys.path.append(str(Path(__file__).parent))

from main import ARAT


async def quick_recon(target: str, phases: list = None, web_panel: bool = False):
    """اجرای سریع reconnaissance"""
    print("🚀 ARAT Quick Start")
    print("=" * 50)
    print(f"🎯 Target: {target}")
    
    if phases:
        print(f"⚙️ Phases: {', '.join(map(str, phases))}")
    else:
        print("⚙️ Phases: All phases")
    
    if web_panel:
        print("🌐 Web Panel: Enabled")
    
    print("=" * 50)
    
    try:
        # ایجاد ARAT instance
        arat = ARAT()
        
        # مقداردهی اولیه
        print("🔧 Initializing ARAT...")
        await arat.initialize()
        print("✅ ARAT initialized successfully")
        
        if web_panel:
            # شروع پنل وب
            print("🌐 Starting web panel...")
            arat.start_web_panel("0.0.0.0", 8080)
            print("✅ Web panel started at http://localhost:8080")
            
            # نگه داشتن برنامه در حال اجرا
            try:
                while True:
                    await asyncio.sleep(1)
            except KeyboardInterrupt:
                print("\n⏹️ Stopping web panel...")
                await arat.cleanup()
        
        elif phases:
            # اجرای فازهای مشخص
            print(f"🎯 Running phases {phases}...")
            
            for phase in phases:
                print(f"\n📋 Running Phase {phase}...")
                result = await arat.run_phase(phase, target)
                
                if result['success']:
                    print(f"✅ Phase {phase} completed successfully")
                else:
                    print(f"❌ Phase {phase} failed: {result.get('error', 'Unknown error')}")
            
            print("\n🎉 All specified phases completed!")
        
        else:
            # اجرای تمامی فازها
            print("🎯 Running all phases...")
            results = await arat.run_all_phases(target)
            
            # نمایش خلاصه نتایج
            print("\n📊 Results Summary:")
            print("-" * 30)
            
            for phase_name, phase_result in results.items():
                if phase_name == "final_report":
                    continue
                
                if isinstance(phase_result, dict) and 'success' in phase_result:
                    status = "✅" if phase_result['success'] else "❌"
                    duration = phase_result.get('duration', 0)
                    print(f"{status} {phase_name}: {duration:.2f}s")
                else:
                    print(f"❓ {phase_name}: Unknown status")
            
            print("-" * 30)
            print("🎉 All phases completed!")
        
        # پاکسازی
        await arat.cleanup()
        
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    return True


def main():
    """تابع اصلی"""
    parser = argparse.ArgumentParser(
        description="ARAT Quick Start - Fast reconnaissance tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python quick_start.py example.com
  python quick_start.py example.com --phases 1,2,3
  python quick_start.py example.com --web-panel
  python quick_start.py example.com --phases 1 --web-panel
        """
    )
    
    parser.add_argument("target", help="Target domain or IP")
    parser.add_argument("--phases", help="Comma-separated list of phases to run (1-10)")
    parser.add_argument("--web-panel", action="store_true", help="Start web panel instead of running phases")
    parser.add_argument("--config", help="Path to config file")
    
    args = parser.parse_args()
    
    # پردازش phases
    phases = None
    if args.phases:
        try:
            phases = [int(p.strip()) for p in args.phases.split(',')]
            # اعتبارسنجی phases
            for phase in phases:
                if not 1 <= phase <= 10:
                    print(f"❌ Invalid phase number: {phase}. Must be between 1 and 10.")
                    sys.exit(1)
        except ValueError:
            print("❌ Invalid phases format. Use comma-separated numbers (e.g., 1,2,3)")
            sys.exit(1)
    
    # اجرای اصلی
    try:
        success = asyncio.run(quick_recon(args.target, phases, args.web_panel))
        if success:
            print("\n🎉 ARAT Quick Start completed successfully!")
        else:
            print("\n❌ ARAT Quick Start failed!")
            sys.exit(1)
    except KeyboardInterrupt:
        print("\n⏹️ Operation cancelled by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()